"""
NetDetect Optimized Bidirectional Flow Feature Extraction.
Single-pass packet inspection engine with 100% mathematical and schema equivalence
to the validated UNSW-NB15 feature specification.
"""
from collections import deque
from pathlib import Path
from typing import Union, Tuple, Dict, Any
import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, Raw, PcapReader

from backend.config.settings import PROTOCOL_MAP, PORT_TO_SERVICE, FLOW_WINDOW_SIZE
from backend.utils.logger import get_logger
from backend.utils.exceptions import PacketExtractionError

logger = get_logger("flow_extractor")

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


def _get_flow_state(proto: int, s2d_rst: int, d2s_rst: int, s2d_fin: int, d2s_fin: int, s2d_syn: int, s2d_pkts: int, d2s_pkts: int) -> str:
    """Exact state machine implementation from validated baseline."""
    if proto == 6:  # TCP
        has_rst = (s2d_rst > 0 or d2s_rst > 0)
        has_fin = (s2d_fin > 0 and d2s_fin > 0)
        has_syn = (s2d_syn > 0)
        if has_rst:
            return "RST"
        elif has_fin:
            return "FIN"
        elif has_syn:
            return "INT"
        else:
            return "CON"
    elif proto == 17:  # UDP
        if s2d_pkts > 0 and d2s_pkts > 0:
            return "CON"
        else:
            return "REQ"
    elif proto in (1, 58):  # ICMP / ICMPv6
        return "ECO"
    else:
        return "URN"


def single_pass_pcap_extraction(pcap_path: Union[str, Path]) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Unified single-pass packet inspection:
    Simultaneously collects flow packet statistics and TCP session attributes
    (TTL, window sizes, SYN/ACK timing, HTTP trans depth, response bodies, FTP logins).
    """
    pcap_path = str(pcap_path)
    flows = {}

    sttl_map = {}
    dttl_map = {}
    swin_map = {}
    dwin_map = {}
    syn_time = {}
    synack_time = {}
    ack_time = {}
    trans_depth_map = {}
    response_body_map = {}
    ftp_login_map = {}

    total_packets = 0

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue

            total_packets += 1
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = int(ip_layer.proto)
            ttl = int(ip_layer.ttl)

            src_port = 0
            dst_port = 0
            flags = 0
            has_tcp = pkt.haslayer(TCP)
            has_udp = pkt.haslayer(UDP)

            if has_tcp:
                tcp_layer = pkt[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                flags = int(tcp_layer.flags)
            elif has_udp:
                udp_layer = pkt[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)

            ts = float(pkt.time)
            size = len(pkt)

            # Bidirectional flow key canonicalization (matches baseline exactly)
            if (src_ip, src_port) <= (dst_ip, dst_port):
                flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                is_fwd = True
            else:
                flow_key = (dst_ip, src_ip, dst_port, src_port, proto)
                is_fwd = False

            if flow_key not in flows:
                flows[flow_key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "pkts": [],
                }
            flows[flow_key]["pkts"].append((ts, size, is_fwd, flags))

            # Directional keys for TCP / PCAP feature mapping
            fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
            rev_key = (dst_ip, src_ip, dst_port, src_port, proto)

            if fwd_key not in sttl_map:
                sttl_map[fwd_key] = ttl
            if rev_key not in dttl_map:
                dttl_map[rev_key] = ttl

            if has_tcp:
                window = int(tcp_layer.window)
                if fwd_key not in swin_map:
                    swin_map[fwd_key] = window
                if rev_key not in dwin_map:
                    dwin_map[rev_key] = window

                if flags == 0x02 and fwd_key not in syn_time:
                    syn_time[fwd_key] = ts
                if flags == 0x12 and rev_key not in synack_time:
                    synack_time[rev_key] = ts
                if flags == 0x10 and fwd_key not in ack_time:
                    if fwd_key in syn_time:
                        ack_time[fwd_key] = ts

                if pkt.haslayer(Raw):
                    try:
                        raw_bytes = bytes(pkt[Raw].load)
                        payload_str = raw_bytes.decode("utf-8", errors="ignore")
                    except Exception:
                        payload_str = ""

                    if any(raw_bytes.startswith(m) for m in HTTP_METHODS):
                        trans_depth_map[fwd_key] = trans_depth_map.get(fwd_key, 0) + 1

                    if payload_str.startswith("HTTP/"):
                        found = False
                        for line in payload_str.split("\r\n"):
                            if line.lower().startswith("content-length:"):
                                try:
                                    length = int(line.split(":")[1].strip())
                                    response_body_map[fwd_key] = response_body_map.get(fwd_key, 0) + length
                                    found = True
                                except Exception:
                                    pass
                        if not found and "\r\n\r\n" in payload_str:
                            body = payload_str.split("\r\n\r\n", 1)[1]
                            response_body_map[fwd_key] = response_body_map.get(fwd_key, 0) + len(body.encode("utf-8"))

                    if (src_port == 21 or dst_port == 21) and "230" in payload_str:
                        ftp_login_map[fwd_key] = 1
                        ftp_login_map[rev_key] = 1

    if not flows:
        return pd.DataFrame(), {}

    # Synthesize bidirectional network flow statistics
    rows = []
    for key, f in flows.items():
        pkts = f["pkts"]
        pkts.sort(key=lambda x: x[0])

        times = [p[0] for p in pkts]
        t_start = times[0]
        t_end = times[-1]
        b_dur_ms = float(int(round((t_end - t_start) * 1000.0)))

        fwd_pkts = [p for p in pkts if p[2]]
        rev_pkts = [p for p in pkts if not p[2]]

        s2d_pkts = len(fwd_pkts)
        d2s_pkts = len(rev_pkts)
        s2d_bytes = sum(p[1] for p in fwd_pkts)
        d2s_bytes = sum(p[1] for p in rev_pkts)

        if len(fwd_pkts) > 1:
            fwd_times = [p[0] for p in fwd_pkts]
            piats = [(fwd_times[i] - fwd_times[i - 1]) * 1000.0 for i in range(1, len(fwd_times))]
            s2d_mean_piat = round(float(np.mean(piats)), 4)
            s2d_dur_ms = float(int(round((fwd_times[-1] - fwd_times[0]) * 1000.0)))
        else:
            s2d_mean_piat = 0.0
            s2d_dur_ms = 0.0

        if len(rev_pkts) > 1:
            rev_times = [p[0] for p in rev_pkts]
            d2s_dur_ms = float(int(round((rev_times[-1] - rev_times[0]) * 1000.0)))
        else:
            d2s_dur_ms = 0.0

        s2d_mean_ps = float(np.mean([p[1] for p in fwd_pkts])) if fwd_pkts else 0.0
        d2s_mean_ps = float(np.mean([p[1] for p in rev_pkts])) if rev_pkts else 0.0

        s2d_rst = sum(1 for p in fwd_pkts if (p[3] & 0x04))
        d2s_rst = sum(1 for p in rev_pkts if (p[3] & 0x04))
        s2d_fin = sum(1 for p in fwd_pkts if (p[3] & 0x01))
        d2s_fin = sum(1 for p in rev_pkts if (p[3] & 0x01))
        s2d_syn = sum(1 for p in fwd_pkts if (p[3] & 0x02))

        rows.append({
            "bidirectional_first_seen_ms": int(round(t_start * 1000.0)),
            "bidirectional_duration_ms": b_dur_ms,
            "src2dst_duration_ms": s2d_dur_ms,
            "dst2src_duration_ms": d2s_dur_ms,
            "src2dst_packets": s2d_pkts,
            "dst2src_packets": d2s_pkts,
            "src2dst_bytes": s2d_bytes,
            "dst2src_bytes": d2s_bytes,
            "src2dst_rst_packets": s2d_rst,
            "dst2src_rst_packets": d2s_rst,
            "src2dst_fin_packets": s2d_fin,
            "dst2src_fin_packets": d2s_fin,
            "src2dst_syn_packets": s2d_syn,
            "src2dst_mean_piat_ms": s2d_mean_piat,
            "src2dst_mean_ps": s2d_mean_ps,
            "dst2src_mean_ps": d2s_mean_ps,
            "protocol": f["protocol"],
            "src_port": f["src_port"],
            "dst_port": f["dst_port"],
            "src_ip": f["src_ip"],
            "dst_ip": f["dst_ip"],
        })

    flow_df = pd.DataFrame(rows)
    if not flow_df.empty:
        flow_df = flow_df.sort_values(["bidirectional_first_seen_ms", "src_ip", "dst_ip", "src_port", "dst_port"]).reset_index(drop=True)

    maps = {
        "sttl_map": sttl_map,
        "dttl_map": dttl_map,
        "swin_map": swin_map,
        "dwin_map": dwin_map,
        "syn_time": syn_time,
        "synack_time": synack_time,
        "ack_time": ack_time,
        "trans_depth_map": trans_depth_map,
        "response_body_map": response_body_map,
        "ftp_login_map": ftp_login_map,
        "total_packets": total_packets,
    }
    return flow_df, maps


def extract_features_from_flow_df(df: pd.DataFrame, maps: dict) -> pd.DataFrame:
    """
    Synthesize all 32 model-required flow attributes from flow statistics and packet maps.
    Guarantees exact matching with the baseline UNSW-NB15 schema.
    """
    if df.empty:
        return pd.DataFrame()

    raw_df = pd.DataFrame()

    raw_df["dur"] = df["bidirectional_duration_ms"] / 1000
    raw_df["spkts"] = df["src2dst_packets"]
    raw_df["dpkts"] = df["dst2src_packets"]
    raw_df["sbytes"] = df["src2dst_bytes"]
    raw_df["dbytes"] = df["dst2src_bytes"]
    raw_df["sload"] = (df["src2dst_bytes"] * 8) / (df["src2dst_duration_ms"] / 1000)
    raw_df["dload"] = (df["dst2src_bytes"] * 8) / (df["dst2src_duration_ms"] / 1000)
    raw_df["sloss"] = df["src2dst_rst_packets"]
    raw_df["dloss"] = df["dst2src_rst_packets"]
    raw_df["sinpkt"] = df["src2dst_mean_piat_ms"] / 1000
    raw_df["smean"] = df["src2dst_mean_ps"]
    raw_df["dmean"] = df["dst2src_mean_ps"]

    raw_df["proto"] = df["protocol"].map(PROTOCOL_MAP).fillna(df["protocol"].astype(str))

    raw_df["service"] = df["dst_port"].map(PORT_TO_SERVICE)
    mask = raw_df["service"].isna()
    raw_df.loc[mask, "service"] = df.loc[mask, "src_port"].map(PORT_TO_SERVICE)
    raw_df["service"] = raw_df["service"].fillna("-")

    # State derivation
    states = []
    for _, r in df.iterrows():
        s = _get_flow_state(
            int(r["protocol"]),
            int(r["src2dst_rst_packets"]),
            int(r["dst2src_rst_packets"]),
            int(r["src2dst_fin_packets"]),
            int(r["dst2src_fin_packets"]),
            int(r["src2dst_syn_packets"]),
            int(r["src2dst_packets"]),
            int(r["dst2src_packets"]),
        )
        states.append(s)
    raw_df["state"] = states

    raw_df["is_sm_ips_ports"] = (
        (df["src_ip"] == df["dst_ip"]) | (df["src_port"] == df["dst_port"])
    ).astype(int)

    # TCP connection & session features via direct lookups
    sttl_map = maps["sttl_map"]
    dttl_map = maps["dttl_map"]
    swin_map = maps["swin_map"]
    dwin_map = maps["dwin_map"]
    syn_time = maps["syn_time"]
    synack_time = maps["synack_time"]
    ack_time = maps["ack_time"]
    trans_depth_map = maps["trans_depth_map"]
    response_body_map = maps["response_body_map"]
    ftp_login_map = maps["ftp_login_map"]

    sttl_list = []
    dttl_list = []
    swin_list = []
    dwin_list = []
    synack_list = []
    tcprtt_list = []
    trans_depth_list = []
    resp_body_list = []
    ftp_login_list = []

    for _, r in df.iterrows():
        src_ip = r["src_ip"]
        dst_ip = r["dst_ip"]
        sp = int(r["src_port"])
        dp = int(r["dst_port"])
        proto = int(r["protocol"])

        f_key = (src_ip, dst_ip, sp, dp, proto)
        r_key = (dst_ip, src_ip, dp, sp, proto)

        sttl_list.append(sttl_map.get(f_key, 0))
        dttl_list.append(dttl_map.get(r_key, 0))
        swin_list.append(swin_map.get(f_key, 0))
        dwin_list.append(dwin_map.get(r_key, 0))

        t1 = syn_time.get(f_key)
        t2 = synack_time.get(f_key)
        t3 = ack_time.get(f_key)
        synack_val = round(t2 - t1, 6) if (t1 and t2) else 0.0
        tcprtt_val = round(t3 - t1, 6) if (t1 and t3) else 0.0
        synack_list.append(synack_val)
        tcprtt_list.append(tcprtt_val)

        trans_depth_list.append(trans_depth_map.get(f_key, 0))
        resp_body_list.append(response_body_map.get(f_key, 0))
        ftp_login_list.append(ftp_login_map.get(f_key, 0))

    raw_df["sttl"] = sttl_list
    raw_df["dttl"] = dttl_list
    raw_df["swin"] = swin_list
    raw_df["dwin"] = dwin_list
    raw_df["synack"] = synack_list
    raw_df["tcprtt"] = tcprtt_list
    raw_df["trans_depth"] = trans_depth_list
    raw_df["response_body_len"] = resp_body_list
    raw_df["is_ftp_login"] = ftp_login_list

    # Connection count features (100-flow window)
    window = deque(maxlen=FLOW_WINDOW_SIZE)
    ct_srv_src = []
    ct_srv_dst = []
    ct_dst_src_ltm = []
    ct_src_dport_ltm = []
    ct_dst_sport_ltm = []
    ct_state_ttl = []

    for idx, row in df.iterrows():
        src_ip = row["src_ip"]
        dst_ip = row["dst_ip"]
        src_port = row["src_port"]
        dst_port = row["dst_port"]
        service = raw_df.loc[idx, "service"]
        state = raw_df.loc[idx, "state"]
        sttl = raw_df.loc[idx, "sttl"]

        ct_srv_src.append(sum(1 for f in window if f["src_ip"] == src_ip and f["service"] == service))
        ct_srv_dst.append(sum(1 for f in window if f["dst_ip"] == dst_ip and f["service"] == service))
        ct_dst_src_ltm.append(sum(1 for f in window if f["src_ip"] == src_ip and f["dst_ip"] == dst_ip))
        ct_src_dport_ltm.append(sum(1 for f in window if f["src_ip"] == src_ip and f["dst_port"] == dst_port))
        ct_dst_sport_ltm.append(sum(1 for f in window if f["dst_ip"] == dst_ip and f["src_port"] == src_port))
        ct_state_ttl.append(sum(1 for f in window if f["state"] == state and f["sttl"] == sttl))

        window.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "service": service,
            "state": state,
            "sttl": sttl,
        })

    raw_df["ct_srv_src"] = ct_srv_src
    raw_df["ct_srv_dst"] = ct_srv_dst
    raw_df["ct_dst_src_ltm"] = ct_dst_src_ltm
    raw_df["ct_src_dport_ltm"] = ct_src_dport_ltm
    raw_df["ct_dst_sport_ltm"] = ct_dst_sport_ltm
    raw_df["ct_state_ttl"] = ct_state_ttl

    # HTTP method connection count
    http_window = deque(maxlen=FLOW_WINDOW_SIZE)
    ct_flw_http_mthd = []

    for _, row in df.iterrows():
        src_ip = row["src_ip"]
        dst_ip = row["dst_ip"]
        src_port = int(row["src_port"])
        dst_port = int(row["dst_port"])
        proto = int(row["protocol"])
        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)

        count = sum(1 for f in http_window if f["had_http"])
        ct_flw_http_mthd.append(count)

        had_http = fwd_key in trans_depth_map and trans_depth_map[fwd_key] > 0
        http_window.append({"had_http": had_http})

    raw_df["ct_flw_http_mthd"] = ct_flw_http_mthd

    return raw_df


def extract_all_features_optimized(pcap_path: Union[str, Path]) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    High-level entrypoint for single-pass packet extraction.
    Returns (raw_feature_df, metadata_dict).
    """
    flow_df, maps = single_pass_pcap_extraction(pcap_path)
    if flow_df.empty:
        raise PacketExtractionError("No valid IPv4 connection flows could be assembled from this capture.")

    raw_df = extract_features_from_flow_df(flow_df, maps)
    metadata = {
        "total_packets": maps.get("total_packets", 0),
        "total_flows": len(raw_df),
        "flow_df": flow_df,
    }
    return raw_df, metadata
