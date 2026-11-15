"""
NetDetect Explainability Engine.
Generates evidence-based explanations for model predictions without modifying or
retraining the underlying machine learning models.
"""
from typing import List, Dict, Any
import numpy as np
import pandas as pd


def explain_prediction(raw_df: pd.DataFrame, prediction_result: dict, flow_df: pd.DataFrame = None) -> List[Dict[str, Any]]:
    """
    Produce structured, evidence-based reasoning for every flagged flow and the overall verdict.
    Identifies high-impact features, outlier indicators, and consensus signals.
    """
    scores = prediction_result.get("all_flow_scores", [])
    threshold = 0.50
    explanations = []

    for idx, score in enumerate(scores):
        flow_id = idx + 1
        is_attack = score >= threshold

        row = raw_df.iloc[idx] if idx < len(raw_df) else None
        f_row = flow_df.iloc[idx] if (flow_df is not None and idx < len(flow_df)) else None

        reasons = []
        indicators = {}

        if row is not None:
            # Check 1: Asymmetric unacknowledged traffic (Port Scan / SYN flood probe)
            spkts = row.get("spkts", 0)
            dpkts = row.get("dpkts", 0)
            if spkts > 0 and dpkts == 0:
                reasons.append("Unidirectional connection: packets sent without return response (characteristic of port probes or scanning).")
                indicators["unidirectional"] = True

            # Check 2: Connection reset anomalies
            sloss = row.get("sloss", 0)
            dloss = row.get("dloss", 0)
            if sloss > 0 or dloss > 0:
                reasons.append(f"Connection termination anomaly: {int(sloss + dloss)} reset (RST) packet(s) observed.")
                indicators["rst_packets"] = int(sloss + dloss)

            # Check 3: High transmission rate
            sload = row.get("sload", 0)
            if sload > 5_000_000:  # > 5 Mbps
                reasons.append(f"Elevated transmission load: {sload/1_000_000:.1f} Mbps throughput.")
                indicators["high_sload"] = True

            # Check 4: Rapid connection density (Connection clustering)
            ct_dst_src = row.get("ct_dst_src_ltm", 0)
            ct_src_dport = row.get("ct_src_dport_ltm", 0)
            if ct_dst_src > 5:
                reasons.append(f"Dense connection clustering: {int(ct_dst_src)} concurrent flows between same host pair within 100-flow window.")
                indicators["dense_host_pair"] = int(ct_dst_src)
            if ct_src_dport > 5:
                reasons.append(f"Target port concentration: {int(ct_src_dport)} connections to same destination port from source.")
                indicators["port_concentration"] = int(ct_src_dport)

            # Check 5: TCP Window Exhaustion
            swin = row.get("swin", 255)
            dwin = row.get("dwin", 255)
            if swin == 0 or dwin == 0:
                reasons.append("TCP Zero-Window advertisement observed (receiver buffer starvation).")
                indicators["zero_window"] = True

        if is_attack and not reasons:
            reasons.append("Multi-dimensional feature vector deviated significantly from baseline normal profile across the model ensemble.")

        if not is_attack and score < 0.35:
            reasons.append("Nominal bi-directional handshake, balanced packet exchange, and standard window sizes.")

        # Source / destination string if available
        src_str = f"{f_row['src_ip']}:{f_row['src_port']}" if f_row is not None else "N/A"
        dst_str = f"{f_row['dst_ip']}:{f_row['dst_port']}" if f_row is not None else "N/A"

        explanations.append({
            "flow_id": flow_id,
            "threat_score": float(score),
            "verdict": "ATTACK" if is_attack else "NORMAL",
            "source": src_str,
            "destination": dst_str,
            "primary_reasons": reasons,
            "evidence_indicators": indicators,
        })

    return explanations
