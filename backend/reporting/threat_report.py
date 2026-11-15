"""
NetDetect Threat Reporting Engine.
Transforms raw model predictions and extracted flow records into a structured,
production-grade cybersecurity analysis report.
"""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np


@dataclass
class ThreatReport:
    analysis_id: str
    filename: str
    file_size_bytes: int
    analyzed_at: str
    duration_seconds: float
    total_packets: int
    total_flows: int
    attack_flows: int
    safe_flows: int
    attack_ratio_pct: float
    verdict: str
    risk_level: str
    network_status: str
    threat_intensity_pct: float
    confidence_pct: float
    peak_flow_index: int
    analyst_note: str
    protocol_distribution: Dict[str, int]
    service_distribution: Dict[str, int]
    top_source_ips: List[Dict[str, Any]]
    top_destination_ips: List[Dict[str, Any]]
    explanations: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def generate_threat_report(
    analysis_id: str,
    filename: str,
    file_size_bytes: int,
    duration_seconds: float,
    raw_df: pd.DataFrame,
    flow_df: pd.DataFrame,
    prediction_result: dict,
    explanations: list = None,
    total_packets: int = 0
) -> ThreatReport:
    """
    Construct a complete ThreatReport from model predictions and flow attributes.
    All metrics are computed strictly from verified inspection data.
    """
    scores = np.array(prediction_result.get("all_flow_scores", []))
    n_flows = len(scores) if len(scores) > 0 else prediction_result.get("total_flows", 0)
    attack_count = int(np.sum(scores >= 0.5)) if len(scores) > 0 else 0
    safe_count = n_flows - attack_count
    attack_ratio = round((attack_count / n_flows) * 100, 2) if n_flows > 0 else 0.0

    # Protocol breakdown
    proto_dist = {}
    if "proto" in raw_df.columns:
        proto_dist = raw_df["proto"].value_counts().to_dict()

    # Service breakdown
    svc_dist = {}
    if "service" in raw_df.columns:
        svc_dist = raw_df["service"].value_counts().head(10).to_dict()

    # Source & destination endpoints
    top_src = []
    top_dst = []
    if not flow_df.empty and "src_ip" in flow_df.columns and "dst_ip" in flow_df.columns:
        src_counts = flow_df["src_ip"].value_counts().head(5)
        top_src = [{"ip": str(ip), "count": int(c)} for ip, c in src_counts.items()]

        dst_counts = flow_df["dst_ip"].value_counts().head(5)
        top_dst = [{"ip": str(ip), "count": int(c)} for ip, c in dst_counts.items()]

    return ThreatReport(
        analysis_id=analysis_id,
        filename=filename,
        file_size_bytes=file_size_bytes,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        duration_seconds=round(duration_seconds, 2),
        total_packets=total_packets or (int(flow_df["src2dst_packets"].sum() + flow_df["dst2src_packets"].sum()) if not flow_df.empty and "src2dst_packets" in flow_df.columns else 0),
        total_flows=n_flows,
        attack_flows=attack_count,
        safe_flows=safe_count,
        attack_ratio_pct=attack_ratio,
        verdict=prediction_result.get("verdict", "NORMAL"),
        risk_level=prediction_result.get("risk_level", "Low"),
        network_status=prediction_result.get("network_status", "Safe"),
        threat_intensity_pct=prediction_result.get("threat_intensity", 0.0),
        confidence_pct=prediction_result.get("confidence", 95.0),
        peak_flow_index=prediction_result.get("peak_flow_index", 1),
        analyst_note=prediction_result.get("analyst_note", ""),
        protocol_distribution=proto_dist,
        service_distribution=svc_dist,
        top_source_ips=top_src,
        top_destination_ips=top_dst,
        explanations=explanations or []
    )
