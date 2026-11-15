"""
NetDetect Database Models and Schemas.
Typed data contracts for analysis records and security audit trails.
"""
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import json


@dataclass
class AnalysisRecord:
    id: str
    filename: str
    file_size_bytes: int
    status: str                         # PENDING, PROCESSING, COMPLETED, FAILED
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    file_hash: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    total_packets: int = 0
    total_flows: int = 0
    attack_flows: int = 0
    verdict: Optional[str] = None       # NORMAL, ATTACK
    risk_level: Optional[str] = None    # Low, Medium, High, Critical
    threat_intensity: float = 0.0
    confidence: float = 0.0
    peak_flow_index: Optional[int] = None
    analyst_note: Optional[str] = None
    error_message: Optional[str] = None
    summary_json: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.summary_json:
            try:
                d["summary"] = json.loads(self.summary_json)
            except Exception:
                d["summary"] = {}
        else:
            d["summary"] = {}
        return d


@dataclass
class LiveAuditRecord:
    id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    predicted_category: str
    is_attack: bool
    confidence: float
    severity: str
    protocol_type: Optional[str] = None
    service: Optional[str] = None
    flag: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
