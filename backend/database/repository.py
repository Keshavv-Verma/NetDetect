"""
NetDetect Repository Layer.
Provides typed, paginated, and filtered data access for persistent SQLite storage.
"""
import json
from typing import Optional, List, Tuple, Dict, Any
from pathlib import Path

from backend.database.connection import get_db_connection, init_db
from backend.database.models import AnalysisRecord, LiveAuditRecord
from backend.utils.logger import get_logger
from backend.utils.exceptions import DatabaseError

logger = get_logger("repository")


class AnalysisRepository:
    """Data access repository for PCAP analyses."""

    def __init__(self, db_path: Path = None):
        self.db_path = db_path
        init_db(self.db_path)

    def save(self, record: AnalysisRecord) -> str:
        """Insert or replace an analysis record."""
        sql = """
        INSERT OR REPLACE INTO analyses (
            id, filename, file_hash, file_size_bytes, status, created_at, completed_at,
            duration_seconds, total_packets, total_flows, attack_flows, verdict,
            risk_level, threat_intensity, confidence, peak_flow_index, analyst_note,
            error_message, summary_json
        ) VALUES (
            :id, :filename, :file_hash, :file_size_bytes, :status, :created_at, :completed_at,
            :duration_seconds, :total_packets, :total_flows, :attack_flows, :verdict,
            :risk_level, :threat_intensity, :confidence, :peak_flow_index, :analyst_note,
            :error_message, :summary_json
        )
        """
        params = {
            "id": record.id,
            "filename": record.filename,
            "file_hash": record.file_hash,
            "file_size_bytes": record.file_size_bytes,
            "status": record.status,
            "created_at": record.created_at,
            "completed_at": record.completed_at,
            "duration_seconds": record.duration_seconds,
            "total_packets": record.total_packets,
            "total_flows": record.total_flows,
            "attack_flows": record.attack_flows,
            "verdict": record.verdict,
            "risk_level": record.risk_level,
            "threat_intensity": record.threat_intensity,
            "confidence": record.confidence,
            "peak_flow_index": record.peak_flow_index,
            "analyst_note": record.analyst_note,
            "error_message": record.error_message,
            "summary_json": record.summary_json,
        }
        with get_db_connection(self.db_path) as conn:
            conn.execute(sql, params)
        logger.debug(f"Saved analysis record {record.id} ({record.filename})")
        return record.id

    def update(self, analysis_id: str, updates: Dict[str, Any]) -> bool:
        """Update specific columns of an analysis record."""
        if not updates:
            return False
        set_clauses = [f"{k} = :{k}" for k in updates.keys()]
        sql = f"UPDATE analyses SET {', '.join(set_clauses)} WHERE id = :_id"
        params = dict(updates)
        params["_id"] = analysis_id
        with get_db_connection(self.db_path) as conn:
            cur = conn.execute(sql, params)
            return cur.rowcount > 0

    def get_by_id(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single analysis record by ID."""
        sql = "SELECT * FROM analyses WHERE id = ?"
        with get_db_connection(self.db_path) as conn:
            cur = conn.execute(sql, (analysis_id,))
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            if res.get("summary_json"):
                try:
                    res["summary"] = json.loads(res["summary_json"])
                except Exception:
                    res["summary"] = {}
            return res

    def list_analyses(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        verdict: Optional[str] = None,
        search: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        List analyses with filtering, full-text search on filename, and pagination.
        Returns (records_list, total_count).
        """
        conditions = []
        params = {}

        if status:
            conditions.append("status = :status")
            params["status"] = status
        if verdict:
            conditions.append("verdict = :verdict")
            params["verdict"] = verdict
        if search:
            conditions.append("filename LIKE :search")
            params["search"] = f"%{search}%"

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        count_sql = f"SELECT COUNT(*) as cnt FROM analyses {where_clause}"
        list_sql = f"""
        SELECT * FROM analyses
        {where_clause}
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
        """
        params["limit"] = limit
        params["offset"] = offset

        with get_db_connection(self.db_path) as conn:
            cur = conn.execute(count_sql, params)
            total = cur.fetchone()["cnt"]

            cur = conn.execute(list_sql, params)
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if r.get("summary_json"):
                    try:
                        r["summary"] = json.loads(r["summary_json"])
                    except Exception:
                        r["summary"] = {}

        return rows, total

    def delete(self, analysis_id: str) -> bool:
        """Delete an analysis record by ID."""
        sql = "DELETE FROM analyses WHERE id = ?"
        with get_db_connection(self.db_path) as conn:
            cur = conn.execute(sql, (analysis_id,))
            return cur.rowcount > 0

    def clear_all(self) -> int:
        """Purge all analysis history records."""
        sql = "DELETE FROM analyses"
        with get_db_connection(self.db_path) as conn:
            cur = conn.execute(sql)
            return cur.rowcount


class LiveAuditRepository:
    """Data access repository for live simulation streaming events."""

    def __init__(self, db_path: Path = None):
        self.db_path = db_path
        init_db(self.db_path)

    def save(self, record: LiveAuditRecord) -> str:
        sql = """
        INSERT INTO live_audit_events (
            id, timestamp, src_ip, dst_ip, protocol_type, service, flag,
            predicted_category, is_attack, confidence, severity
        ) VALUES (
            :id, :timestamp, :src_ip, :dst_ip, :protocol_type, :service, :flag,
            :predicted_category, :is_attack, :confidence, :severity
        )
        """
        params = {
            "id": record.id,
            "timestamp": record.timestamp,
            "src_ip": record.src_ip,
            "dst_ip": record.dst_ip,
            "protocol_type": record.protocol_type,
            "service": record.service,
            "flag": record.flag,
            "predicted_category": record.predicted_category,
            "is_attack": 1 if record.is_attack else 0,
            "confidence": record.confidence,
            "severity": record.severity,
        }
        with get_db_connection(self.db_path) as conn:
            conn.execute(sql, params)
        return record.id

    def list_events(self, limit: int = 100, attacks_only: bool = False) -> List[Dict[str, Any]]:
        cond = "WHERE is_attack = 1" if attacks_only else ""
        sql = f"SELECT * FROM live_audit_events {cond} ORDER BY timestamp DESC LIMIT ?"
        with get_db_connection(self.db_path) as conn:
            cur = conn.execute(sql, (limit,))
            return [dict(r) for r in cur.fetchall()]

    def clear_all(self) -> int:
        with get_db_connection(self.db_path) as conn:
            cur = conn.execute("DELETE FROM live_audit_events")
            return cur.rowcount
