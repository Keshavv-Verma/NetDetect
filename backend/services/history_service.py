"""
NetDetect History Service.
Interfaces between the persistent repository and presentation/API layers.
"""
from typing import Dict, Any, List, Tuple, Optional
import json

from backend.database.repository import AnalysisRepository, LiveAuditRepository
from backend.utils.logger import get_logger

logger = get_logger("history_service")


class HistoryService:
    """Service providing query, filter, export, and deletion capabilities for analysis history."""

    def __init__(self, analysis_repo: AnalysisRepository = None, audit_repo: LiveAuditRepository = None):
        self.analysis_repo = analysis_repo or AnalysisRepository()
        self.audit_repo = audit_repo or LiveAuditRepository()

    def get_analysis_detail(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        return self.analysis_repo.get_by_id(analysis_id)

    def list_analyses(
        self,
        limit: int = 50,
        offset: int = 0,
        status: str = None,
        verdict: str = None,
        search: str = None
    ) -> Tuple[List[Dict[str, Any]], int]:
        return self.analysis_repo.list_analyses(
            limit=limit, offset=offset, status=status, verdict=verdict, search=search
        )

    def delete_analysis(self, analysis_id: str) -> bool:
        return self.analysis_repo.delete(analysis_id)

    def clear_all(self) -> int:
        return self.analysis_repo.clear_all()

    def export_analyses_json(self, limit: int = 500) -> str:
        records, _ = self.analysis_repo.list_analyses(limit=limit)
        return json.dumps(records, indent=2)

    def list_live_audit_events(self, limit: int = 100, attacks_only: bool = False) -> List[Dict[str, Any]]:
        return self.audit_repo.list_events(limit=limit, attacks_only=attacks_only)

    def clear_live_audit_events(self) -> int:
        return self.audit_repo.clear_all()
