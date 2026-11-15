"""Service Layer Integration Tests for NetDetect."""

import json
import tempfile
import time
import unittest
from pathlib import Path

from backend.config.settings import SAMPLE_PCAPS_DIR
from backend.database.repository import AnalysisRepository
from backend.services.upload_service import UploadService
from backend.services.analysis_service import AnalysisService
from backend.services.history_service import HistoryService
from backend.reporting.threat_report import ThreatReport
from backend.utils.exceptions import SecurityValidationError


class TestServices(unittest.TestCase):
    """Test suite for UploadService, AnalysisService, and HistoryService orchestration."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_services.db"
        self.analysis_repo = AnalysisRepository(self.db_path)
        self.analysis_service = AnalysisService(repository=self.analysis_repo)
        self.history_service = HistoryService(analysis_repo=self.analysis_repo)
        self.sample_pcap = str(SAMPLE_PCAPS_DIR / "sample_traffic.pcap")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_upload_service_valid_file(self):
        """Verify UploadService validates, hashes, and calculates size for valid capture."""
        safe_name, file_hash, size, fmt = UploadService.process_and_validate(
            self.sample_pcap, "sample_traffic.pcap"
        )
        self.assertEqual(safe_name, "sample_traffic.pcap")
        self.assertEqual(len(file_hash), 64)  # Valid SHA-256
        self.assertEqual(size, 834)
        self.assertEqual(fmt, "pcap")

    def test_upload_service_sanitizes_traversal(self):
        """Verify directory traversal filename is rejected or sanitized."""
        with open(self.sample_pcap, "rb") as f:
            data = f.read()

        # Should either raise SecurityValidationError or return sanitized base name
        try:
            safe_name, _, _, _ = UploadService.process_and_validate(
                data, "../../../etc/passwd.pcap"
            )
            self.assertNotIn("/", safe_name)
            self.assertNotIn("..", safe_name)
        except SecurityValidationError:
            pass  # Early rejection is also valid security behavior

    def test_analysis_service_sync_execution(self):
        """Test synchronous end-to-end analysis orchestration."""
        report, raw_df, pred_result = self.analysis_service.run_analysis_sync(
            self.sample_pcap, filename="synced_test.pcap"
        )

        self.assertIsInstance(report, ThreatReport)
        self.assertEqual(report.filename, "synced_test.pcap")
        self.assertEqual(report.total_flows, 7)
        self.assertIn(report.verdict, ["NORMAL", "ATTACK DETECTED"])
        self.assertIsNotNone(report.explanations)
        self.assertEqual(len(report.explanations), 7)

        # Verify record was stored in repository
        persisted = self.history_service.get_analysis_detail(report.analysis_id)
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted["filename"], "synced_test.pcap")
        self.assertEqual(persisted["verdict"], report.verdict)

    def test_analysis_service_async_task_tracking(self):
        """Test asynchronous execution with progress monitoring."""
        task = self.analysis_service.start_async_analysis(
            self.sample_pcap, filename="async_test.pcap"
        )
        self.assertIsNotNone(task.task_id)

        # Wait for task completion (or timeout after 15 seconds)
        max_wait = 15.0
        start = time.time()
        while task.status in ("PENDING", "PROCESSING") and (time.time() - start) < max_wait:
            time.sleep(0.1)

        self.assertEqual(task.status, "COMPLETED")
        self.assertEqual(task.progress, 1.0)
        self.assertIsNotNone(task.result)
        self.assertEqual(task.result.filename, "async_test.pcap")

    def test_history_service_export_and_delete(self):
        """Test history querying, JSON vault export, and deletion."""
        # Run an analysis to populate history
        report, _, _ = self.analysis_service.run_analysis_sync(
            self.sample_pcap, filename="history_test.pcap"
        )

        # 1. Export JSON
        exported_json = self.history_service.export_analyses_json()
        parsed = json.loads(exported_json)
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["id"], report.analysis_id)

        # 2. Delete analysis
        deleted = self.history_service.delete_analysis(report.analysis_id)
        self.assertTrue(deleted)
        self.assertIsNone(self.history_service.get_analysis_detail(report.analysis_id))


if __name__ == "__main__":
    unittest.main()
