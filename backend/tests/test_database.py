"""Database and Repository Layer Tests for NetDetect."""

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.database.connection import init_db, get_db_connection
from backend.database.models import AnalysisRecord, LiveAuditRecord
from backend.database.repository import AnalysisRepository, LiveAuditRepository


class TestDatabaseAndRepositories(unittest.TestCase):
    """Test suite ensuring persistence, pagination, filtering, and WAL integrity."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_netdetect.db"
        self.analysis_repo = AnalysisRepository(self.db_path)
        self.live_repo = LiveAuditRepository(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_database_initialization_and_wal_mode(self):
        """Verify tables exist and journal mode is WAL."""
        with get_db_connection(self.db_path) as conn:
            cur = conn.execute("PRAGMA journal_mode;")
            mode = cur.fetchone()[0]
            self.assertEqual(mode.upper(), "WAL")

            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row[0] for row in cur.fetchall()}
            self.assertIn("analyses", tables)
            self.assertIn("live_audit_events", tables)

    def test_save_and_get_analysis_record(self):
        """Test saving an AnalysisRecord and retrieving it by ID."""
        now = datetime.now(timezone.utc).isoformat()
        rec = AnalysisRecord(
            id="ana-100",
            filename="test_capture.pcap",
            file_hash="abcd1234efgh5678",
            file_size_bytes=1024,
            status="COMPLETED",
            created_at=now,
            completed_at=now,
            duration_seconds=1.25,
            total_packets=50,
            total_flows=10,
            attack_flows=2,
            verdict="ATTACK",
            risk_level="High",
            threat_intensity=78.5,
            confidence=95.0,
            peak_flow_index=3,
            analyst_note="High alert",
            error_message=None,
            summary_json='{"status": "ok"}'
        )
        saved_id = self.analysis_repo.save(rec)
        self.assertEqual(saved_id, "ana-100")

        retrieved = self.analysis_repo.get_by_id("ana-100")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["filename"], "test_capture.pcap")
        self.assertEqual(retrieved["verdict"], "ATTACK")
        self.assertEqual(retrieved["total_flows"], 10)
        self.assertEqual(retrieved["summary"]["status"], "ok")

    def test_update_analysis_record(self):
        """Test updating fields on an existing record."""
        now = datetime.now(timezone.utc).isoformat()
        rec = AnalysisRecord(
            id="ana-update",
            filename="pending.pcap",
            file_hash="1111",
            file_size_bytes=500,
            status="PROCESSING",
            created_at=now,
        )
        self.analysis_repo.save(rec)

        updated = self.analysis_repo.update("ana-update", {
            "status": "COMPLETED",
            "verdict": "NORMAL",
            "threat_intensity": 15.0
        })
        self.assertTrue(updated)

        record = self.analysis_repo.get_by_id("ana-update")
        self.assertEqual(record["status"], "COMPLETED")
        self.assertEqual(record["verdict"], "NORMAL")
        self.assertEqual(record["threat_intensity"], 15.0)

    def test_pagination_and_filtering(self):
        """Test list_analyses pagination and search/verdict filters."""
        now = datetime.now(timezone.utc).isoformat()
        for i in range(15):
            verdict = "ATTACK" if i % 2 == 0 else "NORMAL"
            fn = f"traffic_batch_{i:02d}.pcap"
            rec = AnalysisRecord(
                id=f"ana-{i:02d}",
                filename=fn,
                file_hash=f"hash_{i}",
                file_size_bytes=100 * (i + 1),
                status="COMPLETED",
                created_at=now,
                verdict=verdict,
            )
            self.analysis_repo.save(rec)

        # 1. Total count
        records, total = self.analysis_repo.list_analyses(limit=10, offset=0)
        self.assertEqual(total, 15)
        self.assertEqual(len(records), 10)

        # 2. Offset page 2
        page_2, total_2 = self.analysis_repo.list_analyses(limit=10, offset=10)
        self.assertEqual(total_2, 15)
        self.assertEqual(len(page_2), 5)

        # 3. Filter by verdict
        attacks, total_attacks = self.analysis_repo.list_analyses(verdict="ATTACK")
        self.assertEqual(total_attacks, 8)
        for a in attacks:
            self.assertEqual(a["verdict"], "ATTACK")

        # 4. Search by filename substring
        searched, total_searched = self.analysis_repo.list_analyses(search="batch_0")
        # Matches batch_00 through batch_09 = 10 records
        self.assertEqual(total_searched, 10)

    def test_delete_and_clear_all(self):
        """Test deleting individual records and purging vault."""
        now = datetime.now(timezone.utc).isoformat()
        rec1 = AnalysisRecord(id="del-1", filename="a.pcap", file_hash="h1", file_size_bytes=10, status="COMPLETED", created_at=now)
        rec2 = AnalysisRecord(id="del-2", filename="b.pcap", file_hash="h2", file_size_bytes=20, status="COMPLETED", created_at=now)
        self.analysis_repo.save(rec1)
        self.analysis_repo.save(rec2)

        deleted = self.analysis_repo.delete("del-1")
        self.assertTrue(deleted)
        self.assertIsNone(self.analysis_repo.get_by_id("del-1"))
        self.assertIsNotNone(self.analysis_repo.get_by_id("del-2"))

        purged_count = self.analysis_repo.clear_all()
        self.assertEqual(purged_count, 1)
        _, remaining = self.analysis_repo.list_analyses()
        self.assertEqual(remaining, 0)

    def test_live_audit_repository(self):
        """Test LiveAuditRepository insertion and retrieval."""
        now = datetime.now(timezone.utc).isoformat()
        event = LiveAuditRecord(
            id="evt-1",
            timestamp=now,
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            protocol_type="tcp",
            service="http",
            flag="SF",
            predicted_category="Dos",
            is_attack=1,
            confidence=99.2,
            severity="CRITICAL"
        )
        self.live_repo.save(event)

        events = self.live_repo.list_events(limit=5)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["src_ip"], "192.168.1.50")
        self.assertEqual(events[0]["predicted_category"], "Dos")
        self.assertEqual(events[0]["is_attack"], 1)


if __name__ == "__main__":
    unittest.main()
