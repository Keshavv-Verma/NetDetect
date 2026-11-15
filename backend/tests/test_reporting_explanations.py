"""Threat Reporting and Explainability Engine Tests for NetDetect."""

import json
import unittest
import pandas as pd
import numpy as np

from backend.reporting.threat_report import ThreatReport, generate_threat_report
from backend.reporting.explanations import explain_prediction


class TestReportingAndExplanations(unittest.TestCase):
    """Test suite for threat intelligence reports and evidence-based explanations."""

    def setUp(self):
        self.raw_df = pd.DataFrame([
            {
                "dur": 0.002, "proto": "tcp", "service": "http", "state": "INT",
                "spkts": 3, "dpkts": 2, "sbytes": 157, "dbytes": 131,
                "sload": 628000.0, "dload": 524000.0, "sloss": 0, "dloss": 0,
                "swin": 8192, "dwin": 8192, "ct_dst_src_ltm": 1, "ct_src_dport_ltm": 1,
            },
            {
                "dur": 0.0, "proto": "tcp", "service": "ftp", "state": "REQ",
                "spkts": 1, "dpkts": 0, "sbytes": 40, "dbytes": 0,
                "sload": 0.0, "dload": 0.0, "sloss": 0, "dloss": 0,
                "swin": 0, "dwin": 0, "ct_dst_src_ltm": 8, "ct_src_dport_ltm": 8,
            }
        ])

        self.flow_df = pd.DataFrame([
            {
                "src_ip": "192.168.1.10", "dst_ip": "93.184.216.34",
                "src_port": 54321, "dst_port": 80,
                "src2dst_packets": 3, "dst2src_packets": 2
            },
            {
                "src_ip": "10.0.0.99", "dst_ip": "192.168.1.10",
                "src_port": 40021, "dst_port": 21,
                "src2dst_packets": 1, "dst2src_packets": 0
            }
        ])

        self.prediction_result = {
            "verdict": "ATTACK",
            "risk_level": "High",
            "network_status": "Danger",
            "threat_intensity": 75.5,
            "confidence": 98.0,
            "peak_flow_index": 2,
            "analyst_note": "Hostile activity detected.",
            "all_flow_scores": [0.25, 0.85],
            "total_flows": 2
        }

    def test_explain_prediction_generates_evidence_reasons(self):
        """Verify explain_prediction identifies unidirectional probe and nominal traffic."""
        exps = explain_prediction(self.raw_df, self.prediction_result, self.flow_df)
        self.assertEqual(len(exps), 2)

        # Flow 1 (score 0.25 -> NORMAL)
        exp1 = exps[0]
        self.assertEqual(exp1["flow_id"], 1)
        self.assertEqual(exp1["verdict"], "NORMAL")
        self.assertAlmostEqual(exp1["threat_score"], 0.25)
        self.assertTrue(any("Nominal" in r for r in exp1["primary_reasons"]))

        # Flow 2 (score 0.85 -> ATTACK)
        exp2 = exps[1]
        self.assertEqual(exp2["flow_id"], 2)
        self.assertEqual(exp2["verdict"], "ATTACK")
        self.assertAlmostEqual(exp2["threat_score"], 0.85)
        # Should flag unidirectional and zero-window
        self.assertTrue(exp2["evidence_indicators"].get("unidirectional"))
        self.assertTrue(exp2["evidence_indicators"].get("zero_window"))
        self.assertIn("10.0.0.99:40021", exp2["source"])

    def test_generate_threat_report_statistics(self):
        """Verify generate_threat_report computes aggregate metrics accurately."""
        exps = explain_prediction(self.raw_df, self.prediction_result, self.flow_df)
        report = generate_threat_report(
            analysis_id="rep-001",
            filename="capture.pcap",
            file_size_bytes=2048,
            duration_seconds=0.45,
            raw_df=self.raw_df,
            flow_df=self.flow_df,
            prediction_result=self.prediction_result,
            explanations=exps,
            total_packets=6
        )

        self.assertIsInstance(report, ThreatReport)
        self.assertEqual(report.analysis_id, "rep-001")
        self.assertEqual(report.filename, "capture.pcap")
        self.assertEqual(report.total_flows, 2)
        self.assertEqual(report.attack_flows, 1)  # score 0.85 >= 0.5
        self.assertEqual(report.safe_flows, 1)
        self.assertEqual(report.attack_ratio_pct, 50.0)
        self.assertEqual(report.verdict, "ATTACK")
        self.assertEqual(report.risk_level, "High")
        self.assertEqual(report.total_packets, 6)

        # Breakdown checks
        self.assertEqual(report.protocol_distribution.get("tcp"), 2)
        self.assertIn("10.0.0.99", [x["ip"] for x in report.top_source_ips])

        # JSON serialization check
        report_dict = report.to_dict()
        self.assertIsInstance(report_dict, dict)
        serialized = json.dumps(report_dict)
        self.assertIn("rep-001", serialized)


if __name__ == "__main__":
    unittest.main()
