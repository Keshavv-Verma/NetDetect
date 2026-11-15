"""Feature Extraction Equivalence Tests for NetDetect.

Validates that the optimized single-pass packet extractor produces 100%
bit-for-bit, schema, and mathematical equivalence with the original baseline
feature extraction on capture files, and produces identical model predictions.
"""

import unittest
import numpy as np
import pandas as pd
from pathlib import Path

from backend.config.settings import MODELS_DIR, SAMPLE_PCAPS_DIR
from backend.packet_processing.extractor import extract_all_features_optimized
import feature_extraction
from prediction import load_artifacts, run_prediction


class TestFeatureEquivalence(unittest.TestCase):
    """Rigorous equivalence test between legacy extraction and optimized extraction."""

    @classmethod
    def setUpClass(cls):
        cls.pcap_path = str(SAMPLE_PCAPS_DIR / "sample_traffic.pcap")
        cls.artifacts = load_artifacts(str(MODELS_DIR))

    def test_sample_pcap_exists(self):
        """Ensure sample test capture exists."""
        self.assertTrue(Path(self.pcap_path).exists(), f"Missing {self.pcap_path}")

    def test_legacy_vs_optimized_dataframe_exact_match(self):
        """Test that single-pass extraction matches legacy extraction with 100% exact values."""
        df_legacy = feature_extraction.extract_all_features_legacy(self.pcap_path)
        df_opt, flow_meta = extract_all_features_optimized(self.pcap_path)

        # 1. Row count match
        self.assertEqual(len(df_legacy), len(df_opt), "Flow count mismatch")

        # 2. Columns match
        self.assertEqual(list(df_legacy.columns), list(df_opt.columns), "Column names or ordering mismatch")

        # 3. Exact DataFrame equality
        pd.testing.assert_frame_equal(
            df_legacy,
            df_opt,
            check_exact=True,
            check_like=False,
            check_dtype=True,
            obj="Legacy vs Optimized Flow Features"
        )
        self.assertEqual(flow_meta["total_flows"], len(df_opt))
        self.assertEqual(len(flow_meta["flow_df"]), len(df_opt))

    def test_feature_extraction_wrapper_uses_optimized(self):
        """Test that calling feature_extraction.extract_all_features returns exact match."""
        df_public = feature_extraction.extract_all_features(self.pcap_path)
        df_opt, _ = extract_all_features_optimized(self.pcap_path)

        pd.testing.assert_frame_equal(df_public, df_opt, check_exact=True)

    def test_downstream_model_prediction_equivalence(self):
        """Verify downstream ML predictions on legacy vs optimized extractions are identical."""
        df_legacy = feature_extraction.extract_all_features_legacy(self.pcap_path)
        df_opt, _ = extract_all_features_optimized(self.pcap_path)

        pred_legacy = run_prediction(df_legacy, self.artifacts)
        pred_opt = run_prediction(df_opt, self.artifacts)

        self.assertEqual(pred_legacy["verdict"], pred_opt["verdict"])
        self.assertEqual(pred_legacy["total_flows"], pred_opt["total_flows"])
        self.assertEqual(pred_legacy["risk_level"], pred_opt["risk_level"])
        self.assertEqual(pred_legacy["network_status"], pred_opt["network_status"])
        self.assertAlmostEqual(pred_legacy["threat_intensity"], pred_opt["threat_intensity"], places=6)
        self.assertEqual(pred_legacy["traffic_behavior"], pred_opt["traffic_behavior"])
        self.assertEqual(pred_legacy["peak_flow_index"], pred_opt["peak_flow_index"])
        self.assertEqual(pred_legacy["confidence"], pred_opt["confidence"])

        # Check all individual flow scores match
        np.testing.assert_allclose(
            pred_legacy["all_flow_scores"],
            pred_opt["all_flow_scores"],
            rtol=1e-5,
            atol=1e-5
        )


if __name__ == "__main__":
    unittest.main()
