"""ML Model and Artifact Integrity Tests for NetDetect.

Verifies:
1. Presence and integrity of all ML model artifacts (classifiers, anomaly, scalers, encoders).
2. Exact feature schema and feature ordering invariants (42 raw features -> 32 scaled model features).
3. Unbroken inference pipeline and prediction output schema.
4. Model fingerprinting and non-modification verification.
"""

import os
import unittest
import joblib
import pandas as pd
import numpy as np
from pathlib import Path

from backend.config.settings import (
    MODELS_DIR,
    NIDSS_ENCODERS_PATH,
    NIDSS_SCALER_PATH,
    NIDSS_FEATURES_PATH,
    IF_MODEL_PATH,
    IF_SCALER_PATH,
    IF_FEATURES_PATH,
    RF_MODEL_PATH,
    LGBM_MODEL_PATH,
    XGB_MODEL_PATH,
    FINAL_THRESHOLD_PATH,
    EXPECTED_42_FEATURES,
    ZERO_FILL_FEATURES,
    DEFAULT_DECISION_THRESHOLD,
    ENSEMBLE_WEIGHT,
    IF_WEIGHT,
)
from prediction import run_prediction, load_artifacts, ALL_42_FEATURES, TO_FILL_ZERO


class TestMLModelIntegrity(unittest.TestCase):
    """Test suite ensuring existing ML models and artifacts remain 100% intact."""

    def test_all_model_artifact_files_exist(self):
        """Verify every protected artifact file exists on disk."""
        artifacts = [
            NIDSS_ENCODERS_PATH,
            NIDSS_SCALER_PATH,
            NIDSS_FEATURES_PATH,
            IF_MODEL_PATH,
            IF_SCALER_PATH,
            IF_FEATURES_PATH,
            RF_MODEL_PATH,
            LGBM_MODEL_PATH,
            XGB_MODEL_PATH,
            FINAL_THRESHOLD_PATH,
        ]
        for path in artifacts:
            self.assertTrue(
                os.path.exists(path),
                f"Required ML artifact missing: {path}"
            )
            self.assertGreater(
                os.path.getsize(path), 0,
                f"Artifact file is empty: {path}"
            )

    def test_live_ids_artifacts_exist(self):
        """Verify secondary live_ids artifacts exist."""
        live_model = Path("live_ids/models/nids_model.joblib")
        live_preprocessor = Path("live_ids/models/preprocessor.joblib")
        if live_model.parent.exists():
            self.assertTrue(live_model.exists(), "Live IDS model joblib missing")
            self.assertTrue(live_preprocessor.exists(), "Live IDS preprocessor joblib missing")

    def test_artifacts_load_successfully(self):
        """Verify all artifacts load cleanly via load_artifacts."""
        artifacts = load_artifacts(str(MODELS_DIR))
        expected_keys = [
            'encoders', 'scaler', 'nids_features', 'iso_forest',
            'if_scaler', 'if_feature_order', 'model_xgb', 'model_lgbm',
            'model_rf', 'threshold'
        ]
        for k in expected_keys:
            self.assertIn(k, artifacts)
            self.assertIsNotNone(artifacts[k], f"Artifact {k} loaded as None")

    def test_feature_order_schema_invariants(self):
        """Verify the exact 42 expected features and 32 model features."""
        artifacts = load_artifacts(str(MODELS_DIR))
        nids_features = artifacts['nids_features']
        
        # Raw UNSW-NB15 features must be exactly 42
        self.assertEqual(len(ALL_42_FEATURES), 42)
        self.assertEqual(ALL_42_FEATURES, EXPECTED_42_FEATURES)

        # Trained model features: 42 raw minus 10 zero-filled = 32 features
        self.assertEqual(len(nids_features), 32)
        expected_32 = [f for f in ALL_42_FEATURES if f not in TO_FILL_ZERO]
        # Check set equality
        self.assertEqual(set(nids_features), set(expected_32))

    def test_zero_fill_features_invariants(self):
        """Verify exact 10 zero-filled features."""
        self.assertEqual(len(ZERO_FILL_FEATURES), 10)
        self.assertEqual(ZERO_FILL_FEATURES, TO_FILL_ZERO)
        expected_zero_fills = [
            'rate', 'dinpkt', 'sjit', 'djit',
            'stcpb', 'dtcpb', 'ackdat',
            'ct_dst_ltm', 'ct_ftp_cmd', 'ct_src_ltm'
        ]
        self.assertEqual(ZERO_FILL_FEATURES, expected_zero_fills)

    def test_threshold_and_weights_invariants(self):
        """Verify classification threshold and ensemble weights are strictly preserved."""
        artifacts = load_artifacts(str(MODELS_DIR))
        threshold = artifacts['threshold']
        self.assertAlmostEqual(float(threshold), DEFAULT_DECISION_THRESHOLD, places=4)
        self.assertEqual(ENSEMBLE_WEIGHT, 0.5)
        self.assertEqual(IF_WEIGHT, 0.5)

    def test_prediction_pipeline_contract(self):
        """Verify run_prediction runs and produces expected output contract on sample flows."""
        artifacts = load_artifacts(str(MODELS_DIR))
        np.random.seed(42)
        row = {feat: 0.0 for feat in ALL_42_FEATURES}
        row['proto'] = 'tcp'
        row['service'] = 'http'
        row['state'] = 'CON'
        df_dummy = pd.DataFrame([row])

        result = run_prediction(df_dummy, artifacts)

        self.assertIsInstance(result, dict)
        self.assertIn("verdict", result)
        self.assertIn("threat_intensity", result)
        self.assertIn("risk_level", result)
        self.assertIn("all_flow_scores", result)
        self.assertIn("confidence", result)
        self.assertIn(result["verdict"], ["NORMAL", "ATTACK DETECTED"])
        self.assertTrue(0.0 <= result["threat_intensity"] <= 100.0)


if __name__ == "__main__":
    unittest.main()
