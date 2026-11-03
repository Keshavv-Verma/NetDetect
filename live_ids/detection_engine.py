"""
Detection engine: loads trained model + preprocessor, scores incoming
traffic records, and returns structured detection results.

This is the core module used for real-time inference on simulated traffic.
"""

import uuid
import joblib
import pandas as pd
from pathlib import Path
from datetime import datetime, timezone

try:
    from .columns import COLUMNS
    from .preprocessing import NIDSPreprocessor
except ImportError:
    from columns import COLUMNS
    from preprocessing import NIDSPreprocessor

ARTIFACT_DIR = Path(__file__).resolve().parent / "models"

# Columns a raw traffic record needs (everything except label/difficulty,
# which aren't known for live/incoming traffic).
FEATURE_INPUT_COLS = [c for c in COLUMNS if c not in ("label", "difficulty")]

# Severity ranking used for alert prioritization on the dashboard.
CATEGORY_SEVERITY = {
    "Normal": "info",
    "Probe": "low",
    "DoS": "high",
    "R2L": "high",
    "U2R": "critical",
    "Unknown": "medium",
}


class DetectionEngine:
    def __init__(self):
        self.model = joblib.load(ARTIFACT_DIR / "nids_model.joblib")
        self.preprocessor = NIDSPreprocessor.load()

    def score_record(self, record: dict) -> dict:
        """
        Score a single traffic record (dict of raw feature values).
        Returns a structured detection result dict.
        """
        row = pd.DataFrame([record], columns=FEATURE_INPUT_COLS)
        X = self.preprocessor.transform(row)

        pred_category = self.model.predict(X)[0]
        proba = self.model.predict_proba(X)[0]
        class_index = list(self.model.classes_).index(pred_category)
        confidence = float(proba[class_index])

        is_attack = pred_category != "Normal"
        severity = CATEGORY_SEVERITY.get(pred_category, "medium")

        result = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": record.get("src_ip", "N/A"),
            "dst_ip": record.get("dst_ip", "N/A"),
            "protocol_type": record.get("protocol_type"),
            "service": record.get("service"),
            "flag": record.get("flag"),
            "predicted_category": pred_category,
            "is_attack": bool(is_attack),
            "confidence": round(confidence, 4),
            "severity": severity,
        }
        return result

    def score_batch(self, records: list) -> list:
        return [self.score_record(r) for r in records]
