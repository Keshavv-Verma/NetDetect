"""
Logging & alerting layer for NetDetect Live IDS.

- Every scored record is appended to live_ids/logs/activity_log.jsonl (full audit trail)
- Records flagged as attacks are additionally appended to live_ids/logs/alerts.jsonl
- Provides read-back helpers the dashboard uses to display recent
  activity/alerts and summary stats.
"""

import json
import threading
from pathlib import Path
from collections import Counter

LOG_DIR = Path(__file__).resolve().parent / "logs"
ACTIVITY_LOG = LOG_DIR / "activity_log.jsonl"
ALERT_LOG = LOG_DIR / "alerts.jsonl"

_lock = threading.Lock()  # simple guard since Flask dev server + simulator thread both write


def _append_jsonl(path: Path, record: dict):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with _lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


def log_activity(result: dict):
    """Log every scored record (normal + attack) for the full audit trail."""
    _append_jsonl(ACTIVITY_LOG, result)
    if result.get("is_attack"):
        _append_jsonl(ALERT_LOG, result)


def _read_jsonl(path: Path, limit: int = None) -> list:
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    records = [json.loads(line) for line in lines if line.strip()]
    if limit:
        records = records[-limit:]
    return list(reversed(records))  # most recent first


def get_recent_activity(limit: int = 50) -> list:
    return _read_jsonl(ACTIVITY_LOG, limit)


def get_recent_alerts(limit: int = 50) -> list:
    return _read_jsonl(ALERT_LOG, limit)


def get_stats() -> dict:
    """Summary stats for the dashboard header cards."""
    activity = _read_jsonl(ACTIVITY_LOG)
    alerts = _read_jsonl(ALERT_LOG)

    category_counts = Counter(r["predicted_category"] for r in activity)
    severity_counts = Counter(r["severity"] for r in alerts)

    return {
        "total_analyzed": len(activity),
        "total_alerts": len(alerts),
        "normal_count": category_counts.get("Normal", 0),
        "category_counts": dict(category_counts),
        "severity_counts": dict(severity_counts),
    }


def clear_logs():
    """Utility for resetting demo state."""
    with _lock:
        for p in (ACTIVITY_LOG, ALERT_LOG):
            if p.exists():
                p.unlink()
