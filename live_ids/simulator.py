"""
Live traffic simulator.

Simulates live network traffic by replaying real NSL-KDD test-set records at a
configurable interval, running them through the detection engine exactly like
real incoming traffic would be.

Each record gets synthetic src_ip / dst_ip for realistic dashboard display.
"""

import os
import time
import random
import threading
import pandas as pd
from pathlib import Path

try:
    from .columns import COLUMNS
    from .detection_engine import DetectionEngine
    from .logger import log_activity
except ImportError:
    from columns import COLUMNS
    from detection_engine import DetectionEngine
    from logger import log_activity

DATA_PATH = Path(__file__).resolve().parent / "data" / "KDDTest+.txt"


def _fake_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


class TrafficSimulator:
    def __init__(self, interval_seconds: float = 1.5):
        env_interval = os.getenv("SIMULATOR_INTERVAL_SECONDS")
        try:
            self.interval = float(env_interval) if env_interval else interval_seconds
        except ValueError:
            self.interval = interval_seconds
        self.engine = DetectionEngine()
        self.df = pd.read_csv(DATA_PATH, names=COLUMNS)
        self._thread = None
        self._stop_flag = threading.Event()

    def _run_loop(self):
        while not self._stop_flag.is_set():
            row = self.df.sample(1).iloc[0].to_dict()
            row["src_ip"] = _fake_ip()
            row["dst_ip"] = _fake_ip()

            result = self.engine.score_record(row)
            log_activity(result)

            time.sleep(self.interval)

    def start(self):
        if self._thread and self._thread.is_alive():
            return  # already running
        self._stop_flag.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_flag.set()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop_flag.is_set())


_simulator_instance = None
_sim_lock = threading.Lock()


def get_simulator(interval_seconds: float = 1.5) -> TrafficSimulator:
    """Return the global singleton TrafficSimulator instance."""
    global _simulator_instance
    with _sim_lock:
        if _simulator_instance is None:
            _simulator_instance = TrafficSimulator(interval_seconds=interval_seconds)
    return _simulator_instance
