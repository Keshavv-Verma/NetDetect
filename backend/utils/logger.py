"""
NetDetect Structured Logging Utility.
Provides thread-safe, sanitized logging to console and persistent log files.
"""
import logging
import sys
from pathlib import Path
from backend.config.settings import LOG_DIR

LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "backend.log"

_formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Root backend logger
_logger = logging.getLogger("netdetect")
_logger.setLevel(logging.INFO)

# Console handler
if not _logger.handlers:
    _ch = logging.StreamHandler(sys.stdout)
    _ch.setLevel(logging.INFO)
    _ch.setFormatter(_formatter)
    _logger.addHandler(_ch)

    # File handler
    try:
        _fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
        _fh.setLevel(logging.INFO)
        _fh.setFormatter(_formatter)
        _logger.addHandler(_fh)
    except Exception:
        pass


def get_logger(name: str = None) -> logging.Logger:
    """Return a named child logger under the 'netdetect' namespace."""
    if name:
        return _logger.getChild(name)
    return _logger
