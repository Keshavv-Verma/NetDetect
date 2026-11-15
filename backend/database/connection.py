"""
NetDetect SQLite Database Connection Manager.
Thread-safe connection pooling, WAL mode concurrency, and table migration.
"""
import sqlite3
import threading
from pathlib import Path
from contextlib import contextmanager
from typing import Generator

from backend.config.settings import DATABASE_PATH, DB_BUSY_TIMEOUT_SECONDS
from backend.utils.logger import get_logger
from backend.utils.exceptions import DatabaseError

logger = get_logger("database")

_local = threading.local()

CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    file_hash TEXT,
    file_size_bytes INTEGER NOT NULL,
    status TEXT NOT NULL,               -- PENDING, PROCESSING, COMPLETED, FAILED
    created_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    duration_seconds REAL,
    total_packets INTEGER DEFAULT 0,
    total_flows INTEGER DEFAULT 0,
    attack_flows INTEGER DEFAULT 0,
    verdict TEXT,                       -- NORMAL, ATTACK
    risk_level TEXT,                    -- Low, Medium, High, Critical
    threat_intensity REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    peak_flow_index INTEGER,
    analyst_note TEXT,
    error_message TEXT,
    summary_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status);
CREATE INDEX IF NOT EXISTS idx_analyses_verdict ON analyses(verdict);

CREATE TABLE IF NOT EXISTS live_audit_events (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol_type TEXT,
    service TEXT,
    flag TEXT,
    predicted_category TEXT NOT NULL,
    is_attack INTEGER NOT NULL,
    confidence REAL NOT NULL,
    severity TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_live_audit_ts ON live_audit_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_live_audit_attack ON live_audit_events(is_attack);
"""


def init_db(db_path: Path = None):
    """Initialize database tables, indexes, and configure WAL journal mode."""
    db_path = db_path or DATABASE_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        conn = sqlite3.connect(str(db_path), timeout=DB_BUSY_TIMEOUT_SECONDS)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.executescript(CREATE_TABLES_SQL)
        conn.commit()
        conn.close()
        logger.info(f"Initialized SQLite database at {db_path} (WAL mode enabled).")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise DatabaseError(f"Database initialization failed: {e}")


@contextmanager
def get_db_connection(db_path: Path = None) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager yielding an active SQLite connection configured with
    row factory and timeout. Automatically commits on clean exit and rolls back on exception.
    """
    db_path = db_path or DATABASE_PATH
    conn = sqlite3.connect(str(db_path), timeout=DB_BUSY_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Transaction rolled back due to error: {e}")
        raise DatabaseError(f"Database transaction error: {e}")
    finally:
        conn.close()
