"""
NetDetect Configuration Module.
Centralized, immutable application and backend settings.
"""
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = BASE_DIR / "models"
SAMPLE_PCAPS_DIR = BASE_DIR / "sample_pcaps"
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
DATABASE_PATH = BASE_DIR / "netdetect.db"

# Artifact Paths
NIDSS_ENCODERS_PATH = MODELS_DIR / "encoders" / "nidss_encoders.pkl"
NIDSS_SCALER_PATH = MODELS_DIR / "scalers" / "nidss_scaler.pkl"
NIDSS_FEATURES_PATH = MODELS_DIR / "feature_order" / "nidss_features.pkl"
IF_MODEL_PATH = MODELS_DIR / "anomaly" / "isolation_forest.pkl"
IF_SCALER_PATH = MODELS_DIR / "scalers" / "if_scaler.pkl"
IF_FEATURES_PATH = MODELS_DIR / "feature_order" / "if_feature_order.pkl"
RF_MODEL_PATH = MODELS_DIR / "classifiers" / "final_rf.pkl"
LGBM_MODEL_PATH = MODELS_DIR / "classifiers" / "final_lgbm.pkl"
XGB_MODEL_PATH = MODELS_DIR / "classifiers" / "final_xgb.pkl"
FINAL_THRESHOLD_PATH = MODELS_DIR / "threshold" / "final_threshold.pkl"

# Feature Schemas (Protected Invariants)
EXPECTED_42_FEATURES = [
    'dur', 'proto', 'service', 'state',
    'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload',
    'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'stcpb', 'dtcpb',
    'dwin', 'tcprtt', 'synack', 'ackdat',
    'smean', 'dmean', 'trans_depth',
    'response_body_len', 'ct_srv_src',
    'ct_state_ttl', 'ct_dst_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm',
    'ct_dst_src_ltm', 'is_ftp_login',
    'ct_ftp_cmd', 'ct_flw_http_mthd',
    'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]

ZERO_FILL_FEATURES = [
    'rate', 'dinpkt', 'sjit', 'djit',
    'stcpb', 'dtcpb', 'ackdat',
    'ct_dst_ltm', 'ct_ftp_cmd', 'ct_src_ltm'
]

# Security & Upload Limits
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("NETDETECT_MAX_UPLOAD_BYTES", 50 * 1024 * 1024))  # 50 MB
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

# Magic Numbers for PCAP / PCAPNG
# Standard PCAP (microsecond / nanosecond, big / little endian)
PCAP_MAGIC_NUMBERS = {
    b"\xd4\xc3\xb2\xa1",  # Microsecond big-endian
    b"\xa1\xb2\xc3\xd4",  # Microsecond little-endian
    b"\x4d\x3c\xb2\xa1",  # Nanosecond big-endian
    b"\xa1\xb2\x3c\x4d",  # Nanosecond little-endian
}
# PCAPNG: Section Header Block magic \x0a\x0d\x0d\x0a
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Packet Processing Limits
MAX_PACKETS_LIMIT = int(os.getenv("NETDETECT_MAX_PACKETS", 1_000_000))
FLOW_WINDOW_SIZE = 100

# ML Decision Boundaries (DO NOT ALTER - Inherited from validated pipeline)
ENSEMBLE_WEIGHT = 0.5
IF_WEIGHT = 0.5
ATTACK_RATIO_THRESHOLD = 0.3
DEFAULT_DECISION_THRESHOLD = 0.55

# Database Settings
DB_BUSY_TIMEOUT_SECONDS = 30.0

# Protocol & Port Maps
PROTOCOL_MAP = {
    6: "tcp",
    17: "udp",
    1: "icmp",
    58: "icmpv6",
    41: "ipv6",
    132: "sctp",
    2: "igmp",
    47: "gre",
    50: "esp",
    89: "ospf",
}

PORT_TO_SERVICE = {
    80: "http",
    443: "https",
    8080: "http",
    21: "ftp",
    20: "ftp-data",
    22: "ssh",
    53: "dns",
    25: "smtp",
    110: "pop3",
    143: "imap",
    23: "telnet",
    3306: "mysql",
    5432: "postgres",
    6667: "irc",
    161: "snmp",
    67: "dhcp",
    68: "dhcp",
    123: "ntp",
    137: "netbios",
    138: "netbios",
    139: "netbios",
    445: "smb",
    3389: "rdp",
    5060: "sip",
}
