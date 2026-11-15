# 🛡️ NetDetect — AI-Powered Network Intrusion Detection System

> A Machine Learning–based Network Intrusion Detection System (NIDS) that analyzes PCAP files and live simulated network traffic to detect malicious activity using an ensemble of classifiers, anomaly detection via Bayesian fusion, and a real-time SPA streaming dashboard.

---

## Table of Contents

- [About the Project](#about-the-project)
- [Technology Stack](#technology-stack)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Installation and Setup](#installation-and-setup)
- [Datasets](#datasets)
- [Team Members](#team-members)
- [License](#license)

---

## About the Project

**NetDetect** is an intelligent intrusion detection platform combining offline packet capture (PCAP) inspection with interactive live traffic streaming detection:

1. **Upload & Analyze (PCAP Engine):** Processes `.pcap` and `.pcapng` capture files and classifies network flows as **NORMAL** or **ATTACK**. It extracts 32 flow-level features using NFStream and Scapy, runs them through a trained ensemble of Random Forest, LightGBM, and XGBoost classifiers alongside an Isolation Forest anomaly detector, and combines the outputs via Bayesian fusion to produce a final threat verdict with risk level, threat intensity, and analyst notes.
2. **Live Detection & Simulation (SPA Engine):** A real-time Single Page Application (SPA) driven by a Random Forest multi-class detector trained on NSL-KDD. It continuously replays connection records on a timer with dynamic IP mapping, provides an animated live traffic pulse strip, streams severity-coded intrusion alerts (DoS, Probe, R2L, U2R), and maintains an audit activity log.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Main Dashboard & UI | Streamlit (Native Single-Page Architecture) |
| Traffic Simulation Engine | Multi-threaded NSL-KDD Replay Generator |
| Charts and Visualization | Plotly |
| Packet Processing | NFStream, Scapy |
| ML — Supervised (PCAP) | Random Forest, XGBoost, LightGBM (scikit-learn) |
| ML — Unsupervised (PCAP) | Isolation Forest |
| ML — Supervised (Live Simulation) | Multi-Class Random Forest (NSL-KDD) |
| Fusion Strategy | Bayesian Combination (50/50 weighted) |
| Language | Python 3.10+ |

---

## Features

- **PCAP File Analysis** — Upload any `.pcap` or `.pcapng` file for instant threat analysis.
- **Interactive Live Traffic Simulation** — Replay real test records through the detection engine on a continuous timer without requiring raw-socket or root privileges.
- **Visual Live Traffic Pulse** — Real-time bar strip charting packet activity and color-coded severity levels.
- **Ensemble Classification** — Random Forest, LightGBM, and XGBoost vote together for robust supervised predictions on PCAP flows.
- **Anomaly Detection** — Isolation Forest detects zero-day and unseen attack patterns without labels.
- **Bayesian Fusion** — 50/50 weighted combination of ensemble probability and anomaly score for unified risk assessment.
- **Live Alert Feed & Audit Log** — Flagged security events logged with timestamps, source/destination IPs, protocols, and confidence metrics.
- **Human-Readable Verdict** — Risk Level (Low / Medium / High), Network Status (Safe / Suspicious / Danger), Threat Intensity %, and analyst recommendations.

---

## Project Structure

```text
NetDetect/
├── dashboard.py                  # Main Streamlit application orchestrator
├── ui/                           # Modular SOC Frontend Architecture
│   ├── styles.py                 # Centralized SOC dark design system & tokens
│   ├── layout.py                 # Sidebar navigation & topbar SOC header
│   ├── components.py             # Reusable UI widgets (cards, badges, banners)
│   ├── charts.py                 # Cohesive Plotly cybersecurity visualizations
│   └── views/                    # Section-specific views
│       ├── overview.py           # Global security posture & telemetry
│       ├── analysis.py           # PCAP upload, pipeline inspection & sample test
│       ├── results.py            # Deep threat classification & flow ledger
│       ├── visualization.py      # Transport protocol & traffic volume charts
│       ├── live_monitoring.py    # Real-time traffic simulation & pulse strip
│       └── history.py            # Session audits & disk-backed activity logs
├── feature_extraction.py         # NFStream + Scapy PCAP flow extraction
├── prediction.py                 # UNSW-NB15 ensemble prediction & Bayesian fusion
├── models/                       # UNSW-NB15 trained model artifacts
│   ├── anomaly/
│   │   └── isolation_forest.pkl
│   ├── classifiers/
│   │   ├── final_lgbm.pkl
│   │   ├── final_rf.pkl
│   │   └── final_xgb.pkl
│   ├── encoders/
│   │   └── nidss_encoders.pkl
│   ├── feature_order/
│   │   ├── if_feature_order.pkl
│   │   └── nidss_features.pkl
│   ├── scalers/
│   │   ├── if_scaler.pkl
│   │   └── nidss_scaler.pkl
│   └── threshold/
│       └── final_threshold.pkl
├── live_ids/                     # Integrated Live Detection & Simulation Subsystem
│   ├── columns.py                # NSL-KDD column schemas & attack categories
│   ├── detection_engine.py       # NSL-KDD inference engine
│   ├── logger.py                 # Thread-safe JSONL activity & alert logging
│   ├── preprocessing.py          # NSL-KDD encoder & scaler pipeline
│   ├── simulator.py              # Real-time traffic replay generator
│   ├── data/
│   │   └── KDDTest+.txt          # NSL-KDD test corpus for live simulation
│   ├── logs/
│   │   └── .gitkeep              # Runtime log directory
│   └── models/
│       ├── feature_importances.csv
│       ├── nids_model.joblib     # Multi-class Random Forest model (NSL-KDD)
│       └── preprocessor.joblib   # Fitted OneHotEncoder & StandardScaler
├── sample_pcaps/
│   └── sample_traffic.pcap       # Sample PCAP capture for testing
├── .env.example                  # Environment configuration template
├── .python-version               # Python 3.11 pin for cloud runners
├── .dockerignore                 # Docker build exclusions
├── Dockerfile                    # Containerization specification
├── packages.txt                  # Linux system packages (Streamlit Cloud / Debian)
├── requirements.txt              # Project dependencies
└── README.md
```

---

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/NetDetect.git
cd NetDetect
```

### 2. Create and Activate a Virtual Environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run NetDetect

```bash
streamlit run dashboard.py
```

Open `http://localhost:8501` in your browser to access the unified NetDetect interface. Use the sidebar to seamlessly switch between **PCAP Upload & Analyze** and **Traffic Monitoring**.

---

## Cloud Deployment Guide

### Streamlit Community Cloud (Recommended)

1. **Push your repository to GitHub:** Ensure all files, including `packages.txt`, `.python-version`, and model directories, are pushed to your remote repository on the `main` branch.
2. **Access Streamlit Cloud:** Navigate to [share.streamlit.io](https://share.streamlit.io) and sign in with your GitHub account.
3. **Create New App:**
   - Click **New app**.
   - Select your **Repository**: `your-username/NetDetect`.
   - Select your **Branch**: `main`.
   - Set **Main file path**: `dashboard.py`.
4. **Advanced Settings (Optional):**
   - Python Version: Automatically picked up as `3.11` from `.python-version`.
   - Secrets: NetDetect operates locally and does not require third-party API keys or external database credentials.
5. **Deploy:** Click **Deploy!**
   - Streamlit Cloud automatically reads `packages.txt` to install `libpcap-dev` and `libpcap0.8`.
   - Python wheels from `requirements.txt` will be installed.
6. **Verify Public URL:** Once the build completes, the app will be live at `https://<your-app-name>.streamlit.app`.

---

### Docker Deployment

To build and run NetDetect inside an isolated container:

```bash
# Build Docker image
docker build -t netdetect:latest .

# Run container on port 8501
docker run -d -p 8501:8501 --name netdetect-app netdetect:latest
```

The container includes a built-in healthcheck at `http://localhost:8501/_stcore/health`.

---

## Known Limitations

1. **Traffic Simulation vs. Live Packet Capture:** The Traffic Monitoring subsystem replays real connection records from the NSL-KDD benchmark. It runs without raw sockets or administrator privileges, making it cloud-friendly. It is not raw-socket hardware packet capture.
2. **Ephemeral Storage:** Free-tier cloud instances (like Streamlit Cloud) utilize ephemeral containers. Log files (`activity_log.jsonl`) are automatically rotated (capped at 5,000 entries) and reset on container rebuilds.
3. **PCAP Upload Size:** Configured to a maximum of 50 MB to prevent memory exhaustion (OOM) on 1 GB free-tier cloud containers.

---

## Deployment Troubleshooting

- **`ImportError: libpcap.so.0.8: cannot open shared object file`**: Ensure `packages.txt` is present at the repository root with `libpcap-dev` and `libpcap0.8`.
- **`MemoryError` / Container Killed:** Ensure uploaded PCAP files are under 50 MB.
- **Model Deserialization Warnings:** Scikit-learn unpickling warnings between minor versions (e.g. 1.8 vs 1.9) are non-breaking and handled automatically.

---

## Datasets

1. **UNSW-NB15:** Used for PCAP flow-level feature extraction and ensemble classification. Covers 9 attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms.
2. **NSL-KDD:** Used for the real-time Live Detection SPA and traffic replay simulation. Covers 4 broad categories: DoS, Probe, R2L, and U2R.

---

## Team Members

| Name | Role |
|---|---|
| Aditi Bhatnagar | Core Developer |
| Abhinay Jat | Core Developer |

B.Tech — Computer Science and Engineering

---

## License

This project is intended for educational and research purposes.
