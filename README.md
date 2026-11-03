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
├── dashboard.py                  # Main Streamlit application (PCAP & Traffic Monitoring)
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
