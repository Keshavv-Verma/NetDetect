
import os
import html
import sys
import time
import subprocess
import threading
import tempfile
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
# Scapy AsyncSniffer removed (replaced with NetDetect live simulation)

st.set_page_config(
    page_title="NetDetect",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
            
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600;700&display=swap');


:root {
    --bg:         #0b0f1a;
    --bg2:        #111827;
    --bg3:        #1a2235;
    --border:     #1e2d45;
    --accent:     #00d4ff;
    --accent2:    #7c3aed;
    --green:      #10b981;
    --yellow:     #f59e0b;
    --red:        #ef4444;
    --text:       #e2e8f0;
    --text-muted: #64748b;
    --mono:       'Space Mono', monospace;
    --sans:       'DM Sans', sans-serif;
}

html, body, [class*="css"] {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--sans) !important;
}

#MainMenu, 
footer, 
[data-testid="stDeployButton"], 
.stDeployButton, 
[data-testid="stAppDeployButton"], 
.stAppDeployButton,
[data-testid="stToolbarActions"],
.stToolbarActions,
[data-testid="stDecoration"] {
    display: none !important;
    visibility: hidden !important;
    opacity: 0 !important;
    height: 0 !important;
    width: 0 !important;
    pointer-events: none !important;
}

header[data-testid="stHeader"], [data-testid="stToolbar"] {
    background: transparent !important;
}

[data-testid="stExpandSidebarButton"], 
[data-testid="stSidebarCollapseButton"], 
[data-testid="stSidebarCollapsedControl"] {
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    z-index: 1000000 !important;
}

[data-testid="stExpandSidebarButton"] {
    position: fixed !important;
    top: 14px !important;
    left: 14px !important;
    background: #111827 !important;
    border: 1px solid #00d4ff !important;
    border-radius: 8px !important;
    padding: 4px 8px !important;
    box-shadow: 0 0 12px rgba(0, 212, 255, 0.35) !important;
}

[data-testid="stExpandSidebarButton"]:hover {
    background: #1a2235 !important;
    border-color: #00d4ff !important;
    box-shadow: 0 0 18px rgba(0, 212, 255, 0.6) !important;
}

[data-testid="stExpandSidebarButton"] button,
[data-testid="stExpandSidebarButton"] svg,
[data-testid="stExpandSidebarButton"] span {
    color: #00d4ff !important;
    fill: #00d4ff !important;
    visibility: visible !important;
}

[data-testid="stSidebarCollapseButton"] button {
    color: var(--accent) !important;
    background-color: var(--bg2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    transition: all 0.2s ease !important;
}

[data-testid="stSidebarCollapseButton"] button:hover {
    border-color: var(--accent) !important;
    color: #fff !important;
    box-shadow: 0 0 10px rgba(0, 212, 255, 0.3) !important;
}
.block-container { padding-top: 3rem !important; padding-bottom: 2rem !important; }

[data-testid="stSidebar"] {
    background: var(--bg2) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text) !important; }

.ng-topbar {
    background: linear-gradient(135deg, var(--bg2) 0%, #0d1525 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.4rem 2rem;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: relative;
    overflow: hidden;
}
.ng-topbar::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent2), var(--accent), var(--green));
}
.ng-logo { display: flex; align-items: center; gap: 1rem; }
.ng-logo-icon {
    width: 44px; height: 44px;
    background: linear-gradient(135deg, var(--accent2), var(--accent));
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.3rem;
}
.ng-logo-text h1 {
    font-family: var(--mono) !important;
    font-size: 1.3rem !important;
    font-weight: 700 !important;
    color: var(--accent) !important;
    margin: 0 !important; padding: 0 !important;
    letter-spacing: 0.05em;
}
.ng-logo-text p {
    font-size: 0.75rem !important;
    color: var(--text-muted) !important;
    margin: 0 !important;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}
.ng-status-pill {
    font-family: var(--mono);
    font-size: 0.72rem;
    padding: 0.35rem 0.85rem;
    border-radius: 20px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}
.ng-status-pill.ready {
    background: rgba(16,185,129,0.12);
    color: var(--green);
    border: 1px solid rgba(16,185,129,0.3);
}
.ng-status-pill.scanning {
    background: rgba(0,212,255,0.12);
    color: var(--accent);
    border: 1px solid rgba(0,212,255,0.3);
    animation: pulse-glow 1.5s ease-in-out infinite;
}
.ng-status-pill.alert {
    background: rgba(239,68,68,0.12);
    color: var(--red);
    border: 1px solid rgba(239,68,68,0.3);
}
@keyframes pulse-glow {
    0%, 100% { box-shadow: 0 0 4px rgba(0,212,255,0.3); }
    50%       { box-shadow: 0 0 12px rgba(0,212,255,0.6); }
}

.ng-metric {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem 1.4rem;
    position: relative;
    overflow: hidden;
    transition: transform 0.2s, border-color 0.2s;
}
.ng-metric:hover { transform: translateY(-2px); border-color: var(--accent); }
.ng-metric::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 3px;
    border-radius: 0 0 12px 12px;
}
.ng-metric.blue::after   { background: var(--accent); }
.ng-metric.purple::after { background: var(--accent2); }
.ng-metric.green::after  { background: var(--green); }
.ng-metric.red::after    { background: var(--red); }
.ng-metric.yellow::after { background: var(--yellow); }
.ng-metric-label {
    font-size: 0.7rem !important;
    color: var(--text-muted) !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.4rem;
    font-weight: 600;
}
.ng-metric-value {
    font-family: var(--mono) !important;
    font-size: 2rem !important;
    font-weight: 700 !important;
    line-height: 1.1;
    margin-bottom: 0.3rem;
}
.ng-metric-value.blue   { color: var(--accent) !important; }
.ng-metric-value.purple { color: var(--accent2) !important; }
.ng-metric-value.green  { color: var(--green) !important; }
.ng-metric-value.red    { color: var(--red) !important; }
.ng-metric-value.yellow { color: var(--yellow) !important; }
.ng-metric-sub {
    font-size: 0.72rem !important;
    color: var(--text-muted) !important;
}
.ng-metric-icon {
    position: absolute; top: 1rem; right: 1rem;
    font-size: 1.4rem; opacity: 0.15;
}

[data-testid="stVerticalBlockBorderWrapper"] {
    background: var(--bg2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    padding: 0.4rem 0.6rem !important;
    margin-bottom: 1.2rem !important;
}

.ng-panel-title {
    font-family: var(--mono) !important;
    font-size: 0.78rem !important;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text-muted) !important;
    font-weight: 700 !important;
    margin-bottom: 1rem;
    display: flex; align-items: center; gap: 0.5rem;
}
.ng-panel-title span { color: var(--accent); font-size: 1rem; }

.ng-verdict {
    display: inline-flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.6rem 1.4rem;
    border-radius: 8px;
    font-family: var(--mono);
    font-size: 1.1rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    margin-bottom: 0.5rem;
}
.ng-verdict.safe {
    background: rgba(16,185,129,0.12);
    color: var(--green);
    border: 1px solid rgba(16,185,129,0.4);
}
.ng-verdict.attack {
    background: rgba(239,68,68,0.12);
    color: var(--red);
    border: 1px solid rgba(239,68,68,0.4);
    animation: threat-pulse 2s ease-in-out infinite;
}
@keyframes threat-pulse {
    0%, 100% { box-shadow: 0 0 6px rgba(239,68,68,0.2); }
    50%       { box-shadow: 0 0 20px rgba(239,68,68,0.5); }
}

[data-testid="stFileUploader"] {
    background: var(--bg3) !important;
    border: 2px dashed var(--border) !important;
    border-radius: 12px !important;
    transition: border-color 0.2s;
}
[data-testid="stFileUploader"]:hover {
    border-color: var(--accent) !important;
}
[data-testid="stFileUploader"] * { color: var(--text) !important; }

.stButton > button {
    background: linear-gradient(135deg, var(--accent2), var(--accent)) !important;
    color: #fff !important;
    border: none !important;
    border-radius: 8px !important;
    font-family: var(--mono) !important;
    font-weight: 700 !important;
    font-size: 0.82rem !important;
    letter-spacing: 0.06em !important;
    text-transform: uppercase !important;
    padding: 0.6rem 1.4rem !important;
    transition: opacity 0.2s, transform 0.15s !important;
    width: 100%;
}
.stButton > button:hover {
    opacity: 0.88 !important;
    transform: translateY(-1px) !important;
}
.stButton > button:active { transform: translateY(0px) !important; }

.stop-btn .stButton > button {
    background: linear-gradient(135deg, #7f1d1d, var(--red)) !important;
}

.stSpinner > div { border-top-color: var(--accent) !important; }
.stProgress > div > div > div {
    background: linear-gradient(90deg, var(--accent2), var(--accent)) !important;
}

.js-plotly-plot .plotly { background: transparent !important; }

.ng-analyst-note {
    background: rgba(0,212,255,0.05);
    border-left: 3px solid var(--accent);
    border-radius: 0 8px 8px 0;
    padding: 0.8rem 1.2rem;
    font-size: 0.88rem;
    color: var(--text);
    margin-top: 0.8rem;
}

.ng-callout {
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.2rem;
    font-size: 0.85rem;
    line-height: 1.7;
    color: var(--text);
}
.ng-callout b { color: var(--accent); }

.stSelectbox > div > div, .stSlider { background: transparent !important; }
[data-baseweb="select"] > div {
    background: var(--bg3) !important;
    border-color: var(--border) !important;
    color: var(--text) !important;
}

[data-testid="stExpander"] {
    background: var(--bg3) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
}
[data-testid="stExpander"] summary { color: var(--text) !important; }

hr { border-color: var(--border) !important; }

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg2); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent); }

/* ---------- Traffic Monitoring Native SPA Styles ---------- */
.tm-status-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-family: var(--mono);
    font-size: 0.75rem;
    letter-spacing: 0.05em;
    padding: 6px 14px;
    border: 1px solid var(--border);
    border-radius: 20px;
    background: var(--bg2);
    color: var(--text-muted);
}
.tm-status-pill.live {
    border-color: #4FD1C5;
    color: #4FD1C5;
    background: rgba(79, 209, 197, 0.06);
}
.tm-status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #475569;
}
.tm-status-dot.live {
    background: #4FD1C5;
    box-shadow: 0 0 0 0 rgba(79, 209, 197, 0.7);
    animation: tm-pulse-dot 1.6s infinite;
}
@keyframes tm-pulse-dot {
    0% { box-shadow: 0 0 0 0 rgba(79, 209, 197, 0.6); }
    70% { box-shadow: 0 0 0 8px rgba(79, 209, 197, 0); }
    100% { box-shadow: 0 0 0 0 rgba(79, 209, 197, 0); }
}

/* Pulse strip */
.pulse-wrap {
    border: 1px solid var(--border);
    background: #111827;
    border-radius: 8px;
    padding: 10px 18px;
    margin-bottom: 1.2rem;
}
.pulse-label {
    font-family: var(--mono);
    font-size: 0.68rem;
    color: var(--text-muted);
    letter-spacing: 0.08em;
    margin-bottom: 6px;
}
#pulse-strip {
    display: flex;
    align-items: flex-end;
    gap: 3px;
    height: 36px;
    overflow-x: hidden;
}
.pulse-bar {
    flex: 1;
    min-width: 3px;
    max-width: 14px;
    min-height: 4px;
    border-radius: 2px 2px 0 0;
    background: #1e2d45;
    transition: height 0.25s ease;
}
.pulse-bar.info { background: #4FD1C5; }
.pulse-bar.low { background: #F2C94C; }
.pulse-bar.high { background: #F2994A; }
.pulse-bar.critical { background: #EB5757; }

/* Stats row */
.stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 1.4rem;
}
.stat-card {
    background: #111827;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 18px;
}
.stat-card .label {
    font-family: var(--mono);
    font-size: 0.68rem;
    color: var(--text-muted);
    letter-spacing: 0.06em;
    margin-bottom: 6px;
}
.stat-card .value {
    font-family: var(--mono);
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--text);
}
.stat-card.alert .value { color: #EB5757; }
.stat-card.normal .value { color: #4FD1C5; }

/* Content Grid */
.content-grid {
    display: grid;
    grid-template-columns: 1fr 1.6fr;
    gap: 16px;
}
.panel {
    background: #111827;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
}
.panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    background: #1a2235;
    font-family: var(--mono);
    font-size: 0.75rem;
    letter-spacing: 0.05em;
    color: var(--text);
}
.panel-header .count {
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--text-muted);
}
.panel-body {
    max-height: 520px;
    overflow-y: auto;
}

/* Alert list */
.alert-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 0.75rem;
}
.alert-row:last-child { border-bottom: none; }
.sev-tag {
    font-size: 0.62rem;
    letter-spacing: 0.06em;
    padding: 2px 6px;
    border-radius: 3px;
    text-transform: uppercase;
    font-weight: 700;
    width: 60px;
    text-align: center;
    flex-shrink: 0;
}
.sev-tag.info { background: rgba(79,209,197,0.15); color: #4FD1C5; }
.sev-tag.low { background: rgba(242,201,76,0.15); color: #F2C94C; }
.sev-tag.high { background: rgba(242,153,74,0.15); color: #F2994A; }
.sev-tag.critical { background: rgba(235,87,87,0.18); color: #EB5757; }
.alert-cat { color: var(--text); font-weight: 600; width: 68px; flex-shrink: 0; }
.alert-ip { color: var(--text-muted); flex: 1; font-size: 0.73rem; }
.alert-time { color: var(--text-muted); font-size: 0.7rem; flex-shrink: 0; }

/* Activity table */
.tm-table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--mono);
    font-size: 0.75rem;
}
.tm-table thead th {
    position: sticky;
    top: 0;
    background: #1a2235;
    text-align: left;
    padding: 9px 12px;
    color: var(--text-muted);
    font-weight: 600;
    font-size: 0.7rem;
    letter-spacing: 0.04em;
    border-bottom: 1px solid var(--border);
}
.tm-table tbody td {
    padding: 8px 12px;
    border-bottom: 1px solid #172234;
    color: var(--text-muted);
    font-size: 0.73rem;
}
.tm-table tbody tr.is-attack td { color: var(--text); }
.tm-table tbody tr.is-attack { background: rgba(235, 87, 87, 0.06); }
.badge {
    padding: 2px 7px;
    border-radius: 3px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.03em;
}
.badge.normal { background: rgba(79,209,197,0.12); color: #4FD1C5; }
.badge.attack { background: rgba(235,87,87,0.15); color: #EB5757; }
.tm-empty-state {
    padding: 40px 20px;
    text-align: center;
    color: var(--text-muted);
    font-family: var(--mono);
    font-size: 0.8rem;
}

@media (max-width: 900px) {
    .stats-row { grid-template-columns: repeat(2, 1fr); }
    .content-grid { grid-template-columns: 1fr; }
}

</style>
""", unsafe_allow_html=True)


def panel_title(icon, text):
    st.markdown(
        f'<div class="ng-panel-title"><span>{icon}</span> {text}</div>',
        unsafe_allow_html=True,
    )

def html_panel(icon, title, body_html):
    st.markdown(f"""
    <div style="background:#111827;border:1px solid #1e2d45;border-radius:12px;
                padding:1.4rem 1.6rem;margin-bottom:1.2rem;">
      <div class="ng-panel-title"><span>{icon}</span> {title}</div>
      {body_html}
    </div>
    """, unsafe_allow_html=True)


def _plotly_layout(title="", height=320):
    return dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="DM Sans, sans-serif", color="#e2e8f0", size=11),
        title=dict(text=title, font=dict(size=13, color="#64748b",
                                          family="Space Mono, monospace")),
        margin=dict(l=10, r=10, t=40 if title else 10, b=10),
        height=height,
        showlegend=True,
        legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor="rgba(0,0,0,0)",
                    font=dict(size=10)),
        xaxis=dict(gridcolor="#1e2d45", zerolinecolor="#1e2d45",
                   tickfont=dict(size=10)),
        yaxis=dict(gridcolor="#1e2d45", zerolinecolor="#1e2d45",
                   tickfont=dict(size=10)),
    )


def render_topbar(status="ready"):
    status_map = {
        "ready":    ("SYSTEM READY",       "ready"),
        "scanning": ("ANALYZING...",       "scanning"),
        "attack":   ("⚠ THREAT DETECTED",  "alert"),
        "normal":   ("ALL CLEAR",          "ready"),
        "live":     ("LIVE STREAM ACTIVE", "scanning"),
    }
    label, cls = status_map.get(status, ("READY", "ready"))
    ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    st.markdown(f"""
    <div class="ng-topbar">
      <div class="ng-logo">
        <div class="ng-logo-icon">🛡️</div>
        <div class="ng-logo-text">
          <h1>NetDetect</h1>
          <p>AI-Powered Network Intrusion Detection System</p>
        </div>
      </div>
      <div style="text-align:right">
        <div class="ng-status-pill {cls}">{label}</div>
        <div style="font-size:0.68rem;color:#334155;margin-top:0.3rem;
                    font-family:'Space Mono',monospace;">{ts}</div>
      </div>
    </div>
    """, unsafe_allow_html=True)


def render_metric(label, value, sub, color="blue", icon=""):
    st.markdown(f"""
    <div class="ng-metric {color}">
      <div class="ng-metric-icon">{icon}</div>
      <div class="ng-metric-label">{label}</div>
      <div class="ng-metric-value {color}">{value}</div>
      <div class="ng-metric-sub">{sub}</div>
    </div>
    """, unsafe_allow_html=True)


def human_bytes(n):
    for unit in ['B','KB','MB','GB']:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def plain_english_risk(risk, verdict, note):
    if verdict == "NORMAL":
        headline = "✅ Your network looks healthy"
        body = ("Our AI scanned every connection in this file and found no signs of "
                "hacking, data theft, or unusual activity. Think of it like a security "
                "guard who watched every person enter and leave a building — nobody "
                "suspicious was spotted.")
    else:
        headline = "⚠️ Suspicious activity was detected"
        body = ("Our AI found patterns in this network traffic that look like they could "
                "be an attack — similar to noticing someone trying every door handle in "
                "a building. This doesn't mean damage has been done, but it's worth "
                "asking your IT team to take a closer look.")
    return headline, body


MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

@st.cache_resource(show_spinner=False)
def load_artifacts_cached():
    try:
        from prediction import load_artifacts
        return load_artifacts(MODELS_DIR), None
    except Exception as e:
        return None, str(e)


def run_full_analysis(pcap_path):
    try:
        from feature_extraction import extract_all_features
        from prediction import load_artifacts, run_prediction

        with st.spinner(""):
            st.markdown("""
            <div class="ng-callout">
              <b>Step 1 / 3</b> — Reading PCAP file and extracting network flows…
            </div>""", unsafe_allow_html=True)
            raw_df = extract_all_features(pcap_path)

        with st.spinner(""):
            st.markdown("""
            <div class="ng-callout">
              <b>Step 2 / 3</b> — Running AI threat detection models…
            </div>""", unsafe_allow_html=True)
            artifacts, err = load_artifacts_cached()
            if err:
                raise RuntimeError(err)
            result = run_prediction(raw_df, artifacts)

        st.markdown("""
        <div class="ng-callout">
          <b>Step 3 / 3</b> — Generating report… done ✓
        </div>""", unsafe_allow_html=True)
        time.sleep(0.4)
        return result, raw_df, None

    except Exception as e:
        return None, None, str(e)


def mock_result(seed=42):
    rng = np.random.default_rng(seed)
    n = rng.integers(80, 300)
    scores = rng.beta(2, 5, n).tolist()
    attack_count = int(sum(s > 0.5 for s in scores))
    ratio = attack_count / n
    verdict = "ATTACK" if ratio >= 0.3 else "NORMAL"
    mean_score = float(np.mean(scores))
    return {
        "verdict":           verdict,
        "total_flows":       n,
        "risk_level":        "High" if verdict == "ATTACK" else ("Medium" if mean_score > 0.35 else "Low"),
        "network_status":    "Danger" if verdict == "ATTACK" else "Safe",
        "threat_intensity":  round(mean_score * 100, 1),
        "traffic_behavior":  "Erratic" if verdict == "ATTACK" else "Stable",
        "peak_flow_index":   int(np.argmax(scores)) + 1,
        "analyst_note":      ("High threat intensity detected. Immediate action recommended."
                              if verdict == "ATTACK" else
                              "Traffic appears normal. No immediate action required."),
        "all_flow_scores":   [round(s, 4) for s in scores],
        "confidence":        round(min(abs(mean_score - 0.4) * 250, 100), 1),
    }


def mock_raw_df(n):
    rng = np.random.default_rng(0)
    protos   = rng.choice(['TCP','UDP','ICMP'], n, p=[0.7,0.25,0.05])
    services = rng.choice(['http','https','dns','-','ssh','ftp'], n, p=[0.25,0.35,0.15,0.15,0.07,0.03])
    return pd.DataFrame({
        'proto':   protos,
        'service': services,
        'sbytes':  rng.integers(100, 50000, n),
        'dbytes':  rng.integers(50, 30000, n),
        'spkts':   rng.integers(1, 200, n),
        'dpkts':   rng.integers(1, 100, n),
        'dur':     rng.uniform(0.001, 60, n).round(4),
        'state':   rng.choice(['CON','FIN','RST','INT'], n, p=[0.5,0.3,0.15,0.05]),
    })


def render_results(result, raw_df, filename="uploaded.pcap"):
    scores       = np.array(result["all_flow_scores"])
    n            = result["total_flows"]
    attack_flows = int(sum(scores >= 0.5))
    safe_flows   = n - attack_flows


    v_cls   = "attack" if result["verdict"] == "ATTACK" else "safe"
    v_icon  = "⚠️"    if result["verdict"] == "ATTACK" else "✅"
    v_label = "THREAT DETECTED" if result["verdict"] == "ATTACK" else "NETWORK SAFE"
    headline, body = plain_english_risk(result["risk_level"], result["verdict"], result["analyst_note"])
    st.markdown(f"""
    <div style="background:#111827;border:1px solid #1e2d45;border-radius:12px;
                padding:1.4rem 1.6rem;margin-bottom:1rem;">
      <div class="ng-panel-title"><span>📋</span> Analysis Result — {filename}</div>
      <div class="ng-verdict {v_cls}">{v_icon} &nbsp; {v_label}</div>
      <div style="font-size:1.05rem;font-weight:600;margin:0.6rem 0 0.3rem;color:#e2e8f0;">
        {headline}
      </div>
      <div style="font-size:0.88rem;color:#94a3b8;line-height:1.7;">{body}</div>
      <div class="ng-analyst-note">
        <b>AI Note:</b> {result["analyst_note"]}
      </div>
    </div>
    """, unsafe_allow_html=True)

    cols = st.columns(4)
    metric_data = [
        ("Total Connections", str(n),              "network flows analyzed",               "blue",   "🌐"),
        ("Threat Level",      result["risk_level"], f"{result['threat_intensity']}% intensity",
         "red" if result["risk_level"] == "High" else ("yellow" if result["risk_level"] == "Medium" else "green"), "🎯"),
        ("Suspicious Flows",  str(attack_flows),   f"{round(attack_flows/n*100,1)}% of traffic",
         "red" if attack_flows > 0 else "green", "⚠️"),
        ("AI Confidence",     f"{result['confidence']}%", "model certainty",              "purple", "🤖"),
    ]
    for col, (lbl, val, sub, clr, ico) in zip(cols, metric_data):
        with col:
            render_metric(lbl, val, sub, clr, ico)

    st.markdown("<br>", unsafe_allow_html=True)


    col1, col2 = st.columns([1.6, 1])

    with col1:
        with st.container(border=True):
            panel_title("📈", "Per-Flow Threat Score")
            x         = list(range(1, n + 1))
            color_arr = ["#ef4444" if s >= 0.5 else "#10b981" for s in scores]
            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=x, y=scores.tolist(),
                marker_color=color_arr,
                hovertemplate="Flow %{x}<br>Score: %{y:.3f}<extra></extra>",
            ))
            fig.add_hline(y=0.5, line_dash="dash", line_color="#f59e0b",
                          annotation_text="Risk Threshold",
                          annotation_font_color="#f59e0b",
                          annotation_font_size=10)
            layout = _plotly_layout(height=280)
            layout.update(bargap=0.1)
            fig.update_layout(**layout)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with col2:
        with st.container(border=True):
            panel_title("🍩", "Traffic Breakdown")
            fig2 = go.Figure(go.Pie(
                labels=["Safe Flows", "Suspicious Flows"],
                values=[safe_flows, attack_flows],
                hole=0.62,
                marker_colors=["#10b981", "#ef4444"],
                textfont_size=11,
                hovertemplate="%{label}: %{value} flows (%{percent})<extra></extra>",
            ))
            fig2.add_annotation(
                text=f"{round(safe_flows/n*100)}%<br><span style='font-size:10px'>Safe</span>",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16, color="#10b981", family="Space Mono"))
            layout2 = _plotly_layout(height=280)
            layout2.update(showlegend=True)
            fig2.update_layout(**layout2)
            st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})

    if raw_df is not None:
        col3, col4 = st.columns(2)

        with col3:
            with st.container(border=True):
                panel_title("📡", "Protocol Distribution")
                proto_col    = 'proto' if 'proto' in raw_df.columns else raw_df.columns[0]
                proto_counts = raw_df[proto_col].value_counts().head(8)
                fig3 = go.Figure(go.Bar(
                    x=proto_counts.index.tolist(),
                    y=proto_counts.values.tolist(),
                    marker=dict(
                        color=proto_counts.values.tolist(),
                        colorscale=[[0, "#7c3aed"], [0.5, "#00d4ff"], [1, "#10b981"]],
                        showscale=False,
                    ),
                    hovertemplate="%{x}: %{y} flows<extra></extra>",
                ))
                fig3.update_layout(**_plotly_layout(height=250))
                st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})

        with col4:
            with st.container(border=True):
                panel_title("🔗", "Top Services Contacted")
                svc_col = 'service' if 'service' in raw_df.columns else None
                if svc_col:
                    svc_counts = raw_df[svc_col].value_counts().head(8)
                    fig4 = go.Figure(go.Bar(
                        x=svc_counts.values.tolist(),
                        y=svc_counts.index.tolist(),
                        orientation='h',
                        marker=dict(
                            color=svc_counts.values.tolist(),
                            colorscale=[[0, "#1a2235"], [1, "#00d4ff"]],
                            showscale=False,
                        ),
                        hovertemplate="%{y}: %{x} flows<extra></extra>",
                    ))
                    fig4.update_layout(**_plotly_layout(height=250))
                    st.plotly_chart(fig4, use_container_width=True, config={"displayModeBar": False})
                else:
                    st.info("Service data not available in this capture.")

    with st.container(border=True):
        panel_title("📊", "Threat Score Distribution — How Risky Are the Connections?")
        st.markdown("""
        <div style="font-size:0.8rem;color:#64748b;margin-bottom:0.8rem;">
          Each bar shows how many connections fall into a threat-score range.
          Bars to the <b style="color:#10b981">left (green)</b> = safe.
          Bars to the <b style="color:#ef4444">right (red)</b> = suspicious.
        </div>
        """, unsafe_allow_html=True)
        bins = np.linspace(0, 1, 21)
        hist, edges = np.histogram(scores, bins=bins)
        bar_colors  = ["#10b981" if (e + edges[i+1])/2 < 0.5 else "#ef4444"
                       for i, e in enumerate(edges[:-1])]
        fig5 = go.Figure(go.Bar(
            x=[(edges[i]+edges[i+1])/2 for i in range(len(hist))],
            y=hist.tolist(),
            marker_color=bar_colors,
            width=0.045,
            hovertemplate="Score %.2f-%.2f: %%{y} flows<extra></extra>",
        ))
        fig5.add_vline(x=0.5, line_dash="dash", line_color="#f59e0b",
                       annotation_text="Risk boundary",
                       annotation_font_color="#f59e0b",
                       annotation_font_size=10)
        l5 = _plotly_layout(height=200)
        l5["xaxis"]["title"] = "Threat Score (0 = safe, 1 = dangerous)"
        l5["yaxis"]["title"] = "# Connections"
        fig5.update_layout(**l5)
        st.plotly_chart(fig5, use_container_width=True, config={"displayModeBar": False})

    if raw_df is not None and 'sbytes' in raw_df.columns:
        with st.container(border=True):
            panel_title("📦", "Data Volume per Connection")
            st.markdown("""
            <div style="font-size:0.8rem;color:#64748b;margin-bottom:0.8rem;">
              Shows how much data was sent and received in each connection.
              Unusually large transfers might indicate data theft.
            </div>
            """, unsafe_allow_html=True)
            sample_n  = min(150, len(raw_df))
            sample_df = raw_df.head(sample_n)
            fig6 = go.Figure()
            fig6.add_trace(go.Scatter(
                y=sample_df['sbytes'].tolist(), name="Sent (bytes)",
                fill='tozeroy', line=dict(color="#7c3aed", width=1.5),
                fillcolor="rgba(124,58,237,0.15)",
                hovertemplate="Flow %{x}<br>Sent: %{y:,.0f} bytes<extra></extra>",
            ))
            if 'dbytes' in raw_df.columns:
                fig6.add_trace(go.Scatter(
                    y=sample_df['dbytes'].tolist(), name="Received (bytes)",
                    fill='tozeroy', line=dict(color="#00d4ff", width=1.5),
                    fillcolor="rgba(0,212,255,0.1)",
                    hovertemplate="Flow %{x}<br>Received: %{y:,.0f} bytes<extra></extra>",
                ))
            fig6.update_layout(**_plotly_layout(height=220))
            st.plotly_chart(fig6, use_container_width=True, config={"displayModeBar": False})

    with st.expander("📖  What do these terms mean? (Click to expand)"):
        st.markdown("""
        <div class="ng-callout">
        <b>Network Flow</b> — A single conversation between two devices (like a phone call between two people).<br><br>
        <b>Threat Score</b> — A number from 0 to 1 our AI assigns to each connection.
        Near 0 = safe. Near 1 = suspicious.<br><br>
        <b>Protocol</b> — The "language" two devices use to communicate.
        TCP = reliable (like a registered letter); UDP = fast but unverified (like a postcard).<br><br>
        <b>Service</b> — The type of activity in a connection.
        HTTPS = secure web browsing; DNS = looking up website names; SSH = remote computer access.<br><br>
        <b>Isolation Forest</b> — One of our AI models. It looks for connections that are
        unusually different from normal traffic — like spotting someone wearing a costume at a business meeting.<br><br>
        <b>Ensemble Model</b> — Three separate AI classifiers (XGBoost, LightGBM, Random Forest) that vote on
        whether each connection is safe or suspicious. Majority rules.<br><br>
        <b>PCAP File</b> — A recording of all network traffic, like a CCTV tape for your internet connection.
        </div>
        """, unsafe_allow_html=True)

    if raw_df is not None:
        with st.expander("🔬  Raw Flow Data (for technical users)"):
            show_cols = [c for c in ['proto','service','state','sbytes','dbytes','spkts','dpkts','dur','sttl']
                         if c in raw_df.columns]
            st.dataframe(
                raw_df[show_cols].head(200).style.set_properties(**{
                    'background-color': '#111827',
                    'color': '#e2e8f0',
                    'border': '1px solid #1e2d45'
                }),
                use_container_width=True,
            )




# ══════════════════════════════════════════════════════════════════════════════
# NATIVE TRAFFIC MONITORING ENGINE (NSL-KDD CLASSIFIER & SIMULATOR)
# ══════════════════════════════════════════════════════════════════════════════

def _format_time(iso_str):
    if not iso_str:
        return "--:--:--"
    try:
        s = str(iso_str).strip()
        if " " in s:
            s = s.replace(" ", "T")
        if "T" in s:
            return s.split("T")[1].split(".")[0].split("+")[0]
        return s.split(".")[0].split("+")[0][:8]
    except Exception:
        return str(iso_str)[:8]


def _build_traffic_monitoring_html(stats, alerts, activity, is_running):
    total = stats.get("total_analyzed", 0)
    alerts_count = stats.get("total_alerts", 0)
    normal_count = stats.get("normal_count", 0)
    rate = f"{round((alerts_count / total) * 100)}%" if total > 0 else "0%"

    # Pulse strip bars (last 60 records, newest on right)
    heights = {"info": 8, "low": 16, "high": 26, "critical": 34}
    pulse_records = list(reversed(activity[:60]))
    pulse_bars = []
    idle_count = max(0, 60 - len(pulse_records))
    for _ in range(idle_count):
        pulse_bars.append('<div class="pulse-bar" style="height:4px"></div>')
    for r in pulse_records:
        sev = r.get("severity", "info")
        h = heights.get(sev, 6)
        pulse_bars.append(f'<div class="pulse-bar {sev}" style="height:{h}px"></div>')
    pulse_strip_html = "".join(pulse_bars)

    # Alerts feed list
    if not alerts:
        alerts_body_html = '<div class="tm-empty-state">No alerts yet &mdash; start monitoring to begin analysis.</div>'
    else:
        alert_rows = []
        for a in alerts:
            sev = a.get("severity", "info")
            cat = html.escape(str(a.get("predicted_category", "Unknown")))
            src = html.escape(str(a.get("src_ip", "N/A")))
            dst = html.escape(str(a.get("dst_ip", "N/A")))
            ts = _format_time(a.get("timestamp"))
            alert_rows.append(
                f'<div class="alert-row">'
                f'<span class="sev-tag {sev}">{sev}</span>'
                f'<span class="alert-cat">{cat}</span>'
                f'<span class="alert-ip">{src} &rarr; {dst}</span>'
                f'<span class="alert-time">{ts}</span>'
                f'</div>'
            )
        alerts_body_html = "".join(alert_rows)

    # Activity table
    if not activity:
        activity_body_html = '<tr><td colspan="8" class="tm-empty-state">No activity recorded yet.</td></tr>'
    else:
        rows = []
        for r in activity:
            is_atk = r.get("is_attack", False)
            cls = "is-attack" if is_atk else ""
            badge_cls = "attack" if is_atk else "normal"
            badge_text = "ATTACK" if is_atk else "NORMAL"
            ts = _format_time(r.get("timestamp"))
            src = html.escape(str(r.get("src_ip", "N/A")))
            dst = html.escape(str(r.get("dst_ip", "N/A")))
            proto = html.escape(str(r.get("protocol_type", "-")))
            srv = html.escape(str(r.get("service", "-")))
            cat = html.escape(str(r.get("predicted_category", "Normal")))
            conf = f"{int(r.get('confidence', 0) * 100)}%"
            rows.append(
                f'<tr class="{cls}">'
                f'<td>{ts}</td>'
                f'<td>{src}</td>'
                f'<td>{dst}</td>'
                f'<td>{proto}</td>'
                f'<td>{srv}</td>'
                f'<td>{cat}</td>'
                f'<td>{conf}</td>'
                f'<td><span class="badge {badge_cls}">{badge_text}</span></td>'
                f'</tr>'
            )
        activity_body_html = "".join(rows)

    return (
        f'<div class="pulse-wrap">'
        f'<div class="pulse-label">LIVE TRAFFIC PULSE</div>'
        f'<div id="pulse-strip">{pulse_strip_html}</div>'
        f'</div>'
        f'<div class="stats-row">'
        f'<div class="stat-card"><div class="label">RECORDS ANALYZED</div><div class="value">{total}</div></div>'
        f'<div class="stat-card alert"><div class="label">ALERTS RAISED</div><div class="value">{alerts_count}</div></div>'
        f'<div class="stat-card normal"><div class="label">NORMAL TRAFFIC</div><div class="value">{normal_count}</div></div>'
        f'<div class="stat-card"><div class="label">DETECTION RATE</div><div class="value">{rate}</div></div>'
        f'</div>'
        f'<div class="content-grid">'
        f'<div class="panel">'
        f'<div class="panel-header"><span>ALERT FEED</span><span class="count">{len(alerts)} ALERTS</span></div>'
        f'<div class="panel-body">{alerts_body_html}</div>'
        f'</div>'
        f'<div class="panel">'
        f'<div class="panel-header"><span>TRAFFIC ACTIVITY LOG</span><span class="count">{len(activity)} RECORDS</span></div>'
        f'<div class="panel-body">'
        f'<table class="tm-table">'
        f'<thead><tr><th>Time</th><th>Source IP</th><th>Dest IP</th><th>Proto</th><th>Service</th><th>Category</th><th>Conf.</th><th>Status</th></tr></thead>'
        f'<tbody>{activity_body_html}</tbody>'
        f'</table>'
        f'</div>'
        f'</div>'
        f'</div>'
    )


def _render_monitoring_markup(html_markup):
    if hasattr(st, "html"):
        st.html(html_markup)
    else:
        st.markdown(html_markup, unsafe_allow_html=True)


@st.fragment(run_every=1.5)
def _render_live_monitoring_fragment():
    from live_ids.logger import get_stats, get_recent_alerts, get_recent_activity
    stats = get_stats()
    alerts = get_recent_alerts(25)
    activity = get_recent_activity(40)
    html_markup = _build_traffic_monitoring_html(stats, alerts, activity, is_running=True)
    _render_monitoring_markup(html_markup)


@st.fragment()
def _render_static_monitoring_fragment():
    from live_ids.logger import get_stats, get_recent_alerts, get_recent_activity
    stats = get_stats()
    alerts = get_recent_alerts(25)
    activity = get_recent_activity(40)
    html_markup = _build_traffic_monitoring_html(stats, alerts, activity, is_running=False)
    _render_monitoring_markup(html_markup)


def render_traffic_monitoring_tab():
    from live_ids.simulator import get_simulator
    from live_ids.logger import clear_logs

    sim = get_simulator()
    is_running = sim.is_running()

    st.markdown("""
    <div class="ng-callout" style="margin-bottom:1.2rem">
      <b>Traffic Monitoring &amp; Live Simulation:</b> Replays real connection records
      from the NSL-KDD benchmark through a multi-class Random Forest detector on a continuous timer.
      Click <b>Start Monitoring</b> to activate real-time scoring, stream the live traffic pulse strip,
      and track incoming intrusion alerts.
    </div>
    """, unsafe_allow_html=True)

    # Action Controls Bar
    c_status, c_start, c_stop, c_reset = st.columns([2.8, 1.2, 1, 1])

    with c_status:
        if is_running:
            st.markdown("""
            <div style="padding-top:4px;">
              <div class="tm-status-pill live">
                <span class="tm-status-dot live"></span>
                <span style="color:#4FD1C5;font-weight:700">MONITORING LIVE</span>
                <span style="color:#64748b;font-size:0.68rem">&nbsp;// 1.5s interval</span>
              </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="padding-top:4px;">
              <div class="tm-status-pill">
                <span class="tm-status-dot"></span>
                <span>STOPPED</span>
              </div>
            </div>
            """, unsafe_allow_html=True)

    with c_start:
        if st.button("▶  Start", disabled=is_running, key="btn_sim_start", use_container_width=True):
            sim.start()
            st.session_state.monitoring = True
            st.rerun()

    with c_stop:
        if st.button("⏹  Stop", disabled=not is_running, key="btn_sim_stop", use_container_width=True):
            sim.stop()
            st.session_state.monitoring = False
            st.rerun()

    with c_reset:
        if st.button("🔄  Reset", key="btn_sim_reset", use_container_width=True):
            clear_logs()
            st.rerun()

    st.markdown("<div style='margin-bottom:0.8rem'></div>", unsafe_allow_html=True)

    if is_running:
        _render_live_monitoring_fragment()
    else:
        _render_static_monitoring_fragment()

def main():
    with st.sidebar:
        st.markdown("""
        <div style="padding:1rem 0.5rem 0.5rem">
          <div style="font-family:'Space Mono',monospace;font-size:0.65rem;
                      color:#334155;text-transform:uppercase;letter-spacing:0.12em;
                      margin-bottom:1.2rem">Navigation</div>
        </div>
        """, unsafe_allow_html=True)

        page = st.radio(
            "", ["📁  PCAP Upload & Analyze", "📡  Traffic Monitoring"],
            label_visibility="collapsed"
        )

        st.markdown("---")
        st.markdown("""
        <div style="font-size:0.72rem;color:#334155;line-height:1.8;padding:0 0.3rem">
          <div style="font-family:'Space Mono',monospace;font-size:0.62rem;
                      color:#475569;text-transform:uppercase;letter-spacing:0.1em;
                      margin-bottom:0.6rem">AI Models</div>
          🤖 XGBoost Classifier<br>
          🌲 Random Forest<br>
          💡 LightGBM<br>
          🔍 Isolation Forest<br>
          ⚖️ Bayesian Combiner
        </div>
        """, unsafe_allow_html=True)
        with st.expander("ℹ️  Architecture & AI Models"):
            st.markdown("""
            <div style="font-size:0.75rem;line-height:1.7;color:#94a3b8">
              <b style="color:#00d4ff">PCAP Engine (UNSW-NB15)</b><br>
              • 32-42 flow features extracted via NFStream & Scapy<br>
              • Supervised ensemble: XGBoost, LightGBM, Random Forest<br>
              • Unsupervised: Isolation Forest anomaly scanner<br>
              • Bayesian combination (50/50 weighted fusion)<br><br>
              <b style="color:#4FD1C5">Live Engine (NSL-KDD)</b><br>
              • Real-time traffic simulation & replay<br>
              • 41-feature multi-class Random Forest detector<br>
              • Alert prioritization: DoS, Probe, R2L, U2R<br>
              • Animated pulse strip & audit logging
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("""
        <div style="font-size:0.72rem;color:#334155;line-height:1.8;padding:0 0.3rem">
          <div style="font-family:'Space Mono',monospace;font-size:0.62rem;
                      color:#475569;text-transform:uppercase;letter-spacing:0.1em;
                      margin-bottom:0.6rem">Dataset</div>
          Trained on UNSW-NB15<br>
          2.5M+ network flows<br>
          Covers 9 attack categories
        </div>
        """, unsafe_allow_html=True)

    

    if "📁" in page:
        
        if "upload_result" in st.session_state:
            verdict       = st.session_state.upload_result.get("verdict", "NORMAL")
            topbar_status = "attack" if verdict == "ATTACK" else "normal"
        else:
            topbar_status = "ready"
        render_topbar(topbar_status)

        
        st.markdown("""
        <div class="ng-callout" style="margin-bottom:1rem">
          <b>What is a PCAP file?</b> It's a recording of network traffic — like a security camera
          recording for your internet connection. You can create one using tools like
          <b>Wireshark</b> (free, Windows/Mac/Linux) or <b>tcpdump</b> (Linux/Mac terminal).
          Upload it here and our AI will check it for threats in seconds.
        </div>
        """, unsafe_allow_html=True)

        
        uploaded = st.file_uploader(
            "Drag & drop your .pcap or .pcapng file here",
            type=["pcap", "pcapng", "cap"],
            label_visibility="collapsed",
        )

        if uploaded is not None:
            file_size = len(uploaded.getvalue())
            st.markdown(f"""
            <div style="font-size:0.8rem;color:#64748b;margin:-0.5rem 0 1rem;
                        font-family:'Space Mono',monospace;">
              📎 {uploaded.name} &nbsp;·&nbsp; {human_bytes(file_size)}
            </div>
            """, unsafe_allow_html=True)

            if st.button("🔍  Analyze File"):
                with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                    tmp.write(uploaded.getvalue())
                    pcap_path = tmp.name

                progress_placeholder = st.empty()
                steps = [
                    ("📡  Parsing packet headers…",          0.15),
                    ("🔬  Extracting flow features…",        0.40),
                    ("🤖  Running ensemble classifiers…",    0.70),
                    ("🔍  Isolation Forest anomaly scan…",   0.85),
                    ("📊  Building your report…",            1.00),
                ]

                with progress_placeholder.container():
                    bar = st.progress(0)
                    msg = st.empty()

                    result, raw_df, err = None, None, None
                    models_available    = os.path.isdir(MODELS_DIR)

                    def _run():
                        nonlocal result, raw_df, err
                        if models_available:
                            result, raw_df, err = run_full_analysis(pcap_path)
                        else:
                            time.sleep(3.5)
                            result = mock_result(seed=abs(hash(uploaded.name)) % 9999)
                            raw_df = mock_raw_df(result["total_flows"])

                    t = threading.Thread(target=_run, daemon=True)
                    t.start()

                    step_idx = 0
                    while t.is_alive():
                        if step_idx < len(steps):
                            label, prog = steps[step_idx]
                            msg.markdown(f"""
                            <div style="font-family:'Space Mono',monospace;
                                        font-size:0.78rem;color:#00d4ff;
                                        padding:0.4rem 0;animation:pulse-glow 1s infinite">
                              {label}
                            </div>""", unsafe_allow_html=True)
                            bar.progress(prog)
                            step_idx = (step_idx + 1) % len(steps)
                        time.sleep(0.9)

                    t.join()
                    bar.progress(1.0)
                    msg.empty()

                progress_placeholder.empty()

                if not models_available and err is None:
                    st.info("ℹ️ Models folder not found — showing a **demo analysis** "
                            "with simulated data. To use your real models, place them "
                            f"in `{MODELS_DIR}`.")

                if err:
                    st.error(f"❌ Analysis error: {err}")
                else:
                    st.session_state.upload_result = result
                    st.session_state.upload_raw_df = raw_df
                    st.session_state.upload_name   = uploaded.name
                    st.rerun()  

        if "upload_result" in st.session_state:
            render_results(
                st.session_state.upload_result,
                st.session_state.upload_raw_df,
                filename=st.session_state.get("upload_name", "capture.pcap"),
            )

    elif "📡" in page:
        from live_ids.simulator import get_simulator
        render_topbar("live" if get_simulator().is_running() else "ready")
        render_traffic_monitoring_tab()


if __name__ == "__main__":
    main()
