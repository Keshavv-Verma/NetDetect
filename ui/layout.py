"""
NetDetect Layout Module
Topbar, Sidebar, and Global Layout Elements
"""

from datetime import datetime, timezone
import streamlit as st

NAVIGATION_SECTIONS = [
    ("overview",      "📊  Overview Dashboard",       "System-wide security posture and telemetry"),
    ("analysis",      "📁  Traffic Analysis",          "PCAP/PCAPNG packet inspection and flow extraction"),
    ("results",       "🎯  Detection Results",         "Deep threat classification and anomaly breakdown"),
    ("visualization", "🌐  Network Visualization",     "Interactive flow patterns and protocol graphs"),
    ("monitoring",    "📡  Live Monitoring",           "Real-time streaming traffic simulation engine"),
    ("history",       "📜  Analysis History",          "Historical audit trail and activity logs"),
]


def render_topbar(status: str = "ready", active_page: str = "Overview"):
    """Render top navigation bar for NetDetect SOC."""
    status_map = {
        "ready":      ("SYSTEM READY",           "ready",    "active"),
        "live":       ("LIVE SIMULATION ACTIVE",  "live",     "active"),
        "analyzing":  ("ANALYZING PACKETS...",   "scanning", "active"),
        "attack":     ("⚠️ THREAT FLAGGED",       "danger",   "danger"),
        "normal":     ("NETWORK HEALTHY",        "ready",    ""),
    }
    label, cls, dot_cls = status_map.get(status, ("SYSTEM READY", "ready", ""))
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M:%S UTC")

    st.markdown(f"""
    <div class="nd-topbar">
      <div class="nd-topbar-brand">
        <div class="nd-logo-mark">
          <svg viewBox="0 0 24 24" fill="none" stroke="#fafafa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <circle cx="12" cy="11" r="3"></circle>
            <path d="M12 8v-1"></path>
            <path d="M12 15v-1"></path>
          </svg>
        </div>
        <div class="nd-brand-titles">
          <h1>Net<span class="nd-highlight">Detect</span></h1>
          <p>Autonomous Network Intrusion Detection System &middot; SOC Edition</p>
        </div>
      </div>
      
      <div class="nd-topbar-telemetry">
        <div class="nd-telemetry-pill">
          <span class="nd-status-dot {dot_cls}"></span>
          <span>{label}</span>
        </div>
        <div class="nd-telemetry-pill nd-telemetry-pill-view">
          <span style="color:#71717a;">VIEW:</span>
          <span style="color:#ffffff;font-weight:600;">{active_page.upper()}</span>
        </div>
        <div class="nd-telemetry-pill">
          <span style="color:#71717a;">TIME:</span>
          <span>{now_utc}</span>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)


def render_sidebar():
    """Render modern SOC sidebar with navigation and engine details."""
    with st.sidebar:
        # Branding block
        st.markdown("""
        <div style="padding: 0.8rem 0.4rem 1.2rem;">
          <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.4rem;">
            <div style="width:32px;height:32px;border-radius:8px;background:#1f1f23;border:1px solid rgba(255,255,255,0.2);display:flex;align-items:center;justify-content:center;font-size:1rem;">
              🛡️
            </div>
            <div>
              <div style="font-family:'Inter',sans-serif;font-weight:700;font-size:1.05rem;letter-spacing:-0.02em;">
                Net<span style="color:#ffffff;">Detect</span>
              </div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;color:#71717a;letter-spacing:0.06em;text-transform:uppercase;">
                SOC Console v2.0
              </div>
            </div>
          </div>
          <div style="height:1px;background:rgba(255,255,255,0.08);margin-top:0.8rem;"></div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:#71717a;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:0.6rem;padding-left:0.2rem;">
          Navigation Console
        </div>
        """, unsafe_allow_html=True)

        # Nav options
        nav_keys = [k for k, label, desc in NAVIGATION_SECTIONS]
        nav_labels = [label for k, label, desc in NAVIGATION_SECTIONS]
        label_to_key = dict(zip(nav_labels, nav_keys))
        key_to_label = dict(zip(nav_keys, nav_labels))

        if "active_nav_key" not in st.session_state:
            st.session_state.active_nav_key = "overview"
        if "_last_active_key" not in st.session_state:
            st.session_state._last_active_key = "overview"

        # Detect if active_nav_key was changed externally (e.g. by an in-page CTA button)
        if st.session_state.active_nav_key != st.session_state._last_active_key:
            st.session_state.main_nav_radio = key_to_label.get(st.session_state.active_nav_key, nav_labels[0])
            st.session_state._last_active_key = st.session_state.active_nav_key
        elif "main_nav_radio" not in st.session_state:
            st.session_state.main_nav_radio = key_to_label.get(st.session_state.active_nav_key, nav_labels[0])

        selected_label = st.radio(
            "Navigation Console",
            nav_labels,
            key="main_nav_radio",
            label_visibility="collapsed",
        )
        st.session_state.active_nav_key = label_to_key.get(selected_label, "overview")
        st.session_state._last_active_key = st.session_state.active_nav_key

        st.markdown("<div style='margin-top:1.2rem;border-top:1px solid rgba(255,255,255,0.08);padding-top:1rem;'></div>", unsafe_allow_html=True)

        # System Architecture & AI Specification Accordion
        with st.expander("🤖 AI Models & Architecture", expanded=False):
            st.markdown("""
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;line-height:1.7;color:#a1a1aa;">
              <b style="color:#fafafa;">OFFLINE PCAP ENGINE</b><br>
              &bull; <b>Model:</b> UNSW-NB15 Ensemble<br>
              &bull; <b>Classifiers:</b> RF + LightGBM + XGBoost<br>
              &bull; <b>Anomaly:</b> Isolation Forest (IF)<br>
              &bull; <b>Fusion:</b> Bayesian 50/50 Weighted<br>
              &bull; <b>Decision Threshold:</b> 0.50<br><br>
              <b style="color:#d4d4d8;">LIVE STREAMING ENGINE</b><br>
              &bull; <b>Model:</b> NSL-KDD Multi-Class RF<br>
              &bull; <b>Categories:</b> DoS, Probe, R2L, U2R<br>
              &bull; <b>Replay Speed:</b> 1.5s Synthetic IP Stream<br>
              &bull; <b>Severity Engine:</b> Priority Tagging
            </div>
            """, unsafe_allow_html=True)

        # Live telemetry quick stats in sidebar
        st.markdown("""
        <div style="background:#18181b;border:1px solid rgba(255,255,255,0.12);border-radius:8px;padding:0.75rem 0.9rem;margin-top:0.6rem;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.3rem;">
            <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:#71717a;text-transform:uppercase;">Engine State</span>
            <span class="nd-badge safe" style="font-size:0.6rem;padding:1px 6px;">ONLINE</span>
          </div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#a1a1aa;">
            Pipeline: <span style="color:#ffffff;">NFStream + Scapy</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

    return st.session_state.active_nav_key
