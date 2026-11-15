"""
NetDetect — ML-Based Network Anomaly Detection System
Unified Commercial SOC Interface & Dashboard Entrypoint
"""

import os
import sys
import streamlit as st

# Configure page settings as first Streamlit call
st.set_page_config(
    page_title="NetDetect — AI Network Anomaly Detection Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Import design system, layout, and view orchestrators
from ui.styles import NETDETECT_CSS
from ui.layout import render_sidebar, render_topbar
from ui.views.overview import render_overview_view
from ui.views.analysis import render_analysis_view, load_artifacts_cached, execute_pcap_analysis
from ui.views.results import render_results_view
from ui.views.visualization import render_visualization_view
from ui.views.live_monitoring import render_monitoring_view
from ui.views.history import render_history_view
from live_ids.simulator import get_simulator


# Backward compatibility aliases
run_full_analysis = execute_pcap_analysis


def main():
    # Inject unified dark-first SOC stylesheet
    st.markdown(NETDETECT_CSS, unsafe_allow_html=True)

    # Render sidebar navigation and capture active view key
    active_key = render_sidebar()

    # Determine global SOC status for topbar telemetry
    sim = get_simulator()
    is_live = sim.is_running()
    pcap_res = st.session_state.get("upload_result")

    if pcap_res and pcap_res.get("verdict") == "ATTACK":
        topbar_status = "attack"
    elif is_live:
        topbar_status = "live"
    elif pcap_res and pcap_res.get("verdict") == "NORMAL":
        topbar_status = "normal"
    else:
        topbar_status = "ready"

    # Human-readable view names for topbar
    view_titles = {
        "overview":      "Overview Dashboard",
        "analysis":      "PCAP Traffic Analysis",
        "results":       "Detection Results",
        "visualization": "Network Visualization",
        "monitoring":    "Live Monitoring Stream",
        "history":       "Analysis History & Logs",
    }
    active_title = view_titles.get(active_key, "Overview")

    # Render topbar
    render_topbar(status=topbar_status, active_page=active_title)

    # Route view execution
    if active_key == "overview":
        render_overview_view()
    elif active_key == "analysis":
        render_analysis_view()
    elif active_key == "results":
        render_results_view()
    elif active_key == "visualization":
        render_visualization_view()
    elif active_key == "monitoring":
        render_monitoring_view()
    elif active_key == "history":
        render_history_view()
    else:
        render_overview_view()


if __name__ == "__main__":
    main()
