"""
NetDetect View: Network Visualization
Interactive cybersecurity charts, flow dynamics, and traffic patterns
"""

import streamlit as st
import numpy as np
import pandas as pd
from ui.components import render_page_header, render_empty_state, render_card_header
from ui.charts import (
    build_flow_threat_chart,
    build_traffic_donut,
    build_protocol_chart,
    build_services_chart,
    build_threat_histogram,
    build_volume_chart,
    build_live_category_chart,
    build_severity_bar_chart,
)
from live_ids.logger import get_stats


def render_visualization_view():
    render_page_header(
        title="Network Telemetry & Flow Visualization",
        subtitle="Multi-dimensional visual inspection of protocols, byte transfer volumes, and anomaly clustering",
        badge_text="TELEMETRY RADAR",
    )

    result = st.session_state.get("upload_result")
    raw_df = st.session_state.get("upload_raw_df")
    stats = get_stats()

    has_pcap = result is not None
    has_live = stats.get("total_analyzed", 0) > 0

    if not has_pcap and not has_live:
        render_empty_state(
            icon="🌐",
            title="Awaiting Telemetry Data",
            description="No active PCAP capture or live monitoring records available for visualization. Analyze a capture file or start live monitoring to activate charts.",
        )
        c1, c2, c3 = st.columns([1, 1.2, 1])
        with c2:
            if st.button("📁  Go To Traffic Analysis", key="btn_viz_goto_pcap", width="stretch"):
                st.session_state.active_nav_key = "analysis"
                st.rerun()
        return

    # Mode Selector if both are available
    if has_pcap and has_live:
        viz_mode = st.radio(
            "Telemetry Source",
            ["📁 PCAP Packet Capture Flows", "📡 Live Streamed Simulation Telemetry"],
            horizontal=True,
            key="viz_source_selector",
        )
    elif has_pcap:
        viz_mode = "📁 PCAP Packet Capture Flows"
    else:
        viz_mode = "📡 Live Streamed Simulation Telemetry"

    st.markdown("<div style='margin-bottom:1rem;'></div>", unsafe_allow_html=True)

    if "PCAP" in viz_mode and has_pcap:
        scores = result.get("all_flow_scores", [])
        attack_count = sum(1 for s in scores if s >= 0.5)
        safe_count = len(scores) - attack_count

        # Top Charts Row: Per-Flow Score Bar & Traffic Donut
        col1, col2 = st.columns([1.6, 1])
        with col1:
            with st.container(border=True):
                render_card_header("Per-Flow Threat Intensity", icon="📈", action="Threshold: 0.50")
                fig1 = build_flow_threat_chart(scores, height=270)
                st.plotly_chart(fig1, width="stretch", config={"displayModeBar": False})

        with col2:
            with st.container(border=True):
                render_card_header("Normal vs Suspicious Ratio", icon="🍩", action="Ensemble Verdict")
                fig2 = build_traffic_donut(safe_count, attack_count, height=270)
                st.plotly_chart(fig2, width="stretch", config={"displayModeBar": False})

        # Middle Row: Protocol Breakdown and Top Services
        if raw_df is not None:
            col3, col4 = st.columns(2)
            with col3:
                with st.container(border=True):
                    render_card_header("Transport Protocol Distribution", icon="📡", action="Active Flows")
                    fig3 = build_protocol_chart(raw_df, height=250)
                    st.plotly_chart(fig3, width="stretch", config={"displayModeBar": False})

            with col4:
                with st.container(border=True):
                    render_card_header("Service Port Utilization", icon="🔗", action="Top Inbound/Outbound")
                    fig4 = build_services_chart(raw_df, height=250)
                    if fig4:
                        st.plotly_chart(fig4, width="stretch", config={"displayModeBar": False})
                    else:
                        st.info("Service ports not indexed in this capture.")

        # Bottom Row: Anomaly Score Histogram
        with st.container(border=True):
            render_card_header("Threat Score Density Histogram", icon="📊", action="Anomaly Clustering")
            fig5 = build_threat_histogram(scores, height=230)
            st.plotly_chart(fig5, width="stretch", config={"displayModeBar": False})

        # Byte Transfer Streams
        if raw_df is not None and ('sbytes' in raw_df.columns or 'dbytes' in raw_df.columns):
            with st.container(border=True):
                render_card_header("Packet Payload Transfer Rates", icon="📦", action="Tx vs Rx Volume Streams")
                fig6 = build_volume_chart(raw_df, height=230)
                st.plotly_chart(fig6, width="stretch", config={"displayModeBar": False})

    else:
        # Live Monitoring Visualizations
        col_l1, col_l2 = st.columns(2)
        with col_l1:
            with st.container(border=True):
                render_card_header("Attack Taxonomy Breakdown", icon="⚡", action="NSL-KDD Classifications")
                cat_counts = stats.get("category_counts", {})
                if cat_counts:
                    fig_cat = build_live_category_chart(cat_counts, height=270)
                    st.plotly_chart(fig_cat, width="stretch", config={"displayModeBar": False})
                else:
                    st.info("No live categories recorded yet.")

        with col_l2:
            with st.container(border=True):
                render_card_header("Intrusion Severity Tiers", icon="🚨", action="Alert Prioritization")
                sev_counts = stats.get("severity_counts", {})
                if sev_counts:
                    fig_sev = build_severity_bar_chart(sev_counts, height=270)
                    st.plotly_chart(fig_sev, width="stretch", config={"displayModeBar": False})
                else:
                    st.info("No security alerts raised yet.")
