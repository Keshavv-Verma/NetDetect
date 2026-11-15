"""
NetDetect View: Overview Dashboard
Aggregated Security Operations Center (SOC) posture and telemetry
"""

import os
import streamlit as st
import pandas as pd
from ui.components import render_page_header, render_metric_grid, render_empty_state, render_card_header
from ui.charts import (
    build_flow_threat_chart,
    build_traffic_donut,
    build_live_category_chart,
    build_severity_bar_chart,
)
from live_ids.logger import get_stats, get_recent_alerts, clear_logs
from live_ids.simulator import get_simulator


def render_overview_view():
    render_page_header(
        title="Security Operations Console",
        subtitle="Unified network anomaly monitoring, threat telemetry, and real-time posture",
        badge_text="SOC LIVE AGGREGATOR",
    )

    # Gather data from both PCAP subsystem and Live IDS subsystem
    stats = get_stats()
    live_sim = get_simulator()
    is_live_running = live_sim.is_running()
    
    pcap_result = st.session_state.get("upload_result")
    pcap_raw_df = st.session_state.get("upload_raw_df")
    pcap_name = st.session_state.get("upload_name", "None")

    # Metrics calculation
    pcap_flows = pcap_result.get("total_flows", 0) if pcap_result else 0
    pcap_threats = sum(1 for s in pcap_result.get("all_flow_scores", []) if s >= 0.5) if pcap_result else 0
    
    live_analyzed = stats.get("total_analyzed", 0)
    live_alerts = stats.get("total_alerts", 0)
    
    total_analyzed = pcap_flows + live_analyzed
    total_threats = pcap_threats + live_alerts
    threat_rate = f"{round((total_threats / total_analyzed) * 100, 1)}%" if total_analyzed > 0 else "0.0%"

    if pcap_result and pcap_result.get("verdict") == "ATTACK":
        posture_status = "ELEVATED RISK"
        posture_color = "rose"
        posture_icon = "⚠️"
    elif total_threats > 0:
        posture_status = "CAUTION"
        posture_color = "amber"
        posture_icon = "⚡"
    else:
        posture_status = "HEALTHY"
        posture_color = "emerald"
        posture_icon = "🛡️"

    # Top KPI metric cards
    metrics = [
        ("Network Security Posture", posture_status, f"{'Active threat flagged' if posture_color == 'rose' else 'Nominal baseline'}", posture_color, posture_icon),
        ("Total Records Analyzed", f"{total_analyzed:,}", f"{pcap_flows} PCAP + {live_analyzed} Live", "cyan", "🌐"),
        ("Detected Anomalies", f"{total_threats:,}", f"Flagged intrusions / anomalies", "rose" if total_threats > 0 else "emerald", "🎯"),
        ("Global Threat Ratio", threat_rate, "Across all inspection engines", "indigo", "📊"),
    ]
    render_metric_grid(metrics)

    # Quick Actions & Engine Status Strip with Reset Option
    with st.container(border=True):
        c_status, c_actions = st.columns([2.1, 1.3])

        with c_status:
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:1.4rem;flex-wrap:wrap;padding:0.25rem 0;">
              <div>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#71717a;text-transform:uppercase;">PCAP Capture Engine:</span>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;font-weight:600;color:{'#ffffff' if pcap_result else '#a1a1aa'};">
                  {'Loaded: ' + pcap_name if pcap_result else 'Standing By'}
                </span>
              </div>
              <div style="height:16px;width:1px;background:rgba(255,255,255,0.1);"></div>
              <div>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#71717a;text-transform:uppercase;">Live Simulator:</span>
                <span class="nd-badge {'safe' if is_live_running else 'neutral'}" style="margin-left:0.4rem;">
                  {'ACTIVE (1.5s)' if is_live_running else 'STOPPED'}
                </span>
              </div>
              <div style="height:16px;width:1px;background:rgba(255,255,255,0.1);"></div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#a1a1aa;">
                Hybrid Bayesian (UNSW-NB15 + NSL-KDD)
              </div>
            </div>
            """, unsafe_allow_html=True)

        with c_actions:
            c_rst, c_opt = st.columns([1.6, 1])
            with c_rst:
                st.markdown('<div class="nd-reset-btn">', unsafe_allow_html=True)
                if st.button("🔄 Reset Dashboard", key="btn_ov_reset_all", width="stretch", help="Flush loaded PCAP captures, stop live simulation, and reset telemetry logs back to nominal baseline"):
                    # 1. Clear PCAP analysis state
                    st.session_state.pop("upload_result", None)
                    st.session_state.pop("upload_raw_df", None)
                    st.session_state.pop("upload_name", None)
                    st.session_state.pop("upload_elapsed", None)
                    st.session_state.pop("pcap_history", None)
                    st.session_state.pop("trigger_sample_analysis", None)

                    # 2. Stop live simulation if running
                    if is_live_running:
                        live_sim.stop()
                    st.session_state["monitoring"] = False

                    # 3. Clear logs
                    clear_logs()

                    st.toast("Dashboard telemetry, PCAP cache, and event logs reset to nominal baseline.", icon="🔄")
                    st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)

            with c_opt:
                with st.popover("⚙️ Options", width="stretch"):
                    st.markdown("""
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;font-weight:700;color:#ffffff;margin-bottom:0.5rem;">
                      RESET CONTROLS
                    </div>
                    <div style="font-size:0.72rem;color:#a1a1aa;line-height:1.4;margin-bottom:0.8rem;">
                      Select which subsystem state to purge:
                    </div>
                    """, unsafe_allow_html=True)

                    if st.button("📁 Clear PCAP Cache Only", key="btn_rst_pcap_only", width="stretch", disabled=not bool(pcap_result)):
                        st.session_state.pop("upload_result", None)
                        st.session_state.pop("upload_raw_df", None)
                        st.session_state.pop("upload_name", None)
                        st.session_state.pop("upload_elapsed", None)
                        st.session_state.pop("pcap_history", None)
                        st.toast("PCAP capture data cleared.", icon="📁")
                        st.rerun()

                    if st.button("📜 Clear Live Event Logs Only", key="btn_rst_logs_only", width="stretch"):
                        clear_logs()
                        st.toast("Live event logs flushed.", icon="📜")
                        st.rerun()

                    if is_live_running:
                        if st.button("⏹ Stop Live Stream Only", key="btn_rst_stop_live", width="stretch"):
                            live_sim.stop()
                            st.session_state["monitoring"] = False
                            st.toast("Live stream halted.", icon="⏹")
                            st.rerun()

    # Core Content Grid: PCAP Insights & Live IDS Insights
    col_left, col_right = st.columns([1.3, 1])

    with col_left:
        with st.container(border=True):
            render_card_header("PCAP Flow Threat Distribution", icon="📈", action="Offline Ensemble Analysis")
            if pcap_result:
                scores = pcap_result.get("all_flow_scores", [])
                fig_flows = build_flow_threat_chart(scores, height=260)
                st.plotly_chart(fig_flows, width="stretch", config={"displayModeBar": False})
            else:
                render_empty_state(
                    icon="📁",
                    title="No PCAP Capture Loaded",
                    description="Upload a .pcap / .pcapng capture file or load the sample dataset to inspect connection flows and view ensemble threat scores.",
                )
                col_b1, col_b2, col_b3 = st.columns([1, 1.4, 1])
                with col_b2:
                    if st.button("📁  Go To Traffic Analysis", key="btn_ov_goto_pcap", width="stretch"):
                        st.session_state.active_nav_key = "analysis"
                        st.rerun()

    with col_right:
        with st.container(border=True):
            render_card_header("Traffic Classification Ratio", icon="🍩", action="Ensemble Verdict")
            if pcap_result:
                scores = pcap_result.get("all_flow_scores", [])
                threats = sum(1 for s in scores if s >= 0.5)
                safe = len(scores) - threats
                fig_donut = build_traffic_donut(safe, threats, height=260)
                st.plotly_chart(fig_donut, width="stretch", config={"displayModeBar": False})
            elif stats.get("category_counts"):
                fig_cats = build_live_category_chart(stats["category_counts"], height=260)
                st.plotly_chart(fig_cats, width="stretch", config={"displayModeBar": False})
            else:
                render_empty_state(
                    icon="⚡",
                    title="Awaiting Traffic Data",
                    description="Start the Live Traffic Simulator or inspect a capture file to visualize normal vs malicious traffic ratios.",
                )
                col_s1, col_s2, col_s3 = st.columns([1, 1.4, 1])
                with col_s2:
                    if st.button("📡  Go To Live Monitor", key="btn_ov_goto_live", width="stretch"):
                        st.session_state.active_nav_key = "monitoring"
                        st.rerun()

    # Lower Grid: Recent Security Events & Alerts Feed Preview
    with st.container(border=True):
        render_card_header("Recent Security Intrusion Events", icon="🚨", action="Live Stream & Audit Trail")
        alerts = get_recent_alerts(8)
        if alerts:
            alert_rows = []
            for a in alerts:
                sev = a.get("severity", "info")
                cat = a.get("predicted_category", "Unknown")
                src = a.get("src_ip", "N/A")
                dst = a.get("dst_ip", "N/A")
                proto = a.get("protocol_type", "tcp")
                ts = a.get("timestamp", "")[:19].replace("T", " ")
                conf = f"{int(a.get('confidence', 0) * 100)}%"
                
                alert_rows.append(f"""
                <div class="nd-alert-row">
                  <span class="nd-badge {'attack' if sev in ('critical', 'high') else 'warning'}">{sev}</span>
                  <span class="nd-alert-cat">{cat}</span>
                  <span class="nd-alert-ip"><span style="color:#fafafa;">{src}</span> &rarr; <span style="color:#fafafa;">{dst}</span> <span style="color:#71717a;">({proto})</span></span>
                  <span style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#fafafa;">{conf}</span>
                  <span class="nd-alert-time">{ts}</span>
                </div>
                """)
            st.markdown(f'<div class="nd-alert-feed">{"".join(alert_rows)}</div>', unsafe_allow_html=True)
        else:
            render_empty_state(
                icon="🛡️",
                title="No Active Threats In Log",
                description="The real-time intrusion detection feed currently has no logged alerts. Launch live traffic monitoring to simulate incoming connection events.",
            )
