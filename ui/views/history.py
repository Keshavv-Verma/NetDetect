"""
NetDetect View: Analysis History & Audit Log
Historical inspection ledger, session captures, and disk-backed audit trails
"""

import os
import json
import streamlit as st
import pandas as pd
from ui.components import render_page_header, render_empty_state, render_callout, render_card_header
from live_ids.logger import ACTIVITY_LOG, ALERT_LOG, _read_jsonl, clear_logs
from backend.services.history_service import HistoryService


def render_history_view():
    render_page_header(
        title="Analysis History & Security Audit Logs",
        subtitle="Chronological records of offline PCAP captures and persistent live intrusion activity",
        badge_text="AUDIT VAULT",
    )

    tab_pcap, tab_stream, tab_alerts = st.tabs([
        "📁  Session PCAP Inspections",
        "📜  Live Engine Audit Trail (JSONL)",
        "🚨  Flagged Incident Ledger",
    ])

    with tab_pcap:
        hist_service = HistoryService()
        db_records, total_db = hist_service.list_analyses(limit=100)
        pcap_history = st.session_state.get("pcap_history", [])
        has_history = total_db > 0 or len(pcap_history) > 0

        if not has_history:
            render_empty_state(
                icon="📁",
                title="No PCAP Analyses Recorded Yet",
                description="When you analyze packet capture files in the Traffic Analysis section, their timestamps, flow counts, and verdicts are recorded here in the persistent database.",
            )
            col1, col2, col3 = st.columns([1, 1.2, 1])
            with col2:
                if st.button("📁  Go To Traffic Analysis", key="btn_hist_goto_pcap", width="stretch"):
                    st.session_state.active_nav_key = "analysis"
                    st.rerun()
        else:
            with st.container(border=True):
                render_card_header("Persistent PCAP Inspection Vault", icon="📋", action=f"{total_db or len(pcap_history)} Records in netdetect.db")

                # Filter and Export Toolbar
                col_hp1, col_hp2, col_hp3 = st.columns([1.5, 1.2, 1.2])
                with col_hp1:
                    search_txt = st.text_input("Filter by filename", placeholder="e.g. sample or traffic", key="hist_pcap_search")
                with col_hp2:
                    verdict_sel = st.selectbox("Verdict", ["All Verdicts", "ATTACK", "NORMAL"], key="hist_pcap_verdict")
                with col_hp3:
                    st.markdown("<div style='font-family:\"JetBrains Mono\",monospace;font-size:0.7rem;color:#71717a;margin-bottom:0.35rem;text-transform:uppercase;'>Export Vault</div>", unsafe_allow_html=True)
                    json_export = hist_service.export_analyses_json()
                    st.download_button(
                        "⬇️ Download Vault (JSON)",
                        data=json_export,
                        file_name="netdetect_analysis_vault.json",
                        mime="application/json",
                        width="stretch",
                        key="btn_dl_vault",
                    )

                # Query with filter if using DB
                if total_db > 0:
                    v_filter = verdict_sel if verdict_sel != "All Verdicts" else None
                    display_records, _ = hist_service.list_analyses(
                        limit=100, search=search_txt or None, verdict=v_filter
                    )
                    rows_html = []
                    for r in display_records:
                        is_atk = r.get("verdict") == "ATTACK"
                        cls = "is-attack" if is_atk else ""
                        badge_cls = "attack" if is_atk else "safe"
                        ts = str(r.get("created_at", ""))[:19].replace("T", " ")

                        rows_html.append(f"""
                        <tr class="{cls}">
                          <td>{ts}</td>
                          <td><span style="color:#ffffff;font-weight:600;">{r.get('filename')}</span></td>
                          <td class="num-col">{r.get('total_flows', 0):,}</td>
                          <td class="center-col"><span class="nd-badge {badge_cls}">{r.get('verdict')}</span></td>
                          <td><span style="font-weight:600;">{r.get('risk_level') or 'Nominal'}</span></td>
                          <td class="num-col"><span style="color:{'#f43f5e' if is_atk else '#10b981'};font-weight:700;">{r.get('threat_intensity', 0.0):.1f}%</span></td>
                        </tr>
                        """)
                else:
                    hist_df = pd.DataFrame(pcap_history)
                    rows_html = []
                    for _, r in hist_df.iloc[::-1].iterrows():
                        is_atk = r.get("verdict") == "ATTACK"
                        cls = "is-attack" if is_atk else ""
                        badge_cls = "attack" if is_atk else "safe"
                        rows_html.append(f"""
                        <tr class="{cls}">
                          <td>{r.get('timestamp')}</td>
                          <td><span style="color:#ffffff;font-weight:600;">{r.get('filename')}</span></td>
                          <td class="num-col">{r.get('flows', 0):,}</td>
                          <td class="center-col"><span class="nd-badge {badge_cls}">{r.get('verdict')}</span></td>
                          <td><span style="font-weight:600;">{r.get('risk_level')}</span></td>
                          <td class="num-col"><span style="color:{'#f43f5e' if is_atk else '#10b981'};font-weight:700;">{r.get('intensity')}%</span></td>
                        </tr>
                        """)

                st.markdown(f"""
                <div class="nd-table-wrap">
                  <div style="max-height: 480px; overflow-y: auto;">
                    <table class="nd-table">
                      <thead>
                        <tr>
                          <th>Timestamp (UTC)</th><th>Capture File</th><th class="num-col">Flows</th><th class="center-col">Verdict</th><th>Risk Tier</th><th class="num-col">Threat Intensity</th>
                        </tr>
                      </thead>
                      <tbody>{"".join(rows_html)}</tbody>
                    </table>
                  </div>
                </div>
                """, unsafe_allow_html=True)

    with tab_stream:
        records = _read_jsonl(ACTIVITY_LOG, limit=500)
        if not records:
            render_empty_state(
                icon="📜",
                title="Activity Log Empty",
                description="The disk-backed activity log (activity_log.jsonl) has no records. Launch Live Traffic Monitoring to begin recording connection audits.",
            )
        else:
            with st.container(border=True):
                render_card_header("Disk-Backed Connection Audit Log", icon="📜", action="Persisted in live_ids/logs/activity_log.jsonl")

                # Filter toolbar
                col_s1, col_s2, col_s3 = st.columns([1.5, 1.2, 1.2])
                with col_s1:
                    search_query = st.text_input("Search IP / Category / Protocol", placeholder="e.g. 192.168 or DoS or tcp", key="hist_search")
                with col_s2:
                    cat_filter = st.selectbox("Category", ["All Categories"] + sorted(list(set(r.get("predicted_category", "Normal") for r in records))), key="hist_cat")
                with col_s3:
                    st.markdown("<div style='font-family:\"JetBrains Mono\",monospace;font-size:0.7rem;color:#71717a;margin-bottom:0.35rem;text-transform:uppercase;'>Export Ledger</div>", unsafe_allow_html=True)
                    raw_json = json.dumps(records, indent=2).encode("utf-8")
                    st.download_button(
                        "⬇️ Download Audit Log (JSON)",
                        data=raw_json,
                        file_name="netdetect_audit_log.json",
                        mime="application/json",
                        width="stretch",
                        key="btn_dl_audit",
                    )

                # Filter
                filtered = records
                if search_query:
                    q = search_query.lower()
                    filtered = [r for r in filtered if q in str(r.get("src_ip", "")).lower() or q in str(r.get("dst_ip", "")).lower() or q in str(r.get("predicted_category", "")).lower() or q in str(r.get("protocol_type", "")).lower()]
                if cat_filter != "All Categories":
                    filtered = [r for r in filtered if r.get("predicted_category") == cat_filter]

                st.markdown(f"""
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#a1a1aa;margin-bottom:0.8rem;">
                  Showing <b style="color:#ffffff;">{len(filtered):,}</b> of {len(records):,} audit records
                </div>
                """, unsafe_allow_html=True)

                rows_html = []
                for r in filtered[:100]:
                    is_atk = r.get("is_attack", False)
                    cls = "is-attack" if is_atk else ""
                    badge_cls = "attack" if is_atk else "safe"
                    badge_text = "ATTACK" if is_atk else "NORMAL"
                    ts = str(r.get("timestamp", ""))[:19].replace("T", " ")
                    conf = f"{int(r.get('confidence', 0) * 100)}%"

                    rows_html.append(f"""
                    <tr class="{cls}">
                      <td>{ts}</td>
                      <td><b>{r.get('src_ip', 'N/A')}</b></td>
                      <td><b>{r.get('dst_ip', 'N/A')}</b></td>
                      <td>{r.get('protocol_type', '-')}</td>
                      <td>{r.get('service', '-')}</td>
                      <td>{r.get('predicted_category', '-')}</td>
                      <td class="center-col"><span style="color:#fafafa;">{conf}</span></td>
                      <td class="center-col"><span class="nd-badge {badge_cls}">{badge_text}</span></td>
                    </tr>
                    """)

                st.markdown(f"""
                <div class="nd-table-wrap">
                  <div style="max-height: 480px; overflow-y: auto;">
                    <table class="nd-table">
                      <thead>
                        <tr>
                          <th>Time (UTC)</th><th>Source IP</th><th>Dest IP</th><th>Proto</th><th>Service</th><th>Category</th><th class="center-col">Conf</th><th class="center-col">Status</th>
                        </tr>
                      </thead>
                      <tbody>{"".join(rows_html)}</tbody>
                    </table>
                  </div>
                </div>
                """, unsafe_allow_html=True)

    with tab_alerts:
        alerts = _read_jsonl(ALERT_LOG, limit=500)
        if not alerts:
            render_empty_state(
                icon="🚨",
                title="No Flagged Incidents in Log",
                description="No attack records have been saved to alerts.jsonl. Intrusion events are archived here automatically when flagged.",
            )
        else:
            with st.container(border=True):
                render_card_header("Archived Threat Incidents", icon="🚨", action="Persisted in live_ids/logs/alerts.jsonl")

                col_a1, col_a2 = st.columns([2.5, 1])
                with col_a2:
                    raw_alert_json = json.dumps(alerts, indent=2).encode("utf-8")
                    st.download_button(
                        "⬇️ Download Incidents (JSON)",
                        data=raw_alert_json,
                        file_name="netdetect_threat_incidents.json",
                        mime="application/json",
                        width="stretch",
                        key="btn_dl_alerts",
                    )

                rows_html = []
                for a in alerts[:100]:
                    sev = a.get("severity", "info")
                    badge_cls = "attack" if sev in ("critical", "high") else "warning"
                    ts = str(a.get("timestamp", ""))[:19].replace("T", " ")
                    conf = f"{int(a.get('confidence', 0) * 100)}%"

                    rows_html.append(f"""
                    <tr class="is-attack">
                      <td>{ts}</td>
                      <td class="center-col"><span class="nd-badge {badge_cls}">{sev}</span></td>
                      <td><b style="color:#fafafa;">{a.get('predicted_category', 'Unknown')}</b></td>
                      <td>{a.get('src_ip', 'N/A')} &rarr; {a.get('dst_ip', 'N/A')}</td>
                      <td>{a.get('protocol_type', '-')} / {a.get('service', '-')}</td>
                      <td class="center-col"><span style="color:#fafafa;">{conf}</span></td>
                    </tr>
                    """)

                st.markdown(f"""
                <div class="nd-table-wrap">
                  <div style="max-height: 480px; overflow-y: auto;">
                    <table class="nd-table">
                      <thead>
                        <tr>
                          <th>Timestamp</th><th class="center-col">Severity</th><th>Category</th><th>Target Endpoint</th><th>Proto/Port</th><th class="center-col">Confidence</th>
                        </tr>
                      </thead>
                      <tbody>{"".join(rows_html)}</tbody>
                    </table>
                  </div>
                </div>
                """, unsafe_allow_html=True)
