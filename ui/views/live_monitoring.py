"""
NetDetect View: Live Traffic Monitoring
Real-time streaming traffic simulation engine with live pulse strip & intrusion alerting
"""

import html
import streamlit as st
from ui.components import render_page_header, render_callout, render_metric_card
from live_ids.simulator import get_simulator
from live_ids.logger import get_stats, get_recent_alerts, get_recent_activity, clear_logs


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


def build_live_monitoring_html(stats, alerts, activity, is_running):
    total = stats.get("total_analyzed", 0)
    alerts_count = stats.get("total_alerts", 0)
    normal_count = stats.get("normal_count", 0)
    rate = f"{round((alerts_count / total) * 100, 1)}%" if total > 0 else "0.0%"

    # Pulse strip bars (last 60 records, newest on right)
    heights = {"info": 8, "low": 16, "high": 26, "critical": 36}
    pulse_records = list(reversed(activity[:60]))
    pulse_bars = []
    idle_count = max(0, 60 - len(pulse_records))
    for _ in range(idle_count):
        pulse_bars.append('<div class="nd-pulse-bar" style="height:4px"></div>')
    for r in pulse_records:
        sev = r.get("severity", "info")
        h = heights.get(sev, 6)
        pulse_bars.append(f'<div class="nd-pulse-bar {sev}" style="height:{h}px"></div>')
    pulse_strip_html = "".join(pulse_bars)

    # Alerts list
    if not alerts:
        alerts_body_html = '<div class="nd-empty-state"><div class="nd-empty-icon">🛡️</div><div class="nd-empty-title">No Threats Detected</div><div>Monitoring engine active &mdash; no intrusion alerts logged.</div></div>'
    else:
        alert_rows = []
        for a in alerts:
            sev = a.get("severity", "info")
            cat = html.escape(str(a.get("predicted_category", "Unknown")))
            src = html.escape(str(a.get("src_ip", "N/A")))
            dst = html.escape(str(a.get("dst_ip", "N/A")))
            ts = _format_time(a.get("timestamp"))
            conf = f"{int(a.get('confidence', 0) * 100)}%"
            badge_class = "attack" if sev in ("critical", "high") else ("warning" if sev == "low" else "info")
            
            alert_rows.append(
                f'<div class="nd-alert-row">'
                f'<span class="nd-badge {badge_class}" style="min-width:62px;text-align:center;">{sev}</span>'
                f'<span class="nd-alert-cat">{cat}</span>'
                f'<span class="nd-alert-ip"><span style="color:#fafafa;">{src}</span> &rarr; <span style="color:#fafafa;">{dst}</span></span>'
                f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.7rem;color:#fafafa;">{conf}</span>'
                f'<span class="nd-alert-time">{ts}</span>'
                f'</div>'
            )
        alerts_body_html = f'<div class="nd-alert-feed">{"".join(alert_rows)}</div>'

    # Activity table
    if not activity:
        activity_body_html = '<tr><td colspan="8" class="nd-empty-state">No traffic activity recorded yet. Start monitoring to ingest records.</td></tr>'
    else:
        rows = []
        for r in activity:
            is_atk = r.get("is_attack", False)
            cls = "is-attack" if is_atk else ""
            badge_cls = "attack" if is_atk else "safe"
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
                f'<td><b>{src}</b></td>'
                f'<td><b>{dst}</b></td>'
                f'<td>{proto}</td>'
                f'<td>{srv}</td>'
                f'<td>{cat}</td>'
                f'<td class="center-col"><span style="color:#fafafa;">{conf}</span></td>'
                f'<td class="center-col"><span class="nd-badge {badge_cls}">{badge_text}</span></td>'
                f'</tr>'
            )
        activity_body_html = "".join(rows)

    return f"""
    <div class="nd-pulse-container">
      <div class="nd-pulse-label-row">
        <span>LIVE TRAFFIC PULSE STRIP &middot; ROLLING 60-FLOW BUFFER</span>
        <span style="color:{'#ffffff' if is_running else '#71717a'};">
          {'STREAMING ACTIVE' if is_running else 'STANDBY'}
        </span>
      </div>
      <div class="nd-pulse-strip">{pulse_strip_html}</div>
    </div>

    <div class="nd-metric-grid" style="margin-bottom:1.4rem;">
      <div class="nd-stat-card cyan">
        <div class="nd-stat-label">Records Analyzed</div>
        <div class="nd-stat-value cyan">{total:,}</div>
        <div class="nd-stat-sub">Streaming test records</div>
      </div>
      <div class="nd-stat-card rose">
        <div class="nd-stat-label">Alerts Flagged</div>
        <div class="nd-stat-value rose">{alerts_count:,}</div>
        <div class="nd-stat-sub">Intrusions detected</div>
      </div>
      <div class="nd-stat-card emerald">
        <div class="nd-stat-label">Normal Traffic</div>
        <div class="nd-stat-value emerald">{normal_count:,}</div>
        <div class="nd-stat-sub">Clean connection flows</div>
      </div>
      <div class="nd-stat-card indigo">
        <div class="nd-stat-label">Threat Detection Rate</div>
        <div class="nd-stat-value indigo">{rate}</div>
        <div class="nd-stat-sub">Attack percentage</div>
      </div>
    </div>

    <div class="nd-monitoring-grid">
      <div class="nd-card" style="margin-bottom:0;">
        <div class="nd-card-header">
          <div class="nd-card-title"><span class="icon">🚨</span> High-Priority Alerts</div>
          <div class="nd-card-action">{len(alerts)} EVENTS</div>
        </div>
        {alerts_body_html}
      </div>

      <div class="nd-card" style="margin-bottom:0;">
        <div class="nd-card-header">
          <div class="nd-card-title"><span class="icon">📜</span> Live Activity Ledger</div>
          <div class="nd-card-action">{len(activity)} LOGGED</div>
        </div>
        <div class="nd-table-wrap">
          <div style="max-height: 480px; overflow-y: auto;">
            <table class="nd-table">
              <thead>
                <tr>
                  <th>Time</th><th>Src IP</th><th>Dst IP</th><th>Proto</th><th>Service</th><th>Category</th><th class="center-col">Conf</th><th class="center-col">Status</th>
                </tr>
              </thead>
              <tbody>{activity_body_html}</tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """


def _render_monitoring_markup(html_markup):
    if hasattr(st, "html"):
        st.html(html_markup)
    else:
        st.markdown(html_markup, unsafe_allow_html=True)


@st.fragment(run_every=1.5)
def _render_live_monitoring_fragment():
    stats = get_stats()
    alerts = get_recent_alerts(30)
    activity = get_recent_activity(50)
    html_markup = build_live_monitoring_html(stats, alerts, activity, is_running=True)
    _render_monitoring_markup(html_markup)


@st.fragment()
def _render_static_monitoring_fragment():
    stats = get_stats()
    alerts = get_recent_alerts(30)
    activity = get_recent_activity(50)
    html_markup = build_live_monitoring_html(stats, alerts, activity, is_running=False)
    _render_monitoring_markup(html_markup)


def render_monitoring_view():
    render_page_header(
        title="Live Traffic Monitoring & Simulation",
        subtitle="Real-time multi-threaded traffic replay, NSL-KDD multi-class inference, and alert streaming",
        badge_text="REAL-TIME SPA STREAM",
    )

    sim = get_simulator()
    is_running = sim.is_running()

    render_callout(
        "<b>Live Traffic Engine:</b> Replays real connection records from the <b>NSL-KDD benchmark</b> through a trained "
        "multi-class Random Forest detector on a continuous 1.5s timer. Every record receives dynamic IP synthesis, "
        "scores for multi-class taxonomy (<b>DoS, Probe, R2L, U2R</b>), and streams into the audit ledger without requiring raw sockets.",
        title="SIMULATION TELEMETRY"
    )

    # Simulation Controls Bar
    st.markdown("""
    <div style="background:var(--nd-bg-card);border:1px solid var(--nd-border-card);border-radius:10px;padding:0.9rem 1.4rem;margin-bottom:1.4rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
    """, unsafe_allow_html=True)

    c_status, c_start, c_stop, c_reset = st.columns([2.5, 1.2, 1.2, 1])

    with c_status:
        if is_running:
            st.markdown("""
            <div style="padding-top:6px;">
              <span class="nd-badge safe" style="padding:4px 10px;font-size:0.72rem;">
                <span class="nd-status-dot active" style="margin-right:6px;"></span>
                STREAMING LIVE // 1.5s POLLING
              </span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="padding-top:6px;">
              <span class="nd-badge neutral" style="padding:4px 10px;font-size:0.72rem;">
                <span class="nd-status-dot" style="background:#71717a;box-shadow:none;margin-right:6px;"></span>
                ENGINE STOPPED
              </span>
            </div>
            """, unsafe_allow_html=True)

    with c_start:
        if st.button("▶  Start Stream", disabled=is_running, key="btn_sim_start", width="stretch"):
            sim.start()
            st.session_state["monitoring"] = True
            st.rerun()

    with c_stop:
        # Wrap stop in subtle/danger style container
        st.markdown('<div class="nd-stop-btn">', unsafe_allow_html=True)
        if st.button("⏹  Stop Stream", disabled=not is_running, key="btn_sim_stop", width="stretch"):
            sim.stop()
            st.session_state["monitoring"] = False
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    with c_reset:
        st.markdown('<div class="nd-subtle-btn">', unsafe_allow_html=True)
        if st.button("🔄  Reset Logs", key="btn_sim_reset", width="stretch"):
            clear_logs()
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

    # Dynamic Fragment Rendering
    if is_running:
        _render_live_monitoring_fragment()
    else:
        _render_static_monitoring_fragment()
