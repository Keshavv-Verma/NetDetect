"""
NetDetect Reusable UI Components
Modular HTML & Streamlit UI widgets
"""

import html
import streamlit as st

def human_bytes(n):
    """Format bytes to human-readable string."""
    try:
        n = float(n)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} PB"
    except Exception:
        return "0 B"


def render_page_header(title: str, subtitle: str = "", badge_text: str = ""):
    """Standardized page header across all application views."""
    badge_html = f'<div class="nd-page-badge">{badge_text}</div>' if badge_text else ''
    st.markdown(f"""
    <div class="nd-page-header">
      <div>
        <div class="nd-page-title">{title}</div>
        <div class="nd-page-subtitle">{subtitle}</div>
      </div>
      {badge_html}
    </div>
    """, unsafe_allow_html=True)


def render_card_header(title: str, icon: str = "", action: str = ""):
    """Standardized card header for container-based panels."""
    action_html = f'<div class="nd-card-action">{action}</div>' if action else ""
    icon_html = f'<span class="icon">{icon}</span> ' if icon else ""
    st.markdown(f"""
    <div class="nd-card-header">
      <div class="nd-card-title">{icon_html}{title}</div>
      {action_html}
    </div>
    """, unsafe_allow_html=True)


def render_metric_card(label: str, value: str, subtext: str = "", color: str = "cyan", icon: str = ""):
    """Render a single modern SOC telemetry stat card."""
    st.markdown(f"""
    <div class="nd-stat-card {color}">
      <div class="nd-stat-icon">{icon}</div>
      <div class="nd-stat-label">{label}</div>
      <div class="nd-stat-value {color}">{value}</div>
      <div class="nd-stat-sub">{subtext}</div>
    </div>
    """, unsafe_allow_html=True)


def render_metric_grid(metrics: list):
    """
    Render a responsive row of metrics.
    metrics: list of tuples (label, value, subtext, color, icon)
    """
    cols = st.columns(len(metrics))
    for col, m in zip(cols, metrics):
        with col:
            render_metric_card(m[0], m[1], m[2], m[3], m[4] if len(m) > 4 else "")


def render_verdict_hero(result: dict, filename: str = "capture.pcap"):
    """High-impact SOC threat classification banner."""
    verdict = result.get("verdict", "NORMAL")
    risk_level = result.get("risk_level", "Low")
    network_status = result.get("network_status", "Safe")
    threat_intensity = result.get("threat_intensity", 0.0)
    analyst_note = result.get("analyst_note", "")
    confidence = result.get("confidence", 95.0)
    
    is_attack = verdict == "ATTACK"
    cls = "danger" if is_attack else "safe"
    icon = "⚠️" if is_attack else "🛡️"
    verdict_title = "SUSPICIOUS ACTIVITY FLAGGED" if is_attack else "NETWORK INTEGRITY VERIFIED"
    
    st.markdown(f"""
    <div class="nd-verdict-banner {cls}">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;">
        <div>
          <div class="nd-verdict-badge {cls}">{icon} {verdict} &mdash; {verdict_title}</div>
          <div style="font-size:1.15rem;font-weight:700;color:#fafafa;margin-bottom:0.4rem;word-break:break-all;">
            Capture: <span style="font-family:'JetBrains Mono',monospace;color:#ffffff;">{html.escape(filename)}</span>
          </div>
          <div style="font-size:0.85rem;color:#a1a1aa;line-height:1.6;max-width:750px;">
            Ensemble Bayesian fusion scored <b style="color:#fafafa">{result.get('total_flows', 0)}</b> bidirectional network flows.
            Security status evaluated as <b style="color:{'#f43f5e' if is_attack else '#10b981'}">{network_status.upper()}</b> with <b style="color:#ffffff">{confidence}%</b> confidence.
          </div>
        </div>
        <div class="nd-verdict-metrics">
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#71717a;letter-spacing:0.08em;text-transform:uppercase;">Threat Intensity</div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:2.2rem;font-weight:800;color:{'#f43f5e' if threat_intensity > 50 else ('#f59e0b' if threat_intensity > 25 else '#10b981')};line-height:1.1;">
            {threat_intensity}%
          </div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#a1a1aa;margin-top:0.2rem;">
            Risk Tier: <span style="color:#fafafa;font-weight:700">{risk_level.upper()}</span>
          </div>
        </div>
      </div>
      <div class="nd-analyst-box">
        <b style="color:#fafafa;font-family:'JetBrains Mono',monospace;">ANALYST ASSESSMENT:</b> {html.escape(analyst_note)}
      </div>
    </div>
    """, unsafe_allow_html=True)


def render_callout(message: str, title: str = None):
    """Render an informational SOC callout."""
    title_html = f"<b style='color:#fafafa;font-family:JetBrains Mono,monospace;'>{title}</b><br>" if title else ""
    st.markdown(f"""
    <div class="nd-callout">
      {title_html}{message}
    </div>
    """, unsafe_allow_html=True)


def render_empty_state(icon: str, title: str, description: str):
    """Empty state widget."""
    st.markdown(f"""
    <div class="nd-empty-state">
      <div class="nd-empty-icon">{icon}</div>
      <div class="nd-empty-title">{title}</div>
      <div style="max-width:420px;margin:0 auto;line-height:1.5;">{description}</div>
    </div>
    """, unsafe_allow_html=True)
