"""
NetDetect Chart & Visualization Module
Cohesive SOC dark data visualization using Plotly
"""

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

# SOC Dark Visualization Theme
SOC_PALETTE = {
    "cyan":     "#f4f4f5",
    "indigo":   "#a1a1aa",
    "blue":     "#d4d4d8",
    "emerald":  "#10b981",
    "amber":    "#f59e0b",
    "rose":     "#f43f5e",
    "orange":   "#f97316",
    "slate":    "#27272a",
    "slate_lit": "#a1a1aa",
    "bg_subtle": "rgba(24, 24, 27, 0.8)",
}

def get_soc_layout(title="", height=300):
    return dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#fafafa", size=11),
        title=dict(
            text=title,
            font=dict(size=12, color="#a1a1aa", family="JetBrains Mono, monospace"),
            x=0.01,
            y=0.98,
        ),
        margin=dict(l=35, r=20, t=36 if title else 18, b=36),
        height=height,
        showlegend=True,
        hoverlabel=dict(
            bgcolor="#18181b",
            bordercolor="rgba(255, 255, 255, 0.25)",
            font_size=11,
            font_family="JetBrains Mono, monospace",
            font_color="#fafafa",
        ),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            bordercolor="rgba(0,0,0,0)",
            font=dict(size=10, family="JetBrains Mono, monospace"),
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
        ),
        xaxis=dict(
            gridcolor="rgba(255, 255, 255, 0.06)",
            zerolinecolor="rgba(255, 255, 255, 0.1)",
            tickfont=dict(size=10, family="JetBrains Mono, monospace", color="#71717a"),
        ),
        yaxis=dict(
            gridcolor="rgba(255, 255, 255, 0.06)",
            zerolinecolor="rgba(255, 255, 255, 0.1)",
            tickfont=dict(size=10, family="JetBrains Mono, monospace", color="#71717a"),
        ),
    )


def build_flow_threat_chart(scores, height=270):
    """Per-flow threat scores with threshold boundary line."""
    n = len(scores)
    x = list(range(1, n + 1))
    colors = [SOC_PALETTE["rose"] if s >= 0.5 else SOC_PALETTE["emerald"] for s in scores]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=x,
        y=scores,
        marker=dict(color=colors, line=dict(width=0)),
        hovertemplate="Flow %{x}<br>Threat Score: <b>%{y:.3f}</b><extra></extra>",
        name="Flow Threat Score",
    ))
    
    fig.add_hline(
        y=0.5,
        line_dash="dash",
        line_color=SOC_PALETTE["amber"],
        line_width=1.5,
        annotation_text="Risk Threshold (0.50)",
        annotation_font_color=SOC_PALETTE["amber"],
        annotation_font_size=10,
        annotation_font_family="JetBrains Mono",
        annotation_position="top right",
    )
    
    layout = get_soc_layout(height=height)
    layout.update(
        bargap=0.15,
        xaxis_title="Analyzed Flow Index",
        yaxis_title="Threat Score",
        showlegend=False,
    )
    fig.update_layout(**layout)
    return fig


def build_traffic_donut(safe_flows, attack_flows, height=270):
    """Traffic distribution donut chart."""
    total = safe_flows + attack_flows
    safe_pct = round((safe_flows / total) * 100) if total > 0 else 0
    
    fig = go.Figure(go.Pie(
        labels=["Normal Flows", "Threat Flows"],
        values=[safe_flows, attack_flows],
        hole=0.68,
        marker=dict(
            colors=[SOC_PALETTE["emerald"], SOC_PALETTE["rose"]],
            line=dict(color="#121215", width=2),
        ),
        textfont=dict(size=11, family="JetBrains Mono"),
        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Ratio: %{percent}<extra></extra>",
    ))
    
    fig.add_annotation(
        text=f"<b>{safe_pct}%</b><br><span style='font-size:10px;color:#a1a1aa'>NORMAL</span>",
        x=0.5, y=0.5,
        showarrow=False,
        font=dict(size=16, color=SOC_PALETTE["emerald"], family="JetBrains Mono"),
    )
    
    layout = get_soc_layout(height=height)
    layout.update(showlegend=True)
    fig.update_layout(**layout)
    return fig


def build_protocol_chart(raw_df, height=250):
    """Protocol distribution bar chart."""
    proto_col = 'proto' if 'proto' in raw_df.columns else raw_df.columns[0]
    counts = raw_df[proto_col].value_counts().head(8)
    
    fig = go.Figure(go.Bar(
        x=counts.index.astype(str).tolist(),
        y=counts.values.tolist(),
        marker=dict(
            color=counts.values.tolist(),
            colorscale=[[0, "#3f3f46"], [0.5, "#a1a1aa"], [1, "#f4f4f5"]],
            showscale=False,
            line=dict(width=0),
        ),
        hovertemplate="Protocol: <b>%{x}</b><br>Flows: %{y}<extra></extra>",
    ))
    
    layout = get_soc_layout(height=height)
    layout.update(
        xaxis_title="Network Protocol",
        yaxis_title="Flow Count",
        showlegend=False,
    )
    fig.update_layout(**layout)
    return fig


def build_services_chart(raw_df, height=250):
    """Top services contacted horizontal bar chart."""
    svc_col = 'service' if 'service' in raw_df.columns else None
    if not svc_col:
        return None
        
    counts = raw_df[svc_col].value_counts().head(8)
    
    fig = go.Figure(go.Bar(
        x=counts.values.tolist(),
        y=counts.index.astype(str).tolist(),
        orientation='h',
        marker=dict(
            color=counts.values.tolist(),
            colorscale=[[0, "#27272a"], [1, "#d4d4d8"]],
            showscale=False,
        ),
        hovertemplate="Service: <b>%{y}</b><br>Active Flows: %{x}<extra></extra>",
    ))
    
    layout = get_soc_layout(height=height)
    layout.update(
        xaxis_title="Flow Count",
        yaxis_title="Service Port",
        showlegend=False,
    )
    fig.update_layout(**layout)
    return fig


def build_threat_histogram(scores, height=220):
    """Threat score distribution histogram with risk partition."""
    bins = np.linspace(0, 1, 21)
    hist, edges = np.histogram(scores, bins=bins)
    bar_colors = [
        SOC_PALETTE["emerald"] if (e + edges[i+1]) / 2 < 0.5 else SOC_PALETTE["rose"]
        for i, e in enumerate(edges[:-1])
    ]
    
    fig = go.Figure(go.Bar(
        x=[round((edges[i] + edges[i+1]) / 2, 2) for i in range(len(hist))],
        y=hist.tolist(),
        marker_color=bar_colors,
        width=0.042,
        hovertemplate="Score range [%{x}]: <b>%{y}</b> connections<extra></extra>",
    ))
    
    fig.add_vline(
        x=0.5,
        line_dash="dash",
        line_color=SOC_PALETTE["amber"],
        line_width=1.5,
        annotation_text="Anomaly Boundary",
        annotation_font_color=SOC_PALETTE["amber"],
        annotation_font_size=10,
        annotation_font_family="JetBrains Mono",
        annotation_position="top right",
    )
    
    layout = get_soc_layout(height=height)
    layout.update(
        xaxis_title="Threat Score (0.0 Normal — 1.0 Malicious)",
        yaxis_title="Connection Density",
        showlegend=False,
    )
    fig.update_layout(**layout)
    return fig


def build_volume_chart(raw_df, height=220):
    """Data transfer volume per connection stream."""
    sample_n = min(120, len(raw_df))
    sample_df = raw_df.head(sample_n)
    
    fig = go.Figure()
    if 'sbytes' in raw_df.columns:
        fig.add_trace(go.Scatter(
            y=sample_df['sbytes'].tolist(),
            name="Tx Sent Bytes",
            fill='tozeroy',
            line=dict(color="#71717a", width=1.8),
            fillcolor="rgba(113, 113, 122, 0.15)",
            hovertemplate="Flow %{x}<br>Tx Sent: <b>%{y:,.0f} B</b><extra></extra>",
        ))
    if 'dbytes' in raw_df.columns:
        fig.add_trace(go.Scatter(
            y=sample_df['dbytes'].tolist(),
            name="Rx Received Bytes",
            fill='tozeroy',
            line=dict(color="#d4d4d8", width=1.8),
            fillcolor="rgba(212, 212, 216, 0.12)",
            hovertemplate="Flow %{x}<br>Rx Received: <b>%{y:,.0f} B</b><extra></extra>",
        ))
        
    layout = get_soc_layout(height=height)
    layout.update(
        xaxis_title="Sampled Connection Stream",
        yaxis_title="Transferred Bytes",
    )
    fig.update_layout(**layout)
    return fig


def build_live_category_chart(category_counts, height=260):
    """Live traffic classification breakdown pie."""
    labels = list(category_counts.keys())
    values = list(category_counts.values())
    
    color_map = {
        "Normal":  SOC_PALETTE["emerald"],
        "DoS":     SOC_PALETTE["rose"],
        "Probe":   SOC_PALETTE["amber"],
        "R2L":     SOC_PALETTE["orange"],
        "U2R":     "#dc2626",
    }
    colors = [color_map.get(lbl, SOC_PALETTE["blue"]) for lbl in labels]
    
    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.6,
        marker=dict(colors=colors, line=dict(color="#121215", width=2)),
        textfont=dict(size=11, family="JetBrains Mono"),
        hovertemplate="<b>%{label}</b><br>Records: %{value}<br>Ratio: %{percent}<extra></extra>",
    ))
    
    layout = get_soc_layout(height=height)
    layout.update(showlegend=True)
    fig.update_layout(**layout)
    return fig


def build_severity_bar_chart(severity_counts, height=240):
    """Live alerts severity breakdown bar chart."""
    sev_order = ["info", "low", "high", "critical"]
    labels = [s.upper() for s in sev_order if s in severity_counts]
    values = [severity_counts.get(s, 0) for s in sev_order if s in severity_counts]
    
    color_map = {
        "INFO":     SOC_PALETTE["cyan"],
        "LOW":      SOC_PALETTE["amber"],
        "HIGH":     SOC_PALETTE["orange"],
        "CRITICAL": SOC_PALETTE["rose"],
    }
    colors = [color_map.get(l, SOC_PALETTE["slate"]) for l in labels]
    
    fig = go.Figure(go.Bar(
        x=labels,
        y=values,
        marker=dict(color=colors, line=dict(width=0)),
        hovertemplate="Severity: <b>%{x}</b><br>Alerts: %{y}<extra></extra>",
    ))
    
    layout = get_soc_layout(height=height)
    layout.update(
        xaxis_title="Alert Severity Level",
        yaxis_title="Total Events",
        showlegend=False,
    )
    fig.update_layout(**layout)
    return fig
