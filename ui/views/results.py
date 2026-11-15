"""
NetDetect View: Detection Results
Threat classifications, Bayesian fusion breakdown, and flow audit table
"""

import streamlit as st
import pandas as pd
import numpy as np
from ui.components import (
    render_page_header,
    render_metric_grid,
    render_verdict_hero,
    render_empty_state,
    render_callout,
    render_card_header,
)


def render_results_view():
    render_page_header(
        title="Detection Results & Threat Analysis",
        subtitle="Classification breakdown, Bayesian decision metrics, and flow-level anomaly inspection",
        badge_text="VERDICT CONSOLE",
    )

    result = st.session_state.get("upload_result")
    raw_df = st.session_state.get("upload_raw_df")
    filename = st.session_state.get("upload_name", "capture.pcap")

    if not result:
        render_empty_state(
            icon="🎯",
            title="No Analysis Results Available",
            description="Run a PCAP traffic inspection first to inspect flow classifications, threat levels, and individual connection anomaly scores.",
        )
        col1, col2, col3 = st.columns([1, 1.2, 1])
        with col2:
            if st.button("📁  Go To Traffic Analysis", key="btn_res_goto_analysis", width="stretch"):
                st.session_state.active_nav_key = "analysis"
                st.rerun()
        return

    # Threat Verdict Hero Banner
    render_verdict_hero(result, filename=filename)

    scores = np.array(result.get("all_flow_scores", []))
    n = result.get("total_flows", len(scores))
    attack_flows = int(sum(scores >= 0.5))
    safe_flows = n - attack_flows

    # Key Evaluation Metrics
    metrics = [
        ("Total Flows Evaluated", f"{n:,}", "Bidirectional network conversations", "cyan", "🌐"),
        ("Flagged Threats", f"{attack_flows:,}", f"{round(attack_flows/n*100, 1) if n > 0 else 0}% anomaly density", "rose" if attack_flows > 0 else "emerald", "⚠️"),
        ("Model Confidence", f"{result.get('confidence', 95)}%", "Statistical certainty score", "indigo", "🤖"),
        ("Peak Risk Index", f"Flow #{result.get('peak_flow_index', 1)}", f"Score: {max(scores) if len(scores) > 0 else 0:.3f}", "amber", "📍"),
    ]
    render_metric_grid(metrics)

    # Bayesian Model Fusion Architecture Explainer
    with st.expander("⚖️  Bayesian Fusion & Ensemble Decision Logic (Click to view)", expanded=False):
        st.markdown("""
        <div class="nd-callout">
          <b>How the verdict is determined:</b><br>
          NetDetect employs a <b>Hybrid Bayesian Fusion</b> strategy to neutralize false positives while retaining zero-day sensitivity:
          <ul style="margin: 0.5rem 0 0.5rem 1.2rem; line-height: 1.8;">
            <li><b>Supervised Ensemble (50% weight):</b> Random Forest, LightGBM, and XGBoost vote collectively on known exploit signatures.</li>
            <li><b>Unsupervised Anomaly Detector (50% weight):</b> Isolation Forest isolates multi-dimensional feature outliers without requiring pre-existing attack labels.</li>
            <li><b>Decision Threshold:</b> A flow is classified as malicious if the combined posterior score is &ge; <b>0.50</b>. If the attack flow ratio exceeds <b>30%</b>, the overall capture status shifts to <b>ATTACK / DANGER</b>.</li>
          </ul>
        </div>
        """, unsafe_allow_html=True)

    # Evidence-Based Explainability Layer
    explanations = result.get("explanations", [])
    if explanations:
        with st.expander("🔍  Evidence-Based Detection Explanations (Click to view)", expanded=False):
            st.markdown("""
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#ffffff;font-weight:700;margin-bottom:0.6rem;">
              ANOMALY REASONING & FEATURE EVIDENCE
            </div>
            """, unsafe_allow_html=True)
            for exp in explanations:
                f_id = exp.get("flow_id")
                score = exp.get("threat_score", 0.0)
                reasons = exp.get("primary_reasons", [])
                src = exp.get("source", "N/A")
                dst = exp.get("destination", "N/A")
                is_atk = score >= 0.50
                badge_cls = "attack" if is_atk else "safe"
                badge_txt = "FLAGGED" if is_atk else "NOMINAL"

                reasons_html = "".join([f"<li style='margin-bottom:3px;'>{r}</li>" for r in reasons]) if reasons else "<li>No anomalous outlier indicators detected.</li>"
                st.markdown(f"""
                <div style="background:#121215;border:1px solid rgba(255,255,255,0.12);border-radius:8px;padding:0.75rem 1rem;margin-bottom:0.6rem;">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.4rem;flex-wrap:wrap;gap:0.5rem;">
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#fafafa;font-weight:700;">
                      Flow #{f_id}: <span style="color:#ffffff;">{src} &rarr; {dst}</span>
                    </span>
                    <div>
                      <span class="nd-badge {badge_cls}">{badge_txt} (Score: {score:.4f})</span>
                    </div>
                  </div>
                  <ul style="font-size:0.75rem;color:#a1a1aa;margin:0 0 0 1.2rem;line-height:1.5;">
                    {reasons_html}
                  </ul>
                </div>
                """, unsafe_allow_html=True)

    # Enriched Flow Table with Search and Filtering
    with st.container(border=True):
        render_card_header("Flow-Level Anomaly Ledger", icon="🔬", action="Interactive Filter & CSV Export")

        # Construct unified dataframe
        if raw_df is not None:
            table_df = raw_df.copy()
        else:
            table_df = pd.DataFrame()

        table_df["flow_id"] = list(range(1, len(scores) + 1))
        table_df["threat_score"] = scores
        table_df["verdict"] = ["ATTACK" if s >= 0.5 else "NORMAL" for s in scores]

        # Filter toolbar
        c_flt1, c_flt2, c_flt3, c_flt4 = st.columns([1.2, 1.2, 1.4, 1.2])

        with c_flt1:
            verdict_filter = st.selectbox(
                "Verdict Filter",
                ["All Flows", "Flagged Attacks Only", "Normal Traffic Only"],
                key="res_flt_verdict",
            )

        with c_flt2:
            proto_options = ["All Protocols"]
            if "proto" in table_df.columns:
                proto_options += sorted(table_df["proto"].astype(str).unique().tolist())
            proto_filter = st.selectbox("Protocol", proto_options, key="res_flt_proto")

        with c_flt3:
            min_score = st.slider(
                "Min Threat Score",
                min_value=0.0,
                max_value=1.0,
                value=0.0,
                step=0.05,
                key="res_flt_score",
            )

        with c_flt4:
            st.markdown("<div style='font-family:\"JetBrains Mono\",monospace;font-size:0.7rem;color:#71717a;margin-bottom:0.35rem;text-transform:uppercase;'>Export Ledger</div>", unsafe_allow_html=True)
            # CSV Export
            csv_data = table_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="⬇️ Export CSV",
                data=csv_data,
                file_name=f"netdetect_flows_{filename.split('.')[0]}.csv",
                mime="text/csv",
                width="stretch",
                key="btn_export_csv",
            )

        # Apply filters
        filtered_df = table_df.copy()
        if verdict_filter == "Flagged Attacks Only":
            filtered_df = filtered_df[filtered_df["verdict"] == "ATTACK"]
        elif verdict_filter == "Normal Traffic Only":
            filtered_df = filtered_df[filtered_df["verdict"] == "NORMAL"]

        if proto_filter != "All Protocols" and "proto" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["proto"].astype(str) == proto_filter]

        filtered_df = filtered_df[filtered_df["threat_score"] >= min_score]

        st.markdown(f"""
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#a1a1aa;margin-bottom:0.8rem;">
          Showing <b style="color:#ffffff;">{len(filtered_df):,}</b> of {len(table_df):,} matching flow records
        </div>
        """, unsafe_allow_html=True)

        # Select display columns
        key_cols = ["flow_id", "threat_score", "verdict"]
        optional_cols = ["proto", "service", "state", "sbytes", "dbytes", "spkts", "dpkts", "dur", "sttl"]
        numeric_fields = {'sbytes', 'dbytes', 'spkts', 'dpkts', 'dur', 'sttl'}
        available_optional = [c for c in optional_cols if c in filtered_df.columns]
        display_cols = ["flow_id", "threat_score", "verdict"] + available_optional

        # Render formatted table
        preview_df = filtered_df[display_cols].head(150)
        
        rows_html = []
        for _, row in preview_df.iterrows():
            is_atk = row["verdict"] == "ATTACK"
            cls = "is-attack" if is_atk else ""
            badge_cls = "attack" if is_atk else "safe"
            
            tds = [
                f"<td class='center-col'><b>#{int(row['flow_id'])}</b></td>",
                f"<td class='center-col'><span style='color:{'#f43f5e' if is_atk else '#10b981'};font-weight:700;'>{row['threat_score']:.4f}</span></td>",
                f"<td class='center-col'><span class='nd-badge {badge_cls}'>{row['verdict']}</span></td>",
            ]
            for c in available_optional:
                val = row[c]
                cls_col = " class='num-col'" if c in numeric_fields else ""
                if isinstance(val, (int, np.integer)):
                    val_str = f"{val:,}"
                elif isinstance(val, (float, np.floating)):
                    val_str = f"{val:.3f}"
                else:
                    val_str = str(val)
                tds.append(f"<td{cls_col}>{val_str}</td>")
                
            rows_html.append(f"<tr class='{cls}'>{''.join(tds)}</tr>")

        headers_html = "".join([
            f"<th class='center-col'>{c.upper()}</th>" if c in ("flow_id", "threat_score", "verdict")
            else (f"<th class='num-col'>{c.upper()}</th>" if c in numeric_fields else f"<th>{c.upper()}</th>")
            for c in display_cols
        ])

        st.markdown(f"""
        <div class="nd-table-wrap">
          <div style="max-height: 480px; overflow-y: auto;">
            <table class="nd-table">
              <thead><tr>{headers_html}</tr></thead>
              <tbody>{"".join(rows_html)}</tbody>
            </table>
          </div>
        </div>
        """, unsafe_allow_html=True)
