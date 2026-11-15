"""
NetDetect View: Traffic Analysis
PCAP/PCAPNG file upload, pipeline inspection, and flow extraction
"""

import os
import time
import tempfile
import threading
import streamlit as st
import pandas as pd
from ui.components import (
    render_page_header,
    render_callout,
    render_verdict_hero,
    render_card_header,
    human_bytes,
)

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "models")
SAMPLE_PCAP_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "sample_pcaps", "sample_traffic.pcap")


@st.cache_resource(show_spinner=False)
def load_artifacts_cached():
    try:
        from prediction import load_artifacts
        return load_artifacts(MODELS_DIR), None
    except Exception as e:
        return None, str(e)


def execute_pcap_analysis(pcap_path: str):
    """Run flow feature extraction and Bayesian fusion inference via backend service."""
    try:
        from backend.services.analysis_service import AnalysisService
        service = AnalysisService()
        filename = os.path.basename(pcap_path)
        report, raw_df, result = service.analyze_pcap_sync(pcap_path, filename)

        # Attach rich metadata and explanations for UI consumption
        result["analysis_id"] = report.analysis_id
        result["explanations"] = report.explanations
        result["total_packets"] = report.total_packets
        result["duration_seconds"] = report.duration_seconds
        return result, raw_df, None
    except Exception as e:
        return None, None, str(e)


def render_analysis_view():
    render_page_header(
        title="PCAP Traffic Analysis",
        subtitle="Deep packet capture inspection, flow extraction, and ensemble threat classification",
        badge_text="OFFLINE INSPECTOR",
    )

    render_callout(
        "Upload a packet capture (<b>.pcap</b> or <b>.pcapng</b>) to extract bi-directional network flows. "
        "The system computes 32–42 statistical flow attributes (duration, jitter, packet sizes, window advertisements) "
        "and evaluates them against an ensemble of <b>XGBoost</b>, <b>LightGBM</b>, <b>Random Forest</b>, and <b>Isolation Forest</b> models.",
        title="ANALYST ADVISORY"
    )

    # File Upload & Sample Loader Card
    with st.container(border=True):
        render_card_header("Ingestion Interface", icon="📥", action="Supported: .pcap, .pcapng, .cap · Max 50 MB")

        c_upload, c_sample = st.columns([2.2, 1])

        with c_upload:
            uploaded = st.file_uploader(
                "Drop your packet capture file here",
                type=["pcap", "pcapng", "cap"],
                label_visibility="collapsed",
                key="pcap_file_uploader",
            )

        with c_sample:
            st.markdown("""
            <div style="background:var(--nd-bg-surface);border:1px solid var(--nd-border-card);border-radius:10px;padding:0.9rem 1.1rem;margin-bottom:0.8rem;">
              <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#a1a1aa;font-weight:600;margin-bottom:0.4rem;">
                QUICK EVALUATION
              </div>
              <div style="font-size:0.75rem;color:#71717a;line-height:1.4;">
                Don't have a capture handy? Load the pre-configured sample traffic capture.
              </div>
            </div>
            """, unsafe_allow_html=True)
            
            sample_exists = os.path.isfile(SAMPLE_PCAP_PATH)
            if st.button("⚡  Load Sample PCAP", disabled=not sample_exists, width="stretch", key="btn_load_sample"):
                st.session_state["trigger_sample_analysis"] = True
                st.rerun()

    # Process either uploaded file or triggered sample file
    file_to_process = None
    file_name = ""
    file_size = 0
    is_sample = False

    if st.session_state.get("trigger_sample_analysis"):
        st.session_state["trigger_sample_analysis"] = False
        if os.path.isfile(SAMPLE_PCAP_PATH):
            with open(SAMPLE_PCAP_PATH, "rb") as f:
                file_bytes = f.read()
            file_to_process = file_bytes
            file_name = "sample_traffic.pcap"
            file_size = len(file_bytes)
            is_sample = True
    elif uploaded is not None:
        file_to_process = uploaded.getvalue()
        file_name = uploaded.name
        file_size = len(file_to_process)

    if file_to_process is not None:
        st.markdown(f"""
        <div style="background:var(--nd-bg-elevated);border:1px solid rgba(255,255,255,0.18);border-radius:8px;padding:0.8rem 1.2rem;margin:1rem 0;display:flex;justify-content:space-between;align-items:center;flex-wrap:gap:0.8rem;">
          <div style="display:flex;align-items:center;gap:0.8rem;">
            <span style="font-size:1.3rem;">📎</span>
            <div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:0.82rem;font-weight:700;color:#fafafa;">
                {file_name} {'(Pre-loaded Sample)' if is_sample else ''}
              </div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#71717a;">
                Payload Size: <span style="color:#ffffff;">{human_bytes(file_size)}</span> &middot; Format: Valid Packet Capture
              </div>
            </div>
          </div>
          <div>
            <span class="nd-badge safe">READY FOR EXTRACTION</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

        if file_size == 0:
            st.warning("⚠️ The capture file is 0 bytes. Please provide a valid packet capture.")
        elif file_size > 50 * 1024 * 1024:
            st.error("⚠️ File size exceeds the 50 MB threshold. Please supply a smaller capture file.")
        else:
            col_act1, col_act2, col_act3 = st.columns([1, 1.4, 1])
            with col_act2:
                btn_label = "🔬  Run Full Security Inspection" if not is_sample else "🔬  Analyze Sample Traffic"
                run_btn = st.button(btn_label, width="stretch", key="btn_run_analysis")
                
            if run_btn:
                temp_pcap = None
                try:
                    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                        tmp.write(file_to_process)
                        temp_pcap = tmp.name

                    progress_placeholder = st.empty()
                    steps = [
                        ("Decoding raw Ethernet & IP frame headers…", 0.20),
                        ("Synthesizing bi-directional network flow attributes…", 0.45),
                        ("Executing XGBoost, LightGBM, and Random Forest ensemble…", 0.70),
                        ("Scanning for zero-day outliers via Isolation Forest…", 0.85),
                        ("Computing Bayesian probability fusion & final verdict…", 1.00),
                    ]

                    with progress_placeholder.container():
                        st.markdown("""
                        <div class="nd-pipeline-wrap">
                          <div style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;font-weight:700;color:#ffffff;margin-bottom:0.6rem;">
                            ANALYSIS PIPELINE EXECUTING
                          </div>
                        """, unsafe_allow_html=True)
                        prog_bar = st.progress(0)
                        status_msg = st.empty()
                        
                        start_time = time.time()
                        result, raw_df, err = None, None, None

                        def _worker():
                            nonlocal result, raw_df, err
                            result, raw_df, err = execute_pcap_analysis(temp_pcap)

                        t = threading.Thread(target=_worker, daemon=True)
                        t.start()

                        step_idx = 0
                        while t.is_alive():
                            if step_idx < len(steps):
                                label, pct = steps[step_idx]
                                prog_bar.progress(pct)
                                status_msg.markdown(f"""
                                <div style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#a1a1aa;padding:0.3rem 0;">
                                  <span style="color:#ffffff;">&bull;</span> {label}
                                </div>
                                """, unsafe_allow_html=True)
                                step_idx = (step_idx + 1) % len(steps)
                            time.sleep(0.8)

                        t.join()
                        prog_bar.progress(1.0)
                        status_msg.empty()
                        st.markdown("</div>", unsafe_allow_html=True)

                    progress_placeholder.empty()

                    if err:
                        st.error(f"❌ Analysis failed: {err}")
                    else:
                        elapsed = round(time.time() - start_time, 2)
                        st.session_state["upload_result"] = result
                        st.session_state["upload_raw_df"] = raw_df
                        st.session_state["upload_name"] = file_name
                        st.session_state["upload_elapsed"] = elapsed

                        # Append to session history
                        if "pcap_history" not in st.session_state:
                            st.session_state["pcap_history"] = []
                        st.session_state["pcap_history"].append({
                            "filename": file_name,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "verdict": result.get("verdict"),
                            "risk_level": result.get("risk_level"),
                            "flows": result.get("total_flows"),
                            "intensity": result.get("threat_intensity"),
                        })

                        st.success(f"✅ Inspection complete in {elapsed}s! Processed {result.get('total_flows')} network flows.")
                        st.rerun()

                finally:
                    if temp_pcap and os.path.exists(temp_pcap):
                        try:
                            os.unlink(temp_pcap)
                        except Exception:
                            pass

    # If results exist in session state, display immediate high-level summary
    if "upload_result" in st.session_state:
        st.markdown("<div style='margin-top:1.4rem;'></div>", unsafe_allow_html=True)
        render_verdict_hero(
            st.session_state["upload_result"],
            filename=st.session_state.get("upload_name", "capture.pcap"),
        )
        
        # Shortcut action buttons to Results and Visualization
        col_g1, col_g2 = st.columns(2)
        with col_g1:
            if st.button("🎯  Open Full Detection Results & Flow Table", width="stretch", key="btn_goto_results"):
                st.session_state.active_nav_key = "results"
                st.rerun()
        with col_g2:
            if st.button("🌐  Explore Interactive Network Visualizations", width="stretch", key="btn_goto_viz"):
                st.session_state.active_nav_key = "visualization"
                st.rerun()
