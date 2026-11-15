"""
NetDetect Analysis Orchestration Service.
Coordinates file validation, single-pass feature extraction, protected ML inference,
explainability generation, and persistent database archiving.
"""
import time
import uuid
import threading
from pathlib import Path
from typing import Union, Tuple, Dict, Any, Optional

import pandas as pd

from backend.config.settings import MODELS_DIR
from backend.utils.file_utils import SafeTempFile
from backend.utils.logger import get_logger
from backend.utils.exceptions import NetDetectError, FileValidationError, PacketExtractionError, InferenceError
from backend.services.upload_service import UploadService
from backend.packet_processing.extractor import extract_all_features_optimized
from backend.reporting.threat_report import generate_threat_report, ThreatReport
from backend.reporting.explanations import explain_prediction
from backend.database.models import AnalysisRecord
from backend.database.repository import AnalysisRepository
from prediction import load_artifacts, run_prediction

logger = get_logger("analysis_service")


class AnalysisTask:
    """Represents a tracked analysis execution with thread-safe progress status."""
    def __init__(self, task_id: str, filename: str):
        self.task_id = task_id
        self.filename = filename
        self.status = "PENDING"          # PENDING, PROCESSING, COMPLETED, FAILED, CANCELLED
        self.progress = 0.0              # 0.0 to 1.0
        self.stage_message = "Task initialized"
        self.result: Optional[ThreatReport] = None
        self.raw_df: Optional[pd.DataFrame] = None
        self.prediction_result: Optional[dict] = None
        self.error: Optional[str] = None
        self._cancel_flag = threading.Event()
        self.start_time = time.time()
        self.elapsed_seconds = 0.0

    def update_progress(self, progress: float, stage: str):
        self.progress = progress
        self.stage_message = stage
        self.elapsed_seconds = round(time.time() - self.start_time, 2)
        logger.debug(f"Task {self.task_id} [{self.progress*100:.0f}%]: {stage}")

    def cancel(self):
        self._cancel_flag.set()
        self.status = "CANCELLED"
        self.stage_message = "Analysis cancelled by user"

    def is_cancelled(self) -> bool:
        return self._cancel_flag.is_set()


class AnalysisService:
    """Service orchestrating end-to-end network traffic anomaly detection."""

    _cached_artifacts = None
    _artifacts_lock = threading.Lock()

    def __init__(self, repository: AnalysisRepository = None, models_dir: Path = None):
        self.repository = repository or AnalysisRepository()
        self.models_dir = str(models_dir or MODELS_DIR)

    def analyze_pcap_async(
        self,
        file_input: Union[str, Path, bytes],
        filename: str
    ) -> AnalysisTask:
        """
        Execute PCAP analysis asynchronously in a background worker thread.
        Returns the tracked AnalysisTask object immediately.
        """
        task_id = str(uuid.uuid4())
        task = AnalysisTask(task_id, filename)
        
        thread = threading.Thread(
            target=self.analyze_pcap_sync,
            args=(file_input, filename, task),
            daemon=True,
            name=f"netdetect-analysis-{task_id[:8]}"
        )
        thread.start()
        return task

    def get_artifacts(self) -> dict:
        """Thread-safe cached loader for protected ML model artifacts."""
        with self._artifacts_lock:
            if AnalysisService._cached_artifacts is None:
                logger.info(f"Loading protected ML artifacts from {self.models_dir}...")
                AnalysisService._cached_artifacts = load_artifacts(self.models_dir)
                logger.info("Protected ML model artifacts loaded successfully.")
            return AnalysisService._cached_artifacts

    def analyze_pcap_sync(
        self,
        file_input: Union[str, Path, bytes],
        filename: str,
        task: AnalysisTask = None
    ) -> Tuple[ThreatReport, pd.DataFrame, dict]:
        """
        Execute synchronous PCAP analysis pipeline with database recording.
        """
        analysis_id = str(uuid.uuid4())
        start_time = time.time()

        if task:
            task.update_progress(0.05, "Validating file integrity and magic headers...")

        # 1. Validation & Staging
        safe_filename, file_hash, file_size, format_type = UploadService.process_and_validate(file_input, filename)

        # Initialize persistent DB record
        record = AnalysisRecord(
            id=analysis_id,
            filename=safe_filename,
            file_hash=file_hash,
            file_size_bytes=file_size,
            status="PROCESSING",
        )
        self.repository.save(record)

        try:
            # 2. Extract features from PCAP via safe temporary file if bytes were passed
            if isinstance(file_input, (bytes, bytearray)):
                with SafeTempFile(content=file_input, suffix=f".{format_type}") as tmp_path:
                    raw_df, meta, prediction_result = self._execute_pipeline(tmp_path, task)
            else:
                raw_df, meta, prediction_result = self._execute_pipeline(Path(file_input), task)

            if task and task.is_cancelled():
                self.repository.update(analysis_id, {"status": "CANCELLED"})
                raise NetDetectError("Analysis was cancelled.")

            if task:
                task.update_progress(0.85, "Synthesizing evidence-based threat explanations...")

            # 3. Generate explainability & threat report
            flow_df = meta.get("flow_df", pd.DataFrame())
            explanations = explain_prediction(raw_df, prediction_result, flow_df)

            elapsed = round(time.time() - start_time, 2)
            report = generate_threat_report(
                analysis_id=analysis_id,
                filename=safe_filename,
                file_size_bytes=file_size,
                duration_seconds=elapsed,
                raw_df=raw_df,
                flow_df=flow_df,
                prediction_result=prediction_result,
                explanations=explanations,
                total_packets=meta.get("total_packets", 0),
            )

            # 4. Update persistent record in database
            self.repository.update(analysis_id, {
                "status": "COMPLETED",
                "completed_at": report.analyzed_at,
                "duration_seconds": elapsed,
                "total_packets": report.total_packets,
                "total_flows": report.total_flows,
                "attack_flows": report.attack_flows,
                "verdict": report.verdict,
                "risk_level": report.risk_level,
                "threat_intensity": report.threat_intensity_pct,
                "confidence": report.confidence_pct,
                "peak_flow_index": report.peak_flow_index,
                "analyst_note": report.analyst_note,
                "summary_json": report.to_dict().get("summary_json") or str({
                    "protocols": report.protocol_distribution,
                    "services": report.service_distribution,
                }).replace("'", '"')
            })

            if task:
                task.result = report
                task.raw_df = raw_df
                task.prediction_result = prediction_result
                task.status = "COMPLETED"
                task.update_progress(1.0, f"Analysis complete in {elapsed}s.")

            logger.info(f"Analysis {analysis_id} for '{safe_filename}' completed with verdict: {report.verdict} ({elapsed}s)")
            return report, raw_df, prediction_result

        except Exception as e:
            elapsed = round(time.time() - start_time, 2)
            error_msg = str(e)
            logger.error(f"Analysis {analysis_id} failed: {error_msg}", exc_info=True)
            self.repository.update(analysis_id, {
                "status": "FAILED",
                "duration_seconds": elapsed,
                "error_message": error_msg,
            })
            if task:
                task.status = "FAILED"
                task.error = error_msg
                task.update_progress(1.0, f"Analysis failed: {error_msg}")
            raise

    def _execute_pipeline(self, pcap_path: Path, task: AnalysisTask = None) -> Tuple[pd.DataFrame, dict, dict]:
        """Internal helper running feature extraction and protected ML inference."""
        if task:
            task.update_progress(0.20, "Executing single-pass flow extraction...")

        raw_df, meta = extract_all_features_optimized(pcap_path)
        if raw_df is None or raw_df.empty:
            raise PacketExtractionError("No valid IP flows could be constructed from capture.")

        if task:
            task.update_progress(0.60, "Running protected ML model ensemble & Isolation Forest...")

        artifacts = self.get_artifacts()
        prediction_result = run_prediction(raw_df, artifacts)
        return raw_df, meta, prediction_result

    # Friendly method aliases
    run_analysis_sync = analyze_pcap_sync
    start_async_analysis = analyze_pcap_async
