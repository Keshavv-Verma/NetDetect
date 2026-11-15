"""
NetDetect Ingestion & Upload Service.
Validates file security, hashes contents, and safely stages capture files.
"""
from pathlib import Path
from typing import Union, Tuple

from backend.utils.file_utils import compute_sha256, sanitize_filename
from backend.security.security_checks import validate_upload_security
from backend.utils.logger import get_logger

logger = get_logger("upload_service")


class UploadService:
    """Service handling PCAP file ingestion and security validation."""

    @classmethod
    def process_and_validate(cls, file_data: Union[str, Path, bytes], raw_filename: str) -> Tuple[str, str, int, str]:
        """
        Validates the uploaded capture.
        Returns: (safe_filename, file_hash, byte_size, format_type)
        """
        safe_filename = validate_upload_security(file_data, raw_filename)
        file_hash = compute_sha256(file_data)
        
        if isinstance(file_data, (str, Path)):
            byte_size = Path(file_data).stat().st_size
        else:
            byte_size = len(file_data)

        format_type = "pcapng" if safe_filename.endswith(".pcapng") else "pcap"
        logger.info(f"Processed valid upload '{safe_filename}' (SHA256: {file_hash[:12]}..., Size: {byte_size} bytes)")
        return safe_filename, file_hash, byte_size, format_type
