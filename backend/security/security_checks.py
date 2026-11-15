"""
NetDetect Cybersecurity Defensive Checks.
Protects against path traversal, zip bombs, and payload spoofing.
"""
from pathlib import Path
from typing import Union

from backend.utils.exceptions import FileValidationError
from backend.utils.file_utils import sanitize_filename
from backend.security.file_validation import PcapValidator
from backend.utils.logger import get_logger

logger = get_logger("security_checks")


def validate_upload_security(file_path_or_bytes: Union[str, Path, bytes], raw_filename: str) -> str:
    """
    Run comprehensive cybersecurity validation on uploaded file:
    1. Sanitize filename and prevent directory traversal.
    2. Enforce binary structure and format validity via PcapValidator.
    Returns the sanitized safe filename.
    """
    safe_filename = sanitize_filename(raw_filename)
    if ".." in raw_filename or "/" in raw_filename or "\\" in raw_filename:
        logger.warning(f"Path traversal attempt detected in upload: {raw_filename!r}")

    # Validate file binary integrity and format
    PcapValidator.validate_file(file_path_or_bytes, filename=safe_filename)

    return safe_filename
