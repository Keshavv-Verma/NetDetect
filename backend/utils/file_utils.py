"""
NetDetect File Utilities.
Safe temporary file lifecycles, cryptographic hashing, and path sanitization.
"""
import os
import re
import hashlib
import tempfile
from pathlib import Path
from typing import Union, Generator
from contextlib import contextmanager

from backend.utils.logger import get_logger

logger = get_logger("file_utils")


def compute_sha256(target: Union[str, Path, bytes]) -> str:
    """Compute the SHA-256 hexadecimal digest of a file path or raw bytes."""
    h = hashlib.sha256()
    if isinstance(target, (str, Path)):
        with open(target, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    elif isinstance(target, (bytes, bytearray)):
        h.update(target)
    else:
        raise TypeError(f"Unsupported target type for hashing: {type(target)}")
    return h.hexdigest()


def human_readable_bytes(size: Union[int, float]) -> str:
    """Convert raw byte count into human-readable string (KB, MB, GB)."""
    try:
        n = float(size)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if n < 1024.0:
                return f"{n:.2f} {unit}"
            n /= 1024.0
        return f"{n:.2f} PB"
    except Exception:
        return "0 B"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize an uploaded filename to prevent directory traversal and injection.
    Strips relative path traversal sequences, null bytes, and non-printable characters.
    """
    if not filename:
        return "unnamed_capture.pcap"

    # Extract bare filename (removing directory parts)
    filename = os.path.basename(filename)
    filename = filename.replace("\\", "/").split("/")[-1]

    # Strip null bytes and non-printable chars
    filename = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", filename)

    # Replace forbidden path characters
    filename = re.sub(r'[<>:"/\\|?*]', "_", filename)

    # Restrict continuous dots and leading dots
    filename = re.sub(r"\.{2,}", ".", filename).lstrip(".")

    # Ensure max filename length
    if len(filename) > 200:
        base, ext = os.path.splitext(filename)
        filename = base[:190] + ext

    return filename or "capture.pcap"


@contextmanager
def SafeTempFile(content: bytes = None, suffix: str = ".pcap", prefix: str = "netdetect_") -> Generator[Path, None, None]:
    """
    Context manager that safely allocates and cleans up a temporary file.
    Guarantees deletion upon exit even if exceptions are raised.
    """
    temp_file = None
    try:
        fd, path_str = tempfile.mkstemp(suffix=suffix, prefix=prefix)
        temp_file = Path(path_str)
        if content:
            with os.fdopen(fd, "wb") as f:
                f.write(content)
        else:
            os.close(fd)
        yield temp_file
    finally:
        if temp_file and temp_file.exists():
            try:
                temp_file.unlink()
            except Exception as e:
                logger.warning(f"Failed to delete temp file {temp_file}: {e}")
