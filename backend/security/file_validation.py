"""
NetDetect PCAP File Validation Engine.
Validates file extensions, size limits, binary magic numbers, and PCAP frame structure.
"""
import struct
from pathlib import Path
from typing import Union, Tuple

from backend.config.settings import (
    MAX_UPLOAD_SIZE_BYTES,
    ALLOWED_EXTENSIONS,
    PCAP_MAGIC_NUMBERS,
    PCAPNG_MAGIC,
)
from backend.utils.exceptions import (
    PcapEmptyError,
    OversizedFileError,
    UnsupportedFormatError,
    PcapCorruptError,
    FileValidationError,
)
from backend.utils.logger import get_logger

logger = get_logger("file_validation")


class PcapValidator:
    """
    Validates network capture files (PCAP, PCAPNG, CAP) prior to parsing.
    Rejects malformed, truncated, oversized, or malicious files early.
    """

    @classmethod
    def validate_file(cls, file_path_or_bytes: Union[str, Path, bytes], filename: str = None) -> Tuple[str, int]:
        """
        Comprehensive pre-ingestion validation.
        Returns tuple of (format_type, byte_size).
        format_type is either 'pcap' or 'pcapng'.
        """
        # 1. Determine size and buffer
        if isinstance(file_path_or_bytes, (str, Path)):
            path = Path(file_path_or_bytes)
            if not path.exists():
                raise FileValidationError(f"File does not exist: {path}")
            size = path.stat().st_size
            filename = filename or path.name
            with open(path, "rb") as f:
                header_bytes = f.read(64)
        elif isinstance(file_path_or_bytes, (bytes, bytearray)):
            size = len(file_path_or_bytes)
            header_bytes = bytes(file_path_or_bytes[:64])
            filename = filename or "capture.pcap"
        else:
            raise TypeError(f"Invalid input type: {type(file_path_or_bytes)}")

        # 2. Extension validation
        if filename:
            ext = Path(filename).suffix.lower()
            if ext not in ALLOWED_EXTENSIONS:
                raise UnsupportedFormatError(
                    f"Unsupported extension '{ext}'. Allowed extensions are: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
                )

        # 3. File size restrictions
        if size == 0:
            raise PcapEmptyError()

        if size > MAX_UPLOAD_SIZE_BYTES:
            raise OversizedFileError(size, MAX_UPLOAD_SIZE_BYTES)

        # 4. Binary Magic Number Validation
        if len(header_bytes) < 4:
            raise PcapCorruptError("File is too short to contain a valid capture header.")

        magic = header_bytes[:4]
        is_pcapng = (magic == PCAPNG_MAGIC)
        is_pcap = (magic in PCAP_MAGIC_NUMBERS)

        if not is_pcap and not is_pcapng:
            raise UnsupportedFormatError(
                f"File signature (magic bytes: {magic.hex()}) does not match standard PCAP or PCAPNG specifications."
            )

        format_type = "pcapng" if is_pcapng else "pcap"

        # 5. Header Integrity and Truncation Checks
        if is_pcap:
            if size < 24:
                raise PcapCorruptError("Truncated PCAP global header (file is less than 24 bytes).")
            # Parse endianness from magic
            # 0xd4c3b2a1 / 0x4d3cb2a1 on disk is little-endian; 0xa1b2c3d4 / 0xa1b23c4d on disk is big-endian
            is_little_endian = (magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"))
            endian_char = "<" if is_little_endian else ">"
            try:
                major, minor, thiszone, sigfigs, snaplen, linktype = struct.unpack(
                    f"{endian_char}HHIIII", header_bytes[4:24]
                )
                if snaplen == 0 or snaplen > 1_000_000:
                    logger.warning(f"Unusual snaplen ({snaplen}) in PCAP header for {filename}")
            except Exception as e:
                raise PcapCorruptError(f"Malformed PCAP global header: {e}")

            # Verify first packet header if file is large enough
            if size >= 40:
                try:
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                        f"{endian_char}IIII", header_bytes[24:40]
                    )
                    if incl_len > orig_len or incl_len > 65535:
                        logger.warning(f"Abnormal frame capture length ({incl_len} > {orig_len}) in first packet.")
                except Exception as e:
                    raise PcapCorruptError(f"Malformed packet record header: {e}")

        elif is_pcapng:
            if size < 28:
                raise PcapCorruptError("Truncated PCAPNG header (file is less than 28 bytes).")
            # PCAPNG Section Header Block: magic (4), block_len (4), byte_order_magic (4)
            # Byte order magic is 0x1A2B3C4D
            try:
                bom = header_bytes[8:12]
                if bom not in (b"\x1a\x2b\x3c\x4d", b"\x4d\x3c\x2b\x1a"):
                    raise PcapCorruptError("Invalid PCAPNG Byte Order Magic.")
            except Exception as e:
                raise PcapCorruptError(f"Malformed PCAPNG Section Header Block: {e}")

        logger.info(f"Validated {format_type.upper()} capture '{filename}' ({size} bytes).")
        return format_type, size
