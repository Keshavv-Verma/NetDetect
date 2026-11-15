"""PCAP and PCAPNG Validation Engine Tests for NetDetect."""

import os
import struct
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from backend.config.settings import SAMPLE_PCAPS_DIR, MAX_UPLOAD_SIZE_BYTES
from backend.security.file_validation import PcapValidator
from backend.utils.exceptions import (
    PcapEmptyError,
    OversizedFileError,
    UnsupportedFormatError,
    PcapCorruptError,
    FileValidationError,
)


class TestPcapValidator(unittest.TestCase):
    """Test suite for pre-ingestion file validation and security checks."""

    def setUp(self):
        self.sample_pcap = str(SAMPLE_PCAPS_DIR / "sample_traffic.pcap")

    def test_valid_sample_pcap_file(self):
        """Verify standard sample PCAP validates as 'pcap'."""
        fmt, size = PcapValidator.validate_file(self.sample_pcap)
        self.assertEqual(fmt, "pcap")
        self.assertGreater(size, 0)

    def test_valid_pcap_from_bytes(self):
        """Verify validating raw in-memory bytes."""
        with open(self.sample_pcap, "rb") as f:
            content = f.read()
        fmt, size = PcapValidator.validate_file(content, filename="traffic.pcap")
        self.assertEqual(fmt, "pcap")
        self.assertEqual(size, len(content))

    def test_valid_synthetic_pcapng(self):
        """Construct and validate a minimal valid PCAPNG Section Header Block."""
        # PCAPNG magic 0x0A0D0D0A, block total len 28, BOM 0x1A2B3C4D, major 1, minor 0, section_len -1, block total len 28
        magic = b"\x0a\x0d\x0d\x0a"
        block_len = struct.pack("<I", 28)
        bom = b"\x1a\x2b\x3c\x4d"
        maj_min = struct.pack("<HH", 1, 0)
        sec_len = struct.pack("<q", -1)
        pcapng_bytes = magic + block_len + bom + maj_min + sec_len + block_len

        fmt, size = PcapValidator.validate_file(pcapng_bytes, filename="capture.pcapng")
        self.assertEqual(fmt, "pcapng")
        self.assertEqual(size, len(pcapng_bytes))

    def test_empty_file_rejected(self):
        """Empty byte payload or file raises PcapEmptyError."""
        with self.assertRaises(PcapEmptyError):
            PcapValidator.validate_file(b"", filename="empty.pcap")

    def test_oversized_file_rejected(self):
        """Files exceeding MAX_UPLOAD_SIZE_BYTES raise OversizedFileError."""
        oversized = b"\xd4\xc3\xb2\xa1" + b"\x00" * 30
        fake_size = MAX_UPLOAD_SIZE_BYTES + 1024
        # Test using mock or temp file
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name
            f.write(oversized)
        try:
            # Validate with small upload size override
            with self.assertRaises(OversizedFileError):
                with mock.patch("backend.security.file_validation.MAX_UPLOAD_SIZE_BYTES", 10):
                    PcapValidator.validate_file(temp_path)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_unsupported_extension_rejected(self):
        """Disallowed extensions raise UnsupportedFormatError."""
        with self.assertRaises(UnsupportedFormatError):
            PcapValidator.validate_file(b"\xd4\xc3\xb2\xa1" * 10, filename="malicious.exe")

    def test_invalid_magic_number_rejected(self):
        """Non-PCAP magic bytes raise UnsupportedFormatError."""
        garbage = b"NOT_A_PCAP_MAGIC_DATA_STREAM"
        with self.assertRaises(UnsupportedFormatError):
            PcapValidator.validate_file(garbage, filename="invalid.pcap")

    def test_truncated_pcap_header_rejected(self):
        """PCAP files shorter than 24 bytes raise PcapCorruptError."""
        truncated_magic = b"\xd4\xc3\xb2\xa1\x00\x02\x00\x04"  # Only 8 bytes
        with self.assertRaises(PcapCorruptError):
            PcapValidator.validate_file(truncated_magic, filename="short.pcap")

    def test_truncated_pcapng_header_rejected(self):
        """PCAPNG files shorter than 28 bytes raise PcapCorruptError."""
        truncated_pcapng = b"\x0a\x0d\x0d\x0a" + b"\x00" * 10  # Only 14 bytes
        with self.assertRaises(PcapCorruptError):
            PcapValidator.validate_file(truncated_pcapng, filename="short.pcapng")

    def test_nonexistent_file_raises_validation_error(self):
        """Missing file path raises FileValidationError."""
        with self.assertRaises(FileValidationError):
            PcapValidator.validate_file("nonexistent_path_to_capture.pcap")


if __name__ == "__main__":
    unittest.main()
