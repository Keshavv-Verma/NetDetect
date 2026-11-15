"""Security, File Utilities, and Input Sanitization Tests for NetDetect."""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from backend.utils.file_utils import (
    sanitize_filename,
    compute_sha256,
    human_readable_bytes,
    SafeTempFile,
)
from backend.utils.exceptions import SecurityValidationError


class TestSecurityAndSanitization(unittest.TestCase):
    """Test suite ensuring defensive sanitization and safe temporary staging."""

    def test_sanitize_filename_traversal_stripping(self):
        """Verify directory traversal indicators and illegal path characters are removed."""
        dirty_inputs = [
            ("../../../etc/shadow.pcap", "shadow.pcap"),
            ("..\\..\\windows\\system32\\cmd.pcap", "cmd.pcap"),
            ("capture file name with spaces.pcap", "capture file name with spaces.pcap"),
            ("foo/bar/baz.pcapng", "baz.pcapng"),
            ("suspicious\x00file.pcap", "suspiciousfile.pcap"),
            ("../../bad$!@#name.pcap", "bad$!@#name.pcap"),
            ("../../invalid:name*file?.pcap", "invalid_name_file_.pcap"),
        ]
        for raw, expected in dirty_inputs:
            cleaned = sanitize_filename(raw)
            self.assertEqual(cleaned, expected, f"Failed sanitizing '{raw}'")

    def test_safe_temp_file_automatic_cleanup(self):
        """Verify SafeTempFile automatically removes staged file on exit."""
        data = b"TEMPORARY_TEST_PACKET_DATA"
        temp_path = None
        with SafeTempFile(content=data, suffix=".pcap") as path:
            temp_path = path
            self.assertTrue(path.exists())
            self.assertEqual(path.read_bytes(), data)

        # After exiting the block, file must be deleted
        self.assertFalse(temp_path.exists())

    def test_safe_temp_file_cleanup_on_exception(self):
        """Verify SafeTempFile removes staged file even if an exception occurs."""
        temp_path = None
        try:
            with SafeTempFile(content=b"DATA", suffix=".pcap") as path:
                temp_path = path
                self.assertTrue(path.exists())
                raise RuntimeError("Simulated processing failure")
        except RuntimeError:
            pass

        self.assertFalse(temp_path.exists())

    def test_compute_sha256_bytes_and_file(self):
        """Verify compute_sha256 produces identical hash for bytes and file on disk."""
        data = b"NETDETECT_PCAP_CRYPTOGRAPHIC_INTEGRITY_CHECK"
        expected_hash = hashlib.sha256(data).hexdigest()

        # From bytes
        self.assertEqual(compute_sha256(data), expected_hash)

        # From file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            temp_name = f.name
        try:
            self.assertEqual(compute_sha256(temp_name), expected_hash)
        finally:
            if os.path.exists(temp_name):
                os.remove(temp_name)

    def test_human_readable_bytes_formatting(self):
        """Verify byte formatting outputs standard human readable strings."""
        self.assertEqual(human_readable_bytes(500), "500.00 B")
        self.assertEqual(human_readable_bytes(1024), "1.00 KB")
        self.assertEqual(human_readable_bytes(1024 * 1024 * 5), "5.00 MB")
        self.assertEqual(human_readable_bytes(1024 * 1024 * 1024 * 2), "2.00 GB")


if __name__ == "__main__":
    unittest.main()
