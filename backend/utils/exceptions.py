"""
NetDetect Exception Hierarchy.
Strongly typed exceptions for granular error handling and safe user messaging.
"""

class NetDetectError(Exception):
    """Base exception for all NetDetect backend errors."""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR", user_message: str = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.user_message = user_message or message


class FileValidationError(NetDetectError):
    """Raised when an uploaded file fails validation checks."""
    def __init__(self, message: str, code: str = "FILE_VALIDATION_ERROR", user_message: str = None):
        super().__init__(message, code=code, user_message=user_message)


class SecurityValidationError(FileValidationError):
    """Raised when a security policy or path traversal attempt is detected."""
    def __init__(self, message: str, code: str = "SECURITY_VIOLATION", user_message: str = None):
        super().__init__(message, code=code, user_message=user_message or "Security check failed.")


class PcapEmptyError(FileValidationError):
    """Raised when the PCAP file has 0 bytes or 0 packets."""
    def __init__(self, message: str = "The capture file is empty."):
        super().__init__(message, code="EMPTY_FILE", user_message="The provided file contains 0 bytes.")


class OversizedFileError(FileValidationError):
    """Raised when file exceeds allowed size threshold."""
    def __init__(self, size_bytes: int, max_bytes: int):
        super().__init__(
            f"File size ({size_bytes} bytes) exceeds maximum limit ({max_bytes} bytes).",
            code="FILE_TOO_LARGE",
            user_message=f"File exceeds maximum allowed upload size ({max_bytes // (1024*1024)} MB)."
        )


class UnsupportedFormatError(FileValidationError):
    """Raised when file format/magic number is not supported."""
    def __init__(self, message: str = "Unsupported capture format."):
        super().__init__(
            message,
            code="UNSUPPORTED_FORMAT",
            user_message="Invalid file format. Only valid PCAP or PCAPNG packet captures are accepted."
        )


class PcapCorruptError(FileValidationError):
    """Raised when PCAP headers or packet frames are corrupted."""
    def __init__(self, message: str = "Corrupted packet capture file."):
        super().__init__(
            message,
            code="CORRUPTED_PCAP",
            user_message="Capture file header or frame structure is corrupted and cannot be parsed."
        )


class PacketExtractionError(NetDetectError):
    """Raised when bidirectional flow feature extraction fails."""
    def __init__(self, message: str, user_message: str = None):
        super().__init__(
            message,
            code="EXTRACTION_ERROR",
            user_message=user_message or "Failed to extract IP network flows from capture."
        )


class InferenceError(NetDetectError):
    """Raised when ML model inference fails."""
    def __init__(self, message: str, user_message: str = None):
        super().__init__(
            message,
            code="INFERENCE_ERROR",
            user_message=user_message or "Machine learning inference pipeline encountered an error."
        )


class DatabaseError(NetDetectError):
    """Raised when SQLite database operations fail."""
    def __init__(self, message: str, user_message: str = None):
        super().__init__(
            message,
            code="DATABASE_ERROR",
            user_message=user_message or "Database persistence error."
        )
