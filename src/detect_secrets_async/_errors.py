from __future__ import annotations

from enum import Enum


class ScanFailureCode(str, Enum):
    """Safe runtime failure codes."""

    INVALID_CONFIG = "invalid_config"
    QUEUE_FULL = "queue_full"
    QUEUE_TIMEOUT = "queue_timeout"
    WORKER_STARTUP_ERROR = "worker_startup_error"
    WORKER_TIMEOUT = "worker_timeout"
    WORKER_CRASH = "worker_crash"
    WORKER_PROTOCOL_ERROR = "worker_protocol_error"
    RUNTIME_ERROR = "runtime_error"


DEFAULT_ERROR_MESSAGES: dict[ScanFailureCode, str] = {
    ScanFailureCode.INVALID_CONFIG: "scan config is invalid",
    ScanFailureCode.QUEUE_FULL: "runtime queue is full",
    ScanFailureCode.QUEUE_TIMEOUT: "scan request timed out while waiting for a worker",
    ScanFailureCode.WORKER_STARTUP_ERROR: "worker failed to start",
    ScanFailureCode.WORKER_TIMEOUT: "scan request timed out",
    ScanFailureCode.WORKER_CRASH: "worker exited unexpectedly",
    ScanFailureCode.WORKER_PROTOCOL_ERROR: "worker protocol error",
    ScanFailureCode.RUNTIME_ERROR: "runtime error",
}


class DetectSecretsAsyncError(Exception):
    """Base package exception."""


class RuntimeConfigConflictError(DetectSecretsAsyncError):
    """Raised when the shared runtime is re-initialized with conflicting settings."""


class RuntimeScanError(DetectSecretsAsyncError):
    """Raised when a scan request cannot be completed safely."""

    def __init__(self, code: ScanFailureCode, message: str | None = None) -> None:
        self.code = code
        self.message = message or DEFAULT_ERROR_MESSAGES[code]
        super().__init__(self.message)
