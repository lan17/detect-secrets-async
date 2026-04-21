"""Async runtime for detect-secrets subprocess workers."""

from importlib.metadata import PackageNotFoundError, version

from ._config import RuntimeConfig
from ._errors import (
    DetectSecretsAsyncError,
    RuntimeConfigConflictError,
    RuntimeScanError,
    ScanFailureCode,
)
from ._models import RuntimeInfo, ScanConfig, ScanFinding, ScanRequest, ScanResult
from ._runtime import (
    DetectSecretsRuntime,
    configure_runtime,
    get_runtime,
    get_runtime_info,
    init_runtime,
    reset_runtime_for_tests,
    shutdown_runtime,
)

try:
    __version__ = version("detect-secrets-async")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = [
    "DetectSecretsAsyncError",
    "DetectSecretsRuntime",
    "RuntimeConfig",
    "RuntimeConfigConflictError",
    "RuntimeInfo",
    "RuntimeScanError",
    "ScanConfig",
    "ScanFailureCode",
    "ScanFinding",
    "ScanRequest",
    "ScanResult",
    "__version__",
    "configure_runtime",
    "get_runtime",
    "get_runtime_info",
    "init_runtime",
    "reset_runtime_for_tests",
    "shutdown_runtime",
]
