from __future__ import annotations

from typing import Annotated, Literal, TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PositiveInt,
    TypeAdapter,
    field_validator,
)

from ._config import RuntimeConfig
from ._errors import ScanFailureCode

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 16 * 1024 * 1024


class ScanConfig(BaseModel):
    """Per-request detect-secrets configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled_plugins: tuple[str, ...] | None = None

    @field_validator("enabled_plugins")
    @classmethod
    def validate_enabled_plugins(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if value is None:
            return None

        normalized = tuple(plugin_name.strip() for plugin_name in value)
        if any(not plugin_name for plugin_name in normalized):
            raise ValueError("plugin names must be non-empty")

        return normalized


class ScanRequest(BaseModel):
    """A text scan request for the shared runtime."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str
    timeout_ms: PositiveInt
    config: ScanConfig = Field(default_factory=ScanConfig)


class ScanFinding(BaseModel):
    """A safe, content-local finding emitted by detect-secrets."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: str
    line_number: PositiveInt | None = None


class ScanResult(BaseModel):
    """A successful scan result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    findings: tuple[ScanFinding, ...] = ()
    detect_secrets_version: str

    @property
    def findings_count(self) -> int:
        return len(self.findings)


class RuntimeInfo(BaseModel):
    """Static runtime/package facts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    package_version: str
    detect_secrets_version: str
    available_plugin_names: tuple[str, ...]
    default_plugin_names: tuple[str, ...]
    configured_runtime: RuntimeConfig | None = None


class WorkerError(BaseModel):
    """A safe worker error payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ScanFailureCode
    message: str


class WorkerHelloFrame(BaseModel):
    """Worker startup handshake."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    frame_type: Literal["hello"] = "hello"
    protocol_version: Literal[1] = 1
    detect_secrets_version: str
    available_plugin_names: tuple[str, ...]
    default_plugin_names: tuple[str, ...]


class WorkerScanRequestFrame(BaseModel):
    """Parent-to-worker scan request frame."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    frame_type: Literal["scan_request"] = "scan_request"
    request: ScanRequest


class WorkerScanResultFrame(BaseModel):
    """Worker-to-parent success frame."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    frame_type: Literal["scan_result"] = "scan_result"
    result: ScanResult


class WorkerScanErrorFrame(BaseModel):
    """Worker-to-parent error frame."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    frame_type: Literal["scan_error"] = "scan_error"
    error: WorkerError


WorkerResponseFrame: TypeAlias = Annotated[
    WorkerScanResultFrame | WorkerScanErrorFrame,
    Field(discriminator="frame_type"),
]

WorkerFrame: TypeAlias = Annotated[
    WorkerHelloFrame | WorkerScanRequestFrame | WorkerScanResultFrame | WorkerScanErrorFrame,
    Field(discriminator="frame_type"),
]

WORKER_RESPONSE_ADAPTER: TypeAdapter[WorkerResponseFrame] = TypeAdapter(WorkerResponseFrame)
WORKER_HELLO_ADAPTER: TypeAdapter[WorkerHelloFrame] = TypeAdapter(WorkerHelloFrame)
WORKER_REQUEST_ADAPTER: TypeAdapter[WorkerScanRequestFrame] = TypeAdapter(WorkerScanRequestFrame)
WORKER_FRAME_ADAPTER: TypeAdapter[WorkerFrame] = TypeAdapter(WorkerFrame)
