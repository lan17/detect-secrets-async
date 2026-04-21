from __future__ import annotations

import io
import sys

import pytest

import detect_secrets_async._worker as worker_module
from detect_secrets_async import ScanConfig, ScanFailureCode, ScanFinding, ScanRequest
from detect_secrets_async._errors import DEFAULT_ERROR_MESSAGES, RuntimeScanError
from detect_secrets_async._models import (
    WORKER_FRAME_ADAPTER,
    WorkerHelloFrame,
    WorkerScanErrorFrame,
    WorkerScanRequestFrame,
    WorkerScanResultFrame,
)


class _BufferedStream:
    def __init__(self, buffer: io.BytesIO) -> None:
        self.buffer = buffer


def _request_frame_bytes(content: str = "github_token = 'ghp_example'") -> bytes:
    return (
        WorkerScanRequestFrame(
            request=ScanRequest(
                content=content,
                timeout_ms=1_000,
                config=ScanConfig(),
            )
        )
        .model_dump_json(exclude_none=True)
        .encode("utf-8")
        + b"\n"
    )


def _parse_output_frames(
    buffer: io.BytesIO,
) -> list[WorkerHelloFrame | WorkerScanErrorFrame | WorkerScanResultFrame]:
    frames: list[WorkerHelloFrame | WorkerScanErrorFrame | WorkerScanResultFrame] = []
    for raw_frame in buffer.getvalue().splitlines():
        frame = WORKER_FRAME_ADAPTER.validate_json(raw_frame)
        if isinstance(frame, WorkerScanRequestFrame):
            raise AssertionError("worker output unexpectedly contained a request frame")
        frames.append(frame)
    return frames


def _patch_worker_stdio(
    monkeypatch: pytest.MonkeyPatch,
    raw_input: bytes,
) -> io.BytesIO:
    output_buffer = io.BytesIO()
    monkeypatch.setattr(sys, "stdin", _BufferedStream(io.BytesIO(raw_input)))
    monkeypatch.setattr(sys, "stdout", _BufferedStream(output_buffer))
    return output_buffer


def _patch_worker_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_module, "get_detect_secrets_version", lambda: "detect-secrets-1.0.0")
    monkeypatch.setattr(worker_module, "get_available_plugin_names", lambda: ("FakeDetector",))
    monkeypatch.setattr(worker_module, "get_default_plugin_names", lambda: ("FakeDetector",))


def test_encode_frame_rejects_payloads_that_exceed_protocol_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(worker_module, "MAX_FRAME_BYTES", 8)

    with pytest.raises(RuntimeError, match="worker frame exceeds protocol size limit"):
        worker_module._encode_frame(
            WorkerHelloFrame(
                detect_secrets_version="detect-secrets-1.0.0",
                available_plugin_names=("FakeDetector",),
                default_plugin_names=("FakeDetector",),
            )
        )


def test_read_frame_handles_eof_and_protocol_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert worker_module._read_frame(io.BytesIO(b"")) is None

    with pytest.raises(RuntimeScanError) as missing_newline_error:
        worker_module._read_frame(io.BytesIO(b'{"frame_type":"scan_request"}'))

    assert missing_newline_error.value.code == ScanFailureCode.WORKER_PROTOCOL_ERROR

    monkeypatch.setattr(worker_module, "MAX_FRAME_BYTES", 4)
    with pytest.raises(RuntimeScanError) as oversized_error:
        worker_module._read_frame(io.BytesIO(b"12345\n"))

    assert oversized_error.value.code == ScanFailureCode.WORKER_PROTOCOL_ERROR


def test_main_writes_hello_and_scan_result_frames(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_buffer = _patch_worker_stdio(monkeypatch, _request_frame_bytes("scan me"))
    _patch_worker_metadata(monkeypatch)

    def fake_scan_content(content: str, config: ScanConfig) -> tuple[ScanFinding, ...]:
        assert content == "scan me"
        assert config == ScanConfig()
        return (ScanFinding(type="FakeDetector", line_number=1),)

    monkeypatch.setattr(worker_module, "scan_content", fake_scan_content)

    assert worker_module.main() == 0

    frames = _parse_output_frames(output_buffer)
    assert len(frames) == 2
    assert isinstance(frames[0], WorkerHelloFrame)
    assert isinstance(frames[1], WorkerScanResultFrame)
    assert frames[1].result.findings == (ScanFinding(type="FakeDetector", line_number=1),)
    assert frames[1].result.detect_secrets_version == "detect-secrets-1.0.0"


def test_main_returns_protocol_error_for_invalid_request_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_buffer = _patch_worker_stdio(monkeypatch, b'{"frame_type":"scan_request"}\n')
    _patch_worker_metadata(monkeypatch)

    assert worker_module.main() == 2

    frames = _parse_output_frames(output_buffer)
    assert len(frames) == 2
    assert isinstance(frames[0], WorkerHelloFrame)
    assert isinstance(frames[1], WorkerScanErrorFrame)
    assert frames[1].error.code == ScanFailureCode.WORKER_PROTOCOL_ERROR
    assert frames[1].error.message == DEFAULT_ERROR_MESSAGES[ScanFailureCode.WORKER_PROTOCOL_ERROR]


def test_main_serializes_runtime_scan_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_buffer = _patch_worker_stdio(monkeypatch, _request_frame_bytes())
    _patch_worker_metadata(monkeypatch)

    def fake_scan_content(_: str, __: ScanConfig) -> tuple[ScanFinding, ...]:
        raise RuntimeScanError(ScanFailureCode.INVALID_CONFIG, "bad plugin configuration")

    monkeypatch.setattr(worker_module, "scan_content", fake_scan_content)

    assert worker_module.main() == 0

    frames = _parse_output_frames(output_buffer)
    assert len(frames) == 2
    assert isinstance(frames[1], WorkerScanErrorFrame)
    assert frames[1].error.code == ScanFailureCode.INVALID_CONFIG
    assert frames[1].error.message == "bad plugin configuration"


def test_main_serializes_unexpected_exceptions_as_runtime_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_buffer = _patch_worker_stdio(monkeypatch, _request_frame_bytes())
    _patch_worker_metadata(monkeypatch)

    def fake_scan_content(_: str, __: ScanConfig) -> tuple[ScanFinding, ...]:
        raise RuntimeError("boom")

    monkeypatch.setattr(worker_module, "scan_content", fake_scan_content)

    assert worker_module.main() == 0

    frames = _parse_output_frames(output_buffer)
    assert len(frames) == 2
    assert isinstance(frames[1], WorkerScanErrorFrame)
    assert frames[1].error.code == ScanFailureCode.RUNTIME_ERROR
    assert frames[1].error.message == DEFAULT_ERROR_MESSAGES[ScanFailureCode.RUNTIME_ERROR]
