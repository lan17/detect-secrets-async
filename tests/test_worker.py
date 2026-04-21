from __future__ import annotations

import io
import json

import pytest

from detect_secrets_async import RuntimeScanError, ScanFailureCode, ScanRequest
from detect_secrets_async._models import ScanResult, WorkerScanRequestFrame, WorkerScanResultFrame
from detect_secrets_async._worker import _encode_frame, _read_frame, main


class _BinaryStreamWrapper:
    def __init__(self, buffer: io.BytesIO) -> None:
        self.buffer = buffer


def test_encode_frame_rejects_payloads_that_exceed_the_protocol_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: a worker result frame larger than the configured protocol limit
    monkeypatch.setattr("detect_secrets_async._worker.MAX_FRAME_BYTES", 64)
    oversized_frame = WorkerScanResultFrame(
        result=ScanResult(findings=(), detect_secrets_version="x" * 128)
    )

    # When: the worker encodes the frame
    # Then: it rejects the payload before writing it
    with pytest.raises(RuntimeError, match="protocol size limit"):
        _encode_frame(oversized_frame)


def test_read_frame_rejects_an_oversized_input_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: an input line larger than the configured protocol limit
    monkeypatch.setattr("detect_secrets_async._worker.MAX_FRAME_BYTES", 32)
    oversized_stream = io.BytesIO((b"x" * 40) + b"\n")

    # When: the worker reads the frame from stdin
    # Then: it reports a protocol error
    with pytest.raises(RuntimeScanError) as exc_info:
        _read_frame(oversized_stream)

    assert exc_info.value.code == ScanFailureCode.WORKER_PROTOCOL_ERROR


def test_main_returns_a_runtime_error_frame_for_unexpected_scan_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: a valid request and an unexpected exception from scan_content
    stdin_buffer = io.BytesIO(
        WorkerScanRequestFrame(request=ScanRequest(content="secret", timeout_ms=1_000))
        .model_dump_json()
        .encode("utf-8")
        + b"\n"
    )
    stdout_buffer = io.BytesIO()

    def raise_unexpected_error(*_args: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr("detect_secrets_async._worker.scan_content", raise_unexpected_error)
    monkeypatch.setattr(
        "detect_secrets_async._worker.get_detect_secrets_version",
        lambda: "test-version",
    )
    monkeypatch.setattr(
        "detect_secrets_async._worker.get_available_plugin_names",
        lambda: ("FakeDetector",),
    )
    monkeypatch.setattr(
        "detect_secrets_async._worker.get_default_plugin_names",
        lambda: ("FakeDetector",),
    )
    monkeypatch.setattr("sys.stdin", _BinaryStreamWrapper(stdin_buffer))
    monkeypatch.setattr("sys.stdout", _BinaryStreamWrapper(stdout_buffer))

    # When: the worker main loop handles the request
    exit_code = main()

    # Then: it emits a safe runtime error frame and exits cleanly after EOF
    frames = [json.loads(line) for line in stdout_buffer.getvalue().splitlines()]
    assert exit_code == 0
    assert frames[0]["frame_type"] == "hello"
    assert frames[1] == {
        "frame_type": "scan_error",
        "error": {
            "code": ScanFailureCode.RUNTIME_ERROR.value,
            "message": "runtime error",
        },
    }


def test_main_returns_a_protocol_error_frame_for_invalid_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: an invalid scan request frame on stdin
    stdin_buffer = io.BytesIO(b'{"frame_type":"scan_request"}\n')
    stdout_buffer = io.BytesIO()

    monkeypatch.setattr(
        "detect_secrets_async._worker.get_detect_secrets_version",
        lambda: "test-version",
    )
    monkeypatch.setattr(
        "detect_secrets_async._worker.get_available_plugin_names",
        lambda: ("FakeDetector",),
    )
    monkeypatch.setattr(
        "detect_secrets_async._worker.get_default_plugin_names",
        lambda: ("FakeDetector",),
    )
    monkeypatch.setattr("sys.stdin", _BinaryStreamWrapper(stdin_buffer))
    monkeypatch.setattr("sys.stdout", _BinaryStreamWrapper(stdout_buffer))

    # When: the worker main loop validates the request
    exit_code = main()

    # Then: it emits a safe protocol error frame and exits non-zero
    frames = [json.loads(line) for line in stdout_buffer.getvalue().splitlines()]
    assert exit_code == 2
    assert frames[0]["frame_type"] == "hello"
    assert frames[1] == {
        "frame_type": "scan_error",
        "error": {
            "code": ScanFailureCode.WORKER_PROTOCOL_ERROR.value,
            "message": "worker protocol error",
        },
    }
