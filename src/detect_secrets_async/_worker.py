from __future__ import annotations

import sys
from typing import BinaryIO

from pydantic import ValidationError

from ._detect_secrets import (
    get_available_plugin_names,
    get_default_plugin_names,
    get_detect_secrets_version,
    scan_content,
)
from ._errors import DEFAULT_ERROR_MESSAGES, RuntimeScanError, ScanFailureCode
from ._models import (
    MAX_FRAME_BYTES,
    WORKER_REQUEST_ADAPTER,
    ScanResult,
    WorkerError,
    WorkerHelloFrame,
    WorkerScanErrorFrame,
    WorkerScanResultFrame,
)


def _encode_frame(
    payload: WorkerHelloFrame | WorkerScanErrorFrame | WorkerScanResultFrame,
) -> bytes:
    encoded = payload.model_dump_json(exclude_none=True).encode("utf-8") + b"\n"
    if len(encoded) > MAX_FRAME_BYTES:
        raise RuntimeError("worker frame exceeds protocol size limit")
    return encoded


def _write_frame(
    stream: BinaryIO,
    payload: WorkerHelloFrame | WorkerScanErrorFrame | WorkerScanResultFrame,
) -> None:
    stream.write(_encode_frame(payload))
    stream.flush()


def _read_frame(stream: BinaryIO) -> bytes | None:
    frame = stream.readline(MAX_FRAME_BYTES + 2)
    if frame == b"":
        return None
    if not frame.endswith(b"\n"):
        raise RuntimeScanError(ScanFailureCode.WORKER_PROTOCOL_ERROR)
    if len(frame) > MAX_FRAME_BYTES:
        raise RuntimeScanError(ScanFailureCode.WORKER_PROTOCOL_ERROR)
    return frame[:-1]


def _protocol_error_frame() -> WorkerScanErrorFrame:
    return WorkerScanErrorFrame(
        error=WorkerError(
            code=ScanFailureCode.WORKER_PROTOCOL_ERROR,
            message=DEFAULT_ERROR_MESSAGES[ScanFailureCode.WORKER_PROTOCOL_ERROR],
        )
    )


def main() -> int:
    _write_frame(
        sys.stdout.buffer,
        WorkerHelloFrame(
            detect_secrets_version=get_detect_secrets_version(),
            available_plugin_names=get_available_plugin_names(),
            default_plugin_names=get_default_plugin_names(),
        ),
    )

    while True:
        try:
            raw_frame = _read_frame(sys.stdin.buffer)
            if raw_frame is None:
                return 0

            request_frame = WORKER_REQUEST_ADAPTER.validate_json(raw_frame)
        except (ValidationError, RuntimeScanError):
            _write_frame(sys.stdout.buffer, _protocol_error_frame())
            return 2

        try:
            findings = scan_content(request_frame.request.content, request_frame.request.config)
            _write_frame(
                sys.stdout.buffer,
                WorkerScanResultFrame(
                    result=ScanResult(
                        findings=findings,
                        detect_secrets_version=get_detect_secrets_version(),
                    )
                ),
            )
        except RuntimeScanError as exc:
            _write_frame(
                sys.stdout.buffer,
                WorkerScanErrorFrame(
                    error=WorkerError(
                        code=exc.code,
                        message=exc.message,
                    )
                ),
            )
        except Exception:
            _write_frame(
                sys.stdout.buffer,
                WorkerScanErrorFrame(
                    error=WorkerError(
                        code=ScanFailureCode.RUNTIME_ERROR,
                        message=DEFAULT_ERROR_MESSAGES[ScanFailureCode.RUNTIME_ERROR],
                    )
                ),
            )


if __name__ == "__main__":
    raise SystemExit(main())
