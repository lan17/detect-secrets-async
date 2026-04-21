from __future__ import annotations

import asyncio
import sys
import textwrap
import time
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path

import pytest

from detect_secrets_async import (
    RuntimeConfig,
    RuntimeConfigConflictError,
    RuntimeScanError,
    ScanConfig,
    ScanFailureCode,
    ScanRequest,
    configure_runtime,
    get_runtime,
    get_runtime_info,
    shutdown_runtime,
)
from detect_secrets_async._runtime import _WorkerSlot


def _request(
    content: str,
    *,
    timeout_ms: int = 5_000,
    enabled_plugins: tuple[str, ...] | None = None,
) -> ScanRequest:
    return ScanRequest(
        content=content,
        timeout_ms=timeout_ms,
        config=ScanConfig(enabled_plugins=enabled_plugins),
    )


def _write_fake_worker_script(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "fake_worker.py"
    body_block = textwrap.dedent(body).strip()
    script.write_text(
        "\n".join(
            [
                "import json",
                "import os",
                "import sys",
                "import time",
                "",
                "def send(payload):",
                '    sys.stdout.write(json.dumps(payload) + "\\n")',
                "    sys.stdout.flush()",
                "",
                "send({",
                '    "frame_type": "hello",',
                '    "protocol_version": 1,',
                '    "detect_secrets_version": "fake-1.0.0",',
                '    "available_plugin_names": ["FakeDetector"],',
                '    "default_plugin_names": ["FakeDetector"],',
                "})",
                "",
                body_block,
                "",
            ]
        ),
        encoding="utf-8",
    )
    return script


def _patch_worker_command(
    monkeypatch: pytest.MonkeyPatch,
    command_factory: Callable[[], tuple[str, ...]],
) -> None:
    monkeypatch.setattr(_WorkerSlot, "_build_worker_command", lambda self: command_factory())


@pytest.mark.asyncio
async def test_runtime_scans_content_with_default_plugins() -> None:
    runtime = get_runtime()

    result = await runtime.scan(
        _request("github_token = 'ghp_123456789012345678901234567890123456'")
    )

    assert result.detect_secrets_version == version("detect-secrets")
    assert [finding.type for finding in result.findings] == ["GitHub Token"]
    assert [finding.line_number for finding in result.findings] == [1]


@pytest.mark.asyncio
async def test_runtime_keeps_plugin_configs_isolated_between_requests() -> None:
    runtime = get_runtime()
    sample = "api_key = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDE='"

    github_only = await runtime.scan(_request(sample, enabled_plugins=("GitHubTokenDetector",)))
    default_plugins = await runtime.scan(_request(sample))

    assert github_only.findings == ()
    assert {finding.type for finding in default_plugins.findings} == {
        "Base64 High Entropy String",
        "Secret Keyword",
    }


@pytest.mark.asyncio
async def test_runtime_rejects_unknown_plugins() -> None:
    runtime = get_runtime()

    with pytest.raises(RuntimeScanError) as exc_info:
        await runtime.scan(
            _request(
                "github_token = 'ghp_123456789012345678901234567890123456'",
                enabled_plugins=("NoSuchPlugin",),
            )
        )

    assert exc_info.value.code == ScanFailureCode.INVALID_CONFIG


@pytest.mark.asyncio
async def test_runtime_runs_two_workers_in_parallel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_fake_worker_script(
        tmp_path,
        """
        for line in sys.stdin:
            time.sleep(0.4)
            send({
                "frame_type": "scan_result",
                "result": {
                    "findings": [],
                    "detect_secrets_version": "fake-1.0.0",
                },
            })
        """,
    )
    _patch_worker_command(monkeypatch, lambda: (sys.executable, str(script)))
    serial_runtime = get_runtime(
        RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10)
    )

    start = time.perf_counter()
    await asyncio.gather(
        serial_runtime.scan(_request("one", timeout_ms=2_000)),
        serial_runtime.scan(_request("two", timeout_ms=2_000)),
    )
    serial_elapsed = time.perf_counter() - start

    await shutdown_runtime()

    parallel_runtime = get_runtime(
        RuntimeConfig(pool_size=2, max_queue_depth=4, max_requests_per_worker=10)
    )
    start = time.perf_counter()
    await asyncio.gather(
        parallel_runtime.scan(_request("one", timeout_ms=2_000)),
        parallel_runtime.scan(_request("two", timeout_ms=2_000)),
    )
    parallel_elapsed = time.perf_counter() - start

    assert parallel_elapsed < serial_elapsed * 0.9


@pytest.mark.asyncio
async def test_queue_full_is_rejected_immediately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_fake_worker_script(
        tmp_path,
        """
        for line in sys.stdin:
            time.sleep(0.3)
            send({
                "frame_type": "scan_result",
                "result": {
                    "findings": [],
                    "detect_secrets_version": "fake-1.0.0",
                },
            })
        """,
    )
    _patch_worker_command(monkeypatch, lambda: (sys.executable, str(script)))
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=1, max_requests_per_worker=10))

    task_one = asyncio.create_task(runtime.scan(_request("one", timeout_ms=1_000)))
    task_two = asyncio.create_task(runtime.scan(_request("two", timeout_ms=1_000)))
    await asyncio.sleep(0.05)

    with pytest.raises(RuntimeScanError) as exc_info:
        await runtime.scan(_request("three", timeout_ms=1_000))

    assert exc_info.value.code == ScanFailureCode.QUEUE_FULL
    await asyncio.gather(task_one, task_two)


@pytest.mark.asyncio
async def test_timeout_while_waiting_for_worker_is_queue_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_fake_worker_script(
        tmp_path,
        """
        for line in sys.stdin:
            time.sleep(0.35)
            send({
                "frame_type": "scan_result",
                "result": {
                    "findings": [],
                    "detect_secrets_version": "fake-1.0.0",
                },
            })
        """,
    )
    _patch_worker_command(monkeypatch, lambda: (sys.executable, str(script)))
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=1, max_requests_per_worker=10))

    task_one = asyncio.create_task(runtime.scan(_request("one", timeout_ms=1_000)))
    await asyncio.sleep(0.05)

    with pytest.raises(RuntimeScanError) as exc_info:
        await runtime.scan(_request("two", timeout_ms=100))

    assert exc_info.value.code == ScanFailureCode.QUEUE_TIMEOUT
    await task_one


@pytest.mark.asyncio
async def test_worker_timeout_kills_and_replaces_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slow_script = _write_fake_worker_script(
        tmp_path,
        """
        for line in sys.stdin:
            time.sleep(1.0)
            send({
                "frame_type": "scan_result",
                "result": {
                    "findings": [],
                    "detect_secrets_version": "fake-1.0.0",
                },
            })
        """,
    )
    _patch_worker_command(monkeypatch, lambda: (sys.executable, str(slow_script)))
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=1, max_requests_per_worker=10))

    with pytest.raises(RuntimeScanError) as exc_info:
        await runtime.scan(_request("one", timeout_ms=100))

    assert exc_info.value.code == ScanFailureCode.WORKER_TIMEOUT
    old_process = runtime._worker_slots[0].process
    assert old_process is None

    fast_script = _write_fake_worker_script(
        tmp_path,
        """
        for line in sys.stdin:
            send({
                "frame_type": "scan_result",
                "result": {
                    "findings": [],
                    "detect_secrets_version": "fake-1.0.0",
                },
            })
        """,
    )
    _patch_worker_command(monkeypatch, lambda: (sys.executable, str(fast_script)))
    result = await runtime.scan(_request("two", timeout_ms=1_000))

    assert result.findings == ()


@pytest.mark.asyncio
async def test_worker_crash_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    crash_script = _write_fake_worker_script(
        tmp_path,
        """
        for line in sys.stdin:
            os._exit(3)
        """,
    )
    _patch_worker_command(monkeypatch, lambda: (sys.executable, str(crash_script)))
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=1, max_requests_per_worker=10))

    with pytest.raises(RuntimeScanError) as exc_info:
        await runtime.scan(_request("one", timeout_ms=1_000))

    assert exc_info.value.code == ScanFailureCode.WORKER_CRASH
    assert runtime._worker_slots[0].process is None

    success_script = _write_fake_worker_script(
        tmp_path,
        """
        for line in sys.stdin:
            send({
                "frame_type": "scan_result",
                "result": {
                    "findings": [],
                    "detect_secrets_version": "fake-1.0.0",
                },
            })
        """,
    )
    _patch_worker_command(monkeypatch, lambda: (sys.executable, str(success_script)))
    result = await runtime.scan(_request("two", timeout_ms=1_000))

    assert result.findings == ()


@pytest.mark.asyncio
async def test_worker_protocol_error_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol_script = _write_fake_worker_script(
        tmp_path,
        """
        for line in sys.stdin:
            sys.stdout.write("not-json\\n")
            sys.stdout.flush()
        """,
    )
    _patch_worker_command(monkeypatch, lambda: (sys.executable, str(protocol_script)))
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=1, max_requests_per_worker=10))

    with pytest.raises(RuntimeScanError) as exc_info:
        await runtime.scan(_request("one", timeout_ms=1_000))

    assert exc_info.value.code == ScanFailureCode.WORKER_PROTOCOL_ERROR
    assert runtime._worker_slots[0].process is None


@pytest.mark.asyncio
async def test_worker_startup_failure_is_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken_script = tmp_path / "broken_worker.py"
    broken_script.write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    _patch_worker_command(monkeypatch, lambda: (sys.executable, str(broken_script)))
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=1, max_requests_per_worker=10))

    with pytest.raises(RuntimeScanError) as exc_info:
        await runtime.scan(_request("one", timeout_ms=1_000))

    assert exc_info.value.code == ScanFailureCode.WORKER_STARTUP_ERROR


@pytest.mark.asyncio
async def test_caller_cancellation_kills_inflight_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slow_script = _write_fake_worker_script(
        tmp_path,
        """
        for line in sys.stdin:
            time.sleep(1.0)
            send({
                "frame_type": "scan_result",
                "result": {
                    "findings": [],
                    "detect_secrets_version": "fake-1.0.0",
                },
            })
        """,
    )
    _patch_worker_command(monkeypatch, lambda: (sys.executable, str(slow_script)))
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=1, max_requests_per_worker=10))

    scan_task = asyncio.create_task(runtime.scan(_request("one", timeout_ms=5_000)))
    await asyncio.sleep(0.1)
    scan_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await scan_task

    assert runtime._worker_slots[0].process is None


@pytest.mark.asyncio
async def test_worker_recycles_after_max_requests() -> None:
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=1, max_requests_per_worker=1))

    await runtime.scan(_request("github_token = 'ghp_123456789012345678901234567890123456'"))
    first_process = runtime._worker_slots[0].process
    assert first_process is None

    await runtime.scan(_request("github_token = 'ghp_123456789012345678901234567890123456'"))
    second_process = runtime._worker_slots[0].process
    assert second_process is None


@pytest.mark.asyncio
async def test_shutdown_runtime_terminates_workers_deterministically() -> None:
    runtime = get_runtime()
    await runtime.scan(_request("github_token = 'ghp_123456789012345678901234567890123456'"))

    process = runtime._worker_slots[0].process
    assert process is not None

    await shutdown_runtime()
    assert process.returncode is not None


def test_singleton_runtime_conflict_raises() -> None:
    configure_runtime(RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=5))

    with pytest.raises(RuntimeConfigConflictError):
        get_runtime(RuntimeConfig(pool_size=2, max_queue_depth=4, max_requests_per_worker=5))


def test_runtime_info_exposes_pinned_detect_secrets_version() -> None:
    info = get_runtime_info()

    assert info.detect_secrets_version == version("detect-secrets")
    assert "GitHubTokenDetector" in info.available_plugin_names
    assert info.default_plugin_names == info.available_plugin_names
