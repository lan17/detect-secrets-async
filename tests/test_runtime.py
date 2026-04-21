from __future__ import annotations

import asyncio
import concurrent.futures
import sys
import textwrap
import threading
import time
from collections.abc import Callable, Coroutine
from contextlib import suppress
from importlib.metadata import version
from pathlib import Path

import pytest
from pydantic import ValidationError

from detect_secrets_async import (
    DetectSecretsRuntime,
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
from detect_secrets_async._config import resolve_runtime_config
from detect_secrets_async._runtime import _RuntimeService, _WorkerSlot


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


def _slot_process(
    runtime: DetectSecretsRuntime,
    slot_index: int = 0,
) -> asyncio.subprocess.Process | None:
    service = runtime._service
    assert service is not None
    return service._worker_slots[slot_index].process


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
    assert runtime._service is not None
    assert runtime._service._requests_by_id == {}


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
    old_process = _slot_process(runtime)
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
    assert _slot_process(runtime) is None

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
    assert _slot_process(runtime) is None


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

    assert _slot_process(runtime) is None


@pytest.mark.asyncio
async def test_worker_recycles_after_max_requests() -> None:
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=1, max_requests_per_worker=1))

    await runtime.scan(_request("github_token = 'ghp_123456789012345678901234567890123456'"))
    first_process = _slot_process(runtime)
    assert first_process is None

    await runtime.scan(_request("github_token = 'ghp_123456789012345678901234567890123456'"))
    second_process = _slot_process(runtime)
    assert second_process is None


@pytest.mark.asyncio
async def test_shutdown_runtime_terminates_workers_deterministically() -> None:
    runtime = get_runtime()
    await runtime.scan(_request("github_token = 'ghp_123456789012345678901234567890123456'"))

    process = _slot_process(runtime)
    assert process is not None

    await shutdown_runtime()
    assert process.returncode is not None


@pytest.mark.asyncio
async def test_runtime_instance_shutdown_clears_singleton_reference() -> None:
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10))

    await runtime.shutdown()

    replacement = get_runtime(
        RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10)
    )
    assert replacement is not runtime


@pytest.mark.asyncio
async def test_runtime_instance_shutdown_blocks_singleton_access_while_tearing_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10))
    started = threading.Event()
    release = threading.Event()
    original_shutdown = _RuntimeService.shutdown

    async def delayed_shutdown(self: _RuntimeService) -> None:
        started.set()
        await asyncio.to_thread(release.wait)
        await original_shutdown(self)

    monkeypatch.setattr(_RuntimeService, "shutdown", delayed_shutdown)

    shutdown_task = asyncio.create_task(runtime.shutdown())
    assert await asyncio.to_thread(started.wait, 1.0)

    with pytest.raises(RuntimeScanError) as runtime_exc_info:
        get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10))

    assert runtime_exc_info.value.code == ScanFailureCode.RUNTIME_ERROR

    with pytest.raises(RuntimeScanError) as configure_exc_info:
        configure_runtime(RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10))

    assert configure_exc_info.value.code == ScanFailureCode.RUNTIME_ERROR

    release.set()
    await shutdown_task


@pytest.mark.asyncio
async def test_runtime_shutdown_raises_if_thread_does_not_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = DetectSecretsRuntime(
        RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10)
    )
    started = threading.Event()
    release = threading.Event()

    monkeypatch.setattr("detect_secrets_async._runtime.THREAD_JOIN_TIMEOUT_SECONDS", 0.01)

    async def linger_during_teardown() -> None:
        started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await asyncio.to_thread(release.wait)
            raise

    assert runtime._loop is not None
    asyncio.run_coroutine_threadsafe(linger_during_teardown(), runtime._loop)
    assert await asyncio.to_thread(started.wait, 1.0)

    with pytest.raises(RuntimeScanError) as exc_info:
        await runtime.shutdown()

    assert exc_info.value.code == ScanFailureCode.RUNTIME_ERROR
    assert runtime._thread is not None
    assert runtime._thread.is_alive()

    release.set()
    await asyncio.to_thread(runtime._thread.join, 1.0)
    runtime._close_nowait()


@pytest.mark.asyncio
async def test_shutdown_runtime_can_recover_after_prior_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10))
    started = threading.Event()
    release = threading.Event()

    monkeypatch.setattr("detect_secrets_async._runtime.THREAD_JOIN_TIMEOUT_SECONDS", 0.01)

    async def linger_during_teardown() -> None:
        started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await asyncio.to_thread(release.wait)
            raise

    assert runtime._loop is not None
    asyncio.run_coroutine_threadsafe(linger_during_teardown(), runtime._loop)
    assert await asyncio.to_thread(started.wait, 1.0)

    with pytest.raises(RuntimeScanError):
        await shutdown_runtime()

    release.set()
    assert runtime._thread is not None
    await asyncio.to_thread(runtime._thread.join, 1.0)

    await shutdown_runtime()

    replacement = get_runtime(
        RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10)
    )
    assert replacement is not runtime


@pytest.mark.asyncio
async def test_shutdown_runtime_blocks_new_access_until_teardown_finishes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10))
    started = threading.Event()
    release = threading.Event()
    original_shutdown = _RuntimeService.shutdown

    async def delayed_shutdown(self: _RuntimeService) -> None:
        started.set()
        await asyncio.to_thread(release.wait)
        await original_shutdown(self)

    monkeypatch.setattr(_RuntimeService, "shutdown", delayed_shutdown)

    shutdown_task = asyncio.create_task(shutdown_runtime())
    assert await asyncio.to_thread(started.wait, 1.0)

    with pytest.raises(RuntimeScanError) as exc_info:
        get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10))

    assert exc_info.value.code == ScanFailureCode.RUNTIME_ERROR

    release.set()
    await shutdown_task

    replacement = get_runtime(
        RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10)
    )
    assert replacement is not runtime


def test_runtime_supports_queued_scans_from_multiple_event_loops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_fake_worker_script(
        tmp_path,
        """
        for line in sys.stdin:
            time.sleep(0.2)
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
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10))

    results: list[tuple[str, tuple[ScanFailureCode, str] | None]] = []
    results_lock = threading.Lock()
    start_barrier = threading.Barrier(3)

    def run_scan(name: str) -> None:
        async def runner() -> None:
            start_barrier.wait()
            try:
                await runtime.scan(_request(name, timeout_ms=2_000))
                outcome: tuple[ScanFailureCode, str] | None = None
            except RuntimeScanError as exc:  # pragma: no cover - exercised only on regression
                outcome = (exc.code, str(exc))
            with results_lock:
                results.append((name, outcome))

        asyncio.run(runner())

    threads = [threading.Thread(target=run_scan, args=(label,)) for label in ("one", "two")]
    for thread in threads:
        thread.start()
    start_barrier.wait()
    for thread in threads:
        thread.join()

    assert sorted(results) == [("one", None), ("two", None)]


def test_shutdown_runtime_is_safe_from_a_different_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_fake_worker_script(
        tmp_path,
        """
        for line in sys.stdin:
            time.sleep(0.5)
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
    runtime = get_runtime(RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10))

    scan_started = threading.Event()

    def run_scan() -> None:
        async def runner() -> None:
            scan_started.set()
            with suppress(RuntimeScanError):
                await runtime.scan(_request("one", timeout_ms=2_000))

        asyncio.run(runner())

    thread = threading.Thread(target=run_scan)
    thread.start()
    assert scan_started.wait(timeout=1.0)

    asyncio.run(shutdown_runtime())

    thread.join(timeout=1.0)
    assert not thread.is_alive()


@pytest.mark.asyncio
async def test_submit_does_not_build_coroutine_after_runtime_shutdown() -> None:
    runtime = DetectSecretsRuntime(
        RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10)
    )
    await runtime.shutdown()

    factory_called = False

    async def fake_scan() -> object:
        return object()

    def build_coroutine() -> Coroutine[object, object, object]:
        nonlocal factory_called
        factory_called = True
        return fake_scan()

    with pytest.raises(RuntimeScanError) as exc_info:
        runtime._submit(build_coroutine)

    assert exc_info.value.code == ScanFailureCode.RUNTIME_ERROR
    assert not factory_called


def test_submit_holds_thread_lock_while_scheduling(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = DetectSecretsRuntime(
        RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=10)
    )
    submitted = concurrent.futures.Future[object]()
    submitted.set_result(object())

    async def fake_scan() -> object:
        return object()

    def fake_run_coroutine_threadsafe(
        coroutine: Coroutine[object, object, object],
        loop: asyncio.AbstractEventLoop,
    ) -> concurrent.futures.Future[object]:
        assert runtime._thread_lock.locked()
        coroutine.close()
        return submitted

    monkeypatch.setattr(asyncio, "run_coroutine_threadsafe", fake_run_coroutine_threadsafe)

    future = runtime._submit(fake_scan)

    assert future is submitted
    runtime._close_nowait()


def test_singleton_runtime_conflict_raises() -> None:
    configure_runtime(RuntimeConfig(pool_size=1, max_queue_depth=4, max_requests_per_worker=5))

    with pytest.raises(RuntimeConfigConflictError):
        get_runtime(RuntimeConfig(pool_size=2, max_queue_depth=4, max_requests_per_worker=5))


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("pool_size", 0),
        ("pool_size", -1),
        ("max_queue_depth", -1),
        ("max_requests_per_worker", 0),
    ],
)
def test_explicit_runtime_overrides_are_validated(field_name: str, value: int) -> None:
    with pytest.raises(ValidationError):
        if field_name == "pool_size":
            resolve_runtime_config(pool_size=value)
        elif field_name == "max_queue_depth":
            resolve_runtime_config(max_queue_depth=value)
        else:
            resolve_runtime_config(max_requests_per_worker=value)


def test_env_runtime_overrides_are_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DETECT_SECRETS_ASYNC_POOL_SIZE", "abc")

    with pytest.raises(ValidationError):
        resolve_runtime_config()


def test_runtime_info_exposes_pinned_detect_secrets_version() -> None:
    info = get_runtime_info()

    assert info.detect_secrets_version == version("detect-secrets")
    assert "GitHubTokenDetector" in info.available_plugin_names
    assert info.default_plugin_names == info.available_plugin_names
