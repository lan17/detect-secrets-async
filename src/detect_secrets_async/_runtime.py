from __future__ import annotations

import asyncio
import atexit
import logging
import sys
import threading
from collections import deque
from contextlib import suppress
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version

from pydantic import ValidationError

from ._config import RuntimeConfig, resolve_runtime_config
from ._detect_secrets import (
    get_available_plugin_names,
    get_default_plugin_names,
    get_detect_secrets_version,
)
from ._errors import RuntimeConfigConflictError, RuntimeScanError, ScanFailureCode
from ._models import (
    MAX_FRAME_BYTES,
    WORKER_HELLO_ADAPTER,
    WORKER_RESPONSE_ADAPTER,
    RuntimeInfo,
    ScanRequest,
    ScanResult,
    WorkerScanRequestFrame,
)

LOGGER = logging.getLogger(__name__)
PROCESS_KILL_WAIT_SECONDS = 0.5

_RUNTIME_LOCK = threading.Lock()
_RUNTIME: DetectSecretsRuntime | None = None
_CONFIG: RuntimeConfig | None = None


def _package_version() -> str:
    try:
        return version("detect-secrets-async")
    except PackageNotFoundError:
        return "0.0.0"


def _consume_future_result(future: asyncio.Future[ScanResult]) -> None:
    with suppress(asyncio.CancelledError, Exception):
        future.result()


@dataclass(slots=True)
class _PendingRequest:
    request: ScanRequest
    future: asyncio.Future[ScanResult]
    deadline: float
    started: bool = False
    slot: _WorkerSlot | None = None

    def mark_started(self, slot: _WorkerSlot) -> None:
        self.started = True
        self.slot = slot

    def abandon(self) -> None:
        self.future.add_done_callback(_consume_future_result)


class _WorkerSlot:
    def __init__(self, slot_id: int) -> None:
        self.slot_id = slot_id
        self.process: asyncio.subprocess.Process | None = None
        self.requests_served = 0

    def _build_worker_command(self) -> tuple[str, ...]:
        return (sys.executable, "-m", "detect_secrets_async._worker")

    def _remaining_seconds(self, deadline: float) -> float:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise RuntimeScanError(ScanFailureCode.WORKER_TIMEOUT)
        return remaining

    async def ensure_started(self, deadline: float) -> None:
        if self.process is not None and self.process.returncode is None:
            return

        self.process = None
        self.requests_served = 0
        try:
            self.process = await asyncio.create_subprocess_exec(
                *self._build_worker_command(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                limit=MAX_FRAME_BYTES + 1,
            )
        except (OSError, ValueError) as exc:
            LOGGER.warning("failed to start detect-secrets worker %s", self.slot_id, exc_info=exc)
            raise RuntimeScanError(ScanFailureCode.WORKER_STARTUP_ERROR) from exc

        try:
            raw_hello = await self._read_frame(
                deadline,
                eof_code=ScanFailureCode.WORKER_STARTUP_ERROR,
            )
            hello = WORKER_HELLO_ADAPTER.validate_json(raw_hello)
        except ValidationError as exc:
            raise RuntimeScanError(ScanFailureCode.WORKER_PROTOCOL_ERROR) from exc

        if hello.protocol_version != 1:
            raise RuntimeScanError(ScanFailureCode.WORKER_PROTOCOL_ERROR)

    async def execute(self, request: ScanRequest, deadline: float) -> ScanResult:
        await self.ensure_started(deadline)

        try:
            payload = (
                WorkerScanRequestFrame(request=request)
                .model_dump_json(exclude_none=True)
                .encode("utf-8")
                + b"\n"
            )
        except ValidationError as exc:
            raise RuntimeScanError(ScanFailureCode.INVALID_CONFIG) from exc

        if len(payload) > MAX_FRAME_BYTES:
            raise RuntimeScanError(
                ScanFailureCode.RUNTIME_ERROR,
                "scan request exceeds the runtime protocol frame size limit",
            )

        process = self._require_process()
        stdin = process.stdin
        if stdin is None:
            raise RuntimeScanError(ScanFailureCode.WORKER_CRASH)

        try:
            stdin.write(payload)
            async with asyncio.timeout(self._remaining_seconds(deadline)):
                await stdin.drain()
        except TimeoutError as exc:
            raise RuntimeScanError(ScanFailureCode.WORKER_TIMEOUT) from exc
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise RuntimeScanError(ScanFailureCode.WORKER_CRASH) from exc

        raw_response = await self._read_frame(deadline, eof_code=ScanFailureCode.WORKER_CRASH)
        try:
            response = WORKER_RESPONSE_ADAPTER.validate_json(raw_response)
        except ValidationError as exc:
            raise RuntimeScanError(ScanFailureCode.WORKER_PROTOCOL_ERROR) from exc

        if response.frame_type == "scan_error":
            raise RuntimeScanError(response.error.code, response.error.message)

        self.requests_served += 1
        return response.result

    def needs_recycle(self, max_requests_per_worker: int) -> bool:
        return self.requests_served >= max_requests_per_worker

    def schedule_terminate(self, reason: str) -> asyncio.Task[None] | None:
        process = self.process
        self.process = None
        self.requests_served = 0
        if process is None:
            return None

        return asyncio.create_task(self._terminate_process(process, reason))

    def kill_nowait(self) -> None:
        process = self.process
        self.process = None
        self.requests_served = 0
        if process is None:
            return
        if process.returncode is None:
            with suppress(ProcessLookupError):
                process.kill()

    async def _terminate_process(
        self,
        process: asyncio.subprocess.Process,
        reason: str,
    ) -> None:
        if process.returncode is None:
            LOGGER.warning("terminating detect-secrets worker %s (%s)", self.slot_id, reason)
            with suppress(ProcessLookupError):
                process.kill()
            with suppress(TimeoutError):
                await asyncio.wait_for(process.wait(), timeout=PROCESS_KILL_WAIT_SECONDS)

        if process.stdin is not None:
            with suppress(BrokenPipeError):
                process.stdin.close()

    async def _read_frame(self, deadline: float, *, eof_code: ScanFailureCode) -> bytes:
        process = self._require_process()
        stdout = process.stdout
        if stdout is None:
            raise RuntimeScanError(ScanFailureCode.WORKER_CRASH)

        try:
            async with asyncio.timeout(self._remaining_seconds(deadline)):
                frame = await stdout.readuntil(b"\n")
        except TimeoutError as exc:
            raise RuntimeScanError(ScanFailureCode.WORKER_TIMEOUT) from exc
        except asyncio.IncompleteReadError as exc:
            if exc.partial:
                raise RuntimeScanError(ScanFailureCode.WORKER_PROTOCOL_ERROR) from exc
            raise RuntimeScanError(eof_code) from exc
        except asyncio.LimitOverrunError as exc:
            raise RuntimeScanError(ScanFailureCode.WORKER_PROTOCOL_ERROR) from exc

        if len(frame) > MAX_FRAME_BYTES:
            raise RuntimeScanError(ScanFailureCode.WORKER_PROTOCOL_ERROR)

        return frame[:-1]

    def _require_process(self) -> asyncio.subprocess.Process:
        if self.process is None:
            raise RuntimeScanError(ScanFailureCode.WORKER_CRASH)
        return self.process


class DetectSecretsRuntime:
    """Async facade over a bounded pool of detect-secrets subprocess workers."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self._state_lock = asyncio.Lock()
        self._closed = False
        self._worker_slots = tuple(_WorkerSlot(slot_id=index) for index in range(config.pool_size))
        self._available_slots: deque[_WorkerSlot] = deque(self._worker_slots)
        self._pending_requests: deque[_PendingRequest] = deque()
        self._job_tasks: set[asyncio.Task[None]] = set()
        self._background_tasks: set[asyncio.Task[None]] = set()

    async def scan(self, request: ScanRequest) -> ScanResult:
        deadline = asyncio.get_running_loop().time() + (request.timeout_ms / 1000)
        pending = _PendingRequest(
            request=request,
            future=asyncio.get_running_loop().create_future(),
            deadline=deadline,
        )

        async with self._state_lock:
            self._ensure_open()
            if self._available_slots and not self._pending_requests:
                slot = self._available_slots.popleft()
                pending.mark_started(slot)
                self._schedule_job(slot, pending)
            else:
                if len(self._pending_requests) >= self.config.max_queue_depth:
                    raise RuntimeScanError(ScanFailureCode.QUEUE_FULL)
                self._pending_requests.append(pending)

        try:
            return await asyncio.wait_for(
                asyncio.shield(pending.future),
                timeout=request.timeout_ms / 1000,
            )
        except TimeoutError as exc:
            failure = await self._handle_wait_expiry(pending)
            raise failure from exc
        except asyncio.CancelledError:
            await self._handle_caller_cancellation(pending)
            raise

    async def shutdown(self) -> None:
        async with self._state_lock:
            if self._closed:
                return

            self._closed = True
            pending_requests = list(self._pending_requests)
            self._pending_requests.clear()
            termination_tasks = [
                task
                for slot in self._worker_slots
                for task in [slot.schedule_terminate("runtime shutdown")]
                if task is not None
            ]

        for pending in pending_requests:
            if not pending.future.done():
                pending.future.set_exception(
                    RuntimeScanError(
                        ScanFailureCode.RUNTIME_ERROR,
                        "runtime is shut down",
                    )
                )
                pending.abandon()

        for task in termination_tasks:
            self._track_background_task(task)

        await asyncio.gather(*tuple(self._job_tasks), return_exceptions=True)
        await asyncio.gather(*tuple(self._background_tasks), return_exceptions=True)

    def close_nowait(self) -> None:
        self._closed = True
        for slot in self._worker_slots:
            slot.kill_nowait()

    def info(self) -> RuntimeInfo:
        return RuntimeInfo(
            package_version=_package_version(),
            detect_secrets_version=get_detect_secrets_version(),
            available_plugin_names=get_available_plugin_names(),
            default_plugin_names=get_default_plugin_names(),
            configured_runtime=self.config,
        )

    async def _handle_wait_expiry(self, pending: _PendingRequest) -> RuntimeScanError:
        async with self._state_lock:
            if not pending.started:
                with suppress(ValueError):
                    self._pending_requests.remove(pending)
                pending.future.cancel()
                return RuntimeScanError(ScanFailureCode.QUEUE_TIMEOUT)

            slot = pending.slot

        if slot is not None:
            pending.abandon()
            self._reset_slot(slot, reason="request timeout")

        return RuntimeScanError(ScanFailureCode.WORKER_TIMEOUT)

    async def _handle_caller_cancellation(self, pending: _PendingRequest) -> None:
        async with self._state_lock:
            if not pending.started:
                with suppress(ValueError):
                    self._pending_requests.remove(pending)
                pending.future.cancel()
                return

            slot = pending.slot

        if slot is not None and not pending.future.done():
            pending.abandon()
            self._reset_slot(slot, reason="caller cancellation")

    def _schedule_job(self, slot: _WorkerSlot, pending: _PendingRequest) -> None:
        task = asyncio.create_task(self._run_job(slot, pending))
        self._job_tasks.add(task)
        task.add_done_callback(self._job_tasks.discard)

    def _track_background_task(self, task: asyncio.Task[None]) -> None:
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _run_job(self, slot: _WorkerSlot, pending: _PendingRequest) -> None:
        recycle_after_completion = False
        try:
            result = await slot.execute(pending.request, pending.deadline)
            recycle_after_completion = slot.needs_recycle(self.config.max_requests_per_worker)
            if not pending.future.done():
                pending.future.set_result(result)
        except RuntimeScanError as exc:
            if exc.code in {
                ScanFailureCode.WORKER_STARTUP_ERROR,
                ScanFailureCode.WORKER_TIMEOUT,
                ScanFailureCode.WORKER_CRASH,
                ScanFailureCode.WORKER_PROTOCOL_ERROR,
            }:
                self._reset_slot(slot, reason=exc.code.value)
            if not pending.future.done():
                pending.future.set_exception(exc)
        except Exception as exc:
            LOGGER.exception("unexpected runtime error in detect-secrets worker %s", slot.slot_id)
            self._reset_slot(slot, reason="unexpected runtime error")
            if not pending.future.done():
                pending.future.set_exception(RuntimeScanError(ScanFailureCode.RUNTIME_ERROR))
            raise exc
        finally:
            if recycle_after_completion:
                self._reset_slot(slot, reason="max requests reached")
            await self._release_slot(slot)

    def _reset_slot(self, slot: _WorkerSlot, *, reason: str) -> None:
        task = slot.schedule_terminate(reason)
        if task is not None:
            self._track_background_task(task)

    async def _release_slot(self, slot: _WorkerSlot) -> None:
        async with self._state_lock:
            if self._closed:
                return

            while self._pending_requests:
                next_pending = self._pending_requests.popleft()
                if next_pending.future.done():
                    continue
                next_pending.mark_started(slot)
                self._schedule_job(slot, next_pending)
                return

            self._available_slots.append(slot)

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeScanError(
                ScanFailureCode.RUNTIME_ERROR,
                "runtime is shut down",
            )


def get_runtime(
    config: RuntimeConfig | None = None,
    *,
    pool_size: int | None = None,
    max_queue_depth: int | None = None,
    max_requests_per_worker: int | None = None,
) -> DetectSecretsRuntime:
    """Return the shared runtime, creating it lazily on first access."""

    resolved = resolve_runtime_config(
        config,
        pool_size=pool_size,
        max_queue_depth=max_queue_depth,
        max_requests_per_worker=max_requests_per_worker,
    )
    global _CONFIG, _RUNTIME
    with _RUNTIME_LOCK:
        if _CONFIG is None:
            _CONFIG = resolved
        elif resolved != _CONFIG:
            raise RuntimeConfigConflictError(
                "detect-secrets runtime is already configured with different settings"
            )

        if _RUNTIME is None:
            _RUNTIME = DetectSecretsRuntime(_CONFIG)

        return _RUNTIME


def init_runtime(
    config: RuntimeConfig | None = None,
    *,
    pool_size: int | None = None,
    max_queue_depth: int | None = None,
    max_requests_per_worker: int | None = None,
) -> DetectSecretsRuntime:
    """Alias for get_runtime()."""

    return get_runtime(
        config,
        pool_size=pool_size,
        max_queue_depth=max_queue_depth,
        max_requests_per_worker=max_requests_per_worker,
    )


def configure_runtime(
    config: RuntimeConfig | None = None,
    *,
    pool_size: int | None = None,
    max_queue_depth: int | None = None,
    max_requests_per_worker: int | None = None,
) -> RuntimeConfig:
    """Configure host-level runtime settings before first use."""

    resolved = resolve_runtime_config(
        config,
        pool_size=pool_size,
        max_queue_depth=max_queue_depth,
        max_requests_per_worker=max_requests_per_worker,
    )
    global _CONFIG
    with _RUNTIME_LOCK:
        if _CONFIG is None:
            _CONFIG = resolved
        elif resolved != _CONFIG:
            raise RuntimeConfigConflictError(
                "detect-secrets runtime is already configured with different settings"
            )
        return _CONFIG


async def shutdown_runtime() -> None:
    """Shutdown and clear the shared runtime instance."""

    global _CONFIG, _RUNTIME
    with _RUNTIME_LOCK:
        runtime = _RUNTIME
        _RUNTIME = None
        _CONFIG = None

    if runtime is not None:
        await runtime.shutdown()


async def reset_runtime_for_tests() -> None:
    """Test helper to clear shared runtime state."""

    await shutdown_runtime()


def get_runtime_info() -> RuntimeInfo:
    """Return static runtime/package facts without requiring a scan."""

    with _RUNTIME_LOCK:
        configured_runtime = _CONFIG
    return RuntimeInfo(
        package_version=_package_version(),
        detect_secrets_version=get_detect_secrets_version(),
        available_plugin_names=get_available_plugin_names(),
        default_plugin_names=get_default_plugin_names(),
        configured_runtime=configured_runtime,
    )


def _cleanup_runtime_at_exit() -> None:
    with _RUNTIME_LOCK:
        runtime = _RUNTIME
    if runtime is not None:
        runtime.close_nowait()


atexit.register(_cleanup_runtime_at_exit)
