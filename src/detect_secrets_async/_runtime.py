from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import itertools
import logging
import sys
import threading
from collections import deque
from collections.abc import Callable, Coroutine
from contextlib import suppress
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import TypeVar

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
# Keep shutdown and cancellation responsive even when a child process is slow to die.
PROCESS_KILL_WAIT_SECONDS = 0.5
THREAD_JOIN_TIMEOUT_SECONDS = 2.0
CALLER_CANCELLATION_CLEANUP_WAIT_SECONDS = 1.0

_RUNTIME_LOCK = threading.Lock()
_RUNTIME: DetectSecretsRuntime | None = None
_CONFIG: RuntimeConfig | None = None
_SHUTTING_DOWN = False
_T = TypeVar("_T")


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
                timeout_code=ScanFailureCode.WORKER_TIMEOUT,
            )
            WORKER_HELLO_ADAPTER.validate_json(raw_hello)
        except ValidationError as exc:
            raise RuntimeScanError(ScanFailureCode.WORKER_PROTOCOL_ERROR) from exc

    async def execute(self, request: ScanRequest, deadline: float) -> ScanResult:
        await self.ensure_started(deadline)

        payload = (
            WorkerScanRequestFrame(request=request)
            .model_dump_json(exclude_none=True)
            .encode("utf-8")
            + b"\n"
        )

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

        raw_response = await self._read_frame(
            deadline,
            eof_code=ScanFailureCode.WORKER_CRASH,
            timeout_code=ScanFailureCode.WORKER_TIMEOUT,
        )
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
        if process.stdin is not None:
            with suppress(BrokenPipeError):
                process.stdin.close()
        if process.returncode is None:
            with suppress(ProcessLookupError):
                process.kill()
        self._close_transport(process)

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
        self._close_transport(process)

    async def _read_frame(
        self,
        deadline: float,
        *,
        eof_code: ScanFailureCode,
        timeout_code: ScanFailureCode,
    ) -> bytes:
        process = self._require_process()
        stdout = process.stdout
        if stdout is None:
            raise RuntimeScanError(ScanFailureCode.WORKER_CRASH)

        try:
            async with asyncio.timeout(self._remaining_seconds(deadline)):
                frame = await stdout.readuntil(b"\n")
        except TimeoutError as exc:
            raise RuntimeScanError(timeout_code) from exc
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

    def _close_transport(self, process: asyncio.subprocess.Process) -> None:
        # asyncio subprocess pipes can keep transports open after process exit; close explicitly.
        transport = getattr(process, "_transport", None)
        if transport is not None:
            transport.close()


class _RuntimeService:
    """Single-loop runtime implementation hosted on the background event loop."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self._state_lock = asyncio.Lock()
        self._closed = False
        self._worker_slots = tuple(_WorkerSlot(slot_id=index) for index in range(config.pool_size))
        self._available_slots: deque[_WorkerSlot] = deque(self._worker_slots)
        self._pending_requests: deque[_PendingRequest] = deque()
        self._requests_by_id: dict[int, _PendingRequest] = {}
        self._job_tasks: set[asyncio.Task[None]] = set()
        self._background_tasks: set[asyncio.Task[None]] = set()

    async def scan(self, request_id: int, request: ScanRequest) -> ScanResult:
        deadline = asyncio.get_running_loop().time() + (request.timeout_ms / 1000)
        pending = _PendingRequest(
            request=request,
            future=asyncio.get_running_loop().create_future(),
            deadline=deadline,
        )

        async with self._state_lock:
            self._ensure_open()
            if self._available_slots and not self._pending_requests:
                self._requests_by_id[request_id] = pending
                slot = self._available_slots.popleft()
                pending.mark_started(slot)
                self._schedule_job(slot, pending)
            else:
                if len(self._pending_requests) >= self.config.max_queue_depth:
                    raise RuntimeScanError(ScanFailureCode.QUEUE_FULL)
                self._requests_by_id[request_id] = pending
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
        finally:
            async with self._state_lock:
                self._requests_by_id.pop(request_id, None)

    async def cancel(self, request_id: int) -> None:
        async with self._state_lock:
            pending = self._requests_by_id.get(request_id)
            if pending is None:
                return

            if not pending.started:
                with suppress(ValueError):
                    self._pending_requests.remove(pending)
                self._requests_by_id.pop(request_id, None)
                if not pending.future.done():
                    pending.future.set_exception(
                        RuntimeScanError(
                            ScanFailureCode.RUNTIME_ERROR,
                            "request cancelled by caller",
                        )
                    )
                return

            slot = pending.slot
            self._requests_by_id.pop(request_id, None)
            if not pending.future.done():
                pending.future.set_exception(
                    RuntimeScanError(
                        ScanFailureCode.RUNTIME_ERROR,
                        "request cancelled by caller",
                    )
                )

        if slot is not None:
            pending.abandon()
            self._reset_slot(slot, reason="caller cancellation")

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

        if slot is not None:
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
        except Exception:
            LOGGER.exception("unexpected runtime error in detect-secrets worker %s", slot.slot_id)
            self._reset_slot(slot, reason="unexpected runtime error")
            if not pending.future.done():
                pending.future.set_exception(RuntimeScanError(ScanFailureCode.RUNTIME_ERROR))
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

            loop = asyncio.get_running_loop()
            while self._pending_requests:
                next_pending = self._pending_requests.popleft()
                if next_pending.future.done():
                    continue
                if next_pending.deadline <= loop.time():
                    next_pending.future.set_exception(
                        RuntimeScanError(ScanFailureCode.QUEUE_TIMEOUT)
                    )
                    next_pending.abandon()
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


class DetectSecretsRuntime:
    """Thread-safe async facade over a dedicated runtime event loop."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self._thread_lock = threading.Lock()
        self._request_ids = itertools.count()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._service: _RuntimeService | None = None
        self._started = threading.Event()
        self._startup_error: BaseException | None = None
        self._closed = False
        self._start_loop_thread()

    async def scan(self, request: ScanRequest) -> ScanResult:
        request_id = next(self._request_ids)
        service = self._get_service()
        future = self._submit(lambda: service.scan(request_id, request))
        wrapped = asyncio.wrap_future(future)
        try:
            return await wrapped
        except asyncio.CancelledError:
            with suppress(
                asyncio.CancelledError,
                concurrent.futures.CancelledError,
                RuntimeScanError,
                TimeoutError,
            ):
                await asyncio.wait_for(
                    asyncio.wrap_future(
                        self._submit(lambda: service.cancel(request_id)),
                    ),
                    timeout=CALLER_CANCELLATION_CLEANUP_WAIT_SECONDS,
                )
            with suppress(
                asyncio.CancelledError,
                concurrent.futures.CancelledError,
                RuntimeScanError,
                TimeoutError,
            ):
                await asyncio.wait_for(
                    asyncio.wrap_future(future),
                    timeout=CALLER_CANCELLATION_CLEANUP_WAIT_SECONDS,
                )
            raise

    async def shutdown(self) -> None:
        _mark_global_runtime_shutting_down(self)
        thread = self._thread
        loop = self._loop
        service = self._service
        if thread is None or loop is None or service is None:
            with self._thread_lock:
                self._closed = True
            _clear_global_runtime_reference(self)
            return

        if not thread.is_alive() or loop.is_closed():
            with self._thread_lock:
                self._closed = True
            self._clear_thread_state()
            _clear_global_runtime_reference(self)
            return

        with self._thread_lock:
            self._closed = True

        future = asyncio.run_coroutine_threadsafe(service.shutdown(), loop)
        await asyncio.wrap_future(future)
        loop.call_soon_threadsafe(loop.stop)
        await asyncio.to_thread(thread.join, THREAD_JOIN_TIMEOUT_SECONDS)
        if thread.is_alive():
            raise RuntimeScanError(ScanFailureCode.RUNTIME_ERROR, "runtime thread did not stop")
        self._clear_thread_state()
        _clear_global_runtime_reference(self)

    def _close_nowait(self) -> None:
        _mark_global_runtime_shutting_down(self)
        with self._thread_lock:
            self._closed = True
            loop = self._loop
            service = self._service
            thread = self._thread

        if loop is not None and service is not None:
            with suppress(RuntimeError):
                loop.call_soon_threadsafe(service.close_nowait)
                loop.call_soon_threadsafe(loop.stop)

        if thread is not None:
            self._clear_thread_state()
        _clear_global_runtime_reference(self)

    def info(self) -> RuntimeInfo:
        return RuntimeInfo(
            package_version=_package_version(),
            detect_secrets_version=get_detect_secrets_version(),
            available_plugin_names=get_available_plugin_names(),
            default_plugin_names=get_default_plugin_names(),
            configured_runtime=self.config,
        )

    def _get_service(self) -> _RuntimeService:
        service = self._service
        if service is None:
            raise RuntimeScanError(ScanFailureCode.RUNTIME_ERROR, "runtime failed to initialize")
        return service

    def _submit(
        self,
        coroutine_factory: Callable[[], Coroutine[object, object, _T]],
    ) -> concurrent.futures.Future[_T]:
        with self._thread_lock:
            loop = self._loop
            if self._closed or loop is None:
                raise RuntimeScanError(ScanFailureCode.RUNTIME_ERROR, "runtime is shut down")
            coroutine = coroutine_factory()
            try:
                return asyncio.run_coroutine_threadsafe(coroutine, loop)
            except Exception:
                coroutine.close()
                raise

    def _start_loop_thread(self) -> None:
        with self._thread_lock:
            if self._closed:
                raise RuntimeScanError(ScanFailureCode.RUNTIME_ERROR, "runtime is shut down")
            if self._thread is not None and self._thread.is_alive():
                return

            self._started.clear()
            self._startup_error = None
            thread = threading.Thread(
                target=self._thread_main,
                name="detect-secrets-async-runtime",
                daemon=True,
            )
            self._thread = thread
            thread.start()

        self._started.wait()
        if self._startup_error is not None:
            raise RuntimeScanError(ScanFailureCode.RUNTIME_ERROR) from self._startup_error

    def _thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        service: _RuntimeService | None = None
        asyncio.set_event_loop(loop)
        try:
            service = _RuntimeService(self.config)
            with self._thread_lock:
                self._loop = loop
                self._service = service
            self._started.set()
            loop.run_forever()
        except BaseException as exc:  # pragma: no cover - startup failures are hard to force safely
            self._startup_error = exc
            self._started.set()
            raise
        finally:
            service = self._service
            if service is not None:
                service.close_nowait()

            pending_tasks = [task for task in asyncio.all_tasks(loop) if not task.done()]
            for task in pending_tasks:
                task.cancel()
            if pending_tasks:
                loop.run_until_complete(asyncio.gather(*pending_tasks, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    def _clear_thread_state(self) -> None:
        with self._thread_lock:
            self._loop = None
            self._service = None
            self._thread = None


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
        if _SHUTTING_DOWN:
            raise RuntimeScanError(ScanFailureCode.RUNTIME_ERROR, "runtime is shutting down")
        if _CONFIG is None:
            _CONFIG = resolved
        elif resolved != _CONFIG:
            raise RuntimeConfigConflictError(
                "detect-secrets runtime is already configured with different settings"
            )

        if _RUNTIME is None:
            _RUNTIME = DetectSecretsRuntime(_CONFIG)

        return _RUNTIME


def configure_runtime(
    config: RuntimeConfig | None = None,
    *,
    pool_size: int | None = None,
    max_queue_depth: int | None = None,
    max_requests_per_worker: int | None = None,
) -> RuntimeConfig:
    """Configure or confirm host-level runtime settings for the shared runtime."""

    resolved = resolve_runtime_config(
        config,
        pool_size=pool_size,
        max_queue_depth=max_queue_depth,
        max_requests_per_worker=max_requests_per_worker,
    )
    global _CONFIG
    with _RUNTIME_LOCK:
        if _SHUTTING_DOWN:
            raise RuntimeScanError(ScanFailureCode.RUNTIME_ERROR, "runtime is shutting down")
        if _CONFIG is None:
            _CONFIG = resolved
        elif resolved != _CONFIG:
            raise RuntimeConfigConflictError(
                "detect-secrets runtime is already configured with different settings"
            )
        return _CONFIG


async def shutdown_runtime() -> None:
    """Shutdown and clear the shared runtime instance."""

    global _CONFIG, _RUNTIME, _SHUTTING_DOWN
    with _RUNTIME_LOCK:
        runtime = _RUNTIME
        _SHUTTING_DOWN = runtime is not None

    shutdown_succeeded = runtime is None
    try:
        if runtime is not None:
            await runtime.shutdown()
            shutdown_succeeded = True
    finally:
        with _RUNTIME_LOCK:
            if shutdown_succeeded and _RUNTIME is runtime:
                _RUNTIME = None
                _CONFIG = None
                _SHUTTING_DOWN = False
            elif runtime is None:
                _SHUTTING_DOWN = False


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
        # atexit is synchronous, so interpreter shutdown falls back to best-effort child cleanup.
        runtime._close_nowait()


def _clear_global_runtime_reference(runtime: DetectSecretsRuntime) -> None:
    global _CONFIG, _RUNTIME, _SHUTTING_DOWN
    with _RUNTIME_LOCK:
        if _RUNTIME is runtime:
            _RUNTIME = None
            _CONFIG = None
            _SHUTTING_DOWN = False


def _mark_global_runtime_shutting_down(runtime: DetectSecretsRuntime) -> None:
    global _SHUTTING_DOWN
    with _RUNTIME_LOCK:
        if _RUNTIME is runtime:
            _SHUTTING_DOWN = True


atexit.register(_cleanup_runtime_at_exit)
