from __future__ import annotations

import argparse
import asyncio
import logging
import time
from dataclasses import dataclass, field

from detect_secrets_async import RuntimeConfig, ScanRequest, get_runtime, shutdown_runtime
from detect_secrets_async._runtime import _RuntimeService

SECRET_LINE = "github_token = 'ghp_123456789012345678901234567890123456'\n"
FILLER_LINE = "filler = '0123456789abcdefghijklmnopqrstuvwxyz'\n"


@dataclass(slots=True)
class SoakStats:
    completed_requests: int = 0
    failures: list[str] = field(default_factory=list)
    unique_worker_pids: set[int] = field(default_factory=set)
    max_live_workers: int = 0
    max_pending_requests: int = 0
    max_requests_by_id: int = 0


def _build_payload(target_bytes: int) -> str:
    chunks = [SECRET_LINE]
    while len("".join(chunks).encode("utf-8")) < target_bytes:
        chunks.append(FILLER_LINE)
    return "".join(chunks)


def _live_worker_processes(service: _RuntimeService) -> list[asyncio.subprocess.Process]:
    return [
        process
        for slot in service._worker_slots
        for process in [slot.process]
        if process is not None and process.returncode is None
    ]


async def _run_client(
    *,
    runtime_config: RuntimeConfig,
    payload: str,
    timeout_ms: int,
    stop_event: asyncio.Event,
    stats: SoakStats,
) -> None:
    runtime = get_runtime(runtime_config)
    while not stop_event.is_set():
        try:
            await runtime.scan(ScanRequest(content=payload, timeout_ms=timeout_ms))
            stats.completed_requests += 1
        except Exception as exc:  # pragma: no cover - soak failures should stop the run immediately
            stats.failures.append(repr(exc))
            stop_event.set()


async def main() -> None:
    logging.getLogger("detect_secrets_async._runtime").setLevel(logging.ERROR)

    parser = argparse.ArgumentParser(
        description=(
            "Run a sustained detect-secrets-async soak test. "
            "This is a non-CI stress harness for worker recycling and shutdown cleanup."
        )
    )
    parser.add_argument("--duration-seconds", type=int, default=30)
    parser.add_argument("--pool-size", type=int, default=4)
    parser.add_argument("--queue-depth", type=int, default=16)
    parser.add_argument("--max-requests-per-worker", type=int, default=8)
    parser.add_argument("--client-count", type=int, default=8)
    parser.add_argument("--payload-bytes", type=int, default=4 * 1024)
    parser.add_argument("--timeout-ms", type=int, default=10_000)
    parser.add_argument("--sample-interval-ms", type=int, default=200)
    args = parser.parse_args()

    runtime_config = RuntimeConfig(
        pool_size=args.pool_size,
        max_queue_depth=args.queue_depth,
        max_requests_per_worker=args.max_requests_per_worker,
    )
    payload = _build_payload(args.payload_bytes)
    stop_event = asyncio.Event()
    stats = SoakStats()
    runtime = get_runtime(runtime_config)
    service = runtime._service
    assert service is not None

    async def sample_runtime_state() -> None:
        deadline = time.monotonic() + args.duration_seconds
        while time.monotonic() < deadline and not stop_event.is_set():
            live_processes = _live_worker_processes(service)
            stats.unique_worker_pids.update(process.pid for process in live_processes)
            stats.max_live_workers = max(stats.max_live_workers, len(live_processes))
            stats.max_pending_requests = max(
                stats.max_pending_requests,
                len(service._pending_requests),
            )
            stats.max_requests_by_id = max(stats.max_requests_by_id, len(service._requests_by_id))
            await asyncio.sleep(args.sample_interval_ms / 1000)
        stop_event.set()

    clients = [
        asyncio.create_task(
            _run_client(
                runtime_config=runtime_config,
                payload=payload,
                timeout_ms=args.timeout_ms,
                stop_event=stop_event,
                stats=stats,
            )
        )
        for _ in range(args.client_count)
    ]
    sampler = asyncio.create_task(sample_runtime_state())

    try:
        await sampler
        await asyncio.gather(*clients)
        live_processes_before_shutdown = _live_worker_processes(service)
        assert not stats.failures, f"soak run failures: {stats.failures}"
        assert not service._pending_requests, "pending request queue did not drain before shutdown"
        assert not service._requests_by_id, "request bookkeeping did not drain before shutdown"
    finally:
        await shutdown_runtime()

    for process in live_processes_before_shutdown:
        assert process.returncode is not None, "worker process was still alive after shutdown"

    print("detect-secrets-async soak test")
    print(f"completed_requests: {stats.completed_requests}")
    print(f"unique_worker_pids: {len(stats.unique_worker_pids)}")
    print(f"max_live_workers: {stats.max_live_workers}")
    print(f"max_pending_requests: {stats.max_pending_requests}")
    print(f"max_requests_by_id: {stats.max_requests_by_id}")
    print("shutdown_cleanup: ok")


if __name__ == "__main__":
    asyncio.run(main())
