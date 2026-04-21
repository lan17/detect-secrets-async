from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from time import perf_counter

from detect_secrets_async import RuntimeConfig, ScanRequest, get_runtime, shutdown_runtime

SECRET_LINE = "github_token = 'ghp_123456789012345678901234567890123456'\n"
FILLER_LINE = "filler = '0123456789abcdefghijklmnopqrstuvwxyz'\n"
PAYLOAD_SIZES = {
    "small": 256,
    "medium": 4 * 1024,
    "large": 64 * 1024,
}


@dataclass(slots=True)
class ScenarioResult:
    suite: str
    label: str
    payload_bytes: int
    pool_size: int
    concurrency: int
    requests: int
    max_requests_per_worker: int
    elapsed_seconds: float
    throughput_rps: float
    p50_ms: float
    p95_ms: float


def _build_payload(target_bytes: int) -> str:
    chunks = [SECRET_LINE]
    while len("".join(chunks).encode("utf-8")) < target_bytes:
        chunks.append(FILLER_LINE)
    return "".join(chunks)


def _percentile(values: Sequence[float], percentile: float) -> float:
    ordered = sorted(values)
    index = round((len(ordered) - 1) * percentile)
    return ordered[index]


async def _run_scenario(
    *,
    suite: str,
    label: str,
    payload: str,
    pool_size: int,
    concurrency: int,
    requests: int,
    max_requests_per_worker: int,
    timeout_ms: int,
) -> ScenarioResult:
    runtime = get_runtime(
        RuntimeConfig(
            pool_size=pool_size,
            max_queue_depth=max(concurrency, 1),
            max_requests_per_worker=max_requests_per_worker,
        )
    )
    semaphore = asyncio.Semaphore(concurrency)
    latencies_ms: list[float] = []

    async def run_one_request() -> None:
        async with semaphore:
            start = perf_counter()
            await runtime.scan(ScanRequest(content=payload, timeout_ms=timeout_ms))
            latencies_ms.append((perf_counter() - start) * 1000)

    start = perf_counter()
    try:
        await asyncio.gather(*(run_one_request() for _ in range(requests)))
    finally:
        await shutdown_runtime()

    elapsed_seconds = perf_counter() - start
    return ScenarioResult(
        suite=suite,
        label=label,
        payload_bytes=len(payload.encode("utf-8")),
        pool_size=pool_size,
        concurrency=concurrency,
        requests=requests,
        max_requests_per_worker=max_requests_per_worker,
        elapsed_seconds=elapsed_seconds,
        throughput_rps=requests / elapsed_seconds,
        p50_ms=_percentile(latencies_ms, 0.50),
        p95_ms=_percentile(latencies_ms, 0.95),
    )


def _print_table(title: str, results: Sequence[ScenarioResult]) -> None:
    print(title)
    print(
        "| label | payload_bytes | pool_size | concurrency | requests | "
        "max_requests_per_worker | elapsed_s | throughput_rps | p50_ms | p95_ms |"
    )
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for result in results:
        print(
            f"| {result.label} | {result.payload_bytes} | {result.pool_size} | "
            f"{result.concurrency} | {result.requests} | {result.max_requests_per_worker} | "
            f"{result.elapsed_seconds:.3f} | {result.throughput_rps:.2f} | "
            f"{result.p50_ms:.2f} | {result.p95_ms:.2f} |"
        )
    print()


async def main() -> None:
    logging.getLogger("detect_secrets_async._runtime").setLevel(logging.ERROR)

    parser = argparse.ArgumentParser(
        description=(
            "Benchmark detect-secrets-async pool-size and recycle-threshold behavior. "
            "Run on representative host hardware before changing runtime defaults."
        )
    )
    parser.add_argument("--pool-sizes", nargs="+", type=int, default=[1, 2, 4, 8])
    parser.add_argument("--pool-suite-requests", type=int, default=48)
    parser.add_argument("--pool-suite-multiplier", type=int, default=2)
    parser.add_argument("--pool-suite-recycle-threshold", type=int, default=1_000)
    parser.add_argument("--recycle-thresholds", nargs="+", type=int, default=[1, 10, 100])
    parser.add_argument("--recycle-cycles", type=int, default=3)
    parser.add_argument("--timeout-ms", type=int, default=10_000)
    args = parser.parse_args()

    pool_results: list[ScenarioResult] = []
    for payload_name, payload_bytes in PAYLOAD_SIZES.items():
        payload = _build_payload(payload_bytes)
        for pool_size in args.pool_sizes:
            concurrency = min(
                args.pool_suite_requests,
                max(pool_size, pool_size * args.pool_suite_multiplier),
            )
            pool_results.append(
                await _run_scenario(
                    suite="pool-size",
                    label=f"{payload_name}/pool={pool_size}",
                    payload=payload,
                    pool_size=pool_size,
                    concurrency=concurrency,
                    requests=args.pool_suite_requests,
                    max_requests_per_worker=args.pool_suite_recycle_threshold,
                    timeout_ms=args.timeout_ms,
                )
            )

    recycle_payload = _build_payload(PAYLOAD_SIZES["medium"])
    recycle_results: list[ScenarioResult] = []
    for threshold in args.recycle_thresholds:
        recycle_results.append(
            await _run_scenario(
                suite="recycling",
                label=f"recycle={threshold}",
                payload=recycle_payload,
                pool_size=1,
                concurrency=1,
                requests=threshold * args.recycle_cycles,
                max_requests_per_worker=threshold,
                timeout_ms=args.timeout_ms,
            )
        )

    print("detect-secrets-async benchmark")
    print(
        "Use these measurements to sanity-check `pool_size=4` and "
        "`max_requests_per_worker=100` on representative host hardware."
    )
    print()
    _print_table("Pool-size benchmark", pool_results)
    _print_table("Worker-recycling benchmark", recycle_results)


if __name__ == "__main__":
    asyncio.run(main())
