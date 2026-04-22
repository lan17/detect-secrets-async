# detect-secrets-async

[![CI](https://github.com/lan17/detect-secrets-async/actions/workflows/ci.yml/badge.svg)](https://github.com/lan17/detect-secrets-async/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/lan17/detect-secrets-async/branch/main/graph/badge.svg)](https://codecov.io/gh/lan17/detect-secrets-async)
[![PyPI version](https://img.shields.io/pypi/v/detect-secrets-async.svg)](https://pypi.org/project/detect-secrets-async/)
[![Python versions](https://img.shields.io/pypi/pyversions/detect-secrets-async.svg)](https://pypi.org/project/detect-secrets-async/)
[![License](https://img.shields.io/github/license/lan17/detect-secrets-async.svg)](https://github.com/lan17/detect-secrets-async/blob/main/LICENSE)

`detect-secrets-async` is a standalone async runtime for [Yelp detect-secrets](https://github.com/Yelp/detect-secrets).
It wraps the synchronous Python API in a bounded pool of long-lived subprocess workers so hosts can
run text scans with real timeouts and isolated per-request settings.

The package is intentionally generic. It does not know anything about Agent Control, evaluator
result mapping, payload normalization, or JSON Pointer metadata.

Internally, the shared runtime owns one dedicated background event-loop thread per host process plus
up to `pool_size` worker subprocesses. That extra thread is what lets the runtime stay safe across
multiple caller event loops while keeping worker orchestration centralized.

## Scope

V1 supports:

- text/content scanning only
- per-request plugin selection
- host-level runtime settings for pool size, queue depth, and worker recycling
- one in-flight request per worker
- real timeout behavior across queue wait, worker startup, scan execution, and response read
- worker replacement on timeout, crash, protocol failure, and caller cancellation

V1 does not support:

- repository or directory scanning
- baselines or diff mode
- verification
- arbitrary plugin or filter imports

## Installation

```bash
uv add detect-secrets-async
```

The package pins `detect-secrets==1.5.0` to keep the default plugin set stable.

## Quick Start

```python
import asyncio

from detect_secrets_async import ScanRequest, get_runtime


async def main() -> None:
    runtime = get_runtime()
    result = await runtime.scan(
        ScanRequest(
            content="github_token = 'ghp_123456789012345678901234567890123456'",
            timeout_ms=5_000,
        )
    )
    print(result.findings)


asyncio.run(main())
```

## Runtime Configuration

Runtime settings are host-level and use first-init-wins semantics. Configure them before the first
scan with `configure_runtime(...)` or `get_runtime(...)`, or through environment variables:

- `DETECT_SECRETS_ASYNC_POOL_SIZE` (default `4`)
- `DETECT_SECRETS_ASYNC_MAX_QUEUE_DEPTH` (default `16`)
- `DETECT_SECRETS_ASYNC_MAX_REQUESTS_PER_WORKER` (default `100`)

Conflicting re-initialization raises `RuntimeConfigConflictError`.
Same-config calls are allowed and return or confirm the existing runtime settings.

```python
from detect_secrets_async import RuntimeConfig, configure_runtime

configure_runtime(RuntimeConfig(pool_size=8, max_queue_depth=32, max_requests_per_worker=200))
```

`max_queue_depth=0` is valid and disables queueing beyond currently idle workers.

## Lifecycle Helpers

- `get_runtime(...)`: return the shared runtime, creating it on first access
- `configure_runtime(...)`: pin or confirm host-level settings
- `shutdown_runtime()`: async teardown for tests and long-lived hosts
- `reset_runtime_for_tests()`: async reset helper
- `get_runtime_info()`: package version, pinned `detect-secrets` version, and plugin metadata

## Request and Result Types

```python
from detect_secrets_async import ScanConfig, ScanRequest

request = ScanRequest(
    content="api_key = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDE='",
    timeout_ms=10_000,
    config=ScanConfig(enabled_plugins=("Base64HighEntropyString",)),
)
```

Results contain only safe metadata:

- `findings[].type`
- `findings[].line_number`
- `detect_secrets_version`

The runtime never returns plaintext secret values, snippets, or `hashed_secret`.

## Failures

Runtime failures raise `RuntimeScanError` with a safe `code`:

- `invalid_config`
- `queue_full`
- `queue_timeout`
- `worker_startup_error`
- `worker_timeout`
- `worker_crash`
- `worker_protocol_error`
- `runtime_error`

## Operational Notes

- Workers start lazily. The first scan in a process pays cold-start cost for worker creation and
  `detect-secrets` import.
- If a host uses runtime introspection to validate plugin names ahead of scans, `detect-secrets`
  must be importable in that validating process, not only inside a worker child.

### Tuning

- Repeated `queue_full`: raise `pool_size`, raise `max_queue_depth`, or reduce caller burstiness.
- Repeated `queue_timeout`: raise `timeout_ms` or add worker/queue capacity.
- Repeated `worker_timeout`: raise `timeout_ms`, narrow `enabled_plugins`, or reduce payload size.
- Repeated `worker_startup_error`: verify the host can import both `detect_secrets_async` and
  `detect-secrets`, and check Python environment consistency.

## Benchmarking and Soak Runs

Runtime defaults are intentionally conservative and should be re-checked on representative host
hardware before changing them.

```bash
make benchmark
make soak
```

Useful overrides:

- `make benchmark BENCHMARK_ARGS="--pool-sizes 1 2 4 8 --pool-suite-requests 64"`
- `make soak SOAK_ARGS="--duration-seconds 60 --max-requests-per-worker 5 --client-count 12"`

`make benchmark` compares throughput and latency across pool sizes and recycle thresholds.
`make soak` runs a sustained, non-CI stress pass that forces worker recycling and asserts that
request bookkeeping and child processes drain cleanly on shutdown.

## Development

```bash
make sync
make check
```

Available commands:

- `make lint`
- `make typecheck`
- `make test`
- `make build`
- `make check`
- `make benchmark`
- `make soak`

## License

Apache-2.0
