# detect-secrets-async

[![CI](https://github.com/lan17/detect-secrets-async/actions/workflows/ci.yml/badge.svg)](https://github.com/lan17/detect-secrets-async/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/lan17/detect-secrets-async/branch/main/graph/badge.svg)](https://codecov.io/gh/lan17/detect-secrets-async)
[![PyPI version](https://img.shields.io/pypi/v/detect-secrets-async.svg)](https://pypi.org/project/detect-secrets-async/)
[![Python versions](https://img.shields.io/pypi/pyversions/detect-secrets-async.svg)](https://pypi.org/project/detect-secrets-async/)
[![License](https://img.shields.io/github/license/lan17/detect-secrets-async.svg)](https://github.com/lan17/detect-secrets-async/blob/main/LICENSE)

Async runtime for [Yelp detect-secrets](https://github.com/Yelp/detect-secrets). Wraps the
synchronous scanner in a bounded pool of long-lived subprocess workers so hosts can run secret
scans with real timeouts, isolated per-request plugin configuration, and cross-request
concurrency.

The package is intentionally generic — it has no knowledge of Agent Control, evaluator result
mapping, payload normalization, or JSON Pointer metadata.

## Install

```bash
uv add detect-secrets-async
```

`detect-secrets==1.5.0` is pinned so the default plugin set stays stable across upgrades.

## Quick start

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
    for finding in result.findings:
        print(finding.type, finding.line_number)


asyncio.run(main())
```

## How it works

One shared runtime per host process. It owns:

- a dedicated background event-loop thread that orchestrates all workers
- up to `pool_size` `detect-secrets` subprocesses, each handling one request at a time
- a bounded FIFO queue for bursts above `pool_size`

Callers from any event loop or thread can `await runtime.scan(...)` concurrently. The runtime
queues, dispatches, and replaces workers on timeout, crash, protocol failure, or caller
cancellation.

> Subprocess isolation is the reason you want this library. Upstream `detect-secrets` is
> synchronous and configures itself through process-global settings, so `asyncio.to_thread` gives
> you theatrical timeouts (the scan keeps running) and state bleed between concurrent configs. A
> serializing lock kills throughput. Subprocesses solve both.

## Scope (v1)

**Supported**
- text/content scanning with per-request plugin selection
- real timeouts across queue wait, worker startup, scan execution, and response read
- automatic worker replacement on timeout, crash, protocol failure, or caller cancellation
- host-level pool size, queue depth, and worker recycling

**Not supported**
- repository or directory scanning
- baselines or diff mode
- network-backed secret verification
- arbitrary plugin or filter imports

## Configuration

Runtime settings are **host-level** with **first-init-wins** semantics: one runtime per process,
pinned at first use. Configure it through environment variables or an explicit call before the
first scan.

| Env var | Default | Field |
|---|---|---|
| `DETECT_SECRETS_ASYNC_POOL_SIZE` | `4` | `pool_size` |
| `DETECT_SECRETS_ASYNC_MAX_QUEUE_DEPTH` | `16` | `max_queue_depth` |
| `DETECT_SECRETS_ASYNC_MAX_REQUESTS_PER_WORKER` | `100` | `max_requests_per_worker` |

```python
from detect_secrets_async import RuntimeConfig, configure_runtime

configure_runtime(RuntimeConfig(pool_size=8, max_queue_depth=32, max_requests_per_worker=200))
```

Re-initializing with the same config is a no-op. Conflicting config raises
`RuntimeConfigConflictError`.

## API reference

### Lifecycle

| Function | Purpose |
|---|---|
| `get_runtime(config=None, **overrides)` | Return the shared runtime, creating it on first call. |
| `configure_runtime(config=None, **overrides)` | Pin (or confirm) settings without starting workers. |
| `shutdown_runtime()` *(async)* | Tear down workers and the background thread. |
| `reset_runtime_for_tests()` *(async)* | Test-fixture alias for `shutdown_runtime`. |
| `get_runtime_info()` | Return `RuntimeInfo` (version + plugin metadata) without running a scan. |

`get_runtime` and `configure_runtime` accept either a `RuntimeConfig` or matching keyword
overrides (`pool_size`, `max_queue_depth`, `max_requests_per_worker`), not both.

### Runtime

`DetectSecretsRuntime` is the object returned by `get_runtime()`.

| Method | Purpose |
|---|---|
| `scan(request)` *(async)* | Run a pool-backed scan. Returns `ScanResult`, raises `RuntimeScanError`. |
| `shutdown()` *(async)* | Instance-level teardown. |
| `info()` | Same payload as `get_runtime_info()`. |

### Types

```python
class RuntimeConfig:
    pool_size: int = 4                 # worker subprocesses
    max_queue_depth: int = 16          # queued requests when all workers busy (0 disables queueing)
    max_requests_per_worker: int = 100 # recycle worker after N requests

class ScanRequest:
    content: str                       # normalized text to scan (≤ ~16 MB protocol limit)
    timeout_ms: int                    # full lifecycle: queue + startup + scan + read
    config: ScanConfig = ScanConfig()

class ScanConfig:
    enabled_plugins: tuple[str, ...] | None = None   # None → upstream default plugins

class ScanResult:
    findings: tuple[ScanFinding, ...]
    detect_secrets_version: str
    # .findings_count -> int (property)

class ScanFinding:
    type: str                          # detect-secrets secret_type, e.g. "GitHub Token"
    line_number: int | None            # 1-indexed into content; None when unavailable

class RuntimeInfo:
    package_version: str
    detect_secrets_version: str
    available_plugin_names: tuple[str, ...]   # class names, e.g. "GitHubTokenDetector"
    default_plugin_names: tuple[str, ...]     # subset enabled by upstream default_settings()
    configured_runtime: RuntimeConfig | None
```

> **Plugin naming.** `enabled_plugins` takes detect-secrets *class* names
> (`"GitHubTokenDetector"`, `"Base64HighEntropyString"`). The `ScanFinding.type` field reports the
> upstream `secret_type` string instead (`"GitHub Token"`, …). Discover valid class names via
> `get_runtime_info().available_plugin_names`.

### Errors

| Class | When |
|---|---|
| `DetectSecretsAsyncError` | Base class for all package errors. |
| `RuntimeConfigConflictError` | Conflicting runtime re-initialization. |
| `RuntimeScanError(code, message)` | Any scan-time failure. Inspect `.code`. |

`ScanFailureCode` enumerates the safe codes returned in `RuntimeScanError.code`:

| Code | Cause |
|---|---|
| `invalid_config` | e.g. unknown plugin name |
| `queue_full` | `max_queue_depth` reached |
| `queue_timeout` | queue wait exceeded `timeout_ms` |
| `worker_startup_error` | subprocess failed to launch or say hello |
| `worker_timeout` | scan exceeded `timeout_ms` |
| `worker_crash` | subprocess exited unexpectedly |
| `worker_protocol_error` | malformed frame on the subprocess channel |
| `runtime_error` | other sanitized runtime failure |

Raw exception strings, plaintext secrets, snippets, matching lines, and upstream `hashed_secret`
values are never surfaced in results or errors.

## Operational notes

**Cold start.** Workers launch lazily, so the first scan in a process pays subprocess startup plus
`detect-secrets` import. Budget a few hundred milliseconds on the first request, especially in
short-lived SDK processes.

**Cancellation.** Cancelling an `await runtime.scan(...)` kills the assigned worker within a
bounded cleanup budget (~2 seconds) and replaces it — no silent background work.

**Thread-safety.** `scan()` is safe to call from any event loop or thread. All subprocess I/O
happens on one dedicated background loop inside the runtime, regardless of the caller's loop.

**Plugin-name validation.** If you validate plugin names before submitting (for example in an
evaluator adapter), `detect-secrets` must be importable in the validating process — not only in
the worker subprocesses.

**Deployment footprint.** Each host process gets one background thread plus up to `pool_size`
`detect-secrets` subprocesses. A gunicorn/uvicorn deployment with *N* application workers will
have *N × pool_size* `detect-secrets` children in total.

### Tuning

| Repeated failure | Try |
|---|---|
| `queue_full` | raise `pool_size`, raise `max_queue_depth`, or smooth caller bursts |
| `queue_timeout` | raise `timeout_ms` or add worker/queue capacity |
| `worker_timeout` | raise `timeout_ms`, narrow `enabled_plugins`, or shrink payloads |
| `worker_startup_error` | verify `detect_secrets_async` and `detect-secrets` are installed in the caller's Python environment |

## Benchmarking and soak runs

Defaults are conservative. Re-check them on representative hardware before raising them.

```bash
make benchmark
make soak
```

Useful overrides:

- `make benchmark BENCHMARK_ARGS="--pool-sizes 1 2 4 8 --pool-suite-requests 64"`
- `make soak SOAK_ARGS="--duration-seconds 60 --max-requests-per-worker 5 --client-count 12"`

`make benchmark` sweeps pool size and recycle threshold and reports throughput plus p50/p95
latency. `make soak` runs a sustained non-CI stress pass that forces worker recycling and asserts
request bookkeeping and child processes drain cleanly on shutdown.

## Development

```bash
make sync     # install dev deps
make check    # lint + typecheck + test + build
```

Individual targets: `make lint`, `make typecheck`, `make test`, `make build`, `make benchmark`,
`make soak`.

## License

Apache-2.0
