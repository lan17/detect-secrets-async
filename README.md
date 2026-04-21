# detect-secrets-async

`detect-secrets-async` is a standalone async runtime for [Yelp detect-secrets](https://github.com/Yelp/detect-secrets).
It wraps the synchronous Python API in a bounded pool of long-lived subprocess workers so hosts can
run text scans with real timeouts and isolated per-request settings.

The package is intentionally generic. It does not know anything about Agent Control, evaluator
result mapping, payload normalization, or JSON Pointer metadata.

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

```python
from detect_secrets_async import RuntimeConfig, configure_runtime

configure_runtime(RuntimeConfig(pool_size=8, max_queue_depth=32, max_requests_per_worker=200))
```

## Lifecycle Helpers

- `get_runtime(...)` / `init_runtime(...)`: return the shared runtime
- `configure_runtime(...)`: pin host-level settings before first use
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

## License

Apache-2.0
