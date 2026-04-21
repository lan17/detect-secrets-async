# detect-secrets-async

Async-first packaging and automation scaffold for integrating `detect-secrets` into service-oriented workflows.

This repository is intentionally at bootstrap stage. The package, tests, CI, and release automation are in place; runtime functionality will land in follow-up PRs.

## Status

- Package name: `detect-secrets-async`
- Import name: `detect_secrets_async`
- Python support: 3.11+
- Build backend: `uv_build`
- Release automation: `python-semantic-release` + GitHub Actions + PyPI trusted publishing

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

## Packaging

The project uses a standard `src/` layout and is ready to build with:

```bash
make build
```

Artifacts are written to `dist/`.

## Releases

Releases are driven by Conventional Commits on `main`.

When a qualifying change lands on `main`, the release workflow will:

1. compute the next semantic version,
2. update the package version and `uv.lock`,
3. create a git tag and GitHub release,
4. build the distribution artifacts, and
5. publish to PyPI through trusted publishing.

Before the first release, configure a PyPI trusted publisher for:

- repository: `lan17/detect-secrets-async`
- workflow: `.github/workflows/release.yml`
- environment: `pypi`

## License

Apache-2.0
