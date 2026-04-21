# Contributing

## Development setup

1. Install `uv`.
2. Run `make sync`.
3. Run `make check` before opening a pull request.

## CI coverage

- GitHub Actions uploads `coverage.xml` from the Python 3.11 test job to Codecov to avoid duplicate reports from the full test matrix.
- Maintainers need to connect the repository in Codecov and install the Codecov GitHub App so uploads surface as PR statuses and comments. The current workflow uses OIDC, so it does not require a `CODECOV_TOKEN` secret.

## Commit and PR conventions

- Use Conventional Commits for merge commits or squash-merge PR titles, for example `feat: add async scanner`.
- Keep packaging, release, and CI changes separated from runtime behavior changes where possible.

## Release model

- Pushes to `main` run semantic-release.
- semantic-release computes the next version from Conventional Commits, creates the tag and GitHub release, and uploads built artifacts to PyPI through GitHub Actions trusted publishing.
