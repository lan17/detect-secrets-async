# Contributing

## Development setup

1. Install `uv`.
2. Run `make sync`.
3. Run `make check` before opening a pull request.

## Commit and PR conventions

- Use Conventional Commits for merge commits or squash-merge PR titles, for example `feat: add async scanner`.
- Keep packaging, release, and CI changes separated from runtime behavior changes where possible.

## Release model

- Pushes to `main` run semantic-release.
- semantic-release computes the next version from Conventional Commits, creates the tag and GitHub release, and uploads built artifacts to PyPI through GitHub Actions trusted publishing.

