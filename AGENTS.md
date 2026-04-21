# detect-secrets-async agent instructions

## Workflow

- Use the existing `make` targets for common validation work: `make sync`, `make lint`,
  `make typecheck`, `make test`, and `make build`.
- Keep this package runtime-generic. Do not add Agent Control-specific normalization, mapping, or
  evaluator semantics here.

## Testing style

- Write tests in behavioral style.
- Every test must include explicit `# GIVEN`, `# WHEN`, and `# THEN` comments.
- Prefer assertions on externally visible behavior and safe failure codes.
- Reach into internals only when the behavior under test is lifecycle/process management that the
  public API does not expose directly.
