.PHONY: sync lint lint-fix typecheck test build check benchmark soak

sync:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

lint-fix:
	uv run ruff check --fix .
	uv run ruff format .

typecheck:
	uv run mypy .

test:
	uv run pytest --cov=detect_secrets_async --cov-report=term-missing

build:
	uv build --no-sources

check: lint typecheck test build

benchmark:
	uv run python scripts/benchmark_runtime.py $(BENCHMARK_ARGS)

soak:
	uv run python scripts/soak_runtime.py $(SOAK_ARGS)
