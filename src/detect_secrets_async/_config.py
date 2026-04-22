from __future__ import annotations

import os
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt, PositiveInt

ENV_PREFIX = "DETECT_SECRETS_ASYNC_"


class RuntimeConfig(BaseModel):
    """Host-level runtime settings for the shared subprocess pool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pool_size: PositiveInt = Field(default=4)
    max_queue_depth: NonNegativeInt = Field(default=16)
    max_requests_per_worker: PositiveInt = Field(default=100)

    @classmethod
    def from_env(cls) -> Self:
        """Load runtime settings from environment variables."""

        data: dict[str, Any] = {}
        mappings = {
            "pool_size": f"{ENV_PREFIX}POOL_SIZE",
            "max_queue_depth": f"{ENV_PREFIX}MAX_QUEUE_DEPTH",
            "max_requests_per_worker": f"{ENV_PREFIX}MAX_REQUESTS_PER_WORKER",
        }
        for field_name, env_name in mappings.items():
            raw_value = os.getenv(env_name)
            if raw_value is None:
                continue
            data[field_name] = raw_value

        return cls(**data)


def resolve_runtime_config(
    config: RuntimeConfig | None = None,
    *,
    pool_size: int | None = None,
    max_queue_depth: int | None = None,
    max_requests_per_worker: int | None = None,
) -> RuntimeConfig:
    """Resolve runtime settings from explicit values or the environment."""

    if config is not None and any(
        value is not None for value in (pool_size, max_queue_depth, max_requests_per_worker)
    ):
        raise ValueError("runtime config and explicit override arguments are mutually exclusive")

    if config is not None:
        return config

    base = RuntimeConfig.from_env()
    updates = {
        key: value
        for key, value in {
            "pool_size": pool_size,
            "max_queue_depth": max_queue_depth,
            "max_requests_per_worker": max_requests_per_worker,
        }.items()
        if value is not None
    }
    if not updates:
        return base

    return RuntimeConfig.model_validate({**base.model_dump(), **updates})
