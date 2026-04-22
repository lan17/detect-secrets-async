from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest

from detect_secrets_async import reset_runtime_for_tests


@pytest.fixture(autouse=True)
async def reset_runtime_fixture() -> AsyncGenerator[None, None]:
    await reset_runtime_for_tests()
    yield
    await reset_runtime_for_tests()
