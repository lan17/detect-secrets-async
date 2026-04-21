import importlib
import sys
from importlib import metadata

import pytest

import detect_secrets_async


def test_version_matches_installed_metadata() -> None:
    assert detect_secrets_async.__version__ == metadata.version("detect-secrets-async")


def test_version_falls_back_when_package_metadata_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "detect_secrets_async"
    original_module = sys.modules[module_name]

    def missing_version(_: str) -> str:
        raise metadata.PackageNotFoundError

    monkeypatch.setattr(metadata, "version", missing_version)
    sys.modules.pop(module_name, None)

    try:
        reimported_module = importlib.import_module(module_name)
        assert reimported_module.__version__ == "0.0.0"
    finally:
        sys.modules[module_name] = original_module
