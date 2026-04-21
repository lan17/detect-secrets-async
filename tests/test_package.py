from __future__ import annotations

import importlib
import sys
from importlib import metadata

import pytest

import detect_secrets_async


def test_version_matches_installed_metadata() -> None:
    # Given: installed package metadata is available
    expected_version = metadata.version("detect-secrets-async")

    # When: the package exposes its version
    actual_version = detect_secrets_async.__version__

    # Then: it matches the installed distribution metadata
    assert actual_version == expected_version


def test_version_falls_back_when_package_metadata_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: importlib metadata cannot find the installed distribution
    module_name = "detect_secrets_async"
    original_module = sys.modules[module_name]

    def missing_version(_: str) -> str:
        raise metadata.PackageNotFoundError

    monkeypatch.setattr(metadata, "version", missing_version)
    sys.modules.pop(module_name, None)

    try:
        # When: the package is imported again
        reimported_module = importlib.import_module(module_name)

        # Then: it falls back to the bootstrap version string
        assert reimported_module.__version__ == "0.0.0"
    finally:
        sys.modules[module_name] = original_module
