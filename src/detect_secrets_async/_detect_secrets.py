from __future__ import annotations

from contextlib import AbstractContextManager
from functools import lru_cache
from importlib.metadata import version
from typing import Any, cast

from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
from detect_secrets.core.scan import scan_line
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.settings import default_settings, transient_settings

from ._errors import RuntimeScanError, ScanFailureCode
from ._models import ScanConfig, ScanFinding


@lru_cache(maxsize=1)
def get_detect_secrets_version() -> str:
    """Return the installed detect-secrets package version."""

    return version("detect-secrets")


@lru_cache(maxsize=1)
def get_available_plugin_names() -> tuple[str, ...]:
    """Return all installed upstream plugin class names for the pinned version."""

    mapping = cast(dict[str, type[BasePlugin]], get_mapping_from_secret_type_to_class())
    return tuple(sorted(plugin_class.__name__ for plugin_class in mapping.values()))


@lru_cache(maxsize=1)
def get_default_plugin_names() -> tuple[str, ...]:
    """Return the plugin names used by the pinned upstream default settings."""

    with default_settings() as settings:
        return tuple(sorted(settings.plugins))


def _build_plugin_settings(enabled_plugins: tuple[str, ...]) -> dict[str, Any]:
    available = set(get_available_plugin_names())
    unknown = tuple(
        sorted(plugin_name for plugin_name in enabled_plugins if plugin_name not in available)
    )
    if unknown:
        raise RuntimeScanError(
            ScanFailureCode.INVALID_CONFIG,
            "scan config references unknown detect-secrets plugins",
        )

    return {"plugins_used": [{"name": plugin_name} for plugin_name in enabled_plugins]}


def get_scan_settings(scan_config: ScanConfig) -> AbstractContextManager[object]:
    """Return the detect-secrets settings context for a scan request."""

    if scan_config.enabled_plugins is None:
        return default_settings()

    return transient_settings(_build_plugin_settings(scan_config.enabled_plugins))


def scan_content(content: str, scan_config: ScanConfig) -> tuple[ScanFinding, ...]:
    """Run detect-secrets over normalized text content."""

    findings: list[ScanFinding] = []
    with get_scan_settings(scan_config):
        for line_number, line in enumerate(content.splitlines(), start=1):
            for secret in scan_line(line):
                findings.append(ScanFinding(type=secret.type, line_number=line_number))

    return tuple(findings)
