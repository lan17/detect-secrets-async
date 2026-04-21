from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager

import pytest

import detect_secrets_async._detect_secrets as detect_secrets_module
from detect_secrets_async import ScanConfig
from detect_secrets_async._errors import RuntimeScanError, ScanFailureCode


class _FakeSecret:
    def __init__(self, secret_type: str) -> None:
        self.type = secret_type


@contextmanager
def _tracking_context(events: list[str]) -> Iterator[None]:
    events.append("enter")
    try:
        yield
    finally:
        events.append("exit")


def test_build_plugin_settings_returns_requested_plugins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        detect_secrets_module,
        "get_available_plugin_names",
        lambda: ("AlphaDetector", "BetaDetector"),
    )

    settings = detect_secrets_module._build_plugin_settings(("BetaDetector",))

    assert settings == {"plugins_used": [{"name": "BetaDetector"}]}


def test_build_plugin_settings_rejects_unknown_plugins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        detect_secrets_module,
        "get_available_plugin_names",
        lambda: ("AlphaDetector",),
    )

    with pytest.raises(RuntimeScanError) as exc_info:
        detect_secrets_module._build_plugin_settings(("MissingDetector",))

    assert exc_info.value.code == ScanFailureCode.INVALID_CONFIG


def test_get_scan_settings_uses_default_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def fake_default_settings() -> AbstractContextManager[object]:
        return _tracking_context(events)

    monkeypatch.setattr(detect_secrets_module, "default_settings", fake_default_settings)

    with detect_secrets_module.get_scan_settings(ScanConfig()):
        pass

    assert events == ["enter", "exit"]


def test_get_scan_settings_uses_transient_settings_for_enabled_plugins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    observed_settings: dict[str, object] = {}

    def fake_transient_settings(settings: dict[str, object]) -> AbstractContextManager[object]:
        observed_settings["value"] = settings
        return _tracking_context(events)

    monkeypatch.setattr(
        detect_secrets_module,
        "_build_plugin_settings",
        lambda enabled_plugins: {"plugins_used": [{"name": enabled_plugins[0]}]},
    )
    monkeypatch.setattr(detect_secrets_module, "transient_settings", fake_transient_settings)

    with detect_secrets_module.get_scan_settings(ScanConfig(enabled_plugins=("AlphaDetector",))):
        pass

    assert observed_settings["value"] == {"plugins_used": [{"name": "AlphaDetector"}]}
    assert events == ["enter", "exit"]


def test_scan_content_collects_findings_with_line_numbers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def fake_get_scan_settings(_: ScanConfig) -> AbstractContextManager[object]:
        return _tracking_context(events)

    def fake_scan_line(line: str) -> list[_FakeSecret]:
        if line == "first":
            return [_FakeSecret("FirstDetector")]
        if line == "third":
            return [_FakeSecret("ThirdDetector"), _FakeSecret("OtherDetector")]
        return []

    monkeypatch.setattr(detect_secrets_module, "get_scan_settings", fake_get_scan_settings)
    monkeypatch.setattr(detect_secrets_module, "scan_line", fake_scan_line)

    findings = detect_secrets_module.scan_content("first\nsecond\nthird", ScanConfig())

    assert [(finding.type, finding.line_number) for finding in findings] == [
        ("FirstDetector", 1),
        ("ThirdDetector", 3),
        ("OtherDetector", 3),
    ]
    assert events == ["enter", "exit"]
