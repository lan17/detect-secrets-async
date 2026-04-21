from __future__ import annotations

import pytest
from pydantic import ValidationError

from detect_secrets_async import RuntimeConfig
from detect_secrets_async._config import resolve_runtime_config
from detect_secrets_async._models import ScanConfig, ScanFinding, ScanResult


def test_resolve_runtime_config_rejects_mixed_override_styles() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        resolve_runtime_config(RuntimeConfig(), pool_size=2)


def test_scan_config_rejects_empty_plugin_names() -> None:
    with pytest.raises(ValidationError, match="plugin names must be non-empty"):
        ScanConfig(enabled_plugins=("AlphaDetector", " "))


def test_scan_result_findings_count_matches_findings() -> None:
    result = ScanResult(
        findings=(
            ScanFinding(type="AlphaDetector", line_number=1),
            ScanFinding(type="BetaDetector", line_number=2),
        ),
        detect_secrets_version="1.0.0",
    )

    assert result.findings_count == 2
