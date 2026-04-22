from __future__ import annotations

import pytest
from detect_secrets.settings import default_settings

from detect_secrets_async import RuntimeScanError, ScanConfig, ScanFailureCode
from detect_secrets_async._detect_secrets import get_default_plugin_names, scan_content


def test_default_plugin_names_match_upstream_default_settings() -> None:
    # Given: the pinned upstream detect-secrets default settings
    with default_settings() as settings:
        upstream_default_plugin_names = tuple(sorted(settings.plugins))

    # When: the runtime reports its default plugin names
    runtime_default_plugin_names = get_default_plugin_names()

    # Then: the runtime matches the upstream default plugin set exactly
    assert runtime_default_plugin_names == upstream_default_plugin_names


def test_scan_content_rejects_unknown_plugin_names() -> None:
    # Given: a scan config that names a plugin not shipped by the pinned detect-secrets build
    scan_config = ScanConfig(enabled_plugins=("NoSuchPlugin",))

    # When: the runtime utility builds settings for the scan
    with pytest.raises(RuntimeScanError) as exc_info:
        scan_content("secret = 'value'", scan_config)

    # Then: it fails with a safe invalid-config error
    assert exc_info.value.code == ScanFailureCode.INVALID_CONFIG


def test_scan_content_preserves_line_numbers_with_explicit_plugin_selection() -> None:
    # Given: multiline content with a GitHub token only on the third line
    content = "\n".join(
        [
            "first line",
            "second line",
            "github_token = 'ghp_123456789012345678901234567890123456'",
        ]
    )
    scan_config = ScanConfig(enabled_plugins=("GitHubTokenDetector",))

    # When: the content is scanned directly through the detect-secrets helper
    findings = scan_content(content, scan_config)

    # Then: the helper returns only the requested detector result with the original line number
    assert [finding.type for finding in findings] == ["GitHub Token"]
    assert [finding.line_number for finding in findings] == [3]
