"""
Unit tests for plugin isolation and dynamic discovery system (Phase 5).
"""
import asyncio
import json
import pytest
from unittest.mock import patch, MagicMock
from core.findings import Finding
from plugins import discover_plugins, PLUGIN_REGISTRY, get_plugin, list_plugins
from plugins.base_plugin import BasePlugin


# Module-level definition of mock plugins for subprocess compatibility
class SlowPlugin(BasePlugin):
    PLUGIN_ID = "9999"
    PLUGIN_NAME = "Slow Test Plugin"
    PLUGIN_FAMILY = "Test"
    PLUGIN_SHORT_KEY = "slow_test"
    
    def run(self, progress_callback=None):
        import time
        time.sleep(5)
        return self.get_results()


class NoisyPlugin(BasePlugin):
    PLUGIN_ID = "9998"
    PLUGIN_NAME = "Noisy Test Plugin"
    PLUGIN_FAMILY = "Test"
    PLUGIN_SHORT_KEY = "noisy_test"
    
    def run(self, progress_callback=None):
        print("SOME RANDOM PRINT OUT OF SPEC")
        self.add_finding("Noisy Finding", "INFO", "Desc", evidence="proof")
        return self.get_results()


def test_dynamic_plugin_discovery():
    discover_plugins()
    # Check that all 7 built-in plugins are registered under their short keys
    expected_keys = {"ssl", "services", "cms", "network", "compliance", "takeover", "ssrf"}
    assert expected_keys.issubset(PLUGIN_REGISTRY.keys())

    # Check list_plugins structure
    plugins_list = list_plugins()
    assert len(plugins_list) >= 7
    keys_in_list = {p["id"] for p in plugins_list}
    assert expected_keys.issubset(keys_in_list)


def test_get_plugin():
    plugin = get_plugin("compliance", "https://example.com", timeout=10.0)
    assert plugin.PLUGIN_SHORT_KEY == "compliance"
    assert plugin.url == "https://example.com"
    assert plugin.timeout == 10.0


@pytest.mark.asyncio
async def test_run_isolated_success():
    # Use CompliancePlugin to verify success execution in subprocess
    plugin = get_plugin("compliance", "https://example.com")
    
    # We pass a simple finding to map and calculate grade
    finding = Finding(
        title="SQL Injection",
        severity="HIGH",
        module="SQLiScanner",
        description="SQL injection vulnerability",
        evidence={"param": "id"},
        remediation="Fix it",
        target="https://example.com",
    )

    findings = await plugin.run_isolated(
        timeout=120.0,
        existing_findings=[finding]
    )

    # CompliancePlugin should return graded compliance findings
    assert len(findings) > 0
    posture_finding = next((f for f in findings if "Posture Rating" in f.title), None)
    assert posture_finding is not None
    assert "GRADE" in posture_finding.title
    assert "Findings summary:" in posture_finding.evidence["raw"]


@pytest.mark.asyncio
async def test_run_isolated_timeout():
    # Register temporarily in registry
    PLUGIN_REGISTRY["slow_test"] = {
        "class": SlowPlugin,
        "name": SlowPlugin.PLUGIN_NAME,
        "description": "Slow test",
        "family": SlowPlugin.PLUGIN_FAMILY
    }

    try:
        plugin = SlowPlugin("https://example.com")
        # Run with a short timeout of 0.5s
        findings = await plugin.run_isolated(timeout=0.5)
        # Should gracefully return empty findings on timeout instead of hanging/raising
        assert findings == []
    finally:
        # Clean up registry
        PLUGIN_REGISTRY.pop("slow_test", None)


@pytest.mark.asyncio
async def test_run_isolated_with_noisy_prints():
    # Register temporarily
    PLUGIN_REGISTRY["noisy_test"] = {
        "class": NoisyPlugin,
        "name": NoisyPlugin.PLUGIN_NAME,
        "description": "Noisy test",
        "family": NoisyPlugin.PLUGIN_FAMILY
    }

    try:
        plugin = NoisyPlugin("https://example.com")
        findings = await plugin.run_isolated(timeout=30.0)
        # Verify that despite noise, the finding is parsed successfully!
        assert len(findings) == 1
        assert findings[0].title == "Noisy Finding"
    finally:
        PLUGIN_REGISTRY.pop("noisy_test", None)
