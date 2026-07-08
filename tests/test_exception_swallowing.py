"""
tests/test_exception_swallowing.py — Unit tests for exception tracking and logging.
"""
from __future__ import annotations

import asyncio
import pytest
from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner
from plugins.base_plugin import BasePlugin
from plugins import PLUGIN_REGISTRY

class DummyExceptionScanner(BaseScanner):
    """A dummy scanner that raises exceptions and records them using self.add_error."""
    async def scan(self):
        try:
            raise ValueError("Test value error in scanner")
        except ValueError as e:
            self.add_error("DummyValueCheck", e)
        
        try:
            raise RuntimeError("Test runtime error in scanner")
        except RuntimeError as e:
            self.add_error("DummyRuntimeCheck", e)
        return []

class DummyExceptionPlugin(BasePlugin):
    """A dummy plugin that raises exceptions and records them using self.add_error."""
    PLUGIN_ID = "9997"
    PLUGIN_NAME = "Dummy Exception Plugin"
    PLUGIN_FAMILY = "Test"
    PLUGIN_SHORT_KEY = "dummy_exception"

    def run(self, progress_callback=None):
        try:
            raise ValueError("Test value error in plugin")
        except ValueError as e:
            self.add_error("DummyPluginValueCheck", e)
        return self.get_results()

@pytest.mark.asyncio
async def test_scanner_exception_tracking():
    ctx = ScanContext(target="https://example.com", host="example.com", timeout=3.0)
    scanner = DummyExceptionScanner(ctx, None)
    await scanner.scan()

    assert len(ctx.scan_errors) == 2
    err1 = ctx.scan_errors[0]
    assert err1[0] == "DummyValueCheck"
    assert "Test value error in scanner" in err1[2]
    assert err1[1] == "https://example.com"

    err2 = ctx.scan_errors[1]
    assert err2[0] == "DummyRuntimeCheck"
    assert "Test runtime error in scanner" in err2[2]

@pytest.mark.asyncio
async def test_plugin_isolated_exception_tracking():
    # Register the plugin temporarily
    PLUGIN_REGISTRY["dummy_exception"] = {
        "class": DummyExceptionPlugin,
        "name": DummyExceptionPlugin.PLUGIN_NAME,
        "description": "Dummy exception",
        "family": DummyExceptionPlugin.PLUGIN_FAMILY,
    }

    try:
        ctx = ScanContext(target="https://example.com", host="example.com", timeout=3.0)
        plugin = DummyExceptionPlugin("https://example.com")
        await plugin.run_isolated(ctx=ctx, timeout=10.0)

        # The errors list from the isolated process should be transferred to ctx.scan_errors
        assert len(ctx.scan_errors) == 1
        err = ctx.scan_errors[0]
        assert err[0] == "DummyPluginValueCheck"
        assert "Test value error in plugin" in err[2]
        assert err[1] == "https://example.com"
    finally:
        PLUGIN_REGISTRY.pop("dummy_exception", None)
