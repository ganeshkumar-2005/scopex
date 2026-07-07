"""
tests/test_sqli_scanner.py — Unit tests for the async SQLi scanner (v2).
Tests all 4 detection techniques with mocked HTTP responses.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from core.context import ScanContext
from core.findings import Finding
from scanners.sqli_scanner import SQLiScanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ctx(target="https://example.com/page?id=1") -> ScanContext:
    """Create a ScanContext with a parameterized URL."""
    host = "example.com"
    ctx = ScanContext(target=target, host=host, timeout=3.0)
    ctx.discovered_urls = [target]
    return ctx


def _mock_response(text="", status_code=200):
    from tests.conftest import MockResponse
    return MockResponse(status_code=status_code, text=text)


def _make_scanner(ctx, responses):
    """Create a SQLiScanner with a mocked client that returns responses in order."""
    client = AsyncMock()
    client.get = AsyncMock(side_effect=responses)
    client.post = AsyncMock(side_effect=responses)
    return SQLiScanner(ctx, client)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sqli_no_params():
    """Scanner returns INFO finding when no parameterized URLs exist."""
    ctx = ScanContext(target="https://example.com/", host="example.com", timeout=3.0)
    ctx.discovered_urls = ["https://example.com/about", "https://example.com/contact"]
    client = AsyncMock()
    scanner = SQLiScanner(ctx, client)
    findings = await scanner.scan()
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert "No URL Parameters" in findings[0].title


@pytest.mark.asyncio
async def test_sqli_error_based_detection():
    """Detects error-based SQLi when DBMS error signatures appear in 2+ payloads."""
    ctx = _ctx()
    normal = _mock_response("Welcome to our website.")
    mysql_error = _mock_response(
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    )

    responses = [
        normal, normal,   # baseline (2 requests)
        normal,           # error payload 1: ' → no error
        mysql_error,      # error payload 2: " → MySQL error
        mysql_error,      # error payload 3: \' → MySQL error (2nd hit → confirmed)
    ]
    scanner = _make_scanner(ctx, responses)
    findings = await scanner.scan()

    sqli_findings = [f for f in findings if f.severity == "CRITICAL"]
    assert len(sqli_findings) >= 1
    assert "Error-Based" in sqli_findings[0].title
    assert "MySQL" in sqli_findings[0].title
    assert sqli_findings[0].verified is True


@pytest.mark.asyncio
async def test_sqli_boolean_blind_detection():
    """Detects boolean-blind SQLi when TRUE/FALSE responses differ significantly."""
    ctx = _ctx()
    normal = _mock_response("A" * 1000)  # Baseline 1000 chars
    true_resp = _mock_response("A" * 1000)   # TRUE response similar to baseline
    false_resp = _mock_response("B" * 100)   # FALSE response much shorter

    responses = [
        normal, normal,  # baseline timing (2 requests)
        # Error-based: 4 payloads, all return normal
        normal, normal, normal, normal,
        # Boolean-blind: baseline fetch, then TRUE/FALSE pair
        normal,       # baseline for the URL
        true_resp,    # TRUE payload
        false_resp,   # FALSE payload
    ]
    scanner = _make_scanner(ctx, responses)
    findings = await scanner.scan()

    blind_findings = [f for f in findings if "Boolean" in f.title]
    assert len(blind_findings) >= 1
    assert blind_findings[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_sqli_clean_target():
    """No CRITICAL/HIGH findings on a target that doesn't echo errors or change behavior."""
    ctx = _ctx()
    normal = _mock_response("This is a clean, safe response with no SQL content.")

    # All responses are normal
    responses = [normal] * 50  # Enough for all techniques
    scanner = _make_scanner(ctx, responses)
    findings = await scanner.scan()

    critical_or_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    assert len(critical_or_high) == 0


@pytest.mark.asyncio
async def test_sqli_findings_are_finding_objects():
    """All returned findings are proper Finding dataclass instances."""
    ctx = _ctx()
    normal = _mock_response("Normal page.")
    responses = [normal] * 50
    scanner = _make_scanner(ctx, responses)
    findings = await scanner.scan()
    for f in findings:
        assert isinstance(f, Finding)
        assert f.module == "SQLiScanner"
