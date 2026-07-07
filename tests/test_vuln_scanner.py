"""
tests/test_vuln_scanner.py — Unit tests for the async VulnScanner (v2).

Strategy: VulnScanner makes many sequential requests (baseline, canary 404,
CORS probes, redirect probes, file probes, method check, CRLF, host header,
security.txt …). We use URL/header-aware callable side effects instead of
positional side_effect lists so the mock never runs dry.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from core.context import ScanContext
from core.findings import Finding
from scanners.vuln_scanner import VulnScanner
from tests.conftest import MockResponse


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _ok(text: str = "<html></html>", headers: dict | None = None) -> MockResponse:
    return MockResponse(status_code=200, text=text, headers=headers or {})


def _not_found(text: str = "Not Found") -> MockResponse:
    return MockResponse(status_code=404, text=text)


def _make_client(side_effect_fn) -> AsyncMock:
    """Return a mock AsyncClient whose .get() delegates to *side_effect_fn*."""
    client = AsyncMock()
    client.get = AsyncMock(side_effect=side_effect_fn)
    client.request = AsyncMock(return_value=_not_found())
    return client


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def default_context():
    return ScanContext(target="https://example.com", host="example.com", timeout=1.0)


# ---------------------------------------------------------------------------
# CORS wildcard test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vuln_scanner_cors_wildcard(default_context):
    """Wildcard CORS header (Access-Control-Allow-Origin: *) should be reported as LOW."""

    async def _get(url, **kwargs):
        headers_sent = kwargs.get("headers", {})
        origin = headers_sent.get("Origin", "")
        # CORS probe with evil.com origin → return wildcard header
        if origin == "https://evil.com":
            return _ok(headers={"Access-Control-Allow-Origin": "*"})
        # Canary 404 probe
        if "does-not-exist" in url:
            return _not_found()
        # All other requests: plain 200
        return _ok()

    client = _make_client(_get)
    scanner = VulnScanner(default_context, client)
    findings = await scanner.scan()

    cors_findings = [f for f in findings if "CORS" in f.title]
    assert len(cors_findings) >= 1, f"Expected CORS finding, got: {[f.title for f in findings]}"
    assert cors_findings[0].severity == "LOW"
    assert "*" in cors_findings[0].description


# ---------------------------------------------------------------------------
# CORS origin reflection with credentials
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vuln_scanner_cors_reflection_with_credentials(default_context):
    """Reflected origin + Allow-Credentials: true should be reported as HIGH."""

    async def _get(url, **kwargs):
        headers_sent = kwargs.get("headers", {})
        origin = headers_sent.get("Origin", "")
        if origin == "https://evil.com":
            return _ok(headers={
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "true",
            })
        if "does-not-exist" in url:
            return _not_found()
        return _ok()

    client = _make_client(_get)
    scanner = VulnScanner(default_context, client)
    findings = await scanner.scan()

    cors_findings = [f for f in findings if "CORS" in f.title]
    assert len(cors_findings) >= 1
    assert cors_findings[0].severity == "HIGH"
    assert "evil.com" in cors_findings[0].evidence["Access-Control-Allow-Origin"]


# ---------------------------------------------------------------------------
# Clickjacking test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vuln_scanner_clickjacking(default_context):
    """Missing X-Frame-Options and CSP frame-ancestors → MEDIUM clickjacking finding."""

    async def _get(url, **kwargs):
        if "does-not-exist" in url:
            return _not_found()
        # Baseline returns response with NO framing headers
        return _ok(text="<html></html>", headers={})

    client = _make_client(_get)
    scanner = VulnScanner(default_context, client)
    findings = await scanner.scan()

    clickjacking = [f for f in findings if "Clickjacking" in f.title]
    assert len(clickjacking) >= 1, f"Expected clickjacking, got: {[f.title for f in findings]}"
    assert clickjacking[0].severity == "MEDIUM"


# ---------------------------------------------------------------------------
# Sensitive file exposure test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vuln_scanner_sensitive_file_exposed(default_context):
    """
    .env file that passes the signature validator should be reported as CRITICAL.

    Key constraints:
    - Canary page (/this-page-definitely-does-not-exist-…) → 404 so the
      custom-404 fingerprint is set to a non-200 status (no filtering needed).
    - /.env → 200 with a body that passes _validate_env (contains 'DB_PASSWORD=…').
    - All other probes → 404.
    """

    async def _get(url, **kwargs):
        if "does-not-exist" in url:
            # Canary → real 404 so fingerprint.status_code == 404
            return _not_found("Page not found")
        if url.endswith("/.env"):
            # .env exposed with a signature keyword
            return _ok(text="DB_PASSWORD=supersecret\nDB_HOST=localhost\n")
        # All other file probes / probes → 404
        return _not_found()

    client = _make_client(_get)
    scanner = VulnScanner(default_context, client)
    findings = await scanner.scan()

    exposed = [f for f in findings if "Sensitive File Exposed" in f.title and ".env" in f.title]
    assert len(exposed) >= 1, f"Expected .env finding, got: {[f.title for f in findings]}"
    assert exposed[0].severity == "CRITICAL"
