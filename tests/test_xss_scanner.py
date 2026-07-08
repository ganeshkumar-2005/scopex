"""
tests/test_xss_scanner.py — Unit tests for the async XSS scanner (v2).
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from core.context import ScanContext
from core.findings import Finding
from scanners.xss_scanner import XSSScanner


def _ctx(target="https://example.com/search?q=test") -> ScanContext:
    ctx = ScanContext(target=target, host="example.com", timeout=3.0)
    ctx.discovered_urls = [target]
    return ctx


def _mock_response(text="", status_code=200, headers=None):
    from tests.conftest import MockResponse
    return MockResponse(status_code=status_code, text=text, headers=headers or {})


def _make_scanner(ctx, responses):
    client = AsyncMock()
    client.get = AsyncMock(side_effect=responses)
    client.post = AsyncMock(side_effect=responses)
    return XSSScanner(ctx, client)


@pytest.mark.asyncio
async def test_xss_no_params():
    """Scanner returns INFO when no parameters found."""
    ctx = ScanContext(target="https://example.com/", host="example.com", timeout=3.0)
    ctx.discovered_urls = []
    normal = _mock_response("<html><body>Hello</body></html>")
    scanner = _make_scanner(ctx, [normal] * 10)
    findings = await scanner.scan()
    info = [f for f in findings if f.severity == "INFO" and "No Parameters" in f.title]
    assert len(info) >= 1


@pytest.mark.asyncio
async def test_xss_reflected_detection():
    """Detects reflected XSS when payload appears unencoded in response."""
    ctx = _ctx()
    normal = _mock_response("<html><body>Search results for: test</body></html>")
    reflected = _mock_response('<html><body>Search results for: <img src=x onerror=alert(1)></body></html>')

    # Baseline response, then for each discovered URL, then payload responses
    responses = [normal] * 2 + [reflected] * 20
    scanner = _make_scanner(ctx, responses)
    
    from unittest.mock import patch
    with patch("scanners.xss_scanner._PLAYWRIGHT_AVAILABLE", False):
        findings = await scanner.scan()

    xss_findings = [f for f in findings if "Reflected XSS" in f.title]
    assert len(xss_findings) >= 1
    assert xss_findings[0].severity == "HIGH"
    assert xss_findings[0].verified is True
    assert xss_findings[0].verification_method == "unverified"


@pytest.mark.asyncio
async def test_xss_safely_encoded():
    """Reports INFO when payload is HTML-encoded in response."""
    ctx = _ctx()
    normal = _mock_response("<html><body>Search</body></html>")
    encoded = _mock_response(
        '<html><body>Search: &lt;img src=x onerror=alert(1)&gt;</body></html>'
    )

    responses = [normal] * 2 + [encoded] * 20
    scanner = _make_scanner(ctx, responses)
    findings = await scanner.scan()

    encoded_findings = [f for f in findings if "Safely Encoded" in f.title]
    assert len(encoded_findings) >= 1
    assert encoded_findings[0].severity == "INFO"


@pytest.mark.asyncio
async def test_xss_dom_based_detection():
    """Detects DOM XSS when script block contains source/sink pattern."""
    ctx = ScanContext(target="https://example.com/", host="example.com", timeout=3.0)
    ctx.discovered_urls = []
    dom_page = _mock_response(
        '<html><body><script>var x = location.hash; document.write(x);</script></body></html>'
    )
    responses = [dom_page] * 10
    scanner = _make_scanner(ctx, responses)
    findings = await scanner.scan()

    dom_findings = [f for f in findings if "DOM" in f.title]
    assert len(dom_findings) >= 1
    assert dom_findings[0].severity in ("MEDIUM", "INFO")


@pytest.mark.asyncio
async def test_xss_csp_mitigation():
    """Reports CSP presence but keeps severity HIGH per deterministic rules."""
    ctx = _ctx()
    csp_normal = _mock_response(
        "<html><body>Search</body></html>",
        headers={"content-security-policy": "script-src 'self'"}
    )
    csp_reflected = _mock_response(
        '<html><body><img src=x onerror=alert(1)></body></html>',
        headers={"content-security-policy": "script-src 'self'"}
    )
    responses = [csp_normal] * 2 + [csp_reflected] * 20
    scanner = _make_scanner(ctx, responses)
    findings = await scanner.scan()

    reflected = [f for f in findings if "Reflected XSS" in f.title]
    assert len(reflected) >= 1
    assert reflected[0].severity == "HIGH"
    assert reflected[0].verification_method == "csp_present"


@pytest.mark.asyncio
async def test_xss_findings_are_finding_objects():
    """All findings are proper Finding instances."""
    ctx = _ctx()
    normal = _mock_response("<html></html>")
    responses = [normal] * 50
    scanner = _make_scanner(ctx, responses)
    findings = await scanner.scan()
    for f in findings:
        assert isinstance(f, Finding)
        assert f.module == "XSSScanner"


@pytest.mark.asyncio
async def test_xss_reflected_browser_confirmed_execution():
    """Verify that browser-confirmed execution results in CRITICAL severity."""
    ctx = _ctx()
    normal = _mock_response("<html><body>Search results for: test</body></html>")
    reflected = _mock_response('<html><body>Search results for: <img src=x onerror=alert(1)></body></html>')
    responses = [normal] * 2 + [reflected] * 20
    scanner = _make_scanner(ctx, responses)

    from unittest.mock import patch, AsyncMock
    with patch("scanners.xss_scanner._PLAYWRIGHT_AVAILABLE", True), \
         patch.object(scanner, "_verify_with_playwright", new_callable=AsyncMock) as mock_verify:
        mock_verify.return_value = True
        findings = await scanner.scan()

    xss_findings = [f for f in findings if "Reflected XSS" in f.title]
    assert len(xss_findings) >= 1
    assert xss_findings[0].severity == "CRITICAL"
    assert xss_findings[0].verified is True
    assert xss_findings[0].verification_method == "browser_confirmed_execution"


@pytest.mark.asyncio
async def test_xss_reflected_browser_confirmed_no_execution():
    """Verify that browser-confirmed no-execution results in MEDIUM severity."""
    ctx = _ctx()
    normal = _mock_response("<html><body>Search results for: test</body></html>")
    reflected = _mock_response('<html><body>Search results for: <img src=x onerror=alert(1)></body></html>')
    responses = [normal] * 2 + [reflected] * 20
    scanner = _make_scanner(ctx, responses)

    from unittest.mock import patch, AsyncMock
    with patch("scanners.xss_scanner._PLAYWRIGHT_AVAILABLE", True), \
         patch.object(scanner, "_verify_with_playwright", new_callable=AsyncMock) as mock_verify:
        mock_verify.return_value = False
        findings = await scanner.scan()

    xss_findings = [f for f in findings if "Reflected XSS" in f.title]
    assert len(xss_findings) >= 1
    assert xss_findings[0].severity == "MEDIUM"
    assert xss_findings[0].verified is False
    assert xss_findings[0].verification_method == "browser_confirmed_no_execution"


@pytest.mark.asyncio
async def test_xss_reflected_csp_present_severity():
    """Verify that CSP present results in HIGH severity but 'csp_present' verification method."""
    ctx = _ctx()
    csp_normal = _mock_response(
        "<html><body>Search</body></html>",
        headers={"content-security-policy": "script-src 'self'"}
    )
    csp_reflected = _mock_response(
        '<html><body><img src=x onerror=alert(1)></body></html>',
        headers={"content-security-policy": "script-src 'self'"}
    )
    responses = [csp_normal] * 2 + [csp_reflected] * 20
    scanner = _make_scanner(ctx, responses)
    findings = await scanner.scan()

    reflected = [f for f in findings if "Reflected XSS" in f.title]
    assert len(reflected) >= 1
    assert reflected[0].severity == "HIGH"
    assert reflected[0].verified is False
    assert reflected[0].verification_method == "csp_present"
