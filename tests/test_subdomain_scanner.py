"""
tests/test_subdomain_scanner.py — Unit tests for the async SubdomainScanner (v2).

Tests wildcard DNS detection, subdomain resolution, and proper
Finding object generation using mocked socket.gethostbyname() calls.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.context import ScanContext
from core.findings import Finding
from scanners.subdomain_scanner import SubdomainScanner


@pytest.fixture
def default_context():
    return ScanContext(target="https://example.com", host="example.com", timeout=1.0)


@pytest.mark.asyncio
async def test_subdomain_scanner_discovers_subdomains(default_context):
    """SubdomainScanner should discover subdomains that resolve via DNS."""

    def mock_resolve(hostname):
        known = {
            "www.example.com": "93.184.216.34",
            "mail.example.com": "93.184.216.35",
            "api.example.com": "93.184.216.36",
        }
        if hostname in known:
            return known[hostname]
        import socket
        raise socket.gaierror("Name or service not known")

    with patch("scanners.subdomain_scanner.socket.gethostbyname", side_effect=mock_resolve):
        client = AsyncMock()
        scanner = SubdomainScanner(default_context, client)
        findings = await scanner.scan()

    # Should find 3 active subdomains
    discovered = [f for f in findings if "Discovered Active Subdomain" in f.title]
    assert len(discovered) == 3

    # Verify they are Finding objects
    for f in findings:
        assert isinstance(f, Finding)

    # Verify evidence is a dict (not a string)
    for f in discovered:
        assert isinstance(f.evidence, dict)
        assert "ip" in f.evidence

    # Verify context was populated
    assert len(default_context.discovered_subdomains) == 3


@pytest.mark.asyncio
async def test_subdomain_scanner_wildcard_dns(default_context):
    """When wildcard DNS is active, only subdomains with distinct IPs should be reported."""

    def mock_resolve(hostname):
        # Wildcard: everything resolves to the same IP
        wildcard_ip = "10.0.0.1"
        distinct = {
            "api.example.com": "10.0.0.99",  # different from wildcard
        }
        if hostname in distinct:
            return distinct[hostname]
        return wildcard_ip  # wildcard catch-all

    with patch("scanners.subdomain_scanner.socket.gethostbyname", side_effect=mock_resolve):
        client = AsyncMock()
        scanner = SubdomainScanner(default_context, client)
        findings = await scanner.scan()

    # Should detect wildcard
    wildcard_findings = [f for f in findings if "Wildcard" in f.title]
    assert len(wildcard_findings) == 1
    assert wildcard_findings[0].severity == "INFO"

    # Only api.example.com should be reported (distinct IP)
    discovered = [f for f in findings if "Discovered Active Subdomain" in f.title]
    assert len(discovered) == 1
    assert "api.example.com" in discovered[0].description


@pytest.mark.asyncio
async def test_subdomain_scanner_no_results(default_context):
    """When no subdomains resolve, scanner should return empty list or minimal info."""

    def mock_resolve(hostname):
        import socket
        raise socket.gaierror("Name or service not known")

    with patch("scanners.subdomain_scanner.socket.gethostbyname", side_effect=mock_resolve):
        client = AsyncMock()
        scanner = SubdomainScanner(default_context, client)
        findings = await scanner.scan()

    # No discovered subdomains
    discovered = [f for f in findings if "Discovered Active Subdomain" in f.title]
    assert len(discovered) == 0
