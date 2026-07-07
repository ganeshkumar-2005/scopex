"""
tests/test_whois_scanner.py — Unit tests for the async WhoisScanner (v2).

Tests WHOIS parsing, referral following, expiry detection, and DNSSEC checks
using mocked raw socket WHOIS responses.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta

import pytest

from core.context import ScanContext
from core.findings import Finding
from scanners.whois_scanner import WhoisScanner


@pytest.fixture
def default_context():
    return ScanContext(target="https://example.com", host="example.com", timeout=1.0)


# Sample WHOIS responses for mocking
_WHOIS_RESPONSE_NORMAL = """\
   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.iana.org
   Registrar URL: http://www.iana.org
   Updated Date: 2024-08-14T07:01:34Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2025-08-13T04:00:00Z
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Registrar IANA ID: 376
   Registrar Abuse Contact Email: abuse@iana.org
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
"""

_WHOIS_RESPONSE_EXPIRING = """\
   Domain Name: EXPIRING.COM
   Registrar: GoDaddy
   Registrant Organization: Test Corp
   Registrant Country: US
   Creation Date: 2020-01-01T00:00:00Z
   Registry Expiry Date: {expiry_date}
   Name Server: NS1.GODADDY.COM
   DNSSEC: unsigned
"""

_WHOIS_RESPONSE_EXPOSED = """\
   Domain Name: EXPOSED.COM
   Registrar: Namecheap
   Registrant Organization: Acme Corporation
   Registrant Country: US
   Creation Date: 2018-06-15T00:00:00Z
   Registry Expiry Date: 2030-06-15T00:00:00Z
   Name Server: NS1.NAMECHEAP.COM
   DNSSEC: unsigned
"""


@pytest.mark.asyncio
async def test_whois_basic_registration_info(default_context):
    """Basic WHOIS lookup should return registration details as INFO finding."""

    def mock_query(server, domain):
        return _WHOIS_RESPONSE_NORMAL

    with patch.object(WhoisScanner, "_query_whois", side_effect=mock_query):
        client = AsyncMock()
        scanner = WhoisScanner(default_context, client)
        findings = await scanner.scan()

    # Should have at least the registration details finding
    reg_findings = [f for f in findings if "Registration" in f.title or "WHOIS" in f.title]
    assert len(reg_findings) >= 1

    # All findings should be Finding objects
    for f in findings:
        assert isinstance(f, Finding)
        assert isinstance(f.evidence, dict)

    # Check that registration info is captured
    reg = reg_findings[0]
    assert reg.severity == "INFO"
    assert "example.com" in reg.description.lower() or "example.com" in str(reg.evidence).lower()


@pytest.mark.asyncio
async def test_whois_expiring_domain(default_context):
    """Domain expiring within 30 days should generate HIGH finding."""

    expiry = (datetime.now(timezone.utc) + timedelta(days=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
    response = _WHOIS_RESPONSE_EXPIRING.format(expiry_date=expiry)

    def mock_query(server, domain):
        return response

    with patch.object(WhoisScanner, "_query_whois", side_effect=mock_query):
        client = AsyncMock()
        scanner = WhoisScanner(default_context, client)
        findings = await scanner.scan()

    expiry_findings = [f for f in findings if "Expir" in f.title]
    assert len(expiry_findings) >= 1
    assert expiry_findings[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_whois_dnssec_unsigned(default_context):
    """Unsigned DNSSEC should generate MEDIUM finding."""

    def mock_query(server, domain):
        return _WHOIS_RESPONSE_EXPOSED

    with patch.object(WhoisScanner, "_query_whois", side_effect=mock_query):
        client = AsyncMock()
        scanner = WhoisScanner(default_context, client)
        findings = await scanner.scan()

    dnssec_findings = [f for f in findings if "DNSSEC" in f.title]
    assert len(dnssec_findings) >= 1
    assert dnssec_findings[0].severity == "MEDIUM"


@pytest.mark.asyncio
async def test_whois_registrant_exposed(default_context):
    """Publicly visible registrant org should generate LOW finding."""

    def mock_query(server, domain):
        return _WHOIS_RESPONSE_EXPOSED

    with patch.object(WhoisScanner, "_query_whois", side_effect=mock_query):
        client = AsyncMock()
        scanner = WhoisScanner(default_context, client)
        findings = await scanner.scan()

    privacy_findings = [f for f in findings if "Exposed" in f.title or "Privacy" in f.title or "Registrant" in f.title]
    assert len(privacy_findings) >= 1
    assert privacy_findings[0].severity == "LOW"


@pytest.mark.asyncio
async def test_whois_connection_failure(default_context):
    """When WHOIS server is unreachable, scanner should return gracefully."""

    def mock_query(server, domain):
        return ""

    with patch.object(WhoisScanner, "_query_whois", side_effect=mock_query):
        client = AsyncMock()
        scanner = WhoisScanner(default_context, client)
        findings = await scanner.scan()

    # Should not crash; may return an INFO finding about connection failure
    for f in findings:
        assert isinstance(f, Finding)
