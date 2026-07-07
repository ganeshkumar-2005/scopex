"""
tests/test_port_scanner.py — Unit tests for the hybrid port scanner (v2).
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.context import ScanContext
from scanners.port_scanner import PortScanner


@pytest.fixture
def default_context():
    return ScanContext(target="https://127.0.0.1", host="127.0.0.1", timeout=1.0)


@pytest.mark.asyncio
async def test_port_scanner_nmap_success(default_context):
    """Test that PortScanner uses Nmap successfully when available."""
    mock_nmap_instance = MagicMock()
    mock_nmap_instance.all_hosts.return_value = ["127.0.0.1"]
    mock_nmap_instance.scan.return_value = {
        "scan": {
            "127.0.0.1": {
                "tcp": {
                    80: {"state": "open", "name": "http", "product": "Apache", "version": "2.4"},
                    443: {"state": "open", "name": "https", "product": "nginx", "version": "1.18"},
                },
                "osmatch": [{"name": "Linux 5.x"}],
            }
        }
    }

    with patch("scanners.port_scanner._NMAP_AVAILABLE", True), \
         patch("nmap.PortScanner", return_value=mock_nmap_instance):
        
        client = AsyncMock()
        scanner = PortScanner(default_context, client)
        findings = await scanner.scan()

        assert len(findings) == 2
        # Port 80 finding
        f_80 = [f for f in findings if f.evidence["port"] == 80][0]
        assert f_80.severity == "INFO"
        assert "Apache 2.4" in f_80.description
        assert f_80.evidence["os_detection"] == "Linux 5.x"

        # Port 443 finding
        f_443 = [f for f in findings if f.evidence["port"] == 443][0]
        assert f_443.severity == "INFO"
        assert "nginx 1.18" in f_443.description


@pytest.mark.asyncio
async def test_port_scanner_socket_fallback(default_context):
    """Test that PortScanner falls back to async sockets if Nmap is unavailable."""
    with patch("scanners.port_scanner._NMAP_AVAILABLE", False):
        client = AsyncMock()
        scanner = PortScanner(default_context, client)

        # Mock the socket connection scan to simulate open/closed ports
        async def mock_scan_port_socket(host, port, sem):
            if port == 80:
                return {"port": 80, "service": "HTTP", "open": True, "banner": "Server: TestServer"}
            return {"port": port, "service": "Unknown", "open": False}

        with patch.object(scanner, "_scan_port_socket", side_effect=mock_scan_port_socket):
            findings = await scanner.scan()

            assert len(findings) == 1
            assert findings[0].evidence["port"] == 80
            assert findings[0].evidence["banner"] == "Server: TestServer"
            assert findings[0].severity == "INFO"
