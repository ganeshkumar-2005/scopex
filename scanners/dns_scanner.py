"""
scanners/dns_scanner.py — DNS record scanner (v2 async rewrite).
Uses asyncio executor for blocking socket DNS lookups.
"""
from __future__ import annotations

import asyncio
import socket
from typing import Dict, List

from loguru import logger

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner


class DNSScanner(BaseScanner):
    """Async DNS record scanner."""

    async def scan(self) -> List[Finding]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._scan_sync)

    def _scan_sync(self) -> List[Finding]:
        findings: List[Finding] = []
        host = self.ctx.host
        dns_records: Dict[str, list] = {}

        # A records (IPv4)
        try:
            info_v4 = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            ips_v4 = list({x[4][0] for x in info_v4})
            dns_records["A"] = ips_v4
        except Exception:
            dns_records["A"] = []

        # AAAA records (IPv6)
        try:
            info_v6 = socket.getaddrinfo(host, None, socket.AF_INET6, socket.SOCK_STREAM)
            ips_v6 = list({x[4][0] for x in info_v6})
            dns_records["AAAA"] = ips_v6
        except Exception:
            dns_records["AAAA"] = []

        # Check resolution
        if not dns_records["A"] and not dns_records["AAAA"]:
            findings.append(self.finding(
                title="DNS Host Resolution Failed",
                severity="HIGH",
                description=f"Host '{host}' could not be resolved to any IP address.",
                evidence={"host": host, "records": dns_records},
                remediation="Verify target hostname and DNS zone configuration.",
                tags=["dns"],
            ))
            return findings

        # Private IP check (RFC 1918)
        for ip in dns_records["A"]:
            try:
                parts = [int(x) for x in ip.split(".")]
                is_private = (
                    parts[0] == 10 or
                    (parts[0] == 172 and 16 <= parts[1] <= 31) or
                    (parts[0] == 192 and parts[1] == 168) or
                    parts[0] == 127
                )
                if is_private:
                    findings.append(self.finding(
                        title="Private IP Address in DNS",
                        severity="MEDIUM",
                        description=f"Target resolves to private RFC 1918 address: {ip}",
                        evidence={"host": host, "private_ip": ip},
                        remediation="Ensure external DNS zones don't expose internal network topology.",
                        tags=["dns", "info-leak"],
                    ))
            except Exception:
                continue

        # Reverse DNS (PTR)
        if dns_records["A"]:
            try:
                ptr_info = socket.gethostbyaddr(dns_records["A"][0])
                dns_records["PTR"] = [ptr_info[0]]
            except Exception:
                dns_records["PTR"] = []

        return findings
