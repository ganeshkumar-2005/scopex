"""
ScopeX Subdomain Scanner Module (v2 — async BaseScanner architecture)
Enumerates subdomains for the target domain using DNS resolution.
Uses asyncio.Semaphore for concurrency control and run_in_executor
for non-blocking socket.gethostbyname() calls.
"""
from __future__ import annotations

import asyncio
import random
import socket
import string
from typing import List

import httpx

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner


class SubdomainScanner(BaseScanner):
    def __init__(self, context: ScanContext, client: httpx.AsyncClient) -> None:
        super().__init__(context, client)

        domain = self.host

        # Remove common starting subdomains if present to get root domain
        parts = domain.split('.')
        if len(parts) > 2:
            # Check for multi-level TLDs (e.g. co.uk, com.au, org.uk, gov.in)
            multi_level_tlds = ("co", "com", "org", "net", "gov", "edu", "ac", "govt", "mil")
            if parts[-2] in multi_level_tlds:
                self.root_domain = ".".join(parts[-3:])
            else:
                self.root_domain = ".".join(parts[-2:])
        else:
            self.root_domain = domain

        # Built-in wordlist of common subdomains (deduplicated)
        default_subs = [
            "www", "mail", "ftp", "admin", "blog", "dev", "staging", "api", "test", "portal",
            "secure", "vpn", "support", "webmail", "shop", "status", "git", "gitlab", "cpanel",
            "dns", "ns1", "ns2", "mx", "docs", "app", "dashboard", "monitor", "beta", "demo",
            "db", "database", "sql", "internal", "intranet", "corp", "m", "news", "static",
            "assets", "images", "cdn", "store", "forum", "help", "billing", "accounts"
        ]
        self.subdomains: List[str] = list(dict.fromkeys(default_subs))  # deduplicate preserving order

        # Wildcard detection state
        self._wildcard_ip: str = ""

        # Concurrency limiter
        self._semaphore = asyncio.Semaphore(20)

    # ------------------------------------------------------------------
    # Wildcard DNS detection
    # ------------------------------------------------------------------

    async def _detect_wildcard(self) -> str:
        """Detect wildcard DNS by resolving a random non-existent subdomain.

        If a randomly generated subdomain resolves, the domain has a wildcard
        DNS record (*.domain.com) and all brute-force results would be false positives.

        Returns the wildcard IP if detected, empty string otherwise.
        """
        # Generate a random subdomain that almost certainly doesn't exist
        random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        wildcard_host = f"{random_sub}.{self.root_domain}"
        loop = asyncio.get_running_loop()
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, wildcard_host)
            return ip  # Wildcard detected
        except socket.gaierror as e:
            self.add_error("Subdomain Wildcard Check socket.gaierror", e)
            return ""
        except socket.error as e:
            self.add_error("Subdomain Wildcard Check socket.error", e)
            return ""
        except Exception as e:
            self.add_error("Subdomain Wildcard Check Generic Exception", e)
            return ""

    # ------------------------------------------------------------------
    # Single subdomain resolution
    # ------------------------------------------------------------------

    async def _resolve_subdomain(self, sub: str) -> dict:
        """Resolve a single subdomain, respecting the concurrency semaphore."""
        subdomain_url = f"{sub}.{self.root_domain}"
        result = {
            "subdomain": subdomain_url,
            "resolved": False,
            "ip": ""
        }
        async with self._semaphore:
            loop = asyncio.get_running_loop()
            try:
                ip = await loop.run_in_executor(None, socket.gethostbyname, subdomain_url)
                # If wildcard is active, only count as "resolved" if IP differs from wildcard
                if self._wildcard_ip and ip == self._wildcard_ip:
                    return result  # Same as wildcard — likely false positive
                result["resolved"] = True
                result["ip"] = ip
            except socket.gaierror as e:
                self.add_error(f"Subdomain Resolution socket.gaierror {subdomain_url}", e)
            except socket.error as e:
                self.add_error(f"Subdomain Resolution socket.error {subdomain_url}", e)
            except Exception as e:
                self.add_error(f"Subdomain Resolution Generic Exception {subdomain_url}", e)
        return result

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    async def scan(self) -> List[Finding]:
        """Enumerate subdomains via async DNS resolution and return findings."""
        findings: List[Finding] = []

        # Step 1: Wildcard DNS detection
        self._wildcard_ip = await self._detect_wildcard()

        if self._wildcard_ip:
            findings.append(self.finding(
                title="Wildcard DNS Record Detected",
                severity="INFO",
                description=(
                    f"The domain '{self.root_domain}' has a wildcard DNS record "
                    f"(*.{self.root_domain}). Non-existent subdomains resolve to "
                    f"{self._wildcard_ip}. Only subdomains resolving to different "
                    f"IPs are reported as genuine discoveries."
                ),
                evidence={
                    "root_domain": self.root_domain,
                    "wildcard_ip": self._wildcard_ip,
                },
                remediation=(
                    "Wildcard DNS records can expose information about infrastructure. "
                    "Ensure this is intentional."
                ),
                target=self.root_domain,
            ))

        # Step 2: Enumerate subdomains in parallel (filtering out wildcard matches)
        tasks = [self._resolve_subdomain(sub) for sub in self.subdomains]
        results = await asyncio.gather(*tasks)

        discovered: List[dict] = []
        for res in results:
            if res["resolved"]:
                discovered.append(res)

        # Step 3: Populate context and build findings for each discovered subdomain
        for d in discovered:
            subdomain = d["subdomain"]
            ip = d["ip"]

            # Register with the shared scan context
            self.ctx.add_discovered_subdomain(subdomain)

            findings.append(self.finding(
                title="Discovered Active Subdomain",
                severity="INFO",
                description=(
                    f"The active subdomain '{subdomain}' was discovered via DNS resolution."
                ),
                evidence={
                    "ip": ip,
                    "subdomain": subdomain,
                },
                remediation=(
                    "Review the discovered subdomain to ensure it is intended to be "
                    "active and properly secured. Ensure it is included in your threat "
                    "modeling and vulnerability management cycles."
                ),
                target=subdomain,
            ))

        self.log.info(
            f"Subdomain scan complete: {len(discovered)} discovered "
            f"(wildcard={'yes' if self._wildcard_ip else 'no'})"
        )

        return findings
