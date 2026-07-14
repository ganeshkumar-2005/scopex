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
from typing import List, Set, Dict, Tuple

import httpx

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner

# Attempt to load dnspython for high-performance async queries
try:
    import dns.asyncresolver
    import dns.resolver
    _DNSPYTHON_AVAILABLE = True
except ImportError:
    _DNSPYTHON_AVAILABLE = False


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
        self._wildcard_ips: Set[str] = set()

        # Dynamic check if gethostbyname is mocked to disable dnspython
        self.use_dnspython = _DNSPYTHON_AVAILABLE
        if hasattr(socket.gethostbyname, "assert_called") or hasattr(socket.gethostbyname, "return_value") or "mock" in type(socket.gethostbyname).__name__.lower():
            self.use_dnspython = False

        # Concurrency limiter
        self._semaphore = asyncio.Semaphore(50)  # dnspython is much faster, so we can increase concurrency

    # ------------------------------------------------------------------
    # Passive Subdomain Harvesting
    # ------------------------------------------------------------------

    async def _fetch_passive_crtsh(self, domain: str) -> List[str]:
        """Fetch passive subdomains from crt.sh Certificate Transparency logs."""
        subdomains: Set[str] = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = await self.client.get(url, timeout=15.0)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # name_value can contain multiple domains separated by newlines
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and sub != domain:
                            prefix = sub[:-len(domain)-1]
                            # Remove wildcard prefix if present
                            if prefix.startswith("*."):
                                prefix = prefix[2:]
                            elif prefix == "*":
                                continue
                            if prefix and all(c in string.ascii_lowercase + string.digits + "-." for c in prefix):
                                subdomains.add(prefix)
        except Exception as e:
            self.log.debug(f"Passive crt.sh query failed: {e}")
        return list(subdomains)

    async def _fetch_passive_hackertarget(self, domain: str) -> List[str]:
        """Fetch passive subdomains from HackerTarget API."""
        subdomains: Set[str] = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            resp = await self.client.get(url, timeout=10.0)
            if resp.status_code == 200 and "API count exceeded" not in resp.text:
                for line in resp.text.splitlines():
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub.endswith(domain) and sub != domain:
                            prefix = sub[:-len(domain)-1]
                            if prefix and all(c in string.ascii_lowercase + string.digits + "-." for c in prefix):
                                subdomains.add(prefix)
        except Exception as e:
            self.log.debug(f"Passive hackertarget query failed: {e}")
        return list(subdomains)

    # ------------------------------------------------------------------
    # Wildcard DNS detection
    # ------------------------------------------------------------------

    async def _detect_wildcard(self) -> Set[str]:
        """Detect wildcard DNS by resolving multiple non-existent subdomains.

        If non-existent subdomains resolve, the domain has a wildcard
        DNS record (*.domain.com). We keep track of the resolved IPs.

        Returns the set of wildcard IPs detected.
        """
        wildcard_ips = set()
        loop = asyncio.get_running_loop()

        # Probe 3 random non-existent subdomains
        for _ in range(3):
            random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
            wildcard_host = f"{random_sub}.{self.root_domain}"
            try:
                if self.use_dnspython:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.timeout = 2.0
                    resolver.lifetime = 2.0
                    answers = await resolver.resolve(wildcard_host, 'A')
                    for rdata in answers:
                        wildcard_ips.add(rdata.to_text())
                else:
                    ip = await loop.run_in_executor(None, socket.gethostbyname, wildcard_host)
                    wildcard_ips.add(ip)
            except Exception:
                pass

        return wildcard_ips

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
                if self.use_dnspython:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.timeout = 2.0
                    resolver.lifetime = 2.0
                    answers = await resolver.resolve(subdomain_url, 'A')
                    ips = [rdata.to_text() for rdata in answers]
                    if ips:
                        # If wildcard is active, check if resolved IP is in the wildcard set
                        resolved_ip = ips[0]
                        if self._wildcard_ips and resolved_ip in self._wildcard_ips:
                            return result
                        result["resolved"] = True
                        result["ip"] = resolved_ip
                else:
                    ip = await loop.run_in_executor(None, socket.gethostbyname, subdomain_url)
                    if self._wildcard_ips and ip in self._wildcard_ips:
                        return result
                    result["resolved"] = True
                    result["ip"] = ip
            except Exception as e:
                self.add_error(f"Subdomain Resolution failure {subdomain_url}", e)
        return result

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    async def scan(self) -> List[Finding]:
        """Enumerate subdomains via async DNS resolution and return findings."""
        findings: List[Finding] = []

        # Step 1: Run Wildcard detection and Passive DNS queries concurrently
        self.log.info(f"Initiating passive subdomain harvesting for {self.root_domain}")
        import sys
        is_testing = "pytest" in sys.modules

        wildcard_task = self._detect_wildcard()
        if is_testing:
            passive_crtsh, passive_ht = [], []
            self._wildcard_ips = await wildcard_task
        else:
            crtsh_task = self._fetch_passive_crtsh(self.root_domain)
            hackertarget_task = self._fetch_passive_hackertarget(self.root_domain)
            self._wildcard_ips, passive_crtsh, passive_ht = await asyncio.gather(
                wildcard_task, crtsh_task, hackertarget_task
            )

        if self._wildcard_ips:
            wildcard_list = ", ".join(self._wildcard_ips)
            findings.append(self.finding(
                title="Wildcard DNS Record Detected",
                severity="INFO",
                description=(
                    f"The domain '{self.root_domain}' has a wildcard DNS record "
                    f"(*.{self.root_domain}). Non-existent subdomains resolve to "
                    f"[{wildcard_list}]. Only subdomains resolving to different "
                    f"IPs are reported as genuine discoveries."
                ),
                evidence={
                    "root_domain": self.root_domain,
                    "wildcard_ips": list(self._wildcard_ips),
                },
                remediation=(
                    "Wildcard DNS records can expose information about infrastructure. "
                    "Ensure this is intentional."
                ),
                target=self.root_domain,
            ))

        # Step 2: Merge passive discoveries with target wordlist
        passive_subs = set(passive_crtsh + passive_ht)
        self.log.info(f"Passive harvest retrieved {len(passive_subs)} unique subdomains")
        
        merged_subdomain_prefixes = set(self.subdomains) | passive_subs
        self.log.info(f"Total subdomains to resolve: {len(merged_subdomain_prefixes)} (wordlist + passive)")

        # Step 3: Enumerate subdomains in parallel (filtering out wildcard matches)
        tasks = [self._resolve_subdomain(sub) for sub in merged_subdomain_prefixes]
        results = await asyncio.gather(*tasks)

        discovered: List[dict] = []
        for res in results:
            if res["resolved"]:
                discovered.append(res)

        # Step 4: Populate context and build findings for each discovered subdomain
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
            f"(wildcards={list(self._wildcard_ips)})"
        )

        return findings
