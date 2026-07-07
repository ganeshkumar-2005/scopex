"""
ScopeX WHOIS Scanner Module (v2 — async BaseScanner architecture)
Performs WHOIS lookups on target domains to extract registration details,
registrar info, expiration dates, and nameserver configurations.
Uses raw socket connections to WHOIS servers (port 43) — no external dependencies.
"""
from __future__ import annotations

import asyncio
import re
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner


class WhoisScanner(BaseScanner):
    def __init__(self, context: ScanContext, client: httpx.AsyncClient) -> None:
        super().__init__(context, client)

        # Top-level WHOIS servers for common TLDs
        self.tld_whois_servers: Dict[str, str] = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "info": "whois.afilias.net",
            "io": "whois.nic.io",
            "co": "whois.nic.co",
            "in": "whois.registry.in",
            "us": "whois.nic.us",
            "uk": "whois.nic.uk",
            "de": "whois.denic.de",
            "fr": "whois.nic.fr",
            "au": "whois.auda.org.au",
            "ca": "whois.cira.ca",
            "ru": "whois.tcinet.ru",
            "br": "whois.registro.br",
            "nl": "whois.sidn.nl",
            "eu": "whois.eu",
            "me": "whois.nic.me",
            "xyz": "whois.nic.xyz",
            "dev": "whois.nic.google",
            "app": "whois.nic.google",
            "tech": "whois.nic.tech",
        }

    # ------------------------------------------------------------------
    # WHOIS server selection
    # ------------------------------------------------------------------

    def _get_whois_server(self) -> str:
        """Determines the appropriate WHOIS server for the target domain's TLD."""
        parts = self.host.split(".")
        if len(parts) >= 2:
            tld = parts[-1].lower()
            # Check for country-code second level (e.g., .co.uk, .com.au)
            if len(parts) >= 3:
                sld_tld = f"{parts[-2]}.{parts[-1]}".lower()
                if sld_tld in ("co.uk", "org.uk", "me.uk"):
                    return "whois.nic.uk"
                elif sld_tld in ("com.au", "net.au", "org.au"):
                    return "whois.auda.org.au"
                elif sld_tld in ("co.in", "net.in", "org.in"):
                    return "whois.registry.in"

            if tld in self.tld_whois_servers:
                return self.tld_whois_servers[tld]

        # Fallback to IANA WHOIS
        return "whois.iana.org"

    # ------------------------------------------------------------------
    # Raw WHOIS query (blocking — run via executor)
    # ------------------------------------------------------------------

    def _query_whois(self, server: str, domain: str) -> str:
        """Sends a raw WHOIS query to the specified server on port 43."""
        try:
            with socket.create_connection((server, 43), timeout=self.timeout) as sock:
                sock.sendall((domain + "\r\n").encode("ascii"))
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                return response.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # WHOIS response parser
    # ------------------------------------------------------------------

    def _parse_whois(self, raw: str) -> Dict[str, Any]:
        """Parses raw WHOIS text output into structured key-value pairs."""
        info: Dict[str, Any] = {
            "registrar": "",
            "registrant_org": "",
            "registrant_country": "",
            "creation_date": "",
            "expiration_date": "",
            "updated_date": "",
            "nameservers": [],
            "status": [],
            "dnssec": "",
        }

        # Common WHOIS field patterns (case-insensitive)
        patterns: Dict[str, List[str]] = {
            "registrar": [
                r"Registrar:\s*(.+)",
                r"Sponsoring Registrar:\s*(.+)",
                r"registrar:\s*(.+)",
            ],
            "registrant_org": [
                r"Registrant Organization:\s*(.+)",
                r"Registrant Organisation:\s*(.+)",
                r"org-name:\s*(.+)",
            ],
            "registrant_country": [
                r"Registrant Country:\s*(.+)",
                r"Registrant State/Province:\s*(.+)",
                r"country:\s*(.+)",
            ],
            "creation_date": [
                r"Creation Date:\s*(.+)",
                r"Created Date:\s*(.+)",
                r"created:\s*(.+)",
                r"Registration Time:\s*(.+)",
            ],
            "expiration_date": [
                r"Registry Expiry Date:\s*(.+)",
                r"Expiration Date:\s*(.+)",
                r"Expiry Date:\s*(.+)",
                r"paid-till:\s*(.+)",
            ],
            "updated_date": [
                r"Updated Date:\s*(.+)",
                r"Last Modified:\s*(.+)",
                r"changed:\s*(.+)",
            ],
            "dnssec": [
                r"DNSSEC:\s*(.+)",
                r"dnssec:\s*(.+)",
            ],
        }

        for field_name, regexes in patterns.items():
            for regex in regexes:
                match = re.search(regex, raw, re.IGNORECASE)
                if match:
                    info[field_name] = match.group(1).strip()
                    break

        # Extract nameservers
        ns_matches = re.findall(
            r"Name Server:\s*(.+)", raw, re.IGNORECASE
        )
        if not ns_matches:
            ns_matches = re.findall(r"nserver:\s*(.+)", raw, re.IGNORECASE)
        info["nameservers"] = [ns.strip().lower() for ns in ns_matches]

        # Extract domain statuses
        status_matches = re.findall(
            r"Domain Status:\s*(.+)", raw, re.IGNORECASE
        )
        info["status"] = [s.strip() for s in status_matches]

        # Check for a referred WHOIS server
        refer_match = re.search(r"Registrar WHOIS Server:\s*(.+)", raw, re.IGNORECASE)
        if not refer_match:
            refer_match = re.search(r"refer:\s*(.+)", raw, re.IGNORECASE)
        if refer_match:
            info["_refer"] = refer_match.group(1).strip()

        return info

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    async def scan(self) -> List[Finding]:
        """Performs the WHOIS lookup and generates findings."""
        findings: List[Finding] = []
        loop = asyncio.get_running_loop()

        # Step 1: Query the primary WHOIS server
        whois_server = self._get_whois_server()
        raw_whois: str = await loop.run_in_executor(
            None, self._query_whois, whois_server, self.host
        )

        if not raw_whois:
            self.log.warning(f"Could not connect to WHOIS server: {whois_server}")
            return findings

        # Step 2: Parse the initial response
        whois_info = self._parse_whois(raw_whois)

        # Step 3: Follow referral if a more specific WHOIS server is indicated
        if whois_info.get("_refer"):
            refer_server = whois_info["_refer"]
            referred_raw: str = await loop.run_in_executor(
                None, self._query_whois, refer_server, self.host
            )
            if referred_raw:
                raw_whois = referred_raw
                whois_info = self._parse_whois(referred_raw)

        # --- Generate Findings ---

        # 1. Basic registration info (always report)
        registrar = whois_info.get("registrar") or "Unknown"
        org = whois_info.get("registrant_org") or "Redacted / Not Disclosed"
        country = whois_info.get("registrant_country") or "Unknown"
        created = whois_info.get("creation_date") or "Unknown"
        expires = whois_info.get("expiration_date") or "Unknown"
        nameservers = whois_info.get("nameservers", [])

        findings.append(self.finding(
            title="WHOIS Registration Details",
            severity="INFO",
            description=(
                f"Domain registration information for {self.host}. "
                f"Includes registrar, dates, and nameserver assignments."
            ),
            evidence={
                "domain": self.host,
                "registrar": registrar,
                "organization": org,
                "country": country,
                "created": created,
                "expires": expires,
                "nameservers": nameservers,
            },
            remediation=(
                "Enable WHOIS privacy protection to prevent PII exposure "
                "if registrant details are publicly visible."
            ),
        ))

        # 2. Check for expiring domain (within 30 days)
        if expires and expires != "Unknown":
            try:
                # Try common date formats
                exp_date = None
                for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"]:
                    try:
                        exp_date = datetime.strptime(expires.split(".")[0].strip(), fmt)
                        break
                    except ValueError:
                        continue

                if exp_date:
                    # Make the parsed date timezone-aware for proper comparison
                    exp_date_utc = exp_date.replace(tzinfo=timezone.utc)
                    days_left = (exp_date_utc - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        findings.append(self.finding(
                            title="Domain Registration Expired",
                            severity="CRITICAL",
                            description=(
                                f"The domain {self.host} appears to have expired "
                                f"{abs(days_left)} days ago. Expired domains are "
                                f"vulnerable to takeover by third parties."
                            ),
                            evidence={
                                "registrar": registrar,
                                "expiration_date": expires,
                                "days_expired": abs(days_left),
                            },
                            remediation=(
                                "Renew the domain immediately or enable auto-renewal "
                                "with your registrar."
                            ),
                        ))
                    elif days_left <= 30:
                        findings.append(self.finding(
                            title="Domain Expiring Soon",
                            severity="HIGH",
                            description=(
                                f"The domain {self.host} expires in {days_left} day(s). "
                                f"Losing control of a domain can cause service disruption "
                                f"and enable phishing."
                            ),
                            evidence={
                                "registrar": registrar,
                                "expiration_date": expires,
                                "days_remaining": days_left,
                            },
                            remediation=(
                                "Renew the domain immediately and enable auto-renewal."
                            ),
                        ))
            except Exception:
                pass

        # 3. Check for DNSSEC status
        dnssec = whois_info.get("dnssec", "").lower()
        if dnssec and "unsigned" in dnssec:
            findings.append(self.finding(
                title="DNSSEC Not Enabled",
                severity="MEDIUM",
                description=(
                    "DNSSEC is not configured for this domain. Without DNSSEC, "
                    "DNS responses can be spoofed by attackers (DNS cache poisoning)."
                ),
                evidence={
                    "dnssec_status": whois_info.get("dnssec", "unsigned"),
                    "domain": self.host,
                },
                remediation=(
                    "Enable DNSSEC signing with your DNS provider and registrar."
                ),
            ))

        # 4. Check for exposed registrant information (privacy not enabled)
        if org and org.lower() not in (
            "redacted", "redacted / not disclosed", "not disclosed",
            "data protected", ""
        ):
            findings.append(self.finding(
                title="WHOIS Registrant Information Publicly Exposed",
                severity="LOW",
                description=(
                    f"The domain registrant organization ({org}) is publicly visible "
                    f"in WHOIS records. This can be used for social engineering and "
                    f"targeted phishing."
                ),
                evidence={
                    "registrant_organization": org,
                    "registrant_country": country,
                    "domain": self.host,
                },
                remediation=(
                    "Enable WHOIS privacy protection (domain privacy) through "
                    "your registrar."
                ),
            ))

        self.log.info(f"WHOIS scan complete for {self.host}: {len(findings)} findings")

        return findings
