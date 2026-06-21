"""
EncryptX WHOIS Scanner Module
Performs WHOIS lookups on target domains to extract registration details,
registrar info, expiration dates, and nameserver configurations.
Uses raw socket connections to WHOIS servers (port 43) - no external dependencies.
"""
import socket
import re
from datetime import datetime


class WhoisScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        # Extract clean domain from URL if needed
        if "://" in target:
            self.host = target.split("://")[1].split("/")[0].split(":")[0]
        else:
            self.host = target.split("/")[0].split(":")[0]
        self.timeout = timeout

        # Top-level WHOIS servers for common TLDs
        self.tld_whois_servers = {
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

    def _parse_whois(self, raw: str) -> dict:
        """Parses raw WHOIS text output into structured key-value pairs."""
        info = {
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
        patterns = {
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

        for field, regexes in patterns.items():
            for regex in regexes:
                match = re.search(regex, raw, re.IGNORECASE)
                if match:
                    info[field] = match.group(1).strip()
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

    def scan(self, progress_callback=None) -> dict:
        """Performs the WHOIS lookup and generates findings."""
        findings = []

        # Step 1: Query the primary WHOIS server
        whois_server = self._get_whois_server()
        raw_whois = self._query_whois(whois_server, self.host)

        if not raw_whois:
            return {
                "domain": self.host,
                "error": f"Could not connect to WHOIS server: {whois_server}",
                "findings": [],
            }

        # Step 2: Parse the initial response
        whois_info = self._parse_whois(raw_whois)

        # Step 3: Follow referral if a more specific WHOIS server is indicated
        if whois_info.get("_refer"):
            refer_server = whois_info["_refer"]
            referred_raw = self._query_whois(refer_server, self.host)
            if referred_raw:
                raw_whois = referred_raw
                whois_info = self._parse_whois(referred_raw)

        if progress_callback:
            progress_callback(1, 1)

        # --- Generate Findings ---

        # 1. Basic registration info (always report)
        registrar = whois_info.get("registrar") or "Unknown"
        org = whois_info.get("registrant_org") or "Redacted / Not Disclosed"
        country = whois_info.get("registrant_country") or "Unknown"
        created = whois_info.get("creation_date") or "Unknown"
        expires = whois_info.get("expiration_date") or "Unknown"
        nameservers = whois_info.get("nameservers", [])

        evidence_lines = [
            f"Domain: {self.host}",
            f"Registrar: {registrar}",
            f"Organization: {org}",
            f"Country: {country}",
            f"Created: {created}",
            f"Expires: {expires}",
            f"Nameservers: {', '.join(nameservers) if nameservers else 'N/A'}",
        ]

        findings.append({
            "module": "WHOIS Scanner",
            "target": self.host,
            "severity": "INFO",
            "title": "WHOIS Registration Details",
            "description": f"Domain registration information for {self.host}. Includes registrar, dates, and nameserver assignments.",
            "evidence": "\n".join(evidence_lines),
            "remediation": "Enable WHOIS privacy protection to prevent PII exposure if registrant details are publicly visible.",
        })

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
                    days_left = (exp_date - datetime.now()).days
                    if days_left < 0:
                        findings.append({
                            "module": "WHOIS Scanner",
                            "target": self.host,
                            "severity": "CRITICAL",
                            "title": "Domain Registration Expired",
                            "description": f"The domain {self.host} appears to have expired {abs(days_left)} days ago. Expired domains are vulnerable to takeover by third parties.",
                            "evidence": f"Expiration date: {expires}",
                            "remediation": "Renew the domain immediately or enable auto-renewal with your registrar.",
                        })
                    elif days_left <= 30:
                        findings.append({
                            "module": "WHOIS Scanner",
                            "target": self.host,
                            "severity": "HIGH",
                            "title": "Domain Expiring Soon",
                            "description": f"The domain {self.host} expires in {days_left} day(s). Losing control of a domain can cause service disruption and enable phishing.",
                            "evidence": f"Expiration date: {expires} ({days_left} days remaining)",
                            "remediation": "Renew the domain immediately and enable auto-renewal.",
                        })
            except Exception:
                pass

        # 3. Check for DNSSEC status
        dnssec = whois_info.get("dnssec", "").lower()
        if dnssec and "unsigned" in dnssec:
            findings.append({
                "module": "WHOIS Scanner",
                "target": self.host,
                "severity": "MEDIUM",
                "title": "DNSSEC Not Enabled",
                "description": "DNSSEC is not configured for this domain. Without DNSSEC, DNS responses can be spoofed by attackers (DNS cache poisoning).",
                "evidence": f"DNSSEC status: {whois_info.get('dnssec', 'unsigned')}",
                "remediation": "Enable DNSSEC signing with your DNS provider and registrar.",
            })

        # 4. Check for exposed registrant information (privacy not enabled)
        if org and org.lower() not in ("redacted", "redacted / not disclosed", "not disclosed", "data protected", ""):
            findings.append({
                "module": "WHOIS Scanner",
                "target": self.host,
                "severity": "LOW",
                "title": "WHOIS Registrant Information Publicly Exposed",
                "description": f"The domain registrant organization ({org}) is publicly visible in WHOIS records. This can be used for social engineering and targeted phishing.",
                "evidence": f"Registrant Organization: {org}\nRegistrant Country: {country}",
                "remediation": "Enable WHOIS privacy protection (domain privacy) through your registrar.",
            })

        return {
            "domain": self.host,
            "whois_server": whois_server,
            "raw_length": len(raw_whois),
            "info": whois_info,
            "findings": findings,
        }

Class = WhoisScanner
