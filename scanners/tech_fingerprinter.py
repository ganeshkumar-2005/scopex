"""
scanners/tech_fingerprinter.py — Technology fingerprinting scanner (v2 async rewrite).
"""
from __future__ import annotations

import re
from typing import Dict, List

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner

# Simple local CVE database for common server software
_CVE_DATABASE = {
    "Apache/2.4.49": [("CVE-2021-41773", "CRITICAL", "Path traversal and file disclosure in Apache 2.4.49")],
    "Apache/2.4.50": [("CVE-2021-42013", "CRITICAL", "Path traversal and RCE in Apache 2.4.50")],
    "nginx/1.18.0": [("CVE-2021-23017", "HIGH", "1-byte memory overwrite in resolver module")],
    "WordPress/6.0": [("CVE-2022-21661", "HIGH", "SQL injection via WP_Query")],
    "PHP/8.1.0-dev": [("RCE-Backdoor", "CRITICAL", "User-Agentt backdoor RCE signature")],
}


class TechFingerprinter(BaseScanner):
    """Async technology fingerprinting scanner."""

    async def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        technologies: Dict[str, str] = {}

        resp = await self.get(self.ctx.target)
        if resp is None:
            return []

        headers = {k.lower(): v for k, v in resp.headers.items()}
        html = resp.text

        # Header fingerprinting
        server = headers.get("server", "")
        if server:
            technologies["Server"] = server

        x_powered = headers.get("x-powered-by", "")
        if x_powered:
            technologies["Framework"] = x_powered

        set_cookie = headers.get("set-cookie", "")
        if "PHPSESSID" in set_cookie:
            technologies["Language"] = "PHP"
        elif "JSESSIONID" in set_cookie:
            technologies["Language"] = "Java"

        # HTML/JS fingerprinting
        if "wp-content" in html or "wp-includes" in html:
            match = re.search(r'generator" content="WordPress\s?([0-9.]+)"', html, re.IGNORECASE)
            version = match.group(1) if match else "Unknown"
            technologies["CMS"] = f"WordPress/{version}"

        if "jquery" in html.lower():
            technologies["JS Library"] = "jQuery"

        if "react" in html.lower() or "data-reactroot" in html:
            technologies["Frontend Framework"] = "React"
        elif "ng-app" in html or "angular" in html.lower():
            technologies["Frontend Framework"] = "Angular"

        # Register discovered technologies in context
        for tech_val in technologies.values():
            self.ctx.add_technology(tech_val)

        # CVE matching
        for category, tech_val in technologies.items():
            for vuln_key, cves in _CVE_DATABASE.items():
                if vuln_key.lower() in tech_val.lower():
                    for cve_id, severity, desc in cves:
                        findings.append(self.finding(
                            title=f"Known CVE in {category}: {cve_id}",
                            severity=severity,
                            description=f"Detected '{tech_val}' matches known vulnerability: {desc}",
                            evidence={"technology": tech_val, "cve": cve_id, "category": category},
                            remediation="Update the affected software to the latest secure release.",
                            cve=cve_id if cve_id.startswith("CVE") else None,
                            tags=["tech", "cve", category.lower()],
                        ))

        return findings
