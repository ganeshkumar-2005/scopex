"""
scanners/header_scanner.py — Security header scanner (v2 async rewrite).

Checks for missing/misconfigured security headers:
  - HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
  - CSP quality analysis (unsafe-inline, unsafe-eval, wildcards)
  - HSTS preload readiness
  - Deprecated header detection (X-XSS-Protection, ALLOW-FROM)
  - Cache-Control audit
  - Information disclosure headers (Server, X-Powered-By)
"""
from __future__ import annotations

import re
from typing import Dict, List

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner


# Security headers to check for presence
_SECURITY_HEADERS = {
    "strict-transport-security": {
        "title": "Missing HTTP Strict Transport Security (HSTS) Header",
        "severity": "MEDIUM",
        "desc": "HSTS instructs the browser to always use HTTPS, preventing SSL stripping attacks.",
        "remedy": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to responses.",
    },
    "content-security-policy": {
        "title": "Missing Content Security Policy (CSP) Header",
        "severity": "HIGH",
        "desc": "CSP restricts resources the browser may load, offering defense-in-depth against XSS.",
        "remedy": "Implement a Content-Security-Policy header. Start with: default-src 'self';",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options Header",
        "severity": "MEDIUM",
        "desc": "X-Content-Type-Options: nosniff prevents MIME-type sniffing attacks.",
        "remedy": "Send 'X-Content-Type-Options: nosniff' header.",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options Header",
        "severity": "MEDIUM",
        "desc": "X-Frame-Options prevents clickjacking by restricting iframe embedding.",
        "remedy": "Send 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP frame-ancestors.",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy Header",
        "severity": "INFO",
        "desc": "Referrer-Policy controls how much referrer information is sent with requests.",
        "remedy": "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy Header",
        "severity": "INFO",
        "desc": "Permissions-Policy controls browser features (camera, geolocation, etc.).",
        "remedy": "Add 'Permissions-Policy: geolocation=(), camera=()'.",
    },
}

# Information disclosure headers
_INFO_HEADERS = {
    "server": ("Web Server Signature Disclosure", "Server header reveals backend software."),
    "x-powered-by": ("Technology Information Disclosure", "X-Powered-By leaks framework info."),
    "x-aspnet-version": ("ASP.NET Version Disclosure", "X-AspNet-Version leaks the .NET version."),
}


class HeaderScanner(BaseScanner):
    """Async security header scanner."""

    async def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        resp = await self.get(self.ctx.target)
        if resp is None:
            return [self.finding(
                title="Header Scanner: Target Unreachable",
                severity="INFO",
                description="Could not connect to the target for header analysis.",
                evidence={"target": self.ctx.target},
                remediation="Verify target accessibility.",
            )]

        headers_found = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing security headers
        for header, info in _SECURITY_HEADERS.items():
            if header not in headers_found:
                findings.append(self.finding(
                    title=info["title"],
                    severity=info["severity"],
                    description=info["desc"],
                    evidence={"missing_header": header, "url": self.ctx.target},
                    remediation=info["remedy"],
                    tags=["headers", "missing"],
                ))
            else:
                val = headers_found[header]
                if header == "strict-transport-security" and "max-age" not in val:
                    findings.append(self.finding(
                        title="Weak HSTS Header Configuration",
                        severity="LOW",
                        description="HSTS header is present but missing max-age or misconfigured.",
                        evidence={"header": "Strict-Transport-Security", "value": val},
                        remediation="Set HSTS to: max-age=31536000; includeSubDomains; preload",
                        tags=["headers", "hsts"],
                    ))

        # CSP quality analysis
        if "content-security-policy" in headers_found:
            self._check_csp_quality(findings, headers_found["content-security-policy"])

        # HSTS preload readiness
        if "strict-transport-security" in headers_found:
            self._check_hsts_preload(findings, headers_found["strict-transport-security"])

        # Deprecated headers
        self._check_deprecated_headers(findings, headers_found)

        # Cache-Control audit
        self._check_cache_control(findings, headers_found)

        # Information disclosure headers
        for header, (title, desc) in _INFO_HEADERS.items():
            if header in headers_found:
                val = headers_found[header]
                is_verbose = any(c.isdigit() for c in val) or len(val.split()) > 1
                severity = "LOW" if is_verbose else "INFO"
                findings.append(self.finding(
                    title=title,
                    severity=severity,
                    description=desc,
                    evidence={"header": header, "value": val},
                    remediation=f"Remove or strip the '{header}' header in your web server config.",
                    tags=["headers", "info-disclosure"],
                ))

        return findings

    # ------------------------------------------------------------------
    # CSP quality analysis
    # ------------------------------------------------------------------

    def _parse_csp(self, csp_value: str) -> dict:
        """Parse CSP header into directive -> sources dict."""
        directives = {}
        for part in csp_value.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directives[tokens[0].lower()] = [s.lower() for s in tokens[1:]]
        return directives

    def _check_csp_quality(self, findings: List[Finding], csp_value: str) -> None:
        directives = self._parse_csp(csp_value)
        issues = []
        script_src = directives.get("script-src", directives.get("default-src", []))
        default_src = directives.get("default-src", [])

        if "'unsafe-inline'" in script_src:
            issues.append("'unsafe-inline' in script-src — allows inline <script> execution")
        elif "'unsafe-inline'" in default_src:
            issues.append("'unsafe-inline' in default-src — allows inline scripts as fallback")
        if "'unsafe-eval'" in script_src:
            issues.append("'unsafe-eval' in script-src — allows eval()/Function()")
        elif "'unsafe-eval'" in default_src:
            issues.append("'unsafe-eval' in default-src — allows eval() as fallback")
        for dname, sources in directives.items():
            if "*" in sources:
                issues.append(f"Wildcard '*' in '{dname}' — allows loading from any origin")
                break
        if "data:" in script_src:
            issues.append("'data:' URI in script-src — attackers can execute scripts via data: URIs")
        if "frame-ancestors" not in directives:
            issues.append("Missing 'frame-ancestors' — page can be framed by any origin")

        if issues:
            findings.append(self.finding(
                title="Content Security Policy (CSP) Weaknesses",
                severity="MEDIUM",
                description="CSP header is present but contains weaknesses reducing XSS protection.",
                evidence={"csp": csp_value[:300], "issues": issues},
                remediation=(
                    "Remove 'unsafe-inline' and 'unsafe-eval' (use nonces/hashes). "
                    "Replace wildcards with explicit origins. Add 'frame-ancestors'."
                ),
                tags=["headers", "csp"],
            ))

    # ------------------------------------------------------------------
    # HSTS preload readiness
    # ------------------------------------------------------------------

    def _check_hsts_preload(self, findings: List[Finding], hsts_value: str) -> None:
        hsts_lower = hsts_value.lower()
        issues = []
        match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
        if match:
            max_age = int(match.group(1))
            if max_age < 31536000:
                issues.append(f"max-age is {max_age}s ({max_age // 86400}d), minimum recommended is 31536000 (1yr)")
        else:
            issues.append("max-age directive is missing or malformed")
        if "includesubdomains" not in hsts_lower:
            issues.append("Missing 'includeSubDomains'")
        if "preload" not in hsts_lower:
            issues.append("Missing 'preload' — not eligible for browser HSTS preload lists")

        if issues:
            findings.append(self.finding(
                title="HSTS Header Not Preload-Ready",
                severity="LOW",
                description="HSTS is present but doesn't meet browser preload list requirements.",
                evidence={"hsts": hsts_value, "issues": issues},
                remediation="Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                tags=["headers", "hsts"],
            ))

    # ------------------------------------------------------------------
    # Deprecated headers
    # ------------------------------------------------------------------

    def _check_deprecated_headers(self, findings: List[Finding], headers: dict) -> None:
        xxss = headers.get("x-xss-protection", "")
        if xxss and xxss.strip().startswith("1"):
            findings.append(self.finding(
                title="Deprecated X-XSS-Protection Header Enabled",
                severity="LOW",
                description=(
                    "X-XSS-Protection is deprecated and removed from modern browsers. "
                    "In legacy browsers it can introduce XSS vulnerabilities."
                ),
                evidence={"header": "X-XSS-Protection", "value": xxss},
                remediation="Remove X-XSS-Protection or set to '0'. Use CSP for XSS mitigation.",
                tags=["headers", "deprecated"],
            ))

        xfo = headers.get("x-frame-options", "")
        if "allow-from" in xfo.lower():
            findings.append(self.finding(
                title="Deprecated X-Frame-Options ALLOW-FROM Directive",
                severity="MEDIUM",
                description="ALLOW-FROM is deprecated and unsupported by modern browsers.",
                evidence={"header": "X-Frame-Options", "value": xfo},
                remediation="Use CSP 'frame-ancestors' instead of X-Frame-Options ALLOW-FROM.",
                tags=["headers", "deprecated"],
            ))

    # ------------------------------------------------------------------
    # Cache-Control audit
    # ------------------------------------------------------------------

    def _check_cache_control(self, findings: List[Finding], headers: dict) -> None:
        cc = headers.get("cache-control", "")
        if not cc:
            findings.append(self.finding(
                title="Missing Cache-Control Header",
                severity="LOW",
                description="No Cache-Control header; responses may be cached by browsers/proxies.",
                evidence={"missing_header": "Cache-Control"},
                remediation="Add 'Cache-Control: no-store, no-cache, must-revalidate' for sensitive pages.",
                tags=["headers", "caching"],
            ))
        elif "no-store" not in cc.lower():
            findings.append(self.finding(
                title="Cache-Control Missing 'no-store' Directive",
                severity="LOW",
                description="Cache-Control is present but lacks 'no-store', allowing response caching.",
                evidence={"header": "Cache-Control", "value": cc},
                remediation="Add 'no-store' to Cache-Control for sensitive responses.",
                tags=["headers", "caching"],
            ))
