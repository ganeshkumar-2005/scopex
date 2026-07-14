"""
scanners/vuln_scanner.py — Vulnerability Scanner (v2 async rewrite).

Detects misc web server configurations and common vulnerabilities:
  - CORS origin reflections and matching bypasses
  - Clickjacking headers (X-Frame-Options, CSP frame-ancestors)
  - Open redirect (common parameters)
  - Sensitive file exposure (with custom-404 filtering & body verification)
  - Dangerous HTTP methods (PUT)
  - CRLF injection in parameter reflection
  - Host header injection
  - security.txt (RFC 9116 compliance audit)
"""
from __future__ import annotations

import urllib.parse
from typing import Dict, List, Optional

import httpx

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner


class VulnScanner(BaseScanner):
    """
    Async vulnerability scanner.
    Implements base checks for misconfigurations and common web application flaws.
    """

    def __init__(self, context: ScanContext, client: httpx.AsyncClient) -> None:
        super().__init__(context, client)
        self._custom_404_fingerprint: Optional[Dict[str, any]] = None

    # ------------------------------------------------------------------
    # Custom 404 fingerprint helper
    # ------------------------------------------------------------------

    async def _fingerprint_custom_404(self) -> None:
        """
        Request a guaranteed-nonexistent path and record the server's
        response characteristics so we can distinguish real files from
        custom 404 pages that return HTTP 200.
        """
        canary_path = "/this-page-definitely-does-not-exist-8f3k2j"
        parsed = urllib.parse.urlparse(self.target)
        canary_url = f"{parsed.scheme}://{parsed.netloc}{canary_path}"
        try:
            resp = await self.get(canary_url)
            if resp is None:
                self._custom_404_fingerprint = None
                return

            body_lower = resp.text.lower()
            key_phrases = set()
            for phrase in [
                "not found", "404", "page not found", "does not exist",
                "page you requested", "cannot be found", "no longer available",
                "error", "sorry",
            ]:
                if phrase in body_lower:
                    key_phrases.add(phrase)

            self._custom_404_fingerprint = {
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "key_phrases": key_phrases,
            }
        except httpx.RequestError as e:
            self.log.debug(f"Custom 404 calibration failed: {e}")
            self.add_error("Custom 404 Calibration HTTP Request", e)
            self._custom_404_fingerprint = None
        except Exception as e:
            self.log.debug(f"Custom 404 calibration failed: {e}")
            self.add_error("Custom 404 Calibration Generic Exception", e)
            self._custom_404_fingerprint = None

    def _looks_like_custom_404(self, response: httpx.Response) -> bool:
        """
        Return True if *response* matches the custom-404 fingerprint,
        indicating the server returned its generic "not found" page with
        an HTTP 200 status code.
        """
        if self._custom_404_fingerprint is None:
            return False

        fp = self._custom_404_fingerprint

        # If the canary itself got a non-200, the server uses proper status
        # codes — no custom-404 filtering needed.
        if fp["status_code"] != 200:
            return False

        # The response we're testing must also be 200 to be a false positive
        if response.status_code != 200:
            return False

        body_lower = response.text.lower()

        # Heuristic 1: content length within ±15 % of the canary
        resp_len = len(response.content)
        fp_len = fp["content_length"]
        if fp_len > 0:
            length_ratio = abs(resp_len - fp_len) / fp_len
            if length_ratio < 0.15:
                return True

        # Heuristic 2: most of the canary's key phrases appear in this body
        if fp["key_phrases"]:
            matched = sum(1 for p in fp["key_phrases"] if p in body_lower)
            if matched >= len(fp["key_phrases"]) * 0.6:
                return True

        return False

    # ------------------------------------------------------------------
    # CORS checks
    # ------------------------------------------------------------------

    async def _check_cors(self, findings: List[Finding]) -> None:
        """Checks for CORS origin reflections and misconfigurations."""
        # --- Arbitrary evil origin ---
        headers = {"Origin": "https://evil.com"}
        response = await self.get(self.target, headers=headers)
        if response is not None:
            allow_origin = response.headers.get("Access-Control-Allow-Origin")
            allow_creds = response.headers.get("Access-Control-Allow-Credentials")

            if allow_origin == "https://evil.com" and allow_creds == "true":
                findings.append(self.finding(
                    title="CORS Over-Permissive Origin Reflection with Credentials Allowed",
                    severity="HIGH",
                    description=(
                        "The server dynamically reflects the Origin header back in "
                        "Access-Control-Allow-Origin and enables Access-Control-Allow-Credentials, "
                        "allowing third-party sites to perform authenticated actions on behalf of the user."
                    ),
                    evidence={
                        "origin_sent": "https://evil.com",
                        "Access-Control-Allow-Origin": allow_origin,
                        "Access-Control-Allow-Credentials": allow_creds,
                    },
                    remediation=(
                        "Do not allow dynamic reflection of the Origin header unless validated "
                        "against an explicit whitelist of trusted origins. Avoid wildcard origins "
                        "when Allow-Credentials is true."
                    ),
                    tags=["cors", "misconfiguration"],
                ))
            elif allow_origin == "*":
                findings.append(self.finding(
                    title="CORS Wildcard Policy Allowed",
                    severity="LOW",
                    description="The server allows all origins via Access-Control-Allow-Origin: *.",
                    evidence={"Access-Control-Allow-Origin": "*"},
                    remediation=(
                        "Ensure this is intended for public content. If the resource contains "
                        "sensitive data, restrict access to authorized origins."
                    ),
                    tags=["cors", "wildcard"],
                ))

        # --- Null origin ---
        await self._cors_probe(
            findings,
            origin="null",
            label="Null Origin",
            description="The server accepts the 'null' Origin, which attackers can forge via sandboxed iframes or data: URIs."
        )

        # --- Subdomain matching bypass ---
        parsed = urllib.parse.urlparse(self.target)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme or "https"

        evil_subdomain = f"{scheme}://evil.{hostname}"
        await self._cors_probe(
            findings,
            origin=evil_subdomain,
            label="Subdomain Matching Bypass",
            description=f"The server trusts arbitrary subdomains of {hostname}. An attacker controlling a subdomain (e.g. via subdomain takeover) can steal credentials cross-origin."
        )

        # --- Suffix matching bypass ---
        evil_suffix = f"{scheme}://{hostname}.evil.com"
        await self._cors_probe(
            findings,
            origin=evil_suffix,
            label="Suffix Matching Bypass",
            description=f"The server appears to match origins by suffix rather than exact domain, allowing {hostname}.evil.com to be trusted."
        )

        # --- Protocol downgrade (http vs https) ---
        if scheme == "https":
            http_origin = f"http://{hostname}"
            await self._cors_probe(
                findings,
                origin=http_origin,
                label="Protocol Downgrade",
                description="The HTTPS server trusts an HTTP origin. An active network attacker can downgrade the origin to HTTP and exfiltrate data."
            )

    async def _cors_probe(self, findings: List[Finding], origin: str, label: str, description: str) -> None:
        """Send a single CORS probe and record a finding if credentials enabled."""
        resp = await self.get(self.target, headers={"Origin": origin})
        if resp is None:
            return
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == origin and acac.lower() == "true":
            findings.append(self.finding(
                title=f"CORS Misconfiguration: {label}",
                severity="HIGH",
                description=description,
                evidence={
                    "origin_sent": origin,
                    "Access-Control-Allow-Origin": acao,
                    "Access-Control-Allow-Credentials": acac,
                },
                remediation=(
                    "Validate the Origin header against a strict whitelist. "
                    "Do not reflect arbitrary origins when credentials are enabled."
                ),
                tags=["cors", label.lower().replace(" ", "-")],
            ))

    # ------------------------------------------------------------------
    # Clickjacking
    # ------------------------------------------------------------------

    def _check_clickjacking(self, findings: List[Finding], headers: dict) -> None:
        """Checks for clickjacking protection headers."""
        x_frame = headers.get("x-frame-options", "").lower()
        csp = headers.get("content-security-policy", "").lower()

        has_xframe = "deny" in x_frame or "sameorigin" in x_frame
        has_csp_frame = "frame-ancestors" in csp

        if not has_xframe and not has_csp_frame:
            findings.append(self.finding(
                title="Clickjacking Vulnerability (Missing Framing Protections)",
                severity="MEDIUM",
                description=(
                    "The site does not restrict framing via X-Frame-Options or "
                    "Content-Security-Policy (frame-ancestors directive), leaving users vulnerable to clickjacking attacks."
                ),
                evidence={
                    "X-Frame-Options": headers.get("x-frame-options", "None"),
                    "Content-Security-Policy": headers.get("content-security-policy", "None"),
                },
                remediation=(
                    "Set X-Frame-Options to DENY or SAMEORIGIN, or add the 'frame-ancestors' directive "
                    "to your Content-Security-Policy."
                ),
                tags=["clickjacking", "headers"],
            ))

    # ------------------------------------------------------------------
    # Open redirect
    # ------------------------------------------------------------------

    async def _check_open_redirect(self, findings: List[Finding]) -> None:
        """Tests common open redirect parameters."""
        redirect_payloads = [
            "https://google.com",
            "//google.com",
            "/\\google.com"
        ]
        redirect_params = [
            "url", "redirect", "redirect_url", "redirect_uri",
            "return", "return_to", "returnTo", "return_path",
            "next", "continue",
            "dest", "destination",
            "redir", "out", "view",
            "go", "goto",
            "login_url", "image_url",
        ]

        test_urls = [self.target] + [u for u in self.ctx.discovered_urls if "?" in u]

        for base_url in test_urls[:5]:
            try:
                parsed_base = urllib.parse.urlparse(base_url)
                base_params = urllib.parse.parse_qs(parsed_base.query)
            except ValueError as e:
                self.add_error("Open Redirect URL Parse ValueError", e)
                continue
            except Exception as e:
                self.add_error("Open Redirect URL Parse Generic Exception", e)
                continue

            for param in redirect_params:
                for payload in redirect_payloads:
                    params_to_send = {k: v[0] for k, v in base_params.items()}
                    params_to_send[param] = payload
                    query = urllib.parse.urlencode(params_to_send)
                    test_url = parsed_base._replace(query=query).geturl()

                    try:
                        response = await self.get(test_url, follow_redirects=False)
                        if response is not None and response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get("Location", "")
                            if location:
                                is_match = False
                                try:
                                    parsed_loc = urllib.parse.urlparse(location)
                                    netloc_lower = parsed_loc.netloc.lower()
                                    if netloc_lower:
                                        host_only = netloc_lower.split(':')[0]
                                        if host_only == "google.com" or host_only.endswith(".google.com"):
                                            is_match = True
                                    else:
                                        stripped = location.replace('\\', '/').lstrip('/')
                                        if stripped.startswith("google.com"):
                                            next_char = stripped[10:11]
                                            if next_char in ("", "/", "?", "#"):
                                                is_match = True
                                except Exception:
                                    pass

                                if is_match:
                                    findings.append(self.finding(
                                        title="Open Redirect Vulnerability Detected",
                                        severity="HIGH",
                                        description=(
                                            f"The application redirects a user to an external destination based on "
                                            f"user-controlled parameter '{param}' without proper validation."
                                        ),
                                        evidence={
                                            "test_url": test_url,
                                            "status_code": response.status_code,
                                            "location_header": location,
                                        },
                                        remediation=(
                                            "Implement strict whitelisting for redirection targets, validate parameters "
                                            "against local routes only, or force local redirects by stripping external host names."
                                        ),
                                        target=test_url,
                                        tags=["open-redirect"],
                                    ))
                                    return
                    except httpx.RequestError as e:
                        self.add_error("Open Redirect Probe HTTP Request", e)
                    except Exception as e:
                        self.add_error("Open Redirect Probe Generic Exception", e)

    # ------------------------------------------------------------------
    # Sensitive file probing
    # ------------------------------------------------------------------

    async def _check_sensitive_files(self, findings: List[Finding]) -> None:
        """Checks for exposure of sensitive configuration and backup files."""
        def _validate_env(text):
            return any(kw in text for kw in ("DB_", "API_", "KEY", "SECRET", "PASSWORD"))

        def _validate_git_config(text):
            return "[core]" in text

        def _validate_robots(text):
            return "Disallow" in text or "Allow" in text or "User-agent" in text

        def _validate_sitemap(text):
            return "<urlset" in text or "<sitemapindex" in text

        def _validate_composer(text):
            return '"name"' in text and '"require"' in text

        def _validate_package_json(text):
            return '"name"' in text and ('"dependencies"' in text or '"version"' in text)

        def _validate_htaccess(text):
            return any(kw in text for kw in (
                "RewriteEngine", "RewriteRule", "RewriteCond",
                "Options", "DirectoryIndex", "AuthType", "Require",
                "Order", "Deny", "Allow", "Header",
            ))

        def _validate_wp_config(text):
            return "<?php" in text and any(kw in text for kw in (
                "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST",
                "table_prefix", "AUTH_KEY",
            ))

        sensitive_paths = [
            (".env", "Environment configuration file exposed", "CRITICAL", _validate_env),
            (".git/config", "Git repository configuration file exposed", "CRITICAL", _validate_git_config),
            ("robots.txt", "Robots.txt available (Information)", "INFO", _validate_robots),
            ("sitemap.xml", "Sitemap.xml available (Information)", "INFO", _validate_sitemap),
            ("wp-config.php", "WordPress configuration file backup exposure", "CRITICAL", _validate_wp_config),
            (".htaccess", "Apache config file exposure", "CRITICAL", _validate_htaccess),
            ("composer.json", "Composer dependency profile exposure", "INFO", _validate_composer),
            ("package.json", "Node.js dependency profile exposure", "INFO", _validate_package_json),
        ]

        parsed = urllib.parse.urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path, description, severity, validator in sensitive_paths:
            test_url = f"{base_url}/{path}"
            try:
                response = await self.get(test_url)
                if response is None or response.status_code != 200:
                    continue

                if self._looks_like_custom_404(response):
                    continue

                body = response.text or ""
                if not validator(body):
                    continue

                findings.append(self.finding(
                    title=f"Sensitive File Exposed: {path}",
                    severity=severity,
                    description=(
                        f"The sensitive file '{path}' is publicly accessible on the web server, "
                        "which could leak internal configurations or software dependencies."
                    ),
                    evidence={
                        "url": test_url,
                        "preview": body.splitlines()[0][:100] if body.splitlines() else "Empty",
                    },
                    remediation=(
                        "Restrict access to configuration, database, backup, and environment files "
                        "in your web server configurations."
                    ),
                    target=test_url,
                    tags=["sensitive-file", path.replace("/", "-").replace(".", "")],
                ))
            except httpx.RequestError as e:
                self.add_error(f"Sensitive File Probe HTTP Request {path}", e)
            except Exception as e:
                self.add_error(f"Sensitive File Probe Generic Exception {path}", e)

    # ------------------------------------------------------------------
    # Dangerous HTTP methods
    # ------------------------------------------------------------------

    async def _check_dangerous_methods(self, findings: List[Finding]) -> None:
        """Tests for PUT HTTP method exposure."""
        try:
            response_put = await self.request("PUT", self.target, json={"test": "data"})
            if response_put is not None and response_put.status_code in (200, 201, 204):
                findings.append(self.finding(
                    title="Dangerous HTTP Method Allowed: PUT",
                    severity="HIGH",
                    description=(
                        "The server accepts the PUT method on root URL, potentially "
                        "allowing unauthorized file creation or modification."
                    ),
                    evidence={"status_code": response_put.status_code},
                    remediation="Restrict HTTP methods in web server configurations. Disable PUT, DELETE, and TRACE.",
                    tags=["http-methods", "dangerous"],
                ))
        except httpx.RequestError as e:
            self.add_error("Dangerous HTTP Methods PUT Probe HTTP Request", e)
        except Exception as e:
            self.add_error("Dangerous HTTP Methods PUT Probe Generic Exception", e)

    # ------------------------------------------------------------------
    # CRLF injection
    # ------------------------------------------------------------------

    async def _check_crlf_injection(self, findings: List[Finding]) -> None:
        """Tests CRLF injection in parameter reflection."""
        crlf_payload = "test%0d%0aSet-Cookie:%20scopex_crlf=1"
        test_url = f"{self.target}?q={crlf_payload}" if "?" not in self.target else f"{self.target}&q={crlf_payload}"
        try:
            response = await self.get(test_url)
            if response is not None and "scopex_crlf" in response.headers.get("Set-Cookie", ""):
                findings.append(self.finding(
                    title="CRLF Injection Vulnerability Detected",
                    severity="HIGH",
                    description=(
                        "The application reflects user input into HTTP headers without stripping "
                        "Carriage Return (CR) and Line Feed (LF) characters, allowing HTTP response splitting or session fixation."
                    ),
                    evidence={"header": "Set-Cookie", "value": response.headers.get("Set-Cookie")},
                    remediation=(
                        "Sanitize user inputs before printing them into HTTP response headers, "
                        "ensuring CR and LF characters are stripped or encoded."
                    ),
                    target=test_url,
                    tags=["crlf-injection"],
                ))
        except httpx.RequestError as e:
            self.add_error("CRLF Injection Probe HTTP Request", e)
        except Exception as e:
            self.add_error("CRLF Injection Probe Generic Exception", e)

    # ------------------------------------------------------------------
    # Host header injection
    # ------------------------------------------------------------------

    async def _check_host_header_injection(self, findings: List[Finding]) -> None:
        """Tests for host header injection vulnerability."""
        try:
            headers = {"Host": "malicious-host.com"}
            response = await self.get(self.target, headers=headers)
            if response is not None:
                if "malicious-host.com" in response.text or "malicious-host.com" in response.headers.get("Location", ""):
                    findings.append(self.finding(
                        title="Host Header Injection Vulnerability Detected",
                        severity="MEDIUM",
                        description=(
                            "The application dynamically constructs links, redirects, or header parameters "
                            "using the client-provided HTTP Host header without validation."
                        ),
                        evidence={"host_sent": "malicious-host.com"},
                        remediation=(
                            "Configure the web server to only bind/respond to the explicit server name "
                            "or configured hostname. Do not trust or reflect the incoming Host header."
                        ),
                        tags=["host-header-injection"],
                    ))
        except httpx.RequestError as e:
            self.add_error("Host Header Injection Probe HTTP Request", e)
        except Exception as e:
            self.add_error("Host Header Injection Probe Generic Exception", e)

    # ------------------------------------------------------------------
    # security.txt compliance check
    # ------------------------------------------------------------------

    async def _check_security_txt(self, findings: List[Finding]) -> None:
        """Check presence and RFC 9116 compliance of security.txt."""
        security_txt_paths = [
            "/.well-known/security.txt",
            "/security.txt",
        ]
        found = False
        found_url = ""
        body = ""

        parsed = urllib.parse.urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in security_txt_paths:
            url = f"{base_url}{path}"
            try:
                resp = await self.get(url)
                if resp is not None and resp.status_code == 200 and resp.text:
                    content_type = resp.headers.get("Content-Type", "")
                    if "text/" in content_type or "octet-stream" in content_type:
                        if "Contact:" in resp.text or "contact:" in resp.text.lower():
                            found = True
                            found_url = url
                            body = resp.text
                            break
            except httpx.RequestError as e:
                self.add_error(f"Security.txt Probe HTTP Request {path}", e)
                continue
            except Exception as e:
                self.add_error(f"Security.txt Probe Generic Exception {path}", e)
                continue

        if not found:
            findings.append(self.finding(
                title="Missing security.txt (RFC 9116)",
                severity="INFO",
                description=(
                    "No valid security.txt file was found at /.well-known/security.txt "
                    "or /security.txt. RFC 9116 recommends publishing a security.txt so "
                    "that security researchers can report vulnerabilities responsibly."
                ),
                evidence={"paths_probed": [f"{base_url}{p}" for p in security_txt_paths]},
                remediation=(
                    "Create a security.txt file at /.well-known/security.txt with at "
                    "least the 'Contact:' and 'Expires:' fields as specified by RFC 9116. "
                    "See https://securitytxt.org for a generator."
                ),
                tags=["security-txt", "rfc-9116"],
            ))
            return

        body_lower = body.lower()
        issues = []

        if "contact:" not in body_lower:
            issues.append("Missing required 'Contact' field")
        if "expires:" not in body_lower:
            issues.append("Missing required 'Expires' field")
        if "/.well-known/" not in found_url:
            issues.append("File is at /security.txt instead of the recommended /.well-known/security.txt")
        if found_url.startswith("http://"):
            issues.append("security.txt served over plain HTTP instead of HTTPS")

        if issues:
            findings.append(self.finding(
                title="security.txt Found but Not Fully RFC 9116 Compliant",
                severity="INFO",
                description=(
                    "A security.txt file was found but has compliance issues per RFC 9116: "
                    + "; ".join(issues) + "."
                ),
                evidence={
                    "url": found_url,
                    "issues": issues,
                    "preview": body[:200],
                },
                remediation=(
                    "Update your security.txt to include all required fields (Contact, Expires) "
                    "and serve it from /.well-known/security.txt over HTTPS. "
                    "See https://securitytxt.org for guidance."
                ),
                target=found_url,
                tags=["security-txt", "rfc-9116"],
            ))
        else:
            findings.append(self.finding(
                title="security.txt Present and RFC 9116 Compliant",
                severity="INFO",
                description="A valid security.txt file was found that meets RFC 9116 requirements.",
                evidence={
                    "url": found_url,
                    "preview": body[:200],
                },
                remediation="No action required. Ensure the Expires date is kept up to date.",
                target=found_url,
                tags=["security-txt", "rfc-9116"],
            ))

    # ------------------------------------------------------------------
    # Main scan orchestrator
    # ------------------------------------------------------------------

    async def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        response = await self.get(self.target)
        if response is None:
            return [self.finding(
                title="Vulnerability Scanner: Target Unreachable",
                severity="INFO",
                description="Could not connect to target to perform vulnerability scanning.",
                evidence={"target": self.target},
                remediation="Verify target accessibility.",
            )]

        headers = {k.lower(): v for k, v in response.headers.items()}

        # Fingerprint custom 404
        await self._fingerprint_custom_404()

        # Run audits
        await self._check_cors(findings)
        self._check_clickjacking(findings, headers)
        await self._check_open_redirect(findings)
        await self._check_sensitive_files(findings)
        await self._check_dangerous_methods(findings)
        await self._check_crlf_injection(findings)
        await self._check_host_header_injection(findings)
        await self._check_security_txt(findings)

        return findings
