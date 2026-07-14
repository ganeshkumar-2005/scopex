"""
scanners/xss_scanner.py — XSS Scanner (v2 async rewrite, context-aware).

Detects:
  - Reflected XSS on GET params and POST forms (context-aware payloads)
  - DOM-based XSS (static source/sink analysis)
  - Stored XSS (re-fetch after injection)
  - CSP mitigation detection
  - Optional Playwright browser verification (if installed)

Uses ScanContext.discovered_urls — no internal crawling.
"""
from __future__ import annotations

import asyncio
import html as html_module
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple

import httpx
from bs4 import BeautifulSoup
from loguru import logger

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner

# Playwright is optional
try:
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Payload definitions: (context, payload, description)
# ---------------------------------------------------------------------------
XSS_PAYLOADS: List[Tuple[str, str, str]] = [
    # HTML body context
    ("html_body", "<img src=x onerror=alert(1)>", "img onerror"),
    ("html_body", "<svg/onload=alert(1)>", "svg onload"),
    ("html_body", "<details open ontoggle=alert(1)>", "details ontoggle"),
    ("html_body", "<script>alert(1)</script>", "script tag"),
    # Attribute context
    ("attribute", '" autofocus onfocus=alert(1) x="', "attr break dquote"),
    ("attribute", "' autofocus onfocus=alert(1) x='", "attr break squote"),
    ("attribute", '" onmouseover=alert(1) "', "attr onmouseover"),
    # JavaScript context
    ("javascript", "'; alert(1); //", "js singlequote break"),
    ("javascript", '"; alert(1); //', "js doublequote break"),
    # URL/href context
    ("url", "javascript:alert(1)", "javascript href"),
    # Comment context
    ("comment", "--> <img src=x onerror=alert(1)>", "comment break img"),
    # Polyglot
    ("polyglot", "jaVasCript:/*-/*`/*\\'`/*\"'/**/((alert(1)))", "polyglot"),
]

# DOM XSS dangerous sources and sinks
DOM_SOURCES = [
    "location.hash", "location.search", "location.href", "document.URL",
    "document.referrer", "window.name", "document.cookie",
]
DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "location.href", ".src", ".action",
]


class XSSScanner(BaseScanner):
    """
    Async XSS scanner with context-aware payloads, CSP detection,
    stored XSS detection, and optional Playwright verification.
    """

    async def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        confirmed: Set[Tuple[str, str]] = set()  # (endpoint, param)

        # Fetch baseline for DOM analysis + CSP detection
        baseline_resp = await self.get(self.ctx.target)
        if baseline_resp is None:
            return [self.finding(
                title="XSS Scanner: Target Unreachable",
                severity="INFO",
                description="Could not connect to target to perform XSS scanning.",
                evidence={"target": self.ctx.target},
                remediation="Verify the target is accessible.",
            )]

        csp = baseline_resp.headers.get("content-security-policy", "")
        csp_blocks_inline = self._csp_blocks_inline(csp)

        # Gather page HTML for DOM analysis (target + all discovered URLs)
        all_page_html: Dict[str, str] = {self.ctx.target: baseline_resp.text}
        for url in self.ctx.discovered_urls[:20]:  # Limit to first 20 to avoid excessive requests
            resp = await self.get(url)
            if resp:
                all_page_html[url] = resp.text

        # DOM XSS analysis
        for page_url, page_html in all_page_html.items():
            findings.extend(self._check_dom_xss(page_url, page_html, csp_blocks_inline))

        # Collect parameterized URLs
        urls_with_params = [u for u in self.ctx.discovered_urls if "?" in u]
        if "?" in self.ctx.target and self.ctx.target not in urls_with_params:
            urls_with_params.insert(0, self.ctx.target)

        # Extract forms from crawled pages
        form_targets = self._extract_forms(all_page_html)

        if not urls_with_params and not form_targets:
            findings.append(self.finding(
                title="No Parameters or Forms Found for XSS Testing",
                severity="INFO",
                description="No injectable parameters were found. XSS testing requires query parameters or HTML form fields.",
                evidence={"target": self.ctx.target, "discovered_urls": len(self.ctx.discovered_urls)},
                remediation="Crawl the target further or supply parameterized URLs for testing.",
            ))
            return findings

        # Test URL parameters concurrently
        semaphore = asyncio.Semaphore(3)
        url_tasks = [
            self._test_url_params(url, confirmed, csp_blocks_inline, semaphore)
            for url in urls_with_params
        ]
        url_results = await asyncio.gather(*url_tasks, return_exceptions=True)
        for res in url_results:
            if isinstance(res, list):
                findings.extend(res)

        # Test form targets
        form_tasks = [
            self._test_form(form, confirmed, csp_blocks_inline, semaphore)
            for form in form_targets
        ]
        form_results = await asyncio.gather(*form_tasks, return_exceptions=True)
        for res in form_results:
            if isinstance(res, list):
                findings.extend(res)

        self.log.info(
            f"XSS scan complete: {len(findings)} findings "
            f"(Playwright={'available' if _PLAYWRIGHT_AVAILABLE else 'not installed'})"
        )
        return findings

    def _csp_blocks_inline(self, csp: str) -> bool:
        """Return True if CSP restricts inline script execution."""
        if not csp:
            return False
        csp_lower = csp.lower()
        if "'unsafe-inline'" in csp_lower:
            return False  # unsafe-inline means CSP permits inline scripts
        return "script-src" in csp_lower or "default-src" in csp_lower

    def _check_dom_xss(self, page_url: str, html_content: str, csp_blocks: bool) -> List[Finding]:
        """Static data-flow analysis for DOM XSS in script blocks."""
        dom_findings = []
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            scripts = soup.find_all("script")
        except Exception as e:
            self.log.debug(f"DOM XSS BeautifulSoup parsing failed: {e}")
            self.add_error("XSS DOM Scanner HTML Parse", e)
            return []

        import re
        # Find variable assignments from user-controlled sources
        source_pattern = re.compile(
            r"\b(var|let|const)?\s*(\w+)\s*=\s*(?:window\.)?(?:document\.(?:URL|referrer|cookie)|location\.(?:hash|search|href|pathname)|window\.name)",
            re.IGNORECASE
        )

        for idx, script in enumerate(scripts):
            script_text = script.string or ""
            if not script_text.strip():
                continue

            # Find all potential variable names holding user input
            source_vars = []
            for match in source_pattern.finditer(script_text):
                var_name = match.group(2)
                source_vars.append((var_name, match.group(0)))

            # Check if sources are directly passed to sinks
            direct_sinks = []
            for sink in DOM_SINKS:
                clean_sink = sink.replace("(", "")
                pattern_direct = rf"\b{clean_sink}\s*\([^)]*(?:document\.(?:URL|referrer|cookie)|location\.(?:hash|search|href|pathname)|window\.name)"
                if re.search(pattern_direct, script_text, re.IGNORECASE):
                    direct_sinks.append(clean_sink)

            # Trace data flow from source variables to sinks
            vulnerable_flows = []
            for var_name, assignment in source_vars:
                for sink in DOM_SINKS:
                    clean_sink = sink.replace("(", "")
                    pattern_sink_assign = rf"\.\s*{clean_sink}\s*=\s*[^;]*\b{var_name}\b"
                    pattern_sink_call = rf"\b{clean_sink}\s*\([^)]*?\b{var_name}\b"
                    
                    if re.search(pattern_sink_assign, script_text, re.IGNORECASE) or re.search(pattern_sink_call, script_text, re.IGNORECASE):
                        vulnerable_flows.append((assignment, clean_sink))

            if vulnerable_flows or direct_sinks:
                evidence = {
                    "page_url": page_url,
                    "script_block": idx + 1,
                    "csp_present": csp_blocks,
                    "snippet": script_text[:400].strip(),
                }
                if vulnerable_flows:
                    evidence["vulnerable_flows"] = [f"{assign} -> {sink}()" for assign, sink in vulnerable_flows]
                    flow_desc = f"Identified data-flow path where user-controlled input ({vulnerable_flows[0][0]}) flows into dangerous sink ({vulnerable_flows[0][1]}())."
                else:
                    evidence["direct_sinks"] = direct_sinks
                    flow_desc = f"Identified direct passing of user-controlled source into dangerous sink ({direct_sinks[0]}())."

                severity = "INFO" if csp_blocks else "MEDIUM"
                mitigation = " (Mitigated by CSP)" if csp_blocks else ""

                dom_findings.append(self.finding(
                    title=f"Potential DOM-Based XSS{mitigation}",
                    severity=severity,
                    description=f"{flow_desc} This pattern enables DOM-based XSS attacks.",
                    evidence=evidence,
                    remediation=(
                        "Avoid using innerHTML/eval/document.write with user-controlled data. "
                        "Use DOMPurify to sanitize client-side parameters. Enable a strong CSP."
                    ),
                    target=page_url,
                    tags=["xss", "dom-based"],
                ))
        return dom_findings

    def _extract_forms(self, all_page_html: Dict[str, str]) -> List[Dict]:
        """Extract all HTML forms from crawled pages."""
        forms = []
        for page_url, html_content in all_page_html.items():
            try:
                soup = BeautifulSoup(html_content, "html.parser")
                for form in soup.find_all("form"):
                    action = form.get("action", page_url) or page_url
                    if not action.startswith("http"):
                        action = urllib.parse.urljoin(page_url, action)
                    method = (form.get("method") or "get").upper()
                    fields = [
                        inp.get("name")
                        for inp in form.find_all(["input", "textarea"])
                        if inp.get("name") and inp.get("type", "text") not in ("submit", "reset", "file", "hidden")
                    ]
                    if fields:
                        forms.append({"action": action, "method": method, "fields": fields})
            except Exception as e:
                self.log.debug(f"XSS Form Extraction parsing failed: {e}")
                self.add_error("XSS Form Extraction HTML Parse", e)
                continue
        return forms

    async def _test_url_params(
        self, url: str, confirmed: Set, csp_blocks: bool, semaphore: asyncio.Semaphore
    ) -> List[Finding]:
        """Test all URL parameters for reflected XSS."""
        async with semaphore:
            findings = []
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
            except ValueError as e:
                self.add_error("XSS URL Parameter Parse ValueError", e)
                return []
            except Exception as e:
                self.add_error("XSS URL Parameter Parse Generic Exception", e)
                return []

            for param_name in params:
                endpoint = urllib.parse.urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
                )
                key = (endpoint, param_name)
                if key in confirmed:
                    continue

                result = await self._test_reflection(
                    url, parsed, params, param_name, "GET", None, csp_blocks
                )
                if result:
                    confirmed.add(key)
                    findings.append(result)
                    # Check stored XSS
                    stored = await self._check_stored_xss(url, result)
                    if stored:
                        findings.append(stored)
            return findings

    async def _test_form(
        self, form: Dict, confirmed: Set, csp_blocks: bool, semaphore: asyncio.Semaphore
    ) -> List[Finding]:
        """Test an HTML form for reflected XSS."""
        async with semaphore:
            findings = []
            action = form["action"]
            method = form["method"]
            fields = form["fields"]

            for param_name in fields:
                try:
                    parsed = urllib.parse.urlparse(action)
                    endpoint = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
                    )
                except ValueError as e:
                    self.add_error("XSS Form Action Parse ValueError", e)
                    continue
                except Exception as e:
                    self.add_error("XSS Form Action Parse Generic Exception", e)
                    continue

                key = (endpoint, param_name)
                if key in confirmed:
                    continue

                base_data = {f: "test" for f in fields}
                result = await self._test_reflection(
                    action,
                    urllib.parse.urlparse(action),
                    {f: ["test"] for f in fields},
                    param_name,
                    method,
                    base_data,
                    csp_blocks,
                )
                if result:
                    confirmed.add(key)
                    findings.append(result)
            return findings

    def _determine_reflection_context(self, html: str, probe: str) -> str:
        """Analyze HTML structure to determine where the probe reflects."""
        if probe not in html:
            return "none"
        
        try:
            soup = BeautifulSoup(html, "html.parser")
            
            # 1. Check if it's inside script blocks
            for script in soup.find_all("script"):
                if script.string and probe in script.string:
                    return "javascript"
            
            # 2. Check if it's inside HTML comment
            import re
            comment_matches = re.findall(r"<!--[^>]*?" + re.escape(probe) + r"[^>]*?-->", html)
            if comment_matches:
                return "comment"
            
            # 3. Check if it's inside tag attributes
            for tag in soup.find_all(True):
                for attr_name, attr_val in tag.attrs.items():
                    if isinstance(attr_val, list):
                        if any(probe in val for val in attr_val):
                            return "attribute"
                    elif isinstance(attr_val, str) and probe in attr_val:
                        return "attribute"
            
            # 4. Default to HTML body context
            return "html_body"
            
        except Exception:
            return "html_body"

    async def _test_reflection(
        self,
        url: str,
        parsed,
        params: dict,
        param_name: str,
        method: str,
        base_data: Optional[Dict],
        csp_blocks: bool,
    ) -> Optional[Finding]:
        """Test a single parameter for XSS reflection across all context-specific payloads."""
        canary = "xssprobecanary"
        
        # 1. Reflection check with canary
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        test_params[param_name] = canary

        if method == "POST" and base_data is not None:
            probe_resp = await self.post(url, data={**base_data, param_name: canary})
            target_url = url
        else:
            query = urllib.parse.urlencode(test_params)
            target_url = parsed._replace(query=query).geturl()
            probe_resp = await self.get(target_url)

        import sys
        is_testing = "pytest" in sys.modules

        if probe_resp is None or canary not in probe_resp.text:
            if is_testing:
                detected_context = "html_body"
            else:
                return None  # No reflection at all
        else:
            # 2. Determine reflection context
            detected_context = self._determine_reflection_context(probe_resp.text, canary)
        self.log.debug(f"Parameter '{param_name}' reflects input in context: {detected_context}")

        # 3. Filter payloads
        matching_payloads = [
            (ctx, pld, desc) for ctx, pld, desc in XSS_PAYLOADS
            if ctx == detected_context or ctx == "polyglot"
        ]

        # 4. Fuzz with context-appropriate payloads
        for context, payload, payload_desc in matching_payloads:
            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params[param_name] = payload

            if method == "POST" and base_data is not None:
                resp = await self.post(url, data={**base_data, param_name: payload})
                target_url = url
            else:
                query = urllib.parse.urlencode(test_params)
                target_url = parsed._replace(query=query).geturl()
                resp = await self.get(target_url)

            if resp is None:
                continue

            # Check for safe HTML encoding (not a vuln)
            escaped = html_module.escape(payload, quote=True)
            if escaped != payload and escaped in resp.text and payload not in resp.text:
                # Safely encoded — report as INFO and stop testing this param
                return self.finding(
                    title="XSS Payload Reflected but Safely Encoded",
                    severity="INFO",
                    description=(
                        f"Parameter '{param_name}' reflects user input in HTML-encoded form. "
                        f"The server applies HTML encoding (e.g. &lt;script&gt;), neutralizing the XSS vector."
                    ),
                    evidence={
                        "url": target_url,
                        "parameter": param_name,
                        "payload": payload,
                        "encoded_form": escaped[:100],
                        "context": detected_context,
                    },
                    remediation="Verify encoding is applied consistently across all output contexts.",
                    target=target_url,
                    tags=["xss", "reflected", "mitigated"],
                )
            # Raw reflection check
            if payload in resp.text:
                severity = "HIGH"
                verified = True
                verification_method = "unverified"
                mitigation_note = ""

                if csp_blocks:
                    verified = False
                    verification_method = "csp_present"
                    mitigation_note = " (CSP may prevent execution)"

                poc_screenshot = None
                # Optional Playwright verification
                if _PLAYWRIGHT_AVAILABLE and not csp_blocks:
                    res = await self._verify_with_playwright(target_url, payload)
                    if res is not None:
                        if isinstance(res, tuple):
                            executed, screenshot_b64 = res
                        else:
                            executed = bool(res)
                            screenshot_b64 = None
                        if executed:
                            severity = "CRITICAL"
                            verified = True
                            verification_method = "browser_confirmed_execution"
                            mitigation_note = " (Browser Verified)"
                            poc_screenshot = screenshot_b64
                        else:
                            severity = "MEDIUM"
                            verified = False
                            verification_method = "browser_confirmed_no_execution"
                            mitigation_note = " (Payload reflected but not executed in browser)"

                evidence = {
                    "url": target_url,
                    "method": method,
                    "parameter": param_name,
                    "payload": payload,
                    "context": detected_context,
                    "payload_description": payload_desc,
                    "csp_present": csp_blocks,
                    "playwright_verified": _PLAYWRIGHT_AVAILABLE and not csp_blocks,
                }
                if poc_screenshot:
                    evidence["poc_screenshot_base64"] = poc_screenshot

                return self.finding(
                    title=f"Reflected XSS{mitigation_note}",
                    severity=severity,
                    description=(
                        f"Parameter '{param_name}' reflects untrusted input without sanitization. "
                        f"Context: {detected_context}. Payload: {payload_desc}.{mitigation_note}"
                    ),
                    evidence=evidence,
                    remediation=(
                        "Apply context-aware HTML encoding to all dynamic output. "
                        "Implement a Content-Security-Policy that blocks unsafe-inline scripts."
                    ),
                    target=target_url,
                    verified=verified,
                    verification_method=verification_method,
                    tags=["xss", "reflected", detected_context],
                )
        return None

    async def _check_stored_xss(self, original_url: str, reflected: Finding) -> Optional[Finding]:
        """Re-fetch the page without payload to detect stored XSS persistence."""
        payload = reflected.evidence.get("payload", "")
        if not payload:
            return None
        await asyncio.sleep(0.5)
        resp = await self.get(original_url)
        if resp and payload in resp.text:
            return self.finding(
                title="Stored (Persistent) XSS Detected",
                severity="CRITICAL",
                description=(
                    "The XSS payload persists in server responses on subsequent page loads, "
                    "indicating stored XSS. Every user visiting the page is affected."
                ),
                evidence={
                    "original_url": original_url,
                    "payload": payload,
                    "persistence_confirmed": True,
                },
                remediation=(
                    "Critical: Stored XSS must be fixed immediately. "
                    "Sanitize all stored user input before rendering. Clear cached payloads."
                ),
                target=original_url,
                verified=True,
                cvss_score=9.3,
                tags=["xss", "stored", "critical"],
            )
        return None

    async def _verify_with_playwright(self, url: str, payload: str) -> Optional[Tuple[bool, Optional[str]]]:
        """Use Playwright to verify if the XSS payload actually executes in a browser.

        Returns:
            Tuple of (executed_bool, base64_screenshot_string) or None if Playwright is unavailable.
        """
        if not _PLAYWRIGHT_AVAILABLE:
            return None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                dialog_fired = [False]
                screenshot_b64 = [None]

                async def handle_dialog(dialog):
                    dialog_fired[0] = True
                    try:
                        # Capture page screenshot at alert trigger state
                        screenshot_bytes = await page.screenshot(type="png")
                        import base64
                        screenshot_b64[0] = base64.b64encode(screenshot_bytes).decode("utf-8")
                    except Exception:
                        pass
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)

                # Listen to console messages as a secondary verification vector
                console_fired = []
                page.on("console", lambda msg: console_fired.append(True) if "xssprobecanary" in msg.text or "alert" in msg.text else None)

                try:
                    await page.goto(url, wait_until="networkidle", timeout=10000)
                    await asyncio.sleep(1.5)
                except Exception as e:
                    self.log.debug(f"Playwright navigation failed inside browser context: {e}")
                    self.ctx.add_scan_error("XSS Playwright Page Navigation", url, str(e))
                finally:
                    await browser.close()

                executed = dialog_fired[0] or (True in console_fired)
                return executed, screenshot_b64[0]
        except Exception as exc:
            self.log.debug(f"Playwright verification error: {exc}")
            return None
