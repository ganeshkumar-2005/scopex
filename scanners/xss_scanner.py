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
    ('"attribute', '" autofocus onfocus=alert(1) x="', "attr break dquote"),
    ("attribute", "' autofocus onfocus=alert(1) x='", "attr break squote"),
    ("attribute", '" onmouseover=alert(1) "', "attr onmouseover"),
    # JavaScript context
    ("javascript", "'; alert(1); //", "js singlequote break"),
    ("javascript", '"; alert(1); //', "js doublequote break"),
    # URL/href context
    ("url", "javascript:alert(1)", "javascript href"),
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
        """Static analysis for DOM XSS source/sink flows in <script> blocks."""
        dom_findings = []
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            scripts = soup.find_all("script")
        except Exception:
            return []

        seen_keys: Set[tuple] = set()
        for idx, script in enumerate(scripts):
            script_text = script.string or ""
            found_sources = [s for s in DOM_SOURCES if s in script_text]
            found_sinks = [s for s in DOM_SINKS if s in script_text]
            if not (found_sources and found_sinks):
                continue

            key = (tuple(sorted(found_sources)), tuple(sorted(found_sinks)))
            if key in seen_keys:
                continue
            seen_keys.add(key)

            severity = "INFO" if csp_blocks else "MEDIUM"
            mitigation = " (Mitigated by CSP)" if csp_blocks else ""
            dom_findings.append(self.finding(
                title=f"Potential DOM-Based XSS{mitigation}",
                severity=severity,
                description=(
                    f"Client-side JavaScript uses dangerous sources ({', '.join(found_sources)}) "
                    f"flowing to dangerous sinks ({', '.join(found_sinks)}). "
                    + ("CSP headers may block exploitation." if csp_blocks
                       else "This pattern enables DOM-based XSS attacks.")
                ),
                evidence={
                    "page_url": page_url,
                    "script_block": idx + 1,
                    "sources": found_sources,
                    "sinks": found_sinks,
                    "snippet": script_text[:300],
                    "csp_present": csp_blocks,
                },
                remediation=(
                    "Avoid using innerHTML/eval with user-controlled data. "
                    "Use DOMPurify for sanitization. Set a strict Content-Security-Policy."
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
            except Exception:
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
            except Exception:
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
                except Exception:
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
        for context, payload, payload_desc in XSS_PAYLOADS:
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
                    },
                    remediation="Verify encoding is applied consistently across all output contexts.",
                    target=target_url,
                    tags=["xss", "reflected", "mitigated"],
                )

            # Raw reflection check
            if payload in resp.text:
                severity = "HIGH"
                verified = True
                mitigation_note = ""

                if csp_blocks:
                    severity = "MEDIUM"
                    verified = False
                    mitigation_note = " (CSP may prevent execution)"

                # Optional Playwright verification
                if _PLAYWRIGHT_AVAILABLE and not csp_blocks:
                    executed = await self._verify_with_playwright(target_url, payload)
                    if executed is True:
                        severity = "CRITICAL"
                        verified = True
                    elif executed is False:
                        severity = "MEDIUM"
                        mitigation_note = " (Payload reflected but not executed in browser)"

                return self.finding(
                    title=f"Reflected XSS{mitigation_note}",
                    severity=severity,
                    description=(
                        f"Parameter '{param_name}' reflects untrusted input without sanitization. "
                        f"Context: {context}. Payload: {payload_desc}.{mitigation_note}"
                    ),
                    evidence={
                        "url": target_url,
                        "method": method,
                        "parameter": param_name,
                        "payload": payload,
                        "context": context,
                        "payload_description": payload_desc,
                        "csp_present": csp_blocks,
                        "playwright_verified": _PLAYWRIGHT_AVAILABLE and not csp_blocks,
                    },
                    remediation=(
                        "Apply context-aware HTML encoding to all dynamic output. "
                        "Implement a Content-Security-Policy that blocks unsafe-inline scripts."
                    ),
                    target=target_url,
                    verified=verified,
                    tags=["xss", "reflected", context],
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

    async def _verify_with_playwright(self, url: str, payload: str) -> Optional[bool]:
        """Use Playwright to verify if the XSS payload actually executes in a browser."""
        if not _PLAYWRIGHT_AVAILABLE:
            return None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                dialog_fired = [False]

                async def handle_dialog(dialog):
                    dialog_fired[0] = True
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)
                try:
                    await page.goto(url, wait_until="networkidle", timeout=10000)
                    await asyncio.sleep(1)
                except Exception:
                    pass
                finally:
                    await browser.close()
                return dialog_fired[0]
        except Exception as exc:
            self.log.debug(f"Playwright verification error: {exc}")
            return None
