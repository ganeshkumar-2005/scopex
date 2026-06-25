import html
import urllib.parse
from bs4 import BeautifulSoup
from utils.helpers import make_web_request
from .crawler import Crawler

class XSSScanner:
    def __init__(self, target: str, discovered_urls: list = None, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.discovered_urls = discovered_urls or []
        self.timeout = timeout
        
        # Test payloads representing different injection contexts
        self.payloads = [
            # HTML body context
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            # Attribute context
            "\" onmouseover=\"alert(1)",
            "' onmouseover='alert(1)",
            "javascript:alert(1)",
            # Filter evasion polyglots
            "jaVasCript:/*-/*`/*\\'`/*\"'/**/((alert(1)))",
            "<svg><animatetransform onbegin=alert(1)>"
        ]

    def _check_dom_xss(self, html_content: str) -> list:
        """Parses HTML and searches for potential DOM XSS sources and sinks."""
        dom_findings = []
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Search all scripts
        scripts = soup.find_all("script")
        
        dangerous_sinks = ["innerHTML", "document.write", "eval", "setTimeout", "setInterval", "location.href"]
        dangerous_sources = ["location.hash", "location.search", "document.URL", "document.referrer"]
        
        for idx, script in enumerate(scripts):
            script_text = script.string or ""
            found_sources = [src for src in dangerous_sources if src in script_text]
            found_sinks = [sink for sink in dangerous_sinks if sink in script_text]
            
            if found_sources and found_sinks:
                dom_findings.append({
                    "context": f"Script block {idx + 1}",
                    "sources": found_sources,
                    "sinks": found_sinks,
                    "snippet": script_text[:200]
                })
        return dom_findings

    def _is_html_encoded(self, payload: str, response_text: str) -> bool:
        """Checks if the payload appears in the response only in HTML-encoded form.
        
        Returns True if an HTML-encoded version of the payload (e.g., &lt;script&gt;)
        is present but the raw payload is NOT — meaning the server safely encoded it.
        """
        # Build the HTML-escaped version of the payload
        escaped_payload = html.escape(payload, quote=True)
        # Only relevant if the escaped form differs from the raw payload
        if escaped_payload == payload:
            return False
        # Check if the escaped form appears in the response
        return escaped_payload in response_text

    def scan(self, progress_callback=None) -> dict:
        findings = []
        
        try:
            baseline = make_web_request(self.url, timeout=self.timeout)
            baseline_html = baseline.text
        except Exception as e:
            return {
                "error": f"Failed to connect to target to scan XSS: {str(e)}",
                "findings": []
            }
            
        # Parse DOM XSS threats first (on the root page)
        dom_threats = self._check_dom_xss(baseline_html)
        seen_targets = set()
        for dt in dom_threats:
            seen_targets.add((self.url, "dom", dt["context"]))
            findings.append({
                "module": "XSS Scanner",
                "target": self.url,
                "severity": "MEDIUM",
                "title": "Potential DOM-Based XSS Detected",
                "description": f"The client-side JavaScript utilizes dynamic sources ({', '.join(dt['sources'])}) and outputs to dangerous sinks ({', '.join(dt['sinks'])}) which can facilitate DOM-based Cross-Site Scripting.",
                "evidence": f"Location: {dt['context']}\nSources found: {dt['sources']}\nSinks found: {dt['sinks']}\nSnippet: {dt['snippet']}",
                "remediation": "Avoid using dangerous sinks like innerHTML or eval. Use safe alternatives such as textContent or innerText, and implement robust sanitization using libraries like DOMPurify."
            })

        # Run Crawler (pass make_web_request to enable mocking in tests)
        crawler = Crawler(self.url, timeout=self.timeout, make_request_fn=make_web_request)
        try:
            crawl_results = crawler.crawl()
            urls_with_params = crawl_results["urls_with_params"]
            form_targets = crawl_results["form_targets"]
            all_pages_html = crawl_results.get("all_pages_html", {})
        except Exception:
            urls_with_params = []
            form_targets = []
            all_pages_html = {}

        # Loop over every (url, html) pair in crawl_result["all_pages_html"]
        for page_url, page_html in all_pages_html.items():
            # Skip it if it's the root URL (already checked earlier)
            if page_url == self.url:
                continue

            page_dom_threats = self._check_dom_xss(page_html)
            for dt in page_dom_threats:
                dedup_key = (page_url, "dom", dt["context"])
                if dedup_key in seen_targets:
                    continue
                seen_targets.add(dedup_key)

                findings.append({
                    "module": "XSS Scanner",
                    "target": page_url,
                    "severity": "MEDIUM",
                    "title": "Potential DOM-Based XSS Detected",
                    "description": f"The client-side JavaScript utilizes dynamic sources ({', '.join(dt['sources'])}) and outputs to dangerous sinks ({', '.join(dt['sinks'])}) which can facilitate DOM-based Cross-Site Scripting.",
                    "evidence": f"Page URL: {page_url}\nLocation: {dt['context']}\nSources found: {dt['sources']}\nSinks found: {dt['sinks']}\nSnippet: {dt['snippet']}",
                    "remediation": "Avoid using dangerous sinks like innerHTML or eval. Use safe alternatives such as textContent or innerText, and implement robust sanitization using libraries like DOMPurify."
                })

        # Calculate total steps across all targets
        total_steps = 0
        for u in urls_with_params:
            try:
                p_url = urllib.parse.urlparse(u)
                p = urllib.parse.parse_qs(p_url.query)
                total_steps += len(p) * len(self.payloads)
            except Exception:
                pass
        for form in form_targets:
            total_steps += len(form["fields"]) * len(self.payloads)

        if total_steps == 0:
            # No parameters or forms to test — log INFO and skip gracefully
            findings.append({
                "module": "XSS Scanner",
                "target": self.url,
                "severity": "INFO",
                "title": "No URL Parameters Found to Test",
                "description": "The target URL does not contain any query string parameters. Reflected XSS testing requires injectable parameters.",
                "evidence": f"URL: {self.url}\nQuery string: (empty)",
                "remediation": "Provide a URL with query parameters (e.g., ?search=term) for reflected XSS testing."
            })
            if progress_callback:
                progress_callback(1, 1)
            return {
                "target": self.url,
                "findings": findings
            }

        current_step = 0
        confirmed_findings = set()  # Keyed by (endpoint, param)

        # 1. Test Reflected XSS on GET parameters of URLs
        for current_url in urls_with_params:
            try:
                parsed = urllib.parse.urlparse(current_url)
                current_params = urllib.parse.parse_qs(parsed.query)
                endpoint = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
            except Exception:
                continue

            for param, values in current_params.items():
                if (endpoint, param) in confirmed_findings:
                    current_step += len(self.payloads)
                    if progress_callback:
                        progress_callback(current_step, total_steps)
                    continue

                for payload in self.payloads:
                    current_step += 1
                    if progress_callback:
                        progress_callback(current_step, total_steps)

                    test_params = current_params.copy()
                    test_params[param] = [payload]

                    query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = parsed._replace(query=query).geturl()

                    try:
                        res = make_web_request(test_url, timeout=self.timeout)
                        if not res:
                            continue

                        if payload in res.text:
                            confirmed_findings.add((endpoint, param))
                            findings.append({
                                "module": "XSS Scanner",
                                "target": test_url,
                                "severity": "HIGH",
                                "title": "Reflected Cross-Site Scripting (XSS) Vulnerability",
                                "description": f"The application reflects untrusted input parameter '{param}' directly back into the response without sanitization or HTML encoding.",
                                "evidence": f"Endpoint: {endpoint}\nMethod: GET\nParameter: {param}\nPayload: {payload}\nReflected in response body: True",
                                "remediation": "Apply context-aware output encoding to all dynamic values printed in HTML body, attributes, and scripts. Utilize Content-Security-Policy headers."
                            })
                            break

                        elif self._is_html_encoded(payload, res.text):
                            confirmed_findings.add((endpoint, param))
                            findings.append({
                                "module": "XSS Scanner",
                                "target": test_url,
                                "severity": "INFO",
                                "title": "Payload Reflected but Safely Encoded",
                                "description": f"The parameter '{param}' value is reflected in the response, but the server applies HTML encoding (e.g., &lt;script&gt; instead of <script>), neutralizing the XSS vector.",
                                "evidence": f"Endpoint: {endpoint}\nMethod: GET\nParameter: {param}\nPayload: {payload}\nReflected as HTML-encoded: True",
                                "remediation": "No immediate action required. The server correctly encodes reflected input. Continue to verify encoding is applied consistently across all contexts."
                            })
                            break

                    except Exception:
                        pass

        # 2. Test Reflected XSS on HTML form fields (GET and POST)
        for form in form_targets:
            action = form["action"]
            method = form["method"]
            fields = form["fields"]

            try:
                parsed_action = urllib.parse.urlparse(action)
                endpoint = urllib.parse.urlunparse((parsed_action.scheme, parsed_action.netloc, parsed_action.path, '', '', ''))
            except Exception:
                endpoint = action

            for param in fields:
                if (endpoint, param) in confirmed_findings:
                    current_step += len(self.payloads)
                    if progress_callback:
                        progress_callback(current_step, total_steps)
                    continue

                for payload in self.payloads:
                    current_step += 1
                    if progress_callback:
                        progress_callback(current_step, total_steps)

                    # Build form data: set target parameter to payload, others to "test"
                    form_data = {f: "test" for f in fields}
                    form_data[param] = payload

                    try:
                        if method == "POST":
                            target_url = action
                            res = make_web_request(action, method="POST", data=form_data, timeout=self.timeout)
                        else:  # GET
                            query = urllib.parse.urlencode(form_data, doseq=True)
                            target_url = parsed_action._replace(query=query).geturl()
                            res = make_web_request(target_url, method="GET", timeout=self.timeout)

                        if not res:
                            continue

                        if payload in res.text:
                            confirmed_findings.add((endpoint, param))
                            findings.append({
                                "module": "XSS Scanner",
                                "target": target_url,
                                "severity": "HIGH",
                                "title": "Reflected Cross-Site Scripting (XSS) Vulnerability",
                                "description": f"The application reflects untrusted input parameter '{param}' directly back into the response without sanitization or HTML encoding.",
                                "evidence": f"Endpoint: {endpoint}\nMethod: {method}\nParameter: {param}\nPayload: {payload}\nReflected in response body: True",
                                "remediation": "Apply context-aware output encoding to all dynamic values printed in HTML body, attributes, and scripts. Utilize Content-Security-Policy headers."
                            })
                            break

                        elif self._is_html_encoded(payload, res.text):
                            confirmed_findings.add((endpoint, param))
                            findings.append({
                                "module": "XSS Scanner",
                                "target": target_url,
                                "severity": "INFO",
                                "title": "Payload Reflected but Safely Encoded",
                                "description": f"The parameter '{param}' value is reflected in the response, but the server applies HTML encoding (e.g., &lt;script&gt; instead of <script>), neutralizing the XSS vector.",
                                "evidence": f"Endpoint: {endpoint}\nMethod: {method}\nParameter: {param}\nPayload: {payload}\nReflected as HTML-encoded: True",
                                "remediation": "No immediate action required. The server correctly encodes reflected input. Continue to verify encoding is applied consistently across all contexts."
                            })
                            break

                    except Exception:
                        pass

        if progress_callback:
            progress_callback(total_steps, total_steps)

        return {
            "target": self.url,
            "findings": findings
        }

Class = XSSScanner
