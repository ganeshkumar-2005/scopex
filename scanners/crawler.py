"""
scanners/crawler.py — Async web crawler for ScopeX v2.

AsyncCrawler uses the shared httpx.AsyncClient from the orchestrator.
Legacy sync Crawler class is preserved for backward compatibility with
scanners not yet migrated (sqli_scanner, xss_scanner old versions).
"""
from __future__ import annotations

import asyncio
import urllib.parse
from typing import Dict, List, Optional, Set

import httpx
from bs4 import BeautifulSoup
from loguru import logger

from core.context import ScanContext


class AsyncCrawler:
    """
    Async web crawler. Uses the shared httpx.AsyncClient session.
    Results are stored in ScanContext so all scanners share a single crawl.

    Returns dict with:
      - urls_with_params: List[str] — pages with query parameters
      - form_targets:     List[dict] — {action, method, fields}
      - pages_visited:    int
      - all_pages_html:   Dict[url, html_text]
    """

    MAX_PAGES = 40  # Hard limit to prevent runaway crawls
    MAX_CONCURRENT = 5  # Max parallel page fetches

    def __init__(self, ctx: ScanContext, client: httpx.AsyncClient) -> None:
        self.ctx = ctx
        self.client = client
        self.root_url = ctx.target
        self.log = logger.bind(scanner="AsyncCrawler")

        try:
            parsed = urllib.parse.urlparse(self.root_url)
            self._root_host = (parsed.hostname or "").lower()
        except Exception as e:
            logger.debug(f"[AsyncCrawler Init] failed to parse target {self.root_url}: {e}")
            self.ctx.add_scan_error("AsyncCrawler Init urlparse", self.root_url, str(e))
            self._root_host = ""

    async def crawl(self) -> Dict:
        """Run the async crawl and return results dict."""
        visited: Set[str] = set()
        urls_with_params: Set[str] = set()
        form_targets: List[Dict] = []
        all_pages_html: Dict[str, str] = {}
        seen_forms: Set[tuple] = set()
        queue: List[str] = [self.root_url]

        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)

        while queue and len(visited) < self.MAX_PAGES:
            # Take a batch of URLs to fetch concurrently
            batch = queue[:self.MAX_CONCURRENT]
            queue = queue[self.MAX_CONCURRENT:]

            tasks = [
                self._fetch_page(url, semaphore)
                for url in batch
                if url not in visited
            ]
            if not tasks:
                continue

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for url, res in zip(batch, results):
                if url in visited:
                    continue
                visited.add(url)

                if isinstance(res, Exception) or res is None:
                    continue

                html_text, status = res
                if status != 200 or not html_text:
                    continue

                all_pages_html[url] = html_text

                # Parse URLs and forms
                try:
                    new_urls, new_forms = self._parse_page(url, html_text)
                except Exception as exc:
                    self.log.debug(f"Parse error on {url}: {exc}")
                    continue

                for new_url in new_urls:
                    if new_url not in visited and new_url not in queue:
                        queue.append(new_url)
                    parsed = urllib.parse.urlparse(new_url)
                    if parsed.query:
                        urls_with_params.add(new_url)

                for form in new_forms:
                    fkey = (form["action"], form["method"], tuple(form["fields"]))
                    if fkey not in seen_forms:
                        seen_forms.add(fkey)
                        form_targets.append(form)

        # Also include root URL itself if it has parameters
        try:
            root_parsed = urllib.parse.urlparse(self.root_url)
            if root_parsed.query:
                urls_with_params.add(self.root_url)
        except Exception as e:
            self.log.debug(f"[AsyncCrawler Root Query Check] failed: {e}")
            self.ctx.add_scan_error("AsyncCrawler Root Query Check", self.root_url, str(e))

        self.log.info(
            f"Crawl done: {len(visited)} pages, {len(urls_with_params)} param-URLs, "
            f"{len(form_targets)} forms"
        )
        return {
            "urls_with_params": sorted(urls_with_params),
            "form_targets": form_targets,
            "pages_visited": len(visited),
            "all_pages_html": all_pages_html,
        }

    async def _fetch_page(self, url: str, semaphore: asyncio.Semaphore) -> Optional[tuple]:
        """Fetch a single page; returns (html_text, status_code) or None."""
        async with semaphore:
            try:
                resp = await self.client.get(url, follow_redirects=True, timeout=self.ctx.timeout)
                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type.lower():
                    return None
                return (resp.text, resp.status_code)
            except httpx.RequestError as e:
                self.log.debug(f"[_fetch_page] HTTP RequestError on {url}: {e}")
                self.ctx.add_scan_error("AsyncCrawler HTTP Fetch", url, str(e))
                return None
            except Exception as e:
                self.log.debug(f"[_fetch_page] generic error on {url}: {e}")
                self.ctx.add_scan_error("AsyncCrawler Generic Fetch", url, str(e))
                return None

    def _parse_page(self, page_url: str, html_text: str) -> tuple:
        """Extract links and forms from a page. Returns (new_urls, forms)."""
        soup = BeautifulSoup(html_text, "html.parser")
        new_urls: List[str] = []
        forms: List[Dict] = []

        # Extract links
        for a_tag in soup.find_all("a", href=True):
            href = (a_tag["href"] or "").strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            try:
                resolved = urllib.parse.urljoin(page_url, href)
                parsed = urllib.parse.urlparse(resolved)
                if parsed.scheme not in ("http", "https"):
                    continue
                clean = urllib.parse.urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, "")
                )
                if self._is_same_host(clean):
                    new_urls.append(clean)
            except Exception as e:
                self.log.debug(f"[_parse_page Link Processing] failed on {href} from {page_url}: {e}")
                self.ctx.add_scan_error("AsyncCrawler link parse", page_url, str(e))
                continue

        # Extract forms
        for form in soup.find_all("form"):
            action = form.get("action") or page_url
            try:
                resolved_action = urllib.parse.urljoin(page_url, action)
                parsed_action = urllib.parse.urlparse(resolved_action)
                clean_action = urllib.parse.urlunparse(
                    (parsed_action.scheme, parsed_action.netloc, parsed_action.path,
                     parsed_action.params, parsed_action.query, "")
                )
            except Exception as e:
                self.log.debug(f"[_parse_page Form Processing] failed on action {action} from {page_url}: {e}")
                self.ctx.add_scan_error("AsyncCrawler form action parse", page_url, str(e))
                clean_action = page_url

            if not self._is_same_host(clean_action):
                continue

            method = (form.get("method") or "GET").upper()
            if method not in ("GET", "POST"):
                method = "GET"

            fields = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                tag_type = tag.get("type", "text")
                if name and tag_type not in ("submit", "reset", "file", "hidden"):
                    fields.append(name)
            fields = list(dict.fromkeys(fields))  # Deduplicate, preserve order

            if fields:
                forms.append({"action": clean_action, "method": method, "fields": fields})

        return new_urls, forms

    def _is_same_host(self, url: str) -> bool:
        """Check if URL belongs to the same host as the scan target."""
        try:
            host = (urllib.parse.urlparse(url).hostname or "").lower()
            return host == self._root_host
        except Exception as e:
            self.log.debug(f"[_is_same_host] failed on {url}: {e}")
            self.ctx.add_scan_error("AsyncCrawler _is_same_host", url, str(e))
            return False


# ---------------------------------------------------------------------------
# Legacy sync Crawler (kept for backward compatibility)
# Scanners not yet migrated to async still import this directly.
# ---------------------------------------------------------------------------
class Crawler:
    """
    Legacy synchronous crawler. Preserved for backward compatibility.
    New code should use AsyncCrawler instead.
    """
    def __init__(self, target_url: str, timeout: float = 5.0, make_request_fn=None):
        from utils.helpers import make_web_request
        self.target_url = target_url
        self.root_url = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"
        self.timeout = timeout
        self.make_request_fn = make_request_fn or make_web_request

    def _is_same_host(self, url: str) -> bool:
        try:
            url_host = (urllib.parse.urlparse(url).hostname or "").lower()
            root_host = (urllib.parse.urlparse(self.root_url).hostname or "").lower()
            return url_host == root_host
        except Exception as e:
            from loguru import logger
            logger.debug(f"[Legacy Crawler _is_same_host] failed on {url}: {e}")
            return False

    def crawl(self) -> dict:
        visited: Set[str] = set()
        urls_with_params: Set[str] = set()
        form_targets = []
        seen_forms: Set[tuple] = set()
        all_pages_html: Dict[str, str] = {}
        queue = [self.root_url]

        while queue and len(visited) < 30:
            current_url = queue.pop(0)
            try:
                parsed_current = urllib.parse.urlparse(current_url)
                clean_current = urllib.parse.urlunparse(
                    (parsed_current.scheme, parsed_current.netloc, parsed_current.path,
                     parsed_current.params, parsed_current.query, "")
                )
            except Exception as e:
                from loguru import logger
                logger.debug(f"[Legacy Crawler parse_current] failed on {current_url}: {e}")
                continue

            if clean_current in visited or not self._is_same_host(clean_current):
                continue

            try:
                response = self.make_request_fn(clean_current, timeout=self.timeout)
                visited.add(clean_current)
                if not response or response.status_code != 200:
                    continue
                content_type = response.headers.get("content-type", "") if hasattr(response, "headers") else ""
                if content_type and "text/html" not in content_type.lower():
                    continue

                all_pages_html[clean_current] = response.text
                soup = BeautifulSoup(response.text, "html.parser")

                for form in soup.find_all("form"):
                    action = form.get("action", "") or ""
                    resolved_action = urllib.parse.urljoin(clean_current, action)
                    try:
                        pa = urllib.parse.urlparse(resolved_action)
                        clean_action = urllib.parse.urlunparse(
                            (pa.scheme, pa.netloc, pa.path, pa.params, pa.query, "")
                        )
                    except Exception as e:
                        from loguru import logger
                        logger.debug(f"[Legacy Crawler form action] failed on {resolved_action}: {e}")
                        clean_action = resolved_action

                    if not self._is_same_host(clean_action):
                        continue

                    method = (form.get("method") or "GET").upper()
                    fields = list(dict.fromkeys(
                        inp.get("name") for inp in form.find_all(["input", "textarea", "select"])
                        if inp.get("name") and inp.get("type", "text") not in ("submit", "reset", "file", "hidden")
                    ))
                    form_key = (clean_action, method, tuple(fields))
                    if form_key not in seen_forms and fields:
                        seen_forms.add(form_key)
                        form_targets.append({"action": clean_action, "method": method, "fields": fields})

                for a_tag in soup.find_all("a", href=True):
                    href = (a_tag["href"] or "").strip()
                    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue
                    resolved = urllib.parse.urljoin(clean_current, href)
                    try:
                        pu = urllib.parse.urlparse(resolved)
                        if pu.scheme not in ("http", "https"):
                            continue
                        clean_url = urllib.parse.urlunparse(
                            (pu.scheme, pu.netloc, pu.path, pu.params, pu.query, "")
                        )
                    except Exception as e:
                        from loguru import logger
                        logger.debug(f"[Legacy Crawler link parse] failed on {resolved}: {e}")
                        continue
                    if self._is_same_host(clean_url):
                        if pu.query:
                            urls_with_params.add(clean_url)
                        if clean_url not in visited and clean_url not in queue:
                            queue.append(clean_url)

            except httpx.RequestError as e:
                from loguru import logger
                logger.debug(f"[Legacy Crawler] HTTP request error on {clean_current}: {e}")
                visited.add(clean_current)
            except Exception as e:
                from loguru import logger
                logger.debug(f"[Legacy Crawler] generic error on {clean_current}: {e}")
                visited.add(clean_current)

        try:
            rp = urllib.parse.urlparse(self.root_url)
            if rp.query:
                urls_with_params.add(urllib.parse.urlunparse(
                    (rp.scheme, rp.netloc, rp.path, rp.params, rp.query, "")
                ))
        except Exception as e:
            from loguru import logger
            logger.debug(f"[Legacy Crawler root query] failed on {self.root_url}: {e}")

        return {
            "urls_with_params": sorted(urls_with_params),
            "form_targets": form_targets,
            "pages_visited": len(visited),
            "all_pages_html": all_pages_html,
        }
