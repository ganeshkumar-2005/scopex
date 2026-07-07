"""
scanners/base_scanner.py — Abstract async base class for all ScopeX v2 scanners.

All scanners must inherit from BaseScanner and implement the async scan() method.
This base class provides:
  - WAF-aware HTTP helpers (get / post) with automatic header injection and jitter delays
  - Structured loguru logging bound to the scanner class name
  - A convenience finding() factory method pre-filled with module name and target
  - Request counting for basic rate-limiting awareness
"""
from __future__ import annotations

import asyncio
import random
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx
from loguru import logger

from core.context import ScanContext
from core.findings import Finding


# ---------------------------------------------------------------------------
# Rotating User-Agents for WAF evasion
# ---------------------------------------------------------------------------

_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
]

_ACCEPT_LANGUAGES: List[str] = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.7",
    "es-ES,es;q=0.9,en;q=0.8",
]


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class ScannerError(Exception):
    """Base exception raised by ScopeX scanners."""


class ScannerTimeoutError(ScannerError):
    """Raised when a scanner request times out."""


# ---------------------------------------------------------------------------
# BaseScanner
# ---------------------------------------------------------------------------


class BaseScanner(ABC):
    """
    Abstract async base class for all ScopeX v2 scanners.

    Subclasses must implement :meth:`scan` and may rely on :meth:`get` /
    :meth:`post` for WAF-aware HTTP requests.

    Example::

        class MyScanner(BaseScanner):
            async def scan(self) -> List[Finding]:
                resp = await self.get(self.target)
                if resp is None:
                    return []
                # ... analyse resp ...
                return [self.finding(title="...", severity="HIGH", ...)]
    """

    def __init__(self, context: ScanContext, client: httpx.AsyncClient) -> None:
        """
        Initialise the scanner.

        Args:
            context: Shared :class:`~core.context.ScanContext` containing all
                     runtime configuration (target, timeouts, WAF flags, auth…).
            client:  Pre-configured :class:`httpx.AsyncClient` shared across
                     all scanners in a session for connection-pool reuse.
        """
        self.ctx = context
        self.client = client
        self.log = logger.bind(scanner=self.__class__.__name__)
        self._request_count: int = 0

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def target(self) -> str:
        """Full target URL from the scan context."""
        return self.ctx.target

    @property
    def host(self) -> str:
        """Bare hostname / IP from the scan context."""
        return self.ctx.host

    @property
    def timeout(self) -> float:
        """Per-request timeout in seconds."""
        return self.ctx.timeout

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def scan(self) -> List[Finding]:
        """
        Execute the scan and return a list of :class:`~core.findings.Finding`
        objects.  Must be implemented by every concrete scanner.
        """
        ...

    # ------------------------------------------------------------------
    # Finding factory
    # ------------------------------------------------------------------

    def finding(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: Dict[str, Any],
        remediation: str,
        target: Optional[str] = None,
        cve: Optional[str] = None,
        cvss_score: Optional[float] = None,
        tags: Optional[List[str]] = None,
        verified: bool = False,
        false_positive_risk: str = "LOW",
    ) -> Finding:
        """
        Create a :class:`~core.findings.Finding` pre-filled with this
        scanner's module name and the scan target.

        Args:
            title:               Short human-readable title.
            severity:            One of CRITICAL | HIGH | MEDIUM | LOW | INFO.
            description:         Detailed explanation of the vulnerability.
            evidence:            Dict of proof data (payloads, response snippets…).
            remediation:         Actionable fix guidance.
            target:              Override the target URL (defaults to ctx.target).
            cve:                 Optional CVE identifier string.
            cvss_score:          Optional CVSS v3 base score (0.0–10.0).
            tags:                Optional list of string labels.
            verified:            True if the finding is confirmed exploitable.
            false_positive_risk: ``LOW`` | ``MEDIUM`` | ``HIGH``.

        Returns:
            A fully-populated :class:`~core.findings.Finding` instance.
        """
        return Finding(
            title=title,
            severity=severity,  # type: ignore[arg-type]
            module=self.__class__.__name__,
            description=description,
            evidence=evidence,
            remediation=remediation,
            target=target or self.ctx.target,
            cve=cve,
            cvss_score=cvss_score,
            tags=tags or [],
            verified=verified,
            false_positive_risk=false_positive_risk,  # type: ignore[arg-type]
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_headers(
        self,
        extra: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """
        Construct request headers, injecting auth headers and rotating the
        User-Agent when WAF evasion is enabled.

        Args:
            extra: Additional headers to merge in (take lowest priority,
                   overriding only the defaults — not auth headers).

        Returns:
            A fully-merged ``dict`` of HTTP headers.
        """
        headers: Dict[str, str] = {}

        # Caller-supplied overrides (lowest priority)
        if extra:
            headers.update(extra)

        # Apply rotating User-Agent / Accept-Language for WAF evasion
        if self.ctx.waf_evasion:
            headers["User-Agent"] = random.choice(_USER_AGENTS)
            headers["Accept-Language"] = random.choice(_ACCEPT_LANGUAGES)
            headers["Accept"] = (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            )
            headers["Cache-Control"] = "no-cache"
            headers["Pragma"] = "no-cache"
        else:
            headers.setdefault("User-Agent", _USER_AGENTS[0])

        # Auth headers from context (highest priority — always win)
        if self.ctx.auth and self.ctx.auth.auth_headers:
            headers.update(self.ctx.auth.auth_headers)

        return headers

    async def _maybe_delay(self) -> None:
        """
        Introduce a randomised jitter delay when WAF evasion is active.

        Delay magnitude is governed by the ``waf_evasion_profile``:
          - ``stealth``    → 1.0–3.0 s
          - ``bypass``     → 0.5–1.5 s
          - ``aggressive`` → 0.1–0.5 s
        """
        if not self.ctx.waf_evasion:
            return

        profile = self.ctx.waf_evasion_profile
        if profile == "stealth":
            delay = random.uniform(1.0, 3.0)
        elif profile == "aggressive":
            delay = random.uniform(0.1, 0.5)
        else:  # bypass (default fallback)
            delay = random.uniform(0.5, 1.5)

        self.log.debug(f"WAF evasion delay: {delay:.2f}s (profile={profile!r})")
        await asyncio.sleep(delay)

    # ------------------------------------------------------------------
    # HTTP request helpers
    # ------------------------------------------------------------------

    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[httpx.Response]:
        """
        Perform a WAF-aware async HTTP GET request.

        Applies jitter delays and header rotation when
        ``ctx.waf_evasion`` is ``True``.  Returns ``None`` on any network
        error so callers must handle the ``None`` case.

        Args:
            url:               Target URL.
            params:            Optional query-string parameters.
            headers:           Additional request headers (merged with base).
            follow_redirects:  Whether to follow HTTP redirects.
            timeout:           Per-request timeout override (falls back to
                               ``ctx.timeout``).

        Returns:
            :class:`httpx.Response` on success, ``None`` on failure.
        """
        await self._maybe_delay()
        req_headers = self._build_headers(headers)
        self._request_count += 1

        self.log.debug(
            f"GET {url}",
            extra={"params": params, "request_num": self._request_count},
        )

        try:
            resp = await self.client.get(
                url,
                params=params,
                headers=req_headers,
                follow_redirects=follow_redirects,
                timeout=timeout or self.timeout,
            )
            self.log.debug(
                f"← {resp.status_code} {url}",
                extra={"length": len(resp.content), "url": url},
            )
            return resp

        except httpx.TimeoutException:
            self.log.warning(f"GET timeout: {url}")
            return None
        except httpx.TooManyRedirects:
            self.log.warning(f"Too many redirects: {url}")
            return None
        except httpx.RequestError as exc:
            self.log.debug(f"GET request error: {url} — {exc}")
            return None

    async def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[httpx.Response]:
        """
        Perform a WAF-aware async HTTP POST request.

        Applies jitter delays and header rotation when
        ``ctx.waf_evasion`` is ``True``.  Returns ``None`` on any network
        error so callers must handle the ``None`` case.

        Args:
            url:               Target URL.
            data:              Optional form-encoded body data.
            json:              Optional JSON-serialisable body (mutually
                               exclusive with ``data``; ``json`` takes
                               priority when both are given).
            headers:           Additional request headers (merged with base).
            follow_redirects:  Whether to follow HTTP redirects.
            timeout:           Per-request timeout override.

        Returns:
            :class:`httpx.Response` on success, ``None`` on failure.
        """
        await self._maybe_delay()
        req_headers = self._build_headers(headers)
        self._request_count += 1

        self.log.debug(
            f"POST {url}",
            extra={
                "has_data": data is not None,
                "has_json": json is not None,
                "request_num": self._request_count,
            },
        )

        try:
            resp = await self.client.post(
                url,
                data=data,
                json=json,
                headers=req_headers,
                follow_redirects=follow_redirects,
                timeout=timeout or self.timeout,
            )
            self.log.debug(
                f"← {resp.status_code} {url}",
                extra={"length": len(resp.content), "url": url},
            )
            return resp

        except httpx.TimeoutException:
            self.log.warning(f"POST timeout: {url}")
            return None
        except httpx.TooManyRedirects:
            self.log.warning(f"Too many redirects on POST: {url}")
            return None
        except httpx.RequestError as exc:
            self.log.debug(f"POST request error: {url} — {exc}")
            return None

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        follow_redirects: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[httpx.Response]:
        """
        Generic WAF-aware async HTTP request for methods beyond GET/POST
        (e.g. PUT, DELETE, PATCH, OPTIONS).

        Args:
            method:            HTTP method string (e.g. ``"PUT"``).
            url:               Target URL.
            headers:           Additional request headers.
            params:            Query-string parameters.
            data:              Form-encoded body data.
            json:              JSON-serialisable body.
            follow_redirects:  Whether to follow HTTP redirects.
            timeout:           Per-request timeout override.

        Returns:
            :class:`httpx.Response` on success, ``None`` on failure.
        """
        await self._maybe_delay()
        req_headers = self._build_headers(headers)
        self._request_count += 1

        self.log.debug(f"{method.upper()} {url}")

        try:
            resp = await self.client.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                params=params,
                data=data,
                json=json,
                follow_redirects=follow_redirects,
                timeout=timeout or self.timeout,
            )
            self.log.debug(f"← {resp.status_code} {url} (len={len(resp.content)})")
            return resp

        except httpx.TimeoutException:
            self.log.warning(f"{method.upper()} timeout: {url}")
            return None
        except httpx.TooManyRedirects:
            self.log.warning(f"Too many redirects on {method.upper()}: {url}")
            return None
        except httpx.RequestError as exc:
            self.log.debug(f"{method.upper()} request error: {url} — {exc}")
            return None

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"{self.__class__.__name__}("
            f"target={self.target!r}, "
            f"requests={self._request_count})"
        )
