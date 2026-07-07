"""
tests/conftest.py — Shared fixtures for ScopeX v2 pytest suite.
"""
from __future__ import annotations

import asyncio
from typing import Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from core.context import ScanContext
from core.findings import Finding


# ---------------------------------------------------------------------------
# Async event loop fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# ScanContext factories
# ---------------------------------------------------------------------------

@pytest.fixture
def make_context():
    """Factory fixture that creates ScanContext instances."""
    def _make(
        target: str = "https://example.com",
        host: str = "example.com",
        profile: str = "standard",
        timeout: float = 3.0,
        discovered_urls: Optional[List[str]] = None,
        **kwargs,
    ) -> ScanContext:
        ctx = ScanContext(
            target=target,
            host=host,
            profile=profile,
            timeout=timeout,
            **kwargs,
        )
        if discovered_urls:
            ctx.discovered_urls = discovered_urls
        return ctx
    return _make


@pytest.fixture
def default_context(make_context):
    """A default ScanContext targeting https://example.com."""
    return make_context()


# ---------------------------------------------------------------------------
# Mock HTTP client
# ---------------------------------------------------------------------------

class MockResponse:
    """Lightweight mock for httpx.Response."""
    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
        cookies: Optional[Dict[str, str]] = None,
    ):
        self.status_code = status_code
        self.text = text
        self.content = content or text.encode("utf-8")
        self.headers = httpx.Headers(headers or {})
        self._cookies = cookies or {}
        self.url = httpx.URL("https://example.com")

    @property
    def cookies(self):
        jar = httpx.Cookies()
        for k, v in self._cookies.items():
            jar.set(k, v)
        return jar


@pytest.fixture
def mock_client():
    """Create a mock httpx.AsyncClient for scanner unit tests."""
    client = AsyncMock(spec=httpx.AsyncClient)
    # Default: return 200 OK with empty body
    default_resp = MockResponse(status_code=200, text="<html></html>")
    client.get = AsyncMock(return_value=default_resp)
    client.post = AsyncMock(return_value=default_resp)
    client.request = AsyncMock(return_value=default_resp)
    return client


# ---------------------------------------------------------------------------
# Vulnerable response helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def sqli_error_response():
    """Response containing MySQL error signature."""
    return MockResponse(
        text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    )


@pytest.fixture
def sqli_clean_response():
    """Clean response with no SQL errors."""
    return MockResponse(text="Welcome to our website. No errors here.")


@pytest.fixture
def xss_reflected_response():
    """Response that reflects an XSS payload."""
    return MockResponse(text='<html><body><img src=x onerror=alert(1)></body></html>')


@pytest.fixture
def xss_encoded_response():
    """Response that safely encodes XSS payload."""
    return MockResponse(text='<html><body>&lt;img src=x onerror=alert(1)&gt;</body></html>')
