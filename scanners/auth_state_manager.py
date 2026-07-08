"""
scanners/auth_state_manager.py — Authentication state manager for ScopeX v2.
Handles login flow, CSRF token extraction, session cookie persistence,
and session validation for authenticated scanning.
"""
from __future__ import annotations

import re
from typing import Optional

import httpx
from loguru import logger

from core.context import AuthContext


class AuthStateManager:
    """
    Manages authentication state across all scanners in a scan session.

    Usage::

        manager = AuthStateManager(ctx.auth, client)
        if await manager.login():
            # client now carries session cookies
            # all subsequent requests via client will be authenticated
    """

    def __init__(self, auth: AuthContext, client: httpx.AsyncClient) -> None:
        self.auth = auth
        self.client = client
        self.log = logger.bind(scanner="AuthStateManager")

    async def login(self) -> bool:
        """
        Perform the login flow:
        1. GET the login page to capture CSRF tokens/cookies
        2. POST credentials to login_url
        3. Detect success via success_indicator or heuristics
        4. Persist session cookies to the httpx client cookie jar

        Returns True if login succeeded, False otherwise.
        """
        if not self.auth.login_url:
            self.log.warning("No login_url configured; skipping authentication")
            return False

        try:
            self.log.info(f"Authenticating at {self.auth.login_url}")

            # Step 1: GET login page to capture CSRF tokens
            get_resp = await self.client.get(
                self.auth.login_url,
                follow_redirects=True,
                timeout=10,
            )
            csrf_token = self._extract_csrf_token(get_resp.text)

            # Step 2: POST credentials
            login_data = {
                self.auth.username_field: self.auth.username,
                self.auth.password_field: self.auth.password,
            }
            if csrf_token:
                # Common CSRF field names
                for csrf_field in ("_token", "csrf_token", "_csrf", "authenticity_token"):
                    login_data[csrf_field] = csrf_token

            post_resp = await self.client.post(
                self.auth.login_url,
                data=login_data,
                follow_redirects=True,
                timeout=15,
            )

            # Step 3: Detect success
            success = self._detect_login_success(post_resp)
            if success:
                self.auth.authenticated = True
                self.auth.session_cookies = dict(self.client.cookies)
                self.log.info(
                    f"Authentication successful ({len(self.auth.session_cookies)} session cookies set)"
                )
            else:
                self.log.warning(
                    f"Authentication failed: HTTP {post_resp.status_code}, "
                    f"success_indicator='{self.auth.success_indicator}' not found"
                )
            return success

        except httpx.RequestError as exc:
            self.log.error(f"Authentication request failed: {exc}")
            return False
        except Exception as exc:
            self.log.error(f"Unexpected authentication error: {exc}", exc_info=True)
            return False

    async def validate_session(self) -> bool:
        """
        Check if the current session is still valid.
        Detects session expiry by checking if we're redirected to the login page.
        """
        if not self.auth.authenticated or not self.auth.login_url:
            return False
        try:
            resp = await self.client.get(
                self.auth.login_url, follow_redirects=True, timeout=10
            )
            # Redirected back to login page = session expired
            if "login" in str(resp.url).lower() and str(resp.url) != self.auth.login_url:
                self.log.warning("Session has expired")
                self.auth.authenticated = False
                return False
            return True
        except httpx.RequestError as e:
            self.log.debug(f"Session validation HTTP request failed: {e}")
            self.ctx.add_scan_error("Auth State Manager Session Validity Check HTTP Request", self.auth.login_url, str(e))
            return False
        except Exception as e:
            self.log.debug(f"Session validation generic check failed: {e}")
            self.ctx.add_scan_error("Auth State Manager Session Validity Check Generic Exception", self.auth.login_url, str(e))
            return False

    async def refresh_session(self) -> bool:
        """Re-authenticate if the session has expired."""
        self.log.info("Refreshing authentication session")
        self.auth.authenticated = False
        self.auth.session_cookies = {}
        return await self.login()

    def _extract_csrf_token(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML login page using common patterns."""
        patterns = [
            r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']',
            r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']',
            r'name=["\']_csrf["\']\s+value=["\']([^"\']+)["\']',
            r'name=["\']authenticity_token["\']\s+value=["\']([^"\']+)["\']',
            r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']',
            r'content=["\']([a-zA-Z0-9/+=]{20,})["\']\s+name=["\']csrf-token["\']',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                token = match.group(1)
                self.log.debug(f"CSRF token found: {token[:10]}...")
                return token
        return None

    def _detect_login_success(self, response: httpx.Response) -> bool:
        """Detect whether the login POST was successful."""
        # Custom success indicator takes priority
        if self.auth.success_indicator:
            return self.auth.success_indicator.lower() in response.text.lower()

        # Generic heuristics
        if response.status_code == 200:
            text_lower = response.text.lower()
            failure_keywords = [
                "invalid password", "incorrect password", "login failed",
                "authentication failed", "wrong password", "invalid credentials",
                "username or password", "could not log in", "bad credentials",
            ]
            if any(kw in text_lower for kw in failure_keywords):
                return False
            return True

        # Redirect to non-login page = likely success
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "").lower()
            if location and "login" not in location:
                return True

        return False
