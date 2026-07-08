"""
scanners/cookie_scanner.py — Cookie security scanner (v2 async rewrite).
Checks cookie flags (Secure, HttpOnly, SameSite) and JWT vulnerabilities.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Dict, List, Optional

from loguru import logger

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner

_COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "key", "jwt_secret",
    "changeme", "admin", "test", "default", "token_secret",
]


class CookieScanner(BaseScanner):
    """Async cookie security scanner."""

    async def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        resp = await self.get(self.ctx.target)
        if resp is None:
            return []

        cookies = resp.cookies
        raw_set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else []

        # Also parse cookies from Set-Cookie headers for flag analysis
        for cookie in cookies.jar:
            name = cookie.name
            value = cookie.value

            # Check Secure flag
            if not cookie.secure:
                findings.append(self.finding(
                    title=f"Cookie Missing 'Secure' Flag: {name}",
                    severity="MEDIUM",
                    description=f"Cookie '{name}' is not marked Secure. It can be sent over unencrypted HTTP.",
                    evidence={"cookie": name, "flags": {"secure": False}},
                    remediation="Set the Secure flag on all session/authentication cookies.",
                    tags=["cookies", "secure-flag"],
                ))

            # Check HttpOnly (not directly available from httpx cookie jar — check Set-Cookie header)
            httponly = False
            for sc in raw_set_cookies:
                if name.lower() in sc.lower() and "httponly" in sc.lower():
                    httponly = True
                    break

            if not httponly:
                findings.append(self.finding(
                    title=f"Cookie Missing 'HttpOnly' Flag: {name}",
                    severity="MEDIUM",
                    description=f"Cookie '{name}' is not HttpOnly. JavaScript can access it via document.cookie.",
                    evidence={"cookie": name, "flags": {"httponly": False}},
                    remediation="Set the HttpOnly flag to prevent client-side script access.",
                    tags=["cookies", "httponly-flag"],
                ))

            # Check SameSite
            samesite_set = False
            for sc in raw_set_cookies:
                if name.lower() in sc.lower() and "samesite" in sc.lower():
                    samesite_set = True
                    break

            if not samesite_set:
                findings.append(self.finding(
                    title=f"Cookie Missing 'SameSite' Attribute: {name}",
                    severity="LOW",
                    description=f"Cookie '{name}' lacks a SameSite attribute, increasing CSRF risk.",
                    evidence={"cookie": name, "flags": {"samesite": None}},
                    remediation="Set SameSite=Strict or SameSite=Lax on all cookies.",
                    tags=["cookies", "samesite"],
                ))

            # JWT detection
            if value and self._looks_like_jwt(value):
                jwt_findings = self._analyze_jwt(name, value)
                findings.extend(jwt_findings)

        return findings

    def _looks_like_jwt(self, value: str) -> bool:
        parts = value.split(".")
        return len(parts) == 3 and all(len(p) > 5 for p in parts)

    def _decode_jwt_payload(self, jwt_str: str) -> Optional[dict]:
        try:
            parts = jwt_str.split(".")
            def b64d(s):
                s += "=" * (4 - len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s))
            return {"header": b64d(parts[0]), "payload": b64d(parts[1])}
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            self.add_error("JWT Payload Decoding Parse Error", e)
            return None
        except Exception as e:
            self.add_error("JWT Payload Decoding Generic Exception", e)
            return None

    def _analyze_jwt(self, cookie_name: str, jwt_str: str) -> List[Finding]:
        findings: List[Finding] = []
        jwt_data = self._decode_jwt_payload(jwt_str)
        if not jwt_data:
            return []

        alg = jwt_data.get("header", {}).get("alg", "").upper()

        # 'none' algorithm vulnerability
        if alg == "NONE":
            findings.append(self.finding(
                title=f"JWT 'none' Algorithm Vulnerability in Cookie '{cookie_name}'",
                severity="CRITICAL",
                description="JWT uses 'none' algorithm — signature not verified.",
                evidence={"cookie": cookie_name, "algorithm": alg, "header": jwt_data["header"]},
                remediation="Never accept JWTs with 'none' algorithm. Enforce HS256/RS256 on server.",
                verified=True,
                tags=["cookies", "jwt", "none-alg"],
            ))

        # Weak secret brute-force (only for HMAC algorithms)
        if alg in ("HS256", "HS384", "HS512"):
            weak_secret = self._check_jwt_weak_secret(jwt_str, alg)
            if weak_secret:
                findings.append(self.finding(
                    title=f"JWT Signed with Weak Secret in Cookie '{cookie_name}'",
                    severity="CRITICAL",
                    description=f"JWT signature verified with trivial secret: '{weak_secret}'.",
                    evidence={"cookie": cookie_name, "weak_secret": weak_secret, "algorithm": alg},
                    remediation="Use a cryptographically strong random secret (256+ bits).",
                    verified=True,
                    tags=["cookies", "jwt", "weak-secret"],
                ))

        return findings

    def _check_jwt_weak_secret(self, jwt_str: str, alg: str) -> str:
        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hash_fn = hash_map.get(alg)
        if not hash_fn:
            return ""

        parts = jwt_str.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig_segment = parts[2]

        # Pad and decode signature
        try:
            sig_padded = sig_segment + "=" * (4 - len(sig_segment) % 4)
            expected_sig = base64.urlsafe_b64decode(sig_padded)
        except ValueError as e:
            self.add_error("JWT Weak Secret Decode ValueError", e)
            return ""
        except Exception as e:
            self.add_error("JWT Weak Secret Decode Generic Exception", e)
            return ""

        for secret in _COMMON_JWT_SECRETS:
            computed = hmac.new(secret.encode(), signing_input, hash_fn).digest()
            if hmac.compare_digest(computed, expected_sig):
                return secret
        return ""
