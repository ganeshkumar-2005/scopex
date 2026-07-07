"""
scanners/auth_scanner.py — Admin path discovery scanner (v2 async rewrite).
Probes common admin/login paths and reports exposed management interfaces.
"""
from __future__ import annotations

import asyncio
from typing import List

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner

_ADMIN_PATHS = [
    "admin", "administrator", "wp-admin", "login", "admin/login",
    "dashboard", "manage", "portal", "cpanel", "phpmyadmin",
    "wp-login.php", "user/login", "auth/login", "signin", "controlpanel",
    "adminer", "manager", "console", "admin.php",
]


class AuthScanner(BaseScanner):
    """Async admin path discovery scanner."""

    async def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        base_url = self.ctx.target.rstrip("/")
        semaphore = asyncio.Semaphore(5)

        async def test_path(path: str) -> dict:
            url = f"{base_url}/{path}"
            async with semaphore:
                resp = await self.get(url)
                if resp and resp.status_code in (200, 301, 302, 401):
                    return {"path": path, "url": url, "status": resp.status_code}
            return {}

        tasks = [test_path(p) for p in _ADMIN_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        discovered = [r for r in results if isinstance(r, dict) and r.get("path")]

        for p in discovered:
            findings.append(self.finding(
                title=f"Exposed Admin/Login Panel: /{p['path']}",
                severity="MEDIUM",
                description=f"Administrative or login endpoint found at /{p['path']}. Publicly exposed login pages increase brute-force risk.",
                evidence={"url": p["url"], "status_code": p["status"], "path": p["path"]},
                remediation="Restrict admin access via IP whitelisting, VPN, or obscure paths.",
                target=p["url"],
                tags=["auth", "admin-panel"],
            ))

        return findings
