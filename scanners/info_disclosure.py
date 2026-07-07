"""
scanners/info_disclosure.py — Information disclosure scanner (v2 async rewrite).
Scans for leaked internal IPs, emails, API keys, and sensitive HTML comments.
"""
from __future__ import annotations

import re
from typing import Dict, List

from bs4 import BeautifulSoup, Comment

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner

_PATTERNS = {
    "Internal IPv4": r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
    "Email Address": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "Potential API Key": r'(?:key|api|token|secret|password|db_pass)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,80})["\']',
}

_SENSITIVE_COMMENT_KEYWORDS = ["todo", "fixme", "pass", "user", "db", "internal", "config", "hack", "bug"]


class InfoDisclosureScanner(BaseScanner):
    """Async information disclosure scanner."""

    async def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        resp = await self.get(self.ctx.target)
        if resp is None:
            return []

        html = resp.text

        # 1. Regex pattern matching
        for name, pattern in _PATTERNS.items():
            matches = list(set(re.findall(pattern, html, re.IGNORECASE)))
            if matches:
                redacted = [str(m)[:30] + "..." if len(str(m)) > 30 else str(m) for m in matches]
                severity = "HIGH" if name == "Potential API Key" else "INFO"
                findings.append(self.finding(
                    title=f"Information Leak: {name}",
                    severity=severity,
                    description=f"Response body contains patterns indicating leakage of {name}.",
                    evidence={"pattern": name, "matches_redacted": redacted[:5], "total_matches": len(matches)},
                    remediation="Strip debugging details, keys, and internal identifiers from production output.",
                    tags=["info-disclosure", name.lower().replace(" ", "-")],
                ))

        # 2. HTML comments analysis
        try:
            soup = BeautifulSoup(html, "html.parser")
            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
            sensitive_comments = [
                c.strip() for c in comments
                if any(kw in c.lower() for kw in _SENSITIVE_COMMENT_KEYWORDS)
            ]
            if sensitive_comments:
                findings.append(self.finding(
                    title="Sensitive Code Comments in HTML",
                    severity="LOW",
                    description="Developer HTML comments with sensitive keywords were found in the page source.",
                    evidence={"count": len(sensitive_comments), "sample": sensitive_comments[0][:150]},
                    remediation="Remove development comments and TODO markers from production builds.",
                    tags=["info-disclosure", "comments"],
                ))
        except Exception:
            pass

        return findings
