"""
scanners/waf_detector.py — WAF detection scanner (v2 async rewrite).

Detects Web Application Firewalls via:
  1. Passive header signature matching
  2. Active probing with simulated attack payloads
"""
from __future__ import annotations

from typing import Dict, List

import httpx
from loguru import logger

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner

# WAF signatures: waf_name -> [(header_name, header_value_substring_or_*)]
WAF_SIGNATURES: Dict[str, List[tuple]] = {
    "Cloudflare":              [("cf-ray", "*"), ("server", "cloudflare")],
    "AWS WAF / ALB":           [("x-amz-id-2", "*"), ("x-amz-request-id", "*"), ("server", "awselb")],
    "ModSecurity / OWASP CRS": [("server", "mod_security"), ("x-powered-by", "mod_security")],
    "Imperva / Incapsula":     [("x-iinfo", "*"), ("visid_incap", "*"), ("server", "incapsula")],
    "Akamai":                  [("server", "akamaighost"), ("x-akamai-transformed", "*")],
    "Sucuri":                  [("server", "sucuri"), ("x-sucuri-id", "*")],
    "F5 BIG-IP ASM":           [("server", "big-ip"), ("x-cnection", "*")],
    "Barracuda":               [("server", "barracuda")],
}


class WAFDetector(BaseScanner):
    """Async WAF detection scanner."""

    async def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        # Step 1: Passive header-based detection
        resp = await self.get(self.ctx.target)
        if resp is None:
            self.log.warning("Target unreachable for WAF detection")
            return []

        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        detected_waf = None
        confidence = "Low"

        for waf_name, sigs in WAF_SIGNATURES.items():
            match_count = 0
            for h_name, h_val in sigs:
                if h_name in headers:
                    if h_val == "*" or h_val in headers[h_name]:
                        match_count += 1
            if match_count > 0:
                detected_waf = waf_name
                confidence = "High" if match_count >= 2 else "Medium"
                break

        # Step 2: Active probing (trigger WAF block page)
        if detected_waf is None:
            probe_url = f"{self.ctx.target}?test=<script>alert(1)</script>%20OR%201=1"
            probe_resp = await self.get(probe_url)
            if probe_resp is not None and probe_resp.status_code in (403, 406, 429, 501, 999):
                detected_waf = "Generic WAF/IDS"
                confidence = "Medium"
                body = probe_resp.text.lower()
                for sig_name, keywords in [
                    ("Cloudflare", ["cloudflare"]),
                    ("Sucuri WAF", ["sucuri"]),
                    ("ModSecurity", ["mod_security", "modsecurity"]),
                    ("AWS WAF", ["aws", "forbidden"]),
                ]:
                    if any(kw in body for kw in keywords):
                        detected_waf = sig_name
                        confidence = "High"
                        break

        if detected_waf:
            findings.append(self.finding(
                title=f"WAF Detected: {detected_waf}",
                severity="INFO",
                description=(
                    f"A Web Application Firewall ({detected_waf}) was detected protecting the target. "
                    f"Detection confidence: {confidence}."
                ),
                evidence={
                    "vendor": detected_waf,
                    "waf_name": detected_waf,
                    "confidence": confidence,
                    "method": "passive_headers" if confidence == "High" else "active_probe",
                },
                remediation=(
                    "No remediation required. WAF presence improves security posture. "
                    "Consider enabling WAF evasion mode for thorough scanning."
                ),
                tags=["waf", "recon"],
            ))

        return findings
