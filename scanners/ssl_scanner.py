"""
scanners/ssl_scanner.py — SSL/TLS certificate and protocol scanner (v2 async rewrite).

Checks:
  - Certificate expiry (expired / expiring within 30 days)
  - Self-signed certificates
  - Insecure TLS protocol versions (SSLv2, SSLv3, TLS 1.0/1.1)
  - Weak cipher suites (RC4, 3DES, DES, NULL, EXPORT, anon)

Uses stdlib ssl module in an executor to keep the async event loop unblocked.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional

from loguru import logger

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner


class SSLScanner(BaseScanner):
    """Async SSL/TLS scanner."""

    async def scan(self) -> List[Finding]:
        """Run SSL checks in an executor (blocking socket calls)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._scan_sync)

    def _scan_sync(self) -> List[Finding]:
        findings: List[Finding] = []
        host = self.ctx.host
        port = 443

        # Resolve host
        try:
            socket.gethostbyname(host)
        except socket.gaierror as e:
            self.log.warning(f"Cannot resolve {host} for SSL scan: {e}")
            return []

        # SSL handshake
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            conn = socket.create_connection((host, port), timeout=self.ctx.timeout)
            sock = context.wrap_socket(conn, server_hostname=host)

            cert = sock.getpeercert()
            cipher = sock.cipher()
            tls_version = sock.version()
            sock.close()
        except Exception as exc:
            self.log.debug(f"SSL handshake failed on {host}:{port}: {exc}")
            return []

        if not cert:
            findings.append(self.finding(
                title="SSL Handshake Succeeded but No Certificate",
                severity="HIGH",
                description="SSL handshake completed but no certificate details could be extracted.",
                evidence={"host": host, "port": port, "tls_version": tls_version},
                remediation="Verify server TLS configuration.",
                tags=["ssl"],
            ))
            return findings

        # Parse certificate
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_before_str = cert.get("notBefore")
        not_after_str = cert.get("notAfter")

        try:
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError as e:
            self.add_error("SSL Certificate Date Parse ValueError", e)
            not_before = not_after = datetime.now(timezone.utc)
        except Exception as e:
            self.add_error("SSL Certificate Date Parse Generic Exception", e)
            not_before = not_after = datetime.now(timezone.utc)

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        days_to_expire = (not_after - now).days

        # Check expiry
        if now > not_after:
            findings.append(self.finding(
                title="Expired SSL/TLS Certificate",
                severity="CRITICAL",
                description=f"The certificate for {host} expired on {not_after.strftime('%Y-%m-%d')}.",
                evidence={"expiry_date": not_after.isoformat(), "host": host},
                remediation="Renew the SSL/TLS certificate immediately.",
                verified=True,
                tags=["ssl", "expired"],
            ))
        elif days_to_expire < 30:
            findings.append(self.finding(
                title="SSL/TLS Certificate Expiring Soon",
                severity="MEDIUM",
                description=f"The certificate for {host} expires in {days_to_expire} days.",
                evidence={"expiry_date": not_after.isoformat(), "days_remaining": days_to_expire},
                remediation="Renew the SSL/TLS certificate before expiration.",
                tags=["ssl", "expiring"],
            ))

        # Self-signed check
        subj_cn = subject.get("commonName", "")
        issuer_cn = issuer.get("commonName", "")
        if subj_cn and subj_cn == issuer_cn:
            findings.append(self.finding(
                title="Self-Signed SSL/TLS Certificate",
                severity="HIGH",
                description="Certificate issuer matches the subject, indicating a self-signed certificate.",
                evidence={"subject": subj_cn, "issuer": issuer_cn},
                remediation="Use a certificate from a trusted CA (e.g. Let's Encrypt).",
                tags=["ssl", "self-signed"],
            ))

        # TLS version check
        if tls_version in ("SSLv2", "SSLv3"):
            findings.append(self.finding(
                title=f"Deprecated {tls_version} Protocol Negotiated",
                severity="CRITICAL",
                description=f"Server negotiated {tls_version} which is completely broken.",
                evidence={"protocol": tls_version},
                remediation=f"Disable {tls_version} immediately. Only enable TLS 1.2+.",
                verified=True,
                tags=["ssl", "deprecated-protocol"],
            ))
        elif tls_version in ("TLSv1", "TLSv1.1"):
            findings.append(self.finding(
                title=f"Insecure TLS Protocol: {tls_version}",
                severity="HIGH",
                description=f"Server negotiated {tls_version}, which is vulnerable to BEAST/POODLE.",
                evidence={"protocol": tls_version},
                remediation="Disable TLS 1.0 and 1.1. Only enable TLS 1.2 and TLS 1.3.",
                tags=["ssl", "insecure-protocol"],
            ))

        # Cipher strength check
        if cipher:
            negotiated_cipher = cipher[0]
            weak_patterns = ["RC4", "3DES", "DES", "MD5", "EXPORT", "NULL", "anon"]
            if any(w.lower() in negotiated_cipher.lower() for w in weak_patterns):
                findings.append(self.finding(
                    title="Weak Cipher Suite Negotiated",
                    severity="MEDIUM",
                    description=f"Cipher {negotiated_cipher} uses weak/deprecated algorithms.",
                    evidence={"cipher": negotiated_cipher, "bits": cipher[2] if len(cipher) > 2 else "unknown"},
                    remediation="Disable weak ciphers. Prefer ECDHE-AES-GCM cipher suites.",
                    tags=["ssl", "weak-cipher"],
                ))

        return findings
