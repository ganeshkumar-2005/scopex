"""
core/context.py — Shared scan context passed to every scanner and plugin.
Eliminates the 28-parameter anti-pattern in scopex.py.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AuthContext:
    """
    Authentication configuration for authenticated scanning.

    Attributes:
        login_url:          Full URL of the login endpoint.
        username:           Credential – username / email.
        password:           Credential – password (never logged).
        username_field:     HTML form field name for the username.
        password_field:     HTML form field name for the password.
        success_indicator:  String that appears in the response body on
                            successful login (used to verify auth worked).
        session_cookies:    Populated after a successful login attempt.
        auth_headers:       Bearer / API-key headers set after login.
        authenticated:      True once login has been verified.
    """

    login_url: str
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    success_indicator: str = ""

    # Populated after successful login:
    session_cookies: Dict[str, str] = field(default_factory=dict)
    auth_headers: Dict[str, str] = field(default_factory=dict)
    authenticated: bool = False

    def to_dict(self) -> Dict[str, str | bool]:
        """
        Return a safe (password-redacted) dictionary representation.

        The ``password`` field is intentionally excluded so this dict is
        safe to log or include in reports.
        """
        return {
            "login_url": self.login_url,
            "username": self.username,
            "username_field": self.username_field,
            "password_field": self.password_field,
            "success_indicator": self.success_indicator,
            "authenticated": self.authenticated,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"AuthContext(login_url={self.login_url!r}, "
            f"username={self.username!r}, authenticated={self.authenticated})"
        )


@dataclass
class ScanContext:
    """
    Shared context object passed to all scanners during a scan session.

    Mutable fields (``discovered_urls``, ``discovered_subdomains``, etc.)
    are updated in-place by individual scanners and are protected by an
    internal ``threading.Lock`` so concurrent async tasks can safely call
    the ``add_*`` helpers without data races.

    Attributes:
        target:                   Validated base URL, e.g. 'https://example.com'.
        host:                     Bare hostname / IP, e.g. 'example.com'.
        profile:                  Scan intensity: 'quick' | 'standard' | 'full'.
        ports:                    Ports to scan (overrides profile default when set).
        timeout:                  Per-request HTTP timeout in seconds.
        scanner_timeout:          Per-scanner wall-clock timeout in seconds.
                                  Fast scanners (headers, ssl, dns …) use half this
                                  value; slow scanners (sqli, xss, ports …) use the
                                  full value. Default: 120s.
        verify_ssl:               Verify TLS certificates on outbound requests.
                                  Defaults to False so ScopeX works against
                                  pentesting targets with self-signed certs.
                                  Set to True for production-posture audits.
        waf_evasion:              Enable WAF evasion techniques.
        waf_evasion_profile:      'stealth' | 'aggressive' | 'bypass'.
        auth:                     Optional :class:`AuthContext`.
        skip_nuclei:              Skip the Nuclei engine entirely.
        nuclei_tags:              Nuclei template tags to restrict scanning.
        nuclei_templates:         Path to a custom Nuclei templates directory.
        resume_checkpoint:        Path to a checkpoint file for resume support.
        discovered_urls:          URLs found during crawling / spidering.
        discovered_subdomains:    Subdomains found during DNS enumeration.
        discovered_technologies:  Tech stack identifications (Wappalyzer-style).
        open_ports:               Ports confirmed open during port scanning.
        waf_detected:             True if a WAF was fingerprinted.
        waf_vendor:               Name of the detected WAF vendor.
    """

    # ------------------------------------------------------------------ #
    #  Required fields                                                     #
    # ------------------------------------------------------------------ #
    target: str                        # Validated URL, e.g. 'https://example.com'
    host: str                          # Bare hostname/IP, e.g. 'example.com'

    # ------------------------------------------------------------------ #
    #  Scan behaviour                                                      #
    # ------------------------------------------------------------------ #
    profile: str = "standard"          # 'quick' | 'standard' | 'full'
    ports: List[int] = field(default_factory=list)
    timeout: float = 3.0
    scanner_timeout: float = 120.0     # per-scanner wall-clock timeout (slow scanners); fast = half
    verify_ssl: bool = False           # False = skip cert verification (pentest default)
    waf_evasion: bool = False
    waf_evasion_profile: str = "stealth"   # 'stealth' | 'aggressive' | 'bypass'
    auth: Optional[AuthContext] = None
    skip_nuclei: bool = False
    nuclei_tags: List[str] = field(default_factory=list)
    nuclei_templates: Optional[str] = None
    resume_checkpoint: Optional[str] = None

    # ------------------------------------------------------------------ #
    #  Discovered / shared state (mutated during scan)                    #
    # ------------------------------------------------------------------ #
    discovered_urls: List[str] = field(default_factory=list)
    discovered_subdomains: List[str] = field(default_factory=list)
    discovered_technologies: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    scan_errors: List[tuple] = field(default_factory=list)  # (check_name, target, error_summary)
    waf_detected: bool = False
    waf_vendor: Optional[str] = None

    # Internal concurrency guard (excluded from repr/eq by dataclass)
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False, compare=False
    )

    # ------------------------------------------------------------------ #
    #  Thread-safe mutators                                                #
    # ------------------------------------------------------------------ #

    def add_discovered_url(self, url: str) -> None:
        """
        Append *url* to :attr:`discovered_urls` if not already present.

        Thread-safe — safe to call from concurrent asyncio tasks.
        """
        with self._lock:
            if url not in self.discovered_urls:
                self.discovered_urls.append(url)

    def add_discovered_subdomain(self, subdomain: str) -> None:
        """
        Append *subdomain* to :attr:`discovered_subdomains` if not already
        present.

        Thread-safe — safe to call from concurrent asyncio tasks.
        """
        with self._lock:
            if subdomain not in self.discovered_subdomains:
                self.discovered_subdomains.append(subdomain)

    def add_technology(self, tech: str) -> None:
        """
        Append *tech* to :attr:`discovered_technologies` if not already
        present.

        Thread-safe — safe to call from concurrent asyncio tasks.
        """
        with self._lock:
            if tech not in self.discovered_technologies:
                self.discovered_technologies.append(tech)

    def add_open_port(self, port: int) -> None:
        """
        Record *port* as open if not already in :attr:`open_ports`.

        Thread-safe — safe to call from concurrent asyncio tasks.
        """
        with self._lock:
            if port not in self.open_ports:
                self.open_ports.append(port)

    def add_scan_error(self, check_name: str, target: str, error_summary: str) -> None:
        """
        Record a scan error. Thread-safe.
        """
        with self._lock:
            self.scan_errors.append((check_name, target, error_summary))

    def set_waf(self, vendor: str) -> None:
        """
        Mark a WAF as detected and record the vendor name.

        Thread-safe — safe to call from concurrent asyncio tasks.
        """
        with self._lock:
            self.waf_detected = True
            self.waf_vendor = vendor

    # ------------------------------------------------------------------ #
    #  Snapshot / summary helpers                                          #
    # ------------------------------------------------------------------ #

    def summary(self) -> Dict[str, object]:
        """
        Return a lightweight, JSON-serialisable snapshot of discovered
        assets — useful for checkpoint files and report headers.
        """
        return {
            "target": self.target,
            "host": self.host,
            "profile": self.profile,
            "waf_detected": self.waf_detected,
            "waf_vendor": self.waf_vendor,
            "open_ports": list(self.open_ports),
            "discovered_urls_count": len(self.discovered_urls),
            "discovered_subdomains": list(self.discovered_subdomains),
            "discovered_technologies": list(self.discovered_technologies),
        }

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"ScanContext(target={self.target!r}, host={self.host!r}, "
            f"profile={self.profile!r}, "
            f"urls={len(self.discovered_urls)}, "
            f"subdomains={len(self.discovered_subdomains)})"
        )
