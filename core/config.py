"""
core/config.py — Configuration loading and validation for ScopeX v2.

Loads config.json from the project root (two levels up from this file).
Falls back to DEFAULT_CONFIG when config.json is absent or malformed.
Uses a module-level singleton so the file is parsed at most once per
process.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from loguru import logger

# ---------------------------------------------------------------------------
# Default configuration (used when config.json is missing or broken)
# ---------------------------------------------------------------------------
DEFAULT_CONFIG: Dict[str, Any] = {
    "profiles": {
        "quick": {
            "ports": [21, 22, 23, 25, 53, 80, 443, 8080, 8443],
            "timeout": 2.0,
            "scanners": ["ports", "headers", "ssl", "dns"],
            "nuclei_tags": [],
        },
        "standard": {
            "ports": [
                21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                3306, 5432, 6379, 8080, 8443, 27017,
            ],
            "timeout": 3.0,
            "scanners": [
                "ports", "headers", "ssl", "dns", "sqli", "xss",
                "tech", "cookies", "waf", "vulns",
            ],
            "nuclei_tags": ["http", "ssl"],
        },
        "full": {
            "ports": [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389,
                443, 445, 512, 513, 514, 587, 631, 993, 995, 1433, 1521,
                2049, 2181, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                8888, 9200, 11211, 27017, 50000,
            ],
            "timeout": 5.0,
            "scanners": "all",
            "nuclei_tags": "all",
        },
    },
    "default_profile": "standard",
    "dns_wordlist": [
        "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "webmail",
        "remote", "vpn", "api", "dev", "staging", "test", "beta",
        "cdn", "static", "assets", "app", "mobile", "admin", "blog",
        "shop", "forum",
    ],
    "waf_evasion": {
        "enabled": False,
        "profile": "stealth",
        "max_retries": 3,
    },
    "authentication": {
        "login_url": "",
        "username_field": "username",
        "password_field": "password",
        "success_indicator": "",
    },
    "scanner_timeouts": {
        "default": 60,
        "port_scanner": 120,
        "nuclei": 300,
        "ssl_vulns": 90,
    },
    "checkpoints": {
        "enabled": True,
        "interval": 5,
    },
}

# Path to the project root (two directories above core/config.py)
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
_CONFIG_FILE: Path = _PROJECT_ROOT / "config.json"


# ---------------------------------------------------------------------------
# Singleton machinery
# ---------------------------------------------------------------------------

class _ConfigLoader:
    """
    Internal singleton that loads and caches ScopeX configuration.

    Do **not** instantiate this class directly — use the module-level
    :func:`get_config` / :func:`get_profile` / :func:`get_scanner_timeout`
    helper functions instead.
    """

    _instance: Optional["_ConfigLoader"] = None
    _lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton constructor
    # ------------------------------------------------------------------

    def __new__(cls) -> "_ConfigLoader":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._loaded = False  # type: ignore[attr-defined]
        return cls._instance  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Lazy load
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        """Load config.json once; fall back to defaults on any error."""
        if self._loaded:  # type: ignore[attr-defined]
            return

        with self._lock:
            if self._loaded:  # type: ignore[attr-defined]  # double-checked
                return

            raw: Dict[str, Any] = {}

            if _CONFIG_FILE.exists():
                try:
                    with _CONFIG_FILE.open("r", encoding="utf-8") as fh:
                        raw = json.load(fh)
                    logger.debug(f"Loaded config from {_CONFIG_FILE}")
                except json.JSONDecodeError as exc:
                    logger.warning(
                        f"config.json is malformed ({exc}); using defaults"
                    )
                    raw = {}
                except OSError as exc:
                    logger.warning(
                        f"Cannot read config.json ({exc}); using defaults"
                    )
                    raw = {}
            else:
                logger.debug(
                    f"config.json not found at {_CONFIG_FILE}; using defaults"
                )

            # Deep-merge: defaults first, then overrides from file
            self._config: Dict[str, Any] = _deep_merge(DEFAULT_CONFIG, raw)
            self._loaded = True  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    def raw(self) -> Dict[str, Any]:
        """Return the fully merged configuration dictionary."""
        self._ensure_loaded()
        return self._config

    def get_profile(self, name: Optional[str] = None) -> Dict[str, Any]:
        """
        Return the configuration dict for the named profile.

        Args:
            name: Profile name ('quick' | 'standard' | 'full').
                  Falls back to ``default_profile`` when *None*.

        Returns:
            A dict with keys ``ports``, ``timeout``, ``scanners``, and
            ``nuclei_tags``.

        Raises:
            ValueError: If *name* is not defined in the configuration.
        """
        self._ensure_loaded()
        profiles: Dict[str, Any] = self._config.get("profiles", {})
        profile_name = name or self._config.get("default_profile", "standard")

        if profile_name not in profiles:
            available = ", ".join(profiles.keys())
            raise ValueError(
                f"Unknown profile {profile_name!r}. "
                f"Available profiles: {available}"
            )

        return dict(profiles[profile_name])

    def get_scanner_timeout(self, scanner_name: str) -> int:
        """
        Return the timeout (seconds) for a named scanner.

        Falls back to the ``default`` timeout when the scanner is not
        explicitly configured.

        Args:
            scanner_name: The canonical scanner name (e.g. 'nuclei',
                          'port_scanner').

        Returns:
            Timeout in seconds as an integer.
        """
        self._ensure_loaded()
        timeouts: Dict[str, Any] = self._config.get("scanner_timeouts", {})
        default_timeout: int = int(timeouts.get("default", 60))
        return int(timeouts.get(scanner_name, default_timeout))

    def get_dns_wordlist(self) -> List[str]:
        """Return the subdomain brute-force wordlist."""
        self._ensure_loaded()
        return list(self._config.get("dns_wordlist", []))

    def get(self, key: str, default: Any = None) -> Any:
        """
        Generic top-level key accessor with optional default.

        Args:
            key:     Top-level config key.
            default: Value to return when *key* is absent.
        """
        self._ensure_loaded()
        return self._config.get(key, default)

    def checkpoints_enabled(self) -> bool:
        """Return True when checkpoint persistence is enabled."""
        self._ensure_loaded()
        return bool(self._config.get("checkpoints", {}).get("enabled", True))

    def checkpoint_interval(self) -> int:
        """Return the checkpoint save interval (number of scanners)."""
        self._ensure_loaded()
        return int(self._config.get("checkpoints", {}).get("interval", 5))

    def reload(self) -> None:
        """
        Force a reload of config.json on the next access.

        Useful in tests that swap out configuration between cases.
        """
        with self._lock:
            self._loaded = False  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Module-level helpers (preferred public API)
# ---------------------------------------------------------------------------

_loader = _ConfigLoader()


def get_config() -> _ConfigLoader:
    """Return the singleton :class:`_ConfigLoader` instance."""
    return _loader


def get_profile(name: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience wrapper — see :meth:`_ConfigLoader.get_profile`.

    Args:
        name: Profile name, or *None* to use the default.

    Returns:
        Profile configuration dictionary.
    """
    return _loader.get_profile(name)


def get_scanner_timeout(scanner_name: str) -> int:
    """
    Convenience wrapper — see :meth:`_ConfigLoader.get_scanner_timeout`.

    Args:
        scanner_name: Scanner identifier.

    Returns:
        Timeout in seconds.
    """
    return _loader.get_scanner_timeout(scanner_name)


def get_dns_wordlist() -> List[str]:
    """Convenience wrapper — return the DNS brute-force wordlist."""
    return _loader.get_dns_wordlist()


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge *override* into *base* and return a new dict.

    Nested dicts are merged rather than replaced.  Non-dict values in
    *override* always win over *base*.

    Args:
        base:     Default configuration dictionary.
        override: User-supplied overrides (may be partial).

    Returns:
        Merged configuration dictionary.
    """
    result: Dict[str, Any] = dict(base)
    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
