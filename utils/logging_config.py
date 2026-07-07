"""
utils/logging_config.py — Structured logging configuration for ScopeX v2.
Uses loguru for rotating file handler with DEBUG payload capture.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from loguru import logger as _root_logger

# ---------------------------------------------------------------------------
# Format strings
# ---------------------------------------------------------------------------

_CONSOLE_FORMAT: str = (
    "<green>{time:HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{extra[scanner]}</cyan> | "
    "{message}"
)

_FILE_FORMAT: str = (
    "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
    "{level: <8} | "
    "{name}:{function}:{line} | "
    "{extra} | "
    "{message}"
)


# ---------------------------------------------------------------------------
# Public setup function
# ---------------------------------------------------------------------------

def setup_logging(
    log_dir: str = "logs",
    debug: bool = False,
    log_file_prefix: str = "scopex",
) -> None:
    """
    Configure loguru sinks for the ScopeX application.

    Two sinks are installed:

    * **Console sink** (stderr) — WARNING+ in normal mode, DEBUG+ in debug
      mode.  Output is colourised and formatted for human readability.
    * **File sink** — always DEBUG+, with 10 MB rotation, 7-day retention,
      gzip compression, and async enqueueing for thread safety.

    Call this function **once** at application start-up before any scanner
    imports ``logger``.

    Args:
        log_dir:         Directory where rotating log files are written.
                         Created automatically if it does not exist.
        debug:           When *True*, the console sink also emits DEBUG
                         records so payloads / request–response cycles are
                         visible in the terminal.
        log_file_prefix: Prefix for log file names (default ``'scopex'``).
    """
    # Remove the default loguru handler (id 0) so we start clean.
    _root_logger.remove()

    # ── Console sink ──────────────────────────────────────────────────────
    _root_logger.add(
        sys.stderr,
        level="DEBUG" if debug else "WARNING",
        format=_CONSOLE_FORMAT,
        colorize=True,
        # Ensure every record has the 'scanner' extra key so the format
        # string never raises a KeyError even for un-bound loggers.
        filter=_ensure_scanner_extra,
    )

    # ── File sink ─────────────────────────────────────────────────────────
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    log_file = log_path / f"{log_file_prefix}_{{time:YYYYMMDD_HHmmss}}.log"
    _root_logger.add(
        str(log_file),
        level="DEBUG",
        format=_FILE_FORMAT,
        rotation="10 MB",
        retention="7 days",
        compression="gz",
        enqueue=True,       # Non-blocking, thread-safe async queue
        backtrace=True,     # Full traceback in exception records
        diagnose=True,      # Variable values in tracebacks (dev / audit)
        filter=_ensure_scanner_extra,
    )

    _root_logger.debug(
        f"Logging initialised. log_dir={log_dir!r}, debug={debug}"
    )


# ---------------------------------------------------------------------------
# Bound loggers
# ---------------------------------------------------------------------------

def get_scanner_logger(scanner_name: str):  # type: ignore[return]
    """
    Return a loguru logger bound to a specific scanner name.

    The bound logger automatically injects ``scanner=<scanner_name>`` into
    every log record so the console format string can display it without
    extra boilerplate at each call site.

    Args:
        scanner_name: Human-readable scanner identifier, e.g.
                      ``'sqli_scanner'``.

    Returns:
        A loguru ``BoundLogger`` instance.

    Example::

        log = get_scanner_logger("xss_scanner")
        log.info("Starting XSS scan on {url}", url=ctx.target)
    """
    return _root_logger.bind(scanner=scanner_name)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_scanner_extra(record: dict) -> bool:  # type: ignore[type-arg]
    """
    Loguru filter that guarantees the ``scanner`` key exists in
    ``record['extra']``.

    Without this, any logger that hasn't been bound with
    ``logger.bind(scanner=…)`` would cause a ``KeyError`` when the console
    format string tries to render ``{extra[scanner]}``.

    Args:
        record: The loguru log record dictionary.

    Returns:
        Always *True* (the record is never suppressed by this filter).
    """
    record["extra"].setdefault("scanner", "scopex")
    return True


# ---------------------------------------------------------------------------
# Module-level default logger
# ---------------------------------------------------------------------------

# Bind a default 'scopex' scanner context so callers that do
#   from utils.logging_config import logger
# get a ready-to-use logger without needing to call get_scanner_logger().
logger = _root_logger.bind(scanner="scopex")

__all__ = [
    "setup_logging",
    "get_scanner_logger",
    "logger",
]
