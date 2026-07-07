"""
BasePlugin - Abstract base class for all ScopeX plugins.
Every plugin must inherit from this class and implement the run() method.
Supports async execution in isolated subprocesses with timeout enforcement.
"""
from __future__ import annotations

import asyncio
import json
import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.findings import Finding


class BasePlugin(ABC):
    """Base class that all ScopeX plugins must inherit from."""

    # Plugin metadata - override in subclass
    PLUGIN_ID = "0000"
    PLUGIN_NAME = "Base Plugin"
    PLUGIN_FAMILY = "General"
    PLUGIN_VERSION = "1.0"
    PLUGIN_SHORT_KEY = "base"   # Override in subclass (e.g. "ssl", "takeover")
    RISK_FACTOR = "INFO"         # CRITICAL, HIGH, MEDIUM, LOW, INFO
    CVSS_SCORE = 0.0             # 0.0 - 10.0
    CVE_IDS: List[str] = []      # List of CVE identifiers
    DESCRIPTION = ""
    SOLUTION = ""

    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        self.timeout = timeout
        self.findings: List[Finding] = []

        # Normalize target
        if "://" in target:
            self.host = target.split("://")[1].split("/")[0].split(":")[0]
        else:
            self.host = target.split("/")[0].split(":")[0]

        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target

    def add_finding(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: str | Dict[str, Any] = "",
        remediation: str = "",
        cve_ids: list = None,
        cvss: float = None,
        plugin_id: str = None,
    ):
        """Registers a standardized finding from this plugin."""
        evidence_dict = evidence if isinstance(evidence, dict) else {"raw": str(evidence)}
        cve = cve_ids[0] if (cve_ids and isinstance(cve_ids, list)) else (cve_ids or None)

        finding = Finding(
            title=title,
            severity=severity.upper(),  # type: ignore[arg-type]
            module=f"Plugin: {self.PLUGIN_NAME}",
            description=description,
            evidence=evidence_dict,
            remediation=remediation or self.SOLUTION or "Apply security patches.",
            target=self.url,
            cve=cve,
            cvss_score=cvss or self.CVSS_SCORE,
            tags=[self.PLUGIN_FAMILY.lower(), "plugin"],
        )
        self.findings.append(finding)

    @abstractmethod
    def run(self, progress_callback=None) -> dict:
        """
        Execute the plugin scan. Must be implemented by all subclasses.

        Returns:
            dict with keys:
                - 'plugin_name': str
                - 'plugin_family': str  
                - 'findings': list of finding dicts
                - 'error': str (optional, if scan failed)
        """
        pass

    def get_results(self) -> dict:
        """Returns standardized results after run() completes."""
        return {
            "plugin_id": self.PLUGIN_ID,
            "plugin_name": self.PLUGIN_NAME,
            "plugin_family": self.PLUGIN_FAMILY,
            "plugin_version": self.PLUGIN_VERSION,
            "target": self.url,
            "findings": [f.to_dict() for f in self.findings]
        }

    async def run_isolated(
        self,
        timeout: float = 60.0,
        discovered_subdomains: Optional[List[Dict[str, Any]]] = None,
        discovered_urls: Optional[List[str]] = None,
        existing_findings: Optional[List[Finding]] = None,
    ) -> List[Finding]:
        """
        Run the plugin in an isolated subprocess via runner.py.
        """
        from loguru import logger
        log = logger.bind(scanner=self.__class__.__name__)

        runner_path = Path(__file__).parent / "runner.py"
        if not runner_path.exists():
            log.error(f"Runner script not found at {runner_path}")
            return []

        # Prepare payload
        payload = {
            "plugin_module": self.__class__.__module__,
            "plugin_class": self.__class__.__name__,
            "target": self.target,
            "timeout": self.timeout,
        }
        if discovered_subdomains is not None:
            payload["discovered_subdomains"] = discovered_subdomains
        if discovered_urls is not None:
            payload["discovered_urls"] = discovered_urls
        if existing_findings is not None:
            payload["existing_findings"] = [f.to_dict() for f in existing_findings]

        try:
            # Determine command depending on whether running as frozen binary
            if getattr(sys, "frozen", False):
                cmd = [sys.executable, "_run_plugin"]
            else:
                scopex_py = Path(__file__).resolve().parent.parent / "scopex.py"
                cmd = [sys.executable, str(scopex_py), "_run_plugin"]

            # Spawn subprocess
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Feed stdin and wait for completion
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=json.dumps(payload).encode("utf-8")),
                timeout=timeout,
            )

            # Process stderr output (plugin printing/logging)
            if stderr:
                stderr_text = stderr.decode(errors="replace").strip()
                if stderr_text:
                    log.debug(f"Subprocess stderr:\n{stderr_text}")

            if proc.returncode != 0:
                log.error(f"Subprocess exited with code {proc.returncode}")
                return []

            # Parse stdout JSON
            stdout_text = stdout.decode(errors="replace").strip()
            if not stdout_text:
                return []

            result_dict = json.loads(stdout_text)
            findings: List[Finding] = []
            for f_dict in result_dict.get("findings", []):
                try:
                    findings.append(Finding.from_dict(f_dict))
                except Exception as e:
                    log.warning(f"Failed to deserialize isolated finding: {e}")

            return findings

        except asyncio.TimeoutError:
            log.warning(f"Plugin isolation execution timed out after {timeout}s")
            try:
                proc.kill()
                await proc.communicate()
            except Exception:
                pass
            return []
        except Exception as exc:
            log.error(f"Error during isolated plugin execution: {exc}")
            return []

    @staticmethod
    def cvss_to_severity(score: float) -> str:
        """Converts a CVSS 3.1 score to a severity label."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        return "INFO"
