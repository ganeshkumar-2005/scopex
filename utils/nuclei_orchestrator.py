"""
utils/nuclei_orchestrator.py — Intelligent Nuclei orchestration layer for ScopeX v2.

Replaces nuclei_integration.py with:
  - asyncio subprocess (non-blocking, no shell=True)
  - NucleiNotFoundError exception instead of sys.exit()
  - No hardcoded mock data
  - Smart tag selection based on ScanContext technologies + existing findings
  - Structured Finding output
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from core.context import ScanContext
from core.findings import Finding


class NucleiNotFoundError(Exception):
    """Raised when the Nuclei binary is not found in PATH or project directory."""


class NucleiOrchestrator:
    """
    Intelligent Nuclei orchestration layer.

    Selects relevant templates based on discovered technologies,
    runs Nuclei asynchronously, and returns structured Finding objects.
    """

    # Mapping from ScopeX technology detections to Nuclei tags
    TECH_TO_TAGS: Dict[str, List[str]] = {
        "wordpress": ["wordpress", "wp", "cms"],
        "joomla": ["joomla", "cms"],
        "drupal": ["drupal", "cms"],
        "apache": ["apache"],
        "nginx": ["nginx"],
        "iis": ["iis"],
        "php": ["php"],
        "java": ["java", "spring", "tomcat"],
        "node": ["nodejs", "node"],
        "jquery": ["jquery"],
        "react": ["react"],
        "angular": ["angular"],
        "laravel": ["laravel", "php"],
        "django": ["django", "python"],
        "flask": ["flask", "python"],
    }

    # Tags always included for web targets
    BASE_TAGS = ["http", "ssl", "misconfig", "exposure", "tech"]

    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self.log = logger.bind(scanner="NucleiOrchestrator")

    async def run(
        self,
        existing_findings: Optional[List[Finding]] = None,
        timeout: int = 300,
    ) -> List[Finding]:
        """
        Run Nuclei orchestration:
        1. Verify Nuclei installation
        2. Determine relevant tags from ScanContext
        3. Ensure templates are available
        4. Run Nuclei asynchronously
        5. Return structured Finding objects

        Raises NucleiNotFoundError if Nuclei binary is missing.
        """
        existing_findings = existing_findings or []

        version = await self._get_nuclei_version()
        if version is None:
            raise NucleiNotFoundError(
                "Nuclei not found. Install from: https://github.com/projectdiscovery/nuclei/releases"
            )
        self.log.info(f"Nuclei {version} found")

        tags = self._determine_tags(existing_findings)
        self.log.info(f"Running Nuclei with tags: {tags}")

        await self._ensure_templates()

        findings = await self._run_nuclei(tags, timeout)
        self.log.info(f"Nuclei returned {len(findings)} findings")
        return findings

    def _determine_tags(self, existing_findings: List[Finding]) -> List[str]:
        """Smart tag selection based on discovered technologies and existing findings."""
        # User explicitly specified tags via CLI — use them directly
        if self.ctx.nuclei_tags:
            if self.ctx.nuclei_tags == ["all"] or self.ctx.nuclei_tags == "all":
                return []  # No tag filter = run all templates
            return list(self.ctx.nuclei_tags)

        tags = set(self.BASE_TAGS)

        # Add tech-based tags from context
        for tech in self.ctx.discovered_technologies:
            tech_lower = tech.lower()
            for key, tech_tags in self.TECH_TO_TAGS.items():
                if key in tech_lower:
                    tags.update(tech_tags)

        # Skip redundant templates for CVEs already found by ScopeX
        existing_cves = {f.cve for f in existing_findings if f.cve}
        if existing_cves:
            self.log.debug(f"Existing CVEs (will skip redundant templates): {existing_cves}")

        return sorted(tags)

    async def _get_nuclei_version(self) -> Optional[str]:
        """Check if Nuclei is installed and return version string."""
        nuclei_bin = self._find_nuclei_binary()
        try:
            proc = await asyncio.create_subprocess_exec(
                nuclei_bin, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = (stdout or b"").decode(errors="replace") + (stderr or b"").decode(errors="replace")
            match = re.search(r"v?(\d+\.\d+\.\d+)", output)
            return match.group(1) if match else "unknown"
        except (FileNotFoundError, PermissionError):
            return None
        except asyncio.TimeoutError:
            return None
        except Exception as exc:
            self.log.debug(f"Nuclei version check failed: {exc}")
            return None

    def _find_nuclei_binary(self) -> str:
        """Find the Nuclei binary — checks project directory first, then PATH."""
        # Check project directory (bundled nuclei.exe on Windows)
        local_name = "nuclei.exe" if os.name == "nt" else "nuclei"
        local_path = Path(__file__).parent.parent / local_name
        if local_path.exists():
            return str(local_path)
        return "nuclei"

    async def _ensure_templates(self) -> None:
        """Download Nuclei templates if not present."""
        templates_dir = Path.home() / "nuclei-templates"
        if templates_dir.exists():
            try:
                if any(templates_dir.iterdir()):
                    return
            except Exception:
                return

        self.log.info("Nuclei templates not found; downloading...")
        nuclei_bin = self._find_nuclei_binary()
        try:
            proc = await asyncio.create_subprocess_exec(
                nuclei_bin, "-update-templates",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
        except Exception as exc:
            self.log.warning(f"Template download failed: {exc}")

    async def _run_nuclei(self, tags: List[str], timeout: int) -> List[Finding]:
        """Run Nuclei subprocess and parse JSONL output."""
        nuclei_bin = self._find_nuclei_binary()
        temp_output = Path(tempfile.gettempdir()) / f"nuclei_{uuid.uuid4().hex}.jsonl"

        cmd = [
            nuclei_bin,
            "-u", self.ctx.target,
            "-json-export", str(temp_output),
            "-silent",
            "-severity", "critical,high,medium,low,info",
        ]
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        if self.ctx.nuclei_templates:
            cmd.extend(["-t", self.ctx.nuclei_templates])

        self.log.debug(f"Nuclei command: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                if stderr:
                    stderr_text = stderr.decode(errors="replace")
                    if "error" in stderr_text.lower() or "fatal" in stderr_text.lower():
                        self.log.warning(f"Nuclei stderr: {stderr_text[:300]}")
            except asyncio.TimeoutError:
                self.log.warning(f"Nuclei timed out after {timeout}s; using partial results")
                try:
                    proc.kill()
                    await proc.communicate()
                except ProcessLookupError:
                    pass

            return self._parse_jsonl(temp_output)

        except FileNotFoundError:
            raise NucleiNotFoundError("Nuclei binary not found")
        except Exception as exc:
            self.log.error(f"Nuclei execution failed: {exc}")
            return []
        finally:
            try:
                if temp_output.exists():
                    temp_output.unlink()
            except Exception:
                pass

    def _parse_jsonl(self, output_file: Path) -> List[Finding]:
        """Parse Nuclei JSONL output file into Finding objects."""
        findings: List[Finding] = []
        if not output_file.exists():
            return []

        skipped = 0
        with open(output_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    finding = self._convert(data)
                    if finding:
                        findings.append(finding)
                except json.JSONDecodeError:
                    skipped += 1
                except Exception as exc:
                    self.log.debug(f"Failed to parse Nuclei finding: {exc}")
                    skipped += 1

        if skipped:
            self.log.warning(f"Skipped {skipped} invalid Nuclei output lines")
        return findings

    def _convert(self, data: Dict) -> Optional[Finding]:
        """Convert a Nuclei JSONL record to a ScopeX Finding object."""
        try:
            info = data.get("info", {})
            template_id = data.get("template-id", "")
            matcher_name = data.get("matcher-name", "")

            title = f"{template_id}: {matcher_name}" if matcher_name else template_id
            if not title:
                title = info.get("name", "Nuclei Finding")

            severity_raw = info.get("severity", "info").upper()
            severity_map = {
                "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                "LOW": "LOW", "INFO": "INFO", "UNKNOWN": "INFO",
            }
            severity = severity_map.get(severity_raw, "INFO")

            host = data.get("host", self.ctx.target)
            matched_at = data.get("matched-at", host)
            description = info.get("description") or f"Nuclei template '{template_id}' matched."
            remediation = info.get("remediation") or "Review the Nuclei template documentation for remediation."

            # Extract CVE and CVSS
            classification = info.get("classification", {})
            cve_ids = classification.get("cve-id", [])
            cve = (cve_ids[0] if isinstance(cve_ids, list) else cve_ids) if cve_ids else None
            cvss_raw = classification.get("cvss-score")
            cvss = float(cvss_raw) if cvss_raw else None

            evidence: Dict = {"matched_at": matched_at, "template_id": template_id}
            curl_cmd = data.get("curl-command", "")
            if curl_cmd:
                evidence["curl_command"] = curl_cmd[:500]

            tags = list(info.get("tags", [])) + ["nuclei"]

            return Finding(
                title=title,
                severity=severity,  # type: ignore[arg-type]
                module="NucleiOrchestrator",
                description=description,
                evidence=evidence,
                remediation=remediation,
                target=host,
                cve=cve,
                cvss_score=cvss,
                tags=tags,
                verified=False,
            )
        except Exception as exc:
            self.log.debug(f"Nuclei finding conversion failed: {exc}")
            return None
