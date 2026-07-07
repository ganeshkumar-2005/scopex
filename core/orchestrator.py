"""
core/orchestrator.py — Async scan orchestration engine for ScopeX v2.

Replaces the sequential 28-parameter scan() function in scopex.py with:
  - One shared httpx.AsyncClient session (connection pool reuse)
  - One shared crawl (results stored in ScanContext)
  - asyncio.gather() for concurrent scanner execution
  - Per-scanner timeout enforcement
  - Checkpoint saving after scanner groups
  - Structured error handling (scanner crash -> log + continue)
  - Returns ScanResult with List[Finding]
"""
from __future__ import annotations

import asyncio
import importlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

import httpx
from loguru import logger

from core.context import ScanContext
from core.findings import Finding


@dataclass
class ScanResult:
    """Complete result of a ScopeX v2 scan."""
    scan_id: str
    target: str
    profile: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    nuclei_findings: List[Finding] = field(default_factory=list)
    scanners_run: List[str] = field(default_factory=list)
    scanners_failed: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def all_findings(self) -> List[Finding]:
        """All findings deduplicated."""
        from utils.deduplication import deduplicate_findings
        return deduplicate_findings(self.findings + self.nuclei_findings)

    def summary(self) -> Dict[str, int]:
        findings = self.all_findings
        return {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
            "high": sum(1 for f in findings if f.severity == "HIGH"),
            "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
            "low": sum(1 for f in findings if f.severity == "LOW"),
            "info": sum(1 for f in findings if f.severity == "INFO"),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": round(self.duration_seconds, 2),
            "findings": [f.to_dict() for f in self.findings],
            "nuclei_findings": [f.to_dict() for f in self.nuclei_findings],
            "scanners_run": self.scanners_run,
            "scanners_failed": self.scanners_failed,
            "summary": self.summary(),
        }


# Scanner registry: key -> (module_path, class_name)
_SCANNER_REGISTRY = {
    "headers":      ("scanners.header_scanner",       "HeaderScanner"),
    "ssl":          ("scanners.ssl_scanner",          "SSLScanner"),
    "dns":          ("scanners.dns_scanner",          "DNSScanner"),
    "cookies":      ("scanners.cookie_scanner",       "CookieScanner"),
    "tech":         ("scanners.tech_fingerprinter",   "TechFingerprinter"),
    "info":         ("scanners.info_disclosure",      "InfoDisclosureScanner"),
    "auth_paths":   ("scanners.auth_scanner",         "AuthScanner"),
    "api":          ("scanners.api_scanner",          "APIScanner"),
    "whois":        ("scanners.whois_scanner",        "WhoisScanner"),
    "subdomain":    ("scanners.subdomain_scanner",    "SubdomainScanner"),
    "sqli":         ("scanners.sqli_scanner",         "SQLiScanner"),
    "xss":          ("scanners.xss_scanner",          "XSSScanner"),
    "vulns":        ("scanners.vuln_scanner",         "VulnScanner"),
    "ports":        ("scanners.port_scanner",         "PortScanner"),
    "waf":          ("scanners.waf_detector",         "WAFDetector"),
    "custom_rules": ("scanners.custom_rules_scanner", "CustomRulesScanner"),
}

# Fast scanners that can all run in parallel
_FAST_SCANNERS = {"headers", "ssl", "dns", "cookies", "tech", "info", "auth_paths", "api", "whois", "custom_rules"}
# Slow scanners (deep testing) — run in parallel but separately from fast group
_SLOW_SCANNERS = {"sqli", "xss", "vulns", "subdomain", "ports"}


class ScanOrchestrator:
    """
    Async scan orchestrator.

    Usage::

        orchestrator = ScanOrchestrator()
        result = await orchestrator.run(ctx, scanners_to_run=["headers", "ssl", "sqli"])
    """

    def __init__(self) -> None:
        self.log = logger.bind(scanner="Orchestrator")
        self.progress_ctx = None
        self.progress_task = None

    async def run(
        self,
        ctx: ScanContext,
        scanners_to_run: Optional[List[str]] = None,
    ) -> ScanResult:
        """
        Execute the full scan pipeline and return a ScanResult.

        Args:
            ctx:             Shared scan context (target, profile, auth, etc.)
            scanners_to_run: If provided, only run these scanner keys.
                             If None, run all scanners for the profile.
        """
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)
        self.log.info(
            f"Starting scan [{scan_id[:8]}] target={ctx.target} profile={ctx.profile}"
        )

        result = ScanResult(
            scan_id=scan_id,
            target=ctx.target,
            profile=ctx.profile,
            started_at=started_at,
        )

        # Resolve scanners list initially
        if scanners_to_run is None:
            from core.config import get_profile
            try:
                profile_conf = get_profile(ctx.profile)
                scanners_list = profile_conf.get("scanners", list(_SCANNER_REGISTRY.keys()))
                if scanners_list == "all":
                    scanners_list = list(_SCANNER_REGISTRY.keys())
                scanners_to_run = list(scanners_list)
            except Exception:
                scanners_to_run = list(_SCANNER_REGISTRY.keys())

        # Resume support: restore previous results if checkpoint specified
        already_run = set()
        if ctx.resume_checkpoint:
            try:
                cp_path = Path(ctx.resume_checkpoint)
                if cp_path.exists():
                    with open(cp_path, "r", encoding="utf-8") as f:
                        cp_data = json.load(f)
                    
                    self.log.info(f"Resuming scan from checkpoint: {ctx.resume_checkpoint}")
                    result.scan_id = cp_data.get("scan_id", scan_id)
                    result.scanners_run = cp_data.get("scanners_run", [])
                    result.scanners_failed = cp_data.get("scanners_failed", [])
                    already_run = set(result.scanners_run)
                    
                    # Convert raw dict findings back to Finding objects
                    for raw_f in cp_data.get("findings", []):
                        try:
                            result.findings.append(Finding.from_dict(raw_f))
                        except Exception as e:
                            self.log.debug(f"Failed to load checkpoint finding: {e}")
                            
                    for raw_f in cp_data.get("nuclei_findings", []):
                        try:
                            result.nuclei_findings.append(Finding.from_dict(raw_f))
                        except Exception as e:
                            self.log.debug(f"Failed to load checkpoint nuclei finding: {e}")
                            
                    scanners_to_run = [s for s in scanners_to_run if s not in already_run]
                    self.log.info(f"Scanners remaining to run: {scanners_to_run}")
                else:
                    self.log.warning(f"Checkpoint file not found: {ctx.resume_checkpoint}; starting fresh scan")
            except Exception as exc:
                self.log.warning(f"Failed to load checkpoint ({exc}); starting fresh scan")

        # Setup rich progress if interactive (not outputting raw JSON to stdout)
        show_progress = not getattr(ctx, "output_json", False)
        if show_progress:
            try:
                from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
                import sys
                is_utf8 = getattr(sys.stdout, "encoding", "").lower() in ("utf-8", "utf8")
                spinner_name = "dots" if is_utf8 else "line"
                
                self.progress_ctx = Progress(
                    SpinnerColumn(spinner_name=spinner_name),
                    TextColumn("[bold cyan]{task.description}[/bold cyan]"),
                    BarColumn(bar_width=40, complete_style="green", finished_style="bold green"),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(),
                )
                
                # Count plugins that will run
                try:
                    from plugins import PLUGIN_REGISTRY
                    plugin_keys = list(PLUGIN_REGISTRY.keys())
                except Exception:
                    plugin_keys = []
                
                active_plugins_count = 0
                for name in plugin_keys:
                    if scanners_to_run is not None:
                        if f"plugin:{name}" not in scanners_to_run and "plugins" not in scanners_to_run:
                            continue
                    active_plugins_count += 1

                total_steps = 3 + len(scanners_to_run) + active_plugins_count + (0 if ctx.skip_nuclei else 1)
                self.progress_task = self.progress_ctx.add_task("Initializing Scan...", total=total_steps)
            except Exception as exc:
                self.log.debug(f"Failed to initialize rich progress: {exc}")
                self.progress_ctx = None

        try:
            if self.progress_ctx:
                self.progress_ctx.start()

            # Build shared httpx client
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=ctx.timeout + 5, write=10.0, pool=5.0),
                follow_redirects=True,
                verify=ctx.verify_ssl,  # Configurable: default False for pentest targets (self-signed certs)
                http2=True,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    )
                },
                cookies=ctx.auth.session_cookies if ctx.auth else {},
            ) as client:

                # 1. Authenticate if configured
                if ctx.auth and ctx.auth.login_url:
                    await self._setup_auth(ctx, client)
                else:
                    self._update_progress("Authentication skipped", advance=1)

                # 2. WAF detection first (adapts subsequent evasion)
                await self._run_waf_detection(ctx, client, result)

                # 3. Shared crawler run (populates ctx.discovered_urls)
                await self._run_crawl(ctx, client)

                # 4. Concurrent scanner execution
                await self._run_scanners(ctx, client, result, scanners_to_run)

                # 5. Nuclei orchestration (after ScopeX scans)
                if not ctx.skip_nuclei:
                    await self._run_nuclei(ctx, result)

        finally:
            if self.progress_ctx:
                self.progress_ctx.stop()
                self.progress_ctx = None
                self.progress_task = None

        # Finalize
        result.completed_at = datetime.now(timezone.utc)
        result.duration_seconds = (result.completed_at - result.started_at).total_seconds()
        s = result.summary()
        self.log.info(
            f"Scan complete in {result.duration_seconds:.1f}s | "
            f"C:{s['critical']} H:{s['high']} M:{s['medium']} L:{s['low']} I:{s['info']} | "
            f"{len(result.scanners_failed)} scanner failure(s)"
        )
        return result

    async def _setup_auth(self, ctx: ScanContext, client: httpx.AsyncClient) -> None:
        """Run authentication flow."""
        self._update_progress("Authenticating target...")
        try:
            from scanners.auth_state_manager import AuthStateManager
            manager = AuthStateManager(ctx.auth, client)  # type: ignore[arg-type]
            success = await manager.login()
            if not success:
                self.log.warning("Authentication failed; scanning unauthenticated")
        except Exception as exc:
            self.log.error(f"Auth setup failed: {exc}")
        finally:
            self._update_progress("Authentication done", advance=1)

    async def _run_waf_detection(
        self, ctx: ScanContext, client: httpx.AsyncClient, result: ScanResult
    ) -> None:
        """Run WAF detection before main scans to set ctx.waf_detected."""
        self._update_progress("Checking WAF posture...")
        try:
            cls = self._load_scanner("waf")
            if cls is None:
                return
            scanner = cls(ctx, client)
            findings = await asyncio.wait_for(scanner.scan(), timeout=30.0)
            result.findings.extend(findings)
            result.scanners_run.append("waf")
            for f in findings:
                if f.severity in ("MEDIUM", "HIGH") and "waf" in f.title.lower():
                    ctx.waf_detected = True
                    ctx.waf_vendor = f.evidence.get("vendor") or f.evidence.get("waf_name")
                    if ctx.waf_evasion:
                        self.log.info(f"WAF detected ({ctx.waf_vendor}); evasion active")
                    break
        except Exception as exc:
            self.log.warning(f"WAF detection failed: {exc}")
            result.scanners_failed.append("waf")
        finally:
            self._update_progress("WAF check complete", advance=1)

    async def _run_crawl(self, ctx: ScanContext, client: httpx.AsyncClient) -> None:
        """Run the shared async crawler once; populate ScanContext with discovered URLs."""
        self._update_progress("Crawling target endpoints...")
        try:
            from scanners.crawler import AsyncCrawler
            crawler = AsyncCrawler(ctx, client)
            discovered = await asyncio.wait_for(crawler.crawl(), timeout=60.0)
            ctx.discovered_urls = discovered.get("urls_with_params", [])
            ctx._form_targets = discovered.get("form_targets", [])  # type: ignore[attr-defined]
            self.log.info(
                f"Crawl complete: {len(ctx.discovered_urls)} parameterized URLs, "
                f"{len(ctx._form_targets)} forms"  # type: ignore[attr-defined]
            )
        except asyncio.TimeoutError:
            self.log.warning("Crawler timed out after 60s")
        except ImportError:
            self.log.debug("AsyncCrawler not available; skipping crawler phase")
        except Exception as exc:
            self.log.error(f"Crawler failed: {exc}")
        finally:
            self._update_progress("Crawler complete", advance=1)

    async def _run_scanners(
        self,
        ctx: ScanContext,
        client: httpx.AsyncClient,
        result: ScanResult,
        scanners_to_run: Optional[List[str]],
    ) -> None:
        """Run configured scanners in two concurrent groups: fast then slow."""
        available = {
            k: self._load_scanner(k)
            for k in _SCANNER_REGISTRY
            if k != "waf"
        }
        available = {k: v for k, v in available.items() if v is not None}

        if scanners_to_run:
            active = {k: v for k, v in available.items() if k in scanners_to_run}
        else:
            active = available

        fast = {k: v for k, v in active.items() if k in _FAST_SCANNERS}
        slow = {k: v for k, v in active.items() if k in _SLOW_SCANNERS}

        # Run fast scanners concurrently
        if fast:
            tasks = [
                self._timed_scanner(name, cls, ctx, client, timeout=60.0)
                for name, cls in fast.items()
            ]
            await self._gather_results(fast.keys(), tasks, result)
            self._save_checkpoint(result)

        # Run slow scanners concurrently
        if slow:
            tasks = [
                self._timed_scanner(name, cls, ctx, client, timeout=120.0)
                for name, cls in slow.items()
            ]
            await self._gather_results(slow.keys(), tasks, result)
            self._save_checkpoint(result)

        # Run plugins (sequential; compliance last)
        await self._run_plugins(ctx, result, scanners_to_run)

    async def _gather_results(self, names, tasks, result: ScanResult) -> None:
        """Gather scanner coroutines and collect results into ScanResult."""
        raw = await asyncio.gather(*tasks, return_exceptions=True)
        for name, res in zip(names, raw):
            if isinstance(res, list):
                result.findings.extend(res)
                result.scanners_run.append(name)
            elif isinstance(res, Exception):
                self.log.error(f"Scanner '{name}' failed: {res}")
                result.scanners_failed.append(name)

    async def _timed_scanner(
        self,
        name: str,
        cls: Type,
        ctx: ScanContext,
        client: httpx.AsyncClient,
        timeout: float,
    ) -> List[Finding]:
        """Instantiate and run a scanner with timeout isolation."""
        self._update_progress(f"Running scanner: {name}...")
        self.log.info(f"Starting scanner: {name}")
        try:
            scanner = cls(ctx, client)
            findings = await asyncio.wait_for(scanner.scan(), timeout=timeout)
            self.log.info(f"Scanner '{name}' done: {len(findings)} finding(s)")
            return findings
        except asyncio.TimeoutError:
            self.log.warning(f"Scanner '{name}' timed out after {timeout}s")
            return []
        except Exception as exc:
            self.log.error(f"Scanner '{name}' raised: {exc}", exc_info=True)
            raise
        finally:
            self._update_progress(f"Scanner {name} done", advance=1)

    async def _run_plugins(
        self,
        ctx: ScanContext,
        result: ScanResult,
        scanners_to_run: Optional[List[str]] = None,
    ) -> None:
        """Run plugins in isolated subprocesses."""
        try:
            from plugins import PLUGIN_REGISTRY
        except ImportError:
            return

        plugin_order = [k for k in PLUGIN_REGISTRY if k != "compliance"] + ["compliance"]

        # Map discovered subdomains list of strings to list of dicts for takeover plugin compatibility
        subdomain_dicts = [{"subdomain": s, "ip": ""} for s in ctx.discovered_subdomains]

        for name in plugin_order:
            if scanners_to_run is not None:
                if f"plugin:{name}" not in scanners_to_run and "plugins" not in scanners_to_run:
                    continue

            plugin_info = PLUGIN_REGISTRY.get(name)
            if not plugin_info:
                continue
            self._update_progress(f"Running isolated plugin: {name}...")
            try:
                plugin_cls = plugin_info["class"]
                # Instantiate with target only
                plugin = plugin_cls(target=ctx.target)
                
                # Execute in isolated subprocess
                findings = await plugin.run_isolated(
                    timeout=90.0,
                    discovered_subdomains=subdomain_dicts,
                    discovered_urls=ctx.discovered_urls,
                    existing_findings=result.findings,
                )
                
                # Add findings to the result
                result.findings.extend(findings)
                result.scanners_run.append(f"plugin:{name}")
            except Exception as exc:
                self.log.error(f"Plugin '{name}' failed: {exc}")
                result.scanners_failed.append(f"plugin:{name}")
            finally:
                self._update_progress(f"Plugin {name} done", advance=1)

    async def _run_nuclei(self, ctx: ScanContext, result: ScanResult) -> None:
        """Run Nuclei orchestration."""
        self._update_progress("Running Nuclei scanner...")
        try:
            from utils.nuclei_orchestrator import NucleiOrchestrator, NucleiNotFoundError
            orchestrator = NucleiOrchestrator(ctx)
            nuclei_findings = await orchestrator.run(existing_findings=result.findings)
            result.nuclei_findings = nuclei_findings
            result.scanners_run.append("nuclei")
        except Exception as exc:
            self.log.warning(f"Nuclei skipped: {exc}")
            result.scanners_failed.append("nuclei")
        finally:
            self._update_progress("Nuclei complete", advance=1)

    def _save_checkpoint(self, result: ScanResult) -> None:
        """Save intermediate scan results to disk."""
        try:
            checkpoint_dir = Path("output") / "checkpoints"
            checkpoint_dir.mkdir(parents=True, exist_ok=True)
            cp_file = checkpoint_dir / f"{result.scan_id[:8]}_checkpoint.json"
            with open(cp_file, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            self.log.debug(f"Checkpoint saved: {cp_file}")
        except Exception as exc:
            self.log.debug(f"Checkpoint save failed: {exc}")

    def _load_scanner(self, key: str) -> Optional[Type]:
        """Dynamically load a scanner class by registry key."""
        entry = _SCANNER_REGISTRY.get(key)
        if not entry:
            return None
        module_path, class_name = entry
        try:
            mod = importlib.import_module(module_path)
            return getattr(mod, class_name)
        except (ImportError, AttributeError) as exc:
            self.log.debug(f"Could not load scanner '{key}': {exc}")
            return None

    def _update_progress(self, description: str, advance: float = 0.0) -> None:
        """Helper to safely update the console progress bar if active."""
        if self.progress_ctx and self.progress_task is not None:
            self.progress_ctx.update(self.progress_task, description=description, advance=advance)
