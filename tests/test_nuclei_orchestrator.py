"""
Unit tests for utils/nuclei_orchestrator.py
"""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path
from core.findings import Finding
from utils.nuclei_orchestrator import NucleiOrchestrator, NucleiNotFoundError

def test_determine_tags(default_context):
    orchestrator = NucleiOrchestrator(default_context)

    # 1. Base tags only — returns (tags, skip_cves) tuple
    tags, skip_cves = orchestrator._determine_tags([])
    assert "http" in tags
    assert "ssl" in tags
    assert skip_cves == set()  # no existing CVEs

    # 2. Tech-based tags
    default_context.discovered_technologies = ["WordPress 6.0", "Nginx"]
    tags, skip_cves = orchestrator._determine_tags([])
    assert "wordpress" in tags
    assert "nginx" in tags

    # 3. CVE-skip: findings with CVEs should populate skip_cves
    from core.findings import Finding
    cve_finding = Finding(
        title="Log4Shell RCE",
        description="Log4j RCE",
        severity="CRITICAL",
        target="https://example.com",
        module="test",
        evidence={},
        remediation="Upgrade Log4j.",
        cve="CVE-2021-44228",
    )
    default_context.nuclei_tags = []
    tags, skip_cves = orchestrator._determine_tags([cve_finding])
    assert "CVE-2021-44228" in skip_cves

    # 4. Custom CLI tags
    default_context.nuclei_tags = ["cve", "xss"]
    tags, skip_cves = orchestrator._determine_tags([])
    assert tags == ["cve", "xss"]

    # 5. Custom CLI "all"
    default_context.nuclei_tags = ["all"]
    tags, skip_cves = orchestrator._determine_tags([])
    assert tags == []

@pytest.mark.asyncio
async def test_get_nuclei_version_missing(default_context):
    orchestrator = NucleiOrchestrator(default_context)

    # Mock FileNotFoundError on subprocess execute
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
        version = await orchestrator._get_nuclei_version()
        assert version is None

@pytest.mark.asyncio
async def test_get_nuclei_version_success(default_context):
    orchestrator = NucleiOrchestrator(default_context)

    mock_proc = AsyncMock()
    mock_proc.communicate.return_value = (b"nuclei version v3.1.2", b"")
    
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        version = await orchestrator._get_nuclei_version()
        assert version == "3.1.2"

@pytest.mark.asyncio
async def test_run_missing_nuclei_raises_error(default_context):
    orchestrator = NucleiOrchestrator(default_context)

    with patch.object(orchestrator, "_get_nuclei_version", return_value=None), \
         patch.object(orchestrator, "_install_nuclei", return_value=False):
        with pytest.raises(NucleiNotFoundError):
            await orchestrator.run()

@pytest.mark.asyncio
async def test_run_success_and_parse(default_context, tmp_path):
    orchestrator = NucleiOrchestrator(default_context)

    # Create dummy JSONL file
    dummy_jsonl = tmp_path / "dummy.jsonl"
    finding_data = {
        "template-id": "cve-2021-44228",
        "matcher-name": "log4j-rce",
        "host": "https://example.com",
        "matched-at": "https://example.com/log4j",
        "info": {
            "name": "Apache Log4j RCE",
            "severity": "critical",
            "description": "Log4j RCE vulnerability",
            "remediation": "Upgrade Log4j",
            "classification": {
                "cve-id": ["CVE-2021-44228"],
                "cvss-score": 10.0
            },
            "tags": ["rce", "cve"]
        },
        "curl-command": "curl -i https://example.com/log4j"
    }
    with open(dummy_jsonl, "w", encoding="utf-8") as f:
        f.write(json.dumps(finding_data) + "\n")

    # Mock _get_nuclei_version, _ensure_templates, and _run_nuclei
    with patch.object(orchestrator, "_get_nuclei_version", return_value="3.1.2"), \
         patch.object(orchestrator, "_ensure_templates", return_value=None), \
         patch.object(orchestrator, "_run_nuclei") as mock_run:
        
        # When _run_nuclei is called, we return findings parsed from dummy_jsonl
        mock_run.return_value = orchestrator._parse_jsonl(dummy_jsonl)

        findings = await orchestrator.run()
        assert len(findings) == 1
        f = findings[0]
        assert f.title == "cve-2021-44228: log4j-rce"
        assert f.severity == "CRITICAL"
        assert f.cve == "CVE-2021-44228"
        assert f.cvss_score == 10.0
        assert f.target == "https://example.com"
        assert "nuclei" in f.tags

@pytest.mark.asyncio
async def test_run_windows_subprocess_args_and_no_shell(default_context):
    with patch("os.name", "nt"), \
         patch("utils.nuclei_orchestrator.NucleiOrchestrator._get_nuclei_version", return_value="3.2.9"), \
         patch("utils.nuclei_orchestrator.NucleiOrchestrator._ensure_templates", return_value=None), \
         patch("asyncio.create_subprocess_exec") as mock_exec:
        
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_exec.return_value = mock_proc
        
        orchestrator = NucleiOrchestrator(default_context)
        
        with patch.object(orchestrator, "_parse_jsonl", return_value=[]):
            findings = await orchestrator.run()
            assert findings == []
            
            mock_exec.assert_called()
            called_args = mock_exec.call_args[0]
            assert isinstance(called_args, tuple)
            assert len(called_args) > 1

@pytest.mark.asyncio
async def test_demo_testfire_zero_findings_no_fabrication(default_context):
    default_context.target = "http://demo.testfire.net"
    default_context.host = "demo.testfire.net"
    
    orchestrator = NucleiOrchestrator(default_context)
    with patch.object(orchestrator, "_get_nuclei_version", return_value="3.2.9"), \
         patch.object(orchestrator, "_ensure_templates", return_value=None), \
         patch.object(orchestrator, "_run_nuclei", return_value=[]):
        
        findings = await orchestrator.run()
        assert len(findings) == 0
