"""
Unit tests for CustomRulesScanner (Phase 9 signature matching engine).
"""
import os
import pytest
import respx
import httpx
from core.context import ScanContext
from core.findings import Finding
from scanners.custom_rules_scanner import CustomRulesScanner, _load_yaml_simple


def test_load_yaml_simple():
    content = """
# Exposed Git Repository Config
id: exposed_git
title: "Exposed Git Repository"
severity: "CRITICAL"
description: "The target has a publicly accessible Git configuration file."
match:
  paths:
    - "/.git/config"
  status: 200
  body:
    - "\\[core\\]"
    - "repositoryformatversion"
"""
    parsed = _load_yaml_simple(content)
    assert parsed["id"] == "exposed_git"
    assert parsed["title"] == "Exposed Git Repository"
    assert parsed["severity"] == "CRITICAL"
    assert "paths" in parsed["match"]
    assert parsed["match"]["paths"] == ["/.git/config"]
    assert parsed["match"]["status"] == "200"
    assert parsed["match"]["body"] == ["\\[core\\]", "repositoryformatversion"]


@pytest.mark.asyncio
@respx.mock
async def test_custom_rules_scanner_exposed_git():
    target = "https://example-test.local"
    ctx = ScanContext(target=target, host="example-test.local", profile="quick")
    
    # Mock exposed Git repository response
    git_config_content = """[core]
repositoryformatversion = 0
filemode = true
bare = false
logallrefupdates = true
"""
    respx.get(f"{target}/.git/config").mock(
        return_value=httpx.Response(200, text=git_config_content)
    )
    
    # Mock all other rules to return 404
    respx.get(f"{target}/.env").mock(return_value=httpx.Response(404))
    respx.get(f"{target}/admin/login.php").mock(return_value=httpx.Response(404))
    respx.get(f"{target}/wp-admin").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        scanner = CustomRulesScanner(ctx, client)
        findings = await scanner.scan()

    # Should detect exposed git config!
    git_finding = next((f for f in findings if f.evidence.get("rule_id") == "exposed_git"), None)
    assert git_finding is not None
    assert git_finding.severity == "CRITICAL"
    assert "Exposed Git" in git_finding.title
    assert git_finding.target == f"{target}/.git/config"


@pytest.mark.asyncio
@respx.mock
async def test_custom_rules_scanner_clean():
    target = "https://example-clean.local"
    ctx = ScanContext(target=target, host="example-clean.local", profile="quick")
    
    # Mock clean responses returning 404
    respx.get(f"{target}/.git/config").mock(return_value=httpx.Response(404))
    respx.get(f"{target}/.env").mock(return_value=httpx.Response(404))
    respx.get(f"{target}/admin/login.php").mock(return_value=httpx.Response(404))
    respx.get(f"{target}/wp-admin").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        scanner = CustomRulesScanner(ctx, client)
        findings = await scanner.scan()

    # No findings should be returned
    assert len(findings) == 0
