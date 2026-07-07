"""
Integration tests for ScopeX v2 full scan pipeline.
Tests Orchestrator -> Scanners -> Deduplication -> Reporting flow.
"""
import json
import os
from pathlib import Path
from unittest.mock import patch, AsyncMock
import pytest
import respx
import httpx
from core.context import ScanContext
from core.orchestrator import ScanOrchestrator
from reports.json_report import generate_json_report
from reports.pdf_report import generate_pdf_report


@pytest.mark.asyncio
@respx.mock
async def test_full_scan_pipeline_integration(tmp_path):
    # Setup target routes via respx
    target_url = "https://scan-target.local"
    
    # 1. Search page response (vulnerable to SQLi error) - Register first (most specific)
    # Use url__startswith to capture all parameters and payloads injected by sqli_scanner
    respx.get(url__startswith=f"{target_url}/search.php").mock(
        return_value=httpx.Response(
            200,
            text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        )
    )
    
    # 2. Login page response
    respx.get(f"{target_url}/login.php").mock(
        return_value=httpx.Response(200, text='<form action="/login.php" method="POST"><input name="username"><input name="password"></form>')
    )
    respx.post(f"{target_url}/login.php").mock(
        return_value=httpx.Response(302, headers={"Location": "/dashboard.php", "Set-Cookie": "session=logged_in_user_cookie"})
    )
    
    # 3. Homepage response - Register catch-all root last
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            headers={
                "Server": "Apache/2.4.41 (Ubuntu)",
                "X-Powered-By": "PHP/7.4.3",
                "Set-Cookie": "session=xyz123; HttpOnly",
            },
            text='<html><body><h1>Welcome</h1><a href="/login.php">Login</a><a href="/search.php?q=test">Search</a></body></html>'
        )
    )

    # Instantiate ScanContext
    ctx = ScanContext(
        target=target_url,
        host="scan-target.local",
        profile="quick",
        timeout=1.0,
        skip_nuclei=True,  # Skip nuclei to avoid running local binary
    )
    ctx.discovered_technologies = ["apache", "php"]

    # Run orchestrator, mocking the crawl phase to return the vulnerable search parameter
    orchestrator = ScanOrchestrator()
    scanners = ["headers", "cookies", "tech", "sqli"]
    
    mock_crawl = AsyncMock()
    mock_crawl.return_value = {
        "urls_with_params": [f"{target_url}/search.php?q=test"],
        "form_targets": []
    }
    
    with patch("scanners.crawler.AsyncCrawler.crawl", mock_crawl):
        result = await orchestrator.run(ctx, scanners_to_run=scanners)
    
    # Verify orchestrator ran successfully
    assert result.scan_id is not None
    assert "headers" in result.scanners_run
    assert "cookies" in result.scanners_run
    assert "sqli" in result.scanners_run
    
    # Verify findings collected
    assert len(result.findings) > 0
    
    # Check that SQLi scanner found the vulnerability and returned a CRITICAL severity Finding object
    sqli_finding = next((f for f in result.findings if f.module == "SQLiScanner" and f.severity == "CRITICAL"), None)
    assert sqli_finding is not None
    assert "SQL Injection" in sqli_finding.title

    # Generate JSON Report
    json_path = tmp_path / "result.json"
    generate_json_report(result.to_dict(), output_file=str(json_path))
    assert json_path.exists()
    with open(json_path, "r", encoding="utf-8") as f:
        json_data = json.load(f)
    assert json_data["scan_id"] == result.scan_id

    # Generate PDF Report
    pdf_path = tmp_path / "result.pdf"
    generate_pdf_report(result.to_dict(), output_filepath=str(pdf_path))
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0
