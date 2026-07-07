"""
Unit tests for the ScopeX HTML Report Dashboard (Phase 11).
"""
import os
import json
import pytest
import httpx
from http.server import HTTPServer
import threading
import time
from reports.dashboard import DashboardHTTPRequestHandler


@pytest.fixture(scope="module")
def temp_output_reports():
    """Setup mock files in output/ directory for dashboard tests."""
    os.makedirs("output", exist_ok=True)
    json_path = os.path.join("output", "test_mock_scan.json")
    pdf_path = os.path.join("output", "test_mock_scan_report.pdf")
    
    mock_scan_data = {
        "scan_id": "test-uuid-12345",
        "target": "https://dashboard-test.local",
        "profile": "quick",
        "started_at": "2026-07-07T14:44:00Z",
        "findings": [
            {
                "id": "find-1",
                "title": "Mock Vulnerability",
                "severity": "HIGH",
                "module": "MockScanner",
                "description": "Vulnerability desc",
                "evidence": {"raw": "mock evidence"},
                "remediation": "mock fix",
                "target": "https://dashboard-test.local",
            }
        ]
    }
    
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(mock_scan_data, f)
        
    with open(pdf_path, "wb") as f:
        f.write(b"%PDF-1.4 Mock PDF content")
        
    yield json_path, pdf_path
    
    # Cleanup mock files
    for p in (json_path, pdf_path):
        if os.path.exists(p):
            os.remove(p)


@pytest.fixture(scope="module")
def run_test_server():
    """Starts a local HTTP server on a random port for testing."""
    # Find a free port dynamically
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()

    server = HTTPServer(("", port), DashboardHTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    
    # Allow port to bind
    time.sleep(0.5)
    
    yield f"http://localhost:{port}"
    
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.mark.asyncio
async def test_dashboard_index(run_test_server):
    url = run_test_server
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{url}/")
        assert resp.status_code == 200
        assert "ScopeX Security Dashboard" in resp.text
        assert "<style>" in resp.text


@pytest.mark.asyncio
async def test_dashboard_reports_api(run_test_server, temp_output_reports):
    url = run_test_server
    json_path, pdf_path = temp_output_reports
    
    async with httpx.AsyncClient() as client:
        # Check listing API
        resp = await client.get(f"{url}/api/reports")
        assert resp.status_code == 200
        reports = resp.json()
        assert len(reports) >= 2
        
        json_item = next((r for r in reports if r["name"] == "test_mock_scan.json"), None)
        assert json_item is not None
        assert json_item["size"] > 0
        
        pdf_item = next((r for r in reports if r["name"] == "test_mock_scan_report.pdf"), None)
        assert pdf_item is not None


@pytest.mark.asyncio
async def test_dashboard_single_report_apis(run_test_server, temp_output_reports):
    url = run_test_server
    json_path, pdf_path = temp_output_reports
    
    async with httpx.AsyncClient() as client:
        # Check single report data fetch
        resp = await client.get(f"{url}/api/report/test_mock_scan.json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == "test-uuid-12345"
        assert data["target"] == "https://dashboard-test.local"
        
        # Check PDF download
        resp_pdf = await client.get(f"{url}/api/download/test_mock_scan_report.pdf")
        assert resp_pdf.status_code == 200
        assert resp_pdf.headers.get("content-type") == "application/pdf"
        assert b"Mock PDF" in resp_pdf.content
