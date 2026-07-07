"""
Unit tests for reports/json_report.py
"""
import json
import pytest
from reports.json_report import generate_json_report

def test_generate_json_report(tmp_path):
    scan_data = {
        "scan_id": "test-uuid-123",
        "target": "https://example.com",
        "profile": "standard",
        "findings": [
            {
                "title": "SQL Injection",
                "severity": "HIGH",
                "module": "SQLiScanner",
                "description": "SQL Injection vulnerability",
                "evidence": {"param": "id"},
                "remediation": "Fix it",
                "target": "https://example.com/page.php?id=1",
            }
        ],
        "nuclei_findings": []
    }

    # Test generation to string
    json_str = generate_json_report(scan_data, to_stdout=False)
    decoded = json.loads(json_str)
    assert decoded["scopex_version"] == "2.0.0"
    assert decoded["report_type"] == "web_vapt"
    assert decoded["scan_id"] == "test-uuid-123"
    assert decoded["findings"][0]["title"] == "SQL Injection"

    # Test writing to file
    outfile = tmp_path / "report.json"
    generate_json_report(scan_data, output_file=str(outfile), to_stdout=False)
    assert outfile.exists()
    
    with open(outfile, "r", encoding="utf-8") as f:
        file_data = json.load(f)
    assert file_data["scan_id"] == "test-uuid-123"
    assert file_data["report_type"] == "web_vapt"
