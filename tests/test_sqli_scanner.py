import pytest
import time
from unittest.mock import patch, MagicMock
from scanners.sqli_scanner import SQLiScanner

def test_sqli_scanner_no_params():
    """Test that SQLiScanner skips and logs INFO when no query params are present in URL."""
    scanner = SQLiScanner("http://example.com/index.php")
    res = scanner.scan()
    assert "findings" in res
    assert len(res["findings"]) == 1
    assert res["findings"][0]["title"] == "No URL Parameters Found to Test"
    assert res["findings"][0]["severity"] == "INFO"

@patch("scanners.sqli_scanner.make_web_request")
def test_sqli_scanner_error_based(mock_request):
    """Test that SQLiScanner detects Error-Based SQLi when a database error appears in response."""
    # Mock baseline request
    mock_baseline = MagicMock()
    mock_baseline.text = "This is a normal database output."
    mock_baseline.status_code = 200
    
    # Mock vulnerable parameter response (MySQL error)
    mock_vuln = MagicMock()
    mock_vuln.text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    mock_vuln.status_code = 200
    
    # Side effects: baseline request first, then error payload requests.
    # The first payload is error_payloads[0]. We return normal baseline response for first payload,
    # and vulnerable response for the second payload.
    mock_request.side_effect = [
        mock_baseline, # Baseline request
        mock_baseline, # First payload: '
        mock_vuln,     # Second payload: "
        mock_baseline, 
        mock_baseline,
        mock_baseline
    ]
    
    scanner = SQLiScanner("http://example.com/index.php?id=1")
    res = scanner.scan()
    
    assert "findings" in res
    assert len(res["findings"]) == 1
    finding = res["findings"][0]
    assert finding["title"] == "Error-Based SQL Injection Vulnerability"
    assert finding["severity"] == "CRITICAL"
    assert "MySQL" in finding["evidence"]
    assert "MySQL" in finding["description"]

@patch("scanners.sqli_scanner.make_web_request")
@patch("scanners.sqli_scanner.time.time")
def test_sqli_scanner_time_blind(mock_time, mock_request):
    """Test that SQLiScanner detects Time-Based Blind SQLi using the two-step verification mechanism."""
    # Mock baseline request
    mock_baseline = MagicMock()
    mock_baseline.text = "This is a normal database output."
    mock_baseline.status_code = 200
    
    # Simulate elapsed time using mock_time
    # baseline request: start=0.0, end=0.1 (elapsed=0.1)
    # error-based payloads (6 of them, none trigger SQLi):
    # each request starts and ends, time diff is 0.1s.
    # time-based payload 1 (MySQL sleep(5)):
    # request start=1.0, end=6.1 (elapsed=5.1)
    # confirmation request (MySQL sleep(2)):
    # request start=7.0, end=9.1 (elapsed=2.1)
    
    time_values = [
        0.0, 0.1,  # Baseline start, end (elapsed = 0.1)
        1.0, 6.1,  # MySQL sleep(5) start, end (elapsed = 5.1)
        7.0, 9.1,  # MySQL sleep(2) confirmation start, end (confirm_elapsed = 2.1)
    ]
    mock_time.side_effect = time_values
    
    mock_request.return_value = mock_baseline
    
    scanner = SQLiScanner("http://example.com/index.php?id=1")
    res = scanner.scan()
    
    assert "findings" in res
    assert len(res["findings"]) == 1
    finding = res["findings"][0]
    assert finding["title"] == "Time-Based Blind SQL Injection Vulnerability"
    assert finding["severity"] == "CRITICAL"
    assert "sleep(5)" in finding["evidence"]
    assert "MySQL" in finding["description"]
