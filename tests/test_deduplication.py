"""
Unit tests for utils/deduplication.py
"""
import pytest
from core.findings import Finding
from utils.deduplication import (
    _similarity_score,
    _choose_primary,
    _merge_pair,
    deduplicate_findings,
    merge_nuclei_findings,
    group_by_severity,
    summary_stats,
)

def test_similarity_score():
    f1 = Finding(
        title="SQL Injection in parameter id",
        severity="HIGH",
        module="SQLiScanner",
        description="SQL injection vulnerability found in query parameter id.",
        evidence={"param": "id"},
        remediation="Use parameterized queries",
        target="http://example.com/page.php?id=1",
    )
    f2 = Finding(
        title="SQL Injection in id parameter",
        severity="HIGH",
        module="SQLiScanner",
        description="SQL injection vulnerability found in query parameter id.",
        evidence={"param": "id"},
        remediation="Use parameterized queries",
        target="http://example.com/page.php?id=1",
    )
    # They should be highly similar
    score = _similarity_score(f1, f2)
    assert score > 85.0

    # Different targets should reduce similarity significantly
    f3 = Finding(
        title="SQL Injection in parameter id",
        severity="HIGH",
        module="SQLiScanner",
        description="SQL injection vulnerability found in query parameter id.",
        evidence={"param": "id"},
        remediation="Use parameterized queries",
        target="http://otherdomain.com/index.php",
    )
    score_diff_target = _similarity_score(f1, f3)
    assert score_diff_target < 95.0

def test_choose_primary():
    f_low = Finding(
        title="SQL Injection",
        severity="LOW",
        module="SQLiScanner",
        description="Desc",
        evidence={},
        remediation="Remedy",
        target="http://example.com",
    )
    f_high = Finding(
        title="SQL Injection",
        severity="HIGH",
        module="SQLiScanner",
        description="Desc",
        evidence={},
        remediation="Remedy",
        target="http://example.com",
    )
    # Higher severity rank wins
    primary, secondary = _choose_primary(f_low, f_high)
    assert primary.severity == "HIGH"
    assert secondary.severity == "LOW"

    # verified=True wins if severity is equal
    f_unverified = Finding(
        title="SQL Injection",
        severity="HIGH",
        module="SQLiScanner",
        description="Desc",
        evidence={},
        remediation="Remedy",
        target="http://example.com",
        verified=False,
    )
    f_verified = Finding(
        title="SQL Injection",
        severity="HIGH",
        module="SQLiScanner",
        description="Desc",
        evidence={},
        remediation="Remedy",
        target="http://example.com",
        verified=True,
    )
    primary, secondary = _choose_primary(f_unverified, f_verified)
    assert primary.verified is True
    assert secondary.verified is False

    # Higher CVSS score wins if severity & verification are equal
    f_cvss_5 = Finding(
        title="SQL Injection",
        severity="HIGH",
        module="SQLiScanner",
        description="Desc",
        evidence={},
        remediation="Remedy",
        target="http://example.com",
        cvss_score=5.0,
    )
    f_cvss_8 = Finding(
        title="SQL Injection",
        severity="HIGH",
        module="SQLiScanner",
        description="Desc",
        evidence={},
        remediation="Remedy",
        target="http://example.com",
        cvss_score=8.0,
    )
    primary, secondary = _choose_primary(f_cvss_5, f_cvss_8)
    assert primary.cvss_score == 8.0
    assert secondary.cvss_score == 5.0

def test_merge_pair():
    f1 = Finding(
        title="SQL Injection",
        severity="HIGH",
        module="SQLiScanner",
        description="Desc",
        evidence={"param": "id"},
        remediation="Remedy",
        target="http://example.com",
        tags=["sqli"],
        cve=None,
        cvss_score=7.0,
    )
    f2 = Finding(
        title="SQL Injection",
        severity="HIGH",
        module="SQLiScanner",
        description="Desc",
        evidence={"payload": "1' OR '1'='1"},
        remediation="Remedy",
        target="http://example.com",
        tags=["web", "owasp"],
        cve="CVE-2023-12345",
        cvss_score=8.5,
        verified=True,
    )
    merged = _merge_pair(f1, f2)
    assert "sqli" in merged.tags
    assert "web" in merged.tags
    assert "owasp" in merged.tags
    assert merged.cve == "CVE-2023-12345"
    assert merged.cvss_score == 8.5
    assert merged.verified is True
    assert merged.evidence == {"param": "id", "payload": "1' OR '1'='1"}

def test_deduplicate_findings():
    f1 = Finding(
        title="SQL Injection in parameter id",
        severity="HIGH",
        module="SQLiScanner",
        description="SQL injection vulnerability found in query parameter id.",
        evidence={"param": "id"},
        remediation="Use parameterized queries",
        target="http://example.com/page.php?id=1",
    )
    f2 = Finding(
        title="SQL Injection in id parameter",
        severity="HIGH",
        module="SQLiScanner",
        description="SQL injection vulnerability found in query parameter id.",
        evidence={"payload": "1'"},
        remediation="Use parameterized queries",
        target="http://example.com/page.php?id=1",
    )
    f3 = Finding(
        title="XSS vulnerability on index page",
        severity="MEDIUM",
        module="XSSScanner",
        description="Cross-site scripting found.",
        evidence={"param": "q"},
        remediation="Encode output",
        target="http://example.com/index.php",
    )
    
    deduped = deduplicate_findings([f1, f2, f3])
    # f1 and f2 should be merged. f3 should remain. Total should be 2.
    assert len(deduped) == 2
    # Verify sorting by severity
    assert deduped[0].severity == "HIGH"
    assert deduped[1].severity == "MEDIUM"

def test_merge_nuclei_findings():
    f_scopex = Finding(
        title="WordPress core vulnerability",
        severity="HIGH",
        module="CMSPlugin",
        description="Vulnerable WP version",
        evidence={"version": "5.0"},
        remediation="Update WP",
        target="http://example.com",
        tags=["cms"],
    )
    f_nuclei = Finding(
        title="WordPress core vulnerability",
        severity="HIGH",
        module="NucleiOrchestrator",
        description="Vulnerable WP version",
        evidence={"template": "wp-vuln"},
        remediation="Update WP",
        target="http://example.com",
        tags=["wp"],
    )

    merged = merge_nuclei_findings([f_scopex], [f_nuclei])
    assert len(merged) == 1
    # Check that "nuclei" tag was added and tags from both are present
    assert "nuclei" in merged[0].tags
    assert "cms" in merged[0].tags
    assert "wp" in merged[0].tags

def test_group_by_severity_and_stats():
    f1 = Finding(
        title="Critical Vulnerability",
        severity="CRITICAL",
        module="SQLiScanner",
        description="Desc",
        evidence={},
        remediation="Remedy",
        target="http://example.com",
    )
    f2 = Finding(
        title="Info Finding",
        severity="INFO",
        module="WhoisScanner",
        description="Desc",
        evidence={},
        remediation="Remedy",
        target="http://example.com",
    )
    
    findings = [f1, f2]
    groups = group_by_severity(findings)
    assert len(groups["CRITICAL"]) == 1
    assert len(groups["HIGH"]) == 0
    assert len(groups["INFO"]) == 1

    stats = summary_stats(findings)
    assert stats["total"] == 2
    assert stats["critical"] == 1
    assert stats["info"] == 1
    assert stats["medium"] == 0
