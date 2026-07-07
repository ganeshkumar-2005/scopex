"""
tests/test_findings.py — Unit tests for the Finding dataclass.
"""
from __future__ import annotations

import pytest
from core.findings import Finding, SEVERITY_RANK


def _make_finding(**kwargs):
    defaults = {
        "title": "Test Finding",
        "severity": "HIGH",
        "module": "TestModule",
        "description": "A test finding.",
        "evidence": {"key": "value"},
        "remediation": "Fix it.",
        "target": "https://example.com",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


class TestFindingCreation:
    def test_basic_creation(self):
        f = _make_finding()
        assert f.title == "Test Finding"
        assert f.severity == "HIGH"
        assert f.module == "TestModule"
        assert f.id  # UUID auto-generated

    def test_severity_validation(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            _make_finding(severity="EXTREME")

    def test_empty_title_rejected(self):
        with pytest.raises(ValueError, match="title"):
            _make_finding(title="")

    def test_empty_description_rejected(self):
        with pytest.raises(ValueError, match="description"):
            _make_finding(description="   ")

    def test_evidence_must_be_dict(self):
        with pytest.raises(TypeError, match="evidence must be dict"):
            _make_finding(evidence="string evidence")

    def test_cvss_validation(self):
        f = _make_finding(cvss_score=9.8)
        assert f.cvss_score == 9.8
        with pytest.raises(ValueError, match="cvss_score"):
            _make_finding(cvss_score=11.0)

    def test_cvss_zero_valid(self):
        f = _make_finding(cvss_score=0.0)
        assert f.cvss_score == 0.0


class TestFindingRank:
    def test_rank_ordering(self):
        crit = _make_finding(severity="CRITICAL")
        high = _make_finding(severity="HIGH")
        info = _make_finding(severity="INFO")
        assert crit.rank > high.rank > info.rank

    def test_all_severities_have_ranks(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            f = _make_finding(severity=sev)
            assert f.rank == SEVERITY_RANK[sev]


class TestFindingSerialization:
    def test_to_dict(self):
        f = _make_finding(tags=["sqli", "error-based"])
        d = f.to_dict()
        assert d["title"] == "Test Finding"
        assert d["severity"] == "HIGH"
        assert d["tags"] == ["sqli", "error-based"]
        assert "timestamp" in d

    def test_from_dict_roundtrip(self):
        f1 = _make_finding(tags=["test"])
        d = f1.to_dict()
        f2 = Finding.from_dict(d)
        assert f2.title == f1.title
        assert f2.severity == f1.severity
        assert f2.tags == f1.tags
        # IDs differ because from_dict regenerates UUID
        assert f2.id != f1.id


class TestFindingSort:
    def test_sort_by_severity(self):
        findings = [
            _make_finding(severity="LOW"),
            _make_finding(severity="CRITICAL"),
            _make_finding(severity="MEDIUM"),
            _make_finding(severity="HIGH"),
            _make_finding(severity="INFO"),
        ]
        sorted_findings = Finding.sort_by_severity(findings)
        severities = [f.severity for f in sorted_findings]
        assert severities == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def test_filter_by_severity(self):
        findings = [
            _make_finding(severity="LOW"),
            _make_finding(severity="CRITICAL"),
            _make_finding(severity="INFO"),
            _make_finding(severity="HIGH"),
        ]
        filtered = Finding.filter_by_severity(findings, "HIGH")
        assert all(f.severity in ("CRITICAL", "HIGH") for f in filtered)
        assert len(filtered) == 2
