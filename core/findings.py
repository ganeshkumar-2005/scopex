"""
core/findings.py — Canonical Finding dataclass for ScopeX v2.
All scanners and plugins must return List[Finding], never raw dicts.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


@dataclass
class Finding:
    """
    Canonical finding produced by every ScopeX scanner/plugin.

    Attributes:
        title:              Short, human-readable title of the vulnerability.
        severity:           One of CRITICAL | HIGH | MEDIUM | LOW | INFO.
        module:             Name of the scanner that produced this finding.
        description:        Detailed description of the vulnerability.
        evidence:           Arbitrary dict containing proof (payload, response
                            snippets, screenshots paths, etc.).
        remediation:        Actionable fix guidance.
        target:             The URL / host / IP that was tested.
        id:                 Auto-generated UUID4 string.
        cve:                Optional CVE identifier, e.g. 'CVE-2021-44228'.
        cvss_score:         Optional CVSS v3 base score (0.0 – 10.0).
        timestamp:          UTC datetime of discovery (auto-set).
        tags:               Arbitrary string labels for grouping/filtering.
        verified:           True when the finding is confirmed exploitable.
        false_positive_risk: Estimated FP risk of this detection method.
    """

    title: str
    severity: Severity
    module: str
    description: str
    evidence: Dict[str, Any]        # payload, response snippet, proof
    remediation: str
    target: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    tags: List[str] = field(default_factory=list)
    verified: bool = False          # True if exploitable, False if just detectable
    false_positive_risk: Literal["LOW", "MEDIUM", "HIGH"] = "LOW"

    # ------------------------------------------------------------------ #
    #  Validation                                                          #
    # ------------------------------------------------------------------ #

    def __post_init__(self) -> None:
        """Validate all fields after dataclass initialisation."""
        # Severity check
        if self.severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            raise ValueError(f"Invalid severity: {self.severity!r}")

        # Evidence must be a plain dict
        if not isinstance(self.evidence, dict):
            raise TypeError(
                f"evidence must be dict, got {type(self.evidence).__name__}"
            )

        # Non-empty string fields
        for field_name in ("title", "module", "description", "remediation", "target"):
            val = getattr(self, field_name)
            if not val or not val.strip():
                raise ValueError(f"{field_name!r} must not be empty")

        # CVSS range
        if self.cvss_score is not None:
            if not (0.0 <= self.cvss_score <= 10.0):
                raise ValueError(
                    f"cvss_score must be 0.0-10.0, got {self.cvss_score}"
                )

        # false_positive_risk allowed values
        if self.false_positive_risk not in ("LOW", "MEDIUM", "HIGH"):
            raise ValueError(
                f"false_positive_risk must be LOW | MEDIUM | HIGH, "
                f"got {self.false_positive_risk!r}"
            )

    # ------------------------------------------------------------------ #
    #  Properties                                                          #
    # ------------------------------------------------------------------ #

    @property
    def rank(self) -> int:
        """Integer severity rank (5 = CRITICAL … 1 = INFO)."""
        return SEVERITY_RANK.get(self.severity, 0)

    # ------------------------------------------------------------------ #
    #  Serialisation                                                       #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "module": self.module,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "target": self.target,
            "cve": self.cve,
            "cvss_score": self.cvss_score,
            "timestamp": self.timestamp.isoformat(),
            "tags": self.tags,
            "verified": self.verified,
            "false_positive_risk": self.false_positive_risk,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """
        Deserialise from a dictionary (e.g. loaded from JSON).

        The ``id`` field is intentionally discarded so a fresh UUID is
        assigned, preventing accidental ID collisions when findings are
        cloned across runs.
        """
        data = dict(data)
        if "timestamp" in data and isinstance(data["timestamp"], str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        data.pop("id", None)       # regenerate UUID
        return cls(**data)

    # ------------------------------------------------------------------ #
    #  Collection helpers (static)                                         #
    # ------------------------------------------------------------------ #

    @staticmethod
    def sort_by_severity(findings: List["Finding"]) -> List["Finding"]:
        """Return a new list sorted from highest to lowest severity."""
        return sorted(findings, key=lambda f: f.rank, reverse=True)

    @staticmethod
    def filter_by_severity(
        findings: List["Finding"], min_severity: Severity
    ) -> List["Finding"]:
        """Return findings with rank >= *min_severity*."""
        min_rank = SEVERITY_RANK[min_severity]
        return [f for f in findings if f.rank >= min_rank]

    @staticmethod
    def group_by_module(
        findings: List["Finding"],
    ) -> Dict[str, List["Finding"]]:
        """Group findings by the scanner module that produced them."""
        groups: Dict[str, List["Finding"]] = {}
        for finding in findings:
            groups.setdefault(finding.module, []).append(finding)
        return groups

    @staticmethod
    def deduplicate(
        findings: List["Finding"], similarity_threshold: float = 90.0
    ) -> List["Finding"]:
        """
        Simple title-based deduplication using rapidfuzz.

        Falls back to exact-match deduplication if rapidfuzz is not
        installed (graceful degradation).

        Args:
            findings:             Input findings, may contain duplicates.
            similarity_threshold: Minimum fuzz ratio (0-100) to consider
                                  two findings duplicates.

        Returns:
            Deduplicated list preserving the first occurrence.
        """
        try:
            from rapidfuzz import fuzz  # type: ignore[import]

            unique: List["Finding"] = []
            for candidate in findings:
                is_dup = False
                for existing in unique:
                    if (
                        existing.module == candidate.module
                        and fuzz.ratio(existing.title, candidate.title)
                        >= similarity_threshold
                    ):
                        is_dup = True
                        break
                if not is_dup:
                    unique.append(candidate)
            return unique

        except ImportError:
            # Fallback: exact title + module deduplication
            seen: set = set()
            unique_exact: List["Finding"] = []
            for f in findings:
                key = (f.module, f.title.strip().lower())
                if key not in seen:
                    seen.add(key)
                    unique_exact.append(f)
            return unique_exact

    # ------------------------------------------------------------------ #
    #  Dunder helpers                                                      #
    # ------------------------------------------------------------------ #

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"Finding(id={self.id!r}, severity={self.severity!r}, "
            f"title={self.title!r}, module={self.module!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)
