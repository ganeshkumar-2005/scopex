"""
utils/deduplication.py — Finding deduplication using rapidfuzz text similarity.

Merges near-duplicate findings produced by ScopeX built-in scanners and the
Nuclei integration.  Falls back to exact-title deduplication when rapidfuzz
is not installed so the module always functions.

Key design decisions:
- rapidfuzz is used for O(n²) similarity comparison with token-sort and
  token-set ratios, which are robust to word-order differences in titles.
- The primary finding in each cluster is the one with the highest severity
  (and verified=True when tied), so the best-quality signal is preserved.
- Nuclei findings are tagged "nuclei" before merging so they can be filtered
  independently in reports.
"""
from __future__ import annotations

import copy
from typing import Dict, List, Optional, Tuple

from loguru import logger

from core.findings import Finding, SEVERITY_RANK

try:
    from rapidfuzz import fuzz as _fuzz
    _RAPIDFUZZ_AVAILABLE = True
except ImportError:
    _RAPIDFUZZ_AVAILABLE = False
    logger.warning(
        "rapidfuzz is not installed — falling back to exact title+module "
        "deduplication.  Install it with: pip install rapidfuzz"
    )


# ---------------------------------------------------------------------------
# Internal similarity scoring
# ---------------------------------------------------------------------------


def _similarity_score(a: Finding, b: Finding) -> float:
    """
    Compute a composite similarity score between two findings.

    Weights:
      - Title similarity (token_sort_ratio)    → 60 %
      - Description similarity (token_set_ratio on first 300 chars) → 20 %
      - Target similarity (ratio)              → 20 %

    The target weight ensures findings against different URLs are never
    collapsed even if they have identical titles (e.g. the same XSS on
    two different endpoints).

    Args:
        a: First finding.
        b: Second finding.

    Returns:
        Float in the range 0.0–100.0.
    """
    if not _RAPIDFUZZ_AVAILABLE:
        # Graceful degradation: only exact-match on title + module
        if a.title.strip().lower() == b.title.strip().lower() and a.module == b.module:
            return 100.0
        return 0.0

    title_sim: float = _fuzz.token_sort_ratio(a.title, b.title)
    desc_sim: float = _fuzz.token_set_ratio(
        a.description[:300], b.description[:300]
    )
    target_sim: float = _fuzz.ratio(a.target, b.target)

    return 0.6 * title_sim + 0.2 * desc_sim + 0.2 * target_sim


# ---------------------------------------------------------------------------
# Finding merger
# ---------------------------------------------------------------------------


def _choose_primary(a: Finding, b: Finding) -> Tuple[Finding, Finding]:
    """
    Choose which of two duplicate findings should be the *primary* (kept) one.

    Selection criteria (in priority order):
    1. Higher severity rank
    2. verified=True preferred over False
    3. Higher CVSS score preferred
    4. Original order preserved as final tiebreaker (``a`` wins)

    Returns:
        Tuple of ``(primary, secondary)`` where primary is the winner.
    """
    a_rank = SEVERITY_RANK.get(a.severity, 0)
    b_rank = SEVERITY_RANK.get(b.severity, 0)

    if b_rank > a_rank:
        return b, a
    if a_rank > b_rank:
        return a, b

    # Equal severity: prefer verified
    if b.verified and not a.verified:
        return b, a
    if a.verified and not b.verified:
        return a, b

    # Equal verification: prefer higher CVSS
    a_cvss = a.cvss_score or 0.0
    b_cvss = b.cvss_score or 0.0
    if b_cvss > a_cvss:
        return b, a

    # Default: original order (a wins)
    return a, b


def _merge_pair(primary: Finding, secondary: Finding) -> Finding:
    """
    Merge *secondary* finding's metadata into *primary*.

    Merging rules:
    - Tags are unioned (no duplicates)
    - CVE is taken from whichever has it (primary wins on conflict)
    - CVSS score: take the maximum
    - Evidence dicts are merged (primary wins on key conflicts)
    - verified=True is "sticky" — once true in either, result is true

    Since Finding is a regular (mutable) dataclass we can directly mutate
    the copy returned here.

    Args:
        primary:   The winning (higher-quality) finding.
        secondary: The finding being absorbed.

    Returns:
        A new :class:`Finding` with merged metadata.
    """
    # Deep-copy so we never mutate the originals (callers may still hold refs)
    merged = copy.deepcopy(primary)

    # Merge tags
    combined_tags = list(dict.fromkeys(merged.tags + secondary.tags))
    merged.tags = combined_tags

    # CVE: primary wins, fall back to secondary
    if not merged.cve and secondary.cve:
        merged.cve = secondary.cve

    # CVSS: take maximum
    if secondary.cvss_score is not None:
        if merged.cvss_score is None or secondary.cvss_score > merged.cvss_score:
            merged.cvss_score = secondary.cvss_score

    # verified: sticky-true
    if secondary.verified:
        merged.verified = True

    # Evidence: merge dicts, primary keys win
    merged_evidence: Dict = dict(secondary.evidence)
    merged_evidence.update(merged.evidence)
    merged.evidence = merged_evidence

    return merged


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def deduplicate_findings(
    findings: List[Finding],
    threshold: float = 85.0,
    prefer_verified: bool = True,
) -> List[Finding]:
    """
    Deduplicate a list of :class:`~core.findings.Finding` objects.

    Uses rapidfuzz text similarity to identify near-duplicate findings and
    collapses them into a single high-quality representative finding.

    Algorithm:
      1. Sort findings so higher-severity / verified findings are processed
         first (they become cluster primaries).
      2. For each un-visited finding, scan remaining un-visited findings for
         duplicates above ``threshold``.
      3. Merge duplicates into the primary using :func:`_merge_pair`.
      4. Return the de-duplicated list sorted by severity descending.

    Args:
        findings:        Input findings (may contain duplicates from multiple
                         scanner modules and/or Nuclei).
        threshold:       Similarity score (0–100) above which two findings
                         are considered duplicates.  85 is a safe default.
        prefer_verified: If ``True``, verified findings are sorted first
                         so they become cluster primaries when severity is
                         equal.  Has no effect when rapidfuzz is absent.

    Returns:
        Deduplicated list of :class:`~core.findings.Finding`, sorted from
        highest to lowest severity.
    """
    if not findings:
        return []

    log = logger.bind(scanner="deduplication")
    original_count = len(findings)

    # Sort so the "best" finding in each cluster comes first
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            SEVERITY_RANK.get(f.severity, 0),
            int(f.verified) if prefer_verified else 0,
            f.cvss_score or 0.0,
        ),
        reverse=True,
    )

    kept: List[Finding] = []
    absorbed: set = set()  # indices of findings already merged into another

    for i, candidate in enumerate(sorted_findings):
        if i in absorbed:
            continue

        current_primary = candidate

        for j in range(i + 1, len(sorted_findings)):
            if j in absorbed:
                continue

            other = sorted_findings[j]
            score = _similarity_score(current_primary, other)

            if score >= threshold:
                absorbed.add(j)
                primary, secondary = _choose_primary(current_primary, other)
                current_primary = _merge_pair(primary, secondary)
                log.debug(
                    f"Dedup merge: {other.title[:60]!r} → {current_primary.title[:60]!r} "
                    f"(score={score:.1f}, severity: {other.severity}→{current_primary.severity})"
                )

        kept.append(current_primary)

    deduped_count = len(kept)
    removed = original_count - deduped_count
    if removed > 0:
        log.info(
            f"Deduplication complete: {original_count} → {deduped_count} findings "
            f"({removed} merged, threshold={threshold})"
        )
    else:
        log.debug(
            f"Deduplication complete: {original_count} findings, no duplicates found"
        )

    return Finding.sort_by_severity(kept)


def merge_nuclei_findings(
    scopex_findings: List[Finding],
    nuclei_findings: List[Finding],
    threshold: float = 80.0,
) -> List[Finding]:
    """
    Merge Nuclei findings into ScopeX findings with deduplication.

    ScopeX built-in findings take priority over Nuclei findings when they
    cover the same vulnerability (lower threshold here since Nuclei titles
    often differ in phrasing from ScopeX titles).

    All Nuclei findings are tagged with ``"nuclei"`` before merging so they
    remain identifiable in reports even after deduplication.

    Args:
        scopex_findings:  Findings produced by ScopeX built-in scanners.
        nuclei_findings:  Findings imported from the Nuclei integration.
        threshold:        Similarity score (0–100) for cross-source
                          deduplication.  80 is recommended (slightly lower
                          than intra-source because naming conventions differ).

    Returns:
        Merged, deduplicated list sorted by severity descending.
    """
    log = logger.bind(scanner="deduplication")

    # Tag Nuclei findings — deep-copy so originals are not mutated
    tagged_nuclei: List[Finding] = []
    for f in nuclei_findings:
        tagged = copy.deepcopy(f)
        if "nuclei" not in tagged.tags:
            tagged.tags = ["nuclei"] + tagged.tags
        tagged_nuclei.append(tagged)

    log.info(
        f"Merging {len(scopex_findings)} ScopeX findings + "
        f"{len(tagged_nuclei)} Nuclei findings (threshold={threshold})"
    )

    combined = scopex_findings + tagged_nuclei
    return deduplicate_findings(combined, threshold=threshold)


def group_by_severity(findings: List[Finding]) -> Dict[str, List[Finding]]:
    """
    Group deduplicated findings by severity level.

    Args:
        findings: Any list of :class:`~core.findings.Finding` objects.

    Returns:
        Dict mapping severity string → list of findings.
        Keys are always present even if the list is empty:
        ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, ``INFO``.
    """
    groups: Dict[str, List[Finding]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFO": [],
    }
    for finding in findings:
        groups.setdefault(finding.severity, []).append(finding)
    return groups


def summary_stats(findings: List[Finding]) -> Dict[str, int]:
    """
    Return a concise severity breakdown dictionary.

    Useful for report headers and progress displays.

    Args:
        findings: List of :class:`~core.findings.Finding` objects.

    Returns:
        Dict with keys ``total``, ``critical``, ``high``, ``medium``,
        ``low``, ``info``.
    """
    groups = group_by_severity(findings)
    return {
        "total": len(findings),
        "critical": len(groups["CRITICAL"]),
        "high": len(groups["HIGH"]),
        "medium": len(groups["MEDIUM"]),
        "low": len(groups["LOW"]),
        "info": len(groups["INFO"]),
    }
