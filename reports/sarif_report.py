from __future__ import annotations
import json, re
from pathlib import Path
from typing import List

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"

_SEVERITY_TO_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}
_SEVERITY_TO_SECURITY_SEVERITY = {"CRITICAL": "9.0", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "0.0"}


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", text or "unknown")
    return slug.strip("-")[:64]


def generate_sarif_report(findings: list, output_path: str) -> None:
    """Write a SARIF 2.1.0 JSON file from a list of ScopeX Finding objects."""
    rules: List[dict] = []
    rule_index: dict = {}

    for f in findings:
        rule_id = _slugify(getattr(f, "title", "unknown"))
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            sev = (getattr(f, "severity", "INFO") or "INFO").upper()
            cve = getattr(f, "cve", None)
            rules.append({
                "id": rule_id,
                "name": getattr(f, "title", "Unknown Finding"),
                "shortDescription": {"text": getattr(f, "title", "Unknown Finding")},
                "fullDescription": {"text": getattr(f, "description", "") or getattr(f, "title", "")},
                "helpUri": ("https://www.cve.org/CVERecord?id=" + cve) if cve else "https://owasp.org/www-project-top-ten/",
                "properties": {
                    "security-severity": _SEVERITY_TO_SECURITY_SEVERITY.get(sev, "0.0"),
                    "tags": ["security"],
                },
                "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL.get(sev, "none")},
            })

    results: List[dict] = []
    for f in findings:
        rule_id = _slugify(getattr(f, "title", "unknown"))
        sev = (getattr(f, "severity", "INFO") or "INFO").upper()
        target_uri = getattr(f, "target", "") or ""
        msg = getattr(f, "description", "") or getattr(f, "title", "")
        evidence = getattr(f, "evidence", "")
        remediation = getattr(f, "remediation", "")
        if evidence:
            msg += "\n\nEvidence: " + evidence
        if remediation:
            msg += "\n\nRemediation: " + remediation
        result_obj = {
            "ruleId": rule_id,
            "ruleIndex": rule_index.get(rule_id, 0),
            "level": _SEVERITY_TO_LEVEL.get(sev, "none"),
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": target_uri, "uriBaseId": "%SRCROOT%"}}}],
        }
        cve = getattr(f, "cve", None)
        if cve:
            result_obj["relatedLocations"] = [{"message": {"text": "CVE: " + cve},
                "physicalLocation": {"artifactLocation": {"uri": "https://www.cve.org/CVERecord?id=" + cve}}}]
        cvss = getattr(f, "cvss", None)
        if cvss is not None:
            result_obj.setdefault("properties", {})["cvss"] = float(cvss)
        results.append(result_obj)

    doc = {
        "version": SARIF_VERSION,
        "runs": [{"tool": {"driver": {"name": "ScopeX", "version": "2.0.0",
            "informationUri": "https://github.com/ganeshkumar-2005/scopex", "rules": rules}},
            "results": results}],
    }
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
