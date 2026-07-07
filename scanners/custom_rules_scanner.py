"""
scanners/custom_rules_scanner.py — Custom YAML/JSON Rules Scanner for ScopeX v2.

Allows users to define custom HTTP signature checks in YAML or JSON format under the rules/ directory.
Supported matchers:
  - path: Relative path to request
  - status: Expected HTTP status code(s)
  - headers: Headers pattern matching (regex dict)
  - body: Response body pattern matching (regex list)
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set

import httpx
from loguru import logger

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner

# PyYAML fallback parser
try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


def _load_yaml_simple(content: str) -> Dict[str, Any]:
    """Fallback parser for basic YAML key-value/lists if PyYAML is missing."""
    data: Dict[str, Any] = {}
    current_key = None
    sub_key = None
    
    for line in content.splitlines():
        line_strip = line.strip()
        if not line_strip or line_strip.startswith("#"):
            continue
            
        indent = len(line) - len(line.lstrip())
        
        # Simple lists
        if line_strip.startswith("-"):
            val = line_strip[1:].strip().strip("'\"")
            val = val.replace("\\\\", "\\")
            if current_key and sub_key:
                sub_dict = data[current_key]
                if not isinstance(sub_dict.get(sub_key), list):
                    sub_dict[sub_key] = []
                sub_dict[sub_key].append(val)
            elif current_key:
                if not isinstance(data.get(current_key), list):
                    data[current_key] = []
                data[current_key].append(val)
            continue
            
        # Simple key-value
        if ":" in line_strip:
            parts = line_strip.split(":", 1)
            k = parts[0].strip()
            v = parts[1].strip().strip("'\"")
            v = v.replace("\\\\", "\\")
            
            if indent == 0:
                current_key = k
                sub_key = None
                if v == "":
                    data[current_key] = {}
                else:
                    data[current_key] = v
            elif indent == 2 and current_key:
                sub_key = k
                if v == "":
                    data[current_key][sub_key] = {}
                else:
                    data[current_key][sub_key] = v
            elif indent == 4 and current_key and sub_key:
                sub_dict = data[current_key][sub_key]
                if isinstance(sub_dict, dict):
                    sub_dict[k] = v
                    
    return data


class CustomRulesScanner(BaseScanner):
    """
    Scans targets using external YAML/JSON signature matching templates.
    """

    def __init__(self, ctx: ScanContext, client: httpx.AsyncClient) -> None:
        super().__init__(ctx, client)
        self.rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")

    async def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(self.rules_dir):
            self.log.debug(f"Rules directory {self.rules_dir} not found; skipping custom rules")
            return []

        rules = self._load_rules()
        self.log.info(f"CustomRules: Loaded {len(rules)} signature rules from {self.rules_dir}")

        for rule in rules:
            rule_findings = await self._run_rule(rule)
            findings.extend(rule_findings)

        return findings

    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load and parse all rules from the rules directory."""
        rules = []
        for filename in os.listdir(self.rules_dir):
            path = os.path.join(self.rules_dir, filename)
            if not os.path.isfile(path):
                continue
            
            ext = os.path.splitext(filename)[1].lower()
            if ext not in (".yaml", ".yml", ".json"):
                continue

            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()

                if ext == ".json":
                    import json
                    rule = json.loads(content)
                else:
                    if _YAML_AVAILABLE:
                        rule = yaml.safe_load(content)
                    else:
                        rule = _load_yaml_simple(content)

                if self._validate_rule(rule):
                    rules.append(rule)
                else:
                    self.log.warning(f"Invalid rule format in {filename}")
            except Exception as exc:
                self.log.error(f"Failed to load rule {filename}: {exc}")

        return rules

    def _validate_rule(self, rule: Any) -> bool:
        """Verify the rule template contains all required keys."""
        if not isinstance(rule, dict):
            return False
        required = {"id", "title", "severity", "match"}
        if not required.issubset(rule.keys()):
            return False
        
        match = rule["match"]
        if not isinstance(match, dict):
            return False
        
        # Must have at least one matcher criteria
        matchers = {"status", "headers", "body"}
        if not matchers.intersection(match.keys()):
            return False
        
        return True

    async def _run_rule(self, rule: Dict[str, Any]) -> List[Finding]:
        findings = []
        rule_id = rule["id"]
        title = rule["title"]
        severity = rule["severity"].upper()
        description = rule.get("description", "Vulnerability detected via custom signature.")
        remediation = rule.get("remediation", "Update components or restrict public access.")
        
        match_criteria = rule["match"]
        paths: List[str] = match_criteria.get("paths", ["/"])
        if isinstance(paths, str):
            paths = [paths]

        for rel_path in paths:
            # Construct target path URL
            target_url = self.ctx.target.rstrip("/") + "/" + rel_path.lstrip("/")
            resp = await self.get(target_url)
            if resp is None:
                continue

            # 1. Match HTTP Status Code(s)
            status_match = True
            if "status" in match_criteria:
                allowed_status = match_criteria["status"]
                if isinstance(allowed_status, int):
                    status_list = [allowed_status]
                elif isinstance(allowed_status, str):
                    status_list = [int(allowed_status)]
                elif isinstance(allowed_status, list):
                    status_list = [int(s) for s in allowed_status]
                else:
                    status_list = []
                
                if status_list and resp.status_code not in status_list:
                    status_match = False

            if not status_match:
                continue

            # 2. Match Headers
            headers_match = True
            if "headers" in match_criteria:
                for header_name, pattern in match_criteria["headers"].items():
                    header_val = resp.headers.get(header_name.lower(), "")
                    if not re.search(str(pattern), header_val, re.IGNORECASE):
                        headers_match = False
                        break

            if not headers_match:
                continue

            # 3. Match Response Body Pattern(s)
            body_match = True
            if "body" in match_criteria:
                patterns = match_criteria["body"]
                if isinstance(patterns, str):
                    patterns = [patterns]
                for pattern in patterns:
                    if not re.search(str(pattern), resp.text, re.IGNORECASE):
                        body_match = False
                        break

            if not body_match:
                continue

            # If all match criteria passed, register a Finding!
            findings.append(self.finding(
                title=title,
                severity=severity,
                description=description,
                evidence={
                    "rule_id": rule_id,
                    "target_url": target_url,
                    "status_code": resp.status_code,
                    "headers_matched": list(match_criteria.get("headers", {}).keys()),
                    "matched_patterns": match_criteria.get("body", []),
                },
                remediation=remediation,
                target=target_url,
                tags=["custom-rule", rule_id],
            ))

        return findings
