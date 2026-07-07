from .base_plugin import BasePlugin

class CompliancePlugin(BasePlugin):
    PLUGIN_ID = "10005"
    PLUGIN_NAME = "Compliance & Scoring Engine"
    PLUGIN_FAMILY = "Compliance"
    PLUGIN_VERSION = "1.0"
    PLUGIN_SHORT_KEY = "compliance"
    DESCRIPTION = "OWASP Top 10 mapping, PCI-DSS checks, A-F security grading"

    def __init__(self, target: str, timeout: float = 5.0, existing_findings: list = None):
        super().__init__(target, timeout)
        raw_findings = existing_findings or []
        self.existing_findings = [
            f.to_dict() if hasattr(f, "to_dict") else f
            for f in raw_findings
        ]

    def run(self, progress_callback=None) -> dict:
        """Process findings, map to compliance controls, and grade security posture."""
        self.map_owasp_top_10()
        self.check_pci_dss()
        self.check_cis_benchmarks()
        self.check_soc2()
        self.calculate_security_grade()
        return self.get_results()

    def map_owasp_top_10(self):
        """Maps findings to OWASP Top 10 2021 categories."""
        owasp_map = {
            "A01": {"name": "Broken Access Control", "count": 0, "examples": []},
            "A02": {"name": "Cryptographic Failures", "count": 0, "examples": []},
            "A03": {"name": "Injection", "count": 0, "examples": []},
            "A04": {"name": "Insecure Design", "count": 0, "examples": []},
            "A05": {"name": "Security Misconfiguration", "count": 0, "examples": []},
            "A06": {"name": "Vulnerable and Outdated Components", "count": 0, "examples": []},
            "A07": {"name": "Identification and Authentication Failures", "count": 0, "examples": []},
            "A08": {"name": "Software and Data Integrity Failures", "count": 0, "examples": []},
            "A09": {"name": "Security Logging and Monitoring Failures", "count": 0, "examples": []},
            "A10": {"name": "Server-Side Request Forgery (SSRF)", "count": 0, "examples": []}
        }

        # Analyze current findings and map them
        for f in self.existing_findings:
            title = f.get("title", "").lower()
            module = f.get("module", "").lower()
            severity = f.get("severity", "").upper()

            # Mapping Logic
            if any(term in title for term in ["auth", "admin", "redirect", "takeover", "cors"]):
                category = "A01"
            elif any(term in title for term in ["ssl", "tls", "cipher", "hsts", "crypt"]):
                category = "A02"
            elif any(term in title for term in ["sqli", "xss", "inject", "crlf"]):
                category = "A03"
            elif any(term in title for term in ["rate limit", "csrf"]):
                category = "A04"
            elif any(term in title for term in ["header", "cookie", "expose", "leak", "signing", "default"]):
                category = "A05"
            elif any(term in title for term in ["version", "outdated", "vulnerable"]):
                category = "A06"
            elif any(term in title for term in ["credential", "login", "password"]):
                category = "A07"
            elif any(term in title for term in ["csp", "sri"]):
                category = "A08"
            elif any(term in title for term in ["log", "monitor"]):
                category = "A09"
            elif any(term in title for term in ["ssrf", "local file", "lfi", "rfi"]):
                category = "A10"
            else:
                category = "A05" # Default to Security Misconfiguration

            owasp_map[category]["count"] += 1
            if len(owasp_map[category]["examples"]) < 3:
                owasp_map[category]["examples"].append(f.get("title"))

        # Generate findings for active categories
        for cat_id, info in owasp_map.items():
            if info["count"] > 0:
                examples_str = ", ".join(info["examples"])
                self.add_finding(
                    title=f"OWASP Top 10 Mapping: {cat_id} ({info['name']})",
                    severity="INFO",
                    description=f"Identified {info['count']} finding(s) mapping directly to OWASP 2021 Category {cat_id}: {info['name']}.",
                    evidence=f"Associated vulnerabilities: {examples_str}",
                    remediation=f"Review OWASP guidance for {cat_id} and resolve dependencies.",
                    cvss=0.0
                )

    def check_pci_dss(self):
        """Basic PCI-DSS security compliance verification."""
        pci_failures = []
        
        # Check TLS versions from findings
        has_weak_tls = False
        for f in self.existing_findings:
            title_lower = f.get("title", "").lower()
            if "sslv3" in title_lower or "sslv2" in title_lower or "tls 1.0" in title_lower or "tls 1.1" in title_lower:
                has_weak_tls = True

        if has_weak_tls:
            pci_failures.append("Requirement 2.3/4.1: Strong cryptography required (Weak TLS 1.0/1.1 or SSL v2/v3 enabled)")

        # Check for open databases/exposed services
        for f in self.existing_findings:
            title_lower = f.get("title", "").lower()
            if "database" in title_lower or "default credentials" in title_lower or "no auth" in title_lower:
                pci_failures.append(f"Requirement 1.2.1/2.1: Default settings & exposed services detected ({f.get('title')})")

        # Map compliance outcome
        if pci_failures:
            self.add_finding(
                title="PCI-DSS Compliance Check: FAILED",
                severity="MEDIUM",
                description="The target does not comply with core PCI-DSS cryptographic and access security requirements.",
                evidence="\n".join(pci_failures),
                remediation="Upgrade database rules, disable default credentials, and restrict TLS versions to TLS 1.2 or TLS 1.3.",
                cvss=5.0
            )
        else:
            self.add_finding(
                title="PCI-DSS Compliance Check: PASSED",
                severity="INFO",
                description="No critical PCI-DSS violations were found on standard exposed interfaces checked.",
                evidence="Complied with basic TLS protocols, cipher, and access checks.",
                remediation="Continue routine audits to monitor state changes.",
                cvss=0.0
            )

    def check_cis_benchmarks(self):
        """Maps findings to CIS Controls v8 sub-families (Access Control, Data Protection, Audit/Log, Network Defence)."""
        cis_controls = {
            "CIS-1":  {"name": "Inventory and Control of Enterprise Assets", "failures": []},
            "CIS-3":  {"name": "Data Protection", "failures": []},
            "CIS-4":  {"name": "Secure Configuration of Enterprise Assets and Software", "failures": []},
            "CIS-6":  {"name": "Access Control Management", "failures": []},
            "CIS-8":  {"name": "Audit Log Management", "failures": []},
            "CIS-9":  {"name": "Email and Web Browser Protections", "failures": []},
            "CIS-12": {"name": "Network Infrastructure Management", "failures": []},
            "CIS-13": {"name": "Network Monitoring and Defence", "failures": []},
            "CIS-16": {"name": "Application Software Security", "failures": []},
        }

        for f in self.existing_findings:
            title = f.get("title", "").lower()
            sev = f.get("severity", "INFO").upper()
            if sev in ("INFO",):
                continue  # Only map actionable findings

            if any(t in title for t in ["port", "service", "open", "banner"]):
                cis_controls["CIS-1"]["failures"].append(f.get("title"))
                cis_controls["CIS-12"]["failures"].append(f.get("title"))
            if any(t in title for t in ["ssl", "tls", "cipher", "hsts", "crypt", "cert"]):
                cis_controls["CIS-3"]["failures"].append(f.get("title"))
                cis_controls["CIS-4"]["failures"].append(f.get("title"))
            if any(t in title for t in ["header", "cookie", "csp", "cors", "xframe", "referrer"]):
                cis_controls["CIS-4"]["failures"].append(f.get("title"))
                cis_controls["CIS-16"]["failures"].append(f.get("title"))
            if any(t in title for t in ["auth", "admin", "login", "credential", "password"]):
                cis_controls["CIS-6"]["failures"].append(f.get("title"))
            if any(t in title for t in ["log", "monitor", "trace", "debug"]):
                cis_controls["CIS-8"]["failures"].append(f.get("title"))
            if any(t in title for t in ["xss", "inject", "sqli", "rfi", "lfi", "ssrf", "traversal"]):
                cis_controls["CIS-16"]["failures"].append(f.get("title"))
                cis_controls["CIS-13"]["failures"].append(f.get("title"))

        triggered = {k: v for k, v in cis_controls.items() if v["failures"]}
        if triggered:
            details = "; ".join(
                f"{k} ({v['name']}): {len(set(v['failures']))} issue(s)"
                for k, v in triggered.items()
            )
            self.add_finding(
                title="CIS Controls v8: Gaps Identified",
                severity="MEDIUM",
                description=(
                    f"{len(triggered)} CIS Control families have associated findings. "
                    "Review each control sub-family for remediation guidance."
                ),
                evidence=details,
                remediation=(
                    "Consult the CIS Controls v8 implementation guide at "
                    "https://www.cisecurity.org/controls/v8 and address each flagged control family."
                ),
                cvss=0.0,
            )
        else:
            self.add_finding(
                title="CIS Controls v8: No Gaps Detected",
                severity="INFO",
                description="No actionable findings mapped to CIS Controls v8 sub-families.",
                evidence="All checked CIS control families appear compliant based on current scan findings.",
                remediation="Continue routine audits.",
                cvss=0.0,
            )

    def check_soc2(self):
        """Maps findings to SOC 2 Trust Service Criteria (CC6, CC7, CC8)."""
        soc2_criteria = {
            "CC6": {"name": "Logical and Physical Access Controls", "failures": []},
            "CC7": {"name": "System Operations (Monitoring & Incident Response)", "failures": []},
            "CC8": {"name": "Change Management", "failures": []},
            "CC9": {"name": "Risk Mitigation", "failures": []},
            "A1":  {"name": "Availability", "failures": []},
        }

        for f in self.existing_findings:
            title = f.get("title", "").lower()
            sev = f.get("severity", "INFO").upper()
            if sev in ("INFO",):
                continue

            if any(t in title for t in ["auth", "admin", "login", "credential", "access", "cors", "takeover"]):
                soc2_criteria["CC6"]["failures"].append(f.get("title"))
            if any(t in title for t in ["log", "monitor", "trace", "error disclosure", "debug"]):
                soc2_criteria["CC7"]["failures"].append(f.get("title"))
            if any(t in title for t in ["version", "outdated", "vulnerable component", "cve"]):
                soc2_criteria["CC8"]["failures"].append(f.get("title"))
            if any(t in title for t in ["ssrf", "lfi", "rfi", "inject", "xss", "sqli"]):
                soc2_criteria["CC9"]["failures"].append(f.get("title"))
            if any(t in title for t in ["port", "service", "open", "availability"]):
                soc2_criteria["A1"]["failures"].append(f.get("title"))

        triggered = {k: v for k, v in soc2_criteria.items() if v["failures"]}
        if triggered:
            details = "; ".join(
                f"{k} ({v['name']}): {len(set(v['failures']))} issue(s)"
                for k, v in triggered.items()
            )
            self.add_finding(
                title="SOC 2 Trust Service Criteria: Gaps Identified",
                severity="MEDIUM",
                description=(
                    f"{len(triggered)} SOC 2 Trust Service Criteria have associated findings. "
                    "These gaps may affect SOC 2 Type II audit readiness."
                ),
                evidence=details,
                remediation=(
                    "Engage your auditor to review each criterion and implement the recommended "
                    "controls from the AICPA Trust Services Criteria guide."
                ),
                cvss=0.0,
            )
        else:
            self.add_finding(
                title="SOC 2 Trust Service Criteria: No Gaps Detected",
                severity="INFO",
                description="No actionable findings mapped to SOC 2 Trust Service Criteria.",
                evidence="All checked SOC 2 criteria appear compliant based on current scan findings.",
                remediation="Continue routine audits.",
                cvss=0.0,
            )

    def calculate_security_grade(self):
        """Calculates security grade (A-F) based on severity of findings."""
        criticals = 0
        highs = 0
        mediums = 0
        lows = 0

        for f in self.existing_findings:
            sev = f.get("severity", "").upper()
            if "CRIT" in sev:
                criticals += 1
            elif "HIGH" in sev:
                highs += 1
            elif "MED" in sev or "WARN" in sev:
                mediums += 1
            elif "LOW" in sev:
                lows += 1

        # Grading logic
        if criticals > 1:
            grade = "F"
            notes = f"Failed audit due to {criticals} Critical vulnerabilities."
        elif criticals == 1 or highs >= 4:
            grade = "D"
            notes = "Unsatisfactory posture with High/Critical issues present."
        elif highs >= 2 or mediums >= 6:
            grade = "C"
            notes = "Fair security posture. Moderate vulnerabilities found."
        elif highs == 1 or mediums >= 2:
            grade = "B"
            notes = "Good posture. Only minor issues discovered."
        else:
            grade = "A"
            notes = "Excellent posture. No significant security findings."

        self.add_finding(
            title=f"Security Posture Rating: GRADE {grade}",
            severity="INFO",
            description=f"ScopeX evaluated target security score at Grade {grade}.",
            evidence=f"Findings summary: {criticals} Critical, {highs} High, {mediums} Medium, {lows} Low",
            remediation=notes,
            cvss=0.0
        )
