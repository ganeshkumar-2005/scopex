import json
from fpdf import FPDF
from utils.helpers import get_readable_timestamp

class ScopeXReport(FPDF):
    def header(self):
        # Banner Header
        self.set_fill_color(30, 41, 59) # Slate Dark Blue
        self.rect(0, 0, 210, 30, 'F')
        
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 18)
        self.cell(10)
        self.cell(0, 10, "SCOPEX SECURITY AUDIT REPORT", 0, 1, "L")
        
        self.set_font("Helvetica", "I", 10)
        self.cell(10)
        
        scan_mode = None
        if hasattr(self, "scan_results") and self.scan_results:
            scan_mode = self.scan_results.get("scan_mode")
            if not scan_mode and any(f.get("module") == "Nuclei Integration" for f in self.scan_results.get("findings", [])):
                scan_mode = "ScopeX + Nuclei"
                
        suffix = f" | {scan_mode}" if scan_mode else " | Full-Spectrum Vulnerability Scan"
        self.cell(0, 10, f"Developed by Ganesh Kumar{suffix}", 0, 0, "L")
        self.ln(20)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | Confidential - Audit Target Security Report", 0, 0, "C")

def generate_pdf_report(scan_results: dict, output_filepath: str):
    """Generates a professional PDF audit report using fpdf2."""
    pdf = ScopeXReport()
    pdf.scan_results = scan_results
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)
    
    # Executive Summary Card
    pdf.set_text_color(30, 41, 59)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Executive Summary", 0, 1, "L")
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    
    target = scan_results.get("target", "Unknown")
    timestamp = scan_results.get("timestamp", get_readable_timestamp())
    findings = scan_results.get("findings", [])
    
    # Calculate Severity Metrics
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
            
    # Risk Score calculation
    # Critical: 10 pts, High: 7 pts, Medium: 4 pts, Low: 1 pt
    total_score = (severity_counts["CRITICAL"] * 10 + 
                   severity_counts["HIGH"] * 7 + 
                   severity_counts["MEDIUM"] * 4 + 
                   severity_counts["LOW"] * 1)
    risk_level = "LOW"
    risk_color = (34, 197, 94) # Green
    
    if total_score > 30:
        risk_level = "CRITICAL"
        risk_color = (239, 68, 68) # Red
    elif total_score > 15:
        risk_level = "HIGH"
        risk_color = (249, 115, 22) # Orange
    elif total_score > 5:
        risk_level = "MEDIUM"
        risk_color = (234, 179, 8) # Yellow

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(50, 8, f"Target Host: {target}", 0, 1)
    pdf.cell(50, 8, f"Scan Timestamp: {timestamp}", 0, 1)
    pdf.cell(50, 8, f"Total Findings Detected: {len(findings)}", 0, 1)
    pdf.ln(3)
    
    # Print Risk Level Panel
    pdf.set_fill_color(*risk_color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, f"OVERALL RISK RATING: {risk_level} (Score: {total_score})", 0, 1, "C", True)
    pdf.ln(5)
    
    # Severity breakdown Table
    pdf.set_text_color(30, 41, 59)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(38, 8, "CRITICAL", 1, 0, "C")
    pdf.cell(38, 8, "HIGH", 1, 0, "C")
    pdf.cell(38, 8, "MEDIUM", 1, 0, "C")
    pdf.cell(38, 8, "LOW", 1, 0, "C")
    pdf.cell(38, 8, "INFO", 1, 1, "C")
    
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(38, 8, str(severity_counts["CRITICAL"]), 1, 0, "C")
    pdf.cell(38, 8, str(severity_counts["HIGH"]), 1, 0, "C")
    pdf.cell(38, 8, str(severity_counts["MEDIUM"]), 1, 0, "C")
    pdf.cell(38, 8, str(severity_counts["LOW"]), 1, 0, "C")
    pdf.cell(38, 8, str(severity_counts["INFO"]), 1, 1, "C")
    pdf.ln(10)
    
    # Detailed Findings Section
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Detailed Vulnerability Assessment", 0, 1, "L")
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    
    if not findings:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 10, "No vulnerabilities or security warnings were detected on the target system.", 0, 1)
    else:
        # --- Sort findings by severity: CRITICAL > HIGH > MEDIUM > LOW > INFO ---
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "INFO").upper(), 5)
        )

        # Severity section colors: (fill_r, fill_g, fill_b, text_r, text_g, text_b)
        severity_styles = {
            "CRITICAL": ((180, 30, 30), (255, 255, 255)),
            "HIGH":     ((220, 90, 20), (255, 255, 255)),
            "MEDIUM":   ((200, 160, 20), (30, 41, 59)),
            "LOW":      ((50, 140, 200), (255, 255, 255)),
            "INFO":     ((100, 116, 139), (255, 255, 255)),
        }

        # Helper to draw indented fields (defined once, reused for every finding)
        def draw_field(label, text, font_name="Helvetica", font_style="", font_size=10, color=(30, 41, 59)):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(100, 116, 139)  # Muted slate label
            pdf.cell(40, 6, f"  {label}", border=0)

            # Temporarily indent left margin
            old_margin = pdf.l_margin
            pdf.set_left_margin(50)

            pdf.set_font(font_name, font_style, font_size)
            pdf.set_text_color(*color)
            pdf.multi_cell(0, 6, str(text), new_x="LMARGIN", new_y="NEXT")

            # Restore original margin
            pdf.set_left_margin(old_margin)
            pdf.x = old_margin

        current_severity = None
        finding_num = 0

        for f in sorted_findings:
            severity = f.get("severity", "INFO").upper()

            # --- Print severity group header when the group changes ---
            if severity != current_severity:
                current_severity = severity
                count = severity_counts.get(severity, 0)
                fill_c, text_c = severity_styles.get(severity, ((100, 100, 100), (255, 255, 255)))

                pdf.ln(6)
                pdf.set_fill_color(*fill_c)
                pdf.set_text_color(*text_c)
                pdf.set_font("Helvetica", "B", 11)
                pdf.cell(0, 9, f"  {severity}  ({count} finding{'s' if count != 1 else ''})", 0, 1, "L", True)
                pdf.ln(3)

            finding_num += 1
            title = f.get("title", "Security Warning")

            # Print finding title
            pdf.set_text_color(30, 41, 59)
            pdf.set_font("Helvetica", "B", 11)
            ver_method = f.get("verification_method", "unverified")
            ver_suffix = f" ({ver_method})" if ver_method != "unverified" else ""
            pdf.cell(0, 8, f"{finding_num}. [{severity}{ver_suffix}] {title}", new_x="LMARGIN", new_y="NEXT")

            # Module
            draw_field("Audit Module:", f.get("module", "General"))

            # CVE / CVSS Info
            cves = f.get("cve_ids", [])
            cvss = f.get("cvss_score", 0.0)
            if cvss is None:
                cvss = 0.0
            if cves or cvss > 0.0:
                info_text = f"CVSS Score: {cvss}"
                if cves:
                    info_text += f" | CVEs: {', '.join(cves)}"
                draw_field("Vulnerability Info:", info_text, font_style="B")

            # Description
            desc = f.get("description", "No description provided.")
            draw_field("Description:", desc)

            # Evidence
            evidence = f.get("evidence", "No technical proof required.")
            if isinstance(evidence, dict):
                evidence = json.dumps(evidence, indent=2)
            elif not isinstance(evidence, str):
                evidence = str(evidence) if evidence is not None else ""

            if not evidence or evidence.strip() == "":
                evidence = "No technical proof required."
            draw_field("Evidence / Proof:", evidence, font_name="Courier", font_size=9, color=(100, 116, 139))

            # Remediation
            remedy = f.get("remediation", "Apply security patches or update service settings.")
            if not remedy or remedy.strip() == "":
                remedy = "Apply security patches or update service settings."
            draw_field("Remediation Guide:", remedy, color=(22, 163, 74))  # Muted green for solution

            pdf.ln(4)
            
    pdf.output(output_filepath)
