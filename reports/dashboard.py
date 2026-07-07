"""
reports/dashboard.py — Premium HTML Report Dashboard Visualizer for ScopeX.
Hosts a local web server serving an interactive dashboard that parses JSON scan reports.
"""
from __future__ import annotations

import os
import json
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote
from loguru import logger

# Premium Dashboard HTML/CSS/JS template
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScopeX Security Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Space+Grotesk:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0f111a;
            --bg-card: rgba(30, 41, 59, 0.4);
            --primary: #00f0ff;
            --primary-glow: rgba(0, 240, 255, 0.15);
            --critical: #ff2e5c;
            --high: #ff8533;
            --medium: #ffcc00;
            --low: #33cc33;
            --info: #00ccff;
            --text-main: #f1f5f9;
            --text-dim: #94a3b8;
            --border: rgba(255, 255, 255, 0.08);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            min-height: 100vh;
            padding: 2rem;
            background-image: 
                radial-gradient(at 10% 10%, rgba(0, 240, 255, 0.05) 0px, transparent 50%),
                radial-gradient(at 90% 90%, rgba(255, 46, 92, 0.05) 0px, transparent 50%);
            background-attachment: fixed;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
        }

        .logo-section h1 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2.2rem;
            font-weight: 800;
            background: linear-gradient(135deg, #00f0ff 0%, #ff2e5c 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -1px;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .logo-section p {
            color: var(--text-dim);
            font-size: 0.95rem;
            margin-top: 0.2rem;
        }

        .dashboard-container {
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 2rem;
        }

        /* Glassmorphism Card Style */
        .glass-card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }

        .sidebar h2 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.2rem;
            margin-bottom: 1rem;
            color: var(--primary);
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .report-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
            max-height: 70vh;
            overflow-y: auto;
            padding-right: 0.5rem;
        }

        .report-list::-webkit-scrollbar {
            width: 4px;
        }
        .report-list::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 4px;
        }

        .report-item {
            padding: 1rem;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid transparent;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .report-item:hover {
            background: rgba(255, 255, 255, 0.05);
            border-color: rgba(0, 240, 255, 0.2);
            transform: translateY(-2px);
        }

        .report-item.active {
            background: var(--primary-glow);
            border-color: var(--primary);
            box-shadow: 0 0 15px rgba(0, 240, 255, 0.1);
        }

        .report-name {
            font-weight: 600;
            font-size: 0.95rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .report-meta {
            font-size: 0.8rem;
            color: var(--text-dim);
            margin-top: 0.4rem;
            display: flex;
            justify-content: space-between;
        }

        /* Main View */
        .main-view {
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        .welcome-screen {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 60vh;
            text-align: center;
        }

        .welcome-screen h2 {
            font-size: 2rem;
            color: var(--text-dim);
            margin-bottom: 1rem;
        }

        .welcome-screen p {
            color: var(--text-dim);
            max-width: 500px;
        }

        /* Scan Summary Row */
        .summary-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }

        .scan-title h2 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.8rem;
            margin-bottom: 0.3rem;
        }

        .scan-title p {
            color: var(--text-dim);
            font-size: 0.95rem;
        }

        .download-btn {
            background: linear-gradient(135deg, #00f0ff 0%, #0088ff 100%);
            color: #050510;
            padding: 0.8rem 1.5rem;
            border-radius: 8px;
            font-weight: bold;
            border: none;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .download-btn:hover {
            box-shadow: 0 0 20px rgba(0, 240, 255, 0.4);
            transform: translateY(-1px);
        }

        /* Severity Cards Grid */
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
        }

        .sev-card {
            text-align: center;
            padding: 1.2rem;
            border-radius: 12px;
            border: 1px solid var(--border);
            position: relative;
            overflow: hidden;
        }

        .sev-card::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
        }

        .sev-card.critical::after { background: var(--critical); }
        .sev-card.high::after { background: var(--high); }
        .sev-card.medium::after { background: var(--medium); }
        .sev-card.low::after { background: var(--low); }
        .sev-card.info::after { background: var(--info); }

        .sev-value {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.2rem;
        }

        .sev-label {
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-dim);
        }

        /* Findings List */
        .findings-section h3 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.4rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        .findings-table th {
            padding: 1rem;
            border-bottom: 2px solid var(--border);
            color: var(--text-dim);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .findings-table td {
            padding: 1.2rem 1rem;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }

        .findings-row {
            transition: background 0.3s ease;
        }

        .findings-row:hover {
            background: rgba(255, 255, 255, 0.02);
        }

        .badge {
            display: inline-block;
            padding: 0.3rem 0.6rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }

        .badge.critical { background: rgba(255, 46, 92, 0.15); color: var(--critical); border: 1px solid rgba(255, 46, 92, 0.3); }
        .badge.high { background: rgba(255, 133, 51, 0.15); color: var(--high); border: 1px solid rgba(255, 133, 51, 0.3); }
        .badge.medium { background: rgba(255, 204, 0, 0.15); color: var(--medium); border: 1px solid rgba(255, 204, 0, 0.3); }
        .badge.low { background: rgba(51, 204, 51, 0.15); color: var(--low); border: 1px solid rgba(51, 204, 51, 0.3); }
        .badge.info { background: rgba(0, 204, 255, 0.15); color: var(--info); border: 1px solid rgba(0, 204, 255, 0.3); }

        .finding-title {
            font-weight: 600;
            font-size: 1rem;
            margin-bottom: 0.3rem;
        }

        .finding-desc {
            font-size: 0.85rem;
            color: var(--text-dim);
            line-height: 1.4;
            max-width: 500px;
        }

        .finding-target {
            font-family: monospace;
            font-size: 0.85rem;
            color: var(--primary);
            word-break: break-all;
        }

        .remediation-block {
            font-size: 0.85rem;
            background: rgba(255, 255, 255, 0.01);
            padding: 0.8rem;
            border-radius: 8px;
            border-left: 3px solid var(--border);
            max-width: 400px;
        }

        /* Detail Modal / Nested details */
        .evidence-btn {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-dim);
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .evidence-btn:hover {
            color: var(--primary);
            border-color: var(--primary);
        }

        .evidence-pre {
            display: none;
            background: #08090f;
            color: #5af78e;
            padding: 1rem;
            border-radius: 8px;
            font-family: monospace;
            font-size: 0.8rem;
            overflow-x: auto;
            margin-top: 0.8rem;
            border: 1px solid rgba(255, 255, 255, 0.05);
            max-width: 500px;
        }

        .visible {
            display: block !important;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-section">
            <h1>ScopeX</h1>
            <p>Interactive Local Audit Dashboard & Visualizer</p>
        </div>
        <div>
            <span style="color: var(--text-dim); font-size: 0.9rem;">Status: <b style="color: var(--low)">Online</b></span>
        </div>
    </header>

    <div class="dashboard-container">
        <!-- Sidebar reports list -->
        <div class="sidebar glass-card">
            <h2>Scan History</h2>
            <ul class="report-list" id="report-list">
                <!-- Loaded dynamically -->
            </ul>
        </div>

        <!-- Main Report View -->
        <div class="main-view">
            <div id="welcome-screen" class="welcome-screen glass-card">
                <h2>Welcome to ScopeX Visualizer</h2>
                <p>Select a scan report file from the sidebar history list to view interactive analysis, metrics, and remediations.</p>
            </div>

            <div id="scan-dashboard" class="main-view" style="display: none;">
                <!-- Summary Header -->
                <div class="summary-header glass-card">
                    <div class="scan-title">
                        <h2 id="target-title">target.com</h2>
                        <p>Scan Profile: <span id="scan-profile" style="color: var(--primary); font-weight: bold;">standard</span> | Date: <span id="scan-date">2026-07-07</span></p>
                    </div>
                    <a href="#" id="download-link" target="_blank" class="download-btn">
                        PDF Report
                    </a>
                </div>

                <!-- Severity Grid -->
                <div class="severity-grid">
                    <div class="sev-card critical">
                        <div class="sev-value" id="count-critical" style="color: var(--critical)">0</div>
                        <div class="sev-label">Critical</div>
                    </div>
                    <div class="sev-card high">
                        <div class="sev-value" id="count-high" style="color: var(--high)">0</div>
                        <div class="sev-label">High</div>
                    </div>
                    <div class="sev-card medium">
                        <div class="sev-value" id="count-medium" style="color: var(--medium)">0</div>
                        <div class="sev-label">Medium</div>
                    </div>
                    <div class="sev-card low">
                        <div class="sev-value" id="count-low" style="color: var(--low)">0</div>
                        <div class="sev-label">Low</div>
                    </div>
                    <div class="sev-card info">
                        <div class="sev-value" id="count-info" style="color: var(--info)">0</div>
                        <div class="sev-label">Info</div>
                    </div>
                </div>

                <!-- Findings Table -->
                <div class="findings-section glass-card">
                    <h3>Vulnerability Findings</h3>
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th style="width: 15%;">Severity</th>
                                <th style="width: 45%;">Finding Details</th>
                                <th style="width: 25%;">Remediation</th>
                                <th style="width: 15%;">Evidence</th>
                            </tr>
                        </thead>
                        <tbody id="findings-body">
                            <!-- Loaded dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Load report list on window load
        window.addEventListener('DOMContentLoaded', async () => {
            await loadReportsList();
        });

        async function loadReportsList() {
            try {
                const response = await fetch('/api/reports');
                const reports = await response.json();
                const listEl = document.getElementById('report-list');
                listEl.innerHTML = '';

                if (reports.length === 0) {
                    listEl.innerHTML = '<li style="color: var(--text-dim); text-align: center; padding: 2rem 0;">No reports found in output/</li>';
                    return;
                }

                // Filter only JSON reports for viewing
                const jsonReports = reports.filter(r => r.name.endsWith('.json'));

                jsonReports.forEach(report => {
                    const li = document.createElement('li');
                    li.className = 'report-item';
                    
                    const name = report.name;
                    const date = report.date || 'Unknown';
                    const sizeKB = (report.size / 1024).toFixed(1) + ' KB';

                    li.innerHTML = `
                        <div class="report-name" title="${name}">${name}</div>
                        <div class="report-meta">
                            <span>${date}</span>
                            <span>${sizeKB}</span>
                        </div>
                    `;
                    li.addEventListener('click', () => loadReport(name, li));
                    listEl.appendChild(li);
                });
            } catch (err) {
                console.error('Error loading report list:', err);
            }
        }

        async function loadReport(filename, itemElement) {
            // Highlight active list item
            document.querySelectorAll('.report-item').forEach(el => el.classList.remove('active'));
            itemElement.classList.add('active');

            try {
                const response = await fetch(`/api/report/${filename}`);
                const data = await response.json();

                // Show dashboard elements
                document.getElementById('welcome-screen').style.display = 'none';
                document.getElementById('scan-dashboard').style.display = 'flex';

                // Fill header info
                document.getElementById('target-title').innerText = data.target || 'Target Scan';
                document.getElementById('scan-profile').innerText = data.profile || 'standard';
                document.getElementById('scan-date').innerText = data.started_at ? data.started_at.split('T')[0] : 'Unknown';

                // Map download PDF link
                const pdfName = filename.replace('.json', '_report.pdf');
                const downloadLink = document.getElementById('download-link');
                downloadLink.href = `/api/download/${pdfName}`;
                downloadLink.style.display = 'inline-flex';

                // Calculate severities
                const findings = [...(data.findings || []), ...(data.nuclei_findings || [])];
                const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
                
                findings.forEach(f => {
                    const sev = (f.severity || 'INFO').toUpperCase();
                    if (counts[sev] !== undefined) {
                        counts[sev]++;
                    } else {
                        counts['INFO']++;
                    }
                });

                document.getElementById('count-critical').innerText = counts.CRITICAL;
                document.getElementById('count-high').innerText = counts.HIGH;
                document.getElementById('count-medium').innerText = counts.MEDIUM;
                document.getElementById('count-low').innerText = counts.LOW;
                document.getElementById('count-info').innerText = counts.INFO;

                // Render findings list
                const tbody = document.getElementById('findings-body');
                tbody.innerHTML = '';

                if (findings.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-dim); padding: 2rem;">No security vulnerabilities discovered during this scan.</td></tr>';
                    return;
                }

                // Sort findings by severity
                const sevOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
                findings.sort((a, b) => {
                    const sevA = sevOrder[(a.severity || 'INFO').toUpperCase()] || 0;
                    const sevB = sevOrder[(b.severity || 'INFO').toUpperCase()] || 0;
                    return sevB - sevA;
                });

                findings.forEach((f, idx) => {
                    const tr = document.createElement('tr');
                    tr.className = 'findings-row';

                    const sev = (f.severity || 'INFO').toUpperCase();
                    const badgeClass = sev.toLowerCase();
                    const title = f.title || 'Vulnerability Check';
                    const desc = f.description || '';
                    const target = f.target || '';
                    const rem = f.remediation || 'N/A';
                    
                    // Evidence block formatting
                    let evidenceHtml = '';
                    if (f.evidence) {
                        const evStr = typeof f.evidence === 'object' ? JSON.stringify(f.evidence, null, 2) : String(f.evidence);
                        evidenceHtml = `
                            <button class="evidence-btn" onclick="toggleEvidence(${idx})">View Raw</button>
                            <pre class="evidence-pre" id="evidence-pre-${idx}">${escapeHtml(evStr)}</pre>
                        `;
                    } else {
                        evidenceHtml = '<span style="color: var(--text-dim)">N/A</span>';
                    }

                    tr.innerHTML = `
                        <td><span class="badge ${badgeClass}">${sev}</span></td>
                        <td>
                            <div class="finding-title">${title}</div>
                            <div class="finding-target">${target}</div>
                            <div class="finding-desc">${desc}</div>
                        </td>
                        <td>
                            <div class="remediation-block">${rem}</div>
                        </td>
                        <td>
                            ${evidenceHtml}
                        </td>
                    `;
                    tbody.appendChild(tr);
                });

            } catch (err) {
                console.error('Error loading report file:', err);
            }
        }

        function toggleEvidence(idx) {
            const el = document.getElementById(`evidence-pre-${idx}`);
            if (el) {
                el.classList.toggle('visible');
            }
        }

        function escapeHtml(text) {
            return text
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
    </script>
</body>
</html>
"""


class DashboardHTTPRequestHandler(BaseHTTPRequestHandler):
    """Simple API & static file serving router for output scans."""

    def log_message(self, format: str, *args: Any) -> None:
        # Redirect standard http request logs to loguru
        logger.bind(scanner="Dashboard").debug(format % args)

    def do_GET(self) -> None:
        try:
            # Route API endpoints
            if self.path == "/" or self.path == "/index.html":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(DASHBOARD_HTML.encode("utf-8"))
                return

            elif self.path == "/api/reports":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                reports = self._get_reports_list()
                self.wfile.write(json.dumps(reports).encode("utf-8"))
                return

            elif self.path.startswith("/api/report/"):
                filename = unquote(self.path[12:])
                filepath = os.path.join("output", filename)
                if os.path.exists(filepath) and filepath.endswith(".json"):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    with open(filepath, "r", encoding="utf-8") as f:
                        self.wfile.write(f.read().encode("utf-8"))
                else:
                    self.send_error(404, "Report not found")
                return

            elif self.path.startswith("/api/download/"):
                filename = unquote(self.path[14:])
                filepath = os.path.join("output", filename)
                if os.path.exists(filepath) and filepath.endswith(".pdf"):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/pdf")
                    self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                    self.end_headers()
                    with open(filepath, "rb") as f:
                        self.wfile.write(f.read())
                else:
                    self.send_error(404, "PDF report not found")
                return

            else:
                self.send_error(404, "Not Found")

        except Exception as exc:
            logger.error(f"Error handling request: {exc}")
            self.send_error(500, "Internal Server Error")

    def _get_reports_list(self) -> List[Dict[str, Any]]:
        reports = []
        output_dir = "output"
        if not os.path.exists(output_dir):
            return []

        for filename in os.listdir(output_dir):
            filepath = os.path.join(output_dir, filename)
            if not os.path.isfile(filepath):
                continue
            
            ext = os.path.splitext(filename)[1].lower()
            if ext not in (".json", ".pdf"):
                continue

            stat = os.stat(filepath)
            
            # Extract basic date from stat
            from datetime import datetime
            dt = datetime.fromtimestamp(stat.st_mtime)
            date_str = dt.strftime("%Y-%m-%d %H:%M")

            reports.append({
                "name": filename,
                "size": stat.st_size,
                "date": date_str,
            })
        
        # Sort by mtime descending (newest scans first)
        reports.sort(key=lambda x: x["date"], reverse=True)
        return reports


def start_dashboard(port: int = 8080) -> None:
    """Start local HTTPServer and open browser."""
    server_address = ("", port)
    httpd = HTTPServer(server_address, DashboardHTTPRequestHandler)
    
    logger.info(f"Dashboard: Starting visualizer web server on http://localhost:{port}")
    logger.info("Dashboard: Press Ctrl+C in terminal to stop dashboard service.")
    
    # Auto open in user browser
    try:
        webbrowser.open(f"http://localhost:{port}")
    except Exception as exc:
        logger.warning(f"Could not automatically launch browser: {exc}")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Dashboard: Stopping web server...")
        httpd.server_close()
