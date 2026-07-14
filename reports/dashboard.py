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
from pathlib import Path

# Premium Dashboard HTML/CSS/JS template loader
def load_dashboard_html() -> str:
    template_path = Path(__file__).resolve().parent / "dashboard.html"
    if template_path.exists():
        try:
            return template_path.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Failed to read dashboard template: {e}")
    
    # Fallback minimal HTML
    return """<!DOCTYPE html>
<html>
<head>
    <title>ScopeX - Error</title>
    <style>body { background: #0f111a; color: #ff2e5c; font-family: sans-serif; padding: 3rem; text-align: center; }</style>
</head>
<body>
    <h1>Dashboard HTML Template Missing or Inaccessible</h1>
    <p>Please ensure reports/dashboard.html exists and is readable.</p>
</body>
</html>"""


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
                self.wfile.write(load_dashboard_html().encode("utf-8"))
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
                output_dir = str(Path(__file__).resolve().parent.parent / "output")
                filepath = os.path.join(output_dir, filename)
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
                output_dir = str(Path(__file__).resolve().parent.parent / "output")
                filepath = os.path.join(output_dir, filename)
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
        output_dir = str(Path(__file__).resolve().parent.parent / "output")
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
