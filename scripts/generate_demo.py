import os
import sys
import time
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.align import Align

# Intercept sys.stdout to write asciinema v2 format (.cast)
class CastRecorder:
    def __init__(self, filepath, width=100, height=35):
        self.filepath = filepath
        self.width = width
        self.height = height
        self.start_time = None
        self.file = None
        self.old_stdout_write = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        self.file = open(self.filepath, "w", encoding="utf-8")
        # Write header
        header = {
            "version": 2,
            "width": self.width,
            "height": self.height,
            "timestamp": int(time.time()),
            "env": {"TERM": "xterm-256color"}
        }
        self.file.write(json.dumps(header) + "\n")
        self.start_time = time.time()
        self.old_stdout_write = sys.stdout.write
        sys.stdout.write = self.write
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout.write = self.old_stdout_write
        self.file.close()

    def write(self, data):
        self.old_stdout_write(data)
        elapsed = time.time() - self.start_time
        # Write to cast file, making sure to escape raw output nicely
        event = [elapsed, "o", data]
        self.file.write(json.dumps(event) + "\n")

BANNER_TEXT = r"""
  ______                             _  __  __
 |  ____|                           | | \ \/ /
 | |__   _ __   ___ _ __ _   _ _ __ | |_ \  / 
 |  __| | '_ \ / __| '__| | | | '_ \| __| /  \ 
 | |____| | | | (__| |  | |_| | |_) | |_ /  \ \
 |______|_| |_|\___|_|   \__, | .__/ \__/_/\_\_\
                          __/ | |               
                         |___/|_|               
"""

DISCLAIMER = """[bold red]LEGAL DISCLAIMER:[/bold red]
EncryptX is a professional security auditing and vulnerability scanning toolkit.
Usage of EncryptX for scanning targets without prior written authorization is strictly
prohibited and may violate computer crime laws (e.g., Computer Fraud and Abuse Act).
The developers assume no liability for misuse, damage, or loss caused by this tool.

[bold yellow]By using this software, you agree to assume all responsibility for its application.[/bold yellow]
"""

def simulate_demo():
    console = Console(force_terminal=True, color_system="truecolor", width=100, height=35)
    
    # 1. Print Banner & Legal Disclaimer
    console.print(Align.center(f"[bold cyan]{BANNER_TEXT}[/bold cyan]"))
    console.print(Align.center("[bold white]* Professional Vulnerability Scanning & Security Audit Suite *[/bold white]"))
    console.print(Align.center("[cyan]Version: 1.0.0 | Engine: Python 3.10+ | Developed by Ganesh Kumar[/cyan]\n"))
    
    disclaimer_panel = Panel(
        DISCLAIMER,
        title="[!] SECURITY WARNING & CONDITIONS",
        border_style="red",
        expand=False
    )
    console.print(Align.center(disclaimer_panel))
    time.sleep(1.0)
    
    # 2. Scanning prompt simulation
    console.print("[yellow]Target target resolved to:[/yellow] [bold cyan]scanme.nmap.org[/bold cyan]")
    console.print("[yellow]Bypassing permission prompt (--force active). Ensure authorization exists.[/yellow]")
    time.sleep(0.5)
    
    # 3. Progress Bar Simulation
    modules = [
        ("Detecting WAF/CDN Protection...", 0.2),
        ("Scanning open TCP ports...", 0.4),
        ("Auditing security headers...", 0.1),
        ("Auditing SSL/TLS parameters...", 0.3),
        ("Resolving DNS host records...", 0.1),
        ("Performing WHOIS domain lookup...", 0.2),
        ("Checking core web vulnerabilities...", 0.3),
        ("Testing SQL Injection vectors...", 0.5),
        ("Testing XSS script vulnerabilities...", 0.4),
        ("Mining info disclosure risks...", 0.2),
        ("Looking for admin/login interfaces...", 0.3),
        ("Discovering API routes...", 0.2),
        ("Running Plugin: SSL/TLS Vulnerability Scanner...", 0.4),
        ("Running Plugin: Service Vulnerability Scanner...", 0.3),
        ("Running Plugin: CMS Vulnerability Scanner...", 0.2),
        ("Running Plugin: Network Vulnerability Scanner...", 0.3),
        ("Running Plugin: Subdomain Takeover Scanner...", 0.2),
        ("Running Plugin: SSRF & Path Traversal Scanner...", 0.3),
        ("Running Compliance Audit...", 0.4)
    ]
    
    with Progress(
        SpinnerColumn("line"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        console=console
    ) as progress:
        for desc, duration in modules:
            task = progress.add_task(f"[cyan]{desc}", total=100)
            steps = 5
            for step in range(steps):
                time.sleep(duration / steps)
                progress.update(task, advance=20)
            progress.update(task, completed=100)
            
    time.sleep(0.5)
    console.print("\n[green]* Scan complete! Results recorded to: [bold white]output/scan_20260623_080000.json[/bold white][/green]")
    time.sleep(0.5)
    
    # 4. Table of findings
    table = Table(title="EncryptX Vulnerability Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("Severity", justify="center")
    table.add_column("Module", justify="left")
    table.add_column("Title", justify="left")
    table.add_column("Target/URL", justify="left")
    
    findings = [
        ("[bold red][CRITICAL] CRITICAL[/bold red]", "Service Vulnerability Scanner", "MySQL Passwordless Root Login Allowed", "scanme.nmap.org:3306"),
        ("[red][HIGH] HIGH[/red]", "Header Scanner", "Missing Content Security Policy (CSP) Header", "http://scanme.nmap.org"),
        ("[yellow][WARN] MEDIUM[/yellow]", "Port Scanner", "Open Port Detected (22/SSH)", "scanme.nmap.org:22"),
        ("[yellow][WARN] MEDIUM[/yellow]", "Header Scanner", "Missing HTTP Strict Transport Security (HSTS) Header", "http://scanme.nmap.org"),
        ("[yellow][WARN] MEDIUM[/yellow]", "Header Scanner", "Missing X-Frame-Options Header", "http://scanme.nmap.org"),
        ("[blue][LOW] LOW[/blue]", "Header Scanner", "Missing X-Content-Type-Options Header", "http://scanme.nmap.org"),
        ("[blue][LOW] LOW[/blue]", "Header Scanner", "Web Server Signature Disclosure", "http://scanme.nmap.org"),
        ("[green][INFO] INFO[/green]", "Port Scanner", "Open Port Detected (80/HTTP)", "scanme.nmap.org:80"),
        ("[green][INFO] INFO[/green]", "Header Scanner", "Missing Referrer-Policy Header", "http://scanme.nmap.org")
    ]
    
    for row in findings:
        table.add_row(*row)
        
    console.print(table)
    time.sleep(0.8)
    
    # 5. Report Generation Simulation
    console.print("\n[yellow]Generating PDF report from output/scan_20260623_080000.json...[/yellow]")
    time.sleep(0.8)
    console.print("\n[green]* Professional PDF security audit report generated![/green]")
    console.print("[bold white]  Saved to: C:\\Users\\Ganesh kumar\\Downloads\\scan_20260623_080000_report.pdf[/bold white]")
    console.print("[dim]  Copy saved: output/scan_20260623_080000_report.pdf[/dim]")
    console.print("\n[bold cyan]>> Report downloaded to your Downloads folder! <<[/bold cyan]\n")
    time.sleep(1.0)

if __name__ == "__main__":
    cast_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "demo.cast"))
    print(f"Recording terminal session to {cast_path}...")
    with CastRecorder(cast_path, width=105, height=38):
        simulate_demo()
    print("Recording complete!")
