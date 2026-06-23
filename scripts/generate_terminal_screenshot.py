import os
import sys
import fitz  # PyMuPDF
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align

BANNER_TEXT = r"""
  ____                        __  __ 
 / ___|  ___ ___  _ __   ___  \ \/ / 
 \___ \ / __/ _ \| '_ \ / _ \  \  /  
  ___) | (_| (_) | |_) |  __/  /  \  
 |____/ \___\___/| .__/ \___| /_/\_\ 
                 |_|                 
"""

DISCLAIMER = """[bold red]LEGAL DISCLAIMER:[/bold red]
ScopeX is a professional security auditing and vulnerability scanning toolkit.
Usage of ScopeX for scanning targets without prior written authorization is strictly
prohibited and may violate computer crime laws (e.g., Computer Fraud and Abuse Act).
The developers assume no liability for misuse, damage, or loss caused by this tool.

[bold yellow]By using this software, you agree to assume all responsibility for its application.[/bold yellow]
"""

def generate_screenshot():
    # Use record=True to capture the SVG output
    console = Console(record=True, width=100, color_system="truecolor")
    
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
    
    # 2. Scanning prompt simulation
    console.print("[yellow]Target target resolved to:[/yellow] [bold cyan]scanme.nmap.org[/bold cyan]")
    console.print("[yellow]Bypassing permission prompt (--force active). Ensure authorization exists.[/yellow]")
    
    # 3. Progress bar completions
    console.print("  Detecting WAF/CDN Protection...                  ---------------------------------------- 100%")
    console.print("  Scanning open TCP ports...                       ---------------------------------------- 100%")
    console.print("  Auditing security headers...                     ---------------------------------------- 100%")
    console.print("  Auditing SSL/TLS parameters...                   ---------------------------------------- 100%")
    console.print("  Resolving DNS host records...                    ---------------------------------------- 100%")
    console.print("  Performing WHOIS domain lookup...                ---------------------------------------- 100%")
    console.print("  Checking core web vulnerabilities...             ---------------------------------------- 100%")
    console.print("  Testing SQL Injection vectors...                 ---------------------------------------- 100%")
    console.print("  Testing XSS script vulnerabilities...            ---------------------------------------- 100%")
    console.print("  Mining info disclosure risks...                  ---------------------------------------- 100%")
    console.print("  Looking for admin/login interfaces...            ---------------------------------------- 100%")
    console.print("  Discovering API routes...                        ---------------------------------------- 100%")
    console.print("  Running Plugin: SSL/TLS Vulnerability Scanner... ---------------------------------------- 100%")
    console.print("  Running Plugin: Service Vulnerability Scanner... ---------------------------------------- 100%")
    console.print("  Running Plugin: CMS Vulnerability Scanner...     ---------------------------------------- 100%")
    console.print("  Running Plugin: Network Vulnerability Scanner... ---------------------------------------- 100%")
    console.print("  Running Plugin: Subdomain Takeover Scanner...    ---------------------------------------- 100%")
    console.print("  Running Plugin: SSRF & Path Traversal Scanner... ---------------------------------------- 100%")
    console.print("  Running Compliance Audit...                      ---------------------------------------- 100%")
    
    console.print("\n[green]* Scan complete! Results recorded to: [bold white]output/scan_20260623_080000.json[/bold white][/green]\n")
    
    # 4. Table of findings
    table = Table(title="ScopeX Vulnerability Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("Severity", justify="center")
    table.add_column("Module", justify="left")
    table.add_column("Title", justify="left")
    table.add_column("Target/URL", justify="left")
    
    findings = [
        ("[bold red]CRITICAL[/bold red]", "Service Vulnerability Scanner", "MySQL Passwordless Root Login Allowed", "scanme.nmap.org:3306"),
        ("[red]HIGH[/red]", "Header Scanner", "Missing Content Security Policy (CSP) Header", "http://scanme.nmap.org"),
        ("[yellow]MEDIUM[/yellow]", "Port Scanner", "Open Port Detected (22/SSH)", "scanme.nmap.org:22"),
        ("[yellow]MEDIUM[/yellow]", "Header Scanner", "Missing HTTP Strict Transport Security (HSTS) Header", "http://scanme.nmap.org"),
        ("[yellow]MEDIUM[/yellow]", "Header Scanner", "Missing X-Frame-Options Header", "http://scanme.nmap.org"),
        ("[blue]LOW[/blue]", "Header Scanner", "Missing X-Content-Type-Options Header", "http://scanme.nmap.org"),
        ("[blue]LOW[/blue]", "Header Scanner", "Web Server Signature Disclosure", "http://scanme.nmap.org"),
        ("[green]INFO[/green]", "Port Scanner", "Open Port Detected (80/HTTP)", "scanme.nmap.org:80"),
        ("[green]INFO[/green]", "Header Scanner", "Missing Referrer-Policy Header", "http://scanme.nmap.org")
    ]
    
    for row in findings:
        table.add_row(*row)
        
    console.print(table)
    
    console.print("\n[yellow]Generating PDF report from output/scan_20260623_080000.json...[/yellow]")
    console.print("\n[green]* Professional PDF security audit report generated![/green]")
    console.print("[bold white]  Saved to: C:\\Users\\Ganesh kumar\\Downloads\\scan_20260623_080000_report.pdf[/bold white]")
    console.print("[dim]  Copy saved: output/scan_20260623_080000_report.pdf[/dim]")
    console.print("\n[bold cyan]>> Report downloaded to your Downloads folder! <<[/bold cyan]\n")

    # Save to SVG
    svg_path = "assets/scan_output.svg"
    os.makedirs(os.path.dirname(svg_path), exist_ok=True)
    console.save_svg(svg_path, title="ScopeX Vulnerability Scan")
    
    # Convert SVG to PNG via PyMuPDF
    png_path = "assets/scan_output.png"
    print(f"Converting {svg_path} to {png_path}...")
    doc = fitz.open(svg_path)
    page = doc.load_page(0)
    pix = page.get_pixmap(dpi=150)
    pix.save(png_path)
    print("Done!")
    
    # Clean up SVG
    if os.path.exists(svg_path):
        os.remove(svg_path)

if __name__ == "__main__":
    generate_screenshot()
