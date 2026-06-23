import os
import json
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from utils.banner import display_banner
from utils.helpers import validate_target, get_timestamp, get_readable_timestamp, severity_color, severity_icon
from scanners import (
    PortScanner, HeaderScanner, SSLScanner, DNSScanner, SubdomainScanner,
    VulnScanner, SQLiScanner, XSSScanner, TechFingerprinter, CookieScanner,
    WAFDetector, InfoDisclosureScanner, AuthScanner, APIScanner, WhoisScanner
)
from reports import generate_pdf_report

console = Console()

CONFIG_PATH = "config.json"

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def make_progress_callback(progress, task_id):
    """Generates a progress updating callback for Rich progress bars."""
    return lambda curr, total: progress.update(task_id, completed=int((curr / total) * 100))

@click.group()
def cli():
    """EncryptX — Terminal-Based Infrastructure Security Auditing Tool."""
    pass

@cli.command()
def config():
    """Interactive wizard to view or customize configurations."""
    display_banner(console)
    conf = load_config()
    console.print(Panel("[bold cyan]EncryptX Configuration Panel[/bold cyan]"))
    console.print(f"[yellow]Current Default Profile:[/yellow] {conf.get('default_profile', 'standard')}")
    console.print(f"[yellow]DNS Wordlist Size:[/yellow] {len(conf.get('dns_wordlist', []))} subdomains")
    
    # Simple interactive option
    if click.confirm("Would you like to customize the default scan profile?"):
        new_prof = click.prompt("Choose profile (quick, standard, full)", type=click.Choice(["quick", "standard", "full"]))
        conf["default_profile"] = new_prof
        with open(CONFIG_PATH, "w") as f:
            json.dump(conf, f, indent=2)
        console.print("[green]* Configuration updated successfully![/green]")

@cli.command()
@click.option("--target", required=True, help="Domain name, host IP or web URL to scan.")
@click.option("--ports", is_flag=True, help="Scan target ports.")
@click.option("--headers", is_flag=True, help="Scan HTTP headers.")
@click.option("--ssl", is_flag=True, help="Scan SSL/TLS configuration.")
@click.option("--dns", is_flag=True, help="Scan DNS settings.")
@click.option("--subdomains", is_flag=True, help="Scan subdomains.")
@click.option("--vulns", is_flag=True, help="Scan core vulnerabilities.")
@click.option("--sqli", is_flag=True, help="Scan SQL Injection.")
@click.option("--xss", is_flag=True, help="Scan Cross-Site Scripting.")
@click.option("--tech", is_flag=True, help="Scan tech stack fingerprint.")
@click.option("--cookies", is_flag=True, help="Scan cookie safety flags.")
@click.option("--waf", is_flag=True, help="Scan WAF presence.")
@click.option("--info", is_flag=True, help="Scan info disclosure risks.")
@click.option("--auth", is_flag=True, help="Scan auth/login exposures.")
@click.option("--api", is_flag=True, help="Scan API interface routes.")
@click.option("--whois", is_flag=True, help="Run WHOIS domain registration lookup.")
@click.option("--deep", is_flag=True, help="Run all deep scan vulnerability modules.")
@click.option("--plugins", is_flag=True, help="Run all advanced Nessus-style plugins.")
@click.option("--plugin-ssl", is_flag=True, help="Run SSL/TLS vulnerability plugin.")
@click.option("--plugin-services", is_flag=True, help="Run service vulnerability plugin.")
@click.option("--plugin-cms", is_flag=True, help="Run CMS vulnerability plugin.")
@click.option("--plugin-network", is_flag=True, help="Run network vulnerability plugin.")
@click.option("--plugin-takeover", is_flag=True, help="Run subdomain takeover plugin.")
@click.option("--plugin-ssrf", is_flag=True, help="Run SSRF & Path Traversal plugin.")
@click.option("--plugin-compliance", is_flag=True, help="Run Compliance & Scoring plugin.")
@click.option("--all", "run_all", is_flag=True, help="Run all available basic, deep, and plugin scans.")
@click.option("--force", "-f", is_flag=True, help="Bypass interactive scan permission confirmation.")
def scan(target, ports, headers, ssl, dns, subdomains, vulns, sqli, xss, tech, cookies, waf, info, auth, api, whois, deep, plugins, plugin_ssl, plugin_services, plugin_cms, plugin_network, plugin_takeover, plugin_ssrf, plugin_compliance, run_all, force):
    """Audits targets for configuration flaws and security vulnerabilities."""
    display_banner(console)
    
    # Store all kwargs for dynamic parameter checks later
    kwargs = {
        "ports": ports, "headers": headers, "ssl": ssl, "dns": dns, "subdomains": subdomains,
        "vulns": vulns, "sqli": sqli, "xss": xss, "tech": tech, "cookies": cookies,
        "waf": waf, "info": info, "auth": auth, "api": api, "whois": whois, "deep": deep,
        "plugins": plugins, "plugin_ssl": plugin_ssl, "plugin_services": plugin_services,
        "plugin_cms": plugin_cms, "plugin_network": plugin_network, "plugin_takeover": plugin_takeover,
        "plugin_ssrf": plugin_ssrf, "plugin_compliance": plugin_compliance, "run_all": run_all
    }

    try:
        validated_target = validate_target(target)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        return
        
    # Legal disclaimer confirmation
    console.print(f"[yellow]Target target resolved to:[/yellow] [bold cyan]{validated_target}[/bold cyan]")
    if not force:
        if not click.confirm("Do you have explicit permission to scan this host?"):
            console.print("[red]Aborted. Security scanning requires written authorization.[/red]")
            return
    else:
        console.print("[yellow]Bypassing permission prompt (--force active). Ensure authorization exists.[/yellow]")
        
    conf = load_config()
    profile_name = conf.get("default_profile", "standard")
    profile = conf.get("profiles", {}).get(profile_name, {"ports": [80, 443], "timeout": 3.0})
    
    # Collect modules to execute
    run_ports = ports or run_all
    run_headers = headers or run_all
    run_ssl = ssl or run_all
    run_dns = dns or run_all
    run_subdomains = subdomains or run_all
    run_vulns = vulns or run_all
    run_whois = whois or run_all
    
    # Deep modules
    run_sqli = sqli or deep or run_all
    run_xss = xss or deep or run_all
    run_tech = tech or deep or run_all
    run_cookies = cookies or deep or run_all
    run_waf = waf or deep or run_all
    run_info = info or deep or run_all
    run_auth = auth or deep or run_all
    run_api = api or deep or run_all
    
    # If no flags are provided, run a standard set of basic scans
    if not any([ports, headers, ssl, dns, subdomains, vulns, sqli, xss, tech, cookies, waf, info, auth, api, whois, deep, plugins, plugin_ssl, plugin_services, plugin_cms, plugin_network, plugin_takeover, plugin_ssrf, plugin_compliance, run_all]):
        run_ports = run_headers = run_ssl = run_dns = run_vulns = True

    results = {
        "target": validated_target,
        "timestamp": get_readable_timestamp(),
        "findings": [],
        "scans": {}
    }
    
    all_findings = []
    
    # Set up Rich progress bar
    with Progress(
        SpinnerColumn("line"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        console=console
    ) as progress:
        
        # 1. WAF Scan
        if run_waf:
            t = progress.add_task("[cyan]Detecting WAF/CDN Protection...", total=100)
            waf_scanner = WAFDetector(validated_target, timeout=profile["timeout"])
            waf_res = waf_scanner.scan()
            progress.update(t, completed=100)
            results["scans"]["waf"] = waf_res
            all_findings.extend(waf_res.get("findings", []))
            
        # 2. Port Scan
        if run_ports:
            t = progress.add_task("[cyan]Scanning open TCP ports...", total=100)
            port_scanner = PortScanner(validated_target, ports=profile["ports"], timeout=profile["timeout"])
            port_res = port_scanner.scan(progress_callback=make_progress_callback(progress, t))
            results["scans"]["ports"] = port_res
            all_findings.extend(port_res.get("findings", []))

        # 3. HTTP Headers Audit
        if run_headers:
            t = progress.add_task("[cyan]Auditing security headers...", total=100)
            h_scanner = HeaderScanner(validated_target, timeout=profile["timeout"])
            h_res = h_scanner.scan()
            progress.update(t, completed=100)
            results["scans"]["headers"] = h_res
            all_findings.extend(h_res.get("findings", []))
            
        # 4. SSL/TLS Audit
        if run_ssl:
            t = progress.add_task("[cyan]Auditing SSL/TLS parameters...", total=100)
            ssl_scanner = SSLScanner(validated_target, timeout=profile["timeout"])
            ssl_res = ssl_scanner.scan()
            progress.update(t, completed=100)
            results["scans"]["ssl"] = ssl_res
            all_findings.extend(ssl_res.get("findings", []))
            
        # 5. DNS Audit
        if run_dns:
            t = progress.add_task("[cyan]Resolving DNS host records...", total=100)
            dns_scanner = DNSScanner(validated_target)
            dns_res = dns_scanner.scan()
            progress.update(t, completed=100)
            results["scans"]["dns"] = dns_res
            all_findings.extend(dns_res.get("findings", []))

        # 5.5 WHOIS Lookup
        if run_whois:
            t = progress.add_task("[cyan]Performing WHOIS domain lookup...", total=100)
            whois_scanner = WhoisScanner(validated_target, timeout=profile["timeout"])
            whois_res = whois_scanner.scan()
            progress.update(t, completed=100)
            results["scans"]["whois"] = whois_res
            all_findings.extend(whois_res.get("findings", []))

        # 6. Subdomain Enumeration
        if run_subdomains:
            t = progress.add_task("[cyan]Enumerating subdomains...", total=100)
            sub_scanner = SubdomainScanner(validated_target, subdomains=conf.get("dns_wordlist"))
            sub_res = sub_scanner.scan(progress_callback=make_progress_callback(progress, t))
            results["scans"]["subdomains"] = sub_res
            all_findings.extend(sub_res.get("findings", []))

        # 7. Technology Stack Check
        if run_tech:
            t = progress.add_task("[cyan]Fingerprinting software stack...", total=100)
            tech_scanner = TechFingerprinter(validated_target, timeout=profile["timeout"])
            tech_res = tech_scanner.scan()
            progress.update(t, completed=100)
            results["scans"]["tech"] = tech_res
            all_findings.extend(tech_res.get("findings", []))

        # 8. Cookie Audit
        if run_cookies:
            t = progress.add_task("[cyan]Auditing cookie security flags...", total=100)
            cookie_scanner = CookieScanner(validated_target, timeout=profile["timeout"])
            cookie_res = cookie_scanner.scan()
            progress.update(t, completed=100)
            results["scans"]["cookies"] = cookie_res
            all_findings.extend(cookie_res.get("findings", []))

        # 9. Core Vulnerabilities Check
        if run_vulns:
            t = progress.add_task("[cyan]Checking core web vulnerabilities...", total=100)
            vuln_scanner = VulnScanner(validated_target, timeout=profile["timeout"])
            vuln_res = vuln_scanner.scan()
            progress.update(t, completed=100)
            results["scans"]["vulns"] = vuln_res
            all_findings.extend(vuln_res.get("findings", []))

        # 10. Deep SQLi Scanner
        if run_sqli:
            t = progress.add_task("[cyan]Testing SQL Injection vectors...", total=100)
            sqli_scanner = SQLiScanner(validated_target, timeout=profile["timeout"])
            sqli_res = sqli_scanner.scan(progress_callback=make_progress_callback(progress, t))
            results["scans"]["sqli"] = sqli_res
            all_findings.extend(sqli_res.get("findings", []))

        # 11. Deep XSS Scanner
        if run_xss:
            t = progress.add_task("[cyan]Testing XSS script vulnerabilities...", total=100)
            xss_scanner = XSSScanner(validated_target, timeout=profile["timeout"])
            xss_res = xss_scanner.scan(progress_callback=make_progress_callback(progress, t))
            results["scans"]["xss"] = xss_res
            all_findings.extend(xss_res.get("findings", []))

        # 12. Information Disclosure
        if run_info:
            t = progress.add_task("[cyan]Mining info disclosure risks...", total=100)
            info_scanner = InfoDisclosureScanner(validated_target, timeout=profile["timeout"])
            info_res = info_scanner.scan(progress_callback=make_progress_callback(progress, t))
            results["scans"]["info"] = info_res
            all_findings.extend(info_res.get("findings", []))

        # 13. Administrative Panels Discovery
        if run_auth:
            t = progress.add_task("[cyan]Looking for admin/login interfaces...", total=100)
            auth_scanner = AuthScanner(validated_target, timeout=profile["timeout"])
            auth_res = auth_scanner.scan(progress_callback=make_progress_callback(progress, t))
            results["scans"]["auth"] = auth_res
            all_findings.extend(auth_res.get("findings", []))

        # 14. API endpoints discovery
        if run_api:
            t = progress.add_task("[cyan]Discovering API routes...", total=100)
            api_scanner = APIScanner(validated_target, timeout=profile["timeout"])
            api_res = api_scanner.scan(progress_callback=make_progress_callback(progress, t))
            results["scans"]["api"] = api_res
            all_findings.extend(api_res.get("findings", []))

        # --- Nessus-Style Advanced Plugins ---
        # Import plugin registry
        from plugins import PLUGIN_REGISTRY, get_plugin

        run_plugins = kwargs.get("plugins") or kwargs.get("run_all")
        
        # Determine specific plugins to run
        active_plugins = []
        plugin_flags = {
            "ssl": kwargs.get("plugin_ssl"),
            "services": kwargs.get("plugin_services"),
            "cms": kwargs.get("plugin_cms"),
            "network": kwargs.get("plugin_network"),
            "takeover": kwargs.get("plugin_takeover"),
            "ssrf": kwargs.get("plugin_ssrf"),
            "compliance": kwargs.get("plugin_compliance")
        }

        for plugin_name, flag_active in plugin_flags.items():
            if run_plugins or flag_active:
                active_plugins.append(plugin_name)

        # Execute selected plugins
        results["plugins"] = {}
        for plugin_id in active_plugins:
            # Skip compliance scoring plugin until last, as it analyzes previous findings
            if plugin_id == "compliance":
                continue
                
            plugin_info = PLUGIN_REGISTRY[plugin_id]
            t = progress.add_task(f"[cyan]Running Plugin: {plugin_info['name']}...", total=100)
            
            try:
                # Instantiate plugin
                extra_args = {}
                if plugin_id == "takeover":
                    # Pass subdomains finding references
                    extra_args["discovered_subdomains"] = results["scans"].get("subdomains", {}).get("findings", [])
                
                plugin_instance = get_plugin(plugin_id, validated_target, timeout=profile["timeout"], **extra_args)
                plugin_res = plugin_instance.run()
                progress.update(t, completed=100)
                
                results["plugins"][plugin_id] = plugin_res
                all_findings.extend(plugin_res.get("findings", []))
            except Exception as e:
                progress.update(t, completed=100)
                console.print(f"[bold red]Plugin Error ({plugin_id}):[/bold red] {str(e)}")

        # Run Compliance scoring last if enabled
        if run_plugins or kwargs.get("plugin_compliance"):
            plugin_info = PLUGIN_REGISTRY["compliance"]
            t = progress.add_task(f"[cyan]Running Compliance Audit...", total=100)
            try:
                # Pass all accumulated findings up to this point
                comp_plugin = get_plugin("compliance", validated_target, timeout=profile["timeout"], existing_findings=all_findings)
                comp_res = comp_plugin.run()
                progress.update(t, completed=100)
                
                results["plugins"]["compliance"] = comp_res
                all_findings.extend(comp_res.get("findings", []))
            except Exception as e:
                progress.update(t, completed=100)
                console.print(f"[bold red]Plugin Error (compliance):[/bold red] {str(e)}")

    results["findings"] = all_findings

    # Save scan data to output JSON
    ts = get_timestamp()
    os.makedirs("output", exist_ok=True)
    output_filename = f"output/scan_{ts}.json"
    with open(output_filename, "w") as f:
        json.dump(results, f, indent=2)
        
    console.print(f"\n[green]* Scan complete! Results recorded to: [bold white]{output_filename}[/bold white][/green]")

    # Print summary findings to console
    table = Table(title="EncryptX Vulnerability Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("Severity", justify="center")
    table.add_column("Module", justify="left")
    table.add_column("Title", justify="left")
    table.add_column("Target/URL", justify="left")

    # Sort findings by severity for ordered display
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "INFO").upper(), 5))

    for f in all_findings:
        color = severity_color(f["severity"])
        icon = severity_icon(f["severity"])
        table.add_row(
            f"[{color}]{icon} {f['severity']}[/{color}]",
            f["module"],
            f["title"],
            f["target"]
        )

    if all_findings:
        console.print(table)
    else:
        console.print("[bold green]Zero warnings or vulnerabilities detected on this target![/bold green]")

@cli.command()
@click.option("--input", "input_file", required=True, help="Input JSON scan results file.")
@click.option("--output", "output_file", help="Path to write the output PDF report.")
def report(input_file, output_file):
    """Generates a professional PDF report and saves it to Downloads folder."""
    if not os.path.exists(input_file):
        console.print(f"[bold red]Error:[/bold red] Scan file '{input_file}' not found.")
        return
        
    try:
        with open(input_file, "r") as f:
            scan_results = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to parse JSON file: {str(e)}")
        return

    # Determine Downloads folder path
    downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.exists(downloads_folder):
        downloads_folder = os.path.expanduser("~")  # Fallback to home directory

    # Build PDF filename
    base_name = os.path.basename(input_file).replace(".json", "_report.pdf")
    downloads_path = os.path.join(downloads_folder, base_name)

    # If user provided custom output path, use it; otherwise default to Downloads
    final_path = output_file if output_file else downloads_path
        
    console.print(f"[yellow]Generating PDF report from {input_file}...[/yellow]")
    
    try:
        generate_pdf_report(scan_results, final_path)
        console.print(f"\n[green]* Professional PDF security audit report generated![/green]")
        console.print(f"[bold white]  Saved to: {final_path}[/bold white]")
        
        # Also save a copy in the output/ folder for reference
        output_copy = os.path.join("output", base_name)
        if final_path != output_copy:
            import shutil
            shutil.copy2(final_path, output_copy)
            console.print(f"[dim]  Copy saved: {output_copy}[/dim]")
            
        console.print(f"\n[bold cyan]>> Report downloaded to your Downloads folder! <<[/bold cyan]")
    except Exception as e:
        console.print(f"[bold red]Error generating report:[/bold red] {str(e)}")

if __name__ == "__main__":
    cli()
