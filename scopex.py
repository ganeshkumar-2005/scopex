import os
import json
import click
import urllib.parse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from utils.banner import display_banner
from utils.helpers import validate_target, get_timestamp, severity_color, severity_icon
from reports import generate_pdf_report

console = Console()
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
OUTPUT_DIR = BASE_DIR / "output"

def load_config():
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            console.print(f"[bold red]Warning: config.json is invalid ({str(e)}), using defaults[/bold red]")
    return {}

@click.group()
def cli():
    """ScopeX — Terminal-Based Infrastructure Security Auditing Tool."""
    pass

@cli.command()
def config():
    """Interactive wizard to view or customize configurations."""
    display_banner(console)
    conf = load_config()
    console.print(Panel("[bold cyan]ScopeX Configuration Panel[/bold cyan]"))
    console.print(f"[yellow]Current Default Profile:[/yellow] {conf.get('default_profile', 'standard')}")
    console.print(f"[yellow]DNS Wordlist Size:[/yellow] {len(conf.get('dns_wordlist', []))} subdomains")
    
    # Simple interactive option
    if click.confirm("Would you like to customize the default scan profile?"):
        new_prof = click.prompt("Choose profile (quick, standard, full)", type=click.Choice(["quick", "standard", "full"]))
        conf["default_profile"] = new_prof
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
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
@click.option("--nuclei", is_flag=True, help="Run Nuclei integration scanner.")
@click.option("--nuclei-tags", help="Comma-separated list of tags to run with Nuclei.")
@click.option("--nuclei-templates", help="Path to a specific Nuclei template file or directory.")
@click.option("--force", "-f", is_flag=True, help="Bypass interactive scan permission confirmation.")
# V2 specific flags
@click.option("--auth-user", help="Username for authenticated scanning.")
@click.option("--auth-pass", help="Password for authenticated scanning.")
@click.option("--auth-url", help="Login URL for authenticated scanning.")
@click.option("--resume", "resume_checkpoint", help="Path to checkpoint JSON file to resume scan.")
@click.option("--waf-evasion", type=click.Choice(["stealth", "aggressive", "bypass"]), help="Enable WAF evasion with selected profile.")
@click.option("--skip-nuclei", is_flag=True, help="Skip Nuclei scan integration.")
@click.option("--output-json", is_flag=True, help="Output results in JSON format to stdout.")
@click.option("--output-sarif", "output_sarif", default=None, help="Write SARIF 2.1.0 output to this file path.")
@click.option("--debug", is_flag=True, help="Enable verbose console debugging output.")
@click.option("--verify-ssl/--no-verify-ssl", "verify_ssl", default=False,
              help="Verify TLS certificates (default: --no-verify-ssl for pentest targets).")
@click.option("--modules", "modules", default=None,
              help="Comma-separated scanner/plugin keys to run, e.g. headers,ssl,sqli,plugin:ssrf. "
                   "Overrides individual --headers, --ssl etc. flags when provided.")
@click.option("--scanner-timeout", "scanner_timeout", default=120.0, show_default=True, type=float,
              help="Per-scanner wall-clock timeout in seconds. "
                   "Slow scanners (sqli, xss, ports) use this value; fast scanners use half. "
                   "Increase for deep targets with many endpoints.")
def scan(
    target, ports, headers, ssl, dns, subdomains, vulns, sqli, xss, tech, cookies, waf, info, auth, api, whois,
    deep, plugins, plugin_ssl, plugin_services, plugin_cms, plugin_network, plugin_takeover, plugin_ssrf,
    plugin_compliance, run_all, nuclei, nuclei_tags, nuclei_templates, force,
    auth_user, auth_pass, auth_url, resume_checkpoint, waf_evasion, skip_nuclei, output_json, output_sarif,
    debug, verify_ssl, modules, scanner_timeout
):
    """Audits targets for configuration flaws and security vulnerabilities."""
    import asyncio
    from core.context import ScanContext, AuthContext
    from core.orchestrator import ScanOrchestrator
    from utils.logging_config import setup_logging
    
    # Initialize logging
    setup_logging(debug=debug)
    
    display_banner(console)
    
    # Target validation
    try:
        validated_target = validate_target(target)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        return
        
    # Normalize target URL and host
    if not (validated_target.startswith("http://") or validated_target.startswith("https://")):
        host = validated_target
        validated_target = f"https://{validated_target}"
    else:
        parsed_target = urllib.parse.urlparse(validated_target)
        host = parsed_target.hostname or parsed_target.netloc
        if not host:
            host = validated_target

    console.print(f"[yellow]Target target resolved to:[/yellow] [bold cyan]{validated_target}[/bold cyan]")
    if not force:
        if not click.confirm("Do you have explicit permission to scan this host?"):
            console.print("[red]Aborted. Security scanning requires written authorization.[/red]")
            return
    else:
        console.print("[yellow]Bypassing permission prompt (--force active). Ensure authorization exists.[/yellow]")
        
    # Load configuration
    conf = load_config()
    profile_name = conf.get("default_profile", "standard")
    profile = conf.get("profiles", {}).get(profile_name, {})
    timeout = profile.get("timeout", 3.0)

    # Determine which scanners to run
    scanners_to_run = []
    
    # --modules overrides individual boolean flags when provided
    if modules:
        from core.orchestrator import _SCANNER_REGISTRY
        valid_keys = set(_SCANNER_REGISTRY.keys()) | {
            "plugin:ssl", "plugin:services", "plugin:cms",
            "plugin:network", "plugin:takeover", "plugin:ssrf", "plugin:compliance",
            "plugins",
        }
        requested = [m.strip() for m in modules.split(",") if m.strip()]
        unknown = [m for m in requested if m not in valid_keys]
        if unknown:
            console.print(
                f"[bold red]Error:[/bold red] Unknown module(s): {', '.join(unknown)}\n"
                f"Valid keys: {', '.join(sorted(valid_keys))}"
            )
            return
        scanners_to_run = requested
    elif run_all:
        scanners_to_run = None  # None tells orchestrator to run all
    elif any([ports, headers, ssl, dns, subdomains, vulns, sqli, xss, tech, cookies,
               waf, info, auth, api, whois, plugins, plugin_ssl, plugin_services,
               plugin_cms, plugin_network, plugin_takeover, plugin_ssrf, plugin_compliance]):
        if ports: scanners_to_run.append("ports")
        if headers: scanners_to_run.append("headers")
        if ssl: scanners_to_run.append("ssl")
        if dns: scanners_to_run.append("dns")
        if subdomains: scanners_to_run.append("subdomain")
        if vulns: scanners_to_run.append("vulns")
        if sqli: scanners_to_run.append("sqli")
        if xss: scanners_to_run.append("xss")
        if tech: scanners_to_run.append("tech")
        if cookies: scanners_to_run.append("cookies")
        if waf: scanners_to_run.append("waf")
        if info: scanners_to_run.append("info")
        if auth: scanners_to_run.append("auth_paths")
        if api: scanners_to_run.append("api")
        if whois: scanners_to_run.append("whois")
        
        # Deep profile adds all deep scanners if requested
        if deep:
            deep_keys = ["sqli", "xss", "tech", "cookies", "waf", "info", "auth_paths", "api"]
            for dk in deep_keys:
                if dk not in scanners_to_run:
                    scanners_to_run.append(dk)
                    
        # Plugins
        if plugins:
            scanners_to_run.append("plugins")
        else:
            if plugin_ssl: scanners_to_run.append("plugin:ssl")
            if plugin_services: scanners_to_run.append("plugin:services")
            if plugin_cms: scanners_to_run.append("plugin:cms")
            if plugin_network: scanners_to_run.append("plugin:network")
            if plugin_takeover: scanners_to_run.append("plugin:takeover")
            if plugin_ssrf: scanners_to_run.append("plugin:ssrf")
            if plugin_compliance: scanners_to_run.append("plugin:compliance")
    else:
        # Default scan profile list
        scanners_to_run = profile.get("scanners", ["ports", "headers", "ssl", "dns", "vulns"])
        if scanners_to_run == "all":
            scanners_to_run = None

    # AuthContext setup
    auth_ctx = None
    login_url = auth_url or conf.get("authentication", {}).get("login_url")
    username = auth_user or conf.get("authentication", {}).get("username")
    password = auth_pass or conf.get("authentication", {}).get("password")
    
    if login_url and username and password:
        auth_ctx = AuthContext(
            login_url=login_url,
            username=username,
            password=password,
            username_field=conf.get("authentication", {}).get("username_field", "username"),
            password_field=conf.get("authentication", {}).get("password_field", "password"),
            success_indicator=conf.get("authentication", {}).get("success_indicator", ""),
        )

    # ScanContext setup
    waf_evasion_enabled = waf_evasion is not None or conf.get("waf_evasion", {}).get("enabled", False)
    waf_evasion_profile = waf_evasion or conf.get("waf_evasion", {}).get("profile", "stealth")
    
    should_skip_nuclei = skip_nuclei or not (nuclei or run_all) or profile.get("nuclei_tags") == []

    ctx = ScanContext(
        target=validated_target,
        host=host,
        profile=profile_name,
        ports=profile.get("ports", []),
        timeout=timeout,
        scanner_timeout=scanner_timeout,
        verify_ssl=verify_ssl,
        waf_evasion=waf_evasion_enabled,
        waf_evasion_profile=waf_evasion_profile,
        auth=auth_ctx,
        skip_nuclei=should_skip_nuclei,
        nuclei_tags=[t.strip() for t in nuclei_tags.split(",")] if nuclei_tags else profile.get("nuclei_tags", []),
        nuclei_templates=nuclei_templates,
        resume_checkpoint=resume_checkpoint,
    )

    # Attach CLI output settings to context for orchestrator progress visibility
    ctx.output_json = output_json

    async def run_orchestrator():
        orchestrator = ScanOrchestrator()
        return await orchestrator.run(ctx, scanners_to_run)

    result = asyncio.run(run_orchestrator())

    # Write output to JSON
    ts = get_timestamp()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_filename = str(OUTPUT_DIR / f"scan_{ts}.json")
    result_dict = result.to_dict()
    
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(result_dict, f, indent=2)

    # SARIF export if requested
    if output_sarif:
        try:
            from reports.sarif_report import generate_sarif_report
            generate_sarif_report(result.all_findings, output_sarif)
            console.print(f"[green]* SARIF report written to: [bold white]{output_sarif}[/bold white][/green]")
        except Exception as sarif_err:
            console.print(f"[bold red]Warning:[/bold red] SARIF export failed: {sarif_err}")

    # Output JSON directly if requested
    if output_json:
        click.echo(json.dumps(result_dict, indent=2))
        return

    console.print(f"\n[green]* Scan complete! Results recorded to: [bold white]{output_filename}[/bold white][/green]")

    # Print summary Table
    table = Table(title="ScopeX Vulnerability Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("Severity", justify="center")
    table.add_column("Module", justify="left")
    table.add_column("Title", justify="left")
    table.add_column("Target/URL", justify="left")

    all_findings = result.all_findings
    
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.severity.upper(), 5))

    for f in all_findings:
        color = severity_color(f.severity)
        icon = severity_icon(f.severity)
        table.add_row(
            f"[{color}]{icon} {f.severity}[/{color}]",
            f.module,
            f.title,
            f.target
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
        with open(input_file, "r", encoding="utf-8") as f:
            scan_results = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to parse JSON file: {str(e)}")
        return

    downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.exists(downloads_folder):
        downloads_folder = os.path.expanduser("~")

    base_name = os.path.basename(input_file).replace(".json", "_report.pdf")
    downloads_path = os.path.join(downloads_folder, base_name)
    final_path = output_file if output_file else downloads_path
        
    console.print(f"[yellow]Generating PDF report from {input_file}...[/yellow]")
    
    try:
        generate_pdf_report(scan_results, final_path)
        console.print(f"\n[green]* Professional PDF security audit report generated![/green]")
        console.print(f"[bold white]  Saved to: {final_path}[/bold white]")
        
        output_copy = str(OUTPUT_DIR / base_name)
        if final_path != output_copy:
            import shutil
            shutil.copy2(final_path, output_copy)
            console.print(f"[dim]  Copy saved: {output_copy}[/dim]")
            
        console.print(f"\n[bold cyan]>> Report downloaded to your Downloads folder! <<[/bold cyan]")
    except Exception as e:
        console.print(f"[bold red]Error generating report:[/bold red] {str(e)}")

@cli.command()
@click.option("--port", default=8080, help="Port to host the dashboard on (default: 8080).")
def dashboard(port):
    """Launches the premium HTML interactive visualizer dashboard."""
    display_banner(console)
    console.print(Panel(f"[bold cyan]ScopeX Interactive Visualizer[/bold cyan]\n[dim]Hosting at: http://localhost:{port}[/dim]"))
    
    from reports.dashboard import start_dashboard
    start_dashboard(port)

@cli.command(name="_run_plugin", hidden=True)
def run_plugin():
    """Hidden command to execute isolated plugins in a subprocess."""
    from plugins.runner import main as runner_main
    runner_main()

if __name__ == "__main__":
    cli()
