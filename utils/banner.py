import sys
from rich.console import Console
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

def display_banner(console: Console):
    """Displays the ScopeX ASCII banner and a formatted panel showing version, status, and legal disclaimer."""
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
