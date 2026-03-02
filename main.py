#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║      Threat Analyzer - by João Mincuzzi  ║
║   IP Analysis | Domain | Spoofing Check  ║
╚══════════════════════════════════════════╝
"""

import argparse
import sys
from modules.ip_analyzer import analyze_ip
from modules.domain_analyzer import analyze_domain
from modules.report import generate_report
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = """
[bold cyan]
 ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
    ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
    ██║   ███████║██████╔╝█████╗  ███████║   ██║   
    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   
    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝  
         █████╗ ███╗   ██╗ █████╗ ██╗  ██╗██╗
        ██╔══██╗████╗  ██║██╔══██╗██║  ██║██║
        ███████║██╔██╗ ██║███████║██║  ██║██║
        ██╔══██║██║╚██╗██║██╔══██║╚██╗██╔╝██║
        ██║  ██║██║ ╚████║██║  ██║ ╚████╔╝ ███████╗
        ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝
[/bold cyan]
[dim]          Threat Intelligence & Spoofing Analyzer[/dim]
"""

def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        description="Threat Analyzer - IP, Domain & Spoofing Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --ip 8.8.8.8
  python main.py --domain google.com
  python main.py --ip 1.2.3.4 --domain evil.com
  python main.py --domain phishing.com --report
        """
    )
    parser.add_argument("--ip", help="IP address to analyze")
    parser.add_argument("--domain", help="Domain to analyze")
    parser.add_argument("--vt-key", help="VirusTotal API Key (or set VT_API_KEY env var)")
    parser.add_argument("--abuse-key", help="AbuseIPDB API Key (or set ABUSE_API_KEY env var)")
    parser.add_argument("--report", action="store_true", help="Export results to JSON report")

    args = parser.parse_args()

    if not args.ip and not args.domain:
        console.print("[bold red]❌ Informe ao menos um --ip ou --domain[/bold red]")
        parser.print_help()
        sys.exit(1)

    results = {}

    if args.ip:
        console.rule(f"[bold yellow]🔍 Analisando IP: {args.ip}")
        ip_result = analyze_ip(args.ip, vt_key=args.vt_key, abuse_key=args.abuse_key)
        results["ip"] = ip_result

    if args.domain:
        console.rule(f"[bold yellow]🌐 Analisando Domínio: {args.domain}")
        domain_result = analyze_domain(args.domain, vt_key=args.vt_key)
        results["domain"] = domain_result

    if args.report:
        path = generate_report(results)
        console.print(f"\n[bold green]📄 Relatório exportado:[/bold green] {path}")

    console.rule("[dim]Análise concluída[/dim]")

if __name__ == "__main__":
    main()
