#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║      Threat Analyzer - by João Mincuzzi  ║
║   IP | Domain | SSL | URLScan | Bulk     ║
╚══════════════════════════════════════════╝
"""

import argparse
import os
import sys
import time

# Carrega .env se existir
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from modules.ip_analyzer import analyze_ip
from modules.domain_analyzer import analyze_domain
from modules.ssl_analyzer import analyze_ssl
from modules.urlscan import analyze_url
from modules.validator import validate_ip, validate_domain, sanitize_domain, load_bulk_targets
from modules.report import generate_report
from modules.html_report import generate_html_report
from rich.console import Console

console = Console()

BANNER = """[bold cyan]
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
[/bold cyan][dim]     Threat Intelligence | IP | Domain | SSL | Spoofing[/dim]
"""

VT_RATE_LIMIT_DELAY = 16


def check_vt_ratelimit(vt_used: list, api_key: str):
    if not api_key:
        return
    if len(vt_used) > 0 and len(vt_used) % 4 == 0:
        console.print(f"[dim]⏳ Rate limit VT — aguardando {VT_RATE_LIMIT_DELAY}s...[/dim]")
        time.sleep(VT_RATE_LIMIT_DELAY)
    vt_used.append(1)


def run_analysis(target_type: str, target: str, args, vt_used: list) -> dict:
    results = {}
    vt_key = args.vt_key or os.environ.get("VT_API_KEY")
    abuse_key = args.abuse_key or os.environ.get("ABUSE_API_KEY")
    urlscan_key = args.urlscan_key or os.environ.get("URLSCAN_API_KEY")

    if target_type == "ip":
        console.rule(f"[bold yellow]🔍 IP: {target}")
        check_vt_ratelimit(vt_used, vt_key)
        results["ip"] = analyze_ip(target, vt_key=vt_key, abuse_key=abuse_key)

    elif target_type == "domain":
        console.rule(f"[bold yellow]🌐 Domínio: {target}")
        check_vt_ratelimit(vt_used, vt_key)
        domain_result = analyze_domain(target, vt_key=vt_key)

        if not args.no_ssl:
            ssl_result = analyze_ssl(target)
            domain_result["ssl"] = ssl_result

        if not args.no_urlscan:
            urlscan_result = analyze_url(target, api_key=urlscan_key)
            domain_result["urlscan"] = urlscan_result

        results["domain"] = domain_result

    return results


def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        description="Threat Analyzer — IP, Domain, SSL & Spoofing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python main.py --ip 185.220.101.45
  python main.py --domain google.com
  python main.py --ip 1.2.3.4 --domain evil.com --html
  python main.py --bulk targets.txt --html
  python main.py --domain phishing.com --no-ssl --no-urlscan
        """
    )

    target_group = parser.add_argument_group("Alvos")
    target_group.add_argument("--ip", help="IP para analisar")
    target_group.add_argument("--domain", help="Domínio para analisar")
    target_group.add_argument("--bulk", metavar="FILE", help="Arquivo .txt com lista de IPs/domínios")

    key_group = parser.add_argument_group("API Keys (opcional se configuradas no .env)")
    key_group.add_argument("--vt-key", help="VirusTotal API Key")
    key_group.add_argument("--abuse-key", help="AbuseIPDB API Key")
    key_group.add_argument("--urlscan-key", help="URLScan.io API Key")

    opt_group = parser.add_argument_group("Opções")
    opt_group.add_argument("--no-ssl", action="store_true", help="Pular análise SSL/TLS")
    opt_group.add_argument("--no-urlscan", action="store_true", help="Pular URLScan.io")
    opt_group.add_argument("--report", action="store_true", help="Exportar relatório JSON")
    opt_group.add_argument("--html", action="store_true", help="Exportar relatório HTML visual")

    args = parser.parse_args()

    if not args.ip and not args.domain and not args.bulk:
        console.print("[bold red]❌ Informe ao menos --ip, --domain ou --bulk[/bold red]")
        parser.print_help()
        sys.exit(1)

    all_results = {}
    vt_used = []

    if args.bulk:
        console.print(f"[bold cyan]📋 Modo bulk: {args.bulk}[/bold cyan]")
        targets = load_bulk_targets(args.bulk)

        if "error" in targets:
            console.print(f"[red]❌ {targets['error']}[/red]")
            sys.exit(1)

        if targets.get("errors"):
            console.print("[yellow]⚠️  Entradas ignoradas:[/yellow]")
            for e in targets["errors"]:
                console.print(f"  [dim]{e}[/dim]")

        ips = targets.get("ips", [])
        domains = targets.get("domains", [])
        console.print(f"[green]✅ {len(ips)} IPs e {len(domains)} domínios carregados[/green]\n")

        all_results["bulk"] = {}
        for ip in ips:
            all_results["bulk"][ip] = run_analysis("ip", ip, args, vt_used)
        for domain in domains:
            all_results["bulk"][domain] = run_analysis("domain", domain, args, vt_used)

    else:
        if args.ip:
            valid, msg = validate_ip(args.ip)
            if not valid:
                console.print(f"[red]❌ {msg}[/red]")
                sys.exit(1)
            all_results.update(run_analysis("ip", args.ip, args, vt_used))

        if args.domain:
            clean = sanitize_domain(args.domain)
            valid, result = validate_domain(clean)
            if not valid:
                console.print(f"[red]❌ {result}[/red]")
                sys.exit(1)
            all_results.update(run_analysis("domain", result, args, vt_used))

    if args.report:
        path = generate_report(all_results)
        console.print(f"\n[bold green]📄 Relatório JSON:[/bold green] {path}")

    if args.html:
        path = generate_html_report(all_results)
        console.print(f"\n[bold green]🌐 Relatório HTML:[/bold green] {path}")
        console.print(f"[dim]   → Abra no navegador para visualizar[/dim]")

    console.rule("[dim]Análise concluída[/dim]")


if __name__ == "__main__":
    main()
