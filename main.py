#!/usr/bin/env python3
"""
Threat Analyzer — by João Carlos Minozzi
Fins educacionais | Vibe coded | SOC Learning
"""

import argparse, os, sys, time, webbrowser

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
from modules.resumo import exibir_resumo
from modules.historico import registrar_resultados
from modules.explicacoes import explicar_ssl
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich import box

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
[/bold cyan][dim]  Threat Intelligence | IP | Domain | SSL | Spoofing
  ⚠️  Fins educacionais | Vibe coded | by João Carlos Minozzi[/dim]
"""

VT_RATE_LIMIT_DELAY = 16


def check_env():
    keys = {"VT_API_KEY": "VirusTotal", "ABUSE_API_KEY": "AbuseIPDB", "URLSCAN_API_KEY": "URLScan.io (opcional)"}
    faltando = [f"{n} ({l})" for n, l in keys.items() if not os.environ.get(n)]
    if faltando:
        console.print(Panel(
            "[yellow]API Keys não configuradas:[/yellow]\n" +
            "\n".join([f"  [dim]→ {k}[/dim]" for k in faltando]) +
            "\n\n[dim]Edite o arquivo .env e adicione suas chaves.[/dim]",
            title="[yellow]⚙️  Configuração incompleta[/yellow]", box=box.SIMPLE
        ))


def check_vt_ratelimit(vt_used, api_key):
    if not api_key: return
    if len(vt_used) > 0 and len(vt_used) % 4 == 0:
        console.print(f"[dim]⏳ Aguardando {VT_RATE_LIMIT_DELAY}s (rate limit VT: 4 req/min)...[/dim]")
        time.sleep(VT_RATE_LIMIT_DELAY)
    vt_used.append(1)


def run_analysis(target_type, target, args, vt_used):
    results = {}
    vt_key = getattr(args, 'vt_key', None) or os.environ.get("VT_API_KEY")
    abuse_key = getattr(args, 'abuse_key', None) or os.environ.get("ABUSE_API_KEY")
    urlscan_key = getattr(args, 'urlscan_key', None) or os.environ.get("URLSCAN_API_KEY")
    no_ssl = getattr(args, 'no_ssl', False)
    no_urlscan = getattr(args, 'no_urlscan', False)

    if target_type == "ip":
        console.rule(f"[bold yellow]🔍 Analisando IP: {target}")
        check_vt_ratelimit(vt_used, vt_key)
        results["ip"] = analyze_ip(target, vt_key=vt_key, abuse_key=abuse_key)

    elif target_type == "domain":
        console.rule(f"[bold yellow]🌐 Analisando Domínio: {target}")
        check_vt_ratelimit(vt_used, vt_key)
        domain_result = analyze_domain(target, vt_key=vt_key)
        if not no_ssl:
            ssl_result = analyze_ssl(target)
            domain_result["ssl"] = ssl_result
            explicar_ssl(ssl_result)
        if not no_urlscan:
            domain_result["urlscan"] = analyze_url(target, api_key=urlscan_key)
        results["domain"] = domain_result

    return results


def finalizar(all_results, gerar_html, gerar_json, auto_open=False):
    exibir_resumo(all_results)
    registrar_resultados(all_results)
    console.print("[dim]📝 Registrado em output/historico.csv[/dim]")

    if gerar_json:
        path = generate_report(all_results)
        console.print(f"\n[bold green]📄 JSON:[/bold green] {path}")

    if gerar_html:
        path = generate_html_report(all_results)
        console.print(f"\n[bold green]🌐 HTML:[/bold green] {path}")
        if auto_open:
            webbrowser.open(f"file:///{os.path.abspath(path)}")
            console.print("[dim]   → Abrindo no navegador...[/dim]")

    console.rule("[dim]✅ Análise concluída[/dim]")


def modo_interativo():
    console.print(Panel(
        "[cyan]Modo interativo![/cyan]\n"
        "[dim]Responda as perguntas para configurar a análise.\n"
        "Pressione Ctrl+C para sair a qualquer momento.[/dim]",
        box=box.SIMPLE
    ))

    class Args:
        vt_key = abuse_key = urlscan_key = None
        no_ssl = no_urlscan = False

    args = Args()
    all_results = {}
    vt_used = []

    console.print("\n[bold]O que quer analisar?[/bold]")
    console.print("  [cyan]1[/cyan] → IP")
    console.print("  [cyan]2[/cyan] → Domínio")
    console.print("  [cyan]3[/cyan] → IP + Domínio")
    console.print("  [cyan]4[/cyan] → Lista de alvos (.txt)")

    escolha = Prompt.ask("Escolha", choices=["1","2","3","4"], default="2")

    if escolha in ["1","3"]:
        ip_input = Prompt.ask("\n🔍 IP para analisar")
        valid, msg = validate_ip(ip_input.strip())
        if not valid:
            console.print(f"[red]❌ {msg}[/red]"); return
        all_results.update(run_analysis("ip", ip_input.strip(), args, vt_used))

    if escolha in ["2","3"]:
        domain_input = Prompt.ask("\n🌐 Domínio (ex: google.com)")
        clean = sanitize_domain(domain_input)
        valid, result = validate_domain(clean)
        if not valid:
            console.print(f"[red]❌ {result}[/red]"); return
        args.no_ssl = not Confirm.ask("\n🔒 Analisar SSL/TLS?", default=True)
        args.no_urlscan = not Confirm.ask("🌐 Verificar no URLScan.io?", default=True)
        all_results.update(run_analysis("domain", result, args, vt_used))

    if escolha == "4":
        filepath = Prompt.ask("\n📋 Caminho do arquivo .txt")
        targets = load_bulk_targets(filepath)
        if "error" in targets:
            console.print(f"[red]❌ {targets['error']}[/red]"); return
        all_results["bulk"] = {}
        for ip in targets.get("ips", []):
            all_results["bulk"][ip] = run_analysis("ip", ip, args, vt_used)
        for domain in targets.get("domains", []):
            all_results["bulk"][domain] = run_analysis("domain", domain, args, vt_used)

    gerar_html = Confirm.ask("\n🌐 Gerar relatório HTML?", default=True)
    gerar_json = Confirm.ask("📄 Gerar relatório JSON?", default=False)
    finalizar(all_results, gerar_html=gerar_html, gerar_json=gerar_json, auto_open=True)


def main():
    console.print(BANNER)
    check_env()

    if len(sys.argv) == 1:
        modo_interativo()
        return

    parser = argparse.ArgumentParser(
        description="Threat Analyzer | Fins educacionais | by João Carlos Minozzi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python main.py                           → Modo interativo
  python main.py --ip 185.220.101.45
  python main.py --domain google.com --html
  python main.py --bulk targets.txt --html
  python main.py --domain evil.com --no-ssl --no-urlscan

⚠️  Use apenas em alvos com autorização.
        """
    )
    tg = parser.add_argument_group("Alvos")
    tg.add_argument("--ip")
    tg.add_argument("--domain")
    tg.add_argument("--bulk", metavar="FILE")

    kg = parser.add_argument_group("API Keys (ou configure no .env)")
    kg.add_argument("--vt-key")
    kg.add_argument("--abuse-key")
    kg.add_argument("--urlscan-key")

    og = parser.add_argument_group("Opções")
    og.add_argument("--no-ssl",     action="store_true")
    og.add_argument("--no-urlscan", action="store_true")
    og.add_argument("--report",     action="store_true", help="Exportar JSON")
    og.add_argument("--html",       action="store_true", help="Exportar e abrir HTML")

    args = parser.parse_args()

    if not args.ip and not args.domain and not args.bulk:
        console.print("[red]❌ Informe --ip, --domain ou --bulk[/red]")
        console.print("[dim]   → Dica: rode sem argumentos para o modo interativo[/dim]")
        sys.exit(1)

    all_results = {}
    vt_used = []

    if args.bulk:
        targets = load_bulk_targets(args.bulk)
        if "error" in targets:
            console.print(f"[red]❌ {targets['error']}[/red]"); sys.exit(1)
        all_results["bulk"] = {}
        for ip in targets.get("ips", []):
            all_results["bulk"][ip] = run_analysis("ip", ip, args, vt_used)
        for domain in targets.get("domains", []):
            all_results["bulk"][domain] = run_analysis("domain", domain, args, vt_used)
    else:
        if args.ip:
            valid, msg = validate_ip(args.ip)
            if not valid:
                console.print(f"[red]❌ {msg}[/red]"); sys.exit(1)
            all_results.update(run_analysis("ip", args.ip, args, vt_used))
        if args.domain:
            clean = sanitize_domain(args.domain)
            valid, result = validate_domain(clean)
            if not valid:
                console.print(f"[red]❌ {result}[/red]"); sys.exit(1)
            all_results.update(run_analysis("domain", result, args, vt_used))

    finalizar(all_results, gerar_html=args.html, gerar_json=args.report, auto_open=args.html)


if __name__ == "__main__":
    main()
