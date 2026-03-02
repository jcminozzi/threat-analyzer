"""
URLScan.io Module
- Submete URL para análise
- Obtém screenshot, IPs, domínios, tecnologias detectadas
- Veredicto de malícia
"""

import os
import time
import requests
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

URLSCAN_BASE = "https://urlscan.io/api/v1"


def submit_scan(url: str, api_key: str, visibility: str = "private") -> dict:
    """Submete uma URL para scan no URLScan.io."""
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json"
    }
    payload = {"url": url, "visibility": visibility}

    try:
        resp = requests.post(f"{URLSCAN_BASE}/scan/", headers=headers, json=payload, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 429:
            return {"error": "Rate limit atingido no URLScan.io — aguarde 1 minuto"}
        elif resp.status_code == 400:
            return {"error": f"URL inválida ou domínio bloqueado: {resp.text}"}
        else:
            return {"error": f"HTTP {resp.status_code}: {resp.text}"}
    except Exception as e:
        return {"error": str(e)}


def get_result(scan_uuid: str, max_wait: int = 30) -> dict:
    """Aguarda e obtém o resultado de um scan pelo UUID."""
    console.print(f"[dim]⏳ Aguardando resultado do URLScan (até {max_wait}s)...[/dim]")

    for attempt in range(max_wait // 5):
        time.sleep(5)
        try:
            resp = requests.get(f"{URLSCAN_BASE}/result/{scan_uuid}/", timeout=10)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                continue  # Ainda processando
        except Exception:
            continue

    return {"error": "Timeout aguardando resultado — tente buscar manualmente no urlscan.io"}


def search_existing(domain: str) -> dict:
    """Busca scans anteriores de um domínio (sem precisar de API key)."""
    try:
        resp = requests.get(
            f"{URLSCAN_BASE}/search/",
            params={"q": f"domain:{domain}", "size": 5},
            timeout=10
        )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def render_urlscan(domain: str, data: dict, scan_url: str = None):
    """Renderiza resultados do URLScan.io."""
    if "error" in data:
        console.print(Panel(
            f"[yellow]⚠️  {data['error']}[/yellow]",
            title="[bold magenta]🌐 URLScan.io[/bold magenta]",
            box=box.ROUNDED
        ))
        return

    # Resultado de scan completo
    if "page" in data:
        page = data.get("page", {})
        verdicts = data.get("verdicts", {})
        lists = data.get("lists", {})
        stats = data.get("stats", {})
        meta = data.get("meta", {})
        task = data.get("task", {})

        overall = verdicts.get("overall", {})
        malicious = overall.get("malicious", False)
        score = overall.get("score", 0)
        brands = overall.get("brands", [])
        tags = overall.get("tags", [])

        verdict_str = "[bold red]🚨 MALICIOSO[/bold red]" if malicious else "[green]✅ LIMPO[/green]"

        ips = lists.get("ips", [])[:5]
        domains = lists.get("domains", [])[:5]
        urls_count = stats.get("uniqURLs", 0)
        screenshot = task.get("screenshotURL", "")

        content = f"""[bold]Domínio:[/bold] {page.get('domain', domain)}
[bold]URL Final:[/bold] {page.get('url', 'N/A')[:80]}
[bold]IP Resolvido:[/bold] {page.get('ip', 'N/A')}
[bold]País:[/bold] {page.get('country', 'N/A')}
[bold]Servidor:[/bold] {page.get('server', 'N/A')}

[bold]Score:[/bold] {score}/100
[bold]Veredicto:[/bold] {verdict_str}
[bold]IPs contactados:[/bold] {', '.join(ips) or 'N/A'}
[bold]Domínios contactados:[/bold] {', '.join(domains) or 'N/A'}
[bold]URLs únicas:[/bold] {urls_count}"""

        if brands:
            content += f"\n[bold red]⚠️  Marcas detectadas:[/bold red] {', '.join(brands)} (possível phishing)"
        if tags:
            content += f"\n[bold]Tags:[/bold] {', '.join(tags)}"
        if screenshot:
            content += f"\n[bold]Screenshot:[/bold] {screenshot}"
        if scan_url:
            content += f"\n[bold]Relatório completo:[/bold] {scan_url}"

    # Resultado de busca histórica
    elif "results" in data:
        results = data.get("results", [])
        if not results:
            content = f"Nenhum scan anterior encontrado para {domain}"
        else:
            content = f"[bold]{len(results)} scans anteriores encontrados:[/bold]\n"
            for r in results[:3]:
                task = r.get("task", {})
                verdicts = r.get("verdicts", {}).get("overall", {})
                malicious = verdicts.get("malicious", False)
                icon = "🚨" if malicious else "✅"
                content += f"\n{icon} {task.get('time', 'N/A')[:10]} — {task.get('url', 'N/A')[:60]}"
                content += f"\n   [dim]→ https://urlscan.io/result/{r.get('_id', '')}[/dim]"
    else:
        content = str(data)

    console.print(Panel(content, title="[bold magenta]🌐 URLScan.io[/bold magenta]", box=box.ROUNDED))


def analyze_url(target: str, api_key: str = None) -> dict:
    """
    Analisa uma URL/domínio no URLScan.io.
    Se tiver API key, faz novo scan. Senão, busca histórico.
    """
    api_key = api_key or os.environ.get("URLSCAN_API_KEY")

    # Garante que é uma URL válida
    if not target.startswith("http"):
        target_url = f"https://{target}"
    else:
        target_url = target

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    if api_key:
        console.print(f"[dim]🔄 Submetendo para URLScan.io (privado)...[/dim]")
        submit = submit_scan(target_url, api_key, visibility="private")

        if "error" in submit:
            render_urlscan(domain, submit)
            return submit

        scan_uuid = submit.get("uuid", "")
        scan_url = submit.get("result", "")

        result = get_result(scan_uuid)
        render_urlscan(domain, result, scan_url)
        return result
    else:
        console.print(f"[dim]🔄 Buscando scans anteriores no URLScan.io...[/dim]")
        console.print("[yellow]⚠️  URLSCAN_API_KEY não configurada — usando histórico público.[/yellow]")
        console.print("[dim]   → Obtenha em: https://urlscan.io/user/signup[/dim]")
        result = search_existing(domain)
        render_urlscan(domain, result)
        return result
