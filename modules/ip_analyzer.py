"""
IP Analyzer Module
- VirusTotal: reputação, detecções de malware
- AbuseIPDB: score de abuso, categoria, país
"""

import os
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


def get_virustotal_ip(ip: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(f"{VT_BASE}/ip_addresses/{ip}", headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("attributes", {})
        else:
            return {"error": f"HTTP {resp.status_code}: {resp.text}"}
    except Exception as e:
        return {"error": str(e)}


def get_abuseipdb(ip: str, api_key: str) -> dict:
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        resp = requests.get(f"{ABUSE_BASE}/check", headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("data", {})
        else:
            return {"error": f"HTTP {resp.status_code}: {resp.text}"}
    except Exception as e:
        return {"error": str(e)}


ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted"
}


def render_vt_result(ip: str, data: dict):
    if "error" in data:
        console.print(f"[red]VirusTotal: {data['error']}[/red]")
        return

    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    # Reputation score
    reputation = data.get("reputation", "N/A")
    country = data.get("country", "N/A")
    asn = data.get("asn", "N/A")
    owner = data.get("as_owner", "N/A")
    network = data.get("network", "N/A")

    # Risk color
    if malicious > 5:
        risk_color = "bold red"
        risk_label = "🚨 ALTO RISCO"
    elif malicious > 0 or suspicious > 0:
        risk_color = "bold yellow"
        risk_label = "⚠️  SUSPEITO"
    else:
        risk_color = "bold green"
        risk_label = "✅ LIMPO"

    panel_content = f"""[bold]IP:[/bold] {ip}
[bold]País:[/bold] {country}
[bold]ASN:[/bold] {asn} | [bold]Dono:[/bold] {owner}
[bold]Rede:[/bold] {network}
[bold]Reputação VT:[/bold] {reputation}

[bold]Detecções:[/bold]
  [{risk_color}]🔴 Malicioso:[/{risk_color}] {malicious}/{total}
  [yellow]🟡 Suspeito:[/yellow]   {suspicious}/{total}
  [green]🟢 Limpo:[/green]      {harmless}/{total}

[{risk_color}]Veredicto: {risk_label}[/{risk_color}]"""

    console.print(Panel(panel_content, title="[bold cyan]🛡️  VirusTotal[/bold cyan]", box=box.ROUNDED))


def render_abuse_result(ip: str, data: dict):
    if "error" in data:
        console.print(f"[red]AbuseIPDB: {data['error']}[/red]")
        return

    score = data.get("abuseConfidenceScore", 0)
    country = data.get("countryCode", "N/A")
    isp = data.get("isp", "N/A")
    domain = data.get("domain", "N/A")
    total_reports = data.get("totalReports", 0)
    last_reported = data.get("lastReportedAt", "Nunca")
    is_tor = data.get("isTor", False)
    is_public = data.get("isPublic", True)
    usage = data.get("usageType", "N/A")
    categories_raw = data.get("reports", [])

    # Get unique categories from reports
    unique_cats = set()
    for report in categories_raw[:10]:  # limit to last 10 reports
        for cat in report.get("categories", []):
            unique_cats.add(cat)
    
    cat_names = [ABUSE_CATEGORIES.get(c, f"Cat#{c}") for c in unique_cats]

    if score >= 80:
        score_color = "bold red"
        verdict = "🚨 ALTO RISCO"
    elif score >= 40:
        score_color = "bold yellow"
        verdict = "⚠️  MODERADO"
    else:
        score_color = "bold green"
        verdict = "✅ BAIXO RISCO"

    panel_content = f"""[bold]IP:[/bold] {ip}
[bold]País:[/bold] {country} | [bold]ISP:[/bold] {isp}
[bold]Domínio:[/bold] {domain}
[bold]Uso:[/bold] {usage}
[bold]TOR:[/bold] {"[red]SIM[/red]" if is_tor else "[green]NÃO[/green]"}

[bold]Score de Abuso:[/bold] [{score_color}]{score}/100[/{score_color}]
[bold]Total de Reports:[/bold] {total_reports}
[bold]Último Report:[/bold] {last_reported if last_reported else 'N/A'}
[bold]Categorias:[/bold] {', '.join(cat_names) if cat_names else 'Nenhuma'}

[{score_color}]Veredicto: {verdict}[/{score_color}]"""

    console.print(Panel(panel_content, title="[bold magenta]🗄️  AbuseIPDB[/bold magenta]", box=box.ROUNDED))


def analyze_ip(ip: str, vt_key: str = None, abuse_key: str = None) -> dict:
    vt_key = vt_key or os.environ.get("VT_API_KEY")
    abuse_key = abuse_key or os.environ.get("ABUSE_API_KEY")

    results = {"ip": ip}

    # VirusTotal
    if vt_key:
        console.print(f"[dim]🔄 Consultando VirusTotal...[/dim]")
        vt_data = get_virustotal_ip(ip, vt_key)
        render_vt_result(ip, vt_data)
        results["virustotal"] = vt_data
    else:
        console.print("[yellow]⚠️  VT_API_KEY não configurada. Pulando VirusTotal.[/yellow]")
        console.print("[dim]   → Obtenha em: https://www.virustotal.com/gui/my-apikey[/dim]")

    # AbuseIPDB
    if abuse_key:
        console.print(f"[dim]🔄 Consultando AbuseIPDB...[/dim]")
        abuse_data = get_abuseipdb(ip, abuse_key)
        render_abuse_result(ip, abuse_data)
        results["abuseipdb"] = abuse_data
    else:
        console.print("[yellow]⚠️  ABUSE_API_KEY não configurada. Pulando AbuseIPDB.[/yellow]")
        console.print("[dim]   → Obtenha em: https://www.abuseipdb.com/account/api[/dim]")

    return results
