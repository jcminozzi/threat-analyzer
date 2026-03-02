"""
Domain Analyzer Module
- DNS Records (A, MX, NS, TXT)
- SPF, DKIM, DMARC (Anti-Spoofing)
- WHOIS info
- VirusTotal domain reputation
"""

import os
import re
import socket
import dns.resolver
import whois
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from datetime import datetime

console = Console()

VT_BASE = "https://www.virustotal.com/api/v3"


# ─── DNS ───────────────────────────────────────────────────────────────────────

def get_dns_records(domain: str) -> dict:
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []
    
    return records


# ─── ANTI-SPOOFING ─────────────────────────────────────────────────────────────

def check_spf(txt_records: list) -> dict:
    """Verifica presença e validade do registro SPF."""
    spf = None
    for record in txt_records:
        if record.strip('"').startswith("v=spf1"):
            spf = record.strip('"')
            break
    
    if not spf:
        return {
            "found": False,
            "record": None,
            "status": "AUSENTE",
            "risk": "ALTO",
            "details": "Sem SPF: qualquer servidor pode enviar e-mails como este domínio"
        }
    
    # Análise do SPF
    issues = []
    
    if "+all" in spf:
        issues.append("'+all' permite QUALQUER servidor enviar — extremamente perigoso")
        risk = "CRÍTICO"
    elif "?all" in spf:
        issues.append("'?all' é neutro — não bloqueia spoofing efetivamente")
        risk = "ALTO"
    elif "~all" in spf:
        issues.append("'~all' (softfail) — recomendado usar '-all' para bloqueio total")
        risk = "MÉDIO"
    elif "-all" in spf:
        risk = "BAIXO"
    else:
        risk = "MÉDIO"
        issues.append("Sem mecanismo 'all' definido")

    # Muitos includes podem causar lookups excessivos (max 10)
    includes = spf.count("include:")
    if includes > 8:
        issues.append(f"{includes} 'include:' encontrados — pode exceder limite de 10 DNS lookups")

    return {
        "found": True,
        "record": spf,
        "status": "OK" if not issues else "ATENÇÃO",
        "risk": risk,
        "details": issues if issues else ["SPF configurado corretamente com -all"]
    }


def check_dmarc(domain: str) -> dict:
    """Verifica presença e configuração do registro DMARC."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        dmarc_record = None
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith("v=DMARC1"):
                dmarc_record = txt
                break
        
        if not dmarc_record:
            raise Exception("No DMARC record")
        
        # Parse policy
        policy_match = re.search(r'p=(\w+)', dmarc_record)
        policy = policy_match.group(1) if policy_match else "none"

        sp_match = re.search(r'sp=(\w+)', dmarc_record)
        sp_policy = sp_match.group(1) if sp_match else None

        pct_match = re.search(r'pct=(\d+)', dmarc_record)
        pct = int(pct_match.group(1)) if pct_match else 100

        rua_match = re.search(r'rua=([^;]+)', dmarc_record)
        rua = rua_match.group(1) if rua_match else None

        issues = []
        if policy == "none":
            risk = "ALTO"
            issues.append("p=none: DMARC só monitora, não bloqueia spoofing")
        elif policy == "quarantine":
            risk = "MÉDIO"
            issues.append("p=quarantine: e-mails suspeitos vão para spam (não são rejeitados)")
        else:
            risk = "BAIXO"

        if pct < 100:
            issues.append(f"pct={pct}: DMARC aplicado em apenas {pct}% dos e-mails")

        if not rua:
            issues.append("Sem rua= configurado: você não receberá relatórios de abuso")

        return {
            "found": True,
            "record": dmarc_record,
            "policy": policy,
            "subdomain_policy": sp_policy,
            "percentage": pct,
            "reporting": rua,
            "status": "OK" if risk == "BAIXO" else "ATENÇÃO",
            "risk": risk,
            "details": issues if issues else ["DMARC configurado com política de rejeição"]
        }

    except Exception:
        return {
            "found": False,
            "record": None,
            "policy": None,
            "status": "AUSENTE",
            "risk": "ALTO",
            "details": ["Sem DMARC: e-mails fraudulentos não serão bloqueados pelo destinatário"]
        }


def check_dkim(domain: str, selectors: list = None) -> dict:
    """Testa seletores DKIM comuns."""
    if not selectors:
        selectors = [
            "default", "google", "mail", "email", "selector1",
            "selector2", "k1", "dkim", "smtp", "mta", "s1", "s2"
        ]

    found_selectors = []
    for sel in selectors:
        try:
            answers = dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", lifetime=3)
            for r in answers:
                txt = str(r).strip('"')
                if "v=DKIM1" in txt or "p=" in txt:
                    found_selectors.append({"selector": sel, "record": txt[:80] + "..."})
                    break
        except Exception:
            continue

    if found_selectors:
        return {
            "found": True,
            "selectors": found_selectors,
            "status": "OK",
            "risk": "BAIXO",
            "details": [f"Seletor(es) encontrado(s): {', '.join([s['selector'] for s in found_selectors])}"]
        }
    else:
        return {
            "found": False,
            "selectors": [],
            "status": "NÃO DETECTADO",
            "risk": "MÉDIO",
            "details": [
                "Nenhum seletor DKIM comum encontrado",
                "DKIM pode existir com seletor customizado não testado",
                f"Seletores testados: {', '.join(selectors)}"
            ]
        }


def check_bimi(domain: str) -> dict:
    """Verifica BIMI (Brand Indicators for Message Identification)."""
    try:
        answers = dns.resolver.resolve(f"default._bimi.{domain}", "TXT", lifetime=3)
        for r in answers:
            txt = str(r).strip('"')
            if "v=BIMI1" in txt:
                return {"found": True, "record": txt}
    except Exception:
        pass
    return {"found": False}


# ─── WHOIS ─────────────────────────────────────────────────────────────────────

def get_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        expiration = w.expiration_date
        
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiration, list):
            expiration = expiration[0]

        age_days = None
        if creation:
            age_days = (datetime.now() - creation).days

        return {
            "registrar": w.registrar or "N/A",
            "creation_date": str(creation)[:10] if creation else "N/A",
            "expiration_date": str(expiration)[:10] if expiration else "N/A",
            "age_days": age_days,
            "name_servers": w.name_servers or [],
            "status": w.status,
            "country": w.country or "N/A",
            "org": w.org or "N/A"
        }
    except Exception as e:
        return {"error": str(e)}


# ─── VIRUSTOTAL DOMAIN ─────────────────────────────────────────────────────────

def get_vt_domain(domain: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(f"{VT_BASE}/domains/{domain}", headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("attributes", {})
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ─── SPOOFING SCORE ────────────────────────────────────────────────────────────

def calculate_spoofing_risk(spf: dict, dmarc: dict, dkim: dict) -> dict:
    """Calcula score geral de risco de spoofing."""
    score = 0  # menor = mais seguro
    
    risk_weights = {"CRÍTICO": 40, "ALTO": 30, "MÉDIO": 15, "BAIXO": 0}
    
    score += risk_weights.get(spf["risk"], 30)
    score += risk_weights.get(dmarc["risk"], 30)
    score += risk_weights.get(dkim["risk"], 15)

    if score == 0:
        level = "BAIXO"
        color = "green"
        verdict = "✅ Domínio bem protegido contra spoofing"
    elif score <= 25:
        level = "MÉDIO"
        color = "yellow"
        verdict = "⚠️  Proteção parcial — melhorias recomendadas"
    elif score <= 55:
        level = "ALTO"
        color = "orange3"
        verdict = "🔴 Vulnerável a spoofing de e-mail"
    else:
        level = "CRÍTICO"
        color = "bold red"
        verdict = "🚨 Domínio facilmente utilizável para phishing/spoofing"

    return {"score": score, "level": level, "color": color, "verdict": verdict}


# ─── RENDER ────────────────────────────────────────────────────────────────────

def render_dns(domain: str, records: dict):
    table = Table(title=f"DNS Records — {domain}", box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("Tipo", style="bold cyan", width=8)
    table.add_column("Valor", style="white")

    for rtype, values in records.items():
        if values:
            for v in values:
                table.add_row(rtype, v)

    console.print(table)


def render_whois(data: dict):
    if "error" in data:
        console.print(f"[red]WHOIS: {data['error']}[/red]")
        return

    age = data.get("age_days")
    age_warning = ""
    if age and age < 30:
        age_warning = f" [bold red]⚠️ DOMÍNIO RECENTE ({age} dias)[/bold red]"
    elif age:
        age_warning = f" [dim]({age} dias)[/dim]"

    content = f"""[bold]Registrador:[/bold] {data['registrar']}
[bold]Criado em:[/bold] {data['creation_date']}{age_warning}
[bold]Expira em:[/bold] {data['expiration_date']}
[bold]País:[/bold] {data['country']}
[bold]Organização:[/bold] {data['org']}
[bold]Name Servers:[/bold] {', '.join(list(data['name_servers'])[:3]) if data['name_servers'] else 'N/A'}"""

    console.print(Panel(content, title="[bold blue]📋 WHOIS[/bold blue]", box=box.ROUNDED))


def render_spoofing_analysis(spf, dmarc, dkim, bimi, overall):
    risk_colors = {"BAIXO": "green", "MÉDIO": "yellow", "ALTO": "red", "CRÍTICO": "bold red"}

    def status_icon(s):
        icons = {"OK": "[green]✅[/green]", "ATENÇÃO": "[yellow]⚠️[/yellow]",
                 "AUSENTE": "[red]❌[/red]", "NÃO DETECTADO": "[yellow]❓[/yellow]"}
        return icons.get(s, "❓")

    # Tabela de resumo
    table = Table(title="Análise Anti-Spoofing", box=box.ROUNDED, show_lines=True)
    table.add_column("Protocolo", style="bold", width=10)
    table.add_column("Status", width=14)
    table.add_column("Risco", width=10)
    table.add_column("Detalhe", width=50)

    for proto, data in [("SPF", spf), ("DMARC", dmarc), ("DKIM", dkim)]:
        risk_color = risk_colors.get(data["risk"], "white")
        details = data["details"]
        detail_str = details[0] if isinstance(details, list) and details else str(details)
        table.add_row(
            proto,
            f"{status_icon(data['status'])} {data['status']}",
            f"[{risk_color}]{data['risk']}[/{risk_color}]",
            detail_str
        )

    # BIMI
    bimi_status = "[green]✅ Presente[/green]" if bimi["found"] else "[dim]Não configurado[/dim]"
    table.add_row("BIMI", bimi_status, "[dim]—[/dim]", "Indicador visual de marca (opcional)")

    console.print(table)

    # Registros encontrados
    for proto, data in [("SPF", spf), ("DMARC", dmarc)]:
        if data.get("record"):
            console.print(f"[dim]{proto}:[/dim] [italic]{data['record'][:100]}[/italic]")

    if dkim["found"]:
        for sel in dkim["selectors"]:
            console.print(f"[dim]DKIM [{sel['selector']}]:[/dim] [italic]{sel['record'][:80]}[/italic]")

    # Issues detalhadas
    all_issues = []
    for data in [spf, dmarc, dkim]:
        if isinstance(data.get("details"), list):
            for d in data["details"]:
                if data["risk"] not in ["BAIXO"]:
                    all_issues.append((data["risk"], d))

    if all_issues:
        console.print("\n[bold yellow]⚠️  Problemas encontrados:[/bold yellow]")
        for risk, issue in all_issues:
            c = risk_colors.get(risk, "white")
            console.print(f"  [{c}][{risk}][/{c}] {issue}")

    # Veredicto final
    console.print(Panel(
        f"[{overall['color']}]{overall['verdict']}[/{overall['color']}]\n"
        f"[dim]Score de risco: {overall['score']}/85[/dim]",
        title="[bold]🎯 Veredicto Spoofing[/bold]",
        box=box.HEAVY
    ))


def render_vt_domain(domain: str, data: dict):
    if "error" in data:
        console.print(f"[red]VirusTotal Domain: {data['error']}[/red]")
        return

    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    
    cats = data.get("categories", {})
    cat_str = ", ".join(list(cats.values())[:5]) if cats else "N/A"
    reputation = data.get("reputation", "N/A")

    if malicious > 3:
        verdict = "[bold red]🚨 MALICIOSO[/bold red]"
    elif malicious > 0 or suspicious > 0:
        verdict = "[yellow]⚠️  SUSPEITO[/yellow]"
    else:
        verdict = "[green]✅ LIMPO[/green]"

    content = f"""[bold]Domínio:[/bold] {domain}
[bold]Reputação:[/bold] {reputation}
[bold]Detecções:[/bold] {malicious} maliciosas, {suspicious} suspeitas de {total} engines
[bold]Categorias:[/bold] {cat_str}
[bold]Veredicto:[/bold] {verdict}"""

    console.print(Panel(content, title="[bold cyan]🛡️  VirusTotal Domain[/bold cyan]", box=box.ROUNDED))


# ─── MAIN ──────────────────────────────────────────────────────────────────────

def analyze_domain(domain: str, vt_key: str = None) -> dict:
    vt_key = vt_key or os.environ.get("VT_API_KEY")
    results = {"domain": domain}

    # DNS
    console.print(f"[dim]🔄 Resolvendo DNS...[/dim]")
    dns_records = get_dns_records(domain)
    render_dns(domain, dns_records)
    results["dns"] = dns_records

    # WHOIS
    console.print(f"[dim]🔄 Consultando WHOIS...[/dim]")
    whois_data = get_whois(domain)
    render_whois(whois_data)
    results["whois"] = whois_data

    # Anti-Spoofing
    console.print(f"[dim]🔄 Verificando proteções anti-spoofing...[/dim]")
    txt_records = dns_records.get("TXT", [])
    spf = check_spf(txt_records)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)
    bimi = check_bimi(domain)
    overall = calculate_spoofing_risk(spf, dmarc, dkim)

    render_spoofing_analysis(spf, dmarc, dkim, bimi, overall)
    results["spoofing"] = {
        "spf": spf, "dmarc": dmarc,
        "dkim": dkim, "bimi": bimi,
        "overall_risk": overall
    }

    # VirusTotal
    if vt_key:
        console.print(f"[dim]🔄 Consultando VirusTotal...[/dim]")
        vt_data = get_vt_domain(domain, vt_key)
        render_vt_domain(domain, vt_data)
        results["virustotal"] = vt_data
    else:
        console.print("[yellow]⚠️  VT_API_KEY não configurada. Pulando VirusTotal.[/yellow]")

    return results
