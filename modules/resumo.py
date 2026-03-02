"""
Módulo de Resumo Final
========================
Após todas as análises, exibe uma tabela consolidada com todos os veredictos.
Facilita a leitura rápida dos resultados, especialmente em análises bulk.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

RISK_COLORS = {
    "CRÍTICO":     "bold red",
    "ALTO":        "red",
    "MÉDIO":       "yellow",
    "BAIXO":       "green",
    "DESCONHECIDO": "dim",
}

RISK_ICONS = {
    "CRÍTICO":     "🚨",
    "ALTO":        "🔴",
    "MÉDIO":       "⚠️ ",
    "BAIXO":       "✅",
    "DESCONHECIDO": "❓",
}


def _extrair_linhas(results: dict) -> list[dict]:
    """
    Percorre os resultados e extrai uma linha de resumo para cada alvo analisado.
    Retorna uma lista de dicts com: tipo, alvo, modulo, veredicto, risco, detalhe.
    """
    linhas = []

    def processar_ip(ip_data: dict):
        ip = ip_data.get("ip", "?")

        # VirusTotal
        vt = ip_data.get("virustotal", {})
        if vt and "error" not in vt:
            stats = vt.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            risco = "CRÍTICO" if mal > 10 else "ALTO" if mal > 3 else "MÉDIO" if mal > 0 else "BAIXO"
            linhas.append({
                "tipo": "IP", "alvo": ip, "modulo": "VirusTotal",
                "veredicto": f"{mal}/{total} detecções",
                "risco": risco,
                "detalhe": vt.get("as_owner", "N/A"),
            })

        # AbuseIPDB
        abuse = ip_data.get("abuseipdb", {})
        if abuse and "error" not in abuse:
            score = abuse.get("abuseConfidenceScore", 0)
            is_tor = abuse.get("isTor", False)
            risco = "CRÍTICO" if score >= 80 else "ALTO" if score >= 50 else "MÉDIO" if score >= 20 else "BAIXO"
            linhas.append({
                "tipo": "IP", "alvo": ip, "modulo": "AbuseIPDB",
                "veredicto": f"Score {score}/100" + (" | TOR" if is_tor else ""),
                "risco": risco,
                "detalhe": abuse.get("isp", "N/A"),
            })

    def processar_domain(domain_data: dict):
        domain = domain_data.get("domain", "?")

        # Spoofing
        spoofing = domain_data.get("spoofing", {})
        if spoofing:
            overall = spoofing.get("overall_risk", {})
            risco = overall.get("level", "DESCONHECIDO")
            score = overall.get("score", 0)
            linhas.append({
                "tipo": "Domínio", "alvo": domain, "modulo": "Spoofing",
                "veredicto": overall.get("verdict", "N/A").replace("🔴 ", "").replace("✅ ", "").replace("⚠️  ", "").replace("🚨 ", ""),
                "risco": risco,
                "detalhe": f"Score {score}/85",
            })

        # SSL
        ssl = domain_data.get("ssl", {})
        if ssl and "error" not in ssl:
            expires = ssl.get("expires_in_days")
            if ssl.get("is_expired"):
                risco = "CRÍTICO"
                veredicto = "Certificado EXPIRADO"
            elif expires and expires <= 14:
                risco = "ALTO"
                veredicto = f"Expira em {expires} dias"
            elif expires and expires <= 30:
                risco = "MÉDIO"
                veredicto = f"Expira em {expires} dias"
            else:
                risco = "BAIXO"
                veredicto = f"Válido ({expires}d restantes)" if expires else "Válido"

            alerts = ssl.get("alerts", [])
            tls_alert = next((a for a in alerts if "TLS" in a[1] or "insegur" in a[1]), None)
            if tls_alert and risco == "BAIXO":
                risco = tls_alert[0]
                veredicto = tls_alert[1]

            linhas.append({
                "tipo": "Domínio", "alvo": domain, "modulo": "SSL/TLS",
                "veredicto": veredicto,
                "risco": risco,
                "detalhe": f"TLS: {ssl.get('tls_version','N/A')} | Emissor: {ssl.get('issuer_org','N/A')[:30]}",
            })

        # VT Domínio
        vt = domain_data.get("virustotal", {})
        if vt and "error" not in vt:
            stats = vt.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            risco = "ALTO" if mal > 3 else "MÉDIO" if mal > 0 else "BAIXO"
            linhas.append({
                "tipo": "Domínio", "alvo": domain, "modulo": "VirusTotal",
                "veredicto": f"{mal}/{total} detecções",
                "risco": risco,
                "detalhe": f"Reputação: {vt.get('reputation', 'N/A')}",
            })

    # Navega pelos resultados
    if "ip" in results:
        processar_ip(results["ip"])
    if "domain" in results:
        processar_domain(results["domain"])
    if "bulk" in results:
        for data in results["bulk"].values():
            if "ip" in data:
                processar_ip(data["ip"])
            if "domain" in data:
                processar_domain(data["domain"])

    return linhas


def exibir_resumo(results: dict):
    """Exibe a tabela de resumo consolidado no terminal."""
    linhas = _extrair_linhas(results)

    if not linhas:
        return

    table = Table(
        title="📊 Resumo Consolidado da Análise",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold cyan",
    )

    table.add_column("Tipo",     style="dim",        width=8)
    table.add_column("Alvo",     style="white",       width=22)
    table.add_column("Módulo",   style="cyan",        width=12)
    table.add_column("Veredicto",                     width=30)
    table.add_column("Risco",                         width=10)
    table.add_column("Detalhe",  style="dim",         width=35)

    # Ordena por risco (mais grave primeiro)
    ordem = {"CRÍTICO": 0, "ALTO": 1, "MÉDIO": 2, "BAIXO": 3, "DESCONHECIDO": 4}
    linhas_sorted = sorted(linhas, key=lambda x: ordem.get(x["risco"], 99))

    for linha in linhas_sorted:
        risco = linha["risco"]
        cor = RISK_COLORS.get(risco, "white")
        icone = RISK_ICONS.get(risco, "")
        table.add_row(
            linha["tipo"],
            linha["alvo"],
            linha["modulo"],
            linha["veredicto"],
            f"[{cor}]{icone} {risco}[/{cor}]",
            linha["detalhe"],
        )

    console.print()
    console.print(table)

    # Contagem por risco
    contagem = {}
    for l in linhas:
        contagem[l["risco"]] = contagem.get(l["risco"], 0) + 1

    resumo_parts = []
    for nivel in ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO"]:
        if nivel in contagem:
            cor = RISK_COLORS[nivel]
            icone = RISK_ICONS[nivel]
            resumo_parts.append(f"[{cor}]{icone} {contagem[nivel]} {nivel}[/{cor}]")

    if resumo_parts:
        console.print(Panel(
            "  ".join(resumo_parts),
            title="[bold]Contagem por Nível de Risco[/bold]",
            box=box.SIMPLE
        ))
