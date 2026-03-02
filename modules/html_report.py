"""
HTML Report Generator
Gera relatório visual em HTML com os resultados da análise.
"""

import json
import os
from datetime import datetime


RISK_COLORS = {
    "CRÍTICO": "#dc2626",
    "ALTO": "#ea580c",
    "MÉDIO": "#ca8a04",
    "BAIXO": "#16a34a",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Threat Analyzer Report — {target}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; }}
  .header {{ background: linear-gradient(135deg, #1e3a5f, #0f172a); padding: 2rem; border-bottom: 1px solid #334155; }}
  .header h1 {{ font-size: 1.8rem; color: #38bdf8; }}
  .header .meta {{ color: #94a3b8; font-size: 0.85rem; margin-top: 0.5rem; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
  .section {{ background: #1e293b; border: 1px solid #334155; border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .section h2 {{ color: #38bdf8; font-size: 1.1rem; margin-bottom: 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }}
  .badge-red {{ background: #7f1d1d; color: #fca5a5; }}
  .badge-orange {{ background: #7c2d12; color: #fdba74; }}
  .badge-yellow {{ background: #713f12; color: #fde68a; }}
  .badge-green {{ background: #14532d; color: #86efac; }}
  .badge-gray {{ background: #1e293b; color: #94a3b8; border: 1px solid #475569; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th {{ text-align: left; color: #94a3b8; font-weight: 600; padding: 0.5rem 0.75rem; border-bottom: 1px solid #334155; }}
  td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid #1e293b; vertical-align: top; word-break: break-all; }}
  tr:hover td {{ background: #0f172a; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-top: 0.5rem; }}
  .stat-card {{ background: #0f172a; border-radius: 0.5rem; padding: 1rem; text-align: center; }}
  .stat-card .value {{ font-size: 1.8rem; font-weight: 700; }}
  .stat-card .label {{ color: #94a3b8; font-size: 0.75rem; margin-top: 0.25rem; }}
  .alert-item {{ padding: 0.4rem 0.75rem; border-radius: 0.4rem; margin-bottom: 0.4rem; font-size: 0.85rem; }}
  .alert-critico {{ background: #450a0a; border-left: 3px solid #dc2626; }}
  .alert-alto {{ background: #431407; border-left: 3px solid #ea580c; }}
  .alert-medio {{ background: #422006; border-left: 3px solid #ca8a04; }}
  .kv {{ display: flex; gap: 0.5rem; margin-bottom: 0.4rem; font-size: 0.9rem; }}
  .kv .key {{ color: #94a3b8; min-width: 160px; flex-shrink: 0; }}
  .kv .val {{ color: #e2e8f0; }}
  .verdict-box {{ padding: 1rem 1.5rem; border-radius: 0.5rem; font-weight: 600; font-size: 1rem; margin-top: 1rem; }}
  .verdict-critico {{ background: #450a0a; border: 1px solid #dc2626; color: #fca5a5; }}
  .verdict-alto {{ background: #431407; border: 1px solid #ea580c; color: #fdba74; }}
  .verdict-medio {{ background: #422006; border: 1px solid #ca8a04; color: #fde68a; }}
  .verdict-baixo {{ background: #052e16; border: 1px solid #16a34a; color: #86efac; }}
  .tag {{ display: inline-block; background: #0f172a; border: 1px solid #475569; color: #94a3b8; padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.75rem; margin: 0.1rem; }}
  .footer {{ text-align: center; color: #475569; font-size: 0.8rem; padding: 2rem; }}
</style>
</head>
<body>
<div class="header">
  <div class="container">
    <h1>🛡️ Threat Analyzer Report</h1>
    <div class="meta">
      Gerado em: {generated_at} &nbsp;|&nbsp; Alvo: <strong style="color:#e2e8f0">{target}</strong> &nbsp;|&nbsp; Por: {author}
    </div>
  </div>
</div>
<div class="container">
  {content}
</div>
<div class="footer">Threat Analyzer — {author} | Uso exclusivo para fins educacionais e SOC</div>
</body>
</html>"""


def _badge(text, color="gray"):
    classes = {"red": "badge-red", "orange": "badge-orange", "yellow": "badge-yellow",
               "green": "badge-green", "gray": "badge-gray"}
    cls = classes.get(color, "badge-gray")
    return f'<span class="badge {cls}">{text}</span>'


def _kv(key, value):
    return f'<div class="kv"><span class="key">{key}</span><span class="val">{value}</span></div>'


def _risk_badge(risk):
    colors = {"CRÍTICO": "red", "ALTO": "orange", "MÉDIO": "yellow", "BAIXO": "green"}
    return _badge(risk, colors.get(risk, "gray"))


def _verdict_box(text, level):
    cls = {"CRÍTICO": "critico", "ALTO": "alto", "MÉDIO": "medio", "BAIXO": "baixo"}.get(level, "baixo")
    return f'<div class="verdict-box verdict-{cls}">{text}</div>'


def render_ip_section(ip_data: dict) -> str:
    ip = ip_data.get("ip", "N/A")
    html = f'<div class="section"><h2>🔍 Análise de IP: {ip}</h2>'

    # VirusTotal
    vt = ip_data.get("virustotal", {})
    if vt and "error" not in vt:
        stats = vt.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        risk = "CRÍTICO" if malicious > 10 else "ALTO" if malicious > 3 else "MÉDIO" if malicious > 0 else "BAIXO"

        html += '<h3 style="color:#94a3b8; margin: 1rem 0 0.5rem">VirusTotal</h3>'
        html += '<div class="stat-grid">'
        html += f'<div class="stat-card"><div class="value" style="color:#dc2626">{malicious}</div><div class="label">Malicioso</div></div>'
        html += f'<div class="stat-card"><div class="value" style="color:#ca8a04">{suspicious}</div><div class="label">Suspeito</div></div>'
        html += f'<div class="stat-card"><div class="value" style="color:#16a34a">{harmless}</div><div class="label">Limpo</div></div>'
        html += f'<div class="stat-card"><div class="value" style="color:#475569">{total}</div><div class="label">Total engines</div></div>'
        html += '</div>'
        html += _kv("País", vt.get("country", "N/A"))
        html += _kv("ASN", str(vt.get("asn", "N/A")))
        html += _kv("Dono", vt.get("as_owner", "N/A"))
        html += _kv("Reputação", str(vt.get("reputation", "N/A")))
        tags = vt.get("tags", [])
        if tags:
            html += _kv("Tags", "".join([f'<span class="tag">{t}</span>' for t in tags]))
        html += _verdict_box(f"VirusTotal: {malicious}/{total} detecções — Risco {risk}", risk)

    # AbuseIPDB
    abuse = ip_data.get("abuseipdb", {})
    if abuse and "error" not in abuse:
        score = abuse.get("abuseConfidenceScore", 0)
        risk = "CRÍTICO" if score >= 80 else "ALTO" if score >= 50 else "MÉDIO" if score >= 20 else "BAIXO"

        html += '<h3 style="color:#94a3b8; margin: 1rem 0 0.5rem">AbuseIPDB</h3>'
        html += _kv("Score de Abuso", f'<strong style="color:{"#dc2626" if score >= 80 else "#ca8a04" if score >= 40 else "#16a34a"}">{score}/100</strong>')
        html += _kv("Total de Reports", str(abuse.get("totalReports", 0)))
        html += _kv("Usuários distintos", str(abuse.get("numDistinctUsers", 0)))
        html += _kv("Último report", abuse.get("lastReportedAt", "N/A")[:10] if abuse.get("lastReportedAt") else "N/A")
        html += _kv("TOR", '<span style="color:#dc2626">SIM</span>' if abuse.get("isTor") else '<span style="color:#16a34a">NÃO</span>')
        html += _kv("ISP", abuse.get("isp", "N/A"))
        html += _verdict_box(f"AbuseIPDB: Score {score}/100 — Risco {risk}", risk)

    html += '</div>'
    return html


def render_domain_section(domain_data: dict) -> str:
    domain = domain_data.get("domain", "N/A")
    html = f'<div class="section"><h2>🌐 Análise de Domínio: {domain}</h2>'

    # WHOIS
    whois = domain_data.get("whois", {})
    if whois and "error" not in whois:
        html += '<h3 style="color:#94a3b8; margin: 0.5rem 0">WHOIS</h3>'
        html += _kv("Registrador", whois.get("registrar", "N/A"))
        html += _kv("Criado em", whois.get("creation_date", "N/A"))
        html += _kv("Expira em", whois.get("expiration_date", "N/A"))
        age = whois.get("age_days")
        if age and age < 30:
            html += _kv("Idade", f'<span style="color:#dc2626">⚠️ {age} dias — DOMÍNIO RECENTE</span>')
        elif age:
            html += _kv("Idade", f"{age} dias")

    # DNS
    dns = domain_data.get("dns", {})
    if dns:
        html += '<h3 style="color:#94a3b8; margin: 1rem 0 0.5rem">DNS Records</h3>'
        html += '<table><tr><th>Tipo</th><th>Valor</th></tr>'
        for rtype, values in dns.items():
            for v in (values or []):
                html += f'<tr><td><span class="tag">{rtype}</span></td><td>{v}</td></tr>'
        html += '</table>'

    # Spoofing
    spoofing = domain_data.get("spoofing", {})
    if spoofing:
        overall = spoofing.get("overall_risk", {})
        html += '<h3 style="color:#94a3b8; margin: 1rem 0 0.5rem">Análise Anti-Spoofing</h3>'
        html += '<table><tr><th>Protocolo</th><th>Status</th><th>Risco</th><th>Detalhe</th></tr>'
        for proto in ["spf", "dmarc", "dkim"]:
            d = spoofing.get(proto, {})
            status_icon = "✅" if d.get("status") == "OK" else "❌" if d.get("status") == "AUSENTE" else "⚠️"
            details = d.get("details", [])
            detail_str = details[0] if isinstance(details, list) and details else ""
            html += f'<tr><td><strong>{proto.upper()}</strong></td><td>{status_icon} {d.get("status","N/A")}</td><td>{_risk_badge(d.get("risk",""))}</td><td>{detail_str}</td></tr>'
        html += '</table>'
        level = overall.get("level", "BAIXO")
        html += _verdict_box(f"🎯 {overall.get('verdict', 'N/A')} — Score: {overall.get('score', 0)}/85", level)

    # SSL
    ssl_data = domain_data.get("ssl", {})
    if ssl_data and "error" not in ssl_data:
        html += '<h3 style="color:#94a3b8; margin: 1rem 0 0.5rem">SSL/TLS</h3>'
        html += _kv("Certificado para", ssl_data.get("subject_cn", "N/A"))
        html += _kv("Emissor", f'{ssl_data.get("issuer_cn","N/A")} ({ssl_data.get("issuer_org","N/A")})')
        html += _kv("Válido até", ssl_data.get("not_after", "N/A"))
        expires = ssl_data.get("expires_in_days")
        if ssl_data.get("is_expired"):
            html += _kv("Status", '<span style="color:#dc2626">EXPIRADO</span>')
        elif expires:
            color = "#dc2626" if expires <= 14 else "#ca8a04" if expires <= 30 else "#16a34a"
            html += _kv("Expira em", f'<span style="color:{color}">{expires} dias</span>')
        html += _kv("TLS", ssl_data.get("tls_version", "N/A"))
        alerts = ssl_data.get("alerts", [])
        if alerts:
            for level, msg in alerts:
                cls = {"CRÍTICO": "alert-critico", "ALTO": "alert-alto", "MÉDIO": "alert-medio"}.get(level, "")
                html += f'<div class="alert-item {cls}">[{level}] {msg}</div>'

    # VT Domain
    vt = domain_data.get("virustotal", {})
    if vt and "error" not in vt:
        stats = vt.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        risk = "ALTO" if malicious > 3 else "MÉDIO" if malicious > 0 else "BAIXO"
        html += '<h3 style="color:#94a3b8; margin: 1rem 0 0.5rem">VirusTotal — Domínio</h3>'
        html += _kv("Detecções", f'{malicious}/{total}')
        html += _kv("Reputação", str(vt.get("reputation", "N/A")))
        html += _verdict_box(f"Domínio: {malicious} detecções maliciosas de {total} engines", risk)

    html += '</div>'
    return html


def generate_html_report(results: dict) -> str:
    """Gera relatório HTML completo."""
    os.makedirs("output", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = results.get("ip", {}).get("ip") or results.get("domain", {}).get("domain", "unknown")
    filename = f"output/report_{target}_{timestamp}.html"

    content_parts = []

    if "ip" in results:
        content_parts.append(render_ip_section(results["ip"]))
    if "domain" in results:
        content_parts.append(render_domain_section(results["domain"]))

    html = HTML_TEMPLATE.format(
        target=target,
        generated_at=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        author="João Carlos Minozzi",
        content="\n".join(content_parts)
    )

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename
