"""
SSL/TLS Analyzer Module
- Validade do certificado
- Emissor e subject
- SANs (Subject Alternative Names)
- Algoritmo e tamanho de chave
- Alertas de segurança
"""

import ssl
import socket
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()


def get_ssl_cert(domain: str, port: int = 443, timeout: int = 10) -> dict:
    """Obtém o certificado SSL/TLS de um domínio."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {"cert": cert, "cipher": cipher, "tls_version": version}
    except ssl.SSLCertVerificationError as e:
        return {"error": f"Certificado inválido: {e}"}
    except ssl.SSLError as e:
        return {"error": f"Erro SSL: {e}"}
    except socket.timeout:
        return {"error": "Timeout ao conectar (sem HTTPS ou porta fechada)"}
    except ConnectionRefusedError:
        return {"error": "Conexão recusada na porta 443"}
    except socket.gaierror:
        return {"error": "Domínio não resolvido — verifique o DNS"}
    except Exception as e:
        return {"error": str(e)}


def parse_cert(data: dict) -> dict:
    """Analisa o certificado e retorna dados estruturados."""
    cert = data.get("cert", {})
    cipher = data.get("cipher", ())
    tls_version = data.get("tls_version", "N/A")

    # Validade
    not_after_str = cert.get("notAfter", "")
    not_before_str = cert.get("notBefore", "")

    now = datetime.utcnow()
    expires_in = None
    is_expired = False
    not_after = None
    not_before = None

    try:
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
        expires_in = (not_after - now).days
        is_expired = expires_in < 0
    except Exception:
        pass

    # Subject
    subject = {}
    for item in cert.get("subject", []):
        for key, val in item:
            subject[key] = val

    # Issuer
    issuer = {}
    for item in cert.get("issuer", []):
        for key, val in item:
            issuer[key] = val

    # SANs
    sans = []
    for ext in cert.get("subjectAltName", []):
        sans.append(ext[1])

    # Alertas
    alerts = []

    if is_expired:
        alerts.append(("CRÍTICO", "Certificado EXPIRADO"))
    elif expires_in is not None and expires_in <= 14:
        alerts.append(("ALTO", f"Certificado expira em {expires_in} dias"))
    elif expires_in is not None and expires_in <= 30:
        alerts.append(("MÉDIO", f"Certificado expira em {expires_in} dias"))

    if tls_version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
        alerts.append(("ALTO", f"Versão insegura: {tls_version} (use TLS 1.2+)"))

    if cipher:
        cipher_name = cipher[0] if cipher else ""
        if "RC4" in cipher_name or "DES" in cipher_name or "MD5" in cipher_name:
            alerts.append(("ALTO", f"Cipher fraco detectado: {cipher_name}"))
        if "NULL" in cipher_name:
            alerts.append(("CRÍTICO", "Cipher NULL — sem criptografia"))

    issuer_org = issuer.get("organizationName", "")
    if not issuer_org or issuer_org == subject.get("commonName", ""):
        alerts.append(("MÉDIO", "Possível certificado autoassinado"))

    wildcard_sans = [s for s in sans if s.startswith("*")]
    if len(wildcard_sans) > 3:
        alerts.append(("INFO", f"{len(wildcard_sans)} SANs wildcard — certificado compartilhado"))

    return {
        "subject_cn": subject.get("commonName", "N/A"),
        "subject_org": subject.get("organizationName", "N/A"),
        "issuer_cn": issuer.get("commonName", "N/A"),
        "issuer_org": issuer.get("organizationName", "N/A"),
        "not_before": str(not_before)[:10] if not_before else "N/A",
        "not_after": str(not_after)[:10] if not_after else "N/A",
        "expires_in_days": expires_in,
        "is_expired": is_expired,
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else "N/A",
        "sans": sans,
        "sans_count": len(sans),
        "alerts": alerts,
    }


def render_ssl(domain: str, parsed: dict):
    """Renderiza análise SSL no terminal."""
    if "error" in parsed:
        console.print(Panel(
            f"[yellow]⚠️  {parsed['error']}[/yellow]",
            title="[bold cyan]🔒 SSL/TLS[/bold cyan]",
            box=box.ROUNDED
        ))
        return

    expires_in = parsed["expires_in_days"]
    if parsed["is_expired"]:
        exp_str = f"[bold red]EXPIRADO[/bold red]"
    elif expires_in is not None and expires_in <= 30:
        exp_str = f"[yellow]{expires_in} dias[/yellow]"
    else:
        exp_str = f"[green]{expires_in} dias[/green]"

    tls = parsed["tls_version"]
    tls_color = "green" if tls in ["TLSv1.2", "TLSv1.3"] else "red"

    sans_preview = ", ".join(parsed["sans"][:5])
    if parsed["sans_count"] > 5:
        sans_preview += f" (+{parsed['sans_count'] - 5} mais)"

    content = f"""[bold]Domínio:[/bold] {domain}
[bold]Emitido para:[/bold] {parsed['subject_cn']} ({parsed['subject_org']})
[bold]Emissor:[/bold] {parsed['issuer_cn']} — {parsed['issuer_org']}
[bold]Válido de:[/bold] {parsed['not_before']} até {parsed['not_after']}
[bold]Expira em:[/bold] {exp_str}
[bold]Versão TLS:[/bold] [{tls_color}]{tls}[/{tls_color}]
[bold]Cipher:[/bold] {parsed['cipher']}
[bold]SANs ({parsed['sans_count']}):[/bold] {sans_preview or 'Nenhum'}"""

    if parsed["alerts"]:
        content += "\n\n[bold yellow]⚠️  Alertas:[/bold yellow]"
        colors = {"CRÍTICO": "bold red", "ALTO": "red", "MÉDIO": "yellow", "INFO": "dim"}
        for level, msg in parsed["alerts"]:
            c = colors.get(level, "white")
            content += f"\n  [{c}][{level}][/{c}] {msg}"
    else:
        content += "\n\n[green]✅ Certificado sem alertas[/green]"

    console.print(Panel(content, title="[bold cyan]🔒 SSL/TLS[/bold cyan]", box=box.ROUNDED))


def analyze_ssl(domain: str) -> dict:
    """Analisa o SSL/TLS de um domínio."""
    console.print(f"[dim]🔄 Analisando SSL/TLS...[/dim]")
    raw = get_ssl_cert(domain)

    if "error" in raw:
        render_ssl(domain, raw)
        return raw

    parsed = parse_cert(raw)
    render_ssl(domain, parsed)
    return parsed
