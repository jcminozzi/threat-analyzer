"""
Input Validator Module
Valida e sanitiza IPs e domínios antes de processar.
"""

import re
import ipaddress
from rich.console import Console

console = Console()


def validate_ip(ip: str) -> tuple[bool, str]:
    """Valida se o IP é válido. Retorna (válido, mensagem)."""
    ip = ip.strip()
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_loopback:
            return False, f"IP {ip} é loopback (127.x.x.x) — não há o que analisar."
        if obj.is_link_local:
            return False, f"IP {ip} é link-local — não analisável externamente."
        return True, "OK"
    except ValueError:
        return False, f"'{ip}' não é um endereço IP válido."


def validate_domain(domain: str) -> tuple[bool, str]:
    """Valida se o domínio tem formato correto. Retorna (válido, mensagem)."""
    domain = domain.strip().lower()
    # Remove http/https se o usuário colou uma URL completa
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]  # Remove path

    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(pattern, domain):
        return False, f"'{domain}' não parece um domínio válido."
    if len(domain) > 253:
        return False, "Domínio muito longo (máximo 253 caracteres)."
    return True, domain  # Retorna o domínio limpo


def sanitize_domain(domain: str) -> str:
    """Remove http/https e paths de uma URL, retornando apenas o domínio."""
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0].split('?')[0]
    return domain


def load_bulk_targets(filepath: str) -> dict:
    """
    Lê um arquivo .txt com IPs e domínios (um por linha).
    Linhas começando com # são comentários.
    Retorna dict com listas separadas de IPs e domínios válidos.
    """
    ips = []
    domains = []
    errors = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return {"error": f"Arquivo não encontrado: {filepath}"}
    except Exception as e:
        return {"error": str(e)}

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Tenta como IP primeiro
        valid, msg = validate_ip(line)
        if valid:
            ips.append(line)
            continue

        # Tenta como domínio
        clean = sanitize_domain(line)
        valid, result = validate_domain(clean)
        if valid:
            domains.append(result)
        else:
            errors.append(f"Linha {i}: '{line}' — ignorado ({result})")

    return {"ips": ips, "domains": domains, "errors": errors}
