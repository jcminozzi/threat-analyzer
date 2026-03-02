"""
Módulo de Histórico
===================
Registra cada análise realizada em um arquivo CSV (historico.csv).
Isso permite que você acompanhe seu histórico de investigações ao longo do tempo.

O que é CSV?
  Um arquivo de planilha simples que pode ser aberto no Excel ou Google Sheets.
  Cada linha representa uma análise feita, com data, alvo e resultado.
"""

import csv
import os
from datetime import datetime


HISTORICO_PATH = "output/historico.csv"

# Colunas que serão salvas no histórico
COLUNAS = [
    "data",
    "hora",
    "tipo",        # IP ou Domínio
    "alvo",        # O IP ou domínio analisado
    "veredicto",   # LIMPO, SUSPEITO, MALICIOSO, etc.
    "risco",       # BAIXO, MÉDIO, ALTO, CRÍTICO
    "detalhes",    # Resumo do que foi encontrado
]


def registrar(tipo: str, alvo: str, veredicto: str, risco: str, detalhes: str):
    """
    Salva uma linha no histórico CSV.
    
    Parâmetros:
      tipo     → "IP" ou "Domínio"
      alvo     → ex: "185.220.101.45" ou "google.com"
      veredicto→ ex: "MALICIOSO", "LIMPO", "SUSPEITO"
      risco    → ex: "ALTO", "MÉDIO", "BAIXO"
      detalhes → ex: "15 detecções VT | Score AbuseIPDB: 92"
    """
    os.makedirs("output", exist_ok=True)

    # Verifica se o arquivo já existe para decidir se escreve o cabeçalho
    arquivo_novo = not os.path.exists(HISTORICO_PATH)

    with open(HISTORICO_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUNAS)

        if arquivo_novo:
            writer.writeheader()  # Escreve os títulos das colunas na primeira vez

        agora = datetime.now()
        writer.writerow({
            "data": agora.strftime("%d/%m/%Y"),
            "hora": agora.strftime("%H:%M:%S"),
            "tipo": tipo,
            "alvo": alvo,
            "veredicto": veredicto,
            "risco": risco,
            "detalhes": detalhes,
        })


def extrair_resumo_ip(ip_data: dict) -> tuple[str, str, str]:
    """
    Extrai veredicto, risco e detalhes de uma análise de IP.
    Retorna (veredicto, risco, detalhes).
    """
    detalhes_parts = []
    risco_final = "DESCONHECIDO"
    veredicto = "SEM DADOS"

    vt = ip_data.get("virustotal", {})
    if vt and "error" not in vt:
        stats = vt.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        detalhes_parts.append(f"VT: {malicious}/{total} detecções")
        if malicious > 10:
            risco_final = "CRÍTICO"
            veredicto = "MALICIOSO"
        elif malicious > 3:
            risco_final = "ALTO"
            veredicto = "MALICIOSO"
        elif malicious > 0:
            risco_final = "MÉDIO"
            veredicto = "SUSPEITO"
        else:
            risco_final = "BAIXO"
            veredicto = "LIMPO"

    abuse = ip_data.get("abuseipdb", {})
    if abuse and "error" not in abuse:
        score = abuse.get("abuseConfidenceScore", 0)
        is_tor = abuse.get("isTor", False)
        detalhes_parts.append(f"AbuseIPDB: {score}/100")
        if is_tor:
            detalhes_parts.append("TOR")
        # Eleva o risco se o score de abuso for alto
        if score >= 80 and risco_final not in ["CRÍTICO"]:
            risco_final = "CRÍTICO"
            veredicto = "MALICIOSO"
        elif score >= 50 and risco_final not in ["CRÍTICO", "ALTO"]:
            risco_final = "ALTO"
            veredicto = "SUSPEITO"

    return veredicto, risco_final, " | ".join(detalhes_parts) or "Sem detalhes"


def extrair_resumo_dominio(domain_data: dict) -> tuple[str, str, str]:
    """
    Extrai veredicto, risco e detalhes de uma análise de domínio.
    Retorna (veredicto, risco, detalhes).
    """
    detalhes_parts = []

    spoofing = domain_data.get("spoofing", {})
    overall = spoofing.get("overall_risk", {}) if spoofing else {}
    risco_final = overall.get("level", "DESCONHECIDO")
    veredicto = "VULNERÁVEL A SPOOFING" if risco_final in ["ALTO", "CRÍTICO"] else "OK"

    score = overall.get("score", 0)
    if score:
        detalhes_parts.append(f"Spoofing score: {score}/85")

    ssl = domain_data.get("ssl", {})
    if ssl and "error" not in ssl:
        expires = ssl.get("expires_in_days")
        if ssl.get("is_expired"):
            detalhes_parts.append("SSL EXPIRADO")
        elif expires and expires <= 14:
            detalhes_parts.append(f"SSL expira em {expires}d")

    vt = domain_data.get("virustotal", {})
    if vt and "error" not in vt:
        mal = vt.get("last_analysis_stats", {}).get("malicious", 0)
        if mal > 0:
            detalhes_parts.append(f"VT: {mal} detecções")
            veredicto = "MALICIOSO"
            risco_final = "ALTO"

    return veredicto, risco_final, " | ".join(detalhes_parts) or "Sem detalhes"


def registrar_resultados(results: dict):
    """
    Ponto de entrada: registra todos os resultados de uma análise no histórico.
    Chamado automaticamente no final de cada análise.
    """
    if "ip" in results:
        ip = results["ip"].get("ip", "?")
        veredicto, risco, detalhes = extrair_resumo_ip(results["ip"])
        registrar("IP", ip, veredicto, risco, detalhes)

    if "domain" in results:
        domain = results["domain"].get("domain", "?")
        veredicto, risco, detalhes = extrair_resumo_dominio(results["domain"])
        registrar("Domínio", domain, veredicto, risco, detalhes)

    if "bulk" in results:
        for alvo, data in results["bulk"].items():
            if "ip" in data:
                veredicto, risco, detalhes = extrair_resumo_ip(data["ip"])
                registrar("IP", alvo, veredicto, risco, detalhes)
            if "domain" in data:
                veredicto, risco, detalhes = extrair_resumo_dominio(data["domain"])
                registrar("Domínio", alvo, veredicto, risco, detalhes)
