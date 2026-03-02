"""
Módulo de Explicações Educacionais
====================================
Exibe, após cada veredicto, uma explicação em linguagem simples do que
aquele resultado significa e o que você deve fazer na prática.

Isso é especialmente útil em contexto de SOC/suporte, onde você precisa
comunicar riscos para outras pessoas ou tomar ações corretivas rapidamente.
"""

from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich import box

console = Console()


# ─── EXPLICAÇÕES DE IP ─────────────────────────────────────────────────────────

IP_EXPLICACOES = {
    "CRÍTICO": {
        "titulo": "🚨 O que isso significa?",
        "significado": (
            "Este IP é amplamente reconhecido como malicioso por múltiplas fontes de inteligência. "
            "Pode ser um servidor de comando e controle (C2), nó de saída TOR, ou host usado em ataques coordenados. "
            "Qualquer comunicação com este IP representa risco alto para a sua rede."
        ),
        "acoes": [
            "Bloqueie imediatamente este IP no firewall",
            "Verifique nos logs se algum equipamento interno se comunicou com ele",
            "Se houver comunicação interna, isole o host afetado para análise",
            "Documente o incidente e escalone conforme política da empresa",
        ],
        "contexto_soc": (
            "Em um ambiente SOC, este IP seria imediatamente adicionado a uma blocklist "
            "e acionaria um alerta de nível P1 (crítico). Investigue origem da conexão antes de qualquer outra ação."
        ),
    },
    "ALTO": {
        "titulo": "🔴 O que isso significa?",
        "significado": (
            "Este IP tem histórico de atividade maliciosa confirmada por diversas engines. "
            "Pode estar associado a phishing, malware, brute force ou scanning."
        ),
        "acoes": [
            "Adicione à blocklist do firewall ou IDS/IPS",
            "Revise os logs das últimas 72h buscando conexões com este IP",
            "Se for externo chegando à sua rede, verifique qual serviço foi alvo",
            "Considere um alerta de monitoramento ativo",
        ],
        "contexto_soc": (
            "Prioridade alta. Correlacione com outros alertas abertos. "
            "Se o IP aparece em múltiplos logs de diferentes hosts, pode indicar varredura de rede."
        ),
    },
    "MÉDIO": {
        "titulo": "⚠️ O que isso significa?",
        "significado": (
            "Algumas engines sinalizaram este IP, mas não há consenso. "
            "Pode ser um falso positivo, um servidor legítimo com histórico antigo, "
            "ou um IP que foi reutilizado após uso malicioso."
        ),
        "acoes": [
            "Investigue o contexto: de onde veio esta conexão?",
            "Verifique se é IP de provedor conhecido ou residencial",
            "Busque o IP em fontes adicionais: Shodan, GreyNoise, IPInfo",
            "Monitore por recorrência antes de bloquear",
        ],
        "contexto_soc": (
            "Não bloqueie imediatamente — investigue primeiro. "
            "Falsos positivos são comuns em IPs de provedores compartilhados ou CDNs."
        ),
    },
    "BAIXO": {
        "titulo": "✅ O que isso significa?",
        "significado": (
            "Nenhuma fonte de inteligência identificou atividade maliciosa neste IP. "
            "Isso não garante 100% de segurança — IPs novos ou raramente usados podem não ter histórico."
        ),
        "acoes": [
            "Sem ação imediata necessária",
            "Mantenha monitoramento padrão",
            "Se for um IP interno ou parceiro, documente para referência futura",
        ],
        "contexto_soc": (
            "IP limpo nas fontes consultadas. Continue o monitoramento de rotina. "
            "Lembre-se: ausência de histórico não é garantia de segurança."
        ),
    },
}

# ─── EXPLICAÇÕES DE SPOOFING ───────────────────────────────────────────────────

SPOOFING_EXPLICACOES = {
    "CRÍTICO": {
        "titulo": "🚨 Domínio completamente exposto ao spoofing",
        "significado": (
            "Qualquer pessoa pode enviar e-mails fingindo ser este domínio. "
            "Sem SPF, DMARC e DKIM, não há nenhuma barreira técnica contra falsificação de remetente. "
            "Este é o cenário ideal para ataques de phishing e BEC (Business Email Compromise)."
        ),
        "acoes": [
            "Configure SPF: adicione um registro TXT no DNS indicando quais servidores podem enviar e-mail",
            "Configure DMARC: comece com p=none para monitorar, depois evolua para p=reject",
            "Configure DKIM: ative no seu provedor de e-mail (Gmail, Exchange, etc.)",
            "Use ferramentas como MXToolbox para validar após configurar",
        ],
        "contexto_soc": (
            "Domínios sem proteção são alvos frequentes em campanhas de phishing direcionado. "
            "Se este for um domínio corporativo, escale imediatamente para o responsável pelo DNS."
        ),
    },
    "ALTO": {
        "titulo": "🔴 Proteção incompleta contra spoofing",
        "significado": (
            "Parte da proteção está configurada, mas há lacunas que permitem spoofing. "
            "Comum: SPF presente mas DMARC ausente, ou DMARC com política fraca (p=none)."
        ),
        "acoes": [
            "Verifique qual protocolo está faltando ou mal configurado (veja tabela acima)",
            "Se DMARC está ausente: crie o registro _dmarc.dominio.com no DNS",
            "Se DMARC está em p=none: evolua para p=quarantine e depois p=reject",
            "Se SPF usa ~all (softfail): considere mudar para -all (hardfail)",
        ],
        "contexto_soc": (
            "Proteção parcial ainda permite que e-mails spoofados cheguem à caixa de spam do destinatário. "
            "Isso já é suficiente para enganar usuários menos atentos."
        ),
    },
    "MÉDIO": {
        "titulo": "⚠️ Melhorias recomendadas",
        "significado": (
            "A configuração básica existe, mas há pontos que podem ser otimizados. "
            "Exemplos: DMARC em quarantine (ideal seria reject), SPF com muitos includes."
        ),
        "acoes": [
            "Revise a política DMARC: se estiver em p=quarantine, considere evoluir para p=reject",
            "Verifique se recebe relatórios DMARC (rua=) e analise-os regularmente",
            "Reduza o número de includes no SPF se estiver próximo do limite de 10",
        ],
        "contexto_soc": (
            "Domínio com proteção funcional mas não ideal. Sem urgência crítica, mas registre como melhoria pendente."
        ),
    },
    "BAIXO": {
        "titulo": "✅ Domínio bem protegido contra spoofing",
        "significado": (
            "SPF, DMARC e DKIM estão configurados corretamente. "
            "E-mails falsificados com este domínio serão rejeitados pelos servidores de destino."
        ),
        "acoes": [
            "Mantenha monitoramento periódico das configurações",
            "Revise os relatórios DMARC mensalmente para detectar tentativas de abuso",
            "Documente os seletores DKIM ativos para referência futura",
        ],
        "contexto_soc": (
            "Configuração ideal. Nenhuma ação corretiva necessária no momento."
        ),
    },
}

# ─── EXPLICAÇÕES DE SSL ────────────────────────────────────────────────────────

SSL_EXPLICACOES = {
    "expirado": {
        "titulo": "🚨 Certificado SSL expirado",
        "significado": (
            "O certificado de segurança do site está vencido. "
            "Isso significa que a criptografia pode não estar funcionando corretamente "
            "e qualquer navegador vai exibir aviso de segurança para os visitantes."
        ),
        "acoes": [
            "Renove o certificado imediatamente pelo seu provedor de hosting",
            "Se usa Let's Encrypt, verifique se o processo de renovação automática está ativo",
            "Após renovar, teste em: https://www.ssllabs.com/ssltest/",
        ],
    },
    "expirando": {
        "titulo": "⚠️ Certificado SSL prestes a expirar",
        "significado": (
            "O certificado expira em breve. Se não renovado, o site passará a exibir "
            "erros de segurança para todos os visitantes."
        ),
        "acoes": [
            "Renove o certificado antes da data de expiração",
            "Configure renovação automática para evitar este problema no futuro",
        ],
    },
    "tls_fraco": {
        "titulo": "🔴 Versão TLS insegura detectada",
        "significado": (
            "TLS 1.0 e 1.1 são versões antigas com vulnerabilidades conhecidas (POODLE, BEAST). "
            "O padrão atual é TLS 1.2 ou 1.3."
        ),
        "acoes": [
            "Desabilite TLS 1.0 e 1.1 nas configurações do servidor web",
            "Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
            "Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
        ],
    },
}

# ─── RENDERIZAÇÃO ──────────────────────────────────────────────────────────────

def _render_explicacao(titulo: str, significado: str, acoes: list, contexto_soc: str = None):
    """Renderiza uma caixa de explicação educacional."""

    acoes_str = "\n".join([f"  [cyan]→[/cyan] {a}" for a in acoes])

    content = f"[bold]{titulo}[/bold]\n\n"
    content += f"[white]{significado}[/white]\n\n"
    content += "[bold yellow]💡 O que fazer:[/bold yellow]\n"
    content += acoes_str

    if contexto_soc:
        content += f"\n\n[bold dim]🎯 Contexto SOC:[/bold dim]\n[dim]{contexto_soc}[/dim]"

    console.print(Panel(content, title="[bold]📚 Explicação[/bold]", box=box.SIMPLE, border_style="dim"))


def explicar_ip(risco: str):
    """Exibe explicação após análise de IP."""
    exp = IP_EXPLICACOES.get(risco)
    if exp:
        _render_explicacao(
            exp["titulo"],
            exp["significado"],
            exp["acoes"],
            exp.get("contexto_soc")
        )


def explicar_spoofing(risco: str):
    """Exibe explicação após análise de spoofing."""
    exp = SPOOFING_EXPLICACOES.get(risco)
    if exp:
        _render_explicacao(
            exp["titulo"],
            exp["significado"],
            exp["acoes"],
            exp.get("contexto_soc")
        )


def explicar_ssl(parsed: dict):
    """Exibe explicação após análise SSL se houver alertas relevantes."""
    if not parsed or "error" in parsed:
        return

    if parsed.get("is_expired"):
        exp = SSL_EXPLICACOES["expirado"]
        _render_explicacao(exp["titulo"], exp["significado"], exp["acoes"])
    elif parsed.get("expires_in_days") and parsed["expires_in_days"] <= 14:
        exp = SSL_EXPLICACOES["expirando"]
        _render_explicacao(exp["titulo"], exp["significado"], exp["acoes"])

    tls = parsed.get("tls_version", "")
    if tls in ["TLSv1", "TLSv1.1", "SSLv3"]:
        exp = SSL_EXPLICACOES["tls_fraco"]
        _render_explicacao(exp["titulo"], exp["significado"], exp["acoes"])
