# 🛡️ Threat Analyzer

> Ferramenta de análise de IPs suspeitos, domínios e detecção de spoofing.  
> Desenvolvida por **João Carlos Minozzi** — SOC / Cibersegurança
> Esta ferramenta foi desenvolvida com vibecoding, não sou desenvolvedor

---

## 📦 Funcionalidades

### 🔍 Análise de IP
| Fonte | O que verifica |
|-------|----------------|
| **VirusTotal** | Reputação, detecções de malware por 90+ engines |
| **AbuseIPDB** | Score de abuso (0-100), histórico de reports, categorias de ataque, TOR |

### 🌐 Análise de Domínio
| Verificação | Descrição |
|-------------|-----------|
| **DNS Records** | A, AAAA, MX, NS, TXT, CNAME |
| **WHOIS** | Registrador, data de criação, expiração, idade do domínio |
| **SPF** | Verifica quais servidores podem enviar e-mail pelo domínio |
| **DMARC** | Política de rejeição de e-mails não autorizados |
| **DKIM** | Assinatura criptográfica — testa 12 seletores comuns |
| **BIMI** | Indicador de marca (opcional) |
| **VirusTotal** | Reputação e categorização do domínio |

### 🎯 Score de Risco de Spoofing
Calcula automaticamente o risco de spoofing com base nos 3 protocolos:
- **BAIXO** → Domínio bem protegido
- **MÉDIO** → Melhorias recomendadas  
- **ALTO** → Vulnerável a spoofing de e-mail
- **CRÍTICO** → Domínio facilmente utilizável para phishing

---

## 🚀 Instalação

```bash
git clone https://github.com/seu-usuario/threat-analyzer.git
cd threat-analyzer
pip install -r requirements.txt
```

---

## 🔑 API Keys

| API | Gratuito | Link |
|-----|----------|------|
| VirusTotal | ✅ 4 req/min | https://virustotal.com/gui/my-apikey |
| AbuseIPDB | ✅ 1000 req/dia | https://abuseipdb.com/account/api |

Configure via variável de ambiente (recomendado):
```bash
export VT_API_KEY="sua_chave_aqui"
export ABUSE_API_KEY="sua_chave_aqui"
```

Ou passe direto na linha de comando:
```bash
python main.py --ip 1.2.3.4 --vt-key SUA_CHAVE --abuse-key SUA_CHAVE
```

---

## 💻 Uso

```bash
# Analisar um IP
python main.py --ip 185.220.101.45

# Analisar um domínio
python main.py --domain google.com

# Análise completa (IP + domínio) com relatório
python main.py --ip 192.168.1.1 --domain suspeito.com --report

# Verificar se domínio é spoofável (sem API key necessária)
python main.py --domain empresa-alvo.com
```

---

## 📄 Relatório JSON

Use `--report` para exportar os resultados em JSON:

```bash
python main.py --domain phishing.com --report
# Gera: output/report_phishing.com_20250101_120000.json
```

---

## 🏗️ Estrutura

```
threat-analyzer/
├── main.py                  # CLI principal
├── requirements.txt
├── modules/
│   ├── ip_analyzer.py       # VirusTotal + AbuseIPDB
│   ├── domain_analyzer.py   # DNS + WHOIS + SPF/DKIM/DMARC
│   └── report.py            # Geração de relatório JSON
└── output/                  # Relatórios gerados
```

---

## 🔬 Exemplo de Saída — Spoofing Check

```
┌─────────────────────────────────────────────────────────┐
│  Protocolo │ Status      │ Risco  │ Detalhe             │
├────────────┼─────────────┼────────┼─────────────────────┤
│  SPF       │ ✅ OK       │ BAIXO  │ -all configurado    │
│  DMARC     │ ⚠️ ATENÇÃO  │ MÉDIO  │ p=quarantine        │
│  DKIM      │ ✅ OK       │ BAIXO  │ Seletor: google     │
│  BIMI      │ Não config. │ —      │ Opcional            │
└─────────────────────────────────────────────────────────┘

🎯 Veredicto: ⚠️ Proteção parcial — melhorias recomendadas
Score: 15/85
```

---

## 📚 Referências

- [RFC 7208 — SPF](https://tools.ietf.org/html/rfc7208)
- [RFC 7489 — DMARC](https://tools.ietf.org/html/rfc7489)
- [RFC 6376 — DKIM](https://tools.ietf.org/html/rfc6376)
- [VirusTotal API v3](https://developers.virustotal.com/reference)
- [AbuseIPDB API](https://docs.abuseipdb.com/)

---

> 🛡️ Desenvolvido para fins educacionais e uso em SOC / Threat Intelligence.
