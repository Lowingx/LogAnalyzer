# Explicação Técnica Completa — Log Analyzer & Alerting System

> Documento de aprendizado separado do README.
> Aqui você entende **por que** cada decisão foi tomada, não apenas **o que** o código faz.

---

## 1. Por que analisar logs?

Em um SOC (Security Operations Center), a maior parte do trabalho do analista é olhar para logs. Logs são registros cronológicos de eventos gerados por sistemas operacionais, aplicações, firewalls, etc.

**O problema:** servidores reais podem gerar milhões de linhas de log por dia. Nenhum humano consegue ler isso manualmente. A solução é automatizar a detecção de padrões suspeitos.

Esse projeto simula exatamente o que ferramentas como **Splunk**, **Elastic SIEM** e **Wazuh** fazem internamente — com a diferença de que aqui você entende cada linha do processo.

---

## 2. Arquitetura do projeto

```
log file(s)
     |
     v
[detect_log_type]     <- identifica o formato do arquivo
     |
     v
[parse_ssh / parse_http]   <- extrai eventos estruturados linha a linha
     |
     v
[detect_ssh_threats / detect_http_threats]  <- aplica as regras de detecção
     |
     v
[Alert objects]       <- dados estruturados com severidade, evidências, etc.
     |
     v
[generate_report]     <- formata e exporta (texto colorido / JSON / Markdown)
```

Esse fluxo em pipeline é o mesmo padrão usado em SIEMs profissionais:
**ingestão → parsing → correlação → alerta → relatório.**

---

## 3. Regex: o coração do parsing de logs

Expressões regulares (regex) são o principal mecanismo de parsing de logs na área de segurança.

### 3.1 Exemplo: detectar falhas SSH

```python
RE_SSH_FAILED = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]+).*Failed password.*?from (?P<ip>[\d.]+)"
)
```

Linha real de log:
```
Jan 10 08:01:12 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
```

Decompondo o regex:

| Parte | Significado |
|---|---|
| `(?P<ts>\w{3}\s+\d+\s[\d:]+)` | Captura o timestamp (ex: `Jan 10 08:01:12`) e nomeia como `ts` |
| `.*` | Qualquer coisa entre o timestamp e a palavra-chave |
| `Failed password` | Texto literal que identifica uma falha de autenticação |
| `.*?` | Qualquer coisa (não-gulosa) até o próximo match |
| `from ` | Texto literal |
| `(?P<ip>[\d.]+)` | Captura o IP de origem e nomeia como `ip` |

**O que são grupos nomeados?** `(?P<nome>padrão)` permite recuperar o match pelo nome:
```python
m = RE_SSH_FAILED.search(linha)
if m:
    ip = m.group("ip")   # '192.168.1.100'
    ts = m.group("ts")   # 'Jan 10 08:01:12'
```

Isso é muito mais legível do que usar índices numéricos (`m.group(1)`, `m.group(2)`).

### 3.2 Regex para HTTP (Common Log Format)

```python
RE_HTTP = re.compile(
    r'(?P<ip>[\d.]+) - - \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>\S+) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
)
```

Linha real:
```
203.0.113.5 - - [10/Jan/2024:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024
```

O Common Log Format (CLF) é um padrão usado por Apache e Nginx. Entender esse formato é essencial para qualquer analista SOC que trabalhe com logs de servidores web.

---

## 4. Estrutura de dados: @dataclass

```python
@dataclass
class Alert:
    severity: str
    category: str
    source_ip: str
    description: str
    evidence: list
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    count: int = 1
```

**Por que usar dataclass?**

Em vez de dicionários (`{"severity": "HIGH", ...}`), usamos uma classe com tipos definidos. Isso traz:
- Autocompletar na IDE
- Clareza sobre quais campos existem
- O método `asdict()` converte automaticamente para dicionário (útil para exportar JSON)

**`field(default_factory=...)`** é necessário quando o valor padrão precisa ser calculado na hora da criação do objeto. Se usássemos `timestamp: str = datetime.now().isoformat()`, todos os alertas teriam o mesmo timestamp (o da importação do módulo). Com `default_factory`, o timestamp é gerado quando cada `Alert` é instanciado.

---

## 5. Lógica de detecção: padrões de ataque reais

### 5.1 Brute Force SSH

```python
for ip, lines in failed.items():
    if len(lines) >= THRESHOLD_BRUTE_FORCE_SSH:
        severity = "CRITICAL" if len(lines) >= 20 else "HIGH"
```

**O que é brute force?** Um atacante tenta automaticamente combinações de usuário/senha até acertar. Ferramentas como `hydra` e `medusa` fazem isso a dezenas de tentativas por segundo.

**Por que o threshold padrão é 5?** Em uso legítimo, um usuário raramente erra a senha mais de 2-3 vezes. Cinco falhas do mesmo IP é um indicador forte de ataque automatizado.

**Na prática real:** SIEMs como Splunk usam janelas de tempo (ex: "5 falhas em 60 segundos"). Aqui simplificamos para "5 falhas no arquivo inteiro" — o roadmap inclui adicionar análise por janela de tempo.

### 5.2 Credential Stuffing (o alerta mais crítico)

```python
for ip in accepted:
    if ip in failed and len(failed[ip]) >= 3:
        # LOGIN BEM-SUCEDIDO após múltiplas falhas
```

**O que é credential stuffing?** O atacante compra um dump de credenciais vazadas e tenta automaticamente cada par usuário/senha em outros serviços. A chave do alerta é: **o mesmo IP que falhou muitas vezes conseguiu um login bem-sucedido.**

Isso é CRITICAL porque significa que há uma conta provavelmente comprometida no sistema.

### 5.3 User Enumeration

```python
invalid = defaultdict(set)   # ip -> {conjunto de usernames}
```

**Por que `set` e não `list`?** Um set armazena apenas valores únicos. Se o atacante tentar "root" 50 vezes, conta como 1 username inválido. O que importa é a **diversidade** de usernames tentados — isso indica enumeração (o atacante está descobrindo quais usuários existem).

### 5.4 Directory Scanning HTTP

```python
if len(lines) >= THRESHOLD_HTTP_404:  # 20 erros 404
```

**O que é directory scanning?** Ferramentas como `gobuster` tentam automaticamente centenas de paths comuns (`/admin`, `/.env`, `/wp-admin`…) para encontrar recursos expostos. O sinal é um volume anormalmente alto de erros 404 do mesmo IP.

---

## 6. `defaultdict` — estrutura essencial para análise

```python
failed = defaultdict(list)   # ip -> [linhas de log]
invalid = defaultdict(set)   # ip -> {usernames únicos}
```

**O que é `defaultdict`?** É como um dicionário normal, mas com valor padrão para chaves inexistentes.

Sem `defaultdict`:
```python
if ip not in failed:
    failed[ip] = []
failed[ip].append(linha)
```

Com `defaultdict(list)`:
```python
failed[ip].append(linha)   # A lista é criada automaticamente
```

Esse padrão — agrupar eventos por IP — é extremamente comum em análise de segurança.

---

## 7. Auto-detecção de tipo de log

```python
def detect_log_type(path: Path) -> str:
    name = path.name.lower()
    if any(k in name for k in ("auth", "secure", "sshd")):
        return "ssh"
    # Fallback: inspeciona o conteúdo
    first_lines = path.read_text(errors="replace").splitlines()[:5]
    ...
```

**Por que `errors="replace"`?** Logs de sistema às vezes contêm bytes inválidos em UTF-8. Em vez de lançar uma exceção, substituímos por um caractere de substituição. Isso é importante para robustez em ambiente real.

**A lógica em duas etapas** (nome → conteúdo) começa pelo indicador mais barato computacionalmente e só inspeciona o conteúdo se necessário.

---

## 8. Múltiplos formatos de saída

| Formato | Uso |
|---|---|
| `text` | Uso interativo no terminal, com cores ANSI |
| `json` | Integração com outras ferramentas (SIEMs, scripts, APIs) |
| `markdown` | Relatórios em GitHub, Confluence, Notion |

`asdict()` converte o dataclass em dicionário recursivamente, permitindo `json.dumps()` direto.

---

## 9. Ordenação por severidade

```python
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

alerts_sorted = sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 9))
```

`SEVERITY_ORDER.get(a.severity, 9)` retorna 9 para qualquer severidade desconhecida — comportamento seguro por padrão.

---

## 10. Próximos passos para evoluir este projeto

**Nível 1 — Melhorias diretas:**
- Análise por janela de tempo (5 falhas em 60 segundos, não no arquivo inteiro)
- Suporte a logs do Windows (Event ID 4625 = falha de login)
- Allowlist de IPs confiáveis

**Nível 2 — Integrações:**
- Lookup de geolocalização do IP (biblioteca `geoip2` com base MaxMind gratuita)
- Envio de alertas por Slack webhook ou email
- Exportação para formato CEF (Common Event Format) usado por SIEMs

**Nível 3 — Arquitetura:**
- Monitoramento contínuo com `inotify` (reagir a novos eventos em tempo real)
- Armazenar alertas em SQLite para histórico e correlação entre sessões
- API REST simples para consultar alertas (Flask ou FastAPI)

**Como isso se conecta com o próximo projeto?**
O **SIEM caseiro com Elastic Stack** é essencialmente este projeto escalado: ao invés de ler arquivos e imprimir no terminal, os eventos são indexados no Elasticsearch e visualizados no Kibana. Os conceitos de parsing e detecção são os mesmos.

---

## 11. Conceitos de segurança aprendidos aqui

| Conceito | Onde aparece no código |
|---|---|
| Brute force attack | `detect_ssh_threats` → `brute_force_ssh` |
| Credential stuffing | `detect_ssh_threats` → `brute_force_success_ssh` |
| User enumeration | `detect_ssh_threats` → `user_enumeration_ssh` |
| Directory scanning | `detect_http_threats` → `directory_scan_http` |
| Log parsing com regex | `RE_SSH_FAILED`, `RE_HTTP`, etc. |
| Alertas por severidade | `SEVERITY_ORDER`, classe `Alert` |
| Common Log Format (CLF) | `RE_HTTP` e `samples/access.log` |
| Indicadores de Comprometimento (IoC) | IPs de origem capturados nos alertas |

---

*Este documento faz parte da trilha de portfólio Blue Team / SOC.*
*Cada projeto da trilha constrói sobre os conceitos do anterior.*
