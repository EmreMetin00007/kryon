# Operasyon ve Güvenlik Rehberi

HackAgent'ın birincil çalışma zamanı **Python + OpenAI uyumlu model ucu**dur.
Tüm ana akışlar `cco-agent`, `python3 scripts/agent_cli.py` veya `./scripts/cco.sh`
üzerinden yönetilir.

---

## 1. Sağlayıcı ve MCP Konfigürasyonu

Sağlayıcı şeması [config/llm.example.json](../config/llm.example.json) altındadır.
Yerel ayar için dosyayı `config/llm.json` olarak kopyalayın (Git tarafından yok
sayılır) veya `CCO_LLM_CONFIG` ile yol verin:

```bash
cp config/llm.example.json config/llm.json
export CCO_LLM_API_KEY="sk-..."   # Yapılandırmaya yalnızca env değişken adı yazılır
./scripts/cco.sh check-config --provider-config config/llm.json
```

> Gizli anahtar değerlerini asla `config/llm.json` içine yazmayın ve `.env`
> sırlarını repoya eklemeyin.

Ortak çalışma ortamı değişkenleri:

```bash
export CCO_HOME=~/.cco                 # State, credential vault ve defterler
export CCO_WORKDIR=~/cco-work          # Engagement / koşu çıktıları
export CCO_GRAPH_BACKEND=auto          # auto | kuzu | networkx
```

MCP envanteri [config/mcp-servers.json](../config/mcp-servers.json) ve profil
kataloğu [config/profiles.json](../config/profiles.json) (`min`, `recon`, `web`,
`llm`, `ctf`, `ad`, `full`) içinde tutulur.

---

## 2. Planlama, Preflight ve Python Koşusu

Planlama ve operasyon önizlemesi çevrimdışıdır; yerel bir plan asla ağ trafiği
yetkisi vermez. Gerçek hedef veya sahip olunan lab etkileşimi öncesinde `.codex/scope.json`
doğrulanmalı, preflight tamamlanmalı ve `--execute` açıkça verilmelidir:

```bash
# Çevrimdışı planlama ve durum denetimi
./scripts/cco.sh plan --help
./scripts/cco.sh status

# Preflight snapshot üretimi (LLM çağrısı yapmaz)
./scripts/cco.sh preflight --baseline <baseline> --provider-config config/llm.json

# Bounded dört fazlı Python döngüsü (--execute olmadan yalnızca çevrimdışı inceleme yapar)
./scripts/cco.sh run --preflight <preflight.json> --seed <seed> --provider-config config/llm.json --execute

# E6 değerlendirme ve audit
./scripts/cco.sh benchmark --help
./scripts/cco.sh audit --help
```

---

## 3. Güvenlik Kapısı (`security`)

Her araç çağrısı ve HTTP çıkışı `scripts/policy_engine.py` ve `scripts/wire_budget.py`
üzerinden scope, program politikası, hız limiti ve onay denetiminden geçer:

```bash
# Araç/hedef doğrulaması
./scripts/cco.sh security validate --tool kali-tools_nmap_scan --target 127.0.0.1

# Zaman sınırlı onay verme ve iptal
./scripts/cco.sh security approve \
  --tool-pattern 'kali-tools_*' \
  --target-pattern 'example.com' \
  --ttl 3600 \
  --reason 'ACTIVE_OK'
./scripts/cco.sh security approvals

# Yüklü policy, scope ve audit kayıtları
./scripts/cco.sh security policy
./scripts/cco.sh security scope --add-scope example.com --scope-type domain
./scripts/cco.sh security audit --limit 20
```

Örnek program politikası `.codex/program-policy.example.json` dosyasındadır
(`approval_required_tools`, `denied_tools`, `blocked_http_methods`, `blocked_paths`,
`rate_limits`).

---

## 4. Kalıcı Campaign Runtime ve Worker

`scripts/campaign_runtime.py` ve `scripts/campaign_worker.py` SQLite tabanlı
**campaign + task queue + checkpoint + retry + dead-letter** akışı sağlar.
Worker varsayılan olarak `dry-run` çalışır; gerçek yerel MCP yürütmesi için
`--mode local-mcp` ve politika/onay şarttır. Kuyruk başarısı tek başına tam
güvenlik kapsamı kanıtı değildir.

```bash
# Campaign oluşturma ve görev ekleme
./scripts/cco.sh campaign create my-engagement --scope-file .codex/scope.json
./scripts/cco.sh campaign enqueue 1 recon --tool kali-tools_nmap_scan \
  --args-json '{"target":"127.0.0.1"}'

# Güvenli dry-run worker
./scripts/cco.sh worker run-once --worker-id worker-1 --campaign-id 1

# Sınırlı local-mcp worker
CCO_WORKER_ALLOWED_TOOLS='kali-tools_cvss_calculate,validator_*' \
  ./scripts/cco.sh worker run-once \
  --mode local-mcp \
  --worker-id worker-1 \
  --campaign-id 1 \
  --claim-timeout 300 \
  --heartbeat-interval 30 \
  --execution-timeout 900 \
  --cpu-limit-cores 1 \
  --memory-limit-mb 1024 \
  --pids-limit 128

# Custom executor contract (config/executor-contract.example.json)
CCO_ENABLE_CUSTOM_WORKER_EXECUTOR=1 \
  ./scripts/cco.sh worker run-once \
  --mode custom \
  --executor-contract config/my-executor-contract.json \
  --execution-timeout 900

# Operatör görünümü ve sağlık denetimi
./scripts/cco.sh status
python3 scripts/operator_cli.py doctor
```

Çoklu worker, stale claim kurtarma ve WAL bütünlüğü için soak testi:

```bash
python3 scripts/worker_soak.py \
  --tasks 16 --workers 4 --stale-claims 2 \
  --executor synthetic --max-tasks 16 --json
```

---

## 5. Lab Doğrulaması ve Graph Backend

Loopback doğrulama gerçek hedeflere trafik göndermez; yalnızca `127.0.0.1`
üzerindeki lab'ı kullanır:

```bash
# Embedded loopback lab
python3 scripts/lab-validate.py --skip-rag --quiet --json

# Negatif kontroller (false-positive oranı)
python3 scripts/negative-control.py --rounds 1 --json

# Graph DB testleri (auto | kuzu | networkx)
CCO_GRAPH_BACKEND=networkx python3 -m pytest tests/test_graph_backend.py tests/test_memory_server.py -q
```

Docker tabanlı lab için `scripts/lab/docker-compose.yml` kullanılabilir.

---

## 6. Governance, Release Gate ve Reproducible Paketleme

`scripts/governance_audit.py` secret/PII adaylarını değer basmadan raporlar;
`.env`, `.pem`, `.key` gibi dosyalar okunmaz. `scripts/release_check.py` CI
kalite kapısını toplu çalıştırır:

```bash
# Kalite kapısı kontrol listesi ve çalıştırma
python3 scripts/release_check.py --list
python3 scripts/governance_audit.py --root scripts --format json --fail-on high
python3 scripts/check_repo_layout.py

# Hash-pinned bağımlılık doğrulaması (Python 3.12)
python3 scripts/release_artifacts.py check-lock

# Reproducible build + SPDX SBOM + Ed25519 imzalı manifest
python3 scripts/release_artifacts.py build \
  --output-dir /tmp/cco-release \
  --private-key /secure/path/cco-release-key.pem \
  --verify-reproducible

python3 scripts/release_artifacts.py verify \
  --release-dir /tmp/cco-release \
  --public-key /trusted/path/cco-release-public-key.pem
```

Üretim release iş akışı (`.github/workflows/release.yml`) geçerli bir
`CCO_RELEASE_PRIVATE_KEY_B64` olmadan fail-closed çalışır; `--ephemeral-key`
yalnızca smoke testler içindir.

---

## 7. Kanıtlı Kapanış ve İmzalı Defter

`ChainExecutor` tüm HTTP gönderimlerini `ChainTransport` üzerinden yapar;
bütçe ve program hız limitleri gerçek gönderim anında uygulanır. `confirmed`
bulgu durumu için model beyanı yeterli değildir; kalıcı, imzası geçerli bir
validator kanıtı gerekir (`closure/2`):

```bash
python3 scripts/brain.py hypotheses mark --workdir <run> \
  --vector <vector> --status confirmed --validation-id <validator-id>
python3 scripts/brain.py check --spec <run>/specs.json --workdir <run> --closure
python3 scripts/brain.py closure verify --workdir <run>
```
