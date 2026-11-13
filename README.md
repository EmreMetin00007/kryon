# HackAgent (`kryon`) — Python + LLM Güvenlik Motoru

Politika, kapsam, bütçe ve imzalı kanıt kontrolleriyle yönetilen bağımsız Python + OpenAI uyumlu LLM güvenlik operatörü. Model yalnızca veri üretir; aşama geçişlerini, araç izinlerini, wire bütçesini, imzalı doğrulamayı ve kapanış kararlarını Python host katmanı kontrol eder.

> Güncel yetenek sınırları ve tamamlanan/açık aşamalar (E1–E9): [PYTHON_ENGINE_GAPS.md](docs/PYTHON_ENGINE_GAPS.md).
> Dokümantasyon dizini: [docs/README.md](docs/README.md).

## Kurulum (Python 3.12+)

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --require-hashes -r requirements.lock
python3 -m pip install --no-deps --no-build-isolation -e .
```

Playwright/Chromium, Kali araçları ve opsiyonel MCP sunucu bağımlılıkları kullanılacak özelliklere göre ayrıca kurulur (`requirements.lock` ana Python bağımlılık kilididir).

## Yapılandırma

1. Örnek sağlayıcı yapılandırmasını (`cco-llm/1`) kopyalayıp kendi endpoint/model adınızla `config/llm.json` olarak uyarlayın (Git tarafından yok sayılır) veya `CCO_LLM_CONFIG` ile yol verin:

```bash
cp config/llm.example.json config/llm.json
python3 scripts/agent_cli.py check-config --provider-config config/llm.json
```

2. Yapılandırmaya **hiçbir zaman ham API anahtarı yazmayın**; yalnızca anahtarın bulunduğu ortam değişkeni adını (`api_key_env`, örnek: `CCO_LLM_API_KEY`) belirtin. Sağlayıcı URL'si HTTPS veya sahip olunan loopback olmalıdır.

## Temel Kullanım (`cco-agent` / `scripts/agent_cli.py`)

Paket kurulduğunda `cco-agent` girişi, repo içinden doğrudan `./scripts/cco.sh` veya `python3 scripts/agent_cli.py` kullanılabilir:

```bash
python3 scripts/agent_cli.py --help
python3 scripts/agent_cli.py check-config --provider-config config/llm.example.json

# Çevrimdışı plan ve operasyon özeti üretir (ağ trafiği oluşturmaz)
python3 scripts/agent_cli.py plan --target https://example.invalid --workdir ~/cco-work/example
python3 scripts/agent_cli.py operations --workdir ~/cco-work/example

# Laboratuvar çalışması: preflight + imzalı koşu (yalnız --execute verildiğinde çalışır)
python3 scripts/agent_cli.py preflight --baseline <baseline-dir> --provider-config config/llm.json --output-dir ~/cco-work/preflight
python3 scripts/agent_cli.py run --preflight ~/cco-work/preflight/<id>/preflight.json --seed 123456 --execute
python3 scripts/agent_cli.py run --resume ~/cco-work/runs/<run-dir> --execute

# E6 çok-aileli benchmark sözleşmesi (plan sıfır trafik üretir; canlı uzak sağlayıcı açık onay ister)
python3 scripts/agent_cli.py benchmark plan --label e6-plan --baseline <baseline-dir> --output-dir ~/cco-work/e6-plan
```

Diğer alt komutlar: `audit`, `campaign`, `worker`, `security`, `status`.

- `plan` ve `operations` ağ isteği göndermez.
- `preflight`/`run` bugün dondurulmuş baseline ve sentetik test kimlikleriyle sınırlı laboratuvar akışını yürütür; canlı hedef etkileşimi öncesinde `.codex/scope.json` (veya `CCO_SCOPE_FILE`), `.codex/program-policy.json` ve açık operatör onayı zorunludur.

## Mimari Özeti

| Bileşen | Görevi |
|---|---|
| `scripts/agent_cli.py`, `./scripts/cco.sh`, `cco-agent` | Tek Python CLI girişi (`plan`, `operations`, `preflight`, `run`, `audit`, `benchmark`, `campaign`, `worker`, `security`, `status`) |
| `scripts/full_agent_python_solver.py` | Sınırlı model/araç döngüsü (`recon`, `enum`, `access`, `report`) ve atomik imzalı checkpoint/resume |
| `scripts/full_agent_python_broker.py`, `full_agent_broker.py`, `full_agent_budget.py` | Bağlam projeksiyonu, aşama araç izni, oturum referansları, sağlayıcı/token/HTTP muhasebesi |
| `scripts/brain.py`, `orchestration_spec.py` | TaskSpec planlama, P5 hipotez gözlem seçimi ve kapanış sözleşmesi |
| `scripts/policy_engine.py`, `policy_gate_cli.py`, `wire_budget.py` | Scope, onay, secret koruması ve istek bazında egress/bütçe kapıları |
| `scripts/campaign_runtime.py`, `campaign_worker.py` | Kalıcı SQLite görev kuyruğu ve sınırlı worker yürütmesi |
| `scripts/full_agent_holdout.py`, `full_agent_e6_benchmark.py` | Bağımsız holdout puanlama ve ≥3-aile önce/sonra benchmark karşılaştırıcısı |
| `mcp-servers/`, `config/mcp-servers.json`, `config/profiles.json` | Yeniden kullanılabilir keşif, kimlik, hipotez, doğrulama, iş mantığı ve kanıt sunucuları/profilleri |

## Çalışma Verisi ve Scope Sınırları

- Kod repoda kalır; engagement ve koşu çıktıları `CCO_WORKDIR` (varsayılan `~/cco-work`), host imza/ledger/vault durumu `CCO_HOME` altında tutulur. Repoya çalışma çıktısı bırakılmaz.
- Program bazlı çalışma alanı hazırlığı için:

```bash
python3 scripts/engagement_workspace.py \
  --id my-program --scope .codex/scope.json \
  --policy .codex/program-policy.json
```

## Doğrulama

```bash
python3 -m pytest tests -q -m 'not integration'
python3 scripts/check_repo_layout.py
python3 scripts/release_artifacts.py check-lock
python3 scripts/agent_cli.py check-config --provider-config config/llm.example.json
python3 scripts/governance_audit.py --root scripts --format json --fail-on high
python3 scripts/release_check.py --list
```
