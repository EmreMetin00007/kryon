> **Güncel çalışma motoru: Python + LLM.** Başlangıç:
> `python3 scripts/agent_cli.py --help` veya `./scripts/cco.sh --help`.
> Sağlayıcı şeması: `config/llm.example.json`.
> [Güncel mimari ve eksikler](docs/PYTHON_ENGINE_GAPS.md).

# CCO — HackAgent on OpenCode

OpenCode üzerinden çalışan, kapsam ve kanıt kontrolleriyle yönetilen güvenlik
operatörü. `kalibounty` planlama ve değerlendirmeyi, `worker` yürütme görevlerini
üstlenir. MCP sunucuları araçları; Python katmanı görev sözleşmelerini, kampanya
kuyruğunu, güvenlik politikasını, oturumları ve doğrulanabilir kanıtları sağlar.

Başlangıç noktası bu belge. [Dokümantasyon dizini](docs/README.md), güncel
rehberleri, özellik notlarını ve tarihsel incelemeleri ayrı gösterir.

## Başlatma

Mevcut kurulumda proje kökünden:

```bash
./scripts/opencode-cco.sh
```

İlk OpenCode oturumunda `/connect` ile sağlayıcıyı yapılandırın. Sağlayıcı
kimlik bilgileri OpenCode credential store'da tutulur; MCP'ye özel anahtarlar
başlatma ortamından alınır. Runtime ve model seçimi OpenCode'a aittir.

OpenCode başlatma ve uyarlama ayrıntıları: [OPENCODE.md](OPENCODE.md).
`install-cco.sh` Claude Code/global kurulum yoludur; bu clone'un ana
başlatıcısı değildir. Eski kılavuz [tarihsel arşivde](docs/history/claude-code-readme.md)
korunur.

## Python ortamı

Python 3.12 veya üzeri ve OpenCode CLI gerekir. Yeni bir Python ortamı için:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --require-hashes -r requirements.lock
python3 -m pip install --no-deps --no-build-isolation -e .
```

Playwright/Chromium, Kali araçları ve bazı MCP sunucularının ek bağımlılıkları
kullanılacak özelliklere göre kurulmalıdır. Sunucuların kendi `requirements.txt`
dosyaları ve [MCP referansı](docs/mcp-reference.md) bu sınırları gösterir.
`requirements.lock` mevcut Python bağımlılık kilididir.

## Göreve uygun profil

```bash
./scripts/opencode-cco.sh profile list
./scripts/opencode-cco.sh profile apply web
./scripts/opencode-optimized.sh --task "web application security test"
python3 scripts/tool_counts.py
```

Profil kaynağı `.opencode/profiles.json`: `min`, `recon`, `web`, `llm`, `ctf`,
`ad`, `full`. 16 MCP sunucusu tanımlıdır; etkin kayıtlar `opencode.json` ve
seçilen profile bağlıdır. AD/container/CTF sunucuları ilgili profillerde
korunur. `tool_counts.py` kaynakta bildirilen araçları sayar; etkin profilde
yüklenen araç sayısı farklı olabilir. Profil değişiminden sonra yeni oturum açın.

## Çalışma yapısı

| Bileşen | Görevi |
| --- | --- |
| `opencode.json`, `.opencode/` | Sağlayıcı/MCP yapılandırması, agent, komut, plugin ve TUI |
| `AGENTS.md`, `CLAUDE.md`, `.claude/skills/` | Runtime uyarlaması, metodoloji ve 24 skill |
| `scripts/brain.py`, `orchestration_spec.py` | Deterministik plan, TaskSpec ve kanıt sözleşmesi |
| Campaign/worker/workflow/chain modülleri | Kalıcı kuyruk, görev yürütme ve taşıma |
| `policy_engine.py`, `policy_gate_cli.py`, security plugin | Scope, approval, araç/bütçe ve izolasyon kontrolleri |
| `mcp-servers/`, `cco_*_core/` | MCP API'leri ve bağlı core modülleri |
| Oturum, kimlik ve ledger modülleri | Oturum devamı, hedef bağları, doğrulanabilir kanıt |
| `tests/`, CI ve release araçları | Regresyon, paket ve kalite kontrolleri |

`CLAUDE.md` ve `.claude/skills` OpenCode tarafından hâlâ kullanılır. `skills`
bunlara yönelen uyumluluk symlink'idir. `.opencode/tui/` içindeki HUD, server
plugin dizininden ayrı kalır.

Ayrıntılar: [mimari](docs/architecture.md), [operasyon](docs/operations.md),
[MCP kataloğu](docs/mcp-reference.md).

## Kod ve çalışma verisi

Kod bu repoda kalır. Engagement çıktıları `CCO_WORKDIR` altında tutulur
(varsayılan `~/cco-work`). MCP state/vault kökü `CCO_HOME`'dur; mevcut
başlatıcıların varsayılanı repo içindeki ignore edilmiş `.cco/` dizinidir.
Bu iki kök aynı görevde değildir ve mevcut state sıradan dosya temizliğiyle
taşınmaz.

Her program için ayrı state/çalışma alanı kullanan giriş:

```bash
python3 scripts/engagement_workspace.py \
  --id my-program --scope .codex/scope.json \
  --policy .codex/program-policy.json
```

Bu komut yalnız izolasyon planını gösterir. Sonuna `--` ile bir komut eklenirse
ayrı dizinleri oluşturup o ortamda çalıştırır.

Scope ve program policy ayarları `.codex/` altında; yeniden kullanılabilir
presetler `config/program-profiles/` altında korunur. Canlı hedef etkileşimi
öncesinde kesin scope ve kullanıcı onayı gerekir. Bulgular raporlanmadan önce
tekrarlanabilir araç/istek-cevap kanıtıyla doğrulanır.

## Doğrulama

```bash
python3 -m pytest tests -q
python3 scripts/release_artifacts.py check-lock
python3 scripts/check_repo_layout.py
```

Lab senaryoları ve benchmark yeniden üretimleri [operasyon rehberinde](docs/operations.md)
ve [benchmark skor kartında](docs/benchmark-scorecard.md) bulunur.

Düzen kapısı yeni çalışma çıktıları için başarısız olur. Kalıcı arşive taşınması
beklenen mevcut dosyalar adlarıyla ayrıca gösterilir; başarılı çıkış kodu bu
verilerin taşındığı anlamına gelmez. Temizlik ilerlemesi ve açık işler
[repo temizlik planında](docs/repo-cleanup-plan-2026-11-02.md) kayıtlıdır.
