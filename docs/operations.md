# Operasyon ve Hardening Notları

> README'den taşındı: Faz 1/2 iyileştirmeleri, P0 hardening ve konfigürasyon.

Oturumlu Web/API akışının kimlik/nesne girdisi, koşu bazlı kapsaması ve
otomatik adımlardaki güncel sınırlar için
[uygulama notuna](authenticated-web-api-2026-10-30.md) bakın.

## 🆕 Faz 1 İyileştirmeleri (Yeni!)

### 💰 Token Optimizasyonu
- **Otomatik Profil Seçimi:** Görev tipine göre MCP profili otomatik aktifleştirme
- **Profil kapsamı:** Yalnız görev için gereken sunucuları etkinleştir.
  `lazy_loading` ayarı ve standalone `lazy_loader.py` bulunuyor; başlatıcılara
  entegrasyonu ve startup tasarrufu ölçülmüş kabul edilmez.
- **7 Hazır Profil:** min, recon, web, llm, ctf, ad, full

```bash
# Profil yönetimi
./scripts/opencode-cco.sh profile list
./scripts/opencode-cco.sh profile apply web
./scripts/opencode-cco.sh profile detect --task "web pentest"

# Optimize edilmiş başlatma (auto-profile)
./scripts/opencode-optimized.sh --task "web application security test"
```

### 🛡️ Güvenlik Middleware
- **Scope Validation:** Hedef scope dışındaysa otomatik blok
- **Audit Logging:** Tüm tool çağrıları immutable log'a kaydedilir
- **Rate Limiting:** Tool bazında rate limit kontrolü
- **Permission Matrix:** Granular izin yönetimi

```bash
# Güvenlik yönetimi
./scripts/opencode-cco.sh security validate --tool kali-tools_nmap_scan --target example.com
./scripts/opencode-cco.sh security audit --limit 50
./scripts/opencode-cco.sh security scope --add-scope example.com --scope-type domain
```

### 🔧 Interactive Setup Wizard
- **Adım adım kurulum:** Provider, API keys, profil, güvenlik ayarları
- **Otomatik yapılandırma:** .env, scope.json, opencode.json otomatik oluşturulur

```bash
# Setup wizard'ı başlat
./scripts/opencode-cco.sh setup
```

---

## 🆕 Faz 2 İyileştirmeleri

### 🧠 Graph DB Migration
- **KuzuDB backend:** `mcp-memory-server` artık `CCO_GRAPH_BACKEND=auto|kuzu|networkx` destekler
- **Idempotent migration:** SQLite graph projection fingerprint ile tek sefer migrate edilir
- **Fail-closed backend selection:** Kuzu store varsa sessiz fallback yerine açık hata verir
- **Outbox projection:** Legacy SQLite kayıtları ile graph projection ayrışmaz; hata olursa replay edilir

```bash
# Varsayılan: auto (kuzu varsa kuzu, yoksa networkx)
python3 -m pytest tests/test_graph_backend.py tests/test_memory_server.py -q

# Açık backend seçimi
CCO_GRAPH_BACKEND=kuzu python3 -m pytest tests/test_memory_server.py -q
CCO_GRAPH_BACKEND=networkx python3 -m pytest tests/test_memory_server.py -q
```

### 🧩 Reasoning/Hunter Modülerizasyonu
- **Pure policy/core paketleri:** `cco_reasoning_core/` ve `cco_hunter_core/`
- **MCP API korunur:** tool isimleri, sıraları ve imzaları değişmedi
- **Daha küçük facade dosyaları:** büyük statik kataloglar ve saf helper'lar ayrı modüllere taşındı
- **Contract testleri:** facade'ların tool sözleşmesi `tests/test_module_boundaries.py` ile korunuyor

### 🧪 Reproducible Integration Lab
- **Embedded loopback lab:** `python3 scripts/lab-validate.py`
- **Docker lab:** `scripts/lab/docker-compose.yml`
- **Gerçek e2e doğrulama:** hunter + validator gerçek HTTP üzerinden kasıtlı zafiyetli hedefe karşı koşar
- **Kapsanan sınıflar:** XSS, SQLi, IDOR/BOLA, auth bypass/BFLA, business logic, open redirect

```bash
# Embedded lab
python3 scripts/lab-validate.py --skip-rag --json

# Docker lab
docker compose -f scripts/lab/docker-compose.yml up --build -d vuln-lab
python3 scripts/lab-validate.py --base-url http://127.0.0.1:8899 --skip-rag
docker compose -f scripts/lab/docker-compose.yml down
```

---

## 🆕 P0 Hardening

### 🔒 Merkezi Policy Gate
- **OpenCode plugin enforcement:** `.opencode/plugins/security-gate.js`
- **Her aktif tool çağrısı** `scripts/policy_gate_cli.py` üzerinden scope/policy/approval kontrolünden geçer
- **Approval grants:** canlı hedef etkileşimi için zaman sınırlı onay verilebilir
- **Untrusted-content guard:** browser/webfetch/curl benzeri çıktıların başına instruction-safety banner eklenir

```bash
# Aktif etkileşim için onay ver
./scripts/opencode-cco.sh security approve \
  --tool-pattern 'kali-tools_*' \
  --target-pattern 'example.com' \
  --ttl 3600 \
  --reason 'ACTIVE_OK'

# Yüklü policy'yi görüntüle
./scripts/opencode-cco.sh security policy

# Audit log
./scripts/opencode-cco.sh security audit --limit 20
```

### 🔐 Encrypted Credential Vault
- `mcp-memory-server` artık yeni credential'ları **Fernet ile şifrelenmiş vault** içinde saklar
- `agent_memory.db` içinde plaintext parola tutulmaz; yalnızca `secret_ref` ve redacted görünüm kalır
- Eski plaintext credential kayıtları ilk açılışta otomatik migrate edilir

### 🗂️ Durable Campaign Runtime + Worker
- `scripts/campaign_runtime.py` ve `scripts/campaign_worker.py`
- SQLite tabanlı **campaign + task queue + checkpoint + retry + dead-letter**
- Signed execution permit, policy revalidation, heartbeat fencing ve budget settlement içerir
- Worker varsayılan olarak dry-run çalışır; production için explicit `--mode local-mcp` gerekir

Hedefli coverage görevleri `schedule-gaps --max-attempts 3` ile ilk deneme
sınırı belirlenerek eklenebilir (1–3). Saf oturum hatasıyla engellenen görev,
tüm bağlı hesapların engellemeden sonraki yeni doğrulamasıyla sonraki worker
sorgusunda devam eder. `campaign resume-gaps CAMPAIGN TARGET` aynı kabulü
HTTP göndermeden değerlendirir; eski tek denemeli görev yükseltilmez,
tüketilmiş istekler kalan haktan düşülür. Ayrıntılar
[kampanya köprüsü notundadır](coverage-campaign-bridge-2026-10-31.md).

Native worker, desteklenen HTTP validator/browser/Hunter yollarında ve temel
HTTP isteğinde rezervasyonu ortak sayaçla uygular. Harici veya sayaca
bağlanmamış ağ araçları ile ağ erişimli custom executor kampanyada çalıştırılmaz.
Chain manifestinin tavanı da kampanya hakkıyla sınırlanır. Kullanım kaydı
geçersiz veya child kaybolmuşsa rezervasyon hesaplanır; ölçülen tüketim varsa
yalnız o sayı düşülür. Destek kapsamı ve ölçüm sınırı
[ortak bütçe notundadır](shared-wire-budget-2026-10-31.md).

```bash
# Campaign oluştur
./scripts/opencode-cco.sh campaign create my-engagement --scope-file .codex/scope.json

# Görev ekle
./scripts/opencode-cco.sh campaign enqueue 1 recon --tool kali-tools_nmap_scan \
  --args-json '{"target":"127.0.0.1"}'

# Güvenli dry-run worker
./scripts/opencode-cco.sh worker run-once --worker-id worker-1 --campaign-id 1

# Production local MCP executor (yalnızca policy/approval/scope geçerse)
CCO_WORKER_ALLOWED_TOOLS='kali-tools_cvss_calculate,validator_*' \
  ./scripts/opencode-cco.sh worker run-once \
  --mode local-mcp \
  --worker-id worker-1 \
  --campaign-id 1 \
  --claim-timeout 300 \
  --heartbeat-interval 30 \
  --execution-timeout 900 \
  --cpu-limit-cores 1 \
  --memory-limit-mb 1024 \
  --pids-limit 128 \
  --cgroup-mode required

# Contract-bound custom executor (parent worker custom modülü import etmez)
chmod 600 config/my-executor-contract.json
CCO_ENABLE_CUSTOM_WORKER_EXECUTOR=1 \
  ./scripts/opencode-cco.sh worker run-once \
  --mode custom \
  --executor-contract config/my-executor-contract.json \
  --execution-timeout 900

# Operatör görünümü
./scripts/opencode-cco.sh operator dashboard --json
./scripts/opencode-cco.sh operator doctor
```

Custom executor contract şeması `cco-executor-contract/1` ve örnek dosya
`config/executor-contract.example.json` altındadır. Contract CPU süresi, CPU
çekirdeği, RAM, PID, network ve cgroup politikasını açıkça belirtmeden kabul
edilmez. `process` backend child-only import + RLIMIT + cgroup sağlar; host dosya
sistemi sınırı gerektiren güvenilmeyen kod için digest-pinned image kullanan
`container` backend seçilmelidir. Container backend read-only root, dropped
capabilities, `no-new-privileges`, PID/RAM/CPU ve explicit network policy ile
çalışır; Docker/Podman yoksa fail-closed olur.

Uzun süreli offline worker doğrulaması gerçek SQLite queue, çoklu worker,
execution permit/fencing, stale lease recovery, exactly-once completion,
reservation cleanup, WAL ve DB integrity invariantlarını birlikte ölçer:

```bash
# Hızlı CI smoke
./scripts/opencode-cco.sh soak \
  --tasks 32 --workers 4 --stale-claims 4 \
  --executor synthetic --max-tasks 32 --json

# Gerçek local-MCP subprocess soak; bir saat boyunca batch üretir
./scripts/opencode-cco.sh soak \
  --tasks 100 --workers 8 --stale-claims 10 \
  --executor local-mcp --duration-seconds 3600 --max-tasks 100000 \
  --output .cco/worker-soak.json
```

### 🧾 Governance + Release Gate
- `scripts/governance_audit.py` secret/PII adaylarını değerleri basmadan raporlar
- `.env`, `.pem`, `.key` gibi hassas dosyalar okunmaz; yalnızca atlandı olarak listelenir
- Baseline ve allowlist desteklenir; CI kalite kapısı `scripts/release_check.py` ile tek yerden çalışır

```bash
# Mevcut bulguları baseline'a al
./scripts/opencode-cco.sh governance --root . --write-baseline .cco/governance-baseline.json

# Baseline/allowlist ile kontrol et
./scripts/opencode-cco.sh governance \
  --root . \
  --baseline .cco/governance-baseline.json \
  --allowlist .cco/governance-allowlist.json \
  --fail-on high

# Release quality gate
./scripts/opencode-cco.sh release-check --skip-opencode

# Hash-pinned transitive lock doğrulaması
./scripts/opencode-cco.sh release check-lock
```

### Signed Reproducible Release

`requirements.lock` Python 3.12 için tüm transitive bağımlılıkları exact version
ve SHA-256 hash ile sabitler. Release builder iki bağımsız wheel/sdist build'ini
karşılaştırır, yalnız allowlisted source staging kullanır, archive içeriğini
secret/engagement path'lerine karşı denetler, SPDX 2.3 SBOM üretir ve tüm
checksum'ları Ed25519 detached signature ile bağlar.

```bash
# Lock'u dependency değişikliğinden sonra yeniden üret
uv pip compile pyproject.toml --extra dev --generate-hashes \
  --python-version 3.12 --output-file requirements.lock

# Private key her zaman repo dışında ve owner-only olmalı
openssl genpkey -algorithm Ed25519 -out /secure/path/cco-release-key.pem
chmod 600 /secure/path/cco-release-key.pem

# Reproducible build + SPDX SBOM + signed manifest
./scripts/opencode-cco.sh release build \
  --output-dir dist/release \
  --private-key /secure/path/cco-release-key.pem \
  --verify-reproducible

# Doğrulamada bundle içindeki key yerine önceden yayınlanmış trust root kullan
./scripts/opencode-cco.sh release verify \
  --release-dir dist/release \
  --public-key /trusted/path/cco-release-public-key.pem
```

`.github/workflows/release.yml`, `CCO_RELEASE_PRIVATE_KEY_B64` GitHub secret'ı
olmadan fail-closed çalışır. `--ephemeral-key` yalnız CI smoke içindir ve production
release için kullanılmamalıdır.

### 📜 Program Policy
- Örnek policy: `.codex/program-policy.example.json`
- Kural türleri:
  - `approval_required_tools`
  - `denied_tools`
  - `blocked_http_methods`
  - `blocked_paths`
  - `rate_limits`

Not: `opencode.json` plugin konfigürasyonu değiştiği için bu değişikliklerin etkili olması adına OpenCode'u yeniden başlatın.

---


---

## 🔧 Konfigürasyon

### `.env`
```bash
# Claude Code → OpenRouter
ANTHROPIC_AUTH_TOKEN=sk-or-v1-...
ANTHROPIC_BASE_URL=https://openrouter.ai/api
ANTHROPIC_API_KEY=                   # Boş (OAuth devre dışı)

# Alias mapping (Claude Code haiku/sonnet/opus)
ANTHROPIC_DEFAULT_SONNET_MODEL=qwen/qwen3-next-80b-a3b-instruct
ANTHROPIC_DEFAULT_HAIKU_MODEL=meta-llama/llama-3.3-70b-instruct
ANTHROPIC_DEFAULT_OPUS_MODEL=qwen/qwen3-max

# MCP tool içi modeller
CCO_ANALYZE_MODEL=qwen/qwen3.6-plus
CCO_EXPLOIT_MODEL=nousresearch/hermes-4-405b

# Bütçe
CCO_BUDGET_USD=10.00

# Veri dizini
CCO_HOME=~/.cco
```

### `~/.claude.json` (install-cco.sh tarafından oluşturulur)
16 MCP server'ın command/args/env tanımları. Mevcut dosya yedeklenir, sadece
`mcpServers` alanı güncellenir.

---

## Zincir istekleri ve kanıtlı kapanış (P0 düzeltmeleri, 2026-10-29)

`ChainExecutor` bütün HTTP gönderimlerini `ChainTransport` üzerinden yapar.
Son URL, metot ve oturum başlıkları her gönderimden önce politika motoruna
iletilir. İlk istek, login, yeniden deneme, şema düzeltmesi, batch ve burst
aynı toplam/adım bütçesini kullanır. Bir adımı `goto` ile tekrar ziyaret etmek
adımın bütçesini sıfırlamaz. Başarısız veya kısmen tamamlanmış zincirlerde de
`requests_sent`, göndericiye gerçekten ulaşan denemeleri sayar. Varsayılan
HTTP göndericisi yönlendirmeleri otomatik takip etmez.
Program hız limitleri de her gerçek gönderimde uygulanır; bir batch veya
burst, bütün turları için tek bir istek olarak sayılmaz.

Programın zorunlu araştırmacı başlıkları chain isteklerinde ad ve değer
olarak denetlenir; başlık adları büyük/küçük harfe duyarsızdır. Oturumun
login isteği için gerekiyorsa bunları `login_recipe.headers` içinde de
tanımlayın. Eksik başlıkla login gönderilmez; başlık değeri başka bir başlık
altına yazılarak kontrol geçilemez.

`confirmed` durumu için kalıcı, imzası geçerli bir validator kanıtı gerekir:

```bash
python3 scripts/brain.py hypotheses mark --workdir <run> \
  --vector <vector> --status confirmed --validation-id <validator-id>
python3 scripts/brain.py check --spec <run>/specs.json --workdir <run> --closure
python3 scripts/brain.py closure verify --workdir <run>
```

Özet işleme yolu da aynı doğrulamayı yapar; `validator_verified=true` gibi
bir beyan, dosya kanıtının yerini tutmaz. Kanıtın hedefi, vektörün beklenen
bulgu türü ve aktif scope/policy bağı eşleşmelidir. Doğrulanan kimlik ve
kanıt hash'i hipotez kaydına yazılır.

Yeni kapanış şeması `closure/2`'dir. Kapanış yalnızca ilgili confirmed
kayıtların kanıtlarını içerir ve bütün hipotez defterinin hash'ine bağlanır.
`closure verify` defter değişikliğini, kaybolan/değişen kanıtı ve değişen
scope/policy bağını reddeder. `closure/1` kayıtlarını otomatik yükseltmez:
mevcut confirmed kayıtları geçerli `--validation-id` ile yeniden işaretleyin,
ardından `check --closure` çalıştırarak yeni kapanışı üretin.

## Host checkpoint ve açık anahtarla doğrulama (2026-10-29, ikinci dilim)

Yeni imzalar Ed25519 kullanır. Sandbox yalnızca salt okunur açık anahtar
mount'unu ve redakte edilmiş validator artifact'lerini görür. İmzalama
host'ta kalır; ortam değişkeni veya çalışma dizini değişikliğiyle yeni bir
güven kökü seçilemez.

Sandbox içinden kapanış üretmek için
`kali-tools_ledger_checkpoint(workdir=<run>, seal=true, spec_file="specs.json")`
çağrılır. Host aynı `brain.py check --closure` kontrolünü çalıştırır; başarılı
sonuç `check_exit=0, sealed=true` içerir. Sonrasında
`brain.py closure verify --workdir <run>` sandbox'ta açık anahtarla doğrular.
Yukarıdaki doğrudan imzalama komutları host içindir.

Eski HMAC kayıtlarını taşımak için aynı araç `seal=false` ile checkpoint
üretir. Kayıt/artifact içeriği korunur; eski özel anahtar doğrulanamıyorsa
geçiş yapılmaz. MCP süreçleri yeni sürümle başlatılmalıdır. Özel `CCO_HOME`
kullanılıyorsa plugin ve MCP sunucularının aynı state home'a bakması gerekir.

Ayrıntılar ve test kanıtları: [ikinci dilim raporu](ledger-integrity-2026-10-29.md).

