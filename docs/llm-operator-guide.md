# Kryon LLM Operator Guide (`cco-agent`)

Bu rehber, hedef uygulama üzerinde doğrudan ağ isteği atmak yerine **yalnızca Kryon (`cco-agent`)** arayüzünü kullanan bir dış LLM (ör. Codex, Claude Code, Gemini CLI, Antigravity) için sade çalışma sözleşmesini tanımlar.

## Temel Kural: Yalnızca Kryon Üzerinden Çalış

- Hedef uygulamaya doğrudan `curl`, `python`, `httpx` veya ham Playwright ile istek **gönderme**.
- Tüm keşif, oturum yönetimi, doğrulama (`DifferentialOracle`) ve raporlama işini `cco-agent` yürütür.
- Çıktı dizinleri her zaman `~/cco-work/...` (`CCO_WORKDIR`) altında olmalıdır; repo köküne çalışma verisi yazma.
- Gizli bilgileri (`.env`, `config/llm.json`, çerez, token, parola, özel başlık değerleri) asla okuma veya ekrana basma.

## 5 Adımlı Standart Akış

### 1. Yapılandırmayı ve Profilleri Kontrol Et (0 Ağ İsteği)

```bash
cco-agent check-config --provider-config config/llm.json
cco-agent presets --format json
```

Hazır profiller (`--preset`):

| Preset | Kullanım Amacı | Mod | HTTP / Token / Süre | Hız Limiti |
| :--- | :--- | :--- | :--- | :--- |
| `quick` | Hızlı ön keşif / triage | `monolithic` | 120 / 250K / 300s | Yok |
| `standard` | Dengeli kapsamlı değerlendirme + Stage 0 crawl | `sharded` (3) | 300 / 1M / 900s | Yok |
| `bounty-safe` | Bug bounty için muhafazakâr profil (`GET,HEAD`, yavaş hız) | `sharded` (2) | 200 / 750K / 900s | 2.0 req/s |
| `deep` | Derin çoklu-shard tarama + Stage 0 crawl | `sharded` (5) | 600 / 2M / 1800s | Yok |

### 2. Önce Plan Üret (`cco-agent plan` — 0 Trafik, 0 LLM Maliyeti)

`plan` komutu `--execute` bayrağını **reddeder**; yalnızca `agentic-plan.json` üretir:

```bash
cco-agent plan \
  --preset bounty-safe \
  --target https://target.example.invalid \
  --scope-file .codex/scope.json \
  --allow-non-loopback \
  -H "X-Program-Tag: authorized-test" \
  --output-dir ~/cco-work/target-run
```

Veya tekrar kullanılabilir bir `cco-run/1` yapılandırma dosyası ile ([config/run.example.json](../config/run.example.json)):

```bash
cco-agent plan --config ~/cco-work/target/run.json
```

> **Güvenlik Sınırı:** `execute`, `allow_non_loopback`, `authorize_live_provider` ve `live_authorization_reason` alanları `--config` JSON dosyasında **yasaktır**; bu güvenlik kapıları her zaman CLI'dan açıkça verilmelidir.

### 3. Planı Özetle ve Operatör Onayı Al

`cco-agent status ~/cco-work/target-run` çıktısından hedef, kapsam, izinli HTTP metotları, özel başlık **adları** (değerleri değil) ve bütçeleri kontrol edip kullanıcı onayı al.

### 4. Onay Sonrası Çalıştır (`cco-agent run --execute`)

Yerel (loopback) hedef için:

```bash
cco-agent run \
  --preset standard \
  --target http://127.0.0.1:8000 \
  --output-dir ~/cco-work/demo-run \
  --execute
```

Yetkili dış (non-loopback) hedef + uzak LLM sağlayıcı için:

```bash
cco-agent run \
  --config ~/cco-work/target/run.json \
  --allow-non-loopback \
  --authorize-live-provider \
  --live-authorization-reason "approved-engagement" \
  --execute
```

### 5. Sonucu Oku ve Raporla

```bash
cco-agent status ~/cco-work/target-run
cco-agent report ~/cco-work/target-run --format all
```

> **İnsan Operatör İçin Canlı TUI:** Dış LLM JSON çıktılı `status` komutunu kullanırken, operatör aynı koşuyu başka bir terminalden salt-okunur canlı TUI ile izleyebilir (`cco-agent watch ~/cco-work/target-run`) veya doğrudan `cco-agent run ... --execute --tui` ile başlatabilir.

- Bulguları yalnızca `findings.json` ve `report.md` içindeki kanıta dayalı kayıtlardan aktar; model metnine dayanarak teyit edilmemiş iddia üretme.
- Raporlardaki `NOT TESTED` bölümünü her zaman koru.

## Dış LLM İçin Yeterli Olan Temel Bayraklar

Düşük seviyeli ayarlar (`--epoch-char-limit`, `--cache-token-weight`, `--shard-token-quota` vb.) preset tarafından yönetilir. Dış LLM'in neredeyse her zaman yalnızca şu bayraklara ihtiyacı vardır:

- `--preset quick|standard|bounty-safe|deep` (`standard`, `bounty-safe` ve `deep` deterministik 0-LLM `--prescan` ön taramasını otomatik açar)
- `--prescan` / `--no-prescan` / `--prescan-max-requests <N>` (0-LLM-token CORS/redirect/GraphQL/secret + 2-aktörlü BOLA/BFLA ön matrisi)
- `cco-agent recon --target <url> --output-dir <dir>` (kapsam içi pasif CT + AssetGraph keşfi; `--execute` olmadan 0 trafik planı)
- `--config <run.json>` (`cco-run/1`)
- `--target <url>`
- `--output-dir <dir>`
- `--scope-file <scope.json>` + `--allow-non-loopback` (non-loopback için zorunlu)
- `-H "Ad: Değer"` (tekrarlanabilir özel başlık)
- `--storage-state alias=/path/to/storage.json` (tarayıcı oturumu aktarımı)
- `--allowed-methods GET,POST` / `--discovery-hint /api` / `--tech-hint nextjs`
- `--execute` + (uzak LLM için) `--authorize-live-provider --live-authorization-reason "..."`
