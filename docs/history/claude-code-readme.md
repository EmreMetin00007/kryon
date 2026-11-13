# Tarihsel Claude Code README

2 Kasım 2026 temizliği öncesindeki belge korunmuştur. Sayılar, model seçimi ve
kurulum anlatımı tarihsel referanstır. Güncel rehber: [ana README](../../README.md)
ve [dokümantasyon dizini](../README.md).

---

# 🔴 CCO — Claude Code Offensive Operator

> Otonom bug bounty avcısı & CTF çözücü. **Claude Code CLI** orkestrasyonu,
> **OpenRouter** üzerinden ucuz/sansürsüz modeller, **16 MCP server** ile 289
> güvenlik aracı (deterministik **validator** + **reasoning beyni** + **bug-hunting zekası** dahil). Kali Linux için.
> Sayıların tek kaynağı: `python3 scripts/tool_counts.py` (EXPECTED_TOOL_COUNTS).

**v3.1 HackerAgent → v2.0 CCO geçişi:** 4.327 satır Python orkestrasyon kodu
silindi; tüm orkestrasyon Claude Code'a bırakıldı. Sadece MCP tool'lar, skills,
workflows ve rules kaldı.

---

## 🏗️ Mimari Özet

```
Kullanıcı ──▶ OpenCode / Claude Code (orkestrasyon, OODA döngüsü)
                     │
        ┌────────────┼──────────────────────┐
        ▼            ▼                      ▼
   16 MCP sunucu   Policy Gate        Memory + Graph
   (289 araç)    (scope/onay/denetim)  (SQLite + Kuzu/NetworkX)
        │
        ▼
   Deterministik Validator (XBOW-tarzı kanıt)
```

Katmanlar ve sözleşmeler: [docs/architecture.md](../architecture.md) ·
Operasyon/hardening: [docs/operations.md](../operations.md) ·
MCP kataloğu: [docs/mcp-reference.md](../mcp-reference.md) ·
Metodoloji kaynağı: [CLAUDE.md](../../CLAUDE.md) · OpenCode uyarlaması: [AGENTS.md](../../AGENTS.md)

Veri sınırı: kod bu repoda yaşar; engagement çalışma verisi `CCO_WORKDIR`
(varsayılan `~/cco-work`) altında tutulur ve repoya yazılmaz.

## ⚡ Tek Komutla Kurulum

```bash
git clone https://github.com/EmreMetin00007/AgentCracker.git cco
cd cco
chmod +x install-cco.sh
./install-cco.sh
# Kurulum sırasında OpenRouter API key'iniz sorulur
```

`install-cco.sh` şunları yapar:
- ✅ Kali güvenlik araçları (nmap, sqlmap, ffuf, nuclei, hashcat, john, ...)
- ✅ Python MCP bağımlılıkları (mcp, chromadb, networkx, dnspython, ...)
- ✅ KuzuDB graph backend (`kuzu>=0.11,<0.12`)
- ✅ Claude Code CLI kurulumu (npm -g @anthropic-ai/claude-code)
- ✅ `~/.cco/` veri dizini (DB, loglar, RAG, approvals)
- ✅ `.env` dosyası (OpenRouter yönlendirmesi)
- ✅ `~/.claude.json` — 16 MCP server kaydı (mevcut dosya yedeklenir)
- ✅ (opsiyonel) RAG bilgi tabanını CVE/ExploitDB/payload ile doldurma

---

## 🏁 Başlatma

```bash
cd /path/to/cco
source .env
claude
```

İlk komutlar (slash command'la başlamak en garantili yol):
```
> /tools                                         # Tüm MCP araçlarını listele
> /pwn hedef.com scope: hedef.com                # Otonom recon→exploit zinciri (tek komut)
> /bugbounty hedef.com                           # Bug bounty kampanyası
> /recon-enumeration scanme.nmap.org             # Keşif skill'ini tetikle
> /web-exploit testphp.vulnweb.com/?test=query   # Web zafiyet skill'i
> /llm-security https://hedef.com/api/chat       # LLM/AI uygulama güvenliği
> /ctf-solver picoCTF Binary Exploitation        # CTF orkestratör
> 10.10.10.10 hedefini tara                      # Doğal dil de çalışır
```

**Neden slash command önerilir?** Gerçek testlerde model tool-use davranışı
orkestrator modele göre değişiyor (Llama 3.3 70B `Skill` tool'unu düzgün çağırıyor,
Qwen3-next-80b bazen sadece metin yazıyor). Slash command Claude Code tarafında
handle edilir ve modelden bağımsız olarak her zaman skill'i tetikler.

## ✅ Doğrulama

```bash
python3 -m pytest tests -q
python3 scripts/lab-validate.py --skip-rag --quiet --json
python3 -m pytest tests/test_policy_engine.py tests/test_campaign_runtime.py -q
```

---

## 💸 Token Tasarrufu — MCP Profilleri

Claude Code **her istekte tüm kayıtlı MCP server'ların tool şemalarını** context'e
yükler — 16 server / 289 tool ≈ **~37K token/istek** (sadece şema). Göreve göre
yalnızca ilgili server'ları yükleyerek istek başına 10-24K token tasarruf edilir.

```bash
bash scripts/cco-profile.sh list      # profilleri + tahmini maliyeti gör
bash scripts/cco-profile.sh llm       # sadece LLM-sec görevine geç (~8K, %74↓)
bash scripts/cco-profile.sh web       # web + validator + reasoning görevi (~25K, %20↓)
bash scripts/cco-profile.sh full      # 16 server (varsayılan)
python3 scripts/token-estimate.py     # server + profil token tablosu
python3 scripts/token-estimate.py --current   # aktif profilin maliyeti
```

| Profil | Server | Tool | ~token/istek | Tasarruf |
|--------|---|---|---|---|
| `llm`   | 5 | 59 | ~8.2K  | **%78** |
| `min`   | 4 | 114 | ~19.1K | %48 |
| `ad`    | 6 | 136 | ~22.6K | %38 |
| `recon` | 7 | 138 | ~23.3K | %36 |
| `ctf`   | 7 | 148 | ~24.3K | %33 |
| `web`   | 10 | 182 | ~30.7K | %18 |
| `full`  | 16 | 289 | ~37.2K | %0 |

> Profil değişikliği **yeni bir `claude` oturumunda** etkili olur. Mevcut config
> (doldurulmuş token'lar dahil) korunur; yalnızca `mcpServers` alanı güncellenir.
> Uzun oturumlarda ek tasarruf için Claude Code'un `/compact` komutunu kullan.

---

## 🧪 Test (regresyon)

```bash
pip install pytest
pytest -q                    # 16 server import + 289 tool sayım guard'ı + validator + benchmark
```

`tests/test_mcp_servers.py` her server'ı import eder, tool sayısını doğrular
(yeni tool eklerken `EXPECTED_TOOL_COUNTS` güncellenmeli) ve metadata + pure-function
temel çağrılarını test eder. `tests/test_validator.py` deterministik oracle'ları,
`tests/test_reasoning.py` reasoning beynini (EV/öğrenme/plan), `tests/test_hunter.py`
bug-hunting zekasını (predict/authz/abuse/variant/coverage/fanout/RAG),
`tests/test_xbow_benchmark.py` benchmark harness'ını (mock) doğrular. Tamamen offline çalışır.

### 🔬 Canlı Lab Doğrulaması (`mcp-hunter` uçtan uca)

Kasıtlı-zafiyetli bir **loopback** hedefe (`scripts/lab/vuln_lab.py`) karşı tüm hunter
zincirini **gerçekten** (`live=True`) koşturur — sadece `127.0.0.1`, yetkisiz/gerçek hedefe
dokunmaz. Kali'de de aynen çalışır:

```bash
bash scripts/lab-validate.sh        # veya: python3 scripts/lab-validate.py
```

Doğruladıkları (9/9): `enrich_with_rag` inline PoC hit (RAG önce `rag_ingest_writeup` ile
doldurulur) + CVE çıkarımı · `predict_vulnerabilities` · `coverage_report` kör nokta ·
`build_authz_matrix`→**canlı**→`analyze_authz_result` ile **BOLA + unauth admin CONFIRMED** ·
`generate_abuse_cases` + canlı negatif-fiyat iş mantığı · `auto_fanout_variants(live=True)`
ile **XSS + SQLi LIKELY** triage. Gerçek hedefte: `scripts/lab/vuln_lab.py` yerine kendi
**yetkili** kapsamını koy, identity token'larını `auto_fanout_variants(headers=...)` /
`build_authz_matrix(identities=...)`'a ver.

---

## ⚠️ Önemli Notlar

### Thinking-only modeller
`qwen/qwen3.6-plus` gibi bazı modeller **sadece `thinking` block** döndürür —
Claude Code session modeli olarak kullanırsan `result` boş görünür. Bu modelleri
sadece **MCP tool içinden** programatik olarak çağır (hali hazırda `qwen_analyze`
bu modeli kullanıyor). Session modeli olarak `qwen3-next-80b-a3b-instruct`
(non-thinking) veya `llama-3.3-70b-instruct` kullan.

### Root/sudo ortamında Claude Code
Container veya Kali root session'unda `IS_SANDBOX=1` env variable'ını set et;
aksi halde `--dangerously-skip-permissions` reddedilir.

### Bütçe ve maliyet takibi
OpenRouter her yanıtın `usage.cost` alanını döndürür. `mcp-telemetry` server
her LLM/tool çağrısını kaydeder. Session özeti için:
```
claude -p "telemetry ile bu session'daki toplam maliyeti göster"
```

---

## ⚠️ Yasal Uyarı

Bu sistem **yalnızca yasal ve etik** güvenlik testi amaçlarıyla kullanılmalıdır:

- ✅ Yazılı izin aldığınız hedefleri test edin
- ✅ Bug bounty program kurallarına uyun
- ✅ CTF yarışmalarında sportif davranın
- ✅ Zafiyetleri sorumlu şekilde raporlayın
- ❌ Yetkisiz hedeflere saldırmayın
- ❌ Bulunan verileri kötüye kullanmayın

---

*Developed for ethical security research and CTF competitions.*
*4.327 lines of Python orchestration → 0. MCP tools: 289 (16 server; deterministik validator + reasoning beyni + bug-hunting zekası dahil). Skills: 24. XBOW benchmark harness dahil. Model choices: unlimited.*
