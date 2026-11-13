# MCP Referansı

> Sunucu/araç kataloğu, RAG, reasoning, hunter ve validator referansı.

## ⚙️ 16 MCP Server — 292 Tool

> Sayıların tek kaynağı: `python3 scripts/tool_counts.py` (MCP tool dekoratörleri).
> Bu toplam kaynakta bildirilen araçları sayar. Envanter ve profiller
> [config/mcp-servers.json](../config/mcp-servers.json) ile
> [config/profiles.json](../config/profiles.json) içinde tanımlıdır; çalışan Python
> solver'ı ayrıca kendi açık, sınırlı araç kataloğunu kullanır.

| Server | Tool | Öne Çıkanlar |
|--------|---|--------------|
| `kali-tools` | 93 | `nmap_scan_structured`, `sqlmap_test_structured`, `ffuf`, `nuclei`, `hydra`, `qwen_analyze`, `generate_exploit_poc`, `parallel_llm_analyze`, `swarm_dispatch`, `interactsh_*` |
| `web-advanced` | 30 | GraphQL injection, JWT attacks, OAuth/SAML, HTTP smuggling, cache poisoning, prototype pollution, WebSocket fuzz, IDOR matrix, `generate_stealth_curl` |
| `ctf-platform` | 14 | `ctfd_list_challenges`, `htb_submit_flag`, `thm_get_room`, decode/hash yardımcıları |
| `validator` 🆕 | 27 | **Deterministik exploit doğrulama (XBOW-tarzı):** `validate_sqli` (differential boolean), `validate_ssti` (aritmetik oracle), `validate_command_injection` (echo+timing), `validate_path_traversal`, `validate_xss_reflection`, `validate_open_redirect`, `validate_ssrf_oob`+`confirm_oob_callback` (imzalı kolektör doğrulaması; sonuç henüz inconclusive), `validate_xxe`, `validate_auth_bypass`, `validate_idor`, `validate_finding`, `generate_validation_report` |
| `ad-tools` | 12 | Kerberos (AS-REP/Kerberoast), SMB enum, NTLM, BloodHound veri toplama |
| `memory-server` | 15 | `store_finding`, `store_credential`, `query_attack_paths`, `suggest_next_action` |
| `container-tools` | 10 | Container escape, K8s RBAC, secret dump, privileged pod, Helm analizi |
| `osint-tools` | 9 | `crtsh_subdomains`, `dns_recon`, `dns_zone_transfer`, `wayback_urls`, `rdap_whois`, `username_osint`, `github_code_search`, `password_spray_structured` |
| `telemetry` | 10 | `log_tool_call`, `log_llm_call`, `get_cost_summary`, `get_savings_report`, `get_metrics_dashboard` |
| `browser` | 20 | `browser_screenshot`, `browser_extract_links`, `browser_security_headers`, `browser_cookie_audit`, `browser_capture_requests`, `browser_console_logs`, `browser_dom_xss_probe` (Playwright) |
| `reasoning` 🆕 | 20 | **Biliş/beyin katmanı (DeepSeek-destekli):** `deep_think` (bayrak gemisi — recon→zincir→doğrula→skorla orkestratörü), `plan_attack_tree` (Bayesçi EV + ToT), `next_best_action`, `reason_reflexion` (actor↔critic self-correct), `critic_review`, `record_lesson`, `recall_lessons`, `lesson_stats` (kalıcı öğrenme) · **Kill-Chain:** `compose_attack_chains` (çok-adımlı zincir), `kill_chain_report` · **Payload Evo:** `evolve_payload` (WAF-aware), `record_payload_result` · **Kalibre güven:** `exploitability_score` · **Skill Router:** `recommend_skills` (fingerprint→/skill) · **Reverse-Proxy + WAF:** `fingerprint_waf`, `classify_response`, `discover_origin` (CDN arkası origin IP → WAF baypas), `adaptive_evasion_step` |
| `rag-engine` | 7 | `rag_search`, `rag_similar_exploits`, `rag_ingest_cve`, `rag_ingest_exploitdb`, `rag_ingest_writeup`, `rag_bulk_ingest`, `rag_stats` (ChromaDB) |
| `hunter` 🆕 | 16 | **Bug-hunting zekası (tarayıcıların kaçırdığı yüksek-ödüllü sınıflar):** `predict_vulnerabilities` (tech parmak izi → muhtemel sınıf + CVE ailesi + hedefli hipotez), `build_authz_matrix` (BOLA/BFLA/IDOR çok-kimlikli farksal test matrisi), `analyze_authz_result` (owner-vs-attacker farksal ORACLE → yetki ihlali kanıtı), `generate_abuse_cases` (fiyat/miktar/rol/kupon/iş-akışı/race business-logic abuse), `hunt_variants` (doğrulanan bug'ı kardeş param/endpoint/method/subdomain'de çoğalt), `coverage_report` (attack-surface × vuln-class kapsama + kör nokta = kaçırılan bug guard), `auto_fanout_variants` (varyantları **otomatik çalıştır+doğrula** → kali-tools curl + validator köprüsü; PLAN/LIVE), `enrich_with_rag` (predict çıktısını **rag-engine**'e besle → CVE PoC/exploit çek) |
| `llm-security` | 6 | `llm_prompt_injection_probe`, `llm_system_prompt_leak`, `llm_jailbreak_test`, `llm_data_leak_probe`, `generate_injection_payloads`, `llm_owasp_top10_checklist` (OWASP LLM Top 10) |
| `agent-browse` | 2 | Guardrailed agentic browser (browser-use, self-hosted) |
| `otp` | 1 | `get_latest_otp` — IMAP'taki son OTP kodu |

> Sunucular [config/mcp-servers.json](../config/mcp-servers.json) ve profiller
> [config/profiles.json](../config/profiles.json) içinde tanımlıdır. `browser` için
> Playwright gerekir. RAG bilgi tabanı ayrı ve kontrollü
> `python3 scripts/rag-bootstrap.py` akışıyla doldurulur.

### Yerel kanıt checkpoint'i

`kali-tools_ledger_checkpoint(workdir, seal=false, spec_file="specs.json")`
host tarafında deneme defterini doğrular ve eski HMAC kanıtları için açık
anahtarla doğrulanabilen geçiş receipt'leri üretir. `seal=true`, koşunun
spec ve validator kontrollerinden geçen kapanışını da üretir; başarılı
sonuç `check_exit=0, sealed=true` içerir. Araç ham bir payload imzalamaz.
Sandbox kapanışı salt okunur açık anahtarla doğrular; özel anahtar açılmaz.
Son işçi görevinde araç `tool_justification` ile ayrıca seçilir.

Operasyon ve kapanış komutları: [operations.md](operations.md).

### RAG v2 bootstrap ve kurtarma

RAG v2, Chroma semantic aramayı SQLite FTS5 exact-token aramasıyla birleştirir.
CISA KEV ve NVD doküman olarak indekslenir; FIRST EPSS sayısal risk kataloğunda
tutulur. Her kaynak hash, revision, lisans, güven seviyesi ve transform sürümüyle
manifestlenir. Bootstrap tek-yazarlıdır ve kesilirse tamamlanan embedding'leri
yeniden üretmeden eksik Chroma/FTS kayıtlarını uzlaştırır.

```bash
# Kontrollü high-signal bootstrap
CCO_HOME=.cco python3 scripts/rag-bootstrap.py --cve-count 100 --top-epss 750

# Tamlık, snapshot hash'i ve Chroma/FTS eşitliği
CCO_HOME=.cco python3 scripts/rag-bootstrap.py --doctor --json

# İstatistik ve retrieval kalite raporu
CCO_HOME=.cco python3 scripts/rag-bootstrap.py --stats --json
CCO_HOME=.cco python3 scripts/rag-bootstrap.py --evaluate-only

# Ağ kullanmadan yarım kalmış CISA snapshot'ını kurtarma
CCO_HOME=.cco python3 scripts/rag-bootstrap.py --kev-only \
  --from-snapshot .cco/rag_db/raw/cisa-kev-<sha256-prefix>.json
```

`ready=true` yalnız source manifestleri `ok`, şema/transform uyumlu, raw snapshot
hash'leri geçerli ve Chroma ile FTS kimlik/içerikleri birebir eşitse döner. RAG
çıktıları her zaman güvenilmeyen veri kabul edilir; doğrudan talimat veya doğrulanmış
exploit sayılmaz.

---

## 🧠 Reasoning Beyni — Güçlü LLM Çekirdeği 🆕

CCO'nun zekası tek bir session modelinden ibaret değil. `mcp-reasoning` server'ı
ajana gerçek bir **biliş katmanı** ekler — üç pilar birbirini besler:

| Pilar | Ne yapar | Tool'lar |
|---|---|---|
| **1a Reflexion** | actor→critic→(validator)→retry: kendi exploit'ini eleştirir, başarısızsa öğrenip revize eder → halüsinasyonsuz | `reason_reflexion`, `critic_review` |
| **1d Bayesçi planlama** | knowledge-graph'i okur, her vektörü beklenen-değer (EV) ile puanlar, tree-of-thought zinciri kurar | `plan_attack_tree`, `next_best_action` |
| **1e Kalıcı öğrenme** | "neyin işe yaradığı" derslerini saklar; öğrenilen win-rate'ler planlayıcının önceliklerine karışır → **zamanla akıllanır** | `record_lesson`, `recall_lessons`, `lesson_stats` |

**Bayrak gemisi — tek çağrı:**
```
mcp__reasoning__deep_think(task, target, scope, context)
  → recall_lessons (geçmiş deneyim) + plan_attack_tree (Bayesçi EV) + reason_reflexion (self-correct)
  → chosen_action.validate_with ile DOĞRULA → exploit → record_lesson
```

**Altın döngü (beynin akıllanması):**
```
deep_think → validator (deterministik) → exploit → record_lesson(worked=?)
     ▲                                                        │
     └──────── öğrenilen win-rate → EV priors'ı günceller ◄───┘
```

Modeller env ile güçlendirilebilir (LLM yoksa EV/öğrenme yine çalışır):
```
# DeepSeek (önerilen güçlü reasoning) — anahtar varsa beyin OTOMATİK DeepSeek'e geçer:
export DEEPSEEK_API_KEY=sk-...        # actor=deepseek-reasoner, critic=deepseek-chat
# veya ~/.cco/config.yaml →  llm:\n  deepseek_api_key: sk-...

# Override (opsiyonel):
CCO_REASON_MODEL=deepseek-reasoner    # actor/planner (DeepSeek varsayılanı)
CCO_CRITIC_MODEL=deepseek-chat        # critic (actor'dan farklı = daha sert eleştiri)
# DeepSeek yoksa OpenRouter'a düşer: qwen/qwen3.6-plus + nousresearch/hermes-4-405b
# Daha üst seviye için CCO_REASON_MODEL=deepseek-v4-pro (thinking) da kullanılabilir
```
> ⚠️ API anahtarını **asla** koda/commit'e koyma — yalnızca env veya `~/.cco/config.yaml`.
Detay: skill `deep-reasoning`.

---

## 🎯 Bug-Hunting Zekası — `mcp-hunter` (scanner → hunter) 🆕

Reasoning beyni "hangi vektör en yüksek EV?" sorusunu çözer; **`mcp-hunter`** ise o zekayı
otomatik tarayıcıların **kaçırdığı** ve bug bounty'de **en çok ödeyen** sınıflara yöneltir.
Hepsi deterministik çekirdek (offline test edilir); LLM varsa H1/H3 zenginleşir.

| Tool | Ne yapar | Neden kritik |
|---|---|---|
| **`predict_vulnerabilities`** | Teknoloji parmak izinden (stack/banner/memory) muhtemel zafiyet sınıflarını + CVE ailelerini + hedefli hipotezi DETERMİNİSTİK tahmin eder; RAG sorgusu + skill + validator hook verir | "Körlemesine tarama" yerine **stack'e özel hipotez** → ilk denemede doğru vektör |
| **`build_authz_matrix`** | anon/userA/userB/admin × kaynaklar için **BOLA/BFLA/IDOR farksal test matrisi** üretir (object-level vs function-level sınıflama + id substitution) | OWASP #1 + API #1/#5 — tarayıcıların yetki bağlamı yok, **en çok ödeyen** sınıf |
| **`analyze_authz_result`** | owner ve attacker yanıtlarını farksal oracle ile değerlendirir | Aday üretir; raporlanabilir bulgu için sahiplik ve imzalı validator kanıtı ayrıca gerekir |
| **`generate_abuse_cases`** | fiyat/miktar/rol/kupon/iş-akışı/OTP semantiğine göre **business-logic abuse** + jenerik race/replay/mass-assignment | Mantık hataları imza ile bulunamaz → **AI'nın tarayıcıyı ezdiği** sınıf |
| **`hunt_variants`** | Doğrulanan bir bug'ı kardeş param/endpoint/method/content-type/konum/subdomain'de **sistematik çoğaltır** | Tek bug → sürü; bug bounty avcısının elle yaptığı çoğaltmanın otomasyonu |
| **`coverage_report`** | Bilinen hedef/metot/sınıf/parametre ve planlı kimlik hücreleri için kanıta bağlı matris; son imzalı koşu | `enqueue_gaps=True` ve `campaign_id` ile uygun boşluklar tekil görevlere dönüşür; `max_attempts=3` (1–3) ilk deneme sınırını belirler. Oturum sonrası devam aynı görev ve kalan bütçeyle yapılır |
| **`coverage_report_run`** | `target` ve `run_id` ile belirli koşunun kanıta bağlı matrisini gösterir | Koşuların test sonuçları birbirine karışmaz; envanter günceldir |
| **`run_web_loop`** | Yetkili keşif, istek bağlamlı fuzz ve sahipliği belirtilen GET authz doğrulaması | Seçmeli `gap_ref` yalnız bir kapsam boyutunu doğrular; bütçe ve oturum sınırları [operations.md](operations.md) içinde özetlenir |

Yerel native kampanyada desteklenen Hunter/HTTP validator/tek kullanımlık
browser yolları aynı görev rezervasyonunu kullanır. Bağımsız araçlarda ortak
çıkış garantisi bu tablo üzerinden varsayılmamalıdır; ortak bütçe kuralları
`scripts/wire_budget.py` tarafından uygulanır.
| **`auto_fanout_variants`** 🆕 | Doğrulanan bug'ın varyantlarını **otomatik çalıştırılabilir** yapar: PLAN modu `mcp__kali-tools__curl_request` + `mcp__validator__*` çağrıları döndürür; LIVE modu GET-tabanlı güvenli varyantları gerçekten gönderip hızlı triage oracle uygular → umut verenler validator'a devredilir | Variant analizini **otomasyona** bağlar (kali-tools köprüsü) — tek bug'dan sürüye, elle koşturmadan |
| **`enrich_with_rag`** 🆕 | `predict_vulnerabilities` çıktısını **rag-engine**'e besler: tahmin CVE'lerini çıkarır, RAG'da inline semantic arama yapıp eşleşen **PoC/exploit**'leri çeker + `rag_ingest_cve`/`rag_ingest_exploitdb`/`rag_search` ingest planı üretir | "Stack tahmini → **somut PoC**" zincirini otomatikleştirir |

**Bug-hunting döngüsü (deep_think'i tamamlar):**
```
predict_vulnerabilities → enrich_with_rag (CVE PoC çek) → coverage_report (kör nokta?)
   → build_authz_matrix → (test çalıştır) → analyze_authz_result (CONFIRMED?)
   → store_finding → auto_fanout_variants (otomatik çoğalt+doğrula) → record_lesson
   → coverage_report (% arttı mı?)
```
Tetikleyici skill: `/access-control-hunting` (BOLA/BFLA/IDOR + iş mantığı metodolojisi).


---

## 🧪 Deterministik Validator (XBOW-tarzı) + Benchmark 🆕

CCO'nun XBOW'a karşı en büyük açığı **deterministik doğrulama** ve **bağımsız
kıyas kanıtıydı**. v3.2 bunu iki parçayla kapatır:

**1) `mcp-validator` — "yaratıcı AI keşfeder, mantık doğrular".** Bir bulgunun
*gerçekten* exploit edilebilir olduğunu LLM görüşü değil, **nesnel oracle'larla**
değerlendirir (differential boolean SQLi, aritmetik SSTI, echo-token/timing cmdi,
dosya-imzası LFI/XXE, Location-header open redirect...). OOB kolektör imzası
yalnız olayın kolektör tarafından imzalandığını doğrular; kaynak atfı olmadan
SSRF sonucu `INCONCLUSIVE` kalır.
Her doğrulama `~/.cco/validations/` altına **reproducible audit-trail** olarak yazılır.

```
# Recon/exploit sırasında bir şüphe → doğrula → CONFIRMED ise raporla
mcp__validator__validate_sqli(target_url="http://t/item?id=1", param="id")
mcp__validator__validate_finding(vuln_type="ssti", target_url=..., params_json='{"param":"name"}')
mcp__validator__generate_validation_report(result_json=...)   # XBOW-tarzı PoC raporu
```

**2) XBOW Benchmark Harness** — CCO'yu XBOW'un 104-challenge public benchmark'ına
karşı çalıştırıp skorlar (başarı = gerçek flag, yalnızca "tespit" değil):

```bash
python3 scripts/xbow_benchmark.py list  --mock              # gömülü mock seti (offline)
python3 scripts/xbow_benchmark.py run   --all --mock        # harness mantığı testi (SELF-TEST)
python3 scripts/xbow_benchmark.py list  --repo ~/xbow-benchmarks   # gerçek 104 challenge
python3 scripts/xbow_benchmark.py run   --all --repo ~/xbow-benchmarks --timeout 1200 \
    --resume --max-cost 30 --junit ~/.cco/benchmark/junit.xml      # resume+bütçe+CI export
python3 scripts/xbow_benchmark.py score                     # kategori/level scorecard + XBOW kıyas
```

**v1.1 kanıt bütünlüğü:** harness artık (1) **anti-cheat echo guard** (flag
prompt'taysa SOLVED sayılmaz), (2) **validator-onaylı çözüm** metriği (oracle
kanıtı vs LLM iddiası), (3) **reprodüksiyon metadata** (mode/model/git_commit/host)
+ per-challenge transcript, (4) mock scorecard'a **"SELF-TEST — kanıt değil"
watermark**'ı (mock skoru XBOW ile kıyaslanmaz). Yayınlanabilir kanıt = `--repo`
(docker) koşusu.

---

