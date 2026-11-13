# Hackagent–OpenCode: Güncel Sistem Taslağı — Nasıl Çalışıyor?

> Tarih: 2026-11-02 · Durum: **çalışma ağacına göre güncel mimari haritası** (kod değişikliği yok)
> Baz: `HEAD e839e23` + 92 değişmiş / 100 takipsiz dosya. Bu belge kaydedilmiş (commit) koda göre **değildir**; ağaçtaki güncel koda göredir.
> Kaynak: 7 alt sistemin kod okuması + bağımsız eleştiri turu. Doğrulanamayan maddeler §7'de açıkça listelidir.

## 0. Bu Belge Nasıl Okunur?

sistem üç cümleyle anlaşılır:

1. **Planlayan çalıştırmaz, çalıştıran planlamaz.** `kalibounty` ajanı + `brain.py` yalnızca deterministik görev sözleşmesi (TaskSpec) üretir; tek yürütücü `worker`'dır.
2. **Hiçbir bulgu LLM sözüyle kesinleşmez.** `CONFIRMED` yalnızca validator'ın imzalı artefaktıyla mümkündür; LLM görüşü en fazla `POSSIBLE/LIKELY` bandına çıkar.
3. **Her araç çağrısı ve her gerçek HTTP isteği iki ayrı kapıdan geçer:** çağrı kapısı (plugin → PolicyEngine) ve tel (wire) kapısı (adaptör içinde, taşınan gerçek URL üzerinden).

Karışıklık hissi bu üç kuraldan değil, §6'daki eski katmanların aynı ağaçta yaşamasından gelir.

---

## 1. Sistem Tek Paragrafta Ne Yapar?

KaliBounty/OpenCode; kapsam-öncelikli (scope-first), politika-kapılı, deterministik doğrulamaya dayalı **otonom bug-bounty operatörüdür**. OpenCode'da kayıtlı tek birincil ajan `kalibounty` (varsayılan ajan, [opencode.json:280-281](/root/hackagent-opencode/opencode.json)), İnce Beyin (Thin Brain) ile görevi fazlara böler; `worker` MCP araçlarıyla keşif/tarama yapar; `hunter` aday zafiyetler üretir; `validator` deterministik oracle ile imzalı kanıt artefaktı üretmeden hiçbir bulgu `CONFIRMED` olamaz; `memory-server` yalnızca doğrulanmış + raporlanabilir bulguları kalıcılaştırır; kapsam (coverage) boşlukları kampanya kuyruğuna görev olarak geri beslenir.

---

## 2. Bir Görevin Yaşam Döngüsü (Adım Adım)

```
Kullanıcı → kalibounty ──plan──▶ brain.py ──TaskSpec──▶ worker ──▶ security-gate ──▶ MCP araçları ──▶ hedef
                ▲                    │                       │                                    │
                └── özet (JSON) ─────┴── next_spec ──────────┘         hunter → validator → imzalı artefakt → memory
                                                                                    │
                                              coverage boşluğu ──▶ campaign kuyruğu ──▶ campaign_worker ──┘
```

### 2.1 Giriş

- OpenCode `kalibounty` ile açılır; talimatlar `CLAUDE.md` + `rules/` üzerinden yüklenir ([opencode.json:283-287](/root/hackagent-opencode/opencode.json)).
- Oturum bulguları için önce `.cco/session-vault.json` okunur ([kalibounty.md:17-19](/root/hackagent-opencode/.opencode/agents/kalibounty.md)).
- İlk iş her zaman kapsam analizi + pasif plandır; aktif araç, kapsam ve onay olmadan çalışmaz.

### 2.2 Planlama — İnce Beyin

- Girdi: `brain.py plan --target <t> --workdir <run> [--kind web|host|llm]`, ardından `hypotheses init`.
- Fazlar: varsayılan `(recon, enum, access, report)`; `llm` türünde `(recon, enum, llm)`; kimlikli (authed) türde `(seed, authz, access, report)` ([brain.py:251-258](/root/hackagent-opencode/scripts/brain.py)).
- Dikkat: Faz listesinde **`privesc` yoktur**. `AGENTS.md` privesc vaat eder ama [brain.py](/root/hackagent-opencode/scripts/brain.py) ve [orchestration_spec.py](/root/hackagent-opencode/scripts/orchestration_spec.py) içinde şablonu, TaskSpec'i ve dispatch yolu bulunmaz (0 isabet, eleştiri turunda doğrulandı). En yakın karşılıklar `access/authz/seed` fazlarıdır.
- Çıktı: birbirine `depends_on` ile zincirli TaskSpec'ler; görev başına en fazla 30 araç çağrısı ([orchestration_spec.py:67](/root/hackagent-opencode/scripts/orchestration_spec.py)), faz varsayılanı 20/25 çağrı.

### 2.3 TaskSpec Sözleşmesi

TaskSpec ([orchestration_spec.py:142-158](/root/hackagent-opencode/scripts/orchestration_spec.py)) şunları sabitler: kesin hedef, kesin MCP araç adları (`Tools:` satırı, kapı tarafından zorlanır), izinli komutlar, kanıt dizini, çağrı bütçesi, bağımlılık. Çekirdek araç seti 29 araçtır; kaynağı [orchestration_spec.py CORE_TOOLS](/root/hackagent-opencode/scripts/orchestration_spec.py:27), [mcp-core-tools.json](/root/hackagent-opencode/config/mcp-core-tools.json) yalnızca aynasıdır. Çekirdek dışı araç görev başına gerekçe ister.

Worker, eksik hedef/kapsam/`Tools:`/komut/kanıt dizini görürse görevi `INCOMPLETE_SPEC` ile reddeder ve önce iskelet (skeleton) özet yazar. Eski [task_spec.py](/root/hackagent-opencode/scripts/task_spec.py) şeması hâlâ durur ama beyin onu kullanmaz; eski şemayla üretilen prompt `Tools:` satırı taşımadığı için kapıda reddedilir (§6).

### 2.4 Dağıtım ve Özet Döngüsü

- Her batch `worker`'a `task(subagent_type=worker)` ile gider; beyin kendisi `bash/kali/validator/hunter/browser` çağıramaz.
- Worker sabit özet şemasıyla (`phase/target/status/evidence/findings/next`) tek JSON döner. `next_spec()` ilk bağımlılığı tamamlanmış görevi verir; `blocked/failed` veya bozuk özet zinciri durdurur, `partial` ilerletir.
- Kapanış (`closure.json`) yalnızca kapı imzalıdır; elle yazılamaz.

### 2.5 Kapı — Her Çağrı, Her İstek

1. **Çağrı kapısı:** [security-gate.js](/root/hackagent-opencode/.opencode/plugins/security-gate.js) her `tool.execute.before` için [policy_gate_cli.py](/root/hackagent-opencode/scripts/policy_gate_cli.py) üzerinden `PolicyEngine.validate_tool_invocation` çalıştırır ([policy_engine.py:2290](/root/hackagent-opencode/scripts/policy_engine.py)). Not: Belgelerde geçen `validate_invocation` adlı sembol kodda **yoktur**; gerçek ad `validate_tool_invocation`'dır.
2. **Sandbox:** İzin alan `bash`, bubblewrap altında yeniden yazılır: tüm capability'ler düşürülür, PID/IPC/UTS (+ ağsızsa net) namespace, repo + çalışma dizini yazılabilir, kimlik depoları maskelenir, `.env*` `/dev/null`'a bağlanır. `bwrap` yoksa bash kilitlenir.
3. **Tel (wire) kapısı:** Adaptörler (kali curl, browser, validator, hunter, campaign worker, member_login) gerçek taşınacak URL/metot/başlık üzerinden `validate_wire_invocation` + `WireBudget` tüketimi yapar. Çağrı kapısı çağrı başına fan-out ağırlığı keserken tel kapısı gerçek istek başına 1 keser; yönlendirme (redirect) ve çok istekli araçlar bu yüzden ikinci kez yargılanır.

Kapı sırası kodda tek zincirdir; özetle: kör-yazma → gizli yol → görev sözleşmesi → bilinmeyen araç → izin → yıkıcı bash → güvensiz argüman → (yerel bash geçişi) → hedef/kapsam → metot/yol/başlık → program politikası → arka plan işi/fuzz bütçesi → onay → bash bütçesi → zaman bütçesi → hız limiti → tekrar freni. Her karar (izin/red) `audit.db`'ye yazılır.

### 2.6 Keşif → Aday → Doğrulama → Kayıt

1. **Keşif:** `kali-tools` + tarama ile yüzey toplanır; [store.py ingest_records](/root/hackagent-opencode/mcp-servers/mcp-memory-server/cco_surface_core/store.py) ile `agent_memory.db` içindeki `attack_surface` (metot + parametre şeması) ve `endpoints` tablolarına yazılır.
2. **Aday:** `hunter` tahmin + fuzz kanarya planı üretir; hafif oracle `LIKELY` derse aday, opak `request_ref` (TTL 300 sn, gövde/başlık kuyruğa kopyalanmaz) ile validator kuyruğuna girer. Kör (blind) BOLA adayı yalnızca açık sahip işaretiyle (owned marker) üretilebilir.
3. **Doğrulama:** `execute_web_loop` adayları AUTO / AUTHZ (salt GET) / OOB sınıflarına ayırır, mir alınan tel kapısıyla validator'a gönderir. Validator deterministik oracle çalıştırır (diferansiyel, işaret eşleşmesi, zamanlama vb.) ve HMAC-imzalı artefaktı `validations/*.json` altına yazar. Yalnızca 2xx yetmez; işaret/etki kanıtı yoksa sonuç `INCONCLUSIVE` kalır.
4. **Onay:** Hunter artefaktı yeniden yükler: imza, içerik hash'i, güncel kapsam/politika, isteğin gerçekten gözlemlenmiş olması denetlenir. Geçerse `store_validated_finding` yalnızca `verified + reportable` bulguyu `findings` + bilgi grafiğine (graph_outbox) yazar.
5. **Kapsam döngüsü:** İmzalı coverage olayları → `coverage_report` boşlukları → kampanya görevleri → `run_web_loop`'a `gap_ref` ile yeniden giriş. Otomatik yeniden deneme yoktur (`automatic_retry=False`); tıkanan iş replana düşer.

### 2.7 İkinci Yürütme Yolu — Kampanya (Beyni Atlayabilir)

[campaign_runtime.py](/root/hackagent-opencode/scripts/campaign_runtime.py) SQLite kuyruğudur (`campaigns.db`): görev durumları `pending/running/waiting_approval/rate_limited/blocked/dead_letter/done`; kiralama (lease) + HMAC yürütme izni (permit) + fencing token ile çalışır. [campaign_worker.py](/root/hackagent-opencode/scripts/campaign_worker.py) iki yürütücü sunar: `LocalMCPExecutor` (izole alt süreçte tek MCP aracı) ve `ChainTaskExecutor` (`chain_runner_execute`: derlenmiş iş-mantığı manifestini modelsiz, atomik koşar; bkz. [workflow_compiler.py](/root/hackagent-opencode/scripts/workflow_compiler.py) 9 manifest tipi, [chain_executor.py](/root/hackagent-opencode/scripts/chain_executor.py) oracle'ları).

Önemli: Bu yol beyin zincirine **alternatiftir**, parçası değildir. Boş `tool_name`'li canlı türler ve `brainstorm → reasoning_next_best_action` görevleri beyin bütçesini (`max_calls ≤ 30`) ve `next_spec` kapısını kullanmadan yürüyebilir. İki yolun bütçesi birleşik değildir (§7).

---

## 3. Bileşen Haritası

### 3.1 Orkestrasyon

- [kalibounty.md](/root/hackagent-opencode/.opencode/agents/kalibounty.md) — birincil ajan: planlar, dağıtır, özet okur; kendisi aktif araç çağıramaz.
- [worker.md](/root/hackagent-opencode/.opencode/agents/worker.md) — tek yürütücü; eksik sözleşmeyi reddeder, iskelet özetle başlar.
- [brain.py](/root/hackagent-opencode/scripts/brain.py) (1979 satır) — deterministik planlayıcı; çalıştırmaz, hipotez/ledger/closure yönetir.
- [orchestration_spec.py](/root/hackagent-opencode/scripts/orchestration_spec.py) — TaskSpec + 29 çekirdek araç + özet şeması + `classify_finding` (CONFIRMED kapısı).

### 3.2 Güvenlik ve Politika

- [security-gate.js](/root/hackagent-opencode/.opencode/plugins/security-gate.js) — OpenCode eklentisi; her çağrıyı kapıya sorar, bash'i sandbox'a sarar, fail-closed (kapı cevap vermezse blok).
- [policy_engine.py](/root/hackagent-opencode/scripts/policy_engine.py) — kapsam, metot/yol/başlık, onay, hız/bütçe/zaman, gizli yol sınıfı, tekrar freni; karar günlüğü `audit.db`.
- [wire_budget.py](/root/hackagent-opencode/scripts/wire_budget.py) — süreç geneli gerçek istek sayacı; kampanya rezervasyonuyla birlikte çift katmanlı bütçe.
- Program profilleri ([config/program-profiles/](/root/hackagent-opencode/config/program-profiles)) — otomatik yüklenmez; aktif dosyaya kopyalanır (örn. `strict-bounty`: fuzz 50/çağrı, DELETE/PUT/PATCH kapalı, zorunlu araştırmacı başlıkları; `lab` gevşek; `ctf` en gevşek). Kapsam dosyası `.codex/scope.json` ile birlikte programa özel üç değişkendir: kapsam + araştırmacı etiketi + onay kaydı (grant).

### 3.3 MCP Filosu (16 sunucu, 291 araç — AST sayımı)

Sayılar [tool_counts.py](/root/hackagent-opencode/scripts/tool_counts.py) canlı sayımıdır; eski belgelerdeki 227 araç / 14 sunucu artık geçersizdir.

- **kali-tools (93)** — Kali araç zoo'su: tarama, fuzz, nuclei, sqlmap, ledger araçları. En büyük sunucu.
- **web-advanced (30)** — GraphQL/JWT/smuggling/cache/CORS/OAuth/gRPC/OpenAPI.
- **validator (26)** — deterministik doğrulayıcılar (`validate_sqli/ssti/ssrf_oob/idor/...`) + oturum kasası girişleri.
- **browser (20)** — kapılı Playwright: render, form, link, istek yakalama, oturumlu gezinme.
- **reasoning (20)** — biliş katmanı: saldırı ağacı, reflexion, dersler (lessons).
- **hunter (16)** — av zekası: tahmin, authz matrisi, `run_web_loop`, coverage. Çekirdek listede **yoktur** ama fiilen merkezîdir; çekirdek/opt-in etiketi kritiklikle ters orantılıdır.
- **memory-server (15)** — bilgi grafiği + bulgu deposu + Fernet kimlik kasası.
- **ctf-platform (14), ad-tools (12), container-tools (10)** — opencode.json'da **kapalı** (enabled:false); alan uzmanlıkları.
- **telemetry (10), osint-tools (9), rag-engine (7)** — gözlem/maliyet, OSINT, ChromaDB bilgi tabanı.
- **llm-security (6), agent-browse (2), otp (1)** — LLM zafiyet sondaları, korumalı tarayıcı (2 araç), tek araçlık OTP okuyucu.

Kayıtlı 16 sunucudan 13'ü açıktır. Profiller (`.opencode/profiles.json`: min/recon/web/llm/ctf/ad/full) sunucu alt kümesi + token bütçesi seçer; başlatma tembeldir (lazy), yalnızca memory + telemetry önden kalkar.

### 3.4 Oturum ve Tarayıcı

- **Oturum üretimi:** [member_login.py](/root/hackagent-opencode/scripts/member_login.py) yalnızca program politikasında `test_data_only` işaretli, yayınlanmış test hesaplarıyla giriş yapar; kimlik/rol sentezlemez. Başarı, özel profil işaretinin görülmesi + anonim kontrolün başarısız olmasıyla kanıtlanır.
- **İki ayrı depo karıştırılmamalı:** (1) Fernet şifreli kasa — `session_vault.json` (alt çizgi) yalnızca opak `secret_ref` indeksi tutar, malzeme [credential_vault.py](/root/hackagent-opencode/mcp-servers/mcp-memory-server/credential_vault.py) kasasında şifrelidir, worker'a yalnızca başlık/çerez **adları** döner; (2) paylaşımlı [session-jar.json](/root/hackagent-opencode/mcp-servers/mcp-validator/cco_validator_core/egress.py) — düz metin, 0600 izinli, origin-bağlı çerez kavanozu. "Worker'a ham sır gitmez" sözü yalnızca kasa yolu için geçerlidir (§7).
- **Tarayıcı:** Kapılı MCP `browser` canlıdır (istek başına GET/HEAD/OPTIONS + tel kapısı + WebSocket kapatma + yönlendirme hop denetimi). Buna karşılık [agent_browse.py](/root/hackagent-opencode/scripts/agent_browse.py) **bilerek kapalıdır**: `_agent_wire_policy_available()` sabiti `False` döner, baypası yoktur; gerekçesi, browser-use adaptörünün istek başına kapı sunamamasıdır. MITM ([mitm_scope.py](/root/hackagent-opencode/scripts/mitm_scope.py)) yalnızca loglar, engellemez; yakalanan trafik şema olarak `attack_surface`'e beslenir ama zincir derlemesine girmez (redakte yakalama).

---

## 4. Güvenlik ve Kanıt Modeli (Özet)

- **Fail-closed varsayılan:** Kayıtsız araç reddedilir; eksik/bozuk kapsam-politika dosyası kapıyı çökertir ve eklenti bunu blok sayar. Bilinen fail-open cepleri §7'dedir.
- **Gizli yol sınıfı:** `.env*`, `.ssh/.aws/.gnupg/.cco/.kube/.docker`, `*.pem/*.key/*.p12/*.pfx`, `credential_vault.db` okuma/yazması reddedilir (güvenli sonekli şablonlar hariç). Kasa API'leri tek erişim yoludur.
- **Onay (grant):** Aktif araçlar hedef desenine bağlı, süreli onayla açılır; loopback muafiyeti dardır. `member_login` POST istisnası tek URL + tek metot + test hesabı şartına bağlıdır.
- **Kanıt üç katmanlıdır:** validator artefaktı (imzalı, `reportable = CONFIRMED`) → hunter yeniden doğrulaması (güncellik + gözlem) → brain kapanış denetimi (artefakt vektör/hedef/tür bağı). Katmanlardan biri düşerse bulgu `blocked/INCONCLUSIVE`'a iner.
- **Bütçeler:** görev çağrı bütçesi (≤30), kampanya istek rezervasyonu, süreç geneli WireBudget, bash saatlik bütçesi (varsayılan 50), hedef başına zaman bütçesi, fuzz çağrı bütçesi (profil: 50–5000).

---

## 5. Kalıcılık Haritası (`.cco/` altında)

- **agent_memory.db** — sistem kaydı: `findings` (+ kimlik/alias/geçmiş tabloları), `attack_surface`, `endpoints`, coverage olayları, bilgi grafiği (`graph_nodes/edges/graph_outbox`), kimlik referansları. Tek sahibi yoktur; memory/hunter/yüzey/tarayıcı/MITM hepsi yazar.
- **credential_vault.db** — Fernet şifreli sırlar (yalnızca ciphertext); anahtar `vault.key` / `CCO_VAULT_KEY`.
- **audit.db** — kapı kararları, onaylar, hız rezervasyonları. Bulgu tutmaz.
- **campaigns.db** — kampanya + görev kuyruğu, checkpoint, bütçe rezervasyon/kullanım ayrımı.
- **validations/*.json** — HMAC-imzalı doğrulama artefaktları; raporlanabilirliğin kaynağı.
- **lessons.db** — hunter/reasoning öğrenme deposu.
- Kökteki 0 baytlık `agent_memory.db` yer tutucudur; gerçek DB `.cco/` altındadır.

Çalışma verisi repo dışındadır: kod bu ağaçta, run verisi `CCO_WORKDIR` (varsayılan `~/cco-work`) altında tutulur; bu sınır [check_repo_layout.py](/root/hackagent-opencode/scripts/check_repo_layout.py) ile denetlenir.

---

## 6. Eski Düzenlemeler ve Karışıklık Kaynakları

- **Arşiv ajanlar:** `.opencode/agents/archive/` içindeki `brain_glm/brain_sol/brainstorm` 2026-10-24 ince-beyin refactor'ıyla emekliye ayrıldı, `c540ab5` ile kayıttan düşürüldü. Aktif kod bunları import etmez; yalnızca tarih içindir.
- **Çift TaskSpec:** [task_spec.py](/root/hackagent-opencode/scripts/task_spec.py) (eski zorunlu-alan şeması) ile [orchestration_spec.py](/root/hackagent-opencode/scripts/orchestration_spec.py) (canlı sözleşme) yan yana durur. Eskisiyle üretilen prompt kapıda reddedilir.
- **Sayı sürüklenmesi:** [yapılacaklar.txt](/root/hackagent-opencode/yapilacaklar.txt) (Temmuz) 227 araç/14 MCP ve "worker yok" der; bugün 291 araç/16 sunucu ve gerçek kampanya worker'ı vardır. Belgenin yol haritası (egress broker, negatif kontrol vb.) hâlâ geçerli bir yapılacak listesidir ama durum tablosu güncel değildir.
- **Belge zinciri:** [architecture.md](/root/hackagent-opencode/docs/architecture.md) kendi ASCII bölümünü "tarihsel referans" ilan edip güncel şemayı ayrı belgeye devreder; 2026-10-29 inceleme zinciri, 10-30/31 ilerleme notları ve 2026-11-02 ödünleşim incelemesiyle aşamalı olarak aşılmıştır. Tarihli notlar "o tarihteki dilim" olarak okunmalıdır.
- **Tasarım gereği kopya:** `rag-bootstrap.py` (8 satırlık başlatıcı) → `rag_bootstrap.py` (modül) + `.sh` sarmalı ölü kod değil, CLI/modül ayrımıdır. Tireli adlar giriş noktası, alt çizgili adlar kütüphanedir.
- **Oturum adı kalabalığı:** `session-vault.json` (tire, program kasası) / `session_vault.json` (alt çizgi, Fernet hedef kasası) / `session-jar.json` (düz metin kavanoz) / `target-session.json` (işaretçi) — dördü farklı şeydir.
- **Kapalı ama erişilebilir:** opencode.json'da kapalı 3 sunucu, campaign worker'ın sunucu önek tablosu üzerinden doğrudan import ile hâlâ çalıştırılabilir. Aynı şekilde kapalı `agent_browse.py` ile açık `agent-browse` MCP sunucusu yan yana durur; yanlış yol seçimi davet eder.
- **En büyük pratik risk — commit'siz yetenek:** 100 takipsiz dosya (38 test, 15 belge, 9 script, 11 MCP modülü) yalnızca çalışma ağacındadır. HEAD'e dönmek veya takipsizleri temizlemek, güncel yeteneğin önemli kısmını sessizce siler.

---

## 7. Açık Boşluklar ve Karar Bekleyenler

Doğrulanmış boşluklar (eleştiri turu dahil):

- **Egress sınır zorlaması yok.** MITM yalnızca loglar, tarayıcı proxy yoksa doğrudan çıkar. Ağ sınırı proxy'si (ünix-socket) uygulanmadı; `agent-browser`'ın kapalı kalma gerekçesi budur.
- **Kapsamı sınırlı bilerek-kapalı yollar:** ZAP/gelişmiş yüzey kancaları canlı `run_web_loop` içinde kapalı (`zap_fn=None`); SSRF `CCO_OOB_DOMAIN` olmadan, deserialization örnek değer olmadan `INCONCLUSIVE` kalır. Plan listesinde görünen her sınıf fiilen test edilmiş sayılmamalıdır.
- **İki yürütücünün birleşik bütçesi yok** (§2.7) ve claim → execute arasında politikanın yeniden doğrulanması incelenmedi (TOCTOU adayı).
- **Sade `store_finding`** doğrulamasız yazabilir; CONFIRMED bütünlüğü, okuyucuların (TUI/rapor) `verified+reportable` filtresine bağlıdır — bu filtre incelenmedi.
- **Kasa anahtarı saklama/rotasyonu** ve sade kayıt yüklerinde ham sır bulunup bulunmadığı incelenmedi.

Karar bekleyenler:

- 100 dosyalık takipsiz batch tek commit mi olacak, kısmen mi atılacak? 38 takipsiz test hiç çalıştırılmadan bu karar verilmemelidir.
- `privesc` fazı eklenecek mi, `AGENTS.md` vaadi mi düzeltilecek?
- Dört oturum deposunun adı/sahipliği sadeleştirilecek mi, belgeyle mi yaşatılacak?

---

## Ek A — Giriş Noktaları (Hızlı Başvuru)

- Operatör kabuğu: `./scripts/opencode-cco.sh` (setup / profile / security / campaign alt komutları)
- Profil seçimi: `./scripts/opencode-optimized.sh --task "açıklama"`
- Beyin: `python3 scripts/brain.py plan --target <t> --workdir <run>` → `next` döngüsü
- Kalite kapısı parçası: `python3 -m pytest tests/test_module_boundaries.py -q`
- Lab doğrulama: `python3 scripts/lab-validate.py --skip-rag --json`
- Mimari karar geçmişi: [architecture-tradeoff-review-2026-11-02.md](/root/hackagent-opencode/docs/architecture-tradeoff-review-2026-11-02.md)

## Ek B — Kanıt ve Yöntem Notu

Bu taslak; orkestrasyon, güvenlik kapısı, kampanya, MCP filosu, hunter/validator/veri akışı, tarayıcı/oturum/egress ve eski-katman denetimi başlıklarında kod gövdelerini doğrudan okuyan yedi inceleme ile bir bağımsız eleştiri turunun sentezidir. Sayılar (16 sunucu/291 araç, 1979 satır beyin, 192 satır git durumu) çalışma ağacında ölçülmüştür. `.env`, kasa içerikleri ve oturum günlüklerinin gövdeleri okunmamıştır; `opencode.json` içinde gözlenen sağlayıcı anahtar literalleri burada yeniden üretilmemiştir.
