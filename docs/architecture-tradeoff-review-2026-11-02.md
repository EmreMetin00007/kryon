# Mimari Ödünleşim İncelemesi ve Yol Haritası — Bölüm 1/2 Değerlendirmesi

> Tarih: 2026-11-02 · Durum: **inceleme (kod değişikliği yok)**
> Karar kaydı: Teslim = mimari inceleme + yol haritası · Öncelik = **Öneri 2 (davranışsal BOLA/BFLA)** · Uyumluluk = **tam uyumlu, opt-in**
> Baz çizgisi: `HEAD e839e23` **üzerindeki kirli çalışma ağacı** (çok sayıda kaydedilmemiş değişiklik).
> Bu inceleme çalışma ağacındaki güncel koda göredir; commit'lenmiş ağaca göre değildir. Ağaç commit'lenmeden önce bulgular yeniden doğrulanmalıdır.

## 0. Yöntem ve Kapsam

Bölüm 1'deki dört ikilem ve Bölüm 2'deki beş öneri, aşağıdaki kaynak dosyalar **doğrudan okunarak** doğrulandı (arama çıktısı yalnızca aday bulmak için kullanıldı, kanıt sayılmadı):

- Sahiplik keşfi: [blind_discovery.py](../mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py), [object_identity.py](../scripts/object_identity.py)
- İstek kapısı: [request_context.py](../mcp-servers/mcp-hunter/cco_hunter_core/request_context.py), [policy_engine.py](../scripts/policy_engine.py), [wire_budget.py](../scripts/wire_budget.py)
- Yetki oracle'ı: [mcp-hunter/server.py](../mcp-servers/mcp-hunter/server.py) (`build_authz_matrix`, `analyze_authz_result`, `_loop_authz_validate`), [mcp-validator/server.py](../mcp-servers/mcp-validator/server.py) (`validate_idor`, `_validate_bfla_readonly`)
- Zincir köprüsü: [workflow_compiler.py](../scripts/workflow_compiler.py), [chain_executor.py](../scripts/chain_executor.py), [campaign_worker.py](../scripts/campaign_worker.py), [brain.py](../scripts/brain.py), [orchestration_spec.py](../scripts/orchestration_spec.py)
- Yüzey deposu: [store.py](../mcp-servers/mcp-memory-server/cco_surface_core/store.py), [identifiers.py](../mcp-servers/mcp-hunter/cco_hunter_core/identifiers.py)
- Tarayıcı/çıkış: [agent_browse.py](../scripts/agent_browse.py), [egress_policy.py](../scripts/egress_policy.py), program profilleri (`config/program-profiles/*.json`)

**Kısaltmalar:** VAR = bugün kodda mevcut ve çalışır durumda · KISMEN = iskelet/yarım halka mevcut · YOK = kodda karşılığı yok.

---

## 1. İkilem Doğrulaması

### İkilem 1 — Zero FP vs. Semantik Kapsam: **Tez doğru, antitez doğru, sentez doğru yönde**

**Tez (doğrulandı).** Açık metaveri şartı gerçektir ve katıdır:

- [blind_discovery.py:106-124](../mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py) — `_attribution()` yalnızca `ownerid/owneruuid/ownerusername/ownedby` alanlarını ve iç içe `owner` nesnesini sahiplik sayar; çakışan beyan sahipliği **boş kümeye** indirir (satır 122-123, muhafazakâr tasarım bilinçli).
- [blind_discovery.py:401-408](../mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py) — aday, ancak URL içindeki opak işaret (`marker`) yanıt metninde de görülürse ve `owners & subjects` kesişimi boş değilse üretilir.
- [mcp-hunter/server.py:2482-2493](../mcp-servers/mcp-hunter/server.py) — `_loop_authz_validate`, `owned_object` + iki kimlik + `owner_marker` eşleşmesi olmadan `INCONCLUSIVE` döner; tahmin yürütmez.
- [mcp-validator/server.py:1836-1852](../mcp-servers/mcp-validator/server.py) — `validate_idor`, `owner_marker` sahip yanıtında yoksa `INCONCLUSIVE`; işaretsiz yüksek benzerlik (`sim >= 0.92`) bile yalnızca "IDOR candidate / INCONCLUSIVE" üretir. `CONFIRMED` için işaretin **saldırgan yanıtında** da bulunması şarttır.
- [orchestration_spec.py:568-575](../scripts/orchestration_spec.py) — `classify_finding`, deterministik validator kanıtı olmadan `CONFIRMED` bandına çıkmayı kod düzeyinde yasaklar. LLM beyanı tek başına raporlanamaz.

Bu katman Bölüm 1'in tarif ettiği gibi çalışıyor ve **korunmalıdır**.

**Antitez (doğrulandı, ölçülebilir karşılığı var).** Şartın bedeli, keşif özetinin kendi dilinde görünür: [blind_discovery.py:451-461](../mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py), açık ilişki gözlenmezse `status="incomplete"` + `"no explicit owner relationship observed"` döner. Gerçek API'lerin çoğunluğu `owner` döndürmediği için bu dal, sahada varsayılan sonuçtur. "%80" oranı koddan ölçülemez; oran iddiası **doğrulanmamış saha tahmini** olarak işaretlenmelidir, mimari gerekçe olarak oran değil mekanizma (şartın karşılanma olasılığının düşüklüğü) kullanılmalıdır.

**Sentez (katılıyorum, bir düzeltmeyle).** "Kanıt kapısını gevşetmek yanlıştır; çıkarımı davranışa taşımak doğrudur" hükmü mevcut mimariyle uyumludur, çünkü sistemde **keşif ile kanıt zaten ayrı katmanlardadır**: `blind_discovery` yalnızca `authz_candidate` üretir, `CONFIRMED`'i yalnızca validator verir ([blind_discovery.py:446-448](../mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py)). Dolayısıyla küme farkı, kapıyı gevşetmeden **aday üretimini** genişletir; yanlış pozitif riski VERIFY'da değil, bütçe ve gürültü tarafında belirir. Düzeltme: sentez metnindeki "Validator statik alan eşleştirmeden diferansiyel modele evrilmelidir" cümlesi geç kalmıştır — validator **zaten diferansiyeldir** (bkz. §2, Öneri 2). Evrilmesi gereken validator değil, **aday keşfidir**.

### İkilem 2 — Salt-okunur vs. Stateful Denetim: **Tez eksik, antitez doğru, sentez kabul (koşullu)**

**Tez (kısmen yanlış — iki farklı kapı tek kapı sanılmış).** "Neredeyse tamamen GET" hükmü hangi katmana bakıldığına göre değişir:

- Hunter adaptör kapısı gerçekten salt-okunurdur: [request_context.py:72-73](../mcp-servers/mcp-hunter/cco_hunter_core/request_context.py) — `GET/HEAD/OPTIONS` dışı her metot `"blocked policy: hunter permits read-only methods only"` ile reddedilir. `blind_discovery` ve `run_web_loop` bu kapının arkasındadır.
- `PolicyEngine` katmanı ise genel bir GET kilidi **değildir**: metot yasağı program politikasındaki `blocked_http_methods` listesinden gelir ([policy_engine.py:2434-2441](../scripts/policy_engine.py)). Profiller bunu doğrular: `strict-bounty*.json` ve `vdp-nebius.json` `DELETE/PUT/PATCH` engeller ama `POST`'a (login hariç) genel yasak koymaz; `lab.json` yalnızca `DELETE` engeller; `ctf.json` hiçbiri. `member_login` istisnası da sanılandan dardır: yalnızca `kali-tools_member_login`, tek URL, tek `POST`, `test_data_only is True` ise geçer ([policy_engine.py:2436-2439](../scripts/policy_engine.py)).

Sonuç: "sistem GET'e kilitli" ifadesi Hunter yüzeyi için doğru, sistem geneli için **fazla geneldir**. Öneri 3'ün tasarımı bu ayrımı esas almalıdır; aksi halde zaten politikayla açılabilen `POST` için gereksiz yere yeni imtiyaz mekanizması icat edilir. Asıl kilit, **hedefli mutasyonun (PUT/PATCH/DELETE) gerçek kayıtlara değmemesi** garantisidir ve o garanti bugün yoktur.

**Antitez (doğru).** Yazma tabanlı BOLA, mass assignment ve durum değiştirme kontrolleri salt-okunur yüzeyde `not_tested` kalır; mevcut BFLA doğrulaması da adından belli olduğu üzere salt-okunurdur (`_validate_bfla_readonly`, [mcp-validator/server.py:1901](../mcp-servers/mcp-validator/server.py)).

**Sentez (kabul, iki koşulla).** Create-Own-Teardown modeli doğru yöndedir. Koşullar: (1) imtiyaz, metot bazlı genel izin olarak değil, **nesne kimliği + oluşturan oturum + görev** üçlüsüne bağlanmalıdır; (2) kayıt defteri yeri `audit.db` olmamalıdır (bkz. §2, Öneri 3).

### İkilem 3 — 30 Çağrı Bütçesi vs. Çok Adımlı İş Mantığı: **Tez doğru, antitez artık kısmen geçersiz, sentez zaten uygulanmış**

**Tez (doğrulandı).** [orchestration_spec.py:67](../scripts/orchestration_spec.py) `MAX_CALLS_PER_TASK = 30`; [orchestration_spec.py:228-229](../scripts/orchestration_spec.py) bunu doğrular; faz varsayılanları 20/25 çağrıdır ([brain.py:283](../scripts/brain.py)). Bütçe disiplini gerçektir ve `WireBudget` ile paylaşılır ([wire_budget.py:40](../scripts/wire_budget.py)).

**Antitez (güncelliğini yitirmiş).** "`campaign_worker.py` yalnızca tekil araç fonksiyonlarını çalıştırabildiği için çok adımlı bağlamı taşıyamaz" cümlesi **artık yanlıştır**:

- [campaign_worker.py:620-717](../scripts/campaign_worker.py) — `chain_runner_execute` görevi, `manifest`i `ChainExecutor` ile atomik koşar; bütçeyi kampanya rezervasyonundan türetir, manifestin kendi bütçesine güvenmez (satır 654-659).
- [workflow_compiler.py:453-476](../scripts/workflow_compiler.py) — `compile_workflow_manifests`, gözlenen trafikten 9 tip deterministik zincir üretir; aralarında Bölüm 2 Öneri 4'ün saydığı `sequence_step_skip`, `idempotency_replay`, `order_permutation`, `rewrite_after_complete`, `race_replay` zaten vardır.
- [chain_executor.py:421-477](../scripts/chain_executor.py) — `_eval_state_invariant`, sayısal alan kurallarını (negative/decreased/collapsed…) ve salt-okunur alan mutasyonunu (`readonly_mutated`) deterministik değerlendirir; her ağ adımı policy gate'ten geçer, model çağrısı harcamaz.

**Sentez (zaten hayatta; eksik halka köprü değil, besleme).** LLM → `ChainSpec` → `campaign_worker` köprüsü tarif edilen biçimiyle mevcuttur (`action-manifest/1.0` + `validate_manifest`). Gerçek boşluk köprüde değil, **zincirlerin beslendiği girdidedir**: manifestler yalnızca *gözlenmiş* trafikten derlenir; gözlenmemiş (keşfedilmemiş) uç noktalar için zincir üretilemez. Bu, Öneri 4'ü Öneri 1'e (şema hasadı) bağımlı kılar. Bölüm 2'nin Öneri 4'ü bu bağımlılığı belirtmeden zinciri bağımsız iş gibi sunması bakımından eksiktir.

### İkilem 4 — Uygulama İçi Wire Gate vs. SPA Yüzeyleri: **Tez doğru, antitez doğru, sentez pahalı ama yön doğru**

**Tez (doğrulandı).** Kapı uygulama içindedir ve atlatılabilir araç bu yüzden kapalıdır: [agent_browse.py:19-21](../scripts/agent_browse.py) — *"Live agent-browser execution is currently disabled: the browser-use adapter does not provide an enforceable per-request gate."* Aynı gerekçe dosya başlığında da yazılıdır: adım geri çağrısı gezinme **sonrasında** çalışır, istek başına kapı değildir.

**Antitez (doğru, kanıtı yüzey verisinde).** Hasat tarafı zayıftır: `.js` dosyaları taramada atlanır ([crawl.py:59](../mcp-servers/mcp-memory-server/cco_surface_core/crawl.py)); bundle içinden rota/şema çıkaran bir AST katmanı yoktur. Kimlik hasadı (`harvest_identifiers`, [identifiers.py:30](../mcp-servers/mcp-hunter/cco_hunter_core/identifiers.py)) metin üzerinden çalışır, JS semantiğini çözmez. SPA'da uç nokta keşfi bu yüzden eksik kalır.

**Sentez (yön doğru, sıralama yanlış).** Unix-socket egress proxy, kapıyı fiziksel sınıra taşır ve `agent-browser`'ı güvenli sensör yapar; bu mimari olarak tutarlıdır. Ancak beş öneri içinde **maliyeti en yüksek, bağımlılığı en ağır** olanıdır (bubblewrap `--unshare-net` + soket bind-mount + proxy'nin `PolicyEngine`/`WireBudget`/`credential_vault` ile host tarafında eşleşmesi). Getirisi (SPA yüzey keşfi) Öneri 1'in deterministik hasadıyla büyük ölçüde daha ucuza elde edilebilir. Bu yüzden yol haritasında **son faza** alınmıştır (bkz. §4).

---

## 2. Öneri Bazında Durum

### Öneri 1 — Şema Çıkarımı ve Parametre Sentezi: **KISMEN** (depo hazır, hasat yok)

- Beklenmedik iyi haber: hedef depo şeması **zaten vardır**. [store.py:16-38](../mcp-servers/mcp-memory-server/cco_surface_core/store.py) — `attack_surface` tablosu `method`, `params_json`, `content_type`, `auth_required` saklar; ayrıca `endpoints` tablosu vardır (satır 75). `workflow_compiler.ingest_captured_requests` tarayıcı/MITM trafiğini metot + parametrelerle bu tabloya yazar ([workflow_compiler.py:225-283](../scripts/workflow_compiler.py)). Yani Bölüm 2'nin "`surface` tablosuna şemayla kaydet" isteğinin **depo yarısı tamamdır**; tablo adı metindeki gibi `surface` değil, `attack_surface`'tır.
- Eksik olan tek halka **hasat kaynağıdır**: JS bundle AST analizi, OpenAPI/Swagger ve GraphQL şema çıkarımı kodda yoktur. Source-map ve `.js` içerikleri bugün atlanır.
- Düzeltme: iş, "yeni tablo + yeni `RequestContext`" olarak değil, **mevcut `attack_surface.params_json` şemasını besleyen yeni bir hasat adaptörü** olarak tanımlanmalıdır. `request_context.py` zaten kısa ömürlü istek bağlamı (TTL 300 sn, opak referans) sağlar ([request_context.py:215-236](../mcp-servers/mcp-hunter/cco_hunter_core/request_context.py)); şema hasadı bu mekanizmayı genişletmeli, paralel bir bağlam icat etmemelidir.
- Bütçe notu: hasat, sayfa başına sabit sayıda `GET` ile sınırlanmalıdır; aksi halde `WireBudget`'ı keşif değil ayrıştırma tüketir.

### Öneri 2 — Davranışsal / Küme Farkı Yetkilendirme: **Validator VAR, keşif YOK** → öncelik doğru seçim

- **Validator yarısı büyük ölçüde mevcuttur.** `analyze_authz_result` ([mcp-hunter/server.py:812-950](../mcp-servers/mcp-hunter/server.py)) tam da Bölüm 2'nin tarif ettiği diferansiyel oracle'dır: byte-aynı gövde → `CONFIRMED 0.95`, alan-eşdeğer → `0.92`, sahip işareti paylaşımı → `0.90`; yalnızca durum/uzunluk benzerliği → `INCONCLUSIVE` (FP koruması bilinçli). `unauth` ve `bfla` kolları da vardır. `validate_idor` ayrıca **anonim kontrolü kendi içinde** çalıştırır ([mcp-validator/server.py:1854-1860](../mcp-servers/mcp-validator/server.py)); yani önerilen 4'lü matrisin Baseline + Yatay + Anonim ayakları fiilen validator'ın içindedir, Dikey ayak `_validate_bfla_readonly` + `bfla` koluyla karşılanır. Yeni bir "Authz Validator" yazmak **tekrar** olur; yasaklanmalıdır.
- **Eksik halka yalnızca aday üretimidir.** `blind_discovery` açık `owner` olmadan aday üretemez (§1, İkilem 1). Küme farkı bu halkayı kapatır ve mimariye en az dokunan yerdedir: çıktı biçimi değişmez (`authz_candidate` listesi), kanıt kapısı değişmez.
- Detaylı tasarım §3'tedir.

### Öneri 3 — Scoped CRUD (Create-Own-Teardown): **YOK** (koşullu kabul)

- `owned_ephemeral_objects` veya benzeri bir yaşam döngüsü kaydı kodda yoktur; `PolicyEngine`'de dinamik kaynak imtiyazı yoktur.
- **Kayıt yeri düzeltmesi:** öneri tabloyu `audit.db` içine koyar. `audit.db`, `PolicyEngine`'in karar günlüğüdür (`.cco/audit.db`, salt-karar kaydı). Yaşam döngüsü durumu (oluşturuldu / mühürlendi / silindi / süresi doldu) **değiştirilebilir durumdur**; denetim günlüğüne yazılması, günlüğün salt-eklemeli (append-only) anlamını bozar ve `ledger_checkpoint` mühürlemesiyle çakışır. Doğru yer: kampanya durumu tarafı (`.cco/campaigns.db`) veya `agent_memory.db` içinde ayrı tablo. Bu, güven sınırını (`credential_vault.db`, mühür) bozmadan yapılabilir.
- **Sıralama bağımlılığı:** Scoped CRUD, Öneri 2 olmadan da çalışır ama değeri sınırlıdır: oluşturulan nesne üzerinde B→A kontrolü, nesne kimliğinin nasıl doğrulanacağını gerektirir. Öneri 2'nin marker türetimi (§3.4) burada da kullanılacağından, Öneri 3, Öneri 2'den **sonra** gelmelidir.
- Ek koşul: oluşturma uç noktası beyaz listesi program politikasından gelmelidir; kod içine gömülü uç nokta deseni kabul edilmez.

### Öneri 4 — State-Machine Doğrulayıcısı: **Büyük ölçüde VAR** (yeniden yazma, tamamlama)

- Zincir derleme + yürütme + durum değişmezi değerlendirme mevcuttur (§1, İkilem 3). Bölüm 2'nin saydığı üç pertürbasyondan adım atlama ve tekrarlama direnci manifest tipleri olarak, parametre bütünlüğü `_eval_state_invariant` + `schema_symmetry` olarak karşılanır.
- Kalan iş "aktif hale getirme" değil, **kapsam genişletmedir**: (a) zincir girdisini yalnızca gözlenmiş trafikle sınırlı olmaktan çıkarmak (Öneri 1'e bağımlı), (b) `brain.py` tarafında zincir görevlerinin `TaskSpec` bütçesiyle ilişkisini netleştirmek (zincir tek görevde koştuğu için 30 çağrı bütçesini tüketmez; bu avantaj dokümante edilmelidir).
- Bu öneri yol haritasında bağımsız faz değil, Öneri 1'in devamı olarak ele alınmalıdır.

### Öneri 5 — Local Egress Proxy + `agent-browser`: **YOK** (son faz, koşullu)

- Mevcut durum: uygulama içi kapı + `agent-browser` kapalı (§1, İkilem 4). Ara katman olarak `mitm_scope.py` ve tarayıcı oturum köprüsü (`workflow_compiler.sync_browser_cookies_to_vault`) vardır; ancak bunlar istek başına zorlayıcı kapı değildir.
- Mermaid şemasına iki itiraz: (1) `PROXY --> MEM ("Pasif API/Şema Kaydı")` oku, proxy'ye DB yazma yetkisi verir; host güven katmanında yazma, proxy'nin değil, mevcut `ingest_captured_requests` yolunun işi olmalıdır (proxy yalnızca **gözlemi iletir**, yazmayı mevcut içe aktarma yapar). (2) Şema, `credential_vault.db` çözümünü proxy'ye verir; bugün oturum malzemesi kasadan referansla çözülür ve worker'a ham sır verilmez ([campaign_worker.py:251-256](../scripts/campaign_worker.py) deseni). Proxy tasarımı bu "sır worker'a inmez" ilkesini korumalıdır; aksi halde güven sınırı genişler, daralmaz.
- Karar: faz 5'e alınır; giriş kriteri, Öneri 1'in SPA yüzey açığını ölçülmüş olarak kapatamamasıdır. Ölçüm yoksa proxy yatırımı gerekçesizdir.

---

## 3. Öncelik: Öneri 2 — Küme Farkı Sahiplik Çıkarımı (Detaylı Tasarım)

Seçilen uyumluluk kuralı gereği bu tasarım **tam uyumlu ve opt-in**'dir: mevcut imzalar, policy alanları ve varsayılan davranış değişmez; yeni davranış yalnızca açık bayrakla açılır.

### 3.1 Tasarım ilkesi: keşif gevşer, kanıt gevşemez

Mevcut katman ayrımı korunur:

```
discover_owned_resources (keşif)  →  authz_candidate listesi  →  _loop_authz_validate  →  validate_idor / _validate_bfla_readonly  →  CONFIRMED / UNCONFIRMED / INCONCLUSIVE
        ↑ yeni halka buraya eklenir              ↑ çıktı biçimi aynı                  ↑ kapı aynı, yalnızca aday kabul şartı genişler
```

Küme farkı **sahiplik kanıtı değildir**; aday üreticisidir. A'ya özel görünen her kimlik, validator'dan geçmeden `CONFIRMED` olamaz. Böylece Zero-FP garantisi VERIFY katmanında aynen kalır; gevşeyen yalnızca "hangi nesneler teste değer" sorusudur. Bu ayrım, Bölüm 1 sentezinin "kapıyı gevşetmek yanlış yoldur" hükmüyle çelişmez, onu uygular.

### 3.2 Algoritma (mevcut bütçe ve kapı içinde)

Yeni mantık, `blind_discovery.py` içine **ayrı bir fonksiyon** olarak eklenir; `discover_owned_resources` imzası ve varsayılan davranışı değişmez.

1. **Girdi şartları (mevcutlarla aynı):** 2-8 ayrı sentetik kimlik, `test_data_only is True`, farklı credential parmak izi ([blind_discovery.py:337-348](../mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py)). Anonim oturum üçüncü küme olarak eklenir; kimlik sayısı üst sınırı (8) aşılmaz, anonim mevcut bütçeden yer.
2. **Liste hasadı:** Aynı listeleyici uç noktaya her kimlikle `GET` yapılır. Yanıtlar mevcut `_document` ayrıştırıcısından **geçirilmez**; bunun yerine yeni, dar kapsamlı bir kimlik çıkarıcı yalnızca tanımlayıcı alanlarını (`id`, `uuid`, `slug` ve URL yol parçaları) toplar. Tanımlayıcı normalizasyonu için [object_identity.py](../scripts/object_identity.py) içindeki `normalize_object_id` / `object_id_key` yeniden kullanılır — ikinci bir kimlik temsili icat edilmez.
3. **Küme farkı:** `CandidateOwned(A) = IDs(A) \ (IDs(B) ∪ IDs(Anon))`. Bir kimlik birden çok karşı kimlikle sınanıyorsa fark, **tüm** karşı kümelerin birleşimine göre alınır.
4. **Kararlılık filtresi:** Aynı liste bir kez daha çekilir (bütçe içinde, en fazla +1 istek/kimlik). İki çekişte de fark kümesinde kalan kimlikler aday olur; tek çekişte belirenler elenir. Bu, sayfalama kayması ve zaman penceresi gürültüsünü ucuza keser.
5. **Aday kaydı:** Aday, mevcut aday biçimiyle (`{"vuln_class": "bola", "url": ..., "method": "GET", "authz_candidate": True}`) döner; ek olarak türetilmiş işaret (§3.4) ve kaynak (`"set_difference"`) taşınır. Özet (`summary`) şemasına yalnızca geriye uyumlu alanlar eklenir (`differential_candidates` sayacı); mevcut alanların anlamı değişmez.

### 3.3 Bilinen yanlış pozitif tuzakları (tasarımın asıl işi)

Küme farkı saflıkla uygulanırsa aşağıdaki beş durumda sistematik yanlış aday üretir. Her biri için eleme kuralı tasarımın parçasıdır; hiçbiri validator'a havale edilemez, çünkü havale edilen her yanlış aday `WireBudget` ve doğrulama bütçesi tüketir.

- **Paylaşılan katalog / rol görünürlüğü:** B'nin listesinde olmayan nesne, A'ya "özel" olduğu için değil, B'nin rolü/planı farklı olduğu için görünmüyor olabilir. Eleme: aday nesneye B ile **doğrudan** erişim validator'da zaten sınanır; ancak aday aşamasında, nesnenin detay yanıtında sahiplik dışı açıklama (ör. `visibility: "role:admin"`) varsa aday düşürülür. Kural muhafazakâr uygulanır: şüphe varsa aday kalır, etiketlenir (`visibility_hint`).
- **Sayfalama ve sıralama:** Liste uçları sayfalıysa fark, sahiplik değil sayfa kayması olabilir. Eleme: §3.2 adım 4'teki çift çekiş + mümkünse sayfalama parametrelerinin sabitlenmesi; sayfalama tespit edilirse (yanıtta `next`/`total` alanları) fark yalnızca **tam liste** üzerinden hesaplanır, tam liste bütçeye sığmıyorsa aday üretilmez, özet `incomplete` kalır.
- **Uçucu alanlar:** Zaman damgası, sayaç, `updated_at` gibi alanlar kimlik sanılmamalıdır. Eleme: çıkarıcı yalnızca tanımlayıcı alan adlarını ve URL parçalarını alır; gövde metnindeki her sayı kimlik değildir. Mevcut `_marker` kuralı (en az 8 karakter, URL'de birebir görünme, tek aday şartı, [blind_discovery.py:270-279](../mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py)) küme farkı yolunda da aynen uygulanır.
- **Ortak havuz nesneleri:** Herkese açık ama anonim listede görünmeyen (örn. giriş yapmış herkese açık) nesneler fark kümesine girer. Eleme: anonim küme bu yüzden zorunludur; anonim çekiş yapılamıyorsa (uç anonimde 401/403 veriyorsa) fark yalnızca A/B arasında alınır ve aday güven etiketi düşürülür (`anon_baseline: false`), validator'daki anonim kontrol yine de çalışır.
- **Kişiselleştirilmiş öneri / A-B testi:** "Sana özel" listeler sahiplik değildir. Eleme: aday, detay yanıtı aşamasında doğrulanır; öneri listesi uçları (yolunda `recommend`, `suggest`, `feed` geçenler) varsayılan olarak listeleyici sayılmaz, operatör açıkça eklerse işlenir.

### 3.4 İşaret (marker) türetimi — entegrasyonun kritik noktası

Mevcut kapı, `validate_idor`'da `owner_marker` ister ve işaret sahip yanıtında yoksa `INCONCLUSIVE` döner ([mcp-validator/server.py:1836-1844](../mcp-servers/mcp-validator/server.py)). Küme farkı adaylarında operatörün verdiği işaret yoktur; işaret **türetilmelidir**:

1. Adayın detay URL'si sahip (A) oturumuyla çekilir (baseline; 200 + kararlı JSON şart).
2. Yanıttaki skaler alanlardan, B'nin **kendi** nesnelerinin yanıtlarında ve anonim yanıtta görünmeyen değerler işaret adayı olur (e-posta, isim, nesnenin kendi kimlik değeri önceliklidir).
3. Tek ve kararlı (iki çekişte aynı) bir değer bulunursa `owner_marker` olarak adaya yazılır; bulunamazsa aday `INCONCLUSIVE` beklentisiyle yine de validator'a gider (işaretsiz benzerlik dalı mevcuttur ve doğru biçimde `INCONCLUSIVE` üretir), ancak önceliği düşürülür.

Böylece `_loop_authz_validate` içindeki "explicit ownership" şartı, küme farkı kaynaklı adaylar için "differential ownership + türetilmiş işaret" ile karşılanır. Değişiklik yalnızca aday kabul dalındadır; validator imzası ve karar kuralları değişmez.

### 3.5 Entropi filtresine itiraz (Bölüm 2 metnine düzeltme)

Bölüm 2, "yalnızca A'da beliren **yüksek entropili** tanımlayıcılar" der. Bu filtre **kaldırılmalıdır**: en yaygın ve en çok ödeyen BOLA sınıfı, sıralı tamsayı kimliklerdedir (`/api/orders/8841`) ve bunlar düşük entropilidir. Entropi şartı, bulunması en kolay sınıfı eler. Doğru filtre entropi değil, §3.3'teki kararlılık + işaret türetilebilirliğidir. Düşük entropili kimliklerde komşu kimlik taraması (`object_identity` sıralaması ile) ayrıca aday genişletmesi olarak kullanılabilir, ancak bu genişletme de yalnızca aday üretir.

### 3.6 Opt-in ve policy tasarımı

- Program politikasına yeni alan eklenmez; mevcut `blind_discovery` bloğu genişletilir. Bugün blok yalnızca `synthetic_accounts_only` / `owned_objects_private` boolean'larını kabul eder ve başkası gelirse reddeder ([policy_engine.py:966-973](../scripts/policy_engine.py)). Genişletme, izin verilen anahtar kümesine `differential_ownership: true` eklenerek yapılır; bilinmeyen anahtar reddi korunur (fail-closed).
- `hunter_run_web_loop` tarafında yeni parametre varsayılanı `False` olur; `campaign_runtime` köprüsü parametreyi yalnızca açıkça verilirse taşır (mevcut `blind_discovery` taşıma deseninin aynısı, [campaign_runtime.py:32-84](../scripts/campaign_runtime.py)).
- Bayrak kapalıyken davranış **bit bit aynı** olmalıdır; regresyon testi bunu kilitler.

### 3.7 Bütçe etkileşimi

- Keşif bütçesi mevcut tavanlarla sınırlıdır: toplam en fazla 40, kimlik başına en fazla 12 istek ([blind_discovery.py:351-352](../mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py)). Küme farkı yolu, liste çekişlerini bu bütçeden yer; aşımda mevcut davranış (`budget_limited`, `incomplete`) aynen uygulanır.
- Çift çekiş kararlılığı (adım 4) bütçeyi en fazla iki katına çıkarır; kimlik başına tavan yükseltilmeden uygulanmalıdır. Sığmıyorsa kararlılık çekişi atlanır ve aday `stability: "single_fetch"` etiketiyle düşürülür — sessizce güven varsayılmaz.

### 3.8 Test planı (uygulama fazında yazılacak)

Mevcut testler: [test_blind_identity_discovery.py](../tests/test_blind_identity_discovery.py) (15 test), [test_blind_discovery_integration.py](../tests/test_blind_discovery_integration.py) (12 test). Yeni davranış aynı dosyalara eklenir:

- Açık `owner` alanı **olmayan** listede küme farkı aday üretir; aynı aday validator'da işaretle `CONFIRMED` olur (uçtan uca, laboratuvar hedefi).
- Paylaşılan katalog senaryosu: B'de görünmeyen ama herkese açık nesne aday olur, validator `UNCONFIRMED` verir; sistem bunu bulgu saymaz.
- Sayfalama kayması senaryosu: iki çekiş arasında sıralama değişir; kararsız kimlik aday olmaz.
- Sıralı tamsayı kimlik senaryosu: düşük entropili kimlik elenmez (§3.5 regresyonu).
- Bayrak kapalı senaryosu: mevcut 27 testin tamamı değişmeden geçer; bayrak açık + policy izni yoksa ağa çıkmadan `blocked_blind_discovery_policy` ile durur (mevcut desenin aynısı).
- Anonim küme yokluğu senaryosu: aday üretilir ama `anon_baseline: false` etiketi taşır.

### 3.9 Kabul kriterleri (Öneri 2 fazı için çıkış kapısı)

- Yukarıdaki testler yeşil; mevcut `test_blind*`, `test_authenticated_web_api*`, `test_campaign*` paketleri regresyonsuz.
- `ruff` temiz (proje kapısı: `python3 -m pytest tests/test_module_boundaries.py -q` dahil modül sınırı testleri geçer).
- Laboratuvar hedefinde, açık `owner` döndürmeyen bir uçta en az bir gerçek BOLA adayı uçtan uca `CONFIRMED` olur; aynı hedefte herkese açık nesne `CONFIRMED` olmaz.

---

## 4. Yol Haritası

Fazlar bağımlılık sırasınadır. Her fazın giriş kriteri sağlanmadan sonrakine geçilmez. Tahminler tek geliştirici, mevcut test altyapısıyla, keşif dahil değildir.

**Faz 0 — Karar ve baz kilidi (ön koşul, 0.5 gün).** Çalışma ağacı commit'lenir veya inceleme bulguları commit'lenmiş ağaçta yeniden doğrulanır. `blind_discovery` policy bloğunun genişletme biçimi (§3.6) onaylanır. Çıkış: temiz `git status` üzerinde yeşil `test_blind*` paketi.

**Faz 1 — Öneri 2: küme farkı aday üretimi (öncelik, 3-5 gün).** §3 tasarımı uygulanır: yeni keşif fonksiyonu, işaret türetimi, `_loop_authz_validate` aday dalı, opt-in policy anahtarı, §3.8 testleri. Çıkış: §3.9 kapısı. Bağımlılık: yok (mevcut validator yeterli).

**Faz 2 — Öneri 1: şema hasadı (3-4 gün).** JS bundle / OpenAPI / GraphQL kaynaklarından metot + parametre şeması çıkarılır; yazma yeri yeni tablo değil, mevcut `attack_surface` (`method`, `params_json`) olur. Hasat, sayfa başına sabit `GET` tavanıyla `WireBudget` dostudur. Çıkış: SPA laboratuvar hedefinde, statik taramanın bulamadığı en az bir uç şemasıyla birlikte `attack_surface`'e düşer. Bağımlılık: Faz 1 değil, paraleldir; ancak zincir beslemesi (Faz 3) buna bağımlıdır.

**Faz 3 — Öneri 4 tamamlama (1-2 gün).** Yeni iş: zincir yazmak değil, Faz 2 şemalarından `workflow_compiler` girdisi üretmek ve `brain.py` görev bütçesiyle zincir ilişkisini dokümante etmektir. Çıkış: hasat edilen (gözlenmemiş) bir uç için derlenmiş manifest, `campaign_worker` üzerinden koşar. Bağımlılık: Faz 2.

**Faz 4 — Öneri 3: Scoped CRUD (4-6 gün, en dikkatli faz).** Dinamik kaynak imtiyazı: oluşturma beyaz listesi (program politikasından), yaşam döngüsü kaydı (`campaigns.db` veya `agent_memory.db`; **`audit.db` değil**), hedef kimliği mühürlü mutasyon izni, görev başına oluşturma tavanı. Çıkış: laboratuvarda kendi oluşturduğu nesne üzerinde yazma-BOLA `CONFIRMED` olur; gerçek (mühürsüz) kayda mutasyon denemesi `PolicyEngine` tarafından reddedilir ve bu red testle kilitlenir. Bağımlılık: Faz 1 (işaret türetimi yeniden kullanılır).

**Faz 5 — Öneri 5: egress proxy (5-8 gün, koşullu).** Giriş kriteri: Faz 2 sonrası SPA yüzey açığının ölçülmüş ve kapanmamış olması. Proxy yalnızca gözlemi iletir; DB yazması mevcut içe aktarma yolundan yapılır; sır çözümü "worker'a ham sır inmez" ilkesini korur. Çıkış: `agent-browser`, `--unshare-net` altında yalnızca Unix-socket proxy üzerinden, istek başına kapıyla çalışır. Bağımlılık: Faz 2 ölçümü.

**Toplam:** koşulsuz kısım (Faz 0-4) yaklaşık 12-18 gün; Faz 5 koşullu +5-8 gün.

---

## 5. Riskler, Açık Sorular ve Yapılmayacaklar

**Riskler.**

- Küme farkı gürültüsü: §3.3 tuzakları eleme kurallarıyla kapatılmazsa aday patlaması `WireBudget`'ı tüketir ve asıl doğrulamayı aç bırakır. Kararlılık filtresi bu yüzden isteğe bağlı değil, varsayılandır.
- Bayrak çoğalması: her öneri yeni opt-in eklerse program politikası okunamaz hale gelir. Kural: yeni alan yalnızca mevcut bloğun genişletilmesiyle eklenir, yeni üst düzey blok açılmaz.
- Kirli ağaç: bu inceleme kaydedilmemiş koda göredir; Faz 0 atlanırsa §1-2'deki satır referansları hızla bayatlar.

**Açık sorular (uygulama öncesi yanıt bekler).**

- Listeleyici uç tespiti otomatik mi (yanıt biçimi sezgisi) olacak, operatör mü işaretleyecek? Öneri: ilk sürümde operatör işaretler; otomatik tespit Faz 1 sonrası ayrı iş.
- Küme farkında anonim küme zorunlu mu, önerilen mi? §3.3 gereği önerilen + etiketli; zorunluluk keşfi fazla daraltabilir. Karar Faz 1 başında kilitlenir.
- Faz 4'te yaşam döngüsü kaydının sahibi hangi bileşen olacak (`PolicyEngine` mi, kampanya çalışma zamanı mı)? Öneri: kampanya çalışma zamanı yazar, `PolicyEngine` yalnızca okur ve karar verir; yazan ile karar veren ayrılır.

**Yapılmayacaklar (bu yol haritasının açıkça dışında).**

- Validator karar kurallarını gevşetmek veya LLM beyanını kanıt saymak (İkilem 1 sentezi gereği).
- Yeni bir "Authz Validator" yazmak (mevcut oracle tekrarı olur).
- Genel `POST/PUT/DELETE` izni açmak; imtiyaz her zaman mühürlü nesneye bağlıdır.
- `audit.db` içine yaşam döngüsü durumu yazmak.
- Proxy'ye DB yazma veya ham sır taşıma yetkisi vermek.

---

## Ek — Kanıt İndeksi

| İddia | Kaynak |
| --- | --- |
| Açık owner şartı, çakışmada sahipliği sıfırlar | [blind_discovery.py:106-124](../mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py) |
| Aday, marker + owner kesişimi ister | [blind_discovery.py:401-408](../mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py) |
| Keşif bütçesi: toplam ≤40, kimlik ≤12 | [blind_discovery.py:351-352](../mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py) |
| Hunter kapısı GET/HEAD/OPTIONS only | [request_context.py:72-73](../mcp-servers/mcp-hunter/cco_hunter_core/request_context.py) |
| Metot yasağı program politikasından gelir | [policy_engine.py:2434-2441](../scripts/policy_engine.py) |
| member_login istisnası dar kapsamlı | [policy_engine.py:2436-2439](../scripts/policy_engine.py) |
| blind_discovery policy bloğu fail-closed | [policy_engine.py:966-973](../scripts/policy_engine.py) |
| CONFIRMED validator kanıtı ister | [orchestration_spec.py:568-575](../scripts/orchestration_spec.py) |
| validate_idor işaretsiz CONFIRMED vermez | [mcp-validator/server.py:1836-1852](../mcp-servers/mcp-validator/server.py) |
| validate_idor anonim kontrolü içerir | [mcp-validator/server.py:1854-1860](../mcp-servers/mcp-validator/server.py) |
| Diferansiyel oracle (0.95/0.92/0.90) | [mcp-hunter/server.py:812-950](../mcp-servers/mcp-hunter/server.py) |
| _loop_authz_validate açık sahiplik ister | [mcp-hunter/server.py:2482-2493](../mcp-servers/mcp-hunter/server.py) |
| attack_surface method+params saklar | [store.py:16-38](../mcp-servers/mcp-memory-server/cco_surface_core/store.py) |
| Zincir görevi campaign_worker'da koşar | [campaign_worker.py:620-717](../scripts/campaign_worker.py) |
| 9 tip manifest derlenir (step-skip dahil) | [workflow_compiler.py:453-476](../scripts/workflow_compiler.py) |
| Durum değişmezi deterministik değerlendirilir | [chain_executor.py:421-477](../scripts/chain_executor.py) |
| agent-browser kapalı: istek kapısı yok | [agent_browse.py:19-21](../scripts/agent_browse.py) |
| TaskSpec tavanı 30 çağrı | [orchestration_spec.py:67](../scripts/orchestration_spec.py) |

