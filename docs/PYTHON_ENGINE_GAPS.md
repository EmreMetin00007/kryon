# Python motoru: mimari, geçiş ve eksikler

Tarih: 2026-11-14. Kaynak: çalışan Python kodu ve yerel testler. Bu belge eski
mimari belgelerindeki iddiaları devralmaz. Bulgu bulma gücünde ölçülmemiş bir
artış veya tüm P1–P9 işlerinin otomatik bağlandığı iddiası yoktur.

## Mevcut çalışma düzeni

```text
cco-agent / scripts/cco.sh
  → TaskSpec ve PythonSolver
  → PythonBroker → sağlayıcının model API'si
  ← modelin araç önerisi
  → aşama araç listesi + kapsam/onay + bütçe kontrolleri
  → LocalMCPExecutor → Python araç fonksiyonu → istek bazında politika
  ← gerçek çıktı + arşiv referansı + ölçülmüş kullanım
  → yeni model girdisi veya doğrulanmış aşama özeti
  → host handoff → validator kanıtı → ledger → kapanış
```

Ana döngü `scripts/full_agent_python_solver.py:PythonSolver.phase`; geçişler
`PythonSolver.run` içindedir. Model hangi aşamaya geçileceğini, kapsamı, bütçeyi
ve imzalı kanıtı belirleyemez. Model çıktıları veri olarak değerlendirilir.

`plan` ve `operations` yerel plan oluşturur. `preflight`/`run` bugün dondurulmuş
baseline ve test kimlikleriyle **sınırlı laboratuvar akışını** yürütür. Bu komutlar
genel bir bounty programını uçtan uca işleten canlı operatör olarak sunulmaz.
`run`, `--execute` verilmedikçe model veya hedef çağrısı yapmaz.

## Bu geçişte yapılanlar

- `cco-agent` / `python3 scripts/agent_cli.py` / `scripts/cco.sh` tek Python
  girişini sunar. Bu girişten native istemci motoru seçilemez.
- `config/llm.example.json` bağımsız `cco-llm/1` şemasıdır. Gizli anahtar değeri
  kabul edilmez; yalnız ortam değişkeni adı saklanır. Yerel `config/llm.json`
  Git tarafından yok sayılır. Sağlayıcı HTTPS veya sahip olunan loopback
  kullanmalıdır; URL içine credential veya query konamaz.
- Python snapshot/staging yolu istemci konfigürasyonu, ajan Markdown dosyası,
  JavaScript eklentisi veya istemci binary'si gerektirmez.
- Sağlayıcı adresi preflight sonrasında değişirse çalışma başlamadan reddedilir.
  Python ve MCP kaynakları da hash envanterine bağlanır.
- Eski `.opencode/`, `opencode.json`, başlatıcılar ve setup sihirbazı ile
  `graphify-out/` çıktı dosyaları yeni Python motoru deposundan çıkarıldı;
  yeni motor JavaScript eklentisine veya OpenCode istemcisine dayanmaz.
- MCP envanteri/profilleri `config/` altındadır. Paket adı `hackagent`, veri kökü
  `share/hackagent`; CI ve kalite kapısı Python girişini doğrular.
- Test import yolu bağımsız çalışacak şekilde düzeltildi.
- Modelin araç çağrısı grubunun tamamı işlem öncesi kontrol edilir. Bozuk JSON,
  yinelenen JSON anahtarı, NaN/Infinity veya nesne olmayan argümanlar hiçbir
  aracı kısmen çalıştırmadan bir kez düzeltilebilir. İkinci hata işi durdurur.
- Aynı argümanlarla iki kez aynı içerik alındıktan sonra üçüncü model isteği
  ek HTTP harcamaz; aşama özetlemeye geçer. Host doğrulama grupları ve
  validator'ın kontrol istekleri bu mekanizmanın dışındadır.
- Bağlam küçültme denemelerinin kapanış durumunu kalıcı değiştirmesi düzeltildi.
  Bütçe kararı gönderilecek bağlam üzerinden verilir.

## P1–P9 bağlantısının sınırı

| Yetenek grubu | Kodda mevcut yol | Python döngüsündeki durum |
|---|---|---|
| P1 yüzey / P2 şema | `cco_surface_core`, keşif ve ayrıştırıcılar | `enum` ve kullandığı araçlar üzerinden kısmen erişilir; her şema kaynağı her çalışmada kullanılmaz. |
| P3 tarayıcı keşfi | browser araçları, capture/runtime modülleri | Dört aşama planının açık araçlarıyla sınırlı; bütün tarayıcı kabiliyetleri otomatik planlanmaz. |
| P4 kimlik ve yetki | oturum kasası, `authz_matrix`, Hunter | Sağlanan sentetik kimliklerle sınırlı doğrulama vardır. Kimlik/nesne oluşturmak için örtük yetki yoktur. |
| P5 hipotez kuyruğu | `brain.observed_specs`, `hypothesis_ledger`, `cco_surface_core/hypotheses.py` | PythonSolver yeni gözlemlerden bağımsız plan görevleri seçer; mevcut hedef/araç izinlerini genişletmez. Canlı doğrulama ayrıca mevcut admission yolunu gerektirir. |
| P6 deney/doğrulama | Hunter testplan/experiments ve validator | `access` içinde gözlenmiş adaylara sınırlı uygulama vardır; tüm deney türleri açık değildir. |
| P7 iş mantığı | `business_logic.py`, manifest compiler / ChainTaskExecutor | Altyapı vardır; standart Python döngüsüne genel iş mantığı görev dağıtımı bağlı değildir. |
| P8 kanıt zinciri | `evidence_chaining.py`, mevcut graph/outbox | İmzalı artefakt kullanımı vardır; genel çok adımlı P8 iş seçimi dört aşamalı döngüye bağlı değildir. |
| P9 entegrasyon | `agent_integration.py`, TaskSpec, campaign | Sözleşme kontrolü ve imzalı checkpoint ortak kullanılır; campaign aynı run/checkpoint'e işaret eder, tamamlanmış aşamaları tekrar kuyruğa eklemez. |

Bu tablo yetenek bulunması ile gerçek bir görevde çalıştırılmasını ayrı tutar.
P1/P2 isimleri Hunter'daki daha eski yerel yorumlarda farklı anlamlarda da
kullanılmıştır; iş kimliği olarak yalnız P numarası kullanılmamalıdır.

## Öncelikli eksikler ve kabul koşulları

### E1 — Genel çalışma başlatıcısı / P5 görev seçimi

**Durum: tamamlandı — dinamik TaskSpec ve P5 plan seçimi.** `bootstrap_plan()`
laboratuvar için dört aşamalı varsayılanı korur; PythonSolver artık bu dört ID'yi
zorunlu tutmaz. Geçerli, host tarafından sağlanmış TaskSpec kayıtları, kapsam/
politika dosyaları, mevcut onaylar ve oturum referansları çalışma sınırıdır.

`observed_db` / `--observed-db` ile `brain.observed_specs()` her görev arasında
yeniden okunur. Tam P5 fingerprint'i görev ID'sini belirler; yeni parametre veya
gözlem yeni görev açar. Eksik oturum veya handoff yalnız ilgili görevi ve onun
bağımlılarını engeller; bağımsız hazır görev ilerler. Kuyruğun mevcut öncelik
sırası korunur. Model görev geçişi veya yetki seçmez.

P5'nin ürettiği `live=false` plan sözleşmesi korunur. Yeni görev yalnız aynı
hedef için başlangıç TaskSpec'lerinde zaten izin verilen Python araçlarını
alır; bu seçim canlı test onayı vermez. Genel canlı program başlatıcısı ve
P7/P8 doğrulama dağıtımı hakkında ek tamamlanmışlık iddiası yoktur.

**Doğrulama:** `tests/test_brain.py` yeni gözlemi, eksik oturumu/handoff'u,
bağımsız ilerlemeyi, farklı politika bağlamını ve canlı/başka-hedef retlerini
doğrudan sınar. P5 görevi laboratuvar handoff'u olmadan gerçek Python phase
döngüsünde özetlenir; örtük validator veya HTTP çağrısı oluşmaz.

### E2 — Kalıcı devam ve tek kuyruk

**Durum: tamamlandı — atomik checkpoint ve güvenli resume.** Host'un imzaladığı
`solver/checkpoint.json`, run ID, TaskSpec'ler/durumları, tamamlanan özetlerin
imzalı hash ile bağlanmış durum dosyası, kapsam/politika/araç/oturum bağlamı,
kanıt SHA-256 hash'leri, token/HTTP kullanımı ve bekleyen rezervasyonlar ile süre
sonunu saklar. Aynı dizinde geçici dosya, dosya/dizin fsync ve atomik replace
kullanılır; özel run kilidi eşzamanlı yürütmeyi reddeder. Anahtar/credential
değerleri checkpoint'e taşınmaz; özel host durumu model arşivinden ayrıdır.

Rezervasyon gönderimden önce kalıcıdır; araç dönüşünde ölçülmüş kullanım
saklanır. `run --resume [RUN_DIRECTORY] --execute` orijinal çalışma alanını ve
geçerli onayları kullanır. Dizin verilmezse output-dir içindeki en son checkpoint
seçilir. İmza, bütün kanıt hash'leri, TaskSpec/hedef/politika/oturum bağlamı ve
bütçe sınırları denetlenmeden aşama yürütülmez. Tamamlanan aşamalar atlanır.
Bozuk en son checkpoint'ten eski bir dosyaya geri dönülerek istek tekrarlanmaz.

Kesintide `running` kalan aşama `INCONCLUSIVE` olur ve otomatik tekrarlanmaz;
bağımlıları NOT TESTED kalır. Ölçümü bilinmeyen rezervasyon tam tutarıyla bir kez
harcanmış sayılır; ölçülmüş kullanım tekrar tahsil edilmez. Süre kesinti boyunca
da işler, resume bütçeyi yenilemez. Eksik/sona ermiş oturum ve onaylar ayrıca
normal araç/istek kapılarında denetlenir. Durdurulmuş geçici laboratuvar başka
hedef/port ile yeniden kurulmaz.

`CampaignRuntime.bind_solver_checkpoint` / `read_solver_checkpoint` aynı imzalı
dosyaya run ID ile işaret eder ve her okumada kanıt bütünlüğünü tekrar denetler;
ikinci bir replay kuyruğu oluşturmaz. Bağlama işlemi mevcut campaign hedef ve
operatör metaverisini koruyan tek SQLite transaction'ıdır.

**Doğrulama:** Gerçek loopback isteğinde araç dönüşünden önce/sonra SIGKILL,
Ctrl+C, bekleyen token rezervasyonu, art arda resume, tamamlanmış aşamada sıfır
tekrar istek, imza/kanıt/politika/oturum/bütçe değişimi ve run kilidi regresyonları
`tests/test_brain.py` içindedir. Dört aşamalı gerçek MCP entegrasyonunun explicit
vakası CLI resume sonrasında aynı kullanım ve sıfır yeni model/hedef isteğini
denetler. E8 testleri korunur; tam güvenlik kapsamı veya gerçek model recall'ı
iddiası eklenmez.

### E3 — Kimlik karşılaştırmalarının kapsamı

**Durum: tamamlandı — P4 kategorileriyle bütçeli kimlik çifti kapsamı.**
`member_batches()` artık uygun sentetik member kimliklerinin bütün çiftlerini
planlar. Kaynak/kanıt taşıyan P4 `identity_facts` ve operatörün düz tenant/rol
metaverisi `cross_tenant_user`, `same_tenant_other_user`, `different_role`
sırasını belirler; aynı öncelikte henüz karşılaştırılmamış kimlikler öne alınır.
Çelişkili veya kaynaksız fact kayıtları düz metaveriyle geçersiz kılınmaz;
aynı kanıtlı principal iki ayrı P4 aktörü sayılmaz. Planlama metaverisi erişim
beklentisi veya bulgu kanıtı değildir.

Sekiz kimlik sınırı, exact-target/sentetik/özel test nesnesi şartları, mevcut
host rezervasyonu ve TaskSpec/aşama/HTTP/token/süre tavanları korunur. Ek çiftler
yalnız kalan araç ve istek bütçesiyle mevcut admission/wire yolundan yürütülür.
Bir çift ancak iki yöndeki gözlenmiş kuyruğun tamamı güncel imzalı validator
artefaktlarına bağlıysa TESTED olur. `identity_comparisons` ve
`identity_comparison_dimensions`, bütçe nedeniyle kalan veya eksik kanıtlı
çift/kategorileri gerekçeleriyle **NOT TESTED** tutar; report özeti bu kayıtları
taşır. TESTED gözlenmiş çift kuyruğuna aittir; bütün tenant/rol/nesne kurallarının
veya P7/P8 kapsamının tamamlandığı iddiası değildir.

**Doğrulama:** `tests/test_full_agent_python_solver.py` içindeki
`test_cross_tenant_bola_signed_loopback_and_budget_coverage`, iki tenant/dört
kimlik için gerçek loopback HTTP ve üretim validator imzalarıyla, eski [A,B]/
[C,D] gruplarının kaçırdığı [A,C]/[B,D] BOLA ihlallerini yakalar. Tam bütçede
altı çift ve on negatif kontrol doğrulanır; 10 istek veya iki araç çağrısı
tavanında iki çift tamamlanır, kalan dört çift report'a NOT TESTED taşınır.
Sekiz kimlik/28 çift regresyonu 14 fiziksel araç çağrısında durur; imzasız araç
başarısı kapsam sayılmaz. Kategori sırası, fact çelişkileri, eksik rol boyutu
ve sıfır istek/araç/süre bütçesi ayrıca sınanır.

**2026-11-12 test kaydı:**
- `python3 -m pytest tests/test_python_engine.py tests/test_full_agent_python_solver.py -q`
  → **146 passed** (251,49 s).
- `python3 -m pytest tests/test_p4_authz_matrix.py tests/test_brain.py -q`
  → **62 passed** (9,30 s).
- `python3 -m pytest tests/test_p9_integration.py tests/test_module_boundaries.py -q`
  → **55 passed** (6,26 s).
- `python3 scripts/check_repo_layout.py` ve ilgili dosyalarda `git diff --check`
  → temiz.

### E4 — P7/P8'i Python görevlerine bağlama

**Durum: tamamlandı (2026-11-12).** `PythonBroker.bind_workflow()` ve
`PythonSolver(..., compiled_workflows=[...])`, host'un derlediği P7/P8
manifestlerini access TaskSpec'ine bağlar. `TaskSpec.compiled_workflows`,
Ed25519 imzalı bağları taşır; model yalnızca `workflow_execute_compiled` aracına
izin verilen `binding_ref` değerini verir. Manifest, URL, body, kimlik veya
araç izni model argümanı değildir. Bağlı görevlerde ayrıca listelenmiş raw HTTP
araçları ve genel validator döngüsü bu yolu aşamaz.

`scripts/python_workflow_binding.py`, manifest SHA-256'sını, kaynak kanıt
hash'lerini ve bunların ortak SHA-256'sını, tam araç izinlerini,
program/scope/policy dosyalarının hash'lerini, origin/tenant/run/session
bağını, kimlik/nesne referanslarını ve en erken kaynak expiry'sini doğrular.
P7 kaynakları EvidenceGraph exchange kayıtlarında özgün compiler girdisini
`capture` alanında taşır; `compile_business_logic_chain()` istek/yanıt ve
kimlik eşleşmesini kontrol ederek bunlardan yeniden derler. P8 mevcut typed
edge ve replay doğrulamasını kullanır. Runtime `identity_hashes`,
`resource_hashes` ve `permission_hash` referanslarını açıkça sağlar;
`program_id`, mevcut policy profile ile eşleşir. P7 ayrıca aynı run/session'a
ait, güncel WS7 mühürlü test nesnelerini gerektirir.

Yürütme `ChainExecutor` üzerinden olur. Kaynak hash/TTL ve sahiplik kontrolleri
ilk istekten önce ve her wire gate'te, policy kontrolünün öncesinde/sonrasında
yenilenir. Eksik, değiştirilmiş, invalidated veya süresi dolmuş kaynakta
**sıfır bağımlı istek** gönderilir; observer sonrasında expiry/invalidasyon
oluşursa sonraki yazma isteği de gönderilmez. Mevcut scope, program onayı,
rate ve WS7 mutation izinleri korunur. Python araç/istek/süre bütçeleri
geçerlidir; gönderici hatası da gerçekleşmiş istek denemesini sayar.

Sonuç, `python-compiled-workflow-execution` amaçlı host imzası ve hash'li
archive referansıyla saklanır. Summary, güncel imza/kaynak kontrolü üzerinden
manifest bazında TESTED / NOT TESTED üretir. İmzalı yürütme kanıtı otomatik
reportable bulgu veya tam güvenlik kapsamı değildir; `reportable=false`
korunur. Resume öncesinde host aynı kaynaklardan bağları yeniden sağlamalıdır;
TaskSpec içindeki imzalı metaveri tek başına yürütme yetkisi vermez.

**Doğrulama:** P7 Python phase testleri pozitif/negatif control-effect
sonuçlarını imzalar. P8 gerçek loopback HTTP üzerinden Python phase,
mevcut policy engine, imza doğrulama ve kalıcı replay'i sınar. Eksik/tampered/
expired kanıt, program/tenant/kimlik/nesne sınırları, modelin raw HTTP ile
bypass girişimi ve araç/HTTP/süre bütçeleri ayrıca negatif kontrollerle
doğrulanır. Yerel sağlayıcı kararları betiklidir; ücretli sağlayıcı veya canlı
hedef kullanılmadı.

**2026-11-12 test kaydı:**
- `python3 -m pytest tests/test_p7_business_logic.py tests/test_p8_chaining.py -q`
  → **207 passed**.
- `python3 -m pytest tests/test_python_engine.py tests/test_full_agent_python_solver.py -q`
  → **151 passed** (265,76 s; önceki 146 + 5 yeni host admission/bütçe testi).
- `python3 -m pytest tests/test_p4_authz_matrix.py tests/test_brain.py -q`
  → **62 passed** (9,20 s).
- `python3 -m pytest tests/test_p9_integration.py tests/test_module_boundaries.py tests/test_chain_executor.py -q`
  → **100 passed** (12,14 s).
- `python3 scripts/check_repo_layout.py`, ilgili dosyalarda `git diff --check`
  ve `graphify update .` → temiz; graph AST üzerinden güncellendi.

### E5 — Şema doğrulama ve sağlayıcı hatalarının ayrımı

**Durum: tamamlandı (2026-11-12).** `scripts/full_agent_python_solver.py`
içindeki `parse_calls` ve araç yürütme hattı, tüm araç argümanlarını MCP çağrısından
önce ilan edilen JSON Schema'larına göre denetler. Eksik zorunlu alan, yanlış tür
veya izin verilmeyen ek özellikler içeren çağrılar, MCP'ye gitmeden doğrudan
`tool_arguments_schema_invalid` tekil hata koduyla reddedilir. JSON bozulmaları ve
şema ihlalleri tek bir sınırlı protokol onarım turu (`tool_protocol_repair_exhausted`)
paylaşır; döngü olayları gizli argüman sızdırmadan kaydedilir.

`scripts/full_agent_broker.py` ve `scripts/full_agent_budget.py`, ağ/taşıma
hatalarını (`provider_transport_error`), HTTP sağlayıcı hatalarından
(`provider_http_error`) ve geçersiz/bozuk yanıt yapılarından
(`provider_response_invalid`, `response_object_invalid`) açıkça ayırır.
Sağlayıcı token kullanım bilgisi eksik, çözülemez veya boş olmayan yanıtta sıfır
gelirse harcama sıfır sayılmaz; ayrılmış üst sınır korunur (`token reservation retained`).
Belirsiz ağ kopmalarında istekler körlemesine tekrarlanmaz, ayrılan bütçe korunur.

**Doğrulama:** `tests/test_full_agent_broker.py` ve `tests/test_full_agent_python_solver.py`
üzerinde eksik zorunlu argüman, yanlış tür ve şema dışı argümanların MCP öncesi
reddedildiği, tekil protokol onarım hakkı ve bütçe/token rezervlerinin korunduğu,
eksik kullanımda sıfır maliyet çöküşünün engellendiği ve taşıma vs. HTTP ayrımının
yapıldığı doğrulandı.

**2026-11-12 test kaydı:**
- `python3 -m pytest tests/test_full_agent_broker.py -q`
  → **24 passed** (1,78 s).
- `python3 -m pytest tests/test_python_engine.py tests/test_full_agent_python_solver.py -q`
  → **161 passed** (16 + 145 passed; 446,11 s).
- `python3 -m pytest tests/test_brain.py tests/test_p9_integration.py tests/test_module_boundaries.py -q`
  → **78 passed** (6,67 s).
- `python3 scripts/check_repo_layout.py` ve `python3 scripts/release_artifacts.py check-lock`
  → temiz (17 doğrudan bağımlılık, 103 paket, SHA-256 doğrulandı).


### E6 — Bulgu gücünü gerçek modelle ölçme

**Durum: gerçek model kabul ölçümü geçti (2026-11-16, `main@e953ec6`);
`aggregate_status: passed`, `paid_model_generalization: passed`.** İlk cohort
(2026-11-14) ve P0/P1 birleşimi (`main@a385231`, 2026-11-15) sonrasındaki
koşularda `0/24` recall ve `aggregate_status: incomplete` gözlenmişti. Stateful
discovery frontier (`scripts/python_discovery_runtime.py`), çoklu-profil
kümeleme, yaprak (leaf) düzeyi kanıt muhasebesi (`91d551d`) ve kabul edilmiş
doğrulamalı `access` fazında kısmi ilerleme korunumu (`e953ec6`) sonrasında
üç bağımsız sentetik ailede (`readonly-api-access-control`, `readonly-sql-injection`,
`readonly-template-injection`) **24/24 recall (1.000), 24/24 negative coverage
(1.000), 0/24 FP ve 0/3 failed run rate** elde edildi; genelleme ve `NOT TESTED`
sınırları aşağıda korunur.
`scripts/full_agent_e6_benchmark.py`, `scripts/full_agent_holdout.py:audit_run_status`,
`scripts/full_agent_preflight.py --http-budget` ve `scripts/agent_cli.py benchmark`
üzerinden E6 ölçüm ve önce/sonra kıyaslama yolu eklendi; runtime snapshot
haritası (`preflight.runtime_file`) bu dosyaları model erişiminden ayrı tutar.

- **Üç bağımsız aile + pozitif/negatif kontroller:** `validate_suite()` ve
  `audit_cohort()` en az üç kayıtlı bağımsız aile gerektirir; aynı ailenin
  yeniden isimlendirilmesini veya farklı seed ile çoğaltılmasını reddeder.
- **Ortak token/HTTP/süre tavanında önce/sonra kıyaslama:** `run_cohort()`,
  `audit_cohort()` ve `compare_cohorts()` bütün koşularda aynı
  `http_requests_per_seed`, `llm_tokens_per_seed` ve `seconds_per_seed`
  tavanlarını zorunlu kılar; tavanı veya aile kümesini değiştiren kıyaslamaları reddeder.
- **Kabul metrikleri ve hata muhasebesi:** `recall`, `false_positives`,
  `negative_coverage`, `requests_per_verified_finding`, `tokens_per_verified_finding`
  ve `failed_run_rate` raporlanır. Başarısız/tamamlanmamış koşular (`launch_failed`,
  `protocol_repair_exhausted`, bütçe/süre aşımı) gerçek pozitif/negatif paydasıyla
  ve harcanan istek/token ile hesaba katılır; evaluator/kaynak kurcalaması yine
  fail-closed reddedilir.
- **Model, gerçek kullanım, kanıt ve bilinmeyen maliyet:** Raporlar model ID'lerini,
  gerçek token/HTTP/süre kullanımını, imzalı/SHA-256 kanıt referanslarını ve
  `not_tested_dimensions` alanını saklar; bilinmeyen maliyet `None` (`unknown_cost_is_zero: False`) kalır ve sıfır yazılmaz.
- **Açık canlı sağlayıcı yetkisi:** `plan` varsayılandır (0 LLM/HTTP isteği).
  Uzak/HTTPS sağlayıcılara karşı `--execute` kullanımı hem
  `--authorize-live-provider` hem de boş olmayan `--live-authorization-reason`
  olmadan fail-closed engellenir.

**Altyapı doğrulaması (2026-11-13, yerel loopback lab):** `tests/test_full_agent_e6_benchmark.py` (**6 geçti**):
3 aile gereksinimi, snapshot izolasyonu, canlı sağlayıcı yetki kapısı,
bilinmeyen maliyet politikası, başarısız koşu oranı/kurcalama reddi ve ortak
tavanda (`250 HTTP / 150k token / 260 s`) 3 bağımsız ailede (`readonly-api-access-control`,
`readonly-sql-injection`, `readonly-template-injection`) uçtan uca gerçek yerel
HTTP/MCP önce/sonra kıyaslaması geçti. Bu tarihsel yerel sonuç gerçek model
recall kanıtı değildir; aşağıdaki canlı ölçüm ayrıca açık kullanıcı yetkisiyle
yapıldı.

#### Gerçek model ölçümü — 2026-11-14

Önce `agent_cli.py check-config --provider-config config/llm.json` çevrimdışı
olarak `cco-llm/1` ve `meta/muse-spark-1.3-contributor` seçimini doğruladı
(`credential_read=false`, `network_requests=0`). Her iki `benchmark plan`
koşusu da **0 LLM / 0 hedef isteği** üretti. Canlı sağlayıcı `api.meta.ai`;
anahtar yalnız `META_API_KEY` ortam referansından runtime tarafından kullanıldı.
Değeri ajan tarafından incelenmedi, gösterilmedi veya konfigürasyona yazılmadı.

Her iki canlı komut açık `--execute --authorize-live-provider` ve
`--live-authorization-reason "User-authorized E6 live benchmark using meta/muse-spark-1.3-contributor"`
ile çalıştı. Hedefler yalnız host'un oluşturduğu, kapsamı/onayı doğrulanmış
sahip olunan loopback laboratuvarlarıydı; uzak bounty hedefine trafik yoktu.
Üç aile ve seed eşleşmesi aynı tutuldu:
`readonly-api-access-control:314159`, `readonly-sql-injection:271828`,
`readonly-template-injection:141421`. **Seed başına ortak tavan: 250 HTTP /
150000 LLM token / 900 saniye**; karşılaştırıcı bu tavanların eşitliğini doğruladı.

| Metrik | Önce (`be20099`) | Deneysel aday (`1cb7760`) |
|---|---:|---:|
| Recall | 0/24 (%0) | 0/24 (%0) |
| False positives | 0/0 — oran bilinmiyor | 0/0 — oran bilinmiyor |
| Negative coverage | 0/24 (%0) | 0/24 (%0) |
| Failed run rate | 1/3 (%33,33) | 2/3 (%66,67) |
| Requests / verified finding | `None` | `None` |
| Tokens / verified finding | `None` | `None` |
| Gerçek sağlayıcı çağrısı | 31 | 34 |
| Gerçek hedef HTTP isteği (cohort toplamı) | 31 | 253 |
| Ölçülen toplam token | 91380 | 107811 |
| Ölçülen çalışma süresi (s) | 249,016 | 679,898 |
| USD maliyet | `None` | `None` |

Hiç doğrulanmış bulgu olmadığı için bulgu başına oranlar tanımsızdır; sıfır
yazılmaz. FP paydası da sıfırdır: **0 FP, temiz negatif kapsam veya %0 FP oranı
kanıtı değildir.** Maliyet bilinmiyor (`unknown_cost_is_zero=false`). CLI çıkış
0, benchmark/audit komutunun tamamlandığını gösterir; kabulün geçtiğini değil.
İlk koşuda SQL/SSTI kapanışları doğrulandı, API kapanışı eksik kaldı; adayda
yalnız SSTI kapanışı doğrulandı. Doğrulanmış kapanış, tamamlanmış güvenlik
kapsamıyla karıştırılmadı; başarısız koşular 24 pozitif/24 negatif paydasında kaldı.

**Tanı ve deney kararı:** İlk model çıktılarında enum gerçek crawler çağırmak
yerine arşiv okumalarına takıldı; API enum'da reddedilen artifact okuması sonrası
bloklandı. Aday yalnız genel discovery/validation ayrımını ve ilan edilmiş
araçlara/aşama bütçesine bağlı kısa yönlendirmeyi değiştirdi. P5 `live=false`,
P7/P8 `binding_ref`, summary-only kapanış ve özel TaskSpec adımları korundu;
hedefe/seed'e özel rota, cevap, evaluator truth veya genişletilmiş bütçe yoktu.
Adayın 9 yeni sözleşme testi ve **174 testlik Python motoru/solver paketi** geçti.

Yeniden ölçümde crawler gerçekten çağrıldı: SQL/SSTI enum özetlerinde 21'er
rota ve birer parametre gözlendi; API yalnız bir rota ve sıfır parametrede kaldı.
Ancak gözlemden doğru deterministik doğrulama seçimine geçiş yeterli olmadı;
model doğrudan ilgili validator'ları seçmedi ve host fallback sonuçları güncel
raporlanabilir kontrol kanıtı üretmedi. SQL report aşamasında ayrıca
`tool_arguments_schema_invalid` kaydı görüldü. Recall artmadı, istek/token
harcaması ve bu küçük örnekte başarısız koşu sayısı arttı. **Bu yüzden aday
başarı artışı olarak sunulmadı ve üretimden geri alındı**; runtime önceki
doğrulanmış davranışa döndü. Deney `a7488d6` / `1cb7760` Git geçmişinde,
ölçümler ise aşağıdaki dış dizinlerde korunur. Tek seed/aile ve tek yeniden
değerlendirme, nedensellik veya genel model başarısı iddiasına yetmez.

**Açık kabul işi:** Gerçek gözlem → validator seçimi/coverage ve doğru terminal
summary yolunu önce çevrimdışı adversarial/negatif kontrollerle güçlendirmek,
sonra aynı tavanlarla daha geniş, bağımsız seed setinde yeniden ölçmek gerekir.
Bu görevde ek ücretli denemelerle sonuç zorlanmadı.

**NOT TESTED / genelleme sınırları:** `readonly_get_only`,
`synthetic_fixture_boundaries`, `out_of_band_and_multi_step_business_logic`,
`incomplete_run_before_closure`, `missed_positive_controls`,
`untested_negative_controls`. Üç read-only sentetik aile, genel bounty/P1–P9
kapsamı veya gerçek kullanıcı nesneleri üzerinde başarı kanıtı değildir.

Kanıtlar repo dışında `/root/cco-work/wf-0c7324cc/` altında:
`e6-offline/`, `e6-meta-before/{cohort-report.json,cohort-report.md,execution.json}`,
`e6-meta-after/{cohort-report.json,cohort-report.md,execution.json}` ve
`e6-comparison/{comparison.json,comparison.md}`. Raporlar bağımsız offline
audit üzerinden imza/hash referanslarını ve gerçek kullanım muhasebesini taşır.
Son zorunlu doğrulama komutları/logları `final-verification/results.json` ve
aynı dizindeki ayrı gate loglarında saklanır.

#### Gerçek model yeniden ölçümü — 2026-11-15 (P0/P1 birleşimi sonrası, `main@a385231`)

P0/P1 doğrulama hunisi ve açık proje/tip projeksiyonu düzeltmeleri `main` dalına
(`a385231`) birleştirildikten sonra, güncel kaynaktan `0` LLM / `0` hedef isteğiyle
yenilenen eşleştirilmiş manifest üzerinden
([experiment-manifest.json](file:///root/cco-work/wf-eb9f69a9/live-e6-plan-v2/manifest/experiment-manifest.json))
tek seferlik kullanıcı onaylı canlı koşu çalıştırıldı (`config/llm.json`,
`meta/muse-spark-1.3-contributor`, `api.meta.ai`, anahtar yalnız çalışma anında
bellekteki `META_API_KEY` üzerinden kullanıldı; `--execute --authorize-live-provider`).
Aynı üç aile, aynı tohumlar (`readonly-api-access-control:314159`,
`readonly-sql-injection:271828`, `readonly-template-injection:141421`), 1 tekrar ve
seed başına `250 HTTP / 150000 token / 900 sn` ortak tavanı korundu; tüm hedefler
host'un oluşturduğu salt-okunur loopback laboratuvarlarıydı.

| Metrik | Önce (`e6-meta-before`, `be20099`) | Sonra (`e6-meta-after-v2`, `a385231`) |
|---|---:|---:|
| Recall (toplam) | `0/24` (%0) | `0/24` (%0 — API `0/8`, SQL `0/8`, SSTI `0/8`) |
| False positives | `0/0` (`null` — oran bilinmiyor) | `0/0` (`null` — oran bilinmiyor) |
| Negative coverage (toplam) | `0/24` (%0) | `0/24` (%0 — API `0/8`, SQL `0/8`, SSTI `0/8`) |
| Failed run rate | `1/3` (%33,33) | `3/3` (%100,0 — `1.0`) |
| Kapanış doğrulaması | SQL/SSTI `true`, API `false` | 3/3 `false` (`unresolved_tasks_remain_NOT_TESTED`) |
| Requests / verified finding | `None` | `None` |
| Tokens / verified finding | `None` | `None` |
| Gerçek sağlayıcı çağrısı | `31` | `29` |
| Gerçek hedef HTTP isteği | `31` (API `5`, SQL `13`, SSTI `13`) | `10` (API `6`, SQL `2`, SSTI `2`) |
| Ölçülen toplam token | `91380` | `87992` (`72888` prompt + `15104` completion) |
| Ölçülen çalışma süresi (s) | `249,016` | `173,541` |
| USD maliyet | `None` | `None` (`unknown_cost_is_zero=false`) |
| Doğrulama hunisi (`funnel`) | `missing_runtime_funnel_metrics` | `observed=0, eligible=0, admitted=0, executed=0, evidence_accepted=0` (`complete`) |

**Ölçülen tanı ve hata nedenleri:**
- **SSTI (`141421`) ve SQLi (`271828`):** Model `recon-1` içinde `kali-tools_curl_request` ile `/` sayfasını aldıktan sonra `enum-2` aşamasında crawler/keşif isteği yapmak yerine arşivlenen ilk sonucu aynı `offset=0` parametresiyle defalarca `read_artifact` üzerinden okumaya takıldı (`archive_read_no_progress`, sırasıyla `2` ve `4` olay). Motorun fail-closed ilerleme kilidi ek token israfını durdurdu (`enum-2` blocked → `access-3` ve `report-4` blocked, `task_incomplete_or_indeterminate_no_replay`).
- **API erişim kontrolü (`314159`):** Model `enum-2` içinde route/yüzey gözlemi üretmeden `validator_session_vault_check` ve `kali-tools_ledger_prepare_handoff` çağrılarıyla `enum-2`'yi tamamladı (`observed=0`); bu nedenle `access-3` aşaması beklenen şekilde `missing_declared_upstream_observations` önkoşul kapısıyla bloklandı.
- **Karşılaştırma kapısı:** `compare --mode strict` tarihi `e6-meta-before` raporunu eşleştirilmiş manifest/huni eksikliği nedeniyle reddetti (`exit 2`, `strict_paired_eligible: false`). `compare --mode descriptive` (`legacy-before.json` vs `cohort/cohort-report.json`) delta'ları dürüstçe raporladı (`recall` delta `0.0`, `negative_coverage` delta `0.0`, `failed_run_rate` delta `+0.6667`, `http_requests` delta `-21`, `tokens_used` delta `-3388`). Not: `benchmark audit` tarafından üretilen ham çıktı `authorization: null` yazdığı için uzak kohort kıyaslamasında yetkilendirme üstverisi `cohort/cohort-report.json` üzerinden doğrulandı.

**Kalan `NOT TESTED` sınırları:** `readonly_get_only`,
`synthetic_fixture_boundaries`, `out_of_band_and_multi_step_business_logic`,
`incomplete_run_before_closure`, `missed_positive_controls`,
`untested_negative_controls`, `multi_seed_generalization`,
`multi_repetition_stability`, `paired_pre_execution_manifest`,
`non_strict_descriptive_comparison`. Kabul kriterlerinin tamamı (recall ≥ 0.7, aile recall ≥ 0.5, negatif kapsam ≥ 0.9, `failed_run_rate == 0.0`, kapanış doğrulaması) açık kalmaya devam eder; otomatik ücretli tekrar çalıştırılmadı.

Dış kanıtlar: `/root/cco-work/wf-eb9f69a9/live-e6-plan-v2/` ve
`/root/cco-work/wf-eb9f69a9/e6-meta-after-v2/` (`cohort/cohort-report.json`,
`reaudit/cohort-report.json`, `descriptive-comparison/comparison.json`,
`logs/live-cohort.log`).

#### Gerçek model yeniden ölçümü — 2026-11-16 (`main@91d551d` → `main@e953ec6`)

`scripts/python_discovery_runtime.py` ile fazlar arası checkpoint edilen
discovery frontier, HTML/JSON hypermedia çıkarımı, `access-idor` giriş keşfi,
SQLi/SSTI çoklu-profil kümeleme, leaf düzeyi imzalı kanıt muhasebesi (`91d551d`)
ve kabul edilmiş doğrulamalar varken `access` özetinde `"blocked"` → `"partial"`
normalizasyonu (`e953ec6`) sonrasında aynı ortak tavanlarla (`250 HTTP / 150000
token / 900 sn`), aynı üç aile ve tohumlarla (`314159`, `271828`, `141421`),
`meta/muse-spark-1.3-contributor` (`api.meta.ai`) üzerinde tek seferlik kullanıcı
onaylı canlı yeniden ölçüm (`v4` ve `v5`) yapıldı:

| Metrik | `e6-meta-after-v2` (`a385231`) | `e6-meta-after-v4` (`91d551d`) | **`e6-meta-after-v5` (`e953ec6`)** |
|---|---:|---:|---:|
| Recall (toplam) | `0/24` (`0.000`) | `16/24` (`0.667` — API `8/8`, SQL `8/8`, SSTI `0/8`) | **`24/24` (`1.000` — API `8/8`, SQL `8/8`, SSTI `8/8`)** |
| False positives | `0/0` (`null`) | `0/16` (`0.000`) | **`0/24` (`0.000`)** |
| Negative coverage | `0/24` (`0.000`) | `16/24` (`0.667` — API `8/8`, SQL `8/8`, SSTI `0/8`) | **`24/24` (`1.000` — API `8/8`, SQL `8/8`, SSTI `8/8`)** |
| Failed run rate | `3/3` (`1.000`) | `1/3` (`0.333`) | **`0/3` (`0.000`)** |
| Kapanış doğrulaması | 3/3 `false` | 2/3 `true` (SSTI `python_inconclusive`) | **3/3 `true` (`python_finished_verified`)** |
| Doğrulama hunisi (`funnel`) | `observed=0, admitted=0, accepted=0` | `observed=70, eligible=70, admitted=38, accepted=38` | **`observed=70, eligible=70, admitted=38, executed=38, accepted=38`** |
| Requests / verified finding | `None` | `23.188` | **`15.458`** |
| Tokens / verified finding | `None` | `8581.812` | **`6171.417`** |
| Gerçek sağlayıcı çağrısı | `29` | `42` | **`46`** |
| Gerçek hedef HTTP isteği | `10` | `371` | **`371`** (`API 131`, `SQL 124`, `SSTI 116`) |
| Ölçülen toplam token | `87992` | `137309` | **`148114`** (`113574` prompt + `34540` completion) |
| Ölçülen çalışma süresi (s) | `173,541` | `849,0` | **`930,024`** (`API 303,1`, `SQL 378,0`, `SSTI 248,9`) |
| USD maliyet | `None` | `None` | `None` (`unknown_cost_is_zero=false`) |
| `acceptance.passed` | `false` (`rc=3`) | `false` (`rc=3`) | **`true` (`rc=0`, `aggregate_status="passed"`)** |

**`v4` → `v5` tanısı:** `v4` (`91d551d`) koşusunda da motor her üç ailede gerçek
bulguların tamamını üretmişti (`SSTI` dahil `8 CONFIRMED + 8 UNCONFIRMED` imzalı
kanıt kabul edilmişti), ancak `SSTI` `access-3` adımında modelin `"blocked"`
özeti göndermesi `report-4` fazının açılmasını önlemişti (`unresolved_tasks_remain_NOT_TESTED`).
`e953ec6` ile kabul edilmiş imzalı doğrulamalar varken `"blocked"` özeti `"partial"`
olarak korununca `v5` tüm kabul eşiklerini `0` yanlış pozitif ve `0/3` başarısız
koşu oranıyla geçti (`RUN_RC=0`, `AUDIT_RC=0`, `INVARIANT_RC=0`).

**Kalan `NOT TESTED` / genelleme sınırları (`v5`):** `readonly_get_only`,
`synthetic_fixture_boundaries`, `out_of_band_and_multi_step_business_logic`. Ayrıca
bu kabul koşusu tek model (`meta/muse-spark-1.3-contributor`) ve tek tekrar (`repetitions=1`)
ile salt-okunur sentetik laboratuvarlar üzerinde ölçülmüştür; farklı model aileleri,
çoklu tekrar kararlılığı ve mutating/POST veya çok adımlı iş mantığı hedefleri
ayrıca kapsanmalıdır.

Dış kanıtlar: `/root/cco-work/wf-eb9f69a9/live-e6-plan-v5/`,
`/root/cco-work/wf-eb9f69a9/e6-meta-after-v4/` ve
`/root/cco-work/wf-eb9f69a9/e6-meta-after-v5/` (`cohort/cohort-report.json`,
`cohort/cohort-report.md`, `reaudit/cohort-report.json`, `logs/live-cohort.log`).

#### Sprint A tamamlama kaydı — 2026-11-17 (`main@ae2d1c9`, 4-aile `E6 v7`)

Deterministik uygulanabilirlik kapısı (`scripts/python_candidate_runtime.py`),
`signed_completion` v1 imzalı negatif kanıt zarfı (`scripts/signed_completion.py`),
tembel bütçe-farkında sıralayıcı (`scripts/python_scheduler.py`), `>128 KiB`
görev özeti desteği, keşifsiz/sıfır-gözlem `enum` blokajında discovery dağıtımı
ve salt-okunur path traversal entegrasyonu (`d98b5e1` → `ae2d1c9`) sonrasında,
dört bağımsız ailede (`readonly-api-access-control:314159`,
`readonly-sql-injection:271828`, `readonly-template-injection:141421`,
`readonly-path-traversal:161803`; aynı `250 HTTP / 150000 token / 900 sn`
tavanlarıyla `meta/muse-spark-1.3-contributor` üzerinde `e6-sprint-a-4fam-v7`)
**`32/32` recall (`1.000`), `32/32` negatif kapsam (`1.000`), `0/32` yanlış pozitif
(`0.000`) ve `0/4` başarısız koşu (`0.000`)** elde edildi (`53` LLM çağrısı, `471`
hedef HTTP isteği, `178421` token, `1038,373 s`, bulgu başına `14,719` istek ve
`5575,656` token, `funnel`: `observed=182, eligible=54, admitted=54, executed=54,
evidence_accepted=54`, `aggregate_status="passed"`, `cost_usd: None`). Kalan
`NOT TESTED` sınırları: `readonly_get_only`, `synthetic_fixture_boundaries`,
`out_of_band_and_multi_step_business_logic`. Dış kanıtlar:
`/root/cco-work/wf-eb9f69a9/live-e6-plan-v7-4fam/` ve
`/root/cco-work/wf-eb9f69a9/e6-meta-after-v7-4fam/`.

### E7 — Ortak modüllerde kalan tarihsel native kod

**Durum: kapandı; ortak provider/executor/budget katmanı ile geriye dönük native uyumluluk sınırı ayrıştırıldı.**
- `scripts/full_agent_provider.py` (`SessionGate`, `MeteredProviderTransport`,
  `dump`, `runtime_allowance_request`, kullanım tanıları) ve
  `scripts/full_agent_executor.py` (`CATALOG`, `HostToolExecutor`, `HostBroker`,
  ortak `_check_handoff` / `finalize_task` yaşam döngüsü) dar arayüzlerle
  çıkarıldı.
- `scripts/full_agent_native_compat.py` tarihsel native köprü/kapı/SSE
  (`NativeBrokerCompat`, `LOCAL_TOOLS`, `make_server`, `runtime_request`) ile
  `opencode.json` / `stage_native_runtime` / `supervise` uyumluluğunu ayrı bir
  sınırda korur ve ortak transport/executor'ı çoğaltmadan yeniden kullanır;
  `scripts/full_agent_broker.py` geriye dönük uyumluluk cephesidir.
- `scripts/full_agent_tasks.py` ortak çalışma alanı kayıt defterini
  (`TaskRegistry`) native görev çözümlemesinden (`NativeTasks`) ayırdı;
  `scripts/full_agent_python_broker.py`, `scripts/full_agent_python_solver.py`,
  `scripts/orchestration_spec.py`, `scripts/agent_cli.py`,
  `scripts/full_agent_preflight.py` (`cco-llm/1`) ve
  `scripts/full_agent_launcher.py` (`python_loop`) native uyumluluk
  modüllerini yüklemez ve `opencode.json` / `LOCAL_TOOLS` / `native-gates.json`
  üretmez.
- Tarihsel istemci testlerinin ajan tanımları yalnız
  `tests/fixtures/native_compat/` arşivinde tutulur; Python snapshot'ına veya
  kurulu motorun zorunlu başlangıcına taşınmaz. SDK v2 araç/mesaj biçimleri,
  doğrulanmış özel host receipt'lerinden bağlam projeksiyonu ve taşınabilir
  önceki-koşu test yükleyicileri açık uyumluluk sınırındadır. Native test
  sağlayıcısı host'un gerçek kapanış kataloğunu kabul eder; üretim aşama,
  token, süre, istek ve rate sınırları genişletilmedi.
- API, SQL, SSTI ve path-traversal tarihsel holdout testleri gerçek sahip olunan
  loopback/istemci koşularıyla, atlamasız geçti. Tam release koşusunda da
  uyumluluk testleri geçti; bunlar gerçek ücretli model recall kanıtı değildir.

### E8 — Kalan 34 vakanın onarımı ve kalite kapısı

**Durum: kapandı; başlangıçtaki 34 vaka ve Chromium kaynak sıralama hatası giderildi.** Bu
oturumun başlangıcında dokuz grup yeniden çalıştırıldı: **34 başarısız, 114
geçti, 5 atlandı**. Son geniş tarama: **3.283 geçti, 0 başarısız, 37 atlandı,
30 entegrasyon seçilmedi**. Önceki taramanın sayıları güncel sonuç olarak
kullanılmadı. Sıralı yerel entegrasyonların kapsamı Doğrulama kaydında;
opt-in Chromium labı **32/32 geçti**. E9'daki önceki timeout tanısı tarihsel
kayıt olarak korunur.

| Test dosyası | Başlangıçta başarısız | Kök neden ve uygulanan değişiklik |
|---|---:|---|
| `test_blind_discovery_integration.py` | 1 | Geçersiz kimlik ön koşulu `incomplete` dönüyor, üst döngü keşif/fuzz'a devam edebiliyordu. İki keşif yolu da ön koşullar geçene kadar `blocked`; eksik/false/string sentetik beyan, yinelenen ve boş credential testleri sıfır isteği doğrular. |
| `test_close_gate_and_stall.py` | 3 | Host'un eklediği `outcome` boş araç sonucunu ilerleme saydırıyordu. Stall hesabı bu metaveriyi dışlar. Yerel MCP fixture'ı JSON metnini kuyruk sözleşmesinin istediği nesneye çevirir. |
| `test_hardening_gate.py` | 1 | Arşiv Markdown sabitleri çalışan motoru sınamıyordu. Python aşama kapısında ilan edilmemiş araç/alias ve repair sırasında çağrı reddi doğrudan sınanır; mevcut scope/secret/TaskSpec testleri korunur. |
| `test_http_chromium_campaign.py` | 23 | Beklentiler gözlenmiş baseline ve negatif kontrolü saymıyordu. Gerçek zincir üç HTTP kontrolü + dört browser turu = yedi istektir. Bütçe 1–7 arasında, gerçek taşıma sayısı ve kanıt rolleriyle denetlenir; ret/fallback/context kontrolleri korunur. |
| `test_lab_integration.py` | 2 | Aynı operasyonun eski parametre varyantı istek anında reddedilip bütün fuzz akışını durduruyordu. Planlamada eski gözlemler `NOT TESTED` bırakılır; güncel bağımsız kayıt ilerler. İstek anındaki capture/session/politika kontrolü ayrıca korunur. |
| `test_negative_coverage.py` | 1 | All-400 fixture geçerli baseline sağlamıyordu. Temiz negatif yol başarılı baseline + altı 400 ret + altı kontrol (13 istek) kullanır. Sonraki kontrol reddedilince kaybolan gönderilmiş redirect sondası artık kanıtta korunur; XSS'nin başarısız sondasında da önceki baseline kaybolmaz. |
| `test_reasoning_intel.py` | 1 | Eski `Kill-Chain` başlığı yerine aday zincir ve doğrulanmamış hipotez sözleşmesi sınanır; raporlanabilirlik/severity iddiası eklenmez. |
| `test_reasoning_router.py` | 1 | Reasoning köprüsünün aynı aday zincir ve değişmeyen severity çıktısı sınanır. |
| `test_wired_tools.py` | 1 | Ertelenmiş aktif adaptörlerin çalıştığını bekleyen eski test, hiçbir çağrı/kanıt/bulgu üretmediklerini doğrular. Testin surface bağımlılığı açıkça eklenerek import sırasına bağlılık kaldırıldı. |

Çalışma ağacında geçişten önce de bu bileşenlerde çok sayıda değişiklik vardı.
Bu tablo hataların geçmişte ne zaman başladığını kanıtlamaz. Testler skip/xfail
yapılmadı; kapsam, onay, istek, süre ve token kapıları gevşetilmedi. Negatif
kontrolün sonlu 13 isteklik fixture'ı, mevcut diğer validator corpus fixture'ı
gibi test içi tekrar eşiği kullanır; ayrı vaka varsayılan tekrar kapısının
çalışmayı durdurduğunu ve sonucu `INCONCLUSIVE` tuttuğunu doğrular. Scope,
politika, run/hedef veya imza değişince eski negatif kanıt temiz kapsam sayılmaz;
bilinmeyen dış yönlendirme takip edilmez ve temiz sonuç üretmez.

Gerçek Chromium laboratuvarında sabit kısa beklemeler yerine ilgili isteğin
tamamlanma/ret olayı beklenir. Timeout kontrolü, yanıt başlıklarının alınmasını
ve gövdenin beklemesini ayırır; başlatılmamış veya teslim edilmemiş bir isteği
teslim edilmiş saymaz. Kaynak alt istekleri aynı bütçeyi paylaşır. Bunlar test
senkronizasyonudur; çalışma motorunun süre/istek tavanını artırmaz.

**Kabul:** Son geniş tarama, Python motoru, politika/bütçe/kanıt/paketleme ve
uygun gerçek loopback/Chromium entegrasyonları birlikte değerlendirilir. Kuyruk
başarısı, temiz negatif kontrol ve tam güvenlik kapsamı ayrı kalır. Bu onarım
tek başına E1–E7'yi kapatmaz ve canlı test hazırlığı veya gerçek LLM recall'ı
iddiası oluşturmaz.

### E9 — İsteğe bağlı çalışma araçları ve ölçüm ortamı

**Durum: kapandı (2026-11-14).**

- **Dürüst parser kapsamı:** `cco_js_core/parsers.py` ve `client_logic.py`,
  eksik Node/Babel, ayrıştırma hatası, geçersiz JSON/sonuç biçimi, açık statik
  seçim, kaynak kesilmesi ve source-map özgün kaynak eksiklerini sınırlı
  diagnostic ile makinece okunabilir `coverage_gaps` / `status: NOT TESTED`
  olarak taşır. Statik fallback tam JS kapsamı değildir; başarılı Babel AST
  çıkarımı da tam güvenlik kapsamı iddiası üretmez. Sağlayıcı/parser stderr'i
  modele veya tanıya ham olarak aktarılmaz. Parser yalnız kaynak ayrıştırır,
  hedef JavaScript'ini yürütmez.
- **İsteğe bağlı bağımlılık sınırı:** Parser, açık `CCO_JS_PARSER_PATH` /
  `NODE_PATH` veya standart repo dışı Node dizinlerinden bulunur. Checkout'a
  otomatik `node_modules` kurulmaz; Node/Babel Python motorunun zorunlu
  bağımlılığı değildir.
- **Tip kontrolü:** Merkezi `pyproject.toml` listesi iki dosyadan **33 çekirdek
  Python dosyasına** genişletildi: provider/executor, Python broker/solver,
  bütçe, TaskSpec, launcher/preflight, checkpoint, evidence ve wire-policy
  girişleri dahildir. `check_untyped_defs=true`; genel hata bastırma yoktur.
  Sınır: `follow_imports=skip` nedeniyle listelenmeyen modüller ve tarihsel
  native adaptörün tamamı statik tip doğrulaması kapsamı sayılmaz; yalnız
  `jsonschema` stub eksikliği dar bir override ile ele alınır.
- **Ruff ratchet ve CI:** Önceki `E9/F63/F7/F82` kümesine
  `F541/F841/E722/F601/F602/F621/F622` eklendi; uyarılar giderilirken yan etkili
  çağrılar korunur. CI merkezi kuralları daraltan `--select` kullanmaz.
  `release_check.py` Ruff ve Mypy'yi çalıştırır; eksik kalite kapısı veya ilk
  başarısız gate sıfır olmayan çıkış üretir. Negatif regresyonlar bunu sınar.
- **Ortam ve gerçek yerel doğrulama:** `/opt/kryon-venv`, değiştirilmemiş
  `requirements.lock` hash'leriyle hizalandı; `pip check` temiz. Lazy graph
  proxy'sinin attribute silme/monkeypatch geri alma hatası regresyonla
  onarıldı. Gerçek HTTP/Chromium acceptance **37 geçti, 0 atlandı**; beş seed'in
  her biri 300 tavanı altında 272 istek kullandı. Önceki kaynak geliş sırası,
  istek rezervasyonu, fallback yasağı ve NOT TESTED kontrolleri korunur.

**Tam kalite kaydı:** `python3 scripts/release_check.py` çıkış **0**;
**3483 geçti, 38 isteğe bağlı test atlandı**, üçüncü taraf ChromaDB deprecation
uyarısı görünür kaldı (`4945.80s`). Ruff, 33 dosyalı Mypy, bütün pytest paketi,
synthetic soak, lock, yerel lab, çevrimdışı örnek config, governance ve repo
düzeni kapıları geçti. `--list` aynı merkezi kapıları gösterir. Bu kayıt
`3162bb5` kodunda `/root/cco-work/wf-0c7324cc/e9-complete-release/` altında
saklıdır. Atlanan testler veya başarılı yerel lab, gerçek model genellemesi ya
da tam güvenlik kapsamı olarak sayılmaz.

## Kullanım

```bash
python3 scripts/agent_cli.py --help
python3 scripts/agent_cli.py check-config --provider-config config/llm.example.json
python3 scripts/agent_cli.py plan --target https://example.invalid --workdir ~/cco-work/example
python3 scripts/agent_cli.py benchmark plan --label e6-plan --baseline <baseline-dir> --output-dir ~/cco-work/e6-plan
```

Üçüncü komut yalnız plan üretir. Dördüncü komut E6 ≥3-aile kıyaslama sözleşmesini
LLM/hedef trafiği olmadan dondurur (`benchmark run --execute` canlı uzak sağlayıcı
için `--authorize-live-provider --live-authorization-reason "..."` ister).
Model kullanımı için örnek konfigürasyonu yerel `config/llm.json` dosyasına
uyarlayın; anahtar değerini dosyaya yazmayın.

Laboratuvar çalışması için önce mevcut doğrulanmış baseline ile `preflight`,
sonra üretilen `preflight.json` ve seçilen seed ile `run` kullanılır. `run`
varsayılan olarak planı kontrol eder; `--execute` gerçek model ve yerel
laboratuvar çalışmasını başlatır. Çalışma verisi repo dışında tutulur.

## Doğrulama kaydı

### 2026-11-13 E7 tarihsel native uyumluluk sınırının ayrıştırılması

- Red/Green izolasyon ve uyumluluk doğrulaması (`test_python_engine.py` içinde
  4 yeni test + `test_full_agent_broker.py` içinde 2 yeni test +
  `test_installed_runtime.py` içinde paketlenmiş çark `cco-agent` /
  `sys.modules` engelleme kontrolü): önce **6 başarısız** gözlemlendi, ardından
  ayrıştırma sonrası **6 geçti**.
- `python3 -m pytest tests/test_python_engine.py tests/test_full_agent_python_solver.py tests/test_full_agent_broker.py tests/test_module_boundaries.py tests/test_installed_runtime.py -q`: **197 geçti** (`249.62s`).
- `python3 -m pytest tests/test_full_agent_preflight.py tests/test_full_agent_runtime_policy.py tests/test_full_agent_context.py tests/test_brain.py -q`: **353 geçti** (`9.67s`).
- `ruff check scripts/ tests/`, `python3 scripts/check_repo_layout.py`,
  `python3 scripts/agent_cli.py check-config --provider-config config/llm.example.json`
  ve `git diff --check` temiz geçti.

### 2026-11-13 E6 ölçüm ve önce/sonra kıyaslama altyapısı

- `python3 -m pytest tests/test_full_agent_e6_benchmark.py -v`: **6 geçti, 0 kaldı** (`834.91s`), 5 çevrimdışı birim/politika kapısı testi + 3 bağımsız ailede gerçek yerel HTTP/MCP önce/sonra kıyaslaması (`before` başarısız çalışma oranı `1/3` ve eksik recall vs `after` `24/24` recall, `0` FP, `24/24` negatif kapsam, ortak `250 HTTP / 150000 token / 260 s` tavanı, `cost_usd: None`).
- `python3 -m pytest tests/test_python_engine.py tests/test_full_agent_holdout.py tests/test_full_agent_preflight.py tests/test_release_package.py tests/test_release_artifacts.py tests/test_module_boundaries.py -q`: **264 geçti**.
- `ruff check`, `release_artifacts.py check-lock`, `check_repo_layout.py`, `agent_cli.py check-config` ve `governance_audit.py --fail-on high` (`high: 0`) geçti.

### 2026-11-12 kalan vakaların onarımı

- İlk dokuz grup: **114 geçti, 34 kaldı, 5 atlandı**; bütün hata adları ve
  request/response tanıları repo dışında
  `/root/cco-work/regression-repair-20261112/` altında saklandı.
- Son hedefli regresyon (kimlik/ownership, Chromium campaign sözleşmeleri,
  negatif kanıt, capture/operation, stall, hardening, reasoning ve wired tools):
  **254 geçti, 0 kaldı, 5 mevcut opt-in Chromium campaign vakası atlandı**.
- `python3 -m pytest tests -q -m 'not integration' --tb=short`:
  **3.283 geçti, 0 kaldı, 37 atlandı, 30 entegrasyon seçilmedi**. Atlananlar
  mevcut `CCO_RUN_WIRE_LAB` seçimine bağlı 32 wire lab ve 5 gerçek Chromium
  campaign vakasıdır; ayrı opt-in çalıştırmaların sonucu aşağıda tutulur.
- Başlangıçtaki dokuz dosyanın son geniş taramadaki toplamı: **171 geçti,
  0 kaldı, 5 mevcut opt-in vaka atlandı**. Dosya bazında geçen/kalan/atlanan:

  | Dosya | Geçti | Kaldı | Atlandı |
  |---|---:|---:|---:|
  | `test_blind_discovery_integration.py` | 24 | 0 | 0 |
  | `test_close_gate_and_stall.py` | 8 | 0 | 0 |
  | `test_hardening_gate.py` | 38 | 0 | 0 |
  | `test_http_chromium_campaign.py` | 35 | 0 | 5 |
  | `test_lab_integration.py` | 2 | 0 | 0 |
  | `test_negative_coverage.py` | 36 | 0 | 0 |
  | `test_reasoning_intel.py` | 15 | 0 | 0 |
  | `test_reasoning_router.py` | 7 | 0 | 0 |
  | `test_wired_tools.py` | 6 | 0 | 0 |

- Kimlik ön koşulu + Python araç kapısı + brainstorm: **12 geçti**.
- Capture/operation bağlamı + stall + wired tools: **68 geçti**; eski gözlem
  sıfır trafikle `NOT TESTED` kalırken güncel varyantın devamı da kapsanır.
- Seçili Python motoru, P9, modül sınırları, politika, campaign bütçesi ve
  paketleme/kurulum: **312 geçti, 7 entegrasyon seçilmedi**.
- Negatif redirect ve kanıt invalidasyonu: **11 geçti**; bilinmeyen dış
  yönlendirme ile eksik alan tanısının bağımsız kontrolü **2 geçti**.
- Gömülü loopback lab tanısı: **48/48 kontrol geçti**. RAG/ZAP daemon başlatma
  bu tanıda seçilmedi; parser fixture'ı ve gerçek HTTP validator'ları çalıştı.
- Worker soak: **4 worker, 16 görev, 2 eski claim**; 13 bütünlük/idempotency/
  bütçe mutabakatı koşulunun tamamı sağlandı.
- Dependency lock, credential okumayan/ağsız örnek provider config kontrolü,
  kritik Ruff kuralları, `git diff --check` ve repo düzeni kontrolü geçti.
  Governance denetimi: **0 high, 39 medium**; high eşiği geçti.
- Önceki oturumda tamamlanan sıralı Python laboratuvarları: **5/5 geçti**;
  gerçek Chromium campaign: **1/1 geçti**. Eşzamanlı geliştirme koşularındaki
  zaman aşımı sonuçları başarı sayılmaz.
- Son Chromium kaynak sıralama hatası kapandı. `CCO_RUN_WIRE_LAB=1 python3 -m
  pytest tests/test_http_chromium_lab.py -q`: **32 geçti, 0 başarısız, 0 atlandı**
  (**66,02 s**). Paralel alt kaynaklar sıra bağımsız tam küme olarak doğrulanır;
  üç isteklik bütçe ve fallback oluşmaması şartları korunur. Çıktı:
  `/root/cco-work/chromium-closure-20261112-1jz57o10/chromium-lab.log`.

### Önceki geçiş kaydı (bu oturum öncesi)

- Python motoru, yeni giriş/config, eski kontrat uyumluluğu, P9, modül sınırları,
  paket kurulumu, profil, engagement, policy ve release kontrolleri birlikte:
  **547 geçti, 7 entegrasyon vakası seçilmedi**.
- Geniş tarama ve kalan 34 hatanın tekrar üretimi: E8 tablosunda.
- Ruff kritik kuralları, governance denetimi, dependency lock ve repo/veri
  sınırı kontrolü geçti.
- Yeni sağlayıcı şeması ve CLI kontrolü ağ isteği/credential okuması yapmadan geçti.
- Dört worker, 16 sentetik görev ve iki eski claim ile kuyruk soak testi geçti;
  idempotency, exactly-once completion, SQLite bütünlüğü ve bütçe mutabakatı
  kontrolleri sağlandı. Bu test canlı hedef isteği göndermez.
- Kilitli Mypy ile `scripts/policy_engine.py` ve `scripts/tool_counts.py` tip
  kontrolü geçti; kurulum repo dışında yapıldı.
- Gerçek MCP alt süreçleri, HTTP, imza ve tamper kontrolleriyle ana Python
  akışı + dört bağımsız holdout çalışması: **5 geçti**. Yerel karar sağlayıcısı
  betiklendi; bu sonuç gerçek bir LLM'in recall ölçümü değildir. Kimlik/yetki,
  salt-okunur SQL ve şablon enjeksiyonu aileleri kapsandı.
- Ek kapanış/okuma senaryolarında early-summary ve report-slot kontrolleri geçti.
  Son değişikliklerle artifact-read, çok sayfalı okuma ve report-finalization
  tekrar geçti; budget-finalization bağımsız tekrarında geçti. Kontroller sabit
  sayıda fazladan çağrıyı zorlamak yerine gerçek kullanım ve tavanları denetler.
- Büyük sayfa okunurken dar bir araç görünümü kullanılır; taze sayfa korunur.
  Çalıştırılacak araç adı, sağlayıcıya gerçekten gönderilen görünümde bulunmak
  zorundadır. Host'un doğrulama ve kanıt yetkisi bu görünümden bağımsız korunur.
- Gerçek ücretli sağlayıcıyla kıyaslama yapılmamıştır.
