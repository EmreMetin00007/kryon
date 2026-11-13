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

**Durum: ölçüm ve önce/sonra kıyaslama altyapısı tamamlandı (2026-11-13); canlı ücretli model koşusu operatör onayı bekler.**
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

**Doğrulama (yerel loopback lab):** `tests/test_full_agent_e6_benchmark.py` (**6 geçti**):
3 aile gereksinimi, snapshot izolasyonu, canlı sağlayıcı yetki kapısı,
bilinmeyen maliyet politikası, başarısız koşu oranı/kurcalama reddi ve ortak
tavanda (`250 HTTP / 150k token / 260 s`) 3 bağımsız ailede (`readonly-api-access-control`,
`readonly-sql-injection`, `readonly-template-injection`) uçtan uca gerçek yerel
HTTP/MCP önce/sonra kıyaslaması geçti. Ücretli uzak gerçek LLM koşusu ayrıca açık
operatör yetkisi gerektirir (`paid_model_generalization: not_evaluated`).

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
