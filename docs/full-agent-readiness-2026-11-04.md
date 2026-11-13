# Tam OpenCode ajan kabulü: hazırlık sınırı

Tarih: 2026-11-04. Durum: **hazırlık altyapısı uygulandı; tam ajan koşusu
başlamadı**. Önceki [gerçek HTTP/Chromium kabulü](http-chromium-reacceptance-2026-11-04.md)
beş seed'de 8/8 pozitif ve 8/8 temiz negatif verdi. Bu sonuç native OpenCode
planner/worker/closure başarısı veya bağımsız holdout kabulü değildir.

## İncelemede bulunan eksikler

`scripts/lab/blind_agent_run.py` doğrudan deterministik `hunter.run_web_loop`
çağırır. `scripts/blind_run.sh` host kökünü salt okunur, host `/tmp` dizinini
yazılabilir bağlar; bu düzen lab kaynağını ve önceki sonuçları ajandan gizlemez.
Dolayısıyla bu iki yolu yalnız bir LLM komutuyla birleştirmek tam kör ajan
benchmark'ı olarak raporlanamaz.

Native akış `.opencode/agents/kalibounty.md`, `worker.md`, `brain.py` ve
imzalı closure sözleşmesini kullanmalıdır. Sadece modelin son mesajı veya
deterministik campaign çağrısı, planner/worker/closure kanıtı yerine geçmez.

## Uygulanan hazırlık

`scripts/full_agent_preflight.py` LLM çağrısı veya lab koşusu başlatmadan:

- Kayıtlı karşılaştırma manifestini JUnit ve beş seed'in ölçümleriyle yeniden
  eşler; `blind-lab/3` ve 8/8 pozitif bazını ister. Artifact/hash referansını
  yeni, özel operatör sözleşmesine kaydeder.
- Planner/worker model adlarını seçilen provider kataloğuna karşı denetler;
  provider credential değerlerini çıktıya kopyalamaz. Worker seçilmezse
  sözleşme açıkça planner ile aynı modeli seçer; canlı repo ayarları değişmez.
- Runtime kodunu izin listesiyle ayrı, salt okunur bir pakete kopyalar.
  Lab/değerlendirici, tests/docs, graph, `.git`, eski policy, oturumlar ve
  sonuçlar pakete alınmaz. Kaynak ve çıktı dosyaları hash'lenir.
- Paket başlangıç scope'unu boş, araç politikasını kapalı üretir. MCP
  transport'u eklenmez; paket **`runnable=false`** durumundadır. Bu durum
  native yürütücünün henüz uygulanmadığını görünür tutar.
- OS ön kontrolünde host root veya host `/tmp` mount etmek yerine izinli
  executable/library dizinlerini kullanır. Ayrı PID/IPC/UTS namespace ve
  temiz environment içinde özel sentinel'in okunamadığını, çalışma dizininin
  kullanılabildiğini gerçek subprocess ile sınar. Eksik nonce'lu veya boş
  çıktı, exit code sıfır olsa da izolasyon kanıtı sayılmaz.

Özel kontratın sınırları seed başına **300 HTTP isteği**, **30 dakika** ve
operatörün seçeceği LLM token bütçesidir. Fresh native session, task delegation,
gerçek araç artifact'leri, güncel imzalı coverage, gate tarafından imzalanmış
closure, toplam HTTP/LLM kullanımı, süre ve sözleşme onarım sayısı zorunlu
ölçümler olarak kaydedilir. Bilinmeyen maliyet sıfıra çevrilmez.

## Bu oturumdaki sonuç

Sağlık kontrolü **7/7**, hazırlık ve kabul kapısı testleri **36/36** geçti.
Gerçek hazırlıkta OpenCode ve bubblewrap bulundu; ancak:

- Loopback socket: `PermissionError: [Errno 1] Operation not permitted`.
- Bubblewrap: `Creating new namespace failed: Operation not permitted`.

Sonuç **`environment_unavailable`**, çıkış kodu **2**. LLM çağrısı ve hedef
isteği **0**. Model/bütçe sorusu kullanıcıya iletildi; ücretli koşu başlamadı.

Artifact dizini:
`/tmp/cco-work/full-agent-preflight/preflight-a09u1u_p/`.
`preflight.json` ortam sonucunu; `contract.json` operatör sözleşmesini;
`runtime-index.json` **206** dosyalık paketin hash'lerini içerir.
`runtime/` ajan paketidir; özel kontrat paketin dışındadır.
Offline JUnit: `/tmp/cco-work/full-agent-preflight-verified.xml`.

Socket/namespace erişimli ortamda yalnız ön koşulları tekrar sınamak için:

```bash
python3 scripts/full_agent_preflight.py \
  --baseline /tmp/cco-work/http-chromium-reacceptance/run-74exq857 \
  --output-dir /tmp/cco-work/full-agent-preflight
```

`--model`, `--worker-model` ve `--token-budget` ile sözleşme seçimleri verilir.
Token bütçesi verilmezse ortam hazır olsa bile `configuration_required`
durumu ve çıkış kodu 3 üretilir. `prerequisites_ready` ve çıkış kodu 0 da
**ajanın çalıştığı veya kabulün geçtiği anlamına gelmez**.

## Launcher bağlantısı — 2026-11-05

`scripts/full_agent_launcher.py` ortak bütçeyi, host broker'ı ve solver
köprüsünü bağlar. Varsayılan çağrı **offline `plan_only`** durumundadır;
`--execute` verilmeden lab, native oturum veya provider çağrısı başlatılmaz.
Launcher, preflight kontratını, baz ölçümleri ve runtime dosya hash'lerini
yeniden denetler; kaynak artifact'lerin üzerine yazmaz.

Çalıştırma yolu her seed için yeni bir dizin, exact loopback scope, salt
okunur politika ve sentetik vault oturumları kurar. Oturum sağlık istekleri
de aynı **300 HTTP / 30 dakika** bütçesinden düşülür. Planner, worker ve
küçük yardımcı model aynı metered provider'a; MCP katalogları host broker'a
yönlendirilir. Bu dilim tek bir OpenAI-compatible provider destekler.
Provider anahtarı yalnız launcher ortamından alınır
(`CCO_BENCHMARK_API_KEY` veya `--api-key-env`); solver'a taşınmaz.

Solver'ın ağ namespace'i ayrıdır. Yalnız Unix socket köprüsü, runtime,
çalışma dizini, public doğrulama anahtarı ve redakte edilmiş imzalı validator
artifact'leri bağlanır. Son iki dizin salt okunurdur; signing key, session
vault, değerlendirici ve önceki oturumlar host'ta kalır. Köprü nonce kontrolü
başarılı olmadan OpenCode başlatılmaz. Süre sınırı, kesinti veya geçersiz
usage durumunda native süreç grubu ve host araç çocukları durdurulur;
mevcut araç çıktıları ve bütçe rezervasyonları saklanır.

Örnek offline inceleme (`PREFLIGHT_MANIFEST`, seçilmiş `preflight.json` yolu):

```bash
python3 scripts/full_agent_launcher.py \
  --preflight "$PREFLIGHT_MANIFEST" --seed 20261104
```

Gerçek başlatma ayrıca `--execute`, açıkça seçilmiş preflight token bütçesi,
`prerequisites_ready` ve provider ortam anahtarı ister. Preflight'ta token
bütçesi verilmezse `configuration_required` davranışı geri yüklenmiştir.

`launch.json`, yeni runtime indeksi ve `private/` altında native olaylar,
gate kararları, araç indeksi, checkpoint adayları ve bütçe kayıtları üretilir.
Başarılı süreç çıkışı **`native_finished_unverified`** olur;
**`acceptance_passed=false`** kalır. Ölçülmemiş maliyet ve kontrat onarım
sayısı `null` kalır. Token rezervasyonu UTF-8 baytlarından muhafazakâr bir
mühendislik üst sınırı kullanır; provider tokenizer garantisi değildir.
Eksik/geçersiz usage rezervasyonu iade etmez ve sonraki çağrıları durdurur.

Bu dilimin offline kontrolleri snapshot değişimi, kapsam, model/MCP
yönlendirmesi, credential ayrımı, eşzamanlı rezervasyonlar, usage, nonce,
kurulum/kapanış ve kısmi kanıt korumasını kapsar. Ağ bağlantıları test
fixture'ında reddedilir; süreç ve provider uçları test doubles kullanır.
Bu kontroller gerçek native koşu veya kabul kanıtı sayılmaz.

Son offline doğrulama: `test_full_agent_preflight.py` **70/70**;
HTTP/Chromium kabul kapısı ve modül sınırı testleriyle toplam **90/90**,
hata ve atlama **0**. Ruff, JS sözdizimi ve repo düzeni kontrolleri geçti;
kod grafiği `graphify update .` ile güncellendi. LLM veya canlı hedef
çağrısı yapılmadı.

```bash
python3 -m pytest tests/test_full_agent_preflight.py \
  tests/test_http_chromium_acceptance.py tests/test_module_boundaries.py -q \
  --junitxml=/tmp/cco-work/full-agent-launcher-offline-2026-11-05.xml
```

## Tam koşuya geçmek için kalan doğrulama

### Yerel native entegrasyon dilimi — 2026-11-05

`tests/test_full_agent_integration.py`, `integration` işaretiyle eklendi.
Yerel OpenAI-compatible HTTP provider'ı deterministik `tool_calls` ve
sentetik prompt/completion usage döndürür. OpenCode, planner/worker oturumları,
`task`, JS security gate, Unix `host.sock` broker'ı ve MCP executor süreçleri
gerçek uygulamalardır. Karşılaştırma fixture'ı sentetiktir; bu testin geçmesi
beş seed benchmark veya bağımsız holdout kabulü sayılmaz.

Dört test senaryosu şunları denetler:

- İki taze native koşuda ayrı oturum kimlikleri, gerçek delegasyon/gate
  olayları ve planner/worker usage toplamının aynı bütçeye yazılması.
  Kurulum ve iki MCP HTTP çağrısının wire ölçümleri lab sayacıyla eşlenir.
- Solver içindeki Python probe'u, mevcut host canary dosyalarını ve gerçek
  koşunun signing/vault dosyalarını `open()` ile okumayı dener. API key
  environment'ı, `/proc` yolları, lab kaynağı, `tests/answers.py` ve önceki
  koşunun artifact'leri de sınanır. Yazılabilir solver dizini, salt okunur
  scope/public trust ve kullanılabilir bridge pozitif kontrollerdir.
- Timeout ve gerçek CLI `SIGINT` sırasında uzun yaşayan native alt süreçler
  ile bekleyen MCP isteği kapatılır; PID/start-time ile izlenen ağaçta canlı
  süreç kalmaması ve `native-events.jsonl`, `budget.json`, `tool-index.json`
  dosyalarının korunması istenir. Ölçülemeyen HTTP rezervasyonu iade edilmez.
- Eksik provider usage, token rezervasyonunu iade etmeden koşuyu durdurur.

Launcher artık `--provider-config` ile ayrı operatör yapılandırması alır;
`--timeout-seconds` yalnız donmuş kontratın süresini kısaltabilir.
`effective_limits` launch manifestine yazılır. Native dosya araçlarının solver
çalışma dizinine ve public kanıt mount'larına erişimi `external_directory`
izinleriyle tanımlıdır. Provider usage hatasıyla aynı anda native süreç
çıkarsa da sonuç `budget_invalid` olarak korunur.

Bu Codex yürütme bağlamındaki denemede **90 offline test geçti**; dört yeni
entegrasyon senaryosu ön koşulda **hata** verdi: loopback `bind()` ve bwrap
namespace oluşturma `Operation not permitted` döndürdü. Dış ortamda bildirilen
`isolated_solver_namespace: ok` bu alt süreç bağlamında yeniden üretilemedi.
Testler bu durumu atlamaya veya başarıya çevirmiyor. Gerçek native protokol,
izolasyon ve kesinti sonuçları henüz doğrulanmış sayılmaz.

İzinli host'taki takip koşusunda ön koşullar geçti; sonuç **90 başarılı,
4 başarısız** oldu. Dört native günlük de aynı başlangıç hatasını gösterdi:
OpenCode 1.18.35, salt okunur runtime içinde `.opencode/.gitignore` oluşturmaya
çalıştı (`Unknown: FileSystem.writeFile`). Her koşuda kurulumun üç HTTP isteği
ölçüldü; provider çağrısı ve delegasyon sayısı sıfırdı. Örnek kanıt:
`/tmp/cco-work/full-agent-integration/normal-bmbyy53y/runs/native-f88ycq86/private/native-stderr.log`.

Launcher bu dosyayı artık runtime dondurulmadan önce oluşturur ve hash
indeksine ekler; runtime salt okunur kalır. Tek `--chdir` kullanılır.
Entegrasyon hata mesajları redakte edilmiş native stderr özetini gösterir;
artifact konumları xUnit2 uyumlu testsuite properties alanına yazılır.
Bu düzeltmenin offline regresyonu **90/90** geçti:
`/tmp/cco-work/full-agent-startup-fix-offline.xml`.
İkinci host koşusu **91 başarılı, 3 başarısız** verdi: invalid-usage senaryosu
geçti; planner/worker, gerçek gate ve namespace içindeki probe çalıştı.
Başlangıç yaklaşık 80 saniye sürdü ve bazı koşularda MCP grupları araç
listesine giremedi. SIGINT senaryosunda ise pytest kaynak yolundaki
`test_shutdown_*` sözcüğü bash guard'ına takıldı; süreç temizliği tamamlandı
ancak izolasyon probe'u çalışmadı.

Takip düzeltmesi global OpenCode yapılandırmasını da hazır, salt okunur bir
mount'a alır; native otomatik npm bağımlılık kurulumu için yazılabilir global
config bırakmaz. Varsayılan provider auth plugin'leri kapalı, yerel security
gate etkindir. TCP/Unix accept kuyrukları eşzamanlı MCP başlangıcı için 64'e
çıkarılmıştır. Probe bağlamı shell argümanı yerine üretilen Python dosyasında
taşınır; gate kuralları gevşetilmez. Eksik MCP katalogları ve provider fixture
hataları açıkça raporlanır; native INFO günlüğü korunur. Offline regresyon
yine **90/90**; güncel native tekrar koşusunun sonucu bekleniyor.

Sonraki host tekrarında normal entegrasyon testi geçti: iki fresh planner/worker
oturumu, ortak bütçe ve private state izolasyonu doğrulandı. Timeout koşusunda
browser MCP grubunun eksik kalması, kalan başlangıç kararsızlığını gösterdi.
Bridge ve broker artık uzunlukları açık HTTP/1.1 yanıtları kullanır. Broker,
yalnız metin `content` döndürdüğü için FastMCP'nin `outputSchema` alanını
iletmez; araç adları ve giriş şemaları korunur. RPC başlangıç metaverisi
`private/transport-events.jsonl` dosyasında tutulur; payload veya credential
kaydedilmez.

Aynı bağlantıda initialize, boş 202 ve tools/list yanıtlarını standart HTTP
istemcisiyle ayrıştıran yeni offline regresyon geçti. Mevcut 90 testle birlikte
offline sonuç **91/91** oldu (`/tmp/cco-work/full-agent-transport-offline.xml`).
Son socket/namespace erişimli host doğrulamasında **4/4 native entegrasyon**
ve **91/91 offline** test geçti; hata ve atlama sıfırdır. OpenCode'un optional
MCP event-stream GET isteğine bridge artık `Allow: POST`, `Content-Length: 0`
ile boş HTTP 405 döndürür. HTML hata gövdesi ve bağlantı kapatma, eşzamanlı
catalog POST isteklerinde grupların rastgele eksik kalmasına yol açıyordu.
Offline regresyon, aynı bağlantıda GET reddinden sonra POST yanıtının da
ayrıştırılabildiğini denetler; native test her grubun initialize/initialized/
tools-list sırasını artifact üzerinden doğrular.

Beş fresh launch'ın planner ve worker isteklerinde **35 araç** görünür:
**26 MCP**, bunların **8'i kali-tools**. OpenCode 1.18.35 sanitization'ı tireyi
korur; `kali-tools_curl_request` adı ve launcher/broker izinleri değişmez.
İzolasyon kanıtları 25–28 reddedilmiş private yolu, gizli host ağı/environment,
iki salt okunur mount ve farklı PID/network namespace'lerini doğrular.
İzlenen süreç ağaçlarında canlı çocuk kalmadı. Timeout/SIGINT HTTP ve geçersiz
provider usage rezervasyonları ölçüm yokken tam tutarla korunur.

Artifact denetim özeti: `/tmp/cco-work/full-agent-integration-verification.json`.
Ruff ve repo düzeni kontrolleri geçti; kod grafiği güncellendi. Provider ve
karşılaştırma hâlâ sentetiktir; `acceptance_passed=false` korunur.

JUnit: `/tmp/cco-work/full-agent-integration.xml`.
Offline regresyon JUnit: `/tmp/cco-work/full-agent-offline-regression.xml`.
Ortam kontrolleri ve koşu kanıtları: `/tmp/cco-work/full-agent-integration/`.

```bash
PYTHONPATH=scripts python3 -m pytest tests/test_full_agent_integration.py \
  tests/test_full_agent_preflight.py tests/test_http_chromium_acceptance.py \
  tests/test_module_boundaries.py -q \
  --junitxml=/tmp/cco-work/full-agent-integration.xml
```

### Kabul için açık kalanlar

1. Aynı izolasyon ve kapanış kontrollerinin gerçek LLM provider ve benchmark
   koşularında doğrulanması.
2. Ortak bütçe kayıtlarının gerçek HTTP/Chromium ve provider usage ile
   eşlenmesi; provider maliyeti ve kontrat onarım sayısının ölçülmesi.
3. Fresh native planner/worker delegasyonları, aynı beş seed, imzalı closure
   ve doğrulanmış coverage ile deterministik baza karşı ölçüm.
4. Sonraki bağımsız holdout: en az üç farklı uygulama ailesi, 24 pozitif ve
   24 negatif; toplam recall ≥%70, her aile ≥%50, negatif kapsam ≥%90,
   sıfır gözlenen FP. Aynı labın başka seed'i ayrı aile sayılmaz.

M4'ün üç zincir ve güvenli ikiz ölçütü de ayrıca açıktır. Bu hazırlık dilimi
M3 veya M4'ü tamamlanmış saymaz.
