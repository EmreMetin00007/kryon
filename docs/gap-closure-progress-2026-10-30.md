# Eksik kapatma ilerlemesi — 30 Ekim 2026

Bu belge, [proje incelemesinin](project-review-2026-10-29.md) R05–R14
maddeleri ve [pentest yetenek incelemesinin](pentest-capability-review-2026-10-29.md)
devamı için çalışma ağacındaki durumu kaydeder. 31 Ekim devamında teste ait
loopback sunucuları ve gerçek Chromium ile 32 lab testi ve 4 browser oturumu
testi geçti; ilgili çevrimdışı regresyonda 190 test geçti. Sonuç ve kanıt
[HTTP/Chromium notundadır](http-chromium-lab-2026-10-31.md). Önceki sayılar
tarihsel doğrulamalardır; yeni sonuçlarla toplanmaz. Harici hedef/VDS trafiği
gönderilmedi.

## Uygulananlar

| Alan | Değişiklik ve doğrulama sınırı |
|---|---|
| R05 — nesne kimlikleri | UUID, opaque ve aileye bağlı sayısal kimlikler havuz, imzalı deneme, handoff ve kapsam kontrolünde korunur. Havuz kesilirse kapanış engellenir; büyük havuz ve imzalı kayıt testleri vardır. Kimliğin bir test hesabına ait olduğu ayrıca kanıtlanmalıdır. |
| R06 — dağıtım | Wheel kaynak ağacın dışında kurulup on CLI girişi, 16 MCP sunucusu ve browser/Kali özellikleri sınandı. Release'e yalnız belirtilen profil dosyaları alınır; kullanıcıya özel takip edilmeyen profiller alınmaz. |
| R07 — bulgu kimliği | Yeni kayıtlar hedefin yolunu/sorgusunu, türünü, açıklamasını, girdisini ve çalışma bağlamını dikkate alarak işlem içinde tekilleştirilir. Eşzamanlı yazım aynı kaydı kullanır. Eski imzalar değiştirilmeden varsayılan port eşdeğerliği doğrulanır. Seçili tarihsel satırlar silinmeden önizlenebilir ve alias olarak eşlenebilir. |
| R08 — güncel kanıt | Tarihsel imza doğrulaması ile güncel scope/policy altında raporlanabilirlik ayrıldı. Memory, validator, hunter, rapor kapısı ve TUI güncel kanıtı denetler. SQLi kapısı hedef ve bulgu türünü de kanıta bağlar. |
| R10 — yükleme yan etkileri | Pytest izolasyonu toplamadan önce başlar. Memory ve validator modüllerinin import edilmesi/araç listelemesi veritabanı veya kasa oluşturmaz; ilk araç kullanımında başlatılır. Kasa geçişi ve import izolasyonu test edildi. |
| R11 — işçi sözleşmesi | Görevler scope dosyasını, kanıt araçlarını ve doğrulanmış araç adlarını içerir; eksik komut ve gerekçesiz istisnalar reddedilir. Hedef URL'nin yolu ve sorgusu görevde korunur. |
| R12 — ortak scope, kısmi | Tek kullanımlık ve kalıcı Playwright context'leri ile yüzey crawler'ında her HTTP isteği scope, grant ve metot kapısından geçer. Kalıcı/CDP context ve crawler tek origin ile sınırlıdır; service worker, WebSocket ve yazma metotları kapalıdır. Browser kapısı ve CDP izolasyonu gerçek HTTP/Chromium labında doğrulandı. Agent-browser ve canlı ZAP bu garantiyi sağlamadığından çalışmayı reddeder. |
| R13 — envanter | Profil yöneticisi gerçek sunucu envanterini kullanır ve özel MCP'leri korur. Bu ağaçta 16 sunucu, 289 araç vardır. |
| R14 — browser fallback | Playwright yoksa veya başarısızsa düz HTTP yolu mevcut test oturumunu, araştırmacı başlığını ve proxy ayarını kullanır. Her yönlendirme kapsam/politika kapısından geçer; 401, 429 ve login yönlendirmesi sonuç olarak işaretlenir. JavaScript çalıştırılmaz. |

Web/API varsayılan planı Hunter ile kapsam ve aday incelemesini içerir ve
kanıt kontrollü rapor aşamasına ulaşır. Oturumlu plan mevcut test kimliklerini
kullanır; hesap oluşturma ve veri değiştirme önermez. Hunter raporunda oturum,
hız limiti, politika, şema ve kimlik sorunları için ayrı yeniden planlama
önerileri bulunur; bu öneriler otomatik ağ isteği veya otomatik yeniden deneme
başlatmaz. Yerel MCP worker üzerinden çalışan eksik/engelli Hunter görevi
kampanyada `blocked` tutulur; gerekçesi ve kapıdan geçen istek denemesi sayısı
korunur. Bu sayaç gönderim denemesinin üst sınırıdır; bir taşıma hatasında
isteğin hedefe ulaştığını kanıtlamaz.

Yerel native MCP worker'da Hunter, HTTP validator, tek kullanımlık browser,
HTTP fallback ve temel curl yolu aynı görev hakkını kullanır; mevcut chain
manifestinin sınırı da rezervasyona bağlanır. 401, 429, policy iptali ve bütçe
tükenmesi çalışmayı durdurur. Çocuk süreç hatasında, süresi dolmuş lease'te
veya çalışan görev iptal edildiğinde güvenilir sayaç yoksa ayrılmış miktar
muhafazakâr biçimde harcanmış sayılır; görev `blocked` kalır. Sayaca bağlı
olmayan ağ araçları ve ağ erişimli custom executor native kampanyada
gönderimden önce reddedilir. Ayrıntılar
[ortak bütçe notundadır](shared-wire-budget-2026-10-31.md).

Kapsam raporunda `enqueue_gaps=True` artık sınıfın yanında URL, metot,
parametre, kimlik, sahip ve koşu boyutlarını içeren kalıcı planlar üretir.
Kapsam dışı adresler ve yazma metotları kuyruğa alınmaz; sorgu değerleri
kaydedilmez. Bu kayıtlar `needs_scheduling` durumundadır: kendiliklerinden
ağ isteği başlatmaz veya bütçe ayırmaz. Planlama sırasında güncel scope,
grant, istek bağlamı ve kampanya bütçesi tekrar denetlenmelidir.
Kampanya görevleri aynı idempotency anahtarıyla eşzamanlı eklendiğinde tek kayıt
oluşur; aynı anahtara farklı araç, argüman veya bütçe bağlama girişimi reddedilir.

**Son eklenenler:** `blind_discovery=True` ile sınırlı, çok hesaplı nesne
keşfi; açık sahiplik alanları ve özel test nesnesi politikası bulunan sentetik
uygulamalarda çalışır. Yeni merkezi oturum kayıtları Fernet kasasındadır;
doğrulanmış hesap referansları Hunter'a ve elle oluşturulan Hunter kampanya
görevlerine taşınabilir. 401/429/yönlendirme veya hesap/oturum değişimi güvenli
devamı durdurur. Bu mekanizma genel şema keşfi, otomatik login veya kapsam
boşluğundan otomatik görev üretimi değildir. Ayrıntılı kullanım ve kısıtlar
[Web/API notundadır](authenticated-web-api-2026-10-30.md).

OOB için hedef URL'si şifreli ve yerel olarak imzalı challenge, yapılandırılmış
kolektörün Ed25519 imzası, hedef/istek/parametre/koşu/scope/policy bağı ve
kalıcı replay kontrolü eklenmiştir. İmzalı callback hâlâ hedef kaynak atfı
sağlamaz ve sonuç
`INCONCLUSIVE` kalır. Gerçek kolektör entegrasyonu yapılmamıştır; olay şeması
ve sınırlar [OOB notundadır](oob-collector-provenance-2026-10-31.md).

MITM yakalamasının yeni kayıtlarında header değerleri varsayılan olarak
maskelenir, sorgu ve gövde değerleri kaydedilmez. Bu metadata yüzey envanterine
girer; eksik gövdelerden otomatik yürütülebilir iş akışı üretilmez.

Kalıcı browser araçlarında `browser_session_open(url=...)` başlangıç URL'si
zorunludur. `snapshot`, `click`, `fill`, `press`, `text`, `crawl` ve `requests`
çağrılarında `url` olarak aktif sayfanın güncel URL'si verilir; işlem ve scope
yeniden denetlenir. CDP yalnız yerel adrese bağlanır, kullanıcının açık
oturumlarını devralmaz. Eski Kali `browser_crawl` aynı korumalı crawler'ı
kullanır; eski DOM XSS ve otomatik login araçları korumaları tamamlanana kadar
istek göndermeden hata döndürür.

SSRF OOB adayı, açık scope içindeki callback hostuna en fazla bir GET denemesi
planlar ve başarısız gönderime challenge açmaz. Dışarıdan sağlanan callback
metni tek başına `CONFIRMED` üretemez; hedef ve sınıf challenge ile eşleşir,
sonuç doğrulanmış kaynak kanıtı yoksa `INCONCLUSIVE` kalır. Genel blind OOB
yürütmesi güvenilir kolektör ve taşıma entegrasyonu tamamlanana kadar kapalıdır.
Eski OOB artifact'larının imza bütünlüğü tarihsel olarak kontrol edilebilir;
doğrulanmamış callback kaynağıyla üretilen eski `CONFIRMED` sonuçları güncel
rapor ve kapsam kapılarından geçmez.

Yeni tekilleştirme kimliğinde `CCO_ENGAGEMENT_ID`, `CCO_WORKDIR`, etkin scope
dosyası ve scope revizyonu dikkate alınır. Ayrı programlar veya koşular için
açık bir engagement kimliği ve ayrı çalışma dizini kullanılması gerekir.
Etkin engagement belirtildiğinde memory, rapor ve TUI bulguları bu bağlama
göre süzer; bağlamı bilinmeyen eski bulgular gösterilmez. Credential, endpoint
ve graph tabloları henüz satır bazında engagement filtresi taşımaz. Programlar
arasında ayrı `CCO_HOME` gerekir. Başlatıcı ayrı state ve çalışma dizini sağlar:

```bash
python3 scripts/engagement_workspace.py --id PROGRAM_OR_RUN \
  --scope .codex/scope.lab.json --policy config/program-profiles/lab.json
python3 scripts/engagement_workspace.py --id PROGRAM_OR_RUN \
  --scope .codex/scope.lab.json --policy config/program-profiles/lab.json -- opencode
```

İlk komut yalnız dizin planını gösterir; ikincisi boş dizinleri gerekiyorsa
oluşturup komutu bu ortamda çalıştırır. Kurulu wheel'de `cco-engagement` da
kullanılabilir. İzolasyon yalnız bu başlatıcıyla veya eşdeğer ayrı ortam
değişkenleriyle başlatılan süreçlerde geçerlidir; geçmiş veri taşınmaz.
OpenCode başlatıldığında repo yapılandırmasındaki yerel MCP'lerin `CCO_HOME`,
`CCO_WORKDIR`, scope ve engagement değerleri işlem ortamında ayrı dizinlere
zorlanır; sabit `.cco` ayarı izolasyonu ezemez. OpenCode yapılandırma
çözümleyicisinde 16 yerel MCP için doğrulandı. Harici/uzak veya proje
yapılandırmasında bulunmayan özel sunucuların kendi depolaması ayrıca gözden
geçirilmelidir.
Eski kayıtların program/koşu bağı bulunmadığı için otomatik birleştirme
yapılmaz; `cco-finding-migration --help` ile önce önizleme yapılabilir. Araç
yalnız açık engagement, scope, workdir ve `--ids` ile seçilen kayıtları
`--apply` sırasında bağlar; URL şeması belirsiz satırları atlar. Değişiklik
kaynak satırları silmez. Gerçek veritabanına migration uygulanmadı.

## Açık kalanlar

1. **ZAP ve agent-browser ağ kapısı:** Mevcut browser gate ve CDP izolasyonu
   gerçek Chromium/HTTP ile sınandı; bağımsız kör benchmark ve diğer ağ
   adaptörlerinin fiziksel bütçe garantisi açık kalır. CDP mevcut sekme ve
   login'i devralmaz, yeni context açar. Agent-browser ve canlı ZAP kapalıdır; ZAP'ın
   daha önce toplanmış JSON `urls` ve `alerts` çıktısı `zap_map_surface`'in
   `snapshot_json` alanıyla yalnız aynı-origin, kapsam içi ve salt-okunur
   metadata olarak içeri alınabilir. Bu işlem tarama yapmaz ve alert'leri
   doğrulanmış bulgu saymaz. MITM kaydı bir wire gate değildir.
2. **Oturum yenileme ve yürütme kuyruğu:** Doğrulanmış şifreli test oturumları
   seçmeli kör Hunter yoluna hesap/origin bağıyla verilebilir; her istekte
   rotasyon ve geçerlilik kontrol edilir. Gözlenen uygun GET/sahiplik boyutları
   hedefli kampanya görevine bağlanır; saf oturum hatasıyla duran görev yeni
   imzalı kontrollerden sonra aynı kimlik ve kalan bütçeyle devam edebilir.
   Otomatik login, genel koşu devamı ve diğer taşıyıcıların görev köprüsü açık
   kalır. Ayrı `session-jar.json` otomatik şifrelenmedi. Ortak bütçenin
   desteklenen yolları yukarıdaki notta tanımlıdır.
3. **Tarihsel bulgu migration'ı:** Önizleme ve seçili ID'ler için alias aracı
   hazırdır. Gerçek eski kayıtların program/koşu bağı kullanıcı tarafından
   gözden geçirilmeli; şeması veya sahipliği belirsiz kayıtlar otomatik
   birleştirilmemelidir. Credential, endpoint ve graph izolasyonu yeni
   başlatıcıda ayrı veritabanıyla sağlanır; satır bazında paylaşımlı veritabanı
   izolasyonu henüz tamamlanmadı.
4. **İş mantığı ve uzman teknikler:** Gözlenen akıştan güvenilir kural ve
   oracle üretimi, sonuç-temelli yeniden kuyruklama, stored/DOM XSS, GraphQL
   alan yetkisi, OAuth/reset, upload ve kaynak doğrulamalı SSRF callback korelasyonu uçtan uca
   tamamlanmış değildir. Veri değiştiren senaryolar bu çalışmada çalıştırılmadı.
5. **Kör lab ve sandbox kabulü:** Yerel HTTP/Chromium labı onaylı sandbox dışı
   loopback yürütmeyle tamamlandı. Bağımsız lab, ayrı değerlendirici ve
   başlangıç URL'sinden rapora kadar kör ölçüm açık kalır. Bubblewrap/namespace
   izolasyonu ve tam test paketi bu browser kabulüyle doğrulanmış sayılmaz.
6. **Trafik verisi minimizasyonu:** Yeni MITM ve kalıcı browser kayıtları gövde
   ve sorgu değerlerini tutmaz. Form aracı input/token değerlerini döndürmez.
   URL yolundaki tanımlayıcılar, ekran görüntüleri ve daha önce oluşturulmuş
   kayıtlar ayrıca değerlendirilmelidir. Eski kayıtlar otomatik silinmez veya
   yeniden yazılmaz.

Çalışma ağacındaki kod değişikliklerinin etkili olması için ilgili MCP
sunucuları uygun zamanda yeniden başlatılmalıdır. Bu belge dağıtım yapmaz.

İzolasyon başlatıcısının son güncellemesinden hemen önceki geniş çevrimdışı
çalışmada **1.048 test geçti**, sekiz soket testi seçilmedi; soket ve namespace
gerektiren bazı dosyalar ayrıca dışarıda bırakıldı. Başlatıcının son değişikliği
hedefli testlerle ve OpenCode'un gerçek yapılandırma çözümleyicisiyle sınandı.
Ayrı surface/Hunter/policy grubunda **181 test geçti**, dört test seçilmedi;
wheel dış çalışma dizinine kurulup CLI ve 16 MCP sunucusu sınandı. Sentetik
worker soak 16/16 görevi tamamladı ve iki eski claim'i toparladı. Bu sonuçlar
gerçek HTTP labı veya tam test paketinin yerine geçmez.

Kör keşif ve şifreli oturum eklerinden sonraki geniş çevrimdışı çalışmada
**1.282 test geçti**, dört test atlandı ve 12 test seçilmedi; ayrıca soket veya
namespace gerektiren test dosyaları dışarıda bırakıldı. Son oturum sertleştirmesi
sonrasında ilgili grupta **175 test geçti**, kurulu wheel'deki şifreli oturum
kontrolü dahil. Gerçek HTTP/Chromium ve bağımsız kör lab sonucu değildir.
