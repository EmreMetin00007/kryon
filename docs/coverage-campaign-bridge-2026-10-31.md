# Kapsam boşluğundan hedefli kampanya görevine — 31 Ekim 2026

Mevcut Hunter ve kampanya worker'ı genişletildi. `coverage_report`, açıkça
seçilen kampanyada uygun kapsam boşluklarını yürütülebilir görevlere bağlar.
Yeni MCP aracı veya ikinci bir orkestrasyon sistemi eklenmedi.

## Davranış

- Hunter doğrulama kuyruğu hazırlanırken endpoint, metot, sınıf, parametre,
  taşıyıcı, test kimliği, sahip ve kaynak koşu boyutları kaydedilir. Uygun
  isteğin ayrıntıları mevcut Fernet kasasında şifreli saklanır; kampanya
  görevi cookie/token ve sorgulu hedef yerine referansları içerir. Önceki oturumun credential header'ları yürütme
  bağlamına taşınmaz; güncel doğrulanmış oturumdan çözülür.
- `enqueue_gaps=True` ile planlama ve pozitif `campaign_id` ile kampanyaya
  kabul ayrıca seçilir. Kabul sırasında güncel scope/policy, grant, istek
  şeması, doğrulanmış test oturumu ve kalan istek bütçesi kontrol edilir.
  Planlama HTTP isteği göndermez ve yürütme bütçesini ayırmaz.
- Her boyutun sabit idempotency anahtarı vardır. Eşzamanlı planlama ve görev
  ekleme tek görev üretir; aynı kaynak boyutu başka kampanyaya bağlanamaz.
  İkinci kez kuyruğa alma yerine mevcut görev korunur.
- Görev, `hunter_run_web_loop(gap_ref=...)` üzerinden yalnız seçilen
  doğrulayıcıyı çalıştırır. Genel keşif, crawl, fuzz ve exploit adımları
  yeniden çalıştırılmaz. Doğrulayıcının baseline ve negatif kontrolleri aynı
  ayrılmış istek bütçesine dahildir; IDOR anonim kontrolü de yapabilir.
- Kaynak `run_id` korunur; sonuç başka koşuya veya başka parametre/kimliğe
  yazılmaz. Yalnız eşleşen güncel imzalı validator artifact'ı ve gözlenen
  başarılı taşıma `tested_clean` / `confirmed` kapsamını tamamlar.
- 401, 429, login yönlendirmesi, oturum rotasyonu, yetki iptali ve bütçe
  bitişi mevcut wire kapısıyla durdurulur. Kanıtsız/kısmi sonuç worker'da
  `blocked` kalır. Yeni görevler varsayılan üç, seçime göre bir ila üç
  denemelidir. Başlangıçtaki sınır sabittir; eski tek denemeli görevler yükseltilmez.
  `queued_dimensions` hem plan durumunu hem bağlı `task_status` değerini
  gösterir; `scheduled` tamamlanmış test anlamına gelmez.

## Arayüz

MCP `hunter_coverage_report` mevcut alanlara ek olarak `campaign_id`,
`session_bindings`, `headers`, `request_cost` ve `max_attempts=3` alır. Sonuçtaki
`campaign_tasks.scheduled` görev kimliklerini, `deferred` ise eksik
önkoşulları gösterir. Varsayılan `campaign_id=0` kampanya görevi oluşturmaz.

Örnek, yetkili ve önceden kurulmuş sentetik bir kampanya içindir:

```python
coverage_report(
    target="https://owned.test/allowed/",
    enqueue_gaps=True,
    campaign_id=17,
    headers='{"X-Research":"researcher"}',
    session_bindings='{"alice":{"target":"https://owned.test/allowed/","role":"member","test_data_only":true,"owned_objects_private":true},"bob":{"target":"https://owned.test/allowed/","role":"member","test_data_only":true,"owned_objects_private":true}}',
    request_cost=12,
)
```

Önceden kaydedilmiş planlar için yerel CLI da kullanılabilir:

```bash
cco-campaign schedule-gaps 17 https://owned.test/allowed/ --request-cost 12
```

CLI aynı `--headers`, `--session-bindings`, `--max-attempts` (1–3), `--limit` ve kaynak koşuyu seçen
`--run-id` seçeneklerini alır. MCP raporundan planlama yalnız raporun seçtiği
kaynak koşunun boşluklarını alır.
`session_bindings` yalnız hesap referanslarıdır; cookie/token içeremez.
Anonim bir boyut oturum istemez; oturumlu tek boyut bir, BOLA/IDOR/BFLA
boyutu farklı iki doğrulanmış hesap ister.

## Oturum nedeniyle engellenen göreve devam

Yalnız saf oturum hatasıyla duran hedefli görev devam edebilir; eşlik eden
`unavailable` sınıfına izin verilir. 429, policy, şema, bağlantı veya bütçe
hatasıyla birleşmiş sonuçlar engelli kalır. Göreve bağlı her hesap için
engellemeden **sonra** başarılı ve güncel bir kontrol gerekir. Aynı saniyede
iki kontrol rastgele nonce ile ayrılır; imzalı nanosaniye zaman bilgisi eski
geçerli kontrolün geri yüklenerek devam izni sayılmasını engeller. Eski
attestation sürümleri okunabilir; devam için yeni kontrol yapılmalıdır.

Worker'ın sonraki kuyruk kontrolü uygun görevi otomatik olarak yeniden kabul
eder. Yalnız önkoşulları yeniden değerlendirmek için CLI kullanılabilir:

```bash
cco-campaign resume-gaps 17 https://owned.test/allowed/ --run-id source-run
```

Bu işlem HTTP isteği göndermez; yeni görev veya oturum üretmez. Oturumu
kontrol eden araç login/refresh işlemi yapmaz. Devamda görev kimliği, sabit
anahtar, argümanlar, kaynak koşu, deneme sayısı ve başlangıçtaki deneme sınırı
korunur. Önceki denemede tüketilen istekler kalan görev bütçesinden düşülür:
örneğin başlangıçta 4 istek ayrılan görev 1 istek sonrası durduysa devamda
en fazla 3 istek ayırabilir. Harcaması bilinmeyen veya tüm hakkı tüketilmiş
görev devam edemez. Eski worker permit'i yeni denemeyi kontrol edemez.
Genel `fail_task` / `fail_task_with_permit` yolu da canlı Hunter görevini
yeniden kuyruğa almaz; bilinmeyen harcamayı ayrılmış bütçeden düşürüp engeller.

Bloke olma ve deneme kayıtları HMAC ile görev/argüman/sonuç/checkpoint ve
oturum sürümlerine bağlanır. Kabul sırasında snapshot, scope/policy, grant,
hesap/rol, bağımlılık ve kampanya bütçesi yeniden denetlenir; kabul sırasında
oturum değişirse görev engelli kalır. Her sorguda en fazla 100 engelli görev
incelenir; kalıcı tarama imleci önceki hesapları bekleyen görevlerin sonraki
görevleri sürekli dışarıda bırakmasını önler.

## Sınırlar ve kalanlar

İlk sürüm gözlenen GET query/path adaylarını ve açık sahiplikli GET
BOLA/IDOR/BFLA boyutlarını destekler. Gövde taşıyan istekler, cookie/header
parametre mutasyonu, OOB, opaque token ve deserialization yeniden planlaması
bu köprüden çalıştırılmaz. Şeması eksik aday adresi veya payload uydurulmaz.

Şifreli istek kaydı bir saat geçerlidir; oturum attestation'ı mevcut beş
dakikalık sınırını korur. Eski scope/policy veya süresi dolmuş snapshot
yeniden kullanılamaz. Yeni gözlem yeni kaynak koşusuyla kaydedilmelidir.
Otomatik oturum yenileme ve genel Hunter koşusunun kaldığı aşamadan devamı
açık iştir. Diğer MCP araçları için ortak bütçe ve gerçek Chromium/HTTP/VDS
doğrulaması da devam eder.

## Doğrulama

Son kodla Hunter, kampanya, worker, oturum, API, orkestrasyon, MCP ve kurulu
wheel grubunda 436 test geçti. Chromium bulunmadığından dört browser testi
atlandı; TCP gerektiren bir loopback HTTP testi bu turda seçilmedi. Önceki
köprü adımında bu loopback testi kendi geçici scope ve grant'iyle geçmişti.

Sentetik 401 → yeni imzalı kontrol → aynı görevde kanıtlı tamamlanma;
eski kontrolün geri yüklenmesi, tüm hesapların yeniden kontrol şartı,
karışık hatalar, sabit deneme sınırı, birikimli istek hakkı, değiştirilmiş
receipt/argüman/sonuç/checkpoint, grant/scope/policy değişimi, eşzamanlı
claim ve eski permit'in reddi sınandı. Kurulu wheel'de de şifreli snapshot
ve aynı görevin kalan bütçeyle devamı doğrulandı. Ruff, diff ve repo düzeni
kontrolleri temiz.

Kodun yüklenmesi için ilgili MCP sunucusu güncel sürümle yeniden başlatılır.
Gerçek hedefe, VDS'ye veya callback kolektörüne trafik gönderilmedi; yeni
köprünün hedefli doğrulama senaryoları sentetik taşıyıcılarla sınandı.
