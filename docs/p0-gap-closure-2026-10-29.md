# P0 kapatma — ilk dilim, 29 Ekim 2026

Bu dilim [proje incelemesindeki](project-review-2026-10-29.md) R01 ve R02'yi
kapsar. İlk dilim tamamlandığında diğer 12 madde açıktı; R03/R04 daha sonra
[ikinci dilimde](ledger-integrity-2026-10-29.md) kapatıldı. Aşağıdaki test
sonuçları ilk dilimin kaydıdır. Mevcut commit edilmemiş değişiklikler
korunmuştur; canlı hedeflerde işlem yapılmamıştır.

## R01: son HTTP gönderiminde politika ve bütçe

[ChainTransport](../scripts/chain_transport.py) bütün chain HTTP yollarının
ortak çıkışıdır. Final URL/metot/başlıklar, oturum token ve cookie'leri
eklendikten sonra politika motoruna verilir. Eksik araştırmacı başlığı,
engellenen metot, kapsam dışı hedef veya süresi dolan grant gönderimden önce
reddedilir. Manifest dispatch kontrolü, gerçek HTTP gönderimi kontrolünden
ayrılmıştır; her adım doğru başlıklarını taşıyabilir.

İlk istek, login, retry, şema düzeltmesi, mailbox, batch ve burst aynı
sayaçtan geçer. Toplam, adım ve rota bütçeleri gönderimden önce ayrılır;
paralel rezervasyonlar kilit altında yapılır, ağ işlemi kilidin dışında
kalır. Kısmi başarısızlık gerçek maliyeti gizlemez. `goto` ile adımı yeniden
ziyaret etmek bütçeyi sıfırlamaz. Varsayılan HTTP göndericisi otomatik
yönlendirme takip etmez.

Login'in zorunlu araştırmacı başlıkları `login_recipe.headers` içinde
tanımlanır. Başlık kontrolü ad ve değeri birlikte denetler; adlarda
büyük/küçük harf farkı kabul edilir.

## R02: kanıtla doğrulanan confirmed ve closure/2

[Beyin](../scripts/brain.py) özet işleme ve CLI işaretleme yollarında aynı
validator doğrulayıcısını kullanır. `validator_verified=true` beyanı yetki
vermez. Kalıcı dosya, imza, hedef, kodda tanımlı vektör/tür eşleşmesi ve
aktif scope/policy bağı kontrol edilir. İlgili alt türler açık bir listede
tanımlıdır; bulgu metni bu listeyi genişletemez.
Yalnızca saklama/yansımayı doğrulayan genel `Second-Order (Stored)` kanıtı,
tek başına XSS confirmed durumu vermez.

Doğrulanan `validation_id` ve `validation_sha256` hipotez kaydına yazılır.
Check, mühürleme ve verify aşamaları bunları yeniden denetler. `closure/2`,
hedef ve koşu diziniyle birlikte hipotez defterinin tamamının hash'ine ve
yalnızca ilgili kanıtlara bağlanır. Değişen defter, silinen/değişen kanıt,
bozuk imzalı deneme zinciri veya değişen scope/policy bağı doğrulamayı
başarısız yapar.

Bu dilim güncel scope/policy bağını beyin/kapanış yolunda denetler.
R08'deki diğer rapor ve memory tüketicilerinin tamamının birleştirilmesi
ayrı iş olarak kalır. MCP/sandbox anahtar custody sorunu R04 kapsamındadır
ve ikinci dilimde açık anahtarla doğrulama protokolüyle kapatılmıştır.

## Doğrulama ve yeniden üretim

[Regresyon testleri](../tests/test_p0_security_contracts.py) gerçek politika
motorunu, geçici depoları, gerçek imzalı test artifact'lerini ve sahte HTTP
göndericilerini kullanır. Önceki davranışta ilk 25 testin 24'ü başarısızdı.
Dispatch ayrımı ve geçerli alt türler için ek kırmızı testler de düzeltme
öncesinde yeniden üretildi.

Eski olumlu kapanış örnekleri yalnızca bir metin/boolean ile doğrulanmış
gibi davranıyordu; şimdi gerçek, kalıcı ve imzalı test kanıtı üretirler.
Koruma kontrolleri mock bir `True` sonucuyla devre dışı bırakılmamıştır.

Bu dilimin test çıktıları `/tmp/cco-p0-fix-20261029/` altındadır:

| Son kontrol | Sonuç |
|---|---|
| Son kaynak sürümü, tam pytest | **1.098 geçti; 0 hata, 0 başarısız, 0 atlanan** |
| Yeni güvenlik sınırı regresyonları | **44 geçti** |
| Gömülü loopback lab | **48/48** |
| Negatif kontrol | **6/6 UNCONFIRMED**, yanlış pozitif yok |
| Sentetik worker kontrolü | **16/16**, 2 eski claim kurtarıldı |
| Ruff / JS sözdizimi / kilit dosyası / repo düzeni | Geçti |
| CI mypy kontrolü | 2 kaynak dosyada hata yok |
| OpenCode debug config | Geçti; 16 MCP sunucusu yapılandırılmış |

Mypy kontrolü HEAD'de de bulunan iki eski tip tanımı hatasını gösterdi:
değişken uzunluktaki kök dizin tuple'ı ve listelerle birlikte metin içeren
invocation sonucu. Bunlar doğru tuple tanımı ve `InvocationData` şemasıyla
düzeltildi. Mypy yalnızca `/tmp` altına kuruldu; proje bağımlılıkları
değişmedi. Bu tip düzeltmelerinden sonra da tam test paketi yeniden geçti.

Governance kontrolü 0 high / 31 medium ile geçti; önceki incelemedeki medium
kayıtların ayrıca değerlendirilmesi gerekir. OpenCode config kontrolü model
sağlayıcısına gerçek istek veya canlı hedef kampanyası doğrulaması değildir.

- `red.xml`, `red.log`: ilk regresyonların düzeltme öncesi sonucu.
- `contract-verified.xml`: kanıt ve tür eşleşmesi kontrolleri.
- `release-verified.xml`: son kaynak sürümünün tam test paketi.
- `quality-results.json`: lab, statik denetim ve diğer kalite kontrolleri.
- `lab-final.log`, `negative-final.log`: gömülü loopback lab sonuçları.
- `soak.json`: 16 görev / 4 worker / 2 eski claim için sentetik kontrol.

## Eski koşuların geçişi

`closure/1` otomatik olarak güvenilir sayılmaz. Mevcut confirmed kaydını
geçerli bir validator kimliğiyle yeniden işaretleyin; ardından kapanışı
yeniden üretin. Eksik kanıtlar otomatik olarak tamamlanmış sayılmaz.

Komutlar ve yeni login başlığı davranışı
[operasyon belgesinde](operations.md) açıklanmıştır.
