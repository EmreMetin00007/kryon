# Oturumlu Web/API geliştirme dilimi — 30 Ekim 2026

Bu dilim, [pentest yetenek incelemesinin](pentest-capability-review-2026-10-29.md)
ilk paketi olan P01–P05 üzerinde çalışır. Canlı bir hedefe istek gönderilmedi.
Önceki ortamda cookie ve UUID kullanan iki hesaplı loopback lab'ı, güvenli ve
zafiyetli nesneleri de içeren 166 testlik grupla geçti. Daha sonra keşif kapısı,
kanıt kontrolü ve durdurma davranışı da değişti; mevcut ortam TCP soketi açmayı
engellediği için bu son sürümde gerçek HTTP lab'ı yeniden çalıştırılamadı.

## Yapılanlar

- Kapsama; hedef, koşu, URL, metot, sınıf, parametre/taşıyıcı, kimlik ve
  kaynak sahibi üzerinden tutulur. İmzalı validator kaydı ve eşleşen gözlenmiş
  istek olmadan bir hücre temiz veya doğrulanmış sayılmaz. Eski sınıf bayrakları
  ve genel dersler kapsama kanıtı değildir.
- Cookie fuzz aşamasına taşınır. JSON/form gövdesi, nested alanlar, tipler,
  diğer alanlar, metot ve header/cookie/path taşıyıcıları validator'a kısa
  ömürlü bir istek referansıyla iletilir. Bilinmeyen veya süresi dolan bağlam
  `INCONCLUSIVE`/`not_tested` kalır.
- Gözlenen GET nesneleri için BOLA/IDOR; ayrı roller belirtilen işlevler için
  BFLA adayları üretilir. İki ayrı test hesabı, açık sahiplik URL'si ve o
  nesnede görülen bir işaret gerekir. Oturumlar ve UUID'ler korunur; kaynak
  sahipliği hesap sırasından veya komşu kimlik tahmininden çıkarılmaz.
- Otomatik keşfin her HTTP isteği ve yönlendirmesi kapsam, grant, metot,
  zorunlu başlık ve hız kurallarından geçer. Oturum başka origin'e taşınmaz.
  Fuzz ve validator istekleri de son istek bağlamıyla aynı kontrollerden geçer.
  401, 429, login yönlendirmesi veya taşıma hatası sonraki otomatik yoklamaları
  durdurur. Hunter ve browser kapılarında, ayrıca validator egress'in login
  durdurma ve paylaşılan oturum kontrolünde kodlanmış login yönlendirmeleri de
  denetlenir. Tamamlanmamış hücreler kapsama yüzdesini artırmaz.
- Doğrulanmış sonucu rapora veya sonraki adıma almak için imzalı ve güncel
  scope/policy ile eşleşen artifact, geçerli taşıma ve ilgili rota/metot kanıtı
  gerekir. Sahipsiz eski authz adayları ağ çağrısı yapılmadan durur.
- Negatif kontrol bataryası yalnızca dolu ve tamamı `UNCONFIRMED` olan bir
  sonucu geçirir. `ERROR`, `INCONCLUSIVE`, `SKIPPED` ve yanlış pozitifler
  başarısızdır; bu, önceki incelemedeki R09'u kapatır.

## Kimlik ve nesne girdisi

`hunter_run_web_loop` aracındaki `identities` argümanı JSON metnidir. Aşağıdaki
örnek yalnızca alan biçimini gösterir; değerler test hesabından ve yetkili
kapsamdan sağlanmalıdır. Programın zorunlu başlıkları `headers` argümanında
verilir. Discover/fuzz için kullanılan `cookie`, geçici `request_fields`
değerlerinin eşleşeceği kimliğin Cookie başlığıyla aynı olmalıdır.

```json
{
  "alice": {
    "role": "admin",
    "headers": {"Cookie": "session=<ALICE_TEST_SESSION>"},
    "request_fields": {"json:csrf_token": "<ALICE_CSRF>"},
    "objects": [
      {"url": "https://lab.example/api/orders/<ALICE_UUID>", "marker": "<ALICE_TEST_MARKER>"}
    ]
  },
  "bob": {
    "role": "member",
    "headers": {"Cookie": "session=<BOB_TEST_SESSION>"},
    "objects": []
  }
}
```

Oturum ve CSRF değerleri, API çağrısında işletim ortamından sağlanmalı; gerçek
kimlik bilgileri örneğe, repoya veya rapora yazılmamalıdır. Araç istemcisinin
argümanları ayrıca kaydedip kaydetmediği işletim ortamında kontrol edilmelidir.
Maskelemiş bir alan ancak geçerli credential başlıkları tam olarak tek bir
kimlikle eşleşirse o kimliğin `request_fields` değerinden tamamlanır. Değer
eksikse tahmin edilmez. İstek referansları işlem belleğinde beş dakika yaşar;
sunucunun yeniden başlaması veya referansın sona ermesi tekrar yakalamayı
gerektirir. Bu akış CSRF değerini kendisi yenilemez ve login yapmaz.

## Çok hesaplı sınırlı kör keşif

`hunter_run_web_loop` artık açıkça etkinleştirildiğinde (`blind_discovery=True`)
iki ila sekiz sentetik hesapla başlangıç URL'sinden gözlenmiş bağlantıları
izleyebilir. Her hesabın `test_data_only: true` bildirmesi ve kendi credential
başlığının farklı olması gerekir. Keşif yalnız aynı origin ve kapsam içindeki
salt okunur GET bağlantılarını kullanır; kimlik veya nesne adresi tahmin etmez.
Oturum kaybı, 429 veya policy hatası sonrasındaki istekler durur.

Bu yol varsayılan olarak kapalıdır. Programın gerçekten izin verdiği sentetik
test hesapları için operatörün kullandığı program politikasında şu alanın yer
alması gerekir; dosya araç tarafından kendiliğinden değiştirilmez:

```json
"blind_discovery": {
  "synthetic_accounts_only": true,
  "owned_objects_private": true
}
```

İkinci alan yalnız test nesnelerine erişimin gerçekten sahibiyle sınırlı olması
gerektiği biliniyorsa açılır. Bu koşul ve hesap girdisindeki
`owned_objects_private: true` yoksa gözlenen sahiplik tek başına karşı hesapla
yetki testi üretmez. Güncel kapsam ve grant her istekte ayrıca gereklidir.

Mevcut keşif, yanıtın açık `current_user`/`viewer` benzeri kimlik alanı ve
nesnenin `owner_id` ya da `owner` alanı eşleştiğinde sahipliği ilişkilendirir;
nesne kimliği hem gözlenen URL'de hem nesne yanıtında yer almalıdır. Bunlar
olmayan uygulama biçimleri veya sadece düz ID veren listeler henüz otomatik
bağlanmaz. URL'den GET çağrısı yapmak her uygulamada yan etkisiz olacağının
garantisi değildir; operatör kapsam ve program kurallarını buna göre seçmelidir.

Keşif varsayılan olarak en çok 24, yapılandırmayla en çok 40 istek kullanır;
hesap başına ayrıca en çok 12 istek, derinlik ve yanıt boyutu sınırı vardır.
`identity_discovery` özetinde yalnız sayılar ve eksiklik nedenleri bulunur;
`ready` tüm uygulama kapsamının tamamlandığı anlamına gelmez. Bu yol sentetik
taşıyıcıyla doğrulandı; gerçek HTTP veya bağımsız kör lab sonucu değildir.

## Şifreli oturum ve devam referansları

Yeni `validator_session_vault_put` kayıtlarının cookie/header, kontrol URL'si ve
marker değerleri mevcut Fernet credential kasasında tutulur; `session_vault.json`
yalnız hesap/hedef metadata'sı ve referans taşır. Kasa anahtarı varsayılan
olarak aynı çalışma home dizininde 0600 izinli dosyadadır; ortam anahtarı ve
işletim sistemi erişim sınırı ayrıca korunmalıdır. Eski `session_vault.json`
kayıtları silinmez; ilgili kayıt kontrol edildiğinde veya değiştirildiğinde
kademeli olarak taşınır. Ayrı `session-jar.json` ve diğer geçmiş saklama
yolları bu değişiklikle otomatik şifrelenmez.
Anahtar kayıpsa eski oturum okunamaz ve okuma işlemi yeni anahtar üretmez.

Operatörün sağladığı yeni test oturumu için `validator_session_vault_check`,
aynı origin'deki açık kontrol URL'sine yalnız bir GET gönderir. Beklenen,
hesaba özgü sentetik marker ve HTTP 200 birlikte gerekir; 401, 429, yönlendirme,
farklı origin, eksik marker ve erişim/policy hatası geçerli sayılmaz. İsteğin
son URL'si, gerekli header'ları, kapsamı ve grant'i tekrar kontrol edilir.
Yönlendirme takip edilmez. Doğrulama sonucunun hesap, origin ve şifreli kayıtla
bağı imzalıdır ve Hunter'a bağlanırken en fazla beş dakika yaşında olmalıdır.
Yeni kontroller nonce ve imzalı hassas zaman bilgisiyle birbirinden ayrılır;
eski imzalı kontrol sürümleri okunabilir. Bu kontrol login yapmaz veya yenileme
isteği göndermez. Uygun hedefli kampanya görevini sonraki worker sorgusu devam ettirebilir.

Kör keşifte ham `identities` yerine `session_bindings` JSON metni kullanılabilir:

```json
{
  "alice": {"target": "https://lab.example", "role": "member",
            "test_data_only": true, "owned_objects_private": true},
  "bob": {"target": "https://lab.example", "role": "member",
          "test_data_only": true, "owned_objects_private": true}
}
```

Her etiket önceden kaydedilip kontrol edilmiş aynı isimli hesapla, `target` ise
tam kayıt anahtarı ve koşu origin'iyle eşleşmelidir. `session_bindings` yalnız
`blind_discovery=True` veya hedefli `gap_ref` ile çalışır; ham `cookie`, credential header veya
`identities` ile karıştırılmaz. Her gönderimden önce oturumun değişmediği,
doğrulamasının geçerliliği ve mevcut wire kapısı denetlenir. Yenilenmiş veya
süresi dolmuş kayıt koşuyu durdurur. Hedefli `gap_ref` kampanya görevi yalnız
saf oturum hatasıyla engellendiyse, tüm bağlı hesaplar engellemeden sonra
yeniden doğrulandığında aynı görevle devam eder. İlk deneme sınırı ve
tüketilmiş bütçe korunur; 429, karışık hata veya bilinmeyen harcama devam izni
vermez. Ayrıntılar ve `resume-gaps` arayüzü
[kampanya köprüsü notundadır](coverage-campaign-bridge-2026-10-31.md).

Kampanya kuyruğundaki Hunter görevleri ham `cookie`, `identities`, credential
header'ları ve sorgulu hedefleri artık kaydetmez; desteklenen güvenli yol hesap
referanslarıdır. Görev argümanları ve diğer araçlar için genel bir sır tespit
garantisi yoktur. MCP istemcisinin `session_vault_put` argümanlarını loglayıp
loglamadığı ayrıca kontrol edilmeli; örnek alanlara gerçek sır yazılmamalıdır.

Çalışma `run_id` döndürür. `hunter_coverage_report(target)` hedef için son
imzalı olayın koşusunu gösterir; belirli koşu için
`hunter_coverage_report_run(target, run_id)` kullanılabilir. Hiç imzalı olayı
olmayan bir koşu bu sorguda bulunmayabilir. Yüzde, mevcut envanterde bilinen
parametreler ve planlanan kimlik/sahiplik hücreleri içindir; keşfedilmemiş
uçların veya hiç planlanmamış kimliklerin test edildiğini göstermez. Eski bir
koşu seçildiğinde bile endpoint envanteri güncel envanterdir, tarihsel anlık
görüntü değildir.

## Kontroller

Oturum kontrolündeki son küçük sertleştirmeden önce geniş çevrimdışı grupta
**1.282 test geçti**, dört test atlandı ve soket/namespace gerektiren 12 test
seçilmedi; ayrıca aynı sistem gereksinimlerini taşıyan test dosyaları dışarıda
bırakıldı. Yeni keşif, kasa, politika ve kampanya bağlantıları sentetik
taşıyıcılarla ayrıca sınandı. Son sertleştirmeden sonra ilgili grupta **175 test
geçti**; kurulu wheel üzerinde şifreli oturum kontrolü de buna dahildir. Son
sürümün gerçek HTTP lab'ı ve tam test paketi,
TCP soketi ve namespace açılabilen bir ortamda yeniden çalıştırılmalıdır.
Ruff'ın `E9,F63,F7,F82` kontrolleri, repo düzeni kontrolü ve `git diff --check`
geçti; tool envanteri 16 sunucu / 289 araçtır.

StateOps'a geliştirme olayı kaydedildi. Raporun ayrıca StateOps kanıtı olarak
eklenmesi, aracın onay gerektirmesi ve bu oturumun onay politikasının `never`
olması nedeniyle reddedildi; raporun çalışma alanındaki yolu olayda kayıtlıdır.

## Sınırlar ve sonraki işler

- Hunter'daki Playwright crawl artık ortak scope/grant/bütçe kapısını kullanır;
  sahte tarayıcı testleri geçmiştir, gerçek Chromium/HTTP doğrulaması bekler.
  Canlı ZAP ve eski gelişmiş yüzey kancaları açıkça atlanır. Ayrı araçların
  kendi kapsam ve grant kontrolleri gerekir.
- POST gövdelerinin korunması, bir POST işleminin zararsız olduğunu kanıtlamaz.
  Yalnızca veri değiştirmediği bilinen, program kurallarının izin verdiği test
  yüzeylerinde çalışılmalıdır.
- Test noktalarının kabul edildiği veya CSRF/oturumun tazelendiği bir uçtan uca
  canlı ürün deneyi yapılmadı. Otomatik oturum yenileme, browser trafiğinin
  politika kapısına bağlanması ve yeniden planlama devam ediyor.
- Tekrarlanan gerçek istekler mevcut tekrar freni tarafından sayılır; uzun bir
  validator serisi de bu korumaya takılabilir. Sonuç bu durumda tamamlanmış
  sayılmaz ve ilgili test için yeni planlama gerekir.
- P05'te hunter akışı UUID/opaque nesneleri korur; önceki R05'in `brain.py`
  havuz → deneme → kapsam zinciri genelinde kapandığı anlamına gelmez.
- İş mantığı, teknik başına uzmanlık ve kör lab paketi, incelemenin sonraki
  öncelikleridir. R10 ve diğer açık proje incelemesi maddeleri ayrıca sürer.

MCP sunucuları mevcutsa değişiklikleri yüklemek için uygun zamanda yeniden
başlatılmalıdır; bu belge dağıtım veya canlı hedef çalıştırma yapmaz.
