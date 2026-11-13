# XSS/traversal kayıpları ve eşlenmeyen doğrulamalar

Tarih: 2026-11-04. Durum: inceleme tamamlandı. Kaynak,
[37/37 gerçek HTTP/Chromium kabulü](http-chromium-acceptance-2026-11-04.md).
Bu dilimde yeni wire isteği gönderilmedi. İlk kabulün **6/8 pozitif, 8/8
negatif, eşlenen vakalarda sıfır FP** sonucu korunur.

## XSS: yansıma var, çalıştırma kanıtı yok

Beş seed'de `/search?q=laptop` keşfedilmiş, XSS adayı kuyruğa alınmış ve
validator çağrılmış. İmzalı sonuç `INCONCLUSIVE`: `reflection.verdict=CONFIRMED`,
`reflected_raw=true`, `primitive_confirmed=unescaped_html_reflection`, ancak
`execution.observed=false`. Dolayısıyla kayıp `validation_inconclusive`.

Başlangıç sayfasını Chromium ile açmak, sonradan gönderilen XSS payload'ının
çalıştığını kanıtlamaz. `validate_xss_reflection` yalnız yansıma kontrolü yapar;
campaign bu aday için bir tarayıcı çalıştırma doğrulaması yürütmüyor. Seed
20261104'te ilgili artifact kimliği `7996d9618c59f5550dbdbe5ad5e71cfd`;
campaign görev 5, boyut inconclusive kaldığı için `blocked` ve otomatik retry
kapalı. Bu kayıt bütçe taşması veya keşif kaybı değildir.

## Traversal: tarihsel seçim kaybı ve mevcut fixture sınırı

Kayıtlı kabulün ham fuzz ve sunucu kayıtlarında `/file` için gönderilen payload
`../../../../etc/passwd`, yanıt **404**. Benign `notes.txt` baseline'ı başarılı;
light oracle sinyal üretmiyor. Aday seçimi açık 404 sonucunu uygun kabul
etmediğinden validator çağrılmamış: `probe_no_candidate`. `/safe/file` aynı
payload'a **400** verdiği için bounded sampling üzerinden doğrulanmış.

Mevcut worktree'de `bind_file_probes`, policy'de ilan edilen `../secret.txt`
payload'ını kullanıyor. Değişiklik öncesi bu oturumda yapılan seed 20261104
offline yeniden üretimi, traversal'ın artık candidate → queued → invoked
aşamalarını geçtiğini gösterdi. Sonuç yine `INCONCLUSIVE`; validator'ın
gerekçesi **“Direct-name control cannot establish a directory boundary.”**

Bu ikinci kayıp fixture davranışından kaynaklanıyor. `/file` handler'ı
`name.endswith("secret.txt")` için aynı içeriği döndürüyor. Yerel handler
modelinde kontroller şöyle:

| Kontrol | Değer | HTTP | İlan edilen marker |
| --- | --- | --- | --- |
| Baseline | `notes.txt` | 200 | Yok |
| Doğrudan ad | `secret.txt` | 200 | Var |
| Eksik dosya | `../cco-missing-local-model.txt` | 404 | Yok |
| Traversal | `../secret.txt` | 200 | Var |
| Tekrar | `../secret.txt` | 200 | Var |

Marker doğrudan adla da erişilebilir olduğu için bu kontroller dizin sınırı
ihlali göstermez. Validator'ın temkinli sonucu doğrudur; mevcut fixture'ın
traversal-positive etiketi, application-file oracle'ının sınır sözleşmesiyle
uyumlu değildir. Yerel model isteği ve offline ölçüm, tarihsel wire sayısına
katılmaz.

Offline baseline artifact'i:
`/tmp/cco-work/loss-analysis-baseline-20261104/test_observed_controls_resume_0/automatic-campaign-controls.json`.
**251 in-memory istek**, hazırlık 7, keşif 99, campaign 145, 28 görev;
6/8 pozitif, 8/8 temiz negatif, iki pozitif için `validation_inconclusive`.
Bu sonuç yeni HTTP/Chromium kabulü değildir.

## Dört eşlenmeyen kayıt: ek hesap matrisi

İlk truth listesi bir BOLA nesnesi ve bir BFLA aktörü seçiyor. Campaign iki
üye ve bir admin test hesabıyla daha fazla karşılaştırma yapıyor. Strict
actor/owner eşlemesi bu ek sonuçları ilk 16 vakanın dışında bırakıyor.

Her seed için dört kayıt şu boyutlarda:

| Sınıf/kaynak | Kaynak sahibi | Test aktörü | İnceleme sonucu |
| --- | --- | --- | --- |
| BOLA, member-a'nın vulnerable siparişi | member-a | admin-a | Ek özel nesne ihlali |
| BOLA, member-b'nin vulnerable siparişi | member-b | member-a | Ek özel nesne ihlali |
| BOLA, aynı member-b siparişi | member-b | admin-a | Ek özel nesne ihlali |
| BFLA, `/admin/export` | admin-a | member-b | Ek rol ihlali |

Admin hesabına ilişkin beklenti genel bir varsayım değildir: bu koşunun
`owned_objects_private=true` beyanı, owner dışındaki bütün test hesapları için
özel nesne sınırı tanımlar. Fonksiyon beyanı da `member` rolünü reddeder; her
iki üye aynı role sahiptir. İmzalı request evidence'da farklı kimlikler ve
protected/owner marker kontrolleri bulunur. Sonuçlar yalnız bu sentetik lab
ve ilan edilen erişim sözleşmesi için değerlendirilir.

Bu sözleşmeden operatör tarafında ayrı bir ek truth matrisi üretildi. Solver'a
ek vaka veya cevap anahtarı verilmedi; ilk 8+8 vaka genişletilmedi.

| Seed | Doğrulanan imzalı kayıt | Ek pozitif | Ek temiz negatif | Ek matriste FP | Birleşik eşlemede açıklanamayan |
| --- | --- | --- | --- | --- | --- |
| 20261104 | 27 | 4/4 | 4/4 | 0 | 0 |
| 20261105 | 27 | 4/4 | 4/4 | 0 | 0 |
| 20261106 | 27 | 4/4 | 4/4 | 0 | 0 |
| 20261107 | 27 | 4/4 | 4/4 | 0 | 0 |
| 20261108 | 27 | 4/4 | 4/4 | 0 | 0 |

İlk skorun `unmapped_confirmed=4` sayısı hâlâ doğrudur; ek matris bu dört
kaydın her birini açıklar. Bu sonuç XSS/traversal kayıplarını kapatmaz veya
ilk pozitif recall'ı yükseltmez.

## Kod ve kanıt yolu

- `scripts/blind-validate.py`, `blind-score/4` çıktısına
  `unmapped_confirmations` ekler: tam request boyutları, ilişkili vakalar,
  eşleşmeyen boyutlar ve deduplicate edilmiş validation ID'leri. Query değerleri
  bu listede tutulmaz; vaka eşleme kuralları korunur.
- Hunter loop fanout'u artık `status` ve `baseline_eligible` alanlarını
  saklar. Böylece 404 seçim kaybı ham fuzz dosyasını açmadan görülebilir.
- `scripts/http_chromium_loss_analysis.py`, kayıtlı JUnit/manifest ölçümlerini
  yeniden karşılaştırır; SQLite'ı read-only açar ve yalnız public trust ile
  coverage/artifact imzalarını doğrular. Artifact yolu, hash, scope/policy,
  request boyutları, verdict ve başarılı request evidence bağını denetler.
  Secret vault veya signing key okumaz. Eksik/bozuk kanıt analizi durdurur.

Ana çıktı:
`/tmp/cco-work/http-chromium-loss-analysis/analysis-7gyx07ex/analysis.json`.
SHA-256: `4c7aad3b96e68975969dbc03ff01ca7635d982dc25b0be3e7b4dc176f56afc1d`.
Dosya beş seed'in vaka analizi, validator referansları, model kontrolleri,
ham probe durumları ve okunan kanıt dosyalarının hash'lerini içerir.
Kullanılan analyzer/scorer/lab kodunun hash'leri de kaydedilmiştir.

Kaynak kabul manifestinin SHA-256 değeri aynı kaldı:
`d0517f88eec7d8edac95fee1d72c0fdae239c43646f6e06be0887032867a7ac3`.

Yeniden üretim:

```bash
python3 scripts/http_chromium_loss_analysis.py \
  /tmp/cco-work/http-chromium-acceptance/run-xmpidxvp \
  --output-dir /tmp/cco-work/http-chromium-loss-analysis
```

## Regresyon ve sonraki uygulama dilimi

Bu dilimde **219 farklı offline test geçti**. İlk geniş pakette 161/163 geçti;
iki eski entegrasyon assertion'ı, 404 traversal sondasını aday bekliyordu.
Bu assertion'lar mevcut failed-status sözleşmesini ve `probe_no_candidate`
kaybını açıkça denetleyecek şekilde düzeltildi. Son campaign/analiz paketi
**75/75**, offline scorer/analiz paketi **56/56** geçti; önceki sonuçlarla
test kimliği bazında birleştirilerek 219/219 hesaplandı.

Ayrı socket testi `PermissionError: Operation not permitted` ile çalışamadı.
Bu hata korunur; offline tekrarında socket testi deselect edildi. Önceki
37/37 gerçek kabulün yerine yeni gerçek kabul iddiası yapılmaz. Derleme,
`git diff --check`, repo veri sınırı kontrolü ve graphify güncellemesi geçti.
Sağlık kontrolü 7/7 geçti.

Sonraki dar uygulama işleri:

1. XSS yansıma adayından scope/bütçe/oturum bağlı browser execution
   doğrulamasına geçiş; yalnız marker ile korele gerçek execution artifact'i
   olduğunda confirmed sonucu.
2. Ayrı sürümlenmiş fixture'da doğrudan basename'i reddeden gerçek dizin
   sınırı; benign/direct/missing/traversal/repeat kontrolleriyle pozitif ve
   negatif doğrulama. Tarihsel `blind-lab/2` artifact'leri korunmalı.
3. Bu iki değişiklikten sonra beş seed gerçek HTTP/Chromium kabulünü yeniden
   ölçmek. Tam LLM ajan ve holdout kilometre taşları açık kalır.

## Uygulama dilimi: XSS execution ve dizin sınırı

İlk iki uygulama işi offline doğrulandı. Yukarıdaki tarihsel kabul sonuçları
ve `blind-lab/2` artifact'leri değiştirilmedi.

`validate_xss_reflection`, başarılı ham HTML yansımasını policy izin verdiğinde
Chromium oracle'ına bağlar. Her tur ayrı, geçici bir browser context kullanır;
adayın header/cookie kimliği, scope/policy revision'ı ve campaign wire gate'i
korunur. Baseline ve inert kontrolde alert olmamalı; probe ve repeat kendi
benzersiz nonce'larıyla, tam enjekte edilen URL'de alert üretmelidir. İmzalı
validation artifact'i nonce/URL hash'lerini, Chromium sürümünü ve dört browser
request evidence kaydını içerir. Yansıma, ilgisiz alert, eksik tekrar/kanıt,
browser yokluğu veya değişen bağlam `CONFIRMED` üretmez; HTTP fallback yoktur.

Program policy'de etkinleştirme:

```json
"xss_execution": {"enabled": true, "max_browser_requests": 8, "wait_ms": 100}
```

Bu izin mevcut scope/grant gerekliliklerinin yerini almaz. Browser istekleri
aynı campaign bütçesinden sayılır. Desteklenen dar sözleşme GET/query'dir;
policy kapalıysa yansıma adayı önceki gibi `INCONCLUSIVE` kalır.

`blind-lab/3`, dosyaları sanal `/public` köküne göre normalize eder:
`notes.txt` başarılı, `secret.txt` ve eksik dosya başarısız,
`../secret.txt` ve tekrarı başarılıdır. Gerçek OS dosyaları okunmaz.
`/safe/file` traversal'ı reddeder. Benign/direct/missing/traversal/repeat
kontrolleri beş seed'de hem pozitif hem negatif imzalı coverage ile doğrulandı.

Doğrulama:

- İstenen iki dosya: **62 başarılı, 5 atlanan** test. Atlananlar opt-in gerçek
  HTTP/Chromium campaign testleridir.
- İlgili traversal, validator, browser policy ve modül sınırı regresyonları:
  **96/96**; kabul sonucu denetimleri: **15/15**. Toplam **173** farklı offline test.
- Beş seed offline browser protokol simülasyonunda **8/8 pozitif, 8/8 temiz
  negatif**. Bu sonuç gerçek JavaScript execution veya yeni wire kabulü değildir.
- Gerçek kabul runner'ı yalnız gerçek campaign testini seçer; offline testler
  tarihsel **37 testlik** wire paketine katılmaz. Koleksiyon 37 olarak doğrulandı.

```bash
CCO_RUN_WIRE_LAB=0 python3 -m pytest \
  tests/test_http_chromium_loss_analysis.py \
  tests/test_http_chromium_campaign.py -q
```

Offline JUnit çıktısı:
`/tmp/cco-work/xss-traversal-offline-verified.xml`.
Yeni beş-seed gerçek HTTP/Chromium kabul ölçümü henüz yapılmadı.

## Yeniden ölçüm denemesi: ortam engeli

Kullanıcı onayıyla `2026-11-04T21:49:44Z` tarihinde gerçek kabul runner'ı
yeniden çalıştırıldı. Sağlık kontrolü **7/7** geçti; runner'ın loopback socket
ön kontrolü `PermissionError: [Errno 1] Operation not permitted` verdi.
Çıkış kodu **2**, durum **`environment_unavailable`**. Chromium ve pytest
başlatılmadı; yeni wire isteği, seed skoru veya JUnit sonucu üretilmedi.

Deneme manifesti:
`/tmp/cco-work/http-chromium-reacceptance/run-h8ua22_b/acceptance.json`.
SHA-256: `e8667325d08007b28cfa6d0ead2081327dbd3520e7ced7df13c341ac3eb3ca53`.
Tarihsel başarılı manifestin hash'i tekrar kontrol edildi ve aynı kaldı:
`d0517f88eec7d8edac95fee1d72c0fdae239c43646f6e06be0887032867a7ac3`.

Bu oturumda socket izni yükseltilemiyor. Socket ve Chromium çalıştırmaya izin
veren yerel ortamda devam komutu:

```bash
python3 scripts/http_chromium_acceptance.py \
  --output-dir /tmp/cco-work/http-chromium-reacceptance
```

Yeni koşu ayrı bir `run-*` dizini oluşturur. Hedef, `blind-lab/3` için **37/37
gerçek test**, her seed'de **8/8 pozitif, 8/8 temiz negatif** ve gerçek Chromium
execution kanıtıdır; bu hedef ortam engeli nedeniyle henüz doğrulanmadı.

## Sonraki gerçek koşunun sonucu

Kullanıcının socket erişimli ortamda çalıştırdığı `run-74exq857` koşusu ve
kayıtlı kanıt denetimi geçti: **37/37 gerçek test**, beş seed'in tamamında
**8/8 pozitif, 8/8 temiz negatif**, seed başına **259/300 istek**.
XSS marker/execution bağı ve traversal kontrolleri 140 imzalı kayıt üzerinden
doğrulandı. Ayrıntılar [gerçek yeniden kabul kaydında](http-chromium-reacceptance-2026-11-04.md).
Yukarıdaki ortam engeli ve tarihsel 6/8 ölçümler korunur; iki kayıp ve gerçek
yeniden ölçüm dilimi artık tamamlandı.
