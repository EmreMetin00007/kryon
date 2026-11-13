# Gerçek HTTP/Chromium campaign kabulü

Tarih: 2026-11-04. Durum: kullanıcı tarafından socket erişimli ortamda
çalıştırılan gerçek HTTP/Chromium campaign kabulü geçti; artifact'ler ayrıca
doğrulandı. Önceki [beş seed offline sonuçları](negative-controls-2026-11-04.md)
ayrı ölçüm olarak korunur.

## Hazırlanan yol

`tests/test_http_chromium_campaign.py`, aynı `blind-lab/2` handler'ını testin
kendi oluşturduğu `127.0.0.1:<port>` sunucusunda çalıştırır. Geçici scope tam
origin'i kapsar; scope ve tool grant'ları her test için ayrıdır. Projenin aktif
harici hedef scope dosyası değiştirilmez. Ortam proxy'leri ve mevcut CDP oturumu
bu testlere aktarılmaz.

Native `browser_browser_extract_links`, gerçek Chromium ile başlangıç sayfasını
açar ve linkleri gerçek surface deposuna işler. Başarısız Playwright çalışmasının
HTTP fallback'i kabul edilmez. Ardından gözlenen keşif, vault kaynak bağlama ve
kalıcı campaign görevleri yürür. Bu yol offline testle aynı kabul yardımcısını
kullanır; hedef URL ve transport ayrıdır. Truth yalnız sonunda puanlamada okunur.
Tam LLM ajan izolasyonu veya holdout genellemesi bu testin kapsamı değildir.

Her seed için hedefler değişmedi: en az 6/8 kanıtlı pozitif, 8/8 tamamlanan
negatif, sıfır FP, hazırlık ve Chromium dahil en fazla 300 istek. Sunucu gelen
istekleri sayar; hazırlık/browser/keşif/campaign faz toplamı bu sayıya eşit
olmalıdır. Yalnız GET ve zorunlu program başlığını taşıyan istekler kabul edilir.
İki runtime yeniden başlatması, görev/bütçe korunması ve duplicate engeli aynı
sözleşmede sınanır. Kimlikli campaign görevlerinin ortak başlık alanı boştur;
credential'lar ilgili account vault'larından çözülür. Browser hazırlığına yalnız
kamuya açık program başlıkları verilir. Ölçüm dosyaları token/cookie saklamaz.

`scripts/http_chromium_acceptance.py`, socket ve Chromium ön kontrolünden sonra
32 mevcut wire guardrail testiyle beş yeni seed testini çalıştırır. Her koşu için
ayrı çalışma dizini, JUnit, pytest log'u ve `acceptance.json` üretir. Skip, hata,
eksik seed, yanlış ölçüm modu, fallback veya tutarsız sunucu/browser sayımı
`passed` sayılmaz. Kod deposu içine çalışma çıktısı yazmayı reddeder.

## İlk denemede gözlenen ortam engeli

Gerçek guardrail paketi denendi: **32 test kurulum hatası** verdi. Loopback
socket oluşturma `PermissionError: [Errno 1] Operation not permitted` ile
reddedildi; Chromium başlatma da `sandbox_host_linux.cc` içinde aynı sistem
çağrısı kısıtıyla durdu. Bu ağ/IPC sandbox sınırı nedeniyle gerçek test sonuçları
üretilmedi. Güvenlik kapıları gevşetilmedi ve mock transport'a geçilmedi.

Yeni koşucunun ön kontrolü bu durumu `environment_unavailable` ve çıkış kodu
`2` olarak kaydetti. Artifact:
`/tmp/cco-work/http-chromium-acceptance/run-6i92f52k/acceptance.json`.
İlk gerçek çalıştırma hata kaydı:
`/tmp/cco-work/http-chromium-acceptance/guardrails.xml`.

Offline doğrulamalar: ortak campaign sözleşmesi ve gap bridge paketi **34/34**,
sonuç kapısının karşı örnekleri **15/15** geçti. Opt-in paket toplaması **37 test**
buldu. Bu sayılar gerçek HTTP/Chromium kabulünün yerine geçmez.

Ortak yardımcıya geçişten sonra kalan dört offline campaign seed'i de **4/4**
geçti; böylece beş seed'in tamamı yeniden doğrulandı. Bu dilimde toplam **53
offline kontrol** geçti. Derleme, `git diff --check` ve repo veri sınırı kontrolü
geçti; graphify kod grafiği güncellendi. Sağlık kontrolü **7/7** geçti.

## Doğrulanan gerçek kabul sonucu

Kullanıcı koşucuyu socket erişimli ortamda çalıştırdı. Başlangıç
`2026-11-04T17:05:17.098823Z`, bitiş `2026-11-04T17:07:01.022416Z`; toplam
süre yaklaşık **104 saniye**. Chromium sürümü **145.0.7632.6**. **37/37 test
geçti; hata, failure ve skip sıfır**. Koşucu çıkış kodu `0`, durum `passed`.

| Seed | Kanıtlı pozitif | Temiz negatif | Eşlenen vakalarda FP | Hazırlık | Browser | Keşif | Campaign | Toplam | Görev |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 20261104 | 6/8 | 8/8 | 0 | 7 | 1 | 99 | 143 | 250 | 27 |
| 20261105 | 6/8 | 8/8 | 0 | 7 | 1 | 99 | 143 | 250 | 27 |
| 20261106 | 6/8 | 8/8 | 0 | 7 | 1 | 99 | 143 | 250 | 27 |
| 20261107 | 6/8 | 8/8 | 0 | 7 | 1 | 99 | 143 | 250 | 27 |
| 20261108 | 6/8 | 8/8 | 0 | 7 | 1 | 99 | 143 | 250 | 27 |

`assess_results` kayıtlı JUnit ve beş seed'in campaign, sunucu ve browser
artifact'leri üzerinde yeniden çalıştırıldı. Sonuç manifestle birebir eşleşti:
gerçek ölçüm modu, toplam/faz istekleri, program başlığı, loopback origin,
Chromium fallback yokluğu ve surface ingestion denetimleri geçti. Önceki
sandbox hatası başarılı koşunun üzerine yazılmadı.

Kanıt dizini: `/tmp/cco-work/http-chromium-acceptance/run-xmpidxvp/`.
Ana manifest `acceptance.json`; JUnit `junit.xml`; test log'u `pytest.log`.
Manifest SHA-256:
`d0517f88eec7d8edac95fee1d72c0fdae239c43646f6e06be0887032867a7ac3`.

Her seed'de `xss-search`, `validation_inconclusive` nedeniyle candidate;
`traversal-file`, `probe_no_candidate` nedeniyle missed kaldı. Ayrıca seed
başına `unmapped_confirmed=4` var. Bu kayıtlar doğru pozitif veya yanlış
pozitif toplamına katılmadığından FP metriği eşlenen vakalar içindir;
eşlenmeyen kayıtların doğruluğu ayrıca incelenmelidir. Bu kabul mevcut sayısal
eşiği karşılar; bütün pozitiflerin kanıtlandığını veya M0–M4'ün kapandığını
göstermez. Tam LLM ajan, farklı lab aileleri ve holdout kabulü açık kalır.

## Yeniden üretim

Socket ve Chromium çalıştırmaya izin veren yerel ortamda:

```bash
python3 scripts/http_chromium_acceptance.py \
  --output-dir /tmp/cco-work/http-chromium-acceptance
```

Yalnız ortam ön kontrolü için `--check-only` eklenir. `ready`, ön kontrolün
geçtiğini gösterir; tam kabul ancak bütün testler ve ölçüm kapısı geçtiğinde
`passed` olur. `failed` çıkış kodu `1`, ortam engeli çıkış kodu `2` üretir.

Offline regresyonu yeniden üretme:

```bash
python3 -m pytest tests/test_http_chromium_acceptance.py \
  'tests/test_automatic_negative_controls.py::test_observed_controls_resume_as_campaign_tasks[20261104]' \
  tests/test_campaign_gap_bridge.py -q
```

XSS/traversal kayıp aşamaları ve dört eşlenmeyen doğrulamanın vaka bağı
[sonraki inceleme diliminde](http-chromium-loss-analysis-2026-11-04.md)
çözümlendi. Bu belgenin tarihsel ölçümleri korunur. Gerçek HTTP/Chromium
campaign kabulü tamamlandı; execution/boundary düzeltmeleri, tam ajan ve
holdout kilometre taşları açık kalır.
