# XSS/traversal sonrası gerçek HTTP/Chromium kabulü

Tarih: 2026-11-04. Durum: **yeniden ölçüm ve kayıtlı kanıt denetimi geçti**.
Kullanıcı koşucuyu socket erişimli ortamda çalıştırdı. `blind-lab/3` üzerinde
**37/37 gerçek test**, her seed'de **8/8 pozitif ve 8/8 temiz negatif** elde
edildi. [Önceki 6/8 kabul](http-chromium-acceptance-2026-11-04.md) ve
[ortam engeli kaydı](http-chromium-loss-analysis-2026-11-04.md) korunur.

## Ölçüm

Başlangıç `2026-11-04T22:22:12.197680Z`, bitiş
`2026-11-04T22:24:01.319176Z`; yaklaşık **109 saniye**.
Chromium **145.0.7632.6**. Runner durumu `passed`, çıkış kodu `0`;
JUnit hata, failure ve skip sayıları sıfır.

| Seed | Pozitif | Temiz negatif | Eşlenen vakalarda FP | Hazırlık | Browser keşfi | Keşif | Campaign | Toplam | Görev |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 20261104 | 8/8 | 8/8 | 0 | 7 | 1 | 99 | 152 | 259 | 28 |
| 20261105 | 8/8 | 8/8 | 0 | 7 | 1 | 99 | 152 | 259 | 28 |
| 20261106 | 8/8 | 8/8 | 0 | 7 | 1 | 99 | 152 | 259 | 28 |
| 20261107 | 8/8 | 8/8 | 0 | 7 | 1 | 99 | 152 | 259 | 28 |
| 20261108 | 8/8 | 8/8 | 0 | 7 | 1 | 99 | 152 | 259 | 28 |

Browser keşfi sütunu başlangıç sayfasının açılmasını sayar. XSS doğrulamasının
dört Chromium isteği **campaign** sütununa dahildir. Sunucunun aldığı toplam
**1.295 istek** faz toplamlarıyla eşleşir; her seed 300 istek sınırının altındadır.
İsteklerin tamamı testin tam loopback origin'ine, GET yöntemi ve zorunlu
program başlığıyla gönderilmiştir. HTTP fallback yoktur.

## XSS ve traversal kanıtı

Beş seed'in tamamında `xss-search` artık `CONFIRMED`, oracle
`browser_execution`, primitive `javascript_execution`:

- Baseline ve inert kontrolde alert sayısı **0/0**.
- Execution probe ve repeat'te kendi nonce'ıyla korele alert sayısı **1/1**.
- Üç nonce birbirinden farklı; imzalı nonce/URL hash'leri sunucunun aldığı
  isteklerdeki nonce ve tam URL ile eşleşiyor.
- Reflection ve dört browser yanıtının tamamı başarılı **200**; Chromium
  sürümü artifact'te kayıtlı, `completed=true`, `observed=true`, `fallback=false`.

`traversal-file` da beş seed'de `CONFIRMED`. İmzalı request evidence sırası:

| Kontrol | HTTP |
| --- | --- |
| Benign `notes.txt` | 200 |
| Doğrudan `secret.txt` | 404 |
| Eksik dosya | 404 |
| `../secret.txt` | 200 |
| Aynı traversal tekrarı | 200 |

Probe ve repeat response hash'leri eşleşiyor; baseline ve hata yanıtlarından
farklı. Marker yalnız traversal yoluyla doğrulanıyor. `/safe/file` kontrol
sırası **200/404/400/400/400**, verdict `UNCONFIRMED`; `/safe/search` marker'ı
HTML-encode ediyor ve `UNCONFIRMED` kalıyor. İki pozitif için loss stage artık
`null`; blocked campaign görevi yok.

## İmza, kapsam ve ek hesap matrisi

Kayıtlı JUnit, manifest ve beş seed'in ölçümleri `assess_results` ile yeniden
karşılaştırıldı. Public trust üzerinden seed başına **28**, toplam **140**
validation/coverage kaydının imzası, artifact hash'i, scope/policy bağı,
request boyutları ve verdict eşleşmesi doğrulandı. SQLite read-only açıldı;
private signing key veya secret vault okunmadı. Bu denetimde yeni wire isteği
gönderilmedi.

İlk 16 vakaya ait skor seed başına `unmapped_confirmed=4` tutmaya devam ediyor.
Önceden tanımlı ek hesap matrisi her seed'de **4/4 ek pozitif ve 4/4 ek temiz
negatif** veriyor; ek matriste FP ve birleşik eşlemede açıklanamayan kayıt
sayısı **0**. Bu ek vakalar ana 8+8 skoruna eklenmedi.

## Artifact ve yeniden üretim

Kabul dizini: `/tmp/cco-work/http-chromium-reacceptance/run-74exq857/`.
Ana kayıtlar `acceptance.json`, `junit.xml`, `pytest.log` ve seed dizinlerindeki
campaign, browser, wire ve imzalı validation dosyalarıdır.

Manifest SHA-256:
`4eed18818be844d4d75dc62843747d23cf4e5a5edaaeb161d55adfbbf77f8f46`.
JUnit SHA-256:
`780c2d57663f3e610e85338fdd3a0cf2598b40da84e89b3786520087b52c0f12`.

İmza/puan denetimi:
`/tmp/cco-work/http-chromium-reacceptance-audit/analysis-wetlmvw0/analysis.json`.
SHA-256: `4aa8da6db0f33a3dcbd87135ac02c6c79e369c1b70bb34cb64ead82df9b62e32`.
Nonce-wire ve kontrol eşleşmelerinin özeti aynı dizindeki `verified-summary.json`;
SHA-256: `49b19c9501520bd3d9ba5e0429c4f83892c16f43dade6a14f1cb5d891e63706c`.
Özet StateOps projesine evidence olarak bağlandı.

Kayıtlı imzaları ve skorları yeni istek göndermeden yeniden denetlemek için:

```bash
python3 scripts/http_chromium_loss_analysis.py \
  /tmp/cco-work/http-chromium-reacceptance/run-74exq857 \
  --output-dir /tmp/cco-work/http-chromium-reacceptance-audit
```

Tarihsel `blind-lab/2` manifest hash'i aynı kaldı:
`d0517f88eec7d8edac95fee1d72c0fdae239c43646f6e06be0887032867a7ac3`.
XSS execution/dizin sınırı ve bunların gerçek kabul dilimi tamamlandı.
Tam LLM ajan koşusu ve holdout değerlendirmesi sonraki açık işlerdir.
