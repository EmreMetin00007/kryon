# Negatif kontrol kanıtları ve yarım kalan testin tamamlanması

Tarih: 2026-11-04. `codex-session-05.md` sonunda kesilen negatif kapsam
doğrulaması bu kayıtta devam ettirildi. Ölçüm, operatörün seçtiği sentetik
validator sözleşmesidir; kör keşif veya tam ajan kabulü değildir.

## Değişiklikler

SQLi, SSTI, reflected XSS ve open redirect doğrulayıcılarının tamamlanan
olumsuz kontrolleri artık request/response metadata'sıyla imzalı kanıt üretir.
Başarısız transport, başarısız baseline, rate limit veya eksik kontrol temiz
kapsam sayılmaz. SSTI'nin başarısız malformed kontrolü doğrulama kanıtı olarak
kabul edilmez. Kontrol izleri response gövdesini saklamaz.

Yarım kalan entegrasyon testinde lab handler'ı `/allowed/` altında çalışırken
root-relative `Location` yolları eski kökte kalıyordu. Sentetik HTTP adaptörü
artık bu yerel yolları aynı prefix altında eşler; absolute ve protocol-relative
dış hedefleri değiştirmez. Üretim scope/grant/rate kapıları değiştirilmedi.

## Gözlenen sonuç

Değiştirilmemiş, seed `20261104` labının sekiz negatif vakası doğrudan validator
kuyruğuna verildi. Bütün 47 adaptör isteği politika kapısından geçti.

| Ölçüt | Sonuç |
| --- | --- |
| Doğrulamaya giren negatif vaka | 8 |
| İmzalı kanıtla tamamlanan negatif kontrol | 7 |
| Sonuçsuz negatif kontrol | 1, open redirect |
| Negatif kapsam | 7/8, %87,5 |
| Tamamlanan kontrollerde gözlenen yanlış doğrulama | 0/7 |

Labın `/safe/go` handler'ı `/\host/` biçimini kabul edip bulunmayan yerel bir
yola yönlendirir. Sonraki `404` yanıtı tamamlanmış redirect kontrolü değildir;
bu vaka `INCONCLUSIVE` kalır. Lab handler'ı veya truth değiştirilmedi. Ayrı bir
sentetik sözleşme, altı redirect payload'ını başarılı `400` ret yanıtıyla
sonuçlandıran uygulamanın imzalı `tested_clean` kapsam üretebildiğini sınar.

Test, kaynak/kimlik bağlamı sağlanırken oluşan advisory planları tamamlanan
kontrollerden ayırır. Tamamlanan yedi kontrol `tested_no_violation`, redirect
kontrolü `inconclusive` geri bildirimi üretir. Bir tamamlanmış kontrolün artifact'i
kaldırıldığında yeniden export/puanlama yalnız altı kontrolü tamamlanmış sayar.
Oturum token'larının export'a sızmadığı ve temiz kontrol kanıtlarında gövde
excerpt'i bulunmadığı da sınanır.

## Doğrulama

```bash
python3 -m pytest tests/test_negative_coverage.py tests/test_validator.py -q \
  --junitxml=/tmp/cco-session05-negative-controls.xml
```

Dar paket: **58 test geçti**. Sağlık kontrolü: **7/7**.

[Kaynak bağlama kaydındaki](test-resource-resume-2026-11-04.md) geniş regresyon
komutuna `tests/test_negative_coverage.py` ve
`tests/test_application_file_traversal.py` eklenerek **587 offline test geçti**;
aynı yedi socket/tarayıcı testi seçilmedi. JUnit çıktısı
`/tmp/cco-session05-offline-regression.xml` altında üretildi.

`git diff --check` geçti. `check_repo_layout.py`, repo kökünde bulunan
`codex-session-02.md`, `codex-session-03.md`, `codex-session-045.md` ve
`codex-session-05.md` nedeniyle başarısız; mevcut oturum kayıtları taşınmadı.

## Önceki dilimde kalan kabul işleri

M2'nin **8/8 tamamlanan negatif kontrol**, en az **6/8 doğru pozitif** ve beş
seed hedefleri korunur; bu sözleşme M2'yi kapatmaz. Kör keşifte negatif
kontrollerin otomatik seçilmesi, geçerli redirect kontrol yolu, gerçek
HTTP/Chromium ve tam ajan kabulü ayrıca yürütülmelidir. Bu sonuçlar önceki kör
koşuların puanlarının yerine yazılmaz.

## Beş seed campaign kabulü ve yeniden başlatma

`test_observed_controls_resume_as_campaign_tasks` artık `20261104`–`20261108`
seed'lerini ayrı çalıştırır. Kuyruk lab truth'undan hazırlanmaz: gözlenen
yüzeyler, operatörün kendi kaynaklarında gözlediği marker'lar ve vault'a bağlı
erişim beyanları kullanılır. Truth yalnız yürütme bittikten sonra puanlama
için açılır. HTTP transport, sürümlü `blind-lab/2` handler'ını bellekte çağırır.

Her koşuda iki tamamlanan worker batch'i sonrasında runtime ve worker yeniden
oluşturulur. Görev kimliği, argümanları, deneme sayısı, durum ve kullanılan/ayrılan
istek bütçesi korunur. Aynı boyut tekrar planlandığında duplicate görev oluşmaz.
Campaign görevlerinin ortak `headers` alanı boştur; zorunlu `X-Research` başlığı
yalnız ilgili oturum vault'undan bellekte çözülür. Token'lar görev argümanlarına
ve kabul çıktısına yazılmaz.

Kabul eşikleri her seed için en az 6/8 kanıtlı pozitif, 8/8 tamamlanan negatif,
sıfır FP ve hazırlık dahil en fazla 300 istektir. Hazırlık, keşif ve campaign
istekleri ayrı sayılır; gerçek toplam sentetik transport çağrılarıyla eşleşir.

| Seed | Kanıtlı pozitif | Temiz negatif | FP | Hazırlık | Keşif | Campaign | Toplam | Görev |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 20261104 | 6/8 | 8/8 | 0 | 7 | 99 | 143 | 249 | 27 |
| 20261105 | 6/8 | 8/8 | 0 | 7 | 99 | 143 | 249 | 27 |
| 20261106 | 6/8 | 8/8 | 0 | 7 | 99 | 143 | 249 | 27 |
| 20261107 | 6/8 | 8/8 | 0 | 7 | 99 | 143 | 249 | 27 |
| 20261108 | 6/8 | 8/8 | 0 | 7 | 99 | 143 | 249 | 27 |

Ana regresyon paketi **122/122**, ek campaign politika paketi **21/21** geçti.
Vault başlıklarıyla oturum bloklama/yeniden doğrulama senaryolarının son hali
ayrıca **2/2** geçti. Birleştirilmiş beş seed kanıtı
`/tmp/cco-work/campaign-five-seed-acceptance.json` altında, JUnit çıktıları aynı
çalışma dizininde tutulur. Bu artifact yolları geçici çalışma verisidir.

Yeniden üretim:

```bash
mkdir -p /tmp/cco-work
CCO_WORKDIR=/tmp/cco-work python3 -m pytest \
  tests/test_automatic_negative_controls.py::test_observed_controls_resume_as_campaign_tasks \
  tests/test_campaign_gap_bridge.py tests/test_access_resource_resume.py \
  tests/test_campaign_session_resume.py tests/test_hunter_gap_queue.py \
  tests/test_module_boundaries.py -q --tb=short \
  --basetemp=/tmp/cco-work/campaign-resilience-tests \
  --junitxml=/tmp/cco-work/campaign-resilience.xml
```

Bu ölçüm M2'nin offline campaign kabulüdür. Gerçek HTTP/Chromium sonucu ayrı
koşu olarak aşağıda kaydedilir; tam LLM ajan ve farklı lab aileleriyle holdout
kabulü ayrıca sürer.

Gerçek HTTP/Chromium yolu ve koşucu sonraki dilimde hazırlandı; bu sandbox'ta
ilk deneme socket/Chromium başlatma engeliyle durdu. Kullanıcının socket
erişimli ortamda yürüttüğü sonraki koşu **37/37 gerçek testi** geçti: beş
seed'in her birinde **6/8 pozitif, 8/8 temiz negatif ve toplam 250 istek**.
Eşlenen vakalarda FP sıfır; seed başına dört `unmapped_confirmed` kaydı ayrıca
inceleme gerektirir. [Gerçek kabul kaydı](http-chromium-acceptance-2026-11-04.md)
artifact doğrulamasını, önceki ortam hatasını ve açık kalan kayıpları içerir.
