# Gerçek HTTP/Chromium doğrulaması — 31 Ekim 2026

Mevcut HTTP, browser ve kampanya yolları teste ait iki loopback sunucusunda
gerçek Playwright/Chromium ile çalıştırıldı. Opt-in labda **32 test geçti**;
daha önce Chromium eksikliği nedeniyle atlanan browser oturumu grubundaki
**4 test de geçti**. İlgili çevrimdışı regresyon grubunda **190 test geçti**.
Bu üç çalışmada başarısız veya atlanan test yoktur.

Labın 32 ayrı ölçüm dosyasında toplam **50 yetkili istek**, **52 alınan istek**
ve **0 kapsam dışı istek** vardır. Aradaki iki istek, CDP izolasyon testinde
ana kullanıcı context'inin testten önce ve test context'i kapandıktan sonra
çalıştığını gösteren kontrol istekleridir. Her ölçümde alınan istek sayısı,
yetkili istek sayısı ve bu açık kontrol isteklerinin toplamına eşittir.
Pytest'in `current` symlink'leri toplama ikinci kez dahil edilmedi.

## Sınanan davranışlar

| Yol / senaryo | Gerçek sunucu gözlemi |
|---|---|
| Native kampanyada curl + browser + HTTP validator | Kampanya bütçesi 5; sunucuya ulaşan toplam istek 5. |
| Browser sayfası ve sıralı fetch kaynakları | Bütçe 3'te üçüncü fetch engellenir; sayfa ve ilk iki fetch toplam 3 istek gönderir. Fallback yeni hak açmaz. |
| HTTP ve Chromium redirect hop'ları | İki hop için iki hak gerekir; 0/1 hak sınırında fazladan istek gönderilmez. |
| Kapsam dışı yol/port ve login redirect | İlk yanıt alınır; redirect hedefi sunucuya ulaşmaz. |
| Fetch, iframe ve popup | İzinli hedef ulaşır; kapsam dışı yol ve port engellenir. |
| POST, WebSocket ve service worker | Yalnız ilk GET ulaşır; bu üç yol ek sunucu isteği oluşturmaz. |
| İstekler arasında scope değişimi ve grant iptali | Değişikliğe kadar iki istek ulaşır; sonraki fetch ulaşmaz. |
| Zorunlu program header'ı eksikliği | Program varlığı olarak değerlendirilen `owned.test` için sıfır istek gönderilir. |
| 401 / 429 | İlk yanıt gözlenir; takip isteği ulaşmaz. |
| Navigation timeout | Sunucuya ulaşan tek denemenin tüketimi korunur. |
| İki port da kapsam içindeyken oturum izolasyonu | Aynı-origin fetch cookie ve Authorization taşır; farklı origin'e fetch/iframe/popup/goto/redirect gönderilmez. |
| Yerel CDP ve mevcut kullanıcı context'i | Test context'i kullanıcı cookie/localStorage/window durumunu devralmaz; kapatma sonrası ana context ve tarayıcı çalışmaya devam eder. |

Cookie testinde Chromium'un cookie jar'ının aynı hostun başka portuyla da
eşleştiği ayrıca kontrol edilir. Bu nedenle farklı porta sızıntının engellenmesi
yalnız scope reddine veya cookie'nin portla sınırlı olmasına dayanmaz;
BrowserSession'ın origin filtresi gerçek taşıma üzerinde sınanır.

CDP testinde ana kullanıcı context'i sentetik ve teste aittir. Test context'i
kapandıktan sonra açık context ve page listesi yeniden kontrol edilir; ana
sayfa tekrar gezinir ve başlık okunur.

## Doğrulanan tarayıcı düzeltmeleri

Güncel request gate, Chromium'un Playwright route'larını atlayabilen otomatik
redirect hop'larını CDP `Fetch` yanıt aşamasında durdurur. `Location` hedefi
scope/grant/header ve aynı istek bütçesinden geçmeden yanıt serbest bırakılmaz.
İlgili iframe ve popup hedefleri de bu denetime alınır.

Yeni page'in CDP denetimi `new_page()` dönmeden hazırlanır. WebSocket kapatma
callback'i async çalışır; context kapatma sonrasında CDP session temizliği
Sync API çağrısının dışına alınır. Gerçek Chromium testleri ve mevcut sahte
browser regresyonları bu güncel kodla geçti.

## Komutlar ve sonuçlar

Bu çalışmada pytest **9.0.2**, Playwright **1.58.0** kullanıldı. Shell sandbox'ı
TCP soketi oluşturmayı engellediğinden iki gerçek browser grubu onaylı sandbox
dışı yürütmeyle, yalnız fixture'ların oluşturduğu loopback sunucularında çalıştı.
Scope/policy/grant ve sentetik oturumlar geçici test dizinlerinde kaldı.

```bash
CCO_RUN_WIRE_LAB=1 python3 -m pytest tests/test_http_chromium_lab.py -q -ra \
  --basetemp=/tmp/cco-http-chromium-lab-20261031-resume-1738
python3 -m pytest tests/test_browser_session.py -q -ra \
  --basetemp=/tmp/cco-browser-session-20261031-resume-1746
```

Yeniden çalıştırırken mevcut ölçümleri korumak için yeni bir `--basetemp`
dizini seçilir veya seçenek kaldırılır.

| Kontrol | Sonuç |
|---|---|
| Gerçek HTTP/Chromium labı | 32 geçti, 50,05 saniye |
| Browser oturumu MCP arayüzleri | 4 geçti, 11,31 saniye |
| Browser/policy/fallback/surface/campaign/egress/modül regresyonları | 190 geçti, 14,71 saniye |
| `kalibounty-healthcheck` | 7 geçti |
| İlgili Python dosyalarında Ruff | Temiz |
| `git diff --check` | Temiz |
| `python3 scripts/check_repo_layout.py` | Temiz |

Regresyon grubunun gerçek komutu ölçüm özetinde kayıtlıdır. Önceki belgelerdeki
593/436 gibi sonuçlar bu sayılarla toplanmaz.

## Kanıt kaydı

Ölçüm özeti `hackagent-opencode` projesine StateOps kanıtı olarak bağlandı.
Özet; her fiziksel ölçümün istek sayısını, sentetik yollarını, ölçüm dosyası
hash'ini, seçilen kaynak dosyaların SHA-256 değerlerini ve test komutlarını
içerir. Cookie ve Authorization değerleri özete alınmadı.

- Kalıcı artifact: `/opt/AgentPent/evidence/mcp_artifacts/hackagent-opencode/1793468773737_http-chromium-lab-2026-10-31-measurement-summary.json`
- Artifact SHA-256 / StateOps evidence hash: `d4583cb8ae859847fdafbaf90e6ae24a8a540f34d2bc20d70a6be2d488d608bf`
- Yerel özet: `/tmp/cco-http-chromium-lab-20261031-measurement-summary.json`
- Ham fixture ölçümleri: `/tmp/cco-http-chromium-lab-20261031-resume-1738/*/measurement.json`

## Kalan sınırlar

Native kampanya ölçümü curl, tek kullanımlık browser ve HTTP validator'ı
kapsar. Hunter'ın tüm gerçek keşif/validator akışları bu labda ölçülmüş sayılmaz.
Kalıcı BrowserSession testleri origin, policy ve CDP izolasyonunu doğrular;
ayrı MCP çağrılarının ortak fiziksel bütçesini veya harici araçların çıkışını
garantilemez. Browser süreçleri testte `--no-sandbox` ile açılır; bubblewrap ve
namespace izolasyonu ayrıca doğrulanmalıdır.

Bağımsız kör benchmark, doğru/yanlış bulgu ve kaçırılan açık ölçümü, gerçek
OOB kaynak atfı, canlı ZAP ve agent-browser entegrasyonu açık kalır. Güncel
uygulama sırası [kalan iş listesinde](pentest-remaining-work-2026-10-30.md)
yer alır. Harici hedef/VDS/kolektör trafiği gönderilmedi.
