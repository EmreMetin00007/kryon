# Kampanya görevlerinde ortak HTTP bütçesi — 31 Ekim 2026

Bağımsız validator ve browser görevleri de artık yerel MCP worker'ın ayırdığı
istek hakkını kullanır. Worker, HTTP sayısını aracın serbest sonuç metninden
çıkarmak yerine native child'ın ortak sayacından alır.

## Desteklenen yollar

- Hunter'ın `run_web_loop`, `fuzz_attack_surface`, `auto_fanout_variants` ve
  `exploit_confirmed` HTTP yolları.
- Mevcut HTTP validator'ları, `validate_finding` yönlendiricisi ve oturum
  kontrolü; her gerçek istek ve redirect hop'unda parent aracın scope, grant,
  başlık ve hız kuralları uygulanır.
- Tek kullanımlık browser araçları, plain HTTP link çıkarma fallback'i ve
  `kali-tools_crawl_web_surface`. Sayfa, kaynak ve redirect istekleri aynı
  hakkı paylaşır; Playwright yardımcı thread'i yeni sayaç açmaz.
- Kampanyadaki temel `kali-tools_curl_request`. Bu yol mevcut egress adaptörü
  üzerinden tek tek HTTP gönderir. `extra_args` ve multipart kampanya
  adaptöründe desteklenmez; gönderim öncesi açık hata verir.
- Mevcut `ChainTaskExecutor`: manifestin istek tavanı, kampanyanın ayırdığı
  hakla sınırlanır. ChainTransport'ın mevcut per-step/rota sınırları da uygulanır.

Harici nmap/ffuf/sqlmap gibi araçlar ve henüz sayaca bağlanmamış ağ araçları,
bütçeli native kampanya yürütmesinde araç fonksiyonu yüklenmeden reddedilir.
Ağ erişimli custom executor da aynı garantiyi sağlamadığı için gönderim
öncesi reddedilir. Bu davranış kampanya yürütmesine aittir; bağımsız araç
çağrılarının bütün ağ yollarının bağlandığı anlamına gelmez.

## Sayaç ve sonuç

Her native child tek görev çalıştırır. `scripts/wire_budget.py`, o process ve
yardımcı thread'lerde tek kilitli sayaç tutar. Hunter'ın devralınan kapısı
zaten tüketim yaptığında alt HTTP/browser adaptörü ikinci kez saymaz.
Validator'ın eski yerel sayacını sıfırlamak bu hakkı yenilemez.

İstek hakkı scope/grant/header kontrolünden sonra, taşıma denemesinden hemen
önce tüketilir. Engellenen istek hak tüketmez; başarısız I/O denemesi tüketir.
Browser route'u devam ettirilemeden hata oluşursa ayrılan deneme geri verilmez.
Bu, uygulamanın aldığı istek sayısının birebir ölçümü değildir; gerçek HTTP
ve browser koşusunda giriş proxy'sinin sayacıyla karşılaştırılmalıdır.

Child, `cco-wire-usage/1` kaydında invocation kimliği, başlangıç limiti,
`authorized_requests` ve sabit engelleme nedenini döndürür. Parent başka
invocation'a ait, eksik, boolean/float sayaçlı, limit üstü veya ek alan taşıyan
kayıtla settlement yapmaz. Sonuç metnindeki farklı bir sayı bütçeyi değiştirmez.
Bu kayıt bulgu kanıtı veya validator artifact imzasının yerine geçmez.

Bütçe/policy engeli veya native yürütme hatası görevi `blocked` tutar.
Ölçülen sayı mevcutsa yalnız o tüketim hesaplanır; chain'in ölçülmüş başarısız
sonucu da aynı şekilde korunur. Timeout, öldürülen child, eski lease ve
geçersiz sayaçta harcama bilinmiyorsa tüm reservation hesaplanır. Genel ağ
görevi hatası yeni bir tam bütçeyle otomatik tekrar başlatılmaz. Offline
görevlerin mevcut retry davranışı korunur.

## Sınırlar ve sonraki ölçüm

Kampanyadaki ayrı görevlerin toplamını mevcut SQLite rezervasyon/settlement
işlemleri sınırlar. Doğrudan MCP istemcileri, keyfi Python callback'leri,
kalıcı browser oturumları, harici tarayıcı süreçleri ve diğer adaptörler için
bu aşamada ortak fiziksel çıkış garantisi verilmez. Üretim yürütmesi desteklenen
native yol üzerinden seçilmelidir.

Desteklenen curl/browser/HTTP validator yollarının ilk gerçek loopback
HTTP/Chromium ölçümü tamamlandı; ayrıntılar
[lab sonucundadır](http-chromium-lab-2026-10-31.md). Bağımsız kör koşuda doğru
bulgu, kaçırılan açık, yanlış pozitif, istek maliyeti ve gereksiz durma sayılarını
değerlendirmek açık iştir. Mevcut 401/429 ve yeniden doğrulama kurallarının
ayarı bu daha geniş ölçümün sonuçlarına dayanmalıdır.

## Doğrulama

Ortak sayaç, eşzamanlı tüketim, helper thread, redirect, scope/grant değişimi,
zorunlu header, iki farklı araçla toplam kampanya bütçesi, bağımsız validator,
browser fallback, Hunter'da çift sayım, custom/scanner reddi, chain sınırı,
bilinen/bilinmeyen harcama ve kullanım kaydı doğrulaması sentetik taşıyıcılarla
sınanır. Kurulu wheel'de ortak HTTP/browser sayacı ve native child'ın sıfır
HTTP tüketimli offline sonucu ayrıca kontrol edilir.

Son doğrulama sonuçları:

- Kampanya, worker, policy, egress, browser, surface, oturum, Hunter,
  authenticated API, validator, MCP ve kurulu wheel uyumluluk grubu:
  **593 geçti, 4 atlandı, 4 kapsam dışı bırakıldı** (61,97 saniye).
- Kampanya runtime, oturum devamı, ortak bütçe, chain ve worker soak hedefli
  grubu: **100 geçti** (17,23 saniye). Bu testler yukarıdaki grupla örtüşür.
- Değişen bütçe yollarında Ruff, `git diff --check` ve
  `python3 scripts/check_repo_layout.py` başarılı.

Atlanan dört browser-session testi Playwright/Chromium bulunmadığı için
çalışmadı. `test_fanout_live_reflection_xss` ve mevcut soket gerektiren
`test_katana_crawl_finds_endpoints`,
`test_browser_headers_from_asyncio_does_not_hit_sync_api_error`,
`test_crawl_site_from_asyncio_does_not_hit_sync_api_error` offline grubundan
çıkarıldı. Bu sonuç gerçek HTTP/browser entegrasyonunun yerine geçmez.

İlk geniş çalışmada execution-permit testinin son base64 karakterini
değiştirmesi bazen yalnız kullanılmayan padding bitlerini değiştiriyordu;
imza baytları aynı kalabiliyordu. Test artık imzanın bir baytını kesin olarak
bozar. Çalışma kodunun imza kabul kuralları değiştirilmedi.

Yukarıdaki geniş regresyon sonuçlarından sonra gerçek HTTP/Chromium labında
32 test, mevcut browser oturumu grubunda 4 test ve ilgili çevrimdışı
regresyonda 190 test geçti; bu çalışmalarda atlanan test yoktur. Labın 32
ölçümünde 50 yetkili istek ve CDP ana context'inin 2 kontrol isteği sunucuya
ulaştı; kapsam dışı istek sayısı sıfırdır. Ölçümler ve kaynak hash'leri
[lab notuna](http-chromium-lab-2026-10-31.md) bağlı kalıcı kanıtta saklandı.
Bu doğrulama teste ait loopback sunucularında yapıldı; harici hedef/VDS trafiği
gönderilmedi.
