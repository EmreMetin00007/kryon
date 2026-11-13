# Kalıcı test kaynağı bağlama ve campaign devamı

Tarih: 2026-11-04. Durum: P4/P5/P6 kaynak bağlama ve sınırlı yeniden planlama dilimi tamamlandı. Bu kayıt canlı hedef kabulü veya Web/API geliştirme planının bütünüyle tamamlandığı anlamına gelmez.

## Oturumla birlikte saklanan kaynak beyanı

Yeni MCP aracı `validator_session_vault_bind_resources(target, identity, resources_json)`, mevcut test oturumuna rol, fonksiyon ve korumalı kaynak beyanlarını bağlar. Ağ isteği göndermez; scope gerektiren yerel durum değişikliği olarak capability kataloğuna kayıtlıdır. Oturum cookie/token değerleri aracın argümanlarına yeniden taşınmaz.

`resources_json` bir JSON object metnidir. Örnek yalnız sözleşmeyi gösterir; marker, operatörün kendi test kaynağında gözlediği değerden sağlanmalıdır:

```json
{
  "role": "admin",
  "functions": [{
    "url": "https://application.test/admin/report",
    "marker": "<observed-test-marker>",
    "test_data_only": true,
    "denied_roles": ["member"]
  }],
  "protected_resources": [{
    "url": "https://application.test/account/statement",
    "marker": "<observed-test-marker>",
    "test_data_only": true,
    "authentication_required": true
  }]
}
```

Beyanlar mevcut Fernet vault içindeki oturum payload'ında saklanır. Kamuya açık oturum indeksi, araç yanıtı ve campaign argümanları marker/kaynak listelerini içermez. Koleksiyon başına en fazla 32 kaynak kabul edilir; rol etiketleri, marker boyutu, tam origin, scope, fragment/userinfo ve kaynak başına erişim kuralı denetlenir. HTTP yöntem izni eklenmez; kaynak doğrulaması GET alt kümesinde kalır.

Beyan değişikliği oturum secret referansını yeniler ve freshness bilgisini kaldırır. Kullanım için yeni başarılı `session_vault_check` gerekir. Aynı normalize edilmiş beyanın tekrar bağlanması mevcut doğrulamayı geçersiz kılmaz. `session_vault_put` ile oturumun değiştirilmesi eski beyanları taşımaz. Rol etiketi değiştirerek eski kuralı kullanmak veya yeni scope/policy altında eski beyanı çözmek reddedilir.

Vault referansları normal `run_web_loop` akışında da çözülür; BFLA/authentication bypass için kör keşfin açılması gerekmez. Authentication bypass için bir yetkili test kimliği yeterlidir. Kör çok kimlikli keşif en az iki kimlik istemeye devam eder. Vault referansları ham cookie/identity malzemesiyle karıştırılamaz.

## Adaydan sınırlı göreve

Eksik erişim bağlamı olan BFLA/authentication bypass adayı, mevcut encrypted request deposu ve imzalı aday kaydıyla saklanır. Kaynak beyanı sağlandıktan sonra coverage/campaign planlayıcısı yalnız aynı kaynak, operasyon, gözlem ve koşuya ait adayı yeniden bağlar. Düz metadata planı, gözlenen imzalı adayın yerini tutmaz. Bağlama ve planlama ağ isteği göndermez.

Bağlı boyutun actor/owner değerleri somutlaşır: BFLA için yasaklı rolün test kimliği ve yetkili kimlik; authentication bypass için `anonymous` ve yetkili kimlik. `access_rule_hash`, marker, kaynak, erişim kuralı ve ilgili kimlik/rol bağlamını ayrıştırır. Bu değer request snapshot, gap anahtarı, imzalı coverage ve geri bildirim boyunca taşınır. Kaynak adayının advisory satırı, doğrulanan bağlı boyutun terminal sonucundan ayrı kalır.

Kaynak veya oturum kullanılamazsa mevcut görev bloklanır. Bütün bağlı hesaplar bloktan sonra yeniden doğrulandığında, kaynak/kural aynıysa mevcut görev kimliğiyle devam edebilir. Scope/policy, grant, gözlem/request snapshot, görev bağımlılığı, lease, deneme sınırı ve kalan toplam istek bütçesi tekrar denetlenir. Kaynak kuralı değişmişse eski görev devam etmez. Genel hata, rate limit veya sonuçsuz oracle, yalnız oturum yenilemeyle otomatik yeniden çalıştırılmaz.

İki kontrol isteği arasında beyan değiştiğinde de her istek öncesindeki session guard sonraki isteği durdurur. Eski kaynak, marker veya doğrulama bağlamı kullanılarak sonuç kapatılamaz.

## Doğrulama sonuçları

Auth bypass'ın olumsuz sonucu artık yetkili ve anonim kontrolün request/response metadata'sıyla imzalı artifact üretir; tamamlanan kontrol doğru coverage boyutunu `tested_clean`, geri bildirimi `tested_no_violation` yapabilir. Eksik marker, marker sızıntısı bulunan çelişkili yanıt, belirsiz HTTP durumu, transport hatası, 429 veya sunucu hatası temiz kontrol sayılmaz.

BFLA sentetik test modeli yetkili/yasaklı rol/anonim erişimi ayrı üretir. Yasaklı rol engellenmişse iki istek yeterlidir. Yasaklı rol marker'ı alıyorsa anonim kontrol gerekir; aynı içeriğin herkese açık olması BFLA kanıtı sayılmaz. Diğer rol veya anonim kontrolündeki başarısız/belirsiz yanıtlar `INCONCLUSIVE` kalır.

Dar sözleşme paketi:

```bash
python3 -m pytest tests/test_access_resource_resume.py tests/test_validator.py -q
```

Bu testler sentetik HTTP transport kullanır. Yeni MCP aracının checkout dışındaki temiz bir Python sürecinden çalışması da sınanır. Gerçek loopback, tarayıcı ve tam LLM ajan kabulü bu ölçümün dışındadır; kör labın pozitif recall veya negatif kapsam sayıları bu dilimden türetilmez.

Son doğrulama: **514 ilgili offline test geçti, 7 socket/tarayıcı testi seçilmedi**. Kaynak bağlama paketinde 36, validator paketinde 33 ve kör keşif entegrasyonunun offline alt kümesinde 15 test var; bu 84 test geniş toplamın içindedir. Scope/policy/grant değişimleri, görev receipt/lease bütünlüğü, bloktan sonra doğrulama zamanı, kalan bütçe, farklı gözlemler, plaintext sızıntı kontrolleri ve eski MCP sözleşmeleri de geniş regresyonda sınandı.

Geniş koşuyu yeniden üretme:

```bash
python3 -m pytest \
  tests/test_access_resource_resume.py tests/test_session_vault.py \
  tests/test_session_vault_policy.py tests/test_session_store.py tests/test_validator.py \
  tests/test_candidate_feedback.py tests/test_operation_context.py tests/test_openapi_refs.py \
  tests/test_blind_lab.py tests/test_surface.py tests/test_authenticated_web_api.py \
  tests/test_schema_contract.py tests/test_module_boundaries.py tests/test_wired_tools.py \
  tests/test_phase_b_loop_hook.py tests/test_hunter.py tests/test_blind_discovery_integration.py \
  tests/test_blindspot_and_wiring_fixes.py tests/test_surface_discovery_filter.py \
  tests/test_spa_lab.py tests/test_hunter_gap_queue.py tests/test_campaign_gap_bridge.py \
  tests/test_campaign_web_replan.py tests/test_campaign_session_resume.py \
  tests/test_opaque_id_coverage.py tests/test_blind_identity_discovery.py \
  tests/test_phase5_authz_upload_jwt.py \
  -k 'not fanout_live_reflection_xss and not app_positive_and_control_behaviour and not browser_headers_from_asyncio_does_not_hit_sync_api_error and not crawl_site_from_asyncio_does_not_hit_sync_api_error and not auth_bypass_wiring_unconfirmed_on_safe and not loop_authz_validate_confirms_bola and not validate_file_upload_confirmed' \
  -q --junitxml=/tmp/cco-resource-resume-20261104.xml
```

Geçici JUnit artifact'i `/tmp/cco-resource-resume-20261104.xml` altında üretildi. `git diff --check` ve ilgili Python modüllerinin derleme kontrolü geçti. Sağlık kontrolü 7/7 geçti. `check_repo_layout.py`, çalışma başında repo kökünde bulunan `codex-session-02.md` ve `codex-session-045.md` nedeniyle başarısız; bu oturum dosyaları taşınmadı.

## Önceki dilimde kalan işler

Bu dilimden sonraki öncelik traversal oracle'ını izinli uygulama dosyalarıyla sınamak, kör benchmark'ın negatif kontrollerini tamamlamak ve gerçek loopback/tam ajan kabulünü yürütmektir. Tam istek yakalamasının bütün serileştirme biçimleriyle kalıcı bağlanması ve P0–P9 planının diğer açık maddeleri ayrıca sürer.

## Campaign dayanıklılığı dilimi

Scheduler, hedef/context/run başına SQLite'ta kalıcı sıra imleci tutar. Bir
çağrıda en fazla `limit` görev planlanır ve en fazla `2 * limit` boyut işlenir.
Ertelenmiş boyutun arkasından devam edilir; sıra sonunda başa dönülür. Runtime
yeniden başlatıldığında imleç korunur. Eksik request snapshot, eski beyan veya
oturum koşulları bu dönüş sırasında gevşetilmez; terminal boyutlar ve mevcut
görev bağlantıları yeniden açılmaz.

Admission ve görev yaşam döngüsü politika kontrolü aynı geçici başlık
oluşturucusunu kullanır. Kimlikli görev kendi vault başlıklarını alır; beyanlı
authentication bypass'ın anonim kontrolü sahibin yalnız credential içermeyen
başlıklarını kullanır. Sıradan anonim parametre görevi başka bir bağlı hesabın
başlıklarını alamaz. Vault değerleri campaign SQLite argümanlarına yazılmaz.

Yaşam döngüsü kontrolünde oturum metadata'sını okumak yeni freshness kanıtı
sayılmaz. Süresi dolmuş oturumla görev claim edilebilir, yürütme kapısı trafiği
durdurur ve devam için gerekli blok receipt'ini üretir. Aynı görev ancak bloktan
sonra gerekli hesapların yeni doğrulamalarıyla devam eder. Bu senaryo ortak
program başlıkları boş bırakılarak BFLA ve authentication bypass için sınandı.

MCP sözleşme testleri mevcut `sample_limit=4` ve `candidate_sample_limit=4`
parametreleriyle güncellendi. Önceki kayıtlarda anılan dört kök oturum notu,
içerikleri açılmadan `/tmp/cco-work/session-notes-20261104/` altına taşındı;
`check_repo_layout.py` geçti. Kullanıcının kalıcı `CCO_WORKDIR` ayarı değiştirilmedi.

Beş seed'in kabul sonuçları ve yeniden üretim komutu
[negatif kontrol kaydında](negative-controls-2026-11-04.md) tutulur. Gerçek
HTTP/Chromium ve tam ajan kabulü sonraki dilimdir.
