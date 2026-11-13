# Aday üretimi ve geri bildirim kuyruğu

Tarih: 2026-11-03. P4/P5/P6'nın ilk aday/geri bildirim dilimi uygulandı. Planın tamamı ve canlı hedef kabulü bitmedi.

2026-11-04 devamı: aşağıda bu ilk dilim için açık bırakılan kalıcı kaynak bağlama ve sınırlı campaign devamı, [sonraki dilim kaydında](test-resource-resume-2026-11-04.md) ele alındı. Buradaki 2026-11-03 ölçümleri tarihsel sonuçlardır.

## Değişen davranış

- SQLi hafif oracle'ı, baseline'da olmayan `sqlite3.OperationalError` imzasını aday sinyali olarak tanır. Bu sinyal tek başına bulgu değildir.
- Hafif sinyal vermeyen, geçerli baseline ile gerçekten çalıştırılmış SQLi/SSTI/traversal problarından sınıflar arasında sırayla en fazla **4** aday seçilir. Engellenmiş, çalıştırılmamış veya geçersiz baseline'lı problar seçilmez. Bu seçim ek canary isteği göndermez; validator kendi kontrollerini mevcut wire bütçesinden kullanır.
- SQLi/traversal kuyruğunda tek `(class, param)` anahtarı kullanılmaz. Operasyon/gözlem, metot, kaynak URL'si, taşıyıcı, alan ve actor/owner ayrımı korunur. `lfi` ve `path_traversal` aynı doğrulama ailesinde dedup edilir.
- Canary'ler operasyonlar arasında sırayla işlenir; validator kuyruğu da sınıflar arasında sırayla ilerler. İlk operasyonun çok sayıda payload'ı veya ilk sınıfın çok sayıda nesnesi bütün bütçeyi önceden tüketmez. Kuyruk bütçesi hâlâ üst sınırdır.
- `name`, `message`, `text`, `template`, `greeting`, `content` gibi kayıtlı metin alanları veya renderer ipuçları SSTI hipotezi üretir. `account/profile/statement` rotaları ve `auth_required` metadata'sı authentication bypass hipotezi üretir. Rota adı, koruma kuralının kanıtı sayılmaz.

MCP tool adları ve imzaları korundu. OpenCode orkestrasyonu ve Hunter salt-okunur wire politikası korunur; bu dilim yeni HTTP metot izni vermez.

## BFLA ve authentication bypass önkoşulları

BFLA, nesne sahipliğiyle aynı önkoşulu kullanmaz. Yetkili test kimliğine ait `functions` listesinde kaynak URL'si, gerçek test yanıtından alınmış marker, sentetik kaynak beyanı ve yasaklı rol listesi gerekir. Diğer test kimliğinin rolü bu listede bulunmalıdır. Yalnız iki farklı rol adı veya `objects` listesi BFLA doğrulaması başlatmaz.

Authentication bypass için bir yetkili test kimliği yeterlidir. Kimliğin `protected_resources` listesinde kaynak, marker, `test_data_only: true` ve `authentication_required: true` gerekir. Actor anonim, kaynak sahibi yetkili kimlik olarak coverage'a bağlanır. Eksik koruma beyanından ihlal çıkarılmaz.

Aşağıdaki örnek geçici adapter sözleşmesidir; kalıcı oturum vault'ına aktarım bu dilimde tamamlanmadı. Header değerleri örnekte gösterilmez; çalışma sırasında mevcut test oturumu adaptörü sağlar.

```json
{
  "admin-test": {
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
  },
  "member-test": {"role": "member"}
}
```

Validator çağrısından önce kaynak/marker/rol beyanı yeniden eşleştirilir. Değişmiş bağlam validator'a aktarılmaz. Gerçek doğrulama mevcut owner/other-role/anonymous veya authorized/anonymous oracle'larından ve imzalı coverage/artifact denetiminden geçer. Eksik beyan, gerekçeli ve yürütülmeyen bir onarım planı oluşturur; kaynak veya marker uydurulmaz.

## Kalıcı geri bildirim

`hunter_feedback_queue` ve `hunter_feedback_events`, mevcut çalışma SQLite veritabanına eklenir. Anahtar scope/policy bağlamını, koşuyu, operasyon/gözlemi, URL/metodu, alan/taşıyıcıyı ve kimlik/sahibi içerir. Aynı gözlem aynı geri bildirim satırına gider; yeni gözlem veya scope/policy bağlamı ayrı iş oluşturur. Durum/gerekçe değişmediğinde tekrar olay yazılmaz.

Durumlar `proposed`, `ready`, `blocked`, `inconclusive`, `tested_no_violation`, `confirmed` olarak ayrılır. Eksik oturum, şema, erişim kuralı, bütçe, transport veya policy için sabit `reason_code`, `next_action` ve gerekli önkoşullar bulunur. Query değerleri redakte edilir; hata metni, request_ref, header, gövde ve credential planlara yazılmaz.

Terminal durum, kamuya açık loop verdict'inden veya `coverage_recorded` boolean'ından türetilmez. Aynı bağlam/validation ID için Hunter'ın güncel doğrulanmış coverage olayı gerekir. Kaybolan veya değişmiş artifact, önbellekteki terminal durumu da `inconclusive` yapar. Sonuçlar `run_web_loop.feedback_queue` ve mevcut `coverage_report[_run]` çıktısında okunabilir; coverage yüzdesini veya bulgu sayısını ayrıca artırmaz.

Geri bildirim planı ağ isteği göndermez ve kendi kendine retry/claim başlatmaz. `automatic_retry: false` korunur. Çalıştırılabilir gap task'larının mevcut encrypted-request, campaign claim/lease, grant ve bütçe kapıları korunur. BFLA/auth bypass için yeni kaynak beyanlarının vault/session ve campaign resume boyunca kalıcı taşınması sonraki iştir.

## Doğrulama ve sınırlar

`tests/test_candidate_feedback.py` içindeki **25 test geçti**. Sınıf/operasyon bütçesi, başarısız probun seçilmemesi, istek referansı, SQLite sinyal ayrımı, kaynağa bağlama, değişmiş erişim kuralının reddi, gerçek validator'lardan imzalı BFLA/auth bypass çıktısı, kuyruk dedup, eski kanıtın yeni gözlemi kapatmaması ve artifact kaybında terminal durumun geri alınması kontrol edildi. Transport sentetiktir; testler socket açmaz.

Toplam **395 ilgili offline test geçti**: geniş yüzey/Hunter/coverage/campaign paketinde 391, Phase 5'in socket gerektirmeyen alt kümesinde 4 test. Socket kullanan 7 test bu son doğrulamada seçilmedi. Bütün repo test paketi çalıştırılmış değildir. `git diff --check` ve `python3 scripts/check_repo_layout.py` geçti.

Dar sözleşme paketini yeniden çalıştırma:

```bash
python3 -m pytest tests/test_candidate_feedback.py -q
```

Değiştirilmemiş kör lab uygulaması, bellek içi HTTP adaptörüyle çalıştırıldı. Solver yalnız başlangıç URL'si ve test kimliklerini aldı; truth puanlayıcıda kullanıldı. Bu ölçüm **sentetik transport regresyonudur**; önceki gerçek loopback benchmark'ının veya tam LLM ajan kabulünün yerine geçmez. Zaman tabanlı oracle ve gerçek ağ maliyeti bu transport ile kabul edilmez.

| Seed 20261103, `blind-score/3`, sentetik transport | Kanıtlı pozitif vaka | Adaptör isteği | Tamamlanmış negatif |
| --- | --- | --- | --- |
| Deterministik | 3/8 | 159 | 0/8 |
| Diferansiyel kimlik keşfi | 4/8 | 159 | 0/8 |

SQLi ve SSTI artık kanıtlı validator sonucuna ulaşır; traversal aday üretiminden geçer fakat mevcut dosya oracle'ı sonuçsuz kalır. Lab yalnız uygulamaya özgü `secret.txt` içeriği sunar; mevcut validator'ın passwd/win.ini probları bu içeriğe ulaşmaz. Kör akışta BFLA/auth bypass kaynak beyanı bulunmaz, bu nedenle ikisi de açık önkoşul olarak kalır. XSS hâlâ sonuçsuzdur. Diferansiyel koşunun 2 truth dışı doğrulaması ayrı tutulur. Negatiflerin hiçbiri tamamlanmadığından FP oranı `null` kalır.

Artefact'lar: `/tmp/cco-p5p6-deterministic-regression-20261103.json`, `/tmp/cco-p5p6-differential-regression-20261103.json`.

Bu ortam socket açmayı `Operation not permitted` ile engellediği için gerçek loopback doğrulaması yenilenemedi. Sıradaki işler: kalıcı test-kaynağı bağlama, traversal'ın izinli uygulama dosyalarıyla kontrolü, negatif kontrol kapsamı ve tam ajan/loopback kabulü.
