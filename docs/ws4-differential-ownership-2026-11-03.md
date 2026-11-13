# WS4 Küme Farkı Sahiplik Çıkarımı — Uygulama ve Ölçüm

> Tarih: 2026-11-03 · İş paketi: WS4 (Öneri 2) · Tasarım: [architecture-tradeoff-review §3](/root/hackagent-opencode/docs/architecture-tradeoff-review-2026-11-02.md)
> İlke: keşif gevşer, kanıt gevşemez. Küme farkı aday üretir; `CONFIRMED` hükmünü mevcut validator verir.

## 1. Uygulanan

- [blind_discovery.py](/root/hackagent-opencode/mcp-servers/mcp-hunter/cco_hunter_core/blind_discovery.py): yeni `discover_differential_resources`. Aynı liste yüzeyini her sentetik kimlikle iki kez tarar; `IDs(A) \ (IDs(B) ∪ IDs(Anon))` farkını, kararlılık filtresinden geçenleri aday yapar. Türetilmiş işaret (sahip detayından, başkalarında görünmeyen tekil skaler) mevcut `objects` bağlama yoluna yazılır; `_loop_authz_validate` ve validator değişmedi.
- FP tuzakları: paylaşılan katalog fark dışı; `visibility: public` beyanlı nesne aday olmaz; sayfalı (`next`) yüzeyde aday bastırılır; kararsız kimlik (tek çekiş) elenir; anonim 401'de aday sürer ama `anon_baseline: false` etiketi düşer. Entropi filtresi yok: sıralı tamsayı kimlikler aday olur.
- Opt-in zinciri: program politikası `blind_discovery.differential_ownership: true` (bilinmeyen anahtar hâlâ fail-closed) + `run_web_loop(blind_differential=True)` (varsayılan kapalı) + kampanya köprüsü argümanı. Bayrak kapalıyken davranış değişmez.

## 2. Testler

- Birim: açık owner olmadan aday + işaret bağlama; kararlılık ve public eleme (test_blind_identity_discovery).
- Entegrasyon: sentetik taşımada uçtan uca CONFIRMED/UNCONFIRMED; politika opt-in yoksa ağa çıkmadan blocked; politika anahtarı fail-closed (test_blind_discovery_integration).
- Regresyon: blind + hunter + validator + campaign + authenticated + lab paketleri yeşil; lab 48/48; negatif kontrol FP 0.0; modül sınırı testi yeni parametreyi pinler.

## 3. Kör Lab Ölçümü (seed 20261102, iskelet hattı)

| Koşu | Kanıtlı | Aday | Kaçan | FP | İstek |
|---|---|---|---|---|---|
| Baz (bayrak kapalı) | 1/8 | 1 | 6 | 0/8 | 66 |
| WS4 (bayrak açık) | **2/8** | 1 | 5 | 0/8 | 118 |

Artışın tamamı BOLA: açık `owner` döndürmeyen `/orders/<uuid>` ucu ilk kez uçtan uca `CONFIRMED` oldu; güvenli ikizi `CONFIRMED` olmadı. Bedel: keşif bütçesi istek sayısını ~1.8 katına çıkarıyor; adaylar `stability: single_fetch` etiketi taşıyabiliyor (bütçe ikinci çekişe yetmediğinde) — hüküm yine validator'da.

Ölçüm sırasında bulunan lab hatası: sıfır nesneli hesabın `/notes` isteği lab sunucusunu düşürüyordu (500-sınıfı çökme); düzeltildi ve liste öğelerine detay `href` alanı eklendi (gerçek API'lerin self-link davranışı).

## 4. Kalan

- BFLA yazma yolu ve iş mantığı adayları bu fazın dışında (WS6/WS7).
- LLM hattında WS4 ölçümü ayrıca alınmadı; iskelet delta'sı ölçüldü.
- Keşif istek maliyeti yüksek: bütçe etkileşimi gerçek hedefte izlenmeli.
