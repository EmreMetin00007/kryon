# WS2 Şema Hasadı — Uygulama ve Kanıt

> Tarih: 2026-11-03 · İş paketi: WS2 (Öneri 1 / Faz 2) · Tasarım: [architecture-tradeoff-review](/root/hackagent-opencode/docs/architecture-tradeoff-review-2026-11-02.md)
> İlke: yeni tablo yok; hasat mevcut `attack_surface` kaydına düşer, bütçe tavanları aynen geçerli.

## 1. Boşluk (ölçülen)

Keşif, JS dosyalarını indiriyor ama içinden yalnız ham URL çıkarıyordu: HTTP metodu, gövde parametreleri ve GraphQL şeması hasat edilmiyordu. OpenAPI yalnız üç sabit adresten aranıyordu; JS/HTML içinde anılan spec adresi izlenmiyordu.

## 2. Uygulanan

- [extract.py](/root/hackagent-opencode/mcp-servers/mcp-memory-server/cco_surface_core/extract.py): `extract_js_calls` — fetch/axios çağrılarından URL + metot + gövde anahtarları (üst düzey, tırnak/parantez duyarlı tarama), şablon URL'leri (`/api/orders/${id}` → `{id}` yol parametresi), GraphQL uçlarında sorgu değişkenleri parametre olur. `find_spec_urls` — JS/HTML içindeki OpenAPI/Swagger adreslerini bulur.
- [discover_web_surface](/root/hackagent-opencode/mcp-servers/mcp-kali-tools/server.py): JS hasadına şema çıkarımı eklendi; bulunan spec adresleri (en çok 3) çekilip mevcut `parse_openapi` ile aynı tabloya işlenir. Çağrı başına dilim kendi parantez aralığıyla sınırlı (sonraki çağrıya taşma yok).

## 3. Kanıt

- Birim: metot+gövde şeması, şablon parametre, GraphQL değişkenleri, spec URL (tests/test_surface.py, önce kırmızı).
- Uçtan uca SPA kanıtı: rotası yalnız JS içinde olan POST ucu (gövde şemasıyla) ve JS'nin andığı OpenAPI'den gelen uç aynı koşuda iş kuyruğuna düştü (tests/test_surface_discovery_filter.py).
- Regresyon: surface + discovery + lab + hunter + cookie + crawl-policy + memory paketleri yeşil; lab 48/48.

## 4. Kalan

- JS hasadı regex tabanlıdır; ağır minify/obfuscation ve runtime XHR (browser crawl) bu fazın dışında.
- Hasadın kör lab recall'una etkisi ölçülmedi (lab SPA değil); gerçek SPA biçimli hedefte ölçüm gerekir.
- Yazma tabanlı BOLA/mass-assignment (WS7) ve LLM hattında hasat ölçümü sonraki işler.
