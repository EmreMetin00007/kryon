# SPA Kapsama Ölçümü — Düzenek ve İlk Sonuç

> Tarih: 2026-11-03 · Amaç: "keşif/harita yeterince iyi mi" sorusunu sayıyla cevaplamak.
> Düzenek: [spa_lab.py](/root/hackagent-opencode/scripts/lab/spa_lab.py) + [spa-validate.py](/root/hackagent-opencode/scripts/spa-validate.py) + [spa_discover_run.py](/root/hackagent-opencode/scripts/lab/spa_discover_run.py)

## 1. Düzenek

SPA biçimli hedef: ana sayfada rota bağlantısı yok. 13 gerçek rotanın bilgisi yalnız JS paketi (fetch/axios/GraphQL çağrıları), JS'nin andığı OpenAPI belgesi, robots ve sitemap içinde. Keşif süreci doğruluk listesini görmez; puanlama operatör tarafında: rota kapsaması (metot+yol şablonu) ve parametre kapsaması ayrı sayılır, fazla rotalar ayrıca raporlanır.

## 2. Ölçümler (aynı düzenek)

| Koşu | Rota | Parametre | Kaçan |
|---|---|---|---|
| Baz | 10/13 (%76.9) | 13/18 (%72.2) | 3 OpenAPI rotası |
| Spec adı düzeltmesi sonrası | **13/13 (%100)** | **18/18 (%100)** | yok |

Kaçan katman tek çıktı: JS'nin andığı spec belgesi, dosya adı `openapi` içermediği için bulunamıyordu. `find_spec_urls` artık spec atamalarını ve `spec` adlı dosyaları da tanır.

Fazla rota: `GET /api/v2` — JS içindeki sürüm sabiti ham URL hasadından envantere giriyor. Puan silinmiyor; gürültü olarak görünür durumda.

## 3. Dürüst sınır

Bu lab, hasatçının işlediği biçimde operatör tarafından kuruldu; %100 buradaki boru hattının uçtan uca çalıştığını ve regresyon ölçüsü olduğunu kanıtlar, gerçek dünya SPA kapsamasını kanıtlamaz. Hâlâ ölçümsüz/zayıf katmanlar:

- Giriş arkası (kimlikli) yüzey: keşif anonim/tek kimlikle bakar.
- Runtime XHR: tarayıcı gezintisi varsayılan kapalı.
- Ağır minify/obfuscation altında regex hasadı.
- Arşiv (wayback/gau) katmanı varsayılan kapalı.

## 4. Hüküm

Bu düzenekte harita yeterli; genelleme için ikinci bir biçim (ör. kimlikli + tarayıcı XHR'li lab) gerekir. Sonraki büyük iş: yazma testleri (WS7) — harita artık yazma kapılarını şemasıyla verdiği için önkoşul ölçülebilir durumda.
