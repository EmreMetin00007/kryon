# Mimari Derinleştirme — Tasarım

Tarih: 2026-10-26. Karar: kullanıcı seçimi "Mimariyi derinleştir" (ince beyinle
bitirici sefer yerine). Bu belge kapsamı sabitler; uygulama dilim dilim,
her dilim testle kapanır. Yeni özellik, bu belgedeki bir zayıflığa bağlanmadan
eklenmez.

## Teşhis (kanıtlı zayıflıklar)

1. **Tek-ipe saplanma.** Faz zinciri doğrusal: bir vektör ilk engelde
   (SQLi 400, SSRF allowlist, race 409) durunca zincir ya STOP oluyor ya da
   aynı vektörde oyalanıyor. Yan vektöre geçiş mekanizması yok; karar LLM'in
   anlık muhakemesine kalıyor.
2. **Hedef kimliği birleşik değil.** Aynı hedef `192.168.2.1:8080` ve
   `192.168.2.1` olarak iki ayrı anahtarla kaydedildi; bulgu kaydı
   `inconclusive` saplandı.
3. **Kapanış zinciri kırık.** Validator CONFIRMED ürettiği hâlde bulgu kalıcı
   depoya mühürlenemedi (`.cco` sır-koruması artefakt yollarını da vuruyor);
   rapor fazı süre bütçesinin dışında kaldığı için koşu raporsuz bitti.
4. **Hafıza kör noktası.** `get_target_memory` hedef-kapsamlı değil; kör
   koşuda bile paylaşımlı hafıza önceki koşu izlerini taşıdı. "Körlük"
   iddiası denetlenemiyor.

## Hedef mimari (4 bileşen)

### A. Hipotez defteri (zayıflık 1)
Çalışma dizininde `<workdir>/hypotheses.json`: hedef başına vektör kuyruğu.
Her kayıt: `vector`, `status` (`untried|active|blocked|exhausted|confirmed|
not_applicable`), `attempts`, `evidence[]`, `note`. Rotasyon kuralı kodda:
`blocked` attempts artırır; `max_attempts` (varsayılan 2) dolunca kayıt
`exhausted` olur ve `next` bir sonraki `untried` kaydı verir. `confirmed`
yalnızca o vektörü kapatır, kuyruğu durdurmaz. Karar LLM'de değil defterde.

Varsayılan vektör sırası (web/authed): `authz-idor`, `authn-session`,
`csrf`, `injection-sqli`, `ssrf`, `xss-stored`, `race-business`,
`file-access`. Sıra önceliktir, zorunluluk değil: `not_applicable`
işaretli vektör atlanır ama kaydı görünür kalır.

### B. Kanonik hedef kimliği (zayıflık 2)
`scripts/target_identity.py`: tek doğruluk kaynağı.
`canonical_target(raw)` görünen biçimi (şema/küçük harf host, yol atılır,
açık port korunur), `target_key(raw)` kimlik anahtarını (varsayılan port
dahil `host:port`) üretir. Plan, özet, bulgu ve defter aynı anahtarı kullanır.
`brain.py plan` hedefi yazmadan önce kanonikleştirir.

### C. Bulgu yaşam döngüsü kapanışı (zayıflık 3)
Mevcut durum makinesi (`mcp-memory-server`: store → validate →
`update_finding_validation`, reportable yalnızca CONFIRMED artefaktla)
korunur. Kaydetmeden önce tekilleştirme zorunlu: kanonik `target_key` +
tip (+ varsa `validation_id`) ile mevcut kayıt aranır; duplicate varsa
kanonik kayıt yaşam döngüsünde ilerletilir, yeni satır açılmaz (bugün
`_store_finding_internal` koşulsuz INSERT yapıyor — bu dilimde düzelir).
Eklenen halka: depo yazımı başarısızsa bulgu çalışma dizininde
`findings/<target_key>/<id>.json` kanıt paketi olarak düşer; CONFIRMED
hiçbir koşulda kaybolmaz. Rapor fazı her zincirin sonuna koşulsuz eklenir
ve süre bütçesinde kapanış penceresi ayrılır (son faz, önceki faz
`partial` olsa da dispatch edilir).

### D. Hedef-kapsamlı hafıza (zayıflık 4)
`get_target_memory` kanonik anahtarla filtrelenir; kör koşularda hafıza
okuması provenance etiketi taşır (`source_run`), böylece "kör" iddiası
denetlenebilir hâle gelir. Paylaşımlı (hedefsiz) hafıza keşif kanıtı
sayılmaz.

## Uygulama dilimleri

| Dilim | İçerik | Kapanış ölçütü |
|---|---|---|
| 1 ✅ | `target_identity` + `hypothesis_ledger` + `brain.py hypotheses` CLI | Birim testler yeşil; mevcut testler kırılmaz (878 passed) |
| 2 ✅ | Defterin `access` fazına bağlanması: `next --workdir`, özeti deftere işler, vektör claim eder, CONFIRMED'a kadar access döngüsü | Zincir testi: blocked vektör → rotasyon → CONFIRMED → zincir ilerler |
| 3 | Bulgu kanıt-paketi fallback + koşulsuz rapor fazı | CONFIRMED, depo kapalıyken bile paketlenir (test) |
| 4 | Hafıza hedef-kapsamı + provenance | Kör-koşu testi: başka hedefin kaydı sızmaz |

## Kapsam dışı
- Kapı (policy engine) güvenlik kuralları değişmez; derinleşme kapıyı
  baypas eden hiçbir yol eklemez.
- Yeni MCP aracı yok; mevcut çekirdek envanter yeterli.
- Tam otonomi yok: rotasyon ve kapanış kodda, hipotez üretimi LLM'de kalır.

## Başarı tanımı
Bir lab koşusunda: en az iki vektör defter üzerinden rotasyonla denenir,
CONFIRMED bulgu depoya veya kanıt paketine mühürlenir, rapor fazı koşu
içinde tamamlanır. Bu üçü aynı koşuda görülmeden mimari "derinleşti"
sayılmaz.
