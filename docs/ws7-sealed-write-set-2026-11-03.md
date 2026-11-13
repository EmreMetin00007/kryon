# WS7 Mühürlü Yazma Kümesi — Uygulama ve Ölçüm

> Tarih: 2026-11-03 · İş paketi: Faz 4 / Scoped CRUD (Create-Own-Teardown) · Tasarım: [tradeoff §4 Faz 4](/root/hackagent-opencode/docs/architecture-tradeoff-review-2026-11-02.md)
> İlke: genel metot izni yok; yazma yalnız mühürlü test nesnesine, koşu kimliğiyle, süre dolmadan.

## 1. Uygulanan

- [write_set.py](/root/hackagent-opencode/scripts/write_set.py): mühür defteri. Yeri `CCO_HOME/write_set.db` — `audit.db` değil (denetim günlüğü salt-eklemeli kalır). Yaşam döngüsü: seal → mutation → torn_down/expired; görev başına oluşturma tavanı; kimlik parmak izi yalnız hash.
- [policy_engine.py](/root/hackagent-opencode/scripts/policy_engine.py): `write_set` politika bloğu (fail-closed; bilinmeyen anahtar reddi). Etkin programda tel üstündeki PUT/PATCH/DELETE, nesne mühürlü + arayan koşu kimliği + süre geçerliyse geçer ve metot yasağını da aşar; değilse `blocked_unsealed_mutation`. Blok kapalıyken davranış değişmez.
- Lab: blind_lab'a yazılabilir `/docs` (zafiyetli) ve `/safe/docs` (güvenli) ikizleri. Kör okuma ölçümü değişmedi (1/8, FP 0).

## 2. Ölçüm ([write-validate.py](/root/hackagent-opencode/scripts/write-validate.py))

| Kontrol | Sonuç |
|---|---|
| Mühürlü nesneye çapraz yazma kapıdan geçti | evet |
| Yazma-BOLA (öbür kimlik başlığı değiştirdi) | **CONFIRMED** (delta aracı değişimi işaretledi) |
| Mass assignment (`role: admin` enjeksiyonu) | **CONFIRMED** |
| Güvenli ikiz (hedef reddetti, delta temiz) | değişmedi |
| Mühürsüz nesneye yazma | kapıda `blocked_unsealed_mutation`, istek çıkmadı |

Öncesi/sonrası anlık görüntüler `kalibounty-delta` ile karşılaştırıldı; değişim hükmü araç çıktısı + tekrar okuma ile verildi.

## 3. Testler ve regresyon

- tests/test_write_set.py: defter yaşam döngüsü, görev tavanı, kapı izin/red matrisi, politika fail-closed (önce kırmızı).
- Regresyon: write/policy/member-login/wire-budget/authenticated/blind/kapı paketleri 244 test yeşil; kör baz ölçümü aynı (1/8, FP 0/8).

## 4. Kalan / dürüst sınır

- Mühürleme bugün ölçüm ve test akışında açık çağrıyla yapılıyor; ajanın (LLM) oluştur→mühürle→yaz akışını kendi kendine koşması ve LLM hattı yazma ölçümü sonraki iş.
- Oluşturma sonrası otomatik mühürleme (yanıt kimliğini kapıda yakalama) yok; bilinçli olarak dışarıda bırakıldı.
- DELETE pratikte yalnız mühürlü nesnede ve politika izin verirse; gerçek hedefte yazma bu fazın konusu değil, kanıt labdadır.
- Politika kuralı sapması: `write_set` yeni üst bloktur; yazma için genişletilebilecek mevcut blok olmadığından fail-closed yeni blok tercih edildi ve burada kayda geçti.
