# Brain Routing — Beyin/Worker Rolleri ve Maliyet Dengesi

## Roller
1. Worker (varsayılan): `mimo-v2.6-flash` — recon, tool çalıştırma, dosya işleri, taslak.
2. Ana Beyin / Yönetici (`kalibounty` / `brainstorm`): `mimo-v2.6-pro` — plan onayı, strateji, worker orkestrasyonu, otonom döngü yönetimi.
3. İkinci Görüş Beyni: `glm-5.3` (`brain_glm`) — plan onayı, alternatif hipotez, PoC öncesi eleştiri, rapor taslağı.
4. Hakem & Şüpheci Denetçi: `gpt-6.1-sol` (`brain_sol`) — anlaşmazlıklarda son söz; AYRICA tüm bulgu ve raporlarda LLM abartılarını ve halüsinasyonlarını eleyen, triager itirazlarını peşinen simüle eden ZORUNLU son onay kapısı (Reality-Check Gate).

## Fırtına ve Doğrulama Protokolü
1. İki Beyin Tartışması: primary (pro) ve `brain_glm` strateji, plan ve PoC aşamalarında paralel değerlendirir.
2. ZORUNLU Şüpheci Denetim (Reality-Check Gate): Bir bulgu doğrulandıktan (validated) ve rapor taslağı hazırlandıktan sonra, maintainer/triager'a gitmeden önce **MUTLAKA `brain_sol` (gpt-6.1-sol)** subagent'ına gönderilir:
   - Teknik iddialar abartılı mı? (Örn. Framework'ün davranışı, log mekanizması, gerçek etki).
   - Triager bunu "Informative / Best Practice" diye kapatıp Signal'ımızı yakabilir mi?
   - Gerçek şiddet (severity) ne olmalı? Dili nasıl sadeleştirilmeli?
3. Hakemlik: İki beyin anlaşamazsa yine `brain_sol` nihai hükmü verir.
4. Kural: `brain_sol` onayı (`REALITY_CHECK: APPROVED` veya `DOWNGRADE_BEFORE_SUBMIT`) almamış hiçbir bulgu "submit-ready" ilan edilemez.

## Maliyet Frenleri
1. Beyinler günlük işe karışmaz; worker takılırsa veya güven düşükse yükseltilir.
2. Beyin output'u kısa olur: madde listesi, destan değil (`textVerbosity: low`).
3. Plan bir kez üretilir, tekrar kullanılır; her adıma yeniden beyin çağrılmaz.

## Özet Kuralı
1. Ham tool output'u dosyaya yazılır, sohbete sadece şemalı özet + dosya yolu döner.
2. Şüphe varsa özetleme, ham veriyi yönlendir.
3. Kritik bulgularda ham veri kısaltılmadan iletilir.

## Kapatma Kapısı (Zorunlu)
1. Bir yolu "kapalı/ölü" ilan etmeden önce varyasyon matrisini tamamla: farklı metod (GET + HEAD/OPTIONS), farklı User-Agent, farklı header.
2. Kapatmadan önce kapıya sor: `python3 scripts/policy_gate_cli.py path-close --url <URL>` — `allowed: false` ise listedeki eksikleri tamamla.
3. Kapı, gate'den geçen gerçek istekleri sayar; denemediğin varyasyonu iddia edemezsin. 403 yolu kapatmaz, varyasyon ister.

## Hedef Takibi (Geri Zincirleme)
1. Recon sonrası TEK hedef koy: en yetkili endpoint + gereksinimleri (`campaign goal-set`).
2. Her parti, `unmet` bir gereksinime hizmet etmeli (`campaign show` → checkpoint.goal).
3. Öğrendikçe güncelle (`campaign goal-update ... met|blocked --evidence <yol>`).
4. Raporlanan bulgu hedefi otomatik kapatmaz; kalan gereksinimler tekrar kontrol edilir.

## Stall Gözcüsü (Otomatik)
1. Task sonucu ilerleme içermiyorsa `{"no_progress": true}` dön; boş sonuç worker tarafından otomatik işaretlenir.
2. Üst üste 3 ilerlemesiz task = stall → gözcü kuyruğa `brainstorm` task'ı ekler (30 dk cooldown, kampanya başına max 5).
3. Brainstorm task'ı worker tarafından otomatik çalışır (`reasoning_next_best_action`, takılan hedeften türetilir) ve yeni yön önerir.
4. Periyodik kontrol: `./scripts/opencode-cco.sh campaign check-stall <campaign_id> --enqueue` (cron ile 10 dk'da bir önerilir).
