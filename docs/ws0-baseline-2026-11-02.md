# WS0 Baz Raporu — Pentest Güçlendirme Planı

> Tarih: 2026-11-02 · İş paketi: WS0 (baz kilidi) · Kod değişikliği: **yok** (yalnız ölçüm)
> Baz: `HEAD e839e23` üzerindeki çalışma ağacı. Ortam: `CCO_GRAPH_BACKEND=networkx`, lab koşuları geçici `CCO_HOME` ile.

## 1. Çalışma Ağacı Envanteri

- Durum: 96 değişmiş + 1 silinmiş (`skills~master`) + 102 takipsiz dosya.
- Takipsiz dağılım: 39 test, 20 belge (2'si bu oturumda üretilen mimari taslaklar), 18 `.codex` (program kapsam/politika varyantları), 11 `mcp-servers` modülü, 9 `scripts`, 3 `.agents` planı, 2 `config`.
- Araç sayımı (canlı AST): 16 sunucu, 291 araç. Eski belgelerdeki 227/14 sayıları geçersizdir.

## 2. Takipsiz Testler (39 dosya)

Komut: takipsiz test dosyalarının tamamı tek pakette koşuldu.

**Sonuç: 505 passed, 32 skipped, 0 failed (97 sn).**

Atlananlar beklenen kapılardır: opt-in HTTP/Chromium labı (`CCO_RUN_WIRE_LAB=1` ister) ve Playwright/Chromium yokluğu. Takipsiz yetenek (gap-closure, OOB, kimlik doğrulamalı API, oturum kasası, kampanya köprüsü) bu pakette yeşildir.

## 3. Tam Test Paketi

Komut: `CCO_GRAPH_BACKEND=networkx python3 -m pytest tests -q`

**Sonuç: 1604 passed, 5 failed, 33 skipped (655 sn).**

Başarısızlar ve ilk sınıflandırma:

- [test_lab_integration.py](/root/hackagent-opencode/tests/test_lab_integration.py) (2 test) — §4'teki lab düşüşünün aynası; aynı kök neden.
- [test_phase5_authz_upload_jwt.py:96](/root/hackagent-opencode/tests/test_phase5_authz_upload_jwt.py) — döngü içi BOLA doğrulaması `CONFIRMED` yerine `INCONCLUSIVE` verdi. Gerçek işlevsel açık adayı; WS4 öncesi triyaj gerekir.
- [test_carriers_blind_csrf.py:103](/root/hackagent-opencode/tests/test_carriers_blind_csrf.py) — kanarya taşıyıcılarında `header` konumu eksik (`{path, header} <= {path}`). Gerçek işlevsel açık adayı.
- [test_campaign_worker.py](/root/hackagent-opencode/tests/test_campaign_worker.py) (`test_local_mcp_resource_limits_and_required_cgroup`) — zorunlu cgroup altında alt süreç 5 sn zaman aşımı. Ortam/zamanlama duyarlı; kod regresyonu olduğu kanıtlanmadı, ayrı triyaj gerekir.

Bu beşli WS0'da düzeltilmez; bazın parçası olarak dondurulur. Sonraki fazlar bu listeyi büyütmemekle yükümlüdür.

## 4. Lab Doğrulama: 42/48 (Regresyon Değil, Ortam Bağlaşımı)

Komut: `python3 scripts/lab-validate.py --skip-rag --quiet --json`

**Sonuç: 42 passed / 48, `all_passed: false`. Negatif kontrol ayrı koşuda 6/6 temiz, FP oranı 0.0.**

Düşen 6 kontrol tek zincirden düşer: `web loop ok`, `fuzz XSS likely`, `fuzz SQLi likely`, `fuzz params probed`, `web loop confirmed`, `coverage increased after fuzz`.

### Kök neden (deterministik yeniden üretimle doğrulandı)

1. Aktif kapsam dosyası [scope.json](/root/hackagent-opencode/.codex/scope.json) içinde `rules.rate_limit: "conservative"` tanımlı.
2. Program politikasında `rate_limit_profile` yoksa [policy_engine.py:1090-1091](/root/hackagent-opencode/scripts/policy_engine.py) kapsam kuralını politika profiline taşır; `_rate_limit_for` muhafazakâr tabloyu seçer: **araç başına 20 çağrı/dk**.
3. Hunter'ın tel isteklerinin tamamı `hunter_run_web_loop` araç adıyla ücretlendirilir. `run_web_loop` keşif sırasında 20 isteğe ulaşır ve `blocked_rate_limit` ile durur (`requests_authorized=20`, `stopped: run stopped: policy gate blocked_rate_limit`).
4. Fuzz aşaması hiç çalışamaz; XSS/SQLi olasılıkları, doğrulanmış bulgu ve coverage artışı zincirleme düşer.

Doğrudan validator kontrolleri (SQLi/XSS/SSRF/IDOR/auth-bypass onay + güvenli ikizlerde onaylamama çiftleri) bu koşuda **geçti**; doğrulama oracle'ları kırık değildir. Kırılan, lab koşusunun gerçek program kapsamının hız profilini miras almasıdır.

Karşılaştırma notu: 17 Ekim skor kartındaki 48/48, `fbdbd4b` + o günkü kapsam dosyasıyla alınmıştır; bugünkü kapsam 27 Ekim'de değişmiştir. İki sayı aynı baz değildir. Hız sınırını aşmak veya profili labda sessizce gevşetmek çözüm değildir; doğru düzeltme WS1'de lab koşusunun kendi izole kapsam/politikasıyla koşmasıdır (WS0 düzeltme yapmaz, kararı kaydeder).

Yeniden üretim betiği: `/tmp/ws0_probe.py` (repo dışı, ölçüm amaçlı).

## 5. Diğer Kalite Kapıları

- Ruff (CI dar ratchet kapsamı): temiz.
- Repo düzeni (`check_repo_layout.py`): temiz.
- `node --check .opencode/plugins/security-gate.js`: temiz.
- Governance audit + worker soak + release list dumanları: koşuldu, bloklayan bulgu yok.
- **mypy yerel ortamda kurulu değil**; CI kapısı yerelde doğrulanamadı (CI kurup koşar). Bu bir baz boşluğudur, yeşil sayılmaz.

## 6. Dondurulmuş Baz Sayıları

- Takipsiz testler: 505/0/32 (geçti/başarısız/atlandı)
- Tam paket: 1604/5/33 (655 sn)
- Lab: 42/48; negatif kontrol FP: 0/6
- Filo: 16 sunucu / 291 araç
- Bilinen kırmızı liste: §3'teki 5 test + §4 kök nedeni

WS1 ve sonrası her faz, bu sayıları baz alır: tam paket kırmızı listesi büyümez, lab 48/48 olmadan "iyileşme" ilan edilmez, recall iddiası kör lab (WS1) kurulmadan yapılmaz.

## 7. Commit / Atılma Kararı (Kullanıcı Kararı Bekler)

WS0 düzeltme ve commit yapmaz. Seçenekler:

- **A — Tek batch commit:** 102 takipsiz + 96 değişmiş dosya tek seferde. Hızlı ama lab kırmızısı ve iki işlevsel açık adayıyla birlikte tarihe geçer; geri alma zor.
- **B — Önce lab bağlaşımını düzelt, sonra dilimli commit (önerilen):** WS1 başında lab koşusu izole kapsamla 48/48 yapılır; ardından iş akışlarına göre (kapı, hunter/validator, kampanya, belgeler/testler) ayrı commit'ler. İnceleme edilebilir, regresyon izi sürülebilir.
- **C — Atılma:** Takipsiz batch silinir. 505 yeşil testle kanıtlanmış yetenek (kör keşif, OOB, oturum kasası, kampanya köprüsü) kaybolur; önerilmez.

Öneri B'dir ancak commit yetkilendirmesi açıkça verilmeden hiçbir seçenek uygulanmaz.

## 8. WS0 Çıkış Durumu

Tamamlanan: envanter, takipsiz test koşusu, tam paket, lab + negatif kontrol, kök neden kanıtı, baz dondurma. Bekleyen tek madde: §7 kararı. Karar verilince WS1 (kör ölçüm laboratuvarı) başlar; lab bağlaşımı düzeltmesi WS1'in ilk işidir.

**B kararı sonrası çözüm notu (aynı gün):** Kullanıcı B seçeneğini seçti. [lab-validate.py](/root/hackagent-opencode/scripts/lab-validate.py) artık repo kapsam/politikasını miras almıyor: geçici `CCO_HOME` içine izole loopback kapsamı + lab profili yazılıyor (`CCO_SCOPE_FILE`/`CCO_PROGRAM_POLICY_FILE`). İkinci bağlaşım da aynı düzeltmede izole edildi: tek koşu içi deterministik fuzz, takılma dedektörünü sahte biçimde tetiklediği için labda `CCO_STUCK_THRESHOLD` yükseltiliyor (dedektörün kendi testleri ayrıca koşar; bu çakışma WS5/WS9 iş listesine girdi). Sonuç: **lab 48/48, `test_lab_integration` yeşil, negatif kontrol FP 0.0 korundu.** Ardından çalışma ağacı iş akışına göre dilimli commit'lenmiştir; `opencode.json` (sağlayıcı anahtar literalleri içerir, HEAD'de de mevcut) ve programa özel takipsiz kapsam dosyaları bilinçli olarak commit dışında bırakılmıştır.
