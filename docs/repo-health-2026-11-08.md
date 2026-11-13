# Repo sağlık kontrolü ve biriken değişikliklerin commit'i — 2026-11-08

İmzalı native/Python ajan akışları, bağımsız holdout altyapısı ve tamamlanan
Python erişim kontrolü kapsamı bağımlılıklarıyla birlikte commit'e alındı.
Yerel kapsam/profil dosyaları, kişisel OpenCode izin değişiklikleri, görüşme
notları ve önceden silinmiş `skills~master` çalışma alanında korundu.
Graphify çıktıları sürümlendi; cache ve makineye özgü durum dosyaları gitignore'a eklendi.

Sağlık denetimi eski senaryolarda eksik erişim kuralı/marker tanımlarını ve
validator araç sayısının 26 yerine 27 olması gerektiğini ortaya çıkardı.
Kampanya devamı ile salt okunur kanıt denetiminde `vuln_class` bağlamdan
çıkarıldığı için geçerli kanıtlar reddediliyordu; tam bağlam karşılaştırması
korunarak alan geri eklendi. Safe redirect laboratuvarı tarayıcıların ters
bölü işaretini normalleştirmesini dikkate alır ve geçerli terminal sayfayı sunar.
SQLi aday yönlendirme kontrolü, hafif oracle'ın LIKELY kararı yerine gerçek
validation kuyruğunu inceler; doğrulama ayrı kontrol edilir. Fuzz bütçesi korunur.

Yönetişim tarayıcısı yalnız tam `{env:VARIABLE_NAME}` referansını sır değerinden
ayırır; aynı satırdaki gerçek literal ve bozuk referanslar testlerde yakalanır.
Mypy CI'da adı verilen iki çekirdek dosyayı denetler; çift paket/standalone
adlarıyla yüklenen geçişli runtime modülleri bu dar tip kapısına dahil değildir.
Daha geniş tip denemesinin tanıları çalışma dizininde korunmuştur.

| Kontrol | Sonuç |
| --- | --- |
| Codex/MCP/DB sağlık kontrolü | 7/7 |
| Birim ve çevrimdışı testler | 2506 başarılı, 37 atlanan; 28 integration deselected |
| Ruff, Mypy core, bağımlılık kilidi, repo düzeni, JS sözdizimi | Geçti |
| Gerçek loopback laboratuvarı | 48/48 |
| Negatif kontroller | 6/6; yanlış pozitif 0, belirsiz 0 |
| Worker-soak | 16 görev, 4 worker; bütün invariantlar geçti |
| Yönetişim | Yüksek 0, orta 33; orta bulgular kayıtta korunur |
| Git nesne bağlantıları | Bozulma yok |
| Graphify | AST-only; model çağrısı yok |

Commit adaylarının gizli bilgi taramasında şema sabitleri ve açıkça sentetik
test değerleri incelendi; gerçek credential bulunmadı. Credential dosyaları
okunmadı ve commit'e alınmadı. Tarama ağ doğrulaması veya entropy taraması yapmaz.
Yeni uzak sağlayıcı/ücretli koşu başlatılmadı; eski çalışma kanıtları korundu.

[Toplu sağlık kanıtı](/tmp/cco-work/accesscoverage-commit-health-verification.json),
[son JUnit](/tmp/cco-work/accesscoverage-commit-health-unit-complete.xml),
[önceki erişim kontrolü kabul kanıtı](/tmp/cco-work/accesscoverage-step1-verification.json).
