# Dokümantasyon dizini

Başlangıç noktası [ana README](../README.md). Güncel kullanım, özellik notları ve
eski çalışma kayıtları aşağıda ayrı gösterilir. Tarihli belgelerdeki sonuçlar
belgenin yazıldığı dilime aittir; bugün çalışan kodun tamamını temsil etmez.

## Güncel rehberler

| Konu | Belge |
| --- | --- |
| Python motoru durumu ve eksikler (E1–E9) | [PYTHON_ENGINE_GAPS.md](PYTHON_ENGINE_GAPS.md) |
| Bileşenler ve veri sınırları | [Mimari](architecture.md) |
| Operasyon, güvenlik ve kampanyalar | [Operasyon](operations.md) |
| MCP araç kataloğu | [MCP referansı](mcp-reference.md) |
| Sonuçları yeniden üretme | [Benchmark skor kartı](benchmark-scorecard.md) |
| Uygulanan ve kalan repo temizliği | [Temizlik planı ve durum](repo-cleanup-plan-2026-11-02.md) |

## Mevcut özelliklerin teknik notları

Bu belgelerin yolları korunur; operasyon ve MCP rehberlerinden bağlantı alırlar.

| Konu | Belge |
| --- | --- |
| Ayrıntılı sistem taslağı | [Güncel sistem taslağı](system-architecture-current-2026-11-02.md) |
| Görsel kaynak eşlemesi | [Mermaid görünümleri](system-architecture-mermaid.md) |
| Oturumlu Web/API | [Kimlik, nesne ve oturum](authenticated-web-api-2026-10-30.md) |
| Aday üretimi ve geri bildirim kuyruğu | [P4/P5/P6 ilk dilim](candidate-feedback-2026-11-03.md) |
| Kalıcı test kaynağı ve campaign devamı | [P4/P5/P6 kaynak bağlama](test-resource-resume-2026-11-04.md) |
| Negatif kontrollerin imzalı kanıtı | [Negatif kapsam doğrulaması](negative-controls-2026-11-04.md) |
| Kapsam boşluğundan kampanya görevine | [Campaign bridge](coverage-campaign-bridge-2026-10-31.md) |
| Ortak HTTP bütçesi | [Wire budget](shared-wire-budget-2026-10-31.md) |
| İmzalı defter | [Ledger bütünlüğü](ledger-integrity-2026-10-29.md) |
| OOB kolektör kaynağı | [Kolektör doğrulaması](oob-collector-provenance-2026-10-31.md) |
| HTTP ve Chromium kontrol kaydı | [Lab sonuçları](http-chromium-lab-2026-10-31.md) |
| Gerçek HTTP/Chromium campaign kabulü | [37/37 kabul](http-chromium-acceptance-2026-11-04.md) |
| XSS/traversal kayıpları ve ek hesap matrisi | [Kayıp analizi](http-chromium-loss-analysis-2026-11-04.md) |
| XSS execution ve dizin sınırı sonrası gerçek kabul | [Beş seed 8/8 yeniden kabul](http-chromium-reacceptance-2026-11-04.md) |
| Native OpenCode ajan kabulünün hazırlığı | [Koşu sözleşmesi ve ortam kontrolü](full-agent-readiness-2026-11-04.md) |
| Ajan canlı kabul ve holdout kayıtları | [İmzalı akış ve kapsam](full-agent-live-acceptance-2026-11-05.md) |
| Repo sağlığı ve commit doğrulaması | [Sağlık kaydı](repo-health-2026-11-08.md) |

## Tasarım, inceleme ve açık iş kayıtları

Bu kayıtlar otomatik olarak tamamlanmış sayılmaz. Açık maddelerin bugünkü kod ve
testlerle karşılaştırılması gerekir. Güncel Python motoru durumu için
[PYTHON_ENGINE_GAPS.md](PYTHON_ENGINE_GAPS.md) esas alınır.

- [Mimari derinleştirme](architecture-deepening.md)
- [Mimari ödünleşim incelemesi](architecture-tradeoff-review-2026-11-02.md)
- [Web/API pentest geliştirme planı](web-api-pentest-improvement-plan-2026-11-03.md)
- [Proje incelemesi](project-review-2026-10-29.md)
- [Pentest yetenek incelemesi](pentest-capability-review-2026-10-29.md)
- [P0 kapatma dilimi](p0-gap-closure-2026-10-29.md)
- [Eksik kapatma ilerlemesi](gap-closure-progress-2026-10-30.md)
- [Kalan pentest işleri](pentest-remaining-work-2026-10-30.md)
- [Kör lab şartnamesi](blind-pentest-lab-spec-2026-10-30.md)

## Tarihsel ve uyumluluk kaynakları

- [Temizlik öncesi Claude Code README](history/claude-code-readme.md)
- [Temizlik öncesi mimari anlatımı](history/architecture-before-cleanup.md)
- `scripts/cco-profile.sh` ve `scripts/token-estimate.py`: eski Claude Code
  profil yardımcıları; güncel `cco-agent` Python başlatıcısının yerine geçmez.
- `rules/brain-routing.md`: emekli agent adları içeren tarihsel yönlendirme;
  güncel çalışma kuralları `AGENTS.md` içindedir.

`CLAUDE.md` ve `.claude/skills/` (`skills` symlink'i ile) mevcut yapı tarafından
metodoloji/skill kataloğu olarak kullanılır. Tarihsel belgeler ile çalışan
kaynaklar karıştırılmamalıdır.
