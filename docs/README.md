# Dokümantasyon Dizini

Başlangıç noktası: [English README](../README.md) · [Türkçe README](../README.tr.md)

Bu dizin, tek mimarili **`cco-agent agentic` (Sharded ReAct Motoru + `kryon_core`)** çalışma zamanına ait güncel belgeleri ve yapılandırma referanslarını toplar.

## Güncel Belgeler ve Yapılandırma Referansları

| Konu | Belge / Dosya |
| :--- | :--- |
| Sistem Mimarisi, Modül Haritası ve Veri Sınırları | [docs/architecture.md](architecture.md) |
| Proje Özeti ve Hızlı Başlangıç (EN) | [README.md](../README.md) |
| Proje Özeti ve Hızlı Başlangıç (TR) | [README.tr.md](../README.tr.md) |
| Ajan Çalışma Kuralları, Kapsam ve Kanıt İlkeleri | [AGENTS.md](../AGENTS.md) |
| Dış LLM Operatör Rehberi (`plan`, `run`, `presets`, `status`) | [docs/llm-operator-guide.md](llm-operator-guide.md) |
| LLM Sağlayıcı Yapılandırma Şeması (`cco-llm/1`) | [config/llm.example.json](../config/llm.example.json) |
| Çalıştırma Yapılandırma Şablonu (`cco-run/1`) | [config/run.example.json](../config/run.example.json) |
| Program Politikası Şablonu | [config/bounty-program-policy.json](../config/bounty-program-policy.json) |

> **Arşiv notu:** Emekliye ayrılan v1 Python Engine (`PythonSolver`, `Brain`, `CampaignRuntime`), 16 MCP sunucusu, P5–P9 belgeleri ve `skills/` kataloğu kalıcı olarak `git tag legacy-v1-archive` etiketinde korunmaktadır.
