# Dokümantasyon dizini

Başlangıç noktası [English README](../README.md) · [Türkçe README](../README.tr.md). Bu dizin güncel
**`cco-agent agentic` (Sharded ReAct)** mimarisini, operasyon/güvenlik rehberlerini ve
eski Python Engine / P5–P9 sözleşme belgelerini içerir.

## Güncel rehberler

| Konu | Belge |
| --- | --- |
| Güncel `agentic` Mimarisi (`cco-agent agentic` / Sharded ReAct Motoru) | [Mimari](architecture.md) |
| Operasyon, güvenlik ve kampanyalar | [Operasyon](operations.md) |
| Tekrarlanabilir lab ve doğrulama sonuçları | [Benchmark ve Doğrulama Kartı](benchmark-scorecard.md) |
| MCP araç kataloğu (eski Python Engine / `mcp-servers/*`) | [MCP referansı](mcp-reference.md) |
| Eski Python Engine durumu ve eksikler (E1–E9) | [PYTHON_ENGINE_GAPS.md](PYTHON_ENGINE_GAPS.md) |

## P5–P9 yetenek ve sözleşme belgeleri (eski Python Engine)

| Aşama | Belge |
| --- | --- |
| P5: Observation-level hypothesis queue | [p5-hypothesis-queue.md](p5-hypothesis-queue.md) |
| P6: Observation-bound web experiments | [p6-web-experiments.md](p6-web-experiments.md) |
| P7: Observation-bound business logic | [p7-business-logic.md](p7-business-logic.md) |
| P8: Evidence-bound chaining | [p8-chaining.md](p8-chaining.md) |
| P9: Agent integration ve operatör sözleşmeleri | [p9-agent-integration.md](p9-agent-integration.md) |

`CLAUDE.md`, `AGENTS.md` ve `.claude/skills/` (`skills` symlink'i ile) güncel
çalışma sınırları ve metodoloji kataloğu olarak korunur.
