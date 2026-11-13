# Temizlik öncesi mimari anlatımı

2 Kasım 2026 temizliği öncesindeki belge korunmuştur. Sayılar, model seçimi ve
kurulum anlatımı tarihsel referanstır. Güncel rehber: [ana README](../../README.md)
ve [dokümantasyon dizini](../README.md).

---

# Mimari

Güncel kaynak ağacının altı Mermaid görünümü ve kaynak eşlemesi:
[Sistem mimarisi — Mermaid](../system-architecture-mermaid.md).
Aşağıdaki ASCII şema ve model routing bölümü tarihsel referanstır; güncel model
seçimi, güven sınırları ve koşullu entegrasyonlar yeni belgede açıklanır.

> README'den taşındı: mimari diyagram, model routing, dosya yapısı.

## 🏗️ Mimari

```
┌─────────────────────────────────────────────┐
│         Kullanıcı (Kali Terminal)           │
│         opencode (birincil orkestratör)     │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│         OpenCode (birincil)                 │
│  • Orkestrasyon, OODA loop, tool routing    │
│  • CLAUDE.md → metodoloji (AGENTS.md çevirir)│
│  • Claude Code/Codex: ikincil çeviri katmanı │
└──────┬──────────────┬───────────────────────┘
       │              │
       ▼              ▼
┌────────────┐  ┌─────────────────────────────────┐
│ OpenRouter │  │      MCP Server'lar (16)        │
│   API      │  │  ┌──────────────────────────┐   │
│            │  │  │ mcp-kali-tools  (85 tool) │   │
│ Session:   │  │  │ mcp-web-advanced (27 tool)│   │
│ qwen3-next │  │  │ mcp-ctf-platform (14 tool)│   │
│ 80b-a3b    │  │  │ mcp-validator   (15 tool) │   │
│            │  │  │ mcp-ad-tools    (12 tool) │   │
│ Tool içi:  │  │  │ mcp-memory-srv  (15 tool) │   │
│ qwen3.6+,  │  │  │ mcp-container   (10 tool) │   │
│ hermes-405 │  │  │ mcp-osint-tools  (9 tool) │   │
│            │  │  │ mcp-telemetry   (10 tool) │   │
│            │  │  │ mcp-browser     (10 tool) │   │
│            │  │  │ mcp-reasoning   (19 tool) │   │
│            │  │  │ mcp-rag-engine   (7 tool) │   │
│            │  │  │ mcp-hunter      (15 tool) │   │
│            │  │  │ mcp-llm-security (6 tool) │   │
│            │  │  │ mcp-agent-browse (2)      │   │
│            │  │  │ mcp-otp          (1)      │   │
│            │  │  └──────────────────────────┘   │
└────────────┘  └─────────────────────────────────┘
```

### Model Routing

> ⚠️ Claude Code runtime'da modeli ANLIK değiştiremez — tek session = tek model.
> Model routing MCP tool katmanında çözüldü.

- **Orkestratör** (session): `qwen/qwen3-next-80b-a3b-instruct` (non-thinking,
  tool use uyumlu, `ANTHROPIC_DEFAULT_SONNET_MODEL`)
- **Derin analiz:** Claude Code `qwen_analyze()` çağırır → tool içi kod
  OpenRouter'a `qwen/qwen3.6-plus` ile ayrı istek atar
- **Exploit PoC:** Claude Code `generate_exploit_poc()` çağırır → tool içi kod
  `nousresearch/hermes-4-405b`'e istek atar
- **Paralel analiz + PoC:** `parallel_llm_analyze()` — ThreadPoolExecutor ile
  Qwen ve Hermes eş zamanlı

Tüm modeller `.env` üzerinden override edilebilir:
```
CCO_ANALYZE_MODEL=...
CCO_EXPLOIT_MODEL=...
CCO_FAST_MODEL=...
CCO_CODE_MODEL=...
```

---

## 📁 Dosya Yapısı

```
cco/
├── CLAUDE.md                    ← ANA DOSYA — hacker persona + metodoloji
├── .env.example                 ← OpenRouter config şablonu
├── .env                         ← Gerçek key (gitignore'da)
├── install-cco.sh               ← Tek komut kurulum
├── README.md
│
├── mcp-servers/                 ← 16 MCP server (289 tool; tek kaynak: scripts/tool_counts.py)
│   ├── mcp-kali-tools/          ← 85 güvenlik aracı + LLM tools
│   ├── mcp-web-advanced/        ← 27 modern web/API saldırı aracı
│   ├── mcp-ctf-platform/        ← 14 — CTFd/HTB/THM entegrasyonu
│   ├── mcp-validator/           ← 15 — DETERMİNİSTİK exploit doğrulama (XBOW-tarzı)
│   ├── mcp-ad-tools/            ← 12 — Active Directory / Kerberos / SMB
│   ├── mcp-memory-server/       ← 15 — NetworkX Knowledge Graph + SQLite
│   ├── mcp-container-tools/     ← 10 — Docker/K8s container security
│   ├── mcp-osint-tools/         ← 9 — pasif OSINT + password spraying
│   ├── mcp-telemetry/           ← 10 — maliyet + call tracking
│   ├── mcp-browser/             ← 10 — Playwright client-side recon (opsiyonel)
│   ├── mcp-reasoning/           ← 19 — BEYİN: deep_think (recon→zincir→doğrula→skorla) + plan + Reflexion + öğrenme + kill-chain + payload-evo + exploitability + skill-router + WAF/origin-bypass
│   ├── mcp-hunter/              ← 15 🆕 BUG-HUNTING ZEKASI: predictive vuln intel + access-control (BOLA/BFLA/IDOR) matris+oracle + business-logic abuse + variant analizi + coverage + auto-fanout (kali-tools köprüsü) + RAG enrichment (CVE PoC)
│   ├── mcp-rag-engine/          ← 7 — ChromaDB CVE/exploit/writeup search
│   └── mcp-llm-security/        ← 6 — OWASP LLM Top 10 (prompt inj./jailbreak)
│
├── .claude/                     ← Claude Code native konfigürasyon
│   ├── commands/                ← Custom slash command'lar
│   │   ├── pwn.md               ←   /pwn <hedef> — otonom recon→exploit zinciri
│   │   └── bugbounty.md         ←   /bugbounty <hedef> — bug bounty kampanyası
│   └── skills/                  ← 23 Agent Skill (YAML frontmatter ile)
│       ├── recon-enumeration/  attack-surface-mapping/  llm-security/
│       ├── web-exploit/  web-advanced/  advanced-api-sec/
│       ├── exploit-validation/ ← deterministik doğrulama metodolojisi
│       ├── access-control-hunting/ ← 🆕 BOLA/BFLA/IDOR + iş mantığı (en çok ödeyen sınıflar)
│       ├── deep-reasoning/     ← derin düşünme: plan + reflexion + öğrenme (beyin)
│       ├── binary-pwn/  crypto-forensics/  ctf-solver/
│       ├── report-generator/  source-code-review/
│       ├── active-directory/  windows-exploitation/
│       ├── post-exploitation/  stealth-evasion/  payload-generation/
│       ├── cloud-exploitation/  container-security/
│       └── mobile-security/  osint-password-spraying/
│
├── skills → .claude/skills      ← Geriye uyumluluk için symlink
│
├── workflows/                   ← Metodoloji dokümanları
│   ├── recon-to-exploit-workflow.md ← /pwn'in otonom zinciri
│   ├── bug-bounty-workflow.md
│   ├── ctf-workflow.md
│   ├── modern-web-workflow.md
│   ├── benchmark-workflow.md    ← CCO'yu XBOW benchmark'ına karşı çalıştır
│   └── supervisor-workflow.md
│
├── rules/                       ← Güvenlik kuralları
│   ├── scope-guard.md
│   └── safety-rules.md
│
├── tests/                       ← pytest smoke/regresyon suite
│   ├── conftest.py
│   ├── test_mcp_servers.py      ← 16 server import + 289 tool sayım guard
│   ├── test_validator.py        ← deterministik validator oracle testleri
│   ├── test_reasoning.py        ← reasoning beyni (EV/öğrenme/plan) testleri
│   └── test_xbow_benchmark.py   ← benchmark harness (mock) testleri
│
├── scripts/                     ← Yardımcılar
│   ├── cco-profile.sh           ← MCP profil değiştir (TOKEN TASARRUFU)
│   ├── token-estimate.py        ← Profil token maliyeti tablosu
│   ├── xbow_benchmark.py        ← XBOW 104-challenge benchmark harness
│   ├── xbow_bench_fixtures/     ← offline mock benchmark seti (harness testi)
│   ├── rag-bootstrap.py/.sh     ← RAG bilgi tabanı doldurma
│   ├── recon_daemon.py          ← (kali-tools'a wired)
│   ├── swarm_orchestrator.py    ← (kali-tools'a wired)
│   ├── attack_planner.py        ← (standalone CLI — orphan, opsiyonel)
│   ├── budget-check.sh          ← OpenRouter bakiye sorgu
│   └── model-list.sh            ← Kullanılabilir modeller
│
└── system_prompt.md             ← (Referans — CLAUDE.md kaynağı)
```
