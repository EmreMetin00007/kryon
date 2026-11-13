---
name: attack-surface-mapping
description: "Pasif OSINT ve client-side keşif ile saldırı yüzeyi haritalama skill'i. Hedefe doğrudan saldırmadan, Certificate Transparency (crt.sh), DNS recon, Wayback Machine arşivi, RDAP/WHOIS, GitHub dork, kullanıcı adı OSINT ve headless tarayıcı (Playwright) analizi ile maksimum bilgi toplar. Bu skill'i şu durumlarda kullan: kullanıcı 'saldırı yüzeyi', 'attack surface', 'pasif keşif', 'passive recon', 'OSINT haritalama', 'subdomain bul (pasif)', 'crt.sh', 'wayback', 'arşiv URL', 'github dork', 'leak ara', 'kullanıcı adı ara', 'sosyal medya OSINT', 'API endpoint keşfi', 'security header', 'cookie audit', 'DOM XSS', 'JS endpoint' dediğinde veya bir domain/kurum hakkında temas kurmadan istihbarat toplaması istendiğinde. mcp-osint-tools ve mcp-browser server'larını birlikte kullanan ilk-temas-öncesi keşif metodolojisi."
---

## P9 runtime contract

Use the deterministic flow in `docs/p9-agent-integration.md`: observed inventory,
schema and UI captures plus sourced test identities feed exact P5 hypotheses.
Use `brain.py operations` for references and campaign `schedule-gaps` for admitted
read work. P7/P8 dependent work uses compiled manifests, source hashes/TTL and
independent controls. Recipe examples below are candidate inventory only; they
never override runtime scope, grant, transport, test-object or write permissions.

Prevalidate tasks locally; allow at most one structured schema repair. Policy,
session and budget blocks remain `blocked_prerequisite`, with evidence and
untested dimensions retained. No manual JSON bypass, repeated model repair,
automatic escalation or destructive/state-changing work. Current validator
artifacts and mandatory deduplication precede finding storage/reporting. Raw
CONFIRMED text and local P8 replay effects alone remain non-reportable. Track
task completion, run closure and observed scope completion independently.

## Surface mapping

Use approved passive sources first. DNS/zone transfer and browser navigation can
contact targets and require the applicable scope/grant; passive does not mean
unrestricted third-party access. Preserve discoveries as inventory, never
unvalidated findings. Browser links/forms/captures and schema imports merge into
the existing SQLite operation store with source observation references.
Captured methods, typed parameters, security alternatives and UI request state
must survive normalization. Discovery creates proposed hypotheses; only normal
admission makes supported work runnable. Missing accounts, request context or
ownership remain visible prerequisites. Header configuration or an open schema
alone does not establish high severity or authorize exploitation.
