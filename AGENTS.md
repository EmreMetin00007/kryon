# HackAgent (`kryon`) Agent Guide

The primary runtime is the unified **`cco-agent` (`agentic` Sharded ReAct Engine + `kryon_core`)** built on Python 3.12+ and an OpenAI-compatible model endpoint. Start with `python3 scripts/agent_cli.py --help`, `./scripts/cco.sh --help`, or the installed `cco-agent --help` entry point (`agentic`, `report`, `save-auth`, `governance`, `check-config`). Do not start an external agent client or MCP server daemon as part of the Python workflow.

> **Legacy archive:** The retired v1 Python Engine / MCP server ecosystem (`PythonSolver`, 16 MCP servers, `skills/`) is preserved permanently at `git tag legacy-v1-archive`.

## Runtime Ownership

- **CLI & Run Bootstrap:**
  - `scripts/agent_cli.py`: unified entry point (`agentic`, `report`, `save-auth`, `governance`, `check-config`).
  - `scripts/agentic_runner.py`: offline plan (`agentic-plan.json` when `--execute` is omitted) and live run orchestration.
  - `scripts/provider_auth.py` / `scripts/llm_config.py`: `cco-llm/1` config validation and fail-closed live remote provider authorization (`authorize_provider`).
  - `scripts/target_bootstrap.py`: target origin validation, loopback-by-default enforcement, `--scope-file` parsing, and `ScopeGuard`.
- **Sharded ReAct Loop & Context:**
  - `scripts/agentic_investigator.py`: bounded model/tool loop (`--execution-mode sharded|monolithic|ephemeral`), Stage 1 discovery bootstrap with `discovery_finish_gate`, Stage 2 parallel shard execution, and `ServiceDegradationError` circuit breaker.
  - `scripts/agentic_sharding.py` / `scripts/agentic_context.py`: subsystem surface clustering (`cluster_discovered_surface`), `80K` epoch compaction, and HTTP 400 recovery.
  - `scripts/agentic_bsag.py` / `scripts/agentic_scheduler.py`: optional opt-in BSAG / scheduler modes (off by default).
- **Tools, Transport & Passive Intelligence:**
  - `scripts/agentic_tools.py`: closed 11-tool `TOOL_SCHEMAS` dispatcher (`http_request`, `read_receipt`, `replay_as`, `extract_surface`, `notebook`, `callback_listener`, `concurrent_check`, `browser_crawl`, `analyze_token`, `record_finding`, `finish`).
  - `scripts/agentic_http.py` / `scripts/agentic_oob.py`: scope-locked `AgenticHTTPClient`, multi-actor session manager, and loopback-only `LoopbackCallbackServer`.
  - `scripts/agentic_browser.py` / `scripts/agentic_preview.py` / `scripts/agentic_waf.py` / `scripts/agentic_crypto.py` / `scripts/agentic_surface.py` / `scripts/agentic_receipts.py`: read-only Playwright SPA/Shadow DOM crawl, HTML/JS/OpenAPI/GraphQL/Postman previews, passive WAF diagnosis, offline token/deserialization inspection, `SurfaceFrontierTracker`, and secret-redacted `ReceiptStore`.
- **Startup Loaders & Vault:**
  - `scripts/agentic_auth_import.py` / `scripts/save_browser_auth.py`: zero-overhead Playwright `--storage-state` session capture and import.
  - `scripts/agentic_seed.py` / `scripts/tech_routes.py`: offline `--seed-surface` (HAR/mitm/ZAP/ffuf/nuclei/URL) and `--tech-hint` discovery seeding.
  - `scripts/agentic_vault.py`: bridge to encrypted `CredentialVault`, IMAP OTP retrieval, and Ed25519 OOB verification.
- **Verification, Evidence & Reporting:**
  - `scripts/agentic_oracle.py` / `scripts/agentic_evidence.py` / `scripts/evidence_trust.py`: 3-stage `DifferentialOracle` (Control/Falsification -> Masked Diff -> Clean Replay), finding canonicalization/deduplication, and Ed25519 host signing/verification. Model text never confirms a finding.
  - `scripts/agentic_report.py` / `scripts/agentic_telemetry.py`: Markdown (`report.md`) and SARIF 2.1.0 (`report.sarif`) output with redacted PoCs and explicit `NOT TESTED` coverage accounting.
- **Shared Provider & Budget Accounting:**
  - `scripts/full_agent_provider.py` / `scripts/full_agent_budget.py` / `scripts/wire_budget.py`: `MeteredProviderTransport` (`--cache-token-weight`), `SessionGate`, atomic `SharedBudget`, and `WireBudget`.
- **Pure-Python Core Libraries (`kryon_core/`):**
  - `kryon_core/surface`: W3C HTML/JS/CSS/Header/OpenAPI/GraphQL/Postman extraction, normalization, wordlists, and read-only crawl primitives.
  - `kryon_core/browser`: read-only Playwright runtime hooks and request interception policy.
  - `kryon_core/js`: JavaScript parser, route composition, source-map decoding, and client-logic mapping.
  - `kryon_core/waf`: offline WAF/CDN signatures and passive HTTP block classification.
  - `kryon_core/validator`: offline JWT/opaque crypto-token analysis, serialization analysis, and Ed25519 OOB collector verification.
  - `kryon_core/vault`: encrypted local `CredentialVault` and bounded IMAP OTP reader (`otp_core`).

## Configuration and Data Boundaries

- **Provider schema:** [config/llm.example.json](config/llm.example.json) (`schema: "cco-llm/1"`). Local configuration lives at `config/llm.json` (git-ignored) or `CCO_LLM_CONFIG`. Store only the credential environment-variable name (`api_key_env`) in configuration; never store credential values.
- **Program policy template:** [config/bounty-program-policy.json](config/bounty-program-policy.json).
- **Work & host directories:** Engagement and run outputs belong under `CCO_WORKDIR` (default `~/cco-work`); host state, encrypted vault data, and trust bundles belong under `CCO_HOME` (default `~/.cco`). Never place run output, loot, or session artifacts in the repository root (`scripts/check_repo_layout.py` enforces this gate).
- **Tool admission:** The agent loop only exposes the closed 11-tool `TOOL_SCHEMAS` catalog owned by `scripts/agentic_tools.py`.

## Scope, Safety, and Evidence Rules

- **Explicit authorization before non-loopback traffic:** Loopback targets are the default. Before any live non-loopback target interaction, read the active scope file (`.codex/scope.json` or `~/.codex/data/scope.json`), confirm the exact authorized asset, and require explicit user approval alongside `--scope-file`, `--allow-non-loopback`, `--execute`, and (for remote LLM providers) `--authorize-live-provider`. An offline `agentic-plan.json` never authorizes network traffic.
- **Fail-closed operational gates:** Keep scope, program-policy, HTTP method allowlist, rate, request (`--http-budget`), time (`--seconds-budget`), and token (`--token-budget`) gates active in every execution path. Never perform DoS, destructive actions, persistence, privilege escalation, or real-user data exfiltration. Stop immediately on service degradation (`ServiceDegradationError` circuit breaker).
- **Secret hygiene & synthetic identities:** Use authorized synthetic identities and owned test objects. Preserve session references, `--storage-state` files, or encrypted vault handles rather than raw credentials in tasks, receipts, and model contexts. Never read, print, copy, or commit `.env`, `config/llm.json`, private keys, cookies, or raw credentials.
- **Evidence discipline:** Model text never confirms a finding; keep unsupported claims as hypotheses. Before recording or reporting findings, require current scope verification, deterministic `DifferentialOracle` / receipt artifacts, deduplication, and a minimal redacted reproduction. Closure, task completion, and complete security coverage are separate facts. `NOT TESTED` stays visible in every report.

## Verification

Run the repository quality gates from the repo root:

- `python3 scripts/release_check.py` (full gate; `python3 scripts/release_check.py --list` to inspect all steps)
- `python3 -m pytest tests -q`
- `python3 -m ruff check .`
- `python3 -m mypy`
- `python3 scripts/check_repo_layout.py`
- `python3 scripts/governance_audit.py --root scripts --format json --fail-on high` (also `--root kryon_core` and `--root docs`)
- `python3 scripts/agent_cli.py check-config --provider-config config/llm.example.json`

A scripted local provider verifies host protocol and oracle behavior, not real-model recall. Never spend provider credits or send traffic to remote targets implicitly during verification.
