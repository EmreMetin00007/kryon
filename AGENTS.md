# HackAgent Python Engine

The primary runtime is Python + an OpenAI-compatible model endpoint. Start with
`python3 scripts/agent_cli.py --help` or `./scripts/cco.sh --help`.
`cco-agent` is the installed entry point. Do not start an external agent client
as part of the Python workflow.

## Runtime ownership

- `scripts/agent_cli.py`: plan, operations, preflight, run, audit, campaign,
  worker, security and status commands.
- `scripts/full_agent_python_solver.py`: bounded model/tool loop and four-phase
  workflow. The host owns transitions, summaries, evidence and closure.
- `scripts/full_agent_python_broker.py`: model context projection, phase tool
  admission, session references and signed evidence handoff.
- `scripts/full_agent_broker.py` / `full_agent_budget.py`: shared provider,
  executor and measured usage accounting. Model text never confirms a finding.
- `scripts/brain.py` / `orchestration_spec.py`: TaskSpec planning/contracts.
- `scripts/policy_engine.py` / `wire_budget.py`: tool and actual-request policy.
  These checks must work without a JavaScript client plugin.
- `scripts/campaign_runtime.py` / `campaign_worker.py`: persistent task queue and
  bounded tool execution. Queue success is not proof of security coverage.
- `mcp-servers/`: reusable discovery, identity, hypothesis, validator, business
  logic, evidence and memory capabilities. P1–P9 are capabilities, not an implied
  complete sequence in every Python run.

## Configuration and data

- Provider schema: `config/llm.example.json`. Local configuration lives at
  `config/llm.json` (ignored) or `CCO_LLM_CONFIG`. Put only the credential
  environment-variable name in configuration. Never store credential values.
- MCP inventory: `config/mcp-servers.json`; inventory profiles:
  `config/profiles.json`. The solver also has an explicit bounded tool catalog;
  changing inventory profiles does not grant tools to a running solver.
- Work data belongs under `CCO_WORKDIR` (default `~/cco-work`); host state uses
  `CCO_HOME`. Never place run output in the repository. Historical documents may
  describe retired OpenCode setups; use executable Python code for current behavior.

## Scope and evidence

Before live target interaction, read the project `.codex/scope.json` (or
`~/.codex/data/scope.json`), confirm the exact asset, and require explicit user
approval. A local plan never authorizes traffic. Keep scope, program-policy,
rate, request, time and token gates in every execution path. Never perform
DoS, destructive work, persistence, privilege escalation or real-user data
exfiltration. Stop at service degradation.

Use authorized synthetic identities and owned test objects. Preserve session
references rather than credentials in tasks and model contexts. Never read,
print, copy or commit `.env` secrets. Keep unsupported claims as hypotheses.
Before saving/reporting findings require current scope, deterministic tool
artifacts, deduplication and a minimal reproduction. Closure, task completion
and complete security coverage are separate facts. NOT TESTED stays visible.

## Verification

- `python3 -m pytest tests/test_python_engine.py tests/test_full_agent_python_solver.py -q`
- `python3 -m pytest tests/test_p9_integration.py tests/test_module_boundaries.py -q`
- `python3 scripts/release_check.py --list`
- `python3 scripts/check_repo_layout.py`
- Run the appropriate loopback/negative-control suite for transport or validator
  changes. A scripted local provider proves protocol behavior, not real-model
  recall. Do not spend provider credits or test remote targets implicitly.
- See `docs/PYTHON_ENGINE_GAPS.md` for verified limitations and acceptance work.
