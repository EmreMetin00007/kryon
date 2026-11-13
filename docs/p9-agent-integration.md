# P9 agent integration and operator contracts

P9 uses the existing SQLite stores and transport/reporting gates. It introduces
no network client, persistent service, alternative validator or credential store.
Working artifacts belong under `CCO_WORKDIR`; source belongs in this repository.

## Main flow

1. `brain.py plan` still builds the deterministic phase chain. P1 operation
   inventory, P2 typed schema imports, P3 UI requests and P4 sourced account and
   resource facts feed the existing P5 `web_hypotheses` table.
2. `brain.py operations --db <agent_memory.db> --target <url> --workdir <run>
   [--context <context-key>]` emits local TaskSpecs with exact P5 references.
   This is plan-only: proposed/blocked entries remain inventory. Nothing in a
   prompt, graph score or task spec grants traffic or changes admission state.
3. Campaign `schedule-gaps` / `schedule_coverage_gaps` preserves the existing
   observed-request, identity, scope, policy, header, grant and budget checks.
   Its encrypted request packet produces the same P5 dimension as the brain.
   The gap scheduling fingerprint is a separate key: never replace the P5 key
   with it. `CampaignRuntime.enqueue_spec` prevalidates a TaskSpec and checks
   that its execution target/tool match before normal queue admission.
4. P6 uses the existing Hunter validator adapters. P7 business and P8 evidence
   workflows use compiled action manifests through `ChainTaskExecutor`, with
   the existing request/WS7/source/TTL/independent-control gates. The executor
   accepts host-owned `evidence_graph` and `evidence_context` adapters; it can
   reopen the campaign memory graph when omitted, but missing independent
   runtime context remains blocked. Model task arguments cannot replace it.
5. Summary scaffold/validate, verified handoffs and signed host checkpoints
   remain the phase/closure authority. The solver validates its task before
   provider work. Its existing one-summary-repair ceiling remains in force.
6. Artifact verification and deduplication remain required before saving or
   reporting findings. P8 replay effects alone are non-reportable; neither a
   successful manifest nor `agent-outcome/1` saves a finding or issues a receipt.

## References and local validation

`TaskSpec.references` and campaign `tasks.references_json` carry:

```json
{
  "hypothesis_ref": "<existing P5 fingerprint>",
  "operation_ref": "<observed operation id>",
  "dimension": {"operation_id": "...", "context": "...", "method": "GET"}
}
```

The example dimension is abbreviated. The stored value retains **every** P5
field: target/context, URL/request hash, method, carrier/parameter, actor/owner,
resource/family, state, variant, run and source observation, plus sourced access
rule when present. `agent_integration.references` verifies the canonical P5
SHA-256; it does not derive a coarse vector identifier. Serializers omit an
empty reference field to retain existing native prompt/token contracts.

The campaign migration is additive. Legacy tasks have `{}` references; a
legacy gap task without an observation packet can be queued, but cannot execute
until the normal admission gate verifies its prerequisites. Newly admitted
scheduled work carries the exact references. Idempotency includes references.

`agent_integration.preflight(spec, repair=None)` returns `ready` or `blocked`,
errors, a detached spec, `repair_attempts` and `reason_code`. Local validation
runs before dispatch. A supplied repair callback receives structured errors
**once**; it cannot change target, scope, ID/phase, references, tools, budgets,
paths, dependencies or justifications. Failure ends with
`schema_validation_failed`. No model is needed for valid contracts. Missing
sessions, policy permissions, source proofs and exhausted budgets do not enter
schema repair; they remain visible prerequisites for normal readmission.

## Common persisted outcome

Both direct runtime completion/block calls and campaign workers store an
`outcome` alongside their existing raw result:

```json
{
  "schema": "agent-outcome/1",
  "source": "web_loop|manifest|task",
  "references": {},
  "task_completion": "done|blocked",
  "run_closure": "open",
  "scope_completion": "incomplete",
  "execution": "tested|not_tested",
  "test_result": "confirmed|tested_clean|inconclusive",
  "reportable": false,
  "reason_code": "",
  "requests_sent": 0,
  "request_count_known": true,
  "requests_charged": 0,
  "artifacts": []
}
```

`test_result` defaults to inconclusive. A linked P5 terminal state is projected
only after rechecking its current signed validator artifact, class, target,
execution dimensions and transport guard. Raw verdict strings, task success,
HTTP status or model summaries cannot promote it. `reportable` remains false;
actual reportability is decided by the existing artifact/dedup/report gates.
The recorded P8 verdict and replay hash remain in the raw manifest result.

Request usage comes from the trusted worker/transport count. If unavailable,
the existing conservative reservation is charged, `request_count_known` is
false, and no invented sent count is reported. Manifest errors retain step
hashes and the partial evidence file pointer. Safe P8 twins complete the test
with NOT_CONFIRMED instead of becoming a worker error or automatic retry.

## HUD and closure

`campaign_snapshot(home, campaign_id=None)` reads databases in read-only mode.
The default is the newest campaign; task counts and request totals belong to
that campaign. Missing/legacy data is unknown or incomplete. The snapshot
includes discovered operation count, ready hypotheses, waiting prerequisites,
verified tested/confirmed and inconclusive counts, measured/charged requests,
reservations, remaining request allowance (`null` means unlimited) and every
remaining task/hypothesis reference. Cached terminal states with missing,
stale, edited or mismatched validator artifacts are inconclusive.

The TUI reads the same `CCO_HOME` path as the Python collector, displays these
counters and independently labels task completion, run closure and observed
scope completion. Snapshot replacement is atomic. Finding toasts retain their
existing current-artifact checks and remain separate from local replay effects.

Pending work that cannot fit the campaign request/USD allowance remains queued
with a durable `blocked_budget` event. It is not retried as a schema repair or
silently removed. Existing measured results and partial evidence remain stored.
Campaign close-out refuses incomplete operation coverage without an explicit
written waiver, in addition to the existing route/review checks. A waived close
stores the full integration snapshot and remaining references in its close-out
checkpoint. A waiver allows run closure and **never** complete scope. Task
outcomes remain historical open-run snapshots; the campaign close-out is the
current run-level authority. Scope refers to the observed inventory only; no
finite test proves that an application has no undiscovered surface.

## Offline validation

`tests/test_p9_integration.py` exercises exact dimensions, task/schema repair
bounds, outcome trust, scheduler handoff, budgets/restart, signed artifact
freshness and socket-free P8 campaign twins/reopened replay. Existing full-agent
solver/preflight/runtime/summary/budget and orchestration tests are also run.
All 1,150 accepted P8 test IDs must remain passing, with the same three historic
P8 exclusions. Test IDs and protected artifact hashes are compared explicitly.

Acceptance runs in `unshare --net` with Python socket audit hooks on parent and
Python children. Pure Node plugin tests receive a network-denial preload as
well. Legacy tests that require loopback HTTP/provider servers are collected
and explicitly deselected for this socket-free acceptance; no loopback traffic,
live target interaction or real provider call is authorized. Their unmodified
contracts remain available for a separately authorized networked acceptance.
`P9-REPORT.md`, `ACCEPTANCE.json`, exact commands, test results, network audits,
source diffs and quality logs live under `/root/cco-work/p9-<timestamp>/`.
