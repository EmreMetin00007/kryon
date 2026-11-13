# Observation-bound business logic and controlled objects (P7)

P7 compiles experiments from a captured resource relationship, a sourced business
rule and a captured normal-operation control. Semantic parameter names remain
hypotheses. No compiler grants scope, wire approval or permission to write.
The acceptance lab uses an in-memory HTTP-handler adapter with no sockets.

## Draft and capture contracts

Hunter `generate_abuse_cases` returns `status: draft_hypothesis`, `runnable: false`,
`confirmed: false`, `observed_context: null` and `executable_manifests: []`.
Every case carries the same draft status and missing prerequisites. Generated
sample bodies/responses no longer enter the workflow compiler. A draft must be
replaced by actual capture context; setting a runnable flag is insufficient.
`plan_from_hypothesis` also blocks synthetic/draft endpoints even when they carry
a request-shaped dictionary. P6 observed injection plans retain their existing
routing, permission and signed-receipt contracts.

`compile_workflow_manifests(captures, diagnostics=gaps)` returns only runnable,
schema-valid action manifests. `gaps` contains explicit `missing_prerequisite`
records such as `unobserved_context`, `unobserved_observer`,
`unobserved_business_rule`, `unobserved_normal_effect` or
`independent_normal_control_required`. Browser harvest exposes these through
`workflow_missing_prerequisites`. Raw or redacted browser traffic remains surface
inventory until the required capture relationships and business rules exist.

Each captured request needs its actual method, absolute URL, HTTP status,
`req_body`/`resp_body`, and the following private metadata:

```json
{
  "observed_context": {
    "source": "capture",
    "capture_id": "apply-1",
    "workflow_id": "captured-checkout",
    "session_id": "test-session",
    "resource_id": "test-cart-a",
    "identity_ref": "owner",
    "response_links": [
      {
        "producer": "read-cart-a",
        "response_field": "id",
        "request_field": "body.resource_id"
      }
    ]
  }
}
```

The producer ID references an actual captured response. The scalar at its dotted
response field must equal the resource ID and the value actually consumed by the
request. Supported request references are dotted `body.field`, unambiguous
`query.name` and zero-based `path.2`. Both directions (observer response to action
request, or action response to observer request) are supported. Resource, workflow,
session and complete origin must agree. GET observers must also return their own
resource identity (`resource_field`, default `id`). Multiple matching observer
URLs, conflicting capture IDs and missing links fail closed. There is no
same-host, path-prefix, nearest endpoint or invented URL fallback.

A candidate capture's `observed_context.business_rules` list references two
captured flows and their rule:

```json
{
  "contract": {
    "kind": "idempotency_replay",
    "expected_rule": "One coupon permits one redemption.",
    "alternative_explanation": "A normal first application legitimately discounts the cart.",
    "evidence_ref": "controlled-rule-artifact:coupon-single-use",
    "control": {"field": "uses", "before": 0, "after": 1},
    "probe": {"field": "uses", "before": 0, "after": 2}
  },
  "control": {
    "before": "read-control-before",
    "actions": ["normal-apply"],
    "after": "read-control-after"
  },
  "probe": {
    "before": "read-probe-before",
    "actions": ["apply-1", "apply-1"],
    "after": "read-probe-after"
  }
}
```

All referenced captures must exist. The normal control uses a distinct resource
in the same workflow/session/origin, and its captured state must match the
specified legitimate effect. Each action needs an observed data link to its
observer. POST/PUT/PATCH actions preserve their captured bodies; fields and
endpoints are never invented. The runtime additionally verifies the resource
identity in every before/after observation.

## Effect and control oracle

`scripts/business_logic.py` implements the shared contract and oracle. The order
is control-before → normal actions → control-after → probe-before → probe actions
→ probe-after. The `business_control` oracle must pass before any probe request.
The final `business_logic` oracle requires both exact, typed state effects.
Nested field values can describe a state/access pair. Missing fields, malformed
JSON, failed transport, non-2xx observer responses, wrong resource identity,
wrong baseline values and missing controls cannot confirm a violation.

A decreasing total is insufficient evidence: one valid coupon discount passes
the normal control but fails the repeated-redemption effect. Likewise HTTP 200,
a reflected read-only field and an edited terminal branch cannot replace the
state oracle. Manifest validation rejects skipped controls, mismatched contracts,
status-only terminal oracles and invalid lifecycle phases. Generic `validate`
steps and the default validator provider demote business-logic status-only
confirmation requests, including normalized class aliases.

Automatic race generation and inferred arithmetic/quantity writes are removed.
Explicit legacy race DSL retains its separate approval gate. P7 emits no
concurrent experiment. Historical invariant helpers remain available for their
existing diagnostic callers; business-logic confirmation uses the stronger
P7 effect/control contract.

## WS7 lifecycle

`write_set.seal_object` requires explicit `run_id`, `session_id`, a declared test
account, credential fingerprints, owner label, task, creation/ownership evidence
and a finite expiry (maximum one day). Object identity includes origin, path and
query. Existing rows cannot be resealed or overwritten by another run. Legacy
rows migrate structurally but remain unusable without run/session bindings.

| State | Meaning |
| --- | --- |
| `sealed` | Setup and ownership evidence recorded; pre-state still required |
| `pre_state` | Actual observer snapshot hashed; mutation may be checked |
| `experiment` | Run-bound test action recorded |
| `post_state` | Actual post-state hashed; experiment writes closed |
| `torn_down` | Fixture adapter explicitly verified disposal |
| `cleanup_failed` | Disposal failed; object remains visible and unwritable |
| `unknown` | Interrupted or uncertain fixture; remains visible and unwritable |

`mark_state(..., run_id=..., session_id=..., evidence=...)` enforces transitions
and writes hashed evidence to the lifecycle journal. It never assumes rollback.
`inspect_object` exposes state and journal hashes without credential fingerprints
or snapshot contents. `mutation_permitted` requires an unexpired pre-state or
experiment seal, the exact run/session and a credential from that run.
Reusing the same credential in another run returns `cross_run_rejected`.

`ChainExecutor(..., write_context={"db_path": ..., "run_id": ..., "session_id": ...})`
checks all P7 fixtures before the first request and checks write permission again
for each action. The existing wire gate, request/time budgets and identity checks
also apply. The central policy engine gets trusted caller bindings from
`CCO_RUN_ID` and `CCO_SESSION_ID`; request arguments cannot replace those bindings.
The repository's existing scope/approval policies remain authoritative.

## Offline acceptance lab

`python3 scripts/write-validate.py --offline` runs vulnerable and safe twins of:

- Object write authorization (owner edit versus a different test principal).
- Binding a server-owned read-only field versus an editable title.
- A single-use coupon replay versus one legitimate redemption.
- Completion without preparation versus the complete normal sequence.
- Share-to-private access revocation versus legitimate sharing.

`run_scenario` creates two fresh local fixtures, seals ownership, captures actual
handler requests/responses on a fork, compiles the rule and runs it through the
chain executor. Cleanup is attempted in `finally` and its verified result is
recorded. Failed/uncertain cleanup stays in `unresolved_fixtures`. If sealing is
rejected, the runner never attempts teardown against that unowned object.
Interrupted experiments retain an `unknown` journal event even when subsequent
fixture disposal succeeds. Lab outcomes do not create findings or signed reports.

Tests live in `tests/test_p7_business_logic.py`, `tests/test_write_set.py` and
`tests/test_browser_workflow_bridge.py`, with the P6 regression suite retained.
Several historical browser test IDs now assert the intended stronger contract:
synthetic workflows and automatic races are blocked, and positive examples use
observed local handler captures with explicit rules and controls. These changed
expectations are recorded in the P7 acceptance artifacts. All test commands run
inside a network namespace with Python socket audit hooks inherited by Python
subprocesses. Working data, logs and acceptance reports belong under `CCO_WORKDIR`.
