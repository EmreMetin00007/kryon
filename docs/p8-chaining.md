# Evidence-bound chaining (P8)

P8 turns explicit captured data flow into a typed read workflow. A static
`CHAIN_RULES` path is a `draft_hypothesis`: every pivot stays `unvalidated_edge`,
with no severity or reportability grant. Its impact and EV values describe
potential outcomes for prioritization. Individually valid observations do not
prove the connection between them or a terminal effect.

## Evidence and graph contract

`scripts/evidence_chaining.py` provides `EvidenceGraph(db_path, clock=None)` on
the existing memory SQLite database. It adds `p8_evidence`, `p8_relations`,
`p8_chain_jobs`, `p8_chain_dependencies` and `p8_chain_replays`; it uses the existing
`graph_outbox` and graph backends. No additional persistent service is introduced.
Call `close()` when finished.

`observe(record)` hashes canonical JSON with SHA-256. Each record carries a
canonical HTTP origin, tenant, run and session, finite observation/expiry times
and a TTL of at most one day. Evidence kinds are `exchange`, `identity`,
`resource`, `permission` and a recorded `replay`. Captures contain the actual
request and response, an explicit identity reference and a credential fingerprint.
Credential values remain in the caller's vault/session adapter; the store retains
only their hash. The origin includes the scheme, host and normalized port.
Future observations, invalid times and ambiguous request slots fail closed.

```json
{
  "kind": "exchange",
  "context": {
    "origin": "https://p8.test:443", "tenant": "tenant-a",
    "run_id": "run-p8", "session_id": "session-p8"
  },
  "observed_at": 1000, "expires_at": 2000,
  "identity_ref": "alice", "credential_hash": "<SHA-256 of identity headers>",
  "request": {"url": "https://p8.test/api/orders/order-a", "method": "GET", "body": ""},
  "response": {"ok": true, "status": 200, "body": {"id": "order-a", "invoice_id": "invoice-a"}}
}
```

Every typed relation includes source evidence hashes, the full context and the
intersection of its source validity intervals. Relation payloads are immutable
and hash-addressed. The six kinds are:

| Relation | Required observation |
| --- | --- |
| `produces_reference` | A successful structured response yields the selected scalar |
| `consumes_reference` | The selected actual request slot consumes that exact typed scalar |
| `reads_resource` | The captured read addresses the explicitly declared test object |
| `requires_identity` | Capture identity and credential hash agree with sourced account facts |
| `changes_state` | Same actor, URL and resource ID; observed typed before/after values differ |
| `validated_effect` | Recorded replay passes the independent control and exact authorization oracle |

`bind(producer_hash, consumer_hash, response_field, request_field, value_type,
family)` compares actual values. String and integer scalars are distinct; no
coercion, semantic-name inference or endpoint guessing occurs. Response selectors
are dotted JSON paths; request selectors include unambiguous `body.field`,
`query.name` and zero-based `path.N`. The initial runnable read workflow supports
path/query string slots only. Other observed bindings remain inventory.
`changes_state(before, after, field)` records an observed state difference; it
does not attribute causation to an unobserved operation or validate an exploit.

Outbox operation `evidence_relation` rechecks the authoritative SQLite evidence
before projection. Edge-specific intermediate nodes preserve parallel typed
relations on both existing backends, whose edges are unique per source/target
pair. Failed or expired projections retain their failed outbox record. Generic
`add_relationship` refuses typed evidence relations; arbitrary graph edges do
not become proofs. Diagnostic graph projections can be stale: execution and
replay always consult SQLite, verify hashes and TTL, and ignore graph scoring.

## Typed workflow API

`compile_evidence_chain(graph, spec, diagnostics=None)` returns a ready manifest
or a non-runnable `blocked` result with `unvalidated_edge` and a reason. A ready
plan remains `NOT_TESTED` and has no severity. It never grants scope or approval.
The explicit spec contains:

```python
spec = {
    "context": context,
    "captures": {"producer": producer_hash, "owner": owner_read_hash,
                 "negative": missing_object_read_hash, "peer": peer_read_hash},
    "identity_hashes": {"alice": alice_fact_hash, "bob": bob_fact_hash},
    "resource_hash": owned_invoice_fact_hash,
    "permission_hash": exact_read_scope_fact_hash,
    "owner_identity": "alice", "peer_identity": "bob",
    "response_field": "invoice_id", "request_field": "path.3",
    "value_type": "string", "resource_field": "id",
    "private_field": "private_marker",
}
```

The resource fact requires its exact URL, resource ID, family, tenant, owner,
`test_data_only: true` and a sourced P4 access rule. Identity facts require test
accounts, principal, tenant and authority. Distinct credentials alone do not
establish distinct people. Public/shared objects, unknown rules, cross-context
references and mismatched credentials cannot produce an authorization plan.
Permission facts enumerate the exact URLs and explicitly allow scope and reads.

The four requests are producer → owner read → independent negative control →
peer read. Owner and peer consume the produced identifier at the same explicit
request slot. The negative control uses the same endpoint family, changing only
that slot to an observed missing test object. Each step requires the prior step;
route, binding, identity, budget or oracle edits fail before traffic.

`ChainExecutor(..., evidence_graph=graph, evidence_context=runtime_context)`
rechecks the manifest by recompiling from the stored sources before every request
and before completion. `runtime_context` independently supplies the same origin,
tenant, run, session and resource hash plus `scope_allowed` and `read_allowed`.
The actual supplied identity headers must match their captured fingerprints.
Each request additionally passes the existing central transport scope/approval
gate and the four-request budget. No shared cookie jar or automatic relogin can
silently replace a tested principal. A newly produced different reference stops
the chain and requires replanning; it is never substituted into an unrelated
existing proof. P8 emits GET only; existing P7 write/WS7 paths retain their gates.

The terminal oracle follows P4's evidenced identity/privacy rules and P7's
independent control/effect principle. It requires a successful producer, the
owner's exact resource ID and nonempty private field, a successful negative
403/404 without that protected field, and the peer receiving the exact resource
ID and same protected field. HTTP 200 alone, failed transport, unrelated content,
wrong resources and a leaking or failed control cannot confirm. A safe twin
still has the reference link but returns `NOT_CONFIRMED` when access is enforced.

## Jobs, invalidation and replay

`register_job(id, spec)` records only that chain and its relation dependencies.
A missing prerequisite gives `blocked`; unrelated jobs remain available.
New `observe` calls retry blocked specs through `refresh_blocked()`. A waiting
spec must identify its source hash; a genuinely new reference requires supplying
the refreshed explicit spec. No guessed value substitutes for a missing proof.

`invalidate(evidence_hash)` and `sweep()` invalidate every dependent job if any
relation, identity, permission, resource, control or runtime replay proof expires,
is revoked or fails its content hash. `job(id)` sweeps before returning state;
completed jobs can become `invalidated`. Expired observations remain immutable
history. Refreshing requires new evidence intervals and recompilation; replaying
an old spec cannot revive it. These transitions affect local chain jobs only.

Execution stores the actual exchanges and a canonical replay artifact.
`replay(replay_evidence_hash)` loads those hash-addressed exchanges, rechecks all
current prerequisites, replays typed bindings and recomputes the terminal oracle
without requests. Durable replay works after reopening the database. Tampered,
missing, expired or revoked source/runtime evidence prevents replay confirmation.
An observed authorization effect has a local medium severity cap; possible static
RCE/ATO outcomes never raise it. Outcomes remain `reportable: false` and never
automatically call a provider, create a finding or issue a signed validator
receipt. Reporting still requires the existing artifact and deduplication gates.

## Offline acceptance

`tests/test_p8_chaining.py` uses socket-free actual local handler calls with
synthetic A/B accounts, orders and invoices. Vulnerable and safe twins exercise
the same link. Adversarial tests cover scope, identity, tenancy, session/run,
exact object, typed references, controls, edited plans, TTL, invalidation, durable
replay and existing graph/outbox integration. The full accepted P7 test-ID set
is compared against the P8 result; no historical test contracts are weakened.
Acceptance artifacts, isolated fixture databases and logs belong under
`/root/cco-work/p8-<timestamp>/`, outside the source repository. Acceptance uses
a network namespace plus socket audit hooks on Python and Python subprocesses.
