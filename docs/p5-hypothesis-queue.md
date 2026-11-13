# Observation-level hypothesis queue

Surface observations now create individual hypotheses in `web_hypotheses` in
`agent_memory.db`. Ingestion sends no requests. Replaying an observation keeps
its original key and state; a new field, object, operation or context creates
new work. Existing vector names remain available for reporting and legacy CLI
compatibility. They do not close this observation queue.

A hypothesis key includes the policy/context namespace, target, operation,
HTTP method, exact request digest, carrier and field, actor and owner,
resource/family, request or screen state, hypothesis type, run, observation,
access-rule reference and validation variant. Lifecycle status is separate
from request/screen state and does not change the key. Concrete resource,
state and variant values are hashed; request bodies, credential headers and
query values are not stored in this queue.

The optional fields `resource_key`, `resource_family`, `state_key` and
`variant_key` travel through candidate deduplication, signed plans, encrypted
request snapshots, validator execution context and signed coverage events.
Raw `resource_id`, `request_state` and `variant_id` inputs can produce those
digests. A validator strategy gets a stable variant key when the canary adapter
routes it. Multiple light canary payloads pointing to the same validator
strategy are clues for that strategy, rather than claims that each payload
has received a separate deterministic validation.

| State | Meaning |
| --- | --- |
| `proposed` | Observation received; needs admission or missing context |
| `ready` | Candidate planned for validation; the execution gate still applies |
| `running` | Existing campaign claim or validator attempt is active |
| `blocked` | A named prerequisite prevents progress |
| `inconclusive` | No adequate deterministic result; also used when evidence becomes unavailable |
| `tested_no_violation` | Current, matching validator evidence reports no violation for this exact hypothesis |
| `confirmed` | Current, matching deterministic validator evidence confirms this exact hypothesis |

A task ending with `done` can only project `inconclusive` when no validator
result is available. A task cannot promote a hypothesis to either terminal
state. Existing artifact verification and signed coverage remain authoritative;
the hypothesis table is an advisory projection, never a finding verifier.
Cached terminal states are downgraded during feedback reconciliation if their
verified evidence is unavailable. Raw table/CLI reads are advisory snapshots,
not evidence revalidation.

Blockers identify their kind, subject and version. Resolving a changed session
version only reopens matching blocked hypotheses, initially to `proposed` for
readmission. Other session, budget, scope or request-context blockers remain.
The campaign integration performs its existing signed post-block freshness,
policy, lease, dependency, attempt and remaining-budget checks before reopening
or claiming tasks. Task rows, fencing tokens, canonical task keys and request
reservations retain their existing ownership in `CampaignRuntime`.

Ready candidates are ordered by readiness, observation quality, coverage
contribution, impact and estimated request/time cost. These are deterministic
ordering rules, not calibrated probabilities. Priority metadata does not change
a gap's identity. Scheduling applies this order within its bounded lookahead;
it does not scan an unbounded campaign or expand authorization.

Owned-resource candidates can reach the existing oracle before a long crawl.
Within fuzzing, an eligible high-signal observation can reach the validator
before the remaining canaries complete. A scoped `ContextVar` listener keeps
concurrent and nested runs separate. All arrivals use the same deduplication
set and validation limit as end-of-batch arrivals. Valid-baseline candidates
without a light signal retain the existing bounded sampling path. Per-run
validation limits/usage and canary request counts remain visible separately;
the wire gate and campaign reservation remain the actual request limit.

Read the detailed queue without executing work:

```bash
python3 scripts/brain.py hypotheses queue \
  --db "$CCO_WORKDIR/agent_memory.db" --target https://example.test/
```

Use the actual engagement DB path if the launch configuration keeps
`agent_memory.db` elsewhere. `--context` optionally selects a namespace;
`inventory` contains source hypotheses, while policy-bound validator attempts
use the current feedback context. Source inventory and admitted attempts stay
separate because an unattributed schema import cannot inherit an account's
coverage. This command does not issue grants, reserve budget, claim tasks or
produce a vulnerability report.
