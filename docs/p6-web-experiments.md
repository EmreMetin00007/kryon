# Observation-bound web experiments

P6 connects the P5 hypothesis dimensions to an observed baseline, one selected
mutation, a negative control and an existing deterministic validator. Planning
does not issue grants, send traffic, reserve campaign budget or confirm findings.

`cco_hunter_core.experiments.ROUTES` is the routing table used by the experiment
compiler and the main loop's core validator dispatch. Each entry names its
validator, supported carriers, permission requirements, oracle and dependencies.

| Class | Oracle requirements |
| --- | --- |
| SQLi | Repeated boolean differential, controlled errors or repeated timing evidence |
| SSTI | Two arithmetic evaluations with literal/malformed controls |
| Path traversal | Declared file/signature evidence and missing-file controls |
| XSS | Browser execution with silent controls; reflection remains a separate primitive |
| SSRF | Signed challenge, exact probe binding and independently verified callback provenance |
| Open redirect | Exact destination hostname, negative control and explicit allowed-host checks |
| BOLA / BFLA / authentication / field access | P4 identity/resource cell and a sourced denial rule |

The input compiler accepts a private observed `request_context`: URL, method,
baseline headers/body, selected parameter path and operation descriptor. It
does not make sample values from schema field names. A missing mutation,
missing slot, repeated ambiguous parameter, unavailable validator or missing
browser/OOB dependency produces an explicit gap. `plan_from_hypothesis` embeds
this manifest in the existing test-plan format; its executor delegates to the
bounded, sequential experiment interpreter. Legacy manually authored DSL plans
retain their existing behavior, including explicitly requested race steps.

`cco_surface_core.mutation` replaces one observed query, form, JSON, header,
cookie or path slot. Sibling values, duplicate pairs, encoded sibling bytes,
nested dictionaries and arrays remain intact. Repeated target names require
an explicit occurrence. Missing JSON paths are refused. Type changes apply to
an existing slot; they do not create an inferred request body.

The Hunter-to-Validator adapter uses a short-lived `ContextVar` request builder
for all control and payload rounds. Baselines use the actual observed value.
The same builder renders reproductions, so a literal `{{PAYLOAD}}` in a sibling
field is preserved. Existing capture freshness, identity binding, per-wire scope,
approval and request budgets still apply. The signed validator artifacts and
matching coverage verifier remain the authority for terminal hypothesis states.

GET, HEAD and OPTIONS retain their existing read-only admission. A read-only
POST needs an exact entry in operator-controlled program policy:

```json
{
  "readonly_operations": [
    {
      "method": "POST",
      "url": "https://example.test/api/search",
      "operation_id": "op-observed-query-id",
      "read_only": true
    }
  ]
}
```

This declaration is an additional prerequisite for the existing wire gate.
A schema flag or an LLM declaration does not authorize POST. It does not
authorize PUT, PATCH or DELETE. Existing durable campaign gap scheduling
retains its GET-only subset; it is not expanded by this compiler.

GraphQL keeps the observed selected query, operation name, schema fields and
variable paths. Document/operation mismatches and mutation/subscription
operations are refused. Variable injection preserves the document and sibling
variables. REST access inventory separates object, function and field scope,
including supplied API-version metadata. Field access without a dedicated
oracle remains blocked. The P4-bound authorization compiler swaps only the
actor on a declared resource with an evidenced denial cell.

JWT/OAuth routes need an observed flow. A protocol label creates no active
probe. An explicitly injected JWT hook can consume an observed Bearer token;
its return text cannot mark a tool validated. Production advanced hooks retain
their existing disabled setting. WebSocket, gRPC, smuggling and cache adapters
are passive inventory entries throughout P6.

Tool status separates `available`, `applicable`, `runnable`, `executed` and
`validated`. Registration or a disabled hook never counts as execution.
Validation requires a matching trusted receipt; budget exhaustion, missing
controls and invalid baselines cannot become negative findings. Public
execution summaries contain stage/status metadata and receipt identifiers,
not request bodies or header samples.

Legacy fanout categories remain visible as prerequisite gaps. Only an observed
slot gets an executable variant. Missing form/JSON/cookie captures have no curl
or request body, and never enter the execution branch.

Offline coverage is in `tests/test_p6_experiments.py`; existing validator,
callback-trust, traversal, P4/P5, module-boundary and SPA fixtures provide the
regression checks. The acceptance artifacts and command logs live outside the
repository under the P6 work directory.
