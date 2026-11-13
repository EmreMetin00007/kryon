# Live Evren provider acceptance — 2026-11-05

All five fresh native launches ran against the measured `blind-lab/3`
comparison seeds. **Live acceptance failed for all five seeds.**
Planner and worker were configured as `evren/deepseek-v4.1-flash`.
Each seed retained the frozen ceiling of 300 HTTP requests, 1,000,000
LLM tokens, and 1,800 seconds. The five-seed token ceiling was 5,000,000.

| Seed | Launch result | Tokens charged | Measured tokens | HTTP requests | Worker delegations | Verified closure |
|---|---|---:|---:|---:|---:|---|
| 20261104 | native_failed | 683,475 | 683,475 | 3 | 0 | no |
| 20261105 | native_failed | 698,457 | 698,457 | 3 | 0 | no |
| 20261106 | native_failed | 688,734 | 688,734 | 3 | 0 | no |
| 20261107 | native_failed | 671,042 | 671,042 | 3 | 0 | no |
| 20261108 | budget_invalid | 283,767 | 1,143 | 3 | 0 | no |

The first four runs consumed their allowance on planner context and local
setup. Their previous conservative prompt bound already exceeded the
remaining allowance, and the next completion was refused. No native worker
delegation, discovery requests, signed vulnerability coverage, or verified
closure was produced. All 40 negative cases remain **NOT TESTED**.

The final seed stopped when a provider call yielded no valid token
measurement. Its 282,624-token reservation was retained. The transport did
not retain upstream HTTP status/body for that call; the exact provider
failure cause is unverified. Total measured usage was **2,742,851 tokens**;
the conservative total charged to the budget was **3,025,475 tokens**.
There were 69 provider calls and 15 synthetic session-health setup requests.
USD cost and contract-repair count remain unmeasured.

All five MCP group handshakes, runtime bundle hashes, read-only wire
accounting, and final PID/start-time cleanup checks passed. No live child
processes remained. The artifact scan found no Evren credential prefix.
Live namespace observations were retained for seeds 20261106 and 20261107;
the preflight namespace probe and preceding real integration isolation
checks also passed. `acceptance_passed=false`; holdout remains unevaluated.

## Provider configuration

Preflight now accepts `--provider-config` so an external operator-owned
configuration can supply the selected provider without editing the
repository configuration. The launcher accepts the broker-specific option
`options.apiKeyHeader`, restricted to `Authorization` (default) or
`X-API-Key`. The credential comes from the selected launcher environment
variable; the live driver supplied it through a hidden terminal prompt and
kept it in host memory. Provider headers and credentials are stripped from
the solver runtime.

The preparation regression suite passed **92 offline tests** and **4 real
local integration tests**, with no failures or skips. Ruff, graph update,
and repository layout checks passed. The added offline case verifies
external model selection, credential stripping, and invalid header denial;
existing transport tests cover both supported authentication headers.

## Evidence and next work

Canonical audit:
`/tmp/cco-work/full-agent-live-evren/run-8uetj0v1/acceptance.json`.
The same directory contains `REPORT.md`, the frozen contract, fresh
launches, budgets, native events, gate decisions, wire counts, verified
coverage exports, closure verification logs, and process observations.
`operator-acceptance.json` retains the original driver summary, including
its collector parsing error; the offline auditor corrected that error
without more provider or target requests.

Private operational scripts are under
`/tmp/cco-work/full-agent-live-evren/`: `operator.py`, `audit_completed.py`,
`observe_live.py`, and `finalize.py`. StateOps run:
`21f4db19-af68-4843-8683-b9e097c00863`.

Next implementation work is to reduce repeated planner context and provide
a bounded native bootstrap handoff that reaches worker execution within
the existing token contract. Safe provider HTTP-status diagnostics are
also needed before another paid benchmark. This run does not establish
M3/M4 acceptance or independent holdout performance.

## Bounded bootstrap follow-up — 2026-11-05

Native launches now select `brain.py plan --tool-profile broker`. The profile
validates phase and vector MCP tools against `full_agent_broker.CATALOG` and
uses a launcher-frozen catalog projection inside the isolated solver. Its
protocol requires the signed attempt ledger, without adding unavailable
memory tools. General operator profiles retain their existing inventories;
the broker profile rejects unsupported host/LLM plans.

The launcher writes `solver/specs.json` before OpenCode starts and supplies
the first rendered TaskSpec as ready-to-call `task` arguments. The prompt
requires Step 1 worker delegation, states that no prior program/session vault
exists in the fresh solver, prohibits exploratory filesystem searches, and
supplies the initialized host-owned synthetic session references. Summary
helpers use the concrete spec-file path.

Provider budget events retain `upstream_http_status`, exception class, and
validated numeric usage fields. Non-200 bodies and headers are withheld;
arbitrary usage extensions and exception text are excluded. Failed calls
retain their reservation and stop further admission.

Local verification passed **163 tests**, **zero failures and zero skips**:
104 launcher/acceptance/module regressions, 55 orchestration regressions,
and four real local integration tests. JUnit:
`/tmp/cco-work/full-agent-bootstrap-regression.xml`. Ruff, JS syntax, graph
update, and repository layout checks passed.

The single authorized Evren smoke seed **20261104 failed to verify worker
delegation**. It used a shortened 600-second ceiling with the existing
1,000,000-token / 300-HTTP ceilings and stopped after approximately 199 seconds.
One provider completion returned HTTP 200 and measured **2,032 tokens**.
The next call raised **ReadTimeout** after the broker's 180-second read timeout,
before returning an HTTP status or valid usage. Its **290,916-token reservation**
was conservatively charged, bringing the budget total to **292,948 tokens**.
The failed call's actual usage is unknown; it is not reported as measured cost.

No native tool gate or worker delegation occurred. All three HTTP requests
were synthetic session setup; read-only wire accounting matched. No signed
security coverage or verified closure was produced. Process cleanup and the
credential-prefix artifact scan passed. `status=budget_invalid`,
`delegation_passed=false`, and `acceptance_passed=false`; holdout remains
unevaluated. This run does not demonstrate whether the paid planner follows
the corrected bootstrap prompt. No additional live seed was launched.

Canonical smoke audit:
`/tmp/cco-work/full-agent-live-evren/run-0l0plnft/acceptance.json`.
Launch and safe provider diagnostics:
`/tmp/cco-work/full-agent-live-evren/run-0l0plnft/launches/native-i05i1j_w/launch.json`
and its sibling `private/budget.json`. StateOps run:
`40899cb3-8fd5-4925-8a86-b098b5794895`.

## ZenMux comparison — 2026-11-05

The operator authorized the same owned-lab seed through ZenMux. The public
catalog confirmed `deepseek/deepseek-v4.1-flash`; planner and worker selected
`zenmux/deepseek/deepseek-v4.1-flash`, using the OpenAI-compatible endpoint
`https://zenmux.ai/api/v1` with a host-only Bearer credential.

The first attempt received HTTP 200 but failed in the broker with
`UnicodeDecodeError`. ZenMux sends gzip responses; the broker had parsed
compressed raw bytes as JSON. `raw.read(..., decode_content=True)` now decodes
before JSON parsing and enforces the body ceiling on decoded bytes. Diagnostics
retain only an allowlisted content-encoding label. The correction passed
**168 tests with zero failures and zero skips**, including gzip/deflate
completion tests, a decoded-body size-limit test, and all four real local
integration tests with gzip provider responses. JUnit:
`/tmp/cco-work/full-agent-zenmux-regression.xml`. Ruff, graph update and repository
layout checks passed.

That initial attempt conservatively charged 28,440 tokens without valid usage.
The corrected retry therefore used a **971,560-token** ceiling, retaining the
600-second and 300-HTTP per-launch ceilings. Both attempts used seed 20261104.

| Attempt | Result | Tokens charged | Measured tokens | HTTP requests | Allowed worker delegations | Recon summary |
|---|---|---:|---:|---:|---:|---|
| Before gzip fix | budget_invalid | 28,440 | unknown | 3 | 0 | absent |
| After gzip fix | native_failed | 685,934 | 685,934 | 4 | 1 | done, two evidence pointers |

The corrected retry's **first native gate was an allowed `task` dispatch**.
Worker execution completed the read-only recon task and one real lab GET;
the other three requests were synthetic session setup. All **17 provider
calls** returned HTTP 200, gzip content, and valid measured usage. There was
no provider timeout. The retry ended after approximately **143 seconds**.
Both attempts together charged **714,374 tokens**, below the 1,000,000 total
ceiling; only 685,934 of those tokens have valid measurement.

**Bootstrap delegation and worker recon passed; full acceptance did not.**
The subsequent enum task was rejected as `blocked_task_spec`: offline replay
of its actual prompt returned `worker task lacks exact commands` because the
required `Commands:` section was absent. The planner then read prompt helper
code. Its next completion was refused with `BudgetError`; 285,626 tokens
remained, below the preceding prompt reservation of 328,620. The guard's
conservative prompt bound still prevents continued execution despite nominal
tokens remaining. The initial worker also incurred two
`blocked_missing_target` local-helper denials before completing its scaffold.

Wire accounting, read-only methods, process cleanup and credential-prefix
artifact scans passed. No signed security coverage or verified closure was
produced; all security cases remain untested. `acceptance_passed=false` and
holdout remains unevaluated. The remaining work is reliable rendered
TaskSpec dispatch and lower planner/worker context overhead.

Canonical corrected audit:
`/tmp/cco-work/full-agent-live-zenmux/run-_6gedl4m/acceptance.json`.
Launch, budget, native events and replayed task-contract error:
`/tmp/cco-work/full-agent-live-zenmux/run-_6gedl4m/launches/native-piaek6ph/`.
The pre-fix attempt is preserved at
`/tmp/cco-work/full-agent-live-zenmux/run-_upakzyb/acceptance.json`.
StateOps run: `60980d2b-634b-4de1-823f-19819bbd7206`.

## Host-rendered tasks and bounded context — 2026-11-05

The native planner now sends only `prompt="TaskSpec: recon-1"` (then the next
phase ID). `full_agent_tasks.NativeTasks` expands this pointer into the frozen
host-generated worker contract, including exact tools, commands, budgets,
synthetic references and summary/evidence paths. Legacy `Task: <id>` pointers
are also accepted, but all model-authored commands, targets, tools and resume
IDs are discarded. Phase dependencies, exact target identity, workspace
confinement and terminal summary validation remain enforced in code.

The host scaffolds each summary before dispatch. The native gate must replace
task arguments **in place**: assigning a new `output.args` object did not reach
the worker in OpenCode 1.18.35. Real integration now asserts that the worker
receives the expanded `Commands:` section, rather than just checking a gate
response. MCP admission and provider tool definitions are restricted to the
active phase's tools.

The staged runtime uses concise launcher-owned planner/worker policies and
`instructions=[]`, removing repeated ambient repository instructions. Planner
tools are restricted to `task` and `read`; source, directory and missing-vault
exploration is prohibited. Model context/output limits are capped at
32,768/4,096 tokens, with automatic compaction retaining 8,192 tokens and an
8,192-token buffer. Tool descriptions are shortened to 320 characters while
literal defaults, enums, constants, examples and argument constraints are
preserved. The broker does not truncate messages or tool-call arguments.
Conservative token admission remains unchanged; an admission rejection creates
no reservation. Safe request-size/admission diagnostics contain no message or
credential bodies.

One fresh ZenMux run used seed 20261104 with the remaining **285,626-token**
allowance, plus the existing 600-second / 300-HTTP per-launch limits:

| Measurement | Prior ZenMux run | Bounded-context run |
|---|---:|---:|
| First worker prompt tokens | 37,358 | 2,876 |
| First primary planner prompt tokens | 40,646 | 1,958 |
| Accepted worker delegations | 1 | 2 |
| Measured/charged run tokens | 685,934 | 197,357 |
| Provider calls | 17 | 27 |
| Target HTTP requests, including session setup | 4 | 16 |

First-request prompt reductions were **92.3% for worker** and **95.2% for
planner**. Total usage is not an equal-work comparison: the later run reached
both recon and enum. All 27 provider calls returned HTTP 200, gzip content and
valid usage. The first native gate was an allowed canonical worker task.
Recon completed; enum returned a partial summary. Read-only wire accounting,
process cleanup and credential-prefix artifact checks passed.

**Task dispatch and initial context reduction were verified live; full
acceptance remains false.** The enum summary used `integer`, `filename` and
`email-like marker` as ID-format labels and supplied `value` instead of
`example`. The schema rejected the output; subsequent repair attempts did not
advance the phase before token admission stopped the run. This is an output
contract failure despite successful upstream HTTP responses.

The follow-up host correction recognizes only explicit equivalent format
labels (`integer` → `int`, `filename` / `email-like marker` → `string`) and copies
an existing nonempty textual `value` into a missing `example`. Existing examples
and all status, step, evidence, finding and ownership assertions are preserved.
Unknown formats and missing/nontext examples remain invalid. Normalization
records contain changed field names, alias labels and before/after hashes;
they omit example values. Worker contracts now state these output requirements.

An **offline replay of the actual live summaries** in a separate workspace
verified that the corrected enum passes schema validation and permits the
canonical `access-3` dispatch. Original live artefact hashes remained unchanged.
The replay preserved enum `partial`, all blocked/not-tested steps, evidence and
finding assertions, and rejected an unknown-format negative control. It did
not execute access, prepare a signed handoff, validate any finding or establish
coverage/closure. The follow-up correction has not received another paid run.

Final local verification: **188 tests passed, zero failures/errors/skips**,
including all four real local integration cases. Ruff, JavaScript syntax,
repository layout and graph update passed. Canonical artefacts:

- Live audit: `/tmp/cco-work/full-agent-live-zenmux-context/run-taj8elc7/acceptance.json`.
- Native launch and safe diagnostics: `/tmp/cco-work/full-agent-live-zenmux-context/run-taj8elc7/launches/native-wrj9o53a/`.
- Replay audit: `/tmp/cco-work/full-agent-context-replay/replay-audit.json`.
- Final JUnit: `/tmp/cco-work/full-agent-context-final-regression.xml`.
- StateOps run: `32f43730-2a15-469a-9cce-971511894c4d`.

Cumulative ZenMux budget charge is **911,731 tokens**, including the initial
28,440-token unmeasured reservation; **88,269 tokens** remain under the original
1,000,000-token aggregate ceiling. No additional paid seed was launched. Full
signed coverage, verified closure and independent holdout remain unproven.

## Single enum-fix seed preparation - 2026-11-05

Prepared one follow-up for seed **20261104**, with limits of **88,269 tokens,
600 seconds and 300 target HTTP requests**. The aggregate ceiling remains
1,000,000; the prior 911,731 charge includes the initial unmeasured 28,440-token
reservation. That reservation is already charged, not additional available
budget. No refund, ceiling increase or automatic paid retry is authorized.

**At preparation time, the new live attempt had not started.** No ZenMux credential was present in
the current launch environment. No credential stores or `.env` files were read.
The operator can run the prepared driver from a terminal using hidden `getpass`
input, or supply `ZENMUX_API_KEY` / `CCO_BENCHMARK_API_KEY` in its launch
environment. The driver refuses an insecure echoed-input fallback.

Fresh preflight passed all five checks: OpenCode, bubblewrap, loopback socket,
Chromium and isolated solver namespace. It froze 206 runtime files from current
code. The driver generates another fresh preflight on execution; it never
reuses an earlier runtime snapshot. Only seed 20261104 is dispatched, and an
exclusive single-use claim prevents a second live attempt.

The repository and global scope files name other targets. The launcher supplies
the active scope for this explicitly authorized owned lab. The driver checks
the staged scope and read-only policy against the exact ephemeral loopback
origin before session setup or provider/target traffic. Offline checks verified
the staged policy and rejected four invalid origins; actual live origin
verification remains pending until launch.

The remaining budget may prevent the requested enum/handoff verification.
An offline calculation using the prior run's recorded prompt sizes and measured
usage shows that repeating that trajectory cannot reach terminal enum under
88,269 tokens. The new model trajectory is unknown. The driver retains the
existing conservative admission guard and does not increase the limit.

Preparation made **zero provider calls and zero target HTTP requests**.
System health passed 7/7; the driver compiled, Ruff passed, and its measurement
parser was checked against existing live artifacts without modifying them.
The completed 188-test implementation suite was not repeated. No launcher or
TaskSpec implementation changes were needed in this continuation.

Prepared artifacts under `/tmp/cco-work/full-agent-live-zenmux-enum-fix/`:

- `preparation.json` and `preflights/preflight-gl5kzrhw/preflight.json`.
- `run.py` and `README.md`: single-use launch with environment/getpass credentials.
- `driver-checks.json`: offline scope and measurement checks.
- `budget-feasibility.json`: conditional prior-trajectory budget analysis.

The collector records canonical task gates, summary schema results, real handoff
tool artifacts, prompt/usage/admission diagnostics, wire accounting, signed
coverage, closure verification and process cleanup. Actual handoff consumption
requires direct consumer evidence; neither a schema check nor access dispatch
alone establishes it. StateOps run remains
`32f43730-2a15-469a-9cce-971511894c4d`. Full acceptance is **false**, holdout is
unevaluated, cumulative charge is unchanged at **911,731**, and **88,269 tokens**
remain. USD cost is unknown.

## Single enum-fix seed result - 2026-11-05

The prepared driver subsequently executed the one authorized seed, **20261104**.
It used a fresh preflight (`preflight-t165dnre`), the current code, and the exact
owned origin `http://127.0.0.1:44663/`. Scope and read-only policy were verified
before traffic; the final runtime inventory and source hashes matched. Limits
remained **88,269 tokens, 600 seconds and 300 HTTP requests**.

**This run did not reach enum, so it did not live-test the latest enum fix.**
The first gate accepted canonical `recon-1`; the native event retained the
host-expanded worker contract with exact tools and commands. The worker made
13 GET requests, then hit conservative token admission before saving a terminal
summary. Recon remained an `in-progress` skeleton with no summary evidence.
A subsequent planner attempt to dispatch recon again was denied by the phase
gate. Enum, real handoff preparation/consumption and `access-3` were not executed.
No summary normalization was applied. The planner's suggestion that prompt
expansion caused the failure is not established: expansion was the intended
host behavior, and the deterministic admission diagnostics identify the block.

At the rejected worker completion, **53,903 tokens remained**. Recorded message
and tool sizes alone imply a conservative prompt bound of at least **56,660
tokens**, before additional framing fields and output. Admission rejected it
as `bounded_prompt_does_not_fit`, without reserving tokens or contacting the
provider. Three smaller planner completions then reported the block and stopped.
The process exited with code 0 and status `native_finished_unverified` after
**92.36 seconds**; this status does not indicate successful task completion.

| Measurement | Result |
|---|---:|
| Accepted canonical worker tasks | 1 (`recon-1`) |
| First primary planner prompt | 1,930 tokens |
| First worker prompt | 2,834 tokens |
| First auxiliary prompt | 1,205 tokens |
| Measured prompt / completion tokens | 41,358 / 4,193 |
| Measured and charged run tokens | 45,551 |
| Provider calls | 11, all HTTP 200 / gzip / valid usage |
| Target HTTP requests | 16 GET: 3 setup + 13 worker |
| Signed coverage events / verified closure | 0 / no |

Wire accounting and read-only methods matched. Process cleanup was verified;
no tracked live children remained. The provider credential-prefix scan of 630
generated artifact files found no matches, excluding private state and
credential stores. No additional live seed was launched: another launcher
invocation encountered the already-active single-use claim and was refused
before traffic. The existing run was observed and audited to completion.

The cumulative conservative ZenMux charge is now **957,282 tokens**, including
the unchanged **28,440-token unmeasured reservation**. **42,718 tokens remain**
under the 1,000,000 aggregate ceiling. USD cost is unknown. There were no paid
retries, reservation refunds or ceiling increases. **Full acceptance remains
false**; signed security coverage, verified closure and holdout remain unproven.
All eight positive cases are unproven, and all eight negative cases are
**NOT TESTED**. Terminal enum schema and real handoff consumption remain
**NOT TESTED**, rather than evidence that the enum correction failed.

Canonical artifacts:

- Driver result: `/tmp/cco-work/full-agent-live-zenmux-enum-fix/acceptance.json`.
- Post-run artifact audit: `/tmp/cco-work/full-agent-live-zenmux-enum-fix/result-audit.json`.
- Native launch: `/tmp/cco-work/full-agent-live-zenmux-enum-fix/launches/native-gjsnr6yp/`.
- Exact scope: `/tmp/cco-work/full-agent-live-zenmux-enum-fix/scope-verification.json`.
- Credential artifact audit: `/tmp/cco-work/full-agent-live-zenmux-enum-fix/credential-artifact-audit.json`.
- StateOps run: `32f43730-2a15-469a-9cce-971511894c4d`.

This continuation changed the acceptance document and added offline audit
artifacts; no launcher implementation changed and the completed implementation
regressions were not repeated. Further work should address bounded recon
completion and terminal-summary preservation offline before another authorized
paid attempt. The remaining allowance does not establish that a fresh end-to-end
run can reach enum, and no automatic retry is planned.

## Offline admission diagnostics and interruption preservation - 2026-11-05

The next implementation slice preserves discovery scope, tool catalogs, phase
plans, HTTP limits and the existing token admission coefficient. It adds exact
numeric diagnostics for serialized request bytes, prompt upper bound, output
allowance and remaining capacity. Successful provider budget events retain the
prompt bound and reserved output alongside measured usage. No prompt bodies,
credentials or private provider response bodies are added to these diagnostics.
The engineering bound remains `2 * request_bytes + 4096`; these measurements do
not establish a tokenizer guarantee or justify relaxing the ceiling.

A `bounded_prompt_does_not_fit` rejection now stops further broker admission
and terminates the native session as `token_admission_exhausted`. It creates no
reservation and is not mislabeled invalid provider usage. The supervisor
finalizes the active task after the native process tree exits, avoiding races
with worker file writes. It preserves valid terminal summaries byte-for-byte.
For an unfinished draft, it archives the original bytes privately and writes a
schema-valid `blocked` summary with a host interruption receipt. Existing valid
draft evidence, findings and step states are retained; malformed or wrong-target
drafts are archived without promoting their assertions. Unsafe symlink paths
remain untouched and produce a safe finalization error record.

Host tool artifacts now carry their task ID. Interruption receipts include
only that task's actual artifact paths and hashes, without copying private
request/response bodies into the solver. The receipt explicitly makes no
security-validation or acceptance claim. A blocked summary prevents phase
advancement; shutdown does not manufacture a successful recon or enum result.

Offline analysis of the last paid run separated its 45,551 measured tokens:

| Role | Calls | Measured tokens |
|---|---:|---:|
| Auxiliary | 1 | 1,228 |
| Planner | 4 | 13,206 |
| Recon worker | 6 | 31,117 |

Three planner calls after the worker admission rejection accounted for 11,185
of those tokens. This is an observation from the old run, not a claim of live
savings or equivalent discovery performance in the new code.

Verification passed **183 distinct test cases**, including **five real local
OpenCode integration tests**, with zero failures/errors/skips in the successful
regression reports. The new integration scenario uses a scripted loopback
provider to enlarge a subsequent prompt after a real lab GET. It verifies the
admission stop, no further provider calls, process cleanup, a valid blocked
summary and the preserved tool artifact. Its synthetic token usage is not a
model-performance or tokenizer calibration benchmark. Existing normal-session,
invalid-usage, deadline and interruption integration cases also passed.

A separate offline replay applied the finalizer to a copy of the actual live
recon skeleton. All **13 worker tool artifact references** were preserved, the
original summary bytes were archived, the blocked summary passed validation,
and enum dispatch was denied. Original live artifact hashes were unchanged.
This replay made no provider or target calls and establishes no handoff,
security coverage, closure or live acceptance.

Artifacts:

- Verification: `/tmp/cco-work/full-agent-interruption-audit/verification.json`.
- Budget breakdown: `/tmp/cco-work/full-agent-interruption-audit/budget-analysis.json`.
- Real-draft replay: `/tmp/cco-work/full-agent-interruption-audit/live-draft-replay-el9f200e/replay-audit.json`.
- Unit/module/orchestration JUnit: `/tmp/cco-work/full-agent-interruption-unit.xml`.
- Final preflight regression JUnit: `/tmp/cco-work/full-agent-interruption-preflight-final.xml`.
- Local integration JUnit: `/tmp/cco-work/full-agent-interruption-integration.xml`.

No new ZenMux calls were made. The cumulative charge remains **957,282** and
the allowance **42,718 tokens**. Full acceptance remains false; live enum,
real handoff consumption, signed coverage, closure and holdout still require
their own evidence. A further paid run was not started.

## Native enum handoff and request accounting - 2026-11-05

This slice exercises the enum correction through actual local OpenCode workers,
the production broker and MCP executors, with a scripted loopback provider.
Each run stages a fresh runtime and exact ephemeral loopback scope. Synthetic
session references stay in the host-managed session store. No ZenMux or other
paid provider is used, and no real provider credential is read.

The new positive scenario reads the real lab entry response and derives its
routes, parameter names and example values from that response. The enum summary
uses `integer` and `filename` aliases with existing textual `value` fields.
The host must normalize them to `int` and `string`, preserve those values as
examples, and pass the resulting summary to the actual `ledger_prepare_handoff`
tool. Ownership stays unknown (`own_ids_json=[]`), enum stays `partial`, and its
ownership step stays `not_tested`.

Access admission now requires a private host receipt from a successful handoff
tool execution. It binds the discovery task, exact target, normalized input
summary, producer artifact, packet and object pool by hash. Missing receipts,
modified summaries or files, symlinks and stale state prevent access dispatch.
The existing handoff state/attempt fingerprint checks remain in force. These
receipts establish host execution provenance; they are not signed security
validation or closure evidence.

The access worker must read the actual packet and pool through native `read`
tool results, verify their fingerprint, and write a consumption receipt. It
then invokes the real `hunter_run_web_loop(live=False)` and checks its successful
PLAN result before writing a `partial` access summary. Security validation
remains `not_tested`. Negative scenarios supply a malformed enum summary or
omit handoff preparation; neither may reach an access worker.

The initial integration exposed duplicate policy accounting: the native gate,
broker, session helper and transport could count the same request repeatedly,
triggering stuck detection before a session refresh completed. Native MCP
dispatch now enforces the catalog and active TaskSpec, while the broker performs
current static policy checks without debiting request counters for supported
network tools. Full scope, grant, method, header, rate and stuck checks still run
immediately before actual requests. Unsupported transports remain denied.
Standalone session checks install the same transport guard; calls with an
inherited guard reuse it. The internal preview flag cannot be selected through
model tool arguments. Local tools retain ordinary invocation accounting.

No threshold, discovery scope, token admission coefficient, task tool catalog,
or paid allowance was reduced to make these checks pass. Policy/session tests
verify scope and revoked-grant denial, one counter debit per transport request,
and that injecting a preview flag into tool arguments does not bypass accounting.

Verification passed **393 distinct test cases**, including **eight real native
OpenCode integration cases** (nine launches, because the normal-session case
uses two fresh launches). The final per-test results have zero failures,
errors or skips: 385 policy/session/validator/wire/orchestration/module/preflight
cases, five existing native cases, and all three new handoff cases. Results are
combined by each testcase's latest outcome; the original failed attempts remain
in their reports and are listed in the verification artifact.

| Final local scenario | Accepted tasks | Handoff / access result | Target HTTP |
|---|---|---|---:|
| Valid enum | recon-1, enum-2, access-3 | Host handoff, native reads and actual PLAN pass | 8 |
| Malformed enum | recon-1, enum-2 | Real handoff rejects schema; access denied | 8 |
| Missing handoff | recon-1, enum-2 | Valid enum alone cannot admit access | 8 |

In each scenario, eight real target requests match eight full transport policy
decisions: three setup checks, one recon GET, one enum GET and three session
refreshes. Preview checks add no request debits. The first native gate is an
accepted canonical recon task. The successful enum preserves its partial
status and unknown ownership, and the access summary remains partial with
security validation NOT TESTED. All three scenarios verify process cleanup,
isolated namespaces and absence of test credentials from solver-visible output.

Artifacts:

- Verification: `/tmp/cco-work/full-agent-handoff-audit/verification.json`.
- Combined latest JUnit: `/tmp/cco-work/full-agent-handoff-audit/latest-results.xml`.
- Native handoff JUnit: `/tmp/cco-work/full-agent-handoff-verified.xml`.
- Broader regression JUnit: `/tmp/cco-work/full-agent-handoff-regression.xml`.
- Existing five native cases: `/tmp/cco-work/full-agent-handoff-integration-serial.xml`.
- Positive handoff: `/tmp/cco-work/full-agent-integration/handoff-a7upj6qc/handoff-acceptance.json`.
- Malformed summary: `/tmp/cco-work/full-agent-integration/handoff_bad_summary-0jn46d3e/handoff-acceptance.json`.
- Missing handoff: `/tmp/cco-work/full-agent-integration/handoff_missing-kvx3cln0/handoff-acceptance.json`.

An earlier concurrent integration
attempt exhausted its 120-second startup deadline after the three setup GETs,
before any provider call or delegation. A sequential handoff attempt reached
enum but also exceeded the 120-second fixture deadline. The new three-worker
handoff scenarios now use a 600-second local fixture timeout; the existing
normal and deadline test limits and the production/paid limits are unchanged.
This extra fixture time is not evidence of latency or paid-model performance.
Both failed artifacts remain at
`/tmp/cco-work/full-agent-integration/handoff-1ed_yaip/` and
`/tmp/cco-work/full-agent-integration/handoff-1hibt8ie/`.

A 300-second attempt completed host handoff and consumer reads but timed out
during PLAN while the graph update was also running. With graph work suspended,
the next real run (`handoff-f97ko277`) completed the full native chain and PLAN.
Its post-run test exposed an incorrect fixture assumption: rate reservations
expire from a sliding window and cannot serve as the lifetime request total.
The permanent audit contains exactly six full session-check decisions and two
full curl decisions, matching eight target requests. The test now checks that
permanent audit and recorded probes, while bounding surviving window counters.
No production counter retention or threshold changed. The completed run's host
receipt, summary, packet and pool hashes and actual PLAN result were separately
verified in `/tmp/cco-work/full-agent-handoff-audit/completed-run-artifact-review.json`.

Ruff, Node syntax, repository layout and the final `graphify update .` passed.
The verification artifact includes source hashes, native artifact paths and
superseded test attempts. StateOps and scan history record this slice under run
`32f43730-2a15-469a-9cce-971511894c4d`.

The conservative ZenMux charge remains **957,282**, including the unchanged
**28,440-token reservation**, and the remaining allowance is **42,718 tokens**. USD cost remains
unknown. Full acceptance is **false**. Local scripted-provider integration does
not establish paid-model performance, live enum completion, signed security
coverage, verified closure, or holdout success.


## Native read-only signed validation - 2026-11-06

The `handoff_validation` scenario now selects the redirect parameter from the
actual enum summary read through the native tool. Its loopback-only handler
returns a normal 200 landing page for local destinations on `/go`, keeping
surface discovery on the observed parameterized endpoint. External canaries
and fresh validator sentinels receive the original lab's real 302 Location
response. No external destination is followed, and no validator result or
signature is manufactured by the scripted provider.

The previous first-link selection chose `/search`, whose multi-class fuzz
sequence reached the default ten-probe stuck limit before validation. Changing
query values does not create distinct stuck-detector paths. A first redirect
attempt retained the original local redirect; discovery consequently reached
the entry page and the one-endpoint fuzz allowance selected an unrelated route.
That failed attempt is retained at
`/tmp/cco-work/full-agent-integration/handoff_validation-5a6pjune/` and in
`/tmp/cco-work/full-agent-signed-validation.xml`.

The final scenario allows one surface record, one signaled validation and zero
signal-free candidate samples, with a 0.2-second fuzz pace. The existing
600-second local fixture deadline, 100-request integration ceiling, production
stuck threshold, rate limits, scope checks, transport accounting and paid
allowance remain unchanged. The test requires a successful LIVE result without
errors or stop reasons, confirmed request/response evidence, trusted coverage,
and direct verification of each persisted validator artifact against the fresh
run's public trust bundle. It then checks native report delegation, the signed
attempt ledger and unsealed checkpoint, partial phase summaries, isolated
namespaces and process cleanup.


The targeted command passed: **1 passed in 50.82 seconds**, with zero failures,
errors or skips. Ruff and the repository layout check passed. The completed run
has four native delegations, one confirmed `open_redirect` validation with
request/response evidence and a verified `ed25519:v1` signature, and **18 actual
HTTP requests** matching the shared budget (eight setup/recon/enum requests and
ten LIVE requests). Its permanent policy audit has zero stuck-detector blocks;
the `/go` bucket contains five probes, below the unchanged threshold of ten.
The signed attempt ledger contains one trusted record with no integrity errors;
its checkpoint remains unsealed. Namespace isolation and process cleanup passed.

Artifacts:

- Passing JUnit: `/tmp/cco-work/full-agent-signed-validation-final.xml`.
- Verification: `/tmp/cco-work/full-agent-signed-validation-audit/verification.json`.
- Native evidence: `/tmp/cco-work/full-agent-integration/handoff_validation-sjay_6jl/signed-access-acceptance.json`.
- LIVE output: `/tmp/cco-work/full-agent-integration/handoff_validation-sjay_6jl/runs/native-gqmd7x9n/solver/access/live-result.json`.
- Signed validator artifact: `/tmp/cco-work/full-agent-integration/handoff_validation-sjay_6jl/runs/native-gqmd7x9n/private/state/validations/6fa9555f2a6b694655e2c8e4e62aab48_open-redirect.json`.

No paid provider calls were made. The unchanged conservative ZenMux charge is
**957,282 tokens**, with **42,718 tokens** remaining. This establishes native
local signed-validation and ledger plumbing with a scripted loopback provider.
Full paid acceptance remains **false**; remaining security coverage, verified
closure and holdout success remain unproven.

The required AST-only `graphify update .` also passed with zero LLM calls.
StateOps and scan history record this slice under run
`ee1020f0-9d5e-49d3-83d3-7f38d645cf18`.

## Native negative controls and closure gate - 2026-11-06

The `handoff_negative` scenario extends the actual local OpenCode worker chain,
production broker and MCP executors. The worker selects `/safe/go?next=/` from
the enum summary returned by native `read`. One bounded, signal-free candidate
sample reaches the real redirect validator. Discovery's empty parameter
placeholder receives a non-redirecting landing page; external redirect
sentinels are rejected by the original safe lab handler and are never followed.
The positive `/go` scenario retains its original external redirect behavior.

The test requires an actual `UNCONFIRMED` validation with completed transport
and request evidence, a persisted `ed25519:v1` artifact in `validations`, and
signature verification against the fresh run's trust bundle. Its coverage
dimension must be `tested_clean` for the observed endpoint, `next` parameter
and acting identity. Other dimensions remain `not_tested`; no finding is
confirmed by the negative control.

The report worker invokes the real `kali-tools_ledger_checkpoint(seal=True)`.
The test requires `sealed=False`, a nonzero closure check, explicit rejection
of untried vectors, no closure pointer, and no `closure.json`. Partial summaries
and remaining `not_tested` steps are preserved. This verifies closure rejection;
successful closure remains unproven.

Through native `read` and `edit`, the worker separately changes the signed
attempt record's validation verdict and corrupts its signature while preserving
the signature's syntax. Each real `kali-tools_ledger_coverage` call must return
`integrity_errors` and `trusted_records=0`. After each edit the worker restores
the original bytes; a final coverage call must match the clean baseline.
Modified validator-artifact copies also fail direct signature verification,
while the original persisted validator artifact remains intact. These checks
cover signed attempt-record tampering and validator-artifact integrity; they
do not assert that ledger coverage itself revalidates referenced artifact bodies.

Two initial fixture attempts are retained. The first lacked a usable empty
redirect baseline and produced no validation. The second proved clean coverage,
closure rejection and verdict tampering, but a malformed signature was rejected
by the ledger schema before coverage could return integrity errors. The final
fixture uses a syntactically valid corrupted signature. Neither correction
changes production validation, closure, policy, rate or budget enforcement.

Verification passed **2 native integration cases in 106.02 seconds**, including
the existing positive signed validation and the new negative control, with zero
failures, errors or skips. The negative run has **22 actual HTTP requests**
matching the shared budget, one trusted clean validation, closure check exit
**2**, `record-hash mismatch` for verdict tampering and `signature mismatch`
for signature tampering. Isolation and process cleanup passed. Preflight passed
**130 tests**; Ruff and the repository layout check passed.
The required AST-only `graphify update .` completed successfully; its output is
preserved at `/tmp/cco-work/full-agent-negative-graphify.log`.

Commands and artifacts:

- Native verification: `PYTHONPATH=scripts pytest tests/test_full_agent_integration.py -k 'negative or readonly_validation' -v`.
- Native JUnit: `/tmp/cco-work/full-agent-negative-controls-final.xml`.
- Preflight: `PYTHONPATH=scripts pytest tests/test_full_agent_preflight.py -q`.
- Preflight JUnit: `/tmp/cco-work/full-agent-negative-preflight.xml`.
- Negative evidence: `/tmp/cco-work/full-agent-integration/handoff_negative-l_arpgcx/negative-controls-acceptance.json`.
- Superseded attempts: `/tmp/cco-work/full-agent-negative-controls.xml` and `/tmp/cco-work/full-agent-negative-controls-retry.xml`.

StateOps run: `e96ecc44-9117-4b86-b8b6-a7b5d29856f6`.

No paid provider calls were made. The conservative ZenMux charge remains
**957,282 tokens**, with **42,718 tokens** remaining. All native model responses
come from the scripted loopback provider; their usage is synthetic. Full paid
acceptance remains **false**, and verified closure and holdout success remain
unproven.

## Native successful closure and integrity verification - 2026-11-06

The new `handoff_closure` scenario completes the actual local OpenCode
recon, enum, access and report worker chain through the production broker and
MCP executors. The model responses come exclusively from the scripted loopback
provider. The real read-only redirect validator supplies confirmed
request/response evidence and a fresh `ed25519:v1` artifact; the solver has no
host signing authority.

All **eight default closure vectors remain present**. The native worker uses
`brain.py hypotheses mark --validation-id` to close `authn-session` with the
actual signed `open_redirect` evidence, using the existing deterministic alias.
The other seven vectors are explicitly parked as `not_applicable`, with
`not_tested: auth:not-required:` attestations explaining that this public,
redirect-only slice did not exercise them. The closure preserves those seven
NOT TESTED justifications. These are audited exclusions, not evidence of clean
coverage or authentication recovery. No vector is removed or assigned a
manufactured validation result.

The report worker records the observed validator ID and verdict through the
real signed attempt ledger, then invokes
`kali-tools_ledger_checkpoint(workdir, seal=True)`. It returns **`sealed=True`**
and **`check_exit=0`**, creating a **gate-produced, gate-signed `closure/2`
`closure.json`**. The test verifies its public signature, canonical target and
workdir, all terminal vector states, scope/policy binding, validator ID and hash,
and one trusted attempt record with zero signature or chain errors.

Inside the actual solver sandbox, with its pinned read-only public trust bundle,
the native worker runs `brain.py closure verify --workdir <workdir>` as a fresh
CLI subprocess. It returns **exit 0** and
`closure verify: verified (trusted=1/1)`. Post-seal checks require these results:

| Mutation | CLI exit | Detected condition |
|---|---:|---|
| Change closure payload target | 2 | Signature mismatch |
| Corrupt closure signature, preserving its syntax | 2 | Signature mismatch |
| Change referenced attempt verdict | 2 | Invalid attempt ledger |
| Corrupt attempt signature, preserving its syntax | 2 | Invalid attempt ledger |
| Remove the referenced attempt record | 2 | Signed ledger summary drift |

After each mutation, the worker restores the original closure and attempt bytes
and requires a fresh verification to return exit 0. The final native artifacts
retain their original bytes. Enum, access and report summaries remain valid and
partial, with broader security coverage explicitly NOT TESTED. Namespace
isolation and process cleanup pass; **18 actual target HTTP requests** match
the shared budget. Production scope, rate, stuck, token and closure gates are
unchanged.

The requested native selection passed **3 tests in 84.97 seconds**, with zero
failures, errors or skips, covering successful closure, existing closure
rejection and negative controls, and positive read-only signed validation.
Preflight passed **130 tests in 2.75 seconds**. Ruff, repository layout and the
local system health check passed. The health check reported seven successful
checks, including MCP registration and SQLite access.

Two initial test attempts successfully sealed and exercised native tamper
detection but exposed fixture assertions: closure stores a canonical target
without the launch URL's trailing slash, and a partial report needs an explicit
unfinished step. The corrected fixture checks canonical target identity and
retains a broader-security-coverage NOT TESTED step. Both superseded JUnit
reports and native artifacts remain available; no production gate was relaxed.

Commands and artifacts:

- Native verification: `PYTHONPATH=scripts pytest tests/test_full_agent_integration.py -k 'closure or negative or readonly_validation' -v`.
- Passing native JUnit: `/tmp/cco-work/full-agent-closure-verified.xml`.
- Preflight: `PYTHONPATH=scripts pytest tests/test_full_agent_preflight.py -q`.
- Preflight JUnit: `/tmp/cco-work/full-agent-closure-preflight.xml`.
- Layout: `python3 scripts/check_repo_layout.py`.
- Graph maintenance: `graphify update .`; output at `/tmp/cco-work/full-agent-closure-graphify.log`.
- Closure evidence: `/tmp/cco-work/full-agent-integration/handoff_closure-fu3d_t95/closure-acceptance.json`.
- Sealed closure: `/tmp/cco-work/full-agent-integration/handoff_closure-fu3d_t95/runs/native-hs39rwup/solver/closure.json`.
- Native CLI integrity results: `/tmp/cco-work/full-agent-integration/handoff_closure-fu3d_t95/runs/native-hs39rwup/solver/report/closure-integrity.json`.
- Verification summary: `/tmp/cco-work/full-agent-closure-audit/verification.json`.
- Superseded reports: `/tmp/cco-work/full-agent-closure-native.xml` and `/tmp/cco-work/full-agent-closure-native-final.xml`.

StateOps run: `85b03a19-55bf-4246-80d2-7b5c706dac4a`.

**Zero paid provider calls** were made. The conservative ZenMux charge remains
**957,282 tokens**, with **42,718 tokens** remaining. This establishes
successful native local closure and post-seal integrity verification. Full
paid acceptance remains **false**; broader security coverage, live paid-model
closure and holdout success remain unproven.

The required AST-only `graphify update .` completed successfully with zero LLM
calls, rebuilding 8,922 nodes and 20,477 edges. Scan history records the checks
and their artifacts alongside the StateOps run.

## Native held-out seed isolation and closure - 2026-11-06

This slice runs the real native recon, enum, access and report chain twice:
first on frozen comparison seed **20261104**, then on **20261105**. Each launch
has a fresh preflight, solver workspace, private state, planner/worker sessions,
public trust bundle and signed validation evidence. Both runs use only the
scripted loopback provider and actual local MCP executors. The shared closure
assertions retain all eight vectors, bind the real redirect validation to
`authn-session`, and preserve the seven explicit NOT TESTED attestations.

Both seeds produce a gate-signed closure with `sealed=True`, `check_exit=0`
and native CLI verification exit **0**. Each also reruns all five closure/attempt
tamper checks, requiring exit **2** and successful verification after restoring
the original bytes. Each seed records **18 actual HTTP requests**, matching its
fresh shared budget. The two native session-ID sets are disjoint, and the
closure signing-key IDs, validator IDs and validator content hashes differ.
Namespace isolation and process cleanup pass for both launches.

The second run's actual native isolation probe attempts to open the first
run's closure, signed attempts, hypotheses, object pool, enum/access/report
summaries, LIVE result, integrity report and persisted validator artifacts.
These existing files are unreadable inside the new solver sandbox. The probe
also checks previous native events and session state, plus the host-only
comparison manifest, JUnit evidence and current launch manifest. Host checks
confirm that the tested paths exist; missing files cannot satisfy these controls.
The fixture now checks solver-visible output for previous synthetic credential
canaries as well as current ones, without reading any real credential store.

Host verification under the second run's real public trust bundle rejects the
first run's closure, attempt records and validator artifact. Switching back to
the original run's public trust verifies all three again. Hashes of **27 prior
public workspace and validation files** remain unchanged after the second launch. This establishes
run-specific signing provenance and absence of prior-result modification,
alongside actual native read denial.

The acceptance contract explicitly states that **seed variation is not an
independent holdout family**. This lab's anonymous entry links are identical
across these two seeds. The test therefore verifies fresh launch/evidence
isolation and records `independent_family_holdout=not_evaluated`; it does not
claim new-family discovery performance. The unchanged real holdout contract
still requires at least three families, 24 positives and 24 negatives, overall
recall of 0.70, per-family recall of 0.50 and negative coverage of 0.90.
Neither synthetic provider usage nor the comparison fixture supplies those
measurements. Both launch manifests retain `acceptance_passed=false` and
`holdout=not_evaluated`.

Verification passed **4 native tests in 149.74 seconds**, covering five real
launches: the two-seed isolation scenario and the existing signed validation,
negative-control/closure rejection, and successful closure scenarios. There
were zero failures, errors or skips in the final report. Preflight passed
**130 tests in 1.96 seconds**; Ruff, repository layout and the local system
health check passed. No production catalog, scope, approval, rate, budget or
closure rule changed.

The first attempt completed both native closures but failed a fixture assertion
that anonymous entry links would differ by seed. The corrected assertion
preserves their observed equality and checks distinct real validator evidence
instead. That initial failed report and its two completed native runs remain
available; it is not counted as a passing test.

Commands and artifacts:

- Native verification: `PYTHONPATH=scripts pytest tests/test_full_agent_integration.py -k 'holdout or closure or negative or readonly_validation' -v`.
- Passing native JUnit: `/tmp/cco-work/full-agent-holdout-native-final.xml`.
- Preflight JUnit: `/tmp/cco-work/full-agent-holdout-preflight.xml`.
- Seed isolation evidence: `/tmp/cco-work/full-agent-integration/handoff_closure-kli8w5s1/held-out-seed-acceptance.json`.
- First seed closure evidence: `/tmp/cco-work/full-agent-integration/handoff_closure-zo_7wmwy/closure-acceptance.json`.
- Second seed closure evidence: `/tmp/cco-work/full-agent-integration/handoff_closure-kli8w5s1/closure-acceptance.json`.
- Verification summary: `/tmp/cco-work/full-agent-holdout-audit/verification.json`.
- Health check: `/tmp/cco-work/full-agent-holdout-healthcheck.json`.
- Graph maintenance: `graphify update .`; output at `/tmp/cco-work/full-agent-holdout-graphify.log`.
- Superseded native JUnit: `/tmp/cco-work/full-agent-holdout-native.xml`.

StateOps run: `21b52055-9324-4029-af95-fe82bd3f5a9a`.

**Zero paid provider calls** were made. The conservative ZenMux charge remains
**957,282 tokens**, with **42,718 tokens** remaining. Native seed isolation and
signed closure pass; full paid acceptance, the seven untested security vectors
and independent-family holdout performance remain unproven.

The required AST-only `graphify update .` passed with zero LLM calls, rebuilding
8,926 nodes and 20,486 edges. StateOps and scan history retain the verification
summary and superseded attempt alongside the final passing results.

## Independent holdout infrastructure and read-only API family — 2026-11-06

The first registered independent family is **`readonly-api-access-control`**,
implemented by a separate **`readonly-api-access/1`** service. It does not import,
wrap, rename or reuse the comparison lab's handlers. Its only application
operations are an account-scoped index and opaque, owned record GETs. There are
four fresh synthetic member accounts, eight positive owner-check omissions and
eight secure negative records. Negative handlers either return 403 or return
200 with the private record redacted. An anonymous record read returns 401.
Record IDs and handler assignments are generated privately; bearer credentials
and record contents are fresh synthetic data. No external target is contacted.

`scripts/full_agent_holdout.py` supplies the host-only registry, frozen family
selection, replay checks, evidence scorer and aggregate contract checks.
Preflight accepts `--holdout-family` and `--holdout-seed` together. The selection
binds the registered identity, version, seed, lab source hash and evaluator hash.
The production launcher replays these bytes before execution and rejects a
different seed, unknown/renamed family, changed source or weakened contract.
The measured comparison baseline remains a separate prerequisite. Independent
selection does not repurpose comparison seeds or alter its acceptance criteria.

The launcher stages the exact ephemeral loopback origin and the existing
read-only policy before traffic. It starts the registered service, production
broker, real native OpenCode planner/workers and production MCP subprocesses.
Only the loopback model responses are scripted. Sessions stay in the encrypted
host vault; the solver receives references and discovers owned URLs and record
relationships through actual HTTP. The solver is never given an object list,
handler verdict, truth file, expected case count or seed.

Discovery and validation use `hunter_run_web_loop` with two supplied synthetic
identities per bounded call. These calls run the existing ownership discovery,
`validate_idor`, signed validator persistence and signed coverage pipeline.
Each measured record is compared under its owner and one different test
identity. Confirmed access also has an actual anonymous baseline. This measures
horizontal object authorization; it does not claim every possible account pair,
function/role authorization, state-changing authorization or general API coverage.
The scripted solver uses a generic validation ceiling rather than the expected
number of cases. A native local helper waits 60 seconds between groups to
respect the existing rolling rate limit. No rate or stuck-detector exemption,
catalog extension, raw credential exposure or signing shortcut was introduced.

The scorer joins persisted Ed25519 validator evidence, signed coverage events,
production executor run IDs and the lab's actual HTTP transcript. It requires
current scope/policy binding, the exact origin/resource, distinct bound test
identities, successful owner/attacker controls, response lengths and response
hashes. A confirmed outcome requires the owned marker in the unauthorized
response; a clean outcome requires its absence. Missing, inconclusive, stale,
tampered or unmatched evidence receives no credit. Claimed confirmations on
negative cases count as false positives even if supporting evidence is missing.
The FP denominator is tested or positively claimed negative cases; untested
unclaimed negatives cannot dilute it. Outcomes retain validation IDs, signed
artifact paths/hashes and matching server request sequence numbers.

The native report phase records actual validation attempts and trusted
session-recovery records for the seven parked vectors. The latter cite the real
`session_vault_check` outputs, which the host auditor compares against executor
receipts. `authz-idor` is confirmed by matching signed IDOR evidence. The seven
other vectors remain explicitly **NOT TESTED**, with `auth:recovered` attestations
and corresponding trusted ledger records. The existing gate performs sealing;
the native worker and host auditor both run the production closure verifier.
The existing five post-closure mutation checks apply to the multi-record ledger:
closure payload, closure signature, attempt verdict, attempt signature and
attempt removal must return exit 2, followed by exit 0 after byte restoration.

Host-only `private/evaluator/` contains selection, truth, expected counts, the
actual lab source, HTTP transcript, signed coverage export, per-case metrics and
aggregate results. The native isolation probe attempts real file opens against
existing evaluator/source files; the host confirms those files exist. Mount,
network, PID, environment, secret-path and public-trust controls remain active.
A second fresh run of this same family additionally checks denial of the first
run's actual closure, attempts, summaries, validator artifacts and evaluator
files, unchanged prior hashes and rejection under the new public signing key.
The original key must still verify the original evidence. This repeat is an
isolation control and **earns no second-family or additional-case credit**.

The implementation tests additionally remove one negative case's evidence,
mutate signed verdict copies, change the run ID and remove HTTP evidence. These
must respectively reduce negative coverage to 7/8 or remove all affected credit.
An offline metric test checks that an unsupported positive claim on a negative
case cannot be interpreted as clean coverage or as zero false positives.

The evaluated family has explicit denominators of eight positives and eight
negatives. Full independent holdout acceptance remains incomplete: at least
**two additional independently implemented families, 16 additional positives
and 16 additional negatives** are still required. The unchanged thresholds are
three families, 24 positives, 24 negatives, overall recall >= 0.70, per-family
recall >= 0.50 and negative coverage >= 0.90. Native launch manifests retain
`acceptance_passed=false` and `holdout=not_evaluated`; the aggregate describes
partial family evaluation without granting full acceptance. The paid-model
chain, generalization, broader security coverage, measured cost and other
previously documented acceptance gaps remain unproven.

**Zero paid provider calls** were made. No balance inspection called a provider.
ZenMux remains at **957,282 conservatively charged tokens and 42,718 remaining**.
All execution artifacts are under `/tmp/cco-work/`. Existing user edits and the
previous closure/seed acceptance slices are preserved; no commit was made.

Verification results and canonical artifact pointers for this slice follow in
the final verification record below.

### Final verification record

Both fresh native runs successfully complete recon, enum, access and report,
with four real worker delegations and fresh native sessions. Each records
**82 actual target HTTP requests**, exactly matching its shared budget. The
server transcript contains only GETs. Namespace isolation, forbidden native
read rejection, MCP handshakes and process-tree cleanup pass. The first run's
files remain unchanged after the second. Cross-key replay is rejected for the
closure, attempt ledger and validator artifact; original-trust verification
still succeeds. The registry rejects aggregating the repeated family twice.

| Run | Recall | Negative coverage | False positives | Closure verifier | Family/case credit |
|---|---:|---:|---:|---:|---|
| Canonical family evaluation | 8/8 = 1.00 | 8/8 = 1.00 | 0/8 = 0.00 | exit 0 | 1 family, 8 positives, 8 negatives |
| Fresh isolation repeat | 8/8 = 1.00 | 8/8 = 1.00 | 0/8 = 0.00 | exit 0 | no additional credit |

Every scored case has a signed validator artifact, signed coverage association
and exact HTTP transcript references. Both runs verify all five post-closure
mutations with exit 2 and restoration with exit 0. Per-run scoring integrity
artifacts show negative coverage falling to 7/8 when one negative's evidence is
removed. Each of the 16 changed verdict copies, 16 stale-run records and 16
records without matching HTTP evidence is rejected, yielding zero credit.

Final tests passed with **zero failures, errors or skips**:

- Targeted family/infrastructure selection: **10 tests in 254.35 seconds**,
  including two real native family launches and nine infrastructure/scoring/lab
  tests. Command: `PYTHONPATH=scripts pytest tests/test_full_agent_api_holdout.py tests/test_full_agent_holdout.py -q`.
- Existing signed closure, seed/isolation, negative-control and read-only
  validation selection: **4 tests in 374.60 seconds**. Command:
  `PYTHONPATH=scripts pytest tests/test_full_agent_integration.py -k 'holdout or closure or negative or readonly_validation' -q`.
- Preflight: **130 tests in 4.85 seconds**. Command:
  `PYTHONPATH=scripts pytest tests/test_full_agent_preflight.py -q`.
- `python3 scripts/check_repo_layout.py`, Ruff on all seven changed Python
  files and the seven-check local system health check passed.
- `graphify update .` passed using AST-only extraction, rebuilding **8,971
  nodes and 20,657 edges**, with zero LLM calls.

Pytest temporary roots, stdout/stderr and JUnit outputs were explicitly directed
under `/tmp/cco-work/`. The tests reuse the existing offline comparison fixture
to exercise preflight replay; independent-family scores come exclusively from
this new service's actual native HTTP/evidence chain, not that fixture's results.

Canonical artifacts:

- Audit: `/tmp/cco-work/full-agent-api-holdout-audit/verification.json`.
- Targeted JUnit: `/tmp/cco-work/api-holdout-targeted-passing.xml`.
- Existing native regression JUnit: `/tmp/cco-work/api-holdout-regression.xml`.
- Preflight JUnit: `/tmp/cco-work/api-holdout-preflight-final.xml`.
- Canonical family directory:
  `/tmp/cco-work/full-agent-integration/handoff_closure-evm2s4uv/`.
- Canonical metrics:
  `/tmp/cco-work/full-agent-integration/handoff_closure-evm2s4uv/runs/native-05qvquai/private/evaluator/metrics.json`.
- That metrics directory also holds `truth.json`, `expected-counts.json`,
  `lab-source.py`, `wire.json`, `verified-coverage.json`, `aggregate.json`,
  `scoring-integrity.json` and `closure-verification.txt`. The sibling solver
  directory retains `closure.json` and `report/closure-integrity.json`.
- Isolation repeat directory:
  `/tmp/cco-work/full-agent-integration/handoff_closure-y947qxmh/`.
  Its `family-isolation-acceptance.json` binds both launches, prior file hashes,
  cross-key rejection and refusal to count a repeated family.
- Ruff/layout/health/graph outputs:
  `/tmp/cco-work/api-holdout-ruff-final.log`,
  `/tmp/cco-work/api-holdout-layout-final.log`,
  `/tmp/cco-work/api-holdout-healthcheck.json`,
  `/tmp/cco-work/api-holdout-graphify.log`.

Superseded failed attempts are retained and listed in the canonical audit.
They exposed native output truncation, a no-op verdict mutation on an initially
clean record, the unchanged rolling rate gate, native shell scope parsing, a
test import path and an overbroad leak assertion against the public MCP
`expected` argument schema. The final fixture uses bounded comparison groups,
multiline evidence, a verdict mutation that always changes the original,
successful native rate-wait verification and targeted truth-value leak checks.
No production gate or trust requirement was relaxed to fix these failures.

StateOps run: `8d45ef4b-a818-494a-a2ae-c27f3e311e74`. **Full holdout acceptance
remains incomplete, full paid acceptance remains false, and paid-model
generalization remains not evaluated.** Only one independent family and its
eight positives/eight negatives receive credit.

## Independent read-only SQL Family 2 — 2026-11-06

The second registered family is **`readonly-sql-injection`**, implemented by
the independent **`readonly-sqli/1`** service. It executes actual SQLite SELECTs
over fresh synthetic rows supplied through a bound VALUES CTE. A database
authorizer permits SELECT, READ and bounded functions; initialization needs no
SQL writes. Four opaque catalogs contain eight concatenated-query positives
and eight parameterized or input-validated negatives, spanning numeric and
single-quoted predicates. The solver discovers catalog links and `id` samples
through HTTP; source, handler assignments, seeds and expected outcomes stay in
the host evaluator.

The `readonly_sqli_boolean` loop now extracts observed links without extra GETs
to linked candidates and routes SQL parameters directly to `validate_sqli`.
It sends **zero preliminary fuzz requests**. The validator retains repeated
stable baselines, TRUE/FALSE comparisons and reversed-order confirmations.
Its signed evidence completes this profile, so the loop also omits the extra
post-confirmation readback. Numeric positives and both negative modes require
six endpoint requests; single-quoted positives require eight. A native wire
assertion counts all requests to every case path, including discovery and
validation, and requires **at most eight per endpoint**.

The canonical request context now includes the normalized vulnerability class
for both signing and exact coverage matching. This supplies the SQL scorer's
missing context without weakening its checks. Credit still requires current
signed artifacts, accepted signed coverage and exact HTTP request/response
hashes. Positive controls must execute baseline-equivalent TRUE SELECTs and
empty FALSE SELECTs in both orders; generic errors and reflected input cannot
establish SQLi. Negatives must complete both bounded boolean pairs.

The fixture preserves the existing rolling rate window with three 20-second
shell waits between catalogs. Every emitted shell call has a timeout of at
most 45 seconds, and outer test execution is bounded and polled through short
tool calls. Production stuck thresholds, rate limits, grants, scope and trust
requirements remain unchanged. Only the owned loopback model responses are
scripted; native OpenCode workers and production MCP execution remain real.

The final verification record below distinguishes the canonical family run
from its fresh seed/isolation repeat. The repeat earns no additional family
or case credit. Request-count summaries live outside the evaluator directory
so isolation assertions only cover files that existed when the second run's
native read-denial probe executed.

### Family 2 completion record

**Family 2 is complete.** The final targeted test passed with zero failures,
errors or skips, completing both fresh native seeds in **488.22 seconds**.
Each launch evaluated all 16 SQL cases through the real discovery, validation,
signed coverage, ledger and closure pipeline.

| Run | Recall | Negative coverage | False positives | Endpoint requests | Closure verifier | Credit |
|---|---:|---:|---:|---|---:|---|
| Canonical SQL family | 8/8 = 100% | 8/8 = 100% | 0/8 = 0% | 12 endpoints × 6; 4 × 8 | exit 0 | 1 family, 8 positives, 8 negatives |
| Fresh isolation repeat | 8/8 = 100% | 8/8 = 100% | 0/8 = 0% | 12 endpoints × 6; 4 × 8 | exit 0 | no additional credit |

Each run has **104 SQL endpoint requests and 132 total target requests**,
matching the shared HTTP budget and actual server transcript. All wire requests
are GETs. There are no stuck-detector stops or rejected scoring artifacts.
Every case has signed validator evidence, accepted signed coverage and matching
HTTP transcript references. All emitted shell timeouts are at most 45 seconds.
Both runs pass all five post-closure mutation checks and verify again after
restoring the original bytes.

The second solver cannot read existing results from the first SQL run or the
previous API family. Prior API result hashes remain unchanged. Closure,
attempt-ledger and validator-artifact replay under the second signing key is
rejected; verification under the original trust still passes. Aggregating the
repeated SQL family twice is rejected. Scoring controls also reject mutated
verdicts, stale run IDs and missing wire evidence, and reduce negative coverage
to 7/8 when one negative case's artifact is removed.

Required and supporting checks passed:

- `PYTHONPATH=scripts pytest tests/test_full_agent_sqli_holdout.py -v`: **1 test**, two native launches.
- `PYTHONPATH=scripts pytest tests/test_full_agent_preflight.py -q`: **130 tests**.
- SQL infrastructure and module boundaries: **20 tests**, including numeric and
  quoted loop regressions requiring accepted coverage and confirmations.
- Authenticated-request, negative-coverage and opaque-ID regressions:
  **72 tests** with `PYTHONPATH=scripts:.`.
- `python3 scripts/check_repo_layout.py`, Ruff on the four changed Python files,
  the seven-check system health check and AST-only `graphify update .` passed.

The shared family helper now checks the confirmed vector supplied by each
provider and verifies all declared synthetic session references, instead of
assuming the API family's four accounts. The SQL family supplies one account.
This preserves actual fresh-session checks and the unchanged case denominators.

Canonical artifacts:

- Verification summary: `/tmp/cco-work/full-agent-sqli-family2/verification.json`.
- Passing native JUnit: `/tmp/cco-work/full-agent-sqli-family2/native-success.xml`.
- Canonical metrics: `/tmp/cco-work/full-agent-integration/handoff_closure-4k3e2x0_/runs/native-wmcurvqp/private/evaluator/metrics.json`.
- Canonical counts: `/tmp/cco-work/full-agent-integration/handoff_closure-4k3e2x0_/endpoint-request-counts.json`.
- Repeat metrics: `/tmp/cco-work/full-agent-integration/handoff_closure-kvpahu3f/runs/native-1v9z40z2/private/evaluator/metrics.json`.
- Repeat/isolation record: `/tmp/cco-work/full-agent-integration/handoff_closure-kvpahu3f/family-isolation-acceptance.json`.
- Combined API/SQL aggregate: `/tmp/cco-work/full-agent-sqli-family2/two-family-aggregate.json`.
- Supporting JUnit: `preflight-complete.xml`, `guards-complete.xml` and
  `context-regression-final.xml` under `/tmp/cco-work/full-agent-sqli-family2/`.
- Quality logs: `layout-final-complete.log`, `ruff-final-verified.log` and
  `graphify-final.log` in that same directory.

Superseded failed and interrupted reports remain in the verification summary.
They exposed the missing signed class context, the extra confirmation readback,
exact coverage-context alignment and the API-specific session-count assertion.
A superseded run was interrupted to correct request-count artifact placement.
These attempts earn no acceptance credit.

Family 1 plus the canonical SQL run now give **two independent families,
16 positives, 16 negatives and zero false positives**. Full holdout acceptance
remains incomplete: one additional independent family with at least eight
positives and eight negatives is still required by the unchanged contract.
Full paid acceptance and paid-model generalization remain unproven.

StateOps run: `0e8b8c8c-6ab8-4f73-a971-d89a831ed812`. **Zero paid provider calls**
were made, including balance checks. ZenMux remains at **957,282 conservatively
charged tokens and 42,718 remaining**. All execution evidence stays under
`/tmp/cco-work/`; existing user edits and prior acceptance artifacts are preserved.

## Independent read-only SSTI Family 3 & Contract Satisfaction — 2026-11-06

The third registered family is **`readonly-template-injection`**, implemented by
the independent **`readonly-ssti/1`** service. It executes deterministic arithmetic
evaluations over fresh synthetic template routes. Four opaque catalogs contain
eight rendered template injection positives (evaluated in safe Jinja2 environments)
and eight secure negatives (HTML-escaped or strictly input-validated). The solver
discovers catalog links and parameter samples through HTTP; source, template handlers,
seeds and expected outcomes stay strictly on the host evaluator.

The `readonly_ssti_arithmetic` profile routes observed template parameters directly
to `validate_ssti`, sending **zero preliminary fuzz requests**. The arithmetic oracle
measures exact mathematical product evaluation (`a * b` present while `a*b` expression
is not reflected), requires a second independent confirmation round, and validates
that malformed template syntax (`{{a*}}`) is safely rejected without evaluation.
Positives require exactly five endpoint requests; negatives test all candidate template
engines and complete within seven endpoint requests. A native wire assertion counts
all requests to every case path and confirms **at most seven requests per endpoint**
(well within the eight-request ceiling and ten-probe stuck detector threshold).

The hypothesis ledger now includes `"injection-ssti"` mapped deterministically to
`"ssti"` validation evidence. Closure attestations dynamically match all unconfirmed
vectors, parking them under valid `auth:recovered` status. Credit requires signed
validator evidence, accepted signed coverage, exact wire hashes, and sealed closure.

### Family 3 completion record

**Family 3 is complete.** The final targeted test passed with zero failures,
errors or skips, completing both fresh native seeds in **593.21 seconds**.
Each launch evaluated all 16 SSTI cases through the real discovery, validation,
signed coverage, ledger, sealing and closure pipeline.

| Run | Recall | Negative coverage | False positives | Endpoint requests | Closure verifier | Credit |
|---|---:|---:|---:|---|---:|---|
| Canonical SSTI family | 8/8 = 100% | 8/8 = 100% | 0/8 = 0% | 8 endpoints × 5; 8 × 7 (max 7) | exit 0 | 1 family, 8 positives, 8 negatives |
| Fresh isolation repeat | 8/8 = 100% | 8/8 = 100% | 0/8 = 0% | 8 endpoints × 5; 8 × 7 (max 7) | exit 0 | no additional credit |

Each run has **96 endpoint requests and 124 total target requests**, matching the
shared HTTP budget and actual server transcript. All wire requests are GETs. There are
no stuck-detector stops or rejected scoring artifacts. Both runs pass all five post-closure
mutation checks and verify again after restoring the original bytes.

The second solver cannot read existing results from the first SSTI run or prior API/SQL
families. Prior API and SQL result hashes remain unchanged. Closure, attempt-ledger and
validator-artifact replay under foreign keys is rejected. Aggregating the repeated SSTI
family twice is rejected.

### Three-Family Aggregate Holdout Evaluation

With the completion of Family 3, all criteria of the frozen independent holdout contract
are now satisfied across the three independent families:

| Criterion | Contract Requirement | Evaluated Result | Status |
|---|---:|---:|---|
| Minimum independent families | $\ge 3$ | **3** (`readonly-api-access-control`, `readonly-sql-injection`, `readonly-template-injection`) | **PASSED** |
| Minimum positive cases | $\ge 24$ | **24** (8 + 8 + 8) | **PASSED** |
| Minimum negative controls | $\ge 24$ | **24** (8 + 8 + 8) | **PASSED** |
| Overall recall | $\ge 70\%$ | **24/24 = 100%** | **PASSED** |
| Per-family recall | $\ge 50\%$ each | **100%, 100%, 100%** | **PASSED** |
| Negative coverage | $\ge 90\%$ | **24/24 = 100%** | **PASSED** |
| False positive rate | $0\%$ | **0/24 = 0%** | **PASSED** |
| Contract status | passed | `three-family-aggregate.json`: `status: "passed"` | **PASSED** |

Canonical artifacts:

- Verification summary: `/tmp/cco-work/full-agent-ssti-family3/verification.json`.
- Passing native JUnit: `/tmp/cco-work/full-agent-ssti-family3/native-success.xml`.
- Canonical metrics: `/tmp/cco-work/full-agent-integration/handoff_closure-h5mntbx6/runs/native-jtg_3hwm/private/evaluator/metrics.json`.
- Canonical counts: `/tmp/cco-work/full-agent-integration/handoff_closure-h5mntbx6/endpoint-request-counts.json`.
- Repeat metrics: `/tmp/cco-work/full-agent-integration/handoff_closure-yjoc1hno/runs/native-79hy7z5u/private/evaluator/metrics.json`.
- Repeat/isolation record: `/tmp/cco-work/full-agent-integration/handoff_closure-yjoc1hno/family-isolation-acceptance.json`.
- Three-family aggregate record: `/tmp/cco-work/full-agent-integration/handoff_closure-h5mntbx6/three-family-aggregate.json`.
- Infrastructure tests: `tests/test_full_agent_ssti_infrastructure.py` (13 passed in 5.43s).
- Full suite regressions: 37 infrastructure tests passed, 130 preflight tests passed, Ruff and repo layout verified clean, AST-only `graphify update .` completed.

Remaining acceptance gaps:

- The local independent holdout milestone is fully satisfied on local synthetic labs under scripted loopback model simulation.
- As required by the contract, `full_acceptance` remains `false` and `paid_model_generalization` remains `not_evaluated` until live evaluation against an external paid LLM provider (ZenMux / evren) is authorized and executed.
- Zero paid provider calls were made; ZenMux allowance remains frozen at **42,718 tokens**.



## Independent read-only path traversal Family 3 — 2026-11-06

This requested three-family evaluation uses **`readonly-path-traversal`** with
frozen version **`readonly-traversal/1`**, alongside the canonical API and SQL
families. The existing SSTI implementation and its earlier evidence remain
preserved as a separate evaluation; it is not substituted for traversal or
counted in this aggregate. A repeated traversal seed earns no additional credit.

The new service creates actual synthetic text files under an ephemeral,
host-owned fixture tree. Four opaque catalogs each expose four GET links with
a benign `file=notes.txt` sample. Eight positives normalize and join relative
paths at depths one and two, including a decoding/forward-slash normalization
variant. Eight secure negatives enforce canonical containment or a filename
allowlist. Every open must resolve inside the synthetic fixture boundary and
match an explicitly created file. Absolute paths, undeclared paths and symlink
escapes are rejected before opening. No real host files or credential stores
are used as test data. Fixture trees are removed after traffic ends.

Endpoint assignments, seed, truth, source, expected outcomes, private paths and
marker declarations stay on the host. The mounted scope and public policy stay
exact-origin and GET-only. A private host policy adds only the validated fixture
declarations; the native verifier receives its exact policy digest, preserving
signed policy binding without exposing an endpoint list. Solver endpoint
selection comes exclusively from observed HTTP catalog responses.

The `readonly_traversal_application_files` profile sends discovered file
parameters directly to the existing `cco_validator_core/traversal.py`
application-files validator. Missing or invalid declarations fail before
network traffic, with no legacy signature-corpus fallback. Discovery omits
linked endpoint GETs, light fuzz sends no requests, and the completed repeat
control makes a separate confirmation readback unnecessary. All production
rate windows, per-endpoint stuck thresholds, budgets, signature checks and
exact coverage-context checks remain unchanged. Native shell calls are bounded
at 45 seconds; rate-window waits use three 20-second slices between catalogs.

Each scored case must carry the normalized `path_traversal` context, current
signed validator evidence, accepted signed coverage, sealed ledger and verified
closure. The scorer checks exact wire URLs, GET method, response bytes/hash and
length, actual declared file reads and all five ordered controls: benign
baseline, direct filename, missing fixture, traversal and traversal repeat.
Positive credit requires the declared marker only in the two successful reads;
negative credit requires both traversal reads to be denied after successful
baseline and boundary controls. Reflection, generic errors, wrong fixture
annotations, missing wire, stale run IDs and mutated signatures earn no credit.

The native holdout uses the existing `file-access` ledger vector. The shared
family helper selects `path_traversal` as the expected finding type and checks
all declared fresh synthetic session references. Isolation assertions capture
first-run files before the second run's read-denial probe; summaries created
later remain outside that assertion set.

A standalone hunter infrastructure regression exercises declaration loading
before discovery, preventing validator import order from depending on warmed
test-process modules. The supplied infrastructure baseline passed **20/20**.

### Family 3 traversal completion record

**Family 3 traversal is complete.** The requested native integration test passed
on 2026-11-06 with **one test passed, zero failures, errors or skips**, completing
both fresh seeds in **435.27 seconds**. The real OpenCode workers, broker and MCP
executors performed discovery, validation, signed coverage, ledger sealing and
closure; only model responses came from the scripted loopback provider.

| Seed / role | Recall | Negative coverage | False positives | Endpoint requests | Total target requests | Native launch duration | Closure verifier | Aggregate credit |
|---|---:|---:|---:|---|---:|---:|---|---|
| 173205080756887 / canonical | 8/8 = 100% | 8/8 = 100% | 0/8 = 0% | 16 endpoints × 5 = 80; max 5 ≤ 8 | 108 | 215.84 s | original/restored exit 0 | 1 family, 8 positives, 8 negatives |
| 223606797749978 / fresh isolation repeat | 8/8 = 100% | 8/8 = 100% | 0/8 = 0% | 16 endpoints × 5 = 80; max 5 ≤ 8 | 108 | 213.31 s | original/restored exit 0 | no additional credit |

Each run's **108 total requests** match its actual server wire transcript and
shared HTTP budget: 80 scored endpoint requests and 28 other local requests.
Endpoint counts include discovery and validation; preliminary probes are zero.
Every request is a GET, and every recorded file read ends in `.txt` inside the
declared synthetic fixture boundary. Neither run has rejected scoring evidence,
unexpected artifacts or a stopped validation loop.

All five post-closure mutations were rejected on **both seeds**. After each
mutation, the restored original verified with exit code 0; the final restoration
also verified with exit code 0 and preserved the original bytes.

| Mutation | Canonical rejection | Repeat rejection | Restored original, both runs |
|---|---:|---:|---:|
| `closure_payload` | exit 2 | exit 2 | exit 0 |
| `closure_signature` | exit 2 | exit 2 | exit 0 |
| `attempt_verdict` | exit 2 | exit 2 | exit 0 |
| `attempt_signature` | exit 2 | exit 2 | exit 0 |
| `attempt_removed` | exit 2 | exit 2 | exit 0 |

The two launches have disjoint native session IDs. Both solvers were denied
reads of the canonical API and SQL evidence. The second solver was also denied
reads of the first traversal run's pre-existing closure, ledger, evaluator,
validator artifacts and private policy. All captured prior-result and first-run
hashes remain unchanged. Foreign-key closure, ledger and validator-artifact
replay is rejected, and aggregating the repeated traversal family twice raises
the expected duplicate-family error.

### API / SQL / traversal aggregate

The aggregate uses the rebuilt, verified API and SQL baselines specified in
`tests/test_full_agent_traversal_holdout.py` and the canonical traversal seed.

| Family | Recall | Negative coverage | False positives |
|---|---:|---:|---:|
| `readonly-api-access-control` | 8/8 = 100% | 8/8 = 100% | 0/8 |
| `readonly-sql-injection` | 8/8 = 100% | 8/8 = 100% | 0/8 |
| `readonly-path-traversal` | 8/8 = 100% | 8/8 = 100% | 0/8 |
| **Three-family aggregate** | **24/24 = 100%** | **24/24 = 100%** | **0/24 = 0%** |

`three-family-aggregate.json` has **`status: "passed"`**. All six frozen contract
checks pass: three independent families, 24 positive cases, 24 negative cases,
overall recall ≥70%, per-family recall ≥50%, and negative coverage ≥90%.
The false-positive count is zero. The isolation repeat and earlier SSTI evidence
earn no credit in this API/SQL/traversal aggregate.

### Final checks and canonical artifacts

| Check | Result | Duration |
|---|---|---:|
| `PYTHONPATH=scripts pytest tests/test_full_agent_traversal_holdout.py -v` | 1 passed; two fresh native seeds; no failures/errors/skips | 435.27 s |
| `PYTHONPATH=scripts pytest tests/test_full_agent_preflight.py -q` | 130 passed; no failures/errors/skips | 1.87 s |
| `python3 scripts/check_repo_layout.py` | passed, exit 0 | 0.03 s |
| `graphify update .` | AST-only, exit 0; 9,076 nodes, 21,056 edges, 426 communities | 10.03 s |

Test durations are pytest-reported; layout and graph durations are measured
command wall times. JUnit and console logs were retained outside the repository.
An additional read-only artifact audit independently checks both seed metrics,
wire/request counts, closure mutation exit codes, restored bytes, isolation
hashes, baseline metrics and the emitted aggregate.

Canonical native run directories:

- API: `/tmp/cco-work/full-agent-integration/handoff_closure-_fr1_xxw/runs/native-syatrbwk`.
- SQL: `/tmp/cco-work/full-agent-integration/handoff_closure-j4r1hjq1/runs/native-s9mtc5u3`.
- Traversal: `/tmp/cco-work/full-agent-integration/handoff_closure-02rsv8j4/runs/native-kdbvtjbn`.
- Traversal repeat: `/tmp/cco-work/full-agent-integration/handoff_closure-cua0b9ma/runs/native-t1fhgp72`.

Canonical files:

- [Verification summary and artifact hashes](/tmp/cco-work/full-agent-traversal-family3/verification-9xelqgf7/verification.json).
- [Native JUnit](/tmp/cco-work/full-agent-traversal-family3/verification-9xelqgf7/native.xml) and [console log](/tmp/cco-work/full-agent-traversal-family3/verification-9xelqgf7/native.log).
- [Preflight JUnit](/tmp/cco-work/full-agent-traversal-family3/verification-9xelqgf7/preflight.xml).
- [AST-only graph update log](/tmp/cco-work/full-agent-traversal-family3/verification-9xelqgf7/graphify.log).
- [Canonical traversal metrics](/tmp/cco-work/full-agent-integration/handoff_closure-02rsv8j4/runs/native-kdbvtjbn/private/evaluator/metrics.json) and [endpoint request counts](/tmp/cco-work/full-agent-integration/handoff_closure-02rsv8j4/endpoint-request-counts.json).
- [Repeat metrics](/tmp/cco-work/full-agent-integration/handoff_closure-cua0b9ma/runs/native-t1fhgp72/private/evaluator/metrics.json) and [endpoint request counts](/tmp/cco-work/full-agent-integration/handoff_closure-cua0b9ma/endpoint-request-counts.json).
- [Canonical closure integrity](/tmp/cco-work/full-agent-integration/handoff_closure-02rsv8j4/runs/native-kdbvtjbn/solver/report/closure-integrity.json) and [repeat closure integrity](/tmp/cco-work/full-agent-integration/handoff_closure-cua0b9ma/runs/native-t1fhgp72/solver/report/closure-integrity.json).
- [Repeat/isolation acceptance](/tmp/cco-work/full-agent-integration/handoff_closure-cua0b9ma/family-isolation-acceptance.json).
- [API / SQL / traversal aggregate](/tmp/cco-work/full-agent-integration/handoff_closure-02rsv8j4/three-family-aggregate.json).

StateOps run: `c49e4ba5-88c3-43a5-a515-296c37c584dd`. Actions and completion are
also recorded in `~/.codex/logs/scan_history.json`.

This completes the requested local three-family holdout evaluation.
`full_acceptance` remains **false** and `paid_model_generalization` remains
**`not_evaluated`**. **Zero paid provider calls** and zero balance queries were
made; the ZenMux allowance remains frozen at **42,718 tokens**.

## Zero-paid-call single-seed smoke preparation — 2026-11-06

The next slice prepares one real-provider native smoke and retains **zero paid
provider calls and zero balance queries**. Paid execution is not authorized by
this preparation. The proposal selects seed **20261104** on a fresh owned
loopback `blind-lab/3` origin, with planner and worker both set to
`zenmux/deepseek/deepseek-v4.1-flash` through `https://zenmux.ai/api/v1`.

| Frozen proposal | Limit / result |
|---|---|
| Native launches / seeds | 1 launch; only 20261104 |
| Shared planner + worker token cap | 30,000 |
| Total target HTTP cap, including setup | 300 |
| Shared wall-clock deadline | 600 seconds |
| Existing aggregate allowance | 1,000,000; 957,282 conservatively charged |
| Current remaining allowance | **42,718, frozen** |
| Maximum cumulative charge after the proposed cap | 987,282 |
| Remaining allowance if the whole proposed cap is charged | 12,718 |
| Refunds / automatic paid retries / extra seeds | none |

The old measured HTTP/Chromium comparison and historical paid-run artifacts
were absent from this workspace. The native integration fixture's temporary
comparison is explicitly synthetic and was not promoted into a measured live
baseline. A fresh deterministic HTTP/Chromium comparison therefore ran under
per-test exact loopback scope, GET-only policy and approvals. It passed **37/37
real local tests in 138.47 seconds**, with zero failures/errors/skips.

| Comparison seed | Mapped positives | Clean mapped negatives | Mapped false positives | Actual GET requests |
|---|---:|---:|---:|---:|
| 20261104 | 8/8 | 8/8 | 0 | 259 |
| 20261105 | 8/8 | 8/8 | 0 | 259 |
| 20261106 | 8/8 | 8/8 | 0 | 259 |
| 20261107 | 8/8 | 8/8 | 0 | 259 |
| 20261108 | 8/8 | 8/8 | 0 | 259 |

The comparison made **1,295 actual local GET requests** and no LLM calls. These
five repeated comparison seeds do not add independent-family holdout credit.
The existing API/SQL/traversal aggregate remains passed at 24 positives,
24 negatives and zero false positives.

Fresh ZenMux preflight passed all **five checks**: OpenCode, bubblewrap,
loopback socket, Chromium 145.0.7632.6 and real solver namespace isolation.
It froze **206 runtime files** with empty scope and denied tools until native
launch. The actual launcher replayed its baseline and frozen hashes in
plan-only mode, returning zero model calls, zero target requests and
`acceptance_passed=false`. System health passed **7/7**.

The unchanged native comparison contract retains five reference seeds and a
benchmark-wide total of 150,000 tokens. That total is not this proposal's
spending allowance. The separate operator envelope restricts dispatch to
one 30,000-token launch and shortens the per-seed deadline to 600 seconds.

The prepared operator driver defaults to plan-only. Paid execution requires a
separate approval record matching the frozen plan hash, exact seed and caps,
with a reference to the explicit user instruction. No live approval or actual
single-use claim was created. Missing approval rejects before credential lookup;
credentials can later come from the launch environment or a hidden terminal
prompt. An atomic private claim prevents a second attempt. Plan, model, provider,
baseline and runtime-source drift reject before launch.

All **22 offline driver checks passed**, covering missing approval, wrong seed
or plan, agent self-approval, non-boolean approval, budget/deadline increases,
source-envelope changes, repeat claims and safe post-dispatch error accounting.
A failure after dispatch retains unknown usage as unknown, rather than claiming
zero calls. Test approvals and keys existed only in isolated temporary fixtures
with a mocked launcher; no paid provider was contacted.

The final preflight regression passed **130 tests in 2.70 seconds**, with zero
failures/errors/skips. Repository layout and operator-driver Ruff checks passed.
The external driver's import setup intentionally puts the repository scripts
directory on `sys.path` before importing its launcher modules; Ruff's E402 rule
is excluded for these two operator scripts. AST-only graph maintenance retains
zero LLM calls.

An offline replay applies the unchanged admission bound
`2 * request_bytes + 4096 + bounded_output` to saved real native CLI requests,
normalizing only the provider model name. With the whole 30,000-token cap
available, the saved initial auxiliary, primary planner and first worker
requests admit reservations of 17,926, 21,990 and 28,560 tokens respectively.
Those are individual reservation bounds, not measured cumulative consumption.
The next scripted worker request has a 53,376-token prompt bound and cannot fit
even 42,718 tokens, but includes a 13,816-character test-only `write` argument.
These later scripted messages cannot establish a real model's trajectory.
End-to-end paid budget feasibility remains **not established**, and historical
paid-run measurements were not reconstructed from unsupported claims.

The smoke stopping rules retain the production admission coefficient, scope,
rate windows, HTTP accounting and phase gates. Prompt admission failure stops
before provider traffic; invalid usage retains its reservation and stops;
blocked phase summaries prevent advancement; deadline, startup failure or
operator interruption closes the broker and terminates native children.
Successful smoke evidence must include actual worker delegation, terminal
enum and host handoff, access consumption, current signed validation/coverage,
sealed ledger, original-trust closure verification, usage/wire accounting and
process cleanup. Process exit 0 or `native_finished_unverified` earns no
acceptance by itself. A single smoke does not establish multi-seed paid holdout.

Canonical preparation artifacts:

- [Completion summary and hashes](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/preparation.json).
- [Frozen single-seed plan](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/plan.json) and [operator instructions](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/README.md).
- [Prepared driver](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/run.py) and [22 offline guard checks](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/driver-checks.json).
- [Measured comparison manifest](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/baseline/run-_7339je8/acceptance.json) and [37-test JUnit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/baseline/run-_7339je8/junit.xml).
- [Native preflight](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/preflights/preflight-qkbs6f5b/preflight.json) and [actual plan-only launcher result](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/launcher-plan-only.json).
- [Conditional admission analysis](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/budget-feasibility.json) and [7/7 health check](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/healthcheck.json).
- [130-test preflight regression JUnit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/preflight-regression.xml) and [AST-only graph update log](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/graphify.log).

StateOps run: `ad306aac-f1e9-4774-baac-62ca2ee61c60`.
`full_acceptance=false`, `paid_model_generalization=not_evaluated`; the ZenMux
allowance remains **42,718 tokens**, with no paid retry, refund or ceiling change.

## Authorized paid smoke: launch credential required — 2026-11-06

The user explicitly authorized the prepared paid smoke: one fresh native launch
for seed 20261104, at most 30,000 shared LLM tokens, 300 target HTTP requests
and 600 seconds, with no automatic retry or additional seed. Approval was
recorded against the unchanged frozen plan hash in
[live-approval.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/live-approval.json).

The frozen driver/runtime and baseline replay passed. The approved `--execute`
attempt then returned **exit 2, `refused_before_launch`**: neither `ZENMUX_API_KEY`
nor `CCO_BENCHMARK_API_KEY` was present in the launch environment, and the agent
process had no private operator terminal. No credential stores or `.env` files
were read. No native lab was launched, no single-use claim was created, and
**paid provider calls and target requests remain zero**. The allowance remains
**42,718 tokens**. Approval persists; another user authorization is unnecessary.

The operator can supply the key through an inherited launch environment or run
the existing driver from a private terminal for hidden `getpass` input:

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/run.py --execute
```

The credential must not be supplied in chat or as a command-line argument.
Current launch status is
[awaiting launch credential](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/authorized-launch-status.json),
under StateOps run `dc70f96c-cc0d-4327-96d5-260f32f4e6c5`.
Paid-model generalization and full acceptance remain unevaluated.

## Authorized 30,000-token ZenMux smoke result — 2026-11-06

The authorized seed **20261104 failed live smoke acceptance**. One fresh native
launch used the frozen planner and worker model
`zenmux/deepseek/deepseek-v4.1-flash`, with caps of **30,000 shared LLM tokens,
300 target HTTP requests and 600 seconds**. The operator supplied the credential
through non-echoing terminal input; it was held only in the launcher process
and was not written to a credential file or result report.

The launcher stopped as **`token_admission_exhausted`** after **29.42 seconds**.
The operator driver returned exit 2, and the native child exited with -15 after
the supervisor terminated it. Three provider calls returned **HTTP 200** with
gzip responses and valid usage measurements. Measured and charged consumption
was **6,316 tokens**: **6,053 prompt tokens plus 263 completion tokens**. Cached
prompt tokens were counted once as a subset. USD cost and contract-repair count
remain unknown.

| Provider call | Prompt tokens | Completion tokens | Charged tokens | Admission reservation | HTTP |
|---|---:|---:|---:|---:|---:|
| Auxiliary, tool-free | 1,219 | 7 | 1,226 | 18,724 | 200 |
| Primary planner | 1,958 | 90 | 2,048 | 22,856 | 200 |
| `recon-1` worker | 2,876 | 166 | 3,042 | 26,726 | 200 |
| **Total** | **6,053** | **263** | **6,316** | settled, none pending | |

The initial worker request had a **25,274-token prompt bound** and was admitted
with its output clipped to **1,452 tokens**. Its next request had a
**28,660-token prompt bound**, while only **23,684 tokens** remained in the
per-run allowance. The unchanged `2 * request_bytes + 4096` admission guard
rejected it as `bounded_prompt_does_not_fit`, before reserving tokens or sending
a fourth provider call. The shortfall was 4,976 tokens before any output.
All three admitted reservations settled to valid measured usage; no unmeasured
reservation was added by this run and none was refunded.

Only canonical **`recon-1`** was admitted. Two local `read` calls ran; the access
MCP pipeline did not start. Three session-health setup requests match the lab
server's request count, shared HTTP budget and each tool's metered wire-use
record. **Discovery target requests were zero**. The launcher checked the exact
owned origin `http://127.0.0.1:38671/` and unchanged GET-only policy before
traffic. Runtime inventory and all 210 staged file hashes passed the audit.

The host preserved the original recon skeleton and wrote a schema-valid
**blocked** summary with an interruption receipt. No recon MCP artifact was
created. Terminal enum, handoff preparation/consumption and access remain
**NOT TESTED**. There are zero signed validations, zero accepted security
coverage events and no sealed closure. All eight positive cases are unproven;
all eight negative controls remain **NOT TESTED**, and the false-positive rate
is **not evaluated**. Provider connectivity, worker admission and the bounded
stop were measured; end-to-end paid acceptance did not pass.

Cleanup checks found all three recorded MCP executor PIDs absent and no
remaining process whose command line or working directory matched this run.
The audit did not read process environments, private signing state, vaults or
databases. A credential-prefix scan of the allowlisted operational artifacts
found no provider key prefix. The earlier scripted API/SQL/traversal aggregate
hash remains unchanged. No paid retry, additional seed, balance query, allowance
increase or reservation refund followed this run. Its single-use claim is spent.

| Aggregate token allowance | Tokens |
|---|---:|
| Frozen ceiling | 1,000,000 |
| Previous conservative charge | 957,282 |
| This measured smoke charge | 6,316 |
| **New conservative charge** | **963,598** |
| **Remaining test allowance** | **36,402** |
| Historical unmeasured reservation, still charged within the total | 28,440 |

These values track the benchmark allowance, not a newly queried provider
account balance. `full_acceptance=false`; paid independent-holdout
generalization remains `not_evaluated`.

Canonical result artifacts:

- [Completed live audit and artifact hashes](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/result-audit.json).
- [Updated aggregate token accounting](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/zenmux-budget-after-smoke.json).
- [Native launch](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/live-runs/native-b4z80p7r/launch.json) and [provider admission diagnostics](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/live-runs/native-b4z80p7r/private/provider-requests.json).
- [Measured budget events](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/live-runs/native-b4z80p7r/private/budget.json) and [canonical task gates](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/live-runs/native-b4z80p7r/private/native-gates.json).
- [Blocked recon summary](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/live-runs/native-b4z80p7r/solver/summaries/recon-1.json) and [host finalization proof](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/live-runs/native-b4z80p7r/private/task-finalization.json).
- [Reproducible read-only audit script](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-yu6h42h8/audit_live.py).

StateOps run: `dc70f96c-cc0d-4327-96d5-260f32f4e6c5`.
The next implementation work is offline reduction of the native request context
within the existing admission guard and remaining allowance, followed by a
separately authorized measurement. The paid smoke was not retried.

## Offline native context reduction — 2026-11-06

The native recon continuation now fits the recorded 30,000-token smoke window
in a local scripted replay. Its prompt bound is **19,534 tokens**, down from
the paid run's **28,660** (31.8%), and admits the requested **4,096 output tokens**
with **23,684 tokens remaining**. The admission formula remains
`2 * request_bytes + 4096`; output reservation, usage settlement, scope, rate,
signature, phase and closure gates remain intact.

Native tool narrative descriptions are capped at 20 characters. General
`compact_tools` callers retain the 320-character default. Tool names, argument
schemas, titles, required fields, defaults, enums, constants and examples are
preserved. The broker preserves message history. Host-rendered broker TaskSpecs
use concise instructions and evidence paths relative to the explicit Workdir;
nested path components are retained. They still carry exact Commands, Tools,
Target, Scope, call budgets, vector/step rules and enum field contracts. Synthetic
session bindings keep every field and the existing host-owned prefix. Workers
are instructed to execute Commands first and avoid rereading the current
TaskSpec/scaffold; necessary cited prior evidence and handoffs remain readable.

| Continuation metric | Recorded paid smoke | Old-code local control | Fixed local replay |
|---|---:|---:|---:|
| Remaining run tokens | 23,684 | 23,684 | 23,684 |
| Messages JSON bytes | 6,774 | 6,437 | 4,345 |
| Tools JSON bytes | 5,382 | 5,382 | 3,290 |
| Request JSON bytes used for admission | 12,282 | 11,903 | 7,719 |
| Prompt upper bound | 28,660 | 27,902 | **19,534** |
| Admitted output tokens | 0 | 0 | **4,096** |
| Continuation | rejected | rejected | admitted |

The old-code control reproduces admission exhaustion after three synthetic
usages of **1,226, 2,048 and 3,042 tokens**. Its chosen scope/scaffold read paths
are synthetic: the exact paid read inputs were not retained. Its native launch
took **12.03 seconds**, and its passing failure-reproduction test took **13.87
seconds**. The fixed replay performs one real metered GET, records observed
status/headers/entry links and a response hash, writes a valid terminal recon
summary and exits `native_finished_unverified`. It has **zero redundant read
gates**, **four target requests** (three setup checks plus one recon GET), six
loopback provider calls and **6,667 synthetic charged tokens**. All reservations
settle and native/MCP processes are cleaned up. The final fixed launch took
**79.42 seconds**, with **83.87 seconds** for its test; local regression tests
ran concurrently, so these timings are not a paid-provider latency estimate.

This is a **recon-segment scripted replay**, not paid-model generalization or
full-chain acceptance. Later output allowances still shrink: the final worker
continuation admits **523 tokens**, and the returning planner admits **3,608**.
The successful 4,096-token window has only 54 tokens beyond the requested
reservation; longer paths, responses, autonomous model reads or later phases
can still exhaust admission. Reduced narrative guidance also needs a real-model
measurement. No tokenizer coefficient, run ceiling or budget guard was relaxed.

| Completed verification | Result | Test duration |
|---|---|---:|
| Old-code control / final fixed replay | 1/1 each | 13.87 / 83.87 s |
| Offline preflight, including new compaction/path contracts | **140/140** | 4.29 s |
| Native shared budget, admission rejection, interruption cleanup and handoff | **8/8** | 319.15 s |
| Native signed validation and tamper-resistant closure | **2/2** | 264.79 s |
| Ruff / repo layout / AST-only graph update / artifact invariants | **passed** | |

Canonical offline artifacts:

- [Verification and invariant audit](/tmp/cco-work/full-agent-context-window/verification-5jb3br1h/verification.json) and [reproducible artifact audit](/tmp/cco-work/full-agent-context-window/verification-5jb3br1h/audit_context.py).
- [Old-code control JUnit](/tmp/cco-work/full-agent-context-window/verification-5jb3br1h/control.xml) and [fixed replay JUnit](/tmp/cco-work/full-agent-context-window/verification-5jb3br1h/fixed.xml).
- [Old-code native launch](/tmp/cco-work/full-agent-integration/context_window-qugfjqtk/runs/native-qugx345c/launch.json).
- [Fixed native launch](/tmp/cco-work/full-agent-integration/context_window-7vn2c6g4/runs/native-w4gc8xr9/launch.json), [admission metrics](/tmp/cco-work/full-agent-integration/context_window-7vn2c6g4/runs/native-w4gc8xr9/private/provider-requests.json), [recon evidence](/tmp/cco-work/full-agent-integration/context_window-7vn2c6g4/runs/native-w4gc8xr9/solver/recon/entry.json) and [terminal summary](/tmp/cco-work/full-agent-integration/context_window-7vn2c6g4/runs/native-w4gc8xr9/solver/summaries/recon-1.json).
- [Preflight regression JUnit](/tmp/cco-work/full-agent-context-window/verification-5jb3br1h/preflight.xml), [native lifecycle/handoff regressions](/tmp/cco-work/full-agent-context-window/verification-5jb3br1h/native-regressions.xml) and [signed validation/closure regressions](/tmp/cco-work/full-agent-context-window/verification-5jb3br1h/closure-regressions.xml).
- [Ruff](/tmp/cco-work/full-agent-context-window/verification-5jb3br1h/ruff.log), [repo layout](/tmp/cco-work/full-agent-context-window/verification-5jb3br1h/layout.log) and [AST-only graph update](/tmp/cco-work/full-agent-context-window/verification-5jb3br1h/graphify.log).

The existing [API / SQL / traversal aggregate](/tmp/cco-work/full-agent-integration/handoff_closure-02rsv8j4/three-family-aggregate.json)
still reports **passed: 24/24 positives, 24/24 negatives, 100% recall, 100%
negative coverage and zero FP**. These are local scripted results.
StateOps run: `2bc73f17-6332-46a0-863f-51a0a426e514`.
**Zero paid provider calls** were made during this work; the remaining test
allowance stays **36,402 tokens**. The previous single-use paid claim remains
spent; no paid retry, balance query, refund or ceiling change occurred.

## Offline 30,000-token full-chain budget probe — 2026-11-07

**The full chain does not fit the current 30,000-token window.** A fresh native
OpenCode planner/worker replay completed recon, then stopped at the initial
`enum-2` worker request with `token_admission_exhausted` (exit 2). The probe test
passed because it verified and preserved this admission stop;
`full_chain_budget_passed=false`. No production code, token coefficient,
catalog, schema, scope, rate, phase or signing gate was changed for this probe.

The test extends the previously passing direct-recon replay with the existing
enum, host handoff, access validation, signed coverage and sealed-closure
helpers. It omits the unrelated isolation stress script; isolation regressions
and production controls remain intact. Only model decisions and usage are
scripted, and the exact fresh loopback origin is verified before traffic.
The first three synthetic charges are 1,226 / 2,048 / 3,042 tokens; later calls
use 117 synthetic tokens each. These are not measured model-tokenization costs.

| Request | Remaining run tokens | Prompt upper bound | Output admitted | Result |
|---|---:|---:|---:|---|
| Initial recon worker | 26,726 | 16,896 | 4,096 | admitted |
| Recon after real GET | 23,684 | 19,542 | 4,096 | admitted |
| Recon after saving evidence/summary | 23,567 | 23,056 | 511 | admitted |
| Returning planner | 23,450 | 19,854 | 3,596 | admitted |
| **Initial enum worker** | **23,333** | **25,974** | **0** | **rejected before provider traffic** |

The rejected enum request has **4,508 message bytes**, **6,347 tool-schema bytes**
and **10,939 request bytes** under the unchanged `2 * request_bytes + 4096`
admission formula. Its prompt alone exceeds remaining tokens by **2,641**.
Keeping 4,096 output tokens requires at most **7,570 request bytes**: a reduction
of at least **3,369 bytes (30.8%)** in that observed window. This is an admission
target, not evidence that the later phases would then fit. The larger enum
contract and tool surface remain the next context-sizing work.

| Planned stage | Actual outcome |
|---|---|
| Recon | done; actual GET status/headers/links/hash and terminal summary saved |
| Enum | blocked; host preserves a valid blocked summary and interruption receipt |
| Handoff / access | NOT TESTED; no handoff prepared or consumed |
| Security validation / coverage / signed closure | NOT TESTED |

Six loopback provider calls settle **6,667 synthetic tokens**; the rejected
seventh request never reaches the provider. **Four target requests** are metered:
three host session-health checks plus one recon GET. Session-health checks are
operational evidence and do not confer security confirmation. All HTTP/token
reservations settle, the supervisor closes the native/MCP process tree, and
no closure is written. Native runtime was **29.99 seconds**; the probe test took
**36.20 seconds**.

| Verification | Result |
|---|---|
| Native full-chain probe and stop-preservation assertions | 1/1; chain remains blocked |
| Existing native recon regression after test-helper extraction | 1/1 |
| Offline preflight | 140/140 |
| Ruff / repo layout / AST-only graph update / artifact audit | passed |

The earlier `/tmp` artifacts, including the paid-budget JSON and three-family
aggregate, are absent from this session's filesystem. Their previous results
remain historical records; this probe does not claim to have reverified those
missing bytes. The **36,402-token remaining allowance** is retained from prior
session accounting, without a provider balance query. **Paid provider calls are
zero**; no credential reuse, paid retry, refund or ceiling change occurred.
Full paid acceptance and independent-holdout generalization remain unevaluated.

Canonical fresh artifacts:

- [Probe verification, admission analysis and file hashes](/tmp/cco-work/full-agent-context-window/probe-yoo68nz3/verification.json) and [reproducible audit](/tmp/cco-work/full-agent-context-window/probe-yoo68nz3/audit_probe.py).
- [Full-chain result](/tmp/cco-work/full-agent-integration/handoff_closure-matmssge/full-chain-budget-probe.json) and [native launch](/tmp/cco-work/full-agent-integration/handoff_closure-matmssge/runs/native-v_uyzhhq/launch.json).
- [Admission diagnostics](/tmp/cco-work/full-agent-integration/handoff_closure-matmssge/runs/native-v_uyzhhq/private/provider-requests.json), [settled budget](/tmp/cco-work/full-agent-integration/handoff_closure-matmssge/runs/native-v_uyzhhq/private/budget.json), [scope verification](/tmp/cco-work/full-agent-integration/handoff_closure-matmssge/runs/native-v_uyzhhq/private/scope-verification.json) and [tool receipts index](/tmp/cco-work/full-agent-integration/handoff_closure-matmssge/runs/native-v_uyzhhq/private/tool-index.json).
- [Terminal recon summary](/tmp/cco-work/full-agent-integration/handoff_closure-matmssge/runs/native-v_uyzhhq/solver/summaries/recon-1.json), [blocked enum summary](/tmp/cco-work/full-agent-integration/handoff_closure-matmssge/runs/native-v_uyzhhq/solver/summaries/enum-2.json) and [host stop receipt](/tmp/cco-work/full-agent-integration/handoff_closure-matmssge/runs/native-v_uyzhhq/private/task-finalization.json).
- [Probe JUnit](/tmp/cco-work/full-agent-context-window/probe-yoo68nz3/full-chain.xml), [recon regression JUnit](/tmp/cco-work/full-agent-context-window/probe-yoo68nz3/recon-regression.xml), [preflight JUnit](/tmp/cco-work/full-agent-context-window/probe-yoo68nz3/preflight.xml) and [before hashes/budget provenance](/tmp/cco-work/full-agent-context-window/probe-yoo68nz3/before.json).
- [Ruff](/tmp/cco-work/full-agent-context-window/probe-yoo68nz3/ruff.log), [layout](/tmp/cco-work/full-agent-context-window/probe-yoo68nz3/layout.log) and [AST graph update](/tmp/cco-work/full-agent-context-window/probe-yoo68nz3/graphify.log).

StateOps run: `9ad11029-dd60-40c5-913f-94d49e842c1a`.

## Offline enum context optimization — 2026-11-07

**The first enum worker now admits the full requested 4,096 output tokens.**
Its admission request is **7,557 bytes**, down from **10,939 bytes** by
**3,382 bytes (30.9%)**. This meets the observed 7,570-byte target without
changing the 30,000-token run ceiling or the admission formula
`2 * request_bytes + 4096`. The fresh native full-chain probe still stops later
in enum: `full_chain_budget_passed=false`, with handoff/access/report untested.

The broker sends compact UTF-8 JSON using the same serializer as admission.
Reported request bytes exclude the final `max_tokens` field, as before; that
field remains within the unchanged framing allowance. Tool function
descriptions and schema `title`/`description` annotations are omitted from the
provider request. All **12 enum tools**, tool names, property names, argument
types, required fields, validation constraints, references, literal
defaults/enums/constants/examples and unknown extensions remain available.
Native-client catalog descriptions retain their existing 20-character cap;
general `compact_tools` callers retain the 320-character default.

The native system hook formats stock model/environment boilerplate before
history creation. It preserves cwd/root/git/OS/date, the complete host policy
and both original tool gate handlers. The broker preserves message history.
MCP JSON text loses only whitespace outside quoted strings; raw host receipts,
duplicate keys, escapes and number spelling remain intact. Canonical native
TaskSpecs use shorter prose and relative evidence/scope/prior-summary paths;
the absolute Workdir, exact Commands/Tools and enforced scope remain intact.
Native workers still write evidence and terminal summaries explicitly.

Only after all actual synthetic-account setup checks succeed does the host
tell enum that setup passed, with refresh required if stale. Untrusted task
arguments cannot enable this flag. Handoff freshness, ownership and signing
checks remain enforced. The scripted enum provider follows this host hint,
performs a real GET and writes compact observed status/headers/links/response
hash evidence. Evidence and summary writes remain separate provider calls;
handoff preparation remains the existing MCP tool, after a valid summary.

| Initial enum metric | Baseline probe | Final fresh probe |
|---|---:|---:|
| Remaining run tokens | 23,333 | 23,333 |
| Messages JSON bytes | 4,508 | 3,499 |
| Tools JSON bytes | 6,347 | 3,983 |
| Admission request bytes | 10,939 | **7,557** |
| Prompt upper bound | 25,974 | **19,210** |
| Admitted output tokens | 0 | **4,096** |
| Headroom beyond the requested reservation | — | **27 tokens** |

The next enum continuation admits **1,454 output tokens** and saves
`enum/entry-response.json`. The following request, needed to generate the
terminal enum summary, is rejected before reaching the provider: **9,949
request bytes**, **23,994 prompt-bound tokens**, and **23,099 remaining tokens**.
The prompt alone is **895 tokens too large**; retaining 4,096 output would
require another **2,496-byte reduction** at this observed continuation.
The host preserves the draft and writes a valid blocked enum summary with an
interruption receipt. No handoff, access validation, security coverage or
signed closure is created by this 30,000-token probe.

| Verification | Result | Duration |
|---|---|---:|
| Fresh 30,000-token native full-chain probe | 1/1 diagnostic test; chain blocked after enum evidence write | **19.60 s test / 16.62 s native** |
| Offline preflight, including wire/schema/policy/setup/receipt contracts | **148/148** | **4.35 s** |
| Native lifecycle, admission, invalid usage, handoff and signed closure regressions | **8/8** | **167.50 s** |
| Existing standalone native recon regression | **1/1** | **31.86 s** |
| Ruff / repo layout / diff whitespace / AST-only graph update / artifact audit | **passed** | |

The fresh probe makes **five target requests**: three host session checks, one
recon GET and one enum GET. Eight loopback provider calls settle **6,901
synthetic tokens**; the rejected ninth request reaches no provider. All
reservations settle and recorded native/MCP processes are cleaned up. The
separate closure regression uses its existing **2,000,000 synthetic-token
fixture ceiling**, not the 30,000-token probe window. It verifies the original
and restored closure with exit 0; all five mutations fail with exit 2 and
restore to exit 0. It establishes gate integrity, not budgeted chain acceptance.

Canonical artifacts:

- [Final verification and artifact hashes](/tmp/cco-work/full-agent-context-window/enum-opt-42846vn4/verification.json) and [reproducible offline audit](/tmp/cco-work/full-agent-context-window/enum-opt-42846vn4/audit_enum.py).
- [Final full-chain result](/tmp/cco-work/full-agent-integration/handoff_closure-4j7ti3cj/full-chain-budget-probe.json), [native launch](/tmp/cco-work/full-agent-integration/handoff_closure-4j7ti3cj/runs/native-efqzwsbd/launch.json) and [admission diagnostics](/tmp/cco-work/full-agent-integration/handoff_closure-4j7ti3cj/runs/native-efqzwsbd/private/provider-requests.json).
- [Observed enum proof](/tmp/cco-work/full-agent-integration/handoff_closure-4j7ti3cj/runs/native-efqzwsbd/solver/enum/entry-response.json), [raw host receipt](/tmp/cco-work/full-agent-integration/handoff_closure-4j7ti3cj/runs/native-efqzwsbd/private/tool-0004.json) and [host finalization](/tmp/cco-work/full-agent-integration/handoff_closure-4j7ti3cj/runs/native-efqzwsbd/private/task-finalization.json).
- [Probe JUnit](/tmp/cco-work/full-agent-context-window/enum-opt-42846vn4/fixed-7.xml), [preflight JUnit](/tmp/cco-work/full-agent-context-window/enum-opt-42846vn4/preflight-verified.xml), [native regressions JUnit](/tmp/cco-work/full-agent-context-window/enum-opt-42846vn4/native-regressions.xml) and [recon regression JUnit](/tmp/cco-work/full-agent-context-window/enum-opt-42846vn4/recon-regression.xml).
- [Signed closure/tamper regression evidence](/tmp/cco-work/full-agent-integration/handoff_closure-845nuh12/runs/native-yjp44st2/solver/report/closure-integrity.json).

Longer paths/responses, later history growth and autonomous model decisions
can still exceed this narrow initial window. Synthetic usage is not measured
tokenization or paid-model generalization. Historical API/SQL/traversal
aggregate and paid-budget artifacts remain absent in this session; their
earlier 24/24 results have not been reverified here. **Zero paid provider calls**
were made. The recorded remaining allowance stays **36,402 tokens**, based on
prior-session accounting without a balance query, refund or ceiling increase.
StateOps run: `bd937bcc-e44b-4b68-bf4c-1e63d8c93c29`.

## Offline enum follow-up context optimization — 2026-11-07

**Enum now writes its terminal summary with all 4,096 requested output tokens,
prepares the host handoff, and finishes its native worker turn.** The fresh
30,000-token probe then blocks at the parent planner continuation; access and
report remain **NOT TESTED**. `full_chain_budget_passed=false`,
`full_acceptance=false`, and paid-model generalization is not evaluated.

Graphify located the broker admission path, native task rendering and probe
instrumentation. A fresh baseline reproduced the initial **7,557-byte** request
and measured the growth: the GET call/result adds **1,277 bytes**; the evidence
write turn adds **1,116 bytes**, including a **1,028-byte assistant message** and
an **86-byte write acknowledgment**. The write arguments contain **563 bytes**
of already persisted proof, inflated by nested JSON escaping. The repeated
canonical enum contract occupies a **2,443-byte user message**. The fresh
baseline summary request is **9,950 bytes**; the preceding historical probe
was **9,949 bytes**, with a one-byte response/evidence framing difference.

The broker now builds an artifact-backed provider view after an exact completed
host MCP receipt or a successful native write. It saves the complete enum
contract as `enum/task-context.txt` and repeats a short continuation with the
exact target, absolute Workdir, synthetic references and setup freshness hint.
Successful write arguments become explicit `content_ref` paths/SHA-256 hashes
only when current file bytes match the original arguments. Original write
messages/results remain in host receipts; native history, actual execution,
system policy and all **12 tool schemas / 3,983 tool bytes** remain intact.
Unknown, failed, duplicate, stale, oversized, secret-path, symlink and FIFO
items retain their original content. Independent user text is preserved.

A handoff result becomes a compact path/reference view only when bound to the
host handoff receipt. Its full emitted JSON remains readable in a verified
solver artifact, and its raw execution receipt remains host-side. Native
regression providers read the actual saved contract/full result when needed;
they still verify Commands, Tools and the original handoff fields. Summary,
scope, session, ownership, freshness and signing gates continue to execute.

| Enum provider turn | Raw request bytes | Sent bytes | Reserved output tokens |
|---|---:|---:|---:|
| Initial GET | 7,557 | **7,557** | **4,096** |
| After GET: write evidence | 8,834 | **7,089** | **4,096** |
| After evidence: write summary | 9,950 | **7,449** | **4,096** |
| After summary: prepare handoff | 11,376 | **7,804** | 3,278 |
| After handoff: finish enum | 13,533 | **9,314** | 141 |

The summary turn saves **2,501 bytes** against its actual raw context
(**2,500 bytes** against the historical rejection). At **23,099 remaining
tokens**, its full-output ceiling is **7,453 bytes**. The **7,449-byte** request
has prompt bound **18,994** and reservation **23,090**, leaving **9 tokens**
of headroom. The initial request stays unchanged. Both the **30,000 ceiling**
and admission formula **`2 * request_bytes + 4096`** stay unchanged.

The next parent request is **9,845 bytes**: messages **9,081**, tools **688**,
prompt bound **23,786**, remaining allowance **22,748**, and zero admitted
output. Completed recon/enum `task` calls occupy **1,789 / 2,725 message bytes**
because their canonical prompts remain in the planner history. This is the
next offline optimization target: **7,278 request bytes** or less would admit
4,096 output tokens at this point, requiring a **2,567-byte reduction**.

The final native probe takes **38.78 seconds** (**44.44 seconds** for its test),
makes **five target requests** (three host setup checks and two discovery GETs),
and settles **7,252 synthetic tokens** across **11 loopback provider calls**.
The twelfth request is rejected before provider dispatch. Reservations settle
and native/MCP processes are cleaned up. Recon is `done`; enum's valid terminal
status is `partial` because ownership remains untested. The host preserves
that summary byte-for-byte and retains the prepared access handoff. No access
validation, report, signed closure or broader security coverage is claimed.

Verification and canonical artifacts:

All **179 preflight/context checks** passed in **6.06 seconds**, and all
**nine native/recon regressions** passed in **271.43 seconds**, with no failures
or skips. The separate signed-closure regression retains its existing
**2,000,000 synthetic-token fixture ceiling**: original/restored closures exit
0, all five mutations exit 2 and restore to exit 0. This verifies integrity
outside the 30,000-token probe. Ruff, repo layout, whitespace checks and the
artifact audit passed. The AST-only graph update produced **9,134 nodes /
21,272 edges** with zero provider calls.

- [Final verification and hashes](/tmp/cco-work/full-agent-context-window/enum-followup-ueuav9t1/verification.json) and [offline audit script](/tmp/cco-work/full-agent-context-window/enum-followup-ueuav9t1/audit_enum_followup.py). Reproduce with `python3 /tmp/cco-work/full-agent-context-window/enum-followup-ueuav9t1/audit_enum_followup.py`.
- [Final native probe](/tmp/cco-work/full-agent-integration/handoff_closure-t3n07t47/full-chain-budget-probe.json), [request diagnostics](/tmp/cco-work/full-agent-integration/handoff_closure-t3n07t47/runs/native-wse07rcf/private/provider-requests.json) and [message component measurements](/tmp/cco-work/full-agent-integration/handoff_closure-t3n07t47/runs/native-wse07rcf/private/native-context-sizes.json).
- [Observed enum proof](/tmp/cco-work/full-agent-integration/handoff_closure-t3n07t47/runs/native-wse07rcf/solver/enum/entry-response.json), [terminal summary](/tmp/cco-work/full-agent-integration/handoff_closure-t3n07t47/runs/native-wse07rcf/solver/summaries/enum-2.json) and [host handoff receipts](/tmp/cco-work/full-agent-integration/handoff_closure-t3n07t47/runs/native-wse07rcf/private/handoff-receipts.json).
- [Probe JUnit](/tmp/cco-work/full-agent-context-window/enum-followup-ueuav9t1/probe-final.xml), [179 preflight/context checks](/tmp/cco-work/full-agent-context-window/enum-followup-ueuav9t1/preflight.xml), [native and recon regressions](/tmp/cco-work/full-agent-context-window/enum-followup-ueuav9t1/native-final.xml), [Ruff](/tmp/cco-work/full-agent-context-window/enum-followup-ueuav9t1/ruff.log), [repo layout](/tmp/cco-work/full-agent-context-window/enum-followup-ueuav9t1/layout.log) and [AST-only graph update](/tmp/cco-work/full-agent-context-window/enum-followup-ueuav9t1/graphify.log).

The earlier audit remains a historical snapshot. Synthetic accounting does
not measure provider tokenization; the final 141-token enum completion and
9-token summary headroom are narrow. **Zero paid provider calls** were made.
The remaining paid allowance stays frozen at **36,402 tokens**, without a
balance query or refund. StateOps run: `0351ecc6-19ca-46c9-8361-b15b0f502c3f`.

## Offline completed-task planner context optimization — 2026-11-07

**The parent planner now admits all 4,096 output tokens and delegates access.**
Its enum follow-up request drops from **9,845 to 5,781 bytes**, saving
**4,064 bytes (41.3%)** against the actual native request. The next admission
stop moves to the **initial access worker request**. Access has been admitted
and scaffolded but has executed no target validation; report is **NOT TESTED**.
`full_chain_budget_passed=false`, `full_acceptance=false`, and paid-model
generalization remain unchanged/not evaluated.

Graphify traced the completed native `task` calls back to the canonical host
arguments. Their original recon/enum assistant messages occupy **1,789 /
2,725 bytes** in the parent history. The optimization replaces only completed,
exactly matched historical arguments with the original compact
`TaskSpec: <id>` pointers. The planner keeps its full system/user instructions,
both tool schemas (**688 bytes**), raw task results, call IDs and message order.
Native execution still receives the full host-rendered commands and tool list.

The native task after-hook sends a completion callback to the local broker.
The broker correlates the admitted parent session/call ID, child-session
metadata and completed native wrapper; verifies a terminal summary for the
exact phase/target; and checks the saved contract bytes. It stores immutable
SHA-256 receipts containing the full original arguments/output and summary/
contract references. Provider projection additionally requires the exact
history arguments/result and current file/receipt hashes. Missing, changed,
failed-shape, duplicate, out-of-order, symlink and nonregular items retain
their original content. A valid failed terminal phase still cannot advance.
The completion callback grants no execution or security-confirmation authority.

Full contracts are now saved for every admitted phase. The existing tool
before-hook and MCP untrusted-output wrapper are byte-for-byte unchanged;
the task completion callback is the only addition to the after-hook. Scope,
session/ownership/handoff freshness, shared budget and signing gates remain
active. The **30,000 ceiling** and **`2 * request_bytes + 4096`** admission
formula are unchanged. Enum still admits **4,096 tokens for its first three
turns**, including the unchanged **7,557-byte initial request**.

| Parent enum follow-up metric | Prior probe | Fresh probe |
|---|---:|---:|
| Remaining run tokens | 22,748 | 22,748 |
| Messages bytes | 9,081 | **5,017** |
| Tools bytes | 688 | 688 |
| Request bytes | 9,845 | **5,781** |
| Prompt upper bound | 23,786 | **15,658** |
| Admitted output tokens | 0 | **4,096** |
| Full-output reservation headroom | — | **2,994 tokens** |

The earlier recon-to-enum planner continuation also shrinks from **6,928 to
5,368 bytes**. Its output allowance remains 4,096. The native planner then
really calls `task` for access; the host verifies the existing handoff and
creates the deterministic access skeleton before attempting worker admission.

The access request is **9,899 bytes**: messages **3,618**, tools **6,206**,
prompt bound **23,894**, and remaining budget **22,631**. Its prompt alone is
**1,263 tokens too large**, so no provider call or access MCP validation occurs.
The next offline target is **7,219 request bytes or less** to retain 4,096
output tokens, requiring a **2,680-byte reduction**. The host preserves the
in-progress draft and writes a valid blocked access summary with an
interruption receipt and **zero access tool artifacts**. Recon remains `done`;
enum remains terminal `partial` with its real prepared handoff. No report or
30,000-token signed closure is produced.

The final probe takes **20.57 seconds native / 23.83 seconds test**, makes
**five target requests** (three setup checks, recon GET, enum GET), and settles
**7,369 synthetic tokens across 12 loopback provider calls**. The thirteenth
request is rejected before dispatch. All reservations settle and recorded
native/MCP processes are cleaned up. **204 offline preflight/context tests**
passed in **2.34 seconds**; all **nine native/recon regressions** passed in
**170.03 seconds**, with zero failures or skips. The separate closure integrity
regression retains its **2,000,000 synthetic-token fixture ceiling**: baseline
and restored closures exit 0; five mutations exit 2 and restore to exit 0.
Ruff, JavaScript syntax, repo layout, whitespace checks and artifact audit pass.
AST-only graph update: **9,149 nodes / 21,301 edges**, with zero provider calls.

Canonical artifacts:

- [Verification and hashes](/tmp/cco-work/full-agent-context-window/planner-opt-rswv25hp/verification.json) and [reproducible offline audit](/tmp/cco-work/full-agent-context-window/planner-opt-rswv25hp/audit_planner.py). Run `python3 /tmp/cco-work/full-agent-context-window/planner-opt-rswv25hp/audit_planner.py`.
- [Fresh native probe](/tmp/cco-work/full-agent-integration/handoff_closure-ff4wf_ej/full-chain-budget-probe.json), [request diagnostics](/tmp/cco-work/full-agent-integration/handoff_closure-ff4wf_ej/runs/native-1aqgfxey/private/provider-requests.json) and [native completion receipts](/tmp/cco-work/full-agent-integration/handoff_closure-ff4wf_ej/runs/native-1aqgfxey/private/task-completions.json).
- [Blocked access summary](/tmp/cco-work/full-agent-integration/handoff_closure-ff4wf_ej/runs/native-1aqgfxey/solver/summaries/access-3.json), [host finalization](/tmp/cco-work/full-agent-integration/handoff_closure-ff4wf_ej/runs/native-1aqgfxey/private/task-finalization.json) and [access tool schemas](/tmp/cco-work/full-agent-integration/handoff_closure-ff4wf_ej/runs/native-1aqgfxey/private/access-tool-schemas.json).
- [Probe JUnit](/tmp/cco-work/full-agent-context-window/planner-opt-rswv25hp/probe-final.xml), [204 offline checks](/tmp/cco-work/full-agent-context-window/planner-opt-rswv25hp/preflight.xml), [native/recon regressions](/tmp/cco-work/full-agent-context-window/planner-opt-rswv25hp/native-final.xml), [Ruff](/tmp/cco-work/full-agent-context-window/planner-opt-rswv25hp/ruff.log), [JS syntax](/tmp/cco-work/full-agent-context-window/planner-opt-rswv25hp/js-check.log), [layout](/tmp/cco-work/full-agent-context-window/planner-opt-rswv25hp/layout.log) and [AST graph update](/tmp/cco-work/full-agent-context-window/planner-opt-rswv25hp/graphify.log).

This establishes the planner-context slice and actual access admission, not
full-chain acceptance or paid-model behavior. **Zero paid provider calls**;
the allowance stays frozen at **36,402 tokens**, without a balance query or
refund. StateOps run: `f881f291-4d60-44f0-b33a-7773516a82c2`.

## Offline access results and conservative chain recheck — 2026-11-07

**The native validation and signed-closure regressions now finish cleanly.
The exact conservative 30,000-token chain still blocks at the initial access
request.** Its strict test remains **FAILED**, `full_chain_budget_passed=false`
and `full_acceptance=false`. Paid-model generalization is not evaluated.
This is the measured boundary permitted by the resume task, not a completed
30,000-token acceptance claim.

Read `AGENTS.md`, the two preceding sections and
`/tmp/cco-work/resume-task.md`; retained the existing worktree changes and
regenerated verification artifacts after the host restart. Local health check:
**7 passed / 0 failed**. Graphify queries located the provider view, native
fixture, admission and closure paths before source inspection.

The chain child previously called the launcher directly, bypassing the native
integration fixture's loopback discovery baseline. It now calls the shared
`integration_child`: the observed `/go` page returns a usable 200 discovery
baseline; the original lab handler still provides the real 302 Location oracle
for external sentinel parameters. The baseline replay stopped discovery/fuzz
with a policy rate-limit diagnostic before validation. No validator verdict,
request receipt or signing result is manufactured by the fixture correction.
The report provider requires real validation IDs; its assertion on an empty
list can otherwise return HTTP 500 and correctly retain a provider reservation
as invalid. The fail-closed production usage checks remain unchanged.

The preserved large-MCP-result projection keeps validation decisions,
confirmation IDs, errors and signatures, and references large fields through
an explicit `omitted_fields` list and a hash-bound full JSON artifact. The
native validation fixture now reads that full artifact through `read` before
persisting `access/live-result.json`. The saved result matches the actual host
MCP receipt, including discovery/fuzz and blocked-work diagnostics. Projection
also refuses stale files, unsafe parents, out-of-workspace paths, symlinks,
FIFOs, directories and failed artifact creation. **Eight additional artifact
fault checks pass.** The access contract continues to expose the real
`validator_session_vault_check` refresh command/tool before LIVE.

The context replay fixture also stops restarting bootstrap after its GET has
completed: a shortened recon continuation must not trigger new scope/scaffold
reads. Its native regression passes, and the chain's first three enum turns
again admit **4,096 output tokens each**, including the unchanged **7,557-byte**
initial request. The original strict enum assertions remain in place.

There is a material accounting distinction in the resumed workspace.
`full_agent_budget.py` already contains a calibrated production bound, with
an offline fallback of `request_bytes + 2048`; that existing code was **not
edited** in this resume. The interrupted snapshot's 10,446-byte report request
could not be admitted at 20,642 remaining tokens under the requested historical
formula: `2 * 10446 + 4096 = 24988`, exceeding even the prompt allowance by
4,346 tokens. The old temporary receipts were lost in the restart, so that
snapshot is not conservative-budget proof. The final chain child explicitly
pins **`2 * request_bytes + 4096`** independently of production calibration or
local tokenizer caches. Every request diagnostic is audited against that exact
formula. The **30,000 ceiling** and frozen paid allowance are unchanged.

| Final conservative access admission metric | Measured value |
|---|---:|
| Remaining synthetic run tokens | **22,631** |
| Messages / tools bytes | **3,735 / 6,448** |
| Request bytes | **10,258** |
| Prompt bound: `2 * request_bytes + 4096` | **24,612** |
| Prompt deficit before any output | **1,981 tokens** |
| Admitted output / dispatched access provider calls | **0 / 0** |
| Largest request admitting 4,096 output tokens | **7,219 bytes** |
| Required reduction for that output allowance | **3,039 bytes** |

The final conservative probe takes **38.91 seconds native / 42.57 seconds
test**, sends **five target requests** (three setup checks and two discovery
GETs), and charges **7,369 synthetic tokens across 12 loopback provider calls**.
The thirteenth request is rejected before dispatch. Recon is `done`, enum is
terminal `partial`, access is admitted/scaffolded and finalized `blocked`, and
report is **NOT TESTED**. No access validation or closure is claimed for this
probe. Its launch status is **`token_admission_exhausted`**, not `budget_invalid`;
all measurements are valid, all reservations settle, and recorded native/MCP
processes are cleaned up. The probe JSON is saved before the strict success
assertion, so failure cannot erase the measured boundary.

The separate existing signed-closure regression retains its **2,000,000
synthetic-token fixture ceiling** and production admission profile. It produces
`ok=True`, one real `open_redirect` validation with `CONFIRMED` verdict, the full
host result and an Ed25519 closure. Launch status is
**`native_finished_unverified`**, with **51 loopback provider calls**, **21 target
requests**, **7,293 measured synthetic tokens**, **66.11 seconds** native time,
no invalid budget and no outstanding reservations. Original/restored closure
verification exits 0; all **five** payload/signature/attempt mutations exit 2
and restore to exit 0. This resolves the two fixture failures without claiming
that small synthetic settled usage establishes conservative 30,000-token
admission. Broader vectors remain explicitly NOT TESTED.

Final verification: **225 preflight/context checks passed in 2.84 seconds**,
**one native context replay passed in 33.73 seconds**, and **all 12 native
regressions passed in 723.21 seconds**, with no errors or skips. The separate
strict chain test has **one failure**, at its required successful-exit check.
Initial concurrent diagnostic runs caused a context timeout on this host;
the initial native batch was interrupted with fixture cleanup. Final native
runs were serialized. Whole-repo Ruff, repo layout, JS syntax, whitespace and
the artifact-consistency audit pass. AST-only `graphify update .` uses no LLM;
final graph counts and SHA-256 hashes are recorded in the audit artifact.

Canonical regenerated artifacts:

- [Verification and hashes](/tmp/cco-work/offline-context-resume/verification.json), [offline audit](/tmp/cco-work/offline-context-resume/audit_resume.py) and [audit output](/tmp/cco-work/offline-context-resume/audit.log). Reproduce with `python3 /tmp/cco-work/offline-context-resume/audit_resume.py`; audit consistency is distinct from chain acceptance.
- [Final conservative probe](/tmp/cco-work/full-agent-integration/handoff_closure-2fgf4z9z/full-chain-budget-probe.json), [request diagnostics](/tmp/cco-work/full-agent-integration/handoff_closure-2fgf4z9z/runs/native-bqc6z922/private/provider-requests.json), [budget](/tmp/cco-work/full-agent-integration/handoff_closure-2fgf4z9z/runs/native-bqc6z922/private/budget.json) and [blocked access summary](/tmp/cco-work/full-agent-integration/handoff_closure-2fgf4z9z/runs/native-bqc6z922/solver/summaries/access-3.json).
- [Native closure regression](/tmp/cco-work/full-agent-integration/handoff_closure-7pjy9kzn/closure-acceptance.json), [complete LIVE result](/tmp/cco-work/full-agent-integration/handoff_closure-7pjy9kzn/runs/native-51uw5rvz/solver/access/live-result.json), [signed closure](/tmp/cco-work/full-agent-integration/handoff_closure-7pjy9kzn/runs/native-51uw5rvz/solver/closure.json) and [five-mutation integrity check](/tmp/cco-work/full-agent-integration/handoff_closure-7pjy9kzn/runs/native-51uw5rvz/solver/report/closure-integrity.json).
- [Strict probe JUnit](/tmp/cco-work/offline-context-resume/probe-final.xml), [225 offline checks](/tmp/cco-work/offline-context-resume/preflight-context-final.xml), [native context replay](/tmp/cco-work/offline-context-resume/context-native-final.xml) and [12 native regressions](/tmp/cco-work/offline-context-resume/native-final.xml).
- [Ruff](/tmp/cco-work/offline-context-resume/ruff-full.log), [repo layout](/tmp/cco-work/offline-context-resume/layout.log), [JS syntax](/tmp/cco-work/offline-context-resume/js-check.log), [whitespace](/tmp/cco-work/offline-context-resume/diff-check.log) and [AST graph update](/tmp/cco-work/offline-context-resume/graphify.log).

**Zero paid provider calls**, with no paid-provider API-key use, balance query or refund.
The remaining paid allowance stays frozen at **36,402 tokens**. Synthetic
fixture authentication uses fresh loopback-only credentials. StateOps run:
`bd6a300c-9565-4eb7-9545-dbe7e921dc51`. Earlier temporary artifact links remain
historical and were not recreated under their old names.

## Production-bound 30,000-token chain and fresh smoke package — 2026-11-07

**The native 30,000-token chain now PASSES under the actual production
`prompt_bound`: recon-1 → enum-2 → access-3 → report-4 → Ed25519 closure.**
`full_chain_budget_passed=true`; `full_acceptance=false` and paid-model
generalization remain unevaluated. This production-bound check replaces the
historical 2x probe as the next-step gate. The preceding historical results
remain recorded under their original assumptions.

Read `/tmp/cco-work/next-step.md` and removed the test-only
`historical_prompt_bound` override from `tests/test_full_agent_chain_budget.py`.
The test now recomputes every actual serialized upstream request with the
production function, checking its bound, tokenizer profile and framing
metadata. Production budget, context and launcher files, and the existing
context/native fixture tests, retain their previous SHA-256 hashes. No further
historical-formula byte reduction is retained.

The host restart had cleared the production default tokenizer cache. The first
production-bound replay therefore used `utf8_bytes_1x` and stopped after the
LIVE result: 25,661 request bytes, 27,709 prompt-bound tokens and 21,578 remaining
tokens. A keyless public dependency GET obtained the pinned **1,681,126-byte**
`cl100k_base` vocabulary; its SHA-256 is
`223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7`.
The verified asset is retained in the smoke package and installed at
`/tmp/data-gym-cache/9b5ad71b2ce5302211f9c61530b329a4922fc6a4`.
Production still never downloads a missing vocabulary. The passing replay
uses the unmodified **`cl100k_base_1.5x`** profile:
`min(request_bytes, ceil(1.5 * serialized_cl100k_tokens)) + 2048`.
An uncached fallback is not claimed to pass this chain; the prepared operator
driver refuses missing, changed or differently located cache assets before
credential lookup or paid dispatch.

| Production-bound chain measurement | Result |
|---|---:|
| Shared LLM ceiling | **30,000 tokens** |
| Measured synthetic charge / remaining run tokens | **10,528 / 19,472** |
| Loopback provider calls / target HTTP requests | **39 / 18** |
| Native / test duration | **85.14 / 95.22 seconds** |
| Largest serialized request | **29,855 bytes** |
| Largest prompt bound | **14,345 tokens** |
| Requested and admitted output on every call | **4,096 tokens** |
| Minimum reservation headroom | **1,706 tokens** |
| Admission rejections / invalid measurements / pending reservations | **0 / 0 / 0** |

All four actual native tasks are admitted in order. Recon finishes `done`;
enum, access and report retain valid terminal `partial` summaries and explicitly
park broader coverage. LIVE returns `ok=True` with one real `open_redirect`
`CONFIRMED` validation. Its complete saved JSON matches the host MCP receipt;
current signed validation/ledger evidence and the Ed25519 closure are retained.
Original and restored closure verification exit 0, all five payload/signature/
attempt mutations exit 2 and restore to exit 0. Launch exits 0 with
`native_finished_unverified`, exact scope verified before traffic, valid usage
settlement and native/MCP process cleanup. These are local scripted-model
measurements, not paid-model tokenization or broader acceptance evidence.

A fresh measured HTTP/Chromium comparison passed **37/37 tests** in **202.98
seconds** (JUnit), with no errors or skips: five seeds, each with **8/8 proven
positives, 8/8 clean negatives, zero mapped false positives and 259 actual GETs**.
Total comparison traffic is **1,295 test-owned local GETs**, with no LLM calls.
The native integration fixture's synthetic comparison was not used as the paid
smoke baseline. Fresh ZenMux native preflight passes all **five checks** and
freezes **206 runtime files**, initially non-runnable with empty scope and
denied tools.

The new operator package freezes seed **20261104**, planner and worker
`zenmux/deepseek/deepseek-v4.1-flash`, and provider
`https://zenmux.ai/api/v1`. It permits **one launch, 30,000 shared LLM tokens,
300 target HTTP requests and 600 seconds**, with no paid retry or extra seed.
The reference contract's five seeds and 150,000-token benchmark aggregate do
not expand this operator envelope. The session allowance stays **36,402**;
if the whole proposed cap is later charged, the conservative aggregate would
be **993,598 charged / 6,402 remaining**. This is a forecast, not a preparation
charge or balance query.

The actual driver/launcher plan-only check succeeds with zero model and target
calls. Plan, model, provider, measured baseline, runtime/source/binary hashes and
the pinned cache are checked before credentials. The operator's `--execute`
flag triggers one frozen attempt, with an inherited `ZENMUX_API_KEY` or
`CCO_BENCHMARK_API_KEY`, or hidden terminal input. No `.env` or credential store
is read. Missing credentials do not spend the attempt. An exclusive 0600 claim
precedes dispatch; repeat claims/prior output reject, prompt-time drift is
rechecked, and post-claim errors retain unknown usage under the full conservative
cap. No real claim, live-run directory or paid dispatch was created.

Operator launch command (prepared, **not executed** during this work):

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/run.py --execute
```

Run the same command without `--execute` for offline plan-only verification.
The [README](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/README.md)
contains credential handling, stopping rules and cache recovery details.

Final checks: **one production chain test passed**, **225 preflight/context
checks passed in 10.78 seconds**, and **33 offline driver guards passed in
19.30 seconds**, with no failures/errors/skips. Whole-repo and explicit operator
file Ruff, repo layout, whitespace and artifact audit pass. Ruff-generated cache
files were removed from the frozen runtime; final operator lint uses
`--no-cache`, and the original inventory/hash replay succeeds unchanged.
AST-only graph update: **9,167 nodes / 21,362 edges**, with zero LLM calls.

Canonical fresh artifacts:

- [Production-chain verification and hashes](/tmp/cco-work/full-agent-paid-smoke-preparation/production-chain/verification.json) and [reproducible offline preparation audit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/audit_preparation.py). Run `python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/audit_preparation.py`.
- [Passing native chain](/tmp/cco-work/full-agent-integration/handoff_closure-c82g_l0k/full-chain-budget-probe.json), [production admission diagnostics](/tmp/cco-work/full-agent-integration/handoff_closure-c82g_l0k/runs/native-wob_6l42/private/provider-requests.json), [full LIVE evidence](/tmp/cco-work/full-agent-integration/handoff_closure-c82g_l0k/runs/native-wob_6l42/solver/access/live-result.json) and [closure integrity](/tmp/cco-work/full-agent-integration/handoff_closure-c82g_l0k/runs/native-wob_6l42/solver/report/closure-integrity.json).
- [Preparation summary](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/preparation.json), [frozen plan](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/plan.json), [driver](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/run.py), [33 offline guards](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/driver-checks.xml) and [real plan-only output](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/plan-only.log).
- [Measured comparison](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/baseline/run-ox3vv3bp/acceptance.json), [37-test JUnit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/baseline/run-ox3vv3bp/junit.xml) and [fresh native preflight](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/preflights/preflight-m425ychw/preflight.json).
- [Chain JUnit](/tmp/cco-work/full-agent-paid-smoke-preparation/production-chain/probe.xml), [225 offline checks](/tmp/cco-work/full-agent-paid-smoke-preparation/production-chain/preflight-context.xml), [Ruff](/tmp/cco-work/full-agent-paid-smoke-preparation/production-chain/ruff.log), [repo layout](/tmp/cco-work/full-agent-paid-smoke-preparation/production-chain/layout.log) and [AST-only graph update](/tmp/cco-work/full-agent-paid-smoke-preparation/production-chain/graphify.log).

**Paid provider calls remain zero; the 36,402-token allowance stays frozen**,
with no balance query or refund. The single public vocabulary download is
dependency setup, separate from provider or target testing. StateOps run:
`3b88b392-004c-46aa-b066-41d8798f66b7`.


## Continuation contract repair and 150,000-token solve preparation — 2026-11-07

The previously prepared production smoke was subsequently executed. Its
[launch](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261107/live-runs/native-ers_iwjv/launch.json)
stopped at `token_admission_exhausted` after **7 paid calls, 23,532 charged tokens,
4 target requests and 57.88 seconds**, during `recon-1`. Reservations settled.
The final request had **6,468 tokens remaining**, a **13,054-token prompt bound**
and zero admitted output. Its historical session allowance became **12,870**.
The zero-paid-call statements above describe those earlier preparation steps,
not the later execution.

The requested `proxy/calls.jsonl` is absent from the supplied preparation and
run directories. The review uses available host admission diagnostics,
`native-gates.json`, original native write receipts and the persisted worker
contract. Raw provider message reconstruction is unavailable. The
[launch analysis](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-solve-20261107/launch-analysis.json)
records that evidence limit and the measured admission stop.

`worker_followup_context` now retains exact Commands, ordered step/fallback
instructions, Tools, scope and call/deadline constraints, evidence directory,
summary output path, pool/handoff paths and phase-specific summary fields in
continuations. Output paths remain present even for commandless tasks. A
successful historical write keeps its original `filePath` alongside the
byte-verified content reference. Current tool schemas, native history and
original files stay intact. The continuation asks workers to complete remaining
commands and write compact JSON with `filePath` and `content`; it avoids a
blanket bash restriction that would contradict an authorized command.

The regressions cover recon, enum, access and report; the first successful MCP
result; subsequent verified writes; repeated projections; nested evidence
paths; commandless tasks; exact summary/step contracts; and unchanged write
schemas. Existing failed, stale, ambiguous, symlink and artifact integrity
checks remain in the suite. The broader native provider regression also checks
that preserved Tools prevent unnecessary fallback contract reads.

The new [plan](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-solve-20261107/plan.json)
and [driver](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-solve-20261107/run.py)
freeze **one attempt, 150,000 shared LLM tokens, 600 seconds, 300 target HTTP
requests and zero automatic retries**. Planner/worker remain
`zenmux/deepseek/deepseek-v4.1-flash`, seed `20261104`, through the existing
ZenMux provider. This is the explicitly requested allowance for this new run;
the previous session accounting remains separate historical metadata. No
account balance, refund or paid acceptance result is inferred.

The **17 original, hash-verified baseline measurement files** were reused,
retaining the recorded 37/37 comparison and five-seed measurements. Only
measurement files enter the new baseline; pytest scratch state and symlink
aliases are excluded. The existing pinned tokenizer vocabulary and production
cache were reused with **zero downloads**. A fresh native preflight freezes the
current runtime and passes all prerequisites. Its reference benchmark contract
retains its supported limits; the driver restricts execution to the single
seed and applies `--timeout-seconds 600`. Reference benchmark aggregates do not
expand the operator envelope.

Plan-only replay passes with zero provider and target dispatch. Package,
source, binary, baseline and cache hashes are checked before credentials. The
0600 exclusive claim, prompt-time drift recheck, no-retry behavior and
conservative unknown-usage handling are retained. No `attempt-claim.json` or
`live-runs` directory was created in this preparation.

Operator command, **prepared and not executed**:

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-solve-20261107/run.py --execute
```

Verification artifacts live under
[checks](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-solve-20261107/checks).
The offline [audit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-solve-20261107/audit_preparation.py)
replays frozen hashes, budget/claim invariants, baseline reuse and successful
JUnit/quality-gate records. Local scripted tests establish regression coverage;
paid model generalization and full acceptance remain unevaluated.
StateOps run: `5641b751-cdef-4d03-a342-3c966b0156c3`.

Final verification: **287/287 regressions passed** in 367.97 seconds, including
the native read-only API family; **2/2 native context/full-chain replays passed**
in 176.33 seconds; **33/33 frozen driver guards passed** in 17.78 seconds. The
final continuation/ordered-step edit was separately verified by **53/53 context
tests** in 0.68 seconds. All JUnit records have zero failures, errors and skips.
Ruff, repository layout, whitespace and AST-only graph update passed. The graph
contains **9,170 nodes / 21,372 edges**; no LLM was used for its update.
Preparation made **zero paid provider calls**, ran no paid solve and downloaded
no tokenizer vocabulary.


## Paid-run failure repair: retained write versions and enum feedback — 2026-11-07

The 150,000-token package was subsequently executed as
`native-gm4v2zz9`. Recon completed, enum stopped, and access/report were not
admitted. The run charged **130,566 tokens** over **24 paid calls**: **118,516
prompt / 12,050 completion tokens**, with **21 HTTP requests / 191.81 seconds**.
The next request required a **23,423-token prompt bound** with **19,434 tokens
remaining** and was rejected before dispatch. Its terminal enum draft lacked
embedded `surface.routes/params`; no host handoff receipt existed. The earlier
preparation claims above refer to preparation, before this later execution.

The repair preserves exact current write paths while referencing superseded
content through immutable workspace snapshots. A historical version is eligible
only when its earlier exact private write receipt exists and a later successful
native write verifies the current file bytes. Unknown edits, failed successors,
ambiguous IDs/results and stale/corrupt/symlink receipts remain unprojected.
Current contents and native history are unchanged.

Full native JSON reads now omit only formatting/line-number overhead after
matching the entire numbered output to current workspace bytes. Every JSON
value, validation result and signature is preserved; the original numbered
output remains available in a hashed snapshot. Partial, truncated and unknown
read formats stay intact. Current Commands, Tools, scope, evidence paths,
summary paths and ordered step instructions remain in the worker context.

Both prompt modes explicitly require enum surface fields inside the summary
JSON. Every provider continuation receives current host feedback for malformed
or invalid terminal summary bytes. The worker must rewrite the file from
observations; the host never inserts inferred routes or repairs a verdict.
A valid enum summary receives separate feedback until a current exact-vector
host handoff receipt exists. Existing phase, scope, signature, closure and
budget admission checks remain authoritative.

**315/315 related tests passed** (including module boundaries), and **3/3 native
replays passed** with zero skips/failures/errors. The new replay deliberately
omits surface, consumes real validation feedback, rewrites a valid enum summary,
prepares the host handoff, and completes all four native phases and signed
closure/tamper checks. It reports **40 scripted provider calls, 10,645 synthetic
tokens, 18 HTTP requests and 26.97 seconds**, with no pending reservations and
verified process cleanup. Ten full JSON-read projections were exercised in its
actual provider request history. These are scripted-model measurements.

The original paid run's **four known enum writes** were independently replayed
with remapped local paths: context fell from **18,586 to 4,438 bytes**, and the
subset prompt bound fell from **11,389 to 4,037 tokens**. The exact missing-surface
error reaches the worker. Unavailable paid request history is excluded, so this
is not a reconstructed full paid run or proof of paid-model acceptance.
A separate pressure regression verifies twelve surface rewrites: the raw
history fails the 19,434-token remaining window, while the projected history
admits all 4,096 requested output tokens. No tokenizer coefficient or budget
guard was relaxed.

Artifacts: [known paid-write replay](/tmp/cco-work/full-agent-context-repair/repair-20261107/paid-artifact-replay.json),
[reproducible replay script](/tmp/cco-work/full-agent-context-repair/repair-20261107/replay_paid_artifacts.py),
[unit JUnit](/tmp/cco-work/full-agent-context-repair/repair-20261107/checks/unit.xml),
[native JUnit](/tmp/cco-work/full-agent-context-repair/repair-20261107/checks/native.xml),
and [repair verification](/tmp/cco-work/full-agent-context-repair/repair-20261107/repair-verification.json).
Ruff, repository layout, whitespace and AST-only graph update passed.
**Zero new paid provider calls** and no paid retry/package were created during
this repair. A fresh paid-model acceptance measurement remains outstanding.
StateOps run: `6cfd2f9a-2d17-41cb-a982-cf62d863789a`.


## Fresh post-repair live measurement package — 2026-11-07

A new single-use package freezes the repaired host context and enum feedback
code, with **one launch, 150,000 shared LLM tokens, 600 seconds, 300 target HTTP
requests and zero automatic retries**. It retains seed `20261104`, planner and
worker `zenmux/deepseek/deepseek-v4.1-flash`, and the existing provider. The two
previous paid runs are immutable historical metadata: **23,532 + 130,566 =
154,098 tokens**. That history is separate from this new run allowance and
makes no claim about an account balance or refund.

The existing **17 hash-verified baseline measurement files** and pinned
vocabulary/production cache were reused unchanged. A fresh preflight passes
prerequisites and freezes the current runtime. Repaired code bytes match the
previously passing **315 unit/module checks and 3 native replays**; those JUnit
artifacts are retained without rerunning the comparison or repeating unchanged
native tests. The benchmark reference's aggregate limits do not expand the
single-launch envelope; the operator driver applies its 600-second timeout.

The driver now writes `run-measurement.json` after dispatch and links it from
`result.json`. Measurements include charged/prompt/completion tokens per phase,
peak admission bounds, context savings, read and retired-write projections,
summary feedback, preserved draft errors, admitted tasks and terminal summary
checks. Cache/reasoning subsets are counted once. Missing usage remains unknown;
finished phases or artifact presence do not confer acceptance. Current signed
validation, coverage and closure must still be independently audited.

The collector was replayed against `native-gm4v2zz9`: **35,234 recon tokens,
90,416 enum tokens and 4,916 orchestration tokens**, totaling **130,566**. The
blocked enum's preserved draft still exposes its missing-surface error.
Fresh driver guards and measurement accounting/integrity checks pass. Ruff,
repo layout, whitespace and AST-only graph update pass. Default plan-only
passes with zero credential lookup, provider calls or target dispatch.

**The paid measurement has not started:** the agent runtime has no inherited
`ZENMUX_API_KEY` or `CCO_BENCHMARK_API_KEY`. The operator can execute the prepared
command in the credential-bearing terminal, with inherited credentials or
hidden key input. Missing credentials do not spend the claim. No .env or
credential store is read. No live-run directory, attempt claim, paid dispatch
or vocabulary download was created during preparation.

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-measurement-20261107/run.py --execute
```

Artifacts: [frozen plan](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-measurement-20261107/plan.json),
[driver](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-measurement-20261107/run.py),
[measurement code](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-measurement-20261107/measure_run.py),
[previous-run measurement](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-measurement-20261107/previous-run-analysis.json),
[preparation audit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-measurement-20261107/audit_package.py),
and [verification](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-live-measurement-20261107/preparation.json).
StateOps run: `2ac71fba-38fd-4a5c-9c68-e19552296d43`.

## Recorded measurement failure and host budget controls — 2026-11-07

The operator subsequently executed the measurement package. Its single-use
claim is consumed: `native-a895ydyz` stopped with `token_admission_exhausted`,
25 paid provider calls and **141,730 charged tokens** (130,038 prompt + 11,692
completion). Recon consumed 70,977 tokens, enum 65,576 and orchestration 5,177.
The next prompt bound was 21,854 with only 8,270 tokens remaining. HTTP (23
requests) and time (212.08 seconds) were not limiting. Enum never replaced its
in-progress scaffold; access, report and current handoff were absent. Full paid
acceptance remains **false**. The earlier statement that the package had not
started describes preparation time only. Do not reuse its consumed driver or
assume it contains the following repairs.

Recon made six attempt-ledger calls. Five sequential failures reported missing
vector, endpoint, identity, verdict and an invalid string status. This repair
removes the attempt ledger from broker recon/enum/seed contracts and provider
tool exposure; direct calls are also refused by the existing TaskSpec boundary.
Validation/report contracts retain the signed ledger and now explain its inner
JSON fields in full, including HTTP integer status and artifact paths. Batch
validation reports all field defects together without appending bad records.
Two failed executions of the same tool disable further retries for that task;
a successful execution resets the failure count. Native local policy denials
also feed this brake. Scope, validation, signing and closure gates still apply.

Native launches now publish a host-owned `native-runtime-policy/1` in
`launch.json` effective limits and `private/runtime-policy.json`. For the
150,000-token envelope, ceilings are:

| Phase | Token ceiling | Provider call ceiling | Finalization turns |
| --- | ---: | ---: | ---: |
| recon | 30,000 | 10 | 3 |
| enum | 45,000 | 16 | 4 |
| access | 37,500 | 24 | 4 |
| report | 22,500 | 16 | 8 |
| planner | 15,000 | 8 | — |

Shares include prompt and completion usage, use conservative charging on
unknown usage, and cannot be reset by reusing a task ID. Small budgets have a
planner framing floor taken from worker shares; no allowance is added to the
global cap. Unused phase shares are not borrowed by earlier phases. Probe
admission withholds a finish reserve; near the phase/call/tool boundary the
worker receives `FINALIZE NOW` and only closure-related tools remain available.
Report has more finalization turns because coverage, custody, checkpoint and
integrity checks require several distinct operations. Finalization also
reserves native tool opportunities: enum retains six calls for session
refreshes, summary and handoff, rather than just two generic closing calls.
The completion minimum
is 1,024 admitted output tokens, so the recorded 526-token tail is refused.
Recon is also limited to ten native tool attempts. An unfinished task at a
hard ceiling stops with an explicit phase-budget reason and preserves its
draft/evidence; it never gains a successful or tested verdict automatically.

Outgoing context includes at most 24,000 message bytes and a 12,000-token
prompt bound, including tool schemas and the host's own allowance feedback.
Complete older assistant/tool turns move to exact hash-verified, solver-visible
workspace archives. System/user instructions, Commands, summary paths,
write.filePath and unresolved/ambiguous calls remain available. Recent turns
are kept where they fit; explicit history indexes identify completed calls and
truncated excerpts. Full errors, observations and signatures remain in exact
archives. These references supply context only and confer no execution or
coverage authority. If safe projection cannot meet the limit, admission stops
before provider dispatch with `context_limit_exhausted`.

The [recorded-input replay](/tmp/cco-work/full-agent-budget-repair/repair-20261107/recorded-failure-replay.json)
replays the exact six saved ledger inputs: five invalid records report all
remaining defects, the sixth creates exactly one signed record. Replaying
original prompt bounds/charges against the new phase policy refuses original
provider call 9 while 123,991 global tokens remain. This counterfactual checks
the stopping policy; it does not predict repaired model behavior or acceptance.
The [reproducer](/tmp/cco-work/full-agent-budget-repair/repair-20261107/replay_recorded_failure.py)
makes zero provider calls and zero target requests.

Verification and current source hashes are recorded in
[repair-verification.json](/tmp/cco-work/full-agent-budget-repair/repair-20261107/repair-verification.json).
**324 unit/module/contract checks and four native tests pass**: context
continuation, malformed-enum repair, isolated planner/worker execution and the
four-phase signed closure with five post-seal tamper controls. Whole-repo Ruff,
repo layout, whitespace and AST-only graph update pass. All repair/replay
provider calls are local scripted calls; **paid provider calls: zero**.
The native chain probe now uses the 150,000-token envelope with phase controls;
earlier 30,000-token probe results remain historical. Scripted providers consume
the public archive indexes and verify archived result hashes, preserving real
MCP execution, signed closure and post-seal tamper controls. Their synthetic
usage is not paid-model performance evidence. No paid retry or replacement
operator package was launched or prepared in this repair.

StateOps repair run: `884e3ff9-313a-42d6-81ab-63b5a3f35ec0`.


## Fresh production package after host budget repairs — 2026-11-08

The replacement operator package is prepared at
`/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108` with **TOKENS=150000, SECONDS=900, HTTP=300, SEED=20261104**.
It admits **one launch**, planner and worker
`zenmux/deepseek/deepseek-v4.1-flash`, provider `https://zenmux.ai/api/v1`,
with no paid retry or extra seed. The repaired phase ceilings, `FINALIZE NOW`
finish reserves, retry brake, 24,000-byte context limit, 12,000-token prompt
limit and exact hash-verified history archives are frozen from current source.
Phase token ceilings are recon **30,000**, enum **45,000**, access **37,500**,
report **22,500**, planner **15,000**; provider call ceilings remain
**10 / 16 / 24 / 16 / 8**. The driver passes the **900-second** host deadline
explicitly to the native launcher. The reference contract retains five baseline
seeds and its supported 1,800-second ceiling/750,000-token aggregate; these do
not expand the single-launch operator envelope. Historical session allowances
are not treated as a current balance or permission to spend.

The previously documented measured baseline under
`preparation-production-20261107/baseline/run-ox3vv3bp` was absent in this
session. Searches found only synthetic pytest fixture baselines; those were
refused as paid-run evidence. A fresh run of the existing HTTP/Chromium
comparison produced [measured baseline](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/baseline/run-z1d2x_9a/acceptance.json) and retained the existing
five seeds and comparison contract. **37/37 tests pass**, with zero errors,
failures or skips; each seed measures **8/8 proven positives, 8/8 clean
negatives, zero mapped false positives and 259 GETs**. The **1,295 total GETs**
belong to test-owned ephemeral loopback origins, with fixture-local scope and
approval. This baseline recovery makes **zero paid model calls**.

The existing **1,681,126-byte** tokenizer cache at
`/tmp/data-gym-cache/9b5ad71b2ce5302211f9c61530b329a4922fc6a4` was hash-verified
and reused, with **no download**. The driver requires `cl100k_base_1.5x` and
refuses a missing/changed cache or a different configured cache directory.
Fresh native preflight passes **5/5 checks** and freezes **206 runtime files**,
initially denied and unscoped; **253 frozen source/evidence files**, provider
and executable hashes are verified before credentials or dispatch. Owned exact
loopback scope and read-only policy are verified by the native launcher before
its first target request; evaluator/private state is kept outside the solver.

The exact requested command `python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/run.py`
returned **exit code 0**, `status=plan_only`, `errors=0`, **zero credential
lookup, zero model calls and zero target requests**; its actual stdout is saved
in [plan-only.log](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/plan-only.log).
**9/9 offline driver guards pass**, covering offline credential/network denial,
plan/source/policy drift, missing or displaced cache, consumed attempts, missing
credentials and prompt-time drift. An exclusive 0600 attempt claim precedes a
single dispatch; missing credentials leave it unclaimed. Post-claim exceptions
retain unknown usage under the full conservative cap. `--execute` reads only
inherited `ZENMUX_API_KEY`/`CCO_BENCHMARK_API_KEY` or hidden terminal input;
no `.env` or credential store is read.

Whole-repo and explicit package Ruff (`--no-cache`) and
`python3 scripts/check_repo_layout.py` pass with exit code 0.
[Preparation summary](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/preparation.json),
[complete hash inventory](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/hashes.json),
[sha256sum inventory](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/SHA256SUMS),
[driver guards](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/driver-checks.xml) and
[offline audit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/audit_package.py) are retained.
The audit replays frozen hashes and the default driver without a paid call.

| Frozen artifact | SHA-256 |
| --- | --- |
| [preflight.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/preflight.json) | `dd06fbacaf05e3869e2d632514ad39933463d811a5701308b5369c22f845fb37` |
| [plan.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/plan.json) | `26e40718c78bba27c108f7a13f539b74c99aa8592386ba220729b45c634fdca2` |
| [run.py](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/run.py) | `3b86d08d4b95a1ee356e02e72d5ff818d391fa51d4cb116bd1f7b4d1d28d9ed0` |
| [contract.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/contract.json) | `8a8e2b225e20ef1fd61deac15816bdc6ec8dd182f0d6ddcb01d67e12213bf78b` |
| [runtime-index.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/runtime-index.json) | `d9f2b0b2a4f2a6883b309ddf71192d78930a2d9332a118cbde593cb0bdaa1e6b` |
| [provider.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/provider.json) | `6aec6b33e6698052c75b0c569601284a448fd542a6a69b26a0092b58a2907cff` |
| [measured baseline acceptance.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/baseline/run-z1d2x_9a/acceptance.json) | `01bafe4bd598d47172ff8fbdf06b8a942cb15ecded3f39ab9ce00fd4f4a87771` |
| [measured baseline junit.xml](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/baseline/run-z1d2x_9a/junit.xml) | `31d03004779f5aa0ef4c2107aa7b5753f525de6b80055fba4ac857b78f987c69` |
| [full_agent_runtime_policy.py](/root/hackagent-opencode/scripts/full_agent_runtime_policy.py) | `5ab4f53f8ae709d91ff3d42aa0c770df69a0980236b7f643b2451b5d9fca5868` |
| [full_agent_context.py](/root/hackagent-opencode/scripts/full_agent_context.py) | `4fb76d5cd320825ae49ee1f9bd23df3afa952de2b9808eb2991d8e815df2168a` |
| [full_agent_history.py](/root/hackagent-opencode/scripts/full_agent_history.py) | `d7bb249253305436cd1feafad2add1d272e45caaf0bb4e65b8444af33be0f4d7` |
| [pinned cl100k_base cache](/tmp/data-gym-cache/9b5ad71b2ce5302211f9c61530b329a4922fc6a4) | `223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7` |

Operator command, prepared **but not executed**:

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/run.py --execute
```

**Paid calls remain zero; no live-run output, real attempt claim, refund or
balance query was created. Full paid acceptance remains false.**
StateOps preparation run: `8092bf25-ebae-4bcb-8f64-fc98f6b1ef21`.

Final AST-only `graphify update .` passes with exit code 0: **9,229 nodes / 21,659 edges**, zero LLM calls.
[Graph update log](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-production-20261108/graphify.log) is retained. The offline artifact audit and whitespace checks also pass.
Preparation summary SHA-256: `4d9e6a1040132dcfc42b45180a1c18e17dc3d07b9e335563824475cee738db76`; complete hash inventory SHA-256: `8d4351b0fa5432b5d72b65b502e26f6ec15e2de59edbc8819f671bd82fd68ed8`.


## OpenRouter Crouton Alpha operator configuration — 2026-11-08

At the operator's request, a separate package at
`/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108` selects
**`openrouter/stealth/crouton-alpha` for both planner and worker**, through
`https://openrouter.ai/api/v1`. The public keyless
[OpenRouter model catalog](https://openrouter.ai/api/v1/models), retrieved at
`2026-11-08T09:44:20.266579+00:00`, lists the exact API model ID
**`stealth/crouton-alpha`**, with prompt and completion prices **0 / 0**, and
`tools`, `tool_choice` and `max_tokens` support. A `:free` suffix was not added
to this catalog ID. The catalog snapshot is frozen in
[model-catalog.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/model-catalog.json).
This is catalog evidence only; no model inference or native-model acceptance
was tested. Availability and free quotas remain provider-controlled.

The existing measured baseline and its hashes are reused unchanged, without a
comparison rerun or target traffic. **TOKENS=150000, SECONDS=900, HTTP=300,
SEED=20261104**, one attempt, phase caps, `FINALIZE NOW`, history archives,
retry brake and pinned offline tokenizer remain frozen. The host retains a
32,768-token model context configuration and 4,096-token output cap. The local
prompt bound remains an engineering estimate for this different tokenizer.
The earlier ZenMux package and its source/hash records are preserved; the
following model-specific command selects OpenRouter.

The new driver uses **`OPENROUTER_API_KEY`**, or an explicitly supplied
`CCO_BENCHMARK_API_KEY`; hidden terminal input is available with `--execute`.
It ignores `ZENMUX_API_KEY`, never stores credentials, and performs no
credential lookup in default offline mode. Fresh preflight passes **5/5
checks**, with **206 runtime files** and **254 frozen source/evidence files**.
The actual `run.py` default invocation returns **`plan_only`, errors=0,
exit code 0**, with zero model/target calls. **9/9 offline driver guards pass**,
including correct provider/model selection and refusal to use an old ZenMux key.
Whole-repo/package Ruff (`--no-cache`) and repo layout checks pass.

[Preparation summary](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/preparation.json),
[complete hash inventory](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/hashes.json),
[plan-only stdout](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/plan-only.log),
[driver guards](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/driver-checks.xml),
[offline audit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/audit_package.py) and
[operator instructions](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/README.md) are retained.

| Frozen artifact | SHA-256 |
| --- | --- |
| [preflight.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/preflight.json) | `aec7213ce8a651cda20dd85c7d7b296a9e3ed20c3bbc43994f0bdb59cb7ed7c6` |
| [plan.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/plan.json) | `4898df5d2a5bd35098fa38455d824499028e2aef8581d264c4c50cf1ffbefba5` |
| [run.py](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/run.py) | `ceedbb482d6381c8727a485eab5d61392809983e2a9d931a7bc67a5f169b840e` |
| [provider.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/provider.json) | `f6dda07bfa3a4dadb2f4d40cdccdc6c14ec3136f3fcfb30e1e1decba4fe75ccd` |
| [contract.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/contract.json) | `5bbdcf865db37390868f40cc7659e08d3313da87a5644389fa4a3b21eabbd780` |
| [runtime-index.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/runtime-index.json) | `69b70b0549054bb6aeb25ceb28e73cf29e56171fe73dce3d7d5c06754247c3e3` |
| [model-catalog.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/model-catalog.json) | `b4157fb88ec59e02ec2285bf11647f77e62d57847f89ad7bfd2d5a6c1427ca00` |

Use this prepared command for Crouton Alpha (**not executed during setup**):

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/run.py --execute
```

**Model calls, paid calls and target requests remain zero. No attempt claim or
live output was created. Full model acceptance remains false.** The single
public catalog GET was provider configuration discovery, not a model call.
StateOps configuration run: `9642d57a-aca3-40ce-a49a-7ce22212ecdc`.

AST-only `graphify update .` passes with exit code 0 and zero LLM calls: **9,230 nodes / 21,660 edges**. [Graph update log](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-20261108/graphify.log) is retained.
Final preparation SHA-256: `ac7fe9584a1a224cb2ffd5b7db0d9812be3633d1427fa10467d718b2d17625b2`; hash inventory SHA-256: `a797634c26be920cbb501462b65897eef799508ba325ad477960efc50695b8d7`.


## OpenRouter terminal-only credential entry — 2026-11-08

The operator executed the preceding OpenRouter package as `native-eyaelkkp`.
Its claim is consumed. The single provider request was rejected with HTTP
**401** and missing usage, producing `budget_invalid`; the budget conservatively
settled **8,228 reserved tokens**, not measured model consumption. Its three
HTTP requests were local session setup. The earlier zero-call statements refer
to preparation before that subsequent execution. The original claim, run and
failure evidence are retained without resetting or refunding them.
[Minimal prior-attempt metadata](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/previous-attempt-analysis.json)
contains no credential values.

At the operator's request, a fresh package at
`/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108` always uses hidden terminal input for the API key on `--execute`.
**Environment credentials are ignored**, including `OPENROUTER_API_KEY`,
`CCO_BENCHMARK_API_KEY` and `ZENMUX_API_KEY`. The prompt is
`OpenRouter API key (hidden): `. Non-interactive stdin, empty input, EOF or
Ctrl-C stop before any attempt claim. A `getpass.GetPassWarning` is a hard
error, preventing fallback to echoing input. Keys are never saved or supplied
through command-line arguments. Default `plan_only` never prompts.

Planner and worker remain **`openrouter/stealth/crouton-alpha`**;
**TOKENS=150000, SECONDS=900, HTTP=300, SEED=20261104**, the measured baseline,
pinned tokenizer and repaired runtime policy are reused unchanged. The new
live output directory is separate from the consumed attempt. Fresh preflight
passes **5/5 checks**, default driver returns **`plan_only`, errors=0, exit code
0**, and **17/17 offline driver checks pass**. A real pseudo-terminal check
verifies the prompt appears, echo is disabled, entered synthetic input is
accepted and the key does not appear in terminal output. Other checks cover
ignored environment keys, empty/cancelled input and refused echo fallback;
none dispatch a provider request. Health check **7/7**, StateOps readiness,
whole-repo/package Ruff and repo layout pass.

[Preparation summary](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/preparation.json),
[full hash inventory](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/hashes.json),
[plan-only output](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/plan-only.log),
[17 driver guards](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/driver-checks.xml),
[offline audit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/audit_package.py) and
[terminal instructions](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/README.md) are retained.

| Frozen artifact | SHA-256 |
| --- | --- |
| [preflight.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/preflight.json) | `625d95f9eb195be2114dbf7f23b6ece2717e7a33a27cd7d4a800d9729d024756` |
| [plan.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/plan.json) | `9ab228e36361caa8d4a58ff84f146bda467e0a44491efa6c8c8571cdf07ecdf4` |
| [run.py](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/run.py) | `1a591221db1daccef1031d80dc9a6be49853ab8111a23370cb1f09e3d94067f6` |
| [provider.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/provider.json) | `f6dda07bfa3a4dadb2f4d40cdccdc6c14ec3136f3fcfb30e1e1decba4fe75ccd` |
| [test_driver.py](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/test_driver.py) | `193fdc039975bd9e4536abc703c3ed03560db6192c182246dbe39bf68109039b` |

Run from an interactive terminal (**not executed during this repair**):

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/run.py --execute
```

**New model/provider calls and target requests remain zero. No new claim or live
output was created. Full model acceptance remains false.**
StateOps terminal-input repair run: `2f081f6c-02c3-4a37-8111-b81a0de1ff27`.

AST-only `graphify update .` passes with exit code 0, zero LLM calls, **9,231 nodes / 21,661 edges**. [Graph log](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-terminal-20261108/graphify.log) is retained.
Final preparation SHA-256: `94caa1603519948d8ecdc14d5e3e3efdf28e062e5af7dbfa58e3013de514770a`; hash inventory SHA-256: `10354fae44d30351b4be0077bbd56d6dc5b74c774d7c1448f7954ce5cc12f424`.


## Nullable usage compatibility and safe provider diagnostics — 2026-11-08

The operator subsequently executed the terminal-input package as
`native-plc2afa0`. Its consumed claim remains intact. OpenRouter returned **HTTP
200 / gzip**, followed by `budget_invalid`: one provider call, three local
session-setup requests and **8,231 conservatively charged reservation tokens**.
The operator's Activity text reports **1,303 prompt + 12 completion = 1,315
tokens**, finish reason `stop` and **$0.00**. Zero price does not imply zero
tokens and is not examined by `usage_tokens`. The original raw upstream JSON
was not retained; previous telemetry discarded usage on validation failure, so
its exact rejected field cannot be reconstructed. The Activity report and
stored host measurements have distinct provenance in
[prior-attempt analysis](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-usagefix-20261108/previous-attempt-analysis.json).

The parser now accepts **null optional cached/reasoning subsets**, representing
unknown detail covered by known aggregate counts. Null optional detail objects
are also safe when retaining whitelisted usage. Mandatory prompt/completion
counts still require nonnegative integers and a positive sum; any supplied total
must match. Invalid known subset types/ranges, unknown aggregate usage and
separate prompt/output overruns still stop admission and retain reservations.
Unknown optional subsets are omitted from settled subset metadata rather than
invented as measured zero. Provider response content passed to the native
client is unchanged.

The [offline nullable-field replay](/tmp/cco-work/full-agent-paid-smoke-preparation/provider-usage-repair-20261108/nullable-subset-replay.json)
uses operator-reported aggregate counts with **synthetic nullable subsets**:
the original parser rejects `invalid provider usage subset`; the repaired parser
counts **1,315** once and rejects all invalid aggregate controls. This proves a
compatibility defect, not that the unretained Crouton response had this exact
shape. The [reproducer](/tmp/cco-work/full-agent-paid-smoke-preparation/provider-usage-repair-20261108/replay_usage.py) makes no model or target call.

The broker now retains fixed failure reasons, bounded numeric accounting shape,
field types, decoded response size and encoding in
`private/provider-response-diagnostics.json` and budget events. Counts are
inspected before usage validation. No model text, header, credential, arbitrary
usage extension, invalid string value or exception text is persisted. This
makes any remaining provider mismatch distinguishable from gzip decoding or
an admission overrun while keeping the existing budget gate.

**198 preflight/accounting checks**, **17 terminal-driver guards** and **one
four-phase native chain test** pass, with no failures/errors/skips. Gzip/null
compatibility passes for buffered and native streamed output; malformed counts,
separate overruns, hidden terminal echo and secret-free diagnostics retain their
controls. The native chain uses a local scripted provider with real MCP and
signed closure, not OpenRouter inference. Standalone native test invocation
uses `PYTHONPATH=scripts:tests` for module discovery. Health check **7/7**,
whole-repo/package Ruff and repo layout pass.

The new package at `/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-usagefix-20261108`
retains **`openrouter/stealth/crouton-alpha`**, **TOKENS=150000, SECONDS=900,
HTTP=300, SEED=20261104**, the measured baseline and pinned tokenizer, phase
caps, `FINALIZE NOW`, exact history archives and terminal-only credentials.
Fresh preflight **5/5** and the actual driver **`plan_only`, errors=0, exit code
0** pass. The new driver also links provider diagnostics from `result.json`.
[Preparation summary](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-usagefix-20261108/preparation.json),
[hash inventory](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-usagefix-20261108/hashes.json),
[offline audit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-usagefix-20261108/audit_package.py) and
[terminal instructions](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-usagefix-20261108/README.md) are retained.

| Frozen artifact | SHA-256 |
| --- | --- |
| [preflight.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-usagefix-20261108/preflight.json) | `9091ca4986d7b7a4be109d2b25e789425c54c0f56adc82245da375fb60206261` |
| [plan.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-usagefix-20261108/plan.json) | `2ec75f7c13afbacd8feac06f0ef02d33db7656cdb4e5c9792bdd78fe2a3f9623` |
| [run.py](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-usagefix-20261108/run.py) | `9fd8acfd53b5df54e78576ff064ba488a0ecaed03f793b5cbdbf589168c9b00b` |
| [full_agent_budget.py](/root/hackagent-opencode/scripts/full_agent_budget.py) | `20f5e91429b6dae18304384a5af107f4b089807f28f02d37082f0d2fdc865374` |
| [full_agent_broker.py](/root/hackagent-opencode/scripts/full_agent_broker.py) | `6169ac7f733814063650d9e2033223b131d0a9819ad08493fc2672997876ced6` |

Prepared operator command (**not executed during repair**):

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-usagefix-20261108/run.py --execute
```

**New OpenRouter/model calls remain zero; no new claim or live output was
created, and no consumed reservation was refunded. Full model acceptance is
still false.** Provider-specific success must be checked on a future operator
attempt; any further mismatch is retained in the safe diagnostics.
StateOps usage repair run: `f249c1d6-8bdd-4534-9e06-f5d493e8b1e3`.

AST-only `graphify update .` passes with exit code 0 and zero LLM calls: **9,245 nodes / 21,690 edges**. [Graph log](/tmp/cco-work/full-agent-paid-smoke-preparation/provider-usage-repair-20261108/graphify.log) is retained.
Final preparation SHA-256: `fd817a15f6bf9f7ffbc3b5880832846dc08d0e352cecbde08b2dd7664fbe7545`; hash inventory SHA-256: `199f9744aa78c2b36f42f2fa06e39c24fac863c21f3bba862d00059d0acd3a02`.


## Enum closure slots protected at tool execution — 2026-11-08

The operator subsequently executed the usage-compatible package as
`native-oqrj6qqd`. **All 19 provider token measurements are valid**: **37,401
charged / 112,599 remaining tokens**, **18 local HTTP requests**, no pending
reservation and no budget-invalid flag. Recon completed. Enum stopped at
`phase_call_budget_exhausted` after **9 provider calls / 20 native tools**.
Four finalization responses wrote the surface artifact three times and then a
valid terminal `partial` enum summary. Its host handoff receipt was absent;
access/report were not admitted. The consumed run is preserved and its usage
is not refunded. [Prior-attempt analysis](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-enumfinish-20261108/previous-attempt-analysis.json)
records the separate accounting and closure outcomes.

Finalization was previously checked between provider responses. At **13/20**
enum tools the next response executed three probes, reaching **16/20** before
the next check, which reduced the intended **six** closing-tool slots to **four**.
All four closing provider turns were then spent on native writes. The next
handoff could not be requested despite **20,967 enum tokens** still available.

`RuntimePolicy.check_tool` now switches to finalization **before each native
execution** at the exact reserve boundary, including calls batched in one model
response. Additional probes are refused while closing tools retain their six
slots. Enum's provider finalization allowance is **6 turns**, matching its
reserved six native closing operations within the unchanged **16-provider-call
and 20-tool ceilings**. Global **150,000**, enum **45,000** and all other phase
token ceilings stay unchanged; unused earlier phase funds are not borrowed.
Provider allowance telemetry and runtime snapshots now expose finalization
calls used and remaining native tool calls. `FINALIZE NOW`, signed handoff
requirements, the retry brake, history archives and scope gates remain active.

The [recorded counter replay](/tmp/cco-work/full-agent-paid-smoke-preparation/enum-finalization-repair-20261108/recorded-finalization-replay.json)
uses the saved enum counters and valid charges. The old policy admits all
three tail probes and has four closing-tool slots; the new policy admits one,
refuses two and retains six. After the same four writes, the old policy refuses
another model turn, while the new policy admits the handoff request with two
native slots left. Both retain **112,599 global / 20,967 enum tokens** and the
same ceilings. This is **counterfactual admission**, not new model behavior,
target traffic, a fabricated receipt or a completed handoff.
[Reproducer](/tmp/cco-work/full-agent-paid-smoke-preparation/enum-finalization-repair-20261108/replay_finalization.py): zero model/target calls.

**222 runtime/accounting unit checks**, **17 terminal-driver guards** and **one
native four-phase chain** pass, with no errors/failures/skips. The native chain
uses only local scripted provider decisions with real MCP/signed closure.
Fresh native preflight **5/5**, actual operator **`plan_only`, errors=0, exit code
0**, health check **7/7**, whole-repo/package Ruff and repo layout pass.

The replacement package at `/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-enumfinish-20261108`
keeps **`openrouter/stealth/crouton-alpha`**, **TOKENS=150000, SECONDS=900,
HTTP=300, SEED=20261104**, the existing measured baseline, pinned tokenizer,
hidden terminal-only API key and a single attempt. Its
[preparation summary](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-enumfinish-20261108/preparation.json),
[hash inventory](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-enumfinish-20261108/hashes.json),
[offline audit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-enumfinish-20261108/audit_package.py) and
[operator instructions](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-enumfinish-20261108/README.md) are retained.

| Frozen artifact | SHA-256 |
| --- | --- |
| [preflight.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-enumfinish-20261108/preflight.json) | `58b773c52ffcb3ffe4d456d235b95069622f3d5cbf31efd47a188e41d97f6538` |
| [plan.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-enumfinish-20261108/plan.json) | `264e9ed74c7a09581fb729ebc683aa8d929dd12843f157a9ef78d6c1cf908866` |
| [run.py](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-enumfinish-20261108/run.py) | `7ce483216daf442a574dbe99f1df8ae92e0e42b89906428f856d48ec2d680d4d` |
| [full_agent_runtime_policy.py](/root/hackagent-opencode/scripts/full_agent_runtime_policy.py) | `4a992f4fce132b5f9272accc03bc74aa1f85e3d0f305229511dbefc0abe0faad` |

Prepared operator command (**not executed during repair**):

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-enumfinish-20261108/run.py --execute
```

**New OpenRouter calls, claims and live output remain zero. Full model acceptance
is still false.** A subsequent model must execute the real handoff and signed
validation/closure; the replay does not grant those results.
StateOps finalization repair run: `024f2023-f35d-452b-8a24-b727d7ee61f3`.

AST-only `graphify update .` passes with exit code 0 and zero LLM calls: **9,248 nodes / 21,693 edges**. [Graph log](/tmp/cco-work/full-agent-paid-smoke-preparation/enum-finalization-repair-20261108/graphify.log) is retained.
Final preparation SHA-256: `314abcfe929db5ce28a36418c9aaf10ff9fc3af2395292844723737a9dd8ebe5`; hash inventory SHA-256: `625879af8ee3ceb0e565ad45717a36a4d7b70c11898f5fa5bff8f97d9f5c5024`.


## OpenRouter Crouton reasoning metadata adapter — 2026-11-08

The agent executed `native-lsxcrchv` using hidden terminal input. HTTP 200/gzip
reported prompt=1330, completion=10, total=1340, reasoning=33. Strict subset
validation stopped the first provider call and retained its 8,267-token
reservation; three setup requests had reached the owned loopback fixture.
The consumed attempt remains unchanged.

For exactly `https://openrouter.ai/api/v1` and `stealth/crouton-alpha`, otherwise
valid reasoning-above-completion metadata is now conservatively charged as
completion + reasoning. The recorded response replays as completion=43,
total=1373. Core counts, original total consistency, cache bounds, canonical
prompt/output bounds and the reservation ceiling remain enforced. The raw
response is preserved; safe diagnostics distinguish reported counts from
accounted usage with `conservative_completion_plus_reasoning`. This is an
accounting upper estimate for inconsistent metadata, not proven provider
semantics. Valid reasoning subsets remain counted once.

247 accounting/runtime tests, 17 terminal-driver tests and the native four-phase
chain passed with no failures, errors or skips. Health 7/7, whole-repo Ruff,
package Ruff with `--no-cache`, repo layout and AST-only `graphify update .`
passed (9255 nodes / 21717 edges; zero LLM calls). Ruff cache files accidentally
created during package checking were identified by the runtime inventory gate
and removed before successful rechecking; no live attempt was claimed then.

The fresh reasoningfix package keeps TOKENS=150000, SECONDS=900, HTTP=300,
SEED=20261104, the unchanged measured production baseline, pinned tokenizer,
phase ceilings and terminal-only credentials. OpenRouter's public model catalog
was rechecked: prompt and completion price both zero. Actual plan-only returned
errors=0 and exit code 0; its offline audit verified 269 hash records without
provider or target calls. Preparation claims no model acceptance.

| Frozen artifact | SHA-256 |
| --- | --- |
| [preflight.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-reasoningfix-20261108/preflight.json) | `32aec13533c8d892f4c6071ef4f7ee33dd69002fafa0b7b7f019c2d1f25e68ab` |
| [plan.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-reasoningfix-20261108/plan.json) | `dd1eaced82a6f96e1823461164536c2055c9d8821b4f4c701cbe03c629c7c1fb` |
| [run.py](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-reasoningfix-20261108/run.py) | `9a77da5fb5d8cbc5d431b4d186aaff800aa7c73fecba4fcdfaafa2642372343a` |
| [preparation.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-reasoningfix-20261108/preparation.json) | `a106d53d41111fd3009652d0ecb1ade5a360fa827d6bfb7cffc47f6a29bdc066` |
| [hashes.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-reasoningfix-20261108/hashes.json) | `800eac2c1a0d6d22897ffc1aecb188bdb6334ebc33bafa79d6c1e4578b79c2f4` |

[Recorded replay](/tmp/cco-work/full-agent-paid-smoke-preparation/openrouter-reasoning-repair-20261108/recorded-usage-replay.json).
StateOps run: `ad46667a-2cf7-4c58-bb16-61da19a6caea`.

## Authcoverage artifact okuma ve kapanış düzeltmesi — 2026-11-08

Kullanıcının çalıştırdığı `python-ntiqodi4`, `access-3` aşamasında
`phase_token_budget_exhausted` ile durdu. 13 sağlayıcı çağrısı, toplam 24.444
token ve 7 loopback HTTP isteği ölçüldü. Recon 2.396, enum 1.410, access
20.638 token harcadı; bütün ölçümler geçerli ve rezervler kapalıydı.
Access hiçbir gerçek doğrulama aracını çalıştırmadan 10 artifact okuması yaptı.

Kök neden: 3000 karakterlik `read_artifact` sonucuna referans metaverisi
eklendiğinde genel 3000 baytlık `view` sınırı aşılıyor ve `text` alanı model
bağlamından çıkarılıyordu. Model aynı önceki özeti 9 kez, discovery kaydını
1 kez istedi; okunan metin hiçbir çağrıda görünmedi. Son admission sırasında
access'te 16.862 token kalmasına rağmen 10.215 token kapanış rezervinden sonra
6.647 token kullanılabiliyordu. 8.315 token prompt tahmini bunun içine sığmadı.
Bu, toplam 150.000 token sınırına ulaşılması değildi.
[Değiştirilmemiş kayıtların hashleri ve tanı](/tmp/cco-work/full-agent-python-diagnosis/python-ntiqodi4/live-audit.json).

`read_artifact` artık önceden sınırlandırılmış metni tekrar küçültmeden sunuyor;
`next_offset` ve `eof` karakter ofsetleriyle sayfalamayı açıklıyor. Metaveri
özgün artifact referansını koruyor. Aynı okuma sonucu model bağlamında tek
kez tutuluyor; bütün çağrılar host geçmişinde ve araç/token hesabında kalıyor.
Python politikası token/çağrı/araç sınırına yaklaşınca özet şemasına geçiyor.
Kapanış rezervi küçülen şemaya göre yeniden hesaplanıyor. Henüz doğrulama
çalışmamış access aşaması için bir araç hakkı ve gerçek sonucu özetleyecek
ek model turu ayrılıyor; bunlar mevcut sınırlar içinden geliyor. Scope,
oturum referansı, handoff, HTTP ölçümü, imza ve tek onarım sınırı korunuyor.

İlk zorlayıcı yerel entegrasyon, doğrulama sonrası ek özet turunun da
rezerv gerektirdiğini gösterdi. Başarısız test/run kanıtları korundu;
access rezerv hesabı düzeltildi ve nihai senaryolar yeniden geçti.

Nihai doğrulama: **344 birim/regresyon + 4 gerçek dört aşamalı entegrasyon +
1 bağımsız holdout = 349 geçen test**, hata veya skip yok. Tüm depo Ruff,
repo düzeni ve AST-only `graphify update .` geçti; 9439 düğüm / 22207 kenar.

| Yerel senaryo | Model çağrısı | Test token | HTTP | Kapanış |
| --- | ---: | ---: | ---: | --- |
| Doğrudan validator | 10 | 2000 | 11 | İmzalı, doğrulandı |
| Erken özet ve host validator | 8 | 1600 | 58 | İmzalı, doğrulandı |
| Tam boy artifact okuma ve validator | 9 | 1800 | 58 | İmzalı, doğrulandı |
| Tekrarlayan okuma ve bütçeli kapanış | 11 | 10700 | 58 | İmzalı, doğrulandı |
| Bağımsız API holdout | 8 | 1600 | 46 | İmzalı, doğrulandı |

[Birim/regresyon JUnit](/tmp/cco-work/authcoverage-readfix-final-unit.xml),
[entegrasyon JUnit](/tmp/cco-work/authcoverage-readfix-final-integration.xml),
[holdout JUnit](/tmp/cco-work/authcoverage-readfix-holdout.xml),
[graf kaydı](/tmp/cco-work/authcoverage-readfix-graphify.log).
Holdout recall 4/8, negatif kapsam 4/8, yanlış pozitif 0/4; aggregate
`incomplete`. Bütün run'larda `acceptance_passed=false` korunuyor. Sonraki
dilim bağımsız aile çeşitliliği ve eksik pozitif/negatif kapsamın tamamlanması:
en az 3 aile, 24 pozitif/24 negatif, toplam recall ≥0,7, aile başına ≥0,5,
negatif kapsam ≥0,9. Bu düzeltmenin uzak sağlayıcıdaki etkisi henüz ölçülmedi.

Yeni paket:
[plan.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-authcoverage-readfix-20261108-kkdc0xv1/plan.json).
Aynı `openrouter/stealth/crouton-alpha`, `seed=20261104`, 150.000 token /
900 saniye / 300 HTTP / 1 launch; paket ve 12 host kaynak hash'i sabit.
Yalnızca `--plan-only` çalıştırıldı: `prerequisites_ready`, 0 model çağrısı,
0 hedef isteği. Önceki tüketilmiş paket ve işareti değiştirilmedi.

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-authcoverage-readfix-20261108-kkdc0xv1/run.py --execute
```

Bu komut kullanıcı çalıştırması içindir; ajan yeni bir uzak sağlayıcı
denemesi veya ücretli retry başlatmadı.

## Authcoverage ardışık artifact sayfaları ve bütçeye sığdırma — 2026-11-08

Kullanıcının sonraki `python-q93a46ih` çalıştırması yine access admission
kontrolünde durdu: 9 model çağrısı, 19.813 toplam token, 26 loopback HTTP.
Access yalnızca 2 model çağrısı / 4.583 token harcamıştı. Önceki okuma
düzeltmesi çalıştı: `text` görünürdü ve model aynı özeti 0 ile 3000
ofsetlerinden okudu. Enum bu kez 40 sayfa sınırıyla gerçek oturumlu crawl
çalıştırmıştı. Ancak iki ayrı sayfanın tam metni model bağlamında birikti.
Kapanışta 32.917 token kalmasına rağmen 23.652 token rezerv sonrası
9.265 token kullanılabiliyordu; 9.937 token prompt tahmini sığmadı.
Doğrulama araçlarına geçilemedi. Önceki testler tekrarlanan aynı aralığı
kapsıyordu; farklı sayfaların birlikte büyüttüğü payload'u kapsamıyordu.
[Özgün hashler ve admission tanısı](/tmp/cco-work/full-agent-python-diagnosis/python-q93a46ih/live-audit.json).

Yeni davranış: son okunan sayfanın metni korunurken önceki sayfalar kendi
hash'li artifact referansı ve `offset/next_offset/eof` bilgileriyle taşınıyor.
Host kayıtları tam metni tutmaya devam ediyor. Python broker, allowance
mesajı dahil gönderilecek gerçek payload'u ortak tokenizer ve minimum
1024 çıktı token kontrolüyle sağlayıcıya göndermeden önce değerlendiriyor.
Gerekirse önce eski okuma metinleri, sonra eski sonuçlar referanslara
indiriliyor. Yalnızca özet araçlarının açık olduğu kapanışta daha küçük
bir TaskSpec/sonuç/onarım bağlamı kullanılabiliyor. Tam kaynak bağlam
hash'li `provider-context` artifact'inde korunuyor; sonuç veya kapsam
üretilmiyor. Bu işlemler sağlayıcı çağrısı ya da araç hakkı tüketmiyor.
Scope, oturum, handoff, imza, token/HTTP/çağrı sınırları korunuyor.

Başarısız run'ın gerçek artifact'lerinden yeniden kurulan çevrimdışı bağlam
önce aynı admission hatasını üretti: prompt tahmini 9.946 token, çıktı hakkı 0.
Yeni projeksiyonda prompt 7.865 token'a indi ve 4096 çıktı token sığdı.
Son sayfanın 3000 karakteri görünür kaldı; 1 sahte sağlayıcı çağrısı, **0
gerçek sağlayıcı çağrısı ve 0 hedef isteği**. Kaynak run ve çağıran bağlam
değiştirilmedi. Yeniden kurulan payload'un dosya yolları özgün çağrıdan
farklı olduğundan bu sayılar özgün admission kaydının birebir kopyası değildir.
[Yeniden üretim betiği](/tmp/cco-work/full-agent-python-diagnosis/python-q93a46ih/replay-context-admission.py),
[ölçülen çevrimdışı sonuç](/tmp/cco-work/full-agent-python-diagnosis/python-q93a46ih/offline-replay.json).

**348 birim/regresyon + 5 gerçek dört aşamalı entegrasyon + 1 bağımsız
holdout = 354 test geçti**, hata/skip yok. 40 sayfalık crawl ve ardışık
`0,3000,6000` okumaları kullanan yeni entegrasyon, 11 yerel model çağrısı /
10.700 test token / 74 HTTP ile gerçek validator kanıtı ve doğrulanmış imzalı
kapanış üretti. Her access isteği, kapanış rezervi dahil aşama sınırına sığdı.
Diğer dört entegrasyon ve bağımsız holdout da `python_finished_verified`.
Bütün run'larda `acceptance_passed=false`; tam bağımsız kabul tamamlanmadı.
[Birim/regresyon JUnit](/tmp/cco-work/authcoverage-pagefit-final-unit2.xml),
[entegrasyon JUnit](/tmp/cco-work/authcoverage-pagefit-integration.xml),
[holdout JUnit](/tmp/cco-work/authcoverage-pagefit-holdout.xml).
Tüm depo ve hazırlık/tanı yardımcıları Ruff, repo düzeni ve AST-only graf
kontrolünü geçti: 9447 düğüm / 22236 kenar.
[Graf güncelleme kaydı](/tmp/cco-work/authcoverage-pagefit-graphify.log).

Yeni tek kullanımlık
[paket](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-authcoverage-pagefit-20261108-m80nhtix/plan.json):
aynı `openrouter/stealth/crouton-alpha`, `seed=20261104`, 150.000 token /
900 saniye / 300 HTTP / 1 launch. Yalnızca `--plan-only` doğrulandı:
`prerequisites_ready`, 0 model çağrısı, 0 hedef isteği. Önceki tüketilmiş
paketlerin işaretleri ve run kanıtları korunuyor; ajan uzak sağlayıcı
denemesi başlatmadı. Uzak sağlayıcıdaki sonuç henüz ölçülmedi.

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-authcoverage-pagefit-20261108-m80nhtix/run.py --execute
```

## Authcoverage rapor checkpoint yetkisi ve ayrılmış araç hakkı — 2026-11-08

Kullanıcının `python-n704tbx4` çalıştırmasında dört aşamanın geçerli özetleri
yazıldı, fakat imzalı kapanış tamamlanmadı: `python_failed`, `workflow_failed`,
`report-4`; 13 model çağrısı / 27.193 token / 74 loopback HTTP. Access gerçek
hunter/validator çalıştırdı; dört validator artifact'inde 2 CONFIRMED ve
2 UNCONFIRMED sonuç var. Bunlar yerel lab kanıtlarıdır; tam kabul değildir.
Rapor özeti `partial`, `unresolved-work=not_tested` olarak korundu.

Kök neden: rapor üçüncü model turunda token rezervi nedeniyle özet moduna
geçti. `seal`, hipotezleri mevcut doğrulanmış artifact'lerle terminal duruma
getirdikten sonra `kali-tools_ledger_checkpoint` çağrısını modelin sınırlı
araç yetkisi altında yaptı. Enum handoff'undaki `host_finalizing` mekanizması
rapor checkpoint'ine uygulanmamıştı. Çağrı politika tarafından yürütülmeden
reddedildi; `closure.json` oluşmadı. Bütçe aşılmadı, ölçümler geçerliydi.
[Özgün run hashleri ve tanı](/tmp/cco-work/full-agent-python-diagnosis/python-n704tbx4/live-audit.json).

Raporun mevcut **6 araç çağrısı** içinden bir hak host checkpoint'ine
ayrılıyor; model en çok kalan beş hakkı kullanıyor. Geçerli rapor özetinden
sonra checkpoint, yalnızca bu çağrı süresince host finalization bağlamında
çalıştırılıyor. Bütün katalog, TaskSpec, workspace, scope, HTTP bütçesi,
signature ve closure kontrolleri uygulanmaya devam ediyor. `finally`,
geçici yetkiyi ve rezervi başarı/ret/hata/bütçe kesintisinde kaldırıyor.
`seal`, araç bütçesi bitmişse ledger değişikliğinden önce duruyor. Başarısız
checkpoint için `closure_checkpoint_denied` veya artifact referanslı
`closure_checkpoint_failed` kodları üretiliyor; başarılı sonuçta `sealed=true`
ve tamsayı `check_exit=0` aranıyor. Tam imza/kapanış doğrulaması sonrasında
da uygulanıyor. Model checkpoint aracını doğrudan görmüyor.

Özgün rapor politika durumu çevrimdışı yeniden kuruldu: model bağlamında
aynı checkpoint reddi üretildi; geçici host bağlamında sayaç 2'den 3'e
çıkarak 6 sınırının içinde kabul edildi. Bu yalnızca politika yeniden
üretimidir; gerçek checkpoint, sağlayıcı veya hedef isteği çalıştırılmadı.
[Politika yeniden üretim kaydı](/tmp/cco-work/full-agent-python-diagnosis/python-n704tbx4/policy-replay.json).

**354 birim/regresyon + 7 gerçek dört aşamalı entegrasyon + 1 bağımsız
holdout = 362 test geçti**, hata/skip yok. Son entegrasyonlar eski beş
senaryoya ek olarak raporun token nedeniyle özet moduna geçmesini ve
modelin beş araç hakkını tek yanıtta tüketmesini kapsıyor. Her ikisi de
gerçek MCP alt süreçleriyle checkpoint ve doğrulanmış imzalı kapanış üretti:

| Rapor senaryosu | Model çağrısı | Test token | HTTP | Rapor araç çağrısı |
| --- | ---: | ---: | ---: | ---: |
| Token rezervi nedeniyle özet modu | 9 | 9600 | 58 | 3, checkpoint dahil |
| Beş model hakkından sonra host checkpoint | 8 | 1600 | 58 | 6, toplam sınır içinde |

Tüm entegrasyonlar ve holdout `python_finished_verified`; özet onarımı 0.
Bütün run'larda `acceptance_passed=false` korunuyor. Bağımsız kapsam ve aile
çeşitliliği için tam kabul hâlâ tamamlanmadı.
[Birim/regresyon JUnit](/tmp/cco-work/authcoverage-sealfix-final-unit.xml),
[entegrasyon JUnit](/tmp/cco-work/authcoverage-sealfix-final-integration.xml),
[holdout JUnit](/tmp/cco-work/authcoverage-sealfix-holdout.xml).
Tüm repo ve hazırlık yardımcısı Ruff, repo düzeni ve AST-only graf güncellemesi
geçti: 9455 düğüm / 22255 kenar.
[Graf kaydı](/tmp/cco-work/authcoverage-sealfix-graphify.log).

Yeni tek kullanımlık
[sealfix paketi](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-authcoverage-sealfix-20261108-04nec2n1/plan.json):
aynı `openrouter/stealth/crouton-alpha`, `seed=20261104`, 150.000 token /
900 saniye / 300 HTTP / 1 launch. Yalnızca `--plan-only` doğrulandı:
`prerequisites_ready`, 0 model çağrısı, 0 hedef isteği. Özgün run ve önceki
tüketilmiş paket işaretleri değişmedi. Ajan uzak sağlayıcı denemesi veya
retry başlatmadı; bu düzeltmenin uzak sağlayıcıdaki sonucu henüz ölçülmedi.

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-authcoverage-sealfix-20261108-04nec2n1/run.py --execute
```

## Oturumlu keşif ve kapsam dilimi (authcoverage) — 2026-11-08

`/tmp/cco-work/slice-authcoverage-plan.md` içindeki 1–9 adımları bu ekin
konusudur. Önceki Path B uygulaması, tüketilmiş paketler ve çalışma kanıtları
korundu. Alt ajan kullanılmadı; çalışma verileri `/tmp/cco-work` altında.

`python-o508grir` kayıtları üç ayrı kopukluğu gösterdi: crawl çağrısına kayıtlı
oturum bağlanmıyordu; gerçek HTML bağlantıları yapılandırılmış envantere
alınmadığı için access handoff işleri boş kalıyordu; access yalnızca oturum
kontrolü/kanıt okumasıyla kapanabiliyordu. Report içindeki coverage çağrısı da
`target` eksik olduğu için hata döndürüyordu. Yeni testler ayrıca crawl'ın
hostname anahtarının portu kaybettiğini, bu nedenle kapsam raporunun doğru
hedef verildiğinde bile envanteri bulamadığını gösterdi.

Crawl artık tam kayıt hedefi ve kimlik referansını alıyor. Gizli header/cookie
araç sürecinde, yakın zamanda doğrulanmış kasadan çözülüyor. Her istekte aynı
oturum sürümü, origin, kapsam ve mevcut politika/bütçe denetleniyor. Yanlış
hedef/kimlik, ham kimlik bilgisiyle karıştırma ve süresi dolmuş oturum trafik
öncesinde reddediliyor; oturum değişikliği sonraki isteği durduruyor. Python
şeması raw header/cookie alanlarını kaldırıyor ve broker kayıtlı üye kimliğini
varsayılan olarak bağlıyor. Crawl envanter anahtarı artık portu koruyor.

Host, gerçek HTML/crawl çıktısından rota ve parametreleri kaynak artifact/SHA
ile derliyor; bağlantı keşfi ve gerçek HTTP gözlemini ayrı alanlarda tutuyor.
Doğrulanmış recon gözlemleri enum'a taşınıyor. Access bağlamına yapılandırılmış
keşif ve güvenli oturum referansları veriliyor; handoff, kapsam, imza ve çağrı
sınırları korunuyor. Erken access özeti, henüz validator çalışmadıysa mevcut
izinlerle bütçeli `hunter_run_web_loop(live=true)` yürütmesini tetikliyor.
İlk regresyon keşif/fuzz'ın hız penceresini validator öncesinde tükettiğini
gösterdi: otomatik adım artık tek sentetik üye çifti ve dört karşılaştırmayla
sınırlı, geniş fuzz kapalı. Hız sınırları ve toplam bütçe yükseltilmedi.

Hem CONFIRMED hem UNCONFIRMED sonuçlar yalnız gerçek araçların verdiği ID'ler
ve geçerli validator imzalarından alınarak attempt zincirine/validator
artifact'larına yazılıyor. Modelin `done` veya bulgu beyanı kanıt oluşturmuyor.
Test edilmeyen hipotezlerin host gerekçeleri ve gerçek enum oturum kontrolü
kanıtları kapanışa taşınıyor. Coverage şemasında `target` zorunlu ve TaskSpec
hedefine bağlı; broker yalnız eksik hedefi tamamlıyor, farklı hedefi reddediyor.

Bağımsız denetçi Python yürütücüsünün host çıktılarıyla uyumlu hale getirildi.
TaskSpec, dört özet, handoff, oturum kontrolü, canlı döngü sonucu ve validator
dosyaları imzalı Python snapshot'ından doğrulanıyor; gerçek executor run ID,
imzalı coverage event, HTTP wire ve mevcut kapanış kapıları korunuyor.
`acceptance_passed` elle değiştirilmedi. Host denetimi trafik üretmez:

```bash
python3 scripts/full_agent_preflight.py --baseline <baseline> --provider-config <config> --token-budget 150000 --solver-mode python_loop --holdout-family readonly-api-access-control --holdout-seed <seed> --output-dir /tmp/cco-work/<fresh-preflight>
python3 scripts/full_agent_holdout.py audit --manifest /tmp/cco-work/<run>/launch.json
python3 scripts/full_agent_holdout.py aggregate --manifest <family-1>/launch.json --manifest <family-2>/launch.json --manifest <family-3>/launch.json
```

İlk komut preflight hazırlığıdır; bu dilimde canlı sağlayıcı çalıştırılmadı.
Aggregate her manifesti yeniden denetler; aile yeniden adlandırma/tekrarı veya
seed değişimi yeni bağımsız aile kredisi sağlamaz. Kabul sözleşmesi en az üç
aile, 24 pozitif/24 negatif, toplam recall ≥0.7, aile recall ≥0.5 ve negatif
kapsam ≥0.9 koşullarını korur.

| Yerel kontrol | Sonuç |
| --- | --- |
| Konsolide çevrimdışı regresyon | 516 geçti; 3 integration testi ayrı çalıştırılıyor |
| Oturumlu crawl + doğrudan validator + imzalı kapanış/tamper | Geçti; 10 yerel model çağrısı, 2000 test token, 11 HTTP, 1 validator artifact |
| Erken özette host doğrulaması + imzalı kapanış/tamper | Geçti; 8 yerel model çağrısı, 1600 test token, 58 HTTP, 4 validator artifact |
| Python bağımsız API holdout ve snapshot mutasyonları | Geçti; 8 yerel model çağrısı, 1600 test token, 46 HTTP, 8 validator artifact |
| Holdout modülüyle birlikte kabul regresyonları | 10 geçti |
| Ayrı native bağlam regresyonu | 1 geçti; ilk eşzamanlı çalıştırmanın startup timeout kanıtı korundu |
| `ruff check` | Geçti |
| `python3 scripts/check_repo_layout.py` | Geçti |
| `kalibounty-healthcheck` | 7/7 geçti |

Yerel holdout yalnız bir üye çiftini test etti: recall **4/8**, negatif kapsam
**4/8**, yanlış pozitif **0/4**; imzalı HTTP kanıtı ile ölçüldü. Diğer hesaplar
NOT TESTED kaldı ve aggregate **incomplete / full_acceptance=false**.
Ücretli model genellemesi ve tam bağımsız holdout kabulü henüz ölçülmedi.
Özet onarımı bu üç yerel Python çalıştırmasında 0. Eski live-audit içindeki
29 kanıt hash'i değişmedi; eski `acceptance_passed=false` sonucu korunuyor.

Kanıtlar: [çevrimdışı JUnit](/tmp/cco-work/authcoverage-final-unit.xml),
[erken kapanış JUnit](/tmp/cco-work/authcoverage-early4.xml),
[holdout JUnit](/tmp/cco-work/authcoverage-holdout2.xml),
[native bağlam JUnit](/tmp/cco-work/authcoverage-native-context2.xml),
[holdout metrikleri](/tmp/cco-work/full-agent-python-holdout/authcoverage-g9u5nqhz/runs/python-wp94e752/private/evaluator/metrics.json).

Son kaynaklarla tekrar edilen iki Python entegrasyonu da geçti:
[JUnit](/tmp/cco-work/authcoverage-final-integration.xml). Toplam **516
çevrimdışı + 4 ayrı entegrasyon kontrolü** başarılı; holdout modülünün tekrar
çalıştırılan çevrimdışı testleri bu toplama ikinci kez eklenmedi.
`graphify update .` AST-only, LLM/API çağrısı olmadan başarılı:
9435 node, 22196 edge, 439 community.
[Graf güncelleme kaydı](/tmp/cco-work/authcoverage-graphify.log).

Adım 9 için yeni, benzersiz ve tek kullanımlık
[authcoverage paketi](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-authcoverage-20261108-8yi51hzv/plan.json)
hazırlandı. Aynı `openrouter/stealth/crouton-alpha`, `seed=20261104`,
**150000 token / 900 saniye / 300 HTTP / 1 launch** korunuyor. Gerçek önceki
baseline yeniden doğrulandı; sağlayıcı/model kataloğuna yeni istek yapılmadı.
Paket artifact'ları ve 12 host kaynak dosyası hash ile sabitlendi. Yeni driver
ve hazırlama yardımcısı Ruff kontrolünden geçti.

Yalnız aşağıdaki doğrulama çalıştırıldı ve exit 0 döndü:

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-authcoverage-20261108-8yi51hzv/run.py --plan-only
```

[Plan-only sonucu](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-authcoverage-20261108-8yi51hzv/plan-only-result.json):
`status=plan_only`, `preflight_status=prerequisites_ready`, `llm_calls=0`,
`target_requests=0`, `acceptance_passed=false`. Yeni execute-once işareti yok;
eski tüketilmiş paketin işareti korunuyor. **Canlı sağlayıcı denemesi
başlatılmadı.** İleride paketin tek kullanımlık çalıştırma komutu:

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-authcoverage-20261108-8yi51hzv/run.py --execute
```

Bu execute komutu uygulanmadı. Konsolide kaynak/kanıt hash'leri, başarılı
testler, son yerel çalıştırma ölçümleri ve kalan eksikler
[doğrulama belgesinde](/tmp/cco-work/authcoverage-verification.json). İşlemler
mevcut scan_history listesi korunarak eklendi ve StateOps event log'una işlendi.

### Python enum evidence inheritance fix — 2026-11-08

The operator's `python-xyh1nmli` run stopped at `enum-2` with
`summary_repair_exhausted`: 6 provider calls, 7,694 charged tokens and 6
owned-loopback HTTP requests. Recon had an actual HTTP 200 observation of the
root. Enum's anonymous crawl returned `crawl stopped: http_401`. The host
compiled an empty enum surface from that phase alone, discarding recon's
observation. Both archived model drafts were partial and otherwise valid;
the additional repair could not change the host-generated surface.

Enum now retains actual GET/HEAD observations from declared, validated
dependency phases for the same target origin. Archive registration, path
confinement, byte count and SHA-256 are checked before inheritance. Evidence
records its source phase; current `route_probes` and `tested_parameters`
continue to describe only current execution. Partial/blocked step states
remain unchanged, and no ownership or finding is inferred. Invalid host
inventory stops with `enum_surface_unavailable` or `enum_surface_incomplete`,
preserving draft/error references without a futile model repair. The existing
repair for model-managed metadata, session freshness, budgets and signed
handoff/closure gates remain enforced.

Read-only recompilation of both original drafts now passes the unchanged
summary validator. Twelve original evidence/package hashes remain unchanged,
including the consumed package marker. The original failure and charges are
preserved. [Diagnosis](/tmp/cco-work/full-agent-python-diagnosis/python-xyh1nmli/diagnosis.json)
and [replay](/tmp/cco-work/full-agent-python-diagnosis/python-xyh1nmli/readonly-replay.json).

Verification: **507 tests passed** (67 Python workflow tests, 439 regression
tests and one separately executed native context test). The real subprocess
integration combines the failed anonymous crawl, inherited recon observation,
370-second simulated session aging, host refresh and exact session binding
recovery. Its four-phase workflow reaches `python_finished_verified` with
signed closure and tamper rejection: 9 scripted local completions, 1,800 test
tokens, 11 loopback HTTP requests and zero summary repairs. Ruff and repository
layout pass; the AST-only graph update is recorded in the consolidated
[verification](/tmp/cco-work/full-agent-python-diagnosis/python-xyh1nmli/enumfix-verification.json).

The fresh single-use
[package](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-enumfix-20261108/plan.json)
retains the same selected model, baseline, seed 20261104 and budgets
(150,000 tokens / 900 seconds / 300 HTTP). Plan-only returns
`prerequisites_ready`, zero provider calls and zero target requests. Package
validation checks 211 frozen files and 21 current host code hashes. No live
retry was started, and live/independent holdout acceptance remains unproven.

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-enumfix-20261108/run.py --execute
```

### Operator-run Python enumfix result — 2026-11-08

The operator's `python-o508grir` run reaches `python_finished_verified`:
all four phases have valid summaries and signed closure verifies. It uses
11 actual provider calls, 18,777 charged tokens and 11 owned-loopback HTTP
requests in 81.40 seconds, with zero summary repairs. Read-only rechecking
verifies both Ed25519 closure/attempt-ledger signatures and 22 signed artifact
references; usage measurements are valid and no reservations remain.

This proves live phase progression and closure integrity. Security coverage
remains incomplete: recon is done; enum remains partial after an anonymous
HTTP 401 crawl (retaining both the prior and current root HTTP 200
observations); access records minimal validation and broader coverage as
`not_tested`. Report preserves these unfinished steps. The signed closure has
9 hypotheses, all 9 `not_tested`, zero attempt records and zero validator
artifacts. The report's scoped coverage query also omitted the target and
returned an error. No confirmed finding is claimed.

`acceptance_passed: false` remains accurate: this single-seed smoke package
has `holdout: not_evaluated` and does not establish independent acceptance.
The package is now consumed. No additional provider or target calls were made
during this audit. Original execution artifacts remain unchanged.
[Read-only live audit](/tmp/cco-work/full-agent-python-diagnosis/python-o508grir/live-audit.json).

## Python live-run diagnosis and summary repair — 2026-11-08

The user executed the original Path B preparation package. Run
`python-y1q2tply` ended `python_failed`, with acceptance false, after 16
provider calls, 25,628 charged tokens, 10 HTTP requests and approximately
88 seconds. Recon, enum and access produced validated summaries; report did
not complete. Usage accounting remained valid with no unsettled reservations.
Access remained partial, with both validation steps NOT TESTED and no verified
findings. The original package is consumed; its execution marker and the
original run evidence remain unchanged.

The archived report draft has `status=partial` and only
`review-evidence=done`. Its reproducible validation error is
`status=partial but no step is blocked/not_tested`. The exact final provider
response was not retained: the terminal log records only
`ValueError/workflow_failed`. Therefore the archived draft establishes a
report-contract defect, but does not establish the exact terminal response.
[Read-only diagnosis and original artifact hashes](/tmp/cco-work/full-agent-python-diagnosis/python-y1q2tply/diagnosis.json).

The Python host now carries unfinished preceding work into a report-only,
host-managed `unresolved-work` step. The model submits `review-evidence`; the
host derives the carryover from validated summaries and keeps the report
partial when preceding work remains NOT TESTED. Explicit blocked/failed
statuses remain intact. Submission schemas identify model-managed step IDs,
and context explains host-managed steps and exact artifact reference reads.
This preserves incomplete coverage without inventing findings or completion.

Enumeration now consumes the browser's actual `internal_links`,
`urls_with_params`, `form_actions` and `js_files` fields as well as `links`.
It normalizes same-origin URLs and derives query parameter names. Discovery
alone does not establish that a route or parameter was tested. A read-only
replay of the original evidence retains 15 routes and four parameters,
compared with the original one route and zero parameters. The replay also
validates a partial report retaining both unfinished access steps. It made
zero new provider calls and zero target requests.

Malformed summaries, including a failed repair response, are now archived
before termination. Failures retain a stable code, phase, schema errors and
available evidence references in `private/workflow-failure.json` and the run
result. Python launcher output exposes `stop_reason` and `failure_phase`.
Malformed provider/tool arguments are handled explicitly, and denied-tool
results are persisted immediately.

Follow-up verification: **422 tests passed, zero failures/errors/skips**.

| Verification group | Passed | Saved JUnit |
| --- | ---: | --- |
| Python boundary/repair tests and real four-phase integration | 31 | [path-b-summaryfix-tests.xml](/tmp/cco-work/path-b-summaryfix-tests.xml) |
| Preflight, runtime, context, orchestration and module regressions | 391 | [path-b-summaryfix-regressions.xml](/tmp/cco-work/path-b-summaryfix-regressions.xml) |

The local scripted-provider integration reproduces partial access and a
model-only report review step, exercises real subprocess execution and signed
closure, and rejects tampered evidence.
[Integration artifacts](/tmp/cco-work/full-agent-python-integration/run-vu_m2bu_/runs/python-ft2mku1e).
Whole-repository Ruff, repository layout and the seven health checks pass.
The source AST graph update passes without model/API calls (9,351 nodes /
21,972 edges before this documentation append). The three native integration
tests from the original Path B verification remain recorded above; they were
not rerun for this Python-only follow-up.

The fresh, unconsumed package is
`/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-summaryfix-20261108/`.
It retains TOKENS=150000, SECONDS=900, HTTP=300, SEED=20261104 and
`openrouter/stealth/crouton-alpha`, with a fresh preflight and 211 verified
package file hashes. No credential values were copied. Actual driver
`--plan-only` returned exit 0, `status=plan_only`,
`preflight_status=prerequisites_ready`, zero LLM calls, zero target requests
and acceptance false. Its execution marker is absent; the consumed original
marker remains present. The final audit rechecked all original evidence
hashes successfully.
[Package validation](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-summaryfix-20261108/validation.json),
[follow-up verification](/tmp/cco-work/full-agent-python-diagnosis/python-y1q2tply/verification.json).

**No live retry was started.** The contract repair is verified locally;
paid-provider completion and live/holdout acceptance remain unproven.
The new package can be executed once with:

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-summaryfix-20261108/run.py --execute
```

### Summaryfix package consumed: completed user-run verification

The user's subsequent `--execute` retry was refused because this package had
already launched `python-0as6g_o1`. Its execution marker was written at
2026-11-08 15:45:53 UTC, and the matching launch completed approximately
54 seconds later with `python_finished_verified`. The package preflight path
in the launch record establishes the association.

All four phases completed their workflow transitions; recon and enum are done,
while access and report remain partial. The run used 13 provider calls,
21,590 charged tokens and nine loopback HTTP requests. All usage measurements
are valid and all reservations settled. Enumeration retained 16 routes and
four parameters. Access records `minimal-validation=blocked` and
`broader-coverage=not_tested`; report carries both unresolved steps. There are
zero confirmed findings and zero signed probe attempts. Holdout is
`not_evaluated`, and acceptance remains false.

A read-only post-run audit using the original public trust, scope and policy
verified the attempt snapshot signature, all 21 snapshot references, and
closure again: `closure verify: verified (trusted=0/0)`, exit 0. This proves
workflow integrity and live-provider completion of the repaired partial-report
contract; it does not establish full coverage or benchmark acceptance. The
consumed marker and original evidence were preserved. No additional provider
call or target request was made during this audit.

[Completed launch](/tmp/cco-work/full-agent-python-runs/python-0as6g_o1/launch.json),
[execution audit](/tmp/cco-work/full-agent-python-diagnosis/python-0as6g_o1/execution-audit.json).

### Exact registered session lookup repair — 2026-11-08

The preserved access call used `identity=admin-a` with
`target=http://127.0.0.1:43431/admin/users`, while host setup registered that
identity at `http://127.0.0.1:43431/`. The session store's lookup key retains
the URL path, so this call returned `missing` without an HTTP request. It did
not establish that the registered identity was unavailable.
[Artifact-backed diagnosis](/tmp/cco-work/full-agent-python-diagnosis/python-0as6g_o1/session-binding-diagnosis.json).

Python workflow schemas now bind `validator_session_vault_check.target` to
the exact host-registered TaskSpec target and require a registered identity.
Fresh context supplies only the safe target/identity pairs, even when the
handoff is too large for an inline view. The host independently rejects an
endpoint URL, different port/origin, query, missing trailing slash or unknown
identity before execution, and returns the safe accepted pairs as feedback.
Rejected calls count toward the existing call allowance and failure brake.
Valid arguments reach the ordinary policy-gated, metered MCP executor unchanged.
Registrations do not imply freshness; real session checks remain necessary.
The global vault lookup rules, credential isolation and native contract are
unchanged. This repair addresses the observed lookup defect and does not claim
that every access-validation prerequisite or benchmark objective is satisfied.

Before the implementation change, two regressions reproduced the unbound
schema and execution of the wrong endpoint lookup.
[Pre-fix reproduction](/tmp/cco-work/path-b-sessionfix-reproduction.xml).
Final verification: **484 tests passed, zero failures/errors/skips**.

| Verification group | Passed | Saved JUnit |
| --- | ---: | --- |
| Python boundaries, session mismatch/recovery and real signed workflow | 44 | [path-b-sessionfix-python-tests.xml](/tmp/cco-work/path-b-sessionfix-python-tests.xml) |
| Preflight/runtime/context/orchestration/module, vault and authenticated API regressions | 440 | [path-b-sessionfix-regressions.xml](/tmp/cco-work/path-b-sessionfix-regressions.xml) |

The real local scripted-provider integration intentionally requests the wrong
endpoint lookup, receives host feedback without sending that request, then
checks the exact registered target successfully (`fresh`) through the real
subprocess. It subsequently performs a signed open-redirect validation and
completes the four-phase closure, preserving broader NOT TESTED work. It uses
nine local scripted completions (1,800 test tokens); signed closure and the
existing tamper checks pass. Only one solver vault-check reaches execution.
[Integration launch](/tmp/cco-work/full-agent-python-integration/run-_mtm5337/runs/python-dvlommya/launch.json).
Whole-repository Ruff and repository layout checks pass, as do all seven
health checks. The final AST-only graph update runs after this documentation
append and makes no model/API calls.

The new unconsumed package is
`/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-sessionfix-20261108/`.
Its fresh preflight freezes 211 file hashes and the updated host-code inventory;
TOKENS=150000, SECONDS=900, HTTP=300, SEED=20261104 and the selected model
remain unchanged. Provider configuration contains an environment reference,
with no copied credential values. Actual `--plan-only` returns exit 0,
`prerequisites_ready`, zero LLM/target calls and acceptance false. Both earlier
packages and their consumed markers remain intact. No live retry was started.
[Package validation](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-sessionfix-20261108/validation.json),
[final verification](/tmp/cco-work/full-agent-python-diagnosis/python-0as6g_o1/sessionfix-verification.json).

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-sessionfix-20261108/run.py --execute
```

### Handoff freshness failure and host refresh — 2026-11-08

The user-run `python-r7f5iyp9` ended `python_failed/workflow_failed` at the
enum handoff, after eight provider calls, 12,829 charged tokens, eight loopback
HTTP requests and 373.24 seconds. Recon and enum summaries are valid; enum is
partial, with 16 observed routes and four parameter names. Handoff preparation
returned `session reference is unavailable or not recently verified`; access
and report were not admitted. The three successful setup-check artifacts were
366.04–368.64 seconds old at handoff. The existing session gate accepts at most
300 seconds, so setup-only checks no longer satisfied freshness. All usage
measurements are valid and reservations settled.
[Diagnosis and original hashes](/tmp/cco-work/full-agent-python-diagnosis/python-r7f5iyp9/diagnosis.json).

The Python host now checks every registered identity through the normal
policy-gated, metered session tool immediately before preparing handoff.
It keeps the exact registered target from the preceding repair and requires
actual `fresh` results. An expired, missing, blocked, rate-limited or failed
check stops handoff immediately with an archived result reference. The
300-second gate, secret isolation and signed handoff checks remain enforced.

Three checks plus handoff reserve four of the existing 16 enum tool calls;
the model sees 12 discovery calls available initially. Both schema visibility
and runtime admission protect this reserve, including batched probe attempts.
The host prechecks remaining calls and consumes the same phase/HTTP allowances;
no tool or token ceiling is increased. Known handoff failures now retain codes
such as `handoff_session_refresh_failed` or `handoff_preparation_failed` with
`failed_tool_ref` in the run result and failure artifact. Budget exceptions also
retain their existing safe reason instead of a generic workflow failure.

The real subprocess integration simulates the observed delay using signed
fixture checks dated 370 seconds ago, without sleeping or changing the
production freshness window. Before the repair, those expired checks reproduce
the enum handoff failure.
[Pre-fix reproduction](/tmp/cco-work/path-b-freshnessfix-reproduction.xml).
After the repair, three real metered checks return fresh, handoff succeeds,
and all four phases and signed closure verify. The test also retains the prior
endpoint-lookup rejection/recovery and signed-evidence tamper checks. Its nine
local scripted completions charge 1,800 test tokens and ten owned-loopback
HTTP requests. Broader coverage remains NOT TESTED and acceptance stays false.
[Final integration launch](/tmp/cco-work/full-agent-python-integration/run-holq6q_p/runs/python-dmdvm1pq/launch.json).

Final selected verification: **495 tests passed, zero failures/errors/skips**.

| Verification group | Passed | Saved JUnit |
| --- | ---: | --- |
| Python boundaries, host refresh/reserve/failure and real signed workflow | 55 | [path-b-freshnessfix-python-tests.xml](/tmp/cco-work/path-b-freshnessfix-python-tests.xml) |
| Preflight/runtime/context/orchestration/module, vault and authenticated API regressions | 439 | [path-b-freshnessfix-regressions.xml](/tmp/cco-work/path-b-freshnessfix-regressions.xml) |
| Native context regression, run separately | 1 | [path-b-freshnessfix-context-recheck.xml](/tmp/cco-work/path-b-freshnessfix-context-recheck.xml) |

The initial parallel regression run timed out in the native context test;
its record is preserved in
[initial regression JUnit](/tmp/cco-work/path-b-freshnessfix-regressions-initial.xml).
That test passed separately, with unchanged limits. The remaining groups were
then rerun successfully in sequence. Whole-repository Ruff, repository layout
and all seven health checks pass. The final AST-only graph update follows this
documentation append and makes no model/API calls.

The new unconsumed package is
`/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-freshnessfix-20261108/`.
It freezes the fresh preflight, updated host code and 211 package files, keeping
TOKENS=150000, SECONDS=900, HTTP=300, SEED=20261104 and the prior selected model.
Actual `--plan-only` returns exit 0, `prerequisites_ready`, zero LLM/target
calls and acceptance false. Earlier run evidence and consumed packages remain
unchanged; no credentials were copied and no live retry was started.
[Package validation](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-freshnessfix-20261108/validation.json),
[final verification](/tmp/cco-work/full-agent-python-diagnosis/python-r7f5iyp9/freshnessfix-verification.json).
Live completion and full acceptance of the new package remain unproven.

```bash
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-freshnessfix-20261108/run.py --execute
```

## Python workflow (Path B) — 2026-11-08

Phases 1–4 of `/tmp/cco-work/path-b-plan.md` are implemented as
`python-workflow-v1`, selected with `--solver-mode python_loop` in preflight
and the launcher. The default native contract and execution path remain
compatible. The Python workflow does not start OpenCode or its native bridge.

`full_agent_python_broker.py` calls the existing host MCP execution path,
retaining PolicyEngine checks, LocalMCPExecutor subprocess accounting,
wire-budget admission, provider usage validation and Ed25519 host custody.
Phase token ceilings at 150,000 total tokens are 30,000 / 45,000 / 37,500 /
22,500 for recon / enum / access / report; the unused planner share is 15,000.
Provider and execution call ceilings are 12 / 16 / 14 / 6. Two consecutive
tool failures stop the phase; ordinary negative validator verdicts do not.
Bounded artifact reads consume execution allowance and respect the shared
deadline. HTTP 429/503 responses stop further execution after preserving evidence.

`full_agent_python_solver.py` enforces recon-1 → enum-2 → access-3 → report-4
through `brain.next_spec`. Every completion receives fresh messages containing
the current task goals and schemas, the verified previous summary and host
handoff, remaining budgets, at most four compressed recent results and a
bounded index pointing into `context-archive/`. Exact raw tool results remain
on disk behind hashed `content_ref` references.

The host compiles summaries from structured `submit_phase_summary` responses.
Route probes, tested parameters and evidence references come from actual
broker records; observed ID formats never establish ownership. Model claims
remain hypotheses, while reportable confirmation references must pass the
existing current signed-validator gate. The plan named a feedback module that
did not yet exist: `full_agent_summary_feedback.py` now aggregates schema and
TaskSpec defects and permits one summary-only repair using the reserved
completion allowance. Handoff and closure are charged host operations.

At report completion, the existing `brain.py closure verify` gate validates
the signed closure and canonical `attempts.jsonl` chain. The additional signed
`attempt-ledger.json` snapshot binds all four summaries, handoff/pool files,
validator copies and archived evidence. Missing, replayed or changed files
fail verification. Remaining vectors retain explicit NOT TESTED attestations;
successful closure does not grant full benchmark acceptance.

Final selected verification: **417 tests passed, zero failures/errors/skips**.

| Verification group | Passed | Saved JUnit |
| --- | ---: | --- |
| Preflight, runtime, context, orchestration and module regressions | 391 | [path-b-regressions.xml](/tmp/cco-work/path-b-regressions.xml) |
| Python boundary/repair tests and real four-phase integration | 23 | [path-b-python-tests.xml](/tmp/cco-work/path-b-python-tests.xml) |
| Native negative/positive closure and seed-isolation integration | 3 | [path-b-native-integration.xml](/tmp/cco-work/path-b-native-integration.xml) |

The Python integration uses a local scripted OpenAI-compatible provider and
the real production subprocess, scope, request-accounting and signing paths.
Its final run made seven local scripted completions (1,400 reported test
tokens), six owned-loopback HTTP requests, one signed validation and one
signed attempt. All four phases and the signed closure verified; child PIDs
were gone at completion. Tampering with the attempt snapshot, canonical
attempt, handoff, enum summary, closure or copied validator artifact was
rejected, and verification passed after restoring the original bytes.
[Retained integration launch](/tmp/cco-work/full-agent-python-integration/run-evhjipgo/runs/python-zyxnpd4j/launch.json).

Whole-repository and driver `ruff check` and
`python3 scripts/check_repo_layout.py` pass. The final AST-only
`graphify update .` passes without model/API calls: 9,338 nodes and 21,940
edges. The system health check also passes all seven checks.

The unexecuted preparation package is
`/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-20261108/`:
[run.py](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-20261108/run.py),
[plan.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-20261108/plan.json),
and [validation.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-20261108/validation.json).
It freezes TOKENS=150000, SECONDS=900, HTTP=300, SEED=20261104 and 211 package
file hashes. Preflight also checks current host-code hashes. The measured
blind-lab/3 comparison is reused. Model selection follows the preceding
bindingsfix package (`openrouter/stealth/crouton-alpha`); no fresh catalog or
provider request was made. Credentials are supplied only at explicit
single-use execution through the host environment or hidden terminal input.

Actual default/`--plan-only` driver verification returns exit 0,
`status=plan_only`, `preflight_status=prerequisites_ready`, `llm_calls=0`,
`target_requests=0`, and `acceptance_passed=false`. The execution marker does
not exist. **No live provider or live target run was started.** Paid-provider
behavior and independent holdout acceptance remain unevaluated.

```bash
PYTHONPATH=scripts python3 -m pytest tests/test_full_agent_python_solver.py -q
PYTHONPATH=scripts python3 -m pytest tests/test_full_agent_preflight.py tests/test_full_agent_runtime_policy.py tests/test_full_agent_context.py tests/test_full_agent_context_window.py tests/test_orchestration_spec.py tests/test_module_boundaries.py -q
PYTHONPATH=scripts python3 -m pytest tests/test_full_agent_integration.py -k 'native_successful_closure_and_integrity or native_holdout_seed_isolation_and_signed_closure or native_negative_control_closure_and_tamper' -q
python3 /tmp/cco-work/full-agent-paid-smoke-preparation/preparation-python-solver-20261108/run.py --plan-only
```
The user's later instruction authorizes agent-run live verification. The agent
has now started the single-use reasoningfix attempt; its result is recorded below
when complete. No credential is stored in these artifacts.


### Agent-run reasoningfix result

`native-c9qx3k47` ended `context_limit_exhausted`, exit 2, after 20 OpenRouter
calls, 43,506 charged tokens and 16 owned-loopback HTTP requests. All usage
measurements are valid; one uses the conservative reasoning adapter. No pending
reservation remains. Recon is done; enum has a valid partial summary and actual
host handoff receipts. Access/report were not admitted. This is not full
acceptance. [Measured analysis](/tmp/cco-work/full-agent-paid-smoke-preparation/openrouter-reasoning-repair-20261108/reasoningfix-live-analysis.json).

At the rejected continuation the worker still had 106,494 global / 15,246 enum
tokens but its conservative prompt bound exceeded 12,000. History archives
preserved completed turns, yet each index repeated up to 512 result characters
and argument locators. Runtime-bound projections now retain call IDs/tool names,
64-character context excerpts and exact hash-verified archives. System/user
instructions and unresolved/ambiguous calls remain unchanged. Signed decisions
and complete arguments/results must still come from the archived full bytes.
The first compact draft omitted IDs, which the native chain caught; IDs are
preserved in the final implementation and the draft never claimed a live run.


### Frozen contextfix package

Final verification: 254 unit/runtime checks, 17 terminal-driver checks and one
native full-chain probe pass without failures/errors/skips. Actual plan-only is
errors=0, exit 0; the offline audit verifies 269 hash records. Ruff, repo layout
and AST-only graph update pass (9259 nodes / 21732 edges, zero LLM calls).
The contextfix package retains the same free model, budgets, measured baseline,
tokenizer, scope and signed closure gates. This pre-execution record does not
claim live acceptance. The agent has started its single-use live attempt under
the user's explicit run authorization.

| Frozen artifact | SHA-256 |
| --- | --- |
| [preflight.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-contextfix-20261108/preflight.json) | `d8bc05f6181378b67f948a95648d18c495d214af37352ff097f841e4e9e7961b` |
| [plan.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-contextfix-20261108/plan.json) | `486e8b4834a6ce692a50bd3f54f2e2c9108eb70d39f6c9ebf99eb2b5258b04be` |
| [run.py](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-contextfix-20261108/run.py) | `e4c41c1f289c323258a98e9f8fbb7c354b8934c8eb913e493c3f4c81feb35d0c` |
| [preparation.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-contextfix-20261108/preparation.json) | `7261ca9889ee2ef8b9360c883fd53c60fdee914a687344d8d2f4e11d6966b855` |
| [hashes.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-contextfix-20261108/hashes.json) | `9b0366209684fa7386388e0f47323348c3550ba28c3a473a8ee6af4edd892e68` |


### Agent-run contextfix result and exact binding guidance

`native-o095vp91` ended `phase_call_budget_exhausted`, exit 2, after 20 model
calls, 43,557 charged tokens and 18 owned-loopback requests. All usage is valid;
context bounds hold. Recon finished, enum remained partial; no host handoff
receipt was produced. The first handoff failed an invalid summary status; the
second included an invented `present` field in `session_bindings_json` and failed
`invalid test session reference binding`. Six closing model turns and 20 native
operations were consumed. Access/report were not admitted. The failure is
preserved; no usage was refunded and no invalid packet was accepted.
[Measured analysis](/tmp/cco-work/full-agent-paid-smoke-preparation/openrouter-reasoning-repair-20261108/contextfix-live-analysis.json).

The metered provider handoff schema now exposes a required single-value enum for
`session_bindings_json`, containing the exact safe opaque host references.
It supplies model guidance; actual execution still validates the submitted
arguments independently. The host does not rewrite wrong arguments, fabricate
sessions or relax phase/closure gates. The regression verifies the original
request is unmodified and the provider receives the exact reference literal.


### Frozen bindingsfix package

255 unit/runtime tests, 17 terminal guards and one native four-phase chain pass
with no errors/failures/skips. Actual plan-only returns errors=0, exit 0; offline
hash audit verifies 267 entries. Whole-repo/package Ruff and repo layout pass.
AST-only graph update passes with zero model calls (9261 nodes / 21739 edges).
Public catalog was rechecked immediately before execution; the selected model's
prompt/completion prices remain zero. All budgets, phase/provider/native tool
ceilings, baseline and pinned tokenizer remain unchanged. The agent started the
single-use bindingsfix attempt using hidden terminal credential input.

| Frozen artifact | SHA-256 |
| --- | --- |
| [preflight.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-bindingsfix-20261108/preflight.json) | `d69203c61bb6dc1d3cd03af1ef091c537de3c96e46681db7d49ebda7583134bb` |
| [plan.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-bindingsfix-20261108/plan.json) | `193bdb80395ba27f34e45a06229bfe45465b65a71e3d0ccfe395de7be9340abc` |
| [run.py](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-bindingsfix-20261108/run.py) | `6f513719990d6688f38d6fbc5ddfb756bd895f383596017743229e02687a6652` |
| [preparation.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-bindingsfix-20261108/preparation.json) | `7e755579532f9fb11e2f74e5e803af1adcd16daf1b36a6a1bc088a4de3375adb` |
| [hashes.json](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-bindingsfix-20261108/hashes.json) | `4d07fe82c8d90f1feff4a54e57a86b8f1ada9b4d2fe0eaf7d6090d523f50f2b4` |


### Final agent-run verification result

The third run `native-1ld5pa_g` ended `phase_call_budget_exhausted`, exit 2,
after 12 provider calls / 15,837 charged tokens / 4 owned-loopback HTTP requests.
The recon worker used its 10-call ceiling and three closing turns; its last
model-written summary has `findings` as an object rather than the required list.
That invalid draft is preserved privately. Host finalization wrote a valid
`blocked` summary with its stop receipt and actual tool evidence. Enum,
access and report were not admitted. This run did not reach the handoff schema
change, so its live benefit remains unproven despite passing offline/native
regressions. All usage measurements and admission bounds remain valid; the
read-only post-run audit verifies scope hashes, event sums, settled reservations,
current frozen source hashes and admitted tasks. No closure exists and holdout
acceptance remains unevaluated. No run is promoted to full acceptance.

| Agent-executed run | Terminal status | Model calls | Charged tokens | Local HTTP |
| --- | --- | --- | --- | --- |
| `native-c9qx3k47` | `context_limit_exhausted` | 20 | 43506 | 16 |
| `native-o095vp91` | `phase_call_budget_exhausted` | 20 | 43557 | 18 |
| `native-1ld5pa_g` | `phase_call_budget_exhausted` | 12 | 15837 | 4 |

Across these three fresh single-use attempts: 52 provider calls, 102,900 charged
tokens and 38 loopback HTTP requests; limits are per attempt. The earlier
`native-lsxcrchv` reasoning-mismatch run is retained separately and is not
included in this table. Catalog prices are zero; billed dollar cost was not
queried independently. Credentials were submitted only through hidden PTY input
and were not written to package/repository artifacts. Old claims and charges
remain unchanged. The packages are consumed; reusing their execute commands
is correctly refused.

[Combined measured results](/tmp/cco-work/full-agent-paid-smoke-preparation/openrouter-reasoning-repair-20261108/agent-live-results.json),
[read-only execution audit](/tmp/cco-work/full-agent-paid-smoke-preparation/preparation-openrouter-crouton-bindingsfix-20261108/execution-audit.json),
[final source and evidence hashes](/tmp/cco-work/full-agent-paid-smoke-preparation/openrouter-reasoning-repair-20261108/final-hashes.json).
Final repository/package/helper Ruff and repo-layout checks pass. Final code
AST graph update passed before execution; no subsequent source edit occurred.
StateOps run: `ad46667a-2cf7-4c58-bb16-61da19a6caea`.


## Adım 1: Python erişim kontrolü holdout kapsamının tamamlanması — 2026-11-08

Önceki Python holdout ilk iki kayıtlı üyeyle sınırlıydı: pozitif recall 4/8,
negatif kapsam 4/8 idi. Diğer iki üyenin kaynakları doğrulanmadığından sonuç
kısmi kalıyordu. Üretim yürütücüsünün host fallback'i de yalnız ilk iki üyeyi
seçiyor ve dört doğrulamadan sonra duruyordu.

Python host artık aynı hedefe kayıtlı, `role=member`, `test_data_only=true` ve
`owned_objects_private=true` koşullarını sağlayan 2–8 kimliği ikili gruplara
ayırır. Her grup için mevcut access araç sınırı içinde bir çağrı ayrılır;
keşif 24 istek ve doğrulama 16 adayla sınırlıdır. Dört üyeli senaryoda gruplar
ayrıktır; tek sayıda üyede son üye ilk üyeyle eşleştirilir. Bir grubun yeniden
çalıştırılmaması için gözlenen kuyruğun tamamına ait güncel imzalı sonuçlar ve
URL/yöntem/işlem/kimlik/sahip bağlarının eşleşmesi gerekir. Başka bir vektöre
yapılan tek doğrulama, bekleyen üye gruplarını tamamlanmış saydırmaz.

Gruplar arasında mevcut araç hız penceresi beklenir (bu laboratuvarda 60 saniye).
Bekleme iptal edilebilir; yeterli süre veya araç/HTTP bütçesi yoksa bekleyen
gruplar gerekçeleriyle `not_tested` olarak özete taşınır. Faz sınırları ve
150000 token / 900 saniye / 300 HTTP üst sınırları korunmuştur.

İki yeni seed ile gerçek MCP alt süreçleri, GET-only loopback ve bağımsız
host denetimi çalıştırıldı. Her koşuda 16 imzalı doğrulama vardır: sekiz
`CONFIRMED`, sekiz `UNCONFIRMED`. Negatif kontrollerin dördü 403, dördü HTTP 200
ile redakte edilmiş yanıttır; owner/attacker yanıtları ve wire kanıtları
ayrı ayrı doğrulanmıştır. İmzalı kapanış, kullanım muhasebesi ve dört snapshot
bozma/geri yükleme denemesi geçmiştir; reddedilmiş sonuç kanıtı yoktur.

| Senaryo | Çalıştırma | Seed | Pozitif recall | Negatif kapsam | Yanlış pozitif | Model çağrısı | Token | HTTP | Saniye |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Host bütün grupları yürütür | [python-mhbwd5sz](/tmp/cco-work/full-agent-python-holdout/authcoverage-uxuu1zb5/runs/python-mhbwd5sz/launch.json) | 314159 | 8/8 | 8/8 | 0/8 | 8 | 1600 | 82 | 226.53 |
| Model ilk grubu, host kalan grubu yürütür | [python-9z05du58](/tmp/cco-work/full-agent-python-holdout/authcoverage-v6myb2db/runs/python-9z05du58/launch.json) | 161803 | 8/8 | 8/8 | 0/8 | 9 | 1800 | 82 | 107.85 |

Python solver testleri 119, ilgili preflight/runtime/crawl regresyonları 266,
bağımsız holdout testleri 2: toplam **387 test geçti**. Depo genelinde Ruff ve
repo düzeni kontrolleri geçti. AST-only graf güncellendi: 9476 düğüm, 22299 kenar,
model çağrısı sıfır.

İlk ara testin kaynak sabitleme denetimi, test sürerken host kaynağı güncellendiği
için doğru biçimde reddedildi. İkinci ara testte doğrulama sayısına sekiz imzalı
`session-recovery` kaydı da katılmıştı; test yalnız gerçek validator sonuçlarını
sayacak şekilde düzeltildi. Ara kanıtlar ve başarısız JUnit korunmuş, son iki
koşu kaynak sabitken yeniden çalıştırılmıştır.

Bu ölçüm tek bağımsız aile içindir. İki seed yeni aile sayılmaz; genel kabul
hâlâ `false`, uzak sağlayıcı genellemesi henüz değerlendirilmemiştir. Sonraki
aileler bu adımda çalıştırılmadı. Uzak sağlayıcı çağrısı ve yeni ücretli paket
hazırlığı yapılmadı; önceki tüketilmiş paket ve çalışma kayıtları korundu.

[Toplu doğrulama ve SHA-256 kayıtları](/tmp/cco-work/accesscoverage-step1-verification.json),
[solver JUnit](/tmp/cco-work/accesscoverage-step1-solver.xml),
[regresyon JUnit](/tmp/cco-work/accesscoverage-step1-regression.xml),
[son holdout JUnit](/tmp/cco-work/accesscoverage-step1-holdout-final.xml),
[korunan ara başarısızlıklar](/tmp/cco-work/accesscoverage-step1-holdout.xml).


## Adım 2–3: Python SQLi/SSTI holdout ve toplu kabul — 2026-11-08

`python_loop` artık modelin gerçekten başlattığı `readonly_sqli_boolean` veya
`readonly_ssti_arithmetic` profilini, enum'un gözlediği GET query yüzeyindeki
kalan kataloglara taşır. Host devamı yalnız enum kanıtının kayıtlı SHA-256 bağı
korunuyorsa çalışır. Bir parametreyi tamamlanmış saymak için aynı URL, query
parametresi, yöntem, taşıyıcı ve oracle'a ait güncel imzalı validator sonucu
gerekir. Tek bir doğrulama diğer katalogları tamamlanmış saydırmaz. Katalog
hedefleri gözlenen yüzeyden gelir; evaluator ailesi, truth veya beklenen vaka
sayıları yürütücüye/model bağlamına aktarılmaz.

Mevcut MCP araçları ve salt okunur profiller yeniden kullanılmıştır. İlk
hunter çağrısı dört parametreyi doğrular; erken faz özeti geldiğinde host kalan
üç kataloğu tamamlar. Çağrı başına dört yüzey kaydı, en fazla 16 validator adayı
ve mevcut 60 saniyelik hız penceresi korunur. Yeni altyapı eklenmemiştir;
150000 token / 900 saniye / 300 HTTP ve faz/araç sınırları değişmemiştir.
Bütçe veya süre yetmezse host gerekçeli `not_tested` bırakır. Değişen keşif
kanıtı yürütme öncesinde reddedilir; farklı oracle/query veya tek bir sonuç
bekleyen parametreleri kapatamaz.

İki yeni aile, yalnız kararları betiklenmiş yerel OpenAI-compatible sağlayıcıyla,
gerçek LocalMCPExecutor alt süreçleri ve launcher'ın trafik öncesinde doğruladığı
koşuya özel tam loopback scope üzerinden çalıştırıldı. SQLi gerçek SQLite SELECT
sonuçlarını tekrarlı boolean kontrollerle; SSTI gerçek Jinja2 aritmetiğini iki
bağımsız çarpım ve bozuk sözdizimi kontrolüyle doğrular. Negatifler SQLi'de
parametre bağlama/girdi doğrulama, SSTI'de literal kaçış/girdi doğrulamadır.
Her yeni ailede 16 imzalı sonuç vardır: sekiz `CONFIRMED`, sekiz `UNCONFIRMED`.
SQLi vaka başına en fazla sekiz, SSTI en fazla yedi HTTP isteği kullanır.

| Aile / seçilen koşu | Seed | Pozitif recall | Negatif kapsam | FP | Yerel model çağrısı | Token | HTTP | Saniye |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [readonly-api-access-control / python-3wcgrzli](/tmp/cco-work/full-agent-python-holdout/authcoverage-i51rwl9n/runs/python-3wcgrzli/launch.json) | 314159 | 8/8 | 8/8 | 0/8 | 8 | 1600 | 82 | 100.14 |
| [readonly-sql-injection / python-oxzi9zpy](/tmp/cco-work/full-agent-python-holdout/authcoverage-aa1qgdy6/runs/python-oxzi9zpy/launch.json) | 271828 | 8/8 | 8/8 | 0/8 | 9 | 1800 | 136 | 248.12 |
| [readonly-template-injection / python-2f1gokqq](/tmp/cco-work/full-agent-python-holdout/authcoverage-grpazr_u/runs/python-2f1gokqq/launch.json) | 141421 | 8/8 | 8/8 | 0/8 | 9 | 1800 | 128 | 204.58 |

Erişim kontrolünün model-ilk-grup senaryosu da yeniden geçti:
[python-km2ndstm](/tmp/cco-work/full-agent-python-holdout/authcoverage-99wc1mv6/runs/python-km2ndstm/launch.json),
seed 161803; 8/8 pozitif, 8/8 negatif, FP=0, 9 çağrı, 1800 token,
82 HTTP, 102.85 saniye. Bu tekrar ek aile kredisi kazanmaz; aggregate'a eklenmesi
reddedilmiştir. Eski koşuların kaynak sabitlemesi değiştirilmeden, toplu hesapta
bu değişikliğin kaynaklarıyla hazırlanmış üç yeni koşu kullanılmıştır.

Üç koşu `holdout.audit_run` ile orijinal host güveni altında tekrar denetlendi:
`closure_verified=true`, `accounting_matches=true`, reddedilmiş kanıt sıfır.
Her koşuda kalan sekiz vektörün gerekçeli `not_tested_reasons` kümesi imzalı
kapanışın `not_tested` kümesiyle aynıdır. Bu kayıtlar daha geniş güvenlik
kapsamının tamamlandığını iddia etmez; `broader-coverage` kısmi kalırken gerçek
SQLi/SSTI doğrulamaları kanıtlarıyla korunur. Dört snapshot üzerinde bozma/geri
yükleme denemesi her holdout koşusunda reddedilmiş; Python uçtan uca testlerinde
kapanış, handoff ve validator bütünlüğü de doğrulanmıştır.

`full_agent_holdout.aggregate` eksik olan FP=0 ve doğrulanmış kapanış koşullarını
artık açıkça denetler. FP veya eksik/doğrulanmamış kapanış, diğer sayısal eşikler
geçse de `passed` üretemez. Mevcut imza doğrulaması `audit_run` içinde korunur.

| Toplu koşul | Ölçüm | Sonuç |
| --- | --- | --- |
| En az 3 bağımsız aile | 3 | geçti |
| En az 24 pozitif / 24 negatif | 24 / 24 | geçti |
| Toplam recall ≥ %70 | 24/24 = %100 | geçti |
| Her ailede recall ≥ %50 | her aile 8/8 = %100 | geçti |
| Negatif kapsam ≥ %90 | 24/24 = %100 | geçti |
| FP=0 | 0/24 | geçti |
| Her koşuda doğrulanmış imzalı kapanış | 3/3 | geçti |

Aggregate `status=passed` döndürür. Bu yerel holdout eşiklerinin kabulüdür;
`full_acceptance=false` ve `paid_model_generalization=not_evaluated` korunur.
Uzak sağlayıcı veya harici hedef çağrısı başlatılmamıştır. Tüm ölçüm artefaktları
`/tmp/cco-work` altındadır.

Kalite doğrulaması: **559 test geçti; hata, başarısızlık ve skip sıfır**.

| Grup | Geçen | JUnit |
| --- | --- | --- |
| Python solver ve holdout/SQLi/SSTI birim/altyapı testleri | 157 | [step2-unit.xml](/tmp/cco-work/step2-unit.xml) |
| Preflight, runtime, context, orchestration, modül regresyonları | 391 | [step2-regression.xml](/tmp/cco-work/step2-regression.xml) |
| Python gerçek dört faz entegrasyonu | 7 | [step2-python-integration.xml](/tmp/cco-work/step2-python-integration.xml) |
| Python erişim kontrolü holdout | 2 | [step2-api-holdout.xml](/tmp/cco-work/step2-api-holdout.xml) |
| Python SQLi/SSTI holdout | 2 | [step2-parameter-holdout.xml](/tmp/cco-work/step2-parameter-holdout.xml) |

Depo genelinde `ruff check`, `python3 scripts/check_repo_layout.py` ve
`git diff --check` geçti. AST-only `graphify update .` sonucu aşağıdaki son
kontrol kaydına işlenir; uzak model/API çağrısı kullanılmaz.

[Toplu metrikler](/tmp/cco-work/step2-holdout-aggregate.json),
[bağımsız denetim, koşular, bütçeler, gerekçeler ve SHA-256 kayıtları](/tmp/cco-work/step2-holdout-verification.json),
[trafiksiz tekrar denetimi](/tmp/cco-work/step2-audit.py),
[Ruff](/tmp/cco-work/step2-ruff.log),
[depo düzeni](/tmp/cco-work/step2-layout.log).
StateOps koşusu: `a24988f4-1a6b-44ac-84dc-076aab309c3f`.

Son AST kontrolü: `graphify update .` exit 0; **9492 düğüm, 22331 kenar**.
Çıktı `no LLM needed` olarak doğrulandı; semantik/LLM etiketleme çalıştırılmadı.
[Graphify günlüğü](/tmp/cco-work/step2-graphify.log).
