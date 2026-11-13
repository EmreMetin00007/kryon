---
name: advanced-api-sec
description: "MITRE ATT&CK T1190 (Exploit Public-Facing Application). GraphQL, gRPC, REST ve JWT tabanlı modern API sistemlerinde karmaşık zafiyetleri tespit etme ve sömürme metodolojisi."
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

## API work

1. Import observed OpenAPI/WSDL/Postman/GraphQL descriptions through the existing
   schema adapters. Preserve method, typed parameters/body, security alternatives
   and source observations; schema-only operations stay untested.
2. Merge browser captures with exact authenticated request context; UI links and
   schema paths alone do not prove execution, ownership or private access rules.
3. Use sourced test-account facts and explicitly owned synthetic resources for
   P4 authorization comparisons. Do not guess other users' identifiers.
4. Admit exact operation/carrier/actor/resource/state/variant hypotheses through
   P5. P6 dispatches the existing validator for supported read-only carriers;
   unsupported, write-dependent and missing-control work stays explicitly blocked.
5. Compile P7 business flows and P8 typed evidence chains through their existing
   APIs. A safe twin or missing independent control cannot confirm an effect.
6. Use minimum reproducible synthetic impact and a signed current artifact.
   Never use load amplification, brute-force sweeps or privilege escalation.
