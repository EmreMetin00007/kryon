#!/usr/bin/env python3
"""Thin brain: deterministic phase planner over the task-spec engine.

Replaces the multi-variant brain agent files. Given a target it emits
TaskSpec JSON for the standard phases (recon -> enum -> access -> report),
each with exact MCP tool names the policy gate enforces. The LLM still
chooses hypotheses at runtime; this planner owns the contract: tools,
budgets, evidence dirs, summary schema.

Usage:
  python3 scripts/brain.py plan --target https://host --workdir /path/run [--kind web|host|llm]
  python3 scripts/brain.py check --spec specs.json
  python3 scripts/brain.py render --spec specs.json --id recon-1
  python3 scripts/brain.py next --spec specs.json --summaries /path/run/summaries

Specs form a dependency chain; `next` renders only the first spec whose
dependencies have validated `done` summaries (<spec-id>.json in the
summaries dir) and stops the chain on blocked/failed/malformed summaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestration_spec import (  # noqa: E402
    PROTOCOL_TOOLS,
    broker_tools,
    protocol_tools,
    Step,
    TaskSpec,
    dump_specs,
    load_specs,
    render_task_prompt,
    is_skeleton_summary,
    skeleton_summary,
    SUMMARY_STATUSES,
    spec_expects_surface,
    surface_errors,
    validate_chain,
    validate_spec,
    validate_summary,
)
from target_identity import canonical_target  # noqa: E402
import hypothesis_ledger as ledger_mod  # noqa: E402
import attempt_ledger as attempts_mod  # noqa: E402
import session_store as session_mod  # noqa: E402
from object_identity import normalize_object_id, object_id_key  # noqa: E402
from runtime_paths import runtime_root  # noqa: E402

PHASE_TEMPLATES: dict[str, dict] = {
    "recon": {
        "tools": ["kali-tools_nmap_scan", "kali-tools_curl_request"],
        "commands": [
            "Full TCP connect scan with service detection on {target}",
            "Fetch {target} and record status, headers, title as evidence",
        ],
        "max_minutes": 10,
    },
    "enum": {
        "tools": [
            "browser_browser_extract_links",
            "browser_browser_capture_requests",
            "kali-tools_compose_js_routes",
            "kali-tools_ffuf_fuzz",
            "kali-tools_ledger_prepare_handoff",
        ],
        "commands": [
            "Extract links and JS bundles from {target}",
            "Compose JS route inventory from fetched bundles",
            "Light route fuzz (top-100) against {target}",
        ],
        "steps": [
            {"id": "links", "command": "Extract links and JS bundles from {target}"},
            {"id": "js-routes", "command": "Compose JS route inventory from fetched bundles"},
            {
                "id": "route-fuzz",
                "command": "Light route fuzz (top-100) against {target}",
                "optional": True,
                "fallback": "gate-default invocation only: default wordlist, "
                            "no extra_args, no custom output/filter flags",
            },
        ],
        "max_minutes": 15,
        "tool_justification": "observed surface discovery and local deterministic pool/handoff preparation",
    },
    "access": {
        "tools": [
            "hunter_run_web_loop",
            "hunter_coverage_report_run",
            "validator_validate_finding",
            "kali-tools_sqlmap_test",
            "web-advanced_graphql_introspect",
        ],
        "commands": [
            "Use hunter_run_web_loop on {target} with live=false to plan from observed surface and supplied identities",
            "Inspect hunter_coverage_report_run for this run; retain untested combinations as incomplete",
            "Validate the highest-EV candidate vector on {target} with the deterministic validator",
            "Record CONFIRMED only with validator evidence",
        ],
        "tool_justification": "run-scoped web/API planning and coverage; live calls remain scope and approval gated",
        "max_minutes": 20,
    },
    "report": {
        "tools": ["memory-server_get_target_memory", "validator_generate_validation_report"],
        "commands": [
            "Review persisted findings for {target} and distinguish current validated evidence from hypotheses",
            "Generate a report only for current artifact-backed findings; list blocked and untested coverage separately",
        ],
        "tool_justification": "retrieve existing findings for evidence-gated reporting",
        "max_minutes": 15,
    },
    "seed": {
        "tools": ["kali-tools_curl_request", "browser_browser_capture_requests",
                  "kali-tools_ledger_prepare_handoff"],
        "commands": [
            "Inspect the supplied authorized test session and recorded application entry point for {target}",
            "Use existing operator-provided test identities from the session store; never write credentials to evidence",
            "Verify the supplied session with a read-only scoped request",
        ],
        "steps": [
            {"id": "entry-point", "command": "Inspect the authorized entry point on {target} without changing data"},
            {"id": "own-identity", "command": "Use operator-provided own test identity from the session store; if missing, mark blocked"},
            {"id": "verify-session", "command": "Verify the existing test session using a scoped read-only request"},
        ],
        "max_minutes": 15,
        "tool_justification": "verified session references and deterministic local pool/handoff preparation",
    },
    "authz": {
        "tools": [
            "kali-tools_curl_request",
            "validator_validate_finding",
            "web-advanced_jwt_analyze",
            "memory-server_store_finding",
        ],
        "commands": [
            "Audit session cookie flags (HttpOnly/Secure/SameSite) on {target} from the seed session",
            "Identify CSRF protection from captured requests; mark state-changing checks untested",
            "Inspect redirect responses without following destinations outside scope",
            "Compare only explicitly owned test objects using the supplied authorized test identities",
            "Mark business-logic checks requiring state changes as untested",
        ],
        "steps": [
            {"id": "cookie-flags", "command": "Record session cookie attributes from the seed session on {target}"},
            {"id": "csrf-observation", "command": "Inspect captured CSRF controls without submitting a state-changing form", "optional": True},
            {"id": "redirect-observation", "command": "Inspect captured redirect destinations without following out-of-scope URLs", "optional": True},
            {"id": "own-objects", "command": "Compare access to explicitly owned test objects using authorized test identities only", "optional": True},
            {"id": "business-prerequisite", "command": "Record state-changing business checks as untested", "optional": True},
        ],
        "max_minutes": 20,
    },
    "llm": {
        "tools": [
            "llm-security_llm_prompt_injection_probe",
            "llm-security_llm_system_prompt_leak",
        ],
        "commands": [
            "Probe the chat endpoint of {target} for prompt injection (canary only)",
            "Attempt system-prompt leakage with benign payloads",
        ],
        "max_minutes": 15,
    },
}

# Host targets have no browser/JS surface: recon/enum stay on network tools.
KIND_OVERRIDES: dict[str, dict[str, dict]] = {
    "host": {
        "recon": {
            "tools": ["kali-tools_nmap_scan"],
            "commands": [
                "Full TCP connect scan with service detection on {target}",
            ],
            "max_minutes": 15,
        },
        "enum": {
            "tools": ["kali-tools_nmap_scan", "kali-tools_nuclei_scan"],
            "commands": [
                "Deep service enumeration of open ports on {target}",
                "Template scan (safe templates only) against {target}",
            ],
            "max_minutes": 20,
        },
        "access": {
            "tools": ["validator_validate_finding", "kali-tools_curl_request"],
            "commands": ["Inspect only observed in-scope services on {target} and retain hypotheses without evidence"],
            "max_minutes": 20,
        },
    },
}

# Per-vector access work: the ledger claims one vector, the access spec is
# re-rendered for exactly that vector. Tools stay inside the core inventory.
VECTOR_COMMANDS: dict[str, dict] = {
    "authz-idor": {
        "tools": ["kali-tools_curl_request", "validator_validate_finding"],
        "commands": [
            "Compare only explicitly owned test objects on {target} with operator-provided test identities",
            "Validate a cross-account difference only with a non-sensitive owned marker and deterministic evidence",
        ],
    },
    "authn-session": {
        "tools": ["kali-tools_curl_request", "web-advanced_jwt_analyze"],
        "commands": [
            "Audit session cookie/JWT on {target}: flags, expiry, tamper resistance (own session only)",
        ],
    },
    "csrf": {
        "tools": ["kali-tools_curl_request"],
        "commands": [
            "Inspect captured CSRF controls on {target}; mark state-changing verification untested",
        ],
    },
    "injection-sqli": {
        "tools": ["kali-tools_sqlmap_test", "validator_validate_sqli"],
        "commands": [
            "Test injectable parameters on {target} (safe mode), including non-obvious fields (JSON extras, sort/filter params)",
            "Confirm only via validator_validate_sqli evidence",
        ],
    },
    "injection-ssti": {
        "tools": ["validator_validate_ssti"],
        "commands": [
            "Test template injection parameters on {target} using arithmetic evaluation",
            "Confirm only via validator_validate_ssti evidence",
        ],
    },
    "ssrf": {
        "tools": ["kali-tools_curl_request", "validator_validate_finding"],
        "commands": [
            "Inspect observed URL-fetch parameters on {target}; use only an explicitly authorized non-sensitive canary",
            "Mark internal-data access and unverified reachability as untested",
        ],
    },
    "xss-stored": {
        "tools": ["validator_validate_xss_reflection", "kali-tools_curl_request"],
        "commands": [
            "Inspect already recorded own-object evidence on {target}; mark stored-XSS verification untested if it requires a write",
        ],
    },
    "race-business": {
        "tools": ["kali-tools_curl_request"],
        "commands": [
            "Document the business-flow preconditions on {target}; do not change state or run concurrent bursts",
        ],
    },
    "file-access": {
        "tools": ["kali-tools_curl_request", "validator_validate_path_traversal"],
        "commands": [
            "Probe download/export paths on {target} for traversal and unauthenticated access, own objects first",
        ],
    },
}

DEFAULT_PHASES = ("recon", "enum", "access", "report")

KIND_PHASES: dict[str, tuple[str, ...]] = {
    "web": DEFAULT_PHASES,
    "host": DEFAULT_PHASES,
    "llm": ("recon", "enum", "llm"),
    "authed": ("seed", "authz", "access", "report"),
}

# The full-agent mediator deliberately exposes a smaller, read-only catalog.
# Keep the general operator plans intact; native launches select this profile.
BROKER_PHASE_TEMPLATES = {
    "recon": {
        "tools": ["kali-tools_curl_request"],
        "commands": ["Fetch {target} with kali-tools_curl_request using GET; record status, headers and entry-point links as evidence"],
        "max_minutes": 5,
    },
    "enum": {
        "tools": ["kali-tools_curl_request", "kali-tools_crawl_web_surface", "browser_browser_extract_links",
                  "browser_browser_capture_requests", "kali-tools_compose_js_routes",
                  "validator_session_vault_check", "kali-tools_ledger_prepare_handoff"],
        "commands": [
            "Crawl observed links and documentation on {target} with kali-tools_crawl_web_surface; stay within the shared HTTP budget",
            "Compose routes from observed JS bundles; record surface.routes, surface.params, id_formats and docs_probes",
            "Refresh only supplied synthetic session references with validator_session_vault_check; prepare the exact-vector handoff with kali-tools_ledger_prepare_handoff",
        ],
        "max_minutes": 10,
    },
    "access": {
        "tools": ["hunter_run_web_loop", "hunter_coverage_report", "kali-tools_curl_request",
                  "validator_validate_sqli", "validator_validate_ssti", "validator_validate_path_traversal",
                  "validator_validate_xss_reflection", "validator_validate_open_redirect",
                  "validator_validate_auth_bypass", "validator_validate_idor"],
        "commands": [
            "Use hunter_run_web_loop on {target} with live=false to plan from observed surface and supplied identities",
            "Validate only observed, authorized read-only candidate vectors using the named deterministic validators",
            "Inspect hunter_coverage_report for this run; preserve blocked and NOT TESTED combinations",
        ],
        "max_minutes": 10,
    },
    "report": {
        "tools": ["hunter_coverage_report", "kali-tools_ledger_attempt_add_batch",
                  "kali-tools_ledger_coverage", "kali-tools_ledger_checkpoint"],
        "commands": [
            "Review current signed coverage and artifact pointers for {target}; keep unsupported claims as hypotheses",
            "Record only observed validator IDs and verdicts with kali-tools_ledger_attempt_add_batch; invocation signatures alone do not confirm security coverage",
            "Request kali-tools_ledger_checkpoint only after the normal closure gates pass; report blocked and NOT TESTED work",
        ],
        "max_minutes": 5,
    },
    "seed": {
        "tools": ["kali-tools_curl_request", "validator_session_vault_check",
                  "browser_browser_capture_requests", "kali-tools_ledger_prepare_handoff"],
        "commands": [
            "Inspect {target} using the supplied synthetic session references only; refresh them with validator_session_vault_check",
            "Record observed surface and prepare an authorized handoff; if references are missing, report blocked without searching for a vault",
        ],
        "max_minutes": 5,
    },
    "authz": {
        "tools": ["kali-tools_curl_request", "validator_session_vault_check",
                  "validator_validate_auth_bypass", "validator_validate_idor", "validator_validate_open_redirect"],
        "commands": [
            "Inspect cookie flags and redirects on {target}; compare only explicitly owned objects with supplied synthetic identities",
            "Validate only observed read-only authorization candidates; mark state-changing checks NOT TESTED",
        ],
        "max_minutes": 10,
    },
}


def broker_vector_template(vector: str) -> dict:
    template = VECTOR_COMMANDS[vector]
    allowed = broker_tools()
    tools = [tool for tool in template["tools"] if tool in allowed]
    if vector == "authz-idor":
        tools.append("validator_validate_idor")
    return {"tools": tools, "commands": [
        command for command in template["commands"] if "validator_validate_finding" not in command]}


def build_plan(target: str, workdir: str, phases: tuple[str, ...] | None = None,
               kind: str = "web", tool_profile: str | None = None) -> list[TaskSpec]:
    tool_profile = tool_profile or os.environ.get("CCO_TOOL_PROFILE", "core")
    if tool_profile not in {"core", "broker"}:
        raise ValueError("unknown tool profile: " + tool_profile)
    if tool_profile == "broker" and kind not in {"web", "authed"}:
        raise ValueError("broker profile supports only web and authed plans")
    if kind not in KIND_PHASES:
        raise ValueError(f"unknown kind: {kind} (expected {sorted(KIND_PHASES)})")
    target = str(target or "").strip()
    # Keep the requested URL path and query: the target may be scoped only to
    # a subtree. Host-only targets retain the existing display normalization.
    if "://" not in target:
        target = canonical_target(target) or target
    if phases is None:
        phases = KIND_PHASES[kind]
    overrides = KIND_OVERRIDES.get(kind, {})
    specs: list[TaskSpec] = []
    for index, phase in enumerate(phases, start=1):
        if tool_profile == "broker" and phase not in BROKER_PHASE_TEMPLATES:
            raise ValueError("phase unavailable in broker catalog: " + phase)
        template = (BROKER_PHASE_TEMPLATES[phase] if tool_profile == "broker"
                    else overrides.get(phase, PHASE_TEMPLATES[phase]))
        specs.append(TaskSpec(
            id=f"{phase}-{index}",
            phase=phase,
            target=target,
            tools=list(dict.fromkeys([*template["tools"], *protocol_tools(tool_profile, phase)])),
            tool_profile=tool_profile,
            commands=[c.format(target=target) for c in template["commands"]],
            evidence_dir=f"{workdir.rstrip('/')}/{phase}",
            max_calls=20 if phase in ("recon", "enum") else 25,
            max_minutes=int(template.get("max_minutes", 0)),
            tool_justification=str(template.get("tool_justification", "")),
            depends_on=[specs[-1].id] if specs else [],
            steps=[Step(
                id=str(s["id"]),
                command=str(s["command"]).format(target=target),
                optional=bool(s.get("optional", False)),
                fallback=str(s.get("fallback", "")),
            ) for s in template.get("steps", [])],
        ))
    if tool_profile == "broker":
        errors = validate_chain(specs)
        if errors:
            raise ValueError("invalid broker plan: " + "; ".join(errors))
    return specs


def observed_specs(db_path, target, workdir, context=None):
    """Plan P1–P8 observation work using exact P5 dimensions; never grant traffic.

    Surface/schema/UI capture and identity facts already feed this SQLite queue.
    Ready entries use the existing Hunter scheduler; P7/P8 manifests retain their
    evidence compiler and executor rather than being rebuilt by a model.
    """
    import sqlite3
    from agent_integration import references, preflight
    queue = ledger_mod.observation_queue(db_path, target, context)
    specs = []
    with sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True) as conn:
        for row in queue:
            dimension = conn.execute('SELECT dimension_json FROM web_hypotheses WHERE fingerprint=?',
                                     (row['fingerprint'],)).fetchone()[0]
            refs = references({'fingerprint': row['fingerprint'], 'dimension_json': dimension})
            spec = TaskSpec(id='operation-' + row['fingerprint'], phase='access', target=target,
                tools=['hunter_run_web_loop', 'hunter_coverage_report_run'],
                tool_justification='observed operation and exact hypothesis dimension',
                commands=['Plan the referenced observed operation with hunter_run_web_loop live=false; '
                          'schedule live work through campaign schedule-gaps after admission. '
                          'Use compiled P7/P8 manifests for dependent business/evidence steps.'],
                evidence_dir=str(Path(workdir) / row['fingerprint']), max_calls=25, references=refs)
            checked = preflight(spec)
            if checked['status'] != 'ready':
                raise ValueError('schema_validation_failed: ' + '; '.join(checked['errors']))
            specs.append(spec)
    return specs


def skeleton_stale(summary_mtime: float | None, now: float, max_minutes: int) -> bool:
    """A skeleton older than the phase budget is stale: the worker went
    silent instead of reporting. Unknown age or no budget never counts."""
    if summary_mtime is None or max_minutes <= 0:
        return False
    return (now - summary_mtime) > max_minutes * 60


def next_spec(specs: list[TaskSpec], summaries: dict[str, object],
              mtimes: dict[str, float] | None = None,
              now: float | None = None,
              summary_paths: dict[str, str] | None = None) -> tuple[TaskSpec | None, str]:
    """Next dispatchable spec, gated on validated `done` summaries.

    Returns (spec, "") to dispatch, or (None, reason) to stop: a dependency
    blocked/failed, a malformed summary, or the chain is complete. Order is
    enforced here, in code — never by prompt discipline alone.
    """
    chain_errors = validate_chain(specs)
    if chain_errors:
        return None, "invalid spec chain: " + "; ".join(chain_errors)
    done: set[str] = set()
    for spec in specs:
        summary = summaries.get(spec.id)
        if summary is None:
            if all(dep in done for dep in spec.depends_on):
                from agent_integration import preflight
                checked = preflight(spec)
                if checked['status'] != 'ready':
                    return None, 'schema_validation_failed: ' + '; '.join(checked['errors'])
                return spec, ""
            return None, f"waiting on dependencies of {spec.id}: {spec.depends_on}"
        if is_skeleton_summary(summary):
            aged = (mtimes or {}).get(spec.id)
            moment = now if now is not None else time.time()
            if skeleton_stale(aged, moment, spec.max_minutes):
                path = (summary_paths or {}).get(spec.id, f"{spec.id}.json")
                return None, (f"stale skeleton for {spec.id} ({path}): older than "
                              f"the {spec.max_minutes}min phase budget — "
                              "worker silent, reflexion required")
            return None, f"waiting: {spec.id} has an in-progress skeleton (worker still running)"
        errors = validate_summary(summary)
        if spec.phase == "enum" and not spec_expects_surface(spec):
            surface = set(surface_errors(summary))
            errors = [error for error in errors if error not in surface]
        if errors:
            return None, f"malformed summary for {spec.id}: " + "; ".join(errors)
        status = summary.get("status") if isinstance(summary, dict) else None
        if status not in ("done", "partial"):
            return None, f"chain stopped at {spec.id}: status={status}"
        done.add(spec.id)
    return None, "chain complete: all phases done"


def _parse_id_arg(text: str):
    try:
        if text.strip().startswith("{"):
            return normalize_object_id(json.loads(text))
        refs = _parse_id_refs(text)
        if len(refs) != 1:
            raise ValueError("expected one object identifier")
        return normalize_object_id(refs[0])
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _parse_id_list(text: str) -> list:
    out: list = []
    for part in re.split(r"[\s,;]+", text or ""):
        if not part:
            continue
        out.append(_parse_id_arg(part))
    return out


def _parse_id_refs(text: str) -> list[dict]:
    """Opaque object-id refs; nothing is dropped for being non-numeric.

    Tokens are `family:id` or bare `id`; the id stays a string so UUIDs
    and other formats survive into the pool file. Integer neighbours
    are derived later from int-like ids only.
    """
    refs: list[dict] = []
    for part in re.split(r"[\s,;]+", text or ""):
        token = part.strip()
        if not token:
            continue
        if ":" in token:
            family, ident = token.split(":", 1)
            family, ident = family.strip(), ident.strip()
            if not ident:
                continue
            if family and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", family):
                # Host-like "a.b.c.d:port" tokens are kept whole and opaque
                # so ports never leak into the integer neighbour space.
                family, ident = "", token
        else:
            family, ident = "", token
        refs.append({"family": family, "id": ident})
    return refs


def _numbers_in(items: object) -> list[int]:
    out: list[int] = []
    if not isinstance(items, (list, tuple, set)):
        return out
    for item in items:
        out.extend(int(match) for match in re.findall(r"(?<![A-Za-z0-9-])\d+(?![A-Za-z0-9-])", str(item)))
    return out


def _attempts_command(args: argparse.Namespace) -> int:
    if args.att_command == "add":
        record: dict = {
            "vector": args.vector,
            "endpoint": args.endpoint,
            "identity": args.identity,
            "verdict": args.verdict,
        }
        for key in ("candidate", "control", "status", "size"):
            if getattr(args, key) is not None:
                record[key] = getattr(args, key)
        if args.note:
            record["note"] = args.note
        if args.artifact:
            artifact_path = attempts_mod.resolve_artifact(args.workdir, args.artifact)
            if artifact_path is None:
                print(f"STOP: artifact must exist inside the run workdir: {args.artifact}")
                return 2
            digest = attempts_mod.sha256_of(artifact_path)
            if args.sha256 and args.sha256 != digest:
                print("STOP: artifact sha256 mismatch")
                return 2
            root = Path(args.workdir).expanduser().resolve()
            record["artifact"] = artifact_path.relative_to(root).as_posix()
            record["sha256"] = digest
        elif args.sha256:
            print("STOP: --sha256 needs --artifact")
            return 2
        try:
            stored = attempts_mod.append_record(
                attempts_mod.ledger_path(args.workdir), record)
        except (OSError, ValueError) as exc:
            print(f"STOP: bad attempt record: {exc}")
            return 2
        print(json.dumps(stored, ensure_ascii=False))
        return 0
    try:
        records = attempts_mod.read_records(attempts_mod.ledger_path(args.workdir))
    except (OSError, ValueError) as exc:
        print(f"STOP: unreadable attempt ledger: {exc}")
        return 2
    if args.att_command == "list":
        if args.vector:
            records = [r for r in records if r.get("vector") == args.vector]
        print(json.dumps(records, ensure_ascii=False))
        return 0
    if args.att_command == "coverage":
        try:
            expected = _parse_id_list(args.expected)
        except argparse.ArgumentTypeError as exc:
            print(f"STOP: invalid expected identifier: {exc}")
            return 2
        print(json.dumps(attempts_mod.coverage(records, args.vector, expected,
                         path=attempts_mod.ledger_path(args.workdir)),
                         ensure_ascii=False))
        return 0
    print(json.dumps(records, ensure_ascii=False))
    return 0


def _race_request_command(args: argparse.Namespace) -> int:
    reason = str(args.reason or "").strip()
    evidence = str(args.evidence or "").strip()
    if not reason or not evidence:
        print("STOP: race-request needs a non-empty --reason and --evidence")
        return 2
    workdir = Path(args.workdir)
    if not workdir.is_dir():
        print(f"STOP: unknown run workdir {args.workdir}")
        return 2
    payload = {
        "reason": reason,
        "evidence": evidence,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }
    (workdir / "race-request.json").write_text(
        json.dumps(payload, ensure_ascii=False))
    print(f"race-request: {workdir / 'race-request.json'}")
    return 0


def _state_command(args: argparse.Namespace) -> int:
    try:
        state = attempts_mod.load_state(args.workdir)
    except (OSError, ValueError) as exc:
        print(f"STOP: bad run state: {exc}")
        return 2
    try:
        if args.state_command == "identity":
            entry = attempts_mod.set_identity(state, args.name, args.pointer)
        elif args.state_command == "job":
            entry = attempts_mod.add_job(state, args.kind, args.ref)
        elif args.state_command == "job-reopen":
            entry = attempts_mod.reopen_job(state, args.ref, args.kind)
        else:
            entry = attempts_mod.set_job(state, args.ref, args.status)
    except (KeyError, ValueError) as exc:
        print(f"STOP: {exc}")
        return 2
    try:
        attempts_mod.save_state(args.workdir, state)
    except (OSError, ValueError) as exc:
        print(f"STOP: cannot save run state: {exc}")
        return 2
    print(json.dumps(entry, ensure_ascii=False))
    return 0


def build_object_pool(summary: dict, own_ids: list, docs_ids: list | None = None,
                      budget_calls: int = 25, radius: int | None = None) -> dict:
    """Build the same bounded pool for CLI and host-side MCP callers."""
    if not isinstance(summary, dict):
        raise ValueError("summary must be a JSON object")
    surface = summary.get("surface", {})
    if not isinstance(surface, dict):
        raise ValueError("summary surface must be an object")
    routes = surface.get("routes", [])
    if not isinstance(routes, list):
        raise ValueError("summary surface.routes must be a list")
    docs_surface = surface.get("docs", [])
    if not isinstance(docs_surface, list):
        raise ValueError("summary surface.docs must be a list")
    docs_ids = list(docs_ids or []) + [
        {"family": "", "id": str(value)} for value in _numbers_in(docs_surface)]
    budget = max(5, int(budget_calls))
    if radius is None:
        radius, pool, truncated, dropped = _budgeted_pool(routes, own_ids, docs_ids, budget)
    else:
        full_pool = ledger_mod.object_candidates(
            routes, own_ids, docs_ids, radius, priority_order=True, max_candidates=None)
        if len(full_pool) + _POOL_CALL_RESERVE > budget:
            raise ValueError(f"pool of {len(full_pool)} candidates needs "
                             f"{len(full_pool) + _POOL_CALL_RESERVE} calls, over budget "
                             f"{budget} (narrow --radius or raise --budget-calls)")
        pool = full_pool[:ledger_mod.POOL_MAX_CANDIDATES]
        dropped = len(full_pool) - len(pool)
        truncated = dropped > 0
    return {
        "routes": len(routes), "own_ids": own_ids, "docs_ids": docs_ids,
        "radius": radius, "candidates": pool,
        "empty_tenant": not own_ids and not docs_ids,
        "budget_calls": budget, "estimated_calls": len(pool) + _POOL_CALL_RESERVE,
        "estimate_basis": "batched-logging", "truncated": truncated, "dropped": dropped,
    }


def _hypotheses_command(args: argparse.Namespace) -> int:
    if args.hyp_command == "queue":
        print(json.dumps(ledger_mod.observation_queue(args.db, args.target, args.context), ensure_ascii=False))
        return 0
    if args.hyp_command == "init":
        vectors = tuple(v.strip() for v in args.vectors.split(",") if v.strip()) or None
        ledger = ledger_mod.init_ledger(args.target, vectors, args.max_attempts)
        path = ledger_mod.save_ledger(args.workdir, ledger)
        print(f"ledger: {path} target_key={ledger['target_key']} vectors={len(ledger['hypotheses'])}")
        return 0
    if args.hyp_command == "pool":
        try:
            summary = json.loads(Path(args.summary).read_text())
            out = build_object_pool(summary, _parse_id_refs(args.own_ids),
                                    _parse_id_refs(args.docs_ids), args.budget_calls, args.radius)
        except (OSError, ValueError) as exc:
            print(f"STOP: invalid pool summary {args.summary}: {exc}")
            return 2
        path = Path(args.workdir) / "object-pool.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(out, ensure_ascii=False))
        print(json.dumps({"pool": str(path), "radius": out["radius"],
                          "candidates": len(out["candidates"]),
                          "estimated_calls": out["estimated_calls"],
                          "budget_calls": out["budget_calls"],
                          "truncated": out["truncated"], "dropped": out["dropped"]},
                         ensure_ascii=False))
        return 0
    try:
        ledger = ledger_mod.load_ledger(args.workdir)
    except (OSError, ValueError) as exc:
        print(f"STOP: no readable ledger in {args.workdir}: {exc}")
        return 2
    if args.hyp_command == "next":
        entry = ledger_mod.claim_next(ledger)
        if entry is None:
            print("STOP: ledger exhausted: " + json.dumps(ledger_mod.ledger_summary(ledger)))
            return 2
        ledger_mod.save_ledger(args.workdir, ledger)
        print(json.dumps(entry, ensure_ascii=False))
        return 0
    if args.hyp_command == "mark":
        try:
            confirmation = None
            if args.status == "confirmed":
                confirmation, reason = _confirmation_record(
                    {"validation_id": args.validation_id}, args.vector, ledger)
                if confirmation is None:
                    print(f"STOP: validator evidence required: {reason}")
                    return 2
            entry = ledger_mod.mark(ledger, args.vector, args.status, args.evidence, args.note)
            if confirmation is not None:
                entry.update(_confirmation_reference(confirmation))
        except (KeyError, ValueError) as exc:
            print(f"STOP: {exc}")
            return 2
        ledger_mod.save_ledger(args.workdir, ledger)
        print(json.dumps(entry, ensure_ascii=False))
        return 0
    if args.hyp_command == "reorder":
        try:
            summary = json.loads(Path(args.summary).read_text())
        except (OSError, ValueError) as exc:
            print(f"STOP: unreadable enum summary {args.summary}: {exc}")
            return 2
        surface = summary.get("surface", {}) if isinstance(summary, dict) else {}
        routes = surface.get("routes", []) if isinstance(surface, dict) else []
        params = surface.get("params", []) if isinstance(surface, dict) else []
        ledger_mod.reorder_by_surface(ledger, routes, params)
        ledger_mod.save_ledger(args.workdir, ledger)
        print(json.dumps([e["vector"] for e in ledger["hypotheses"]], ensure_ascii=False))
        return 0
    print(json.dumps(ledger, indent=1, ensure_ascii=False))
    return 0


def _safe_format(command: str, target: str) -> str:
    try:
        return command.format(target=target)
    except (KeyError, IndexError, ValueError):
        return command


def apply_vector(spec: TaskSpec) -> TaskSpec:
    """Re-render an access spec for its claimed ledger vector.

    Brain-authored custom_commands survive the re-render: the template
    is the base, customs are appended. Without this, spec-customize
    edits would vanish from the dispatched worker prompt.
    """
    template = (broker_vector_template(spec.vector) if spec.tool_profile == "broker"
                and spec.vector in VECTOR_COMMANDS else VECTOR_COMMANDS.get(spec.vector))
    if template is None:
        return spec
    tools = list(spec.tools)
    for tool in template["tools"]:
        if tool not in tools:
            tools.append(tool)
    spec.tools = tools
    spec.commands = [c.format(target=spec.target) for c in template["commands"]]
    if "hunter_run_web_loop" in spec.tools:
        spec.commands.insert(0, f"Use hunter_run_web_loop on {spec.target} with live=false to plan from observed surface and supplied identities")
        coverage_tool = "hunter_coverage_report" if spec.tool_profile == "broker" else "hunter_coverage_report_run"
        spec.commands.append(f"Inspect {coverage_tool} for this run; retain untested combinations as incomplete")
    spec.commands.extend(_safe_format(custom, spec.target)
                         for custom in spec.custom_commands)
    return spec


def vector_result_of(summary: object) -> str:
    """Deterministic ledger outcome from a worker summary.

    Explicit `vector_result` wins; a CONFIRMED-band finding confirms;
    blocked/failed/partial burn an attempt; a clean `done` exhausts the
    vector (tested, nothing found) instead of silently advancing.
    """
    if not isinstance(summary, dict):
        return "blocked"
    explicit = str(summary.get("vector_result", "")).strip().lower()
    if explicit in ("confirmed", "blocked", "not_applicable", "tested_clean"):
        return explicit
    for finding in summary.get("findings", []) or []:
        if isinstance(finding, dict) and str(finding.get("band", "")).upper() == "CONFIRMED":
            return "confirmed"
    status = summary.get("status")
    if status == "done":
        return "tested_clean"
    return "blocked"


_RESULT_TO_STATUS = {
    "confirmed": "confirmed",
    "not_applicable": "not_applicable",
    "tested_clean": "exhausted",
    "blocked": "blocked",
}


_VALIDATOR_VECTOR_TYPES = {
    "authz-idor": "idor",
    "authn-session": "auth_bypass",
    "csrf": "csrf",
    "injection-sqli": "sql_injection",
    "injection-ssti": "ssti",
    "ssrf": "ssrf",
    "xss-stored": "xss",
    "file-access": "path_traversal",
    "race-business": "business_logic",
}

# Related, deterministically validated subtypes are defined by code, never
# chosen by a finding's prose. Keep existing token/upload/authz oracles usable.
_VALIDATOR_VECTOR_ALIASES = {
    "authz-idor": ("bola", "bfla", "broken_access_control"),
    "authn-session": ("open_redirect", "token_differential_opaque_carrier",
                      "token_round_trip_application_flow"),
    "file-access": ("unrestricted_file_upload", "xxe"),
}


def _validation_context() -> dict:
    validator_dir = runtime_root() / "mcp-servers" / "mcp-validator"
    if str(validator_dir) not in sys.path:
        sys.path.append(str(validator_dir))
    try:
        from cco_validator_core.evidence import current_scope_revision, current_policy_hash
        return {"scope_revision": current_scope_revision(), "policy_hash": current_policy_hash()}
    except Exception as exc:
        raise ValueError(f"validator context unavailable: {exc}") from exc


def _confirmation_record(summary: dict, vector: str,
                         ledger: dict | None) -> tuple[dict | None, str]:
    """Resolve a signed artifact against the vector, target and current policy.

    Finding prose cannot choose a different vulnerability type to authorize
    this vector. Return the actual verified record, not just a boolean, so
    every transition persists the reference that was checked.
    """
    validation_ids: list[str] = []
    findings = summary.get("findings", [])
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            for key in ("validation_id", "validationId", "artifact_id"):
                value = str(finding.get(key, "") or "").strip()
                if value:
                    validation_ids.append(value)
                    break
    for key in ("validation_id", "validationId", "artifact_id"):
        value = str(summary.get(key, "") or "").strip()
        if value:
            validation_ids.append(value)
            break
    if not validation_ids:
        return None, "missing validation_id from a CONFIRMED validator artifact"
    validator_dir = runtime_root() / "mcp-servers" / "mcp-validator"
    if str(validator_dir) not in sys.path:
        sys.path.append(str(validator_dir))
    try:
        from cco_validator_core import artifact_is_current, load_validation, normalize_finding_type
    except Exception as exc:  # validator core unavailable must fail closed
        return None, f"validator core unavailable: {exc}"
    target = str((ledger or {}).get("target") or summary.get("target") or "")
    if not target:
        return None, "confirmation target is missing"
    allowed_types = {normalize_finding_type(kind) for kind in (
        _VALIDATOR_VECTOR_TYPES.get(vector, vector),
        *_VALIDATOR_VECTOR_ALIASES.get(vector, ()))}
    for validation_id in dict.fromkeys(validation_ids):
        try:
            record = load_validation(validation_id)
        except Exception:
            record = None
        if not record or str(record.get("verdict", "")).upper() != "CONFIRMED":
            continue
        expected_type = normalize_finding_type(
            (record.get("binding") or {}).get("finding_type") or record.get("vuln_type", ""))
        if expected_type not in allowed_types:
            continue
        try:
            valid = artifact_is_current(record, expected_target=target, expected_finding_type=expected_type)
        except Exception:
            valid = False
        if valid:
            return record, ""
    return None, "validator artifact missing, stale, or bound to another target/type/scope/policy"


def _validator_confirmation(summary: dict, vector: str,
                            ledger: dict | None) -> tuple[bool, str]:
    record, reason = _confirmation_record(summary, vector, ledger)
    return record is not None, reason


def _confirmation_reference(record: dict) -> dict:
    return {"validation_id": record["validation_id"],
            "validation_sha256": record["artifact"]["content_sha256"]}


def _confirmed_artifacts(ledger: dict) -> list[dict]:
    """Revalidate every confirmed entry at check, seal and verify boundaries."""
    artifacts = []
    for entry in ledger.get("hypotheses", []):
        if entry.get("status") != "confirmed":
            continue
        vector = str(entry.get("vector", ""))
        record, reason = _confirmation_record(
            {"validation_id": entry.get("validation_id", "")}, vector, ledger)
        if record is None:
            raise ValueError(f"{vector}: {reason}")
        reference = _confirmation_reference(record)
        if entry.get("validation_sha256") != reference["validation_sha256"]:
            raise ValueError(f"{vector}: validator artifact hash missing or changed")
        artifacts.append({"vector": vector, **reference,
                          "file": Path(record["artifact"]["path"]).name,
                          "binding": record["binding"]})
    return artifacts


def ingest_access_summary(ledger: dict, summary: object,
                          pool_candidates: int | None = None,
                          coverage_block: str | None = None,
                          validator_verified: bool = False,
                          confirmation_error: str | None = None) -> dict | None:
    """Fold one access summary into the ledger. Idempotent per vector
    attempt: re-ingesting the same summary never burns a second attempt."""
    if not isinstance(summary, dict):
        return None
    if is_skeleton_summary(summary):
        return None
    vector = str(summary.get("vector", "")).strip()
    if not vector:
        return None
    ingested = ledger.setdefault("ingested", [])
    marker = json.dumps(summary, sort_keys=True, ensure_ascii=False)
    if marker in ingested:
        return None
    result = vector_result_of(summary)
    note = f"summary status={summary.get('status')}"
    if result == "tested_clean" and pool_candidates:
        probed = summary.get("pool_probed")
        if not isinstance(probed, int) or isinstance(probed, bool) \
                or probed < pool_candidates:
            shown = probed if isinstance(probed, int) else 0
            result = "blocked"
            note = (f"pool coverage incomplete: probed {shown} of "
                    f"{pool_candidates} candidates")
    if result == "tested_clean" and coverage_block:
        result = "blocked"
        note = f"attempt coverage incomplete: {coverage_block}"
    if vector == "xss-stored" and result in ("tested_clean", "confirmed"):
        pair = summary.get("readback")
        rendered = pair.get("rendered") if isinstance(pair, dict) else None
        submitted = pair.get("submitted") if isinstance(pair, dict) else ""
        readback = pair.get("readback") if isinstance(pair, dict) else ""
        if not submitted or not readback or not isinstance(rendered, bool):
            result = "blocked"
            note = ("xss verdict without readback pair (submitted marker + "
                    "read-back body comparison required)")
        elif (result == "confirmed") != rendered:
            result = "blocked"
            note = "xss verdict contradicts readback rendered flag"
    confirmation = None
    if result == "confirmed":
        # Legacy boolean arguments are hints only, never evidence or authority.
        confirmation, reason = _confirmation_record(summary, vector, ledger)
        if confirmation is None:
            result = "blocked"
            note = f"validator evidence required: {reason}"
    entry = ledger_mod.mark(
        ledger, vector, _RESULT_TO_STATUS[result],
        evidence="; ".join(str(e) for e in (summary.get("evidence") or [])[:3]),
        note=note,
    )
    if confirmation is not None:
        entry.update(_confirmation_reference(confirmation))
    ingested.append(marker)
    return entry


def chain_time_estimate_minutes(specs: list[TaskSpec]) -> int:
    """Worst-case wall clock for the chain if every phase runs full length."""
    return sum(int(getattr(spec, "max_minutes", 0) or 0) for spec in specs)


RACE_VECTOR = "race-business"
RACE_DEFAULT_MAX_ITEMS = 10
RACE_DEFAULT_METHODS = ("GET", "POST")


def _load_policy_file(path: str | Path | None) -> dict:
    if path is None:
        return {}
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _resolve_policy(policy_arg: str, repo_root: Path | None = None) -> dict:
    """Effective program policy for brain gates.

    An explicit --policy file is authoritative. Otherwise the live
    `.codex/program-policy.json` wins, inheriting `race_burst` from the
    shipped profile it names (default lab) when it does not set one —
    so enabling the burst in the profile actually reaches the brain.
    """
    if policy_arg:
        return _load_policy_file(policy_arg)
    root = repo_root or runtime_root()
    policy = _load_policy_file(root / ".codex" / "program-policy.json")
    if "race_burst" not in policy:
        profile = str(policy.get("profile") or "lab")
        profile_data = _load_policy_file(
            root / "config" / "program-profiles" / f"{profile}.json")
        if isinstance(profile_data.get("race_burst"), dict):
            policy = {**policy, "race_burst": profile_data["race_burst"]}
    return policy


HANDOFF_DEFAULT_MAX_CHARS = 4000
HANDOFF_EXCERPT_CHARS = 300


def _safe_slug(text: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in text) or "run"


def _sha256_json(value: object) -> str:
    material = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _trusted_attempts(workdir: str, vector: str) -> list[dict]:
    records = attempts_mod.read_records(attempts_mod.ledger_path(workdir))
    verified, errors = attempts_mod.verify_records(records, path=attempts_mod.ledger_path(workdir))
    if errors:
        raise ValueError(f"invalid attempt ledger: {'; '.join(errors)}")
    return [record for record in verified if record.get("vector") == vector]


def _state_fingerprint(state: dict) -> str:
    return _sha256_json({
        "identities": state.get("identities", []),
        "jobs": state.get("jobs", []),
    })


def _artifact_excerpt(workdir: str, record: dict) -> str:
    artifact = record.get("artifact", "")
    expected_sha = str(record.get("sha256", "") or "")
    if not expected_sha:
        return ""
    path = attempts_mod.resolve_artifact(workdir, artifact)
    if path is None or attempts_mod.sha256_of(path) != expected_sha:
        return ""
    with path.open("rb") as handle:
        raw = handle.read(HANDOFF_EXCERPT_CHARS * 4)
    return raw.decode("utf-8", "replace")[:HANDOFF_EXCERPT_CHARS]


def _fit_handoff_packet(packet: dict, max_chars: int) -> dict:
    fitted = json.loads(json.dumps(packet, ensure_ascii=False))

    def size() -> int:
        return len(json.dumps(fitted, ensure_ascii=False))

    while size() > max_chars and fitted["recent"]:
        fitted["recent"].pop(0)
        fitted["truncated"] = True
    if size() > max_chars:
        for entry in fitted["recent"]:
            entry["excerpt"] = ""
        fitted["truncated"] = True
    if size() > max_chars:
        fitted["identities"] = []
        fitted["jobs"] = []
        fitted["truncated"] = True
    if size() > max_chars:
        fitted["tried"] = []
        fitted["truncated"] = True
    if size() > max_chars:
        minimal = {
            "schema_version": 1,
            "vector": fitted["vector"],
            "untried": fitted["untried"],
            "truncated": True,
            "untried_truncated": False,
        }
        fitted = minimal
    if size() > max_chars:
        untried = list(fitted.get("untried", []))
        low, high = 0, len(untried)
        while low < high:
            middle = (low + high + 1) // 2
            trial = {**fitted, "untried": untried[:middle],
                     "untried_truncated": middle < len(untried)}
            if len(json.dumps(trial, ensure_ascii=False)) <= max_chars:
                low = middle
            else:
                high = middle - 1
        fitted["untried"] = untried[:low]
        fitted["untried_truncated"] = low < len(untried)
    return fitted


def _handoff_packet(workdir: str, vector: str, max_chars: int,
                    pool_data: dict | None = None,
                    state_data: dict | None = None) -> dict:
    pool = _pool_data(workdir) if pool_data is None else pool_data
    expected = pool.get("candidates", [])
    records = _trusted_attempts(workdir, vector)
    all_records = attempts_mod.read_records(attempts_mod.ledger_path(workdir))
    covered = attempts_mod.coverage(all_records, vector, expected, path=attempts_mod.ledger_path(workdir))
    state = attempts_mod.load_state(workdir) if state_data is None else attempts_mod.validate_state(state_data)
    recent: list[dict] = []
    for record in records:
        recent.append({
            "endpoint": record.get("endpoint"),
            "identity": record.get("identity"),
            "candidate": record.get("candidate"),
            "control": record.get("control"),
            "status": record.get("status"),
            "size": record.get("size"),
            "verdict": record.get("verdict"),
            "artifact": record.get("artifact", ""),
            "excerpt": _artifact_excerpt(workdir, record),
        })
    packet = {
        "schema_version": 1,
        "vector": vector,
        "identities": state.get("identities", []),
        "jobs": state.get("jobs", []),
        "tried": covered["tried"],
        "untried": covered["untried"],
        "controls": covered["controls"],
        "trusted_records": len(records),
        "chain_head": records[-1]["record_hash"] if records else "",
        "pool_sha256": _sha256_json(pool),
        "attempts_sha256": _sha256_json(records),
        "state_sha256": _state_fingerprint(state),
        "recent": recent,
        "truncated": False,
        "untried_truncated": False,
    }
    return _fit_handoff_packet(packet, max_chars)


def _handoff_command(args: argparse.Namespace) -> int:
    vector = (args.vector or "").strip()
    if not vector:
        print("STOP: handoff needs a --vector label")
        return 2
    try:
        packet = _handoff_packet(args.workdir, vector, max(200, args.max_chars))
        text = json.dumps(packet, ensure_ascii=False)
        path = Path(args.workdir) / f"handoff-{_safe_slug(vector)}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")
    except (OSError, ValueError) as exc:
        print(f"STOP: cannot build handoff packet: {exc}")
        return 2
    print(text)
    return 0


def _handoff_gate_error(spec: TaskSpec) -> str | None:
    path = Path(spec.evidence_dir).parent / _handoff_name(spec)
    run_root = str(path.parent)
    label = spec.vector or (spec.phase if spec.phase == "authz" else "access")
    if not path.is_file():
        return (f"handoff packet missing for {spec.id}: run `handoff "
                f"--workdir <run> --vector {label}` first (packet: {path})")
    try:
        packet = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return f"handoff packet unreadable for {spec.id}: {path}"
    if not isinstance(packet, dict):
        return f"handoff packet malformed for {spec.id}: {path}"
    if packet.get("schema_version") != 1 or packet.get("vector") != label:
        return f"handoff packet mismatch for {spec.id}: {path}"
    if packet.get("truncated") or packet.get("untried_truncated"):
        return f"handoff packet incomplete for {spec.id}: {path}"
    try:
        records = _trusted_attempts(run_root, label)
        state = attempts_mod.load_state(run_root)
    except (OSError, ValueError) as exc:
        return f"handoff packet stale for {spec.id}: {exc}"
    if packet.get("pool_sha256") != _sha256_json(_pool_data(run_root)):
        return f"handoff packet stale for {spec.id}: candidate pool changed"
    if packet.get("attempts_sha256") != _sha256_json(records):
        return f"handoff packet stale for {spec.id}: attempt ledger changed"
    if packet.get("state_sha256") != _state_fingerprint(state):
        return f"handoff packet stale for {spec.id}: run state changed"
    if packet.get("trusted_records") != len(records):
        return f"handoff packet stale for {spec.id}: trusted record count changed"
    return None


def _handoff_name(spec: TaskSpec) -> str:
    label = spec.vector or (spec.phase if spec.phase == "authz" else "access")
    return f"handoff-{_safe_slug(label)}.json"


def _pool_gate_error(spec: TaskSpec) -> str | None:
    path = Path(spec.evidence_dir).parent / "object-pool.json"
    if not path.is_file():
        return (f"object pool missing for {spec.id}: run `hypotheses pool "
                f"--summary <enum-or-seed>.json --own-ids <ids>` first (pool: {path})")
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return f"object pool unreadable for {spec.id}: {path}"
    if not isinstance(data, dict) or not isinstance(data.get("candidates"), list):
        return f"object pool malformed for {spec.id}: {path} (needs a candidates list)"
    return None


POOL_VECTORS = ("authz-idor", "file-access")


def _pool_data(workdir: str) -> dict:
    if not workdir:
        return {}
    try:
        data = json.loads((Path(workdir) / "object-pool.json").read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _pool_candidates(workdir: str) -> list:
    data = _pool_data(workdir)
    return list(data["candidates"]) if isinstance(data.get("candidates"), list) else []


def _pool_candidate_count(workdir: str) -> int:
    return len(_pool_candidates(workdir))


def _ledger_coverage_block(workdir: str, vector: str) -> str | None:
    """Why the signed attempt ledger forbids a tested-clean close."""
    if not workdir or not vector:
        return None
    try:
        records = attempts_mod.read_records(attempts_mod.ledger_path(workdir))
    except (OSError, ValueError) as exc:
        return f"attempt ledger unreadable: {exc}"
    covered = attempts_mod.coverage(records, vector, [], path=attempts_mod.ledger_path(workdir))
    if covered["integrity_errors"]:
        return f"invalid attempt ledger: {'; '.join(covered['integrity_errors'])}"
    verified, _ = attempts_mod.verify_records(records, path=attempts_mod.ledger_path(workdir))
    trusted_for_vector = [
        record for record in verified
        if record.get("vector") == vector and attempts_mod.is_probe_record(record)
    ]
    if not trusted_for_vector:
        return "no trusted attempt records"
    if vector not in POOL_VECTORS:
        return None
    if _pool_data(workdir).get("truncated"):
        return "candidate pool truncated; omitted identifiers remain untested"
    expected = _pool_candidates(workdir)
    try:
        covered = attempts_mod.coverage(records, vector, expected, path=attempts_mod.ledger_path(workdir))
    except ValueError as exc:
        return f"invalid object pool: {exc}"
    if covered["untried"]:
        shown = ", ".join(str(c) for c in covered["untried"][:12])
        extra = "" if len(covered["untried"]) <= 12 else ", ..."
        return f"untried pool candidates: [{shown}{extra}]"
    if covered["controls"] == 0:
        return "no control record"
    return None


def race_burst_policy(policy: dict | None) -> dict:
    section = (policy or {}).get("race_burst", {})
    if not isinstance(section, dict):
        section = {}
    methods = section.get("methods", list(RACE_DEFAULT_METHODS))
    if not isinstance(methods, list) or not methods:
        methods = list(RACE_DEFAULT_METHODS)
    try:
        max_items = int(section.get("max_items", RACE_DEFAULT_MAX_ITEMS))
    except (TypeError, ValueError):
        max_items = RACE_DEFAULT_MAX_ITEMS
    return {
        "enabled": section.get("enabled") is True,
        "approval_ref": str(section.get("approval_ref", "") or "").strip(),
        "max_items": max(1, max_items),
        "methods": [str(item).upper() for item in methods],
    }


def race_launch_allowed(policy: dict | None) -> tuple[bool, str]:
    section = race_burst_policy(policy)
    if not section["enabled"]:
        return False, "race_burst disabled in program policy"
    if not section["approval_ref"]:
        return False, "race_burst needs an approval_ref in program policy"
    return True, (f"approval_ref={section['approval_ref']} "
                  f"max_items={section['max_items']} methods={','.join(section['methods'])}")


def close_race_not_tested(ledger: dict, reason: str) -> dict | None:
    try:
        entry = next(entry for entry in ledger.get("hypotheses", [])
                     if entry.get("vector") == RACE_VECTOR)
    except StopIteration:
        return None
    if entry.get("status") not in ("untried", "blocked", "active"):
        return None
    return ledger_mod.mark(ledger, RACE_VECTOR, "not_applicable",
                           note=f"not_tested: auth:not-required: {reason}")


CLOSURE_FILENAME = "closure.json"
CLOSURE_SCHEMA = "closure/2"


def closure_ledger_summary(records: list[dict], path: str | Path | None = None) -> dict:
    """Trusted-count digest of the signed attempt ledger."""
    verified, errors = attempts_mod.verify_records(records, path=path)
    sig_errors = sum(1 for item in errors if "signature" in item)
    return {"records": len(records), "trusted": len(verified),
            "sig_errors": sig_errors,
            "chain_errors": len(errors) - sig_errors,
            "head": records[-1].get("record_hash", "") if records else ""}


def build_closure_payload(workdir: str, ledger: dict, records: list[dict],
                          race_probes: int) -> dict:
    """Assemble the gate-signed closure payload (never agent-written)."""
    entries = [{"vector": entry.get("vector", "?"),
                "status": entry.get("status", ""),
                "note": str(entry.get("note", "") or "")}
               for entry in ledger.get("hypotheses", [])]
    not_tested = [{"vector": entry["vector"],
                   "justification": entry["note"][len("not_tested:"):].strip()}
                  for entry in entries
                  if entry["status"] == "not_applicable"
                  and entry["note"].startswith("not_tested:")]
    race_entry = next((entry for entry in entries
                       if entry["vector"] == RACE_VECTOR), None)
    return {
        "producer": "gate",
        "schema": CLOSURE_SCHEMA,
        "workdir": str(Path(workdir).resolve()),
        "target": ledger.get("target", ""),
        "target_key": ledger.get("target_key", ""),
        "binding": _validation_context(),
        "hypotheses_sha256": _sha256_json(ledger),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hypotheses": entries,
        "not_tested": not_tested,
        "race": ({"status": race_entry["status"], "note": race_entry["note"],
                  "probes": race_probes} if race_entry is not None else None),
        "ledger": closure_ledger_summary(records, attempts_mod.ledger_path(workdir)),
        "validations": _confirmed_artifacts(ledger),
    }


def _closure_command(args: argparse.Namespace) -> int:
    target = Path(args.workdir) / CLOSURE_FILENAME
    try:
        signed = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print(f"closure verify: {target} missing or invalid JSON (unverified)")
        return 2
    payload, reason = attempts_mod.verify_signed_payload(signed)
    if payload is None:
        print(f"closure verify: {reason} (unverified)")
        return 2
    if payload.get("producer") != "gate":
        print("closure verify: producer is not gate (unverified)")
        return 2
    if payload.get("schema") != CLOSURE_SCHEMA:
        print("closure verify: unsupported closure schema; rerun check --closure (unverified)")
        return 2
    try:
        records = attempts_mod.read_records(
            attempts_mod.ledger_path(args.workdir))
        ledger = ledger_mod.load_ledger(args.workdir)
        fresh = build_closure_payload(args.workdir, ledger, records, sum(
            1 for record in attempts_mod.verify_records(records, path=attempts_mod.ledger_path(args.workdir))[0]
            if record.get("vector") == RACE_VECTOR and attempts_mod.is_probe_record(record)))
    except (OSError, ValueError) as exc:
        print(f"closure verify: ledger unreadable: {exc}")
        return 2
    expected = closure_ledger_summary(records, attempts_mod.ledger_path(args.workdir))
    if expected["sig_errors"] or expected["chain_errors"]:
        print("closure verify: invalid attempt ledger (unverified)")
        return 2
    if payload.get("ledger") != expected:
        print(f"closure verify: ledger summary drifted: "
              f"signed={payload.get('ledger')} local={expected}")
        return 2
    for key in ("workdir", "target", "target_key", "binding", "hypotheses_sha256",
                "hypotheses", "validations", "not_tested", "race"):
        if payload.get(key) != fresh.get(key):
            print(f"closure verify: {key} changed (unverified)")
            return 2
    print(f"closure verify: verified "
          f"(trusted={expected['trusted']}/{expected['records']})")
    return 0


AUTH_ATTEST_RECOVERED = "auth:recovered"
AUTH_ATTEST_NOT_REQUIRED = "auth:not-required:"


def _auth_attestation(note: str) -> str | None:
    """Explicit park attestation: recovered | not-required | None.

    Substring heuristics are evadable by rewording, so every
    not_applicable note must carry an explicit marker instead. A false
    not-required claim is still possible, but it is an auditable
    attestation in the signed ledger — not a silent dodge.
    """
    lowered = note.lower()
    if AUTH_ATTEST_RECOVERED in lowered:
        return "recovered"
    if AUTH_ATTEST_NOT_REQUIRED in lowered:
        return "not-required"
    return None


def _session_command(args: argparse.Namespace) -> int:
    report = session_mod.session_status(args.workdir)
    print(json.dumps(report, ensure_ascii=False))
    return 0


SPEC_CUSTOMIZE_MAX_ADDS = 4


def _customize_command(args: argparse.Namespace) -> int:
    """Brain-authored spec extension (bounded; validated before write)."""
    try:
        specs = load_specs(Path(args.spec).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"spec-customize: unreadable spec file: {exc}", file=sys.stderr)
        return 2
    target = next((s for s in specs if s.id == args.id), None)
    if target is None:
        print(f"spec-customize: unknown spec id: {args.id}", file=sys.stderr)
        return 2
    new_commands: list[str] = []
    if args.add_commands_file:
        try:
            lines = Path(args.add_commands_file).read_text(
                encoding="utf-8").splitlines()
        except OSError as exc:
            print(f"spec-customize: unreadable commands file: {exc}",
                  file=sys.stderr)
            return 2
        new_commands = [line.strip() for line in lines if line.strip()]
    new_tools = [t.strip() for t in (args.add_tools or "").split(",")
                 if t.strip()]
    if len(new_commands) > SPEC_CUSTOMIZE_MAX_ADDS or \
            len(new_tools) > SPEC_CUSTOMIZE_MAX_ADDS:
        print(f"spec-customize: at most {SPEC_CUSTOMIZE_MAX_ADDS} commands "
              f"and {SPEC_CUSTOMIZE_MAX_ADDS} tools per call",
              file=sys.stderr)
        return 2
    target.custom_commands = [*target.custom_commands, *new_commands]
    for tool in new_tools:
        if tool not in target.tools:
            target.tools.append(tool)
    justification = str(args.tool_justification or "").strip()
    if justification and justification not in target.tool_justification:
        joined = f"{target.tool_justification}; {justification}" \
            if target.tool_justification else justification
        target.tool_justification = joined
    bash_justification = str(args.bash_justification or "").strip()
    if bash_justification and bash_justification not in target.bash_justification:
        joined = f"{target.bash_justification}; {bash_justification}" \
            if target.bash_justification else bash_justification
        target.bash_justification = joined
    errors = validate_spec(target)
    if errors:
        print(f"spec-customize: invalid result: {'; '.join(errors)}",
              file=sys.stderr)
        return 2
    Path(args.spec).write_text(dump_specs(specs), encoding="utf-8")
    print(f"spec-customize: {target.id} "
          f"(+{len(new_commands)} commands, +{len(new_tools)} tools)")
    return 0


SYNTHESIZE_KINDS = ("ledger-summary", "coverage-count")


_POOL_RADIUS_LADDER = (0, 2, 5, 10, 25)
_POOL_CALL_RESERVE = 4


def _budgeted_pool(routes: object, own_ids: object, docs_ids: object,
                   budget: int) -> tuple[int, list, bool, int]:
    """Widest radius whose batched-logging estimate fits the budget.

    Estimate is one probe call per candidate plus a small reserve for
    batch log calls. When even seeds overflow, truncate with an honest
    dropped count instead of silently shrinking the radius to nothing.
    """
    best_pool: list | None = None
    best_radius = 0
    for radius in _POOL_RADIUS_LADDER:
        pool = ledger_mod.object_candidates(routes, own_ids, docs_ids,
                                            radius, priority_order=True, max_candidates=None)
        if len(pool) + _POOL_CALL_RESERVE > budget or len(pool) > ledger_mod.POOL_MAX_CANDIDATES:
            if best_pool is not None:
                return best_radius, best_pool, False, 0
            keep = min(ledger_mod.POOL_MAX_CANDIDATES, max(0, budget - _POOL_CALL_RESERVE))
            return radius, pool[:keep], True, len(pool) - keep
        best_pool, best_radius = pool, radius
    return best_radius, best_pool or [], False, 0


def _summary_command(args: argparse.Namespace, specs: list[TaskSpec]) -> int:
    """Deterministic summary scaffold/validate (no LLM in the loop).

    scaffold writes the skeleton from the spec itself; validate runs the
    same gate `next` applies, per-spec, before the worker returns."""
    spec = next((s for s in specs if s.id == args.id), None)
    if spec is None:
        print(f"summary: spec id not found: {args.id}", file=sys.stderr)
        return 2
    summaries_dir = Path(args.summaries) if args.summaries else \
        Path(spec.evidence_dir).parent / "summaries"
    path = summaries_dir / f"{spec.id}.json"
    if args.summary_command == "scaffold":
        if path.is_file():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                existing = None
            if isinstance(existing, dict) \
                    and existing.get("status") in SUMMARY_STATUSES:
                print(f"summary: refusing to overwrite terminal summary {path}",
                      file=sys.stderr)
                return 2
        summaries_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(skeleton_summary(spec), indent=1,
                                   ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"skeleton: {path}")
        return 0
    # validate
    if not path.is_file():
        print(f"summary: no summary file: {path}", file=sys.stderr)
        return 2
    try:
        summary = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"summary: unreadable summary {path}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(summary, dict):
        print("summary must be a JSON object")
        return 2
    errors: list[str] = []
    if summary.get("phase") != spec.phase:
        errors.append(f"summary phase must be {spec.phase!r} "
                      f"(got {summary.get('phase')!r})")
    if summary.get("target") != spec.target:
        errors.append(f"summary target must be {spec.target!r}")
    if not is_skeleton_summary(summary):
        errors.extend(validate_summary(summary))
        if spec.phase == "enum" and not spec_expects_surface(spec):
            surface = set(surface_errors(summary))
            errors = [e for e in errors if e not in surface]
    if errors:
        for error in errors:
            print(f"summary invalid: {error}")
        return 2
    print(f"summary valid: {spec.id} status={summary.get('status')}")
    return 0


def _synthesize_command(args: argparse.Namespace) -> int:
    """Read-only ledger synthesis (brake-hatch; never writes, never nets)."""
    if args.kind not in SYNTHESIZE_KINDS:
        print(f"synthesize: unknown kind {args.kind} "
              "(want ledger-summary|coverage-count)", file=sys.stderr)
        return 2
    try:
        records = attempts_mod.read_records(
            attempts_mod.ledger_path(args.workdir))
    except ValueError as exc:
        print(f"synthesize: ledger unreadable: {exc}", file=sys.stderr)
        return 2
    if args.kind == "ledger-summary":
        verified, errors = attempts_mod.verify_records(records, path=attempts_mod.ledger_path(args.workdir))
        by_vector: dict[str, int] = {}
        by_verdict: dict[str, int] = {}
        for record in verified:
            by_vector[record["vector"]] = by_vector.get(
                record["vector"], 0) + 1
            by_verdict[record["verdict"]] = by_verdict.get(
                record["verdict"], 0) + 1
        print(json.dumps({"records": len(records), "trusted": len(verified),
                          "integrity_errors": len(errors),
                          "by_vector": by_vector, "by_verdict": by_verdict},
                         ensure_ascii=False))
    else:
        vectors = sorted({str(record.get("vector", "")) for record in records
                          if record.get("vector")})
        out = {}
        for vector in vectors:
            covered = attempts_mod.coverage(records, vector, [], path=attempts_mod.ledger_path(args.workdir))
            out[vector] = {"tried": covered["tried"],
                           "controls": covered["controls"],
                           "trusted_records": covered["trusted_records"]}
        print(json.dumps(out, ensure_ascii=False))
    return 0


def budget_warning(specs: list[TaskSpec], budget_seconds: int) -> str | None:
    """Warn before launch when the chain cannot fit the time budget."""
    estimate = chain_time_estimate_minutes(specs) * 60
    if estimate > budget_seconds:
        return (f"BUDGET-WARN: chain estimate {estimate}s exceeds time budget "
                f"{budget_seconds}s — extend policy or trim phases before launch")
    return None


def _race_status(ledger: dict | None) -> str | None:
    if ledger is None:
        return None
    for entry in ledger.get("hypotheses", []):
        if entry.get("vector") == RACE_VECTOR:
            return str(entry.get("status"))
    return None


def next_dispatch(specs: list[TaskSpec], summaries: dict[str, object],
                  ledger: dict | None, mtimes: dict[str, float] | None = None,
                  now: float | None = None,
                  race_allowed: bool = False,
                  summary_paths: dict[str, str] | None = None) -> tuple[TaskSpec | None, str]:
    """Chain dispatch with the access loop: while the ledger still has a
    claimable vector, access re-dispatches with the next claimed vector
    instead of advancing or stopping. A confirmed vector closes only
    itself; rotation continues past it until the ledger is exhausted."""
    dispatch, reason = next_spec(specs, summaries, mtimes, now, summary_paths)
    if ledger is None:
        return dispatch, reason
    access = next((s for s in specs if s.phase == "access"), None)
    if access is None:
        return dispatch, reason

    def _claim_filtered() -> dict | None:
        while True:
            claimed = ledger_mod.claim_next(ledger)
            if claimed is None or claimed["vector"] != RACE_VECTOR or race_allowed:
                return claimed
            ledger_mod.mark(ledger, RACE_VECTOR, "not_applicable",
                            note="not_tested: auth:not-required: race_burst "
                                 "not authorized in program policy")

    if dispatch is not None and dispatch.id == access.id:
        claimed = _claim_filtered()
        if claimed is None:
            # Ledger exhausted with no access summary on file (e.g. the
            # consumed/ archival pattern): treat access as done so the
            # chain advances instead of rendering a vectorless dispatch.
            virtual = dict(summaries)
            virtual[access.id] = {
                "phase": "access", "target": access.target, "status": "done",
                "evidence": [], "findings": [], "next": "",
            }
            return next_spec(specs, virtual, mtimes, now, summary_paths)
        access.vector = claimed["vector"]
        return apply_vector(access), ""
    if dispatch is not None and specs.index(dispatch) > specs.index(access):
        claimed = _claim_filtered()
        if claimed is not None:
            access.vector = claimed["vector"]
            return apply_vector(access), ""
    return dispatch, reason


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Thin brain planner")
    sub = parser.add_subparsers(dest="command", required=True)

    observed = sub.add_parser("operations", help="Plan exact observed P5 hypotheses, without traffic")
    observed.add_argument("--db", required=True)
    observed.add_argument("--target", required=True)
    observed.add_argument("--workdir", required=True)
    observed.add_argument("--context", default=None)

    plan = sub.add_parser("plan", help="Emit task specs for a target")
    plan.add_argument("--target", required=True)
    plan.add_argument("--workdir", required=True)
    plan.add_argument("--phases", default="")
    plan.add_argument("--kind", default="web", choices=sorted(KIND_PHASES))
    plan.add_argument("--tool-profile", choices=("core", "broker"), default=None)

    check = sub.add_parser("check", help="Validate a spec file")
    check.add_argument("--spec", required=True)
    check.add_argument("--workdir", default="",
                       help="Run workdir; when it holds hypotheses.json the race "
                            "gate closes unauthorized race vectors as not_tested")
    check.add_argument("--policy", default="",
                       help="Program policy JSON (default: .codex/program-policy.json)")
    check.add_argument("--closure", action="store_true",
                       help="Closure readiness: every hypothesis vector must be "
                            "terminal (not_applicable needs a justification note)")

    render = sub.add_parser("render", help="Render one spec as a worker prompt")
    render.add_argument("--spec", required=True)
    render.add_argument("--id", required=True)

    nxt = sub.add_parser("next", help="Render the next dispatchable spec")
    nxt.add_argument("--spec", required=True)
    nxt.add_argument("--summaries", required=True,
                     help="Dir holding <spec-id>.json worker summaries")
    nxt.add_argument("--workdir", default="",
                     help="Run workdir; when it holds hypotheses.json the access "
                          "phase loops over the ledger")
    nxt.add_argument("--policy", default="",
                     help="Program policy JSON (default: .codex/program-policy.json)")

    ing = sub.add_parser("ingest", help="Fold worker summaries into the ledger")
    ing.add_argument("--spec", required=True)
    ing.add_argument("--summaries", required=True)
    ing.add_argument("--workdir", required=True)
    ing.add_argument("--policy", default="",
                     help="Program policy JSON (default: .codex/program-policy.json)")

    hyp = sub.add_parser("hypotheses", help="Per-target vector ledger (rotation)")
    hyp_sub = hyp.add_subparsers(dest="hyp_command", required=True)
    hyp_queue = hyp_sub.add_parser("queue", help="Read observation-level hypotheses; sends no requests")
    hyp_queue.add_argument("--db", required=True)
    hyp_queue.add_argument("--target", required=True)
    hyp_queue.add_argument("--context", default=None)
    hyp_init = hyp_sub.add_parser("init")
    hyp_init.add_argument("--target", required=True)
    hyp_init.add_argument("--workdir", required=True)
    hyp_init.add_argument("--vectors", default="")
    hyp_init.add_argument("--max-attempts", type=int, default=2)
    hyp_next = hyp_sub.add_parser("next")
    hyp_next.add_argument("--workdir", required=True)
    hyp_mark = hyp_sub.add_parser("mark")
    hyp_mark.add_argument("--workdir", required=True)
    hyp_mark.add_argument("--vector", required=True)
    hyp_mark.add_argument("--status", required=True, choices=ledger_mod.STATUSES)
    hyp_mark.add_argument("--evidence", default="")
    hyp_mark.add_argument("--validation-id", default="",
                          help="Persisted CONFIRMED artifact required for --status confirmed")
    hyp_mark.add_argument("--note", default="")
    hyp_list = hyp_sub.add_parser("list")
    hyp_list.add_argument("--workdir", required=True)
    hyp_reorder = hyp_sub.add_parser("reorder")
    hyp_reorder.add_argument("--workdir", required=True)
    hyp_reorder.add_argument("--summary", required=True,
                             help="Enum summary JSON whose surface.routes/params reorders the ledger")
    hyp_pool = hyp_sub.add_parser("pool")
    hyp_pool.add_argument("--workdir", required=True)
    hyp_pool.add_argument("--summary", required=True,
                          help="Enum (or seed) summary JSON whose surface.routes seed the pool")
    hyp_pool.add_argument("--own-ids", default="",
                          help="Comma/space separated owned object ids from the seed summary")
    hyp_pool.add_argument("--docs-ids", default="",
                          help="Comma/space separated numbers observed in docs evidence")
    hyp_pool.add_argument("--radius", type=int, default=None,
                          help="Explicit window radius (omit for budget-fitted auto)")
    hyp_pool.add_argument("--budget-calls", type=int, default=25,
                          help="Worker call budget the pool must fit")

    att = sub.add_parser("attempts", help="Append-only probe log (blackboard)")
    att_sub = att.add_subparsers(dest="att_command", required=True)
    att_add = att_sub.add_parser("add")
    att_add.add_argument("--workdir", required=True)
    att_add.add_argument("--vector", required=True)
    att_add.add_argument("--endpoint", required=True)
    att_add.add_argument("--identity", required=True)
    att_add.add_argument("--verdict", required=True)
    att_add.add_argument("--candidate", type=_parse_id_arg, default=None)
    att_add.add_argument("--control", type=_parse_id_arg, default=None)
    att_add.add_argument("--status", type=int, default=None)
    att_add.add_argument("--size", type=int, default=None)
    att_add.add_argument("--artifact", default="")
    att_add.add_argument("--sha256", default="")
    att_add.add_argument("--note", default="")
    att_list = att_sub.add_parser("list")
    att_list.add_argument("--workdir", required=True)
    att_list.add_argument("--vector", default="")
    att_cov = att_sub.add_parser("coverage")
    att_cov.add_argument("--workdir", required=True)
    att_cov.add_argument("--vector", required=True)
    att_cov.add_argument("--expected", default="")

    off = sub.add_parser("handoff", help="Build the deterministic worker handoff packet")
    off.add_argument("--workdir", required=True)
    off.add_argument("--vector", required=True)
    off.add_argument("--max-chars", type=int, default=HANDOFF_DEFAULT_MAX_CHARS)

    st = sub.add_parser("state", help="Run state: identities and async jobs")
    st_sub = st.add_subparsers(dest="state_command", required=True)
    st_id = st_sub.add_parser("identity")
    st_id.add_argument("--workdir", required=True)
    st_id.add_argument("--name", required=True)
    st_id.add_argument("--pointer", required=True)
    st_job = st_sub.add_parser("job")
    st_job.add_argument("--workdir", required=True)
    st_job.add_argument("--kind", required=True)
    st_job.add_argument("--ref", required=True)
    st_reopen = st_sub.add_parser("job-reopen")
    st_reopen.add_argument("--workdir", required=True)
    st_reopen.add_argument("--ref", required=True)
    st_reopen.add_argument("--kind", default="")
    st_done = st_sub.add_parser("job-done")
    st_done.add_argument("--workdir", required=True)
    st_done.add_argument("--ref", required=True)
    st_done.add_argument("--status", default="done",
                         choices=("done", "failed", "expired"))

    rr = sub.add_parser("race-request", help="Record a race-burst approval request")
    rr.add_argument("--workdir", required=True)
    rr.add_argument("--reason", required=True)
    rr.add_argument("--evidence", required=True)

    clo = sub.add_parser("closure", help="Gate-signed closure artifact")
    clo_sub = clo.add_subparsers(dest="closure_command", required=True)
    clo_verify = clo_sub.add_parser("verify", help="Verify a gate-signed closure")
    clo_verify.add_argument("--workdir", required=True)

    ses = sub.add_parser("session", help="Target-session pointer health")
    ses_sub = ses.add_subparsers(dest="session_command", required=True)
    ses_status = ses_sub.add_parser("status", help="Report pointer health")
    ses_status.add_argument("--workdir", required=True)

    summ = sub.add_parser("summary",
                          help="Deterministic worker summary scaffold/validate")
    summ_sub = summ.add_subparsers(dest="summary_command", required=True)
    for _name in ("scaffold", "validate"):
        _p = summ_sub.add_parser(_name)
        _p.add_argument("--spec", required=True)
        _p.add_argument("--id", required=True)
        _p.add_argument("--summaries", default="",
                        help="Summaries dir (default: <run>/summaries from spec)")

    syn = sub.add_parser("synthesize",
                         help="Read-only ledger synthesis (brake hatch)")
    syn.add_argument("--workdir", required=True)
    syn.add_argument("--kind", required=True)

    cus = sub.add_parser("spec-customize",
                         help="Brain-authored spec extension (bounded)")
    cus.add_argument("--spec", required=True)
    cus.add_argument("--id", required=True)
    cus.add_argument("--add-commands-file", default="")
    cus.add_argument("--add-tools", default="")
    cus.add_argument("--tool-justification", default="")
    cus.add_argument("--bash-justification", default="")

    args = parser.parse_args(argv)

    if args.command == "hypotheses":
        return _hypotheses_command(args)
    if args.command == "attempts":
        return _attempts_command(args)
    if args.command == "handoff":
        return _handoff_command(args)
    if args.command == "state":
        return _state_command(args)
    if args.command == "race-request":
        return _race_request_command(args)
    if args.command == "closure":
        return _closure_command(args)
    if args.command == "session":
        return _session_command(args)
    if args.command == "synthesize":
        return _synthesize_command(args)
    if args.command == "spec-customize":
        return _customize_command(args)

    if args.command == "operations":
        print(dump_specs(observed_specs(args.db, args.target, args.workdir, args.context)))
        return 0

    if args.command == "plan":
        phases = tuple(p.strip() for p in args.phases.split(",") if p.strip()) or None
        if phases:
            unknown = [p for p in phases if p not in PHASE_TEMPLATES]
            if unknown:
                print(f"unknown phases: {unknown}", file=sys.stderr)
                return 2
        try:
            specs = build_plan(args.target, args.workdir, phases, kind=args.kind, tool_profile=args.tool_profile)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        chain_errors = validate_chain(specs)
        if chain_errors:
            print(f"invalid plan: {chain_errors}", file=sys.stderr)
            return 2
        print(dump_specs(specs))
        return 0

    try:
        specs = load_specs(Path(args.spec).read_text())
    except (OSError, TypeError, ValueError, AttributeError) as exc:
        print(json.dumps({'status': 'blocked', 'reason_code': 'schema_validation_failed',
                          'error_type': type(exc).__name__}), file=sys.stderr)
        return 2
    if args.command == "summary":
        return _summary_command(args, specs)
    if args.command == "check":
        bad = False
        for spec in specs:
            errors = validate_spec(spec)
            print(f"{spec.id or '?'}: {'OK' if not errors else errors}")
            bad = bad or bool(errors)
        chain_errors = validate_chain(specs)
        if chain_errors:
            print(f"chain: {chain_errors}")
            bad = True
        policy = _resolve_policy(args.policy)
        try:
            budget_seconds = int(policy.get("time_budget_max_seconds", 3600))
        except (TypeError, ValueError):
            budget_seconds = 3600
        warning = budget_warning(specs, budget_seconds)
        if warning:
            print(warning)
        closure_ctx = None
        if args.workdir and ledger_mod.ledger_path(args.workdir).is_file():
            try:
                ledger = ledger_mod.load_ledger(args.workdir)
            except (OSError, ValueError) as exc:
                print(f"race gate: unreadable ledger: {exc}")
                if args.closure:
                    bad = True
            else:
                has_race = any(entry.get("vector") == RACE_VECTOR
                               for entry in ledger.get("hypotheses", []))
                if has_race:
                    allowed, detail = race_launch_allowed(policy)
                    if allowed:
                        print(f"race gate: {RACE_VECTOR} authorized ({detail})")
                    else:
                        closed = close_race_not_tested(ledger, detail)
                        if closed is not None:
                            ledger_mod.save_ledger(args.workdir, ledger)
                            print(f"race gate: {RACE_VECTOR} closed as not_tested ({detail})")
                        else:
                            print(f"race gate: {RACE_VECTOR} not runnable ({detail})")
                try:
                    records = attempts_mod.read_records(
                        attempts_mod.ledger_path(args.workdir))
                except (OSError, ValueError) as exc:
                    print(f"coverage unavailable: {exc}")
                    bad = True
                    records = []
                known_vectors = set(ledger_mod.DEFAULT_VECTORS)
                integrity = attempts_mod.verify_records(records, path=attempts_mod.ledger_path(args.workdir))[1]
                if integrity:
                    print(f"coverage: invalid attempt ledger: {'; '.join(integrity)}")
                    bad = True
                try:
                    _confirmed_artifacts(ledger)
                except ValueError as exc:
                    print(f"confirmation: {exc}")
                    bad = True
                for odd in sorted({str(item.get("vector", "?")) for item in records
                                   if item.get("vector") not in known_vectors}):
                    print(f"vector-label: '{odd}' is not canonical "
                          f"(known: {','.join(ledger_mod.DEFAULT_VECTORS)}); "
                          "coverage maps only canonical vectors")
                try:
                    expected = [normalize_object_id(c) for c in _pool_candidates(args.workdir)]
                except ValueError as exc:
                    print(f"coverage: invalid object pool: {exc}")
                    expected = []
                    bad = True
                for entry in ledger.get("hypotheses", []):
                    vector = entry.get("vector")
                    if not vector:
                        continue
                    covered = attempts_mod.coverage(
                        records, vector,
                        expected if vector in POOL_VECTORS else [],
                        path=attempts_mod.ledger_path(args.workdir))
                    verified_records, _ = attempts_mod.verify_records(records, path=attempts_mod.ledger_path(args.workdir))
                    trusted_for_vector = sum(
                        1 for record in verified_records
                        if record.get("vector") == vector
                        and attempts_mod.is_probe_record(record))
                    suffix = (f" untried={covered['untried']}"
                              if vector in POOL_VECTORS else "")
                    print(f"coverage {vector}: tried={covered['tried']}{suffix} "
                          f"controls={covered['controls']}")
                    if entry.get("status") == "exhausted" and (
                            covered["integrity_errors"] or covered["untried"]
                            or trusted_for_vector == 0):
                        print(f"coverage {vector}: exhausted status is not "
                              "backed by the signed attempt ledger")
                        bad = True
                    if entry.get("status") == "exhausted" and vector in POOL_VECTORS:
                        if _pool_data(args.workdir).get("truncated"):
                            print(f"coverage {vector}: candidate pool was truncated; close blocked")
                            bad = True
                        tried_pool = ({object_id_key(item) for item in covered["tried"]}
                                      & {object_id_key(item) for item in expected})
                        if not expected or not tried_pool:
                            print(f"coverage {vector}: exhausted status on "
                                  "empty/untried pool (close blocked with "
                                  "empty-tenant evidence instead)")
                            bad = True
                race_probes = sum(
                    1 for record in attempts_mod.verify_records(records, path=attempts_mod.ledger_path(args.workdir))[0]
                    if record.get("vector") == RACE_VECTOR
                    and attempts_mod.is_probe_record(record))
                if race_probes:
                    request_path = Path(args.workdir) / "race-request.json"
                    if not request_path.is_file():
                        print("race gate: burst records without race-request.json "
                              "(request-before-burst required)")
                        bad = True
                    # Absolute ceiling: the program policy file is
                    # agent-visible, so it can only lower the burst cap,
                    # never raise it above the code default.
                    ceiling = min(race_burst_policy(policy)["max_items"],
                                  RACE_DEFAULT_MAX_ITEMS)
                    if race_probes > ceiling:
                        print(f"race gate: {race_probes} burst records exceed "
                              f"max_items={ceiling}")
                        bad = True
                if args.closure:
                    for entry in ledger.get("hypotheses", []):
                        vector = entry.get("vector", "?")
                        status = entry.get("status", "")
                        if status not in ledger_mod.TERMINAL:
                            print(f"closure: {vector} is not terminal ({status})")
                            bad = True
                        elif status == "not_applicable" and not str(
                                entry.get("note", "")).strip():
                            print(f"closure: {vector} not_applicable needs "
                                  "a justification note")
                            bad = True
                    recovered_vectors = {
                        str(item.get("vector", "")).strip()
                        for item in attempts_mod.verify_records(records, path=attempts_mod.ledger_path(args.workdir))[0]
                        if str(item.get("verdict", "")).strip().lower()
                        == "session-recovery"}
                    for entry in ledger.get("hypotheses", []):
                        if entry.get("status") != "not_applicable":
                            continue
                        vector = str(entry.get("vector", "?"))
                        att = _auth_attestation(
                            str(entry.get("note", "") or ""))
                        if att is None:
                            print(f"closure: {vector} not_applicable needs "
                                  "auth attestation (auth:recovered with a "
                                  "trusted session-recovery record, or "
                                  "auth:not-required:<why>)")
                            bad = True
                        elif att == "recovered" \
                                and vector not in recovered_vectors:
                            print(f"closure: {vector} claims auth:recovered "
                                  "without a trusted session-recovery record "
                                  "for this vector in the signed ledger "
                                  "(run brain.py session status)")
                            bad = True
                closure_ctx = (ledger, records, race_probes)
        elif args.closure:
            print("closure: no readable hypotheses ledger in workdir")
            bad = True
        if args.closure and not bad and closure_ctx is not None:
            ctx_ledger, ctx_records, ctx_probes = closure_ctx
            try:
                payload = build_closure_payload(args.workdir, ctx_ledger,
                                                ctx_records, ctx_probes)
            except ValueError as exc:
                print(f"closure: {exc}")
                return 2
            try:
                signed = attempts_mod.sign_payload(payload)
            except ValueError as exc:
                print(f"closure: host signing required ({exc}); use "
                      "kali-tools_ledger_checkpoint(workdir, seal=true)")
                return 2
            target = Path(args.workdir) / CLOSURE_FILENAME
            target.write_text(json.dumps(signed, ensure_ascii=False,
                                         indent=2) + "\n", encoding="utf-8")
            print(f"closure: gate-signed {target}")
        return 2 if bad else 0

    if args.command in ("next", "ingest"):
        summaries: dict[str, object] = {}
        mtimes: dict[str, float] = {}
        summary_paths: dict[str, str] = {}
        summaries_dir = Path(args.summaries)
        if summaries_dir.is_dir():
            for entry in sorted(summaries_dir.glob("*.json")):
                try:
                    summaries[entry.stem] = json.loads(entry.read_text())
                    mtimes[entry.stem] = entry.stat().st_mtime
                    summary_paths[entry.stem] = str(entry)
                except (OSError, ValueError) as exc:
                    print(f"STOP: unreadable summary {entry.name}: {exc}")
                    return 2
        ledger = None
        if args.workdir and ledger_mod.ledger_path(args.workdir).is_file():
            try:
                ledger = ledger_mod.load_ledger(args.workdir)
            except (OSError, ValueError) as exc:
                print(f"STOP: unreadable ledger: {exc}")
                return 2
        if ledger is not None:
            access = next((s for s in specs if s.phase == "access"), None)
            if access is not None and access.id in summaries:
                policy = _resolve_policy(getattr(args, "policy", ""))
                approval_ref = race_burst_policy(policy)["approval_ref"]
                access_summary = summaries[access.id]
                access_vector = access_summary.get("vector", "") \
                    if isinstance(access_summary, dict) else ""
                folded = ingest_access_summary(
                    ledger, access_summary,
                    pool_candidates=_pool_candidate_count(args.workdir) or None,
                    coverage_block=_ledger_coverage_block(args.workdir, access_vector))
                if folded is not None and folded.get("vector") == RACE_VECTOR \
                        and approval_ref:
                    marker = f"approval_ref={approval_ref}"
                    evidence = folded.setdefault("evidence", [])
                    if marker not in evidence:
                        evidence.append(marker)
                if folded is not None:
                    consumed = summaries_dir / "consumed"
                    consumed.mkdir(exist_ok=True)
                    src = summaries_dir / f"{access.id}.json"
                    if src.is_file():
                        src.replace(consumed / f"{access.id}-{folded['vector']}.json")
                    del summaries[access.id]
                    ledger_mod.save_ledger(args.workdir, ledger)
                    print(f"ingested: {folded['vector']} -> {folded['status']}",
                          file=sys.stderr)
            if args.command == "ingest":
                print(json.dumps(ledger_mod.ledger_summary(ledger)))
                return 0
        elif args.command == "ingest":
            print("STOP: no ledger in workdir", file=sys.stderr)
            return 2
        policy = _resolve_policy(args.policy)
        race_allowed, race_detail = race_launch_allowed(policy)
        race_before = _race_status(ledger)
        dispatch, reason = next_dispatch(specs, summaries, ledger, mtimes,
                                         race_allowed=race_allowed,
                                         summary_paths=summary_paths)
        if ledger is not None and args.workdir and _race_status(ledger) != race_before:
            ledger_mod.save_ledger(args.workdir, ledger)
        if dispatch is not None and (
                dispatch.phase == "authz"
                or (dispatch.phase == "access"
                    and dispatch.vector in POOL_VECTORS)):
            gate_error = _pool_gate_error(dispatch)
            if gate_error is not None:
                print(f"STOP: {gate_error}")
                return 2
            gate_error = _handoff_gate_error(dispatch)
            if gate_error is not None:
                print(f"STOP: {gate_error}")
                return 2
        if ledger is not None and dispatch is not None and dispatch.vector:
            ledger_mod.save_ledger(args.workdir, ledger)
        if dispatch is None:
            print(f"STOP: {reason}")
            return 2
        prompt = render_task_prompt(dispatch)
        if dispatch.vector == RACE_VECTOR and race_allowed:
            prompt += (f"\nRace authorization: {race_detail} "
                       "(record approval_ref in the summary evidence)")
        print(prompt)
        return 0

    for spec in specs:
        if spec.id == args.id:
            print(render_task_prompt(spec))
            return 0
    print(f"spec id not found: {args.id}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
