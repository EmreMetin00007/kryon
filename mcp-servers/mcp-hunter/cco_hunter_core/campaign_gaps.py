"""Encrypted observed requests bridge coverage dimensions to campaign tasks.

Planning never sends traffic. Only recently observed GET query/path requests
and explicit two-account ownership probes are executable; missing context is
kept untested. The existing Hunter wire gate and campaign lease own execution.
"""
from __future__ import annotations

import copy
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from urllib.parse import parse_qsl, unquote

from .gap_queue import _target_key, gap_plan, list_gaps
from .loop import AUTO_VALIDATE, _origin

_REF = re.compile(r"[a-f0-9]{64}\Z")
_SCHEMA = """CREATE TABLE IF NOT EXISTS hunter_gap_requests (
    fingerprint TEXT PRIMARY KEY, secret_ref TEXT NOT NULL,
    campaign_id INTEGER, task_id INTEGER)"""
_CURSOR_SCHEMA = """CREATE TABLE IF NOT EXISTS hunter_gap_schedule_cursors (
    target TEXT NOT NULL, context_key TEXT NOT NULL, run_id TEXT NOT NULL,
    last_id INTEGER NOT NULL, PRIMARY KEY (target, context_key, run_id))"""
_ITEM_KEYS = {"url", "method", "vuln_class", "param", "location", "carrier", "identity", "operation_id", "observation_id",
              "resource_owner", "run_id", "authz_candidate", "owned_object", "owner_identity",
              "attacker_identity", "owner_marker", "owner_role", "attacker_role",
              "test_resource", "protected_marker", "access_rule_hash", "resource_key", "resource_family", "state_key", "variant_key"}
_AUTHZ = {"idor", "bola", "bfla", "authentication_bypass"}
_DECLARED = {"bfla", "authentication_bypass"}
_TTL = 3600


def versions():
    path = str(Path(__file__).resolve().parents[2] / "mcp-validator")
    if path not in sys.path:
        sys.path.insert(0, path)
    from cco_validator_core.evidence import current_policy_hash, current_scope_revision
    from target_identity import finding_context_key
    revision = current_scope_revision()
    return finding_context_key(revision), revision, current_policy_hash()


def _vault(home, *, create=False):
    path = str(Path(__file__).resolve().parents[2] / "mcp-memory-server")
    if path not in sys.path:
        sys.path.insert(0, path)
    from credential_vault import CredentialVault
    return CredentialVault(str(home), create_key=create)


def _eligible(item):
    if not isinstance(item, dict) or str(item.get("method") or "GET").upper() != "GET":
        return False
    url = str(item.get("url") or "")
    if not _origin(url)[0] or any(c in url for c in "\r\n\x00") or "<redacted>" in unquote(url):
        return False
    kind = item.get("vuln_class")
    if kind in _DECLARED:
        if not item.get("test_resource"):
            return item.get("authz_candidate") is True and not item.get("owned_object")
        return bool(item.get("owner_marker") and item.get("owner_identity") and item.get("attacker_identity")
                    and item["owner_identity"] != item["attacker_identity"]
                    and _REF.fullmatch(str(item.get("access_rule_hash") or ""))
                    and (kind != "authentication_bypass" or item["attacker_identity"] == "anonymous"))
    if kind in _AUTHZ:
        return bool(item.get("owned_object") and item.get("owner_marker")
                    and item.get("owner_identity") and item.get("attacker_identity")
                    and item["owner_identity"] != item["attacker_identity"])
    carrier = item.get("location") or item.get("carrier") or "query"
    if kind not in AUTO_VALIDATE or kind in {"deserialization", "opaque_token", "xxe"}:
        return False
    if item.get("identity") in (None, "", "unspecified") or not item.get("param"):
        return False
    if carrier == "query":
        return sum(name == item["param"] for name, _ in parse_qsl(url.split("?", 1)[-1],
                                                                  keep_blank_values=True)) == 1
    return carrier == "path" and url.count("{" + str(item["param"]) + "}") == 1


def remember_request(db_path, home, target, gap, item, request_context=None):
    """Save only executable observed context; never persist raw values in plans."""
    if not _eligible(item) or _origin(target) != _origin(item["url"]):
        return False
    if request_context and (request_context.get("baseline_json") is not None
                            or request_context.get("baseline_data") is not None):
        return False
    context, revision, policy = versions()
    fingerprint, _ = gap_plan(target, gap, context)
    packet = {"schema": "hunter-gap-request/1", "fingerprint": fingerprint,
              "target": _target_key(target), "context_key": context,
              "scope_revision": revision, "policy_hash": policy, "created_at": int(time.time()),
              "gap": copy.deepcopy(gap),
              "item": {key: copy.deepcopy(value) for key, value in item.items() if key in _ITEM_KEYS},
              "request_context": copy.deepcopy(request_context)}
    if packet["request_context"]:
        # Session credentials come only from a fresh account attestation at execution.
        packet["request_context"]["baseline_headers"] = {
            k: v for k, v in (packet["request_context"].get("baseline_headers") or {}).items()
            if not re.search(r"auth|cookie|token|session|credential|api[-_]?key|csrf|xsrf|secret|password", k, re.I)}
    with sqlite3.connect(db_path, timeout=10) as conn:
        conn.execute(_SCHEMA)
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT 1 FROM hunter_gap_requests WHERE fingerprint=?", (fingerprint,)).fetchone():
            return True  # Do not overwrite a request already bound to a task.
        vault = _vault(home, create=True)
        ref = vault.store_secret("hunter_gap_request", json.dumps(packet, ensure_ascii=False, allow_nan=False))
        try:
            conn.execute("INSERT INTO hunter_gap_requests (fingerprint, secret_ref) VALUES (?, ?)",
                         (fingerprint, ref))
            conn.commit()
        except Exception:
            vault.delete_secret(ref)
            raise
    return True


def load_request(db_path, home, target, fingerprint):
    if not isinstance(fingerprint, str) or not _REF.fullmatch(fingerprint):
        raise ValueError("invalid gap reference")
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            row = conn.execute("SELECT secret_ref FROM hunter_gap_requests WHERE fingerprint=?",
                               (fingerprint,)).fetchone()
        packet = json.loads(_vault(home).get_secret(row[0])) if row else None
        context, revision, policy = versions()
        if (not isinstance(packet, dict) or packet.get("schema") != "hunter-gap-request/1"
                or packet.get("fingerprint") != fingerprint or packet.get("target") != _target_key(target)
                or packet.get("context_key") != context or packet.get("scope_revision") != revision
                or packet.get("policy_hash") != policy
                or not 0 <= time.time() - packet["created_at"] <= _TTL
                or gap_plan(target, packet["gap"], context)[0] != fingerprint
                or not _eligible(packet["item"]) or _origin(target) != _origin(packet["item"]["url"])):
            raise ValueError("stale or mismatched request context")
        return packet
    except Exception as exc:
        raise ValueError("request context missing, expired or mismatched") from exc


def _sessions():
    path = str(Path(__file__).resolve().parents[2] / "mcp-memory-server")
    if path not in sys.path:
        sys.path.insert(0, path)
    from cco_surface_core import session_store
    return session_store


def capture_checks(home, bindings):
    """Capture account versions before execution, including missing/expired ones."""
    parsed = json.loads(bindings) if bindings else {}
    store = _sessions()
    return {label: store.check_fingerprint(spec["target"], label, home=str(home))
            for label, spec in parsed.items()}


def verified_checks(home, bindings):
    parsed = json.loads(bindings) if bindings else {}
    store = _sessions()
    checks, expected = {}, []
    for label, spec in parsed.items():
        entry = store.verified_session(spec["target"], label, home=str(home))
        if not entry:
            raise ValueError("session unavailable or not recently verified")
        checks[label] = store.check_fingerprint(spec["target"], label, home=str(home), entry=entry)
        expected.append((spec["target"], label, entry))
    return checks, expected


def checks_unchanged(home, expected):
    store = _sessions()
    return all(store.same_verified_session(target, label, entry, home=str(home))
               for target, label, entry in expected)


def request_headers(item, common, entries):
    """Build ephemeral wire headers from the exact observed identity."""
    actor = item.get("identity")
    anonymous_control = (actor == "anonymous" and item.get("test_resource")
                         and item.get("vuln_class") == "authentication_bypass")
    source = item.get("owner_identity") if anonymous_control else actor
    entry = entries.get(source) or {}
    specific = entry.get("headers") or {}
    headers = {k: v for k, v in common.items()
               if not any(k.lower() == s.lower() for s in specific)}
    headers.update(specific)
    if anonymous_control:
        secret = re.compile(r"authorization|cookie|token|secret|session|password|api[-_]?key|^x[-_]auth$", re.I)
        return {k: v for k, v in headers.items() if not secret.search(k)}
    if entry.get("cookies"):
        headers = {k: v for k, v in headers.items() if k.lower() != "cookie"}
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in entry["cookies"].items())
    return headers


def lifecycle_request_headers(home, args):
    """Read header metadata without requiring a fresh execution attestation.

    Expired sessions must still be claimable to produce a resumable block
    receipt. Admission and the validator retain their fresh-session checks.
    """
    packet = load_request(str(Path(home) / "agent_memory.db"), home, args["target"], args["gap_ref"])
    store = _sessions()
    bindings = json.loads(args.get("session_bindings") or "{}")
    entries = {label: store.get_session(spec["target"], label, home=str(home))
               for label, spec in bindings.items()}
    return request_headers(packet["item"], json.loads(args.get("headers") or "{}"), entries)


def plan_observed_requests(db_path, home, target, scope, *, run_id="", limit=100):
    """Restore source dimensions only from signed plans and matching snapshots."""
    _sessions()
    context = versions()[0]
    from .coverage_store import read_events
    from .gap_queue import plan_gaps
    from cco_surface_core.normalize import canonical_target
    from cco_validator_core.evidence import artifact_is_current, load_validation, trust

    events = read_events(db_path, canonical_target(target), trust)
    if not events:
        return [], []
    with sqlite3.connect(db_path, timeout=10) as conn:
        existing = {row[0] for row in conn.execute("SELECT fingerprint FROM hunter_gap_queue")} if conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='hunter_gap_queue'").fetchone() else set()
    completed = {gap_plan(target, {**event, "endpoint": event["url"]}, context)[0]: event
                 for event in events if event.get("schema") == "hunter-coverage/1"
                 and event.get("status") in {"confirmed", "tested_clean"}}
    gaps = []
    for event in events:
        if (event.get("schema") != "hunter-coverage-plan/1" or event.get("status") != "not_tested"
                or (run_id and event.get("run_id") != run_id)):
            continue
        fingerprint, _ = gap_plan(target, {**event, "endpoint": event["url"]}, context)
        if fingerprint in existing:
            continue
        try:
            packet = load_request(db_path, home, target, fingerprint)
        except ValueError:
            continue  # A signed advisory plan without its exact request stays untested.
        terminal = completed.get(fingerprint)
        if terminal:
            record = load_validation(terminal.get("validation_id") or "")
            execution_context = {key: event[key] for key in (
                "url", "vuln_class", "method", "param", "carrier", "identity", "resource_owner", "run_id",
                "operation_id", "observation_id", "access_rule_hash", "resource_key", "resource_family", "state_key", "variant_key") if key in event}
            if (record and record.get("execution_context") == execution_context
                    and (record.get("guard") or {}).get("transport_ok")
                    and {"CONFIRMED": "confirmed", "UNCONFIRMED": "tested_clean"}.get(record.get("verdict"))
                    == terminal["status"]
                    and (record.get("artifact") or {}).get("content_sha256") == terminal.get("artifact_sha256")
                    and artifact_is_current(record, expected_target=event["url"],
                                            expected_path=terminal.get("artifact_path") or "")):
                continue
        gaps.append(packet["gap"])
        existing.add(fingerprint)
        if len(gaps) >= max(1, min(int(limit), 100)):
            break
    return plan_gaps(db_path, target, gaps, scope, context, limit=limit)


def admit_request(runtime, campaign, args):
    """One admission contract for first scheduling and verified session resume."""
    from campaign_runtime import _validate_hunter_queue_args
    from policy_engine import ScopeResolver

    _validate_hunter_queue_args(args)
    engine = runtime._policy_engine(campaign.get("scope_file") or None)
    active_scope = ScopeResolver()._engine.scope_file
    if ((engine.scope_file.resolve() if engine.scope_file else None)
            != (active_scope.resolve() if active_scope else None)):
        raise ValueError("campaign must use the active scope")
    packet = load_request(str(runtime.cco_home / "agent_memory.db"), runtime.cco_home,
                          args["target"], args["gap_ref"])
    item = packet["item"]
    scope = ScopeResolver(scope_file=engine.scope_file)
    if not scope.permits_url(item["url"]):
        raise ValueError("blocked_scope")
    bindings = json.loads(args.get("session_bindings") or "{}")
    checks, expected = verified_checks(runtime.cco_home, args.get("session_bindings") or "")
    entries = {label: entry for _, label, entry in expected}
    if item["vuln_class"] in _DECLARED and not item.get("test_resource"):
        raise ValueError("declared test resource unavailable or changed")
    needed = ({item["owner_identity"], item["attacker_identity"]}
              if item.get("owned_object") or item.get("test_resource") else {item.get("identity")})
    if needed - {"anonymous"} - set(entries):
        raise ValueError("session unavailable for planned identity")
    for actor, entry in entries.items():
        spec = bindings[actor]
        if not scope.permits_url(entry.get("check_url") or ""):
            raise ValueError("blocked_scope")
        if item.get("owned_object") and actor in needed:
            role_field = "owner_role" if actor == item["owner_identity"] else "attacker_role"
            if (spec.get("owned_objects_private") is not True
                    or (spec.get("role") or "member") != item.get(role_field)):
                raise ValueError("session unavailable or ownership context mismatched")
    if item.get("test_resource"):
        from .access_context import require_declared_access, session_identity
        actors = {label: session_identity(entry, bindings[label], scope) for label, entry in entries.items()}
        require_declared_access(item, actors)
        if item.get("identity") != item["attacker_identity"] or item.get("resource_owner") != item["owner_identity"]:
            raise ValueError("declared test resource unavailable or changed")
    if item.get("owned_object"):
        rule = engine.program_policy.get("blind_discovery") or {}
        if rule.get("synthetic_accounts_only") is not True or rule.get("owned_objects_private") is not True:
            raise ValueError("blocked_blind_discovery_policy")
    wire_headers = request_headers(item, json.loads(args.get("headers") or "{}"), entries)
    decision = engine.validate_wire_invocation("hunter_run_web_loop", {
        "target": item["url"], "url": item["url"], "method": item["method"], "headers": wire_headers})
    if not decision.get("allowed"):
        raise ValueError(str(decision.get("reason") or "blocked_policy"))
    load_request(str(runtime.cco_home / "agent_memory.db"), runtime.cco_home, args["target"], args["gap_ref"])
    if not checks_unchanged(runtime.cco_home, expected):
        raise ValueError("session changed during admission")
    return packet, checks, expected


def bind_observed_candidate(runtime, target, fingerprint, session_bindings, scope, limit):
    """Repair only a saved observed candidate; metadata planning sends no traffic."""
    from .access_context import bind_declared_access, session_identity
    from .coverage_store import read_events, append_event
    from .gap_queue import plan_gaps
    from cco_surface_core.normalize import canonical_target
    from cco_validator_core.evidence import trust

    db_path = str(runtime.cco_home / "agent_memory.db")
    packet = load_request(db_path, runtime.cco_home, target, fingerprint)
    item = packet["item"]
    if item["vuln_class"] not in _DECLARED or item.get("test_resource"):
        return None
    context = versions()[0]
    observed = read_events(db_path, canonical_target(target), trust)
    if not any(event.get("schema") == "hunter-access-candidate/1"
               and event.get("status") == "not_tested"
               and gap_plan(target, {**event, "endpoint": event["url"]}, context)[0] == fingerprint
               for event in observed):
        raise ValueError("observed access candidate unavailable")
    if not scope.permits_url(item["url"]):
        raise ValueError("blocked_scope")
    bindings = json.loads(session_bindings or "{}")
    _, expected = verified_checks(runtime.cco_home, session_bindings)
    actors = {label: session_identity(entry, bindings[label], scope) for _, label, entry in expected}
    bound = bind_declared_access(item, actors, lambda left, right: left == right)
    if not bound or not checks_unchanged(runtime.cco_home, expected):
        raise ValueError("declared test resource unavailable or changed")
    # Do not partially bind a source and silently lose the other role dimensions.
    if len(bound) > limit:
        raise ValueError("candidate binding limit exceeded")
    plans = []
    for row in bound:
        row.update(identity=row["attacker_identity"], resource_owner=row["owner_identity"])
        gap = {**packet["gap"], "endpoint": row["url"], "identity": row["identity"],
               "resource_owner": row["resource_owner"], "access_rule_hash": row["access_rule_hash"]}
        if not remember_request(db_path, runtime.cco_home, target, gap, row, packet.get("request_context")):
            raise ValueError("request context unavailable")
        planned, _ = plan_gaps(db_path, target, [gap], scope, versions()[0])
        event = {"schema": "hunter-coverage-plan/1", "target": canonical_target(target),
                 **{k: v for k, v in gap.items() if k != "endpoint"},
                 "url": gap["endpoint"], "status": "not_tested"}
        append_event(db_path, event, trust)
        plans.extend(planned)
    # Both a new observation and a new run retain independent source records.
    with sqlite3.connect(db_path, timeout=10) as conn:
        conn.execute("UPDATE hunter_gap_queue SET status='bound' WHERE fingerprint=? AND status='needs_scheduling'",
                     (fingerprint,))
    from .feedback import record_access_binding
    record_access_binding(db_path, target, packet["gap"], [p["fingerprint"] for p in plans])
    return plans


def schedule_gaps(runtime, campaign_id, target, *, session_bindings="", headers="", request_cost=12, limit=15,
                  run_id="", max_attempts=3):
    """Turn admitted dimensions into bounded tasks, under a scheduler lock."""
    from campaign_runtime import _validate_hunter_queue_args
    from policy_engine import ScopeResolver

    if isinstance(request_cost, bool) or not isinstance(request_cost, int) or request_cost < 1:
        raise ValueError("positive request reservation required")
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= 3:
        raise ValueError("coverage tasks permit one to three attempts")
    # Validate the exact public task shape before opening any queue transaction.
    base_args = {"target": target, "live": True, "gap_ref": "0" * 64,
                 "crawl": False, "zap": False, "session_bindings": session_bindings, "headers": headers}
    _validate_hunter_queue_args(base_args)
    context, _, _ = versions()
    db_path = str(runtime.cco_home / "agent_memory.db")
    scheduled, deferred, rebound = [], [], []
    fd = os.open(runtime.cco_home / "coverage-scheduler.lock",
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        campaign = runtime.show_campaign(campaign_id)
        if not campaign or campaign["status"] != "active":
            raise ValueError("active campaign required")
        engine = runtime._policy_engine(campaign.get("scope_file") or None)
        active_scope = ScopeResolver()._engine.scope_file
        if ((engine.scope_file.resolve() if engine.scope_file else None)
                != (active_scope.resolve() if active_scope else None)):
            raise ValueError("campaign must use the active scope")
        tasks = runtime.list_tasks(campaign_id)
        existing = {task["idempotency_key"]: task for task in tasks}
        committed = campaign["requests_used"] + campaign["requests_reserved"] + sum(
            task["request_cost"] for task in tasks
            if task["status"] in {"pending", "waiting_approval", "rate_limited"})
        bound_limit = max(1, min(int(limit), 100))
        scope = ScopeResolver(scope_file=engine.scope_file)
        runtime._plan_observed_coverage_gaps(target, scope, run_id=run_id, limit=bound_limit)
        cursor_key = (_target_key(target), context, run_id)
        with sqlite3.connect(db_path, timeout=10) as conn:
            conn.execute(_CURSOR_SCHEMA)
            cursor = conn.execute("SELECT last_id FROM hunter_gap_schedule_cursors "
                                  "WHERE target=? AND context_key=? AND run_id=?", cursor_key).fetchone()
        pending = list_gaps(db_path, target, context, limit=min(100, 2 * bound_limit),
                            status="needs_scheduling", run_id=run_id, after_id=cursor[0] if cursor else 0)
        from cco_surface_core.hypotheses import priority
        pending.sort(key=lambda row: priority({**row, "status": "ready"}))
        processed = set()
        for plan in pending:
            if len(processed) >= 2 * bound_limit or len(scheduled) >= bound_limit:
                break
            fingerprint = plan["fingerprint"]
            if plan["status"] != "needs_scheduling" or fingerprint in processed:
                continue
            processed.add(fingerprint)
            key = "coverage-gap-" + fingerprint
            with sqlite3.connect(db_path, timeout=10) as conn:
                conn.execute(_SCHEMA)
                row = conn.execute("SELECT id FROM hunter_gap_queue WHERE fingerprint=?", (fingerprint,)).fetchone()
                if row:
                    conn.execute("INSERT INTO hunter_gap_schedule_cursors (target, context_key, run_id, last_id) "
                                 "VALUES (?, ?, ?, ?) ON CONFLICT(target, context_key, run_id) "
                                 "DO UPDATE SET last_id=excluded.last_id", (*cursor_key, row[0]))
                link = conn.execute("SELECT campaign_id, task_id FROM hunter_gap_requests WHERE fingerprint=?",
                                    (fingerprint,)).fetchone()
            if link and link[1] is not None:
                continue
            # Recover a crash between the canonical task insert and its link.
            if key in existing:
                task_id = existing[key]["id"]
            else:
                try:
                    bound = bind_observed_candidate(runtime, target, fingerprint, session_bindings,
                                                    scope, bound_limit)
                    if bound is not None:
                        rebound.append({"source_ref": fingerprint, "bound_refs": [p["fingerprint"] for p in bound]})
                        pending.extend(bound)
                        continue
                    args = {**base_args, "gap_ref": fingerprint}
                    if campaign["budget_requests"] and committed + request_cost > campaign["budget_requests"]:
                        raise ValueError("campaign request budget exhausted")
                    admit_request(runtime, campaign, args)
                    # A policy edit during admission invalidates the encrypted snapshot.
                    load_request(db_path, runtime.cco_home, target, fingerprint)
                    task_id = runtime.enqueue_task(campaign_id, "web", "hunter_run_web_loop", args,
                                                   request_cost=request_cost, max_attempts=max_attempts, idempotency_key=key)
                    committed += request_cost
                except (ValueError, KeyError, TypeError) as exc:
                    # Exceptions here are fixed prerequisite codes, never response bodies.
                    if "budget" in str(exc):
                        hypothesis_task_state(runtime, args, "blocked", reason="budget_exhausted")
                    deferred.append({"fingerprint": fingerprint, "reason": prerequisite_reason(exc)})
                    continue
            with sqlite3.connect(db_path, timeout=10) as conn:
                conn.execute("UPDATE hunter_gap_requests SET campaign_id=?, task_id=? WHERE fingerprint=? AND task_id IS NULL",
                             (campaign_id, task_id, fingerprint))
                conn.execute("UPDATE hunter_gap_queue SET status='scheduled' WHERE fingerprint=?", (fingerprint,))
            scheduled.append({"fingerprint": fingerprint, "task_id": task_id, "status": "scheduled"})
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    return {"scheduled": scheduled, "deferred": deferred, "rebound": rebound, "requests_sent": 0}


def prerequisite_reason(exc):
    text = str(exc)
    known = {"request context missing, expired or mismatched", "blocked_scope",
             "session unavailable or not recently verified", "explicit private synthetic objects required",
             "blocked_blind_discovery_policy", "campaign request budget exhausted",
             "session unavailable for planned identity", "session unavailable or ownership context mismatched",
             "blocked policy: synthetic ownership authorization required",
             "request context cannot contain raw identity headers", "attempt limit exhausted",
             "verified session block record unavailable", "active campaign required",
             "coverage dimension already complete", "task dependency unavailable",
             "session changed during admission", "new session verification required for each bound account"}
    known.update({"declared test resource unavailable or changed", "candidate binding limit exceeded",
                  "observed access candidate unavailable"})
    return text if text in known or re.fullmatch(r"blocked_[a-z_]+", text) else "request context unavailable"


def finish_dimension(db_path, target, gap, status):
    """Only the caller's verified observation may complete a dimension."""
    if status not in {"confirmed", "tested_clean"}:
        return
    context, _, _ = versions()
    fingerprint, _ = gap_plan(target, gap, context)
    with sqlite3.connect(db_path, timeout=10) as conn:
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='hunter_gap_queue'").fetchone():
            conn.execute("UPDATE hunter_gap_queue SET status=? WHERE fingerprint=?", (status, fingerprint))


def hypothesis_task_state(runtime, args, state, *, checks=None, previous_checks=None, reason=''):
    """Project an already-admitted task's lifecycle; never claim or authorize work."""
    from cco_surface_core import hypotheses
    from cco_surface_core.normalize import canonical_target
    from .feedback import feedback_context
    try:
        if not args.get('gap_ref'):
            return
        path = str(runtime.cco_home / 'agent_memory.db')
        packet = load_request(path, runtime.cco_home, args['target'], args['gap_ref'])
        item = {**packet['item'], 'url': packet['gap']['endpoint']}
        target, context = canonical_target(args['target']), feedback_context()
        with sqlite3.connect(path, timeout=10) as conn:
            key = hypotheses.observe(conn, target, item, context)
            if previous_checks is not None:
                for actor, version in previous_checks.items():
                    if actor in (checks or {}):
                        hypotheses.resolve(conn, target, context, kind='session', subject=actor,
                                           previous_version=version, new_version=checks[actor])
            blockers = [{'kind': 'session', 'subject': actor, 'version': version}
                        for actor, version in (checks or {}).items()] if state == 'blocked' else []
            hypotheses.transition(conn, key, state, reason='session_unavailable' if blockers else reason, blockers=blockers)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        return  # Advisory state cannot invalidate an authoritative lease transaction.


def task_references(runtime, args):
    """Use the same exact dimension as hypothesis_task_state, not the gap key."""
    from cco_surface_core import hypotheses
    from .feedback import feedback_context
    from agent_integration import references
    packet = load_request(str(runtime.cco_home / 'agent_memory.db'), runtime.cco_home,
                          args['target'], args['gap_ref'])
    key, dimension = hypotheses.dimension(args['target'],
        {**packet['item'], 'url': packet['gap']['endpoint']}, feedback_context())
    return references({'fingerprint': key, 'dimension': dimension})
