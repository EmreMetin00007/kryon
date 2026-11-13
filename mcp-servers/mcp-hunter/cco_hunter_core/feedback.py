"""Non-executable feedback plans, separate from signed coverage and task leases."""
from __future__ import annotations

import json
import hashlib
import sqlite3
from pathlib import Path

from .gap_queue import _label, _redact_url, _target_key, gap_plan, _target_origin

_SCHEMA = """CREATE TABLE IF NOT EXISTS hunter_feedback_queue (
    fingerprint TEXT PRIMARY KEY, context_key TEXT NOT NULL, target TEXT NOT NULL,
    plan_json TEXT NOT NULL, status TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS hunter_feedback_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL,
    status TEXT NOT NULL, reason_code TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP);"""


def feedback_context():
    from .campaign_gaps import versions
    return hashlib.sha256(json.dumps(versions(), separators=(",", ":")).encode()).hexdigest()


def record_access_binding(db_path, target, source_gap, bound_refs):
    """Explain a repaired advisory source; only validators may close its children."""
    ref, _ = gap_plan(target, source_gap, feedback_context())
    with sqlite3.connect(db_path, timeout=10) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='hunter_feedback_queue'").fetchone():
            return
        previous = conn.execute("SELECT plan_json,status FROM hunter_feedback_queue WHERE fingerprint=?", (ref,)).fetchone()
        if not previous or previous[1] in {"confirmed", "tested_no_violation"}:
            return
        plan = {**json.loads(previous[0]), "status": "proposed", "reason_code": "access_context_bound",
                "next_action": "schedule_bounded_validation", "bound_refs": bound_refs,
                "preconditions": ["fresh_scope_and_grant", "campaign_budget"], "automatic_retry": False}
        raw = json.dumps(plan, sort_keys=True, ensure_ascii=False)
        if raw != previous[0]:
            conn.execute("UPDATE hunter_feedback_queue SET status='proposed',plan_json=?,updated_at=CURRENT_TIMESTAMP "
                         "WHERE fingerprint=?", (raw, ref))
            conn.execute("INSERT INTO hunter_feedback_events(fingerprint,status,reason_code) VALUES (?,?,?)",
                         (ref, "proposed", "access_context_bound"))


def list_feedback(db_path, target, context_key, run_id="", limit=100):
    """Read advisory states only; this is not a coverage or finding verifier."""
    if not Path(db_path).is_file():
        return []
    try:
        with sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True) as conn:
            query = "SELECT fingerprint,plan_json FROM hunter_feedback_queue WHERE target=? AND context_key=?"
            args = [_target_key(target), context_key]
            if run_id:
                query += " AND json_extract(plan_json,'$.run_id')=?"
                args.append(run_id)
            rows = conn.execute(query + " ORDER BY updated_at DESC LIMIT ?", [*args, max(1, min(int(limit), 100))])
            return [{"fingerprint": ref, **json.loads(raw)} for ref, raw in rows]
    except (sqlite3.Error, ValueError, TypeError):
        return []


def verified_feedback(plans, target, context_key, events, normalize=lambda url: url):
    """Recheck cached terminal states against current trusted artifacts."""
    trusted = {}
    for event in events:
        if isinstance(event, dict) and event.get("status") in {"confirmed", "tested_clean"}:
            gap = {**event, "endpoint": normalize(event.get("url") or "")}
            trusted[gap_plan(target, gap, context_key)[0]] = event
    out = []
    for plan in plans:
        if plan.get("status") in {"confirmed", "tested_no_violation"}:
            event = trusted.get(plan["fingerprint"]) or {}
            expected = "confirmed" if plan["status"] == "confirmed" else "tested_clean"
            if event.get("status") != expected or event.get("validation_id") != plan.get("validation_id"):
                plan = {**plan, "status": "inconclusive", "reason_code": "evidence_unavailable",
                        "next_action": "review_probe_controls"}
        out.append(plan)
    return out


def _dimension(row, normalize):
    from cco_surface_core.hypotheses import extensions
    row = {**row, **extensions(row)}
    url = normalize(row.get("url") or "")
    return (url, str(row.get("method") or "GET").upper(),
            "path_traversal" if row.get("vuln_class") == "lfi" else row.get("vuln_class"),
            str(row.get("param") or ""), row.get("carrier") or row.get("location") or "query",
            row.get("identity") or "unspecified", row.get("resource_owner") or "unspecified",
            row.get("run_id") or "unspecified", row.get("operation_id") or "",
            str(row.get("observation_id") or ""), str(row.get("access_rule_hash") or ""),
            *(row.get(k) or "" for k in ("resource_key", "resource_family", "state_key", "variant_key")))


def reason_action(reason):
    """Map untrusted diagnostic text to a fixed action; never persist that text."""
    text = str(reason or "").lower().replace("_", " ")
    for words, code, action in (
        (("max validations", "budget"), "budget_exhausted", "review_budget"),
        (("429", "rate limit", "rate limited"), "rate_limited", "wait_and_reassess"),
        (("session", "401", "login redirect"), "session_unavailable", "restore_test_session"),
        (("access context", "test identities", "owned object", "roles", "test resource"),
         "missing_access_context", "bind_declared_test_resource"),
        (("schema", "required", "field unavailable", "graphql", "error envelope", "request context"),
         "invalid_request_context", "repair_request_context"),
        (("policy", "outside", "grant"), "policy_blocked", "review_scope_and_grant"),
        (("transport", "timeout", "connection"), "transport_unavailable", "inspect_transport"),
        (("waf",), "waf_blocked", "review_probe_controls"),
    ):
        if any(word in text for word in words):
            return code, action
    return "validator_inconclusive", "review_probe_controls"


def build_feedback(report, verified_events=(), normalize=lambda url: url):
    """Terminal states require the caller's verified, matching coverage events.

    The public report's verdict/coverage_recorded fields alone cannot close a
    hypothesis. Budgets and missing prerequisites generate repair plans only.
    """
    cells = {}

    def put(row, status, code, action, prerequisites=()):
        if not isinstance(row, dict) or not row.get("url") or not row.get("vuln_class"):
            return
        row = {"run_id": report.get("run_id") or "unspecified", **row}
        key = _dimension(row, normalize)
        cells[key] = {"url": key[0], "method": key[1], "vuln_class": key[2], "param": key[3],
                      "carrier": key[4], "identity": key[5], "resource_owner": key[6], "run_id": key[7],
                      "operation_id": key[8], "observation_id": key[9], "status": status,
                      "reason_code": code, "next_action": action,
                      "preconditions": list(prerequisites), "automatic_retry": False,
                      "validation_id": _label(row.get("validation_id"), ""),
                      "candidate_source": _label(row.get("candidate_source"), "")}
        if key[10]:
            cells[key]["access_rule_hash"] = key[10]
        for name, value in zip(("resource_key", "resource_family", "state_key", "variant_key"), key[11:]):
            if value:
                cells[key][name] = value

    for row in (report.get("fuzz") or {}).get("fanout") or []:
        if not isinstance(row, dict):
            continue
        code, action = reason_action(row.get("reason") or row.get("triage_verdict"))
        if row.get("live") and row.get("triage_verdict") in {"LIKELY", "INCONCLUSIVE"}:
            put(row, "proposed", "probe_without_candidate", "schedule_bounded_validation")
        else:
            put(row, "blocked", code, action)
    for row in report.get("validation_candidates") or []:
        put(row, "proposed", "candidate_proposed", "bind_request_context")
    for row in report.get("validation_queue") or []:
        put(row, "ready", "candidate_ready", "validate_with_fresh_budget")
    for row in report.get("skipped") or []:
        if isinstance(row, dict):
            code, action = reason_action(row.get("reason"))
            put(row, "blocked", code, action, row.get("preconditions") or [])
    trusted = {( _dimension(event, normalize), event.get("validation_id")): event
               for event in verified_events if isinstance(event, dict)}
    for row in report.get("validations") or []:
        if not isinstance(row, dict):
            continue
        event = trusted.get((_dimension(row, normalize), row.get("validation_id")))
        status = (event or {}).get("status")
        if status in {"confirmed", "tested_clean"}:
            state = "confirmed" if status == "confirmed" else "tested_no_violation"
            put(row, state, "verified_validator_evidence", "none")
        else:
            code, action = reason_action(row.get("feedback_reason"))
            put(row, "blocked" if code == "budget_exhausted" else "inconclusive", code, action)
    return list(cells.values())


def persist_feedback(db_path, target, context_key, report, scope, verified_events=(), normalize=lambda url: url):
    """Persist scoped metadata. No request, grant, claim or session mutation."""
    from target_identity import target_query_matches

    if not context_key or not callable(getattr(scope, "permits_url", None)):
        return []
    plans = []
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path, timeout=10) as conn:
        conn.executescript(_SCHEMA)
        for row in build_feedback(report, verified_events, normalize):
            try:
                if (row["method"] not in {"GET", "HEAD"}
                        or not target_query_matches(_target_origin(target), row["url"])
                        or not scope.permits_url(row["url"])):
                    continue
                fingerprint, plan = gap_plan(target, {"endpoint": row["url"], **row}, context_key)
                plan.update(status=row["status"], reason_code=_label(row["reason_code"], "validator_inconclusive"),
                            next_action=row["next_action"], automatic_retry=False,
                            preconditions=[_label(p, "") for p in row["preconditions"]],
                            validation_id=row["validation_id"],
                            candidate_source=row["candidate_source"])
                plan["url"] = _redact_url(row["url"])
            except (TypeError, ValueError):
                continue
            from cco_surface_core import hypotheses
            hypothesis_key = hypotheses.observe(conn, target, row, context_key)
            plan["hypothesis_fingerprint"] = hypothesis_key
            previous = conn.execute("SELECT plan_json, status FROM hunter_feedback_queue WHERE fingerprint=?",
                                    (fingerprint,)).fetchone()
            # A later partial report for the same observation cannot erase an
            # artifact-backed terminal state. A new observation gets a new key.
            if previous and previous[1] in {"confirmed", "tested_no_violation"}:
                checked = verified_feedback([{"fingerprint": fingerprint, **json.loads(previous[0])}],
                                            target, context_key, verified_events, normalize)[0]
                if checked["status"] == "inconclusive":
                    old_plan = json.loads(previous[0])
                    if old_plan.get("hypothesis_fingerprint"):
                        hypotheses.invalidate(conn, old_plan["hypothesis_fingerprint"])
                    hypotheses.invalidate(conn, hypothesis_key)
                    conn.execute("UPDATE hunter_feedback_queue SET status=?,plan_json=? WHERE fingerprint=?",
                                 (checked["status"], json.dumps(checked, sort_keys=True), fingerprint))
                    conn.execute("INSERT INTO hunter_feedback_events (fingerprint,status,reason_code) VALUES (?,?,?)",
                                 (fingerprint, checked["status"], checked["reason_code"]))
                plans.append(checked)
                continue
            raw = json.dumps(plan, sort_keys=True, ensure_ascii=False)
            if not previous or raw != previous[0]:
                conn.execute("INSERT INTO hunter_feedback_queue (fingerprint, context_key, target, plan_json, status) "
                             "VALUES (?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET "
                             "plan_json=excluded.plan_json, status=excluded.status, updated_at=CURRENT_TIMESTAMP",
                             (fingerprint, context_key, _target_key(target), raw, row["status"]))
                conn.execute("INSERT INTO hunter_feedback_events (fingerprint,status,reason_code) VALUES (?,?,?)",
                             (fingerprint, row["status"], plan["reason_code"]))
            if row["status"] in hypotheses.TERMINAL:
                matching = next((event for event in verified_events
                                 if _dimension(event, normalize) == _dimension(row, normalize)
                                 and event.get("validation_id") == row.get("validation_id")), None)
                if matching:
                    hypotheses.complete(conn, hypothesis_key, matching,
                                        lambda dimension, receipt: receipt is matching)
            else:
                hypotheses.transition(conn, hypothesis_key, row["status"], reason=row["reason_code"])
            plans.append({"fingerprint": fingerprint, **plan})
    return plans
