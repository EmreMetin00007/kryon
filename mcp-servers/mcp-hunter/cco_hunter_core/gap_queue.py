"""Durable, non-executable coverage dimensions for later campaign planning."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SCHEMA = """CREATE TABLE IF NOT EXISTS hunter_gap_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    context_key TEXT NOT NULL,
    target TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'needs_scheduling',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)"""
_LABEL = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


def _label(value, default="unspecified"):
    value = str(value or "")
    return value if _LABEL.fullmatch(value) else default


def _redact_url(url):
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)
    query = urlencode([(name, "<redacted>") for name, _ in pairs])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _target_key(target):
    value = str(target or "")
    return _redact_url(value) if "://" in value else value


def _target_origin(target):
    from target_identity import canonical_target
    if "://" not in str(target or ""):
        return canonical_target(target)
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
        return ""
    _ = parsed.port
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def gap_plan(target: str, gap: dict, context_key: str) -> tuple[str, dict]:
    """One dimension key shared by observation, planning and execution."""
    url = str(gap.get("endpoint") or "")
    plan = {"url": _redact_url(url), "method": str(gap.get("method") or "GET").upper(),
            "vuln_class": _label(gap.get("vuln_class"), ""),
            "param": _label(gap.get("param"), ""), "carrier": _label(gap.get("carrier"), "query"),
            "identity": _label(gap.get("identity")), "resource_owner": _label(gap.get("resource_owner")),
            "run_id": _label(gap.get("run_id")), "status": "needs_scheduling",
            "preconditions": ["fresh_scope_and_grant", "request_context", "campaign_budget"]}
    if gap.get("param") and not plan["param"]:
        plan["param"] = "field:" + hashlib.sha256(str(gap["param"]).encode()).hexdigest()
    if gap.get("operation_id"):
        plan["operation_id"] = _label(gap["operation_id"], "")
    if gap.get("observation_id") not in (None, "", "unspecified"):
        plan["observation_id"] = _label(gap["observation_id"], "")
    if gap.get("access_rule_hash"):
        if not re.fullmatch(r"[a-f0-9]{64}", str(gap["access_rule_hash"])):
            raise ValueError("invalid access rule reference")
        plan["access_rule_hash"] = gap["access_rule_hash"]
    from cco_surface_core.hypotheses import extensions
    plan.update(extensions(gap))
    resource_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
    raw = json.dumps([context_key, _target_key(target), resource_hash, plan], sort_keys=True, ensure_ascii=False)
    fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    from cco_surface_core.hypotheses import metric
    for field in ("observation_quality", "coverage_contribution", "impact", "estimated_requests", "estimated_seconds"):
        if field in gap:
            plan[field] = metric(gap[field])
    return fingerprint, plan


def plan_gaps(db_path: str, target: str, gaps: list[dict], scope, context_key: str,
              limit: int = 15) -> tuple[list[dict], list[dict]]:
    """Store scoped GET/HEAD plans; never reserve budget or send requests."""
    from target_identity import target_query_matches
    if not context_key or not callable(getattr(scope, "permits_url", None)):
        return [], []
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    planned, admitted = [], []
    with sqlite3.connect(path, timeout=10) as conn:
        conn.execute(_SCHEMA)
        for gap in gaps:
            if len(planned) >= max(0, min(int(limit), 100)):
                break
            if not isinstance(gap, dict):
                continue
            url = str(gap.get("endpoint") or "")
            method = str(gap.get("method") or "GET").upper()
            if method not in {"GET", "HEAD"}:
                continue
            try:
                if not target_query_matches(_target_origin(target), url) or not scope.permits_url(url):
                    continue
                _redact_url(url)
            except (TypeError, ValueError):
                continue
            vclass = _label(gap.get("vuln_class"), "")
            if not vclass:
                continue
            # Different object IDs in query values must stay distinct, without
            # persisting those values in the queue.
            fingerprint, plan = gap_plan(target, gap, context_key)
            safe_target = _target_key(target)
            conn.execute("INSERT OR IGNORE INTO hunter_gap_queue (fingerprint, context_key, target, plan_json) "
                         "VALUES (?, ?, ?, ?)", (fingerprint, context_key, safe_target,
                                                  json.dumps(plan, sort_keys=True, ensure_ascii=False)))
            planned.append({"fingerprint": fingerprint, **plan})
            admitted.append(gap)
    return planned, admitted


def list_gaps(db_path: str, target: str, context_key: str, limit: int = 50, status: str = "",
              run_id: str = "", *, after_id: int = 0) -> list[dict]:
    if not Path(db_path).is_file():
        return []
    try:
        with sqlite3.connect(db_path) as conn:
            query = "SELECT fingerprint, plan_json, status FROM hunter_gap_queue WHERE target=? AND context_key=? "
            params = [_target_key(target), context_key]
            if status:
                query += "AND status=? "
                params.append(status)
            if run_id:
                query += "AND json_extract(plan_json, '$.run_id')=? "
                params.append(run_id)
            rows = conn.execute(query + "ORDER BY (id<=?), id LIMIT ?",
                                [*params, after_id, max(1, min(int(limit), 100))]).fetchall()
            links = {}
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='hunter_gap_requests'").fetchone():
                links = {ref: (campaign, task) for ref, campaign, task in conn.execute(
                    "SELECT fingerprint, campaign_id, task_id FROM hunter_gap_requests WHERE task_id IS NOT NULL")}
        plans = [{"fingerprint": fingerprint, **json.loads(raw), "status": state}
                 for fingerprint, raw, state in rows]
        campaign_path = Path(db_path).parent / "campaigns.db"
        if links and campaign_path.is_file():
            with sqlite3.connect(campaign_path.resolve().as_uri() + "?mode=ro", uri=True) as conn:
                for plan in plans:
                    link = links.get(plan["fingerprint"])
                    if link:
                        row = conn.execute("SELECT status FROM tasks WHERE campaign_id=? AND id=?", link).fetchone()
                        plan.update(campaign_id=link[0], task_id=link[1], task_status=row[0] if row else "missing")
        return plans
    except (sqlite3.Error, TypeError, ValueError):
        return []
