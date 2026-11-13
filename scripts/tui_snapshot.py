#!/usr/bin/env python3
"""Write .cco/tui_snapshot.json for the KB HUD TUI plugin.

Reads finding lifecycle states from .cco/agent_memory.db and queue
stats from .cco/campaigns.db. Read-only, safe to run on an interval.
"""
import json
import sqlite3
import sys
import time
from pathlib import Path

import os

ROOT = Path(__file__).resolve().parent.parent
CCO = Path(os.environ.get("CCO_HOME") or (ROOT / ".cco")).expanduser()


def count_by(db: Path, table: str, col: str) -> dict:
    out: dict = {}
    if not db.exists():
        return out
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        for val, n in con.execute(f"select {col}, count(*) from {table} group by 1"):
            out[str(val)] = n
    finally:
        con.close()
    return out


def _artifact_current(row: dict) -> bool:
    if not row.get("reportable") or not row.get("validation_artifact"):
        return False
    try:
        root = (CCO / "validations").resolve()
        path = Path(row["validation_artifact"]).resolve(strict=True)
        if not path.is_relative_to(root):
            return False
        validator_dir = ROOT / "mcp-servers" / "mcp-validator"
        if str(validator_dir) not in sys.path:
            sys.path.insert(0, str(validator_dir))
        from cco_validator_core.evidence import artifact_is_current
        record = json.loads(path.read_text(encoding="utf-8"))
        return bool(artifact_is_current(record, trusted_root=str(root),
                                        expected_path=str(path), expected_target=row["target"],
                                        expected_finding_type=row["type"]))
    except Exception:
        return False


def finding_snapshot(db: Path) -> tuple[dict, dict | None]:
    """Only current signed artifacts count as verified in the HUD."""
    if not db.exists():
        return {}, None
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("select * from findings order by id desc").fetchall()
        try:
            aliases = {int(row[0]): int(row[1]) for row in con.execute(
                "select alias_id, canonical_id from finding_aliases")}
        except sqlite3.OperationalError:
            aliases = {}
        try:
            bindings = {int(row[0]): str(row[1]) for row in con.execute(
                "select finding_id, context_key from finding_identity")}
        except sqlite3.OperationalError:
            bindings = {}
    finally:
        con.close()
    counts: dict = {}
    latest = None
    active_context = None
    if os.environ.get("CCO_ENGAGEMENT_ID", "").strip():
        try:
            validator_dir = ROOT / "mcp-servers" / "mcp-validator"
            if str(validator_dir) not in sys.path:
                sys.path.insert(0, str(validator_dir))
            from cco_validator_core.evidence import current_scope_revision
            from target_identity import finding_context_key
            active_context = finding_context_key(current_scope_revision())
        except Exception:
            active_context = object()  # Missing context fails closed.
    for item in rows:
        row = dict(item)
        state = str(row.get("validation_state") or "")
        canonical_id = aliases.get(int(row["id"]), int(row["id"]))
        if active_context is not None and bindings.get(canonical_id) != active_context:
            continue
        if row["id"] in aliases:
            counts["duplicate_alias"] = counts.get("duplicate_alias", 0) + 1
            continue
        if state in {"confirmed", "verified"}:
            if _artifact_current(row):
                if latest is None:
                    latest = {"id": row["id"], "target": row["target"], "type": row["type"],
                              "severity": row["severity"], "state": state}
            else:
                state = "stale_or_invalid_artifact"
        counts[state] = counts.get(state, 0) + 1
    return counts, latest


def latest_confirmed(db: Path) -> dict | None:
    return finding_snapshot(db)[1]


def active_campaign(db: Path) -> dict | None:
    if not db.exists():
        return None
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        cols = [r[1] for r in con.execute("pragma table_info(campaigns)")]
        pick = [c for c in ("id", "name", "status", "state") if c in cols]
        if not pick:
            return None
        row = con.execute(
            f"select {', '.join(pick)} from campaigns order by id desc limit 1"
        ).fetchone()
    finally:
        con.close()
    return dict(zip(pick, row)) if row else None


def campaign_snapshot(home: Path, campaign_id: int | None = None) -> dict:
    """Read one campaign's durable state; queue completion never seals coverage."""
    empty = {'operations': 0, 'runnable': 0, 'pending_prerequisites': 0, 'tested': 0,
             'inconclusive': 0, 'confirmed': 0, 'requests_sent': 0, 'requests_remaining': None,
             'task_completion': 'unknown', 'run_closure': 'open', 'scope_completion': 'unknown',
             'remaining': [], 'hypotheses_by_status': {}, 'tasks_by_status': {}}
    surface_dir = str(ROOT / 'mcp-servers' / 'mcp-memory-server')
    if surface_dir not in sys.path:
        sys.path.insert(0, surface_dir)
    db = home / 'campaigns.db'
    if not db.is_file():
        return empty
    with sqlite3.connect(f'file:{db}?mode=ro', uri=True) as con:
        con.row_factory = sqlite3.Row
        row = con.execute('SELECT * FROM campaigns WHERE id=?', (campaign_id,)).fetchone() if campaign_id else con.execute(
            'SELECT * FROM campaigns ORDER BY id DESC LIMIT 1').fetchone()
        if row is None:
            return empty
        campaign = dict(row)
        tasks = [dict(r) for r in con.execute('SELECT * FROM tasks WHERE campaign_id=?', (row['id'],))]
    checkpoint = json.loads(campaign.get('checkpoint_json') or '{}')
    close = checkpoint.get('close_out') or {}
    used, reserved, limit = (int(campaign.get(k) or 0) for k in
                             ('requests_used', 'requests_reserved', 'budget_requests'))
    stats = {**empty, 'campaign_id': campaign['id'], 'requests_sent': 0, 'requests_charged': used, 'request_count_known': True,
             'requests_reserved': reserved, 'requests_remaining': max(0, limit - used - reserved) if limit else None,
             'task_completion': 'done' if tasks and all(t['status'] == 'done' for t in tasks) else 'incomplete',
             'run_closure': 'closed' if campaign['status'] == 'closed' and close else 'open',
             'scope_completion': 'incomplete', 'budget_exhausted': bool(limit and used + reserved >= limit)}
    refs, targets = {}, set()
    for task in tasks:
        state = task['status']
        outcome = json.loads(task.get('result_json') or '{}').get('outcome') or {}
        if outcome.get('request_count_known'):
            stats['requests_sent'] += outcome.get('requests_sent', 0)
        elif state in {'done', 'blocked'} and (outcome.get('requests_charged') or task.get('attempts')):
            stats['request_count_known'] = False
        stats['tasks_by_status'][state] = stats['tasks_by_status'].get(state, 0) + 1
        args = json.loads(task.get('args_json') or '{}')
        target = args.get('target') or args.get('url')
        if target:
            targets.add(target)
        ref = json.loads(task.get('references_json') or '{}')
        if ref:
            refs[ref['hypothesis_ref']] = ref['dimension']
        if state != 'done':
            stats['remaining'].append({'task_id': task['id'], 'status': state,
                                       'reason': task.get('last_error') or '', 'references': ref})
    memory = home / 'agent_memory.db'
    if not memory.is_file():
        return stats
    with sqlite3.connect(f'file:{memory}?mode=ro', uri=True) as con:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        dimensions = list(refs.values())
        contexts = {(d['target_key'], d['context']) for d in dimensions}
        from cco_surface_core.normalize import canonical_target
        hunter_dir = str(ROOT / 'mcp-servers' / 'mcp-hunter')
        if hunter_dir not in sys.path:
            sys.path.insert(0, hunter_dir)
        from cco_hunter_core.feedback import feedback_context
        from policy_engine import ScopeResolver
        import hashlib
        context = feedback_context()
        scope = ScopeResolver(scope_file=campaign.get('scope_file') or None)
        runs = {(d['target_key'], d['context'], d['run_id']) for d in dimensions}
        # A campaign without bound dimensions uses current scope/policy, never
        # historical terminal rows from other engagements.
        if not contexts and targets:
            contexts = {(hashlib.sha256(json.dumps(canonical_target(t), ensure_ascii=False).encode()).hexdigest(), context)
                        for t in targets}
        states, remaining, operations = {}, [], set()
        if 'web_hypotheses' in tables:
            for key, dimension_json, state, reason, validation_id in con.execute(
                    'SELECT fingerprint,dimension_json,status,reason,validation_id FROM web_hypotheses'):
                dimension = json.loads(dimension_json)
                if (dimension.get('target_key'), dimension.get('context')) not in contexts:
                    continue
                if runs and (dimension['target_key'], dimension['context'], dimension['run_id']) not in runs:
                    continue
                if not scope.permits_url(dimension['url']) and key not in refs:
                    continue
                if dimension['context'] != context or not scope.permits_url(dimension['url']):
                    state, reason = 'blocked', 'scope_or_policy_changed'
                # Only current signed-evidence terminal transitions count.
                if state in {'confirmed', 'tested_no_violation'}:
                    from agent_integration import current_hypothesis_result
                    state = current_hypothesis_result(home, dimension, state, validation_id)
                states[state] = states.get(state, 0) + 1
                operations.add(dimension['operation_id'])
                if state not in {'confirmed', 'tested_no_violation'}:
                    remaining.append({'hypothesis_ref': key, 'operation_ref': dimension['operation_id'],
                                      'status': state, 'reason': reason})
        if 'attack_surface' in tables:
            from cco_surface_core.normalize import canonical_target
            canonical = {canonical_target(t) for t in targets}
            operations.update(r[0] for r in con.execute('SELECT operation_id,target,url FROM attack_surface')
                              if r[0] and canonical_target(r[1]) in canonical and scope.permits_url(r[2]))
    stats.update(operations=len(operations), runnable=states.get('ready', 0),
                 pending_prerequisites=states.get('blocked', 0) + states.get('proposed', 0),
                 tested=states.get('confirmed', 0) + states.get('tested_no_violation', 0),
                 inconclusive=states.get('inconclusive', 0), confirmed=states.get('confirmed', 0),
                 hypotheses_by_status=states)
    stats['remaining'].extend(remaining)
    # Waivers allow run closure, never scope completion. An empty queue is not proof.
    if (states and not remaining and stats['task_completion'] == 'done'
            and stats['run_closure'] == 'closed' and not close.get('waive_untested')
            and not close.get('untested_at_close')):
        stats['scope_completion'] = 'complete'
    return stats


def main() -> int:
    mem = CCO / "agent_memory.db"
    camp = CCO / "campaigns.db"
    findings, latest = finding_snapshot(mem)
    snap = {
        "updated_at": int(time.time()),
        "findings_by_state": findings,
        "latest_validated": latest,
        "web": campaign_snapshot(CCO),
        "active_campaign": active_campaign(camp),
    }
    snap['tasks_by_status'] = snap['web']['tasks_by_status']
    out = CCO / "tui_snapshot.json"
    CCO.mkdir(parents=True, exist_ok=True)
    pending = out.with_suffix('.tmp')
    pending.write_text(json.dumps(snap, indent=1) + "\n")
    pending.replace(out)
    print(json.dumps(snap))
    return 0


if __name__ == "__main__":
    sys.exit(main())
