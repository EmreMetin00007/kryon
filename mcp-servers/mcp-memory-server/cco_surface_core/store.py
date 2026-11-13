"""SQLite persistence for attack_surface records."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from pathlib import Path

from .normalize import dumps_list, dumps_params, normalize_record, score_record, suggested_classes
from .fuzz import remaining_classes

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS attack_surface (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    target TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    host TEXT DEFAULT '',
    path TEXT DEFAULT '',
    params_json TEXT DEFAULT '[]',
    status INTEGER,
    content_type TEXT DEFAULT '',
    title TEXT DEFAULT '',
    body_hash TEXT DEFAULT '',
    body_len INTEGER,
    auth_required INTEGER,
    tech_json TEXT DEFAULT '[]',
    sources_json TEXT DEFAULT '[]',
    ev_score REAL DEFAULT 0,
    tested_classes TEXT DEFAULT '[]',
    queued_classes TEXT DEFAULT '[]',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    operation_json TEXT DEFAULT '{}',
    operation_id TEXT DEFAULT '',
    latest_observation_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_surface_target_ev
    ON attack_surface(target, ev_score DESC);
CREATE INDEX IF NOT EXISTS idx_surface_target
    ON attack_surface(target);
"""


def memory_db_path(home: str | None = None) -> str:
    root = home or os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, "agent_memory.db")


def artifact_dir(home: str | None = None) -> str:
    root = home or os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
    path = os.path.join(root, "artifacts", "surface")
    os.makedirs(path, exist_ok=True)
    return path


def write_artifact(payload, prefix: str = "surface") -> str:
    path = os.path.join(artifact_dir(), f"{prefix}-{int(time.time())}-{uuid.uuid4().hex[:8]}.json")
    if isinstance(payload, (dict, list)):
        text = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        text = str(payload)
    Path(path).write_text(text, encoding="utf-8")
    return path


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(attack_surface)")}
    if "queued_classes" not in cols:
        conn.execute("ALTER TABLE attack_surface ADD COLUMN queued_classes TEXT DEFAULT '[]'")
    for name, default in (("operation_json", "{}"), ("operation_id", "")):
        if name not in cols:
            conn.execute(f"ALTER TABLE attack_surface ADD COLUMN {name} TEXT DEFAULT '{default}'")
    if "latest_observation_id" not in cols:
        conn.execute("ALTER TABLE attack_surface ADD COLUMN latest_observation_id INTEGER")
    conn.execute("""CREATE TABLE IF NOT EXISTS surface_observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL,
        observation_key TEXT NOT NULL, observation_json TEXT NOT NULL,
        sources_json TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(fingerprint, observation_key))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS surface_operation_heads (
        operation_id TEXT PRIMARY KEY, observation_id INTEGER NOT NULL,
        request_state TEXT NOT NULL)""")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            url_or_port TEXT NOT NULL,
            protocol TEXT,
            state TEXT,
            technologies TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )"""
    )


def _load_json_list(raw) -> list:
    if isinstance(raw, list):
        return raw
    try:
        data = json.loads(raw or "[]")
        return data if isinstance(data, list) else []
    except (TypeError, json.JSONDecodeError):
        return []


def _merge_unique(left, right, key=None):
    out = []
    seen = set()
    for item in list(left or []) + list(right or []):
        marker = key(item) if key else json.dumps(item, sort_keys=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return out


def _merge_params(left, right, *, observed_request=False):
    """Enrich request parameters without replacing observations with schema samples."""
    out = {}
    schema_sources = {"openapi_example", "openapi_default", "openapi_enum",
                      "schema_generated", "schema_unresolved"}
    sample_priority = {"openapi_example": 4, "openapi_default": 3, "openapi_enum": 2,
                       "schema_generated": 1, "schema_unresolved": 0}
    for item in [*(left or []), *(right or [])]:
        if not isinstance(item, dict):
            continue
        path = tuple(item.get("path") or ())
        if path == (item.get("name"),):
            path = ()
        marker = (item.get("in"), item.get("name"), path)
        if marker not in out:
            out[marker] = dict(item)
            continue
        previous = out[marker]
        previous_schema = previous.get("sample_source") in schema_sources
        incoming_schema = item.get("sample_source") in schema_sources
        # Preserve schema attributes even when the observed value wins.
        merged = {**previous, **{key: item[key] for key in (
            "type", "required", "nullable", "enum", "format", "schema_context", "schema_version",
            "encoding", "repeated", "body_root", "file_part") if key in item}}
        if ((observed_request and not incoming_schema) or
                (previous_schema and (not incoming_schema or
                 sample_priority[item["sample_source"]] >= sample_priority[previous["sample_source"]]))):
            for key in ("sample", "sample_source", "schema_unresolved", "sample_available"):
                merged.pop(key, None)
                if key in item:
                    merged[key] = item[key]
        out[marker] = merged
    return list(out.values())


def _mirror_endpoint(conn: sqlite3.Connection, record: dict) -> None:
    url = record["url"]
    target = record["target"]
    protocol = "https" if url.startswith("https://") else "http"
    tech = " ".join(record.get("tech") or [])
    row = conn.execute(
        "SELECT id, technologies FROM endpoints WHERE target=? AND url_or_port=?",
        (target, url),
    ).fetchone()
    if row:
        existing = row[1] or ""
        merged = " ".join(dict.fromkeys((existing + " " + tech).split()))
        if merged != existing:
            conn.execute("UPDATE endpoints SET technologies=? WHERE id=?", (merged, row[0]))
        return
    conn.execute(
        "INSERT INTO endpoints (target, url_or_port, protocol, state, technologies) "
        "VALUES (?, ?, ?, 'open', ?)",
        (target, url, protocol, tech),
    )


def ingest_records(records, target: str = "", base: str = "", db_path: str | None = None,
                   max_records: int = 800) -> dict:
    db_path = db_path or memory_db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    inserted = 0
    updated = 0
    skipped = 0
    by_source = {}
    capture_secrets = []
    conn = sqlite3.connect(db_path)
    try:
        ensure_schema(conn)
        for raw in records or []:
            if inserted + updated >= max_records:
                skipped += 1
                continue
            rec = normalize_record(raw, target=target, base=base)
            if rec is None:
                skipped += 1
                continue
            for source in rec["sources"]:
                by_source[source] = by_source.get(source, 0) + 1
            existing = conn.execute(
                "SELECT id, params_json, tech_json, sources_json, tested_classes, "
                "status, title, content_type, body_hash, body_len, auth_required, ev_score "
                "FROM attack_surface WHERE fingerprint=?",
                (rec["fingerprint"],),
            ).fetchone()
            if existing:
                params = _merge_params(_load_json_list(existing[1]), rec["params"],
                                       observed_request=rec["request_state"] == "observed_request")
                tech = _merge_unique(_load_json_list(existing[2]), rec["tech"])
                sources = _merge_unique(_load_json_list(existing[3]), rec["sources"])
                tested = _load_json_list(existing[4])
                status = rec["status"] if rec["status"] is not None else existing[5]
                title = rec["title"] or existing[6] or ""
                content_type = rec["content_type"] or existing[7] or ""
                body_hash = rec["body_hash"] or existing[8] or ""
                body_len = rec["body_len"] if rec["body_len"] is not None else existing[9]
                auth = rec["auth_required"] if rec["auth_required"] is not None else existing[10]
                merged = dict(rec)
                merged["params"] = params
                merged["tech"] = tech
                merged["sources"] = sources
                merged["status"] = status
                merged["title"] = title
                merged["content_type"] = content_type
                merged["body_hash"] = body_hash
                merged["body_len"] = body_len
                merged["auth_required"] = auth
                merged["tested_classes"] = tested
                merged["ev_score"] = max(float(existing[11] or 0), score_record(merged))
                conn.execute(
                    "UPDATE attack_surface SET url=?, method=?, host=?, path=?, params_json=?, "
                    "status=?, content_type=?, title=?, body_hash=?, body_len=?, auth_required=?, "
                    "tech_json=?, sources_json=?, ev_score=?, tested_classes=?, last_seen=CURRENT_TIMESTAMP "
                    "WHERE id=?",
                    (
                        merged["url"], merged["method"], merged["host"], merged["path"],
                        dumps_params(merged["params"]), merged["status"], merged["content_type"],
                        merged["title"], merged["body_hash"], merged["body_len"], merged["auth_required"],
                        dumps_list(merged["tech"]), dumps_list(merged["sources"]), merged["ev_score"],
                        dumps_list(tested), existing[0],
                    ),
                )
                _mirror_endpoint(conn, merged)
                updated += 1
            else:
                conn.execute(
                    "INSERT INTO attack_surface ("
                    "fingerprint, target, url, method, host, path, params_json, status, "
                    "content_type, title, body_hash, body_len, auth_required, tech_json, "
                    "sources_json, ev_score, tested_classes, operation_json, operation_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        rec["fingerprint"], rec["target"], rec["url"], rec["method"], rec["host"],
                        rec["path"], dumps_params(rec["params"]), rec["status"], rec["content_type"],
                        rec["title"], rec["body_hash"], rec["body_len"], rec["auth_required"],
                        dumps_list(rec["tech"]), dumps_list(rec["sources"]), rec["ev_score"],
                        dumps_list(rec["tested_classes"]),
                        json.dumps(rec["operation"], sort_keys=True), rec["operation_id"],
                    ),
                )
                _mirror_endpoint(conn, rec)
                inserted += 1
            observation_id = _record_observation(conn, rec)
            from .hypotheses import observe_surface
            observe_surface(conn, rec, observation_id, suggested_classes(rec))
            if raw.get("_captured_request") is not None:
                from .request_store import save_capture
                _, secret_ref = save_capture(conn, rec, raw["_captured_request"], observation_id,
                                              home=str(Path(db_path).parent))
                if secret_ref:
                    capture_secrets.append(secret_ref)
        conn.commit()
    except Exception:
        conn.rollback()
        if capture_secrets:
            from .request_store import discard_secret
            for secret_ref in capture_secrets:
                discard_secret(str(Path(db_path).parent), secret_ref)
        raise
    finally:
        conn.close()
    return {
        "inserted": inserted,
        "updated": updated,
        "skipped": skipped,
        "sources": by_source,
        "db_path": db_path,
        "total_touched": inserted + updated,
    }


def _row_to_work(row) -> dict:
    params = _load_json_list(row["params_json"])
    record = {
        "id": row["id"],
        "fingerprint": row["fingerprint"],
        "target": row["target"],
        "url": row["url"],
        "method": row["method"],
        "host": row["host"],
        "path": row["path"],
        "params": params,
        "status": row["status"],
        "content_type": row["content_type"],
        "title": row["title"],
        "tech": _load_json_list(row["tech_json"]),
        "sources": _load_json_list(row["sources_json"]),
        "ev_score": row["ev_score"],
        "tested_classes": _load_json_list(row["tested_classes"]),
        "queued_classes": _load_json_list(row["queued_classes"] if "queued_classes" in row.keys() else "[]"),
        "auth_required": row["auth_required"],
        "operation_id": row["operation_id"] if "operation_id" in row.keys() else "",
        "operation": json.loads(row["operation_json"] or "{}") if "operation_json" in row.keys() else {},
    }
    if not record["operation"]:
        record["operation"] = {"kind": "legacy_unknown"}
    record["suggested_classes"] = suggested_classes(record)
    record["remaining_classes"] = remaining_classes(record)
    return record


def _record_observation(conn, record):
    import hashlib
    observation = {key: record.get(key) for key in ("operation_id", "url", "params", "status", "body_hash",
                                                   "content_type", "request_state", "identity", "resource_owner", "run_id")}
    if record.get("capture_binding"):
        observation["capture_binding"] = record["capture_binding"]
    raw = json.dumps(observation, sort_keys=True, ensure_ascii=False)
    key = hashlib.sha256(raw.encode()).hexdigest()
    old = conn.execute("SELECT sources_json FROM surface_observations WHERE fingerprint=? AND observation_key=?",
                       (record["fingerprint"], key)).fetchone()
    sources = _merge_unique(_load_json_list(old[0]) if old else [], record["sources"])
    conn.execute("INSERT INTO surface_observations (fingerprint,observation_key,observation_json,sources_json) "
                 "VALUES (?,?,?,?) ON CONFLICT(fingerprint,observation_key) DO UPDATE SET sources_json=excluded.sources_json",
                 (record["fingerprint"], key, raw, dumps_list(sources)))
    observation_id = conn.execute("SELECT id FROM surface_observations WHERE fingerprint=? AND observation_key=?",
                                  (record["fingerprint"], key)).fetchone()[0]
    previous = conn.execute("SELECT o.observation_json FROM attack_surface s "
                            "JOIN surface_observations o ON o.id=s.latest_observation_id WHERE s.fingerprint=?",
                            (record["fingerprint"],)).fetchone()
    # Repeated captures keep their ID but become current again. A schema import
    # can enrich fields, but cannot displace the actual observed request binding.
    previous_observation = json.loads(previous[0]) if previous else {}
    if (record.get("request_state") == "observed_request" or
            previous_observation.get("request_state") != "observed_request"):
        conn.execute("UPDATE attack_surface SET latest_observation_id=? WHERE fingerprint=?",
                     (observation_id, record["fingerprint"]))
    elif previous_observation.get("url"):
        conn.execute("UPDATE attack_surface SET url=? WHERE fingerprint=?",
                     (previous_observation["url"], record["fingerprint"]))
    head = conn.execute("SELECT request_state FROM surface_operation_heads WHERE operation_id=?",
                        (record["operation_id"],)).fetchone()
    if not head or record["request_state"] == "observed_request" or head[0] != "observed_request":
        conn.execute("INSERT INTO surface_operation_heads (operation_id,observation_id,request_state) VALUES (?,?,?) "
                     "ON CONFLICT(operation_id) DO UPDATE SET observation_id=excluded.observation_id,request_state=excluded.request_state",
                     (record["operation_id"], observation_id, record["request_state"]))
    return observation_id


def query_observations(fingerprint: str, limit: int = 50, db_path: str | None = None) -> list[dict]:
    path = db_path or memory_db_path()
    if not os.path.exists(path):
        return []
    with sqlite3.connect(path) as conn:
        ensure_schema(conn)
        rows = conn.execute("SELECT id,observation_json,sources_json FROM surface_observations "
                            "WHERE fingerprint=? ORDER BY id DESC LIMIT ?",
                            (fingerprint, max(1, min(int(limit), 500)))).fetchall()
    return [{"id": ident, **json.loads(raw), "sources": _load_json_list(sources)} for ident, raw, sources in rows]


def mark_tested(target: str, fingerprint: str, classes, db_path: str | None = None) -> dict:
    db_path = db_path or memory_db_path()
    to_add = [str(item) for item in (classes or []) if item]
    if not fingerprint or not to_add:
        return {"updated": 0, "tested_classes": []}
    conn = sqlite3.connect(db_path)
    try:
        ensure_schema(conn)
        row = conn.execute(
            "SELECT id, tested_classes FROM attack_surface WHERE fingerprint=? AND target=?",
            (fingerprint, target),
        ).fetchone()
        if not row:
            row = conn.execute(
                "SELECT id, tested_classes FROM attack_surface WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
        if not row:
            return {"updated": 0, "tested_classes": []}
        merged = _merge_unique(_load_json_list(row[1]), to_add)
        conn.execute(
            "UPDATE attack_surface SET tested_classes=?, last_seen=CURRENT_TIMESTAMP WHERE id=?",
            (dumps_list(merged), row[0]),
        )
        conn.commit()
        return {"updated": 1, "tested_classes": merged, "id": row[0]}
    finally:
        conn.close()


def queue_classes(target: str, fingerprint: str, classes, db_path: str | None = None) -> dict:
    """Merge vuln classes into queued_classes so remaining_classes keeps them in next_work."""
    db_path = db_path or memory_db_path()
    to_add = [str(item) for item in (classes or []) if item]
    if not fingerprint or not to_add:
        return {"updated": 0, "queued_classes": []}
    conn = sqlite3.connect(db_path)
    try:
        ensure_schema(conn)
        row = conn.execute(
            "SELECT id, queued_classes FROM attack_surface WHERE fingerprint=? AND target=?",
            (fingerprint, target),
        ).fetchone()
        if not row:
            row = conn.execute(
                "SELECT id, queued_classes FROM attack_surface WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
        if not row:
            return {"updated": 0, "queued_classes": []}
        merged = _merge_unique(_load_json_list(row[1]), to_add)
        conn.execute(
            "UPDATE attack_surface SET queued_classes=?, last_seen=CURRENT_TIMESTAMP WHERE id=?",
            (dumps_list(merged), row[0]),
        )
        conn.commit()
        return {"updated": 1, "queued_classes": merged, "id": row[0]}
    finally:
        conn.close()


def enqueue_coverage_gaps(target: str, gaps, db_path: str | None = None, limit: int = 12) -> list[dict]:
    """Turn coverage (endpoint × class) gaps into surface queue work."""
    db_path = db_path or memory_db_path()
    queued = []
    for gap in list(gaps or [])[: max(0, int(limit))]:
        url = str(gap.get("endpoint") or gap.get("url") or "").strip()
        vclass = str(gap.get("vuln_class") or gap.get("class") or "").strip()
        if not url or not vclass:
            continue
        rec = normalize_record(
            {"url": url, "method": str(gap.get("method") or "GET"),
             "sources": ["coverage_gap"], "status": 200},
            target=target,
        )
        if rec is None:
            continue
        ingest_records([rec], target=target, db_path=db_path)
        queue_classes(target, rec["fingerprint"], [vclass], db_path=db_path)
        queued.append({
            "url": rec.get("url"),
            "fingerprint": rec.get("fingerprint"),
            "vuln_class": vclass,
        })
    return queued


def _target_key_candidates(target: str) -> list:
    """Aynı hedefin yazım varyantları (şema/host/port/sondaki /).

    Aşamalar hedefi farklı normalize ediyor (discover: şema+host[:port], crawl: host).
    Kuyruk sorgusu tek anahtara körü körüne bağlanırsa boş döner ve fuzz
    sessizce 0 probe koşar; varyantlar birlikte sorgulanır.
    """
    raw = (target or "").strip()
    keys: list = []
    def _add(k):
        if k and k not in keys:
            keys.append(k)
    _add(raw)
    _add(raw.rstrip("/"))
    try:
        from urllib.parse import urlparse
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or "").lower()
        netloc = (parsed.netloc or "").lower()
        if host:
            _add(host)
            _add(f"http://{host}")
            _add(f"https://{host}")
        if netloc and netloc != host:
            _add(netloc)
            _add(f"http://{netloc}")
            _add(f"https://{netloc}")
    except Exception:  # noqa: BLE001
        pass
    return keys


def _operation_inventory(rows) -> list[dict]:
    """A value-free field union; surface rows remain the request/coverage unit."""
    groups = {}
    for row in rows:
        operation_id = row["operation_id"] or ""
        key = operation_id or "legacy:" + row["fingerprint"]
        if key not in groups:
            groups[key] = {"operation_id": operation_id,
                           "operation": json.loads(row["operation_json"] or "{}") or {"kind": "legacy_unknown"},
                           "fields": {}, "sources": [], "surface_records": []}
        group = groups[key]
        sources = _load_json_list(row["sources_json"])
        group["sources"] = _merge_unique(group["sources"], sources)
        group["surface_records"].append({"fingerprint": row["fingerprint"],
                                          "observation_id": row["latest_observation_id"]})
        for param in _load_json_list(row["params_json"]):
            if not isinstance(param, dict) or not param.get("name"):
                continue
            path = tuple(param.get("path") or ())
            if path == (param["name"],):
                path = ()
            marker = (param.get("in") or "query", param["name"], path)
            field = group["fields"].setdefault(marker, {
                "name": param["name"], "in": marker[0],
                **({"path": list(param["path"])} if param.get("path") else {}),
                "constraints": [], "sources": [], "fingerprints": []})
            hint = {k: param[k] for k in ("type", "required") if k in param}
            if hint:
                field["constraints"] = _merge_unique(field["constraints"], [hint])
            field["sources"] = _merge_unique(field["sources"], sources)
            field["fingerprints"] = _merge_unique(field["fingerprints"], [row["fingerprint"]])
    return [{**g, "fields": list(g["fields"].values())} for g in groups.values()]


def next_work(target: str, limit: int = 15, untested_only: bool = True,
              min_ev: float = 0.0, class_hint: str = "", db_path: str | None = None) -> dict:
    db_path = db_path or memory_db_path()
    if not os.path.exists(db_path):
        return {"target": target, "count": 0, "total_surface": 0, "untested": 0, "queue": [],
                "operations": [], "total_operations": 0}
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        ensure_schema(conn)
        keys = _target_key_candidates(target)
        placeholders = ",".join("?" for _ in keys)
        total = conn.execute(
            f"SELECT COUNT(*) FROM attack_surface WHERE (target IN ({placeholders}) OR host IN ({placeholders}))",
            [*keys, *keys],
        ).fetchone()[0]
        query = f"SELECT * FROM attack_surface WHERE (target IN ({placeholders}) OR host IN ({placeholders})) AND ev_score >= ?"
        args: list = [*keys, *keys, float(min_ev)]
        if class_hint:
            query += " AND (url LIKE ? OR path LIKE ? OR params_json LIKE ?)"
            like = f"%{class_hint}%"
            args.extend([like, like, like])
        query += " ORDER BY ev_score DESC, id ASC"
        rows = conn.execute(query, args).fetchall()
        operations = _operation_inventory(rows)
        heads = dict(conn.execute("SELECT operation_id,observation_id FROM surface_operation_heads"))
        for operation in operations:
            operation["observation_id"] = heads.get(operation["operation_id"])
        operation_fields = {op["operation_id"]: op["fields"] for op in operations if op["operation_id"]}
        observations = {fp: (count, latest) for fp, count, latest in conn.execute(
            "SELECT fingerprint,COUNT(*),MAX(id) FROM surface_observations GROUP BY fingerprint")}
        capture_refs = {}
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='surface_request_bindings'").fetchone():
            capture_refs = {(fp, obs): (ref, json.loads(metadata)) for fp, obs, ref, metadata in conn.execute(
                "SELECT fingerprint,observation_id,capture_ref,metadata_json FROM surface_request_bindings")}
        queue = []
        untested = 0
        for row in rows:
            rec = _row_to_work(row)
            rec["operation_fields"] = operation_fields.get(rec["operation_id"], [])
            rec["observation_count"], rec["observation_id"] = observations.get(rec["fingerprint"], (0, None))
            if row["latest_observation_id"] is not None:
                rec["observation_id"] = row["latest_observation_id"]
            capture = capture_refs.get((rec["fingerprint"], rec["observation_id"]))
            if capture:
                rec["capture_ref"], rec["capture_binding"] = capture
            leftover = rec.get("remaining_classes") or []
            if leftover:
                untested += 1
            if untested_only and not leftover:
                continue
            if len(queue) < max(1, int(limit)):
                queue.append(rec)
    finally:
        conn.close()
    return {
        "target": target,
        "count": len(queue),
        "total_surface": total,
        "untested": untested,
        "queue": queue,
        "operations": operations[:max(1, int(limit))],
        "total_operations": len(operations),
    }


def query_surface(target: str, limit: int = 50, db_path: str | None = None) -> list[dict]:
    result = next_work(target, limit=limit, untested_only=False, db_path=db_path)
    return result["queue"]


def query_operations(target: str, limit: int = 50, db_path: str | None = None) -> list[dict]:
    """Read operation fields and source links without choosing a request baseline."""
    return next_work(target, limit=limit, untested_only=False, db_path=db_path)["operations"]
