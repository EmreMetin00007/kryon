#!/usr/bin/env python3
"""Preview or explicitly bind selected legacy finding IDs to one engagement.

Legacy rows and artifacts are never deleted. Only exact, scope-confirmed
identity matches are linked. The preview prints IDs and hashes, not payloads.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
from pathlib import Path

try:
    from .runtime_paths import runtime_root
    from .policy_engine import ScopeResolver
    from .target_identity import finding_context_key
except ImportError:
    from runtime_paths import runtime_root
    from policy_engine import ScopeResolver
    from target_identity import finding_context_key


def _memory_module():
    path = runtime_root() / "mcp-servers" / "mcp-memory-server" / "server.py"
    spec = importlib.util.spec_from_file_location("cco_finding_migration_memory", path)
    if not spec or not spec.loader:
        raise RuntimeError("memory server unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def migrate_findings(db_path: Path, memory, resolver, ids: list[int] | None = None,
                     *, apply: bool = False) -> dict:
    """Build a fresh plan under a transaction; bind only explicitly selected IDs."""
    db = Path(db_path).expanduser().resolve()
    if not db.is_file():
        raise ValueError("existing memory database required")
    selected = sorted(set(ids or []))
    if len(selected) > 500 or any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in selected):
        raise ValueError("provide at most 500 positive finding IDs")
    if apply and not selected:
        raise ValueError("--apply requires explicitly selected --ids")
    if not getattr(memory, "validator_artifact_is_current", None):
        raise RuntimeError("validator evidence module unavailable")
    scope_path = resolver._engine.scope_file
    if not scope_path or not Path(scope_path).is_file():
        raise ValueError("readable active scope required")
    active_scope = os.environ.get("CCO_SCOPE_FILE", "")
    if (not os.environ.get("CCO_ENGAGEMENT_ID", "").strip() or not os.environ.get("CCO_WORKDIR", "").strip()
            or not active_scope or Path(active_scope).expanduser().resolve() != Path(scope_path).resolve()):
        raise ValueError("explicit engagement, workdir and matching active scope are required")
    scope_digest = hashlib.sha256(Path(scope_path).read_bytes()).hexdigest()
    resolver = ScopeResolver(scope_file=scope_path,
                             program_policy_file=resolver._engine.program_policy_file)
    if hashlib.sha256(Path(scope_path).read_bytes()).hexdigest() != scope_digest:
        raise ValueError("scope changed before migration")
    scope_before = memory._validator_mod.current_scope_revision()
    context_key = finding_context_key(scope_before)
    if scope_before in {"scope:missing", "scope:unreadable"}:
        raise ValueError("readable active scope required")
    uri = db.as_uri() + ("?mode=rw" if apply else "?mode=ro")
    conn = sqlite3.connect(uri, uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        if apply:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("CREATE TABLE IF NOT EXISTS finding_identity "
                         "(identity_key TEXT PRIMARY KEY, finding_id INTEGER NOT NULL UNIQUE, "
                         "context_key TEXT NOT NULL DEFAULT '')")
            columns = {row[1] for row in conn.execute("PRAGMA table_info(finding_identity)")}
            if "context_key" not in columns:
                conn.execute("ALTER TABLE finding_identity ADD COLUMN context_key TEXT NOT NULL DEFAULT ''")
            conn.execute("CREATE TABLE IF NOT EXISTS finding_aliases "
                         "(alias_id INTEGER PRIMARY KEY, canonical_id INTEGER NOT NULL, "
                         "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        try:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(finding_identity)")}
            fields = "identity_key, finding_id, context_key" if "context_key" in columns else "identity_key, finding_id, ''"
            identities = {row[0]: (int(row[1]), row[2]) for row in conn.execute(
                f"SELECT {fields} FROM finding_identity")}
        except sqlite3.OperationalError:
            identities = {}
        try:
            aliases = {int(row[0]): int(row[1]) for row in conn.execute(
                "SELECT alias_id, canonical_id FROM finding_aliases")}
        except sqlite3.OperationalError:
            aliases = {}
        rows = conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
        by_id = {int(row["id"]): row for row in rows}
        if selected and any(item not in by_id for item in selected):
            raise ValueError("one or more selected IDs do not exist")
        grouped: dict[str, list[int]] = {}
        skipped = 0
        for row in rows:
            rid = int(row["id"])
            if selected and rid not in selected:
                continue
            if rid in aliases:
                skipped += 1
                continue
            target = str(row["target"] or "")
            # Bare host labels are ambiguous about scheme and port.
            if "://" not in target or not resolver.permits_url(target):
                skipped += 1
                continue
            key = memory._finding_identity_key(target, row["type"], row["description"], row["payload"])
            if not key:
                skipped += 1
                continue
            grouped.setdefault(key, []).append(rid)
        groups = []
        for key, members in sorted(grouped.items()):
            def preference(rid: int):
                row = dict(by_id[rid])
                artifact = row.get("validation_artifact") or ""
                if row.get("reportable") and artifact:
                    metadata = memory._extract_validation_metadata(
                        "", validation_artifact_path=artifact,
                        finding_target=row["target"], finding_type=row["type"])
                    if metadata.get("reportable"):
                        return (0, rid)
                return (1, rid)

            previous = identities.get(key)
            canonical = previous[0] if previous else min(members, key=preference)
            if previous and previous[1] not in ("", context_key):
                raise ValueError("existing finding belongs to another context")
            if apply and previous and not previous[1] and canonical not in members:
                raise ValueError("unbound canonical finding must be explicitly selected")
            current = by_id.get(canonical)
            if current is None or memory._finding_identity_key(
                    current["target"], current["type"], current["description"], current["payload"]) != key:
                raise ValueError("existing canonical identity is inconsistent")
            groups.append({"identity_hash": key, "selected_ids": members, "canonical_id": canonical})
            if apply:
                conn.execute("INSERT OR IGNORE INTO finding_identity (identity_key, finding_id, context_key) VALUES (?, ?, ?)",
                             (key, canonical, context_key))
                conn.execute("UPDATE finding_identity SET context_key=? WHERE identity_key=? AND finding_id=? AND context_key=''",
                             (context_key, key, canonical))
                actual = conn.execute("SELECT finding_id, context_key FROM finding_identity WHERE identity_key=?", (key,)).fetchone()
                if not actual or int(actual[0]) != canonical or actual[1] != context_key:
                    raise ValueError("conflicting finding identity")
                for rid in members:
                    if rid != canonical:
                        conn.execute("INSERT OR IGNORE INTO finding_aliases (alias_id, canonical_id) VALUES (?, ?)",
                                     (rid, canonical))
                        linked = conn.execute("SELECT canonical_id FROM finding_aliases WHERE alias_id=?", (rid,)).fetchone()
                        if not linked or int(linked[0]) != canonical:
                            raise ValueError("conflicting finding alias")
        if (memory._validator_mod.current_scope_revision() != scope_before or
                hashlib.sha256(Path(scope_path).read_bytes()).hexdigest() != scope_digest):
            raise ValueError("scope changed during migration")
        if apply:
            conn.commit()
        return {"mode": "applied" if apply else "preview", "groups": groups, "skipped": skipped}
    except Exception:
        if apply:
            conn.rollback()
        raise
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cco-home", required=True)
    parser.add_argument("--scope-file", required=True)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--ids", default="", help="Comma-separated legacy IDs; required with --apply")
    parser.add_argument("--apply", action="store_true", help="Bind only the specified IDs to this engagement")
    args = parser.parse_args(argv)
    try:
        if not args.engagement_id.strip():
            raise ValueError("engagement ID must not be empty")
        ids = [int(item.strip()) for item in args.ids.split(",") if item.strip()]
        os.environ["CCO_HOME"] = str(Path(args.cco_home).expanduser().resolve())
        os.environ["CCO_SCOPE_FILE"] = str(Path(args.scope_file).expanduser().resolve())
        os.environ["CCO_WORKDIR"] = str(Path(args.workdir).expanduser().resolve())
        os.environ["CCO_ENGAGEMENT_ID"] = args.engagement_id.strip()
        memory = _memory_module()
        resolver = ScopeResolver(scope_file=os.environ["CCO_SCOPE_FILE"])
        result = migrate_findings(Path(os.environ["CCO_HOME"]) / "agent_memory.db", memory, resolver, ids, apply=args.apply)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, sqlite3.Error, RuntimeError) as exc:
        print(f"finding migration: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
