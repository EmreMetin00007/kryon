"""Şema sözleşmesi: paylaşılan tablolara (attack_surface, endpoints, findings)
doğrudan SQL yazan/okuyan HER modül cco_surface_core.schema kaydına uymalı.

Yakalar: sütun adı kayması (INSERT'te olmayan kolon, CREATE'te eksik kolon).
"""
from __future__ import annotations

import pathlib
import re
import sqlite3
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
MEM_DIR = REPO / "mcp-servers" / "mcp-memory-server"
sys.path.insert(0, str(MEM_DIR))

from cco_surface_core.schema import SHARED_TABLES  # noqa: E402

CREATE_RE = re.compile(
    r"CREATE TABLE IF NOT EXISTS (\w+)\s*\((.*?)\)\s*\"?;?", re.S | re.I)
INSERT_RE = re.compile(r"INSERT INTO (\w+)\s*\(([^)]*)\)", re.I)
UPDATE_RE = re.compile(r"UPDATE (\w+)\s+SET\s+([^W]+?)(?:WHERE|RETURNING|$)", re.S | re.I)


def _sql_text(path: pathlib.Path) -> str:
    raw = path.read_text(errors="ignore")
    return re.sub(r'"\s*"', "", raw)


def _sources() -> list[pathlib.Path]:
    roots = [REPO / "mcp-servers", REPO / "scripts"]
    return [p for r in roots for p in r.rglob("*.py") if "__pycache__" not in str(p)]


def _columns_of_create(body: str) -> set[str]:
    cols = set()
    for line in body.split(","):
        tok = line.strip().split()
        if not tok:
            continue
        name = tok[0].strip('"`[]')
        if not name:
            continue
        if name.upper() in {"PRIMARY", "UNIQUE", "KEY", "CONSTRAINT", "CHECK", "FOREIGN"}:
            continue
        cols.add(name)
    return cols


def test_create_literals_match_registry():
    created: dict[str, set[str]] = {}
    for path in _sources():
        text = _sql_text(path)
        for table, body in CREATE_RE.findall(text):
            if table in SHARED_TABLES:
                created.setdefault(table, set()).update(_columns_of_create(body))
    assert set(created) == set(SHARED_TABLES), f"CREATE yok: {set(SHARED_TABLES) - set(created)}"
    for table, expected in SHARED_TABLES.items():
        got = created.get(table, set())
        assert got == set(expected), f"{table}: CREATE={sorted(got)} sözleşme={sorted(expected)}"


def test_all_writes_use_registry_columns():
    violations = []
    for path in _sources():
        text = _sql_text(path)
        for table, cols in INSERT_RE.findall(text):
            if table in SHARED_TABLES:
                bad = [c.strip() for c in cols.split(",") if c.strip() not in SHARED_TABLES[table]]
                if bad:
                    violations.append(f"{path.name}: INSERT {table} {bad}")
        for table, sets in UPDATE_RE.findall(text):
            if table in SHARED_TABLES:
                bad = [a.split("=")[0].strip() for a in sets.split(",")
                       if a.split("=")[0].strip() not in SHARED_TABLES[table]]
                if bad:
                    violations.append(f"{path.name}: UPDATE {table} {bad}")
    assert not violations, "sözleşme dışı yazım:\n" + "\n".join(violations)


def test_registry_builds_live_schema():
    ddl = {
        "attack_surface": ",".join(f"{c} TEXT" for c in SHARED_TABLES["attack_surface"]),
        "endpoints": ",".join(f"{c} TEXT" for c in SHARED_TABLES["endpoints"]),
        "findings": ",".join(f"{c} TEXT" for c in SHARED_TABLES["findings"]),
    }
    conn = sqlite3.connect(":memory:")
    for t, cols in ddl.items():
        conn.execute(f"CREATE TABLE {t} ({cols})")
    for t, expected in SHARED_TABLES.items():
        live = {r[1] for r in conn.execute(f"PRAGMA table_info({t})")}
        assert live == set(expected), t
    conn.close()
