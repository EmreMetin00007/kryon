"""Append-only signed coverage observations; legacy class flags are not proof."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hunter_coverage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    signature TEXT NOT NULL UNIQUE,
    signed_json TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_hunter_coverage_target ON hunter_coverage_events(target);
"""


def append_event(db_path: str, payload: dict, trust) -> None:
    signed = trust.attest(payload, "coverage-attempt")
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path, timeout=10) as conn:
        conn.executescript(_SCHEMA)
        conn.execute("INSERT OR IGNORE INTO hunter_coverage_events (target, signature, signed_json) VALUES (?, ?, ?)",
                     (payload["target"], signed["signature"],
                      json.dumps(signed, sort_keys=True, separators=(",", ":"))))


def read_events(db_path: str, target: str, trust) -> list[dict]:
    if not Path(db_path).is_file():
        return []
    try:
        with sqlite3.connect(db_path) as conn:
            if target:
                rows = conn.execute("SELECT signed_json FROM hunter_coverage_events WHERE target=? ORDER BY id", (target,)).fetchall()
            else:
                rows = conn.execute("SELECT signed_json FROM hunter_coverage_events ORDER BY id").fetchall()
    except sqlite3.Error:
        return []
    events = []
    for (raw,) in rows:
        try:
            signed = json.loads(raw)
            payload = signed["payload"]
            if isinstance(payload, dict) and trust.verify(trust.canonical_bytes(payload), signed, "coverage-attempt"):
                events.append(payload)
        except (KeyError, TypeError, ValueError):
            continue
    return events
