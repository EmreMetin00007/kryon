#!/usr/bin/env python3
"""Stuck-detector: tekrar eden canli-hedef yoklamalarinda reflexion zorunlulugu.

Gozlem (ApexCore session, 2026-09-16): agent dogru bypass + dogru path'lerle
404 alinca hipotez degistirmek yerine wordlist buyuttu (raft-small -> large,
~1M istek ayni endpoint'e) ve reasoning tool'larini HIC cagirmadi.

Bu modul policy gate'in icinden calisir: her canli-hedef cagrisini
(action-class, host, path) ile imzalar; pencere icinde esik asilinca
reasoning receipt (herhangi bir `reasoning_*` tool cagrisi) gelmeden
yeni cagriyi bloklar. Blok mesaji ajana ne yapacagini soyler.

Kapsam: yalnizca URL/hedef iceren cagrilar izlenir (canli yoklama).
Sonuc bilinmez (gate pre-execution calisir) — tekrar sayisi proxy'dir.
Guvenlik siniri DEGIL, kalite korkulugu: hata durumunda fail-open.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

RECEIPT_PREFIX = "reasoning_"

# Kabuk kokenli trafik tek kovada toplanir: agent ayni endpoint'i
# bash/python ile yokluyorsa komut metni degisse de ayni imzadir.
SHELL_PROBE_TOOLS = frozenset({
    "bash",
    "shell_exec",
    "python_exec",
    "kali-tools_shell_exec",
    "kali-tools_python_exec",
    "webfetch",
})

PATH_SEGMENTS = 3


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def enabled() -> bool:
    return os.environ.get("CCO_STUCK_ENABLED", "1").strip().lower() not in {
        "0", "false", "no", "off"}


def threshold() -> int:
    return _env_int("CCO_STUCK_THRESHOLD", 10)


def window_minutes() -> int:
    return _env_int("CCO_STUCK_WINDOW_MINUTES", 30)


def is_receipt_tool(tool_name: str) -> bool:
    return (tool_name or "").startswith(RECEIPT_PREFIX)


def action_class(tool_name: str) -> str:
    if (tool_name or "") in SHELL_PROBE_TOOLS:
        return "shell-probe"
    return tool_name or "unknown"


def _endpoint_key(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = (parsed.netloc or "").lower()
    if not host:
        return None
    segs = [s for s in parsed.path.split("/") if s][:PATH_SEGMENTS]
    return f"{host}/{'/'.join(segs)}"


def signature_for(tool_name: str, urls: list[str] | None,
                  targets: list[str] | None) -> str | None:
    """Canli-hedef cagrisi icin kova imzasi; hedef yoksa None (izlenmez)."""
    cls = action_class(tool_name)
    for url in urls or []:
        key = _endpoint_key(str(url))
        if key:
            return f"{cls}|{key}"
    for target in targets or []:
        target = str(target).strip().lower()
        if target:
            return f"{cls}|{target}|"
    return None


def _ensure_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS stuck_probes ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
        "signature TEXT NOT NULL)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS stuck_receipts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
        "tool TEXT NOT NULL)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_stuck_probes_sig_ts "
        "ON stuck_probes(signature, ts)")
    conn.commit()


def record_receipt(conn: sqlite3.Connection, tool_name: str) -> None:
    _ensure_tables(conn)
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(minutes=window_minutes())).isoformat()
    conn.execute("DELETE FROM stuck_receipts WHERE ts <= ?", (cutoff,))
    conn.execute(
        "INSERT INTO stuck_receipts (ts, tool) VALUES (?, ?)",
        (now.isoformat(), tool_name))
    conn.commit()


def evaluate_probe(conn: sqlite3.Connection, tool_name: str,
                   urls: list[str] | None,
                   targets: list[str] | None) -> tuple[bool, str]:
    """Gate karari: (allowed, detail).

    Yan etki: receipt ise makbuz yazar; izin verilen yoklama sayaca
    islenir; bloklanan cagri sayaca islenmez (bütce tuketmez).
    """
    if not enabled():
        return True, ""
    if is_receipt_tool(tool_name):
        try:
            record_receipt(conn, tool_name)
        except Exception:
            pass
        return True, ""
    signature = signature_for(tool_name, urls, targets)
    if not signature:
        return True, ""
    try:
        _ensure_tables(conn)
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=window_minutes())
        conn.execute("DELETE FROM stuck_probes WHERE ts <= ?",
                     (window_start.isoformat(),))
        row = conn.execute(
            "SELECT MAX(ts) FROM stuck_receipts WHERE ts > ?",
            (window_start.isoformat(),)).fetchone()
        floor = row[0] if row and row[0] else window_start.isoformat()
        count = conn.execute(
            "SELECT COUNT(*) FROM stuck_probes "
            "WHERE signature = ? AND ts > ?",
            (signature, floor)).fetchone()[0]
        limit = threshold()
        if count >= limit:
            endpoint = signature.split("|", 1)[1] if "|" in signature else signature
            detail = (
                f"{count} similar live-target probes to '{endpoint}' in the "
                f"last {window_minutes()}m with no reasoning step. "
                f"STOP repeating this probe family. Call "
                f"reasoning_reason_reflexion(task, target, context) with a NEW "
                f"hypothesis (or reasoning_plan_attack_tree / "
                f"reasoning_next_best_action), record the failed hypothesis via "
                f"reasoning_record_lesson(worked=false), then retry. "
                f"Bigger wordlists or reworded identical probes stay blocked."
            )
            conn.commit()
            return False, detail
        conn.execute(
            "INSERT INTO stuck_probes (ts, signature) VALUES (?, ?)",
            (now.isoformat(), signature))
        conn.commit()
        return True, ""
    except Exception:
        # Kalite korkulugu gate'i asla dusurmez.
        return True, ""
