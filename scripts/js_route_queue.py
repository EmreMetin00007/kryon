"""JS compose queue: composed {id} templates must be probed before diversion.

Gozlem (NexusWorks session ses_f53d59445ffe, 2026-09-16): agent
compose_js_routes ciktisinda `/users/{id}/profile` gordu, sonra JWT crack /
nmap :8081 / interactsh'e kacti. Sablon hic istenmedi.

Gate pre-execution: compose cagrisi kuyrugu doldurur; curl eslesen path'i
isaretler; jwt/nmap/ffuf/interactsh/hashcat ve jwt-bash, kuyruk bosalana
kadar bloklanir. Hata durumunda fail-open.
"""

from __future__ import annotations

import os
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse


DIVERSION_TOOLS = frozenset({
    "web-advanced_jwt_analyze",
    "web-advanced_jwt_none",
    "web-advanced_jwt_confusion",
    "web-advanced_jwt_attack_alg_none",
    "web-advanced_jwt_rs_to_hs_confusion",
    "web-advanced_jwt_brute_hs256",
    "web-advanced_jwt_attack_kid",
    "web-advanced_jwt_attack_jku",
    "web-advanced_jwt_kid_jku_verify",
    "kali-tools_nmap_scan",
    "kali-tools_nmap_scan_structured",
    "kali-tools_masscan_scan",
    "kali-tools_ffuf_fuzz",
    "kali-tools_gobuster_scan",
    "kali-tools_hydra_brute",
    "kali-tools_hashcat_crack",
    "kali-tools_john_crack",
    "kali-tools_interactsh_start",
    "kali-tools_interactsh_poll",
    "kali-tools_interactsh_stop",
})

BASH_DIVERSION_RE = re.compile(
    r"rockyou|hashcat|john\.|jwt|hmac|nmap|interactsh|wordlist|fastapi_fuzz|"
    r"hydra|gobuster|ffuf",
    re.I,
)

MAX_PENDING = 12
WINDOW_MINUTES = 120


def enabled() -> bool:
    return os.environ.get("CCO_JS_QUEUE_ENABLED", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


def hostname_of(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    try:
        parsed = urlparse(text)
    except ValueError:
        return ""
    return (parsed.hostname or "").lower()


def instantiate(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path)


def path_matches(pending: str, actual: str) -> bool:
    pending = (pending or "").rstrip("/") or "/"
    actual = (actual or "").rstrip("/") or "/"
    if pending == actual:
        return True
    rx = re.escape(pending)
    rx = rx.replace(r"\{id\}", r"[^/]+").replace(r"\{param\}", r"[^/]+")
    rx = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", rx)
    return re.fullmatch(rx, actual) is not None


def _ensure_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS js_route_pending ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
        "host TEXT NOT NULL, path TEXT NOT NULL, UNIQUE(host, path))"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_js_route_pending_host "
        "ON js_route_pending(host)"
    )
    conn.commit()


def _compose(source: str) -> dict:
    kali = Path(__file__).resolve().parents[1] / "mcp-servers" / "mcp-kali-tools"
    kali_s = str(kali)
    if kali_s not in sys.path:
        sys.path.insert(0, kali_s)
    from cco_js_core.compose import compose_js_routes  # type: ignore[import-not-found]
    return compose_js_routes(source or "")


def paths_to_enqueue(composed: dict) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for path in list(composed.get("templates") or []) + list(composed.get("composed") or []):
        path = str(path).strip()
        if not path.startswith("/") or path in seen:
            continue
        if "{id}" in path or "{param}" in path:
            seen.add(path)
            candidates.append(path)
    # Keep the longest template when one path extends another
    # (`/users/{id}/profile` covers `/users/{id}`).
    kept: list[str] = []
    for path in sorted(candidates, key=len, reverse=True):
        prefix = path.rstrip("/") + "/"
        if any(other.startswith(prefix) or other.startswith(path + "/") for other in kept):
            continue
        kept.append(path)
        if len(kept) >= MAX_PENDING:
            break
    return kept


def infer_host(conn: sqlite3.Connection, args: dict, urls: list[str],
               targets: list[str]) -> str:
    for candidate in (
        args.get("target"),
        args.get("base_url"),
        *(urls or []),
        *(targets or []),
    ):
        host = hostname_of(str(candidate or ""))
        if host:
            return host
    try:
        row = conn.execute(
            "SELECT target, targets_json FROM audit_log "
            "WHERE result='allowed' AND tool_name LIKE '%curl%' "
            "ORDER BY id DESC LIMIT 8"
        ).fetchall()
    except sqlite3.Error:
        row = []
    for target, extra in row:
        host = hostname_of(target or "")
        if host:
            return host
        try:
            import json
            for item in json.loads(extra or "[]"):
                host = hostname_of(str(item))
                if host:
                    return host
        except (TypeError, ValueError):
            continue
    return ""


def enqueue_from_source(conn: sqlite3.Connection, source: str, host: str) -> list[str]:
    if not host or not (source or "").strip():
        return []
    _ensure_tables(conn)
    paths = paths_to_enqueue(_compose(source))
    now = datetime.now(timezone.utc).isoformat()
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MINUTES)).isoformat()
    conn.execute("DELETE FROM js_route_pending WHERE ts <= ?", (cutoff,))
    for path in paths:
        conn.execute(
            "INSERT OR IGNORE INTO js_route_pending (ts, host, path) VALUES (?, ?, ?)",
            (now, host, path),
        )
    conn.commit()
    return paths


def header_hints_from_source(source: str) -> list[str]:
    """Observed `Name: value` header pairs from JS source (masked for secrets)."""
    try:
        result = _compose(source or "")
    except Exception:
        return []
    return [
        f"-H \"{name}: {value}\""
        for name, value in (result.get("header_values") or {}).items()
        if value and "***" not in value and "..." not in value
    ][:8]


def _store_header_hints(conn: sqlite3.Connection, host: str, source: str) -> None:
    if not host or not (source or "").strip():
        return
    conn.execute(
        "CREATE TABLE IF NOT EXISTS js_header_hints ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
        "host TEXT NOT NULL, hint TEXT NOT NULL)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_js_header_hints_host ON js_header_hints(host)")
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MINUTES)).isoformat()
    conn.execute("DELETE FROM js_header_hints WHERE ts <= ?", (cutoff,))
    for hint in header_hints_from_source(source):
        conn.execute(
            "INSERT INTO js_header_hints (ts, host, hint) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), host, hint),
        )
    conn.commit()


def _latest_header_hints(conn: sqlite3.Connection, hosts: list[str]) -> list[str]:
    try:
        wanted = {hostname_of(h) for h in hosts if hostname_of(h)}
        if not wanted:
            rows = conn.execute(
                "SELECT DISTINCT hint FROM js_header_hints ORDER BY id DESC LIMIT 8"
            ).fetchall()
            return [r[0] for r in rows]
        out: list[str] = []
        for host in wanted:
            rows = conn.execute(
                "SELECT DISTINCT hint FROM js_header_hints WHERE host = ? ORDER BY id DESC LIMIT 8",
                (host,),
            ).fetchall()
            out.extend(r[0] for r in rows)
        return out[:8]
    except sqlite3.Error:
        return []


def mark_probed(conn: sqlite3.Connection, urls: list[str] | None) -> int:
    _ensure_tables(conn)
    marked = 0
    for url in urls or []:
        try:
            parsed = urlparse(str(url))
        except ValueError:
            continue
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        if not host:
            continue
        rows = conn.execute(
            "SELECT id, path FROM js_route_pending WHERE host = ?", (host,)
        ).fetchall()
        for row_id, pending in rows:
            if path_matches(pending, path):
                conn.execute("DELETE FROM js_route_pending WHERE id = ?", (row_id,))
                marked += 1
    if marked:
        conn.commit()
    return marked


def pending_for(conn: sqlite3.Connection, hosts: list[str]) -> list[tuple[str, str]]:
    _ensure_tables(conn)
    wanted = {hostname_of(h) for h in hosts if hostname_of(h)}
    if not wanted:
        rows = conn.execute(
            "SELECT host, path FROM js_route_pending ORDER BY id"
        ).fetchall()
        return [(h, p) for h, p in rows]
    out: list[tuple[str, str]] = []
    for host in wanted:
        rows = conn.execute(
            "SELECT host, path FROM js_route_pending WHERE host = ? ORDER BY id",
            (host,),
        ).fetchall()
        out.extend((h, p) for h, p in rows)
    return out


def is_diversion(tool_name: str, args: dict | None) -> bool:
    name = tool_name or ""
    if name in DIVERSION_TOOLS:
        return True
    if name in {"bash", "kali-tools_shell_exec", "kali-tools_python_exec", "shell_exec", "python_exec"}:
        command = str((args or {}).get("command") or "")
        return bool(BASH_DIVERSION_RE.search(command))
    return False


def evaluate(conn: sqlite3.Connection, tool_name: str, args: dict | None,
             urls: list[str] | None, targets: list[str] | None) -> tuple[bool, str]:
    """(allowed, detail). Side effects: enqueue on compose, mark on curl."""
    if not enabled():
        return True, ""
    args = args or {}
    urls = list(urls or [])
    targets = list(targets or [])
    try:
        _ensure_tables(conn)
        if (tool_name or "").endswith("compose_js_routes") or tool_name == "compose_js_routes":
            host = infer_host(conn, args, urls, targets)
            source = str(args.get("source") or "")
            enqueue_from_source(conn, source, host)
            _store_header_hints(conn, host, source)
            return True, ""
        if urls:
            mark_probed(conn, urls)
        if not is_diversion(tool_name, args):
            return True, ""
        pending = pending_for(conn, targets + [hostname_of(u) for u in urls])
        if not pending:
            return True, ""
        probes = []
        for host, path in pending[:6]:
            probes.append(f"GET http://{host}{instantiate(path)}")
        hints = _latest_header_hints(conn, targets + [hostname_of(u) for u in urls])
        header_note = (
            " Send observed headers verbatim: " + " ".join(hints) if hints else ""
        )
        detail = (
            f"{len(pending)} composed JS route(s) are still unprobed. "
            "Do not JWT-crack, nmap sibling ports, fuzz wordlists, or start "
            "OOB listeners yet. Curl these first: " + "; ".join(probes)
            + header_note
        )
        return False, detail
    except Exception:
        return True, ""
