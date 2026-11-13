#!/usr/bin/env python3
"""Target-session pointer store (workdir-local, pointer-only).

This is the TARGET session (the engagement account's cookie jar), not the
CCO program-context vault (`.cco/session-vault.json`). Only pointers live
here: an identity label plus a workdir-relative jar path. Passwords, cookie
values, and tokens are never stored — `save_session` refuses them.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

SESSION_FILENAME = "target-session.json"
_IDENTITY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
_POINTER_SEGMENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.~-]{0,63}")
_RECOVERY_PROCEDURE = (
    "recovery: (1) re-login with the SAME seeded account (single-account "
    "rule holds); (2) on login failure ONE re-seed is allowed; (3) record "
    "each attempt in the ledger with verdict session-recovery; "
    "(4) only then may auth-blocked vectors park as not_tested."
)

def session_path(workdir: str | Path) -> Path:
    return Path(workdir) / SESSION_FILENAME


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _pointer_shape_ok(pointer: str) -> bool:
    if not pointer or len(pointer) > 256 or "\\" in pointer:
        return False
    candidate = Path(pointer)
    if candidate.is_absolute() or ".." in candidate.parts:
        return False
    parts = pointer.split("/")
    if not 1 <= len(parts) <= 8:
        return False
    if not all(_POINTER_SEGMENT_RE.fullmatch(part) for part in parts):
        return False
    return "." in parts[-1]


def _contained(workdir: str | Path, pointer: str) -> bool:
    base = Path(workdir).resolve()
    try:
        resolved = (base / pointer).resolve()
    except OSError:
        return False
    return resolved == base or base in resolved.parents


def save_session(workdir: str | Path, identity: str, jar_pointer: str) -> dict:
    """Persist a session pointer; refuse secret values and path escapes."""
    label = (identity or "").strip()
    pointer = (jar_pointer or "").strip()
    if not _IDENTITY_RE.fullmatch(label):
        raise ValueError("session identity must be a short label "
                         "(letter start, <=32 chars), not a secret value")
    if not _pointer_shape_ok(pointer):
        raise ValueError("session jar_pointer must be a workdir-relative "
                         "jar path, not a secret value")
    if not _contained(workdir, pointer):
        raise ValueError("session jar_pointer escapes the workdir")
    data = {"identity": label, "jar_pointer": pointer,
            "updated_at": _utc_now()}
    target = session_path(workdir)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")
    return data


def load_session(workdir: str | Path) -> dict | None:
    """Return the stored pointer, or None when missing/broken."""
    target = session_path(workdir)
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if not data.get("identity") or not data.get("jar_pointer"):
        return None
    return data


def session_status(workdir: str | Path) -> dict:
    """Pointer health: ok | missing | stale | broken, plus recovery text."""
    target = session_path(workdir)
    if not target.is_file():
        return {"state": "missing",
                "detail": f"{SESSION_FILENAME} not found in workdir",
                "recovery": _RECOVERY_PROCEDURE}
    stored = load_session(workdir)
    if stored is None:
        return {"state": "broken",
                "detail": f"{SESSION_FILENAME} is invalid JSON or schema",
                "recovery": _RECOVERY_PROCEDURE}
    jar = Path(workdir) / stored["jar_pointer"]
    if not (jar.is_symlink() or jar.exists()):
        return {"state": "stale",
                "detail": f"jar pointer missing: {stored['jar_pointer']}",
                "recovery": _RECOVERY_PROCEDURE}
    if not _contained(workdir, stored["jar_pointer"]):
        return {"state": "broken",
                "detail": f"jar pointer escapes workdir: "
                          f"{stored['jar_pointer']}",
                "recovery": _RECOVERY_PROCEDURE}
    if not jar.is_file():
        return {"state": "stale",
                "detail": f"jar pointer unreadable: {stored['jar_pointer']}",
                "recovery": _RECOVERY_PROCEDURE}
    return {"state": "ok", "detail": f"identity={stored['identity']}",
            "recovery": _RECOVERY_PROCEDURE}
