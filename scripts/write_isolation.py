"""Run-scoped, expiring Ed25519 write-isolation attestation for mutating checks."""
from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import evidence_trust as trust

SCHEMA = "write-isolation-attestation/1"
PURPOSE = "write-isolation"
DEFAULT_TTL_SECONDS = 900.0
MAX_TTL_SECONDS = 86400.0


def canonical_origin(url: str) -> str:
    """Return canonical scheme://host:port origin for http(s) URLs, else ''."""
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ""
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
        return ""
    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    if port <= 0:
        return ""
    return f"{scheme}://{parsed.hostname.lower()}:{port}"


def issue_attestation(
    target_origin: str,
    run_id: str,
    *,
    ttl_seconds: float = DEFAULT_TTL_SECONDS,
    scope_revision: str = "",
    policy_hash: str = "",
    test_data_only: bool = True,
    now: float | None = None,
) -> dict[str, Any]:
    """Issue a host-signed, run-scoped write-isolation attestation envelope."""
    origin = canonical_origin(target_origin)
    if not origin:
        raise ValueError("valid target_origin required")
    rid = str(run_id or "").strip()
    if not rid:
        raise ValueError("run_id required")
    if test_data_only is not True:
        raise ValueError("write isolation requires synthetic test_data_only=True")
    ttl = float(ttl_seconds)
    if not math.isfinite(ttl) or ttl <= 0 or ttl > MAX_TTL_SECONDS:
        raise ValueError("ttl_seconds must be in (0, 86400]")
    issued_at = float(time.time() if now is None else now)
    if not math.isfinite(issued_at):
        raise ValueError("finite issued_at required")
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "target_origin": origin,
        "run_id": rid,
        "issued_at": issued_at,
        "expires_at": issued_at + ttl,
        "test_data_only": True,
    }
    if scope_revision:
        payload["scope_revision"] = str(scope_revision)
    if policy_hash:
        payload["policy_hash"] = str(policy_hash)
    return trust.attest(payload, PURPOSE)


def _load_attestation(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, (str, Path)):
        raw = str(value).strip()
        if not raw:
            return None
        if raw.startswith("{"):
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else None
            except ValueError:
                return None
        try:
            path = Path(raw).expanduser().resolve(strict=True)
            if path.is_symlink():
                return None
            parsed = json.loads(path.read_text(encoding="utf-8"))
            return parsed if isinstance(parsed, dict) else None
        except (OSError, ValueError):
            return None
    return None


def verify_attestation(
    attestation: Any,
    *,
    expected_origin: str,
    expected_run_id: str,
    expected_scope_revision: str = "",
    expected_policy_hash: str = "",
    now: float | None = None,
) -> tuple[bool, str]:
    """Fail-closed verification of write-isolation attestation against origin, run_id, and freshness."""
    envelope = _load_attestation(attestation)
    if not isinstance(envelope, dict):
        return False, "write_isolation_unattested:missing"
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        return False, "write_isolation_unattested:invalid_schema"
    if not trust.verify(trust.canonical_bytes(payload), envelope, PURPOSE):
        return False, "write_isolation_unattested:invalid_signature"
    if payload.get("test_data_only") is not True:
        return False, "write_isolation_unattested:test_data_required"
    want_origin = canonical_origin(expected_origin)
    got_origin = canonical_origin(str(payload.get("target_origin") or ""))
    if not want_origin or not got_origin or got_origin != want_origin:
        return False, "write_isolation_unattested:wrong_origin"
    want_run = str(expected_run_id or "").strip()
    got_run = str(payload.get("run_id") or "").strip()
    if not want_run or not got_run or got_run != want_run:
        return False, "write_isolation_unattested:wrong_run"
    issued_at = payload.get("issued_at")
    expires_at = payload.get("expires_at")
    now_ts = float(time.time() if now is None else now)
    if (
        isinstance(issued_at, bool)
        or isinstance(expires_at, bool)
        or not isinstance(issued_at, (int, float))
        or not isinstance(expires_at, (int, float))
        or not math.isfinite(float(issued_at))
        or not math.isfinite(float(expires_at))
        or float(expires_at) <= float(issued_at)
        or float(issued_at) > now_ts + 5.0
        or now_ts > float(expires_at)
    ):
        return False, "write_isolation_unattested:stale"
    if expected_scope_revision and payload.get("scope_revision") and payload.get("scope_revision") != expected_scope_revision:
        return False, "write_isolation_unattested:scope_mismatch"
    if expected_policy_hash and payload.get("policy_hash") and payload.get("policy_hash") != expected_policy_hash:
        return False, "write_isolation_unattested:policy_mismatch"
    return True, ""
