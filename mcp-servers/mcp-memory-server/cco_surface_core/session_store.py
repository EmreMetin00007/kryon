"""Target/account sessions backed by the existing encrypted credential vault.

The public index contains metadata and an opaque reference, never new session
material. Legacy plaintext entries remain readable and migrate when checked or
replaced; this module does not imply that the separate session-jar is encrypted.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

_VAULT_NAME = "session_vault.json"
_SCHEMA = "target-session/1"
_CREDENTIAL = re.compile(r"auth|cookie|token|session|credential|api[-_]?key", re.I)


def vault_path(home: str | None = None) -> Path:
    root = Path(home or os.environ.get("CCO_HOME") or Path.home() / ".cco")
    return root / _VAULT_NAME


@contextmanager
def _locked(home):
    path = vault_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _load(home: str | None = None) -> dict:
    path = vault_path(home)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("session index cannot be read") from exc
    if not isinstance(data, dict):
        raise ValueError("session index must be an object")
    return data


def _save(data: dict, home: str | None = None) -> Path:
    path = vault_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".session-index-", delete=False) as handle:
            temporary = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path


def _vault(home, *, create_key=True):
    from credential_vault import CredentialVault
    return CredentialVault(str(vault_path(home).parent), create_key=create_key)


def key_for(target: str, identity: str) -> str:
    return f"{(target or '').strip().rstrip('/')}::{identity or 'anon'}"


def _materialize(stored, home):
    if not isinstance(stored, dict):
        return None
    ref = stored.get("secret_ref")
    if not ref:
        return dict(stored)  # preexisting plaintext index; retained for compatibility
    try:
        payload = json.loads(_vault(home, create_key=False).get_secret(str(ref)))
    except Exception:
        return None
    if (not isinstance(payload, dict) or payload.get("schema") != _SCHEMA
            or payload.get("target") != stored.get("target")
            or payload.get("identity") != stored.get("identity")):
        return None
    return {**stored, **{key: payload.get(key) for key in ("headers", "cookies", "check_url", "marker", "test_resources")}}


def _encrypted_entry(entry, home):
    payload = {key: entry.get(key) for key in ("target", "identity", "headers", "cookies", "check_url", "marker", "test_resources")}
    payload["schema"] = _SCHEMA
    vault = _vault(home)
    ref = vault.store_secret("target_session", json.dumps(payload, ensure_ascii=False))
    stored = {key: entry.get(key) for key in ("target", "identity", "updated_at", "status", "checked_at")
              if key in entry}
    stored.update({"secret_ref": ref, "secret_backend": "fernet"})
    return stored, vault


def put_session(target: str, identity: str, *, headers: dict | None = None,
                cookies: dict | None = None, check_url: str = "",
                marker: str = "", home: str | None = None) -> dict:
    if not isinstance(headers or {}, dict) or not isinstance(cookies or {}, dict):
        raise ValueError("headers and cookies must be objects")
    raw_target = str(target or "").strip()
    if not raw_target or any(char in raw_target for char in "?#\r\n\x00"):
        raise ValueError("target must not contain query or fragment")
    if "://" in raw_target and not _origin(raw_target):
        raise ValueError("target must be an HTTP origin without userinfo")
    if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", identity or "anon"):
        raise ValueError("identity must be a short label")
    entry = {
        "target": raw_target, "identity": identity or "anon",
        "headers": dict(headers or {}), "cookies": dict(cookies or {}),
        "check_url": check_url, "marker": marker,
        "updated_at": int(time.time()), "status": "unknown",
    }
    with _locked(home):
        data = _load(home)
        key = key_for(raw_target, identity)
        old_ref = (data.get(key) or {}).get("secret_ref")
        stored, vault = _encrypted_entry(entry, home)
        try:
            data[key] = stored
            _save(data, home)
        except Exception:
            vault.delete_secret(stored["secret_ref"])
            raise
        if old_ref:
            vault.delete_secret(old_ref)
    return summarize(entry)


def get_session(target: str, identity: str = "anon", home: str | None = None) -> dict | None:
    try:
        return _materialize(_load(home).get(key_for(target, identity)), home)
    except (OSError, ValueError):
        return None


def bind_resources(target: str, identity: str, resources: dict, *, permits,
                   home: str | None = None) -> dict:
    """Attach declarations without copying credentials through public arguments.

    An edit clears freshness. Idempotent rebinding leaves a valid check intact.
    Replacing a session with put_session deliberately clears its declarations.
    """
    from .test_resources import normalize_resources
    if not callable(permits) or not permits(target):
        raise ValueError("invalid declared test resources")
    normalized = normalize_resources(target, resources, permits)
    with _locked(home):
        data = _load(home)
        key = key_for(target, identity)
        previous = data.get(key)
        entry = _materialize(previous, home)
        if not entry or entry.get("target") != target or entry.get("identity") != identity:
            raise ValueError("session unavailable for resource binding")
        if entry.get("test_resources") == normalized:
            return summarize(entry)
        entry = {**entry, "test_resources": normalized, "status": "unknown", "updated_at": int(time.time())}
        entry.pop("checked_at", None)
        stored, vault = _encrypted_entry(entry, home)
        try:
            data[key] = stored
            _save(data, home)
        except Exception:
            vault.delete_secret(stored["secret_ref"])
            raise
        if previous.get("secret_ref"):
            vault.delete_secret(previous["secret_ref"])
    return summarize(entry)


def _attestation(entry, home):
    fields = [entry.get(key) for key in ("target", "identity", "secret_ref", "status", "checked_at")]
    prefix = b"target-session-check/1\x00"
    if "check_id" in entry:
        if not isinstance(entry["check_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", entry["check_id"]):
            raise ValueError("invalid session check identifier")
        fields.append(entry["check_id"])
        prefix = b"target-session-check/2\x00"
    if "checked_at_ns" in entry:
        checked_ns = entry["checked_at_ns"]
        if ("check_id" not in entry or isinstance(checked_ns, bool) or not isinstance(checked_ns, int)
                or not int(entry["checked_at"]) * 10**9 <= checked_ns < (int(entry["checked_at"]) + 1) * 10**9):
            raise ValueError("invalid session check timestamp")
        fields.append(checked_ns)
        prefix = b"target-session-check/3\x00"
    message = prefix + json.dumps(fields, separators=(",", ":")).encode()
    return hmac.new(_vault(home, create_key=False).key, message, hashlib.sha256).hexdigest()


def check_fingerprint(target: str, identity: str, *, home: str | None = None,
                      entry: dict | None = None) -> str:
    """Opaque check/version reference; this is never a freshness attestation."""
    stored = entry if entry is not None else _load(home).get(key_for(target, identity))
    if stored is not None and (not isinstance(stored, dict) or stored.get("target") != target
                               or stored.get("identity") != identity):
        raise ValueError("session binding mismatch")
    fields = [target, identity, *[(stored or {}).get(key) for key in
              ("secret_ref", "status", "checked_at", "checked_at_ns", "check_id", "verification")]]
    return hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest()


def verified_session(target: str, identity: str, *, home: str | None = None,
                     max_age: int = 300) -> dict | None:
    """Resolve only a recent attested check for this account's current secret."""
    entry = get_session(target, identity, home)
    if not entry or entry.get("target") != target or entry.get("identity") != identity:
        return None
    try:
        checked = int(entry.get("checked_at") or 0)
        age = time.time() - checked
        if (entry.get("status") != "fresh" or not entry.get("secret_ref")
                or age < -5 or age > max_age or not isinstance(entry.get("verification"), str)):
            return None
        if not hmac.compare_digest(entry["verification"], _attestation(entry, home)):
            return None
    except (TypeError, ValueError, OSError):
        return None
    return entry


def same_verified_session(target: str, identity: str, expected: dict, *, home: str | None = None,
                          max_age: int = 300) -> bool:
    """Detect rotation, failed checks and expiry without exposing credentials."""
    try:
        stored = _load(home).get(key_for(target, identity))
        if not isinstance(stored, dict):
            return False
        return (all(stored.get(key) == expected.get(key) for key in
                    ("target", "identity", "secret_ref", "status", "checked_at", "checked_at_ns", "check_id", "verification"))
                and stored.get("status") == "fresh"
                and -5 <= time.time() - int(stored.get("checked_at") or 0) <= max_age)
    except (OSError, TypeError, ValueError):
        return False


def summarize(entry: dict | None) -> dict:
    if not entry:
        return {"present": False}
    return {
        "present": True, "target": entry.get("target"), "identity": entry.get("identity"),
        "header_keys": sorted((entry.get("headers") or {}).keys()),
        "cookie_keys": sorted((entry.get("cookies") or {}).keys()),
        "status": entry.get("status", "unknown"), "updated_at": entry.get("updated_at"),
        "has_check": bool(entry.get("check_url") and entry.get("marker")),
        "has_test_resources": bool(entry.get("test_resources")),
    }


def _origin(url):
    try:
        parsed = urlsplit(str(url or ""))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
            return None
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme.lower() == "https" else 80)
        return (parsed.scheme.lower(), parsed.hostname.lower(), port) if port > 0 else None
    except ValueError:
        return None


def probe_session(entry: dict, http_get) -> dict:
    """Make at most one caller-gated GET; a marker never overrides HTTP failure."""
    url, marker = entry.get("check_url", ""), entry.get("marker", "")
    if not isinstance(marker, str) or not marker or not url:
        return {"status": "unknown", "reason": "check_url/marker missing"}
    if not _origin(entry.get("target")) or _origin(entry.get("target")) != _origin(url):
        return {"status": "blocked", "reason": "origin_mismatch_or_unbound"}
    headers, cookies = entry.get("headers") or {}, entry.get("cookies") or {}
    if not isinstance(headers, dict) or not isinstance(cookies, dict):
        return {"status": "blocked", "reason": "invalid_session_material"}
    header_names = [str(name).lower() for name in headers]
    if (len(header_names) != len(set(header_names))
            or any(not re.fullmatch(r"[A-Za-z0-9-]{1,80}", str(name))
                   or str(name).lower() in {"host", "proxy-authorization", "content-length", "transfer-encoding"}
                   or any(char in str(value) for char in "\r\n\x00") for name, value in headers.items())
            or any(not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", str(name))
                   or any(char in str(value) for char in ";\r\n\x00") for name, value in cookies.items())):
        return {"status": "blocked", "reason": "invalid_session_material"}
    if cookies and any(str(key).lower() == "cookie" for key in headers):
        return {"status": "blocked", "reason": "ambiguous_cookie_sources"}
    if not cookies and not any(_CREDENTIAL.search(str(key)) and str(value).strip()
                               for key, value in headers.items()):
        return {"status": "blocked", "reason": "credential_missing"}
    try:
        status, body = http_get(url, dict(headers), dict(cookies))
    except PermissionError:
        return {"status": "blocked", "reason": "policy_denied"}
    except Exception as exc:
        return {"status": "stale", "reason": f"probe_error:{type(exc).__name__}"}
    if status == 401:
        return {"status": "expired", "reason": "http_401"}
    if status == 429:
        return {"status": "rate_limited", "reason": "http_429"}
    if status in (301, 302, 303, 307, 308):
        return {"status": "blocked", "reason": "redirect_not_followed"}
    if status != 200:
        return {"status": "stale", "reason": "unexpected_http_status"}
    found = isinstance(body, str) and marker in body
    return {"status": "fresh" if found else "stale", "reason": "marker_found" if found else "marker_missing"}


def refresh_status(target: str, identity: str, http_get, home: str | None = None) -> dict:
    key = key_for(target, identity)
    try:
        snapshot = _load(home).get(key)
        entry = _materialize(snapshot, home)
    except (OSError, ValueError):
        entry, snapshot = None, None
    if not entry:
        return {"present": False, "status": "missing", "action": "human_needed: session unavailable"}
    if entry.get("target") != target or entry.get("identity") != identity:
        return {"present": True, "status": "blocked", "reason": "session_binding_mismatch",
                "action": "human_needed: session not verified"}
    verdict = probe_session(entry, http_get)
    try:
        with _locked(home):
            data = _load(home)
            if data.get(key) != snapshot:
                return {"present": True, "status": "superseded", "reason": "session_replaced_during_check",
                        "action": "human_needed: check the new session"}
            if not snapshot.get("secret_ref"):
                snapshot, vault = _encrypted_entry(entry, home)
            else:
                snapshot, vault = dict(snapshot), None
            snapshot["status"] = verdict["status"]
            checked_ns = time.time_ns()
            snapshot["checked_at"] = checked_ns // 10**9
            snapshot.pop("verification", None)
            snapshot.pop("check_id", None)
            snapshot.pop("checked_at_ns", None)
            if verdict["status"] == "fresh":
                snapshot["checked_at_ns"] = checked_ns
                snapshot["check_id"] = secrets.token_hex(16)
                snapshot["verification"] = _attestation(snapshot, home)
            data[key] = snapshot
            try:
                _save(data, home)
            except Exception:
                if vault:
                    vault.delete_secret(snapshot["secret_ref"])
                raise
    except (OSError, ValueError):
        return {"present": True, "status": "blocked", "reason": "session_index_unavailable",
                "action": "human_needed: session check was not saved"}
    entry["status"] = verdict["status"]
    out = summarize(entry)
    out.update(verdict)
    if verdict["status"] == "fresh":
        out["action"] = "ok"
    elif verdict["status"] == "rate_limited":
        out["action"] = "wait_and_reassess: rate limit observed"
    else:
        out["action"] = "human_needed: session not verified"
    return out
