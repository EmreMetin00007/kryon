"""Encrypted capture references; SQLite owns links, the existing vault owns values.

Saving a capture grants no permission to execute its method. Readers must still
use the caller's wire policy, and recheck the reference before every request.
"""
from __future__ import annotations

import copy
import base64
import hashlib
import hmac
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import time
from urllib.parse import urlsplit

from . import session_store

SCHEMA_SQL = """CREATE TABLE IF NOT EXISTS surface_request_bindings (
    capture_ref TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
    operation_id TEXT NOT NULL, observation_id INTEGER NOT NULL,
    secret_ref TEXT NOT NULL, metadata_json TEXT NOT NULL,
    UNIQUE(fingerprint, observation_id))"""
_CREDENTIAL = re.compile(r"auth|cookie|token|session|credential|api[-_]?key|csrf|xsrf|password|secret", re.I)
_TENANT = re.compile(r"tenant", re.I)
_TTL = 3600


def _versions():
    scripts = str(Path(__file__).resolve().parents[3] / "scripts")
    validator = str(Path(__file__).resolve().parents[2] / "mcp-validator")
    for path in (scripts, validator):
        if path not in sys.path:
            sys.path.insert(0, path)
    from policy_engine import ScopeResolver
    from cco_validator_core.evidence import current_scope_revision, current_policy_hash
    revision, policy = current_scope_revision(), current_policy_hash()
    if not all(re.fullmatch(r"sha256:[a-f0-9]{64}", value) for value in (revision, policy)):
        raise ValueError("capture requires explicit readable scope and policy revisions")
    return ScopeResolver(), revision, policy


def _vault(home):
    from credential_vault import CredentialVault
    return CredentialVault(str(home), create_key=False)


def canonical_request(request):
    """Preserve complete values in an encrypted packet, including long documents."""
    headers = request.get("req_headers") or request.get("headers") or {}
    if not isinstance(headers, dict):
        raise ValueError("capture headers must be an object")
    headers = {str(k).lower(): str(v) for k, v in headers.items()}
    body = request.get("req_body", request.get("post_data", request.get("body", "")))
    ctype = str(request.get("content_type") or request.get("contentType") or headers.get("content-type") or "")
    if ctype:
        headers.setdefault("content-type", ctype)
    encoding = {"body_encoding": "base64"} if request.get("body_encoding") == "base64" else {}
    if encoding:
        if not isinstance(body, str):
            raise ValueError("encoded capture body must be a string")
        base64.b64decode(body, validate=True)
    if isinstance(body, bytes):
        body = base64.b64encode(body).decode()
        encoding["body_encoding"] = "base64"
    if isinstance(body, str) and not encoding and ("json" in ctype or body.lstrip().startswith(("{", "["))):
        try:
            body = json.loads(body)
        except ValueError:
            pass
    return {"url": str(request.get("url") or ""), "method": str(request.get("method") or "GET").upper(),
            "headers": headers, "body": copy.deepcopy(body), "content_type": ctype, **encoding}


def _same_origin(left, right):
    try:
        a, b = urlsplit(left), urlsplit(right)
        def origin(p):
            return p.scheme.lower(), p.hostname, p.port or (443 if p.scheme == "https" else 80)
        return (a.scheme in {"http", "https"} and b.scheme in {"http", "https"}
                and a.username is None and b.username is None and origin(a) == origin(b))
    except ValueError:
        return False


def _check_session_headers(entry, headers):
    expected = {str(k).lower(): str(v) for k, v in (entry.get("headers") or {}).items()}
    if any(headers.get(k) != v for k, v in expected.items()):
        raise ValueError("capture headers do not match the verified session")
    cookies = SimpleCookie()
    try:
        cookies.load(headers.get("cookie", ""))
    except Exception as exc:
        raise ValueError("invalid capture cookies") from exc
    if any(k not in cookies or cookies[k].value != str(v) for k, v in (entry.get("cookies") or {}).items()):
        raise ValueError("capture cookies do not match the verified session")


def prepare_capture(request, session_binding, *, home):
    if not isinstance(session_binding, dict) or set(session_binding) != {"target", "identity"}:
        raise ValueError("capture needs an exact target/account session binding")
    target, identity = session_binding["target"], session_binding["identity"]
    wire = canonical_request(request)
    scope, revision, policy = _versions()
    if not _same_origin(target, wire["url"]) or not scope.permits_url(wire["url"]):
        raise ValueError("capture is outside its session origin or current scope")
    entry = session_store.verified_session(target, identity, home=str(home))
    if not entry:
        raise ValueError("capture session is missing, expired or unverified")
    _check_session_headers(entry, wire["headers"])
    raw = json.dumps(wire, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()
    return {"session_target": target, "identity": identity,
            "session_version": session_store.check_fingerprint(target, identity, home=str(home), entry=entry),
            "scope_revision": revision, "policy_hash": policy,
            "request_mac": hmac.new(_vault(home).key, raw, hashlib.sha256).hexdigest()}


def save_capture(conn, record, request, observation_id, *, home):
    """Return the stable reference and a newly created secret for rollback cleanup."""
    metadata = record.get("capture_binding")
    session = {"target": metadata["session_target"], "identity": metadata["identity"]}
    if metadata != prepare_capture(request, session, home=home):
        raise ValueError("capture binding changed during ingestion")
    conn.execute(SCHEMA_SQL)
    old = conn.execute("SELECT capture_ref FROM surface_request_bindings WHERE fingerprint=? AND observation_id=?",
                       (record["fingerprint"], observation_id)).fetchone()
    if old:
        return old[0], None
    packet = {"schema": "surface-capture/1", "fingerprint": record["fingerprint"],
              "operation_id": record["operation_id"], "observation_id": observation_id,
              "binding": metadata, "created_at": time.time(), "request": canonical_request(request)}
    vault = _vault(home)
    secret_ref = vault.store_secret("surface_request", json.dumps(packet, ensure_ascii=False, allow_nan=False))
    capture_ref = "cap-" + secrets.token_hex(24)
    try:
        conn.execute("INSERT INTO surface_request_bindings (capture_ref,fingerprint,operation_id,observation_id,secret_ref,metadata_json) VALUES (?,?,?,?,?,?)",
                     (capture_ref, record["fingerprint"], record["operation_id"], observation_id,
                      secret_ref, json.dumps(metadata, sort_keys=True)))
    except Exception:
        vault.delete_secret(secret_ref)
        raise
    return capture_ref, secret_ref


def discard_secret(home, secret_ref):
    _vault(home).delete_secret(secret_ref)


def load_capture(ref, *, operation_id, observation_id, headers, home=None):
    home = home or os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
    if not isinstance(ref, str) or not re.fullmatch(r"cap-[a-f0-9]{48}", ref):
        raise ValueError("invalid capture reference")
    try:
        with sqlite3.connect(str(Path(home) / "agent_memory.db")) as conn:
            row = conn.execute("SELECT b.fingerprint,b.operation_id,b.observation_id,b.secret_ref,b.metadata_json,s.latest_observation_id,h.observation_id "
                               "FROM surface_request_bindings b JOIN attack_surface s ON s.fingerprint=b.fingerprint "
                               "JOIN surface_operation_heads h ON h.operation_id=b.operation_id WHERE b.capture_ref=?",
                               (ref,)).fetchone()
        if not row or row[1] != operation_id or row[2] != observation_id or row[5] != observation_id or row[6] != observation_id:
            raise ValueError("capture operation or observation changed")
        packet = json.loads(_vault(home).get_secret(row[3]))
        metadata = json.loads(row[4])
        if (packet.get("schema") != "surface-capture/1" or packet.get("fingerprint") != row[0]
                or packet.get("operation_id") != operation_id or packet.get("observation_id") != observation_id
                or packet.get("binding") != metadata or not 0 <= time.time() - packet["created_at"] <= _TTL):
            raise ValueError("capture packet missing, expired or mismatched")
        session = {"target": metadata["session_target"], "identity": metadata["identity"]}
        if metadata != prepare_capture(packet["request"], session, home=home):
            raise ValueError("capture session, scope or policy changed")
        supplied = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        for key, value in packet["request"]["headers"].items():
            if _CREDENTIAL.search(key) and supplied.get(key) != value:
                raise ValueError("caller credentials differ from captured account")
            if _TENANT.search(key) and key in supplied and supplied[key] != value:
                raise ValueError("caller tenant differs from captured request")
        return packet
    except Exception as exc:
        raise ValueError("capture reference is missing, stale or mismatched") from exc
