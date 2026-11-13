"""Verify operator-configured OOB collector metadata without asserting source.

A valid signature proves only that the configured collector signed the event;
it does not establish that the target application caused the callback.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_FIELDS = {"schema", "collector_id", "event_id", "nonce", "host", "target_binding",
           "probe_binding", "param", "run_id", "scope_revision", "policy_hash", "protocol", "observed_at",
           "signature"}
_LABEL = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _bytes(value, size):
    if not isinstance(value, str) or len(value) > 256:
        raise ValueError("invalid encoding")
    raw = value.encode("ascii")
    decoded = base64.b64decode(raw + b"=" * (-len(raw) % 4), altchars=b"-_", validate=True)
    if len(decoded) != size:
        raise ValueError("invalid length")
    return decoded


def _persist_event(directory: Path, event: dict, public_key: str, verified_at: int) -> tuple[str, str]:
    """Write minimal, locally attested collector metadata; never a target URL."""
    from cco_validator_core.evidence import trust
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = {"schema": "cco-oob-collector-record/1", "event": event,
              "collector_public_key": public_key, "verified_at": verified_at}
    encoded = trust.canonical_bytes(record)
    digest = hashlib.sha256(encoded).hexdigest()
    path = directory / f"{digest}.json"
    trust.atomic_write(path, encoded + b"\n", mode=0o600)
    trust.publish_receipt(path, record, "oob-collector-event/1")
    if not trust.verify_receipt(path, record, "oob-collector-event/1"):
        raise ValueError("collector evidence receipt unavailable")
    return str(path), digest


def verify_collector_event(challenge: dict, raw_event: str, trusted_keys: str,
                           replay_db: str, *, scope_revision: str, policy_hash: str,
                           now: int | None = None) -> dict:
    """Verify a signed event and consume its ID exactly once, offline.

    Keys come from operator-controlled runtime configuration, never from the
    event or the caller's tool arguments. Failure never exposes event contents.
    """
    failure = {"authenticated": False, "reason": "collector evidence invalid or unavailable"}
    if not isinstance(raw_event, str) or len(raw_event) > 8192 or len(trusted_keys or "") > 32768:
        return failure
    try:
        event = json.loads(raw_event, object_pairs_hook=_unique_object)
        keys = json.loads(trusted_keys, object_pairs_hook=_unique_object)
        if not isinstance(event, dict) or set(event) != _FIELDS or not isinstance(keys, dict):
            return failure
        collector_id, event_id = event["collector_id"], event["event_id"]
        if (event["schema"] != "cco-oob-collector-event/1"
                or not isinstance(collector_id, str) or not _LABEL.fullmatch(collector_id)
                or not isinstance(event_id, str) or not _LABEL.fullmatch(event_id)
                or collector_id not in keys or event["protocol"] not in {"dns", "http"}):
            return failure
        signature = _bytes(event["signature"], 64)
        public_key = _bytes(keys[collector_id], 32)
        observed = event["observed_at"]
        current = int(time.time()) if now is None else int(now)
        if (isinstance(observed, bool) or not isinstance(observed, int)
                or not isinstance(challenge.get("sent_at"), int)
                or not isinstance(challenge.get("expires_at"), int)
                or observed < challenge["sent_at"] or observed > challenge["expires_at"]
                or observed > current + 30 or current > challenge["expires_at"]):
            return failure
        target_binding = str(challenge.get("target_binding") or "")
        probe_binding = str(challenge.get("probe_binding") or "")
        expected = {"nonce": challenge.get("token"), "host": challenge.get("host"),
                    "target_binding": target_binding, "probe_binding": probe_binding,
                    "param": challenge.get("param"), "run_id": challenge.get("run_id"),
                    "scope_revision": challenge.get("scope_revision"), "policy_hash": challenge.get("policy_hash")}
        if (challenge.get("collector_eligible") is not True or not challenge.get("target_url")
                or not _DIGEST.fullmatch(target_binding) or not _DIGEST.fullmatch(probe_binding)
                or not expected["param"] or not expected["run_id"]
                or not scope_revision or not policy_hash or expected["scope_revision"] != scope_revision
                or expected["policy_hash"] != policy_hash
                or any(event[key] != value for key, value in expected.items())):
            return failure
        unsigned = {key: event[key] for key in event if key != "signature"}
        message = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        path = Path(replay_db)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with sqlite3.connect(path, timeout=10) as conn:
            os.chmod(path, 0o600)
            conn.execute("CREATE TABLE IF NOT EXISTS consumed_oob_events "
                         "(event_key TEXT PRIMARY KEY, challenge_key TEXT UNIQUE NOT NULL, consumed_at INTEGER NOT NULL)")
            event_key = hashlib.sha256(f"{collector_id}\x00{event_id}".encode()).hexdigest()
            challenge_key = hashlib.sha256(str(challenge["token"]).encode()).hexdigest()
            try:
                conn.execute("INSERT INTO consumed_oob_events VALUES (?, ?, ?)", (event_key, challenge_key, current))
            except sqlite3.IntegrityError:
                return {"authenticated": False, "reason": "collector event already consumed"}
            event_path, event_digest = _persist_event(path.parent / "collector-events", event,
                                                       str(keys[collector_id]), current)
        return {"authenticated": True, "reason": "collector signature and challenge binding verified",
                "collector_id": collector_id, "protocol": event["protocol"],
                "event_path": event_path, "event_sha256": event_digest}
    except (ValueError, TypeError, KeyError, OSError, sqlite3.Error, InvalidSignature, UnicodeError):
        return failure
