"""Authenticated collector events still do not prove a callback's source."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import evidence_trust as trust
import kryon_core.validator.oob_collector as collector
from kryon_core.validator.oob_collector import verify_collector_event


def _encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _sign(event, private):
    message = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return json.dumps({**event, "signature": _encode(private.sign(message))})


def _fixture():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keys = json.dumps({"trusted-collector": _encode(public)})
    target = "https://owned.test/fetch?url=synthetic"
    challenge = {"token": "ccossrfabc", "host": "ccossrfabc.callback.test", "target_url": target,
                 "param": "url", "run_id": "run-1", "target_binding": "b" * 64,
                 "probe_binding": "a" * 64, "scope_revision": "scope-1", "policy_hash": "policy-1",
                 "collector_eligible": True,
                 "sent_at": 1000, "expires_at": 2000}
    event = {"schema": "cco-oob-collector-event/1", "collector_id": "trusted-collector",
             "event_id": "event-1", "nonce": challenge["token"], "host": challenge["host"],
             "target_binding": challenge["target_binding"], "probe_binding": challenge["probe_binding"],
             "scope_revision": "scope-1", "policy_hash": "policy-1", "param": "url", "run_id": "run-1",
             "protocol": "dns", "observed_at": 1100}
    return private, keys, challenge, event


def _verify(challenge, signed, keys, db, *, now=1100, scope="scope-1", policy="policy-1"):
    return verify_collector_event(challenge, signed, keys, db, scope_revision=scope, policy_hash=policy, now=now)


def test_only_signed_bound_current_event_is_consumed_once(tmp_path):
    private, keys, challenge, event = _fixture()
    db = str(tmp_path / "oob.db")
    for bad in ({"host": "wrong.callback.test"}, {"run_id": "other-run"},
                {"target_binding": "d" * 64}, {"probe_binding": "c" * 64},
                {"scope_revision": "other-scope"}, {"policy_hash": "other-policy"},
                {"nonce": "other"}, {"param": "other"}, {"observed_at": 999},
                {"observed_at": 2001}, {"protocol": "smtp"}):
        assert not _verify(challenge, _sign({**event, **bad}, private), keys, db)["authenticated"]
    wrong_key = _sign(event, Ed25519PrivateKey.generate())
    assert not _verify(challenge, wrong_key, keys, db)["authenticated"]
    assert not _verify(challenge, _sign(event, private), keys, db, now=2001)["authenticated"]
    assert not _verify(challenge, _sign(event, private), keys, db, scope="scope-new")["authenticated"]
    assert not _verify(challenge, _sign(event, private), keys, db, policy="policy-new")["authenticated"]
    signed = _sign(event, private)
    accepted = _verify(challenge, signed, keys, db)
    assert accepted["authenticated"] and accepted["collector_id"] == "trusted-collector"
    artifact = Path(accepted["event_path"])
    saved = json.loads(artifact.read_text())
    assert saved["event"]["event_id"] == "event-1" and "owned.test" not in artifact.read_text()
    assert trust.verify_receipt(artifact, saved, "oob-collector-event/1")
    saved["event"]["param"] = "tampered"
    assert not trust.verify_receipt(artifact, saved, "oob-collector-event/1")
    assert not _verify(challenge, signed, keys, db)["authenticated"]
    assert not _verify(challenge, _sign({**event, "event_id": "event-2"}, private), keys, db)["authenticated"]
    assert b"owned.test" not in Path(db).read_bytes() and b"event-1" not in Path(db).read_bytes()


def test_duplicate_json_keys_missing_probe_and_unconfigured_collector_fail(tmp_path):
    private, keys, challenge, event = _fixture()
    db = str(tmp_path / "oob.db")
    signed = _sign(event, private)
    duplicate = signed[:-1] + ', "protocol": "dns"}'
    assert not _verify(challenge, duplicate, keys, db)["authenticated"]
    assert not _verify({**challenge, "probe_binding": ""}, signed, keys, db)["authenticated"]
    assert not _verify({**challenge, "collector_eligible": False}, signed, keys, db)["authenticated"]
    assert not _verify(challenge, signed, "{}", db)["authenticated"]
    assert not Path(db).exists()


def test_evidence_write_failure_does_not_consume_a_valid_event(tmp_path, monkeypatch):
    private, keys, challenge, event = _fixture()
    signed, db = _sign(event, private), str(tmp_path / "oob.db")

    def fail(*args, **kwargs):
        raise OSError("synthetic storage error")

    with monkeypatch.context() as patch:
        patch.setattr(collector, "_persist_event", fail)
        assert not _verify(challenge, signed, keys, db)["authenticated"]
    assert _verify(challenge, signed, keys, db)["authenticated"]


def test_concurrent_replay_admits_exactly_one_event(tmp_path):
    private, keys, challenge, event = _fixture()
    signed = _sign(event, private)
    db = str(tmp_path / "oob.db")

    def verify(_):
        return _verify(challenge, signed, keys, db)["authenticated"]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(verify, range(16)))
    assert sum(results) == 1
