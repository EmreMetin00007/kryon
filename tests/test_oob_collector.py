"""Authenticated collector events still do not prove a callback's source."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-validator"))
from cco_validator_core.oob_collector import verify_collector_event  # noqa: E402


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
    from cco_validator_core.evidence import trust
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
    import cco_validator_core.oob_collector as collector
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


def test_signed_collector_event_is_correlated_but_never_confirms_ssrf(tmp_path, monkeypatch):
    from cco_validator_core.evidence import validation_context
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_SCOPE_REVISION", "scope-a")
    monkeypatch.setenv("CCO_POLICY_HASH", "policy-a")
    validator = load_server("validator")
    monkeypatch.setattr(validator, "_oob_host_in_scope", lambda host: True)
    def send(url, payload, **kwargs):
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[kwargs["param"]] = payload
        sent_url = urlunparse(parsed._replace(query=urlencode(query)))
        return {"ok": True, "status": 200, "request_method": "GET", "requests_sent": 1,
                "final_url": sent_url}
    monkeypatch.setattr(validator, "_send_payload", send)
    private, keys, _, _ = _fixture()
    monkeypatch.setenv("CCO_OOB_COLLECTORS_JSON", keys)
    with validation_context({"run_id": "run-synthetic"}):
        pending = json.loads(validator.validate_ssrf_oob("https://owned.test/fetch?url=x", "callback.test", "url"))
    binding = pending["evidence"]["collector_binding"]
    assert binding["run_id"] == "run-synthetic" and binding["probe_binding"]
    event = {"schema": "cco-oob-collector-event/1", "collector_id": "trusted-collector", "event_id": "event-1",
             **{key: binding[key] for key in ("nonce", "host", "target_binding", "probe_binding", "param", "run_id",
                                               "scope_revision", "policy_hash")},
             "protocol": "dns", "observed_at": binding["sent_at"]}
    signed = _sign(event, private)
    monkeypatch.setenv("CCO_SCOPE_REVISION", "scope-changed")
    wrong_scope = json.loads(validator.confirm_oob_callback(binding["nonce"], collector_event_json=signed))
    assert wrong_scope["verdict"] == "INCONCLUSIVE" and not wrong_scope["evidence"]["collector_authenticated"]
    monkeypatch.setenv("CCO_SCOPE_REVISION", "scope-a")
    result = json.loads(validator.confirm_oob_callback(binding["nonce"], collector_event_json=signed))
    assert result["verdict"] == "INCONCLUSIVE" and result["evidence"]["collector_authenticated"] is True
    assert result["evidence"]["correlated"] is False and "attribution" in result["notes"]
    assert Path(result["evidence"]["collector_event_path"]).is_file()
    assert len(result["evidence"]["collector_event_sha256"]) == 64
    replay = json.loads(validator.confirm_oob_callback(binding["nonce"], collector_event_json=signed))
    assert replay["verdict"] == "INCONCLUSIVE" and replay["evidence"]["collector_authenticated"] is False


def test_tampering_with_local_challenge_invalidates_its_signature(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("CCO_VAULT_KEY", raising=False)
    monkeypatch.setenv("CCO_USE_KEYRING", "0")
    validator = load_server("validator")
    token = "ccossrf0123456789abcdef01234567"
    validator._store_oob_challenge(token, token + ".callback.test", "https://owned.test/fetch?url=x",
                                   "SSRF", "url", "run-1", 1000, "a" * 64, "b" * 64, "scope", "policy")
    loaded = validator._load_oob_challenge(token)
    assert loaded["collector_eligible"] is True and loaded["target_url"] == "https://owned.test/fetch?url=x"
    path = Path(validator._oob_challenge_path(token))
    contents = path.read_text()
    assert "https://owned.test/fetch?url=x" not in contents
    assert not (tmp_path / "home" / "credential_vault.db").exists()
    key_path = tmp_path / "home" / "vault.key"
    synthetic_key = key_path.read_bytes()
    key_path.unlink()
    assert validator._load_oob_challenge(token) is None and not key_path.exists()
    key_path.write_bytes(synthetic_key)
    key_path.chmod(0o600)
    monkeypatch.setenv("CCO_VAULT_KEY", Fernet.generate_key().decode())
    assert validator._load_oob_challenge(token) is None
    monkeypatch.delenv("CCO_VAULT_KEY")
    envelope = json.loads(contents)
    envelope["payload"]["param"] = "different"
    path.write_text(json.dumps(envelope))
    assert validator._load_oob_challenge(token) is None
