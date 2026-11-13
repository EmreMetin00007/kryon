"""Concurrent append, pinned verification and legacy custody regressions."""
import copy
import importlib
import json
import multiprocessing
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-validator"))
import attempt_ledger as ledger
from cco_validator_core import evidence


def record(number=1):
    return {"vector": "csrf", "endpoint": f"/own/{number}",
            "identity": "own", "status": 200, "verdict": "observed"}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("CCO_BASH_SANDBOXED", raising=False)
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    monkeypatch.delenv("CCO_ARTIFACT_HMAC_KEY", raising=False)
    return tmp_path / "home"


def append_worker(path, event, outcomes, count):
    event.wait(10)
    try:
        for i in range(count):
            ledger.append_record(path, record(i + 1))
        outcomes.put(None)
    except Exception as exc:
        outcomes.put(str(exc))


def test_concurrent_processes_keep_one_sequence_and_one_signing_key(home, tmp_path):
    ctx = multiprocessing.get_context("spawn")
    start, outcomes = ctx.Event(), ctx.Queue()
    path = tmp_path / "run" / "attempts.jsonl"
    workers = [ctx.Process(target=append_worker, args=(path, start, outcomes, 8)) for _ in range(4)]
    for worker in workers:
        worker.start()
    start.set()
    errors = [outcomes.get(timeout=30) for _ in workers]
    for worker in workers:
        worker.join(10)
        assert worker.exitcode == 0
    assert errors == [None] * 4
    records = ledger.read_records(path)
    assert [r["seq"] for r in records] == list(range(1, 33))
    assert ledger.verify_records(records)[1] == []


def test_reader_never_observes_a_partial_commit(home, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    path = tmp_path / "attempts.jsonl"
    def write():
        for i in range(20):
            ledger.append_record(path, record(i + 1))
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(write)
        while not future.done():
            records = ledger.read_records(path)
            assert ledger.verify_records(records)[1] == []
        future.result()
    assert len(ledger.read_records(path)) == 20


def test_failed_atomic_replace_keeps_previous_committed_ledger(home, tmp_path, monkeypatch):
    path = tmp_path / "attempts.jsonl"
    ledger.append_record(path, record())
    before = path.read_bytes()
    original = os.replace
    def interrupted(source, destination):
        if Path(destination) == path:
            raise OSError("simulated commit failure")
        return original(source, destination)
    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", interrupted)
        with pytest.raises(OSError):
            ledger.append_record(path, record(2))
    assert path.read_bytes() == before
    assert len(ledger.read_records(path)) == 1
    assert ledger.append_record(path, record(2))["seq"] == 2


def test_ledger_lock_symlink_cannot_touch_another_file(home, tmp_path):
    path = tmp_path / "attempts.jsonl"
    outside = tmp_path / "untouched"
    outside.write_text("untouched")
    path.with_suffix(path.suffix + ".lock").symlink_to(outside)
    with pytest.raises((OSError, ValueError)):
        ledger.append_record(path, record())
    assert outside.read_text() == "untouched" and not path.exists()


def public_reader(monkeypatch, home, tmp_path):
    trust = importlib.import_module("evidence_trust")
    bundle = home / "public-trust" / "verification.json"
    assert bundle.exists()
    monkeypatch.setattr(trust, "pinned_bundle", lambda: bundle)
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "reader-home"))
    monkeypatch.setenv("CCO_BASH_SANDBOXED", "1")
    return trust


def test_same_ledger_verifies_in_different_home_without_private_keys(home, tmp_path, monkeypatch):
    path = tmp_path / "attempts.jsonl"
    ledger.append_record(path, record())
    public_reader(monkeypatch, home, tmp_path)
    records = ledger.read_records(path)
    assert ledger.verify_records(records, path=path)[1] == []
    assert not Path(os.environ["CCO_HOME"]).exists()


def test_record_cannot_be_replayed_under_another_run(home, tmp_path):
    path = tmp_path / "run-a" / "attempts.jsonl"
    ledger.append_record(path, record())
    assert ledger.verify_records(ledger.read_records(path), path=tmp_path / "run-b" / "attempts.jsonl")[1]


def test_public_reader_cannot_sign_even_after_environment_override(home, tmp_path, monkeypatch):
    ledger.append_record(tmp_path / "attempts.jsonl", record())
    public_reader(monkeypatch, home, tmp_path)
    monkeypatch.delenv("CCO_BASH_SANDBOXED")
    monkeypatch.setenv("CCO_ATTEMPT_HMAC_KEY", "attacker-synthetic-key")
    with pytest.raises(ValueError, match="sign|host|sandbox"):
        ledger.sign_payload({"producer": "gate"})


def test_validator_artifact_and_gate_payload_verify_without_secrets(home, tmp_path, monkeypatch):
    result = evidence.persist_result({"schema_version": "2.0", "validation_id": "public-test",
        "target": "https://own.test", "vuln_type": "csrf", "verdict": "CONFIRMED"},
        str(home / "validations"))
    signed = ledger.sign_payload({"producer": "gate", "test": 1})
    public_reader(monkeypatch, home, tmp_path)
    assert evidence.artifact_is_valid(result, trusted_root=str(home / "validations"))
    assert ledger.verify_signed_payload(signed) == (signed["payload"], "")
    changed = copy.deepcopy(signed)
    changed["payload"]["test"] = 2
    assert ledger.verify_signed_payload(changed)[0] is None


def test_foreign_public_key_does_not_authorize_gate_payload(home, tmp_path, monkeypatch):
    signed = ledger.sign_payload({"producer": "gate"})
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "foreign"))
    ledger.sign_payload({"producer": "gate", "foreign": True})
    assert ledger.verify_signed_payload(signed)[0] is None


def legacy_record(path, number=1):
    payload = {**record(number), "seq": 1, "prev_hash": ledger.GENESIS_HASH}
    digest = ledger._record_hash(payload)
    stored = {**payload, "record_hash": digest, "signature_alg": "hmac-sha256:v1",
              "signature": ledger._signature(digest)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(stored) + "\n")
    return stored


def test_legacy_prefix_kept_and_authenticated_for_public_reader(home, tmp_path, monkeypatch):
    path = tmp_path / "attempts.jsonl"
    old = legacy_record(path)
    ledger.append_record(path, record(2))
    public_reader(monkeypatch, home, tmp_path)
    records = ledger.read_records(path)
    assert records[0] == old
    assert ledger.verify_records(records, path=path)[1] == []
    records[0]["signature"] = "0" * 64
    assert ledger.verify_records(records, path=path)[1]


def test_record_signature_tamper_stays_untrusted(home, tmp_path):
    path = tmp_path / "attempts.jsonl"
    ledger.append_record(path, record())
    records = ledger.read_records(path)
    records[0]["signature"] = "0" * len(records[0]["signature"])
    assert ledger.verify_records(records, path=path)[1]


def test_legacy_without_checkpoint_is_not_trusted_by_public_reader(home, tmp_path, monkeypatch):
    trust = importlib.import_module("evidence_trust")
    trust.prepare()
    path = tmp_path / "attempts.jsonl"
    legacy_record(path)
    public_reader(monkeypatch, home, tmp_path)
    verified, errors = ledger.verify_records(ledger.read_records(path), path=path)
    assert verified == [] and "checkpoint" in errors[0]
    with pytest.raises(ValueError, match="host-only"):
        ledger.checkpoint(path)


def test_forged_legacy_receipt_cannot_replace_host_authority(home, tmp_path, monkeypatch):
    trust = importlib.import_module("evidence_trust")
    path = tmp_path / "attempts.jsonl"
    legacy_record(path)
    ledger.checkpoint(path)
    records = ledger.read_records(path)
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "attacker"))
    trust.publish_receipt(path, records, "legacy-ledger")
    public_reader(monkeypatch, home, tmp_path)
    assert ledger.verify_records(records, path=path)[1]


def test_signature_purpose_cannot_be_reused(home):
    trust = importlib.import_module("evidence_trust")
    signature = trust.sign(b"same bytes", "gate-payload")
    assert trust.verify(b"same bytes", signature, "gate-payload")
    assert not trust.verify(b"same bytes", signature, "attempt-record")
    assert not trust.verify(b"same bytes", signature, "validator-artifact")


def test_verification_never_bootstraps_a_missing_home(tmp_path, monkeypatch):
    trust = importlib.import_module("evidence_trust")
    missing = tmp_path / "absent"
    monkeypatch.setenv("CCO_HOME", str(missing))
    assert not trust.verify(b"data", {"signature_alg": trust.ALGORITHM,
        "key_id": "0" * 64, "signature": "0" * 128}, "gate-payload")
    assert not missing.exists()


def test_missing_key_cannot_silently_replace_established_trust(home):
    trust = importlib.import_module("evidence_trust")
    info = trust.prepare()
    public_bytes = Path(info["bundle"]).read_bytes()
    (home / trust.PRIVATE_NAME).unlink()
    with pytest.raises(ValueError, match="restoring"):
        trust.prepare()
    assert Path(info["bundle"]).read_bytes() == public_bytes
    assert not (home / trust.PRIVATE_NAME).exists()


def test_public_read_uses_a_read_only_lock(home, tmp_path, monkeypatch):
    path = tmp_path / "attempts.jsonl"
    ledger.append_record(path, record())
    original = os.open
    def readonly_open(name, flags, *args, **kwargs):
        if str(name).endswith("attempts.jsonl.lock"):
            assert not flags & (os.O_RDWR | os.O_WRONLY | os.O_CREAT)
        return original(name, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", readonly_open)
    assert len(ledger.read_records(path)) == 1
