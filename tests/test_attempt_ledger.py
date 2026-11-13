import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _record(**overrides):
    data = {
        "vector": "authz-idor",
        "endpoint": "/api/documents/7/download",
        "identity": "own",
        "candidate": 7,
        "control": 5,
        "status": 200,
        "size": 812,
        "artifact": "ev.bin",
        "verdict": "miss",
    }
    data.update(overrides)
    return data


def test_attempt_record_roundtrip_and_schema(tmp_path):
    mod = _load("attempt_ledger")
    path = tmp_path / "attempts.jsonl"
    assert mod.read_records(path) == []
    stored = mod.append_record(path, _record())
    assert stored["candidate"] == 7
    assert mod.read_records(path) == [stored]

    with pytest.raises(ValueError):
        mod.append_record(path, _record(vector=""))
    with pytest.raises(ValueError):
        mod.append_record(path, _record(candidate=True))
    with pytest.raises(ValueError):
        mod.append_record(path, _record(made_up_field=1))
    # Rejected records never land in the file.
    assert len(mod.read_records(path)) == 1


def test_attempt_coverage_counts(tmp_path):
    mod = _load("attempt_ledger")
    path = tmp_path / "attempts.jsonl"
    mod.append_record(path, _record(
        candidate=4, control=4, endpoint="/api/documents/4/download"))
    mod.append_record(path, _record(
        candidate=5, control=4, endpoint="/api/documents/5/download"))
    mod.append_record(path, _record(
        candidate=5, control=4, endpoint="/api/documents/5/download"))
    mod.append_record(path, _record(candidate=6, control=None,
                                    endpoint="/api/documents/7/download"))
    mod.append_record(path, _record(vector="csrf", candidate=None, control=None))
    records = mod.read_records(path)
    covered = mod.coverage(records, "authz-idor", [4, 5, 6, 7])
    assert covered["tried"] == [4, 5]
    assert covered["untried"] == [6, 7]
    assert covered["controls"] == 1
    assert covered["control_ids"] == [4]
    assert mod.coverage(records, "csrf")["tried"] == []


def test_unsigned_and_tampered_records_do_not_count(tmp_path):
    mod = _load("attempt_ledger")
    path = tmp_path / "attempts.jsonl"
    path.write_text(json.dumps(_record()) + "\n")
    assert mod.coverage(mod.read_records(path), "authz-idor", [7])["tried"] == []
    with pytest.raises(ValueError):
        mod.append_record(path, _record(candidate=8))

    signed_path = tmp_path / "signed.jsonl"
    mod.append_record(signed_path, _record(candidate=7))
    lines = signed_path.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["candidate"] = 8
    signed_path.write_text(json.dumps(tampered) + "\n")
    covered = mod.coverage(mod.read_records(signed_path), "authz-idor", [7, 8])
    assert covered["tried"] == []
    with pytest.raises(ValueError):
        mod.append_record(signed_path, _record(candidate=9))


def test_attempts_cli_add_list_coverage(tmp_path, capsys):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    assert brain.main([
        "attempts", "add", "--workdir", str(workdir),
        "--vector", "authz-idor", "--endpoint", "/api/documents/7/download",
        "--identity", "own", "--candidate", "7", "--control", "5",
        "--status", "200", "--size", "812", "--verdict", "miss",
    ]) == 0
    capsys.readouterr()
    assert brain.main([
        "attempts", "list", "--workdir", str(workdir),
        "--vector", "authz-idor",
    ]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert len(listed) == 1 and listed[0]["candidate"] == 7
    assert listed[0]["seq"] == 1 and listed[0]["signature"]
    assert brain.main([
        "attempts", "coverage", "--workdir", str(workdir),
        "--vector", "authz-idor", "--expected", "5,6,7",
    ]) == 0
    covered = json.loads(capsys.readouterr().out)
    assert covered["tried"] == [7] and covered["untried"] == [5, 6]


def test_state_identity_rejects_session_values(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    assert brain.main([
        "state", "identity", "--workdir", str(workdir),
        "--name", "alice", "--pointer", "vault:seed-alice",
    ]) == 0
    for secret in ("session=abc123; Path=/", "Bearer hunter2", "a" * 200):
        assert brain.main([
            "state", "identity", "--workdir", str(workdir),
            "--name", "mallory", "--pointer", secret,
        ]) == 2, secret


def test_state_identity_rejects_bare_tokens(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    for secret in ("a" * 128, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"):
        assert brain.main([
            "state", "identity", "--workdir", str(workdir),
            "--name", "mallory", "--pointer", secret,
        ]) == 2, secret


def test_malformed_attempts_and_state_return_stop(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    (workdir / "attempts.jsonl").write_text("not json\n")
    assert brain.main([
        "attempts", "coverage", "--workdir", str(workdir),
        "--vector", "csrf",
    ]) == 2
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "csrf",
    ]) == 2
    (workdir / "run-state.json").write_text("{")
    assert brain.main([
        "state", "identity", "--workdir", str(workdir),
        "--name", "alice", "--pointer", "vault:seed-alice",
    ]) == 2


def test_state_job_transitions(tmp_path):
    brain = _load("brain")
    mod = _load("attempt_ledger")
    workdir = tmp_path / "run"
    workdir.mkdir()
    assert brain.main([
        "state", "job", "--workdir", str(workdir),
        "--kind", "webhook", "--ref", "wh-1",
    ]) == 0
    assert brain.main([
        "state", "job-done", "--workdir", str(workdir), "--ref", "wh-1",
    ]) == 0
    job = mod.load_state(workdir)["jobs"][0]
    assert job["kind"] == "webhook" and job["status"] == "done"
    assert job["updated_at"]
    assert brain.main([
        "state", "job", "--workdir", str(workdir),
        "--kind", "report", "--ref", "wh-1",
    ]) == 2
    assert brain.main([
        "state", "job-reopen", "--workdir", str(workdir), "--ref", "wh-1",
    ]) == 0
    job = mod.load_state(workdir)["jobs"][0]
    assert job["kind"] == "webhook" and job["status"] == "pending"
    assert brain.main([
        "state", "job-done", "--workdir", str(workdir), "--ref", "wh-1",
    ]) == 0
    assert brain.main([
        "state", "job-done", "--workdir", str(workdir), "--ref", "wh-1",
    ]) == 2
    assert brain.main([
        "state", "job-done", "--workdir", str(workdir), "--ref", "ghost",
    ]) == 2


def test_handoff_packet_shows_pending_jobs(tmp_path, capsys):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    assert brain.main([
        "state", "job", "--workdir", str(workdir),
        "--kind", "report", "--ref", "rep-7",
    ]) == 0
    capsys.readouterr()
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "injection-sqli",
    ]) == 0
    packet = json.loads(capsys.readouterr().out)
    assert any(job["ref"] == "rep-7" and job["status"] == "pending"
               and job["updated_at"] for job in packet["jobs"])


def test_attempts_cli_rejects_artifact_outside_workdir(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("TOPSECRET-VALUE-1234")
    for artifact in (str(outside), "../secret.txt"):
        assert brain.main([
            "attempts", "add", "--workdir", str(workdir),
            "--vector", "csrf", "--endpoint", "/e", "--identity", "own",
            "--artifact", artifact, "--verdict", "miss",
        ]) == 2, artifact
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "csrf",
    ]) == 0


def test_attempts_cli_verifies_artifact_sha(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    artifact = workdir / "ev.bin"
    artifact.write_bytes(b"response-body")
    digest = hashlib.sha256(b"response-body").hexdigest()
    assert brain.main([
        "attempts", "add", "--workdir", str(workdir),
        "--vector", "authz-idor", "--endpoint", "/e", "--identity", "own",
        "--artifact", "ev.bin", "--sha256", "0" * 64, "--verdict", "miss",
    ]) == 2
    assert brain.main([
        "attempts", "add", "--workdir", str(workdir),
        "--vector", "authz-idor", "--endpoint", "/e", "--identity", "own",
        "--artifact", "ev.bin", "--verdict", "miss",
    ]) == 0
    mod = _load("attempt_ledger")
    assert mod.read_records(workdir / "attempts.jsonl")[0]["sha256"] == digest
    assert brain.main([
        "attempts", "add", "--workdir", str(workdir),
        "--vector", "authz-idor", "--endpoint", "/e", "--identity", "own",
        "--artifact", "missing.bin", "--verdict", "miss",
    ]) == 2
