import importlib.util
import json
import sys
from pathlib import Path

from conftest import make_signed_validation

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _terminal_run(tmp_path, monkeypatch, entries, record_count=2):
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    ts = _load("orchestration_spec")
    al = _load("attempt_ledger")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    workdir = tmp_path / "run"
    workdir.mkdir()
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=[vector for vector, _, _ in entries],
                            max_attempts=2)
    for vector, status, note in entries:
        if status == "untried":
            continue
        target = hl.claim_next(ledger)
        assert target is not None and target["vector"] == vector
        hl.mark(ledger, vector, status, note=note)
        if status == "confirmed":
            record = make_signed_validation(ledger["target"], brain._VALIDATOR_VECTOR_TYPES[vector])
            target.update(brain._confirmation_reference(record))
    hl.save_ledger(workdir, ledger)
    for index in range(record_count):
        al.append_record(al.ledger_path(workdir), {
            "vector": "ssrf", "endpoint": f"/probe/{index}",
            "identity": "own", "verdict": "no_signal"})
    return brain, workdir, spec_file


def test_closure_exit_zero_writes_signed_closure(tmp_path, monkeypatch):
    brain, workdir, spec_file = _terminal_run(
        tmp_path, monkeypatch,
        [("ssrf", "confirmed", "validator artifact"),
         ("injection-sqli", "not_applicable",
          "auth:not-required: no such surface")])
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 0
    closure_file = workdir / "closure.json"
    assert closure_file.is_file()
    signed = json.loads(closure_file.read_text())
    assert signed["payload"]["producer"] == "gate"
    assert signed["payload"]["ledger"] == {
        "records": 2, "trusted": 2, "sig_errors": 0,
        "chain_errors": 0, "head": signed["payload"]["ledger"]["head"]}
    assert len(signed["payload"]["ledger"]["head"]) == 64
    assert signed["signature_alg"] == "ed25519:v1"
    assert len(signed["signature"]) == 128
    assert brain.main(["closure", "verify",
                       "--workdir", str(workdir)]) == 0


def test_closure_exit_two_writes_nothing(tmp_path, monkeypatch):
    brain, workdir, spec_file = _terminal_run(
        tmp_path, monkeypatch,
        [("ssrf", "confirmed", "validator artifact"),
         ("injection-sqli", "untried", "")])
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 2
    assert not (workdir / "closure.json").exists()


def test_closure_exit_two_preserves_handwritten_bytes(tmp_path, monkeypatch):
    brain, workdir, spec_file = _terminal_run(
        tmp_path, monkeypatch,
        [("ssrf", "confirmed", "validator artifact"),
         ("injection-sqli", "untried", "")])
    draft = b'{"status": "agent draft", "brain_check": {"exit": 125}}\n'
    (workdir / "closure.json").write_bytes(draft)
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 2
    assert (workdir / "closure.json").read_bytes() == draft


def test_closure_verify_rejects_handwritten(tmp_path, monkeypatch, capsys):
    brain = _load("brain")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("CCO_HOME", str(home))
    workdir = tmp_path / "run"
    workdir.mkdir()
    (workdir / "closure.json").write_text(json.dumps({
        "brain_check": {"exit": 125, "note": "NOT RUN"},
        "status": "partial/no-confirmed-findings"}))
    assert brain.main(["closure", "verify",
                       "--workdir", str(workdir)]) == 2
    assert "unverified" in capsys.readouterr().out


def test_closure_verify_detects_tamper(tmp_path, monkeypatch):
    brain, workdir, spec_file = _terminal_run(
        tmp_path, monkeypatch,
        [("ssrf", "confirmed", "validator artifact")])
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 0
    closure_file = workdir / "closure.json"
    signed = json.loads(closure_file.read_text())
    signed["payload"]["ledger"]["trusted"] = 99
    closure_file.write_text(json.dumps(signed))
    assert brain.main(["closure", "verify",
                       "--workdir", str(workdir)]) == 2


def test_closure_verify_rejects_foreign_key(tmp_path, monkeypatch):
    brain, workdir, spec_file = _terminal_run(
        tmp_path, monkeypatch,
        [("ssrf", "confirmed", "validator artifact")])
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 0
    other_home = tmp_path / "other"
    other_home.mkdir()
    monkeypatch.setenv("CCO_HOME", str(other_home))
    assert brain.main(["closure", "verify",
                       "--workdir", str(workdir)]) == 2


def test_closure_overwrites_handwritten_on_clean_exit(tmp_path, monkeypatch):
    brain, workdir, spec_file = _terminal_run(
        tmp_path, monkeypatch,
        [("ssrf", "confirmed", "validator artifact")])
    (workdir / "closure.json").write_text(json.dumps({"status": "agent draft"}))
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 0
    signed = json.loads((workdir / "closure.json").read_text())
    assert signed["payload"]["producer"] == "gate"
