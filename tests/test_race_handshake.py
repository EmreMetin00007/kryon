"""Race handshake: request-before-burst + over-cap audit."""

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _run_with_race_records(tmp_path, monkeypatch, race_records, with_request):
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    ts = _load("orchestration_spec")
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
                            vectors=["race-business"], max_attempts=2)
    claimed = hl.claim_next(ledger)
    assert claimed is not None and claimed["vector"] == "race-business"
    hl.mark(ledger, "race-business", "exhausted", note="burst done")
    hl.save_ledger(workdir, ledger)
    if with_request:
        assert brain.main(["race-request", "--workdir", str(workdir),
                           "--reason", "promo balance logic observed",
                           "--evidence", "billing/balance.body"]) == 0
    for index in range(race_records):
        assert brain.main([
            "attempts", "add", "--workdir", str(workdir),
            "--vector", "race-business", "--endpoint", "/promo/redeem",
            "--identity", "own", "--verdict", "race_probe_balance_delta",
            "--status", "200", "--size", str(12 + index),
        ]) == 0
    return brain, spec_file, workdir


def test_race_request_writes_schema_file(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    assert brain.main(["race-request", "--workdir", str(workdir),
                       "--reason", "promo balance logic observed",
                       "--evidence", "billing/balance.body"]) == 0
    request = json.loads((workdir / "race-request.json").read_text())
    assert request["reason"] == "promo balance logic observed"
    assert request["evidence"] == "billing/balance.body"
    assert request["requested_at"]


def test_race_request_rejects_empty_fields(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    assert brain.main(["race-request", "--workdir", str(workdir),
                       "--reason", "", "--evidence", "billing/balance.body"]) == 2
    assert brain.main(["race-request", "--workdir", str(workdir),
                       "--reason", "promo logic", "--evidence", ""]) == 2


def test_race_burst_without_request_fails_check(tmp_path, monkeypatch, capsys):
    brain, spec_file, workdir = _run_with_race_records(
        tmp_path, monkeypatch, 2, False)
    capsys.readouterr()
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir)]) == 2
    assert "race-request" in capsys.readouterr().out


def test_race_burst_over_cap_fails_check(tmp_path, monkeypatch, capsys):
    brain, spec_file, workdir = _run_with_race_records(
        tmp_path, monkeypatch, 11, True)
    capsys.readouterr()
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir)]) == 2
    assert "max_items" in capsys.readouterr().out


def test_race_burst_within_cap_passes(tmp_path, monkeypatch, capsys):
    brain, spec_file, workdir = _run_with_race_records(
        tmp_path, monkeypatch, 3, True)
    capsys.readouterr()
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir)]) == 0
