"""Checkpoint sealing and foreign-spec/workdir rejection tests."""
import json
from pathlib import Path
import sys

import pytest

from conftest import load_server, make_signed_validation

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import brain


@pytest.fixture
def run(tmp_path, monkeypatch):
    home, work = tmp_path / "home", tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_WORKDIR", str(work))
    monkeypatch.delenv("CCO_BASH_SANDBOXED", raising=False)
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    monkeypatch.delenv("CCO_ARTIFACT_HMAC_KEY", raising=False)
    scope, policy = work / "scope.json", work / "policy.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://own.test"}]}))
    policy.write_text("{}")
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    ledger = brain.ledger_mod.init_ledger("https://own.test", vectors=("csrf",))
    record = make_signed_validation(ledger["target"], "csrf")
    entry = brain.ledger_mod.mark(ledger, "csrf", "confirmed")
    entry.update(brain._confirmation_reference(record))
    brain.ledger_mod.save_ledger(work, ledger)
    (work / "specs.json").write_text(brain.dump_specs(brain.build_plan(
        ledger["target"], str(work), phases=("access",))))
    return home, work, record


def test_checkpoint_seals_only_after_the_existing_validator_gate(run):
    _, work, record = run
    server = load_server("kali-tools")
    outcome = server.ledger_checkpoint_impl(str(work), seal=True)
    assert outcome["sealed"] and outcome["check_exit"] == 0
    assert brain.main(["closure", "verify", "--workdir", str(work)]) == 0
    Path(record["artifact"]["path"]).unlink()
    result = json.loads(server.ledger_checkpoint(str(work), seal=True))
    assert result.get("error") or result.get("check_exit") == 2


def test_checkpoint_rejects_forged_confirmation_and_foreign_spec(run):
    _, work, _ = run
    server = load_server("kali-tools")
    state = brain.ledger_mod.load_ledger(work)
    state["hypotheses"][0].pop("validation_id")
    brain.ledger_mod.save_ledger(work, state)
    outcome = server.ledger_checkpoint_impl(str(work), seal=True)
    assert outcome["check_exit"] == 2 and outcome["sealed"] is False
    assert not (work / "closure.json").exists()
    specs = brain.build_plan("https://foreign.test", str(work), phases=("access",))
    (work / "specs.json").write_text(brain.dump_specs(specs))
    with pytest.raises(ValueError, match="target"):
        server.ledger_checkpoint_impl(str(work), seal=True)


def test_checkpoint_rejects_external_spec_and_workdir(run, tmp_path):
    _, work, _ = run
    server = load_server("kali-tools")
    outside = tmp_path / "outside.json"
    outside.write_text("[]")
    for spec in (str(outside), "../outside.json"):
        with pytest.raises(ValueError, match="inside the run"):
            server.ledger_checkpoint_impl(str(work), seal=True, spec_file=spec)
    with pytest.raises(ValueError, match="CCO_WORKDIR"):
        server.ledger_checkpoint_impl(str(tmp_path))
