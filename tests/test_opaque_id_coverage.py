"""UUID and opaque identifiers stay tied to family and signed attempts."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import attempt_ledger as attempts  # noqa: E402
import brain  # noqa: E402
import hypothesis_ledger as hypotheses  # noqa: E402

UUID_A = "5080c899-12bf-4523-89ce-d91a5ce3d1f4"
UUID_B = "c534cae2-f5c9-41bc-b77a-de99aa2df907"


def test_uuid_and_opaque_seeds_preserve_family_without_numeric_fragments():
    pool = hypotheses.object_candidates(
        routes=[f"https://owned.test/api/orders/{UUID_A}"],
        own_ids=[{"family": "orders", "id": UUID_A},
                 {"family": "orders", "id": "opaque-a9"}], radius=25)
    assert {"family": "orders", "format": "uuid", "value": UUID_A} in pool
    assert {"family": "orders", "format": "opaque", "value": "opaque-a9"} in pool
    assert not any(isinstance(value, int) for value in pool)


def test_numeric_families_remain_distinct_in_candidate_pool():
    pool = hypotheses.object_candidates(
        own_ids=[{"family": "orders", "id": "7"}, {"family": "files", "id": "7"}], radius=0)
    assert {"family": "orders", "format": "int", "value": 7} in pool
    assert {"family": "files", "format": "int", "value": 7} in pool


def test_signed_uuid_records_drive_handoff_and_closure(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    run = tmp_path / "run"
    run.mkdir()
    first = {"family": "orders", "format": "uuid", "value": UUID_A}
    second = {"family": "orders", "format": "uuid", "value": UUID_B}
    (run / "object-pool.json").write_text(json.dumps({"candidates": [first, second]}))
    path = attempts.ledger_path(run)
    attempts.append_record(path, {"vector": "authz-idor", "endpoint": f"/api/orders/{UUID_A}",
                                  "identity": "alice", "verdict": "control", "status": 200,
                                  "candidate": first, "control": first})
    records = attempts.read_records(path)
    result = attempts.coverage(records, "authz-idor", [first, second], path=path)
    assert result["tried"] == [first] and result["untried"] == [second]
    assert result["controls"] == 1
    packet = brain._handoff_packet(str(run), "authz-idor", 4000)
    assert packet["untried"] == [second]
    (run / "handoff-authz-idor.json").write_text(json.dumps(packet))
    spec = brain.TaskSpec(id="authz-1", phase="authz", target="https://owned.test",
                          vector="authz-idor", evidence_dir=str(run / "authz"))
    assert brain._handoff_gate_error(spec) is None
    (run / "object-pool.json").write_text(json.dumps({"candidates": [first, second], "truncated": True}))
    assert "stale" in brain._handoff_gate_error(spec)
    assert "truncated" in brain._ledger_coverage_block(str(run), "authz-idor")
    (run / "object-pool.json").write_text(json.dumps({"candidates": [first, second]}))
    assert "untried" in brain._ledger_coverage_block(str(run), "authz-idor")
    attempts.append_record(path, {"vector": "authz-idor", "endpoint": f"/api/orders/{UUID_B}",
                                  "identity": "bob", "verdict": "observed", "status": 403,
                                  "candidate": second, "control": first})
    assert brain._ledger_coverage_block(str(run), "authz-idor") is None


def test_uuid_attempt_on_other_family_does_not_close_expected_coverage(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    candidate = {"family": "orders", "format": "uuid", "value": UUID_A}
    path = tmp_path / "attempts.jsonl"
    attempts.append_record(path, {"vector": "authz-idor", "endpoint": f"/api/files/{UUID_A}",
                                  "identity": "alice", "verdict": "observed", "status": 200,
                                  "candidate": candidate})
    result = attempts.coverage(attempts.read_records(path), "authz-idor", [candidate], path=path)
    assert result["tried"] == [] and result["untried"] == [candidate]


def test_uuid_survives_cli_pool_and_signed_attempt(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    run = tmp_path / "run"
    run.mkdir()
    summary = run / "enum.json"
    summary.write_text(json.dumps({"surface": {"routes": [], "docs": []}}))
    assert brain.main(["hypotheses", "pool", "--workdir", str(run), "--summary", str(summary),
                       "--own-ids", f"orders:{UUID_A}", "--radius", "0"]) == 0
    expected = {"family": "orders", "format": "uuid", "value": UUID_A}
    assert json.loads((run / "object-pool.json").read_text())["candidates"] == [expected]
    assert brain.main(["attempts", "add", "--workdir", str(run), "--vector", "authz-idor",
                       "--endpoint", f"/api/orders/{UUID_A}", "--identity", "alice", "--verdict", "control",
                       "--candidate", f"orders:{UUID_A}", "--control", f"orders:{UUID_A}",
                       "--status", "200"]) == 0
    assert attempts.read_records(attempts.ledger_path(run))[0]["candidate"] == expected
    assert brain._ledger_coverage_block(str(run), "authz-idor") is None
    capsys.readouterr()
def test_large_observed_pool_cannot_silently_close():
    import brain
    own = [{"family": "account", "id": f"opaque-{i}"} for i in range(225)]
    radius, pool, truncated, dropped = brain._budgeted_pool([], own, [], 1000)
    assert radius == 0
    assert len(pool) == 200
    assert truncated is True
    assert dropped == 25
