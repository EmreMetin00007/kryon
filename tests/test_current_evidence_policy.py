"""Historical signatures must not imply current reportability."""
import json
import sqlite3
import importlib.util
from pathlib import Path

from conftest import load_server


def test_stale_artifact_is_historical_not_current_in_consumers(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_GRAPH_BACKEND", "networkx")
    monkeypatch.setenv("CCO_SCOPE_REVISION", "scope-v1")
    monkeypatch.setenv("CCO_POLICY_HASH", "policy-v1")
    validator = load_server("validator")
    memory = load_server("memory-server")
    hunter = load_server("hunter")
    kali = load_server("kali-tools")
    url = "https://owned.test/search?q=1"
    record = json.loads(validator._result(
        "SQL Injection", url, "CONFIRMED", "differential_boolean", {}, "-",
        guard={"transport_ok": True}, request_evidence=[{
            "role": "probe", "transport_ok": True, "status": 200,
            "method": "GET", "request_url": url}]))
    artifact = record["artifact"]["path"]
    assert validator.artifact_is_valid(record)
    assert memory._extract_validation_metadata("", validation_artifact_path=artifact,
        finding_target=url, finding_type="SQL Injection")["reportable"] == 1
    stored = memory._store_finding_internal(url, "SQL Injection", "medium", "synthetic",
                                             validation_result_json=json.dumps(record))
    snapshot_path = Path(__file__).resolve().parents[1] / "scripts" / "tui_snapshot.py"
    spec = importlib.util.spec_from_file_location("tui_snapshot_current_test", snapshot_path)
    snapshot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(snapshot)
    monkeypatch.setattr(snapshot, "CCO", tmp_path / "home")
    assert snapshot.finding_snapshot(Path(memory.DB_PATH))[1]["id"] == stored["finding_id"]
    assert kali._validation_artifact_current(artifact, url, "SQL Injection")
    assert hunter._load_confirmed_artifact(record["validation_id"])[0]

    monkeypatch.setenv("CCO_POLICY_HASH", "policy-v2")
    assert validator.artifact_is_valid(record), "historical signature remains verifiable"
    stale = memory._extract_validation_metadata("", validation_artifact_path=artifact,
        finding_target=url, finding_type="SQL Injection")
    assert stale["reportable"] == 0 and stale["validation_state"] != "verified"
    assert not kali._validation_artifact_current(artifact, url, "SQL Injection")
    assert hunter._load_confirmed_artifact(record["validation_id"])[0] is None
    counts, latest = snapshot.finding_snapshot(Path(memory.DB_PATH))
    assert latest is None and counts["stale_or_invalid_artifact"] == 1
    assert "UNVERIFIED_INPUT" in validator.generate_validation_report(json.dumps(record))
    with sqlite3.connect(memory.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM findings WHERE id=?", (stored["finding_id"],)).fetchone()
    current = memory._serialize_finding_row(row)
    assert current["reportable"] is False
    assert json.loads(memory.update_finding_validation(stored["finding_id"], state="confirmed"))["updated"] is False


def test_missing_explicit_scope_or_policy_does_not_fall_back_to_repo(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("CCO_SCOPE_REVISION", raising=False)
    monkeypatch.delenv("CCO_POLICY_HASH", raising=False)
    monkeypatch.setenv("CCO_SCOPE_FILE", str(tmp_path / "missing-scope.json"))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(tmp_path / "missing-policy.json"))
    validator = load_server("validator")
    from cco_validator_core.evidence import current_scope_revision, current_policy_hash
    assert current_scope_revision() == "scope:missing"
    assert current_policy_hash() == "policy:unreadable"
    assert not validator.artifact_is_current({})


def test_old_oob_signature_remains_historical_but_is_not_reportable(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_GRAPH_BACKEND", "networkx")
    monkeypatch.setenv("CCO_SCOPE_REVISION", "scope-v1")
    monkeypatch.setenv("CCO_POLICY_HASH", "policy-v1")
    validator = load_server("validator")
    memory = load_server("memory-server")
    url = "https://owned.test/fetch?url=x"
    record = json.loads(validator._result(
        "SSRF", url, "CONFIRMED", "oob_correlation", {"correlated": True}, "-",
        guard={"transport_ok": True}, request_evidence=[{
            "role": "probe", "transport_ok": True, "status": 200,
            "method": "GET", "request_url": url}]))
    assert validator.artifact_is_valid(record)
    assert not validator.artifact_is_current(record)
    metadata = memory._extract_validation_metadata("", validation_artifact_path=record["artifact"]["path"],
                                                    finding_target=url, finding_type="SSRF")
    assert metadata["reportable"] == 0
    brain_path = Path(__file__).resolve().parents[1] / "scripts" / "brain.py"
    spec = importlib.util.spec_from_file_location("brain_oob_current_test", brain_path)
    brain = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(brain)
    resolved, _ = brain._confirmation_record({"validation_id": record["validation_id"]}, "ssrf", {"target": url})
    assert resolved is None
