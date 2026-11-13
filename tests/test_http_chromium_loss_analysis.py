"""Offline audit boundaries: signatures, scope, primary truth and file controls."""
import json
from pathlib import Path
import sqlite3
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import http_chromium_loss_analysis as audit
from test_automatic_negative_controls import BASE, HEADERS, environment, transport  # noqa: F401


@pytest.fixture
def saved_seed(environment, monkeypatch, tmp_path):
    hunter, home, _scope = environment
    handler, state = audit.make_lab(20261104, version="blind-lab/2")
    try:
        transport(monkeypatch, handler)
        candidate = {"url": BASE + "hello?name=guest", "method": "GET", "param": "name", "carrier": "query",
                     "vuln_class": "ssti", "identity": "anonymous", "resource_owner": "unspecified", "run_id": "audit-run"}
        raw = hunter._loop_validate(candidate, headers=json.dumps(HEADERS))
        record = json.loads(raw) if isinstance(raw, str) else raw
        assert record["verdict"] == "CONFIRMED"
        assert hunter._record_coverage_validation(BASE, candidate, record)
        yield tmp_path, home, record
    finally:
        state["db"].close()


def test_saved_events_verify_with_public_keys_and_do_not_modify_inputs(saved_seed, monkeypatch):
    directory, home, record = saved_seed
    monkeypatch.setattr(audit.trust, "_read_private", lambda *_: pytest.fail("audit must not read private keys"))
    paths = [home / "agent_memory.db", Path(record["artifact"]["path"]), directory / "policy.json", directory / "scope.json"]
    before = [audit.sha256(path) for path in paths]
    events, records, _ = audit.verify_events(directory, BASE, "audit-run")
    assert len(events) == 1 and events[0]["status"] == "confirmed"
    assert records[record["validation_id"]] == record
    assert before == [audit.sha256(path) for path in paths]


@pytest.mark.parametrize("fault", ["artifact", "signature", "policy", "scope", "context", "legacy", "outside_path", "verdict"])
def test_invalid_or_mismatched_saved_evidence_cannot_be_scored(saved_seed, fault):
    directory, home, record = saved_seed
    path = Path(record["artifact"]["path"])
    if fault in {"artifact", "legacy"}:
        if fault == "artifact":
            record["verdict"] = "UNCONFIRMED"
        else:
            record["artifact"]["signature"]["algorithm"] = "hmac-sha256:v1"
        path.write_text(json.dumps(record))
    elif fault in {"policy", "scope"}:
        path = directory / (fault + ".json")
        path.write_text(path.read_text() + "\n")
    else:
        with sqlite3.connect(home / "agent_memory.db") as db:
            (raw,) = db.execute("SELECT signed_json FROM hunter_coverage_events").fetchone()
            signed = json.loads(raw)
            if fault == "signature":
                signed["signature"] = "0" * 128
            else:
                if fault == "context":
                    signed["payload"]["identity"] = "someone-else"
                elif fault == "verdict":
                    signed["payload"]["status"] = "tested_clean"
                else:
                    signed["payload"]["artifact_path"] = str(directory / "outside.json")
                    (directory / "outside.json").write_text(json.dumps(record))
                signed = audit.trust.attest(signed["payload"], "coverage-attempt")
            db.execute("UPDATE hunter_coverage_events SET signed_json=?", (json.dumps(signed),))
    with pytest.raises(ValueError):
        audit.verify_events(directory, BASE, "audit-run")


def test_supplemental_matrix_preserves_primary_cases_and_excludes_owner_self_access():
    _, state = audit.make_lab(20261104, version="blind-lab/2")
    try:
        original = json.dumps(state["truth"])
        extra = audit.supplemental_access_truth(state)
        assert len(extra) == 8 and sum(case["expected"] == "positive" for case in extra) == 4
        assert sum(case["expected"] == "negative" for case in extra) == 4
        assert all(case["owner"] != case["actor"] for case in extra)
        assert json.dumps(state["truth"]) == original
        assert len(state["truth"]) == 16
    finally:
        state["db"].close()


def test_direct_basename_exposure_cannot_be_called_traversal():
    handler, state = audit.make_lab(20261104, version="blind-lab/2")
    rule = {"mode": "application_files", "files": [{"url": BASE + "file", "param": "name", "carrier": "query",
        "path": "../secret.txt", "marker": "root:x:0:0:synthetic:/root:/bin/bash", "test_data_only": True, "outside_root": True}]}
    try:
        model = audit.traversal_model(handler, rule, BASE)
        assert [row["status"] for row in model["controls"]] == [200, 200, 404, 200, 200]
        assert model["controls"][1]["marker_present"] and not model["boundary_established"]
        assert model["counts_toward_acceptance"] is False
    finally:
        state["db"].close()


@pytest.mark.parametrize("seed", [20261104, 20261105, 20261106, 20261107, 20261108])
@pytest.mark.parametrize("path,expected,statuses", [
    ("file", "CONFIRMED", [200, 404, 404, 200, 200]),
    ("safe/file", "UNCONFIRMED", [200, 404, 400, 400, 400]),
])
def test_version_three_enforces_directory_boundary(environment, monkeypatch, seed, path, expected, statuses):
    hunter, *_ = environment
    handler, state = audit.make_lab(seed, version="blind-lab/3")
    try:
        calls = transport(monkeypatch, handler)
        candidate = {"url": BASE + path + "?name=notes.txt", "method": "GET", "param": "name",
                     "carrier": "query", "vuln_class": "path_traversal", "identity": "anonymous",
                     "resource_owner": "unspecified", "run_id": "boundary-run"}
        result = json.loads(hunter._loop_validate(candidate, headers=json.dumps(HEADERS)))
        assert result["verdict"] == expected
        assert len(calls) == 5
        assert [row["status"] for row in result["request_evidence"]] == statuses
        assert [row["role"] for row in result["request_evidence"]] == [
            "baseline", "direct-name", "missing-file", "traversal-probe", "traversal-repeat"]
        assert hunter._record_coverage_validation(BASE, candidate, result)
        events = hunter._verified_coverage_events(BASE)
        assert len(events) == 1
        assert events[0]["status"] == ("confirmed" if path == "file" else "tested_clean")
        assert "root:x:0:0:synthetic" not in json.dumps(result)
    finally:
        state["db"].close()


@pytest.mark.parametrize("name,status", [
    ("secret.txt", 404), ("/secret.txt", 404), ("nested/secret.txt", 404),
    ("notsecret.txt", 404), ("../missing.txt", 404), ("../secret.txt", 200),
    ("notes.txt", 200),
])
def test_version_three_resolves_paths_instead_of_matching_suffixes(name, status):
    from urllib.parse import urlencode
    handler, state = audit.make_lab(20261104, version="blind-lab/3")
    try:
        instance = handler.__new__(handler)
        instance.path, instance.headers = "/file?" + urlencode({"name": name}), {}
        replies = []
        instance._send = lambda code, *_args, **_kwargs: replies.append(code)
        instance.do_GET()
        assert replies == [status]
    finally:
        state["db"].close()


@pytest.mark.parametrize("output", [audit.ROOT / "analysis", Path("/tmp/acceptance-evidence/analysis")])
def test_cli_cannot_write_into_code_or_original_evidence(output):
    with pytest.raises(SystemExit) as caught:
        audit.main(["/tmp/acceptance-evidence", "--output-dir", str(output)])
    assert caught.value.code == 2
