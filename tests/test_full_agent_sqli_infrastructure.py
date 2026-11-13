"""Frozen SQL family identity, actual SELECT/HTTP controls and fail-closed scoring."""
from __future__ import annotations

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import threading
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest

import full_agent_holdout as holdout
import full_agent_launcher as launcher
import full_agent_preflight as preflight
from full_agent_broker import dump
from conftest import load_server
from test_full_agent_preflight import prepared_snapshot, baseline, runtime_source, acceptance_evidence
from test_full_agent_holdout import test_frozen_family_contract_rejects_source_or_requirement_drift as frozen_check

FAMILY = "readonly-sql-injection"


@pytest.fixture
def sql_lab(tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir()
    lab = holdout.start(holdout.selection(FAMILY, 987654321), private)
    base = f"http://127.0.0.1:{lab.server_port}/"
    runtime = tmp_path / "runtime"
    (runtime / ".codex").mkdir(parents=True)
    scope, policy = launcher.lab_policy(base)
    dump(runtime / ".codex/scope.json", scope)
    dump(runtime / ".codex/program-policy.json", policy)
    assert launcher.verify_lab_scope(runtime, base)["before_traffic"]
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(runtime / ".codex/scope.json"))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(runtime / ".codex/program-policy.json"))
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    try:
        yield lab, base, private
    finally:
        lab.shutdown()
        lab.server_close()
        thread.join(timeout=5)
        lab.blind_state["db"].close()


def test_sql_identity_and_duplicate_or_renamed_credit():
    first, repeat = holdout.selection(FAMILY, 123), holdout.selection(FAMILY, 456)
    assert first["family"] == repeat["family"] and first["lab_sha256"] == repeat["lab_sha256"]
    assert first["family"] != "readonly-api-access-control"
    for family in ("renamed-readonly-sql", "readonly-sqli/123"):
        with pytest.raises(ValueError):
            holdout.selection(family, 123)
    metrics = {"family": FAMILY, "recall": {"numerator": 8, "denominator": 8, "value": 1.0},
               "negative_coverage": {"numerator": 8, "denominator": 8, "value": 1.0},
               "false_positives": {"numerator": 0, "denominator": 8, "value": 0.0}}
    contract = preflight.native_contract({}, {}, 100)["holdout"]
    with pytest.raises(ValueError, match="repeated"):
        holdout.aggregate([metrics, metrics], contract)
    api = {**metrics, "family": "readonly-api-access-control"}
    summary = holdout.aggregate([api, metrics], contract)
    assert summary["positives"] == summary["negatives"] == 16
    assert len(summary["families"]) == 2 and summary["status"] == "incomplete"
    assert summary["false_positives"] == {"numerator": 0, "denominator": 16}


@pytest.mark.parametrize("fault", ["lab_sha256", "evaluator_sha256", "lab_version", "seed", "minimum_families"])
def test_frozen_sql_contract(prepared_snapshot, fault, monkeypatch):
    # Reuse the same replay mutation test with the second registered identity.
    with monkeypatch.context() as family:
        family.setitem(frozen_check.__globals__, "FAMILY", FAMILY)
        frozen_check(prepared_snapshot, fault)


def test_sql_family_excluded_from_solver():
    for path in ("scripts/full_agent_holdout.py", "scripts/lab/readonly_sqli_holdout.py",
                 "tests/test_full_agent_sqli_holdout.py", "graphify-out/graph.json"):
        assert not preflight.runtime_file(Path(path))


def test_actual_select_http_and_signed_boolean_controls(sql_lab):
    lab, base, private = sql_lab
    validator = load_server("validator")
    from cco_validator_core.egress import scoped_wire_gate
    from cco_validator_core.evidence import artifact_is_current, validation_context
    artifacts = []
    state = lab.blind_state
    def gate(method, url, headers):
        return (method == "GET" and urlsplit(url).netloc == urlsplit(base).netloc), "owned loopback"
    with scoped_wire_gate(gate):
        for case in state["truth"]:
            context = {"run_id": "run-sql-controls", "vuln_class": "sql_injection", "method": "GET",
                       "param": "id", "carrier": "query", "identity": "anonymous", "resource_owner": "unspecified"}
            with validation_context(context):
                record = json.loads(validator.validate_sqli(base.rstrip("/") + case["path"] + "?id=1",
                                                           param="id", boolean_only=True))
            assert record["verdict"] == ("CONFIRMED" if case["expected"] == "positive" else "UNCONFIRMED"), case
            assert artifact_is_current(record, expected_target=record["target"], expected_finding_type="sql_injection")
            path = record["artifact"]["path"]
            artifacts.append({"record": record, "path": path, "sha256": holdout.digest(path)})
    def verify(record):
        return artifact_is_current(record, expected_target=record["target"], expected_finding_type="sql_injection")
    result = holdout.evaluate(state["truth"], state["wire"], artifacts, target=base,
                              run_id="run-sql-controls", verify_artifact=verify)
    assert result["recall"]["numerator"] == result["negative_coverage"]["numerator"] == 8
    assert result["false_positives"] == {"numerator": 0, "denominator": 8, "value": 0.0}
    assert not result["rejected_evidence"]
    assert len(state["wire"]) == state["requests"] == 104
    assert all(row["query"].startswith("WITH inventory") for row in state["wire"] if row["query"])
    # Operations outside the SELECT authorizer allowlist are denied.
    with pytest.raises(sqlite3.DatabaseError):
        state["db"].execute("PRAGMA user_version")
    # Response hashes alone cannot substitute reflected/error/empty/failing
    # behavior for actual SELECT rows or the exact submitted SQL parameter.
    for fault in ("reflection", "generic_error", "empty_baseline", "failed_transport", "wrong_payload"):
        changed = copy.deepcopy(state["wire"])
        for row in changed:
            if fault == "reflection":
                row["sql_rows"] = None
            elif fault == "generic_error":
                row["sql_error"] = "generic error"
            elif fault == "empty_baseline":
                row["sql_rows"] = []
            elif fault == "failed_transport":
                row["status"] = 503
            else:
                row["request_path"] = row["path"] + "?id=unrelated"
        denied = holdout.evaluate(state["truth"], changed, artifacts, target=base,
                                  run_id="run-sql-controls", verify_artifact=verify)
        assert denied["recall"]["numerator"] == denied["negative_coverage"]["numerator"] == 0
    dump(private / "infra-metrics.json", result)


@pytest.mark.parametrize("behavior", ["reflection", "generic_error", "empty_results", "http_failure"])
def test_actual_http_oracle_traps_never_confirm(tmp_path, monkeypatch, behavior):
    validator = load_server("validator")
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "state"))
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            value = dict(parse_qsl(urlsplit(self.path).query)).get("id", "1")
            payload = ({"input": value} if behavior == "reflection" else
                       {"error": "SQL syntax error"} if behavior == "generic_error" else {"records": []})
            raw = json.dumps(payload).encode()
            self.send_response(503 if behavior == "http_failure" else 200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    lab = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base = f"http://127.0.0.1:{lab.server_port}/"
    runtime = tmp_path / "runtime"
    (runtime / ".codex").mkdir(parents=True)
    scope, policy = launcher.lab_policy(base)
    dump(runtime / ".codex/scope.json", scope)
    dump(runtime / ".codex/program-policy.json", policy)
    assert launcher.verify_lab_scope(runtime, base)["before_traffic"]
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    from cco_validator_core.egress import scoped_wire_gate
    try:
        with scoped_wire_gate(lambda method, url, headers: (method == "GET" and url.startswith(base), "owned lab")):
            result = json.loads(validator.validate_sqli(base + "?" + urlencode({"id": "1"}),
                                                       param="id", boolean_only=True))
        assert result["verdict"] != "CONFIRMED"
        # A failed or empty baseline cannot be credited as a tested negative.
        if behavior != "reflection":
            assert result["verdict"] == "INCONCLUSIVE"
    finally:
        lab.shutdown()
        lab.server_close()
        thread.join(timeout=5)


def test_sql_unknown_profile_fails_before_network():
    hunter = load_server("hunter")
    result = json.loads(hunter.run_web_loop("http://127.0.0.1:1/", live=True, validation_profile="unknown"))
    assert not result["ok"] and result["requests_authorized"] == 0


@pytest.mark.parametrize("context", ["numeric", "single-quoted"])
def test_sql_loop_uses_only_signed_boolean_controls(sql_lab, monkeypatch, context):
    from collections import Counter

    lab, base, _private = sql_lab
    hunter = load_server("hunter")
    from cco_hunter_core.request_context import bind_policy_gate
    state = lab.blind_state
    case = next(case for case in state["truth"] if case["context"] == context)
    catalog = case["path"].rsplit("/", 1)[0]
    cases = [case for case in state["truth"] if case["path"].startswith(catalog + "/")]

    def no_light_probe(*args, **kwargs):
        pytest.fail("read-only SQL candidates must go directly to the boolean validator")

    monkeypatch.setattr(hunter, "_live_request", no_light_probe)
    with bind_policy_gate(lambda method, url, headers: (
            method == "GET" and urlsplit(url).netloc == urlsplit(base).netloc, "owned loopback")):
        result = json.loads(hunter.run_web_loop(
            base.rstrip("/") + catalog, live=True, crawl=False, fuzz_limit=4,
            max_validations=4, candidate_sample_limit=4, validation_profile="readonly_sqli_boolean"))
    assert result["ok"] and not result["errors"]
    assert result["fuzz"]["executed_live"] == 0
    assert not result["exploits"]
    assert len(result["validations"]) == len(cases)
    assert all(row["coverage_recorded"] for row in result["validations"])
    assert len(result["confirmed"]) == sum(case["expected"] == "positive" for case in cases)
    counts = Counter(row["path"] for row in state["wire"])
    for case in cases:
        assert counts[case["path"]] == (8 if context == "single-quoted" and case["expected"] == "positive" else 6)
    artifacts = [{"path": str(path), "sha256": holdout.digest(path), "record": json.loads(path.read_text())}
                 for path in (Path(hunter.CCO_HOME) / "validations").glob("*.json")]
    from cco_validator_core.evidence import artifact_is_current
    metrics = holdout.evaluate(cases, state["wire"], artifacts, target=base, run_id=result["run_id"],
                              verify_artifact=lambda record: artifact_is_current(
                                  record, expected_target=record["target"], expected_finding_type="sql_injection"))
    assert metrics["recall"]["value"] == metrics["negative_coverage"]["value"] == 1.0
    assert metrics["false_positives"]["numerator"] == 0
    assert not metrics["rejected_evidence"]
