"""Candidate losses and repair plans; transport and all identities are synthetic."""
import json
import importlib.util
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers/mcp-hunter"))
sys.path.insert(0, str(ROOT / "mcp-servers/mcp-memory-server"))
from cco_hunter_core.candidates import select_candidates, fair_queue, interleave_probes
from cco_hunter_core.feedback import build_feedback, persist_feedback, list_feedback, verified_feedback
from cco_hunter_core.loop import execute_web_loop
from cco_surface_core.normalize import normalize_record


def probe(kind="sql_injection", **kw):
    return {"url": "https://own.test/item?id=1", "baseline_url": "https://own.test/item?id=1",
            "method": "GET", "vuln_class": kind, "param": "id", "location": "query",
            "operation_id": "op-1", "observation_id": 1, "live": True,
            "baseline_eligible": True, "triage_verdict": "INCONCLUSIVE",
            "coverage_status": "inconclusive", **kw}


@pytest.mark.parametrize("field,value", [("live", False), ("baseline_eligible", False),
    ("triage_verdict", "WAF_BLOCKED"), ("coverage_status", "not_tested"),
    ("coverage_status", "blocked")])
def test_failed_or_unexecuted_probe_cannot_enter_sampling(field, value):
    assert select_candidates([probe(**{field: value})]) == []


def test_sampling_balances_classes_and_keeps_resource_carrier_and_observation():
    rows = [probe(param=str(i)) for i in range(6)]
    rows += [probe("ssti"), probe("path_traversal"), probe("lfi")]
    selected = select_candidates(rows, 3)
    assert [r["vuln_class"] for r in selected] == ["sql_injection", "ssti", "path_traversal"]
    assert all(r["candidate_source"] == "bounded_sampling" for r in selected)
    assert select_candidates(rows, 0) == []
    rows = [probe(triage_verdict="LIKELY"), probe(triage_verdict="LIKELY", location="cookie"),
            probe(triage_verdict="LIKELY", observation_id=2),
            probe(triage_verdict="LIKELY", url="https://own.test/other?id=1",
                  baseline_url="https://own.test/other?id=1")]
    assert len(select_candidates(rows + rows)) == 4


def test_validation_queue_prevents_first_class_consuming_all_slots():
    items = [probe("bola", param=str(i)) for i in range(6)] + [probe("ssti"), probe("sql_injection")]
    assert [r["vuln_class"] for r in fair_queue(items)[:3]] == ["bola", "ssti", "sql_injection"]


def test_completed_xss_and_redirect_controls_are_bounded_candidates():
    rows = [probe("xss_reflected", status=200), probe("open_redirect", status=400)]
    selected = select_candidates(rows, 2)
    assert {row["vuln_class"] for row in selected} == {"xss_reflected", "open_redirect"}
    assert all(row["candidate_source"] == "bounded_sampling" for row in selected)
    assert len(select_candidates(rows, 1)) == 1
    assert not select_candidates(rows, 0)


@pytest.mark.parametrize("status", [None, 0, True, "200", 401, 403, 404, 429, 500, 503])
@pytest.mark.parametrize("verdict", ["LIKELY", "INCONCLUSIVE"])
def test_explicit_failed_probe_status_cannot_enter_candidate_queue(status, verdict):
    assert not select_candidates([probe("open_redirect", status=status, triage_verdict=verdict)])


@pytest.mark.parametrize("limit", [-1, 21, True, "4", 1.5, None])
def test_invalid_sampling_limit_is_rejected_before_discovery(hunter, monkeypatch, limit):
    monkeypatch.setattr(hunter, "_loop_discover", lambda *a, **kw: pytest.fail("must reject before transport"))
    result = json.loads(hunter.run_web_loop("https://own.test/", live=True, candidate_sample_limit=limit))
    assert result["ok"] is False and result["requests_authorized"] == 0
    assert "candidate_sample_limit" in result["error"]


def test_canary_budget_visits_operations_before_more_payloads():
    rows = [probe(param=str(i)) for i in range(5)] + [probe("ssti", operation_id="op-2")]
    assert [r["operation_id"] for r in interleave_probes(rows)[:2]] == ["op-1", "op-2"]
    assert len(interleave_probes(rows)) == len(rows)


@pytest.mark.parametrize("record,kind", [
    ({"url": "https://own.test/hello?name=guest"}, "ssti"),
    ({"url": "https://own.test/account/statement"}, "authentication_bypass"),
    ({"url": "https://own.test/opaque", "auth_required": True}, "authentication_bypass")])
def test_surface_applicability_does_not_require_search_or_login_route(record, kind):
    assert kind in normalize_record(record)["suggested_classes"]


@pytest.fixture
def hunter(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_GRAPH_BACKEND", "networkx")
    module = load_server("hunter")
    monkeypatch.setattr(module, "write_artifact", lambda *a, **kw: "")
    return module


def test_inconclusive_query_sqli_and_traversal_reach_bound_validator(hunter, monkeypatch):
    records = [{"url": f"https://own.test/{path}?{param}={value}", "method": "GET",
                "params": [{"name": param, "in": "query", "sample": value}],
                "suggested_classes": [kind], "operation_id": f"op-{path}", "observation_id": 1}
               for path, param, value, kind in [("item", "id", "1", "sql_injection"),
                                              ("file", "name", "notes.txt", "path_traversal")]]
    from cco_surface_core.store import ingest_records, query_surface
    # Observation IDs must come from the same persistent request inventory that
    # the capture guard verifies. A fabricated ID is deliberately rejected.
    expected = {record["url"]: record["suggested_classes"] for record in records}
    ingest_records(records, db_path=hunter.MEM_DB)
    records = [{**record, "suggested_classes": expected[record["url"]]}
               for record in query_surface("own.test", db_path=hunter.MEM_DB)]
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": records})
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: {
        "ok": True, "status": 200, "text": "no light signal", "len": 15, "headers": {}})
    called = []
    out = execute_web_loop("https://own.test", live=True, crawl=False, fuzz=hunter._loop_fuzz,
                           validate=lambda item, **kw: called.append(item) or {"verdict": "INCONCLUSIVE"})
    assert {r["vuln_class"] for r in called} == {"sql_injection", "path_traversal"}
    assert all(r["request_ref"] and r["candidate_source"] == "bounded_sampling" for r in called)
    assert not out["confirmed"]


def test_sqlite_signal_is_new_error_only(hunter):
    baseline = {"ok": True, "text": "item: apple", "status": 200, "len": 11}
    error = {"ok": True, "text": "error: sqlite3.OperationalError: near syntax", "status": 200, "len": 51}
    assert hunter._light_oracle("sql_injection", "'", baseline, error)[0] == "LIKELY"
    assert hunter._light_oracle("sql_injection", "'", error, error)[0] != "LIKELY"


def identities(url, kind="bfla"):
    resource = {"url": url, "marker": "synthetic-private-marker", "test_data_only": True,
                "denied_roles": ["member"], "authentication_required": True}
    return {"admin": {"headers": {"Cookie": "session=admin"}, "role": "admin",
                      "functions" if kind == "bfla" else "protected_resources": [resource]},
            "member": {"headers": {"Cookie": "session=member"}, "role": "member"}}


@pytest.mark.parametrize("kind", ["bfla", "authentication_bypass"])
def test_declared_test_resource_binds_without_object_id(hunter, monkeypatch, kind):
    url = "https://own.test/opaque"
    ids = identities(url, kind)
    calls = []
    candidate = {"url": url, "method": "GET", "vuln_class": kind, "authz_candidate": True}
    result = execute_web_loop("https://own.test", live=True, crawl=False, identities=ids,
        fuzz=lambda *a, **kw: {"probes": 0, "validator_queue": [candidate]},
        authz_validate=lambda item, actors: calls.append(item) or {"verdict": "INCONCLUSIVE"})
    assert len(calls) == 1 and calls[0]["test_resource"] and not calls[0].get("owned_object")
    assert calls[0]["owner_identity"] == "admin"
    assert calls[0]["attacker_identity"] == ("member" if kind == "bfla" else "anonymous")
    assert "synthetic-private-marker" not in json.dumps(result)
    validator_calls = []
    monkeypatch.setattr(hunter, "_load_peer", lambda *a: SimpleNamespace(
        _validate_bfla_readonly=lambda *a, **kw: validator_calls.append((a, kw)) or '{"verdict":"INCONCLUSIVE"}',
        validate_auth_bypass=lambda *a, **kw: validator_calls.append((a, kw)) or '{"verdict":"INCONCLUSIVE"}'))
    hunter._loop_authz_validate(calls[0], ids)
    assert validator_calls
    collection = "functions" if kind == "bfla" else "protected_resources"
    ids["admin"][collection][0]["marker"] = "changed"
    validator_calls.clear()
    assert hunter._loop_authz_validate(calls[0], ids)["verdict"] == "INCONCLUSIVE"
    assert not validator_calls


def test_bfla_missing_role_rule_produces_repair_plan_without_validation():
    url = "https://own.test/admin/report"
    ids = identities(url)
    ids["admin"]["functions"][0].pop("denied_roles")
    calls = []
    result = execute_web_loop("https://own.test", live=True, crawl=False, identities=ids,
        fuzz=lambda *a, **kw: {"probes": 0, "validator_queue": [{"url": url,
            "vuln_class": "bfla", "authz_candidate": True}]},
        authz_validate=lambda *a: calls.append(a))
    assert calls == []
    skipped = next(r for r in result["skipped"] if isinstance(r, dict) and r.get("vuln_class") == "bfla")
    assert skipped["reason_code"] == "missing_access_context"
    assert "denied_role_rule" in skipped["preconditions"]
    feedback = build_feedback(result)
    assert feedback[0]["status"] == "blocked" and feedback[0]["next_action"] == "bind_declared_test_resource"


def test_bfla_different_roles_and_owned_object_do_not_invent_function_rule():
    url = "https://own.test/admin/report"
    ids = identities(url)
    ids["admin"]["objects"] = ids["admin"].pop("functions")
    calls = []
    result = execute_web_loop("https://own.test", live=True, crawl=False, identities=ids,
        fuzz=lambda *a, **kw: {"probes": 0, "validator_queue": [{"url": url,
            "vuln_class": "bfla", "authz_candidate": True}]},
        authz_validate=lambda *a: calls.append(a))
    assert calls == [] and not result["validation_queue"]


class Scope:
    def permits_url(self, url):
        return url.startswith("https://own.test/")


def report(row, **kw):
    return {"run_id": "run-1", "validation_candidates": [row], "validation_queue": [row], **kw}


def test_feedback_terminal_states_require_matching_verified_events():
    row = {**probe(), "carrier": "query", "identity": "alice", "resource_owner": "unspecified", "run_id": "run-1",
           "verdict": "CONFIRMED", "validation_id": "val-1", "coverage_recorded": True}
    source = report(row, validations=[row])
    assert build_feedback(source)[0]["status"] == "inconclusive"
    event = {**row, "status": "confirmed"}
    assert build_feedback(source, [event])[0]["status"] == "confirmed"
    for field, value in [("run_id", "run-2"), ("observation_id", 2), ("operation_id", "other"),
                         ("identity", "bob"), ("carrier", "cookie"), ("validation_id", "val-other")]:
        assert build_feedback(source, [{**event, field: value}])[0]["status"] == "inconclusive"
    assert build_feedback(source, [{**event, "status": "inconclusive"}])[0]["status"] == "inconclusive"


def test_feedback_budget_failure_is_not_a_clean_control():
    row = {**probe(), "run_id": "run-1"}
    result = build_feedback(report(row, skipped=[{**row, "reason": "max_validations"}]))
    assert result[0]["status"] == "blocked"
    assert result[0]["next_action"] == "review_budget" and result[0]["automatic_retry"] is False


def test_cached_terminal_feedback_cannot_survive_missing_or_changed_evidence(tmp_path):
    db = str(tmp_path / "feedback.db")
    row = {**probe(), "identity": "alice", "run_id": "run-1", "validation_id": "val-1"}
    event = {**row, "status": "confirmed"}
    plans = persist_feedback(db, "https://own.test", "ctx-1", report(row, validations=[row]), Scope(), [event])
    assert verified_feedback(plans, "https://own.test", "ctx-1", [event])[0]["status"] == "confirmed"
    assert verified_feedback(plans, "https://own.test", "ctx-1", [])[0]["status"] == "inconclusive"
    assert verified_feedback(plans, "https://own.test", "ctx-1", [{**event, "validation_id": "val-other"}])[0]["status"] == "inconclusive"
    stale = persist_feedback(db, "https://own.test", "ctx-1", report(row), Scope())
    assert stale[0]["status"] == "inconclusive" and stale[0]["reason_code"] == "evidence_unavailable"


def test_feedback_dedup_terminal_retention_and_new_observation(tmp_path):
    db = str(tmp_path / "feedback.db")
    row = {**probe(), "identity": "alice", "run_id": "run-1", "validation_id": "val-1"}
    source = report(row, validations=[row])
    event = {**row, "status": "tested_clean"}
    first = persist_feedback(db, "https://own.test", "ctx-1", source, Scope(), [event])
    assert first[0]["status"] == "tested_no_violation"
    persist_feedback(db, "https://own.test", "ctx-1", source, Scope(), [event])
    retained = persist_feedback(db, "https://own.test", "ctx-1", report(row), Scope(), [event])
    assert retained[0]["status"] == "tested_no_violation"
    new = persist_feedback(db, "https://own.test", "ctx-1", report({**row, "observation_id": 2}), Scope())
    assert new[0]["status"] == "ready" and new[0]["fingerprint"] != first[0]["fingerprint"]
    assert len(list_feedback(db, "https://own.test", "ctx-1", "run-1")) == 2
    assert list_feedback(db, "https://own.test", "ctx-other") == []
    assert list_feedback(db, "https://own.test", "ctx-1", "run-other") == []
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM hunter_feedback_queue").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM hunter_feedback_events").fetchone()[0] == 2


def test_feedback_hides_query_and_error_values_and_rejects_other_origin(tmp_path):
    db = str(tmp_path / "feedback.db")
    row = {**probe(), "url": "https://own.test/item?id=synthetic-secret"}
    rows = [row, {**row, "url": "https://other.test/item?id=1"}]
    result = persist_feedback(db, "https://own.test", "ctx-1", report(row,
        validation_queue=rows, skipped=[{**row, "reason": "budget synthetic-secret"}]), Scope())
    assert len(result) == 1 and "synthetic-secret" not in json.dumps(result)
    assert b"synthetic-secret" not in Path(db).read_bytes()


def test_declared_bfla_and_auth_bypass_reach_signed_evidence(tmp_path, monkeypatch):
    import requests
    from policy_engine import PolicyEngine

    scope, policy, home = tmp_path / "scope.json", tmp_path / "policy.json", tmp_path / "home"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://own.test/"}]}))
    policy.write_text("{}")
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
    engine.grant_approval("hunter_run_web_loop", "own.test", ttl_seconds=600, reason="synthetic transport")
    hunter = load_server("hunter")
    urls = {"bfla": "https://own.test/admin/report", "authentication_bypass": "https://own.test/account/statement"}
    ids = identities(urls["bfla"])
    ids["admin"].update(identities(urls["authentication_bypass"], "authentication_bypass")["admin"])
    monkeypatch.setattr(hunter, "_loop_discover", lambda *a, **kw: {"ok": True})
    monkeypatch.setattr(hunter, "_loop_fuzz", lambda *a, **kw: {"probes": 0, "validator_queue": [
        {"url": url, "method": "GET", "vuln_class": kind, "authz_candidate": True}
        for kind, url in urls.items()]})
    calls = []

    def request(method, url, **kwargs):
        assert method == "GET" and url in urls.values()
        credential = (kwargs.get("headers") or {}).get("Cookie")
        response = requests.Response()
        response.url, response.encoding, response._content_consumed = url, "utf-8", True
        response.status_code = 401 if url == urls["bfla"] and not credential else 200
        body = "unauthorized" if response.status_code == 401 else "synthetic-private-marker"
        response._content = json.dumps({"result": body}).encode()
        response.headers["Content-Type"] = "application/json"
        calls.append((url, credential))
        return response

    monkeypatch.setattr(requests, "request", request)
    result = json.loads(hunter.run_web_loop("https://own.test/", live=True, crawl=False,
                                          identities=json.dumps(ids), sleep_s=0, max_validations=2))
    assert {r["vuln_class"] for r in result["confirmed"]} == set(urls)
    events = hunter._verified_coverage_events("https://own.test/")
    assert {r["vuln_class"] for r in events if r["status"] == "confirmed"} == set(urls)
    assert {r["vuln_class"] for r in result["feedback_queue"] if r["status"] == "confirmed"} == set(urls)
    assert result["requests_authorized"] == len(calls) == 5
    assert "synthetic-private-marker" not in json.dumps(result)
    persisted = json.loads(hunter.coverage_report_run("https://own.test/", result["run_id"]))
    assert {r["vuln_class"] for r in persisted["feedback_queue"] if r["status"] == "confirmed"} == set(urls)
    # No surface was imported by this narrow integration test; the run output
    # still carries durable feedback independently of inventory coverage.
    from cco_hunter_core.feedback import feedback_context
    assert list_feedback(hunter.MEM_DB, "https://own.test/", feedback_context(), result["run_id"])


@pytest.mark.parametrize("differential", [False, True])
def test_original_blind_lab_candidate_losses_with_in_memory_http(tmp_path, monkeypatch, differential):
    """Unchanged blind lab application, real routing/validators, zero sockets.

    This is an integration regression, not a full-agent or loopback benchmark.
    The solver receives only base and test identities; truth is read by scoring.
    """
    import requests
    import time
    from urllib.parse import urlsplit, urlunsplit, urlencode
    from policy_engine import PolicyEngine
    from scripts.lab.blind_lab import make_lab
    from cco_surface_core.store import next_work

    base = "http://owned.test/"
    handler, state = make_lab(20261103)
    scope, policy, home = tmp_path / "scope.json", tmp_path / "policy.json", tmp_path / "home"
    scope.write_text(json.dumps({"in_scope": [{"asset": base}], "allow_loopback": False,
                                 "allow_public_labs": False, "allow_osint": False}))
    policy.write_text(json.dumps({"rate_limits": {"default": {"window_seconds": 60, "max_calls": 1000},
                                                  "conservative": {"window_seconds": 60, "max_calls": 1000}},
                                  "blind_discovery": {"synthetic_accounts_only": True,
                                                      "differential_ownership": True}}))
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    monkeypatch.setenv("CCO_STUCK_THRESHOLD", "10000")
    monkeypatch.setenv("CCO_HUNTER_ENABLE_LLM", "0")
    monkeypatch.setattr(time, "sleep", lambda _: None)
    calls = []

    def request(session, method, url, **kwargs):
        assert method.upper() == "GET" and url.startswith(base)
        if kwargs.get("params"):
            url += ("&" if "?" in url else "?") + urlencode(kwargs["params"], doseq=True)
        instance = handler.__new__(handler)
        parsed = urlsplit(url)
        instance.path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        instance.headers = kwargs.get("headers") or {}
        response = requests.Response()
        response.url, response.encoding = url, "utf-8"
        response._content_consumed = True

        def send(code, body, ctype="text/html", extra=None):
            response.status_code = code
            response._content = body.encode() if isinstance(body, str) else body
            response.headers.update({"Content-Type": ctype, **(extra or {})})

        instance._send = send
        instance.do_GET()
        calls.append(url)
        return response

    monkeypatch.setattr(requests.Session, "request", request)
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
    engine.grant_approval("hunter_run_web_loop", "owned.test", ttl_seconds=600, reason="synthetic transport")
    hunter = load_server("hunter")
    ids = {name: {"headers": {"Authorization": "Bearer " + account["token"]}, "role": account["role"],
                  "test_data_only": True} for name, account in state["accounts"].items()}
    result = json.loads(hunter.run_web_loop(base, live=True, crawl=False,
        identities=json.dumps(ids), headers=json.dumps(ids["member-a"]["headers"]),
        blind_discovery=differential, blind_differential=differential, blind_max_requests=40,
        fuzz_limit=12, max_validations=10, sleep_s=0))
    snapshot = next_work(base, limit=10000, untested_only=False, db_path=hunter.MEM_DB)
    inventory = {"run_id": result["run_id"], "source": "isolated_run_surface_snapshot",
                 "complete": snapshot["count"] == snapshot["total_surface"],
                 "records": [{**{k: row[k] for k in ("url", "method", "operation_id", "fingerprint", "sources")},
                              "params": [{"name": p["name"], "in": p["in"]} for p in row["params"]]}
                             for row in snapshot["queue"]]}
    events = hunter._verified_coverage_events(base)
    spec = importlib.util.spec_from_file_location("candidate_feedback_score", ROOT / "scripts/blind-validate.py")
    scorer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scorer)
    score = scorer.evaluate(state["truth"], result, verified_coverage=events, surface_inventory=inventory)
    cases = {case["case"]: case for case in score["cases"]}
    assert cases["sqli-item"]["result"] == "proven"
    assert cases["ssti-hello"]["result"] == "proven"
    # The undeclared system-file canary receives 404 from this fixture.
    # Explicit failed probe statuses are excluded by the sampling contract;
    # telemetry must preserve that loss rather than imply a validation ran.
    assert not cases["traversal-file"]["pipeline"]["candidate_generated"]
    assert cases["traversal-file"]["loss_stage"] == "probe_no_candidate"
    assert not cases["traversal-file"]["validation_ids"]
    file_probes = [row for row in result["fuzz"]["fanout"] if row.get("vuln_class") == "path_traversal"
                   and urlsplit(row.get("url", "")).path == "/file"]
    assert file_probes and all(row["status"] == 404 and row["baseline_eligible"] for row in file_probes)
    assert cases["sqli-item"]["pipeline"]["surface_observed"] is True
    assert cases["bfla-export"]["loss_stage"] == "validation_prerequisite"
    assert cases["authbypass-statement"]["loss_stage"] == "validation_prerequisite"
    assert result["feedback_queue"]
    assert result["requests_authorized"] == len(calls)
    assert all(account["token"] not in json.dumps(result) for account in state["accounts"].values())
    artifact = {"mode": "in_memory_transport_regression", "seed": 20261103,
                "differential": differential, "score": score,
                "requests": len(calls), "feedback_queue": result["feedback_queue"]}
    (tmp_path / "regression.json").write_text(json.dumps(artifact, indent=2))
    state["db"].close()
