"""WS1 kör lab: seed determinizmi, uygulama davranışı, puanlama."""
import http.client
import importlib.util
import json
import os
import threading

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


blind_lab = _load("blind_lab_t", "scripts/lab/blind_lab.py")
blind_validate = _load("blind_validate_t", "scripts/blind-validate.py")


def _serve(seed):
    srv = blind_lab.serve(seed, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"127.0.0.1:{srv.server_address[1]}"


def _get(host, path, token=""):
    conn = http.client.HTTPConnection(host, timeout=10)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", "replace")
    conn.close()
    return resp.status, body, resp.getheader("Location") or ""


def test_seed_determinism_and_variation():
    _, s1 = blind_lab.make_lab(42)
    _, s2 = blind_lab.make_lab(42)
    _, s3 = blind_lab.make_lab(43)
    ids1 = [c["path"] for c in s1["truth"] if c["class"] == "bola"]
    ids3 = [c["path"] for c in s3["truth"] if c["class"] == "bola"]
    assert ids1 == [c["path"] for c in s2["truth"] if c["class"] == "bola"]
    assert ids1 != ids3
    assert s1["accounts"]["member-a"]["token"] != s3["accounts"]["member-a"]["token"]


def test_app_positive_and_control_behaviour():
    srv, host = _serve(7)
    try:
        st = srv.blind_state
        a = st["accounts"]["member-a"]["token"]
        b = st["accounts"]["member-b"]["token"]
        truth = {c["case"]: c for c in st["truth"]}
        # BOLA olumlu: B, A nesnesini okur; kontrol nesnesi 403
        assert _get(host, truth["bola-order"]["path"], b)[0] == 200
        assert _get(host, truth["ctrl-bola"]["path"], b)[0] == 403
        assert _get(host, truth["bola-order"]["path"], a)[0] == 200
        assert _get(host, truth["bola-order"]["path"])[0] == 401
        # BFLA olumlu/kontrol
        assert _get(host, "/admin/export", a)[0] == 200
        assert _get(host, "/admin/users", a)[0] == 403
        # Kimlik atlama olumlu/kontrol (anon)
        assert _get(host, "/account/statement")[0] == 200
        assert _get(host, "/account/settings")[0] == 401
        # Enjeksiyon olumlu/kontrol ayrımı
        assert "OperationalError" in _get(host, "/item?id=1'")[1]
        assert "OperationalError" not in _get(host, "/safe/item?id=1'")[1]
        status, body, _ = _get(host, "/search?q=<svg/onload=1>")
        assert "<svg/onload=1>" in body
        assert "<svg" not in _get(host, "/safe/search?q=<svg/onload=1>")[1]
        # Yönlendirme
        assert _get(host, "/go?next=https://sentinel.example/x")[2].startswith("https://")
        assert _get(host, "/safe/go?next=https://sentinel.example/x")[0] == 400
        # Kendi listesi yalnız kendi nesneleri
        _, mine, _ = _get(host, "/notes", a)
        my_ids = {o["id"] for o in json.loads(mine)["orders"]}
        assert truth["bola-order"]["path"].split("/orders/")[1] in my_ids
        assert truth["ctrl-bola"]["path"].split("/orders/")[1] in my_ids
    finally:
        srv.shutdown()


def test_evaluate_scoring():
    truth = [
        {"case": "p1", "expected": "positive", "class": "sql_injection",
         "path": "/a", "owner": None, "actor": None},
        {"case": "p2", "expected": "positive", "class": "bola",
         "path": "/b", "owner": "member-a", "actor": "member-b"},
        {"case": "n1", "expected": "negative", "class": "sql_injection",
         "path": "/safe/a", "owner": None, "actor": None},
    ]
    loop = {"ok": True, "target": "http://x", "run_id": "run-test", "confirmed": [
                {"vuln_class": "sql_injection", "url": "http://x/a?id=1"},
                {"vuln_class": "sql_injection", "url": "http://x/safe/a?id=1"}],
            "fuzz": {"likely_hits": [
                {"vuln_class": "bola", "url": "http://x/b"}]}}
    out = blind_validate.evaluate(truth, loop, verified_coverage=[
        _coverage(url="http://x/a?id=1", status="confirmed"),
        _coverage(url="http://x/safe/a?id=1", status="confirmed"),
    ])
    assert (out["proven"], out["candidate_only"], out["missed"]) == (1, 1, 0)
    assert out["false_positives"] == 1 and out["positives"] == 2


def _coverage(**overrides):
    """Evaluator fixture: upstream Hunter verification is tested separately."""
    return {"schema": "hunter-coverage/1", "run_id": "run-test",
            "url": "http://x/safe/a?id=1", "method": "GET",
            "vuln_class": "sql_injection", "status": "tested_clean",
            "validation_id": "validation-test", "identity": "anonymous",
            "resource_owner": "unspecified", "param": "id", "carrier": "query",
            **overrides}


def _negative(**overrides):
    return {"case": "safe", "expected": "negative", "class": "sql_injection",
            "path": "/safe/a", "owner": None, "actor": None, **overrides}


def _loop(**overrides):
    return {"ok": True, "target": "http://x", "run_id": "run-test",
            "confirmed": [], "validations": [], **overrides}


@pytest.mark.parametrize("loop", [
    _loop(requests_authorized=0),
    _loop(ok=False, stopped="request budget exhausted", requests_authorized=0),
    _loop(fuzz={"likely_hits": [{"url": "http://x/safe/a", "vuln_class": "sql_injection"}]}),
    _loop(validations=[{"url": "http://x/safe/a", "vuln_class": "sql_injection",
                        "verdict": "UNCONFIRMED", "coverage_recorded": True}]),
])
def test_unexecuted_or_unverified_negative_never_counts_as_clean(loop):
    out = blind_validate.evaluate([_negative()], loop)
    assert out["cases"][0]["result"] == "not_tested"
    assert out["negatives_evaluated"] == 0
    assert out["negatives_not_tested"] == 1
    assert out["negative_coverage"] == 0
    assert out["fp_rate"] is None


def test_verified_clean_control_counts_once_and_preserves_evidence_reference():
    event = _coverage()
    out = blind_validate.evaluate([_negative()], _loop(), verified_coverage=[event, event])
    assert out["cases"][0]["result"] == "clean"
    assert out["cases"][0]["validation_ids"] == ["validation-test"]
    assert out["negatives_evaluated"] == out["negatives_clean"] == 1
    assert out["negative_coverage"] == 1
    assert out["fp_rate"] == 0


@pytest.mark.parametrize("status, expected", [
    ("inconclusive", "inconclusive"), ("blocked", "blocked"),
])
def test_failed_or_inconclusive_control_is_not_clean(status, expected):
    out = blind_validate.evaluate([_negative()], _loop(),
                                  verified_coverage=[_coverage(status=status)])
    assert out["cases"][0]["result"] == expected
    assert out["negatives_evaluated"] == 0
    assert out["fp_rate"] is None


def test_mixed_unresolved_control_does_not_claim_complete_clean_coverage():
    out = blind_validate.evaluate([_negative()], _loop(), verified_coverage=[
        _coverage(), _coverage(status="inconclusive", validation_id="unresolved")])
    assert out["cases"][0]["result"] == "inconclusive"
    assert out["negatives_evaluated"] == 0


def test_verified_false_positive_is_counted_once_even_with_clean_observation():
    event = _coverage(status="confirmed")
    out = blind_validate.evaluate([_negative()], _loop(),
                                  verified_coverage=[_coverage(), event, event])
    assert out["cases"][0]["result"] == "false_positive"
    assert out["false_positives"] == out["negatives_evaluated"] == 1
    assert out["fp_rate"] == 1


@pytest.mark.parametrize("changes", [
    {"method": "POST"}, {"vuln_class": "ssti"}, {"run_id": "previous-run"},
    {"url": "http://other.test/safe/a?id=1"}, {"url": "http://x:8080/safe/a?id=1"},
    {"validation_id": ""}, {"schema": "hunter-coverage-plan/1"},
])
def test_other_context_or_unexecuted_plan_cannot_close_negative(changes):
    out = blind_validate.evaluate([_negative()], _loop(),
                                  verified_coverage=[_coverage(**changes)])
    assert out["cases"][0]["result"] == "not_tested"
    assert out["negatives_evaluated"] == 0


@pytest.mark.parametrize("changes", [
    {"identity": "admin"}, {"resource_owner": "someone-else"},
])
def test_wrong_authz_actor_or_owner_does_not_match_case(changes):
    case = _negative(**{"class": "bola", "owner": "alice", "actor": "bob"})
    event = _coverage(vuln_class="idor", status="confirmed",
                      identity="bob", resource_owner="alice")
    out = blind_validate.evaluate([case], _loop(), verified_coverage=[{**event, **changes}])
    assert out["false_positives"] == 0
    assert out["unmapped_confirmed"] == 1


def test_parameter_constraint_is_matched_when_truth_declares_it():
    out = blind_validate.evaluate([_negative(param="other")], _loop(),
                                  verified_coverage=[_coverage()])
    assert out["negatives_evaluated"] == 0


def test_generic_access_control_label_does_not_become_auth_bypass():
    case = _negative(**{"class": "authentication_bypass"})
    event = _coverage(vuln_class="broken_access_control", status="confirmed")
    out = blind_validate.evaluate([case], _loop(), verified_coverage=[event])
    assert out["false_positives"] == 0
    assert out["unmapped_confirmed"] == 1


def test_unmapped_confirmations_use_full_case_identity_and_are_deduplicated():
    event = _coverage(vuln_class="ssti", status="confirmed")
    out = blind_validate.evaluate([_negative()], _loop(), verified_coverage=[event, event])
    assert out["unmapped_confirmed"] == 1
    assert out["unmapped_confirmations"][0]["validation_ids"] == [event["validation_id"]]


def test_unmapped_audit_keeps_actor_constraints_and_hides_query_values():
    case = _negative(**{"class": "bola", "owner": "alice", "actor": "bob"})
    event = _coverage(vuln_class="idor", status="confirmed", identity="admin", resource_owner="alice",
                      url="http://x/safe/a?token=must-not-appear", validation_id="first")
    other = {**event, "validation_id": "second", "observation_id": "2"}
    out = blind_validate.evaluate([case], _loop(), verified_coverage=[other, event, event])
    assert out["false_positives"] == 0 and out["unmapped_confirmed"] == 1
    row = out["unmapped_confirmations"][0]
    assert row["validation_ids"] == ["first", "second"]
    assert row["related_cases"][0]["mismatches"] == {"actor": {"expected": "bob", "observed": "admin"}}
    assert "must-not-appear" not in json.dumps(row)


def test_bare_confirmation_cannot_prove_a_positive_case():
    case = _negative(expected="positive")
    out = blind_validate.evaluate([case], _loop(confirmed=[{
        "url": "http://x/safe/a", "vuln_class": "sql_injection", "verdict": "CONFIRMED"}]))
    assert out["proven"] == 0
    assert out["recall"] == 0


def test_verified_positive_is_deduplicated_and_blocked_cases_remain_in_recall():
    case = _negative(expected="positive")
    other = {**case, "case": "other", "path": "/other"}
    event = _coverage(status="confirmed")
    out = blind_validate.evaluate([case, other], _loop(ok=False, stopped="budget"),
                                  verified_coverage=[event, event])
    assert out["proven"] == out["blocked"] == 1
    assert out["positives"] == 2 and out["recall"] == 0.5


def test_empty_truth_has_no_fabricated_rates():
    out = blind_validate.evaluate([], _loop(), verified_coverage=[])
    assert out["fp_rate"] is None
    assert out["negative_coverage"] is None
    assert out["recall"] is None


def _inventory(*records, **overrides):
    return {"run_id": "run-test", "source": "isolated_run_surface_snapshot",
            "complete": True, "records": list(records), **overrides}


@pytest.mark.parametrize("extra, inventory, stage", [
    ({}, _inventory(), "discovery_missing"),
    ({}, _inventory({"url": "http://x/safe/a", "method": "GET"}), "candidate_generation"),
    ({"validation_candidates": [_coverage()]}, None, "validation_selection"),
    ({"validation_candidates": [_coverage()], "skipped": [
        {**_coverage(), "reason": "max_validations"}]}, None, "validation_budget"),
    ({"validation_candidates": [_coverage()], "skipped": [
        {**_coverage(), "reason": "authz requires two test identities"}]}, None, "validation_prerequisite"),
    ({"validations": [{**_coverage(), "verdict": "CONFIRMED"}]}, None, "evidence_missing"),
    ({"fuzz": {"fanout": [{**_coverage(), "live": True, "triage_verdict": "UNLIKELY"}]}},
     None, "probe_no_candidate"),
    ({}, None, "discovery_unknown"),
])
def test_loss_stage_uses_observed_pipeline_records(extra, inventory, stage):
    out = blind_validate.evaluate([_negative(expected="positive")],
                                  _loop(steps=["discover", "fuzz"], **extra),
                                  verified_coverage=[], surface_inventory=inventory)
    assert out["cases"][0]["loss_stage"] == stage
    assert out["positive_loss_stages"] == {stage: 1}
    assert out["proven"] == 0


@pytest.mark.parametrize("status, stage", [
    ("confirmed", None), ("tested_clean", "validation_not_confirmed"),
    ("inconclusive", "validation_inconclusive"), ("blocked", "validation_blocked"),
])
def test_loss_stage_prefers_verified_validation_over_earlier_skips(status, stage):
    out = blind_validate.evaluate([_negative(expected="positive")],
                                  _loop(skipped=[{**_coverage(), "reason": "max_validations"}]),
                                  verified_coverage=[_coverage(status=status)])
    assert out["cases"][0]["loss_stage"] == stage
    assert out["cases"][0]["pipeline"]["validation_verified"] is True


def test_stale_or_incomplete_inventory_cannot_claim_discovery_failure():
    for inventory in (_inventory(run_id="old-run"), _inventory(complete=False)):
        out = blind_validate.evaluate([_negative(expected="positive")],
                                      _loop(steps=["discover"]), surface_inventory=inventory)
        assert out["cases"][0]["loss_stage"] == "discovery_unknown"


def test_wrong_method_inventory_and_wrong_actor_validation_do_not_advance_case():
    case = _negative(expected="positive", actor="bob", owner="alice")
    out = blind_validate.evaluate([case], _loop(steps=["discover"], validations=[
        {**_coverage(identity="admin", resource_owner="alice"), "verdict": "CONFIRMED"}]),
        surface_inventory=_inventory({"url": "http://x/safe/a", "method": "POST"}),
        verified_coverage=[_coverage(status="confirmed", identity="admin", resource_owner="alice")])
    assert out["cases"][0]["loss_stage"] == "validation_context_mismatch"
    assert out["proven"] == 0


def test_global_stop_is_preserved_without_inventing_case_prerequisite():
    out = blind_validate.evaluate([_negative(expected="positive")],
                                  _loop(ok=False, stopped="request budget exhausted"))
    assert out["cases"][0]["loss_stage"] == "run_blocked"
    assert out["cases"][0]["pipeline"]["reasons"] == ["request budget exhausted"]


def test_loop_preserves_post_carrier_and_budget_without_exporting_request_context():
    import sys
    sys.path.insert(0, os.path.join(REPO, "mcp-servers", "mcp-hunter"))
    from cco_hunter_core.loop import execute_web_loop
    item = {"url": "http://x/safe/a", "method": "POST", "vuln_class": "sql_injection",
            "param": "id", "location": "json", "baseline_json": {"token": "private-value"},
            "request_ref": "private-request-reference"}
    loop = execute_web_loop("http://x", live=True, crawl=False, run_id="run-test",
                            fuzz=lambda *a, **kw: {"probes": 1, "validator_queue": [item]},
                            max_validations=0)
    loop["run_id"] = "run-test"
    telemetry = {key: loop[key] for key in ("validation_candidates", "validation_queue", "skipped")}
    assert "private-value" not in json.dumps(telemetry)
    assert "private-request-reference" not in json.dumps(telemetry)
    case = _negative(expected="positive", method="POST", carrier="json", param="id")
    score = blind_validate.evaluate([case], loop, verified_coverage=[])
    assert score["cases"][0]["loss_stage"] == "validation_budget"
    assert score["cases"][0]["pipeline"]["candidate_generated"] is True
