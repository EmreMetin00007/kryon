"""Encrypted declarations → observed candidates → bounded campaign continuation.

All transport is synthetic. These are integration contracts, not lab recall.
"""
import copy
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import load_server
from test_campaign_gap_bridge import BASE, CampaignWorker, schedule, sessions, setup  # noqa: F401
from test_campaign_session_resume import refresh

MARKER = "private-synthetic-resource-marker"
URL = BASE + "opaque"


def resources(kind="bfla", *, marker=MARKER, denied_roles=None):
    collection = "functions" if kind == "bfla" else "protected_resources"
    rule = {"denied_roles": denied_roles or ["member"]} if kind == "bfla" else {"authentication_required": True}
    return {"role": "admin", collection: [{"url": URL, "marker": marker, "test_data_only": True, **rule}]}


def declare(hunter, kind="bfla"):
    from cco_surface_core import session_store
    from policy_engine import ScopeResolver
    labels = ("alice", "bob") if kind == "bfla" else ("alice",)
    bindings = json.loads(sessions(hunter, labels))
    session_store.bind_resources(BASE, "alice", resources(kind), permits=ScopeResolver().permits_url)
    bindings["alice"]["role"] = "admin"
    if kind == "bfla":
        session_store.bind_resources(BASE, "bob", {"role": "member"}, permits=ScopeResolver().permits_url)
    refresh(labels)
    return json.dumps(bindings)


def candidate(hunter, kind="bfla", *, observation=1, run="source-run"):
    from cco_hunter_core.loop import execute_web_loop
    from cco_hunter_core.feedback import persist_feedback, feedback_context
    from cco_hunter_core.gap_queue import list_gaps
    from cco_hunter_core.campaign_gaps import versions
    from policy_engine import ScopeResolver
    item = {"url": URL, "method": "GET", "param": "", "location": "query", "vuln_class": kind,
            "authz_candidate": True, "operation_id": "op-source", "observation_id": observation}
    report = execute_web_loop(BASE, live=True, crawl=False, run_id=run, identity="source-actor", identities={},
        fuzz=lambda *a, **kw: {"probes": 1, "validator_queue": [item]},
        on_plan=hunter._record_coverage_plan,
        authz_validate=lambda *a: pytest.fail("missing context must not reach a validator"))
    persist_feedback(hunter.MEM_DB, BASE, feedback_context(), report, ScopeResolver(), normalize=hunter._coverage_url)
    plans = list_gaps(hunter.MEM_DB, BASE, versions()[0], status="needs_scheduling", run_id=run)
    return report, next(p["fingerprint"] for p in plans if str(p.get("observation_id")) == str(observation))


def synthetic_wire(monkeypatch, *, kind="bfla", vulnerable=True, public=False, anonymous_status=403):
    import requests
    calls = []

    def request(method, url, **kwargs):
        assert method == "GET" and url == URL
        headers = kwargs.get("headers") or {}
        calls.append(dict(headers))
        credential = headers.get("Cookie", "")
        owner = "alice" in credential
        allowed = owner or public or (vulnerable and (kind == "authentication_bypass" or bool(credential)))
        if not credential and not allowed and anonymous_status is None:
            raise requests.ConnectionError("synthetic anonymous transport failure")
        response = type("Response", (), {"status_code": 200 if allowed else (403 if credential else anonymous_status),
                          "text": MARKER if allowed else "forbidden", "headers": {}})()
        response.content = response.text.encode()
        return response

    monkeypatch.setattr(requests, "request", request)
    return calls


def worker(hunter, runtime, monkeypatch, reports=None):
    def execute(task):
        monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", str(task["reserved_request_cost"]))
        raw = hunter.run_web_loop(**json.loads(task["args_json"]))
        report = json.loads(raw)
        if reports is not None:
            reports.append(report)
        return {"result": {"mode": "local_mcp", "output": raw},
                "actual_request_cost": report["requests_authorized"]}
    return CampaignWorker(runtime, "synthetic-worker", execute)


@pytest.mark.parametrize("kind", ["bfla", "authentication_bypass"])
def test_declared_access_controls_keep_vault_only_program_headers(setup, monkeypatch, kind):
    hunter, runtime, campaign, *_ = setup
    candidate(hunter, kind)
    bindings = declare(hunter, kind)
    result = runtime.schedule_coverage_gaps(campaign, BASE, session_bindings=bindings, request_cost=4)
    assert len(result["scheduled"]) == 1 and result["requests_sent"] == 0
    calls = synthetic_wire(monkeypatch, kind=kind, vulnerable=False)
    outcome = worker(hunter, runtime, monkeypatch).run_once(campaign)
    assert outcome["status"] == "done" and len(calls) == 2
    assert all(call["X-Research"] == "researcher" for call in calls)
    if kind == "authentication_bypass":
        assert not calls[-1].get("Cookie")
    task = runtime.list_tasks(campaign)[0]
    assert json.loads(task["args_json"])["headers"] == ""
    assert "synthetic-secret" not in task["args_json"]
    assert runtime.show_campaign(campaign)["requests_used"] == len(calls)


def test_resource_bind_is_encrypted_idempotent_and_requires_new_attestation(setup):
    from cco_surface_core import session_store
    hunter, runtime, *_ = setup
    sessions(hunter, ("alice",))
    old = session_store.verified_session(BASE, "alice")
    validator = load_server("validator")
    public = json.loads(validator.session_vault_bind_resources(BASE, "alice", json.dumps(resources())))
    assert public["stored"] and public["has_test_resources"] and public["status"] == "unknown"
    assert session_store.verified_session(BASE, "alice") is None
    assert not session_store.same_verified_session(BASE, "alice", old)
    refresh()
    current = session_store.verified_session(BASE, "alice")
    validator.session_vault_bind_resources(BASE, "alice", json.dumps(resources()))
    assert session_store.same_verified_session(BASE, "alice", current)
    for path in (session_store.vault_path(), runtime.cco_home / "credential_vault.db"):
        assert MARKER.encode() not in path.read_bytes() and b"alice-synthetic-secret" not in path.read_bytes()
    assert MARKER not in json.dumps(public) and URL not in json.dumps(public)


def test_resource_bind_tool_works_in_a_fresh_process_outside_checkout(setup, tmp_path):
    hunter, *_ = setup
    sessions(hunter, ("alice",))
    server = Path(__file__).resolve().parents[1] / "mcp-servers" / "mcp-validator" / "server.py"
    code = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("cold_validator", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result = json.loads(module.session_vault_bind_resources(sys.argv[2], "alice", sys.argv[3]))
assert result["stored"] and result["has_test_resources"] and result["status"] == "unknown"
print("bound")
"""
    result = subprocess.run([sys.executable, "-c", code, str(server), BASE, json.dumps(resources())],
                            cwd=tmp_path, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "bound"


@pytest.mark.parametrize("change", [
    {"url": "https://elsewhere.test/opaque"}, {"url": "http://owned.test/allowed/opaque"},
    {"url": "https://owned.test/outside"}, {"url": URL + "#fragment"},
    {"url": "https://user@owned.test/allowed/opaque"}, {"marker": ""},
    {"test_data_only": False}, {"denied_roles": ["admin"]}, {"method": "POST"},
])
def test_invalid_declarations_leave_the_original_session_unchanged(setup, change):
    from cco_surface_core import session_store
    hunter, *_ = setup
    sessions(hunter, ("alice",))
    before = session_store.verified_session(BASE, "alice")
    declared = resources()
    declared["functions"][0].update(change)
    result = json.loads(load_server("validator").session_vault_bind_resources(BASE, "alice", json.dumps(declared)))
    assert result == {"stored": False, "error": "declared test resource binding unavailable"}
    assert session_store.same_verified_session(BASE, "alice", before)


@pytest.mark.parametrize("kind", ["bfla", "authentication_bypass"])
@pytest.mark.parametrize("vulnerable", [True, False])
def test_repaired_candidate_reaches_real_validator_with_exact_signed_dimensions(setup, monkeypatch, kind, vulnerable):
    from cco_hunter_core.campaign_gaps import load_request
    hunter, runtime, campaign, *_ = setup
    report, source_ref = candidate(hunter, kind)
    assert not report["validations"]
    assert not schedule(runtime, campaign)["scheduled"]
    bindings = declare(hunter, kind)
    scheduled = schedule(runtime, campaign, session_bindings=bindings)
    assert scheduled["requests_sent"] == 0 and len(scheduled["scheduled"]) == 1
    ref = scheduled["scheduled"][0]["fingerprint"]
    assert scheduled["rebound"] == [{"source_ref": source_ref, "bound_refs": [ref]}]
    packet = load_request(hunter.MEM_DB, runtime.cco_home, BASE, ref)
    assert packet["item"]["owner_identity"] == "alice"
    assert packet["item"]["identity"] == ("bob" if kind == "bfla" else "anonymous")
    calls = synthetic_wire(monkeypatch, kind=kind, vulnerable=vulnerable)
    result = worker(hunter, runtime, monkeypatch).run_once(campaign)
    assert result["status"] == "done"
    output = json.loads(result["result"]["output"])
    assert output["coverage_gap"]["status"] == ("confirmed" if vulnerable else "tested_clean")
    event = next(e for e in hunter._verified_coverage_events(BASE) if e["validation_id"] == output["coverage_gap"]["validation_id"])
    assert event["identity"] == packet["item"]["identity"] and event["resource_owner"] == "alice"
    assert event["operation_id"] == "op-source" and event["observation_id"] == "1"
    assert event["access_rule_hash"] == packet["item"]["access_rule_hash"] and event["run_id"] == "source-run"
    assert output["feedback_queue"][0]["status"] == ("confirmed" if vulnerable else "tested_no_violation")
    assert output["requests_authorized"] == len(calls) and 2 <= len(calls) <= 4
    assert all(h.get("X-Research") == "researcher" for h in calls)
    assert any("alice" in h.get("Cookie", "") for h in calls)
    if kind == "bfla":
        assert any("bob" in h.get("Cookie", "") for h in calls)
    if kind == "authentication_bypass" or vulnerable:
        assert any(not h.get("Cookie") for h in calls)
    else:
        assert len(calls) == 2
    assert not schedule(runtime, campaign, session_bindings=bindings)["scheduled"]
    assert len(runtime.list_tasks(campaign)) == 1 and runtime.show_campaign(campaign)["requests_used"] == len(calls)
    for path in (runtime.db_path, Path(hunter.MEM_DB), runtime.cco_home / "credential_vault.db"):
        assert MARKER.encode() not in path.read_bytes() and b"alice-synthetic-secret" not in path.read_bytes()
    assert MARKER not in json.dumps(output) and "synthetic-secret" not in json.dumps(runtime.list_tasks(campaign))


def test_public_function_remains_inconclusive_after_resource_binding(setup, monkeypatch):
    hunter, runtime, campaign, *_ = setup
    candidate(hunter)
    bindings = declare(hunter)
    schedule(runtime, campaign, session_bindings=bindings)
    calls = synthetic_wire(monkeypatch, public=True)
    reports = []
    executor = worker(hunter, runtime, monkeypatch, reports)
    out = executor.run_once(campaign)
    assert out["status"] == "blocked" and len(calls) == 3
    output = reports[-1]
    assert output["coverage_gap"]["status"] == "inconclusive" and not output["confirmed"]
    assert output["feedback_queue"][0]["status"] == "inconclusive"
    refresh(("alice", "bob"))
    assert executor.run_once(campaign) == {"claimed": False}
    assert runtime.show_campaign(campaign)["requests_used"] == len(calls)


@pytest.mark.parametrize("kind", ["bfla", "authentication_bypass"])
def test_normal_web_loop_restores_declared_resources_without_blind_discovery(setup, monkeypatch, kind):
    hunter, *_ = setup
    bindings = declare(hunter, kind)
    monkeypatch.setattr(hunter, "_loop_discover", lambda *a, **kw: {"ok": True})
    monkeypatch.setattr(hunter, "_loop_fuzz", lambda *a, **kw: {"probes": 0, "validator_queue": [
        {"url": URL, "method": "GET", "vuln_class": kind, "authz_candidate": True,
         "operation_id": "op-source", "observation_id": 1}]})
    monkeypatch.setattr(hunter, "_loop_blind_discover", lambda *a, **kw: pytest.fail("blind discovery must not run"))
    calls = synthetic_wire(monkeypatch, kind=kind)
    report = json.loads(hunter.run_web_loop(BASE, live=True, crawl=False, blind_discovery=False,
        session_bindings=bindings, headers='{"X-Research":"researcher"}', sleep_s=0, max_validations=1))
    assert [r["vuln_class"] for r in report["confirmed"]] == [kind]
    events = [e for e in hunter._verified_coverage_events(BASE) if e["status"] == "confirmed"]
    assert len(events) == 1 and events[0]["identity"] == ("bob" if kind == "bfla" else "anonymous")
    assert events[0]["resource_owner"] == "alice" and events[0]["operation_id"] == "op-source"
    assert events[0]["access_rule_hash"]
    bound_feedback = [r for r in report["feedback_queue"] if r.get("access_rule_hash") == events[0]["access_rule_hash"]]
    assert len(bound_feedback) == 1 and bound_feedback[0]["status"] == "confirmed"
    assert report["requests_authorized"] == len(calls) == (3 if kind == "bfla" else 2)
    assert MARKER not in json.dumps(report) and "synthetic-secret" not in json.dumps(report)


@pytest.mark.parametrize("anonymous_status", [None, 429, 503])
@pytest.mark.parametrize("kind", ["bfla", "authentication_bypass"])
def test_failed_anonymous_control_never_completes_or_resumes_after_refresh(setup, monkeypatch, anonymous_status, kind):
    hunter, runtime, campaign, *_ = setup
    candidate(hunter, kind)
    bindings = declare(hunter, kind)
    schedule(runtime, campaign, session_bindings=bindings)
    calls = synthetic_wire(monkeypatch, kind=kind, vulnerable=kind == "bfla",
                           anonymous_status=anonymous_status)
    reports = []
    executor = worker(hunter, runtime, monkeypatch, reports)
    out = executor.run_once(campaign)
    assert out["status"] == "blocked" and len(calls) == (3 if kind == "bfla" else 2)
    output = reports[-1]
    assert output["coverage_gap"]["status"] == "inconclusive" and not output["confirmed"]
    validator = load_server("validator")
    stored = validator.load_validation(output["coverage_gap"]["validation_id"])
    assert stored["verdict"] == "INCONCLUSIVE"
    assert [e["role"] for e in stored["request_evidence"]] == (
        ["owner", "other", "anonymous"] if kind == "bfla" else ["authorized", "anonymous"])
    assert stored["request_evidence"][-1]["status"] == anonymous_status
    assert not any(e["status"] in {"confirmed", "tested_clean"} for e in hunter._verified_coverage_events(BASE))
    refresh(("alice", "bob") if kind == "bfla" else ("alice",))
    assert executor.run_once(campaign) == {"claimed": False}
    assert runtime.show_campaign(campaign)["requests_used"] == len(calls)


@pytest.mark.parametrize("other_status", [429, 503])
def test_failed_other_role_response_does_not_close_bfla_coverage(setup, monkeypatch, other_status):
    import requests

    hunter, runtime, campaign, *_ = setup
    candidate(hunter)
    bindings = declare(hunter)
    schedule(runtime, campaign, session_bindings=bindings)
    calls = synthetic_wire(monkeypatch, vulnerable=False)
    original_send = requests.request

    def failing_other(*args, **kwargs):
        response = original_send(*args, **kwargs)
        if "bob" in kwargs["headers"].get("Cookie", ""):
            response.status_code = other_status
        return response

    monkeypatch.setattr(requests, "request", failing_other)
    reports = []
    executor = worker(hunter, runtime, monkeypatch, reports)
    out = executor.run_once(campaign)
    assert out["status"] == "blocked" and len(calls) == 2
    assert reports[-1]["coverage_gap"]["status"] == "inconclusive"
    assert not any(e["status"] in {"confirmed", "tested_clean"} for e in hunter._verified_coverage_events(BASE))
    refresh(("alice", "bob"))
    assert executor.run_once(campaign) == {"claimed": False}


@pytest.mark.parametrize("kind", ["bfla", "authentication_bypass"])
def test_resource_edit_between_control_requests_stops_the_current_task(setup, monkeypatch, kind):
    from cco_surface_core import session_store
    from policy_engine import ScopeResolver
    import requests

    hunter, runtime, campaign, *_ = setup
    candidate(hunter, kind)
    bindings = declare(hunter, kind)
    schedule(runtime, campaign, session_bindings=bindings)
    calls = synthetic_wire(monkeypatch, kind=kind)
    original_send = requests.request

    def edit_after_owner(*args, **kwargs):
        response = original_send(*args, **kwargs)
        session_store.bind_resources(BASE, "alice", resources(kind, marker="changed-marker"),
                                     permits=ScopeResolver().permits_url)
        return response

    monkeypatch.setattr(requests, "request", edit_after_owner)
    reports = []
    out = worker(hunter, runtime, monkeypatch, reports).run_once(campaign)
    assert out["status"] == "blocked" and len(calls) == 1
    output = reports[-1]
    assert output["coverage_gap"]["status"] == "inconclusive" and not output["confirmed"]
    assert "session" in output["stopped"]
    assert runtime.show_campaign(campaign)["requests_used"] == 1


@pytest.mark.parametrize("kind", ["bfla", "authentication_bypass"])
def test_targeted_task_waits_for_post_block_checks_then_resumes_same_task(setup, monkeypatch, kind):
    from cco_surface_core import session_store
    hunter, runtime, campaign, *_ = setup
    candidate(hunter, kind)
    bindings = declare(hunter, kind)
    runtime.schedule_coverage_gaps(campaign, BASE, session_bindings=bindings, request_cost=4)
    original = runtime.list_tasks(campaign)[0]
    session_store.refresh_status(BASE, "alice", lambda *_: (401, "expired"))
    calls = synthetic_wire(monkeypatch, kind=kind)
    executor = worker(hunter, runtime, monkeypatch)
    blocked = executor.run_once(campaign)
    assert blocked["status"] == "blocked" and not calls
    assert executor.run_once(campaign) == {"claimed": False}
    refresh(("alice", "bob") if kind == "bfla" else ("alice",))
    done = executor.run_once(campaign)
    assert done["status"] == "done" and done["task_id"] == blocked["task_id"] == original["id"]
    task = runtime.list_tasks(campaign)[0]
    assert task["attempts"] == 2 and task["args_json"] == original["args_json"]
    assert json.loads(task["args_json"])["headers"] == ""
    assert runtime.show_campaign(campaign)["requests_used"] == len(calls)


def test_resource_repair_resumes_same_task_but_changed_rule_does_not(setup, monkeypatch):
    from cco_surface_core import session_store
    from policy_engine import ScopeResolver
    hunter, runtime, campaign, *_ = setup
    candidate(hunter)
    bindings = declare(hunter)
    schedule(runtime, campaign, session_bindings=bindings)
    original = runtime.list_tasks(campaign)[0]
    session_store.bind_resources(BASE, "alice", {"role": "admin"}, permits=ScopeResolver().permits_url)
    refresh(("alice", "bob"))
    calls = synthetic_wire(monkeypatch)
    executor = worker(hunter, runtime, monkeypatch)
    blocked = executor.run_once(campaign)
    assert blocked["status"] == "blocked" and not calls
    session_store.bind_resources(BASE, "alice", resources(denied_roles=["member", "auditor"]),
                                 permits=ScopeResolver().permits_url)
    refresh(("alice", "bob"))
    out = runtime.resume_coverage_gaps(campaign, BASE)
    assert not out["resumed"] and out["deferred"][0]["reason"] == "declared test resource unavailable or changed"
    session_store.bind_resources(BASE, "alice", resources(), permits=ScopeResolver().permits_url)
    refresh(("alice", "bob"))
    done = executor.run_once(campaign)
    assert done["status"] == "done" and done["task_id"] == original["id"]
    assert runtime.list_tasks(campaign)[0]["attempts"] == 2


@pytest.mark.parametrize("changed_file", [3, 4])
def test_policy_or_scope_changes_cannot_rebind_old_observation(setup, changed_file):
    hunter, runtime, campaign, *_ = setup
    candidate(hunter)
    bindings = declare(hunter)
    setup[changed_file].write_text(setup[changed_file].read_text() + "\n")
    assert not schedule(runtime, campaign, session_bindings=bindings)["scheduled"]
    assert runtime.list_tasks(campaign) == []


def test_plain_metadata_without_signed_observed_candidate_never_becomes_a_task(setup):
    from cco_hunter_core.campaign_gaps import remember_request, versions
    from cco_hunter_core.gap_queue import plan_gaps
    from policy_engine import ScopeResolver
    hunter, runtime, campaign, *_ = setup
    bindings = declare(hunter)
    item = {"url": URL, "vuln_class": "bfla", "method": "GET", "authz_candidate": True,
            "identity": "anonymous", "resource_owner": "unspecified", "run_id": "unsigned"}
    gap = {"endpoint": URL, **{k: v for k, v in item.items() if k != "url"}}
    assert remember_request(hunter.MEM_DB, runtime.cco_home, BASE, gap, item)
    plan_gaps(hunter.MEM_DB, BASE, [gap], ScopeResolver(), versions()[0])
    result = schedule(runtime, campaign, session_bindings=bindings)
    assert not result["scheduled"] and result["deferred"][0]["reason"] == "observed access candidate unavailable"


def test_binding_does_not_overwrite_a_queued_request_and_observations_remain_distinct(setup):
    hunter, runtime, campaign, *_ = setup
    candidate(hunter, observation=1)
    bindings = declare(hunter)
    assert len(schedule(runtime, campaign, session_bindings=bindings)["scheduled"]) == 1
    candidate(hunter, observation=2)
    assert len(schedule(runtime, campaign, session_bindings=bindings)["scheduled"]) == 1
    assert len(runtime.list_tasks(campaign)) == 2
    assert len({t["idempotency_key"] for t in runtime.list_tasks(campaign)}) == 2


def test_role_relabeling_and_session_rotation_cannot_preserve_old_declarations(setup):
    from cco_surface_core import session_store
    hunter, runtime, campaign, *_ = setup
    candidate(hunter)
    bindings = json.loads(declare(hunter))
    bindings["alice"]["role"] = "member"
    assert not schedule(runtime, campaign, session_bindings=json.dumps(bindings))["scheduled"]
    session_store.put_session(BASE, "alice", cookies={"sid": "rotated"}, check_url=BASE + "me", marker="alice-account")
    refresh(("alice", "bob"))
    bindings["alice"]["role"] = "admin"
    assert not schedule(runtime, campaign, session_bindings=json.dumps(bindings))["scheduled"]
    assert runtime.list_tasks(campaign) == []
