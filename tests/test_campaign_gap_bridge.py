"""Gap planning to one evidence-backed task, with synthetic traffic only."""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import sys

import pytest

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from campaign_runtime import CampaignRuntime  # noqa: E402
from campaign_worker import CampaignWorker  # noqa: E402
from policy_engine import PolicyEngine, ScopeResolver  # noqa: E402

BASE = "https://owned.test/allowed/"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home = tmp_path / "home"
    scope, policy = tmp_path / "scope.json", tmp_path / "policy.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": BASE}]}))
    policy.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"},
                                  "blind_discovery": {"synthetic_accounts_only": True,
                                                      "owned_objects_private": True}}))
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    monkeypatch.delenv("CCO_SCOPE_REVISION", raising=False)
    monkeypatch.delenv("CCO_POLICY_HASH", raising=False)
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
    engine.grant_approval("hunter_run_web_loop", "owned.test", ttl_seconds=600, reason="synthetic")
    hunter = load_server("hunter")
    runtime = CampaignRuntime(str(home))
    campaign = runtime.create_campaign("synthetic", scope_file=str(scope), budget_requests=24)
    return hunter, runtime, campaign, scope, policy


def plan(hunter, *, param="q", identity="anonymous", **changes):
    from cco_hunter_core.campaign_gaps import versions
    from cco_hunter_core.gap_queue import plan_gaps
    item = {"url": BASE + "search?q=baseline&sort=date", "method": "GET", "location": "query",
            "vuln_class": "sql_injection", "param": param, "identity": identity,
            "resource_owner": "unspecified", "run_id": "source-run", **changes}
    assert hunter._record_coverage_plan(BASE, item)
    gap = {"endpoint": hunter._coverage_url(item["url"]), "vuln_class": item["vuln_class"],
           **{key: hunter._coverage_context(item)[key] for key in
              ("method", "param", "carrier", "identity", "resource_owner", "run_id")}}
    rows, _ = plan_gaps(hunter.MEM_DB, BASE, [gap], ScopeResolver(), versions()[0])
    return item, rows[0]["fingerprint"]


def sessions(hunter, labels=("alice", "bob")):
    from cco_surface_core import session_store
    bindings = {}
    for label in labels:
        session_store.put_session(BASE, label, cookies={"sid": label + "-synthetic-secret"},
                                  headers={"X-Research": "researcher"}, check_url=BASE + "me",
                                  marker=label + "-account")
        session_store.refresh_status(BASE, label, lambda *a, actor=label: (200, actor + "-account"))
        bindings[label] = {"target": BASE, "role": "member", "test_data_only": True,
                           "owned_objects_private": True}
    return json.dumps(bindings)


def schedule(runtime, campaign, **changes):
    return runtime.schedule_coverage_gaps(campaign, BASE, headers='{"X-Research":"researcher"}',
                                          request_cost=4, **changes)


def evidence(hunter, item, verdict="UNCONFIRMED"):
    from cco_validator_core.evidence import validation_context
    validator = load_server("validator")
    with validation_context(hunter._coverage_context(item)):
        return json.loads(validator._result("SQL Injection", item["url"], verdict,
                         "synthetic-differential", {}, "-", guard={"transport_ok": True},
                         request_evidence=[{"role": "baseline", "transport_ok": True,
                                            "status": 200, "method": "GET", "request_url": item["url"]}]))


def test_schedule_is_dimension_specific_and_idempotent(setup):
    hunter, runtime, campaign, *_ = setup
    _, q = plan(hunter)
    _, sort = plan(hunter, param="sort")
    first = schedule(runtime, campaign)
    assert {row["fingerprint"] for row in first["scheduled"]} == {q, sort}
    assert schedule(runtime, campaign)["scheduled"] == []
    tasks = runtime.list_tasks(campaign)
    assert len(tasks) == 2
    assert all(row["max_attempts"] == 3 for row in tasks)
    args = [json.loads(row["args_json"]) for row in tasks]
    assert {arg["gap_ref"] for arg in args} == {q, sort}
    assert all(arg["crawl"] is False and arg["zap"] is False and "?" not in arg["target"] for arg in args)
    assert first["requests_sent"] == 0 and runtime.show_campaign(campaign)["requests_reserved"] == 0


def test_concurrent_schedulers_create_one_task(setup):
    hunter, runtime, campaign, *_ = setup
    plan(hunter)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: schedule(runtime, campaign), range(2)))
    assert sum(len(row["scheduled"]) for row in results) == 1
    assert len(runtime.list_tasks(campaign)) == 1


@pytest.mark.parametrize("deferred_count", [1, 5])
def test_bounded_scheduler_rotates_past_deferred_prefix_after_restart(setup, deferred_count):
    from cco_hunter_core.campaign_gaps import versions
    from cco_hunter_core.gap_queue import plan_gaps
    hunter, runtime, campaign, *_ = setup
    missing = [{"endpoint": BASE + f"unavailable-{n}?q=baseline", "method": "GET",
                "vuln_class": "sql_injection", "param": "q", "identity": "anonymous",
                "resource_owner": "unspecified", "run_id": "source-run"} for n in range(deferred_count)]
    plan_gaps(hunter.MEM_DB, BASE, missing, ScopeResolver(), versions()[0], limit=100)
    _, ready = plan(hunter)
    for _ in range(deferred_count + 1):
        runtime = CampaignRuntime(str(runtime.cco_home))
        result = schedule(runtime, campaign, limit=1, run_id="source-run")
        assert result["requests_sent"] == 0 and len(result["scheduled"]) <= 1
        assert len(result["deferred"]) <= 2
        if result["scheduled"]:
            assert result["scheduled"][0]["fingerprint"] == ready
            break
    else:
        pytest.fail("deferred source prefix starved a ready dimension")
    assert len(runtime.list_tasks(campaign)) == 1
    assert not schedule(runtime, campaign, limit=1, run_id="source-run")["scheduled"]


def test_targeted_worker_uses_vault_only_program_headers_without_persisting_them(setup, monkeypatch):
    hunter, runtime, campaign, *_ = setup
    bindings = sessions(hunter, ("alice",))
    _, fingerprint = plan(hunter, identity="alice")
    scheduled = runtime.schedule_coverage_gaps(campaign, BASE, session_bindings=bindings, request_cost=4)
    assert [row["fingerprint"] for row in scheduled["scheduled"]] == [fingerprint]
    calls = []
    from cco_hunter_core.request_context import current_policy_gate

    def validate(item, headers="", **kwargs):
        wire = json.loads(headers)
        assert wire["X-Research"] == "researcher" and "alice" in wire["Cookie"]
        assert current_policy_gate()("GET", item["url"], wire)[0]
        calls.append(item["url"])
        return evidence(hunter, item)

    def execute(task):
        monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", str(task["reserved_request_cost"]))
        report = json.loads(hunter.run_web_loop(**json.loads(task["args_json"])))
        return {"result": {"mode": "local_mcp", "output": json.dumps(report)},
                "actual_request_cost": report["requests_authorized"]}

    monkeypatch.setattr(hunter, "_loop_validate", validate)
    result = CampaignWorker(runtime, "vault-header-worker", execute).run_once(campaign)
    assert result["status"] == "done" and len(calls) == 1
    task = runtime.list_tasks(campaign)[0]
    assert json.loads(task["args_json"])["headers"] == ""
    assert runtime.show_campaign(campaign)["requests_used"] == len(calls)
    assert b"alice-synthetic-secret" not in runtime.db_path.read_bytes()


def test_anonymous_parameter_task_cannot_borrow_unrelated_vault_headers(setup):
    hunter, runtime, campaign, *_ = setup
    bindings = sessions(hunter, ("alice",))
    plan(hunter)
    result = runtime.schedule_coverage_gaps(campaign, BASE, session_bindings=bindings, request_cost=4)
    assert result["scheduled"] == [] and result["requests_sent"] == 0
    assert runtime.list_tasks(campaign) == []


def test_scheduling_restores_source_plans_with_exact_session_and_observation(setup):
    from cco_hunter_core.campaign_gaps import load_request
    hunter, runtime, campaign, *_ = setup
    bindings = sessions(hunter, ("alice",))
    item = {"url": BASE + "search?q=baseline", "method": "GET", "location": "query",
            "vuln_class": "sql_injection", "param": "q", "identity": "alice",
            "resource_owner": "unspecified", "operation_id": "op-source"}
    assert hunter._record_coverage_plan(BASE, {**item, "run_id": "old-run", "observation_id": 1})
    assert hunter._record_coverage_plan(BASE, {**item, "run_id": "current-run", "observation_id": 2})
    result = schedule(runtime, campaign, session_bindings=bindings, run_id="current-run", limit=1)
    assert len(result["scheduled"]) == 1 and result["requests_sent"] == 0
    packet = load_request(hunter.MEM_DB, runtime.cco_home, BASE, result["scheduled"][0]["fingerprint"])
    assert packet["gap"]["run_id"] == "current-run" and packet["gap"]["observation_id"] == "2"
    assert packet["item"]["identity"] == "alice" and packet["item"]["operation_id"] == "op-source"
    assert json.loads(runtime.list_tasks(campaign)[0]["args_json"])["session_bindings"] == bindings
    assert not schedule(runtime, campaign, session_bindings=bindings, run_id="current-run", limit=1)["scheduled"]


def test_targeted_lifecycle_checks_use_one_rate_slot_and_still_enforce_limits(setup):
    hunter, runtime, campaign, scope, policy_path = setup
    policy = json.loads(policy_path.read_text())
    policy["rate_limits"] = {name: {"window_seconds": 60, "max_calls": 2}
                             for name in ("default", "conservative")}
    policy_path.write_text(json.dumps(policy))
    _, fingerprint = plan(hunter)
    args = {"target": BASE, "live": True, "gap_ref": fingerprint, "crawl": False,
            "headers": '{"X-Research":"researcher"}'}
    full_loop = runtime._validate_task_policy("hunter_run_web_loop", {k: v for k, v in args.items() if k != "gap_ref"},
                                             campaign, 0, str(scope))
    assert full_loop["allowed"] is False and full_loop["reason"] == "blocked_rate_limit"
    assert runtime._validate_task_policy("hunter_run_web_loop", args, campaign, 0, str(scope))["allowed"]
    assert runtime._validate_task_policy("hunter_run_web_loop", args, campaign, 0, str(scope))["allowed"]
    third = runtime._validate_task_policy("hunter_run_web_loop", args, campaign, 0, str(scope))
    assert third["allowed"] is False and third["reason"] == "blocked_rate_limit"


@pytest.mark.parametrize("extra", [
    {"headers": '{"Authorization":"Bearer synthetic-secret"}'},
    {"blind_discovery": True}, {"unexpected": "value"},
])
def test_targeted_lifecycle_checks_reject_invalid_queue_arguments(setup, extra):
    _, runtime, campaign, scope, *_ = setup
    args = {"target": BASE, "live": True, "gap_ref": "a" * 64, "crawl": False, **extra}
    result = runtime._validate_task_policy("hunter_run_web_loop", args, campaign, 0, str(scope))
    assert result == {"allowed": False, "reason": "blocked_invalid_hunter_arguments"}


def test_restoration_requires_the_exact_signed_observation_for_a_saved_request(setup):
    from cco_hunter_core.campaign_gaps import remember_request
    from cco_hunter_core.coverage_store import append_event
    hunter, runtime, campaign, *_ = setup
    item = {"url": BASE + "search?q=baseline", "method": "GET", "location": "query",
            "vuln_class": "sql_injection", "param": "q", "identity": "anonymous",
            "resource_owner": "unspecified", "run_id": "source-run", "observation_id": 1}
    gap = {"endpoint": hunter._coverage_url(item["url"]), "vuln_class": item["vuln_class"],
           **hunter._coverage_context(item)}
    assert remember_request(hunter.MEM_DB, runtime.cco_home, BASE, gap, item)
    event = {"schema": "hunter-coverage-plan/1", "target": hunter._coverage_target(BASE),
             **hunter._coverage_context({**item, "observation_id": 2}),
             "vuln_class": item["vuln_class"], "status": "not_tested"}
    append_event(hunter.MEM_DB, event, hunter._validator_mod.trust)
    result = schedule(runtime, campaign, run_id="source-run")
    assert result["scheduled"] == [] and result["requests_sent"] == 0
    assert runtime.list_tasks(campaign) == []


@pytest.mark.parametrize("artifact_current", [True, False])
def test_restoration_checks_completed_observations_against_current_artifacts(setup, artifact_current):
    hunter, runtime, campaign, *_ = setup
    item = {"url": BASE + "search?q=baseline", "method": "GET", "location": "query",
            "vuln_class": "sql_injection", "param": "q", "identity": "anonymous",
            "resource_owner": "unspecified", "run_id": "source-run"}
    assert hunter._record_coverage_plan(BASE, item)
    result = evidence(hunter, item)
    assert hunter._record_coverage_validation(BASE, item, result)
    if not artifact_current:
        path = Path(result["artifact"]["path"])
        path.write_text(json.dumps({**json.loads(path.read_text()), "tampered": True}))
    scheduled = schedule(runtime, campaign, run_id="source-run")
    assert len(scheduled["scheduled"]) == (0 if artifact_current else 1)
    assert scheduled["requests_sent"] == 0


def test_public_coverage_report_plans_and_schedules_observed_gap(setup):
    hunter, runtime, campaign, *_ = setup
    from cco_surface_core.store import ingest_records
    item, fingerprint = plan(hunter)
    ingest_records([{"url": item["url"], "method": "GET"}], target=BASE, db_path=hunter.MEM_DB)
    report = json.loads(hunter.coverage_report(BASE, enqueue_gaps=True, campaign_id=campaign,
                                              headers='{"X-Research":"researcher"}', request_cost=4))
    assert fingerprint in {row["fingerprint"] for row in report["campaign_tasks"]["scheduled"]}
    assert len(runtime.list_tasks(campaign)) == 1


def test_targeted_worker_runs_one_validator_and_preserves_source_dimensions(setup, monkeypatch):
    hunter, runtime, campaign, *_ = setup
    item, fingerprint = plan(hunter)
    schedule(runtime, campaign)
    seen = []
    from cco_hunter_core.request_context import current_policy_gate
    def validate(candidate, headers="", **kwargs):
        seen.append(candidate)
        assert current_policy_gate()("GET", candidate["url"], json.loads(headers))[0]
        return evidence(hunter, candidate)
    monkeypatch.setattr(hunter, "_loop_validate", validate)
    for name in ("_loop_discover", "_loop_crawl", "_loop_fuzz", "_loop_exploit"):
        monkeypatch.setattr(hunter, name, lambda *a, **kw: pytest.fail("unrelated work must not run"))
    def executor(task):
        monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", str(task["reserved_request_cost"]))
        raw = hunter.run_web_loop(**json.loads(task["args_json"]))
        report = json.loads(raw)
        return {"result": {"mode": "local_mcp", "output": raw},
                "actual_request_cost": report["requests_authorized"]}
    out = CampaignWorker(runtime, "synthetic-worker", executor).run_once(campaign)
    assert out["status"] == "done"
    report = json.loads(out["result"]["output"])
    assert report["steps"] == ["validate_coverage_gap"]
    assert report["coverage_gap"]["status"] == "tested_clean"
    assert report["coverage_gap"]["fingerprint"] == fingerprint
    assert len(seen) == 1 and seen[0]["param"] == item["param"] and seen[0]["run_id"] == "source-run"
    assert runtime.show_campaign(campaign)["requests_used"] == 1
    assert schedule(runtime, campaign)["scheduled"] == []


def test_unsigned_targeted_result_stays_blocked_without_retry(setup, monkeypatch):
    hunter, runtime, campaign, *_ = setup
    _, fingerprint = plan(hunter)
    schedule(runtime, campaign)
    monkeypatch.setattr(hunter, "_loop_validate", lambda *a, **kw: {"verdict": "CONFIRMED"})
    def executor(task):
        raw = hunter.run_web_loop(**json.loads(task["args_json"]))
        return {"result": {"mode": "local_mcp", "output": raw}, "actual_request_cost": 0}
    out = CampaignWorker(runtime, "worker", executor).run_once(campaign)
    assert out["status"] == "blocked"
    assert runtime.claim_next_task("again", campaign) is None
    assert schedule(runtime, campaign)["scheduled"] == []
    assert len(runtime.list_tasks(campaign)) == 1


@pytest.mark.parametrize("file_index", [3, 4])
def test_scope_or_policy_change_rejects_snapshot_before_sending(setup, monkeypatch, file_index):
    hunter, runtime, campaign, *_ = setup
    _, fingerprint = plan(hunter)
    schedule(runtime, campaign)
    setup[file_index].write_text(setup[file_index].read_text() + "\n")
    monkeypatch.setattr(hunter, "_loop_validate", lambda *a, **kw: pytest.fail("must not send"))
    report = json.loads(hunter.run_web_loop(BASE, live=True, gap_ref=fingerprint))
    assert report["ok"] is False and report["requests_authorized"] == 0
    assert report["replan"]["status"] == "blocked"


def test_expired_session_reference_never_queues(setup):
    hunter, runtime, campaign, *_ = setup
    plan(hunter, identity="alice")
    result = schedule(runtime, campaign, session_bindings=json.dumps({
        "alice": {"target": BASE, "test_data_only": True}}))
    assert not result["scheduled"] and "session unavailable" in result["deferred"][0]["reason"]
    assert runtime.list_tasks(campaign) == []


def test_session_rotation_requires_a_new_successful_check(setup, monkeypatch):
    hunter, runtime, campaign, *_ = setup
    from cco_surface_core import session_store
    bindings = sessions(hunter, ("alice",))
    _, fingerprint = plan(hunter, identity="alice")
    assert schedule(runtime, campaign, session_bindings=bindings)["scheduled"]
    session_store.put_session(BASE, "alice", cookies={"sid": "rotated-synthetic-secret"},
                              check_url=BASE + "me", marker="alice-account")
    monkeypatch.setattr(hunter, "_loop_validate", lambda *a, **kw: pytest.fail("must not send"))
    report = json.loads(hunter.run_web_loop(BASE, live=True, gap_ref=fingerprint, session_bindings=bindings))
    assert report["requests_authorized"] == 0 and report["ok"] is False
    assert "synthetic-secret" not in json.dumps(report)


def test_budget_and_missing_grant_are_checked_at_admission(setup):
    hunter, runtime, campaign, *_ = setup
    plan(hunter)
    with runtime._connect() as conn:
        conn.execute("UPDATE campaigns SET budget_requests=3 WHERE id=?", (campaign,))
    result = schedule(runtime, campaign)
    assert result["deferred"][0]["reason"] == "campaign request budget exhausted"
    assert runtime.list_tasks(campaign) == []


def test_plain_plan_with_no_request_context_is_not_executable(setup):
    hunter, runtime, campaign, *_ = setup
    from cco_hunter_core.campaign_gaps import versions
    from cco_hunter_core.gap_queue import plan_gaps
    plan_gaps(hunter.MEM_DB, BASE, [{"endpoint": BASE + "unknown?q=x", "method": "GET",
                                   "vuln_class": "sql_injection", "param": "q"}], ScopeResolver(), versions()[0])
    result = schedule(runtime, campaign)
    assert not result["scheduled"] and result["deferred"]


def test_swapped_encrypted_request_reference_is_rejected(setup):
    hunter, runtime, campaign, *_ = setup
    from cco_hunter_core.campaign_gaps import load_request
    _, q = plan(hunter)
    _, sort = plan(hunter, param="sort")
    with sqlite3.connect(hunter.MEM_DB) as conn:
        ref = conn.execute("SELECT secret_ref FROM hunter_gap_requests WHERE fingerprint=?", (sort,)).fetchone()[0]
        conn.execute("UPDATE hunter_gap_requests SET secret_ref=? WHERE fingerprint=?", (ref, q))
    with pytest.raises(ValueError, match="request context"):
        load_request(hunter.MEM_DB, runtime.cco_home, BASE, q)


def test_queue_rejects_raw_material_and_full_loop_options(setup):
    _, runtime, campaign, *_ = setup
    for extra in ({"cookie": "sid=synthetic-secret"}, {"crawl": True}, {"blind_discovery": True},
                  {"gap_ref": "invalid"}, {"headers": '{"Authorization":"Bearer synthetic-secret"}'}):
        with pytest.raises(ValueError):
            runtime.enqueue_task(campaign, "web", "hunter_run_web_loop", {
                "target": BASE, "live": True, "gap_ref": "a" * 64, "crawl": False, **extra})
    assert runtime.list_tasks(campaign) == []
    assert b"synthetic-secret" not in runtime.db_path.read_bytes()


def test_authz_gap_restores_only_its_owner_and_attacker(setup, monkeypatch):
    import requests
    hunter, runtime, campaign, *_ = setup
    bindings = sessions(hunter)
    item, fingerprint = plan(hunter, identity="bob", url=BASE + "orders/owned-object",
                             param="", vuln_class="bola", authz_candidate=True, owned_object=True,
                             owner_identity="alice", attacker_identity="bob", resource_owner="alice",
                             owner_marker="private-synthetic-owner-marker", owner_role="member", attacker_role="member")
    result = schedule(runtime, campaign, session_bindings=bindings)
    assert len(result["scheduled"]) == 1
    calls = []
    class Response:
        status_code = 200
        text = "private-synthetic-owner-marker"
        content = text.encode()
        headers = {}
    def send(method, url, **kwargs):
        assert method == "GET" and url == item["url"]
        calls.append(kwargs["headers"].get("Cookie", ""))
        return Response()
    monkeypatch.setattr(requests, "request", send)
    monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", "4")
    report = json.loads(hunter.run_web_loop(BASE, live=True, gap_ref=fingerprint,
                                           session_bindings=bindings, headers='{"X-Research":"researcher"}'))
    assert report["coverage_gap"]["status"] == "confirmed"
    assert report["run_id"] == "source-run"
    assert report["requests_authorized"] == len(calls)
    assert set(calls) == {"sid=alice-synthetic-secret", "sid=bob-synthetic-secret", ""}
    for path in (runtime.db_path, Path(hunter.MEM_DB), runtime.cco_home / "credential_vault.db"):
        assert b"private-synthetic-owner-marker" not in path.read_bytes()
    assert "synthetic-secret" not in json.dumps(report)


def test_dropped_grant_never_queues_an_observed_request(setup):
    hunter, runtime, campaign, *_ = setup
    plan(hunter)
    engine = runtime._policy_engine()
    for grant in engine.list_approvals():
        engine.revoke_approval(grant["id"])
    result = schedule(runtime, campaign)
    assert result["scheduled"] == []
    assert "blocked_approval" in result["deferred"][0]["reason"]


def test_coverage_list_shows_blocked_task_without_claiming_completion(setup):
    hunter, runtime, campaign, *_ = setup
    from cco_hunter_core.campaign_gaps import versions
    from cco_hunter_core.gap_queue import list_gaps
    _, ref = plan(hunter)
    schedule(runtime, campaign)
    task = runtime.claim_next_task("worker", campaign)
    runtime.block_task_with_permit(task["execution_permit"], "session unavailable", actual_request_cost=0)
    row = next(row for row in list_gaps(hunter.MEM_DB, BASE, versions()[0]) if row["fingerprint"] == ref)
    assert row["status"] == "scheduled" and row["task_status"] == "blocked"


def test_scheduling_limit_does_not_get_stuck_behind_scheduled_dimensions(setup):
    hunter, runtime, campaign, *_ = setup
    _, first = plan(hunter)
    _, second = plan(hunter, param="sort")
    assert schedule(runtime, campaign, limit=1)["scheduled"][0]["fingerprint"] == first
    assert schedule(runtime, campaign, limit=1)["scheduled"][0]["fingerprint"] == second


def test_cross_campaign_cannot_schedule_the_same_dimension_twice(setup):
    hunter, runtime, campaign, scope, _ = setup
    plan(hunter)
    schedule(runtime, campaign)
    other = runtime.create_campaign("second", scope_file=str(scope), budget_requests=24)
    assert schedule(runtime, other)["scheduled"] == []
    assert runtime.list_tasks(other) == []


def test_direct_enqueue_also_deduplicates_gap_tasks(setup):
    _, runtime, campaign, scope, _ = setup
    args = {"target": BASE, "live": True, "gap_ref": "b" * 64, "crawl": False}
    first = runtime.enqueue_task(campaign, "web", "hunter_run_web_loop", args)
    assert runtime.enqueue_task(campaign, "web", "hunter_run_web_loop", args) == first
    assert runtime.list_tasks(campaign)[0]["max_attempts"] == 3
    other = runtime.create_campaign("other", scope_file=str(scope))
    with pytest.raises(ValueError, match="another campaign"):
        runtime.enqueue_task(other, "web", "hunter_run_web_loop", args)
    with pytest.raises(ValueError, match="canonical"):
        runtime.enqueue_task(campaign, "web", "hunter_run_web_loop", args, idempotency_key="different")


def test_scheduling_selects_only_the_requested_source_run(setup):
    hunter, runtime, campaign, *_ = setup
    plan(hunter, run_id="old-run")
    _, current = plan(hunter, run_id="current-run")
    result = schedule(runtime, campaign, run_id="current-run", limit=1)
    assert [row["fingerprint"] for row in result["scheduled"]] == [current]


def test_current_session_is_guarded_before_every_validator_request(setup, monkeypatch):
    hunter, runtime, campaign, *_ = setup
    from cco_hunter_core.request_context import current_policy_gate
    from cco_surface_core import session_store
    bindings = sessions(hunter, ("alice",))
    _, ref = plan(hunter, identity="alice")
    schedule(runtime, campaign, session_bindings=bindings)
    decisions = []
    def validate(item, headers="", **kwargs):
        gate = current_policy_gate()
        decisions.append(gate("GET", item["url"], json.loads(headers))[0])
        session_store.put_session(BASE, "alice", cookies={"sid": "new-synthetic-secret"})
        decisions.append(gate("GET", item["url"], json.loads(headers))[0])
        return {"verdict": "INCONCLUSIVE"}
    monkeypatch.setattr(hunter, "_loop_validate", validate)
    report = json.loads(hunter.run_web_loop(BASE, live=True, gap_ref=ref, session_bindings=bindings))
    assert decisions == [True, False]
    assert report["requests_authorized"] == 1 and report["ok"] is False
    assert report["replan"]["status"] == "blocked"
