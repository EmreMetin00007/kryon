"""Incomplete web loops must remain blocked with conserved budget."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from campaign_runtime import CampaignRuntime  # noqa: E402
from campaign_worker import CampaignWorker, LocalMCPExecutor  # noqa: E402


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    runtime = CampaignRuntime(str(tmp_path / "home"))
    # Synthetic executor and policy: no real network interaction occurs.
    monkeypatch.setattr(runtime, "_validate_task_policy", lambda *a, **kw: {"allowed": True})
    return runtime


def test_incomplete_web_loop_is_blocked_and_settles_budget(runtime):
    campaign = runtime.create_campaign("synthetic", budget_requests=10)
    task_id = runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                                   {"target": "https://owned.test", "live": True}, request_cost=4)
    def executor(task):
        report = {"mode": "LIVE", "ok": False, "run_id": "synthetic-run",
                  "private": "synthetic-session-value", "replan": {
                      "status": "blocked", "automatic_retry": False,
                      "actions": [{"category": "session", "action": "restore_test_session"}]}}
        return {"result": {"mode": "local_mcp", "output": json.dumps(report)},
                "actual_request_cost": 2}
    worker = CampaignWorker(runtime, "worker", executor)
    outcome = worker.run_once(campaign)
    assert outcome["status"] == "blocked" and outcome["task_id"] == task_id
    assert "synthetic-session-value" not in json.dumps(outcome)
    task = runtime.list_tasks(campaign)[0]
    assert task["status"] == "blocked"
    assert json.loads(task["checkpoint_json"])["phase"] == "replan_required"
    assert json.loads(task["result_json"])["replan"]["actions"][0]["category"] == "session"
    assert runtime.claim_next_task("worker-2", campaign) is None
    totals = runtime.show_campaign(campaign)
    assert totals["requests_used"] == 2 and totals["requests_reserved"] == 0


def test_malformed_live_output_is_blocked_and_charged_conservatively(runtime):
    campaign = runtime.create_campaign("synthetic", budget_requests=10)
    runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                         {"target": "https://owned.test", "live": True}, request_cost=3)
    executor = lambda task: {"result": {"mode": "local_mcp", "output": "invalid"}}
    result = CampaignWorker(runtime, "worker", executor).run_once(campaign)
    assert result["status"] == "blocked" and result["result"]["replan"]["status"] == "invalid"
    assert runtime.show_campaign(campaign)["requests_used"] == 3


def test_stale_fencing_token_cannot_block_a_task(runtime):
    campaign = runtime.create_campaign("synthetic")
    runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                         {"target": "https://owned.test", "live": True})
    task = runtime.claim_next_task("worker", campaign_id=campaign)
    first = task["execution_permit"]
    refreshed = runtime.heartbeat_task_with_permit(first, {"phase": "still-running"})
    with pytest.raises(ValueError, match="fencing"):
        runtime.block_task_with_permit(first, "stale")
    assert runtime.list_tasks(campaign)[0]["status"] == "running"
    runtime.block_task_with_permit(refreshed, "replan")
    assert runtime.list_tasks(campaign)[0]["status"] == "blocked"


def test_local_hunter_executor_reports_the_observed_request_budget(monkeypatch, tmp_path):
    executor = LocalMCPExecutor(tmp_path)
    monkeypatch.setattr(executor, "_run_subprocess", lambda *a, **kw: (
        {"ok": True, "output": json.dumps({"requests_authorized": 7})}, {}))
    output = executor({"tool_name": "hunter_run_web_loop", "args_json": "{}"})
    assert output["actual_request_cost"] == 7


def test_local_hunter_child_receives_only_its_reservation(monkeypatch, tmp_path):
    executor = LocalMCPExecutor(tmp_path)
    received = {}
    monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", "999")
    def run(*args, **kwargs):
        received.update(kwargs["env"])
        descriptor = args[1]["wire_budget"]
        return {"ok": True, "output": json.dumps({"requests_authorized": 2}), "wire_usage": {
            "schema": "cco-wire-usage/1", **descriptor, "authorized_requests": 2, "blocked_reason": ""}}, {}
    monkeypatch.setattr(executor, "_run_subprocess", run)
    executor({"tool_name": "hunter_run_web_loop", "args_json": "{}", "request_cost": 5,
              "reserved_request_cost": 3})
    assert received["CCO_CAMPAIGN_WIRE_BUDGET"] == "3"


def test_local_hunter_rejects_count_above_reservation(monkeypatch, tmp_path):
    executor = LocalMCPExecutor(tmp_path)
    def run(*args, **kwargs):
        descriptor = args[1]["wire_budget"]
        return {"ok": True, "output": json.dumps({"requests_authorized": 4}), "wire_usage": {
            "schema": "cco-wire-usage/1", **descriptor, "authorized_requests": 4, "blocked_reason": ""}}, {}
    monkeypatch.setattr(executor, "_run_subprocess", run)
    with pytest.raises(RuntimeError, match="invalid campaign wire usage"):
        executor({"tool_name": "hunter_run_web_loop", "args_json": "{}", "request_cost": 3,
                  "reserved_request_cost": 3})


def test_failed_live_execution_is_blocked_and_reservation_is_charged(runtime):
    campaign = runtime.create_campaign("synthetic", budget_requests=4)
    runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                         {"target": "https://owned.test", "live": True}, request_cost=4)
    def executor(task):
        raise TimeoutError("sensitive test detail")
    result = CampaignWorker(runtime, "worker", executor).run_once(campaign)
    assert result["status"] == "blocked" and "sensitive test detail" not in json.dumps(result)
    totals = runtime.show_campaign(campaign)
    assert totals["requests_used"] == 4 and totals["requests_reserved"] == 0
    assert runtime.claim_next_task("other", campaign) is None


def test_stale_live_lease_is_blocked_and_charged_without_retry(runtime):
    campaign = runtime.create_campaign("synthetic", budget_requests=3)
    runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                         {"target": "https://owned.test", "live": True}, request_cost=3)
    task = runtime.claim_next_task("worker", campaign_id=campaign)
    with runtime._connect() as conn:
        conn.execute("UPDATE tasks SET claim_expires_at='1970-01-01T00:00:00+00:00' WHERE id=?", (task["id"],))
    assert runtime.recover_stale_tasks() == 1
    assert runtime.list_tasks(campaign)[0]["status"] == "blocked"
    totals = runtime.show_campaign(campaign)
    assert totals["requests_used"] == 3 and totals["requests_reserved"] == 0
    assert runtime.claim_next_task("other", campaign) is None


def test_cancelled_live_task_conservatively_consumes_reservation(runtime):
    campaign = runtime.create_campaign("synthetic", budget_requests=3)
    runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                         {"target": "https://owned.test", "live": True}, request_cost=3)
    runtime.claim_next_task("worker", campaign_id=campaign)
    assert runtime.kill_campaign(campaign, "synthetic stop") == 1
    totals = runtime.show_campaign(campaign)
    assert totals["requests_used"] == 3 and totals["requests_reserved"] == 0


def test_changed_policy_blocks_running_live_task_without_retry(runtime, monkeypatch):
    campaign = runtime.create_campaign("synthetic", budget_requests=3)
    runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                         {"target": "https://owned.test", "live": True}, request_cost=3)
    task = runtime.claim_next_task("worker", campaign_id=campaign)
    monkeypatch.setattr(runtime, "_validate_task_policy", lambda *a, **kw: {
        "allowed": False, "reason": "blocked_scope"})
    with pytest.raises(ValueError, match="policy gate"):
        runtime.heartbeat_task_with_permit(task["execution_permit"])
    assert runtime.list_tasks(campaign)[0]["status"] == "blocked"
    totals = runtime.show_campaign(campaign)
    assert totals["requests_used"] == 3 and totals["requests_reserved"] == 0


@pytest.mark.parametrize("actual_request_cost", [None, 0, 2])
def test_policy_block_at_completion_preserves_observed_request_cost(runtime, monkeypatch, actual_request_cost):
    campaign = runtime.create_campaign("synthetic", budget_requests=3)
    runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                         {"target": "https://owned.test", "live": True}, request_cost=3)
    task = runtime.claim_next_task("worker", campaign_id=campaign)
    monkeypatch.setattr(runtime, "_validate_task_policy", lambda *a, **kw: {
        "allowed": False, "reason": "blocked_scope"})
    with pytest.raises(ValueError, match="policy gate"):
        runtime.complete_task_with_permit(task["execution_permit"], actual_request_cost=actual_request_cost)
    assert runtime.list_tasks(campaign)[0]["status"] == "blocked"
    totals = runtime.show_campaign(campaign)
    assert totals["requests_used"] == (3 if actual_request_cost is None else actual_request_cost)
    assert totals["requests_reserved"] == 0


@pytest.mark.parametrize("extra", [
    {"cookie": "session=synthetic-secret"},
    {"identities": '{"alice":{"headers":{"Cookie":"synthetic-secret"}}}'},
    {"headers": '{"Authorization":"Bearer synthetic-secret"}'},
    {"target": "https://owned.test/allowed?token=synthetic-secret"},
    {"session_bindings": '{"alice":{"cookie":"synthetic-secret"}}', "blind_discovery": True},
    {"unexpected": "synthetic-secret"},
])
def test_live_hunter_queue_rejects_credentials_before_persisting(runtime, extra):
    campaign = runtime.create_campaign("synthetic", budget_requests=10)
    with pytest.raises(ValueError):
        runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                             {"target": "https://owned.test/allowed", "live": True, **extra})
    assert runtime.list_tasks(campaign) == []
    assert b"synthetic-secret" not in runtime.db_path.read_bytes()


def test_live_hunter_queue_accepts_only_labelled_session_references(runtime):
    campaign = runtime.create_campaign("synthetic", budget_requests=10)
    bindings = {name: {"target": "https://owned.test/allowed", "role": "member",
                       "test_data_only": True, "owned_objects_private": True}
                for name in ("alice", "bob")}
    args = {"target": "https://owned.test/allowed", "live": True, "blind_discovery": True,
            "headers": '{"X-Research":"researcher"}', "session_bindings": json.dumps(bindings)}
    task = runtime.enqueue_task(campaign, "web", "hunter_run_web_loop", args, request_cost=4)
    stored = next(row for row in runtime.list_tasks(campaign) if row["id"] == task)
    assert json.loads(stored["args_json"]) == args


def test_hunter_plan_task_cannot_persist_identity_material(runtime):
    campaign = runtime.create_campaign("synthetic")
    with pytest.raises(ValueError):
        runtime.enqueue_task(campaign, "web", "hunter_run_web_loop", {
            "target": "https://owned.test/", "live": False,
            "cookie": "session=synthetic-secret"})
    assert runtime.list_tasks(campaign) == []
