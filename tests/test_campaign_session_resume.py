"""Session-gated continuation preserves one task and its cumulative allowance."""
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from test_campaign_gap_bridge import (  # noqa: F401
    BASE, CampaignRuntime, CampaignWorker, evidence, plan, schedule, sessions, setup,
)


def refresh(labels=("alice",)):
    from cco_surface_core import session_store
    for label in labels:
        assert session_store.refresh_status(BASE, label, lambda *a, actor=label: (200, actor + "-account"))["status"] == "fresh"


def prepare(setup, *, labels=("alice",), max_attempts=3):
    hunter, runtime, campaign, *_ = setup
    bindings = sessions(hunter, labels)
    item, ref = plan(hunter, identity="alice")
    assert schedule(runtime, campaign, session_bindings=bindings, max_attempts=max_attempts)["scheduled"]
    return item, ref


def block(runtime, campaign, ref, *, task=None, count=1, categories=("session", "unavailable")):
    task = task or runtime.claim_next_task("worker", campaign)
    result = {"coverage_gap": {"fingerprint": ref, "status": "inconclusive"}, "replan": {
        "status": "blocked", "automatic_retry": False,
        "actions": [{"category": category} for category in categories]}}
    runtime.block_task_with_permit(task["execution_permit"], "coverage dimension remains untested", result=result,
                                   checkpoint={"phase": "replan_required"}, actual_request_cost=count)
    return task


def test_worker_resumes_after_401_with_new_signed_check_and_completes_same_dimension(setup, monkeypatch):
    hunter, runtime, campaign, *_ = setup
    item, ref = prepare(setup)
    original = runtime.list_tasks(campaign)[0]
    calls, claims = [], []
    from cco_hunter_core.request_context import current_policy_gate

    def validate(candidate, headers="", **kwargs):
        gate = current_policy_gate()
        wire = json.loads(headers)
        assert gate("GET", candidate["url"], wire)[0]
        calls.append(candidate)
        if len(calls) == 1:
            gate.observe(wire, {"ok": True, "status": 401})
            return {"verdict": "INCONCLUSIVE"}
        return evidence(hunter, candidate)

    def executor(task):
        claims.append(task)
        monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", str(task["reserved_request_cost"]))
        raw = hunter.run_web_loop(**json.loads(task["args_json"]))
        return {"result": {"mode": "local_mcp", "output": raw},
                "actual_request_cost": json.loads(raw)["requests_authorized"]}

    monkeypatch.setattr(hunter, "_loop_validate", validate)
    worker = CampaignWorker(runtime, "synthetic-worker", executor)
    first = worker.run_once(campaign)
    assert first["status"] == "blocked"
    assert worker.run_once(campaign) == {"claimed": False}
    refresh()
    second = worker.run_once(campaign)
    assert second["status"] == "done" and second["task_id"] == first["task_id"] == original["id"]
    final = runtime.list_tasks(campaign)[0]
    assert len(runtime.list_tasks(campaign)) == 1
    assert final["attempts"] == 2 and final["max_attempts"] == 3
    assert final["args_json"] == original["args_json"] and final["idempotency_key"] == original["idempotency_key"]
    assert [task["reserved_request_cost"] for task in claims] == [4, 3]
    assert claims[0]["execution_permit"] != claims[1]["execution_permit"]
    assert all(call["run_id"] == "source-run" and call["param"] == item["param"] for call in calls)
    report = json.loads(second["result"]["output"])
    assert report["coverage_gap"]["fingerprint"] == ref and report["coverage_gap"]["status"] == "tested_clean"
    assert runtime.show_campaign(campaign)["requests_used"] == 2
    assert runtime.show_campaign(campaign)["requests_reserved"] == 0
    assert "synthetic-secret" not in json.dumps([first, second, final])
    assert b"synthetic-secret" not in runtime.db_path.read_bytes()


def test_unchanged_check_or_refresh_before_block_does_not_resume(setup):
    _, runtime, campaign, *_ = setup
    _, ref = prepare(setup)
    task = runtime.claim_next_task("worker", campaign)
    refresh()  # A new check that precedes the failure must not authorize continuation.
    block(runtime, campaign, ref, task=task)
    out = runtime.resume_coverage_gaps(campaign, BASE)
    assert not out["resumed"] and "new session verification" in out["deferred"][0]["reason"]
    assert runtime.claim_next_task("again", campaign) is None


def test_replay_of_an_older_valid_attestation_is_not_a_post_block_check(setup):
    from cco_surface_core import session_store
    _, runtime, campaign, *_ = setup
    _, ref = prepare(setup)
    path = session_store.vault_path()
    previous = path.read_text()
    refresh()
    block(runtime, campaign, ref)
    path.write_text(previous)  # Still a valid signed check, with a different nonce.
    out = runtime.resume_coverage_gaps(campaign, BASE)
    assert not out["resumed"] and "new session verification" in out["deferred"][0]["reason"]


def test_every_bound_account_must_refresh_and_reservation_is_remaining_only(setup):
    _, runtime, campaign, *_ = setup
    _, ref = prepare(setup, labels=("alice", "bob"))
    original = block(runtime, campaign, ref)
    refresh(("alice",))
    assert not runtime.resume_coverage_gaps(campaign, BASE)["resumed"]
    refresh(("bob",))
    out = runtime.resume_coverage_gaps(campaign, BASE, run_id="source-run")
    assert out["resumed"] == [{"task_id": original["id"], "gap_ref": ref, "remaining_request_cost": 3}]
    assert out["requests_sent"] == 0 and runtime.show_campaign(campaign)["requests_reserved"] == 0
    claimed = runtime.claim_next_task("new-worker", campaign)
    assert claimed["id"] == original["id"] and claimed["reserved_request_cost"] == 3
    assert claimed["attempts"] == 2
    with pytest.raises(ValueError):
        runtime.heartbeat_task_with_permit(original["execution_permit"])
    with pytest.raises(ValueError):
        runtime.complete_task_with_permit(original["execution_permit"], actual_request_cost=0)


@pytest.mark.parametrize("max_attempts", [1, 3])
def test_attempt_limits_survive_fresh_sessions_and_repeated_scheduling(setup, max_attempts):
    _, runtime, campaign, *_ = setup
    _, ref = prepare(setup, max_attempts=max_attempts)
    for attempt in range(1, max_attempts + 1):
        task = block(runtime, campaign, ref)
        assert task["attempts"] == attempt
        refresh()
        out = runtime.resume_coverage_gaps(campaign, BASE)
        assert bool(out["resumed"]) is (attempt < max_attempts)
    assert runtime.claim_next_task("extra", campaign) is None
    assert not schedule(runtime, campaign, max_attempts=3)["scheduled"]
    final = runtime.list_tasks(campaign)[0]
    assert final["status"] == "blocked" and final["attempts"] == final["max_attempts"] == max_attempts
    assert runtime.show_campaign(campaign)["requests_used"] == max_attempts


@pytest.mark.parametrize("count", [None, 4])
def test_unknown_or_exhausted_request_allowance_cannot_resume(setup, count):
    _, runtime, campaign, *_ = setup
    _, ref = prepare(setup)
    block(runtime, campaign, ref, count=count)
    refresh()
    assert not runtime.resume_coverage_gaps(campaign, BASE)["resumed"]
    assert runtime.claim_next_task("again", campaign) is None
    assert runtime.show_campaign(campaign)["requests_used"] == 4


@pytest.mark.parametrize("use_permit", [False, True])
def test_generic_failure_cannot_bypass_session_resume_gate(setup, use_permit):
    _, runtime, campaign, *_ = setup
    prepare(setup)
    task = runtime.claim_next_task("worker", campaign)
    if use_permit:
        runtime.fail_task_with_permit(task["execution_permit"], "session failed", retry_in=0)
    else:
        runtime.fail_task(task["id"], "worker", task["lease_token"], "session failed", retry_in=0)
    refresh()
    assert runtime.claim_next_task("again", campaign) is None
    assert runtime.list_tasks(campaign)[0]["status"] == "blocked"
    assert runtime.show_campaign(campaign)["requests_used"] == 4
    assert runtime.show_campaign(campaign)["requests_reserved"] == 0


@pytest.mark.parametrize("category", ["rate_limit", "policy", "schema", "transport", "budget"])
def test_mixed_failures_never_resume_after_session_refresh(setup, category):
    _, runtime, campaign, *_ = setup
    _, ref = prepare(setup)
    block(runtime, campaign, ref, categories=("session", category))
    refresh()
    assert not runtime.resume_coverage_gaps(campaign, BASE)["resumed"]
    assert runtime.claim_next_task("again", campaign) is None


@pytest.mark.parametrize("change", ["scope", "policy", "grant", "canceled", "budget", "complete", "expired", "parent"])
def test_current_admission_prerequisites_are_rechecked_without_sending(setup, monkeypatch, change):
    hunter, runtime, campaign, scope, policy = setup
    _, ref = prepare(setup)
    task = block(runtime, campaign, ref)
    refresh()
    if change in {"scope", "policy"}:
        path = scope if change == "scope" else policy
        path.write_text(path.read_text() + "\n")
    elif change == "grant":
        engine = runtime._policy_engine()
        for grant in engine.list_approvals():
            engine.revoke_approval(grant["id"])
    elif change == "canceled":
        runtime.set_campaign_status(campaign, "cancelled")
    elif change == "budget":
        with runtime._connect() as conn:
            conn.execute("UPDATE campaigns SET budget_requests=3 WHERE id=?", (campaign,))
    elif change == "complete":
        with sqlite3.connect(hunter.MEM_DB) as conn:
            conn.execute("UPDATE hunter_gap_queue SET status='tested_clean' WHERE fingerprint=?", (ref,))
    elif change == "expired":
        from cco_hunter_core import campaign_gaps
        monkeypatch.setattr(campaign_gaps, "_TTL", -1)
    elif change == "parent":
        parent = runtime.enqueue_task(campaign, "analysis", "reasoning_recall_lessons", {})
        with runtime._connect() as conn:
            conn.execute("UPDATE tasks SET parent_id=? WHERE id=?", (parent, task["id"]))
    out = runtime.resume_coverage_gaps(campaign, BASE)
    assert not out["resumed"] and out["deferred"] and out["requests_sent"] == 0
    assert next(row for row in runtime.list_tasks(campaign) if row["id"] == task["id"])["status"] == "blocked"


@pytest.mark.parametrize("field", ["args_json", "result_json", "checkpoint_json", "last_error", "attempts",
                                   "max_attempts", "request_cost", "idempotency_key", "receipt"])
def test_tampered_block_metadata_cannot_authorize_continuation(setup, field):
    _, runtime, campaign, *_ = setup
    _, ref = prepare(setup)
    task = block(runtime, campaign, ref)
    refresh()
    with runtime._connect() as conn:
        if field == "receipt":
            conn.execute("UPDATE task_events SET payload_json=? WHERE task_id=? AND event_type='coverage_session_block'",
                         ('{"receipt":"invalid"}', task["id"]))
        else:
            row = runtime.list_tasks(campaign)[0]
            value = row[field]
            if field.endswith("_json"):
                value = json.loads(value)
                value["max_validations" if field == "args_json" else "changed"] = 1
                value = json.dumps(value)
            else:
                value = value + 1 if isinstance(value, int) else value + "changed"
            conn.execute(f"UPDATE tasks SET {field}=? WHERE id=?", (value, task["id"]))
    assert not runtime.resume_coverage_gaps(campaign, BASE)["resumed"]


def test_concurrent_polls_claim_one_resumed_task_without_resetting_costs(setup):
    _, runtime, campaign, *_ = setup
    _, ref = prepare(setup)
    original = block(runtime, campaign, ref)
    refresh()
    with ThreadPoolExecutor(max_workers=2) as pool:
        claimed = list(pool.map(lambda worker: runtime.claim_next_task(worker, campaign), ("a", "b")))
    tasks = [task for task in claimed if task]
    assert len(tasks) == 1 and tasks[0]["id"] == original["id"]
    assert tasks[0]["attempts"] == 2 and tasks[0]["reserved_request_cost"] == 3
    assert runtime.show_campaign(campaign)["requests_used"] == 1
    assert runtime.show_campaign(campaign)["requests_reserved"] == 3


def test_rotation_during_resume_admission_stays_blocked(setup, monkeypatch):
    from cco_hunter_core import campaign_gaps
    from cco_surface_core import session_store
    _, runtime, campaign, *_ = setup
    _, ref = prepare(setup)
    block(runtime, campaign, ref)
    refresh()
    original = campaign_gaps.admit_request
    def rotate(*args):
        result = original(*args)
        session_store.put_session(BASE, "alice", cookies={"sid": "rotated-synthetic-secret"})
        return result
    monkeypatch.setattr(campaign_gaps, "admit_request", rotate)
    out = runtime.resume_coverage_gaps(campaign, BASE)
    assert not out["resumed"] and out["deferred"][0]["reason"] == "session changed during admission"


def test_unreadable_session_index_allows_safe_claim_and_block(setup):
    from cco_surface_core import session_store
    _, runtime, campaign, *_ = setup
    _, ref = prepare(setup)
    session_store.vault_path().write_text("invalid JSON")
    block(runtime, campaign, ref, count=0)
    assert runtime.list_tasks(campaign)[0]["status"] == "blocked"
    assert not runtime.resume_coverage_gaps(campaign, BASE)["resumed"]


def test_bounded_resume_scan_rotates_past_unchanged_earlier_accounts(setup):
    hunter, runtime, campaign, *_ = setup
    bindings = sessions(hunter)
    _, first = plan(hunter, identity="alice")
    schedule(runtime, campaign, session_bindings=json.dumps({"alice": json.loads(bindings)["alice"]}))
    block(runtime, campaign, first)
    _, second = plan(hunter, identity="bob", param="sort")
    schedule(runtime, campaign, session_bindings=json.dumps({"bob": json.loads(bindings)["bob"]}))
    block(runtime, campaign, second)
    refresh(("bob",))
    assert not runtime.resume_coverage_gaps(campaign, BASE, limit=1)["resumed"]
    # The cursor survives runtime recreation and does not keep selecting Alice.
    runtime = CampaignRuntime(str(runtime.cco_home))
    out = runtime.resume_coverage_gaps(campaign, BASE, limit=1)
    assert [row["gap_ref"] for row in out["resumed"]] == [second]


@pytest.mark.parametrize("attempts", [0, 4, True, "3"])
def test_invalid_attempt_limits_are_rejected_before_task_creation(setup, attempts):
    hunter, runtime, campaign, *_ = setup
    plan(hunter)
    with pytest.raises(ValueError, match="one to three"):
        schedule(runtime, campaign, max_attempts=attempts)
    assert runtime.list_tasks(campaign) == []
