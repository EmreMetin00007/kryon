import concurrent.futures
import importlib.util
import json
import math
import os
import sqlite3
import sys

import pytest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_runtime():
    path = os.path.join(REPO_ROOT, "scripts", "campaign_runtime.py")
    spec = importlib.util.spec_from_file_location("campaign_runtime_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_campaign_lifecycle_and_retry(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "in_scope": [{"asset": "http://127.0.0.1"}],
        "allow_loopback": True,
    }), encoding="utf-8")

    campaign_id = runtime.create_campaign("bb", str(scope_file), 100, 10.0, "notes")
    task_id = runtime.enqueue_task(campaign_id, "score", "kali-tools_cvss_calculate", {}, max_attempts=2)

    task = runtime.claim_next_task("worker-a", campaign_id)
    assert task["id"] == task_id
    runtime.heartbeat_task(task_id, "worker-a", task["lease_token"], {"step": "probe"})
    runtime.fail_task(task_id, "worker-a", task["lease_token"], "temporary", retry_in=0, checkpoint={"step": "retry"})

    tasks = runtime.list_tasks(campaign_id)
    assert tasks[0]["status"] == "pending"
    assert tasks[0]["attempts"] == 1
    assert tasks[0]["checkpoint_json"] == '{"step": "retry"}'

    task = runtime.claim_next_task("worker-b", campaign_id)
    assert task["id"] == task_id
    runtime.fail_task(task_id, "worker-b", task["lease_token"], "permanent", retry_in=0)

    tasks = runtime.list_tasks(campaign_id)
    assert tasks[0]["status"] == "dead_letter"
    summary = runtime.show_campaign(campaign_id)
    assert summary["task_counts"]["dead_letter"] == 1


def test_campaign_complete_and_status(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("engagement")
    task_id = runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"})

    task = runtime.claim_next_task("worker", campaign_id)
    assert task["id"] == task_id
    runtime.complete_task(task_id, "worker", task["lease_token"], {"ports": [80, 443]}, {"done": True})
    runtime.set_campaign_status(campaign_id, "paused")

    summary = runtime.show_campaign(campaign_id)
    assert summary["status"] == "paused"
    assert summary["task_counts"]["done"] == 1


def test_paused_campaign_does_not_dispatch(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("paused")
    runtime.set_campaign_status(campaign_id, "paused")
    runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"})
    assert runtime.claim_next_task("worker", campaign_id) is None


def test_task_state_changes_require_matching_lease(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("lease")
    task_id = runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"})
    task = runtime.claim_next_task("worker-a", campaign_id)
    assert task["id"] == task_id

    import pytest

    with pytest.raises(ValueError, match="lease"):
        runtime.complete_task(task_id, "worker-b", task["lease_token"], {"bad": True})
    with pytest.raises(ValueError, match="lease"):
        runtime.fail_task(task_id, "worker-a", "wrong-token", "oops")

    runtime.complete_task(task_id, "worker-a", task["lease_token"], {"ok": True})
    tasks = runtime.list_tasks(campaign_id)
    assert tasks[0]["status"] == "done"


def test_checkpoint_is_preserved_when_not_overridden(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("checkpoint")
    task_id = runtime.enqueue_task(campaign_id, "validator", "validator_validate_sqli", {"target_url": "http://127.0.0.1/item?id=1"}, max_attempts=2)
    task = runtime.claim_next_task("worker", campaign_id)
    runtime.heartbeat_task(task_id, "worker", task["lease_token"], {"phase": "mid"})
    runtime.fail_task(task_id, "worker", task["lease_token"], "retry", retry_in=0)
    tasks = runtime.list_tasks(campaign_id)
    assert tasks[0]["checkpoint_json"] == '{"phase": "mid"}'


def test_campaign_budget_requests_is_enforced(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("budget", budget_requests=1)
    runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"})
    runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"})
    assert runtime.claim_next_task("worker", campaign_id) is not None
    assert runtime.claim_next_task("worker-2", campaign_id) is None


def test_campaign_claim_uses_scope_file(tmp_path):
    module = _load_runtime()
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "https://allowed.example", "type": "web"}],
    }))
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("scoped", scope_file=str(scope_file))
    task_id = runtime.enqueue_task(
        campaign_id,
        "web",
        "kali-tools_curl_request",
        {"url": "https://denied.example/path"},
    )
    assert runtime.claim_next_task("worker", campaign_id) is None
    task = runtime.list_tasks(campaign_id)[0]
    assert task["id"] == task_id
    assert task["status"] == "blocked"
    assert "policy gate" in task["last_error"]


def test_idempotency_key_and_parent_completion_gate(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("deps")
    parent_id = runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"})
    child_id = runtime.enqueue_task(
        campaign_id,
        "follow-up",
        "kali-tools_nmap_scan",
        {"target": "127.0.0.1"},
        parent_id=parent_id,
        idempotency_key="child-once",
    )
    duplicate_child = runtime.enqueue_task(
        campaign_id,
        "follow-up",
        "kali-tools_nmap_scan",
        {"target": "127.0.0.1"},
        parent_id=parent_id,
        idempotency_key="child-once",
    )

    assert duplicate_child == child_id
    first = runtime.claim_next_task("worker", campaign_id)
    assert first["id"] == parent_id
    assert runtime.claim_next_task("worker-2", campaign_id) is None

    runtime.complete_task_with_permit(first["execution_permit"], {"ok": True})
    second = runtime.claim_next_task("worker-2", campaign_id)
    assert second["id"] == child_id


def test_concurrent_idempotent_enqueue_returns_one_task_and_rejects_mismatch(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign = runtime.create_campaign("idempotency")
    def enqueue(_):
        return runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                                    {"target": "https://owned.test/", "live": True},
                                    request_cost=4, idempotency_key="dimension-1")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(enqueue, range(24)))
    assert len(set(ids)) == 1 and len(runtime.list_tasks(campaign)) == 1
    with pytest.raises(ValueError, match="different task"):
        runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                             {"target": "https://owned.test/other", "live": True},
                             request_cost=4, idempotency_key="dimension-1")
    with pytest.raises(ValueError, match="different task"):
        runtime.enqueue_task(campaign, "web", "hunter_run_web_loop",
                             {"target": "https://owned.test/", "live": True},
                             request_cost=5, idempotency_key="dimension-1")
    assert len(runtime.list_tasks(campaign)) == 1


def test_waiting_approval_requeues_after_grant(tmp_path, monkeypatch):
    # Hermetik: aktif operator program-policy (zorunlu header vb.) sizmamali.
    empty_policy = tmp_path / "program-policy.json"
    empty_policy.write_text("{}")
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(empty_policy))
    module = _load_runtime()
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "example.com", "type": "web"}],
    }))
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("approval", scope_file=str(scope_file))
    task_id = runtime.enqueue_task(campaign_id, "web", "kali-tools_curl_request", {"url": "https://example.com"})

    assert runtime.claim_next_task("worker", campaign_id) is None
    assert runtime.list_tasks(campaign_id)[0]["status"] == "waiting_approval"

    runtime._policy_engine(str(scope_file)).grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    task = runtime.claim_next_task("worker", campaign_id)
    assert task["id"] == task_id
    assert task["status"] == "running"


def test_rate_limited_state_is_durable(tmp_path, monkeypatch):
    module = _load_runtime()
    cco_home = tmp_path / ".cco"
    cco_home.mkdir()
    (cco_home / "program_policy.json").write_text(json.dumps({
        "rate_limits": {"default": {"window_seconds": 60, "max_calls": 0}, "overrides": {}},
    }))
    # Repo .codex/program-policy.json onceligi bu dosyayi golgelemesin.
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(cco_home / "program_policy.json"))
    runtime = module.CampaignRuntime(str(cco_home))
    campaign_id = runtime.create_campaign("rate")
    runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"})

    assert runtime.claim_next_task("worker", campaign_id) is None
    task = runtime.list_tasks(campaign_id)[0]
    assert task["status"] == "rate_limited"
    assert "blocked_rate_limit" in task["last_error"]


def test_budget_reservation_settles_actual_telemetry_and_hides_tokens(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("budget", budget_requests=2, budget_usd=1.0)
    task_id = runtime.enqueue_task(
        campaign_id,
        "recon",
        "kali-tools_nmap_scan",
        {"target": "127.0.0.1"},
        request_cost=2,
        usd_cost=0.50,
    )
    task = runtime.claim_next_task("worker", campaign_id)
    assert task["id"] == task_id
    summary = runtime.show_campaign(campaign_id)
    assert summary["requests_reserved"] == 2
    assert summary["requests_used"] == 0

    listed = runtime.list_tasks(campaign_id)[0]
    assert listed["lease_token"] == ""
    assert listed["execution_permit_id"] == ""
    assert listed["worker_fencing_token"] == ""

    runtime.complete_task_with_permit(task["execution_permit"], {"ok": True}, actual_request_cost=1, actual_usd_cost=0.25)
    summary = runtime.show_campaign(campaign_id)
    assert summary["requests_reserved"] == 0
    assert summary["requests_used"] == 1
    assert summary["usd_reserved_micros"] == 0
    assert summary["usd_used_micros"] == 250000


def test_execution_permit_signature_and_heartbeat_fencing(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("permit")
    runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"})
    task = runtime.claim_next_task("worker", campaign_id)
    permit = task["execution_permit"]

    encoded_payload, encoded_signature = permit.split(".", 1)
    signature = runtime._b64decode(encoded_signature)
    # The last base64 character may change only unused padding bits.
    tampered_signature = bytes([signature[0] ^ 1]) + signature[1:]
    tampered = f"{encoded_payload}.{runtime._b64encode(tampered_signature)}"
    with pytest.raises(ValueError, match="permit"):
        runtime.complete_task_with_permit(tampered, {"bad": True})

    refreshed = runtime.heartbeat_task_with_permit(permit, {"phase": "mid"})
    with pytest.raises(ValueError, match="fencing"):
        runtime.complete_task_with_permit(permit, {"stale": True})
    runtime.complete_task_with_permit(refreshed, {"ok": True})
    assert runtime.list_tasks(campaign_id)[0]["status"] == "done"


def test_execution_time_policy_revalidation_blocks_running_task(tmp_path, monkeypatch):
    empty_policy = tmp_path / "program-policy.json"
    empty_policy.write_text("{}")
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(empty_policy))
    module = _load_runtime()
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "https://example.com/app", "type": "web"}],
    }))
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    runtime._policy_engine(str(scope_file)).grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    campaign_id = runtime.create_campaign("revalidate", scope_file=str(scope_file))
    runtime.enqueue_task(campaign_id, "web", "kali-tools_curl_request", {"url": "https://example.com/app"})
    task = runtime.claim_next_task("worker", campaign_id)

    scope_file.write_text(json.dumps({
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "https://other.example/app", "type": "web"}],
    }))
    with pytest.raises(ValueError, match="policy gate"):
        runtime.heartbeat_task_with_permit(task["execution_permit"], {"phase": "before-exec"})
    blocked = runtime.list_tasks(campaign_id)[0]
    assert blocked["status"] == "blocked"
    assert "blocked_scope" in blocked["last_error"]


def test_pause_and_kill_controls_running_workers(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("control")
    runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"})
    task = runtime.claim_next_task("worker", campaign_id)

    runtime.set_campaign_status(campaign_id, "paused")
    with pytest.raises(ValueError, match="paused"):
        runtime.heartbeat_task_with_permit(task["execution_permit"], {"phase": "pause-check"})

    blocked_count = runtime.kill_campaign(campaign_id, "operator kill")
    assert blocked_count == 1
    blocked = runtime.list_tasks(campaign_id)[0]
    assert blocked["status"] == "blocked"
    assert blocked["last_error"] == "operator kill"


def test_negative_or_nan_costs_are_rejected(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))

    with pytest.raises(ValueError, match="budget_requests"):
        runtime.create_campaign("bad", budget_requests=-1)
    with pytest.raises(ValueError, match="budget_usd"):
        runtime.create_campaign("bad", budget_usd=math.nan)

    campaign_id = runtime.create_campaign("costs")
    with pytest.raises(ValueError, match="request_cost"):
        runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"}, request_cost=-1)
    with pytest.raises(ValueError, match="usd_cost"):
        runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"}, usd_cost=math.nan)

    runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"})
    task = runtime.claim_next_task("worker", campaign_id)
    with pytest.raises(ValueError, match="actual_request_cost"):
        runtime.complete_task_with_permit(task["execution_permit"], actual_request_cost=-1)


def test_concurrent_workers_claim_each_task_once_with_wal(tmp_path, monkeypatch):
    module = _load_runtime()
    cco_home = tmp_path / ".cco"
    policy_file = tmp_path / "program-policy.json"
    policy_file.write_text(json.dumps({
        "rate_limits": {
            "default": {"window_seconds": 60, "max_calls": 1000},
            "overrides": {},
        },
    }))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy_file))
    runtime = module.CampaignRuntime(str(cco_home))
    campaign_id = runtime.create_campaign("concurrency")
    for index in range(16):
        runtime.enqueue_task(
            campaign_id,
            "score",
            "kali-tools_cvss_calculate",
            {},
            idempotency_key=f"task-{index}",
        )

    def claim_and_complete(index):
        worker_runtime = module.CampaignRuntime(str(cco_home))
        task = worker_runtime.claim_next_task(f"worker-{index}", campaign_id)
        if not task:
            return None
        worker_runtime.complete_task_with_permit(task["execution_permit"], {"worker": index})
        return task["id"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        first_wave = list(pool.map(claim_and_complete, range(16)))
        second_wave = list(pool.map(claim_and_complete, range(16, 32)))

    claimed = [task_id for task_id in first_wave + second_wave if task_id is not None]
    assert len(claimed) == 16
    assert len(set(claimed)) == 16
    assert runtime.show_campaign(campaign_id)["task_counts"] == {"done": 16}

    conn = sqlite3.connect(runtime.db_path)
    journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()
    assert journal_mode.lower() == "wal"
    audit_conn = sqlite3.connect(cco_home / "audit.db")
    audit_journal_mode = audit_conn.execute("PRAGMA journal_mode").fetchone()[0]
    audit_conn.close()
    assert audit_journal_mode.lower() == "wal"


def test_untested_routes_flags_inventory_gaps(tmp_path):
    module = _load_runtime()
    cco = tmp_path / ".cco"
    runtime = module.CampaignRuntime(str(cco))
    campaign_id = runtime.create_campaign("coverage", "", 100, 0.0, "")

    mem = sqlite3.connect(cco / "agent_memory.db")
    mem.execute("CREATE TABLE endpoints (id INTEGER PRIMARY KEY, target TEXT, url_or_port TEXT)")
    mem.executemany(
        "INSERT INTO endpoints (target, url_or_port) VALUES (?, ?)",
        [("lab.test", "http://lab.test/a"), ("lab.test", "http://lab.test/b"),
         ("lab.test", "http://lab.test/c")],
    )
    mem.commit()
    mem.close()

    runtime.enqueue_task(campaign_id, "probe", "chain_runner_http_get",
                         {"url": "http://lab.test/a"}, request_cost=1)
    out = runtime.untested_routes(campaign_id, target_like="lab.test")
    assert out["total"] == 3
    assert out["tested"] == ["http://lab.test/a"]
    assert out["untested"] == ["http://lab.test/b", "http://lab.test/c"]

    out = runtime.untested_routes(campaign_id)
    assert out["total"] == 3


def test_untested_routes_empty_without_inventory(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("coverage", "", 0, 0.0, "")
    out = runtime.untested_routes(campaign_id)
    assert out == {"untested": [], "tested": [], "total": 0, "note": "envanter yok"}


def test_record_verdict_links_file_and_checkpoint(tmp_path):
    module = _load_runtime()
    cco = tmp_path / ".cco"
    runtime = module.CampaignRuntime(str(cco))
    campaign_id = runtime.create_campaign("verdict", "", 0, 0.0, "")
    note = tmp_path / "storm.md"
    note.write_text("# Hüküm\nBağımsız görüş: devam.")
    out = runtime.record_verdict(campaign_id, "Report Final", str(note), "kapanış onayı")
    assert out["recorded"] is True
    assert out["verdict_count"] == 1
    import os as _os
    assert _os.path.exists(out["verdict"]["path"])
    assert out["verdict"]["path"].startswith(str(cco))


def test_close_out_enforces_coverage_and_brain_review(tmp_path):
    import sqlite3
    module = _load_runtime()
    cco = tmp_path / ".cco"
    runtime = module.CampaignRuntime(str(cco))
    campaign_id = runtime.create_campaign("closeout", "", 100, 0.0, "")
    mem = sqlite3.connect(cco / "agent_memory.db")
    mem.execute("CREATE TABLE endpoints (id INTEGER PRIMARY KEY, target TEXT, url_or_port TEXT)")
    mem.execute("INSERT INTO endpoints (target, url_or_port) VALUES ('t','http://t/a')")
    mem.commit()
    mem.close()

    blocked = runtime.close_out(campaign_id, require_brain_review=True)
    assert blocked["closed"] is False
    assert blocked["reason"] == "untested-routes"

    waived = runtime.close_out(campaign_id, require_brain_review=True,
                               waive_untested="bütçe bitti, raporda NOT TESTED")
    assert waived["closed"] is False
    assert waived["reason"] == "brain-review-missing"

    note = tmp_path / "storm2.md"
    note.write_text("# Hüküm\nOnay.")
    runtime.record_verdict(campaign_id, "final", str(note))
    done = runtime.close_out(campaign_id, require_brain_review=True,
                             waive_untested="bütçe bitti, raporda NOT TESTED")
    assert done["closed"] is True
    assert done["close_out"]["verdict_count"] == 1
    assert done["close_out"]["untested_at_close"] == ["http://t/a"]


def test_check_stall_all_covers_active_campaigns(tmp_path):
    module = _load_runtime()
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    runtime.create_campaign("a", "", 0, 0.0, "")
    runtime.create_campaign("b", "", 0, 0.0, "")
    out = runtime.check_stall_all(enqueue=False)
    assert len(out["checked"]) == 2
    assert out["enqueued_total"] == 0
