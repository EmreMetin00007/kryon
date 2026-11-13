import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name, rel_path):
    path = REPO_ROOT / rel_path
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _engine_with_scope(tmp_path):
    module = _load_module("policy_engine_gate_test", "scripts/policy_engine.py")
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "scope.json").write_text(json.dumps({
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "example.com", "type": "web"}],
    }))
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    return engine


def test_path_close_gate_denies_then_allows(tmp_path):
    engine = _engine_with_scope(tmp_path)
    url = "https://example.com/api/v2/cluster/build-info"

    engine.validate_tool_invocation("kali-tools_curl_request", {"url": url})
    engine.validate_tool_invocation("kali-tools_curl_request", {"url": url})
    denied = engine.check_path_close(url)
    assert denied["allowed"] is False
    assert denied["observed"]["probes"] == 2
    assert denied["missing"]

    engine.validate_tool_invocation("kali-tools_curl_request", {"url": url, "method": "HEAD"})
    engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": url, "user_agent": "Probe/1.0"})
    engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": url, "headers": {"X-Custom": "1"}})
    allowed = engine.check_path_close(url)
    assert allowed["allowed"] is True
    assert allowed["observed"]["probes"] == 5
    assert len(allowed["observed"]["methods"]) >= 2
    assert len(allowed["observed"]["ua_variants"]) >= 2
    assert len(allowed["observed"]["header_variants"]) >= 2


def test_path_close_gate_ignores_blocked_probes(tmp_path):
    engine = _engine_with_scope(tmp_path)
    denied_call = engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://evil.com/secret"})
    assert denied_call["allowed"] is False
    result = engine.check_path_close("https://evil.com/secret")
    assert result["allowed"] is False
    assert result["observed"]["probes"] == 0


def test_path_close_gate_reads_bash_curl_variants(tmp_path):
    engine = _engine_with_scope(tmp_path)
    engine.grant_approval("bash", "example.com", ttl_seconds=600, reason="test")
    url = "https://example.com/api/v2/cluster/build-info"
    engine.validate_tool_invocation("bash", {"command": f"curl -s {url}"})
    engine.validate_tool_invocation(
        "bash", {"command": f"curl -s -A 'Custom/2.0' -H 'X-Probe: 1' {url}"})
    result = engine.check_path_close(url, min_probes=2, min_methods=1, min_ua=2, min_headers=2)
    assert result["allowed"] is True
    assert "ua:custom" in result["observed"]["ua_variants"]
    assert "hdr:x-probe" in result["observed"]["header_variants"]


_TASK_SEQ = {"n": 0}


def _complete_done_task(runtime, campaign_id, worker, result):
    _TASK_SEQ["n"] += 1
    seq = _TASK_SEQ["n"]
    task_id = runtime.enqueue_task(
        campaign_id, "recon", "kali-tools_httpx",
        {"target": f"http://127.0.0.1/probe{seq}"},
    )
    task = runtime.claim_next_task(worker, campaign_id)
    assert task is not None
    assert task["id"] == task_id
    runtime.complete_task(task_id, worker, task["lease_token"], result)
    return task_id


def _runtime_with_scope(tmp_path):
    module = _load_module("campaign_runtime_stall_test", "scripts/campaign_runtime.py")
    runtime = module.CampaignRuntime(str(tmp_path / ".cco"))
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "in_scope": [{"asset": "http://127.0.0.1"}],
        "allow_loopback": True,
    }), encoding="utf-8")
    return runtime, str(scope_file)


def test_stall_detector_enqueues_brainstorm_once(tmp_path):
    runtime, scope_file = _runtime_with_scope(tmp_path)
    campaign_id = runtime.create_campaign("stall-lab", scope_file)

    assert runtime.detect_stall(campaign_id, window=3)["stalled"] is False

    _complete_done_task(runtime, campaign_id, "w", {"no_progress": True})
    _complete_done_task(runtime, campaign_id, "w", {})
    _complete_done_task(runtime, campaign_id, "w", {"no_progress": True})

    stall = runtime.detect_stall(campaign_id, window=3)
    assert stall["stalled"] is True

    first = runtime.maybe_enqueue_brainstorm(campaign_id, window=3)
    assert first["enqueued"] is True
    brainstorms = [t for t in runtime.list_tasks(campaign_id) if t["kind"] == "brainstorm"]
    assert len(brainstorms) == 1
    assert brainstorms[0]["tool_name"] == "reasoning_next_best_action"
    assert "target" in json.loads(brainstorms[0]["args_json"])

    second = runtime.maybe_enqueue_brainstorm(campaign_id, window=3)
    assert second["enqueued"] is False
    assert second["reason"] == "cooldown sürüyor"


def test_stall_detector_progress_breaks_stall_and_quota_caps(tmp_path):
    runtime, scope_file = _runtime_with_scope(tmp_path)
    campaign_id = runtime.create_campaign("stall-lab-2", scope_file)

    _complete_done_task(runtime, campaign_id, "w", {"no_progress": True})
    _complete_done_task(runtime, campaign_id, "w", {})
    _complete_done_task(runtime, campaign_id, "w", {"ports": [80, 443]})
    assert runtime.detect_stall(campaign_id, window=3)["stalled"] is False

    _complete_done_task(runtime, campaign_id, "w", {"no_progress": True})
    _complete_done_task(runtime, campaign_id, "w", {"no_progress": True})
    _complete_done_task(runtime, campaign_id, "w", {})
    assert runtime.detect_stall(campaign_id, window=3)["stalled"] is True

    first = runtime.maybe_enqueue_brainstorm(campaign_id, window=3, cooldown_seconds=0, max_brainstorms=1)
    assert first["enqueued"] is True
    capped = runtime.maybe_enqueue_brainstorm(campaign_id, window=3, cooldown_seconds=0, max_brainstorms=1)
    assert capped["enqueued"] is False
    assert capped["reason"] == "brainstorm kotası doldu"


def test_brainstorm_task_auto_executes(tmp_path):
    import os

    runtime, scope_file = _runtime_with_scope(tmp_path)
    worker_module = _load_module("campaign_worker_brain_test", "scripts/campaign_worker.py")
    campaign_id = runtime.create_campaign("brain-loop", scope_file)

    _complete_done_task(runtime, campaign_id, "w", {"no_progress": True})
    _complete_done_task(runtime, campaign_id, "w", {})
    _complete_done_task(runtime, campaign_id, "w", {"no_progress": True})
    enqueued = runtime.maybe_enqueue_brainstorm(campaign_id, window=3)
    assert enqueued["enqueued"] is True
    assert enqueued["target"].startswith("http://127.0.0.1/probe")

    cco_home = str(tmp_path / ".cco")
    previous_cco_home = os.environ.get("CCO_HOME")

    def _real_executor(task):
        raw = worker_module._invoke_local_mcp_tool(
            task["tool_name"], json.loads(task.get("args_json") or "{}"), cco_home)
        return {"result": json.loads(raw) if isinstance(raw, str) else raw,
                "checkpoint": {"phase": "completed"}}

    try:
        worker = worker_module.CampaignWorker(runtime, "w", executor=_real_executor)
        outcome = worker.run_once(campaign_id)
    finally:
        if previous_cco_home is None:
            os.environ.pop("CCO_HOME", None)
        else:
            os.environ["CCO_HOME"] = previous_cco_home
    assert outcome["status"] == "done", outcome
    assert "next_best_action" in outcome["result"] or "advice" in outcome["result"]

    stall = runtime.detect_stall(campaign_id, window=3)
    assert stall["stalled"] is True
    assert all(tid != outcome["task_id"] for tid in stall["task_ids"])


def test_empty_result_marked_no_progress(tmp_path):
    runtime, scope_file = _runtime_with_scope(tmp_path)
    worker_module = _load_module("campaign_worker_brain_test", "scripts/campaign_worker.py")
    campaign_id = runtime.create_campaign("empty-mark", scope_file)

    assert worker_module.mark_empty_result({}) == {"no_progress": True, "reason": "empty_result"}
    assert worker_module.mark_empty_result({"ports": [80]}) == {"ports": [80]}

    runtime.enqueue_task(campaign_id, "recon", "kali-tools_httpx", {"target": "http://127.0.0.1/empty"})
    worker = worker_module.CampaignWorker(
        runtime, "w", executor=lambda task: {"result": {}, "checkpoint": {}})
    outcome = worker.run_once(campaign_id)
    assert outcome["status"] == "done"
    assert outcome["result"] == {"no_progress": True, "reason": "empty_result"}


def test_goal_lifecycle_and_validation(tmp_path):
    runtime, scope_file = _runtime_with_scope(tmp_path)
    campaign_id = runtime.create_campaign("goal-lab", scope_file)
    assert runtime.get_goal(campaign_id) is None

    goal = runtime.set_goal(campaign_id, {
        "endpoint": "/api/v2/admin/cluster/probe",
        "objective": "trigger probe via SSRF",
        "requires": [
            {"id": "cluster-admin-role", "description": "cluster-admin JWT"},
            {"id": "jwt-secret", "description": "HS256 secret for forgery"},
        ],
    })
    assert goal["status"] == "active"
    assert [r["status"] for r in goal["requires"]] == ["unmet", "unmet"]

    updated = runtime.update_requirement(campaign_id, "jwt-secret", "blocked", "evidence/build-info-403.txt")
    blocked = [r for r in updated["requires"] if r["id"] == "jwt-secret"][0]
    assert blocked["status"] == "blocked"
    assert blocked["evidence"] == "evidence/build-info-403.txt"

    shown = runtime.show_campaign(campaign_id)
    assert json.loads(shown["checkpoint_json"])["goal"]["endpoint"] == "/api/v2/admin/cluster/probe"

    with pytest.raises(ValueError):
        runtime.set_goal(campaign_id, {"objective": "missing endpoint"})
    with pytest.raises(ValueError):
        runtime.update_requirement(campaign_id, "nope", "met")
    with pytest.raises(ValueError):
        runtime.update_requirement(campaign_id, "jwt-secret", "done")
