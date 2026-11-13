"""Faz 3: campaign worker, chain_runner_execute gorevini ChainExecutor ile kosar."""
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def _load(alias, filename):
    spec = importlib.util.spec_from_file_location(alias, REPO_ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


runtime_mod = _load("campaign_runtime_chain", "campaign_runtime.py")
worker_mod = _load("campaign_worker_chain", "campaign_worker.py")


class _AllowGate:
    def validate_tool_invocation(self, tool_name, args=None, **kwargs):
        return {"allowed": True}


def _sender(method, url, headers, body, timeout):
    routes = {"http://lab.test/order/9": (200, "order of alice@example.com")}
    if url not in routes:
        return {"ok": False, "status": None, "len": 0, "text": "",
                "headers": {}, "location": "", "error": "bilinmeyen rota"}
    status, text = routes[url]
    return {"ok": True, "status": status, "len": len(text), "text": text,
            "headers": {}, "location": "", "error": None}


MANIFEST = {
    "schema_version": "action-manifest/1.0",
    "objective": "bola-chain",
    "target_ref": "scope-asset-1",
    "risk": "active_read_only",
    "budget": {"max_requests": 10, "max_duration_seconds": 30},
    "identity_refs": ["owner"],
    "steps": [
        {"id": "fetch-owner", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "fetch-attacker", "on_failure": "abort"},
        {"id": "fetch-attacker", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "differential_content", "owner_step": "fetch-owner",
                    "attacker_step": "fetch-attacker", "marker": "alice@example.com"},
         "on_success": "succeed", "on_failure": "fail"},
    ],
}


def test_worker_runs_chain_task_end_to_end(tmp_path, monkeypatch):
    empty_policy = tmp_path / "program-policy.json"
    empty_policy.write_text("{}")
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(empty_policy))
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "lab.test", "type": "web"}],
    }))
    runtime = runtime_mod.CampaignRuntime(str(tmp_path / ".cco"))
    runtime._policy_engine(str(scope_file)).grant_approval(
        "chain_runner_*", "lab.test", ttl_seconds=600, reason="test")
    campaign_id = runtime.create_campaign("chain-campaign", scope_file=str(scope_file))
    runtime.enqueue_task(campaign_id, "chain", "chain_runner_execute", {
        "url": "http://lab.test",
        "manifest": MANIFEST,
        "identities": {"owner": {"Cookie": "o=1"}},
        "target_bases": {"scope-asset-1": "http://lab.test"},
    }, request_cost=2)

    chain_exec = worker_mod.ChainTaskExecutor(runtime, sender=_sender, policy_engine=_AllowGate())
    worker = worker_mod.CampaignWorker(runtime, "worker", chain_executor=chain_exec)
    result = worker.run_once(campaign_id)
    assert result["status"] == "done"
    task = runtime.list_tasks(campaign_id)[0]
    assert task["status"] == "done"
    stored = json.loads(task["result_json"])
    assert stored["terminal"] == "succeed"
    assert stored["requests_sent"] == 2


def test_chain_failure_persists_step_evidence(tmp_path, monkeypatch):
    empty_policy = tmp_path / "program-policy.json"
    empty_policy.write_text("{}")
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(empty_policy))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path / "work"))
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "lab.test", "type": "web"}],
    }))
    runtime = runtime_mod.CampaignRuntime(str(tmp_path / ".cco"))
    runtime._policy_engine(str(scope_file)).grant_approval(
        "chain_runner_*", "lab.test", ttl_seconds=600, reason="test")
    bad = dict(MANIFEST)
    bad["steps"] = [
        {"id": "only", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "status_code", "status": 500},
         "on_success": "succeed", "on_failure": "fail"},
    ]
    chain_exec = worker_mod.ChainTaskExecutor(runtime, sender=_sender,
                                              policy_engine=_AllowGate())
    task = {"id": 7, "args_json": json.dumps({"manifest": bad})}
    try:
        chain_exec(task)
    except RuntimeError as exc:
        msg = str(exc)
    else:
        raise AssertionError("başarısız zincir istisna vermedi")
    assert "only:http_get:oracle=False" in msg
    evpath = tmp_path / "work" / "chain-evidence" / "task_7_steps.json"
    assert evpath.is_file()
    steps = json.loads(evpath.read_text(encoding="utf-8"))
    assert steps and steps[0]["id"] == "only"
