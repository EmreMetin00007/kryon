import importlib.util
import os
import sys


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_runtime():
    path = os.path.join(REPO_ROOT, "scripts", "campaign_runtime.py")
    spec = importlib.util.spec_from_file_location("campaign_runtime_operator_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_operator():
    path = os.path.join(REPO_ROOT, "scripts", "operator_cli.py")
    spec = importlib.util.spec_from_file_location("operator_cli_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_operator_dashboard_summarizes_campaign_and_redacts_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / ".cco"))
    runtime_mod = _load_runtime()
    runtime = runtime_mod.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("operator")
    runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"})
    claimed = runtime.claim_next_task("worker", campaign_id)

    operator = _load_operator()
    dashboard = operator.build_dashboard(campaign_id=campaign_id, audit_limit=1)

    assert dashboard["campaigns"][0]["id"] == campaign_id
    assert dashboard["tasks"][0]["status"] == "running"
    assert dashboard["tasks"][0]["lease_token"] == ""
    assert dashboard["tasks"][0]["execution_permit_id"] == ""
    assert claimed["lease_token"]
