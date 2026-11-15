import concurrent.futures
import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
import time

import pytest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_runtime():
    path = os.path.join(REPO_ROOT, "scripts", "campaign_runtime.py")
    spec = importlib.util.spec_from_file_location("campaign_runtime_worker_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_worker():
    path = os.path.join(REPO_ROOT, "scripts", "campaign_worker.py")
    spec = importlib.util.spec_from_file_location("campaign_worker_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_custom_executor(tmp_path, *, cgroup_mode="best_effort", io_limits=None, module_source=None, pids=16):
    module_path = tmp_path / "custom_fixture.py"
    default_source = (
        "import json\n"
        "import os\n"
        "def execute(task):\n"
        "    return {\n"
        "        'result': {\n"
        "            'task_keys': sorted(task),\n"
        "            'args': json.loads(task.get('args_json') or '{}'),\n"
        "            'allowed_env': os.environ.get('CUSTOM_SAFE'),\n"
        "            'secret_env': os.environ.get('API_TOKEN'),\n"
        "        },\n"
        "        'checkpoint': {'phase': 'fixture_complete'},\n"
        "        'actual_request_cost': 0,\n"
        "    }\n"
    )
    module_path.write_text(module_source or default_source, encoding="utf-8")
    module_path.chmod(0o600)
    contract = {
        "schema": "cco-executor-contract/1",
        "executor": "custom_fixture:execute",
        "code": {
            "path": module_path.name,
            "sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
        },
        "isolation": {
            "backend": "process",
            "network": "inherit",
            "cpu_seconds": 10,
            "cpu_cores": 1.0,
            "memory_mb": 256,
            "pids": pids,
            "cgroup_mode": cgroup_mode,
        },
        "environment": {"allow": ["CUSTOM_SAFE"]},
        "io": io_limits or {"max_input_bytes": 65536, "max_output_bytes": 65536},
    }
    contract_path = tmp_path / "executor-contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    contract_path.chmod(0o600)
    return contract_path, contract


def test_worker_dry_run_redacts_args_and_completes(tmp_path):
    runtime_mod = _load_runtime()
    worker_mod = _load_worker()
    runtime = runtime_mod.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("dry-run", budget_requests=1, budget_usd=1.0)
    runtime.enqueue_task(
        campaign_id,
        "web",
        "kali-tools_curl_request",
        {"url": "http://127.0.0.1/", "headers": "Authorization: Bearer secret-token-12345"},
        request_cost=1,
        usd_cost=0.5,
    )

    result = worker_mod.CampaignWorker(runtime, "worker").run_once(campaign_id)

    assert result["status"] == "done"
    assert "secret-token" not in json.dumps(result)
    task = runtime.list_tasks(campaign_id)[0]
    assert task["status"] == "done"
    stored = json.loads(task["result_json"])
    assert stored["args"]["headers"] == "<redacted>"
    summary = runtime.show_campaign(campaign_id)
    assert summary["requests_used"] == 0
    assert summary["requests_reserved"] == 0


def test_worker_callback_settles_actual_costs(tmp_path):
    runtime_mod = _load_runtime()
    worker_mod = _load_worker()
    runtime = runtime_mod.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("callback", budget_requests=5, budget_usd=1.0)
    runtime.enqueue_task(campaign_id, "recon", "kali-tools_nmap_scan", {"target": "127.0.0.1"}, request_cost=2, usd_cost=0.5)

    def executor(task):
        return {
            "result": {"executed": True, "task_id": task["id"]},
            "actual_request_cost": 1,
            "actual_usd_cost": 0.25,
        }

    result = worker_mod.CampaignWorker(runtime, "worker", executor).run_once(campaign_id)

    assert result["status"] == "done"
    summary = runtime.show_campaign(campaign_id)
    assert summary["requests_used"] == 1
    assert summary["usd_used_micros"] == 250000


def test_worker_local_mcp_executor_runs_safe_tool(tmp_path, monkeypatch):
    runtime_mod = _load_runtime()
    worker_mod = _load_worker()
    monkeypatch.setenv("CCO_WORKER_ALLOWED_TOOLS", "kali-tools_cvss_calculate")
    runtime = runtime_mod.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("local-mcp")
    runtime.enqueue_task(
        campaign_id,
        "score",
        "kali-tools_cvss_calculate",
        {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"},
    )

    executor = worker_mod.LocalMCPExecutor(runtime.cco_home)
    result = worker_mod.CampaignWorker(runtime, "worker", executor).run_once(campaign_id)

    assert result["status"] == "done"
    task = runtime.list_tasks(campaign_id)[0]
    stored = json.loads(task["result_json"])
    assert stored["mode"] == "local_mcp"
    assert stored["tool_name"] == "kali-tools_cvss_calculate"
    assert "CVSS:3.1" in stored["output"]
    assert stored["executor_pid"] != os.getpid()


def test_worker_heartbeats_through_long_execution(tmp_path):
    runtime_mod = _load_runtime()
    worker_mod = _load_worker()
    runtime = runtime_mod.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("long-running")
    runtime.enqueue_task(campaign_id, "score", "kali-tools_cvss_calculate", {})

    def slow_executor(_task):
        time.sleep(0.45)
        return {"result": {"ok": True}}

    worker = worker_mod.CampaignWorker(
        runtime,
        "worker",
        slow_executor,
        claim_timeout_seconds=0.2,
        heartbeat_interval_seconds=0.05,
    )
    result = worker.run_once(campaign_id)

    assert result["status"] == "done"
    conn = sqlite3.connect(runtime.db_path)
    heartbeat_count = conn.execute(
        "SELECT COUNT(*) FROM task_events WHERE event_type='heartbeat'"
    ).fetchone()[0]
    conn.close()
    assert heartbeat_count >= 3


def test_local_mcp_subprocess_timeout_terminates_child(tmp_path, monkeypatch):
    worker_mod = _load_worker()
    executor = worker_mod.LocalMCPExecutor(tmp_path / ".cco", timeout_seconds=0.1)
    monkeypatch.setattr(
        executor,
        "_command",
        lambda: [sys.executable, "-c", "import time; time.sleep(10)"],
    )
    task = {"tool_name": "kali-tools_cvss_calculate", "args_json": "{}"}

    started = time.monotonic()
    with pytest.raises(TimeoutError, match="timed out"):
        executor(task)

    assert time.monotonic() - started < 3
    assert executor._process is None


def test_pause_terminates_running_subprocess(tmp_path, monkeypatch):
    runtime_mod = _load_runtime()
    worker_mod = _load_worker()
    runtime = runtime_mod.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("pause-child")
    runtime.enqueue_task(campaign_id, "score", "kali-tools_cvss_calculate", {})
    executor = worker_mod.LocalMCPExecutor(runtime.cco_home, timeout_seconds=10)
    monkeypatch.setattr(
        executor,
        "_command",
        lambda: [sys.executable, "-c", "import time; time.sleep(10)"],
    )
    worker = worker_mod.CampaignWorker(
        runtime,
        "worker",
        executor,
        claim_timeout_seconds=0.4,
        heartbeat_interval_seconds=0.05,
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(worker.run_once, campaign_id)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if runtime.list_tasks(campaign_id)[0]["status"] == "running":
                break
            time.sleep(0.01)
        runtime.set_campaign_status(campaign_id, "paused")
        result = future.result(timeout=3)

    assert result["status"] == "failed"
    assert runtime.list_tasks(campaign_id)[0]["status"] == "pending"
    assert executor._process is None


def test_worker_failure_requeues_without_leaking_exception_payload(tmp_path):
    runtime_mod = _load_runtime()
    worker_mod = _load_worker()
    runtime = runtime_mod.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("failure")
    runtime.enqueue_task(campaign_id, "score", "kali-tools_cvss_calculate", {}, max_attempts=2)

    def executor(_task):
        raise RuntimeError("boom bearer secret-token-12345")

    result = worker_mod.CampaignWorker(runtime, "worker", executor).run_once(campaign_id)

    assert result["status"] == "failed"
    assert "secret-token" not in json.dumps(result)
    conn = sqlite3.connect(runtime.db_path)
    row = conn.execute("SELECT status, attempts, lease_token FROM tasks WHERE campaign_id=?", (campaign_id,)).fetchone()
    conn.close()
    assert row[0] == "pending"
    assert row[1] == 1
    assert row[2] == ""


def test_custom_executor_is_contract_bound_and_child_only(tmp_path, monkeypatch):
    worker_mod = _load_worker()
    contract_path, _contract = _write_custom_executor(tmp_path)
    monkeypatch.setenv("CCO_ENABLE_CUSTOM_WORKER_EXECUTOR", "1")
    monkeypatch.setenv("CUSTOM_SAFE", "delegated")
    monkeypatch.setenv("API_TOKEN", "must-not-cross-boundary")
    sys.modules.pop("custom_fixture", None)

    executor = worker_mod.CustomSubprocessExecutor(contract_path, timeout_seconds=5)
    output = executor({
        "id": 7,
        "campaign_id": 3,
        "tool_name": "fixture_tool",
        "args_json": '{"value":42}',
        "execution_permit": "must-not-cross-boundary",
        "lease_token": "must-not-cross-boundary",
    })

    result = output["result"]
    assert result["mode"] == "custom_subprocess"
    assert result["executor_pid"] != os.getpid()
    assert result["args"] == {"value": 42}
    assert result["allowed_env"] == "delegated"
    assert result["secret_env"] is None
    assert "execution_permit" not in result["task_keys"]
    assert "lease_token" not in result["task_keys"]
    assert len(result["contract_sha256"]) == 64
    assert "custom_fixture" not in sys.modules


def test_custom_executor_fails_closed_without_enable_flag_or_secure_contract(tmp_path, monkeypatch):
    worker_mod = _load_worker()
    contract_path, contract = _write_custom_executor(tmp_path)
    monkeypatch.delenv("CCO_ENABLE_CUSTOM_WORKER_EXECUTOR", raising=False)

    with pytest.raises(ValueError, match="disabled"):
        worker_mod.CustomSubprocessExecutor(contract_path)

    monkeypatch.setenv("CCO_ENABLE_CUSTOM_WORKER_EXECUTOR", "1")
    contract_path.chmod(0o666)
    with pytest.raises(ValueError, match="group/world writable"):
        worker_mod.CustomSubprocessExecutor(contract_path)

    contract_path.chmod(0o600)
    contract["environment"]["allow"] = ["API_TOKEN"]
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    with pytest.raises(ValueError, match="sensitive environment"):
        worker_mod.CustomSubprocessExecutor(contract_path)


def test_custom_executor_required_cgroup_and_rlimits_are_reported(tmp_path, monkeypatch):
    worker_mod = _load_worker()
    contract_path, _contract = _write_custom_executor(tmp_path, cgroup_mode="required")
    cgroup_root = tmp_path / "cgroup"
    cgroup_root.mkdir()
    (cgroup_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="ascii")
    monkeypatch.setenv("CCO_ENABLE_CUSTOM_WORKER_EXECUTOR", "1")

    executor = worker_mod.CustomSubprocessExecutor(
        contract_path,
        timeout_seconds=5,
        cgroup_root=cgroup_root,
    )
    output = executor({"id": 1, "args_json": "{}"})

    isolation = output["result"]["isolation"]
    assert isolation["cgroup"]["applied"] is True
    assert isolation["cgroup"]["memory_mb"] == 256
    assert isolation["rlimits"]["memory_bytes"] == 256 * 1024 * 1024
    assert isolation["rlimits"]["pids"] == 16


def test_container_contract_requires_digest_and_builds_hardened_command(tmp_path, monkeypatch):
    worker_mod = _load_worker()
    _process_path, contract = _write_custom_executor(tmp_path)
    contract["isolation"].update({
        "backend": "container",
        "cgroup_mode": "container",
        "runtime": "docker",
        "image": "python:3.12-slim@sha256:" + "a" * 64,
    })
    container_path = tmp_path / "container-contract.json"
    container_path.write_text(json.dumps(contract), encoding="utf-8")
    container_path.chmod(0o600)
    isolation_mod = sys.modules[worker_mod.ExecutorContract.__module__]
    monkeypatch.setattr(isolation_mod.shutil, "which", lambda name: f"/usr/bin/{name}")

    loaded = worker_mod.ExecutorContract.load(container_path)
    command, container_name, runtime = loaded.container_command(
        worker_mod.SCRIPT_DIR / "custom_executor_child.py",
        worker_mod.SCRIPT_DIR / "executor_isolation.py",
    )

    assert runtime == "/usr/bin/docker"
    assert container_name.startswith("cco-worker-")
    assert command[command.index("--network") + 1] == "bridge"
    assert "--read-only" in command
    assert ["--cap-drop", "ALL"] == command[command.index("--cap-drop"):command.index("--cap-drop") + 2]
    assert "no-new-privileges" in command
    assert contract["isolation"]["image"] in command
    assert not any(str(worker_mod.REPO_ROOT) + ":/workspace" in item for item in command)
    assert any("custom_executor_child.py:/runner/custom_executor_child.py:ro" in item for item in command)
    assert any("custom_fixture.py:/contract/custom_fixture.py:ro" in item for item in command)

    contract["isolation"]["image"] = "python:3.12-slim"
    container_path.write_text(json.dumps(contract), encoding="utf-8")
    with pytest.raises(ValueError, match="pinned"):
        worker_mod.ExecutorContract.load(container_path)


def test_custom_executor_rejects_source_tampering(tmp_path, monkeypatch):
    worker_mod = _load_worker()
    contract_path, _contract = _write_custom_executor(tmp_path)
    monkeypatch.setenv("CCO_ENABLE_CUSTOM_WORKER_EXECUTOR", "1")
    (tmp_path / "custom_fixture.py").write_text("def execute(task): return {}\n", encoding="utf-8")
    (tmp_path / "custom_fixture.py").chmod(0o600)

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        worker_mod.CustomSubprocessExecutor(contract_path)


def test_local_mcp_resource_limits_and_required_cgroup(tmp_path, monkeypatch):
    worker_mod = _load_worker()
    monkeypatch.setenv("CCO_WORKER_ALLOWED_TOOLS", "kali-tools_cvss_calculate")
    cgroup_root = tmp_path / "cgroup"
    cgroup_root.mkdir()
    (cgroup_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="ascii")
    limits = worker_mod.ResourceLimits(
        cpu_seconds=10,
        cpu_cores=0.5,
        memory_mb=512,
        pids=32,
        network="inherit",
        cgroup_mode="required",
    )
    executor = worker_mod.LocalMCPExecutor(
        tmp_path / ".cco",
        # Soğuk kali-tools içe aktarması bu makinede ~7 sn; bütçe izolasyon
        # iddiası içindir, içe aktarma hızı için değil.
        timeout_seconds=60,
        limits=limits,
        cgroup_root=cgroup_root,
    )

    output = executor({"tool_name": "kali-tools_cvss_calculate", "args_json": "{}"})

    isolation = output["result"]["isolation"]
    assert isolation["cgroup"]["applied"] is True
    assert isolation["cgroup"]["cpu_cores"] == 0.5
    assert isolation["rlimits"]["memory_bytes"] == 512 * 1024 * 1024
    assert isolation["rlimits"]["open_files"] <= 1024


def test_required_cgroup_failure_terminates_child(tmp_path, monkeypatch):
    worker_mod = _load_worker()
    limits = worker_mod.ResourceLimits(
        cpu_seconds=10,
        cpu_cores=1.0,
        memory_mb=256,
        pids=16,
        network="inherit",
        cgroup_mode="required",
    )
    executor = worker_mod.LocalMCPExecutor(
        tmp_path / ".cco",
        timeout_seconds=10,
        limits=limits,
        cgroup_root=tmp_path / "missing-cgroup",
    )
    monkeypatch.setattr(
        executor,
        "_command",
        lambda: [sys.executable, "-c", "import time; time.sleep(10)"],
    )

    started = time.monotonic()
    with pytest.raises(RuntimeError, match="required cgroup"):
        executor({"tool_name": "kali-tools_cvss_calculate", "args_json": "{}"})

    assert time.monotonic() - started < 3
    assert executor._process is None


def test_successful_custom_executor_reaps_spawned_descendants(tmp_path, monkeypatch):
    worker_mod = _load_worker()
    source = (
        "import subprocess\n"
        "import sys\n"
        "def execute(task):\n"
        "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "    return {'result': {'descendant_pid': child.pid}}\n"
    )
    # Non-root Linux runners share RLIMIT_NPROC across the whole UID, so fork headroom must exceed ambient runner processes.
    contract_path, _contract = _write_custom_executor(tmp_path, module_source=source, pids=2048)
    monkeypatch.setenv("CCO_ENABLE_CUSTOM_WORKER_EXECUTOR", "1")
    executor = worker_mod.CustomSubprocessExecutor(contract_path, timeout_seconds=5)

    output = executor({"id": 1, "args_json": "{}"})
    descendant = int(output["result"]["descendant_pid"])
    deadline = time.monotonic() + 3
    while os.path.exists(f"/proc/{descendant}") and time.monotonic() < deadline:
        time.sleep(0.02)

    assert not os.path.exists(f"/proc/{descendant}")


def test_claim_kinds_filter_and_drain_loop(tmp_path):
    runtime_mod = _load_runtime()
    worker_mod = _load_worker()
    runtime = runtime_mod.CampaignRuntime(str(tmp_path / ".cco"))
    campaign_id = runtime.create_campaign("kinds", budget_requests=10, budget_usd=10.0)
    runtime.enqueue_task(campaign_id, "brainstorm", "reasoning_next_best_action",
                         {"target": "t"}, request_cost=0)
    runtime.enqueue_task(campaign_id, "probe", "kali-tools_curl_request",
                         {"url": "http://127.0.0.1/"}, request_cost=1)

    claimed = runtime.claim_next_task("w1", campaign_id=campaign_id, kinds=["brainstorm"])
    assert claimed and claimed["kind"] == "brainstorm"
    runtime.complete_task(claimed["id"], "w1", claimed["lease_token"], result={"ok": True})

    worker = worker_mod.CampaignWorker(runtime, "w1", worker_mod.dry_run_executor)
    out = worker.run_once(campaign_id, kinds=["brainstorm"])
    assert out.get("claimed") is False

    out = worker.run_once(campaign_id, kinds=["probe"])
    assert out.get("claimed") is True
    assert out["status"] == "done"
