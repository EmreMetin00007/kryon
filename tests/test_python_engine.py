"""Python entry point, frozen routing and model-loop regression boundaries."""
import json
from pathlib import Path

import pytest

import agent_cli
import full_agent_launcher as launcher
import full_agent_preflight as preflight
import llm_config
from full_agent_python_broker import SUMMARY_TOOL
from full_agent_python_solver import PythonSolver, WorkflowError
from test_full_agent_python_solver import python_broker, terminal
from test_full_agent_preflight import baseline
from test_full_agent_preflight import mock_provider
from test_http_chromium_acceptance import evidence as acceptance_evidence


@pytest.fixture
def config(tmp_path):
    path = tmp_path / "llm.json"
    path.write_text(json.dumps({"schema": "cco-llm/1", "model": "owned/model", "providers": {
        "owned": {"base_url": "https://provider.invalid/v1", "models": ["model"],
                  "api_key_env": "LOCAL_TEST_KEY"}}}))
    return path


@pytest.mark.parametrize("endpoint", ["http://external.invalid/v1", "https://user:secret@provider.invalid/v1",
                                      "https://provider.invalid/v1?token=secret", "https://provider.invalid:0/v1"])
def test_provider_route_rejects_plaintext_remote_credentials_and_invalid_port(config, endpoint):
    data = json.loads(config.read_text())
    data["providers"]["owned"]["base_url"] = endpoint
    config.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        llm_config.load_config(config)


def test_provider_snapshot_never_resolves_credentials(config, monkeypatch):
    monkeypatch.setenv("LOCAL_TEST_KEY", "private-environment-sentinel")
    models = llm_config.model_selection(config)
    frozen = llm_config.snapshot(config, models)
    assert "private-environment-sentinel" not in json.dumps(frozen)
    assert frozen["providers"]["owned"]["api_key_env"] == "LOCAL_TEST_KEY"
    data = json.loads(config.read_text())
    data["providers"]["owned"]["api_key"] = "plaintext-disallowed"
    config.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="never credentials"):
        llm_config.load_config(config)


def test_entrypoint_exposes_only_python_workflow(monkeypatch):
    calls = []
    monkeypatch.setattr(preflight, "main", lambda args: calls.append(args) or 0)
    assert agent_cli.main(["preflight", "--baseline", "somewhere"]) == 0
    assert calls == [["--baseline", "somewhere", "--solver-mode", "python_loop"]]
    with pytest.raises(SystemExit):
        agent_cli.main(["preflight", "--solver-mode=native"])
    assert len(calls) == 1


def test_python_preflight_never_uses_client_or_binary(config, baseline, tmp_path, monkeypatch):
    original_which = preflight.shutil.which
    def which(name):
        assert name != "opencode", "Python preflight must not search for a client binary"
        return original_which(name)
    monkeypatch.setattr(preflight.shutil, "which", which)
    monkeypatch.setattr(preflight, "browser_preflight", lambda: [{"name": "local_fixture", "ok": True}])
    monkeypatch.setattr(preflight, "prepare_runtime", lambda *_a: pytest.fail("legacy staging selected"))
    output = tmp_path.parent / (tmp_path.name + "-preflights")
    assert agent_cli.main(["preflight", "--baseline", str(baseline), "--provider-config", str(config),
                           "--token-budget", "150000", "--output-dir", str(output)]) == 0
    prepared = launcher.prepared_run(next(output.glob("*/preflight.json")))
    runtime = prepared["runtime"]
    assert not (runtime / "opencode.json").exists()
    assert not (runtime / ".opencode").exists()
    assert (runtime / "config/llm.json").is_file()
    assert prepared["contract"]["solver_mode"] == "python_loop"
    assert agent_cli.main(["run", "--preflight", str(prepared["manifest_path"]),
                           "--seed", str(prepared["contract"]["baseline"]["seeds"][0])]) == 0
    # The complete MCP implementation is frozen, not just the thin loop files.
    inventory = prepared["manifest"]["host_runtime"]
    assert "mcp-servers/mcp-hunter/server.py" in inventory
    monkeypatch.setattr(preflight, "python_host_inventory", lambda: {**inventory, "changed": "digest"})
    with pytest.raises(ValueError, match="host runtime changed"):
        launcher.prepared_run(prepared["manifest_path"])


def test_provider_drift_is_rejected_before_lab_or_model_start(config, tmp_path):
    runtime = tmp_path / "runtime/config"
    runtime.mkdir(parents=True)
    (runtime / "llm.json").write_bytes(config.read_bytes())
    models = llm_config.model_selection(config)
    provider = llm_config.provider_settings(config, models)
    provider["url"] = "https://different.invalid/v1"
    prepared = {"runtime": runtime.parent, "contract": {
        "solver_mode": "python_loop", "baseline": {"seeds": [1]}, "models": models}}
    with pytest.raises(ValueError, match="routing changed"):
        launcher.launch_seed(prepared, seed=1, output=tmp_path / "never-created", provider=provider, api_key="sentinel")
    assert not (tmp_path / "never-created").exists()


@pytest.mark.parametrize("arguments", ["{", "[]", '{"url":NaN}', '{"url":1e999}', '{"url":"a","url":"b"}'])
def test_malformed_model_batch_repairs_once_before_any_execution(python_broker, monkeypatch, arguments):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.active_spec
    contexts = []
    def completion(body):
        contexts.append(json.loads(body["messages"][1]["content"]))
        if len(contexts) == 1:
            return {"choices": [{"message": {"tool_calls": [
                {"function": {"name": "kali-tools_curl_request", "arguments": json.dumps({"url": spec.target})}},
                {"function": {"name": "kali-tools_curl_request", "arguments": arguments}},
            ]}}]}
        assert not python_broker.executor.tasks
        return {"choices": [{"message": {"content": json.dumps(terminal(spec, status="blocked"))}}]}
    monkeypatch.setattr(python_broker, "completion", completion)
    assert solver.phase(spec)["status"] == "blocked"
    assert contexts[-1]["protocol_feedback"]["reason_code"]
    assert solver.protocol_repairs == {spec.id: 1}
    assert not python_broker.executor.tasks


def test_second_bad_model_batch_stops_without_tool_execution(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    monkeypatch.setattr(python_broker, "completion", lambda _body: {"choices": [{"message": {"tool_calls": [
        {"function": {"name": "kali-tools_curl_request", "arguments": "{"}}]}}]})
    with pytest.raises(WorkflowError, match="protocol repair exhausted"):
        solver.phase(python_broker.tasks.active_spec)
    assert not python_broker.executor.tasks


def test_repeated_identical_observation_stops_extra_requests_but_allows_summary(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.active_spec
    seen = []
    def completion(body):
        context = json.loads(body["messages"][1]["content"])
        seen.append(context)
        if context["protocol_feedback"]:
            assert {tool["function"]["name"] for tool in body["tools"]} == {SUMMARY_TOOL}
            return {"choices": [{"message": {"content": json.dumps(terminal(spec))}}]}
        return {"choices": [{"message": {"tool_calls": [{"function": {
            "name": "kali-tools_curl_request", "arguments": json.dumps({"url": spec.target})}}]}}]}
    monkeypatch.setattr(python_broker, "completion", completion)
    assert solver.phase(spec)["status"] == "done"
    assert len(seen) == 4 and len(python_broker.executor.tasks) == 2
    assert solver.loop_events[-1]["reason_code"] == "repeated_request_without_new_evidence"
    assert python_broker.budget.used["http"] == 2


def test_full_tool_catalog_fits_byte_fallback_without_premature_closure(python_broker, monkeypatch):
    """Real schemas are materially larger than the one-tool unit fixture."""
    import full_agent_python_broker as broker_module
    from full_agent_python_solver import SYSTEM
    from full_agent_budget import provider_json
    monkeypatch.setattr(broker_module, 'prompt_bound', lambda raw: (len(raw) + 2048, {}))
    python_broker.load_catalog(python_broker.private / 'state')
    spec = python_broker.tasks.specs[2]
    python_broker.tasks.active_spec = spec
    python_broker.tasks.bindings = {name: {'target': spec.target, 'role': role,
        'test_data_only': True, 'owned_objects_private': True}
        for name, role in [('member-a', 'member'), ('member-b', 'member'), ('admin-a', 'admin')]}
    solver = PythonSolver(python_broker, model='model')
    surface = {'routes': [spec.target + f'api/item/{n}?id={n}' for n in range(20)], 'params': ['id']}
    solver.summaries['enum-2'] = {'surface': surface, 'status': 'partial'}
    (python_broker.workdir / 'handoff.json').write_text(json.dumps({'surface': surface}))
    context = solver.context(spec)
    body = {'model': 'model', 'max_tokens': 4096, 'stream': False, 'parallel_tool_calls': False,
            'messages': [{'role': 'system', 'content': SYSTEM},
                         {'role': 'user', 'content': provider_json(context).decode()}],
            'tools': solver.tool_schemas(spec)}
    sink = {}
    mock_provider(monkeypatch, python_broker, {'choices': [{'message': {'content': '{}'}}],
        'usage': {'prompt_tokens': 100, 'completion_tokens': 100, 'total_tokens': 200}}, request_sink=sink)
    python_broker.completion(body)
    sent = {tool['function']['name'] for tool in sink['payload']['tools']}
    assert {'hunter_run_web_loop', 'validator_session_vault_check', SUMMARY_TOOL} <= sent
    assert spec.id not in python_broker.runtime_policy.finalizing
    assert python_broker.budget.used['tokens'] == 200 and python_broker.budget.used['http'] == 0


def test_python_engine_imports_without_native_compat_modules(tmp_path):
    """Python engine modules and orchestration catalog must not pull native compat."""
    import os
    import subprocess
    import sys

    scripts_dir = str(Path(__file__).resolve().parents[1] / "scripts")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    env.pop("PYTHONPATH", None)
    probe = """
import importlib, sys

BLOCKED = {
    "full_agent_broker",
    "full_agent_native_compat",
    "full_agent_context",
    "full_agent_history",
    "full_agent_bridge",
}

class Blocker:
    def find_spec(self, fullname, path=None, target=None):
        root = fullname.split(".", 1)[0]
        if root in BLOCKED:
            raise ImportError(f"blocked native module: {fullname}")
        return None

sys.meta_path.insert(0, Blocker())
sys.path.insert(0, sys.argv[1])

for name in (
    "agent_cli",
    "full_agent_provider",
    "full_agent_executor",
    "full_agent_python_broker",
    "full_agent_python_solver",
    "full_agent_tasks",
    "full_agent_preflight",
    "full_agent_launcher",
    "orchestration_spec",
):
    importlib.import_module(name)

from orchestration_spec import broker_tools
assert "kali-tools_curl_request" in broker_tools()
from full_agent_tasks import TaskRegistry
assert not hasattr(TaskRegistry, "resolve")
"""
    result = subprocess.run(
        [sys.executable, "-c", probe, scripts_dir],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr[-2000:]


def test_python_broker_omits_native_mediator_and_local_tool_surfaces(python_broker):
    import inspect
    import full_agent_python_broker as python_broker_mod

    for native_attr in (
        "gate",
        "dispatch",
        "record_task_completion",
        "gates",
        "ready",
        "nonce",
        "completed_tasks",
        "task_calls",
    ):
        assert not hasattr(python_broker, native_attr), f"unexpected native attribute: {native_attr}"
    assert "native_context" not in inspect.signature(python_broker.completion).parameters
    assert not hasattr(python_broker_mod, "LOCAL_TOOLS")


def test_python_snapshot_rejects_opencode_json_and_excludes_new_host_modules(
    config, baseline, tmp_path, monkeypatch
):
    monkeypatch.setattr(preflight, "browser_preflight", lambda: [{"name": "local_fixture", "ok": True}])
    for name in (
        "scripts/full_agent_provider.py",
        "scripts/full_agent_executor.py",
        "scripts/full_agent_native_compat.py",
    ):
        assert not preflight.runtime_file(Path(name))
    output = tmp_path.parent / (tmp_path.name + "-preflights-e7")
    assert agent_cli.main([
        "preflight", "--baseline", str(baseline), "--provider-config", str(config),
        "--token-budget", "150000", "--output-dir", str(output),
    ]) == 0
    preflight_path = next(output.glob("*/preflight.json"))
    prepared = launcher.prepared_run(preflight_path)
    inventory = prepared["manifest"]["host_runtime"]
    assert "scripts/full_agent_provider.py" in inventory
    assert "scripts/full_agent_executor.py" in inventory
    assert "scripts/full_agent_native_compat.py" in inventory

    # Adding opencode.json into a python_loop snapshot must be rejected even with matching index hash.
    runtime = prepared["runtime"]
    index_path = Path(prepared["manifest"]["runtime_snapshot"]["index"])
    index_path.chmod(0o644)
    runtime.chmod(0o755)
    (runtime / "opencode.json").write_text("{}\n")
    index = json.loads(index_path.read_text())
    index["files"].append({"path": "opencode.json", "sha256": preflight.sha256(runtime / "opencode.json")})
    index_path.write_text(json.dumps(index, indent=2) + "\n")
    manifest = json.loads(preflight_path.read_text())
    manifest["runtime_snapshot"]["index_sha256"] = preflight.sha256(index_path)
    manifest["runtime_snapshot"]["files"] = len(index["files"])
    preflight_path.write_text(json.dumps(manifest, indent=2) + "\n")
    with pytest.raises(ValueError, match="invalid runtime inventory"):
        launcher.prepared_run(preflight_path)


def test_python_launch_seed_omits_local_tools_and_native_gate_artifacts(
    config, baseline, tmp_path, monkeypatch
):
    import campaign_worker
    import full_agent_python_solver as solver_mod
    from full_agent_python_broker import PythonBroker
    import lab.blind_lab as blind_lab
    from types import SimpleNamespace

    monkeypatch.setattr(preflight, "browser_preflight", lambda: [{"name": "local_fixture", "ok": True}])
    output = tmp_path.parent / (tmp_path.name + "-preflight-launch")
    assert agent_cli.main([
        "preflight", "--baseline", str(baseline), "--provider-config", str(config),
        "--token-budget", "150000", "--output-dir", str(output),
    ]) == 0
    prepared = launcher.prepared_run(next(output.glob("*/preflight.json")))

    class FakeLab:
        server_port = 18765
        blind_state = {"requests": 0, "accounts": {}, "db": None, "fixtures": None}
        def serve_forever(self):
            pass
        def shutdown(self):
            pass
        def server_close(self):
            pass

    class FakeExecutor:
        timeout_seconds = 900
        def __call__(self, _task):
            return {"actual_request_cost": 0, "result": {"output": "{}"}}
        def terminate(self):
            pass

    seen = {}
    class FakeSolver:
        def __init__(self, broker, **_kwargs):
            seen["broker"] = broker
            seen["tasks_type"] = type(broker.tasks).__name__
        def run(self):
            return {"status": "python_finished_verified", "closure_verified": True}

    monkeypatch.setattr(blind_lab, "serve", lambda *_a, **_kw: FakeLab())
    monkeypatch.setattr(campaign_worker, "LocalMCPExecutor", lambda _home: FakeExecutor())
    monkeypatch.setattr(PythonBroker, "load_catalog", lambda self, _home: self.catalog.update({"kali-tools": []}))
    monkeypatch.setattr(solver_mod, "PythonSolver", FakeSolver)

    runs = tmp_path.parent / (tmp_path.name + "-runs")
    runs.mkdir()
    provider = llm_config.provider_settings(config, prepared["contract"]["models"])
    seed = prepared["contract"]["baseline"]["seeds"][0]
    path, manifest = launcher.launch_seed(
        prepared, seed=seed, output=runs, provider=provider, api_key="host-only-sentinel"
    )
    assert manifest["status"] == "python_finished_verified"
    assert "native_session_ids" not in manifest
    assert "native_delegations" not in manifest
    assert seen["tasks_type"] == "TaskRegistry"
    private = path.parent / "private"
    assert not (private / "native-gates.json").exists()
    perms = json.loads((private / "state/permissions.json").read_text())
    for local_tool in ("read", "glob", "grep", "list", "skill", "todowrite", "task", "bash", "write", "edit", "apply_patch"):
        assert local_tool not in perms["tools"]
    assert "kali-tools_curl_request" in perms["tools"]
