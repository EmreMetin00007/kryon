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
