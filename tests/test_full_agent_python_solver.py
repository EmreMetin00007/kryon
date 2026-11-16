"""Offline boundary regressions and a real loopback/subprocess signed workflow."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urljoin, urlsplit

import pytest

import full_agent_launcher as launcher
import full_agent_preflight as preflight
from full_agent_broker import dump
from full_agent_budget import BudgetError, SharedBudget, prompt_bound, provider_json
from full_agent_python_broker import ClosureError, PHASE_CALL_LIMITS, PythonBroker, PythonRuntimePolicy, REPORT_CARRYOVER_STEP, SUMMARY_TOOL
from full_agent_python_solver import PHASE_IDS, PythonSolver, WorkflowError
from full_agent_summary_feedback import summary_feedback
from full_agent_tasks import NativeTasks
from test_full_agent_preflight import baseline as baseline, mock_provider
from test_http_chromium_acceptance import evidence as acceptance_evidence
from fixtures.output_root import output_root


@pytest.fixture
def python_broker(tmp_path, monkeypatch):
    work, private = tmp_path / "solver", tmp_path / "private"
    work.mkdir()
    private.mkdir()
    home = private / "state"
    home.mkdir()
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.delenv("CCO_EVIDENCE_PUBLIC_ONLY", raising=False)
    monkeypatch.delenv("CCO_EVIDENCE_TRUST_FILE", raising=False)
    class Executor:
        tasks = []
        timeout_seconds = 900
        def __call__(self, task):
            self.tasks.append(task)
            return {"actual_request_cost": 1, "result": {"output": {
                "ok": True, "status": 200, "body": "owned fixture"}}}
        def terminate(self):
            pass
    engine = SimpleNamespace(_is_known_tool=lambda _name: True,
                             _rate_limit_for=lambda _name: (0, 60),
                             tool_capability=lambda name: {"network": name == "kali-tools_curl_request"},
                             validate_tool_invocation=lambda *_a, **_kw: {"allowed": True, "reason": "allowed"})
    broker = PythonBroker(budget=SharedBudget(tokens=150000, http=300, seconds=900), engine=engine,
                          executor=Executor(), workdir=work, private=private,
                          provider="https://provider.invalid/v1", models={"model"}, api_key="host-only-sentinel")
    broker.tasks = NativeTasks(launcher.bootstrap_plan("http://127.0.0.1:18765/", work, solver_mode="python_loop"), work, {})
    broker.tasks.active_spec = broker.tasks.specs[0]
    broker.catalog = {"kali-tools": [{"name": "curl_request", "inputSchema": {"type": "object",
                       "properties": {"url": {"type": "string"}}, "required": ["url"]}}]}
    return broker


def terminal(spec, **overrides):
    return {"status": "done", "next": "continue", "steps": [
        {"id": step.id, "status": "done"} for step in spec.steps], **overrides}


@pytest.mark.parametrize("invalid", ["missing_required", "wrong_type", "extra_property"])
def test_schema_invalid_batch_repairs_before_any_mcp_invocation(python_broker, monkeypatch, invalid):
    python_broker.catalog["kali-tools"][0]["inputSchema"]["additionalProperties"] = False
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.active_spec
    bad = {"missing_required": {}, "wrong_type": {"url": 42}, "extra_property": {
        "url": spec.target, "unexpected": "synthetic-private-argument"}}[invalid]
    original_completion, original_invoke = python_broker.completion, python_broker.invoke
    contexts, invoked = [], []

    def invoke(name, args):
        invoked.append((name, args))
        return original_invoke(name, args)

    def call(args):
        return {"function": {"name": "kali-tools_curl_request", "arguments": json.dumps(args)}}

    def completion(body):
        contexts.append(json.loads(body["messages"][1]["content"]))
        if len(contexts) == 1:
            # Even the valid first call must be withheld when a later call
            # in the same batch violates the advertised schema.
            message = {"tool_calls": [call({"url": spec.target}), call(bad)]}
        elif len(contexts) == 2:
            assert not invoked and not python_broker.executor.tasks
            assert python_broker.budget.used["http"] == 0
            assert contexts[-1]["protocol_feedback"]["reason_code"] == "tool_arguments_schema_invalid"
            message = {"tool_calls": [call({"url": spec.target})]}
        else:
            assert len(invoked) == 1
            message = {"content": json.dumps(terminal(spec))}
        mock_provider(monkeypatch, python_broker, {"choices": [{"message": message}],
                      "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
        return original_completion(body)

    monkeypatch.setattr(python_broker, "invoke", invoke)
    monkeypatch.setattr(python_broker, "completion", completion)
    assert solver.phase(spec)["status"] == "done"
    assert len(invoked) == len(python_broker.executor.tasks) == 1
    assert python_broker.calls == 3 and python_broker.budget.used == {"http": 1, "tokens": 330}
    assert solver.protocol_repairs == {spec.id: 1} and not solver.repairs
    events = json.loads((python_broker.private / "python-loop-events.json").read_text())
    assert events == [{"spec_id": spec.id, "reason_code": "tool_arguments_schema_invalid"}]
    assert "synthetic-private-argument" not in json.dumps(events)


@pytest.mark.parametrize("first_arguments", ["{", "{}"])
def test_schema_failures_share_one_bounded_protocol_repair(python_broker, monkeypatch, first_arguments):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.active_spec
    original = python_broker.completion
    calls = []

    def completion(body):
        calls.append(body)
        arguments = first_arguments if len(calls) == 1 else "{}"
        mock_provider(monkeypatch, python_broker, {"choices": [{"message": {"tool_calls": [{"function": {
            "name": "kali-tools_curl_request", "arguments": arguments}}]}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
        return original(body)

    monkeypatch.setattr(python_broker, "completion", completion)
    monkeypatch.setattr(python_broker, "invoke", lambda *_args: pytest.fail("invalid batch reached invocation"))
    with pytest.raises(WorkflowError) as caught:
        solver.phase(spec)
    assert caught.value.code == "tool_protocol_repair_exhausted"
    assert python_broker.calls == len(calls) == 2
    assert python_broker.budget.used == {"http": 0, "tokens": 220}
    assert solver.protocol_repairs == {spec.id: 1} and len(solver.loop_events) == 1
    assert not python_broker.executor.tasks


@pytest.mark.parametrize("value", [{}, {"count": True}, {"count": 4}, {"count": 1, "extra": 1}])
def test_schema_validation_enforces_nested_local_refs(python_broker, value):
    solver = PythonSolver(python_broker, model="model")
    schema = {"type": "object", "$defs": {"entry": {"type": "object", "properties": {
        "count": {"type": "integer", "minimum": 1, "maximum": 3}}, "required": ["count"],
        "additionalProperties": False}}, "properties": {"entries": {"type": "array", "minItems": 1,
        "items": {"$ref": "#/$defs/entry"}}}, "required": ["entries"], "additionalProperties": False}
    call = {"function": {"name": "example", "arguments": json.dumps({"entries": [value]})}}
    with pytest.raises(WorkflowError) as caught:
        solver.parse_calls([call], {"example": schema})
    assert caught.value.code == "tool_arguments_schema_invalid"
    call["function"]["arguments"] = json.dumps({"entries": [{"count": 2}]})
    assert solver.parse_calls([call], {"example": schema}) == [("example", {"entries": [{"count": 2}]})]
    assert not python_broker.executor.tasks


def test_schema_validation_does_not_fetch_remote_refs(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    monkeypatch.setattr("urllib.request.urlopen", lambda *_a, **_kw: pytest.fail("schema fetched a remote ref"))
    schema = {"type": "object", "properties": {"url": {"$ref": "https://schema.invalid/private"}}}
    call = {"function": {"name": "example", "arguments": '{"url":"synthetic-private-argument"}'}}
    with pytest.raises(WorkflowError) as caught:
        solver.parse_calls([call], {"example": schema})
    assert caught.value.code == "tool_arguments_schema_invalid"
    assert "synthetic-private-argument" not in str(caught.value)
    assert not python_broker.executor.tasks


def test_solver_host_admission_and_taskspec_roundtrip(tmp_path, monkeypatch):
    from test_p7_business_logic import bound_p7
    from orchestration_spec import TaskSpec
    broker, spec, ref, graph, _, prep = bound_p7(tmp_path, monkeypatch)
    binding = broker.workflow_bindings.pop(ref)
    spec.compiled_workflows.clear()
    try:
        solver = PythonSolver(broker, model='local', compiled_workflows=[{
            'task_spec_id': spec.id, 'manifest': binding.manifest, 'graph': graph,
            'runtime': binding.runtime, 'identities': binding.identities,
            'authorized_tools': binding.envelope['payload']['authorized_tools'],
            'capture_hashes': binding.capture_hashes, 'write_context': binding.write_context}])
        assert ref in broker.workflow_bindings
        assert TaskSpec.from_dict(spec.to_dict()).compiled_workflows == spec.compiled_workflows
        assert solver.base_specs[0]['compiled_workflows'] == spec.compiled_workflows
        assert solver.authorization_context() == solver._authorization_context
        assert not prep[0].calls and broker.budget.used['http'] == 0
    finally:
        graph.close()


@pytest.mark.parametrize('limit', ['http', 'time', 'calls'])
def test_compiled_workflow_keeps_python_shared_budgets(tmp_path, monkeypatch, limit):
    from test_p7_business_logic import bound_p7
    broker, spec, ref, graph, _, prep = bound_p7(tmp_path, monkeypatch)
    if limit == 'http':
        broker.budget.used['http'] = broker.budget.limits['http'] - 1
    elif limit == 'time':
        broker.budget.deadline = broker.budget.clock()
    else:
        broker.runtime_policy.tool_calls[spec.id] = 14
    try:
        with pytest.raises(BudgetError):
            broker.invoke('workflow_execute_compiled', {'binding_ref': ref})
        assert not prep[0].calls
    finally:
        graph.close()


def test_compiled_workflow_sender_failure_accounts_attempt(tmp_path, monkeypatch):
    from test_p7_business_logic import bound_p7
    broker, spec, ref, graph, _, prep = bound_p7(tmp_path, monkeypatch)
    def sender(*args):
        prep[0].calls.append((args[0], args[1]))
        raise OSError('synthetic interrupted request')
    broker.workflow_sender = sender
    try:
        value = broker.invoke('workflow_execute_compiled', {'binding_ref': ref})['result']
        assert value['execution_failed'] and value['requests_sent'] == 1
        assert broker.budget.used['http'] == len(prep[0].calls) == 1
    finally:
        graph.close()



def member_solver(broker, monkeypatch, count=4):
    spec = broker.tasks.specs[2]
    broker.tasks.bindings = {f"synthetic-{index}": {"target": spec.target, "role": "member",
                            "test_data_only": True, "owned_objects_private": True} for index in range(count)}
    solver = PythonSolver(broker, model="model")
    source = broker.tasks.specs[1]
    view = broker.view({"records": [{"url": spec.target}]})
    broker.results.append({"spec_id": source.id, "tool": "kali-tools_crawl_web_surface",
                           "arguments": {"target": spec.target}, **view})
    solver.summaries[source.id] = solver.compile_summary(source, terminal(source))
    broker.catalog["hunter"] = [{"name": "run_web_loop", "inputSchema": {"type": "object"}}]
    broker.tasks.active_spec = spec
    monkeypatch.setattr(broker, "_check_handoff", lambda _spec: None)
    return solver, spec


@pytest.mark.parametrize("count,expected", [(0, 0), (1, 0), (2, 1), (3, 3), (4, 6), (7, 21), (8, 28)])
def test_host_member_batches_cover_every_registered_eligible_identity(python_broker, monkeypatch, count, expected):
    solver, spec = member_solver(python_broker, monkeypatch, count)
    batches = solver.access_batches
    assert len(batches) == expected
    assert all(len(batch) == 2 for batch in batches)
    if count >= 2:
        assert set().union(*(set(batch) for batch in batches)) == set(python_broker.tasks.bindings)
    assert len({tuple(batch) for batch in batches}) == expected
    policy = python_broker.runtime_policy
    reserve = max(1, (count + 1) // 2) if count >= 2 else 1
    assert policy.validation_reserves[spec.id] == reserve
    assert policy.tool_allowance(spec) == 14 - reserve
    assert python_broker.budget.limits == {"http": 300, "tokens": 150000}


def test_host_member_batches_refuse_more_than_eight_identities(python_broker, monkeypatch):
    with pytest.raises(ValueError, match="host member identity limit"):
        member_solver(python_broker, monkeypatch, 9)


@pytest.mark.parametrize("change", [{"target": "http://127.0.0.1:1/"}, {"role": "admin"},
    {"test_data_only": False}, {"test_data_only": 1}, {"owned_objects_private": False},
    {"owned_objects_private": "true"}])
def test_host_member_batches_keep_exact_target_and_synthetic_private_guards(python_broker, monkeypatch, change):
    solver, spec = member_solver(python_broker, monkeypatch)
    python_broker.tasks.bindings["synthetic-3"].update(change)
    batches = solver.member_batches(spec)
    assert "synthetic-3" not in set().union(*(set(batch) for batch in batches))


def test_host_batches_execute_once_and_keep_reserves_until_all_calls(python_broker, monkeypatch):
    solver, spec = member_solver(python_broker, monkeypatch)
    policy, calls = python_broker.runtime_policy, []
    def invoke(tool, args):
        assert policy.validation_reserves[spec.id] == 2
        policy.check_tool(spec, tool)
        calls.append(args)
        return python_broker.view({"ok": True})
    monkeypatch.setattr(python_broker, "invoke", invoke)
    assert solver.dispatch_access_validation(spec)
    assert len(calls) == 6 and policy.tool_calls[spec.id] == 6
    assert all(args["max_validations"] == 16 and args["blind_max_requests"] == 24 for args in calls)
    assert set(json.loads(calls[0]["session_bindings"])).isdisjoint(json.loads(calls[1]["session_bindings"]))
    assert not policy.host_finalizing and not policy.validation_reserves
    assert not solver.dispatch_access_validation(spec) and len(calls) == 6
    assert python_broker.calls == 0 and python_broker.budget.used == {"http": 0, "tokens": 0}


@pytest.mark.parametrize("limit", ["slots", "http", "time"])
def test_host_batch_shortfall_stays_not_tested_without_exceeding_limits(python_broker, monkeypatch, limit):
    solver, spec = member_solver(python_broker, monkeypatch)
    if limit == "slots":
        python_broker.runtime_policy.tool_calls[spec.id] = 14
    elif limit == "http":
        python_broker.budget.used["http"] = 300
    else:
        python_broker.budget.deadline = python_broker.budget.clock()
    monkeypatch.setattr(python_broker, "invoke", lambda *_args: pytest.fail("no budget remains"))
    assert not solver.dispatch_access_validation(spec)
    assert python_broker.results[-1]["result"]["status"] == "not_tested"
    summary = solver.compile_summary(spec, terminal(spec))
    assert summary["status"] == "partial" and not summary["validation_outcomes"]
    assert next(step for step in summary["steps"] if step["id"] == "minimal-validation")["status"] == "not_tested"
    assert len(summary["identity_comparisons"]) == 6
    assert all(row["status"] == "NOT TESTED" for row in summary["identity_comparisons"])
    assert all(row["status"] == "NOT TESTED" for row in summary["identity_comparison_dimensions"])
    assert not python_broker.runtime_policy.host_finalizing


def identity_facts(principal, tenant, role="member"):
    return [{"field": field, "value": value, "source": "operator", "evidence": "owned E3 fixture"}
            for field, value in {"principal": principal, "authority": "e3-test", "tenant": tenant, "role": role}.items()]


def test_member_pairs_follow_p4_facts_and_cover_new_identities_first(python_broker, monkeypatch):
    solver, spec = member_solver(python_broker, monkeypatch)
    for index, binding in enumerate(python_broker.tasks.bindings.values()):
        binding["identity_facts"] = identity_facts(str(index), str(index // 2), "manager" if index % 2 else "member")
    batches = solver.member_batches(spec)
    assert [list(batch) for batch in batches[:2]] == [
        ["synthetic-0", "synthetic-2"], ["synthetic-1", "synthetic-3"]]
    assert all("cross_tenant_user" in solver.member_pair_categories(batch) for batch in batches[:4])
    assert all("same_tenant_other_user" in solver.member_pair_categories(batch) for batch in batches[4:])
    assert any("different_role" in solver.member_pair_categories(batch) for batch in batches)
    # Scheduling facts stay private; existing wire binding guards stay intact.
    assert all(set(binding) == {"target", "role", "test_data_only", "owned_objects_private"}
               for batch in batches for binding in batch.values())


def test_flat_tenant_metadata_prioritizes_pairs_without_inventing_facts(python_broker, monkeypatch):
    solver, spec = member_solver(python_broker, monkeypatch)
    for index, binding in enumerate(python_broker.tasks.bindings.values()):
        binding["tenant"] = str(index // 2)
    assert list(solver.member_batches(spec)[0]) == ["synthetic-0", "synthetic-2"]
    binding = python_broker.tasks.bindings["synthetic-0"]
    binding["identity_facts"] = identity_facts("0", "0") + [
        {"field": "tenant", "value": "other", "source": "operator", "evidence": "conflict"}]
    assert solver.member_pair_categories(["synthetic-0", "synthetic-2"]) == []
    # Credential aliases of one evidenced principal cannot fill P4 categories.
    python_broker.tasks.bindings["synthetic-2"]["identity_facts"] = identity_facts("0", "1", "manager")
    assert solver.member_pair_categories(["synthetic-0", "synthetic-2"]) == []


def test_all_pairs_respect_the_physical_host_call_ceiling(python_broker, monkeypatch):
    solver, spec = member_solver(python_broker, monkeypatch, count=8)
    monkeypatch.setattr(python_broker.engine, "tool_capability", lambda _tool: {"network": True})
    assert len(solver.access_batches) == 28
    assert solver.dispatch_access_validation(spec)
    assert python_broker.runtime_policy.tool_calls[spec.id] == PHASE_CALL_LIMITS["access"] == 14
    assert len(python_broker.executor.tasks) == 14
    assert python_broker.budget.used == {"http": 14, "tokens": 0}
    summary = solver.compile_summary(spec, terminal(spec))
    assert len(summary["member_batch_shortfalls"][0]["pending_batches"]) == 14
    assert summary["member_batch_shortfalls"][0]["reason_code"] == "phase_tool_budget_exhausted"
    # Tool success with no signed pair queue is still NOT TESTED.
    assert len(summary["identity_comparisons"]) == 28
    assert all(row["status"] == "NOT TESTED" for row in summary["identity_comparisons"])
    assert python_broker.calls == 0


@pytest.mark.parametrize("limit", ["full", "http", "slots"])
def test_cross_tenant_bola_signed_loopback_and_budget_coverage(python_broker, monkeypatch, tmp_path, limit):
    """Real HTTP and validator receipts: adjacent pairs miss these two BOLAs."""
    from conftest import load_server
    validator = load_server("validator")
    from cco_validator_core.egress import scoped_wire_gate
    from cco_validator_core.evidence import validation_context
    from wire_budget import campaign_wire_budget
    import uuid
    wire = []
    vulnerable = {("synthetic-0", "synthetic-2"), ("synthetic-1", "synthetic-3")}
    assert all(set(pair) not in ({"synthetic-0", "synthetic-1"}, {"synthetic-2", "synthetic-3"})
               for pair in vulnerable)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_GET(self):
            owner, actor = self.path.removeprefix("/objects/"), self.headers.get("Cookie", "").removeprefix("identity=")
            allowed = actor == owner or (owner, actor) in vulnerable
            wire.append({"owner": owner, "actor": actor, "status": 200 if allowed else 403})
            body = json.dumps({"marker": "owned-marker-" + owner} if allowed else {"error": "denied"}).encode()
            self.send_response(200 if allowed else 403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base = f"http://127.0.0.1:{server.server_port}/"
    runtime = tmp_path / "e3-runtime"
    (runtime / ".codex").mkdir(parents=True)
    scope, policy = launcher.lab_policy(base)
    dump(runtime / ".codex/scope.json", scope)
    dump(runtime / ".codex/program-policy.json", policy)
    assert launcher.verify_lab_scope(runtime, base)["before_traffic"]
    monkeypatch.setenv("CCO_SCOPE_FILE", str(runtime / ".codex/scope.json"))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(runtime / ".codex/program-policy.json"))
    for spec in python_broker.tasks.specs:
        spec.target = base
    if limit == "http":
        python_broker.budget.limits["http"] = 10
    if limit == "slots":
        python_broker.tasks.specs[2].max_calls = 2
    solver, spec = member_solver(python_broker, monkeypatch)
    for index, binding in enumerate(python_broker.tasks.bindings.values()):
        binding["identity_facts"] = identity_facts(str(index), str(index // 2))
    solver.access_batches = solver.member_batches(spec)
    monkeypatch.setattr(python_broker.engine, "tool_capability", lambda _tool: {"network": True})
    def gate(method, url, _headers):
        return (method == "GET" and urlsplit(url).netloc == urlsplit(base).netloc), "owned E3 loopback"
    def execute(self, task):
        self.tasks.append(task)
        names = list(json.loads(json.loads(task["args_json"])["session_bindings"]))
        queue, validations = [], []
        with campaign_wire_budget(task["reserved_request_cost"], uuid.uuid4().hex) as budget, scoped_wire_gate(gate):
            for owner, actor in (names, names[::-1]):
                item = {"url": base + "objects/" + owner, "method": "GET", "vuln_class": "idor",
                        "resource_owner": owner, "identity": actor}
                queue.append(item)
                with validation_context(item):
                    record = json.loads(validator.validate_idor(item["url"],
                        json.dumps({"Cookie": "identity=" + owner}), json.dumps({"Cookie": "identity=" + actor}),
                        owner_marker="owned-marker-" + owner))
                validations.append({**item, "validation_id": record["validation_id"]})
        return {"actual_request_cost": budget.used, "result": {"output": {"ok": True,
            "identity_discovery": {"status": "ready", "reasons": [], "budget_limited": False},
            "validation_queue": queue, "validations": validations}}}
    monkeypatch.setattr(type(python_broker.executor), "__call__", execute)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert solver.dispatch_access_validation(spec)
        summary = solver.compile_summary(spec, terminal(spec))
        confirmed = [row for row in python_broker.validation_attempts(spec) if row["record"]["verdict"] == "CONFIRMED"]
        assert {(row["record"]["execution_context"]["resource_owner"], row["record"]["execution_context"]["identity"])
                for row in confirmed} == vulnerable
        pairs = summary["identity_comparisons"]
        assert len(pairs) == 6 and all(row["status"] == "TESTED" for row in pairs[:2])
        assert python_broker.budget.used["http"] == len(wire) <= python_broker.budget.limits["http"]
        assert python_broker.runtime_policy.tool_calls[spec.id] <= min(spec.max_calls, PHASE_CALL_LIMITS["access"])
        assert python_broker.calls == 0 and python_broker.budget.used["tokens"] == 0
        if limit == "full":
            assert all(row["status"] == "TESTED" for row in pairs)
            assert len(python_broker.executor.tasks) == 6
            assert len([row for row in summary["validation_outcomes"] if row["verdict"] == "UNCONFIRMED"]) == 10
        else:
            assert len(python_broker.executor.tasks) == 2 and len(wire) == 10
            assert all(row["status"] == "NOT TESTED" for row in pairs[2:])
            expected = "http_budget_exhausted" if limit == "http" else "phase_tool_budget_exhausted"
            assert all(row["reason_code"] == expected for row in pairs[2:])
            assert summary["member_batch_shortfalls"][0]["pending_batches"] == [row["identities"] for row in pairs[2:]]
        different_role = next(row for row in summary["identity_comparison_dimensions"] if row["category"] == "different_role")
        assert different_role["status"] == "NOT TESTED" and different_role["total_pairs"] == 0
        solver.summaries[spec.id] = summary
        report = solver.compile_summary(python_broker.tasks.specs[3], terminal(python_broker.tasks.specs[3]))
        assert report["identity_comparisons"] == [{"phase": spec.id, **row} for row in pairs if row["status"] == "NOT TESTED"]
        assert {"phase": spec.id, **different_role} in report["identity_comparison_dimensions"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)



def parameter_solver(broker, monkeypatch):
    solver, spec = member_solver(broker, monkeypatch, count=1)
    spec.vector = 'injection-sqli'
    view = broker.view({'links': ['/lookup/catalog/a?id=1', '/lookup/catalog/b?id=1']})
    ref = view['content_ref']
    broker.results.append({'spec_id': broker.tasks.specs[1].id, 'tool': 'kali-tools_crawl_web_surface',
                           'arguments': {'target': spec.target, 'identity': 'synthetic-0'}, **view})
    records = [{'url': spec.target + path, 'method': 'GET', 'identity_ref': 'synthetic-0',
                'source_artifact': ref['path'], 'source_sha256': ref['sha256']} for path in (
                    'lookup/catalog', 'lookup/catalog/a?id=1', 'lookup/catalog/b?id=1')]
    solver.summaries['enum-2'] = {'surface': {'records': records}}
    broker.results.append({'spec_id': spec.id, 'tool': 'hunter_run_web_loop',
        'arguments': {'target': spec.target, 'live': True, 'validation_profile': 'readonly_sqli_boolean'},
        **broker.view({'ok': True})})
    return solver, spec, ref


def test_parameter_continuation_requires_each_current_signed_control(python_broker, monkeypatch):
    solver, spec, _ref = parameter_solver(python_broker, monkeypatch)
    def attempt(suffix, oracle='differential_boolean'):
        return {'vector': 'injection-sqli', 'record': {'target': spec.target + suffix,
            'validation_id': suffix, 'oracle': oracle, 'execution_context': {
                'param': 'id', 'method': 'GET', 'carrier': 'query', 'identity': 'synthetic-0'}},
                'source_artifact': 'test-control', 'source_sha256': 'test-control'}
    one = attempt('lookup/catalog/a?id=1')
    other = attempt('lookup/catalog/b?id=1')
    monkeypatch.setattr(python_broker, 'validation_attempts', lambda _spec: [one])
    assert len(solver.pending_parameter_batches(spec)) == 1
    # A different oracle or query value cannot suppress the missing control.
    for wrong in (attempt('lookup/catalog/b?id=1', 'error_based'), attempt('lookup/catalog/b?id=2')):
        monkeypatch.setattr(python_broker, 'validation_attempts', lambda _spec: [one, wrong])
        assert len(solver.pending_parameter_batches(spec)) == 1
    monkeypatch.setattr(python_broker, 'validation_attempts', lambda _spec: [one, other])
    assert solver.pending_parameter_batches(spec) == []


def test_parameter_continuation_rejects_changed_discovery_before_execution(python_broker, monkeypatch):
    solver, spec, ref = parameter_solver(python_broker, monkeypatch)
    (python_broker.workdir / ref['path']).write_text('{}')
    with pytest.raises(ValueError, match='prior phase evidence changed'):
        solver.dispatch_access_validation(spec)
    assert not python_broker.executor.tasks


@pytest.mark.parametrize('limit', ['slots', 'http', 'time'])
def test_parameter_shortfall_remains_unexecuted_with_reason(python_broker, monkeypatch, limit):
    solver, spec, _ref = parameter_solver(python_broker, monkeypatch)
    if limit == 'slots':
        python_broker.runtime_policy.tool_calls[spec.id] = 14
    elif limit == 'http':
        python_broker.budget.used['http'] = 300
    else:
        python_broker.budget.deadline = python_broker.budget.clock()
    monkeypatch.setattr(python_broker, 'invoke', lambda *_args: pytest.fail('budget exhausted'))
    assert not solver.dispatch_access_validation(spec)
    assert python_broker.results[-1]['result']['status'] == 'not_tested'
    assert python_broker.results[-1]['result']['reason_code']
    assert not python_broker.runtime_policy.validation_reserves
    assert not python_broker.runtime_policy.host_finalizing

def test_prior_unrelated_validator_cannot_skip_pending_member_batches(python_broker, monkeypatch):
    solver, spec = member_solver(python_broker, monkeypatch)
    python_broker.results.append({"spec_id": spec.id, "tool": "validator_validate_open_redirect",
                                 "arguments": {}, **python_broker.view({"verdict": "UNCONFIRMED"})})
    calls = []
    monkeypatch.setattr(python_broker, "invoke", lambda tool, args: calls.append(args))
    assert solver.dispatch_access_validation(spec) and len(calls) == 6


@pytest.mark.parametrize("trusted,ready", [(False, True), (True, False), (True, True)])
def test_only_complete_current_signed_member_queue_avoids_replay(python_broker, monkeypatch, trusted, ready):
    solver, spec = member_solver(python_broker, monkeypatch)
    batch = solver.access_batches[0]
    names = list(batch)
    queue = [{"url": spec.target + str(index), "resource_owner": name, "identity": names[1 - index]}
             for index, name in enumerate(names)]
    report = {"ok": True, "identity_discovery": {"status": "ready" if ready else "blocked"},
              "validation_queue": queue, "validations": [{**item, "validation_id": str(index)}
                                                           for index, item in enumerate(queue)]}
    python_broker.results.append({"spec_id": spec.id, "tool": "hunter_run_web_loop", "arguments": {
        "target": spec.target, "live": True, "blind_discovery": True, "session_bindings": json.dumps(batch)},
        **python_broker.view(report)})
    records = [{"record": {"validation_id": str(index), "target": item["url"], "execution_context": item}}
               for index, item in enumerate(queue)]
    monkeypatch.setattr(python_broker, "validation_attempts", lambda _spec: records if trusted else [])
    assert solver.completed_member_batch(spec, batch) == (trusted and ready)


def test_access_backoff_uses_policy_windows_and_is_interruptible(python_broker, monkeypatch):
    solver, spec = member_solver(python_broker, monkeypatch)
    monkeypatch.setattr(python_broker.engine, "_rate_limit_for", lambda name: (75 if name == "validator_validate_idor" else 60, 20))
    now, waits = [100.0], []
    python_broker.budget.clock = lambda: now[0]
    python_broker.budget.deadline = 1000
    def wait(seconds):
        waits.append(seconds)
        now[0] += seconds
    monkeypatch.setattr(python_broker.closed, "wait", wait)
    assert solver.wait_access_rate_window(spec)
    assert sum(waits) == 75 and max(waits) <= 1
    assert python_broker.results[-1]["result"]["window_seconds"] == 75
    monkeypatch.setattr(python_broker.closed, "wait", lambda _seconds: python_broker.closed.set())
    with pytest.raises(BudgetError, match="closed"):
        solver.wait_access_rate_window(spec)


def test_access_backoff_with_insufficient_time_does_not_send_requests(python_broker, monkeypatch):
    solver, spec = member_solver(python_broker, monkeypatch)
    monkeypatch.setattr(python_broker.engine, "_rate_limit_for", lambda _name: (60, 60))
    python_broker.budget.deadline = python_broker.budget.clock() + 30
    monkeypatch.setattr(python_broker.closed, "wait", lambda _seconds: pytest.fail("insufficient time"))
    assert not solver.wait_access_rate_window(spec)
    assert python_broker.budget.used == {"http": 0, "tokens": 0}

def test_python_phase_shares_limits_and_reserved_repair(python_broker):
    policy = python_broker.runtime_policy
    assert policy.limits == {"recon": 30000, "enum": 45000, "access": 37500, "report": 22500, "planner": 15000}
    assert [spec.max_calls for spec in python_broker.tasks.specs] == [12, 16, 14, 6]
    spec = python_broker.tasks.active_spec
    info = policy.prepare(spec, 5000)
    assert info["request_token_allowance"] < info["remaining_phase_tokens"]
    policy.calls[spec.id] = 11
    with pytest.raises(BudgetError, match="phase_call"):
        policy.prepare(spec, 5000)
    policy.repairing.add(spec.id)
    assert policy.prepare(spec, 5000)["request_token_allowance"] == 30000
    policy.calls[spec.id] = 12
    with pytest.raises(BudgetError, match="phase_call"):
        policy.prepare(spec, 5000)


def test_phase_counters_cannot_reset_by_reusing_a_spec(python_broker):
    policy, spec = python_broker.runtime_policy, python_broker.tasks.active_spec
    for _ in range(12):
        policy.check_tool(spec, "kali-tools_curl_request")
    with pytest.raises(BudgetError, match="phase_tool"):
        policy.check_tool(spec, "kali-tools_curl_request")
    ticket = policy.budget.reserve("tokens", 30000)
    policy.budget.settle(ticket, 30000, runtime_phase="recon")
    assert policy.allowance(spec)[0] == 0


def test_two_consecutive_failures_across_tools_brake_and_success_resets(python_broker):
    policy, spec = python_broker.runtime_policy, python_broker.tasks.active_spec
    policy.record_result(spec, "first", None, "failure")
    policy.record_result(spec, "second", {"result": {"output": {"verdict": "UNCONFIRMED"}}})
    assert policy.consecutive_failures[spec.id] == 0
    policy.record_result(spec, "first", None, "failure")
    policy.record_result(spec, "second", {"result": {"output": {"error": "schema"}}})
    with pytest.raises(BudgetError, match="consecutive_tool"):
        policy.check_tool(spec, "kali-tools_curl_request")


def test_direct_execution_is_accounted_and_signed_without_model_keys(python_broker):
    from evidence_trust import canonical_bytes, verify
    view = python_broker.invoke("kali-tools_curl_request", {"url": python_broker.tasks.active_spec.target})
    assert view["result"]["status"] == 200
    assert python_broker.budget.used["http"] == 1
    assert python_broker.executor.tasks[0]["reserved_request_cost"] == 300
    signed = json.loads((python_broker.workdir / "attempt-ledger.json").read_bytes())
    assert verify(canonical_bytes(signed["payload"]), signed, "python-attempt-ledger")
    assert "host-only-sentinel" not in json.dumps(view)
    with pytest.raises(ValueError, match="active TaskSpec"):
        python_broker.invoke("validator_validate_sqli", {"target_url": python_broker.tasks.active_spec.target})


@pytest.mark.parametrize("bytes_count", [5000, 200000])
def test_large_content_keeps_exact_archive_and_bounded_reads(python_broker, bytes_count):
    value = {"ok": True, "body": "x" * bytes_count}
    view = python_broker.view(value)
    assert len(provider_json(view)) < 1000 and view["omitted"]
    ref = view["content_ref"]
    assert json.loads((python_broker.workdir / ref["path"]).read_bytes()) == value
    read = python_broker.invoke("read_artifact", {"path": ref["path"], "limit": 100})
    assert len(read["result"]["text"]) == 100
    (python_broker.workdir / ref["path"]).write_text("changed")
    with pytest.raises(ValueError, match="artifact"):
        python_broker.invoke("read_artifact", {"path": ref["path"]})


@pytest.mark.parametrize("text", ["x" * 8000, "ş🔎" * 4000])
def test_full_artifact_pages_reach_model_without_recursive_projection(python_broker, text):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.active_spec
    ref = python_broker.view({"body": text})["content_ref"]
    raw = (python_broker.workdir / ref["path"]).read_text()
    offset, chunks = 0, []
    while True:
        page = python_broker.invoke("read_artifact", {"path": ref["path"], "offset": offset})
        visible = solver.context(spec)["recent_results"][-1]["result"]
        assert visible == page["result"]
        assert visible["text"] == raw[offset:offset + 3000]
        assert visible["content_ref"] == ref and not page.get("omitted")
        assert len(visible["text"]) <= 3000
        chunks.append(visible["text"])
        if visible["eof"]:
            assert visible["next_offset"] is None
            break
        assert visible["next_offset"] > offset
        offset = visible["next_offset"]
    assert "".join(chunks) == raw and python_broker.budget.used["http"] == 0


def test_repeated_read_does_not_grow_model_context_or_reset_accounting(python_broker):
    solver = PythonSolver(python_broker, model="model")
    ref = python_broker.view({"body": "x" * 8000})["content_ref"]
    for _ in range(8):
        python_broker.invoke("read_artifact", {"path": ref["path"]})
    context = solver.context(python_broker.tasks.active_spec)
    assert len(context["recent_results"]) == 2 and not context["older_results"]
    assert context["recent_results"][-1]["result"]["reason_code"] == "archive_read_no_progress"
    assert len(python_broker.results) == 8
    assert python_broker.runtime_policy.tool_calls["recon-1"] == 8


def test_distinct_artifact_pages_keep_latest_text_and_prior_progress(python_broker):
    solver = PythonSolver(python_broker, model='model')
    ref = python_broker.view({'body': 'x' * 15000})['content_ref']
    for offset in (0, 3000, 6000, 9000):
        python_broker.invoke('read_artifact', {'path': ref['path'], 'offset': offset})
    context = solver.context(python_broker.tasks.active_spec)
    recent = context['recent_results']
    assert len(recent) == 4 and recent[-1]['result']['text'] == 'x' * 3000
    assert all('text' not in row['result'] and row['result']['text_archived'] for row in recent[:-1])
    assert [row['result']['offset'] for row in recent] == [0, 3000, 6000, 9000]
    assert all(len(row['result']['text']) == 3000 for row in python_broker.results)
    assert len(provider_json(context)) < 8500


@pytest.mark.parametrize('spent,pages', [(4583, 2), (4583, 4), (20638, 4)])
def test_large_access_context_is_projected_before_exact_provider_admission(python_broker, monkeypatch, spent, pages):
    import copy
    import hashlib
    from full_agent_python_solver import SYSTEM
    from full_agent_runtime_policy import MAX_CONTEXT_BYTES, MAX_PROMPT_TOKENS, MIN_OUTPUT_TOKENS
    solver = PythonSolver(python_broker, model='model')
    spec = python_broker.tasks.specs[2]
    python_broker.tasks.active_spec = spec
    dump(python_broker.workdir / 'handoff.json', {'fixture': 'opaque reference only'})
    ticket = python_broker.budget.reserve('tokens', spent)
    python_broker.budget.settle(ticket, spent, runtime_phase='access')
    python_broker.runtime_policy.calls[spec.id] = 2
    # Deterministic, varied ASCII pages stress token/byte bounds as well as
    # distinct-page accumulation, rather than repeating cheap single tokens.
    text = ''.join(hashlib.sha256(str(n).encode()).hexdigest() for n in range(250))
    ref = python_broker.archive({'body': text})
    context = solver.context(spec)
    context['recent_results'] = []
    for n in range(pages):
        value = {'content_ref': ref, 'offset': n * 3000, 'text': text[n * 3000:(n + 1) * 3000],
                 'next_offset': (n + 1) * 3000, 'eof': False}
        context['recent_results'].append({'tool': 'read_artifact', **{
            'result': value, 'content_ref': python_broker.archive(value)}})
    context['older_results'] = [{'tool': 'read_artifact', 'content_ref': ref}] * 8
    body = {'model': 'model', 'max_tokens': 4096, 'tools': solver.tool_schemas(spec),
            'messages': [{'role': 'system', 'content': SYSTEM},
                         {'role': 'user', 'content': provider_json(context).decode()}]}
    before = copy.deepcopy(body)
    response = {'choices': [{'message': {'content': '{}'}}],
                'usage': {'prompt_tokens': 1800, 'completion_tokens': 100, 'total_tokens': 1900}}
    captured = {}
    mock_provider(monkeypatch, python_broker, response, request_sink=captured)
    python_broker.completion(body)
    assert body == before and python_broker.calls == 1
    sent = captured['payload']
    projected = json.loads(sent['messages'][1]['content'])
    metrics = python_broker.provider_requests[-1]
    assert metrics['admitted'] and metrics['context_projection']['level'] > 0
    archived = projected['context_archive_ref']
    assert json.loads((python_broker.workdir / archived['path']).read_bytes()) == context
    assert len(provider_json(sent['messages'])) <= MAX_CONTEXT_BYTES
    assert prompt_bound(provider_json(sent))[0] <= MAX_PROMPT_TOKENS
    assert sent['max_tokens'] >= MIN_OUTPUT_TOKENS
    assert metrics['reservation'] + metrics['runtime_allowance']['finish_reserve_tokens'] <= 37500 - spent
    assert python_broker.budget.used['http'] == 0 and python_broker.budget.used['tokens'] == spent + 1900
    # A real host validator releases its reserved slot before the next summary.
    python_broker.runtime_policy.validation_reserves.pop(spec.id)
    python_broker.runtime_policy.repairing.add(spec.id)
    mock_provider(monkeypatch, python_broker, response)
    python_broker.completion(body)
    assert python_broker.calls == 2 and not python_broker.budget.blocked


def test_observed_access_admission_preserves_summary_and_repair(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.specs[2]
    python_broker.tasks.active_spec = spec
    policy = python_broker.runtime_policy
    ticket = policy.budget.reserve("tokens", 20638)
    policy.budget.settle(ticket, 20638, runtime_phase="access")
    policy.calls[spec.id] = 10
    info = policy.prepare(spec, 8167)
    assert info["finalizing"] and policy.allowed_tools(spec) == {SUMMARY_TOOL}
    assert info["remaining_phase_tokens"] == 16862
    response = {
        "choices": [{"message": {"content": "{}"}}],
        "usage": {"prompt_tokens": 1700, "completion_tokens": 100, "total_tokens": 1800}}
    mock_provider(monkeypatch, python_broker, response)
    body = {"model": "model", "messages": [{"role": "user", "content": "x" * 3000}],
            "tools": solver.tool_schemas(spec), "max_tokens": 4096}
    python_broker.completion(body)
    policy.repairing.add(spec.id)
    mock_provider(monkeypatch, python_broker, response)
    python_broker.completion(body)
    assert policy.calls[spec.id] == 12 and python_broker.calls == 2
    assert policy.budget.used["tokens"] == 24238
    assert policy.budget.used["http"] == 0 and not policy.budget.blocked


def test_python_closes_before_call_or_tool_limit(python_broker):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.specs[2]
    policy = python_broker.runtime_policy
    policy.tool_calls[spec.id] = 13
    assert policy.prepare(spec, 5000)["finalizing"]
    assert {t["function"]["name"] for t in solver.tool_schemas(spec)} == {SUMMARY_TOOL}
    assert policy.validation_reserves[spec.id] == 1
    policy.host_finalizing.add(spec.id)
    policy.check_tool(spec, "hunter_run_web_loop")
    assert policy.tool_calls[spec.id] == 14 and policy.tool_allowance(spec) == 0
    policy.host_finalizing.discard(spec.id)
    with pytest.raises(BudgetError, match="phase_tool"):
        policy.check_tool(spec, "hunter_run_web_loop")


def test_report_reserves_one_host_checkpoint_without_increasing_limits(python_broker):
    solver = PythonSolver(python_broker, model='model')
    spec = python_broker.tasks.specs[3]
    policy = python_broker.runtime_policy
    assert spec.max_calls == PHASE_CALL_LIMITS['report'] == 6
    assert policy.tool_allowance(spec) == 5 and policy.checkpoint_reserves[spec.id] == 1
    for _ in range(5):
        policy.check_tool(spec, 'read_artifact')
    assert policy.prepare(spec, 5000)['finalizing']
    assert {t['function']['name'] for t in solver.tool_schemas(spec)} == {SUMMARY_TOOL}
    with pytest.raises(ValueError, match='reserved'):
        policy.check_tool(spec, 'read_artifact')
    policy.host_finalizing.add(spec.id)
    policy.check_tool(spec, 'kali-tools_ledger_checkpoint')
    policy.host_finalizing.discard(spec.id)
    assert policy.tool_calls[spec.id] == 6 and policy.tool_allowance(spec) == 0
    assert not policy.host_finalizing


@pytest.mark.parametrize('outcome', ['success', 'denied', 'failed', 'budget'])
def test_seal_restores_model_limits_and_preserves_checkpoint_failures(python_broker, monkeypatch, outcome):
    import hypothesis_ledger as hypotheses
    solver = PythonSolver(python_broker, model='model')
    spec = python_broker.tasks.specs[3]
    python_broker.tasks.active_spec = spec
    python_broker.runtime_policy.finalizing.add(spec.id)
    python_broker.runtime_policy.tool_calls[spec.id] = 5
    monkeypatch.setattr(hypotheses, 'load_ledger', lambda _path: {'hypotheses': [], 'target': spec.target})
    monkeypatch.setattr(hypotheses, 'save_ledger', lambda *_args: None)
    monkeypatch.setattr(python_broker.tasks, 'read_summary', lambda _spec: {'findings': []})
    observed = []
    def invoke(name, args):
        observed.append((name, args))
        python_broker.runtime_policy.check_tool(spec, name)
        assert spec.id in python_broker.runtime_policy.host_finalizing
        if outcome == 'denied':
            raise ValueError('private executor text must not escape')
        if outcome == 'budget':
            raise BudgetError('wall clock budget exhausted')
        return python_broker.view({'sealed': outcome == 'success', 'check_exit': 0 if outcome == 'success' else 2})
    monkeypatch.setattr(python_broker, 'invoke', invoke)
    if outcome == 'success':
        assert python_broker.seal()['result']['sealed']
    else:
        kind, code = (BudgetError, 'wall clock') if outcome == 'budget' else (
            ClosureError, 'closure_checkpoint_denied' if outcome == 'denied' else 'closure_checkpoint_failed')
        with pytest.raises(kind) as failure:
            python_broker.seal()
        if kind is ClosureError:
            assert failure.value.code == code
            assert 'private executor' not in str(failure.value)
            if outcome == 'failed':
                assert failure.value.evidence_ref['path'] in python_broker.references
    assert observed == [('kali-tools_ledger_checkpoint', {'workdir': str(python_broker.workdir), 'seal': True})]
    assert python_broker.runtime_policy.tool_calls[spec.id] == 6
    assert not python_broker.runtime_policy.host_finalizing and not python_broker.runtime_policy.checkpoint_reserves
    assert {t['function']['name'] for t in solver.tool_schemas(spec)} == {SUMMARY_TOOL}
    assert python_broker.calls == 0 and python_broker.budget.used['http'] == 0


def test_exhausted_checkpoint_slot_stops_before_ledger_changes(python_broker, monkeypatch):
    import hypothesis_ledger as hypotheses
    PythonSolver(python_broker, model='model')
    spec = python_broker.tasks.specs[3]
    python_broker.tasks.active_spec = spec
    python_broker.runtime_policy.tool_calls[spec.id] = 6
    monkeypatch.setattr(hypotheses, 'load_ledger', lambda *_args: pytest.fail('must stop before ledger changes'))
    with pytest.raises(BudgetError, match='closure_tool_budget_exhausted'):
        python_broker.seal()
    assert not python_broker.runtime_policy.host_finalizing


@pytest.mark.parametrize("path", ["../private/state", ".env", "/etc/passwd"])
def test_artifact_reads_refuse_unregistered_paths(python_broker, path):
    with pytest.raises(ValueError, match="artifact"):
        python_broker.invoke("read_artifact", {"path": path})


def test_context_is_fresh_and_retains_only_four_results(python_broker):
    solver = PythonSolver(python_broker, model="model")
    for index in range(20):
        view = python_broker.view({"index": index, "body": "x" * 5000})
        python_broker.results.append({"spec_id": "recon-1", "tool": "kali-tools_curl_request", "arguments": {}, **view})
    context = solver.context(python_broker.tasks.active_spec)
    assert len(context["recent_results"]) == 4
    assert len(context["older_results"]) <= 8
    assert context["older_index_ref"]
    assert "host-only-sentinel" not in provider_json(context).decode()
    assert len(provider_json(context)) < 8000


def test_summary_uses_real_probes_and_downgrades_model_findings(python_broker):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.active_spec
    python_broker.invoke("kali-tools_curl_request", {"url": spec.target + "?q=demo"})
    summary = solver.compile_summary(spec, terminal(spec, findings=[{"verdict": "CONFIRMED", "validation_id": "invented"}]))
    assert not summary["findings"] and summary["hypotheses"][0]["validation_id"] == "invented"
    assert summary["route_probes"][0]["status"] == 200
    assert summary["evidence"] and not summary_feedback(summary, spec)["errors"]


def test_summary_feedback_reports_all_defects(python_broker):
    feedback = summary_feedback({"phase": "wrong", "target": "wrong", "status": "unknown", "evidence": {}, "findings": {}}, python_broker.tasks.active_spec)
    assert len(feedback["errors"]) >= 5
    assert feedback["repair_limit"] == 1 and not feedback["valid"]


def test_one_reserved_summary_repair_consumes_no_tool_calls(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.active_spec
    seen = []
    def complete(body):
        context = json.loads(body["messages"][1]["content"])
        seen.append(context)
        submitted = terminal(spec, status="unknown") if len(seen) == 1 else terminal(spec)
        return {"choices": [{"message": {"content": json.dumps(submitted)}}]}
    monkeypatch.setattr(python_broker, "completion", complete)
    assert solver.phase(spec)["status"] == "done"
    assert seen[1]["summary_feedback"]["errors"]
    assert solver.repairs == {spec.id: 1} and not python_broker.runtime_policy.tool_calls


def test_second_invalid_summary_stops_without_probe_retries(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    monkeypatch.setattr(python_broker, "completion", lambda _body: {"choices": [{"message": {"content": "invalid"}}]})
    with pytest.raises(ValueError, match="repair exhausted"):
        solver.phase(python_broker.tasks.active_spec)
    assert solver.repairs == {"recon-1": 1} and not python_broker.executor.tasks


def test_missing_provider_usage_retains_reservation_and_blocks(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.active_spec
    mock_provider(monkeypatch, python_broker, {"choices": [{"message": {"content": "{}"}}]})
    with pytest.raises(BudgetError):
        python_broker.completion({"model": "model", "messages": [{"role": "user", "content": "owned task"}], "tools": solver.tool_schemas(spec)})
    assert python_broker.budget.used["tokens"] > 0 and python_broker.budget.blocked
    assert python_broker.budget.snapshot()["reserved"]["tokens"] == 0


def test_paid_repair_uses_shared_accounting_and_fresh_feedback(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    original = python_broker.completion
    spec = python_broker.tasks.active_spec
    bodies = []
    def completion(body):
        bodies.append(body)
        submitted = terminal(spec, status="unknown") if len(bodies) == 1 else terminal(spec)
        mock_provider(monkeypatch, python_broker, {"choices": [{"message": {"content": json.dumps(submitted)}}],
                      "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
        return original(body)
    monkeypatch.setattr(python_broker, "completion", completion)
    assert solver.phase(spec)["status"] == "done"
    assert python_broker.calls == 2 and python_broker.budget.used["tokens"] == 220
    assert not python_broker.executor.tasks
    assert json.loads(bodies[1]["messages"][1]["content"])["summary_feedback"]["errors"]
    assert all(len(body["messages"]) == 2 for body in bodies)
    assert python_broker.runtime_policy.finalization_calls[spec.id] == 1


def test_policy_denials_stop_chain_before_any_executor_or_later_phase(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    python_broker.engine.validate_tool_invocation = lambda *_a, **_kw: {"allowed": False, "reason": "scope denied"}
    def completion(_body):
        return {"choices": [{"message": {"tool_calls": [{"function": {"name": "kali-tools_curl_request",
                "arguments": json.dumps({"url": "https://outside.invalid/"})}}]}}]}
    monkeypatch.setattr(python_broker, "completion", completion)
    result = solver.run()
    assert result["status"] == "python_failed" and result["completed_phases"] == []
    assert not python_broker.executor.tasks and python_broker.budget.used["http"] == 0
    assert python_broker.runtime_policy.consecutive_failures["recon-1"] == 2
    assert json.loads((python_broker.workdir / "summaries/recon-1.json").read_bytes())["status"] == "blocked"


def test_access_cannot_start_without_host_handoff(python_broker):
    solver = PythonSolver(python_broker, model="model")
    with pytest.raises(ValueError, match="host handoff missing"):
        solver.phase(python_broker.tasks.specs[2])
    assert python_broker.calls == 0


def session_check_setup(broker):
    spec = broker.tasks.specs[2]
    broker.tasks.active_spec = spec
    broker.tasks.bindings = {
        "admin-a": {"target": spec.target, "role": "admin", "private_metadata": "must-not-enter-context"},
        "member-a": {"target": spec.target, "role": "member"},
        "foreign": {"target": "https://outside.invalid/", "role": "member"}}
    broker.catalog["validator"] = [{"name": "session_vault_check", "inputSchema": {
        "type": "object", "properties": {"target": {"type": "string"},
            "identity": {"type": "string", "default": "anon"}}, "required": ["target"]}}]
    original_capability = broker.engine.tool_capability
    broker.engine.tool_capability = lambda name: ({"network": True} if name == "validator_session_vault_check"
                                                  else original_capability(name))
    return spec


def test_session_check_schema_and_context_use_registered_target(python_broker):
    spec = session_check_setup(python_broker)
    original_catalog = provider_json(python_broker.catalog)
    dump(python_broker.workdir / "handoff.json", {"identities": ["opaque"], "padding": "x" * 5000})
    solver = PythonSolver(python_broker, model="model")
    schema = next(t["function"]["parameters"] for t in solver.tool_schemas(spec)
                  if t["function"]["name"] == "validator_session_vault_check")
    assert schema["properties"]["target"].get("enum") == [spec.target]
    assert schema["properties"]["identity"]["enum"] == ["admin-a", "member-a"]
    assert set(schema["required"]) == {"target", "identity"}
    context = solver.context(spec)
    assert context["handoff"] is None  # Unsealed files cannot manufacture a dependency handoff.
    assert context["registered_session_checks"] == [
        {"target": spec.target, "identity": "admin-a"}, {"target": spec.target, "identity": "member-a"}]
    assert "must-not-enter-context" not in provider_json(context).decode()
    assert provider_json(python_broker.catalog) == original_catalog


def test_session_check_rejects_endpoint_lookup_before_execution(python_broker):
    spec = session_check_setup(python_broker)
    args = {"target": urljoin(spec.target, "admin/users"), "identity": "admin-a"}
    original = dict(args)
    with pytest.raises(ValueError, match="session binding mismatch"):
        python_broker.invoke("validator_session_vault_check", args)
    assert args == original
    assert not python_broker.executor.tasks and not python_broker.tools
    assert python_broker.budget.used["http"] == 0 and not python_broker.budget.pending
    assert python_broker.runtime_policy.consecutive_failures[spec.id] == 1
    assert python_broker.runtime_policy.tool_calls[spec.id] == 1


@pytest.mark.parametrize("target,identity", [
    ("http://127.0.0.1:18765", "admin-a"),
    ("http://127.0.0.1:18765/?q=other", "admin-a"),
    ("http://127.0.0.1:18766/", "admin-a"),
    ("https://outside.invalid/", "admin-a"),
    ("http://127.0.0.1:18765/", "foreign"),
    ("http://127.0.0.1:18765/", "unknown"),
    ("http://127.0.0.1:18765/", None)])
def test_session_check_cannot_widen_registered_binding(python_broker, target, identity):
    session_check_setup(python_broker)
    with pytest.raises(ValueError, match="session binding mismatch"):
        python_broker.invoke("validator_session_vault_check", {"target": target, "identity": identity})
    assert not python_broker.executor.tasks and not python_broker.budget.used["http"]


def test_registered_session_check_reaches_executor_unchanged(python_broker):
    spec = session_check_setup(python_broker)
    args = {"target": spec.target, "identity": "admin-a"}
    python_broker.invoke("validator_session_vault_check", args)
    assert json.loads(python_broker.executor.tasks[-1]["args_json"]) == args
    assert python_broker.results[-1]["arguments"] == args
    assert python_broker.budget.used["http"] == 1
    assert python_broker.runtime_policy.consecutive_failures[spec.id] == 0


def test_no_registered_session_check_is_advertised_without_bindings(python_broker):
    spec = session_check_setup(python_broker)
    python_broker.tasks.bindings = {}
    solver = PythonSolver(python_broker, model="model")
    assert "validator_session_vault_check" not in {t["function"]["name"] for t in solver.tool_schemas(spec)}
    with pytest.raises(ValueError, match="session binding mismatch"):
        python_broker.invoke("validator_session_vault_check", {"target": spec.target, "identity": "anon"})
    assert not python_broker.executor.tasks


def test_wrong_session_target_recovers_with_safe_feedback_and_accounting(python_broker, monkeypatch):
    spec = session_check_setup(python_broker)
    dump(python_broker.workdir / "handoff.json", {})
    monkeypatch.setattr(python_broker, "_check_handoff", lambda _spec: None)
    solver = PythonSolver(python_broker, model="model")
    original = python_broker.completion
    bodies = []
    def completion(body):
        bodies.append(body)
        if len(bodies) < 3:
            args = {"target": urljoin(spec.target, "admin/users") if len(bodies) == 1 else spec.target, "identity": "admin-a"}
            message = {"tool_calls": [{"function": {"name": "validator_session_vault_check", "arguments": json.dumps(args)}}]}
        else:
            message = {"content": json.dumps(terminal(spec, status="partial", steps=[
                {"id": step.id, "status": "not_tested"} for step in spec.steps]))}
        mock_provider(monkeypatch, python_broker, {"choices": [{"message": message}],
                      "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
        return original(body)
    monkeypatch.setattr(python_broker, "completion", completion)
    summary = solver.phase(spec)
    context = json.loads(bodies[1]["messages"][1]["content"])
    assert not context["recent_results"]
    assert context["protocol_feedback"]["reason_code"] == "tool_arguments_schema_invalid"
    assert context["registered_session_checks"] == [
        {"target": spec.target, "identity": "admin-a"}, {"target": spec.target, "identity": "member-a"}]
    assert "must-not-enter-context" not in provider_json(bodies).decode()
    assert python_broker.calls == 3 and python_broker.budget.used == {"tokens": 330, "http": 1}
    assert len(python_broker.executor.tasks) == 1
    assert python_broker.runtime_policy.tool_calls[spec.id] == 1
    assert python_broker.runtime_policy.consecutive_failures[spec.id] == 0
    assert summary["status"] == "partial" and not summary["findings"] and not solver.repairs
    assert solver.protocol_repairs == {spec.id: 1}


def test_repeated_session_target_mismatch_respects_failure_brake(python_broker):
    spec = session_check_setup(python_broker)
    for _ in range(2):
        with pytest.raises(ValueError, match="session binding mismatch"):
            python_broker.invoke("validator_session_vault_check", {"target": spec.target + "admin/users", "identity": "admin-a"})
    with pytest.raises(BudgetError, match="consecutive_tool_failure_limit"):
        python_broker.invoke("validator_session_vault_check", {"target": spec.target, "identity": "admin-a"})
    assert python_broker.runtime_policy.tool_calls[spec.id] == 2
    assert not python_broker.executor.tasks and not python_broker.budget.used["http"]


def test_crawl_reference_binding_keeps_credentials_out_of_schema_and_arguments(python_broker):
    spec = handoff_setup(python_broker)
    python_broker.catalog["kali-tools"].append({"name": "crawl_web_surface", "inputSchema": {
        "type": "object", "properties": {name: {"type": "string"} for name in
         ("target", "cookie", "headers", "identity", "session_target")}, "required": ["target"]}})
    solver = PythonSolver(python_broker, model="model")
    schema = next(row["function"]["parameters"] for row in solver.tool_schemas(spec)
                  if row["function"]["name"] == "kali-tools_crawl_web_surface")
    assert not {"cookie", "headers"} & schema["properties"].keys()
    assert schema["properties"]["session_target"]["enum"] == [spec.target]
    args = {"target": spec.target, "max_pages": 2}
    python_broker.engine.tool_capability = lambda _tool: {"network": True}
    python_broker.invoke("kali-tools_crawl_web_surface", args)
    emitted = json.loads(python_broker.executor.tasks[-1]["args_json"])
    assert emitted == {**args, "identity": "member-a", "session_target": spec.target}
    assert "identity" not in args


@pytest.mark.parametrize("args", [
    {"target": "https://outside.invalid/"},
    {"target": "http://127.0.0.1:18765/", "identity": "unknown"},
    {"target": "http://127.0.0.1:18765/", "session_target": "http://127.0.0.1:18765/notes"},
    {"target": "http://127.0.0.1:18765/", "cookie": "sid=raw"}])
def test_crawl_binding_denial_is_metered_without_egress(python_broker, args):
    spec = handoff_setup(python_broker)
    with pytest.raises(ValueError, match="session binding"):
        python_broker.invoke("kali-tools_crawl_web_surface", args)
    assert not python_broker.executor.tasks and not python_broker.budget.used["http"]
    assert python_broker.runtime_policy.tool_calls[spec.id] == 1


def test_coverage_missing_target_is_bound_but_explicit_mismatch_is_rejected(python_broker, monkeypatch):
    spec = python_broker.tasks.specs[3]
    python_broker.tasks.active_spec = spec
    args = {"campaign_id": 0}
    def execute(self, task):
        self.tasks.append(task)
        return {"actual_request_cost": 0, "result": {"output": {"ok": True}}}
    monkeypatch.setattr(type(python_broker.executor), "__call__", execute)
    python_broker.invoke("hunter_coverage_report", args)
    assert json.loads(python_broker.executor.tasks[-1]["args_json"])["target"] == spec.target
    assert args == {"campaign_id": 0}
    count = len(python_broker.executor.tasks)
    with pytest.raises(ValueError, match="coverage target mismatch"):
        python_broker.invoke("hunter_coverage_report", {"target": "https://outside.invalid/"})
    assert len(python_broker.executor.tasks) == count


def test_model_done_cannot_replace_validator_evidence_or_not_tested_reasons(python_broker):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.specs[2]
    summary = solver.compile_summary(spec, terminal(spec, findings=[{"validation_id": "invented", "verdict": "CONFIRMED"}]))
    assert summary["status"] == "partial" and not summary["validation_outcomes"] and not summary["findings"]
    assert summary["steps"][0]["status"] == "not_tested"
    assert len(summary["not_tested_reasons"]) == 9


def handoff_setup(broker):
    session_check_setup(broker)
    spec = broker.tasks.specs[1]
    broker.tasks.active_spec = spec
    broker.tasks.bindings = {identity: {"target": spec.target,
        "role": "admin" if identity == "admin-a" else "member", "test_data_only": True,
        "owned_objects_private": True} for identity in ("member-a", "member-b", "admin-a")}
    return spec


def test_enum_reserves_checks_and_handoff_without_increasing_call_ceiling(python_broker, monkeypatch):
    spec = handoff_setup(python_broker)
    solver = PythonSolver(python_broker, model="model")
    policy = python_broker.runtime_policy
    assert policy.handoff_reserves[spec.id] == 4 and policy.tool_allowance(spec) == 12
    policy.tool_calls[spec.id] = 12
    with pytest.raises(ValueError, match="reserved for host handoff"):
        policy.check_tool(spec, "kali-tools_curl_request")
    assert {t["function"]["name"] for t in solver.tool_schemas(spec)} == {SUMMARY_TOOL}
    context = solver.context(spec)
    assert context["remaining_tool_calls"] == 0 and context["reserved_handoff_tool_calls"] == 4
    seen = []
    def invoke(tool, args):
        policy.check_tool(spec, tool)
        seen.append((tool, args))
        if tool == "validator_session_vault_check":
            return python_broker.view({"status": "fresh"})
        assert len(seen) == 4
        python_broker.handoffs["access"] = {}
        dump(python_broker.workdir / "handoff-access.json", {"identities": [args["session_bindings_json"]]})
        return python_broker.view({"ok": True})
    monkeypatch.setattr(python_broker, "invoke", invoke)
    python_broker.handoff()
    assert [tool for tool, _ in seen] == ["validator_session_vault_check"] * 3 + ["kali-tools_ledger_prepare_handoff"]
    assert policy.tool_calls[spec.id] == spec.max_calls == 16
    assert not policy.host_finalizing
    with pytest.raises(BudgetError, match="phase_tool_budget_exhausted"):
        policy.check_tool(spec, "kali-tools_curl_request")


@pytest.mark.parametrize("output", [
    {"status": "expired"}, {"status": "missing"}, {"status": "blocked"},
    {"status": "rate_limited"}, {"status": "stale"}, {"execution_failed": True},
    {"status": "fresh", "error": "check failed"}])
def test_handoff_stops_on_first_failed_refresh_with_evidence(python_broker, monkeypatch, output):
    handoff_setup(python_broker)
    monkeypatch.setattr(type(python_broker.executor), "__call__", lambda *_a: {
        "actual_request_cost": 1, "result": {"output": output}})
    with pytest.raises(ValueError) as caught:
        python_broker.handoff()
    assert caught.value.code == "handoff_session_refresh_failed"
    ref = caught.value.evidence_ref
    assert json.loads((python_broker.workdir / ref["path"]).read_text()) == output
    assert len(python_broker.results) == 1 and python_broker.results[0]["tool"] == "validator_session_vault_check"
    assert not python_broker.handoffs and not python_broker.runtime_policy.host_finalizing
    assert not (python_broker.workdir / "handoff.json").exists()
    assert python_broker.budget.used["http"] == 1 and not python_broker.budget.pending


def test_handoff_prechecks_remaining_tool_budget_before_refresh(python_broker):
    spec = handoff_setup(python_broker)
    python_broker.runtime_policy.tool_calls[spec.id] = 13
    with pytest.raises(BudgetError, match="handoff_tool_budget_exhausted"):
        python_broker.handoff()
    assert not python_broker.executor.tasks and not python_broker.budget.used["http"]
    assert not python_broker.runtime_policy.host_finalizing


def test_handoff_policy_denial_has_safe_code_and_no_execution(python_broker):
    handoff_setup(python_broker)
    python_broker.engine.validate_tool_invocation = lambda *_a, **_kw: {"allowed": False, "reason": "private-policy-detail"}
    with pytest.raises(ValueError) as caught:
        python_broker.handoff()
    assert caught.value.code == "handoff_session_check_denied"
    assert "private-policy-detail" not in str(caught.value)
    assert not python_broker.executor.tasks and not python_broker.budget.used["http"]
    assert not python_broker.runtime_policy.host_finalizing


def test_failed_handoff_keeps_specific_reason_and_archived_tool_reference(python_broker, monkeypatch):
    handoff_setup(python_broker)
    solver = PythonSolver(python_broker, model="model")
    def phase(spec):
        python_broker.tasks.active_spec = spec
        summary = solver.compile_summary(spec, terminal(spec))
        if spec.phase == "enum":
            summary["surface"]["routes"] = [spec.target]
        python_broker.tasks.summary_path(spec).parent.mkdir(parents=True, exist_ok=True)
        dump(python_broker.tasks.summary_path(spec), summary)
        solver.summaries[spec.id] = summary
        return summary
    monkeypatch.setattr(solver, "phase", phase)
    monkeypatch.setattr(type(python_broker.executor), "__call__", lambda *_a: {
        "actual_request_cost": 1, "result": {"output": {"status": "expired"}}})
    result = solver.run()
    assert result["stop_reason"] == "handoff_session_refresh_failed" and result["failure_phase"] == "enum-2"
    assert result["completed_phases"] == ["recon-1", "enum-2"]
    failure = json.loads((python_broker.private / "workflow-failure.json").read_text())
    assert failure["failed_tool_ref"] == result["failed_tool_ref"]
    assert failure["stop_reason"] == result["stop_reason"]
    assert "host-only-sentinel" not in provider_json(failure).decode()
    assert not (python_broker.workdir / "handoff.json").exists()


def test_observed_object_routes_get_formats_without_ownership(python_broker):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.specs[1]
    view = python_broker.view({"routes": ["/objects/123"], "params": ["id"]})
    python_broker.results.append({"spec_id": spec.id, "tool": "browser_browser_extract_links", "arguments": {}, **view})
    summary = solver.compile_summary(spec, terminal(spec))
    assert not summary_feedback(summary, spec)["errors"]
    assert summary["surface"]["id_formats"] == [{"family": "objects", "format": "int", "example": "123"}]
    assert "own_ids" not in summary and not summary["findings"]


def test_degradation_stops_after_recording_the_first_response(python_broker, monkeypatch):
    monkeypatch.setattr(type(python_broker.executor), "__call__", lambda _self, _task: {
        "actual_request_cost": 1, "result": {"output": {"ok": False, "status": 503}}})
    with pytest.raises(BudgetError, match="service_degradation"):
        python_broker.invoke("kali-tools_curl_request", {"url": python_broker.tasks.active_spec.target})
    assert python_broker.budget.used["http"] == 1 and len(python_broker.tools) == 1
    assert python_broker.results[-1]["result"]["status"] == 503
    assert python_broker.stop_reason == "service_degradation"


def test_artifact_read_respects_shared_deadline(python_broker):
    ref = python_broker.archive({"data": "owned"})
    python_broker.budget.deadline = python_broker.budget.clock() - 1
    with pytest.raises(BudgetError, match="wall clock"):
        python_broker.invoke("read_artifact", {"path": ref["path"]})
    assert not python_broker.results and not python_broker.budget.pending


def test_python_contract_and_native_contract_are_separate(baseline):
    reference = preflight.baseline_reference(baseline)
    native = preflight.native_contract(reference, {"planner": "owned/model", "worker": "owned/model"}, 150000)
    python = preflight.native_contract(reference, native["models"], 150000, solver_mode="python_loop")
    assert native["solver"] == "native_opencode_planner_worker" and "solver_mode" not in native
    assert python["solver"] == "python-workflow-v1" and python["limits"]["seconds_per_seed"] == 900
    assert python["limits"]["http_requests_per_seed"] == 300
    assert "native_task_delegation_events" not in python["required_evidence"]


def partial_access(solver):
    spec = solver.broker.tasks.specs[2]
    summary = solver.compile_summary(spec, terminal(spec, status="partial", steps=[
        {"id": step.id, "status": "not_tested"} for step in spec.steps]))
    assert summary_feedback(summary, spec)["valid"]
    solver.summaries[spec.id] = summary


@pytest.mark.parametrize("submitted_status,expected", [("partial", "partial"), ("done", "partial"), ("blocked", "blocked"), ("failed", "failed")])
def test_report_preserves_unfinished_access_without_promoting_coverage(python_broker, submitted_status, expected):
    solver = PythonSolver(python_broker, model="model")
    partial_access(solver)
    spec = python_broker.tasks.specs[3]
    submitted = {"status": submitted_status, "next": "Unperformed access probes remain NOT TESTED.",
                 "steps": [{"id": "review-evidence", "status": "done"}]}
    summary = solver.compile_summary(spec, submitted)
    assert summary_feedback(summary, spec)["valid"]
    assert summary["status"] == expected
    assert summary["steps"][-1] == {"id": REPORT_CARRYOVER_STEP, "status": "not_tested"}
    assert len(summary["unfinished_work"]) == 2 and not summary["findings"]


def test_observed_partial_report_completes_in_one_metered_turn(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    partial_access(solver)
    spec = python_broker.tasks.specs[3]
    dump(python_broker.workdir / "handoff.json", {})
    mock_provider(monkeypatch, python_broker, {"choices": [{"message": {"content": json.dumps({
        "status": "partial", "next": "Access remains NOT TESTED.", "steps": [{"id": "review-evidence", "status": "done"}]})}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
    summary = solver.phase(spec)
    assert summary["status"] == "partial" and summary_feedback(summary, spec)["valid"]
    assert python_broker.calls == 1 and python_broker.budget.used["tokens"] == 110
    assert not solver.repairs and not python_broker.executor.tasks
    schema = next(tool["function"]["parameters"] for tool in solver.tool_schemas(spec)
                  if tool["function"]["name"] == SUMMARY_TOOL)
    assert schema["properties"]["steps"]["items"]["properties"]["id"]["enum"] == ["review-evidence"]


def test_browser_native_link_fields_survive_compilation_without_probe_claims(python_broker):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.specs[1]
    value = {"internal_links": ["/notes", "/search?q=demo", "/item?id=1", "https://outside.invalid/?foreign=1"],
             "urls_with_params": ["/item?id=1"], "form_actions": ["/submit?form=contact"], "js_files": ["/app.js"],
             "external_links": ["https://outside.invalid/"]}
    view = python_broker.view(value)
    python_broker.results.append({"spec_id": spec.id, "tool": "browser_browser_extract_links", "arguments": {}, **view})
    summary = solver.compile_summary(spec, terminal(spec))
    assert summary_feedback(summary, spec)["valid"]
    assert set(summary["surface"]["routes"]) == {urljoin(spec.target, route) for route in
        ("/notes", "/search?q=demo", "/item?id=1", "/submit?form=contact", "/app.js")}
    assert set(summary["surface"]["params"]) == {"q", "id", "form"}
    assert not summary["route_probes"] and not summary["tested_parameters"] and not python_broker.executor.tasks


def recon_observation(solver, url=None):
    broker = solver.broker
    spec = broker.tasks.specs[0]
    broker.tasks.active_spec = spec
    broker.invoke("kali-tools_curl_request", {"url": url or spec.target})
    summary = solver.compile_summary(spec, terminal(spec))
    assert summary_feedback(summary, spec)["valid"]
    solver.summaries[spec.id] = summary
    return broker.results[-1]


@pytest.mark.parametrize("step_status", ["blocked", "not_tested"])
def test_failed_enum_crawl_keeps_validated_recon_observation(python_broker, step_status):
    solver = PythonSolver(python_broker, model="model")
    prior = recon_observation(solver)
    spec = python_broker.tasks.specs[1]
    failure = python_broker.view({"ok": False, "error": "crawl stopped: http_401"})
    python_broker.results.append({"spec_id": spec.id, "tool": "kali-tools_crawl_web_surface", "arguments": {"target": spec.target}, **failure})
    summary = solver.compile_summary(spec, terminal(spec, status="partial", steps=[{"id": "discover-surface", "status": step_status}]))
    assert summary_feedback(summary, spec)["valid"]
    assert summary["surface"]["routes"] == [spec.target]
    assert summary["surface"]["params"] == []
    assert summary["status"] == "partial" and summary["steps"][0]["status"] == step_status
    assert not summary["route_probes"] and not summary["tested_parameters"] and not summary["findings"]
    inherited = summary["inherited_http_observations"]
    assert len(inherited) == 1 and inherited[0]["source_spec_id"] == "recon-1"
    assert inherited[0]["artifact"] == prior["content_ref"]["path"] and inherited[0]["status"] == 200
    assert any(e["kind"] == "prior_phase_http_observation" and e["source_spec_id"] == "recon-1" for e in summary["evidence"])


def test_observed_empty_enum_failure_compiles_in_one_metered_turn(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    recon_observation(solver)
    spec = python_broker.tasks.specs[1]
    view = python_broker.view({"ok": False, "error": "crawl stopped: http_401"})
    python_broker.results.append({"spec_id": spec.id, "tool": "kali-tools_crawl_web_surface", "arguments": {}, **view})
    mock_provider(monkeypatch, python_broker, {"choices": [{"message": {"content": json.dumps(terminal(spec,
        status="partial", steps=[{"id": "discover-surface", "status": "blocked"}]))}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
    summary = solver.phase(spec)
    assert summary_feedback(summary, spec)["valid"] and summary["surface"]["routes"] == [spec.target]
    assert python_broker.calls == 1 and python_broker.budget.used["tokens"] == 110
    assert not solver.repairs and not python_broker.runtime_policy.repairing
    assert not list((python_broker.workdir / "context-archive").glob("invalid-summary-*.json"))


@pytest.mark.parametrize("change", ["contents", "reference", "symlink"])
def test_inherited_http_observation_requires_unchanged_host_archive(python_broker, tmp_path, change):
    solver = PythonSolver(python_broker, model="model")
    prior = recon_observation(solver)
    path = python_broker.workdir / prior["content_ref"]["path"]
    if change == "contents":
        path.write_text('{"status":200,"ok":true}')
    elif change == "reference":
        prior["content_ref"]["sha256"] = "0" * 64
    else:
        target = tmp_path / "replacement.json"
        target.write_text('{}')
        path.unlink()
        path.symlink_to(target)
    spec = python_broker.tasks.specs[1]
    with pytest.raises(ValueError, match="prior phase evidence changed"):
        solver.compile_summary(spec, terminal(spec))


@pytest.mark.parametrize("field,value", [("status", "unknown"), ("target", "https://outside.invalid/")])
def test_unvalidated_dependency_cannot_seed_enum_inventory(python_broker, field, value):
    solver = PythonSolver(python_broker, model="model")
    recon_observation(solver)
    solver.summaries["recon-1"][field] = value
    spec = python_broker.tasks.specs[1]
    with pytest.raises(ValueError, match="prior phase summary invalid"):
        solver.compile_summary(spec, terminal(spec))


def test_inherited_query_names_are_discovery_without_enum_test_or_ownership(python_broker):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.specs[1]
    recon_observation(solver, spec.target + "?q=demo")
    summary = solver.compile_summary(spec, terminal(spec))
    assert summary["surface"]["params"] == ["q"]
    assert not summary["route_probes"] and not summary["tested_parameters"] and not summary["findings"]
    assert "own_ids" not in summary
    assert summary["surface"]["docs_probes"][0]["source_spec_id"] == "recon-1"


def test_prior_foreign_request_cannot_widen_current_inventory(python_broker):
    solver = PythonSolver(python_broker, model="model")
    recon_observation(solver, "https://outside.invalid/?foreign=1")
    spec = python_broker.tasks.specs[1]
    summary = solver.compile_summary(spec, terminal(spec, status="blocked", steps=[{"id": "discover-surface", "status": "blocked"}]))
    assert not summary["inherited_http_observations"]
    assert not summary["surface"]["routes"] and not summary["surface"]["params"]


@pytest.mark.parametrize("result,code", [
    ({"ok": False, "error": "crawl stopped: http_401"}, "enum_surface_unavailable"),
    ({"internal_links": ["/openapi.json"]}, "enum_surface_incomplete")])
def test_host_inventory_defects_do_not_consume_model_summary_repair(python_broker, monkeypatch, result, code):
    solver = PythonSolver(python_broker, model="model")
    spec = python_broker.tasks.specs[1]
    view = python_broker.view(result)
    python_broker.results.append({"spec_id": spec.id, "tool": "kali-tools_crawl_web_surface", "arguments": {}, **view})
    mock_provider(monkeypatch, python_broker, {"choices": [{"message": {"content": json.dumps(terminal(spec,
        status="partial", steps=[{"id": "discover-surface", "status": "blocked"}]))}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
    with pytest.raises(ValueError) as caught:
        solver.phase(spec)
    assert caught.value.code == code and caught.value.errors and caught.value.summary_ref
    assert python_broker.calls == 1 and not solver.repairs and not python_broker.executor.tasks
    assert len(list((python_broker.workdir / "context-archive").glob("invalid-summary-*.json"))) == 1


def test_terminal_summary_failure_retains_both_drafts_and_safe_reason(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    original = python_broker.completion
    attempts = []
    def completion(body):
        attempts.append(body)
        draft = terminal(python_broker.tasks.active_spec, status="invalid-first" if len(attempts) == 1 else "invalid-second")
        mock_provider(monkeypatch, python_broker, {"choices": [{"message": {"content": json.dumps(draft)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
        return original(body)
    monkeypatch.setattr(python_broker, "completion", completion)
    result = solver.run()
    assert result["stop_reason"] == "summary_repair_exhausted" and result["failure_phase"] == "recon-1"
    assert result["summary_errors"] and result["failed_summary_ref"]
    assert len(list((python_broker.workdir / "context-archive").glob("invalid-summary-*.json"))) == 2
    saved = json.loads((python_broker.private / "workflow-failure.json").read_bytes())
    assert saved["stop_reason"] == result["stop_reason"] and "host-only-sentinel" not in json.dumps(saved)
    assert python_broker.calls == 2 and python_broker.budget.used["tokens"] == 220
    assert not python_broker.executor.tasks


def test_probe_requested_during_summary_repair_has_a_specific_failure(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    attempts = []
    def completion(_body):
        attempts.append(True)
        if len(attempts) == 1:
            return {"choices": [{"message": {"content": json.dumps(terminal(python_broker.tasks.active_spec, status="invalid"))}}]}
        return {"choices": [{"message": {"tool_calls": [{"function": {"name": "kali-tools_curl_request", "arguments": "{}"}}]}}]}
    monkeypatch.setattr(python_broker, "completion", completion)
    result = solver.run()
    assert result["stop_reason"] == "tool_outside_advertised_phase_schema" and result["failure_phase"] == "recon-1"
    assert not python_broker.executor.tasks and not python_broker.budget.used["http"]


@pytest.mark.integration
@pytest.mark.parametrize("validation_mode", ["explicit", "early_summary", "artifact_read", "budget_finalization", "artifact_pages",
                                          "report_finalization", "report_slot"])
def test_four_phase_real_subprocess_signed_closure_and_tamper(monkeypatch, baseline, record_testsuite_property, validation_mode):
    """Only provider decisions are scripted; MCP/wire/signatures are production."""
    from evidence_trust import canonical_bytes, verify
    from full_agent_python_solver import PythonSolver
    from full_agent_python_broker import PythonBroker
    artifacts = output_root("full-agent-python-integration")
    artifacts.mkdir(parents=True, exist_ok=True)
    tmp_path = Path(tempfile.mkdtemp(prefix="run-", dir=artifacts))
    captured = []
    decisions = []
    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert body["stream"] is False
            assert len(body["messages"]) == 3 and all(row["role"] != "tool" for row in body["messages"])
            assert "host-only-test-key" not in json.dumps(body)
            context = json.loads(body["messages"][1]["content"])
            spec = context["task_spec"]
            decisions.append(spec["id"])
            base = spec["target"]
            results = context["recent_results"]
            names = {tool["function"]["name"] for tool in body["tools"]}
            assert SUMMARY_TOOL in names and not names & {"bash", "write", "edit", "task"}
            if spec["phase"] == "recon" and not results:
                name, args = "kali-tools_curl_request", {"url": base, "follow_redirects": False}
            elif spec["phase"] == "enum" and not results:
                # No raw credentials are supplied. The host binds member-a;
                # the second page (/notes) requires its registered session.
                name, args = "kali-tools_crawl_web_surface", {"target": base,
                                                           "max_pages": 40 if validation_mode == 'artifact_pages' else 2}
            elif spec["phase"] == "access" and decisions.count(spec["id"]) == 1 and validation_mode == "explicit":
                # Reproduce the live endpoint-as-vault-target error. The host
                # rejects the enum mismatch before invoking the vault tool.
                name, args = "validator_session_vault_check", {"target": urljoin(base, "admin/users"), "identity": "admin-a"}
            elif spec["phase"] == "access" and decisions.count(spec["id"]) == 2 and validation_mode == "explicit":
                assert not results
                assert context["protocol_feedback"]["reason_code"] == "tool_arguments_schema_invalid"
                schema = next(t["function"]["parameters"] for t in body["tools"]
                              if t["function"]["name"] == "validator_session_vault_check")
                check = next(row for row in context["registered_session_checks"] if row["identity"] == "admin-a")
                assert check["target"] == schema["properties"]["target"]["enum"][0] == base
                name, args = "validator_session_vault_check", check
            elif spec["phase"] == "access" and decisions.count(spec["id"]) == 3 and validation_mode == "explicit":
                assert results[-1]["result"]["status"] == "fresh"
                name, args = "validator_validate_open_redirect", {"target_url": urljoin(base, "go?next=/"), "param": "next"}
            elif (spec['phase'] == 'access' and validation_mode == 'artifact_pages'
                  and 'read_artifact' in names and not any(row['tool'] == 'hunter_run_web_loop' for row in results)
                  and (not results or results[-1]['result'].get('next_offset', 12000) < 12000)):
                offset = 0 if not results else results[-1]['result']['next_offset']
                if results:
                    assert len(results[-1]['result']['text']) == 3000
                    assert all('text' not in row['result'] for row in results[:-1] if row['tool'] == 'read_artifact')
                name, args = 'read_artifact', {'path': context.get('previous_summary', context.get('discovery'))['content_ref']['path'], 'offset': offset}
            elif (spec["phase"] == "access" and validation_mode in {"artifact_read", "budget_finalization"}
                  and "read_artifact" in names and (not results or validation_mode == "budget_finalization")
                  and not any(row["tool"] == "hunter_run_web_loop" for row in results)):
                if results:
                    page = results[-1]["result"]
                    assert results[-1]["tool"] == "read_artifact"
                    if page.get("reason_code") == "archive_read_no_progress":
                        assert "text" not in page
                    else:
                        assert len(page["text"]) == 3000 and page["next_offset"] == 3000 and not page["eof"]
                # The full read wrapper exceeded 3000 bytes in the paid run.
                # A stubborn provider repeats that exact range until the host
                # switches to summary-only tools without raising any budget.
                name, args = "read_artifact", {"path": context.get("previous_summary", context.get("discovery"))["content_ref"]["path"]}
            elif (spec['phase'] == 'report' and validation_mode == 'report_finalization'
                  and 'read_artifact' in names and decisions.count('report-4') <= 2):
                name, args = 'read_artifact', {'path': context['previous_summary']['content_ref']['path']}
            elif spec["phase"] == "report" and not results and validation_mode != 'report_finalization':
                schema = next(t["function"]["parameters"] for t in body["tools"]
                              if t["function"]["name"] == "hunter_coverage_report")
                assert "target" in schema["required"] and schema["properties"]["target"]["enum"] == [base]
                # Reproduce a missing advertised required target, then repair
                # it explicitly without executing any part of the bad batch.
                name, args = "hunter_coverage_report", {"campaign_id": 0}
                if context["protocol_feedback"]:
                    assert context["protocol_feedback"]["reason_code"] == "tool_arguments_schema_invalid"
                    args["target"] = base
            else:
                name, args = SUMMARY_TOOL, {"status": "done", "next": "continue", "steps": [
                    {"id": step["id"], "status": "done"} for step in spec["steps"] if not step["host_managed"]]}
                if spec["phase"] == "enum":
                    assert results[-1]["result"]["ok"]
                elif spec["phase"] == "access":
                    if validation_mode == "artifact_read" and results[-1]["tool"] == "read_artifact":
                        assert len(results[-1]["result"]["text"]) == 3000
                    if validation_mode == "budget_finalization":
                        assert names == {SUMMARY_TOOL}
                    args["status"] = "partial"
                    args["steps"][-1]["status"] = "not_tested"
                elif spec["phase"] == "report":
                    # Reproduce the live report: review complete, prior probes
                    # unfinished, no model-authored carryover step.
                    args["status"] = "partial"
                    if validation_mode in {'report_finalization', 'report_slot'}:
                        assert names == {SUMMARY_TOOL}
            prompt_tokens = 1800 if validation_mode in {"budget_finalization", 'artifact_pages'} and spec["phase"] == "access" else 100
            if validation_mode == 'report_finalization' and spec['phase'] == 'report':
                prompt_tokens = 2700
            emitted = [{'id': f'call-{len(decisions)}', 'type': 'function',
                        'function': {'name': name, 'arguments': json.dumps(args)}}]
            if validation_mode == 'report_slot' and spec['phase'] == 'report' and not results:
                # Five sequential model operations in one response leave the
                # sixth physical slot for the host checkpoint. No extra tool
                # or provider allowance is granted.
                emitted.extend({'id': f'read-{n}', 'type': 'function', 'function': {
                    'name': 'read_artifact', 'arguments': json.dumps({
                        'path': context['previous_summary']['content_ref']['path']})}} for n in range(4))
            raw = provider_json({"choices": [{"message": {"role": "assistant", "content": None,
                "tool_calls": emitted}, "finish_reason": "tool_calls"}],
                "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 100, "total_tokens": prompt_tokens + 100}})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "provider.json"
    dump(config, {"schema": "cco-llm/1", "model": "owned/model", "providers": {"owned": {
        "models": ["model"], "api_key_env": "CCO_BENCHMARK_API_KEY",
        "base_url": f"http://127.0.0.1:{server.server_port}/v1"}}})
    output = tmp_path.parent / (tmp_path.name + "-preflights")
    try:
        assert preflight.main(["--baseline", str(baseline), "--provider-config", str(config), "--token-budget", "150000", "--solver-mode", "python_loop", "--output-dir", str(output)]) == 0
        prepared = launcher.prepared_run(next(output.glob("*/preflight.json")))
        runs = tmp_path.parent / (tmp_path.name + "-runs")
        runs.mkdir()
        assert launcher.main(["--preflight", str(prepared["manifest_path"]), "--seed", str(prepared["contract"]["baseline"]["seeds"][0]),
                              "--solver-mode", "python_loop", "--output-dir", str(runs)]) == 0
        original = PythonSolver.__init__
        def capture(self, broker, **kwargs):
            original(self, broker, **kwargs)
            captured.append(self)
        monkeypatch.setattr(PythonSolver, "__init__", capture)
        original_handoff = PythonBroker.handoff
        def handoff_after_expired_setup(broker):
            from cco_surface_core import session_store
            base = broker.tasks.active_spec.target
            # Simulate the observed 366+ second provider delay without waiting
            # or changing the production freshness window. This fixture uses
            # signed checks dated 370 seconds ago; the actual MCP subprocess
            # must reject them until a real, metered session refresh occurs.
            with monkeypatch.context() as clocks:
                clocks.setattr(session_store, "time", SimpleNamespace(
                    time=lambda: time.time() - 370, time_ns=lambda: time.time_ns() - 370_000_000_000))
                for identity in broker.tasks.bindings:
                    result = session_store.refresh_status(base, identity, lambda *_a: (200, identity))
                    assert result["status"] == "fresh"
            assert all(session_store.verified_session(base, identity) is None for identity in broker.tasks.bindings)
            dump(broker.private / "fixture-session-expiry.json", {"simulated_age_seconds": 370,
                "identities": sorted(broker.tasks.bindings), "all_expired_before_handoff": True})
            return original_handoff(broker)
        monkeypatch.setattr(PythonBroker, "handoff", handoff_after_expired_setup)
        monkeypatch.setattr(launcher, "make_server", lambda *_a: pytest.fail("native bridge must not start"))
        provider = launcher.provider_settings(config, prepared["contract"]["models"])
        seed = prepared["contract"]["baseline"]["seeds"][0]
        path, manifest = launcher.launch_seed(prepared, seed=seed, output=runs, provider=provider,
                                              api_key="host-only-test-key", bwrap=None, opencode=None)
        assert manifest["status"] == "python_finished_verified", json.dumps(manifest)
        assert manifest["closure_verified"] and not manifest["acceptance_passed"]
        assert list(dict.fromkeys(decisions)) == list(PHASE_IDS)
        expected_calls = {"explicit": 12, "early_summary": 9, "artifact_read": 10}.get(validation_mode, len(decisions))
        access_calls = decisions.count("access-3")
        expected_tokens = expected_calls * 200 + (access_calls * 1700 if validation_mode in {"budget_finalization", 'artifact_pages'} else 0)
        if validation_mode == 'report_finalization':
            expected_tokens += decisions.count('report-4') * 2600
        assert manifest["llm_calls"] == expected_calls and manifest["budget"]["used"]["tokens"] == expected_tokens
        if validation_mode == "budget_finalization":
            # A smaller closing context can finish in three turns. Require
            # observation/validation/finalization without forcing extra calls.
            assert 3 <= access_calls < PHASE_CALL_LIMITS["access"]
            requests = json.loads((path.parent / "private/provider-requests.json").read_bytes())
            assert all(row["admitted"] for row in requests)
            assert any(row["runtime_allowance"]["finalizing"] for row in requests if row["task_spec_id"] == "access-3")
        assert manifest["target_requests"] == manifest["budget"]["used"]["http"] > 3
        directory, work = path.parent, path.parent / "solver"
        assert all((directory / name).is_file() for name in ("manifest.json", "run-result.json", "provider-usage.jsonl", "budget.json"))
        assert all((work / name).is_file() for name in ("closure.json", "attempt-ledger.json", "handoff.json"))
        assert len(list((work / "summaries").glob("*.json"))) == 4
        enum_summary = json.loads((work / "summaries/enum-2.json").read_text())
        assert enum_summary["status"] == "done"
        assert urljoin(manifest["target"], "notes") in enum_summary["surface"]["routes"]
        assert {"q", "id", "name", "next"} <= set(enum_summary["surface"]["params"])
        assert enum_summary["surface"]["records"]
        assert enum_summary["inherited_http_observations"][0]["source_spec_id"] == "recon-1"
        assert any(row["url"] == urljoin(manifest["target"], "notes") and row["status"] == 200
                   for row in enum_summary["route_probes"])
        assert not enum_summary["tested_parameters"]
        expected_repairs = int(validation_mode != 'report_finalization') + int(validation_mode == 'explicit')
        assert manifest["contract_repair_count"] == manifest["protocol_repair_count"] == expected_repairs
        schema_events = [row for row in manifest["loop_events"] if row["reason_code"] == "tool_arguments_schema_invalid"]
        assert len(schema_events) == expected_repairs
        tool_results = json.loads((directory / "private/python-tool-results.json").read_bytes())
        if validation_mode == 'artifact_pages':
            pages = [row for row in tool_results if row['spec_id'] == 'access-3' and row['tool'] == 'read_artifact']
            assert len(pages) >= 2
            assert [row['arguments']['offset'] for row in pages] == [3000 * n for n in range(len(pages))]
            requests = json.loads((directory / 'private/provider-requests.json').read_bytes())
            assert all(row['admitted'] for row in requests)
            assert all(row['reservation'] + row['runtime_allowance']['finish_reserve_tokens'] <=
                       row['runtime_allowance']['remaining_phase_tokens'] for row in requests
                       if row['task_spec_id'] == 'access-3')
        checks = [row for row in tool_results if row["tool"] == "validator_session_vault_check" and row["spec_id"] == "access-3"]
        if validation_mode == "explicit":
            assert len(checks) == 1
            assert checks[0]["arguments"] == {"target": manifest["target"], "identity": "admin-a"}
            assert checks[0]["result"]["status"] == "fresh"
        crawl = next(row for row in tool_results if row["tool"] == "kali-tools_crawl_web_surface")
        assert crawl["arguments"]["identity"] == "member-a" and crawl["arguments"]["session_target"] == manifest["target"]
        if validation_mode != 'report_finalization':
            coverage = next(row for row in tool_results if row["tool"] == "hunter_coverage_report")
            assert coverage["arguments"]["target"] == manifest["target"]
            coverage_result = json.loads((work / coverage["content_ref"]["path"]).read_bytes())
            assert not coverage_result.get("error") and coverage_result["endpoints"] > 0
        if validation_mode in {'report_finalization', 'report_slot'}:
            policy = json.loads((directory / 'private/runtime-policy.json').read_bytes())
            requests = json.loads((directory / 'private/provider-requests.json').read_bytes())
            assert any(row['runtime_allowance']['finalizing'] for row in requests if row['task_spec_id'] == 'report-4')
            checkpoints = [row for row in tool_results if row['tool'] == 'kali-tools_ledger_checkpoint']
            assert len(checkpoints) == 1 and checkpoints[0]['result']['sealed'] is True
            assert checkpoints[0]['result']['check_exit'] == 0
            report_calls = [row for row in tool_results if row['spec_id'] == 'report-4']
            assert policy['tool_calls']['report-4'] == len(report_calls) <= 6
            if validation_mode == 'report_slot':
                assert len(report_calls) == 6
            assert not policy['host_finalizing'] and not policy['checkpoint_tool_reserves']
        handoff_checks = [row for row in tool_results if row["tool"] == "validator_session_vault_check" and row["spec_id"] == "enum-2"]
        assert len(handoff_checks) == 3
        assert {row["arguments"]["identity"] for row in handoff_checks} == {"member-a", "member-b", "admin-a"}
        assert all(row["arguments"]["target"] == manifest["target"] and row["result"]["status"] == "fresh" for row in handoff_checks)
        tools = json.loads((directory / "private/tool-index.json").read_bytes())
        executed_checks = [row for row in tools if row["tool"] == "validator_session_vault_check" and row["origin"] == "solver"]
        assert len(executed_checks) == (4 if validation_mode == "explicit" else 3)
        pids = [json.loads(Path(row["artifact"]).read_bytes())["execution"]["result"]["executor_pid"] for row in tools]
        assert pids and all(pid != os.getpid() and not Path(f"/proc/{pid}").exists() for pid in pids)
        signed = json.loads((work / "attempt-ledger.json").read_bytes())
        monkeypatch.setenv("CCO_HOME", str(directory / "private/state"))
        monkeypatch.setenv("CCO_REPO_ROOT", str(directory / "runtime"))
        monkeypatch.setenv("CCO_SCOPE_FILE", str(directory / "runtime/.codex/scope.json"))
        monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(directory / "runtime/.codex/program-policy.json"))
        assert verify(canonical_bytes(signed["payload"]), signed, "python-attempt-ledger")
        assert any(row["verdict"] in {"CONFIRMED", "UNCONFIRMED"} for row in signed["payload"]["records"])
        assert list((work / "validator-artifacts").glob("*.json"))
        if validation_mode == 'explicit':
            import agent_cli
            before_decisions = list(decisions)
            monkeypatch.setenv('CCO_BENCHMARK_API_KEY', 'host-only-test-key')
            assert agent_cli.main(['run', '--preflight', str(prepared['manifest_path']), '--seed', str(seed),
                                   '--provider-config', str(config), '--output-dir', str(runs),
                                   '--resume', '--execute']) == 0
            resumed = json.loads((directory / 'manifest.json').read_bytes())
            assert resumed['resumed'] and resumed['closure_verified']
            assert resumed['budget']['used'] == manifest['budget']['used']
            assert resumed['target_requests'] == manifest['target_requests']
            assert decisions == before_decisions  # no provider or target replay after lab shutdown
        solver = captured[0]
        validator_copy = next((work / "validator-artifacts").glob("*.json")).relative_to(work).as_posix()
        for name in ("attempt-ledger.json", "handoff.json", "summaries/enum-2.json", "closure.json", "attempts.jsonl", validator_copy):
            target = work / name
            original_bytes = target.read_bytes()
            data = json.loads(original_bytes.splitlines()[0]) if name == "attempts.jsonl" else json.loads(original_bytes)
            if name == "closure.json":
                data["payload"]["target"] = "changed"
            elif name == "attempt-ledger.json":
                data["payload"]["target"] = "changed"
            elif name == "attempts.jsonl":
                data["verdict"] = "changed"
            else:
                data["tampered"] = True
            if name == "attempts.jsonl":
                target.write_bytes(provider_json(data) + b"\n" + b"\n".join(original_bytes.splitlines()[1:]) + b"\n")
            else:
                dump(target, data)
            try:
                with launcher.host_environment(directory / "private/state", work, directory / "runtime"):
                    assert solver.verify_closure() is False
            except ValueError:
                pass
            target.write_bytes(original_bytes)
            with launcher.host_environment(directory / "private/state", work, directory / "runtime"):
                assert solver.verify_closure()
        assert "host-only-test-key" not in "".join(p.read_text(errors="replace") for p in work.rglob("*") if p.is_file())
        record_testsuite_property("python_workflow_run", str(directory))
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_enum_continuation_preserves_handoff_reserve_and_empty_json_entry_member_batches(python_broker, monkeypatch):
    target = python_broker.tasks.specs[0].target
    python_broker.tasks.bindings = {
        "member-a": {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True},
        "member-b": {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True},
    }
    python_broker.catalog["hunter"] = [{
        "name": "run_web_loop",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "live": {"type": "boolean"},
                "crawl": {"type": "boolean"},
                "blind_discovery": {"type": "boolean"},
                "blind_max_requests": {"type": "integer"},
                "max_validations": {"type": "integer"},
                "fuzz_limit": {"type": "integer"},
                "candidate_sample_limit": {"type": "integer"},
                "sleep_s": {"type": "number"},
                "session_bindings": {"type": "string"},
            },
            "required": ["target", "live", "session_bindings"],
        },
    }]
    solver = PythonSolver(python_broker, model="model")
    recon, enum_spec, access_spec = python_broker.tasks.specs[:3]
    recon_view = python_broker.view({"status_code": 200, "text": '{"service":"record archive","links":[]}'})
    python_broker.results.append({
        "spec_id": recon.id,
        "tool": "kali-tools_curl_request",
        "arguments": {"url": recon.target, "follow_redirects": False},
        **recon_view,
    })
    recon_summary = solver.compile_summary(recon, terminal(recon))
    solver.summaries[recon.id] = recon_summary
    recon_path = python_broker.tasks.summary_path(recon)
    recon_path.parent.mkdir(parents=True, exist_ok=True)
    dump(recon_path, recon_summary)

    # Verify host_continuing keeps handoff reserve intact even during finalization.
    policy = python_broker.runtime_policy
    assert policy.handoff_reserves[enum_spec.id] == 3
    policy.finalizing.add(enum_spec.id)
    policy.host_continuing.add(enum_spec.id)
    assert policy.tool_allowance(enum_spec) == PHASE_CALL_LIMITS["enum"] - 3
    policy.host_continuing.discard(enum_spec.id)
    policy.finalizing.discard(enum_spec.id)

    enum_summary = solver.compile_summary(enum_spec, terminal(enum_spec))
    solver.summaries[enum_spec.id] = enum_summary
    dump(python_broker.tasks.summary_path(enum_spec), enum_summary)
    python_broker.handoffs["access"] = {"producer_spec_id": enum_spec.id, "target": target, "files": {}}

    candidates = solver.plan_candidates(access_spec)
    assert len(candidates) == 1
    assert candidates[0]["vector"] == "access-idor"
    assert candidates[0]["eligible"] is True
    assert candidates[0]["provenance"][0]["source_spec_id"] == recon.id
    assert not any(
        row["reason_code"] == "missing_declared_upstream_observations"
        for row in solver.coverage_gaps.get(access_spec.id, [])
    )


def test_enum_launcher_goals_preserve_step_ids_and_exclude_hunter(tmp_path):
    specs = launcher.bootstrap_plan("http://127.0.0.1:18765/", tmp_path / "solver", solver_mode="python_loop")
    by_phase = {spec.phase: spec for spec in specs}
    assert [step.id for step in by_phase["enum"].steps] == ["discover-surface"]
    assert [step.id for step in by_phase["access"].steps] == ["minimal-validation", "broader-coverage"]
    assert "hunter_run_web_loop" not in by_phase["enum"].tools
    assert all(len(step.command) <= 160 for spec in specs for step in spec.steps)


def test_first_dispatch_coalesces_both_profiles_and_retains_idor_and_residual_leaves(python_broker, monkeypatch):
    from test_python_candidate_runtime import catalog, observe
    catalog(python_broker)
    solver, spec = member_solver(python_broker, monkeypatch, count=2)
    pages = [
        {"url": spec.target + "search/grp"},
        {"url": spec.target + "search/grp/0?term=alpha"},
        {"url": spec.target + "search/grp/1?term=alpha"},
        {"url": spec.target + "other?sort=beta"},
        {"url": spec.target + "indet"},
        {"url": spec.target + "indet/0?term=alpha"},
        {"url": spec.target + "indet/1?term=alpha"},
    ]
    observe(python_broker, solver, python_broker.tasks.specs[1], pages)
    candidates = solver.plan_candidates(spec)
    # Mark indet/0 SQLi as dispatch_started (interrupted/indeterminate) -> /indet SQLi cannot slice, indet/0 never replays.
    indet_sqli = next(r for r in candidates
                      if r["route"] == spec.target + "indet/0?term=alpha" and r["vector"] == "injection-sqli")
    indet_sqli["dispatch_started"] = True

    calls = []
    def invoke(tool, args):
        python_broker.runtime_policy.check_tool(spec, tool)
        calls.append((tool, args))
        return python_broker.view({"ok": True})
    monkeypatch.setattr(python_broker, "invoke", invoke)
    assert solver.dispatch_access_validation(spec)
    # Expected calls:
    # 1 IDOR pair (blind_discovery)
    # + 2 /search/grp slices (SQLi + SSTI) + 1 /indet SSTI slice
    # + 2 /other?sort=beta direct residuals (SQLi + SSTI) + 1 /indet/1?term=alpha SQLi direct residual = 7 calls.
    assert len(calls) == 7
    assert any(tool == "hunter_run_web_loop" and args.get("blind_discovery") for tool, args in calls)
    hunter_slices = {(args["target"], args["validation_profile"])
                     for tool, args in calls if tool == "hunter_run_web_loop" and args.get("validation_profile")}
    assert hunter_slices == {
        (spec.target + "search/grp", "readonly_sqli_boolean"),
        (spec.target + "search/grp", "readonly_ssti_arithmetic"),
        (spec.target + "indet", "readonly_ssti_arithmetic"),
    }
    direct_urls = {(tool, args["target_url"], args["param"])
                   for tool, args in calls if tool.startswith("validator_validate_")}
    assert direct_urls == {
        ("validator_validate_sqli", spec.target + "other?sort=beta", "sort"),
        ("validator_validate_ssti", spec.target + "other?sort=beta", "sort"),
        ("validator_validate_sqli", spec.target + "indet/1?term=alpha", "term"),
    }
    assert indet_sqli["route"] not in {args.get("target_url") for _, args in calls}


def test_flat_16_endpoint_32_leaf_residuals_respect_physical_14_call_ceiling(python_broker, monkeypatch):
    from test_python_candidate_runtime import catalog, observe
    catalog(python_broker)
    solver = PythonSolver(python_broker, model="model")
    source, spec = python_broker.tasks.specs[1:3]
    pages = [{"url": spec.target + f"flat/{idx}?term=alpha"} for idx in range(16)]
    observe(python_broker, solver, source, pages)
    python_broker.tasks.active_spec = spec
    monkeypatch.setattr(python_broker, "_check_handoff", lambda _spec: None)
    monkeypatch.setattr(python_broker.engine, "tool_capability", lambda _tool: {"network": True})
    assert solver.dispatch_access_validation(spec)
    assert python_broker.runtime_policy.tool_calls[spec.id] == PHASE_CALL_LIMITS["access"] == 14
    assert len(python_broker.executor.tasks) == 14
    assert all(task["tool_name"].startswith("validator_validate_") for task in python_broker.executor.tasks)
    rows = solver.plan_candidates(spec)
    assert len(rows) == 32
    exhausted = [r for r in rows if r["reason_code"] == "phase_tool_budget_exhausted"]
    assert len(exhausted) == 18 and all(r["validation_state"] == "NOT TESTED" for r in exhausted)


@pytest.fixture
def solver_replay_lab(python_broker, monkeypatch):
    from test_python_candidate_runtime import replay_lab

    yield from getattr(replay_lab, "__wrapped__", replay_lab)(python_broker, monkeypatch)


def test_partial_member_pair_tracks_leaf_progress_without_misleading_invalid_gap(solver_replay_lab, monkeypatch):
    from cco_validator_core import load_validation
    from cco_validator_core.evidence import persist_result
    from test_python_holdout_regressions import prepare_identity_replay

    broker, _target, wire = solver_replay_lab
    solver, spec = prepare_identity_replay(broker)
    solver.batches_by_task[spec.id] = solver.batches_by_task[spec.id][:1]
    batch = solver.batches_by_task[spec.id][0]
    row = solver.plan_candidates(spec)[0]

    original = type(broker.executor).__call__

    def partial_pair_execute(self, task):
        result = original(self, task)
        report = result["result"]["output"]
        validations = list(report.get("validations") or [])
        assert len(validations) >= 2
        # Keep validations[0] as valid signed CONFIRMED/UNCONFIRMED.
        # Make validations[1] genuinely INCONCLUSIVE (valid signature, INCONCLUSIVE verdict).
        # Drop any remaining validations so they stay pending in validation_queue.
        if len(validations) >= 3:
            inc = validations[1]
            rec = load_validation(inc["validation_id"])
            rec["verdict"] = "INCONCLUSIVE"
            persist_result(rec, str(Path(rec["artifact"]["path"]).parent))
            inc["verdict"] = "INCONCLUSIVE"
            report["validations"] = [validations[0], inc]
            expected_pending = len(report["validation_queue"]) - 2
            expected_indet = 1
        else:
            report["validations"] = [validations[0]]
            expected_pending = len(report["validation_queue"]) - 1
            expected_indet = 0
        report["identity_discovery"]["budget_limited"] = True
        partial_pair_execute.expected = (len(report["validation_queue"]), 1, expected_pending, expected_indet)
        return result

    monkeypatch.setattr(type(broker.executor), "__call__", partial_pair_execute)
    assert solver.dispatch_access_validation(spec)
    observed, accepted, pending, indeterminate = partial_pair_execute.expected

    # Strict pair completeness remains False, and candidate-unit validation_funnel is unchanged.
    assert solver.completed_member_batch(spec, batch) is False
    summary = solver.compile_summary(spec, terminal(spec, status="partial", steps=[
        {"id": step.id, "status": "not_tested"} for step in spec.steps]))
    assert summary["validation_funnel"]["unit"] == "deduplicated_task_candidate"
    assert summary["validation_funnel"]["evidence_accepted"] == 0
    pair_cand = next(c for c in summary["validation_funnel"]["candidates"] if c["vector"] == "access-idor")
    assert pair_cand["validation_state"] == "NOT TESTED"
    assert pair_cand["reason_code"] == "partial_leaf_coverage"

    # Explicit leaf-outcome and pair-progress metrics expose the valid partial coverage.
    leaf_funnel = summary["leaf_validation_funnel"]
    assert leaf_funnel["unit"] == "signed_validation_leaf"
    assert (leaf_funnel["observed"], leaf_funnel["accepted"], leaf_funnel["pending"],
            leaf_funnel["indeterminate"], leaf_funnel["invalid_evidence"]) == (
        observed, accepted, pending, indeterminate, 0
    )
    pair_prog = summary["pair_progress"]
    assert pair_prog["schema"] == "python-pair-progress/1"
    assert pair_prog["total_pairs"] == 3 and pair_prog["complete_pairs"] == 0 and pair_prog["partial_pairs"] == 1
    pair_entry = next(p for p in pair_prog["pairs"] if p["identities"] == list(batch))
    assert pair_entry["complete"] is False and pair_entry["partial_coverage"] is True
    assert pair_entry["status"] == "NOT TESTED" and pair_entry["coverage_state"] == "partial_coverage"
    assert (pair_entry["observed"], pair_entry["accepted"], pair_entry["pending"],
            pair_entry["indeterminate"], pair_entry["invalid_evidence"]) == (
        observed, accepted, pending, indeterminate, 0
    )
    pair_comp = next(c for c in summary["identity_comparisons"] if c["identities"] == list(batch))
    assert pair_comp["status"] == "NOT TESTED"
    assert pair_comp["reason_code"] == "partial_leaf_coverage"
    assert not any(g["reason_code"] == "invalid_or_missing_signed_evidence" for g in summary["coverage_gaps"])
    import python_identity_discovery as discovery
    prior_discovery_env = os.environ.get("CCO_PYTHON_DISCOVERY_INVOCATION")
    try:
        disc_payload = json.loads(discovery.prepare_discovery(broker, spec, row["arguments"]).read_bytes())["payload"]
        assert disc_payload["states"] == {} and disc_payload["sources"] == []
        before = len(wire)
        assert not solver.dispatch_access_validation(spec) and len(wire) == before
    finally:
        if prior_discovery_env is None:
            os.environ.pop("CCO_PYTHON_DISCOVERY_INVOCATION", None)
        else:
            os.environ["CCO_PYTHON_DISCOVERY_INVOCATION"] = prior_discovery_env


def test_partial_parameter_slice_shortfall_tracks_leaf_outcomes_without_invalid_gap(solver_replay_lab, monkeypatch):
    from cco_validator_core import load_validation
    from cco_validator_core.evidence import persist_result
    from test_python_candidate_runtime import observe

    broker, target, wire = solver_replay_lab
    solver = PythonSolver(broker, model="model", recent_results=0)
    source, spec = broker.tasks.specs[1:3]
    spec.vector = "injection-sqli"
    pages = [
        {"url": target + "search/part"},
        {"url": target + "search/part/0-unsafe?term=alpha"},
        {"url": target + "search/part/1-safe?term=alpha"},
        {"url": target + "search/part/2-safe?term=alpha"},
    ]
    observe(broker, solver, source, pages)
    broker.tasks.active_spec = spec

    original = type(broker.executor).__call__

    def partial_slice_execute(self, task):
        result = original(self, task)
        report = result["result"]["output"]
        validations = list(report.get("validations") or [])
        assert len(validations) == 3
        # validations[0]: valid accepted; validations[1]: valid INCONCLUSIVE; validations[2]: unexecuted pending.
        inc = validations[1]
        rec = load_validation(inc["validation_id"])
        rec["verdict"] = "INCONCLUSIVE"
        persist_result(rec, str(Path(rec["artifact"]["path"]).parent))
        inc["verdict"] = "INCONCLUSIVE"
        report["validations"] = [validations[0], inc]
        report["stopped"] = "http_budget_exhausted"
        return result

    monkeypatch.setattr(type(broker.executor), "__call__", partial_slice_execute)
    assert solver.dispatch_access_validation(spec)
    summary = solver.compile_summary(spec, terminal(spec, status="partial", steps=[
        {"id": step.id, "status": "not_tested"} for step in spec.steps]))
    assert summary["validation_funnel"]["observed"] == 3
    assert summary["validation_funnel"]["executed"] == 2
    assert summary["validation_funnel"]["evidence_accepted"] == 1
    lf = summary["leaf_validation_funnel"]
    assert (lf["observed"], lf["accepted"], lf["pending"], lf["indeterminate"], lf["invalid_evidence"]) == (3, 1, 1, 1, 0)
    assert not any(g["reason_code"] == "invalid_or_missing_signed_evidence" for g in summary["coverage_gaps"])
    before = len(wire)
    assert not solver.dispatch_access_validation(spec) and len(wire) == before
