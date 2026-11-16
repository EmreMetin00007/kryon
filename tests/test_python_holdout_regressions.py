"""Owned replay protocol and signed validation-continuation regressions."""
import copy
import json
from pathlib import Path

import pytest

from full_agent_python_broker import SUMMARY_TOOL
from full_agent_python_solver import PythonSolver
from test_full_agent_python_holdout import (
    expected_validation_checks,
    observed_validation_checks,
    replay_decision,
)
from test_full_agent_python_solver import python_broker, terminal
from test_python_candidate_runtime import FROZEN, observe, replay_lab


def prepare_parameter_replay(broker, target):
    broker.tasks.bindings = {"first": {"target": target, "role": "member",
        "test_data_only": True, "owned_objects_private": True}}
    solver = PythonSolver(broker, model="model")
    source, spec = broker.tasks.specs[1:3]
    observe(broker, solver, source, [{"url": target + "search/group"}, *(
        {"url": target + f"search/group/{n}-safe?term=alpha"} for n in range(4))], identity="first")
    broker.tasks.active_spec = spec
    return solver, spec


@pytest.mark.parametrize("change", ["foreign", "unobserved", "query", "fragment", "ineligible",
                                       "mixed_param", "mixed_arguments", "ambiguous", "partial_accepted"])
def test_parameter_index_cannot_widen_or_replay_leaf_admission(replay_lab, change):
    broker, target, wire = replay_lab
    solver, spec = prepare_parameter_replay(broker, target)
    rows = copy.deepcopy(solver.plan_candidates(spec))
    index, profile = target + "search/group", "readonly_sqli_boolean"
    selected = [row for row in rows if row["arguments"].get("validation_profile") == profile]
    if change == "foreign":
        index = "http://outside.invalid/search/group"
    elif change == "unobserved":
        index = target + "search"
    elif change == "query":
        index += "?term=alpha"
    elif change == "fragment":
        index += "#group"
    elif change == "ineligible":
        selected[0]["eligible"] = False
    elif change == "mixed_param":
        selected[0]["param"] = "other"
    elif change == "mixed_arguments":
        selected[0]["arguments"]["session_bindings"] = "{}"
    elif change == "ambiguous":
        selected[0]["dispatch_started"] = True
    else:
        selected[0].update(executed=True, evidence_accepted=True)
    sliced = solver.parameter_slice(spec, rows, index, profile)
    # Even a current accepted leaf cannot authorize replay of its whole index.
    assert sliced is None and not wire and not broker.executor.tasks


def test_parameter_index_queue_is_not_execution_or_signed_coverage(replay_lab, monkeypatch):
    broker, target, wire = replay_lab
    solver, spec = prepare_parameter_replay(broker, target)
    profile = "readonly_sqli_boolean"
    rows = solver.plan_candidates(spec)
    leaf = next(row for row in rows if row["arguments"].get("validation_profile") == profile)
    def execute(self, task):
        self.tasks.append(task)
        return {"actual_request_cost": 0, "result": {"output": {"ok": True,
            "validation_queue": [{"url": leaf["route"], "param": leaf["param"],
                                  "method": "GET", "carrier": "query"}], "validations": []}}}
    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    args = solver.parameter_slice(spec, rows, target, profile)["arguments"]
    broker.invoke("hunter_run_web_loop", args)
    solver.plan_candidates(spec)
    assert leaf.get("dispatch_started") and not leaf["executed"] and not leaf["evidence_accepted"]
    assert not broker.validation_attempts(spec) and leaf["validation_state"] == "NOT TESTED"
    assert not wire


def test_first_access_compaction_keeps_admitted_slice_schema_and_caps(replay_lab):
    import asyncio
    from conftest import load_server
    from full_agent_budget import compact_tools, provider_json
    from full_agent_provider import TOOL_DESCRIPTION_LIMIT
    broker, target, _wire = replay_lab
    solver, spec = prepare_parameter_replay(broker, target)
    hunter = load_server("hunter")
    broker.catalog["hunter"] = [row.model_dump(mode="json", exclude_none=True, exclude={"outputSchema"})
                               for row in asyncio.run(hunter.mcp.list_tools()) if row.name == "run_web_loop"]
    context = solver.context(spec)
    body = {"model": "model", "max_tokens": 4096, "messages": [{"role": "system", "content": "bounded"},
        {"role": "user", "content": provider_json(context).decode()}], "tools": compact_tools(
            solver.tool_schemas(spec), description_limit=TOOL_DESCRIPTION_LIMIT, strip_annotations=True)}
    # The production catalog must be compacted before it consumes the reserve;
    # no provider/target calls or additional token budget are granted.
    before = copy.deepcopy(broker.runtime_policy.limits)
    projected, info, projection = broker.project_runtime_context(body, spec, None)
    assert not info["finalizing"] and broker.runtime_policy.limits == before
    assert projection is not None and projection["level"] == 2
    schema = next(row["function"]["parameters"] for row in projected["tools"]
                  if row["function"]["name"] == "hunter_run_web_loop")
    assert set(schema["properties"]) == {"target", "live", "session_bindings", "validation_profile"}
    name, args = replay_decision(projected, "parameter_batches", "readonly_sqli_boolean")
    assert name == "hunter_run_web_loop" and "fuzz_limit" not in args
    selected = solver.parameter_slice(spec, solver.plan_candidates(spec), args["target"], args["validation_profile"])
    assert selected["arguments"]["fuzz_limit"] == 4 and selected["arguments"]["max_validations"] == 16


@pytest.mark.parametrize("profile", ["readonly_sqli_boolean", "readonly_ssti_arithmetic"])
def test_observed_parameter_indexes_continue_bounded_profile_with_leaf_evidence(replay_lab, monkeypatch, profile):
    from cco_validator_core.evidence import validation_context
    from conftest import load_server
    from full_agent_budget import provider_json
    from test_full_agent_preflight import mock_provider
    from python_candidate_runtime import PROFILES
    broker, target, wire = replay_lab
    broker.tasks.bindings = {"first": {"target": target, "role": "member",
        "test_data_only": True, "owned_objects_private": True}}
    solver = PythonSolver(broker, model="model")
    source, spec = broker.tasks.specs[1:3]
    stem = "search" if profile == "readonly_sqli_boolean" else "render"
    leaves = [{"url": target + f"{stem}/{group}/{n}-{'unsafe' if n % 2 else 'safe'}?term=alpha"}
              for group in ("one", "two") for n in range(4)]
    observe(broker, solver, source, [{"url": target + f"{stem}/{group}"} for group in ("one", "two")] + leaves, identity="first")
    broker.tasks.active_spec = spec
    validator = load_server("validator")
    completed: dict[str, set[str]] = {}
    def execute(self, task):
        self.tasks.append(task)
        args = json.loads(task["args_json"])
        current_profile = args["validation_profile"]
        assert current_profile in PROFILES and args["fuzz_limit"] == 4
        fn = getattr(validator, PROFILES[current_profile][1].removeprefix("validator_"))
        done = completed.setdefault(current_profile, set())
        prefix = args["target"].rstrip("/") + "/"
        queue, validations = [], []
        before = len(wire)
        for leaf in leaves:
            url = leaf["url"]
            if not url.startswith(prefix) or url in done or len(validations) == args["fuzz_limit"]:
                continue
            item = {"url": url, "method": "GET", "param": "term", "carrier": "query", "identity": "first"}
            queue.append(item)
            with validation_context(item):
                record = json.loads(fn(target_url=url, param="term", **(
                    {"boolean_only": True} if current_profile == "readonly_sqli_boolean" else {})))
            validations.append({**item, "validation_id": record["validation_id"]})
            done.add(url)
        return {"actual_request_cost": len(wire) - before, "result": {"output": {
            "ok": True, "validation_queue": queue, "validations": validations}}}
    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    original = broker.completion
    turns = []
    def completion(body):
        turns.append(body)
        if len(turns) == 1:
            args = solver.parameter_slice(spec, solver.plan_candidates(spec), target, profile)["arguments"]
            message = {"tool_calls": [{"function": {"name": "hunter_run_web_loop", "arguments": provider_json(args).decode()}}]}
        else:
            message = {"content": json.dumps(terminal(spec))}
        mock_provider(monkeypatch, broker, {"choices": [{"message": message}], "usage": {
            "prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
        return original(body)
    monkeypatch.setattr(broker, "completion", completion)
    waits = []
    monkeypatch.setattr(solver, "wait_access_rate_window", lambda _spec: waits.append(True) or True)
    summary = solver.phase(spec)
    assert len(turns) == 3 and len(broker.executor.tasks) == 4 and waits == [True, True, True]
    assert len(summary["validation_outcomes"]) == summary["validation_funnel"]["evidence_accepted"] == 16
    assert len(summary["tested_parameters"]) == 16
    assert len(completed[profile]) == 8 and sum(len(v) for v in completed.values()) == 16
    assert {row["vector"] for row in summary["validation_outcomes"]} == {"injection-sqli", "injection-ssti"}
    assert all(row["validation_state"] == "TESTED" for row in solver.plan_candidates(spec))
    assert broker.budget.used["http"] == len(wire)
    before = len(wire)
    assert not solver.dispatch_access_validation(spec) and len(wire) == before


@pytest.mark.parametrize("identity", ["anon", "anonymous", "first", "second", "missing", None])
def test_parameter_observation_selects_only_its_request_identity(python_broker, identity):
    from python_candidate_runtime import parameter_candidates
    broker = python_broker
    spec = broker.tasks.specs[2]
    bindings = {name: {"target": spec.target, "role": "member", "test_data_only": True,
                      "owned_objects_private": True} for name in ("first", "second")}
    record = {"url": spec.target + "search?q=1", "identity_ref": identity,
              "source_spec_id": spec.depends_on[0], "source_artifact": "observed.json", "source_sha256": "a" * 64}
    rows = parameter_candidates(spec, [record], bindings)
    assert rows
    if identity in {"missing", None}:
        assert all(not row["eligible"] and row["reason_code"] == "missing_observed_identity_binding" for row in rows)
    else:
        assert all(row["eligible"] for row in rows)
        for row in rows:
            selected = json.loads(row["arguments"].get("session_bindings", "{}"))
            assert selected == ({} if identity in {"anon", "anonymous"} else {identity: bindings[identity]})
            assert row["identity_ref"] == ("anon" if identity in {"anon", "anonymous"} else identity)
    assert not broker.executor.tasks and not broker.budget.used["http"]


@pytest.mark.parametrize("reverse", [False, True])
def test_public_parameter_preference_retains_provenance_without_credential_injection(python_broker, reverse):
    from python_candidate_runtime import parameter_candidates
    broker = python_broker
    spec = broker.tasks.specs[2]
    bindings = {"first": {"target": spec.target, "role": "member", "test_data_only": True,
                           "owned_objects_private": True}}
    records = [{"url": spec.target + "search?q=1", "identity_ref": name,
                "source_spec_id": spec.depends_on[0], "source_artifact": name + ".json", "source_sha256": "a" * 64}
               for name in ("anon", "first")]
    rows = parameter_candidates(spec, records[::-1] if reverse else records, bindings)
    assert len(rows) == 2 and all(row["eligible"] and row["identity_ref"] == "anon" for row in rows)
    assert all("session_bindings" not in row["arguments"] for row in rows)
    assert all({item["source_artifact"] for item in row["provenance"]} == {"anon.json", "first.json"} for row in rows)


@pytest.mark.parametrize("identity", ["anon", "first"])
def test_parameter_freshness_refreshes_only_the_observed_bound_session(python_broker, monkeypatch, identity):
    import full_agent_python_solver as runtime
    from types import SimpleNamespace
    from test_python_candidate_runtime import catalog
    broker = python_broker
    catalog(broker)
    solver, spec = prepare_identity_replay(broker)
    observe(broker, solver, broker.tasks.specs[1], [{"url": "/search?q=1", "identity_ref": identity}])
    broker.engine._rate_limit_for = lambda _tool: (60, 60)
    broker.engine.tool_capability = lambda _tool: {"network": True}
    broker.catalog["validator"].append({"name": "session_vault_check", "inputSchema": {"type": "object"}})
    monkeypatch.setattr(broker, "_check_handoff", lambda _spec: None)
    monkeypatch.setattr(runtime, "time", SimpleNamespace(time=lambda: 1000))
    for name in broker.tasks.bindings:
        broker.results.append({"spec_id": spec.depends_on[0], "tool": "validator_session_vault_check",
            "arguments": {"target": spec.target, "identity": name}, "session_check_observed_at": 630,
            **broker.view({"status": "fresh"})})
    row = next(row for row in solver.plan_candidates(spec) if row["vector"] == "injection-sqli")
    def execute(self, task):
        self.tasks.append(task)
        assert task["tool_name"] == "validator_session_vault_check"
        assert json.loads(task["args_json"]) == {"target": spec.target, "identity": "first"}
        return {"actual_request_cost": 1, "result": {"output": {"status": "fresh"}}}
    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    assert solver.refresh_expiring_access_sessions(spec, row)
    assert len(broker.executor.tasks) == broker.budget.used["http"] == int(identity == "first")
    assert not row["executed"] and not row["evidence_accepted"] and not broker.validation_attempts(spec)


def test_discovery_state_is_not_admitted_outside_its_host_invocation(replay_lab, monkeypatch):
    import os
    from conftest import load_server
    from python_identity_discovery import CONTEXT_ENV, load_discovery, prepare_discovery
    load_server("hunter")
    broker, target, _wire = replay_lab
    solver, spec = prepare_identity_replay(broker)
    row = solver.plan_candidates(spec)[0]
    monkeypatch.delenv(CONTEXT_ENV, raising=False)
    broker.invoke(row["tool"], row["arguments"])
    assert CONTEXT_ENV not in os.environ
    actors = {name: {"headers": {}, "role": "member", "owned_objects_private": True}
              for name in json.loads(row["arguments"]["session_bindings"])}
    assert load_discovery(target, actors, 24) == {}
    prepare_discovery(broker, spec, row["arguments"])
    monkeypatch.setenv(CONTEXT_ENV, "foreign-invocation")
    with pytest.raises(ValueError, match="invocation changed"):
        load_discovery(target, actors, 24)


def test_parameter_only_model_context_matches_public_candidate_without_vault_authority(python_broker):
    from test_python_candidate_runtime import catalog
    broker = python_broker
    catalog(broker)
    target = broker.tasks.specs[2].target
    broker.tasks.bindings = {"first": {"target": target, "role": "member", "test_data_only": True,
                                      "owned_objects_private": True}}
    solver = PythonSolver(broker, model="model")
    source, spec = broker.tasks.specs[1:3]
    observe(broker, solver, source, [{"url": "/search", "identity_ref": "anon"},
                                    {"url": "/search/leaf?q=1", "identity_ref": "anon"}])
    context = solver.context(spec)
    assert context["session_bindings"] == {}
    rows = solver.plan_candidates(spec)
    assert rows and all(row["identity_ref"] == "anon" for row in rows)
    assert all("session_bindings" not in row["arguments"] for row in rows)
    assert context["registered_session_checks"] == [{"target": target, "identity": "first"}]


@pytest.mark.parametrize("profile", ["readonly_sqli_boolean", "readonly_ssti_arithmetic"])
@pytest.mark.parametrize("tools", [[SUMMARY_TOOL], [SUMMARY_TOOL, "hunter_run_web_loop"]])
def test_replay_accepts_compact_frames_without_session_disclosure(profile, tools):
    context = {"schema": "python-workflow-v1", "task_spec": {
        "id": "renamed-validation", "phase": "access", "target": "http://127.0.0.1:1/",
        "steps": [{"id": "validate", "host_managed": False}]}, "recent_results": []}
    body = {"messages": [{}, {"content": json.dumps(context)}],
            "tools": [{"function": {"name": name}} for name in tools]}
    before = copy.deepcopy(body)
    name, args = replay_decision(body, "parameter_batches", profile)
    assert name == SUMMARY_TOOL and args["steps"] == [{"id": "validate", "status": "done"}]
    assert body == before and "session_bindings" not in context


def prepare_identity_replay(broker):
    target = broker.tasks.specs[2].target
    broker.tasks.bindings = {name: {"target": target, "role": "member", "test_data_only": True,
                                  "owned_objects_private": True} for name in ("first", "second", "third")}
    solver = PythonSolver(broker, model="model")
    source, spec = broker.tasks.specs[1:3]
    observe(broker, solver, source, FROZEN["identity_pages"])
    broker.tasks.active_spec = spec
    return solver, spec


@pytest.mark.parametrize("status", ["fresh", "expired"])
def test_session_check_receipt_records_host_time_without_granting_freshness(python_broker, monkeypatch, status):
    import full_agent_python_broker as runtime
    from types import SimpleNamespace
    from test_full_agent_python_solver import session_check_setup
    broker = python_broker
    spec = session_check_setup(broker)
    monkeypatch.setattr(broker, "_check_handoff", lambda _spec: None)
    monkeypatch.setattr(runtime, "time", SimpleNamespace(time=lambda: 1000))
    def execute(self, task):
        self.tasks.append(task)
        return {"actual_request_cost": 1, "result": {"output": {"status": status}}}
    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    view = broker.invoke("validator_session_vault_check", {"target": spec.target, "identity": "member-a"})
    assert broker.results[-1]["session_check_observed_at"] == 1000
    assert view["result"] == {"status": status} and broker.budget.used["http"] == 1
    assert not broker.validation_attempts(spec)


@pytest.mark.parametrize("change", ["due", "recent", "foreign_task", "expired", "denied", "budget", "tampered"])
def test_expiring_pair_sessions_require_metered_bound_refresh_before_dispatch(python_broker, monkeypatch, change):
    import full_agent_python_solver as runtime
    from types import SimpleNamespace
    from test_python_candidate_runtime import catalog
    broker = python_broker
    catalog(broker)
    solver, spec = prepare_identity_replay(broker)
    broker.engine._rate_limit_for = lambda _tool: (60, 60)
    capability = broker.engine.tool_capability
    broker.engine.tool_capability = lambda tool: ({"network": True} if tool == "validator_session_vault_check" else capability(tool))
    broker.catalog["validator"].append({"name": "session_vault_check", "inputSchema": {"type": "object"}})
    monkeypatch.setattr(broker, "_check_handoff", lambda _spec: None)
    monkeypatch.setattr(runtime, "time", SimpleNamespace(time=lambda: 1000))
    row = solver.plan_candidates(spec)[0]
    identities = json.loads(row["arguments"]["session_bindings"])
    for identity in identities:
        broker.results.append({"spec_id": "foreign" if change == "foreign_task" else spec.depends_on[0],
            "tool": "validator_session_vault_check", "arguments": {"target": spec.target, "identity": identity},
            "session_check_observed_at": 990 if change == "recent" else 740,
            **broker.view({"status": "fresh"})})
    if change == "tampered":
        reference = broker.results[-1]["content_ref"]
        (broker.workdir / reference["path"]).write_text('{"status":"expired"}')
    if change == "budget":
        broker.runtime_policy.tool_calls[spec.id] = spec.max_calls - 1
    original = broker.engine.validate_tool_invocation
    if change == "denied":
        broker.engine.validate_tool_invocation = lambda tool, *a, **kw: (
            {"allowed": False, "reason": "denied"} if tool == "validator_session_vault_check" else original(tool, *a, **kw))
    def execute(self, task):
        self.tasks.append(task)
        assert task["tool_name"] == "validator_session_vault_check"
        return {"actual_request_cost": 1, "result": {"output": {"status": "expired" if change == "expired" else "fresh"}}}
    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    before = copy.deepcopy(broker.runtime_policy.limits)
    if change == "tampered":
        with pytest.raises(ValueError, match="artifact reference changed"):
            solver.refresh_expiring_access_sessions(spec, row)
    else:
        assert solver.refresh_expiring_access_sessions(spec, row) == (change in {"due", "recent", "foreign_task"})
    expected = len(identities) if change == "due" else int(change == "expired")
    assert len(broker.executor.tasks) == broker.budget.used["http"] == expected
    assert broker.runtime_policy.limits == before and not broker.validation_attempts(spec)
    assert not row["executed"] and not row["evidence_accepted"]


def test_model_slice_waits_before_first_host_slice_and_stays_task_local(replay_lab, monkeypatch):
    broker, _target, wire = replay_lab
    solver, spec = prepare_identity_replay(broker)
    first = solver.plan_candidates(spec)[0]
    broker.invoke(first["tool"], first["arguments"])
    waits = []
    def wait(current):
        assert current.id == spec.id
        waits.append(len(broker.executor.tasks))
        return True
    monkeypatch.setattr(solver, "wait_access_rate_window", wait)
    assert solver.dispatch_access_validation(spec)
    assert waits == [1, 2] and len(broker.executor.tasks) == 3
    assert solver.compile_summary(spec, terminal(spec))["validation_funnel"]["evidence_accepted"] == 3
    before = len(wire)
    assert not solver.dispatch_access_validation(spec) and len(wire) == before


def test_parameter_profile_does_not_refresh_unrelated_pair_sessions(python_broker, monkeypatch):
    import full_agent_python_solver as runtime
    from types import SimpleNamespace
    from test_python_candidate_runtime import catalog
    broker = python_broker
    catalog(broker)
    solver, spec = prepare_identity_replay(broker)
    broker.engine._rate_limit_for = lambda _tool: (60, 60)
    row = {"vector": "sql-injection", "arguments": {"validation_profile": "readonly_sqli_boolean",
           "session_bindings": json.dumps(broker.tasks.bindings)}}
    monkeypatch.setattr(runtime, "time", SimpleNamespace(time=lambda: 1000))
    for identity in broker.tasks.bindings:
        broker.results.append({"spec_id": spec.depends_on[0], "tool": "validator_session_vault_check",
            "arguments": {"target": spec.target, "identity": identity},
            "session_check_observed_at": 740, **broker.view({"status": "fresh"})})
    calls = []
    monkeypatch.setattr(broker, "invoke", lambda *args: calls.append(args) or broker.view({"status": "fresh"}))
    before = copy.deepcopy(broker.runtime_policy.limits)
    assert solver.refresh_expiring_access_sessions(spec, row)
    assert not calls and not broker.executor.tasks and not broker.budget.used["http"]
    assert broker.runtime_policy.limits == before


@pytest.mark.parametrize("elapsed", [False, True])
@pytest.mark.parametrize("age", [239, 240, 260, 299, 300, 370])
@pytest.mark.parametrize("vector", ["access-idor", "injection-sqli"])
def test_session_refresh_reserves_only_a_pending_rate_window(python_broker, monkeypatch, elapsed, age, vector):
    import full_agent_python_solver as runtime
    from types import SimpleNamespace
    from test_python_candidate_runtime import catalog
    broker = python_broker
    catalog(broker)
    solver, spec = prepare_identity_replay(broker)
    broker.engine._rate_limit_for = lambda _tool: (60, 60)
    capability = broker.engine.tool_capability
    broker.engine.tool_capability = lambda tool: ({"network": True} if tool == "validator_session_vault_check" else capability(tool))
    broker.catalog["validator"].append({"name": "session_vault_check", "inputSchema": {"type": "object"}})
    monkeypatch.setattr(broker, "_check_handoff", lambda _spec: None)
    monkeypatch.setattr(runtime, "time", SimpleNamespace(time=lambda: 1000))
    row = solver.plan_candidates(spec)[0]
    row = {**row, "vector": vector}
    identities = json.loads(row["arguments"]["session_bindings"])
    for identity in identities:
        broker.results.append({"spec_id": spec.depends_on[0], "tool": "validator_session_vault_check",
            "arguments": {"target": spec.target, "identity": identity}, "session_check_observed_at": 1000 - age,
            **broker.view({"status": "fresh"})})
    def execute(self, task):
        self.tasks.append(task)
        assert task["tool_name"] == "validator_session_vault_check"
        assert json.loads(task["args_json"]) in [{"target": spec.target, "identity": name} for name in identities]
        return {"actual_request_cost": 1, "result": {"output": {"status": "fresh"}}}
    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    before = copy.deepcopy(broker.runtime_policy.limits)
    assert solver.refresh_expiring_access_sessions(spec, row, rate_window_elapsed=elapsed)
    expected = len(identities) if age >= (300 if elapsed else 240) else 0
    assert len(broker.executor.tasks) == broker.budget.used["http"] == expected
    assert broker.runtime_policy.limits == before and not broker.validation_attempts(spec)
    assert not row["executed"] and not row["evidence_accepted"]


def test_host_refresh_selection_receives_only_completed_backoff(replay_lab, monkeypatch):
    broker, _target, _wire = replay_lab
    solver, spec = prepare_identity_replay(broker)
    events = []
    original = solver.refresh_expiring_access_sessions
    def refresh(current, row, *, rate_window_elapsed=False):
        events.append(("refresh", rate_window_elapsed, len(broker.executor.tasks)))
        return original(current, row, rate_window_elapsed=rate_window_elapsed)
    def wait(current):
        assert current.id == spec.id
        events.append(("wait", len(broker.executor.tasks)))
        return True
    monkeypatch.setattr(solver, "refresh_expiring_access_sessions", refresh)
    monkeypatch.setattr(solver, "wait_access_rate_window", wait)
    assert solver.dispatch_access_validation(spec)
    assert events == [("refresh", False, 0), ("wait", 1), ("refresh", True, 1),
                      ("wait", 2), ("refresh", True, 2)]
    assert solver.compile_summary(spec, terminal(spec))["validation_funnel"]["evidence_accepted"] == 3


@pytest.mark.parametrize("change", ["current", "partial", "blocked", "signature", "source", "control", "session", "policy", "scope"])
def test_discovery_continuation_requires_whole_current_task_bound_proof(replay_lab, monkeypatch, change):
    from conftest import load_server
    from python_identity_discovery import capture_state, load_discovery, prepare_discovery, state_path
    from cco_validator_core import load_validation
    from cco_validator_core.evidence import persist_result
    load_server("hunter")
    broker, target, _wire = replay_lab
    solver, spec = prepare_identity_replay(broker)
    row = solver.plan_candidates(spec)[0]
    names = json.loads(row["arguments"]["session_bindings"])
    actors = {name: {"headers": {"Cookie": "identity=" + name}, "role": "member", "test_data_only": True,
                    "owned_objects_private": True, "objects": [{"url": target + "objects/" + name,
                    "marker": "owned-" + name}], "identity_facts": [{"field": "principal", "value": name,
                    "source": "response_metadata", "confidence": "observed"}]} for name in names}
    original = type(broker.executor).__call__
    def execute(self, task):
        result = original(self, task)
        report = result["result"]["output"]
        report["identity_discovery_state"] = capture_state(actors)
        if change == "blocked":
            report["identity_discovery"]["status"] = "blocked"
        if change == "partial":
            report["validation_queue"].append({"url": target + "objects/unexecuted", "method": "GET"})
        return result
    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    broker.invoke(row["tool"], row["arguments"])
    prepare_discovery(broker, spec, row["arguments"])
    source = broker.results[-1]["content_ref"]
    if change == "signature":
        envelope = json.loads(state_path().read_text())
        envelope["payload"]["task_spec"]["id"] = "foreign"
        state_path().write_text(json.dumps(envelope))
    elif change == "source":
        (broker.workdir / source["path"]).write_text("{}")
    elif change == "control":
        record = load_validation(broker.validation_attempts(spec)[0]["record"]["validation_id"])
        record["request_evidence"] = []
        persist_result(record, str(Path(record["artifact"]["path"]).parent))
    elif change == "session":
        actors[next(iter(actors))]["headers"] = {"Cookie": "identity=replaced"}
    elif change == "policy":
        from cco_validator_core import evidence
        monkeypatch.setattr(evidence, "current_policy_hash", lambda: "changed")
    elif change == "scope":
        from cco_validator_core import evidence
        monkeypatch.setattr(evidence, "current_scope_revision", lambda: "changed")
    if change in {"signature", "source", "control", "session", "policy", "scope"}:
        with pytest.raises(ValueError):
            load_discovery(target, actors, 24)
    else:
        states = load_discovery(target, actors, 24)
        assert set(states) == (set(actors) if change == "current" else set())
        assert all("headers" not in state and "cookies" not in state for state in states.values())


def test_identity_only_discovery_does_not_schedule_an_unrelated_root_probe(replay_lab):
    from conftest import load_server
    load_server("hunter")
    from cco_hunter_core.loop import execute_web_loop
    target = replay_lab[1]
    calls = []
    def identity_discover(_target, actors):
        calls.append("identity")
        return {"status": "incomplete", "reasons": ["no owned objects"]}, actors, []
    def unrelated(*_args, **_kwargs):
        calls.append("unrelated")
        return {}
    report = execute_web_loop(target, live=True, crawl=False, fuzz_limit=0,
                              identity_discover=identity_discover, discover=unrelated, fuzz=unrelated)
    assert calls == ["identity"] and not report["validation_queue"] and not report["validations"]


@pytest.mark.parametrize("change", ["missing_owner", "missing_attacker", "wrong_object", "failed_transport"])
def test_signed_missing_authorization_controls_are_not_tested_or_reportable(replay_lab, monkeypatch, change):
    from cco_validator_core import load_validation
    from cco_validator_core.evidence import persist_result
    broker, _target, _wire = replay_lab
    solver, spec = prepare_identity_replay(broker)
    row = solver.plan_candidates(spec)[0]
    original = type(broker.executor).__call__
    def execute(self, task):
        result = original(self, task)
        for item in result["result"]["output"]["validations"]:
            record = load_validation(item["validation_id"])
            controls = record["request_evidence"]
            if change.startswith("missing_"):
                record["request_evidence"] = [r for r in controls if r["role"] != change.removeprefix("missing_")]
            elif change == "wrong_object":
                controls[0]["request_url"] += "other"
            else:
                controls[0]["transport_ok"] = False
            # A genuine current host signature is necessary but not sufficient.
            persist_result(record, str(Path(record["artifact"]["path"]).parent))
        return result
    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    broker.invoke(row["tool"], row["arguments"])
    summary = solver.compile_summary(spec, terminal(spec))
    assert not broker.validation_attempts(spec) and not summary["findings"] and not summary["validation_outcomes"]
    assert not summary["validation_funnel"]["evidence_accepted"]
    assert all(r["status"] == "NOT TESTED" for r in summary["identity_comparisons"])


@pytest.mark.parametrize("receipt_state", ["measured", "unknown_cost", "ambiguous_error", "partial_accepted"])
def test_only_measured_zero_accepted_model_attempt_gets_one_admitted_validation(replay_lab, monkeypatch, receipt_state):
    from cco_validator_core import load_validation
    from cco_validator_core.evidence import persist_result
    broker, _target, wire = replay_lab
    solver, spec = prepare_identity_replay(broker)
    # One pair isolates continuation from unrelated ready work.
    solver.batches_by_task[spec.id] = solver.batches_by_task[spec.id][:1]
    original = type(broker.executor).__call__
    def execute(self, task):
        result = original(self, task)
        if len(self.tasks) == 1:
            items = result["result"]["output"]["validations"]
            for item in items[1:] if receipt_state == "partial_accepted" else items:
                record = load_validation(item["validation_id"])
                record["verdict"] = "INCONCLUSIVE"
                persist_result(record, str(Path(record["artifact"]["path"]).parent))
        return result
    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    row = solver.plan_candidates(spec)[0]
    broker.invoke(row["tool"], row["arguments"])
    receipt_path = Path(broker.tools[-1]["artifact"])
    receipt = json.loads(receipt_path.read_bytes())
    if receipt_state == "unknown_cost":
        receipt["execution"].pop("actual_request_cost")
        receipt_path.write_text(json.dumps(receipt))
    elif receipt_state == "ambiguous_error":
        receipt["error"] = "TransportInterrupted"
        receipt_path.write_text(json.dumps(receipt))
    solver.plan_candidates(spec)
    assert not row["evidence_accepted"]
    waits = []
    monkeypatch.setattr(solver, "wait_access_rate_window", lambda _spec: waits.append(True) or True)
    before = len(wire)
    assert solver.dispatch_access_validation(spec) == (receipt_state == "measured")
    if receipt_state == "measured":
        assert waits == [True] and len(broker.executor.tasks) == 2 and len(wire) > before
        assert solver.compile_summary(spec, terminal(spec))["validation_funnel"]["evidence_accepted"] == 1
    else:
        assert not waits and len(wire) == before and len(broker.executor.tasks) == 1
    before = len(wire)
    assert not solver.dispatch_access_validation(spec) and len(wire) == before


def test_standalone_hunter_core_discovery_needs_no_host_scripts_or_validator():
    import ast
    import os
    import subprocess
    import sys

    repo_root = Path(__file__).resolve().parents[1]
    hunter_core = repo_root / "mcp-servers" / "mcp-hunter" / "cco_hunter_core"
    for path in sorted(hunter_core.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            assert not any(
                name == "python_identity_discovery"
                or name.startswith("python_identity_discovery.")
                or name == "scripts"
                or name.startswith("scripts.")
                for name in names
            ), f"{path.name} unexpectedly imports host script module: {names}"

    script = (
        "import json, os, sys, types\n"
        f"sys.path[:] = [{str(repo_root / 'mcp-servers' / 'mcp-hunter')!r}, "
        f"{str(repo_root / 'mcp-servers' / 'mcp-memory-server')!r}] + "
        "[p for p in sys.path if 'mcp-validator' not in p and not p.endswith('/scripts')]\n"
        "for mod in ('cco_validator_core', 'python_identity_discovery', 'python_candidate_runtime', "
        "'evidence_trust', 'full_agent_python_broker', 'full_agent_python_solver'):\n"
        "    sys.modules[mod] = None\n"
        "sys.modules['authz_matrix'] = types.SimpleNamespace(build_identity_matrix=lambda *_a, **_kw: {})\n"
        "from cco_hunter_core.loop import execute_web_loop\n"
        "def fake_discover(target, identities):\n"
        "    return ({'status': 'ready', 'identities': len(identities), 'requests': 1, 'reasons': []},\n"
        "            identities, [{'url': target + 'objects/1', 'method': 'GET', 'resource_owner': 'first'}])\n"
        "report = execute_web_loop('http://127.0.0.1:9999/', live=True, run_id='isolated', crawl=False, fuzz_limit=0,\n"
        "                          identity_discover=fake_discover,\n"
        "                          identities={'first': {'headers': {}, 'role': 'member',\n"
        "                                                'test_data_only': True, 'owned_objects_private': True}})\n"
        "assert report['ok'] is True, report\n"
        "assert 'identity_discovery' in report['steps'], report\n"
        "assert report['identity_discovery']['status'] == 'ready', report\n"
        "assert 'identity_discovery_state' not in report, report\n"
        "os.environ['CCO_PYTHON_DISCOVERY_INVOCATION'] = 'active'\n"
        "try:\n"
        "    execute_web_loop('http://127.0.0.1:9999/', live=True, run_id='armed', crawl=False, fuzz_limit=0,\n"
        "                     identity_discover=fake_discover,\n"
        "                     identities={'first': {'headers': {}, 'role': 'member',\n"
        "                                           'test_data_only': True, 'owned_objects_private': True}})\n"
        "except ImportError:\n"
        "    pass\n"
        "else:\n"
        "    raise AssertionError('armed capture_state must fail closed without cco_validator_core')\n"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("CCO_PYTHON_DISCOVERY_")}
    proc = subprocess.run([sys.executable, "-I", "-c", script], env=env, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr


def test_unarmed_loop_blind_discover_and_load_discovery_fallback(replay_lab, monkeypatch):
    import os
    import subprocess
    import sys
    from conftest import load_server

    repo_root = Path(__file__).resolve().parents[1]
    script = (
        "import sys\n"
        f"sys.path[:] = [{str(repo_root / 'scripts')!r}, {str(repo_root / 'mcp-servers' / 'mcp-hunter')!r}] + "
        "[p for p in sys.path if 'mcp-validator' not in p]\n"
        "sys.modules['cco_validator_core'] = None\n"
        "from python_identity_discovery import load_discovery\n"
        "assert load_discovery('http://127.0.0.1:9999/', {'first': {'headers': {}}}, 24) == {}\n"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("CCO_PYTHON_DISCOVERY_")}
    proc = subprocess.run([sys.executable, "-I", "-c", script], env=env, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr

    from types import SimpleNamespace

    hunter = load_server("hunter")
    _broker, target, _wire = replay_lab
    monkeypatch.delenv("CCO_PYTHON_DISCOVERY_INVOCATION", raising=False)
    monkeypatch.delenv("CCO_PYTHON_DISCOVERY_STATE", raising=False)
    monkeypatch.setitem(sys.modules, "python_identity_discovery", None)
    fetched = []
    monkeypatch.setattr(hunter, "current_policy_gate",
                        lambda: SimpleNamespace(require_blind_policy=lambda _priv: None, stop_reason=None))
    def fake_get(url, headers):
        fetched.append(url)
        actor = "first" if "identity=first" in headers.get("Cookie", "") else "second"
        if url.rstrip("/") == target.rstrip("/"):
            return {"ok": True, "status": 200, "text": json.dumps({
                "current_user": {"id": actor}, "links": [{"href": "/objects/" + actor}]})}
        owner = url.rsplit("/", 1)[-1]
        if owner == actor:
            return {"ok": True, "status": 200, "text": json.dumps({
                "id": owner, "owner_id": owner, "marker": "owned-" + owner, "private": "owned-" + owner})}
        return {"ok": True, "status": 403, "text": ""}
    monkeypatch.setattr(hunter, "_blind_discovery_get", fake_get)
    actors = {name: {"headers": {"Cookie": "identity=" + name}, "role": "member",
                     "test_data_only": True, "owned_objects_private": True}
              for name in ("first", "second")}
    summary, _identities, _candidates = hunter._loop_blind_discover(target, actors, max_requests=12, sleep_s=0.0)
    assert summary["status"] != "blocked", summary
    assert summary["requests"] > 0 and "identity discovery policy unavailable" not in summary.get("reasons", [])
    assert fetched


def test_discovery_state_security_boundaries(replay_lab, monkeypatch, tmp_path):
    import os
    import time
    from types import SimpleNamespace
    from conftest import load_server
    from cco_validator_core.evidence import current_policy_hash, current_scope_revision
    from evidence_trust import attest, canonical_bytes
    from full_agent_python_broker import PythonBroker
    from full_agent_tasks import NativeTasks
    import full_agent_launcher as launcher
    from python_identity_discovery import (CONTEXT_ENV, MAX_BYTES, PURPOSE, STATE_ENV, TTL_SECONDS,
                                           capture_state, load_discovery, prepare_discovery, public_state,
                                           state_path)

    hunter = load_server("hunter")
    monkeypatch.delenv(CONTEXT_ENV, raising=False)
    monkeypatch.delenv(STATE_ENV, raising=False)
    monkeypatch.setattr(hunter, "current_policy_gate",
                        lambda: SimpleNamespace(require_blind_policy=lambda _priv: None, stop_reason=None))
    broker, target, _wire = replay_lab
    solver, spec = prepare_identity_replay(broker)
    row = solver.plan_candidates(spec)[0]
    names = json.loads(row["arguments"]["session_bindings"])
    actors = {name: {"headers": {"Cookie": "identity=" + name}, "role": "member", "test_data_only": True,
                     "owned_objects_private": True, "objects": [{"url": target + "objects/" + name,
                     "marker": "owned-" + name}], "identity_facts": [{"field": "principal", "value": name,
                     "source": "response_metadata", "confidence": "observed"}]} for name in names}
    original = type(broker.executor).__call__

    def with_state(self, task):
        result = original(self, task)
        result["result"]["output"]["identity_discovery_state"] = capture_state(actors)
        return result

    monkeypatch.setattr(type(broker.executor), "__call__", with_state)
    broker.invoke(row["tool"], row["arguments"])
    assert CONTEXT_ENV not in os.environ and STATE_ENV not in os.environ

    # Armed invocation without STATE_ENV or with non-absolute STATE_ENV fails closed and ignores CCO_HOME.
    prepare_discovery(broker, spec, row["arguments"])
    real_state = state_path()
    assert real_state.parent == broker.private
    global_cache = Path(os.environ["CCO_HOME"]) / "python-identity-discovery.json"
    global_cache.write_bytes(real_state.read_bytes())
    monkeypatch.delenv(STATE_ENV)
    with pytest.raises(ValueError, match="invalid identity discovery state path"):
        load_discovery(target, actors, 24)
    monkeypatch.setenv(STATE_ENV, "relative/state.json")
    with pytest.raises(ValueError, match="invalid identity discovery state path"):
        load_discovery(target, actors, 24)

    # Symlink cache fails closed in both load_discovery and hunter._loop_blind_discover.
    link_state = tmp_path / "symlink-state.json"
    link_state.symlink_to(real_state)
    monkeypatch.setenv(STATE_ENV, str(link_state))
    with pytest.raises(ValueError, match="symlink"):
        load_discovery(target, actors, 24)
    summary, _, _ = hunter._loop_blind_discover(target, actors, max_requests=24, sleep_s=0.0)
    assert summary["status"] == "blocked"

    # Oversized cache > 16 MiB fails closed.
    big_state = tmp_path / "oversized-state.json"
    with open(big_state, "wb") as handle:
        handle.truncate(MAX_BYTES + 1)
    monkeypatch.setenv(STATE_ENV, str(big_state))
    with pytest.raises(ValueError, match="archive limit"):
        load_discovery(target, actors, 24)

    # Expired cache (>= 300s) safely falls back to {} without extending observation age and cleans up once consumed.
    monkeypatch.setenv(STATE_ENV, str(real_state))
    envelope = json.loads(real_state.read_text())
    payload = copy.deepcopy(envelope["payload"])
    payload["prepared_at"] = 1.0
    real_state.write_bytes(canonical_bytes(attest(payload, PURPOSE)))
    assert load_discovery(target, actors, 24) == {}

    prepared = prepare_discovery(broker, spec, row["arguments"])
    envelope = json.loads(prepared.read_text())
    payload = copy.deepcopy(envelope["payload"])
    for state in payload["states"].values():
        state["observed_at"] = 1.0
    prepared.write_bytes(canonical_bytes(attest(payload, PURPOSE)))
    # Signing a different age does not change the original measured source state.
    before = len(_wire)
    with pytest.raises(ValueError, match="identity discovery sources missing"):
        load_discovery(target, actors, 24)
    assert prepared.exists() and len(_wire) == before

    # A genuinely expired observation is captured in the actual execution source.
    observed_at = time.time() - TTL_SECONDS - 1
    with monkeypatch.context() as patch:
        for actor in actors.values():
            patch.setitem(actor, "_discovery_observed_at", observed_at)
        broker.invoke(row["tool"], row["arguments"])
    prepared = prepare_discovery(broker, spec, row["arguments"])
    payload = json.loads(prepared.read_bytes())["payload"]
    assert set(payload["states"]) == set(names)
    assert all(state["observed_at"] == observed_at for state in payload["states"].values())
    assert observed_at < payload["prepared_at"] - TTL_SECONDS
    for source in payload["sources"]:
        report = json.loads(Path(source["reference"]["path"]).read_bytes())
        receipt = json.loads(Path(source["execution_reference"]["path"]).read_bytes())
        assert receipt["execution"]["result"]["output"] == report
        archive_ref = {**source["reference"],
                       "path": Path(source["reference"]["path"]).relative_to(broker.workdir).as_posix()}
        for name in source["state_names"]:
            assert public_state(payload["states"])[name] == report["identity_discovery_state"][name]
            assert broker.private_discovery_report(spec, archive_ref)["identity_discovery_state"][name] == payload["states"][name]
    before = len(_wire)
    assert load_discovery(target, actors, 24) == {}
    assert len(_wire) == before
    assert not prepared.exists()

    # Restore a fresh measured source for the unchanged controls below.
    broker.invoke(row["tool"], row["arguments"])

    # Valid cache is single-use and two brokers sharing CCO_HOME stay isolated.
    monkeypatch.setattr(type(broker.executor), "__call__", original)
    monkeypatch.delenv(CONTEXT_ENV, raising=False)
    monkeypatch.delenv(STATE_ENV, raising=False)
    other_root = tmp_path / "other-workdir"
    other_private = tmp_path / "other-private"
    other_root.mkdir()
    other_private.mkdir()
    other_broker = PythonBroker(
        budget=broker.budget,
        engine=broker.engine,
        executor=broker.executor,
        workdir=other_root,
        private=other_private,
        provider=broker.provider,
        models=broker.models,
        api_key=broker.api_key,
    )
    other_broker.tasks = NativeTasks(launcher.bootstrap_plan(target, other_root, solver_mode="python_loop"), other_root, {})
    first_state = prepare_discovery(broker, spec, row["arguments"])
    first_inv = os.environ[CONTEXT_ENV]
    second_state = prepare_discovery(other_broker, other_broker.tasks.specs[0], row["arguments"])
    assert first_state != second_state and first_state.parent == broker.private and second_state.parent == other_private
    assert first_state.exists() and second_state.exists()
    monkeypatch.setenv(STATE_ENV, str(first_state))
    monkeypatch.setenv(CONTEXT_ENV, first_inv)
    loaded = load_discovery(target, actors, 24)
    assert set(loaded) == set(names)
    assert not first_state.exists()
    assert second_state.exists()
    assert load_discovery(target, actors, 24) == {}

    # FIFO cache fails closed immediately without blocking.
    fifo_state = tmp_path / "fifo-state.json"
    os.mkfifo(fifo_state)
    monkeypatch.setenv(STATE_ENV, str(fifo_state))
    with pytest.raises(ValueError, match="regular file"):
        load_discovery(target, actors, 24)

    # Ordinary target / max_requests mismatch on a valid signed cache safely falls back to {}.
    mismatched_state = prepare_discovery(broker, spec, row["arguments"])
    assert load_discovery(target + "other", actors, 24) == {}
    assert not mismatched_state.exists()
    mismatched_budget = prepare_discovery(broker, spec, row["arguments"])
    assert load_discovery(target, actors, 12) == {}
    assert not mismatched_budget.exists()

    # Unknown-cost or errored execution receipts are never cached by prepare_discovery.
    receipt_path = Path(broker.tools[-1]["artifact"])
    receipt = json.loads(receipt_path.read_text())
    receipt["execution"].pop("actual_request_cost")
    receipt_path.write_text(json.dumps(receipt))
    prepare_discovery(broker, spec, row["arguments"])
    assert load_discovery(target, actors, 24) == {}
    assert current_scope_revision() and current_policy_hash()


def test_blk03_python_engine_rejects_public_equal_body_and_unknown_roles(replay_lab, monkeypatch):
    from cco_validator_core.egress import scoped_wire_gate
    from cco_validator_core.evidence import persist_result
    from conftest import load_server
    from python_candidate_runtime import authorization_controls_complete
    from wire_budget import campaign_wire_budget

    validator = load_server("validator")
    broker, target, _wire = replay_lab
    solver, spec = prepare_identity_replay(broker)

    # Preserve legacy raw validate_idor public-endpoint behavior untouched.
    import uuid
    with campaign_wire_budget(10, uuid.uuid4().hex), scoped_wire_gate(lambda _m, _u, _h: (True, "replay")):
        raw_public = json.loads(validator.validate_idor(
            target + "render/safe?term=public-readme",
            '{"Cookie": "identity=first"}',
            '{"Cookie": "identity=second"}',
            owner_marker="literal: public-readme",
        ))
    assert raw_public["verdict"] == "CONFIRMED"
    assert raw_public["evidence"]["owner_marker_in_anonymous_response"] is True
    assert authorization_controls_complete(raw_public) is False

    # Engine acceptance, summary, completed_member_batch, and seal must reject that raw public record.
    persist_dir = str(Path(raw_public["artifact"]["path"]).parent)
    row = solver.plan_candidates(spec)[0]
    original = type(broker.executor).__call__

    def force_public_idor(self, task):
        result = original(self, task)
        report = result["result"]["output"]
        for item in report.get("validations") or ():
            vid = item["validation_id"]
            tampered = copy.deepcopy(raw_public)
            tampered["validation_id"] = vid
            tampered["target"] = item["url"]
            tampered["execution_context"] = {
                "task_spec_id": spec.id,
                "url": item["url"],
                "method": "GET",
                "vuln_class": "authz-idor",
                "operation_id": item.get("operation_id"),
                "resource_owner": item.get("resource_owner", "first"),
                "identity": item.get("identity", "second"),
            }
            persist_result(tampered, persist_dir)
        return result

    monkeypatch.setattr(type(broker.executor), "__call__", force_public_idor)
    broker.invoke(row["tool"], row["arguments"])
    assert broker.validation_attempts(spec) == []
    assert broker.verified_findings(spec) == []
    summary = solver.compile_summary(spec, terminal(spec))
    assert summary["validation_outcomes"] == []
    assert summary["validation_funnel"]["evidence_accepted"] == 0
    assert solver.completed_member_batch(spec, broker.tasks.bindings) is False

    # Seal also rejects a public raw IDOR receipt if an access summary references it.
    public_seal_record = copy.deepcopy(raw_public)
    public_seal_record["target"] = target + "objects/first"
    persist_result(public_seal_record, persist_dir)
    summary_path = broker.tasks.summary_path(spec)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps({
        "phase": spec.phase,
        "target": spec.target,
        "findings": [{"vector": "authz-idor", "validation_id": public_seal_record["validation_id"]}],
    }))
    import hypothesis_ledger as hypotheses
    monkeypatch.setattr(hypotheses, "load_ledger",
                        lambda _path: {"hypotheses": [{"vector": "authz-idor", "status": "open"}], "target": spec.target})
    broker.tasks.active_spec = broker.tasks.specs[-1]
    with pytest.raises(ValueError, match="authorization controls"):
        broker.seal()

    obj_url = target + "objects/first"
    h_owner, h_atk, h_anon, h_diff = "a" * 64, "b" * 64, "c" * 64, "d" * 64
    def ctrl(role, status, digest):
        return {"role": role, "transport_ok": True, "request_url": obj_url, "method": "GET",
                "status": status, "response_sha256": digest, "response_length": 12}

    base_ctx = {"url": obj_url, "method": "GET", "resource_owner": "first", "identity": "second"}
    valid_confirmed = {
        "target": obj_url,
        "oracle": "content_match",
        "verdict": "CONFIRMED",
        "execution_context": copy.deepcopy(base_ctx),
        "request_evidence": [ctrl("owner", 200, h_owner), ctrl("attacker", 200, h_atk), ctrl("anonymous", 403, h_anon)],
        "evidence": {"owner_status": 200, "attacker_status": 200, "anonymous_status": 403,
                     "owner_marker_in_owner_response": True,
                     "owner_marker_in_attacker_response": True,
                     "owner_marker_in_anonymous_response": False,
                     "identity_fingerprints_distinct": True},
    }
    assert authorization_controls_complete(valid_confirmed) is True

    valid_unconfirmed = {
        "target": obj_url,
        "oracle": "content_match",
        "verdict": "UNCONFIRMED",
        "execution_context": copy.deepcopy(base_ctx),
        "request_evidence": [ctrl("owner", 200, h_owner), ctrl("attacker", 200, h_diff), ctrl("anonymous", 401, h_anon)],
        "evidence": {"owner_status": 200, "attacker_status": 200, "anonymous_status": 401,
                     "owner_marker_in_owner_response": True,
                     "owner_marker_in_attacker_response": False,
                     "owner_marker_in_anonymous_response": False},
    }
    assert authorization_controls_complete(valid_unconfirmed) is True

    bad_cases = [
        # Unknown extra role fails closed.
        {**copy.deepcopy(valid_confirmed), "request_evidence": [
            ctrl("owner", 200, h_owner), ctrl("attacker", 200, h_atk),
            ctrl("anonymous", 403, h_anon), ctrl("admin_extra", 200, h_diff)]},
        # Missing anonymous baseline fails closed for CONFIRMED.
        {**copy.deepcopy(valid_confirmed), "request_evidence": [ctrl("owner", 200, h_owner), ctrl("attacker", 200, h_atk)]},
        # Anonymous 200 / 302 / 500 fails closed.
        {**copy.deepcopy(valid_confirmed),
         "request_evidence": [ctrl("owner", 200, h_owner), ctrl("attacker", 200, h_atk), ctrl("anonymous", 200, h_anon)],
         "evidence": {**valid_confirmed["evidence"], "anonymous_status": 200}},
        {**copy.deepcopy(valid_confirmed),
         "request_evidence": [ctrl("owner", 200, h_owner), ctrl("attacker", 200, h_atk), ctrl("anonymous", 302, h_anon)],
         "evidence": {**valid_confirmed["evidence"], "anonymous_status": 302}},
        # Anonymous response carrying owner marker fails closed.
        {**copy.deepcopy(valid_confirmed),
         "evidence": {**valid_confirmed["evidence"], "owner_marker_in_anonymous_response": True}},
        # CONFIRMED without owner marker in attacker response fails closed.
        {**copy.deepcopy(valid_confirmed),
         "evidence": {**valid_confirmed["evidence"], "owner_marker_in_attacker_response": False}},
        # UNCONFIRMED 200 with equal owner/attacker hash or True attacker marker fails closed.
        {**copy.deepcopy(valid_unconfirmed),
         "request_evidence": [ctrl("owner", 200, h_owner), ctrl("attacker", 200, h_owner), ctrl("anonymous", 403, h_anon)],
         "evidence": {**valid_unconfirmed["evidence"], "anonymous_status": 403}},
        {**copy.deepcopy(valid_unconfirmed),
         "evidence": {**valid_unconfirmed["evidence"], "owner_marker_in_attacker_response": True}},
        # Contradictory evidence vs request_evidence fails closed.
        {**copy.deepcopy(valid_confirmed),
         "evidence": {**valid_confirmed["evidence"], "attacker_status": 403}},
        {**copy.deepcopy(valid_confirmed),
         "evidence": {**valid_confirmed["evidence"], "owner_marker_in_owner_response": False}},
    ]
    for bad in bad_cases:
        assert authorization_controls_complete(bad) is False, bad


def test_parameter_routing_defaults_missing_identity_to_anon_without_vault(python_broker):
    from python_candidate_runtime import parameter_candidates
    from test_python_candidate_runtime import catalog

    broker = python_broker
    catalog(broker)
    spec = broker.tasks.specs[2]
    target = spec.target
    broker.tasks.bindings = {
        "member-a": {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True},
        "member-b": {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True},
    }
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, broker.tasks.specs[1], [{"url": target + "search?q=alpha"}], identity=None)

    def all_surface_records():
        records = []
        for entry in broker.results:
            records.extend(solver.surface_records(
                broker.read_reference(entry["content_ref"]),
                entry["arguments"],
                spec,
                entry["content_ref"],
            ))
        return records

    observed_records = all_surface_records()
    assert observed_records and "identity" not in observed_records[0]
    for record in observed_records:
        record["source_spec_id"] = broker.tasks.specs[1].id
    rows = parameter_candidates(spec, observed_records, broker.tasks.bindings)
    assert rows and all(row["identity_ref"] == "anon" for row in rows)
    assert all("session_bindings" not in row["arguments"] and "cookie" not in row["arguments"]
               and "headers" not in row["arguments"] for row in rows)
    by_vector = {row["vector"]: row for row in rows}
    assert by_vector["injection-sqli"]["tool"] == "validator_validate_sqli"
    assert by_vector["injection-ssti"]["tool"] == "validator_validate_ssti"
    spec.vector = "injection-sqli"
    assert solver.context(spec)["session_bindings"] == {}
    spec.vector = ""

    # When direct validator is absent from spec.tools, still route anon without vault credentials.
    spec.tools = ("hunter_run_web_loop",)
    fallback_rows = parameter_candidates(spec, observed_records, broker.tasks.bindings)
    assert fallback_rows and all(row["tool"] == "hunter_run_web_loop" for row in fallback_rows)
    assert all("session_bindings" not in row["arguments"] for row in fallback_rows)

    # Single-URL anonymous observation without cookie/headers stamps identity="anon",
    # whereas explicit cookie/headers never silently stamp identity="anon".
    anon_ref = broker.view({"records": [{"url": target + "anon?q=1"}]}, "surface-anon")["content_ref"]
    anon_records = solver.surface_records(
        broker.read_reference(anon_ref),
        {"url": target + "anon?q=1"},
        spec,
        anon_ref,
    )
    assert anon_records and anon_records[0]["identity_ref"] == "anon"

    auth_ref = broker.view({"records": [{"url": target + "private?q=1"}]}, "surface-auth")["content_ref"]
    auth_records = solver.surface_records(
        broker.read_reference(auth_ref),
        {"url": target + "private?q=1", "cookie": "session=secret"},
        spec,
        auth_ref,
    )
    assert auth_records and "identity_ref" not in auth_records[0] and "identity" not in auth_records[0]


def test_discovery_reuse_across_disjoint_and_overlapping_pairs(replay_lab, monkeypatch):
    import os
    from types import SimpleNamespace
    from conftest import load_server
    from evidence_trust import attest, canonical_bytes
    from full_agent_broker import dump
    from python_identity_discovery import (CONTEXT_ENV, PURPOSE, STATE_ENV,
                                           capture_state, load_discovery, prepare_discovery)

    hunter = load_server("hunter")
    monkeypatch.delenv(CONTEXT_ENV, raising=False)
    monkeypatch.delenv(STATE_ENV, raising=False)
    monkeypatch.setattr(hunter, "current_policy_gate",
                        lambda: SimpleNamespace(require_blind_policy=lambda _priv: None, stop_reason=None))

    broker, target, _wire = replay_lab
    broker.tasks.bindings = {
        name: {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True}
        for name in ("first", "second", "third", "fourth")
    }
    solver = PythonSolver(broker, model="model")
    source, spec = broker.tasks.specs[1:3]
    observe(broker, solver, source, FROZEN["identity_pages"])
    broker.tasks.active_spec = spec

    # Batch 1 executes for ("first", "second") with real signed controls and captured discovery state.
    first_pair = {k: broker.tasks.bindings[k] for k in ("first", "second")}
    batch1_args = {
        "target": target, "live": True, "crawl": False,
        "blind_discovery": True, "blind_max_requests": 24, "max_validations": 16,
        "fuzz_limit": 0, "candidate_sample_limit": 0, "sleep_s": 0.2,
        "session_bindings": json.dumps(first_pair),
    }

    def actor_map(names):
        return {
            name: {
                "headers": {"Cookie": "identity=" + name},
                "role": "member",
                "test_data_only": True,
                "owned_objects_private": True,
                "objects": [{"url": target + "objects/" + name, "marker": "owned-" + name}],
                "identity_facts": [{"field": "principal", "value": name,
                                    "source": "response_metadata", "confidence": "observed"}],
            }
            for name in names
        }

    original_exec = type(broker.executor).__call__

    def with_batch1_state(self, task):
        result = original_exec(self, task)
        output = result["result"]["output"]
        if isinstance(output, dict) and output.get("ok"):
            output["identity_discovery_state"] = capture_state(actor_map(("first", "second")))
        return result

    monkeypatch.setattr(type(broker.executor), "__call__", with_batch1_state)
    broker.invoke("hunter_run_web_loop", batch1_args)
    monkeypatch.setattr(type(broker.executor), "__call__", original_exec)
    assert CONTEXT_ENV not in os.environ and STATE_ENV not in os.environ

    def fake_get(url, headers):
        cookie = headers.get("Cookie", "")
        actor = next((n for n in ("first", "second", "third", "fourth") if f"identity={n}" in cookie), "")
        obj_id = f"record-{actor}-0001"
        if url.rstrip("/") == target.rstrip("/"):
            return {"ok": True, "status": 200, "text": json.dumps({
                "current_user": {"id": actor},
                "links": [{"href": "/objects/" + obj_id, "id": obj_id, "owner_id": actor}]})}
        if url.endswith("/" + obj_id):
            return {"ok": True, "status": 200, "text": json.dumps({
                "id": obj_id, "owner_id": actor, "marker": "owned-" + actor, "private": "owned-" + actor})}
        return {"ok": True, "status": 403, "text": ""}

    monkeypatch.setattr(hunter, "_blind_discovery_get", fake_get)

    # Disjoint pair ("third", "fourth") must not inherit ("first", "second") state or fail validation.
    disjoint_args = {**batch1_args, "session_bindings": json.dumps({k: broker.tasks.bindings[k] for k in ("third", "fourth")})}
    disjoint_path = prepare_discovery(broker, spec, disjoint_args)
    disjoint_payload = json.loads(disjoint_path.read_text())["payload"]
    assert disjoint_payload["states"] == {} and disjoint_payload["sources"] == []
    assert load_discovery(target, actor_map(("third", "fourth")), 24) == {}
    assert not disjoint_path.exists()

    disjoint_path = prepare_discovery(broker, spec, disjoint_args)
    summary_disjoint, _, _ = hunter._loop_blind_discover(
        target, actor_map(("third", "fourth")), max_requests=24, sleep_s=0.0)
    monkeypatch.delenv(CONTEXT_ENV, raising=False)
    monkeypatch.delenv(STATE_ENV, raising=False)
    assert summary_disjoint["status"] == "ready"
    assert "identity discovery policy unavailable" not in summary_disjoint.get("reasons", [])

    # Overlapping pair ("first", "third") reuses only "first" and retains source bindings ["first", "second"].
    overlap_args = {**batch1_args, "session_bindings": json.dumps({k: broker.tasks.bindings[k] for k in ("first", "third")})}
    overlap_path = prepare_discovery(broker, spec, overlap_args)
    overlap_payload = json.loads(overlap_path.read_text())["payload"]
    assert list(overlap_payload["states"]) == ["first"]
    assert len(overlap_payload["sources"]) == 1
    assert overlap_payload["sources"][0]["bindings"] == ["first", "second"]
    reused = load_discovery(target, actor_map(("first", "third")), 24)
    assert list(reused) == ["first"]
    assert not overlap_path.exists()

    prepare_discovery(broker, spec, overlap_args)
    summary_overlap, _, _ = hunter._loop_blind_discover(
        target, actor_map(("first", "third")), max_requests=24, sleep_s=0.0)
    monkeypatch.delenv(CONTEXT_ENV, raising=False)
    monkeypatch.delenv(STATE_ENV, raising=False)
    assert summary_overlap["status"] == "ready"
    assert "identity discovery policy unavailable" not in summary_overlap.get("reasons", [])

    # Negative security controls on signed source["bindings"] and covered states.
    base_state = prepare_discovery(broker, spec, overlap_args)
    base_payload = json.loads(base_state.read_text())["payload"]
    inv = os.environ[CONTEXT_ENV]

    bad_checks = []
    p1 = copy.deepcopy(base_payload)
    p1["sources"][0]["bindings"] = ["first"]  # omits counterparty "second" from signed control pair
    bad_checks.append((p1, "controls are no longer current"))

    p2 = copy.deepcopy(base_payload)
    p2["sources"][0]["bindings"] = []
    bad_checks.append((p2, "source bindings invalid"))

    p3 = copy.deepcopy(base_payload)
    p3["states"]["third"] = copy.deepcopy(p3["states"]["first"])
    bad_checks.append((p3, "sources missing"))

    p4 = copy.deepcopy(base_payload)
    extra_src = copy.deepcopy(p4["sources"][0])
    extra_src["bindings"] = ["second", "fourth"]
    p4["sources"].append(extra_src)
    bad_checks.append((p4, "source unused"))

    for idx, (tampered_payload, err_match) in enumerate(bad_checks):
        path_i = base_state.with_name(f"tamper-{idx}.json")
        path_i.write_bytes(canonical_bytes(attest(tampered_payload, PURPOSE)))
        monkeypatch.setenv(STATE_ENV, str(path_i))
        monkeypatch.setenv(CONTEXT_ENV, inv)
        with pytest.raises(ValueError, match=err_match):
            load_discovery(target, actor_map(("first", "third")), 24)
        dump(path_i, json.loads(path_i.read_text()))  # exercise dump import & ensure valid json before cleanup

    monkeypatch.delenv(CONTEXT_ENV, raising=False)
    monkeypatch.delenv(STATE_ENV, raising=False)


def test_pairwise_member_batches_cover_all_directed_owner_attacker_checks(python_broker):
    from authz_matrix import build_identity_matrix
    from cco_hunter_core.candidates import candidate_key

    broker = python_broker
    spec = broker.tasks.specs[2]
    target = spec.target
    members = ("u1", "u2", "u3", "u4")
    broker.tasks.bindings = {
        name: {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True}
        for name in members
    }
    solver = PythonSolver(broker, model="model")
    batches = solver.member_batches(spec)
    assert len(batches) == 6
    assert len({tuple(sorted(batch)) for batch in batches}) == 6

    objects_per_owner = 4
    owned_by = {
        name: [
            {
                "resource_id": f"{name}-obj-{idx}",
                "tenant": f"unresolved:{name}",
                "family": "/objects",
                "test_data_only": True,
                "owner_identity": name,
                "url": f"{target}objects/{name}-obj-{idx}",
            }
            for idx in range(objects_per_owner)
        ]
        for name in members
    }

    directed_keys = []
    for batch in batches:
        identities = {
            name: {
                "role": "member",
                "test_data_only": True,
                "identity_facts": [
                    {"field": "principal", "value": name, "source": "response_metadata", "evidence": target},
                    {"field": "authority", "value": target, "source": "response_metadata", "evidence": target},
                    {"field": "tenant", "value": "shared-tenant", "source": "response_metadata", "evidence": target},
                ],
            }
            for name in batch
        }
        resources = [obj for name in batch for obj in owned_by[name]]
        matrix = build_identity_matrix(identities, resources)["matrix"]
        cross_checks = [row for row in matrix if row["identity"] in batch and row["identity"] != row["owner_identity"]]
        assert len(cross_checks) == 2 * objects_per_owner
        for row in cross_checks:
            directed_keys.append(candidate_key({
                "vuln_class": "bola",
                "url": f"{target}objects/{row['resource_key']}",
                "identity": row["identity"],
                "resource_owner": row["owner_identity"],
                "resource_key": row["resource_key"],
            }))
    # C(4,2) = 6 unordered pairs map to 12 directed pairs -> 4 * 3 * 4 = 48 unique checks.
    assert len(directed_keys) == len(members) * (len(members) - 1) * objects_per_owner == 48
    assert len(set(directed_keys)) == 48


def test_holdout_validation_check_accounting_derives_pairs_and_parameters(tmp_path):
    from itertools import combinations

    # Multi-identity API fixture: 4 identities -> 6 pairs, 4 objects/owner -> 48 checks (24+24).
    identities = ("member-a", "member-b", "member-c", "member-d")
    api_cases = [
        {
            "path": f"/api/records/{owner}-{idx}",
            "owner": owner,
            "denied_identities": [other for other in identities if other != owner],
            "expected": "positive" if idx < 2 else "negative",
        }
        for owner in identities
        for idx in range(4)
    ]
    pairs = {tuple(sorted(pair)) for pair in combinations(identities, 2)}
    expected_api = expected_validation_checks(api_cases, pairs=pairs)
    assert len(expected_api) == 48
    assert sum(v == "CONFIRMED" for v in expected_api.values()) == 24
    assert sum(v == "UNCONFIRMED" for v in expected_api.values()) == 24

    # Generic scaling: 3 identities -> 3 pairs, 2 objects/owner -> 12 checks (6+6).
    small_ids = ("u1", "u2", "u3")
    small_cases = [
        {
            "path": f"/api/records/{owner}-{idx}",
            "owner": owner,
            "denied_identities": [other for other in small_ids if other != owner],
            "expected": "positive" if idx == 0 else "negative",
        }
        for owner in small_ids
        for idx in range(2)
    ]
    small_pairs = {tuple(sorted(pair)) for pair in combinations(small_ids, 2)}
    expected_small = expected_validation_checks(small_cases, pairs=small_pairs)
    assert len(expected_small) == 12
    assert sum(v == "CONFIRMED" for v in expected_small.values()) == 6
    assert sum(v == "UNCONFIRMED" for v in expected_small.values()) == 6

    # Observed ledger + artifact extraction catches dedup, missing pairs, and verdict parity.
    work = tmp_path / "solver"
    (work / "validator-artifacts").mkdir(parents=True)
    validations = []
    for idx, ((owner, attacker, path), verdict) in enumerate(sorted(expected_small.items())):
        rel = f"validator-artifacts/v-{idx}.json"
        (work / rel).write_text(json.dumps({
            "verdict": verdict,
            "execution_context": {
                "resource_owner": owner,
                "identity": attacker,
                "url": f"http://127.0.0.1:8080{path}",
            },
        }), encoding="utf-8")
        validations.append({
            "endpoint": f"http://127.0.0.1:8080{path}",
            "identity": attacker,
            "verdict": verdict,
            "artifact": rel,
        })
    observed_keys, observed_verdicts = observed_validation_checks(work, validations, paired=True)
    assert len(observed_keys) == len(set(observed_keys)) == len(validations) == 12
    assert set(observed_keys) == set(expected_small)
    assert observed_verdicts == expected_small

    # Single-identity parameter fixture remains 16 checks (8 CONFIRMED + 8 UNCONFIRMED).
    param_cases = [
        {"path": f"/lookup/{idx}", "expected": "positive" if idx < 8 else "negative"}
        for idx in range(16)
    ]
    expected_param = expected_validation_checks(param_cases)
    assert len(expected_param) == 16
    assert sum(v == "CONFIRMED" for v in expected_param.values()) == 8
    assert sum(v == "UNCONFIRMED" for v in expected_param.values()) == 8


def test_mixed_parameters_and_partially_accepted_or_ineligible_groups_never_drop_residuals(replay_lab, monkeypatch):
    broker, target, wire = replay_lab
    solver = PythonSolver(broker, model="model", recent_results=0)
    source, spec = broker.tasks.specs[1:3]
    pages = [
        # Mixed params under /search/mixed -> must not slice, run as direct residuals.
        {"url": target + "search/mixed"},
        {"url": target + "search/mixed/0-unsafe?term=alpha"},
        {"url": target + "search/mixed/1-safe?sort=alpha"},
        # Partially accepted parent /search/parent with narrower /search/parent/pending sub-index.
        {"url": target + "search/parent"},
        {"url": target + "search/parent/done-0-safe?term=alpha"},
        {"url": target + "search/parent/pending"},
        {"url": target + "search/parent/pending/0-unsafe?term=alpha"},
        {"url": target + "search/parent/pending/1-safe?term=alpha"},
        # Group containing an ineligible descendant -> must not slice, eligible leaves run directly.
        {"url": target + "search/guarded"},
        {"url": target + "search/guarded/bad?term=alpha", "method": "POST"},
        {"url": target + "search/guarded/0-safe?term=alpha"},
        {"url": target + "search/guarded/1-unsafe?term=alpha"},
    ]
    observe(broker, solver, source, pages)
    broker.tasks.active_spec = spec

    # Pre-execute done-0-safe SQLi directly so /search/parent is partially accepted for SQLi.
    done_sqli = next(row for row in solver.plan_candidates(spec)
                     if row["route"] == target + "search/parent/done-0-safe?term=alpha"
                     and row["vector"] == "injection-sqli")
    broker.invoke(done_sqli["tool"], done_sqli["arguments"])
    solver.refresh_candidate_evidence(spec)
    assert done_sqli["evidence_accepted"]

    # Parent group must refuse SQLi slice (would replay done-0-safe) and guarded group must refuse both.
    rows = solver.plan_candidates(spec)
    assert solver.parameter_slice(spec, rows, target + "search/parent", "readonly_sqli_boolean") is None
    assert solver.parameter_slice(spec, rows, target + "search/guarded", "readonly_sqli_boolean") is None
    assert solver.parameter_slice(spec, rows, target + "search/mixed", "readonly_sqli_boolean") is None
    assert solver.parameter_slice(spec, rows, target + "search/parent/pending", "readonly_sqli_boolean") is not None

    assert solver.dispatch_access_validation(spec)
    # No replay of pre-executed done-0-safe SQLi.
    assert sum(1 for t in broker.executor.tasks
               if t["tool_name"] == "validator_validate_sqli"
               and json.loads(t["args_json"])["target_url"] == done_sqli["route"]) == 1
    # Narrower /search/parent/pending batched for both SQLi & SSTI; remaining done-0-safe SSTI runs as direct residual.
    hunter_targets = {(json.loads(t["args_json"])["target"], json.loads(t["args_json"])["validation_profile"])
                      for t in broker.executor.tasks if t["tool_name"] == "hunter_run_web_loop"}
    assert hunter_targets == {
        (target + "search/parent/pending", "readonly_sqli_boolean"),
        (target + "search/parent/pending", "readonly_ssti_arithmetic"),
    }
    # Every eligible leaf across mixed/guarded/pending settled without dropping residuals; POST row stays ineligible.
    final_rows = solver.plan_candidates(spec)
    eligible = [r for r in final_rows if r["eligible"]]
    ineligible = [r for r in final_rows if not r["eligible"]]
    assert len(eligible) == 14 and all(r["evidence_accepted"] for r in eligible)
    assert len(ineligible) == 1 and ineligible[0]["reason_code"] == "unsupported_readonly_method"
    assert not ineligible[0]["executed"]


@pytest.mark.parametrize("count,expected_tasks,expected_tool", [
    (4, 2, "hunter_run_web_loop"),
    (6, 12, "validator_validate_"),
])
def test_flat_surface_batches_within_fuzz_limit_and_falls_back_cleanly_above_limit(
    replay_lab, monkeypatch, count, expected_tasks, expected_tool
):
    broker, target, _wire = replay_lab
    solver = PythonSolver(broker, model="model", recent_results=0)
    source, spec = broker.tasks.specs[1:3]
    pages = [{"url": target + f"search/{idx}-{'unsafe' if idx % 2 == 0 else 'safe'}?term=alpha"}
             for idx in range(count)]
    observe(broker, solver, source, pages)
    broker.tasks.active_spec = spec
    assert solver.dispatch_access_validation(spec)
    assert len(broker.executor.tasks) == expected_tasks
    assert all(task["tool_name"].startswith(expected_tool) for task in broker.executor.tasks)
    rows = solver.plan_candidates(spec)
    assert len(rows) == count * 2
    assert all(r["evidence_accepted"] and r["validation_state"] == "TESTED" for r in rows)


def test_pairwise_partial_evidence_keeps_discovery_continuation_strict_and_tamper_revokes(replay_lab, monkeypatch):
    import python_identity_discovery as discovery
    from cco_validator_core import load_validation

    broker, _target, _wire = replay_lab
    solver, spec = prepare_identity_replay(broker)
    solver.batches_by_task[spec.id] = solver.batches_by_task[spec.id][:1]
    batch = solver.batches_by_task[spec.id][0]
    row = solver.plan_candidates(spec)[0]

    # Run a complete pair first, then construct a partial variant and verify discovery cache stays strict.
    original = type(broker.executor).__call__
    recorded_vids = []

    def capture_execute(self, task):
        result = original(self, task)
        for item in result["result"]["output"].get("validations", []):
            recorded_vids.append(item["validation_id"])
        return result

    monkeypatch.setattr(type(broker.executor), "__call__", capture_execute)
    assert solver.dispatch_access_validation(spec)
    assert solver.completed_member_batch(spec, batch) is True
    access_summary = solver.compile_summary(spec, terminal(spec))
    assert access_summary["pair_progress"]["complete_pairs"] == 1
    assert access_summary["identity_comparisons"][0]["status"] == "TESTED"
    solver.summaries[spec.id] = access_summary

    # Tampering one signed leaf in the completed pair revokes pair & leaf acceptance on report and blocks discovery reuse.
    assert recorded_vids
    tampered_rec = load_validation(recorded_vids[0])
    Path(tampered_rec["artifact"]["path"]).write_text("{}")

    discovery_path = discovery.prepare_discovery(broker, spec, row["arguments"])
    discovery_payload = json.loads(discovery_path.read_bytes())["payload"]
    assert discovery_payload["states"] == {} and discovery_payload["sources"] == []

    report_spec = broker.tasks.specs[3]
    report = solver.compile_summary(report_spec, terminal(report_spec))
    assert solver.completed_member_batch(spec, batch) is False
    assert report["validation_funnels"][spec.id]["evidence_accepted"] == 0
    assert report["leaf_validation_funnels"][spec.id]["invalid_evidence"] >= 1
    assert report["pair_progress_by_task"][spec.id]["complete_pairs"] == 0
    assert report["identity_comparisons"][0]["status"] == "NOT TESTED"
    assert report["identity_comparisons"][0]["reason_code"] == "invalid_or_missing_signed_evidence"
    assert report["status"] == "partial"
    assert any(g["reason_code"] == "invalid_or_missing_signed_evidence" for g in report["coverage_gaps"])


