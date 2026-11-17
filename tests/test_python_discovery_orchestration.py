"""Tests for host discovery continuation, JSON hypermedia normalization, and authenticated entry bootstrap."""
from __future__ import annotations

import json
from typing import Any

import pytest

import full_agent_launcher as launcher
from full_agent_budget import BudgetError, provider_json
from full_agent_python_broker import CRAWL_TOOL, READ_TOOL, SUMMARY_TOOL
from full_agent_python_solver import PythonSolver
from python_discovery_runtime import extract_json_hypermedia
from test_full_agent_preflight import mock_provider
from test_full_agent_python_solver import python_broker, terminal


def _setup_enum_with_recon(broker: Any, solver: PythonSolver, body: Any, *, url: str | None = None) -> tuple[Any, Any]:
    recon, enum_spec = broker.tasks.specs[0], broker.tasks.specs[1]
    target_url = url or recon.target
    payload = {"status_code": 200, "text": body} if isinstance(body, str) else body
    view = broker.view(payload)
    broker.results.append({
        "spec_id": recon.id,
        "tool": "kali-tools_curl_request",
        "arguments": {"url": target_url, "follow_redirects": False},
        **view,
    })
    recon_summary = solver.compile_summary(recon, terminal(recon))
    solver.summaries[recon.id] = recon_summary
    recon_path = broker.tasks.summary_path(recon)
    recon_path.parent.mkdir(parents=True, exist_ok=True)
    recon_path.write_bytes(provider_json(recon_summary))
    broker.tasks.active_spec = enum_spec
    return recon, enum_spec


def _complete_enum_to_access(broker: Any, solver: PythonSolver, enum_spec: Any) -> Any:
    access_spec = broker.tasks.specs[2]
    enum_summary = solver.compile_summary(enum_spec, terminal(enum_spec))
    solver.summaries[enum_spec.id] = enum_summary
    enum_path = broker.tasks.summary_path(enum_spec)
    enum_path.parent.mkdir(parents=True, exist_ok=True)
    enum_path.write_bytes(provider_json(enum_summary))
    broker.handoffs["access"] = {"producer_spec_id": enum_spec.id, "target": enum_spec.target, "files": {}}
    broker.tasks.active_spec = access_spec
    return access_spec


def test_empty_anonymous_json_bootstraps_authenticated_entry_discovery_without_fabricated_provenance(
    python_broker, monkeypatch
):
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
    _, enum_spec = _setup_enum_with_recon(
        python_broker,
        solver,
        '{"service":"record archive","links":[]}',
    )
    access_spec = _complete_enum_to_access(python_broker, solver, enum_spec)

    # Bypass handoff file check for unit-level planning & dispatch test.
    monkeypatch.setattr(python_broker, "_check_handoff", lambda _spec: None)
    monkeypatch.setattr(
        "python_identity_discovery.prepare_discovery",
        lambda *_a, **_kw: python_broker.private / "unused-discovery-state.json",
    )
    monkeypatch.setenv("CCO_DISCOVERY_CONTEXT", "{}")

    candidates = solver.plan_candidates(access_spec)
    assert len(candidates) == 1
    idor = candidates[0]
    assert idor["vector"] == "access-idor"
    assert idor["tool"] == "hunter_run_web_loop"
    assert idor["eligible"] is True
    assert idor.get("entry_discovery") is True
    assert idor["arguments"]["target"] == access_spec.target
    assert idor["arguments"]["blind_discovery"] is True
    assert json.loads(idor["arguments"]["session_bindings"]) == {
        "member-a": {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True},
        "member-b": {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True},
    }
    # Provenance must reflect the actual observed entry response, never fabricated objects.
    assert len(idor["provenance"]) == 1
    assert idor["provenance"][0]["source_spec_id"] == "recon-1"
    assert not any(
        gap_row["reason_code"] == "missing_declared_upstream_observations"
        for gap_row in solver.coverage_gaps.get(access_spec.id, [])
    )

    # Without eligible batches (or without hunter tool), the missing-observation gap still applies.
    no_hunter_spec = python_broker.tasks.specs[2]
    original_tools = list(no_hunter_spec.tools)
    no_hunter_spec.tools = ["validator_validate_sqli"]
    solver.candidates_by_task.pop(no_hunter_spec.id, None)
    solver.coverage_gaps.pop(no_hunter_spec.id, None)
    blocked_rows = solver.plan_candidates(no_hunter_spec)
    assert blocked_rows and not blocked_rows[0]["eligible"]
    assert any(
        gap_row["reason_code"] == "missing_declared_upstream_observations"
        for gap_row in solver.coverage_gaps.get(no_hunter_spec.id, [])
    )
    no_hunter_spec.tools = original_tools


def test_stale_and_foreign_identities_rejected_in_entry_bootstrap_and_surface(python_broker, monkeypatch):
    target = python_broker.tasks.specs[0].target
    python_broker.tasks.bindings = {
        "member-a": {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True},
        "member-b": {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True},
        "foreign-c": {"target": "http://outside.invalid/", "role": "member", "test_data_only": True, "owned_objects_private": True},
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
    assert all("foreign-c" not in batch for batch in solver.batches_by_task["access-3"])

    _, enum_spec = _setup_enum_with_recon(python_broker, solver, '{"service":"archive","links":[]}')
    access_spec = _complete_enum_to_access(python_broker, solver, enum_spec)

    # Mutate member-b to a foreign target after init: entry bootstrap must reject it.
    python_broker.tasks.bindings["member-b"]["target"] = "http://outside.invalid/"
    rows = solver.plan_candidates(access_spec)
    assert len(rows) == 1 and not rows[0]["eligible"]
    assert rows[0]["reason_code"] == "missing_synthetic_owned_session_prerequisite"

    # Restore valid target, then inject stale primary session feedback -> admit_candidate rejects.
    python_broker.tasks.bindings["member-b"]["target"] = target
    solver.candidates_by_task.pop(access_spec.id, None)
    rows = solver.plan_candidates(access_spec)
    assert rows[0]["eligible"]
    stale_view = python_broker.view({
        "ok": False,
        "skipped": [{"reason_code": "session_not_recently_verified"}],
    })
    python_broker.results.append({
        "spec_id": access_spec.id,
        "tool": "hunter_run_web_loop",
        "arguments": {"session_bindings": rows[0]["arguments"]["session_bindings"]},
        **stale_view,
    })
    monkeypatch.setattr(python_broker, "_check_handoff", lambda _spec: None)
    assert solver.admit_candidate(access_spec, rows[0]) is False
    assert rows[0]["reason_code"] == "session_not_recently_verified"


def test_html_and_json_hypermedia_normalization_malformed_json_and_cycles(python_broker):
    target = python_broker.tasks.specs[0].target
    solver = PythonSolver(python_broker, model="model")
    enum_spec = python_broker.tasks.specs[1]

    # Malformed JSON must not crash or invent URLs.
    malformed_ref = python_broker.view({"status_code": 200, "text": "{not-json"})["content_ref"]
    assert solver.surface_records(
        python_broker.read_reference(malformed_ref),
        {"url": target},
        enum_spec,
        malformed_ref,
    ) == []

    # Arbitrary scalars, numeric IDs, and disallowed/foreign schemes must not become URLs.
    payload = {
        "service": "record archive",
        "id": 42,
        "owner": "alice",
        "items": [
            "raw-scalar-should-ignore",
            12345,
            {"id": "999", "href": "/records/999?view=full", "identity_ref": "member-a"},
            {"id": "1000", "url": "javascript:alert(1)"},
            {"id": "1001", "url": "https://outside.invalid/leak"},
        ],
        "pagination": {"next_url": "/records?page=2"},
        "_links": {"next": {"href": "/records?page=2"}, "self": {"href": "/records?page=1"}},
    }
    extracted, truncated = extract_json_hypermedia(payload, target)
    assert not truncated
    urls = [row["url"] for row in extracted]
    assert urls == [
        target + "records/999?view=full",
        target + "records?page=2",
        target + "records?page=1",
    ]
    assert extracted[0]["identity_ref"] == "member-a"
    assert extracted[1]["link_relation"] == "pagination"

    # Verify surface_records preserves authenticated identity attribution from args and records.
    json_ref = python_broker.view({"status_code": 200, "text": json.dumps(payload)})["content_ref"]
    surface = solver.surface_records(
        python_broker.read_reference(json_ref),
        {"url": target + "records?page=1"},
        enum_spec,
        json_ref,
    )
    by_url = {row["url"]: row for row in surface}
    assert by_url[target + "records/999?view=full"]["identity_ref"] == "member-a"
    assert by_url[target + "records?page=2"]["identity_ref"] == "anon"
    assert by_url[target + "records?page=2"]["link_relation"] == "pagination"

    # Per-call slice limit preserves truncated flag rather than marking exhaustion.
    many_payload = {"links": [f"/items/{idx}" for idx in range(10)]}
    sliced, is_truncated = extract_json_hypermedia(many_payload, target, max_items=4)
    assert len(sliced) == 4 and is_truncated is True


def test_dispatch_discovery_handles_cycles_and_pagination_frontier_continuation(python_broker, monkeypatch):
    target = python_broker.tasks.specs[0].target
    solver = PythonSolver(python_broker, model="model")
    _, enum_spec = _setup_enum_with_recon(
        python_broker,
        solver,
        json.dumps({"items": [{"href": "/records/1"}], "next": "/records?page=2"}),
        url=target + "records?page=1",
    )

    pages = {
        target + "records?page=2": {"items": [{"href": "/records/2"}], "prev": "/records?page=1", "next": "/records?page=3"},
        target + "records?page=3": {"items": [{"href": "/records/3"}], "prev": "/records?page=2", "next": "/records?page=4"},
        target + "records?page=4": {"items": [], "prev": "/records?page=3"},
        target + "records/1": {"id": 1},
        target + "records/2": {"id": 2},
        target + "records/3": {"id": 3},
    }
    visited: list[str] = []

    def fake_exec(self, task):
        self.tasks.append(task)
        url = json.loads(task["args_json"])["url"]
        visited.append(url)
        body = json.dumps(pages[url])
        return {"actual_request_cost": 1, "result": {"output": {"status_code": 200, "text": body}}}

    monkeypatch.setattr(type(python_broker.executor), "__call__", fake_exec)

    # First bounded slice (max_actions=3) leaves remaining frontier pending instead of exhausting it.
    assert solver.dispatch_discovery(enum_spec, reason="premature_enum_summary", max_actions=3) is True
    assert len(visited) == 3
    assert target + "records?page=1" not in visited  # Cycle back to page=1 must not replay!
    frontier_mid = solver.discovery_frontier(enum_spec)
    assert frontier_mid["counts"]["pending"] >= 1
    assert any(state.continuation.get("has_more_pending") for state in solver.task_discovery_states(enum_spec).values())

    # Second continuation finishes remaining frontier and stops cleanly when exhausted.
    assert solver.dispatch_discovery(enum_spec, reason="continuation", max_actions=6) is True
    assert solver.dispatch_discovery(enum_spec, reason="continuation", max_actions=6) is False
    assert visited.count(target + "records?page=2") == 1
    assert visited.count(target + "records?page=3") == 1
    assert visited.count(target + "records?page=4") == 1
    assert solver.discovery_frontier(enum_spec)["counts"]["pending"] == 0


def test_premature_enum_summary_and_archive_stagnation_preserve_handoff_reserves(python_broker, monkeypatch):
    target = python_broker.tasks.specs[0].target
    python_broker.tasks.bindings = {
        "member-a": {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True},
        "member-b": {"target": target, "role": "member", "test_data_only": True, "owned_objects_private": True},
        "admin-a": {"target": target, "role": "admin", "test_data_only": True, "owned_objects_private": True},
    }
    solver = PythonSolver(python_broker, model="model")
    _, enum_spec = _setup_enum_with_recon(
        python_broker,
        solver,
        '<a href="/api/items?q=1">Items</a><a href="/api/users?id=2">Users</a>',
    )
    policy = python_broker.runtime_policy
    assert policy.handoff_reserves[enum_spec.id] == 4

    # Consume 10 of 12 non-reserved enum calls, leaving only 2 discovery calls + 4 reserved handoff calls.
    policy.tool_calls[enum_spec.id] = 10
    assert policy.tool_allowance(enum_spec) == 2

    large_ref = python_broker.archive({"blob": "x" * 3500}, "tool-result")
    fetched_urls: list[str] = []

    def fake_exec(self, task):
        self.tasks.append(task)
        if task["tool_name"] == "kali-tools_curl_request":
            url = json.loads(task["args_json"])["url"]
            fetched_urls.append(url)
            return {"actual_request_cost": 1, "result": {"output": {"status_code": 200, "text": "<p>ok</p>"}}}
        return {"actual_request_cost": 1, "result": {"output": {"status": "fresh"}}}

    monkeypatch.setattr(type(python_broker.executor), "__call__", fake_exec)

    turns = 0

    def completion(body):
        nonlocal turns
        turns += 1
        ctx = json.loads(body["messages"][1]["content"])
        if turns <= 4:
            # Turn 1 reads initial slice, turn 2 stalls once, turns 3-4 produce 2 archive_read_no_progress events.
            msg: dict[str, Any] = {
                "tool_calls": [{
                    "function": {
                        "name": READ_TOOL,
                        "arguments": json.dumps({"path": large_ref["path"], "offset": 0, "limit": 3000}),
                    }
                }]
            }
        else:
            # After host continuation runs, discovery_frontier shows completed work.
            assert ctx["discovery_frontier"]["counts"]["completed"] >= 2
            msg = {"content": json.dumps(terminal(enum_spec))}
        mock_provider(
            monkeypatch,
            python_broker,
            {"choices": [{"message": msg}], "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}},
        )
        return python_broker.__class__.completion(python_broker, body)

    # 4 reads + 2 curls = 6 calls; starting from 6 leaves 12 used and preserves all 4 handoff reserves.
    policy.tool_calls[enum_spec.id] = 6
    monkeypatch.setattr(python_broker, "completion", completion)
    summary = solver.phase(enum_spec)
    assert summary["status"] == "done"
    assert len(fetched_urls) == 2
    assert policy.tool_calls[enum_spec.id] == 12
    assert policy.handoff_reserves[enum_spec.id] == 4
    assert not policy.host_continuing

    # Now handoff() must succeed without hitting handoff_tool_budget_exhausted!
    def mock_handoff_invoke(tool, args):
        policy.check_tool(enum_spec, tool)
        if tool == "kali-tools_ledger_prepare_handoff":
            python_broker.handoffs["access"] = {"producer_spec_id": enum_spec.id, "target": target, "files": {}}
            (python_broker.workdir / "handoff-access.json").write_text("{}")
            return python_broker.view({"ok": True})
        return python_broker.view({"status": "fresh"})

    monkeypatch.setattr(python_broker, "invoke", mock_handoff_invoke)
    python_broker.handoff()
    assert policy.tool_calls[enum_spec.id] == 16


def test_premature_enum_summary_without_probes_triggers_host_discovery(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    _, enum_spec = _setup_enum_with_recon(
        python_broker,
        solver,
        '{"items":[{"href":"/api/orders/1"}],"next":"/api/orders?page=2"}',
    )
    visited: list[str] = []

    def fake_exec(self, task):
        self.tasks.append(task)
        url = json.loads(task["args_json"])["url"]
        visited.append(url)
        return {"actual_request_cost": 1, "result": {"output": {"status_code": 200, "text": '{"items":[]}'}}}

    monkeypatch.setattr(type(python_broker.executor), "__call__", fake_exec)
    original_completion = python_broker.completion
    seen_frontiers = []

    def completion(body):
        ctx = json.loads(body["messages"][1]["content"])
        seen_frontiers.append(ctx["discovery_frontier"]["counts"])
        mock_provider(
            monkeypatch,
            python_broker,
            {
                "choices": [{"message": {"content": json.dumps(terminal(enum_spec))}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110},
            },
        )
        return original_completion(body)

    monkeypatch.setattr(python_broker, "completion", completion)
    summary = solver.phase(enum_spec)
    assert summary["status"] == "done"
    assert len(seen_frontiers) == 2
    assert seen_frontiers[0]["pending"] == 2
    assert seen_frontiers[1]["pending"] == 0
    assert seen_frontiers[1]["completed"] == 3
    assert set(visited) == {enum_spec.target + "api/orders/1", enum_spec.target + "api/orders?page=2"}


def test_dispatch_discovery_exclusions_no_replay_and_budget_exhaustion(python_broker, monkeypatch):
    solver = PythonSolver(python_broker, model="model")
    _, enum_spec = _setup_enum_with_recon(
        python_broker,
        solver,
        '<a href="/api/a">A</a><a href="/api/b">B</a>',
    )

    # 1. Planning-only / compiled-workflow exclusions.
    enum_spec.references = {"hypothesis_ref": "hyp-1"}
    assert solver.dispatch_discovery(enum_spec) is False
    enum_spec.references = {}
    enum_spec.compiled_workflows = {"wf-1": {"payload": {}}}
    assert solver.dispatch_discovery(enum_spec) is False
    enum_spec.compiled_workflows = {}
    assert not python_broker.executor.tasks

    # 2. Interrupted dispatched action -> indeterminate on resume -> never replayed.
    states = solver.hydrate_discovery_state(enum_spec)
    state_obj = next(iter(states.values()))
    pending_ids = [row["action_id"] for row in state_obj.pending_actions()]
    assert len(pending_ids) == 2
    first_id, second_id = pending_ids
    state_obj.mark_dispatched(first_id)
    solver.task_states[enum_spec.id] = "running"
    solver._checkpoint_active = True
    solver.checkpoint.acquire()
    solver.save_checkpoint()
    solver.checkpoint.release()

    restored = PythonSolver(python_broker, model="model", resume=True)
    restored.restore_checkpoint()
    restored_state = next(iter(restored.task_discovery_states(enum_spec).values()))
    assert restored_state.actions[first_id]["status"] == "indeterminate"

    dispatched_urls: list[str] = []
    monkeypatch.setattr(
        type(python_broker.executor),
        "__call__",
        lambda self, task: (
            dispatched_urls.append(json.loads(task["args_json"])["url"])
            or {"actual_request_cost": 1, "result": {"output": {"status_code": 200, "text": "<p>ok</p>"}}}
        ),
    )
    assert restored.dispatch_discovery(enum_spec) is True
    assert len(dispatched_urls) == 1
    assert dispatched_urls[0] == restored_state.actions[second_id]["url"]
    assert restored_state.actions[first_id]["status"] == "indeterminate"

    # 3. Pre-checked HTTP budget exhaustion stops cleanly without dispatching.
    python_broker.results.clear()
    python_broker.tools.clear()
    solver2 = PythonSolver(python_broker, model="model")
    _, enum_spec2 = _setup_enum_with_recon(python_broker, solver2, '<a href="/api/c">C</a>')
    python_broker.budget.used["http"] = python_broker.budget.limits["http"]
    assert solver2.dispatch_discovery(enum_spec2) is False
    assert any(
        gap_row["reason_code"] == "http_budget_exhausted"
        for gap_row in solver2.coverage_gaps.get(enum_spec2.id, [])
    )

    # 4. Mid-invoke BudgetError transitions in-flight action to indeterminate so it is never replayed.
    python_broker.budget.used["http"] = 0
    monkeypatch.setattr(
        python_broker,
        "invoke",
        lambda *_a, **_kw: (_ for _ in ()).throw(BudgetError("http budget exhausted")),
    )
    with pytest.raises(BudgetError):
        solver2.dispatch_discovery(enum_spec2)
    st2 = next(iter(solver2.task_discovery_states(enum_spec2).values()))
    assert all(row["status"] == "indeterminate" for row in st2.actions.values() if row["url"].endswith("/api/c"))


def test_launcher_bootstrap_strengthens_python_loop_goals_without_changing_ids_or_capabilities(tmp_path):
    specs = launcher.bootstrap_plan("http://127.0.0.1:18765/", tmp_path / "solver", solver_mode="python_loop")
    by_phase = {spec.phase: spec for spec in specs}
    assert [step.id for step in by_phase["recon"].steps] == ["fetch-entry"]
    assert [step.id for step in by_phase["enum"].steps] == ["discover-surface"]
    assert [step.id for step in by_phase["access"].steps] == ["minimal-validation", "broader-coverage"]
    assert [step.id for step in by_phase["report"].steps] == ["review-evidence", "unresolved-work"]
    assert "hunter_run_web_loop" not in by_phase["enum"].tools
    assert "frontier" in by_phase["enum"].steps[0].command.lower()
    assert "entry discovery" in by_phase["access"].steps[0].command.lower()
    for spec in specs:
        for step in spec.steps:
            assert len(step.command) <= 160


def test_premature_blocked_enum_without_discovery_triggers_host_discovery(python_broker, monkeypatch):
    """Submitting status='blocked' in enum-2 with zero DISCOVERY_TOOLS must dispatch host discovery first."""
    solver = PythonSolver(python_broker, model="model")
    _, enum_spec = _setup_enum_with_recon(
        python_broker,
        solver,
        '{"items":[{"href":"/api/orders/1"}],"next":"/api/orders?page=2"}',
    )
    visited: list[str] = []

    def fake_exec(self, task):
        self.tasks.append(task)
        url = json.loads(task["args_json"])["url"]
        visited.append(url)
        return {"actual_request_cost": 1, "result": {"output": {"status_code": 200, "text": '{"items":[]}'}}}

    monkeypatch.setattr(type(python_broker.executor), "__call__", fake_exec)
    original_completion = python_broker.completion
    seen_frontiers = []

    def completion(body):
        ctx = json.loads(body["messages"][1]["content"])
        seen_frontiers.append(ctx["discovery_frontier"]["counts"])
        msg_payload = (
            terminal(enum_spec, status="blocked", steps=[{"id": "discover-surface", "status": "not_tested"}])
            if len(seen_frontiers) == 1
            else terminal(enum_spec, status="done")
        )
        mock_provider(
            monkeypatch,
            python_broker,
            {
                "choices": [{"message": {"content": json.dumps(msg_payload)}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110},
            },
        )
        return original_completion(body)

    monkeypatch.setattr(python_broker, "completion", completion)
    summary = solver.phase(enum_spec)
    assert summary["status"] == "done"
    assert len(seen_frontiers) == 2
    assert seen_frontiers[1]["pending"] == 0
    assert seen_frontiers[1]["completed"] == 3
    assert set(visited) == {enum_spec.target + "api/orders/1", enum_spec.target + "api/orders?page=2"}


def test_blocked_enum_after_discovery_attempt_remains_blocked(python_broker, monkeypatch):
    """Submitting status='blocked' after DISCOVERY_TOOLS already ran must preserve blocked status."""
    solver = PythonSolver(python_broker, model="model")
    _, enum_spec = _setup_enum_with_recon(python_broker, solver, "<html><body>restricted</body></html>")
    view = python_broker.view({"ok": False, "error": "crawl stopped: http_403"})
    python_broker.results.append(
        {"spec_id": enum_spec.id, "tool": "kali-tools_crawl_web_surface", "arguments": {"target": enum_spec.target}, **view}
    )
    submitted = terminal(enum_spec, status="blocked", steps=[{"id": "discover-surface", "status": "blocked"}])
    assert solver._is_premature_enum_summary(enum_spec, submitted) is False
    mock_provider(
        monkeypatch,
        python_broker,
        {
            "choices": [{"message": {"content": json.dumps(submitted)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110},
        },
    )
    summary = solver.phase(enum_spec)
    assert summary["status"] == "blocked"
    assert not python_broker.executor.tasks
