"""Targeted regression tests for BLK-E6-AUTH-BOOL, BLK-E6-MULTISEED-RATE-WINDOW, and schema diagnostics."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import full_agent_e6_benchmark as e6
import policy_engine as pe
from full_agent_budget import BudgetError
from full_agent_python_solver import PythonSolver, WorkflowError
from test_full_agent_preflight import mock_provider
from test_full_agent_python_solver import python_broker, terminal  # noqa: F401
from test_python_candidate_runtime import replay_lab  # noqa: F401
from test_python_holdout_regressions import prepare_identity_replay


def _write_llm_cfg(path: Path, base_url: str, *, model: str = "local-model", env_name: str = "CCO_TEST_API_KEY") -> Path:
    path.write_text(
        json.dumps(
            {
                "schema": "cco-llm/1",
                "model": f"owned/{model}",
                "providers": {
                    "owned": {
                        "base_url": base_url,
                        "models": [model],
                        "api_key_env": env_name,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _attach_real_policy_engine(broker, tmp_path: Path, target: str) -> pe.PolicyEngine:
    from python_identity_discovery import capture_state

    cco_home = tmp_path / "cco-home"
    cco_home.mkdir(parents=True, exist_ok=True)
    (cco_home / "permissions.json").write_text("{}", encoding="utf-8")
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({"in_scope": [{"asset": target.rstrip("/")}]}), encoding="utf-8")
    engine = pe.PolicyEngine(cco_home=str(cco_home), scope_file=str(scope_file))
    broker.engine = engine
    base_url = target if target.endswith("/") else target + "/"
    actors = {
        name: {
            "headers": {"Cookie": "identity=" + name},
            "role": "member",
            "test_data_only": True,
            "owned_objects_private": True,
            "objects": [{"url": base_url + "objects/" + name, "marker": "owned-" + name}],
            "identity_facts": [
                {
                    "field": "principal",
                    "value": name,
                    "source": "response_metadata",
                    "confidence": "observed",
                }
            ],
        }
        for name in ("first", "second", "third")
    }
    adapter = broker.tool_executor.executor
    raw_executor = getattr(adapter, "executor", adapter)

    def wrapped_executor(task: dict[str, object]) -> dict[str, object]:
        result = raw_executor(task)
        if task.get("tool_name") == "hunter_run_web_loop" and isinstance(result, dict):
            output = result.get("result", {}).get("output") if isinstance(result.get("result"), dict) else None
            if isinstance(output, dict) and output.get("ok") and "identity_discovery_state" not in output:
                output["identity_discovery_state"] = capture_state(actors)
        return result

    broker.executor = wrapped_executor
    if hasattr(adapter, "executor"):
        adapter.executor = wrapped_executor
    else:
        broker.tool_executor.executor = wrapped_executor
    return engine


def _seed_rate_reservation(audit_db: str | Path, tool_name: str, *, weight: int, age_seconds: float, now_utc: datetime) -> None:
    ts = (now_utc - timedelta(seconds=age_seconds)).isoformat()
    with sqlite3.connect(str(audit_db)) as conn:
        conn.execute(
            "INSERT INTO rate_limit_reservations (timestamp, tool_name, weight) VALUES (?, ?, ?)",
            (ts, tool_name, int(weight)),
        )
        conn.commit()


def _make_clock_wait(
    waits: list[float],
    now_box: list[float] | None = None,
    *,
    jump_to: float | None = None,
    closed_event=None,
):
    def _wait(sec: float) -> bool:
        waits.append(float(sec))
        if closed_event is not None:
            closed_event.set()
            return True
        if jump_to is not None and now_box is not None:
            now_box[0] = jump_to
        elif now_box is not None:
            now_box[0] += float(sec)
        return False

    return _wait


def test_blk_e6_auth_bool_loopback_returns_false_and_keeps_remote_strict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CCO_TEST_API_KEY", "synthetic-unused-token")
    loopback_cfg = _write_llm_cfg(tmp_path / "loopback-llm.json", "http://127.0.0.1:41234/v1")
    remote_cfg = _write_llm_cfg(tmp_path / "remote-llm.json", "https://api.example.invalid/v1")

    for execute in (False, True):
        auth = e6.authorize_provider(loopback_cfg, execute=execute)
        assert auth["provider_kind"] == "loopback"
        assert auth["live_provider_authorized"] is False
        assert isinstance(auth["live_provider_authorized"], bool)
        assert auth["live_authorization_reason"] is None

    with pytest.raises(PermissionError, match="explicit operator authorization"):
        e6.authorize_provider(remote_cfg, execute=True)

    remote_preview = e6.authorize_provider(remote_cfg, execute=False)
    assert remote_preview["live_provider_authorized"] is False

    remote_authorized = e6.authorize_provider(
        remote_cfg,
        execute=True,
        authorize_live_provider=True,
        live_authorization_reason="approved regression gate",
    )
    assert remote_authorized["live_provider_authorized"] is True
    assert remote_authorized["live_authorization_reason"] == "approved regression gate"


@pytest.mark.parametrize("bad_auth_value,bad_reason", [(None, None), (True, None), (False, "unexpected")])
def test_blk_e6_auth_bool_strict_reauditor_rejects_tampered_loopback_auth(
    tmp_path: Path, bad_auth_value, bad_reason
) -> None:
    import full_agent_holdout as holdout

    exp_manifest = tmp_path / "experiment-manifest.json"
    exp_manifest.write_text(json.dumps({"provider_kind": "loopback"}), encoding="utf-8")
    payload = {
        "schema": e6.SCHEMA_COHORT,
        "label": "tampered-loopback",
        "created_at": "2026-11-15T00:00:00+00:00",
        "provenance": {
            "mode": "frozen_paired_experiment",
            "strict_paired_eligible": True,
            "experiment_manifest": {
                "path": str(exp_manifest),
                "sha256": holdout.digest(exp_manifest),
            },
        },
        "authorization": {
            "provider_kind": "loopback",
            "provider_host": "127.0.0.1",
            "live_provider_authorized": bad_auth_value,
            "live_authorization_reason": bad_reason,
            "api_key_env": "CCO_TEST_API_KEY",
        },
        "runs": [],
    }
    payload["report_digest"] = e6._canonical_sha256(payload)
    with pytest.raises(ValueError, match="authorization"):
        e6._reaudit_cohort_report(payload)


def test_rate_window_no_block_does_not_wait_and_preserves_signatures(
    replay_lab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker, target, _wire = replay_lab
    _attach_real_policy_engine(broker, tmp_path, target)
    solver, spec = prepare_identity_replay(broker)
    now = [100.0]
    waits: list[float] = []
    monkeypatch.setattr(broker.budget, "clock", lambda: now[0])
    monkeypatch.setattr(broker.closed, "wait", _make_clock_wait(waits, now))

    assert solver.dispatch_access_validation(spec)
    assert waits == []
    backoffs = [row for row in broker.results if row["tool"] == "host_access_backoff"]
    assert len(backoffs) == 2
    assert all(row["result"]["window_seconds"] == 0 and row["result"]["elapsed_seconds"] == 0 for row in backoffs)
    assert solver.compile_summary(spec, terminal(spec))["validation_funnel"]["evidence_accepted"] == 3


def test_rate_window_waits_only_remaining_window_not_full(
    replay_lab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker, target, _wire = replay_lab
    _attach_real_policy_engine(broker, tmp_path, target)
    solver, spec = prepare_identity_replay(broker)

    fixed_utc = datetime(2026, 11, 15, 0, 0, 0, tzinfo=timezone.utc)
    now_mono = [200.0]
    waits: list[float] = []

    monkeypatch.setattr(pe, "_utc_now", lambda: fixed_utc + timedelta(seconds=now_mono[0] - 200.0))
    monkeypatch.setattr(broker.budget, "clock", lambda: now_mono[0])
    broker.budget.deadline = 500.0
    monkeypatch.setattr(broker.closed, "wait", _make_clock_wait(waits, now_mono))

    # Exhaust hunter_run_web_loop (limit 60/60s) with a reservation made 45s ago => 15s remaining.
    monkeypatch.setattr(broker.engine, "_rate_limit_for", lambda _tool: (60, 60))
    _seed_rate_reservation(broker.engine.audit_db, "hunter_run_web_loop", weight=60, age_seconds=45.0, now_utc=fixed_utc)
    # Also put a non-blocking reservation on an unrelated tool and verify remaining is still 15s, not 60s.
    _seed_rate_reservation(broker.engine.audit_db, "kali-tools_curl_request", weight=10, age_seconds=5.0, now_utc=fixed_utc)

    assert solver.wait_access_rate_window(spec)
    assert sum(waits) == pytest.approx(15.0, abs=0.01)
    assert max(waits) <= 1.0
    assert broker.results[-1]["tool"] == "host_access_backoff"
    assert broker.results[-1]["result"]["window_seconds"] == pytest.approx(15.0, abs=0.01)
    assert broker.results[-1]["result"]["elapsed_seconds"] == pytest.approx(15.0, abs=0.01)


def test_rate_window_pending_candidate_ignores_unrelated_blocked_tool(
    replay_lab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker, target, _wire = replay_lab
    _attach_real_policy_engine(broker, tmp_path, target)
    solver, spec = prepare_identity_replay(broker)

    fixed_utc = datetime(2026, 11, 15, 0, 0, 0, tzinfo=timezone.utc)
    now_mono = [300.0]
    waits: list[float] = []
    monkeypatch.setattr(pe, "_utc_now", lambda: fixed_utc + timedelta(seconds=now_mono[0] - 300.0))
    monkeypatch.setattr(broker.budget, "clock", lambda: now_mono[0])
    monkeypatch.setattr(broker.engine, "_rate_limit_for", lambda _tool: (60, 60))
    monkeypatch.setattr(broker.closed, "wait", _make_clock_wait(waits, now_mono))

    # Block validator_validate_idor only; hunter_run_web_loop batches must NOT wait on an unrelated key.
    _seed_rate_reservation(broker.engine.audit_db, "validator_validate_idor", weight=60, age_seconds=10.0, now_utc=fixed_utc)
    assert solver.dispatch_access_validation(spec)
    assert waits == []
    assert solver.compile_summary(spec, terminal(spec))["validation_funnel"]["evidence_accepted"] == 3


def test_rate_window_cancellation_and_budget_expiry(
    replay_lab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker, target, _wire = replay_lab
    _attach_real_policy_engine(broker, tmp_path, target)
    solver, spec = prepare_identity_replay(broker)

    fixed_utc = datetime(2026, 11, 15, 0, 0, 0, tzinfo=timezone.utc)
    now_mono = [10.0]
    monkeypatch.setattr(pe, "_utc_now", lambda: fixed_utc)
    monkeypatch.setattr(broker.budget, "clock", lambda: now_mono[0])
    monkeypatch.setattr(broker.engine, "_rate_limit_for", lambda _tool: (60, 60))
    _seed_rate_reservation(broker.engine.audit_db, "hunter_run_web_loop", weight=60, age_seconds=35.0, now_utc=fixed_utc)

    # 1. Insufficient time remaining before wait returns False without sleeping or sending HTTP.
    broker.budget.deadline = 30.0  # 20s remaining < 25s needed
    waits: list[float] = []
    monkeypatch.setattr(broker.closed, "wait", _make_clock_wait(waits, now_mono))
    assert not solver.wait_access_rate_window(spec)
    assert waits == []

    # 2. Mid-wait budget exhaustion raises BudgetError.
    broker.budget.deadline = 40.0  # 30s remaining >= 25s needed, expires if clock hits deadline
    monkeypatch.setattr(broker.closed, "wait", _make_clock_wait(waits, now_mono, jump_to=40.0))
    with pytest.raises(BudgetError, match="wall clock budget exhausted"):
        solver.wait_access_rate_window(spec)

    # 3. Cancellation via broker.closed.set() wakes and aborts immediately.
    now_mono[0] = 10.0
    broker.budget.deadline = 200.0
    monkeypatch.setattr(broker.closed, "wait", _make_clock_wait(waits, closed_event=broker.closed))
    with pytest.raises(BudgetError, match="closed"):
        solver.wait_access_rate_window(spec)


def test_rate_window_repeats_checks_and_preserves_per_task_isolation(
    replay_lab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker, target, _wire = replay_lab
    _attach_real_policy_engine(broker, tmp_path, target)
    spec_b = replace(broker.tasks.specs[2], id="access-isolated-b")
    broker.tasks.specs.append(spec_b)
    solver, spec_a = prepare_identity_replay(broker)

    fixed_utc = datetime(2026, 11, 15, 0, 0, 0, tzinfo=timezone.utc)
    now_mono = [100.0]
    monkeypatch.setattr(pe, "_utc_now", lambda: fixed_utc + timedelta(seconds=now_mono[0] - 100.0))
    monkeypatch.setattr(broker.budget, "clock", lambda: now_mono[0])
    broker.engine._rate_limit_for = lambda _tool: (60, 60)

    # Force batch 2 of spec_a to block on 20s remaining rate window while only 12s budget remain.
    solver.plan_candidates(spec_a)
    solver.plan_candidates(spec_b)
    initial_gaps_b = list(solver.coverage_gaps.get(spec_b.id, []))

    original_invoke = broker.invoke

    def invoke_and_fill_rate(tool, arguments):
        out = original_invoke(tool, arguments)
        if tool == "hunter_run_web_loop":
            _seed_rate_reservation(
                broker.engine.audit_db,
                "hunter_run_web_loop",
                weight=60,
                age_seconds=40.0,
                now_utc=pe._utc_now(),
            )
            broker.budget.deadline = now_mono[0] + 10.0
        return out

    monkeypatch.setattr(broker, "invoke", invoke_and_fill_rate)

    # Batch 1 of spec_a runs; batch 2 stops cleanly on insufficient_time_for_rate_window without corrupting spec_b.
    assert solver.dispatch_access_validation(spec_a)
    gaps_a = {item["reason_code"] for item in solver.coverage_gaps.get(spec_a.id, [])}
    assert "insufficient_time_for_rate_window" in gaps_a
    assert solver.coverage_gaps.get(spec_b.id, []) == initial_gaps_b
    assert [r["spec_id"] for r in broker.results if r["tool"] == "hunter_run_web_loop"] == [spec_a.id]
    # Restore clock/budget deadline and verify spec_b executes its own dispatch with fresh checks & zero leakage from spec_a.
    with sqlite3.connect(str(broker.engine.audit_db)) as conn:
        conn.execute("DELETE FROM rate_limit_reservations")
        conn.commit()
    now_mono[0] = 200.0
    broker.budget.deadline = 600.0
    broker.tasks.active_spec = spec_b
    monkeypatch.setattr(broker, "invoke", original_invoke)
    assert solver.dispatch_access_validation(spec_b)
    assert "insufficient_time_for_rate_window" not in {
        item["reason_code"] for item in solver.coverage_gaps.get(spec_b.id, [])
    }
    assert solver.compile_summary(spec_b, terminal(spec_b))["validation_funnel"]["evidence_accepted"] == 3


def test_tool_arguments_schema_invalid_diagnostics_withholds_secret_values(
    replay_lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio
    from conftest import load_server
    from test_python_holdout_regressions import prepare_parameter_replay

    broker, target, _wire = replay_lab
    solver, spec = prepare_parameter_replay(broker, target)
    hunter = load_server("hunter")
    broker.catalog["hunter"] = [
        row.model_dump(mode="json", exclude_none=True, exclude={"outputSchema"})
        for row in asyncio.run(hunter.mcp.list_tools())
        if row.name == "run_web_loop"
    ]
    secret_value = "SecretBearerTokenValue-DoNotLeak-987654"

    def fake_provider(_payload, **_kwargs):
        return {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "hunter_run_web_loop",
                                    "arguments": json.dumps(
                                        {
                                            "target": target,
                                            "live": True,
                                            "crawl": False,
                                            "blind_discovery": True,
                                            "session_bindings": json.dumps({"Authorization": secret_value}),
                                        }
                                    ),
                                }
                            }
                        ]
                    }
                }
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
        }

    original_completion = broker.completion

    def completion(body):
        mock_provider(monkeypatch, broker, fake_provider(body))
        return original_completion(body)

    monkeypatch.setattr(broker, "completion", completion)
    with pytest.raises(WorkflowError) as exc_info:
        solver.phase(spec)
    assert exc_info.value.code == "tool_protocol_repair_exhausted"
    diag = exc_info.value.schema_diagnostic
    assert diag is not None
    assert diag["tool"] == "hunter_run_web_loop"
    assert diag["validator"] == "additionalProperties"
    assert diag["schema_path"] == ["additionalProperties"]
    assert diag["argument_keys"] == ["blind_discovery", "crawl", "live", "session_bindings", "target"]

    # python-loop-events.json keeps exact schema contract without extra keys.
    events = json.loads((broker.private / "python-loop-events.json").read_text(encoding="utf-8"))
    assert events == [{"spec_id": spec.id, "reason_code": "tool_arguments_schema_invalid"}]

    diag_file = broker.private / "python-schema-diagnostics.json"
    saved_diags = json.loads(diag_file.read_text(encoding="utf-8"))
    assert len(saved_diags) == 2
    assert all(entry["validator"] == "additionalProperties" for entry in saved_diags)
    assert secret_value not in diag_file.read_text(encoding="utf-8")
    assert secret_value not in (broker.private / "python-loop-events.json").read_text(encoding="utf-8")
    assert secret_value not in json.dumps(solver.protocol_feedback)


def test_rate_window_post_wait_repeats_session_refresh_and_policy_checks(
    replay_lab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import full_agent_python_broker as broker_mod
    import full_agent_python_solver as solver_mod

    broker, target, _wire = replay_lab
    engine = _attach_real_policy_engine(broker, tmp_path, target)
    solver, spec = prepare_identity_replay(broker)

    fixed_utc = datetime(2026, 11, 15, 0, 0, 0, tzinfo=timezone.utc)
    now_mono = [100.0]
    waits: list[float] = []
    monkeypatch.setattr(pe, "_utc_now", lambda: fixed_utc + timedelta(seconds=now_mono[0] - 100.0))
    monkeypatch.setattr(broker.budget, "clock", lambda: now_mono[0])
    engine._rate_limit_for = lambda _tool: (60, 60)
    monkeypatch.setattr(broker.closed, "wait", _make_clock_wait(waits, now_mono))

    order: list[str] = []
    orig_validate = engine.validate_tool_invocation

    def spy_validate(tool_name, args, **kwargs):
        if kwargs.get("_policy_preflight") and tool_name == "hunter_run_web_loop":
            order.append("preflight")
        return orig_validate(tool_name, args, **kwargs)

    monkeypatch.setattr(engine, "validate_tool_invocation", spy_validate)

    # Seed prior enum-2 session checks in broker.results (and keep Executor returning "fresh" for refresh calls).
    wall_clock = [1000.0]
    monkeypatch.setattr(solver_mod.time, "time", lambda: wall_clock[0])
    monkeypatch.setattr(broker_mod.time, "time", lambda: wall_clock[0])
    for identity in ("first", "second", "third"):
        broker.results.append(
            {
                "spec_id": spec.depends_on[0],
                "tool": "validator_session_vault_check",
                "arguments": {"target": spec.target, "identity": identity},
                "session_check_observed_at": 995.0,
                **broker.view({"status": "fresh"}),
            }
        )

    orig_invoke = broker.invoke

    def spy_invoke(tool, arguments):
        if tool == "hunter_run_web_loop":
            order.append("invoke")
            return orig_invoke(tool, arguments)
        if tool == "validator_session_vault_check":
            order.append("refresh")
            view = broker.view({"status": "fresh"})
            broker.results.append(
                {
                    "spec_id": spec.id,
                    "tool": tool,
                    "arguments": arguments,
                    "session_check_observed_at": wall_clock[0],
                    **view,
                }
            )
            return view
        return orig_invoke(tool, arguments)

    # First batch executes without wait; right before batch 2, make window blocked (10s left) and push wall_clock
    # past 300s expiry threshold so post-wait refresh MUST invoke validator_session_vault_check before admitting batch 2.
    orig_wait = solver.wait_access_rate_window

    def wait_with_session_expiry(current):
        _seed_rate_reservation(engine.audit_db, "hunter_run_web_loop", weight=60, age_seconds=50.0, now_utc=pe._utc_now())
        wall_clock[0] = 1010.0
        for item in broker.results:
            if item.get("tool") == "validator_session_vault_check":
                item["session_check_observed_at"] = 600.0
        ok = orig_wait(current)
        order.append("wait_done")
        return ok

    monkeypatch.setattr(broker, "invoke", spy_invoke)
    monkeypatch.setattr(solver, "wait_access_rate_window", wait_with_session_expiry)
    assert solver.dispatch_access_validation(spec)
    assert sum(waits) == pytest.approx(20.0, abs=0.01)  # 2 waits of 10s each for batches 2 & 3
    assert order.count("wait_done") == 2 and order.count("invoke") == 3
    for idx, event in enumerate(order):
        if event == "wait_done":
            next_invoke = order.index("invoke", idx)
            assert "refresh" in order[idx:next_invoke]
            assert "preflight" in order[idx:next_invoke]
    refresh_calls = [
        item
        for item in broker.results
        if item.get("spec_id") == spec.id and item.get("tool") == "validator_session_vault_check"
    ]
    assert len(refresh_calls) >= 2
    assert solver.compile_summary(spec, terminal(spec))["validation_funnel"]["evidence_accepted"] == 3


def test_level2_closed_schema_reproduces_legacy_fixture_rejection_and_accepts_projected_calls(
    replay_lab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio
    from conftest import load_server
    import full_agent_python_solver as solver_mod

    broker, target, _wire = replay_lab
    _attach_real_policy_engine(broker, tmp_path, target)
    srv = load_server("hunter")
    run_loop_tool = next(t for t in asyncio.run(srv.mcp.list_tools()) if t.name == "run_web_loop")
    for entry in broker.catalog.get("hunter", []):
        if entry.get("name") == "run_web_loop":
            entry["inputSchema"] = json.loads(json.dumps(run_loop_tool.inputSchema))
    solver, spec = prepare_identity_replay(broker)
    assert spec.id == "access-3"
    broker.tasks.active_spec = spec

    candidates = solver.plan_candidates(spec)
    assert candidates
    unprojected_tools = solver.tool_schemas(spec)
    context = solver.context(spec)
    context["recent_results"] = [
        {
            "tool": "read_artifact",
            "content_ref": {"path": "x", "sha256": "0" * 64},
            "result": {"text": "x" * 1200},
        }
    ]
    body = {
        "model": solver.model,
        "messages": [
            {"role": "system", "content": solver_mod.SYSTEM},
            {"role": "user", "content": json.dumps(context)},
        ],
        "tools": unprojected_tools,
    }
    projected_body, decision, _ = broker.project_runtime_context(body, spec, {})
    assert decision["finalizing"] is False
    tools = {row["function"]["name"]: row["function"]["parameters"] for row in projected_body["tools"]}
    loop_schema = tools["hunter_run_web_loop"]
    assert loop_schema["additionalProperties"] is False
    assert set(loop_schema["properties"]) == {"target", "live", "session_bindings", "validation_profile"}

    # Reproduce the legacy scripted E6 provider payload containing unprojected extra parameters.
    legacy_args = {
        "target": spec.target,
        "live": True,
        "crawl": False,
        "blind_discovery": True,
        "blind_max_requests": 12,
        "fuzz_limit": 0,
        "candidate_sample_limit": 0,
        "max_validations": 8,
        "sleep_s": 0.2,
        "session_bindings": json.dumps({"first": "vault://synthetic-first-secret-value"}),
    }
    legacy_calls = [{"function": {"name": "hunter_run_web_loop", "arguments": json.dumps(legacy_args)}}]
    with pytest.raises(WorkflowError) as exc_info:
        solver.parse_calls(legacy_calls, tools)
    err = exc_info.value
    assert err.code == "tool_arguments_schema_invalid"
    assert err.schema_diagnostic == {
        "tool": "hunter_run_web_loop",
        "validator": "additionalProperties",
        "path": [],
        "schema_path": ["additionalProperties"],
        "argument_keys": sorted(legacy_args),
    }
    assert "synthetic-first-secret-value" not in json.dumps(err.schema_diagnostic)

    # Generic conformance: fitting to the level-2 closed schema passes parse_calls and admit_candidate.
    fitted_args = {
        "target": spec.target,
        "live": True,
        "session_bindings": candidates[0]["arguments"]["session_bindings"],
    }
    fitted_calls = [{"function": {"name": "hunter_run_web_loop", "arguments": json.dumps(fitted_args)}}]
    from python_candidate_runtime import matches_model_call

    parsed = solver.parse_calls(fitted_calls, tools)
    assert len(parsed) == 1
    parsed_name, parsed_args = parsed[0]
    selected = next(
        (row for row in solver.plan_candidates(spec) if matches_model_call(row, parsed_name, parsed_args)),
        None,
    )
    assert selected is not None
    assert solver.admit_candidate(spec, selected)
    assert selected["tool"] == "hunter_run_web_loop"
    assert selected["candidate_id"]
