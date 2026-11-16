"""Offline observed-record replay. Scripted choices are not real-model recall."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3
import threading
import uuid
from urllib.parse import parse_qs, urlsplit

import pytest

from full_agent_budget import BudgetError, provider_json
from full_agent_python_broker import MAX_ARCHIVE_BYTES, ArchiveSizeError, CRAWL_TOOL, COVERAGE_TOOL, READ_TOOL, SUMMARY_TOOL
from full_agent_python_solver import PythonSolver
from orchestration_spec import TaskSpec
from python_candidate_runtime import STAGES, compact_cards, funnel, matches_model_call
from test_full_agent_python_solver import python_broker, terminal
from test_full_agent_preflight import mock_provider

FROZEN = json.loads((Path(__file__).parent / "fixtures/python_runtime_replay/observations.json").read_text())


def observe(broker, solver, source, records, *, gaps=(), identity=None):
    value = {"records": records, "coverage_gaps": list(gaps)}
    view = broker.view(value)
    args = {"target": source.target, **({"identity": identity} if identity is not None else {})}
    broker.results.append({"spec_id": source.id, "tool": CRAWL_TOOL, "arguments": args, **view})
    solver.summaries[source.id] = solver.compile_summary(source, terminal(source))
    return view["content_ref"]


def catalog(broker):
    import asyncio
    from conftest import load_server
    validator = load_server("validator")
    broker.catalog["validator"] = [row.model_dump(mode="json", exclude_none=True, exclude={"outputSchema"})
                                    for row in asyncio.run(validator.mcp.list_tools())
                                    if row.name in {"validate_sqli", "validate_ssti", "validate_idor"}]
    broker.catalog["hunter"] = [{"name": "run_web_loop", "inputSchema": {"type": "object"}}]
    broker.catalog["kali-tools"].append({"name": "crawl_web_surface", "inputSchema": {"type": "object"}})
    return validator


@pytest.fixture
def replay_lab(python_broker, monkeypatch):
    from jinja2 import Template
    validator = catalog(python_broker)
    from cco_validator_core.egress import scoped_wire_gate
    from cco_validator_core.evidence import validation_context
    from wire_budget import campaign_wire_budget
    wire = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            parsed = urlsplit(self.path)
            qs = parse_qs(parsed.query)
            value = qs.get("term", next(iter(qs.values()), [""]))[0]
            status, result = 200, ""
            if parsed.path.startswith("/search/"):
                with sqlite3.connect(":memory:") as db:
                    db.execute("create table records (name text)")
                    db.executemany("insert into records values (?)", [("alpha",), ("beta",)])
                    try:
                        result = json.dumps(db.execute("select name from records where name='" + value + "'").fetchall()
                                            if "unsafe" in parsed.path else
                                            db.execute("select name from records where name=?", (value,)).fetchall())
                    except sqlite3.Error:
                        status, result = 400, "query rejected"
            elif parsed.path.startswith("/render/"):
                try:
                    result = Template(value).render() if "unsafe" in parsed.path else "literal: " + value
                except Exception:
                    status, result = 400, "template rejected"
            elif parsed.path.startswith("/objects/"):
                owner = parsed.path.rsplit("/", 1)[-1]
                actor = self.headers.get("Cookie", "").removeprefix("identity=")
                status = 200 if actor == owner or (owner, actor) == ("first", "second") else 403
                result = json.dumps({"marker": "owned-" + owner} if status == 200 else {"error": "denied"})
            wire.append({"path": self.path, "status": status})
            data = result.encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    target = f"http://127.0.0.1:{server.server_port}/"
    for spec in python_broker.tasks.specs:
        spec.target = target
    from full_agent_launcher import lab_policy
    from full_agent_provider import dump
    runtime = python_broker.workdir.parent / "scope"
    runtime.mkdir()
    scope, policy = lab_policy(target)
    dump(runtime / "scope.json", scope)
    dump(runtime / "policy.json", policy)
    monkeypatch.setenv("CCO_SCOPE_FILE", str(runtime / "scope.json"))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(runtime / "policy.json"))
    monkeypatch.setattr(python_broker, "_check_handoff", lambda _spec: None)
    monkeypatch.setattr(python_broker.engine, "tool_capability", lambda _tool: {"network": True})

    def gate(method, url, _headers):
        return method == "GET" and urlsplit(url).netloc == urlsplit(target).netloc, "owned offline replay lab"

    def execute(self, task):
        from urllib.parse import parse_qsl, urljoin
        from python_candidate_runtime import PROFILES
        self.tasks.append(task)
        args = json.loads(task["args_json"])
        with campaign_wire_budget(task["reserved_request_cost"], uuid.uuid4().hex) as budget, scoped_wire_gate(gate):
            if task["tool_name"] == "hunter_run_web_loop" and args.get("validation_profile") in PROFILES:
                profile = args["validation_profile"]
                fn = getattr(validator, PROFILES[profile][1].removeprefix("validator_"))
                target_parsed = urlsplit(args["target"])
                prefix = target_parsed.path.rstrip("/")
                identity = next(iter(json.loads(args["session_bindings"]))) if args.get("session_bindings") else "anonymous"
                fuzz_limit = max(1, int(args.get("fuzz_limit") or 4))
                queue, validations, seen_urls = [], [], set()
                for entry in python_broker.results:
                    data = python_broker.read_reference(entry["content_ref"])
                    if not isinstance(data, dict) or not isinstance(data.get("records"), list):
                        continue
                    for rec in data["records"]:
                        if not isinstance(rec, dict) or not isinstance(rec.get("url"), str):
                            continue
                        full_url = urljoin(target, rec["url"])
                        parsed = urlsplit(full_url)
                        if (parsed.scheme, parsed.netloc) != (target_parsed.scheme, target_parsed.netloc):
                            continue
                        if not (parsed.path == prefix or parsed.path.startswith(prefix + "/")):
                            continue
                        if not parsed.query or full_url in seen_urls:
                            continue
                        seen_urls.add(full_url)
                        for param, _ in parse_qsl(parsed.query, keep_blank_values=True):
                            item = {"url": full_url, "method": "GET", "param": param, "carrier": "query", "identity": identity}
                            queue.append(item)
                            with validation_context(item):
                                record = json.loads(fn(target_url=full_url, param=param, **(
                                    {"boolean_only": True} if profile == "readonly_sqli_boolean" else {})))
                            validations.append({**item, "validation_id": record["validation_id"]})
                        if len(seen_urls) >= fuzz_limit:
                            break
                    if len(seen_urls) >= fuzz_limit:
                        break
                value = {"ok": True, "validation_queue": queue, "validations": validations}
            elif task["tool_name"] == "hunter_run_web_loop":
                names = list(json.loads(args["session_bindings"]))
                queue, validations = [], []
                for owner, actor in (names, names[::-1]):
                    item = {"url": target + "objects/" + owner, "method": "GET", "vuln_class": "idor",
                            "resource_owner": owner, "identity": actor}
                    queue.append(item)
                    with validation_context(item):
                        record = json.loads(validator.validate_idor(item["url"],
                            json.dumps({"Cookie": "identity=" + owner}), json.dumps({"Cookie": "identity=" + actor}),
                            owner_marker="owned-" + owner))
                    validations.append({**item, "validation_id": record["validation_id"]})
                value = {"ok": True, "identity_discovery": {"status": "ready"},
                         "validation_queue": queue, "validations": validations}
            else:
                fn = getattr(validator, task["tool_name"].removeprefix("validator_"))
                # Direct validators intentionally have no unsigned context. The
                # broker must derive the parameter slice from signed wire trace.
                value = json.loads(fn(**args))
        return {"actual_request_cost": budget.used, "result": {"output": value}}

    monkeypatch.setattr(type(python_broker.executor), "__call__", execute)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield python_broker, target, wire
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("path", ["parameters", "identities"])
def test_frozen_replay_early_summary_signed_positive_negative_paths(replay_lab, monkeypatch, path):
    broker, target, wire = replay_lab
    if path == "identities":
        broker.tasks.bindings = {name: {"target": target, "role": "member", "test_data_only": True,
                                       "owned_objects_private": True} for name in ("first", "second")}
        records = FROZEN["identity_pages"]
    else:
        records = FROZEN["parameter_pages"]
    solver = PythonSolver(broker, model="model", recent_results=0)
    source, spec = broker.tasks.specs[1:3]
    observe(broker, solver, source, records, gaps=[FROZEN["parser_gap"]])
    broker.tasks.active_spec = spec
    original = broker.completion
    turns = []

    def completion(body):
        turns.append(json.loads(body["messages"][1]["content"]))
        mock_provider(monkeypatch, broker, {"choices": [{"message": {"content": json.dumps(terminal(spec))}}],
                      "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
        return original(body)

    monkeypatch.setattr(broker, "completion", completion)
    summary = solver.phase(spec)
    counts = summary["validation_funnel"]
    expected = 1 if path == "identities" else 8
    assert [counts[stage] for stage in STAGES] == [expected] * 5
    assert len(turns) == 2 and turns[0]["candidate_cards"]
    assert broker.budget.used["http"] == len(wire) <= broker.budget.limits["http"]
    assert len(broker.executor.tasks) == (1 if path == "identities" else 2)
    if path == "parameters":
        assert {task["tool_name"] for task in broker.executor.tasks} == {"hunter_run_web_loop"}
        assert {json.loads(task["args_json"])["validation_profile"] for task in broker.executor.tasks} == {
            "readonly_sqli_boolean", "readonly_ssti_arithmetic"}
    outcomes = summary["validation_outcomes"]
    assert sum(row["verdict"] == "CONFIRMED" for row in outcomes) == (1 if path == "identities" else 2)
    assert sum(row["verdict"] == "UNCONFIRMED" for row in outcomes) == (1 if path == "identities" else 6)
    assert {row["vector"] for row in outcomes} == ({"authz-idor"} if path == "identities" else {"injection-sqli", "injection-ssti"})
    assert any(row["reason_code"] == "source_truncated" for row in summary["coverage_gaps"])
    assert not any(row["candidate_id"] for row in summary["coverage_gaps"])
    if path == "parameters":
        assert len(summary["tested_parameters"]) == 8
    before = len(wire)
    assert not solver.dispatch_access_validation(spec) and len(wire) == before


def test_no_model_profile_required_dedup_and_declared_branch_isolation(python_broker, monkeypatch):
    broker = python_broker
    catalog(broker)
    source, access = broker.tasks.specs[1:3]
    source.id = "discovery-renamed"
    access.id, access.depends_on = "access-renamed", [source.id]
    other = TaskSpec.from_dict(source.to_dict())
    other.id, other.depends_on = "independent-discovery", []
    branch = TaskSpec.from_dict(access.to_dict())
    branch.id, branch.depends_on, branch.max_calls = "independent-access", [other.id], 2
    broker.tasks.specs = [source, other, access, branch]
    source.depends_on = []
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/one?q=1"}] * 4)
    observe(broker, solver, other, [{"url": "/two?x=2"}])
    first = solver.plan_candidates(access)
    second = solver.plan_candidates(branch)
    assert len(first) == len(second) == 2
    assert {row["route"] for row in first} == {access.target + "one?q=1"}
    assert {row["route"] for row in second} == {branch.target + "two?x=2"}
    assert {p["source_spec_id"] for row in first for p in row["provenance"]} == {source.id}
    assert set(solver.candidates_by_task[access.id]).isdisjoint(solver.candidates_by_task[branch.id])
    assert broker.runtime_policy.validation_reserves == {access.id: 1, branch.id: 1}
    assert len(solver.pending_parameter_batches(access)) == 2 and not broker.executor.tasks


@pytest.mark.parametrize("limit,reason", [("http", "http_budget_exhausted"), ("tools", "phase_tool_budget_exhausted"),
                                         ("time", "wall_clock_budget_exhausted"), ("tokens", "token_budget_exhausted")])
def test_candidate_budget_gaps_survive_summary_checkpoint_final(python_broker, monkeypatch, limit, reason):
    broker = python_broker
    catalog(broker)
    solver = PythonSolver(broker, model="model")
    source, spec = broker.tasks.specs[1:3]
    observe(broker, solver, source, [{"url": "/check?q=1"}])
    broker.tasks.active_spec = spec
    monkeypatch.setattr(broker, "_check_handoff", lambda _spec: None)
    if limit in {"http", "tokens"}:
        broker.budget.used[limit] = broker.budget.limits[limit]
    elif limit == "time":
        broker.budget.deadline = broker.budget.clock()
    else:
        broker.runtime_policy.tool_calls[spec.id] = 14
    assert not solver.dispatch_access_validation(spec)
    summary = solver.compile_summary(spec, terminal(spec))
    assert {row["reason_code"] for row in summary["coverage_gaps"]} == {reason}
    assert summary["validation_funnel"]["evidence_accepted"] == 0
    solver.summaries[spec.id] = summary
    report = solver.compile_summary(broker.tasks.specs[3], terminal(broker.tasks.specs[3]))
    assert summary["coverage_gaps"] == report["coverage_gaps"]
    for ident, previous in solver.summaries.items():
        path = broker.tasks.summary_path(next(s for s in broker.tasks.specs if s.id == ident))
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(provider_json(previous))
    solver._checkpoint_active = True
    solver.checkpoint.acquire()
    solver.save_checkpoint()
    solver.checkpoint.release()
    payload = solver.checkpoint.read()
    state = json.loads((broker.workdir.parent / payload["state_ref"]["path"]).read_bytes())
    assert state["coverage_gaps"][spec.id] == summary["coverage_gaps"]
    state_path = broker.workdir.parent / payload["state_ref"]["path"]
    state_path.write_text("{}")
    with pytest.raises(ValueError):
        solver.checkpoint.read()


def test_archive_exact_16mib_boundary_and_repeated_overlapping_pages(python_broker):
    broker = python_broker
    value = "x" * (MAX_ARCHIVE_BYTES - 2)
    ref = broker.archive(value)
    assert ref["bytes"] == MAX_ARCHIVE_BYTES
    assert broker.read_reference(ref) == value
    with pytest.raises(ArchiveSizeError):
        broker.archive(value + "x")
    read = lambda offset, limit=3000: broker.invoke(READ_TOOL, {"path": ref["path"], "offset": offset, "limit": limit})["result"]
    assert read(0)["text"]
    assert read(10, 10)["text"]
    assert read(20, 10)["reason_code"] == "archive_read_no_progress"
    assert read(3000)["text"] and read(MAX_ARCHIVE_BYTES + 1)["eof"]
    (broker.workdir / ref["path"]).write_text("tampered")
    with pytest.raises(ValueError):
        read(6000)


def test_level_two_retains_candidate_cards_crawler_and_direct_validators(python_broker, monkeypatch):
    import full_agent_python_broker as module
    broker = python_broker
    catalog(broker)
    solver = PythonSolver(broker, model="model")
    source, spec = broker.tasks.specs[1:3]
    spec.tools.append(CRAWL_TOOL)
    observe(broker, solver, source, [{"url": "/surface?q=1"}])
    broker.tasks.active_spec = spec
    context = solver.context(spec)
    ref = broker.archive({"text": "x" * 10000})
    context["recent_results"] = [{"tool": READ_TOOL, "content_ref": ref,
                                  "result": {"text": "fresh page", "offset": 0}}]
    context["padding"] = "x" * 500
    body = {"model": "model", "max_tokens": 1024, "tools": solver.tool_schemas(spec), "messages": [
        {"role": "system", "content": "offline"}, {"role": "user", "content": provider_json(context).decode()}]}
    original = module.completion_request
    attempts = []

    def admission(wire, **kwargs):
        projected = json.loads(wire["messages"][1]["content"])
        attempts.append(projected)
        if "remaining_phase_calls" in projected or len(projected["recent_results"]) > 1:
            raise BudgetError("force compressed boundary")
        return original(wire, **kwargs)

    monkeypatch.setattr(module, "completion_request", admission)
    sent, _info, projection = broker.project_runtime_context(body, spec, None)
    assert projection["level"] == 2
    visible = {row["function"]["name"] for row in sent["tools"]}
    assert {CRAWL_TOOL, "validator_validate_sqli", "validator_validate_ssti", "hunter_run_web_loop"} <= visible
    projected = json.loads(sent["messages"][1]["content"])
    assert projected["candidate_cards"] == compact_cards(solver.plan_candidates(spec))
    assert all(step.get("goal") for step in projected["task_spec"]["steps"])
    assert projected["recent_results"][-1]["result"]["text"] == "fresh page"
    assert not broker.calls and not broker.budget.used["http"]


def test_level_two_retains_enum_curl_goals_and_discovery_frontier_without_bypassing_allowlist(python_broker, monkeypatch):
    import full_agent_python_broker as module
    broker = python_broker
    catalog(broker)
    solver = PythonSolver(broker, model="model")
    recon, enum_spec = broker.tasks.specs[:2]
    assert "hunter_run_web_loop" not in enum_spec.tools
    assert "kali-tools_curl_request" in enum_spec.tools
    recon_view = broker.view({"status_code": 200, "text": '<a href="/items?q=secret-val">Items</a>'})
    broker.results.append({"spec_id": recon.id, "tool": "kali-tools_curl_request",
                           "arguments": {"url": recon.target}, **recon_view})
    solver.summaries[recon.id] = solver.compile_summary(recon, terminal(recon))
    broker.tasks.active_spec = enum_spec
    context = solver.context(enum_spec)
    ref = broker.archive({"text": "x" * 10000})
    context["recent_results"] = [{"tool": READ_TOOL, "content_ref": ref,
                                  "result": {"text": "fresh enum page", "offset": 0}}]
    context["padding"] = "x" * 500
    body = {"model": "model", "max_tokens": 1024, "tools": solver.tool_schemas(enum_spec), "messages": [
        {"role": "system", "content": "offline"}, {"role": "user", "content": provider_json(context).decode()}]}
    original = module.completion_request

    def admission(wire, **kwargs):
        projected = json.loads(wire["messages"][1]["content"])
        if "remaining_phase_calls" in projected or len(projected["recent_results"]) > 1:
            raise BudgetError("force compressed boundary")
        return original(wire, **kwargs)

    monkeypatch.setattr(module, "completion_request", admission)
    sent, _info, projection = broker.project_runtime_context(body, enum_spec, None)
    assert projection["level"] == 2
    visible = {row["function"]["name"] for row in sent["tools"]}
    assert {"kali-tools_curl_request", CRAWL_TOOL, READ_TOOL, SUMMARY_TOOL} <= visible
    assert "hunter_run_web_loop" not in visible
    projected = json.loads(sent["messages"][1]["content"])
    assert projected["discovery_frontier"]["counts"]["pending"] == 1
    assert "secret-val" not in json.dumps(projected["discovery_frontier"])
    assert all(step.get("goal") for step in projected["task_spec"]["steps"])


def test_level_three_summary_only_preserves_unfinished_work_visibility(python_broker, monkeypatch):
    import full_agent_python_broker as module
    broker = python_broker
    catalog(broker)
    solver = PythonSolver(broker, model="model")
    recon, enum_spec = broker.tasks.specs[:2]
    recon_view = broker.view({"status_code": 200, "text": '<a href="/items?q=secret-val">Items</a>'})
    broker.results.append({"spec_id": recon.id, "tool": "kali-tools_curl_request",
                           "arguments": {"url": recon.target}, **recon_view})
    solver.summaries[recon.id] = solver.compile_summary(recon, terminal(recon))
    broker.tasks.active_spec = enum_spec
    context = solver.context(enum_spec)
    body = {"model": "model", "max_tokens": 1024, "tools": solver.tool_schemas(enum_spec), "messages": [
        {"role": "system", "content": "offline"}, {"role": "user", "content": provider_json(context).decode()}]}
    original = module.completion_request

    def admission(wire, **kwargs):
        projected = json.loads(wire["messages"][1]["content"])
        if "unfinished_work" not in projected:
            raise BudgetError("force level 3 summary-only projection")
        return original(wire, **kwargs)

    monkeypatch.setattr(module, "completion_request", admission)
    sent, _info, projection = broker.project_runtime_context(body, enum_spec, None)
    assert projection["level"] == 3
    assert {row["function"]["name"] for row in sent["tools"]} == {SUMMARY_TOOL}
    projected = json.loads(sent["messages"][1]["content"])
    assert projected["unfinished_work"]["has_unfinished"] is True
    assert projected["unfinished_work"]["discovery"]["pending"] == 1
    assert projected["discovery_frontier"]["counts"]["pending"] == 1
    assert "secret-val" not in json.dumps(projected)


@pytest.mark.parametrize("mode", ["unsigned", "invented", "tampered", "out_of_scope"])
def test_untrusted_ids_never_count_as_signed_candidate_evidence(python_broker, monkeypatch, mode):
    from conftest import make_signed_validation
    broker = python_broker
    catalog(broker)
    solver = PythonSolver(broker, model="model")
    source, spec = broker.tasks.specs[1:3]
    observe(broker, solver, source, [{"url": "/check?q=1"}])
    broker.tasks.active_spec = spec
    target = spec.target + "check?q=1"
    record = make_signed_validation("https://outside.invalid/" if mode == "out_of_scope" else target, "SQL Injection")
    if mode == "tampered":
        Path(record["artifact"]["path"]).write_text("{}")
    value = {"validation_id": "invented" if mode == "invented" else record["validation_id"],
             "verdict": "CONFIRMED", "ok": True}
    if mode == "unsigned":
        Path(record["artifact"]["path"]).unlink()
    broker.results.append({"spec_id": spec.id, "tool": "validator_validate_sqli", "arguments": {
        "target_url": target, "param": "q", "boolean_only": True}, **broker.view(value)})
    summary = solver.compile_summary(spec, terminal(spec, findings=[value]))
    assert not summary["findings"] and not summary["validation_outcomes"]
    assert summary["validation_funnel"]["evidence_accepted"] == 0
    assert not summary["tested_parameters"]


def test_candidate_planner_never_revives_p5_or_compiled_raw_validation(python_broker):
    broker = python_broker
    solver = PythonSolver(broker, model="model")
    spec = broker.tasks.specs[2]
    spec.references = {"hypothesis_ref": "opaque-planning-reference"}
    assert not solver.plan_candidates(spec) and not solver.dispatch_access_validation(spec)
    spec.references = {}
    spec.compiled_workflows = {"host-ref": {"payload": {}}}
    assert not solver.plan_candidates(spec) and not solver.dispatch_access_validation(spec)
    assert broker.runtime_policy.allowed_tools(spec) <= {READ_TOOL, SUMMARY_TOOL, "workflow_execute_compiled"}


@pytest.mark.parametrize("change", [{"test_data_only": False}, {"owned_objects_private": False}, {"test_data_only": 1}])
def test_authenticated_parameters_require_synthetic_owned_refs(python_broker, change):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    broker.tasks.bindings = {"owned": {"target": spec.target, "role": "member", "test_data_only": True,
                                      "owned_objects_private": True, **change}}
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/search?term=hello"}], identity="owned")
    rows = solver.plan_candidates(spec)
    assert len(rows) == 2 and all(not row["eligible"] for row in rows)
    assert {row["reason_code"] for row in rows} == {"missing_synthetic_owned_session_prerequisite"}
    assert not solver.dispatch_access_validation(spec) and not broker.executor.tasks


def test_parameter_shapes_and_nested_singular_gaps_are_visible(python_broker):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    value = {"coverage_gap": {"reason_code": "source_truncated"}, "surface": {
        "coverage_gaps": [{"reason_code": "source_truncated"}, "untrusted narrative"], "records": [
            {"url": "/plain"}, {"url": "/write?q=1", "method": "POST"},
            {"url": "/form", "params": [{"name": "q", "in": "query"}]},
            {"url": "/body", "params": [{"name": "q", "in": "body"}]}]}}
    broker.results.append({"spec_id": source.id, "tool": CRAWL_TOOL, "arguments": {"target": source.target},
                           **broker.view(value)})
    solver.summaries[source.id] = solver.compile_summary(source, terminal(source))
    summary = solver.compile_summary(spec, terminal(spec))
    assert {row["reason_code"] for row in summary["coverage_gaps"]} == {
        "source_truncated", "parser_coverage_incomplete", "unsupported_readonly_method",
        "missing_parameter_or_synthetic_identity_pair", "missing_observed_query_sample", "unsupported_parameter_carrier"}
    assert summary["validation_funnel"]["observed"] == 5 and not summary["validation_funnel"]["eligible"]
    assert not broker.executor.tasks


@pytest.mark.parametrize("change", [{"param": "invented"}, {"target_url": "http://127.0.0.1:1/invented?q=1"},
    {"boolean_only": False}, {"headers_json": '{"Cookie":"synthetic-raw-material"}'}, {"method": "POST"}])
def test_model_cannot_widen_host_parameter_slice(python_broker, change):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/check?q=1"}])
    row = next(row for row in solver.plan_candidates(spec) if row["vector"] == "injection-sqli")
    assert matches_model_call(row, row["tool"], row["arguments"])
    assert not matches_model_call(row, row["tool"], {**row["arguments"], **change})
    assert not broker.executor.tasks


def test_model_identity_slice_requires_refs_and_host_fills_bounded_defaults(python_broker):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    broker.tasks.bindings = {name: {"target": spec.target, "role": "member", "test_data_only": True,
                                  "owned_objects_private": True} for name in ("first", "second")}
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/objects/first"}])
    row = solver.plan_candidates(spec)[0]
    assert not matches_model_call(row, row["tool"], {"target": spec.target})
    assert matches_model_call(row, row["tool"], {"target": spec.target,
                                              "session_bindings": row["arguments"]["session_bindings"]})
    assert not matches_model_call(row, row["tool"], {**row["arguments"], "crawl": True})


def test_real_signed_id_belongs_to_first_executed_task_not_reusing_branch(replay_lab, monkeypatch):
    broker, target, wire = replay_lab
    source, spec = broker.tasks.specs[1:3]
    branch = TaskSpec.from_dict(spec.to_dict())
    branch.id = "independent-access"
    broker.tasks.specs.append(branch)
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, FROZEN["parameter_pages"][:1])
    broker.tasks.active_spec = spec
    row = next(row for row in solver.plan_candidates(spec) if row["vector"] == "injection-sqli")
    view = broker.invoke(row["tool"], row["arguments"])
    assert len(broker.validation_attempts(spec)) == 1
    before = len(wire)
    value = broker.read_reference(view["content_ref"])

    def reuse(self, task):
        self.tasks.append(task)
        return {"actual_request_cost": 0, "result": {"output": value}}

    monkeypatch.setattr(type(broker.executor), "__call__", reuse)
    broker.tasks.active_spec = branch
    broker.invoke(row["tool"], row["arguments"])
    assert not broker.validation_attempts(branch) and len(broker.validation_attempts(spec)) == 1
    assert len(wire) == before
    summary = solver.compile_summary(branch, terminal(branch, findings=[value]))
    assert not summary["findings"] and not summary["tested_parameters"]
    assert summary["validation_funnel"]["evidence_accepted"] == 0


@pytest.mark.parametrize("mismatch", ["parameter", "tool", "route"])
def test_real_signed_id_cannot_validate_another_executed_slice(replay_lab, monkeypatch, mismatch):
    broker, target, wire = replay_lab
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    url = target + "search/unsafe?term=alpha&other=beta"
    observe(broker, solver, source, [{"url": url}])
    broker.tasks.active_spec = spec
    row = next(row for row in solver.plan_candidates(spec)
               if row["vector"] == "injection-sqli" and row["param"] == "term")
    view = broker.invoke(row["tool"], row["arguments"])
    assert len(broker.validation_attempts(spec)) == 1
    value = broker.read_reference(view["content_ref"])
    before = len(wire)

    def reuse(self, task):
        self.tasks.append(task)
        return {"actual_request_cost": 0, "result": {"output": value}}

    monkeypatch.setattr(type(broker.executor), "__call__", reuse)
    tool, args = row["tool"], dict(row["arguments"])
    if mismatch == "parameter":
        args["param"] = "other"
    elif mismatch == "tool":
        tool = "validator_validate_ssti"
        args.pop("boolean_only")
    else:
        args["target_url"] = target + "search/safe?term=alpha&other=beta"
    broker.invoke(tool, args)
    attempts = broker.validation_attempts(spec)
    assert len(attempts) == 1 and attempts[0]["source_artifact"] == view["content_ref"]["path"]
    assert len(wire) == before
    if mismatch == "parameter":
        solver.refresh_candidate_evidence(spec)
        other = next(row for row in solver.plan_candidates(spec)
                     if row["vector"] == "injection-sqli" and row["param"] == "other")
        assert other["executed"] and not other["evidence_accepted"]
        assert other["reason_code"] == "invalid_or_missing_signed_evidence"


def test_compressed_context_still_executes_actual_signed_parameter_slice(replay_lab, monkeypatch):
    import full_agent_python_broker as module
    broker, target, wire = replay_lab
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, FROZEN["parameter_pages"][:1])
    broker.tasks.active_spec = spec
    row = next(row for row in solver.plan_candidates(spec) if row["vector"] == "injection-sqli")
    context = solver.context(spec)
    ref = broker.archive({"text": "x" * 5000})
    context["recent_results"] = [{"tool": READ_TOOL, "content_ref": ref, "result": {"text": "fresh page"}}]
    original = module.completion_request

    def admission(wire, **kwargs):
        if "remaining_phase_calls" in json.loads(wire["messages"][1]["content"]):
            raise BudgetError("force compressed boundary")
        return original(wire, **kwargs)

    monkeypatch.setattr(module, "completion_request", admission)
    sent, _, projection = broker.project_runtime_context({"model": "model", "max_tokens": 1024,
        "tools": solver.tool_schemas(spec), "messages": [{"role": "system", "content": "offline"},
        {"role": "user", "content": provider_json(context).decode()}]}, spec, None)
    assert projection["level"] == 2 and row["tool"] in {item["function"]["name"] for item in sent["tools"]}
    broker.invoke(row["tool"], row["arguments"])
    solver.refresh_candidate_evidence(spec)
    assert row["evidence_accepted"] and row["executed"] and wire


def test_real_catalog_and_candidate_cards_fit_offline_byte_fallback(python_broker, monkeypatch):
    import full_agent_budget as budget_module
    from full_agent_python_solver import SYSTEM
    broker = python_broker
    monkeypatch.setattr(budget_module, "local_encoder", lambda _cache: None)
    broker.load_catalog(broker.private / "state")
    source, spec = broker.tasks.specs[1:3]
    broker.tasks.active_spec = spec
    broker.tasks.bindings = {name: {"target": spec.target, "role": role, "test_data_only": True,
                                  "owned_objects_private": True} for name, role in (
        ("admin-a", "admin"), ("member-a", "member"), ("member-b", "member"))}
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": f"/catalog/{number}?q=1"} for number in range(20)], identity="member-a")
    context = solver.context(spec)
    assert context["candidate_cards"] and context["candidate_count"] == 41
    parameter = next(row for row in solver.plan_candidates(spec) if row["param"])
    assert next(iter(json.loads(parameter["arguments"]["session_bindings"]))) == "member-a"
    sink = {}
    mock_provider(monkeypatch, broker, {"choices": [{"message": {"content": "{}"}}], "usage": {
        "prompt_tokens": 100, "completion_tokens": 100, "total_tokens": 200}}, request_sink=sink)
    broker.completion({"model": "model", "max_tokens": 4096, "tools": solver.tool_schemas(spec), "messages": [
        {"role": "system", "content": SYSTEM}, {"role": "user", "content": provider_json(context).decode()}]})
    names = {tool["function"]["name"] for tool in sink["payload"]["tools"]}
    assert {SUMMARY_TOOL, "hunter_run_web_loop", "validator_validate_sqli", "validator_validate_ssti", "validator_session_vault_check"} <= names
    assert spec.id not in broker.runtime_policy.finalizing and not broker.budget.used["http"]


def test_accumulated_gaps_fit_closing_byte_fallback_with_exact_archive(python_broker, monkeypatch):
    import full_agent_budget as budget_module
    from full_agent_python_solver import SYSTEM
    broker = python_broker
    monkeypatch.setattr(budget_module, "local_encoder", lambda _cache: None)
    broker.load_catalog(broker.private / "state")
    source, spec = broker.tasks.specs[1:3]
    broker.tasks.active_spec = spec
    solver = PythonSolver(broker, model="model")
    ref = observe(broker, solver, source, [{"url": f"/catalog/{number}?q=1"} for number in range(20)])
    for row in solver.plan_candidates(spec):
        row["provenance"] = [{"source_spec_id": source.id, "source_artifact": ref["path"],
                              "source_sha256": ref["sha256"]}] * 8
        solver.add_gap(spec, "invalid_or_missing_signed_evidence", "evidence", row)
    context = solver.context(spec)
    gaps = solver.coverage_gaps[spec.id]
    assert len(provider_json(gaps)) > 24000
    assert len(provider_json(context["coverage_gaps"])) <= 2000
    assert context["coverage_gap_count"] == len(gaps)
    assert broker.read_reference(context["coverage_gap_archive_ref"])["coverage_gaps"] == gaps
    broker.runtime_policy.tool_calls[spec.id] = 14
    sink = {}
    mock_provider(monkeypatch, broker, {"choices": [{"message": {"content": "{}"}}], "usage": {
        "prompt_tokens": 100, "completion_tokens": 100, "total_tokens": 200}}, request_sink=sink)
    broker.completion({"model": "model", "max_tokens": 4096, "tools": solver.tool_schemas(spec), "messages": [
        {"role": "system", "content": SYSTEM}, {"role": "user", "content": provider_json(context).decode()}]})
    payload = sink["payload"]
    assert {row["function"]["name"] for row in payload["tools"]} == {SUMMARY_TOOL}
    sent = json.loads(payload["messages"][1]["content"])
    assert sent["coverage_gap_count"] == len(gaps) and sent["coverage_gaps"]
    assert not broker.budget.used["http"]


def test_full_json_page_keeps_real_catalog_capabilities_and_strict_selection(python_broker, monkeypatch):
    import full_agent_budget as budget_module
    from full_agent_python_solver import SYSTEM, WorkflowError
    broker = python_broker
    monkeypatch.setattr(budget_module, "local_encoder", lambda _cache: None)
    broker.load_catalog(broker.private / "state")
    source, spec = broker.tasks.specs[1:3]
    broker.tasks.active_spec = spec
    broker.tasks.bindings = {name: {"target": spec.target, "role": role, "test_data_only": True,
                                   "owned_objects_private": True} for name, role in (
        ("admin-a", "admin"), ("member-a", "member"), ("member-b", "member"))}
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": f"/catalog/{number}?q=1"} for number in range(20)])
    ref = broker.archive([{"url": spec.target + "catalog?q=1", "source_spec_id": source.id,
                           "source_sha256": "a" * 64}] * 100)
    broker.invoke(READ_TOOL, {"path": ref["path"]})
    context = solver.context(spec)
    sink = {}
    mock_provider(monkeypatch, broker, {"choices": [{"message": {"content": "{}"}}], "usage": {
        "prompt_tokens": 100, "completion_tokens": 100, "total_tokens": 200}}, request_sink=sink)
    broker.completion({"model": "model", "max_tokens": 4096, "tools": solver.tool_schemas(spec), "messages": [
        {"role": "system", "content": SYSTEM}, {"role": "user", "content": provider_json(context).decode()}]})
    sent = json.loads(sink["payload"]["messages"][1]["content"])
    assert len(sent["recent_results"][-1]["result"]["text"]) == 3000
    assert sent["candidate_cards"] and len(provider_json(sent["candidate_cards"])) <= 768
    assert broker.read_reference(sent["context_archive_ref"])["candidate_cards"] == context["candidate_cards"]
    assert {"hunter_run_web_loop", "validator_validate_sqli", "validator_validate_ssti",
            "validator_validate_idor", "validator_session_vault_check", COVERAGE_TOOL} <= set(broker.advertised_tools)
    args = {"target_url": spec.target + "catalog/0?q=1", "param": "q", "boolean_only": True}
    call = lambda value: [{"function": {"name": "validator_validate_sqli", "arguments": json.dumps(value)}}]
    assert solver.parse_calls(call(args), broker.advertised_tools)
    with pytest.raises(WorkflowError) as rejected:
        solver.parse_calls(call({**args, "headers_json": "{}"}), broker.advertised_tools)
    assert rejected.value.code == "tool_arguments_schema_invalid"
    assert spec.id not in broker.runtime_policy.finalizing and not broker.budget.used["http"]


def test_host_stale_session_observation_blocks_repeats_until_primary_refresh(python_broker, monkeypatch):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    broker.tasks.bindings = {name: {"target": spec.target, "role": "member", "test_data_only": True,
                                   "owned_objects_private": True} for name in ("first", "second")}
    broker.catalog["validator"].append({"name": "session_vault_check", "inputSchema": {"type": "object"}})
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/search?q=1"}, {"url": "/render?name=hello"}], identity="first")
    broker.tasks.active_spec = spec
    monkeypatch.setattr(broker, "_check_handoff", lambda _spec: None)
    monkeypatch.setattr(solver, "wait_access_rate_window", lambda _spec: pytest.fail("known stale session cannot be retried"))

    def execute(self, task):
        self.tasks.append(task)
        value = ({"status": "fresh"} if task["tool_name"] == "validator_session_vault_check" else
                 {"ok": False, "skipped": [{"step": "session", "reason_code": "session_not_recently_verified"}]})
        return {"actual_request_cost": 0, "result": {"output": value}}

    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    assert solver.dispatch_access_validation(spec)
    assert len(broker.executor.tasks) == 1 and not broker.budget.used["http"]
    pending = [row for row in solver.plan_candidates(spec) if not row["executed"]]
    assert len(pending) == 4 and all(row["reason_code"] == "session_not_recently_verified" for row in pending)
    broker.invoke("validator_session_vault_check", {"target": spec.target, "identity": "second"})
    assert not solver.admit_candidate(spec, pending[0])
    broker.invoke("validator_session_vault_check", {"target": spec.target, "identity": "first"})
    assert solver.admit_candidate(spec, pending[0]) and not pending[0]["executed"]
    assert len(broker.executor.tasks) == 3 and not broker.budget.used["http"]


def test_summary_funnel_is_a_snapshot_not_mutable_candidate_state(python_broker):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/check?q=1"}])
    rows = solver.plan_candidates(spec)
    snapshot = funnel(rows)
    rows[0]["executed"] = True
    rows[0]["provenance"].clear()
    assert not snapshot["candidates"][0]["executed"] and snapshot["candidates"][0]["provenance"]


def test_model_selection_cannot_bypass_host_slice_and_executes_canonical_defaults(replay_lab, monkeypatch):
    broker, target, wire = replay_lab
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, FROZEN["parameter_pages"][:1])
    broker.tasks.active_spec = spec
    original = broker.completion
    turns = []

    def completion(body):
        turns.append(body)
        if len(turns) <= 2:
            args = {"target_url": target + "search/unsafe?term=alpha", "param": "term", "boolean_only": True}
            if len(turns) == 1:
                args["headers_json"] = '{"Cookie":"synthetic-raw-material"}'
            else:
                assert not broker.executor.tasks and not wire
            message = {"tool_calls": [{"function": {"name": "validator_validate_sqli", "arguments": json.dumps(args)}}]}
        else:
            message = {"content": json.dumps(terminal(spec))}
        mock_provider(monkeypatch, broker, {"choices": [{"message": message}], "usage": {
            "prompt_tokens": 100, "completion_tokens": 100, "total_tokens": 200}})
        return original(body)

    monkeypatch.setattr(broker, "completion", completion)
    summary = solver.phase(spec)
    assert len(turns) == 4 and len(broker.executor.tasks) == 2
    assert [summary["validation_funnel"][stage] for stage in STAGES] == [2] * 5
    args = json.loads(broker.executor.tasks[0]["args_json"])
    assert args["method"] == "GET" and args["carrier"] == "query" and "headers_json" not in args
    assert solver.loop_events[0]["reason_code"] == "model_call_outside_admitted_candidate"


def test_declared_branch_handoff_restores_only_exact_selected_snapshot(python_broker, monkeypatch):
    import hashlib
    from full_agent_executor import HostBroker
    broker = python_broker
    source, spec = broker.tasks.specs[1:3]
    other = TaskSpec.from_dict(source.to_dict())
    other.id, other.depends_on = "other-discovery", []
    branch = TaskSpec.from_dict(spec.to_dict())
    branch.id, branch.depends_on = "other-access", [other.id]
    broker.tasks.specs.extend([other, branch])
    pool = broker.workdir / "object-pool.json"
    packet = broker.workdir / "handoff-access.json"
    for producer in (source, other):
        text = json.dumps({"producer": producer.id})
        broker.branch_handoffs[producer.id] = {"producer_spec_id": producer.id, "target": spec.target,
            "files": {str(path): hashlib.sha256(text.encode()).hexdigest() for path in (pool, packet)},
            "snapshots": {str(path): broker.archive({"exact_text": text}) for path in (pool, packet)}}
    seen = []
    monkeypatch.setattr(HostBroker, "_check_handoff", lambda _broker, current:
        seen.append((current.id, json.loads(pool.read_text())["producer"])))
    broker._check_handoff(spec)
    broker._check_handoff(branch)
    broker._check_handoff(spec)
    assert seen == [(spec.id, source.id), (branch.id, other.id), (spec.id, source.id)]
    spec.vector = "injection-sqli"
    broker._check_handoff(spec)
    assert "injection-sqli" not in broker.handoffs  # An access receipt cannot create vector authority.
    spec.vector = ""
    broker.branch_handoffs[source.id]["snapshots"][str(pool)]["sha256"] = "changed"
    with pytest.raises(ValueError):
        broker._check_handoff(spec)


@pytest.mark.parametrize("query", ["q=1&q=2", "%71=1&q=2", "q=%ZZ", "q=%ff", "=value", "q", "q=1;other=2"])
def test_ambiguous_or_malformed_query_never_becomes_eligible(python_broker, query):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/check?" + query}])
    rows = solver.plan_candidates(spec)
    assert rows and not any(row["eligible"] for row in rows)
    assert not solver.dispatch_access_validation(spec) and not broker.executor.tasks


@pytest.mark.parametrize("params", [None, {"name": "q"}, [{"name": ""}], [{"name": "q", "in": []}],
    [{"name": "q", "in": "query"}, {"name": "q", "in": "body"}]])
def test_malformed_parameter_declarations_are_gaps_not_authority(python_broker, params):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/check?q=1", "params": params}])
    rows = solver.plan_candidates(spec)
    assert rows and not any(row["eligible"] for row in rows)
    assert not broker.executor.tasks


def test_candidate_cards_never_project_query_or_fragment_values(python_broker):
    from python_candidate_runtime import page_cards
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/check?q=synthetic-query-canary&token=synthetic-key-canary#synthetic-fragment-canary"}])
    rows = solver.plan_candidates(spec)
    cards = compact_cards(rows)
    assert cards
    for projected in (cards, page_cards(cards)):
        raw = json.dumps(projected)
        assert not any(value in raw for value in ("synthetic-query-canary", "synthetic-key-canary", "synthetic-fragment-canary"))
        assert all(not urlsplit(row["route"]).query and not urlsplit(row["route"]).fragment for row in projected)


def test_missing_identity_or_provenance_cannot_fall_back_to_anonymous(python_broker):
    from python_candidate_runtime import parameter_candidates
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/check?q=1", "identity": "missing-owned-session"}])
    assert not any(row["eligible"] for row in solver.plan_candidates(spec))
    rows = parameter_candidates(spec, [{"url": spec.target + "check?q=1"}], {})
    assert rows and all(row["reason_code"] == "missing_discovery_provenance" for row in rows)


def test_admission_preflight_is_not_a_checked_dispatch(python_broker, monkeypatch):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/check?q=1"}])
    broker.tasks.active_spec = spec
    monkeypatch.setattr(broker, "_check_handoff", lambda _spec: None)
    row = solver.plan_candidates(spec)[0]
    assert solver.admit_candidate(spec, row)
    assert not row["admitted"] and not row["executed"]
    monkeypatch.setattr(broker.engine, "validate_tool_invocation", lambda *_a, **_kw: {"allowed": False})
    solver.dispatch_access_validation(spec)
    assert not row["admitted"] and not row["executed"] and not broker.executor.tasks


def test_oversize_executed_tool_retains_usage_and_explicit_archive_gap(python_broker, monkeypatch):
    import full_agent_python_broker as module
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [{"url": "/check?q=1"}])
    broker.tasks.active_spec = spec
    monkeypatch.setattr(broker, "_check_handoff", lambda _spec: None)
    monkeypatch.setattr(broker.engine, "tool_capability", lambda _tool: {"network": True})
    monkeypatch.setattr(module, "MAX_ARCHIVE_BYTES", 2048)
    def execute(self, task):
        self.tasks.append(task)
        return {"actual_request_cost": 3, "result": {"output": {"text": "\u20ac" * 1500}}}
    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    assert solver.dispatch_access_validation(spec)
    assert broker.budget.used["http"] == 6
    assert len(broker.executor.tasks) == 2
    assert any(row["reason_code"] == "archive_size_limit_exceeded" for row in solver.coverage_gaps[spec.id])
    assert not any(row["evidence_accepted"] for row in solver.plan_candidates(spec))


def test_utf8_archive_bounds_are_bytes_in_both_directions(python_broker, monkeypatch):
    import full_agent_python_broker as module
    broker = python_broker
    monkeypatch.setattr(module, "MAX_ARCHIVE_BYTES", 32)
    ref = broker.archive("\u20ac" * 10)
    assert ref["bytes"] == 32 and broker.read_reference(ref) == "\u20ac" * 10
    with pytest.raises(ArchiveSizeError):
        broker.archive("\u20ac" * 11)
    # A forged registered size is rejected at read time too, before JSON decoding.
    (broker.workdir / ref["path"]).write_bytes(provider_json("\u20ac" * 11))
    ref["bytes"] = 35
    with pytest.raises(ValueError):
        broker.read_reference(ref)


@pytest.mark.parametrize("change", ["wrong_oracle", "partial_context", "inconclusive"])
def test_signed_but_unbound_or_inconclusive_outcomes_never_become_tested(replay_lab, monkeypatch, change):
    from cco_validator_core import load_validation
    from cco_validator_core.evidence import persist_result
    broker, target, wire = replay_lab
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, FROZEN["parameter_pages"][:1])
    broker.tasks.active_spec = spec
    row = next(row for row in solver.plan_candidates(spec) if row["vector"] == "injection-sqli")
    original = type(broker.executor).__call__
    def execute(self, task):
        execution = original(self, task)
        value = execution["result"]["output"]
        record = load_validation(value["validation_id"])
        if change == "wrong_oracle":
            record["oracle"] = "unrelated_oracle"
        elif change == "partial_context":
            record["execution_context"] = {"param": "term"}
        else:
            record["verdict"] = "INCONCLUSIVE"
        record = persist_result(record, str(Path(record["artifact"]["path"]).parent))
        execution["result"]["output"] = record
        return execution
    monkeypatch.setattr(type(broker.executor), "__call__", execute)
    broker.invoke(row["tool"], row["arguments"])
    assert wire
    summary = solver.compile_summary(spec, terminal(spec))
    assert not summary["tested_parameters"] and not summary["findings"]
    assert not summary["validation_outcomes"] and not summary["validation_funnel"]["evidence_accepted"]


def test_report_rechecks_current_evidence_instead_of_promoting_old_snapshot(replay_lab, monkeypatch):
    import cco_validator_core
    broker, target, wire = replay_lab
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, FROZEN["parameter_pages"][:1])
    broker.tasks.active_spec = spec
    row = next(row for row in solver.plan_candidates(spec) if row["vector"] == "injection-sqli")
    broker.invoke(row["tool"], row["arguments"])
    solver.summaries[spec.id] = solver.compile_summary(spec, terminal(spec))
    assert solver.summaries[spec.id]["validation_funnel"]["evidence_accepted"] == 1
    monkeypatch.setattr(cco_validator_core, "artifact_is_current", lambda *_a, **_kw: False)
    report_spec = broker.tasks.specs[3]
    report = solver.compile_summary(report_spec, terminal(report_spec))
    assert report["validation_funnels"][spec.id]["evidence_accepted"] == 0
    assert any(item["reason_code"] == "invalid_or_missing_signed_evidence" for item in report["coverage_gaps"])
    # The earlier summary is an immutable historical snapshot, not today's proof.
    assert solver.summaries[spec.id]["validation_funnel"]["evidence_accepted"] == 1


def test_changed_discovery_clears_current_funnel_without_dispatch(python_broker):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    ref = observe(broker, solver, source, [{"url": "/check?q=1"}])
    solver.plan_candidates(spec)
    (broker.workdir / ref["path"]).write_text("{}")
    with pytest.raises(ValueError):
        solver.dispatch_access_validation(spec)
    assert not broker.executor.tasks and not broker.budget.used["http"]


def test_conflicting_discovery_carriers_cannot_leave_same_candidate_eligible(python_broker):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [
        {"url": "/check?q=1", "params": [{"name": "q", "in": "query"}]},
        {"url": "/check?q=1", "params": [{"name": "q", "in": "body"}]}])
    rows = solver.plan_candidates(spec)
    assert rows and not any(row["eligible"] for row in rows)
    assert not solver.dispatch_access_validation(spec) and not broker.executor.tasks


def test_changed_discovery_revokes_acceptance_even_with_current_signed_oracle(replay_lab):
    broker, target, wire = replay_lab
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    ref = observe(broker, solver, source, FROZEN["parameter_pages"][:1])
    broker.tasks.active_spec = spec
    row = next(row for row in solver.plan_candidates(spec) if row["vector"] == "injection-sqli")
    broker.invoke(row["tool"], row["arguments"])
    solver.refresh_candidate_evidence(spec)
    assert row["evidence_accepted"]
    (broker.workdir / ref["path"]).write_text("{}")
    with pytest.raises(ValueError):
        solver.refresh_candidate_evidence(spec)
    assert not row["evidence_accepted"] and row["validation_state"] == "NOT TESTED"


def test_final_refresh_failure_revokes_all_task_acceptance(replay_lab, monkeypatch):
    from full_agent_python_solver import WorkflowError
    broker, _target, wire = replay_lab
    source, spec = broker.tasks.specs[1:3]
    branch = TaskSpec.from_dict(spec.to_dict())
    branch.id = "independent-access"
    broker.tasks.specs.append(branch)
    solver = PythonSolver(broker, model="model")
    ref = observe(broker, solver, source, FROZEN["parameter_pages"][:1])
    summary_path = broker.tasks.summary_path(source)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(solver.summaries[source.id]))
    for task in (spec, branch):
        broker.tasks.active_spec = task
        row = next(row for row in solver.plan_candidates(task) if row["vector"] == "injection-sqli")
        broker.invoke(row["tool"], row["arguments"])
        solver.refresh_candidate_evidence(task)
        assert row["evidence_accepted"]
    assert wire
    before = len(wire)
    (broker.workdir / ref["path"]).write_text("{}")
    def stop(_spec):
        raise WorkflowError("offline_diagnostic_stop")
    monkeypatch.setattr(solver, "phase", stop)
    result = solver.run()
    assert result["status"] == "python_failed"
    assert result["stop_reason"] == "candidate_evidence_refresh_failed"
    assert len(wire) == before
    for task in (spec, branch):
        assert result["validation_funnels"][task.id]["evidence_accepted"] == 0
        assert all(not row["evidence_accepted"] and row["validation_state"] == "NOT TESTED"
                   for row in result["validation_funnels"][task.id]["candidates"])
        assert any(gap["task_spec_id"] == task.id and gap["reason_code"] == "prior_phase_evidence_changed"
                   for gap in result["coverage_gaps"])


def test_anonymous_leaf_keeps_stable_candidate_id_across_direct_and_hunter_recipes(replay_lab):
    from python_candidate_runtime import parameter_candidates
    broker, target, wire = replay_lab
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    ref = observe(broker, solver, source, FROZEN["parameter_pages"][:1])
    records = [{"url": target + "search/unsafe?term=alpha", "method": "GET",
                "source_spec_id": source.id, "source_artifact": ref["path"], "source_sha256": ref["sha256"]}]
    spec.tools = ["validator_validate_sqli", "validator_validate_ssti", "hunter_run_web_loop"]
    both_rows = parameter_candidates(spec, records, {})
    spec.tools = ["hunter_run_web_loop"]
    hunter_only_rows = parameter_candidates(spec, records, {})
    spec.tools = ["validator_validate_sqli", "validator_validate_ssti"]
    direct_only_rows = parameter_candidates(spec, records, {})
    assert [r["candidate_id"] for r in both_rows] == [r["candidate_id"] for r in hunter_only_rows]
    assert [r["candidate_id"] for r in both_rows] == [r["candidate_id"] for r in direct_only_rows]
    spec.tools = ["validator_validate_sqli", "validator_validate_ssti", "hunter_run_web_loop"]
    sqli = next(r for r in both_rows if r["vector"] == "injection-sqli")
    assert sqli["tool"] == "validator_validate_sqli"
    assert sqli["validation_profile"] == "readonly_sqli_boolean"
    assert "session_bindings" not in sqli["recipes"]["hunter_run_web_loop"]
    assert matches_model_call(sqli, "validator_validate_sqli", sqli["arguments"])
    assert matches_model_call(sqli, "hunter_run_web_loop", {
        "target": sqli["route"], "live": True, "validation_profile": "readonly_sqli_boolean"})
    assert not matches_model_call(sqli, "hunter_run_web_loop", {
        "target": sqli["route"], "live": True, "validation_profile": "readonly_sqli_boolean",
        "session_bindings": '{"first": {}}'})
    assert "hunter_run_web_loop" not in (direct_only_rows[0].get("recipes") or {})

    broker.tasks.active_spec = spec
    rows = solver.plan_candidates(spec)
    leaf = next(r for r in rows if r["vector"] == "injection-sqli")
    expected_id = leaf["candidate_id"]
    broker.invoke("hunter_run_web_loop", leaf["recipes"]["hunter_run_web_loop"])
    solver.refresh_candidate_evidence(spec)
    assert wire
    assert leaf["candidate_id"] == expected_id
    assert leaf["admitted"] and leaf["executed"] and leaf["evidence_accepted"]
    assert leaf["validation_state"] == "TESTED" and not leaf["reason_code"]
    assert not any(g["candidate_id"] == expected_id for g in solver.coverage_gaps.get(spec.id, []))


def test_direct_leaf_first_followed_by_batched_remainder_without_replay(replay_lab, monkeypatch):
    broker, target, wire = replay_lab
    solver = PythonSolver(broker, model="model", recent_results=0)
    source, spec = broker.tasks.specs[1:3]
    pages = [
        {"url": target + "search/g0"},
        {"url": target + "search/g0/0-unsafe?term=alpha"},
        {"url": target + "search/g0/1-safe?term=alpha"},
        {"url": target + "search/g0/2-unsafe?term=alpha"},
        {"url": target + "search/g0/3-safe?term=alpha"},
        {"url": target + "render/g1"},
        {"url": target + "render/g1/0-unsafe?term=hello"},
        {"url": target + "render/g1/1-safe?term=hello"},
        {"url": target + "render/g1/2-unsafe?term=hello"},
        {"url": target + "render/g1/3-safe?term=hello"},
    ]
    observe(broker, solver, source, pages)
    broker.tasks.active_spec = spec
    first_leaf_url = target + "search/g0/0-unsafe?term=alpha"
    original = broker.completion
    turns = []

    def completion(body):
        turns.append(body)
        if len(turns) == 1:
            message = {"tool_calls": [{"function": {"name": "validator_validate_sqli", "arguments": json.dumps({
                "target_url": first_leaf_url, "param": "term", "boolean_only": True})}}]}
        else:
            message = {"content": json.dumps(terminal(spec))}
        mock_provider(monkeypatch, broker, {"choices": [{"message": message}], "usage": {
            "prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
        return original(body)

    monkeypatch.setattr(broker, "completion", completion)
    summary = solver.phase(spec)
    # 1 model direct + 3 SQLi residuals in g0 + 1 SSTI batch in g0 + 2 batches (SQLi+SSTI) in g1 = 7 tasks.
    assert len(broker.executor.tasks) == 7
    assert [task["tool_name"] for task in broker.executor.tasks].count("validator_validate_sqli") == 4
    assert [task["tool_name"] for task in broker.executor.tasks].count("hunter_run_web_loop") == 3
    # Accepted first_leaf_url SQLi must never be replayed.
    assert sum(1 for task in broker.executor.tasks
               if task["tool_name"] == "validator_validate_sqli"
               and json.loads(task["args_json"])["target_url"] == first_leaf_url) == 1
    assert [summary["validation_funnel"][stage] for stage in STAGES] == [16] * 5
    assert len(summary["validation_outcomes"]) == 16
    assert sum(r["verdict"] == "CONFIRMED" for r in summary["validation_outcomes"]) == 4
    assert sum(r["verdict"] == "UNCONFIRMED" for r in summary["validation_outcomes"]) == 12
    assert not any(g["reason_code"] == "invalid_or_missing_signed_evidence" for g in summary["coverage_gaps"])
    before = len(wire)
    assert not solver.dispatch_access_validation(spec) and len(wire) == before


def test_grouped_16_endpoint_32_leaf_executes_all_positive_and_negative_controls(replay_lab, monkeypatch):
    broker, target, wire = replay_lab
    solver = PythonSolver(broker, model="model", recent_results=0)
    source, spec = broker.tasks.specs[1:3]
    pages = []
    for stem, term_val in (("search", "alpha"), ("render", "hello")):
        for grp in ("g0", "g1"):
            pages.append({"url": target + f"{stem}/{grp}"})
            for idx in range(4):
                kind = "unsafe" if idx % 2 == 0 else "safe"
                pages.append({"url": target + f"{stem}/{grp}/{idx}-{kind}?term={term_val}"})
    observe(broker, solver, source, pages)
    broker.tasks.active_spec = spec
    original = broker.completion

    def completion(body):
        mock_provider(monkeypatch, broker, {"choices": [{"message": {"content": json.dumps(terminal(spec))}}],
                      "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
        return original(body)

    monkeypatch.setattr(broker, "completion", completion)
    summary = solver.phase(spec)
    assert len(broker.executor.tasks) == 8
    assert broker.runtime_policy.tool_calls[spec.id] == 8
    assert all(task["tool_name"] == "hunter_run_web_loop" for task in broker.executor.tasks)
    assert [summary["validation_funnel"][stage] for stage in STAGES] == [32] * 5
    outcomes = summary["validation_outcomes"]
    assert len(outcomes) == 32
    assert sum(r["verdict"] == "CONFIRMED" and r["vector"] == "injection-sqli" for r in outcomes) == 4
    assert sum(r["verdict"] == "UNCONFIRMED" and r["vector"] == "injection-sqli" for r in outcomes) == 12
    assert sum(r["verdict"] == "CONFIRMED" and r["vector"] == "injection-ssti" for r in outcomes) == 4
    assert sum(r["verdict"] == "UNCONFIRMED" and r["vector"] == "injection-ssti" for r in outcomes) == 12
    assert broker.budget.used["http"] == len(wire) <= 250
    assert not any(g["reason_code"] == "invalid_or_missing_signed_evidence" for g in summary["coverage_gaps"])
    before = len(wire)
    assert not solver.dispatch_access_validation(spec) and len(wire) == before


def test_partial_pair_checkpoint_report_rechecks_and_tamper_revocation(replay_lab, monkeypatch):
    from cco_validator_core import load_validation
    from cco_validator_core.evidence import persist_result
    from test_python_holdout_regressions import prepare_identity_replay

    broker, _target, wire = replay_lab
    solver, spec = prepare_identity_replay(broker)
    solver.batches_by_task[spec.id] = solver.batches_by_task[spec.id][:1]
    batch = solver.batches_by_task[spec.id][0]
    for ident, previous in solver.summaries.items():
        path = broker.tasks.summary_path(next(s for s in broker.tasks.specs if s.id == ident))
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(provider_json(previous))
    solver.checkpoint.acquire()
    solver._checkpoint_active = True
    try:
        original = type(broker.executor).__call__
        accepted_vid = []

        def partial_execute(self, task):
            result = original(self, task)
            report = result["result"]["output"]
            validations = list(report.get("validations") or [])
            assert len(validations) >= 2
            accepted_vid.append(validations[0]["validation_id"])
            if len(validations) >= 3:
                rec = load_validation(validations[1]["validation_id"])
                rec["verdict"] = "INCONCLUSIVE"
                persist_result(rec, str(Path(rec["artifact"]["path"]).parent))
                validations[1]["verdict"] = "INCONCLUSIVE"
                report["validations"] = validations[:2]
            else:
                report["validations"] = validations[:1]
            report["identity_discovery"]["budget_limited"] = True
            return result

        monkeypatch.setattr(type(broker.executor), "__call__", partial_execute)
        assert solver.dispatch_access_validation(spec)
        access_summary = solver.compile_summary(spec, terminal(spec, status="partial", steps=[
            {"id": step.id, "status": "not_tested"} for step in spec.steps]))
        solver.summaries[spec.id] = access_summary
        access_path = broker.tasks.summary_path(spec)
        access_path.parent.mkdir(exist_ok=True)
        access_path.write_bytes(provider_json(access_summary))
        solver.task_states[spec.id] = "completed"
        solver.save_checkpoint()
    finally:
        solver._checkpoint_active = False
        solver.checkpoint.release()

    # Restore in a fresh PythonSolver and compile report: partial remainder persists without replay or invalid_or_missing_signed_evidence.
    resumed = PythonSolver(broker, model="model", resume=True)
    resumed.restore_checkpoint()
    assert spec.id in resumed.leaf_outcomes_by_task and spec.id in resumed.pair_progress_by_task
    assert resumed.pair_progress_by_task[spec.id]["partial_pairs"] == 1
    before_wire = len(wire)
    report_spec = broker.tasks.specs[3]
    report = resumed.compile_summary(report_spec, terminal(report_spec))
    assert len(wire) == before_wire
    assert report["status"] == "partial"
    assert report["validation_funnels"][spec.id]["evidence_accepted"] == 0
    assert report["leaf_validation_funnels"][spec.id]["accepted"] == 1
    assert report["pair_progress_by_task"][spec.id]["partial_pairs"] == 1
    assert report["identity_comparisons"][0]["status"] == "NOT TESTED"
    assert not any(g["reason_code"] == "invalid_or_missing_signed_evidence" for g in report["coverage_gaps"])
    assert not resumed.dispatch_access_validation(spec) and len(wire) == before_wire

    # Tampering the accepted leaf evidence revokes acceptance cleanly on refresh and report.
    tampered_record = load_validation(accepted_vid[0])
    Path(tampered_record["artifact"]["path"]).write_text("{}")
    tampered_report = resumed.compile_summary(report_spec, terminal(report_spec))
    assert tampered_report["leaf_validation_funnels"][spec.id]["accepted"] == 0
    assert tampered_report["leaf_validation_funnels"][spec.id]["invalid_evidence"] >= 1
    assert tampered_report["pair_progress_by_task"][spec.id]["partial_pairs"] == 0
    assert tampered_report["pair_progress_by_task"][spec.id]["complete_pairs"] == 0
    assert resumed.completed_member_batch(spec, batch) is False
    assert any(g["reason_code"] == "invalid_or_missing_signed_evidence" for g in tampered_report["coverage_gaps"])


def test_tampering_signed_inconclusive_leaf_revokes_indeterminate_state(replay_lab, monkeypatch):
    from cco_validator_core import load_validation
    from cco_validator_core.evidence import persist_result

    broker, _target, _wire = replay_lab
    solver = PythonSolver(broker, model="model")
    source, spec = broker.tasks.specs[1:3]
    observe(broker, solver, source, FROZEN["parameter_pages"][:1])
    broker.tasks.active_spec = spec
    row = next(r for r in solver.plan_candidates(spec) if r["vector"] == "injection-sqli")

    original = type(broker.executor).__call__
    recorded_path = []

    def inconclusive_execute(self, task):
        execution = original(self, task)
        vid = execution["result"]["output"]["validation_id"]
        record = load_validation(vid)
        record["verdict"] = "INCONCLUSIVE"
        record = persist_result(record, str(Path(record["artifact"]["path"]).parent))
        recorded_path.append(record["artifact"]["path"])
        execution["result"]["output"] = record
        return execution

    monkeypatch.setattr(type(broker.executor), "__call__", inconclusive_execute)
    broker.invoke(row["tool"], row["arguments"])
    summary = solver.compile_summary(spec, terminal(spec))
    assert summary["leaf_validation_funnel"]["indeterminate"] == 1
    assert summary["leaf_validation_funnel"]["invalid_evidence"] == 0
    assert not any(g["reason_code"] == "invalid_or_missing_signed_evidence" for g in summary["coverage_gaps"])

    # Tamper the signed INCONCLUSIVE artifact on disk -> must downgrade to invalid_evidence on refresh/report.
    Path(recorded_path[0]).write_text("{}")
    report_spec = broker.tasks.specs[3]
    solver.summaries[spec.id] = summary
    report = solver.compile_summary(report_spec, terminal(report_spec))
    assert report["leaf_validation_funnels"][spec.id]["indeterminate"] == 0
    assert report["leaf_validation_funnels"][spec.id]["invalid_evidence"] == 1
    assert any(g["reason_code"] == "invalid_or_missing_signed_evidence" for g in report["coverage_gaps"])
