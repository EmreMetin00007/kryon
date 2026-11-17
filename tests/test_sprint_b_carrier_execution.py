"""Sprint B Slice 3 tests: end-to-end POST form/json execution and signed completion binding."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest
from jinja2 import Template

from conftest import load_server
from full_agent_launcher import lab_policy
from full_agent_provider import dump
from full_agent_python_solver import PythonSolver
from policy_engine import PolicyEngine
from python_candidate_runtime import STAGES
from signed_completion import verify_signed_completion
from test_full_agent_python_solver import python_broker, terminal
from test_python_candidate_runtime import catalog


@pytest.fixture
def post_carrier_lab(python_broker, tmp_path, monkeypatch):
    validator = load_server("validator")
    from cco_validator_core.egress import scoped_wire_gate
    from wire_budget import campaign_wire_budget

    db = sqlite3.connect(":memory:", check_same_thread=False)
    rows = [("alpha", "memo-alpha"), ("beta", "memo-beta")]
    db.execute("CREATE TABLE items(term TEXT, memo TEXT)")
    db.executemany("INSERT INTO items VALUES (?, ?)", rows)
    db.commit()
    db_lock = threading.Lock()
    wire: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _reply(self, status: int, text: str, ctype: str = "text/plain") -> None:
            raw = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/":
                html = (
                    '<form action="/search/unsafe" method="POST"><input name="term" value="alpha"></form>'
                    '<form action="/search/safe" method="POST"><input name="term" value="alpha"></form>'
                    '<form action="/render/unsafe" method="POST" enctype="application/json">'
                    '<input name="name" value="alice"></form>'
                    '<form action="/render/safe" method="POST" enctype="application/json">'
                    '<input name="name" value="alice"></form>'
                    '<form action="/unauthorized" method="POST"><input name="term" value="alpha"></form>'
                )
                wire.append({"method": "GET", "path": "/", "status": 200})
                return self._reply(200, html, "text/html")
            wire.append({"method": "GET", "path": parsed.path, "status": 404})
            self._reply(404, "missing")

        def do_POST(self):
            parsed = urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace")
            ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            wire.append({"method": "POST", "path": parsed.path, "ctype": ctype, "body": body})
            if parsed.path in {"/search/unsafe", "/search/safe"}:
                if ctype != "application/x-www-form-urlencoded":
                    return self._reply(415, "expected form")
                form = dict(parse_qsl(body, keep_blank_values=True))
                val = form.get("term", "")
                with db_lock:
                    try:
                        if parsed.path == "/search/unsafe":
                            res = db.execute(f"SELECT memo FROM items WHERE term = '{val}'").fetchall()
                        else:
                            res = db.execute("SELECT memo FROM items WHERE term = ?", (val,)).fetchall()
                        return self._reply(200, json.dumps({"records": res}), "application/json")
                    except sqlite3.Error:
                        return self._reply(400, json.dumps({"error": "invalid"}), "application/json")
            if parsed.path in {"/render/unsafe", "/render/safe"}:
                if ctype != "application/json":
                    return self._reply(415, "expected json")
                try:
                    payload = json.loads(body)
                except ValueError:
                    return self._reply(400, "bad json")
                val = str(payload.get("name", ""))
                if parsed.path == "/render/unsafe":
                    try:
                        return self._reply(200, Template(val).render())
                    except Exception:
                        return self._reply(400, "template error")
                return self._reply(200, "literal: " + val)
            self._reply(404, "not found")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    target = f"http://127.0.0.1:{server.server_port}/"
    for spec in python_broker.tasks.specs:
        spec.target = target
    catalog(python_broker)

    scope_dir = python_broker.workdir.parent / "scope"
    scope_dir.mkdir()
    scope, policy = lab_policy(target)
    policy["readonly_operations"] = [
        {"method": "POST", "url": target + "search/unsafe", "operation_id": "op-sql-unsafe", "carriers": ["form"], "read_only": True},
        {"method": "POST", "url": target + "search/safe", "operation_id": "op-sql-safe", "carriers": ["form"], "read_only": True},
        {"method": "POST", "url": target + "render/unsafe", "operation_id": "op-ssti-unsafe", "carriers": ["json"], "read_only": True},
        {"method": "POST", "url": target + "render/safe", "operation_id": "op-ssti-safe", "carriers": ["json"], "read_only": True},
    ]
    dump(scope_dir / "scope.json", scope)
    dump(scope_dir / "program-policy.json", policy)
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope_dir / "scope.json"))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(scope_dir / "program-policy.json"))
    (python_broker.private / "state/permissions.json").write_text("{}", encoding="utf-8")
    real_engine = PolicyEngine(
        cco_home=str(python_broker.private / "state"),
        scope_file=str(scope_dir / "scope.json"),
        program_policy_file=str(scope_dir / "program-policy.json"),
    )
    python_broker.engine = real_engine
    monkeypatch.setattr(python_broker, "_check_handoff", lambda _spec: None)

    def execute(self, task):
        self.tasks.append(task)
        args = json.loads(task["args_json"])
        tool_name = task["tool_name"]

        def gate(method, url, headers):
            decision = python_broker.engine.validate_wire_invocation(
                tool_name,
                {"target": url, "endpoint": url, "url": url, "method": method, "headers": headers},
            )
            return decision["allowed"], decision["reason"]

        with campaign_wire_budget(task["reserved_request_cost"], uuid.uuid4().hex) as budget, scoped_wire_gate(gate):
            fn = getattr(validator, tool_name.removeprefix("validator_"))
            raw = fn(**args)
            value = json.loads(raw)
        return {
            "tool": tool_name,
            "arguments": args,
            "result": {"output": value},
            "actual_request_cost": budget.used,
            "execution_failed": False,
        }

    monkeypatch.setattr(type(python_broker.executor), "__call__", execute)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield python_broker, target, wire, scope_dir
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        db.close()


def test_end_to_end_post_form_and_json_sqli_ssti_and_signed_completions(post_carrier_lab):
    broker, target, wire, _scope_dir = post_carrier_lab
    recon, enum_spec, access_spec, report_spec = broker.tasks.specs

    # Enum fetches root HTML containing both form and json POST forms + unauthorized POST.
    solver = PythonSolver(broker, model="model")
    import requests
    root_html = requests.get(target, timeout=5).text
    enum_view = broker.view({"status_code": 200, "text": root_html})
    broker.results.append({
        "spec_id": enum_spec.id,
        "tool": "kali-tools_curl_request",
        "arguments": {"url": target, "follow_redirects": False},
        **enum_view,
    })
    solver.summaries[enum_spec.id] = solver.compile_summary(enum_spec, terminal(enum_spec))

    broker.tasks.active_spec = access_spec
    assert solver.dispatch_access_validation(access_spec) is True
    summary = solver.compile_summary(access_spec, terminal(access_spec))

    # Unauthorized POST never received any wire traffic.
    assert not any(entry["path"] == "/unauthorized" for entry in wire)

    # 2 confirmed findings (form SQLi + json SSTI) and 2 negative_verified (form SQLi + json SSTI).
    findings = summary["findings"]
    assert {f["vector"] for f in findings} == {"injection-sqli", "injection-ssti"}
    assert len(findings) == 2

    funnel = summary["validation_funnel"]
    # 4 authorized POST endpoints * 2 applicable profiles (SQLi + SSTI) = 8 eligible POST candidates.
    assert funnel["admitted"] == 8
    assert funnel["executed"] == 8
    assert funnel["evidence_accepted"] == 8
    assert funnel["outcomes"]["positive"] == 2
    assert funnel["outcomes"]["completed_negative"] == 6

    leaves = summary["leaf_outcomes"]
    form_safe = next(l for l in leaves if l["url"].endswith("/search/safe") and l["vector"] == "injection-sqli")
    assert form_safe["method"] == "POST"
    assert form_safe["carrier"] == "form"
    assert form_safe["status"] == "accepted"
    assert form_safe["verdict"] == "UNCONFIRMED"

    json_safe = next(l for l in leaves if l["url"].endswith("/render/safe") and l["vector"] == "injection-ssti")
    assert json_safe["method"] == "POST"
    assert json_safe["carrier"] == "json"
    assert json_safe["status"] == "accepted"
    assert json_safe["verdict"] == "UNCONFIRMED"

    # Signed completion envelopes bind exact method and carrier and fail closed on mismatch.
    completions = broker.signed_completions(access_spec)
    assert len({c["payload"]["completion_id"] for c in completions}) == 6
    form_comp = next(c for c in completions if c["payload"]["execution_context"]["url"].endswith("/search/safe"))
    ok_form, _, _ = verify_signed_completion(
        form_comp["envelope"], expected_target=target, expected_method="POST", expected_carrier="form"
    )
    assert ok_form is True
    bad_method, _, _ = verify_signed_completion(
        form_comp["envelope"], expected_target=target, expected_method="GET", expected_carrier="form"
    )
    assert bad_method is False
    bad_carrier, _, _ = verify_signed_completion(
        form_comp["envelope"], expected_target=target, expected_method="POST", expected_carrier="query"
    )
    assert bad_carrier is False

    # Check report phase aggregates cleanly.
    report_summary = solver.compile_summary(report_spec, terminal(report_spec))
    assert report_summary["validation_funnels"][access_spec.id]["evidence_accepted"] == 8
    assert [report_summary["validation_funnels"][access_spec.id][s] for s in STAGES[2:]] == [8, 8, 8]
