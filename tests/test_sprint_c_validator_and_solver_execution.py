"""Sprint C Slice 2 tests: validator/hunter execution and signed_completion v1 for XSS & Open Redirect."""
from __future__ import annotations

import asyncio
import html
import json
import re
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

import pytest
import requests

from conftest import load_server
from full_agent_launcher import lab_policy
from full_agent_provider import dump
from full_agent_python_solver import PythonSolver
from policy_engine import PolicyEngine
from signed_completion import verify_signed_completion
from test_browser_session_policy import Context, Page, Request, Route
from test_full_agent_python_solver import python_broker, terminal


@pytest.fixture
def browser_double(monkeypatch):
    """Deterministic Playwright Chromium double that fires alert only on executable <svg onload=...> outside <textarea>."""
    state = {"contexts": [], "closed": False}

    class DoublePage(Page):
        def __init__(self, context):
            super().__init__(context)
            self.handlers = {}

        def on(self, event, callback):
            self.handlers[event] = callback

        def wait_for_timeout(self, _ms):
            pass

        def goto(self, url, **_kwargs):
            headers = dict(self.context.headers)
            if self.context.cookies_added:
                headers["Cookie"] = "; ".join(
                    row["name"] + "=" + row["value"] for row in self.context.cookies_added
                )
            route = Route(Request(url, headers=headers))
            self.context.request_handler(route)
            if route.action != "continued":
                raise RuntimeError("browser request denied")
            response = requests.Session().request("GET", url, headers=headers, allow_redirects=False)
            self.url = url
            result = SimpleNamespace(
                status=response.status_code,
                url=url,
                headers=dict(response.headers),
                body=lambda: response.content,
            )
            self.context.handlers["response"](result)
            # Only fire alert if <svg onload="alert('cco-xss-...')"> is rendered outside a <textarea>.
            text_outside_textarea = re.sub(r"<textarea\b[^>]*>.*?</textarea>", "", response.text, flags=re.S | re.I)
            match = re.search(r'<svg onload="alert\(\'(cco-xss-[a-f0-9]+)\'\)"></svg>', text_outside_textarea)
            if match and "dialog" in self.handlers:
                dialog = SimpleNamespace(
                    type="alert",
                    message=match.group(1),
                    dismiss=lambda: None,
                    page=self,
                )
                self.handlers["dialog"](dialog)
            return result

    class DoubleContext(Context):
        def __init__(self, headers):
            super().__init__()
            self.headers = headers

        def new_page(self):
            page = DoublePage(self)
            self.pages.append(page)
            return page

    class DoubleBrowser:
        version = "chromium-headless-test/1"

        def new_context(self, **kwargs):
            ctx = DoubleContext(kwargs.get("extra_http_headers") or {})
            state["contexts"].append(ctx)
            return ctx

        def close(self):
            state["closed"] = True

    class DoublePlaywright:
        def __enter__(self):
            return SimpleNamespace(chromium=SimpleNamespace(launch=lambda **_: DoubleBrowser()))

        def __exit__(self, *_):
            pass

    monkeypatch.setitem(sys.modules, "playwright.sync_api", SimpleNamespace(sync_playwright=DoublePlaywright))
    return state


@pytest.fixture
def xss_redirect_lab(python_broker, tmp_path, monkeypatch, browser_double):
    validator = load_server("validator")
    from cco_validator_core.egress import scoped_wire_gate
    from wire_budget import campaign_wire_budget

    wire: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _reply(self, status: int, text: str, ctype: str = "text/html", location: str = "") -> None:
            raw = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            if location:
                self.send_header("Location", location)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlsplit(self.path)
            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            wire.append({"method": "GET", "path": parsed.path, "query": parsed.query})
            if parsed.path == "/":
                body = (
                    '<html><body>'
                    '<a href="/xss/unsafe?q=hello">XSS Unsafe</a>'
                    '<a href="/xss/safe?q=hello">XSS Safe</a>'
                    '<a href="/xss/reflect-only?q=hello">XSS Reflect Only</a>'
                    '<a href="/go/unsafe?next=/home">Redirect Unsafe</a>'
                    '<a href="/go/safe?next=/home">Redirect Safe</a>'
                    '</body></html>'
                )
                return self._reply(200, body)
            if parsed.path == "/home":
                return self._reply(200, "<html><body>Home</body></html>")
            if parsed.path == "/xss/unsafe":
                val = qs.get("q", "")
                return self._reply(200, f"<html><body><div>{val}</div></body></html>")
            if parsed.path == "/xss/safe":
                val = qs.get("q", "")
                return self._reply(200, f"<html><body><div>{html.escape(val)}</div></body></html>")
            if parsed.path == "/xss/reflect-only":
                val = qs.get("q", "")
                # Reflects raw <cco> marker inside <textarea>, where <svg onload=...> does not execute JS.
                return self._reply(200, f"<html><body><textarea>{val}</textarea></body></html>")
            if parsed.path == "/go/unsafe":
                nxt = qs.get("next", "/home")
                return self._reply(302, "", location=nxt)
            if parsed.path == "/go/safe":
                nxt = qs.get("next", "/home")
                if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
                    return self._reply(400, "<html><body>Invalid redirect target</body></html>")
                return self._reply(302, "", location="/home")
            return self._reply(404, "missing", "text/plain")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    target = f"http://127.0.0.1:{server.server_port}/"
    for spec in python_broker.tasks.specs:
        spec.target = target
    python_broker.catalog["validator"] = [
        row.model_dump(mode="json", exclude_none=True, exclude={"outputSchema"})
        for row in asyncio.run(validator.mcp.list_tools())
        if row.name in {
            "validate_sqli",
            "validate_ssti",
            "validate_path_traversal",
            "validate_xss_reflection",
            "validate_open_redirect",
            "validate_idor",
        }
    ]
    python_broker.catalog["hunter"] = [{"name": "run_web_loop", "inputSchema": {"type": "object"}}]
    python_broker.catalog["kali-tools"].append({"name": "crawl_web_surface", "inputSchema": {"type": "object"}})

    scope_dir = python_broker.workdir.parent / "scope"
    scope_dir.mkdir()
    scope, policy = lab_policy(target)
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
            if tool_name == "hunter_run_web_loop":
                from cco_validator_core.evidence import redact_url, validation_context
                from python_candidate_runtime import PROFILES
                from urllib.parse import urljoin

                profile = args["validation_profile"]
                fn = getattr(validator, PROFILES[profile][1].removeprefix("validator_"))
                target_parsed = urlsplit(args["target"])
                prefix = target_parsed.path.rstrip("/")
                vclass = "xss_reflected" if profile == "readonly_xss_reflection" else "open_redirect"
                queue, validations, seen_urls = [], [], set()
                for entry in python_broker.results:
                    data = python_broker.read_reference(entry["content_ref"])
                    html_text = data.get("text", "") if isinstance(data, dict) else ""
                    for href in re.findall(r'href="([^"]+)"', html_text):
                        full_url = redact_url(urljoin(target, href))
                        parsed = urlsplit(full_url)
                        if (parsed.scheme, parsed.netloc) != (target_parsed.scheme, target_parsed.netloc):
                            continue
                        if not (parsed.path == prefix or parsed.path.startswith(prefix + "/")):
                            continue
                        if not parsed.query or full_url in seen_urls:
                            continue
                        if (profile == "readonly_xss_reflection" and not parsed.path.startswith("/xss/")) or (
                            profile == "readonly_open_redirect" and not parsed.path.startswith("/go/")
                        ):
                            continue
                        seen_urls.add(full_url)
                        for param, _ in parse_qsl(parsed.query, keep_blank_values=True):
                            item = {
                                "url": full_url,
                                "method": "GET",
                                "param": param,
                                "carrier": "query",
                                "identity": "anonymous",
                                "vuln_class": vclass,
                                "run_id": "run-sprint-c",
                            }
                            queue.append(item)
                            with validation_context(item):
                                extra = {"bounded_controls": True} if profile == "readonly_open_redirect" else {}
                                record = json.loads(fn(target_url=full_url, param=param, **extra))
                            validations.append({
                                **item,
                                "verdict": record["verdict"],
                                "validation_id": record["validation_id"],
                            })
                value = {"ok": True, "run_id": "run-sprint-c", "validation_queue": queue, "validations": validations}
            else:
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
        yield python_broker, validator, target, wire
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_direct_xss_and_open_redirect_validators_bind_context_and_emit_signed_completions(xss_redirect_lab):
    _broker, validator, target, _wire = xss_redirect_lab

    # 1. validate_xss alias and positive execution confirmation
    assert validator.validate_xss is validator.validate_xss_reflection
    pos_xss = json.loads(validator.validate_xss(f"{target}xss/unsafe?q=hello", param="q"))
    assert pos_xss["verdict"] == "CONFIRMED"
    assert pos_xss["oracle"] == "browser_execution"
    assert pos_xss["execution_context"]["vuln_class"] == "xss_reflected"
    assert pos_xss["execution_context"]["param"] == "q"
    assert "signed_completion" not in pos_xss

    # 2. Reflection-only without alert execution remains INCONCLUSIVE (zero false positive!)
    refl_only = json.loads(validator.validate_xss_reflection(f"{target}xss/reflect-only?q=hello", param="q"))
    assert refl_only["verdict"] == "INCONCLUSIVE"
    assert refl_only["reportable"] is False
    assert "signed_completion" not in refl_only

    # 3. Safe HTML-escaped XSS emits UNCONFIRMED + verified signed_completion v1
    neg_xss = json.loads(validator.validate_xss_reflection(f"{target}xss/safe?q=hello", param="q"))
    assert neg_xss["verdict"] == "UNCONFIRMED"
    assert neg_xss["execution_context"]["param"] == "q"
    assert isinstance(neg_xss.get("signed_completion"), dict)
    ok_xss, payload_xss, err_xss = verify_signed_completion(
        neg_xss["signed_completion"],
        expected_target=target,
        expected_url=f"{target}xss/safe?q=hello",
        expected_param="q",
        expected_method="GET",
        expected_carrier="query",
        expected_profile="readonly_xss_reflection",
    )
    assert ok_xss is True and payload_xss is not None and err_xss == ""

    # 4. Positive Open Redirect confirmation
    pos_redir = json.loads(validator.validate_open_redirect(f"{target}go/unsafe?next=/home", param="next"))
    assert pos_redir["verdict"] == "CONFIRMED"
    assert pos_redir["oracle"] == "redirect_location"
    assert pos_redir["execution_context"]["vuln_class"] == "open_redirect"
    assert pos_redir["execution_context"]["param"] == "next"
    assert "signed_completion" not in pos_redir

    # 5. Safe same-origin / validated Open Redirect emits UNCONFIRMED + verified signed_completion v1
    neg_redir = json.loads(
        validator.validate_open_redirect(f"{target}go/safe?next=/home", param="next", bounded_controls=True)
    )
    assert neg_redir["verdict"] == "UNCONFIRMED"
    assert neg_redir["execution_context"]["param"] == "next"
    assert isinstance(neg_redir.get("signed_completion"), dict)
    ok_redir, payload_redir, err_redir = verify_signed_completion(
        neg_redir["signed_completion"],
        expected_target=target,
        expected_url=f"{target}go/safe?next=%2Fhome",
        expected_param="next",
        expected_method="GET",
        expected_carrier="query",
        expected_profile="readonly_open_redirect",
    )
    assert ok_redir is True and payload_redir is not None and err_redir == ""


def test_solver_end_to_end_xss_and_open_redirect_execution_and_leaf_accounting(xss_redirect_lab):
    broker, _validator, target, _wire = xss_redirect_lab
    _recon, enum_spec, access_spec, report_spec = broker.tasks.specs

    solver = PythonSolver(broker, model="model")
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

    # Exactly 2 confirmed findings (/xss/unsafe and /go/unsafe); /xss/reflect-only is NOT a finding!
    findings = summary["findings"]
    assert len(findings) == 2
    assert {f["vector"] for f in findings} == {"xss-stored", "authn-session"}
    confirmed_urls = {
        urlsplit(row["url"]).path
        for row in summary["validation_outcomes"]
        if row["verdict"] == "CONFIRMED"
    }
    assert confirmed_urls == {"/xss/unsafe", "/go/unsafe"}

    # Funnel: 5 eligible candidates (3 XSS + 2 Redirect); 4 accepted (2 positive + 2 negative_verified), 1 indeterminate (/xss/reflect-only).
    funnel = summary["validation_funnel"]
    assert funnel["eligible"] == 5
    assert funnel["admitted"] == 5
    assert funnel["executed"] == 5
    assert funnel["evidence_accepted"] == 4
    assert funnel["outcomes"]["positive"] == 2
    assert funnel["outcomes"]["completed_negative"] == 2
    assert funnel["outcomes"]["failed"] == 1

    # Check each of the 5 eligible leaf outcomes by (path, vector):
    leaf_by_path_vec = {(urlsplit(l["url"]).path, l["vector"]): l for l in summary["leaf_outcomes"]}
    assert leaf_by_path_vec[("/xss/unsafe", "xss-stored")]["verdict"] == "CONFIRMED"
    assert leaf_by_path_vec[("/xss/safe", "xss-stored")]["verdict"] == "UNCONFIRMED"
    assert leaf_by_path_vec[("/xss/safe", "xss-stored")]["status"] == "accepted"
    assert leaf_by_path_vec[("/xss/reflect-only", "xss-stored")]["status"] == "indeterminate"
    assert leaf_by_path_vec[("/xss/reflect-only", "xss-stored")]["verdict"] == "INCONCLUSIVE"
    assert leaf_by_path_vec[("/go/unsafe", "authn-session")]["verdict"] == "CONFIRMED"
    assert leaf_by_path_vec[("/go/safe", "authn-session")]["verdict"] == "UNCONFIRMED"
    assert leaf_by_path_vec[("/go/safe", "authn-session")]["status"] == "accepted"

    completions = broker.signed_completions(access_spec)
    comp_urls = {c["payload"]["execution_context"]["url"] for c in completions}
    assert comp_urls == {f"{target}xss/safe?q=hello", f"{target}go/safe?next=%2Fhome"}

    report_summary = solver.compile_summary(report_spec, terminal(report_spec))
    assert report_summary["validation_funnels"][access_spec.id]["evidence_accepted"] == 4
