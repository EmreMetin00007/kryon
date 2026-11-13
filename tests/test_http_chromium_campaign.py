"""Offline execution contracts and opt-in real HTTP/Chromium campaigns.

Offline doubles test orchestration only, never real browser acceptance.
"""
import json
import os
from http.server import ThreadingHTTPServer
import threading

import pytest

from test_automatic_negative_controls import (
    BASE, HEADERS, SEEDS, assert_observed_campaign_controls, campaign_environment,
    environment, transport,
)
from test_campaign_gap_bridge import PolicyEngine
from test_http_chromium_lab import LocalMCPExecutor

@pytest.mark.skipif(os.environ.get("CCO_RUN_WIRE_LAB") != "1",
                   reason="opt-in owned HTTP/Chromium campaign")
@pytest.mark.parametrize("seed", SEEDS)
def test_real_chromium_surface_to_observed_campaign(tmp_path, monkeypatch, seed):
    from scripts.lab.blind_lab import make_lab
    from cco_validator_core.egress import save_shared_session

    handler, state = make_lab(seed, version="blind-lab/3")
    calls = []
    server = thread = None
    base = ""

    class CountingHandler(handler):
        def _record(self):
            with state["lock"]:
                calls.append({"method": self.command, "url": base + self.path.lstrip("/"),
                              "program_header_present": self.headers.get("X-Research") == HEADERS["X-Research"]})

        def do_GET(self):
            self._record()
            super().do_GET()

        def do_POST(self):
            self._record()
            self._send(405, "read-only acceptance fixture")

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = do_POST

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), CountingHandler)
        base = f"http://127.0.0.1:{server.server_port}/"
        environment = campaign_environment(tmp_path, monkeypatch, base=base, fast=False)
        enable_execution(tmp_path)
        _, home, scope = environment
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
                    "CCO_BROWSER_CDP", "CCO_WORKER_ALLOWED_TOOLS"):
            monkeypatch.delenv(key, raising=False)
        for key, value in {"NO_PROXY": "127.0.0.1,localhost", "CCO_PROXY": "", "CCO_HEADED": "0",
                           "CCO_SURFACE_AUTO_INGEST": "1", "CCO_WORKDIR": str(tmp_path / "work"),
                           "HACKERONE_HANDLE": "researcher", "CCO_RESEARCH_HEADER": "X-Research"}.items():
            monkeypatch.setenv(key, value)
        engine = PolicyEngine(cco_home=str(home), scope_file=str(scope))
        engine.grant_approval("browser_browser_extract_links", "127.0.0.1", ttl_seconds=900,
                              reason="user-approved test-owned Chromium acceptance")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def browser_discovery(_bindings):
            before = len(calls)
            # Only public program headers enter the shared browser session;
            # authenticated campaign credentials stay in their account vaults.
            save_shared_session(base, headers=HEADERS, cco_home=str(home))
            result = LocalMCPExecutor(home, timeout_seconds=60)({
                "tool_name": "browser_browser_extract_links", "request_cost": 8,
                "args_json": json.dumps({"url": base, "wait_seconds": 0.2})})
            data = json.loads(result["result"]["output"])
            assert not result.get("execution_failed") and not result["wire_usage"]["blocked_reason"]
            assert not data.get("fallback_reason"), data
            assert data.get("urls_with_params") and data.get("surface_ingest"), data
            assert not data["surface_ingest"].get("error"), data
            count = len(calls) - before
            assert count > 0 and result["actual_request_cost"] == count
            (tmp_path / "chromium-discovery.json").write_text(json.dumps({
                "tool": result["result"]["tool_name"], "requests": count,
                "parameterized_links": len(data["urls_with_params"]),
                "ingest": data["surface_ingest"], "fallback": False}, indent=2))
            return count

        payload = assert_observed_campaign_controls(
            environment, monkeypatch, tmp_path, seed, state, calls, base=base,
            before_discovery=browser_discovery, mode="real_http_chromium")
        assert state["requests"] == payload["requests"] == len(calls)
        assert payload["score"]["proven"] == 8
        assert all(call["method"] == "GET" and call["program_header_present"] for call in calls)
        assert all(call["url"].startswith(base) for call in calls)
    finally:
        if server is not None:
            if thread is not None:
                server.shutdown()
                thread.join(timeout=5)
            server.server_close()
        state["db"].close()
        (tmp_path / "received-wire.json").write_text(json.dumps({
            "mode": "real_http_chromium", "seed": seed, "base": base,
            "received_requests": len(calls), "requests": calls}, indent=2))


def enable_execution(tmp_path, **overrides):
    policy = tmp_path / "policy.json"
    data = json.loads(policy.read_text())
    data["xss_execution"] = {"enabled": True, "max_browser_requests": 8, "wait_ms": 0, **overrides}
    policy.write_text(json.dumps(data))


@pytest.fixture
def browser_protocol(monkeypatch):
    """Exercise real gates/dialog callbacks with an explicitly offline double.

    This tiny SVG simulator is not a JavaScript engine or execution evidence
    for the lab. The opt-in test above must separately prove that in Chromium.
    """
    import re
    import sys
    from types import SimpleNamespace
    import requests
    from test_browser_session_policy import Context, Page, Request, Route

    state = {"behavior": "correlated", "contexts": [], "closed": False, "after_response": None}

    class OfflinePage(Page):
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
                headers["Cookie"] = "; ".join(row["name"] + "=" + row["value"]
                                               for row in self.context.cookies_added)
            route = Route(Request(url, headers=headers))
            self.context.request_handler(route)
            if route.action != "continued":
                raise RuntimeError("offline browser request denied")
            response = requests.Session().request("GET", url, headers=headers, allow_redirects=False)
            self.url = url
            result = SimpleNamespace(status=response.status_code, url=url, headers=dict(response.headers),
                                     body=lambda: response.content)
            self.context.handlers["response"](result)
            index = len(state["contexts"]) - 1
            behavior = state["behavior"]
            match = re.search(r'<svg onload="alert\(\'(cco-xss-[a-f0-9]+)\'\)"></svg>', response.text)
            message = match[1] if match else None
            if behavior == "reflection_only" or (behavior == "missing_repeat" and index == 3):
                message = None
            elif behavior == "wrong_marker" and message:
                message = "unrelated-alert"
            elif behavior == "baseline_alert" and index == 0:
                message = "background-alert"
            elif behavior == "inert_alert" and index == 1:
                message = "background-alert"
            if behavior == "changed_url":
                self.url = url + "#different"
            if message:
                dialog = SimpleNamespace(type="alert", message=message, dismiss=lambda: None,
                                         page=object() if behavior == "other_page" else self)
                self.handlers["dialog"](dialog)
            if state["after_response"]:
                state["after_response"](index)
            return result

    class OfflineContext(Context):
        def __init__(self, headers):
            super().__init__()
            self.headers = headers

        def new_page(self):
            page = OfflinePage(self)
            self.pages.append(page)
            return page

    class OfflineBrowser:
        version = "offline-protocol-double"

        def new_context(self, **kwargs):
            assert kwargs["service_workers"] == "block" and kwargs["accept_downloads"] is False
            context = OfflineContext(kwargs["extra_http_headers"])
            state["contexts"].append(context)
            return context

        def close(self):
            state["closed"] = True

    class OfflinePlaywright:
        def __enter__(self):
            if state["behavior"] == "browser_unavailable":
                raise RuntimeError("offline missing browser")
            return SimpleNamespace(chromium=SimpleNamespace(launch=lambda **_: OfflineBrowser()))

        def __exit__(self, *_):
            pass

    monkeypatch.setitem(sys.modules, "playwright.sync_api", SimpleNamespace(sync_playwright=OfflinePlaywright))
    return state


def xss_candidate(path="search"):
    return {"url": BASE + path + "?q=laptop", "method": "GET", "param": "q", "carrier": "query",
            "vuln_class": "xss_reflected", "identity": "anonymous", "resource_owner": "unspecified",
            "run_id": "execution-run"}


def assert_http_preconditions(calls, result):
    """The observed baseline and negative control surround the reflection probe.

    These three real HTTP requests precede the four browser rounds and share
    their campaign budget. They cannot be omitted from wire/evidence counts.
    """
    from urllib.parse import parse_qs, urlsplit
    assert parse_qs(urlsplit(calls[0]).query) == {"q": ["laptop"]}
    assert parse_qs(urlsplit(calls[2]).query) == {"q": ["laptop"]}
    assert parse_qs(urlsplit(calls[1]).query)["q"][0].startswith("<cco")
    assert [row["role"] for row in result["request_evidence"][:3]] == [
        "baseline", "reflection-probe", "negative-control"]


@pytest.mark.parametrize("behavior,expected", [
    ("correlated", "CONFIRMED"), ("reflection_only", "INCONCLUSIVE"), ("wrong_marker", "INCONCLUSIVE"),
    ("missing_repeat", "INCONCLUSIVE"), ("baseline_alert", "INCONCLUSIVE"), ("inert_alert", "INCONCLUSIVE"),
    ("other_page", "INCONCLUSIVE"), ("changed_url", "INCONCLUSIVE"),
])
def test_reflection_requires_correlated_browser_execution(environment, monkeypatch, tmp_path,
                                                         browser_protocol, behavior, expected):
    from scripts.lab.blind_lab import make_lab
    from cco_validator_core.evidence import artifact_is_valid
    hunter, *_ = environment
    enable_execution(tmp_path)
    browser_protocol["behavior"] = behavior
    handler, state = make_lab(20261104, version="blind-lab/3")
    try:
        calls = transport(monkeypatch, handler)
        candidate = xss_candidate()
        result = json.loads(hunter._loop_validate(candidate, headers=json.dumps(HEADERS)))
        assert result["verdict"] == expected, result
        assert result["evidence"]["reflection"]["reflected_raw"]
        assert result["evidence"]["execution"]["observed"] == (expected == "CONFIRMED")
        assert len(calls) == (4 if behavior == "changed_url" else 7)
        assert_http_preconditions(calls, result)
        assert artifact_is_valid(result)
        assert hunter._record_coverage_validation(BASE, candidate, result)
        assert hunter._verified_coverage_events(BASE)[0]["status"] == (
            "confirmed" if expected == "CONFIRMED" else "inconclusive")
        assert browser_protocol["closed"] and all(ctx.closed for ctx in browser_protocol["contexts"])
        if expected == "CONFIRMED":
            assert result["reportable"] and result["confidence"] > 0
            rows = result["evidence"]["execution"]["observations"]
            assert len({row["nonce_sha256"] for row in rows[1:]}) == 3
            assert len(result["request_evidence"]) == len(calls) == 7
            assert result["evidence"]["execution"]["browser_requests"] == 4
    finally:
        state["db"].close()


@pytest.mark.parametrize("setting", [None, {"enabled": False}, {"enabled": True, "max_browser_requests": 3}])
def test_execution_requires_valid_policy_opt_in(environment, monkeypatch, tmp_path, browser_protocol, setting):
    from scripts.lab.blind_lab import make_lab
    if setting is not None:
        enable_execution(tmp_path, **setting)
    handler, state = make_lab(20261104, version="blind-lab/3")
    try:
        calls = transport(monkeypatch, handler)
        result = json.loads(environment[0]._loop_validate(xss_candidate(), headers=json.dumps(HEADERS)))
        assert result["verdict"] == "INCONCLUSIVE" and len(calls) == 3
        assert_http_preconditions(calls, result)
        assert not browser_protocol["contexts"]
    finally:
        state["db"].close()


@pytest.mark.parametrize("budget", [1, 2, 3, 4, 5, 6, 7])
def test_browser_requests_share_the_campaign_budget(environment, monkeypatch, tmp_path, browser_protocol, budget):
    from scripts.lab.blind_lab import make_lab
    enable_execution(tmp_path)
    monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", str(budget))
    handler, state = make_lab(20261104, version="blind-lab/3")
    try:
        calls = transport(monkeypatch, handler)
        result = json.loads(environment[0]._loop_validate(xss_candidate(), headers=json.dumps(HEADERS)))
        assert len(calls) == budget
        assert result["verdict"] == ("CONFIRMED" if budget == 7 else "INCONCLUSIVE")
        if budget < 3:
            assert not browser_protocol["contexts"]
            assert not result["guard"]["transport_ok"]
            assert "execution" not in result["evidence"]
        else:
            assert_http_preconditions(calls, result)
            assert result["evidence"]["execution"]["browser_requests"] == budget - 3
    finally:
        state["db"].close()


@pytest.mark.parametrize("changed", ["scope.json", "policy.json"])
def test_browser_stops_if_context_changes(environment, monkeypatch, tmp_path, browser_protocol, changed):
    from scripts.lab.blind_lab import make_lab
    enable_execution(tmp_path)
    path = tmp_path / changed
    browser_protocol["after_response"] = lambda _: path.write_text(path.read_text() + "\n")
    handler, state = make_lab(20261104, version="blind-lab/3")
    try:
        calls = transport(monkeypatch, handler)
        result = json.loads(environment[0]._loop_validate(xss_candidate(), headers=json.dumps(HEADERS)))
        assert result["verdict"] == "INCONCLUSIVE" and len(calls) == 4
        assert_http_preconditions(calls, result)
    finally:
        state["db"].close()


def test_browser_unavailable_cannot_fall_back_to_http(environment, monkeypatch, tmp_path, browser_protocol):
    from scripts.lab.blind_lab import make_lab
    enable_execution(tmp_path)
    browser_protocol["behavior"] = "browser_unavailable"
    handler, state = make_lab(20261104, version="blind-lab/3")
    try:
        calls = transport(monkeypatch, handler)
        result = json.loads(environment[0]._loop_validate(xss_candidate(), headers=json.dumps(HEADERS)))
        assert result["verdict"] == "INCONCLUSIVE" and len(calls) == 3
        assert_http_preconditions(calls, result)
        assert result["evidence"]["execution"]["error_kind"] == "RuntimeError"
        assert not result["reportable"]
    finally:
        state["db"].close()


def test_async_tool_context_keeps_gates_and_execution_binding(environment, monkeypatch, tmp_path, browser_protocol):
    import asyncio
    from scripts.lab.blind_lab import make_lab
    enable_execution(tmp_path)
    handler, state = make_lab(20261104, version="blind-lab/3")
    candidate = xss_candidate()

    async def invoke():
        return json.loads(environment[0]._loop_validate(candidate, headers=json.dumps(HEADERS)))

    try:
        calls = transport(monkeypatch, handler)
        result = asyncio.run(invoke())
        assert result["verdict"] == "CONFIRMED" and len(calls) == 7
        assert_http_preconditions(calls, result)
        assert result["execution_context"] == environment[0]._coverage_context(candidate)
        assert environment[0]._record_coverage_validation(BASE, candidate, result)
    finally:
        state["db"].close()


def test_browser_keeps_session_binding_and_stops_on_revocation(environment, monkeypatch, tmp_path, browser_protocol):
    from scripts.lab.blind_lab import make_lab
    from cco_hunter_core.request_context import current_policy_gate, policy_scoped
    enable_execution(tmp_path)
    active = [True]
    browser_protocol["after_response"] = lambda _: active.__setitem__(0, False)
    headers = {**HEADERS, "Authorization": "Bearer offline-test-identity", "Cookie": "sid=offline-cookie"}

    @policy_scoped("hunter_run_web_loop")
    def invoke():
        current_policy_gate().require_session_guard(lambda: active[0])
        return json.loads(environment[0]._loop_validate(xss_candidate(), headers=json.dumps(headers)))

    handler, state = make_lab(20261104, version="blind-lab/3")
    try:
        calls = transport(monkeypatch, handler)
        result = invoke()
        assert result["verdict"] == "INCONCLUSIVE" and len(calls) == 4
        assert_http_preconditions(calls, result)
        context = browser_protocol["contexts"][0]
        assert context.headers["Authorization"] == headers["Authorization"]
        assert context.cookies_added == [{"name": "sid", "value": "offline-cookie", "url": BASE}]
        assert "offline-test-identity" not in json.dumps(result) and "offline-cookie" not in json.dumps(result)
    finally:
        state["db"].close()


@pytest.mark.parametrize("fault", ["nonce", "request_evidence", "fallback", "incomplete"])
def test_incomplete_or_uncorrelated_browser_artifact_cannot_confirm(
        environment, monkeypatch, tmp_path, browser_protocol, fault):
    from scripts.lab.blind_lab import make_lab
    from cco_validator_core import xss_execution
    enable_execution(tmp_path)
    original = xss_execution.run_browser

    def corrupted(*args, **kwargs):
        result = original(*args, **kwargs)
        assert result["completed"]
        if fault == "nonce":
            result["observations"][-1]["nonce_sha256"] = "0" * 64
        elif fault == "request_evidence":
            result["request_evidence"].pop()
        elif fault == "fallback":
            result["fallback"] = True
        else:
            result["completed"] = False
        return result

    monkeypatch.setattr(xss_execution, "run_browser", corrupted)
    handler, state = make_lab(20261104, version="blind-lab/3")
    try:
        transport(monkeypatch, handler)
        result = json.loads(environment[0]._loop_validate(xss_candidate(), headers=json.dumps(HEADERS)))
        assert result["verdict"] == "INCONCLUSIVE" and not result["reportable"]
    finally:
        state["db"].close()


@pytest.mark.parametrize("url,method", [("https://outside.test/", "GET"), (BASE, "POST"),
                                      ("https://owned.test:444/", "GET")])
def test_browser_blocks_cross_origin_and_write_requests(environment, monkeypatch, tmp_path,
                                                        browser_protocol, url, method):
    from scripts.lab.blind_lab import make_lab
    from test_browser_session_policy import Request, Route
    enable_execution(tmp_path)
    denied = []

    def attempt(_index):
        route = Route(Request(url, method=method, headers=HEADERS))
        browser_protocol["contexts"][-1].request_handler(route)
        denied.append(route.action)

    browser_protocol["after_response"] = attempt
    handler, state = make_lab(20261104, version="blind-lab/3")
    try:
        calls = transport(monkeypatch, handler)
        result = json.loads(environment[0]._loop_validate(xss_candidate(), headers=json.dumps(HEADERS)))
        assert result["verdict"] == "INCONCLUSIVE" and len(calls) == 4
        assert_http_preconditions(calls, result)
        assert denied == ["aborted"]
    finally:
        state["db"].close()


@pytest.mark.parametrize("seed", SEEDS)
def test_offline_surface_to_execution_campaign(environment, monkeypatch, tmp_path, browser_protocol, seed):
    from scripts.lab.blind_lab import make_lab
    enable_execution(tmp_path)
    handler, state = make_lab(seed, version="blind-lab/3")
    try:
        calls = transport(monkeypatch, handler)
        payload = assert_observed_campaign_controls(environment, monkeypatch, tmp_path, seed, state, calls,
            mode="offline_browser_protocol_double")
        assert payload["score"]["proven"] == 8
        assert payload["score"]["negatives_clean"] == 8
        assert len(browser_protocol["contexts"]) == 4
        assert browser_protocol["closed"] and all(ctx.closed for ctx in browser_protocol["contexts"])
    finally:
        state["db"].close()
