"""Shared native-worker accounting with fake HTTP/browser transports only."""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys

import pytest

from conftest import FakeCDPContext, FakeCDPFrame, load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
for name in ("mcp-validator", "mcp-browser", "mcp-hunter", "mcp-memory-server"):
    sys.path.insert(0, str(ROOT / "mcp-servers" / name))
from campaign_runtime import CampaignRuntime  # noqa: E402
import campaign_worker as worker  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from wire_budget import (campaign_wire_budget, consume_request, current_budget, validate_usage)  # noqa: E402

BASE = "https://owned.test/allowed/"


class Response:
    def __init__(self, url=BASE, status=200, text="synthetic safe page", location=""):
        self.status_code, self.text, self.url = status, text, url
        self.content = text.encode()
        self.headers = {"Location": location} if location else {}


class Request:
    frame = FakeCDPFrame()
    method = "GET"
    url = BASE + "page"
    def all_headers(self):
        return {"X-Research": "researcher"}


class Route:
    request = Request()
    def abort(self, reason):
        self.action = "aborted"
    def continue_(self, **kwargs):
        self.action = "sent"


class BrowserContext(FakeCDPContext):
    pages = []
    def route(self, pattern, handler):
        self.handler = handler
    def on(self, event, handler):
        if event == "response":
            self.response_handler = handler
    def route_web_socket(self, pattern, handler):
        self.websocket_handler = handler


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home, scope, policy = tmp_path / "home", tmp_path / "scope.json", tmp_path / "policy.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": BASE}], "allow_loopback": False}))
    policy.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"}}))
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path / "work"))
    monkeypatch.delenv("CCO_WORKER_ALLOWED_TOOLS", raising=False)
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
    for tool in ("validator_validate_xss_reflection", "validator_validate_auth_bypass", "kali-tools_curl_request",
                 "browser_browser_extract_links", "hunter_run_web_loop", "kali-tools_nmap_scan"):
        engine.grant_approval(tool, "owned.test", ttl_seconds=600, reason="synthetic")
    return home, engine, scope, policy


def native_executor(home, monkeypatch):
    """Run the real child dispatcher in-process so transports stay synthetic."""
    executor = worker.LocalMCPExecutor(home)
    def run(command, payload, **kwargs):
        captured = []
        monkeypatch.setattr(worker, "_read_child_payload", lambda *_: payload)
        monkeypatch.setattr(worker, "_emit_child_result", lambda value, **_: captured.append(value))
        monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", kwargs["env"]["CCO_CAMPAIGN_WIRE_BUDGET"])
        worker._execute_tool_child()
        response = captured[0]
        if not response["ok"]:
            raise worker.ChildExecutionError(response)
        return response, {}
    monkeypatch.setattr(executor, "_run_subprocess", run)
    return executor


def test_all_adapters_share_one_allowance_and_browser_thread_does_not_reset_it(setup):
    from cco_validator_core.egress import egress_request, reset_request_count
    from cco_browser_core.policy import install_readonly_request_gate
    from cco_surface_core.wire import guarded_get, scoped_surface_requests
    _, engine, *_ = setup
    sends = []
    def transport(method, url, **kwargs):
        sends.append(url)
        return Response(url)
    def gate(method, url, headers):
        decision = engine.validate_wire_invocation("validator_validate_xss_reflection", {
            "target": url, "url": url, "method": method, "headers": headers})
        return decision["allowed"], decision["reason"]
    context = BrowserContext()
    install_readonly_request_gate(context, engine, "browser_browser_extract_links")
    with campaign_wire_budget(3, "a" * 32) as budget:
        first = egress_request("GET", BASE, headers={"X-Research": "researcher"}, transport=transport)
        assert first["ok"]
        route = Route()
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(context.handler, route).result()
        assert route.action == "sent"
        with scoped_surface_requests(gate, BASE):
            assert guarded_get(BASE, headers={"X-Research": "researcher"}, timeout=2,
                               proxies=None, sender=lambda url, **kw: transport("GET", url))
        reset_request_count()  # Resetting the validator's old counter gives no new allowance.
        final = egress_request("GET", BASE, transport=transport)
        assert not final["ok"] and final["blocked"] == "budget"
        assert budget.snapshot()["authorized_requests"] == 3
        assert len(sends) == 2  # The browser route was the third authorized transport.
    assert current_budget() is None


def test_concurrent_adapters_cannot_exceed_allowance():
    with campaign_wire_budget(7, "b" * 32) as budget:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: consume_request()[0], range(40)))
        assert sum(results) == budget.snapshot()["authorized_requests"] == 7


def test_nested_budget_cannot_reset_allowance():
    with campaign_wire_budget(1, "a" * 32):
        assert consume_request()[0]
        with pytest.raises(ValueError, match="already active"):
            with campaign_wire_budget(100, "b" * 32):
                pytest.fail("must not replace active allowance")
        assert not consume_request()[0]


@pytest.mark.parametrize("limit,expected", [(0, 0), (1, 1), (2, 2)])
def test_curl_redirects_spend_each_hop_without_shell_execution(setup, monkeypatch, limit, expected):
    import requests
    home, *_ = setup
    sends = []
    def send(method, url, **kwargs):
        sends.append((method, url))
        assert kwargs["allow_redirects"] is False
        return Response(url, status=302, location="next") if len(sends) == 1 else Response(url)
    monkeypatch.setattr(requests, "request", send)
    executor = native_executor(home, monkeypatch)
    out = executor({"tool_name": "kali-tools_curl_request", "args_json": json.dumps({
        "url": BASE, "headers": "X-Research: researcher"}), "request_cost": limit})
    assert len(sends) == out["actual_request_cost"] == expected
    result = json.loads(out["result"]["output"])
    assert (result.get("blocked") == "budget") is (limit < 2)


def test_curl_extra_args_are_rejected_before_dispatch_without_spending(setup, monkeypatch):
    import requests
    home, *_ = setup
    monkeypatch.setattr(requests, "request", lambda *a, **kw: pytest.fail("must not send"))
    executor = native_executor(home, monkeypatch)
    out = executor({"tool_name": "kali-tools_curl_request", "args_json": json.dumps({
        "url": BASE, "extra_args": "--retry 10"}), "request_cost": 4})
    assert out["execution_failed"] and out["actual_request_cost"] == 0
    assert out["result"]["error_type"] == "UnsupportedWireAccounting"


@pytest.mark.parametrize("change", ["scope", "grant", "header"])
def test_each_redirect_rechecks_admission_before_spending(setup, monkeypatch, change):
    import requests
    home, engine, scope, _ = setup
    calls = []
    def send(method, url, **kwargs):
        calls.append(url)
        if change == "scope":
            scope.write_text(json.dumps({"in_scope": []}))
        elif change == "grant":
            for grant in engine.list_approvals():
                if grant["tool_pattern"] == "kali-tools_curl_request":
                    engine.revoke_approval(grant["id"])
        return Response(url, status=302, location="next")
    monkeypatch.setattr(requests, "request", send)
    executor = native_executor(home, monkeypatch)
    out = executor({"tool_name": "kali-tools_curl_request", "args_json": json.dumps({
        "url": BASE, "headers": "" if change == "header" else "X-Research: researcher"}), "request_cost": 4})
    assert len(calls) == out["actual_request_cost"] == (0 if change == "header" else 1)
    assert json.loads(out["result"]["output"])["blocked"] == "policy"


def test_two_different_tools_settle_one_campaign_budget_and_partial_validator_stays_blocked(setup, monkeypatch):
    import requests
    home, _, scope, _ = setup
    sends = []
    def send(method, url, **kwargs):
        sends.append(url)
        return Response(url)
    monkeypatch.setattr(requests, "request", send)
    runtime = CampaignRuntime(str(home))
    campaign = runtime.create_campaign("synthetic", scope_file=str(scope), budget_requests=2)
    runtime.enqueue_task(campaign, "web", "kali-tools_curl_request", {
        "url": BASE, "headers": "X-Research: researcher"}, request_cost=1)
    runtime.enqueue_task(campaign, "web", "validator_validate_auth_bypass", {
        "protected_url": BASE, "authorized_headers_json": '{"X-Research":"researcher","Authorization":"Bearer synthetic-account"}'},
                         request_cost=1)
    executor = native_executor(home, monkeypatch)
    runner = worker.CampaignWorker(runtime, "synthetic", executor)
    assert runner.run_once(campaign)["status"] == "done"
    assert runner.run_once(campaign)["status"] == "blocked"
    assert runner.run_once(campaign) == {"claimed": False}
    assert runtime.show_campaign(campaign)["requests_used"] == len(sends) == 2
    assert runtime.show_campaign(campaign)["requests_reserved"] == 0


def test_hunter_validator_adapter_is_charged_once(setup, monkeypatch):
    import requests
    from cco_validator_core.egress import egress_request, scoped_wire_gate
    from cco_hunter_core.request_context import current_policy_gate, policy_scoped
    sends = []
    monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", "4")
    monkeypatch.setattr(requests, "request", lambda method, url, **kw: sends.append(url) or Response(url))
    @policy_scoped("hunter_run_web_loop")
    def invoke():
        gate = current_policy_gate()
        with scoped_wire_gate(gate):
            assert egress_request("GET", BASE, headers={"X-Research": "researcher"})["ok"]
        return gate.authorized_requests()
    with campaign_wire_budget(4, "a" * 32) as budget:
        assert invoke() == budget.snapshot()["authorized_requests"] == len(sends) == 1


def test_hunter_browser_adapter_is_charged_once(setup, monkeypatch):
    from cco_browser_core.policy import install_readonly_request_gate
    from cco_surface_core.crawl import _GateAdapter
    from cco_hunter_core.request_context import current_policy_gate, policy_scoped
    monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", "4")
    @policy_scoped("hunter_run_web_loop")
    def invoke():
        gate = current_policy_gate()
        context = BrowserContext()
        install_readonly_request_gate(context, _GateAdapter(gate), "hunter_run_web_loop")
        route = Route()
        context.handler(route)
        assert route.action == "sent"
        return gate.authorized_requests()
    with campaign_wire_budget(4, "a" * 32) as budget:
        assert invoke() == budget.snapshot()["authorized_requests"] == 1


def test_browser_plain_http_fallback_uses_same_native_counter(setup, monkeypatch):
    import requests
    home, *_ = setup
    sends = []
    monkeypatch.setattr(requests, "request", lambda method, url, **kw:
                        sends.append(url) or Response(url, status=302, location="next"))
    browser = worker._load_server_module("mcp-browser", home)
    monkeypatch.setattr(browser, "HAS_PLAYWRIGHT", False)
    monkeypatch.setattr(browser, "_proxy_available", lambda: False)
    monkeypatch.setattr(browser, "_research_headers", lambda: {"X-Research": "researcher"})
    out = native_executor(home, monkeypatch)({"tool_name": "browser_browser_extract_links", "args_json": json.dumps({
        "url": BASE}), "request_cost": 1})
    assert out["actual_request_cost"] == len(sends) == 1
    assert out["wire_usage"]["blocked_reason"] == "campaign request budget exhausted"


def test_network_custom_executor_is_rejected_before_its_code_runs(setup, monkeypatch, tmp_path):
    from test_campaign_worker import _write_custom_executor
    home, _, scope, _ = setup
    monkeypatch.setenv("CCO_ENABLE_CUSTOM_WORKER_EXECUTOR", "1")
    contract, _ = _write_custom_executor(tmp_path)
    custom = worker.CustomSubprocessExecutor(contract)
    monkeypatch.setattr(custom, "_run_subprocess", lambda *a, **kw: pytest.fail("custom code must not run"))
    runtime = CampaignRuntime(str(home))
    campaign = runtime.create_campaign("synthetic", scope_file=str(scope), budget_requests=4)
    runtime.enqueue_task(campaign, "web", "kali-tools_curl_request", {
        "url": BASE, "headers": "X-Research: researcher"}, request_cost=4)
    out = worker.CampaignWorker(runtime, "synthetic", custom).run_once(campaign)
    assert out["status"] == "blocked" and out["error"] == "UnsupportedWireAccounting"
    assert runtime.show_campaign(campaign)["requests_used"] == 0


def test_manifest_cannot_open_more_requests_than_campaign_reserved(setup):
    from test_campaign_chain import MANIFEST, _AllowGate
    home, _, scope, _ = setup
    runtime = CampaignRuntime(str(home))
    sends = []
    def sender(*args):
        sends.append(args)
        return {"ok": True, "status": 200, "text": "alice@example.com", "len": 17,
                "headers": {}, "location": "", "error": None}
    executor = worker.ChainTaskExecutor(runtime, sender=sender, policy_engine=_AllowGate())
    with pytest.raises(RuntimeError, match="chain terminal"):
        executor({"id": 1, "request_cost": 1, "reserved_request_cost": 1, "args_json": json.dumps({
            "manifest": MANIFEST, "target_bases": {"scope-asset-1": "https://owned.test"}})})
    assert len(sends) == 1 and MANIFEST["budget"]["max_requests"] == 10


def test_native_policy_failure_cannot_be_saved_as_completed_validation(setup, monkeypatch):
    home, engine, scope, _ = setup
    for grant in engine.list_approvals():
        if grant["tool_pattern"] == "validator_validate_xss_reflection":
            engine.revoke_approval(grant["id"])
    # The synthetic dispatch bypasses the queue check to exercise the final
    # request gate after a grant could have changed between claim and send.
    runtime = CampaignRuntime(str(home))
    monkeypatch.setattr(runtime, "_validate_task_policy", lambda *a, **kw: {"allowed": True})
    campaign = runtime.create_campaign("synthetic", scope_file=str(scope), budget_requests=4)
    runtime.enqueue_task(campaign, "web", "validator_validate_xss_reflection", {
        "target_url": BASE, "headers_json": '{"X-Research":"researcher"}'}, request_cost=4)
    out = worker.CampaignWorker(runtime, "synthetic", native_executor(home, monkeypatch)).run_once(campaign)
    assert out["status"] == "blocked" and runtime.show_campaign(campaign)["requests_used"] == 0


def test_native_exception_preserves_observed_cost_instead_of_charging_full_reservation(setup, monkeypatch):
    home, _, scope, _ = setup
    runtime = CampaignRuntime(str(home))
    campaign = runtime.create_campaign("synthetic", scope_file=str(scope), budget_requests=4)
    runtime.enqueue_task(campaign, "web", "validator_validate_xss_reflection", {
        "target_url": BASE, "headers_json": '{"X-Research":"researcher"}'}, request_cost=4)
    def fail(*a, **kw):
        assert consume_request()[0]
        raise RuntimeError("synthetic private detail")
    monkeypatch.setattr(worker, "_invoke_local_mcp_tool", fail)
    out = worker.CampaignWorker(runtime, "synthetic", native_executor(home, monkeypatch)).run_once(campaign)
    assert out["status"] == "blocked" and "private detail" not in json.dumps(out)
    assert runtime.show_campaign(campaign)["requests_used"] == 1


def test_transport_error_preserves_attempt_count_even_when_validator_returns_a_report(setup, monkeypatch):
    import requests
    home, _, scope, _ = setup
    def fail(*a, **kw):
        raise requests.ConnectionError("synthetic connection failure")
    monkeypatch.setattr(requests, "request", fail)
    runtime = CampaignRuntime(str(home))
    campaign = runtime.create_campaign("synthetic", scope_file=str(scope), budget_requests=4)
    runtime.enqueue_task(campaign, "web", "validator_validate_xss_reflection", {
        "target_url": BASE, "headers_json": '{"X-Research":"researcher"}'}, request_cost=4)
    out = worker.CampaignWorker(runtime, "synthetic", native_executor(home, monkeypatch)).run_once(campaign)
    assert out["status"] == "blocked" and runtime.show_campaign(campaign)["requests_used"] == 1
    assert out["result"]["wire_usage"]["blocked_reason"] == "campaign transport failed"


def test_failed_chain_settles_measured_requests_instead_of_full_reservation(setup, monkeypatch):
    from test_campaign_chain import MANIFEST, _AllowGate
    home, _, scope, _ = setup
    manifest = json.loads(json.dumps(MANIFEST))
    manifest["steps"] = [{"id": "one", "tool": "http_get", "args": {"path": "/allowed/"},
                          "expect": {"oracle": "status_code", "status": 500},
                          "on_success": "succeed", "on_failure": "fail"}]
    runtime = CampaignRuntime(str(home))
    monkeypatch.setattr(runtime, "_validate_task_policy", lambda *a, **kw: {"allowed": True})
    campaign = runtime.create_campaign("synthetic", scope_file=str(scope), budget_requests=4)
    runtime.enqueue_task(campaign, "chain", "chain_runner_execute", {"url": BASE, "manifest": manifest,
        "target_bases": {"scope-asset-1": "https://owned.test"}}, request_cost=4)
    sender = lambda *a: {"ok": True, "status": 200, "text": "synthetic", "len": 9,
                         "headers": {}, "location": "", "error": None}
    runner = worker.ChainTaskExecutor(runtime, sender=sender, policy_engine=_AllowGate())
    out = worker.CampaignWorker(runtime, "synthetic", chain_executor=runner).run_once(campaign)
    assert out["status"] == "blocked" and runtime.show_campaign(campaign)["requests_used"] == 1


def test_unsupported_scanner_child_does_not_load_or_execute_the_scanner(setup):
    home, _, scope, _ = setup
    scope.write_text(json.dumps({"in_scope": [{"asset": "owned.test"}]}))
    runtime = CampaignRuntime(str(home))
    campaign = runtime.create_campaign("synthetic", scope_file=str(scope), budget_requests=4)
    runtime.enqueue_task(campaign, "web", "kali-tools_nmap_scan", {"target": "owned.test"}, request_cost=4)
    out = worker.CampaignWorker(runtime, "synthetic", worker.LocalMCPExecutor(home)).run_once(campaign)
    assert out["status"] == "blocked" and out["result"]["error_type"] == "UnsupportedWireAccounting"
    assert runtime.show_campaign(campaign)["requests_used"] == 0


@pytest.mark.parametrize("mode", ["timeout", "stale", "generic_failure", "bad_usage"])
def test_unknown_network_counts_spend_reservation_and_do_not_retry(setup, mode, monkeypatch):
    home, _, scope, _ = setup
    runtime = CampaignRuntime(str(home))
    campaign = runtime.create_campaign("synthetic", scope_file=str(scope), budget_requests=4)
    runtime.enqueue_task(campaign, "web", "validator_validate_xss_reflection", {"target_url": BASE}, request_cost=4)
    if mode == "bad_usage":
        native = worker.LocalMCPExecutor(home)
        monkeypatch.setattr(native, "_run_subprocess", lambda *a, **kw:
                            ({"ok": True, "output": '{"requests_authorized":0}'}, {}))
        assert worker.CampaignWorker(runtime, "synthetic", native).run_once(campaign)["status"] == "blocked"
    elif mode == "timeout":
        def fail(task):
            raise TimeoutError("private synthetic detail")
        assert worker.CampaignWorker(runtime, "synthetic", fail).run_once(campaign)["status"] == "blocked"
    else:
        task = runtime.claim_next_task("synthetic", campaign)
        if mode == "stale":
            with runtime._connect() as conn:
                conn.execute("UPDATE tasks SET claim_expires_at='2000-01-01' WHERE id=?", (task["id"],))
            assert runtime.recover_stale_tasks() == 1
        else:
            runtime.fail_task_with_permit(task["execution_permit"], "unknown", retry_in=0)
    assert runtime.show_campaign(campaign)["requests_used"] == 4
    assert runtime.claim_next_task("next", campaign) is None


@pytest.mark.parametrize("change", ["missing", "invocation", "limit", "float_limit", "over_budget", "boolean", "extra"])
def test_usage_from_another_run_or_untrusted_shape_cannot_settle(change):
    with campaign_wire_budget(3, "a" * 32) as budget:
        usage = budget.snapshot()
    if change == "missing":
        usage = None
    elif change == "invocation":
        usage["invocation_id"] = "b" * 32
    elif change == "limit":
        usage["limit"] = 4
    elif change == "float_limit":
        usage["limit"] = 3.0
    elif change == "over_budget":
        usage["authorized_requests"] = 4
    elif change == "boolean":
        usage["authorized_requests"] = False
    elif change == "extra":
        usage["cookie"] = "synthetic-secret"
    with pytest.raises(RuntimeError, match="invalid campaign wire usage"):
        validate_usage(usage, limit=3, invocation_id="a" * 32)
