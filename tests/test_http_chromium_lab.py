"""Opt-in real HTTP/Chromium lab; every server and identity is test-owned.

Run with CCO_RUN_WIRE_LAB=1. Runtime state and measurements stay in tmp_path.
No mock HTTP transport or mock browser is used by this module.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "scripts", ROOT / "mcp-servers/mcp-browser", ROOT / "mcp-servers/mcp-validator"):
    sys.path.insert(0, str(directory))

from campaign_runtime import CampaignRuntime  # noqa: E402
from campaign_worker import CampaignWorker, LocalMCPExecutor  # noqa: E402
from cco_browser_core.policy import install_readonly_request_gate  # noqa: E402
from cco_browser_core.session import BrowserSession  # noqa: E402
from cco_validator_core.egress import save_shared_session  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from wire_budget import campaign_wire_budget  # noqa: E402

pytestmark = pytest.mark.skipif(os.environ.get("CCO_RUN_WIRE_LAB") != "1", reason="opt-in owned HTTP/Chromium lab")


class Lab:
    def __init__(self, directory):
        self.directory = directory
        self._lock = threading.Lock()
        self.requests = []
        self.callback = None
        self.servers = [ThreadingHTTPServer(("127.0.0.1", 0), self._handler(label))
                        for label in ("main", "outside")]
        self.base, self.outside = [f"http://127.0.0.1:{server.server_port}" for server in self.servers]
        self.threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in self.servers]
        for thread in self.threads:
            thread.start()

    def _handler(self, label):
        lab = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, body="", content_type="text/html", location=""):
                raw = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # Expected when the test cancels navigation.

            def do_GET(self):
                with lab._lock:
                    lab.requests.append({"server": label, "method": "GET", "path": self.path,
                                         "cookie": self.headers.get("Cookie", ""),
                                         "authorization": self.headers.get("Authorization", ""),
                                         "research": self.headers.get("X-Research", "")})
                if lab.callback:
                    lab.callback(self.path)
                if self.path == "/allowed/start":
                    return self._send(302, location="/allowed/final")
                if self.path == "/allowed/redirect-outside":
                    return self._send(302, location="/outside/trap")
                if self.path == "/allowed/redirect-port":
                    return self._send(302, location=lab.outside + "/allowed/trap")
                if self.path == "/allowed/redirect-login":
                    return self._send(302, location="/allowed/login")
                if self.path.startswith("/allowed/status/"):
                    return self._send(int(self.path.rsplit("/", 1)[1]), "synthetic stop")
                if self.path == "/allowed/protected":
                    return self._send(200 if "sid=owned" in self.headers.get("Cookie", "") else 401,
                                      "owned account canary")
                if self.path == "/allowed/slow":
                    # Commit headers, then keep the body pending. The test can
                    # observe a real request before timing out on DOM loading.
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", "1")
                    self.end_headers()
                    self.wfile.flush()
                    lab.slow_received.set()
                    lab.release_slow.wait(timeout=10)
                    try:
                        self.wfile.write(b" ")
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    return
                if self.path == "/allowed/sw.js":
                    return self._send(200, "self.addEventListener('fetch', () => {});", "application/javascript")
                if self.path == "/allowed/resources":
                    return self._send(200, """<link rel="icon" href="data:,"><a href="/allowed/final">final</a>
                      <script>window.done = Promise.all(['a', 'b', 'c'].map(name =>
                        fetch('/allowed/api/' + name).catch(() => null)));</script>""")
                if self.path.startswith("/allowed/api/"):
                    return self._send(200, "/* owned resource */", "application/javascript")
                return self._send(200, '<link rel="icon" href="data:,"><title>owned lab</title>owned lab')

            def do_POST(self):
                with lab._lock:
                    lab.requests.append({"server": label, "method": "POST", "path": self.path,
                                         "cookie": self.headers.get("Cookie", ""), "research": ""})
                self._send(200, "unexpected write method")
        return Handler

    def measure(self, authorized, **details):
        with self._lock:
            requests = list(self.requests)
        result = {"authorized_requests": authorized, "received_requests": len(requests),
                  "outside_requests": sum(r["server"] == "outside" for r in requests),
                  "requests": requests, **details}
        (self.directory / "measurement.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    def close(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)


@pytest.fixture
def lab(tmp_path, monkeypatch):
    owned = Lab(tmp_path)
    try:
        home, scope, policy = tmp_path / "home", tmp_path / "scope.json", tmp_path / "policy.json"
        scope.write_text(json.dumps({"in_scope": [{"asset": owned.base + "/allowed"}],
                                     "allow_loopback": False, "allow_osint": False, "allow_public_labs": False}))
        policy.write_text(json.dumps({"allow_loopback": False, "allow_osint": False, "allow_public_labs": False,
                                      "required_request_headers": {"X-Research": "owned-lab"}}))
        for key, value in {"CCO_HOME": str(home), "CCO_SCOPE_FILE": str(scope),
                           "CCO_PROGRAM_POLICY_FILE": str(policy), "CCO_WORKDIR": str(tmp_path / "work"),
                           "CCO_PROXY": "", "CCO_SURFACE_AUTO_INGEST": "0", "CCO_HEADED": "0",
                           "HACKERONE_HANDLE": "owned-lab", "CCO_RESEARCH_HEADER": "X-Research"}.items():
            monkeypatch.setenv(key, value)
        for key in ("CCO_WORKER_ALLOWED_TOOLS", "CCO_CAMPAIGN_WIRE_BUDGET", "CCO_BROWSER_CDP",
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
        owned.home, owned.scope = home, scope
        owned.engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
        for tool in ("browser_*", "validator_*", "kali-tools_curl_request"):
            owned.engine.grant_approval(tool, "127.0.0.1", ttl_seconds=600, reason="owned loopback integration")
        yield owned
    finally:
        owned.close()
        if not (tmp_path / "measurement.json").exists():
            owned.measure(None, measurement_status="test_did_not_reach_count_assertion")


@pytest.fixture(scope="module")
def chromium():
    sync_playwright = pytest.importorskip("playwright.sync_api", reason="Playwright unavailable").sync_playwright
    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage",
                "--host-resolver-rules=MAP owned.test 127.0.0.1,EXCLUDE localhost"])
        except Exception as exc:
            pytest.fail(f"Opt-in Chromium lab cannot launch: {type(exc).__name__}: {str(exc)[:300]}")
        yield browser
        browser.close()


@contextmanager
def session(chromium, lab, limit=20):
    context = chromium.new_context(service_workers="block", extra_http_headers={"X-Research": "owned-lab"})
    state = install_readonly_request_gate(context, lab.engine, "browser_browser_extract_links")
    context.add_cookies([{"name": "sid", "value": "owned", "url": lab.base}])
    try:
        with campaign_wire_budget(limit, "a" * 32) as budget:
            yield context.new_page(), context, state, budget
    finally:
        context.close()


def invoke(browser_session, tool, action):
    return browser_session.call(lambda active: active._invoke(tool, action), timeout=30)


@contextmanager
def persistent_session(lab, cdp_url="", limit=20):
    active = BrowserSession()
    try:
        with campaign_wire_budget(limit, "b" * 32) as budget:
            opened = invoke(active, "browser_browser_session_open",
                            lambda s: s._open(lab.base + "/allowed/final", cdp_url=cdp_url))
            yield active, opened, budget
    finally:
        try:
            invoke(active, "browser_browser_session_close", lambda s: s._close())
        finally:
            active._q.put(None)
            if active._thread is not None:
                active._thread.join(timeout=5)
                assert not active._thread.is_alive(), "owned browser thread did not stop"


def assert_count(lab, count, **details):
    result = lab.measure(count, **details)
    assert result["received_requests"] == count, result
    assert result["outside_requests"] == 0, result
    assert all(r["method"] == "GET" and r["path"].startswith("/allowed/") for r in result["requests"]), result
    assert all(r["research"] == "owned-lab" for r in result["requests"]), result
    return result


def program_hostname(lab):
    """Chromium resolves this reserved name to the owned loopback server.

    The policy treats the name as a program asset, so loopback's grant/header
    exemptions cannot make these checks pass without enforcing the rules.
    """
    port = lab.servers[0].server_port
    lab.base = f"http://owned.test:{port}"
    lab.scope.write_text(json.dumps({"in_scope": [{"asset": lab.base + "/allowed"}],
                                     "allow_loopback": False, "allow_osint": False, "allow_public_labs": False}))
    lab.engine.grant_approval("browser_*", "owned.test", ttl_seconds=600, reason="owned hostname mapped to loopback")


def test_native_campaign_mixed_tools_match_server_count(lab):
    runtime = CampaignRuntime(str(lab.home))
    campaign = runtime.create_campaign("owned mixed wire lab", scope_file=str(lab.scope), budget_requests=5)
    runtime.enqueue_task(campaign, "http", "kali-tools_curl_request", {
        "url": lab.base + "/allowed/start", "headers": "X-Research: owned-lab"}, request_cost=2)
    runtime.enqueue_task(campaign, "browser", "browser_browser_security_headers", {
        "url": lab.base + "/allowed/final"}, request_cost=1)
    runtime.enqueue_task(campaign, "validate", "validator_validate_auth_bypass", {
        "protected_url": lab.base + "/allowed/protected",
        "authorized_headers_json": json.dumps({"Cookie": "sid=owned", "X-Research": "owned-lab"})}, request_cost=2)
    runner = CampaignWorker(runtime, "owned-lab", LocalMCPExecutor(lab.home, timeout_seconds=30))
    outcomes = [runner.run_once(campaign) for _ in range(3)]
    assert [item["status"] for item in outcomes] == ["done"] * 3, [
        {"status": row["status"], "error": row.get("error"),
         "reason": row.get("result", {}).get("reason"),
         "wire_usage": row.get("result", {}).get("wire_usage"),
         "output": str(row.get("result", {}).get("output", ""))[:1000]} for row in outcomes]
    assert runner.run_once(campaign) == {"claimed": False}
    summary = runtime.show_campaign(campaign)
    assert summary["requests_used"] == 5 and summary["requests_reserved"] == 0
    assert_count(lab, 5, tools=[item["result"]["tool_name"] for item in outcomes])


def test_native_browser_resources_exhaust_budget_without_fallback(lab):
    runtime = CampaignRuntime(str(lab.home))
    campaign = runtime.create_campaign("owned resource budget", scope_file=str(lab.scope), budget_requests=3)
    runtime.enqueue_task(campaign, "browser", "browser_browser_extract_links", {
        "url": lab.base + "/allowed/resources", "wait_seconds": 0.5}, request_cost=3)
    out = CampaignWorker(runtime, "owned-lab", LocalMCPExecutor(lab.home, timeout_seconds=30)).run_once(campaign)
    assert out["status"] == "blocked" and "result" in out, out
    assert out["result"]["reason"] == "campaign request budget exhausted"
    assert runtime.show_campaign(campaign)["requests_used"] == 3
    result = assert_count(lab, 3, tool="browser_browser_extract_links")
    # Concurrent subresources can reach the server in either order.
    assert {r["path"] for r in result["requests"]} == {
        "/allowed/resources", "/allowed/api/a", "/allowed/api/b"}


@pytest.mark.parametrize("limit", [0, 1, 2])
def test_native_http_redirect_charges_each_hop(lab, limit):
    out = LocalMCPExecutor(lab.home, timeout_seconds=30)({
        "tool_name": "kali-tools_curl_request", "request_cost": limit,
        "args_json": json.dumps({"url": lab.base + "/allowed/start", "headers": "X-Research: owned-lab"})})
    assert out["actual_request_cost"] == limit
    assert bool(out["wire_usage"]["blocked_reason"]) is (limit < 2)
    assert_count(lab, limit, tool="kali-tools_curl_request")


@pytest.mark.parametrize("path,limit,expected", [
    ("/allowed/start", 2, 2), ("/allowed/start", 1, 1),
    ("/allowed/redirect-outside", 5, 1), ("/allowed/redirect-port", 5, 1),
    ("/allowed/redirect-login", 5, 1),
])
def test_real_browser_redirects_recheck_scope_and_budget(lab, chromium, path, limit, expected):
    from playwright.sync_api import Error
    with session(chromium, lab, limit) as (page, _, state, budget):
        try:
            page.goto(lab.base + path, wait_until="domcontentloaded", timeout=5000)
        except Error:
            if expected == 2:
                raise
        if expected == 2:
            assert page.url == lab.base + "/allowed/final"
        if limit == 1:
            assert state["stopped"] and "budget" in state["reason"]
        assert budget.snapshot()["authorized_requests"] == expected
        assert_count(lab, expected, path=path, stopped=state["reason"])


@pytest.mark.parametrize("kind", ["fetch", "iframe", "popup"])
@pytest.mark.parametrize("destination,expected", [("allowed", 2), ("outside_path", 1), ("outside_port", 1)])
def test_real_browser_fetch_frames_and_popups_obey_scope(lab, chromium, kind, destination, expected):
    target = {"allowed": lab.base + "/allowed/child", "outside_path": lab.base + "/outside/trap",
              "outside_port": lab.outside + "/allowed/trap"}[destination]
    with session(chromium, lab) as (page, context, _, budget):
        page.goto(lab.base + "/allowed/final", wait_until="domcontentloaded")
        # Wait for the specific allowed/denied request to settle. A fixed
        # render delay can end after admission but before delivery or abortion.
        event = "response" if expected == 2 else "requestfailed"
        with context.expect_event(event, predicate=lambda request: request.url == target, timeout=5000):
            page.evaluate("""({kind, target}) => {
                if (kind === 'fetch') return fetch(target).then(() => true, () => false);
                if (kind === 'iframe') { const frame = document.createElement('iframe'); frame.src = target;
                    document.body.appendChild(frame); }
                if (kind === 'popup') window.open(target);
            }""", {"kind": kind, "target": target})
        assert budget.snapshot()["authorized_requests"] == expected
        result = assert_count(lab, expected, kind=kind, destination=destination)
        assert all("sid=owned" in item["cookie"] for item in result["requests"])


def test_real_browser_blocks_post_websocket_and_service_worker(lab, chromium):
    with session(chromium, lab) as (page, context, _, budget):
        page.goto(lab.base + "/allowed/final", wait_until="domcontentloaded")
        result = page.evaluate("""async ({base}) => {
            const post = await Promise.race([
                fetch('/allowed/write', {method:'POST', body:'synthetic'}).then(() => 'sent', () => 'blocked'),
                new Promise(resolve => setTimeout(() => resolve('pending'), 1000))]);
            const worker = await Promise.race([
                navigator.serviceWorker.register('/allowed/sw.js').then(reg => reg ? 'registered' : 'blocked', () => 'rejected'),
                new Promise(resolve => setTimeout(() => resolve('pending'), 300))]);
            const websocket = await new Promise(resolve => {
                const socket = new WebSocket(base.replace('http:', 'ws:') + '/allowed/ws');
                socket.onclose = () => resolve(false); socket.onerror = () => resolve(false);
                socket.onopen = () => { socket.close(); resolve(true); }; setTimeout(() => resolve(false), 1000);
            });
            return {post, worker, websocket};
        }""", {"base": lab.base})
        assert result["post"] == 'blocked' and not result["websocket"]
        assert result["worker"] in {"blocked", "pending", "rejected"} and not context.service_workers
        assert budget.snapshot()["authorized_requests"] == 1
        assert_count(lab, 1, blocked=["POST", "WebSocket", "service worker"], worker_registration=result["worker"])


@pytest.mark.parametrize("change", ["scope", "grant"])
def test_real_browser_rechecks_policy_between_requests(lab, chromium, change):
    if change == "grant":
        program_hostname(lab)
    def change_policy(path):
        if path != "/allowed/change":
            return
        if change == "scope":
            lab.scope.write_text(json.dumps({"in_scope": [], "allow_loopback": False}))
        else:
            for grant in lab.engine.list_approvals():
                lab.engine.revoke_approval(grant["id"])
    with session(chromium, lab) as (page, _, _, budget):
        page.goto(lab.base + "/allowed/final", wait_until="domcontentloaded")
        lab.callback = change_policy
        allowed = page.evaluate("""async () => {
            await fetch('/allowed/change');
            return fetch('/allowed/after').then(() => true, () => false);
        }""")
        assert not allowed
        assert budget.snapshot()["authorized_requests"] == 2
        assert_count(lab, 2, policy_change=change, origin=lab.base)


def test_real_browser_requires_program_header_before_sending(lab, chromium):
    from playwright.sync_api import Error
    program_hostname(lab)
    context = chromium.new_context(service_workers="block")
    install_readonly_request_gate(context, lab.engine, "browser_browser_extract_links")
    try:
        with campaign_wire_budget(5, "c" * 32) as budget:
            page = context.new_page()
            with pytest.raises(Error):
                page.goto(lab.base + "/allowed/final", wait_until="domcontentloaded", timeout=5000)
            assert budget.snapshot()["authorized_requests"] == 0
            assert_count(lab, 0, outcome="required_header_missing", origin=lab.base)
    finally:
        context.close()


@pytest.mark.parametrize("status", [401, 429])
def test_real_browser_status_stops_followup_requests(lab, chromium, status):
    with session(chromium, lab) as (page, _, state, budget):
        page.goto(lab.base + f"/allowed/status/{status}", wait_until="domcontentloaded")
        allowed = page.evaluate("fetch('/allowed/after').then(() => true, () => false)")
        assert not allowed and state["reason"] == f"http_{status}"
        assert budget.snapshot()["authorized_requests"] == 1
        assert_count(lab, 1, stopped=state["reason"])


def test_real_browser_navigation_timeout_keeps_consumed_attempt(lab, chromium):
    from playwright.sync_api import TimeoutError
    lab.slow_received, lab.release_slow = threading.Event(), threading.Event()
    try:
        with session(chromium, lab) as (page, _, _, budget):
            page.goto(lab.base + "/allowed/slow", wait_until="commit")
            with pytest.raises(TimeoutError):
                page.wait_for_load_state("domcontentloaded", timeout=100)
            assert budget.snapshot()["authorized_requests"] == 1
            assert lab.slow_received.is_set()
            assert_count(lab, 1, outcome="navigation_timeout", charged_attempts=1, delivery_observed=True)
    finally:
        lab.release_slow.set()


@pytest.mark.parametrize("kind", ["fetch", "iframe", "popup", "goto", "redirect"])
def test_real_session_cookie_does_not_leave_origin_even_when_both_ports_are_in_scope(lab, kind):
    from playwright.sync_api import Error
    # Both destinations pass scope/grant checks. Cookie isolation must come
    # from BrowserSession's origin binding, not the out-of-scope trap.
    lab.scope.write_text(json.dumps({"in_scope": [{"asset": base + "/allowed"}
                                                  for base in (lab.base, lab.outside)],
                                     "allow_loopback": False, "allow_osint": False, "allow_public_labs": False}))
    save_shared_session(lab.base, cookie="sid=owned", headers={"Authorization": "Bearer owned-origin-canary"})
    with persistent_session(lab) as (active, opened, budget):
        assert opened["session_state"] == "restored"
        # Chromium cookies are host-bound and also match another port. This
        # control establishes that a missing origin filter would leak sid.
        cookies = invoke(active, "browser_browser_session_requests", lambda s: s._context.cookies([lab.outside]))
        assert any(c["name"] == "sid" and c["value"] == "owned" for c in cookies)

        def traffic(s):
            assert s._page.evaluate("fetch('/allowed/child').then(() => true, () => false)")
            target = lab.outside + "/allowed/trap"
            if kind == "goto":
                with pytest.raises(ValueError, match="separate session"):
                    s._goto(target)
            elif kind == "redirect":
                with pytest.raises(Error):
                    s._goto(lab.base + "/allowed/redirect-port")
            else:
                allowed = s._page.evaluate("""({kind, target}) => {
                    if (kind === 'fetch') return fetch(target, {credentials:'include'}).then(() => true, () => false);
                    if (kind === 'iframe') { const frame = document.createElement('iframe'); frame.src = target;
                        document.body.appendChild(frame); }
                    if (kind === 'popup') window.open(target);
                }""", {"kind": kind, "target": target})
                if kind == "fetch":
                    assert not allowed
                s._page.wait_for_timeout(400)

        invoke(active, "browser_browser_session_goto", traffic)
        expected = 3 if kind == "redirect" else 2
        assert budget.snapshot()["authorized_requests"] == expected
        result = assert_count(lab, expected, kind=kind, both_origins_in_scope=True)
        assert all(r["cookie"] == "sid=owned" and r["authorization"] == "Bearer owned-origin-canary"
                   for r in result["requests"])


def test_real_cdp_context_keeps_existing_user_state_and_browser_alive(lab, chromium):
    profile = lab.directory / "cdp-profile"
    with chromium.browser_type.launch_persistent_context(
        str(profile), headless=True, args=["--remote-debugging-port=0", "--no-sandbox", "--disable-dev-shm-usage"],
        extra_http_headers={"X-Research": "owned-lab"}) as user_context:
        parent = user_context.pages[0]
        user_context.add_cookies([{"name": "sid", "value": "user-context-only", "url": lab.base}])
        parent.goto(lab.base + "/allowed/parent", wait_until="domcontentloaded")
        parent.evaluate("localStorage.setItem('parentCanary', 'user-storage-only'); window.parentCanary = 'user-window-only'")
        owner = user_context.browser
        port = int((profile / "DevToolsActivePort").read_text().splitlines()[0])
        save_shared_session(lab.base, cookie="sid=owned")
        with persistent_session(lab, cdp_url=f"http://127.0.0.1:{port}") as (active, opened, budget):
            assert opened["mode"] == "cdp-isolated" and opened["session_state"] == "restored"

            def inspect(s):
                assert s._page.evaluate("localStorage.getItem('parentCanary')") is None
                assert s._page.evaluate("document.cookie") == "sid=owned"
                assert s._page.evaluate("fetch('/allowed/child').then(() => true, () => false)")
                return len(s._browser.contexts)

            assert invoke(active, "browser_browser_session_requests", inspect) == 2
            assert budget.snapshot()["authorized_requests"] == 2
            assert parent.url == lab.base + "/allowed/parent"
            assert parent.evaluate("window.parentCanary") == "user-window-only"
            assert parent.evaluate("localStorage.getItem('parentCanary')") == "user-storage-only"
            assert parent.evaluate("document.cookie") == "sid=user-context-only"

        assert owner.is_connected() and not parent.is_closed()
        parent.wait_for_timeout(50)  # Drain the peer driver's context/target close events.
        assert owner.contexts == [user_context] and user_context.pages == [parent]
        parent.goto(lab.base + "/allowed/parent-after-close", wait_until="domcontentloaded")
        assert parent.title() == "owned lab"
        result = lab.measure(2, control_requests=2, cdp_mode=opened["mode"], parent_survived=True)
        assert result["received_requests"] == 4 and result["outside_requests"] == 0, result
        assert [r["path"] for r in result["requests"]] == [
            "/allowed/parent", "/allowed/final", "/allowed/child", "/allowed/parent-after-close"]
        assert [r["cookie"] for r in result["requests"]] == [
            "sid=user-context-only", "sid=owned", "sid=owned", "sid=user-context-only"]
        assert all(r["research"] == "owned-lab" for r in result["requests"])
