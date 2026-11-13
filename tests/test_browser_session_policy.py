"""Persistent browser actions use isolated contexts and a per-request gate."""
import json
import sys
from pathlib import Path

import pytest

from conftest import FakeCDPContext, FakeCDPFrame

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-browser"))
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-validator"))
from policy_engine import PolicyEngine  # noqa: E402
from cco_browser_core.session import BrowserSession  # noqa: E402
from cco_validator_core.egress import load_shared_session, save_shared_session  # noqa: E402


class Request:
    frame = FakeCDPFrame()
    def __init__(self, url, method="GET", headers=None):
        self.url, self.method = url, method
        self.headers = {"X-Research": "researcher"} if headers is None else headers

    def all_headers(self):
        return dict(self.headers)


class Route:
    def __init__(self, request):
        self.request, self.action, self.forwarded = request, "", {}

    def abort(self, reason):
        self.action = "aborted"

    def continue_(self, **kwargs):
        self.action = "continued"
        self.forwarded = kwargs.get("headers", {})


class Page:
    def __init__(self, context):
        self.context, self.url, self.sent = context, "about:blank", []

    def on(self, event, callback):
        pass

    def goto(self, url, **kwargs):
        route = Route(Request(url))
        self.context.request_handler(route)
        if route.action != "continued":
            raise RuntimeError("request blocked")
        self.sent.append(route)
        self.url = url

    def title(self):
        return "synthetic"

    def is_closed(self):
        return False


class Context(FakeCDPContext):
    def __init__(self):
        self.pages, self.cookies_added, self.closed = [], [], False
        self.handlers = {}

    def on(self, event, callback):
        self.handlers[event] = callback

    def route(self, pattern, callback):
        self.request_handler = callback

    def route_web_socket(self, pattern, callback):
        self.websocket_handler = callback

    def add_cookies(self, cookies):
        self.cookies_added.extend(cookies)

    def cookies(self, urls):
        return []

    def new_page(self):
        page = Page(self)
        self.pages.append(page)
        return page

    def close(self):
        self.closed = True


class Browser:
    def __init__(self):
        self.contexts = [object()]  # User's existing context must not be reused.
        self.new_contexts, self.closed = [], False

    def new_context(self, **kwargs):
        context = Context()
        self.new_contexts.append((context, kwargs))
        return context

    def close(self):
        self.closed = True


@pytest.fixture
def setup(tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test/allowed"},
                                              {"asset": "https://owned.test:444/allowed"}],
                                 "allow_loopback": False, "allow_osint": False, "allow_public_labs": False}))
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"}}))
    home = tmp_path / "home"
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    monkeypatch.setenv("HACKERONE_HANDLE", "researcher")
    monkeypatch.setenv("CCO_RESEARCH_HEADER", "X-Research")
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
    grant = engine.grant_approval("browser_*", "owned.test", ttl_seconds=600, reason="synthetic test")
    save_shared_session("https://owned.test", cookie="sid=synthetic", headers={"Authorization": "Bearer synthetic"})
    fake_browser = Browser()

    class Driver:
        chromium = None
        def start(self):
            return self
        def stop(self):
            pass
    class Chromium:
        def connect_over_cdp(self, url):
            return fake_browser
        def launch(self, **kwargs):
            return fake_browser
    driver = Driver()
    driver.chromium = Chromium()
    monkeypatch.setattr("playwright.sync_api.sync_playwright", lambda: driver)
    monkeypatch.setattr(BrowserSession, "_proxy_if_available", staticmethod(lambda: ""))
    return engine, grant, fake_browser


def test_cdp_uses_new_context_and_origin_bound_test_session(setup):
    _, _, browser = setup
    session = BrowserSession()
    url = "https://owned.test/allowed/start"
    result = session._invoke("browser_browser_session_open",
                             lambda s: s._open(url, "http://127.0.0.1:9222"))
    assert result["mode"] == "cdp-isolated" and result["session_state"] == "restored"
    context, options = browser.new_contexts[0]
    assert options["service_workers"] == "block"
    assert options["extra_http_headers"] == {"X-Research": "researcher"}
    assert context.cookies_added == [{"name": "sid", "value": "synthetic", "url": "https://owned.test/"}]
    assert session._page.sent[0].forwarded["Authorization"] == "Bearer synthetic"
    assert "Bearer synthetic" not in json.dumps(result) and "sid=synthetic" not in json.dumps(result)
    session._invoke("browser_browser_session_close", lambda s: s._close())
    assert context.closed and not browser.closed


def test_each_request_and_action_rechecks_scope_grant_and_origin(setup):
    engine, grant, browser = setup
    session = BrowserSession()
    url = "https://owned.test/allowed/start"
    session._invoke("browser_browser_session_open", lambda s: s._open(url))
    context = browser.new_contexts[0][0]
    for request in (Request("https://owned.test/outside"),
                    Request("https://owned.test:444/allowed/a"),
                    Request("https://owned.test/allowed/a", "POST")):
        route = Route(request)
        session._invoke("browser_browser_session_goto", lambda _: context.request_handler(route))
        assert route.action == "aborted" and not route.forwarded
    idle = Route(Request("https://owned.test/allowed/a"))
    context.request_handler(idle)
    assert idle.action == "aborted"
    with pytest.raises(ValueError, match="must match"):
        session._invoke("browser_browser_session_text", lambda s: s._authorize_current(
            "browser_browser_session_text", "https://owned.test/allowed/other", lambda _: "bad"))
    engine.revoke_approval(grant.id)
    with pytest.raises(RuntimeError, match="policy denied"):
        session._invoke("browser_browser_session_text", lambda s: s._authorize_current(
            "browser_browser_session_text", url, lambda _: "bad"))


@pytest.mark.parametrize("cdp", ["http://remote.test:9222", "ws://192.0.2.1:9222", "http://user:pw@127.0.0.1:9222"])
def test_nonlocal_or_credentialed_cdp_is_rejected_before_connect(setup, cdp):
    session = BrowserSession()
    with pytest.raises(ValueError, match="loopback"):
        session._invoke("browser_browser_session_open",
                        lambda s: s._open("https://owned.test/allowed", cdp))


def test_stale_test_session_never_navigates(setup):
    _, _, browser = setup
    save_shared_session("owned.test", state="expired")
    session = BrowserSession()
    with pytest.raises(RuntimeError, match="expired or stale"):
        session._invoke("browser_browser_session_open", lambda s: s._open("https://owned.test/allowed"))
    assert not browser.new_contexts[0][0].pages


@pytest.mark.parametrize("status,location,expected", [
    (401, "", "expired"), (302, "/login", "expired"), (429, "", "active")])
def test_auth_failure_invalidates_session_but_rate_limit_does_not(setup, status, location, expected):
    _, _, browser = setup
    session = BrowserSession()
    session._invoke("browser_browser_session_open", lambda s: s._open("https://owned.test/allowed"))
    context = browser.new_contexts[0][0]
    response = type("Response", (), {"status": status, "url": "https://owned.test/allowed",
                                     "headers": {"location": location}})()
    context.handlers["response"](response)
    assert load_shared_session("owned.test")["state"] == expected
    session._sync_shared_jar()
    assert load_shared_session("owned.test")["state"] == expected
    route = Route(Request("https://owned.test/allowed/next"))
    session._invoke("browser_browser_session_goto", lambda _: context.request_handler(route))
    assert route.action == "aborted"


def test_capture_keeps_response_metadata_only_and_never_reads_bodies():
    session = BrowserSession()
    page = type("Page", (), {"on": lambda self, event, cb: self.handlers.update({event: cb})})()
    page.handlers = {}
    session._hook_requests(page)
    req = type("Request", (), {"url": "https://owned.test/a?q=private-value", "method": "GET",
                                "resource_type": "fetch"})()
    resp = type("Response", (), {"request": req, "status": 200,
                                  "headers": {"content-type": "application/json",
                                              "location": "https://user:password@owned.test/a?key=value"},
                                  "text": lambda self: pytest.fail("body must never be read")})()
    page.handlers["request"](req)
    assert session._requests == []  # An aborted request is never promoted to an observation.
    page.handlers["response"](resp)
    assert len(session._requests) == 1
    assert session._requests[0]["capture_redacted"] is True
    assert "private-value" not in json.dumps(session._requests)
    assert "password" not in json.dumps(session._requests) and "key=value" not in json.dumps(session._requests)
    assert "resp_body" not in session._requests[0] and "req_body" not in session._requests[0]
    post = type("Request", (), {"url": "https://owned.test/a", "method": "POST", "resource_type": "fetch"})()
    page.handlers["request"](post)
    assert len(session._requests) == 1 and not session._req_index
