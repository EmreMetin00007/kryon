"""Disposable browser contexts gate requests before the route is continued."""
import json
from pathlib import Path
import sys

import pytest

from conftest import FakeCDPContext, FakeCDPFrame, load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from policy_engine import PolicyEngine  # noqa: E402


class FakeRequest:
    frame = FakeCDPFrame()
    def __init__(self, url, method="GET", headers=None):
        self.url, self.method = url, method
        self._headers = headers if headers is not None else {"X-Research": "researcher"}

    def all_headers(self):
        return dict(self._headers)


class FakeRoute:
    def __init__(self, request):
        self.request = request
        self.action = ""

    def abort(self, reason):
        self.action = "aborted:" + reason

    def continue_(self):
        self.action = "continued"


class FakeContext(FakeCDPContext):
    def __init__(self):
        self.closed = False
        self.pages = []

    def route(self, pattern, handler):
        self.handler = handler

    def on(self, event, handler):
        if event == "response":
            self.response_handler = handler
        elif event == "page":
            self.page_handler = handler
        else:
            assert event == "close"
            self.close_handler = handler

    def route_web_socket(self, pattern, handler):
        self.ws_handler = handler

    def close(self):
        self.closed = True


class FakeBrowser:
    def __init__(self, context):
        self.context = context

    def new_context(self, **kwargs):
        self.kwargs = kwargs
        return self.context


@pytest.fixture
def context(tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test/allowed"}],
                                 "allow_loopback": False, "allow_osint": False,
                                 "allow_public_labs": False}))
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"}}))
    home = tmp_path / "home"
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
    engine.grant_approval("browser_browser_extract_links", "owned.test", ttl_seconds=600, reason="test")
    browser = load_server("browser")
    monkeypatch.setattr(browser, "_proxy_available", lambda: False)
    fake = FakeBrowser(FakeContext())
    assert browser._new_context(fake, "browser_browser_extract_links") is fake.context
    assert fake.kwargs["service_workers"] == "block"
    return fake.context


@pytest.mark.parametrize("url,method,headers,allowed", [
    ("https://owned.test/allowed/a", "GET", None, True),
    ("https://owned.test/outside", "GET", None, False),
    ("https://owned.test/allowed/%2e%2e/outside", "GET", None, False),
    ("https://owned.test:444/allowed/a", "GET", None, False),
    ("https://owned.test/allowed/a", "POST", None, False),
    ("https://owned.test/allowed/a", "GET", {}, False),
])
def test_route_fails_closed_before_request(context, url, method, headers, allowed):
    route = FakeRoute(FakeRequest(url, method, headers))
    context.handler(route)
    assert (route.action == "continued") is allowed
    if not allowed:
        assert route.action == "aborted:blockedbyclient"


def test_websockets_are_blocked_until_they_have_a_wire_gate(context):
    import asyncio
    class Socket:
        def close(self, **kwargs):
            self.details = kwargs
    ws = Socket()
    asyncio.run(context.ws_handler(ws))
    assert ws.details["code"] == 1008


@pytest.mark.parametrize("destination,allowed", [
    ("https://owned.test/allowed/b", True),
    ("https://owned.test/outside", False),
    ("https://owned.test:444/allowed/b", False),
    ("https://owned.test/allowed/log%69n", False),
])
def test_cdp_redirect_reuses_scope_and_budget(context, destination, allowed):
    from wire_budget import campaign_wire_budget
    with campaign_wire_budget(2, "a" * 32) as budget:
        route = FakeRoute(FakeRequest("https://owned.test/allowed/a"))
        context.handler(route)
        assert route.action == "continued"
        cdp = context.cdp_root
        handler = lambda event: cdp.emit("Fetch.requestPaused", event)
        handler({"requestId": "first", "responseStatusCode": 200, "request": {"url": route.request.url}})
        assert budget.snapshot()["authorized_requests"] == 1
        handler({"requestId": "second", "responseStatusCode": 302,
                 "responseHeaders": [{"name": "Location", "value": destination}],
                 "request": {"url": route.request.url, "method": "GET", "headers": {"X-Research": "researcher"}}})
        method, params = cdp.protocol_calls[-1]
        assert method == ("Fetch.continueResponse" if allowed else "Fetch.failRequest")
        assert params["requestId"] == "second"
        assert budget.snapshot()["authorized_requests"] == (2 if allowed else 1)


def test_cdp_redirect_exhaustion_cannot_open_another_allowance(context):
    from wire_budget import campaign_wire_budget
    with campaign_wire_budget(1, "a" * 32) as budget:
        context.handler(FakeRoute(FakeRequest("https://owned.test/allowed/a")))
        cdp = context.cdp_root
        cdp.emit("Fetch.requestPaused", {"requestId": "second", "responseStatusCode": 302,
            "responseHeaders": [{"name": "location", "value": "/allowed/b"}],
            "request": {"url": "https://owned.test/allowed/a", "method": "GET",
                        "headers": {"X-Research": "researcher"}}})
        assert cdp.protocol_calls[-1][0] == "Fetch.failRequest"
        assert budget.snapshot()["authorized_requests"] == 1
        assert budget.snapshot()["blocked_reason"] == "campaign request budget exhausted"


@pytest.mark.parametrize("status,location", [(401, ""), (429, ""), (302, "/allowed/login"),
                                               (302, "/allowed/log%69n"), (302, "/allowed/%256cogin")])
def test_session_or_rate_failure_stops_followup_requests(context, status, location):
    class Response:
        url = "https://owned.test/allowed/a"
        headers = {"location": location}
    response = Response()
    response.status = status
    context.response_handler(response)
    followup = FakeRoute(FakeRequest("https://owned.test/allowed/b"))
    context.handler(followup)
    assert followup.action == "aborted:blockedbyclient"


def test_missing_websocket_interception_closes_context(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test/allowed"}]}))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    browser = load_server("browser")
    monkeypatch.setattr(browser, "_proxy_available", lambda: False)
    class OldContext:
        closed = False
        def on(self, event, handler):
            pass
        def close(self):
            self.closed = True
    context = OldContext()
    with pytest.raises(AttributeError):
        browser._new_context(FakeBrowser(context), "browser_browser_extract_links")
    assert context.closed
