"""Crawler interception is exercised with fake browser objects, never a socket."""
import json
import sys
from pathlib import Path
from urllib.parse import urljoin

import pytest

from conftest import FakeCDPContext, FakeCDPFrame

ROOT = Path(__file__).resolve().parents[1]
for folder in ("scripts", "mcp-servers/mcp-hunter", "mcp-servers/mcp-memory-server", "mcp-servers/mcp-browser"):
    sys.path.insert(0, str(ROOT / folder))
from policy_engine import PolicyEngine  # noqa: E402
from cco_surface_core import crawl  # noqa: E402
from cco_hunter_core.request_context import policy_scoped, current_policy_gate  # noqa: E402


class Request:
    frame = FakeCDPFrame()
    def __init__(self, url, method="GET", resource_type="document"):
        self.url, self.method, self.resource_type = url, method, resource_type

    def all_headers(self):
        return {"Cookie": "sid=synthetic"}

    @property
    def headers(self):
        return {}


class Route:
    def __init__(self, request):
        self.request, self.action, self.forwarded = request, "", {}

    def abort(self, reason):
        self.action = "aborted"

    def continue_(self, **kwargs):
        self.action = "continued"
        self.forwarded = kwargs.get("headers", {})


class Page:
    def __init__(self, context, status):
        self.context, self.status, self.url, self.listeners = context, status, "about:blank", {}

    def on(self, event, handler):
        self.listeners[event] = handler

    def goto(self, url, **kwargs):
        route = Route(Request(url))
        self.context.route_handler(route)
        self.context.observed.append(route)
        if route.action != "continued":
            raise RuntimeError("blocked before network")
        self.url = url
        for request in (Request("https://owned.test/outside", "GET", "fetch"),
                        Request("https://other.test/allowed", "GET", "fetch"),
                        Request("https://owned.test/allowed/write", "POST", "fetch")):
            rejected = Route(request)
            self.context.route_handler(rejected)
            self.context.observed.append(rejected)
        response = type("Response", (), {"status": self.status, "url": url, "headers": {},
                                         "request": route.request})()
        self.context.handlers["response"](response)
        return response

    def wait_for_timeout(self, value):
        pass

    def title(self):
        return "synthetic"

    def query_selector_all(self, selector):
        return []

    def evaluate(self, script, value):
        return urljoin(self.url, value)


class Context(FakeCDPContext):
    def __init__(self, status):
        self.status, self.handlers, self.observed, self.cookies = status, {}, [], []
        self.pages = []

    def on(self, event, handler):
        self.handlers[event] = handler

    def route(self, pattern, handler):
        self.route_handler = handler

    def route_web_socket(self, pattern, handler):
        self.websocket_handler = handler

    def add_cookies(self, cookies):
        self.cookies.extend(cookies)

    def new_page(self):
        page = Page(self, self.status)
        self.pages.append(page)
        return page

    def close(self):
        pass


class FakePlaywright:
    def __init__(self, status):
        self.status, self.chromium, self.contexts, self.options = status, self, [], []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def launch(self, **kwargs):
        return self

    def new_context(self, **kwargs):
        context = Context(self.status)
        self.contexts.append(context)
        self.options.append(kwargs)
        return context

    def close(self):
        pass


@pytest.fixture
def setup(tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test/allowed"}],
                                 "allow_loopback": False, "allow_osint": False,
                                 "allow_public_labs": False}))
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"}}))
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    engine = PolicyEngine(cco_home=str(tmp_path / "home"), scope_file=str(scope), program_policy_file=str(policy))
    engine.grant_approval("hunter_run_web_loop", "owned.test", ttl_seconds=600, reason="synthetic")
    monkeypatch.setattr(crawl, "HAS_PLAYWRIGHT", True)
    return monkeypatch


def test_crawler_inherits_parent_gate_and_keeps_credentials_on_origin(setup):
    fake = FakePlaywright(200)
    setup.setattr(crawl, "sync_playwright", lambda: fake)
    setup.setenv("CCO_CAMPAIGN_WIRE_BUDGET", "1")

    @policy_scoped("hunter_run_web_loop")
    def run():
        gate = current_policy_gate()
        result = crawl.crawl_site("https://owned.test/allowed/start", max_pages=1, wait_ms=0,
                                  cookie="sid=synthetic", headers={"X-Research": "researcher",
                                                                   "Authorization": "Bearer synthetic"},
                                  wire_gate=gate, tool_name="hunter_run_web_loop")
        return result, gate.authorized_requests()

    result, count = run()
    assert result["ok"] and count == 1
    context = fake.contexts[0]
    assert fake.options[0]["service_workers"] == "block"
    assert context.cookies == [{"name": "sid", "value": "synthetic", "url": "https://owned.test/"}]
    assert context.observed[0].forwarded["Authorization"] == "Bearer synthetic"
    assert all(route.action == "aborted" and not route.forwarded for route in context.observed[1:])
    assert "Bearer synthetic" not in json.dumps(result) and "sid=synthetic" not in json.dumps(result)


def test_crawler_stops_parent_on_authenticated_401_and_never_retries(setup):
    fake = FakePlaywright(401)
    setup.setattr(crawl, "sync_playwright", lambda: fake)

    @policy_scoped("hunter_run_web_loop")
    def run():
        gate = current_policy_gate()
        result = crawl.crawl_site("https://owned.test/allowed/start", max_pages=2, wait_ms=0,
                                  cookie="sid=synthetic", headers={"X-Research": "researcher"}, wire_gate=gate)
        return result, gate.stop_reason(), gate.authorized_requests()

    result, reason, count = run()
    assert not result["ok"] and result["stop_reason"] == "http_401"
    assert "401" in reason and count == 1


def checked_session():
    from cco_surface_core import session_store
    target = "https://owned.test/allowed"
    session_store.put_session(target, "member-a", headers={
        "Authorization": "Bearer vault-only-synthetic", "X-Research": "researcher"},
        cookies={"sid": "vault-only-cookie"}, check_url=target, marker="member-a")
    session_store.refresh_status(target, "member-a", lambda *_a: (200, "member-a"))
    return target


def test_crawler_resolves_checked_vault_reference_inside_tool(setup):
    target = checked_session()
    fake = FakePlaywright(200)
    setup.setattr(crawl, "sync_playwright", lambda: fake)
    result = crawl.crawl_site(target + "/start", max_pages=1, wait_ms=0,
                             session_target=target, identity="member-a", tool_name="hunter_run_web_loop")
    assert result["ok"]
    routes = fake.contexts[0].observed
    assert routes[0].forwarded["Authorization"] == "Bearer vault-only-synthetic"
    assert all(route.action == "aborted" and not route.forwarded for route in routes[1:])
    assert "vault-only" not in json.dumps(result)


@pytest.mark.parametrize("fault", ["origin", "path_scope", "identity", "expired", "cookie", "headers", "tampered"])
def test_crawler_rejects_invalid_vault_binding_before_browser(setup, fault):
    from cco_surface_core import session_store
    target = checked_session()
    args = {"session_target": target, "identity": "member-a"}
    if fault == "origin":
        args["session_target"] = "https://other.test/allowed"
    elif fault == "path_scope":
        args["session_target"] = "https://owned.test/outside"
    elif fault == "identity":
        args["identity"] = "unknown"
    elif fault in {"cookie", "headers"}:
        args[fault] = "sid=raw" if fault == "cookie" else {"Authorization": "Bearer raw"}
    elif fault == "expired":
        entry = session_store.verified_session(target, "member-a")
        setup.setattr(session_store.time, "time", lambda: entry["checked_at"] + 301)
    else:
        # Rotation leaves the new secret unverified; the old check cannot
        # authorize the replacement without a fresh authenticated check.
        session_store.put_session(target, "member-a", headers={"Authorization": "Bearer replacement"})
    setup.setattr(crawl, "sync_playwright", lambda: pytest.fail("invalid session must not start browser"))
    result = crawl.crawl_site(target + "/start", **args)
    assert not result["ok"] and "session" in result["error"]


def test_crawler_rotation_stops_next_request_and_never_reuses_old_secret(setup):
    from cco_surface_core import session_store
    target = checked_session()
    fake = FakePlaywright(200)
    setup.setattr(crawl, "sync_playwright", lambda: fake)
    original_goto = Page.goto
    def rotate(self, url, **kwargs):
        response = original_goto(self, url, **kwargs)
        session_store.put_session(target, "member-a", headers={"Authorization": "Bearer replacement"})
        return response
    class Anchor:
        def get_attribute(self, name):
            return "/allowed/second"
    setup.setattr(Page, "goto", rotate)
    setup.setattr(Page, "query_selector_all", lambda self, selector: [Anchor()] if selector == "a[href]" else [])
    result = crawl.crawl_site(target + "/start", max_pages=2, wait_ms=0,
                             session_target=target, identity="member-a", tool_name="hunter_run_web_loop")
    assert not result["ok"]
    observed = fake.contexts[0].observed
    assert sum(route.action == "continued" for route in observed) == 1
    assert observed[-1].action == "aborted" and not observed[-1].forwarded
