"""Read-only surface selection and hard-stop behavior, with no real sockets."""
import json
import sys
from pathlib import Path

import pytest

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-memory-server"))
from cco_surface_core.normalize import discovery_link_skip_reason  # noqa: E402
from cco_surface_core.wire import scoped_surface_requests  # noqa: E402

BASE = "https://owned.test/allowed/"


@pytest.mark.parametrize("suffix", [
    "logout", "%256cogout", "data?delete=1", "data?%2564elete=1", "data?token=synthetic",
    "data?%2574oken=synthetic", "data?action=remove", "data?next=/logout", "update.json",
    "%5Clogout", "data%00", "data?next=%255Clogout", "%25252525256cogout",
])
def test_unsafe_links_are_not_suitable_for_automatic_get(suffix):
    assert discovery_link_skip_reason(BASE + suffix)


@pytest.fixture
def discovery(tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": BASE}], "allow_loopback": False,
                                 "allow_osint": False, "allow_public_labs": False}))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path))
    kali = load_server("kali-tools")
    return kali, monkeypatch


class Response:
    cookies = []
    def __init__(self, url, text, status=200):
        self.url, self.status_code, self.text = url, status, text
        self.headers = {"Content-Type": "text/html"}
        self.content = text.encode()


def test_mutating_links_and_post_forms_remain_inventory_but_never_reach_transport(discovery):
    kali, monkeypatch = discovery
    calls = []
    html = ('<a href="/allowed/logout">Logout</a>'
            '<a href="/allowed/%256cogout">Encoded logout</a>'
            '<a href="/allowed/data?token=synthetic-private-value">Unsafe query</a>'
            '<form action="/allowed/actions" method="POST"></form>'
            '<a href="/allowed/data">Data</a>')
    def send(url, **kwargs):
        assert not discovery_link_skip_reason(url) and not url.endswith("actions")
        calls.append(url)
        return Response(url, html if url == BASE else "Data")
    monkeypatch.setattr(kali.requests, "get", send)
    with scoped_surface_requests(lambda *_: (True, ""), BASE):
        report = json.loads(kali.discover_web_surface(BASE, mode="active", probe_limit=4))
    assert calls == [BASE, BASE + "data"]
    assert not report.get("stop_reason") and report["ingested"] >= 5
    assert report["skipped_links"]["mutating_discovery_link"] == 2
    assert report["skipped_links"]["sensitive_discovery_query"] == 1
    assert report["skipped_links"]["non_get_discovery_record"] == 1
    assert "synthetic-private-value" not in json.dumps(report)


@pytest.mark.parametrize("status", [401, 429])
def test_real_session_or_rate_limit_failure_stops_all_later_fetches(discovery, status):
    kali, monkeypatch = discovery
    calls = []
    def send(url, **kwargs):
        calls.append(url)
        html = '<a href="/allowed/data">Data</a><a href="/allowed/later">Later</a>'
        return Response(url, html, 200 if url == BASE else status)
    monkeypatch.setattr(kali.requests, "get", send)
    with scoped_surface_requests(lambda *_: (True, ""), BASE):
        report = json.loads(kali.discover_web_surface(BASE, mode="active"))
    assert calls == [BASE, BASE + "data"] and str(status) in report["stop_reason"]


def test_discover_harvests_js_call_schema_and_js_referenced_spec(discovery):
    """SPA kanıtı (WS2): rotası yalnız JS içinde olan uç + JS'nin andığı spec."""
    kali, monkeypatch = discovery
    js = ("fetch('/allowed/api/notes', {method: 'POST', "
          "body: JSON.stringify({title: t, body: b})});\n"
          "const SPEC = '/allowed/api/openapi.json';")
    spec = json.dumps({"openapi": "3.0.0", "paths": {"/api/search": {"get": {
        "parameters": [{"name": "q", "in": "query"}]}}}})
    pages = {BASE: '<html><script src="/allowed/app.js"></script></html>',
             BASE + "app.js": js, BASE + "api/openapi.json": spec}

    def send(url, **kwargs):
        return Response(url, pages.get(url, "missing"), 200 if url in pages else 404)

    monkeypatch.setattr(kali.requests, "get", send)
    with scoped_surface_requests(lambda *_: (True, ""), BASE):
        report = json.loads(kali.discover_web_surface(
            BASE, mode="passive", probe_limit=2))
    assert not report.get("stop_reason"), report
    assert report["sources"].get("js-call", 0) >= 1
    assert report["sources"].get("openapi", 0) >= 1
    queue = {(item["method"], item["url"]): item for item in report["work_queue"]}
    notes = queue[("POST", BASE + "api/notes")]
    assert {p["name"] for p in notes["params"]} >= {"title", "body"}
    assert any(url.endswith("/api/search") for _, url in queue)


def test_real_policy_denial_stops_instead_of_silently_dropping_a_failed_probe(discovery):
    kali, monkeypatch = discovery
    calls = []
    def gate(method, url, headers):
        return (False, "grant_revoked") if url.endswith("data") else (True, "")
    def send(url, **kwargs):
        calls.append(url)
        return Response(url, '<a href="/allowed/data">Data</a><a href="/allowed/later">Later</a>')
    monkeypatch.setattr(kali.requests, "get", send)
    with scoped_surface_requests(gate, BASE):
        report = json.loads(kali.discover_web_surface(BASE, mode="active"))
    assert calls == [BASE] and "grant_revoked" in report["stop_reason"]
