"""Unit and loopback Playwright integration tests for scripts/agentic_browser.py."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest

import agentic_browser
from agentic_browser import (
    HAS_PLAYWRIGHT,
    _extract_actor_browser_auth,
    inspect_rendered_page,
    run_browser_crawl,
)
from agentic_http import (
    ActorManager,
    AgenticHTTPClient,
    BudgetExhaustedError,
    ScopeViolationError,
)
from agentic_receipts import ReceiptStore
from agentic_surface import SurfaceFrontierTracker


def _make_client(
    tmp_path: Path,
    *,
    base_url: str = "http://127.0.0.1:18080",
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST"),
    max_requests: int = 20,
) -> tuple[AgenticHTTPClient, SurfaceFrontierTracker]:
    store = ReceiptStore(tmp_path)
    actors = ActorManager(accounts or [])
    http = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
    )
    tracker = SurfaceFrontierTracker(
        base_url=base_url,
        allowed_methods=allowed_methods,
        actor_summaries=actors.summaries(),
    )
    return http, tracker


# ---------------------------------------------------------------------------
# run_browser_crawl unit tests
# ---------------------------------------------------------------------------


def test_run_browser_crawl_blocks_off_origin_before_launching_crawler(tmp_path: Path) -> None:
    http, tracker = _make_client(tmp_path)
    called = False

    def fail_if_called(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    with pytest.raises(ScopeViolationError):
        run_browser_crawl(http, tracker, url="https://evil.example/steal", crawl_fn=fail_if_called)

    with pytest.raises(ScopeViolationError):
        run_browser_crawl(http, tracker, url="//evil.example/proto-rel", crawl_fn=fail_if_called)

    assert not called
    assert http.budget.used == 0


def test_run_browser_crawl_honors_custom_check_scope_hook(tmp_path: Path) -> None:
    http, tracker = _make_client(tmp_path)
    called = False

    def _deny_excluded(full_url: str) -> None:
        if "/logout" in full_url:
            raise ScopeViolationError("excluded path /logout")

    setattr(http, "_check_scope", _deny_excluded)

    def fail_if_called(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    with pytest.raises(ScopeViolationError):
        run_browser_crawl(http, tracker, url="/logout", crawl_fn=fail_if_called)

    assert not called
    assert http.budget.used == 0


def test_run_browser_crawl_enforces_budget_cap_consumption_and_exhaustion(tmp_path: Path) -> None:
    http, tracker = _make_client(tmp_path, max_requests=3)
    observed_kwargs: dict[str, Any] = {}

    def fake_crawl(start_url: str, **kwargs: Any) -> dict[str, Any]:
        observed_kwargs.update(kwargs)
        return {
            "ok": True,
            "pages": [
                {"url": f"{http.base_url}p1", "status": 200, "title": "P1"},
                {"url": f"{http.base_url}p2", "status": 200, "title": "P2"},
            ],
            "links": [],
            "forms": [],
            "xhr": [],
        }

    # Request max_pages=20, wait_ms=99999, timeout_ms=50 -> clamped and capped to remaining budget (3)
    res = run_browser_crawl(
        http,
        tracker,
        url="/",
        max_pages=20,
        wait_ms=99999,
        timeout_ms=50,
        crawl_fn=fake_crawl,
    )
    assert res["ok"] is True
    assert observed_kwargs["allow_subdomains"] is False
    assert observed_kwargs["max_pages"] == 3
    assert observed_kwargs["wait_ms"] == 2000
    assert observed_kwargs["timeout_ms"] == 1000
    assert res["pages_crawled"] == 2
    assert http.budget.used == 2

    # Only 1 request remains in WireBudget -> next crawl caps max_pages to 1 and consumes 1
    def fake_crawl_one(start_url: str, **kwargs: Any) -> dict[str, Any]:
        assert kwargs["max_pages"] == 1
        return {
            "ok": True,
            "pages": [{"url": f"{http.base_url}p3", "status": 200, "title": "P3"}],
            "links": [],
            "forms": [],
            "xhr": [],
        }

    res2 = run_browser_crawl(http, tracker, url="/p3", max_pages=6, crawl_fn=fake_crawl_one)
    assert res2["ok"] is True
    assert res2["truncated"] is True
    assert http.budget.used == 3

    # At 0 remaining budget, raises BudgetExhaustedError without calling crawler
    invoked = False

    def never_run(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal invoked
        invoked = True
        return {"ok": True}

    with pytest.raises(BudgetExhaustedError):
        run_browser_crawl(http, tracker, url="/", crawl_fn=never_run)
    assert not invoked


def test_run_browser_crawl_injects_actor_auth_host_side_without_leaking(tmp_path: Path) -> None:
    secret_cookie = "sid_secret_987654321"
    secret_token = "jwt_top_secret_token_abcdef"
    secret_password = "SuperSecretPassword!42"
    http, tracker = _make_client(
        tmp_path,
        accounts=[
            {
                "alias": "alice",
                "role": "member",
                "email": "alice@example.test",
                "password": secret_password,
                "cookie": f"sid={secret_cookie}",
                "session_token": secret_token,
                "headers": {"X-Tenant": "acme"},
            }
        ],
    )
    http.actors.get("alice").cookies["theme"] = "dark"

    # Direct helper check for anon vs authenticated actor
    assert _extract_actor_browser_auth(http, "anon") == ("", {})
    cookie_hdr, extra_hdrs = _extract_actor_browser_auth(http, "alice")
    assert f"sid={secret_cookie}" in cookie_hdr
    assert "theme=dark" in cookie_hdr
    assert extra_hdrs.get("Authorization") == f"Bearer {secret_token}"
    assert extra_hdrs.get("X-Tenant") == "acme"
    assert "Cookie" not in extra_hdrs

    captured_auth: dict[str, Any] = {}

    def fake_crawl(start_url: str, **kwargs: Any) -> dict[str, Any]:
        captured_auth["cookie"] = kwargs.get("cookie")
        captured_auth["extra_headers"] = kwargs.get("extra_headers")
        return {
            "ok": True,
            "pages": [
                {
                    "url": f"{http.base_url}dashboard",
                    "status": 200,
                    "title": f"Dashboard for {secret_token}",
                }
            ],
            "links": [f"{http.base_url}profile"],
            "forms": [
                {
                    "page": f"{http.base_url}dashboard",
                    "action": "/settings/password",
                    "method": "POST",
                    "fields": [
                        {"name": "current_password", "type": "password", "value": secret_password},
                        {"name": "display_name", "type": "text", "value": "Alice"},
                    ],
                }
            ],
            "xhr": [],
        }

    res = run_browser_crawl(http, tracker, url="/dashboard", actor="alice", crawl_fn=fake_crawl)
    assert res["ok"] is True
    assert f"sid={secret_cookie}" in str(captured_auth["cookie"])
    assert captured_auth["extra_headers"]["Authorization"] == f"Bearer {secret_token}"
    assert captured_auth["extra_headers"]["X-Tenant"] == "acme"

    serialized = json.dumps(res)
    assert secret_cookie not in serialized
    assert secret_token not in serialized
    assert secret_password not in serialized
    assert "Authorization" not in serialized
    assert res["forms"] == [
        {"action": "/settings/password", "method": "POST", "fields": ["current_password", "display_name"]}
    ]


def test_extract_actor_browser_auth_uses_get_browser_auth_state_when_present(tmp_path: Path) -> None:
    http, _ = _make_client(tmp_path)
    setattr(
        http.actors,
        "get_browser_auth_state",
        lambda actor: ({"sid": "custom_cookie_val"}, {"Authorization": "Bearer custom_tok", "Cookie": "ignored=1"}),
    )
    cookie_hdr, extra = _extract_actor_browser_auth(http, "bob")
    assert "sid=custom_cookie_val" in cookie_hdr
    assert extra == {"Authorization": "Bearer custom_tok"}


def test_run_browser_crawl_filters_same_origin_and_ingests_into_surface_tracker(tmp_path: Path) -> None:
    http, tracker = _make_client(tmp_path, allowed_methods=("GET", "HEAD", "POST"))

    def fake_crawl(start_url: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "pages": [
                {"url": f"{http.base_url}", "status": 200, "title": "Home"},
                {"url": "https://evil.example/phish", "status": 200, "title": "Off Origin"},
            ],
            "links": [
                f"{http.base_url}reports?view=all",
                f"{http.base_url}reports?view=all",  # duplicate
                f"{http.base_url}static/app.css",  # static asset -> dropped
                f"{http.base_url}images/logo.png",  # static asset -> dropped
                "https://evil.example/external",  # off-origin -> dropped
                "http://127.0.0.1:19999/other-port",  # wrong port -> dropped
                "javascript:alert(1)",
            ],
            "hash_routes": [f"{http.base_url}#/spa/orders/42"],
            "forms": [
                {
                    "page": f"{http.base_url}",
                    "action": f"{http.base_url}api/tickets",
                    "method": "POST",
                    "fields": [{"name": "subject", "type": "text"}, {"name": "priority", "type": "select"}],
                },
                {
                    "page": f"{http.base_url}",
                    "action": "https://evil.example/steal-form",
                    "method": "POST",
                    "fields": [{"name": "secret", "type": "text"}],
                },
            ],
            "xhr": [
                {
                    "method": "GET",
                    "url": f"{http.base_url}api/v1/items?page=1",
                    "status": 200,
                },
                {
                    "method": "POST",
                    "url": f"{http.base_url}api/v1/comments",
                    "status": 0,
                    "body_fields": ["body", "item_id"],
                },
                {
                    "method": "GET",
                    "url": "https://analytics.evil.example/collect",
                    "status": 200,
                },
            ],
        }

    res = run_browser_crawl(http, tracker, url="/", actor="anon", crawl_fn=fake_crawl)
    assert res["ok"] is True
    assert res["start_url"] == "/"
    assert res["pages_crawled"] == 1
    assert [p["url"] for p in res["pages"]] == ["/"]
    assert res["links"] == ["/reports?view=all", "/#/spa/orders/42"]
    assert res["forms"] == [{"action": "/api/tickets", "method": "POST", "fields": ["subject", "priority"]}]
    assert res["xhr_calls"] == [
        {"method": "GET", "url": "/api/v1/items?page=1", "status": 200},
        {"method": "POST", "url": "/api/v1/comments", "status": 0, "body_fields": ["body", "item_id"]},
    ]

    # Verify SurfaceFrontierTracker received links, forms, and XHR endpoints (and NO external URLs)
    assert ("GET", "/reports") in tracker.discovered_routes
    assert ("GET", "/api/v1/items") in tracker.discovered_routes
    assert ("POST", "/api/tickets") in tracker.discovered_routes
    assert ("POST", "/api/v1/comments") in tracker.discovered_routes
    assert "subject" in tracker.discovered_params.get("/api/tickets", set())
    assert "view" in tracker.discovered_params.get("/reports", set())
    assert "body" in tracker.discovered_params.get("/api/v1/comments", set())
    assert all("evil.example" not in route for _, route in tracker.discovered_routes)


def test_run_browser_crawl_playwright_unavailable_consumes_zero_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http, tracker = _make_client(tmp_path, max_requests=5)
    monkeypatch.setattr(agentic_browser, "HAS_PLAYWRIGHT", False)

    res = run_browser_crawl(http, tracker, url="/")
    assert res == {
        "ok": False,
        "error": "playwright_unavailable",
        "pages_crawled": 0,
        "pages": [],
        "links": [],
        "forms": [],
        "xhr_calls": [],
    }
    assert http.budget.used == 0


# ---------------------------------------------------------------------------
# inspect_rendered_page unit tests
# ---------------------------------------------------------------------------


def test_inspect_rendered_page_scope_budget_and_mocked_runner(tmp_path: Path) -> None:
    http, _ = _make_client(
        tmp_path,
        accounts=[{"alias": "bob", "session_token": "bob_secret_jwt_12345"}],
        max_requests=1,
    )

    # Off-origin blocked before consuming budget
    with pytest.raises(ScopeViolationError):
        inspect_rendered_page(http, url="https://other.example/page")
    assert http.budget.used == 0

    captured: dict[str, Any] = {}

    def fake_runner(full_url: str, **kwargs: Any) -> dict[str, Any]:
        captured["url"] = full_url
        captured["kwargs"] = kwargs
        return {
            "ok": True,
            "url": f"{http.base_url}search?q=marker",
            "status": 200,
            "title": "Search Results",
            "csp": "default-src 'self'; script-src 'self'",
            "runtime_events": [
                {
                    "kind": "fetch",
                    "method": "GET",
                    "url": "/api/search?q=secret_val&limit=10",
                    "header_names": ["Accept", "X-Trace-Id"],
                    "body_fields": [],
                    "status": 200,
                },
                {
                    "kind": "fetch",
                    "method": "GET",
                    "url": "https://evil.example/off-origin?leak=1",
                    "header_names": ["X-Evil"],
                    "body_fields": [],
                    "status": 0,
                },
            ],
            "console_error_count": 2,
            "blocked_request_count": 1,
            "marker_check": {
                "checked": True,
                "in_inner_text": True,
                "in_outer_html": False,
                "in_script_or_event_attr": False,
                "script_matches": 0,
                "event_attr_matches": [],
            },
        }

    res = inspect_rendered_page(
        http,
        url="/search?q=marker",
        actor="bob",
        marker="<img onerror=probe>",
        runner=fake_runner,
    )
    assert res["ok"] is True
    assert http.budget.used == 1
    assert captured["kwargs"]["extra_headers"]["Authorization"] == "Bearer bob_secret_jwt_12345"
    assert res["url"] == "/search?q=marker"
    assert res["status"] == 200
    assert res["csp_present"] is True
    assert "default-src 'self'" in res["csp"]
    assert res["console_error_count"] == 2
    assert res["blocked_request_count"] == 1
    assert len(res["runtime_requests"]) == 1
    assert res["runtime_requests"][0]["path"] == "/api/search"
    assert res["runtime_requests"][0]["query_params"] == ["limit", "q"]
    assert "secret_val" not in json.dumps(res)
    assert "bob_secret_jwt_12345" not in json.dumps(res)
    assert res["marker_check"]["in_inner_text"] is True
    assert res["marker_check"]["in_outer_html"] is False
    assert res["marker_check"]["in_script_or_event_attr"] is False

    # Budget is now exhausted (1/1)
    with pytest.raises(BudgetExhaustedError):
        inspect_rendered_page(http, url="/search", runner=fake_runner)


def test_inspect_rendered_page_playwright_unavailable_consumes_zero_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http, _ = _make_client(tmp_path, max_requests=5)
    monkeypatch.setattr(agentic_browser, "HAS_PLAYWRIGHT", False)

    res = inspect_rendered_page(http, url="/")
    assert res == {"ok": False, "error": "playwright_unavailable"}
    assert http.budget.used == 0


# ---------------------------------------------------------------------------
# Live Playwright loopback ThreadingHTTPServer integration tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed")
def test_run_browser_crawl_live_loopback_spa_shadow_dom_and_xhr(tmp_path: Path) -> None:
    received_auth: list[tuple[str, str]] = []
    post_hits: list[str] = []

    class _SpaHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            return

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            received_auth.append((str(self.headers.get("Cookie") or ""), str(self.headers.get("Authorization") or "")))
            if path == "/":
                html = (
                    "<!doctype html><html><head><title>SPA Home</title>"
                    "<link rel='stylesheet' href='/static/theme.css'>"
                    "</head><body>"
                    "<h1>Portal</h1>"
                    "<a href='https://evil.example/off-origin'>External</a>"
                    "<form action='/items/search' method='POST'>"
                    "  <input type='text' name='q' value='hello'>"
                    "  <input type='password' name='pin' value='topsecret'>"
                    "</form>"
                    "<shadow-nav></shadow-nav>"
                    "<script>"
                    "fetch('/api/dynamic-items');"
                    "class ShadowNav extends HTMLElement {"
                    "  connectedCallback() {"
                    "    const root = this.attachShadow({mode: 'open'});"
                    "    root.innerHTML = `<a href='/shadow/secret-route'>Shadow Secret</a>`;"
                    "  }"
                    "}"
                    "customElements.define('shadow-nav', ShadowNav);"
                    "</script>"
                    "</body></html>"
                ).encode("utf-8")
                self._send(200, html, "text/html; charset=utf-8")
                return
            if path == "/api/dynamic-items":
                self._send(200, b'{"items":[{"id":1,"name":"alpha"}]}', "application/json")
                return
            if path == "/shadow/secret-route":
                self._send(200, b"<html><head><title>Shadow Route</title></head><body>OK</body></html>", "text/html")
                return
            if path == "/static/theme.css":
                self._send(200, b"body { color: #111; }", "text/css")
                return
            self._send(404, b"not found", "text/plain")

        def do_POST(self) -> None:
            post_hits.append(self.path)
            self._send(200, b'{"ok":true}', "application/json")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _SpaHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{port}"
        http, tracker = _make_client(
            tmp_path,
            base_url=base_url,
            accounts=[
                {
                    "alias": "tester",
                    "cookie": "sid=live_cookie_xyz",
                    "session_token": "live_bearer_token_999",
                }
            ],
            allowed_methods=("GET", "HEAD", "POST"),
            max_requests=10,
        )

        res = run_browser_crawl(
            http,
            tracker,
            url="/",
            actor="tester",
            max_pages=5,
            wait_ms=250,
            timeout_ms=10000,
        )
        assert res["ok"] is True, res.get("error")
        assert res["pages_crawled"] >= 2
        assert http.budget.used == res["pages_crawled"]

        page_urls = {p["url"] for p in res["pages"]}
        assert "/" in page_urls
        assert "/shadow/secret-route" in page_urls
        assert "/shadow/secret-route" in res["links"]
        assert "/static/theme.css" not in res["links"]
        assert not any("evil.example" in u for u in res["links"])

        xhr_pairs = {(x["method"], x["url"]) for x in res["xhr_calls"]}
        assert ("GET", "/api/dynamic-items") in xhr_pairs

        assert any(
            f["action"] == "/items/search" and f["method"] == "POST" and "q" in f["fields"] and "pin" in f["fields"]
            for f in res["forms"]
        )

        # Auth sent host-side on loopback wire, NEVER leaked in returned dict
        assert any("sid=live_cookie_xyz" in c and "Bearer live_bearer_token_999" in a for c, a in received_auth)
        serialized = json.dumps(res)
        assert "live_cookie_xyz" not in serialized
        assert "live_bearer_token_999" not in serialized
        assert "topsecret" not in serialized

        # Read-only guarantee: no POST ever reached the server
        assert post_hits == []

        # SurfaceFrontierTracker ingested Shadow DOM route, dynamic XHR, and form
        assert ("GET", "/shadow/secret-route") in tracker.discovered_routes
        assert ("GET", "/api/dynamic-items") in tracker.discovered_routes
        assert ("POST", "/items/search") in tracker.discovered_routes
        assert "q" in tracker.discovered_params.get("/items/search", set())
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed")
def test_inspect_rendered_page_live_loopback_csp_hooks_and_marker(tmp_path: Path) -> None:
    post_hits: list[str] = []

    class _InspectHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            return

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            params = dict(parse_qsl(parsed.query))
            if parsed.path == "/escaped":
                # Safely HTML-escaped rendering of marker (visible in innerText, escaped in outerHTML)
                raw_m = params.get("m", "")
                escaped = raw_m.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                html = (
                    "<!doctype html><html><head><title>Escaped QA</title></head><body>"
                    f"<div id='out'>{escaped}</div>"
                    "<script src='/app.js'></script>"
                    "</body></html>"
                ).encode("utf-8")
                self._send(
                    200,
                    html,
                    "text/html; charset=utf-8",
                    extra_headers={
                        "Content-Security-Policy": "default-src 'self'; connect-src *; object-src 'none'"
                    },
                )
                return

            if parsed.path == "/app.js":
                js = (
                    "console.error('qa_test_console_err');\n"
                    "fetch('/api/runtime-ping?secret_param=TOPSECRET', {headers: {'X-Client-Mode': 'qa'}});\n"
                    "fetch('/api/blocked-write', {method: 'POST', headers: {'Content-Type': 'application/json'},"
                    "  body: JSON.stringify({action_name: 'mutate', secret_field: 'do_not_send'})}).catch(() => {});\n"
                    "fetch('https://evil.example/off-origin-ping').catch(() => {});\n"
                ).encode("utf-8")
                self._send(200, js, "application/javascript; charset=utf-8")
                return

            if parsed.path == "/unescaped":
                raw_m = params.get("m", "")
                html = (
                    "<!doctype html><html><head><title>Unescaped QA</title></head><body>"
                    f"<button onclick=\"void('{raw_m}')\">Click</button>"
                    "</body></html>"
                ).encode("utf-8")
                self._send(200, html, "text/html; charset=utf-8")
                return

            if parsed.path == "/api/runtime-ping":
                self._send(200, b'{"pong":true}', "application/json")
                return

            self._send(404, b"not found", "text/plain")

        def do_POST(self) -> None:
            post_hits.append(self.path)
            self._send(200, b'{"mutated":true}', "application/json")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _InspectHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{port}"
        http, _ = _make_client(tmp_path, base_url=base_url, max_requests=5)

        # 1. Escaped reflection: marker appears in innerText, NOT verbatim in outerHTML, NOT in script/event attr
        marker_tag = "<b>QA_MARKER_777</b>"
        res_escaped = inspect_rendered_page(
            http,
            url="/escaped?m=%3Cb%3EQA_MARKER_777%3C/b%3E",
            actor="anon",
            marker=marker_tag,
            wait_ms=250,
            timeout_ms=10000,
        )
        assert res_escaped["ok"] is True, res_escaped.get("error")
        assert http.budget.used == 1
        assert res_escaped["status"] == 200
        assert res_escaped["csp_present"] is True
        assert "default-src 'self'" in res_escaped["csp"]
        assert res_escaped["console_error_count"] >= 1
        assert res_escaped["blocked_request_count"] >= 2  # blocked POST + blocked off-origin GET

        # Verify POST never reached the wire
        assert post_hits == []

        # Runtime fetch hook captured same-origin metadata with redacted query values & body field names
        rt_by_path = {r["path"]: r for r in res_escaped["runtime_requests"]}
        assert "/api/runtime-ping" in rt_by_path
        ping_meta = rt_by_path["/api/runtime-ping"]
        assert ping_meta["method"] == "GET"
        assert ping_meta["query_params"] == ["secret_param"]
        assert "X-Client-Mode" in ping_meta["header_names"]
        assert "/api/blocked-write" in rt_by_path
        write_meta = rt_by_path["/api/blocked-write"]
        assert write_meta["method"] == "POST"
        assert set(write_meta["body_fields"]) == {"action_name", "secret_field"}
        # Off-origin fetch filtered out and secret values never leaked
        assert not any("evil.example" in r["url"] for r in res_escaped["runtime_requests"])
        assert "TOPSECRET" not in json.dumps(res_escaped)
        assert "do_not_send" not in json.dumps(res_escaped)

        # Marker check distinguishes escaped text vs raw HTML
        mc = res_escaped["marker_check"]
        assert mc["checked"] is True
        assert mc["in_inner_text"] is True
        assert mc["in_outer_html"] is False
        assert mc["in_script_or_event_attr"] is False

        # 2. Unescaped event attribute reflection
        event_marker = "QA_EVENT_MARKER_999"
        res_unescaped = inspect_rendered_page(
            http,
            url=f"/unescaped?m={event_marker}",
            actor="anon",
            marker=event_marker,
            wait_ms=150,
            timeout_ms=10000,
        )
        assert res_unescaped["ok"] is True, res_unescaped.get("error")
        assert http.budget.used == 2
        assert res_unescaped["csp_present"] is False
        mc2 = res_unescaped["marker_check"]
        assert mc2["checked"] is True
        assert mc2["in_outer_html"] is True
        assert mc2["in_script_or_event_attr"] is True
        assert "button[onclick]" in mc2["event_attr_matches"]
    finally:
        server.shutdown()
        server.server_close()
