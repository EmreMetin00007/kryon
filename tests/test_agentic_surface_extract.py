"""Unit and integration tests for header/CSS surface extraction and browser Shadow DOM crawling."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
SURFACE_CORE_DIR = REPO_ROOT / "mcp-servers" / "mcp-memory-server"
for _p in (str(SCRIPTS_DIR), str(SURFACE_CORE_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import ToolDispatcher, _build_surface_hints  # noqa: E402


def _unwrap_tool_payload(raw_output: str) -> dict[str, Any]:
    prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw_output.startswith(prefix)
    assert raw_output.endswith(suffix)
    return json.loads(raw_output[len(prefix) : -len(suffix)])


class _HeaderCssHandler(BaseHTTPRequestHandler):
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
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/headers-only":
            self._send(
                200,
                b"ok",
                "text/plain",
                extra_headers={
                    "Link": '</api/v2/catalog>; rel="next", </static/theme.css>; rel="stylesheet"',
                    "Content-Location": "/v2/manifest",
                    "Refresh": "5; url=/redirected-home",
                },
            )
            return

        if path == "/legacy-redirect":
            self._send(
                302,
                b"",
                "",
                extra_headers={
                    "Location": "/portal/overview",
                    "Link": '</api/v2/session-info>; rel="describedby"',
                },
            )
            return

        if path == "/styles/app.css":
            css = (
                "@font-face {\n"
                "  font-family: 'AppSans';\n"
                "  src: url('/fonts/appsans.woff2') format('woff2');\n"
                "}\n"
                "@import url('/api/theme-vars');\n"
                ".hero { background-image: url('/images/hero.png'); }\n"
                ".panel { background-image: url('/hidden/panel-config'); }\n"
            ).encode()
            self._send(200, css, "text/css; charset=utf-8")
            return

        if path == "/not-found":
            self._send(
                404,
                b'{"error":"missing"}',
                "application/json",
                extra_headers={"Link": "</should-not-hint>; rel=\"help\""},
            )
            return

        self._send(200, b"<html><body>ok</body></html>", "text/html")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path == "/items":
            self._send(
                201,
                b'{"created":true}',
                "application/json",
                extra_headers={"Location": "/items/42", "Content-Location": "/api/items/42"},
            )
            return
        self._send(404, b"{}", "application/json")


def test_tool_dispatcher_extract_surface_and_hints_for_headers_and_css(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HeaderCssHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{port}"
        store = ReceiptStore(tmp_path)
        actors = ActorManager([{"alias": "anon", "role": "anonymous"}])
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=actors,
            allowed_methods=("GET", "POST"),
            max_requests=20,
        )
        tools = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path)

        # 1. Response with Link, Content-Location, Refresh headers (non-HTML text/plain)
        hdr_out = _unwrap_tool_payload(tools.dispatch("http_request", {"url": "/headers-only", "actor": "anon"}))
        assert "surface_hints" in hdr_out
        hdr_hints = hdr_out["surface_hints"]
        assert "/api/v2/catalog" in hdr_hints.get("api_endpoints", [])
        assert "/v2/manifest" in hdr_hints.get("links", [])
        assert "/redirected-home" in hdr_hints.get("links", [])
        assert "/static/theme.css" not in hdr_hints.get("links", [])

        budget_before = client.budget.used
        hdr_surf = _unwrap_tool_payload(tools.dispatch("extract_surface", {"receipt_id": hdr_out["receipt_id"]}))
        assert client.budget.used == budget_before
        hdr_urls = {item["url"] for item in hdr_surf.get("links", [])}
        assert {"/api/v2/catalog", "/v2/manifest", "/redirected-home"}.issubset(hdr_urls)
        assert "/static/theme.css" not in hdr_urls

        # 2. 302 redirect receipt populates surface_hints cleanly
        redir_out = _unwrap_tool_payload(tools.dispatch("http_request", {"url": "/legacy-redirect", "actor": "anon"}))
        assert redir_out["status"] == 302
        assert "surface_hints" in redir_out
        redir_hints = redir_out["surface_hints"]
        assert "/portal/overview" in redir_hints.get("links", [])
        assert "/api/v2/session-info" in redir_hints.get("api_endpoints", [])

        # 3. 201 Created with Location + Content-Location
        created_out = _unwrap_tool_payload(
            tools.dispatch("http_request", {"method": "POST", "url": "/items", "actor": "anon", "json_body": {"x": 1}})
        )
        assert created_out["status"] == 201
        assert "surface_hints" in created_out
        assert "/api/items/42" in created_out["surface_hints"].get("api_endpoints", [])
        assert "/items/42" in created_out["surface_hints"].get("links", [])

        # 4. text/css response: non-static URLs surfaced, static .woff2/.png filtered
        css_out = _unwrap_tool_payload(tools.dispatch("http_request", {"url": "/styles/app.css", "actor": "anon"}))
        assert "surface_hints" in css_out
        css_hints = css_out["surface_hints"]
        assert "/api/theme-vars" in css_hints.get("api_endpoints", [])
        assert "/hidden/panel-config" in css_hints.get("links", [])
        assert "/fonts/appsans.woff2" not in css_hints.get("links", [])
        assert "/images/hero.png" not in css_hints.get("links", [])

        css_surf = _unwrap_tool_payload(tools.dispatch("extract_surface", {"receipt_id": css_out["receipt_id"]}))
        css_urls = {item["url"] for item in css_surf.get("links", [])}
        assert "/api/theme-vars" in css_urls
        assert "/hidden/panel-config" in css_urls
        assert "/fonts/appsans.woff2" not in css_urls
        assert "/images/hero.png" not in css_urls

        # 5. Non-2xx/3xx still omits surface_hints
        err_out = _unwrap_tool_payload(tools.dispatch("http_request", {"url": "/not-found", "actor": "anon"}))
        assert err_out["status"] == 404
        assert "surface_hints" not in err_out

        # 6. Direct _build_surface_hints with synthetic 'headers' dict (not only 'response_headers')
        synthetic_hints = _build_surface_hints(
            {
                "receipt_id": "req-9999",
                "url": f"{base_url}/synthetic",
                "status": 200,
                "content_type": "text/plain",
                "headers": {
                    "Link": '</api/v3/ping>; rel="status"',
                    "Refresh": "0;url=/synthetic-next",
                },
                "body": "",
            },
            base_url,
        )
        assert "/api/v3/ping" in synthetic_hints.get("api_endpoints", [])
        assert "/synthetic-next" in synthetic_hints.get("links", [])
    finally:
        server.shutdown()
        server.server_close()


def test_crawl_site_discovers_shadow_dom_interactive_headers_and_css(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cco_surface_core.crawl import HAS_PLAYWRIGHT, crawl_site

    if not HAS_PLAYWRIGHT:
        pytest.skip("playwright not installed")

    server_hits: list[tuple[str, str]] = []

    class _ShadowCrawlHandler(BaseHTTPRequestHandler):
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
            server_hits.append(("GET", path))
            if path == "/":
                html = (
                    "<!doctype html><html><head>"
                    "<link rel='stylesheet' href='/styles/app.css'>"
                    "</head><body>"
                    "<a href='/normal-link' ping='/telemetry/ping /audit/event'>Normal</a>"
                    "<img srcset='/images/hero.png 1x, /api/image-meta 2x'>"
                    "<shadow-widget></shadow-widget>"
                    "<script>"
                    "class ShadowWidget extends HTMLElement {"
                    "  connectedCallback() {"
                    "    const root = this.attachShadow({mode: 'open'});"
                    "    root.innerHTML = `"
                    "      <a href='/shadow-page'>Shadow Link</a>"
                    "      <button id='safe-shadow-btn'>Trigger Shadow</button>"
                    "      <button id='delete-account-btn'>Delete Account</button>"
                    "      <button aria-label='Logout user' id='exit-btn'>Exit</button>"
                    "    `;"
                    "    root.getElementById('safe-shadow-btn').addEventListener('click', () => {"
                    "      fetch('/api/shadow-hit', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({probe: 1})});"
                    "    });"
                    "    root.getElementById('delete-account-btn').addEventListener('click', () => {"
                    "      fetch('/api/destructive-hit', {method: 'POST'});"
                    "    });"
                    "    root.getElementById('exit-btn').addEventListener('click', () => {"
                    "      fetch('/api/logout-hit', {method: 'POST'});"
                    "    });"
                    "  }"
                    "}"
                    "customElements.define('shadow-widget', ShadowWidget);"
                    "</script>"
                    "</body></html>"
                ).encode()
                self._send(
                    200,
                    html,
                    "text/html; charset=utf-8",
                    extra_headers={"Link": '</header-discovered>; rel="alternate"'},
                )
                return

            if path == "/styles/app.css":
                css = (
                    "@font-face { src: url('/fonts/ui.woff2'); }\n"
                    ".banner { background: url('/css-discovered'); }\n"
                ).encode()
                self._send(200, css, "text/css")
                return

            if path in {"/normal-link", "/shadow-page", "/header-discovered", "/css-discovered", "/api/image-meta"}:
                self._send(200, f"<html><body>visited {path}</body></html>".encode(), "text/html")
                return

            self._send(404, b"not found", "text/plain")

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            server_hits.append(("POST", path))
            self._send(200, b'{"ok":true}', "application/json")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _ShadowCrawlHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"

    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({"in_scope": [{"asset": url}], "allow_loopback": True}))
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"allow_loopback": True}))
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope_file))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy_file))
    from policy_engine import PolicyEngine

    PolicyEngine(
        cco_home=str(tmp_path / "home"),
        scope_file=str(scope_file),
        program_policy_file=str(policy_file),
    ).grant_approval("kali-tools_crawl_web_surface", "127.0.0.1", ttl_seconds=600, reason="shadow crawl test")

    try:
        out = crawl_site(url, max_pages=10, wait_ms=60, timeout_ms=10000, max_actions=8)
        assert out.get("ok") is True, out.get("error")

        link_paths = {urlsplit(u).path for u in (out.get("links") or [])}
        page_paths = {urlsplit(p["url"]).path for p in (out.get("pages") or []) if isinstance(p, dict)}
        xhr_entries = {(item.get("method"), urlsplit(item["url"]).path) for item in (out.get("xhr") or [])}
        frontier_items = out.get("frontier") or []

        assert "/normal-link" in link_paths
        assert "/shadow-page" in link_paths
        assert "/shadow-page" in page_paths
        assert "/header-discovered" in link_paths
        assert "/header-discovered" in page_paths
        assert "/css-discovered" in link_paths
        assert "/css-discovered" in page_paths
        assert "/telemetry/ping" in link_paths
        assert "/audit/event" in link_paths
        assert "/api/image-meta" in link_paths

        assert any(
            urlsplit(item["url"]).path == "/header-discovered" and "runtime-header" in (item.get("sources") or [])
            for item in frontier_items
        )
        assert any(
            urlsplit(item["url"]).path == "/css-discovered" and "runtime-css" in (item.get("sources") or [])
            for item in frontier_items
        )

        # Safe interactive Shadow DOM button clicked -> POST /api/shadow-hit captured in xhr/frontier,
        # while read-only gate kept POST off the wire and destructive buttons were NEVER clicked!
        assert ("POST", "/api/shadow-hit") in xhr_entries
        assert ("POST", "/api/destructive-hit") not in xhr_entries
        assert ("POST", "/api/logout-hit") not in xhr_entries
        assert ("POST", "/api/shadow-hit") not in server_hits
        assert any(
            urlsplit(item["url"]).path == "/api/shadow-hit" and item.get("method") == "POST"
            for item in frontier_items
        )

        # Respect max_actions=0 bound: safe button is NOT clicked when action budget is 0
        out_zero = crawl_site(url, max_pages=2, wait_ms=40, timeout_ms=10000, max_actions=0)
        assert out_zero.get("ok") is True
        zero_xhr = {(item.get("method"), urlsplit(item["url"]).path) for item in (out_zero.get("xhr") or [])}
        assert ("POST", "/api/shadow-hit") not in zero_xhr
    finally:
        server.shutdown()
        server.server_close()
