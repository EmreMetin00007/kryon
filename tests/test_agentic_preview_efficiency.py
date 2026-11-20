"""Unit and integration tests for HTML preview pruning and inline surface_hints."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import ToolDispatcher, _format_receipt_preview, prune_html_for_preview  # noqa: E402


def _unwrap_tool_payload(raw_output: str) -> dict[str, Any]:
    prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw_output.startswith(prefix)
    assert raw_output.endswith(suffix)
    return json.loads(raw_output[len(prefix) : -len(suffix)])


def test_prune_html_for_preview_shrinks_noise_and_preserves_security_signal() -> None:
    css_rules = "\n".join(f"  .cls-{i} {{ margin: {i}px; padding: {i}px; color: #123456; }}" for i in range(45))
    passive_svg = (
        '<svg class="icon-logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">\n'
        '  <g fill="none" stroke="currentColor"><path d="M1 1 L20 20 M20 1 L1 20"/><svg><circle cx="12" cy="12" r="5"/></svg></g>\n'
        "</svg>"
    )
    raw_html = f"""<!doctype html>
<html>
  <head>
    <title>Workspace Portal</title>
    <!-- Generated layout template comment block with verbose build metadata -->
    <style type="text/css">
{css_rules}
    </style>
  </head>
  <body style="margin: 0; font-family: sans-serif; background: #fff;">
    <!-- Main navigation banner -->
    <header style="display: flex; padding: 16px;">
      {passive_svg}
      <svg class="spinner" viewBox="0 0 10 10" />
      <a href="/records/rec-1001" style="color: blue;">View Record</a>
    </header>
    <form method="POST" action="/api/v1/orders" style="border: 1px solid #ccc;">
      <input type="text" name="title" value="style='kept-value'" style="width: 100%;" />
      <input type="hidden" name="org_id" value="org-9901" />
    </form>
    <table data-style="kept-data-attr">
      <thead><tr><th>ID</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td>rec-2002</td><td>active</td></tr>
      </tbody>
    </table>
  </body>
</html>"""

    pruned = prune_html_for_preview(raw_html)
    reduction_ratio = 1.0 - (len(pruned) / len(raw_html))
    assert reduction_ratio >= 0.40, f"expected >=40% shrinkage, got {reduction_ratio:.2%}"

    # Noise stripped
    assert "<style" not in pruned.lower()
    assert "cls-44" not in pruned
    assert "<!--" not in pruned
    assert "icon-logo" not in pruned
    assert "spinner" not in pruned
    assert 'style="margin: 0;' not in pruned

    # High-signal HTML preserved
    assert '<a href="/records/rec-1001"' in pruned
    assert '<form method="POST" action="/api/v1/orders"' in pruned
    assert 'name="title"' in pruned
    assert 'value="style=\'kept-value\'"' in pruned
    assert 'name="org_id" value="org-9901"' in pruned
    assert 'data-style="kept-data-attr"' in pruned
    assert "<td>rec-2002</td><td>active</td>" in pruned


def test_prune_html_and_preview_preserve_xss_payloads_verbatim() -> None:
    payloads = [
        "<svg/onload=1>",
        "<svg onload=alert(1)>",
        "<script>alert(1)</script>",
        "<img src=x onerror=1>",
        '<div style="color:red" onclick="alert(1)">click</div>',
        '<a href="javascript:alert(1)" style="color:red">go</a>',
        "<svg><animate onbegin=alert(1) /></svg>",
        "<svg><script>alert(2)</script></svg>",
    ]
    padding_css = "<style>" + ("body { color: #000; }\n" * 100) + "</style>"
    passive_svg = '<svg class="decor"><path d="M0 0h10v10H0z"/></svg>'
    raw_html = (
        "<!doctype html><html><head>"
        + padding_css
        + "</head><body>"
        + passive_svg
        + "\n"
        + "\n".join(f'<div class="echo">{p}</div>' for p in payloads)
        + "</body></html>"
    )

    pruned = prune_html_for_preview(raw_html)
    assert "decor" not in pruned
    assert "<style>" not in pruned
    for payload in payloads:
        assert payload in pruned, f"payload missing after prune_html_for_preview: {payload}"

    receipt = {
        "receipt_id": "req-0001",
        "cached": False,
        "actor": "anon",
        "method": "GET",
        "url": "http://127.0.0.1:8000/search?q=probe",
        "status": 200,
        "elapsed_ms": 5,
        "content_type": "text/html; charset=utf-8",
        "response_length": len(raw_html),
        "redirect_location": "",
        "response_headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": raw_html,
    }
    preview = _format_receipt_preview(receipt, preview_chars=2400)
    assert len(preview["body_preview"]) <= 2400
    for payload in payloads:
        assert payload in preview["body_preview"], f"payload missing in body_preview: {payload}"
    # Because CSS noise was pruned, the entire pruned document now fits cleanly under 2400 chars
    assert "truncation_note" not in preview


def test_format_receipt_preview_truncation_note_and_non_html_untouched() -> None:
    long_rows = "\n".join(f"<tr><td>item-{i:04d}</td><td>value-{i:04d}</td></tr>" for i in range(120))
    long_html = f"<html><body><style>.x{{color:red;}}</style><table>{long_rows}</table></body></html>"
    html_receipt = {
        "receipt_id": "req-0002",
        "cached": False,
        "actor": "anon",
        "method": "GET",
        "url": "http://127.0.0.1:8000/items",
        "status": 200,
        "elapsed_ms": 3,
        "content_type": "text/html",
        "response_length": len(long_html),
        "response_headers": {},
        "body": long_html,
    }
    preview = _format_receipt_preview(html_receipt, preview_chars=400)
    assert len(preview["body_preview"]) == 400
    assert "truncation_note" in preview
    assert "raw chars in store" in preview["truncation_note"]
    assert "read_receipt('req-0002'" in preview["truncation_note"]

    # Non-HTML JSON content must never be altered by HTML pruning
    raw_json = json.dumps({"html_snippet": "<!-- keep --> <style>a{}</style>   spacing"})
    json_receipt = {
        "receipt_id": "req-0003",
        "cached": False,
        "actor": "anon",
        "method": "GET",
        "url": "http://127.0.0.1:8000/api/data",
        "status": 200,
        "elapsed_ms": 2,
        "content_type": "application/json",
        "response_length": len(raw_json),
        "response_headers": {},
        "body": raw_json,
    }
    json_preview = _format_receipt_preview(json_receipt, preview_chars=2400)
    assert json_preview["body_preview"] == raw_json


class _PreviewSurfaceHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:
        pass

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/portal":
            css = "body { color: #333; }\n" * 60
            html = (
                "<!doctype html><html><head><style>"
                + css
                + "</style></head><body>"
                + "<!-- header --><svg class='logo'><path d='M0 0h10v10z'/></svg>"
                + "<form method='POST' action='/api/v1/tickets'><input name='subject'><input name='body'></form>"
                + "<a href='/api/v1/users/me'>Profile</a>"
                + "<a href='/reports/rep-100001'>Report 1</a>"
                + "<a href='/settings'>Settings</a>"
                + "<a href='https://external.example/docs'>External Docs</a>"
                + "<link rel='stylesheet' href='/static/theme.css'>"
                + "<script>fetch('/api/v1/orders');</script>"
                + "</body></html>"
            ).encode()
            self._send(200, html, "text/html; charset=utf-8")
            return

        if path == "/static/bundle.js":
            js = (
                'fetch("/api/v1/invoices");\n'
                'axios.post("/api/v1/invoices/export", {format: "csv"});\n'
                'const routeA = "/api/v1/audit-log";\n'
                'const spaRoute = "#/workspace/members";\n'
            ).encode()
            self._send(200, js, "application/javascript")
            return

        if path == "/openapi.json":
            paths = {
                f"/api/v1/resource-collection-items-{i}-with-very-long-segment-name": {
                    "get": {"summary": f"List resource {i}"},
                    "post": {"summary": f"Create resource {i}"},
                }
                for i in range(15)
            }
            spec = {"openapi": "3.0.0", "info": {"title": "Sample API", "version": "1.0"}, "paths": paths}
            self._send(200, json.dumps(spec).encode(), "application/json")
            return

        if path == "/api/v1/ping":
            self._send(200, json.dumps({"status": "ok", "healthy": True}).encode(), "application/json")
            return

        if path == "/api/v1/missing":
            self._send(404, json.dumps({"error": "not_found", "next": "/api/v1/help"}).encode(), "application/json")
            return

        self._send(404, b'{"error":"not_found"}', "application/json")


def test_http_request_surface_hints_and_lossless_receipt_store(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PreviewSurfaceHandler)
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

        # 1. HTML page: pruned body_preview + compact surface_hints, raw store unmodified
        html_out = _unwrap_tool_payload(tools.dispatch("http_request", {"url": "/portal", "actor": "anon"}))
        assert "<style>" not in html_out["body_preview"]
        assert "icon" not in html_out["body_preview"]
        assert "surface_hints" in html_out
        html_hints = html_out["surface_hints"]
        assert len(json.dumps(html_hints, ensure_ascii=False)) <= 900
        assert html_hints["forms"] == [{"method": "POST", "url": "/api/v1/tickets", "params": ["subject", "body"]}]
        assert "/api/v1/orders" in html_hints["api_endpoints"]
        assert "/api/v1/users/me" in html_hints["api_endpoints"]
        assert "rep-100001" in html_hints.get("ids", [])
        # Non-API same-origin links kept, external & static & api_endpoints excluded
        assert "/settings" in html_hints.get("links", [])
        assert "/api/v1/users/me" not in html_hints.get("links", [])
        assert "/static/theme.css" not in html_hints.get("links", [])
        assert all("external.example" not in link for link in html_hints.get("links", []))

        # Raw ReceiptStore and read_receipt MUST contain original unmodified HTML with <style>, comment, <svg>
        raw_receipt = store.get(html_out["receipt_id"])
        assert "<style>" in raw_receipt["body"]
        assert "<!-- header -->" in raw_receipt["body"]
        assert "<svg class='logo'>" in raw_receipt["body"]
        slice_out = _unwrap_tool_payload(
            tools.dispatch("read_receipt", {"receipt_id": html_out["receipt_id"], "offset": 0, "limit": 2000})
        )
        assert "<style>" in slice_out["body"]
        assert "<!-- header -->" in slice_out["body"]
        assert "<svg class='logo'>" in slice_out["body"]

        # extract_surface continues to work identically at 0 HTTP cost
        budget_before = client.budget.used
        surf_out = _unwrap_tool_payload(tools.dispatch("extract_surface", {"receipt_id": html_out["receipt_id"]}))
        assert client.budget.used == budget_before
        assert len(surf_out["forms"]) == 1
        assert any(lnk["url"] == "/settings" for lnk in surf_out["links"])

        # 2. JS response: api_endpoints and spa_routes bounded <= 900 chars
        js_out = _unwrap_tool_payload(tools.dispatch("http_request", {"url": "/static/bundle.js", "actor": "anon"}))
        js_hints = js_out["surface_hints"]
        assert len(json.dumps(js_hints, ensure_ascii=False)) <= 900
        assert "/api/v1/invoices" in js_hints["api_endpoints"]
        assert "/api/v1/invoices/export" in js_hints["api_endpoints"]
        assert "/api/v1/audit-log" in js_hints["api_endpoints"]
        assert "/workspace/members" in js_hints.get("links", [])

        # 3. OpenAPI JSON spec: bounded openapi_ops (<=10), api_endpoints (<=8), total <= 900 chars
        spec_out = _unwrap_tool_payload(tools.dispatch("http_request", {"url": "/openapi.json", "actor": "anon"}))
        spec_hints = spec_out["surface_hints"]
        assert len(json.dumps(spec_hints, ensure_ascii=False)) <= 900
        assert 1 <= len(spec_hints.get("openapi_ops", [])) <= 10
        assert len(spec_hints.get("api_endpoints", [])) <= 8
        assert spec_hints["openapi_ops"][0].startswith("GET /api/v1/resource-collection-items-0")

        # 4. Simple small JSON response with no links/forms/endpoints/IDs omits surface_hints
        ping_out = _unwrap_tool_payload(tools.dispatch("http_request", {"url": "/api/v1/ping", "actor": "anon"}))
        assert "surface_hints" not in ping_out

        # 5. Non-2xx/3xx responses omit surface_hints
        err_out = _unwrap_tool_payload(tools.dispatch("http_request", {"url": "/api/v1/missing", "actor": "anon"}))
        assert err_out["status"] == 404
        assert "surface_hints" not in err_out
    finally:
        server.shutdown()
        server.server_close()
