"""Unit and loopback Playwright integration tests for scripts/agentic_stage0_crawl.py."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

import pytest

import agentic_stage0_crawl
from agentic_stage0_crawl import (
    HAS_PLAYWRIGHT,
    _Stage0Collector,
    _compute_dom_state_hash,
    _extract_openapi_templates,
    _finalize_routes,
    _parse_multipart_schema,
    _select_crawl_actors,
    run_stage0_crawl,
)
from agentic_http import ActorManager, AgenticHTTPClient
from agentic_receipts import ReceiptStore
from agentic_surface import SurfaceFrontierTracker, route_template_of


def _make_client(
    tmp_path: Path,
    *,
    base_url: str = "http://127.0.0.1:18080",
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST"),
    max_requests: int = 120,
    excluded_paths: tuple[str, ...] = (),
) -> AgenticHTTPClient:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager(accounts or [])
    return AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
        excluded_paths=excluded_paths,
    )


@contextmanager
def _start_test_server(
    router: Callable[[str, str, dict[str, str], bytes], tuple[int, str, bytes | str, dict[str, str]]],
) -> Iterator[tuple[str, int, list[dict[str, Any]]]]:
    """Run a local loopback ThreadingHTTPServer recording every received request."""
    requests_log: list[dict[str, Any]] = []
    log_lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            with log_lock:
                requests_log.append({
                    "method": self.command,
                    "path": self.path,
                    "headers": hdrs,
                    "body": body,
                })
            status, ctype, payload, extra_hdrs = router(self.command, self.path, hdrs, body)
            raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            for hk, hv in (extra_hdrs or {}).items():
                self.send_header(hk, hv)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

        def do_GET(self) -> None:
            self._handle()

        def do_HEAD(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def do_PUT(self) -> None:
            self._handle()

        def do_PATCH(self) -> None:
            self._handle()

        def do_DELETE(self) -> None:
            self._handle()

        def do_OPTIONS(self) -> None:
            self._handle()

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/", port, requests_log
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


# ---------------------------------------------------------------------------
# Unit tests (no browser required)
# ---------------------------------------------------------------------------


def test_graceful_no_playwright_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = _make_client(tmp_path, max_requests=25)
    monkeypatch.setattr(agentic_stage0_crawl, "HAS_PLAYWRIGHT", False)

    res = run_stage0_crawl(http, output_dir=tmp_path, allow_forms=True)

    assert res["schema"] == "stage0-seed/1"
    assert res["url"] == http.base_url
    assert res["status"] == "skipped_no_playwright"
    assert res["mode"] == "readonly"
    assert res["actors_crawled"] == []
    assert res["links"] == []
    assert res["forms"] == []
    assert res["ws_endpoints"] == []
    assert res["body_templates"] == {}
    assert res["multipart_schemas"] == {}
    assert res["discovery_hints"] == []
    assert res["seed_file"] == ""
    assert http.budget.used == 0

    stats = res["stats"]
    assert stats["status"] == "skipped_no_playwright"
    assert stats["mode"] == "readonly"
    for counter_key in (
        "pages_visited",
        "dom_states_seen",
        "ui_actions_taken",
        "forms_submitted",
        "uploads_triggered",
        "network_requests_captured",
        "js_chunks_parsed",
        "passive_probes_sent",
        "ws_endpoints_found",
        "routes_accepted",
        "body_templates_count",
        "multipart_schemas_count",
        "requests_charged",
    ):
        assert stats[counter_key] == 0


def test_multi_actor_selection_picks_member_and_admin_or_fallback(tmp_path: Path) -> None:
    http_anon = _make_client(tmp_path / "a1")
    assert _select_crawl_actors(http_anon, None) == ["anon"]

    http_multi = _make_client(
        tmp_path / "a2",
        accounts=[
            {"alias": "u1", "role": "member", "tenant": "acme", "session_token": "tok_u1_abcdef"},
            {"alias": "u2", "role": "member", "tenant": "beta", "session_token": "tok_u2_abcdef"},
            {"alias": "adm", "role": "admin", "tenant": "acme", "session_token": "tok_adm_abcdef"},
        ],
    )
    assert _select_crawl_actors(http_multi, None) == ["u1", "adm"]
    assert _select_crawl_actors(http_multi, ["u2"]) == ["u2"]

    http_tenants = _make_client(
        tmp_path / "a3",
        accounts=[
            {"alias": "u1", "role": "member", "tenant": "acme", "session_token": "tok_t1_abcdef"},
            {"alias": "u2", "role": "member", "tenant": "beta", "session_token": "tok_t2_abcdef"},
        ],
    )
    assert _select_crawl_actors(http_tenants, None) == ["u1", "u2"]


def test_multipart_schema_parser_extracts_names_only() -> None:
    boundary = "----TestBoundary12345"
    secret_payload = b"BINARY_PNG_SECRET_PAYLOAD_SHOULD_NOT_APPEAR"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="description"\r\n\r\n'
        "super secret field text\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="attachment"; filename="sample.png"\r\n'
        "Content-Type: image/png\r\n\r\n"
    ).encode("utf-8") + secret_payload + f"\r\n--{boundary}--\r\n".encode("utf-8")

    schema = _parse_multipart_schema(body, f"multipart/form-data; boundary={boundary}")
    assert schema == {"fields": ["description"], "files": ["attachment"]}
    assert "super secret" not in json.dumps(schema)
    assert "BINARY_PNG_SECRET" not in json.dumps(schema)


def test_route_clustering_deduplication_and_priority_ranking(tmp_path: Path) -> None:
    http = _make_client(tmp_path, base_url="http://127.0.0.1:18080/")
    collector = _Stage0Collector(http)

    # Record 3 concrete item IDs under same template -> must collapse to <= 2 reps
    collector.record_route(method="GET", raw_url="/api/items/1?view=full", status=200)
    collector.record_route(method="GET", raw_url="/api/items/2?sort=asc", status=200)
    collector.record_route(method="GET", raw_url="/api/items/3?extra=1", status=200)
    collector.record_route(method="GET", raw_url="/about", status=200)
    collector.record_route(method="GET", raw_url="/", status=200)
    collector.record_route(
        method="POST",
        raw_url="/api/notes",
        status=201,
        params=["title", "body"],
        body_template={"title": "hello", "body": "world"},
        body_template_observed=True,
    )
    collector.record_route(
        method="POST",
        raw_url="/api/upload",
        status=200,
        multipart_schema={"fields": ["folder"], "files": ["file"]},
    )

    links, forms, body_templates, multipart_schemas, hints = _finalize_routes(collector)

    item_reps = [r for r in links if route_template_of(r["url"]) == "/api/items/{id}"]
    assert len(item_reps) == 2
    # Merged params from all 3 instances appear on the representatives
    assert set(item_reps[0]["params"]) == {"extra", "sort", "view"}

    # Mutating / body-templated / multipart routes rank ahead of passive GETs
    assert links[0]["method"] == "POST"
    assert links[0]["url"] == "/api/notes"
    assert body_templates["POST /api/notes"] == {"title": "hello", "body": "world"}
    assert multipart_schemas["POST /api/upload"] == {"fields": ["folder"], "files": ["file"]}
    assert any(f["url"] == "/api/upload" and f["is_form"] is True for f in forms)
    assert len(hints) >= 2


def test_websocket_capture_unit_same_origin_and_off_origin(tmp_path: Path) -> None:
    http = _make_client(
        tmp_path,
        base_url="http://127.0.0.1:18080/",
        excluded_paths=("/ws/excluded",),
    )
    collector = _Stage0Collector(http)

    assert collector.record_ws_endpoint("ws://127.0.0.1:18080/ws/events") is True
    assert collector.record_ws_endpoint("ws://127.0.0.1:18080/ws/events") is True  # deduplicated
    assert collector.record_ws_endpoint("ws://127.0.0.1:19999/ws/evil") is False
    assert collector.record_ws_endpoint("wss://evil.example/ws/steal") is False
    assert collector.record_ws_endpoint("ws://127.0.0.1:18080/ws/excluded") is False

    ws_list = list(collector.ws_endpoints.values())
    assert ws_list == [{"url": "ws://127.0.0.1:18080/ws/events", "path": "/ws/events"}]


def test_dom_state_hash_ignores_volatile_numbers_and_timestamps() -> None:
    dom_a = {
        "pathname": "/items/101",
        "hash": "#/panel/1",
        "dialog_count": 0,
        "headings": [{"tag": "h1", "text": "Item 101 updated 2026-11-22 10:15:00"}],
        "forms": [],
        "standalone_files": [],
        "controls": [{"role": "tab", "aria_selected": "true", "aria_expanded": "", "aria_controls": "p1", "label": "Tab 1"}],
        "visible_links": ["/items/101", "/items/102"],
    }
    dom_b = {
        "pathname": "/items/999",
        "hash": "#/panel/9",
        "dialog_count": 0,
        "headings": [{"tag": "h1", "text": "Item 999 updated 2026-12-01 23:59:59"}],
        "forms": [],
        "standalone_files": [],
        "controls": [{"role": "tab", "aria_selected": "true", "aria_expanded": "", "aria_controls": "p1", "label": "Tab 9"}],
        "visible_links": ["/items/500"],
    }
    dom_c = dict(dom_a, controls=[{"role": "tab", "aria_selected": "false", "aria_expanded": "", "aria_controls": "p2", "label": "Settings"}])

    assert _compute_dom_state_hash(dom_a) == _compute_dom_state_hash(dom_b)
    assert _compute_dom_state_hash(dom_a) != _compute_dom_state_hash(dom_c)


def test_openapi_template_synthesis_resolves_refs() -> None:
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/api/projects": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CreateProject"}
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "CreateProject": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "priority": {"type": "integer", "minimum": 2},
                        "secret_key": {"type": "string", "example": "should_be_redacted"},
                    },
                }
            }
        },
    }
    templates, _mp, _ops = _extract_openapi_templates(spec)
    tmpl = templates[("POST", "/api/projects")]
    assert tmpl["name"] == "sample"
    assert tmpl["priority"] == 2
    assert tmpl["secret_key"] == "<redacted>"


# ---------------------------------------------------------------------------
# Real loopback Playwright integration tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_readonly_mode_navigation_tabs_js_openapi_blocks_posts(tmp_path: Path) -> None:
    openapi_doc = {
        "openapi": "3.0.3",
        "info": {"title": "Demo", "version": "1.0"},
        "paths": {
            "/api/openapi-create": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "title": {"type": "string"},
                                        "count": {"type": "integer"},
                                    },
                                }
                            }
                        }
                    }
                }
            }
        },
    }

    def router(method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            html = """<!doctype html>
<html>
<head><title>Home</title><script src="/assets/app.js"></script></head>
<body>
  <h1>Dashboard</h1>
  <nav>
    <a href="/reports">Reports</a>
    <a href="#/hash-view">Hash View</a>
  </nav>
  <div role="tablist">
    <button role="tab" id="tab-overview" aria-selected="true" aria-controls="panel-1">Overview</button>
    <button role="tab" id="tab-extra" aria-selected="false" aria-controls="panel-2" onclick="openExtraTab()">Extra Data</button>
  </div>
  <div id="panel-1"><h2>Overview</h2></div>
  <div id="panel-2" style="display:none"><h2>Extra Panel</h2><a href="/tab-revealed">Revealed Link</a></div>
  <form action="/api/should-not-post" method="POST">
    <input name="note" type="text" />
    <button type="submit">Submit Note</button>
  </form>
  <script>
    function openExtraTab() {
      document.getElementById('tab-overview').setAttribute('aria-selected', 'false');
      document.getElementById('tab-extra').setAttribute('aria-selected', 'true');
      document.getElementById('panel-1').style.display = 'none';
      document.getElementById('panel-2').style.display = 'block';
      fetch('/api/tab-data?source=tab');
    }
    window.addEventListener('hashchange', function() {
      if (window.location.hash === '#/hash-view') {
        fetch('/api/from-hash-route');
      }
    });
    if (window.location.hash === '#/hash-view') {
      fetch('/api/from-hash-route');
    }
  </script>
</body>
</html>"""
            return 200, "text/html; charset=utf-8", html, {}
        if path == "/reports":
            return 200, "text/html; charset=utf-8", "<html><body><h1>Reports</h1><a href='/api/reports/list'>List</a></body></html>", {}
        if path == "/tab-revealed":
            return 200, "text/html; charset=utf-8", "<html><body><h1>Revealed</h1></body></html>", {}
        if path == "/assets/app.js":
            js = """
async function hiddenSubmit(payload) {
  return fetch('/api/hidden-from-js', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({item: payload})
  });
}
"""
            return 200, "application/javascript", js, {}
        if path == "/api/tab-data":
            return 200, "application/json", json.dumps({"ok": True}), {}
        if path == "/api/from-hash-route":
            return 200, "application/json", json.dumps({"hash": True}), {}
        if path == "/api/reports/list":
            return 200, "application/json", json.dumps({"reports": []}), {}
        if path == "/openapi.json":
            return 200, "application/json", json.dumps(openapi_doc), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_test_server(router) as (base_url, _port, log):
        http = _make_client(tmp_path, base_url=base_url, allowed_methods=("GET", "HEAD", "POST"), max_requests=120)
        res = run_stage0_crawl(
            http,
            allow_forms=False,
            max_pages=10,
            max_actions=10,
            wait_ms=250,
            max_passive_probes=10,
        )

        assert res["schema"] == "stage0-seed/1"
        assert res["status"] == "ok"
        assert res["mode"] == "readonly"
        assert res["stats"]["forms_submitted"] == 0
        assert res["stats"]["js_chunks_parsed"] >= 1
        assert res["stats"]["passive_probes_sent"] >= 1

        # Server must receive ZERO POST requests in readonly mode.
        assert [r for r in log if r["method"] == "POST"] == []

        all_routes = {(r["method"], r["url"]) for r in [*res["links"], *res["forms"]]}
        assert ("GET", "/reports") in all_routes
        assert ("GET", "/api/tab-data") in all_routes
        assert ("GET", "/api/from-hash-route") in all_routes
        assert ("POST", "/api/hidden-from-js") in all_routes
        assert ("POST", "/api/openapi-create") in all_routes
        assert "POST /api/openapi-create" in res["body_templates"]
        assert res["body_templates"]["POST /api/openapi-create"] == {"title": "sample", "count": 1}

        # Verify seamless ingestion into SurfaceFrontierTracker
        tracker = SurfaceFrontierTracker(base_url=base_url, allowed_methods=("GET", "HEAD", "POST"))
        tracker.ingest_surface(res, actor="stage0")
        assert ("POST", "/api/hidden-from-js") in tracker.discovered_routes
        assert ("GET", "/api/tab-data") in tracker.discovered_routes


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_forms_and_upload_mode_skips_destructive_and_writes_seed(tmp_path: Path) -> None:
    def router(method: str, raw_path: str, hdrs: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            html = """<!doctype html>
<html>
<head><title>Workspace</title></head>
<body>
  <h1>Notes & Uploads</h1>
  <form id="note-form" onsubmit="submitNote(event)">
    <input name="title" type="text" required />
    <input name="contact_email" type="email" />
    <button type="submit">Create Note</button>
  </form>
  <form id="upload-form" action="/api/upload" method="POST" enctype="multipart/form-data" onsubmit="submitUpload(event)">
    <input name="folder" type="text" />
    <input name="file" type="file" accept="image/png" />
    <button type="submit">Upload Asset</button>
  </form>
  <div>
    <input id="quick-file" name="avatar" type="file" accept="text/plain" onchange="quickUpload(event)" />
  </div>
  <form id="danger-form" action="/api/account/delete" method="POST">
    <input name="confirm" type="text" />
    <button type="submit">Delete Account</button>
  </form>
  <button type="button" onclick="fetch('/api/account/delete', {method: 'POST'})">Delete Account</button>
  <button type="button" onclick="fetch('/api/logout', {method: 'POST'})">Logout</button>
  <script>
    function submitNote(ev) {
      ev.preventDefault();
      const fd = new FormData(ev.target);
      fetch('/api/notes', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({title: fd.get('title'), contact_email: fd.get('contact_email')})
      });
    }
    function submitUpload(ev) {
      ev.preventDefault();
      const fd = new FormData(ev.target);
      fetch('/api/upload', {method: 'POST', body: fd});
    }
    function quickUpload(ev) {
      const fd = new FormData();
      fd.append('tag', 'quick');
      fd.append('avatar', ev.target.files[0]);
      fetch('/api/quick-upload', {method: 'POST', body: fd});
    }
  </script>
</body>
</html>"""
            return 200, "text/html; charset=utf-8", html, {}
        if path == "/api/notes" and method == "POST":
            return 201, "application/json", json.dumps({"created": True}), {}
        if path in {"/api/upload", "/api/quick-upload"} and method == "POST":
            return 200, "application/json", json.dumps({"uploaded": True, "size": len(body)}), {}
        if path in {"/api/account/delete", "/api/logout"}:
            return 200, "application/json", json.dumps({"danger": True}), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_test_server(router) as (base_url, _port, log):
        http = _make_client(tmp_path, base_url=base_url, allowed_methods=("GET", "HEAD", "POST"), max_requests=120)
        seed_dir = tmp_path / "out"
        res = run_stage0_crawl(
            http,
            output_dir=seed_dir,
            allow_forms=True,
            max_pages=6,
            max_actions=10,
            wait_ms=250,
            max_passive_probes=0,
        )

        assert res["status"] == "ok"
        assert res["mode"] == "forms"
        assert res["stats"]["forms_submitted"] >= 2
        assert res["stats"]["uploads_triggered"] >= 2

        # Destructive endpoints must NEVER be hit.
        hit_paths = [urlsplit(r["path"]).path for r in log]
        assert "/api/account/delete" not in hit_paths
        assert "/api/logout" not in hit_paths

        # Exact body_templates and multipart_schemas captured
        assert "POST /api/notes" in res["body_templates"]
        assert res["body_templates"]["POST /api/notes"] == {
            "title": "qa-sample-value",
            "contact_email": "qa-crawl@example.test",
        }
        assert "POST /api/upload" in res["multipart_schemas"]
        assert res["multipart_schemas"]["POST /api/upload"] == {
            "fields": ["folder"],
            "files": ["file"],
        }
        assert "POST /api/quick-upload" in res["multipart_schemas"]
        assert res["multipart_schemas"]["POST /api/quick-upload"] == {
            "fields": ["tag"],
            "files": ["avatar"],
        }

        # stage0-seed.json written cleanly and matches returned dict
        seed_path = Path(res["seed_file"])
        assert seed_path == seed_dir / "stage0-seed.json"
        assert seed_path.is_file()
        loaded = json.loads(seed_path.read_text(encoding="utf-8"))
        assert loaded["schema"] == "stage0-seed/1"
        assert loaded["multipart_schemas"] == res["multipart_schemas"]
        assert loaded["body_templates"] == res["body_templates"]


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_fail_closed_downgrades_when_post_not_allowed(tmp_path: Path) -> None:
    def router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            html = """<!doctype html>
<html><body>
  <form action="/api/notes" method="POST">
    <input name="title" type="text" />
    <button type="submit">Save</button>
  </form>
</body></html>"""
            return 200, "text/html; charset=utf-8", html, {}
        return 404, "text/plain", "not found", {}

    with _start_test_server(router) as (base_url, _port, log):
        http = _make_client(tmp_path, base_url=base_url, allowed_methods=("GET",), max_requests=40)
        res = run_stage0_crawl(http, allow_forms=True, max_pages=4, wait_ms=200, max_passive_probes=0)

        assert res["mode"] == "readonly"
        assert res["stats"]["mode"] == "readonly"
        assert res["stats"]["forms_submitted"] == 0
        assert [r for r in log if r["method"] == "POST"] == []


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_dom_state_hashing_prevents_infinite_loops(tmp_path: Path) -> None:
    def router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        parsed = urlsplit(raw_path)
        page_num = 1
        if parsed.query.startswith("page="):
            try:
                page_num = int(parsed.query.split("=", 1)[1])
            except ValueError:
                page_num = 1
        next_page = page_num + 1
        html = f"""<!doctype html>
<html><body>
  <h1>Feed Page {page_num}</h1>
  <a href="/">Self Link</a>
  <a href="/feed?page={next_page}">Next Page {next_page}</a>
  <button role="tab" id="t1" aria-selected="true" onclick="toggleTab()">Tab A</button>
  <button role="tab" id="t2" aria-selected="false" onclick="toggleTab()">Tab B</button>
  <button type="button" id="noop" onclick="window.__ticks=(window.__ticks||0)+1">Noop Toggle</button>
  <script>
    function toggleTab() {{
      const a = document.getElementById('t1');
      const b = document.getElementById('t2');
      const aSel = a.getAttribute('aria-selected') === 'true';
      a.setAttribute('aria-selected', aSel ? 'false' : 'true');
      b.setAttribute('aria-selected', aSel ? 'true' : 'false');
    }}
  </script>
</body></html>"""
        return 200, "text/html; charset=utf-8", html, {}

    with _start_test_server(router) as (base_url, _port, _log):
        http = _make_client(tmp_path, base_url=base_url, allowed_methods=("GET",), max_requests=80)
        res = run_stage0_crawl(
            http,
            allow_forms=False,
            max_pages=5,
            max_actions=6,
            wait_ms=100,
            max_passive_probes=0,
        )

        assert res["status"] == "ok"
        assert res["stats"]["pages_visited"] <= 5
        assert res["stats"]["ui_actions_taken"] <= 6
        # Pagination /feed?page=1..N should be bounded by template visit cap & DOM hashing
        assert res["stats"]["pages_visited"] <= 3
        assert res["stats"]["dom_states_seen"] <= res["stats"]["pages_visited"] + res["stats"]["ui_actions_taken"]


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_scope_guard_blocks_off_origin_excluded_and_redacts_secrets(tmp_path: Path) -> None:
    secret_cookie = "sid_live_secret_99887766"
    secret_bearer = "bearer_live_secret_xyz987654"
    secret_ls = "ls_secret_token_alpha5544"

    def evil_router(_method: str, _raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        return 200, "text/plain", "evil", {}

    with _start_test_server(evil_router) as (evil_base_url, evil_port, evil_log):
        def target_router(_method: str, raw_path: str, hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
            path = urlsplit(raw_path).path
            if path == "/":
                html = f"""<!doctype html>
<html>
<head><title>Profile {secret_bearer}</title></head>
<body>
  <h1>Welcome {secret_cookie}</h1>
  <a href="/excluded/secret-area">Excluded Area</a>
  <a href="{evil_base_url}steal">Off Origin Link</a>
  <a href="/api/profile?ref={secret_ls}">Profile</a>
  <script>
    fetch('{evil_base_url}beacon');
    fetch('/excluded/api');
    fetch('/api/me');
    try {{ new WebSocket('ws://127.0.0.1:{evil_port}/ws/off-origin'); }} catch (e) {{}}
    try {{ new WebSocket('ws://' + window.location.host + '/ws/notifications'); }} catch (e) {{}}
  </script>
</body>
</html>"""
                return 200, "text/html; charset=utf-8", html, {}
            if path == "/api/me":
                return 200, "application/json", json.dumps({
                    "has_cookie": secret_cookie in hdrs.get("cookie", ""),
                    "has_auth": secret_bearer in hdrs.get("authorization", ""),
                }), {}
            if path == "/api/profile":
                return 200, "application/json", json.dumps({"token_echo": secret_ls}), {}
            return 404, "text/plain", "not found", {}

        with _start_test_server(target_router) as (base_url, target_port, target_log):
            http = _make_client(
                tmp_path,
                base_url=base_url,
                accounts=[
                    {
                        "alias": "alice",
                        "role": "member",
                        "cookie": f"sid={secret_cookie}",
                        "session_token": secret_bearer,
                        "local_storage": {"auth_state": secret_ls},
                    }
                ],
                allowed_methods=("GET", "HEAD", "POST"),
                max_requests=60,
                excluded_paths=("/excluded",),
            )
            seed_dir = tmp_path / "seed_out"
            res = run_stage0_crawl(
                http,
                output_dir=seed_dir,
                allow_forms=False,
                max_pages=6,
                max_actions=6,
                wait_ms=250,
                max_passive_probes=4,
            )

            # Off-origin HTTP/WS server must receive 0 hits
            assert evil_log == []
            # Excluded paths must NEVER be hit on target server
            target_paths = [urlsplit(r["path"]).path for r in target_log]
            assert not any(p.startswith("/excluded") for p in target_paths)

            # Verify auth headers & cookies were actually sent host-side to /api/me
            me_reqs = [r for r in target_log if urlsplit(r["path"]).path == "/api/me"]
            assert me_reqs
            assert secret_cookie in me_reqs[0]["headers"].get("cookie", "")
            assert secret_bearer in me_reqs[0]["headers"].get("authorization", "")

            # Verify same-origin WS recorded and off-origin WS rejected
            assert res["ws_endpoints"] == [
                {"url": f"ws://127.0.0.1:{target_port}/ws/notifications", "path": "/ws/notifications"}
            ]
            assert res["stats"]["ws_endpoints_found"] == 1

            # Verify NO actor secret appears anywhere in returned dict or stage0-seed.json
            serialized = json.dumps(res)
            seed_text = Path(res["seed_file"]).read_text(encoding="utf-8")
            for secret in (secret_cookie, secret_bearer, secret_ls):
                assert secret not in serialized
                assert secret not in seed_text

            # Verify Stage 0 did not drain the investigator's entire budget
            assert http.budget.used < http.budget.limit


def test_stage0_budget_exhausted_returns_cleanly(tmp_path: Path) -> None:
    http = _make_client(tmp_path, max_requests=1)
    allowed, _ = http.budget.consume()
    assert allowed is True

    res = run_stage0_crawl(http, allow_forms=False)
    assert res["schema"] == "stage0-seed/1"
    assert res["status"] == "budget_exhausted"
    assert res["stats"]["status"] == "budget_exhausted"
    assert res["stats"]["requests_charged"] == 0
    assert http.budget.used == 1


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_shadow_dom_and_session_drop_recovery(tmp_path: Path) -> None:
    def router(method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            html = """<!doctype html>
<html><body>
  <div id="host"></div>
  <script>
    const host = document.getElementById('host');
    const sr = host.attachShadow({mode: 'open'});
    sr.innerHTML = `
      <a href="/shadow-page">Shadow Link</a>
      <form id="f1" onsubmit="event.preventDefault(); fetch('/api/expire-session', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({step: 1})});">
        <input name="step" type="text" />
        <button type="submit">Trigger First</button>
      </form>
      <form id="f2" onsubmit="event.preventDefault(); fetch('/api/after-drop', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({step: 2})});">
        <input name="step2" type="text" />
        <button type="submit">Trigger Second</button>
      </form>
    `;
  </script>
</body></html>"""
            return 200, "text/html; charset=utf-8", html, {}
        if path == "/shadow-page":
            return 200, "text/html; charset=utf-8", "<html><body><h1>Shadow Page</h1></body></html>", {}
        if path == "/api/expire-session" and method == "POST":
            return 401, "application/json", json.dumps({"error": "expired"}), {}
        if path == "/api/after-drop" and method == "POST":
            return 200, "application/json", json.dumps({"ok": True}), {}
        return 404, "text/plain", "not found", {}

    with _start_test_server(router) as (base_url, _port, log):
        http = _make_client(
            tmp_path,
            base_url=base_url,
            accounts=[{"alias": "bob", "role": "member", "session_token": "bob_tok_abcdef1234"}],
            allowed_methods=("GET", "HEAD", "POST"),
            max_requests=60,
        )
        reauth_calls: list[tuple[str, bool]] = []

        def _fake_reauth(alias: str, *, force_login: bool = False) -> bool:
            reauth_calls.append((alias, force_login))
            return True

        setattr(http, "authenticate_actor", _fake_reauth)

        res = run_stage0_crawl(
            http,
            allow_forms=True,
            max_pages=4,
            max_actions=4,
            wait_ms=250,
            max_passive_probes=0,
        )

        assert res["status"] == "ok"
        all_routes = {(r["method"], r["url"]) for r in [*res["links"], *res["forms"]]}
        assert ("GET", "/shadow-page") in all_routes
        assert ("POST", "/api/expire-session") in all_routes
        # After 401 on first form, second form must NOT be submitted and reauth must be invoked
        hit_paths = [urlsplit(r["path"]).path for r in log]
        assert "/api/expire-session" in hit_paths
        assert "/api/after-drop" not in hit_paths
        assert reauth_calls == [("bob", True)]

