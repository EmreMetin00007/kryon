"""Unit and loopback integration tests for Faz 6A:
- Stage 0 `/api/`-prefixed OpenAPI/Swagger probing and proxy mount prefixing
- Safe internal canonical-host alias normalization for loopback/RFC1918 targets
"""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_stage0_crawl import (  # noqa: E402
    HAS_PLAYWRIGHT,
    _Stage0Budget,
    _Stage0Collector,
    _extract_openapi_templates,
    _run_layer4_passive_fusion,
    run_stage0_crawl,
)
from agentic_surface import (  # noqa: E402
    SurfaceFrontierTracker,
    apply_openapi_path_prefix,
    detect_internal_canonical_hosts,
    infer_openapi_mount_prefix,
    is_loopback_or_private_base_url,
    is_single_label_internal_host,
    rewrite_internal_canonical_url,
    rewrite_internal_canonical_urls_in_text,
)


def _make_client(
    tmp_path: Path,
    *,
    base_url: str = "http://127.0.0.1:18080/",
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST"),
    max_requests: int = 120,
) -> AgenticHTTPClient:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager([])
    return AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
    )


@contextmanager
def _start_test_server(
    router: Callable[[str, str, dict[str, str], bytes], tuple[int, str, bytes | str, dict[str, str]]],
) -> Iterator[tuple[str, int, list[dict[str, Any]]]]:
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

        def log_message(self, _fmt: str, *_args: Any) -> None:
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
# Unit tests: OpenAPI mount prefixing & single-label canonical host helpers
# ---------------------------------------------------------------------------


def test_openapi_mount_prefix_inference_and_no_double_prefixing() -> None:
    spec_no_servers = {
        "openapi": "3.0.3",
        "paths": {
            "/user/_query": {"post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"pageSize": {"type": "integer"}}}}}}}},
            "/role": {"get": {}},
            "/api/system/version": {"get": {}},
        },
    }
    assert infer_openapi_mount_prefix(spec_no_servers, "http://127.0.0.1:8080/api/v3/api-docs") == "/api"
    assert infer_openapi_mount_prefix(spec_no_servers, "http://127.0.0.1:8080/api/openapi.json") == "/api"
    assert infer_openapi_mount_prefix(spec_no_servers, "http://127.0.0.1:8080/api/swagger.json") == "/api"
    assert infer_openapi_mount_prefix(spec_no_servers, "http://127.0.0.1:8080/v3/api-docs") == ""

    spec_root_server = {
        "openapi": "3.0.3",
        "servers": [{"url": "http://127.0.0.1:8080"}],
        "paths": {"/user/_query": {"post": {}}},
    }
    assert infer_openapi_mount_prefix(spec_root_server, "http://127.0.0.1:8080/api/v3/api-docs") == "/api"

    spec_with_api_server = {
        "openapi": "3.0.3",
        "servers": [{"url": "/api"}],
        "paths": {"/user/_query": {"post": {}}},
    }
    assert infer_openapi_mount_prefix(spec_with_api_server, "http://127.0.0.1:8080/api/v3/api-docs") == "/api"

    assert apply_openapi_path_prefix("/user/_query", "/api") == "/api/user/_query"
    assert apply_openapi_path_prefix("/role", "/api") == "/api/role"
    assert apply_openapi_path_prefix("/api/system/version", "/api") == "/api/system/version"
    assert apply_openapi_path_prefix("/api", "/api") == "/api"
    assert apply_openapi_path_prefix("/user/_query", "") == "/user/_query"

    templates, _mp, ops = _extract_openapi_templates(spec_no_servers, path_prefix="/api")
    op_pairs = {(m, p) for m, p, _params in ops}
    assert ("POST", "/api/user/_query") in op_pairs
    assert ("GET", "/api/role") in op_pairs
    assert ("GET", "/api/system/version") in op_pairs
    assert ("GET", "/api/api/system/version") not in op_pairs
    assert ("POST", "/api/user/_query") in templates
    assert templates[("POST", "/api/user/_query")] == {"pageSize": 1}


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://127.0.0.1:8080/", True),
        ("http://localhost:3000/", True),
        ("http://[::1]:8000/", True),
        ("http://10.0.0.12:8080/", True),
        ("http://172.16.4.5/", True),
        ("http://172.31.255.254/", True),
        ("http://192.168.1.50:8080/", True),
        ("http://172.32.0.1/", False),
        ("http://169.254.169.254/", False),
        ("https://target.example.com/", False),
        ("http://8.8.8.8/", False),
        ("http://shopapp/", False),
    ],
)
def test_loopback_or_private_base_url_safety_gate(url: str, expected: bool) -> None:
    assert is_loopback_or_private_base_url(url) is expected


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("prestashop", True),
        ("shopapp", True),
        ("web-backend_1", True),
        ("localhost", False),
        ("example.org", False),
        ("google.com", False),
        ("cdn.site.com", False),
        ("sub.internal.local", False),
        ("127.0.0.1", False),
        ("::1", False),
        ("12345", False),
        ("0x7f000001", False),
        ("-invalid", False),
        ("", False),
    ],
)
def test_single_label_internal_host_validator(host: str, expected: bool) -> None:
    assert is_single_label_internal_host(host) is expected


def test_detect_and_rewrite_internal_canonical_hosts_positive_and_negative_safety() -> None:
    base_loopback = "http://127.0.0.1:18080/"
    html_canonical = """<!doctype html>
<html>
<head>
  <link rel="canonical" href="http://shopapp/">
  <link rel="stylesheet" href="https://cdn.example.org/app.css">
</head>
<body>
  <a href="http://shopapp/login">Login</a>
  <form action="//shopapp/search" method="GET"><input name="q"></form>
  <a href="https://example.org/out">External</a>
</body>
</html>"""

    hosts = detect_internal_canonical_hosts(html_canonical, base_url=base_loopback)
    assert hosts == {"shopapp"}

    # Dominant >= 3 links/forms detection (no canonical/base tag)
    html_dominant = """<html><body>
      <a href="http://cmsapp/a">A</a>
      <a href="http://cmsapp/b">B</a>
      <form action="//cmsapp/search"></form>
      <a href="https://evil.com/1">1</a>
      <a href="https://evil.com/2">2</a>
      <a href="https://evil.com/3">3</a>
      <a href="http://sub.internal.local/1">L1</a>
      <a href="http://sub.internal.local/2">L2</a>
      <a href="http://sub.internal.local/3">L3</a>
    </body></html>"""
    assert detect_internal_canonical_hosts(html_dominant, base_url=base_loopback) == {"cmsapp"}

    # Location header detection
    assert detect_internal_canonical_hosts(
        "",
        base_url=base_loopback,
        location_header="http://prestashop/index.php?controller=authentication",
    ) == {"prestashop"}
    assert detect_internal_canonical_hosts(
        "",
        base_url=base_loopback,
        location_header="https://evil.com/phish",
    ) == set()

    # Rewriting behavior
    assert (
        rewrite_internal_canonical_url(
            "http://shopapp/login?next=/cart",
            base_url=base_loopback,
            canonical_hosts={"shopapp"},
        )
        == "http://127.0.0.1:18080/login?next=/cart"
    )
    assert (
        rewrite_internal_canonical_url(
            "//shopapp/search?q=shoes",
            base_url=base_loopback,
            canonical_hosts={"shopapp"},
        )
        == "http://127.0.0.1:18080/search?q=shoes"
    )
    assert (
        rewrite_internal_canonical_url(
            "https://shopapp:8443/products",
            base_url=base_loopback,
            canonical_hosts={"shopapp"},
        )
        == "http://127.0.0.1:18080/products"
    )

    # Strict negative safety: non-loopback public base_url NEVER detects or rewrites
    public_base = "https://target.example.com/"
    assert detect_internal_canonical_hosts(
        html_canonical,
        base_url=public_base,
        location_header="http://shopapp/login",
    ) == set()
    assert (
        rewrite_internal_canonical_url(
            "http://shopapp/login",
            base_url=public_base,
            canonical_hosts={"shopapp"},
        )
        == "http://shopapp/login"
    )
    assert (
        rewrite_internal_canonical_urls_in_text(
            html_canonical,
            base_url=public_base,
            canonical_hosts={"shopapp"},
        )
        == html_canonical
    )

    # Strict negative safety: dotted external domains are NEVER rewritten even if passed directly
    assert (
        rewrite_internal_canonical_url(
            "https://example.org/out",
            base_url=base_loopback,
            canonical_hosts={"shopapp", "example.org", "sub.internal.local"},
        )
        == "https://example.org/out"
    )
    assert (
        rewrite_internal_canonical_url(
            "http://sub.internal.local/admin",
            base_url=base_loopback,
            canonical_hosts={"sub.internal.local"},
        )
        == "http://sub.internal.local/admin"
    )
    rewritten_text = rewrite_internal_canonical_urls_in_text(
        '<a href="http://shopapp/login"></a><a href="http://shopapp.example.org/x"></a><a href="https://example.org/out"></a>',
        base_url=base_loopback,
        canonical_hosts={"shopapp", "example.org"},
    )
    assert 'href="http://127.0.0.1:18080/login"' in rewritten_text
    assert 'href="http://shopapp.example.org/x"' in rewritten_text
    assert 'href="https://example.org/out"' in rewritten_text


def test_surface_frontier_tracker_canonical_host_and_proxied_openapi_receipts() -> None:
    base_url = "http://127.0.0.1:18080/"
    tracker = SurfaceFrontierTracker(base_url=base_url, allowed_methods=("GET", "HEAD", "POST"))

    # 1. HTML + Location redirect using internal single-label host `shopapp`
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": base_url,
        "status": 200,
        "content_type": "text/html; charset=utf-8",
        "redirect_location": "http://shopapp/dashboard",
        "body": (
            '<!doctype html><html><head><link rel="canonical" href="http://shopapp/"></head>'
            '<body>'
            '<a href="http://shopapp/login">Login</a>'
            '<a href="http://shopapp/register">Register</a>'
            '<a href="http://shopapp/products">Products</a>'
            '<form action="//shopapp/search" method="GET"><input name="q" type="text"></form>'
            '<a href="https://example.org/out">External</a>'
            '<a href="http://sub.internal.local/secret">Dotted</a>'
            '</body></html>'
        ),
    })

    assert tracker.internal_canonical_hosts == {"shopapp"}
    assert ("GET", "/dashboard") in tracker.discovered_routes
    assert ("GET", "/login") in tracker.discovered_routes
    assert ("GET", "/register") in tracker.discovered_routes
    assert ("GET", "/products") in tracker.discovered_routes
    assert ("GET", "/search") in tracker.discovered_routes
    assert "q" in tracker.discovered_params.get("/search", set())
    assert ("GET", "/out") not in tracker.discovered_routes
    assert ("GET", "/secret") not in tracker.discovered_routes

    # 2. Proxied OpenAPI spec at /api/v3/api-docs
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": f"{base_url}api/v3/api-docs",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({
            "openapi": "3.0.1",
            "paths": {
                "/user/_query": {"post": {}},
                "/role": {"get": {}},
                "/api/system/version": {"get": {}},
            },
        }),
    })
    assert ("POST", "/api/user/_query") in tracker.discovered_routes
    assert ("GET", "/api/role") in tracker.discovered_routes
    assert ("GET", "/api/system/version") in tracker.discovered_routes
    assert ("GET", "/api/api/system/version") not in tracker.discovered_routes

    # 3. Public non-loopback tracker NEVER rewrites single-label hosts
    pub_tracker = SurfaceFrontierTracker(
        base_url="https://target.example.com/",
        allowed_methods=("GET", "HEAD", "POST"),
    )
    pub_tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "https://target.example.com/",
        "status": 200,
        "content_type": "text/html",
        "redirect_location": "http://shopapp/login",
        "body": (
            '<html><head><link rel="canonical" href="http://shopapp/"></head>'
            '<body><a href="http://shopapp/login">L</a><a href="http://shopapp/products">P</a>'
            '<a href="http://shopapp/register">R</a><form action="//shopapp/search"></form></body></html>'
        ),
    })
    assert pub_tracker.internal_canonical_hosts == set()
    assert ("GET", "/login") not in pub_tracker.discovered_routes
    assert ("GET", "/search") not in pub_tracker.discovered_routes


# ---------------------------------------------------------------------------
# Loopback integration tests (Layer 4 + full Playwright Stage 0)
# ---------------------------------------------------------------------------


def test_layer4_probes_api_prefixed_openapi_and_avoids_double_prefix(tmp_path: Path) -> None:
    openapi_doc = {
        "openapi": "3.0.3",
        "info": {"title": "Proxied Backend", "version": "1.0"},
        "paths": {
            "/user/_query": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "pageIndex": {"type": "integer"},
                                        "terms": {"type": "string"},
                                    },
                                }
                            }
                        }
                    }
                }
            },
            "/role": {"get": {"parameters": [{"name": "status", "in": "query"}]}},
            "/api/system/version": {"get": {}},
        },
    }

    def router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/api/v3/api-docs":
            return 200, "application/json", json.dumps(openapi_doc), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_test_server(router) as (base_url, _port, log):
        http = _make_client(tmp_path, base_url=base_url, allowed_methods=("GET", "HEAD", "POST"), max_requests=60)
        collector = _Stage0Collector(http)
        budget = _Stage0Budget(http, cap=20, reserve=8)

        _run_layer4_passive_fusion(
            http,
            collector,
            budget,
            primary_actor="anon",
            max_passive_probes=12,
        )

        hit_paths = [urlsplit(r["path"]).path for r in log]
        assert "/v3/api-docs" in hit_paths
        assert "/api/v3/api-docs" in hit_paths
        # Once /api/v3/api-docs succeeded, remaining /api/ spec probes are skipped.
        assert "/api/openapi.json" not in hit_paths
        assert "/api/swagger.json" not in hit_paths

        assert ("POST", "/api/user/_query") in collector.routes
        assert ("GET", "/api/role") in collector.routes
        assert ("GET", "/api/system/version") in collector.routes
        # Never unprefixed broken backend paths or double-prefixed /api/api/...
        assert ("POST", "/user/_query") not in collector.routes
        assert ("GET", "/role") not in collector.routes
        assert ("GET", "/api/api/system/version") not in collector.routes
        assert collector.routes[("POST", "/api/user/_query")].body_template == {
            "pageIndex": 1,
            "terms": "sample",
        }
        assert "status" in collector.routes[("GET", "/api/role")].params


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_discovers_api_prefixed_openapi_spec_on_loopback(tmp_path: Path) -> None:
    openapi_doc = {
        "openapi": "3.0.1",
        "info": {"title": "Reverse Proxied SPA API", "version": "1.0"},
        "paths": {
            "/user/_query": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"keyword": {"type": "string"}},
                                }
                            }
                        }
                    }
                }
            },
            "/role": {"get": {}},
            "/api/system/version": {"get": {}},
        },
    }

    def router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            return (
                200,
                "text/html; charset=utf-8",
                "<!doctype html><html><body><h1>SPA Shell</h1><script>fetch('/api/health');</script></body></html>",
                {},
            )
        if path == "/api/health":
            return 200, "application/json", json.dumps({"ok": True}), {}
        if path == "/api/v3/api-docs":
            return 200, "application/json", json.dumps(openapi_doc), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_test_server(router) as (base_url, _port, log):
        http = _make_client(tmp_path, base_url=base_url, allowed_methods=("GET", "HEAD", "POST"), max_requests=120)
        res = run_stage0_crawl(
            http,
            allow_forms=False,
            max_pages=6,
            max_actions=4,
            wait_ms=200,
            max_passive_probes=12,
        )

        assert res["status"] == "ok"
        hit_paths = [urlsplit(r["path"]).path for r in log]
        assert "/v3/api-docs" in hit_paths
        assert "/api/v3/api-docs" in hit_paths

        all_routes = {(r["method"], r["url"]) for r in [*res["links"], *res["forms"]]}
        assert ("POST", "/api/user/_query") in all_routes
        assert ("GET", "/api/role") in all_routes
        assert ("GET", "/api/system/version") in all_routes
        assert ("POST", "/user/_query") not in all_routes
        assert ("GET", "/api/api/system/version") not in all_routes
        assert res["body_templates"].get("POST /api/user/_query") == {"keyword": "sample"}


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_canonical_host_alias_crawls_internal_links_and_blocks_external(tmp_path: Path) -> None:
    def router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            html = """<!doctype html>
<html>
<head>
  <title>ShopApp</title>
  <link rel="canonical" href="http://shopapp/">
</head>
<body>
  <h1>Welcome to ShopApp</h1>
  <nav>
    <a href="http://shopapp/login">Login</a>
    <a href="http://shopapp/register">Register</a>
    <a href="http://shopapp/products">Products</a>
    <a href="https://example.org/out">External Site</a>
  </nav>
  <form action="//shopapp/search" method="GET">
    <input name="q" type="text" />
    <button type="submit">Search</button>
  </form>
</body>
</html>"""
            return 200, "text/html; charset=utf-8", html, {}
        if path == "/login":
            return (
                200,
                "text/html; charset=utf-8",
                '<html><body><h1>Login</h1><a href="http://shopapp/forgot-password">Forgot</a></body></html>',
                {},
            )
        if path == "/register":
            return 200, "text/html; charset=utf-8", "<html><body><h1>Register</h1></body></html>", {}
        if path == "/products":
            return 200, "text/html; charset=utf-8", "<html><body><h1>Products</h1></body></html>", {}
        if path == "/search":
            return 200, "text/html; charset=utf-8", "<html><body><h1>Search Results</h1></body></html>", {}
        if path == "/forgot-password":
            return 200, "text/html; charset=utf-8", "<html><body><h1>Reset Password</h1></body></html>", {}
        return 404, "text/plain", "not found", {}

    with _start_test_server(router) as (base_url, _port, log):
        http = _make_client(tmp_path, base_url=base_url, allowed_methods=("GET", "HEAD", "POST"), max_requests=120)
        res = run_stage0_crawl(
            http,
            allow_forms=False,
            max_pages=10,
            max_actions=4,
            wait_ms=150,
            max_passive_probes=0,
        )

        assert res["status"] == "ok"
        crawled_paths = {urlsplit(r["path"]).path for r in log}
        assert "/login" in crawled_paths
        assert "/register" in crawled_paths
        assert "/products" in crawled_paths
        assert "/search" in crawled_paths
        assert "/forgot-password" in crawled_paths
        assert res["stats"]["pages_visited"] >= 5

        all_routes = {(r["method"], r["url"]) for r in [*res["links"], *res["forms"]]}
        assert ("GET", "/login") in all_routes
        assert ("GET", "/register") in all_routes
        assert ("GET", "/products") in all_routes
        assert ("GET", "/search") in all_routes
        assert ("GET", "/forgot-password") in all_routes
        # External example.org link must NEVER be accepted or crawled
        assert ("GET", "/out") not in all_routes
        assert not any("example.org" in json.dumps(r) for r in [*res["links"], *res["forms"]])

        # Verify SurfaceFrontierTracker seamlessly ingests the resulting seed
        tracker = SurfaceFrontierTracker(base_url=base_url, allowed_methods=("GET", "HEAD", "POST"))
        tracker.ingest_surface(res, actor="stage0")
        assert ("GET", "/login") in tracker.discovered_routes
        assert ("GET", "/search") in tracker.discovered_routes
        assert ("GET", "/out") not in tracker.discovered_routes
