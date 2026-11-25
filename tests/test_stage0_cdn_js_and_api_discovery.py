"""Tests for Stage 0 CDN JS bundle analysis, cross-origin API discovery, and SEO route caps."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from types import SimpleNamespace
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit, urlunsplit

import pytest

import agentic_stage0_crawl
from agentic_stage0_crawl import (
    HAS_PLAYWRIGHT,
    _MAX_STAGE0_CDN_SCRIPT_ASSETS,
    _Stage0Budget,
    _Stage0Collector,
    _classify_seo_route_pattern,
    _crawl_actor_playwright,
    _finalize_routes,
    _is_allowed_cdn_script_url,
    _run_layer4_passive_fusion,
    run_stage0_crawl,
)
from agentic_http import ActorManager, AgenticHTTPClient, ScopeViolationError
from agentic_receipts import ReceiptStore


def _make_client(
    tmp_path: Path,
    *,
    base_url: str = "https://www.pazarama.com/",
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST"),
    max_requests: int = 120,
    excluded_paths: tuple[str, ...] = (),
    global_headers: dict[str, str] | None = None,
) -> AgenticHTTPClient:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager(accounts or [], global_headers=global_headers)
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
# 1. _is_allowed_cdn_script_url safety & tracker filtering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("req_url", "req"),
    [
        ("https://js.pzrmcdn.com/asset/_pzweb/app.js", None),
        ("https://js.pzrmcdn.com/asset/_pzweb/chunk-12ab.mjs?v=2", SimpleNamespace(method="GET", resource_type="script")),
        ("https://cdn.example.com/bundle?name=main", SimpleNamespace(method="GET", resource_type="script")),
        ("https://static.shopcdn.net/assets/js/vendor.js", SimpleNamespace(method="GET", resource_type="other")),
    ],
)
def test_is_allowed_cdn_script_url_allows_legitimate_cdn_js(req_url: str, req: Any) -> None:
    assert _is_allowed_cdn_script_url(req_url, "https://www.pazarama.com/", req) is True


@pytest.mark.parametrize(
    "tracker_url",
    [
        "https://www.googletagmanager.com/gtag/js?id=G-12345",
        "https://www.google-analytics.com/analytics.js",
        "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
        "https://securepubads.g.doubleclick.net/tag/js/gpt.js",
        "https://connect.facebook.net/en_US/fbevents.js",
        "https://www.facebook.com/tr.js",
        "https://static.hotjar.com/c/hotjar-123.js",
        "https://www.clarity.ms/tag/abc.js",
        "https://cdn.mixpanel.com/mixpanel.js",
        "https://cdn.segment.com/analytics.js/v1/key/analytics.min.js",
        "https://js.sentry.io/bundle.min.js",
        "https://browser.sentry-cdn.com/7.0.0/bundle.min.js",
        "https://www.datadoghq.com/datadog-rum.js",
        "https://js-agent.newrelic.com/nr-loader.min.js",
        "https://analytics.tiktok.com/i18n/pixel/events.js",
        "https://platform.twitter.com/widgets.js",
        "https://snap.licdn.com/li.lms-analytics/insight.min.js",
        "https://platform.linkedin.com/in.js",
        "https://bat.bing.com/bat.js",
        "https://mc.yandex.ru/metrika/tag.js",
        "https://static.criteo.net/js/ld/ld.js",
        "https://www.criteo.com/js/ld.js",
        "https://api.insider.com/ins.js",
        "https://hit.api.useinsider.com/ins.js",
        "https://cdn.onesignal.com/sdks/OneSignalSDK.js",
        "https://static.zdassets.com/ekr/snippet.js",
        "https://widget.zendesk.com/embeddable.js",
        "https://widget.intercom.io/widget/abc",
        "https://www.recaptcha.net/recaptcha/api.js",
        "https://www.gstatic.com/recaptcha/releases/v1/recaptcha__en.js",
        "https://js.hcaptcha.com/1/api.js",
        "https://challenges.cloudflare.com/turnstile/v0/api.js",
    ],
)
def test_is_allowed_cdn_script_url_blocks_trackers_and_telemetry(tracker_url: str) -> None:
    req = SimpleNamespace(method="GET", resource_type="script")
    assert _is_allowed_cdn_script_url(tracker_url, "https://www.pazarama.com/", req) is False


@pytest.mark.parametrize(
    ("bad_url", "req"),
    [
        # Non-GET methods strictly blocked
        ("https://js.pzrmcdn.com/asset/_pzweb/app.js", SimpleNamespace(method="POST", resource_type="script")),
        ("https://js.pzrmcdn.com/asset/_pzweb/app.js", SimpleNamespace(method="HEAD", resource_type="script")),
        ("https://js.pzrmcdn.com/asset/_pzweb/app.js", SimpleNamespace(method="PUT", resource_type="script")),
        # SSRF pivots to loopback / private / link-local / metadata / internal hosts
        ("http://127.0.0.1/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://127.0.0.1:8080/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://localhost/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://sub.localhost/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://169.254.169.254/latest.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://10.0.0.1/internal.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://172.16.0.1/internal.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://192.168.1.1/router.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://100.64.0.1/cgnat.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://[::1]/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://[::ffff:127.0.0.1]/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://2130706433/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://0x7f000001/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://metadata.google.internal/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("http://internal-service/app.js", SimpleNamespace(method="GET", resource_type="script")),
        # Embedded credentials / non-HTTP schemes / same-origin / non-script types
        ("https://user:pass@js.pzrmcdn.com/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("ftp://js.pzrmcdn.com/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("javascript:alert(1)", None),
        ("//js.pzrmcdn.com/app.js", None),
        ("https://www.pazarama.com/assets/app.js", SimpleNamespace(method="GET", resource_type="script")),
        ("https://js.pzrmcdn.com/asset/_pzweb/app.js", SimpleNamespace(method="GET", resource_type="document")),
        ("https://js.pzrmcdn.com/download.js?file=secret", SimpleNamespace(method="GET", resource_type="fetch")),
        ("https://js.pzrmcdn.com/api/v1/plugin.js", SimpleNamespace(method="GET", resource_type="other")),
        ("https://js.pzrmcdn.com/hero.png", SimpleNamespace(method="GET", resource_type="image")),
    ],
)
def test_is_allowed_cdn_script_url_blocks_ssrf_non_get_and_non_scripts(bad_url: str, req: Any) -> None:
    assert _is_allowed_cdn_script_url(bad_url, "https://www.pazarama.com/", req) is False


def test_is_allowed_cdn_script_url_still_blocks_metadata_ip_on_loopback_target() -> None:
    assert _is_allowed_cdn_script_url(
        "http://169.254.169.254/latest.js",
        "http://127.0.0.1:18080/",
        SimpleNamespace(method="GET", resource_type="script"),
    ) is False
    assert _is_allowed_cdn_script_url(
        "http://127.0.0.1:19090/asset/_pzweb/app.js",
        "http://127.0.0.1:18080/",
        SimpleNamespace(method="GET", resource_type="script"),
    ) is True


# ---------------------------------------------------------------------------
# 2. Simulated Playwright _on_route + _on_response + Layer 4 CDN JS & API discovery
# ---------------------------------------------------------------------------


def test_simulated_playwright_cdn_js_strips_auth_parses_routes_and_records_api_hosts(
    tmp_path: Path,
) -> None:
    secret_cookie = "sid=secret_session_cookie_9988"
    secret_bearer = "Bearer secret_jwt_token_xyz123"
    secret_api_key = "secret_api_key_abc"
    secret_csrf = "secret_csrf_token_def"
    secret_actor_hdr = "secret_custom_actor_hdr_ghi"

    http = _make_client(
        tmp_path,
        base_url="https://www.pazarama.com/",
        accounts=[
            {
                "alias": "alice",
                "role": "member",
                "cookie": secret_cookie,
                "session_token": "secret_jwt_token_xyz123",
                "auth_header_name": "X-Custom-Actor-Auth",
                "headers": {
                    "X-Custom-Actor-Auth": secret_actor_hdr,
                    "X-API-Key": secret_api_key,
                },
            }
        ],
        global_headers={"Pentest": "Cyberbounty"},
        excluded_paths=("/excluded",),
    )

    cdn_js_body = """
export async function submitCheckout(cartId) {
  const ordersPage = "/hesabim/orders";
  await fetch("/api/v1/checkout", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({cartId: cartId, coupon: "SAVE10"})
  });
  await fetch("https://bff.example.com/api/v1/cart", {method: "POST"});
  await fetch("https://www.google-analytics.com/g/collect");
  return ordersPage;
}
"""

    continued_routes: list[tuple[str, dict[str, str] | None]] = []
    aborted_urls: list[str] = []

    class _FakeRoute:
        def __init__(self, url: str, *, method: str = "GET", resource_type: str = "other", headers: dict[str, str] | None = None) -> None:
            self.request = SimpleNamespace(
                url=url,
                method=method,
                resource_type=resource_type,
                headers=dict(headers or {}),
                all_headers=lambda: dict(headers or {}),
            )

        def continue_(self, **kwargs: Any) -> None:
            continued_routes.append((self.request.url, kwargs.get("headers")))

        def abort(self, _reason: str = "failed") -> None:
            aborted_urls.append(self.request.url)

    class _FakePage:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}
            self.url = "https://www.pazarama.com/"

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

        def goto(self, url: str, **_kwargs: Any) -> None:
            self.url = url

        def wait_for_timeout(self, _ms: int) -> None:
            return

        def evaluate(self, _script: str, *_args: Any) -> dict[str, Any]:
            return {
                "pathname": "/",
                "hash": "",
                "dialog_count": 0,
                "headings": [{"tag": "h1", "text": "Store"}],
                "forms": [],
                "standalone_files": [],
                "controls": [],
                "links": [],
                "canonical_links": [],
                "hash_routes": [],
                "visible_links": [],
                "base_uri": "https://www.pazarama.com/",
            }

    class _FakeContext:
        def __init__(self) -> None:
            self.route_handler: Any = None
            self.page = _FakePage()

        def add_init_script(self, _script: str) -> None:
            return

        def add_cookies(self, _cookies: Any) -> None:
            return

        def route(self, _pattern: str, handler: Any) -> None:
            self.route_handler = handler

        def new_page(self) -> _FakePage:
            return self.page

        def close(self) -> None:
            return

    fake_ctx = _FakeContext()

    class _FakeBrowser:
        def new_context(self, **_kwargs: Any) -> _FakeContext:
            return fake_ctx

    collector = _Stage0Collector(http)
    budget = _Stage0Budget(http, cap=20, reserve=4)

    # Simulate _crawl_actor_playwright wiring handlers, then drive _on_route and _on_response.
    def _drive_crawl_and_events() -> list[str]:
        class _DrivingPage(_FakePage):
            def goto(self, url: str, **_kwargs: Any) -> None:
                self.url = url
                rh = fake_ctx.route_handler
                assert rh is not None

                # 1. Legitimate CDN JS request carrying auth/session headers that MUST be stripped.
                cdn_req_headers = {
                    "Accept": "*/*",
                    "Authorization": secret_bearer,
                    "Cookie": secret_cookie,
                    "X-API-Key": secret_api_key,
                    "X-CSRF-Token": secret_csrf,
                    "X-CSRFToken": secret_csrf,
                    "X-XSRF-TOKEN": secret_csrf,
                    "X-Custom-Actor-Auth": secret_actor_hdr,
                }
                cdn_route = _FakeRoute(
                    "https://js.pzrmcdn.com/asset/_pzweb/app.js",
                    method="GET",
                    resource_type="script",
                    headers=cdn_req_headers,
                )
                rh(cdn_route)

                # Simulate _on_response delivering the CDN JS chunk body.
                resp_handler = self.handlers["response"]
                resp_handler(
                    SimpleNamespace(
                        url="https://js.pzrmcdn.com/asset/_pzweb/app.js",
                        status=200,
                        request=cdn_route.request,
                        headers={"content-type": "application/javascript; charset=utf-8"},
                        body=lambda: cdn_js_body.encode("utf-8"),
                    )
                )

                # 2. Tracker JS request MUST be aborted without continuing.
                rh(
                    _FakeRoute(
                        "https://www.googletagmanager.com/gtag/js?id=G-999",
                        method="GET",
                        resource_type="script",
                    )
                )

                # 3. Out-of-scope XHR/fetch to sibling API MUST be aborted AND recorded in discovered_api_hosts.
                rh(
                    _FakeRoute(
                        "https://bff.example.com/v1/cart",
                        method="GET",
                        resource_type="fetch",
                    )
                )
                # 4. Out-of-scope tracker beacon MUST be aborted and IGNORED in discovered_api_hosts.
                rh(
                    _FakeRoute(
                        "https://www.google-analytics.com/g/collect",
                        method="POST",
                        resource_type="fetch",
                    )
                )
                # 5. Same-origin excluded path MUST be aborted and NOT recorded in discovered_api_hosts.
                rh(
                    _FakeRoute(
                        "https://www.pazarama.com/excluded/api",
                        method="GET",
                        resource_type="xhr",
                    )
                )
                # 6. Cap enforcement: extra CDN JS chunks beyond _MAX_STAGE0_CDN_SCRIPT_ASSETS get aborted.
                for idx in range(_MAX_STAGE0_CDN_SCRIPT_ASSETS + 2):
                    rh(
                        _FakeRoute(
                            f"https://js.pzrmcdn.com/asset/_pzweb/chunk-{idx}.js",
                            method="GET",
                            resource_type="script",
                        )
                    )

        fake_ctx.page = _DrivingPage()
        return _crawl_actor_playwright(
            http,
            collector,
            budget,
            browser=_FakeBrowser(),
            actor="alice",
            start_urls=["https://www.pazarama.com/"],
            forms_enabled=False,
            actor_page_limit=1,
            actor_action_limit=0,
            timeout_ms=2000,
            wait_ms=0,
        )

    secrets = _drive_crawl_and_events()
    _run_layer4_passive_fusion(
        http,
        collector,
        budget,
        primary_actor="alice",
        max_passive_probes=0,
    )
    links, forms, _bt, _mp, _hints = _finalize_routes(collector)
    discovered_api_hosts = collector.export_discovered_api_hosts()
    http.close()

    # (a) Verify CDN JS route continued with ALL auth/session headers strictly stripped
    cdn_continued = [hdrs for url, hdrs in continued_routes if url == "https://js.pzrmcdn.com/asset/_pzweb/app.js"]
    assert len(cdn_continued) == 1
    sent_hdrs = cdn_continued[0]
    assert sent_hdrs is not None
    low_sent = {k.lower(): v for k, v in sent_hdrs.items()}
    for forbidden_hdr in (
        "authorization",
        "cookie",
        "x-api-key",
        "x-csrf-token",
        "x-csrftoken",
        "x-xsrf-token",
        "x-custom-actor-auth",
    ):
        assert forbidden_hdr not in low_sent
    assert low_sent.get("accept") == "*/*"
    assert low_sent.get("pentest") == "Cyberbounty"

    # Tracker, API, excluded, and overflow CDN JS routes were aborted
    assert "https://www.googletagmanager.com/gtag/js?id=G-999" in aborted_urls
    assert "https://bff.example.com/v1/cart" in aborted_urls
    assert "https://www.google-analytics.com/g/collect" in aborted_urls
    assert "https://www.pazarama.com/excluded/api" in aborted_urls
    assert f"https://js.pzrmcdn.com/asset/_pzweb/chunk-{_MAX_STAGE0_CDN_SCRIPT_ASSETS}.js" in aborted_urls
    assert len(collector.cdn_script_assets_seen) == _MAX_STAGE0_CDN_SCRIPT_ASSETS

    # (b) Verify CDN JS body was captured and parsed in Layer 4
    assert collector.js_chunks_parsed >= 1
    assert collector.cdn_js_chunks_parsed >= 1

    # (c) Verify relative routes inside CDN JS resolved against target base_url
    route_pairs = {(r["method"], r["url"]) for r in [*links, *forms]}
    assert ("POST", "/api/v1/checkout") in route_pairs
    assert ("GET", "/hesabim/orders") in route_pairs
    # CDN JS URL itself must NOT pollute target routes
    assert not any("js.pzrmcdn.com" in r["url"] for r in [*links, *forms])

    # (d) Verify out-of-scope API hosts were recorded while trackers & same-origin excluded paths were ignored
    api_by_origin = {item["origin"]: item for item in discovered_api_hosts}
    assert "https://bff.example.com" in api_by_origin
    assert "/v1/cart" in api_by_origin["https://bff.example.com"]["sample_paths"]
    assert "/api/v1/cart" in api_by_origin["https://bff.example.com"]["sample_paths"]
    assert set(api_by_origin["https://bff.example.com"]["methods"]) >= {"GET", "POST"}
    assert not any("google-analytics.com" in origin for origin in api_by_origin)
    assert not any("googletagmanager.com" in origin for origin in api_by_origin)
    assert not any("pazarama.com" in origin for origin in api_by_origin)

    # Verify secrets list is populated for redaction
    assert any("secret_jwt_token_xyz123" in s for s in secrets)


# ---------------------------------------------------------------------------
# 3. Layer 4 HTML/SSR config discovery + multi-origin scope route acceptance
# ---------------------------------------------------------------------------


def test_layer4_scans_ssr_html_for_sibling_api_hosts_and_accepts_multi_origin_routes(
    tmp_path: Path,
) -> None:
    http = _make_client(tmp_path, base_url="https://www.pazarama.com/")
    collector = _Stage0Collector(http)
    budget = _Stage0Budget(http, cap=10, reserve=2)

    ssr_html = """<!doctype html>
<html>
<head>
  <link rel="preconnect" href="https://img.pazarama.com" />
  <script>
    window.__NUXT__ = {
      config: {
        public: {
          bffUrl: "https://bff.pazarama.com",
          sfApiUrl: "https://sfapi.pazarama.com/v1/catalog",
          authOrigin: "https://auth.pazarama.com/oauth/token",
          tracker: "https://www.googletagmanager.com/gtag/js"
        }
      }
    };
  </script>
</head>
<body>
  <img src="https://img.pazarama.com/banner.jpg" />
  <a href="https://www.google-analytics.com/g/collect">ga</a>
  <a href="/hesabim/orders">Orders</a>
</body>
</html>"""

    collector.record_document(
        url="https://www.pazarama.com/",
        content_type="text/html; charset=utf-8",
        body=ssr_html,
        headers={},
        is_js=False,
    )
    _run_layer4_passive_fusion(http, collector, budget, primary_actor="anon", max_passive_probes=0)
    hosts = collector.export_discovered_api_hosts()
    origins = {h["origin"]: h for h in hosts}
    http.close()

    assert "https://bff.pazarama.com" in origins
    assert "https://sfapi.pazarama.com" in origins
    assert "https://auth.pazarama.com" in origins
    assert origins["https://bff.pazarama.com"]["same_registrable_domain"] is True
    assert "/v1/catalog" in origins["https://sfapi.pazarama.com"]["sample_paths"]
    assert "/oauth/token" in origins["https://auth.pazarama.com"]["sample_paths"]
    assert "https://img.pazarama.com" not in origins
    assert "https://www.googletagmanager.com" not in origins
    assert "https://www.google-analytics.com" not in origins

    # Multi-origin scope seamlessly accepts sibling API routes extracted from CDN JS chunks.
    multi_http = _make_client(tmp_path / "multi", base_url="https://www.pazarama.com/")
    allowed_origins = {
        ("https", "www.pazarama.com", 443),
        ("https", "bff.pazarama.com", 443),
    }

    def _multi_resolve_in_scope(
        raw_url: str,
        *,
        allow_websocket: bool = True,
        allow_lifecycle_routes: bool | None = None,
    ) -> tuple[str, str, str]:
        _ = (allow_websocket, allow_lifecycle_routes)
        parsed = urlsplit(raw_url)
        if not parsed.scheme and not parsed.netloc:
            parsed = urlsplit(f"https://www.pazarama.com{raw_url if raw_url.startswith('/') else '/' + raw_url}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (parsed.scheme, (parsed.hostname or "").lower(), port) not in allowed_origins:
            raise ScopeViolationError(f"out of scope: {raw_url}")
        clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        return clean, parsed.path or "/", parsed.query

    multi_http.resolve_in_scope = _multi_resolve_in_scope  # type: ignore[method-assign]
    multi_http._check_scope = lambda _u: True  # type: ignore[attr-defined]
    multi_collector = _Stage0Collector(multi_http)
    multi_budget = _Stage0Budget(multi_http, cap=10, reserve=2)
    multi_collector.record_document(
        url="https://js.pzrmcdn.com/asset/_pzweb/checkout.js",
        content_type="application/javascript",
        body='fetch("/api/v1/orders");\nfetch("https://bff.pazarama.com/api/v1/cart", {method: "POST"});\n',
        headers={},
        is_js=True,
        is_cdn_js=True,
    )
    _run_layer4_passive_fusion(multi_http, multi_collector, multi_budget, primary_actor="anon", max_passive_probes=0)
    m_links, m_forms, _bt, _mp, _hints = _finalize_routes(multi_collector)
    m_pairs = {(r["method"], r["url"]) for r in [*m_links, *m_forms]}
    multi_hosts = {h["origin"] for h in multi_collector.export_discovered_api_hosts()}
    multi_http.close()

    assert ("GET", "/api/v1/orders") in m_pairs
    assert ("POST", "https://bff.pazarama.com/api/v1/cart") in m_pairs
    assert "https://bff.pazarama.com" in multi_hosts


# ---------------------------------------------------------------------------
# 4. Stage 0 SEO / Storefront route budgeting
# ---------------------------------------------------------------------------


def test_seo_route_cap_prevents_catalog_slugs_crowding_functional_routes(tmp_path: Path) -> None:
    assert _classify_seo_route_pattern("/elektronik-k-K04001") == "seo_category_k"
    assert _classify_seo_route_pattern("/iphone-15-pro-p-ABCD1234") == "seo_product_p"
    assert _classify_seo_route_pattern("/moda-giyim-c-1024") == "seo_catalog_c"
    assert _classify_seo_route_pattern("/super-yaz-firsatlari-buyuk-indirim-gunleri") == "seo_long_slug"
    # Functional / API / UUID routes MUST NEVER be classified as SEO noise
    assert _classify_seo_route_pattern("/hesabim/orders") == ""
    assert _classify_seo_route_pattern("/api/search") == ""
    assert _classify_seo_route_pattern("/login") == ""
    assert _classify_seo_route_pattern("/orders/12345678-1234-4123-8123-123456789abc") == ""
    assert _classify_seo_route_pattern("/api/v1/get-user-by-account-id") == ""
    assert _classify_seo_route_pattern("/some-super-long-action-path-here", method="POST") == ""

    http = _make_client(tmp_path, base_url="https://www.pazarama.com/")
    collector = _Stage0Collector(http)

    # Flood 100 -k-K... category routes, 25 -p-... product routes, 20 -c-... catalog routes, 25 long slugs
    for i in range(100):
        collector.record_route(method="GET", raw_url=f"/kategori-urun-{i:03d}-k-K{i + 1000}", status=200)
    for i in range(25):
        collector.record_route(method="GET", raw_url=f"/urun-model-{i:02d}-p-PRD{i:04d}X", status=200)
    for i in range(20):
        collector.record_route(method="GET", raw_url=f"/marka-koleksiyon-{i:02d}-c-{500 + i}", status=200)
    for i in range(25):
        collector.record_route(
            method="GET",
            raw_url=f"/ozel-kampanya-haftasonu-firsat-urunleri-etiket-{i:02d}",
            status=200,
        )

    # Add real functional routes after the SEO flood (including unvisited status=0 routes)
    collector.record_route(method="GET", raw_url="/hesabim/orders", status=0)
    collector.record_route(method="GET", raw_url="/api/search", params=["q"], status=200)
    collector.record_route(method="GET", raw_url="/login", status=0)
    collector.record_route(method="GET", raw_url="/orders/12345678-1234-4123-8123-123456789abc", status=200)

    links, _forms, _bt, _mp, hints = _finalize_routes(collector)
    http.close()

    link_urls = [r["url"] for r in links]
    assert "/hesabim/orders" in link_urls
    assert "/api/search" in link_urls
    assert "/login" in link_urls
    assert "/orders/12345678-1234-4123-8123-123456789abc" in link_urls

    # Every SEO pattern class is strictly capped at <= 6 routes
    k_routes = [u for u in link_urls if _classify_seo_route_pattern(u) == "seo_category_k"]
    p_routes = [u for u in link_urls if _classify_seo_route_pattern(u) == "seo_product_p"]
    c_routes = [u for u in link_urls if _classify_seo_route_pattern(u) == "seo_catalog_c"]
    long_routes = [u for u in link_urls if _classify_seo_route_pattern(u) == "seo_long_slug"]
    assert len(k_routes) <= 6
    assert len(p_routes) <= 6
    assert len(c_routes) <= 6
    assert len(long_routes) <= 6
    assert len(link_urls) <= 30

    # Functional routes appear in discovery_hints without being crowded out by -k-K... pages
    assert "/api/search" in hints
    assert "/hesabim/orders" in hints
    assert "/login" in hints
    assert sum(1 for h in hints if _classify_seo_route_pattern(h)) <= 2


# ---------------------------------------------------------------------------
# 5. Real loopback Playwright end-to-end integration test
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_playwright_cdn_js_anonymous_fetch_api_hosts_and_seo_cap_e2e(tmp_path: Path) -> None:
    secret_cookie = "sid_live_pazarama_887766"
    secret_bearer = "bearer_live_pazarama_554433"
    secret_custom = "custom_actor_hdr_112233"

    def api_router(_method: str, _raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        return 200, "application/json", json.dumps({"ok": True}), {}

    with _start_test_server(api_router) as (api_base_url, api_port, api_log):
        api_origin = api_base_url.rstrip("/")

        def cdn_router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
            path = urlsplit(raw_path).path
            if path == "/asset/_pzweb/app.js":
                js = f"""
window.__APP_LOADED = true;
const accountOrders = "/hesabim/orders";
async function doCheckout() {{
  await fetch("/api/v1/checkout", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{cartId: "c1"}})
  }});
}}
fetch("{api_origin}/v1/cart").catch(() => {{}});
"""
                return 200, "application/javascript", js, {"Access-Control-Allow-Origin": "*"}
            return 404, "text/plain", "missing", {}

        with _start_test_server(cdn_router) as (cdn_base_url, _cdn_port, cdn_log):
            cdn_origin = cdn_base_url.rstrip("/")

            def app_router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
                path = urlsplit(raw_path).path
                if path == "/":
                    seo_links = "\n  ".join(
                        f'<a href="/kategori-{i:02d}-k-K{1000 + i}">Cat {i}</a>' for i in range(25)
                    )
                    html = f"""<!doctype html>
<html>
<head>
  <title>Storefront</title>
  <script src="{cdn_origin}/asset/_pzweb/app.js"></script>
</head>
<body>
  <h1>Home</h1>
  <nav>
    {seo_links}
    <a href="/hesabim/orders">My Orders</a>
    <a href="/login">Login</a>
    <a href="/api/search?q=phone">Search</a>
  </nav>
</body>
</html>"""
                    return 200, "text/html; charset=utf-8", html, {}
                if path == "/hesabim/orders":
                    return 200, "text/html; charset=utf-8", "<html><body><h1>Orders</h1></body></html>", {}
                if path == "/login":
                    return 200, "text/html; charset=utf-8", "<html><body><h1>Login</h1></body></html>", {}
                if path == "/api/search":
                    return 200, "application/json", json.dumps({"items": []}), {}
                if path.startswith("/kategori-"):
                    return 200, "text/html; charset=utf-8", "<html><body><h1>Category</h1></body></html>", {}
                return 404, "application/json", json.dumps({"error": "not found"}), {}

            with _start_test_server(app_router) as (app_base_url, _app_port, app_log):
                http = _make_client(
                    tmp_path,
                    base_url=app_base_url,
                    accounts=[
                        {
                            "alias": "member1",
                            "role": "member",
                            "cookie": f"sid={secret_cookie}",
                            "session_token": secret_bearer,
                            "auth_header_name": "X-Actor-Auth",
                            "headers": {"X-Actor-Auth": secret_custom},
                        }
                    ],
                    allowed_methods=("GET", "HEAD", "POST"),
                    max_requests=80,
                )
                seed_dir = tmp_path / "seed_out"
                res = run_stage0_crawl(
                    http,
                    output_dir=seed_dir,
                    allow_forms=False,
                    max_pages=6,
                    max_actions=4,
                    wait_ms=250,
                    max_passive_probes=0,
                )
                http.close()

                assert res["status"] == "ok"
                assert res["stats"]["js_chunks_parsed"] >= 1
                assert res["stats"]["cdn_js_chunks_parsed"] >= 1
                assert res["stats"]["external_api_hosts_seen"] >= 1

                # Target app received actor auth, while CDN received ZERO credentials/cookies,
                # and out-of-scope sibling API received ZERO requests.
                assert any(secret_cookie in r["headers"].get("cookie", "") for r in app_log)
                assert len(cdn_log) == 1
                cdn_hdrs = {k.lower(): v for k, v in cdn_log[0]["headers"].items()}
                assert "cookie" not in cdn_hdrs
                assert "authorization" not in cdn_hdrs
                assert "x-actor-auth" not in cdn_hdrs
                assert api_log == []

                # Verify routes extracted from CDN JS and functional HTML pages
                all_pairs = {(r["method"], r["url"]) for r in [*res["links"], *res["forms"]]}
                assert ("POST", "/api/v1/checkout") in all_pairs
                assert ("GET", "/hesabim/orders") in all_pairs
                assert ("GET", "/login") in all_pairs
                assert ("GET", "/api/search") in all_pairs

                # Verify SEO routes capped to <= 6 and functional routes prioritized in discovery_hints
                k_links = [r["url"] for r in res["links"] if _classify_seo_route_pattern(r["url"]) == "seo_category_k"]
                assert len(k_links) <= 6
                assert "/api/search" in res["discovery_hints"]
                assert "/hesabim/orders" in res["discovery_hints"]
                assert "/login" in res["discovery_hints"]

                # Verify discovered_api_hosts captured the aborted sibling API fetch
                host_entries = {item["origin"]: item for item in res["discovered_api_hosts"]}
                assert f"http://127.0.0.1:{api_port}" in host_entries
                assert "/v1/cart" in host_entries[f"http://127.0.0.1:{api_port}"]["sample_paths"]

                # Verify NO secrets leaked in returned payload or stage0-seed.json
                seed_text = Path(res["seed_file"]).read_text(encoding="utf-8")
                serialized = json.dumps(res)
                for secret in (secret_cookie, secret_bearer, secret_custom):
                    assert secret not in serialized
                    assert secret not in seed_text
