"""Unit tests for Faz 7C: SPA route origin resolution & 3-char lowercase Webpack noise filtering."""
from __future__ import annotations

from pathlib import Path
import sys
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, str(_p))

from agentic_bsag import BeliefStateAttackGraph  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_preview import _build_surface_hints, _extract_surface_summary, _is_skipped_surface_url  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_sharding import cluster_discovered_surface  # noqa: E402
from agentic_stage0_crawl import _Stage0Collector, _finalize_routes, _is_stage0_noise_path  # noqa: E402
from agentic_surface import SurfaceFrontierTracker, is_non_endpoint_source_path  # noqa: E402
from kryon_core.surface.extract import (  # noqa: E402
    _normalize_spa_route_path,
    extract_js,
    extract_js_calls,
    extract_spa_routes,
    is_non_endpoint_noise_path,
)

ORIGIN = "http://127.0.0.1:37781"
ASSET_JS_URL = f"{ORIGIN}/static/js/app.3b9f53020f8b93d23449.js"
CHUNK_JS_URL = f"{ORIGIN}/assets/js/9.70821126cfead55e3db5.js"


# ---------------------------------------------------------------------------
# 1. SPA Route Origin Resolution (never nest under /static/js/... or /assets/js/...)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw_route", "expected"),
    [
        ("login", "/login"),
        ("./login", "/login"),
        ("../jotter/article", "/jotter/article"),
        ("jotter/article?id=1", "/jotter/article?id=1"),
        ("#/users/:userId", "/users/{userId}"),
        ("/(app)/c/[id]", "/c/{id}"),
        ("  users/:id  ", "/users/{id}"),
        ("#section", ""),
        ("//evil.example/login", ""),
        ("https://evil.example/login", ""),
        ("javascript:void(0)", ""),
        ("mailto:sec@example.com", ""),
        (".", ""),
        ("..", ""),
        ("/admin/*", ""),
    ],
)
def test_normalize_spa_route_path_guarantees_leading_slash_and_rejects_schemes(
    raw_route: str,
    expected: str,
) -> None:
    assert _normalize_spa_route_path(raw_route) == expected


def test_extract_spa_routes_and_extract_js_resolve_relative_routes_against_origin_not_script_dir() -> None:
    bundle = "\n".join([
        'next({ path: "login", query: { redirect: to.fullPath } });',
        'const links = [{ path: "jotter/article" }, { path: "./admin/dashboard" }];',
        'router.push("profile");',
        'router.replace("settings/security");',
        'router.push({ path: "account/keys" });',
        'const jsx = `<Route path="reports/daily" /><Link to="billing">Billing</Link>`;',
        'const nestedHash = "#/workspace/:wsId";',
        'const externalLink = `<Link to="https://evil.example/phish">Ext</Link>`;',
        'const jsProp = `<Route path="lineStyle.color" />`;',
    ])

    spa_urls = {rec["url"] for rec in extract_spa_routes(bundle, ASSET_JS_URL, limit=100)}
    assert f"{ORIGIN}/login" in spa_urls
    assert f"{ORIGIN}/jotter/article" in spa_urls
    assert f"{ORIGIN}/admin/dashboard" in spa_urls
    assert f"{ORIGIN}/profile" in spa_urls
    assert f"{ORIGIN}/settings/security" in spa_urls
    assert f"{ORIGIN}/account/keys" in spa_urls
    assert f"{ORIGIN}/reports/daily" in spa_urls
    assert f"{ORIGIN}/billing" in spa_urls
    assert f"{ORIGIN}/workspace/{{wsId}}" in spa_urls

    assert not any("/static/js/" in u for u in spa_urls), f"Asset-relative leak in spa_routes: {spa_urls}"
    assert not any("evil.example" in u or "phish" in u for u in spa_urls)
    assert f"{ORIGIN}/lineStyle.color" not in spa_urls

    js_urls = {rec["url"] for rec in extract_js(bundle, CHUNK_JS_URL, limit=100)}
    assert f"{ORIGIN}/login" in js_urls
    assert f"{ORIGIN}/jotter/article" in js_urls
    assert f"{ORIGIN}/admin/dashboard" in js_urls
    assert not any("/assets/js/" in u for u in js_urls), f"Asset-relative leak in extract_js: {js_urls}"


def test_extract_spa_routes_preserves_explicit_router_basename() -> None:
    jsx = '<BrowserRouter basename="/portal"><Route path="login" /><Link to="./users">U</Link></BrowserRouter>'
    urls = {rec["url"] for rec in extract_spa_routes(jsx, ASSET_JS_URL)}
    assert urls == {f"{ORIGIN}/portal/login", f"{ORIGIN}/portal/users"}


def test_html_inline_script_spa_routes_resolve_to_origin_while_fetch_preserves_page_relative() -> None:
    inline_js = (
        'router.push("login");\n'
        'const jsx = `<Link to="jotter/article">Art</Link>`;\n'
        'fetch("./items");\n'
    )
    page_url = f"{ORIGIN}/sub/page.html"
    spa_urls = {rec["url"] for rec in extract_spa_routes(inline_js, page_url)}
    call_urls = {rec["url"] for rec in extract_js_calls(inline_js, page_url)}

    assert spa_urls == {f"{ORIGIN}/login", f"{ORIGIN}/jotter/article"}
    assert call_urls == {f"{ORIGIN}/sub/items"}


# ---------------------------------------------------------------------------
# 2. 3-4 Char All-Lowercase Consonant-Only Webpack Module IDs & /dist Noise
# ---------------------------------------------------------------------------


CONSONANT_WEBPACK_NOISE = (
    "/bpg",
    "/gxq",
    "/xsj",
    "/qwr",
    "/zkt",
    "/fgh",
    "/mnp",
    "/bcdf",
    "/hjkl",
    "/vwxz",
    "/dist",
    "./bpg",
    "../gxq",
)

PRESERVED_SHORT_LOWER_AND_APP_ROUTES = (
    "/api",
    "/app",
    "/doc",
    "/docs",
    "/faq",
    "/map",
    "/pay",
    "/buy",
    "/add",
    "/new",
    "/top",
    "/raw",
    "/job",
    "/run",
    "/log",
    "/tag",
    "/cat",
    "/box",
    "/web",
    "/hub",
    "/lab",
    "/dev",
    "/ops",
    "/bio",
    "/pro",
    "/vip",
    "/pin",
    "/key",
    "/otp",
    "/mfa",
    "/sso",
    "/jwt",
    "/pdf",
    "/xml",
    "/csv",
    "/rss",
    "/rpc",
    "/sql",
    "/php",
    "/jsp",
    "/cgi",
    "/src",
    "/img",
    "/css",
    "/js",
    "/svg",
    "/html",
    "/http",
    "/csrf",
    "/grpc",
    "/www",
    "/cdn",
    "/cms",
    "/sdk",
    "/cli",
    "/cfg",
    "/env",
    "/pub",
    "/sys",
    "/bin",
    "/lib",
    "/var",
    "/usr",
    "/ui",
    "/ws",
    "/v1",
    "/v2",
    "/v3",
    "/db",
    "/id",
    "/me",
    "/ip",
    "/qa",
    "/login",
    "/admin",
    "/home",
    "/user",
    "/cart",
    "/blog",
    "/shop",
    "/news",
    "/help",
    "/info",
)


@pytest.mark.parametrize("noise_path", CONSONANT_WEBPACK_NOISE)
def test_lowercase_consonant_webpack_ids_and_dist_are_filtered_across_all_layers(noise_path: str) -> None:
    assert is_non_endpoint_noise_path(noise_path) is True
    assert is_non_endpoint_source_path(noise_path) is True
    if noise_path.startswith("/"):
        full_url = f"{ORIGIN}{noise_path}"
        assert is_non_endpoint_noise_path(full_url) is True
        assert _is_skipped_surface_url(full_url, base_url=ORIGIN) is True
        assert _is_stage0_noise_path(noise_path, origin_url=ORIGIN) is True


@pytest.mark.parametrize("valid_route", PRESERVED_SHORT_LOWER_AND_APP_ROUTES)
def test_legitimate_short_and_vowel_routes_remain_preserved(valid_route: str) -> None:
    assert is_non_endpoint_noise_path(valid_route) is False
    assert is_non_endpoint_noise_path(f"{ORIGIN}{valid_route}") is False
    assert is_non_endpoint_source_path(valid_route) is False
    assert _is_skipped_surface_url(f"{ORIGIN}{valid_route}", base_url=ORIGIN) is False


# ---------------------------------------------------------------------------
# 3. Webpack Bundle Context Filtering (/ocq, /bpg, /gxq, /xsj) + White Jotter Regression
# ---------------------------------------------------------------------------


def test_webpack_bundle_module_ids_including_ocq_filtered_while_real_routes_preserved() -> None:
    # Modeled directly on White Jotter webpackJsonp bundle (app.*.js + vendor.*.js)
    webpack_bundle = "\n".join([
        'webpackJsonp([13],{',
        '"+BTi":function(n,e){},"+Rdb":function(n,e){},"/I4U":function(n,e){},',
        '"/bpg":function(n,e){},"/gxq":function(n,e){},"/xsj":function(n,e){},',
        '"/ocq":function(n,e){},"./ocq":function(n,e){},"/i/W":function(n,e){},',
        'YaEn:function(n,e,t){"use strict";',
        '  var u=t("7+uW"),a=t("/ocq"),b=t("/bpg"),c=t("/gxq"),d=t("/xsj"),m=t("./ocq");',
        '  var p=Promise.all([t.e(0)]).then(t.bind(null,"/ocq"));',
        '  var q=__webpack_require__("/ocq");',
        '  var ve={defaults:{baseURL:"/api",withCredentials:!0}};',
        '  ve.get("/authentication").then(function(n){n&&t()}):t({path:"login",query:{redirect:n.fullPath}});',
        '  ve.get("/menu");',
        '  var r=[{path:"/",redirect:"/home"},{path:"/home",redirect:"/index"},',
        '    {path:"/index"},{path:"/jotter"},{path:"/jotter/article"},',
        '    {path:"/admin/content/editor"},{path:"/library"},{path:"/login"},',
        '    {path:"/register"},{path:"/admin"},{path:"/admin/dashboard"}];',
        '  var j={path:"jotter/article",query:{id:1}};',
        '  var d_ref="../../dist";',
        '  var v_faq="/faq", v_doc="/doc", v_pay="/pay", v_map="/map";',
        '}});',
    ])

    js_paths = {urlsplit(r["url"]).path for r in extract_js(webpack_bundle, ASSET_JS_URL, limit=200)}
    spa_paths = {urlsplit(r["url"]).path for r in extract_spa_routes(webpack_bundle, ASSET_JS_URL, limit=200)}

    for banned in ("/bpg", "/gxq", "/ocq", "/xsj", "/I4U", "/i/W", "/dist", "/static/js/login", "/static/js/jotter/article"):
        assert banned not in js_paths, f"Noise leaked into extract_js: {banned}"
        assert banned not in spa_paths, f"Noise leaked into extract_spa_routes: {banned}"

    expected = {
        "/api",
        "/authentication",
        "/menu",
        "/home",
        "/index",
        "/jotter",
        "/jotter/article",
        "/admin/content/editor",
        "/library",
        "/login",
        "/register",
        "/admin",
        "/admin/dashboard",
        "/faq",
        "/doc",
        "/pay",
        "/map",
    }
    assert expected.issubset(js_paths), f"Missing expected JS routes: {sorted(expected - js_paths)}"
    assert {
        "/home",
        "/index",
        "/jotter",
        "/jotter/article",
        "/admin/content/editor",
        "/library",
        "/login",
        "/register",
        "/admin",
        "/admin/dashboard",
    }.issubset(spa_paths)


def test_non_webpack_custom_single_letter_fetch_helper_for_short_route_not_dropped() -> None:
    non_webpack_js = (
        "const t = (p) => fetch(p);\n"
        't("/faq");\n'
        't("/doc");\n'
        't("/api");\n'
    )
    js_paths = {urlsplit(r["url"]).path for r in extract_js(non_webpack_js, f"{ORIGIN}/app.js")}
    assert {"/faq", "/doc", "/api"}.issubset(js_paths)


def test_end_to_end_preview_bsag_stage0_and_sharding_hygiene(tmp_path: Path) -> None:
    bundle = "\n".join([
        'webpackJsonp([13],{',
        '"/bpg":function(n,e){},"/gxq":function(n,e){},"/xsj":function(n,e){},"/ocq":function(n,e){},',
        'NHnr:function(n,e,t){',
        '  var a=t("/ocq"),b=t("/bpg");',
        '  next({path:"login",query:{redirect:to.fullPath}});',
        '  const c={path:"jotter/article",query:{id:1}};',
        '  const r=[{path:"/home"},{path:"/jotter"},{path:"/jotter/article"},{path:"/admin/dashboard"},{path:"/library"}];',
        '  const x="/dist";',
        '  fetch("/api/article/1");',
        '  fetch("/api/admin/user");',
        '}',
        '});',
    ])

    receipt = {
        "receipt_id": "req-0018",
        "url": ASSET_JS_URL,
        "method": "GET",
        "status": 200,
        "content_type": "application/javascript",
        "response_headers": {"Content-Type": "application/javascript"},
        "actor": "anon",
        "body": bundle,
    }

    # 1. agentic_preview summary & surface_hints
    summary = _extract_surface_summary(receipt, ORIGIN)
    hints = _build_surface_hints(receipt, ORIGIN)
    summary_urls = {
        urlsplit(str(item.get("url") or "")).path
        for item in [*(summary.get("links") or []), *(summary.get("spa_routes") or []), *(summary.get("js_calls") or [])]
    }
    hint_urls = set(hints.get("api_endpoints") or []) | set(hints.get("links") or [])

    for bad in ("/bpg", "/gxq", "/ocq", "/xsj", "/dist", "/static/js/login", "/static/js/jotter/article"):
        assert bad not in summary_urls
        assert bad not in hint_urls
    assert {"/login", "/jotter/article", "/api/article/1", "/api/admin/user"}.issubset(summary_urls)

    # 2. agentic_bsag ingestion (JS asset + HTML inline script on nested page)
    bsag = BeliefStateAttackGraph(base_url=ORIGIN)
    bsag.ingest_receipt(receipt)
    bsag.ingest_receipt({
        "receipt_id": "req-0019",
        "url": f"{ORIGIN}/portal/index.html",
        "method": "GET",
        "status": 200,
        "content_type": "text/html",
        "actor": "anon",
        "body": '<html><body><script>router.push("settings/tokens");</script></body></html>',
    })
    bsag_paths = {node.label for node in bsag.nodes.values() if node.node_type == "ENDPOINT"}
    for bad in ("/bpg", "/gxq", "/ocq", "/xsj", "/dist", "/static/js/login", "/static/js/jotter/article", "/portal/settings/tokens"):
        assert bad not in bsag_paths
    assert {"/login", "/jotter/article", "/api/article/{id}", "/api/admin/user", "/settings/tokens"}.issubset(bsag_paths)

    # 3. Stage 0 + SurfaceFrontierTracker + Sharding
    client = AgenticHTTPClient(
        base_url=ORIGIN,
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        actors=ActorManager([{"alias": "anon", "role": "anonymous"}]),
        allowed_methods=("GET", "POST"),
        max_requests=50,
    )
    collector = _Stage0Collector(client)
    collector.ingest_surface_summary(summary, source_url=ASSET_JS_URL)
    links, _forms, _bt, _mp, discovery_hints = _finalize_routes(collector)
    stage0_paths = {item["url"] for item in links} | set(discovery_hints)
    for bad in ("/bpg", "/gxq", "/ocq", "/xsj", "/dist", "/static/js/login", "/static/js/jotter/article"):
        assert bad not in stage0_paths
    assert {"/login", "/jotter/article", "/api/article/1", "/api/admin/user"}.issubset(stage0_paths)

    tracker = SurfaceFrontierTracker(base_url=ORIGIN, allowed_methods=("GET", "POST"))
    tracker.ingest_receipt(receipt)
    for extra in ("/admin/content/editor", "/register", "/authentication", "/menu", "/index"):
        tracker._register_discovered_url(extra, method="GET", actor="anon")
    discovered = {p for _, p in tracker.discovered_routes}
    for bad in ("/bpg", "/gxq", "/ocq", "/xsj", "/dist", "/static/js/login", "/static/js/jotter/article"):
        assert bad not in discovered
    assert {"/login", "/jotter/article", "/api/article/1", "/api/admin/user"}.issubset(discovered)

    clusters = cluster_discovered_surface(tracker, max_shards=3, min_routes_for_sharding=6)
    shard_families = {fam for c in clusters for fam in c.families}
    shard_routes = {r for c in clusters for r in c.routes}
    for bad_fam in ("bpg", "gxq", "ocq", "xsj", "dist", "static"):
        assert bad_fam not in shard_families
    assert "/static/js/login" not in shard_routes
    assert "/static/js/jotter/article" not in shard_routes
