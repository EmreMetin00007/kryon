"""Unit tests for Faz 6C: minified Webpack short-token, JS property-dot path, and epoch-timestamp asset chunk filtering."""
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

from agentic_preview import _is_skipped_surface_url  # noqa: E402
from agentic_seed import _is_non_hint_asset_path  # noqa: E402
from agentic_stage0_crawl import _is_stage0_noise_path  # noqa: E402
from agentic_surface import SurfaceFrontierTracker, is_non_endpoint_source_path  # noqa: E402
from kryon_core.surface.extract import (  # noqa: E402
    _looks_js_url_or_path,
    extract_html,
    extract_js,
    extract_js_calls,
    extract_spa_routes,
    is_hashed_asset_chunk_path,
    is_non_endpoint_noise_path,
)
from kryon_core.surface.normalize import (  # noqa: E402
    discovery_link_skip_reason,
    is_js_property_dot_path,
)

ORIGIN = "http://127.0.0.1:8080"


# ---------------------------------------------------------------------------
# 1. Numeric epoch-timestamp asset chunks (Vite / Rollup)
# ---------------------------------------------------------------------------

EPOCH_TIMESTAMP_CHUNKS = (
    "/assets/useRequest-1743477601894.js",
    "/assets/index-1743477601894317.js",
    "/assets/vue-1743477601894.js",
    "/assets/vendor-1743477601.js",
    "/assets/style-1743477601894.css",
    "/assets/runtime.1743477601894.mjs",
    "/static/js/chunk.1743477601894.cjs",
    "/assets/app.1743477601894.chunk.js",
    "/assets/app-1743477601894.min.css",
    "/dist/js/main-1743477601894317.js",
)

PRESERVED_NON_TIMESTAMP_BUNDLES = (
    "/assets/app.js",
    "/static/js/v2.js",
    "/static/main-2.js",
    "/static/loader-01.js",
    "/static/app-20240101.js",
    "/assets/index-main.js",
    "/api/v1/plugin-1743477601894.js",
    "/files/file=useRequest-1743477601894.js",
)


@pytest.mark.parametrize("chunk_path", EPOCH_TIMESTAMP_CHUNKS)
def test_epoch_timestamp_asset_chunks_are_detected_and_filtered(chunk_path: str) -> None:
    assert is_hashed_asset_chunk_path(chunk_path) is True
    assert is_hashed_asset_chunk_path(f"{ORIGIN}{chunk_path}") is True
    assert is_non_endpoint_noise_path(chunk_path) is True
    assert is_non_endpoint_source_path(chunk_path) is True
    assert _is_skipped_surface_url(chunk_path, base_url=ORIGIN) is True
    assert _is_stage0_noise_path(chunk_path, origin_url=ORIGIN) is True
    assert _is_non_hint_asset_path(chunk_path) is True


@pytest.mark.parametrize("bundle_path", PRESERVED_NON_TIMESTAMP_BUNDLES)
def test_unhashed_and_short_numeric_bundles_remain_preserved(bundle_path: str) -> None:
    assert is_hashed_asset_chunk_path(bundle_path) is False
    assert is_non_endpoint_noise_path(bundle_path) is False


# ---------------------------------------------------------------------------
# 2. JS object-property dot paths under script / asset directories
# ---------------------------------------------------------------------------

JS_PROPERTY_DOT_PATHS = (
    "/static/js/lineStyle.color",
    "/js/itemStyle.borderColor",
    "/assets/tooltip.formatter",
    "/static/js/axisLine.lineStyle.width",
    "/scripts/label.fontSize",
    "/dist/js/emphasis.itemStyle.opacity",
    "/static/assets/echarts.data",
    "/assets/js/chart.backgroundColor",
    "./js/lineStyle.color",
    "../assets/tooltip.formatter",
)

LEGITIMATE_DOTTED_ENDPOINTS = (
    "/index/Article/info.html",
    "/api/v1/users.json",
    "/admin/config.ini",
    "/api/v2.1/orders",
    "/.well-known/openid-configuration",
    "/static/js/app.js",
    "/static/js/index.html",
    "/static/config.ini",
    "/assets/swagger.json",
    "/assets/schema.graphql",
    "/assets/service.wsdl",
    "/assets/backup.sql",
    "/assets/archive.tar.gz",
    "/assets/app.bak",
    "/assets/app.env",
    "/assets/readme.md",
    "/assets/v2.1",
    "/api/assets/tooltip.formatter",
    "/static/js/file=lineStyle.color",
)


@pytest.mark.parametrize("prop_path", JS_PROPERTY_DOT_PATHS)
def test_js_property_dot_paths_are_rejected_across_filters(prop_path: str) -> None:
    assert is_js_property_dot_path(prop_path) is True
    assert is_non_endpoint_noise_path(prop_path) is True
    assert is_non_endpoint_source_path(prop_path) is True
    if prop_path.startswith("/"):
        full_url = f"{ORIGIN}{prop_path}"
        assert is_js_property_dot_path(full_url) is True
        assert discovery_link_skip_reason(full_url) == "js_property_dot_path"


@pytest.mark.parametrize("valid_path", LEGITIMATE_DOTTED_ENDPOINTS)
def test_legitimate_dotted_endpoints_are_preserved(valid_path: str) -> None:
    assert is_js_property_dot_path(valid_path) is False
    full_url = f"{ORIGIN}{valid_path}"
    assert is_js_property_dot_path(full_url) is False
    assert discovery_link_skip_reason(full_url) != "js_property_dot_path"


def test_looks_js_url_or_path_rejects_bare_property_chains_and_keeps_web_files() -> None:
    assert _looks_js_url_or_path("lineStyle.color") is False
    assert _looks_js_url_or_path("itemStyle.borderColor") is False
    assert _looks_js_url_or_path("tooltip.formatter") is False

    assert _looks_js_url_or_path("login.php") is True
    assert _looks_js_url_or_path("users.json") is True
    assert _looks_js_url_or_path("config.ini") is True
    assert _looks_js_url_or_path("index.html") is True
    assert _looks_js_url_or_path("schema.graphql") is True
    assert _looks_js_url_or_path("/api/v1/users") is True
    assert _looks_js_url_or_path("api/v1/users") is True


# ---------------------------------------------------------------------------
# 3. Minified Webpack module IDs, 1-char/1-char pairs, and bare numeric JS paths
# ---------------------------------------------------------------------------

MINIFIED_WEBPACK_AND_FRAGMENT_NOISE = (
    "/86O",
    "/99E",
    "/I4U",
    "/bQp",
    "/ZBO",
    "/BOW",
    "/aBc",
    "/AbC",
    "/xY",
    "/9A",
    "/A9",
    "/X4kP",
    "/Bqp",
    "/i/W",
    "/a/B",
    "/x/y",
    "/a/b/c",
)

PRESERVED_SHORT_AND_REAL_ROUTES = (
    "/API",
    "/SSO",
    "/JWT",
    "/OAuth",
    "/V1",
    "/V2",
    "/UI",
    "/WS",
    "/Home",
    "/User",
    "/Auth",
    "/Menu",
    "/Docs",
    "/api",
    "/app",
    "/v1",
    "/v2",
    "/ui",
    "/ws",
    "/doc",
    "/docs",
    "/auth",
    "/home",
    "/menu",
    "/login",
    "/admin",
    "/users",
    "/index",
    "/jotter",
    "/library",
    "/register",
    "/api/login",
    "/api/admin/user",
    "/admin/dashboard",
    "/jotter/article",
    "/v1/users",
    "/v2/orders",
    "/api/items/1",
    "/product/1.html",
    "/article/4/1",
)


@pytest.mark.parametrize("noise_path", MINIFIED_WEBPACK_AND_FRAGMENT_NOISE)
def test_minified_webpack_ids_and_one_char_pairs_are_filtered(noise_path: str) -> None:
    assert is_non_endpoint_noise_path(noise_path) is True
    assert is_non_endpoint_noise_path(f"{ORIGIN}{noise_path}") is True
    assert is_non_endpoint_source_path(noise_path) is True
    assert _is_skipped_surface_url(noise_path, base_url=ORIGIN) is True


@pytest.mark.parametrize("real_route", PRESERVED_SHORT_AND_REAL_ROUTES)
def test_real_short_and_application_routes_are_preserved(real_route: str) -> None:
    assert is_non_endpoint_noise_path(real_route) is False
    assert is_non_endpoint_noise_path(f"{ORIGIN}{real_route}") is False
    assert is_non_endpoint_source_path(real_route) is False


def test_extract_js_and_js_calls_filter_minified_noise_property_paths_and_bare_numeric_roots() -> None:
    bundle_url = f"{ORIGIN}/static/js/app.js"
    minified_bundle = "\n".join([
        # Minified Webpack module IDs & 1-char/1-char regex fragments
        'var m1 = "/86O", m2 = "/99E", m3 = "/I4U", m4 = "/bQp", m5 = "/ZBO", m6 = "/BOW";',
        'var r1 = "/i/W", r2 = "/a/B";',
        # Bare numeric root strings
        'var n1 = "/1", n2 = "/2", n3 = "/42";',
        'var o1 = { path: "1" };',
        # JS object-property dot paths (direct, relative, and concatenated)
        'var p1 = { path: "lineStyle.color" };',
        'var p2 = { path: "itemStyle.borderColor" };',
        'var p3 = { url: "tooltip.formatter" };',
        'var p4 = "/static/js/lineStyle.color";',
        'var propBase = "lineStyle"; var propFull = propBase + ".color";',
        # Epoch-timestamp Vite/Rollup chunks
        'var c1 = "/assets/useRequest-1743477601894.js";',
        'var c2 = "/assets/index-1743477601894317.js";',
        'var c3 = "/assets/vue-1743477601894.js";',
        # Noisy fetch / axios calls
        'fetch("/86O");',
        'fetch("/i/W");',
        'fetch("/1");',
        'fetch("/42");',
        'axios.get("lineStyle.color");',
        'axios.get("/static/js/lineStyle.color");',
        # Real routes & API endpoints that MUST be preserved
        'var ok1 = "/api/login";',
        'var ok2 = "/api/admin/user";',
        'var ok3 = "/admin/dashboard";',
        'var ok4 = "/jotter/article";',
        'var ok5 = "/v1/users";',
        'var ok6 = "/v2/orders";',
        'var ok7 = "/api/items/1";',
        'var ok8 = "/product/1.html";',
        'var ok9 = "/article/4/1";',
        'var ok10 = "/API";',
        'var ok11 = "/SSO";',
        'var ok12 = "/JWT";',
        'var ok13 = "/OAuth";',
        'var ok14 = "/api";',
        'var ok15 = "/app";',
        'var ok16 = "/v1";',
        'var ok17 = "/v2";',
        'var ok18 = "/ui";',
        'var ok19 = "/ws";',
        'var ok20 = "/docs";',
        'var ok21 = "/auth";',
        'var ok22 = "/home";',
        'var ok23 = "/menu";',
        'var ok24 = "/login";',
        'var ok25 = "/admin";',
        'var ok26 = "/users";',
        'var ok27 = "/index";',
        'var ok28 = "/jotter";',
        'var ok29 = "/library";',
        'var ok30 = "/register";',
        'var ok31 = "/index/Article/info.html";',
        'var ok32 = "/api/v1/users.json";',
        'var ok33 = "/admin/config.ini";',
        'var ok34 = "/api/v2.1/orders";',
        'var ok35 = "/.well-known/openid-configuration";',
        'fetch("/api/login", { method: "POST", body: JSON.stringify({ username: "a" }) });',
        'axios.get("/api/admin/user");',
        'fetch("/api/items/1");',
        'axios.get("/article/4/1");',
        'const routes = [{ path: "/1" }, { path: "/86O" }, { path: "/jotter/article" }, { path: "/admin/dashboard" }];',
    ])

    js_paths = {urlsplit(r["url"]).path for r in extract_js(minified_bundle, bundle_url, limit=200)}
    call_paths = {urlsplit(r["url"]).path for r in extract_js_calls(minified_bundle, bundle_url, limit=200)}
    spa_paths = {urlsplit(r["url"]).path for r in extract_spa_routes(minified_bundle, bundle_url, limit=200)}

    banned = {
        "/86O",
        "/99E",
        "/I4U",
        "/bQp",
        "/ZBO",
        "/BOW",
        "/i/W",
        "/a/B",
        "/1",
        "/2",
        "/42",
        "/static/js/1",
        "/static/js/lineStyle.color",
        "/static/js/itemStyle.borderColor",
        "/static/js/tooltip.formatter",
        "/lineStyle.color",
        "/assets/useRequest-1743477601894.js",
        "/assets/index-1743477601894317.js",
        "/assets/vue-1743477601894.js",
    }
    for noise in banned:
        assert noise not in js_paths, f"Noise leaked into extract_js: {noise}"
        assert noise not in call_paths, f"Noise leaked into extract_js_calls: {noise}"
        assert noise not in spa_paths, f"Noise leaked into extract_spa_routes: {noise}"

    expected_js = {
        "/api/login",
        "/api/admin/user",
        "/admin/dashboard",
        "/jotter/article",
        "/v1/users",
        "/v2/orders",
        "/api/items/1",
        "/product/1.html",
        "/article/4/1",
        "/API",
        "/SSO",
        "/JWT",
        "/OAuth",
        "/api",
        "/app",
        "/v1",
        "/v2",
        "/ui",
        "/ws",
        "/docs",
        "/auth",
        "/home",
        "/menu",
        "/login",
        "/admin",
        "/users",
        "/index",
        "/jotter",
        "/library",
        "/register",
        "/index/Article/info.html",
        "/api/v1/users.json",
        "/admin/config.ini",
        "/api/v2.1/orders",
        "/.well-known/openid-configuration",
    }
    assert expected_js.issubset(js_paths), f"Missing expected JS routes: {sorted(expected_js - js_paths)}"
    assert {"/api/login", "/api/admin/user", "/api/items/1", "/article/4/1"}.issubset(call_paths)
    assert {"/jotter/article", "/admin/dashboard"}.issubset(spa_paths)


def test_bare_property_paths_filtered_even_from_root_level_js_bundle() -> None:
    root_bundle = f"{ORIGIN}/app.js"
    js_src = (
        'var a = { path: "lineStyle.color", url: "tooltip.formatter" };\n'
        'var b = { url: "login.php", endpoint: "users.json" };\n'
        'fetch("itemStyle.borderColor");\n'
        'fetch("users.json");\n'
    )
    js_paths = {urlsplit(r["url"]).path for r in extract_js(js_src, root_bundle)}
    call_paths = {urlsplit(r["url"]).path for r in extract_js_calls(js_src, root_bundle)}

    assert "/lineStyle.color" not in js_paths
    assert "/tooltip.formatter" not in js_paths
    assert "/itemStyle.borderColor" not in call_paths
    assert {"/login.php", "/users.json"}.issubset(js_paths)
    assert "/users.json" in call_paths


def test_html_links_and_surface_frontier_preserve_real_routes_while_dropping_js_noise() -> None:
    html = (
        "<!doctype html><html><body>"
        '<a href="/api/login">Login</a>'
        '<a href="/api/admin/user">Admin Users</a>'
        '<a href="/admin/dashboard">Dashboard</a>'
        '<a href="/jotter/article">Article</a>'
        '<a href="/v1/users">V1 Users</a>'
        '<a href="/v2/orders">V2 Orders</a>'
        '<a href="/index/Article/info.html">Info</a>'
        '<a href="/1">Page 1</a>'
        '<script src="/assets/useRequest-1743477601894.js"></script>'
        '<script src="/assets/app.js"></script>'
        "</body></html>"
    )
    html_paths = {urlsplit(r["url"]).path for r in extract_html(html, f"{ORIGIN}/")}
    assert {
        "/api/login",
        "/api/admin/user",
        "/admin/dashboard",
        "/jotter/article",
        "/v1/users",
        "/v2/orders",
        "/index/Article/info.html",
        "/1",
        "/assets/app.js",
    }.issubset(html_paths)

    tracker = SurfaceFrontierTracker(base_url=ORIGIN, allowed_methods=("GET", "POST"))
    tracker.ingest_receipt({
        "url": f"{ORIGIN}/static/js/app.js",
        "method": "GET",
        "status": 200,
        "content_type": "application/javascript",
        "actor": "anon",
        "body": (
            'const a = "/86O", b = "/99E", c = "/bQp", d = "/i/W", e = "/1";\n'
            'const p = { path: "lineStyle.color" };\n'
            'const ch = "/assets/useRequest-1743477601894.js";\n'
            'fetch("/api/login", { method: "POST" });\n'
            'fetch("/api/admin/user");\n'
        ),
    })
    discovered = {p for _, p in tracker.discovered_routes}
    assert {"/api/login", "/api/admin/user"}.issubset(discovered)
    for noisy in ("/86O", "/99E", "/bQp", "/i/W", "/1", "/static/js/lineStyle.color", "/assets/useRequest-1743477601894.js"):
        assert noisy not in discovered
