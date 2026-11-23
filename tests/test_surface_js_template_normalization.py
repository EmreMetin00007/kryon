"""Unit and integration tests for JS template-literal URL resolution, virtual router-group normalization, and bundler/schema noise filtering."""
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

from agentic_preview import _extract_surface_summary  # noqa: E402
from agentic_sharding import cluster_discovered_surface, extract_resource_family  # noqa: E402
from agentic_surface import SurfaceFrontierTracker, is_non_endpoint_source_path  # noqa: E402
from kryon_core.surface.extract import (  # noqa: E402
    _collect_js_string_symtab,
    extract_js,
    extract_js_calls,
    extract_spa_routes,
    is_non_endpoint_noise_path,
)

BASE_URL = "http://127.0.0.1:8080"
CHUNK_URL = "http://127.0.0.1:8080/_app/immutable/chunks/B0utj4Io.js"


# ---------------------------------------------------------------------------
# 1. JS constant substitution & symtab sharing
# ---------------------------------------------------------------------------


def test_collect_js_string_symtab_and_extract_js_calls_prefix_substitution() -> None:
    filler = "\n".join(f'const cls_{i} = "flex items-center p-{i}";' for i in range(600))
    js = (
        filler
        + "\n"
        + 'const re = "";\n'
        + 'const Ae = `${re}/api/v1`;\n'
        + 'const ROOT = "/api";\n'
        + 'const V2 = ROOT + "/v2/";\n'
        + 'const SAME_ORIGIN = "http://127.0.0.1:8080/internal";\n'
        + 'const OTHER_ORIGIN = "https://evil.example/api";\n'
        + 'const NON_URL = "application/json";\n'
        + 'const TAG = "banners";\n'
        + "fetch(`${Ae}/configs/banners`);\n"
        + 'fetch(`${Ae}/channels/${c}/messages/${o}/delete`, {method: "POST", body: JSON.stringify({force: true})});\n'
        + "axios.get(`${V2}/users`);\n"
        + "fetch(`${SAME_ORIGIN}/metrics`);\n"
        + "fetch(`${OTHER_ORIGIN}/steal`);\n"
        + "fetch(`${NON_URL}/should-not-splice`);\n"
        + "fetch(`/api/v1/${TAG}/items`);\n"
    )

    symtab = _collect_js_string_symtab(js)
    assert symtab["Ae"] == "/api/v1"
    assert symtab["V2"] == "/api/v2/"

    calls = extract_js_calls(js, CHUNK_URL)
    by_url = {(rec["method"], rec["url"]): rec for rec in calls}

    assert ("GET", f"{BASE_URL}/api/v1/configs/banners") in by_url
    assert by_url[("GET", f"{BASE_URL}/api/v1/configs/banners")].get("params") in (None, [])

    delete_key = ("POST", f"{BASE_URL}/api/v1/channels/{{c}}/messages/{{o}}/delete")
    assert delete_key in by_url
    delete_params = {(p["name"], p["in"]) for p in by_url[delete_key].get("params") or []}
    assert ("c", "path") in delete_params
    assert ("o", "path") in delete_params
    assert ("force", "json") in delete_params
    assert ("Ae", "path") not in delete_params
    assert ("re", "path") not in delete_params

    # Trailing slash in V2="/api/v2/" must not produce //users
    assert ("GET", f"{BASE_URL}/api/v2/users") in by_url
    assert ("GET", f"{BASE_URL}/internal/metrics") in by_url
    assert not any("evil.example" in rec["url"] for rec in calls)

    # Non-URL identifiers are never spliced into prefix or path segment positions
    assert ("GET", f"{BASE_URL}/should-not-splice") in by_url
    assert not any("application/json" in rec["url"] for rec in calls)
    assert ("GET", f"{BASE_URL}/api/v1/{{TAG}}/items") in by_url
    tag_params = {(p["name"], p["in"]) for p in by_url[("GET", f"{BASE_URL}/api/v1/{{TAG}}/items")].get("params") or []}
    assert ("TAG", "path") in tag_params


def test_extract_js_reuses_symtab_for_concat_endpoints_and_filters_noise() -> None:
    js = (
        'const base = "/api/v1";\n'
        'const ep = base + "/orders";\n'
        'const bad = "/_app" + "/immutable/chunks/chunk.js";\n'
        'const bundle = "/assets/app.js";\n'
        'const schemaRef = "/$defs/XYChartAxisConfig";\n'
    )
    recs = extract_js(js, CHUNK_URL)
    urls = {rec["url"] for rec in recs}
    assert f"{BASE_URL}/api/v1/orders" in urls
    assert f"{BASE_URL}/assets/app.js" in urls
    assert not any("/_app/immutable/" in u for u in urls)
    assert not any("/$defs/" in u for u in urls)


# ---------------------------------------------------------------------------
# 2. Never resolve ${var}/... or {var}/... or chunk-relative paths under .js dir
# ---------------------------------------------------------------------------


def test_unresolved_leading_template_and_chunk_relative_urls_never_join_chunk_dir() -> None:
    js = (
        "fetch(`${Ae}/configs/banners`);\n"
        'fetch("{Be}/settings");\n'
        'fetch(`${Ae}/channels/${c}/messages/${o}/delete`, {method: "DELETE"});\n'
        "fetch(`/${itemId}`);\n"
        "fetch(`${dynamicOnly}`);\n"
        'fetch("api/v1/relative-items");\n'
        'fetch("./api/v1/dot-items");\n'
    )
    calls = extract_js_calls(js, CHUNK_URL)
    by_url = {(rec["method"], rec["url"]): rec for rec in calls}

    assert ("GET", f"{BASE_URL}/configs/banners") in by_url
    assert by_url[("GET", f"{BASE_URL}/configs/banners")].get("params") in (None, [])

    assert ("GET", f"{BASE_URL}/settings") in by_url
    assert by_url[("GET", f"{BASE_URL}/settings")].get("params") in (None, [])

    del_key = ("DELETE", f"{BASE_URL}/channels/{{c}}/messages/{{o}}/delete")
    assert del_key in by_url
    del_params = {(p["name"], p["in"]) for p in by_url[del_key].get("params") or []}
    assert ("c", "path") in del_params
    assert ("o", "path") in del_params
    assert ("Ae", "path") not in del_params

    # Explicit root path param `/${itemId}` stays intact
    assert ("GET", f"{BASE_URL}/{{itemId}}") in by_url
    item_params = {(p["name"], p["in"]) for p in by_url[("GET", f"{BASE_URL}/{{itemId}}")].get("params") or []}
    assert ("itemId", "path") in item_params

    # Relative API calls inside a .js chunk resolve against origin, never /_app/immutable/chunks/
    assert ("GET", f"{BASE_URL}/api/v1/relative-items") in by_url
    assert ("GET", f"{BASE_URL}/api/v1/dot-items") in by_url
    assert not any("/_app/immutable/" in rec["url"] for rec in calls)
    assert not any("dynamicOnly" in rec["url"] for rec in calls)


def test_html_inline_script_preserves_page_relative_paths() -> None:
    html_calls = extract_js_calls('fetch("./items");', "http://127.0.0.1:8080/portal/index.html")
    assert [rec["url"] for rec in html_calls] == ["http://127.0.0.1:8080/portal/items"]


# ---------------------------------------------------------------------------
# 3. Virtual router-group normalization & schema/bundler noise filtering
# ---------------------------------------------------------------------------


def test_extract_spa_routes_strips_virtual_groups_normalizes_brackets_and_filters_noise() -> None:
    js = """
    const routes = [
        { path: "/(app)/admin/settings" },
        { path: "/(app)/(protected)/c/[id]" },
        { path: "/(app)/docs/[...slug]" },
        { path: "/(app)/notes/[[noteId]]" },
        { path: "/(app)" },
        { path: "/(app)/" },
        { path: "/(app)/?tab=billing" },
        { path: "/users/:userId" },
        { path: "/$defs/XYChartAxisConfig" },
        { path: "/$schema" },
        { path: "/_app/version.json" },
        { path: "/_app/immutable/chunks/B0utj4Io.js" },
        { path: "/_next/static/chunks/app.js" },
        { path: "/_next/data/build-42/home.json" },
        { path: "/definitions/term" }
    ];
    const hashSchema = "#/$defs/XYChartAxisConfig";
    const hashGroup = "#/(app)/workspace/:wsId?mode=edit";
    """
    recs = extract_spa_routes(js, CHUNK_URL)
    by_url = {rec["url"]: rec for rec in recs}

    assert f"{BASE_URL}/admin/settings" in by_url
    assert f"{BASE_URL}/c/{{id}}" in by_url
    assert {"name": "id", "in": "path", "sample": ""} in (by_url[f"{BASE_URL}/c/{{id}}"].get("params") or [])
    assert f"{BASE_URL}/docs/{{slug}}" in by_url
    assert f"{BASE_URL}/notes/{{noteId}}" in by_url
    assert f"{BASE_URL}/?tab=billing" in by_url
    assert f"{BASE_URL}/users/{{userId}}" in by_url
    assert f"{BASE_URL}/workspace/{{wsId}}?mode=edit" in by_url
    assert f"{BASE_URL}/definitions/term" in by_url

    # Stripping /(app) to bare / without query must still be skipped
    assert f"{BASE_URL}/" not in by_url

    # Schema pointers and bundler internals must never be emitted
    for url in by_url:
        assert "/(app)" not in url
        assert "/$defs" not in url
        assert "/$schema" not in url
        assert "/_app/" not in url
        assert "/_next/static/" not in url
        assert "/_next/data/" not in url


@pytest.mark.parametrize(
    "noise_path",
    [
        "/_app/immutable/chunks/foo.js",
        "/_app/immutable/chunks/{c}/bar",
        "/_app/immutable/entry/start.js",
        "/_app/version.json",
        "/_next/static/chunks/main-123.js",
        "/_next/data/build-1/index.json",
        "/$defs/XYChartAxisConfig",
        "/$schema",
        "/$ref/Model",
        "/$_internal/meta",
        "#/$defs/XYChartAxisConfig",
        "http://127.0.0.1:8080/_app/immutable/chunks/B0utj4Io.js",
        "http://127.0.0.1:8080/$defs/XYChartAxisConfig",
    ],
)
def test_is_non_endpoint_source_path_rejects_bundler_and_schema_noise(noise_path: str) -> None:
    assert is_non_endpoint_source_path(noise_path) is True


@pytest.mark.parametrize(
    "valid_path",
    [
        "/assets/app.js",
        "/static/bundle.js",
        "/openapi.json",
        "/definitions/term",
        "/_next/image?url=%2Fhero.png&w=640&q=75",
        "/api/v1/configs/banners",
        "/api/v1/channels/{c}/messages/{o}/delete",
        "/c/{id}",
    ],
)
def test_is_non_endpoint_source_path_preserves_js_bundles_and_real_endpoints(valid_path: str) -> None:
    assert is_non_endpoint_source_path(valid_path) is False


def test_openwebui_style_chunk_end_to_end_tracker_preview_and_sharding() -> None:
    js_bundle = (
        'const Ae = "/api/v1";\n'
        'const r1 = { path: "/(app)/admin/settings" };\n'
        'const r2 = { path: "/(app)/c/[id]" };\n'
        'const ref1 = "#/$defs/XYChartAxisConfig";\n'
        'const ver = "/_app/version.json";\n'
        'const chunk = "/_app/immutable/chunks/Other123.js";\n'
        'const nextChunk = "/_next/static/chunks/main.js";\n'
        'const appBundle = "/assets/app.js";\n'
        'fetch(`${Ae}/configs/banners`);\n'
        'fetch(`${Ae}/channels/${c}/messages/${o}/delete`, {method: "POST"});\n'
        'fetch(`${UNRESOLVED}/auths/signin`, {method: "POST", body: JSON.stringify({email: "a"})});\n'
        'fetch("/api/v1/users");\n'
        'fetch("/api/v1/models");\n'
        'fetch("/api/v1/prompts");\n'
        'fetch("/api/v1/files");\n'
        'fetch("/api/v1/knowledge");\n'
        'fetch("/api/v1/tools");\n'
        'fetch("/api/v1/functions");\n'
    )

    summary = _extract_surface_summary(
        {
            "receipt_id": "req-0001",
            "url": CHUNK_URL,
            "status": 200,
            "content_type": "application/javascript",
            "response_headers": {"Content-Type": "application/javascript"},
            "body": js_bundle,
        },
        BASE_URL,
    )
    summary_urls = {
        urlsplit(item["url"]).path or "/"
        for item in [
            *(summary.get("links") or []),
            *(summary.get("js_calls") or []),
            *(summary.get("spa_routes") or []),
        ]
    }
    assert "/api/v1/configs/banners" in summary_urls
    assert "/api/v1/channels/{c}/messages/{o}/delete" in summary_urls
    assert "/auths/signin" in summary_urls
    assert "/admin/settings" in summary_urls
    assert "/c/{id}" in summary_urls
    assert "/assets/app.js" in summary_urls
    assert not any(
        bad in u
        for u in summary_urls
        for bad in ("/_app/", "/_next/static/", "/$defs", "/(app)", "{Ae}", "{UNRESOLVED}", "[id]")
    )

    tracker = SurfaceFrontierTracker(
        base_url=BASE_URL,
        allowed_methods=("GET", "POST", "DELETE"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )
    tracker.ingest_receipt({
        "url": CHUNK_URL,
        "method": "GET",
        "status": 200,
        "content_type": "application/javascript",
        "actor": "alice",
        "body": js_bundle,
    })

    discovered = {p for _, p in tracker.discovered_routes}
    assert "/api/v1/configs/banners" in discovered
    assert "/api/v1/channels/{c}/messages/{o}/delete" in discovered
    assert "/auths/signin" in discovered
    assert "/admin/settings" in discovered
    assert "/c/{id}" in discovered
    assert "/assets/app.js" in discovered

    assert extract_resource_family("/_app/immutable/chunks/B0utj4Io.js") == "root"
    assert extract_resource_family("/_app/version.json") == "root"
    assert extract_resource_family("/_next/static/chunks/main.js") == "root"
    assert extract_resource_family("/$defs/XYChartAxisConfig") == "root"

    clusters = cluster_discovered_surface(tracker, max_shards=3, min_routes_for_sharding=8)
    all_fams = {fam for c in clusters for fam in c.families}
    all_routes = {r for c in clusters for r in c.routes}
    assert "_app" not in all_fams
    assert "_next" not in all_fams
    assert "$defs" not in all_fams
    assert "(app)" not in all_fams
    assert not any("/_app/" in r or "/$defs" in r or "/(app)" in r for r in all_routes)
    assert "/api/v1/configs/banners" in all_routes
    assert "/api/v1/channels/{id}/messages/{id}/delete" in all_routes


# ---------------------------------------------------------------------------
# 4. Base64 / WASM / JS regex-fragment / hashed chunk plausibility filtering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "blob_or_fragment",
    [
        "////8AAAabcdef",
        "/////9+fXy7uvo5ohe2tjv0s",
        "//////fwD//z8A/w==",
        "////8AAAAAAAAAAP7",
        "///api/v1/users",
        "/api//v1/users",
        "http://127.0.0.1:8080///foo",
        "http://127.0.0.1:8080//foo/bar",
        "/9+fxy7uvo5ohe2tjv0s",
        "/+7b",
        "/qw==",
        "/38aap/w8=",
        "/8=",
        "/wo=",
        "/aqaaaaaaap",
        "/weaaaaaap",
        "/8daaaaap",
        "/8aaaaaaaaaap7",
        "/g),c=u.match(",
        "/g,gv=",
        "/-",
        "/---",
        "/api/;",
        "/api/foo*bar",
        "/chunks/30QLxKeF.js",
        "/chunks/vexCXLX9.js",
        "../chunks/vexCXLX9.js",
        "/app/chunks/AbCdEf12.mjs",
    ],
)
def test_noise_path_rejects_base64_wasm_regex_and_hashed_chunks(blob_or_fragment: str) -> None:
    assert is_non_endpoint_noise_path(blob_or_fragment) is True
    assert is_non_endpoint_source_path(blob_or_fragment) is True


@pytest.mark.parametrize(
    "valid_path",
    [
        "/assets/app.js",
        "/static/bundle.js",
        "/api/v1/users",
        "/api/files/{id}",
        "/c/{id}",
        "/users/id=123",
        "/path/file=/etc/passwd",
        "/search?q=${7*7}",
        "/search?q=' OR 1=1--",
        "/search?q=a+b&tok=abc==",
        "/redirect?next=https://example.com//foo",
        "//127.0.0.1:8080/api/v1/users",
        "/api/v1/jobs/507f1f77bcf86cd799439011",
        "/api/v1/jobs/00000aaaaa1234",
        "/api/v1/records/aaaaaaaa-1111-4111-8111-111111111111",
        "/api/v1/records/AAAAAAAA-1111-4111-8111-111111111111",
    ],
)
def test_noise_path_preserves_valid_endpoints_path_kv_and_query_payloads(valid_path: str) -> None:
    assert is_non_endpoint_noise_path(valid_path) is False
    if "AAAAAAAA-1111" not in valid_path:
        assert is_non_endpoint_source_path(valid_path) is False


@pytest.mark.parametrize("short_kv_path", ["/api/items/id=", "/api/search/q="])
def test_noise_path_preserves_known_short_path_keys(short_kv_path: str) -> None:
    assert is_non_endpoint_noise_path(short_kv_path) is False


def test_extract_js_noise_does_not_starve_limit_and_preserves_later_endpoints() -> None:
    noise_literals = [
        "/////9+fXy7uvo5ohe2tjv0s",
        "//////fwD//z8A/w==",
        "////8AAAAAAAAAAP7",
        "////8AAAabcdef",
        "///api/v1/hidden-by-triple-slash",
        "/api//double-slash",
        "/api/v1;eval()",
        "/qw==",
        "/38aap/w8=",
        "/8=",
        "/wo=",
        "/9+fxy7uvo5ohe2tjv0s",
        "/+7b",
        "/aqaaaaaaap",
        "/weaaaaaap",
        "/8daaaaap",
        "/8aaaaaaaaaap7",
        "/g),c=u.match(",
        "/g,gv=",
        "/-",
        "../chunks/vexCXLX9.js",
        "/chunks/30QLxKeF.js",
    ]
    # Add enough varied base64/padding blobs (> limit=10) before real endpoints
    extra_blobs = [f"/blob{i}w8=" for i in range(25)]
    noise_block = "\n".join(f'const n_{i} = "{val}";' for i, val in enumerate([*noise_literals, *extra_blobs]))

    real_endpoints = [
        "/assets/app.js",
        "/static/bundle.js",
        "/api/v1/users",
        "/api/v1/models",
        "/api/v1/files",
        "/api/v1/tools",
        "/api/v1/prompts",
        "/users/id=123",
        "//127.0.0.1:8080/api/v1/health",
        "/(app)/admin/settings",
    ]
    real_block = "\n".join(f'const e_{i} = "{ep}";' for i, ep in enumerate(real_endpoints))

    recs = extract_js(f"{noise_block}\n{real_block}\n", "http://127.0.0.1:8080/app/main.js", limit=10)
    urls = {rec["url"] for rec in recs}

    assert len(recs) == 10
    expected_urls = {
        f"{BASE_URL}/assets/app.js",
        f"{BASE_URL}/static/bundle.js",
        f"{BASE_URL}/api/v1/users",
        f"{BASE_URL}/api/v1/models",
        f"{BASE_URL}/api/v1/files",
        f"{BASE_URL}/api/v1/tools",
        f"{BASE_URL}/api/v1/prompts",
        f"{BASE_URL}/users/id=123",
        f"{BASE_URL}/api/v1/health",
        f"{BASE_URL}/admin/settings",
    }
    assert urls == expected_urls


def test_extract_js_calls_and_spa_routes_reject_implausible_slashes_and_syntax() -> None:
    js = """
    fetch("///masked-triple");
    fetch("/api/v1;eval()");
    fetch("/api/files/${id}");
    fetch("/search?q=a+b&tok=abc==");
    const routes = [
        { path: "/foo//bar" },
        { path: "///triple" },
        { path: "/g),c=u.match(" },
        { path: "/(app)/c/[id]" },
        { path: "/users/id=123" },
    ];
    """
    call_urls = {rec["url"] for rec in extract_js_calls(js, CHUNK_URL)}
    assert f"{BASE_URL}/api/files/{{id}}" in call_urls
    assert any(u.startswith(f"{BASE_URL}/search?") for u in call_urls)
    assert f"{BASE_URL}/masked-triple" not in call_urls
    assert f"{BASE_URL}/api/v1" not in call_urls

    route_urls = {rec["url"] for rec in extract_spa_routes(js, CHUNK_URL)}
    assert f"{BASE_URL}/c/{{id}}" in route_urls
    assert f"{BASE_URL}/users/id=123" in route_urls
    assert f"{BASE_URL}/foo/bar" not in route_urls
    assert f"{BASE_URL}/triple" not in route_urls
    assert not any("u.match" in u for u in route_urls)
