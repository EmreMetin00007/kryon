"""Unit tests for host:port-in-path URL hygiene and static third-party cloud SDK route filtering."""
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

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_preview import _build_surface_hints, _extract_surface_summary, _is_skipped_surface_url  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_stage0_crawl import _Stage0Collector, _finalize_routes, _is_stage0_noise_path  # noqa: E402
from agentic_surface import SurfaceFrontierTracker, is_non_endpoint_source_path  # noqa: E402
from kryon_core.js.client_logic import build_client_logic_map  # noqa: E402
from kryon_core.js.compose import compose_js_routes  # noqa: E402
from kryon_core.surface.extract import (  # noqa: E402
    _TEXT_REL_FILE_RE,
    extract_html,
    extract_js,
    extract_js_calls,
    extract_json_hypermedia,
    extract_spa_routes,
)
from kryon_core.surface.normalize import (  # noqa: E402
    is_port_in_path_artifact,
    is_third_party_sdk_static_route,
    normalize_bare_hostport_url,
    normalize_url,
)

ORIGIN_50759 = "http://127.0.0.1:50759"
PAGE_SEARCH = f"{ORIGIN_50759}/index/index/search.html"
ORIGIN_8080 = "http://127.0.0.1:8080"

FIREBASE_SDK_ROUTES = (
    "/v1/accounts:signUp",
    "/v1/accounts:lookup",
    "/v1/accounts:sendOobCode",
    "/v1/accounts:signInWithPassword",
    "/v1/accounts:signInWithCustomToken",
    "/v1/accounts:signInWithEmailLink",
    "/v1/accounts:signInWithIdp",
    "/v1/accounts:signInWithPhoneNumber",
    "/v1/accounts:delete",
    "/v1/accounts:update",
    "/v2/accounts:revokeToken",
    "/v2/accounts/mfaEnrollment:start",
    "/v2/accounts/mfaEnrollment:finalize",
    "/v2/accounts/mfaEnrollment:withdraw",
    "/v2/accounts/mfaSignIn:start",
    "/v2/accounts/mfaSignIn:finalize",
)


def _make_client(tmp_path: Path, base_url: str = ORIGIN_50759) -> AgenticHTTPClient:
    return AgenticHTTPClient(
        base_url=base_url,
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        actors=ActorManager([{"alias": "anon", "role": "anonymous"}]),
        allowed_methods=("GET", "HEAD", "POST"),
        max_requests=50,
    )


# ---------------------------------------------------------------------------
# 1. Bug 1A: Regex & parser extraction hygiene for host:port/path strings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "<li>GET : http://127.0.0.1:50759/index/index/search.html</li>",
        "<li>127.0.0.1:50759/index/Article/info.html</li>",
        "localhost:50759/admin/Upload/index.html",
        "[::1]:50759/admin/config.json",
        "https://external.example:8443/secret/report.html",
        "app-backend:50759/admin/panel.html",
    ],
)
def test_text_rel_file_regex_never_splits_host_port_into_relative_port_path(text: str) -> None:
    matches = [m.group(1) for m in _TEXT_REL_FILE_RE.finditer(text)]
    assert not any(m.startswith(("50759/", "8443/")) for m in matches), f"unexpected port-split match: {matches}"


def test_extract_html_prevents_port_in_path_splitting_and_preserves_real_routes() -> None:
    html = (
        "<!doctype html><html><body>"
        "<div class='trace'><ul>"
        "<li>GET : http://127.0.0.1:50759/index/index/search.html</li>"
        "<li>127.0.0.1:50759/index/Article/info.html</li>"
        "<li>127.0.0.1:9999/other-port/secret.html</li>"
        "<li>localhost:50759/admin/Upload/index.html</li>"
        "<li>[::1]:50759/admin/config.json</li>"
        "<li>https://external.example:8443/secret/report.html</li>"
        "<li>REF: /orders/8080/details.html</li>"
        "</ul></div>"
        '<a href="127.0.0.1:50759/index/Article/info.html">Article</a>'
        '<a href="/api/items/50759">Item 50759</a>'
        '<a href="/orders/8080/details">Order 8080</a>'
        "</body></html>"
    )

    records = extract_html(html, PAGE_SEARCH)
    paths = {urlsplit(r["url"]).path for r in records}

    assert "/index/index/search.html" in paths
    assert "/index/Article/info.html" in paths
    assert "/api/items/50759" in paths
    assert "/orders/8080/details" in paths
    assert "/orders/8080/details.html" in paths

    for p in paths:
        assert "/50759/" not in p, f"port-in-path leak: {p}"
        assert "/8443/" not in p, f"off-origin port leak: {p}"
        assert "/9999/" not in p, f"other-port leak: {p}"
        assert "127.0.0.1:50759" not in p, f"embedded host:port leak: {p}"


def test_js_and_json_extractors_preserve_scheme_and_prevent_host_port_corruption() -> None:
    js = (
        'const fullUrl = "http://127.0.0.1:50759/admin/Upload/index.html";\n'
        'const bareHost = "127.0.0.1:50759/index/Article/info.html";\n'
        'const concatUrl = "http://127.0.0.1:50759/api/items/" + itemId;\n'
        'const validItem = "/api/items/50759";\n'
        'const validOrder = "/orders/8080/details";\n'
        "// GET : http://127.0.0.1:50759/index/index/search.html\n"
        "// 127.0.0.1:50759/index/Article/info.html\n"
        'fetch("http://127.0.0.1:50759/admin/Upload/index.html");\n'
        'fetch("127.0.0.1:50759/index/Article/info.html");\n'
        'fetch("/api/items/50759");\n'
    )
    js_url = f"{ORIGIN_50759}/assets/app.js"

    js_paths = {urlsplit(r["url"]).path for r in extract_js(js, js_url)}
    call_paths = {urlsplit(r["url"]).path for r in extract_js_calls(js, js_url)}
    composed = compose_js_routes(js)
    cl_map = build_client_logic_map(js, parser="static")

    assert "/admin/Upload/index.html" in js_paths
    assert "/index/index/search.html" in js_paths
    assert "/index/Article/info.html" in js_paths
    assert "/api/items/50759" in js_paths
    assert "/orders/8080/details" in js_paths

    assert "/admin/Upload/index.html" in call_paths
    assert "/index/Article/info.html" in call_paths
    assert "/api/items/50759" in call_paths

    # compose_js_routes must preserve http:// instead of collapsing into /127.0.0.1:50759/...
    assert f"{ORIGIN_50759}/api/items/{{id}}" in composed["templates"]
    for item in [*composed["literals"], *composed["composed"], *composed["templates"]]:
        assert not item.startswith("/127.0.0.1:50759")
        assert "/50759/" not in item

    # client_logic._norm_path must preserve http:// instead of corrupting to http:/127.0.0.1:50759/...
    ep_paths = [ep["path"] for ep in cl_map["endpoints"]]
    assert f"{ORIGIN_50759}/admin/Upload/index.html" in ep_paths
    assert not any(p.startswith("http:/127.0.0.1") for p in ep_paths)

    # normalize_url & extract_json_hypermedia handle bare host:port and reject malformed http:/
    assert normalize_bare_hostport_url("http:/127.0.0.1:50759/admin/Upload/index.html", base=PAGE_SEARCH) == ""
    assert normalize_url("http:/127.0.0.1:50759/admin/Upload/index.html", base=PAGE_SEARCH) == ""
    assert normalize_url("127.0.0.1:50759/index/Article/info.html", base=PAGE_SEARCH) == f"{ORIGIN_50759}/index/Article/info.html"
    assert normalize_url("/api/items/50759", base=PAGE_SEARCH) == f"{ORIGIN_50759}/api/items/50759"

    hypermedia, _ = extract_json_hypermedia(
        {
            "links": [
                "127.0.0.1:50759/index/Article/info.html",
                "50759/index/index/search.html",
                "/index/index/50759/index/index/search.html",
                "/api/items/50759",
                "/orders/8080/details",
            ]
        },
        f"{ORIGIN_50759}/api/meta",
        origin_url=ORIGIN_50759,
    )
    hm_paths = {urlsplit(item["url"]).path for item in hypermedia}
    assert "/index/Article/info.html" in hm_paths
    assert "/api/items/50759" in hm_paths
    assert "/orders/8080/details" in hm_paths
    assert not any("/50759/" in p or "127.0.0.1:50759" in p for p in hm_paths)


# ---------------------------------------------------------------------------
# 2. Bug 1B: Normalization guards in Stage 0, SurfaceFrontierTracker & Preview
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_path",
    [
        "/50759/index/index/search.html",
        "/50759/admin/Upload/index.html",
        "/50759/admin/Upload/50759/50759/index.html",
        "50759/index/index/search.html",
        "50759/admin/Upload/index.html",
        "./50759/index/search.html",
        "/index/index/50759/index/index/search.html",
        "/index/index/50759/index/Article/info.html",
        "/admin/Upload/50759/admin/Upload/index.html",
        "/index/50759/admin/50759/search.html",
        "/index/index/127.0.0.1:50759/index/Article/info.html",
        f"{ORIGIN_50759}/index/index/50759/index/index/search.html",
        f"{ORIGIN_50759}/50759/admin/Upload/index.html",
    ],
)
def test_port_in_path_guard_rejects_malformed_port_prefix_and_repeated_paths(
    tmp_path: Path,
    bad_path: str,
) -> None:
    assert is_port_in_path_artifact(bad_path, origin_url=ORIGIN_50759) is True
    assert _is_stage0_noise_path(bad_path, origin_url=ORIGIN_50759) is True
    assert _is_skipped_surface_url(bad_path, base_url=ORIGIN_50759) is True

    collector = _Stage0Collector(_make_client(tmp_path, base_url=ORIGIN_50759))
    assert collector.record_route(method="GET", raw_url=bad_path, current_url=PAGE_SEARCH) is False
    assert collector.routes == {}

    tracker = SurfaceFrontierTracker(base_url=ORIGIN_50759, allowed_methods=("GET", "POST"))
    assert tracker._resolve_same_origin(bad_path, current_url=PAGE_SEARCH) is None
    tracker._register_discovered_url(bad_path, method="GET", current_url=PAGE_SEARCH)
    assert tracker.discovered_routes == {}


@pytest.mark.parametrize(
    ("origin", "valid_path"),
    [
        (ORIGIN_50759, "/api/items/50759"),
        (ORIGIN_50759, "/orders/50759/details"),
        (ORIGIN_50759, "/orders/8080/details"),
        (ORIGIN_8080, "/orders/8080/details"),
        (ORIGIN_8080, "/orders/8080/details.html"),
        (ORIGIN_8080, "/api/items/8080"),
        (ORIGIN_50759, "/users/50759/profile/settings"),
        (ORIGIN_50759, "/proxy=http://127.0.0.1:50759/admin"),
        (ORIGIN_50759, "/50759"),
        (ORIGIN_50759, "/index/index/search.html"),
        (ORIGIN_50759, "/index/Article/info.html"),
    ],
)
def test_port_in_path_guard_preserves_legitimate_numeric_id_routes(
    tmp_path: Path,
    origin: str,
    valid_path: str,
) -> None:
    assert is_port_in_path_artifact(valid_path, origin_url=origin) is False
    assert _is_stage0_noise_path(valid_path, origin_url=origin) is False
    assert _is_skipped_surface_url(valid_path, base_url=origin) is False

    collector = _Stage0Collector(_make_client(tmp_path, base_url=origin))
    assert collector.record_route(method="GET", raw_url=valid_path, current_url=origin) is True

    tracker = SurfaceFrontierTracker(base_url=origin, allowed_methods=("GET", "POST"))
    assert tracker._resolve_same_origin(valid_path, current_url=origin) is not None
    tracker._register_discovered_url(valid_path, method="GET", current_url=origin)
    assert ("GET", valid_path) in tracker.discovered_routes


def test_surface_frontier_checkpoint_scrubs_legacy_port_in_path_entries() -> None:
    tracker = SurfaceFrontierTracker(base_url=ORIGIN_50759, allowed_methods=("GET", "POST"))
    tracker._register_discovered_url("/api/items/50759", method="GET")
    tracker._register_discovered_url("/orders/8080/details", method="GET")
    dirty = tracker.to_dict()
    dirty["discovered_routes"].extend([
        ["GET", "/50759/admin/Upload/index.html", "/50759/admin/Upload/index.html"],
        ["GET", "/index/index/50759/index/index/search.html", "/index/index/50759/index/index/search.html"],
    ])
    dirty["discovered_objects"]["/50759/admin/Upload/123"] = {
        "path": "/50759/admin/Upload/123",
        "template": "/{id}/admin/upload/{id}",
        "owner_actor": "",
        "seen_by": [],
        "listed_by": [],
        "tested_by": [],
        "verified_2xx": False,
    }

    restored = SurfaceFrontierTracker.from_dict(dirty)
    routes = {p for _, p in restored.discovered_routes}
    assert "/api/items/50759" in routes
    assert "/orders/8080/details" in routes
    assert "/50759/admin/Upload/index.html" not in routes
    assert "/index/index/50759/index/index/search.html" not in routes
    assert "/50759/admin/Upload/123" not in restored.discovered_objects


def test_end_to_end_html_trace_preview_and_stage0_fusion_yields_clean_routes(tmp_path: Path) -> None:
    html_body = (
        "<!doctype html><html><body>"
        "<ul>"
        "<li>GET : http://127.0.0.1:50759/index/index/search.html</li>"
        "<li>127.0.0.1:50759/index/Article/info.html</li>"
        "</ul>"
        '<a href="/api/items/50759">Item</a>'
        '<a href="/orders/8080/details">Order</a>'
        "</body></html>"
    )
    receipt = {
        "receipt_id": "req-trace-1",
        "url": PAGE_SEARCH,
        "status": 200,
        "content_type": "text/html; charset=utf-8",
        "response_headers": {"Content-Type": "text/html"},
        "body": html_body,
    }

    summary = _extract_surface_summary(receipt, ORIGIN_50759)
    collector = _Stage0Collector(_make_client(tmp_path, base_url=ORIGIN_50759))
    collector.ingest_surface_summary(summary, source_url=PAGE_SEARCH)
    links, _forms, _bt, _mp, hints = _finalize_routes(collector)

    all_urls = {item["url"] for item in links} | set(hints)
    assert "/index/index/search.html" in all_urls
    assert "/index/Article/info.html" in all_urls
    assert "/api/items/50759" in all_urls
    assert "/orders/8080/details" in all_urls
    assert not any("/50759/" in u for u in all_urls)


# ---------------------------------------------------------------------------
# 3. Bug 2: Third-party cloud auth SDK constants in static JS bundles
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sdk_route", FIREBASE_SDK_ROUTES)
def test_is_third_party_sdk_static_route_matches_firebase_identity_toolkit(sdk_route: str) -> None:
    assert is_third_party_sdk_static_route(sdk_route) is True
    assert is_third_party_sdk_static_route(f"{ORIGIN_8080}{sdk_route}?key=fake") is True


@pytest.mark.parametrize(
    "app_route",
    [
        "/api/v1/accounts/profile",
        "/api/userdata",
        "/manager/version",
        "/v1/accounts/profile",
        "/v1/accounts/123",
        "/v1/accounts/{id}",
        "/v1/accounts/:id",
        "/v1/projects",
        "/v1/token",
        "/api/v1/auth/login",
    ],
)
def test_is_third_party_sdk_static_route_preserves_genuine_app_routes(app_route: str) -> None:
    assert is_third_party_sdk_static_route(app_route) is False


def test_static_js_extractors_preview_and_stage0_filter_firebase_sdk_and_keep_app_routes(tmp_path: Path) -> None:
    firebase_bundle = "\n".join([
        'const ENDPOINTS = {',
        '  SIGN_UP: "/v1/accounts:signUp",',
        '  LOOKUP: "/v1/accounts:lookup",',
        '  SEND_OOB: "/v1/accounts:sendOobCode",',
        '  SIGN_IN_PW: "/v1/accounts:signInWithPassword",',
        '  SIGN_IN_CUSTOM: "/v1/accounts:signInWithCustomToken",',
        '  SIGN_IN_EMAIL_LINK: "/v1/accounts:signInWithEmailLink",',
        '  SIGN_IN_IDP: "/v1/accounts:signInWithIdp",',
        '  SIGN_IN_PHONE: "/v1/accounts:signInWithPhoneNumber",',
        '  DELETE: "/v1/accounts:delete",',
        '  UPDATE: "/v1/accounts:update",',
        '  REVOKE: "/v2/accounts:revokeToken",',
        '  MFA_START: "/v2/accounts/mfaEnrollment:start",',
        "};",
        'fetch("/v1/accounts:signInWithPassword", {method: "POST", body: JSON.stringify({email: "a"})});',
        'fetch(`/v1/accounts:${action}`, {method: "POST"});',
        'const routerDef = [{ path: "/v1/accounts:signUp" }, { path: "/manager/version" }];',
        'const appProfile = "/api/v1/accounts/profile";',
        'const appUserData = "/api/userdata";',
        'const appVersion = "/manager/version";',
        'fetch("/api/v1/accounts/profile");',
        'fetch("/api/userdata");',
        'fetch("/manager/version");',
    ])
    bundle_url = f"{ORIGIN_8080}/assets/index-vite.js"

    js_urls = {urlsplit(r["url"]).path for r in extract_js(firebase_bundle, bundle_url)}
    call_urls = {urlsplit(r["url"]).path for r in extract_js_calls(firebase_bundle, bundle_url)}
    spa_urls = {urlsplit(r["url"]).path for r in extract_spa_routes(firebase_bundle, bundle_url)}
    composed = compose_js_routes(firebase_bundle)
    cl_map = build_client_logic_map(firebase_bundle, parser="static")

    for sdk_path in FIREBASE_SDK_ROUTES:
        assert sdk_path not in js_urls
        assert sdk_path not in call_urls
        assert sdk_path not in spa_urls
        assert sdk_path not in composed["literals"]
        assert sdk_path not in composed["composed"]
        assert sdk_path not in composed["templates"]
        assert sdk_path not in {ep["path"] for ep in cl_map["endpoints"]}
    assert not any("accounts{" in p or "accounts:" in p for p in js_urls | call_urls | spa_urls)

    assert {"/api/v1/accounts/profile", "/api/userdata", "/manager/version"}.issubset(js_urls)
    assert {"/api/v1/accounts/profile", "/api/userdata", "/manager/version"}.issubset(call_urls)
    assert "/manager/version" in spa_urls
    assert "/api/v1/accounts/profile" in composed["literals"]
    assert "/api/userdata" in composed["literals"]
    assert {"/api/v1/accounts/profile", "/api/userdata", "/manager/version"}.issubset(
        {ep["path"] for ep in cl_map["endpoints"]}
    )

    # Preview summary, inline hints, Stage 0 passive fusion, and discovery_hints
    receipt = {
        "receipt_id": "req-vite-bundle",
        "url": bundle_url,
        "status": 200,
        "content_type": "application/javascript; charset=utf-8",
        "response_headers": {"Content-Type": "application/javascript"},
        "body": firebase_bundle,
    }
    summary = _extract_surface_summary(receipt, ORIGIN_8080)
    hints_inline = _build_surface_hints(receipt, ORIGIN_8080)

    summary_paths = {
        urlsplit(str(item.get("url") or "")).path
        for item in [
            *(summary.get("links") or []),
            *(summary.get("js_calls") or []),
            *(summary.get("spa_routes") or []),
        ]
    }
    assert {"/api/v1/accounts/profile", "/api/userdata", "/manager/version"}.issubset(summary_paths)
    assert not any("accounts:" in p or "accounts{" in p for p in summary_paths)
    for hint_val in [*(hints_inline.get("api_endpoints") or []), *(hints_inline.get("links") or [])]:
        assert "accounts:" not in hint_val

    collector = _Stage0Collector(_make_client(tmp_path, base_url=ORIGIN_8080))
    collector.ingest_surface_summary(summary, source_url=bundle_url)
    links, _forms, _bt, _mp, discovery_hints = _finalize_routes(collector)

    stage0_urls = {item["url"] for item in links} | set(discovery_hints)
    assert {"/api/v1/accounts/profile", "/api/userdata", "/manager/version"}.issubset(stage0_urls)
    assert not any("accounts:" in u or "accounts{" in u for u in stage0_urls)

    # SurfaceFrontierTracker ingesting the JS bundle receipt must also exclude static Firebase SDK routes
    tracker = SurfaceFrontierTracker(base_url=ORIGIN_8080, allowed_methods=("GET", "POST"))
    tracker.ingest_receipt({
        "url": bundle_url,
        "method": "GET",
        "status": 200,
        "content_type": "application/javascript",
        "actor": "anon",
        "body": firebase_bundle,
    })
    discovered_paths = {p for _, p in tracker.discovered_routes}
    assert {"/api/v1/accounts/profile", "/api/userdata", "/manager/version"}.issubset(discovered_paths)
    assert not any("accounts:" in p or "accounts{" in p for p in discovered_paths)


def test_live_observed_network_requests_to_firebase_style_paths_are_never_filtered(tmp_path: Path) -> None:
    live_path = "/v1/accounts:signInWithPassword"
    assert is_non_endpoint_source_path(live_path) is False
    assert _is_stage0_noise_path(live_path, origin_url=ORIGIN_8080) is False

    # Stage 0 live Layer 1 network capture calls record_route directly -> MUST be accepted
    collector = _Stage0Collector(_make_client(tmp_path, base_url=ORIGIN_8080))
    assert collector.record_route(
        method="POST",
        raw_url=f"{ORIGIN_8080}{live_path}",
        params=["email", "password"],
        status=200,
        body_template={"email": "qa@example.test", "password": "secret"},
        body_template_observed=True,
    ) is True
    assert ("POST", live_path) in collector.routes

    # SurfaceFrontierTracker live receipt ingestion -> MUST track visited/2xx state cleanly
    tracker = SurfaceFrontierTracker(base_url=ORIGIN_8080, allowed_methods=("GET", "POST"))
    tracker.ingest_receipt({
        "url": f"{ORIGIN_8080}{live_path}",
        "method": "POST",
        "status": 200,
        "content_type": "application/json",
        "actor": "anon",
        "body": '{"idToken": "tok"}',
    })
    assert ("POST", live_path) in tracker.visited_method_paths
    assert live_path in tracker.route_2xx_actors
