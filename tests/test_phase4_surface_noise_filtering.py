"""Unit tests for Faz 4C: OS filesystem path, remaining SDK, and hashed asset chunk noise filtering."""
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
from agentic_preview import (  # noqa: E402
    _build_surface_hints,
    _extract_surface_summary,
    _is_skipped_surface_url,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_stage0_crawl import _Stage0Collector, _finalize_routes, _is_stage0_noise_path  # noqa: E402
from agentic_surface import SurfaceFrontierTracker, is_non_endpoint_source_path  # noqa: E402
from kryon_core.surface.extract import (  # noqa: E402
    extract_html,
    extract_js,
    extract_js_calls,
    extract_json_hypermedia,
    extract_spa_routes,
    is_hashed_asset_chunk_path,
    is_non_endpoint_noise_path,
)
from kryon_core.surface.normalize import (  # noqa: E402
    discovery_link_skip_reason,
    has_google_identity_sdk_context,
    is_os_filesystem_path,
    is_third_party_sdk_static_route,
)

ORIGIN = "http://127.0.0.1:8188"


def _make_client(tmp_path: Path, base_url: str = ORIGIN) -> AgenticHTTPClient:
    return AgenticHTTPClient(
        base_url=base_url,
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        actors=ActorManager([{"alias": "anon", "role": "anonymous"}]),
        allowed_methods=("GET", "HEAD", "POST"),
        max_requests=50,
    )


# ---------------------------------------------------------------------------
# 1. OS Filesystem Path filtering (Unix & Windows)
# ---------------------------------------------------------------------------

OS_FILESYSTEM_PATHS = (
    "/var/www/html/app/index/controller/User.php",
    "/var/www/html/app/common/model/Download.php",
    "/var/www/html/app/admin/controller/login.php",
    "/var/www/html/vendor/autoload.php",
    "/var/log/nginx/error.log",
    "/var/tmp/php_upload_123",
    "/var/run/docker.sock",
    "/var/lib/mysql/data",
    "/var/cache/nginx/proxy_temp",
    "/usr/local/lib/python3.12/site-packages/foo.py",
    "/usr/lib/x86_64-linux-gnu/libc.so",
    "/usr/share/doc/README",
    "/usr/bin/python3",
    "/usr/include/stdio.h",
    "/etc/nginx/nginx.conf",
    "/etc/passwd",
    "/opt/app/server.py",
    "/root/.ssh/id_rsa",
    "/proc/self/environ",
    "/proc/1/cmdline",
    "/sys/class/net/eth0",
    "/tmp/session_cache",
    "/srv/www/index.php",
    "/mnt/data/backup.tar",
    "/private/var/folders/tmp/file",
    "/Users/username/Documents/ComfyUI",
    "/Users/alice/.config/settings.json",
    "/home/alice/Documents/notes.txt",
    "/home/ubuntu/projects/webapp",
    "/home/ubuntu/src/main.py",
    "/home/ubuntu/.ssh/authorized_keys",
    "/home/deploy/service.conf",
    "C:/inetpub/wwwroot/index.php",
    "/C:/inetpub/wwwroot/index.php",
    r"C:\inetpub\wwwroot\index.php",
)

LEGITIMATE_WEB_ROUTES = (
    "/users",
    "/users/42",
    "/users/profile",
    "/users/42/settings",
    "/home",
    "/home/feed",
    "/home/dashboard",
    "/home/index/index.php",
    "/api/download?file=/etc/passwd",
    "/api/v1/token",
    "/admin/index.html",
    "/index/Article/info.html",
    "/sys/user/list",
    "/sys/login",
    "/file=../../etc/passwd",
)


@pytest.mark.parametrize("os_path", OS_FILESYSTEM_PATHS)
def test_os_filesystem_paths_are_rejected_across_filters(os_path: str) -> None:
    assert is_os_filesystem_path(os_path) is True
    assert is_non_endpoint_noise_path(os_path) is True
    assert is_non_endpoint_source_path(os_path) is True
    assert _is_skipped_surface_url(os_path, base_url=ORIGIN) is True
    assert _is_stage0_noise_path(os_path, origin_url=ORIGIN) is True

    if os_path.startswith("/"):
        full_url = f"{ORIGIN}{os_path}"
        assert is_os_filesystem_path(full_url) is True
        assert discovery_link_skip_reason(full_url) == "os_filesystem_path"


@pytest.mark.parametrize("web_route", LEGITIMATE_WEB_ROUTES)
def test_legitimate_web_routes_are_preserved_by_os_path_filter(web_route: str) -> None:
    assert is_os_filesystem_path(web_route) is False
    assert is_non_endpoint_noise_path(web_route) is False
    assert is_non_endpoint_source_path(web_route) is False
    assert _is_skipped_surface_url(web_route, base_url=ORIGIN) is False
    assert _is_stage0_noise_path(web_route, origin_url=ORIGIN) is False

    full_url = f"{ORIGIN}{web_route}"
    assert is_os_filesystem_path(full_url) is False
    assert discovery_link_skip_reason(full_url) != "os_filesystem_path"


def test_discovery_link_skip_reason_allows_etc_passwd_in_query_param() -> None:
    assert discovery_link_skip_reason(f"{ORIGIN}/api/download?file=/etc/passwd") == ""
    assert discovery_link_skip_reason(f"{ORIGIN}/etc/passwd") == "os_filesystem_path"
    assert discovery_link_skip_reason(f"{ORIGIN}/var/www/html/app/admin/controller/login.php") == "os_filesystem_path"


def test_html_exception_trace_and_json_hypermedia_filter_os_paths_and_keep_real_routes(
    tmp_path: Path,
) -> None:
    html = (
        "<!doctype html><html><body>"
        "<pre class='trace'>"
        "Error in /var/www/html/app/index/controller/User.php on line 42\n"
        "Called from /var/www/html/app/common/model/Download.php\n"
        "Called from /var/www/html/app/admin/controller/login.php\n"
        "Called from /var/www/html/vendor/autoload.php\n"
        "Config: /etc/nginx/nginx.conf\n"
        "Python: /usr/local/lib/python3.12/site-packages/foo.py\n"
        "WinTrace: C:/inetpub/wwwroot/index.php\n"
        "</pre>"
        '<a href="/admin/index.html">Admin</a>'
        '<a href="/index/Article/info.html">Article</a>'
        '<a href="/users/42">User 42</a>'
        '<a href="/home/feed">Feed</a>'
        '<a href="/api/download?file=/etc/passwd">Download</a>'
        "</body></html>"
    )
    records = extract_html(html, f"{ORIGIN}/")
    paths = {urlsplit(r["url"]).path for r in records}

    assert "/admin/index.html" in paths
    assert "/index/Article/info.html" in paths
    assert "/users/42" in paths
    assert "/home/feed" in paths
    assert "/api/download" in paths
    assert any(r["url"].endswith("/api/download?file=%2Fetc%2Fpasswd") for r in records)

    for p in paths:
        assert not p.startswith(("/var/", "/usr/", "/etc/", "/inetpub/", "/C:")), f"OS path leaked: {p}"

    hypermedia, _ = extract_json_hypermedia(
        {
            "links": [
                "/var/www/html/app/index/controller/User.php",
                "/Users/username/Documents/ComfyUI",
                "/etc/nginx/nginx.conf",
                "C:/inetpub/wwwroot/index.php",
                "/users/42",
                "/api/download?file=/etc/passwd",
            ]
        },
        f"{ORIGIN}/api/meta",
        origin_url=ORIGIN,
    )
    hm_paths = {urlsplit(item["url"]).path for item in hypermedia}
    assert hm_paths == {"/users/42", "/api/download"}

    tracker = SurfaceFrontierTracker(base_url=ORIGIN, allowed_methods=("GET", "POST"))
    tracker.ingest_receipt({
        "url": f"{ORIGIN}/index/index/search.html",
        "method": "GET",
        "status": 200,
        "content_type": "text/html",
        "actor": "anon",
        "body": html,
    })
    discovered_paths = {p for _, p in tracker.discovered_routes}
    assert {"/admin/index.html", "/index/Article/info.html", "/users/42", "/home/feed", "/api/download"}.issubset(
        discovered_paths
    )
    assert not any(is_os_filesystem_path(p) for p in discovered_paths)

    # Checkpoint scrubbing removes legacy OS filesystem entries
    dirty = tracker.to_dict()
    dirty["discovered_routes"].append(
        ["GET", "/var/www/html/app/index/controller/User.php", "/var/www/html/app/index/controller/User.php"]
    )
    restored = SurfaceFrontierTracker.from_dict(dirty)
    assert ("GET", "/var/www/html/app/index/controller/User.php") not in restored.discovered_routes

    # Stage 0 fusion yields clean hints without OS paths
    collector = _Stage0Collector(_make_client(tmp_path))
    summary = _extract_surface_summary(
        {
            "receipt_id": "req-trace",
            "url": f"{ORIGIN}/",
            "status": 200,
            "content_type": "text/html",
            "response_headers": {"Content-Type": "text/html"},
            "body": html,
        },
        ORIGIN,
    )
    collector.ingest_surface_summary(summary, source_url=f"{ORIGIN}/")
    links, _forms, _bt, _mp, discovery_hints = _finalize_routes(collector)
    all_stage0 = {item["url"] for item in links} | set(discovery_hints)
    assert not any(is_os_filesystem_path(u) for u in all_stage0)
    assert "/admin/index.html" in all_stage0
    assert "/index/Article/info.html" in all_stage0


# ---------------------------------------------------------------------------
# 2. Remaining Google Identity Toolkit / Firebase static SDK paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sdk_path",
    [
        "/v2/recaptchaConfig",
        "/v2/passwordPolicy",
        "/v2/projectConfig",
        "/v1/recaptchaParams",
        "/v1/projects/{projectId}/databases/(default)/documents",
        "/v1/projects/my-proj/accounts:lookup",
    ],
)
def test_remaining_firebase_sdk_paths_filtered(sdk_path: str) -> None:
    assert is_third_party_sdk_static_route(sdk_path) is True
    assert is_third_party_sdk_static_route(f"{ORIGIN}{sdk_path}?key=abc") is True


def test_v1_token_filtered_only_in_google_identity_sdk_context() -> None:
    # Globally preserved for non-SDK OAuth apps
    assert is_third_party_sdk_static_route("/v1/token") is False
    assert is_third_party_sdk_static_route("/api/v1/token") is False
    assert is_third_party_sdk_static_route("/v1/projects") is False
    assert is_third_party_sdk_static_route("/v1/projects/{id}") is False

    # Filtered when sdk_context=True, while /api/v1/token remains preserved
    assert is_third_party_sdk_static_route("/v1/token", sdk_context=True) is True
    assert is_third_party_sdk_static_route("/api/v1/token", sdk_context=True) is False

    firebase_js = "\n".join([
        'const AUTH_HOST = "identitytoolkit.googleapis.com";',
        'const TOKEN_HOST = "securetoken.googleapis.com";',
        'const EP_TOKEN = "/v1/token";',
        'const EP_RECAPTCHA = "/v2/recaptchaConfig";',
        'const EP_POLICY = "/v2/passwordPolicy";',
        'const EP_EXAMPLE = "/Users/username/Documents/ComfyUI";',
        'fetch("/v1/token", {method: "POST"});',
        'fetch("/v2/recaptchaConfig");',
        'fetch("/v2/passwordPolicy");',
        'fetch("/api/v1/token", {method: "POST"});',
        'fetch("/api/userdata");',
        'const routes = [{ path: "/v2/recaptchaConfig" }, { path: "/users/42" }];',
    ])
    assert has_google_identity_sdk_context(firebase_js) is True
    bundle_url = f"{ORIGIN}/assets/index-B9xK2mQp.js"

    js_paths = {urlsplit(r["url"]).path for r in extract_js(firebase_js, bundle_url)}
    call_paths = {urlsplit(r["url"]).path for r in extract_js_calls(firebase_js, bundle_url)}
    spa_paths = {urlsplit(r["url"]).path for r in extract_spa_routes(firebase_js, bundle_url)}

    for noisy in ("/v1/token", "/v2/recaptchaConfig", "/v2/passwordPolicy", "/Users/username/Documents/ComfyUI"):
        assert noisy not in js_paths
        assert noisy not in call_paths
        assert noisy not in spa_paths

    assert "/api/v1/token" in js_paths
    assert "/api/userdata" in js_paths
    assert "/api/v1/token" in call_paths
    assert "/api/userdata" in call_paths
    assert "/users/42" in spa_paths

    # Non-Firebase OAuth JS bundle MUST preserve /v1/token
    oauth_js = (
        'const tokenEndpoint = "/v1/token";\n'
        'fetch("/v1/token", {method: "POST", body: JSON.stringify({grant_type: "client_credentials"})});\n'
        'fetch("/api/v1/token", {method: "POST"});\n'
    )
    assert has_google_identity_sdk_context(oauth_js) is False
    oauth_js_paths = {urlsplit(r["url"]).path for r in extract_js(oauth_js, f"{ORIGIN}/assets/app.js")}
    oauth_call_paths = {urlsplit(r["url"]).path for r in extract_js_calls(oauth_js, f"{ORIGIN}/assets/app.js")}
    assert "/v1/token" in oauth_js_paths
    assert "/v1/token" in oauth_call_paths
    assert "/api/v1/token" in oauth_call_paths


# ---------------------------------------------------------------------------
# 3. Hashed / static frontend asset chunks excluded from discovery_hints
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "chunk_path",
    [
        "/assets/ServerConfigPanel-D6a37zVp.js",
        "/assets/UserPanel-C2SgClXS.js",
        "/assets/index-8f3a1c2d.js",
        "/assets/vendor.a1b2c3d4.chunk.js",
        "/assets/style-C2SgClXS.css",
        "/static/js/main-4f9e2a1b.mjs",
        "/chunks/30QLxKeF.js",
        "/nodes/2.DVl3_4LU.js",
    ],
)
def test_hashed_asset_chunk_paths_detected_and_filtered(chunk_path: str) -> None:
    assert is_hashed_asset_chunk_path(chunk_path) is True
    assert is_non_endpoint_noise_path(chunk_path) is True
    assert is_non_endpoint_source_path(chunk_path) is True
    assert _is_skipped_surface_url(chunk_path, base_url=ORIGIN) is True
    assert _is_stage0_noise_path(chunk_path, origin_url=ORIGIN) is True


@pytest.mark.parametrize(
    "preserved_path",
    [
        "/assets/app.js",
        "/static/bundle.js",
        "/static/loader-01.js",
        "/assets/index-main.js",
        "/api/v1/plugin.js",
        "/api/v1/plugin-D6a37zVp.js",
        "/files/file=ServerConfigPanel-D6a37zVp.js",
        "/admin/index.html",
        "/users/42",
    ],
)
def test_non_hashed_bundles_and_api_js_routes_not_flagged_as_hashed_chunks(preserved_path: str) -> None:
    assert is_hashed_asset_chunk_path(preserved_path) is False


def test_hashed_chunks_and_static_assets_excluded_from_hints_and_tracker_while_js_body_still_parsed(
    tmp_path: Path,
) -> None:
    chunk_body = "\n".join([
        'const chunk1 = "/assets/ServerConfigPanel-D6a37zVp.js";',
        'const chunk2 = "/assets/UserPanel-C2SgClXS.js";',
        'const css1 = "/assets/index-C2SgClXS.css";',
        'const map1 = "/assets/ServerConfigPanel-D6a37zVp.js.map";',
        'const img1 = "/assets/logo.png";',
        'const svg1 = "/assets/icon.svg";',
        'const font1 = "/assets/inter.woff2";',
        'const unhashedChild = "/assets/helper.js";',
        'const osPath = "/Users/username/Documents/ComfyUI";',
        'const sdk1 = "/v2/recaptchaConfig";',
        'const sdk2 = "/v2/passwordPolicy";',
        'const sdkTok = "/v1/token";',
        'const sdkHost = "identitytoolkit.googleapis.com";',
        'fetch("/api/system_stats");',
        'fetch("/api/v1/token", {method: "POST"});',
        'const userLink = "/users/42";',
    ])
    receipt = {
        "receipt_id": "req-chunk-1",
        "url": f"{ORIGIN}/assets/ServerConfigPanel-D6a37zVp.js",
        "method": "GET",
        "status": 200,
        "content_type": "application/javascript; charset=utf-8",
        "response_headers": {"Content-Type": "application/javascript"},
        "actor": "anon",
        "body": chunk_body,
    }

    # 1. Preview summary & inline hints
    summary = _extract_surface_summary(receipt, ORIGIN)
    hints = _build_surface_hints(receipt, ORIGIN)

    hint_values = [*(hints.get("api_endpoints") or []), *(hints.get("links") or [])]
    assert "/api/system_stats" in hint_values
    assert "/api/v1/token" in hint_values
    for banned in (
        "/assets/ServerConfigPanel-D6a37zVp.js",
        "/assets/UserPanel-C2SgClXS.js",
        "/assets/index-C2SgClXS.css",
        "/assets/ServerConfigPanel-D6a37zVp.js.map",
        "/assets/logo.png",
        "/assets/icon.svg",
        "/assets/inter.woff2",
        "/assets/helper.js",
        "/Users/username/Documents/ComfyUI",
        "/v2/recaptchaConfig",
        "/v2/passwordPolicy",
        "/v1/token",
    ):
        assert banned not in hint_values

    # 2. SurfaceFrontierTracker still parses the hashed JS chunk body for real routes,
    #    while excluding hashed chunks & static assets from discovered_routes/unvisited_routes.
    tracker = SurfaceFrontierTracker(base_url=ORIGIN, allowed_methods=("GET", "POST"))
    tracker.ingest_receipt(receipt)
    discovered_paths = {p for _, p in tracker.discovered_routes}
    unvisited = tracker.unvisited_routes()
    unvisited_paths = {entry.split(" ", 1)[1].split("?", 1)[0].split(" ", 1)[0] for entry in unvisited}

    assert "/api/system_stats" in discovered_paths
    assert "/api/v1/token" in discovered_paths
    assert "/users/42" in discovered_paths
    for noisy in (
        "/assets/ServerConfigPanel-D6a37zVp.js",
        "/assets/UserPanel-C2SgClXS.js",
        "/assets/index-C2SgClXS.css",
        "/assets/logo.png",
        "/assets/icon.svg",
        "/assets/inter.woff2",
        "/Users/username/Documents/ComfyUI",
        "/v2/recaptchaConfig",
        "/v2/passwordPolicy",
        "/v1/token",
    ):
        assert noisy not in discovered_paths
        assert noisy not in unvisited_paths

    # 3. Stage 0 discovery_hints excludes hashed JS/CSS chunks & static assets
    collector = _Stage0Collector(_make_client(tmp_path))
    collector.ingest_surface_summary(summary, source_url=receipt["url"])
    collector.record_route(method="GET", raw_url="/assets/ServerConfigPanel-D6a37zVp.js")
    collector.record_route(method="GET", raw_url="/assets/UserPanel-C2SgClXS.js")
    collector.record_route(method="GET", raw_url="/assets/style.css")
    collector.record_route(method="GET", raw_url="/assets/logo.png")
    collector.record_route(method="GET", raw_url="/assets/icon.svg")
    collector.record_route(method="GET", raw_url="/assets/font.woff2")
    collector.record_route(method="GET", raw_url="/assets/app.js.map")
    links, _forms, _bt, _mp, discovery_hints = _finalize_routes(collector)

    assert "/api/system_stats" in discovery_hints
    assert "/assets/ServerConfigPanel-D6a37zVp.js" not in discovery_hints
    assert "/assets/UserPanel-C2SgClXS.js" not in discovery_hints
    assert not any(
        h.endswith((".js", ".css", ".map", ".png", ".svg", ".woff2"))
        for h in discovery_hints
    )
    assert not any(is_hashed_asset_chunk_path(item["url"]) for item in links)
