"""Unit tests for frontend source-module/malformed-path filtering and sharding hygiene."""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_preview import _build_surface_hints, _extract_surface_summary  # noqa: E402
from agentic_sharding import cluster_discovered_surface, extract_resource_family  # noqa: E402
from agentic_surface import (  # noqa: E402
    SurfaceFrontierTracker,
    _split_path_kv_segment,
    is_malformed_url_path,
    is_non_endpoint_source_path,
)


# ---------------------------------------------------------------------------
# 1. Direct helper tests: is_malformed_url_path & is_non_endpoint_source_path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_path",
    [
        "/components/ui/button.ts",
        "/components/ui/accordion.ts",
        "/components/ui/dialog.js",
        "/components/ui/popover",
        "http://127.0.0.1:3080/components/ui/button.ts?v=1",
        "/src/components/Header.tsx",
        "/src/components/Modal.js",
        "/src/components/Sidebar",
        "/src/hooks/useAuth.tsx",
        "/src/utils/format.jsx",
        "/src/entry.mjs",
        "/src/config.cjs",
        "/views/Chat.vue",
        "/routes/Panel.svelte",
        "/styles/main.scss",
        "/styles/base.sass",
        "/styles/theme.less",
        "/styles/vars.styl",
        "/types/models.d.ts",
        "/assets/app.js.map",
        "/wasm/tokenizer.wasm",
        "/images/banner.avif",
        "/site.webmanifest",
        "/node_modules/react/index.mjs",
        "/node_modules/react/index.js",
        "/app/node_modules/lodash/fp",
        "/@vite/client",
        "/@vite/env",
        "/@fs/workspace/src/main.ts",
        "/@id/__x00__virtual:pwa-register",
        "/__vite_ping",
        "/__vite/hmr",
        "/@react-refresh",
        "/api/\\",
        "http://127.0.0.1:3080/api/\\",
        "/api/foo\\bar",
        "/api/${foo}",
        "/api/${id}/items",
        '/api/"users"',
        "/api/'users'",
        "/api/`users`",
        "/api/bad path",
        "/api/bad\tpath",
        "/api/bad\npath",
        "/api/bad\rpath",
        "/api/bad\x00path",
    ],
)
def test_is_non_endpoint_source_path_rejects_source_bundler_and_malformed(bad_path: str) -> None:
    assert is_non_endpoint_source_path(bad_path) is True


@pytest.mark.parametrize(
    "good_path",
    [
        "/",
        "/api/files",
        "/api/files/{id}",
        "/api/users",
        "/api/convos",
        "/v1/projects/{id}",
        "/assets/app.js",
        "/static/bundle.js",
        "/openapi.json",
        "/graphql",
        "/api/components/123",
        "/components/42",
        "/robots.txt",
        "/sitemap.xml",
        "/search?q=${7*7}",
        "/api/users?q=a b",
        "http://127.0.0.1:3080/api/files/{id}?limit=10",
    ],
)
def test_is_non_endpoint_source_path_preserves_valid_endpoints_and_js_bundles(good_path: str) -> None:
    assert is_non_endpoint_source_path(good_path) is False


def test_is_malformed_url_path_distinguishes_templates_from_broken_escapes() -> None:
    assert is_malformed_url_path("/api/\\") is True
    assert is_malformed_url_path("/api/${foo}") is True
    assert is_malformed_url_path('/api/"quoted"') is True
    assert is_malformed_url_path("/api/'quoted'") is True
    assert is_malformed_url_path("/api/`tick`") is True
    assert is_malformed_url_path("/api/with space") is True
    assert is_malformed_url_path("/api/with\nnewline") is True
    assert is_malformed_url_path("/api/with\x7fdel") is True

    assert is_malformed_url_path("/api/files/{id}") is False
    assert is_malformed_url_path("/v1/projects/{project_id}") is False
    assert is_malformed_url_path("/assets/app.js") is False
    assert is_malformed_url_path("/search?q=' OR 1=1--") is False


# ---------------------------------------------------------------------------
# 2. SurfaceFrontierTracker filtering (JS bundle + ingest_surface + direct)
# ---------------------------------------------------------------------------


def test_surface_frontier_tracker_filters_source_noise_and_preserves_real_routes() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:3080/",
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )

    ui_components = "\n".join(
        f'const ui_{i} = "/components/ui/comp-{i}.ts";'
        for i in range(35)
    )
    js_bundle = (
        ui_components
        + "\n"
        + 'const h1 = "/src/hooks/useAuth.tsx";\n'
        + 'const h2 = "/node_modules/react/index.mjs";\n'
        + 'const h3 = "/@vite/client";\n'
        + 'const h4 = "/styles/main.scss";\n'
        + 'const h5 = "/api/\\\\";\n'
        + 'const h6 = "/api/${foo}";\n'
        + 'const bundle = "/assets/app.js";\n'
        + 'const spec = "/openapi.json";\n'
        + 'fetch("/api/files");\n'
        + 'fetch(`/api/files/${id}`);\n'
        + 'axios.get("/api/users");\n'
        + 'fetch("/api/convos");\n'
        + 'fetch(`/v1/projects/${id}`);\n'
        + 'fetch("/graphql", {method: "POST", body: JSON.stringify({query: "{ viewer { id } }"})});\n'
    )

    tracker.ingest_receipt({
        "url": "http://127.0.0.1:3080/assets/index-abc123.js",
        "method": "GET",
        "status": 200,
        "content_type": "application/javascript; charset=utf-8",
        "actor": "alice",
        "body": js_bundle,
    })

    # Also test direct registration & ingest_surface with noisy/malformed payloads
    for noisy in (
        "/components/ui/button.ts",
        "/src/hooks/useAuth.tsx",
        "/node_modules/react/index.mjs",
        "/@vite/client",
        "/styles/main.scss",
        "/api/\\",
        "/api/${foo}",
        "/api/bad path",
    ):
        tracker._register_discovered_url(noisy, method="GET", actor="alice")

    tracker.ingest_surface(
        {
            "url": "http://127.0.0.1:3080/",
            "links": [
                {"method": "GET", "url": "/components/ui/button.ts"},
                {"method": "GET", "url": "/@vite/client"},
                {"method": "GET", "url": "/api/\\"},
                {"method": "GET", "url": "/api/${foo}"},
                {"method": "GET", "url": "/api/presets"},
            ],
            "spa_routes": [
                {"method": "GET", "url": "/src/components/Dialog.tsx"},
                {"method": "GET", "url": "/api/${foo}"},
            ],
            "client_logic": {
                "endpoints": [
                    {"method": "GET", "path": "/node_modules/react/index.mjs"},
                    {"method": "POST", "path": "/api/keys"},
                ]
            },
        },
        actor="alice",
    )

    discovered_paths = {path for _, path in tracker.discovered_routes}
    assert "/api/files" in discovered_paths
    assert "/api/files/{id}" in discovered_paths
    assert "/api/users" in discovered_paths
    assert "/api/convos" in discovered_paths
    assert "/v1/projects/{id}" in discovered_paths
    assert "/assets/app.js" in discovered_paths
    assert "/openapi.json" in discovered_paths
    assert "/graphql" in discovered_paths
    assert "/api/presets" in discovered_paths
    assert "/api/keys" in discovered_paths

    # None of the noisy paths may leak into discovered_routes or unvisited_routes or ui_resource_families
    for path in discovered_paths:
        assert not is_non_endpoint_source_path(path), f"unexpected noisy route persisted: {path}"
        assert "/components/ui/" not in path
        assert "/src/hooks/" not in path
        assert "/node_modules/" not in path
        assert "/@vite/" not in path
        assert ".scss" not in path
        assert "\\" not in path
        assert "${" not in path
    assert "components" not in tracker.ui_resource_families


# ---------------------------------------------------------------------------
# 3. agentic_preview: _extract_surface_summary & _build_surface_hints
# ---------------------------------------------------------------------------


def test_extract_surface_summary_and_hints_filter_source_and_malformed_paths() -> None:
    ui_components = "\n".join(
        f'const c{i} = "/components/ui/widget-{i}.ts";'
        for i in range(35)
    )
    js_body = (
        ui_components
        + "\n"
        + 'const f1 = "/components/ui/button.ts";\n'
        + 'const f2 = "/src/hooks/useAuth.tsx";\n'
        + 'const f3 = "/node_modules/react/index.mjs";\n'
        + 'const f4 = "/@vite/client";\n'
        + 'const f5 = "/styles/main.scss";\n'
        + 'const bad1 = { path: "/api/\\\\" };\n'
        + 'const bad2 = { path: "/api/${foo}" };\n'
        + 'fetch("/api/files");\n'
        + 'fetch(`/api/files/${id}`);\n'
        + 'fetch("/api/users");\n'
        + 'fetch("/api/convos");\n'
        + 'fetch(`/v1/projects/${id}`);\n'
        + 'const appBundle = "/assets/app.js";\n'
        + 'const specUrl = "/openapi.json";\n'
        + 'const gqlUrl = "/graphql";\n'
    )
    receipt = {
        "receipt_id": "req-0050",
        "url": "http://127.0.0.1:3080/assets/index-main.js",
        "status": 200,
        "content_type": "application/javascript; charset=utf-8",
        "response_headers": {"Content-Type": "application/javascript"},
        "body": js_body,
    }

    summary = _extract_surface_summary(receipt, "http://127.0.0.1:3080")
    all_emitted_urls = [
        *(str(item.get("url") or "") for item in summary.get("links") or []),
        *(str(item.get("url") or "") for item in summary.get("js_calls") or []),
        *(str(item.get("url") or "") for item in summary.get("spa_routes") or []),
        *(str(u) for u in summary.get("spec_urls") or []),
    ]
    cl_eps = [str(ep.get("path") or "") for ep in (summary.get("client_logic") or {}).get("endpoints") or []]
    all_emitted_urls.extend(cl_eps)

    for emitted in all_emitted_urls:
        assert not is_non_endpoint_source_path(emitted), f"noisy URL emitted by _extract_surface_summary: {emitted}"
        assert "/components/ui/" not in emitted
        assert "/src/hooks/" not in emitted
        assert "/node_modules/" not in emitted
        assert "/@vite/" not in emitted
        assert ".scss" not in emitted
        assert "\\" not in emitted
        assert "${" not in emitted

    joined = "\n".join(all_emitted_urls)
    assert "/api/files" in joined
    assert "/api/files/{id}" in joined
    assert "/api/users" in joined
    assert "/api/convos" in joined
    assert "/v1/projects/{id}" in joined
    assert "/assets/app.js" in joined
    assert "/openapi.json" in joined
    assert "/graphql" in joined

    # Also verify HTML page discovery preserves <script src="/assets/app.js"> while dropping /@vite/client & .tsx
    html_receipt = {
        "receipt_id": "req-0051",
        "url": "http://127.0.0.1:3080/",
        "status": 200,
        "content_type": "text/html; charset=utf-8",
        "response_headers": {"Content-Type": "text/html"},
        "body": (
            "<!doctype html><html><head>"
            '<script type="module" src="/@vite/client"></script>'
            '<script type="module" src="/src/main.tsx"></script>'
            '<script src="/assets/app.js"></script>'
            '<link rel="manifest" href="/site.webmanifest">'
            "</head><body>"
            '<a href="/api/files">Files</a>'
            '<a href="/components/ui/button.ts">Btn</a>'
            "</body></html>"
        ),
    }
    html_summary = _extract_surface_summary(html_receipt, "http://127.0.0.1:3080")
    html_links = {item["url"] for item in html_summary["links"]}
    assert "/assets/app.js" in html_links
    assert "/api/files" in html_links
    assert "/@vite/client" not in html_links
    assert "/src/main.tsx" not in html_links
    assert "/site.webmanifest" not in html_links
    assert "/components/ui/button.ts" not in html_links

    hints = _build_surface_hints(html_receipt, "http://127.0.0.1:3080")
    hint_urls = [*(hints.get("api_endpoints") or []), *(hints.get("links") or [])]
    assert "/api/files" in hint_urls
    assert "/assets/app.js" in hint_urls
    assert all(not is_non_endpoint_source_path(u) for u in hint_urls)


# ---------------------------------------------------------------------------
# 4. agentic_sharding: family hygiene & balanced API sharding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "weird_path",
    [
        "/api/\\",
        "/\\",
        "\\",
        "/api/.",
        "/api/..",
        "/api/*",
        "/.",
        "/..",
        "/*",
        "/---",
        "/___",
        "/api/${foo}",
        '/api/"bad"',
        "/api/bad path",
    ],
)
def test_extract_resource_family_never_returns_backslash_or_punctuation_only(weird_path: str) -> None:
    fam = extract_resource_family(weird_path)
    assert fam == "root"
    assert "\\" not in fam
    assert any(ch.isalnum() for ch in fam)


def test_cluster_discovered_surface_never_wastes_shard_on_components_or_backslash() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:3080/",
        allowed_methods=("GET", "POST", "PUT", "DELETE"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )

    # Even if a legacy checkpoint or manual seed directly injected 35 /components/ui/*.ts
    # paths and /api/\ into discovered_routes / visited_method_templates, clustering must drop them.
    for i in range(35):
        p = f"/components/ui/component-{i}.ts"
        tracker.discovered_routes[("GET", p)] = p
        tracker.visited_method_templates.add(("GET", p))
    tracker.discovered_routes[("GET", "/api/\\")] = "/api/\\"
    tracker.discovered_routes[("GET", "/api/${foo}")] = "/api/${foo}"
    tracker.discovered_routes[("GET", "/@vite/client")] = "/@vite/client"

    api_families = ("files", "users", "convos", "prompts", "tags", "roles", "presets", "keys")
    for fam in api_families:
        tracker.discovered_routes[("GET", f"/api/{fam}")] = f"/api/{fam}"
        tracker.discovered_routes[("GET", f"/api/{fam}/{{id}}")] = f"/api/{fam}/{{id}}"
    tracker.declared_write_ops.add(("POST", "/api/files"))
    tracker.declared_write_ops.add(("POST", "/api/convos"))
    tracker.declared_write_ops.add(("PUT", "/api/presets/{id}"))
    tracker.discovered_objects["/api/files/file-101"] = {
        "path": "/api/files/file-101",
        "template": "/api/files/{id}",
        "owner_actor": "alice",
        "seen_by": {"alice"},
        "listed_by": {"alice"},
        "tested_by": set(),
        "verified_2xx": True,
    }

    clusters = cluster_discovered_surface(tracker, max_shards=4, min_routes_for_sharding=8)
    assert len(clusters) == 4

    all_fams = [fam for c in clusters for fam in c.families]
    assert "components" not in all_fams
    assert "\\" not in all_fams
    assert all(any(ch.isalnum() for ch in fam) for fam in all_fams)
    assert set(api_families).issubset(set(all_fams))

    # Every shard must own at least one real API family (no shard wasted on junk)
    for cluster in clusters:
        assert any(fam in api_families for fam in cluster.families)
        assert all(not is_non_endpoint_source_path(r) for r in cluster.routes)


def test_cluster_discovered_surface_caps_static_readonly_route_bloat() -> None:
    """Even legitimate non-API read-only path bloat (35 /docs/* routes) must not monopolize a shard."""
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:3080/",
        allowed_methods=("GET", "POST"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )
    for i in range(35):
        p = f"/docs/section-{i}"
        tracker.discovered_routes[("GET", p)] = p

    api_families = ("files", "users", "convos", "prompts", "tags", "roles", "presets", "keys")
    for fam in api_families:
        tracker.discovered_routes[("GET", f"/api/{fam}")] = f"/api/{fam}"

    clusters_a = cluster_discovered_surface(tracker, max_shards=3, min_routes_for_sharding=8)
    clusters_b = cluster_discovered_surface(tracker, max_shards=3, min_routes_for_sharding=8)

    # Deterministic output
    assert [(c.shard_id, c.families, c.routes) for c in clusters_a] == [
        (c.shard_id, c.families, c.routes) for c in clusters_b
    ]
    assert len(clusters_a) == 3

    # `docs` must NEVER occupy a shard exclusively by itself while API families are crowded elsewhere
    for cluster in clusters_a:
        assert cluster.families != ["docs"]
        api_in_shard = [f for f in cluster.families if f in api_families]
        assert len(api_in_shard) >= 2, f"shard {cluster.shard_id} under-allocated API families: {cluster.families}"


# ---------------------------------------------------------------------------
# 5. Open WebUI JS-bundle base64, regex-fragment, WASM zero-run, & chunk noise
# ---------------------------------------------------------------------------

_OPENWEBUI_NOISE_FRAGMENTS = (
    "/////9...",
    "////9",
    "///wH///9//wM=",
    "////////////////////////////////////8AAAAAAAAAAP7...",
    "/g),c=u.match(",
    "/g,gv=",
    "/(app)/admin/settings",
    "/w8=",
    "/qw==",
    "/wo=",
    "/8=",
    "/gv=",
    "/9+fxy7uvo5ohe2tjv0s",
    "/+7b",
    "/-",
    "/aqaaaaaaap",
    "/weaaaaaap",
    "/8daaaaap",
    "/8aaaaaaaaaap7",
    "/chunks/30QLxKeF.js",
    "/chunks/30QLxKeF.mjs",
    "/static/chunks/30QLxKeF.js",
)


def test_is_malformed_url_path_rejects_double_slashes_and_js_regex_punctuation() -> None:
    for bad in (
        "/////9...",
        "////9",
        "///wH///9//wM=",
        "////////////////////////////////////8AAAAAAAAAAP7...",
        "////foo",
        "///9",
        "///",
        "http://127.0.0.1:8080//foo",
        "http://127.0.0.1:8080/a//b",
        "/g),c=u.match(",
        "/g,gv=",
        "/(app)/admin/settings",
        "/api/foo;bar",
        "/api/*",
    ):
        assert is_malformed_url_path(bad) is True, f"expected malformed path: {bad}"

    for good in (
        "http://127.0.0.1:8080/a/b",
        "http://127.0.0.1:8080/api/files/{id}?limit=10",
        "/search?q=${7*7}",
        "/search?q=' OR 1=1--",
        "/search?q=a+b&expr=(1,2);*",
        "/api/files/{id}",
        "/assets/app.js",
        "/static/bundle.js",
        "/users/id=123",
        "/file=../../etc/passwd",
        "/proxy=http://127.0.0.1:8080/admin",
        "/proxy=https://example.com/a/b",
    ):
        assert is_malformed_url_path(good) is False, f"expected valid path: {good}"


@pytest.mark.parametrize("noise_path", _OPENWEBUI_NOISE_FRAGMENTS)
def test_is_non_endpoint_source_path_and_family_reject_base64_wasm_and_chunk_noise(noise_path: str) -> None:
    assert is_non_endpoint_source_path(noise_path) is True
    assert extract_resource_family(noise_path) == "root"


def test_blob_filter_and_split_path_kv_preserve_valid_params_hex_ids_and_bundles() -> None:
    for valid in (
        "/search?q=${7*7}",
        "/search?q=' OR 1=1--",
        "/search?q=a+b",
        "/assets/app.js",
        "/static/bundle.js",
        "/api/files/{id}",
        "/users/id=123",
        "/file=abc.txt",
        "/file=/etc/passwd",
        "/api/items/id=",
        "/api/search/q=",
        "/api/files/0123456789abcdef00000aaaaa123456",
        "/api/chunks/123",
    ):
        assert is_non_endpoint_source_path(valid) is False, f"false positive on valid path: {valid}"

    assert is_non_endpoint_source_path("/file=../../etc/passwd") is False
    assert is_non_endpoint_source_path("/proxy=http://127.0.0.1:8080/admin") is False
    assert is_non_endpoint_source_path("/api/v1/records/aaaaaaaa-1111-4111-8111-111111111111") is False

    # Short/base64 empty-value `=` segments must NOT register as path:kv= parameters
    for bad_kv in ("wo=", "gv=", "8=", "w8=", "w8g=", "qw==", "wM="):
        assert _split_path_kv_segment(bad_kv) is None, f"unexpected path kv match: {bad_kv}"
    assert is_non_endpoint_source_path("/abc=") is True

    assert _split_path_kv_segment("file=") == ("file", "")
    assert _split_path_kv_segment("url=") == ("url", "")
    assert _split_path_kv_segment("name=") == ("name", "")
    assert _split_path_kv_segment("id=") == ("id", "")
    assert _split_path_kv_segment("q=") == ("q", "")
    assert _split_path_kv_segment("id=123") == ("id", "123")
    assert _split_path_kv_segment("item=123") == ("item", "123")


def test_tracker_and_sharding_block_base64_wasm_chunk_leaks_and_scrub_legacy_checkpoints() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:3080/",
        allowed_methods=("GET", "POST", "PUT", "DELETE"),
        actor_summaries=[
            {"alias": "alice", "role": "member", "tenant": "t1"},
            {"alias": "bob", "role": "member", "tenant": "t1"},
        ],
    )

    js_lines = "\n".join(f'const junk_{i} = "{p}";' for i, p in enumerate(_OPENWEBUI_NOISE_FRAGMENTS))
    tracker.ingest_receipt({
        "url": "http://127.0.0.1:3080/assets/app.js",
        "method": "GET",
        "status": 200,
        "content_type": "application/javascript",
        "actor": "alice",
        "body": (
            js_lines
            + "\n"
            + 'fetch("/api/v1/chats");\n'
            + 'fetch("/api/v1/chats/chat-101");\n'
            + 'fetch("/users/id=123");\n'
        ),
    })

    for noise in _OPENWEBUI_NOISE_FRAGMENTS:
        tracker._register_discovered_url(noise, method="GET", actor="alice")
        tracker._register_object_path(noise, actor="alice", verified_2xx=True)

    tracker.ingest_surface(
        {
            "url": "http://127.0.0.1:3080/",
            "links": [
                *({"method": "GET", "url": noise} for noise in _OPENWEBUI_NOISE_FRAGMENTS),
                {"method": "GET", "url": "/api/v1/files"},
            ],
        },
        actor="alice",
    )

    assert "/api/v1/chats/chat-101" in tracker.discovered_objects
    for obj_path in tracker.discovered_objects:
        assert not is_non_endpoint_source_path(obj_path)
    untested_objs = tracker.untested_cross_actor_objects()
    assert any("/api/v1/chats/chat-101" in item for item in untested_objs)
    for item in untested_objs:
        assert "////" not in item
        assert "wM=" not in item
        assert "AAAAAAAAAAP" not in item
    assert tracker.discovered_params.get("/users/id={val}") == {"path:id="}

    # Verify legacy checkpoint restoration scrubs pre-existing noisy entries
    dirty_checkpoint = tracker.to_dict()
    dirty_checkpoint["discovered_routes"].extend([["GET", noise, noise] for noise in _OPENWEBUI_NOISE_FRAGMENTS])
    dirty_checkpoint["discovered_objects"]["///wH///9//wM="] = {
        "path": "///wH///9//wM=",
        "template": "/wh/{id}/wm=",
        "owner_actor": "alice",
        "seen_by": ["alice"],
        "listed_by": [],
        "tested_by": [],
        "verified_2xx": True,
    }
    dirty_checkpoint["discovered_objects"]["/api/v1/chats/w8="] = {
        "path": "/api/v1/chats/w8=",
        "template": "/api/v1/chats/{val}",
        "owner_actor": "alice",
        "seen_by": ["alice"],
        "listed_by": [],
        "tested_by": [],
        "verified_2xx": True,
    }
    dirty_checkpoint["discovered_params"]["/g,gv="] = ["path:g,gv="]
    dirty_checkpoint["discovered_write_ops"].append(["POST", "/chunks/30QLxKeF.js", "/chunks/30QLxKeF.js"])
    dirty_checkpoint["declared_write_ops"].append(["POST", "/chunks/30QLxKeF.js"])

    restored = SurfaceFrontierTracker.from_dict(dirty_checkpoint)
    assert "///wH///9//wM=" not in restored.discovered_objects
    assert "/api/v1/chats/w8=" not in restored.discovered_objects
    assert "/g,gv=" not in restored.discovered_params
    assert all(not is_non_endpoint_source_path(p) for _, p in restored.discovered_routes)
    assert all(not is_non_endpoint_source_path(item.split(" ", 2)[1]) for item in restored.unvisited_routes())
    assert all("wM=" not in item and "w8=" not in item for item in restored.untested_cross_actor_objects())
    assert all("/chunks/" not in item for item in restored.untested_write_ops())

    # Clustering with manually injected legacy noise + real API families never creates junk families
    api_families = ("files", "users", "convos", "prompts", "tags", "roles", "presets", "keys")
    for fam in api_families:
        restored.discovered_routes[("GET", f"/api/{fam}")] = f"/api/{fam}"
        restored.discovered_routes[("GET", f"/api/{fam}/{{id}}")] = f"/api/{fam}/{{id}}"
    for noise in _OPENWEBUI_NOISE_FRAGMENTS:
        restored.discovered_routes[("GET", noise)] = noise

    clusters = cluster_discovered_surface(restored, max_shards=4, min_routes_for_sharding=8)
    all_fams = {fam for c in clusters for fam in c.families}
    junk_fams = {
        "9+fxy7uvo5ohe2tjv0s",
        "aqaaaaaaap",
        "weaaaaaap",
        "8daaaaap",
        "8aaaaaaaaaap7",
        "g,gv=",
        "8=",
        "wo=",
        "w8=",
        "qw==",
        "gv=",
        "chunks",
        "(app)",
    }
    assert all_fams.isdisjoint(junk_fams)
    assert set(api_families).issubset(all_fams)
    for cluster in clusters:
        assert all(not is_non_endpoint_source_path(r) for r in cluster.routes)
        assert all(not is_non_endpoint_source_path(o) for o in cluster.objects)
