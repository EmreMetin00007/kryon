"""Faz 7E unit tests: API parity 401 guard, 500-delta injection tracking, soft-deny 200, SPA 404 suppression, and non-BSAG fixation telemetry."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_bsag import BeliefStateAttackGraph  # noqa: E402
from agentic_surface import SurfaceFrontierTracker  # noqa: E402
from agentic_telemetry import compute_process_metrics  # noqa: E402


# ---------------------------------------------------------------------------
# 1. PrestaShop-2 API Parity 401 Guard & Storefront Numeric-Slug Filtering
# ---------------------------------------------------------------------------


def test_prestashop_401_on_passive_specs_and_non_json_never_registers_api_prefix() -> None:
    tracker = SurfaceFrontierTracker(base_url="http://shop.local", allowed_methods=("GET", "HEAD"))

    # Storefront HTML with numeric-slug categories and utility routes
    tracker.ingest_receipt({
        "url": "/",
        "method": "GET",
        "status": 200,
        "content_type": "text/html",
        "body": (
            "<html><body>"
            '<a href="/3-clothes">Clothes</a>'
            '<a href="/4-men">Men</a>'
            '<a href="/9-art">Art</a>'
            '<a href="/contact-us">Contact</a>'
            "</body></html>"
        ),
    })

    # PrestaShop Webservice returns 401 on every /api/* spec and non-JSON probe
    for spec_path in ("/api/openapi.json", "/api/swagger.json", "/api/v3/api-docs", "/api/api-docs"):
        tracker.ingest_receipt({
            "url": spec_path,
            "method": "GET",
            "status": 401,
            "content_type": "application/json",
            "body": '{"error":"401"}',
        })
    for non_json_401 in (
        {"url": "/api/categories", "status": 401, "content_type": "text/xml", "body": "<prestashop/>"},
        {"url": "/api/products", "status": 401, "content_type": "text/html", "body": "Unauthorized"},
        {"url": "/api", "status": 401, "content_type": ""},
    ):
        tracker.ingest_receipt({"method": "GET", **non_json_401})

    assert tracker.api_prefix_routes == {}
    assert "3-clothes" not in tracker.ui_resource_families
    assert "4-men" not in tracker.ui_resource_families
    assert "9-art" not in tracker.ui_resource_families
    assert tracker.untested_api_parity() == []
    assert "api_parity_untested" not in tracker.format_frontier_banner(max_chars=1000)


def test_api_prefix_registers_for_real_api_statuses_and_skips_numeric_slugs_and_specs() -> None:
    # 200/302/400/405/422 or non-spec 401/403 JSON registers the prefix cleanly.
    for status, ctype in (
        (200, "text/plain"),
        (302, ""),
        (400, "text/plain"),
        (405, ""),
        (422, ""),
        (401, "application/json"),
        (403, "application/problem+json"),
    ):
        tracker = SurfaceFrontierTracker(base_url="http://app.local")
        tracker.ingest_receipt({"url": "/api/orders", "method": "GET", "status": status, "content_type": ctype})
        assert "/api" in tracker.api_prefix_routes

    # Even when /api is legitimately active, numeric-slug storefront categories and passive specs never emit parity probes.
    tracker = SurfaceFrontierTracker(base_url="http://shop.local")
    tracker.ingest_receipt({"url": "/api/orders", "method": "GET", "status": 200, "content_type": "application/json", "body": "[]"})
    tracker.ingest_receipt({"url": "/3-clothes", "method": "GET", "status": 200, "content_type": "text/html"})
    tracker.ingest_receipt({"url": "/4-men", "method": "GET", "status": 200, "content_type": "text/html"})
    tracker.ingest_receipt({"url": "/invoices/inv-42", "method": "GET", "status": 403, "content_type": "text/html"})
    tracker.ingest_surface(
        {"url": "http://shop.local/", "spec_urls": ["/api/openapi.json", "/api/v3/api-docs"]},
        actor="anon",
    )

    # Also verify a legacy checkpoint carrying polluted entries is scrubbed on load_dict.
    saved = tracker.to_dict()
    saved["api_prefix_routes"]["/api"].append("/api/openapi.json")
    saved["ui_resource_families"]["3-clothes"] = {
        "concrete_ids": [],
        "collection_2xx": True,
        "collection_403": False,
    }
    restored = SurfaceFrontierTracker.from_dict(saved)
    assert "/api/openapi.json" not in restored.api_prefix_routes.get("/api", set())
    assert "3-clothes" not in restored.ui_resource_families
    assert restored.untested_api_parity() == ["GET /api/invoices/inv-42"]


# ---------------------------------------------------------------------------
# 2. 500-Delta Injection Signal (error_delta_params) & Frontier Banner
# ---------------------------------------------------------------------------


def test_error_delta_params_tracks_query_body_reverse_order_and_banner_roundtrip() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://shop.local",
        allowed_methods=("GET", "POST"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )

    # Multi-param query: `page` stays constant ("1") while `order` mutates and triggers 500.
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "GET",
        "url": "/5-women?page=1&order=product.position.asc&csrf_token=tok1",
        "status": 200,
        "content_type": "text/html",
        "body": "<html>items</html>",
    })
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "GET",
        "url": "/5-women?page=1&order=product.position.asc'&csrf_token=tok2",
        "status": 500,
        "content_type": "text/html",
        "body": "SQL syntax error",
    })
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "GET",
        "url": "/5-women?page=1&order=invalid_col&csrf_token=tok3",
        "status": 500,
        "content_type": "text/html",
        "body": "Fatal error",
    })

    assert ("/5-women", "order") in tracker.error_delta_params
    assert ("/5-women", "page") not in tracker.error_delta_params
    assert ("/5-women", "csrf_token") not in tracker.error_delta_params
    entry = tracker.error_delta_params[("/5-women", "order")]
    assert entry["baseline_status"] == 200
    assert entry["error_status"] == 500
    assert entry["count_500"] == 2

    # Reverse order (500 first, 200 baseline second) + active-probe added param without prior param value
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "GET",
        "url": "/catalog?sort=bad'",
        "status": 500,
        "body": "err",
    })
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "GET",
        "url": "/catalog?sort=name",
        "status": 200,
        "body": "ok",
    })
    assert ("/catalog", "sort") in tracker.error_delta_params

    tracker.ingest_receipt({"actor": "alice", "method": "GET", "url": "/search", "status": 200, "body": "ok"})
    tracker.ingest_receipt({"actor": "alice", "method": "GET", "url": "/search?q='", "status": 500, "body": "err"})
    assert ("/search", "q") in tracker.error_delta_params

    # JSON body param 200 -> 500
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "POST",
        "url": "/api/filter",
        "status": 200,
        "request_body": json.dumps({"expr": "price > 0"}),
        "body": "[]",
    })
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "POST",
        "url": "/api/filter",
        "status": 500,
        "request_body": json.dumps({"expr": "price > 0'"}),
        "body": "500",
    })
    assert ("/api/filter", "expr") in tracker.error_delta_params

    # Form-urlencoded POST body param 200 -> 500
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "POST",
        "url": "/api/export",
        "status": 200,
        "request_body": "fmt=csv",
        "body": "ok",
    })
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "POST",
        "url": "/api/export",
        "status": 500,
        "request_body": "fmt={{7*7}}",
        "body": "TemplateError",
    })
    assert ("/api/export", "fmt") in tracker.error_delta_params

    # Cross-checkpoint 200 baseline before save -> 500 probe after restore
    tracker.ingest_receipt({"actor": "alice", "method": "GET", "url": "/reports?kind=daily", "status": 200, "body": "ok"})

    # Banner & alias render_frontier_banner() highlight 500-delta candidates and stay within max_chars
    banner = tracker.render_frontier_banner(max_chars=1000)
    assert banner == tracker.format_frontier_banner(max_chars=1000)
    assert len(banner) <= 1000
    assert "500-delta injection candidates:" in banner
    assert "/5-women?order (200->500, verify SQLi/SSTI/injection)" in banner
    for tight in (300, 180, 60, 0):
        assert len(tracker.render_frontier_banner(max_chars=tight)) <= tight

    # Checkpoint round-trip + legacy fallback
    saved = tracker.to_dict()
    restored = SurfaceFrontierTracker.from_dict(saved)
    assert restored.error_delta_params == tracker.error_delta_params
    assert "/5-women?order (200->500, verify SQLi/SSTI/injection)" in restored.render_frontier_banner(max_chars=1000)
    restored.ingest_receipt({"actor": "alice", "method": "GET", "url": "/reports?kind=daily'", "status": 500, "body": "err"})
    assert ("/reports", "kind") in restored.error_delta_params

    legacy = {k: v for k, v in saved.items() if k not in {"error_delta_params", "param_2xx_values", "param_500_values"}}
    legacy_restored = SurfaceFrontierTracker.from_dict(legacy)
    assert legacy_restored.error_delta_params == {}

    # Bounded size cap at 40 entries across distinct alphabetic route templates
    capped = SurfaceFrontierTracker(base_url="http://shop.local")
    for idx in range(55):
        slug = f"route{chr(97 + idx // 26)}{chr(97 + idx % 26)}"
        capped.ingest_receipt({"method": "GET", "url": f"/{slug}?k=ok", "status": 200, "body": "ok"})
        capped.ingest_receipt({"method": "GET", "url": f"/{slug}?k=bad'", "status": 500, "body": "err"})
    assert len(capped.error_delta_params) == 40


# ---------------------------------------------------------------------------
# 3. Soft-Deny 200 Tracking & SPA Client-Route 404 Suppression
# ---------------------------------------------------------------------------


def test_soft_deny_200_distinguished_from_verified_data_and_short_dummy_bodies() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://wj.local",
        allowed_methods=("GET", "POST"),
        actor_summaries=[
            {"alias": "admin", "role": "admin", "tenant": "t1"},
            {"alias": "member1", "role": "member", "tenant": "t1"},
        ],
    )

    # White-Jotter-4 empty 200 responses for anon and member1 on /api/admin/user
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/api/admin/user",
        "status": 200,
        "response_length": 0,
        "body": "",
    })
    tracker.ingest_receipt({
        "actor": "member1",
        "method": "GET",
        "url": "/api/admin/user",
        "status": 200,
        "response_length": 0,
        "body": "",
    })
    assert "/api/admin/user" not in tracker.route_2xx_actors
    assert tracker.soft_deny_routes["/api/admin/user"] == {"anon", "member1"}
    # Must NOT produce false auth_bypass frontier claiming member1 got real API 200!
    assert tracker.untested_cross_actor_objects() == []

    # JSON envelope soft-denies (401/403/400 with empty/null data/result)
    tracker.ingest_receipt({
        "actor": "member1",
        "method": "GET",
        "url": "/api/admin/audit",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({"code": 403, "message": "forbidden", "result": None}),
    })
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/api/admin/keys",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({"code": 401, "data": []}),
    })
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/api/admin/config",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({"code": 400, "message": "not logged in", "result": None}),
    })
    for p in ("/api/admin/audit", "/api/admin/keys", "/api/admin/config"):
        assert p not in tracker.route_2xx_actors
        assert p in tracker.soft_deny_routes

    # Real data for admin registers in route_2xx_actors and triggers BFLA/auth_bypass frontier when untested by others
    tracker.ingest_receipt({
        "actor": "admin",
        "method": "GET",
        "url": "/api/admin/user",
        "status": 200,
        "response_length": 28,
        "content_type": "application/json",
        "body": '[{"id":1,"name":"admin"}]',
    })
    tracker.ingest_receipt({
        "actor": "admin",
        "method": "GET",
        "url": "/api/admin/role",
        "status": 200,
        "response_length": 24,
        "content_type": "application/json",
        "body": '[{"id":1,"role":"admin"}]',
    })
    assert tracker.route_2xx_actors["/api/admin/user"] == {"admin"}
    assert tracker.route_2xx_actors["/api/admin/role"] == {"admin"}
    untested = tracker.untested_cross_actor_objects()
    assert any("/api/admin/role" in item and "for BFLA" in item for item in untested)
    assert any("/api/admin/role" in item and "for auth_bypass" in item for item in untested)
    # /api/admin/user already tested by anon & member1, so not duplicated in untested_cross_actor_objects
    assert not any("/api/admin/user" in item for item in untested)

    # Short dummy 200 bodies ("{}" and "ok") and leak payloads MUST count in route_2xx_actors
    tracker.ingest_receipt({"actor": "member1", "method": "GET", "url": "/api/ping", "status": 200, "body": "ok"})
    tracker.ingest_receipt({"actor": "member1", "method": "GET", "url": "/api/empty-obj", "status": 200, "body": "{}"})
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/api/leak",
        "status": 200,
        "body": json.dumps({"code": 401, "data": {"token": "leaked-value"}}),
    })
    assert tracker.route_2xx_actors["/api/ping"] == {"member1"}
    assert tracker.route_2xx_actors["/api/empty-obj"] == {"member1"}
    assert tracker.route_2xx_actors["/api/leak"] == {"anon"}

    # Checkpoint round-trip preserves both maps
    restored = SurfaceFrontierTracker.from_dict(tracker.to_dict())
    assert restored.soft_deny_routes == tracker.soft_deny_routes
    assert restored.route_2xx_actors == tracker.route_2xx_actors


def test_spa_client_route_404_suppression_and_non_spa_preservation() -> None:
    tracker = SurfaceFrontierTracker(base_url="http://spa.local", allowed_methods=("GET",))

    # Ingest JS bundle containing Vue Router paths + real fetch API call
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/assets/app.js",
        "status": 200,
        "content_type": "application/javascript",
        "body": (
            'const routes = [{ path: "/admin/dashboard", component: Dash }, '
            '{ path: "/library?tab=1", component: Lib }];\n'
            'window.location.hash = "#/jotter";\n'
            'fetch("/api/books");\n'
        ),
    })
    # Also ingest via ingest_surface spa_routes
    tracker.ingest_surface({
        "url": "http://spa.local/",
        "spa_routes": [{"url": "/admin/content", "method": "GET", "source_tag": "spa-route"}],
        "links": [{"url": "/real-page", "method": "GET"}],
    })

    unvisited_before = tracker.unvisited_routes()
    for p in ("/admin/dashboard", "/library", "/jotter", "/admin/content", "/api/books", "/real-page"):
        assert any(p in item for item in unvisited_before), f"missing {p} in {unvisited_before}"

    # SPA client routes returning 404 on GET get pruned from frontier (including parameterized /library?tab=)
    for spa_p in ("/admin/dashboard", "/library", "/jotter", "/admin/content"):
        tracker.ingest_receipt({"actor": "anon", "method": "GET", "url": spa_p, "status": 404, "body": "Not Found"})
        assert spa_p in tracker.pruned_spa_routes

    # Non-SPA routes returning 404 must NOT be treated as pruned client-side SPA routes
    tracker.ingest_receipt({"actor": "anon", "method": "GET", "url": "/api/books", "status": 404, "body": "{}"})
    tracker.ingest_receipt({"actor": "anon", "method": "GET", "url": "/real-page", "status": 404, "body": "404"})
    assert "/api/books" not in tracker.pruned_spa_routes
    assert "/real-page" not in tracker.pruned_spa_routes

    # Re-ingesting the same JS bundle does not re-add pruned SPA routes to unvisited_routes()
    tracker.ingest_surface({
        "url": "http://spa.local/login",
        "spa_routes": [
            {"url": "/admin/dashboard", "method": "GET", "sources": ["spa-route"]},
            {"url": "/library?tab=1", "method": "GET", "sources": ["spa-route"]},
            {"url": "/jotter", "method": "GET", "sources": ["spa-hash"]},
        ],
    })
    unvisited_after = tracker.unvisited_routes()
    for spa_p in ("/admin/dashboard", "/library", "/jotter", "/admin/content"):
        assert not any(spa_p in item for item in unvisited_after), f"pruned {spa_p} leaked into {unvisited_after}"
    assert not any("/library" in r["route_template"] for r in tracker.high_risk_unprobed_routes(limit=20))

    # Checkpoint round-trip preserves pruned SPA routes
    restored = SurfaceFrontierTracker.from_dict(tracker.to_dict())
    assert restored.pruned_spa_routes == tracker.pruned_spa_routes
    assert not any("/library" in item for item in restored.unvisited_routes())

    # If later confirmed by a real HTML link or non-404 response, it un-prunes cleanly
    restored.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/real-host",
        "status": 200,
        "content_type": "text/html",
        "body": '<a href="/admin/dashboard">Dash</a>',
    })
    assert "/admin/dashboard" not in restored.pruned_spa_routes


# ---------------------------------------------------------------------------
# 4. Non-BSAG fixation_ratio Telemetry
# ---------------------------------------------------------------------------


def test_non_bsag_fixation_ratio_computes_surface_novelty_and_preserves_bsag() -> None:
    # A. Sharded / non-BSAG mode with delta_v=0, delta_e=0 on every http_event
    events_non_bsag: list[dict[str, Any]] = [
        {"event": "http_event", "method": "GET", "path": "/api/items/1", "route_template": "/api/items/{id}", "actor": "anon", "status": 200, "delta_v": 0, "delta_e": 0},
        # Exact template/actor/status repeat -> zero delta
        {"event": "http_event", "method": "GET", "path": "/api/items/2", "route_template": "/api/items/{id}", "actor": "anon", "status": 200, "delta_v": 0, "delta_e": 0},
        # New actor on same template -> positive delta
        {"event": "http_event", "method": "GET", "path": "/api/items/1", "route_template": "/api/items/{id}", "actor": "member1", "status": 200, "delta_v": 0, "delta_e": 0},
        # New status class (401/403) on same template -> positive delta
        {"event": "http_event", "method": "GET", "path": "/api/items/1", "route_template": "/api/items/{id}", "actor": "member1", "status": 403, "delta_v": 0, "delta_e": 0},
        # New method (PUT) on same template -> positive delta
        {"event": "http_event", "method": "PUT", "path": "/api/items/1", "route_template": "/api/items/{id}", "actor": "member1", "status": 405, "delta_v": 0, "delta_e": 0},
        # New query key set {"sort"} -> positive delta
        {"event": "http_event", "method": "GET", "path": "/api/items/1?sort=asc", "route_template": "/api/items/{id}", "actor": "anon", "status": 200, "delta_v": 0, "delta_e": 0},
        # Same query key set {"sort"} -> zero delta
        {"event": "http_event", "method": "GET", "path": "/api/items/1?sort=desc", "route_template": "/api/items/{id}", "actor": "anon", "status": 200, "delta_v": 0, "delta_e": 0},
        # New status class (5xx) on same template -> positive delta
        {"event": "http_event", "method": "GET", "path": "/api/items/1?sort=desc'", "route_template": "/api/items/{id}", "actor": "anon", "status": 500, "delta_v": 0, "delta_e": 0},
    ]
    metrics = compute_process_metrics(events=events_non_bsag, bsag=None)
    assert metrics["counts"]["step_samples"] == 8
    assert metrics["counts"]["zero_delta_steps"] == 2
    assert metrics["fixation_ratio"] == 0.25

    # B. Absent delta_v/delta_e fields + pure repeat fixation run
    pure_repeat_events = [
        {"event": "http_event", "method": "GET", "path": "/api/ping", "actor": "anon", "status": 200}
        for _ in range(10)
    ]
    repeat_metrics = compute_process_metrics(events=pure_repeat_events, bsag=None)
    assert repeat_metrics["counts"]["step_samples"] == 10
    assert repeat_metrics["counts"]["zero_delta_steps"] == 9
    assert repeat_metrics["fixation_ratio"] == 0.9

    # C. When BSAG is active (non-zero deltas or bsag instance provided), preserve exact BSAG behavior
    bsag_events = [
        {"event": "http_event", "method": "GET", "path": "/a", "route_template": "/a", "actor": "anon", "status": 200, "delta_v": 2, "delta_e": 1},
        {"event": "http_event", "method": "GET", "path": "/b", "route_template": "/b", "actor": "anon", "status": 200, "delta_v": 0, "delta_e": 0},
        {"event": "http_event", "method": "GET", "path": "/c", "route_template": "/c", "actor": "anon", "status": 200, "delta_v": 0, "delta_e": 0},
        {"event": "http_event", "method": "GET", "path": "/d", "route_template": "/d", "actor": "anon", "status": 200, "delta_v": 0, "delta_e": 0},
    ]
    bsag_metrics = compute_process_metrics(events=bsag_events, bsag=None)
    assert bsag_metrics["counts"]["step_samples"] == 4
    assert bsag_metrics["counts"]["zero_delta_steps"] == 3
    assert bsag_metrics["fixation_ratio"] == 0.75

    # Also when bsag object is explicitly passed with all-zero delta events, preserve BSAG formula (1.0)
    bsag_obj = BeliefStateAttackGraph(base_url="http://127.0.0.1:9000")
    all_zero_with_bsag = [
        {"event": "http_event", "method": "GET", "path": "/a", "route_template": "/a", "actor": "anon", "status": 200, "delta_v": 0, "delta_e": 0},
        {"event": "http_event", "method": "GET", "path": "/b", "route_template": "/b", "actor": "anon", "status": 200, "delta_v": 0, "delta_e": 0},
    ]
    bsag_obj_metrics = compute_process_metrics(events=all_zero_with_bsag, bsag=bsag_obj)
    assert bsag_obj_metrics["counts"]["zero_delta_steps"] == 2
    assert bsag_obj_metrics["fixation_ratio"] == 1.0

    # D. Empty events remain 0.0
    empty_metrics = compute_process_metrics(events=[], bsag=None)
    assert empty_metrics["fixation_ratio"] == 0.0
    assert empty_metrics["counts"]["step_samples"] == 0
    assert empty_metrics["counts"]["zero_delta_steps"] == 0
