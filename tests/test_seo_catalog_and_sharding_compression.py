"""Unit tests for SEO/e-commerce catalog slug compression, SPA-404/shell suppression, and catalog shard bucketing."""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_sharding import (  # noqa: E402
    SubsystemCluster,
    _rank_routes_by_input_risk,
    build_shard_prompts,
    cluster_discovered_surface,
    extract_resource_family,
)
from agentic_surface import (  # noqa: E402
    SurfaceFrontierTracker,
    is_catalog_route,
    is_id_segment,
    route_template_of,
)

BASE_URL = "http://127.0.0.1:8080"


# ---------------------------------------------------------------------------
# 1. SEO / E-Commerce Catalog Slug Compression & Functional Route Preservation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw_path", "expected_template"),
    [
        # Category / listing code slugs (Pazarama + generic e-commerce)
        ("/elektronik-k-K04", "/{catalog_category}"),
        ("/vantilatorler-k-K04162", "/{catalog_category}"),
        ("/pet-shop-k-vrtctgry", "/{catalog_category}"),
        ("/electronics-c-12345", "/{catalog_category}"),
        ("/home-appliances-cat-123", "/{catalog_category}"),
        ("/kadin-giyim-x-c1040", "/{catalog_category}"),
        # Multi-brand + category / product paths collapse cleanly
        ("/brit-care/pet-shop-k-K11228", "/{catalog_brand}/{catalog_category}"),
        ("/fissler/duduklu-tencere-k-k05482", "/{catalog_brand}/{catalog_category}"),
        ("/altus/buzdolabi-k-K051", "/{catalog_brand}/{catalog_category}"),
        ("/beko/camasir-makinesi-k-K052", "/{catalog_brand}/{catalog_category}"),
        ("/marka/fissler", "/marka/{catalog_brand}"),
        ("/brand/dyson", "/brand/{catalog_brand}"),
        ("/marka/fissler/duduklu-tencere-k-k05482", "/marka/{catalog_brand}/{catalog_category}"),
        ("/apple/14-inc-macbook-pro-apple-m5-pro-1tb-p-195950489613", "/{catalog_brand}/{catalog_product}"),
        # Product / item code slugs & long hyphenated SEO slugs
        ("/k2-4k-cozunurluklu-akilli-kamera-p-6972520238041", "/{catalog_product}"),
        ("/14-inc-macbook-pro-apple-m5-max-64gb-2tb-ssd-p-195950489613", "/{catalog_product}"),
        ("/kahve-makinesi-p-HRM9002", "/{catalog_product}"),
        ("/duduklu-tencere-p-AYP5139933144", "/{catalog_product}"),
        ("/wireless-gaming-mouse-i-123456", "/{catalog_product}"),
        ("/apple-macbook-pro-14-inch-m5-max-64gb-2tb-space-black", "/{catalog_product}"),
        ("/products/ultra-slim-laptop-sleeve-case-for-notebook", "/products/{catalog_product}"),
        # Campaign / promo code slugs
        ("/firsat/plus-avantajli-urunler", "/firsat/{catalog_campaign}"),
        ("/firsatlar/l-plus-indirim-gunleri", "/firsatlar/{catalog_campaign}"),
        ("/kampanyalar/l-yaz-indirim-firsatlari", "/kampanyalar/{catalog_campaign}"),
    ],
)
def test_seo_catalog_slugs_compress_deterministically_and_idempotently(
    raw_path: str,
    expected_template: str,
) -> None:
    assert route_template_of(raw_path) == expected_template
    assert route_template_of(expected_template) == expected_template
    assert is_catalog_route(raw_path) is True
    assert is_catalog_route(expected_template) is True
    assert extract_resource_family(raw_path) == "catalog"
    assert extract_resource_family(expected_template) == "catalog"


@pytest.mark.parametrize(
    ("functional_path", "expected_template", "expected_family"),
    [
        ("/api/v1/users/42", "/api/v1/users/{id}", "users"),
        ("/api/v1/orders/42", "/api/v1/orders/{id}", "orders"),
        ("/api/v1/products/123", "/api/v1/products/{id}", "products"),
        ("/api/v1/very-long-functional-service-diagnostics-endpoint", "/api/v1/very-long-functional-service-diagnostics-endpoint", "very-long-functional-service-diagnostics-endpoint"),
        ("/users/42", "/users/{id}", "users"),
        ("/orders/101", "/orders/{id}", "orders"),
        ("/invoices/inv-42", "/invoices/{id}", "invoices"),
        ("/admin/settings", "/admin/settings", "admin"),
        ("/hesabim/puanlarim/puan-aktar", "/hesabim/puanlarim/puan-aktar", "hesabim"),
        ("/login", "/login", "login"),
        ("/search", "/search", "search"),
        ("/sepetim", "/sepetim", "sepetim"),
        ("/refresh-token", "/refresh-token", "refresh-token"),
        ("/graphql", "/graphql", "graphql"),
        ("/auth/oauth2-callback-token-exchange-verification-endpoint", "/auth/oauth2-callback-token-exchange-verification-endpoint", "auth"),
        ("/vitamin-c-serum", "/vitamin-c-serum", "vitamin-c-serum"),
        ("/black-cat-cafe", "/black-cat-cafe", "black-cat-cafe"),
        ("/best-k-pop", "/best-k-pop", "best-k-pop"),
        ("/5-women", "/5-women", "5-women"),
    ],
)
def test_functional_api_auth_account_and_short_routes_never_false_collapse(
    functional_path: str,
    expected_template: str,
    expected_family: str,
) -> None:
    assert route_template_of(functional_path) == expected_template
    assert is_catalog_route(functional_path) is False
    assert extract_resource_family(functional_path) == expected_family


def test_is_id_segment_distinguishes_catalog_slugs_from_concrete_ids() -> None:
    # SEO catalog slugs must NOT be classified as concrete resource IDs for BOLA
    for slug in (
        "elektronik-k-K04",
        "vantilatorler-k-K04162",
        "pet-shop-k-K11228",
        "duduklu-tencere-k-k05482",
        "pet-shop-k-vrtctgry",
        "14-inc-macbook-pro-apple-m5-max-64gb-p-195950489613",
        "kahve-makinesi-p-HRM9002",
        "shoes-c-12345",
        "home-cat-123",
    ):
        assert is_id_segment(slug) is False

    # Concrete REST IDs and template placeholders remain IDs
    for cid in ("42", "inv-42", "cat-123", "550e8400-e29b-41d4-a716-446655440000", "{id}", "{catalog_category}"):
        assert is_id_segment(cid) is True


def test_catalog_pages_never_register_as_bola_objects_or_ui_parity_families() -> None:
    tracker = SurfaceFrontierTracker(
        base_url=BASE_URL,
        allowed_methods=("GET", "POST"),
        actor_summaries=[
            {"alias": "alice", "role": "member", "tenant": "t1"},
            {"alias": "bob", "role": "member", "tenant": "t1"},
        ],
    )
    tracker.ingest_receipt({"url": "/api/v1/orders", "method": "GET", "status": 200, "actor": "alice", "body": "[]"})
    for brand in ("altus", "beko", "bosch", "dyson", "fissler", "brit-care"):
        tracker.ingest_receipt({
            "url": f"/{brand}/duduklu-tencere-k-K05482",
            "method": "GET",
            "status": 200,
            "content_type": "text/html",
            "actor": "alice",
            "body": f"<html><body><h1>{brand}</h1></body></html>",
        })
    tracker.ingest_receipt({
        "url": "/14-inc-macbook-pro-apple-m5-max-p-195950489613",
        "method": "GET",
        "status": 200,
        "content_type": "text/html",
        "actor": "alice",
        "body": "<html><body>MacBook</body></html>",
    })
    assert tracker.discovered_objects == {}
    assert tracker.ui_resource_families == {}
    assert tracker.untested_api_parity() == []


# ---------------------------------------------------------------------------
# 2. Sharding Prioritization, Catalog Family Bucketing & Per-Shard Route Cap
# ---------------------------------------------------------------------------


def test_sharding_100_seo_brand_category_urls_plus_5_real_routes_collapses_into_compact_catalog_family() -> None:
    tracker = SurfaceFrontierTracker(
        base_url=BASE_URL,
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )

    # 100 distinct SEO brand/category/product/campaign URLs (alphabetically starting with aa-brand..!)
    for idx in range(60):
        brand = f"aa-brand-{idx:03d}"
        cat_code = f"K{1000 + idx}"
        tracker._register_discovered_url(f"/{brand}/kucuk-ev-aletleri-k-{cat_code}", method="GET", actor="alice")
    for idx in range(25):
        tracker._register_discovered_url(
            f"/akilli-urun-model-{idx}-ozel-seri-p-{6972520238000 + idx}",
            method="GET",
            actor="alice",
        )
    for idx in range(15):
        tracker._register_discovered_url(f"/firsatlar/l-kampanya-gunleri-{idx:02d}", method="GET", actor="alice")

    # 5 real functional / API / account routes
    real_routes = [
        ("GET", "/api/v1/orders/42"),
        ("POST", "/api/v1/orders"),
        ("GET", "/hesabim/puanlarim/puan-aktar"),
        ("GET", "/login"),
        ("GET", "/search?q=laptop"),
    ]
    for method, raw in real_routes:
        tracker._register_discovered_url(raw, method=method, actor="alice")
    tracker._register_discovered_url("/sepetim", method="GET", actor="alice")
    tracker._register_discovered_url("/api/v1/users/7", method="GET", actor="alice")
    tracker._register_discovered_url("/refresh-token", method="POST", actor="alice")

    # Frontier prioritizes real functional/API routes strictly ahead of compressed catalog templates
    unvisited = tracker.unvisited_routes()
    assert len(unvisited) <= 12
    top_frontier = tracker.high_value_frontier()["unvisited_routes"]
    for real_path in (
        "/api/v1/orders/42",
        "/api/v1/orders",
        "/api/v1/users/7",
        "/hesabim/puanlarim/puan-aktar",
        "/login",
        "/search",
        "/sepetim",
    ):
        assert any(real_path in item for item in top_frontier), f"{real_path} displaced in frontier: {top_frontier}"
    first_catalog_idx = next(
        (i for i, item in enumerate(unvisited) if "-k-" in item or "-p-" in item or "/firsatlar/l-" in item),
        len(unvisited),
    )
    for real_path in ("/api/v1/orders/42", "/hesabim/puanlarim/puan-aktar", "/login", "/search", "/sepetim"):
        real_idx = next(i for i, item in enumerate(unvisited) if real_path in item)
        assert real_idx < first_catalog_idx

    # Sharding produces zero brand families and groups all 100 SEO URLs into 1 low-priority "catalog" family
    clusters = cluster_discovered_surface(tracker, max_shards=4, min_routes_for_sharding=6)
    assert len(clusters) >= 2
    all_fams = [fam for c in clusters for fam in c.families]
    assert len(all_fams) == len(set(all_fams))
    assert "catalog" in all_fams
    assert not any(f.startswith("aa-brand-") for f in all_fams)
    for expected_fam in ("orders", "users", "hesabim", "login", "search", "sepetim"):
        assert expected_fam in all_fams

    # All real routes have strictly higher risk scores than pure SEO catalog templates
    ranked = _rank_routes_by_input_risk(
        [r for c in clusters for r in c.routes],
        write_ops=[w for c in clusters for w in c.write_ops],
        params={k: v for c in clusters for k, v in c.params.items()},
        methods_by_route={k: set(v) for c in clusters for k, v in c.methods_by_route.items()},
    )
    score_map = {item["route_template"]: int(item["risk_score"]) for item in ranked}
    cat_score = score_map["/{catalog_brand}/{catalog_category}"]
    for real_tmpl in (
        "/api/v1/orders/{id}",
        "/api/v1/orders",
        "/api/v1/users/{id}",
        "/hesabim/puanlarim/puan-aktar",
        "/login",
        "/search",
        "/sepetim",
    ):
        assert score_map[real_tmpl] > cat_score

    # Verify shard allocation gives real families top shards rather than letting catalog crowd them out
    assert clusters[0].families != ["catalog"]


def test_shard_caps_uncollapsed_catalog_category_pages_while_preserving_high_risk_catalog_inputs() -> None:
    tracker = SurfaceFrontierTracker(
        base_url=BASE_URL,
        allowed_methods=("GET", "POST"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )
    # Simulate 30 distinct non-hyphenated category routes mapped into "catalog"
    for i in range(30):
        tracker.discovered_routes[("GET", f"/catalog/cat{i:02d}")] = f"/catalog/cat{i:02d}"
    # Plus high-risk parameterized / mutating catalog routes and real API/auth routes
    tracker._register_discovered_url("/catalog/search?q=laptop&sort=asc", method="GET", actor="alice")
    tracker._register_discovered_url("/catalog/upload", method="POST", actor="alice")
    tracker._register_discovered_url("/api/v1/orders", method="GET", actor="alice")
    tracker._register_discovered_url("/api/v1/orders/{id}", method="GET", actor="alice")
    tracker._register_discovered_url("/login", method="GET", actor="alice")
    tracker._register_discovered_url("/hesabim/puanlarim/puan-aktar", method="GET", actor="alice")

    clusters = cluster_discovered_surface(tracker, max_shards=3, min_routes_for_sharding=6)
    catalog_cluster = next(c for c in clusters if "catalog" in c.families)
    low_risk_cat_routes = [
        r for r in catalog_cluster.routes if r.startswith("/catalog/cat")
    ]
    assert len(low_risk_cat_routes) <= 5
    assert "/catalog/search" in catalog_cluster.routes
    assert "/catalog/upload" in catalog_cluster.routes

    # Also verify build_shard_prompts caps manually constructed SubsystemCluster with 30 catalog pages
    manual_cluster = SubsystemCluster(
        shard_id="shard-1",
        name="catalog+auth",
        families=["catalog", "login"],
        routes=[
            *(f"/catalog/cat{i:02d}" for i in range(30)),
            "/catalog/search",
            "/login",
        ],
        write_ops=[],
        objects=[],
        params={"/catalog/search": ["q", "sort"]},
    )
    sys_prompt, _ = build_shard_prompts(manual_cluster, base_system_prompt="BASE")
    assigned_sec = sys_prompt.split("- Assigned routes:\n", 1)[1].split("\n- ", 1)[0]
    assert "/login" in assigned_sec
    assert "/catalog/search" in assigned_sec
    rendered_cat_lines = [line for line in assigned_sec.splitlines() if "/catalog/cat" in line]
    assert len(rendered_cat_lines) <= 5


# ---------------------------------------------------------------------------
# 3. Repetitive SPA-404 & Anonymous SPA Shell Fingerprint Suppression
# ---------------------------------------------------------------------------


def test_spa_404_and_anonymous_shell_fingerprints_suppress_redundant_siblings() -> None:
    tracker = SurfaceFrontierTracker(
        base_url=BASE_URL,
        allowed_methods=("GET", "POST"),
        actor_summaries=[{"alias": "anon", "role": "anonymous", "tenant": ""}],
    )

    # Discover real routes + SPA-404 sibling routes + anonymous SPA-shell sibling routes
    for path in (
        "/api/v1/users",
        "/login",
        "/ghost/alpha",
        "/ghost/beta",
        "/ghost/gamma",
        "/ghost/delta",
        "/ghost/epsilon",
        "/shell/orders",
        "/shell/profile",
        "/shell/coupons",
        "/shell/addresses",
        "/shell/cards",
        "/shell/settings?tab=security",
    ):
        tracker._register_discovered_url(path, method="GET", actor="anon")

    # 3 distinct paths under /ghost/* return identical 58KB SPA 404 HTML
    spa_404_body = "<!doctype html><html><body><div id='__nuxt'>404 Page Not Found</div>" + ("x" * 2048) + "</body></html>"
    for p in ("/ghost/alpha", "/ghost/beta", "/ghost/gamma"):
        tracker.ingest_receipt({
            "actor": "anon",
            "method": "GET",
            "url": p,
            "status": 404,
            "content_type": "text/html; charset=utf-8",
            "response_length": 58_000,
            "body": spa_404_body,
        })

    # 3 distinct paths under /shell/* return identical 13KB anonymous SPA auth-shell (using metadata length/sha256)
    for p in ("/shell/orders", "/shell/profile", "/shell/coupons"):
        tracker.ingest_receipt({
            "actor": "anon",
            "method": "GET",
            "url": p,
            "status": 200,
            "content_type": "text/html; charset=utf-8",
            "response_length": 13_400,
            "response_sha256": "deadbeef" * 8,
            "body": "",
        })

    unvisited = tracker.unvisited_routes()
    frontier_routes = tracker.high_value_frontier()["unvisited_routes"]

    # Real routes remain intact
    assert any("/api/v1/users" in r for r in frontier_routes)
    assert any("/login" in r for r in frontier_routes)

    # Parameterized route under /shell/settings?tab=security is preserved (not blindly suppressed)
    assert any("/shell/settings" in r and "tab=" in r for r in unvisited)

    # Redundant parameterless sibling paths under suppressed SPA-404 and SPA-shell prefixes are skipped
    for suppressed_sibling in ("/ghost/delta", "/ghost/epsilon", "/shell/addresses", "/shell/cards"):
        assert not any(suppressed_sibling in r for r in unvisited), f"leaked {suppressed_sibling}: {unvisited}"
        assert not any(suppressed_sibling in r for r in frontier_routes)

    # Identical SPA 200 shells must NOT register fake UI resource families or html_or_form_templates
    assert "shell" not in tracker.ui_resource_families
    assert "/shell/orders" not in tracker.html_or_form_templates
    assert "/shell/coupons" not in tracker.html_or_form_templates

    # Checkpoint round-trip preserves SPA suppression state
    restored = SurfaceFrontierTracker.from_dict(tracker.to_dict())
    restored_unvisited = restored.unvisited_routes()
    for suppressed_sibling in ("/ghost/delta", "/ghost/epsilon", "/shell/addresses", "/shell/cards"):
        assert not any(suppressed_sibling in r for r in restored_unvisited)


def test_spa_length_only_fallback_and_non_identical_same_length_pages() -> None:
    tracker = SurfaceFrontierTracker(base_url=BASE_URL, allowed_methods=("GET",))
    for path in ("/views/a", "/views/b", "/views/c", "/views/d"):
        tracker._register_discovered_url(path, method="GET", actor="anon")

    # Exact same response_length + text/html without sha256/body seen 3 times suppresses /views/d
    for p in ("/views/a", "/views/b", "/views/c"):
        tracker.ingest_receipt({
            "actor": "anon",
            "method": "GET",
            "url": p,
            "status": 200,
            "content_type": "text/html",
            "response_length": 13_100,
        })
    assert not any("/views/d" in r for r in tracker.unvisited_routes())

    # Conversely, distinct response_sha256 values on equal-length pages must NEVER suppress siblings
    tracker_real = SurfaceFrontierTracker(base_url=BASE_URL, allowed_methods=("GET",))
    for path in ("/items/alpha", "/items/beta", "/items/gamma", "/items/delta"):
        tracker_real._register_discovered_url(path, method="GET", actor="anon")
    for idx, p in enumerate(("/items/alpha", "/items/beta", "/items/gamma"), start=1):
        tracker_real.ingest_receipt({
            "actor": "anon",
            "method": "GET",
            "url": p,
            "status": 200,
            "content_type": "text/html",
            "response_length": 2_048,
            "body": f"<html><body><h1>Item {idx}</h1>{'y' * 2000}</body></html>",
        })
    assert any("/items/delta" in r for r in tracker_real.unvisited_routes())
