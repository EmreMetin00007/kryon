"""Unit tests for general-purpose UI <-> API resource-family parity tracking in SurfaceFrontierTracker."""
from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_surface import SurfaceFrontierTracker  # noqa: E402


def test_no_api_prefix_observed_emits_zero_parity_candidates() -> None:
    tracker = SurfaceFrontierTracker(base_url="http://app.local")
    tracker.ingest_receipt({"url": "/invoices/inv-42", "method": "GET", "status": 403, "content_type": "text/html"})
    tracker.ingest_receipt({"url": "/tickets", "method": "GET", "status": 200, "content_type": "text/html"})
    # A blind 404 probe to an API-like path must not hallucinate an observed API prefix.
    tracker.ingest_receipt({"url": "/api/v1/orders", "method": "GET", "status": 404})

    assert tracker.untested_api_parity() == []
    assert "api_parity_untested" not in tracker.format_frontier_banner(max_chars=1000)


def test_dynamic_api_prefix_variants_and_ui_resource_parity_prioritization() -> None:
    for prefix in ("/api/v1", "/api/v2", "/api", "/v1"):
        tracker = SurfaceFrontierTracker(base_url="http://app.local")
        tracker.ingest_receipt({"url": f"{prefix}/orders", "method": "GET", "status": 200})
        tracker.ingest_receipt({"url": "/tickets", "method": "GET", "status": 200, "content_type": "text/html"})
        tracker.ingest_receipt({"url": "/invoices/inv-42", "method": "GET", "status": 403, "content_type": "text/html"})
        tracker.ingest_receipt({
            "url": "/parcels/550e8400-e29b-41d4-a716-446655440000",
            "method": "GET",
            "status": 403,
            "content_type": "text/html",
        })

        candidates = tracker.untested_api_parity()
        assert candidates == [
            f"GET {prefix}/invoices/inv-42",
            f"GET {prefix}/parcels/550e8400-e29b-41d4-a716-446655440000",
            f"GET {prefix}/tickets",
        ]
        assert tracker.has_high_value_frontier() is True


def test_api_prefix_inferred_from_passive_js_and_openapi_discovery() -> None:
    tracker = SurfaceFrontierTracker(base_url="http://app.local")
    tracker.ingest_receipt({
        "url": "/bookings/bkg-9",
        "method": "GET",
        "status": 403,
        "content_type": "text/html",
        "body": '<script src="/static/app.js"></script><a href="/bookings/bkg-10">next</a>',
    })
    assert tracker.untested_api_parity() == []

    # Passive JS extraction discovers /api/v1/orders
    tracker.ingest_receipt({
        "url": "/static/app.js",
        "method": "GET",
        "status": 200,
        "content_type": "application/javascript",
        "body": 'fetch("/api/v1/orders");',
    })
    assert tracker.untested_api_parity() == ["GET /api/v1/bookings/bkg-9"]


def test_utility_auth_static_paths_are_skipped_from_ui_families() -> None:
    tracker = SurfaceFrontierTracker(base_url="http://app.local")
    tracker.ingest_receipt({"url": "/api/v1/orders", "method": "GET", "status": 200})

    skipped_paths = [
        "/login",
        "/logout",
        "/signin",
        "/sign-in",
        "/signup",
        "/sign-up",
        "/register",
        "/auth/callback",
        "/oauth/authorize",
        "/static/app.js",
        "/assets/main.css",
        "/public/logo.png",
        "/media/banner.jpg",
        "/img/icon.svg",
        "/images/hero.webp",
        "/css/site.css",
        "/js/bundle.js",
        "/fonts/inter.woff2",
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/health",
        "/healthz",
        "/ready",
        "/metrics",
        "/status",
        "/dashboard",
        "/home",
        "/index",
        "/docs",
        "/openapi.json",
        "/swagger",
        "/redoc",
        "/admin",
        "/search",
        "/settings",
        "/profile",
        "/account",
        "/help",
        "/about",
        "/contact",
        "/error",
    ]
    for path in skipped_paths:
        tracker.ingest_receipt({"url": path, "method": "GET", "status": 200})

    assert tracker.untested_api_parity() == []


def test_utility_api_subpath_does_not_shadow_versioned_api_prefix() -> None:
    tracker = SurfaceFrontierTracker(base_url="http://app.local")
    tracker.ingest_receipt({"url": "/api/health", "method": "GET", "status": 200})
    tracker.ingest_receipt({"url": "/api/v1/orders", "method": "GET", "status": 200})
    tracker.ingest_receipt({"url": "/invoices/inv-7", "method": "GET", "status": 403})

    assert tracker.untested_api_parity() == ["GET /api/v1/invoices/inv-7"]


def test_parity_candidate_clears_regardless_of_api_status_code() -> None:
    for probe_status in (200, 401, 403, 404):
        tracker = SurfaceFrontierTracker(base_url="http://app.local")
        tracker.ingest_receipt({"url": "/api/v1/orders", "method": "GET", "status": 200})
        tracker.ingest_receipt({"url": "/invoices/inv-42", "method": "GET", "status": 403})
        tracker.ingest_receipt({"url": "/invoices/inv-43", "method": "GET", "status": 403})
        tracker.ingest_receipt({"url": "/tickets", "method": "GET", "status": 200})

        assert tracker.untested_api_parity() == [
            "GET /api/v1/invoices/inv-42",
            "GET /api/v1/tickets",
        ]

        # Any probe to /api/v1/invoices or /api/v1/invoices/{id} clears the entire resource family.
        tracker.ingest_receipt({"url": "/api/v1/invoices/inv-42", "method": "GET", "status": probe_status})
        assert tracker.untested_api_parity() == ["GET /api/v1/tickets"]

        tracker.ingest_receipt({"url": "/api/v1/tickets", "method": "GET", "status": probe_status})
        assert tracker.untested_api_parity() == []


def test_format_frontier_banner_caps_at_3_parity_candidates_and_honors_max_chars() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://app.local",
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[{"alias": "member-a", "role": "member", "tenant": "t1"}],
    )
    tracker.ingest_receipt({"url": "/api/v1/orders", "method": "GET", "status": 200, "actor": "member-a"})
    for idx, res in enumerate(("alpha", "beta", "gamma", "omicron", "sigma"), start=1):
        tracker.ingest_receipt({"url": f"/{res}/{res[:3]}-{idx}", "method": "GET", "status": 403, "actor": "member-a"})

    # Also add unvisited routes to ensure api_parity_untested is still surfaced cleanly within max_chars.
    for i in range(6):
        tracker._register_discovered_url(f"/extraroute{i}/long-segment-name", method="GET")

    banner = tracker.format_frontier_banner(max_chars=1000)
    assert len(banner) <= 1000
    assert "api_parity_untested: [" in banner
    assert "GET /api/v1/alpha/alp-1" in banner
    assert "GET /api/v1/beta/bet-2" in banner
    assert "GET /api/v1/gamma/gam-3" in banner
    assert "omicron" not in banner
    assert "sigma" not in banner

    for tight_limit in (300, 180, 60, 10, 0):
        tight_banner = tracker.format_frontier_banner(max_chars=tight_limit)
        assert len(tight_banner) <= tight_limit


def test_checkpoint_roundtrip_and_backward_compatible_load_dict() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://app.local",
        allowed_methods=("GET", "HEAD"),
        actor_summaries=[{"alias": "member-a", "role": "member", "tenant": "t1"}],
    )
    tracker.ingest_receipt({"url": "/api/v1/orders", "method": "GET", "status": 200, "actor": "member-a"})
    tracker.ingest_receipt({"url": "/invoices/inv-42", "method": "GET", "status": 403, "actor": "member-a"})
    tracker.ingest_receipt({"url": "/tickets", "method": "GET", "status": 200, "actor": "member-a"})

    saved = tracker.to_dict()
    restored_from = SurfaceFrontierTracker.from_dict(saved)
    assert restored_from.untested_api_parity() == [
        "GET /api/v1/invoices/inv-42",
        "GET /api/v1/tickets",
    ]

    restored_load = SurfaceFrontierTracker(base_url="http://app.local")
    restored_load.load_dict(saved)
    assert restored_load.untested_api_parity() == [
        "GET /api/v1/invoices/inv-42",
        "GET /api/v1/tickets",
    ]

    # Simulate an older checkpoint lacking parity keys and metadata keys.
    legacy_saved = {
        k: v
        for k, v in saved.items()
        if k not in {"api_prefix_routes", "ui_resource_families", "base_url", "allowed_methods", "actors"}
    }
    legacy_tracker = SurfaceFrontierTracker.from_dict(legacy_saved, base_url="http://app.local")
    assert legacy_tracker.api_prefix_routes.get("/api/v1")
    # Should not crash on missing new keys
    assert isinstance(legacy_tracker.untested_api_parity(), list)
