"""Wave 1 P0 tests for multi-origin surface tracking, preview, sharding, seed, and browser modules."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import agentic_browser  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_preview import (  # noqa: E402
    _build_surface_hints,
    _extract_openapi_operations,
    _extract_surface_summary,
)
from agentic_receipts import ReceiptStore  # noqa: E402
import agentic_seed  # noqa: E402
from agentic_sharding import (  # noqa: E402
    build_cross_shard_synthesis_prompts,
    build_shard_prompts,
    cluster_discovered_surface,
    collect_cross_shard_synthesis_context,
)
from agentic_surface import SurfaceFrontierTracker, route_template_of  # noqa: E402
from target_bootstrap import ScopeGuard  # noqa: E402


# ---------------------------------------------------------------------------
# 1. SurfaceFrontierTracker: Multi-origin separation, OpenAPI servers & GraphQL
# ---------------------------------------------------------------------------


def test_surface_tracker_multi_origin_isolation_exclusions_and_roundtrip() -> None:
    # route_template_of remains 100% backward-compatible (path-only template)
    assert route_template_of("https://api.target.example/v1/orders/42") == "/v1/orders/{id}"

    tracker = SurfaceFrontierTracker(
        base_url="https://www.target.example/",
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[
            {"alias": "alice", "role": "member", "tenant": "t1"},
            {"alias": "bob", "role": "member", "tenant": "t2"},
        ],
        in_scope_assets=("https://www.target.example", "*.target.example"),
        out_of_scope_assets=("admin.target.example", "https://api.target.example/internal"),
        excluded_paths=("/logout",),
    )

    tracker.ingest_surface(
        {
            "url": "https://www.target.example/",
            "links": [
                {"method": "GET", "url": "https://www.target.example/api/v1/orders/1?view=full", "params": ["view"]},
                {"method": "GET", "url": "https://api.target.example/api/v1/orders/1?q=items", "params": ["q"]},
                {"method": "GET", "url": "https://api.target.example/internal/debug"},
                {"method": "GET", "url": "https://api.target.example/logout"},
                {"method": "GET", "url": "https://admin.target.example/users/9"},
                {"method": "GET", "url": "https://evil.example/steal"},
            ],
            "forms": [
                {"method": "POST", "url": "https://api.target.example/api/v1/orders", "params": ["sku"]},
            ],
        },
        actor="alice",
    )

    assert ("GET", "/api/v1/orders/1") in tracker.discovered_routes
    assert ("GET", "https://api.target.example/api/v1/orders/1") in tracker.discovered_routes
    assert ("GET", "https://api.target.example/internal/debug") not in tracker.discovered_routes
    assert ("GET", "https://api.target.example/logout") not in tracker.discovered_routes
    assert ("GET", "https://admin.target.example/users/9") not in tracker.discovered_routes
    assert ("GET", "https://evil.example/steal") not in tracker.discovered_routes

    assert "/api/v1/orders/1" in tracker.discovered_objects
    assert "https://api.target.example/api/v1/orders/1" in tracker.discovered_objects
    assert tracker.discovered_objects["/api/v1/orders/1"]["template"] == "/api/v1/orders/{id}"
    assert (
        tracker.discovered_objects["https://api.target.example/api/v1/orders/1"]["template"]
        == "https://api.target.example/api/v1/orders/{id}"
    )

    assert "view" in tracker.discovered_params["/api/v1/orders/{id}"]
    assert "q" in tracker.discovered_params["https://api.target.example/api/v1/orders/{id}"]
    assert "view" not in tracker.discovered_params["https://api.target.example/api/v1/orders/{id}"]

    unvisited = tracker.unvisited_routes()
    assert any(item.startswith("GET /api/v1/orders/1") for item in unvisited)
    assert any(item.startswith("GET https://api.target.example/api/v1/orders/1") for item in unvisited)

    writes = tracker.untested_write_ops()
    assert "POST https://api.target.example/api/v1/orders" in writes
    assert "PUT https://api.target.example/api/v1/orders/1" in writes
    assert "PUT /api/v1/orders/1" in writes

    cross = tracker.untested_cross_actor_objects()
    assert any("GET https://api.target.example/api/v1/orders/1" in item for item in cross)
    assert any("GET /api/v1/orders/1" in item for item in cross)

    # Visiting the primary route must NOT mark the sibling-origin route visited or probed
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "GET",
        "url": "https://www.target.example/api/v1/orders/1?view=full",
        "status": 200,
        "content_type": "application/json",
        "body": '{"id": 1}',
    })
    assert not any(item.startswith("GET /api/v1/orders/1") for item in tracker.unvisited_routes())
    assert any(item.startswith("GET https://api.target.example/api/v1/orders/1") for item in tracker.unvisited_routes())

    tracker.ingest_receipt({
        "actor": "alice",
        "method": "GET",
        "url": "https://api.target.example/api/v1/orders/1?q=items",
        "status": 200,
        "content_type": "application/json",
        "body": '{"id": 1}',
    })
    unprobed = tracker.unprobed_params()
    assert any("https://api.target.example/api/v1/orders/1?q=" in p for p in unprobed)

    high_risk = tracker.high_risk_unprobed_routes()
    hr_tmpls = {entry["route_template"] for entry in high_risk}
    assert "https://api.target.example/api/v1/orders" in hr_tmpls
    assert "https://api.target.example/api/v1/orders/{id}" in hr_tmpls

    # Checkpoint roundtrip preserves multi-origin scope guard and sibling state
    snap = tracker.to_dict()
    assert snap.get("in_scope_assets") == ["https://www.target.example", "*.target.example"]
    assert snap.get("out_of_scope_assets") == ["admin.target.example", "https://api.target.example/internal"]
    assert snap.get("excluded_paths") == ["/logout"]

    restored = SurfaceFrontierTracker.from_dict(snap)
    assert restored._scope_guard is not None
    assert "https://api.target.example/api/v1/orders/1" in restored.discovered_objects
    assert (
        restored.discovered_objects["https://api.target.example/api/v1/orders/1"]["template"]
        == "https://api.target.example/api/v1/orders/{id}"
    )
    assert restored._resolve_same_origin("https://api.target.example/v2/health") == (
        "https://api.target.example/v2/health",
        "",
    )
    assert restored._resolve_same_origin("https://admin.target.example/secret") is None


def test_surface_tracker_passive_extraction_and_openapi_servers_multi_origin() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="https://www.target.example/",
        allowed_methods=("GET", "POST"),
        in_scope_assets=("https://www.target.example", "*.target.example"),
        out_of_scope_assets=("admin.target.example",),
    )

    # 1. Receipt with HTML links, inline JS fetch, and sibling-origin URLs
    html_body = """
    <html><body>
      <a href="https://api.target.example/v1/payments">Pay</a>
      <a href="https://admin.target.example/panel">Blocked</a>
      <a href="https://evil.example/phish">External</a>
      <form action="https://api.target.example/v1/transfers" method="POST">
        <input name="amount" />
      </form>
      <script>
        fetch("https://auth.target.example/oauth/token", {method: "POST"});
        fetch("/ui-state");
      </script>
    </body></html>
    """
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "https://www.target.example/dashboard",
        "status": 200,
        "content_type": "text/html",
        "body": html_body,
    })

    assert ("GET", "https://api.target.example/v1/payments") in tracker.discovered_routes
    assert ("POST", "https://api.target.example/v1/transfers") in tracker.discovered_routes
    assert ("POST", "https://auth.target.example/oauth/token") in tracker.discovered_routes
    assert ("GET", "/ui-state") in tracker.discovered_routes
    assert ("GET", "https://api.target.example/ui-state") not in tracker.discovered_routes
    assert ("GET", "https://admin.target.example/panel") not in tracker.discovered_routes
    assert ("GET", "https://evil.example/phish") not in tracker.discovered_routes

    # 2. JSON hypermedia on sibling origin
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "https://api.target.example/v1/orders",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({
            "_links": {
                "self": {"href": "https://api.target.example/v1/orders/55"},
                "next": {"href": "https://billing.target.example/v1/invoices/99"},
                "evil": {"href": "https://evil.example/orders/1"},
            }
        }),
    })
    assert "https://api.target.example/v1/orders/55" in tracker.discovered_objects
    assert "https://billing.target.example/v1/invoices/99" in tracker.discovered_objects
    assert ("GET", "https://evil.example/orders/1") not in tracker.discovered_routes

    # 3. OpenAPI 3 servers[0].url and Swagger 2 host + basePath honor in-scope sibling origin
    oa3_spec = {
        "openapi": "3.0.3",
        "servers": [{"url": "https://api.target.example/v2"}],
        "paths": {
            "/invoices/{id}": {
                "get": {
                    "parameters": [{"name": "fmt", "in": "query"}],
                }
            }
        },
    }
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "https://www.target.example/openapi.json",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps(oa3_spec),
    })
    assert ("GET", "https://api.target.example/v2/invoices/{id}") in tracker.discovered_routes
    assert "fmt" in tracker.discovered_params["https://api.target.example/v2/invoices/{id}"]

    sw2_spec = {
        "swagger": "2.0",
        "host": "billing.target.example",
        "basePath": "/v3",
        "schemes": ["https"],
        "paths": {
            "/charges": {"post": {}},
        },
    }
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "https://www.target.example/swagger.json",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps(sw2_spec),
    })
    assert ("POST", "https://billing.target.example/v3/charges") in tracker.discovered_routes

    # Out-of-scope servers origin is ignored instead of registering evil.example
    bad_spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://evil.example/v9"}],
        "paths": {"/ping": {"get": {}}},
    }
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "https://www.target.example/bad-openapi.json",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps(bad_spec),
    })
    assert not any("evil.example" in p for _, p in tracker.discovered_routes)


def test_surface_tracker_graphql_operation_tracking_prevents_write_saturation() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="https://www.target.example/",
        allowed_methods=("GET", "POST"),
        in_scope_assets=("https://www.target.example", "https://api.target.example"),
    )

    tracker.ingest_surface(
        {
            "url": "https://api.target.example/graphql",
            "graphql_ops": [
                {"kind": "query", "name": "viewer", "args": ["includeRoles"]},
                {"kind": "mutation", "name": "createOrder", "args": ["amount"]},
                {"kind": "mutation", "name": "deleteOrder", "args": ["orderId"]},
            ],
        },
        actor="anon",
    )

    # Generic POST /graphql stays in discovered_routes, while declared write ops split by #opName
    assert ("POST", "https://api.target.example/graphql") in tracker.discovered_routes
    assert "POST https://api.target.example/graphql#viewer" in tracker.untested_write_ops()
    assert "POST https://api.target.example/graphql#createOrder" in tracker.untested_write_ops()
    assert "POST https://api.target.example/graphql#deleteOrder" in tracker.untested_write_ops()

    # Subsequent generic POST /graphql discovery must not re-add unsaturated bare /graphql op
    tracker._register_discovered_url("https://api.target.example/graphql", method="POST", actor="anon")
    assert ("POST", "https://api.target.example/graphql") not in tracker.declared_write_ops

    # First GraphQL query only marks #viewer as tested/probed, NOT createOrder or deleteOrder
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "POST",
        "url": "https://api.target.example/graphql",
        "request_body": json.dumps({"operationName": "viewer", "query": "query viewer { id }"}),
        "status": 200,
        "content_type": "application/json",
        "body": '{"data":{"viewer":{"id":"1"}}}',
    })

    assert ("POST", "https://api.target.example/graphql") in tracker.visited_method_paths
    assert ("POST", "https://api.target.example/graphql#viewer") in tracker.visited_method_paths
    assert ("POST", "https://api.target.example/graphql#viewer") in tracker.tested_write_ops
    assert "https://api.target.example/graphql#viewer" in tracker.actively_probed_templates
    assert ("POST", "https://api.target.example/graphql#createOrder") not in tracker.tested_write_ops

    remaining = tracker.untested_write_ops()
    assert "POST https://api.target.example/graphql#viewer" not in remaining
    assert "POST https://api.target.example/graphql#createOrder" in remaining
    assert "POST https://api.target.example/graphql#deleteOrder" in remaining

    # Second call without operationName parses mutation name from query on /gql endpoint too
    tracker.ingest_surface(
        {
            "url": "https://www.target.example/gql",
            "js_calls": [
                {
                    "method": "POST",
                    "url": "https://www.target.example/gql",
                    "operation": {"protocol": "graphql", "name": "SubmitTicket"},
                },
                {
                    "method": "POST",
                    "url": "https://www.target.example/gql",
                    "operation": {"protocol": "graphql", "name": "CloseTicket"},
                },
            ],
        },
        actor="anon",
    )
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "POST",
        "url": "https://www.target.example/gql",
        "request_body": json.dumps({"query": "mutation SubmitTicket($id: ID!) { submitTicket(id: $id) { ok } }"}),
        "status": 200,
        "content_type": "application/json",
        "body": '{"data":{"submitTicket":{"ok":true}}}',
    })
    assert ("POST", "/gql#SubmitTicket") in tracker.tested_write_ops
    assert ("POST", "/gql#SubmitTicket") in tracker.visited_method_paths
    assert "POST /gql#CloseTicket" in tracker.untested_write_ops()


# ---------------------------------------------------------------------------
# 2. agentic_preview: Multi-origin hints, OpenAPI servers, CDN JS & metadata
# ---------------------------------------------------------------------------


def test_preview_multi_origin_openapi_servers_cdn_js_and_item_metadata() -> None:
    base_url = "https://www.target.example"
    in_scope = ("https://www.target.example", "https://api.target.example", "https://billing.target.example")
    out_scope = ("admin.target.example",)

    # 1. OpenAPI 3 servers & Swagger 2 host+basePath+in:body properties
    oa3_spec = {
        "openapi": "3.0.1",
        "servers": [{"url": "https://api.target.example/v2"}],
        "paths": {
            "/v2/orders/{id}": {
                "post": {
                    "parameters": [{"name": "dry_run", "in": "query"}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"amount": {"type": "number"}, "currency": {"type": "string"}},
                                }
                            }
                        }
                    },
                }
            }
        },
    }
    guard = ScopeGuard(base_url, in_scope_assets=in_scope, out_of_scope_assets=out_scope)
    oa3_ops = _extract_openapi_operations(oa3_spec, base_url, scope_guard=guard)
    assert len(oa3_ops) == 1
    assert oa3_ops[0]["url"] == "https://api.target.example/v2/orders/{id}"
    assert "amount" in oa3_ops[0]["body_fields"]

    sw2_spec = {
        "swagger": "2.0",
        "host": "billing.target.example",
        "basePath": "/v1",
        "schemes": ["https"],
        "paths": {
            "/refunds": {
                "post": {
                    "parameters": [
                        {"name": "reason", "in": "query"},
                        {
                            "name": "payload",
                            "in": "body",
                            "schema": {
                                "type": "object",
                                "properties": {"invoice_id": {"type": "string"}, "total": {"type": "integer"}},
                            },
                        },
                    ]
                }
            }
        },
    }
    sw2_ops = _extract_openapi_operations(sw2_spec, base_url, scope_guard=guard)
    assert len(sw2_ops) == 1
    assert sw2_ops[0]["url"] == "https://billing.target.example/v1/refunds"
    assert set(sw2_ops[0]["body_fields"]) == {"invoice_id", "total"}
    assert {"reason", "payload"} == {p["name"] for p in sw2_ops[0]["params"]}

    # Off-scope servers URL falls back safely to base_url origin
    bad_oa_ops = _extract_openapi_operations(
        {"openapi": "3.0.0", "servers": [{"url": "https://evil.example/v1"}], "paths": {"/health": {"get": {}}}},
        base_url,
        scope_guard=guard,
    )
    assert bad_oa_ops[0]["url"] == "https://www.target.example/v1/health"

    # 2. Multi-origin Postman + JSON hypermedia summary & hints
    postman_receipt = {
        "receipt_id": "req-0001",
        "url": "https://www.target.example/collection.json",
        "content_type": "application/json",
        "body": json.dumps({
            "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": [
                {
                    "name": "Sibling order",
                    "request": {"method": "POST", "url": "https://api.target.example/v1/orders"},
                },
                {
                    "name": "Blocked admin",
                    "request": {"method": "GET", "url": "https://admin.target.example/users"},
                },
                {
                    "name": "External leak",
                    "request": {"method": "GET", "url": "https://evil.example/secret"},
                },
            ],
            "_links": {"next": {"href": "https://billing.target.example/api/invoices/7"}},
        }),
    }
    summary = _extract_surface_summary(
        postman_receipt,
        base_url,
        in_scope_assets=in_scope,
        out_of_scope_assets=out_scope,
    )
    link_urls = {item["url"] for item in summary["links"]}
    assert "https://api.target.example/v1/orders" in link_urls
    assert "https://billing.target.example/api/invoices/7" in link_urls
    assert not any("admin.target.example" in u for u in link_urls)
    assert not any("evil.example" in u for u in link_urls)

    hints = _build_surface_hints(
        postman_receipt,
        base_url,
        in_scope_assets=in_scope,
        out_of_scope_assets=out_scope,
    )
    assert "https://api.target.example/v1/orders" in hints.get("links", [])
    assert "https://billing.target.example/api/invoices/7" in hints.get("api_endpoints", [])

    # 3. CDN JS fix: off-scope CDN JS resolves relative /api/... against base_url
    cdn_js_receipt = {
        "receipt_id": "req-0002",
        "url": "https://cdn.target.example/static/app.js",
        "content_type": "application/javascript",
        "body": """
        export async function checkout(cartId) {
          return fetch("/api/v1/checkout", { method: "POST", body: JSON.stringify({ cartId }) });
        }
        export async function listBilling() {
          return fetch("https://billing.target.example/v2/invoices");
        }
        """,
    }
    cdn_summary = _extract_surface_summary(
        cdn_js_receipt,
        base_url,
        in_scope_assets=in_scope,
        out_of_scope_assets=out_scope,
    )
    js_call_urls = {c["url"] for c in cdn_summary["js_calls"]}
    assert "https://www.target.example/api/v1/checkout" in js_call_urls
    assert "https://billing.target.example/v2/invoices" in js_call_urls
    assert not any("cdn.target.example" in u for u in js_call_urls)
    assert not any("cdn.target.example" in l["url"] for l in cdn_summary["links"])

    cdn_hints = _build_surface_hints(
        cdn_js_receipt,
        base_url,
        in_scope_assets=in_scope,
        out_of_scope_assets=out_scope,
    )
    assert "/api/v1/checkout" in cdn_hints.get("api_endpoints", [])
    assert not any("cdn.target.example" in u for u in cdn_hints.get("api_endpoints", []))

    # 4. _compact_surface_item preserves content_type, graphql_op / operation, and param_in
    html_form_receipt = {
        "receipt_id": "req-0003",
        "url": "https://www.target.example/upload",
        "content_type": "text/html",
        "body": '<form action="https://api.target.example/v1/import" method="POST"><input name="doc" /></form>',
    }
    html_summary = _extract_surface_summary(
        html_form_receipt,
        base_url,
        in_scope_assets=in_scope,
        out_of_scope_assets=out_scope,
    )
    # Direct unit verification on extracted form + hypermedia items with rich metadata
    assert html_summary["forms"][0]["url"] == "https://api.target.example/v1/import"
    meta_receipt = {
        "receipt_id": "req-0004",
        "url": "https://api.target.example/hal",
        "content_type": "application/json",
        "body": json.dumps({
            "_links": {
                "self": {
                    "href": "https://api.target.example/v1/search",
                    "method": "POST",
                    "json_body": {"q": "1"},
                },
            }
        }),
    }
    meta_summary = _extract_surface_summary(meta_receipt, base_url, in_scope_assets=in_scope)
    assert meta_summary["links"][0]["param_in"] == {"q": "json"}
    assert meta_summary["links"][0]["content_type"] == "application/json"


def test_preview_compact_surface_item_preserves_optional_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    import agentic_preview

    monkeypatch.setattr(
        agentic_preview,
        "extract_http_headers",
        lambda *_a, **_kw: [
            {
                "method": "POST",
                "url": "https://api.target.example/graphql",
                "content_type": "application/json",
                "graphql_op": {"kind": "mutation", "name": "UpdateRole", "fields": ["role", "userId"]},
                "params": [{"name": "input", "in": "body"}],
            },
            {
                "method": "POST",
                "url": "https://www.target.example/gql",
                "content_type": "application/json",
                "operation": {"kind": "query", "name": "Viewer"},
                "params": [{"name": "id", "in": "query"}],
            },
        ],
    )
    summary = _extract_surface_summary(
        {
            "receipt_id": "req-meta",
            "url": "https://www.target.example/",
            "content_type": "text/plain",
            "headers": {"Link": "</gql>"},
            "body": "ok",
        },
        "https://www.target.example",
        in_scope_assets=("https://www.target.example", "https://api.target.example"),
    )
    by_url = {item["url"]: item for item in summary["links"]}
    assert by_url["https://api.target.example/graphql"]["content_type"] == "application/json"
    assert by_url["https://api.target.example/graphql"]["param_in"] == {"input": "body"}
    assert by_url["https://api.target.example/graphql"]["graphql_op"]["name"] == "UpdateRole"
    assert by_url["/gql"]["operation"]["name"] == "Viewer"
    assert by_url["/gql"]["param_in"] == {"id": "query"}


# ---------------------------------------------------------------------------
# 3. agentic_sharding: Preserve sibling origins & pass Stage 2 / Stage 3 handoffs
# ---------------------------------------------------------------------------


def test_sharding_preserves_sibling_origins_and_injects_stage2_stage3_handoffs(tmp_path: Path) -> None:
    tracker = SurfaceFrontierTracker(
        base_url="https://www.target.example/",
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[
            {"alias": "alice", "role": "member", "tenant": "t1"},
            {"alias": "bob", "role": "member", "tenant": "t2"},
        ],
        in_scope_assets=("https://www.target.example", "*.target.example"),
    )
    for idx in range(1, 5):
        tracker.ingest_surface(
            {
                "url": "https://api.target.example/",
                "links": [
                    {"method": "GET", "url": f"https://api.target.example/v1/orders/{idx}?expand=items", "params": ["expand"]},
                    {"method": "GET", "url": f"https://www.target.example/v1/orders/{idx}"},
                    {"method": "GET", "url": f"https://billing.target.example/v1/invoices/{idx}"},
                    {"method": "GET", "url": f"https://auth.target.example/v1/users/{idx}"},
                    {"method": "GET", "url": f"https://reports.target.example/v1/reports/{idx}"},
                ],
                "forms": [
                    {
                        "method": "POST",
                        "url": "https://api.target.example/v1/orders",
                        "params": ["sku", "amount"],
                        "body_template": {"sku": "A1", "amount": 10},
                    }
                ],
            },
            actor="alice",
        )

    store = ReceiptStore(tmp_path)
    store.record(
        actor="alice",
        method="GET",
        url="https://api.target.example/v1/orders/1",
        path="/v1/orders/1",
        status=200,
        elapsed_ms=10,
        response_headers={},
        raw_response_bytes=b'{"id":1}',
        content_type="application/json",
    )

    clusters = cluster_discovered_surface(tracker, max_shards=3, min_routes_for_sharding=6)
    orders_cluster = next(c for c in clusters if "orders" in c.families)
    assert "https://api.target.example/v1/orders/{id}" in orders_cluster.routes
    assert "/v1/orders/{id}" in orders_cluster.routes
    assert "POST https://api.target.example/v1/orders" in orders_cluster.write_ops
    assert "https://api.target.example/v1/orders/1" in orders_cluster.objects
    assert "https://api.target.example/v1/orders/{id}" in orders_cluster.params
    assert "POST https://api.target.example/v1/orders" in orders_cluster.body_templates

    s2_sys, s2_usr = build_shard_prompts(
        orders_cluster,
        base_system_prompt="BASE SYS",
        receipts=store,
        surface_tracker=tracker,
        prescan_handoff="PRESCAN LEAD: CORS reflection on api.target.example",
        har_flows_handoff="HAR FLOW: checkout -> billing.target.example/v1/invoices",
        asset_graph_handoff="ASSET GRAPH: www -> api.target.example -> billing.target.example",
        waf_pivot_guidance="WAF PIVOT: avoid raw union keywords on api.target.example",
    )
    assert "https://api.target.example/v1/orders/{id}" in s2_sys
    assert "https://api.target.example/v1/orders/1" in s2_usr
    assert "PRESCAN LEAD: CORS reflection on api.target.example" in s2_usr
    assert "HAR FLOW: checkout -> billing.target.example/v1/invoices" in s2_usr
    assert "ASSET GRAPH: www -> api.target.example -> billing.target.example" in s2_usr
    assert "WAF PIVOT: avoid raw union keywords on api.target.example" in s2_usr

    # Empty optional handoffs should not pollute prompt with empty sections
    _, s2_usr_plain = build_shard_prompts(
        orders_cluster,
        base_system_prompt="BASE SYS",
        receipts=store,
        surface_tracker=tracker,
    )
    assert "STAGE 0 / SHARD INTELLIGENCE HANDOFFS" not in s2_usr_plain

    # Stage 3 cross-shard synthesis keeps sibling origin URLs & injects handoffs cleanly
    synth_ctx = collect_cross_shard_synthesis_context(
        shard_results=[],
        findings=[],
        receipts=store,
        surface_tracker=tracker,
    )
    untested_joined = "\n".join(synth_ctx["untested_writes_and_blocked"])
    assert "https://api.target.example/v1/orders" in untested_joined

    _, s3_usr = build_cross_shard_synthesis_prompts(
        base_system_prompt="BASE SYS",
        synthesis_context=synth_ctx,
        actor_summaries=[],
        http_budget_remaining=40,
        prescan_handoff="PRESCAN LEAD: OpenAPI exposed",
        har_flows_handoff="HAR FLOW: token exchange",
        asset_graph_handoff="ASSET GRAPH: sibling hosts mapped",
        waf_pivot_guidance="WAF PIVOT: alternate JSON content-type",
    )
    assert "PRESCAN LEAD: OpenAPI exposed" in s3_usr
    assert "HAR FLOW: token exchange" in s3_usr
    assert "ASSET GRAPH: sibling hosts mapped" in s3_usr
    assert "WAF PIVOT: alternate JSON content-type" in s3_usr


# ---------------------------------------------------------------------------
# 4. agentic_seed: Preserve full sibling-origin URLs through --tech-hint & seed
# ---------------------------------------------------------------------------


def test_seed_enrich_tech_hints_and_seed_finalize_preserve_sibling_origins(tmp_path: Path) -> None:
    enriched = agentic_seed.enrich_tech_discovery_hints(
        ["graphql", "spring"],
        existing_hints=[
            "https://api.shop.example/v1/orders?page=1",
            "https://graphql.shop.example/graphql",
            "/checkout",
        ],
        max_added=4,
    )
    assert enriched[0] == "https://api.shop.example/v1/orders"
    assert enriched[1] == "https://graphql.shop.example/graphql"
    assert enriched[2] == "/checkout"
    assert any(item == "/graphql" for item in enriched)

    seed_file = tmp_path / "seed.json"
    seed_file.write_text(
        json.dumps({
            "schema": "stage0-seed/1",
            "links": [
                {"method": "GET", "url": "https://www.shop.example/orders?filter=1", "params": ["filter"]},
                {"method": "GET", "url": "https://api.shop.example/v1/orders?expand=user", "params": ["expand"]},
            ],
            "body_templates": {
                "POST https://www.shop.example/orders": {"note": "primary"},
                "POST https://api.shop.example/v1/orders/42": {"amount": 100},
            },
            "multipart_schemas": {
                "POST https://uploads.shop.example/v1/files": {"fields": ["album"], "files": ["file"]},
            },
            "ws_endpoints": [
                {"url": "wss://ws.shop.example/stream"},
            ],
            "discovery_hints": [
                "https://api.shop.example/v1/orders",
            ],
        }),
        encoding="utf-8",
    )

    loaded = agentic_seed.load_seed_surface_files(
        [seed_file],
        base_url="https://www.shop.example/",
        in_scope_assets=("https://www.shop.example", "*.shop.example"),
        max_discovery_hints=10,
    )

    assert "https://api.shop.example/v1/orders/{id}" in {
        k.split(" ", 1)[1] for k in loaded["body_templates"]
    }
    assert "POST /orders" in loaded["body_templates"]
    assert "POST https://api.shop.example/v1/orders/{id}" in loaded["body_templates"]
    assert "POST https://uploads.shop.example/v1/files" in loaded["multipart_schemas"]
    assert loaded["ws_endpoints"] == [{"url": "wss://ws.shop.example/stream", "path": "/stream"}]
    assert "https://api.shop.example/v1/orders" in loaded["discovery_hints"]
    assert "/orders" in loaded["discovery_hints"]


# ---------------------------------------------------------------------------
# 5. agentic_browser: Per-origin cookies/localStorage, crawl hook & sibling URLs
# ---------------------------------------------------------------------------


def test_browser_per_origin_cookies_localstorage_and_compact_urls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = ScopeGuard(
        "https://www.target.example/",
        in_scope_assets=("https://www.target.example", "*.target.example"),
        out_of_scope_assets=("admin.target.example",),
    )

    assert (
        agentic_browser._compact_same_origin_url(
            "https://www.target.example/account?tab=1",
            base_url="https://www.target.example/",
            base_scheme="https",
            base_netloc="www.target.example",
            scope_guard=guard,
        )
        == "/account?tab=1"
    )
    assert (
        agentic_browser._compact_same_origin_url(
            "https://api.target.example/v1/orders?page=2",
            base_url="https://www.target.example/",
            base_scheme="https",
            base_netloc="www.target.example",
            scope_guard=guard,
        )
        == "https://api.target.example/v1/orders?page=2"
    )
    assert (
        agentic_browser._compact_same_origin_url(
            "https://admin.target.example/secret",
            base_url="https://www.target.example/",
            base_scheme="https",
            base_netloc="www.target.example",
            scope_guard=guard,
        )
        is None
    )

    # Mock multi-origin actor with per-origin cookies & localStorage
    base_ls_secret = "LS_PRIMARY_SECRET_ALPHA"
    sib_ls_secret = "LS_SIBLING_SECRET_BETA"
    evil_ls_secret = "LS_EVIL_SECRET_NEVER_INJECT"
    base_cookie_val = "COOKIE_PRIMARY_VAL_1"
    sib_cookie_val = "COOKIE_SIBLING_VAL_2"
    evil_cookie_val = "COOKIE_EVIL_VAL_NEVER_INJECT"

    actors = ActorManager([
        {
            "alias": "alice",
            "role": "member",
            "cookies": {"base_flat": base_cookie_val},
            "cookie_records": [
                {
                    "name": "base_flat",
                    "value": base_cookie_val,
                    "domain": "www.target.example",
                    "path": "/",
                    "secure": True,
                    "host_only": True,
                    "sameSite": "lax",
                },
                {
                    "name": "sib_sess",
                    "value": sib_cookie_val,
                    "domain": "api.target.example",
                    "path": "/v1",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "Strict",
                },
                {
                    "name": "blocked_admin",
                    "value": evil_cookie_val,
                    "domain": "admin.target.example",
                    "path": "/",
                },
            ],
            "local_storage": {"primary_tok": base_ls_secret},
            "local_storage_by_origin": {
                "https://www.target.example": {"primary_tok": base_ls_secret},
                "https://api.target.example": {"api_tok": sib_ls_secret},
                "https://admin.target.example": {"admin_tok": evil_ls_secret},
            },
        }
    ])
    client = AgenticHTTPClient(
        base_url="https://www.target.example/",
        receipt_store=ReceiptStore(tmp_path),
        actors=actors,
        allowed_methods=("GET",),
        max_requests=20,
        in_scope_assets=("https://www.target.example", "*.target.example"),
        out_of_scope_assets=("admin.target.example",),
    )

    added_scripts: list[str] = []
    added_cookies: list[dict[str, Any]] = []

    class _FakeResp:
        status = 200
        headers = {"content-type": "text/html"}

    class _FakePage:
        url = "https://api.target.example/portal"

        def on(self, *_args: Any) -> None:
            return

        def goto(self, *_args: Any, **_kwargs: Any) -> _FakeResp:
            return _FakeResp()

        def wait_for_timeout(self, _ms: int) -> None:
            return

        def evaluate(self, script_src: str, *_args: Any) -> Any:
            if "__ccoRuntime" in script_src:
                return {"events": [], "state": {}, "dom_sinks": [], "postmessage_listeners": []}
            if "data-kryon-dom-canary" in script_src:
                return True
            return {
                "title": f"Portal {sib_ls_secret} {sib_cookie_val}",
                "checked": False,
                "in_inner_text": False,
                "in_outer_html": False,
                "in_script_or_event_attr": False,
                "script_matches": 0,
                "event_attr_matches": [],
            }

    class _FakeContext:
        def add_init_script(self, script_src: str) -> None:
            added_scripts.append(script_src)

        def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
            added_cookies.extend(cookies)

        def route(self, *_args: Any) -> None:
            return

        def new_page(self) -> _FakePage:
            return _FakePage()

        def close(self) -> None:
            return

    class _FakeBrowser:
        def new_context(self, **_kwargs: Any) -> _FakeContext:
            return _FakeContext()

        def close(self) -> None:
            return

    class _FakeChromium:
        def launch(self, **_kwargs: Any) -> _FakeBrowser:
            return _FakeBrowser()

    class _FakePW:
        chromium = _FakeChromium()

        def __enter__(self) -> _FakePW:
            return self

        def __exit__(self, *_args: Any) -> None:
            return

    monkeypatch.setattr(agentic_browser, "HAS_PLAYWRIGHT", True)
    monkeypatch.setattr(agentic_browser, "_sync_playwright", lambda: _FakePW())

    inspected = agentic_browser.inspect_rendered_page(
        client,
        url="https://api.target.example/portal",
        actor="alice",
        wait_ms=0,
    )
    assert inspected["ok"] is True
    assert inspected["url"] == "https://api.target.example/portal"
    assert sib_ls_secret not in json.dumps(inspected)
    assert sib_cookie_val not in json.dumps(inspected)

    # Verify per-origin localStorage script only maps authorized origins cleanly
    ls_scripts = [sc for sc in added_scripts if "window.localStorage.setItem" in sc]
    assert len(ls_scripts) == 1
    assert "map[window.location.origin]" in ls_scripts[0]
    assert "https://www.target.example" in ls_scripts[0]
    assert "https://api.target.example" in ls_scripts[0]
    assert evil_ls_secret not in ls_scripts[0]
    assert "admin.target.example" not in ls_scripts[0]

    # Verify per-origin cookie injection preserved domain/path/secure & stripped host_only + off-scope
    by_cookie_name = {c["name"]: c for c in added_cookies}
    assert set(by_cookie_name) == {"base_flat", "sib_sess"}
    assert by_cookie_name["base_flat"]["domain"] == "www.target.example"
    assert by_cookie_name["base_flat"]["secure"] is True
    assert "host_only" not in by_cookie_name["base_flat"]
    assert by_cookie_name["sib_sess"]["domain"] == "api.target.example"
    assert by_cookie_name["sib_sess"]["path"] == "/v1"

    # Also verify sameSite/httpOnly/origin url handling when supplied via get_browser_auth_state
    with monkeypatch.context() as mp:
        mp.setattr(
            actors,
            "get_browser_auth_state",
            lambda _alias: {
                "cookies": {"base_flat": base_cookie_val},
                "cookie_records": [
                    {
                        "name": "samesite_c",
                        "value": sib_cookie_val,
                        "url": "https://api.target.example/v1",
                        "secure": True,
                        "httpOnly": True,
                        "sameSite": "lax",
                    },
                    {
                        "name": "blocked_url_c",
                        "value": evil_cookie_val,
                        "url": "https://admin.target.example/x",
                    },
                ],
                "headers": {},
            },
        )
        recs = agentic_browser._extract_actor_cookie_records(
            client,
            "alice",
            base_url=client.base_url,
            fallback_cookie_hdr=f"base_flat={base_cookie_val}; blocked_url_c={evil_cookie_val}",
        )
        recs_by_name = {r["name"]: r for r in recs}
        assert set(recs_by_name) == {"base_flat", "samesite_c"}
        assert recs_by_name["samesite_c"]["url"] == "https://api.target.example/v1"
        assert recs_by_name["samesite_c"]["sameSite"] == "Lax"
        assert recs_by_name["samesite_c"]["httpOnly"] is True
        assert recs_by_name["base_flat"]["url"] == client.base_url

    # Verify verify_dom_sink_in_browser also injects multi-origin cookies + localStorage on sibling origin
    added_scripts.clear()
    added_cookies.clear()
    dom_res = agentic_browser.verify_dom_sink_in_browser(
        client,
        url="https://api.target.example/portal",
        actor="alice",
        source="hash",
        wait_ms=0,
    )
    assert dom_res["ok"] is True
    assert dom_res["verified_dom_injection"] is True
    assert dom_res["url"].startswith("https://api.target.example/portal")
    assert any("map[window.location.origin]" in sc for sc in added_scripts)
    assert {c["name"] for c in added_cookies} == {"base_flat", "sib_sess"}

    # Verify run_browser_crawl _inject_crawl_browser_state handles _default_crawl_site WITHOUT local_storage arg
    added_scripts.clear()
    added_cookies.clear()
    import kryon_core.surface.crawl as real_crawl_mod

    monkeypatch.setattr(real_crawl_mod, "sync_playwright", lambda: _FakePW())

    def _fake_default_crawl(
        start_url: str,
        *,
        max_pages: int = 6,
        cookie: str = "",
        headers: dict[str, str] | None = None,
        timeout_ms: int = 12000,
        allow_subdomains: bool = False,
        wait_ms: int = 400,
        wire_gate: Any = None,
    ) -> dict[str, Any]:
        # Simulate real kryon_core.surface.crawl opening a Playwright context via crawl_mod.sync_playwright()
        assert wire_gate is not None
        assert allow_subdomains is True
        with real_crawl_mod.sync_playwright() as pw:  # type: ignore[attr-defined]
            br = pw.chromium.launch(headless=True)
            ctx = br.new_context()
            ctx.close()
            br.close()
        return {
            "ok": True,
            "pages": [
                {"url": start_url, "status": 200, "title": "Home"},
                {"url": "https://api.target.example/app", "status": 200, "title": "API App"},
            ],
            "links": [
                "https://api.target.example/v1/orders",
                "https://admin.target.example/blocked",
                "https://evil.example/leak",
            ],
            "forms": [
                {"page": start_url, "action": "https://api.target.example/v1/orders", "method": "POST", "fields": ["sku"]},
            ],
            "xhr": [
                {"url": "https://api.target.example/v1/me", "method": "GET", "status": 200},
            ],
        }

    monkeypatch.setattr(agentic_browser, "_default_crawl_site", _fake_default_crawl)
    tracker = SurfaceFrontierTracker(
        base_url="https://www.target.example/",
        allowed_methods=("GET", "POST"),
        in_scope_assets=("https://www.target.example", "*.target.example"),
        out_of_scope_assets=("admin.target.example",),
    )
    crawl_out = agentic_browser.run_browser_crawl(
        client,
        tracker,
        url="/",
        actor="alice",
        max_pages=4,
    )
    assert crawl_out["ok"] is True
    assert any("map[window.location.origin]" in sc for sc in added_scripts)
    assert {c["name"] for c in added_cookies} >= {"base_flat", "sib_sess"}
    assert "https://api.target.example/v1/orders" in crawl_out["links"]
    assert not any("admin.target.example" in l for l in crawl_out["links"])
    assert not any("evil.example" in l for l in crawl_out["links"])
    assert ("GET", "https://api.target.example/v1/me") in tracker.discovered_routes
    assert ("POST", "https://api.target.example/v1/orders") in tracker.discovered_routes
