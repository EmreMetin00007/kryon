"""Unit tests for write-body JSON templates, 400/422 validation hints, and path-embedded param affordances."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_sharding import (  # noqa: E402
    SubsystemCluster,
    build_shard_prompts,
    cluster_discovered_surface,
    extract_resource_family,
)
from agentic_surface import (  # noqa: E402
    SurfaceFrontierTracker,
    _extract_path_embedded_params,
    route_template_of,
)


# ---------------------------------------------------------------------------
# 1. Observed Write-Body JSON Schema Templates
# ---------------------------------------------------------------------------


def test_working_write_json_body_templates_sanitized_redacted_and_bounded() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=("GET", "POST", "PUT", "PATCH", "DELETE"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )

    long_str = "A" * 120
    big_payload: dict[str, Any] = {
        "title": long_str,
        "author": "alice",
        "password": "SuperSecretPassword123!",
        "newPassword": "AnotherSecretPassword456!",
        "access_token": "eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "client_secret": "cs_live_987654321",
        "apiKey": "sk-test-123456789",
        "csrf_token": "csrf-val-abc",
        "note": "Bearer eyJhbGciOiJIUzI1NiJ9.secret.value",
        "already_redacted": "<REDACTED_SECRET:sha256_8=12345678>",
        "tags": ["t1", "t2", "t3", "t4", "t5", "t6"],
        "nested": {"secret_key": "raw-secret", "items": [1, 2, 3, 4, 5]},
    }
    for i in range(10):
        big_payload[f"extra_{i}"] = f"val_{i}"

    tracker.ingest_receipt({
        "actor": "alice",
        "method": "POST",
        "url": "http://127.0.0.1:8080/api/v1/records",
        "status": 201,
        "content_type": "application/json",
        "request_body": json.dumps(big_payload),
        "body": '{"id": 101}',
    })

    # 204 No Content with empty response body still records PUT template
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "PUT",
        "url": "http://127.0.0.1:8080/api/v1/records/101",
        "status": 204,
        "content_type": "",
        "request_body": json.dumps({"title": "Updated", "active": True}),
        "body": "",
    })

    # 302 redirect on PATCH still counts as 200 <= status < 400
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "PATCH",
        "url": "http://127.0.0.1:8080/api/v1/records/101",
        "status": 302,
        "redirect_location": "/api/v1/records/101",
        "request_body": json.dumps({"status": "archived"}),
        "body": "",
    })

    assert ("POST", "/api/v1/records") in tracker.discovered_body_templates
    assert ("PUT", "/api/v1/records/{id}") in tracker.discovered_body_templates
    assert ("PATCH", "/api/v1/records/{id}") in tracker.discovered_body_templates

    post_tmpl = tracker.discovered_body_templates[("POST", "/api/v1/records")]
    assert len(post_tmpl) <= 16
    assert len(json.dumps(post_tmpl, ensure_ascii=False, separators=(",", ":"))) <= 600
    assert post_tmpl["author"] == "alice"
    assert len(post_tmpl["title"]) <= 64
    assert post_tmpl["title"].endswith("...")
    assert post_tmpl["password"] == "<redacted>"
    assert post_tmpl["newPassword"] == "<redacted>"
    assert post_tmpl["access_token"] == "<redacted>"
    assert post_tmpl["client_secret"] == "<redacted>"
    assert post_tmpl["apiKey"] == "<redacted>"
    assert post_tmpl["csrf_token"] == "<redacted>"
    assert post_tmpl["note"] == "<redacted>"
    assert post_tmpl["already_redacted"] == "<redacted>"
    assert len(post_tmpl["tags"]) <= 4
    assert post_tmpl["nested"]["secret_key"] == "<redacted>"
    assert len(post_tmpl["nested"]["items"]) <= 4
    # Raw secret values must never appear anywhere in serialized template
    serialized = json.dumps(post_tmpl)
    for raw_secret in ("SuperSecretPassword123!", "AnotherSecretPassword456!", "cs_live_987654321", "sk-test-123456789", "raw-secret"):
        assert raw_secret not in serialized

    # Smaller working POST later must not overwrite the richer captured schema
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "POST",
        "url": "http://127.0.0.1:8080/api/v1/records",
        "status": 200,
        "request_body": json.dumps({"title": "tiny"}),
        "body": '{"ok": true}',
    })
    assert len(tracker.discovered_body_templates[("POST", "/api/v1/records")]) > 1


def test_write_body_templates_ignore_failed_multipart_invalid_and_enforce_cap() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=("GET", "POST", "PUT", "PATCH", "DELETE"),
    )

    ignored_cases = [
        # Failed statuses (4xx / 5xx)
        {"method": "POST", "url": "/api/fail400", "status": 400, "request_body": '{"a": 1}'},
        {"method": "POST", "url": "/api/fail401", "status": 401, "request_body": '{"a": 1}'},
        {"method": "POST", "url": "/api/fail422", "status": 422, "request_body": '{"a": 1}'},
        {"method": "POST", "url": "/api/fail500", "status": 500, "request_body": '{"a": 1}'},
        # Multipart summary
        {
            "method": "POST",
            "url": "/api/upload",
            "status": 200,
            "request_body": 'multipart/form-data {"files":[{"field":"file","filename":"a.txt"}]}',
        },
        # Invalid / truncated / bare redacted / non-object JSON
        {"method": "POST", "url": "/api/broken", "status": 200, "request_body": '{"unclosed": '},
        {"method": "POST", "url": "/api/redacted", "status": 200, "request_body": "<REDACTED:len=50>"},
        {"method": "POST", "url": "/api/form", "status": 200, "request_body": "name=alice&role=member"},
        {"method": "POST", "url": "/api/list", "status": 200, "request_body": "[1, 2, 3]"},
        {"method": "POST", "url": "/api/empty", "status": 200, "request_body": "{}"},
        # Non-mutating or DELETE methods
        {"method": "GET", "url": "/api/read", "status": 200, "request_body": '{"q": "x"}'},
        {"method": "DELETE", "url": "/api/items/1", "status": 200, "request_body": '{"reason": "cleanup"}'},
    ]
    for case in ignored_cases:
        tracker.ingest_receipt({"actor": "anon", "body": "{}", **case})

    assert tracker.discovered_body_templates == {}

    # Cap total stored templates at 40 and per-template serialized length at 600 chars
    for idx in range(50):
        huge_obj = {f"field_{k}": f"value_{k}_" + ("x" * 60) for k in range(16)}
        tracker.ingest_receipt({
            "actor": "anon",
            "method": "POST",
            "url": f"/api/ep{idx}",
            "status": 200,
            "request_body": json.dumps(huge_obj),
            "body": '{"ok": true}',
        })

    assert len(tracker.discovered_body_templates) == 40
    for tmpl_doc in tracker.discovered_body_templates.values():
        assert len(json.dumps(tmpl_doc, ensure_ascii=False, separators=(",", ":"))) <= 600


# ---------------------------------------------------------------------------
# 2. 400 / 422 Validation Field Hints
# ---------------------------------------------------------------------------


def test_validation_schema_hints_fastapi_zod_express_joi_and_missing() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=("GET", "POST", "PUT", "PATCH"),
    )

    # FastAPI / Pydantic v2 422 response
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "POST",
        "url": "/api/v1/batch",
        "status": 422,
        "content_type": "application/json",
        "body": json.dumps({
            "detail": [
                {"loc": ["body", "data"], "msg": "Input should be a valid list", "type": "list_type"},
                {"loc": ["body", "items", 0, "price"], "msg": "Invalid float", "type": "float_parsing"},
                {"loc": ["query", "dry_run"], "msg": "Field required", "type": "missing"},
            ]
        }),
    })
    assert tracker.discovered_schema_hints["/api/v1/batch"] == {
        "body.data:list_type",
        "body.items.0.price:float_parsing",
        "query.dry_run:missing",
    }
    assert {"data", "price", "dry_run"}.issubset(tracker.discovered_params["/api/v1/batch"])

    # Express-validator + Zod + Joi style 400 response
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "POST",
        "url": "/api/v1/users",
        "status": 400,
        "content_type": "application/json",
        "body": json.dumps({
            "errors": [
                {"type": "field", "location": "body", "path": "email", "msg": "Invalid email"},
                {"code": "invalid_type", "expected": "number", "path": ["profile", "age"]},
                {"path": ["role"], "type": "string.valid"},
            ]
        }),
    })
    assert tracker.discovered_schema_hints["/api/v1/users"] == {
        "body.email",
        "body.profile.age:number",
        "body.role:string.valid",
    }
    assert {"email", "age", "role"}.issubset(tracker.discovered_params["/api/v1/users"])

    # Simple {"missing": [...]} and {"fieldErrors": {...}} responses
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "PATCH",
        "url": "/api/v1/orders/42",
        "status": 400,
        "content_type": "application/json",
        "body": json.dumps({"missing": ["shipping_address", "zip_code"]}),
    })
    assert tracker.discovered_schema_hints["/api/v1/orders/{id}"] == {
        "body.shipping_address",
        "body.zip_code",
    }
    assert {"shipping_address", "zip_code"}.issubset(tracker.discovered_params["/api/v1/orders/{id}"])

    tracker.ingest_receipt({
        "actor": "anon",
        "method": "POST",
        "url": "/api/v1/notes",
        "status": 422,
        "content_type": "application/json",
        "body": json.dumps({"fieldErrors": {"subject": ["Required"], "body_text": ["Too short"]}}),
    })
    assert tracker.discovered_schema_hints["/api/v1/notes"] == {
        "body.subject",
        "body.body_text",
    }
    assert {"subject", "body_text"}.issubset(tracker.discovered_params["/api/v1/notes"])

    # Plain prose 400 / non-400-422 statuses must NOT create false-positive schema hints
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "POST",
        "url": "/api/v1/prose",
        "status": 400,
        "content_type": "application/json",
        "body": json.dumps({"detail": "Invalid JSON syntax in request body"}),
    })
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "POST",
        "url": "/api/v1/ok",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({"missing": ["ignored_on_200"]}),
    })
    assert "/api/v1/prose" not in tracker.discovered_schema_hints
    assert "/api/v1/ok" not in tracker.discovered_schema_hints


# ---------------------------------------------------------------------------
# 3. Checkpoint Round-Trip, Banner Rendering & Sharding Integration
# ---------------------------------------------------------------------------


def test_checkpoint_roundtrip_banner_and_shard_prompt_rendering() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:9000/",
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )

    # Populate enough families/routes to trigger multi-shard clustering
    for fam in ("orders", "invoices", "tickets", "reports"):
        tracker.discovered_routes[("GET", f"/api/v1/{fam}")] = f"/api/v1/{fam}"
        tracker.discovered_routes[("GET", f"/api/v1/{fam}/{{id}}")] = f"/api/v1/{fam}/{{id}}"

    tracker.ingest_receipt({
        "actor": "alice",
        "method": "POST",
        "url": "/api/v1/orders",
        "status": 201,
        "content_type": "application/json",
        "request_body": json.dumps({"items": [{"sku": "A1", "qty": 2}], "currency": "USD", "api_token": "tok-secret"}),
        "body": '{"id": 10}',
    })
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "POST",
        "url": "/api/v1/invoices",
        "status": 422,
        "content_type": "application/json",
        "body": json.dumps({"detail": [{"loc": ["body", "line_items"], "type": "list_type"}]}),
    })
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "GET",
        "url": "/file=report.txt",
        "status": 200,
        "content_type": "text/plain",
        "body": "report content",
    })

    # Checkpoint round-trip via to_dict / from_dict / load_dict
    saved = tracker.to_dict()
    restored = SurfaceFrontierTracker.from_dict(saved)
    assert restored.discovered_body_templates == tracker.discovered_body_templates
    assert restored.discovered_body_templates[("POST", "/api/v1/orders")]["api_token"] == "<redacted>"
    assert restored.discovered_schema_hints == tracker.discovered_schema_hints
    assert restored.discovered_params["/file={val}"] == {"path:file="}

    # Legacy checkpoint missing new keys restores cleanly without errors
    legacy = {
        k: v
        for k, v in saved.items()
        if k not in {"discovered_body_templates", "discovered_schema_hints"}
    }
    legacy_restored = SurfaceFrontierTracker.from_dict(legacy)
    assert legacy_restored.discovered_body_templates == {}
    assert legacy_restored.discovered_schema_hints == {}

    # Frontier banner surfaces compact schema hints, body templates, and path params while respecting max_chars
    banner = restored.format_frontier_banner(max_chars=1000)
    assert len(banner) <= 1000
    assert "path:file=" in banner
    assert "schema_hints:" in banner
    assert "body.line_items:list_type" in banner
    assert "body_templates:" in banner
    assert "POST /api/v1/orders" in banner
    for tight in (250, 120, 40, 0):
        assert len(restored.format_frontier_banner(max_chars=tight)) <= tight

    # Backward-compatible SubsystemCluster constructor without new optional fields
    compat_cluster = SubsystemCluster(
        shard_id="shard-0",
        name="compat",
        families=["orders"],
        routes=["/api/v1/orders"],
        write_ops=[],
        objects=[],
        params={},
    )
    assert compat_cluster.body_templates == {}
    assert compat_cluster.schema_hints == {}

    # Clustering attaches body_templates, schema_hints, and path params to the owning family shards
    clusters = cluster_discovered_surface(restored, max_shards=3, min_routes_for_sharding=8)
    assert len(clusters) == 3

    orders_cluster = next(c for c in clusters if "orders" in c.families)
    assert "POST /api/v1/orders" in orders_cluster.body_templates
    assert orders_cluster.body_templates["POST /api/v1/orders"]["currency"] == "USD"

    invoices_cluster = next(c for c in clusters if "invoices" in c.families)
    assert invoices_cluster.schema_hints.get("/api/v1/invoices") == ["body.line_items:list_type"]

    file_cluster = next(c for c in clusters if "file" in c.families)
    assert file_cluster.params.get("/file={val}") == ["path:file="]

    sys_orders, _ = build_shard_prompts(orders_cluster, base_system_prompt="BASE")
    assert "Observed working JSON body templates" in sys_orders
    assert "POST /api/v1/orders" in sys_orders
    assert "tok-secret" not in sys_orders

    sys_invoices, _ = build_shard_prompts(invoices_cluster, base_system_prompt="BASE")
    assert "Validation schema hints (from 400/422):" in sys_invoices
    assert "body.line_items:list_type" in sys_invoices

    sys_file, _ = build_shard_prompts(file_cluster, base_system_prompt="BASE")
    assert "path:file=" in sys_file
    assert "path-embedded inputs" in sys_file

    # Prompt rendering remains compactly bounded even with many large templates & hints
    huge_cluster = SubsystemCluster(
        shard_id="shard-big",
        name="big",
        families=["big"],
        routes=["/api/big"],
        write_ops=["POST /api/big"],
        objects=[],
        params={},
        body_templates={
            f"POST /api/big/{i}": {f"k{j}": "v" * 40 for j in range(10)}
            for i in range(25)
        },
        schema_hints={
            f"/api/big/{i}": [f"body.field_{j}:string_type" for j in range(20)]
            for i in range(25)
        },
    )
    big_sys, _ = build_shard_prompts(huge_cluster, base_system_prompt="BASE")
    assert len(big_sys) < 4500


# ---------------------------------------------------------------------------
# 4. Path-Embedded Input Parameter Detection & Route Normalization Contracts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw_path", "expected_params", "expected_template"),
    [
        ("/file=abc.txt", ["path:file="], "/file={val}"),
        ("/file=../../etc/passwd", ["path:file="], "/file={val}"),
        ("/file=/etc/passwd", ["path:file="], "/file={val}"),
        ("/file={val}", ["path:file="], "/file={val}"),
        ("/proxy=http://127.0.0.1:8080/admin", ["path:proxy="], "/proxy={val}"),
        ("/proxy=https://example.com/a/b", ["path:proxy="], "/proxy={val}"),
        ("/item=123", ["path:item="], "/item={val}"),
        ("/api/v1/render/file=report.pdf", ["path:file="], "/api/v1/render/file={val}"),
        ("/download/{filepath}", ["path:filepath"], "/download/{id}"),
        ("/download/{filename}", ["path:filename"], "/download/{id}"),
        ("/download/{path}", ["path:path"], "/download/{id}"),
        ("/fetch/{url}", ["path:url"], "/fetch/{id}"),
        ("/proxy/{url}", ["path:url"], "/proxy/{id}"),
        ("/redirect/{dest}", ["path:dest"], "/redirect/{id}"),
        ("/redirect/{target}", ["path:target"], "/redirect/{id}"),
        ("/static/{rest:path}", ["path:rest"], "/static/{id}"),
    ],
)
def test_path_embedded_params_and_route_template_normalization(
    raw_path: str,
    expected_params: list[str],
    expected_template: str,
) -> None:
    assert _extract_path_embedded_params(raw_path) == expected_params
    assert SurfaceFrontierTracker._extract_path_embedded_params(raw_path) == expected_params
    assert route_template_of(raw_path) == expected_template
    # Idempotence of route_template_of
    assert route_template_of(expected_template) == expected_template


@pytest.mark.parametrize(
    ("benign_or_bad_path", "expected_template"),
    [
        ("/api/users", "/api/users"),
        ("/health", "/health"),
        ("/robots.txt", "/robots.txt"),
        ("/api/users/{id}", "/api/users/{id}"),
        ("/api/files/{id}", "/api/files/{id}"),
        ("/api/v1/orders/42", "/api/v1/orders/{id}"),
        ("/api/v1/orders/{order_id}", "/api/v1/orders/{id}"),
        ("/tokens/YWJjZA==", "/tokens/ywjjza=="),
        ("/123=abc", "/123=abc"),
        ("/$$$=abc", "/$$$=abc"),
        ("/api/${foo}", "/api/${foo}"),
        ("/api/bad key=1", "/api/bad key=1"),
        ("/api/\\", "/api/\\"),
    ],
)
def test_path_embedded_params_ignores_ordinary_static_id_and_malformed_paths(
    benign_or_bad_path: str,
    expected_template: str,
) -> None:
    assert _extract_path_embedded_params(benign_or_bad_path) == []
    assert route_template_of(benign_or_bad_path) == expected_template


def test_path_embedded_params_discovery_probe_depth_and_sharding_family() -> None:
    assert extract_resource_family("/file=abc.txt") == "file"
    assert extract_resource_family("/file={val}") == "file"
    assert extract_resource_family("/proxy=https://example.com/a") == "proxy"
    assert extract_resource_family("/proxy={val}") == "proxy"

    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=("GET",),
    )

    # 1. HTML link discovery captures /file=avatar.png (not dropped as static image!) and OpenAPI /download/{filepath}
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/",
        "status": 200,
        "content_type": "text/html",
        "body": (
            '<html><body>'
            '<a href="/file=avatar.png">Avatar</a>'
            '<a href="/api/users">Users</a>'
            '</body></html>'
        ),
    })
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/openapi.json",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({
            "openapi": "3.0.0",
            "paths": {
                "/download/{filepath}": {"get": {"responses": {"200": {"description": "ok"}}}},
                "/api/users": {"get": {"responses": {"200": {"description": "ok"}}}},
            },
        }),
    })

    assert "path:file=" in tracker.discovered_params["/file={val}"]
    assert "path:filepath" in tracker.discovered_params["/download/{id}"]
    assert "/api/users" not in tracker.discovered_params

    # Unvisited routes highlight path-embedded inputs and key=value segments do not pollute API parity
    unvisited = tracker.unvisited_routes()
    assert any("/file=avatar.png" in r and "path:file=" in r for r in unvisited)
    assert any("/download/{filepath}" in r and "path:filepath" in r for r in unvisited)
    assert "file=avatar.png" not in tracker.ui_resource_families
    assert tracker.untested_api_parity() == []

    # 2. Visiting /file=avatar.png once leaves path:file= in unprobed_params (1 benign filename seen)
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/file=avatar.png",
        "status": 200,
        "content_type": "image/png",
        "body": "PNG",
    })
    unprobed = tracker.unprobed_params()
    assert any("/file=avatar.png" in item and "path:file=" in item for item in unprobed)
    assert "path:file=" in tracker.format_frontier_banner(max_chars=1000)

    # 3. Sending a traversal probe clears path:file= from unprobed_params immediately
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/file=../../etc/passwd",
        "status": 400,
        "content_type": "text/plain",
        "body": "invalid path",
    })
    assert not any("path:file=" in item for item in tracker.unprobed_params())

    # 4. Single-shard clustering also carries path-embedded params cleanly
    single = cluster_discovered_surface(tracker, max_shards=1, min_routes_for_sharding=8)
    assert len(single) == 1
    assert single[0].params.get("/file={val}") == ["path:file="]
    assert single[0].params.get("/download/{id}") == ["path:filepath"]
