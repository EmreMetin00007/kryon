"""Tests for Wave 2 canonical multi-origin Site Map reconciler and `cco-agent map` CLI."""
from __future__ import annotations

import json
from pathlib import Path
import stat
import sys
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import agent_cli  # noqa: E402
import agentic_surface_map  # noqa: E402
from agentic_surface import SurfaceFrontierTracker  # noqa: E402


def _synthetic_jwt() -> str:
    return ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJ1c2VyLTEifQ", "signaturePart123456"])


def _synthetic_bearer() -> str:
    return "Bearer " + "SyntheticSecretTokenValue987654321"


def test_build_surface_map_reconciles_all_sources_multi_origin_and_redacts_secrets() -> None:
    jwt_val = _synthetic_jwt()
    bearer_val = _synthetic_bearer()
    cookie_val = "session_secret_cookie_value_999"
    api_key_val = "live_api_key_value_secret_888"
    csrf_val = "csrf_token_secret_777"
    password_val = "UltraSecretPass!2026"
    query_secret = "QuerySecretValue555"

    asset_graph: dict[str, Any] = {
        "schema": "cco-asset-graph/1",
        "target": "https://www.shop.example",
        "nodes": [
            {
                "origin": "https://www.shop.example",
                "scheme": "https",
                "host": "www.shop.example",
                "port": 443,
                "in_scope": True,
                "role": "storefront",
                "alive": True,
                "status": 200,
                "waf_vendor": "cloudflare",
                "tech_signals": ["nextjs", "waf:cloudflare"],
                "sample_paths": ["/", "/catalog"],
            },
            {
                "origin": "https://api.shop.example",
                "scheme": "https",
                "host": "api.shop.example",
                "port": 443,
                "in_scope": True,
                "role": "api",
                "alive": True,
                "status": 200,
                "tech_signals": ["json", "graphql"],
                "sample_paths": ["/api/v1/orders", "/graphql"],
            },
            {
                "origin": "https://payments.evil.example",
                "scheme": "https",
                "host": "payments.evil.example",
                "port": 443,
                "in_scope": False,
                "role": "api",
                "sample_paths": ["/charge"],
            },
        ],
        "edges": [],
    }

    seed_surface: dict[str, Any] = {
        "url": "https://www.shop.example/",
        "links": [
            {
                "method": "GET",
                "url": f"https://api.shop.example/api/v1/export?file=report.csv&token={query_secret}",
                "params": ["file", "format"],
            },
            {
                "method": "GET",
                "url": "https://payments.evil.example/leak",
                "params": ["card"],
            },
        ],
        "forms": [
            {
                "method": "POST",
                "url": "https://api.shop.example/api/v1/upload",
                "multipart_schema": {"fields": ["title"], "files": ["avatar"]},
            }
        ],
        "body_templates": {
            "POST https://api.shop.example/api/v1/auth/login": {
                "username": "member1",
                "password": password_val,
                "jwt": jwt_val,
            }
        },
        "stats": {"routes_dropped_scope": 0},
    }

    stage0_result: dict[str, Any] = {
        "schema": "stage0-seed/1",
        "url": "https://www.shop.example/",
        "links": [
            {
                "method": "GET",
                "url": "/account/profile?tab=security",
                "params": ["tab"],
                "status": 200,
            }
        ],
        "forms": [
            {
                "method": "POST",
                "url": "https://api.shop.example/api/v1/orders/42/cancel",
                "params": ["reason"],
                "status": 401,
            }
        ],
        "discovered_api_hosts": [
            {
                "origin": "https://api.shop.example",
                "sample_paths": ["/api/v1/orders/42"],
            },
            {
                "origin": "https://tracker.thirdparty.example",
                "sample_paths": ["/collect"],
            },
        ],
    }

    har_flows: dict[str, Any] = {
        "schema": "har-flow/1",
        "base_url": "https://www.shop.example/",
        "flows": [
            {
                "flow_id": "flow_1",
                "name": "cart -> checkout",
                "steps": [
                    {
                        "step_index": 1,
                        "method": "POST",
                        "url": "https://api.shop.example/api/v1/cart/cart-9001/checkout",
                        "query_keys": ["currency"],
                        "content_type": "application/json",
                        "required_app_headers": {
                            "X-Storefront": "web-tr",
                            "Authorization": bearer_val,
                            "X-CSRF-Token": csrf_val,
                            "X-API-Key": api_key_val,
                        },
                        "json_template": {
                            "coupon": "SAVE10",
                            "totalPrice": 100,
                            "password": password_val,
                            "cardNumber": "4111222233334444",
                        },
                        "response_status": 200,
                    },
                    {
                        "step_index": 2,
                        "method": "POST",
                        "url": "https://api.shop.example/graphql",
                        "content_type": "application/json",
                        "required_app_headers": {"X-Storefront": "web-tr"},
                        "json_template": {
                            "operationName": "UpdateCart",
                            "query": "mutation UpdateCart($cartId: ID!) { updateCart(cartId: $cartId) { ok } }",
                            "variables": {"cartId": "cart-9001"},
                        },
                        "response_status": 200,
                    },
                    {
                        "step_index": 3,
                        "method": "POST",
                        "url": "https://payments.evil.example/out-of-scope",
                        "response_status": 200,
                    },
                ],
            }
        ],
        "stats": {"entries_dropped_scope": 0},
    }

    receipts: list[dict[str, Any]] = [
        {
            "receipt_id": "req-0001",
            "actor": "anon",
            "method": "GET",
            "url": "https://www.shop.example/catalog?page=1&sort=asc",
            "path": "/catalog",
            "query": "page=1&sort=asc",
            "status": 200,
            "content_type": "text/html; charset=utf-8",
            "request_headers": {"Accept": "text/html", "X-Channel": "web"},
            "response_headers": {"Server": "nginx"},
            "body": "<html>Catalog</html>",
        },
        {
            "receipt_id": "req-0002",
            "actor": "anon",
            "method": "GET",
            "url": "https://api.shop.example/api/v1/orders/42",
            "path": "/api/v1/orders/42",
            "status": 401,
            "content_type": "application/json",
            "request_headers": {
                "X-Storefront": "web-tr",
                "Cookie": f"sid={cookie_val}",
            },
            "response_headers": {},
            "body": '{"error":"unauthorized"}',
        },
        {
            "receipt_id": "req-0003",
            "actor": "member_a",
            "method": "GET",
            "url": "https://api.shop.example/api/v1/orders/99",
            "path": "/api/v1/orders/99",
            "status": 200,
            "content_type": "application/json",
            "request_headers": {
                "Authorization": bearer_val,
                "X-Storefront": "web-tr",
                "X-Custom-Secret": "should-never-appear",
                "X-Tenant-Id": "tenant-alpha",
            },
            "response_headers": {},
            "body": '{"order_id":99,"owner":"member_a"}',
        },
        {
            "receipt_id": "req-0004",
            "actor": "anon",
            "method": "GET",
            "url": "https://api.shop.example/api/v1/admin/stats",
            "path": "/api/v1/admin/stats",
            "status": 403,
            "content_type": "application/json",
            "request_headers": {},
            "response_headers": {},
            "body": '{"error":"forbidden"}',
        },
        {
            "receipt_id": "req-0005",
            "actor": "member_a",
            "method": "POST",
            "url": "https://api.shop.example/graphql",
            "path": "/graphql",
            "status": 200,
            "content_type": "application/json",
            "request_headers": {"Content-Type": "application/json", "X-Storefront": "web-tr"},
            "request_body": json.dumps({
                "operationName": "GetOrder",
                "query": "query GetOrder($id: ID!) { order(id: $id) { id total } }",
                "variables": {"id": "42", "api_key": api_key_val},
            }),
            "response_headers": {},
            "body": '{"data":{"order":{"id":"42","total":100}}}',
        },
        {
            "receipt_id": "req-0006",
            "actor": "member_a",
            "method": "POST",
            "url": "https://api.shop.example/graphql",
            "path": "/graphql",
            "status": 200,
            "content_type": "application/json",
            "request_headers": {"Content-Type": "application/json"},
            "request_body": json.dumps({
                "query": "mutation DeleteUser($userId: ID!) { deleteUser(userId: $userId) { ok } }",
                "variables": {"userId": "7"},
            }),
            "response_headers": {},
            "body": '{"data":{"deleteUser":{"ok":true}}}',
        },
        {
            "receipt_id": "req-0007",
            "actor": "anon",
            "method": "GET",
            "url": "https://payments.evil.example/api/secret",
            "path": "/api/secret",
            "status": 200,
            "content_type": "application/json",
            "request_headers": {},
            "response_headers": {},
            "body": "{}",
        },
    ]

    prescan_doc: dict[str, Any] = {
        "schema": "agentic-prescan/1",
        "base_url": "https://www.shop.example/",
        "waf_vendors_seen": ["cloudflare"],
        "leads": [
            {
                "lead_id": "prescan-001",
                "kind": "bola_candidate",
                "severity_hint": "high",
                "receipt_id": "req-0003",
                "url": "https://api.shop.example/api/v1/orders/99",
                "actor": "member_b",
                "control_actor": "member_a",
            },
            {
                "lead_id": "prescan-002",
                "kind": "open_redirect",
                "severity_hint": "medium",
                "receipt_id": "req-0010",
                "url": "https://www.shop.example/auth/callback?next=https://redirect-check.example.invalid",
                "param": "next",
                "actor": "anon",
            },
        ],
    }

    tracker = SurfaceFrontierTracker(
        base_url="https://www.shop.example/",
        allowed_methods=("GET", "POST"),
        in_scope_assets=("https://api.shop.example",),
        out_of_scope_assets=("https://payments.evil.example",),
    )
    tracker.visited_method_paths.add(("GET", "/account/profile"))
    tracker.discovered_routes[("GET", "https://api.shop.example/api/v1/invoices/12")] = (
        "https://api.shop.example/api/v1/invoices/12?download=true"
    )
    tracker.discovered_params["https://api.shop.example/api/v1/invoices/{id}"] = {"download", "file"}

    smap = agentic_surface_map.build_surface_map(
        base_url="https://www.shop.example/",
        receipts=receipts,
        seed_surface=seed_surface,
        stage0_result=stage0_result,
        har_flows=har_flows,
        asset_graph=asset_graph,
        prescan_doc=prescan_doc,
        surface_tracker=tracker,
        in_scope_assets=["https://api.shop.example"],
        out_of_scope_assets=["https://payments.evil.example"],
        excluded_paths=["/internal/excluded"],
    )

    assert smap["schema"] == "cco-surface-map/1"
    assert smap["base_url"] == "https://www.shop.example/"

    # Out-of-scope origins/URLs dropped and counted
    assert smap["stats"]["dropped_out_of_scope"] >= 5
    origin_urls = [o["origin"] for o in smap["origins"]]
    assert origin_urls == ["https://api.shop.example", "https://www.shop.example"]
    assert "https://payments.evil.example" not in origin_urls
    assert "https://tracker.thirdparty.example" not in origin_urls

    # Zero secret leakage anywhere in JSON or Markdown
    serialized_json = json.dumps(smap)
    rendered_md = agentic_surface_map.render_surface_map_markdown(smap)
    for forbidden in (
        jwt_val,
        bearer_val,
        "SyntheticSecretTokenValue987654321",
        cookie_val,
        api_key_val,
        csrf_val,
        password_val,
        query_secret,
        "should-never-appear",
        "4111222233334444",
    ):
        assert forbidden not in serialized_json
        assert forbidden not in rendered_md

    # Build lookup by canonical 4-tuple key
    by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for orig_entry in smap["origins"]:
        # Verify deterministic endpoint sorting by (-risk_score, method, path_template, graphql_op)
        eps = orig_entry["endpoints"]
        expected_order = sorted(
            eps,
            key=lambda e: (-e["risk_score"], e["method"], e["path_template"], e["graphql_op"]),
        )
        assert eps == expected_order
        for ep in eps:
            key = (ep["origin"], ep["method"], ep["path_template"], ep["graphql_op"])
            assert key not in by_key
            by_key[key] = ep

    # Verify origin metadata enrichment
    www_meta = next(o for o in smap["origins"] if o["origin"] == "https://www.shop.example")
    api_meta = next(o for o in smap["origins"] if o["origin"] == "https://api.shop.example")
    assert www_meta["role"] == "storefront"
    assert www_meta["waf_vendor"] == "cloudflare"
    assert "nextjs" in www_meta["tech_signals"]
    assert api_meta["role"] == "api"
    assert "graphql" in api_meta["tech_signals"]

    # Auth inference checks:
    # 1. anon=401 + member_a=200 -> "true"
    ep_order = by_key[("https://api.shop.example", "GET", "/api/v1/orders/{id}", "")]
    assert ep_order["auth_required"] == "true"
    assert ep_order["statuses_seen"] == [200, 401]
    assert ep_order["actors_seen"] == ["anon", "member_a", "member_b"]
    assert ep_order["visited"] is True
    assert set(ep_order["sources"]) == {"live", "prescan", "stage0"}
    assert ep_order["required_app_headers"] == {"X-Storefront": "web-tr", "X-Tenant-Id": "tenant-alpha"}
    assert ep_order["prescan_leads"] == [
        {"kind": "bola_candidate", "severity_hint": "high", "receipt_id": "req-0003"}
    ]

    # 2. anon=403 only -> "true"
    ep_admin = by_key[("https://api.shop.example", "GET", "/api/v1/admin/stats", "")]
    assert ep_admin["auth_required"] == "true"
    assert ep_admin["visited"] is True

    # 3. anon=200 -> "false"
    ep_catalog = by_key[("https://www.shop.example", "GET", "/catalog", "")]
    assert ep_catalog["auth_required"] == "false"
    assert ep_catalog["query_params"] == ["page", "sort"]
    assert ep_catalog["required_app_headers"] == {"X-Channel": "web"}
    assert ep_catalog["visited"] is True

    # 4. Unvisited HAR write op -> auth_required="unknown", redacted body_template, non-secret headers only
    ep_checkout = by_key[("https://api.shop.example", "POST", "/api/v1/cart/{id}/checkout", "")]
    assert ep_checkout["auth_required"] == "unknown"
    assert ep_checkout["visited"] is False
    assert ep_checkout["sources"] == ["har"]
    assert ep_checkout["query_params"] == ["currency"]
    assert "coupon" in ep_checkout["body_params"]
    assert "totalPrice" in ep_checkout["body_params"]
    assert ep_checkout["required_app_headers"] == {"X-Storefront": "web-tr"}
    assert ep_checkout["body_template"]["password"] == "<redacted>"
    assert ep_checkout["body_template"]["cardNumber"] == "<redacted>"
    assert ep_checkout["body_template"]["totalPrice"] == 100

    # 5. Distinct GraphQL operations under (origin, method, path_template, graphql_op)
    ep_gql_get = by_key[("https://api.shop.example", "POST", "/graphql", "GetOrder")]
    ep_gql_del = by_key[("https://api.shop.example", "POST", "/graphql", "DeleteUser")]
    ep_gql_upd = by_key[("https://api.shop.example", "POST", "/graphql", "UpdateCart")]
    assert ep_gql_get["visited"] is True
    assert ep_gql_del["visited"] is True
    assert ep_gql_upd["visited"] is False
    assert ep_gql_upd["sources"] == ["har"]
    assert ep_gql_get["body_template"]["variables"]["api_key"] == "<redacted>"
    assert smap["stats"]["graphql_operations_count"] == 3

    # 6. Visited via tracker visited_method_paths (no receipt for /account/profile)
    ep_profile = by_key[("https://www.shop.example", "GET", "/account/profile", "")]
    assert ep_profile["visited"] is True
    assert set(ep_profile["sources"]) == {"stage0", "tracker"}

    # 7. Multipart upload schema preserved safely
    ep_upload = by_key[("https://api.shop.example", "POST", "/api/v1/upload", "")]
    assert ep_upload["multipart_schema"] == {"fields": ["title"], "files": ["avatar"]}
    assert "multipart/form-data" in ep_upload["content_types"]

    # 8. Risk score prioritization: prescan/write/unvisited high-risk > benign visited catalog
    ep_export = by_key[("https://api.shop.example", "GET", "/api/v1/export", "")]
    assert ep_export["visited"] is False
    assert ep_export["sample_url"] == "https://api.shop.example/api/v1/export"
    assert ep_order["risk_score"] > ep_catalog["risk_score"]
    assert ep_checkout["risk_score"] > ep_catalog["risk_score"]
    assert ep_export["risk_score"] > ep_catalog["risk_score"]

    # 9. Stats consistency
    stats = smap["stats"]
    assert stats["origins_count"] == 2
    assert stats["endpoints_total"] == len(by_key)
    assert stats["endpoints_visited"] + stats["endpoints_unvisited"] == stats["endpoints_total"]
    assert stats["write_endpoints_count"] >= 5
    assert stats["params_total"] > 0
    assert set(stats["sources_counts"].keys()) == {"recon", "seed", "stage0", "har", "prescan", "tracker", "live"}


def test_write_artifacts_markdown_and_build_from_run_dir(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-001"
    (run_dir / "receipts").mkdir(parents=True)

    scope_path = tmp_path / "scope.json"
    scope_path.write_text(
        json.dumps({
            "in_scope": ["https://www.shop.example", "https://api.shop.example"],
            "out_of_scope": ["https://cdn.outside.example"],
            "excluded_paths": ["/logout"],
        }),
        encoding="utf-8",
    )

    (run_dir / "manifest.json").write_text(
        json.dumps({
            "schema": "cco-agentic/1",
            "mode": "agentic",
            "status": "completed",
            "target": "https://www.shop.example/",
            "scope": {
                "loopback_only": False,
                "scope_file": str(scope_path),
            },
        }),
        encoding="utf-8",
    )
    (run_dir / "receipts" / "req-0001.json").write_text(
        json.dumps({
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0001",
            "actor": "anon",
            "method": "GET",
            "url": "https://www.shop.example/products?q=shoe",
            "path": "/products",
            "status": 200,
            "content_type": "text/html",
            "request_headers": {"X-Region": "eu"},
            "response_headers": {},
            "body": "<html>ok</html>",
        }),
        encoding="utf-8",
    )
    (run_dir / "stage0-seed.json").write_text(
        json.dumps({
            "schema": "stage0-seed/1",
            "url": "https://www.shop.example/",
            "links": [{"method": "GET", "url": "/search?q=test", "params": ["q"], "status": 200}],
            "forms": [],
        }),
        encoding="utf-8",
    )
    (run_dir / "stage0-post-auth-seed.json").write_text(
        json.dumps({
            "schema": "stage0-seed/1",
            "url": "https://www.shop.example/",
            "links": [{"method": "GET", "url": "https://api.shop.example/api/v1/me", "status": 200}],
            "forms": [{"method": "POST", "url": "https://api.shop.example/api/v1/profile", "params": ["bio"]}],
        }),
        encoding="utf-8",
    )
    (run_dir / "har-flows.json").write_text(
        json.dumps({
            "schema": "har-flow/1",
            "base_url": "https://www.shop.example/",
            "flows": [
                {
                    "flow_id": "flow_1",
                    "steps": [
                        {
                            "step_index": 1,
                            "method": "POST",
                            "url": "https://api.shop.example/api/v1/orders",
                            "content_type": "application/json",
                            "required_app_headers": {"X-App": "web"},
                            "json_template": {"sku": "A1", "qty": 2},
                            "response_status": 201,
                        }
                    ],
                }
            ],
        }),
        encoding="utf-8",
    )
    (run_dir / "prescan-summary.json").write_text(
        json.dumps({
            "schema": "agentic-prescan/1",
            "base_url": "https://www.shop.example/",
            "leads": [
                {
                    "lead_id": "prescan-001",
                    "kind": "cors_misconfiguration",
                    "severity_hint": "high",
                    "receipt_id": "req-0001",
                    "url": "https://www.shop.example/products",
                    "actor": "anon",
                }
            ],
        }),
        encoding="utf-8",
    )
    (run_dir / "asset-graph.json").write_text(
        json.dumps({
            "schema": "cco-asset-graph/1",
            "target": "https://www.shop.example",
            "nodes": [
                {
                    "origin": "https://api.shop.example",
                    "scheme": "https",
                    "host": "api.shop.example",
                    "port": 443,
                    "in_scope": True,
                    "role": "api",
                    "sample_paths": ["/api/v1/health"],
                },
                {
                    "origin": "https://cdn.outside.example",
                    "scheme": "https",
                    "host": "cdn.outside.example",
                    "port": 443,
                    "in_scope": False,
                    "role": "cdn",
                    "sample_paths": ["/app.js"],
                },
            ],
            "edges": [],
        }),
        encoding="utf-8",
    )

    smap = agentic_surface_map.build_surface_map_from_run_dir(run_dir)
    assert smap["schema"] == "cco-surface-map/1"
    assert smap["stats"]["origins_count"] == 2
    assert smap["stats"]["dropped_out_of_scope"] == 1
    assert smap["stats"]["endpoints_visited"] == 1
    assert set(smap["stats"]["sources_counts"].keys()) >= {"live", "stage0", "har", "prescan", "recon"}

    json_path, md_path = agentic_surface_map.write_surface_map_artifacts(run_dir, smap)
    assert json_path == run_dir / "surface-map.json"
    assert md_path == run_dir / "surface-map.md"
    assert json_path.is_file()
    assert md_path.is_file()

    # Best-effort 0600 permissions on POSIX
    assert stat.S_IMODE(json_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(md_path.stat().st_mode) == 0o600

    reloaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert reloaded == smap

    md_text = md_path.read_text(encoding="utf-8")
    assert "# Canonical Site Map: https://www.shop.example/" in md_text
    assert "## https://api.shop.example" in md_text
    assert "## https://www.shop.example" in md_text
    assert "| Method | Route/Op | Params | Statuses | Auth | Sources | Visited | Leads |" in md_text
    assert "high:cors_misconfiguration(req-0001)" in md_text
    assert "cdn.outside.example" not in md_text


def test_cli_map_run_dir_mode_and_status_surface_map_field(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "cli-run"
    (run_dir / "receipts").mkdir(parents=True)
    (run_dir / "manifest.json").write_text(
        json.dumps({
            "schema": "cco-agentic/1",
            "mode": "agentic",
            "status": "completed",
            "target": "http://127.0.0.1:18080/",
            "surface_map": {
                "endpoints_total": 1,
                "origins_count": 1,
            },
        }),
        encoding="utf-8",
    )
    (run_dir / "receipts" / "req-0001.json").write_text(
        json.dumps({
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0001",
            "actor": "anon",
            "method": "GET",
            "url": "http://127.0.0.1:18080/api/v1/items/5?filter=new",
            "path": "/api/v1/items/5",
            "status": 200,
            "content_type": "application/json",
            "request_headers": {},
            "response_headers": {},
            "body": "{}",
        }),
        encoding="utf-8",
    )

    # Test positional run_dir via cco-agent map
    rc = agent_cli.main(["map", str(run_dir)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["schema"] == "cco-surface-map/1"
    assert out["mode"] == "run_dir"
    assert out["network_requests"] == 0
    assert out["stats"]["endpoints_total"] == 1
    assert out["stats"]["endpoints_visited"] == 1
    assert (run_dir / "surface-map.json").is_file()
    assert (run_dir / "surface-map.md").is_file()

    # Test --run-dir flag into custom --output-dir
    alt_out = tmp_path / "alt-map-out"
    rc_opt = agent_cli.main(["map", "--run-dir", str(run_dir), "--output-dir", str(alt_out)])
    assert rc_opt == 0
    out_opt = json.loads(capsys.readouterr().out)
    assert out_opt["surface_map_json"] == str(alt_out / "surface-map.json")
    assert (alt_out / "surface-map.json").is_file()
    assert (alt_out / "surface-map.md").is_file()

    # Verify cco-agent status surfaces manifest["surface_map"]
    rc_status = agent_cli.main(["status", str(run_dir)])
    assert rc_status == 0
    status_doc = json.loads(capsys.readouterr().out)
    assert status_doc["surface_map"] == {"endpoints_total": 1, "origins_count": 1}


def test_cli_map_offline_target_mode_zero_network_calls(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Fail loudly if any socket/network call is attempted in offline mode.
    import socket

    def _forbid_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("offline cco-agent map attempted network access")

    monkeypatch.setattr(socket, "create_connection", _forbid_network)
    monkeypatch.setattr(socket, "getaddrinfo", _forbid_network)

    scope_path = tmp_path / "scope.json"
    scope_path.write_text(
        json.dumps({
            "in_scope": ["https://www.shop.example", "https://api.shop.example"],
            "out_of_scope": ["https://evil.other.example"],
        }),
        encoding="utf-8",
    )
    graph_path = tmp_path / "asset-graph.json"
    graph_path.write_text(
        json.dumps({
            "schema": "cco-asset-graph/1",
            "target": "https://www.shop.example",
            "nodes": [
                {
                    "origin": "https://api.shop.example",
                    "scheme": "https",
                    "host": "api.shop.example",
                    "port": 443,
                    "in_scope": True,
                    "role": "api",
                    "tech_signals": ["graphql"],
                    "sample_paths": ["/api/v1/orders", "/graphql"],
                },
                {
                    "origin": "https://evil.other.example",
                    "scheme": "https",
                    "host": "evil.other.example",
                    "port": 443,
                    "in_scope": False,
                    "role": "api",
                    "sample_paths": ["/steal"],
                },
            ],
            "edges": [],
        }),
        encoding="utf-8",
    )
    urls_seed = tmp_path / "urls.txt"
    urls_seed.write_text(
        "\n".join([
            "https://www.shop.example/search?q=boots",
            "https://evil.other.example/drop-me",
        ]),
        encoding="utf-8",
    )
    har_seed = tmp_path / "capture.har"
    har_seed.write_text(
        json.dumps({
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "startedDateTime": "2026-11-27T07:00:00Z",
                        "request": {
                            "method": "POST",
                            "url": "https://api.shop.example/api/v1/cart",
                            "headers": [
                                {"name": "Authorization", "value": _synthetic_bearer()},
                                {"name": "X-Storefront", "value": "web-en"},
                                {"name": "Content-Type", "value": "application/json"},
                            ],
                            "postData": {
                                "mimeType": "application/json",
                                "text": json.dumps({"sku": "SKU-9", "qty": 1}),
                            },
                        },
                        "response": {
                            "status": 201,
                            "content": {"mimeType": "application/json", "text": '{"id":"c1"}'},
                        },
                    }
                ],
            }
        }),
        encoding="utf-8",
    )

    out_dir = tmp_path / "offline-map"
    rc = agent_cli.main([
        "map",
        "--target", "https://www.shop.example/",
        "--scope-file", str(scope_path),
        "--allow-non-loopback",
        "--asset-graph", str(graph_path),
        "--seed-surface", str(urls_seed),
        "--seed-surface", str(har_seed),
        "--output-dir", str(out_dir),
    ])
    assert rc == 0
    cli_summary = json.loads(capsys.readouterr().out)
    assert cli_summary["schema"] == "cco-surface-map/1"
    assert cli_summary["mode"] == "offline"
    assert cli_summary["network_requests"] == 0
    assert cli_summary["stats"]["origins_count"] == 2
    assert cli_summary["stats"]["endpoints_total"] >= 4
    assert cli_summary["stats"]["dropped_out_of_scope"] >= 2

    written_json = (out_dir / "surface-map.json").read_text(encoding="utf-8")
    written_md = (out_dir / "surface-map.md").read_text(encoding="utf-8")
    assert "SyntheticSecretTokenValue987654321" not in written_json
    assert "SyntheticSecretTokenValue987654321" not in written_md
    assert "evil.other.example" not in written_json
    assert "X-Storefront" in written_json
    assert "/api/v1/cart" in written_md

    # Fail-closed gate: non-loopback target without --allow-non-loopback must fail
    with pytest.raises(SystemExit) as excinfo:
        agent_cli.main([
            "map",
            "--target", "https://www.shop.example/",
            "--output-dir", str(tmp_path / "denied"),
        ])
    assert excinfo.value.code == 2


def test_graphql_get_op_and_plan_only_run_dir_and_risk_priority(tmp_path: Path) -> None:
    smap = agentic_surface_map.build_surface_map(
        base_url="http://127.0.0.1:18080/",
        receipts=[
            {
                "receipt_id": "req-0001",
                "actor": "anon",
                "method": "GET",
                "url": "http://127.0.0.1:18080/gql?operationName=ViewerHealth&query=query+ViewerHealth+%7B+ok+%7D",
                "status": 200,
                "content_type": "application/json",
                "request_headers": {},
                "response_headers": {},
                "body": '{"data":{"ok":true}}',
            },
            {
                "receipt_id": "req-0002",
                "actor": "anon",
                "method": "GET",
                "url": "http://127.0.0.1:18080/robots.txt",
                "status": 200,
                "content_type": "text/plain",
                "request_headers": {},
                "response_headers": {},
                "body": "User-agent: *",
            },
        ],
        seed_surface={
            "links": [
                {"method": "GET", "url": "/download?file=invoice.pdf", "params": ["file"]},
            ],
        },
    )
    eps = smap["origins"][0]["endpoints"]
    by_route = {(e["method"], e["path_template"], e["graphql_op"]): e for e in eps}
    assert ("GET", "/gql", "ViewerHealth") in by_route
    assert smap["stats"]["graphql_operations_count"] == 1
    assert by_route[("GET", "/download", "")]["risk_score"] > by_route[("GET", "/robots.txt", "")]["risk_score"]

    # Plan-only run_dir (agentic-plan.json without manifest.json)
    plan_dir = tmp_path / "plan-only"
    plan_dir.mkdir()
    (plan_dir / "agentic-plan.json").write_text(
        json.dumps({
            "schema": "cco-agentic/1",
            "mode": "plan_only",
            "target": "http://127.0.0.1:18080/",
        }),
        encoding="utf-8",
    )
    (plan_dir / "stage0-seed.json").write_text(
        json.dumps({
            "schema": "stage0-seed/1",
            "url": "http://127.0.0.1:18080/",
            "links": [{"method": "GET", "url": "/api/items", "status": 200}],
            "forms": [],
        }),
        encoding="utf-8",
    )
    plan_map = agentic_surface_map.build_surface_map_from_run_dir(plan_dir)
    assert plan_map["stats"]["endpoints_total"] == 1
    assert plan_map["origins"][0]["endpoints"][0]["path_template"] == "/api/items"


def test_surface_map_from_run_dir_reads_monolithic_surface_frontier_shards_and_manifest_asset_graph(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "sharded-run"
    (run_dir / "shards" / "shard-01").mkdir(parents=True)
    (run_dir / "shards" / "shard-02").mkdir(parents=True)

    external_ag = tmp_path / "external-asset-graph.json"
    external_ag.write_text(
        json.dumps({
            "schema": "cco-asset-graph/1",
            "target": "https://www.shop.example",
            "nodes": [
                {
                    "origin": "https://api.shop.example",
                    "scheme": "https",
                    "host": "api.shop.example",
                    "port": 443,
                    "in_scope": True,
                    "role": "api",
                    "sample_paths": ["/api/v1/recon-only"],
                }
            ],
            "edges": [],
        }),
        encoding="utf-8",
    )

    scope_path = tmp_path / "scope.json"
    scope_path.write_text(
        json.dumps({"in_scope": ["https://www.shop.example", "https://api.shop.example"]}),
        encoding="utf-8",
    )

    (run_dir / "manifest.json").write_text(
        json.dumps({
            "schema": "cco-agentic/1",
            "mode": "agentic",
            "status": "completed",
            "target": "https://www.shop.example/",
            "scope": {"loopback_only": False, "scope_file": str(scope_path)},
            "asset_graph": {"in_scope_hosts_count": 1, "file": str(external_ag)},
        }),
        encoding="utf-8",
    )

    # Monolithic checkpoint using real key name "surface_frontier"
    (run_dir / "checkpoint.json").write_text(
        json.dumps({
            "schema": "agentic-checkpoint/1",
            "surface_frontier": {
                "base_url": "https://www.shop.example/",
                "visited_method_paths": [["GET", "/monolithic-visited"]],
                "discovered_routes": [["GET", "/monolithic-discovered", "/monolithic-discovered"]],
            },
        }),
        encoding="utf-8",
    )
    # Shard checkpoints under shards/*/checkpoint.json
    (run_dir / "shards" / "shard-01" / "checkpoint.json").write_text(
        json.dumps({
            "schema": "agentic-shard-checkpoint/1",
            "surface_frontier": {
                "visited_method_paths": [["POST", "https://api.shop.example/api/v1/shard-one"]],
                "discovered_params": {"https://api.shop.example/api/v1/shard-one": ["item_id"]},
            },
        }),
        encoding="utf-8",
    )
    (run_dir / "shards" / "shard-02" / "checkpoint.json").write_text(
        json.dumps({
            "schema": "agentic-shard-checkpoint/1",
            "surface_tracker": {
                "discovered_routes": [["GET", "https://api.shop.example/api/v1/shard-two", ""]],
            },
        }),
        encoding="utf-8",
    )

    smap = agentic_surface_map.build_surface_map_from_run_dir(run_dir)
    by_route = {
        (ep["origin"], ep["method"], ep["path_template"]): ep
        for orig in smap["origins"]
        for ep in orig["endpoints"]
    }
    assert ("https://www.shop.example", "GET", "/monolithic-visited") in by_route
    assert by_route[("https://www.shop.example", "GET", "/monolithic-visited")]["visited"] is True
    assert ("https://www.shop.example", "GET", "/monolithic-discovered") in by_route
    assert ("https://api.shop.example", "POST", "/api/v1/shard-one") in by_route
    assert "item_id" in by_route[("https://api.shop.example", "POST", "/api/v1/shard-one")]["body_params"]
    assert ("https://api.shop.example", "GET", "/api/v1/shard-two") in by_route
    assert ("https://api.shop.example", "GET", "/api/v1/recon-only") in by_route


def test_surface_map_ingests_har_form_xml_stage0_headers_graphql_leads_and_waf_only_origin() -> None:
    stage0_merged = agentic_surface_map._merge_stage0_docs([
        {
            "schema": "stage0-seed/1",
            "url": "https://www.shop.example/",
            "links": [{"method": "GET", "url": "/stage0-a"}],
            "observed_app_headers": {
                "X-Storefront": "web-tr",
                "X-Private-Key": "secret-priv-1",
                "X-AntiCSRF": "secret-csrf-1",
            },
        },
        {
            "schema": "stage0-seed/1",
            "url": "https://www.shop.example/",
            "links": [{"method": "GET", "url": "/stage0-b"}],
            "app_headers": {
                "X-Region": "eu",
                "X-Amz-Access-Key": "secret-amz-1",
            },
        },
    ])
    assert stage0_merged is not None
    assert stage0_merged["observed_app_headers"] == {"X-Storefront": "web-tr"}
    assert stage0_merged["app_headers"] == {"X-Region": "eu"}

    har_flows = {
        "schema": "har-flow/1",
        "base_url": "https://www.shop.example/",
        "flows": [
            {
                "flow_id": "flow_1",
                "steps": [
                    {
                        "step_index": 1,
                        "method": "POST",
                        "url": "/checkout/apply",
                        "body_kind": "form",
                        "content_type": "application/x-www-form-urlencoded",
                        "form_template": {
                            "cart_id": "C-1",
                            "quantity": "2",
                            "user_session_id": "SHOULD_REDACT_SESS_1",
                        },
                        "response_status": 200,
                    },
                    {
                        "step_index": 2,
                        "method": "POST",
                        "url": "/soap/order",
                        "body_kind": "xml",
                        "content_type": "application/xml",
                        "xml_tags": ["soap:Envelope", "CreateOrder", "quantity", "owner_id"],
                        "response_status": 200,
                    },
                ],
            }
        ],
    }

    prescan_doc = {
        "schema": "agentic-prescan/1",
        "base_url": "https://www.shop.example/",
        "waf_vendors_seen": ["akamai"],
        "leads": [
            {
                "kind": "graphql_admin_query_exposed",
                "severity_hint": "high",
                "url": "https://www.shop.example/graphql",
                "operation": "adminUsers",
                "receipt_id": "req-0011",
            },
            {
                "kind": "graphql_id_query_accessible",
                "severity_hint": "medium",
                "url": "https://www.shop.example/graphql",
                "operation": "orderById",
                "receipt_id": "req-0012",
            },
            {
                "kind": "graphql_batching_enabled",
                "severity_hint": "medium",
                "url": "https://www.shop.example/graphql",
                "operation": "__typename",
                "receipt_id": "req-0013",
            },
        ],
    }

    smap = agentic_surface_map.build_surface_map(
        base_url="https://www.shop.example/",
        stage0_result=stage0_merged,
        har_flows=har_flows,
        prescan_doc=prescan_doc,
    )
    serialized = json.dumps(smap)
    assert "SHOULD_REDACT_SESS_1" not in serialized
    assert "secret-priv-1" not in serialized
    assert "secret-csrf-1" not in serialized
    assert "secret-amz-1" not in serialized

    by_key = {
        (ep["method"], ep["path_template"], ep["graphql_op"]): ep
        for orig in smap["origins"]
        for ep in orig["endpoints"]
    }
    # HAR form_template & xml_tags ingested
    ep_form = by_key[("POST", "/checkout/apply", "")]
    assert {"cart_id", "quantity", "user_session_id"}.issubset(set(ep_form["body_params"]))
    assert ep_form["body_template"]["user_session_id"] == "<redacted>"
    assert "application/x-www-form-urlencoded" in ep_form["content_types"]

    ep_xml = by_key[("POST", "/soap/order", "")]
    assert {"Envelope", "CreateOrder", "quantity", "owner_id"}.issubset(set(ep_xml["body_params"]))
    assert "application/xml" in ep_xml["content_types"]

    # Stage 0 safe non-secret app headers attached
    ep_s0 = by_key[("GET", "/stage0-a", "")]
    assert ep_s0["required_app_headers"] == {"X-Region": "eu", "X-Storefront": "web-tr"}

    # Prescan GraphQL leads default to POST and read lead["operation"]
    assert ("POST", "/graphql", "adminUsers") in by_key
    assert ("POST", "/graphql", "orderById") in by_key
    assert ("POST", "/graphql", "__typename") in by_key
    assert smap["stats"]["graphql_operations_count"] == 3

    # Prescan-only build still ensures base origin and attaches waf_vendors_seen
    waf_only_map = agentic_surface_map.build_surface_map(
        base_url="https://www.shop.example/",
        prescan_doc={"waf_vendors_seen": ["cloudflare"], "leads": []},
    )
    assert waf_only_map["stats"]["origins_count"] == 1
    assert waf_only_map["origins"][0]["waf_vendor"] == "cloudflare"
    assert "waf:cloudflare" in waf_only_map["origins"][0]["tech_signals"]


def test_surface_map_sanitizes_raw_token_path_segments_and_hardened_b2_headers() -> None:
    raw_jwt = _synthetic_jwt()
    raw_ghp = "ghp_" + "AbCdEf0123456789012345"
    raw_akia = "AKIA" + "0123456789ABCDEF"
    raw_sk = "sk_live_" + "0123456789abcdef0123"
    raw_aiza = "AIza" + "SyTestKeyValue1234567890"

    assert agentic_surface_map._sanitize_sample_path(f"/verify/{raw_jwt}") == "/verify/<REDACTED>"
    assert agentic_surface_map._sanitize_sample_path(f"/cb/{raw_ghp}") == "/cb/<REDACTED>"
    assert agentic_surface_map._sanitize_sample_path(f"/key/{raw_akia}") == "/key/<REDACTED>"
    assert agentic_surface_map._sanitize_sample_path(f"/items/token={raw_sk}") == "/items/token=<REDACTED>"
    assert agentic_surface_map._sanitize_sample_path("/api/v1/orders/42") == "/api/v1/orders/42"

    smap = agentic_surface_map.build_surface_map(
        base_url="https://www.shop.example/",
        receipts=[
            {
                "receipt_id": "req-0001",
                "actor": "anon",
                "method": "GET",
                "url": f"https://www.shop.example/verify/{raw_jwt}",
                "status": 200,
                "request_headers": {
                    "X-Storefront": "web-tr",
                    "X-Private-Key": "priv-secret",
                    "Ocp-Apim-Subscription-Key": "sub-secret",
                    "X-User-Session": "sess-secret",
                    "X-AntiCSRF": "csrf-secret",
                    "X-Amz-Access-Key": raw_akia,
                    "X-CustomAuth": "custom-auth-secret",
                    "X-Custom-Val-1": raw_ghp,
                    "X-Custom-Val-2": raw_sk,
                    "X-Custom-Val-3": raw_aiza,
                    "X-HMAC-Sig": "sig-secret",
                },
                "response_headers": {},
                "body": "ok",
            },
            {
                "receipt_id": "req-0002",
                "actor": "anon",
                "method": "GET",
                "url": f"https://www.shop.example/cb/{raw_ghp}",
                "status": 200,
                "request_headers": {},
                "response_headers": {},
                "body": "ok",
            },
        ],
    )
    serialized = json.dumps(smap)
    for secret in (
        raw_jwt,
        raw_ghp,
        raw_akia,
        raw_sk,
        raw_aiza,
        "priv-secret",
        "sub-secret",
        "sess-secret",
        "csrf-secret",
        "custom-auth-secret",
        "sig-secret",
    ):
        assert secret not in serialized
    eps = smap["origins"][0]["endpoints"]
    sample_urls = {ep["sample_url"] for ep in eps}
    assert "https://www.shop.example/verify/<REDACTED>" in sample_urls
    assert "https://www.shop.example/cb/<REDACTED>" in sample_urls
    verify_ep = next(ep for ep in eps if ep["sample_url"] == "https://www.shop.example/verify/<REDACTED>")
    assert verify_ep["required_app_headers"] == {"X-Storefront": "web-tr"}


