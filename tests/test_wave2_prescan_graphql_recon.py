"""Wave 2 tests: GraphQL full introspection + safe probes, multi-origin prescan, BFF headers/POST prematrix, and recon API spec/GraphQL probing."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any, Callable, Iterator
from urllib.parse import parse_qs, urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_graphql  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_prescan import (  # noqa: E402
    CORS_PROBE_ORIGIN,
    GRAPHQL_FULL_INTROSPECTION_QUERY,
    GRAPHQL_INTROSPECTION_QUERY,
    _collect_candidates,
    _is_graphql_introspection_200,
    _is_graphql_mutation_payload,
    _is_graphql_mutation_query,
    _is_safe_read_lookup_post,
    _is_secret_or_reserved_extra_header,
    _sanitize_extra_headers,
    format_prescan_handoff,
    run_deterministic_prescan,
)
from agentic_receipts import ReceiptStore  # noqa: E402
import agentic_recon  # noqa: E402


@contextmanager
def _start_test_server(
    router: Callable[[str, str, dict[str, str], bytes], tuple[int, str, bytes | str, dict[str, str]]],
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    requests_log: list[dict[str, Any]] = []
    lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            with lock:
                requests_log.append({
                    "method": self.command,
                    "path": self.path,
                    "headers": hdrs,
                    "body": body,
                })
            status, ctype, payload, extra_hdrs = router(self.command, self.path, hdrs, body)
            raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            for hk, hv in (extra_hdrs or {}).items():
                self.send_header(hk, hv)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

        def do_GET(self) -> None:
            self._handle()

        def do_HEAD(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", requests_log
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _make_client(
    tmp_path: Path,
    *,
    base_url: str,
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST"),
    max_requests: int = 80,
    in_scope_assets: tuple[str, ...] = (),
    global_headers: dict[str, str] | None = None,
) -> AgenticHTTPClient:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager(accounts or [], global_headers=global_headers)
    return AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
        in_scope_assets=in_scope_assets,
    )


def _full_introspection_payload() -> dict[str, Any]:
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": None,
                "types": [
                    {"kind": "SCALAR", "name": "ID"},
                    {"kind": "SCALAR", "name": "String"},
                    {"kind": "SCALAR", "name": "Boolean"},
                    {
                        "kind": "OBJECT",
                        "name": "User",
                        "fields": [
                            {
                                "name": "id",
                                "args": [],
                                "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                            },
                            {"name": "email", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                            {"name": "passwordHash", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "AuditLog",
                        "fields": [
                            {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                            {"name": "action", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                            {"name": "internalNotes", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "fields": [
                            {
                                "name": "user",
                                "args": [
                                    {
                                        "name": "id",
                                        "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                                    }
                                ],
                                "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                            },
                            {
                                "name": "adminAuditLogs",
                                "args": [],
                                "type": {"kind": "LIST", "name": None, "ofType": {"kind": "OBJECT", "name": "AuditLog", "ofType": None}},
                            },
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Mutation",
                        "fields": [
                            {
                                "name": "deleteUser",
                                "args": [
                                    {
                                        "name": "id",
                                        "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                                    }
                                ],
                                "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None},
                            },
                            {
                                "name": "promoteAdmin",
                                "args": [
                                    {
                                        "name": "userId",
                                        "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                                    }
                                ],
                                "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                            },
                        ],
                    },
                ],
            }
        }
    }


def test_prescan_full_graphql_introspection_and_safe_probes(tmp_path: Path) -> None:
    assert "queryType" in GRAPHQL_INTROSPECTION_QUERY
    assert "types" in GRAPHQL_FULL_INTROSPECTION_QUERY
    assert "mutationType" in GRAPHQL_FULL_INTROSPECTION_QUERY
    assert "inputFields" in GRAPHQL_FULL_INTROSPECTION_QUERY

    full_schema = _full_introspection_payload()

    def _eval_single_query(qtext: str) -> dict[str, Any]:
        if "__schema" in qtext:
            if "types" in qtext:
                return full_schema
            return {"data": {"__schema": {"queryType": {"name": "Query"}}}}
        if "adminAuditLogs" in qtext:
            return {
                "data": {
                    "adminAuditLogs": [
                        {"id": "audit-1", "action": "grant_role", "internalNotes": "priv-entry"},
                    ]
                }
            }
        if "user(" in qtext:
            return {
                "data": {
                    "user": {
                        "id": "1",
                        "email": "alice@example.invalid",
                    }
                }
            }
        return {"errors": [{"message": "unknown query"}]}

    def router(method: str, raw_path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/graphql" and method == "POST":
            payload = json.loads(body.decode("utf-8"))
            if isinstance(payload, list):
                return 200, "application/json", json.dumps([_eval_single_query(str(item.get("query") or "")) for item in payload]), {}
            return 200, "application/json", json.dumps(_eval_single_query(str(payload.get("query") or ""))), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_test_server(router) as (origin, requests_log):
        client = _make_client(tmp_path, base_url=f"{origin}/", max_requests=60)
        out_dir = tmp_path / "out"
        doc = run_deterministic_prescan(
            client,
            output_dir=out_dir,
            candidate_urls=["/graphql"],
            max_requests=20,
        )

    gql_post_reqs = [r for r in requests_log if r["path"] == "/graphql" and r["method"] == "POST"]
    # 1 lightweight introspection + 1 full introspection follow-up + 3 safe probes (user, adminAuditLogs, batch)
    assert len(gql_post_reqs) == 5
    # Verify NO mutation was ever sent!
    for req in gql_post_reqs:
        body_text = req["body"].decode("utf-8", errors="replace").lower()
        assert "deleteuser" not in body_text
        assert "promoteadmin" not in body_text
        assert "mutation {" not in body_text

    leads = doc["leads"]
    by_kind = {lead["kind"]: lead for lead in leads}
    assert {
        "graphql_introspection",
        "graphql_batching_enabled",
        "graphql_admin_query_exposed",
        "graphql_id_query_accessible",
    } <= set(by_kind)

    intro = by_kind["graphql_introspection"]
    stats = intro["graphql_schema_stats"]
    assert stats["queries_count"] == 2
    assert stats["mutations_count"] == 2
    assert stats["id_lookup_queries_count"] == 1
    assert stats["admin_operations_count"] >= 1
    assert stats["sensitive_fields_count"] >= 2
    assert "[GRAPHQL SCHEMA]" in intro["next_step"]

    # Every emitted GraphQL lead must point to an exact recorded receipt_id in ReceiptStore.
    receipt_ids = set(client.receipt_store.list_ids())
    for kind in ("graphql_introspection", "graphql_batching_enabled", "graphql_admin_query_exposed", "graphql_id_query_accessible"):
        lead = by_kind[kind]
        assert lead["receipt_id"] in receipt_ids

    assert by_kind["graphql_admin_query_exposed"]["operation"] == "adminAuditLogs"
    assert by_kind["graphql_admin_query_exposed"]["severity_hint"] == "high"
    assert by_kind["graphql_id_query_accessible"]["operation"] == "user"
    assert by_kind["graphql_batching_enabled"]["severity_hint"] == "medium"

    handoff = format_prescan_handoff(doc, max_chars=2400)
    assert "graphql_admin_query_exposed" in handoff
    assert "graphql_batching_enabled" in handoff
    assert "graphql_id_query_accessible" in handoff
    assert "queries=2 mutations=2" in handoff


def test_prescan_multi_origin_candidates_not_collapsed_and_openapi_postman_ingested(tmp_path: Path) -> None:
    def _make_router(tag: str) -> Callable[[str, str, dict[str, str], bytes], tuple[int, str, str, dict[str, str]]]:
        def router(method: str, raw_path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
            parsed = urlsplit(raw_path)
            path = parsed.path
            qs = parse_qs(parsed.query)
            auth = headers.get("authorization", "")
            actor = "member-a" if auth == "Bearer tok-a" else ("member-b" if auth == "Bearer tok-b" else "anon")
            if path == "/graphql" and method == "POST":
                return 200, "application/json", json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}), {}
            if path == "/api/v1/orders/1":
                if actor == "anon":
                    return 401, "application/json", json.dumps({"error": "unauthorized"}), {}
                return 200, "application/json", json.dumps({
                    "order_id": 1,
                    "owner": "member-a",
                    "email": f"alice-{tag}@example.invalid",
                    "total": 42,
                }), {}
            if path == "/login":
                nxt = (qs.get("next") or [""])[0]
                if nxt:
                    return 302, "text/plain", "", {"Location": nxt}
            return 200, "application/json", json.dumps({"ok": True}), {}

        return router

    with _start_test_server(_make_router("a")) as (origin_a, _log_a), _start_test_server(_make_router("b")) as (origin_b, _log_b):
        client = _make_client(
            tmp_path,
            base_url=f"{origin_a}/",
            accounts=[
                {"alias": "member-a", "role": "member", "access_token": "tok-a"},
                {"alias": "member-b", "role": "member", "access_token": "tok-b"},
            ],
            max_requests=80,
            in_scope_assets=(origin_a, origin_b),
        )
        seed_surface = {
            "openapi_operations": [
                {"method": "GET", "url": f"{origin_a}/api/v1/orders/1", "params": []},
                {"method": "GET", "url": f"{origin_b}/api/v1/orders/1", "params": []},
                {"method": "GET", "url": f"{origin_a}/login", "params": [{"name": "next", "in": "query"}]},
                {"method": "GET", "url": f"{origin_b}/login", "params": [{"name": "next", "in": "query"}]},
            ],
            "postman_ops": [
                {"method": "POST", "url": f"{origin_a}/graphql", "body_keys": ["query"]},
                {"method": "POST", "url": f"{origin_b}/graphql", "body_keys": ["query"]},
            ],
        }

        cand = _collect_candidates(client, seed_surface=seed_surface, candidate_urls=())
        assert (origin_a, "/graphql") in cand.seen_graphql_paths
        assert (origin_b, "/graphql") in cand.seen_graphql_paths
        assert set(cand.graphql_urls) == {f"{origin_a}/graphql", f"{origin_b}/graphql"}

        assert (origin_a, "/api/v1/orders/1") in cand.seen_norm_paths
        assert (origin_b, "/api/v1/orders/1") in cand.seen_norm_paths
        assert (origin_a, "/api/v1/orders/1") in cand.get_eligible_paths
        assert (origin_b, "/api/v1/orders/1") in cand.get_eligible_paths

        assert (origin_a, "/login", "next") in cand.seen_redirect_keys
        assert (origin_b, "/login", "next") in cand.seen_redirect_keys

        doc = run_deterministic_prescan(client, seed_surface=seed_surface, max_requests=30)

    gql_urls = {lead["url"] for lead in doc["leads"] if lead["kind"] == "graphql_introspection"}
    assert f"{origin_a}/graphql" in gql_urls
    assert f"{origin_b}/graphql" in gql_urls

    bola_urls = {lead["url"] for lead in doc["leads"] if lead["kind"] == "bola_candidate"}
    assert f"{origin_a}/api/v1/orders/1" in bola_urls
    assert f"{origin_b}/api/v1/orders/1" in bola_urls


def test_prescan_extra_headers_sanitized_har_flows_and_safe_post_prematrix(tmp_path: Path) -> None:
    leaked_auth = "Bearer hdr-secret-auth-9911"
    leaked_cookie = "sid=hdr-secret-cookie-8822"
    leaked_csrf = "csrf-secret-7733"
    leaked_apikey = "apikey-secret-6644"

    def router(method: str, raw_path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        # BFF requires X-Storefront=web and X-Api-Version=2 on every request.
        if headers.get("x-storefront") != "web" or headers.get("x-api-version") != "2":
            return 400, "application/json", json.dumps({"error": "missing BFF headers"}), {}

        auth = headers.get("authorization", "")
        actor = "member-a" if auth == "Bearer tok-alice" else ("member-b" if auth == "Bearer tok-bob" else "anon")

        if path == "/api/v1/profile" and method == "GET":
            origin = headers.get("origin", "")
            extra = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} if origin else {}
            return 200, "application/json", json.dumps({"ok": True}), extra

        if path == "/api/v1/orders/lookup" and method == "POST":
            if actor == "anon":
                return 401, "application/json", json.dumps({"error": "unauthorized"}), {}
            parsed = json.loads(body.decode("utf-8") or "{}")
            return 200, "application/json", json.dumps({
                "order_id": parsed.get("order_id", 101),
                "owner": "member-a",
                "email": "alice@example.invalid",
                "total": 250,
            }), {}

        if path == "/api/v1/admin/stats/query" and method == "POST":
            return 200, "application/json", json.dumps({
                "total_users": 99,
                "monthly_revenue": 12000,
                "active_tenants": 4,
            }), {}

        if path in {"/api/v1/cart/checkout", "/api/v1/orders/delete"}:
            return 200, "application/json", json.dumps({"mutated": True}), {}

        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_test_server(router) as (origin, requests_log):
        client = _make_client(
            tmp_path,
            base_url=f"{origin}/",
            accounts=[
                {"alias": "member-a", "role": "member", "access_token": "tok-alice"},
                {"alias": "member-b", "role": "member", "access_token": "tok-bob"},
            ],
            max_requests=80,
        )
        har_flows = {
            "schema": "har-flow/1",
            "recommended_app_headers": {
                "X-Storefront": "web",
                "Authorization": leaked_auth,
            },
            "flows": [
                {
                    "flow_id": "flow_1",
                    "name": "profile -> lookup -> checkout",
                    "steps": [
                        {
                            "step_index": 1,
                            "method": "GET",
                            "url": "/api/v1/profile",
                            "query_keys": [],
                            "json_template": None,
                        },
                        {
                            "step_index": 2,
                            "method": "POST",
                            "url": "/api/v1/orders/lookup",
                            "query_keys": [],
                            "json_template": {"order_id": 101},
                        },
                        {
                            "step_index": 3,
                            "method": "POST",
                            "url": "/api/v1/cart/checkout",
                            "query_keys": [],
                            "json_template": {"cart_id": "c-1", "total": 100},
                        },
                    ],
                }
            ],
        }
        seed_surface = {
            "body_templates": {
                "POST /api/v1/admin/stats/query": {"window": "7d"},
                "POST /api/v1/orders/delete": {"order_id": 101},
            }
        }

        out_dir = tmp_path / "prescan-out"
        doc = run_deterministic_prescan(
            client,
            output_dir=out_dir,
            seed_surface=seed_surface,
            har_flows=har_flows,
            extra_headers={
                "X-Storefront": "web",
                "X-Api-Version": "2",
                "Authorization": leaked_auth,
                "Cookie": leaked_cookie,
                "X-CSRF-Token": leaked_csrf,
                "X-API-Key": leaked_apikey,
            },
            max_requests=24,
        )

    assert len(requests_log) >= 5
    # Verify BFF headers were forwarded on every request, while stripped secret headers were NEVER forwarded.
    for req in requests_log:
        hdrs = req["headers"]
        assert hdrs.get("x-storefront") == "web"
        assert hdrs.get("x-api-version") == "2"
        assert hdrs.get("authorization") != leaked_auth
        assert "cookie" not in hdrs
        assert "x-csrf-token" not in hdrs
        assert "x-api-key" not in hdrs

    # Unsafe/destructive POSTs must NEVER be probed.
    probed_paths = {urlsplit(r["path"]).path for r in requests_log}
    assert "/api/v1/cart/checkout" not in probed_paths
    assert "/api/v1/orders/delete" not in probed_paths

    # Verify leads emitted for HAR-ingested GET + safe read/lookup POST endpoints.
    leads = doc["leads"]
    cors_leads = [l for l in leads if l["kind"] == "cors_misconfiguration"]
    assert len(cors_leads) == 1
    assert "/api/v1/profile" in cors_leads[0]["url"]
    assert cors_leads[0]["acao"] == CORS_PROBE_ORIGIN

    post_bola = [l for l in leads if l["kind"] == "bola_candidate" and l.get("method") == "POST"]
    assert len(post_bola) == 1
    assert "/api/v1/orders/lookup" in post_bola[0]["url"]

    post_bfla = [l for l in leads if l["kind"] == "bfla_candidate" and l.get("method") == "POST"]
    assert len(post_bfla) == 1
    assert "/api/v1/admin/stats/query" in post_bfla[0]["url"]

    # Zero secret leaks on disk or returned doc.
    summary_raw = (out_dir / "prescan-summary.json").read_text(encoding="utf-8")
    for secret in (leaked_auth, "hdr-secret-auth-9911", leaked_cookie, leaked_csrf, leaked_apikey):
        assert secret not in summary_raw
        assert secret not in json.dumps(doc)


def test_recon_probes_api_spec_and_graphql_and_exposes_via_load_asset_graph(tmp_path: Path) -> None:
    def api_router(_m: str, raw_path: str, _h: dict[str, str], _b: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            return 200, "application/json", json.dumps({"service": "orders-bff", "ok": True}), {}
        if path == "/openapi.json":
            return 200, "application/json", json.dumps({
                "openapi": "3.0.3",
                "info": {"title": "Orders API", "version": "1.0"},
                "paths": {"/v1/orders": {"get": {}}},
            }), {}
        if path == "/graphql":
            return 200, "application/json", json.dumps({"data": {"__typename": "Query"}}), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    def swagger_unknown_router(_m: str, raw_path: str, _h: dict[str, str], _b: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/swagger.json":
            return 200, "application/json", json.dumps({
                "swagger": "2.0",
                "info": {"title": "Legacy API"},
                "paths": {"/legacy/items": {}},
            }), {}
        return 404, "text/plain", "not found", {}

    def web_router(_m: str, raw_path: str, _h: dict[str, str], _b: bytes) -> tuple[int, str, str, dict[str, str]]:
        return 200, "text/html", "<html><head><title>Main Storefront</title></head><body>Hi</body></html>", {}

    with (
        _start_test_server(api_router) as (api_origin, api_log),
        _start_test_server(swagger_unknown_router) as (spec_origin, spec_log),
        _start_test_server(web_router) as (web_origin, web_log),
    ):
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(
            json.dumps({"in_scope": [web_origin, api_origin, spec_origin]}),
            encoding="utf-8",
        )
        out_dir = tmp_path / "recon-out"
        graph_path, live_doc = agentic_recon.run_recon(
            target=web_origin,
            output_dir=out_dir,
            scope_file=scope_file,
            allow_non_loopback=True,
            max_requests=25,
            max_rps=0.0,
            execute=True,
        )

        # Storefront host must NOT be probed for API spec / GraphQL paths.
        web_paths = {urlsplit(r["path"]).path for r in web_log}
        assert "/openapi.json" not in web_paths
        assert "/swagger.json" not in web_paths
        assert "/graphql" not in web_paths

        # API host received /openapi.json + /graphql probes and skipped redundant /swagger.json once /openapi.json hit.
        api_paths = {urlsplit(r["path"]).path for r in api_log}
        assert {"/openapi.json", "/graphql"} <= api_paths
        assert "/swagger.json" not in api_paths
        assert len(spec_log) >= 4

        graph = agentic_recon.AssetGraph.from_dict(json.loads(graph_path.read_text(encoding="utf-8")))
        api_node = graph.get_node(api_origin)
        spec_node = graph.get_node(spec_origin)
        assert api_node is not None
        assert "/openapi.json" in api_node.sample_paths
        assert "/graphql" in api_node.sample_paths
        assert "openapi" in api_node.tech_signals
        assert "graphql" in api_node.tech_signals
        assert api_node.role == "graphql"

        assert spec_node is not None
        assert "/swagger.json" in spec_node.sample_paths
        assert "openapi" in spec_node.tech_signals
        assert spec_node.role == "api"
        assert live_doc["requests_sent"] <= 25

        # Verify load_asset_graph_for_run exposes enriched hints, api_hosts, and tech_signals cleanly.
        loaded = agentic_recon.load_asset_graph_for_run(
            graph_path,
            base_url=f"{web_origin}/",
            in_scope_assets=(web_origin, api_origin, spec_origin),
        )
        assert api_origin in loaded["api_hosts"]
        assert spec_origin in loaded["api_hosts"]
        assert f"{api_origin}/openapi.json" in loaded["discovery_hints"]
        assert f"{api_origin}/graphql" in loaded["discovery_hints"]
        assert f"{spec_origin}/swagger.json" in loaded["discovery_hints"]
        hosts_by_origin = {h["origin"]: h for h in loaded["in_scope_hosts"]}
        assert "openapi" in hosts_by_origin[api_origin]["tech_signals"]
        assert "graphql" in hosts_by_origin[api_origin]["tech_signals"]
        assert "/openapi.json" in hosts_by_origin[api_origin]["sample_paths"]
        assert "/graphql" in hosts_by_origin[api_origin]["sample_paths"]

        # Tight max_requests cap skips spec probing gracefully without exceeding budget.
        tight_dir = tmp_path / "recon-tight"
        _, tight_doc = agentic_recon.run_recon(
            target=api_origin,
            output_dir=tight_dir,
            scope_file=scope_file,
            allow_non_loopback=True,
            max_requests=2,
            max_rps=0.0,
            execute=True,
        )
        assert tight_doc["requests_sent"] == 2


def test_b2_extra_headers_hardened_name_prefix_camelcase_and_value_stripping() -> None:
    sink: set[str] = set()
    sample_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.synthetic_sig"
    sample_aws_ak = "AKIA" + "0123456789ABCDEF"
    sample_aws_as = "ASIA" + "0123456789ABCDEF"
    sample_ghp = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    sample_stripe = "sk_" + "live_" + "1234567890abcdef"
    sample_slack = "xoxb-" + "12345678-90abcdef"
    sample_gapi = "AIza" + "SyDummyTestValue1234567890abcdef"
    sample_pem = "-----BEGIN " + "PRIVATE KEY-----"

    raw_headers = {
        # Benign BFF headers that must be preserved.
        "X-Storefront": "web",
        "X-Api-Version": "2",
        "Accept-Language": "en-US,en;q=0.9",
        "X-Shipping-Region": "eu-west",
        # Secret/auth/session header names (camelCase, hyphen, underscore).
        "X-Private-Key": "priv-val-1111",
        "Ocp-Apim-Subscription-Key": "sub-val-2222",
        "X-User-Session": "sess-val-3333",
        "X-Amz-Access-Key": "amz-val-4444",
        "X-CustomAuth": "custom-auth-5555",
        "X-HmacSig": "hmac-sig-6666",
        "X-UserCred": "cred-val-7777",
        "X-UserSid": "sid-val-8888",
        "X-OtpCode": "123456",
        "X-UserPin": "9988",
        # Reserved/proxy/cloud prefixes.
        "Sec-Fetch-Mode": "cors",
        "X-B3-TraceId": "deadbeef1234",
        ":authority": "shop.example.invalid",
        "CF-Connecting-IP": "198.51.100.1",
        "X-Amz-Date": "20261127T000000Z",
        "Proxy-Authenticate": "Basic",
        # Benign header names carrying secret/PII/cookie-like values.
        "X-Hdr-Bearer": "Bearer tok-val-9999",
        "X-Hdr-Basic": "Basic dXNlcjpwYXNz",
        "X-Hdr-Digest": 'Digest username="alice"',
        "X-Hdr-TokenScheme": "Token tok-scheme-1234",
        "X-Hdr-ApiKeyScheme": "ApiKey ak-scheme-1234",
        "X-Hdr-SigV4": "AWS4-HMAC-SHA256 Credential=abc/2026/us-east-1/s3/aws4_request",
        "X-Hdr-Jwt": sample_jwt,
        "X-Hdr-AwsAk": sample_aws_ak,
        "X-Hdr-AwsAs": sample_aws_as,
        "X-Hdr-Ghp": sample_ghp,
        "X-Hdr-Stripe": sample_stripe,
        "X-Hdr-Slack": sample_slack,
        "X-Hdr-Gapi": sample_gapi,
        "X-Hdr-Pem": sample_pem,
        "X-Hdr-Email": "alice@example.invalid",
        "X-Hdr-CookieLike": "sid=abc123; theme=dark",
    }

    cleaned = _sanitize_extra_headers(raw_headers, secret_sink=sink)
    assert cleaned == {
        "X-Storefront": "web",
        "X-Api-Version": "2",
        "Accept-Language": "en-US,en;q=0.9",
        "X-Shipping-Region": "eu-west",
    }
    assert _is_secret_or_reserved_extra_header(":authority", "shop.example.invalid") is True
    assert "priv-val-1111" in sink
    assert "sub-val-2222" in sink
    assert "custom-auth-5555" in sink
    assert "tok-val-9999" in sink


def test_b3_post_prematrix_blocks_mutating_and_camelcase_routes_allows_search(tmp_path: Path) -> None:
    blocked_paths = (
        "/api/orders/42/status",
        "/api/posts/99/report",
        "/api/users/export",
        "/api/orders/deleteOrder/status",
        "/api/coupons/apply/check",
        "/api/orders/cancelOrder",
        "/api/orders/applyCoupon",
        "/api/orders/deleteOrder/search",
        "/api/orders",
        "/api/saved-search",
    )
    for bad in blocked_paths:
        assert _is_safe_read_lookup_post(bad) is False, f"expected {bad} to be rejected"

    assert _is_safe_read_lookup_post("/api/orders/search") is True
    assert _is_safe_read_lookup_post("/api/v1/orders/lookup") is True

    def router(method: str, raw_path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        auth = headers.get("authorization", "")
        actor = "member-a" if auth == "Bearer tok-a" else ("member-b" if auth == "Bearer tok-b" else "anon")
        if path == "/api/orders/search" and method == "POST":
            if actor == "anon":
                return 401, "application/json", json.dumps({"error": "unauthorized"}), {}
            return 200, "application/json", json.dumps({
                "order_id": 42,
                "owner": "member-a",
                "email": "alice@example.invalid",
                "total": 99,
            }), {}
        return 200, "application/json", json.dumps({"mutated": True}), {}

    with _start_test_server(router) as (origin, requests_log):
        client = _make_client(
            tmp_path,
            base_url=f"{origin}/",
            accounts=[
                {"alias": "member-a", "role": "member", "access_token": "tok-a"},
                {"alias": "member-b", "role": "member", "access_token": "tok-b"},
            ],
            max_requests=40,
        )
        seed_surface = {
            "body_templates": {
                "POST /api/orders/42/status": {"status": "cancelled"},
                "POST /api/posts/99/report": {"reason": "spam"},
                "POST /api/users/export": {"format": "csv"},
                "POST /api/orders/deleteOrder/status": {"order_id": 42},
                "POST /api/coupons/apply/check": {"code": "SAVE50"},
                "POST /api/orders/search": {"order_id": 42},
            }
        }
        doc = run_deterministic_prescan(client, seed_surface=seed_surface, max_requests=20)

    probed_post_paths = {urlsplit(r["path"]).path for r in requests_log if r["method"] == "POST"}
    assert "/api/orders/search" in probed_post_paths
    for bad in (
        "/api/orders/42/status",
        "/api/posts/99/report",
        "/api/users/export",
        "/api/orders/deleteOrder/status",
        "/api/coupons/apply/check",
    ):
        assert bad not in probed_post_paths
    post_bola = [l for l in doc["leads"] if l["kind"] == "bola_candidate" and l.get("method") == "POST"]
    assert len(post_bola) == 1
    assert "/api/orders/search" in post_bola[0]["url"]


def test_s2_graphql_5level_oftype_enum_null_querytype_mutation_guard_and_200_auth_retry(tmp_path: Path) -> None:
    # 1. Verify GRAPHQL_FULL_INTROSPECTION_QUERY includes 5-level ofType nesting and enumValues.
    assert "enumValues { name }" in GRAPHQL_FULL_INTROSPECTION_QUERY
    assert GRAPHQL_FULL_INTROSPECTION_QUERY.count("ofType {") >= 15  # 5 levels x (args.type, fields.type, inputFields.type)

    # 2. Verify _is_graphql_introspection_200 rejects null queryType with errors.
    assert _is_graphql_introspection_200({
        "status": 200,
        "body": json.dumps({"data": {"__schema": {"queryType": None}}, "errors": [{"message": "auth required"}]}),
    }) is False
    assert _is_graphql_introspection_200({
        "status": 200,
        "body": json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}),
    }) is True

    # 3. Verify regex mutation guard allows read-only query field `mutationHistory` and blocks actual mutations.
    assert _is_graphql_mutation_query("query { mutationHistory { id } }") is False
    assert _is_graphql_mutation_payload({"query": "query { mutationHistory { id } }"}) is False
    assert _is_graphql_mutation_payload([
        {"query": "query { mutationHistory { id } }"},
        {"query": 'query { usersByRole(role: ADMIN) { id } }'},
    ]) is False
    assert _is_graphql_mutation_query('mutation { deleteUser(id: "1") }') is True
    assert _is_graphql_mutation_query('# comment\n  MUTATION DeleteIt { deleteUser(id: "1") }') is True
    assert _is_graphql_mutation_payload([
        {"query": "query { mutationHistory { id } }"},
        {"query": 'mutation { deleteUser(id: "1") }'},
    ]) is True

    # 4. Verify 5-level [User!]! type + ENUM arg schema parses cleanly, read-only `mutationHistory`
    # query is probed (not falsely blocked), and HTTP 200 anon errors retry as authenticated actor.
    nested_schema = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": None,
                "types": [
                    {"kind": "SCALAR", "name": "ID"},
                    {"kind": "SCALAR", "name": "String"},
                    {
                        "kind": "ENUM",
                        "name": "UserRole",
                        "enumValues": [{"name": "MEMBER"}, {"name": "ADMIN"}],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "User",
                        "fields": [
                            {"name": "id", "args": [], "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}},
                            {"name": "email", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "MutationAudit",
                        "fields": [
                            {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                            {"name": "action", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "fields": [
                            {
                                "name": "adminMutationHistory",
                                "args": [
                                    {
                                        "name": "role",
                                        "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "ENUM", "name": "UserRole", "ofType": None}},
                                    }
                                ],
                                # [MutationAudit!]! -> NON_NULL -> LIST -> NON_NULL -> OBJECT
                                "type": {
                                    "kind": "NON_NULL",
                                    "name": None,
                                    "ofType": {
                                        "kind": "LIST",
                                        "name": None,
                                        "ofType": {
                                            "kind": "NON_NULL",
                                            "name": None,
                                            "ofType": {"kind": "OBJECT", "name": "MutationAudit", "ofType": None},
                                        },
                                    },
                                },
                            },
                            {
                                "name": "usersById",
                                "args": [
                                    {"name": "id", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}},
                                ],
                                # [User!]!
                                "type": {
                                    "kind": "NON_NULL",
                                    "name": None,
                                    "ofType": {
                                        "kind": "LIST",
                                        "name": None,
                                        "ofType": {
                                            "kind": "NON_NULL",
                                            "name": None,
                                            "ofType": {"kind": "OBJECT", "name": "User", "ofType": None},
                                        },
                                    },
                                },
                            },
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Mutation",
                        "fields": [
                            {
                                "name": "deleteUser",
                                "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "ID", "ofType": None}}],
                                "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                            }
                        ],
                    },
                ],
            }
        }
    }
    parsed_nested = agentic_graphql.parse_introspection_schema(nested_schema)
    q_by_name = {q["name"]: q for q in parsed_nested["queries"]}
    assert q_by_name["usersById"]["return_type"] == "[User!]!"
    assert q_by_name["adminMutationHistory"]["return_type"] == "[MutationAudit!]!"
    enum_types = {t["name"]: t for t in parsed_nested["types"] if t["kind"] == "ENUM"}
    assert enum_types["UserRole"]["enum_values"] == ["MEMBER", "ADMIN"]
    generated_probes = agentic_graphql.build_safe_graphql_probes(parsed_nested, allowed_methods=("POST",), max_probes=3)
    admin_probe = next(p for p in generated_probes if p["operation"] == "adminMutationHistory")
    assert "role: MEMBER" in admin_probe["query"]

    def router(method: str, raw_path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if urlsplit(raw_path).path != "/graphql" or method != "POST":
            return 404, "application/json", json.dumps({"error": "not found"}), {}
        auth = headers.get("authorization", "")
        if auth != "Bearer tok-member":
            # GraphQL HTTP 200 with errors and null queryType for anon -> must trigger auth retry.
            return 200, "application/json", json.dumps({
                "data": {"__schema": {"queryType": None}},
                "errors": [{"message": "Authentication required"}],
            }), {}
        payload = json.loads(body.decode("utf-8"))

        def _eval(qtext: str) -> dict[str, Any]:
            if "__schema" in qtext:
                if "enumValues" in qtext:
                    return nested_schema
                return {"data": {"__schema": {"queryType": {"name": "Query"}}}}
            if "adminMutationHistory" in qtext:
                return {"data": {"adminMutationHistory": [{"id": "m-1", "action": "promote"}]}}
            if "usersById" in qtext:
                return {"data": {"usersById": [{"id": "1", "email": "alice@example.invalid"}]}}
            return {"errors": [{"message": "unknown"}]}

        if isinstance(payload, list):
            return 200, "application/json", json.dumps([_eval(str(item.get("query") or "")) for item in payload]), {}
        return 200, "application/json", json.dumps(_eval(str(payload.get("query") or ""))), {}

    with _start_test_server(router) as (origin, requests_log):
        client = _make_client(
            tmp_path,
            base_url=f"{origin}/",
            accounts=[{"alias": "member-a", "role": "member", "access_token": "tok-member"}],
            max_requests=40,
        )
        doc = run_deterministic_prescan(client, candidate_urls=["/graphql"], max_requests=20)

    gql_reqs = [r for r in requests_log if urlsplit(r["path"]).path == "/graphql" and r["method"] == "POST"]
    # First request anon (200 error), second retry as member-a, then full introspection + 3 safe probes.
    assert any(r["headers"].get("authorization", "") == "" for r in gql_reqs)
    assert any(r["headers"].get("authorization") == "Bearer tok-member" for r in gql_reqs)
    assert any("adminMutationHistory" in r["body"].decode("utf-8", errors="replace") for r in gql_reqs)
    assert all("deleteUser" not in r["body"].decode("utf-8", errors="replace") for r in gql_reqs)

    by_kind = {lead["kind"]: lead for lead in doc["leads"]}
    assert "graphql_introspection" in by_kind
    assert by_kind["graphql_introspection"]["actor"] == "member-a"
    assert "graphql_admin_query_exposed" in by_kind
    assert by_kind["graphql_admin_query_exposed"]["operation"] == "adminMutationHistory"


def test_s3_recon_graphql_strict_validation_swagger_skip_and_admin_role_preserved(tmp_path: Path) -> None:
    # Unit checks for strict GraphQL probe classification.
    assert agentic_recon._classify_graphql_probe_response('{"data":{"ok":true}}', "application/json", status=200) == (False, False)
    assert agentic_recon._classify_graphql_probe_response('{"data":{"items":[]}}', "application/json", status=200) == (False, False)
    assert agentic_recon._classify_graphql_probe_response('{"errors":[{"message":"Not found"}]}', "application/json", status=200) == (False, False)
    assert agentic_recon._classify_graphql_probe_response(
        '{"errors":[{"message":"Must provide query string."}]}',
        "application/json",
        status=400,
    ) == (True, True)
    assert agentic_recon._classify_graphql_probe_response(
        '{"errors":[{"message":"GET query missing","extensions":{"code":"GRAPHQL_BAD_REQUEST"}}]}',
        "application/json",
        status=405,
    ) == (True, True)

    def rest_fp_router(_m: str, raw_path: str, _h: dict[str, str], _b: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            return 200, "application/json", json.dumps({"service": "rest-only", "ok": True}), {}
        if path == "/graphql":
            # Plain REST JSON wrapper must NOT be classified as GraphQL.
            return 200, "application/json", json.dumps({"data": {"ok": True}}), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    def admin_gql_router(_m: str, raw_path: str, _h: dict[str, str], _b: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            return 200, "text/html", "<html><head><title>Admin Portal</title></head><body>Admin</body></html>", {}
        if path == "/openapi.json":
            return 200, "application/json", json.dumps({
                "openapi": "3.0.3",
                "info": {"title": "Admin API", "version": "1.0"},
                "paths": {"/admin/users": {"get": {}}},
            }), {}
        if path == "/graphql":
            # Spec-compliant HTTP 400 GraphQL response to GET /graphql without query.
            return 400, "application/json", json.dumps({
                "errors": [{"message": "Must provide query string."}],
            }), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with (
        _start_test_server(rest_fp_router) as (rest_origin, rest_log),
        _start_test_server(admin_gql_router) as (admin_origin, admin_log),
    ):
        scope_file = tmp_path / "scope-s3.json"
        scope_file.write_text(
            json.dumps({"in_scope": [admin_origin, rest_origin]}),
            encoding="utf-8",
        )
        seed_urls = tmp_path / "seed-s3.txt"
        seed_urls.write_text(
            f"{admin_origin}/admin\n{rest_origin}/openapi.json\n",
            encoding="utf-8",
        )
        out_dir = tmp_path / "recon-s3"
        graph_path, _live_doc = agentic_recon.run_recon(
            target=admin_origin,
            output_dir=out_dir,
            scope_file=scope_file,
            seed_files=(seed_urls,),
            allow_non_loopback=True,
            max_requests=25,
            max_rps=0.0,
            execute=True,
        )

    graph = agentic_recon.AssetGraph.from_dict(json.loads(graph_path.read_text(encoding="utf-8")))

    # REST host returning 200 {"data":{"ok":true}} at /graphql must NOT be classified as GraphQL,
    # and /openapi.json already present in sample_paths must not be re-probed.
    rest_paths = {urlsplit(r["path"]).path for r in rest_log}
    assert "/openapi.json" not in rest_paths
    rest_node = graph.get_node(rest_origin)
    assert rest_node is not None
    assert rest_node.role != "graphql"
    assert "graphql" not in rest_node.tech_signals
    assert "/graphql" not in rest_node.sample_paths

    # Admin host: /openapi.json hit -> /swagger.json skipped; 400 GraphQL recognized; role stays "admin"!
    admin_paths = {urlsplit(r["path"]).path for r in admin_log}
    assert "/openapi.json" in admin_paths
    assert "/graphql" in admin_paths
    assert "/swagger.json" not in admin_paths

    admin_node = graph.get_node(admin_origin)
    assert admin_node is not None
    assert admin_node.role == "admin"
    assert "/openapi.json" in admin_node.sample_paths
    assert "/graphql" in admin_node.sample_paths
    assert "openapi" in admin_node.tech_signals
    assert "graphql" in admin_node.tech_signals


def test_s4_operator_global_headers_take_precedence_over_har_extra_headers(tmp_path: Path) -> None:
    def router(_m: str, raw_path: str, headers: dict[str, str], _b: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/api/v1/profile":
            origin = headers.get("origin", "")
            extra = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} if origin else {}
            return 200, "application/json", json.dumps({"ok": True}), extra
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_test_server(router) as (origin, requests_log):
        client = _make_client(
            tmp_path,
            base_url=f"{origin}/",
            global_headers={"X-Storefront": "cli-override"},
            max_requests=30,
        )
        har_flows = {
            "schema": "har-flow/1",
            "recommended_app_headers": {
                "X-Storefront": "har-val",
                "X-Api-Version": "2",
            },
            "flows": [
                {
                    "flow_id": "flow_1",
                    "steps": [{"step_index": 1, "method": "GET", "url": "/api/v1/profile"}],
                }
            ],
        }
        run_deterministic_prescan(
            client,
            har_flows=har_flows,
            extra_headers={"x-storefront": "har-extra-val"},
            max_requests=10,
        )

    assert len(requests_log) >= 1
    for req in requests_log:
        assert req["headers"].get("x-storefront") == "cli-override"
        assert req["headers"].get("x-api-version") == "2"
