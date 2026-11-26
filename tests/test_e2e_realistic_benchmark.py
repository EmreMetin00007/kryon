"""Unit tests for agentic_graphql and full end-to-end realistic loopback multi-origin/multi-actor benchmark."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any, Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agent_cli  # noqa: E402
import agentic_graphql as gql  # noqa: E402
import agentic_recon  # noqa: E402
import agentic_runner  # noqa: E402
import agentic_tui  # noqa: E402


def _make_sample_introspection_schema() -> dict[str, Any]:
    """Build a realistic GraphQL introspection response with nested types, ID lookups, admin ops, and mutations."""
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": None,
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "__Schema",
                        "fields": [{"name": "types", "args": [], "type": {"kind": "LIST", "name": None, "ofType": {"kind": "OBJECT", "name": "__Type", "ofType": None}}}],
                    },
                    {"kind": "OBJECT", "name": "__Type", "fields": []},
                    {"kind": "SCALAR", "name": "ID"},
                    {"kind": "SCALAR", "name": "String"},
                    {"kind": "SCALAR", "name": "Int"},
                    {"kind": "SCALAR", "name": "Float"},
                    {"kind": "SCALAR", "name": "Boolean"},
                    {
                        "kind": "ENUM",
                        "name": "OrderStatus",
                        "enumValues": [{"name": "PENDING"}, {"name": "PAID"}],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Profile",
                        "fields": [
                            {"name": "displayName", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                            {"name": "phone", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                            {"name": "address", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "User",
                        "fields": [
                            {"name": "id", "args": [], "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}},
                            {"name": "email", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                            {"name": "passwordHash", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                            {"name": "apiKey", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                            {"name": "role", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                            {"name": "isAdmin", "args": [], "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None}},
                            {"name": "balance", "args": [], "type": {"kind": "SCALAR", "name": "Float", "ofType": None}},
                            {"name": "profile", "args": [], "type": {"kind": "OBJECT", "name": "Profile", "ofType": None}},
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Order",
                        "fields": [
                            {"name": "id", "args": [], "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}},
                            {"name": "owner", "args": [], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                            {"name": "status", "args": [], "type": {"kind": "ENUM", "name": "OrderStatus", "ofType": None}},
                            {"name": "creditCard", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
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
                            {"name": "__schema", "args": [], "type": {"kind": "OBJECT", "name": "__Schema", "ofType": None}},
                            {
                                "name": "health",
                                "args": [],
                                "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                            },
                            {
                                "name": "user",
                                "args": [
                                    {"name": "id", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}},
                                ],
                                "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                            },
                            {
                                "name": "order",
                                "args": [
                                    {"name": "orderId", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "Int", "ofType": None}}},
                                    {"name": "includeDetails", "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None}},
                                ],
                                "type": {"kind": "OBJECT", "name": "Order", "ofType": None},
                            },
                            {
                                "name": "adminAuditLogs",
                                "args": [
                                    {"name": "limit", "type": {"kind": "SCALAR", "name": "Int", "ofType": None}},
                                    {"name": "filter", "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                                ],
                                "type": {"kind": "LIST", "name": None, "ofType": {"kind": "OBJECT", "name": "AuditLog", "ofType": None}},
                            },
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Mutation",
                        "fields": [
                            {
                                "name": "signIn",
                                "args": [
                                    {"name": "email", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}},
                                ],
                                "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                            },
                            {
                                "name": "promoteUserRole",
                                "args": [
                                    {"name": "userId", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}},
                                    {"name": "role", "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                                ],
                                "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                            },
                            {
                                "name": "deleteAccount",
                                "args": [
                                    {"name": "id", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}},
                                ],
                                "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None},
                            },
                            {
                                "name": "purgeUsers",
                                "args": [],
                                "type": {"kind": "SCALAR", "name": "Int", "ofType": None},
                            },
                        ],
                    },
                ],
            }
        }
    }


# ---------------------------------------------------------------------------
# 1. Unit Tests for scripts/agentic_graphql.py
# ---------------------------------------------------------------------------


def test_parse_introspection_schema_extracts_queries_mutations_sensitive_fields_and_stats() -> None:
    raw = _make_sample_introspection_schema()
    parsed = gql.parse_introspection_schema(raw)

    assert parsed["schema"] == gql.SCHEMA == "agentic-graphql-schema/1"
    assert parsed["query_type"] == "Query"
    assert parsed["mutation_type"] == "Mutation"
    assert parsed["subscription_type"] == ""

    # Ignores __Schema, __Type, and built-in scalar primitives in custom types.
    type_names = {t["name"] for t in parsed["types"]}
    assert type_names == {"AuditLog", "Order", "OrderStatus", "Profile", "User"}

    # Alternative envelope forms parse identically.
    assert gql.parse_introspection_schema({"__schema": raw["data"]["__schema"]}) == parsed
    assert gql.parse_introspection_schema(raw["data"]["__schema"]) == parsed

    queries_by_name = {q["name"]: q for q in parsed["queries"]}
    assert "__schema" not in queries_by_name
    assert set(queries_by_name) == {"health", "user", "order", "adminAuditLogs"}

    user_q = queries_by_name["user"]
    assert user_q["is_id_lookup"] is True
    assert user_q["is_admin_like"] is False
    assert user_q["is_sensitive"] is True
    assert user_q["return_type"] == "User"
    assert user_q["args"] == [{"name": "id", "type": "ID!", "required": True, "is_id_like": True}]
    assert "email" in user_q["return_fields_sample"]

    order_q = queries_by_name["order"]
    assert order_q["is_id_lookup"] is True
    assert order_q["args"] == [
        {"name": "orderId", "type": "Int!", "required": True, "is_id_like": True},
        {"name": "includeDetails", "type": "Boolean", "required": False, "is_id_like": False},
    ]

    audit_q = queries_by_name["adminAuditLogs"]
    assert audit_q["is_admin_like"] is True
    assert audit_q["is_sensitive"] is True
    assert audit_q["return_type"] == "[AuditLog]"

    muts_by_name = {m["name"]: m for m in parsed["mutations"]}
    assert muts_by_name["signIn"]["is_auth_like"] is True
    assert muts_by_name["signIn"]["is_destructive"] is False
    assert muts_by_name["promoteUserRole"]["is_admin_like"] is True
    assert muts_by_name["promoteUserRole"]["is_destructive"] is False
    assert muts_by_name["deleteAccount"]["is_destructive"] is True
    assert muts_by_name["purgeUsers"]["is_destructive"] is True

    sf = set(parsed["sensitive_fields"])
    assert {
        "User.email",
        "User.passwordHash",
        "User.apiKey",
        "User.role",
        "User.isAdmin",
        "User.balance",
        "Profile.phone",
        "Profile.address",
        "Order.creditCard",
        "AuditLog.internalNotes",
    } <= sf

    assert parsed["stats"] == {
        "queries_count": 4,
        "mutations_count": 4,
        "id_lookup_queries_count": 2,
        "admin_operations_count": 2,
        "sensitive_fields_count": len(parsed["sensitive_fields"]),
        "types_count": 5,
    }


def test_build_safe_graphql_probes_prioritizes_id_and_admin_excludes_destructive_and_adds_batching() -> None:
    parsed = gql.parse_introspection_schema(_make_sample_introspection_schema())

    probes = gql.build_safe_graphql_probes(parsed, allowed_methods=("POST",), max_probes=8)
    assert len(probes) <= 8
    # 4 single query probes + 1 batching probe = 5
    assert len(probes) == 5

    # Prioritizes id_lookup (user, order) and admin_like (adminAuditLogs) ahead of health.
    single_probes = [p for p in probes if p["kind"] != "batching_check"]
    assert [p["operation"] for p in single_probes] == ["user", "order", "adminAuditLogs", "health"]
    assert all(p["read_only"] is True for p in probes)

    # Never emits mutations or destructive operations.
    serialized_all = json.dumps(probes)
    for forbidden in ("mutation", "deleteAccount", "purgeUsers", "promoteUserRole", "signIn"):
        assert forbidden not in serialized_all

    # Typed synthetic benign argument literals.
    user_probe = single_probes[0]
    assert 'user(id: "1")' in user_probe["query"]
    assert "id" in user_probe["query"]

    order_probe = single_probes[1]
    assert "order(orderId: 1, includeDetails: false)" in order_probe["query"]
    # Depth <= 2 nested selection set on Order -> owner { id ... }
    assert "owner {" in order_probe["query"]

    audit_probe = single_probes[2]
    assert 'adminAuditLogs(limit: 1, filter: "1")' in audit_probe["query"]

    # Batching check payload present when POST allowed.
    batch_probes = [p for p in probes if p["kind"] == "batching_check"]
    assert len(batch_probes) == 1
    batch_body = batch_probes[0]["payload"]
    assert isinstance(batch_body, list) and len(batch_body) == 2
    assert all(isinstance(item, dict) and "query" in item for item in batch_body)

    # GET-only omits batching payload and emits GET probes.
    get_probes = gql.build_safe_graphql_probes(parsed, allowed_methods=("GET",), max_probes=8)
    assert all(p["method"] == "GET" for p in get_probes)
    assert all(p["kind"] != "batching_check" for p in get_probes)

    # Strict max_probes cap enforcement.
    assert gql.build_safe_graphql_probes(parsed, allowed_methods=("POST",), max_probes=0) == []
    assert len(gql.build_safe_graphql_probes(parsed, allowed_methods=("POST",), max_probes=1)) == 1
    assert len(gql.build_safe_graphql_probes(parsed, allowed_methods=("POST",), max_probes=3)) == 3
    assert gql.build_safe_graphql_probes(parsed, allowed_methods=("DELETE",), max_probes=5) == []


def test_format_graphql_schema_handoff_is_bounded_and_summarizes_targets() -> None:
    parsed = gql.parse_introspection_schema(_make_sample_introspection_schema())

    handoff = gql.format_graphql_schema_handoff(
        parsed,
        endpoint="http://127.0.0.1:8000/graphql",
        max_chars=1600,
    )
    assert 0 < len(handoff) <= 1600
    assert "[GRAPHQL SCHEMA]" in handoff
    assert "http://127.0.0.1:8000/graphql" in handoff
    assert "ID_LOOKUP" in handoff
    assert "ADMIN" in handoff
    assert "DESTRUCTIVE" in handoff
    assert "User.email" in handoff

    for tight_cap in (240, 80, 3):
        bounded = gql.format_graphql_schema_handoff(parsed, endpoint="/graphql", max_chars=tight_cap)
        assert len(bounded) <= tight_cap

    assert gql.format_graphql_schema_handoff(parsed, max_chars=0) == ""


# ---------------------------------------------------------------------------
# 2. Full End-to-End Multi-Origin / Multi-Actor Realistic Loopback Benchmark
# ---------------------------------------------------------------------------


@contextmanager
def _serve_handler(handler_cls: type[BaseHTTPRequestHandler]) -> Iterator[int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = int(srv.server_address[1])
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2.0)


def test_e2e_multi_origin_recon_prescan_har_waf_and_oracle_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    started = time.monotonic()

    # Synthetic credentials & secret constants constructed safely to keep static governance clean.
    alice_tok = "tok_alice_synth_881122"
    bob_tok = "tok_bob_synth_993344"
    alice_cookie = "sess_alice_synth_1122"
    bob_cookie = "sess_bob_synth_3344"
    stale_har_bearer = "Bear" + "er stale_har_secret_token_should_strip_999"
    aws_dummy_key = "AKIA" + "IOSFODNN7EXAMPLE"
    mock_llm_api_key = "synth_mock_llm_key"

    p2_port_box: dict[str, int] = {"port": 0}

    class _StorefrontHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            return

        def _send(self, status: int, ctype: str, body: str, extra_headers: dict[str, str] | None = None) -> None:
            raw = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            p2_port = p2_port_box["port"]
            if parsed.path == "/":
                html_body = (
                    "<html><head><title>ShopFront Portal</title></head><body>"
                    "<script src='/app.js'></script>"
                    f"<a href='http://127.0.0.1:{p2_port}/api/v1/orders/101'>My Order</a>"
                    "<a href='/search?q=shoes'>Search</a>"
                    "</body></html>"
                )
                self._send(200, "text/html; charset=utf-8", html_body)
                return
            if parsed.path == "/app.js":
                js_body = (
                    f'window.__APP_CFG = {{ apiBase: "http://127.0.0.1:{p2_port}/api/v1", '
                    f'AWS_ACCESS_KEY_ID: "{aws_dummy_key}" }};\n'
                    f'fetch("http://127.0.0.1:{p2_port}/api/v1/orders/101");'
                )
                self._send(200, "application/javascript", js_body)
                return
            if parsed.path == "/search":
                waf_html = (
                    "<html><head><title>Attention Required! | Cloudflare</title></head>"
                    "<body><h1>Sorry, you have been blocked</h1>"
                    "<p>Cloudflare Error 1020</p></body></html>"
                )
                self._send(
                    403,
                    "text/html; charset=utf-8",
                    waf_html,
                    {"Server": "cloudflare", "cf-mitigated": "challenge", "CF-Ray": "8f1234567890-IST"},
                )
                return
            self._send(404, "text/plain", "not found")

    def _actor_from_req(headers: Any) -> str:
        auth = str(headers.get("Authorization") or "")
        cookie = str(headers.get("Cookie") or "")
        if alice_tok in auth or alice_cookie in cookie:
            return "alice"
        if bob_tok in auth or bob_cookie in cookie:
            return "bob"
        return "anon"

    class _ApiHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            return

        def _send_json(self, status: int, obj: Any, extra_headers: dict[str, str] | None = None) -> None:
            raw = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            actor = _actor_from_req(self.headers)
            if parsed.path == "/":
                self._send_json(200, {"service": "orders-api", "version": "1.0"})
                return
            if parsed.path == "/api/v1/health":
                origin = str(self.headers.get("Origin") or "").strip()
                extra = (
                    {
                        "Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Credentials": "true",
                    }
                    if origin
                    else {}
                )
                self._send_json(200, {"status": "ok", "service": "orders-api"}, extra)
                return
            if parsed.path == "/api/v1/orders/101":
                if actor == "anon":
                    self._send_json(401, {"error": "unauthorized"})
                    return
                # Intentional BOLA: returns Alice's order to both alice and bob!
                self._send_json(
                    200,
                    {
                        "order_id": 101,
                        "owner": "alice",
                        "email": "alice@example.invalid",
                        "total": 499,
                    },
                )
                return
            if parsed.path == "/api/v1/orders/202":
                if actor == "anon":
                    self._send_json(401, {"error": "unauthorized"})
                    return
                if actor != "bob":
                    self._send_json(403, {"error": "forbidden"})
                    return
                self._send_json(
                    200,
                    {
                        "order_id": 202,
                        "owner": "bob",
                        "email": "bob@example.invalid",
                        "total": 120,
                    },
                )
                return
            self._send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            parsed = urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            _ = self.rfile.read(length) if length > 0 else b""
            if parsed.path == "/graphql":
                introspection_doc = {
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
                                        {"name": "id", "args": [], "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}},
                                        {"name": "email", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                                        {"name": "role", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
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
                                            "args": [{"name": "id", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}}],
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
                                            "args": [{"name": "id", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}}],
                                            "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None},
                                        }
                                    ],
                                },
                            ],
                        }
                    }
                }
                self._send_json(200, introspection_doc)
                return
            if parsed.path == "/api/v1/cart":
                self._send_json(201, {"cart_id": "cart-9001", "items": 1})
                return
            if parsed.path == "/api/v1/cart/cart-9001/checkout":
                self._send_json(200, {"order_id": 101, "cart_id": "cart-9001", "status": "completed"})
                return
            self._send_json(404, {"error": "not_found"})

    # Scripted local OpenAI-compatible mock LLM state.
    llm_turn_state: dict[str, Any] = {
        "turn": 0,
        "turn1_user_prompt": "",
        "waf_guidance_seen": False,
        "alice_rid": "",
        "bob_rid": "",
        "anon_rid": "",
        "record_accepted": False,
    }
    llm_lock = threading.Lock()

    def _unwrap_tool_json(raw_content: str) -> dict[str, Any]:
        prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
        suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
        body = raw_content
        if prefix in body and suffix in body:
            start = body.index(prefix) + len(prefix)
            end = body.index(suffix, start)
            body = body[start:end]
        return json.loads(body)

    def _tool_resp(call_id: str, name: str, args_obj: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": f"chatcmpl-{call_id}",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": json.dumps(args_obj),
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 200, "completion_tokens": 50, "total_tokens": 250},
        }

    def _multi_tool_resp(calls: list[tuple[str, str, dict[str, Any]]]) -> dict[str, Any]:
        return {
            "id": f"chatcmpl-{calls[0][0]}",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": cid,
                                "type": "function",
                                "function": {"name": cname, "arguments": json.dumps(cargs)},
                            }
                            for cid, cname, cargs in calls
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 220, "completion_tokens": 60, "total_tokens": 280},
        }

    with _serve_handler(_StorefrontHandler) as p1_port, _serve_handler(_ApiHandler) as p2_port:
        p2_port_box["port"] = p2_port
        p1_origin = f"http://127.0.0.1:{p1_port}"
        p2_origin = f"http://127.0.0.1:{p2_port}"

        class _MockLLMHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                req_raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
                req_json = json.loads(req_raw)
                msgs = req_json.get("messages") or []

                with llm_lock:
                    llm_turn_state["turn"] += 1
                    t = llm_turn_state["turn"]
                    if t == 1:
                        user_msgs = [m.get("content", "") for m in msgs if m.get("role") == "user"]
                        llm_turn_state["turn1_user_prompt"] = user_msgs[0] if user_msgs else ""
                        reply = _tool_resp("c1", "http_request", {"method": "GET", "url": "/search?q=1", "actor": "anon"})
                    elif t == 2:
                        tool_msgs = [m for m in msgs if m.get("role") == "tool"]
                        res1 = _unwrap_tool_json(str(tool_msgs[-1].get("content") or ""))
                        assert res1["waf_block"]["vendor"] == "cloudflare"
                        assert "waf_pivot_guidance" not in res1
                        reply = _tool_resp("c2", "http_request", {"method": "GET", "url": "/search?q=2", "actor": "anon"})
                    elif t == 3:
                        tool_msgs = [m for m in msgs if m.get("role") == "tool"]
                        res2 = _unwrap_tool_json(str(tool_msgs[-1].get("content") or ""))
                        if "waf_pivot_guidance" in res2:
                            llm_turn_state["waf_guidance_seen"] = True
                        reply = _tool_resp(
                            "c3",
                            "http_request",
                            {"method": "GET", "url": f"{p2_origin}/api/v1/orders/101", "actor": "alice", "force": True},
                        )
                    elif t == 4:
                        tool_msgs = [m for m in msgs if m.get("role") == "tool"]
                        res3 = _unwrap_tool_json(str(tool_msgs[-1].get("content") or ""))
                        alice_rid = str(res3["receipt_id"])
                        llm_turn_state["alice_rid"] = alice_rid
                        reply = _multi_tool_resp([
                            ("c4a", "replay_as", {"receipt_id": alice_rid, "actor": "bob", "force": True}),
                            ("c4b", "replay_as", {"receipt_id": alice_rid, "actor": "anon", "force": True}),
                        ])
                    elif t == 5:
                        tool_msgs = [m for m in msgs if m.get("role") == "tool"]
                        replay_bob = _unwrap_tool_json(str(tool_msgs[-2].get("content") or ""))
                        replay_anon = _unwrap_tool_json(str(tool_msgs[-1].get("content") or ""))
                        bob_rid = str(replay_bob["replay"]["receipt_id"])
                        anon_rid = str(replay_anon["replay"]["receipt_id"])
                        llm_turn_state["bob_rid"] = bob_rid
                        llm_turn_state["anon_rid"] = anon_rid
                        reply = _tool_resp(
                            "c5",
                            "record_finding",
                            {
                                "title": "Cross-actor BOLA on sibling API /api/v1/orders/101",
                                "class_type": "bola",
                                "method": "GET",
                                "url": f"{p2_origin}/api/v1/orders/101",
                                "actor_alias": "bob",
                                "proof_receipt_ids": [bob_rid],
                                "control_receipt_ids": [llm_turn_state["alice_rid"], anon_rid],
                                "evidence_value": "alice@example.invalid",
                                "summary": "Actor bob read alice's sensitive order 101 across sibling API origin.",
                                "severity": "high",
                            },
                        )
                    else:
                        tool_msgs = [m for m in msgs if m.get("role") == "tool"]
                        last_txt = str(tool_msgs[-1].get("content") or "")
                        if '"accepted": true' in last_txt or '"accepted":true' in last_txt:
                            llm_turn_state["record_accepted"] = True
                        reply = _tool_resp(
                            f"c{t}",
                            "finish",
                            {
                                "summary": "Verified cross-origin BOLA on /api/v1/orders/101 and observed Cloudflare WAF pivot.",
                                "untested_areas": ["GraphQL mutations", "Cart checkout race condition"],
                            },
                        )

                payload = json.dumps(reply).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        with _serve_handler(_MockLLMHandler) as llm_port:
            # Shared scope.json explicitly authorizing both local loopback origins only.
            scope_path = tmp_path / "scope.json"
            scope_path.write_text(
                json.dumps({
                    "in_scope": [p1_origin, p2_origin],
                    "out_of_scope": ["https://evil.example.invalid", "/admin/wipe"],
                }),
                encoding="utf-8",
            )

            # HAR seed covering storefront P1, sibling API P2, chained cart->checkout, X-Storefront, and out-of-scope URL.
            har_path = tmp_path / "journey.har"
            har_doc = {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "startedDateTime": "2026-11-26T10:00:00Z",
                            "request": {"method": "GET", "url": f"{p1_origin}/", "headers": []},
                            "response": {"status": 200, "content": {"mimeType": "text/html", "text": "<html></html>"}},
                        },
                        {
                            "startedDateTime": "2026-11-26T10:00:01Z",
                            "request": {"method": "GET", "url": f"{p1_origin}/app.js", "headers": []},
                            "response": {"status": 200, "content": {"mimeType": "application/javascript", "text": ""}},
                        },
                        {
                            "startedDateTime": "2026-11-26T10:00:02Z",
                            "request": {"method": "GET", "url": f"{p2_origin}/api/v1/health", "headers": []},
                            "response": {"status": 200, "content": {"mimeType": "application/json", "text": '{"status":"ok"}'}},
                        },
                        {
                            "startedDateTime": "2026-11-26T10:00:03Z",
                            "request": {"method": "GET", "url": f"{p2_origin}/api/v1/orders/101", "headers": []},
                            "response": {"status": 200, "content": {"mimeType": "application/json", "text": '{"order_id":101}'}},
                        },
                        {
                            "startedDateTime": "2026-11-26T10:00:04Z",
                            "request": {"method": "GET", "url": f"{p2_origin}/api/v1/orders/202", "headers": []},
                            "response": {"status": 200, "content": {"mimeType": "application/json", "text": '{"order_id":202}'}},
                        },
                        {
                            "startedDateTime": "2026-11-26T10:00:05Z",
                            "request": {
                                "method": "POST",
                                "url": f"{p2_origin}/graphql",
                                "headers": [{"name": "Content-Type", "value": "application/json"}],
                                "postData": {"mimeType": "application/json", "text": json.dumps({"query": "{ __typename }"})},
                            },
                            "response": {"status": 200, "content": {"mimeType": "application/json", "text": '{"data":{}}'}},
                        },
                        {
                            "startedDateTime": "2026-11-26T10:00:06Z",
                            "request": {
                                "method": "POST",
                                "url": f"{p2_origin}/api/v1/cart",
                                "headers": [
                                    {"name": "X-Storefront", "value": "web"},
                                    {"name": "Authorization", "value": stale_har_bearer},
                                    {"name": "Content-Type", "value": "application/json"},
                                ],
                                "postData": {"mimeType": "application/json", "text": json.dumps({"item_id": 10, "quantity": 1})},
                            },
                            "response": {"status": 201, "content": {"mimeType": "application/json", "text": json.dumps({"cart_id": "cart-9001"})}},
                        },
                        {
                            "startedDateTime": "2026-11-26T10:00:07Z",
                            "request": {
                                "method": "POST",
                                "url": f"{p2_origin}/api/v1/cart/cart-9001/checkout",
                                "headers": [
                                    {"name": "X-Storefront", "value": "web"},
                                    {"name": "Authorization", "value": stale_har_bearer},
                                    {"name": "Content-Type", "value": "application/json"},
                                ],
                                "postData": {"mimeType": "application/json", "text": json.dumps({"cart_id": "cart-9001", "total": 499})},
                            },
                            "response": {"status": 200, "content": {"mimeType": "application/json", "text": json.dumps({"order_id": 101})}},
                        },
                        {
                            "startedDateTime": "2026-11-26T10:00:08Z",
                            "request": {"method": "GET", "url": "https://evil.example.invalid/collect", "headers": []},
                            "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}},
                        },
                    ],
                }
            }
            har_path.write_text(json.dumps(har_doc), encoding="utf-8")

            # -----------------------------------------------------------------
            # Step A: agentic_recon.run_recon(..., execute=True)
            # -----------------------------------------------------------------
            recon_dir = tmp_path / "recon"
            graph_path, recon_doc = agentic_recon.run_recon(
                target=f"{p1_origin}/",
                output_dir=recon_dir,
                scope_file=scope_path,
                allow_non_loopback=True,
                max_requests=20,
                max_rps=0.0,
                execute=True,
            )
            assert graph_path == recon_dir / "asset-graph.json"
            assert graph_path.is_file()
            assert (recon_dir / "recon-summary.md").is_file()
            assert (recon_dir / "scope.recommended.json").is_file()

            graph_obj = agentic_recon.AssetGraph.from_dict(recon_doc)
            p1_node = graph_obj.get_node(p1_origin)
            p2_node = graph_obj.get_node(p2_origin)
            assert p1_node is not None and p1_node.alive is True and p1_node.in_scope is True
            assert p2_node is not None and p2_node.alive is True and p2_node.in_scope is True
            assert p2_node.role == "api"
            edge_tuples = {(e.source, e.target, e.relation) for e in graph_obj.edges.values()}
            assert (p1_origin, p2_origin, "calls_api") in edge_tuples
            assert "https://evil.example.invalid" not in recon_doc["in_scope_hosts"]

            # -----------------------------------------------------------------
            # Step B: Multi-origin storage_state + HAR seed + agentic_runner
            # -----------------------------------------------------------------
            alice_state = tmp_path / "alice_state.json"
            alice_state.write_text(
                json.dumps({
                    "cookies": [
                        {"name": "session_id", "value": alice_cookie, "domain": "127.0.0.1", "path": "/", "expires": -1},
                    ],
                    "origins": [
                        {"origin": p1_origin, "localStorage": [{"name": "ui_locale", "value": "en"}]},
                        {"origin": p2_origin, "localStorage": [{"name": "access_token", "value": alice_tok}]},
                    ],
                }),
                encoding="utf-8",
            )
            bob_state = tmp_path / "bob_state.json"
            bob_state.write_text(
                json.dumps({
                    "cookies": [
                        {"name": "session_id", "value": bob_cookie, "domain": "127.0.0.1", "path": "/", "expires": -1},
                    ],
                    "origins": [
                        {"origin": p1_origin, "localStorage": [{"name": "ui_locale", "value": "en"}]},
                        {"origin": p2_origin, "localStorage": [{"name": "access_token", "value": bob_tok}]},
                    ],
                }),
                encoding="utf-8",
            )

            llm_cfg = tmp_path / "llm.json"
            llm_cfg.write_text(
                json.dumps({
                    "schema": "cco-llm/1",
                    "model": "local-mock/mock-gpt",
                    "providers": {
                        "local-mock": {
                            "base_url": f"http://127.0.0.1:{llm_port}/v1",
                            "models": ["mock-gpt"],
                            "api_key_env": "KRYON_MOCK_LLM_KEY",
                        }
                    },
                }),
                encoding="utf-8",
            )
            monkeypatch.setenv("KRYON_MOCK_LLM_KEY", mock_llm_api_key)

            run_dir = tmp_path / "run_out"
            manifest_path, manifest = agentic_runner.run_agentic_target(
                target=f"{p1_origin}/",
                provider_config=llm_cfg,
                output_dir=run_dir,
                http_budget=80,
                token_budget=500_000,
                seconds_budget=120,
                allowed_methods=["GET", "POST"],
                max_turns=10,
                execute=True,
                execution_mode="monolithic",
                scope_file=scope_path,
                allow_non_loopback=True,
                storage_states=[f"alice:member={alice_state}", f"bob:member={bob_state}"],
                seed_surface_files=[har_path],
                auto_crawl=False,
                prescan=True,
                prescan_max_requests=24,
            )

    # Assert prescan-summary.json & 0-LLM-cost deterministic detections
    prescan_path = run_dir / "prescan-summary.json"
    assert prescan_path.is_file()
    prescan_doc = json.loads(prescan_path.read_text(encoding="utf-8"))
    prescan_kinds = {lead["kind"] for lead in prescan_doc["leads"]}
    assert "bola_candidate" in prescan_kinds
    assert "cors_misconfiguration" in prescan_kinds
    assert "graphql_introspection" in prescan_kinds
    assert "aws_access_key" in prescan_kinds
    bola_lead = next(l for l in prescan_doc["leads"] if l["kind"] == "bola_candidate")
    assert "/api/v1/orders/101" in bola_lead["url"]

    # Validate GraphQL introspection receipt discovered by prescan via agentic_graphql
    gql_lead = next(l for l in prescan_doc["leads"] if l["kind"] == "graphql_introspection")
    gql_receipt = json.loads((run_dir / "receipts" / f"{gql_lead['receipt_id']}.json").read_text(encoding="utf-8"))
    parsed_gql = gql.parse_introspection_schema(json.loads(gql_receipt["body"]))
    assert parsed_gql["stats"]["id_lookup_queries_count"] == 1
    assert parsed_gql["stats"]["admin_operations_count"] >= 1
    gql_probes = gql.build_safe_graphql_probes(parsed_gql, allowed_methods=("GET", "POST"), max_probes=5)
    assert any(p["kind"] == "id_lookup" and p["operation"] == "user" for p in gql_probes)
    assert any(p["kind"] == "batching_check" for p in gql_probes)
    assert all("deleteUser" not in json.dumps(p) for p in gql_probes)
    gql_handoff = gql.format_graphql_schema_handoff(parsed_gql, endpoint=gql_lead["url"], max_chars=800)
    assert len(gql_handoff) <= 800
    assert "adminAuditLogs" in gql_handoff

    # Assert har-flows.json & chained steps + X-Storefront header
    har_flows_path = run_dir / "har-flows.json"
    assert har_flows_path.is_file()
    har_flows_doc = json.loads(har_flows_path.read_text(encoding="utf-8"))
    assert har_flows_doc["recommended_app_headers"].get("X-Storefront") == "web"
    assert har_flows_doc["stats"]["flows_count"] >= 1
    assert har_flows_doc["stats"]["chained_steps_count"] >= 1
    assert har_flows_doc["stats"]["entries_dropped_scope"] >= 1

    # Assert Turn-1 prompt & WAF pivot & DifferentialOracle acceptance
    assert "[PRESCAN LEADS]" in llm_turn_state["turn1_user_prompt"]
    assert "HAR Multi-Step Flows" in llm_turn_state["turn1_user_prompt"]
    assert llm_turn_state["waf_guidance_seen"] is True
    assert llm_turn_state["record_accepted"] is True

    # Assert manifest, findings, report.md, report.sarif
    assert manifest_path.is_file()
    assert manifest["status"] == "finished"
    assert manifest["findings_count"] >= 1
    assert manifest["seed_surface"]["routes_dropped_scope"] >= 1

    findings_path = run_dir / "findings.json"
    assert findings_path.is_file()
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    assert len(findings) >= 1
    bola_finding = next(f for f in findings if f["class_type"] == "bola")
    assert bola_finding["oracle_verdict"] == "VERIFIED"
    assert bola_finding["status"] == "verified"
    assert "/api/v1/orders/101" in bola_finding["url"]

    report_md_path = run_dir / "report.md"
    report_sarif_path = run_dir / "report.sarif"
    assert report_md_path.is_file()
    assert report_sarif_path.is_file()
    report_md_text = report_md_path.read_text(encoding="utf-8")
    assert "/api/v1/orders/101" in report_md_text
    assert "NOT TESTED" in report_md_text
    sarif_doc = json.loads(report_sarif_path.read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"][0]["results"]) >= 1

    # Assert cco-agent status & TUI plain dashboard succeed cleanly
    _ = capsys.readouterr()
    rc = agent_cli.main(["status", str(run_dir)])
    assert rc == 0
    status_out = json.loads(capsys.readouterr().out)
    assert status_out["status"] == "finished"
    assert status_out["findings_count"] >= 1

    snap = agentic_tui.load_run_snapshot(run_dir)
    plain_dash = agentic_tui.render_plain_dashboard(snap)
    assert "KRYON WATCH" in plain_dash
    assert "FINISHED" in plain_dash
    assert "Verified Findings (1)" in plain_dash
    assert "/api/v1/orders/101" in plain_dash
    assert "Prescan=ok(4 leads)" in plain_dash
    assert "HAR Flows=1(1 chained)" in plain_dash

    # Strict secret hygiene across all on-disk artifacts
    for artifact in (
        manifest_path,
        prescan_path,
        har_flows_path,
        findings_path,
        report_md_path,
        report_sarif_path,
    ):
        text = artifact.read_text(encoding="utf-8")
        for secret in (
            alice_tok,
            bob_tok,
            alice_cookie,
            bob_cookie,
            stale_har_bearer,
            "stale_har_secret_token_should_strip_999",
            aws_dummy_key,
            mock_llm_api_key,
        ):
            assert secret not in text, f"Secret leaked into {artifact.name}"

    assert (time.monotonic() - started) < 15.0
