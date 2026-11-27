"""Focused regression tests for Wave 1 verification, evidence, and reporting fixes."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shlex
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit, urlunsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_evidence import (  # noqa: E402
    _extract_record_owner_and_tenant,
    _find_exact_route_anon_2xx,
    _is_genuine_anon_2xx,
    _resolve_route_auth_bypass_vs_bfla,
    canonicalize_and_deduplicate_findings,
    extract_graphql_operation_key,
    extract_origin,
)
from agentic_http import ActorManager, AgenticHTTPClient, ScopeViolationError  # noqa: E402
from agentic_oracle import (  # noqa: E402
    DifferentialOracle,
    _extract_owner_and_tenant_from_receipt,
    _has_redacted_credential_body,
    _is_graphql_error_envelope,
    _is_one_shot_create_conflict,
    check_bola_false_positive,
    is_persistent_read_path_related,
)
from agentic_receipts import ReceiptStore  # noqa: E402
import agentic_report  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402


def _start_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[str, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{srv.server_port}", srv


def _stop_server(srv: ThreadingHTTPServer) -> None:
    srv.shutdown()
    srv.server_close()


def _make_env(
    tmp_path: Path,
    base_url: str,
    *,
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
    max_requests: int = 80,
) -> tuple[ReceiptStore, AgenticHTTPClient, DifferentialOracle, dict[str, dict[str, str]]]:
    acct_list = (
        accounts
        if accounts is not None
        else [
            {"alias": "alice", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-alice"},
            {"alias": "bob", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-bob"},
            {"alias": "charlie", "role": "member", "tenant": "beta", "auth_header": "Bearer tok-charlie"},
            {"alias": "admin", "role": "admin", "tenant": "alpha", "auth_header": "Bearer tok-admin"},
        ]
    )
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager(acct_list)
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
    )
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential")
    actor_meta = {
        str(a["alias"]): {"role": str(a.get("role") or "").lower(), "tenant": str(a.get("tenant") or "").lower()}
        for a in acct_list
    }
    return store, client, oracle, actor_meta


# ---------------------------------------------------------------------------
# 1. agentic_evidence: Multi-origin dedup separation
# ---------------------------------------------------------------------------


def test_extract_origin_and_multi_origin_dedup_separation(tmp_path: Path) -> None:
    assert extract_origin("https://app.example.com/health") == "https://app.example.com"
    assert extract_origin("https://api.example.com:443/v1/health") == "https://api.example.com"
    assert extract_origin("http://127.0.0.1:8080/api/items") == "http://127.0.0.1:8080"
    assert extract_origin("/relative/path") == ""

    store = ReceiptStore(tmp_path)
    r_app = store.record(
        actor="anon",
        method="GET",
        url="https://app.example.com/health",
        path="/health",
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        raw_response_bytes=b'{"service":"app","secret":"app_tok_1234567890"}',
        response_text='{"service":"app","secret":"app_tok_1234567890"}',
    )
    r_api = store.record(
        actor="anon",
        method="GET",
        url="https://api.example.com/health",
        path="/health",
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        raw_response_bytes=b'{"service":"api","secret":"api_tok_0987654321"}',
        response_text='{"service":"api","secret":"api_tok_0987654321"}',
    )
    ctrl_app = store.record(
        actor="bob",
        method="GET",
        url="https://app.example.com/health",
        path="/health",
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        raw_response_bytes=b'{"service":"app","secret":"app_tok_1234567890"}',
        response_text='{"service":"app","secret":"app_tok_1234567890"}',
    )
    ctrl_api = store.record(
        actor="bob",
        method="GET",
        url="https://api.example.com/health",
        path="/health",
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        raw_response_bytes=b'{"service":"api","secret":"api_tok_0987654321"}',
        response_text='{"service":"api","secret":"api_tok_0987654321"}',
    )

    findings = [
        {
            "title": "App health secret leak",
            "class_type": "auth_bypass",
            "method": "GET",
            "url": "https://app.example.com/health",
            "path": "/health",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "app_tok_1234567890",
            "proof_receipt_ids": [r_app["receipt_id"]],
            "control_receipt_ids": [ctrl_app["receipt_id"]],
        },
        {
            "title": "API health secret leak",
            "class_type": "auth_bypass",
            "method": "GET",
            "url": "https://api.example.com/health",
            "path": "/health",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "api_tok_0987654321",
            "proof_receipt_ids": [r_api["receipt_id"]],
            "control_receipt_ids": [ctrl_api["receipt_id"]],
        },
    ]
    actor_meta = {"bob": {"alias": "bob", "role": "member", "tenant": "alpha"}}
    out = canonicalize_and_deduplicate_findings(findings, actor_meta_map=actor_meta, receipt_store=store)
    assert len(out) == 2
    assert {f["url"] for f in out} == {"https://app.example.com/health", "https://api.example.com/health"}

    # Same-origin duplicates still merge cleanly.
    dup_same_origin = [
        findings[0],
        {
            **findings[0],
            "title": "Duplicate app health leak",
            "class_type": "other",
        },
    ]
    merged_single = canonicalize_and_deduplicate_findings(
        dup_same_origin, actor_meta_map=actor_meta, receipt_store=store
    )
    assert len(merged_single) == 1
    assert merged_single[0]["class_type"] == "auth_bypass"


# ---------------------------------------------------------------------------
# 2. agentic_evidence: GraphQL op dedup + HTTP-200 error envelope
# ---------------------------------------------------------------------------


def test_graphql_operation_dedup_and_200_error_envelope_isolation(tmp_path: Path) -> None:
    assert extract_graphql_operation_key('{"operationName":"GetUsers","query":"query { users { id } }"}') == "GetUsers"
    assert extract_graphql_operation_key('{"query":"mutation PromoteUser($id: ID!) { promoteUser(id: $id) { role } }"}') == "PromoteUser"
    assert extract_graphql_operation_key('{"query":"query { __schema { types { name } } }"}') == "__schema"
    assert extract_graphql_operation_key('{"query":"# lead comment\\n{ u: secretNotes { text } }"}') == "secretNotes"
    assert extract_graphql_operation_key('{"query":"# lead comment\n{ u: secretNotes { text } }"}') == "secretNotes"

    # _is_genuine_anon_2xx must reject GraphQL HTTP-200 error-only envelopes.
    assert _is_genuine_anon_2xx({
        "actor": "anon",
        "status": 200,
        "url": "https://api.example.com/graphql",
        "body": '{"errors":[{"message":"Unauthorized"}],"data":null}',
    }) is False
    assert _is_genuine_anon_2xx({
        "actor": "anon",
        "status": 200,
        "url": "https://api.example.com/graphql",
        "body": '{"errors":[{"message":"Forbidden"}],"data":{"adminNotes":null}}',
    }) is False
    assert _is_genuine_anon_2xx({
        "actor": "anon",
        "status": 200,
        "url": "https://api.example.com/graphql",
        "body": '{"errors":[{"message":"Denied"}]}',
    }) is False
    assert _is_genuine_anon_2xx({
        "actor": "anon",
        "status": 200,
        "url": "https://api.example.com/graphql",
        "body": '{"data":{"secretNotes":[{"text":"SECRET_123"}]}}',
    }) is True

    store = ReceiptStore(tmp_path)
    store.record(
        actor="anon",
        method="POST",
        url="https://api.example.com/graphql",
        path="/graphql",
        request_body='{"operationName":"IntrospectionQuery","query":"query IntrospectionQuery { __schema { types { name } } }"}',
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        raw_response_bytes=b'{"data":{"__schema":{"types":[{"name":"Query"}]}}}',
        response_text='{"data":{"__schema":{"types":[{"name":"Query"}]}}}',
    )
    anon_promote_denied = store.record(
        actor="anon",
        method="POST",
        url="https://api.example.com/graphql",
        path="/graphql",
        request_body='{"operationName":"PromoteUser","query":"mutation PromoteUser { promoteUser(id: 2) { role } }"}',
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        raw_response_bytes=b'{"errors":[{"message":"Unauthorized"}],"data":null}',
        response_text='{"errors":[{"message":"Unauthorized"}],"data":null}',
    )
    bob_promote_ok = store.record(
        actor="bob",
        method="POST",
        url="https://api.example.com/graphql",
        path="/graphql",
        request_body='{"operationName":"PromoteUser","query":"mutation PromoteUser { promoteUser(id: 2) { role } }"}',
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        raw_response_bytes=b'{"data":{"promoteUser":{"id":"2","role":"admin"}}}',
        response_text='{"data":{"promoteUser":{"id":"2","role":"admin"}}}',
    )
    anon_leak_ok = store.record(
        actor="anon",
        method="POST",
        url="https://api.example.com/graphql",
        path="/graphql",
        request_body='{"query":"query { leakedVault { token } }"}',
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        raw_response_bytes=b'{"data":{"leakedVault":{"token":"vault_tok_abcd12345678"}}}',
        response_text='{"data":{"leakedVault":{"token":"vault_tok_abcd12345678"}}}',
    )
    bob_leak_ctrl = store.record(
        actor="bob",
        method="POST",
        url="https://api.example.com/graphql",
        path="/graphql",
        request_body='{"query":"query { leakedVault { token } }"}',
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        raw_response_bytes=b'{"data":{"leakedVault":{"token":"vault_tok_abcd12345678"}}}',
        response_text='{"data":{"leakedVault":{"token":"vault_tok_abcd12345678"}}}',
    )
    # Cross-operation anon 401 on AdminAudit must NOT cancel genuine auth_bypass on leakedVault.
    _anon_audit_401 = store.record(
        actor="anon",
        method="POST",
        url="https://api.example.com/graphql",
        path="/graphql",
        request_body='{"operationName":"AdminAudit","query":"query AdminAudit { auditLogs { id } }"}',
        status=401,
        elapsed_ms=1.0,
        content_type="application/json",
        raw_response_bytes=b'{"error":"unauthorized"}',
        response_text='{"error":"unauthorized"}',
    )

    actor_meta = {"bob": {"alias": "bob", "role": "member", "tenant": "alpha"}}

    # _find_exact_route_anon_2xx must NOT treat anon IntrospectionQuery 200 as anon 2xx for PromoteUser!
    anon_match, anon_denied = _find_exact_route_anon_2xx(
        "/graphql",
        "POST",
        [bob_promote_ok],
        [anon_promote_denied],
        actor_meta_map=actor_meta,
        receipt_store=store,
        origin="https://api.example.com",
        graphql_op="PromoteUser",
    )
    assert anon_match is None
    assert anon_denied is False

    assert _resolve_route_auth_bypass_vs_bfla(
        "/graphql",
        [bob_promote_ok],
        [anon_promote_denied],
        actor_meta_map=actor_meta,
        receipt_store=store,
        exact_path="/graphql",
        method="POST",
        origin="https://api.example.com",
        graphql_op="PromoteUser",
    ) == "bfla"

    assert _resolve_route_auth_bypass_vs_bfla(
        "/graphql",
        [anon_leak_ok],
        [bob_leak_ctrl],
        actor_meta_map=actor_meta,
        receipt_store=store,
        exact_path="/graphql",
        method="POST",
        origin="https://api.example.com",
        graphql_op="leakedVault",
    ) == "auth_bypass"

    # Distinct GraphQL operations on the same /graphql endpoint stay separate findings in dedup!
    bob_notes = store.record(
        actor="bob",
        method="POST",
        url="https://api.example.com/gql",
        path="/gql",
        request_body='{"operationName":"ExportAllSecrets","query":"query ExportAllSecrets { exportAllSecrets { key } }"}',
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        raw_response_bytes=b'{"data":{"exportAllSecrets":{"key":"exp_1234567890abcdef"}}}',
        response_text='{"data":{"exportAllSecrets":{"key":"exp_1234567890abcdef"}}}',
    )
    gql_findings = [
        {
            "title": "BFLA PromoteUser",
            "class_type": "bfla",
            "method": "POST",
            "url": "https://api.example.com/graphql",
            "path": "/graphql",
            "actor": "bob",
            "observed_status": 200,
            "evidence_value": "admin",
            "proof_receipt_ids": [bob_promote_ok["receipt_id"]],
            "control_receipt_ids": [anon_promote_denied["receipt_id"]],
        },
        {
            "title": "Auth bypass leakedVault",
            "class_type": "bfla",
            "method": "POST",
            "url": "https://api.example.com/graphql",
            "path": "/graphql",
            "actor": "bob",
            "observed_status": 200,
            "evidence_value": "vault_tok_abcd12345678",
            "proof_receipt_ids": [bob_leak_ctrl["receipt_id"]],
            "control_receipt_ids": [],
        },
        {
            "title": "BFLA ExportAllSecrets on /gql",
            "class_type": "bfla",
            "method": "POST",
            "url": "https://api.example.com/gql",
            "path": "/gql",
            "actor": "bob",
            "observed_status": 200,
            "evidence_value": "exp_1234567890abcdef",
            "proof_receipt_ids": [bob_notes["receipt_id"]],
            "control_receipt_ids": [],
        },
    ]
    deduped = canonicalize_and_deduplicate_findings(gql_findings, actor_meta_map=actor_meta, receipt_store=store)
    assert len(deduped) == 3
    by_title = {f["title"]: f for f in deduped}
    assert by_title["BFLA PromoteUser"]["class_type"] == "bfla"
    assert by_title["Auth bypass leakedVault"]["class_type"] == "auth_bypass"
    assert by_title["Auth bypass leakedVault"]["actor"] == "anon"
    assert by_title["BFLA ExportAllSecrets on /gql"]["class_type"] == "bfla"


# ---------------------------------------------------------------------------
# 3. Nested JSON owner/tenant extraction (evidence + oracle)
# ---------------------------------------------------------------------------


def test_nested_json_owner_and_tenant_extraction() -> None:
    actor_meta = {
        "alice": {"role": "member", "tenant": "alpha"},
        "bob": {"role": "member", "tenant": "beta"},
    }
    cases = [
        {"data": {"owner": "alice", "tenant": "alpha"}},
        {"result": {"order": {"created_by": "alice", "tenant_id": "alpha"}}},
        {"payload": {"account": {"profile": {"username": "alice", "company": "alpha"}}}},
        [{"user": {"owner_alias": "alice", "org": "alpha"}}],
        {"data": [{"record": {"owner": "alice"}}]},
    ]
    for payload in cases:
        rec = {"body": json.dumps(payload)}
        assert _extract_record_owner_and_tenant(rec, actor_meta) == ("alice", "alpha")
        assert _extract_owner_and_tenant_from_receipt(rec, actor_meta) == ("alice", "alpha")

    # Too deeply nested (> depth 3) does not traverse indefinitely.
    deep_payload = {"data": {"result": {"order": {"item": {"owner": "alice"}}}}}
    assert _extract_record_owner_and_tenant({"body": json.dumps(deep_payload)}, actor_meta) == ("", "")
    assert _extract_owner_and_tenant_from_receipt({"body": json.dumps(deep_payload)}, actor_meta) == ("", "")


# ---------------------------------------------------------------------------
# 4. Oracle multi-origin persistence & Stage 1 control/catch-all probe origin
# ---------------------------------------------------------------------------


def test_oracle_multi_origin_read_path_and_stage1_probe_origin(tmp_path: Path) -> None:
    assert is_persistent_read_path_related(
        "https://app.example.com/comments",
        "https://api.example.com/comments",
    ) is False
    assert is_persistent_read_path_related(
        "https://app.example.com/comments",
        "https://app.example.com/comments",
    ) is True
    assert is_persistent_read_path_related("/comments", "https://app.example.com/comments") is True

    # Two servers: srv_a (primary base_url) and srv_b (sibling origin).
    hits_a: list[str] = []
    hits_b: list[str] = []
    b_mode = {"catchall_html": False}

    class _HandlerA(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            hits_a.append(self.path)
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"not_found_on_a"}')

    class _HandlerB(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            hits_b.append(self.path)
            if self.path == "/admin-json":
                payload = b'{"admin_secret":"SIBLING_ORIGIN_B_SECRET_99"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path == "/admin-spa":
                payload = b"<html><body>SPA Shell</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if b_mode["catchall_html"]:
                payload = b"<html><body>SPA Shell</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            payload = b'{"error":"not_found_on_b"}'
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    origin_a, srv_a = _start_server(_HandlerA)
    origin_b, srv_b = _start_server(_HandlerB)
    store, client, oracle, _ = _make_env(tmp_path, origin_a)
    allowed_origins = {
        urlsplit(origin_a).netloc,
        urlsplit(origin_b).netloc,
    }

    def _multi_resolve(
        raw_url: str,
        *,
        allow_websocket: bool = True,
        allow_lifecycle_routes: bool | None = None,
    ) -> tuple[str, str, str]:
        _ = (allow_websocket, allow_lifecycle_routes)
        p = urlsplit(raw_url)
        if not p.scheme:
            p = urlsplit(f"{origin_a}{raw_url if raw_url.startswith('/') else '/' + raw_url}")
        if p.netloc not in allowed_origins:
            raise ScopeViolationError(f"out of scope: {raw_url}")
        clean = urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))
        return clean, p.path or "/", p.query

    client.resolve_in_scope = _multi_resolve  # type: ignore[method-assign]
    try:
        # 1. Stage 1 auth_bypass control probe targets origin_b, NOT origin_a!
        proof_b = client.request(method="GET", url=f"{origin_b}/admin-json", actor="anon")
        assert proof_b["status"] == 200
        hits_a.clear()
        hits_b.clear()
        v_b = oracle.verify(
            canonical_class="auth_bypass",
            primary_proof=proof_b,
            proof_receipts=[proof_b],
            control_receipts=[],
            evidence_value="SIBLING_ORIGIN_B_SECRET_99",
        )
        assert v_b.verified is True
        assert any(p.endswith("-control-check") for p in hits_b)
        assert hits_a == []

        # 2. Catch-all HTML decoy probe also targets origin_b and detects catch-all SPA on origin_b!
        b_mode["catchall_html"] = True
        spa_b = client.request(method="GET", url=f"{origin_b}/admin-spa", actor="anon")
        hits_a.clear()
        hits_b.clear()
        v_spa = oracle.verify(
            canonical_class="auth_bypass",
            primary_proof=spa_b,
            proof_receipts=[spa_b],
            control_receipts=[],
            evidence_value="SPA Shell",
        )
        assert v_spa.verified is False
        assert v_spa.verdict == "DECEPTION_DETECTED"
        assert v_spa.stages["stage1_control"] == "deception_catchall_html"
        assert any(p.endswith("-control-check") for p in hits_b)
        assert hits_a == []
    finally:
        client.close()
        _stop_server(srv_a)
        _stop_server(srv_b)


# ---------------------------------------------------------------------------
# 5. Oracle GraphQL HTTP-200 error envelope controls + BOLA/Stage 3
# ---------------------------------------------------------------------------


def test_oracle_graphql_200_error_envelope_controls_and_refutations(tmp_path: Path) -> None:
    assert _is_graphql_error_envelope({"body": '{"errors":[{"message":"Denied"}],"data":null}'}) is True
    assert _is_graphql_error_envelope({"body": '{"errors":[{"message":"Denied"}],"data":{"secret":null}}'}) is True
    assert _is_graphql_error_envelope({"body": '{"errors":[{"message":"Warn"}],"data":{"secret":"ok"}}'}) is False
    assert _is_graphql_error_envelope({"body": '{"data":{"secret":"ok"}}'}) is False

    actor_meta = {
        "alice": {"role": "member", "tenant": "alpha"},
        "bob": {"role": "member", "tenant": "alpha"},
        "charlie": {"role": "member", "tenant": "beta"},
    }
    proof_nested = {
        "actor": "bob",
        "method": "POST",
        "url": "https://api.example.com/graphql",
        "path": "/graphql",
        "status": 200,
        "body": json.dumps({"data": {"order": {"owner": "alice", "tenant": "alpha", "secret": "ORD_SECRET"}}}),
    }
    gql_peer_denied_ctrl = {
        "actor": "alice",
        "method": "POST",
        "url": "https://api.example.com/graphql",
        "path": "/graphql",
        "status": 200,
        "body": '{"errors":[{"message":"Forbidden"}],"data":null}',
    }
    gql_cross_tenant_denied_ctrl = {
        "actor": "charlie",
        "method": "POST",
        "url": "https://api.example.com/graphql",
        "path": "/graphql",
        "status": 200,
        "body": '{"errors":[{"message":"Forbidden"}],"data":{"order":null}}',
    }

    # Same-tenant peer GraphQL 200 error control passes check_bola_false_positive!
    assert check_bola_false_positive(
        primary_proof=proof_nested,
        proof_receipts=[proof_nested],
        control_receipts=[gql_peer_denied_ctrl],
        actor_meta_map=actor_meta,
    ) is None

    # Cross-tenant-only GraphQL 200 error control is recognized as denied cross-tenant control and rejected for same-tenant BOLA!
    fp = check_bola_false_positive(
        primary_proof=proof_nested,
        proof_receipts=[proof_nested],
        control_receipts=[gql_cross_tenant_denied_ctrl],
        actor_meta_map=actor_meta,
    )
    assert fp is not None
    assert fp[0] == "failed_bola_cross_tenant_only_control"

    # End-to-end oracle rejects GraphQL 200 error-only primary proof and GraphQL 200 error-only replay.
    gql_mode = {"replay_deny": False}

    class _GqlHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            if self.path == "/graphql":
                if gql_mode["replay_deny"]:
                    payload = b'{"errors":[{"message":"Forbidden"}],"data":null}'
                elif "adminAudit" in body:
                    payload = b'{"data":{"adminAudit":{"secret":"AUDIT_SECRET_77"}}}'
                else:
                    payload = b'{"errors":[{"message":"Denied"}],"data":null}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.end_headers()

    base_url, srv = _start_server(_GqlHandler)
    store, client, oracle, amap = _make_env(tmp_path, base_url)
    try:
        bad_proof = client.request(
            method="POST",
            url="/graphql",
            actor="bob",
            json_body={"query": "query { deniedOp { x } }"},
        )
        v_bad = oracle.verify(
            canonical_class="bfla",
            primary_proof=bad_proof,
            proof_receipts=[bad_proof],
            control_receipts=[],
            evidence_value="Denied",
            actor_meta_map=amap,
        )
        assert v_bad.verified is False
        assert v_bad.stages["stage1_control"] == "failed_graphql_error_proof"

        ctrl_denied = client.request(
            method="POST",
            url="/graphql",
            actor="anon",
            json_body={"query": "query { adminAudit { secret } }"},
        )
        good_proof = client.request(
            method="POST",
            url="/graphql",
            actor="bob",
            json_body={"query": "query { adminAudit { secret } }"},
        )
        gql_mode["replay_deny"] = True
        v_replay_err = oracle.verify(
            canonical_class="bfla",
            primary_proof=good_proof,
            proof_receipts=[good_proof],
            control_receipts=[ctrl_denied],
            evidence_value="AUDIT_SECRET_77",
            actor_meta_map=amap,
        )
        assert v_replay_err.verified is False
        assert v_replay_err.stages["stage3_clean_replay"] == "failed_graphql_error_envelope"
    finally:
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 6. Stage 3 redacted CSRF / token body handling
# ---------------------------------------------------------------------------


def test_stage3_redacted_csrf_and_token_body_handling(tmp_path: Path) -> None:
    for body in (
        '{"csrf_token": "<REDACTED_SECRET>"}',
        '{"csrf": "<REDACTED_SECRET>"}',
        '{"xsrf_token": "<REDACTED_SECRET>"}',
        '{"authenticity_token": "<REDACTED_SECRET>"}',
        '{"access_token": "<REDACTED_SECRET>"}',
        '{"api_key": "<REDACTED_SECRET>"}',
        '{"query": "mutation { x(token: \\"<REDACTED_SECRET:sha256_8=deadbeef>\\") }"}',
        "csrf_token=<REDACTED_SECRET:sha256_8=12345678>&role=admin",
    ):
        assert _has_redacted_credential_body({"request_body": body}) is True

    class _CsrfTokenHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            data = json.loads(raw) if raw.strip().startswith("{") else {}
            if self.path == "/api/profile":
                if data.get("csrf_token") != "live-csrf-xyz-999":
                    payload = b'{"error":"invalid csrf token"}'
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                role = str(data.get("role") or "member")
                payload = json.dumps({"updated": True, "role": role}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path == "/api/token-action":
                if data.get("api_key") != "live-api-key-777":
                    payload = b'{"error":"invalid api_key"}'
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                role = str(data.get("role") or "member")
                payload = json.dumps({"ok": True, "role": role}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.end_headers()

    base_url, srv = _start_server(_CsrfTokenHandler)
    accounts = [
        {
            "alias": "alice",
            "role": "member",
            "tenant": "alpha",
            "auth_header": "Bearer tok-alice",
            "csrf_token": "live-csrf-xyz-999",
            "csrf_field_name": "csrf_token",
        },
        {
            "alias": "bob",
            "role": "member",
            "tenant": "alpha",
            "auth_header": "Bearer tok-bob",
        },
    ]
    store, client, oracle, _ = _make_env(tmp_path, base_url, accounts=accounts)
    try:
        # Case A: session has live csrf_token -> Stage 3 restores live CSRF token and passes 200!
        ctrl_csrf = client.request(
            method="POST",
            url="/api/profile",
            actor="alice",
            json_body={"csrf_token": "live-csrf-xyz-999", "role": "member"},
        )
        proof_csrf = client.request(
            method="POST",
            url="/api/profile",
            actor="alice",
            json_body={"csrf_token": "live-csrf-xyz-999", "role": "admin"},
        )
        assert "<REDACTED_SECRET" in proof_csrf["request_body"]
        v_csrf_live = oracle.verify(
            canonical_class="mass_assignment",
            primary_proof=proof_csrf,
            proof_receipts=[proof_csrf],
            control_receipts=[ctrl_csrf],
            evidence_value="admin",
        )
        assert v_csrf_live.verified is True
        assert v_csrf_live.stages["stage3_clean_replay"] == "passed"

        # Case B: redacted api_key in body (not auto-injected) -> server returns 400 invalid api_key -> verified exempt!
        client.actors.get("bob").register_secret("live-api-key-777")
        ctrl_api = client.request(
            method="POST",
            url="/api/token-action",
            actor="bob",
            json_body={"api_key": "live-api-key-777", "role": "member"},
        )
        proof_api = client.request(
            method="POST",
            url="/api/token-action",
            actor="bob",
            json_body={"api_key": "live-api-key-777", "role": "admin"},
        )
        assert "<REDACTED_SECRET" in proof_api["request_body"]
        v_api = oracle.verify(
            canonical_class="mass_assignment",
            primary_proof=proof_api,
            proof_receipts=[proof_api],
            control_receipts=[ctrl_api],
            evidence_value="admin",
        )
        assert v_api.verified is True
        assert v_api.stages["stage3_clean_replay"] == "passed_redacted_credential_replay_exempt"
    finally:
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 7. 422 one-shot create conflict & extended conflict phrases
# ---------------------------------------------------------------------------


def test_422_oneshot_conflict_and_extended_phrases(tmp_path: Path) -> None:
    for phrase in (
        "Coupon already redeemed",
        "Voucher already used",
        "Promo already applied",
        "Redemption limit reached",
        "Order already processed",
        "Email already exists",
    ):
        assert _is_one_shot_create_conflict({"status": 422, "body": json.dumps({"error": phrase})}) is True
        assert _is_one_shot_create_conflict({"status": 400, "body": json.dumps({"error": phrase})}) is True
    assert _is_one_shot_create_conflict({"status": 422, "body": '{"error":"validation_error"}'}) is False

    redeemed = {"done": False}

    class _Promo422Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            auth = self.headers.get("Authorization", "")
            if auth != "Bearer tok-alice":
                payload = b'{"error":"forbidden"}'
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path == "/api/coupons/redeem":
                if redeemed["done"]:
                    payload = b'{"error":"Coupon already redeemed"}'
                    self.send_response(422)
                else:
                    redeemed["done"] = True
                    payload = b'{"redeemed":true,"credit":50,"code":"GIFT50"}'
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.end_headers()

    base_url, srv = _start_server(_Promo422Handler)
    store, client, oracle, amap = _make_env(tmp_path, base_url)
    try:
        ctrl = client.request(method="POST", url="/api/coupons/redeem", actor="bob", json_body={"code": "GIFT50"})
        proof = client.request(method="POST", url="/api/coupons/redeem", actor="alice", json_body={"code": "GIFT50"})
        assert ctrl["status"] == 403
        assert proof["status"] == 200
        verdict = oracle.verify(
            canonical_class="bfla",
            primary_proof=proof,
            proof_receipts=[proof],
            control_receipts=[ctrl],
            evidence_value="GIFT50",
            actor_meta_map=amap,
        )
        assert verdict.verified is True
        assert verdict.stages["stage3_clean_replay"] == "passed_one_shot_create_conflict"
    finally:
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 8. CORS Origin: null / static ACAO: * & response-header-only Stage 2 diffs
# ---------------------------------------------------------------------------


def test_cors_null_static_wildcard_and_response_header_only_stage2_diff(tmp_path: Path) -> None:
    class _HeadersHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            origin = self.headers.get("Origin", "")
            qs = parse_qs(urlsplit(self.path).query)
            path = urlsplit(self.path).path
            body = json.dumps({"user": "alice", "api_key": "secret-data"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if path == "/cors-null" and origin == "null":
                self.send_header("Access-Control-Allow-Origin", "null")
                self.send_header("Access-Control-Allow-Credentials", "true")
            elif path == "/cors-static-star":
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Credentials", "true")
            elif path == "/cache-diff":
                mode = (qs.get("mode") or ["safe"])[0]
                if mode == "leak":
                    self.send_header("Cache-Control", "public, max-age=3600")
                else:
                    self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    base_url, srv = _start_server(_HeadersHandler)
    store, client, oracle, _ = _make_env(tmp_path, base_url)
    try:
        # 1. Origin: null -> ACAO: null + ACAC: true
        null_proof = client.request(method="GET", url="/cors-null", actor="alice", headers={"Origin": "null"})
        null_ctrl = client.request(method="GET", url="/cors-null", actor="alice")
        v_null = oracle.verify(
            canonical_class="cors_misconfiguration",
            primary_proof=null_proof,
            proof_receipts=[null_proof],
            control_receipts=[null_ctrl],
            evidence_value="null",
        )
        assert v_null.verified is True
        assert v_null.stages["stage3_clean_replay"] == "passed"

        # 2. Static ACAO: * + ACAC: true (control without Origin also gets ACAO: *!)
        star_proof = client.request(
            method="GET",
            url="/cors-static-star",
            actor="alice",
            headers={"Origin": "https://evil.example"},
        )
        star_ctrl = client.request(method="GET", url="/cors-static-star", actor="alice")
        v_star = oracle.verify(
            canonical_class="cors_misconfiguration",
            primary_proof=star_proof,
            proof_receipts=[star_proof],
            control_receipts=[star_ctrl],
            evidence_value="*",
        )
        assert v_star.verified is True
        assert v_star.stages["stage3_clean_replay"] == "passed"

        # Duplicate with IDENTICAL Origin still triggers deception_identical_control.
        star_dup = client.request(
            method="GET",
            url="/cors-static-star",
            actor="alice",
            headers={"Origin": "https://evil.example"},
            force=True,
        )
        v_dup = oracle.verify(
            canonical_class="cors_misconfiguration",
            primary_proof=star_proof,
            proof_receipts=[star_proof],
            control_receipts=[star_dup],
            evidence_value="*",
        )
        assert v_dup.verified is False
        assert v_dup.verdict == "DECEPTION_DETECTED"

        # 3. Response-header-only Stage 2 diff (Cache-Control differs while body/status identical).
        cache_proof = client.request(method="GET", url="/cache-diff?mode=leak", actor="alice")
        cache_ctrl = client.request(method="GET", url="/cache-diff?mode=safe", actor="alice")
        v_hdr = oracle.verify(
            canonical_class="other",
            primary_proof=cache_proof,
            proof_receipts=[cache_proof],
            control_receipts=[cache_ctrl],
            evidence_value="public, max-age=3600",
        )
        assert v_hdr.verified is True
        assert v_hdr.stages["stage1_control"] == "passed"
        assert v_hdr.stages["stage2_diff"] == "passed"
        assert v_hdr.stages["stage3_clean_replay"] == "passed"
    finally:
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 9. race_condition concurrency validation
# ---------------------------------------------------------------------------


def test_race_condition_concurrency_checks(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    client = AgenticHTTPClient(
        base_url="http://127.0.0.1:9999",
        receipt_store=store,
        actors=ActorManager([{"alias": "alice", "role": "member", "tenant": "alpha"}]),
        allowed_methods=("GET", "POST"),
        max_requests=20,
    )
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential")
    t0 = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc)

    try:
        ctrl_409 = {
            "receipt_id": "req-0001",
            "actor": "alice",
            "method": "POST",
            "url": "http://127.0.0.1:9999/api/redeem",
            "path": "/api/redeem",
            "status": 409,
            "body": '{"error":"already_redeemed"}',
            "timestamp": (t0 + timedelta(seconds=20)).isoformat(),
        }

        # 1. Shared concurrent_burst_id passes even with spaced timestamps.
        burst_p1 = {
            "receipt_id": "req-0002",
            "actor": "alice",
            "method": "POST",
            "url": "http://127.0.0.1:9999/api/redeem",
            "path": "/api/redeem",
            "status": 200,
            "body": '{"redeemed":true}',
            "concurrent_burst_id": "burst-42",
            "timestamp": t0.isoformat(),
        }
        burst_p2 = {
            **burst_p1,
            "receipt_id": "req-0003",
            "timestamp": (t0 + timedelta(seconds=5)).isoformat(),
        }
        v_burst = oracle.verify(
            canonical_class="race_condition",
            primary_proof=burst_p1,
            proof_receipts=[burst_p1, burst_p2],
            control_receipts=[ctrl_409],
            evidence_value="redeemed",
        )
        assert v_burst.verified is True

        # 2. Mutating proofs within <= 2.0s without burst_id passes.
        tight_p1 = {
            "receipt_id": "req-0004",
            "actor": "alice",
            "method": "POST",
            "url": "http://127.0.0.1:9999/api/redeem",
            "path": "/api/redeem",
            "status": 200,
            "body": '{"redeemed":true}',
            "timestamp": t0.isoformat(),
        }
        tight_p2 = {
            **tight_p1,
            "receipt_id": "req-0005",
            "timestamp": (t0 + timedelta(milliseconds=150)).isoformat(),
        }
        v_tight = oracle.verify(
            canonical_class="race_condition",
            primary_proof=tight_p1,
            proof_receipts=[tight_p1, tight_p2],
            control_receipts=[ctrl_409],
            evidence_value="redeemed",
        )
        assert v_tight.verified is True

        # 3. Sequential mutating proofs > 2.0s apart without concurrent_burst_id -> REFUTED!
        slow_p2 = {
            **tight_p1,
            "receipt_id": "req-0006",
            "timestamp": (t0 + timedelta(seconds=8)).isoformat(),
        }
        v_seq_slow = oracle.verify(
            canonical_class="race_condition",
            primary_proof=tight_p1,
            proof_receipts=[tight_p1, slow_p2],
            control_receipts=[ctrl_409],
            evidence_value="redeemed",
        )
        assert v_seq_slow.verified is False
        assert v_seq_slow.verdict == "REFUTED"
        assert v_seq_slow.stages["stage1_control"] == "failed_missing_concurrency_evidence"

        # 4. Purely read-only GET pair returning identical body -> REFUTED even with tight timestamps!
        ro_g1 = {
            "receipt_id": "req-0007",
            "actor": "alice",
            "method": "GET",
            "url": "http://127.0.0.1:9999/api/balance",
            "path": "/api/balance",
            "status": 200,
            "body": '{"balance":100}',
            "timestamp": t0.isoformat(),
        }
        ro_g2 = {
            **ro_g1,
            "receipt_id": "req-0008",
            "timestamp": (t0 + timedelta(milliseconds=50)).isoformat(),
        }
        ro_ctrl_401 = {**ro_g1, "receipt_id": "req-0009", "actor": "anon", "status": 401, "body": '{"error":"unauth"}'}
        v_ro_identical = oracle.verify(
            canonical_class="race_condition",
            primary_proof=ro_g1,
            proof_receipts=[ro_g1, ro_g2],
            control_receipts=[ro_ctrl_401],
            evidence_value="100",
        )
        assert v_ro_identical.verified is False
        assert v_ro_identical.stages["stage1_control"] == "failed_missing_concurrency_evidence"

        # 5. Concurrent GET pair with divergent state-change bodies -> VERIFIED!
        ro_g2_changed = {
            **ro_g2,
            "body": '{"balance":50}',
        }
        v_ro_changed = oracle.verify(
            canonical_class="race_condition",
            primary_proof=ro_g1,
            proof_receipts=[ro_g1, ro_g2_changed],
            control_receipts=[ro_ctrl_401],
            evidence_value="50",
        )
        assert v_ro_changed.verified is True
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 10. agentic_report: Multi-origin SARIF/Markdown, shard recovery, budget & curl
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def test_report_multi_origin_shard_recovery_budget_and_curl_redaction(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-crashed-multi"
    budget = SharedBudget(http=120, tokens=300_000, seconds=600)
    t_http = budget.reserve("http", 15)
    budget.settle(t_http, 15)
    t_tok = budget.reserve("tokens", 42_000)
    budget.settle(t_tok, 42_000)

    _write_json(
        run_dir / "manifest.json",
        {
            "run_id": "run-wave1-01",
            "target": "https://app.example.com",
            "status": "aborted",
            "budget": budget.snapshot(),
            "surface_frontier": {
                "base_url": "https://app.example.com",
                "actors": {
                    "alice": {"alias": "alice", "role": "member", "tenant": "alpha"},
                    "bob": {"alias": "bob", "role": "member", "tenant": "beta"},
                },
            },
        },
    )
    # Root findings.json is missing; findings live only in shards/*/findings.json!
    _write_json(
        run_dir / "receipts" / "req-0001.json",
        {
            "receipt_id": "req-0001",
            "actor": "anon",
            "method": "GET",
            "url": "https://app.example.com/health",
            "path": "/health",
            "request_headers": {
                "Authorization": "Bearer supersecret-jwt-value",
                "Cookie": "sid=cookie-secret-val",
                "X-API-Key": "ak_secret_12345",
                "X-Auth-Token": "auth-tok-secret",
                "X-CSRF-Token": "csrf-secret-xyz",
                "X-XSRF-Token": "xsrf-secret-xyz",
                "Proxy-Authorization": "Basic dXNlcjpwYXNz",
                "X-CSRF-Token-Mode": "strict",
                "X-Storefront": "web-eu",
            },
            "status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "body": '{"status":"ok","secret":"app_health_secret_99"}',
        },
    )
    _write_json(
        run_dir / "receipts" / "req-0002.json",
        {
            "receipt_id": "req-0002",
            "actor": "anon",
            "method": "GET",
            "url": "https://api.example.com/health",
            "path": "/health",
            "request_headers": {"X-Storefront": "mobile-api"},
            "status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "body": '{"status":"ok","secret":"api_health_secret_88"}',
        },
    )
    _write_json(
        run_dir / "shards" / "shard-1" / "findings.json",
        [
            {
                "finding_id": "F-001",
                "title": "App health leak",
                "class_type": "auth_bypass",
                "severity": "high",
                "method": "GET",
                "url": "https://app.example.com/health",
                "path": "/health",
                "actor": "anon",
                "supporting_actors": ["anon", "alice"],
                "clean_replay_receipt_id": "req-0001",
                "evidence_value": "app_health_secret_99",
                "proof_receipt_ids": ["req-0001"],
                "control_receipt_ids": [],
            }
        ],
    )
    _write_json(
        run_dir / "shards" / "shard-2" / "findings.json",
        [
            {
                "finding_id": "F-001",
                "title": "API health leak",
                "class_type": "auth_bypass",
                "severity": "critical",
                "method": "GET",
                "url": "https://api.example.com/health",
                "path": "/health",
                "actor": "anon",
                "supporting_actors": ["anon", "bob"],
                "clean_replay_receipt_id": "req-0002",
                "evidence_value": "api_health_secret_88",
                "proof_receipt_ids": ["req-0002"],
                "control_receipt_ids": [],
            }
        ],
    )

    artifacts = agentic_report.load_run_artifacts(run_dir)
    assert len(artifacts["findings"]) == 2
    assert "findings.json" in artifacts["missing_artifacts"]

    summary = agentic_report.generate_run_reports(run_dir)
    assert summary["findings_count"] == 2
    md_text = Path(summary["markdown_path"]).read_text(encoding="utf-8")
    sarif_doc = json.loads(Path(summary["sarif_path"]).read_text(encoding="utf-8"))

    # SharedBudget nested snapshot values appear in Executive Summary.
    assert "| HTTP Requests (used / limit) | 15 / 120 |" in md_text
    assert "| Token Usage | total=42000," in md_text

    # Multi-origin visibility in Markdown Summary Table.
    assert "GET https://app.example.com/health" in md_text
    assert "GET https://api.example.com/health" in md_text

    # Multi-origin SARIF locations, fingerprints, and enriched properties.
    results = sarif_doc["runs"][0]["results"]
    assert len(results) == 2
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert uris == {"https://api.example.com/health", "https://app.example.com/health"}
    fqns = {r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] for r in results}
    assert fqns == {"GET https://api.example.com/health", "GET https://app.example.com/health"}
    hashes = {r["partialFingerprints"]["primaryLocationLineHash"] for r in results}
    ckeys = {r["partialFingerprints"]["canonicalKey"] for r in results}
    assert len(hashes) == 2
    assert ckeys == {
        "auth_bypass:GET:https://api.example.com/health",
        "auth_bypass:GET:https://app.example.com/health",
    }

    by_url = {r["properties"]["url"]: r["properties"] for r in results}
    assert set(by_url) == {"https://api.example.com/health", "https://app.example.com/health"}
    assert by_url["https://app.example.com/health"]["supporting_actors"] == ["anon", "alice"]
    assert by_url["https://app.example.com/health"]["clean_replay_receipt_id"] == "req-0001"
    assert by_url["https://api.example.com/health"]["supporting_actors"] == ["anon", "bob"]
    assert by_url["https://api.example.com/health"]["clean_replay_receipt_id"] == "req-0002"

    # Strict redaction of actual auth/cookie/secret headers while preserving X-CSRF-Token-Mode and X-Storefront.
    app_curl = by_url["https://app.example.com/health"]["reproduction_curl"]
    tokens = shlex.split(app_curl)
    headers_emitted = [tokens[i + 1] for i in range(len(tokens) - 1) if tokens[i] == "-H"]
    assert "Authorization: <REDACTED_AUTH_HEADER>" in headers_emitted
    assert "Proxy-Authorization: <REDACTED_AUTH_HEADER>" in headers_emitted
    assert "Cookie: <REDACTED_COOKIE>" in headers_emitted
    assert "X-API-Key: <REDACTED_HEADER>" in headers_emitted
    assert "X-Auth-Token: <REDACTED_HEADER>" in headers_emitted
    assert "X-CSRF-Token: <REDACTED_HEADER>" in headers_emitted
    assert "X-XSRF-Token: <REDACTED_HEADER>" in headers_emitted
    assert "X-CSRF-Token-Mode: strict" in headers_emitted
    assert "X-Storefront: web-eu" in headers_emitted
    for leaked in ("supersecret-jwt-value", "cookie-secret-val", "ak_secret_12345", "auth-tok-secret", "csrf-secret-xyz", "xsrf-secret-xyz"):
        assert leaked not in md_text
        assert leaked not in json.dumps(sarif_doc)
