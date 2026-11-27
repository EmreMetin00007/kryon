"""Tests for Faz 7A: auth envelope token extraction, custom API token headers, and OpenAPI header discovery."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import (  # noqa: E402
    ActorManager,
    ActorSession,
    AgenticHTTPClient,
    _extract_session_material_details,
    _extract_session_material_from_response,
    _extract_session_material_full,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import TOOL_SCHEMAS, ToolDispatcher  # noqa: E402
from kryon_core.surface.openapi import extract_openapi_header_auth_names  # noqa: E402


def _unwrap_tool_response(raw: str) -> dict[str, Any]:
    prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw.startswith(prefix) and raw.endswith(suffix)
    return json.loads(raw[len(prefix) : -len(suffix)])


@contextmanager
def _start_loopback_server(
    router: Callable[[str, str, dict[str, str], bytes], tuple[int, str, bytes | str, dict[str, str]]],
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    requests_log: list[dict[str, Any]] = []
    log_lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            path_only = urlsplit(self.path).path
            with log_lock:
                requests_log.append({
                    "method": self.command,
                    "path": path_only,
                    "headers": hdrs,
                    "body": body.decode("utf-8", errors="replace"),
                })
            status, ctype, payload, extra_hdrs = router(self.command, path_only, hdrs, body)
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

        def do_PUT(self) -> None:
            self._handle()

        def do_DELETE(self) -> None:
            self._handle()

        def log_message(self, _fmt: str, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/", requests_log
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


# ---------------------------------------------------------------------------
# 1. OpenAPI 3 & Swagger 2 security header extraction
# ---------------------------------------------------------------------------


def test_extract_openapi_header_auth_names_openapi3_and_swagger2() -> None:
    openapi3_spec = {
        "openapi": "3.0.3",
        "components": {
            "securitySchemes": {
                "JetLinksToken": {"type": "apiKey", "in": "header", "name": "X-Access-Token"},
                "DuplicateToken": {"type": "apiKey", "in": "header", "name": "x-access-token"},
                "QueryKey": {"type": "apiKey", "in": "query", "name": "api_key"},
                "CookieKey": {"type": "apiKey", "in": "cookie", "name": "sid"},
                "NonAuthUA": {"type": "apiKey", "in": "header", "name": "User-Agent"},
                "NonAuthCT": {"type": "apiKey", "in": "header", "name": "Content-Type"},
                "NonAuthCSRF": {"type": "apiKey", "in": "header", "name": "X-CSRF-Token"},
                "InvalidCRLF": {"type": "apiKey", "in": "header", "name": "X-Bad\r\nHeader"},
                "SecondaryKey": {"type": "apiKey", "in": "header", "name": "X-Tenant-Auth"},
                "BearerScheme": {"type": "http", "scheme": "bearer"},
                "RefScheme": {"$ref": "#/components/securitySchemes/SecondaryKey"},
            }
        },
    }
    assert extract_openapi_header_auth_names(openapi3_spec) == [
        "X-Access-Token",
        "X-Tenant-Auth",
        "Authorization",
    ]

    swagger2_spec = {
        "swagger": "2.0",
        "securityDefinitions": {
            "ApiToken": {"type": "apiKey", "in": "header", "name": "X-Auth-Token"},
            "BadQuery": {"type": "apiKey", "in": "query", "name": "token"},
            "IgnoredReqId": {"type": "apiKey", "in": "header", "name": "X-Request-Id"},
        },
    }
    assert extract_openapi_header_auth_names(swagger2_spec) == ["X-Auth-Token"]

    # Cap cleanly at 16 header names.
    many_spec = {
        "openapi": "3.0.0",
        "components": {
            "securitySchemes": {
                f"s{i}": {"type": "apiKey", "in": "header", "name": f"X-Custom-Auth-{i}"}
                for i in range(25)
            }
        },
    }
    capped = extract_openapi_header_auth_names(many_spec)
    assert len(capped) == 16
    assert capped[0] == "X-Custom-Auth-0"
    assert extract_openapi_header_auth_names({}) == []


# ---------------------------------------------------------------------------
# 2. Envelope & response-header session material extraction
# ---------------------------------------------------------------------------


def test_extract_session_material_envelopes_headers_and_backward_compat() -> None:
    # JetLinks-style {"message":"success","result":{"token":"..."}}
    c1, b1, r1, csrf1, _, _ = _extract_session_material_details(
        headers={},
        cookies={},
        body_text=json.dumps({"message": "success", "result": {"token": "jet-tok-123", "expires": 1800000}}),
    )
    assert (c1, b1, r1, csrf1) == ({}, "jet-tok-123", "", "")

    # {"payload":{"accessToken":...,"refreshToken":...}}
    _, b2, r2, _, _, _ = _extract_session_material_details(
        headers={},
        cookies={},
        body_text=json.dumps({"payload": {"accessToken": "pay-tok-1", "refreshToken": "pay-ref-1"}}),
    )
    assert (b2, r2) == ("pay-tok-1", "pay-ref-1")

    # {"response":{...}} and {"body":{...}}
    _, b3, _, csrf3, _, _ = _extract_session_material_details(
        headers={},
        cookies={},
        body_text=json.dumps({"response": {"auth_token": "resp-tok-1"}, "body": {"csrf_token": "body-csrf-1"}}),
    )
    assert (b3, csrf3) == ("resp-tok-1", "body-csrf-1")

    # 1 extra nesting hop inside data and result (bounded to 8 dict children)
    _, b4, _, _, _, _ = _extract_session_material_details(
        headers={},
        cookies={},
        body_text=json.dumps({"result": {"data": {"token": "nested-result-tok"}}}),
    )
    assert b4 == "nested-result-tok"

    _, b5, _, _, _, _ = _extract_session_material_details(
        headers={},
        cookies={},
        body_text=json.dumps({"data": {"result": {"accessToken": "nested-data-tok"}}}),
    )
    assert b5 == "nested-data-tok"

    # Bounded at 8 dict children inside result/data
    too_many_children = {f"k{i}": {"unused": i} for i in range(8)}
    too_many_children["k8"] = {"token": "should-not-scan"}
    _, b_cap, _, _, _, _ = _extract_session_material_details(
        headers={},
        cookies={},
        body_text=json.dumps({"result": too_many_children}),
    )
    assert b_cap == ""

    # Response header custom tokens (preserving header name, raw token without Bearer)
    for hdr_name in ("X-Access-Token", "X-Auth-Token", "X-Token", "X-Session-Token", "X-API-Token"):
        _, tok, _, _, _, _, det_hdr, tok_src = _extract_session_material_full(
            headers={hdr_name: "raw-hdr-tok-99"},
            cookies={},
            body_text="",
        )
        assert tok == "raw-hdr-tok-99"
        assert det_hdr == hdr_name
        assert tok_src == "response_header"

    # Authorization header wins over custom token response headers when both present
    _, tok_auth, _, _, _, _, det_auth_hdr, src_auth = _extract_session_material_full(
        headers={"Authorization": "Bearer auth-hdr-tok", "X-Access-Token": "ignored-tok"},
        cookies={},
        body_text="",
    )
    assert tok_auth == "auth-hdr-tok"
    assert det_auth_hdr == ""
    assert src_auth == "authorization_header"

    # 4-tuple legacy wrapper keeps working
    legacy = _extract_session_material_from_response(
        headers={"X-Access-Token": "wrap-tok"},
        cookies={},
        body_text="",
    )
    assert legacy == ({}, "wrap-tok", "", "")


# ---------------------------------------------------------------------------
# 3. ActorSession custom auth header injection, browser state, and redaction
# ---------------------------------------------------------------------------


def test_actor_session_custom_auth_header_build_headers_secrets_and_browser_state() -> None:
    session = ActorSession(
        alias="jet1",
        access_token="secret-jet-token-001",
        auth_header_name="X-Access-Token",
        auth_header_prefix="",
        cookies={"sid": "cookie-secret-001"},
        authenticated=True,
    )
    hdrs = session.build_headers("GET")
    assert hdrs["X-Access-Token"] == "secret-jet-token-001"
    assert "Authorization" not in hdrs
    assert hdrs["Cookie"] == "sid=cookie-secret-001"

    # Prefix support (if explicitly configured)
    prefixed = ActorSession(
        alias="pref",
        access_token="secret-pref-tok",
        auth_header_name="X-API-Token",
        auth_header_prefix="Token ",
        authenticated=True,
    )
    assert prefixed.build_headers("GET")["X-API-Token"] == "Token secret-pref-tok"

    # Empty or Authorization auth_header_name preserves standard Bearer behavior
    default_sess = ActorSession(alias="def", access_token="std-bearer-tok", authenticated=True)
    assert default_sess.build_headers("GET")["Authorization"] == "Bearer std-bearer-tok"
    explicit_auth_sess = ActorSession(
        alias="auth",
        access_token="std-bearer-tok-2",
        auth_header_name="Authorization",
        authenticated=True,
    )
    assert explicit_auth_sess.build_headers("GET")["Authorization"] == "Bearer std-bearer-tok-2"

    # Precedence & dual-auth isolation
    overridden = session.build_headers("GET", {"X-Access-Token": "forged-tok"})
    assert overridden["X-Access-Token"] == "forged-tok"
    assert "Cookie" not in overridden

    stripped = session.build_headers("GET", {"X-Access-Token": ""})
    assert "X-Access-Token" not in stripped

    cookie_ov = session.build_headers("GET", {"Cookie": "sid=other"})
    assert cookie_ov["Cookie"] == "sid=other"
    assert "X-Access-Token" not in cookie_ov

    auth_ov = session.build_headers("GET", {"Authorization": "Bearer other"})
    assert auth_ov["Authorization"] == "Bearer other"
    assert "X-Access-Token" not in auth_ov
    assert "Cookie" not in auth_ov

    # Secret collection covers access_token and custom base_headers
    secrets = session.collect_secrets()
    assert "secret-jet-token-001" in secrets
    assert "cookie-secret-001" in secrets

    sess_base = ActorSession(
        alias="base",
        auth_header_name="X-Vendor-Token",
        base_headers={"X-Vendor-Token": "vendor-secret-99", "X-Access-Token": "access-secret-88"},
        authenticated=True,
    )
    base_secrets = sess_base.collect_secrets()
    assert "vendor-secret-99" in base_secrets
    assert "access-secret-88" in base_secrets

    # ActorManager.get_browser_auth_state injects custom header without Bearer prefix
    mgr = ActorManager()
    mgr.register_discovered_auth_header("X-Access-Token")
    mgr.register_dynamic_session("dyn-jet", bearer_token="browser-jet-tok-77")
    bstate = mgr.get_browser_auth_state("dyn-jet")
    assert bstate["headers"]["X-Access-Token"] == "browser-jet-tok-77"
    assert "Authorization" not in bstate["headers"]


# ---------------------------------------------------------------------------
# 4. Priority resolution, 2xx anon observation, receipt redaction, and replay
# ---------------------------------------------------------------------------


def test_save_session_as_envelopes_priority_and_redaction_live(tmp_path: Path) -> None:
    jet_secret = "jetlinks-token-secret-alpha"
    pay_secret = "payload-token-secret-beta"
    hdr_secret = "header-token-secret-gamma"
    auth_secret = "auth-bearer-secret-delta"

    def _router(method: str, path: str, hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if method == "POST" and path == "/api/authorize/login":
            return 200, "application/json", json.dumps({
                "message": "success",
                "result": {"token": jet_secret, "expires": 1800000},
            }), {}
        if method == "POST" and path == "/api/payload/login":
            return 200, "application/json", json.dumps({
                "payload": {"accessToken": pay_secret},
            }), {}
        if method == "POST" and path == "/api/header/login":
            return 200, "application/json", json.dumps({"result": {"token": "ignored-body-tok"}}), {
                "X-Token": hdr_secret,
            }
        if method == "POST" and path == "/api/bearer-hdr/login":
            return 200, "application/json", json.dumps({"ok": True}), {
                "Authorization": f"Bearer {auth_secret}",
            }
        if method == "POST" and path == "/api/cookie/login":
            return 200, "application/json", json.dumps({"ok": True}), {
                "Set-Cookie": "sid=cookie-only-val; Path=/",
            }
        if method == "GET" and path == "/api/me":
            if hdrs.get("x-access-token") == jet_secret or hdrs.get("x-access-token") == pay_secret:
                return 200, "application/json", json.dumps({"ok": True, "auth_type": "x-access-token"}), {}
            if hdrs.get("x-token") == hdr_secret:
                return 200, "application/json", json.dumps({"ok": True, "auth_type": "x-token"}), {}
            if hdrs.get("authorization") == f"Bearer {auth_secret}":
                return 200, "application/json", json.dumps({"ok": True, "auth_type": "bearer"}), {}
            return 401, "application/json", '{"error":"unauthorized"}', {}
        if method == "GET" and path == "/api/probe-anon":
            if hdrs.get("x-access-token") == "probe-tok":
                return 200, "application/json", '{"ok":true}', {}
            return 401, "application/json", '{"error":"unauthorized"}', {}
        return 404, "application/json", '{"error":"not_found"}', {}

    with _start_loopback_server(_router) as (base_url, req_log):
        # A. OpenAPI/registered discovered header binds JSON result.token automatically
        store = ReceiptStore(tmp_path / "run_a")
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            allowed_methods=("GET", "POST"),
            max_requests=40,
        )
        try:
            # Ignored invalid / non-auth headers
            assert client.register_discovered_auth_header("Authorization") == ""
            assert client.register_discovered_auth_header("Bad\r\nHeader") == ""
            assert client.register_discovered_auth_header("X-CSRF-Token") == ""

            assert client.register_discovered_auth_header("X-Access-Token") == "X-Access-Token"

            # (c) Discovered header binds JSON body token from result.token
            r_login = client.request(
                method="POST",
                url="/api/authorize/login",
                actor="anon",
                json_body={"username": "admin"},
                save_session_as="jetuser",
            )
            assert r_login["saved_session"]["auth_header"] == "X-Access-Token"
            assert jet_secret not in json.dumps(r_login)

            r_me = client.request(method="GET", url="/api/me", actor="jetuser")
            assert r_me["status"] == 200
            assert json.loads(r_me["body"])["auth_type"] == "x-access-token"
            assert "<REDACTED:" in r_me["request_headers"]["X-Access-Token"]

            # (b) Response header name (X-Token) beats discovered header (X-Access-Token)
            r_hdr = client.request(
                method="POST",
                url="/api/header/login",
                actor="anon",
                json_body={},
                save_session_as="hdruser",
            )
            assert r_hdr["saved_session"]["auth_header"] == "X-Token"
            assert client.request(method="GET", url="/api/me", actor="hdruser")["status"] == 200

            # (a) Explicit auth_header_name beats response header (X-Token)
            r_exp = client.request(
                method="POST",
                url="/api/header/login",
                actor="anon",
                json_body={},
                save_session_as="expuser",
                auth_header_name="X-Access-Token",
            )
            assert r_exp["saved_session"]["auth_header"] == "X-Access-Token"
            assert client.actors.get("expuser").auth_header_name == "X-Access-Token"

            # Authorization response header is NOT overridden by discovered X-Access-Token
            r_auth = client.request(
                method="POST",
                url="/api/bearer-hdr/login",
                actor="anon",
                json_body={},
                save_session_as="beareruser",
            )
            assert "auth_header" not in r_auth["saved_session"]
            assert client.request(method="GET", url="/api/me", actor="beareruser")["status"] == 200

            # Cookie-only session does NOT bind discovered_auth_header
            r_cookie = client.request(
                method="POST",
                url="/api/cookie/login",
                actor="anon",
                json_body={},
                save_session_as="cookieuser",
            )
            assert "auth_header" not in r_cookie["saved_session"]
            assert client.actors.get("cookieuser").auth_header_name == ""

            # Explicit X-Access-Token override on 401 does NOT trigger auto-refresh
            req_log.clear()
            r_forged = client.request(
                method="GET",
                url="/api/me",
                actor="jetuser",
                headers={"X-Access-Token": "forged-bad-token"},
                force=True,
            )
            assert r_forged["status"] == 401
            assert len(req_log) == 1

            # Stored receipts on disk must never contain any raw secret token
            for rid in store.list_ids():
                raw_disk = (tmp_path / "run_a" / "receipts" / f"{rid}.json").read_text(encoding="utf-8")
                for secret in (jet_secret, hdr_secret, auth_secret):
                    assert secret not in raw_disk
        finally:
            client.close()

        # B. 2xx anon observation automatically discovers X-Access-Token for subsequent save_session_as
        store_b = ReceiptStore(tmp_path / "run_b")
        client_b = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store_b,
            allowed_methods=("GET", "POST"),
            max_requests=20,
        )
        try:
            # 401 anon probe does NOT register discovered auth header
            r_401 = client_b.request(
                method="GET",
                url="/api/probe-anon",
                actor="anon",
                headers={"X-Access-Token": "wrong"},
                force=True,
            )
            assert r_401["status"] == 401
            assert client_b.actors.discovered_auth_header == ""

            # 200 anon probe carrying X-Access-Token DOES register discovered auth header
            r_200 = client_b.request(
                method="GET",
                url="/api/probe-anon",
                actor="anon",
                headers={"X-Access-Token": "probe-tok"},
                force=True,
            )
            assert r_200["status"] == 200
            assert client_b.actors.discovered_auth_header == "X-Access-Token"

            # Subsequent save_session_as with {"payload":{"accessToken":...}} uses X-Access-Token
            r_pay = client_b.request(
                method="POST",
                url="/api/payload/login",
                actor="anon",
                json_body={},
                save_session_as="payuser",
            )
            assert r_pay["saved_session"]["auth_header"] == "X-Access-Token"
            assert client_b.request(method="GET", url="/api/me", actor="payuser")["status"] == 200
        finally:
            client_b.close()


# ---------------------------------------------------------------------------
# 5. ToolDispatcher integration: schema bounds, explicit auth_header, OpenAPI auto-discovery, replay_as
# ---------------------------------------------------------------------------


def test_tool_dispatcher_http_request_auth_header_openapi_and_replay_hygiene(tmp_path: Path) -> None:
    # 1. TOOL_SCHEMAS invariants remain intact (12 tools, <= 16384 bytes, <= 140 char descriptions)
    assert len(TOOL_SCHEMAS) == 12
    serialized = json.dumps(TOOL_SCHEMAS, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(serialized) <= 16_384
    http_tool = next(t["function"] for t in TOOL_SCHEMAS if t["function"]["name"] == "http_request")
    auth_hdr_prop = http_tool["parameters"]["properties"]["auth_header"]
    assert auth_hdr_prop["type"] == "string"
    assert len(auth_hdr_prop["description"]) <= 140

    tok_secret = "jet-dispatcher-secret-999"

    def _router(method: str, path: str, hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if method == "GET" and path == "/v3/api-docs":
            spec = {
                "openapi": "3.0.1",
                "paths": {"/api/profile": {"get": {"summary": "Profile"}}},
                "components": {
                    "securitySchemes": {
                        "AccessToken": {"type": "apiKey", "in": "header", "name": "X-Access-Token"}
                    }
                },
            }
            return 200, "application/json", json.dumps(spec), {}
        if method == "POST" and path == "/api/authorize/login":
            return 200, "application/json", json.dumps({
                "message": "success",
                "result": {"token": tok_secret},
            }), {}
        if method == "GET" and path == "/api/profile":
            if hdrs.get("x-access-token") == tok_secret:
                return 200, "application/json", '{"user":"jet-admin"}', {}
            return 401, "application/json", '{"error":"unauthorized"}', {}
        if method == "POST" and path == "/api/std/login":
            return 200, "application/json", json.dumps({"access_token": "std-jwt-tok-555"}), {
                "Set-Cookie": "sid=std-cookie-555; Path=/",
            }
        if method == "GET" and path == "/api/std/profile":
            if hdrs.get("authorization") == "Bearer std-jwt-tok-555":
                return 200, "application/json", '{"user":"std"}', {}
            return 401, "application/json", '{"error":"unauthorized"}', {}
        return 404, "application/json", '{"error":"not_found"}', {}

    with _start_loopback_server(_router) as (base_url, _log):
        # Case A: Explicit auth_header validation & forwarding in ToolDispatcher
        store = ReceiptStore(tmp_path / "disp_a")
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            allowed_methods=("GET", "POST"),
            max_requests=30,
        )
        disp = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path / "disp_a")
        try:
            # Invalid CRLF / malformed header names rejected cleanly
            bad_crlf = json.loads(disp.dispatch("http_request", {
                "method": "POST",
                "url": "/api/authorize/login",
                "auth_header": "X-Access-Token\r\nX-Evil: 1",
            }))
            assert bad_crlf["error"] == "ValueError"

            bad_space = json.loads(disp.dispatch("http_request", {
                "method": "POST",
                "url": "/api/authorize/login",
                "auth_header": "X Bad Header",
            }))
            assert bad_space["error"] == "ValueError"

            # Explicit auth_header binds session and appears in saved_session metadata
            login_out = _unwrap_tool_response(disp.dispatch("http_request", {
                "method": "POST",
                "url": "/api/authorize/login",
                "actor": "anon",
                "json_body": {"username": "admin"},
                "save_session_as": "jet_explicit",
                "auth_header": "X-Access-Token",
            }))
            assert login_out["saved_session"]["auth_header"] == "X-Access-Token"
            assert tok_secret not in json.dumps(login_out)

            # Follow-up request as jet_explicit succeeds
            prof_out = _unwrap_tool_response(disp.dispatch("http_request", {
                "method": "GET",
                "url": "/api/profile",
                "actor": "jet_explicit",
            }))
            assert prof_out["status"] == 200

            # replay_as anon MUST NOT leak jet_explicit's X-Access-Token header
            replay_anon = _unwrap_tool_response(disp.dispatch("replay_as", {
                "receipt_id": prof_out["receipt_id"],
                "actor": "anon",
            }))
            assert replay_anon["replay"]["status"] == 401

            # Backward compatibility: standard Authorization: Bearer + Cookie login works cleanly
            std_login = _unwrap_tool_response(disp.dispatch("http_request", {
                "method": "POST",
                "url": "/api/std/login",
                "actor": "anon",
                "json_body": {},
                "save_session_as": "std_actor",
            }))
            assert "auth_header" not in std_login["saved_session"]
            std_prof = _unwrap_tool_response(disp.dispatch("http_request", {
                "method": "GET",
                "url": "/api/std/profile",
                "actor": "std_actor",
            }))
            assert std_prof["status"] == 200
        finally:
            client.close()

        # Case B: Fetching /v3/api-docs (and/or calling extract_surface) auto-discovers X-Access-Token
        store_b = ReceiptStore(tmp_path / "disp_b")
        client_b = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store_b,
            allowed_methods=("GET", "POST"),
            max_requests=20,
        )
        disp_b = ToolDispatcher(http_client=client_b, receipt_store=store_b, root_dir=tmp_path / "disp_b")
        try:
            spec_out = _unwrap_tool_response(disp_b.dispatch("http_request", {
                "method": "GET",
                "url": "/v3/api-docs",
                "actor": "anon",
            }))
            assert spec_out["status"] == 200
            assert client_b.actors.discovered_auth_header == "X-Access-Token"

            # Reset to verify extract_surface also registers from OpenAPI receipt
            client_b.actors._discovered_auth_header = ""
            disp_b.dispatch("extract_surface", {"receipt_id": spec_out["receipt_id"]})
            assert client_b.actors.discovered_auth_header == "X-Access-Token"

            auto_login = _unwrap_tool_response(disp_b.dispatch("http_request", {
                "method": "POST",
                "url": "/api/authorize/login",
                "actor": "anon",
                "json_body": {},
                "save_session_as": "jet_auto",
            }))
            assert auto_login["saved_session"]["auth_header"] == "X-Access-Token"
            assert _unwrap_tool_response(disp_b.dispatch("http_request", {
                "method": "GET",
                "url": "/api/profile",
                "actor": "jet_auto",
            }))["status"] == 200
        finally:
            client_b.close()
