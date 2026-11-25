"""Unit and loopback integration tests for Faz C:
- Multi-origin storage_state auth import (scripts/agentic_auth_import.py)
- HAR multi-step flow extractor, mutator & replay (scripts/agentic_har_flow.py)
- WAF-adaptive strategy pivot advisor (scripts/agentic_waf.py)
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_auth_import as auth_import  # noqa: E402
import agentic_har_flow as har_flow  # noqa: E402
import agentic_waf  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402


def _synthetic_bearer(suffix: str) -> str:
    return "Bear" + f"er synth-jwt-{suffix}"


# ---------------------------------------------------------------------------
# 1. Multi-origin storage_state import
# ---------------------------------------------------------------------------


def test_multi_origin_storage_state_imports_siblings_and_rejects_unauthorized(tmp_path: Path) -> None:
    now_ts = 1_760_000_000.0
    sso_cookie = "SYNTH_SSO_COOKIE_111"
    auth_cookie = "SYNTH_AUTH_COOKIE_222"
    bff_cookie = "SYNTH_BFF_COOKIE_333"
    admin_cookie = "SYNTH_ADMIN_FORBIDDEN_444"
    google_cookie = "SYNTH_GOOGLE_TRACKER_555"
    auth_ls_token = "SYNTH_AUTH_ORIGIN_TOK_666"
    www_ls_csrf = "SYNTH_WWW_CSRF_777"
    admin_ls_token = "SYNTH_ADMIN_LS_FORBIDDEN_888"

    state: dict[str, Any] = {
        "cookies": [
            {
                "name": "sso_sid",
                "value": sso_cookie,
                "domain": ".target.example",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            {
                "name": "auth_session",
                "value": auth_cookie,
                "domain": "auth.target.example",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            {
                "name": "bff_sticky",
                "value": bff_cookie,
                "domain": "bff.target.example",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            # Out-of-scope host under wildcard: MUST be rejected
            {
                "name": "admin_sid",
                "value": admin_cookie,
                "domain": "admin.target.example",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            # Third-party trackers & TLD supercookie: MUST be rejected
            {
                "name": "_ga",
                "value": google_cookie,
                "domain": ".google.com",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            {
                "name": "IDE",
                "value": "SYNTH_DBLCLICK_999",
                "domain": ".doubleclick.net",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            {
                "name": "tld_bad",
                "value": "SYNTH_TLD_BAD",
                "domain": ".com",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
        ],
        "origins": [
            {
                "origin": "https://www.target.example",
                "localStorage": [
                    {"name": "csrf_token", "value": www_ls_csrf},
                    {"name": "ui_theme", "value": "dark"},
                ],
            },
            {
                "origin": "https://auth.target.example",
                "localStorage": [
                    {"name": "access_token", "value": f"Bearer {auth_ls_token}"},
                    {"name": "ui_theme", "value": "auth-should-not-override-base"},
                ],
            },
            {
                "origin": "https://admin.target.example",
                "localStorage": [
                    {"name": "access_token", "value": admin_ls_token},
                ],
            },
            {
                "origin": "https://google.com",
                "localStorage": [
                    {"name": "token", "value": "SYNTH_GOOGLE_LS_BAD"},
                ],
            },
        ],
    }

    # Single-origin default (in_scope_assets omitted) must ignore sibling origins/host cookies
    single = auth_import.load_storage_state_actor(
        state,
        base_url="https://www.target.example/",
        now=now_ts,
    )
    assert single["cookies"] == {"sso_sid": sso_cookie}
    assert single["access_token"] == ""
    assert single["csrf_token"] == www_ls_csrf

    # Multi-origin enabled with wildcard + explicit out_of_scope exclusion
    multi = auth_import.load_storage_state_actor(
        state,
        base_url="https://www.target.example/",
        alias="shopper",
        role="customer",
        now=now_ts,
        in_scope_assets=("*.target.example",),
        out_of_scope_assets=("admin.target.example",),
    )
    assert multi["authenticated"] is True
    assert multi["cookies"] == {
        "sso_sid": sso_cookie,
        "auth_session": auth_cookie,
        "bff_sticky": bff_cookie,
    }
    assert "admin_sid" not in multi["cookies"]
    assert "_ga" not in multi["cookies"]
    assert "IDE" not in multi["cookies"]
    assert multi["access_token"] == auth_ls_token
    assert multi["auth_header"] == f"Bearer {auth_ls_token}"
    assert multi["csrf_token"] == www_ls_csrf
    assert multi["local_storage"]["ui_theme"] == "dark"
    assert admin_ls_token not in json.dumps(multi)

    # Vault roundtrip preserves multi-origin scoping & never leaks secrets in summary
    state_file = tmp_path / "multi_state.json"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    vault_home = tmp_path / "vault_home"
    summary = auth_import.save_storage_state_to_vault(
        vault_home,
        "multi_shopper",
        state_file,
        alias="shopper",
        target_url="https://www.target.example/",
    )
    summary_text = json.dumps(summary)
    for secret in (sso_cookie, auth_cookie, bff_cookie, auth_ls_token, www_ls_csrf, admin_cookie):
        assert secret not in summary_text

    loaded_vault = auth_import.load_storage_state_actor_from_vault(
        vault_home,
        "multi_shopper",
        base_url="https://www.target.example/",
        now=now_ts,
        in_scope_assets=("*.target.example",),
        out_of_scope_assets=("admin.target.example",),
    )
    assert loaded_vault["cookies"] == multi["cookies"]
    assert loaded_vault["access_token"] == auth_ls_token


# ---------------------------------------------------------------------------
# 2. HAR Multi-Step Flow Extractor & Mutation Planner
# ---------------------------------------------------------------------------


def _make_ecommerce_har() -> dict[str, Any]:
    secret_auth = _synthetic_bearer("HAR_SECRET_AUTH_VAL_001")
    secret_cookie = "sid=HAR_SECRET_COOKIE_002"
    secret_api_key = "HAR_SECRET_APIKEY_003"
    secret_csrf = "HAR_SECRET_CSRF_004"
    secret_pwd = "HAR_SECRET_PASS_005"
    secret_email = "buyer.qa@target.example"
    secret_phone = "+905551112233"
    secret_card = "4111222233334444"
    secret_query_tok = "HAR_SECRET_QTOK_006"

    return {
        "log": {
            "version": "1.2",
            "entries": [
                # Static JS asset -> MUST be skipped
                {
                    "startedDateTime": "2026-11-25T10:00:00Z",
                    "request": {
                        "method": "GET",
                        "url": "https://www.target.example/static/app.bundle.js",
                        "headers": [{"name": "User-Agent", "value": "TestBrowser/1.0"}],
                    },
                    "response": {"status": 200, "content": {"mimeType": "application/javascript"}},
                },
                # Static font / image / css -> MUST be skipped
                {
                    "startedDateTime": "2026-11-25T10:00:00Z",
                    "request": {"method": "GET", "url": "https://www.target.example/assets/logo.png"},
                    "response": {"status": 200, "content": {"mimeType": "image/png"}},
                },
                {
                    "startedDateTime": "2026-11-25T10:00:00Z",
                    "request": {"method": "GET", "url": "https://www.target.example/assets/font.woff2"},
                    "response": {"status": 200, "content": {"mimeType": "font/woff2"}},
                },
                # Out-of-scope evil & excluded admin -> MUST be skipped
                {
                    "startedDateTime": "2026-11-25T10:00:01Z",
                    "request": {"method": "POST", "url": "https://evil.example/collect"},
                    "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}},
                },
                {
                    "startedDateTime": "2026-11-25T10:00:01Z",
                    "request": {"method": "GET", "url": "https://admin.target.example/api/users"},
                    "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}},
                },
                # CORS preflight OPTIONS -> MUST be skipped
                {
                    "startedDateTime": "2026-11-25T10:00:02Z",
                    "request": {"method": "OPTIONS", "url": "https://bff.target.example/api/v1/cart/items"},
                    "response": {"status": 204, "content": {"mimeType": "text/plain"}},
                },
                # Step 1: Browse product on www.target.example (compact /path)
                {
                    "startedDateTime": "2026-11-25T10:00:03Z",
                    "request": {
                        "method": "GET",
                        "url": f"https://www.target.example/api/products/101?currency=TRY&token={secret_query_tok}",
                        "headers": [
                            {"name": "Accept", "value": "application/json"},
                            {"name": "Authorization", "value": secret_auth},
                            {"name": "Cookie", "value": secret_cookie},
                            {"name": "Host", "value": "www.target.example"},
                            {"name": "Referer", "value": "https://www.target.example/"},
                        ],
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"product_id": 101, "price": 199.5}),
                        },
                    },
                },
                # Step 2: Add item to cart on bff.target.example (full sibling URL, produces cart_id)
                {
                    "startedDateTime": "2026-11-25T10:00:04Z",
                    "request": {
                        "method": "POST",
                        "url": "https://bff.target.example/api/v1/cart/items",
                        "headers": [
                            {"name": "X-Channel-Code", "value": "WEB"},
                            {"name": "X-Company-Code", "value": "ACME"},
                            {"name": "X-Platform", "value": "desktop"},
                            {"name": "Accept", "value": "application/json"},
                            {"name": "Content-Type", "value": "application/json; charset=utf-8"},
                            {"name": "Authorization", "value": secret_auth},
                            {"name": "Cookie", "value": secret_cookie},
                            {"name": "X-API-Key", "value": secret_api_key},
                            {"name": "X-Auth-Token", "value": "HAR_SECRET_XAUTH_007"},
                            {"name": "X-CSRF-Token", "value": secret_csrf},
                            {"name": "X-CSRFToken", "value": secret_csrf},
                            {"name": "X-XSRF-TOKEN", "value": secret_csrf},
                            {"name": "Host", "value": "bff.target.example"},
                            {"name": "Content-Length", "value": "64"},
                            {"name": "User-Agent", "value": "Mozilla/5.0"},
                            {"name": "Connection", "value": "keep-alive"},
                            {"name": "Referer", "value": "https://www.target.example/products/101"},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({
                                "product_id": 101,
                                "quantity": 2,
                                "userId": 42,
                                "email": secret_email,
                            }),
                        },
                    },
                    "response": {
                        "status": 201,
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"cart_id": "CART-5501", "item_id": 8801}),
                        },
                    },
                },
                # Step 3: Apply coupon (race + discount target, chains from cart_id)
                {
                    "startedDateTime": "2026-11-25T10:00:05Z",
                    "request": {
                        "method": "POST",
                        "url": "https://bff.target.example/api/v1/coupon/apply",
                        "headers": [
                            {"name": "X-Channel-Code", "value": "WEB"},
                            {"name": "X-Company-Code", "value": "ACME"},
                            {"name": "Accept", "value": "application/json"},
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Authorization", "value": secret_auth},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({
                                "cart_id": "CART-5501",
                                "coupon_code": "SAVE20",
                                "discount": 20,
                            }),
                        },
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"cart_id": "CART-5501", "discount": 20}),
                        },
                    },
                },
                # Step 4: Checkout (produces order_id, redacts password/token/phone/card)
                {
                    "startedDateTime": "2026-11-25T10:00:06Z",
                    "request": {
                        "method": "POST",
                        "url": "https://bff.target.example/api/v1/checkout",
                        "headers": [
                            {"name": "X-Channel-Code", "value": "WEB"},
                            {"name": "X-Company-Code", "value": "ACME"},
                            {"name": "Accept", "value": "application/json"},
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Set-Cookie", "value": secret_cookie},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({
                                "cart_id": "CART-5501",
                                "amount": 179.5,
                                "tenantId": "retail-tr",
                                "password": secret_pwd,
                                "token": "HAR_BODY_TOK_008",
                                "secret": "HAR_BODY_SEC_009",
                                "phone": secret_phone,
                                "card": secret_card,
                            }),
                        },
                    },
                    "response": {
                        "status": 201,
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"order_id": "ORD-9001", "status": "created"}),
                        },
                    },
                },
                # Step 5: Read order status (chained from checkout order_id in URL!)
                {
                    "startedDateTime": "2026-11-25T10:00:07Z",
                    "request": {
                        "method": "GET",
                        "url": "https://bff.target.example/api/v1/orders/ORD-9001",
                        "headers": [
                            {"name": "X-Channel-Code", "value": "WEB"},
                            {"name": "X-Company-Code", "value": "ACME"},
                            {"name": "Accept", "value": "application/json"},
                        ],
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"order_id": "ORD-9001", "status": "created", "amount": 179.5}),
                        },
                    },
                },
            ],
        }
    }


def test_extract_har_flows_scoping_redaction_chaining_and_handoff(tmp_path: Path) -> None:
    har_data = _make_ecommerce_har()
    har_path = tmp_path / "ecommerce.har"
    har_path.write_text(json.dumps(har_data), encoding="utf-8")

    flow_doc = har_flow.extract_har_flows(
        har_path,
        base_url="https://www.target.example/",
        in_scope_assets=("*.target.example",),
        out_of_scope_assets=("admin.target.example",),
    )

    assert flow_doc["schema"] == har_flow.HAR_FLOW_SCHEMA
    assert flow_doc["stats"]["entries_dropped_scope"] == 2
    assert flow_doc["stats"]["entries_dropped_static"] == 3
    assert len(flow_doc["flows"]) == 1

    flow = flow_doc["flows"][0]
    steps = flow["steps"]
    assert len(steps) == 5

    # Compact /path for base_url, full https://host/path for sibling origin
    assert steps[0]["url"] == "/api/products/101"
    assert steps[0]["query_keys"] == ["currency", "token"]
    assert steps[1]["url"] == "https://bff.target.example/api/v1/cart/items"
    assert steps[4]["url"] == "https://bff.target.example/api/v1/orders/ORD-9001"

    # Required app headers kept; all auth/CSRF/hop-by-hop headers strictly stripped
    cart_headers = steps[1]["required_app_headers"]
    assert cart_headers["X-Channel-Code"] == "WEB"
    assert cart_headers["X-Company-Code"] == "ACME"
    assert cart_headers["X-Platform"] == "desktop"
    assert cart_headers["Accept"] == "application/json"
    assert cart_headers["Content-Type"] == "application/json"
    for forbidden_hdr in (
        "Authorization",
        "Cookie",
        "Set-Cookie",
        "X-API-Key",
        "X-Auth-Token",
        "X-CSRF-Token",
        "X-CSRFToken",
        "X-XSRF-TOKEN",
        "Host",
        "Content-Length",
        "User-Agent",
        "Connection",
        "Referer",
    ):
        assert forbidden_hdr.lower() not in {k.lower() for k in cart_headers}

    assert flow_doc["recommended_app_headers"]["X-Channel-Code"] == "WEB"
    assert flow_doc["recommended_app_headers"]["X-Company-Code"] == "ACME"

    # Secrets strictly stripped/redacted from entire output and handoff
    checkout_tmpl = steps[3]["json_template"]
    assert checkout_tmpl["cart_id"] == "CART-5501"
    assert checkout_tmpl["amount"] == 179.5
    assert checkout_tmpl["password"] == "<redacted>"
    assert checkout_tmpl["token"] == "<redacted>"
    assert checkout_tmpl["secret"] == "<redacted>"
    assert checkout_tmpl["phone"] == "<redacted>"
    assert checkout_tmpl["card"] == "<redacted>"
    assert steps[1]["json_template"]["email"] == "<redacted>"
    assert steps[1]["json_template"]["quantity"] == 2

    handoff = har_flow.format_har_flows_handoff(flow_doc, max_chars=2400)
    assert len(handoff) <= 2400
    assert "X-Channel-Code=WEB" in handoff
    assert "ORD-9001" in handoff

    serialized = json.dumps(flow_doc) + "\n" + handoff
    for secret in (
        "HAR_SECRET_AUTH_VAL_001",
        "HAR_SECRET_COOKIE_002",
        "HAR_SECRET_APIKEY_003",
        "HAR_SECRET_CSRF_004",
        "HAR_SECRET_PASS_005",
        "HAR_SECRET_QTOK_006",
        "HAR_SECRET_XAUTH_007",
        "HAR_BODY_TOK_008",
        "HAR_BODY_SEC_009",
        "buyer.qa@target.example",
        "+905551112233",
        "4111222233334444",
    ):
        assert secret not in serialized

    # Chained IDs detected between steps
    assert "cart_id" in steps[1]["produced_id_fields"]
    assert steps[2]["chained_from_step"] == steps[1]["step_index"]
    assert "order_id" in steps[3]["produced_id_fields"]
    assert steps[4]["chained_from_step"] == steps[3]["step_index"]

    # Mutation targets and cases
    assert "quantity" in steps[1]["mutation_targets"]
    assert "userId" in steps[1]["mutation_targets"]
    assert "discount" in steps[2]["mutation_targets"]
    assert "coupon" in steps[2]["mutation_targets"]
    assert "checkout" in steps[3]["mutation_targets"]
    assert "amount" in steps[3]["mutation_targets"]
    assert "tenantId" in steps[3]["mutation_targets"]

    cases = har_flow.build_flow_mutation_cases(flow_doc["flows"])
    categories = {c["category"] for c in cases}
    assert "business_logic_numeric" in categories
    assert "concurrent_race" in categories
    assert "cross_actor_replay" in categories
    assert "idor_owner_tamper" in categories
    assert any(c["tool"] == "concurrent_check" and "coupon" in c["url"] for c in cases)
    assert any(c.get("json_overrides") == {"quantity": -1} for c in cases)


def test_har_role_isadmin_and_puan_aktar_mutation_targets() -> None:
    har_doc = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "PATCH",
                        "url": "https://www.target.example/api/v1/profile",
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({"role": "member", "isAdmin": False, "points": 150}),
                        },
                    },
                    "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}},
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://www.target.example/api/v1/puan-aktar",
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({"points": 50, "userId": 77}),
                        },
                    },
                    "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}},
                },
            ]
        }
    }
    doc = har_flow.extract_har_flows(har_doc, base_url="https://www.target.example/")
    steps = doc["flows"][0]["steps"]
    assert set(["role", "isAdmin", "points"]).issubset(steps[0]["mutation_targets"])
    assert "puan-aktar" in steps[1]["mutation_targets"]
    assert "points" in steps[1]["mutation_targets"]
    cases = doc["mutation_cases"]
    assert any(c["category"] == "mass_assignment" and c["target_field"] in {"role", "isAdmin"} for c in cases)
    assert any(c["category"] == "concurrent_race" and "puan-aktar" in c["url"] for c in cases)


def test_har_file_safety_and_bounds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    canary = "HAR_CANARY_SECRET_XYZ_991"
    real_har = tmp_path / "valid.har"
    real_har.write_text(json.dumps({"log": {"entries": []}}), encoding="utf-8")

    # Symlink rejection
    sym = tmp_path / "sym.har"
    sym.symlink_to(real_har)
    with pytest.raises(ValueError, match="symlink"):
        har_flow.extract_har_flows(sym, base_url="http://127.0.0.1:8080/")

    # Directory rejection
    with pytest.raises(ValueError, match="regular file"):
        har_flow.extract_har_flows(tmp_path, base_url="http://127.0.0.1:8080/")

    # Oversized rejection (> 20 MiB; patch constant for fast test execution)
    monkeypatch.setattr(har_flow, "MAX_HAR_BYTES", 256)
    big_har = tmp_path / "big.har"
    big_har.write_bytes(b" " * 300)
    with pytest.raises(ValueError, match="maximum allowed size"):
        har_flow.extract_har_flows(big_har, base_url="http://127.0.0.1:8080/")

    # Malformed JSON must not leak secret canary
    bad_har = tmp_path / "bad.har"
    bad_har.write_text(f'{{"log": {{"entries": [{{"secret": "{canary}"', encoding="utf-8")
    with pytest.raises(ValueError, match="valid JSON") as exc_info:
        har_flow.extract_har_flows(bad_har, base_url="http://127.0.0.1:8080/")
    assert canary not in str(exc_info.value)
    assert exc_info.value.__cause__ is None

    # Flow & step bounds (max 10 flows, max 12 steps per flow)
    entries = []
    for idx in range(150):
        entries.append({
            "request": {
                "method": "POST",
                "url": f"http://127.0.0.1:8080/api/v1/items/{idx}",
                "postData": {"mimeType": "application/json", "text": json.dumps({"quantity": idx + 1})},
            },
            "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}},
        })
    bounded = har_flow.extract_har_flows(
        {"log": {"entries": entries}},
        base_url="http://127.0.0.1:8080/",
    )
    assert len(bounded["flows"]) <= har_flow.MAX_HAR_FLOWS
    assert all(len(f["steps"]) <= har_flow.MAX_STEPS_PER_FLOW for f in bounded["flows"])


def test_replay_har_flow_step_against_loopback_server(tmp_path: Path) -> None:
    captured: list[dict[str, Any]] = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body_raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            with lock:
                captured.append({
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": json.loads(body_raw),
                })
            payload = json.dumps({"ok": True, "quantity": json.loads(body_raw).get("quantity")}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{port}/"
        har_doc = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": f"{base_url}api/v1/cart/items",
                            "headers": [
                                {"name": "X-Channel-Code", "value": "WEB"},
                                {"name": "X-Company-Code", "value": "ACME"},
                                {"name": "Authorization", "value": "Bearer STALE_HAR_TOKEN_SHOULD_STRIP"},
                                {"name": "Content-Type", "value": "application/json"},
                            ],
                            "postData": {
                                "mimeType": "application/json",
                                "text": json.dumps({"product_id": 101, "quantity": 2}),
                            },
                        },
                        "response": {
                            "status": 200,
                            "content": {"mimeType": "application/json", "text": json.dumps({"cart_id": "C1"})},
                        },
                    }
                ]
            }
        }
        flow_doc = har_flow.extract_har_flows(har_doc, base_url=base_url)
        step = flow_doc["flows"][0]["steps"][0]

        actors = ActorManager([
            {
                "alias": "buyer",
                "role": "member",
                "access_token": "ACTIVE_BUYER_TOKEN_123",
            }
        ])
        store = ReceiptStore(tmp_path / "receipts")
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=actors,
            allowed_methods=("GET", "POST"),
        )
        try:
            receipt = har_flow.replay_har_flow_step(
                client,
                step,
                actor="buyer",
                json_overrides={"quantity": -1},
                header_overrides={"X-Test-Probe": "logic-1"},
                force=True,
            )
        finally:
            client.close()

        assert receipt["status"] == 200
        assert len(captured) == 1
        req = captured[0]
        assert req["path"] == "/api/v1/cart/items"
        assert req["body"] == {"product_id": 101, "quantity": -1}
        assert req["headers"]["x-channel-code"] == "WEB"
        assert req["headers"]["x-company-code"] == "ACME"
        assert req["headers"]["x-test-probe"] == "logic-1"
        assert req["headers"]["authorization"] == "Bearer ACTIVE_BUYER_TOKEN_123"
        assert "STALE_HAR_TOKEN_SHOULD_STRIP" not in req["headers"]["authorization"]
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# 3. WAF-Adaptive Strategy Pivot Advisor
# ---------------------------------------------------------------------------


def test_waf_pivot_tracker_triggers_on_repeated_cloudflare_and_stays_quiet_on_app_403() -> None:
    cf_block_1 = {
        "status": 403,
        "url": "https://www.target.example/api/v1/search?q=<script>",
        "path": "/api/v1/search",
        "content_type": "text/html; charset=utf-8",
        "response_headers": {"Server": "cloudflare", "CF-Ray": "8abc111-IAD"},
        "body": "<html><title>Attention Required! | Cloudflare</title><body>Blocked</body></html>",
    }
    cf_block_2 = {
        "status": 403,
        "url": "https://www.target.example/api/v1/orders/42",
        "path": "/api/v1/orders/42",
        "content_type": "text/html; charset=utf-8",
        "response_headers": {"Server": "cloudflare", "CF-Ray": "8abc222-IAD"},
        "body": "<html><title>Attention Required! | Cloudflare</title><body>Error 1020</body></html>",
    }
    app_json_403 = {
        "status": 403,
        "url": "https://www.target.example/api/v1/admin/settings",
        "path": "/api/v1/admin/settings",
        "content_type": "application/json",
        "response_headers": {"Server": "cloudflare", "CF-Ray": "8abc333-IAD", "Content-Type": "application/json"},
        "body": json.dumps({"error": "forbidden", "detail": "insufficient_role"}),
    }

    # Ordinary app 403 behind Cloudflare MUST NOT trigger tracker
    tracker = agentic_waf.WAFPivotTracker()
    assert tracker.record_receipt(app_json_403) is None
    assert tracker.record_receipt(app_json_403) is None
    assert tracker.total_blocks == 0
    assert tracker.should_pivot() is False
    assert tracker.guidance() == ""

    # Single WAF block MUST remain quiet
    first = tracker.record_receipt(cf_block_1)
    assert first is not None and first["waf_blocked"] is True and first["vendor"] == "cloudflare"
    assert tracker.total_blocks == 1
    assert tracker.should_pivot() is False
    assert tracker.guidance() == ""
    assert agentic_waf.build_waf_pivot_guidance("cloudflare", ["/api/v1/search"], 1) == ""

    # Second WAF block crosses threshold -> actionable pivot guidance
    second = tracker.record_receipt(cf_block_2)
    assert second is not None and second["should_pivot"] is True
    assert tracker.total_blocks == 2
    assert tracker.should_pivot() is True
    assert tracker.should_pivot(vendor="cloudflare") is True

    guidance = tracker.guidance()
    assert "cloudflare" in guidance.lower()
    for expected_term in (
        "bola",
        "idor",
        "bfla",
        "mass assignment",
        "concurrent_check",
        "cors",
        "js",
    ):
        assert expected_term in guidance.lower()

    snap = tracker.summary()
    assert snap["total_blocks"] == 2
    assert snap["should_pivot"] is True
    assert snap["vendors"] == {"cloudflare": 2}
    assert "/api/v1/orders/{id}" in snap["blocked_paths"]


def test_waf_pivot_tracker_thread_safety() -> None:
    tracker = agentic_waf.WAFPivotTracker(threshold=2)
    cf_block = {
        "status": 403,
        "path": "/api/v1/items/99",
        "content_type": "text/html",
        "response_headers": {"CF-Ray": "8abc999-SJC"},
        "body": "Attention Required! | Cloudflare",
    }

    def _worker(_: int) -> bool:
        tracker.record_receipt(cf_block)
        return tracker.should_pivot()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_worker, range(24)))

    assert tracker.total_blocks == 24
    assert any(results)
    assert tracker.should_pivot() is True
    assert tracker.guidance() != ""
