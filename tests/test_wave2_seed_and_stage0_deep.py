"""Wave 2 deep tests for offline seed formats (agentic_seed) and deep Stage 0 SPA/multi-origin discovery."""
from __future__ import annotations

import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
import threading
from types import SimpleNamespace
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_stage0_crawl as stage0_mod  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_seed import (  # noqa: E402
    _extract_safe_app_headers,
    load_seed_surface_files,
    merge_seed_surfaces,
)
from agentic_stage0_crawl import (  # noqa: E402
    _MAX_JS_CHUNK_BYTES,
    _Stage0Budget,
    _Stage0Collector,
    _crawl_actor_playwright,
    _extract_lazy_spa_routes_and_chunks,
    _extract_openapi_templates,
    _extract_sourcemap_references,
    _fetch_cdn_sourcemap_anonymously,
    _finalize_routes,
    _ingest_openapi_spec,
    _is_allowed_cdn_sourcemap_url,
    _run_layer4_passive_fusion,
    _sanitize_observed_app_headers,
)
from target_bootstrap import ScopeGuard  # noqa: E402

BASE_URL = "https://www.target.example/"


def _all_entries(seed_data: dict[str, Any]) -> list[dict[str, Any]]:
    return [*seed_data["links"], *seed_data["forms"]]


def _by_key(seed_data: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(item["method"], item["url"]): item for item in _all_entries(seed_data)}


def _make_client(
    tmp_path: Path,
    *,
    base_url: str = BASE_URL,
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST"),
    max_requests: int = 120,
    excluded_paths: tuple[str, ...] = (),
    in_scope_assets: tuple[str, ...] = (),
    out_of_scope_assets: tuple[str, ...] = (),
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
        excluded_paths=excluded_paths,
        in_scope_assets=in_scope_assets,
        out_of_scope_assets=out_of_scope_assets,
    )


@contextmanager
def _start_test_server(
    router: Callable[[str, str, dict[str, str], bytes], tuple[int, str, bytes | str, dict[str, str]]],
) -> Iterator[tuple[str, int, list[dict[str, Any]]]]:
    requests_log: list[dict[str, Any]] = []
    log_lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            with log_lock:
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

        def do_POST(self) -> None:
            self._handle()

        def log_message(self, _fmt: str, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/", port, requests_log
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


# ---------------------------------------------------------------------------
# 1. agentic_seed: Burp XML (+ XXE rejection & secret header stripping)
# ---------------------------------------------------------------------------


def test_seed_burp_xml_base64_and_raw_extracts_templates_and_strips_secrets(tmp_path: Path) -> None:
    secret_bearer = "Bearer " + "burp_tok_" + "99887766554433221100"
    secret_cookie = "sid=burp_cookie_secret_xyz"
    secret_csrf = "burp_csrf_nonce_554433"
    secret_api_key = "burp_apikey_val_112233"
    secret_pw = "BurpUltraSecretPass!99"

    raw_json_req = (
        "POST /api/v1/checkout?currency=USD&promo=SUMMER HTTP/1.1\r\n"
        "Host: www.target.example\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "X-Storefront: web-global\r\n"
        "X-Api-Version: 2026-01\r\n"
        "X-Apollo-Operation-Name: CreateCheckout\r\n"
        f"Authorization: {secret_bearer}\r\n"
        f"Cookie: {secret_cookie}\r\n"
        f"X-CSRF-Token: {secret_csrf}\r\n"
        f"X-API-Key: {secret_api_key}\r\n"
        "\r\n"
        + json.dumps({"cart_id": "cart-12", "qty": 2, "password": secret_pw})
    )
    b64_req = base64.b64encode(raw_json_req.encode("utf-8")).decode("ascii")

    raw_form_req = (
        "POST /profile/update HTTP/1.1\n"
        "Host: www.target.example\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "X-Requested-With: XMLHttpRequest\n"
        f"Cookie: {secret_cookie}\n"
        "\n"
        f"display_name=Alice&csrf_token={secret_csrf}"
    )

    offscope_req = base64.b64encode(
        (
            "GET /leak HTTP/1.1\r\n"
            "Host: evil.other.example\r\n"
            "X-Storefront: evil-storefront\r\n"
            "X-Offscope-Header: leak-me\r\n\r\n"
        ).encode("utf-8")
    ).decode("ascii")

    burp_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<items burpVersion="2025.1">
  <item>
    <url>https://www.target.example/api/v1/checkout?currency=USD</url>
    <method>POST</method>
    <status>200</status>
    <request base64="true">{b64_req}</request>
  </item>
  <item>
    <url>https://www.target.example/profile/update</url>
    <method>POST</method>
    <status>302</status>
    <request base64="false"><![CDATA[{raw_form_req}]]></request>
  </item>
  <item>
    <url>https://evil.other.example/leak</url>
    <method>GET</method>
    <status>200</status>
    <request base64="true">{offscope_req}</request>
  </item>
</items>
"""
    xml_file = tmp_path / "burp-export.xml"
    xml_file.write_text(burp_xml, encoding="utf-8")

    result = load_seed_surface_files([xml_file], base_url=BASE_URL)
    serialized = json.dumps(result)

    for forbidden in (
        secret_bearer,
        "burp_tok_99887766554433221100",
        secret_cookie,
        "burp_cookie_secret_xyz",
        secret_csrf,
        secret_api_key,
        secret_pw,
        "Authorization",
        "X-CSRF-Token",
        "X-API-Key",
        "evil-storefront",
        "X-Offscope-Header",
    ):
        assert forbidden not in serialized

    assert result["stats"]["formats_detected"] == ["burp_xml"]
    assert result["stats"]["routes_dropped_scope"] == 1
    assert result["stats"]["routes_accepted"] == 2

    entries = _by_key(result)
    assert ("POST", "/api/v1/checkout") in entries
    assert set(entries[("POST", "/api/v1/checkout")]["params"]) >= {"currency", "promo", "cart_id", "qty", "password"}
    bt = entries[("POST", "/api/v1/checkout")]["body_template"]
    assert bt["cart_id"] == "cart-12"
    assert bt["qty"] == 2
    assert bt["password"] == "<redacted>"

    assert ("POST", "/profile/update") in entries
    assert entries[("POST", "/profile/update")]["body_template"]["csrf_token"] == "<redacted>"
    assert set(entries[("POST", "/profile/update")]["params"]) == {"csrf_token", "display_name"}

    app_hdrs = result["app_headers"]
    assert app_hdrs["X-Storefront"] == "web-global"
    assert app_hdrs["X-Api-Version"] == "2026-01"
    assert app_hdrs["X-Apollo-Operation-Name"] == "CreateCheckout"
    assert app_hdrs["X-Requested-With"] == "XMLHttpRequest"
    assert app_hdrs["Content-Type"] in {"application/json", "application/x-www-form-urlencoded"}


@pytest.mark.parametrize(
    "xxe_payload",
    [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><items><item><url>https://www.target.example/</url></item></items>',
        '<!DOCTYPE items SYSTEM "http://127.0.0.1:9/evil.dtd"><items></items>',
        '<?xml version="1.0"?><!ENTITY xxe "boom"><items></items>',
    ],
)
def test_seed_burp_xml_rejects_doctype_and_entity_fail_closed(tmp_path: Path, xxe_payload: str) -> None:
    xxe_file = tmp_path / "xxe.xml"
    xxe_file.write_text(xxe_payload, encoding="utf-8")
    with pytest.raises(ValueError, match="DOCTYPE|ENTITY"):
        load_seed_surface_files([xxe_file], base_url=BASE_URL)


# ---------------------------------------------------------------------------
# 2. agentic_seed: OpenAPI 3 YAML & Swagger 2 JSON with sibling servers
# ---------------------------------------------------------------------------


def test_seed_openapi3_yaml_and_swagger2_json_preserve_sibling_servers_and_templates(tmp_path: Path) -> None:
    openapi_yaml = """
openapi: 3.0.3
info:
  title: Sibling Commerce API
  version: "1.0"
servers:
  - url: https://api.target.example/v2
  - url: https://evil.untrusted.example/v2
paths:
  /orders/{orderId}:
    parameters:
      - name: orderId
        in: path
        required: true
        schema:
          type: string
    get:
      parameters:
        - name: expand
          in: query
          schema:
            type: string
  /orders:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateOrder'
  /documents:
    post:
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                title:
                  type: string
                attachment:
                  type: string
                  format: binary
components:
  schemas:
    CreateOrder:
      type: object
      properties:
        sku:
          type: string
          example: SKU-42
        quantity:
          type: integer
          minimum: 1
        secret_pin:
          type: string
          example: topsecret_pin_value
"""
    swagger2_json = {
        "swagger": "2.0",
        "info": {"title": "Legacy BFF", "version": "1.0"},
        "host": "bff.target.example",
        "basePath": "/bff",
        "schemes": ["https"],
        "paths": {
            "/invoices/{invoiceId}": {
                "post": {
                    "parameters": [
                        {"name": "invoiceId", "in": "path", "required": True, "type": "string"},
                        {"name": "dry_run", "in": "query", "type": "boolean"},
                        {
                            "name": "payload",
                            "in": "body",
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "note": {"type": "string", "default": "ok"},
                                    "api_key": {"type": "string", "example": "raw_swagger_secret_key"},
                                },
                            },
                        },
                    ]
                }
            }
        },
    }

    oa_file = tmp_path / "openapi.yaml"
    oa_file.write_text(openapi_yaml, encoding="utf-8")
    sw_file = tmp_path / "swagger2.json"
    sw_file.write_text(json.dumps(swagger2_json), encoding="utf-8")

    result = load_seed_surface_files(
        [oa_file, sw_file],
        base_url=BASE_URL,
        in_scope_assets=("*.target.example",),
    )
    serialized = json.dumps(result)
    assert "topsecret_pin_value" not in serialized
    assert "raw_swagger_secret_key" not in serialized
    assert "evil.untrusted.example" not in serialized

    assert result["stats"]["formats_detected"] == ["openapi"]
    assert result["stats"]["routes_dropped_scope"] == 3

    entries = _by_key(result)
    assert ("GET", "https://api.target.example/v2/orders/{orderId}") in entries
    assert set(entries[("GET", "https://api.target.example/v2/orders/{orderId}")]["params"]) == {"expand", "orderId"}

    assert ("POST", "https://api.target.example/v2/orders") in entries
    order_bt = entries[("POST", "https://api.target.example/v2/orders")]["body_template"]
    assert order_bt["sku"] == "SKU-42"
    assert order_bt["quantity"] == 1
    assert order_bt["secret_pin"] == "<redacted>"

    assert ("POST", "https://api.target.example/v2/documents") in entries
    doc_mp = entries[("POST", "https://api.target.example/v2/documents")]["multipart_schema"]
    assert doc_mp == {"fields": ["title"], "files": ["attachment"]}

    assert ("POST", "https://bff.target.example/bff/invoices/{invoiceId}") in entries
    inv_entry = entries[("POST", "https://bff.target.example/bff/invoices/{invoiceId}")]
    assert set(inv_entry["params"]) >= {"invoiceId", "dry_run", "note", "api_key"}
    assert inv_entry["body_template"]["note"] == "ok"
    assert inv_entry["body_template"]["api_key"] == "<redacted>"


def test_seed_openapi_yaml_graceful_fallback_when_pyyaml_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oa_file = tmp_path / "spec.yaml"
    oa_file.write_text("openapi: 3.0.0\npaths:\n  /ping:\n    get: {}\n", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "yaml", None)
    result = load_seed_surface_files([oa_file], base_url=BASE_URL)
    assert result["stats"]["formats_detected"] == ["openapi"]
    assert result["links"] == []


# ---------------------------------------------------------------------------
# 3. agentic_seed: Postman Collection v2.1 nested folders + {{baseUrl}}
# ---------------------------------------------------------------------------


def test_seed_postman_v21_nested_folders_variables_templates_and_headers(tmp_path: Path) -> None:
    secret_bearer = "Bearer " + "pm_secret_" + "1234567890abcdef1234"
    secret_var_tok = "pm_var_token_hidden_999"

    collection = {
        "info": {
            "_postman_id": "11111111-2222-3333-4444-555555555555",
            "name": "Target App API",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [
            {"key": "apiHost", "value": "https://api.target.example"},
            {"key": "apiToken", "value": secret_var_tok},
        ],
        "item": [
            {
                "name": "Billing",
                "item": [
                    {
                        "name": "Create Payment",
                        "request": {
                            "method": "POST",
                            "header": [
                                {"key": "Authorization", "value": secret_bearer},
                                {"key": "X-CSRF-Token", "value": "pm_csrf_999"},
                                {"key": "X-Storefront", "value": "mobile-ios"},
                                {"key": "Content-Type", "value": "application/json"},
                            ],
                            "url": {
                                "raw": "{{apiHost}}/v1/payments/{{paymentId}}?mode=live",
                                "query": [
                                    {"key": "mode", "value": "live"},
                                    {"key": "locale", "value": "en"},
                                    {"key": "disabled_q", "value": "1", "disabled": True},
                                ],
                            },
                            "body": {
                                "mode": "raw",
                                "raw": json.dumps({"amount": 99, "currency": "EUR", "card_cvv": "999"}),
                                "options": {"raw": {"language": "json"}},
                            },
                        },
                    },
                    {
                        "name": "Unresolved Base Fallback",
                        "request": {
                            "method": "GET",
                            "header": [{"key": "X-Api-Version", "value": "3"}],
                            "url": "{{baseUrl}}/account/settings?tab=security",
                        },
                    },
                    {
                        "name": "Upload Receipt",
                        "request": {
                            "method": "POST",
                            "url": "{{baseUrl}}/account/receipts",
                            "body": {
                                "mode": "formdata",
                                "formdata": [
                                    {"key": "memo", "value": "lunch", "type": "text"},
                                    {"key": "receipt_file", "type": "file", "src": "/tmp/a.pdf"},
                                ],
                            },
                        },
                    },
                ],
            }
        ],
    }

    pm_file = tmp_path / "collection.postman_collection.json"
    pm_file.write_text(json.dumps(collection), encoding="utf-8")

    result = load_seed_surface_files(
        [pm_file],
        base_url=BASE_URL,
        in_scope_assets=("*.target.example",),
    )
    serialized = json.dumps(result)
    for forbidden in (secret_bearer, secret_var_tok, "pm_csrf_999", "Authorization", "X-CSRF-Token", "disabled_q"):
        assert forbidden not in serialized

    assert result["stats"]["formats_detected"] == ["postman"]
    entries = _by_key(result)
    assert ("POST", "https://api.target.example/v1/payments/{paymentId}") in entries
    pay_entry = entries[("POST", "https://api.target.example/v1/payments/{paymentId}")]
    assert set(pay_entry["params"]) >= {"mode", "locale", "amount", "currency", "card_cvv"}
    assert pay_entry["body_template"]["amount"] == 99
    assert pay_entry["body_template"]["card_cvv"] == "<redacted>"

    assert ("GET", "/account/settings") in entries
    assert entries[("GET", "/account/settings")]["params"] == ["tab"]

    assert ("POST", "/account/receipts") in entries
    assert entries[("POST", "/account/receipts")]["multipart_schema"] == {
        "fields": ["memo"],
        "files": ["receipt_file"],
    }

    assert result["app_headers"]["X-Storefront"] == "mobile-ios"
    assert result["app_headers"]["X-Api-Version"] == "3"


# ---------------------------------------------------------------------------
# 4. agentic_seed: cURL commands + merge_seed_surfaces app_headers
# ---------------------------------------------------------------------------


def test_seed_curl_commands_extract_methods_headers_bodies_multipart_and_strip_secrets(tmp_path: Path) -> None:
    secret_bearer = "Bearer " + "curl_tok_" + "abcdef0123456789abcd"
    secret_cookie = "session=curl_cookie_val_777"
    secret_basic_auth = "admin:curl_basic_pass_888"

    curl_script = f"""#!/bin/bash
# Captured API requests
curl -X POST 'https://www.target.example/graphql?env=prod' \\
  -H 'Content-Type: application/json' \\
  -H 'X-Apollo-Operation-Name: GetOrders' \\
  -H 'X-Requested-With: XMLHttpRequest' \\
  -H 'Authorization: {secret_bearer}' \\
  -H 'X-CSRF-Token: curl_csrf_secret' \\
  -b '{secret_cookie}' \\
  -u '{secret_basic_auth}' \\
  --data-raw '{{"operationName":"GetOrders","variables":{{"limit":10,"token":"raw_gql_tok"}}}}'

curl 'https://www.target.example/api/v1/avatar' \\
  -F 'caption=my pic' \\
  -F 'avatar=@/tmp/pic.png'

curl --data-urlencode 'note=hello' --data-urlencode 'secret_answer=my_secret_ans' 'https://www.target.example/api/v1/support'

# Malformed quote line should be skipped safely without crashing
curl 'https://www.target.example/unterminated
"""
    curl_file = tmp_path / "requests.sh"
    curl_file.write_text(curl_script, encoding="utf-8")

    result = load_seed_surface_files([curl_file], base_url=BASE_URL)
    serialized = json.dumps(result)
    for forbidden in (
        secret_bearer,
        secret_cookie,
        secret_basic_auth,
        "curl_csrf_secret",
        "raw_gql_tok",
        "my_secret_ans",
        "Authorization",
        "X-CSRF-Token",
    ):
        assert forbidden not in serialized

    assert result["stats"]["formats_detected"] == ["curl"]
    entries = _by_key(result)
    assert ("POST", "/graphql") in entries
    gql_bt = entries[("POST", "/graphql")]["body_template"]
    assert gql_bt["operationName"] == "GetOrders"
    assert gql_bt["variables"]["token"] == "<redacted>"

    assert ("POST", "/api/v1/avatar") in entries
    assert entries[("POST", "/api/v1/avatar")]["multipart_schema"] == {
        "fields": ["caption"],
        "files": ["avatar"],
    }

    assert ("POST", "/api/v1/support") in entries
    assert set(entries[("POST", "/api/v1/support")]["params"]) == {"note", "secret_answer"}
    assert entries[("POST", "/api/v1/support")]["body_template"]["secret_answer"] == "<redacted>"

    assert result["app_headers"]["X-Apollo-Operation-Name"] == "GetOrders"
    assert result["app_headers"]["X-Requested-With"] == "XMLHttpRequest"

    # merge_seed_surfaces carries app_headers and observed_app_headers while stripping secrets
    merged = merge_seed_surfaces(
        [
            result,
            {
                "schema": "stage0-seed/1",
                "links": [{"method": "GET", "url": "/dashboard", "params": []}],
                "observed_app_headers": {
                    "X-Tenant-Id": "tenant-alpha",
                    "Authorization": secret_bearer,
                    "X-CSRF-Token": "must-drop",
                },
            },
        ],
        base_url=BASE_URL,
    )
    assert merged is not None
    assert merged["app_headers"]["X-Tenant-Id"] == "tenant-alpha"
    assert merged["app_headers"]["X-Apollo-Operation-Name"] == "GetOrders"
    assert "Authorization" not in merged["app_headers"]
    assert "X-CSRF-Token" not in merged["app_headers"]


# ---------------------------------------------------------------------------
# 5. agentic_stage0_crawl: 1 MiB JS chunk cap & inline base64 .js.map decoding
# ---------------------------------------------------------------------------


def test_stage0_js_chunk_cap_is_1mib_and_inline_sourcemap_recovers_hidden_routes(tmp_path: Path) -> None:
    assert _MAX_JS_CHUNK_BYTES == 1024 * 1024

    original_ts_source = """
export async function impersonateUser(uid) {
  return fetch("/api/v2/admin/impersonate", {
    method: "POST",
    body: JSON.stringify({ userId: uid })
  });
}
export async function loadLedger() {
  return fetch("/api/v2/internal/ledger?limit=50");
}
"""
    sourcemap_obj = {
        "version": 3,
        "file": "app.bundle.js",
        "sources": ["webpack:///src/admin/impersonate.ts"],
        "sourcesContent": [original_ts_source],
        "names": [],
        "mappings": "AAAA",
    }
    b64_map = base64.b64encode(json.dumps(sourcemap_obj).encode("utf-8")).decode("ascii")

    # Build a >350 KiB minified bundle so we also verify >256 KiB content is NOT truncated
    padding = "/*pad*/" * 55000
    bundle_js = (
        f"console.log('boot');\n{padding}\n"
        'const lateRoute = "/api/v2/after-300kb";\n'
        f"//# sourceMappingURL=data:application/json;charset=utf-8;base64,{b64_map}\n"
    )
    assert len(bundle_js.encode("utf-8")) > 350_000

    refs = _extract_sourcemap_references(bundle_js, "https://www.target.example/static/app.bundle.js")
    assert len(refs["inline"]) == 1
    assert refs["inline"][0].startswith("data:application/json;base64,")
    assert refs["external"] == []

    ext_refs = _extract_sourcemap_references(
        "console.log(1);\n//# sourceMappingURL=chunks/app.js.map\n",
        "https://www.target.example/static/app.js",
    )
    assert ext_refs["external"] == ["https://www.target.example/static/chunks/app.js.map"]

    assert _is_allowed_cdn_sourcemap_url("https://cdn.shop.example/assets/app.js.map", BASE_URL) is True
    assert _is_allowed_cdn_sourcemap_url("http://169.254.169.254/latest.js.map", BASE_URL) is False
    assert _is_allowed_cdn_sourcemap_url("https://www.googletagmanager.com/gtag.js.map", BASE_URL) is False

    http = _make_client(tmp_path, base_url=BASE_URL)
    collector = _Stage0Collector(http)
    budget = _Stage0Budget(http, cap=10, reserve=2)
    collector.record_document(
        url="https://www.target.example/static/app.bundle.js",
        content_type="application/javascript",
        body=bundle_js,
        headers={},
        is_js=True,
    )

    used_before = http.budget.used
    _run_layer4_passive_fusion(http, collector, budget, primary_actor="anon", max_passive_probes=0)
    links, forms, _bt, _mp, _hints = _finalize_routes(collector)
    http.close()

    # Zero network requests spent decoding inline source map
    assert http.budget.used == used_before
    assert collector.source_maps_parsed == 1

    pairs = {(r["method"], r["url"]) for r in [*links, *forms]}
    assert ("POST", "/api/v2/admin/impersonate") in pairs
    assert ("GET", "/api/v2/internal/ledger") in pairs


# ---------------------------------------------------------------------------
# 6. agentic_stage0_crawl: Lazy SPA route & chunk manifest extraction
# ---------------------------------------------------------------------------


def test_stage0_lazy_spa_nextjs_vite_webpack_extraction(tmp_path: Path) -> None:
    next_html = """<!doctype html>
<html>
<head>
  <link rel="modulepreload" href="/assets/admin-panel.9f8e7d.js" />
  <link rel="preload" as="script" href="/assets/billing-chunk.1234ab.mjs" />
</head>
<body>
  <script id="__NEXT_DATA__" type="application/json">
    {"page": "/dashboard/orders/[orderId]", "buildId": "build-2026-xyz"}
  </script>
</body>
</html>"""

    build_manifest_js = """
self.__BUILD_MANIFEST = {
  "/admin/users": ["static/chunks/pages/admin-users-aaa111.js"],
  "/settings/billing": ["static/chunks/pages/billing-bbb222.js"],
  sortedPages: ["/", "/_app", "/_error", "/admin/users", "/settings/billing", "/account/[tenantId]/api-keys"]
};
const lazyMap = {
  a: "/assets/checkout-flow.deadbeef.js",
  b: "/assets/graphql-client.cafebabe.js",
  c: "/assets/harmless-icons.11223344.js"
};
"""

    html_info = _extract_lazy_spa_routes_and_chunks(
        next_html,
        doc_url="https://www.target.example/",
        base_url=BASE_URL,
    )
    assert "/dashboard/orders/{orderId}" in html_info["routes"]
    assert "/_next/static/build-2026-xyz/_buildManifest.js" in html_info["manifests"]
    assert "/assets/admin-panel.9f8e7d.js" in html_info["chunks"]
    assert "/assets/billing-chunk.1234ab.mjs" in html_info["chunks"]

    js_info = _extract_lazy_spa_routes_and_chunks(
        build_manifest_js,
        doc_url="https://www.target.example/_next/static/build-2026-xyz/_buildManifest.js",
        base_url=BASE_URL,
    )
    assert "/admin/users" in js_info["routes"]
    assert "/settings/billing" in js_info["routes"]
    assert "/account/{tenantId}/api-keys" in js_info["routes"]
    assert "/_app" not in js_info["routes"]
    assert "/_error" not in js_info["routes"]
    assert "/assets/checkout-flow.deadbeef.js" in js_info["chunks"]
    assert "/assets/graphql-client.cafebabe.js" in js_info["chunks"]
    assert "/assets/harmless-icons.11223344.js" not in js_info["chunks"]

    # Wired end-to-end in Layer 4
    http = _make_client(tmp_path, base_url=BASE_URL)
    collector = _Stage0Collector(http)
    budget = _Stage0Budget(http, cap=10, reserve=2)
    collector.record_document(
        url="https://www.target.example/",
        content_type="text/html",
        body=next_html,
        headers={},
        is_js=False,
    )
    collector.record_document(
        url="https://www.target.example/_next/static/build-2026-xyz/_buildManifest.js",
        content_type="application/javascript",
        body=build_manifest_js,
        headers={},
        is_js=True,
    )
    _run_layer4_passive_fusion(http, collector, budget, primary_actor="anon", max_passive_probes=0)
    links, _forms, _bt, _mp, _hints = _finalize_routes(collector)
    http.close()

    link_urls = {r["url"] for r in links}
    assert "/dashboard/orders/{orderId}" in link_urls
    assert "/admin/users" in link_urls
    assert "/settings/billing" in link_urls
    assert "/account/{tenantId}/api-keys" in link_urls
    assert collector.lazy_chunks_discovered >= 5


# ---------------------------------------------------------------------------
# 7. agentic_stage0_crawl: Multi-origin non-collision, OpenAPI servers, cookies/LS & XHR app headers
# ---------------------------------------------------------------------------


def test_stage0_multi_origin_caches_openapi_servers_and_xhr_app_headers(tmp_path: Path) -> None:
    guard = ScopeGuard(BASE_URL, in_scope_assets=("*.target.example",))

    # OpenAPI 3 servers + Swagger 2 host+basePath honored in _extract_openapi_templates
    oa3_spec = {
        "openapi": "3.0.3",
        "servers": [{"url": "https://api.target.example/v2"}],
        "paths": {
            "/widgets": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"name": {"type": "string"}},
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    templates, _mp, ops = _extract_openapi_templates(
        oa3_spec,
        base_url=BASE_URL,
        scope_guard=guard,
    )
    assert ("POST", "https://api.target.example/v2/widgets") in templates
    assert any(m == "POST" and p == "https://api.target.example/v2/widgets" for m, p, _ in ops)

    sw2_spec = {
        "swagger": "2.0",
        "host": "bff.target.example",
        "basePath": "/bff",
        "schemes": ["https"],
        "paths": {"/health": {"get": {}}},
    }
    _sw_t, _sw_mp, sw_ops = _extract_openapi_templates(
        sw2_spec,
        base_url=BASE_URL,
        scope_guard=guard,
    )
    assert any(m == "GET" and p == "https://bff.target.example/bff/health" for m, p, _ in sw_ops)

    # Multi-origin captured_html, captured_css, captured_specs non-collision
    http = _make_client(
        tmp_path,
        base_url=BASE_URL,
        in_scope_assets=("*.target.example",),
        accounts=[
            {
                "alias": "alice",
                "role": "member",
                "cookie": "sid=primary_cookie_secret_111",
                "cookie_records": [
                    {"name": "sid", "value": "primary_cookie_secret_111", "domain": "www.target.example", "path": "/"},
                    {"name": "api_sid", "value": "sibling_cookie_secret_222", "domain": "api.target.example", "path": "/"},
                ],
                "local_storage_by_origin": {
                    "https://www.target.example": {"ui_theme": "dark"},
                    "https://api.target.example": {"api_tok": "sibling_ls_secret_333"},
                },
            }
        ],
    )
    collector = _Stage0Collector(http)
    collector.record_document(
        url="https://www.target.example/index.html",
        content_type="text/html",
        body="<html><body>Primary</body></html>",
        headers={},
        is_js=False,
    )
    collector.record_document(
        url="https://api.target.example/index.html",
        content_type="text/html",
        body="<html><body>API Docs</body></html>",
        headers={},
        is_js=False,
    )
    collector.record_document(
        url="https://www.target.example/app.css",
        content_type="text/css",
        body="body { color: #000; }",
        headers={},
        is_js=False,
        is_css=True,
    )
    collector.record_document(
        url="https://api.target.example/app.css",
        content_type="text/css",
        body="body { color: #fff; }",
        headers={},
        is_js=False,
        is_css=True,
    )
    assert "/index.html" in collector.captured_html
    assert "https://api.target.example/index.html" in collector.captured_html
    assert len(collector.captured_html) == 2
    assert "/app.css" in collector.captured_css
    assert "https://api.target.example/app.css" in collector.captured_css
    assert len(collector.captured_css) == 2

    # Ingest OpenAPI specs from sibling origin preserves sibling URLs
    _ingest_openapi_spec(http, collector, oa3_spec, spec_url="https://api.target.example/openapi.json")
    links, _forms, _bt, _mp, _hints = _finalize_routes(collector)
    assert any(r["method"] == "POST" and r["url"] == "https://api.target.example/v2/widgets" for r in links)

    # Simulated Playwright crawl checks multi-origin cookies, localStorage, captured_specs non-collision, and XHR app headers
    added_init_scripts: list[str] = []
    added_cookies: list[dict[str, Any]] = []

    class _FakePage:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}
            self.url = BASE_URL

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

        def goto(self, url: str, **_kwargs: Any) -> None:
            self.url = url
            req_handler = self.handlers["request"]
            resp_handler = self.handlers["response"]
            req_handler(
                SimpleNamespace(
                    url="https://api.target.example/v2/cart",
                    method="POST",
                    resource_type="fetch",
                    headers={
                        "content-type": "application/json",
                        "x-storefront": "tr-web",
                        "x-api-version": "2.4",
                        "x-requested-with": "XMLHttpRequest",
                        "x-apollo-operation-name": "LoadCart",
                        "x-tenant-id": "tenant-7",
                        "authorization": "Bearer " + "xhr_secret_" + "1234567890abcdef",
                        "cookie": "sid=primary_cookie_secret_111",
                        "x-csrf-token": "xhr_csrf_999",
                        "x-api-key": "xhr_apikey_999",
                    },
                    post_data=json.dumps({"item": "book"}),
                    post_data_buffer=None,
                )
            )
            for sp_url in ("https://www.target.example/openapi.json", "https://api.target.example/openapi.json"):
                resp_handler(
                    SimpleNamespace(
                        url=sp_url,
                        status=200,
                        request=SimpleNamespace(method="GET", resource_type="fetch"),
                        headers={"content-type": "application/json"},
                        body=lambda: json.dumps(oa3_spec).encode("utf-8"),
                    )
                )

        def wait_for_timeout(self, _ms: int) -> None:
            return

        def evaluate(self, _script: str, *_args: Any) -> dict[str, Any]:
            return {
                "pathname": "/",
                "hash": "",
                "dialog_count": 0,
                "headings": [{"tag": "h1", "text": "Home"}],
                "forms": [],
                "standalone_files": [],
                "controls": [],
                "links": [],
                "canonical_links": [],
                "hash_routes": [],
                "visible_links": [],
                "base_uri": BASE_URL,
            }

    class _FakeContext:
        def __init__(self) -> None:
            self.page = _FakePage()

        def add_init_script(self, script: str) -> None:
            added_init_scripts.append(script)

        def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
            added_cookies.extend(cookies)

        def route(self, _pattern: str, _handler: Any) -> None:
            return

        def new_page(self) -> _FakePage:
            return self.page

        def close(self) -> None:
            return

    class _FakeBrowser:
        def new_context(self, **_kwargs: Any) -> _FakeContext:
            return _FakeContext()

    budget = _Stage0Budget(http, cap=20, reserve=4)
    secrets = _crawl_actor_playwright(
        http,
        collector,
        budget,
        browser=_FakeBrowser(),
        actor="alice",
        start_urls=[BASE_URL],
        forms_enabled=False,
        actor_page_limit=1,
        actor_action_limit=0,
        timeout_ms=2000,
        wait_ms=0,
    )
    http.close()

    # Multi-origin cookies & localStorage seeded and secrets collected
    cookie_domains = {c.get("domain") for c in added_cookies}
    assert "www.target.example" in cookie_domains
    assert "api.target.example" in cookie_domains
    assert added_init_scripts and "https://api.target.example" in added_init_scripts[0]
    assert "sibling_cookie_secret_222" in secrets
    assert "sibling_ls_secret_333" in secrets

    # captured_specs kept BOTH primary and sibling /openapi.json without collision
    assert "/openapi.json" in collector.captured_specs
    assert "https://api.target.example/openapi.json" in collector.captured_specs

    # Observed XHR app headers preserved safe headers and stripped ALL secret/auth/CSRF headers
    obs = collector.observed_app_headers
    assert obs["X-Storefront"] == "tr-web"
    assert obs["X-Api-Version"] == "2.4"
    assert obs["X-Requested-With"] == "XMLHttpRequest"
    assert obs["X-Apollo-Operation-Name"] == "LoadCart"
    assert obs["X-Tenant-Id"] == "tenant-7"
    low_obs = {k.lower() for k in obs}
    for forbidden in ("authorization", "cookie", "x-csrf-token", "x-api-key"):
        assert forbidden not in low_obs


# ---------------------------------------------------------------------------
# 8. agentic_stage0_crawl: Layer 4 sibling-origin OpenAPI & GraphQL passive probes (2-port loopback)
# ---------------------------------------------------------------------------


def test_stage0_layer4_sibling_origin_openapi_and_graphql_probes_two_port_loopback(tmp_path: Path) -> None:
    def primary_router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/robots.txt":
            return 200, "text/plain", "User-agent: *\nAllow: /\n", {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    def sibling_api_router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/openapi.json":
            spec = {
                "openapi": "3.0.3",
                "info": {"title": "Sibling API", "version": "1.0"},
                "paths": {
                    "/v1/accounts/{accountId}": {
                        "get": {"parameters": [{"name": "include_roles", "in": "query", "schema": {"type": "boolean"}}]}
                    },
                    "/v1/transfers": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "to": {"type": "string"},
                                                "amount": {"type": "integer"},
                                            },
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            }
            return 200, "application/json", json.dumps(spec), {}
        if path == "/graphql":
            return 400, "application/json", json.dumps({"errors": [{"message": "GraphQL query string missing"}]}), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    def unauth_router(_method: str, _raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        return 200, "application/json", json.dumps({"secret": "must_never_be_probed"}), {}

    with (
        _start_test_server(primary_router) as (primary_url, _p1, _primary_log),
        _start_test_server(sibling_api_router) as (sib_url, sib_port, sib_log),
        _start_test_server(unauth_router) as (unauth_url, _p3, unauth_log),
    ):
        sib_origin = sib_url.rstrip("/")
        unauth_origin = unauth_url.rstrip("/")

        http = _make_client(
            tmp_path,
            base_url=primary_url,
            in_scope_assets=(sib_url,),
            allowed_methods=("GET", "HEAD", "POST"),
            max_requests=50,
        )
        collector = _Stage0Collector(http)
        budget = _Stage0Budget(http, cap=30, reserve=10)

        # Simulate HTML/JS discovery of BOTH an in-scope sibling API and an out-of-scope host
        collector.record_external_api_observation(f"{sib_origin}/v1/cart", method="GET")
        collector.record_external_api_observation(f"{unauth_origin}/v1/leak", method="GET")

        _run_layer4_passive_fusion(
            http,
            collector,
            budget,
            primary_actor="anon",
            max_passive_probes=20,
            start_paths=[primary_url],
        )
        links, forms, body_templates, _mp, _hints = _finalize_routes(collector)
        http.close()

        # Unauthorized port received ZERO wire requests
        assert unauth_log == []

        # Authorized sibling API port received /openapi.json and /graphql probes (and skipped redundant swagger/v3 after openapi hit)
        sib_paths_hit = [urlsplit(req["path"]).path for req in sib_log]
        assert "/openapi.json" in sib_paths_hit
        assert "/graphql" in sib_paths_hit
        assert f"{sib_origin}/openapi.json" in collector.probed_paths
        assert f"{sib_origin}/graphql" in collector.probed_paths

        # Ingested sibling OpenAPI operations and GraphQL endpoint preserve full sibling origin
        pairs = {(r["method"], r["url"]) for r in [*links, *forms]}
        assert ("GET", f"http://127.0.0.1:{sib_port}/v1/accounts/{{accountId}}") in pairs
        assert ("POST", f"http://127.0.0.1:{sib_port}/v1/transfers") in pairs
        assert ("POST", f"http://127.0.0.1:{sib_port}/graphql") in pairs
        assert f"POST http://127.0.0.1:{sib_port}/v1/transfers" in body_templates


def test_stage0_layer4_external_sourcemap_fetch_bounded_and_recovers_routes(tmp_path: Path) -> None:
    route_names = ("alpha", "beta", "gamma", "delta", "epsilon", "zeta")

    def _make_map(route_path: str) -> str:
        return json.dumps({
            "version": 3,
            "file": "bundle.js",
            "sources": ["src/routes.ts"],
            "sourcesContent": [f'export const callApi = () => fetch("{route_path}", {{method: "POST"}});'],
            "names": [],
            "mappings": "AAAA",
        })

    def router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        for idx, name in enumerate(route_names):
            if path == f"/static/chunk-{idx}.js.map":
                return 200, "application/json", _make_map(f"/api/v3/{name}"), {}
        return 404, "text/plain", "missing", {}

    with _start_test_server(router) as (base_url, _port, req_log):
        http = _make_client(tmp_path, base_url=base_url, allowed_methods=("GET", "HEAD", "POST"), max_requests=40)
        collector = _Stage0Collector(http)
        budget = _Stage0Budget(http, cap=25, reserve=10)
        for idx in range(len(route_names)):
            collector.record_document(
                url=f"{base_url.rstrip('/')}/static/chunk-{idx}.js",
                content_type="application/javascript",
                body=f"console.log({idx});\n//# sourceMappingURL=chunk-{idx}.js.map\n",
                headers={},
                is_js=True,
            )

        _run_layer4_passive_fusion(http, collector, budget, primary_actor="anon", max_passive_probes=6)
        links, forms, _bt, _mp, _hints = _finalize_routes(collector)
        http.close()

        map_hits = [urlsplit(r["path"]).path for r in req_log if urlsplit(r["path"]).path.endswith(".js.map")]
        assert len(map_hits) == 4
        assert collector.source_maps_parsed == 4
        pairs = {(r["method"], r["url"]) for r in [*links, *forms]}
        assert ("POST", "/api/v3/alpha") in pairs
        assert ("POST", "/api/v3/delta") in pairs
        assert ("POST", "/api/v3/epsilon") not in pairs


# ---------------------------------------------------------------------------
# 9. Wave 2 Review Fixes: B1, B2#4, B4, S5, S6, and NITs
# ---------------------------------------------------------------------------


def test_b1_cdn_sourcemap_ssrf_scope_dns_referrer_and_session_hardening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = ScopeGuard(
        BASE_URL,
        excluded_paths=("/private/*",),
        out_of_scope_assets=("cdn.blocked.example", "https://cdn.shop.example/secret-maps/*"),
    )

    # 1. Explicit out_of_scope_assets and excluded_paths are ALWAYS rejected.
    assert _is_allowed_cdn_sourcemap_url(
        "https://cdn.blocked.example/assets/app.js.map",
        BASE_URL,
        referrer_url="https://cdn.blocked.example/assets/app.js",
        scope_guard=guard,
    ) is False
    assert _is_allowed_cdn_sourcemap_url(
        "https://cdn.shop.example/secret-maps/app.js.map",
        BASE_URL,
        referrer_url="https://cdn.shop.example/assets/app.js",
        scope_guard=guard,
    ) is False
    assert _is_allowed_cdn_sourcemap_url(
        "https://cdn.shop.example/private/app.js.map",
        BASE_URL,
        referrer_url="https://cdn.shop.example/assets/app.js",
        scope_guard=guard,
    ) is False

    # 2. Loopback/private/link-local/CGNAT/multicast/unspecified ALWAYS rejected EVEN on loopback targets!
    loopback_base = "http://127.0.0.1:8080/"
    for bad_map_url in (
        "http://127.0.0.1:9200/x.map",
        "http://localhost:9200/x.map",
        "http://[::1]:9200/x.map",
        "http://10.0.0.5/app.js.map",
        "http://172.16.0.9/app.js.map",
        "http://192.168.1.50/app.js.map",
        "http://169.254.169.254/latest.js.map",
        "http://100.64.1.2/app.js.map",
        "http://224.0.0.1/app.js.map",
        "http://0.0.0.0/app.js.map",
        "http://[fd00::1]/app.js.map",
        "http://[::ffff:127.0.0.1]:9200/app.js.map",
    ):
        assert _is_allowed_cdn_sourcemap_url(bad_map_url, loopback_base) is False, bad_map_url

    # 3. Referrer exact same-origin lock rejects cross-origin CDN .js.map.
    assert _is_allowed_cdn_sourcemap_url(
        "https://other-cdn.example/assets/app.js.map",
        BASE_URL,
        referrer_url="https://cdn.shop.example/assets/app.js",
        resolve_dns=False,
    ) is False
    assert _is_allowed_cdn_sourcemap_url(
        "https://cdn.shop.example:8443/assets/app.js.map",
        BASE_URL,
        referrer_url="https://cdn.shop.example/assets/app.js",
        resolve_dns=False,
    ) is False

    # 4. DNS rebinding resolving to IMDS 169.254.169.254 (or loopback/private) is rejected.
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _h, p, *_a, **_kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", p))],
    )
    assert _is_allowed_cdn_sourcemap_url(
        "https://cdn.shop.example/assets/app.js.map",
        BASE_URL,
        referrer_url="https://cdn.shop.example/assets/app.js",
    ) is False

    # 5. Session hardening (trust_env=False, verify=True, allow_redirects=False), same-origin redirect check,
    #    and budget + rate-limiter pacing.
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _h, p, *_a, **_kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))],
    )

    session_events: list[dict[str, Any]] = []

    class _FakeResp:
        def __init__(self, status_code: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
            self.status_code = status_code
            self._body = body
            self.headers = headers or {}
            self.closed = False

        def iter_content(self, chunk_size: int = 16384) -> Iterator[bytes]:
            yield self._body

        def close(self) -> None:
            self.closed = True

    class _FakeSession:
        def __init__(self) -> None:
            self.trust_env = True
            self.closed = False

        def get(self, url: str, **kwargs: Any) -> _FakeResp:
            session_events.append({
                "url": url,
                "trust_env": self.trust_env,
                "verify": kwargs.get("verify"),
                "allow_redirects": kwargs.get("allow_redirects"),
            })
            if url.endswith("/redirect-cross.js.map"):
                return _FakeResp(302, headers={"Location": "https://evil.other.example/pwn.js.map"})
            if url.endswith("/redirect-same.js.map"):
                return _FakeResp(302, headers={"Location": "/assets/final.js.map"})
            return _FakeResp(200, body=b'{"version":3,"sources":[],"mappings":""}')

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(stage0_mod, "_requests", SimpleNamespace(Session=_FakeSession))

    http = _make_client(
        tmp_path,
        base_url=BASE_URL,
        out_of_scope_assets=("cdn.blocked.example",),
        max_requests=20,
    )
    pace_calls: list[int] = []
    monkeypatch.setattr(http, "_acquire_rate_limit_slot", lambda **_kw: pace_calls.append(1))
    budget = _Stage0Budget(http, cap=10, reserve=4)

    # Cross-origin redirect hop is blocked before making a 2nd request.
    blocked_res = _fetch_cdn_sourcemap_anonymously(
        http,
        "https://cdn.shop.example/assets/redirect-cross.js.map",
        referrer_url="https://cdn.shop.example/assets/app.js",
        stage0_budget=budget,
    )
    assert blocked_res == ""
    assert len(session_events) == 1
    assert session_events[0]["trust_env"] is False
    assert session_events[0]["verify"] is True
    assert session_events[0]["allow_redirects"] is False

    # Same-origin redirect hop succeeds, consumes budget, and invokes rate limiter.
    session_events.clear()
    used_before = http.budget.used
    ok_res = _fetch_cdn_sourcemap_anonymously(
        http,
        "https://cdn.shop.example/assets/redirect-same.js.map",
        referrer_url="https://cdn.shop.example/assets/app.js",
        stage0_budget=budget,
    )
    assert '"version":3' in ok_res
    assert len(session_events) == 2
    assert all(ev["trust_env"] is False and ev["verify"] is True and ev["allow_redirects"] is False for ev in session_events)
    assert http.budget.used == used_before + 2
    assert len(pace_calls) == 3

    # End-to-end Layer 4 rejects out-of-scope CDN .js.map and cross-origin referrer .js.map without touching CDN session.
    session_events.clear()
    monkeypatch.setattr(
        http,
        "request",
        lambda **_kw: {"status": 404, "url": BASE_URL, "body": "", "content_type": "text/plain", "redirect_location": ""},
    )
    collector = _Stage0Collector(http)
    collector.record_document(
        url="https://cdn.blocked.example/assets/app.js",
        content_type="application/javascript",
        body="console.log(1);\n//# sourceMappingURL=app.js.map\n",
        headers={},
        is_js=True,
    )
    collector.record_document(
        url="https://www.target.example/static/app.js",
        content_type="application/javascript",
        body="console.log(2);\n//# sourceMappingURL=https://cdn.shop.example/other.js.map\n",
        headers={},
        is_js=True,
    )
    _run_layer4_passive_fusion(http, collector, budget, primary_actor="anon", max_passive_probes=4)
    assert session_events == []
    http.close()


def test_b2_observed_and_seed_headers_strip_lowercase_secret_names_and_values() -> None:
    raw_headers = {
        "x-storefront": "web-eu",
        "x-api-version": "2026-04",
        "x-tenant-id": "tenant-42",
        # Lowercase Playwright secret header names (no separators/camelCase)
        "x-customauth": "opaque-val",
        "x-userjwt": "opaque-val",
        "x-reqsignature": "deadbeef",
        "x-hmacsig": "deadbeef",
        "x-amz-access-key": "opaque-val",
        "x-amz-date": "20260401T000000Z",
        "x-mybearer": "opaque-val",
        "x-usercredential": "opaque-val",
        "x-usersession": "opaque-val",
        "x-mycsrf": "opaque-val",
        "x-myxsrf": "opaque-val",
        "x-privateflag": "opaque-val",
        "x-mysecret": "opaque-val",
        "x-mytoken": "opaque-val",
        "x-mykey": "opaque-val",
        "x-userpass": "opaque-val",
        "x-mycookie": "opaque-val",
        # Clean header names carrying secret/PII values
        "x-val-token": "Token abcdef123456",
        "x-val-digest": 'Digest username="alice"',
        "x-val-aws4": "AWS4-HMAC-SHA256 Credential=abc/20260401",
        "x-val-akia": "AKIAIOSFODNN7EXAMPLE",
        "x-val-asia": "ASIAIOSFODNN7EXAMPLE",
        "x-val-ghp": "ghp_1234567890abcdef",
        "x-val-stripe": "sk_live_9876543210abcdef",
        "x-val-slack": "xoxb-123456-abcdef",
        "x-val-gcp": "AIzaSyD-1234567890abcdef",
        "x-val-pem": "-----BEGIN PRIVATE KEY-----abc",
        "x-val-email": "alice@corp.example",
        "x-val-cookie": "sid=abc123; path=/",
    }

    obs_clean = _sanitize_observed_app_headers(raw_headers)
    assert obs_clean == {
        "X-Storefront": "web-eu",
        "X-Api-Version": "2026-04",
        "X-Tenant-Id": "tenant-42",
    }

    seed_clean = _extract_safe_app_headers(raw_headers)
    assert seed_clean == {
        "X-Storefront": "web-eu",
        "X-Api-Version": "2026-04",
        "X-Tenant-Id": "tenant-42",
    }


def test_b4_inline_base64_sourcemap_with_plus_and_urlsafe_decodes_cleanly(tmp_path: Path) -> None:
    # Construct payloads guaranteed to contain '+' (standard b64) and '-' / '_' without '=' padding (URL-safe b64).
    plus_src = 'export const runA = () => fetch("/api/v2/plus-route?a=>>>&b=>>>", {method: "POST"}); // >>>???>>>'
    plus_map = {
        "version": 3,
        "file": "plus.js",
        "sources": ["src/plus.ts"],
        "sourcesContent": [plus_src],
        "names": [],
        "mappings": "AAAA",
    }
    b64_plus = base64.b64encode(json.dumps(plus_map).encode("utf-8")).decode("ascii")
    assert "+" in b64_plus

    urlsafe_src = 'export const runB = () => fetch("/api/v2/urlsafe-route?a=>>>&b=???", {method: "POST"}); // >>>???'
    urlsafe_map = {
        "version": 3,
        "file": "urlsafe.js",
        "sources": ["src/urlsafe.ts"],
        "sourcesContent": [urlsafe_src],
        "names": [],
        "mappings": "AAAA",
    }
    b64_urlsafe = base64.urlsafe_b64encode(json.dumps(urlsafe_map).encode("utf-8")).decode("ascii").rstrip("=")
    assert "-" in b64_urlsafe and "_" in b64_urlsafe

    js_plus = f"console.log('a');\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,{b64_plus}\n"
    js_urlsafe = (
        f"console.log('b');\n"
        f"//# sourceMappingURL=data:application/json;base64,{b64_urlsafe}\n"
        "//# sourceMappingURL=concat.js+bad.map\n"
    )

    refs_plus = _extract_sourcemap_references(js_plus, "https://www.target.example/static/plus.js")
    assert len(refs_plus["inline"]) == 1
    assert refs_plus["external"] == []

    refs_urlsafe = _extract_sourcemap_references(js_urlsafe, "https://www.target.example/static/urlsafe.js")
    assert len(refs_urlsafe["inline"]) == 1
    assert refs_urlsafe["external"] == []  # JS '+' concat external ref still rejected

    http = _make_client(tmp_path, base_url=BASE_URL)
    collector = _Stage0Collector(http)
    budget = _Stage0Budget(http, cap=10, reserve=2)
    collector.record_document(
        url="https://www.target.example/static/plus.js",
        content_type="application/javascript",
        body=js_plus,
        headers={},
        is_js=True,
    )
    collector.record_document(
        url="https://www.target.example/static/urlsafe.js",
        content_type="application/javascript",
        body=js_urlsafe,
        headers={},
        is_js=True,
    )
    _run_layer4_passive_fusion(http, collector, budget, primary_actor="anon", max_passive_probes=0)
    links, forms, _bt, _mp, _hints = _finalize_routes(collector)
    http.close()

    assert collector.source_maps_parsed == 2
    pairs = {(r["method"], r["url"]) for r in [*links, *forms]}
    assert ("POST", "/api/v2/plus-route") in pairs
    assert ("POST", "/api/v2/urlsafe-route") in pairs


def test_s5_graphql_html_catchall_not_fp_and_sibling_api_probe_reservation(tmp_path: Path) -> None:
    def primary_spa_router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/graphql":
            return (
                200,
                "text/html; charset=utf-8",
                '<!DOCTYPE html><html><body><div id="root">SPA GraphQL catch-all</div></body></html>',
                {},
            )
        return 404, "text/html", "<html><body>Not Found</body></html>", {}

    def sibling_api_router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/openapi.json":
            spec = {
                "openapi": "3.0.3",
                "info": {"title": "Reserved Sibling API", "version": "1.0"},
                "paths": {"/v1/orders": {"get": {}}},
            }
            return 200, "application/json", json.dumps(spec), {}
        if path == "/graphql":
            return 200, "application/json", json.dumps({"data": {"__schema": {"types": []}}}), {}
        return 404, "application/json", json.dumps({"error": "missing"}), {}

    with (
        _start_test_server(primary_spa_router) as (primary_url, _p1, primary_log),
        _start_test_server(sibling_api_router) as (sib_url, sib_port, sib_log),
    ):
        sib_origin = sib_url.rstrip("/")
        # Tight max_passive_probes=8: primary storefront alone would try >10 probes (4 root + 3 api + 3 manifest + tech)
        # Without sibling reservation, sibling origin would receive 0 probes!
        http = _make_client(
            tmp_path,
            base_url=primary_url,
            in_scope_assets=(sib_url,),
            allowed_methods=("GET", "HEAD", "POST"),
            max_requests=40,
        )
        collector = _Stage0Collector(http)
        budget = _Stage0Budget(http, cap=20, reserve=8)
        # Also include /graphql in discovered_spec_urls on primary so primary hits the HTML catch-all directly!
        collector.discovered_spec_urls.append("/graphql")
        collector.record_external_api_observation(f"{sib_origin}/v1/items", method="GET")

        _run_layer4_passive_fusion(
            http,
            collector,
            budget,
            primary_actor="anon",
            max_passive_probes=8,
            start_paths=[primary_url],
        )
        links, forms, _bt, _mp, _hints = _finalize_routes(collector)
        http.close()

        # Primary hit /graphql (200 text/html SPA catch-all), but it must NOT be recorded as POST /graphql!
        assert any(urlsplit(r["path"]).path == "/graphql" for r in primary_log)
        pairs = {(r["method"], r["url"]) for r in [*links, *forms]}
        assert ("POST", "/graphql") not in pairs

        # Sibling API origin received its reserved probe slots despite primary missing OpenAPI!
        sib_paths_hit = [urlsplit(r["path"]).path for r in sib_log]
        assert "/openapi.json" in sib_paths_hit
        assert "/graphql" in sib_paths_hit
        assert ("GET", f"http://127.0.0.1:{sib_port}/v1/orders") in pairs
        assert ("POST", f"http://127.0.0.1:{sib_port}/graphql") in pairs


def test_s5_sibling_origin_sorting_prioritizes_api_hints_and_skips_static_cdn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = _make_client(
        tmp_path,
        base_url=BASE_URL,
        in_scope_assets=("*.target.example",),
        allowed_methods=("GET", "HEAD", "POST"),
        max_requests=40,
    )
    probed_urls: list[str] = []

    def _fake_request(*, actor: str, method: str, url: str, **_kw: Any) -> dict[str, Any]:
        probed_urls.append(url)
        return {"status": 404, "url": url, "body": "", "content_type": "text/plain", "redirect_location": ""}

    monkeypatch.setattr(http, "request", _fake_request)
    collector = _Stage0Collector(http)
    budget = _Stage0Budget(http, cap=20, reserve=8)

    # Record static CDN and blog BEFORE api & bff to ensure sorting & CDN filtering work regardless of discovery order.
    collector.record_external_api_observation("https://cdn.target.example/v1/assets", method="GET")
    collector.record_external_api_observation("https://static.target.example/v1/files", method="GET")
    collector.record_external_api_observation("https://blog.target.example/v1/posts", method="GET")
    collector.record_external_api_observation("https://api.target.example/v1/users", method="GET")
    collector.record_external_api_observation("https://bff.target.example/v1/cart", method="GET")

    _run_layer4_passive_fusion(
        http,
        collector,
        budget,
        primary_actor="anon",
        max_passive_probes=18,
        start_paths=[BASE_URL],
    )
    http.close()

    assert not any(u.startswith("https://cdn.target.example") for u in probed_urls)
    assert not any(u.startswith("https://static.target.example") for u in probed_urls)
    assert any(u.startswith("https://api.target.example") for u in probed_urls)
    assert any(u.startswith("https://bff.target.example") for u in probed_urls)
    assert not any(u.startswith("https://blog.target.example") for u in probed_urls)


def test_s6_yaml_alias_bomb_rejected_and_burp_html_response_doctype_accepted(tmp_path: Path) -> None:
    # 1. YAML billion-laughs alias bomb (<1 KiB) is rejected immediately without memory/CPU exhaustion.
    bomb_yaml = """openapi: 3.0.3
info:
  title: Bomb
  version: "1.0"
paths: {}
x-a: &a ["lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol"]
x-b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]
x-c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]
x-d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]
x-e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]
x-f: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e]
x-g: &g [*f, *f, *f, *f, *f, *f, *f, *f, *f]
x-h: &h [*g, *g, *g, *g, *g, *g, *g, *g, *g]
x-i: &i [*h, *h, *h, *h, *h, *h, *h, *h, *h]
"""
    assert len(bomb_yaml.encode("utf-8")) < 1024
    bomb_file = tmp_path / "bomb.yaml"
    bomb_file.write_text(bomb_yaml, encoding="utf-8")
    with pytest.raises(ValueError, match="YAML alias/node limit exceeded"):
        load_seed_surface_files([bomb_file], base_url=BASE_URL)

    # 2. Burp XML with base64="false" HTML <!DOCTYPE html> inside <response> (CDATA and non-CDATA) parses cleanly.
    burp_with_html_resp = """<?xml version="1.0" encoding="UTF-8"?>
<items burpVersion="2025.1">
  <item>
    <url>https://www.target.example/account/overview</url>
    <method>GET</method>
    <status>200</status>
    <request base64="false"><![CDATA[GET /account/overview HTTP/1.1
Host: www.target.example
X-Storefront: web-global

]]></request>
    <response base64="false"><![CDATA[HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html><body><h1>Overview</h1></body></html>]]></response>
  </item>
  <item>
    <url>https://www.target.example/account/orders</url>
    <method>GET</method>
    <status>200</status>
    <response base64="false">HTTP/1.1 200 OK

<!DOCTYPE html><html><body>Orders</body></html></response>
  </item>
</items>
"""
    ok_burp = tmp_path / "burp-html-resp.xml"
    ok_burp.write_text(burp_with_html_resp, encoding="utf-8")
    res = load_seed_surface_files([ok_burp], base_url=BASE_URL)
    entries = _by_key(res)
    assert ("GET", "/account/overview") in entries
    assert ("GET", "/account/orders") in entries
    assert res["app_headers"]["X-Storefront"] == "web-global"

    # 3. Prolog DOCTYPE, comment-smuggled prolog DOCTYPE, ENTITY inside <response>, and DOCTYPE in <request> all rejected.
    for malicious_xml in (
        '<?xml version="1.0"?><!-- <response> --><!DOCTYPE items SYSTEM "http://127.0.0.1/evil.dtd"><!-- </response> --><items></items>',
        '<?xml version="1.0"?><items><item><url>https://www.target.example/x</url><response base64="false"><![CDATA[<!ENTITY xxe "pwn">]]></response></item></items>',
        '<?xml version="1.0"?><items><item><url>https://www.target.example/x</url><request base64="false"><![CDATA[<!DOCTYPE foo SYSTEM "http://127.0.0.1/a.dtd">]]></request></item></items>',
    ):
        bad_file = tmp_path / "bad-burp.xml"
        bad_file.write_text(malicious_xml, encoding="utf-8")
        with pytest.raises(ValueError, match="DOCTYPE|ENTITY"):
            load_seed_surface_files([bad_file], base_url=BASE_URL)


def test_nits_optional_catchall_non_next_static_chunk_and_signed_sourcemap_query(tmp_path: Path) -> None:
    # 1. Optional catch-all /shop/[[...slug]] -> /shop/{slug}
    next_manifest = """
self.__BUILD_MANIFEST = {
  "/shop/[[...slug]]": ["static/chunks/pages/shop-slug-aaa.js"],
  sortedPages: ["/shop/[[...slug]]", "/docs/[...parts]"]
};
"""
    next_info = _extract_lazy_spa_routes_and_chunks(
        next_manifest,
        doc_url="https://www.target.example/_next/static/b1/_buildManifest.js",
        base_url=BASE_URL,
    )
    assert "/shop/{slug}" in next_info["routes"]
    assert "/docs/{parts}" in next_info["routes"]
    assert "/_next/static/chunks/pages/shop-slug-aaa.js" in next_info["chunks"]

    # 2. Generic Django/CRA/Webpack static/ chunk is NOT rewritten to /_next/static/
    generic_webpack = 'const adminChunk = "static/js/admin-dashboard.chunk.js";'
    gen_info = _extract_lazy_spa_routes_and_chunks(
        generic_webpack,
        doc_url="https://www.target.example/",
        base_url=BASE_URL,
    )
    assert "https://www.target.example/static/js/admin-dashboard.chunk.js" in gen_info["chunks"]
    assert not any("/_next/" in c for c in gen_info["chunks"])

    # 3. Signed query params on in-scope .js.map are preserved during Layer 4 fetch!
    smap_payload = json.dumps({
        "version": 3,
        "file": "signed.js",
        "sources": ["src/signed.ts"],
        "sourcesContent": ['export const f = () => fetch("/api/v2/signed-recovered", {method: "POST"});'],
        "names": [],
        "mappings": "AAAA",
    })

    def signed_router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if raw_path == "/static/signed.js.map?sig=abc123&exp=9999":
            return 200, "application/json", smap_payload, {}
        return 403, "text/plain", "signature required", {}

    with _start_test_server(signed_router) as (base_url, _port, req_log):
        http = _make_client(tmp_path, base_url=base_url, allowed_methods=("GET", "HEAD", "POST"), max_requests=20)
        collector = _Stage0Collector(http)
        budget = _Stage0Budget(http, cap=12, reserve=4)
        collector.record_document(
            url=f"{base_url.rstrip('/')}/static/signed.js",
            content_type="application/javascript",
            body="console.log(1);\n//# sourceMappingURL=signed.js.map?sig=abc123&exp=9999\n",
            headers={},
            is_js=True,
        )
        _run_layer4_passive_fusion(http, collector, budget, primary_actor="anon", max_passive_probes=4)
        links, forms, _bt, _mp, _hints = _finalize_routes(collector)
        http.close()

        assert any(r["path"] == "/static/signed.js.map?sig=abc123&exp=9999" for r in req_log)
        assert collector.source_maps_parsed == 1
        assert ("POST", "/api/v2/signed-recovered") in {(r["method"], r["url"]) for r in [*links, *forms]}


