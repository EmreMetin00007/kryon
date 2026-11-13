"""Client Logic Map v1 (offline, deterministic, no network)."""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "mcp-servers", "mcp-kali-tools"))

from cco_js_core.client_logic import build_client_logic_map


SOURCE = r"""
//# sourceMappingURL=app.js.map
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function signRequest(payload) {
  return CryptoJS.HmacSHA256(JSON.stringify(payload), window.__KEY__);
}
async function checkout(cartId, email) {
  const signature = signRequest({cartId, email});
  return fetch(`/api/v2/checkout/${cartId}?preview=true`, {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-Signature": signature, "Authorization": "Bearer SECRET_CANARY"},
    body: JSON.stringify({cartId, email, quantity: 1})
  });
}
const load = (id) => axios.get("/api/v2/users/" + id + "/profile");
const xhr = new XMLHttpRequest();
xhr.open("DELETE", "/api/v2/sessions/current");
xhr.setRequestHeader("X-CSRF-Token", "csrf-canary");
localStorage.setItem("tenant_id", "tenant-canary");
"""


def _endpoint(out, method, path):
    for item in out["endpoints"]:
        if item["method"] == method and item["path"] == path:
            return item
    raise AssertionError(f"endpoint not found: {method} {path}: {out['endpoints']}")


def test_fetch_endpoint_schema_body_and_signer():
    out = build_client_logic_map(SOURCE)
    assert out["schema"] == "cco-client-logic-map/1"
    ep = _endpoint(out, "POST", "/api/v2/checkout/{id}")
    assert ep["query_params"] == ["preview"]
    assert ep["body_fields"] == ["cartId", "email", "quantity"]
    assert "X-Signature" in ep["headers"]
    assert ep["function_context"] == "checkout"
    assert ep["signer_functions"] == ["signRequest"]
    assert out["source_map"]["present"] is True
    assert out["source_map"]["url"] == "app.js.map"


def test_axios_and_xhr_are_normalized():
    out = build_client_logic_map(SOURCE)
    ep = _endpoint(out, "GET", "/api/v2/users/{id}/profile")
    assert ep["source_kind"] == "axios"
    xhr = _endpoint(out, "DELETE", "/api/v2/sessions/current")
    assert xhr["source_kind"] == "xhr"
    assert "X-CSRF-Token" in xhr["headers"]


def test_sensitive_values_and_storage_values_are_not_exposed():
    out = build_client_logic_map(SOURCE)
    text = repr(out)
    assert "SECRET_CANARY" not in text
    assert "csrf-canary" not in text
    assert "tenant-canary" not in text
    assert out["storage_keys"] == ["tenant_id"]


def test_signing_and_validation_indicators_are_reported():
    out = build_client_logic_map(SOURCE)
    assert "signRequest" in out["signing"]["functions"]
    assert out["signing"]["requires_runtime"] is True
    assert any(v["field"] == "email" for v in out["validation_rules"])


def test_dynamic_and_empty_sources_fail_closed():
    dynamic = build_client_logic_map("fetch(buildUrl(id), {method: 'PUT'})")
    assert dynamic["endpoints"][0]["runtime_required"] is True
    empty = build_client_logic_map("")
    assert empty["endpoints"] == []
    assert empty["schema"] == "cco-client-logic-map/1"


def test_parser_interface_reports_static_fallback():
    out = build_client_logic_map(SOURCE, parser="static")
    assert out["parser"]["requested"] == "static"
    assert out["parser"]["used"] == "static"
    assert out["parser"]["ast_available"] is False


def test_babel_parser_when_available(monkeypatch):
    import shutil

    node_modules = os.path.join(REPO_ROOT, "legacy/opencode/client", "node_modules")
    if not shutil.which("node") or not os.path.isdir(os.path.join(node_modules, "@babel", "parser")):
        return
    monkeypatch.setenv("NODE_PATH", node_modules)
    out = build_client_logic_map(SOURCE, parser="babel")
    assert out["parser"]["used"] == "babel"
    assert out["parser"]["ast_available"] is True
    assert _endpoint(out, "POST", "/api/v2/checkout/{id}")


def test_source_map_original_sources_are_mapped_without_values():
    import json

    source_map = json.dumps({
        "version": 3,
        "sources": ["src/orders.ts"],
        "sourcesContent": [
            "export const load = (id) => fetch(`/api/v2/orders/${id}`, "
            "{headers: {Authorization: 'Bearer ORDER_SECRET'}});"
        ],
        "names": [],
        "mappings": "AAAA",
    })
    out = build_client_logic_map("fetch('/api/v2/minified')", source_map=source_map)
    assert out["source_map"]["valid"] is True
    assert out["source_map"]["sources"] == ["src/orders.ts"]
    assert out["source_map"]["mappings_decoded"] >= 1
    original = out["source_map"]["original_endpoints"]
    assert any(e["path"] == "/api/v2/orders/{id}" for e in original)
    assert "ORDER_SECRET" not in repr(out)


def test_malformed_source_map_fails_closed():
    out = build_client_logic_map("fetch('/api/v2/minified')", source_map="{not-json")
    assert out["source_map"]["valid"] is False
    assert out["source_map"]["diagnostics"]
    assert _endpoint(out, "GET", "/api/v2/minified")
