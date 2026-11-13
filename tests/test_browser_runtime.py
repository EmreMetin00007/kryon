"""Browser runtime instrumentation (offline normalization tests)."""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "mcp-servers", "mcp-browser"))

from cco_browser_core.hooks import (
    build_runtime_hook_script,
    merge_runtime_into_client_map,
    normalize_runtime_events,
)


def test_hook_script_wraps_runtime_apis_without_reading_values():
    script = build_runtime_hook_script()
    assert "window.__ccoRuntime" in script
    assert "window.fetch" in script
    assert "XMLHttpRequest.prototype.open" in script
    assert "WebSocket" in script
    assert "Object.keys(localStorage)" in script
    assert "localStorage.getItem" not in script
    assert "sessionStorage.getItem" not in script


def test_normalize_runtime_events_redacts_query_and_values():
    out = normalize_runtime_events([
        {
            "kind": "fetch",
            "method": "POST",
            "url": "https://example.test/api/checkout?token=SECRET&preview=1",
            "header_names": ["Content-Type", "X-Signature"],
            "body_fields": ["cartId", "quantity"],
            "status": 200,
            "duration_ms": 42.5,
        },
        {
            "kind": "websocket",
            "url": "wss://example.test/socket?session=SECRET",
        },
    ], {
        "storage_keys": ["tenant_id"],
        "cookie_names": ["session_id"],
        "framework_hints": {"react": True},
        "signer_candidates": ["signRequest"],
        "storage_values": {"tenant_id": "SECRET"},
    })
    assert out["schema"] == "cco-browser-runtime/1"
    assert out["requests"][0]["query_params"] == ["preview", "token"]
    assert "SECRET" not in repr(out)
    assert out["state"]["storage_keys"] == ["tenant_id"]
    assert out["state"]["cookie_names"] == ["session_id"]
    assert out["websockets"][0]["path"] == "/socket"


def test_merge_runtime_marks_observed_and_adds_new_endpoints():
    client_map = {
        "schema": "cco-client-logic-map/1",
        "endpoints": [{
            "method": "POST", "path": "/api/checkout", "source_kind": "fetch",
            "query_params": [], "body_fields": [], "headers": [],
            "signer_functions": [], "runtime_required": True,
        }],
    }
    runtime = normalize_runtime_events([
        {"kind": "fetch", "method": "POST", "url": "https://x.test/api/checkout"},
        {"kind": "xhr", "method": "GET", "url": "https://x.test/api/orders/1"},
    ])
    merged = merge_runtime_into_client_map(client_map, runtime)
    assert merged["endpoints"][0]["runtime_observed"] is True
    assert any(e["path"] == "/api/orders/{id}" for e in merged["endpoints"])


def test_browser_registers_runtime_observe_tool():
    from conftest import list_tool_names, load_server

    names = list_tool_names(load_server("browser"))
    assert "browser_runtime_observe" in names
