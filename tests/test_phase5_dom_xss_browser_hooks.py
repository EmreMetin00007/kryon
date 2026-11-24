"""Tests for Faz 5C: read-only browser DOM sink & postMessage listener telemetry."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = _REPO_ROOT / "scripts"
for _p in (str(_REPO_ROOT), str(_SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from agentic_browser import (  # noqa: E402
    HAS_PLAYWRIGHT,
    inspect_rendered_page,
    verify_dom_sink_in_browser,
)
from agentic_http import ActorManager, AgenticHTTPClient, ScopeViolationError  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import TOOL_SCHEMAS, ToolDispatcher  # noqa: E402
from kryon_core.browser.hooks import (  # noqa: E402
    build_runtime_hook_script,
    normalize_dom_sinks,
    normalize_postmessage_listeners,
)

_HASH_INNERHTML_PAGE = """<!doctype html>
<html><body>
  <div id="out"></div>
  <script>
    const raw = decodeURIComponent(window.location.hash.slice(1));
    if (raw) {
      document.getElementById("out").innerHTML = raw;
    }
  </script>
</body></html>
"""

_HASH_TEXTCONTENT_PAGE = """<!doctype html>
<html><body>
  <div id="out"></div>
  <script>
    const raw = decodeURIComponent(window.location.hash.slice(1));
    if (raw) {
      document.getElementById("out").textContent = raw;
    }
  </script>
</body></html>
"""

_PM_UNSAFE_PAGE = """<!doctype html>
<html><body>
  <div id="msg"></div>
  <script>
    window.addEventListener("message", function(evt) {
      document.getElementById("msg").innerHTML = String(evt.data || "");
    });
  </script>
</body></html>
"""

_PM_SAFE_PAGE = """<!doctype html>
<html><body>
  <div id="msg"></div>
  <script>
    window.addEventListener("message", function(evt) {
      if (evt.origin !== window.location.origin) return;
      document.getElementById("msg").textContent = String(evt.data || "");
    });
  </script>
</body></html>
"""


def _start_test_server() -> tuple[ThreadingHTTPServer, str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            pages = {
                "/hash-html": _HASH_INNERHTML_PAGE,
                "/hash-safe": _HASH_TEXTCONTENT_PAGE,
                "/pm-unsafe": _PM_UNSAFE_PAGE,
                "/pm-safe": _PM_SAFE_PAGE,
            }
            body = pages.get(path)
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


def _make_client(tmp_path: Path, base_url: str) -> AgenticHTTPClient:
    return AgenticHTTPClient(
        base_url=base_url,
        receipt_store=ReceiptStore(tmp_path),
        actors=ActorManager([]),
        max_requests=30,
    )


def test_hooks_script_and_normalizers() -> None:
    script = build_runtime_hook_script()
    assert "__kryon_dom_telemetry" in script
    assert "postmessage_listeners" in script
    assert "insertAdjacentHTML" in script
    assert "createContextualFragment" in script

    sinks = normalize_dom_sinks([
        {"sink": "innerHTML", "tag": "DIV", "snippet": "<span data-kryon-dom-canary='1'>", "source_matches": ["location.hash"]},
        {"sink": "innerHTML", "tag": "DIV", "snippet": "<span data-kryon-dom-canary='1'>", "source_matches": ["location.hash"]},
        {"sink": "", "tag": "div"},
    ])
    assert len(sinks) == 1
    assert sinks[0]["tag"] == "div"
    assert sinks[0]["source_matches"] == ["location.hash"]

    listeners = normalize_postmessage_listeners([
        {"type": "addEventListener", "has_origin_check": False, "handler_preview": "function(e){ el.innerHTML = e.data; }"},
        {"type": "addEventListener", "has_origin_check": False, "handler_preview": "function(e){ el.innerHTML = e.data; }"},
    ])
    assert len(listeners) == 1
    assert listeners[0]["has_origin_check"] is False


def test_verify_dom_sink_rejects_off_origin(tmp_path: Path) -> None:
    http = _make_client(tmp_path, "http://127.0.0.1:18080")
    with pytest.raises(ScopeViolationError):
        verify_dom_sink_in_browser(http, url="http://127.0.0.1:19999/other", source="hash")


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright not installed")
def test_browser_dom_sink_hash_and_postmessage_live(tmp_path: Path) -> None:
    server, base_url = _start_test_server()
    try:
        http = _make_client(tmp_path, base_url)

        # 1. Vulnerable hash -> innerHTML
        res_vuln = verify_dom_sink_in_browser(http, url="/hash-html", source="hash")
        assert res_vuln["ok"] is True
        assert res_vuln["verified_dom_injection"] is True
        assert res_vuln["dom_element_parsed"] is True
        assert any(s["sink"] == "innerHTML" for s in res_vuln["matched_sinks"])

        # 2. Safe hash -> textContent
        res_safe = verify_dom_sink_in_browser(http, url="/hash-safe", source="hash")
        assert res_safe["ok"] is True
        assert res_safe["verified_dom_injection"] is False
        assert res_safe["dom_element_parsed"] is False

        # 3. Vulnerable postMessage listener (no origin check + innerHTML)
        res_pm_vuln = verify_dom_sink_in_browser(http, url="/pm-unsafe", source="postmessage")
        assert res_pm_vuln["ok"] is True
        assert res_pm_vuln["verified_dom_injection"] is True
        assert res_pm_vuln["dom_element_parsed"] is True
        assert any(not ln["has_origin_check"] for ln in res_pm_vuln["postmessage_listeners"])
        assert any("postmessage" in s["source_matches"] for s in res_pm_vuln["matched_sinks"])

        # 4. Safe postMessage listener (origin check + textContent)
        res_pm_safe = verify_dom_sink_in_browser(http, url="/pm-safe", source="postmessage")
        assert res_pm_safe["ok"] is True
        assert res_pm_safe["verified_dom_injection"] is False
        assert any(ln["has_origin_check"] for ln in res_pm_safe["postmessage_listeners"])

        # 5. inspect_rendered_page returns dom_sinks & postmessage_listeners fields
        inspected = inspect_rendered_page(http, url="/pm-unsafe")
        assert inspected["ok"] is True
        assert isinstance(inspected["dom_sinks"], list)
        assert len(inspected["postmessage_listeners"]) >= 1
        assert inspected["postmessage_listeners"][0]["has_origin_check"] is False
    finally:
        server.shutdown()
        server.server_close()


def _unwrap_untrusted(raw: str) -> dict[str, Any]:
    prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw.startswith(prefix)
    assert raw.rstrip().endswith(suffix.strip())
    body = raw[len(prefix) :].rsplit(suffix, 1)[0]
    parsed = json.loads(body)
    assert isinstance(parsed, dict)
    return parsed


def test_browser_crawl_schema_exposes_dom_verify_and_preserves_11_tools() -> None:
    assert len(TOOL_SCHEMAS) == 11
    browser_tool = next(
        t["function"] for t in TOOL_SCHEMAS if t["function"]["name"] == "browser_crawl"
    )
    props = browser_tool["parameters"]["properties"]
    assert props["mode"]["enum"] == ["crawl", "inspect", "dom_verify"]
    assert props["source"]["enum"] == ["hash", "query", "postmessage"]
    assert props["param_name"]["type"] == "string"


def test_tool_dispatcher_browser_crawl_dom_verify_fails_closed(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    http = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080",
        receipt_store=store,
        actors=ActorManager([]),
        max_requests=20,
    )
    dispatcher = ToolDispatcher(http_client=http, receipt_store=store, root_dir=tmp_path)
    try:
        # Invalid source returns a clean error dict wrapped as untrusted target response.
        bad_src_raw = dispatcher.dispatch(
            "browser_crawl",
            {"mode": "dom_verify", "url": "/hash-html", "source": "invalid_source"},
        )
        bad_src = _unwrap_untrusted(bad_src_raw)
        assert bad_src["ok"] is False
        assert bad_src["verified_dom_injection"] is False
        assert "Unsupported DOM verification source" in bad_src["error"]

        # Off-origin URL fails closed with ScopeViolationError via dispatch().
        off_origin_raw = dispatcher.dispatch(
            "browser_crawl",
            {"mode": "dom_verify", "url": "http://127.0.0.1:19999/other", "source": "hash"},
        )
        off_origin = json.loads(off_origin_raw)
        assert off_origin["error"] == "ScopeViolationError"

        proto_rel_raw = dispatcher.dispatch(
            "browser_crawl",
            {"mode": "dom_verify", "url": "//evil.example/hash-html", "source": "hash"},
        )
        proto_rel = json.loads(proto_rel_raw)
        assert proto_rel["error"] == "ScopeViolationError"
    finally:
        dispatcher.close()
        http.close()


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright not installed")
def test_tool_dispatcher_browser_crawl_dom_verify_live(tmp_path: Path) -> None:
    server, base_url = _start_test_server()
    store = ReceiptStore(tmp_path / "receipts")
    http = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=ActorManager([]),
        max_requests=30,
    )
    dispatcher = ToolDispatcher(http_client=http, receipt_store=store, root_dir=tmp_path)
    try:
        # 1. Vulnerable hash -> innerHTML via ToolDispatcher
        vuln_hash = _unwrap_untrusted(
            dispatcher.dispatch(
                "browser_crawl",
                {"mode": "dom_verify", "url": "/hash-html", "source": "hash"},
            )
        )
        assert vuln_hash["ok"] is True
        assert vuln_hash["verified_dom_injection"] is True
        assert vuln_hash["dom_element_parsed"] is True
        assert any(s["sink"] == "innerHTML" for s in vuln_hash["matched_sinks"])

        # 2. Safe hash -> textContent via ToolDispatcher
        safe_hash = _unwrap_untrusted(
            dispatcher.dispatch(
                "browser_crawl",
                {"mode": "dom_verify", "url": "/hash-safe", "source": "hash"},
            )
        )
        assert safe_hash["ok"] is True
        assert safe_hash["verified_dom_injection"] is False
        assert safe_hash["dom_element_parsed"] is False

        # 3. Vulnerable postMessage listener via ToolDispatcher
        vuln_pm = _unwrap_untrusted(
            dispatcher.dispatch(
                "browser_crawl",
                {"mode": "dom_verify", "url": "/pm-unsafe", "source": "postmessage"},
            )
        )
        assert vuln_pm["ok"] is True
        assert vuln_pm["verified_dom_injection"] is True
        assert vuln_pm["dom_element_parsed"] is True
        assert any(not ln["has_origin_check"] for ln in vuln_pm["postmessage_listeners"])
    finally:
        dispatcher.close()
        http.close()
        server.shutdown()
        server.server_close()
