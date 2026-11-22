"""Tests for OOB bridge binding, same-origin localStorage auth/browser wiring, prompts, and tool dispatcher."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_auth_import as auth_import  # noqa: E402
import agentic_browser  # noqa: E402
from agentic_browser import (  # noqa: E402
    HAS_PLAYWRIGHT,
    _build_origin_localstorage_init_script,
    _collect_actor_secrets,
    _extract_actor_local_storage,
    inspect_rendered_page,
    run_browser_crawl,
)
from agentic_context import build_system_prompt, build_worker_system_prompt  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_oob import LoopbackCallbackServer  # noqa: E402
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_surface import SurfaceFrontierTracker  # noqa: E402
from agentic_tools import TOOL_SCHEMAS, ToolDispatcher  # noqa: E402


def _unwrap_tool_payload(raw: str) -> dict[str, Any]:
    prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw.startswith(prefix)
    assert raw.rstrip().endswith(suffix.strip())
    body = raw[len(prefix) :].rsplit(suffix, 1)[0]
    return json.loads(body)


def _start_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[str, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", srv


def _stop_server(srv: ThreadingHTTPServer) -> None:
    srv.shutdown()
    srv.server_close()


def _make_client(
    tmp_path: Path,
    *,
    base_url: str = "http://127.0.0.1:18080",
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
    max_requests: int = 40,
) -> tuple[ReceiptStore, ActorManager, AgenticHTTPClient, SurfaceFrontierTracker]:
    store = ReceiptStore(tmp_path / "store")
    actors = ActorManager(accounts or [])
    http = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
    )
    tracker = SurfaceFrontierTracker(
        base_url=base_url,
        allowed_methods=allowed_methods,
        actor_summaries=actors.summaries(),
    )
    return store, actors, http, tracker


# ---------------------------------------------------------------------------
# 1. LoopbackCallbackServer binding policy, advertise_host, and from_env()
# ---------------------------------------------------------------------------


def test_loopback_callback_server_strict_default_and_opt_in_private_bridge() -> None:
    # Default mode strictly rejects non-loopback / wildcard / hostname binds.
    for bad_host in ("0.0.0.0", "localhost", "192.168.1.5", "172.17.0.1", "8.8.8.8"):
        with pytest.raises(ValueError):
            LoopbackCallbackServer(host=bad_host)

    # Even with allow_private_bridge=True, unspecified, public, multicast, and hostnames are rejected.
    for forbidden_bridge_host in ("0.0.0.0", "::", "8.8.8.8", "localhost", "224.0.0.1", "172.17.0.1%eth0"):
        with pytest.raises(ValueError):
            LoopbackCallbackServer(host=forbidden_bridge_host, allow_private_bridge=True)

    # Private bridge IPs are accepted when allow_private_bridge=True (validated without binding non-local IP).
    bridge_srv = LoopbackCallbackServer(
        host="172.17.0.1",
        allow_private_bridge=True,
        advertise_host="host.docker.internal",
    )
    assert bridge_srv.host == "172.17.0.1"
    assert bridge_srv.allow_private_bridge is True
    assert bridge_srv.advertise_host == "host.docker.internal"

    # Malformed advertise_host values are rejected.
    for bad_adv in (
        "http://host.docker.internal",
        "host.docker.internal:8080",
        "host.docker.internal/cb",
        "user@host.docker.internal",
        "bad host",
        "0.0.0.0",
        "224.0.0.1",
    ):
        with pytest.raises(ValueError):
            LoopbackCallbackServer(advertise_host=bad_adv)

    # Live loopback bind + opt-in advertise_host produces docker-reachable callback URL.
    srv = LoopbackCallbackServer(
        host="127.0.0.1",
        allow_private_bridge=True,
        advertise_host="host.docker.internal",
    )
    try:
        tok_info = srv.create_token(label="docker-xxe")
        assert tok_info["url"] == f"http://host.docker.internal:{srv.port}/cb/{tok_info['token']}"
        # Underlying socket still listens on 127.0.0.1:<port> and records hits.
        resp = requests.get(f"http://127.0.0.1:{srv.port}/cb/{tok_info['token']}", timeout=2.0)
        assert resp.status_code == 200
        assert srv.poll(tok_info["token"])["hit_count"] == 1
    finally:
        srv.close()


def test_loopback_callback_server_from_env_and_dispatcher_wiring(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CCO_OOB_BIND_HOST", raising=False)
    monkeypatch.delenv("CCO_OOB_ADVERTISE_HOST", raising=False)
    default_srv = LoopbackCallbackServer.from_env()
    assert default_srv.host == "127.0.0.1"
    assert default_srv.allow_private_bridge is False
    assert default_srv.advertise_host == ""

    monkeypatch.setenv("CCO_OOB_BIND_HOST", "172.17.0.1")
    monkeypatch.setenv("CCO_OOB_ADVERTISE_HOST", "host.docker.internal")
    bridge_srv = LoopbackCallbackServer.from_env()
    assert bridge_srv.host == "172.17.0.1"
    assert bridge_srv.allow_private_bridge is True
    assert bridge_srv.advertise_host == "host.docker.internal"

    for bad_env_host in ("0.0.0.0", "8.8.8.8", "localhost"):
        monkeypatch.setenv("CCO_OOB_BIND_HOST", bad_env_host)
        with pytest.raises(ValueError):
            LoopbackCallbackServer.from_env()

    # ToolDispatcher._get_oob_server uses LoopbackCallbackServer.from_env() when env vars are set.
    monkeypatch.setenv("CCO_OOB_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("CCO_OOB_ADVERTISE_HOST", "host.docker.internal")
    store, _, http, _ = _make_client(tmp_path)
    dispatcher = ToolDispatcher(http_client=http, receipt_store=store, root_dir=tmp_path)
    try:
        cb = json.loads(dispatcher.dispatch("callback_listener", {"action": "create_url", "label": "env-test"}))
        assert cb["url"].startswith("http://host.docker.internal:")
        assert f"/cb/{cb['token']}" in cb["url"]
    finally:
        dispatcher.close()
        http.close()


# ---------------------------------------------------------------------------
# 2. Same-origin localStorage preservation in agentic_auth_import
# ---------------------------------------------------------------------------


def test_load_storage_state_actor_preserves_same_origin_local_storage_and_caps(tmp_path: Path) -> None:
    secret_val = "LS_SECRET_VALUE_987654"
    state: dict[str, Any] = {
        "cookies": [],
        "origins": [
            {
                "origin": "https://evil.example.test",
                "localStorage": [
                    {"name": "cross_origin_key", "value": "CROSS_ORIGIN_SECRET"},
                ],
            },
            {
                "origin": "http://app.example.test",
                "localStorage": [
                    {"name": "wrong_scheme_key", "value": "WRONG_SCHEME_SECRET"},
                ],
            },
            {
                "origin": "https://app.example.test:8443",
                "localStorage": [
                    {"name": "wrong_port_key", "value": "WRONG_PORT_SECRET"},
                ],
            },
            {
                "origin": "https://app.example.test:443",
                "localStorage": [
                    {"name": "access_token", "value": f"Bearer {secret_val}"},
                    {"name": "spa_profile", "value": '{"theme":"dark","tenant":"acme"}'},
                    {"name": "", "value": "empty-key-rejected"},
                    {"name": "   ", "value": "ws-key-rejected"},
                    {"name": "bad\nkey", "value": "ctrl-key-rejected"},
                    {"name": "bad\x00key", "value": "nul-key-rejected"},
                    {"name": "non_str_val", "value": 12345},
                ],
            },
        ],
    }

    actor = auth_import.load_storage_state_actor(
        state,
        base_url="https://app.example.test/dashboard",
        alias="spa-alice",
        role="member",
    )
    assert actor["local_storage"] == {
        "access_token": f"Bearer {secret_val}",
        "spa_profile": '{"theme":"dark","tenant":"acme"}',
    }
    assert "cross_origin_key" not in actor["local_storage"]
    assert "wrong_scheme_key" not in actor["local_storage"]
    assert "wrong_port_key" not in actor["local_storage"]

    # Key count cap (MAX_LOCAL_STORAGE_KEYS = 64)
    many_entries = [{"name": f"k_{i:03d}", "value": f"v_{i:03d}"} for i in range(100)]
    capped_keys_actor = auth_import.load_storage_state_actor(
        {"cookies": [], "origins": [{"origin": "http://127.0.0.1:8080", "localStorage": many_entries}]},
        base_url="http://127.0.0.1:8080/",
    )
    assert len(capped_keys_actor["local_storage"]) == auth_import.MAX_LOCAL_STORAGE_KEYS
    assert "k_000" in capped_keys_actor["local_storage"]
    assert "k_063" in capped_keys_actor["local_storage"]
    assert "k_064" not in capped_keys_actor["local_storage"]

    # UTF-8 byte budget cap (MAX_LOCAL_STORAGE_BYTES = 64 KiB)
    huge_chunk = "x" * (40 * 1024)
    byte_entries = [
        {"name": "part1", "value": huge_chunk},
        {"name": "part2_overflow", "value": huge_chunk},
        {"name": "small_after_overflow", "value": "fits-inside-64k"},
    ]
    capped_bytes_actor = auth_import.load_storage_state_actor(
        {"cookies": [], "origins": [{"origin": "http://127.0.0.1:8080", "localStorage": byte_entries}]},
        base_url="http://127.0.0.1:8080/",
    )
    assert "part1" in capped_bytes_actor["local_storage"]
    assert "part2_overflow" not in capped_bytes_actor["local_storage"]
    assert capped_bytes_actor["local_storage"]["small_after_overflow"] == "fits-inside-64k"
    total_utf8 = sum(
        len(k.encode("utf-8")) + len(v.encode("utf-8"))
        for k, v in capped_bytes_actor["local_storage"].items()
    )
    assert total_utf8 <= auth_import.MAX_LOCAL_STORAGE_BYTES

    # Vault save summary and ActorManager summaries never expose localStorage secrets.
    state_file = tmp_path / "spa_state.json"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    vault_summary = auth_import.save_storage_state_to_vault(
        tmp_path / "vault_home",
        "spa_key",
        state_file,
        alias="spa-alice",
        target_url="https://app.example.test/",
    )
    assert secret_val not in json.dumps(vault_summary)

    actors = ActorManager([actor])
    assert secret_val not in json.dumps(actors.summaries())
    browser_state = actors.get_browser_auth_state("spa-alice")
    assert browser_state["local_storage"] == actor["local_storage"]
    assert any(secret_val in s for s in actors.all_secrets())


# ---------------------------------------------------------------------------
# 3. agentic_browser localStorage extraction, init script, redaction & injection
# ---------------------------------------------------------------------------


def test_browser_local_storage_helpers_redaction_and_mocked_init_script(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ls_secret = "SPA_LOCAL_STORAGE_SECRET_4411"
    ls_bearer = "SPA_BEARER_INNER_TOKEN_7722"
    _, _, http, tracker = _make_client(
        tmp_path,
        base_url="http://127.0.0.1:18080",
        accounts=[
            {
                "alias": "spa-user",
                "role": "member",
                "local_storage": {
                    "app_state_secret": ls_secret,
                    "auth_hdr": f"Bearer {ls_bearer}",
                },
            }
        ],
    )

    # 1. _extract_actor_local_storage: anon -> {}, actor -> local_storage from get_browser_auth_state.
    assert _extract_actor_local_storage(http, "anon") == {}
    assert _extract_actor_local_storage(http, "spa-user") == {
        "app_state_secret": ls_secret,
        "auth_hdr": f"Bearer {ls_bearer}",
    }

    # Fallback path when get_browser_auth_state omits local_storage.
    monkeypatch.setattr(
        http.actors,
        "get_browser_auth_state",
        lambda _actor: {"cookies": {}, "headers": {}},
    )
    assert _extract_actor_local_storage(http, "spa-user") == {
        "app_state_secret": ls_secret,
        "auth_hdr": f"Bearer {ls_bearer}",
    }

    # 2. _build_origin_localstorage_init_script formatting, origin normalization, and escaping.
    assert _build_origin_localstorage_init_script("http://127.0.0.1:18080/", {}) == ""
    script = _build_origin_localstorage_init_script(
        "https://app.example.test:443/ignored/path",
        {"k1": 'val"with\nquotes</script>'},
    )
    assert 'if (window.location.origin === "https://app.example.test")' in script
    assert "window.localStorage.setItem(k, v)" in script
    assert "try {" in script
    assert "catch (_) {}" in script
    assert '\\n' in script

    # 3. _collect_actor_secrets captures local_storage values and scrubs run_browser_crawl & inspect outputs.
    collected = _collect_actor_secrets(
        http,
        "",
        {},
        local_storage={"app_state_secret": ls_secret, "auth_hdr": f"Bearer {ls_bearer}"},
    )
    assert ls_secret in collected
    assert ls_bearer in collected

    seen_crawl_kwargs: dict[str, Any] = {}

    def fake_crawl(start_url: str, **kwargs: Any) -> dict[str, Any]:
        seen_crawl_kwargs.update(kwargs)
        return {
            "ok": True,
            "pages": [{"url": start_url, "status": 200, "title": f"Leak {ls_secret} {ls_bearer}"}],
            "links": [],
            "forms": [],
            "xhr": [],
        }

    crawl_res = run_browser_crawl(http, tracker, url="/", actor="spa-user", crawl_fn=fake_crawl)
    assert seen_crawl_kwargs["local_storage"]["app_state_secret"] == ls_secret
    assert ls_secret not in json.dumps(crawl_res)
    assert ls_bearer not in json.dumps(crawl_res)

    # 4. Mocked Playwright context verifies context.add_init_script is invoked with same-origin localStorage script.
    added_scripts: list[str] = []

    class _FakeResp:
        status = 200
        headers = {"content-type": "text/html"}

    class _FakePage:
        url = "http://127.0.0.1:18080/app"

        def on(self, *_args: Any) -> None:
            return

        def goto(self, *_args: Any, **_kwargs: Any) -> _FakeResp:
            return _FakeResp()

        def wait_for_timeout(self, _ms: int) -> None:
            return

        def evaluate(self, script_src: str, *_args: Any) -> dict[str, Any]:
            if "__ccoRuntime" in script_src:
                return {"events": [], "state": {}}
            return {
                "title": f"Rendered {ls_secret}",
                "checked": False,
                "in_inner_text": False,
                "in_outer_html": False,
                "in_script_or_event_attr": False,
                "script_matches": 0,
                "event_attr_matches": [],
            }

    class _FakeContext:
        def add_init_script(self, script_src: str) -> None:
            added_scripts.append(script_src)

        def add_cookies(self, _cookies: list[dict[str, Any]]) -> None:
            return

        def route(self, *_args: Any) -> None:
            return

        def new_page(self) -> _FakePage:
            return _FakePage()

        def close(self) -> None:
            return

    class _FakeBrowser:
        def new_context(self, **_kwargs: Any) -> _FakeContext:
            return _FakeContext()

        def close(self) -> None:
            return

    class _FakeChromium:
        def launch(self, **_kwargs: Any) -> _FakeBrowser:
            return _FakeBrowser()

    class _FakePW:
        chromium = _FakeChromium()

        def __enter__(self) -> _FakePW:
            return self

        def __exit__(self, *_args: Any) -> None:
            return

    monkeypatch.setattr(agentic_browser, "HAS_PLAYWRIGHT", True)
    monkeypatch.setattr(agentic_browser, "_sync_playwright", lambda: _FakePW())

    inspected = inspect_rendered_page(http, url="/app", actor="spa-user", wait_ms=0)
    assert inspected["ok"] is True
    assert ls_secret not in json.dumps(inspected)
    assert any(
        'if (window.location.origin === "http://127.0.0.1:18080")' in sc
        and "window.localStorage.setItem(k, v)" in sc
        and ls_secret in sc
        for sc in added_scripts
    )

    # Anon actor must NOT inject any localStorage init script.
    added_scripts.clear()
    inspected_anon = inspect_rendered_page(http, url="/app", actor="anon", wait_ms=0)
    assert inspected_anon["ok"] is True
    assert not any("window.localStorage.setItem" in sc for sc in added_scripts)


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed")
def test_inspect_rendered_page_live_injects_same_origin_local_storage_without_leaking(tmp_path: Path) -> None:
    ls_secret = "LIVE_SPA_LS_SECRET_554433"

    class _LSHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            return

        def do_GET(self) -> None:
            html = (
                "<!doctype html><html><head><title>LS SPA</title></head><body>"
                "<div id='status'>missing</div>"
                "<script>"
                "const v = window.localStorage.getItem('spa_token') || '';"
                "document.title = 'Token=' + v;"
                "if (v === 'LIVE_SPA_LS_SECRET_554433') {"
                "  document.getElementById('status').textContent = 'LS_INJECTED_OK_MARKER';"
                "}"
                "</script>"
                "</body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

    base_url, srv = _start_server(_LSHandler)
    try:
        _, _, http, _ = _make_client(
            tmp_path,
            base_url=base_url,
            accounts=[{"alias": "spa-live", "local_storage": {"spa_token": ls_secret}}],
        )
        res = inspect_rendered_page(
            http,
            url="/",
            actor="spa-live",
            marker="LS_INJECTED_OK_MARKER",
            wait_ms=150,
            timeout_ms=10000,
        )
        assert res["ok"] is True, res.get("error")
        assert res["marker_check"]["in_inner_text"] is True
        assert ls_secret not in json.dumps(res)
        assert "<REDACTED>" in res["title"]
    finally:
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 4. System & worker prompts coverage
# ---------------------------------------------------------------------------


def test_system_and_worker_prompts_cover_uploads_delete_oob_concurrency_cors_and_ws() -> None:
    sys_prompt = build_system_prompt(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
        discovery_hints=["/"],
        http_budget=100,
    )
    worker_prompt = build_worker_system_prompt(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        http_budget_remaining=50,
        micro_budget=8,
    )
    for label, prompt in (("system", sys_prompt), ("worker", worker_prompt)):
        for required_token in (
            "files=",
            "DELETE",
            "callback_listener",
            "concurrent_check",
            "cors_misconfiguration",
            "ws://",
            "wss://",
            "http_request",
        ):
            assert required_token in prompt, f"{label} prompt missing {required_token!r}"


# ---------------------------------------------------------------------------
# 5. TOOL_SCHEMAS bounds, follow_redirects forwarding, generalized OOB, CORS, 204 DELETE
# ---------------------------------------------------------------------------


def test_tool_schemas_count_size_and_all_property_descriptions_bounded() -> None:
    assert len(TOOL_SCHEMAS) == 11
    serialized = json.dumps(TOOL_SCHEMAS, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(serialized) <= 16_384

    for tool in TOOL_SCHEMAS:
        fn = tool["function"]
        name = fn["name"]
        assert len(fn["description"]) <= 140, f"{name} description > 140 chars"
        props = fn.get("parameters", {}).get("properties", {})
        for prop_name, prop_schema in props.items():
            desc = prop_schema.get("description")
            if isinstance(desc, str):
                assert len(desc) <= 140, f"{name}.{prop_name} description > 140 chars ({len(desc)})"

    http_props = next(
        t["function"]["parameters"]["properties"]
        for t in TOOL_SCHEMAS
        if t["function"]["name"] == "http_request"
    )
    assert http_props["follow_redirects"] == {"type": "boolean"}


def test_tool_http_request_follow_redirects_forwarding_and_mock_compatibility(tmp_path: Path) -> None:
    # 1. Existing strict mock lambdas without `follow_redirects` parameter stay 100% compatible when False/omitted.
    store, _, http, _ = _make_client(tmp_path)
    dispatcher = ToolDispatcher(http_client=http, receipt_store=store, root_dir=tmp_path)
    observed_calls: list[dict[str, Any]] = []

    def _strict_mock_request(
        *,
        method: str = "GET",
        url: str,
        actor: str = "anon",
        headers: Any = None,
        query: Any = None,
        json_body: Any = None,
        form_body: Any = None,
        raw_body: Any = None,
        files: Any = None,
        force: bool = False,
        save_session_as: str = "",
    ) -> dict[str, Any]:
        observed_calls.append({"method": method, "url": url, "actor": actor})
        return store.record(
            actor=actor,
            method=method,
            url=f"http://127.0.0.1:18080{url}",
            path=url,
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"ok":true}',
            response_text='{"ok":true}',
        )

    http.request = _strict_mock_request  # type: ignore[method-assign]
    out_default = _unwrap_tool_payload(dispatcher.dispatch("http_request", {"url": "/ping"}))
    assert out_default["status"] == 200
    out_false = _unwrap_tool_payload(
        dispatcher.dispatch("http_request", {"url": "/ping", "follow_redirects": False})
    )
    assert out_false["status"] == 200
    assert len(observed_calls) == 2

    # 2. When follow_redirects=True, follow_redirects=True IS forwarded to http.request.
    forwarded: list[dict[str, Any]] = []

    def _capturing_request(**kwargs: Any) -> dict[str, Any]:
        forwarded.append(dict(kwargs))
        return store.record(
            actor=kwargs.get("actor", "anon"),
            method=kwargs.get("method", "GET"),
            url="http://127.0.0.1:18080/final",
            path="/final",
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"landed":true}',
            response_text='{"landed":true}',
        )

    http.request = _capturing_request  # type: ignore[method-assign]
    out_true = _unwrap_tool_payload(
        dispatcher.dispatch("http_request", {"url": "/start", "follow_redirects": True})
    )
    assert out_true["status"] == 200
    assert forwarded[-1].get("follow_redirects") is True
    dispatcher.close()
    http.close()


def test_dispatcher_generalized_oob_xxe_cors_headers_and_delete_204(tmp_path: Path) -> None:
    docs: dict[str, dict[str, Any]] = {
        "42": {"id": "42", "owner": "alice", "tenant": "alpha", "secret": "DOC_42_SECRET"},
        "43": {"id": "43", "owner": "alice", "tenant": "alpha", "secret": "DOC_43_SECRET"},
    }

    class _WiringHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: Any) -> None:
            return

        def _actor(self) -> str:
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer tok-alice":
                return "alice"
            if auth == "Bearer tok-bob":
                return "bob"
            if auth == "Bearer tok-charlie":
                return "charlie"
            return "anon"

        def _send_json(self, status: int, obj: Any, extra_headers: dict[str, str] | None = None) -> None:
            payload = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            actor = self._actor()
            if path == "/api/cors-reflect":
                origin = self.headers.get("Origin", "")
                extra: dict[str, str] = {}
                if origin:
                    extra["Access-Control-Allow-Origin"] = origin
                    extra["Access-Control-Allow-Credentials"] = "true"
                self._send_json(200, {"user": actor, "email": "alice@example.test"}, extra_headers=extra)
                return
            if path == "/api/cors-wild":
                origin = self.headers.get("Origin", "")
                extra_w = {"Access-Control-Allow-Origin": "*"} if origin else {}
                self._send_json(200, {"public": True}, extra_headers=extra_w)
                return
            if path.startswith("/api/docs/"):
                doc_id = path.rsplit("/", 1)[-1]
                doc = docs.get(doc_id)
                if doc is None:
                    self._send_json(404, {"error": "not_found"})
                    return
                if actor == "charlie":
                    self._send_json(403, {"error": "forbidden"})
                    return
                self._send_json(200, doc)
                return
            self._send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            raw_len = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(raw_len).decode("utf-8", errors="replace") if raw_len > 0 else ""
            if path == "/api/xml":
                if "NO_EXEC" not in body:
                    match = re.search(r"http://127\.0\.0\.1:\d+/cb/[A-Za-z0-9_-]+", body)
                    if match:
                        requests.get(match.group(0), timeout=2.0)
                self._send_json(200, {"parsed": True})
                return
            self._send_json(404, {"error": "not_found"})

        def do_DELETE(self) -> None:
            path = urlsplit(self.path).path
            actor = self._actor()
            if not path.startswith("/api/docs/"):
                self._send_json(404, {"error": "not_found"})
                return
            doc_id = path.rsplit("/", 1)[-1]
            if actor == "charlie":
                self._send_json(403, {"error": "forbidden"})
                return
            if doc_id not in docs:
                self._send_json(404, {"error": "not_found"})
                return
            docs.pop(doc_id, None)
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

    base_url, srv = _start_server(_WiringHandler)
    accounts = [
        {"alias": "alice", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-alice"},
        {"alias": "bob", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-bob"},
        {"alias": "charlie", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-charlie"},
    ]
    store, _, http, _ = _make_client(tmp_path, base_url=base_url, accounts=accounts, max_requests=60)
    oracle = DifferentialOracle(http_client=http, receipt_store=store, mode="differential")
    dispatcher = ToolDispatcher(http_client=http, receipt_store=store, root_dir=tmp_path, oracle=oracle)
    try:
        # 1. Generalized OOB class (xxe): 0 hits rejected, real hit accepted & verified.
        cb_zero = json.loads(dispatcher.dispatch("callback_listener", {"action": "create_url", "label": "xxe-zero"}))
        xxe_zero = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "POST",
            "url": "/api/xml",
            "actor": "alice",
            "headers": {"Content-Type": "application/xml"},
            "raw_body": f'<!-- NO_EXEC --><!DOCTYPE r [<!ENTITY x SYSTEM "{cb_zero["url"]}">]><r/>',
        }))
        xxe_ctrl = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "POST",
            "url": "/api/xml",
            "actor": "alice",
            "headers": {"Content-Type": "application/xml"},
            "raw_body": "<r>safe</r>",
        }))
        rej_xxe = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Blind XXE with zero callback hits",
            "class_type": "xxe",
            "method": "POST",
            "url": "/api/xml",
            "actor_alias": "alice",
            "proof_receipt_ids": [xxe_zero["receipt_id"]],
            "control_receipt_ids": [xxe_ctrl["receipt_id"]],
            "evidence_value": cb_zero["token"],
            "summary": "Claiming XXE despite zero OOB hits.",
        }))
        assert rej_xxe["rejected"] is True
        assert "0 hits" in rej_xxe["reason"]
        assert "XXE" in rej_xxe["reason"]

        cb_hit = json.loads(dispatcher.dispatch("callback_listener", {"action": "create_url", "label": "xxe-hit"}))
        xxe_proof = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "POST",
            "url": "/api/xml",
            "actor": "alice",
            "headers": {"Content-Type": "application/xml"},
            "raw_body": f'<!DOCTYPE r [<!ENTITY x SYSTEM "{cb_hit["url"]}">]><r>&x;</r>',
        }))
        polled = _unwrap_tool_payload(dispatcher.dispatch("callback_listener", {"action": "poll", "token": cb_hit["token"]}))
        assert polled["hit_count"] == 1
        acc_xxe = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Blind XXE confirmed via OOB callback",
            "class_type": "xxe",
            "method": "POST",
            "url": "/api/xml",
            "actor_alias": "alice",
            "proof_receipt_ids": [xxe_proof["receipt_id"]],
            "control_receipt_ids": [xxe_ctrl["receipt_id"]],
            "evidence_value": cb_hit["token"],
            "summary": "XML parser fetched external DTD entity from local callback server.",
        }))
        assert acc_xxe.get("accepted") is True
        assert acc_xxe.get("class_type") == "xxe"

        # 2. CORS response-header evidence (Header: Value format AND wildcard '*').
        evil_origin = "https://evil.example"
        cors_proof = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "GET",
            "url": "/api/cors-reflect",
            "actor": "alice",
            "headers": {"Origin": evil_origin},
        }))
        cors_ctrl = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "GET",
            "url": "/api/cors-reflect",
            "actor": "alice",
        }))
        acc_cors = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Arbitrary Origin CORS reflection with credentials",
            "class_type": "cors_misconfiguration",
            "method": "GET",
            "url": "/api/cors-reflect",
            "actor_alias": "alice",
            "proof_receipt_ids": [cors_proof["receipt_id"]],
            "control_receipt_ids": [cors_ctrl["receipt_id"]],
            "evidence_value": f"Access-Control-Allow-Origin: {evil_origin}",
            "summary": "Endpoint reflects untrusted Origin with Access-Control-Allow-Credentials: true.",
        }))
        assert acc_cors.get("accepted") is True
        cors_finding = next(f for f in dispatcher.findings if f["finding_id"] == acc_cors["finding_id"])
        assert f"Access-Control-Allow-Origin: {evil_origin}" in cors_finding["evidence"]

        wild_proof = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "GET",
            "url": "/api/cors-wild",
            "actor": "alice",
            "headers": {"Origin": evil_origin},
        }))
        wild_ctrl = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "GET",
            "url": "/api/cors-wild",
            "actor": "alice",
        }))
        acc_wild = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Wildcard ACAO response header",
            "class_type": "cors_misconfiguration",
            "method": "GET",
            "url": "/api/cors-wild",
            "actor_alias": "alice",
            "proof_receipt_ids": [wild_proof["receipt_id"]],
            "control_receipt_ids": [wild_ctrl["receipt_id"]],
            "evidence_value": "*",
            "summary": "Endpoint returns Access-Control-Allow-Origin: * on Origin header.",
        }))
        assert acc_wild.get("accepted") is True

        # 3. Empty-body 204 DELETE cross-actor BOLA verified cleanly through ToolDispatcher + DifferentialOracle.
        alice_get_42 = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "GET",
            "url": "/api/docs/42",
            "actor": "alice",
        }))
        assert alice_get_42["status"] == 200
        charlie_del_42 = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "DELETE",
            "url": "/api/docs/42",
            "actor": "charlie",
        }))
        assert charlie_del_42["status"] == 403
        bob_del_42 = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "DELETE",
            "url": "/api/docs/42",
            "actor": "bob",
        }))
        assert bob_del_42["status"] == 204
        assert bob_del_42["response_length"] == 0

        # Hallucinated evidence on empty 204 DELETE must still be rejected.
        rej_hallucinated = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Hallucinated evidence on 204 DELETE",
            "class_type": "bola",
            "method": "DELETE",
            "url": "/api/docs/42",
            "actor_alias": "bob",
            "proof_receipt_ids": [bob_del_42["receipt_id"]],
            "control_receipt_ids": [charlie_del_42["receipt_id"], alice_get_42["receipt_id"]],
            "evidence_value": "COMPLETELY_HALLUCINATED_VALUE_999",
            "summary": "Invalid hallucinated evidence.",
        }))
        assert rej_hallucinated["rejected"] is True

        # Valid 204 DELETE with differential controls verifies via Stage 3 DELETE persistence (fresh owner GET 404).
        acc_del_204 = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Cross-actor BOLA on 204 DELETE /api/docs/42",
            "class_type": "bola",
            "method": "DELETE",
            "url": "/api/docs/42",
            "actor_alias": "bob",
            "proof_receipt_ids": [bob_del_42["receipt_id"]],
            "control_receipt_ids": [charlie_del_42["receipt_id"], alice_get_42["receipt_id"]],
            "evidence_value": "204",
            "summary": "Bob deleted Alice's doc 42 (204 No Content) while Charlie received 403.",
        }))
        assert acc_del_204.get("accepted") is True
        del_finding = next(f for f in dispatcher.findings if f["finding_id"] == acc_del_204["finding_id"])
        assert del_finding["observed_status"] == 204
        assert "204" in del_finding["evidence"]

        # Negative: non-differential 204 control on empty 204 DELETE must be rejected.
        bob_del_43 = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "DELETE",
            "url": "/api/docs/43",
            "actor": "bob",
        }))
        assert bob_del_43["status"] == 204
        rej_same_204 = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Non-differential 204 control",
            "class_type": "bola",
            "method": "DELETE",
            "url": "/api/docs/43",
            "actor_alias": "bob",
            "proof_receipt_ids": [bob_del_43["receipt_id"]],
            "control_receipt_ids": [bob_del_42["receipt_id"]],
            "evidence_value": "204",
            "summary": "Control also returned 204.",
        }))
        assert rej_same_204["rejected"] is True
    finally:
        dispatcher.close()
        http.close()
        _stop_server(srv)
