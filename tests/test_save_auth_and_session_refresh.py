"""Tests for save_browser_auth HAR/manual modes, localStorage refresh_token import, and mid-run 401 refresh."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import stat
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

import agentic_auth_import as auth_import  # noqa: E402
from agentic_http import (  # noqa: E402
    ActorManager,
    AgenticHTTPClient,
    BudgetExhaustedError,
    ServiceDegradationError,
)
from agentic_receipts import ReceiptStore  # noqa: E402
import save_browser_auth  # noqa: E402


# ---------------------------------------------------------------------------
# 1. save_browser_auth: --record-har, --manual, --browse-seconds, validation
# ---------------------------------------------------------------------------


def _install_fake_playwright(
    monkeypatch: pytest.MonkeyPatch,
    *,
    har_content: str = '{"log":{"entries":[{"request":{"headers":[{"name":"Cookie","value":"SECRET_COOKIE_XYZ"}]}}]}}',
    initial_status: int = 200,
) -> dict[str, Any]:
    state: dict[str, Any] = {
        "launch_kwargs": None,
        "context_kwargs": None,
        "wait_timeouts": [],
        "fills": [],
        "clicks": [],
        "ctx_closed": False,
        "har_written_on_close": False,
    }

    class _FakePage:
        url = "https://target.example.invalid/dashboard"

        def set_default_timeout(self, _ms: int) -> None:
            return

        def goto(self, _url: str, **_kwargs: Any) -> Any:
            return SimpleNamespace(status=initial_status)

        def wait_for_timeout(self, ms: int) -> None:
            state["wait_timeouts"].append(ms)

        def title(self) -> str:
            return "Dashboard"

        def fill(self, sel: str, val: str) -> None:
            state["fills"].append((sel, val))

        def click(self, sel: str, **_kwargs: Any) -> None:
            state["clicks"].append(sel)

        def is_visible(self, _sel: str, **_kwargs: Any) -> bool:
            return False

    class _FakeCtx:
        def new_page(self) -> _FakePage:
            return _FakePage()

        def storage_state(self, path: str) -> None:
            Path(path).write_text(json.dumps({"cookies": [], "origins": []}), encoding="utf-8")

        def cookies(self) -> list[dict[str, str]]:
            return [{"name": "sid", "value": "SECRET_COOKIE_XYZ"}]

        def close(self) -> None:
            state["ctx_closed"] = True
            har_path_str = (state["context_kwargs"] or {}).get("record_har_path")
            if har_path_str:
                hp = Path(har_path_str)
                hp.write_text(har_content, encoding="utf-8")
                hp.chmod(0o644)
                state["har_written_on_close"] = True

    class _FakeBrowser:
        def new_context(self, **kwargs: Any) -> _FakeCtx:
            state["context_kwargs"] = dict(kwargs)
            return _FakeCtx()

        def close(self) -> None:
            return

    class _FakePlaywrightCM:
        def __enter__(self) -> Any:
            def _launch(**kwargs: Any) -> _FakeBrowser:
                state["launch_kwargs"] = dict(kwargs)
                return _FakeBrowser()

            return SimpleNamespace(chromium=SimpleNamespace(launch=_launch))

        def __exit__(self, *_args: Any) -> bool:
            return False

    fake_sync_api = SimpleNamespace(sync_playwright=lambda: _FakePlaywrightCM())
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync_api)
    monkeypatch.setattr(save_browser_auth, "_proxy_args", lambda: {})
    return state


def test_save_browser_auth_record_har_and_chmod_after_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    har_secret = "SECRET_HAR_BEARER_TOKEN_9981"
    state = _install_fake_playwright(
        monkeypatch,
        har_content=json.dumps({"log": {"entries": [{"secret": har_secret}]}}),
    )

    login_file = tmp_path / "login.json"
    login_file.write_text(json.dumps({"username": "u1", "password": "pw1"}), encoding="utf-8")
    login_file.chmod(0o600)
    storage_file = tmp_path / "out" / "storage.json"
    har_file = tmp_path / "nested" / "har" / "auth.har"

    rc = save_browser_auth.main([
        "--program", "demo",
        "--login-url", "https://target.example.invalid/login",
        "--user-selector", "#user",
        "--pass-selector", "#pass",
        "--submit-selector", "#submit",
        "--login-file", str(login_file),
        "--storage", str(storage_file),
        "--record-har", str(har_file),
        "--browse-seconds", "5",
    ])
    assert rc == 0
    assert state["ctx_closed"] is True
    assert state["har_written_on_close"] is True
    assert state["context_kwargs"]["record_har_path"] == str(har_file)
    assert state["context_kwargs"]["record_har_mode"] == "minimal"
    assert state["context_kwargs"]["record_har_content"] == "embed"
    assert 5000 in state["wait_timeouts"]

    # HAR file must exist and have 0o600 permissions applied AFTER ctx.close() flushed it.
    assert har_file.is_file()
    assert stat.S_IMODE(har_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(storage_file.stat().st_mode) == 0o600

    stdout = capsys.readouterr().out
    assert f"[auth] HAR kaydedildi: {har_file}" in stdout
    assert har_secret not in stdout
    assert "SECRET_COOKIE_XYZ" not in stdout


def test_save_browser_auth_manual_skips_selectors_and_login_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = _install_fake_playwright(monkeypatch, initial_status=403)
    storage_file = tmp_path / "manual-storage.json"
    har_file = tmp_path / "manual.har"
    prompts: list[str] = []

    def _fake_input(prompt: str = "") -> str:
        prompts.append(prompt)
        return ""

    monkeypatch.setattr("builtins.input", _fake_input)
    # Point AUTH_DIR to a non-existent directory so default login-file cannot exist.
    monkeypatch.setattr(save_browser_auth, "AUTH_DIR", tmp_path / "nonexistent-auth")

    rc = save_browser_auth.main([
        "--program", "manualprog",
        "--login-url", "https://target.example.invalid/login",
        "--storage", str(storage_file),
        "--record-har", str(har_file),
        "--manual",
    ])
    assert rc == 0
    assert state["launch_kwargs"]["headless"] is False
    assert state["fills"] == []
    assert state["clicks"] == []
    assert len(prompts) == 1
    assert "Enter" in prompts[0]
    assert storage_file.is_file()
    assert har_file.is_file()
    assert stat.S_IMODE(har_file.stat().st_mode) == 0o600
    stdout = capsys.readouterr().out
    assert "[auth] HAR kaydedildi:" in stdout


def test_save_browser_auth_missing_selectors_without_manual_raises_system_exit(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        save_browser_auth.main([
            "--program", "demo",
            "--login-url", "https://target.example.invalid/login",
            "--storage", str(tmp_path / "s.json"),
        ])
    assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# 2. agentic_auth_import: localStorage refresh_token & refresh_path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ls_key,ls_val",
    [
        ("refresh_token", "rt-direct-snake-1111"),
        ("refreshtoken", '"rt-direct-lower-2222"'),
        ("refresh-token", "rt-direct-kebab-3333"),
        ("refreshToken", "rt-direct-camel-4444"),
    ],
)
def test_load_storage_state_actor_extracts_direct_refresh_token_and_refresh_path(
    ls_key: str,
    ls_val: str,
) -> None:
    state = {
        "cookies": [],
        "origins": [
            {
                "origin": "https://app.example.test",
                "localStorage": [
                    {"name": "access_token", "value": "Bearer jwt-access-1234"},
                    {"name": ls_key, "value": ls_val},
                ],
            }
        ],
    }
    actor = auth_import.load_storage_state_actor(
        state,
        base_url="https://app.example.test/home",
        alias="spa-member",
        refresh_path="/api/v2/auth/refresh",
    )
    expected_rt = ls_val.strip('"')
    assert actor["access_token"] == "jwt-access-1234"
    assert actor["refresh_token"] == expected_rt
    assert actor["refresh_path"] == "/api/v2/auth/refresh"

    mgr = ActorManager([actor])
    sess = mgr.get("spa-member")
    assert sess.refresh_token == expected_rt
    assert sess.refresh_path == "/api/v2/auth/refresh"


def test_load_storage_state_actor_extracts_json_blob_refresh_token_and_rejects_out_of_scope(
    tmp_path: Path,
) -> None:
    rt_secret = "RT_JSON_BLOB_SECRET_9911"
    state = {
        "cookies": [],
        "origins": [
            {
                "origin": "https://evil.example.net",
                "localStorage": [
                    {"name": "refresh_token", "value": "EVIL_OUT_OF_SCOPE_RT"},
                    {"name": "auth", "value": json.dumps({"refreshToken": "EVIL_JSON_RT"})},
                ],
            },
            {
                "origin": "http://app.example.test",
                "localStorage": [
                    {"name": "refresh_token", "value": "WRONG_SCHEME_RT"},
                ],
            },
            {
                "origin": "https://app.example.test:443",
                "localStorage": [
                    {
                        "name": "sb-auth-state",
                        "value": json.dumps({
                            "access_token": "jwt-from-top",
                            "data": {"tokens": {"refreshToken": rt_secret}},
                        }),
                    }
                ],
            },
        ],
    }
    actor = auth_import.load_storage_state_actor(
        state,
        base_url="https://app.example.test/",
        alias="json-spa",
    )
    assert actor["refresh_token"] == rt_secret
    assert "refresh_path" not in actor
    assert "EVIL_OUT_OF_SCOPE_RT" not in json.dumps(actor)
    assert "WRONG_SCHEME_RT" not in json.dumps(actor)

    # Vault roundtrip preserves refresh_path and never leaks refresh_token in summaries or errors.
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    vault_home = tmp_path / "vault"
    summary = auth_import.save_storage_state_to_vault(
        vault_home,
        "spa_key",
        state_file,
        alias="json-spa",
        target_url="https://app.example.test/",
    )
    assert rt_secret not in json.dumps(summary)
    loaded = auth_import.load_storage_state_actor_from_vault(
        vault_home,
        "spa_key",
        base_url="https://app.example.test/",
        refresh_path="/api/auth/refresh",
    )
    assert loaded["refresh_token"] == rt_secret
    assert loaded["refresh_path"] == "/api/auth/refresh"


# ---------------------------------------------------------------------------
# 3. agentic_http: mid-run 401 refresh with rotation, cookies, and redaction
# ---------------------------------------------------------------------------


@contextmanager
def _start_loopback_server(
    router: Callable[[str, str, dict[str, str], bytes], tuple[int, str, bytes | str, list[tuple[str, str]]]],
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
            for hk, hv in extra_hdrs:
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
        yield f"http://127.0.0.1:{port}/", requests_log
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


def test_agentic_http_mid_run_401_uses_actors_default_refresh_path_rotates_tokens_and_redacts(
    tmp_path: Path,
) -> None:
    expired_jwt = "jwt-expired-access-1111"
    fresh_jwt = "jwt-rotated-access-2222"
    init_rt = "rt-initial-secret-1111"
    rot_rt = "rt-rotated-secret-2222"

    def _router(
        method: str, path: str, hdrs: dict[str, str], body: bytes
    ) -> tuple[int, str, str, list[tuple[str, str]]]:
        if method == "POST" and path == "/api/v1/access/refresh":
            data = json.loads(body.decode("utf-8") or "{}")
            if data.get("refresh_token") == init_rt:
                return (
                    200,
                    "application/json",
                    json.dumps({"access_token": fresh_jwt, "refresh_token": rot_rt}),
                    [],
                )
            return 401, "application/json", '{"error":"invalid_refresh_token"}', []

        if method == "GET" and path == "/api/protected":
            if hdrs.get("authorization") == f"Bearer {fresh_jwt}":
                return (
                    200,
                    "application/json",
                    json.dumps({"ok": True, "echo_old_rt": init_rt, "echo_new_rt": rot_rt}),
                    [],
                )
            return 401, "application/json", json.dumps({"error": "expired", "tok": expired_jwt}), []

        return 404, "application/json", '{"error":"not_found"}', []

    with _start_loopback_server(_router) as (base_url, req_log):
        # Load from storage_state WITHOUT per-actor refresh_path -> relies on ActorManager default /api/v1/access/refresh.
        account = auth_import.load_storage_state_actor(
            {
                "cookies": [],
                "origins": [
                    {
                        "origin": base_url.rstrip("/"),
                        "localStorage": [
                            {"name": "access_token", "value": expired_jwt},
                            {"name": "auth_blob", "value": json.dumps({"refresh_token": init_rt})},
                        ],
                    }
                ],
            },
            base_url=base_url,
            alias="member",
        )
        assert "refresh_path" not in account

        store = ReceiptStore(tmp_path / "run-default-refresh")
        actors = ActorManager([account])
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=actors,
            allowed_methods=("GET", "POST"),
            max_requests=10,
        )
        try:
            rec = client.request(method="GET", url="/api/protected", actor="member")
            assert rec["status"] == 200
            assert [(r["method"], r["path"]) for r in req_log] == [
                ("GET", "/api/protected"),
                ("POST", "/api/v1/access/refresh"),
                ("GET", "/api/protected"),
            ]
            assert req_log[0]["headers"]["authorization"] == f"Bearer {expired_jwt}"
            assert req_log[2]["headers"]["authorization"] == f"Bearer {fresh_jwt}"

            sess = actors.get("member")
            assert sess.access_token == fresh_jwt
            assert sess.refresh_token == rot_rt

            # Both retired and newly rotated tokens must remain in collect_secrets/all_secrets and be redacted in receipts.
            all_secs = actors.all_secrets()
            for sec in (expired_jwt, fresh_jwt, init_rt, rot_rt):
                assert sec in all_secs

            for rid in store.list_ids():
                raw_text = (tmp_path / "run-default-refresh" / "receipts" / f"{rid}.json").read_text(
                    encoding="utf-8"
                )
                for sec in (expired_jwt, fresh_jwt, init_rt, rot_rt):
                    assert sec not in raw_text
        finally:
            client.close()


def test_agentic_http_mid_run_401_cookie_based_explicit_refresh_path(tmp_path: Path) -> None:
    old_sid = "sid-expired-cookie-1111"
    fresh_sid = "sid-fresh-cookie-2222"
    old_rsid = "rsid-refresh-cookie-1111"
    fresh_rsid = "rsid-refresh-cookie-2222"

    def _router(
        method: str, path: str, hdrs: dict[str, str], _body: bytes
    ) -> tuple[int, str, str, list[tuple[str, str]]]:
        if method == "POST" and path == "/api/auth/cookie-refresh":
            cookie_hdr = hdrs.get("cookie", "")
            if f"refresh_sid={old_rsid}" in cookie_hdr:
                return (
                    200,
                    "application/json",
                    '{"refreshed":true}',
                    [
                        ("Set-Cookie", f"sid={fresh_sid}; Path=/; HttpOnly"),
                        ("Set-Cookie", f"refresh_sid={fresh_rsid}; Path=/; HttpOnly"),
                    ],
                )
            return 401, "application/json", '{"error":"missing_refresh_cookie"}', []

        if method == "GET" and path == "/api/profile":
            cookie_hdr = hdrs.get("cookie", "")
            if f"sid={fresh_sid}" in cookie_hdr:
                return 200, "application/json", json.dumps({"user": "alice", "leaked": old_sid}), []
            return 401, "application/json", '{"error":"session_expired"}', []

        return 404, "application/json", '{"error":"not_found"}', []

    with _start_loopback_server(_router) as (base_url, req_log):
        store = ReceiptStore(tmp_path / "run-cookie-refresh")
        actors = ActorManager([
            {
                "alias": "cookie-user",
                "cookies": {"sid": old_sid, "refresh_sid": old_rsid},
                "refresh_path": "/api/auth/cookie-refresh",
            },
            {
                "alias": "cookie-no-path",
                "cookies": {"sid": old_sid},
            },
        ])
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=actors,
            allowed_methods=("GET", "POST"),
            max_requests=10,
        )
        try:
            # 1. Explicit actor refresh_path triggers cookie-based refresh cleanly.
            rec = client.request(method="GET", url="/api/profile", actor="cookie-user")
            assert rec["status"] == 200
            assert [(r["method"], r["path"]) for r in req_log] == [
                ("GET", "/api/profile"),
                ("POST", "/api/auth/cookie-refresh"),
                ("GET", "/api/profile"),
            ]
            sess = actors.get("cookie-user")
            assert sess.cookies["sid"] == fresh_sid
            assert sess.cookies["refresh_sid"] == fresh_rsid

            for rid in store.list_ids():
                raw_text = (tmp_path / "run-cookie-refresh" / "receipts" / f"{rid}.json").read_text(
                    encoding="utf-8"
                )
                for sec in (old_sid, fresh_sid, old_rsid, fresh_rsid):
                    assert sec not in raw_text

            # 2. Cookie-only actor WITHOUT explicit actor refresh_path does NOT hit default refresh_path.
            req_log.clear()
            rec_no_path = client.request(method="GET", url="/api/profile", actor="cookie-no-path")
            assert rec_no_path["status"] == 401
            assert [(r["method"], r["path"]) for r in req_log] == [("GET", "/api/profile")]
        finally:
            client.close()


def test_try_refresh_extracts_mocked_receipt_material_and_propagates_fatal_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ReceiptStore(tmp_path / "mock-refresh")
    actors = ActorManager([
        {
            "alias": "u1",
            "access_token": "tok-old-1111",
            "refresh_token": "rt-old-1111",
            "refresh_path": "/api/auth/refresh",
        }
    ])
    client = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080/",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=10,
    )
    try:
        # Mock _send_wire returning response_headers + body directly in r_receipt.
        def _fake_send_wire(**_kwargs: Any) -> dict[str, Any]:
            return {
                "status": 200,
                "response_headers": {
                    "Set-Cookie": "sid=mock-cookie-2222; Path=/",
                    "X-CSRF-Token": "mock-csrf-2222",
                },
                "body": json.dumps({
                    "access_token": "mock-tok-2222",
                    "refresh_token": "mock-rt-2222",
                }),
            }

        monkeypatch.setattr(client, "_send_wire", _fake_send_wire)
        assert client._try_refresh_actor_session("u1") is True
        sess = actors.get("u1")
        assert sess.access_token == "mock-tok-2222"
        assert sess.refresh_token == "mock-rt-2222"
        assert sess.csrf_token == "mock-csrf-2222"
        assert sess.cookies["sid"] == "mock-cookie-2222"
        assert "mock-tok-2222" in actors.all_secrets()
        assert "tok-old-1111" in actors.all_secrets()

        # BudgetExhaustedError and ServiceDegradationError must never be swallowed.
        def _raise_budget(**_kwargs: Any) -> dict[str, Any]:
            raise BudgetExhaustedError("budget exhausted")

        monkeypatch.setattr(client, "_send_wire", _raise_budget)
        with pytest.raises(BudgetExhaustedError):
            client._try_refresh_actor_session("u1")

        def _raise_degradation(**_kwargs: Any) -> dict[str, Any]:
            raise ServiceDegradationError("service degraded")

        monkeypatch.setattr(client, "_send_wire", _raise_degradation)
        with pytest.raises(ServiceDegradationError):
            client._try_refresh_actor_session("u1")
    finally:
        client.close()
