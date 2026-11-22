"""Unit tests for target_bootstrap decoupling, scope guard, service degradation, and browser auth state."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import target_bootstrap as tb  # noqa: E402
from agentic_http import (  # noqa: E402
    ActorManager,
    AgenticHTTPClient,
    ScopeViolationError,
    ServiceDegradationError,
)
from agentic_receipts import ReceiptStore  # noqa: E402


# ---------------------------------------------------------------------------
# 1. Import decoupling: zero transitive heavy/legacy engine imports
# ---------------------------------------------------------------------------


def test_target_bootstrap_has_zero_forbidden_transitive_imports() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SCRIPTS_DIR)
    code = (
        "import json, sys, target_bootstrap; "
        "print(json.dumps(sorted(sys.modules.keys())))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    loaded = set(json.loads(proc.stdout))

    forbidden_exact = {
        "external_target_runner",
        "full_agent_python_solver",
        "full_agent_python_broker",
        "full_agent_broker",
        "full_agent_budget",
        "full_agent_provider",
        "full_agent_launcher",
        "full_agent_preflight",
        "brain",
        "campaign_runtime",
        "campaign_worker",
        "policy_engine",
        "requests",
    }
    assert loaded.isdisjoint(forbidden_exact), f"Forbidden modules loaded: {sorted(loaded & forbidden_exact)}"
    forbidden_prefixes = ("full_agent_", "campaign_")
    prefixed_hits = [m for m in loaded if m.startswith(forbidden_prefixes)]
    assert not prefixed_hits, f"Forbidden prefixed modules loaded: {sorted(prefixed_hits)}"


# ---------------------------------------------------------------------------
# 2. Bootstrap helpers
# ---------------------------------------------------------------------------


def test_normalize_loopback_origin_validation() -> None:
    assert tb.normalize_loopback_origin("http://127.0.0.1:8080") == "http://127.0.0.1:8080/"
    assert tb.normalize_loopback_origin("http://127.0.0.1:18901/") == "http://127.0.0.1:18901/"

    for bad in (
        "",
        "https://127.0.0.1:8080/",
        "http://localhost:8080/",
        "http://127.0.0.1/",
        "https://example.com/",
        "http://127.0.0.1:8080/api",
        "http://127.0.0.1:8080/?a=1",
        "http://127.0.0.1:8080/#frag",
        "http://user:pass@127.0.0.1:8080/",
    ):
        with pytest.raises(ValueError):
            tb.normalize_loopback_origin(bad)


def test_load_credentials_bundle_and_select_representative_accounts(tmp_path: Path) -> None:
    assert tb.load_credentials_bundle(None) == {}

    valid_bundle = tmp_path / "creds.json"
    valid_bundle.write_text(json.dumps({"target_url": "http://127.0.0.1:8080", "test_accounts": []}), encoding="utf-8")
    assert tb.load_credentials_bundle(valid_bundle)["target_url"] == "http://127.0.0.1:8080"

    bad_bundle = tmp_path / "bad-creds.json"
    bad_bundle.write_text(json.dumps(["not-a-dict"]), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        tb.load_credentials_bundle(bad_bundle)

    accounts = [
        {"alias": "adm-1", "tenant": "t1", "role": "platform_admin", "password": "p1"},
        {"alias": "adm-2", "tenant": "t2", "role": "superadmin", "password": "p2"},
        {"alias": "m-t1-a", "tenant": "t1", "role": "member", "password": "p3"},
        {"alias": "m-t1-b", "tenant": "t1", "role": "member", "password": "p4"},
        {"alias": "m-t2-a", "tenant": "t2", "role": "viewer", "password": "p5"},
        {"alias": "no-pass", "tenant": "t3", "role": "member"},
    ]
    selected = tb.select_representative_accounts(accounts, max_members=3, max_admins=1)
    aliases = [row["alias"] for row in selected]
    assert aliases == ["m-t1-a", "m-t2-a", "m-t1-b", "adm-1"]

    with pytest.raises(ValueError, match="non-negative"):
        tb.select_representative_accounts(accounts, max_members=-1)


# ---------------------------------------------------------------------------
# 3. load_scope_file & resolve_target_origin & ScopeGuard
# ---------------------------------------------------------------------------


def test_load_scope_file_strict_validation_and_symlink_rejection(tmp_path: Path) -> None:
    real_scope = tmp_path / "scope.json"
    real_scope.write_text(
        json.dumps({"in_scope": [{"asset": "https://example.com"}], "excluded_paths": ["/logout"]}),
        encoding="utf-8",
    )
    loaded = tb.load_scope_file(real_scope)
    assert loaded["in_scope"] == [{"asset": "https://example.com"}]

    # Symlink to a valid file must be rejected.
    sym = tmp_path / "scope-link.json"
    sym.symlink_to(real_scope)
    with pytest.raises(ValueError, match="symlink"):
        tb.load_scope_file(sym)

    # Dangling symlink must also be rejected cleanly.
    dangling = tmp_path / "dangling-link.json"
    dangling.symlink_to(tmp_path / "nonexistent.json")
    with pytest.raises(ValueError, match="symlink"):
        tb.load_scope_file(dangling)

    # Missing file, directory, invalid JSON, non-object JSON, and invalid field types.
    with pytest.raises(ValueError):
        tb.load_scope_file(tmp_path / "missing.json")
    with pytest.raises(ValueError, match="regular file"):
        tb.load_scope_file(tmp_path)

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError, match="valid JSON"):
        tb.load_scope_file(bad_json)

    arr_json = tmp_path / "array.json"
    arr_json.write_text(json.dumps(["https://example.com"]), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        tb.load_scope_file(arr_json)

    bad_field = tmp_path / "bad-field.json"
    bad_field.write_text(json.dumps({"in_scope": "https://example.com"}), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON array"):
        tb.load_scope_file(bad_field)


def test_resolve_target_origin_default_loopback_and_fail_closed_non_loopback(tmp_path: Path) -> None:
    origin, meta = tb.resolve_target_origin("http://127.0.0.1:8080")
    assert origin == "http://127.0.0.1:8080/"
    assert meta == {"loopback_only": True, "excluded_paths": [], "scope_file": None}

    with pytest.raises(ValueError):
        tb.resolve_target_origin("https://example.com")

    # Fail-closed when allow_non_loopback=True without explicit scope_file.
    with pytest.raises(ValueError, match="scope_file"):
        tb.resolve_target_origin("https://example.com", allow_non_loopback=True)

    # Also fail-closed if scope_file does not exist.
    with pytest.raises(ValueError):
        tb.resolve_target_origin(
            "https://example.com",
            scope_file=tmp_path / "missing-scope.json",
            allow_non_loopback=True,
        )


def test_resolve_target_origin_in_scope_out_of_scope_and_excluded_paths(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps({
            "in_scope": [
                {"asset": "https://exact.example.com"},
                {"asset": "hostonly.example.com"},
                {"asset": "*.wild.example.com"},
                "plain.example.org",
            ],
            "out_of_scope": [
                "blocked.wild.example.com",
                {"asset": "*.internal.wild.example.com"},
                {"asset": "https://exact.example.com/billing/delete"},
                "/logout",
                "DoS / load testing",
                "all other hosts, ports and subdomains",
            ],
            "excluded_paths": ["/admin/destroy", "/account/*/close"],
            "allow_loopback": False,
        }),
        encoding="utf-8",
    )

    # Exact URL match (including implicit default port 443).
    origin, meta = tb.resolve_target_origin(
        "https://exact.example.com:443",
        scope_file=scope_file,
        allow_non_loopback=True,
    )
    assert origin == "https://exact.example.com/"
    assert meta["loopback_only"] is False
    assert meta["scope_file"] == str(scope_file.resolve())
    assert set(meta["excluded_paths"]) == {
        "/admin/destroy",
        "/account/*/close",
        "/billing/delete",
        "/logout",
    }

    # Wrong scheme or port against exact https:// asset must be rejected.
    with pytest.raises(ValueError, match="not authorized"):
        tb.resolve_target_origin("http://exact.example.com", scope_file=scope_file, allow_non_loopback=True)
    with pytest.raises(ValueError, match="not authorized"):
        tb.resolve_target_origin("https://exact.example.com:8443", scope_file=scope_file, allow_non_loopback=True)

    # Host-only asset matches both http and https and custom ports.
    host_origin, _ = tb.resolve_target_origin(
        "http://hostonly.example.com:8080",
        scope_file=scope_file,
        allow_non_loopback=True,
    )
    assert host_origin == "http://hostonly.example.com:8080/"

    # Plain string entry matches.
    plain_origin, _ = tb.resolve_target_origin(
        "https://plain.example.org/",
        scope_file=scope_file,
        allow_non_loopback=True,
    )
    assert plain_origin == "https://plain.example.org/"

    # Wildcard matches subdomains and multi-level subdomains, but NOT apex or suffix spoofing.
    wild_origin, wild_meta = tb.resolve_target_origin(
        "https://api.wild.example.com",
        scope_file=scope_file,
        allow_non_loopback=True,
    )
    assert wild_origin == "https://api.wild.example.com/"
    # Path entry for exact.example.com must NOT leak onto api.wild.example.com.
    assert "/billing/delete" not in wild_meta["excluded_paths"]
    assert "/logout" in wild_meta["excluded_paths"]

    for rejected in (
        "https://wild.example.com",
        "https://notwild.example.com",
        "https://wild.example.com.evil.com",
        "https://blocked.wild.example.com",
        "https://db.internal.wild.example.com",
        "https://user:pw@api.wild.example.com",
        "https://api.wild.example.com/with/path",
        "https://api.wild.example.com/?q=1",
        "https://api.wild.example.com/#frag",
    ):
        with pytest.raises(ValueError):
            tb.resolve_target_origin(rejected, scope_file=scope_file, allow_non_loopback=True)


def test_scope_guard_origin_and_excluded_path_matching() -> None:
    guard = tb.ScopeGuard(
        "https://app.example.com",
        ("/logout", "/billing/delete", "/admin/*/purge"),
    )
    # Allowed in-origin paths (exact segment prefix does NOT over-block siblings).
    for ok_url in (
        "/",
        "/api/v1/items",
        "/logout-info",
        "/logout_status",
        "/billing",
        "/billing/deleted-archive",
        "https://app.example.com/api/v1/profile?tab=1",
        "https://app.example.com:443/api/v1/profile",
    ):
        guard.check_url(ok_url)

    # Blocked out-of-origin and excluded paths (case-insensitive, traversal, percent-encoded, glob).
    for bad_url in (
        "https://evil.example.com/api",
        "http://app.example.com/api",
        "https://app.example.com:8443/api",
        "//evil.example.com/api",
        "/logout",
        "/LOGOUT",
        "/logout/",
        "/logout/all",
        "/logout?next=/",
        "/api/../logout",
        "/api/%2e%2e/logout",
        "/%6cogout",
        "/billing/delete",
        "/Billing/Delete/42",
        "/admin/t1/purge",
        "/admin/t1/purge/confirm",
    ):
        with pytest.raises(ValueError):
            guard.check_url(bad_url)


# ---------------------------------------------------------------------------
# 4. AgenticHTTPClient excluded_paths & ServiceDegradationError
# ---------------------------------------------------------------------------


def _start_sequence_server(statuses: list[int], *, retry_after: str = "0.2") -> tuple[ThreadingHTTPServer, str, dict[str, Any]]:
    state: dict[str, Any] = {"index": 0, "paths": [], "lock": threading.Lock()}

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            with state["lock"]:
                state["paths"].append(parsed.path)
                idx = state["index"]
                status = statuses[idx] if idx < len(statuses) else 200
                state["index"] = idx + 1
            body = json.dumps({"status": status, "path": parsed.path, "seq": idx}).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if status == 429:
                self.send_header("Retry-After", retry_after)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else "{}"
            data = json.loads(raw) if raw else {}
            if urlsplit(self.path).path == "/api/v1/access/sign-in":
                if data.get("password") == "TopSecretPass!":
                    body = json.dumps({
                        "access_token": "tok-live-bearer-1",
                        "csrf_token": "csrf-live-1",
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Set-Cookie", "sid=live-cookie-1; Path=/; HttpOnly")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, f"http://127.0.0.1:{srv.server_port}", state


def test_http_client_blocks_excluded_paths_before_wire(tmp_path: Path) -> None:
    srv, base_url, state = _start_sequence_server([200, 200])
    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        allowed_methods=("GET",),
        max_requests=20,
        excluded_paths=("/logout", "/billing/delete"),
    )
    try:
        for blocked in ("/logout", "/LOGOUT/all", "/api/../logout", "/billing/delete/99"):
            with pytest.raises(ScopeViolationError):
                client.request(method="GET", url=blocked)
        assert state["paths"] == []
        assert client.budget.used == 0

        # Non-excluded sibling path succeeds.
        rec = client.request(method="GET", url="/logout-info")
        assert rec["status"] == 200
        assert state["paths"] == ["/logout-info"]
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_http_client_service_degradation_triggers_resets_and_disables(tmp_path: Path) -> None:
    # Sequence: 502, 503, 200 (reset!), 504, 503, 404 (reset!), 502, 503, 504 (streak=3 -> raises!).
    statuses = [502, 503, 200, 504, 503, 404, 502, 503, 504]
    srv, base_url, _state = _start_sequence_server(statuses)
    store = ReceiptStore(tmp_path / "run1")
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        allowed_methods=("GET",),
        max_requests=50,
        max_degradation_streak=3,
    )
    try:
        for idx in range(8):
            rec = client.request(method="GET", url=f"/probe/{idx}", force=True)
            assert rec["status"] == statuses[idx]
        # 9th response (504) hits 3 consecutive degraded responses -> records receipt AND raises.
        with pytest.raises(ServiceDegradationError, match="3 consecutive"):
            client.request(method="GET", url="/probe/8", force=True)
        # All 9 receipts (including the triggering 504) must be recorded.
        recorded_statuses = [store.get(rid)["status"] for rid in store.list_ids()]
        assert recorded_statuses == statuses
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()

    # Dedicated HTTP 429 streak test (with budget headroom <= 4 so each call issues 1 wire request).
    srv429, base_429, _ = _start_sequence_server([429, 429, 429], retry_after="0.2")
    store429 = ReceiptStore(tmp_path / "run429")
    client429 = AgenticHTTPClient(
        base_url=base_429,
        receipt_store=store429,
        allowed_methods=("GET",),
        max_requests=4,
        max_degradation_streak=3,
    )
    try:
        assert client429.request(method="GET", url="/rate/1", force=True)["status"] == 429
        assert client429.request(method="GET", url="/rate/2", force=True)["status"] == 429
        with pytest.raises(ServiceDegradationError, match="3 consecutive"):
            client429.request(method="GET", url="/rate/3", force=True)
        assert [store429.get(rid)["status"] for rid in store429.list_ids()] == [429, 429, 429]
    finally:
        client429.close()
        srv429.shutdown()
        srv429.server_close()

    # max_degradation_streak=0 disables degradation raising cleanly.
    srv_off, base_off, _ = _start_sequence_server([503] * 6)
    store_off = ReceiptStore(tmp_path / "run_off")
    client_off = AgenticHTTPClient(
        base_url=base_off,
        receipt_store=store_off,
        allowed_methods=("GET",),
        max_requests=20,
        max_degradation_streak=0,
    )
    try:
        for idx in range(6):
            rec = client_off.request(method="GET", url=f"/off/{idx}", force=True)
            assert rec["status"] == 503
    finally:
        client_off.close()
        srv_off.shutdown()
        srv_off.server_close()


# ---------------------------------------------------------------------------
# 5. ActorManager.get_browser_auth_state
# ---------------------------------------------------------------------------


def test_actor_manager_get_browser_auth_state_and_no_secret_leak(tmp_path: Path) -> None:
    srv, base_url, _ = _start_sequence_server([200])
    actors = ActorManager([
        {
            "alias": "preauth-bearer",
            "role": "member",
            "tenant": "t1",
            "auth_header": "Bearer tok-preauth-1",
            "password": "NeverExposePassword1!",
            "email": "preauth@example.test",
        },
        {
            "alias": "preauth-cookie",
            "role": "member",
            "tenant": "t1",
            "cookie": "sid=cookie-val-1; theme=dark",
            "password": "NeverExposePassword2!",
        },
        {
            "alias": "login-actor",
            "role": "member",
            "tenant": "t1",
            "email": "login@example.test",
            "password": "TopSecretPass!",
        },
    ])
    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET",),
        max_requests=20,
    )
    try:
        # Anonymous actor returns empty dicts.
        assert actors.get_browser_auth_state("anon") == {"cookies": {}, "headers": {}}

        # Pre-authenticated bearer actor exposes Authorization header, never password/login_payload.
        bearer_state = actors.get_browser_auth_state("preauth-bearer")
        assert bearer_state == {
            "cookies": {},
            "headers": {"Authorization": "Bearer tok-preauth-1"},
        }
        assert "NeverExposePassword1!" not in json.dumps(bearer_state)
        assert "password" not in bearer_state
        assert "login_payload" not in bearer_state

        # Mutating returned dict does not mutate internal ActorSession state.
        bearer_state["headers"]["Authorization"] = "Bearer tampered"
        assert actors.get_browser_auth_state("preauth-bearer")["headers"]["Authorization"] == "Bearer tok-preauth-1"

        # Cookie preauth actor exposes cookies dict and does not duplicate Cookie header.
        cookie_state = actors.get_browser_auth_state("preauth-cookie")
        assert cookie_state == {
            "cookies": {"sid": "cookie-val-1", "theme": "dark"},
            "headers": {},
        }
        assert "NeverExposePassword2!" not in json.dumps(cookie_state)

        # Unauthenticated login actor returns empty dicts and never leaks password/login_payload.
        before_login = actors.get_browser_auth_state("login-actor")
        assert before_login == {"cookies": {}, "headers": {}}
        assert "TopSecretPass!" not in json.dumps(before_login)

        # After live login, cookies + bearer + csrf headers are returned without password/login_payload.
        assert client.authenticate_actor("login-actor") is True
        after_login = actors.get_browser_auth_state("login-actor")
        assert after_login["cookies"] == {"sid": "live-cookie-1"}
        assert after_login["headers"]["Authorization"] == "Bearer tok-live-bearer-1"
        assert after_login["headers"]["X-CSRF-Token"] == "csrf-live-1"
        assert "TopSecretPass!" not in json.dumps(after_login)
        assert "login@example.test" not in json.dumps(after_login)
        assert set(after_login.keys()) == {"cookies", "headers"}

        # Unknown actor raises ValueError.
        with pytest.raises(ValueError, match="unknown actor alias"):
            actors.get_browser_auth_state("missing-actor")
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()
