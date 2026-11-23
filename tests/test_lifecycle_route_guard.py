"""Unit tests for Faz 1C destructive operational lifecycle and authenticated actor logout guards."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient, ScopeViolationError  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
import target_bootstrap as tb  # noqa: E402


def _start_recorder_server() -> tuple[ThreadingHTTPServer, str, dict[str, Any]]:
    state: dict[str, Any] = {
        "hits": [],
        "sessions_active": {"admin-sid-1": True},
        "lock": threading.Lock(),
    }

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def _handle(self, method: str) -> None:
            parsed = urlsplit(self.path)
            path = parsed.path
            cookie_hdr = self.headers.get("Cookie", "")
            auth_hdr = self.headers.get("Authorization", "")
            with state["lock"]:
                state["hits"].append({
                    "method": method,
                    "path": path,
                    "query": parsed.query,
                    "cookie": cookie_hdr,
                    "authorization": auth_hdr,
                })

            if path == "/redirect-to-reboot":
                self.send_response(302)
                self.send_header("Location", "/api/manager/reboot")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if path == "/redirect-to-logout":
                self.send_response(302)
                self.send_header("Location", "/admin/Login/logout.html")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if path == "/admin/Login/logout.html":
                if "PHPSESSID=admin-sid-1" in cookie_hdr:
                    with state["lock"]:
                        state["sessions_active"]["admin-sid-1"] = False
                body = json.dumps({"logged_out": True, "cookie": cookie_hdr}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/admin/dashboard":
                with state["lock"]:
                    valid = state["sessions_active"].get("admin-sid-1", False)
                status = 200 if ("PHPSESSID=admin-sid-1" in cookie_hdr and valid) else 401
                body = json.dumps({"ok": status == 200}).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/api/v1/access/sign-in" and method == "POST":
                body = json.dumps({"access_token": "tok-live-login"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "PHPSESSID=admin-sid-1; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            body = json.dumps({"ok": True, "path": path, "method": method}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 0:
                self.rfile.read(length)
            self._handle("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, f"http://127.0.0.1:{srv.server_port}/", state


# ---------------------------------------------------------------------------
# 1. Pure segment matcher unit tests (target_bootstrap)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path_or_url", "expected_segment"),
    [
        ("/api/manager/reboot", "reboot"),
        ("/API/MANAGER/REBOOT", "reboot"),
        ("/api/manager/reboot/", "reboot"),
        ("/api/manager/reboot?force=1", "reboot"),
        ("/api/manager/reboot.json", "reboot"),
        ("/api/manager/reboot/confirm", "reboot"),
        ("/api/safe/../manager/reboot", "reboot"),
        ("/api/manager/%72eboot", "reboot"),
        ("/api/manager/reboot;jsessionid=xyz", "reboot"),
        ("/admin/restart.php", "restart"),
        ("/restart", "restart"),
        ("/shutdown", "shutdown"),
        ("/admin/system/shutdown.php", "shutdown"),
        ("/admin/system/shutdown.php/now", "shutdown"),
        ("/admin/system/shutdown.html", "shutdown"),
        ("/api/system/poweroff", "poweroff"),
        ("/api/system/power-off", "power-off"),
        ("/api/system/power_off", "power-off"),
        ("/halt", "halt"),
        ("/api/worker/kill", "kill"),
        ("/api/worker/terminate", "terminate"),
        ("/stop-server", "stop-server"),
        ("/stop_server", "stop-server"),
        ("/factory-reset", "factory-reset"),
        ("/factory_reset", "factory-reset"),
        ("/reset-db", "reset-db"),
        ("/reset_db", "reset-db"),
        ("/drop-db", "drop-db"),
        ("/drop_db", "drop-db"),
        ("/wipe", "wipe"),
        ("/wipe-db", "wipe-db"),
        ("/wipe_db", "wipe-db"),
        ("http://127.0.0.1:8188/api/manager/reboot", "reboot"),
    ],
)
def test_match_destructive_lifecycle_route_positives(path_or_url: str, expected_segment: str) -> None:
    assert tb.match_destructive_lifecycle_route(path_or_url) == expected_segment
    assert tb.is_destructive_lifecycle_route(path_or_url) is True


@pytest.mark.parametrize(
    "path_or_url",
    [
        "",
        "/",
        "/api/auth/reset-password",
        "/api/password-reset",
        "/api/auth/password_reset",
        "/api/reset",
        "/api/skills",
        "/api/skills/list",
        "/api/skilled",
        "/api/reboots-log",
        "/api/reboot-history",
        "/api/restart-policy",
        "/api/shutdown-schedule",
        "/api/wipeout",
        "/api/after-drop",
        "/static/reboot.css",
        "/assets/reboot.js",
        "/images/shutdown.png",
        "/api/status?next=/api/manager/reboot",
        "/api/items/123",
    ],
)
def test_match_destructive_lifecycle_route_benign_lookalikes_allowed(path_or_url: str) -> None:
    assert tb.match_destructive_lifecycle_route(path_or_url) is None
    assert tb.is_destructive_lifecycle_route(path_or_url) is False


@pytest.mark.parametrize(
    ("path_or_url", "expected_segment"),
    [
        ("/logout", "logout"),
        ("/LOGOUT/", "logout"),
        ("/admin/Login/logout.html", "logout"),
        ("/admin/Login/logout.php", "logout"),
        ("/admin/Login/logout.asp", "logout"),
        ("/admin/Login/logout.aspx", "logout"),
        ("/api/v1/auth/signout", "signout"),
        ("/api/v1/auth/sign-out", "sign-out"),
        ("/api/v1/auth/log-out", "log-out"),
        ("/api/v1/auth/sign_out", "sign_out"),
        ("/api/v1/auth/log_out", "log_out"),
        ("/api/v1/auth/SIGN-OUT.json", "sign-out"),
        ("/admin/Dashboard/../Login/logout.html?next=/", "logout"),
        ("/admin/Login/%6cogout.html", "logout"),
    ],
)
def test_match_logout_route_positives(path_or_url: str, expected_segment: str) -> None:
    assert tb.match_logout_route(path_or_url) == expected_segment
    assert tb.is_logout_route(path_or_url) is True


@pytest.mark.parametrize(
    "path_or_url",
    [
        "",
        "/",
        "/logout-info",
        "/logout_status",
        "/api/logout-hit",
        "/api/logout/status",
        "/static/logout.css",
        "/api/auth/login",
        "/api/status?next=/logout",
    ],
)
def test_match_logout_route_negatives(path_or_url: str) -> None:
    assert tb.match_logout_route(path_or_url) is None
    assert tb.is_logout_route(path_or_url) is False


# ---------------------------------------------------------------------------
# 2. ScopeGuard destructive lifecycle enforcement & opt-in flag
# ---------------------------------------------------------------------------


def test_scope_guard_blocks_destructive_lifecycle_by_default_and_supports_opt_in() -> None:
    guard = tb.ScopeGuard("http://127.0.0.1:8188")

    for bad in (
        "/api/manager/reboot",
        "/admin/restart.php",
        "/shutdown",
        "/api/system/poweroff",
        "/factory-reset",
        "/reset-db",
        "/drop_db",
        "/wipe-db",
        "/api/safe/../reboot",
    ):
        with pytest.raises(ValueError, match="destructive service-lifecycle route blocked"):
            guard.check_url(bad)

    for ok in (
        "/api/auth/reset-password",
        "/api/password-reset",
        "/api/skills/list",
        "/api/skilled",
        "/api/reboots-log",
        "/api/reboot-history",
        "/static/reboot.css",
    ):
        guard.check_url(ok)

    # Per-call opt-in allows lifecycle route cleanly.
    guard.check_url("/api/manager/reboot", allow_lifecycle_routes=True)

    # Instance-level opt-in allows lifecycle routes, while still honoring explicit excluded_paths.
    opt_in_guard = tb.ScopeGuard(
        "http://127.0.0.1:8188",
        excluded_paths=("/admin/restart.php",),
        allow_lifecycle_routes=True,
    )
    opt_in_guard.check_url("/api/manager/reboot")
    with pytest.raises(ValueError, match="excluded by scope pattern"):
        opt_in_guard.check_url("/admin/restart.php")


# ---------------------------------------------------------------------------
# 3. AgenticHTTPClient destructive lifecycle guard (0 budget, 0 wire traffic)
# ---------------------------------------------------------------------------


def test_http_client_blocks_destructive_lifecycle_routes_before_wire_and_allows_lookalikes(
    tmp_path: Path,
) -> None:
    srv, base_url, state = _start_recorder_server()
    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        allowed_methods=("GET", "POST"),
        max_requests=25,
    )
    try:
        destructive_paths = (
            "/api/manager/reboot",
            "/admin/restart.php",
            "/shutdown",
            "/api/system/poweroff",
            "/factory-reset",
            "/reset-db",
            "/drop-db",
            "/wipe-db",
            "/api/system/halt",
            "/api/worker/kill",
            "/api/worker/terminate",
            "/stop_server",
        )
        for path in destructive_paths:
            with pytest.raises(ScopeViolationError, match="destructive service-lifecycle route blocked"):
                client.request(method="GET", url=path)

        # WebSocket lifecycle route is also blocked before wire or budget charge.
        ws_url = base_url.replace("http://", "ws://") + "api/manager/reboot"
        with pytest.raises(ScopeViolationError, match="destructive service-lifecycle route blocked"):
            client.request(method="WS", url=ws_url)

        assert state["hits"] == []
        assert client.budget.used == 0
        assert store.list_ids() == []

        # Benign look-alikes are allowed cleanly and hit the server.
        benign_paths = (
            "/api/auth/reset-password",
            "/api/password-reset",
            "/api/skills/list",
            "/api/reboot-history",
            "/api/reboots-log",
            "/api/skilled",
        )
        for path in benign_paths:
            rec = client.request(method="GET", url=path)
            assert rec["status"] == 200
            assert rec["path"] == path

        assert [h["path"] for h in state["hits"]] == list(benign_paths)
        assert client.budget.used == len(benign_paths)

        # Explicit opt-in via request(..., allow_lifecycle_routes=True) works cleanly.
        rec_opt_in = client.request(
            method="GET",
            url="/api/manager/reboot",
            allow_lifecycle_routes=True,
        )
        assert rec_opt_in["status"] == 200
        assert state["hits"][-1]["path"] == "/api/manager/reboot"

        # Redirect hops to a destructive lifecycle route are also blocked before hitting it.
        state["hits"].clear()
        with pytest.raises(ScopeViolationError, match="destructive service-lifecycle route blocked"):
            client.request(method="GET", url="/redirect-to-reboot", follow_redirects=True, force=True)
        assert [h["path"] for h in state["hits"]] == ["/redirect-to-reboot"]
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_http_client_instance_allow_lifecycle_routes_flag(tmp_path: Path) -> None:
    srv, base_url, state = _start_recorder_server()
    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        allowed_methods=("GET",),
        max_requests=10,
        allow_lifecycle_routes=True,
    )
    try:
        rec = client.request(method="GET", url="/api/manager/reboot")
        assert rec["status"] == 200
        assert [h["path"] for h in state["hits"]] == ["/api/manager/reboot"]
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 4. Active Authenticated Actor Logout Guard
# ---------------------------------------------------------------------------


def test_authenticated_actor_logout_guard_preserves_session_and_allows_safe_paths(
    tmp_path: Path,
) -> None:
    srv, base_url, state = _start_recorder_server()
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {
            "alias": "admin",
            "role": "admin",
            "cookies": {"PHPSESSID": "admin-sid-1"},
        },
        {
            "alias": "login-admin",
            "role": "admin",
            "email": "admin@example.test",
            "password": "AdminPassword123!",
        },
        {
            "alias": "unauth-guest",
            "role": "guest",
        },
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=30,
    )
    try:
        # 1. Authenticated actor calling /admin/Login/logout.html without header override is blocked
        #    at 0 HTTP budget spent, and session remains alive!
        for logout_path in (
            "/admin/Login/logout.html",
            "/admin/Login/logout.php",
            "/admin/Login/logout.asp",
            "/api/auth/signout",
            "/api/auth/sign-out",
            "/api/auth/log-out",
            "/api/auth/sign_out",
            "/api/auth/log_out",
        ):
            with pytest.raises(ScopeViolationError, match="invalidate that actor for other shards"):
                client.request(method="GET", url=logout_path, actor="admin")

        # Empty Authorization/Cookie override does not bypass the logout guard.
        with pytest.raises(ScopeViolationError, match="active authenticated actor logout route blocked"):
            client.request(
                method="GET",
                url="/admin/Login/logout.html",
                actor="admin",
                headers={"Authorization": ""},
            )

        # Provisioned login-credential actor is also blocked at 0 HTTP cost (no wasted login POST).
        with pytest.raises(ScopeViolationError, match="active authenticated actor logout route blocked"):
            client.request(method="GET", url="/admin/Login/logout.html", actor="login-admin")

        assert state["hits"] == []
        assert client.budget.used == 0
        assert state["sessions_active"]["admin-sid-1"] is True

        # Verify admin's session still works on protected endpoint.
        dash_rec = client.request(method="GET", url="/admin/dashboard", actor="admin")
        assert dash_rec["status"] == 200

        # Redirect hop to /admin/Login/logout.html under admin is also blocked before hitting logout.
        state["hits"].clear()
        with pytest.raises(ScopeViolationError, match="active authenticated actor logout route blocked"):
            client.request(
                method="GET",
                url="/redirect-to-logout",
                actor="admin",
                follow_redirects=True,
                force=True,
            )
        assert [h["path"] for h in state["hits"]] == ["/redirect-to-logout"]
        assert state["sessions_active"]["admin-sid-1"] is True

        # 2. Anon calling /admin/Login/logout.html is allowed cleanly.
        state["hits"].clear()
        anon_rec = client.request(method="GET", url="/admin/Login/logout.html", actor="anon")
        assert anon_rec["status"] == 200
        assert [h["path"] for h in state["hits"]] == ["/admin/Login/logout.html"]
        assert state["sessions_active"]["admin-sid-1"] is True

        # 3. Unauthenticated non-anon actor (no credentials/session) is allowed cleanly.
        unauth_rec = client.request(
            method="GET",
            url="/admin/Login/logout.html",
            actor="unauth-guest",
            force=True,
        )
        assert unauth_rec["status"] == 200
        assert state["sessions_active"]["admin-sid-1"] is True

        # 4. Authenticated actor WITH explicit Cookie or Authorization header override is allowed
        #    and does NOT send admin's shared PHPSESSID cookie.
        state["hits"].clear()
        override_cookie_rec = client.request(
            method="GET",
            url="/admin/Login/logout.html",
            actor="admin",
            headers={"Cookie": "PHPSESSID=disposable-sid"},
            force=True,
        )
        assert override_cookie_rec["status"] == 200
        assert state["hits"][-1]["cookie"] == "PHPSESSID=disposable-sid"
        assert state["sessions_active"]["admin-sid-1"] is True

        override_auth_rec = client.request(
            method="GET",
            url="/admin/Login/logout.html",
            actor="admin",
            headers={"Authorization": "Bearer disposable-token"},
            force=True,
        )
        assert override_auth_rec["status"] == 200
        assert state["hits"][-1]["authorization"] == "Bearer disposable-token"
        assert state["hits"][-1]["cookie"] == ""
        assert state["sessions_active"]["admin-sid-1"] is True

        # 5. Non-logout lookalike under authenticated actor is allowed cleanly.
        info_rec = client.request(method="GET", url="/logout-info", actor="admin")
        assert info_rec["status"] == 200

        # 6. Explicit allow_lifecycle_routes=True permits authenticated actor logout when requested.
        explicit_rec = client.request(
            method="GET",
            url="/admin/Login/logout.html",
            actor="admin",
            allow_lifecycle_routes=True,
            force=True,
        )
        assert explicit_rec["status"] == 200
        assert state["sessions_active"]["admin-sid-1"] is False
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()
