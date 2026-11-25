"""Tests for multi-origin authorized scope support across ScopeGuard, AgenticHTTPClient, runner, and wizard."""
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

import agentic_runner  # noqa: E402
import agentic_wizard  # noqa: E402
import target_bootstrap as tb  # noqa: E402
from agentic_http import (  # noqa: E402
    ActorManager,
    AgenticHTTPClient,
    ScopeViolationError,
)
from agentic_receipts import ReceiptStore  # noqa: E402


# ---------------------------------------------------------------------------
# 1. ScopeGuard single-origin default & multi-origin rule evaluation
# ---------------------------------------------------------------------------


def test_scope_guard_single_origin_default_remains_strictly_locked() -> None:
    guard = tb.ScopeGuard("https://www.target.example", excluded_paths=("/logout",))

    assert guard.is_multi_origin is False
    assert guard.check_origin("https", "www.target.example", 443) is True
    assert guard.check_origin("https", "bff.target.example", 443) is False
    assert guard.check_origin("http", "www.target.example", 80) is False

    guard.check_url("/api/v1/me")
    guard.check_url("https://www.target.example/api/v1/me")

    for bad in (
        "https://bff.target.example/v1/orders",
        "https://evil.example/steal",
        "http://www.target.example/api/v1/me",
        "/logout",
    ):
        with pytest.raises(ValueError):
            guard.check_url(bad)


def test_scope_guard_multi_origin_wildcard_siblings_exclusions_and_fail_closed() -> None:
    guard = tb.ScopeGuard(
        "https://www.target.example",
        excluded_paths=("/logout", "/account/*/close"),
        in_scope_assets=(
            "*.target.example",
            "https://api.partner.example",
            "https://ws.target.example:8443",
        ),
        out_of_scope_assets=(
            "admin.target.example",
            "*.internal.target.example",
            "https://bff.target.example/internal/debug",
            "DoS / load testing",
        ),
    )

    assert guard.is_multi_origin is True
    assert guard.check_origin("https", "www.target.example", 443) is True
    assert guard.check_origin("https", "bff.target.example", 443) is True
    assert guard.check_origin("https", "auth.target.example", 443) is True
    assert guard.check_origin("https", "api.partner.example", 443) is True
    assert guard.check_origin("https", "ws.target.example", 8443) is True
    assert guard.check_origin("https", "admin.target.example", 443) is False
    assert guard.check_origin("https", "db.internal.target.example", 443) is False
    assert guard.check_origin("https", "evil.example", 443) is False
    assert guard.check_origin("http", "api.partner.example", 80) is False
    assert guard.check_origin("ftp", "bff.target.example", 21) is False
    assert guard.check_origin("https", "bff.target.example", -1) is False

    for allowed in (
        "/home",
        "https://www.target.example/internal/debug",
        "https://bff.target.example/v1/orders?limit=10",
        "https://auth.target.example/oauth/authorize",
        "https://sub.a.target.example/health",
        "https://api.partner.example/v2/status",
        "https://ws.target.example:8443/stream",
    ):
        guard.check_url(allowed)

    for blocked in (
        "https://evil.example/api",
        "https://cdn.other.com/bundle.js",
        "https://target.example/apex-not-covered-by-wildcard",
        "https://nottarget.example/spoof",
        "https://target.example.evil.com/spoof",
        "https://admin.target.example/users",
        "https://db.internal.target.example/query",
        "https://bff.target.example/internal/debug",
        "https://bff.target.example/INTERNAL/DEBUG/vars",
        "https://bff.target.example/v1/../internal/debug",
        "https://bff.target.example/logout",
        "https://auth.target.example/account/42/close",
        "https://bff.target.example/api/manager/reboot",
        "http://api.partner.example/v2/status",
        "https://api.partner.example:8443/v2/status",
        "//bff.target.example/scheme-relative",
        "https://user:pass@bff.target.example/v1/orders",
        "https://bff.target.example/v1\r\nX-Inject: 1",
    ):
        with pytest.raises(ValueError):
            guard.check_url(blocked)


def test_scope_guard_single_matching_in_scope_asset_is_not_multi_origin() -> None:
    guard = tb.ScopeGuard(
        "https://www.target.example/",
        in_scope_assets=("https://www.target.example/",),
    )
    assert guard.is_multi_origin is False
    guard.check_url("https://www.target.example/ok")
    with pytest.raises(ValueError):
        guard.check_url("https://bff.target.example/no")


# ---------------------------------------------------------------------------
# 2. resolve_target_origin multi-origin scope_meta & loopback strictness
# ---------------------------------------------------------------------------


def test_resolve_target_origin_extracts_multi_origin_assets_and_preserves_loopback(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps({
            "in_scope": [
                {"asset": "https://www.target.example"},
                "*.target.example",
                {"url": "https://auth.target.example"},
            ],
            "out_of_scope": [
                "admin.target.example",
                {"asset": "https://bff.target.example/internal"},
                "/logout",
                "DoS / load testing",
            ],
            "excluded_assets": [
                "staging.target.example",
            ],
            "excluded_paths": ["/health/shutdown"],
            "custom_headers": {"Pentest": "Cyberbounty"},
        }),
        encoding="utf-8",
    )

    origin, meta = tb.resolve_target_origin(
        "https://www.target.example",
        scope_file=scope_file,
        allow_non_loopback=True,
    )
    assert origin == "https://www.target.example/"
    assert meta["loopback_only"] is False
    assert meta["scope_file"] == str(scope_file.resolve())
    assert meta["matched_in_scope"] == "https://www.target.example"
    assert meta["custom_headers"] == {"Pentest": "Cyberbounty"}
    assert set(meta["excluded_paths"]) == {"/health/shutdown", "/logout"}
    assert meta["in_scope_assets"] == [
        "https://www.target.example",
        "*.target.example",
        "https://auth.target.example",
    ]
    assert meta["out_of_scope_assets"] == [
        "admin.target.example",
        "https://bff.target.example/internal",
        "staging.target.example",
    ]

    # Loopback-only mode stays strictly loopback-only even when scope_file has remote assets.
    lb_origin, lb_meta = tb.resolve_target_origin(
        "http://127.0.0.1:18080",
        scope_file=scope_file,
        allow_non_loopback=False,
    )
    assert lb_origin == "http://127.0.0.1:18080/"
    assert lb_meta["loopback_only"] is True
    assert "in_scope_assets" not in lb_meta

    with pytest.raises(ValueError):
        tb.resolve_target_origin("https://www.target.example", scope_file=scope_file, allow_non_loopback=False)


# ---------------------------------------------------------------------------
# 3. Live multi-origin HTTP client test (2 authorized ports + 1 unauthorized)
# ---------------------------------------------------------------------------


def _start_echo_server(
    label: str,
    *,
    redirect_to: str = "",
    unauthorized_redirect_to: str = "",
) -> tuple[ThreadingHTTPServer, str, list[dict[str, Any]]]:
    observed: list[dict[str, Any]] = []
    lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            parsed = urlsplit(self.path)
            with lock:
                observed.append({
                    "server": label,
                    "path": parsed.path,
                    "query": parsed.query,
                    "headers": hdrs,
                })
            if parsed.path == "/sso" and redirect_to:
                self.send_response(302)
                self.send_header("Location", redirect_to)
                self.send_header("Set-Cookie", "hop_session=hopval-1; Path=/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if parsed.path == "/open-redirect" and unauthorized_redirect_to:
                self.send_response(302)
                self.send_header("Location", unauthorized_redirect_to)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = json.dumps({"server": label, "path": parsed.path, "query": parsed.query}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/", observed


def test_http_client_multi_origin_requests_redirects_headers_and_blocking(tmp_path: Path) -> None:
    srv3, url3, obs3 = _start_echo_server("unauthorized")
    srv2, url2, obs2 = _start_echo_server("bff")
    srv1, url1, obs1 = _start_echo_server(
        "web",
        redirect_to=f"{url2.rstrip('/')}/callback?code=ok",
        unauthorized_redirect_to=f"{url3.rstrip('/')}/steal",
    )

    actors = ActorManager(
        [
            {
                "alias": "member-a",
                "role": "member",
                "auth_header": "Bearer tok-multi-123",
                "cookies": {"sid": "actor-cookie-1"},
            }
        ],
        global_headers={"Pentest": "Cyberbounty"},
    )
    store = ReceiptStore(tmp_path / "run")
    client = AgenticHTTPClient(
        base_url=url1,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "HEAD"),
        max_requests=30,
        excluded_paths=("/logout",),
        in_scope_assets=(url2,),
        out_of_scope_assets=(f"{url2.rstrip('/')}/blocked",),
    )
    try:
        # 1. Relative URL still hits base_url (port1) with global + actor headers.
        r1 = client.request(method="GET", url="/api/front", actor="member-a")
        assert r1["status"] == 200
        assert json.loads(r1["body"])["server"] == "web"

        # 2. Explicit sibling origin URL hits port2 with global + actor headers + cookies.
        r2 = client.request(
            method="GET",
            url=f"{url2.rstrip('/')}/v1/orders",
            query={"page": "2"},
            actor="member-a",
        )
        assert r2["status"] == 200
        assert json.loads(r2["body"]) == {"server": "bff", "path": "/v1/orders", "query": "page=2"}

        # 3. Origin-specific excluded path blocked on port2, allowed on port1.
        with pytest.raises(ScopeViolationError):
            client.request(method="GET", url=f"{url2.rstrip('/')}/blocked/secret", actor="member-a")
        r1_ok = client.request(method="GET", url="/blocked/secret", actor="member-a")
        assert r1_ok["status"] == 200

        # 4. Global excluded path blocked on both origins.
        with pytest.raises(ScopeViolationError):
            client.request(method="GET", url=f"{url2.rstrip('/')}/logout", actor="member-a")

        # 5. Direct request to unauthorized port3 is strictly blocked with zero wire traffic.
        used_before = client.budget.used
        with pytest.raises(ScopeViolationError):
            client.request(method="GET", url=f"{url3.rstrip('/')}/leak", actor="member-a")
        assert client.budget.used == used_before
        assert obs3 == []

        # 6. Redirect from authorized port1 -> authorized port2 succeeds with hop cookies & headers.
        r_redir = client.request(
            method="GET",
            url="/sso",
            actor="member-a",
            follow_redirects=True,
        )
        assert r_redir["status"] == 200
        assert json.loads(r_redir["body"])["server"] == "bff"
        assert len(r_redir["redirect_chain"]) == 1
        assert r_redir["redirect_chain"][0]["url"] == f"{url1.rstrip('/')}/sso"

        # 7. Redirect from port1 -> unauthorized port3 is blocked before hitting port3.
        with pytest.raises(ScopeViolationError):
            client.request(
                method="GET",
                url="/open-redirect",
                actor="member-a",
                follow_redirects=True,
            )
        assert obs3 == []

        # 8. WebSocket scope resolution supports authorized sibling origins and rejects unauthorized ones.
        ws_port2 = urlsplit(url2).port
        ws_port3 = urlsplit(url3).port
        clean_ws, ws_path, _ = client.resolve_in_scope(f"ws://127.0.0.1:{ws_port2}/stream")
        assert clean_ws == f"ws://127.0.0.1:{ws_port2}/stream"
        assert ws_path == "/stream"
        with pytest.raises(ScopeViolationError):
            client.resolve_in_scope(f"ws://127.0.0.1:{ws_port3}/stream")
        with pytest.raises(ScopeViolationError):
            client.resolve_in_scope(f"ws://127.0.0.1:{ws_port2}/blocked/stream")

        # Verify wire headers observed on port2 (direct call + redirect callback).
        assert len(obs2) == 2
        for req in obs2:
            assert req["headers"]["pentest"] == "Cyberbounty"
            assert req["headers"]["authorization"] == "Bearer tok-multi-123"
            assert "sid=actor-cookie-1" in req["headers"]["cookie"]
        assert "hop_session=hopval-1" in obs2[1]["headers"]["cookie"]
        assert obs1[0]["headers"]["pentest"] == "Cyberbounty"
    finally:
        client.close()
        srv1.shutdown()
        srv1.server_close()
        srv2.shutdown()
        srv2.server_close()
        srv3.shutdown()
        srv3.server_close()


# ---------------------------------------------------------------------------
# 4. Runner plan metadata & wizard inline multi-origin scope authoring
# ---------------------------------------------------------------------------


def test_runner_plan_records_multi_origin_scope_metadata(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps({
            "in_scope": [
                "https://www.target.example",
                "*.target.example",
                "https://auth.target.example",
            ],
            "out_of_scope": [
                "admin.target.example",
                "/logout",
            ],
        }),
        encoding="utf-8",
    )

    _, multi_plan = agentic_runner.run_agentic_target(
        target="https://www.target.example",
        provider_config=REPO_ROOT / "config" / "llm.example.json",
        output_dir=tmp_path / "multi-plan",
        scope_file=scope_file,
        allow_non_loopback=True,
        execute=False,
    )
    assert multi_plan["scope"]["loopback_only"] is False
    assert multi_plan["scope"]["multi_origin"] is True
    assert multi_plan["scope"]["in_scope_assets_count"] == 3
    assert multi_plan["scope"]["excluded_paths_count"] == 1
    assert multi_plan["scope"]["scope_file"] == str(scope_file.resolve())

    _, loopback_plan = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18080/",
        provider_config=REPO_ROOT / "config" / "llm.example.json",
        output_dir=tmp_path / "loopback-plan",
        execute=False,
    )
    assert loopback_plan["scope"]["loopback_only"] is True
    assert loopback_plan["scope"]["multi_origin"] is False
    assert loopback_plan["scope"]["in_scope_assets_count"] == 0


def test_wizard_inline_multi_origin_scope_creates_scope_json_without_extra_prompts(tmp_path: Path) -> None:
    out_dir = tmp_path / "wizard-multi"
    logs: list[str] = []
    called_runner: list[list[str]] = []

    answers = iter([
        "https://www.target.example",                          # 1) target
        "https://user:pass@evil.example",                      # 2) invalid inline origin -> re-prompted cleanly
        "*.target.example, https://auth.partner.example",      # 2) valid inline wildcard + sibling origin
        "/logout,/admin/delete",                               # 2b) excluded paths
        "3",                                                   # 3) preset
        "",                                                    # 4) default methods
        "",                                                    # 5) no custom headers
        "",                                                    # 6) anon
        str(out_dir),                                          # 7) output_dir
        "h",                                                   # decline live execution
    ])

    rc = agentic_wizard.run_wizard(
        provider_config=REPO_ROOT / "config" / "llm.example.json",
        input_fn=lambda _prompt: next(answers),
        output_fn=logs.append,
        runner_main=lambda argv: (called_runner.append(argv), 0)[1],
        workdir=tmp_path,
        cwd=tmp_path,
        environ={},
    )
    assert rc == 0
    assert called_runner == []
    assert any("Kapsam hatasi:" in line for line in logs)

    scope_doc = json.loads((out_dir / "scope.json").read_text(encoding="utf-8"))
    assert scope_doc["in_scope"] == [
        "https://www.target.example/",
        "*.target.example",
        "https://auth.partner.example",
    ]
    assert scope_doc["excluded_paths"] == ["/logout", "/admin/delete"]

    plan = json.loads((out_dir / "agentic-plan.json").read_text(encoding="utf-8"))
    assert plan["scope"]["multi_origin"] is True
    assert plan["scope"]["in_scope_assets_count"] == 3


def test_seed_merge_preserves_authorized_multi_origin_sibling_routes_and_drops_unauthorized() -> None:
    import agentic_seed

    stage0_like = {
        "schema": "stage0-seed/1",
        "links": [
            {"method": "GET", "url": "/hesabim/orders", "params": ["page"], "status": 200},
            {"method": "POST", "url": "https://bff.target.example/api/v1/cart", "params": ["itemId"], "status": 200},
            {"method": "GET", "url": "https://admin.target.example/secret", "params": [], "status": 200},
            {"method": "GET", "url": "https://evil.example/steal", "params": [], "status": 200},
        ],
    }
    merged = agentic_seed.merge_seed_surfaces(
        [stage0_like],
        base_url="https://www.target.example/",
        in_scope_assets=("*.target.example",),
        out_of_scope_assets=("admin.target.example",),
    )
    assert merged is not None
    urls = {item["url"] for item in merged["links"]}
    assert "/hesabim/orders" in urls
    assert "https://bff.target.example/api/v1/cart" in urls
    assert not any("admin.target.example" in u for u in urls)
    assert not any("evil.example" in u for u in urls)

