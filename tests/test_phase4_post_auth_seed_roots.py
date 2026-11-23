"""Tests for Faz 4A: post-auth Stage 0 entry-point seeding & extra_seed_paths support."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import types
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_investigator  # noqa: E402
import agentic_stage0_crawl  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import (  # noqa: E402
    AgenticInvestigator,
    _derive_login_section_prefixes,
    _extract_json_redirect_targets,
    _extract_receipt_redirect_targets,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_stage0_crawl import (  # noqa: E402
    HAS_PLAYWRIGHT,
    _normalize_stage0_seed_urls,
    run_stage0_crawl,
)
from full_agent_budget import SharedBudget  # noqa: E402


@contextmanager
def _start_loopback_server(
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

        def do_HEAD(self) -> None:
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


def _make_http_client(
    tmp_path: Path,
    *,
    base_url: str = "http://127.0.0.1:18080/",
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST"),
    max_requests: int = 120,
    excluded_paths: tuple[str, ...] = (),
) -> tuple[AgenticHTTPClient, ReceiptStore]:
    store = ReceiptStore(tmp_path / "run")
    actors = ActorManager(accounts or [])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
        excluded_paths=excluded_paths,
    )
    return client, store


class _ScriptedTransport:
    def __init__(self, handler: Callable[[list[dict[str, Any]], int], dict[str, Any]]) -> None:
        self._handler = handler
        self.calls = 0
        self._lock = threading.Lock()

    def complete(
        self,
        body: dict[str, Any],
        *,
        minimum_output_tokens: int = 16,
    ) -> dict[str, Any]:
        del minimum_output_tokens
        messages = list(body.get("messages") or [])
        with self._lock:
            self.calls += 1
            call_num = self.calls
        return self._handler(messages, call_num)


def _tool_resp(tool_name: str, args: dict[str, Any], call_id: str) -> dict[str, Any]:
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {
                                "name": tool_name,
                                "arguments": json.dumps(args),
                            },
                        }
                    ],
                }
            }
        ],
        "usage": {"prompt_tokens": 80, "completion_tokens": 20, "total_tokens": 100},
    }


def _make_investigator(
    tmp_path: Path,
    http: AgenticHTTPClient,
    store: ReceiptStore,
    *,
    transport: Any | None = None,
    stage0_post_auth_enabled: bool = True,
) -> AgenticInvestigator:
    if transport is None:
        transport = _ScriptedTransport(
            lambda _m, n: _tool_resp("finish", {"summary": "done", "untested_areas": []}, f"f_{n}")
        )
    return AgenticInvestigator(
        http_client=http,
        receipt_store=store,
        transport=transport,  # type: ignore[arg-type]
        budget=SharedBudget(http=150, tokens=500_000, seconds=600),
        model="test-model",
        root_dir=tmp_path / "run",
        discovery_hints=["/"],
        max_turns=16,
        bootstrap_turns=6,
        shard_turns=4,
        max_shards=3,
        execution_mode="sharded",
        enable_cross_shard_synthesis=False,
        stage0_post_auth_enabled=stage0_post_auth_enabled,
        stage0_allow_forms=False,
    )


# ---------------------------------------------------------------------------
# 1. Pure helpers: login parent section prefix & JSON/Location redirect parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("login_path", "expected"),
    [
        ("/admin/Login/checkLogin.html", ["/admin/"]),
        ("/portal/auth/login", ["/portal/"]),
        ("/panel/login/submit", ["/panel/"]),
        ("/backoffice/signin.php", ["/backoffice/"]),
        ("/cms/admin/login.php", ["/cms/admin/", "/cms/"]),
        ("/index.php/admin/Login/checkLogin.html", ["/index.php/admin/"]),
        ("/login", []),
        ("/signin.html", []),
        ("/api/auth/login", []),
        ("/api/v1/login", []),
        ("/v1/auth/login", []),
        ("/auth/login", []),
        ("/oauth2/token", []),
        ("/session/create", []),
    ],
)
def test_derive_login_section_prefixes_general_purpose(login_path: str, expected: list[str]) -> None:
    assert _derive_login_section_prefixes(login_path) == expected


def test_derive_login_section_prefixes_allows_generic_only_if_known_html() -> None:
    assert _derive_login_section_prefixes("/auth/login", known_html_paths={"/auth"}) == ["/auth/"]
    assert _derive_login_section_prefixes("/api/login", known_html_paths={"/home"}) == []


def test_extract_redirect_targets_from_location_and_json_body() -> None:
    rec = {
        "redirect_location": "/admin/home",
        "response_headers": {"Location": "/admin/fallback"},
        "body": json.dumps({
            "code": 1,
            "redirect": "/portal/dashboard",
            "redirect_url": "/portal/overview",
            "next": "/panel/start",
            "url": "/admin/Index/index.html",
            "data": {"redirectUrl": "/console/main", "url": "bad value with spaces"},
        }),
    }
    targets = _extract_receipt_redirect_targets(rec)
    assert targets == [
        "/admin/home",
        "/admin/fallback",
        "/portal/dashboard",
        "/portal/overview",
        "/panel/start",
        "/admin/Index/index.html",
        "/console/main",
    ]
    assert _extract_json_redirect_targets("not json") == []
    assert _extract_json_redirect_targets(json.dumps({"url": "<REDACTED_SECRET:sha256_8=12345678>"})) == []


# ---------------------------------------------------------------------------
# 2. AgenticInvestigator post-auth seed path derivation
# ---------------------------------------------------------------------------


def test_derive_post_auth_seed_paths_from_location_parent_and_auth_gated_pages(tmp_path: Path) -> None:
    base_url = "http://127.0.0.1:18080/"
    http, store = _make_http_client(
        tmp_path,
        base_url=base_url,
        accounts=[],
        excluded_paths=("/excluded",),
    )
    inv = _make_investigator(tmp_path, http, store)

    # Prior anon traffic: public page, auth-gated HTML pages (302/401/403), JSON API 401, and logout/lifecycle noise.
    r_pub = store.record(
        actor="anon",
        method="GET",
        url=f"{base_url}about",
        path="/about",
        status=200,
        elapsed_ms=5.0,
        content_type="text/html",
        response_text="<html><body>About</body></html>",
    )
    inv.dispatcher.surface_tracker.ingest_receipt(r_pub)

    r_302 = store.record(
        actor="anon",
        method="GET",
        url=f"{base_url}portal/reports",
        path="/portal/reports",
        status=302,
        elapsed_ms=5.0,
        content_type="text/html",
        redirect_location="/panel/login/submit",
    )
    inv.dispatcher.surface_tracker.ingest_receipt(r_302)

    r_401 = store.record(
        actor="anon",
        method="GET",
        url=f"{base_url}console/audit",
        path="/console/audit",
        status=401,
        elapsed_ms=5.0,
        content_type="text/html",
        response_text="<html><body>Login required</body></html>",
    )
    inv.dispatcher.surface_tracker.ingest_receipt(r_401)

    r_403 = store.record(
        actor="anon",
        method="GET",
        url=f"{base_url}ops/settings",
        path="/ops/settings",
        status=403,
        elapsed_ms=5.0,
        content_type="text/html",
        response_text="<html><body>Forbidden</body></html>",
    )
    inv.dispatcher.surface_tracker.ingest_receipt(r_403)

    # Pure JSON API 401 should NOT be treated as an HTML/page crawl seed.
    r_api = store.record(
        actor="anon",
        method="GET",
        url=f"{base_url}api/v1/secrets",
        path="/api/v1/secrets",
        status=401,
        elapsed_ms=5.0,
        content_type="application/json",
        response_text='{"error":"unauthorized"}',
    )
    inv.dispatcher.surface_tracker.ingest_receipt(r_api)

    # Static asset & logout/lifecycle paths returning 403/302 must be filtered out.
    store.record(
        actor="anon",
        method="GET",
        url=f"{base_url}static/admin.css",
        path="/static/admin.css",
        status=403,
        elapsed_ms=2.0,
        content_type="text/css",
    )
    store.record(
        actor="anon",
        method="GET",
        url=f"{base_url}panel/logout",
        path="/panel/logout",
        status=302,
        elapsed_ms=2.0,
        content_type="text/html",
        redirect_location="/panel/login/submit",
    )
    store.record(
        actor="anon",
        method="GET",
        url=f"{base_url}manager/reboot",
        path="/manager/reboot",
        status=403,
        elapsed_ms=2.0,
        content_type="text/html",
    )

    # Login receipt: nested under /panel/login/submit with Location redirect containing a query token.
    r_login = store.record(
        actor="anon",
        method="POST",
        url=f"{base_url}panel/login/submit",
        path="/panel/login/submit",
        status=302,
        elapsed_ms=10.0,
        content_type="text/html",
        redirect_location="/panel/dashboard?ticket=ephemeral_secret_token_999",
    )
    http.actors.register_dynamic_session(
        "adm",
        cookies={"sid": "sess_adm_12345"},
        source_receipt_id=r_login["receipt_id"],
    )

    extras = inv._derive_post_auth_extra_seed_paths(["adm"], limit=6)
    assert extras[0] == "/panel/dashboard"  # Location redirect (query token stripped)
    assert "/panel/" in extras  # Derived parent section prefix
    assert "/portal/reports" in extras  # 302 auth-gated page
    assert "/console/audit" in extras  # 401 auth-gated page
    assert "/ops/settings" in extras  # 403 auth-gated page
    assert "/about" not in extras  # Public 200 page
    assert "/api/v1/secrets" not in extras  # Non-HTML JSON API
    assert "/static/admin.css" not in extras
    assert "/panel/logout" not in extras
    assert "/manager/reboot" not in extras
    assert all("ephemeral_secret_token_999" not in p for p in extras)
    assert len(extras) <= 6

    starts = inv._collect_post_auth_start_paths(["adm"], limit=8)
    assert starts[0] == "/"
    assert starts[1:] == extras
    http.close()


def test_derive_post_auth_seed_paths_from_json_login_and_caps_gated_routes(tmp_path: Path) -> None:
    base_url = "http://127.0.0.1:18080/"
    http, store = _make_http_client(tmp_path, base_url=base_url, accounts=[])
    inv = _make_investigator(tmp_path, http, store)

    # 8 auth-gated pages to verify deterministic bounding cap.
    for idx in range(8):
        rec = store.record(
            actor="anon",
            method="GET",
            url=f"{base_url}section{idx}/page",
            path=f"/section{idx}/page",
            status=403,
            elapsed_ms=3.0,
            content_type="text/html",
        )
        inv.dispatcher.surface_tracker.ingest_receipt(rec)

    # JSON login response with off-origin redirect (must be rejected) + valid same-origin JSON url.
    r_login = store.record(
        actor="anon",
        method="POST",
        url=f"{base_url}admin/Login/checkLogin.html",
        path="/admin/Login/checkLogin.html",
        status=200,
        elapsed_ms=8.0,
        content_type="application/json",
        response_text=json.dumps({
            "code": 1,
            "redirect": "https://evil.example/hijack",
            "next": "/admin/logout.html",
            "url": "/admin/Index/index.html",
        }),
    )
    http.actors.register_dynamic_session(
        "adm",
        cookies={"PHPSESSID": "sess_json_98765"},
        source_receipt_id=r_login["receipt_id"],
    )

    extras = inv._derive_post_auth_extra_seed_paths(["adm"], limit=6)
    assert extras[0] == "/admin/Index/index.html"
    assert "/admin/" in extras
    assert all("evil.example" not in p for p in extras)
    assert all("logout" not in p for p in extras)
    assert len(extras) == 6
    # Deterministic on repeated calls.
    assert inv._derive_post_auth_extra_seed_paths(["adm"], limit=6) == extras
    http.close()


# ---------------------------------------------------------------------------
# 3. Stage 0 extra_seed_paths normalization, filtering, and deduplication
# ---------------------------------------------------------------------------


def test_normalize_stage0_seed_urls_filters_scope_noise_logout_lifecycle_and_dupes(tmp_path: Path) -> None:
    base_url = "http://127.0.0.1:18080/"
    http, _ = _make_http_client(
        tmp_path,
        base_url=base_url,
        excluded_paths=("/excluded",),
    )

    seen_keys: set[tuple[str, str, str]] = set()
    base_starts = _normalize_stage0_seed_urls(http, ["/"], seen_keys=seen_keys, block_destructive=False)
    assert base_starts == [base_url]

    extras = _normalize_stage0_seed_urls(
        http,
        [
            "/",  # Duplicate of base start
            "/admin/",
            "/admin",  # Duplicate of /admin/ after path normalization
            f"{base_url}admin/",  # Full same-origin duplicate
            "/portal/dashboard",
            "https://evil.example/admin/",  # Out of scope
            "//evil.example/portal/",  # Scheme-relative off-origin
            "http://127.0.0.1:19999/admin/",  # Different port
            "/excluded/panel",  # Excluded path
            "/admin/logout",  # Logout route
            "/auth/sign-out.php",  # Logout route with extension
            "/manager/reboot",  # Destructive lifecycle
            "/api/shutdown",  # Destructive lifecycle
            "/system/reset-db",  # Destructive lifecycle
            "/admin/delete-user",  # Destructive action
            "/_app/immutable/chunks/entry.js",  # Stage 0 bundler noise
            "/(app)/workspace",  # Virtual route group noise
            "/$defs/UserSchema",  # JSON schema $defs noise
            "/static/style.css",  # Static asset
            "/assets/app.js",  # Script asset
            "/admin//double",  # Double-slash artifact
            "/admin/<REDACTED:len=8>",  # Redacted marker
            "javascript:alert(1)",  # Non-HTTP scheme
            "ws://127.0.0.1:18080/ws/events",  # WebSocket scheme
        ],
        seen_keys=seen_keys,
        block_destructive=True,
    )

    assert extras == [
        f"{base_url}admin/",
        f"{base_url}portal/dashboard",
    ]
    http.close()


def test_run_stage0_crawl_passes_normalized_extra_seed_paths_to_playwright_mocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_url = "http://127.0.0.1:18080/"
    http, _ = _make_http_client(
        tmp_path,
        base_url=base_url,
        accounts=[{"alias": "adm", "role": "admin", "session_token": "tok_adm_seed_test"}],
    )
    monkeypatch.setattr(agentic_stage0_crawl, "HAS_PLAYWRIGHT", True)

    seen_start_urls: list[list[str]] = []

    class _FakeBrowser:
        def close(self) -> None:
            return

    class _FakeChromium:
        def launch(self, **_kwargs: Any) -> _FakeBrowser:
            return _FakeBrowser()

    class _FakePlaywrightCM:
        def __enter__(self) -> Any:
            return types.SimpleNamespace(chromium=_FakeChromium())

        def __exit__(self, *_args: Any) -> None:
            return None

    def _fake_crawl_actor(
        _http: Any,
        collector: Any,
        _budget: Any,
        *,
        start_urls: list[str],
        **_kwargs: Any,
    ) -> list[str]:
        seen_start_urls.append(list(start_urls))
        collector.pages_visited += len(start_urls)
        for u in start_urls:
            collector.record_route(method="GET", raw_url=u, status=200)
        return []

    monkeypatch.setattr(agentic_stage0_crawl, "_sync_playwright", lambda: _FakePlaywrightCM())
    monkeypatch.setattr(agentic_stage0_crawl, "_crawl_actor_playwright", _fake_crawl_actor)
    monkeypatch.setattr(agentic_stage0_crawl, "_run_layer4_passive_fusion", lambda *_a, **_kw: None)

    res = run_stage0_crawl(
        http,
        actors=["adm"],
        extra_seed_paths=[
            "/admin/",
            "/admin",
            "/portal/home",
            "https://evil.example/admin",
            "/admin/logout",
            "/manager/reboot",
        ],
        max_pages=8,
        max_passive_probes=0,
    )

    assert res["status"] == "ok"
    assert seen_start_urls == [[
        base_url,
        f"{base_url}admin/",
        f"{base_url}portal/home",
    ]]
    http.close()


# ---------------------------------------------------------------------------
# 4. End-to-end loopback Playwright crawl with extra_seed_paths
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_loopback_extra_seed_paths_discovers_unlinked_authenticated_section(tmp_path: Path) -> None:
    def router(_method: str, raw_path: str, hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        cookie = hdrs.get("cookie", "")
        is_authed = "sid=adm_phase4_secret_99" in cookie
        if path == "/":
            # Public homepage intentionally has NO link to /admin/ or /portal/.
            html = """<!doctype html>
<html><head><title>Public Site</title></head>
<body><h1>Welcome</h1><a href="/about">About</a></body></html>"""
            return 200, "text/html; charset=utf-8", html, {}
        if path == "/about":
            return 200, "text/html; charset=utf-8", "<html><body><h1>About</h1></body></html>", {}
        if path in {"/admin/", "/admin"}:
            if not is_authed:
                return 302, "text/html", "", {"Location": "/admin/Login/checkLogin.html"}
            html = """<!doctype html>
<html><head><title>Admin Panel</title></head>
<body>
  <h1>Admin Console</h1>
  <nav>
    <a href="/admin/users">Manage Users</a>
    <a href="/admin/uploads">Manage Uploads</a>
    <a href="/admin/logout">Logout</a>
  </nav>
  <form action="/admin/settings/save" method="POST">
    <input name="site_title" type="text" />
    <button type="submit">Save</button>
  </form>
</body></html>"""
            return 200, "text/html; charset=utf-8", html, {}
        if path == "/admin/users":
            if not is_authed:
                return 403, "text/html", "Forbidden", {}
            return 200, "text/html; charset=utf-8", "<html><body><h1>Users</h1><a href='/admin/users/export'>Export</a></body></html>", {}
        if path == "/admin/uploads":
            if not is_authed:
                return 403, "text/html", "Forbidden", {}
            return 200, "text/html; charset=utf-8", "<html><body><h1>Uploads</h1></body></html>", {}
        if path in {"/admin/logout", "/manager/reboot"}:
            return 200, "text/plain", "should never be requested", {}
        return 404, "text/plain", "not found", {}

    with _start_loopback_server(router) as (base_url, _port, log):
        http, _ = _make_http_client(
            tmp_path,
            base_url=base_url,
            accounts=[{"alias": "adm", "role": "admin", "cookie": "sid=adm_phase4_secret_99"}],
            allowed_methods=("GET", "HEAD", "POST"),
            max_requests=100,
        )

        # Baseline without extra_seed_paths misses /admin/ completely.
        res_without = run_stage0_crawl(
            http,
            actors=["adm"],
            max_pages=6,
            max_actions=4,
            wait_ms=150,
            max_passive_probes=0,
        )
        urls_without = {r["url"] for r in [*res_without["links"], *res_without["forms"]]}
        assert "/admin/users" not in urls_without

        # With extra_seed_paths, Stage 0 crawls /admin/ and discovers its links and forms.
        res_with = run_stage0_crawl(
            http,
            actors=["adm"],
            extra_seed_paths=[
                "/admin/",
                "/admin",
                "https://evil.example/steal",
                "/admin/logout",
                "/manager/reboot",
            ],
            max_pages=6,
            max_actions=4,
            wait_ms=150,
            max_passive_probes=0,
        )
        assert res_with["status"] == "ok"
        all_routes = {(r["method"], r["url"]) for r in [*res_with["links"], *res_with["forms"]]}
        assert ("GET", "/admin/users") in all_routes
        assert ("GET", "/admin/uploads") in all_routes
        assert ("POST", "/admin/settings/save") in all_routes

        hit_paths = {urlsplit(r["path"]).path for r in log}
        assert "/admin/logout" not in hit_paths
        assert "/manager/reboot" not in hit_paths
        http.close()


# ---------------------------------------------------------------------------
# 5. Sharded AgenticInvestigator wires extra_seed_paths into run_stage0_crawl
# ---------------------------------------------------------------------------


def test_sharded_investigator_passes_derived_extra_seed_paths_to_post_auth_stage0(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_calls: list[dict[str, Any]] = []

    def _fake_run_stage0_crawl(
        _http: Any,
        *,
        output_dir: Path | str | None = None,
        start_paths: list[str] | None = None,
        extra_seed_paths: list[str] | None = None,
        actors: list[str] | None = None,
        seed_filename: str = "stage0-seed.json",
        **_kwargs: Any,
    ) -> dict[str, Any]:
        captured_calls.append({
            "start_paths": list(start_paths or ()),
            "extra_seed_paths": list(extra_seed_paths or ()),
            "actors": list(actors or ()),
            "seed_filename": seed_filename,
        })
        seed_path = (Path(output_dir) / seed_filename) if output_dir is not None else Path(seed_filename)
        return {
            "schema": "stage0-seed/1",
            "url": base_url,
            "status": "ok",
            "mode": "readonly",
            "actors_crawled": list(actors or ()),
            "seed_file": str(seed_path),
            "links": [
                {"method": "GET", "url": "/panel/users", "params": []},
                {"method": "GET", "url": "/panel/uploads", "params": []},
            ],
            "forms": [],
            "ws_endpoints": [],
            "discovery_hints": ["/panel/users"],
            "stats": {"status": "ok", "pages_visited": 3, "ui_actions_taken": 0, "requests_charged": 3},
        }

    fake_stage0_mod = types.ModuleType("agentic_stage0_crawl")
    fake_stage0_mod.run_stage0_crawl = _fake_run_stage0_crawl  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "agentic_stage0_crawl", fake_stage0_mod)

    def router(method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            return 200, "text/html", "<html><body>Public Home</body></html>", {}
        if path == "/portal/reports":
            return 302, "text/html", "", {"Location": "/panel/login/submit"}
        if path == "/console/audit":
            return 403, "text/html", "<html><body>Forbidden</body></html>", {}
        if path == "/api/v1/private":
            return 401, "application/json", json.dumps({"error": "unauthorized"}), {}
        if path == "/panel/login/submit" and method == "POST":
            return (
                200,
                "application/json",
                json.dumps({"ok": True, "redirect_url": "/panel/home"}),
                {"Set-Cookie": "sid=panel_adm_sess_777; Path=/"},
            )
        return 404, "text/plain", "not found", {}

    with _start_loopback_server(router) as (base_url, _port, _log):
        http, store = _make_http_client(
            tmp_path,
            base_url=base_url,
            accounts=[],
            allowed_methods=("GET", "POST"),
            max_requests=150,
        )

        def _transport_handler(messages: list[dict[str, Any]], call_num: int) -> dict[str, Any]:
            sys_text = str(messages[0].get("content") or "") if messages else ""
            if "SUBSYSTEM SHARD SCOPE" in sys_text:
                return _tool_resp("finish", {"summary": "shard done", "untested_areas": []}, f"sfin_{call_num}")
            if call_num == 1:
                return _tool_resp("http_request", {"actor": "anon", "method": "GET", "url": "/portal/reports"}, "c1")
            if call_num == 2:
                return _tool_resp("http_request", {"actor": "anon", "method": "GET", "url": "/console/audit"}, "c2")
            if call_num == 3:
                return _tool_resp("http_request", {"actor": "anon", "method": "GET", "url": "/api/v1/private"}, "c3")
            if call_num == 4:
                return _tool_resp(
                    "http_request",
                    {
                        "actor": "anon",
                        "method": "POST",
                        "url": "/panel/login/submit",
                        "form_body": {"user": "admin", "pass": "pass"},
                        "save_session_as": "adm",
                    },
                    "c4",
                )
            return _tool_resp("finish", {"summary": "boot done", "untested_areas": []}, f"bfin_{call_num}")

        inv = _make_investigator(
            tmp_path,
            http,
            store,
            transport=_ScriptedTransport(_transport_handler),
            stage0_post_auth_enabled=True,
        )
        result = inv.run()
        assert result["status"] == "finished"
        assert len(captured_calls) == 1
        call = captured_calls[0]
        assert call["actors"] == ["adm"]
        assert call["seed_filename"] == "stage0-post-auth-seed.json"
        assert call["start_paths"][0] == "/"
        assert "/panel/home" in call["extra_seed_paths"]
        assert "/panel/" in call["extra_seed_paths"]
        assert "/portal/reports" in call["extra_seed_paths"]
        assert "/console/audit" in call["extra_seed_paths"]
        assert "/api/v1/private" not in call["extra_seed_paths"]
        assert result["sharding_summary"]["post_auth_stage0_crawl"]["extra_seed_paths"] == call["extra_seed_paths"]
        http.close()
