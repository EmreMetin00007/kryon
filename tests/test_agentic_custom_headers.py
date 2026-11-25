"""Operator global header propagation for HTTP, browser, oracle, scope-file, and save-auth."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import agentic_browser  # noqa: E402
import agentic_runner  # noqa: E402
import agentic_stage0_crawl  # noqa: E402
import save_browser_auth  # noqa: E402
import target_bootstrap  # noqa: E402
from agentic_browser import (  # noqa: E402
    _BROWSER_USER_AGENT,
    _extract_actor_browser_auth,
    _merge_browser_route_headers,
    _operator_browser_headers,
    _operator_user_agent,
    run_browser_crawl,
)
from agentic_http import (  # noqa: E402
    ActorManager,
    AgenticHTTPClient,
    normalize_global_headers,
    parse_custom_headers,
)
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_surface import SurfaceFrontierTracker  # noqa: E402
from agentic_tools import ToolDispatcher  # noqa: E402

PROGRAM_HEADERS = {"Pentest": "Cyberbounty"}


def _start_header_echo_server() -> tuple[ThreadingHTTPServer, str, list[dict[str, Any]]]:
    observed: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _handle(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            observed.append({"method": method, "path": self.path, "headers": hdrs, "body": body})
            if self.path == "/api/login" and method == "POST":
                payload = json.dumps({"access_token": "tok-live-login-123"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            payload = json.dumps({"ok": True, "path": self.path, "seen": hdrs}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}/", observed


def test_global_headers_apply_to_anon_static_and_dynamic_actors() -> None:
    actors = ActorManager(
        [{"alias": "member-a", "auth_header": "Bearer tok-a", "role": "member"}],
        global_headers=PROGRAM_HEADERS,
    )

    assert actors.get("anon").build_headers("GET")["Pentest"] == "Cyberbounty"
    member_headers = actors.get("member-a").build_headers("GET")
    assert member_headers["Pentest"] == "Cyberbounty"
    assert member_headers["Authorization"] == "Bearer tok-a"

    dynamic = actors.register_dynamic_session("dynamic-a", cookies={"sid": "cookie-a"})
    assert dynamic.build_headers("GET")["Pentest"] == "Cyberbounty"
    assert dynamic.authenticated is True

    unauthenticated_dynamic = actors.register_dynamic_session("dynamic-empty")
    assert unauthenticated_dynamic.build_headers("GET")["Pentest"] == "Cyberbounty"
    assert unauthenticated_dynamic.authenticated is False

    assert normalize_global_headers(PROGRAM_HEADERS) == PROGRAM_HEADERS


def test_global_headers_do_not_falsely_mark_password_actor_as_preauthenticated(tmp_path: Path) -> None:
    server, base_url, observed = _start_header_echo_server()
    try:
        actors = ActorManager(
            [{"alias": "member-a", "email": "a@example.test", "password": "secret-password", "role": "member"}],
            login_path="/api/login",
            global_headers={
                "Pentest": "Cyberbounty",
                "User-Agent": "KryonCustomUA/2.0",
            },
        )
        assert actors.get("member-a").authenticated is False
        assert actors.unauthenticated_credentialed_aliases() == ["member-a"]

        receipts = ReceiptStore(tmp_path / "run")
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=receipts,
            actors=actors,
            allowed_methods=("GET", "POST"),
        )
        try:
            auth_res = client.authenticate_all_actors()
            assert auth_res == {"member-a": True}
            assert actors.get("member-a").authenticated is True

            anon_rec = client.request(method="GET", url="/public", actor="anon")
            auth_rec = client.request(method="GET", url="/private", actor="member-a")
            assert anon_rec["status"] == 200
            assert auth_rec["status"] == 200
        finally:
            client.close()

        assert len(observed) == 3
        login_req, anon_req, auth_req = observed
        assert login_req["path"] == "/api/login"
        assert login_req["headers"]["pentest"] == "Cyberbounty"
        assert login_req["headers"]["user-agent"] == "KryonCustomUA/2.0"

        assert anon_req["path"] == "/public"
        assert anon_req["headers"]["pentest"] == "Cyberbounty"
        assert anon_req["headers"]["user-agent"] == "KryonCustomUA/2.0"
        assert "authorization" not in anon_req["headers"]

        assert auth_req["path"] == "/private"
        assert auth_req["headers"]["pentest"] == "Cyberbounty"
        assert auth_req["headers"]["user-agent"] == "KryonCustomUA/2.0"
        assert auth_req["headers"]["authorization"] == "Bearer tok-live-login-123"
    finally:
        server.shutdown()
        server.server_close()


def test_http_client_custom_headers_wire_replay_and_oracle_clean_session(tmp_path: Path) -> None:
    server, base_url, observed = _start_header_echo_server()
    try:
        receipts = ReceiptStore(tmp_path / "run-direct")
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=receipts,
            allowed_methods=("GET", "POST"),
            custom_headers=[
                "Pentest: Cyberbounty",
                "X-API-Key: super-secret-program-key",
                "User-Agent: BugBountyBot/1.0",
            ],
        )
        try:
            first = client.request(method="GET", url="/items/1", actor="anon")
            assert first["status"] == 200
            assert "<REDACTED:" in first["request_headers"]["X-API-Key"]

            dispatcher = ToolDispatcher(
                http_client=client,
                receipt_store=receipts,
                root_dir=tmp_path / "run-direct",
            )
            dispatcher._tool_replay_as({"receipt_id": first["receipt_id"], "actor": "anon", "force": True})

            oracle = DifferentialOracle(http_client=client, receipt_store=receipts)
            clean_rec = oracle._run_clean_session_request(
                actor="anon",
                method="GET",
                url=f"{base_url.rstrip('/')}/items/1",
                headers=first["request_headers"],
                raw_body="",
            )
            assert clean_rec["status"] == 200
        finally:
            client.close()

        assert len(observed) == 3
        for req in observed:
            assert req["headers"]["pentest"] == "Cyberbounty"
            assert req["headers"]["x-api-key"] == "super-secret-program-key"
            assert req["headers"]["user-agent"] == "BugBountyBot/1.0"
    finally:
        server.shutdown()
        server.server_close()


def test_case_insensitive_header_deduplication_and_normalization() -> None:
    parsed = parse_custom_headers([
        "X-Program: old",
        "x-program: new",
        "X-With-Colon: https://example.com:8443/path",
    ])
    assert parsed == {
        "x-program": "new",
        "X-With-Colon": "https://example.com:8443/path",
    }

    normalized = normalize_global_headers({"X-Test": " 1 ", "x-test": "2"})
    assert normalized == {"x-test": "2"}


def test_global_headers_reach_anonymous_browser_crawl() -> None:
    actors = ActorManager(global_headers=PROGRAM_HEADERS)
    http = SimpleNamespace(actors=actors)

    cookie_hdr, extra_headers = _extract_actor_browser_auth(http, "anon")
    assert cookie_hdr == ""
    assert extra_headers["Pentest"] == "Cyberbounty"


def test_global_headers_reach_authenticated_browser_crawl() -> None:
    actors = ActorManager(
        [{"alias": "member-a", "auth_header": "Bearer tok-a", "role": "member"}],
        global_headers=PROGRAM_HEADERS,
    )
    http = SimpleNamespace(actors=actors)

    _cookie_hdr, extra_headers = _extract_actor_browser_auth(http, "member-a")
    assert extra_headers["Pentest"] == "Cyberbounty"
    assert extra_headers["Authorization"] == "Bearer tok-a"


def test_browser_custom_user_agent_and_route_override_helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    actors = ActorManager(
        global_headers={
            "Pentest": "Cyberbounty",
            "User-Agent": "KryonProgramUA/3.0",
            "Accept-Language": "tr-TR",
        }
    )
    http = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080/",
        receipt_store=ReceiptStore(tmp_path / "b"),
        actors=actors,
    )
    try:
        assert _operator_user_agent(http) == "KryonProgramUA/3.0"
        assert _operator_user_agent(SimpleNamespace(actors=ActorManager())) == _BROWSER_USER_AGENT
        op_browser = _operator_browser_headers(http)
        assert op_browser == {"Pentest": "Cyberbounty", "Accept-Language": "tr-TR"}

        merged = _merge_browser_route_headers(
            {":method": "GET", "accept-language": "en-US", "accept": "*/*"},
            op_browser,
            override_names=frozenset(k.lower() for k in op_browser),
        )
        assert ":method" not in merged
        assert merged["Accept-Language"] == "tr-TR"
        assert "accept-language" not in merged
        assert merged["Pentest"] == "Cyberbounty"
        assert merged["accept"] == "*/*"

        captured: dict[str, Any] = {}

        def _fake_default_crawl(url: str, **kwargs: Any) -> dict[str, Any]:
            captured["url"] = url
            captured["kwargs"] = kwargs
            return {"ok": True, "pages": [{"url": url, "status": 200}], "links": [], "forms": [], "xhr": []}

        monkeypatch.setattr(agentic_browser, "HAS_PLAYWRIGHT", True)
        monkeypatch.setattr(agentic_browser, "_default_crawl_site", _fake_default_crawl)
        res = run_browser_crawl(http, SurfaceFrontierTracker(base_url=http.base_url), url="/", actor="anon")
        assert res["ok"] is True
        assert captured["kwargs"]["headers"]["Pentest"] == "Cyberbounty"
        assert captured["kwargs"]["headers"]["User-Agent"] == "KryonProgramUA/3.0"
    finally:
        http.close()


def test_stage0_crawl_applies_custom_ua_and_static_asset_operator_headers(tmp_path: Path) -> None:
    actors = ActorManager(
        [{"alias": "member-a", "auth_header": "Bearer secret-tok", "role": "member"}],
        global_headers={
            "Pentest": "Cyberbounty",
            "User-Agent": "Stage0CustomUA/1.0",
        },
    )
    http = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080/",
        receipt_store=ReceiptStore(tmp_path / "s0"),
        actors=actors,
    )
    captured_context_kwargs: dict[str, Any] = {}
    continued_routes: list[tuple[str, dict[str, str] | None]] = []

    class _FakeRoute:
        def __init__(self, url: str) -> None:
            self.request = SimpleNamespace(
                method="GET",
                url=url,
                headers={"accept": "*/*"},
                all_headers=lambda: {"accept": "*/*"},
                resource_type="stylesheet" if url.endswith(".css") else "document",
            )

        def continue_(self, headers: dict[str, str] | None = None) -> None:
            continued_routes.append((self.request.url, headers))

        def abort(self, _reason: str = "") -> None:
            return

    class _FakePage:
        url = "http://127.0.0.1:18080/"

        def on(self, _event: str, _cb: Any) -> None:
            return

        def goto(self, _url: str, **_kwargs: Any) -> Any:
            return SimpleNamespace(status=200, headers={"content-type": "text/html"})

        def wait_for_timeout(self, _ms: int) -> None:
            return

        def content(self) -> str:
            return "<html><body>ok</body></html>"

        def evaluate(self, _script: str, *_args: Any) -> Any:
            return {}

        def close(self) -> None:
            return

    class _FakeContext:
        def __init__(self) -> None:
            self.route_handler: Any = None

        def add_init_script(self, _script: str) -> None:
            return

        def add_cookies(self, _cookies: Any) -> None:
            return

        def route(self, _pattern: str, handler: Any) -> None:
            self.route_handler = handler

        def new_page(self) -> _FakePage:
            assert self.route_handler is not None
            self.route_handler(_FakeRoute("http://127.0.0.1:18080/assets/app.css"))
            self.route_handler(_FakeRoute("http://127.0.0.1:18080/api/me"))
            return _FakePage()

        def close(self) -> None:
            return

    class _FakeBrowser:
        def new_context(self, **kwargs: Any) -> _FakeContext:
            captured_context_kwargs.update(kwargs)
            return _FakeContext()

    try:
        collector = agentic_stage0_crawl._Stage0Collector(http)
        budget = agentic_stage0_crawl._Stage0Budget(http_client=http, cap=10)
        agentic_stage0_crawl._crawl_actor_playwright(
            http,
            collector,
            budget,
            browser=_FakeBrowser(),
            actor="member-a",
            start_urls=["http://127.0.0.1:18080/"],
            forms_enabled=False,
            actor_page_limit=1,
            actor_action_limit=0,
            timeout_ms=2000,
            wait_ms=0,
        )
    finally:
        http.close()

    assert captured_context_kwargs["user_agent"] == "Stage0CustomUA/1.0"
    by_url = {url: hdrs for url, hdrs in continued_routes}
    static_hdrs = by_url["http://127.0.0.1:18080/assets/app.css"]
    api_hdrs = by_url["http://127.0.0.1:18080/api/me"]
    assert static_hdrs is not None
    assert static_hdrs["Pentest"] == "Cyberbounty"
    assert "Authorization" not in static_hdrs
    assert api_hdrs is not None
    assert api_hdrs["Pentest"] == "Cyberbounty"
    assert api_hdrs["Authorization"] == "Bearer secret-tok"


@pytest.mark.parametrize(
    "bad_headers",
    [
        {"Host": "evil.example"},
        {"Content-Length": "0"},
        {"Authorization": "Bearer leaked"},
        {"Cookie": "sid=leaked"},
        {"Pentest": "Cyberbounty\r\nX-Injected: 1"},
        {"Bad Header": "value"},
        {"Pentest": "   "},
    ],
)
def test_global_header_validation_rejects_unsafe_values(bad_headers: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        ActorManager(global_headers=bad_headers)


def test_runner_plan_records_custom_headers_without_values(tmp_path: Path) -> None:
    plan_path, plan = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18080/",
        provider_config=REPO_ROOT / "config" / "llm.example.json",
        output_dir=tmp_path / "plan",
        custom_headers=["Pentest: Cyberbounty"],
        execute=False,
    )
    assert plan_path.is_file()
    assert plan["request_headers"] == ["Pentest"]
    assert PROGRAM_HEADERS["Pentest"] not in json.dumps(plan)


def test_runner_cli_accepts_short_and_long_header_flags_and_rejects_invalid(tmp_path: Path) -> None:
    out = tmp_path / "plan-cli"
    rc = agentic_runner.main([
        "--target", "http://127.0.0.1:18080/",
        "--provider-config", str(REPO_ROOT / "config" / "llm.example.json"),
        "--output-dir", str(out),
        "-H", "Pentest: Cyberbounty",
        "--header", "X-Researcher: handle-1",
        "--custom-header", "x-researcher: handle-2",
    ])
    assert rc == 0
    plan = json.loads((out / "agentic-plan.json").read_text(encoding="utf-8"))
    assert plan["request_headers"] == ["Pentest", "x-researcher"]
    assert "Cyberbounty" not in json.dumps(plan)
    assert "handle-2" not in json.dumps(plan)

    with pytest.raises(SystemExit):
        agentic_runner.main([
            "--target", "http://127.0.0.1:18080/",
            "--provider-config", str(REPO_ROOT / "config" / "llm.example.json"),
            "--output-dir", str(tmp_path / "bad"),
            "-H", "MissingColonSeparator",
        ])


def test_scope_file_and_credentials_custom_headers_merge_with_cli_precedence(tmp_path: Path) -> None:
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(
        json.dumps({
            "in_scope": ["http://127.0.0.1:18080/"],
            "custom_headers": {"Pentest": "FromScope", "X-Scope-Only": "ScopeVal"},
        }),
        encoding="utf-8",
    )
    creds_path = tmp_path / "creds.json"
    creds_path.write_text(
        json.dumps({
            "target_url": "http://127.0.0.1:18080/",
            "scope_rules": {"headers": {"X-Bundle-Header": "BundleVal", "Pentest": "FromBundle"}},
            "test_accounts": [],
        }),
        encoding="utf-8",
    )

    _, scope_meta = target_bootstrap.resolve_target_origin(
        "http://127.0.0.1:18080/",
        scope_file=scope_path,
    )
    assert scope_meta["custom_headers"] == {"Pentest": "FromScope", "X-Scope-Only": "ScopeVal"}

    _, plan = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18080/",
        credentials_file=creds_path,
        scope_file=scope_path,
        provider_config=REPO_ROOT / "config" / "llm.example.json",
        output_dir=tmp_path / "merged-plan",
        custom_headers=["Pentest: FromCLI"],
        execute=False,
    )
    assert plan["request_headers"] == ["Pentest", "X-Bundle-Header", "X-Scope-Only"]
    serialized = json.dumps(plan)
    for secret_val in ("FromScope", "ScopeVal", "BundleVal", "FromBundle", "FromCLI"):
        assert secret_val not in serialized

    bad_scope = tmp_path / "bad-scope.json"
    bad_scope.write_text(json.dumps({"in_scope": ["http://127.0.0.1:18080/"], "custom_headers": 123}), encoding="utf-8")
    with pytest.raises(ValueError):
        target_bootstrap.load_scope_file(bad_scope)


def test_save_browser_auth_supports_custom_headers_and_custom_ua(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ua, extra = save_browser_auth._build_context_headers([
        "Pentest: Cyberbounty",
        "User-Agent: SaveAuthCustomUA/1.0",
    ])
    assert ua == "SaveAuthCustomUA/1.0"
    assert extra == {"Pentest": "Cyberbounty"}

    login_file = tmp_path / "demo-login.json"
    login_file.write_text(json.dumps({"username": "u", "password": "p"}), encoding="utf-8")
    login_file.chmod(0o600)
    storage_file = tmp_path / "demo-storage.json"

    captured_ctx_kwargs: dict[str, Any] = {}

    class _FakePage:
        url = "https://target.example.invalid/home"

        def set_default_timeout(self, _ms: int) -> None:
            return

        def goto(self, _url: str, **_kwargs: Any) -> Any:
            return SimpleNamespace(status=200)

        def wait_for_timeout(self, _ms: int) -> None:
            return

        def title(self) -> str:
            return "Login"

        def fill(self, _sel: str, _val: str) -> None:
            return

        def click(self, _sel: str, **_kwargs: Any) -> None:
            return

        def is_visible(self, _sel: str, **_kwargs: Any) -> bool:
            return False

    class _FakeCtx:
        def new_page(self) -> _FakePage:
            return _FakePage()

        def storage_state(self, path: str) -> None:
            Path(path).write_text(json.dumps({"cookies": [], "origins": []}), encoding="utf-8")

        def cookies(self) -> list[Any]:
            return []

        def close(self) -> None:
            return

    class _FakeBrowser:
        def new_context(self, **kwargs: Any) -> _FakeCtx:
            captured_ctx_kwargs.update(kwargs)
            return _FakeCtx()

        def close(self) -> None:
            return

    class _FakePlaywrightCM:
        def __enter__(self) -> Any:
            return SimpleNamespace(chromium=SimpleNamespace(launch=lambda **_kw: _FakeBrowser()))

        def __exit__(self, *_args: Any) -> bool:
            return False

    fake_sync_api = SimpleNamespace(sync_playwright=lambda: _FakePlaywrightCM())
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync_api)
    monkeypatch.setattr(save_browser_auth, "_proxy_args", lambda: {})

    rc = save_browser_auth.main([
        "--program", "demo",
        "--login-url", "https://target.example.invalid/login",
        "--user-selector", "#user",
        "--pass-selector", "#pass",
        "--submit-selector", "#submit",
        "--login-file", str(login_file),
        "--storage", str(storage_file),
        "-H", "Pentest: SecretHeaderVal",
        "--header", "User-Agent: SaveAuthUA/9.0",
    ])
    assert rc == 0
    assert captured_ctx_kwargs["user_agent"] == "SaveAuthUA/9.0"
    assert captured_ctx_kwargs["extra_http_headers"] == {"Pentest": "SecretHeaderVal"}
    stdout = capsys.readouterr().out
    assert "Pentest" in stdout
    assert "SecretHeaderVal" not in stdout
