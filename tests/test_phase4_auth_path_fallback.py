"""Tests for Faz 4E: credentials.json auth paths, Stage 0 login_path auto-fallback, and manifest auth metadata."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_runner  # noqa: E402
import agentic_stage0_crawl  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402


@contextmanager
def _start_loopback_server(
    router: Callable[[str, str, dict[str, str], bytes], tuple[int, str, bytes | str, dict[str, str]]],
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
        yield f"http://127.0.0.1:{port}/", requests_log
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


def _write_local_provider_config(tmp_path: Path) -> Path:
    cfg = {
        "schema": "cco-llm/1",
        "model": "local/test-model",
        "providers": {
            "local": {
                "base_url": "http://127.0.0.1:1/v1",
                "models": ["test-model"],
                "api_key_env": "CCO_TEST_LOCAL_KEY",
                "api_key_header": "Authorization",
            }
        },
    }
    cfg_path = tmp_path / "llm.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    return cfg_path


def _install_stub_investigator(
    monkeypatch: pytest.MonkeyPatch,
    observed: dict[str, Any],
) -> None:
    monkeypatch.setenv("CCO_TEST_LOCAL_KEY", "loopback-stub-key")

    class _StubDispatcher:
        def __init__(self) -> None:
            self.findings: list[dict[str, Any]] = []

    class _StubInvestigator:
        def __init__(self, **kwargs: Any) -> None:
            http_client: AgenticHTTPClient = kwargs["http_client"]
            observed["authenticated_at_stage1"] = http_client.actors.authenticated_non_anon_aliases()
            observed["unauthenticated_at_stage1"] = http_client.actors.unauthenticated_credentialed_aliases()
            observed["login_path_at_stage1"] = http_client.actors.login_path
            observed["session_check_path_at_stage1"] = http_client.actors.session_check_path
            self.root_dir = Path(kwargs["root_dir"])
            self.dispatcher = _StubDispatcher()

        def run(self, *, resume: bool = False) -> dict[str, Any]:
            del resume
            return {"status": "completed", "turns": 1}

        def write_metrics(self) -> tuple[Path, Path, dict[str, Any]]:
            m_json = self.root_dir / "process-metrics.json"
            m_md = self.root_dir / "process-metrics.md"
            m_json.write_text("{}\n", encoding="utf-8")
            m_md.write_text("# metrics\n", encoding="utf-8")
            return m_json, m_md, {}

    monkeypatch.setattr(agentic_runner, "AgenticInvestigator", _StubInvestigator)


# ---------------------------------------------------------------------------
# 1. credentials.json login_path / session_check_path & CLI override precedence
# ---------------------------------------------------------------------------


def test_credentials_file_auth_paths_and_cli_precedence_in_plan(tmp_path: Path) -> None:
    provider_cfg = _write_local_provider_config(tmp_path)

    # Case A: Top-level login_path & session_check_path in credentials.json.
    creds_top = tmp_path / "creds_top.json"
    creds_top.write_text(
        json.dumps({
            "target_url": "http://127.0.0.1:18081/",
            "login_path": "/api/auth/login",
            "session_check_path": "/api/auth/me",
            "test_accounts": [
                {"alias": "grace", "email": "grace.secret@example.test", "password": "SuperSecretPassword1!", "role": "member"},
                {"alias": "henry", "email": "henry.secret@example.test", "password": "SuperSecretPassword2!", "role": "admin"},
            ],
        }),
        encoding="utf-8",
    )
    plan_path, plan = agentic_runner.run_agentic_target(
        credentials_file=creds_top,
        provider_config=provider_cfg,
        output_dir=tmp_path / "plan-top",
        execute=False,
    )
    assert plan["auth"] == {
        "login_path": "/api/auth/login",
        "session_check_path": "/api/auth/me",
        "login_path_source": "credentials_file",
        "authenticated_actors": [],
        "unauthenticated_credentialed_actors": ["grace", "henry"],
    }
    raw_plan = plan_path.read_text(encoding="utf-8")
    for secret in ("SuperSecretPassword1!", "SuperSecretPassword2!", "grace.secret@example.test", "henry.secret@example.test"):
        assert secret not in raw_plan

    # Case B: Nested auth.login_path & auth.session_check_path in credentials.json.
    creds_nested = tmp_path / "creds_nested.json"
    creds_nested.write_text(
        json.dumps({
            "target_url": "http://127.0.0.1:18082/",
            "auth": {
                "login_path": "/v2/auth/signin",
                "session_check_path": "/v2/auth/session",
            },
            "test_accounts": [
                {"alias": "alice", "email": "alice@example.test", "password": "AlicePassword1!", "role": "member"},
            ],
        }),
        encoding="utf-8",
    )
    _, plan_nested = agentic_runner.run_agentic_target(
        credentials_file=creds_nested,
        provider_config=provider_cfg,
        output_dir=tmp_path / "plan-nested",
        execute=False,
    )
    assert plan_nested["auth"]["login_path"] == "/v2/auth/signin"
    assert plan_nested["auth"]["session_check_path"] == "/v2/auth/session"
    assert plan_nested["auth"]["login_path_source"] == "credentials_file"

    # Case C: Explicit non-default CLI flags override credentials.json.
    _, plan_cli = agentic_runner.run_agentic_target(
        credentials_file=creds_top,
        provider_config=provider_cfg,
        output_dir=tmp_path / "plan-cli",
        login_path="/custom/cli/login",
        session_check_path="/custom/cli/session",
        execute=False,
    )
    assert plan_cli["auth"]["login_path"] == "/custom/cli/login"
    assert plan_cli["auth"]["session_check_path"] == "/custom/cli/session"
    assert plan_cli["auth"]["login_path_source"] == "cli"

    # Case D: CLI main() passes --login-path through and preserves precedence.
    rc = agentic_runner.main([
        "--credentials-file", str(creds_top),
        "--provider-config", str(provider_cfg),
        "--output-dir", str(tmp_path / "plan-cli-main"),
        "--login-path", "/cli/override/signin",
    ])
    assert rc == 0
    cli_main_plan = json.loads((tmp_path / "plan-cli-main" / "agentic-plan.json").read_text(encoding="utf-8"))
    assert cli_main_plan["auth"]["login_path"] == "/cli/override/signin"
    assert cli_main_plan["auth"]["session_check_path"] == "/api/auth/me"
    assert cli_main_plan["auth"]["login_path_source"] == "cli"

    # Case E: No credentials_file auth paths and default CLI -> default source.
    _, plan_default = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18083/",
        provider_config=provider_cfg,
        output_dir=tmp_path / "plan-default",
        execute=False,
    )
    assert plan_default["auth"] == {
        "login_path": "/api/v1/access/sign-in",
        "session_check_path": "/api/v1/access/session",
        "login_path_source": "default",
        "authenticated_actors": [],
        "unauthenticated_credentialed_actors": [],
    }


def test_credentials_file_login_path_authenticates_live_actors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _router(method: str, path: str, _hdrs: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if method == "POST" and path == "/api/auth/login":
            data = json.loads(body.decode("utf-8"))
            email = str(data.get("email") or "")
            return (
                200,
                "application/json",
                json.dumps({"access_token": f"tok-live-{email}"}),
                {"Set-Cookie": f"sid=cookie-{email}; HttpOnly"},
            )
        return 404, "application/json", '{"error":"not found"}', {}

    with _start_loopback_server(_router) as (base_url, req_log):
        provider_cfg = _write_local_provider_config(tmp_path)
        creds = tmp_path / "creds.json"
        creds.write_text(
            json.dumps({
                "target_url": base_url,
                "login_path": "/api/auth/login",
                "session_check_path": "/api/auth/session",
                "test_accounts": [
                    {"alias": "grace", "email": "grace@orderdesk.test", "password": "GraceSecretValue99!", "role": "member"},
                    {"alias": "henry", "email": "henry@orderdesk.test", "password": "HenrySecretValue99!", "role": "admin"},
                ],
            }),
            encoding="utf-8",
        )
        observed: dict[str, Any] = {}
        _install_stub_investigator(monkeypatch, observed)

        out_dir = tmp_path / "run-creds-live"
        manifest_path, manifest = agentic_runner.run_agentic_target(
            credentials_file=creds,
            provider_config=provider_cfg,
            output_dir=out_dir,
            allowed_methods=["GET", "POST"],
            execute=True,
        )

        assert observed["authenticated_at_stage1"] == ["grace", "henry"]
        assert observed["login_path_at_stage1"] == "/api/auth/login"
        assert observed["session_check_path_at_stage1"] == "/api/auth/session"
        assert [r["path"] for r in req_log] == ["/api/auth/login", "/api/auth/login"]

        expected_auth = {
            "login_path": "/api/auth/login",
            "session_check_path": "/api/auth/session",
            "login_path_source": "credentials_file",
            "authenticated_actors": ["grace", "henry"],
            "unauthenticated_credentialed_actors": [],
        }
        assert manifest["auth"] == expected_auth
        launch_doc = json.loads((out_dir / "launch.json").read_text(encoding="utf-8"))
        assert launch_doc["auth"] == expected_auth

        # Secret hygiene: no passwords, tokens, cookies, or emails in manifest.json or launch.json.
        for artifact_path in (manifest_path, out_dir / "launch.json"):
            raw = artifact_path.read_text(encoding="utf-8")
            for secret in (
                "GraceSecretValue99!",
                "HenrySecretValue99!",
                "tok-live-",
                "cookie-",
                "grace@orderdesk.test",
                "henry@orderdesk.test",
            ):
                assert secret not in raw


# ---------------------------------------------------------------------------
# 2. Stage 0 login_path Auto-Fallback on 404 / 405
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("default_status", [404, 405])
def test_stage0_auto_fallback_authenticates_actors_on_404_or_405(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    default_status: int,
) -> None:
    def _router(method: str, path: str, _hdrs: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if method == "POST" and path == "/api/v1/access/sign-in":
            return default_status, "application/json", '{"error":"wrong route"}', {}
        if method == "POST" and path == "/api/auth/login":
            data = json.loads(body.decode("utf-8"))
            email = str(data.get("email") or "")
            return (
                200,
                "application/json",
                json.dumps({"access_token": f"jwt-fallback-{email}"}),
                {"Set-Cookie": f"session_id=s-{email}; Path=/"},
            )
        return 404, "application/json", '{"error":"not found"}', {}

    with _start_loopback_server(_router) as (base_url, req_log):
        provider_cfg = _write_local_provider_config(tmp_path)
        creds = tmp_path / f"creds-{default_status}.json"
        creds.write_text(
            json.dumps({
                "target_url": base_url,
                "test_accounts": [
                    {"alias": "grace", "email": "grace@lab.test", "password": "GracePassword123!", "role": "member"},
                    {"alias": "henry", "email": "henry@lab.test", "password": "HenryPassword123!", "role": "admin"},
                ],
            }),
            encoding="utf-8",
        )
        observed: dict[str, Any] = {}
        _install_stub_investigator(monkeypatch, observed)

        def _fake_stage0_crawl(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {
                "schema": "stage0-seed/1",
                "url": base_url,
                "status": "ok",
                "mode": "readonly",
                "actors_crawled": ["anon"],
                "links": [
                    {"method": "POST", "url": "/api/auth/logout", "params": [], "status": 200},
                    {"method": "POST", "url": "/api/auth/register", "params": [], "status": 200},
                    {"method": "GET", "url": "/orders", "params": [], "status": 200},
                ],
                "forms": [
                    {"method": "POST", "url": "/api/auth/signup", "params": ["email", "password"], "status": 200, "is_form": True},
                    {"method": "POST", "url": "/api/auth/login", "params": ["email", "password"], "status": 200, "is_form": True},
                ],
                "ws_endpoints": [],
                "body_templates": {},
                "multipart_schemas": {},
                "discovery_hints": ["/orders"],
                "seed_file": "",
                "stats": {"status": "ok", "pages_visited": 2},
            }

        monkeypatch.setattr(agentic_stage0_crawl, "run_stage0_crawl", _fake_stage0_crawl)

        out_dir = tmp_path / f"run-fallback-{default_status}"
        manifest_path, manifest = agentic_runner.run_agentic_target(
            credentials_file=creds,
            provider_config=provider_cfg,
            output_dir=out_dir,
            allowed_methods=["GET", "POST"],
            auto_crawl=True,
            execute=True,
        )

        # Stage 1 must receive both actors already authenticated via /api/auth/login.
        assert observed["authenticated_at_stage1"] == ["grace", "henry"]
        assert observed["unauthenticated_at_stage1"] == []
        assert observed["login_path_at_stage1"] == "/api/auth/login"

        # Logout/register/signup routes must NEVER be hit.
        hit_paths = [r["path"] for r in req_log]
        assert "/api/auth/logout" not in hit_paths
        assert "/api/auth/register" not in hit_paths
        assert "/api/auth/signup" not in hit_paths
        assert hit_paths.count("/api/v1/access/sign-in") == 2
        assert hit_paths.count("/api/auth/login") == 2

        expected_auth = {
            "login_path": "/api/auth/login",
            "session_check_path": "/api/v1/access/session",
            "login_path_source": "stage0_fallback",
            "authenticated_actors": ["grace", "henry"],
            "unauthenticated_credentialed_actors": [],
        }
        assert manifest["auth"] == expected_auth
        launch_doc = json.loads((out_dir / "launch.json").read_text(encoding="utf-8"))
        assert launch_doc["auth"] == expected_auth

        # Zero secret leakage in manifest.json and launch.json.
        for artifact_path in (manifest_path, out_dir / "launch.json"):
            raw = artifact_path.read_text(encoding="utf-8")
            for secret in (
                "GracePassword123!",
                "HenryPassword123!",
                "jwt-fallback-",
                "session_id=s-",
                "grace@lab.test",
                "henry@lab.test",
            ):
                assert secret not in raw


# ---------------------------------------------------------------------------
# 3. Fail-Closed Behavior: 401 / 403 on valid login_path MUST NOT spray creds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reject_status", [401, 403])
def test_fail_closed_no_fallback_on_401_or_403(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reject_status: int,
) -> None:
    def _router(method: str, path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if method == "POST" and path == "/api/v1/access/sign-in":
            return reject_status, "application/json", '{"error":"invalid credentials"}', {}
        if method == "POST" and path == "/api/auth/login":
            return 200, "application/json", '{"access_token":"should-never-be-called"}', {}
        return 404, "application/json", '{"error":"not found"}', {}

    with _start_loopback_server(_router) as (base_url, req_log):
        provider_cfg = _write_local_provider_config(tmp_path)
        creds = tmp_path / f"creds-reject-{reject_status}.json"
        creds.write_text(
            json.dumps({
                "target_url": base_url,
                "test_accounts": [
                    {"alias": "grace", "email": "grace@lab.test", "password": "WrongPassword1!", "role": "member"},
                    {"alias": "henry", "email": "henry@lab.test", "password": "WrongPassword2!", "role": "admin"},
                ],
            }),
            encoding="utf-8",
        )
        observed: dict[str, Any] = {}
        _install_stub_investigator(monkeypatch, observed)

        def _fake_stage0_crawl(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {
                "schema": "stage0-seed/1",
                "url": base_url,
                "status": "ok",
                "mode": "readonly",
                "actors_crawled": ["anon"],
                "links": [{"method": "POST", "url": "/api/auth/login", "params": [], "status": 200}],
                "forms": [{"method": "POST", "url": "/login", "params": [], "status": 200, "is_form": True}],
                "ws_endpoints": [],
                "body_templates": {},
                "multipart_schemas": {},
                "discovery_hints": [],
                "seed_file": "",
                "stats": {"status": "ok"},
            }

        monkeypatch.setattr(agentic_stage0_crawl, "run_stage0_crawl", _fake_stage0_crawl)

        out_dir = tmp_path / f"run-reject-{reject_status}"
        _, manifest = agentic_runner.run_agentic_target(
            credentials_file=creds,
            provider_config=provider_cfg,
            output_dir=out_dir,
            allowed_methods=["GET", "POST"],
            auto_crawl=True,
            execute=True,
        )

        # Credentials must NEVER be sprayed to /api/auth/login or /login when login_path returned 401/403.
        hit_paths = [r["path"] for r in req_log]
        assert hit_paths == ["/api/v1/access/sign-in", "/api/v1/access/sign-in"]
        assert observed["authenticated_at_stage1"] == []
        assert observed["unauthenticated_at_stage1"] == ["grace", "henry"]
        assert manifest["auth"] == {
            "login_path": "/api/v1/access/sign-in",
            "session_check_path": "/api/v1/access/session",
            "login_path_source": "default",
            "authenticated_actors": [],
            "unauthenticated_credentialed_actors": ["grace", "henry"],
        }


# ---------------------------------------------------------------------------
# 4. Candidate Filtering, Ranking, Bounds & Restore on All-Miss
# ---------------------------------------------------------------------------


def test_filter_login_fallback_candidates_excludes_unsafe_and_bounds_to_three(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "filter")
    actors = ActorManager(
        [{"alias": "u1", "email": "u1@test.local", "password": "pw"}],
        login_path="/api/v1/access/sign-in",
    )
    client = AgenticHTTPClient(
        base_url="http://127.0.0.1:18090/",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        excluded_paths=("/api/excluded/login",),
    )
    try:
        candidates = [
            "/api/auth/logout",
            "/api/auth/signout",
            "/api/auth/sign-out",
            "/api/auth/register",
            "/api/auth/signup",
            "/api/auth/sign-up",
            "/api/auth/reset",
            "/api/auth/password-reset",
            "/api/auth/login/reset",
            "/api/auth/forgot-password",
            "/api/auth/refresh",
            "/assets/login.js",
            "/static/signin.css",
            "/api/sessions/{id}",
            "/api/sessions/:id",
            "https://evil.example/api/auth/login",
            "/api/excluded/login",
            "/api/v1/access/sign-in",  # already-failed current login_path
            "/api/orders",
            "/api/session",            # weak match -> ranked after strong matches
            "/api/auth/login",         # strong #1
            "/api/auth/login?next=/",  # duplicate after query strip
            "/auth/token",             # strong #2
            "/users/sign_in",          # strong #3
            "/extra/signin",           # strong #4 -> dropped by cap=3
        ]
        filtered = client.filter_login_fallback_candidates(candidates)
        assert filtered == ["/api/auth/login", "/auth/token", "/users/sign_in"]

        # Weak session route is included when strong slots remain.
        filtered_with_weak = client.filter_login_fallback_candidates(
            ["/api/auth/logout", "/api/session", "/api/auth/login"]
        )
        assert filtered_with_weak == ["/api/auth/login", "/api/session"]
    finally:
        client.close()


def test_retry_fallback_restores_original_login_path_when_all_candidates_fail(tmp_path: Path) -> None:
    def _router(_method: str, _path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        return 404, "application/json", '{"error":"not found"}', {}

    with _start_loopback_server(_router) as (base_url, req_log):
        store = ReceiptStore(tmp_path / "all-miss")
        actors = ActorManager(
            [
                {"alias": "a1", "email": "a1@test.local", "password": "pw1"},
                {"alias": "a2", "email": "a2@test.local", "password": "pw2"},
            ],
            login_path="/api/v1/access/sign-in",
        )
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=actors,
            allowed_methods=("GET", "POST"),
            max_requests=20,
        )
        try:
            assert client.authenticate_all_actors() == {"a1": False, "a2": False}
            assert actors.actors_failed_with_missing_login_route() == ["a1", "a2"]

            res = client.retry_unauthenticated_actors_with_discovered_login_paths(
                ["/api/auth/login", "/auth/signin", "/auth/token", "/login/extra"]
            )
            assert res == {"a1": False, "a2": False}
            # Original configured login_path is restored when no candidate succeeded.
            assert actors.login_path == "/api/v1/access/sign-in"
            # Bounded probing: 2 initial attempts + at most 3 candidate probes (only probe actor a1, not a2).
            probed_fallback = [r["path"] for r in req_log[2:]]
            assert probed_fallback == ["/api/auth/login", "/auth/signin", "/auth/token"]
        finally:
            client.close()


def test_retry_fallback_ignores_unattempted_and_401_actors(tmp_path: Path) -> None:
    def _router(_method: str, path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if path == "/api/v1/access/sign-in":
            return 401, "application/json", '{"error":"bad creds"}', {}
        return 200, "application/json", '{"access_token":"tok"}', {}

    with _start_loopback_server(_router) as (base_url, req_log):
        store = ReceiptStore(tmp_path / "unattempted")
        actors = ActorManager(
            [{"alias": "u1", "email": "u1@test.local", "password": "pw"}],
            login_path="/api/v1/access/sign-in",
        )
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=actors,
            allowed_methods=("GET", "POST"),
            max_requests=10,
        )
        try:
            # Before any initial auth attempt -> no fallback probes.
            assert client.retry_unauthenticated_actors_with_discovered_login_paths(["/api/auth/login"]) == {}
            assert req_log == []

            # After 401 on configured login_path -> fail-closed, zero fallback probes.
            assert client.authenticate_all_actors() == {"u1": False}
            assert actors.get("u1").last_auth_status == 401
            assert client.retry_unauthenticated_actors_with_discovered_login_paths(["/api/auth/login"]) == {}
            assert [r["path"] for r in req_log] == ["/api/v1/access/sign-in"]
        finally:
            client.close()
