"""Tests for Faz 2A: post-auth incremental Stage 0 crawl & SPA interactive UI trigger discovery."""
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
import agentic_runner  # noqa: E402
import agentic_stage0_crawl  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_stage0_crawl import HAS_PLAYWRIGHT, _DESTRUCTIVE_RE, run_stage0_crawl  # noqa: E402
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
    base_url: str,
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
    """Deterministic in-memory provider transport for sharded AgenticInvestigator tests."""

    def __init__(self, handler: Callable[[list[dict[str, Any]], int], dict[str, Any]]) -> None:
        self._handler = handler
        self.calls = 0
        self._lock = threading.Lock()
        self.prompts_seen: list[list[dict[str, Any]]] = []

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
            self.prompts_seen.append(messages)
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


# ---------------------------------------------------------------------------
# 1. _DESTRUCTIVE_RE safety checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "danger_label",
    [
        "Reboot",
        "Reboot Server",
        "/manager/reboot",
        "Restart",
        "Restart ComfyUI",
        "Shutdown",
        "Shut Down",
        "shut_down",
        "poweroff",
        "Power Off",
        "factory reset",
        "factory_reset",
        "Factory-Reset",
        "Logout",
        "Log Out",
        "log-out",
        "Signout",
        "Sign Out",
        "sign_out",
        "Delete Account",
        "Remove Node",
        "Reset Settings",
        "Destroy Workspace",
        "Drop Database",
        "Wipe Cache",
        "Cancel All",
        "Stop",
        "Stop Queue",
        "btn-stop",
        "Kill",
        "Kill Worker",
        "kill_process",
    ],
)
def test_destructive_regex_matches_dangerous_triggers(danger_label: str) -> None:
    assert _DESTRUCTIVE_RE.search(danger_label) is not None, f"expected destructive match for {danger_label!r}"


@pytest.mark.parametrize(
    "safe_label",
    [
        "Manager",
        "ComfyUI Manager",
        "Settings",
        "Models",
        "Extensions",
        "Workflows",
        "Queue History",
        "Toggle Sidebar",
        "Dropdown Menu",
        "Desktop View",
        "Skills Overview",
        "Install Custom Nodes",
    ],
)
def test_destructive_regex_allows_benign_spa_triggers(safe_label: str) -> None:
    assert _DESTRUCTIVE_RE.search(safe_label) is None, f"unexpected destructive match for {safe_label!r}"


# ---------------------------------------------------------------------------
# 2. run_stage0_crawl explicit actors filter & custom seed_filename
# ---------------------------------------------------------------------------


def test_stage0_explicit_actors_and_seed_filename_mocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http, _ = _make_http_client(
        tmp_path,
        base_url="http://127.0.0.1:18080/",
        accounts=[
            {"alias": "member1", "role": "member", "session_token": "tok_member1_xyz"},
            {"alias": "adm", "role": "admin", "session_token": "tok_adm_xyz"},
        ],
        max_requests=100,
    )

    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    initial_seed = out_dir / "stage0-seed.json"
    initial_seed.write_text('{"sentinel":"initial-stage0"}\n', encoding="utf-8")

    # _select_crawl_actors must NOT be called when explicit non-empty actors are provided.
    def _boom_select(*_args: Any, **_kwargs: Any) -> list[str]:
        raise AssertionError("_select_crawl_actors should not be called when explicit actors are provided")

    monkeypatch.setattr(agentic_stage0_crawl, "_select_crawl_actors", _boom_select)
    monkeypatch.setattr(agentic_stage0_crawl, "HAS_PLAYWRIGHT", True)

    crawled_actors: list[str] = []

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
        actor: str,
        **_kwargs: Any,
    ) -> list[str]:
        crawled_actors.append(actor)
        collector.pages_visited += 1
        collector.record_route(method="GET", raw_url="/admin/Index/index.html", status=200)
        collector.record_route(method="GET", raw_url="/admin/users/list", status=200)
        return []

    monkeypatch.setattr(agentic_stage0_crawl, "_sync_playwright", lambda: _FakePlaywrightCM())
    monkeypatch.setattr(agentic_stage0_crawl, "_crawl_actor_playwright", _fake_crawl_actor)
    monkeypatch.setattr(agentic_stage0_crawl, "_run_layer4_passive_fusion", lambda *_a, **_kw: None)

    res = run_stage0_crawl(
        http,
        output_dir=out_dir,
        start_paths=["/", "/admin/Index/index.html"],
        actors=["adm"],
        seed_filename="stage0-post-auth-seed.json",
        max_pages=8,
        max_actions=16,
        max_passive_probes=0,
    )

    assert res["status"] == "ok"
    assert crawled_actors == ["adm"]
    assert res["actors_crawled"] == ["adm"]
    assert res["stats"]["actors_crawled"] == ["adm"]

    post_seed_path = out_dir / "stage0-post-auth-seed.json"
    assert Path(res["seed_file"]) == post_seed_path
    assert post_seed_path.is_file()
    loaded = json.loads(post_seed_path.read_text(encoding="utf-8"))
    assert loaded["actors_crawled"] == ["adm"]
    urls = {r["url"] for r in loaded["links"]}
    assert "/admin/Index/index.html" in urls
    assert "/admin/users/list" in urls

    # Original stage0-seed.json must remain untouched.
    assert json.loads(initial_seed.read_text(encoding="utf-8")) == {"sentinel": "initial-stage0"}

    # Non-existent explicit actor alias must not silently fall back to crawling anon.
    crawled_actors.clear()
    res_missing = run_stage0_crawl(
        http,
        output_dir=out_dir,
        actors=["does_not_exist"],
        seed_filename="stage0-missing.json",
    )
    assert res_missing["status"] == "ok"
    assert res_missing["actors_crawled"] == []
    assert crawled_actors == []
    http.close()


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_loopback_explicit_actor_and_spa_interactive_triggers(tmp_path: Path) -> None:
    def router(_method: str, raw_path: str, hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        auth = hdrs.get("authorization", "")
        if path == "/":
            # Vue/ComfyUI-style SPA shell with zero traditional <a href="/..."> links.
            html = """<!doctype html>
<html>
<head><title>Vue SPA Studio</title></head>
<body>
  <aside class="side-bar">
    <button class="side-bar-button" title="Manager" onclick="openManager()">
      <span class="icon-box"></span>
    </button>
    <div role="button" class="side-bar-item" onclick="fetch('/api/extensions/list')">Extensions</div>
    <button class="side-bar-button" title="Reboot Server" onclick="fetch('/manager/reboot')">
      <span class="icon-power"></span>
    </button>
    <button type="button" onclick="fetch('/api/restart')">Restart</button>
    <button type="button" onclick="fetch('/api/shutdown')">Shutdown</button>
    <button type="button" onclick="fetch('/api/logout')">Logout</button>
    <button type="button" onclick="fetch('/api/stop')">Stop Queue</button>
    <button type="button" onclick="fetch('/api/kill')">Kill Worker</button>
  </aside>
  <nav>
    <a href="#" onclick="event.preventDefault(); fetch('/api/workflows/recent')">Workflows</a>
  </nav>
  <div id="panel-root"></div>
  <script>
    function openManager() {
      fetch('/manager/get_list?mode=local');
      if (!document.getElementById('mgr-ext-script')) {
        const s = document.createElement('script');
        s.id = 'mgr-ext-script';
        s.src = '/extensions/manager-panel.js';
        document.head.appendChild(s);
      }
      document.getElementById('panel-root').innerHTML =
        '<div role="dialog"><h2>Manager</h2><a href="/manager/custom-nodes">Custom Nodes</a></div>';
    }
  </script>
</body>
</html>"""
            return 200, "text/html; charset=utf-8", html, {}
        if path == "/extensions/manager-panel.js":
            js = "export function installNode() { return fetch('/manager/install_node', {method: 'POST'}); }\n"
            return 200, "application/javascript", js, {}
        if path == "/manager/get_list":
            return 200, "application/json", json.dumps({"items": [], "auth": auth}), {}
        if path == "/manager/custom-nodes":
            return 200, "text/html; charset=utf-8", "<html><body><h1>Custom Nodes</h1></body></html>", {}
        if path == "/api/extensions/list":
            return 200, "application/json", json.dumps({"extensions": ["manager"]}), {}
        if path == "/api/workflows/recent":
            return 200, "application/json", json.dumps({"workflows": []}), {}
        if path in {"/manager/reboot", "/api/restart", "/api/shutdown", "/api/logout", "/api/stop", "/api/kill"}:
            return 200, "application/json", json.dumps({"danger": True}), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_loopback_server(router) as (base_url, _port, log):
        http, _ = _make_http_client(
            tmp_path,
            base_url=base_url,
            accounts=[
                {"alias": "member1", "role": "member", "session_token": "tok_member1_never_crawl"},
                {"alias": "adm", "role": "admin", "session_token": "tok_adm_only_crawl"},
            ],
            allowed_methods=("GET", "HEAD", "POST"),
            max_requests=100,
        )
        out_dir = tmp_path / "spa_out"
        res = run_stage0_crawl(
            http,
            output_dir=out_dir,
            actors=["adm"],
            seed_filename="stage0-post-auth-seed.json",
            max_pages=6,
            max_actions=10,
            wait_ms=250,
            max_passive_probes=0,
        )

        assert res["status"] == "ok"
        assert res["actors_crawled"] == ["adm"]
        assert Path(res["seed_file"]) == out_dir / "stage0-post-auth-seed.json"
        assert (out_dir / "stage0-post-auth-seed.json").is_file()
        assert not (out_dir / "stage0-seed.json").exists()

        # Verify ONLY adm's credentials were used on the wire (never member1's).
        auth_headers = {r["headers"].get("authorization", "") for r in log if r["headers"].get("authorization")}
        assert "Bearer tok_adm_only_crawl" in auth_headers
        assert "Bearer tok_member1_never_crawl" not in auth_headers

        # Safe SPA triggers clicked & XHR + dynamically injected <script src> captured.
        assert res["stats"]["ui_actions_taken"] >= 3
        assert res["stats"]["js_chunks_parsed"] >= 1
        all_routes = {(r["method"], r["url"]) for r in [*res["links"], *res["forms"]]}
        assert ("GET", "/manager/get_list") in all_routes
        assert ("GET", "/api/extensions/list") in all_routes
        assert ("GET", "/api/workflows/recent") in all_routes
        assert ("GET", "/manager/custom-nodes") in all_routes
        assert ("POST", "/manager/install_node") in all_routes

        # Destructive buttons must NEVER have been clicked or requested.
        hit_paths = {urlsplit(r["path"]).path for r in log}
        for forbidden in ("/manager/reboot", "/api/restart", "/api/shutdown", "/api/logout", "/api/stop", "/api/kill"):
            assert forbidden not in hit_paths
        http.close()


# ---------------------------------------------------------------------------
# 3. AgenticInvestigator sharded post-auth refresh hook
# ---------------------------------------------------------------------------


def _build_sharded_server_router() -> Callable[[str, str, dict[str, str], bytes], tuple[int, str, str, dict[str, str]]]:
    def router(method: str, raw_path: str, hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        cookie = hdrs.get("cookie", "")
        if path == "/":
            return 200, "text/html", "<html><body><a href='/admin/login'>Login</a></body></html>", {}
        if path == "/admin/login" and method == "POST":
            return (
                302,
                "text/html",
                "",
                {
                    "Set-Cookie": "PHPSESSID=adm_sess_token_12345; Path=/",
                    "Location": "/admin/Index/index.html",
                },
            )
        if path == "/admin/Index/index.html":
            if "adm_sess_token_12345" not in cookie:
                return 302, "text/html", "", {"Location": "/admin/login"}
            return 200, "text/html", "<html><body><h1>Admin Dashboard</h1></body></html>", {}
        return 200, "application/json", json.dumps({"ok": True, "path": path}), {}

    return router


def test_sharded_investigator_triggers_post_auth_stage0_before_clustering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    stage0_calls: list[dict[str, Any]] = []
    clusters_seen: list[list[str]] = []

    orig_cluster = agentic_investigator.cluster_discovered_surface

    def _spy_cluster(tracker: Any, *args: Any, **kwargs: Any) -> Any:
        events.append("cluster_discovered_surface")
        clusters = orig_cluster(tracker, *args, **kwargs)
        for c in clusters:
            clusters_seen.append(list(c.routes))
        return clusters

    monkeypatch.setattr(agentic_investigator, "cluster_discovered_surface", _spy_cluster)

    def _fake_run_stage0_crawl(
        http_client: Any,
        *,
        output_dir: Path | str | None = None,
        start_paths: list[str] | None = None,
        max_pages: int = 12,
        max_actions: int = 24,
        allow_forms: bool = False,
        actors: list[str] | None = None,
        seed_filename: str = "stage0-seed.json",
        **_kwargs: Any,
    ) -> dict[str, Any]:
        del http_client
        events.append("post_auth_stage0_crawl")
        stage0_calls.append({
            "output_dir": Path(output_dir) if output_dir is not None else None,
            "start_paths": list(start_paths or ()),
            "max_pages": max_pages,
            "max_actions": max_actions,
            "allow_forms": allow_forms,
            "actors": list(actors or ()),
            "seed_filename": seed_filename,
        })
        seed_path = (Path(output_dir) / seed_filename) if output_dir is not None else Path(seed_filename)
        return {
            "schema": "stage0-seed/1",
            "url": base_url,
            "status": "ok",
            "mode": "forms" if allow_forms else "readonly",
            "actors_crawled": list(actors or ()),
            "seed_file": str(seed_path),
            "links": [
                {"method": "GET", "url": "/api/v1/articles/list", "params": ["page"]},
                {"method": "GET", "url": "/api/v1/articles/42", "params": []},
                {"method": "GET", "url": "/api/v1/users/list", "params": ["role"]},
                {"method": "GET", "url": "/api/v1/users/7", "params": []},
                {"method": "GET", "url": "/api/v1/uploads/browse", "params": ["dir"]},
                {"method": "GET", "url": "/api/v1/settings/system", "params": []},
                {"method": "GET", "url": "/api/v1/templates/edit", "params": ["file"]},
                {"method": "GET", "url": "/api/v1/plugins/index", "params": []},
            ],
            "forms": [
                {
                    "method": "POST",
                    "url": "/api/v1/uploads/save",
                    "params": ["file", "folder"],
                    "multipart_schema": {"fields": ["folder"], "files": ["file"]},
                },
                {
                    "method": "POST",
                    "url": "/api/v1/articles/create",
                    "params": ["title", "body"],
                    "body_template": {"title": "hello", "body": "content"},
                },
            ],
            "ws_endpoints": [],
            "discovery_hints": ["/api/v1/articles/list", "/api/v1/uploads/browse"],
            "stats": {
                "status": "ok",
                "pages_visited": 5,
                "ui_actions_taken": 4,
                "requests_charged": 7,
            },
        }

    fake_stage0_mod = types.ModuleType("agentic_stage0_crawl")
    fake_stage0_mod.run_stage0_crawl = _fake_run_stage0_crawl  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "agentic_stage0_crawl", fake_stage0_mod)

    with _start_loopback_server(_build_sharded_server_router()) as (base_url, _port, _log):
        http, store = _make_http_client(
            tmp_path,
            base_url=base_url,
            accounts=[],  # Start with anon ONLY
            allowed_methods=("GET", "POST"),
            max_requests=150,
        )
        budget = SharedBudget(http=150, tokens=500_000, seconds=600)

        def _transport_handler(messages: list[dict[str, Any]], call_num: int) -> dict[str, Any]:
            sys_text = str(messages[0].get("content") or "") if messages else ""
            if "SUBSYSTEM SHARD SCOPE" in sys_text:
                return _tool_resp("finish", {"summary": "shard done", "untested_areas": []}, f"shard_fin_{call_num}")
            # Stage 1 bootstrap turns: login as adm (captures dynamic session + redirect), visit dashboard, finish.
            if call_num == 1:
                return _tool_resp(
                    "http_request",
                    {
                        "actor": "anon",
                        "method": "POST",
                        "url": "/admin/login",
                        "form_body": {"user": "admin", "pass": "pass"},
                        "save_session_as": "adm",
                    },
                    "boot_login",
                )
            if call_num == 2:
                return _tool_resp(
                    "http_request",
                    {"actor": "adm", "method": "GET", "url": "/admin/Index/index.html"},
                    "boot_dash",
                )
            return _tool_resp("finish", {"summary": "bootstrap complete", "untested_areas": []}, f"boot_fin_{call_num}")

        transport = _ScriptedTransport(_transport_handler)
        inv = AgenticInvestigator(
            http_client=http,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path / "run",
            discovery_hints=["/"],
            max_turns=20,
            bootstrap_turns=6,
            shard_turns=4,
            max_shards=3,
            execution_mode="sharded",
            enable_cross_shard_synthesis=False,
            stage0_post_auth_enabled=True,
            stage0_allow_forms=True,
        )
        result = inv.run()

        assert result["status"] == "finished"
        # Post-auth Stage 0 MUST run strictly before cluster_discovered_surface().
        assert events == ["post_auth_stage0_crawl", "cluster_discovered_surface"]
        assert len(stage0_calls) == 1
        call = stage0_calls[0]
        assert call["actors"] == ["adm"]
        assert call["seed_filename"] == "stage0-post-auth-seed.json"
        assert call["max_pages"] == 8
        assert call["max_actions"] == 16
        assert call["allow_forms"] is True
        assert call["output_dir"] == inv.root_dir
        assert call["start_paths"][0] == "/"
        assert "/admin/Index/index.html" in call["start_paths"]
        assert len(call["start_paths"]) <= 8

        # Routes discovered by post-auth Stage 0 were merged into surface_tracker & discovery_hints...
        assert ("GET", "/api/v1/articles/list") in inv.dispatcher.surface_tracker.discovered_routes
        assert ("POST", "/api/v1/uploads/save") in inv.dispatcher.surface_tracker.discovered_routes
        assert "/api/v1/articles/list" in inv.discovery_hints
        assert "/api/v1/uploads/browse" in inv.discovery_hints

        # ...and assigned to Stage 2 shards!
        sharding_summary = result["sharding_summary"]
        assert len(sharding_summary["shards"]) >= 2
        all_shard_routes = {route for routes in clusters_seen for route in routes}
        assert "/api/v1/articles/list" in all_shard_routes
        assert "/api/v1/uploads/save" in all_shard_routes
        assert "/api/v1/users/list" in all_shard_routes

        # Compact post_auth_stage0_crawl summary recorded in sharding_summary.
        pa_summary = sharding_summary["post_auth_stage0_crawl"]
        assert pa_summary["triggered"] is True
        assert pa_summary["status"] == "ok"
        assert pa_summary["actors"] == ["adm"]
        assert pa_summary["actors_crawled"] == ["adm"]
        assert pa_summary["pages_visited"] == 5
        assert pa_summary["ui_actions_taken"] == 4
        assert pa_summary["routes_ingested"] == 10
        assert pa_summary["seed_file"].endswith("stage0-post-auth-seed.json")
        http.close()


@pytest.mark.parametrize(
    "scenario",
    [
        "no_new_actors",
        "pre_existing_actor_only",
        "low_http_budget",
        "low_seconds_budget",
        "disabled_flag",
    ],
)
def test_sharded_post_auth_stage0_skipped_cleanly_when_guards_unmet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
) -> None:
    crawl_calls = 0

    def _spy_stage0(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal crawl_calls
        crawl_calls += 1
        raise AssertionError(f"post-auth Stage 0 must not trigger in scenario={scenario}")

    fake_stage0_mod = types.ModuleType("agentic_stage0_crawl")
    fake_stage0_mod.run_stage0_crawl = _spy_stage0  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "agentic_stage0_crawl", fake_stage0_mod)

    with _start_loopback_server(_build_sharded_server_router()) as (base_url, _port, _log):
        pre_accounts = (
            [{"alias": "adm", "role": "admin", "session_token": "tok_preexisting"}]
            if scenario == "pre_existing_actor_only"
            else []
        )
        max_req = 30 if scenario == "low_http_budget" else 150
        secs = 20 if scenario == "low_seconds_budget" else 600
        enabled = scenario != "disabled_flag"

        http, store = _make_http_client(
            tmp_path,
            base_url=base_url,
            accounts=pre_accounts,
            allowed_methods=("GET", "POST"),
            max_requests=max_req,
        )
        budget = SharedBudget(http=max_req, tokens=500_000, seconds=secs)

        def _transport_handler(_messages: list[dict[str, Any]], call_num: int) -> dict[str, Any]:
            if call_num == 1 and scenario in {"low_http_budget", "low_seconds_budget", "disabled_flag"}:
                # Register a new dynamic actor during Stage 1; guards must still skip Stage 0.
                return _tool_resp(
                    "http_request",
                    {
                        "actor": "anon",
                        "method": "POST",
                        "url": "/admin/login",
                        "form_body": {"user": "admin", "pass": "pass"},
                        "save_session_as": "adm",
                    },
                    "boot_login",
                )
            return _tool_resp("finish", {"summary": "done", "untested_areas": []}, f"fin_{call_num}")

        inv = AgenticInvestigator(
            http_client=http,
            receipt_store=store,
            transport=_ScriptedTransport(_transport_handler),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path / f"run-{scenario}",
            discovery_hints=["/"],
            max_turns=12,
            bootstrap_turns=4,
            shard_turns=3,
            max_shards=2,
            execution_mode="sharded",
            enable_cross_shard_synthesis=False,
            stage0_post_auth_enabled=enabled,
            stage0_allow_forms=False,
        )
        result = inv.run()

        assert crawl_calls == 0
        assert "post_auth_stage0_crawl" not in (result.get("sharding_summary") or {})
        http.close()


def test_sharded_post_auth_stage0_exception_is_resilient(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom_stage0(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("playwright launch failed")

    fake_stage0_mod = types.ModuleType("agentic_stage0_crawl")
    fake_stage0_mod.run_stage0_crawl = _boom_stage0  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "agentic_stage0_crawl", fake_stage0_mod)

    with _start_loopback_server(_build_sharded_server_router()) as (base_url, _port, _log):
        http, store = _make_http_client(
            tmp_path,
            base_url=base_url,
            accounts=[],
            allowed_methods=("GET", "POST"),
            max_requests=120,
        )
        budget = SharedBudget(http=120, tokens=500_000, seconds=600)

        def _transport_handler(_messages: list[dict[str, Any]], call_num: int) -> dict[str, Any]:
            if call_num == 1:
                return _tool_resp(
                    "http_request",
                    {
                        "actor": "anon",
                        "method": "POST",
                        "url": "/admin/login",
                        "form_body": {"user": "admin", "pass": "pass"},
                        "save_session_as": "adm",
                    },
                    "boot_login",
                )
            return _tool_resp("finish", {"summary": "done", "untested_areas": []}, f"fin_{call_num}")

        inv = AgenticInvestigator(
            http_client=http,
            receipt_store=store,
            transport=_ScriptedTransport(_transport_handler),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path / "run-err",
            discovery_hints=["/"],
            max_turns=12,
            bootstrap_turns=4,
            shard_turns=3,
            max_shards=2,
            execution_mode="sharded",
            enable_cross_shard_synthesis=False,
            stage0_post_auth_enabled=True,
            stage0_allow_forms=False,
        )
        result = inv.run()

        assert result["status"] == "finished"
        pa = result["sharding_summary"]["post_auth_stage0_crawl"]
        assert pa["triggered"] is True
        assert pa["status"] == "error"
        assert pa["error"] == "RuntimeError"
        assert pa["actors"] == ["adm"]
        http.close()


def test_runner_wires_stage0_post_auth_flags_to_investigator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_kwargs: list[dict[str, Any]] = []
    orig_inv_cls = agentic_runner.AgenticInvestigator

    class _SpyInvestigator(orig_inv_cls):  # type: ignore[valid-type, misc]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured_kwargs.append({
                "stage0_post_auth_enabled": kwargs.get("stage0_post_auth_enabled"),
                "stage0_allow_forms": kwargs.get("stage0_allow_forms"),
            })
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(agentic_runner, "AgenticInvestigator", _SpyInvestigator)

    fake_stage0_mod = types.ModuleType("agentic_stage0_crawl")
    fake_stage0_mod.run_stage0_crawl = lambda *_a, **_kw: {  # type: ignore[attr-defined]
        "schema": "stage0-seed/1",
        "status": "skipped_no_playwright",
        "links": [],
        "forms": [],
        "discovery_hints": [],
        "stats": {"status": "skipped_no_playwright", "pages_visited": 0},
    }
    monkeypatch.setitem(sys.modules, "agentic_stage0_crawl", fake_stage0_mod)

    def _prov_router(_method: str, _path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        return 200, "application/json", json.dumps(_tool_resp("finish", {"summary": "done", "untested_areas": []}, "c1")), {}

    with (
        _start_loopback_server(_build_sharded_server_router()) as (target_base, _tp, _tl),
        _start_loopback_server(_prov_router) as (prov_base, _pp, _pl),
    ):
        cfg = tmp_path / "llm.json"
        cfg.write_text(
            json.dumps({
                "schema": "cco-llm/1",
                "model": "local/test-model",
                "providers": {
                    "local": {
                        "base_url": prov_base + "v1",
                        "models": ["test-model"],
                        "api_key_env": "TEST_FAZ2A_KEY",
                        "api_key_header": "Authorization",
                    }
                },
            }),
            encoding="utf-8",
        )
        monkeypatch.setenv("TEST_FAZ2A_KEY", "dummy-local-key")

        agentic_runner.run_agentic_target(
            target=target_base,
            provider_config=cfg,
            output_dir=tmp_path / "run-enabled",
            allowed_methods=["GET", "POST"],
            auto_crawl=True,
            auto_crawl_forms=True,
            execute=True,
            max_turns=3,
        )
        agentic_runner.run_agentic_target(
            target=target_base,
            provider_config=cfg,
            output_dir=tmp_path / "run-disabled",
            allowed_methods=["GET", "POST"],
            auto_crawl=False,
            auto_crawl_forms=False,
            execute=True,
            max_turns=3,
        )

    assert captured_kwargs == [
        {"stage0_post_auth_enabled": True, "stage0_allow_forms": True},
        {"stage0_post_auth_enabled": False, "stage0_allow_forms": False},
    ]
