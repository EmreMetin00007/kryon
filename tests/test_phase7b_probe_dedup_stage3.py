"""Tests for Faz 7B: Stage 0/post-auth probe deduplication, OpenAPI auth header wiring, and adaptive Stage 3 budget."""
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

import agentic_investigator as inv_mod  # noqa: E402
import agentic_stage0_crawl  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import (  # noqa: E402
    AgenticInvestigator,
    _compute_stage3_synthesis_max_turns,
    _is_post_auth_passive_discovery_path,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_stage0_crawl import (  # noqa: E402
    _Stage0Budget,
    _Stage0Collector,
    _run_layer4_passive_fusion,
    extract_openapi_header_auth_names,
    run_stage0_crawl,
)
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import SessionGate  # noqa: E402


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
) -> tuple[AgenticHTTPClient, ReceiptStore]:
    store = ReceiptStore(tmp_path / "run")
    actors = ActorManager(accounts or [])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
    )
    return client, store


def _patch_mock_playwright(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub Playwright so run_stage0_crawl executes Layer 4 deterministically without Chromium."""
    monkeypatch.setattr(agentic_stage0_crawl, "HAS_PLAYWRIGHT", True)

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
        collector.pages_visited += len(start_urls)
        for u in start_urls:
            collector.record_route(method="GET", raw_url=u, status=200)
        return []

    monkeypatch.setattr(agentic_stage0_crawl, "_sync_playwright", lambda: _FakePlaywrightCM())
    monkeypatch.setattr(agentic_stage0_crawl, "_crawl_actor_playwright", _fake_crawl_actor)


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
        "usage": {
            "prompt_tokens": 120,
            "completion_tokens": 30,
            "total_tokens": 150,
            "prompt_tokens_details": {"cached_tokens": 60},
            "completion_tokens_details": {"reasoning_tokens": 5},
        },
    }


class _ScriptedTransport:
    def __init__(self, handler: Callable[[list[dict[str, Any]], int], dict[str, Any]]) -> None:
        self._handler = handler
        self.calls = 0
        self.provider_responses: list[dict[str, Any]] = []
        self.session_gate = SessionGate()
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


# ---------------------------------------------------------------------------
# 1. Stage 0 skip_probe_paths and stats["probed_paths"]
# ---------------------------------------------------------------------------


def test_stage0_records_probed_paths_and_skips_prior_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_mock_playwright(monkeypatch)

    def router(_method: str, _raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_loopback_server(router) as (base_url, _port, log):
        http, _store = _make_http_client(
            tmp_path,
            base_url=base_url,
            accounts=[{"alias": "adm", "role": "admin", "session_token": "tok_adm_dedup_test"}],
            max_requests=120,
        )

        res1 = run_stage0_crawl(
            http,
            output_dir=tmp_path / "out1",
            actors=["anon"],
            max_pages=4,
            max_passive_probes=12,
        )
        expected_probed = sorted({
            "/openapi.json",
            "/swagger.json",
            "/v3/api-docs",
            "/api-docs",
            "/api/v3/api-docs",
            "/api/openapi.json",
            "/api/swagger.json",
            "/robots.txt",
            "/sitemap.xml",
            "/info",
        })
        assert res1["stats"]["passive_probes_sent"] == 10
        assert res1["stats"]["probed_paths"] == expected_probed
        assert len(log) == 10

        # Crawling as a different actor ("adm") bypasses AgenticHTTPClient GET dedup,
        # proving skip_probe_paths itself suppresses all 10 redundant passive probes.
        log.clear()
        res2 = run_stage0_crawl(
            http,
            output_dir=tmp_path / "out2",
            actors=["adm"],
            max_pages=4,
            max_passive_probes=12,
            skip_probe_paths=res1["stats"]["probed_paths"],
        )
        assert res2["stats"]["passive_probes_sent"] == 0
        assert res2["stats"]["probed_paths"] == []
        assert log == []

        # Partial skip_probe_paths (with trailing slash and full URL normalization) skips only matched paths.
        res3 = run_stage0_crawl(
            http,
            output_dir=tmp_path / "out3",
            actors=["adm"],
            max_pages=4,
            max_passive_probes=3,
            skip_probe_paths=[
                f"{base_url}openapi.json",
                "/swagger.json/",
                "/v3/api-docs",
            ],
        )
        probed3 = [urlsplit(r["path"]).path for r in log]
        assert "/openapi.json" not in probed3
        assert "/swagger.json" not in probed3
        assert "/v3/api-docs" not in probed3
        assert probed3 == ["/api-docs", "/api/v3/api-docs", "/api/openapi.json"]
        assert res3["stats"]["probed_paths"] == ["/api-docs", "/api/openapi.json", "/api/v3/api-docs"]
        http.close()


# ---------------------------------------------------------------------------
# 2. OpenAPI securitySchemes / securityDefinitions header extraction & wiring
# ---------------------------------------------------------------------------


def test_extract_openapi_header_auth_names_filters_standard_and_non_header_schemes() -> None:
    openapi3_spec = {
        "openapi": "3.0.3",
        "paths": {"/items": {"get": {}}},
        "components": {
            "securitySchemes": {
                "AccessToken": {"type": "apiKey", "in": "header", "name": "X-Access-Token"},
                "AccessTokenDup": {"type": "apiKey", "in": "header", "name": "x-access-token"},
                "TenantKey": {"$ref": "#/components/securitySchemes/TenantKeyTarget"},
                "TenantKeyTarget": {"type": "apiKey", "in": "header", "name": "X-Tenant-Api-Key"},
                "StdAuth": {"type": "apiKey", "in": "header", "name": "Authorization"},
                "StdCookie": {"type": "apiKey", "in": "header", "name": "Cookie"},
                "StdAccept": {"type": "apiKey", "in": "header", "name": "Accept"},
                "StdContentType": {"type": "apiKey", "in": "header", "name": "Content-Type"},
                "StdUserAgent": {"type": "apiKey", "in": "header", "name": "User-Agent"},
                "BearerScheme": {"type": "http", "scheme": "bearer"},
                "QueryKey": {"type": "apiKey", "in": "query", "name": "api_key"},
                "CookieKey": {"type": "apiKey", "in": "cookie", "name": "session_id"},
            }
        },
    }
    assert extract_openapi_header_auth_names(openapi3_spec) == ["X-Access-Token", "X-Tenant-Api-Key"]

    swagger2_spec = {
        "swagger": "2.0",
        "paths": {"/orders": {"get": {}}},
        "securityDefinitions": {
            "ApiKeyHeader": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            "BadHeader": {"type": "apiKey", "in": "header", "name": "Bad Header\r\n"},
            "BasicAuth": {"type": "basic"},
        },
    }
    assert extract_openapi_header_auth_names(swagger2_spec) == ["X-API-Key"]


@pytest.mark.parametrize("spec_format", ["json", "yaml"])
def test_stage0_registers_openapi_security_scheme_headers_and_exposes_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    spec_format: str,
) -> None:
    _patch_mock_playwright(monkeypatch)

    openapi_doc = {
        "openapi": "3.0.1",
        "info": {"title": "Header Auth API", "version": "1.0"},
        "components": {
            "securitySchemes": {
                "AccessToken": {"type": "apiKey", "in": "header", "name": "X-Access-Token"},
                "StdAuth": {"type": "apiKey", "in": "header", "name": "Authorization"},
                "QueryKey": {"type": "apiKey", "in": "query", "name": "api_key"},
            }
        },
        "paths": {
            "/api/profile": {"get": {}},
        },
    }

    def router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/openapi.json":
            if spec_format == "json":
                return 200, "application/json", json.dumps(openapi_doc), {}
            import yaml  # type: ignore[import-untyped]

            return 200, "application/yaml", yaml.safe_dump(openapi_doc, sort_keys=False), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_loopback_server(router) as (base_url, _port, _log):
        http, _store = _make_http_client(tmp_path, base_url=base_url, max_requests=80)
        registered: list[tuple[str, str]] = []

        def _register_header(name: str, default_val: str = "") -> None:
            registered.append((name, default_val))

        setattr(http, "register_discovered_auth_header", _register_header)

        res = run_stage0_crawl(
            http,
            output_dir=tmp_path / f"out-{spec_format}",
            max_pages=4,
            max_passive_probes=6,
        )
        assert registered == [("X-Access-Token", "")]
        assert res["auth_headers"] == ["X-Access-Token"]
        assert res["stats"]["discovered_auth_headers"] == ["X-Access-Token"]
        assert "/openapi.json" in res["stats"]["probed_paths"]
        assert any(r["url"] == "/api/profile" for r in res["links"])

        loaded = json.loads(Path(res["seed_file"]).read_text(encoding="utf-8"))
        assert loaded["auth_headers"] == ["X-Access-Token"]
        assert loaded["stats"]["discovered_auth_headers"] == ["X-Access-Token"]
        http.close()


# ---------------------------------------------------------------------------
# 3. _derive_post_auth_extra_seed_paths filters passive discovery/spec paths
# ---------------------------------------------------------------------------


def test_derive_post_auth_extra_seed_paths_excludes_passive_spec_and_metadata_paths(tmp_path: Path) -> None:
    base_url = "http://127.0.0.1:18080/"
    http, store = _make_http_client(tmp_path, base_url=base_url)
    inv = AgenticInvestigator(
        http_client=http,
        receipt_store=store,
        transport=_ScriptedTransport(lambda _m, n: _tool_resp("finish", {"summary": "done"}, f"f{n}")),  # type: ignore[arg-type]
        budget=SharedBudget(http=120, tokens=300_000, seconds=300),
        model="test-model",
        root_dir=tmp_path / "run",
        execution_mode="sharded",
    )

    passive_candidates = [
        "/openapi.json",
        "/swagger.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
        "/swagger-ui",
        "/swagger-ui.html",
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/openid-configuration",
        "/graphql",
        "/api/openapi.json",
        "/api/swagger.json",
        "/api/v3/api-docs",
        "/api/api-docs",
    ]
    for idx, p in enumerate(passive_candidates):
        ctype = "text/html" if idx % 2 == 0 else "application/json"
        rec = store.record(
            actor="anon",
            method="GET",
            url=f"{base_url.rstrip('/')}{p}",
            path=p,
            status=401 if idx % 2 == 0 else 403,
            elapsed_ms=2.0,
            content_type=ctype,
            response_text="<html><body>Unauthorized</body></html>" if ctype == "text/html" else '{"err":"denied"}',
        )
        inv.dispatcher.surface_tracker.ingest_receipt(rec)
        assert _is_post_auth_passive_discovery_path(p) is True

    # Real auth-gated HTML routes must still be preserved.
    r_real_1 = store.record(
        actor="anon",
        method="GET",
        url=f"{base_url}console/dashboard",
        path="/console/dashboard",
        status=403,
        elapsed_ms=2.0,
        content_type="text/html",
        response_text="<html><body>Forbidden</body></html>",
    )
    inv.dispatcher.surface_tracker.ingest_receipt(r_real_1)
    r_real_2 = store.record(
        actor="anon",
        method="GET",
        url=f"{base_url}portal/orders",
        path="/portal/orders",
        status=302,
        elapsed_ms=2.0,
        content_type="text/html",
        redirect_location="/login",
    )
    inv.dispatcher.surface_tracker.ingest_receipt(r_real_2)

    r_login = store.record(
        actor="anon",
        method="POST",
        url=f"{base_url}admin/login",
        path="/admin/login",
        status=200,
        elapsed_ms=5.0,
        content_type="application/json",
        response_text=json.dumps({"redirect": "/admin/home"}),
    )
    http.actors.register_dynamic_session(
        "adm",
        cookies={"sid": "adm_cookie_xyz_12345"},
        source_receipt_id=r_login["receipt_id"],
    )

    extras = inv._derive_post_auth_extra_seed_paths(["adm"], limit=6)
    for passive_p in passive_candidates:
        assert passive_p not in extras, f"passive discovery path {passive_p} leaked into extras: {extras}"
    assert "/admin/home" in extras
    assert "/console/dashboard" in extras
    assert "/portal/orders" in extras
    http.close()


# ---------------------------------------------------------------------------
# 4. AgenticInvestigator post-auth crawl deduplicates passive probes
# ---------------------------------------------------------------------------


def _run_sharded_auth_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    spec_401_path: str | None = None,
    adm_already_fetched_spec: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    captured_calls: list[dict[str, Any]] = []

    def _fake_run_stage0_crawl(
        _http: Any,
        *,
        output_dir: Path | str | None = None,
        start_paths: list[str] | None = None,
        extra_seed_paths: list[str] | None = None,
        actors: list[str] | None = None,
        seed_filename: str = "stage0-seed.json",
        max_passive_probes: int = 12,
        skip_probe_paths: list[str] | None = None,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        captured_calls.append({
            "start_paths": list(start_paths or ()),
            "extra_seed_paths": list(extra_seed_paths or ()),
            "actors": list(actors or ()),
            "seed_filename": seed_filename,
            "max_passive_probes": max_passive_probes,
            "skip_probe_paths": list(skip_probe_paths or ()),
        })
        seed_path = (Path(output_dir) / seed_filename) if output_dir is not None else Path(seed_filename)
        return {
            "schema": "stage0-seed/1",
            "url": "http://127.0.0.1/",
            "status": "ok",
            "mode": "readonly",
            "actors_crawled": list(actors or ()),
            "seed_file": str(seed_path),
            "links": [{"method": "GET", "url": "/panel/users", "params": []}],
            "forms": [],
            "ws_endpoints": [],
            "discovery_hints": ["/panel/users"],
            "stats": {
                "status": "ok",
                "pages_visited": 2,
                "ui_actions_taken": 0,
                "passive_probes_sent": 0,
                "requests_charged": 2,
            },
        }

    fake_stage0_mod = types.ModuleType("agentic_stage0_crawl")
    fake_stage0_mod.run_stage0_crawl = _fake_run_stage0_crawl  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "agentic_stage0_crawl", fake_stage0_mod)

    def router(method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/panel/login" and method == "POST":
            return (
                200,
                "application/json",
                json.dumps({"ok": True, "redirect_url": "/panel/home"}),
                {"Set-Cookie": "sid=adm_dedup_sess_999; Path=/"},
            )
        return 200, "text/html", "<html><body>OK</body></html>", {}

    with _start_loopback_server(router) as (base_url, _port, _log):
        http, store = _make_http_client(
            tmp_path,
            base_url=base_url,
            accounts=[],
            allowed_methods=("GET", "POST"),
            max_requests=150,
        )
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True, exist_ok=True)

        pre_auth_probed = [
            "/api-docs",
            "/api/openapi.json",
            "/api/swagger.json",
            "/api/v3/api-docs",
            "/info",
            "/openapi.json",
            "/robots.txt",
            "/sitemap.xml",
            "/swagger.json",
            "/v3/api-docs",
        ]
        (run_dir / "stage0-seed.json").write_text(
            json.dumps({
                "schema": "stage0-seed/1",
                "url": base_url,
                "stats": {"status": "ok", "probed_paths": pre_auth_probed},
            }),
            encoding="utf-8",
        )
        for p in pre_auth_probed:
            st = 401 if (spec_401_path is not None and p == spec_401_path) else 404
            store.record(
                actor="anon",
                method="GET",
                url=f"{base_url.rstrip('/')}{p}",
                path=p,
                status=st,
                elapsed_ms=1.0,
                content_type="application/json",
                response_text="{}",
            )

        def _transport_handler(messages: list[dict[str, Any]], call_num: int) -> dict[str, Any]:
            sys_text = str(messages[0].get("content") or "") if messages else ""
            if "SUBSYSTEM SHARD SCOPE" in sys_text:
                return _tool_resp("finish", {"summary": "shard done", "untested_areas": []}, f"sfin_{call_num}")
            if call_num == 1:
                return _tool_resp(
                    "http_request",
                    {
                        "actor": "anon",
                        "method": "POST",
                        "url": "/panel/login",
                        "form_body": {"user": "admin", "pass": "pass"},
                        "save_session_as": "adm",
                    },
                    "boot_login",
                )
            if call_num == 2 and adm_already_fetched_spec and spec_401_path:
                return _tool_resp(
                    "http_request",
                    {"actor": "adm", "method": "GET", "url": spec_401_path},
                    "boot_spec_adm",
                )
            return _tool_resp("finish", {"summary": "boot done", "untested_areas": []}, f"bfin_{call_num}")

        inv = AgenticInvestigator(
            http_client=http,
            receipt_store=store,
            transport=_ScriptedTransport(_transport_handler),  # type: ignore[arg-type]
            budget=SharedBudget(http=150, tokens=400_000, seconds=600),
            model="test-model",
            root_dir=run_dir,
            discovery_hints=["/"],
            max_turns=16,
            bootstrap_turns=6,
            shard_turns=4,
            max_shards=2,
            execution_mode="sharded",
            enable_cross_shard_synthesis=False,
            stage0_post_auth_enabled=True,
            stage0_allow_forms=False,
        )
        res = inv.run()
        http.close()
        return captured_calls, res


def test_post_auth_stage0_disables_probes_when_pre_auth_probes_all_404(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, _res = _run_sharded_auth_flow(tmp_path, monkeypatch, spec_401_path=None)
    assert len(calls) == 1
    call = calls[0]
    assert call["seed_filename"] == "stage0-post-auth-seed.json"
    assert call["max_passive_probes"] == 0
    assert "/openapi.json" in call["skip_probe_paths"]
    assert "/robots.txt" in call["skip_probe_paths"]
    assert "/info" in call["skip_probe_paths"]


def test_post_auth_stage0_allows_reprobing_only_auth_gated_spec_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls_gated, _ = _run_sharded_auth_flow(
        tmp_path / "gated",
        monkeypatch,
        spec_401_path="/api/openapi.json",
        adm_already_fetched_spec=False,
    )
    assert len(calls_gated) == 1
    gated_call = calls_gated[0]
    assert gated_call["max_passive_probes"] == 2
    assert "/api/openapi.json" not in gated_call["skip_probe_paths"]
    assert "/openapi.json" in gated_call["skip_probe_paths"]
    assert "/robots.txt" in gated_call["skip_probe_paths"]

    # If the newly authenticated actor already fetched that spec with 200 during Stage 1, skip probes again.
    calls_done, _ = _run_sharded_auth_flow(
        tmp_path / "already_fetched",
        monkeypatch,
        spec_401_path="/api/openapi.json",
        adm_already_fetched_spec=True,
    )
    assert len(calls_done) == 1
    assert calls_done[0]["max_passive_probes"] == 0


def test_layer4_skips_404_probes_and_only_probes_auth_gated_spec_end_to_end(tmp_path: Path) -> None:
    openapi_doc = {
        "openapi": "3.0.3",
        "info": {"title": "Auth Gated Spec", "version": "1.0"},
        "components": {
            "securitySchemes": {
                "AccessToken": {"type": "apiKey", "in": "header", "name": "X-Access-Token"},
            }
        },
        "paths": {"/api/admin/audit": {"get": {}}},
    }

    def router(_method: str, raw_path: str, hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        authed = "adm_tok" in hdrs.get("authorization", "")
        if path == "/api/openapi.json":
            if not authed:
                return 401, "application/json", json.dumps({"error": "auth required"}), {}
            return 200, "application/json", json.dumps(openapi_doc), {}
        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_loopback_server(router) as (base_url, _port, log):
        http, _store = _make_http_client(
            tmp_path,
            base_url=base_url,
            accounts=[{"alias": "adm", "role": "admin", "session_token": "adm_tok_secret_1234"}],
            max_requests=120,
        )
        # Pre-auth passive fusion as anon: 10 probes (9x 404, 1x 401 on /api/openapi.json)
        col_pre = _Stage0Collector(http)
        bud_pre = _Stage0Budget(http, cap=20, reserve=12)
        _run_layer4_passive_fusion(http, col_pre, bud_pre, primary_actor="anon", max_passive_probes=12)
        assert col_pre.passive_probes_sent == 10

        log.clear()
        skip_paths = sorted(col_pre.probed_paths - {"/api/openapi.json"})
        col_post = _Stage0Collector(http)
        bud_post = _Stage0Budget(http, cap=12, reserve=4)
        _run_layer4_passive_fusion(
            http,
            col_post,
            bud_post,
            primary_actor="adm",
            max_passive_probes=2,
            skip_probe_paths=skip_paths,
        )
        post_paths = [urlsplit(r["path"]).path for r in log]
        assert post_paths == ["/api/openapi.json"]
        assert ("GET", "/api/admin/audit") in col_post.routes
        assert col_post.discovered_auth_headers == ["X-Access-Token"]
        http.close()


# ---------------------------------------------------------------------------
# 5. Adaptive Stage 3 synthesis turn cap
# ---------------------------------------------------------------------------


def test_compute_stage3_synthesis_max_turns_adapts_only_with_budget_and_signals() -> None:
    rich_ctx = {
        "findings": [{"finding_id": "F-001"}, {"finding_id": "F-002"}],
        "internal_urls": ["http://127.0.0.1:9100/internal"],
        "extracted_values": ["X-Partner-Key=PK123"],
        "auth_capabilities": ["jwt_weakness: GET /api/admin"],
        "blockers": ["[shard-2] POST /api/upgrade blocked 403"],
        "untested_writes_and_blocked": ["POST /api/upgrade"],
    }
    sparse_ctx = {
        "findings": [],
        "internal_urls": [],
        "extracted_values": [],
        "auth_capabilities": [],
        "blockers": [],
        "untested_writes_and_blocked": ["POST /api/ping"],
    }

    # Small / constrained budgets stay <= 12 (preserving base cap).
    assert _compute_stage3_synthesis_max_turns(
        investigator_max_turns=30,
        remaining_http=45,
        remaining_tokens=200_000,
        remaining_seconds=120.0,
        synthesis_context=rich_ctx,
    ) == 10
    assert _compute_stage3_synthesis_max_turns(
        investigator_max_turns=55,
        remaining_http=79,
        remaining_tokens=300_000,
        remaining_seconds=300.0,
        synthesis_context=rich_ctx,
    ) == 12
    assert _compute_stage3_synthesis_max_turns(
        investigator_max_turns=55,
        remaining_http=120,
        remaining_tokens=119_999,
        remaining_seconds=300.0,
        synthesis_context=rich_ctx,
    ) == 12
    assert _compute_stage3_synthesis_max_turns(
        investigator_max_turns=55,
        remaining_http=120,
        remaining_tokens=300_000,
        remaining_seconds=89.0,
        synthesis_context=rich_ctx,
    ) == 12

    # Abundant budget with sparse synthesis context stays at base 12.
    assert _compute_stage3_synthesis_max_turns(
        investigator_max_turns=55,
        remaining_http=140,
        remaining_tokens=350_000,
        remaining_seconds=300.0,
        synthesis_context=sparse_ctx,
    ) == 12

    # Healthy budget >=80 HTTP / >=120k tok / >=90s with moderate signals scales modestly (>12, <=18).
    mid_turns = _compute_stage3_synthesis_max_turns(
        investigator_max_turns=55,
        remaining_http=85,
        remaining_tokens=150_000,
        remaining_seconds=100.0,
        synthesis_context={"findings": [{"finding_id": "F-1"}], "extracted_values": ["k=v"]},
    )
    assert 12 < mid_turns <= 18

    # Abundant budget (>=100 HTTP / >=220k tok / >=120s) + rich findings/artifacts reaches 18.
    assert _compute_stage3_synthesis_max_turns(
        investigator_max_turns=55,
        remaining_http=120,
        remaining_tokens=320_000,
        remaining_seconds=240.0,
        synthesis_context=rich_ctx,
    ) == 18

    # Strictly honors smaller investigator max_turns ceilings.
    assert _compute_stage3_synthesis_max_turns(
        investigator_max_turns=12,
        remaining_http=140,
        remaining_tokens=350_000,
        remaining_seconds=300.0,
        synthesis_context=rich_ctx,
    ) == 6
    assert _compute_stage3_synthesis_max_turns(
        investigator_max_turns=4,
        remaining_http=140,
        remaining_tokens=350_000,
        remaining_seconds=300.0,
        synthesis_context=rich_ctx,
    ) == 4


def test_e2e_stage3_synthesis_uses_expanded_turn_budget_when_headroom_abundant(tmp_path: Path) -> None:
    def router(_method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            html = (
                "<html><body>"
                "<a href='/api/orders/list'>Orders</a>"
                "<a href='/api/orders/detail'>Orders Detail</a>"
                "<a href='/api/orders/history'>Orders History</a>"
                "<a href='/api/orders/export'>Orders Export</a>"
                "<a href='/api/billing/info'>Billing</a>"
                "<a href='/api/billing/status'>Billing Status</a>"
                "<a href='/api/billing/invoices'>Billing Invoices</a>"
                "<a href='/api/billing/plans'>Billing Plans</a>"
                "<form method='POST' action='/api/billing/upgrade'><input name='plan'/></form>"
                "</body></html>"
            )
            return 200, "text/html", html, {}
        if path == "/api/orders/list":
            return 200, "application/json", json.dumps({
                "partner_key": "PK-7788",
                "internal_url": "http://127.0.0.1:9199/admin/sync",
            }), {}
        if path == "/api/billing/upgrade":
            return 403, "application/json", json.dumps({"error": "partner_key required"}), {}
        return 200, "application/json", json.dumps({"ok": True}), {}

    with _start_loopback_server(router) as (base_url, _port, _log):
        http, store = _make_http_client(
            tmp_path,
            base_url=base_url,
            accounts=[{"alias": "alice", "role": "member", "session_token": "tok_alice_stage3_test"}],
            allowed_methods=("GET", "POST"),
            max_requests=180,
        )
        budget = SharedBudget(http=180, tokens=450_000, seconds=600)
        state_lock = threading.Lock()
        boot_step = [0]
        shard_steps: dict[str, int] = {}
        s3_step = [0]

        def _handler(messages: list[dict[str, Any]], call_num: int) -> dict[str, Any]:
            sys_msg = str((messages[0] if messages else {}).get("content") or "")
            if "UNIFIED CROSS-SHARD CHAIN SYNTHESIS (Stage 3)" in sys_msg:
                with state_lock:
                    s3_step[0] += 1
                    cur = s3_step[0]
                if cur <= 13:
                    return _tool_resp(
                        "notebook",
                        {"action": "read"},
                        f"s3_nb_{cur}",
                    )
                return _tool_resp("finish", {"summary": "Stage 3 finished after 14 turns"}, f"s3_fin_{cur}")

            if "SUBSYSTEM SHARD SCOPE (" in sys_msg:
                marker = "SUBSYSTEM SHARD SCOPE ("
                shard_id = sys_msg[sys_msg.index(marker) + len(marker) :].split(":", 1)[0].strip()
                routes_text = sys_msg.split("Assigned routes:", 1)[1]
                with state_lock:
                    step = shard_steps.get(shard_id, 0) + 1
                    shard_steps[shard_id] = step
                if step == 1 and "orders" in routes_text:
                    return _tool_resp("http_request", {"method": "GET", "url": "/api/orders/list", "actor": "alice"}, f"{shard_id}_1")
                if step == 1 and "billing" in routes_text:
                    return _tool_resp(
                        "http_request",
                        {"method": "POST", "url": "/api/billing/upgrade", "actor": "alice", "json_body": {"plan": "pro"}},
                        f"{shard_id}_1",
                    )
                return _tool_resp(
                    "finish",
                    {
                        "summary": f"{shard_id} blocked awaiting partner_key",
                        "untested_areas": ["POST /api/billing/upgrade blocked 403; requires partner_key"],
                    },
                    f"{shard_id}_fin",
                )

            with state_lock:
                boot_step[0] += 1
                bstep = boot_step[0]
            if bstep == 1:
                return _tool_resp("http_request", {"method": "GET", "url": "/", "actor": "alice"}, "b1")
            if bstep == 2:
                return _tool_resp("extract_surface", {"receipt_id": "req-0001"}, "b2")
            return _tool_resp("finish", {"summary": "boot done", "untested_areas": []}, f"b_{call_num}")

        inv = AgenticInvestigator(
            http_client=http,
            receipt_store=store,
            transport=_ScriptedTransport(_handler),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path / "run",
            discovery_hints=["/"],
            max_turns=54,
            bootstrap_turns=6,
            shard_turns=6,
            max_shards=2,
            execution_mode="sharded",
            enable_cross_shard_synthesis=True,
            sleep_fn=lambda _s: None,
        )
        res = inv.run()
        s3_meta = res["sharding_summary"]["stage3_synthesis"]
        assert s3_meta["triggered"] is True
        assert s3_meta["status"] == "finished"
        assert s3_meta["max_turns"] > 12
        assert s3_meta["max_turns"] <= 18
        assert s3_meta["calls"] == 14
        http.close()
