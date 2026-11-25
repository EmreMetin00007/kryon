"""Tests for Faz A: Scope-Locked Recon, Passive CT Helper, AssetGraph, and CLI."""
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

import agentic_recon  # noqa: E402
from agentic_recon import (  # noqa: E402
    PLAN_SCHEMA,
    SCHEMA,
    AssetGraph,
    fetch_ct_subdomains,
    main,
    run_recon,
)
import target_bootstrap as tb  # noqa: E402


@contextmanager
def _start_test_server(
    router: Callable[[str, str, dict[str, str]], tuple[int, str, str, dict[str, str]]],
) -> Iterator[tuple[str, int, list[dict[str, Any]]]]:
    requests_log: list[dict[str, Any]] = []
    lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            with lock:
                requests_log.append({"method": "GET", "path": self.path, "headers": hdrs})
            status, ctype, body, extra_hdrs = router("GET", self.path, hdrs)
            raw = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            for hk, hv in (extra_hdrs or {}).items():
                self.send_header(hk, hv)
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", port, requests_log
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


def _write_scope_file(tmp_path: Path, data: dict[str, Any], name: str = "scope.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 1. Offline Plan Mode (0 requests, no header values on disk, scope enforced)
# ---------------------------------------------------------------------------


def test_offline_plan_mode_zero_requests_redacts_header_values_and_excludes_oos(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope_file = _write_scope_file(
        tmp_path,
        {
            "in_scope": [
                "https://www.target.example",
                "*.target.example",
                "https://bff.target.example",
            ],
            "out_of_scope": [
                "admin.target.example",
                "/logout",
            ],
        },
    )

    seed_file = tmp_path / "stage0-seed.json"
    seed_file.write_text(
        json.dumps({
            "schema": "stage0-seed/1",
            "url": "https://www.target.example/",
            "discovered_api_hosts": [
                {
                    "origin": "https://auth.target.example",
                    "host": "auth.target.example",
                    "sample_paths": ["/oauth/authorize"],
                },
                {
                    "origin": "https://admin.target.example",
                    "host": "admin.target.example",
                    "sample_paths": ["/users"],
                },
                {
                    "origin": "https://evil.example",
                    "host": "evil.example",
                    "sample_paths": ["/steal"],
                },
            ],
        }),
        encoding="utf-8",
    )

    def _forbid_network(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("network/fetcher must never be called in plan mode")

    monkeypatch.setattr("urllib.request.urlopen", _forbid_network)
    monkeypatch.setattr("requests.Session.request", _forbid_network)

    header_secret_val = "CyberbountyProgramValue99"
    out_dir = tmp_path / "plan-out"
    plan_path, plan_doc = run_recon(
        target="https://www.target.example",
        output_dir=out_dir,
        scope_file=scope_file,
        allow_non_loopback=True,
        seed_files=[seed_file],
        custom_headers=["Pentest: " + header_secret_val, "X-Program-Tag: Alpha9"],
        passive_ct=True,
        execute=False,
        ct_fetcher=_forbid_network,
    )

    assert plan_path == out_dir / "recon-plan.json"
    assert plan_path.is_file()
    assert plan_doc["schema"] == PLAN_SCHEMA
    assert plan_doc["mode"] == "plan_only"
    assert plan_doc["requests_sent"] == 0
    assert plan_doc["request_headers"] == ["Pentest", "X-Program-Tag"]

    raw_plan = plan_path.read_text(encoding="utf-8")
    assert header_secret_val not in raw_plan
    assert "Alpha9" not in raw_plan

    assert "https://www.target.example" in plan_doc["in_scope_hosts"]
    assert "https://bff.target.example" in plan_doc["in_scope_hosts"]
    assert "https://auth.target.example" in plan_doc["in_scope_hosts"]
    assert "https://admin.target.example" not in plan_doc["in_scope_hosts"]
    assert "https://evil.example" not in plan_doc["in_scope_hosts"]
    assert not (out_dir / "asset-graph.json").exists()
    assert not (out_dir / "scope.recommended.json").exists()


# ---------------------------------------------------------------------------
# 2. AssetGraph Ingestion (scope + stage0 + HAR + mocked CT + wildcard rules)
# ---------------------------------------------------------------------------


def test_asset_graph_ingestion_wildcard_scope_and_roundtrip(tmp_path: Path) -> None:
    scope_doc = {
        "in_scope": [
            "https://www.target.example",
            "*.target.example",
        ],
        "out_of_scope": [
            "admin.target.example",
            "*.internal.target.example",
            "/logout",
        ],
    }
    scope_file = _write_scope_file(tmp_path, scope_doc)
    _origin, meta = tb.resolve_target_origin(
        "https://www.target.example",
        scope_file=scope_file,
        allow_non_loopback=True,
    )
    guard = tb.ScopeGuard(
        "https://www.target.example",
        excluded_paths=tuple(meta["excluded_paths"]),
        in_scope_assets=tuple(meta["in_scope_assets"]),
        out_of_scope_assets=tuple(meta["out_of_scope_assets"]),
    )

    graph = AssetGraph(guard)
    graph.ingest_scope_doc(scope_doc)

    # 1. Stage0 seed with discovered_api_hosts
    graph.ingest_stage0_seed({
        "schema": "stage0-seed/1",
        "url": "https://www.target.example/",
        "discovered_api_hosts": [
            {
                "origin": "https://bff.target.example",
                "host": "bff.target.example",
                "sample_paths": ["/v1/cart", "/v1/checkout"],
            },
            {
                "origin": "https://admin.target.example",
                "host": "admin.target.example",
                "sample_paths": ["/users"],
            },
        ],
    })

    # 2. HAR ingestion (edges: authenticates_at, loads_cdn_js, redirects_to; strips query values)
    graph.ingest_har({
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://www.target.example/?secretQuery=dontLeak",
                        "headers": [{"name": "Cookie", "value": "sid=hidden"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Server", "value": "nginx"}],
                        "content": {
                            "mimeType": "text/html",
                            "text": "<html><head><title>Target Storefront</title></head><body></body></html>",
                        },
                    },
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://auth.target.example/oauth/token?code=secretcode",
                        "headers": [{"name": "Origin", "value": "https://www.target.example"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"mimeType": "application/json", "text": '{"ok":true}'},
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://cdn.other.example/bundle.js",
                        "headers": [{"name": "Referer", "value": "https://www.target.example/"}],
                    },
                    "_resourceType": "script",
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/javascript"}],
                        "content": {"mimeType": "application/javascript", "text": ""},
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://evil.example/callback",
                        "headers": [{"name": "Referer", "value": "https://www.target.example/"}],
                    },
                    "response": {
                        "status": 302,
                        "headers": [{"name": "Location", "value": "https://www.target.example/done"}],
                        "content": {"mimeType": "text/html", "text": ""},
                    },
                },
            ]
        }
    })

    # 3. Mocked passive CT-log lookup
    ct_calls: list[str] = []

    def _mock_ct_fetcher(url: str, timeout_s: float = 8.0, max_bytes: int = 1024) -> bytes:
        ct_calls.append(url)
        assert "crt.sh" in url
        assert timeout_s > 0
        assert max_bytes <= 2 * 1024 * 1024
        payload = [
            {"name_value": "bff.target.example\nauth.target.example"},
            {"name_value": "admin.target.example"},
            {"name_value": "db.internal.target.example"},
            {"name_value": "evil.example"},
            {"name_value": "*.target.example"},
        ]
        return json.dumps(payload).encode("utf-8")

    ct_domains = fetch_ct_subdomains("target.example", fetcher=_mock_ct_fetcher)
    assert len(ct_calls) == 1
    assert ct_domains == [
        "admin.target.example",
        "auth.target.example",
        "bff.target.example",
        "db.internal.target.example",
        "evil.example",
    ]
    added_ct = graph.ingest_ct_domains(ct_domains)
    assert {n.host for n in added_ct} == {"auth.target.example", "bff.target.example"}

    # Verify wildcard acceptance & out_of_scope / external rejection
    bff = graph.get_node("https://bff.target.example")
    auth = graph.get_node("https://auth.target.example")
    storefront = graph.get_node("https://www.target.example")
    admin = graph.get_node("https://admin.target.example")
    evil = graph.get_node("https://evil.example")
    cdn = graph.get_node("https://cdn.other.example")

    assert bff is not None and bff.in_scope is True and bff.role == "api"
    assert auth is not None and auth.in_scope is True and auth.role == "auth"
    assert storefront is not None and storefront.in_scope is True and storefront.role == "storefront"
    assert admin is None or admin.in_scope is False
    assert evil is None or evil.in_scope is False
    assert cdn is not None and cdn.in_scope is False and cdn.role == "cdn"
    assert graph.get_node("https://db.internal.target.example") is None

    # Verify ranked_targets excludes out-of-scope and ranks api/auth ahead of storefront
    ranked_origins = [n.origin for n in graph.ranked_targets()]
    assert "https://admin.target.example" not in ranked_origins
    assert "https://evil.example" not in ranked_origins
    assert "https://cdn.other.example" not in ranked_origins
    assert ranked_origins.index("https://bff.target.example") < ranked_origins.index("https://www.target.example")
    assert ranked_origins.index("https://auth.target.example") < ranked_origins.index("https://www.target.example")

    # Verify edges
    edge_tuples = {(e.source, e.target, e.relation) for e in graph.edges.values()}
    assert ("https://www.target.example", "https://bff.target.example", "calls_api") in edge_tuples
    assert ("https://www.target.example", "https://auth.target.example", "authenticates_at") in edge_tuples
    assert ("https://www.target.example", "https://cdn.other.example", "loads_cdn_js") in edge_tuples
    assert ("https://evil.example", "https://www.target.example", "redirects_to") in edge_tuples

    # Verify no query secrets leaked into node paths or markdown
    serialized = json.dumps(graph.to_dict())
    md = graph.render_markdown()
    assert "dontLeak" not in serialized and "dontLeak" not in md
    assert "secretcode" not in serialized and "secretcode" not in md
    assert "hidden" not in serialized and "hidden" not in md

    # Verify lossless round-trip with to_dict / from_dict
    graph_dict = graph.to_dict()
    assert graph_dict["schema"] == SCHEMA
    restored = AssetGraph.from_dict(graph_dict)
    assert restored.to_dict() == graph_dict


def test_fetch_ct_subdomains_rejects_oversized_response_and_skips_loopback() -> None:
    assert fetch_ct_subdomains("127.0.0.1") == []
    assert fetch_ct_subdomains("localhost") == []

    with pytest.raises(ValueError):
        fetch_ct_subdomains(
            "target.example",
            max_bytes=1024,
            fetcher=lambda _url: b"[" + b"x" * 2048 + b"]",
        )


def test_ct_fetcher_not_called_when_passive_ct_is_false(tmp_path: Path) -> None:
    called: list[str] = []

    def _forbidden_ct(url: str) -> list[str]:
        called.append(url)
        return ["sub.target.example"]

    def _router(_m: str, _p: str, _h: dict[str, str]) -> tuple[int, str, str, dict[str, str]]:
        return 200, "application/json", '{"ok":true}', {}

    with _start_test_server(_router) as (origin, _port, _log):
        run_recon(
            target=origin,
            output_dir=tmp_path / "no-ct",
            passive_ct=False,
            execute=True,
            max_requests=2,
            max_rps=0.0,
            ct_fetcher=_forbidden_ct,
        )
    assert called == []


# ---------------------------------------------------------------------------
# 3. Live Multi-Server Loopback Probing (2 authorized + 1 unauthorized)
# ---------------------------------------------------------------------------


def test_live_multi_server_loopback_probing_classification_ranking_and_outputs(tmp_path: Path) -> None:
    def api_router(_m: str, path: str, _h: dict[str, str]) -> tuple[int, str, str, dict[str, str]]:
        if path == "/robots.txt":
            return 200, "text/plain", "User-agent: *\nDisallow: /internal/metrics\n", {}
        return (
            200,
            "application/json",
            json.dumps({"openapi": "3.0.0", "paths": {"/v1/orders": {}}}),
            {"Server": "uvicorn", "X-Powered-By": "FastAPI"},
        )

    def storefront_router(_m: str, path: str, _h: dict[str, str]) -> tuple[int, str, str, dict[str, str]]:
        if path == "/robots.txt":
            return 200, "text/plain", "User-agent: *\nDisallow: /checkout\n", {}
        return (
            200,
            "text/html; charset=utf-8",
            "<!doctype html><html><head><title>Storefront Home</title></head>"
            "<body><script>window.__NEXT_DATA__={}</script></body></html>",
            {"Server": "nginx", "CF-Ray": "89abcdef-IST"},
        )

    def unauth_router(_m: str, _path: str, _h: dict[str, str]) -> tuple[int, str, str, dict[str, str]]:
        return 200, "application/json", '{"secret":"should-never-be-probed"}', {}

    with _start_test_server(api_router) as (api_origin, _api_port, api_log):
        with _start_test_server(storefront_router) as (web_origin, _web_port, web_log):
            with _start_test_server(unauth_router) as (unauth_origin, _unauth_port, unauth_log):
                scope_file = _write_scope_file(
                    tmp_path,
                    {
                        "in_scope": [web_origin, api_origin],
                        "out_of_scope": [unauth_origin, "/logout"],
                        "excluded_paths": ["/account/*/close"],
                    },
                )
                seed_file = tmp_path / "seed.json"
                seed_file.write_text(
                    json.dumps({
                        "schema": "stage0-seed/1",
                        "url": web_origin,
                        "discovered_api_hosts": [
                            {"origin": api_origin, "sample_paths": ["/v1/orders"]},
                            {"origin": unauth_origin, "sample_paths": ["/admin/leak"]},
                        ],
                    }),
                    encoding="utf-8",
                )

                custom_hdr_val = "CyberbountyHeaderVal"
                out_dir = tmp_path / "live-recon"
                graph_path, live_doc = run_recon(
                    target=web_origin,
                    output_dir=out_dir,
                    scope_file=scope_file,
                    allow_non_loopback=True,
                    seed_files=[seed_file],
                    custom_headers=[f"Pentest: {custom_hdr_val}", "X-Scope-ID: Scope77"],
                    max_requests=6,
                    max_rps=0.0,
                    execute=True,
                )

                # Unauthorized server received ZERO requests
                assert unauth_log == []
                assert len(api_log) >= 1
                assert len(web_log) >= 1
                assert live_doc["requests_sent"] <= 6
                assert live_doc["requests_sent"] == len(api_log) + len(web_log)

                # Custom headers & User-Agent were sent on every request
                for req in [*api_log, *web_log]:
                    assert req["headers"]["pentest"] == custom_hdr_val
                    assert req["headers"]["x-scope-id"] == "Scope77"
                    assert "user-agent" in req["headers"]

                # Verify artifacts exist and contain ZERO custom header values
                assert graph_path == out_dir / "asset-graph.json"
                summary_path = out_dir / "recon-summary.md"
                scope_rec_path = out_dir / "scope.recommended.json"
                assert graph_path.is_file()
                assert summary_path.is_file()
                assert scope_rec_path.is_file()

                for artifact in (graph_path, summary_path, scope_rec_path):
                    content = artifact.read_text(encoding="utf-8")
                    assert custom_hdr_val not in content
                    assert "Scope77" not in content

                # Verify AssetGraph classification & ranking (api ahead of storefront)
                loaded = AssetGraph.from_dict(json.loads(graph_path.read_text(encoding="utf-8")))
                ranked = loaded.ranked_targets()
                assert [n.origin for n in ranked] == [api_origin, web_origin]
                api_node = loaded.get_node(api_origin)
                web_node = loaded.get_node(web_origin)
                assert api_node is not None and api_node.role == "api" and api_node.alive is True
                assert "openapi" in api_node.tech_signals
                assert web_node is not None and web_node.role == "storefront" and web_node.alive is True
                assert web_node.title == "Storefront Home"
                assert "nextjs" in web_node.tech_signals
                assert "cloudflare" in web_node.tech_signals

                # Verify scope.recommended.json is directly consumable by target_bootstrap
                rec_scope = json.loads(scope_rec_path.read_text(encoding="utf-8"))
                assert rec_scope["in_scope"] == [api_origin, web_origin]
                assert "/logout" in rec_scope["excluded_paths"]
                assert "/account/*/close" in rec_scope["excluded_paths"]
                resolved_origin, resolved_meta = tb.resolve_target_origin(
                    api_origin,
                    scope_file=scope_rec_path,
                    allow_non_loopback=True,
                )
                assert resolved_origin == f"{api_origin}/"
                assert set(resolved_meta["in_scope_assets"]) == {api_origin, web_origin}


def test_live_probing_respects_wire_budget_and_redirect_edges(tmp_path: Path) -> None:
    def target_router(_m: str, _p: str, _h: dict[str, str]) -> tuple[int, str, str, dict[str, str]]:
        return 403, "text/html", "<html><title>Attention Required! | Cloudflare</title></html>", {"CF-Mitigated": "challenge"}

    def unauth_router(_m: str, _p: str, _h: dict[str, str]) -> tuple[int, str, str, dict[str, str]]:
        return 200, "text/plain", "ok", {}

    with _start_test_server(unauth_router) as (unauth_origin, _uport, unauth_log):
        with _start_test_server(target_router) as (waf_origin, _wport, waf_log):
            def redir_router(_m: str, _p: str, _h: dict[str, str]) -> tuple[int, str, str, dict[str, str]]:
                return 302, "text/plain", "", {"Location": f"{waf_origin}/challenge"}

            with _start_test_server(redir_router) as (redir_origin, _rport, redir_log):
                scope_file = _write_scope_file(
                    tmp_path,
                    {"in_scope": [redir_origin, waf_origin], "out_of_scope": [unauth_origin]},
                )
                # Tight budget = 1 request: probes only redir_origin, detects redirect edge to waf_origin, stops at budget 1!
                out_tight = tmp_path / "tight"
                _, tight_doc = run_recon(
                    target=redir_origin,
                    output_dir=out_tight,
                    scope_file=scope_file,
                    allow_non_loopback=True,
                    max_requests=1,
                    max_rps=0.0,
                    execute=True,
                )
                assert tight_doc["requests_sent"] == 1
                assert len(redir_log) == 1
                assert len(waf_log) == 0
                assert unauth_log == []

                # Larger budget = 2: follows in-scope redirect node waf_origin and detects Cloudflare WAF
                out_full = tmp_path / "full"
                graph_path, full_doc = run_recon(
                    target=redir_origin,
                    output_dir=out_full,
                    scope_file=scope_file,
                    allow_non_loopback=True,
                    max_requests=2,
                    max_rps=0.0,
                    execute=True,
                )
                assert full_doc["requests_sent"] == 2
                loaded = AssetGraph.from_dict(json.loads(graph_path.read_text(encoding="utf-8")))
                waf_node = loaded.get_node(waf_origin)
                assert waf_node is not None and waf_node.waf_vendor == "cloudflare"
                assert (redir_origin, waf_origin, "redirects_to") in loaded.edges


# ---------------------------------------------------------------------------
# 4. CLI main(argv) in Plan Mode
# ---------------------------------------------------------------------------


def test_cli_main_plan_mode_prints_compact_json_and_zero_secrets(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scope_file = _write_scope_file(
        tmp_path,
        {
            "in_scope": ["https://www.target.example", "https://api.target.example"],
            "out_of_scope": ["admin.target.example"],
        },
    )
    out_dir = tmp_path / "cli-plan"
    header_val = "SecretHeaderVal99"
    rc = main([
        "--target", "https://www.target.example",
        "--scope-file", str(scope_file),
        "--allow-non-loopback",
        "--output-dir", str(out_dir),
        "-H", f"Pentest: {header_val}",
        "--max-requests", "15",
        "--max-rps", "1.5",
    ])
    assert rc == 0
    stdout = capsys.readouterr().out.strip()
    assert header_val not in stdout
    summary = json.loads(stdout)
    assert set(summary) == {
        "artifact",
        "mode",
        "target",
        "in_scope_hosts",
        "alive_hosts",
        "requests_sent",
        "recommended_targets",
        "asset_graph",
        "summary_md",
    }
    assert summary["artifact"] == str((out_dir / "recon-plan.json").resolve())
    assert summary["mode"] == "plan_only"
    assert summary["target"] == "https://www.target.example"
    assert summary["in_scope_hosts"] == 2
    assert summary["alive_hosts"] == 0
    assert summary["requests_sent"] == 0
    assert summary["asset_graph"] is None
    assert summary["summary_md"] is None
    assert [t["origin"] for t in summary["recommended_targets"]] == [
        "https://api.target.example",
        "https://www.target.example",
    ]
    assert isinstance(agentic_recon, object)


# ---------------------------------------------------------------------------
# 5. Additional Edge Cases: GraphQL/Auth/Dead Hosts, Tampering, Passive CT Live
# ---------------------------------------------------------------------------


def test_role_inference_graphql_auth_and_dead_host_excluded_from_recommended_scope(
    tmp_path: Path,
) -> None:
    def gql_router(_m: str, _p: str, _h: dict[str, str]) -> tuple[int, str, str, dict[str, str]]:
        return 200, "application/json", '{"data":{"__schema":{"types":[]}}}', {}

    def oidc_router(_m: str, _p: str, _h: dict[str, str]) -> tuple[int, str, str, dict[str, str]]:
        return 200, "application/json", '{"authorization_endpoint":"https://auth.example/oauth/authorize"}', {}

    # Find an unused closed loopback port so one host is guaranteed unreachable (alive=False)
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        dead_port = int(sock.getsockname()[1])
    dead_origin = f"http://127.0.0.1:{dead_port}"

    with _start_test_server(gql_router) as (gql_origin, _gp, _glog):
        with _start_test_server(oidc_router) as (oidc_origin, _op, _olog):
            scope_file = _write_scope_file(
                tmp_path,
                {"in_scope": [gql_origin, oidc_origin, dead_origin]},
            )
            out_dir = tmp_path / "roles-live"
            graph_path, live_doc = run_recon(
                target=oidc_origin,
                output_dir=out_dir,
                scope_file=scope_file,
                allow_non_loopback=True,
                max_requests=6,
                max_rps=0.0,
                timeout_s=1.0,
                execute=True,
            )
            assert set(live_doc["alive_hosts"]) == {gql_origin, oidc_origin}
            loaded = AssetGraph.from_dict(json.loads(graph_path.read_text(encoding="utf-8")))
            gql_node = loaded.get_node(gql_origin)
            oidc_node = loaded.get_node(oidc_origin)
            dead_node = loaded.get_node(dead_origin)

            assert gql_node is not None and gql_node.role == "graphql" and gql_node.alive is True
            assert oidc_node is not None and oidc_node.role == "auth" and oidc_node.alive is True
            assert dead_node is not None and dead_node.alive is False

            rec_scope = json.loads((out_dir / "scope.recommended.json").read_text(encoding="utf-8"))
            assert set(rec_scope["in_scope"]) == {gql_origin, oidc_origin}
            assert dead_origin not in rec_scope["in_scope"]


def test_from_dict_reenforces_scope_guard_and_rejects_bad_schema() -> None:
    with pytest.raises(ValueError):
        AssetGraph.from_dict({"schema": "wrong/1"})

    guard = tb.ScopeGuard("https://www.target.example", in_scope_assets=("*.target.example",), out_of_scope_assets=("admin.target.example",))
    tampered = {
        "schema": SCHEMA,
        "target": "https://www.target.example",
        "nodes": [
            {"origin": "https://www.target.example", "scheme": "https", "host": "www.target.example", "port": 443, "in_scope": True},
            {"origin": "https://admin.target.example", "scheme": "https", "host": "admin.target.example", "port": 443, "in_scope": True},
            {"origin": "https://evil.example", "scheme": "https", "host": "evil.example", "port": 443, "in_scope": True},
        ],
        "edges": [],
    }
    restored = AssetGraph.from_dict(tampered, guard=guard)
    assert [n.origin for n in restored.in_scope_nodes()] == ["https://www.target.example"]
    assert restored.get_node("https://admin.target.example") is not None
    assert restored.get_node("https://admin.target.example").in_scope is False  # type: ignore[union-attr]
    assert restored.get_node("https://evil.example").in_scope is False  # type: ignore[union-attr]


def test_live_passive_ct_ingests_in_scope_hosts_and_rejects_reserved_headers(tmp_path: Path) -> None:
    scope_file = _write_scope_file(
        tmp_path,
        {
            "in_scope": ["https://www.target.example", "*.target.example"],
            "out_of_scope": ["admin.target.example"],
        },
    )

    class _FakeResp:
        def __init__(self, status: int, body: str) -> None:
            self.status_code = status
            self.headers = {"Content-Type": "application/json", "Server": "envoy"}
            self.content = body.encode("utf-8")

        def close(self) -> None:
            return

    probed_urls: list[str] = []

    class _FakeSession:
        def __init__(self) -> None:
            self.cookies: dict[str, str] = {}

        def request(self, _method: str, url: str, **_kwargs: Any) -> _FakeResp:
            probed_urls.append(url)
            return _FakeResp(200, '{"ok":true}')

        def close(self) -> None:
            return

    ct_queried: list[str] = []

    def _fake_ct(url: str) -> list[str]:
        ct_queried.append(url)
        return ["bff.target.example", "admin.target.example", "evil.example"]

    out_dir = tmp_path / "ct-live"
    _path, doc = run_recon(
        target="https://www.target.example",
        output_dir=out_dir,
        scope_file=scope_file,
        allow_non_loopback=True,
        passive_ct=True,
        max_requests=2,
        max_rps=0.0,
        execute=True,
        ct_fetcher=_fake_ct,
        http_session_factory=_FakeSession,
    )
    assert len(ct_queried) == 1
    assert "q=%25.target.example" in ct_queried[0]
    assert set(probed_urls) == {"https://bff.target.example/", "https://www.target.example/"}
    assert "https://admin.target.example/" not in probed_urls
    assert "https://evil.example/" not in probed_urls
    assert doc["requests_sent"] == 2

    with pytest.raises(ValueError):
        run_recon(
            target="https://www.target.example",
            output_dir=tmp_path / "bad-hdr",
            scope_file=scope_file,
            allow_non_loopback=True,
            custom_headers=["Authorization: Bearer bad"],
            execute=False,
        )

