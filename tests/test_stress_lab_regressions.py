"""Regression tests covering real bugs uncovered by the Docker+Chromium stress lab."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import agent_cli  # noqa: E402
import agentic_http  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient, _stdlib_zstd  # noqa: E402
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_prescan import run_deterministic_prescan, scan_offline_secret_leads  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_seed import _extract_postman_variables, load_seed_surface_files  # noqa: E402
from agentic_stage0_crawl import _Stage0Budget, _Stage0Collector, _run_layer4_passive_fusion  # noqa: E402
from agentic_waf import detect_waf_block  # noqa: E402
from target_bootstrap import ScopeGuard  # noqa: E402


@contextmanager
def _start_raw_server(
    handler_fn: Callable[[str, str, dict[str, str], bytes], tuple[int, list[tuple[str, str]], bytes]],
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    observed: list[dict[str, Any]] = []
    lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            hdrs = {str(k).lower(): str(v) for k, v in self.headers.items()}
            with lock:
                observed.append({"method": self.command, "path": self.path, "headers": hdrs, "body": body})
            status, resp_hdrs, resp_body = handler_fn(self.command, self.path, hdrs, body)
            self.send_response(status)
            has_len = any(k.lower() == "content-length" for k, _ in resp_hdrs)
            for k, v in resp_hdrs:
                self.send_header(k, v)
            if not has_len:
                self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(resp_body)

        def do_GET(self) -> None:  # noqa: N802
            self._handle()

        def do_POST(self) -> None:  # noqa: N802
            self._handle()

        def do_HEAD(self) -> None:  # noqa: N802
            self._handle()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(srv.server_address[1])
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}", observed
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 1. Oracle clean-session replay: lowercase zstd + location headers
# ---------------------------------------------------------------------------


def test_oracle_clean_session_request_handles_lowercase_zstd_and_location(tmp_path: Path) -> None:
    payload_bytes = json.dumps({"order": {"id": 101, "secret": "ALICE_ORDER_101"}}).encode("utf-8")
    if _stdlib_zstd is not None:
        enc_name = "zstd"
        compressed_bytes = _stdlib_zstd.compress(payload_bytes)
    else:
        enc_name = "gzip"
        compressed_bytes = gzip.compress(payload_bytes)

    def router(method: str, path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        if path.startswith("/api/orders/101"):
            return (
                200,
                [
                    ("content-type", "application/json; charset=utf-8"),
                    ("content-encoding", enc_name),
                ],
                compressed_bytes,
            )
        if path.startswith("/auth/continue"):
            return (
                302,
                [
                    ("location", "https://redirect-check.example.invalid/x"),
                    ("content-type", "text/plain"),
                ],
                b"",
            )
        return 404, [("content-type", "application/json")], b'{"error":"not found"}'

    with _start_raw_server(router) as (base_url, _log):
        store = ReceiptStore(tmp_path / "receipts")
        http_client = AgenticHTTPClient(base_url=base_url, receipt_store=store, actors=ActorManager([]), max_requests=20)
        oracle = DifferentialOracle(http_client=http_client, receipt_store=store)
        try:
            rec_api = oracle._run_clean_session_request(actor="anon", method="GET", url="/api/orders/101")
            assert rec_api["status"] == 200
            assert rec_api["content_type"] == "application/json"
            assert "ALICE_ORDER_101" in rec_api["body"]

            rec_redir = oracle._run_clean_session_request(actor="anon", method="GET", url="/auth/continue?next=x")
            assert rec_redir["status"] == 302
            assert rec_redir["redirect_location"] == "https://redirect-check.example.invalid/x"
        finally:
            http_client.close()


# ---------------------------------------------------------------------------
# 2. Behavioral WAF block detection for stock Nginx ModSecurity CRS 403
# ---------------------------------------------------------------------------


def test_waf_behavioral_detects_nginx_modsecurity_attack_block_without_fps() -> None:
    nginx_403_html = (
        "<html>\r\n<head><title>403 Forbidden</title></head>\r\n"
        "<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n"
        "<hr><center>nginx/1.30.7</center>\r\n</body>\r\n</html>\r\n"
    )
    xss_block = {
        "status": 403,
        "url": "http://127.0.0.1:8080/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "content_type": "text/html",
        "response_headers": {"server": "nginx/1.30.7", "content-type": "text/html"},
        "body": nginx_403_html,
    }
    sqli_block = {
        "status": 403,
        "url": "http://127.0.0.1:8080/search?q=%27+OR+1%3D1--",
        "content_type": "text/html",
        "response_headers": {"server": "nginx/1.30.7", "content-type": "text/html"},
        "body": nginx_403_html,
    }
    res_xss = detect_waf_block(xss_block)
    res_sqli = detect_waf_block(sqli_block)
    assert res_xss is not None and res_xss["waf_blocked"] is True and res_xss["classification"] == "waf_block"
    assert res_sqli is not None and res_sqli["waf_blocked"] is True

    # Benign HTML 403 without attack probe AND JSON 403 with attack probe must NOT false-positive
    benign_403 = {
        "status": 403,
        "url": "http://127.0.0.1:8080/admin/panel",
        "content_type": "text/html",
        "response_headers": {"server": "nginx/1.30.7", "content-type": "text/html"},
        "body": nginx_403_html,
    }
    json_403 = {
        "status": 403,
        "url": "http://127.0.0.1:8080/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "content_type": "application/json",
        "response_headers": {"server": "nginx/1.30.7", "content-type": "application/json"},
        "body": '{"error":"forbidden"}',
    }
    assert detect_waf_block(benign_403) is None
    assert detect_waf_block(json_403) is None


# ---------------------------------------------------------------------------
# 3. Concurrent single-use 401 refresh lock + GraphQL 200 refresh + resume state
# ---------------------------------------------------------------------------


def test_http_concurrent_401_single_use_refresh_and_graphql_200_refresh_and_session_roundtrip(
    tmp_path: Path,
) -> None:
    state_lock = threading.Lock()
    state: dict[str, Any] = {
        "valid_access": "jwt_active_initial_server_secret",
        "valid_refresh": "rt_v1",
        "refresh_calls": 0,
        "revoked_refresh_hits": 0,
    }

    def router(method: str, path: str, hdrs: dict[str, str], body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        if path == "/oauth/refresh" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}")
            rt = str(payload.get("refresh_token") or "")
            with state_lock:
                state["refresh_calls"] += 1
                if rt != state["valid_refresh"]:
                    state["revoked_refresh_hits"] += 1
                    return 401, [("content-type", "application/json")], b'{"error":"refresh_token_revoked"}'
                # Slight delay forces peer threads to contend on concurrent 401 refresh!
                time.sleep(0.08)
                state["valid_access"] = f"jwt_fresh_{state['refresh_calls']}"
                next_rt = f"rt_v{state['refresh_calls'] + 1}"
                state["valid_refresh"] = next_rt
                return (
                    200,
                    [("content-type", "application/json")],
                    json.dumps({"access_token": state["valid_access"], "refresh_token": next_rt}).encode("utf-8"),
                )

        auth = hdrs.get("authorization", "")
        with state_lock:
            is_fresh = auth == f"Bearer {state['valid_access']}"

        if path == "/api/orders":
            if not is_fresh:
                return 401, [("content-type", "application/json")], b'{"error":"token_expired"}'
            return 200, [("content-type", "application/json")], b'{"ok":true}'

        if path == "/graphql" and method == "POST":
            req_json = json.loads(body.decode("utf-8") or "{}")
            if isinstance(req_json, list):
                if not is_fresh:
                    err = {"errors": [{"message": "Unauthorized", "extensions": {"code": "UNAUTHENTICATED"}}], "data": None}
                    return 200, [("content-type", "application/json")], json.dumps([err, err]).encode("utf-8")
                return 200, [("content-type", "application/json")], json.dumps([{"data": {"ok": 1}}, {"data": {"ok": 2}}]).encode("utf-8")
            if "forbiddenOp" in str(req_json.get("query") or ""):
                err = {"errors": [{"message": "Admin required", "extensions": {"code": "FORBIDDEN"}}], "data": None}
                return 200, [("content-type", "application/json")], json.dumps(err).encode("utf-8")
            if not is_fresh:
                err = {"errors": [{"message": "Unauthorized", "extensions": {"code": "UNAUTHENTICATED"}}], "data": None}
                return 200, [("content-type", "application/json")], json.dumps(err).encode("utf-8")
            return 200, [("content-type", "application/json")], b'{"data":{"ok":1}}'

        return 404, [("content-type", "application/json")], b"{}"

    with _start_raw_server(router) as (base_url, _log):
        store = ReceiptStore(tmp_path / "receipts")
        actors = ActorManager(
            [
                {
                    "alias": "alice",
                    "access_token": "jwt_v1_expired",
                    "refresh_token": "rt_v1",
                    "authenticated": True,
                }
            ],
            refresh_path="/oauth/refresh",
        )
        client = AgenticHTTPClient(base_url=base_url, receipt_store=store, actors=actors, allowed_methods=("GET", "POST"), max_requests=40)
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                f1 = pool.submit(client.request, method="GET", url="/api/orders", actor="alice", force=True)
                f2 = pool.submit(client.request, method="GET", url="/api/orders", actor="alice", force=True)
                r1, r2 = f1.result(), f2.result()
            assert r1["status"] == 200
            assert r2["status"] == 200
            assert state["refresh_calls"] == 1
            assert state["revoked_refresh_hits"] == 0

            # Export private session snapshot and simulate --resume into a fresh ActorManager with stale v1 creds!
            exported = actors.export_private_sessions()
            assert exported["alice"]["refresh_token"] == "rt_v2"

            actors_resumed = ActorManager(
                [{"alias": "alice", "access_token": "jwt_v1_expired", "refresh_token": "rt_v1", "authenticated": True}],
                refresh_path="/oauth/refresh",
            )
            actors_resumed.import_private_sessions(exported)
            client2 = AgenticHTTPClient(base_url=base_url, receipt_store=ReceiptStore(tmp_path / "r2"), actors=actors_resumed, allowed_methods=("GET", "POST"), max_requests=30)
            try:
                # Force single-use token expiration so batched GraphQL HTTP 200 UNAUTHENTICATED triggers refresh via rt_v2!
                with state_lock:
                    state["valid_access"] = "jwt_v3_post_resume"
                # Override router dynamically by checking rt_v2 in actors_resumed
                with actors_resumed.get("alice")._lock:
                    assert actors_resumed.get("alice").refresh_token == "rt_v2"

                # Single GraphQL 200 UNAUTHENTICATED does NOT refresh on FORBIDDEN
                g_forb = client2.request(method="POST", url="/graphql", actor="alice", json_body={"query": "{ forbiddenOp }"}, force=True)
                assert g_forb["status"] == 200
                assert state["refresh_calls"] == 1

                # Batched GraphQL 200 UNAUTHENTICATED DOES refresh once using rt_v2 -> gets valid_access!
                g_batch = client2.request(
                    method="POST",
                    url="/graphql",
                    actor="alice",
                    json_body=[{"query": "{ a }"}, {"query": "{ b }"}],
                    force=True,
                )
                assert g_batch["status"] == 200
                assert json.loads(g_batch["body"]) == [{"data": {"ok": 1}}, {"data": {"ok": 2}}]
                assert state["refresh_calls"] == 2
                assert state["revoked_refresh_hits"] == 0
            finally:
                client2.close()
        finally:
            client.close()


# ---------------------------------------------------------------------------
# 4. Prescan: .js.map non-anon secret scan, CORS auth/null, GraphQL auth retry, BFLA without admin
# ---------------------------------------------------------------------------


def test_prescan_sourcemap_secret_auth_null_cors_graphql_retry_and_member_bfla(tmp_path: Path) -> None:
    def router(method: str, path: str, hdrs: dict[str, str], body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        auth = hdrs.get("authorization", "")
        origin = hdrs.get("origin", "")
        parsed = urlsplit(path)
        clean_path = parsed.path

        if clean_path == "/api/v2/account/export-key":
            if auth != "Bearer tok-alice":
                return 401, [("content-type", "application/json")], b'{"error":"unauthenticated"}'
            extra_hdrs = [("content-type", "application/json")]
            if origin == "null":
                extra_hdrs.extend([("access-control-allow-origin", "null"), ("access-control-allow-credentials", "true")])
            return 200, extra_hdrs, b'{"api_key":"dummy_non_credential_demo"}'

        if clean_path == "/api/v2/internal-metrics":
            if auth != "Bearer tok-alice":
                return 401, [("content-type", "application/json")], b'{"error":"unauthenticated"}'
            return 200, [("content-type", "application/json")], b'{"internal_ops_flag":"METRICS_SECRET"}'

        if clean_path == "/graphql" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}")
            if isinstance(payload, dict) and "__schema" in str(payload.get("query") or ""):
                schema = {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": None,
                            "types": [
                                {
                                    "kind": "OBJECT",
                                    "name": "Query",
                                    "fields": [
                                        {
                                            "name": "adminLogs",
                                            "args": [],
                                            "type": {"kind": "OBJECT", "name": "LogRow", "ofType": None},
                                        }
                                    ],
                                },
                                {
                                    "kind": "OBJECT",
                                    "name": "LogRow",
                                    "fields": [
                                        {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                                        {"name": "secret", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                                    ],
                                },
                            ],
                        }
                    }
                }
                return 200, [("content-type", "application/json")], json.dumps(schema).encode("utf-8")
            if auth != "Bearer tok-alice":
                err = {"errors": [{"message": "Unauthorized", "extensions": {"code": "UNAUTHENTICATED"}}], "data": None}
                body_out = [err, err] if isinstance(payload, list) else err
                return 200, [("content-type", "application/json")], json.dumps(body_out).encode("utf-8")
            if isinstance(payload, list):
                return 200, [("content-type", "application/json")], json.dumps([{"data": {"adminLogs": [{"id": "1"}]}}]).encode("utf-8")
            return 200, [("content-type", "application/json")], json.dumps({"data": {"adminLogs": [{"id": "1", "secret": "x"}]}}).encode("utf-8")

        return 404, [("content-type", "application/json")], b"{}"

    with _start_raw_server(router) as (base_url, _log):
        store = ReceiptStore(tmp_path / "receipts")
        dummy_aws = "AKIA" + "STRESSUNITTEST7K"
        store.record(
            actor="alice",
            method="GET",
            url=f"{base_url}/bundles/app.main.js.map",
            path="/bundles/app.main.js.map",
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            response_text=json.dumps({"version": 3, "sourcesContent": [f"export const AWS_KEY = '{dummy_aws}';"]}),
        )
        # Non-script member API receipt still ignored by default scan_offline_secret_leads contract
        store.record(
            actor="alice",
            method="GET",
            url=f"{base_url}/api/me",
            path="/api/me",
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            response_text='{"client_secret":"ignored-api-secret"}',
        )
        leads_offline, scanned_cnt = scan_offline_secret_leads(store)
        assert scanned_cnt == 1
        assert any(ld["kind"] == "aws_access_key" for ld in leads_offline)
        assert dummy_aws not in json.dumps(leads_offline)

        actors = ActorManager([{"alias": "alice", "role": "member", "access_token": "tok-alice", "authenticated": True}])
        client = AgenticHTTPClient(base_url=base_url, receipt_store=store, actors=actors, allowed_methods=("GET", "POST"), max_requests=60)
        try:
            doc = run_deterministic_prescan(
                client,
                candidate_urls=[
                    f"{base_url}/api/v2/account/export-key",
                    f"{base_url}/api/v2/internal-metrics",
                    f"{base_url}/graphql",
                ],
                max_requests=25,
            )
            kinds = {ld["kind"] for ld in doc["leads"]}
            assert "aws_access_key" in kinds
            assert "cors_misconfiguration" in kinds
            assert "bfla_candidate" in kinds
            assert "graphql_admin_query_exposed" in kinds
            cors_lead = next(ld for ld in doc["leads"] if ld["kind"] == "cors_misconfiguration")
            assert cors_lead["probe_origin"] == "null"
            assert cors_lead["severity_hint"] == "high"
        finally:
            client.close()


# ---------------------------------------------------------------------------
# 5. Postman authBase preservation & loopback multi-origin `cco-agent map`
# ---------------------------------------------------------------------------


def test_seed_keeps_safe_auth_base_variable_and_loopback_map_keeps_sibling_origins(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    vars_map = _extract_postman_variables([
        {"key": "authBase", "value": "http://127.0.0.1:41001"},
        {"key": "authToken", "value": "should-never-keep-secret"},
        {"key": "apiKey", "value": "sk_live_secret_value_12345"},
    ])
    assert vars_map == {"authBase": "http://127.0.0.1:41001"}

    scope_path = tmp_path / "scope.json"
    scope_path.write_text(
        json.dumps({
            "allow_loopback": True,
            "in_scope": ["http://127.0.0.1:41000", "http://127.0.0.1:41001"],
            "out_of_scope": ["https://evil.example"],
            "excluded_paths": ["/logout"],
        }),
        encoding="utf-8",
    )
    postman_path = tmp_path / "postman.json"
    postman_path.write_text(
        json.dumps({
            "info": {"name": "Loopback Multi", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "variable": [
                {"key": "authBase", "value": "http://127.0.0.1:41001"},
                {"key": "apiBase", "value": "http://127.0.0.1:41001"},
            ],
            "item": [
                {
                    "name": "StorefrontSearch",
                    "request": {"method": "GET", "url": "http://127.0.0.1:41000/search?q=shoes"},
                },
                {
                    "name": "Continue",
                    "request": {"method": "GET", "url": "{{authBase}}/auth/continue?next=/profile"},
                },
                {
                    "name": "RemoteBlocked",
                    "request": {"method": "GET", "url": "https://evil.example/steal"},
                },
            ],
        }),
        encoding="utf-8",
    )

    seed = load_seed_surface_files(
        [postman_path],
        base_url="http://127.0.0.1:41000",
        in_scope_assets=["http://127.0.0.1:41000", "http://127.0.0.1:41001"],
    )
    assert any(l["url"] == "http://127.0.0.1:41001/auth/continue" for l in seed["links"])

    out_dir = tmp_path / "offline-map"
    rc = agent_cli.main([
        "map",
        "--target", "http://127.0.0.1:41000/",
        "--scope-file", str(scope_path),
        "--seed-surface", str(postman_path),
        "--output-dir", str(out_dir),
    ])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["network_requests"] == 0
    assert summary["stats"]["origins_count"] == 2
    assert summary["stats"]["dropped_out_of_scope"] >= 1
    smap = json.loads((out_dir / "surface-map.json").read_text(encoding="utf-8"))
    origins_seen = {o["origin"] for o in smap["origins"]}
    assert origins_seen == {"http://127.0.0.1:41000", "http://127.0.0.1:41001"}
    assert ScopeGuard("http://127.0.0.1:41000", in_scope_assets=("http://127.0.0.1:41000", "http://127.0.0.1:41001")).loopback_only is True


# ---------------------------------------------------------------------------
# 6. Stage 0 prioritizes _buildManifest.js before blind spec wordlist probes
# ---------------------------------------------------------------------------


def test_stage0_fetches_next_build_manifest_even_when_spa_catchall_uses_spec_probes(tmp_path: Path) -> None:
    def router(_method: str, path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        if path == "/_next/static/build42/_buildManifest.js":
            js = (
                "self.__BUILD_MANIFEST = {\n"
                "  '/admin/audit-view': ['static/chunks/admin-audit.js'],\n"
                "  sortedPages: ['/', '/admin/audit-view']\n"
                "};\n"
            )
            return 200, [("content-type", "application/javascript")], js.encode("utf-8")
        return 200, [("content-type", "text/html")], b"<!doctype html><html><body>SPA</body></html>"

    with _start_raw_server(router) as (base_url, _log):
        client = AgenticHTTPClient(base_url=base_url, receipt_store=ReceiptStore(tmp_path / "receipts"), actors=ActorManager([]), max_requests=25)
        try:
            collector = _Stage0Collector(client)
            collector.captured_html["/"] = {
                "url": f"{base_url}/",
                "headers": {"content-type": "text/html"},
                "body": '<html><script id="__NEXT_DATA__" type="application/json">{"buildId":"build42","page":"/"}</script></html>',
            }
            collector.record_observed_app_headers({"X-Storefront": "tr-web", "Authorization": "Bearer secret"}, blocked_names=set())
            assert collector.observed_app_headers == {"X-Storefront": "tr-web"}

            budget = _Stage0Budget(client, cap=8, reserve=0)
            _run_layer4_passive_fusion(client, collector, budget, primary_actor="anon", max_passive_probes=4)
            assert any(rec.path == "/admin/audit-view" for rec in collector.routes.values())
            assert "/_next/static/build42/_buildManifest.js" in collector.probed_paths
        finally:
            client.close()
