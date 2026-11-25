"""Tests for Faz B deterministic 0-LLM-token pre-scanner and multi-actor BOLA/BFLA pre-matrix."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any, Callable, Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import (  # noqa: E402
    ActorManager,
    AgenticHTTPClient,
    ServiceDegradationError,
)
from agentic_prescan import (  # noqa: E402
    CORS_PROBE_ORIGIN,
    REDIRECT_PROBE_HOST,
    format_prescan_handoff,
    run_deterministic_prescan,
    scan_offline_secret_leads,
)
from agentic_receipts import ReceiptStore  # noqa: E402


def _make_client(
    tmp_path: Path,
    *,
    base_url: str,
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST"),
    max_requests: int = 80,
    max_degradation_streak: int = 5,
) -> AgenticHTTPClient:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager(accounts or [])
    return AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
        max_degradation_streak=max_degradation_streak,
    )


@contextmanager
def _start_test_server(
    router: Callable[[str, str, dict[str, str], bytes], tuple[int, str, bytes | str, dict[str, str]]],
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
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

        def log_message(self, format: str, *args: Any) -> None:
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
        thread.join(timeout=2.0)


def _actor_from_headers(headers: dict[str, str]) -> str:
    auth = headers.get("authorization", "")
    if auth == "Bearer tok-alice":
        return "member-a"
    if auth == "Bearer tok-bob":
        return "member-b"
    if auth == "Bearer tok-admin":
        return "admin"
    return "anon"


def test_prescan_detects_all_five_check_classes_and_skips_safe_routes(tmp_path: Path) -> None:
    embedded_secret = "secret-xyz-123456"

    def router(method: str, raw_path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        parsed = urlsplit(raw_path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        actor = _actor_from_headers(headers)
        origin = headers.get("origin", "")

        if path == "/public.html":
            html_doc = (
                "<html><body><h1>Portal</h1>"
                f'<script>window.__CFG = {{M2M_PASSWORD:"{embedded_secret}"}};</script>'
                "</body></html>"
            )
            return 200, "text/html", html_doc, {}

        if path == "/api/cors-vuln":
            extra: dict[str, str] = {}
            if origin:
                extra["Access-Control-Allow-Origin"] = origin
                extra["Access-Control-Allow-Credentials"] = "true"
            return 200, "application/json", json.dumps({"ok": True, "cors": "enabled"}), extra

        if path == "/api/cors-safe":
            return 200, "application/json", json.dumps({"ok": True}), {
                "Access-Control-Allow-Origin": "https://trusted.example.com",
            }

        if path == "/login":
            nxt = (qs.get("next") or [""])[0]
            if nxt:
                return 302, "text/plain", "", {"Location": nxt}
            return 200, "text/html", "<form action='/login'><input name='next'></form>", {}

        if path == "/safe-redirect":
            nxt = (qs.get("next") or [""])[0]
            # Safe redirect that only places the URL inside an unredirected query param.
            return 302, "text/plain", "", {"Location": f"/dashboard?ignored={nxt[:24]}"}

        if path == "/graphql" and method == "POST":
            return 200, "application/json", json.dumps({
                "data": {"__schema": {"queryType": {"name": "Query"}}}
            }), {}

        if path == "/api/graphql-safe" and method == "POST":
            return 200, "application/json", json.dumps({
                "errors": [{"message": "Introspection is disabled for queryType"}]
            }), {}

        if path == "/api/orders/101":
            if actor == "anon":
                return 401, "application/json", json.dumps({"error": "unauthorized"}), {}
            return 200, "application/json", json.dumps({
                "order_id": 101,
                "owner": "member-a",
                "email": "alice@example.test",
                "total": 149.99,
                "items": ["widget"],
            }), {}

        if path == "/api/orders/102":
            if actor != "member-a":
                return 403, "application/json", json.dumps({"error": "forbidden"}), {}
            return 200, "application/json", json.dumps({
                "order_id": 102,
                "owner": "member-a",
                "email": "alice@example.test",
                "total": 29.0,
            }), {}

        if path == "/api/admin/stats":
            return 200, "application/json", json.dumps({
                "total_users": 42,
                "monthly_revenue": 9800,
                "active_tenants": 5,
            }), {}

        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_test_server(router) as (base_url, requests_log):
        client = _make_client(
            tmp_path,
            base_url=base_url,
            accounts=[
                {"alias": "member-a", "role": "member", "access_token": "tok-alice"},
                {"alias": "member-b", "role": "member", "access_token": "tok-bob"},
            ],
            max_requests=80,
        )
        # Pre-fetch public HTML page (simulating Stage 0 / initial discovery receipt).
        pre_rec = client.request(method="GET", url="/public.html", actor="anon")
        assert pre_rec["status"] == 200

        out_dir = tmp_path / "out"
        doc = run_deterministic_prescan(
            client,
            output_dir=out_dir,
            candidate_urls=[
                "/api/cors-vuln",
                "/api/cors-safe",
                "/login?next=/dashboard",
                "/safe-redirect?next=/home",
                "/graphql",
                "/api/graphql-safe",
                "/api/orders/101",
                "/api/orders/102",
                "/api/admin/stats",
                "/products/classic-cotton-tshirt-p-12345",  # catalog route must be skipped
            ],
            max_requests=24,
        )

    assert doc["schema"] == "agentic-prescan/1"
    assert doc["status"] == "ok"
    assert doc["stats"]["requests_sent"] <= 24
    assert all(not r["path"].startswith("/products/") for r in requests_log)

    leads = doc["leads"]
    kinds = {lead["kind"] for lead in leads}
    assert {"exposed_secret", "cors_misconfiguration", "open_redirect", "graphql_introspection", "bola_candidate", "bfla_candidate"} <= kinds

    # Priority sorting: high -> medium -> low
    rank = {"high": 0, "medium": 1, "low": 2}
    ranks = [rank[lead["severity_hint"]] for lead in leads]
    assert ranks == sorted(ranks)

    # Check 1: Offline secret lead & strict zero-leak hygiene
    sec_leads = [l for l in leads if l["kind"] == "exposed_secret"]
    assert len(sec_leads) == 1
    assert sec_leads[0]["key_name"] == "M2M_PASSWORD"
    assert sec_leads[0]["receipt_id"] == pre_rec["receipt_id"]
    assert sec_leads[0]["actor"] == "anon"
    assert f"len={len(embedded_secret)}" in sec_leads[0]["redacted_preview"]

    # Check 2: Vulnerable CORS detected, safe CORS skipped
    cors_leads = [l for l in leads if l["kind"] == "cors_misconfiguration"]
    assert len(cors_leads) == 1
    assert "/api/cors-vuln" in cors_leads[0]["url"]
    assert cors_leads[0]["acao"] == CORS_PROBE_ORIGIN
    assert cors_leads[0]["acac"] == "true"
    assert cors_leads[0]["severity_hint"] == "high"
    assert cors_leads[0]["receipt_id"].startswith("req-")

    # Check 3: Open redirect detected on /login, safe redirect skipped
    redir_leads = [l for l in leads if l["kind"] == "open_redirect"]
    assert len(redir_leads) == 1
    assert "/login" in redir_leads[0]["url"]
    assert redir_leads[0]["param"] == "next"
    assert redir_leads[0]["status"] == 302
    assert REDIRECT_PROBE_HOST in redir_leads[0]["location"]

    # Check 4: GraphQL introspection detected on /graphql, disabled error skipped
    gql_leads = [l for l in leads if l["kind"] == "graphql_introspection"]
    assert len(gql_leads) == 1
    assert "/graphql" in gql_leads[0]["url"]
    assert gql_leads[0]["method"] == "POST"

    # Check 5a: BOLA detected on /api/orders/101, safe /api/orders/102 skipped
    bola_leads = [l for l in leads if l["kind"] == "bola_candidate"]
    assert len(bola_leads) == 1
    assert "/api/orders/101" in bola_leads[0]["url"]
    assert bola_leads[0]["proof_receipt_id"].startswith("req-")
    assert bola_leads[0]["control_receipt_id"].startswith("req-")
    assert bola_leads[0]["proof_receipt_id"] != bola_leads[0]["control_receipt_id"]

    # Check 5b: BFLA/auth_bypass detected on /api/admin/stats
    bfla_leads = [l for l in leads if l["kind"] == "bfla_candidate"]
    assert len(bfla_leads) == 1
    assert "/api/admin/stats" in bfla_leads[0]["url"]
    assert bfla_leads[0]["actor"] == "anon"
    assert bfla_leads[0]["control_actor"] == "member-a"
    assert bfla_leads[0]["proof_receipt_id"] != bfla_leads[0]["control_receipt_id"]

    # Disk summary and LLM handoff formatter must NEVER leak raw secret
    summary_file = out_dir / "prescan-summary.json"
    assert summary_file.is_file()
    summary_raw = summary_file.read_text(encoding="utf-8")
    assert embedded_secret not in summary_raw
    assert embedded_secret not in json.dumps(doc)

    handoff = format_prescan_handoff(doc, max_chars=2400)
    assert handoff.startswith("[PRESCAN LEADS]")
    assert len(handoff) <= 2400
    assert embedded_secret not in handoff
    assert "M2M_PASSWORD" in handoff
    assert "/api/orders/101" in handoff
    assert "/api/admin/stats" in handoff


def test_offline_secret_triage_patterns_and_zero_http(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    aws_dummy = "AKIA" + "IOSFODNN7EXAMPLE"
    oauth_secret = "oauth-top-secret-998877"
    pk_header = "-----BEGIN RSA " + "PRIVATE KEY-----"

    r1 = store.record(
        actor="anon",
        method="GET",
        url="http://127.0.0.1:8080/bundle.js",
        path="/bundle.js",
        status=200,
        elapsed_ms=4.0,
        content_type="application/javascript",
        response_text=(
            f'const aws = "{aws_dummy}"; '
            f'const cfg = {{grant_type: "client_credentials", client_secret: "{oauth_secret}"}}; '
            f'const pem = "{pk_header}";'
        ),
    )
    # Non-anon receipt and redacted placeholder must be ignored.
    store.record(
        actor="member-a",
        method="GET",
        url="http://127.0.0.1:8080/api/me",
        path="/api/me",
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        response_text='{"client_secret": "should-not-alert-auth"}',
    )
    store.record(
        actor="anon",
        method="GET",
        url="http://127.0.0.1:8080/clean.js",
        path="/clean.js",
        status=200,
        elapsed_ms=2.0,
        content_type="application/javascript",
        response_text='const client_secret = "<REDACTED_SECRET>"; const api_key = "null";',
    )

    leads, scanned = scan_offline_secret_leads(store)
    assert scanned == 2
    kinds = {lead["kind"] for lead in leads}
    assert {"aws_access_key", "exposed_secret", "oauth_client_credentials", "private_key"} <= kinds
    assert all(lead["receipt_id"] == r1["receipt_id"] for lead in leads)

    serialized = json.dumps(leads)
    assert aws_dummy not in serialized
    assert oauth_secret not in serialized
    assert pk_header not in serialized
    assert all("len=" in lead["redacted_preview"] for lead in leads)


def test_prescan_respects_budget_cap_and_reserve(tmp_path: Path) -> None:
    def router(method: str, raw_path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        return 200, "application/json", json.dumps({"ok": True}), {
            "Access-Control-Allow-Origin": CORS_PROBE_ORIGIN,
        }

    with _start_test_server(router) as (base_url, _log):
        # Total budget > 20 (25) with 12 already consumed -> remaining=13 -> reserve 10 -> cap=3.
        client = _make_client(tmp_path, base_url=base_url, max_requests=25)
        for idx in range(12):
            client.request(method="GET", url=f"/seed/{idx}", actor="anon")
        assert client.budget.used == 12

        doc = run_deterministic_prescan(
            client,
            candidate_urls=[f"/api/ep-{i}" for i in range(10)],
            max_requests=24,
        )
        assert doc["stats"]["effective_request_cap"] == 3
        assert doc["stats"]["requests_sent"] <= 3
        assert (client.budget.limit - client.budget.used) >= 10


def test_prescan_propagates_service_degradation_error(tmp_path: Path) -> None:
    def router(method: str, raw_path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        return 503, "text/plain", "Service Unavailable", {}

    with _start_test_server(router) as (base_url, _log):
        client = _make_client(
            tmp_path,
            base_url=base_url,
            max_requests=40,
            max_degradation_streak=2,
        )
        with pytest.raises(ServiceDegradationError):
            run_deterministic_prescan(
                client,
                candidate_urls=["/api/a", "/api/b", "/api/c"],
                max_requests=10,
            )


def test_prescan_skips_waf_blocks_and_handles_seed_surface_and_handoff_bounds(tmp_path: Path) -> None:
    def router(method: str, raw_path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        parsed = urlsplit(raw_path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        actor = _actor_from_headers(headers)

        if path == "/api/waf-protected":
            return 403, "text/html", (
                "<html><title>Attention Required! | Cloudflare</title>"
                "<body>Sorry, you have been blocked</body></html>"
            ), {"Server": "cloudflare", "CF-Ray": "9999-IAD"}

        if path == "/auth/sso":
            ret = (qs.get("return_to") or [""])[0]
            if ret:
                return 302, "text/plain", "", {"Location": ret}
            return 200, "text/plain", "ok", {}

        if path == "/api/admin/audit":
            if actor == "anon":
                return 401, "application/json", json.dumps({"error": "unauthorized"}), {}
            return 200, "application/json", json.dumps({"audit_events": [{"id": 1, "action": "login"}]}), {}

        if path == "/api/orders/201":
            if actor == "anon":
                return 401, "application/json", json.dumps({"error": "unauthorized"}), {}
            # Properly scoped per-actor response: must NOT trigger BOLA false positive.
            return 200, "application/json", json.dumps({
                "order_id": 201 if actor == "member-a" else 202,
                "owner": actor,
                "email": f"{actor}@example.test",
                "total": 10.0,
            }), {}

        return 404, "application/json", json.dumps({"error": "not found"}), {}

    with _start_test_server(router) as (base_url, _log):
        client = _make_client(
            tmp_path,
            base_url=base_url,
            accounts=[
                {"alias": "member-a", "role": "member", "access_token": "tok-alice"},
                {"alias": "member-b", "role": "member", "access_token": "tok-bob"},
                {"alias": "admin", "role": "admin", "access_token": "tok-admin"},
            ],
            max_requests=80,
        )
        seed = {
            "links": [
                {"method": "GET", "url": "/api/waf-protected", "params": []},
                {"method": "GET", "url": "/auth/sso", "params": ["return_to"]},
                {"method": "GET", "url": "/api/admin/audit", "params": []},
                {"method": "GET", "url": "/api/orders/201", "params": []},
            ],
            "forms": [],
        }
        doc = run_deterministic_prescan(client, seed_surface=seed, max_requests=24)

    assert "cloudflare" in doc["waf_vendors_seen"]
    assert doc["stats"]["waf_blocks_skipped"] >= 1
    kinds = [lead["kind"] for lead in doc["leads"]]
    assert "open_redirect" in kinds
    assert "bfla_candidate" in kinds
    assert "bola_candidate" not in kinds

    bfla = next(l for l in doc["leads"] if l["kind"] == "bfla_candidate")
    assert bfla["suggested_class"] == "bfla"
    assert bfla["actor"] == "member-a"
    assert bfla["control_actor"] == "anon"

    short_handoff = format_prescan_handoff(doc, max_chars=220)
    assert len(short_handoff) <= 220
    assert format_prescan_handoff(doc, max_chars=0) == ""
    assert format_prescan_handoff({"leads": [], "waf_vendors_seen": []}) == ""


def test_cors_severity_variants_and_budget_exhausted_graceful_stop(tmp_path: Path) -> None:
    def router(method: str, raw_path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        origin = headers.get("origin", "")
        if path == "/api/cors-reflect-nocreds":
            return 200, "application/json", json.dumps({"ok": True}), (
                {"Access-Control-Allow-Origin": origin} if origin else {}
            )
        if path == "/api/cors-wildcard-creds":
            return 200, "application/json", json.dumps({"ok": True}), {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        if path == "/api/cors-public-wildcard":
            return 200, "application/json", json.dumps({"ok": True}), {
                "Access-Control-Allow-Origin": "*",
            }
        return 200, "application/json", json.dumps({"ok": True}), {}

    with _start_test_server(router) as (base_url, _log):
        client = _make_client(tmp_path, base_url=base_url, max_requests=40)
        doc = run_deterministic_prescan(
            client,
            candidate_urls=[
                "/api/cors-reflect-nocreds",
                "/api/cors-wildcard-creds",
                "/api/cors-public-wildcard",
            ],
            max_requests=10,
        )
        cors_leads = [l for l in doc["leads"] if l["kind"] == "cors_misconfiguration"]
        assert len(cors_leads) == 2
        assert {l["severity_hint"] for l in cors_leads} == {"medium"}
        assert all("/api/cors-public-wildcard" not in l["url"] for l in cors_leads)

        # Tiny budget client (<=20) stops cleanly without raising BudgetExhaustedError.
        tiny_client = _make_client(tmp_path / "tiny", base_url=base_url, max_requests=2)
        tiny_doc = run_deterministic_prescan(
            tiny_client,
            candidate_urls=[
                "/api/cors-reflect-nocreds",
                "/api/cors-wildcard-creds",
                "/api/cors-public-wildcard",
                "/api/extra",
            ],
            max_requests=10,
        )
        assert tiny_doc["stats"]["requests_sent"] <= 2
        assert tiny_client.budget.used <= 2

