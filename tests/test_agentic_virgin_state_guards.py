"""Tests for virgin-state-sensitive path guards, Stage 1 guard, Stage 0 form skip, and HTTP reserve floor."""
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

from agentic_http import ActorManager, AgenticHTTPClient, BudgetExhaustedError  # noqa: E402
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_stage0_crawl import (  # noqa: E402
    HAS_PLAYWRIGHT,
    run_stage0_crawl,
    should_skip_stage0_form_submit,
)
from agentic_surface import is_virgin_state_sensitive_path  # noqa: E402
from agentic_tools import ToolDispatcher  # noqa: E402


def _unwrap_tool_payload(raw: str) -> dict[str, Any]:
    prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw.startswith(prefix)
    assert raw.rstrip().endswith(suffix.strip())
    body = raw[len(prefix) :].rsplit(suffix, 1)[0]
    return json.loads(body)


@contextmanager
def _start_test_server(
    handler_fn: Callable[[str, str, dict[str, str], bytes], tuple[int, str, bytes | str, dict[str, str]]],
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    requests_log: list[dict[str, Any]] = []
    lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            with lock:
                requests_log.append({
                    "method": self.command,
                    "path": self.path,
                    "headers": hdrs,
                    "body": body,
                })
            status, ctype, payload, extra_hdrs = handler_fn(self.command, self.path, hdrs, body)
            raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            for hk, hv in (extra_hdrs or {}).items():
                self.send_header(hk, hv)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

        def do_GET(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def do_PUT(self) -> None:
            self._handle()

        def do_PATCH(self) -> None:
            self._handle()

        def do_DELETE(self) -> None:
            self._handle()

        def do_HEAD(self) -> None:
            self._handle()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", requests_log
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


def _make_dispatcher(
    tmp_path: Path,
    base_url: str,
    *,
    max_requests: int = 40,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
    bootstrap_stage1_virgin_guard: bool = False,
    http_reserve_floor: int = 0,
    with_oracle: bool = False,
) -> tuple[ReceiptStore, AgenticHTTPClient, ToolDispatcher]:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-alice"},
        {"alias": "bob", "role": "member", "tenant": "t2", "auth_header": "Bearer tok-bob"},
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
    )
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential") if with_oracle else None
    dispatcher = ToolDispatcher(
        http_client=client,
        receipt_store=store,
        root_dir=tmp_path,
        oracle=oracle,
        bootstrap_stage1_virgin_guard=bootstrap_stage1_virgin_guard,
        http_reserve_floor=http_reserve_floor,
    )
    return store, client, dispatcher


@pytest.mark.parametrize(
    "path_or_url",
    [
        "/api/promos/claim",
        "/api/promo/redeem",
        "/api/v1/coupons/SAVE20/redeem",
        "/api/coupon/apply",
        "https://app.example.test/api/vouchers/claim?code=VIP",
        "/api/voucher",
        "/api/bonus",
        "/api/rewards/claim",
        "/api/reward",
        "/api/polls/42/vote",
        "/api/checkin",
        "/api/check-in",
        "/api/wallet/withdraw",
        "/API/PROMOS/CLAIM/",
    ],
)
def test_is_virgin_state_sensitive_path_positives(path_or_url: str) -> None:
    assert is_virgin_state_sensitive_path(path_or_url) is True


@pytest.mark.parametrize(
    "path_or_url",
    [
        "",
        "/",
        "/api/orders",
        "/api/notes",
        "/api/users",
        "/api/webhooks/test",
        "/api/ledger",
        "/api/diagnostics",
        "/api/items",
        "/api/invoices",
        "/api/tickets",
        "/api/auth/login",
        "/api/auth/signup",
        "/api/auth/register",
        "/api/auth/logout",
        "/api/auth/session",
        "/api/health",
        "/api/promos/health",
        "/api/auth/claim",
        "/static/promo.js",
        "/assets/claim.css",
        "/assets/bonus.png",
        "/icons/reward.svg",
        "/assets/voucher.js.map",
        "/api/upvote",
    ],
)
def test_is_virgin_state_sensitive_path_negatives(path_or_url: str) -> None:
    assert is_virgin_state_sensitive_path(path_or_url) is False


def test_stage1_virgin_guard_blocks_sequential_writes_and_allows_safe_or_concurrent(tmp_path: Path) -> None:
    state = {"promo_claims": 0, "orders": 0, "logins": 0}
    lock = threading.Lock()

    def router(method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/api/promos/claim":
            if method == "GET":
                return 200, "application/json", json.dumps({"available": True}), {}
            with lock:
                state["promo_claims"] += 1
                n = state["promo_claims"]
            return 200, "application/json", json.dumps({"claimed": n}), {}
        if path == "/api/auth/login" and method == "POST":
            with lock:
                state["logins"] += 1
            return 200, "application/json", json.dumps({"access_token": "tok-dyn-123"}), {}
        if path == "/api/v1/orders" and method == "POST":
            with lock:
                state["orders"] += 1
            return 201, "application/json", json.dumps({"order_id": 101}), {}
        return 404, "application/json", json.dumps({"error": "not_found"}), {}

    with _start_test_server(router) as (base_url, log):
        _store, client, dispatcher = _make_dispatcher(
            tmp_path / "guarded",
            base_url,
            max_requests=30,
            bootstrap_stage1_virgin_guard=True,
        )
        try:
            # Sequential POST to /api/promos/claim is blocked at 0 HTTP cost.
            blocked_raw = dispatcher.dispatch("http_request", {
                "method": "POST",
                "url": "/api/promos/claim",
                "actor": "alice",
                "json_body": {"code": "WELCOME50"},
            })
            blocked = _unwrap_tool_payload(blocked_raw)
            assert blocked["blocked"] is True
            assert blocked["reason"] == "virgin_state_preserved_for_concurrency_or_shard"
            assert blocked["method"] == "POST"
            assert blocked["url"] == "/api/promos/claim"
            assert "concurrent_check" in blocked["guidance"]
            assert client.budget.used == 0
            assert state["promo_claims"] == 0

            # Payload-inferred POST (omitting method) is also blocked at 0 HTTP cost.
            inferred_blocked = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
                "url": "/api/promos/claim",
                "actor": "alice",
                "json_body": {"code": "WELCOME50"},
            }))
            assert inferred_blocked["blocked"] is True
            assert inferred_blocked["method"] == "POST"
            assert client.budget.used == 0

            # GET on /api/promos/claim is allowed.
            get_ok = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
                "method": "GET",
                "url": "/api/promos/claim",
                "actor": "alice",
            }))
            assert get_ok["status"] == 200
            assert client.budget.used == 1

            # POST /api/auth/login with save_session_as is allowed.
            login_ok = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
                "method": "POST",
                "url": "/api/auth/login",
                "actor": "anon",
                "json_body": {"username": "newuser"},
                "save_session_as": "dyn-user",
            }))
            assert login_ok["status"] == 200
            assert state["logins"] == 1
            assert client.budget.used == 2

            # Normal CRUD write POST /api/v1/orders is allowed.
            order_ok = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
                "method": "POST",
                "url": "/api/v1/orders",
                "actor": "alice",
                "json_body": {"item": "book"},
            }))
            assert order_ok["status"] == 201
            assert state["orders"] == 1
            assert client.budget.used == 3

            # concurrent_check on POST /api/promos/claim is allowed and hits target.
            burst = _unwrap_tool_payload(dispatcher.dispatch("concurrent_check", {
                "method": "POST",
                "url": "/api/promos/claim",
                "actor": "alice",
                "json_body": {"code": "WELCOME50"},
                "count": 3,
            }))
            assert burst["count"] == 3
            assert state["promo_claims"] == 3
            assert client.budget.used == 6
            assert len([r for r in log if r["path"] == "/api/promos/claim" and r["method"] == "POST"]) == 3
        finally:
            dispatcher.close()
            client.close()

        # Default bootstrap_stage1_virgin_guard=False preserves sequential write behavior.
        _store2, client2, unguarded = _make_dispatcher(
            tmp_path / "unguarded",
            base_url,
            max_requests=10,
            bootstrap_stage1_virgin_guard=False,
        )
        try:
            res = _unwrap_tool_payload(unguarded.dispatch("http_request", {
                "method": "POST",
                "url": "/api/promos/claim",
                "actor": "alice",
                "json_body": {"code": "SINGLE"},
            }))
            assert res["status"] == 200
            assert client2.budget.used == 1
        finally:
            unguarded.close()
            client2.close()


def test_http_reserve_floor_enforced_across_tools_and_oracle_untouched(tmp_path: Path) -> None:
    def router(method: str, raw_path: str, hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        auth = hdrs.get("authorization", "")
        if path == "/api/items/1" and method == "GET":
            if auth == "Bearer tok-alice":
                return 200, "application/json", json.dumps({"id": 1, "secret": "ALICE-SECRET-777"}), {}
            return 200, "application/json", json.dumps({"id": 1, "secret": "ALICE-SECRET-777"}), {}
        if path == "/api/items/2" and method == "GET":
            return 200, "application/json", json.dumps({"id": 2, "secret": "BOB-SECRET-888"}), {}
        if path == "/api/ping":
            return 200, "application/json", json.dumps({"pong": True}), {}
        return 404, "application/json", json.dumps({"error": "not_found"}), {}

    with _start_test_server(router) as (base_url, _log):
        # max_requests=20, http_reserve_floor=15 => at most 5 requests before floor triggers.
        _store, client, dispatcher = _make_dispatcher(
            tmp_path,
            base_url,
            max_requests=20,
            http_reserve_floor=15,
            with_oracle=True,
        )
        try:
            # Request 1 & 2 (used=0->2, remaining=18 >= 15) succeed.
            r_proof = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
                "method": "GET",
                "url": "/api/items/1",
                "actor": "bob",
            }))
            r_ctrl = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
                "method": "GET",
                "url": "/api/items/2",
                "actor": "bob",
            }))
            assert client.budget.used == 2

            # concurrent_check with count=4 would cross below 15 (18 - 4 = 14 < 15) -> rejected before sending.
            with pytest.raises(BudgetExhaustedError, match="stage-reserved HTTP floor reached"):
                dispatcher._tool_concurrent_check({
                    "method": "GET",
                    "url": "/api/ping",
                    "actor": "alice",
                    "count": 4,
                })
            assert client.budget.used == 2

            # concurrent_check with count=2 fits cleanly (18 - 2 = 16 >= 15).
            cc_ok = _unwrap_tool_payload(dispatcher._tool_concurrent_check({
                "method": "GET",
                "url": "/api/ping",
                "actor": "alice",
                "count": 2,
            }))
            assert cc_ok["count"] == 2
            assert client.budget.used == 4

            # One replay_as fits cleanly (16 - 1 = 15 >= 15).
            replay_ok = _unwrap_tool_payload(dispatcher._tool_replay_as({
                "receipt_id": r_proof["receipt_id"],
                "actor": "alice",
                "force": True,
            }))
            assert replay_ok["replay"]["status"] == 200
            assert client.budget.used == 5

            # Remaining is now 15 (exact floor). All three request tools must raise BudgetExhaustedError.
            with pytest.raises(BudgetExhaustedError, match="15 requests reserved"):
                dispatcher._tool_http_request({"method": "GET", "url": "/api/ping", "actor": "alice", "force": True})
            with pytest.raises(BudgetExhaustedError, match="15 requests reserved"):
                dispatcher._tool_replay_as({"receipt_id": r_proof["receipt_id"], "actor": "alice", "force": True})
            with pytest.raises(BudgetExhaustedError, match="15 requests reserved"):
                dispatcher._tool_concurrent_check({"method": "GET", "url": "/api/ping", "actor": "alice", "count": 2})

            # Via dispatch(), BudgetExhaustedError is returned cleanly as error JSON without spending budget.
            disp_err = json.loads(dispatcher.dispatch("http_request", {
                "method": "GET",
                "url": "/api/ping",
                "actor": "alice",
                "force": True,
            }))
            assert disp_err["error"] == "BudgetExhaustedError"
            assert "15 requests reserved" in disp_err["message"]
            assert client.budget.used == 5

            # record_finding / DifferentialOracle must remain unaffected by http_reserve_floor.
            finding_res = json.loads(dispatcher.dispatch("record_finding", {
                "title": "Cross-actor object access on /api/items/1",
                "class_type": "bola",
                "method": "GET",
                "url": "/api/items/1",
                "actor_alias": "bob",
                "proof_receipt_ids": [r_proof["receipt_id"]],
                "control_receipt_ids": [r_ctrl["receipt_id"]],
                "evidence_value": "ALICE-SECRET-777",
                "summary": "Bob read Alice's item secret.",
            }))
            assert finding_res.get("accepted") is True
        finally:
            dispatcher.close()
            client.close()


@pytest.mark.parametrize(
    ("action_url", "page_url", "expected"),
    [
        ("/api/promos/claim", "http://127.0.0.1:8080/", True),
        ("redeem", "http://127.0.0.1:8080/api/coupons/", True),
        ("", "http://127.0.0.1:8080/promos/claim", True),
        ("#", "http://127.0.0.1:8080/check-in", True),
        ("/api/search", "http://127.0.0.1:8080/", False),
        ("/login", "http://127.0.0.1:8080/", False),
        ("", "http://127.0.0.1:8080/login", False),
        ("/api/search", "http://127.0.0.1:8080/promos", False),
    ],
)
def test_should_skip_stage0_form_submit_unit(action_url: str, page_url: str, expected: bool) -> None:
    assert should_skip_stage0_form_submit(action_url, page_url) is expected


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright Chromium not available")
def test_stage0_forms_mode_records_promo_form_without_submitting(tmp_path: Path) -> None:
    def router(method: str, raw_path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        path = urlsplit(raw_path).path
        if path == "/":
            html = """<!doctype html>
<html><body>
  <form id="note-form" action="/api/notes" method="POST">
    <input name="title" type="text" />
    <button type="submit">Create Note</button>
  </form>
  <form id="promo-form" action="/api/promos/claim" method="POST">
    <input name="code" type="text" />
    <button type="submit">Claim Promo</button>
  </form>
</body></html>"""
            return 200, "text/html; charset=utf-8", html, {}
        if path == "/api/notes" and method == "POST":
            return 201, "application/json", json.dumps({"created": True}), {}
        if path == "/api/promos/claim" and method == "POST":
            return 200, "application/json", json.dumps({"claimed": True}), {}
        return 404, "application/json", json.dumps({"error": "not_found"}), {}

    with _start_test_server(router) as (base_url, log):
        store = ReceiptStore(tmp_path / "receipts")
        http = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=ActorManager([]),
            allowed_methods=("GET", "HEAD", "POST"),
            max_requests=60,
        )
        try:
            res = run_stage0_crawl(
                http,
                allow_forms=True,
                max_pages=4,
                max_actions=4,
                wait_ms=200,
                max_passive_probes=0,
            )
            assert res["status"] == "ok"
            assert res["mode"] == "forms"
            assert res["stats"]["forms_submitted"] == 1

            promo_forms = [
                f for f in res["forms"]
                if f.get("method") == "POST" and f.get("url") == "/api/promos/claim"
            ]
            assert len(promo_forms) == 1
            assert promo_forms[0]["is_form"] is True
            assert "code" in promo_forms[0]["params"]

            hit_posts = [(r["method"], urlsplit(r["path"]).path) for r in log if r["method"] == "POST"]
            assert ("POST", "/api/notes") in hit_posts
            assert ("POST", "/api/promos/claim") not in hit_posts
        finally:
            http.close()
