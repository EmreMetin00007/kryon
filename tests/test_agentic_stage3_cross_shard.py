"""Stage 3 cross-shard synthesis and virgin-state concurrency guidance tests."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_investigator as inv_mod  # noqa: E402
import agentic_report  # noqa: E402
from agentic_context import build_system_prompt  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_sharding import (  # noqa: E402
    SubsystemCluster,
    _is_virgin_state_action_path,
    build_cross_shard_synthesis_prompts,
    build_shard_prompts,
    collect_cross_shard_synthesis_context,
)
from agentic_surface import SurfaceFrontierTracker  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import SessionGate  # noqa: E402


def test_build_system_prompt_virgin_state_concurrency_guidance() -> None:
    prompt = build_system_prompt(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=["GET", "POST", "PUT", "PATCH"],
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
        discovery_hints=["/"],
        http_budget=120,
    )
    assert "concurrent_check" in prompt
    assert "count=3..5" in prompt
    assert "409" in prompt
    assert "virgin state" in prompt.lower()
    for action_kw in (
        "claim",
        "redeem",
        "coupon",
        "promo",
        "bonus",
        "reward",
        "voucher",
        "withdraw",
        "vote",
        "transfer",
    ):
        assert action_kw in prompt
    assert "NEVER probe with a sequential single" in prompt


def test_is_virgin_state_action_path_and_build_shard_prompts_race_bullet() -> None:
    for positive in (
        "/api/promos/claim",
        "POST /api/promos/claim",
        "/api/v1/coupons/{id}/redeem",
        "/vouchers/apply",
        "/rewards/bonus",
        "/wallet/withdraw",
        "/polls/{id}/vote",
        "/daily/checkin",
        "/daily/check-in",
        "http://127.0.0.1:8080/api/promo?code=SAVE10",
    ):
        assert _is_virgin_state_action_path(positive) is True, f"expected True for {positive!r}"

    for negative in (
        "/api/orders",
        "PUT /api/orders/{id}",
        "/api/disclaimer",
        "/static/promo/bundle.js",
        "/assets/claim/style.css",
        "/claim.png",
        "/api/auth/login",
        "/signup/bonus",
        "/register",
        "/logout",
        "/api/session/claim",
        "",
    ):
        assert _is_virgin_state_action_path(negative) is False, f"expected False for {negative!r}"

    race_bullet = (
        "- Virgin-state race priority: run concurrent_check BEFORE sequential single mutations "
        "on primary actors for claim/redeem/promo/coupon/bonus actions so single-use state is not consumed prematurely."
    )

    promo_cluster = SubsystemCluster(
        shard_id="shard-1",
        name="promos",
        families=["promos"],
        routes=["/api/promos/claim"],
        write_ops=["POST /api/promos/claim"],
        objects=[],
        params={},
    )
    promo_sys, _ = build_shard_prompts(
        promo_cluster,
        base_system_prompt="BASE SYSTEM PROMPT",
    )
    assert race_bullet in promo_sys

    promo_write_only_cluster = SubsystemCluster(
        shard_id="shard-2",
        name="billing",
        families=["billing"],
        routes=["/api/billing/balance"],
        write_ops=["POST /api/billing/bonus"],
        objects=[],
        params={},
    )
    write_only_sys, _ = build_shard_prompts(
        promo_write_only_cluster,
        base_system_prompt="BASE SYSTEM PROMPT",
    )
    assert race_bullet in write_only_sys

    orders_cluster = SubsystemCluster(
        shard_id="shard-3",
        name="orders",
        families=["orders"],
        routes=["/api/orders", "/api/orders/{id}"],
        write_ops=["POST /api/orders"],
        objects=["/api/orders/101"],
        params={"/api/orders": ["status"]},
    )
    orders_sys, _ = build_shard_prompts(
        orders_cluster,
        base_system_prompt="BASE SYSTEM PROMPT",
    )
    assert "Virgin-state race priority:" not in orders_sys


def test_collect_cross_shard_synthesis_context_clean_get_only_returns_false(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path)
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=("GET",),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )

    rec1 = store.record(
        actor="alice",
        method="GET",
        url="http://127.0.0.1:8080/api/orders/101",
        path="/api/orders/101",
        status=200,
        elapsed_ms=5.0,
        content_type="application/json",
        response_text=json.dumps({"order_id": 101, "status": "paid", "code": 200, "admin": False}),
    )
    tracker.ingest_receipt(rec1)

    rec2 = store.record(
        actor="alice",
        method="GET",
        url="http://127.0.0.1:8080/api/invoices/202",
        path="/api/invoices/202",
        status=200,
        elapsed_ms=4.0,
        content_type="application/json",
        response_text=json.dumps({"invoice_id": 202, "amount": 50, "currency": "USD"}),
    )
    tracker.ingest_receipt(rec2)

    # GET returning 401 for anon is NOT a blocked write endpoint.
    rec3 = store.record(
        actor="anon",
        method="GET",
        url="http://127.0.0.1:8080/api/invoices/202",
        path="/api/invoices/202",
        status=401,
        elapsed_ms=3.0,
        content_type="application/json",
        response_text=json.dumps({"error": "unauthorized"}),
    )
    tracker.ingest_receipt(rec3)

    # Link pointing to target's own origin port must not be treated as an internal distinct-port URL.
    rec4 = store.record(
        actor="alice",
        method="GET",
        url="http://127.0.0.1:8080/",
        path="/",
        status=200,
        elapsed_ms=3.0,
        content_type="text/html",
        response_text='<a href="http://127.0.0.1:8080/api/orders/101">Orders</a>',
    )
    tracker.ingest_receipt(rec4)

    shard_results = [
        {"shard_id": "shard-1", "finish_summary": "Checked orders GET routes.", "untested_areas": []},
        {"shard_id": "shard-2", "finish_summary": "Checked invoices GET routes.", "untested_areas": []},
    ]
    ctx = collect_cross_shard_synthesis_context(
        shard_results=shard_results,
        findings=[],
        receipts=store,
        surface_tracker=tracker,
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )
    assert ctx["should_trigger"] is False
    assert ctx["internal_urls"] == []
    assert ctx["extracted_values"] == []
    assert ctx["auth_capabilities"] == []
    assert ctx["blockers"] == []
    assert ctx["untested_writes_and_blocked"] == []


def test_collect_cross_shard_synthesis_context_triggers_and_redacts_safely(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path)
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )
    tracker.declared_write_ops.add(("PUT", "/api/account/upgrade"))
    tracker.discovered_write_ops[("PUT", "/api/account/upgrade")] = "/api/account/upgrade"

    # Receipt 1: 2xx JSON containing internal URL (distinct port), leaked partner key, redacted secret, and password
    rec_diag = store.record(
        actor="alice",
        method="GET",
        url="http://127.0.0.1:8080/api/diagnostics/config",
        path="/api/diagnostics/config",
        status=200,
        elapsed_ms=6.0,
        content_type="application/json",
        response_text=json.dumps({
            "connector_endpoint": "http://127.0.0.1:9100/internal/sync",
            "same_origin_url": "http://127.0.0.1:8080/api/health",
            "partner_key": "PK-LIVE-9988",
            "diagnostics_header": "X-Diag-Auth",
            "tier": "enterprise",
            "redacted_secret": "<REDACTED:len=24,sha256_8=deadbeef>",
            "password": "DO_NOT_HARVEST_PASSWORD",
            "login_password": "ALSO_NEVER_HARVEST_PW",
            "oversized_token": "A" * 150,
        }),
        secret_values=["DO_NOT_HARVEST_PASSWORD"],
    )
    tracker.ingest_receipt(rec_diag)

    # Receipt 2: write endpoint that returned 403 and never got 2xx
    rec_blocked = store.record(
        actor="alice",
        method="POST",
        url="http://127.0.0.1:8080/api/partner/sync",
        path="/api/partner/sync",
        status=403,
        elapsed_ms=4.0,
        content_type="application/json",
        request_body='{"password": "actor-login-pw"}',
        response_text=json.dumps({"error": "partner key required"}),
    )
    tracker.ingest_receipt(rec_blocked)

    # Receipt 3: write endpoint that failed once with 401 and later succeeded with 200 -> should NOT be flagged blocked
    rec_write_401 = store.record(
        actor="anon",
        method="POST",
        url="http://127.0.0.1:8080/api/notes",
        path="/api/notes",
        status=401,
        elapsed_ms=2.0,
        content_type="application/json",
        response_text="{}",
    )
    tracker.ingest_receipt(rec_write_401)
    rec_write_200 = store.record(
        actor="alice",
        method="POST",
        url="http://127.0.0.1:8080/api/notes",
        path="/api/notes",
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        response_text='{"id": 1}',
    )
    tracker.ingest_receipt(rec_write_200)

    findings: list[dict[str, Any]] = [
        {
            "finding_id": "F-001",
            "class_type": "jwt_weakness",
            "method": "GET",
            "path": "/api/admin/metrics",
            "actor_alias": "alice",
            "evidence_value": "ADMIN_PIN_4829",
            "summary": "Forged HS256 JWT with public-key.pem unlocked admin metrics; upgrade_code: PRO99",
            "evidence": '{"admin_pin": "4829"}',
        }
    ]
    shard_results = [
        {
            "shard_id": "shard-1",
            "finish_summary": "Diagnostics exposed internal connector http://localhost:9200/metrics",
            "untested_areas": [
                "POST /api/partner/sync blocked with 403; requires partner key from another shard",
                "POST /api/partner/sync blocked with 403; requires partner key from another shard",
            ],
        },
        {
            "shard_id": "shard-2",
            "finish_summary": "PUT /api/account/upgrade requires enterprise tier prerequisite",
            "untested_areas": [],
        },
    ]

    ctx = collect_cross_shard_synthesis_context(
        shard_results=shard_results,
        findings=findings,
        receipts=store,
        surface_tracker=tracker,
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )

    assert ctx["should_trigger"] is True
    assert ctx["shard_count"] == 2

    # Internal URLs include distinct-port URLs and exclude target's own origin port 8080
    assert "http://127.0.0.1:9100/internal/sync" in ctx["internal_urls"]
    assert "http://localhost:9200/metrics" in ctx["internal_urls"]
    assert all(":8080" not in u for u in ctx["internal_urls"])

    # Extracted values capture operational keys/codes/headers and skip <REDACTED / passwords / >120 chars
    joined_vals = "\n".join(ctx["extracted_values"])
    assert "PK-LIVE-9988" in joined_vals
    assert "X-Diag-Auth" in joined_vals
    assert "enterprise" in joined_vals
    assert "4829" in joined_vals
    assert "PRO99" in joined_vals
    assert "<REDACTED" not in joined_vals
    assert "DO_NOT_HARVEST_PASSWORD" not in joined_vals
    assert "ALSO_NEVER_HARVEST_PW" not in joined_vals
    assert "actor-login-pw" not in joined_vals
    assert "A" * 150 not in joined_vals

    # Auth capabilities captured from jwt_weakness
    assert any("jwt_weakness" in cap for cap in ctx["auth_capabilities"])

    # Blockers deduplicated (duplicate untested_areas line collapsed) and capped
    assert len(ctx["blockers"]) == 3
    assert sum("partner key" in b for b in ctx["blockers"]) == 1
    assert any("internal connector" in b for b in ctx["blockers"])
    assert any("enterprise tier" in b for b in ctx["blockers"])

    # Untested write ops + 403 write endpoint (without 2xx POST /api/notes)
    writes_joined = "\n".join(ctx["untested_writes_and_blocked"])
    assert "PUT /api/account/upgrade" in writes_joined
    assert "POST /api/partner/sync (observed 403, no 2xx)" in writes_joined
    assert "/api/notes" not in writes_joined

    # Single-shard run must NOT trigger Stage 3 even with signals
    single_ctx = collect_cross_shard_synthesis_context(
        shard_results=[shard_results[0]],
        findings=findings,
        receipts=store,
        surface_tracker=tracker,
    )
    assert single_ctx["should_trigger"] is False


def test_collect_cross_shard_synthesis_caps_extracted_values_and_blockers(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path)
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=("GET",),
    )
    many_keys = {f"partner_key_{i}": f"VAL-{i}" for i in range(40)}
    store.record(
        actor="anon",
        method="GET",
        url="http://127.0.0.1:8080/api/keys",
        path="/api/keys",
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        response_text=json.dumps(many_keys),
    )
    shard_results = [
        {
            "shard_id": "shard-1",
            "finish_summary": "",
            "untested_areas": [f"route-{i} blocked (403)" for i in range(30)],
        },
        {
            "shard_id": "shard-2",
            "finish_summary": "another shard prerequisite pending",
            "untested_areas": [],
        },
    ]
    ctx = collect_cross_shard_synthesis_context(
        shard_results=shard_results,
        findings=[],
        receipts=store,
        surface_tracker=tracker,
    )
    assert ctx["should_trigger"] is True
    assert len(ctx["extracted_values"]) <= 25
    assert len(ctx["blockers"]) <= 20


def test_build_cross_shard_synthesis_prompts_lifts_fences_and_embeds_context() -> None:
    sharded_base = (
        "BASE METHODOLOGY PROMPT\n\n"
        "SUBSYSTEM SHARD SCOPE (shard-1: orders):\n"
        "- Assigned resource families: orders\n"
        "- Do NOT duplicate work on unrelated subsystems."
    )
    synthesis_context = {
        "should_trigger": True,
        "findings": [
            {
                "finding_id": "F-001",
                "class_type": "jwt_weakness",
                "method": "GET",
                "path": "/api/admin",
                "actor": "alice",
                "evidence_value": "ADMIN_KEY_77",
                "summary": "Forged JWT accepted",
            }
        ],
        "internal_urls": ["http://127.0.0.1:9100/internal/diag"],
        "extracted_values": ["partner_key=PK-LIVE-9988", "diagnostics_header=X-Diag-Auth"],
        "auth_capabilities": ["jwt_weakness (forged/weak JWT auth): GET /api/admin as alice"],
        "blockers": ["[shard-2] POST /api/partner/sync blocked (403); requires partner key"],
        "untested_writes_and_blocked": ["POST /api/partner/sync (observed 403, no 2xx)"],
    }

    sys_p, usr_p = build_cross_shard_synthesis_prompts(
        base_system_prompt=sharded_base,
        synthesis_context=synthesis_context,
        actor_summaries=[
            {"alias": "alice", "role": "member", "tenant": "t1", "password": "MUST_NOT_APPEAR"},
        ],
        http_budget_remaining=42,
        state_banner="\n[STATE] http_budget: 42/100 left",
    )

    assert "BASE METHODOLOGY PROMPT" in sys_p
    assert "SUBSYSTEM SHARD SCOPE" not in sys_p
    assert "Do NOT duplicate work on unrelated subsystems" not in sys_p
    assert "UNIFIED CROSS-SHARD CHAIN SYNTHESIS (Stage 3)" in sys_p
    assert "F-001" in sys_p
    assert "concurrent_check" in sys_p
    assert "record_finding" in sys_p
    assert "finish" in sys_p

    assert "UNIFIED CROSS-SHARD CHAIN SYNTHESIS (Stage 3)" in usr_p
    assert "42" in usr_p
    assert "http://127.0.0.1:9100/internal/diag" in usr_p
    assert "PK-LIVE-9988" in usr_p
    assert "X-Diag-Auth" in usr_p
    assert "jwt_weakness" in usr_p
    assert "POST /api/partner/sync" in usr_p
    assert "alice" in usr_p
    assert "MUST_NOT_APPEAR" not in usr_p
    assert "MUST_NOT_APPEAR" not in sys_p
    assert "[STATE] http_budget: 42/100 left" in usr_p


def _s3_tool_resp(
    call_id: str,
    name: str,
    args: dict[str, Any],
    *,
    prompt_tokens: int = 200,
    completion_tokens: int = 50,
    cached_tokens: int = 100,
    reasoning_tokens: int = 10,
) -> dict[str, Any]:
    return {
        "id": f"cmpl-{call_id}",
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args)},
                }],
            }
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "prompt_tokens_details": {"cached_tokens": cached_tokens},
            "completion_tokens_details": {"reasoning_tokens": reasoning_tokens},
        },
    }


def _s3_multi_resp(
    calls: list[tuple[str, str, dict[str, Any]]],
    *,
    prompt_tokens: int = 200,
    completion_tokens: int = 50,
) -> dict[str, Any]:
    return {
        "id": f"cmpl-{calls[0][0]}",
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": cid,
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(args)},
                    }
                    for cid, name, args in calls
                ],
            }
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "prompt_tokens_details": {"cached_tokens": prompt_tokens // 2},
            "completion_tokens_details": {"reasoning_tokens": 10},
        },
    }


def test_e2e_sharded_virgin_guard_reserve_and_stage3_cross_shard_chain(tmp_path: Path) -> None:
    """End-to-end loopback sharded run: Stage 1 virgin guard -> Stage 2 shards -> Stage 3 chain + report."""
    state_lock = threading.Lock()
    server_state: dict[str, Any] = {
        "promo_claims": 0,
        "claimed": False,
        "balance": 0,
        "upgrade_calls": [],
    }

    class _ChainAppHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def _send_json(self, status: int, data: Any) -> None:
            raw = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == "/":
                html = (
                    "<html><body>"
                    "<a href='/api/promos/info'>Promo Info</a>"
                    "<a href='/api/promos/status'>Promo Status</a>"
                    "<a href='/api/promos/rules'>Promo Rules</a>"
                    "<form method='POST' action='/api/promos/claim'>"
                    "<input name='code' value='WELCOME100'/></form>"
                    "<a href='/api/ledger/summary'>Ledger Summary</a>"
                    "<a href='/api/ledger/entries'>Ledger Entries</a>"
                    "<a href='/api/ledger/export'>Ledger Export</a>"
                    "<a href='/api/ledger/search?q=partner'>Ledger Search</a>"
                    "<a href='/api/settlements/status'>Settlements Status</a>"
                    "<form method='POST' action='/api/settlements/upgrade'>"
                    "<input name='tier' value='enterprise'/></form>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            if path == "/api/ledger/search":
                q = parse_qs(parsed.query).get("q", [""])[0]
                if "partner" in q.lower():
                    self._send_json(
                        200,
                        {
                            "matches": [
                                {
                                    "id": 1,
                                    "partner_secret": "PARTNER_SECRET",
                                    "required_header": "X-Partner-Secret",
                                }
                            ]
                        },
                    )
                    return
                self._send_json(200, {"matches": []})
                return
            if path == "/api/promos/status":
                with state_lock:
                    bal = int(server_state["balance"])
                    claimed = bool(server_state["claimed"])
                self._send_json(200, {"balance": bal, "claimed": claimed})
                return
            if path.startswith("/api/"):
                self._send_json(200, {"path": path, "ok": True})
                return
            self._send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            _ = self.rfile.read(length)
            path = urlsplit(self.path).path
            if path == "/api/promos/claim":
                with state_lock:
                    already = bool(server_state["claimed"])
                if already:
                    self._send_json(409, {"error": "already_claimed"})
                    return
                # Intentional race window: concurrent_check requests enter before claimed flips.
                time.sleep(0.06)
                with state_lock:
                    server_state["promo_claims"] += 1
                    server_state["balance"] += 50
                    server_state["claimed"] = True
                    bal = int(server_state["balance"])
                self._send_json(200, {"claimed": True, "balance": bal})
                return
            if path == "/api/settlements/upgrade":
                secret_hdr = self.headers.get("X-Partner-Secret", "")
                with state_lock:
                    bal = int(server_state["balance"])
                    server_state["upgrade_calls"].append({"balance": bal, "secret": secret_hdr})
                if bal < 100 or secret_hdr != "PARTNER_SECRET":
                    self._send_json(
                        403,
                        {"error": "requires balance >= 100 and valid X-Partner-Secret"},
                    )
                    return
                self._send_json(
                    200,
                    {
                        "upgraded": True,
                        "tier": "enterprise",
                        "balance": bal,
                        "proof": "CHAINED_SETTLEMENT_UNLOCKED",
                    },
                )
                return
            self._send_json(404, {"error": "not_found"})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _ChainAppHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base_url = f"http://127.0.0.1:{srv.server_address[1]}/"

    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-alice"},
        {"alias": "bob", "role": "member", "tenant": "t2", "auth_header": "Bearer tok-bob"},
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=60,
    )
    budget = SharedBudget(http=60, tokens=240_000, seconds=120)

    stage1_blocked_replies: list[dict[str, Any]] = []
    stage3_prompts_seen: list[tuple[str, str]] = []
    shard_assignments: dict[str, str] = {}
    ctrl_403_rids: list[str] = []
    transport_lock = threading.Lock()

    class _ChainTransport:
        def __init__(self) -> None:
            self.calls = 0
            self.provider_responses: list[dict[str, Any]] = []
            self.session_gate = SessionGate()
            self._boot_step = 0
            self._shard_steps: dict[str, int] = {}
            self._s3_step = 0

        def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
            with transport_lock:
                self.calls += 1
            msgs = body.get("messages") or []
            sys_msg = str((msgs[0] if msgs else {}).get("content") or "")
            usr_msg = str((msgs[1] if len(msgs) > 1 else {}).get("content") or "")

            if "UNIFIED CROSS-SHARD CHAIN SYNTHESIS (Stage 3)" in sys_msg:
                with transport_lock:
                    self._s3_step += 1
                    step = self._s3_step
                    stage3_prompts_seen.append((sys_msg, usr_msg))
                if step == 1:
                    assert "PARTNER_SECRET" in usr_msg
                    return _s3_tool_resp(
                        "s3_1",
                        "http_request",
                        {
                            "method": "POST",
                            "url": "/api/settlements/upgrade",
                            "actor": "alice",
                            "headers": {"X-Partner-Secret": "PARTNER_SECRET"},
                            "json_body": {"tier": "enterprise"},
                        },
                    )
                if step == 2:
                    last_tool = [str(m.get("content") or "") for m in msgs if m.get("role") == "tool"][-1]
                    inner = last_tool.split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1].split(
                        "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1
                    )[0]
                    proof_rid = json.loads(inner)["receipt_id"]
                    return _s3_multi_resp([
                        (
                            "s3_2a",
                            "record_finding",
                            {
                                "class_type": "business_logic",
                                "title": "Chained promo race + ledger secret unlocks enterprise upgrade",
                                "method": "POST",
                                "url": "/api/settlements/upgrade",
                                "actor": "alice",
                                "severity": "critical",
                                "evidence_value": "CHAINED_SETTLEMENT_UNLOCKED",
                                "excerpt": "CHAINED_SETTLEMENT_UNLOCKED",
                                "summary": (
                                    "Chained concurrent /api/promos/claim balance>=100 and leaked "
                                    "PARTNER_SECRET from /api/ledger/search to unlock enterprise upgrade."
                                ),
                                "proof_receipt_ids": [proof_rid],
                                "control_receipt_ids": list(ctrl_403_rids[:1]),
                            },
                        ),
                        ("s3_2b", "finish", {"summary": "Stage 3 chained business logic finding verified."}),
                    ])
                return _s3_tool_resp("s3_end", "finish", {"summary": "Stage 3 complete"})

            if "SUBSYSTEM SHARD SCOPE (" in sys_msg:
                marker = "SUBSYSTEM SHARD SCOPE ("
                shard_id = sys_msg[sys_msg.index(marker) + len(marker) :].split(":", 1)[0].strip()
                routes_text = sys_msg.split("Assigned routes:", 1)[1]
                with transport_lock:
                    shard_assignments[shard_id] = routes_text
                    step = self._shard_steps.get(shard_id, 0) + 1
                    self._shard_steps[shard_id] = step

                if "promos" in routes_text:
                    if step == 1:
                        return _s3_tool_resp(
                            f"{shard_id}_1",
                            "concurrent_check",
                            {
                                "method": "POST",
                                "url": "/api/promos/claim",
                                "actor": "alice",
                                "json_body": {"code": "WELCOME100"},
                                "count": 3,
                            },
                        )
                    return _s3_tool_resp(
                        f"{shard_id}_2",
                        "finish",
                        {"summary": f"{shard_id} executed concurrent_check on /api/promos/claim"},
                    )

                # Ledger + settlements shard
                if step == 1:
                    return _s3_multi_resp([
                        (
                            f"{shard_id}_1a",
                            "http_request",
                            {"method": "GET", "url": "/api/ledger/search?q=partner", "actor": "alice"},
                        ),
                        (
                            f"{shard_id}_1b",
                            "http_request",
                            {
                                "method": "POST",
                                "url": "/api/settlements/upgrade",
                                "actor": "alice",
                                "json_body": {"tier": "enterprise"},
                            },
                        ),
                    ])
                if step == 2:
                    for m in msgs:
                        if m.get("role") == "tool" and m.get("tool_call_id") == f"{shard_id}_1b":
                            raw_block = str(m["content"]).split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1].split(
                                "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1
                            )[0]
                            ctrl_403_rids.append(json.loads(raw_block)["receipt_id"])
                    return _s3_tool_resp(
                        f"{shard_id}_2",
                        "finish",
                        {
                            "summary": (
                                "Extracted PARTNER_SECRET from /api/ledger/search; "
                                "POST /api/settlements/upgrade blocked 403 awaiting promos balance>=100"
                            ),
                            "untested_areas": [
                                "POST /api/settlements/upgrade blocked (403); requires balance>=100 from promos shard"
                            ],
                        },
                    )
                return _s3_tool_resp(f"{shard_id}_end", "finish", {"summary": f"{shard_id} done"})

            # Stage 1 Bootstrap
            with transport_lock:
                self._boot_step += 1
                step = self._boot_step
            if step == 1:
                return _s3_tool_resp("b1", "http_request", {"method": "GET", "url": "/", "actor": "alice"})
            if step == 2:
                return _s3_multi_resp([
                    ("b2", "extract_surface", {"receipt_id": "req-0001"}),
                    (
                        "b3",
                        "http_request",
                        {
                            "method": "POST",
                            "url": "/api/promos/claim",
                            "actor": "alice",
                            "json_body": {"code": "WELCOME100"},
                        },
                    ),
                ])
            for m in msgs:
                if m.get("role") == "tool" and m.get("tool_call_id") == "b3":
                    raw_block = str(m["content"]).split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1].split(
                        "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1
                    )[0]
                    stage1_blocked_replies.append(json.loads(raw_block))
            return _s3_tool_resp("b4", "finish", {"summary": "Stage 1 discovery complete"})

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_ChainTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            discovery_hints=["/"],
            max_turns=30,
            execution_mode="sharded",
            max_shards=2,
            bootstrap_turns=6,
            shard_turns=8,
            verification_gate="differential",
            sleep_fn=lambda _s: None,
        )
        res = inv.run()

        assert res["status"] == "finished"
        assert inv.dispatcher.bootstrap_stage1_virgin_guard is False

        # 1. Stage 1 sequential write to /api/promos/claim was blocked at 0 HTTP cost.
        assert stage1_blocked_replies
        assert stage1_blocked_replies[0]["blocked"] is True
        assert stage1_blocked_replies[0]["reason"] == "virgin_state_preserved_for_concurrency_or_shard"

        # 2. Stage 2 shard-1 ran concurrent_check unlocking balance >= 100; shard-2 extracted PARTNER_SECRET.
        assert "promos" in shard_assignments.get("shard-1", "")
        assert "ledger" in shard_assignments.get("shard-2", "")
        assert server_state["promo_claims"] == 3
        assert server_state["balance"] == 150

        # 3. Stage 3 triggered automatically, lifted shard fences, chained BOTH into POST /api/settlements/upgrade,
        # and verified the chained business_logic finding through DifferentialOracle.
        assert stage3_prompts_seen
        s3_sys, s3_usr = stage3_prompts_seen[0]
        assert "UNIFIED CROSS-SHARD CHAIN SYNTHESIS (Stage 3)" in s3_sys
        assert "SUBSYSTEM SHARD SCOPE" not in s3_sys
        assert "PARTNER_SECRET" in s3_usr
        assert any(
            call["balance"] >= 100 and call["secret"] == "PARTNER_SECRET"
            for call in server_state["upgrade_calls"]
        )

        ss = res["sharding_summary"]
        assert ss["stage3_synthesis"]["triggered"] is True
        assert ss["stage3_synthesis"]["status"] == "finished"
        assert ss["stage3_synthesis"]["findings"] == 1
        assert ss["stage3_synthesis"]["calls"] >= 2
        assert ss["stage3_synthesis"]["tokens"] > 0

        saved = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
        assert len(saved) == 1
        assert saved[0]["class_type"] == "business_logic"
        assert saved[0]["path"] == "/api/settlements/upgrade"
        assert saved[0]["evidence_value"] == "CHAINED_SETTLEMENT_UNLOCKED"

        # 4. report.md renders the Stage 3 execution row in Section 4.
        manifest_doc = {
            **res,
            "run_id": "run-stage3-e2e",
            "target": base_url,
            "surface_frontier": inv.dispatcher.surface_tracker.to_dict(),
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_doc, indent=2), encoding="utf-8")
        rep_summary = agentic_report.generate_run_reports(tmp_path)
        md_text = Path(rep_summary["markdown_path"]).read_text(encoding="utf-8")
        assert "## 4. Shard Execution Summary" in md_text
        assert "| stage3-synthesis | (cross-shard) | finished |" in md_text
        assert "CHAINED_SETTLEMENT_UNLOCKED" in md_text
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_http_reserve_floor_wrapup_and_clean_break(tmp_path: Path, monkeypatch: Any) -> None:
    """Shards see usable_http_rem in wrapup/URGENT, stop after at most 1 final wrapup turn, and preserve Stage 3 HTTP."""
    state_lock = threading.Lock()

    class _ReserveAppHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/":
                html = (
                    "<html><body>"
                    "<a href='/api/alpha/one'>A1</a><a href='/api/alpha/two'>A2</a>"
                    "<a href='/api/alpha/three'>A3</a><a href='/api/alpha/four'>A4</a>"
                    "<a href='/api/beta/one'>B1</a><a href='/api/beta/two'>B2</a>"
                    "<a href='/api/beta/three'>B3</a><a href='/api/beta/four'>B4</a>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            payload = json.dumps({"path": path, "partner_key": "RES_KEY_77"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _ReserveAppHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base_url = f"http://127.0.0.1:{srv.server_address[1]}/"

    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=ActorManager(),
        allowed_methods=("GET",),
        max_requests=44,
    )
    budget = SharedBudget(http=44, tokens=200_000, seconds=120)

    observed_floors: list[int] = []
    orig_disp_cls = inv_mod.ToolDispatcher

    class _FloorSpyDispatcher(orig_disp_cls):  # type: ignore[misc]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            with state_lock:
                if "shards" in str(self.root_dir):
                    observed_floors.append(self.http_reserve_floor)

    monkeypatch.setattr(inv_mod, "ToolDispatcher", _FloorSpyDispatcher)

    shard_wrapup_msgs: list[str] = []
    stage3_http_rem_at_start: list[int] = []

    class _ReserveTransport:
        def __init__(self) -> None:
            self.calls = 0
            self.provider_responses: list[dict[str, Any]] = []
            self.session_gate = SessionGate()
            self._boot_step = 0
            self._shard_steps: dict[str, int] = {}
            self._s3_step = 0

        def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
            with state_lock:
                self.calls += 1
            msgs = body.get("messages") or []
            sys_msg = str((msgs[0] if msgs else {}).get("content") or "")

            if "UNIFIED CROSS-SHARD CHAIN SYNTHESIS (Stage 3)" in sys_msg:
                with state_lock:
                    self._s3_step += 1
                    if self._s3_step == 1:
                        stage3_http_rem_at_start.append(client.budget.limit - client.budget.used)
                        return _s3_tool_resp("s3_get", "http_request", {"method": "GET", "url": "/api/alpha/one"})
                return _s3_tool_resp("s3_fin", "finish", {"summary": "Stage 3 used reserved HTTP headroom"})

            if "SUBSYSTEM SHARD SCOPE (" in sys_msg:
                marker = "SUBSYSTEM SHARD SCOPE ("
                shard_id = sys_msg[sys_msg.index(marker) + len(marker) :].split(":", 1)[0].strip()
                with state_lock:
                    step = self._shard_steps.get(shard_id, 0) + 1
                    self._shard_steps[shard_id] = step
                if step == 1:
                    # Try firing 18 requests across the two shards to hit the 12-request reserve floor.
                    return _s3_multi_resp([
                        (f"{shard_id}_r{i}", "http_request", {"method": "GET", "url": f"/api/alpha/{i}?s={shard_id}"})
                        for i in range(1, 19)
                    ])
                last_tool = [str(m.get("content") or "") for m in msgs if m.get("role") == "tool"][-1]
                with state_lock:
                    shard_wrapup_msgs.append(last_tool)
                # Deliberately do NOT call finish even on the 1 wrapup turn; next turn must break cleanly.
                return _s3_tool_resp(f"{shard_id}_extra", "notebook", {"action": "write", "surface_notes": "wrapup"})

            with state_lock:
                self._boot_step += 1
                step = self._boot_step
            if step == 1:
                return _s3_tool_resp("b1", "http_request", {"method": "GET", "url": "/"})
            if step == 2:
                return _s3_tool_resp("b2", "extract_surface", {"receipt_id": "req-0001"})
            return _s3_tool_resp("b3", "finish", {"summary": "boot done"})

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_ReserveTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=30,
            execution_mode="sharded",
            max_shards=2,
            bootstrap_turns=5,
            shard_turns=10,
            sleep_fn=lambda _s: None,
        )
        res = inv.run()

        # Bootstrap used 1 HTTP -> remaining=43 >= 40 -> stage3_http_reserve = max(12, int(43*0.15)) = 12.
        assert 12 in observed_floors
        assert 0 in observed_floors  # stage3 dispatcher has http_reserve_floor=0
        assert any("[BUDGET-WRAPUP]" in m and "[URGENT]" in m for m in shard_wrapup_msgs)
        assert stage3_http_rem_at_start and stage3_http_rem_at_start[0] >= 12
        assert res["sharding_summary"]["stage3_synthesis"]["triggered"] is True
        assert res["sharding_summary"]["stage3_synthesis"]["status"] == "finished"
        assert all(s["status"] == "budget_exhausted" for s in res["sharding_summary"]["shards"])
        assert all(s["calls"] <= 2 for s in res["sharding_summary"]["shards"])
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()
