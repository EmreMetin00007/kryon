"""Phase 4 tests: per-shard soft token quotas, [BUDGET-WRAPUP], and dispatcher close lifecycle."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_investigator as inv_mod  # noqa: E402
import agentic_runner  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from full_agent_budget import BudgetError, SharedBudget  # noqa: E402
from full_agent_provider import SessionGate  # noqa: E402


def _tool_resp(
    call_id: str,
    name: str,
    args: dict[str, Any],
    *,
    prompt_tokens: int = 100,
    completion_tokens: int = 50,
) -> dict[str, Any]:
    return {
        "id": f"cmpl-{call_id}",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": json.dumps(args)},
                        }
                    ],
                }
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


def _multi_resp(
    calls: list[tuple[str, str, dict[str, Any]]],
    *,
    prompt_tokens: int = 100,
    completion_tokens: int = 50,
) -> dict[str, Any]:
    return {
        "id": f"cmpl-{calls[0][0]}",
        "choices": [
            {
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
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


def _start_multi_family_server() -> tuple[ThreadingHTTPServer, str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/":
                html = (
                    "<html><body>"
                    "<a href='/orders'>Orders</a>"
                    "<a href='/orders/101'>Order 101</a>"
                    "<a href='/invoices'>Invoices</a>"
                    "<a href='/invoices/202'>Invoice 202</a>"
                    "<a href='/tickets'>Tickets</a>"
                    "<a href='/tickets/303'>Ticket 303</a>"
                    "<a href='/api/v1/orders'>API Orders</a>"
                    "<a href='/api/v1/orders/101'>API Order 101</a>"
                    "<a href='/api/v1/invoices'>API Invoices</a>"
                    "<a href='/api/v1/invoices/202'>API Invoice 202</a>"
                    "<a href='/api/v1/tickets'>API Tickets</a>"
                    "<a href='/api/v1/tickets/303'>API Ticket 303</a>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            if path in {"/api/v1/orders", "/api/v1/orders/101"}:
                body = json.dumps({"order_id": 101, "secret_code": "ORD_TOK_111"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path in {"/api/v1/invoices", "/api/v1/invoices/202"}:
                body = json.dumps({"invoice_id": 202, "secret_code": "INV_TOK_222"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path in {"/api/v1/tickets", "/api/v1/tickets/303"}:
                body = json.dumps({"ticket_id": 303, "secret_code": "TKT_TOK_333"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, f"http://127.0.0.1:{port}/"


def test_sharded_soft_quota_injects_budget_wrapup_and_finishes_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shards emit [BUDGET-WRAPUP] and disable coverage_gate_enabled at 80% shard quota before global exhaustion."""
    srv, base_url = _start_multi_family_server()
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-alice"},
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET",),
        max_requests=200,
    )
    # 120,000 tokens total; bootstrap uses 3,000 -> ~117,000 remaining -> auto quota ~35,100/shard.
    budget = SharedBudget(http=200, tokens=120_000, seconds=120)
    state_lock = threading.Lock()
    shard_wrapup_observed: dict[str, bool] = {}
    shard_gate_on_wrapup: dict[str, bool] = {}
    shard_global_avail_on_wrapup: dict[str, int] = {}
    created_dispatchers: list[Any] = []

    orig_dispatcher_cls = inv_mod.ToolDispatcher

    class _TrackingDispatcher(orig_dispatcher_cls):  # type: ignore[misc]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            # Start shard dispatchers with coverage_gate_enabled=True via tracker check below;
            # AgenticInvestigator disables it in shard mode and also on [BUDGET-WRAPUP].
            with state_lock:
                created_dispatchers.append(self)

    monkeypatch.setattr(inv_mod, "ToolDispatcher", _TrackingDispatcher)

    class _QuotaTransport:
        def __init__(self) -> None:
            self.calls = 0
            self.provider_responses: list[dict[str, Any]] = []
            self.session_gate = SessionGate()
            self._boot_step = 0
            self._shard_steps: dict[str, int] = {}

        def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
            with state_lock:
                self.calls += 1
            sys_msg = str((body.get("messages") or [{}])[0].get("content") or "")
            if "SUBSYSTEM SHARD SCOPE (" not in sys_msg:
                with state_lock:
                    self._boot_step += 1
                    step = self._boot_step
                if step == 1:
                    budget.used["tokens"] += 1500
                    return _multi_resp(
                        [
                            ("b1", "http_request", {"method": "GET", "url": "/", "actor": "alice"}),
                            ("b2", "http_request", {"method": "GET", "url": "/nonexistent", "actor": "anon"}),
                        ],
                        prompt_tokens=1000,
                        completion_tokens=500,
                    )
                if step == 2:
                    budget.used["tokens"] += 1500
                    return _tool_resp(
                        "b3",
                        "extract_surface",
                        {"receipt_id": "req-0001"},
                        prompt_tokens=1000,
                        completion_tokens=500,
                    )
                return _tool_resp("b4", "finish", {"summary": "bootstrap done"}, prompt_tokens=100, completion_tokens=50)

            marker = "SUBSYSTEM SHARD SCOPE ("
            start = sys_msg.index(marker) + len(marker)
            shard_id = sys_msg[start:].split(":", 1)[0].strip()
            with state_lock:
                step = self._shard_steps.get(shard_id, 0) + 1
                self._shard_steps[shard_id] = step

            routes_text = sys_msg.split("Assigned routes:", 1)[1]
            if "invoices" in routes_text:
                target_path, secret = "/api/v1/invoices/202", "INV_TOK_222"
            elif "tickets" in routes_text:
                target_path, secret = "/api/v1/tickets/303", "TKT_TOK_333"
            else:
                target_path, secret = "/api/v1/orders/101", "ORD_TOK_111"

            if step == 1:
                # Consume 29,000 tokens (>= 80% of ~35,100 auto quota, well below global 120,000)
                with state_lock:
                    budget.used["tokens"] += 29_000
                return _tool_resp(
                    f"{shard_id}-1",
                    "http_request",
                    {"method": "GET", "url": target_path, "actor": "anon"},
                    prompt_tokens=20_000,
                    completion_tokens=9_000,
                )

            # Step 2: [BUDGET-WRAPUP] must now be present in the shard's tool response message!
            tool_msgs = [str(m.get("content") or "") for m in body["messages"] if m.get("role") == "tool"]
            last_tool = tool_msgs[-1] if tool_msgs else ""
            with state_lock:
                shard_wrapup_observed[shard_id] = "[BUDGET-WRAPUP]" in last_tool
                shard_global_avail_on_wrapup[shard_id] = budget.available("tokens")
                for d in created_dispatchers:
                    if str(d.root_dir).endswith(shard_id):
                        shard_gate_on_wrapup[shard_id] = d.coverage_gate_enabled
            rec_json = last_tool.split("<<<UNTRUSTED_TARGET_RESPONSE>>>", 1)[1].split(
                "<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1
            )[0]
            rec_id = json.loads(rec_json)["receipt_id"]
            with state_lock:
                budget.used["tokens"] += 1500
            return _multi_resp(
                [
                    (
                        f"{shard_id}-2a",
                        "record_finding",
                        {
                            "class_type": "auth_bypass",
                            "title": f"Bypass on {target_path}",
                            "method": "GET",
                            "url": target_path,
                            "actor": "anon",
                            "severity": "high",
                            "evidence_value": secret,
                            "excerpt": secret,
                            "summary": "Unauthenticated access to resource.",
                            "proof_receipt_ids": [rec_id],
                            "control_receipt_ids": ["req-0001"],
                        },
                    ),
                    (f"{shard_id}-2b", "finish", {"summary": f"{shard_id} wrapped up cleanly"}),
                ],
                prompt_tokens=1000,
                completion_tokens=500,
            )

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_QuotaTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            discovery_hints=["/"],
            max_turns=30,
            execution_mode="sharded",
            max_shards=3,
            bootstrap_turns=6,
            shard_turns=10,
            max_shard_retries=0,
            verification_gate="llm_self_judge",
        )
        res = inv.run()

        assert res["status"] == "finished"
        summary = res["sharding_summary"]
        assert summary["fallback_to_monolithic"] is False
        assert len(summary["shards"]) == 3
        for s in summary["shards"]:
            assert s["status"] == "finished"
            assert s["shard_token_quota"] >= 25_000
            assert s["tokens"] > 0

        # All 3 shards received [BUDGET-WRAPUP] with coverage_gate_enabled=False BEFORE global exhaustion
        assert set(shard_wrapup_observed) == {"shard-1", "shard-2", "shard-3"}
        assert all(shard_wrapup_observed.values())
        assert all(gate is False for gate in shard_gate_on_wrapup.values())
        assert all(avail > 10_000 for avail in shard_global_avail_on_wrapup.values())

        # All 3 shard findings merged cleanly
        saved = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
        assert len(saved) == 3
        assert {f["path"] for f in saved} == {
            "/api/v1/orders/101",
            "/api/v1/invoices/202",
            "/api/v1/tickets/303",
        }
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_sharded_quota_hard_cap_and_budget_error_classify_as_budget_exhausted(tmp_path: Path) -> None:
    """Shards hitting per-shard quota, <3500 global tokens, or BudgetError stop as budget_exhausted, preserving findings."""
    srv, base_url = _start_multi_family_server()
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-alice"},
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET",),
        max_requests=200,
    )
    budget = SharedBudget(http=200, tokens=100_000, seconds=120)
    state_lock = threading.Lock()

    class _ContentionTransport:
        def __init__(self) -> None:
            self.calls = 0
            self.provider_responses: list[dict[str, Any]] = []
            self.session_gate = SessionGate()
            self._boot_step = 0
            self._shard_steps: dict[str, int] = {}

        def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
            with state_lock:
                self.calls += 1
            sys_msg = str((body.get("messages") or [{}])[0].get("content") or "")
            if "SUBSYSTEM SHARD SCOPE (" not in sys_msg:
                with state_lock:
                    self._boot_step += 1
                    step = self._boot_step
                if step == 1:
                    return _multi_resp([
                        ("b1", "http_request", {"method": "GET", "url": "/", "actor": "alice"}),
                        ("b2", "http_request", {"method": "GET", "url": "/nonexistent", "actor": "anon"}),
                    ])
                if step == 2:
                    return _tool_resp("b3", "extract_surface", {"receipt_id": "req-0001"})
                return _tool_resp("b4", "finish", {"summary": "bootstrap complete"})

            marker = "SUBSYSTEM SHARD SCOPE ("
            start = sys_msg.index(marker) + len(marker)
            shard_id = sys_msg[start:].split(":", 1)[0].strip()
            with state_lock:
                step = self._shard_steps.get(shard_id, 0) + 1
                self._shard_steps[shard_id] = step

            routes_text = sys_msg.split("Assigned routes:", 1)[1]
            if "invoices" in routes_text:
                target_path, secret = "/api/v1/invoices/202", "INV_TOK_222"
                role_kind = "quota_exceeded"
            elif "tickets" in routes_text:
                target_path, secret = "/api/v1/tickets/303", "TKT_TOK_333"
                role_kind = "budget_error"
            else:
                target_path, secret = "/api/v1/orders/101", "ORD_TOK_111"
                role_kind = "clean_finish"

            if step == 1:
                return _tool_resp(
                    f"{shard_id}-1",
                    "http_request",
                    {"method": "GET", "url": target_path, "actor": "anon"},
                    prompt_tokens=4000,
                    completion_tokens=1000,
                )

            if step == 2:
                last_tool = [m for m in body["messages"] if m.get("role") == "tool"][-1]["content"]
                rec_json = last_tool.split("<<<UNTRUSTED_TARGET_RESPONSE>>>", 1)[1].split(
                    "<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1
                )[0]
                rec_id = json.loads(rec_json)["receipt_id"]
                if role_kind == "clean_finish":
                    return _multi_resp([
                        (
                            f"{shard_id}-2a",
                            "record_finding",
                            {
                                "class_type": "auth_bypass",
                                "title": f"Bypass on {target_path}",
                                "method": "GET",
                                "url": target_path,
                                "actor": "anon",
                                "severity": "high",
                                "evidence_value": secret,
                                "excerpt": secret,
                                "summary": "Verified auth bypass.",
                                "proof_receipt_ids": [rec_id],
                                "control_receipt_ids": ["req-0001"],
                            },
                        ),
                        (f"{shard_id}-2b", "finish", {"summary": "done"}),
                    ])
                # Record finding, but burn >= shard_token_quota (10,000) without calling finish
                return _tool_resp(
                    f"{shard_id}-2a",
                    "record_finding",
                    {
                        "class_type": "auth_bypass",
                        "title": f"Bypass on {target_path}",
                        "method": "GET",
                        "url": target_path,
                        "actor": "anon",
                        "severity": "high",
                        "evidence_value": secret,
                        "excerpt": secret,
                        "summary": "Verified auth bypass.",
                        "proof_receipt_ids": [rec_id],
                        "control_receipt_ids": ["req-0001"],
                    },
                    prompt_tokens=4000 if role_kind == "quota_exceeded" else 1000,
                    completion_tokens=1500 if role_kind == "quota_exceeded" else 500,
                )

            if role_kind == "budget_error":
                # Simulate concurrent global token reservation collision wrapped as provider_budget_error
                raise BudgetError("tokens budget exhausted or reserved", code="provider_budget_error")
            raise AssertionError(f"shard {shard_id} ({role_kind}) should have stopped at quota before step {step}")

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_ContentionTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            discovery_hints=["/"],
            max_turns=30,
            execution_mode="sharded",
            max_shards=3,
            bootstrap_turns=6,
            shard_turns=10,
            shard_token_quota=10_000,
            verification_gate="llm_self_judge",
        )
        res = inv.run()

        assert res["status"] == "finished"
        shards = res["sharding_summary"]["shards"]
        assert len(shards) == 3
        statuses = {s["status"] for s in shards}
        assert statuses == {"finished", "budget_exhausted"}
        assert "provider_budget_error" not in statuses
        assert all(s["shard_token_quota"] == 10_000 for s in shards)

        # Every shard's recorded finding survived despite budget_exhausted / BudgetError!
        saved = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
        assert len(saved) == 3
        assert {f["path"] for f in saved} == {
            "/api/v1/orders/101",
            "/api/v1/invoices/202",
            "/api/v1/tickets/303",
        }
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_shard_precall_global_token_floor_stops_without_provider_call(tmp_path: Path) -> None:
    """Shard stops cleanly as budget_exhausted before LLM call when global available tokens < 3500."""
    srv, base_url = _start_multi_family_server()
    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=ActorManager(),
        allowed_methods=("GET",),
        max_requests=100,
    )
    budget = SharedBudget(http=100, tokens=80_000, seconds=120)
    state_lock = threading.Lock()
    shard_step2_calls = 0

    class _FloorTransport:
        def __init__(self) -> None:
            self.calls = 0
            self.provider_responses: list[dict[str, Any]] = []
            self.session_gate = SessionGate()
            self._boot_step = 0
            self._shard_steps: dict[str, int] = {}

        def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
            nonlocal shard_step2_calls
            with state_lock:
                self.calls += 1
            sys_msg = str((body.get("messages") or [{}])[0].get("content") or "")
            if "SUBSYSTEM SHARD SCOPE (" not in sys_msg:
                with state_lock:
                    self._boot_step += 1
                    step = self._boot_step
                if step == 1:
                    return _tool_resp("b1", "http_request", {"method": "GET", "url": "/", "actor": "anon"})
                if step == 2:
                    return _tool_resp("b2", "extract_surface", {"receipt_id": "req-0001"})
                return _tool_resp("b3", "finish", {"summary": "boot done"})

            marker = "SUBSYSTEM SHARD SCOPE ("
            start = sys_msg.index(marker) + len(marker)
            shard_id = sys_msg[start:].split(":", 1)[0].strip()
            with state_lock:
                step = self._shard_steps.get(shard_id, 0) + 1
                self._shard_steps[shard_id] = step
                if step == 1:
                    # Drop global available tokens below 3500 (but >= 2500)
                    budget.used["tokens"] = 77_000
                    return _tool_resp(f"{shard_id}-1", "http_request", {"method": "GET", "url": "/", "actor": "anon"})
                shard_step2_calls += 1
                raise AssertionError("Should not initiate LLM completion when global available tokens < 3500")

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_FloorTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=20,
            execution_mode="sharded",
            max_shards=3,
            bootstrap_turns=5,
            shard_turns=5,
        )
        res = inv.run()
        assert shard_step2_calls == 0
        assert res["status"] == "budget_exhausted"
        assert all(s["status"] == "budget_exhausted" for s in res["sharding_summary"]["shards"])
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_dispatcher_close_invoked_across_modes_and_error_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """dispatcher.close() is always invoked in finally: for monolithic, ephemeral, and sharded (including errors)."""
    srv, base_url = _start_multi_family_server()

    # 1. Monolithic normal + unexpected error
    for idx, raise_err in enumerate((False, True)):
        sub = tmp_path / f"mono_{idx}"
        sub.mkdir()
        store = ReceiptStore(sub)
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=ActorManager(),
            allowed_methods=("GET",),
            max_requests=20,
        )
        budget = SharedBudget(http=20, tokens=50_000, seconds=60)
        closed_calls: list[str] = []

        class _MonoTransport:
            calls = 0
            provider_responses: list[dict[str, Any]] = []
            session_gate = SessionGate()

            def complete(self, _body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
                if raise_err:
                    raise RuntimeError("boom")
                return _tool_resp("m1", "finish", {"summary": "done"})

        try:
            inv = AgenticInvestigator(
                http_client=client,
                receipt_store=store,
                transport=_MonoTransport(),  # type: ignore[arg-type]
                budget=budget,
                model="test-model",
                root_dir=sub,
                max_turns=5,
                execution_mode="monolithic",
            )
            inv.dispatcher.close = lambda: closed_calls.append("mono")  # type: ignore[method-assign]
            if raise_err:
                with pytest.raises(RuntimeError, match="boom"):
                    inv.run()
            else:
                res = inv.run()
                assert res["status"] == "finished"
            assert closed_calls == ["mono"]
        finally:
            client.close()

    # 2. Ephemeral normal + error
    for idx, raise_err in enumerate((False, True)):
        sub = tmp_path / f"eph_{idx}"
        sub.mkdir()
        store = ReceiptStore(sub)
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=ActorManager(),
            allowed_methods=("GET",),
            max_requests=20,
        )
        budget = SharedBudget(http=20, tokens=50_000, seconds=60)
        closed_calls = []

        class _EphTransport:
            calls = 0
            provider_responses: list[dict[str, Any]] = []
            session_gate = SessionGate()

            def complete(self, _body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
                if raise_err:
                    raise RuntimeError("eph-boom")
                return _tool_resp("e1", "finish", {"summary": "done"})

        try:
            inv = AgenticInvestigator(
                http_client=client,
                receipt_store=store,
                transport=_EphTransport(),  # type: ignore[arg-type]
                budget=budget,
                model="test-model",
                root_dir=sub,
                max_turns=2,
                execution_mode="ephemeral",
            )
            inv.dispatcher.close = lambda: closed_calls.append("eph")  # type: ignore[method-assign]
            if raise_err:
                with pytest.raises(RuntimeError, match="eph-boom"):
                    inv.run()
            else:
                inv.run()
            assert closed_calls == ["eph"]
        finally:
            client.close()

    # 3. Sharded run where one shard fails with an exception -> all shard dispatchers + root dispatcher closed
    sub = tmp_path / "sharded_close"
    sub.mkdir()
    store = ReceiptStore(sub)
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=ActorManager(),
        allowed_methods=("GET",),
        max_requests=100,
    )
    budget = SharedBudget(http=100, tokens=100_000, seconds=60)
    closed_lock = threading.Lock()
    closed_roots: list[str] = []
    orig_dispatcher_cls = inv_mod.ToolDispatcher

    class _CloseTrackingDispatcher(orig_dispatcher_cls):  # type: ignore[misc]
        def close(self) -> None:
            with closed_lock:
                closed_roots.append(str(self.root_dir))
            orig_close = getattr(super(), "close", None)
            if callable(orig_close):
                orig_close()

    monkeypatch.setattr(inv_mod, "ToolDispatcher", _CloseTrackingDispatcher)

    class _ShardedErrTransport:
        def __init__(self) -> None:
            self.calls = 0
            self.provider_responses: list[dict[str, Any]] = []
            self.session_gate = SessionGate()
            self._boot_step = 0

        def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
            sys_msg = str((body.get("messages") or [{}])[0].get("content") or "")
            if "SUBSYSTEM SHARD SCOPE (" not in sys_msg:
                with closed_lock:
                    self._boot_step += 1
                    step = self._boot_step
                if step == 1:
                    return _tool_resp("b1", "http_request", {"method": "GET", "url": "/", "actor": "anon"})
                if step == 2:
                    return _tool_resp("b2", "extract_surface", {"receipt_id": "req-0001"})
                return _tool_resp("b3", "finish", {"summary": "boot done"})
            if "shard-2" in sys_msg:
                raise RuntimeError("shard-2 unexpected failure")
            return _tool_resp("s-ok", "finish", {"summary": "shard done"})

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_ShardedErrTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=sub,
            max_turns=20,
            execution_mode="sharded",
            max_shards=3,
            bootstrap_turns=5,
            shard_turns=5,
        )
        res = inv.run()
        assert len(res["sharding_summary"]["shards"]) == 3
        shard_statuses = {s["shard_id"]: s["status"] for s in res["sharding_summary"]["shards"]}
        assert shard_statuses["shard-2"] == "error:RuntimeError"
        assert str(sub.resolve()) in closed_roots
        for sid in ("shard-1", "shard-2", "shard-3"):
            assert str((sub / "shards" / sid).resolve()) in closed_roots
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_runner_optional_shard_token_quota_flag(tmp_path: Path) -> None:
    cfg = tmp_path / "llm.json"
    cfg.write_text(
        json.dumps({
            "schema": "cco-llm/1",
            "model": "test/model-1",
            "providers": {
                "test": {
                    "base_url": "https://api.example.test/v1",
                    "models": ["model-1"],
                    "api_key_env": "TEST_KEY_ENV",
                    "api_key_header": "Authorization",
                }
            },
        }),
        encoding="utf-8",
    )
    out_custom = tmp_path / "out_custom"
    rc = agentic_runner.main([
        "--target", "http://127.0.0.1:18899",
        "--provider-config", str(cfg),
        "--output-dir", str(out_custom),
        "--execution-mode", "sharded",
        "--max-shards", "3",
        "--bootstrap-turns", "10",
        "--shard-turns", "20",
        "--shard-token-quota", "45000",
    ])
    assert rc == 0
    plan = json.loads((out_custom / "agentic-plan.json").read_text(encoding="utf-8"))
    assert plan["sharding"] == {
        "max_shards": 3,
        "bootstrap_turns": 10,
        "shard_turns": 20,
        "shard_token_quota": 45000,
    }
