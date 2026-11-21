"""Phase 4 tests: cache-friendly 80K epoch tuning, prompt-cache/reasoning telemetry, and discovery-only bootstrap_model."""
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

import agentic_runner  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import (  # noqa: E402
    _EPOCH_HARD_CHAR_LIMIT,
    _PROMPT_HARD_CHAR_LIMIT,
    AgenticInvestigator,
    account_completion_tokens,
    effective_tokens_from_usage,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import TOOL_SCHEMAS, ToolDispatcher  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import MeteredProviderTransport, SessionGate  # noqa: E402


def _make_deps(
    tmp_path: Path,
    *,
    base_url: str = "http://127.0.0.1:18080/",
    http_limit: int = 80,
    token_limit: int = 600_000,
    allowed_methods: tuple[str, ...] = ("GET", "POST"),
    accounts: list[dict[str, Any]] | None = None,
) -> tuple[ReceiptStore, AgenticHTTPClient, SharedBudget]:
    store = ReceiptStore(tmp_path)
    actors = ActorManager(
        accounts
        if accounts is not None
        else [
            {"alias": "anon", "role": "anonymous", "tenant": "public"},
            {"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-alice"},
        ]
    )
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=http_limit,
    )
    budget = SharedBudget(http=http_limit, tokens=token_limit, seconds=120)
    return store, client, budget


def _tool_http_msg(call_id: str, receipt_id: str, url: str, body_preview: str, turn: int) -> dict[str, Any]:
    payload = {
        "receipt_id": receipt_id,
        "cached": False,
        "actor": "anon",
        "method": "GET",
        "url": url,
        "status": 200,
        "elapsed_ms": 4.0,
        "content_type": "application/json",
        "response_length": len(body_preview),
        "body_preview": body_preview,
    }
    return {
        "role": "tool",
        "tool_call_id": call_id,
        "content": (
            "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
            + json.dumps(payload, ensure_ascii=False)
            + f"\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>\n[STATE] http_budget: 70/80 left | turn: {turn}/50"
        ),
    }


def _tool_resp(
    call_id: str,
    name: str,
    args: dict[str, Any],
    *,
    prompt_tokens: int = 200,
    completion_tokens: int = 40,
    cached_tokens: int | None = None,
    reasoning_tokens: int | None = None,
) -> dict[str, Any]:
    usage: dict[str, Any] = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
    }
    if cached_tokens is not None:
        usage["prompt_tokens_details"] = {"cached_tokens": cached_tokens}
    if reasoning_tokens is not None:
        usage["completion_tokens_details"] = {"reasoning_tokens": reasoning_tokens}
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
        "usage": usage,
    }


def _multi_resp(
    calls: list[tuple[str, str, dict[str, Any]]],
    *,
    prompt_tokens: int = 200,
    completion_tokens: int = 40,
    cached_tokens: int = 0,
    reasoning_tokens: int = 0,
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
            "prompt_tokens_details": {"cached_tokens": cached_tokens},
            "completion_tokens_details": {"reasoning_tokens": reasoning_tokens},
        },
    }


class _ScriptedTransport:
    def __init__(self, handler: Any) -> None:
        self.calls = 0
        self.provider_responses: list[dict[str, Any]] = []
        self.session_gate = SessionGate()
        self.seen_bodies: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._handler = handler

    def complete(self, body: dict[str, Any], *, minimum_output_tokens: int = 16) -> dict[str, Any]:  # noqa: ARG002
        with self._lock:
            self.calls += 1
            call_idx = self.calls
            self.seen_bodies.append(json.loads(json.dumps(body)))
            self.provider_responses.append({"call": call_idx, "upstream_http_status": 200})
        return self._handler(call_idx, body)


# ---------------------------------------------------------------------------
# 1. Default 80,000 epoch limit, advancement > 80 KB, and custom limit clamping
# ---------------------------------------------------------------------------


def test_default_80k_epoch_limit_and_custom_clamping(tmp_path: Path) -> None:
    assert _EPOCH_HARD_CHAR_LIMIT == 80_000
    store, client, budget = _make_deps(tmp_path, token_limit=600_000)
    try:
        transport = _ScriptedTransport(lambda _i, _b: {})
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=50,
        )
        assert inv.epoch_char_limit == 80_000

        # Clamping checks: <= 0 defaults to 80_000; < _PROMPT_HARD_CHAR_LIMIT clamps up.
        inv_zero = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path / "z",
            epoch_char_limit=0,
        )
        assert inv_zero.epoch_char_limit == 80_000
        inv_small = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path / "s",
            epoch_char_limit=10_000,
        )
        assert inv_small.epoch_char_limit == _PROMPT_HARD_CHAR_LIMIT

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "S" * 1000},
            {"role": "user", "content": "Investigate target.\n[STATE] http_budget: 80/80 left | turn: 1/50"},
        ]

        # 12 turns of ~3.5 KB stay in Epoch 1 with byte-identical prefix and epoch_advancements == 0.
        epoch1_bodies: list[dict[str, Any]] = []
        for turn in range(1, 13):
            messages.append({
                "role": "assistant",
                "content": f"Turn {turn} analysis.",
                "tool_calls": [{
                    "id": f"c_{turn}",
                    "type": "function",
                    "function": {"name": "http_request", "arguments": json.dumps({"url": f"/api/r/{turn}"})},
                }],
            })
            messages.append(
                _tool_http_msg(f"c_{turn}", f"req-{turn:04d}", f"http://127.0.0.1:18080/api/r/{turn}", "A" * 3100, turn + 1)
            )
            body = inv._prepare_bounded_body(messages)
            epoch1_bodies.append(body)
        assert inv._epoch_advancements == 0
        assert inv._epoch_turn_start == 0
        for idx in range(len(epoch1_bodies) - 1):
            assert epoch1_bodies[idx]["tools"] == epoch1_bodies[idx + 1]["tools"]
            assert epoch1_bodies[idx]["messages"] == epoch1_bodies[idx + 1]["messages"][:len(epoch1_bodies[idx]["messages"])]

        # Push total serialized bytes past 80,000 (~12 more turns of ~4.2 KB) -> advances cleanly.
        for turn in range(13, 25):
            messages.append({
                "role": "assistant",
                "content": f"Turn {turn} analysis.",
                "tool_calls": [{
                    "id": f"c_{turn}",
                    "type": "function",
                    "function": {"name": "http_request", "arguments": json.dumps({"url": f"/api/r/{turn}"})},
                }],
            })
            messages.append(
                _tool_http_msg(f"c_{turn}", f"req-{turn:04d}", f"http://127.0.0.1:18080/api/r/{turn}", "B" * 3800, turn + 1)
            )
            body = inv._prepare_bounded_body(messages)
            wire_bytes = len(
                json.dumps({"messages": body["messages"], "tools": body["tools"]}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            )
            assert wire_bytes <= 80_000
        assert inv._epoch_advancements >= 1
        assert inv._epoch_turn_start > 0

        # Custom epoch_char_limit=30_000 on an explicit epoch_state advances earlier and tracks epoch_state["advancements"].
        inv_custom = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path / "c",
            epoch_char_limit=30_000,
        )
        assert inv_custom.epoch_char_limit == 30_000
        ep_state: dict[str, Any] = {"turn_start": 0, "summary_text": "", "advancements": 0}
        _ = inv_custom._prepare_bounded_body(messages[: 2 + 24], epoch_state=ep_state)
        assert ep_state["advancements"] == 1
        assert inv_custom._epoch_advancements == 1
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 2. Prompt-cache & reasoning token telemetry
# ---------------------------------------------------------------------------


def test_account_completion_tokens_and_run_cache_telemetry(tmp_path: Path) -> None:
    req_body = {"messages": [{"role": "user", "content": "X" * 400}], "tools": []}

    # Standard usage with prompt_tokens_details + completion_tokens_details
    u1 = account_completion_tokens(
        {
            "usage": {
                "prompt_tokens": 1000,
                "completion_tokens": 200,
                "total_tokens": 1200,
                "prompt_tokens_details": {"cached_tokens": 750},
                "completion_tokens_details": {"reasoning_tokens": 120},
            }
        },
        req_body,
    )
    assert u1 == {
        "prompt_tokens": 1000,
        "completion_tokens": 200,
        "total_tokens": 1200,
        "cached_prompt_tokens": 750,
        "uncached_prompt_tokens": 250,
        "reasoning_tokens": 120,
        "source": "provider_usage",
    }

    # Null/missing detail dicts and out-of-range/bool values fall back cleanly to 0
    u_null = account_completion_tokens(
        {
            "usage": {
                "prompt_tokens": 500,
                "completion_tokens": 80,
                "prompt_tokens_details": None,
                "completion_tokens_details": None,
            }
        },
        req_body,
    )
    assert u_null["cached_prompt_tokens"] == 0
    assert u_null["uncached_prompt_tokens"] == 500
    assert u_null["reasoning_tokens"] == 0

    u_invalid = account_completion_tokens(
        {
            "usage": {
                "prompt_tokens": 300,
                "completion_tokens": 40,
                "prompt_tokens_details": {"cached_tokens": 999},
                "completion_tokens_details": {"reasoning_tokens": True},
            }
        },
        req_body,
    )
    assert u_invalid["cached_prompt_tokens"] == 0
    assert u_invalid["uncached_prompt_tokens"] == 300
    assert u_invalid["reasoning_tokens"] == 0

    # Char estimate fallback
    u_est = account_completion_tokens({"choices": [{"message": {"content": "ok"}}]}, req_body)
    assert u_est["source"] == "char_estimate_4x"
    assert u_est["cached_prompt_tokens"] == 0
    assert u_est["uncached_prompt_tokens"] == u_est["prompt_tokens"]
    assert u_est["reasoning_tokens"] == 0

    # Full investigator run accumulates cache & reasoning tokens and computes cache_hit_rate
    store, client, budget = _make_deps(tmp_path)
    try:
        responses = [
            _tool_resp(
                "c1",
                "notebook",
                {"action": "write", "surface_notes": "checked /"},
                prompt_tokens=1000,
                completion_tokens=100,
                cached_tokens=400,
                reasoning_tokens=30,
            ),
            _tool_resp(
                "c2",
                "finish",
                {"summary": "done", "untested_areas": []},
                prompt_tokens=1500,
                completion_tokens=120,
                cached_tokens=1100,
                reasoning_tokens=50,
            ),
        ]
        transport = _ScriptedTransport(lambda idx, _b: responses[idx - 1])
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=6,
            sleep_fn=lambda _s: None,
        )
        res = inv.run()
        assert res["status"] == "finished"
        assert res["epoch_advancements"] == 0
        tu = res["token_usage"]
        assert tu["prompt_tokens"] == 2500
        assert tu["completion_tokens"] == 220
        assert tu["cached_prompt_tokens"] == 1500
        assert tu["uncached_prompt_tokens"] == 1000
        assert tu["reasoning_tokens"] == 80
        assert tu["cache_hit_rate"] == 0.6
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 3. Runner plan validation & CLI flags for bootstrap_model / epoch_char_limit
# ---------------------------------------------------------------------------


def test_runner_bootstrap_model_and_epoch_char_limit_plan(tmp_path: Path) -> None:
    cfg = tmp_path / "llm.json"
    cfg.write_text(
        json.dumps({
            "schema": "cco-llm/1",
            "model": "gw/strong-model",
            "providers": {
                "gw": {
                    "base_url": "https://gateway.example.invalid/v1",
                    "models": ["strong-model", "fast-boot"],
                    "api_key_env": "GW_KEY",
                    "api_key_header": "Authorization",
                },
                "other": {
                    "base_url": "https://other.example.invalid/v1",
                    "models": ["other-boot"],
                    "api_key_env": "OTHER_KEY",
                    "api_key_header": "Authorization",
                },
            },
        }),
        encoding="utf-8",
    )

    out_ok = tmp_path / "plan-ok"
    rc = agentic_runner.main([
        "--target", "http://127.0.0.1:18899",
        "--provider-config", str(cfg),
        "--output-dir", str(out_ok),
        "--execution-mode", "sharded",
        "--bootstrap-model", "gw/fast-boot",
        "--epoch-char-limit", "64000",
    ])
    assert rc == 0
    plan = json.loads((out_ok / "agentic-plan.json").read_text(encoding="utf-8"))
    assert plan["models"]["bootstrap"] == "gw/fast-boot"
    assert plan["sharding"]["bootstrap_model"] == "gw/fast-boot"
    assert plan["limits"]["epoch_char_limit"] == 64_000

    # Default epoch_char_limit=0 resolves to 80_000 in plan limits
    _, plan_def = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18899",
        provider_config=cfg,
        output_dir=tmp_path / "plan-def",
        execution_mode="sharded",
        execute=False,
    )
    assert plan_def["limits"]["epoch_char_limit"] == 80_000
    assert "bootstrap" not in plan_def["models"]
    assert "bootstrap_model" not in plan_def["sharding"]

    # Cross-provider bootstrap_model must fail validation
    with pytest.raises(ValueError, match="one provider"):
        agentic_runner.run_agentic_target(
            target="http://127.0.0.1:18899",
            provider_config=cfg,
            output_dir=tmp_path / "plan-bad",
            execution_mode="sharded",
            bootstrap_model="other/other-boot",
            execute=False,
        )


# ---------------------------------------------------------------------------
# 4. Sharded discovery-only bootstrap_model & Stage 2 transition
# ---------------------------------------------------------------------------


def _start_multi_family_target() -> tuple[ThreadingHTTPServer, str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            if urlsplit(self.path).path == "/api/v1/auth/login":
                body = json.dumps({"token": "dyn-member-tok", "user": "dyn1"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/":
                html = (
                    "<html><body>"
                    "<a href='/orders'>Orders</a><a href='/orders/101'>O101</a>"
                    "<a href='/invoices'>Invoices</a><a href='/invoices/202'>I202</a>"
                    "<a href='/tickets'>Tickets</a><a href='/tickets/303'>T303</a>"
                    "<a href='/api/v1/orders'>AO</a><a href='/api/v1/orders/101'>AO101</a>"
                    "<a href='/api/v1/invoices'>AI</a><a href='/api/v1/invoices/202'>AI202</a>"
                    "<a href='/api/v1/tickets'>AT</a><a href='/api/v1/tickets/303'>AT303</a>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            mapping = {
                "/api/v1/orders/101": {"order_id": 101, "secret": "ORD_SECRET_111"},
                "/api/v1/invoices/202": {"invoice_id": 202, "secret": "INV_SECRET_222"},
                "/api/v1/tickets/303": {"ticket_id": 303, "secret": "TKT_SECRET_333"},
            }
            if path in mapping:
                if path == "/api/v1/orders/101" and self.headers.get("Authorization") != "Bearer dyn-member-tok":
                    self.send_response(401)
                    self.end_headers()
                    return
                body = json.dumps(mapping[path]).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_sharded_discovery_only_bootstrap_model_and_stage2_handoff(tmp_path: Path) -> None:
    srv, base_url = _start_multi_family_target()
    store, client, budget = _make_deps(
        tmp_path,
        base_url=base_url,
        http_limit=100,
        token_limit=400_000,
        accounts=[{"alias": "anon", "role": "anonymous", "tenant": "public"}],
    )
    lock = threading.Lock()
    boot_steps = [0]
    shard_steps: dict[str, int] = {}
    boot_tool_names: list[list[str]] = []
    shard_tool_names: list[list[str]] = []
    boot_models_seen: list[str] = []
    shard_models_seen: list[str] = []
    blocked_record_finding_reply: list[str] = []

    def _handler(_call_idx: int, body: dict[str, Any]) -> dict[str, Any]:
        msgs = body.get("messages") or []
        sys_msg = str((msgs[0] if msgs else {}).get("content") or "")
        tools = [str((t.get("function") or {}).get("name") or "") for t in (body.get("tools") or [])]

        if "SUBSYSTEM SHARD SCOPE (" not in sys_msg:
            with lock:
                boot_steps[0] += 1
                step = boot_steps[0]
                boot_tool_names.append(tools)
                boot_models_seen.append(str(body.get("model") or ""))
            if step == 1:
                return _multi_resp(
                    [
                        ("b1", "http_request", {"method": "GET", "url": "/", "actor": "anon"}),
                        (
                            "b2",
                            "http_request",
                            {
                                "method": "POST",
                                "url": "/api/v1/auth/login",
                                "actor": "anon",
                                "json_body": {"user": "dyn1"},
                                "save_session_as": "dyn-user",
                            },
                        ),
                    ],
                    prompt_tokens=400,
                    completion_tokens=60,
                    cached_tokens=100,
                    reasoning_tokens=10,
                )
            if step == 2:
                # Extract surface AND attempt an illegal record_finding during discovery-only bootstrap
                return _multi_resp(
                    [
                        ("b3", "extract_surface", {"receipt_id": "req-0001"}),
                        (
                            "b4",
                            "record_finding",
                            {
                                "class_type": "auth_bypass",
                                "proof_receipt_id": "req-0001",
                                "control_receipt_id": "req-0002",
                                "evidence_value": "Orders",
                                "summary": "should be blocked",
                            },
                        ),
                    ],
                    prompt_tokens=500,
                    completion_tokens=50,
                    cached_tokens=350,
                    reasoning_tokens=15,
                )
            # Capture the tool response for b4 from messages
            for m in msgs:
                if m.get("role") == "tool" and m.get("tool_call_id") == "b4":
                    blocked_record_finding_reply.append(str(m.get("content") or ""))
            return _tool_resp(
                "b5",
                "finish",
                {"summary": "discovery solid"},
                prompt_tokens=600,
                completion_tokens=30,
                cached_tokens=450,
                reasoning_tokens=5,
            )

        marker = "SUBSYSTEM SHARD SCOPE ("
        shard_id = sys_msg[sys_msg.index(marker) + len(marker):].split(":", 1)[0].strip()
        with lock:
            step = shard_steps.get(shard_id, 0) + 1
            shard_steps[shard_id] = step
            shard_tool_names.append(tools)
            shard_models_seen.append(str(body.get("model") or ""))

        routes_text = sys_msg.split("Assigned routes:", 1)[1]
        if "orders" in routes_text:
            path, secret, actor = "/api/v1/orders/101", "ORD_SECRET_111", "dyn-user"
        elif "invoices" in routes_text:
            path, secret, actor = "/api/v1/invoices/202", "INV_SECRET_222", "anon"
        else:
            path, secret, actor = "/api/v1/tickets/303", "TKT_SECRET_333", "anon"

        if step == 1:
            return _tool_resp(
                f"s_{shard_id}_1",
                "http_request",
                {"method": "GET", "url": path, "actor": actor},
                prompt_tokens=300,
                completion_tokens=30,
                cached_tokens=120,
                reasoning_tokens=8,
            )
        if step == 2:
            if actor == "anon":
                # Authenticated baseline control on the same path using Stage 1's dyn-user session
                return _tool_resp(
                    f"s_{shard_id}_2",
                    "http_request",
                    {"method": "GET", "url": path, "actor": "dyn-user"},
                    prompt_tokens=350,
                    completion_tokens=30,
                    cached_tokens=200,
                    reasoning_tokens=12,
                )
            return _tool_resp(
                f"s_{shard_id}_2",
                "finish",
                {"summary": f"{shard_id} verified dynamic session"},
                prompt_tokens=350,
                completion_tokens=20,
                cached_tokens=200,
                reasoning_tokens=4,
            )
        if step == 3 and actor == "anon":
            tool_rids: list[str] = []
            for m in msgs:
                if m.get("role") == "tool" and "<<<UNTRUSTED_TARGET_RESPONSE>>>" in str(m.get("content") or ""):
                    raw_block = str(m["content"]).split("<<<UNTRUSTED_TARGET_RESPONSE>>>", 1)[1].split(
                        "<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1
                    )[0]
                    tool_rids.append(json.loads(raw_block)["receipt_id"])
            if len(tool_rids) >= 2:
                return _tool_resp(
                    f"s_{shard_id}_3",
                    "record_finding",
                    {
                        "class_type": "auth_bypass",
                        "title": f"Auth bypass on {path}",
                        "method": "GET",
                        "url": path,
                        "actor": "anon",
                        "severity": "high",
                        "proof_receipt_ids": [tool_rids[-2]],
                        "control_receipt_ids": [tool_rids[-1]],
                        "evidence_value": secret,
                        "excerpt": secret,
                        "summary": f"{path} exposed to anon",
                    },
                    prompt_tokens=400,
                    completion_tokens=30,
                    cached_tokens=250,
                    reasoning_tokens=10,
                )
        return _tool_resp(
            f"s_{shard_id}_end",
            "finish",
            {"summary": f"{shard_id} done"},
            prompt_tokens=400,
            completion_tokens=20,
            cached_tokens=250,
            reasoning_tokens=5,
        )

    transport = _ScriptedTransport(_handler)
    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="strong-shard-model",
            bootstrap_model="fast-boot-model",
            root_dir=tmp_path,
            max_turns=30,
            execution_mode="sharded",
            max_shards=3,
            bootstrap_turns=6,
            shard_turns=6,
            sleep_fn=lambda _s: None,
        )
        res = inv.run()
        assert res["status"] == "finished"
        assert boot_models_seen and all(m == "fast-boot-model" for m in boot_models_seen)
        assert shard_models_seen and all(m == "strong-shard-model" for m in shard_models_seen)

        # record_finding excluded from Stage 1 tools and blocked if invoked; included in Stage 2
        assert all("record_finding" not in tools for tools in boot_tool_names)
        assert all("record_finding" in tools for tools in shard_tool_names)
        assert blocked_record_finding_reply
        assert "tool_disabled_in_bootstrap_discovery" in blocked_record_finding_reply[0]

        # Dynamic session registered in Stage 1 worked in Stage 2 (GET /api/v1/orders/101 returned 200 for dyn-user)
        assert any(
            store.get(rid).get("url", "").endswith("/api/v1/orders/101")
            and store.get(rid).get("actor") == "dyn-user"
            and store.get(rid).get("status") == 200
            for rid in store.list_ids()
        )

        ss = res["sharding_summary"]
        assert ss["bootstrap_model"] == "fast-boot-model"
        assert ss["shard_model"] == "strong-shard-model"
        assert ss["bootstrap_discovery_only"] is True
        assert ss["bootstrap_findings"] == 0
        assert ss["bootstrap_cached_tokens"] == 900
        assert ss["bootstrap_uncached_tokens"] == 600
        assert ss["bootstrap_reasoning_tokens"] == 30
        assert ss["bootstrap_epoch_advancements"] == 0
        assert len(ss["shards"]) == 3
        for shard_entry in ss["shards"]:
            assert shard_entry["cached_tokens"] > 0
            assert shard_entry["uncached_tokens"] > 0
            assert shard_entry["reasoning_tokens"] > 0
            assert shard_entry["epoch_advancements"] == 0

        assert res["findings_count"] >= 2
        assert res["token_usage"]["cache_hit_rate"] > 0.0
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 5. Single-cluster fallback from discovery-only bootstrap_model -> strong model
# ---------------------------------------------------------------------------


def _start_single_cluster_target() -> tuple[ThreadingHTTPServer, str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/":
                html = b"<html><body><a href='/items/1'>Item 1</a></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            if path == "/items/1":
                body = json.dumps({"id": 1, "secret": "SINGLE_CLUSTER_SECRET"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_single_cluster_fallback_from_bootstrap_model_uses_clean_strong_model(tmp_path: Path) -> None:
    srv, base_url = _start_single_cluster_target()
    store, client, budget = _make_deps(tmp_path, base_url=base_url, http_limit=40, token_limit=300_000)
    call_records: list[dict[str, Any]] = []

    def _handler(call_idx: int, body: dict[str, Any]) -> dict[str, Any]:
        tools = [str((t.get("function") or {}).get("name") or "") for t in (body.get("tools") or [])]
        call_records.append({
            "call": call_idx,
            "model": body.get("model"),
            "tools": tools,
            "messages": body.get("messages") or [],
        })
        if call_idx == 1:
            return _tool_resp("b1", "http_request", {"method": "GET", "url": "/", "actor": "anon"})
        if call_idx == 2:
            # Discovery-only bootstrap calls finish early on small single-cluster surface
            return _tool_resp("b2", "finish", {"summary": "single-cluster discovery done"})
        if call_idx == 3:
            # Monolithic continuation with strong model
            return _multi_resp([
                ("m1", "http_request", {"method": "GET", "url": "/items/1", "actor": "anon"}),
                ("m2", "http_request", {"method": "GET", "url": "/items/1", "actor": "alice"}),
            ])
        if call_idx == 4:
            return _tool_resp(
                "m3",
                "record_finding",
                {
                    "class_type": "auth_bypass",
                    "title": "Auth bypass on /items/1",
                    "method": "GET",
                    "url": "/items/1",
                    "actor": "anon",
                    "severity": "high",
                    "proof_receipt_ids": ["req-0002"],
                    "control_receipt_ids": ["req-0003"],
                    "evidence_value": "SINGLE_CLUSTER_SECRET",
                    "excerpt": "SINGLE_CLUSTER_SECRET",
                    "summary": "/items/1 accessible to anon",
                },
            )
        return _tool_resp("m4", "finish", {"summary": "monolithic fallback verified"})

    transport = _ScriptedTransport(_handler)
    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="strong-model",
            bootstrap_model="fast-boot",
            root_dir=tmp_path,
            max_turns=12,
            execution_mode="sharded",
            max_shards=3,
            bootstrap_turns=4,
            shard_turns=5,
            sleep_fn=lambda _s: None,
        )
        res = inv.run()
        assert res["status"] == "finished"
        assert res["findings_count"] == 1
        ss = res["sharding_summary"]
        assert ss["fallback_to_monolithic"] is True
        assert ss["fallback_reason"] == "single_cluster"
        assert ss["bootstrap_model"] == "fast-boot"
        assert ss["shard_model"] == "strong-model"
        assert ss["bootstrap_discovery_only"] is True

        # Calls 1..2 used fast-boot without record_finding; calls 3..5 used strong-model with record_finding
        assert call_records[0]["model"] == "fast-boot"
        assert call_records[1]["model"] == "fast-boot"
        assert "record_finding" not in call_records[0]["tools"]
        assert call_records[2]["model"] == "strong-model"
        assert "record_finding" in call_records[2]["tools"]

        # Clean initial 2-message list seeded with [LIVE ACTORS] and [SURFACE FRONTIER], NOT raw bootstrap history
        cont_msgs = call_records[2]["messages"]
        assert len(cont_msgs) == 2
        assert "[LIVE ACTORS]" in cont_msgs[1]["content"]
        assert "[SURFACE FRONTIER]" in cont_msgs[1]["content"]
        assert "single-cluster discovery done" not in cont_msgs[1]["content"]
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_runner_execute_auto_emits_reports_and_survives_report_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_agentic_target(execute=True) emits report.md/report.sarif and tolerates report errors."""
    srv, target_url = _start_single_cluster_target()

    class _ProviderHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            resp = _tool_resp(
                "r1",
                "finish",
                {"summary": "quick execute done", "untested_areas": []},
                prompt_tokens=100,
                completion_tokens=20,
                cached_tokens=50,
            )
            payload = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    prov_srv = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    threading.Thread(target=prov_srv.serve_forever, daemon=True).start()
    cfg = tmp_path / "llm.json"
    cfg.write_text(
        json.dumps({
            "schema": "cco-llm/1",
            "model": "local/test-model",
            "providers": {
                "local": {
                    "base_url": f"http://127.0.0.1:{prov_srv.server_address[1]}/v1",
                    "models": ["test-model"],
                    "api_key_env": "TEST_LOCAL_KEY",
                    "api_key_header": "Authorization",
                }
            },
        }),
        encoding="utf-8",
    )
    creds = tmp_path / "creds.json"
    creds.write_text(
        json.dumps({
            "target_url": target_url,
            "test_accounts": [{"alias": "anon", "role": "anonymous", "tenant": "public"}],
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("TEST_LOCAL_KEY", "dummy-local-key")

    try:
        out_ok = tmp_path / "run-ok"
        manifest_path, manifest = agentic_runner.run_agentic_target(
            credentials_file=creds,
            provider_config=cfg,
            output_dir=out_ok,
            execute=True,
            max_turns=3,
        )
        assert manifest["status"] == "finished"
        assert Path(manifest["report_md"]).is_file()
        assert Path(manifest["report_sarif"]).is_file()
        assert "report_error" not in manifest
        persisted = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert persisted["report_md"] == manifest["report_md"]
        assert persisted["report_sarif"] == manifest["report_sarif"]

        # Guarded error handling: report generation crash must not fail completed run
        def _boom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("report failure")

        monkeypatch.setattr(agentic_runner.agentic_report, "generate_run_reports", _boom)
        out_err = tmp_path / "run-err"
        manifest_path_err, manifest_err = agentic_runner.run_agentic_target(
            credentials_file=creds,
            provider_config=cfg,
            output_dir=out_err,
            execute=True,
            max_turns=3,
        )
        assert manifest_err["status"] == "finished"
        assert manifest_err["report_error"] == "RuntimeError"
        assert json.loads(manifest_path_err.read_text(encoding="utf-8"))["report_error"] == "RuntimeError"
    finally:
        prov_srv.shutdown()
        prov_srv.server_close()
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 6. Cache-discounted effective token accounting (transport, shards, runner)
# ---------------------------------------------------------------------------


def test_metered_provider_transport_cache_token_weight(tmp_path: Path) -> None:
    priv_dir = tmp_path / "private"
    priv_dir.mkdir(parents=True, exist_ok=True)
    budget_dummy = SharedBudget(http=10, tokens=20_000, seconds=60)

    for bad_weight in (-0.1, 1.01, float("nan"), True):
        with pytest.raises(ValueError, match="cache_token_weight"):
            MeteredProviderTransport(
                budget=budget_dummy,
                private=priv_dir,
                provider="http://127.0.0.1:1/v1",
                models={"test-model"},
                api_key="dummy-key",
                cache_token_weight=bad_weight,  # type: ignore[arg-type]
            )

    queued_usages: list[dict[str, Any]] = [
        {
            "prompt_tokens": 1000,
            "completion_tokens": 200,
            "total_tokens": 1200,
            "prompt_tokens_details": {"cached_tokens": 800},
        },
        {
            "prompt_tokens": 1000,
            "completion_tokens": 200,
            "total_tokens": 1200,
            "prompt_tokens_details": {"cached_tokens": 0},
        },
        {
            "prompt_tokens": 1000,
            "completion_tokens": 200,
            "total_tokens": 1200,
            "prompt_tokens_details": {"cached_tokens": 800},
        },
    ]

    class _MockProviderHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            usage = queued_usages.pop(0)
            payload = json.dumps({
                "id": "cmpl-cache-test",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": usage,
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockProviderHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    prov_url = f"http://127.0.0.1:{srv.server_address[1]}/v1"
    req_body = {
        "model": "test-model",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 500,
    }

    try:
        # Weight 0.10: call 1 has 800/1000 cached -> 200 + 80 + 200 = 480; call 2 cache miss -> 1200
        b_weighted = SharedBudget(http=10, tokens=20_000, seconds=60)
        t_weighted = MeteredProviderTransport(
            budget=b_weighted,
            private=tmp_path / "priv-w",
            provider=prov_url,
            models={"test-model"},
            api_key="dummy-key",
            cache_token_weight=0.10,
        )
        (tmp_path / "priv-w").mkdir(parents=True, exist_ok=True)
        t_weighted.complete(req_body)
        assert b_weighted.used["tokens"] == 480
        ev1 = b_weighted.events[-1]
        assert ev1["charged"] == 480
        assert ev1["raw_tokens"] == 1200
        assert ev1["cache_token_weight"] == 0.10

        t_weighted.complete(req_body)
        assert b_weighted.used["tokens"] == 480 + 1200
        ev2 = b_weighted.events[-1]
        assert ev2["charged"] == 1200
        assert ev2["raw_tokens"] == 1200

        # Default weight 1.0: charges full raw 1200 even with 800 cached tokens
        b_default = SharedBudget(http=10, tokens=20_000, seconds=60)
        t_default = MeteredProviderTransport(
            budget=b_default,
            private=tmp_path / "priv-d",
            provider=prov_url,
            models={"test-model"},
            api_key="dummy-key",
        )
        (tmp_path / "priv-d").mkdir(parents=True, exist_ok=True)
        assert t_default.cache_token_weight == 1.0
        t_default.complete(req_body)
        assert b_default.used["tokens"] == 1200
        ev3 = b_default.events[-1]
        assert ev3["charged"] == 1200
        assert ev3["raw_tokens"] == 1200
        assert ev3["cache_token_weight"] == 1.0
    finally:
        srv.shutdown()
        srv.server_close()


def test_sharded_cache_discounted_effective_quota_and_fail_closed_zero_cache(tmp_path: Path) -> None:
    srv, base_url = _start_multi_family_target()
    store, client, budget = _make_deps(
        tmp_path,
        base_url=base_url,
        http_limit=100,
        token_limit=500_000,
        accounts=[{"alias": "anon", "role": "anonymous", "tenant": "public"}],
    )
    lock = threading.Lock()
    boot_steps = [0]
    shard_steps: dict[str, int] = {}

    def _handler(_call_idx: int, body: dict[str, Any]) -> dict[str, Any]:
        msgs = body.get("messages") or []
        sys_msg = str((msgs[0] if msgs else {}).get("content") or "")

        if "SUBSYSTEM SHARD SCOPE (" not in sys_msg:
            with lock:
                boot_steps[0] += 1
                step = boot_steps[0]
            if step == 1:
                return _tool_resp(
                    "b1",
                    "http_request",
                    {"method": "GET", "url": "/", "actor": "anon"},
                    prompt_tokens=1000,
                    completion_tokens=100,
                    cached_tokens=500,
                )
            if step == 2:
                return _tool_resp(
                    "b2",
                    "extract_surface",
                    {"receipt_id": "req-0001"},
                    prompt_tokens=1000,
                    completion_tokens=100,
                    cached_tokens=800,
                )
            return _tool_resp(
                "b3",
                "finish",
                {"summary": "bootstrap complete"},
                prompt_tokens=1000,
                completion_tokens=100,
                cached_tokens=800,
            )

        marker = "SUBSYSTEM SHARD SCOPE ("
        shard_id = sys_msg[sys_msg.index(marker) + len(marker):].split(":", 1)[0].strip()
        with lock:
            step = shard_steps.get(shard_id, 0) + 1
            shard_steps[shard_id] = step

        routes_text = sys_msg.split("Assigned routes:", 1)[1]
        if "orders" in routes_text:
            # High-cache shard: 10_000 prompt (8_500 cached) + 500 completion = 10_500 raw, 2_850 effective/turn
            if step <= 7:
                return _tool_resp(
                    f"o_{step}",
                    "notebook",
                    {"action": "write", "notes": f"turn {step}"},
                    prompt_tokens=10_000,
                    completion_tokens=500,
                    cached_tokens=8_500,
                )
            return _tool_resp(
                f"o_{step}",
                "finish",
                {"summary": "orders deep scan finished"},
                prompt_tokens=10_000,
                completion_tokens=500,
                cached_tokens=8_500,
            )

        if "invoices" in routes_text:
            # Zero-cache shard: 10_000 prompt (0 cached) + 500 completion = 10_500 raw & effective/turn
            return _tool_resp(
                f"i_{step}",
                "notebook",
                {"action": "write", "notes": f"inv turn {step}"},
                prompt_tokens=10_000,
                completion_tokens=500,
                cached_tokens=0,
            )

        # Tickets shard finishes immediately
        return _tool_resp(
            f"t_{step}",
            "finish",
            {"summary": "tickets finished"},
            prompt_tokens=1000,
            completion_tokens=100,
            cached_tokens=500,
        )

    transport = _ScriptedTransport(_handler)
    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=30,
            execution_mode="sharded",
            max_shards=3,
            bootstrap_turns=6,
            shard_turns=12,
            shard_token_quota=50_000,
            cache_token_weight=0.10,
            sleep_fn=lambda _s: None,
        )
        res = inv.run()
        assert res["status"] == "finished"

        tu = res["token_usage"]
        assert tu["cache_token_weight"] == 0.10
        assert tu["effective_tokens"] == effective_tokens_from_usage(tu, 0.10)

        ss = res["sharding_summary"]
        assert ss["cache_token_weight"] == 0.10
        # Bootstrap: 3 turns * (200+500+100=800 + 800*0.10...): (3000 - 2100) + round(2100*0.1) + 300 = 1410
        assert ss["bootstrap_tokens"] == 3300
        assert ss["bootstrap_effective_tokens"] == 1410

        by_family = {s["families"][0]: s for s in ss["shards"]}
        orders = by_family["orders"]
        assert orders["status"] == "finished"
        assert orders["calls"] == 8
        assert orders["tokens"] == 84_000  # > 50_000 raw quota, yet finished cleanly!
        assert orders["effective_tokens"] == 22_800  # 8 * 2_850 < 50_000

        invoices = by_family["invoices"]
        assert invoices["status"] == "budget_exhausted"
        assert invoices["calls"] == 5  # 5 * 10_500 = 52_500 >= 50_000 triggers stop before turn 6
        assert invoices["tokens"] == 52_500
        assert invoices["effective_tokens"] == 52_500
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_runner_cache_token_weight_plan_and_validation(tmp_path: Path) -> None:
    cfg = tmp_path / "llm.json"
    cfg.write_text(
        json.dumps({
            "schema": "cco-llm/1",
            "model": "gw/strong-model",
            "providers": {
                "gw": {
                    "base_url": "https://gateway.example.invalid/v1",
                    "models": ["strong-model"],
                    "api_key_env": "GW_KEY",
                    "api_key_header": "Authorization",
                }
            },
        }),
        encoding="utf-8",
    )

    _, plan_custom = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18899",
        provider_config=cfg,
        output_dir=tmp_path / "plan-custom",
        execute=False,
        cache_token_weight=0.25,
    )
    assert plan_custom["limits"]["cache_token_weight"] == 0.25

    _, plan_default = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18899",
        provider_config=cfg,
        output_dir=tmp_path / "plan-default",
        execute=False,
    )
    assert plan_default["limits"]["cache_token_weight"] == 0.10

    for bad in (-0.01, 1.5, True):
        with pytest.raises(ValueError, match="cache_token_weight"):
            agentic_runner.run_agentic_target(
                target="http://127.0.0.1:18899",
                provider_config=cfg,
                output_dir=tmp_path / "plan-bad",
                execute=False,
                cache_token_weight=bad,  # type: ignore[arg-type]
            )

    out_cli = tmp_path / "plan-cli"
    rc = agentic_runner.main([
        "--target", "http://127.0.0.1:18899",
        "--provider-config", str(cfg),
        "--output-dir", str(out_cli),
        "--cache-token-weight", "0.25",
    ])
    assert rc == 0
    cli_plan = json.loads((out_cli / "agentic-plan.json").read_text(encoding="utf-8"))
    assert cli_plan["limits"]["cache_token_weight"] == 0.25

    with pytest.raises(SystemExit):
        agentic_runner.main([
            "--target", "http://127.0.0.1:18899",
            "--provider-config", str(cfg),
            "--output-dir", str(tmp_path / "plan-cli-bad"),
            "--cache-token-weight", "1.5",
        ])


# ---------------------------------------------------------------------------
# 7. http_request method inference, stringified body parsing & discovery gate
# ---------------------------------------------------------------------------


def _parse_tool_preview(raw_output: str) -> dict[str, Any]:
    inner = raw_output.split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1].rsplit(
        "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1
    )[0]
    return json.loads(inner)


def test_http_request_method_inference_body_normalization_and_warning(tmp_path: Path) -> None:
    http_schema = next(t["function"] for t in TOOL_SCHEMAS if t["function"]["name"] == "http_request")
    assert http_schema["parameters"]["required"] == ["url"]
    method_desc = http_schema["parameters"]["properties"]["method"]["description"]
    assert len(method_desc) <= 140
    assert "POST if body" in method_desc

    seen_requests: list[dict[str, Any]] = []

    class _EchoHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def _handle(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
            seen_requests.append({
                "method": method,
                "path": urlsplit(self.path).path,
                "content_type": self.headers.get("Content-Type", ""),
                "body": raw_body,
            })
            payload = json.dumps({"method": method, "body": raw_body}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base_url = f"http://127.0.0.1:{srv.server_address[1]}/"
    store, client, _ = _make_deps(
        tmp_path,
        base_url=base_url,
        http_limit=20,
        accounts=[{"alias": "anon", "role": "anonymous", "tenant": "public"}],
    )
    disp = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path)
    try:
        # 1. Omitting method with no body defaults to GET and has no method_warning.
        p_get = _parse_tool_preview(disp.dispatch("http_request", {"url": "/ping"}))
        assert p_get["method"] == "GET"
        assert "method_warning" not in p_get

        # 2. Omitting method while supplying stringified json_body infers POST and parses to JSON dict.
        p_json = _parse_tool_preview(
            disp.dispatch(
                "http_request",
                {"url": "/submit-json", "json_body": '{"email": "a@b.test"}'},
            )
        )
        assert p_json["method"] == "POST"
        assert "method_warning" not in p_json
        assert seen_requests[-1]["method"] == "POST"
        assert json.loads(seen_requests[-1]["body"]) == {"email": "a@b.test"}

        # 3. Omitting method while supplying stringified form_body infers POST and encodes form dict.
        p_form = _parse_tool_preview(
            disp.dispatch(
                "http_request",
                {"url": "/submit-form", "form_body": '{"user": "alice", "role": "member"}'},
            )
        )
        assert p_form["method"] == "POST"
        assert "method_warning" not in p_form
        assert seen_requests[-1]["method"] == "POST"
        assert "application/x-www-form-urlencoded" in seen_requests[-1]["content_type"]
        assert "user=alice" in seen_requests[-1]["body"]

        # 4. Explicit method="GET" with body honors GET and emits non-blocking method_warning.
        p_warn = _parse_tool_preview(
            disp.dispatch(
                "http_request",
                {"method": "GET", "url": "/get-with-body", "json_body": {"k": "v"}},
            )
        )
        assert p_warn["method"] == "GET"
        assert "method_warning" in p_warn
        assert "method='POST'" in p_warn["method_warning"]

        # 5. Intentional non-JSON string in json_body is left untouched (not broken) and infers POST.
        p_raw_str = _parse_tool_preview(
            disp.dispatch(
                "http_request",
                {"url": "/raw-json-str", "json_body": "plain-string-payload"},
            )
        )
        assert p_raw_str["method"] == "POST"
        assert json.loads(seen_requests[-1]["body"]) == "plain-string-payload"
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def _start_barrier_target() -> tuple[ThreadingHTTPServer, str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            path = urlsplit(self.path).path
            if path == "/api/auth":
                body = json.dumps({"token": "boot-tok-123"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/":
                html = (
                    "<html><body>"
                    "<form method='post' action='/api/auth'><input name='user'/></form>"
                    "<a href='/alpha'>A</a><a href='/alpha/1'>A1</a>"
                    "<a href='/api/alpha'>AA</a><a href='/api/alpha/1'>AA1</a>"
                    "<a href='/beta'>B</a><a href='/beta/2'>B2</a>"
                    "<a href='/api/beta'>AB</a><a href='/api/beta/2'>AB2</a>"
                    "<a href='/gamma'>G</a><a href='/gamma/3'>G3</a>"
                    "<a href='/api/gamma'>AG</a><a href='/api/gamma/3'>AG3</a>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            if path == "/api/alpha/1":
                if self.headers.get("Authorization") != "Bearer boot-tok-123":
                    self.send_response(401)
                    self.end_headers()
                    return
                body = json.dumps({"id": 1, "secret": "ALPHA_SEC"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path in {"/api/beta/2", "/api/gamma/3"}:
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_discovery_finish_gate_rejects_anon_only_accepts_post_auth_and_last_turns(tmp_path: Path) -> None:
    srv, base_url = _start_barrier_target()
    try:
        # Case A: bootstrap_discovery_only rejects premature anon-only finish,
        # then accepts finish after POST auth + post-auth GET 2xx crawl, and resets gate for Stage 2.
        dir_a = tmp_path / "case_a"
        dir_a.mkdir()
        store_a, client_a, budget_a = _make_deps(
            dir_a,
            base_url=base_url,
            http_limit=60,
            token_limit=400_000,
            accounts=[{"alias": "anon", "role": "anonymous", "tenant": "public"}],
        )
        boot_finish_replies: list[dict[str, Any]] = []
        shard_gate_states: list[bool] = []
        lock = threading.Lock()
        boot_step = [0]

        def _handler_a(_idx: int, body: dict[str, Any]) -> dict[str, Any]:
            msgs = body.get("messages") or []
            sys_msg = str((msgs[0] if msgs else {}).get("content") or "")
            if "SUBSYSTEM SHARD SCOPE (" not in sys_msg:
                with lock:
                    boot_step[0] += 1
                    step = boot_step[0]
                if step == 1:
                    return _multi_resp([
                        ("a1", "http_request", {"url": "/", "actor": "anon"}),
                        ("a2", "http_request", {"url": "/api/alpha/1", "actor": "anon"}),
                    ])
                if step == 2:
                    # Extract surface to populate multi-family routes, then attempt premature finish.
                    return _multi_resp([
                        ("a2b", "extract_surface", {"receipt_id": "req-0001"}),
                        ("a3", "finish", {"summary": "too early"}),
                    ])
                if step == 3:
                    for m in msgs:
                        if m.get("role") == "tool" and m.get("tool_call_id") == "a3":
                            boot_finish_replies.append(json.loads(str(m.get("content") or "{}").split("\n[", 1)[0]))
                    # Authenticate via inferred POST (no explicit method) + perform post-auth GET 2xx.
                    return _multi_resp([
                        (
                            "a4",
                            "http_request",
                            {"url": "/api/auth", "json_body": '{"user":"u1"}', "save_session_as": "dyn-u1"},
                        ),
                        ("a5", "http_request", {"url": "/api/alpha/1", "actor": "dyn-u1"}),
                    ])
                if step == 4:
                    return _tool_resp("a6", "finish", {"summary": "post-auth crawl done"})
                return _tool_resp("a7", "finish", {"summary": "fallback"})
            shard_gate_states.append(inv_a.dispatcher.discovery_finish_gate)
            return _tool_resp(f"s_{_idx}", "finish", {"summary": "shard done"})

        inv_a = AgenticInvestigator(
            http_client=client_a,
            receipt_store=store_a,
            transport=_ScriptedTransport(_handler_a),  # type: ignore[arg-type]
            budget=budget_a,
            model="strong-model",
            bootstrap_model="fast-boot",
            root_dir=dir_a,
            max_turns=36,
            execution_mode="sharded",
            max_shards=3,
            bootstrap_turns=12,
            shard_turns=4,
            sleep_fn=lambda _s: None,
        )
        res_a = inv_a.run()
        client_a.close()
        assert res_a["status"] == "finished"
        assert boot_finish_replies and boot_finish_replies[0]["rejected"] is True
        assert boot_finish_replies[0]["finished"] is False
        assert inv_a.dispatcher.finish_rejections == 1
        assert inv_a.dispatcher.discovery_finish_gate is False
        assert shard_gate_states and all(g is False for g in shard_gate_states)
        assert len(res_a["sharding_summary"]["shards"]) >= 2

        # Case B: Last 2 turns of bootstrap_discovery_only allow premature finish even with barrier & anon-only,
        # and fallback to monolithic resets discovery_finish_gate = False.
        dir_b = tmp_path / "case_b"
        dir_b.mkdir()
        store_b, client_b, budget_b = _make_deps(
            dir_b,
            base_url=base_url,
            http_limit=60,
            token_limit=400_000,
            accounts=[{"alias": "anon", "role": "anonymous", "tenant": "public"}],
        )
        b_step = [0]
        cont_gate_states: list[bool] = []

        def _handler_b(_idx: int, body: dict[str, Any]) -> dict[str, Any]:
            msgs = body.get("messages") or []
            sys_msg = str((msgs[0] if msgs else {}).get("content") or "")
            usr_msg = str((msgs[1] if len(msgs) > 1 else {}).get("content") or "")
            if "Stage 1 discovery is complete." in usr_msg:
                cont_gate_states.append(inv_b.dispatcher.discovery_finish_gate)
                return _tool_resp(f"mc_{_idx}", "finish", {"summary": "monolithic cont done"})
            if "SUBSYSTEM SHARD SCOPE (" not in sys_msg:
                b_step[0] += 1
                step = b_step[0]
                if step == 1:
                    return _tool_resp("b1", "http_request", {"url": "/api/alpha/1", "actor": "anon"})
                if step == 2:
                    # Turn 2 of boot_max_turns=4 is still gated -> rejected
                    return _tool_resp("b2", "finish", {"summary": "early turn 2"})
                # Turn 3 of boot_max_turns=4 (last 2 turns) -> accepted!
                return _tool_resp("b3", "finish", {"summary": "allowed in last 2 turns"})
            return _tool_resp(f"sb_{_idx}", "finish", {"summary": "shard done"})

        inv_b = AgenticInvestigator(
            http_client=client_b,
            receipt_store=store_b,
            transport=_ScriptedTransport(_handler_b),  # type: ignore[arg-type]
            budget=budget_b,
            model="strong-model",
            bootstrap_model="fast-boot",
            root_dir=dir_b,
            max_turns=12,
            execution_mode="sharded",
            max_shards=2,
            bootstrap_turns=4,
            shard_turns=4,
            sleep_fn=lambda _s: None,
        )
        res_b = inv_b.run()
        client_b.close()
        assert res_b["status"] == "finished"
        assert b_step[0] == 3
        assert cont_gate_states and all(g is False for g in cont_gate_states)
        assert inv_b.dispatcher.discovery_finish_gate is False
    finally:
        srv.shutdown()
        srv.server_close()
