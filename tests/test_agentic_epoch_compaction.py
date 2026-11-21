"""Unit tests for append-only Epoch Compaction and [BUDGET-WRAPUP] in AgenticInvestigator."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import (  # noqa: E402
    _EPOCH_HARD_CHAR_LIMIT,
    _PROMPT_HARD_CHAR_LIMIT,
    AgenticInvestigator,
    compact_messages_for_context,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import SessionGate  # noqa: E402


def _make_deps(
    tmp_path: Path,
    *,
    http_limit: int = 40,
    token_limit: int = 400_000,
    allowed_methods: tuple[str, ...] = ("GET", "POST"),
) -> tuple[ReceiptStore, AgenticHTTPClient, SharedBudget]:
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "anon", "role": "anonymous", "tenant": "public"},
        {"alias": "member-a", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-a"},
    ])
    client = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080",
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=http_limit,
    )
    budget = SharedBudget(http=http_limit, tokens=token_limit, seconds=120)
    return store, client, budget


def _tool_http_msg(
    *,
    call_id: str,
    receipt_id: str,
    url: str,
    body_preview: str,
    banner: str = "\n[STATE] http_budget: 35/40 left | turn: 2/40",
) -> dict[str, Any]:
    payload = {
        "receipt_id": receipt_id,
        "cached": False,
        "actor": "anon",
        "method": "GET",
        "url": url,
        "status": 200,
        "elapsed_ms": 5.0,
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
            + "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
            + banner
        ),
    }


class _RecordingTransport:
    """Fake transport that records exact request bodies sent on every turn."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.session_gate = SessionGate()
        self.provider_responses: list[dict[str, Any]] = []
        self.calls = 0
        self._responses = list(responses)
        self.seen_bodies: list[dict[str, Any]] = []

    def complete(self, body: dict[str, Any], *, minimum_output_tokens: int = 16) -> dict[str, Any]:  # noqa: ARG002
        self.calls += 1
        self.seen_bodies.append(copy.deepcopy(body))
        self.provider_responses.append({"call": self.calls, "upstream_http_status": 200})
        idx = min(self.calls - 1, len(self._responses) - 1)
        return copy.deepcopy(self._responses[idx])


def test_monolithic_epoch_prefix_cache_is_byte_identical_across_turns(tmp_path: Path) -> None:
    """Within an epoch, tools and messages[:len(prev)] are byte-identical across turns 1..5."""
    store, client, budget = _make_deps(tmp_path, http_limit=40, token_limit=400_000)
    try:
        # Turn 1..4: notebook write + empty nudges + finish on turn 5 (also crossing into wrapup turns).
        responses = [
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Step 1: logging initial observation.",
                        "tool_calls": [{
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "notebook",
                                "arguments": json.dumps({"action": "write", "surface_notes": "checked /"}),
                            },
                        }],
                    }
                }],
                "usage": {"prompt_tokens": 500, "completion_tokens": 30, "total_tokens": 530},
            },
            {
                "choices": [{"message": {"role": "assistant", "content": "Thinking without tools turn 2."}}],
                "usage": {"prompt_tokens": 600, "completion_tokens": 20, "total_tokens": 620},
            },
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Step 3: updating notebook.",
                        "tool_calls": [{
                            "id": "call_3",
                            "type": "function",
                            "function": {
                                "name": "notebook",
                                "arguments": json.dumps({"action": "write", "surface_notes": "checked /api"}),
                            },
                        }],
                    }
                }],
                "usage": {"prompt_tokens": 700, "completion_tokens": 30, "total_tokens": 730},
            },
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Step 4: adding hypothesis.",
                        "tool_calls": [{
                            "id": "call_4",
                            "type": "function",
                            "function": {
                                "name": "notebook",
                                "arguments": json.dumps({
                                    "action": "write",
                                    "hypothesis": {"id": "H1", "vuln_class": "bola", "status": "open"},
                                }),
                            },
                        }],
                    }
                }],
                "usage": {"prompt_tokens": 800, "completion_tokens": 30, "total_tokens": 830},
            },
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Step 5: finishing.",
                        "tool_calls": [{
                            "id": "call_5",
                            "type": "function",
                            "function": {
                                "name": "finish",
                                "arguments": json.dumps({"summary": "Done", "untested_areas": []}),
                            },
                        }],
                    }
                }],
                "usage": {"prompt_tokens": 900, "completion_tokens": 30, "total_tokens": 930},
            },
        ]
        transport = _RecordingTransport(responses)
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
        result = inv.run()
        assert result["status"] == "finished"
        assert len(transport.seen_bodies) == 5
        assert inv._epoch_turn_start == 0
        assert inv._epoch_summary_text == ""

        # Every consecutive pair of turns in Epoch 1 must share exact tools and exact message prefix.
        for t in range(len(transport.seen_bodies) - 1):
            b_prev = transport.seen_bodies[t]
            b_next = transport.seen_bodies[t + 1]
            assert b_prev["tools"] == b_next["tools"]
            assert b_prev["messages"] == b_next["messages"][:len(b_prev["messages"])]

        # Earlier [STATE] banners and messages[1] must remain intact (no retroactive stripping).
        final_msgs = transport.seen_bodies[-1]["messages"]
        assert "\n[STATE] " in final_msgs[1]["content"]
        assert "\n[STATE] " in final_msgs[3]["content"]
        # Wrapup banner is added at creation time for turn 3+ (max_turns=6, turns left <= 4) without mutating earlier messages.
        assert "[BUDGET-WRAPUP]" in final_msgs[-1]["content"]
    finally:
        client.close()


def test_epoch_advancement_freezes_epoch2_prefix_and_preserves_receipt_summary(tmp_path: Path) -> None:
    """Exceeding epoch_char_limit=32_000 advances the epoch once and keeps Epoch 2 strictly append-only."""
    store, client, budget = _make_deps(tmp_path, http_limit=40, token_limit=500_000)
    try:
        transport = _RecordingTransport([])
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=40,
            epoch_char_limit=32_000,
        )

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "S" * 1000},
            {"role": "user", "content": "Investigate target.\n[STATE] http_budget: 40/40 left | turn: 1/40"},
        ]

        epoch1_bodies: list[dict[str, Any]] = []
        epoch2_bodies: list[dict[str, Any]] = []
        epoch2_start: int | None = None
        advanced_at_turn: int | None = None

        # Each turn adds ~3.2 KB so Epoch 1 grows above _PROMPT_HARD_CHAR_LIMIT (24,000) without compacting,
        # crosses epoch_char_limit (32,000) around turn 8, advances to len(turn_groups)-1, and Epoch 2 holds 4+ turns.
        for turn in range(1, 14):
            rid = f"req-{turn:04d}"
            messages.append({
                "role": "assistant",
                "content": f"Turn {turn} reasoning.",
                "tool_calls": [{
                    "id": f"call_{turn}",
                    "type": "function",
                    "function": {"name": "http_request", "arguments": json.dumps({"url": f"/api/item/{turn}"})},
                }],
            })
            messages.append(
                _tool_http_msg(
                    call_id=f"call_{turn}",
                    receipt_id=rid,
                    url=f"http://127.0.0.1:18080/api/item/{turn}",
                    body_preview=("X" * 2800) + f"MARKER_{turn}",
                    banner=f"\n[STATE] http_budget: {40 - turn}/40 left | turn: {turn + 1}/40",
                )
            )
            body = inv._prepare_bounded_body(messages)
            wire_bytes = len(json.dumps({"messages": body["messages"], "tools": body["tools"]}, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            assert wire_bytes <= 32_000

            if inv._epoch_turn_start == 0:
                epoch1_bodies.append(body)
            else:
                if epoch2_start is None:
                    epoch2_start = inv._epoch_turn_start
                    advanced_at_turn = turn
                if inv._epoch_turn_start == epoch2_start:
                    epoch2_bodies.append(body)

        assert advanced_at_turn is not None
        assert epoch2_start == advanced_at_turn - 1  # len(turn_groups) - 1 at advancement
        assert len(epoch1_bodies) >= 5
        assert len(epoch2_bodies) >= 4
        assert inv._epoch_turn_start > 0
        assert "[COMPACTED HISTORY:" in inv._epoch_summary_text
        # Older receipt IDs from Epoch 1 are frozen into messages[1] of Epoch 2.
        assert "req-0001" in epoch2_bodies[0]["messages"][1]["content"]
        # Epoch 1 allowed growing past _PROMPT_HARD_CHAR_LIMIT up to _EPOCH_HARD_CHAR_LIMIT without early churn.
        last_epoch1_bytes = len(json.dumps({"messages": epoch1_bodies[-1]["messages"], "tools": epoch1_bodies[-1]["tools"]}, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        assert last_epoch1_bytes > _PROMPT_HARD_CHAR_LIMIT

        # Exact prefix equality inside Epoch 1.
        for t in range(len(epoch1_bodies) - 1):
            assert epoch1_bodies[t]["tools"] == epoch1_bodies[t + 1]["tools"]
            assert epoch1_bodies[t]["messages"] == epoch1_bodies[t + 1]["messages"][:len(epoch1_bodies[t]["messages"])]

        # Exact prefix equality inside Epoch 2 (frozen messages[1] + append-only turns).
        for t in range(len(epoch2_bodies) - 1):
            assert epoch2_bodies[t]["tools"] == epoch2_bodies[t + 1]["tools"]
            assert epoch2_bodies[t]["messages"] == epoch2_bodies[t + 1]["messages"][:len(epoch2_bodies[t]["messages"])]

        # Standalone compact_messages_for_context remains intact.
        standalone = compact_messages_for_context(messages, keep_recent_turns=2)
        assert "[COMPACTED HISTORY:" in standalone[1]["content"]
    finally:
        client.close()


def test_epoch_advancement_tries_single_turn_and_never_mutates_state_on_schedules_fallback(tmp_path: Path) -> None:
    """Advancement tries len(turn_groups)-1 with default tools before schedules fallback, and leaves _epoch_* intact on fallback."""
    store, client, budget = _make_deps(tmp_path, http_limit=40, token_limit=30_000)
    try:
        transport = _RecordingTransport([])
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=40,
        )

        # Build 4 turns (~5 KB each) so 2 recent turns + overhead > 27,696 avail, while 1 recent turn + default tools fits <= 27,696.
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "S" * 1000},
            {"role": "user", "content": "Investigate target.\n[STATE] http_budget: 40/40 left | turn: 1/40"},
        ]
        for turn in range(1, 5):
            messages.append({
                "role": "assistant",
                "content": f"Turn {turn} reasoning.",
                "tool_calls": [{
                    "id": f"call_{turn}",
                    "type": "function",
                    "function": {"name": "http_request", "arguments": json.dumps({"url": f"/api/item/{turn}"})},
                }],
            })
            messages.append(
                _tool_http_msg(
                    call_id=f"call_{turn}",
                    receipt_id=f"req-{turn:04d}",
                    url=f"http://127.0.0.1:18080/api/item/{turn}",
                    body_preview="Y" * 4700,
                    banner=f"\n[STATE] http_budget: {40 - turn}/40 left | turn: {turn + 1}/40",
                )
            )
        # Include a second big tool response on turn 4 so 2 turns (turn 3+4) + sys + tools > 24K while 1 turn (turn 4) fits < 27K.
        messages.append(
            _tool_http_msg(
                call_id="call_4b",
                receipt_id="req-0005",
                url="http://127.0.0.1:18080/api/item/4b",
                body_preview="Y" * 4700,
                banner="\n[STATE] http_budget: 36/40 left | turn: 5/40",
            )
        )

        # Force avail=25_000: 2 turns (~18K + ~8K base = ~26K > 22.7K), 1 turn (~10K + ~8K = ~18K <= 22.7K).
        budget.used["tokens"] = 5_000
        body_1 = inv._prepare_bounded_body(messages)
        assert inv._epoch_turn_start == 3  # len(turn_groups) - 1
        assert len(body_1["messages"]) == 5  # sys, init_user+summary, turn-4 asst, tool_4, tool_4b
        assert body_1["tools"][0]["function"]["description"]  # wire_tools_default preserved (non-tight)

        # Now shrink avail so even 1 turn + wire_tools_default cannot fit: falls back to schedules WITHOUT mutating _epoch_*.
        prev_start = inv._epoch_turn_start
        prev_summary = inv._epoch_summary_text
        budget.used["tokens"] = 18_000  # avail=12_000 -> fallback to schedules
        body_fb = inv._prepare_bounded_body(messages)
        assert inv._epoch_turn_start == prev_start
        assert inv._epoch_summary_text == prev_summary
        assert len(body_fb["messages"]) >= 2
    finally:
        client.close()


def test_checkpoint_roundtrip_preserves_epoch_state_and_loads_legacy_checkpoints(tmp_path: Path) -> None:
    """_save_checkpoint/_load_checkpoint preserve epoch state and tolerate old checkpoints lacking those keys."""
    store, client, budget = _make_deps(tmp_path)
    try:
        transport = _RecordingTransport([])
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
        )
        inv._epoch_turn_start = 4
        inv._epoch_summary_text = "\n[COMPACTED HISTORY: 4 earlier turns]\n[collapsed: receipt_id=req-0001]"
        sample_msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "init"},
            {"role": "assistant", "content": "a1"},
            {"role": "user", "content": "u1"},
        ]
        inv._save_checkpoint(turn=4, status="in_progress", messages=sample_msgs)

        # Fresh investigator restores exact epoch state.
        inv2 = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
        )
        loaded = inv2._load_checkpoint()
        assert loaded == (4, sample_msgs)
        assert inv2._epoch_turn_start == 4
        assert inv2._epoch_summary_text == inv._epoch_summary_text

        # Legacy checkpoint without epoch keys loads cleanly with defaults (0, "").
        ckpt_data = json.loads(inv.checkpoint_path.read_text(encoding="utf-8"))
        ckpt_data.pop("epoch_turn_start", None)
        ckpt_data.pop("epoch_summary_text", None)
        inv.checkpoint_path.write_text(json.dumps(ckpt_data), encoding="utf-8")

        inv3 = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
        )
        inv3._epoch_turn_start = 9
        inv3._epoch_summary_text = "stale"
        loaded3 = inv3._load_checkpoint()
        assert loaded3 == (4, sample_msgs)
        assert inv3._epoch_turn_start == 0
        assert inv3._epoch_summary_text == ""
    finally:
        client.close()


def test_budget_wrapup_banner_triggers_and_silence_conditions(tmp_path: Path) -> None:
    """[BUDGET-WRAPUP] fires on <=15% tokens, <=4 turns left, or <=10 HTTP left, and stays silent otherwise."""
    # 1. Healthy budgets: silent, while [STATE], [NOTEBOOK], [SURFACE FRONTIER], [WRITE-PHASE] remain intact.
    store, client, budget = _make_deps(tmp_path, http_limit=30, token_limit=400_000, allowed_methods=("GET", "POST"))
    try:
        transport = _RecordingTransport([])
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=40,
        )
        inv.dispatcher.notebook_state["surface_notes"] = "mapped /api/items"
        inv.dispatcher.surface_tracker._register_discovered_url("/api/items", method="POST")

        healthy_banner = inv._state_banner(turn=10)
        assert "[STATE]" in healthy_banner
        assert "[NOTEBOOK]" in healthy_banner
        assert "[SURFACE FRONTIER]" in healthy_banner
        assert "[WRITE-PHASE]" in healthy_banner
        assert "[BUDGET-WRAPUP]" not in healthy_banner

        # 2. <= 4 turns left (when max_turns > 5): turn 35 is silent, turn 36 triggers.
        assert "[BUDGET-WRAPUP]" not in inv._state_banner(turn=35)
        turns_banner = inv._state_banner(turn=36)
        assert "[BUDGET-WRAPUP]" in turns_banner
        assert "record_finding" in turns_banner
        assert "finish" in turns_banner

        # 3. <= 10 HTTP left (when http_limit > 15): 11 left is silent, 10 left triggers.
        client.budget.used = 19  # 11 left
        assert "[BUDGET-WRAPUP]" not in inv._state_banner(turn=5)
        client.budget.used = 20  # 10 left
        http_banner = inv._state_banner(turn=5)
        assert "[BUDGET-WRAPUP]" in http_banner
        client.budget.used = 0

        # 4. <= 15% token budget remaining (max(30_000, int(400_000 * 0.15)) = 60_000).
        budget.used["tokens"] = 400_000 - 60_001
        assert "[BUDGET-WRAPUP]" not in inv._state_banner(turn=5)
        budget.used["tokens"] = 400_000 - 60_000
        tok_banner = inv._state_banner(turn=5)
        assert "[BUDGET-WRAPUP]" in tok_banner
    finally:
        client.close()

    # 5. Small test budgets (max_turns <= 5 and http_limit <= 15) do NOT false-trigger turn/http wrapup.
    sub_dir = tmp_path / "small"
    sub_dir.mkdir()
    store2, client2, budget2 = _make_deps(sub_dir, http_limit=15, token_limit=100_000)
    try:
        inv_small = AgenticInvestigator(
            http_client=client2,
            receipt_store=store2,
            transport=_RecordingTransport([]),  # type: ignore[arg-type]
            budget=budget2,
            model="test-model",
            root_dir=sub_dir,
            max_turns=5,
        )
        client2.budget.used = 10  # 5 left out of 15
        assert "[BUDGET-WRAPUP]" not in inv_small._state_banner(turn=5)
    finally:
        client2.close()


def test_ephemeral_mode_and_short_message_lists_unaffected_by_epoch_state(tmp_path: Path) -> None:
    """Ephemeral workers and shorter/fresh message lists never inherit stale monolithic epoch state."""
    store, client, budget = _make_deps(tmp_path, http_limit=20, token_limit=200_000)
    try:
        # 1. Direct _project_epoch_messages / _prepare_bounded_body guard on shorter message lists.
        transport = _RecordingTransport([])
        inv_mono = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            execution_mode="monolithic",
        )
        inv_mono._epoch_turn_start = 5
        inv_mono._epoch_summary_text = "\n[COMPACTED HISTORY: stale monolithic summary]"

        fresh_short_msgs: list[dict[str, Any]] = [
            {"role": "system", "content": "Worker system prompt"},
            {"role": "user", "content": "Fresh worker slice"},
            {"role": "assistant", "content": "Checking /items"},
            _tool_http_msg(call_id="w1", receipt_id="req-0099", url="http://127.0.0.1:18080/items", body_preview="ok"),
        ]
        projected_short = inv_mono._project_epoch_messages(fresh_short_msgs)
        assert "stale monolithic summary" not in projected_short[1]["content"]
        assert len(projected_short) == len(fresh_short_msgs)

        body_short = inv_mono._prepare_bounded_body(fresh_short_msgs)
        assert "stale monolithic summary" not in body_short["messages"][1]["content"]

        # 2. Ephemeral execution mode never reads or mutates monolithic epoch state across workers.
        eph_dir = tmp_path / "eph"
        eph_dir.mkdir()
        store_e, client_e, budget_e = _make_deps(eph_dir, http_limit=20, token_limit=200_000)
        try:
            eph_transport = _RecordingTransport([
                {
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": "Done checking slice.",
                            "tool_calls": [{
                                "id": "ec1",
                                "type": "function",
                                "function": {
                                    "name": "finish",
                                    "arguments": json.dumps({"summary": "slice done", "untested_areas": []}),
                                },
                            }],
                        }
                    }],
                    "usage": {"prompt_tokens": 300, "completion_tokens": 20, "total_tokens": 320},
                }
            ])
            inv_eph = AgenticInvestigator(
                http_client=client_e,
                receipt_store=store_e,
                transport=eph_transport,  # type: ignore[arg-type]
                budget=budget_e,
                model="test-model",
                root_dir=eph_dir,
                execution_mode="ephemeral",
                max_turns=3,
                use_bsag=False,
            )
            inv_eph._epoch_turn_start = 3
            inv_eph._epoch_summary_text = "\n[COMPACTED HISTORY: must not appear in ephemeral worker]"
            res = inv_eph.run()
            assert res["status"] in {"finished", "max_turns_reached"}
            assert len(eph_transport.seen_bodies) >= 1
            for req in eph_transport.seen_bodies:
                for m in req["messages"]:
                    assert "must not appear in ephemeral worker" not in str(m.get("content") or "")
            assert inv_eph._epoch_turn_start == 3
        finally:
            client_e.close()
    finally:
        client.close()


def test_default_80k_epoch_limit_retains_long_prefix_without_churn(tmp_path: Path) -> None:
    """Default _EPOCH_HARD_CHAR_LIMIT (80,000) keeps 14 turns (~50 KB) in Epoch 1 with zero advancements."""
    store, client, budget = _make_deps(tmp_path, http_limit=40, token_limit=500_000)
    try:
        assert _EPOCH_HARD_CHAR_LIMIT == 80_000
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_RecordingTransport([]),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=40,
        )
        assert inv.epoch_char_limit == 80_000
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "S" * 1000},
            {"role": "user", "content": "Investigate target.\n[STATE] http_budget: 40/40 left | turn: 1/40"},
        ]
        bodies: list[dict[str, Any]] = []
        for turn in range(1, 15):
            messages.append({
                "role": "assistant",
                "content": f"Turn {turn} reasoning.",
                "tool_calls": [{
                    "id": f"call_{turn}",
                    "type": "function",
                    "function": {"name": "http_request", "arguments": json.dumps({"url": f"/api/item/{turn}"})},
                }],
            })
            messages.append(
                _tool_http_msg(
                    call_id=f"call_{turn}",
                    receipt_id=f"req-{turn:04d}",
                    url=f"http://127.0.0.1:18080/api/item/{turn}",
                    body_preview="X" * 2800,
                    banner=f"\n[STATE] http_budget: {40 - turn}/40 left | turn: {turn + 1}/40",
                )
            )
            body = inv._prepare_bounded_body(messages)
            wire_bytes = len(
                json.dumps({"messages": body["messages"], "tools": body["tools"]}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            )
            assert wire_bytes <= 80_000
            bodies.append(body)

        assert inv._epoch_turn_start == 0
        assert inv._epoch_advancements == 0
        for t in range(len(bodies) - 1):
            assert bodies[t]["tools"] == bodies[t + 1]["tools"]
            assert bodies[t]["messages"] == bodies[t + 1]["messages"][:len(bodies[t]["messages"])]
    finally:
        client.close()
