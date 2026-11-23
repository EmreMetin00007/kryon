"""Unit tests for bounded, fail-safe Provider HTTP 400 recovery in AgenticInvestigator."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import (  # noqa: E402
    _FRAMING_RESERVE_TOKENS,
    AgenticInvestigator,
    _build_assistant_history_entry,
    _sanitize_messages_for_http400,
    _sanitize_text_for_http400,
    compact_messages_for_context,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from full_agent_budget import BudgetError, SharedBudget, completion_request  # noqa: E402
from full_agent_provider import SessionGate  # noqa: E402


def _make_investigator_deps(tmp_path: Path) -> tuple[ReceiptStore, AgenticHTTPClient]:
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {
            "alias": "anon",
            "role": "anonymous",
            "tenant": "public",
        },
        {
            "alias": "member-a",
            "role": "member",
            "tenant": "t1",
            "auth_header": "Bearer tok-member-a",
        },
    ])
    client = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=30,
    )
    return store, client


def _tool_http_message(
    *,
    tool_call_id: str,
    receipt_id: str,
    url: str,
    body_preview: str,
    banners: str = "",
) -> dict[str, Any]:
    payload = {
        "receipt_id": receipt_id,
        "cached": False,
        "actor": "anon",
        "method": "GET",
        "url": url,
        "status": 200,
        "elapsed_ms": 14.2,
        "content_type": "text/html; charset=utf-8",
        "response_length": len(body_preview) + 500,
        "redirect_location": "",
        "notable_headers": {"server": "test"},
        "body_preview": body_preview,
    }
    content = (
        "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
        + json.dumps(payload, ensure_ascii=False)
        + "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
        + banners
    )
    return {
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": content,
    }


def test_http400_recovery_attempt1_sanitizes_untrusted_tool_output_and_preserves_banners(tmp_path: Path) -> None:
    """Attempt 1 strips filter-triggering HTML/XSS/SQLi payloads, preserves banners/receipts, and keeps reservation."""
    store, client = _make_investigator_deps(tmp_path)
    budget = SharedBudget(http=30, tokens=100_000, seconds=120)
    seen_bodies: list[dict[str, Any]] = []

    class _FilterSensitiveTransport:
        def __init__(self) -> None:
            self.session_gate = SessionGate()
            self.provider_responses: list[dict[str, Any]] = []
            self.calls = 0

        def complete(self, body: dict[str, Any], *, minimum_output_tokens: int = 16) -> dict[str, Any]:  # noqa: ARG002
            self.calls += 1
            seen_bodies.append(copy.deepcopy(body))
            self.session_gate.require_open()
            ticket = budget.reserve("tokens", 10_000)
            wire_text = json.dumps(body["messages"])
            if "<script>" in wire_text or "UNION SELECT" in wire_text or "<svg/onload" in wire_text:
                self.session_gate.stop_reason = "provider_http_error"
                self.provider_responses.append({"call": self.calls, "upstream_http_status": 400})
                try:
                    budget.settle(ticket, None, upstream_http_status=400)
                except BudgetError:
                    pass
                raise BudgetError("provider returned HTTP 400", code="provider_http_error")

            budget.settle(ticket, 500, upstream_http_status=200)
            self.provider_responses.append({"call": self.calls, "upstream_http_status": 200})
            return {
                "choices": [{"message": {"role": "assistant", "content": "recovered-attempt-1"}}],
                "usage": {"prompt_tokens": 420, "completion_tokens": 80, "total_tokens": 500},
            }

    nasty_body = (
        "<html><head><script>alert('xss')</script></head>"
        "<body>Result: <svg/onload=alert(1)> ' OR 1=1 -- UNION SELECT password FROM users "
        + ("A" * 800)
        + " café</body></html>"
    )
    banners = (
        "\n[STATE] http_budget: 28/30 left | llm_tokens: 90000/100000 left | turn: 2/40 | "
        "actors: ['anon', 'member-a'] | findings: 0 | receipts: 1"
        "\n[NOTEBOOK] surface=checked search | hyps=H1:reflected_xss:open"
        "\n[SURFACE FRONTIER] GET /search (params: q)"
        "\n[WRITE-PHASE] Mutating HTTP methods (POST) are in scope."
    )
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": "You are a security investigator."},
        {"role": "user", "content": "Start testing."},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "http_request", "arguments": "{}"}}
            ],
        },
        _tool_http_message(
            tool_call_id="call_1",
            receipt_id="req-0007",
            url="http://127.0.0.1:18080/search?q=test",
            body_preview=nasty_body,
            banners=banners,
        ),
    ]
    original_snapshot = copy.deepcopy(messages)

    try:
        transport = _FilterSensitiveTransport()
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            reasoning_effort="low",
            sleep_fn=lambda _s: None,
        )
        resp = inv._complete_with_retry(messages)
        assert resp["choices"][0]["message"]["content"] == "recovered-attempt-1"
        assert transport.calls == 2
        assert budget.blocked == ""
        assert transport.session_gate.stop_reason == ""
        # Conservative reservation (10_000) from failed attempt stays deducted plus actual 500.
        assert budget.used["tokens"] == 10_500
        # Caller's original messages must remain completely unmutated.
        assert messages == original_snapshot

        # Inspect sanitized wire tool message sent on recovery attempt 1.
        retry_body = seen_bodies[1]
        assert retry_body["reasoning_effort"] == "low"
        tool_msg = retry_body["messages"][-1]
        assert tool_msg["role"] == "tool"
        content = tool_msg["content"]
        assert "[STATE]" in content
        assert "[NOTEBOOK]" in content
        assert "[SURFACE FRONTIER]" in content
        assert "[WRITE-PHASE]" in content
        assert "req-0007" in content

        inner = content.split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1].split(
            "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1
        )[0]
        parsed = json.loads(inner)
        assert parsed["receipt_id"] == "req-0007"
        assert parsed["actor"] == "anon"
        assert parsed["method"] == "GET"
        assert parsed["url"] == "http://127.0.0.1:18080/search?q=test"
        assert parsed["status"] == 200
        assert parsed["content_type"] == "text/html; charset=utf-8"
        assert parsed["response_length"] == len(nasty_body) + 500
        assert "body_preview" not in parsed
        snippet = parsed["safe_snippet"]
        assert len(snippet) <= 300
        assert snippet.isascii()
        for ch in ("<", ">", '"', "'", "`"):
            assert ch not in snippet
    finally:
        client.close()


def test_http400_recovery_attempt2_compacts_history_and_omits_reasoning_effort(tmp_path: Path) -> None:
    """Attempt 2 compacts to 1 recent turn and omits reasoning_effort when provider rejects it with HTTP 400."""
    store, client = _make_investigator_deps(tmp_path)
    budget = SharedBudget(http=30, tokens=100_000, seconds=120)
    seen_bodies: list[dict[str, Any]] = []

    class _RejectReasoningEffortTransport:
        def __init__(self) -> None:
            self.session_gate = SessionGate()
            self.provider_responses: list[dict[str, Any]] = []
            self.calls = 0

        def complete(self, body: dict[str, Any], *, minimum_output_tokens: int = 16) -> dict[str, Any]:  # noqa: ARG002
            self.calls += 1
            seen_bodies.append(copy.deepcopy(body))
            self.session_gate.require_open()
            ticket = budget.reserve("tokens", 4_000)
            if "reasoning_effort" in body:
                self.session_gate.stop_reason = "provider_http_error"
                self.provider_responses.append({"call": self.calls, "upstream_http_status": 400})
                try:
                    budget.settle(ticket, None, upstream_http_status=400)
                except BudgetError:
                    pass
                raise BudgetError("unsupported parameter: reasoning_effort", code="provider_http_error")

            budget.settle(ticket, 350, upstream_http_status=200)
            self.provider_responses.append({"call": self.calls, "upstream_http_status": 200})
            return {
                "choices": [{"message": {"role": "assistant", "content": "recovered-attempt-2"}}],
                "usage": {"prompt_tokens": 300, "completion_tokens": 50, "total_tokens": 350},
            }

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": "You are a security investigator."},
        {"role": "user", "content": "Investigate target."},
        {
            "role": "assistant",
            "content": "turn-1-assistant",
            "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "http_request", "arguments": "{}"}}],
        },
        _tool_http_message(
            tool_call_id="c1",
            receipt_id="req-0001",
            url="http://127.0.0.1:18080/one",
            body_preview="TURN_ONE_UNIQUE_BODY_MARKER",
        ),
        {
            "role": "assistant",
            "content": "turn-2-assistant",
            "tool_calls": [{"id": "c2", "type": "function", "function": {"name": "http_request", "arguments": "{}"}}],
        },
        _tool_http_message(
            tool_call_id="c2",
            receipt_id="req-0002",
            url="http://127.0.0.1:18080/two",
            body_preview="TURN_TWO_UNIQUE_BODY_MARKER",
        ),
        {
            "role": "assistant",
            "content": "turn-3-assistant",
            "tool_calls": [{"id": "c3", "type": "function", "function": {"name": "http_request", "arguments": "{}"}}],
        },
        _tool_http_message(
            tool_call_id="c3",
            receipt_id="req-0003",
            url="http://127.0.0.1:18080/three",
            body_preview="TURN_THREE_UNIQUE_BODY_MARKER",
            banners="\n[STATE] http_budget: 27/30 left | turn: 4/40",
        ),
    ]

    try:
        transport = _RejectReasoningEffortTransport()
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            reasoning_effort="medium",
            sleep_fn=lambda _s: None,
        )
        resp = inv._complete_with_retry(messages)
        assert resp["choices"][0]["message"]["content"] == "recovered-attempt-2"
        assert transport.calls == 3
        assert seen_bodies[0]["reasoning_effort"] == "medium"
        assert seen_bodies[1]["reasoning_effort"] == "medium"
        assert "reasoning_effort" not in seen_bodies[2]

        # Attempt 2 keeps only the most recent 1 turn verbatim while rolling older turns.
        attempt2_msgs = seen_bodies[2]["messages"]
        assert len(attempt2_msgs) == 4  # system, user (+ rolled history), turn-3 assistant, turn-3 tool
        assert "[COMPACTED HISTORY: 2 earlier turns" in attempt2_msgs[1]["content"]
        assert "req-0001" in attempt2_msgs[1]["content"]
        assert "req-0002" in attempt2_msgs[1]["content"]
        assert "TURN_THREE_UNIQUE_BODY_MARKER" in attempt2_msgs[3]["content"]
        assert "[STATE]" in attempt2_msgs[3]["content"]

        assert budget.blocked == ""
        assert transport.session_gate.stop_reason == ""
        assert budget.used["tokens"] == (4_000 * 2) + 350
    finally:
        client.close()


def test_http400_recovery_exhausted_fails_closed_with_budget_blocked(tmp_path: Path) -> None:
    """Permanent HTTP 400 stops after 1 initial + 2 recovery attempts and leaves budget.blocked set."""
    store, client = _make_investigator_deps(tmp_path)
    budget = SharedBudget(http=30, tokens=100_000, seconds=120)

    class _Always400Transport:
        def __init__(self) -> None:
            self.session_gate = SessionGate()
            self.provider_responses: list[dict[str, Any]] = []
            self.calls = 0

        def complete(self, body: dict[str, Any], *, minimum_output_tokens: int = 16) -> dict[str, Any]:  # noqa: ARG002
            self.calls += 1
            self.session_gate.require_open()
            ticket = budget.reserve("tokens", 5_000)
            self.session_gate.stop_reason = "provider_http_error"
            self.provider_responses.append({"call": self.calls, "upstream_http_status": 400})
            try:
                budget.settle(ticket, None, upstream_http_status=400)
            except BudgetError:
                pass
            raise BudgetError("provider returned HTTP 400", code="provider_http_error")

    try:
        transport = _Always400Transport()
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_provider_retries=4,
            sleep_fn=lambda _s: None,
        )
        with pytest.raises(BudgetError, match="400"):
            inv._complete_with_retry([{"role": "user", "content": "hi"}])

        assert transport.calls == 3
        assert budget.blocked == "missing or invalid tokens usage"
        assert transport.session_gate.stop_reason == "provider_http_error"
        assert budget.used["tokens"] == 15_000
    finally:
        client.close()


def test_http400_not_retried_when_max_provider_retries_zero(tmp_path: Path) -> None:
    """Setting max_provider_retries=0 disables HTTP 400 recovery retries and fails immediately."""
    store, client = _make_investigator_deps(tmp_path)
    budget = SharedBudget(http=30, tokens=100_000, seconds=120)

    class _Single400Transport:
        def __init__(self) -> None:
            self.session_gate = SessionGate()
            self.provider_responses: list[dict[str, Any]] = []
            self.calls = 0

        def complete(self, body: dict[str, Any], *, minimum_output_tokens: int = 16) -> dict[str, Any]:  # noqa: ARG002
            self.calls += 1
            ticket = budget.reserve("tokens", 3_000)
            self.session_gate.stop_reason = "provider_http_error"
            self.provider_responses.append({"call": self.calls, "upstream_http_status": 400})
            try:
                budget.settle(ticket, None, upstream_http_status=400)
            except BudgetError:
                pass
            raise BudgetError("provider returned HTTP 400", code="provider_http_error")

    try:
        transport = _Single400Transport()
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_provider_retries=0,
        )
        with pytest.raises(BudgetError, match="400"):
            inv._complete_with_retry([{"role": "user", "content": "hi"}])

        assert transport.calls == 1
        assert budget.blocked == "missing or invalid tokens usage"
    finally:
        client.close()


def test_prepare_bounded_body_omit_reasoning_effort_flag(tmp_path: Path) -> None:
    """_prepare_bounded_body preserves existing signature and omits reasoning_effort only when requested."""
    store, client = _make_investigator_deps(tmp_path)
    budget = SharedBudget(http=30, tokens=100_000, seconds=120)

    class _DummyTransport:
        session_gate = SessionGate()
        provider_responses: list[dict[str, Any]] = []

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            reasoning_effort="high",
        )
        msgs = [{"role": "user", "content": "hello"}]
        default_body = inv._prepare_bounded_body(msgs)
        omitted_body = inv._prepare_bounded_body(msgs, omit_reasoning_effort=True)
        assert default_body["reasoning_effort"] == "high"
        assert "reasoning_effort" not in omitted_body
    finally:
        client.close()


def test_http400_sanitizes_replay_read_receipt_and_unclosed_blocks() -> None:
    """Sanitizer handles replay_as, read_receipt, and unclosed blocks while keeping receipt IDs and banners."""
    replay_payload = {
        "baseline_receipt_id": "req-0010",
        "baseline_actor": "member-a",
        "replay": {
            "receipt_id": "req-0011",
            "actor": "anon",
            "method": "GET",
            "url": "http://127.0.0.1:18080/profile?next=\"<script>alert(1)</script>",
            "status": 200,
            "content_type": "text/html",
            "response_length": 400,
            "body_preview": "<script>evil()</script><div>Profile</div>",
        },
        "diff": {"status_diff": [200, 200], "length_diff": 0, "sha256_same": True},
    }
    read_payload = {
        "receipt_id": "req-0012",
        "offset": 0,
        "returned_chars": 200,
        "total_length": 5000,
        "next_offset": 200,
        "body": "SELECT * FROM secrets WHERE id=1; <img src=x onerror=alert(1)>",
    }
    unclosed_raw = (
        "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
        '{"receipt_id":"req-0013","actor":"anon","method":"GET","url":"http://127.0.0.1:18080/x","status":500,'
        '"body_preview":"<script>bad'
        "\n[STATE] http_budget: 10/30 left\n[SURFACE FRONTIER] GET /api/items"
    )
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "usr"},
        {
            "role": "tool",
            "tool_call_id": "t1",
            "content": f"<<<UNTRUSTED_TARGET_RESPONSE>>>\n{json.dumps(replay_payload)}\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>",
        },
        {
            "role": "tool",
            "tool_call_id": "t2",
            "content": f"<<<UNTRUSTED_TARGET_RESPONSE>>>\n{json.dumps(read_payload)}\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>",
        },
        {"role": "tool", "tool_call_id": "t3", "content": unclosed_raw},
    ]

    sanitized = _sanitize_messages_for_http400(msgs)
    for msg in sanitized[2:]:
        text = msg["content"]
        assert "<script>" not in text
        assert "onerror=" not in text
        assert "SELECT * FROM" not in text

    assert "req-0010" in sanitized[2]["content"]
    assert "req-0011" in sanitized[2]["content"]
    assert "req-0012" in sanitized[3]["content"]
    assert "req-0013" in sanitized[4]["content"]
    assert "[STATE] http_budget: 10/30 left" in sanitized[4]["content"]
    assert "[SURFACE FRONTIER] GET /api/items" in sanitized[4]["content"]
    assert len(_sanitize_text_for_http400("x" * 1000, max_chars=300)) <= 300


def test_prepare_bounded_body_max_tokens_8192_and_headroom_scaling(tmp_path: Path) -> None:
    """_prepare_bounded_body defaults max_tokens to 8192 when headroom >= 8192 and scales down below 8192."""
    store, client = _make_investigator_deps(tmp_path)
    budget = SharedBudget(http=30, tokens=100_000, seconds=120)

    class _DummyTransport:
        session_gate = SessionGate()
        provider_responses: list[dict[str, Any]] = []

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
        )
        msgs = [{"role": "user", "content": "hello"}]
        full_body = inv._prepare_bounded_body(msgs)
        assert full_body["max_tokens"] == 8192

        admitted_req, _ = completion_request(
            full_body,
            models=["test-model"],
            remaining=budget.available("tokens"),
        )
        assert admitted_req["max_tokens"] == 8192

        serialized_bytes = len(
            json.dumps(
                {"messages": full_body["messages"], "tools": full_body["tools"]},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        for target_headroom in (3500, 260):
            budget.used["tokens"] = budget.limits["tokens"] - (
                serialized_bytes + _FRAMING_RESERVE_TOKENS + target_headroom
            )
            scaled_body = inv._prepare_bounded_body(msgs)
            assert scaled_body["max_tokens"] == target_headroom

        budget.used["tokens"] = budget.limits["tokens"] - 1000
        tight_body = inv._prepare_bounded_body(msgs)
        assert tight_body["max_tokens"] == 2048
    finally:
        client.close()


def test_build_assistant_history_entry_and_both_loops_preserve_reasoning_content(tmp_path: Path) -> None:
    """_build_assistant_history_entry and both tool loops preserve reasoning_content only on tool-call turns."""
    tc = [{"id": "call_1", "type": "function", "function": {"name": "notebook", "arguments": "{}"}}]

    with_tools = _build_assistant_history_entry({
        "role": "assistant",
        "content": None,
        "tool_calls": tc,
        "reasoning_content": "chain-of-thought",
    })
    assert with_tools == {
        "role": "assistant",
        "content": "",
        "tool_calls": tc,
        "reasoning_content": "chain-of-thought",
    }

    empty_reasoning = _build_assistant_history_entry({
        "role": "assistant",
        "content": "ok",
        "tool_calls": tc,
        "reasoning_content": "",
    })
    assert empty_reasoning == {"role": "assistant", "content": "ok", "tool_calls": tc}
    assert "reasoning_content" not in empty_reasoning

    non_str_reasoning = _build_assistant_history_entry({
        "role": "assistant",
        "content": "ok",
        "tool_calls": tc,
        "reasoning_content": None,
    })
    assert "reasoning_content" not in non_str_reasoning

    no_tools = _build_assistant_history_entry({
        "role": "assistant",
        "content": "plain answer",
        "reasoning_content": "should-be-omitted",
    })
    assert no_tools == {"role": "assistant", "content": "plain answer"}
    assert "tool_calls" not in no_tools
    assert "reasoning_content" not in no_tools

    class _LoopTransport:
        def __init__(self, responses: list[dict[str, Any]]) -> None:
            self.session_gate = SessionGate()
            self.provider_responses: list[dict[str, Any]] = []
            self.calls = 0
            self.seen_bodies: list[dict[str, Any]] = []
            self._responses = responses

        def complete(self, body: dict[str, Any], *, minimum_output_tokens: int = 16) -> dict[str, Any]:  # noqa: ARG002
            self.calls += 1
            self.seen_bodies.append(copy.deepcopy(body))
            self.provider_responses.append({"call": self.calls, "upstream_http_status": 200})
            idx = min(self.calls - 1, len(self._responses) - 1)
            return copy.deepcopy(self._responses[idx])

    # 1. Monolithic loop preserves tool-call reasoning_content across turns and omits on non-tool turns.
    mono_dir = tmp_path / "mono"
    mono_dir.mkdir()
    store_m, client_m = _make_investigator_deps(mono_dir)
    budget_m = SharedBudget(http=30, tokens=200_000, seconds=120)
    try:
        mono_transport = _LoopTransport([
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "reasoning_content": "mono-step-1-reasoning",
                        "tool_calls": [{
                            "id": "m1",
                            "type": "function",
                            "function": {"name": "notebook", "arguments": '{"action":"write","surface_notes":"s1"}'},
                        }],
                    }
                }],
                "usage": {"prompt_tokens": 300, "completion_tokens": 40, "total_tokens": 340},
            },
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Thinking without tools.",
                        "reasoning_content": "mono-no-tool-reasoning",
                    }
                }],
                "usage": {"prompt_tokens": 400, "completion_tokens": 20, "total_tokens": 420},
            },
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "reasoning_content": "mono-finish-reasoning",
                        "tool_calls": [{
                            "id": "m3",
                            "type": "function",
                            "function": {"name": "finish", "arguments": '{"summary":"done","untested_areas":[]}'},
                        }],
                    }
                }],
                "usage": {"prompt_tokens": 450, "completion_tokens": 25, "total_tokens": 475},
            },
        ])
        inv_m = AgenticInvestigator(
            http_client=client_m,
            receipt_store=store_m,
            transport=mono_transport,  # type: ignore[arg-type]
            budget=budget_m,
            model="test-model",
            root_dir=mono_dir,
            execution_mode="monolithic",
            max_turns=5,
            sleep_fn=lambda _s: None,
        )
        res_m = inv_m.run()
        assert res_m["status"] == "finished"
        turn2_msgs = mono_transport.seen_bodies[1]["messages"]
        assert turn2_msgs[2]["reasoning_content"] == "mono-step-1-reasoning"
        assert turn2_msgs[2]["content"] == ""
        turn3_msgs = mono_transport.seen_bodies[2]["messages"]
        assert turn3_msgs[2]["reasoning_content"] == "mono-step-1-reasoning"
        assert "reasoning_content" not in turn3_msgs[4]
        assert turn3_msgs[:4] == turn2_msgs
    finally:
        client_m.close()

    # 2. Ephemeral loop records reasoning_content for tool-call steps and omits it on non-tool steps.
    eph_dir = tmp_path / "eph"
    eph_dir.mkdir()
    store_e, client_e = _make_investigator_deps(eph_dir)
    budget_e = SharedBudget(http=30, tokens=200_000, seconds=120)
    try:
        eph_transport = _LoopTransport([
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "reasoning_content": "eph-step-1-reasoning",
                        "tool_calls": [{
                            "id": "e1",
                            "type": "function",
                            "function": {"name": "notebook", "arguments": '{"action":"write","surface_notes":"e1"}'},
                        }],
                    }
                }],
                "usage": {"prompt_tokens": 250, "completion_tokens": 30, "total_tokens": 280},
            },
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Stopping worker.",
                        "reasoning_content": "eph-no-tool-reasoning",
                    }
                }],
                "usage": {"prompt_tokens": 300, "completion_tokens": 15, "total_tokens": 315},
            },
        ])
        inv_e = AgenticInvestigator(
            http_client=client_e,
            receipt_store=store_e,
            transport=eph_transport,  # type: ignore[arg-type]
            budget=budget_e,
            model="test-model",
            root_dir=eph_dir,
            execution_mode="ephemeral",
            use_bsag=False,
            max_turns=2,
            sleep_fn=lambda _s: None,
        )
        captured_worker_msgs: list[list[dict[str, Any]]] = []
        orig_save = inv_e._save_checkpoint

        def _spy_save(*, turn: int, status: str, messages: list[dict[str, Any]]) -> None:
            if messages:
                captured_worker_msgs.append(copy.deepcopy(messages))
            orig_save(turn=turn, status=status, messages=messages)

        inv_e._save_checkpoint = _spy_save  # type: ignore[method-assign]
        inv_e.run()
        assert len(captured_worker_msgs) == 1
        asst_msgs = [m for m in captured_worker_msgs[0] if m.get("role") == "assistant"]
        assert len(asst_msgs) == 2
        assert asst_msgs[0]["reasoning_content"] == "eph-step-1-reasoning"
        assert "reasoning_content" not in asst_msgs[1]
    finally:
        client_e.close()


def test_http400_recovery_strips_reasoning_content_from_assistant_messages(tmp_path: Path) -> None:
    """_sanitize_messages_for_http400 and HTTP 400 retry strip reasoning_content without mutating input."""
    store, client = _make_investigator_deps(tmp_path)
    budget = SharedBudget(http=30, tokens=100_000, seconds=120)
    seen_bodies: list[dict[str, Any]] = []

    class _RejectReasoningContentTransport:
        def __init__(self) -> None:
            self.session_gate = SessionGate()
            self.provider_responses: list[dict[str, Any]] = []
            self.calls = 0

        def complete(self, body: dict[str, Any], *, minimum_output_tokens: int = 16) -> dict[str, Any]:  # noqa: ARG002
            self.calls += 1
            seen_bodies.append(copy.deepcopy(body))
            self.session_gate.require_open()
            ticket = budget.reserve("tokens", 4_000)
            if any("reasoning_content" in m for m in body["messages"]):
                self.session_gate.stop_reason = "provider_http_error"
                self.provider_responses.append({"call": self.calls, "upstream_http_status": 400})
                try:
                    budget.settle(ticket, None, upstream_http_status=400)
                except BudgetError:
                    pass
                raise BudgetError("unsupported message field: reasoning_content", code="provider_http_error")

            budget.settle(ticket, 300, upstream_http_status=200)
            self.provider_responses.append({"call": self.calls, "upstream_http_status": 200})
            return {
                "choices": [{"message": {"role": "assistant", "content": "ok-after-strip"}}],
                "usage": {"prompt_tokens": 250, "completion_tokens": 50, "total_tokens": 300},
            }

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "usr"},
        {
            "role": "assistant",
            "content": "",
            "reasoning_content": "internal-cot",
            "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "http_request", "arguments": "{}"}}],
        },
        _tool_http_message(
            tool_call_id="c1",
            receipt_id="req-0001",
            url="http://127.0.0.1:18080/",
            body_preview="ok",
        ),
    ]
    snapshot = copy.deepcopy(messages)

    direct_sanitized = _sanitize_messages_for_http400(messages)
    assert "reasoning_content" not in direct_sanitized[2]
    assert direct_sanitized[2]["tool_calls"] == messages[2]["tool_calls"]
    assert messages == snapshot

    try:
        transport = _RejectReasoningContentTransport()
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            sleep_fn=lambda _s: None,
        )
        resp = inv._complete_with_retry(messages)
        assert resp["choices"][0]["message"]["content"] == "ok-after-strip"
        assert transport.calls == 2
        assert "reasoning_content" in seen_bodies[0]["messages"][2]
        assert "reasoning_content" not in seen_bodies[1]["messages"][2]
        assert messages == snapshot
    finally:
        client.close()


def test_compact_messages_for_context_strips_stale_reasoning_content() -> None:
    """Compaction drops reasoning_content on older/non-latest/tight turns while keeping latest active-turn verbatim."""
    msgs: list[dict[str, Any]] = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "init"},
    ]
    for turn in (1, 2, 3):
        msgs.append({
            "role": "assistant",
            "content": f"Turn {turn} summary.",
            "reasoning_content": f"R{turn}-" + ("thought " * 20),
            "tool_calls": [{"id": f"c{turn}", "type": "function", "function": {"name": "http_request", "arguments": "{}"}}],
        })
        msgs.append(
            _tool_http_message(
                tool_call_id=f"c{turn}",
                receipt_id=f"req-{turn:04d}",
                url=f"http://127.0.0.1:18080/p/{turn}",
                body_preview=f"body-{turn}",
            )
        )

    # 1. roll_older_turns=False: older_groups and non-latest recent turn strip reasoning_content; latest keeps it.
    inplace = compact_messages_for_context(msgs, keep_recent_turns=2, roll_older_turns=False)
    assert "reasoning_content" not in inplace[2]
    assert "reasoning_content" not in inplace[4]
    assert inplace[6]["reasoning_content"] == msgs[6]["reasoning_content"]

    # 2. roll_older_turns=True (default): rolled older turns dropped, non-latest recent stripped, latest kept.
    rolled = compact_messages_for_context(msgs, keep_recent_turns=2)
    assert "[COMPACTED HISTORY:" in rolled[1]["content"]
    assert "reasoning_content" not in rolled[2]
    assert rolled[4]["reasoning_content"] == msgs[6]["reasoning_content"]

    # 3. Tight compaction (max_recent_tool_chars is not None): latest turn also drops reasoning_content.
    tight = compact_messages_for_context(msgs, keep_recent_turns=2, max_recent_tool_chars=1200)
    assert "reasoning_content" not in tight[2]
    assert "reasoning_content" not in tight[4]

    # 4. keep_recent cutoff: older assistant before cutoff drops reasoning_content even with empty content.
    short_msgs = copy.deepcopy(msgs)
    short_msgs[2]["content"] = ""
    short_msgs[4]["content"] = ""
    cutoff_compacted = compact_messages_for_context(short_msgs, keep_recent=2)
    assert "reasoning_content" not in cutoff_compacted[2]
    assert "reasoning_content" not in cutoff_compacted[4]
    assert cutoff_compacted[6]["reasoning_content"] == msgs[6]["reasoning_content"]
