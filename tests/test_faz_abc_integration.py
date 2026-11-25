"""End-to-end integration tests wiring Faz A (recon), Faz B (prescan), and Faz C (HAR flows, multi-origin auth, WAF pivot)."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import agent_cli  # noqa: E402
import agentic_investigator  # noqa: E402
import agentic_runner  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import ToolDispatcher  # noqa: E402


def test_agent_cli_recon_plan_mode_zero_traffic(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out_dir = tmp_path / "recon-plan"
    rc = agent_cli.main([
        "recon",
        "--target", "http://127.0.0.1:18080/",
        "--output-dir", str(out_dir),
    ])
    assert rc == 0
    stdout = capsys.readouterr().out
    doc = json.loads(stdout)
    assert doc["mode"] == "plan_only"
    assert (out_dir / "recon-plan.json").is_file()


def test_presets_and_runner_plan_wire_prescan_har_flows_and_multi_origin_storage_state(
    tmp_path: Path,
) -> None:
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(
        json.dumps({
            "in_scope": ["https://www.shop.example", "https://api.shop.example"],
            "out_of_scope": ["https://payments.thirdparty.example"],
        }),
        encoding="utf-8",
    )
    har_path = tmp_path / "flow.har"
    har_path.write_text(
        json.dumps({
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "startedDateTime": "2026-11-25T10:00:00Z",
                        "request": {
                            "method": "POST",
                            "url": "https://api.shop.example/api/v1/cart",
                            "headers": [
                                {"name": "Authorization", "value": "Bearer SUPER_SECRET_TOKEN_12345"},
                                {"name": "X-Storefront", "value": "web-tr"},
                                {"name": "Content-Type", "value": "application/json"},
                            ],
                            "postData": {
                                "mimeType": "application/json",
                                "text": json.dumps({"sku": "SKU-1", "qty": 1}),
                            },
                        },
                        "response": {
                            "status": 201,
                            "content": {
                                "mimeType": "application/json",
                                "text": json.dumps({"cartId": "cart-9001"}),
                            },
                        },
                    },
                    {
                        "startedDateTime": "2026-11-25T10:00:02Z",
                        "request": {
                            "method": "POST",
                            "url": "https://api.shop.example/api/v1/cart/cart-9001/checkout",
                            "headers": [
                                {"name": "X-Storefront", "value": "web-tr"},
                                {"name": "Content-Type", "value": "application/json"},
                            ],
                            "postData": {
                                "mimeType": "application/json",
                                "text": json.dumps({"coupon": "SAVE10", "totalPrice": 100}),
                            },
                        },
                        "response": {
                            "status": 200,
                            "content": {
                                "mimeType": "application/json",
                                "text": json.dumps({"orderId": "ord-777"}),
                            },
                        },
                    },
                ],
            }
        }),
        encoding="utf-8",
    )
    storage_path = tmp_path / "member.storage.json"
    storage_path.write_text(
        json.dumps({
            "cookies": [
                {
                    "name": "session_web",
                    "value": "web-secret-cookie",
                    "domain": "www.shop.example",
                    "path": "/",
                },
                {
                    "name": "session_api",
                    "value": "api-secret-cookie",
                    "domain": "api.shop.example",
                    "path": "/",
                },
                {
                    "name": "third_party",
                    "value": "must-drop",
                    "domain": "payments.thirdparty.example",
                    "path": "/",
                },
            ],
            "origins": [],
        }),
        encoding="utf-8",
    )

    out_dir = tmp_path / "bounty-plan"
    plan_path, plan = agentic_runner.run_agentic_target(
        target="https://www.shop.example/",
        scope_file=scope_path,
        allow_non_loopback=True,
        provider_config=REPO_ROOT / "config" / "llm.example.json",
        output_dir=out_dir,
        preset="bounty-safe",
        seed_surface_files=[har_path],
        storage_states=[f"member:member:t1={storage_path}"],
        execute=False,
    )
    assert plan_path.is_file()
    assert plan["prescan"]["enabled"] is True
    assert plan["prescan"]["max_requests"] == 16
    assert plan["har_flows"] is not None
    assert plan["har_flows"]["flows_count"] >= 1
    assert plan["har_flows"]["chained_steps_count"] >= 1
    assert any(acc["alias"] == "member" for acc in plan["selected_accounts"])
    serialized = json.dumps(plan)
    assert "SUPER_SECRET_TOKEN_12345" not in serialized
    assert "web-secret-cookie" not in serialized
    assert "api-secret-cookie" not in serialized


def test_tool_dispatcher_emits_waf_pivot_guidance_after_repeated_waf_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipts = ReceiptStore(tmp_path)
    actors = ActorManager([])
    http = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080",
        receipt_store=receipts,
        actors=actors,
        allowed_methods=["GET"],
        max_requests=10,
    )

    counter = {"n": 0}

    def _fake_request(**kwargs: Any) -> dict[str, Any]:
        counter["n"] += 1
        rid = f"r-{counter['n']}"
        body = "<html>Attention Required! | Cloudflare Error 1020</html>"
        rec = {
            "receipt_id": rid,
            "actor": kwargs.get("actor", "anon"),
            "method": kwargs.get("method", "GET"),
            "url": f"http://127.0.0.1:18080{kwargs.get('url', '/')}",
            "path": kwargs.get("url", "/"),
            "status": 403,
            "elapsed_ms": 12,
            "content_type": "text/html; charset=utf-8",
            "response_length": len(body),
            "response_headers": {"cf-mitigated": "challenge", "server": "cloudflare"},
            "body": body,
            "request_headers": {},
        }
        return rec

    monkeypatch.setattr(http, "request", _fake_request)
    dispatcher = ToolDispatcher(
        http_client=http,
        receipt_store=receipts,
        root_dir=tmp_path,
    )

    first_raw = dispatcher._tool_http_request({"method": "GET", "url": "/search?q=1"})
    assert "waf_block" in first_raw
    assert "waf_pivot_guidance" not in first_raw

    second_raw = dispatcher._tool_http_request({"method": "GET", "url": "/search?q=2"})
    assert "waf_block" in second_raw
    assert "waf_pivot_guidance" in second_raw
    assert "replay_as" in second_raw


def test_investigator_initial_priority_brief_combines_prescan_and_har_handoffs(
    tmp_path: Path,
) -> None:
    receipts = ReceiptStore(tmp_path)
    http = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080",
        receipt_store=receipts,
        actors=ActorManager([]),
        allowed_methods=["GET"],
        max_requests=10,
    )

    class _DummyTransport:
        calls = 0

    class _DummyBudget:
        limits = {"tokens": 100_000}

    inv = agentic_investigator.AgenticInvestigator(
        http_client=http,
        receipt_store=receipts,
        transport=_DummyTransport(),  # type: ignore[arg-type]
        budget=_DummyBudget(),  # type: ignore[arg-type]
        model="dummy-model",
        root_dir=tmp_path,
        prescan_handoff="[PRESCAN LEADS] high bola_candidate /api/orders/1",
        har_flows_handoff="HAR Multi-Step Flows: flow_1 POST /api/cart -> POST /api/checkout",
    )
    brief = inv._initial_priority_brief()
    assert "[PRESCAN LEADS]" in brief
    assert "HAR Multi-Step Flows" in brief
