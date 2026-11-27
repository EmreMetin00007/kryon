"""Unit tests for reasoning_effort defaults, presets, and DeepSeek max-effort gateway routing."""
from __future__ import annotations

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agent_cli  # noqa: E402
import agentic_presets  # noqa: E402
import agentic_report  # noqa: E402
import agentic_runner  # noqa: E402
import llm_config  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from full_agent_budget import BudgetError, SharedBudget  # noqa: E402
from full_agent_provider import SessionGate  # noqa: E402


def _write_vercel_cfg(tmp_path: Path, provider_options: dict[str, Any] | None) -> Path:
    provider: dict[str, Any] = {
        "base_url": "https://ai-gateway.vercel.sh/v1",
        "models": ["deepseek/deepseek-v4.1-flash", "deepseek/deepseek-v4-pro"],
        "api_key_env": "TEST_VERCEL_KEY",
        "api_key_header": "Authorization",
    }
    if provider_options is not None:
        provider["provider_options"] = provider_options
    cfg_path = tmp_path / "llm.vercel.json"
    cfg_path.write_text(
        json.dumps({"schema": llm_config.SCHEMA, "model": "vercel/deepseek/deepseek-v4.1-flash", "providers": {"vercel": provider}}),
        encoding="utf-8",
    )
    return cfg_path


def test_vercel_max_template_is_valid_and_avoids_deepinfra(capsys: pytest.CaptureFixture[str]) -> None:
    tpl = REPO_ROOT / "config" / "llm.vercel-max.example.json"
    data = llm_config.load_config(tpl)
    order = data["providers"]["vercel"]["provider_options"]["gateway"]["order"]
    assert "deepinfra" not in order
    assert order == ["deepseek", "fireworks", "baseten"]

    rc = agent_cli.main(["check-config", "--provider-config", str(tpl)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "valid"
    assert out["model"] == "vercel/deepseek/deepseek-v4.1-flash"


def test_adapt_provider_options_excludes_deepinfra_only_on_max_xhigh_for_deepseek() -> None:
    opts_in = {"gateway": {"order": ["deepinfra", "deepseek", "fireworks"]}}

    # high/low keep deepinfra in place
    opts_high, meta_high = llm_config.adapt_provider_options_for_effort(
        opts_in,
        models=["vercel/deepseek/deepseek-v4.1-flash"],
        provider_name="vercel",
        provider_url="https://ai-gateway.vercel.sh/v1",
        reasoning_effort="high",
    )
    assert opts_high == opts_in
    assert meta_high["adapted"] is False

    # max strips deepinfra and appends baseten fallback
    opts_max, meta_max = llm_config.adapt_provider_options_for_effort(
        opts_in,
        models=["vercel/deepseek/deepseek-v4.1-flash"],
        provider_name="vercel",
        provider_url="https://ai-gateway.vercel.sh/v1",
        reasoning_effort="max",
    )
    assert opts_max == {"gateway": {"order": ["deepseek", "fireworks", "baseten"]}}
    assert meta_max["adapted"] is True
    assert meta_max["excluded_providers"] == ["deepinfra"]
    assert meta_max["gateway_order"] == ["deepseek", "fireworks", "baseten"]

    # unconfigured provider_options on vercel gets max-capable gateway order automatically
    opts_none, meta_none = llm_config.adapt_provider_options_for_effort(
        None,
        models=["vercel/deepseek/deepseek-v4.1-flash"],
        provider_name="vercel",
        provider_url="https://ai-gateway.vercel.sh/v1",
        reasoning_effort="max",
    )
    assert opts_none == {"gateway": {"order": ["deepseek", "fireworks", "baseten"]}}
    assert meta_none["adapted"] is True

    # strict gateway.only=["deepinfra"] fails closed before any spend/traffic
    with pytest.raises(ValueError, match="deepinfra"):
        llm_config.adapt_provider_options_for_effort(
            {"gateway": {"only": ["deepinfra"]}},
            models=["vercel/deepseek/deepseek-v4.1-flash"],
            provider_name="vercel",
            provider_url="https://ai-gateway.vercel.sh/v1",
            reasoning_effort="max",
        )

    # strict gateway.only=["deepinfra", "deepseek"] keeps subset ["deepseek"]
    opts_only, meta_only = llm_config.adapt_provider_options_for_effort(
        {"gateway": {"only": ["deepinfra", "deepseek"]}},
        models=["vercel/deepseek/deepseek-v4.1-flash"],
        provider_name="vercel",
        provider_url="https://ai-gateway.vercel.sh/v1",
        reasoning_effort="xhigh",
    )
    assert opts_only == {"gateway": {"only": ["deepseek"]}}
    assert meta_only["adapted"] is True
    assert meta_only["gateway_only"] == ["deepseek"]


def test_presets_and_runner_default_reasoning_effort_and_gateway_plan(tmp_path: Path) -> None:
    cfg = _write_vercel_cfg(tmp_path, {"gateway": {"order": ["deepinfra", "deepseek", "fireworks"]}})

    # Bare default (no preset) -> max effort & excludes deepinfra from gateway.order
    _, plan_default = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18080/",
        provider_config=cfg,
        output_dir=tmp_path / "plan-default",
        execute=False,
    )
    assert plan_default["reasoning_effort"] == "max"
    assert plan_default["provider_routing"]["adapted"] is True
    assert plan_default["provider_routing"]["gateway_order"] == ["deepseek", "fireworks", "baseten"]

    # Deep preset -> max effort
    _, plan_deep = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18080/",
        provider_config=cfg,
        output_dir=tmp_path / "plan-deep",
        preset="deep",
        execute=False,
    )
    assert plan_deep["reasoning_effort"] == "max"
    assert plan_deep["provider_routing"]["gateway_order"] == ["deepseek", "fireworks", "baseten"]

    # Standard / quick presets -> high / low keep deepinfra in gateway.order
    _, plan_std = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18080/",
        provider_config=cfg,
        output_dir=tmp_path / "plan-std",
        preset="standard",
        execute=False,
    )
    assert plan_std["reasoning_effort"] == "high"
    assert plan_std["provider_routing"]["adapted"] is False
    assert plan_std["provider_routing"]["gateway_order"] == ["deepinfra", "deepseek", "fireworks"]

    _, plan_quick = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18080/",
        provider_config=cfg,
        output_dir=tmp_path / "plan-quick",
        preset="quick",
        execute=False,
    )
    assert plan_quick["reasoning_effort"] == "low"

    # Invalid effort fails closed
    with pytest.raises(ValueError, match="unsupported reasoning_effort"):
        agentic_runner.run_agentic_target(
            target="http://127.0.0.1:18080/",
            provider_config=cfg,
            output_dir=tmp_path / "plan-bad",
            reasoning_effort="ultra",
            execute=False,
        )

    # cco-run/1 config accepts Faz 5 keys
    run_cfg = tmp_path / "run.json"
    run_cfg.write_text(
        json.dumps({
            "schema": agentic_presets.RUN_CONFIG_SCHEMA,
            "preset": "deep",
            "target": "http://127.0.0.1:18080/",
            "provider_config": str(cfg),
            "output_dir": str(tmp_path / "cfg-out"),
            "max_shard_retries": 1,
            "max_retry_shards": 2,
            "retry_budget_ratio": 0.2,
            "retry_model": "vercel/deepseek/deepseek-v4-pro",
        }),
        encoding="utf-8",
    )
    loaded_cfg = agentic_presets.load_run_config(run_cfg)
    assert loaded_cfg["retry_model"] == "vercel/deepseek/deepseek-v4-pro"
    assert loaded_cfg["retry_budget_ratio"] == 0.2


def test_runner_live_sends_adapted_gateway_order_and_status_report_show_routing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    captured_bodies: list[dict[str, Any]] = []

    class _ProviderHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            raw = self.rfile.read(int(self.headers.get("Content-Length") or "0"))
            body = json.loads(raw.decode("utf-8"))
            captured_bodies.append(copy.deepcopy(body))
            msg: dict[str, Any] = {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": f"tc_{len(captured_bodies)}",
                        "type": "function",
                        "function": {"name": "finish", "arguments": '{"summary":"done","untested_areas":[]}'},
                    }
                ],
            }
            if len(captured_bodies) >= 2:
                msg = {"role": "assistant", "content": "done"}
            resp = json.dumps({
                "id": "cmpl-1",
                "choices": [{"message": msg, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

    class _TargetHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            body = b"<html><body><h1>Lab</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    prov_srv = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    tgt_srv = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    threading.Thread(target=prov_srv.serve_forever, daemon=True).start()
    threading.Thread(target=tgt_srv.serve_forever, daemon=True).start()
    try:
        cfg_path = tmp_path / "llm-loopback.json"
        cfg_path.write_text(
            json.dumps({
                "schema": llm_config.SCHEMA,
                "model": "vercel/deepseek/deepseek-v4.1-flash",
                "providers": {
                    "vercel": {
                        "base_url": f"http://127.0.0.1:{prov_srv.server_address[1]}/v1",
                        "models": ["deepseek/deepseek-v4.1-flash"],
                        "api_key_env": "TEST_LOOPBACK_KEY",
                        "api_key_header": "Authorization",
                        "provider_options": {
                            "gateway": {"order": ["deepinfra", "deepseek", "fireworks"]}
                        },
                    }
                },
            }),
            encoding="utf-8",
        )
        monkeypatch.setenv("TEST_LOOPBACK_KEY", "dummy-local-test-val")
        out_dir = tmp_path / "live-out"
        _, manifest = agentic_runner.run_agentic_target(
            target=f"http://127.0.0.1:{tgt_srv.server_address[1]}/",
            provider_config=cfg_path,
            output_dir=out_dir,
            execution_mode="monolithic",
            max_turns=3,
            http_budget=10,
            token_budget=50_000,
            seconds_budget=30,
            reasoning_effort="max",
            execute=True,
        )
        assert captured_bodies
        assert captured_bodies[0]["reasoning_effort"] == "max"
        assert captured_bodies[0]["providerOptions"]["gateway"]["order"] == ["deepseek", "fireworks", "baseten"]
        assert manifest["reasoning_effort"] == "max"
        assert manifest["provider_routing"]["excluded_providers"] == ["deepinfra"]

        rc = agent_cli.main(["status", str(out_dir)])
        assert rc == 0
        status_doc = json.loads(capsys.readouterr().out)
        assert status_doc["reasoning_effort"] == "max"
        assert status_doc["provider_routing"]["gateway_order"] == ["deepseek", "fireworks", "baseten"]

        md_text = agentic_report.render_markdown_report(agentic_report.load_run_artifacts(out_dir))
        assert "reasoning_effort=`max`" in md_text
        assert "gateway.order=`deepseek,fireworks,baseten`" in md_text
    finally:
        prov_srv.shutdown()
        prov_srv.server_close()
        tgt_srv.shutdown()
        tgt_srv.server_close()


def test_http400_recovery_steps_down_max_to_high_when_content_unchanged(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path)
    actors = ActorManager([{"alias": "anon", "role": "anonymous", "tenant": "public"}])
    client = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET",),
        max_requests=10,
    )
    budget = SharedBudget(http=10, tokens=100_000, seconds=60)
    seen_bodies: list[dict[str, Any]] = []

    class _RejectMaxTransport:
        def __init__(self) -> None:
            self.session_gate = SessionGate()
            self.provider_responses: list[dict[str, Any]] = []
            self.calls = 0

        def complete(self, body: dict[str, Any], *, minimum_output_tokens: int = 16) -> dict[str, Any]:  # noqa: ARG002
            self.calls += 1
            seen_bodies.append(copy.deepcopy(body))
            self.session_gate.require_open()
            ticket = budget.reserve("tokens", 3_000)
            if body.get("reasoning_effort") == "max":
                self.session_gate.stop_reason = "provider_http_error"
                self.provider_responses.append({"call": self.calls, "upstream_http_status": 400})
                try:
                    budget.settle(ticket, None, upstream_http_status=400)
                except BudgetError:
                    pass
                raise BudgetError("unsupported reasoning_effort=max", code="provider_http_error")
            budget.settle(ticket, 200, upstream_http_status=200)
            self.provider_responses.append({"call": self.calls, "upstream_http_status": 200})
            return {
                "choices": [{"message": {"role": "assistant", "content": "recovered-at-high"}}],
                "usage": {"prompt_tokens": 150, "completion_tokens": 50, "total_tokens": 200},
            }

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_RejectMaxTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="deepseek/deepseek-v4.1-flash",
            root_dir=tmp_path,
            reasoning_effort="max",
            sleep_fn=lambda _s: None,
        )
        resp = inv._complete_with_retry([{"role": "user", "content": "clean prompt"}])
        assert resp["choices"][0]["message"]["content"] == "recovered-at-high"
        assert len(seen_bodies) == 2
        assert seen_bodies[0]["reasoning_effort"] == "max"
        assert seen_bodies[1]["reasoning_effort"] == "high"
    finally:
        client.close()
