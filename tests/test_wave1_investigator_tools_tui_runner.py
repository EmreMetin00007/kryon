"""Targeted Wave 1 tests for agentic_investigator, agentic_tools, agentic_tui, and agentic_runner."""
from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_context import _FRAMING_RESERVE_TOKENS  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
import agentic_investigator  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
import agentic_runner  # noqa: E402
import agentic_tools  # noqa: E402
from agentic_tools import ToolDispatcher  # noqa: E402
import agentic_tui  # noqa: E402
from agentic_waf import WAFPivotTracker  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import SessionGate  # noqa: E402


def _make_fake_jwt(payload: dict[str, Any]) -> str:
    def _b64(obj: dict[str, Any]) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64(payload)}.fakesignature1234"


class _DummyTransport:
    def __init__(self, responses: list[dict[str, Any]] | None = None) -> None:
        self.session_gate = SessionGate()
        self.provider_responses: list[dict[str, Any]] = []
        self.provider_lock = threading.Lock()
        self.calls = 0
        self._responses = list(responses or [])
        self.recorded_bodies: list[dict[str, Any]] = []

    def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        self.recorded_bodies.append(body)
        idx = self.calls
        self.calls += 1
        if idx < len(self._responses):
            return self._responses[idx]
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": f"call_fin_{idx}",
                                "type": "function",
                                "function": {"name": "finish", "arguments": '{"summary":"done"}'},
                            }
                        ],
                    }
                }
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
        }

    def close_upstream(self) -> None:
        return


def _multi_cluster_seed_surface(base_url: str = "http://127.0.0.1:18080") -> dict[str, Any]:
    """Return >= 8 distinct route templates across 2 families so clustering creates 2 shards."""
    return {
        "links": [
            {"method": "GET", "url": f"{base_url}/api/orders/1"},
            {"method": "POST", "url": f"{base_url}/api/orders"},
            {"method": "GET", "url": f"{base_url}/api/orders/history"},
            {"method": "GET", "url": f"{base_url}/api/orders/export"},
            {"method": "GET", "url": f"{base_url}/api/invoices/1"},
            {"method": "POST", "url": f"{base_url}/api/invoices"},
            {"method": "GET", "url": f"{base_url}/api/invoices/pdf"},
            {"method": "GET", "url": f"{base_url}/api/invoices/status"},
        ]
    }


def _make_deps(
    tmp_path: Path,
    *,
    base_url: str = "http://127.0.0.1:18080",
    in_scope_assets: tuple[str, ...] = (),
    out_of_scope_assets: tuple[str, ...] = (),
    excluded_paths: tuple[str, ...] = (),
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "POST", "PUT", "DELETE", "HEAD"),
    http_limit: int = 120,
    tokens_limit: int = 300_000,
) -> tuple[ReceiptStore, AgenticHTTPClient, SharedBudget]:
    store = ReceiptStore(tmp_path)
    actors = ActorManager(accounts or [])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=http_limit,
        in_scope_assets=in_scope_assets,
        out_of_scope_assets=out_of_scope_assets,
        excluded_paths=excluded_paths,
    )
    budget = SharedBudget(http=http_limit, tokens=tokens_limit, seconds=600)
    return store, client, budget


# ---------------------------------------------------------------------------
# 1. Investigator: _fits_epoch_budget token-vs-byte, WAFPivot, handoffs, OOB, resume, cancel
# ---------------------------------------------------------------------------


def test_prepare_bounded_body_token_vs_byte_48kb_fits_in_30k_tokens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import full_agent_budget

    class _FakeEncoder:
        def encode_ordinary(self, text: str) -> list[int]:
            return [0] * max(1, (len(text) + 3) // 4)

    store, client, budget = _make_deps(tmp_path, tokens_limit=100_000)
    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            execution_mode="monolithic",
            epoch_char_limit=80_000,
        )
        # Build ~48KB payload across turns (< 80KB epoch_char_limit, ~12K calibrated tokens)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "sys " + ("s" * 1000)},
            {"role": "user", "content": "user " + ("u" * 1000)},
        ]
        for idx in range(1, 10):
            messages.append({
                "role": "assistant",
                "content": "step",
                "tool_calls": [
                    {
                        "id": f"c{idx}",
                        "type": "function",
                        "function": {"name": "http_request", "arguments": '{"url":"/x"}'},
                    }
                ],
            })
            messages.append({
                "role": "tool",
                "tool_call_id": f"c{idx}",
                "content": "A" * 4400,
            })

        # 1. With calibrated local tokenizer, ~48KB (~12K tokens * 1.5x + framing) fits in 30K tokens
        # AND matches completion_request admission exactly (zero BudgetError mismatch).
        monkeypatch.setattr(full_agent_budget, "local_encoder", lambda _cache: _FakeEncoder())
        budget.used["tokens"] = 70_000  # avail = 30_000 tokens
        body = inv._prepare_bounded_body(messages)
        ser_raw = json.dumps(
            {"messages": body["messages"], "tools": body["tools"]},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        ser_bytes = len(ser_raw)
        assert 40_000 <= ser_bytes <= 80_000
        assert inv._epoch_turn_start == 0
        admitted_req, _reserved = full_agent_budget.completion_request(
            body,
            models=["test-model"],
            remaining=budget.available("tokens"),
        )
        assert admitted_req["max_tokens"] >= 8000

        # 2. Separate byte check: shrinking epoch_char_limit below ser_bytes DOES advance epoch even when tokens=100K
        budget.used["tokens"] = 0
        inv.epoch_char_limit = 24_000
        _ = inv._prepare_bounded_body(messages)
        assert inv._epoch_turn_start > 0
    finally:
        client.close()


def test_waf_pivot_shared_across_shards_banner_and_checkpoint(tmp_path: Path) -> None:
    store, client, budget = _make_deps(tmp_path, tokens_limit=500_000)
    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            execution_mode="sharded",
            initial_waf_vendors=["cloudflare"],
        )
        assert inv.dispatcher.waf_pivot.total_blocks == 1
        assert inv.dispatcher.waf_pivot.should_pivot() is False

        # One more block hits threshold=2 and renders in _state_banner
        inv.dispatcher.waf_pivot.record_block("cloudflare", "/api/v1/orders/42")
        assert inv.dispatcher.waf_pivot.should_pivot() is True
        banner = inv._state_banner(2)
        assert "[WAF-PIVOT]" in banner
        assert "cloudflare" in banner.lower()

        # Checkpoint save & restore preserves exact waf_pivot counts without double counting initial_waf_vendors
        inv._save_checkpoint(turn=2, status="in_progress", messages=[{"role": "user", "content": "hi"}])

        inv2 = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            execution_mode="sharded",
            initial_waf_vendors=["cloudflare"],
        )
        loaded = inv2._load_checkpoint()
        assert loaded is not None
        assert inv2.dispatcher.waf_pivot.total_blocks == 2
        assert inv2.dispatcher.waf_pivot.should_pivot() is True
        assert inv2.dispatcher.waf_pivot.summary()["vendors"] == {"cloudflare": 2}
    finally:
        client.close()


def test_handoffs_delivered_to_stage2_stage3_continuation_and_scout_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, client, budget = _make_deps(tmp_path, tokens_limit=500_000)
    try:
        # 1. Seed multi-cluster surface so _run_sharded triggers Stage 2 + Stage 3
        seed_surface = _multi_cluster_seed_surface()
        prescan_text = "[PRESCAN LEADS] GET /api/orders/1 possible BOLA"
        har_text = "HAR Multi-Step Flows: /checkout -> /pay"
        ag_text = "[ASSET GRAPH] api.target.local"

        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="deep-model",
            scout_model="scout-model",
            bootstrap_model="boot-model",
            root_dir=tmp_path,
            execution_mode="sharded",
            seed_surface=seed_surface,
            prescan_handoff=prescan_text,
            har_flows_handoff=har_text,
            asset_graph_handoff=ag_text,
            initial_waf_vendors=["cloudflare", "cloudflare"],
        )

        # Phase 2 scout->deep handoff includes all 3 handoffs + active WAF pivot
        _, p2_usr = inv._build_handoff_packet(reason="scout_finished", next_turn=5)
        assert prescan_text in p2_usr
        assert har_text in p2_usr
        assert ag_text in p2_usr
        assert "[WAF-PIVOT]" in p2_usr

        # Capture Stage 2 shard prompts + Stage 3 synthesis prompts via _run_sharded
        captured_shard_prompts: list[str] = []
        captured_s3_prompts: list[str] = []
        shared_pivots_seen: list[WAFPivotTracker] = []

        orig_exec = inv._execute_monolithic_loop

        def _spy_exec(**kwargs: Any) -> tuple[str, int, list[dict[str, Any]]]:
            disp = kwargs["dispatcher"]
            shared_pivots_seen.append(disp.waf_pivot)
            msgs = kwargs["messages"]
            if kwargs.get("shard_cluster") is not None:
                captured_shard_prompts.append(msgs[0]["content"] + "\n" + msgs[1]["content"])
            elif disp.active_worker_id == "stage3-synthesis":
                captured_s3_prompts.append(msgs[0]["content"] + "\n" + msgs[1]["content"])
            return "finished", int(kwargs.get("start_turn", 1)), msgs

        monkeypatch.setattr(inv, "_execute_monolithic_loop", _spy_exec)
        monkeypatch.setattr(
            agentic_investigator,
            "collect_cross_shard_synthesis_context",
            lambda **_kw: {"should_trigger": True, "findings": [], "internal_urls": [], "extracted_values": [], "auth_capabilities": [], "blockers": [], "untested_writes_and_blocked": [], "high_risk_unprobed_routes": []},
        )
        res = inv.run(resume=False)
        assert res["status"] == "finished"
        assert len(captured_shard_prompts) >= 2
        for prompt in captured_shard_prompts:
            assert prescan_text in prompt
            assert har_text in prompt
            assert ag_text in prompt
            assert "cloudflare" in prompt.lower()
        assert len(captured_s3_prompts) == 1
        assert prescan_text in captured_s3_prompts[0]
        assert har_text in captured_s3_prompts[0]
        assert ag_text in captured_s3_prompts[0]
        assert "cloudflare" in captured_s3_prompts[0].lower()
        assert all(p is inv.dispatcher.waf_pivot for p in shared_pivots_seen)

        # 2. Single-cluster continuation after bootstrap_discovery_only delivers handoffs
        out_single = tmp_path / "single"
        out_single.mkdir()
        store2, client2, budget2 = _make_deps(out_single, tokens_limit=500_000)
        try:
            inv_single = AgenticInvestigator(
                http_client=client2,
                receipt_store=store2,
                transport=_DummyTransport(),  # type: ignore[arg-type]
                budget=budget2,
                model="deep-model",
                bootstrap_model="boot-model",
                root_dir=out_single,
                execution_mode="sharded",
                max_turns=12,
                bootstrap_turns=4,
                prescan_handoff=prescan_text,
                har_flows_handoff=har_text,
                asset_graph_handoff=ag_text,
                initial_waf_vendors=["aws_waf", "aws_waf"],
            )
            cont_prompts: list[str] = []

            def _spy_single(**kwargs: Any) -> tuple[str, int, list[dict[str, Any]]]:
                if kwargs.get("excluded_tools") is None:
                    cont_prompts.append(kwargs["messages"][1]["content"])
                return "finished", int(kwargs.get("start_turn", 1)), kwargs["messages"]

            monkeypatch.setattr(inv_single, "_execute_monolithic_loop", _spy_single)
            monkeypatch.setattr(agentic_investigator, "cluster_discovered_surface", lambda *_a, **_kw: [])
            res_single = inv_single.run(resume=False)
            assert res_single["status"] == "finished"
            assert len(cont_prompts) == 1
            assert prescan_text in cont_prompts[0]
            assert har_text in cont_prompts[0]
            assert ag_text in cont_prompts[0]
            assert "[WAF-PIVOT]" in cont_prompts[0]
        finally:
            client2.close()
        _ = orig_exec
    finally:
        client.close()


def test_shared_oob_server_persists_across_shards_and_closes_on_run_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, client, budget = _make_deps(tmp_path, tokens_limit=500_000)
    try:
        seed_surface = _multi_cluster_seed_surface()
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            execution_mode="sharded",
            seed_surface=seed_surface,
            oob_server=None,
        )
        created_srv_ref: list[Any] = []
        poll_results: list[dict[str, Any]] = []

        def _fake_exec(**kwargs: Any) -> tuple[str, int, list[dict[str, Any]]]:
            disp = kwargs["dispatcher"]
            cluster = kwargs.get("shard_cluster")
            if cluster is not None and cluster.shard_id == "shard-1":
                cb = json.loads(disp.dispatch("callback_listener", {"action": "create_url", "label": "s1"}))
                created_srv_ref.append((disp._get_oob_server(start=False), cb["token"]))
            elif disp.active_worker_id == "stage3-synthesis":
                srv = disp._get_oob_server(start=False)
                assert srv is not None and srv.is_running
                assert srv is created_srv_ref[0][0]
                poll_doc = json.loads(
                    disp.dispatch("callback_listener", {"action": "poll", "token": created_srv_ref[0][1]})
                    .split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1]
                    .rsplit("\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1)[0]
                )
                poll_results.append(poll_doc)
            return "finished", int(kwargs.get("start_turn", 1)), kwargs["messages"]

        monkeypatch.setattr(inv, "_execute_monolithic_loop", _fake_exec)
        monkeypatch.setattr(
            agentic_investigator,
            "collect_cross_shard_synthesis_context",
            lambda **_kw: {"should_trigger": True, "findings": [], "internal_urls": [], "extracted_values": [], "auth_capabilities": [], "blockers": [], "untested_writes_and_blocked": [], "high_risk_unprobed_routes": []},
        )
        res = inv.run(resume=False)
        assert res["status"] == "finished"
        assert len(created_srv_ref) == 1
        assert len(poll_results) == 1
        assert poll_results[0]["registered"] is True
        # Closed once investigator run exits
        assert created_srv_ref[0][0].is_running is False
    finally:
        client.close()


def test_sharded_resume_skips_stage1_and_completed_shards_and_rescues_mid_stage2_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, client, budget = _make_deps(tmp_path, tokens_limit=500_000)
    try:
        seed_surface = _multi_cluster_seed_surface()
        cancel_ev = threading.Event()
        inv1 = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            execution_mode="sharded",
            seed_surface=seed_surface,
            cancel_event=cancel_ev,
            enable_telemetry=True,
        )
        run1_stages: list[str] = []

        def _run1_exec(**kwargs: Any) -> tuple[str, int, list[dict[str, Any]]]:
            disp = kwargs["dispatcher"]
            cluster = kwargs.get("shard_cluster")
            if cluster is None:
                run1_stages.append("stage1")
                return "finished", 1, kwargs["messages"]
            run1_stages.append(cluster.shard_id)
            finding_stub = {
                "finding_id": "F-001",
                "title": f"Finding in {cluster.shard_id}",
                "class_type": "bola",
                "route_template": f"/api/{cluster.families[0]}/{{id}}",
                "method": "GET",
                "url": f"http://127.0.0.1:18080/api/{cluster.families[0]}/1",
                "path": f"/api/{cluster.families[0]}/1",
                "actor": "member-a",
                "evidence_value": "secret_val_123",
                "proof_receipt_ids": [],
                "control_receipt_ids": [],
            }
            disp.findings.append(finding_stub)
            disp._save_findings()
            if cluster.shard_id == "shard-1":
                return "finished", 1, kwargs["messages"]
            cancel_ev.set()
            return "interrupted", 1, kwargs["messages"]

        monkeypatch.setattr(inv1, "_execute_monolithic_loop", _run1_exec)
        res1 = inv1.run(resume=False)
        assert res1["status"] == "interrupted"
        assert "stage1" in run1_stages
        assert (tmp_path / "findings.json").is_file()
        rescued = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
        # Both shard-1 and partial shard-2 findings were rescued into root findings.json
        assert len(rescued) == 2

        # Resume run: Stage 1 and shard-1 MUST be skipped, only shard-2 runs
        inv2 = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            execution_mode="sharded",
            seed_surface=seed_surface,
            enable_cross_shard_synthesis=False,
        )
        run2_stages: list[str] = []

        def _run2_exec(**kwargs: Any) -> tuple[str, int, list[dict[str, Any]]]:
            cluster = kwargs.get("shard_cluster")
            run2_stages.append(cluster.shard_id if cluster is not None else "stage1")
            return "finished", 1, kwargs["messages"]

        monkeypatch.setattr(inv2, "_execute_monolithic_loop", _run2_exec)
        res2 = inv2.run(resume=True)
        assert res2["status"] == "finished"
        assert run2_stages == ["shard-2"]
    finally:
        client.close()


def test_stage2_keyboard_interrupt_still_rescues_shard_findings_and_emits_token_usage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, client, budget = _make_deps(tmp_path, tokens_limit=500_000)
    try:
        # 1. Live token_usage telemetry emission in _execute_monolithic_loop
        transport = _DummyTransport()
        inv_mono = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path / "mono",
            execution_mode="monolithic",
            enable_telemetry=True,
        )
        res_mono = inv_mono.run(resume=False)
        assert res_mono["status"] == "finished"
        telem_lines = [
            json.loads(line)
            for line in (tmp_path / "mono" / "telemetry.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        tok_events = [ev for ev in telem_lines if ev.get("event") == "token_usage"]
        assert len(tok_events) == 1
        assert tok_events[0]["turn"] == 1
        assert tok_events[0]["total_tokens"] == 120
        assert tok_events[0]["llm_calls"] == 1

        # 2. KeyboardInterrupt during Stage 2 ThreadPoolExecutor rescues shards/*/findings.json
        sharded_dir = tmp_path / "kbd"
        sharded_dir.mkdir()
        store2, client2, budget2 = _make_deps(sharded_dir, tokens_limit=500_000)
        try:
            seed_surface = _multi_cluster_seed_surface()
            inv_sh = AgenticInvestigator(
                http_client=client2,
                receipt_store=store2,
                transport=_DummyTransport(),  # type: ignore[arg-type]
                budget=budget2,
                model="test-model",
                root_dir=sharded_dir,
                execution_mode="sharded",
                seed_surface=seed_surface,
            )

            def _kbd_exec(**kwargs: Any) -> tuple[str, int, list[dict[str, Any]]]:
                disp = kwargs["dispatcher"]
                cluster = kwargs.get("shard_cluster")
                if cluster is None:
                    return "finished", 1, kwargs["messages"]
                disp.findings.append({
                    "finding_id": "F-001",
                    "title": f"Rescued from {cluster.shard_id}",
                    "class_type": "bola",
                    "route_template": f"/api/{cluster.families[0]}/{{id}}",
                    "method": "GET",
                    "url": f"http://127.0.0.1:18080/api/{cluster.families[0]}/1",
                    "path": f"/api/{cluster.families[0]}/1",
                    "actor": "member-a",
                    "evidence_value": "rescued_tok_999",
                })
                disp._save_findings()
                if cluster.shard_id == "shard-2":
                    raise KeyboardInterrupt()
                return "finished", 1, kwargs["messages"]

            monkeypatch.setattr(inv_sh, "_execute_monolithic_loop", _kbd_exec)
            with pytest.raises(KeyboardInterrupt):
                inv_sh.run(resume=False)
            saved_root = json.loads((sharded_dir / "findings.json").read_text(encoding="utf-8"))
            assert len(saved_root) == 2
        finally:
            client2.close()
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 2. TUI: SharedBudget.snapshot(), class_type, shard findings, telemetry llm_calls, terminal statuses
# ---------------------------------------------------------------------------


def test_tui_load_run_snapshot_nested_budget_class_type_shards_and_terminals(tmp_path: Path) -> None:
    run_dir = tmp_path / "tui-nested"
    run_dir.mkdir(parents=True)
    budget = SharedBudget(http=150, tokens=250_000, seconds=600)
    budget.used["http"] = 28
    budget.used["tokens"] = 44_000
    snap_doc = budget.snapshot()

    (run_dir / "manifest.json").write_text(
        json.dumps({
            "schema": "agentic-target-run/1",
            "mode": "agentic",
            "status": "finished",
            "target": "http://127.0.0.1:19000/",
            "limits": {"http_requests": 150, "llm_tokens": 250_000, "seconds": 600},
            "budget": snap_doc,
            "sharding_summary": {
                "shards": [
                    {"shard_id": "shard-1", "status": "finished", "turns": 5, "findings": 2},
                    {"shard_id": "shard-2", "status": "budget_exhausted", "turns": 3, "findings": 0},
                ]
            },
        }),
        encoding="utf-8",
    )
    private_dir = run_dir / "private"
    private_dir.mkdir()
    budget.used["http"] = 35
    budget.used["tokens"] = 51_500
    (private_dir / "budget.json").write_text(json.dumps(budget.snapshot()), encoding="utf-8")

    (run_dir / "findings.json").write_text(
        json.dumps([
            {
                "severity": "high",
                "class_type": "bola",
                "method": "GET",
                "path": "/api/orders/9",
                "actor": "member-a",
                "proof_receipt_ids": ["req-0005"],
            }
        ]),
        encoding="utf-8",
    )
    (run_dir / "telemetry.jsonl").write_text(
        "\n".join([
            json.dumps({"event": "token_usage", "turn": 1, "total_tokens": 1200, "llm_calls": 1}),
            json.dumps({"event": "token_usage", "turn": 2, "total_tokens": 55_000, "llm_calls": 7}),
            json.dumps({"event": "llm_turn", "turn": 3}),
        ]) + "\n",
        encoding="utf-8",
    )

    snap = agentic_tui.load_run_snapshot(run_dir)
    assert snap.http_limit == 150
    assert snap.tokens_limit == 250_000
    assert snap.http_used == 35
    assert snap.tokens_used == 55_000
    assert snap.seconds_used >= 0.0
    assert snap.llm_calls == 7
    assert snap.shards[0]["findings"] == 2
    assert snap.shards[1]["findings"] == 0
    assert snap.findings[0]["vuln_class"] == "bola"

    for term in ("finished", "max_turns_reached", "budget_exhausted", "http_budget_exhausted"):
        assert term in agentic_tui.TERMINAL_STATUSES

    # watch_run_dir exits immediately without sleeping when status == "finished"
    rc = agentic_tui.watch_run_dir(
        run_dir,
        refresh_seconds=0.1,
        plain=True,
        exit_on_complete=True,
        sleep_fn=lambda _s: pytest.fail("must not sleep on finished terminal status"),
    )
    assert rc == 0


# ---------------------------------------------------------------------------
# 3. Tools: localStorage JWT, JSON-escaped evidence, open_redirect sibling origin,
#           Origin: null CORS, concurrent_check burst/WAF/id, live dedup (origin, route, graphql_op)
# ---------------------------------------------------------------------------


def test_tools_analyze_token_local_storage_and_receipt_contains_evidence_json_escapes(tmp_path: Path) -> None:
    jwt_ls = _make_fake_jwt({"sub": "spa-user-1", "role": "editor"})
    jwt_origin = _make_fake_jwt({"sub": "origin-user-2", "role": "admin"})
    accounts = [
        {
            "alias": "spa-actor",
            "role": "member",
            "local_storage": {"auth_state": json.dumps({"access_token": jwt_ls})},
        },
        {
            "alias": "origin-actor",
            "role": "member",
        },
    ]
    store, client, _ = _make_deps(tmp_path, accounts=accounts)
    try:
        # Also simulate optional local_storage_by_origin attribute on ActorSession
        sess_origin = client.actors.get("origin-actor")
        setattr(sess_origin, "local_storage_by_origin", {"https://app.example.test": {"token": jwt_origin}})

        disp = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path)
        res1 = json.loads(disp.dispatch("analyze_token", {"value": "actor:spa-actor"}))
        assert res1["valid_jwt"] is True
        assert res1["payload"]["sub"] == "spa-user-1"

        res2 = json.loads(disp.dispatch("analyze_token", {"value": "actor:origin-actor"}))
        assert res2["valid_jwt"] is True
        assert res2["payload"]["sub"] == "origin-user-2"

        # _receipt_contains_evidence: JSON-escaped unicode/slashes/quotes and pretty-printed JSON compaction
        esc_rec = {
            "receipt_id": "req-0001",
            "url": "http://127.0.0.1:18080/api/preview",
            "body": '{\n  "html": "\\u003cscript\\u003ealert(1)\\u003c\\/script\\u003e",\n  "note": "say \\"secret_ok\\""\n}',
            "response_headers": {},
        }
        assert disp._receipt_contains_evidence(esc_rec, "<script>alert(1)</script>")[0] is True
        assert disp._receipt_contains_evidence(esc_rec, 'say "secret_ok"')[0] is True
        assert disp._receipt_contains_evidence(
            esc_rec,
            '{"html":"<script>alert(1)</script>","note":"say \\"secret_ok\\""}',
        )[0] is True
    finally:
        client.close()


def test_tools_open_redirect_sibling_origin_cors_null_and_live_dedup_origin_graphql(tmp_path: Path) -> None:
    store, client, _ = _make_deps(
        tmp_path,
        base_url="https://app.target.example",
        in_scope_assets=("https://auth.target.example", "https://api.target.example"),
        accounts=[{"alias": "member-a", "role": "member"}],
    )
    try:
        disp = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path, oracle=None)

        # Record receipts directly into ReceiptStore
        r_sibling = store.record(
            actor="anon",
            method="GET",
            url="https://app.target.example/redir?next=https://auth.target.example/cb",
            path="/redir",
            query="next=https://auth.target.example/cb",
            request_headers={},
            request_body="",
            status=302,
            elapsed_ms=5.0,
            response_headers={"Location": "https://auth.target.example/cb"},
            content_type="text/plain",
            response_text="",
            redirect_location="https://auth.target.example/cb",
        )
        r_ext = store.record(
            actor="anon",
            method="GET",
            url="https://app.target.example/redir?next=https://evil.example/phish",
            path="/redir",
            query="next=https://evil.example/phish",
            request_headers={},
            request_body="",
            status=302,
            elapsed_ms=5.0,
            response_headers={"Location": "https://evil.example/phish"},
            content_type="text/plain",
            response_text="",
            redirect_location="https://evil.example/phish",
        )
        r_ctrl = store.record(
            actor="anon",
            method="GET",
            url="https://app.target.example/redir?next=/home",
            path="/redir",
            query="next=/home",
            request_headers={},
            request_body="",
            status=200,
            elapsed_ms=5.0,
            response_headers={},
            content_type="text/plain",
            response_text="ok",
            raw_response_bytes=b"ok",
        )

        # 1. Sibling in-scope redirect MUST be rejected as non-external
        rej_sib = json.loads(disp.dispatch("record_finding", {
            "title": "Sibling redirect",
            "class_type": "open_redirect",
            "method": "GET",
            "url": "https://app.target.example/redir",
            "actor_alias": "anon",
            "proof_receipt_ids": [r_sibling["receipt_id"]],
            "control_receipt_ids": [r_ctrl["receipt_id"]],
            "evidence_value": "https://auth.target.example/cb",
            "summary": "Redirect to sibling auth origin",
        }))
        assert rej_sib["rejected"] is True
        assert "in-scope" in rej_sib["reason"]

        # External redirect accepted
        ok_ext = json.loads(disp.dispatch("record_finding", {
            "title": "External open redirect",
            "class_type": "open_redirect",
            "method": "GET",
            "url": "https://app.target.example/redir",
            "actor_alias": "anon",
            "proof_receipt_ids": [r_ext["receipt_id"]],
            "control_receipt_ids": [r_ctrl["receipt_id"]],
            "evidence_value": "https://evil.example/phish",
            "summary": "Redirect to external domain",
        }))
        assert ok_ext["accepted"] is True

        # 2. Origin: null CORS exemption
        r_cors_null = store.record(
            actor="anon",
            method="GET",
            url="https://app.target.example/api/profile",
            path="/api/profile",
            query="",
            request_headers={"Origin": "null"},
            request_body="",
            status=200,
            elapsed_ms=5.0,
            response_headers={"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"},
            content_type="application/json",
            response_text='{"user":"a"}',
            raw_response_bytes=b'{"user":"a"}',
        )
        r_cors_ctrl = store.record(
            actor="anon",
            method="GET",
            url="https://app.target.example/api/profile",
            path="/api/profile",
            query="",
            request_headers={"Origin": "https://app.target.example"},
            request_body="",
            status=200,
            elapsed_ms=5.0,
            response_headers={},
            content_type="application/json",
            response_text='{"user":"a"}',
            raw_response_bytes=b'{"user":"a"}',
        )
        ok_cors = json.loads(disp.dispatch("record_finding", {
            "title": "CORS allows null origin",
            "class_type": "cors_misconfiguration",
            "method": "GET",
            "url": "https://app.target.example/api/profile",
            "actor_alias": "anon",
            "proof_receipt_ids": [r_cors_null["receipt_id"]],
            "control_receipt_ids": [r_cors_ctrl["receipt_id"]],
            "evidence_value": "null",
            "summary": "ACAO null reflected",
        }))
        assert ok_cors["accepted"] is True

        # 3. Live dedup respects distinct origins (app.target.example vs api.target.example)
        r_app_me = store.record(
            actor="member-a",
            method="GET",
            url="https://app.target.example/api/v1/admin/users",
            path="/api/v1/admin/users",
            query="",
            request_headers={},
            request_body="",
            status=200,
            elapsed_ms=5.0,
            response_headers={},
            content_type="application/json",
            response_text='{"secret":"app_admin_token_1111"}',
            raw_response_bytes=b'{"secret":"app_admin_token_1111"}',
        )
        r_api_me = store.record(
            actor="member-a",
            method="GET",
            url="https://api.target.example/api/v1/admin/users",
            path="/api/v1/admin/users",
            query="",
            request_headers={},
            request_body="",
            status=200,
            elapsed_ms=5.0,
            response_headers={},
            content_type="application/json",
            response_text='{"secret":"api_admin_token_2222"}',
            raw_response_bytes=b'{"secret":"api_admin_token_2222"}',
        )
        r_anon_403 = store.record(
            actor="anon",
            method="GET",
            url="https://app.target.example/api/v1/admin/users",
            path="/api/v1/admin/users",
            query="",
            request_headers={},
            request_body="",
            status=403,
            elapsed_ms=5.0,
            response_headers={},
            content_type="application/json",
            response_text='{"error":"forbidden"}',
            raw_response_bytes=b'{"error":"forbidden"}',
        )
        res_app = json.loads(disp.dispatch("record_finding", {
            "title": "App admin BFLA",
            "class_type": "bfla",
            "method": "GET",
            "url": "https://app.target.example/api/v1/admin/users",
            "actor_alias": "member-a",
            "proof_receipt_ids": [r_app_me["receipt_id"]],
            "control_receipt_ids": [r_anon_403["receipt_id"]],
            "evidence_value": "app_admin_token_1111",
            "summary": "App origin BFLA",
        }))
        res_api = json.loads(disp.dispatch("record_finding", {
            "title": "API admin BFLA",
            "class_type": "bfla",
            "method": "GET",
            "url": "https://api.target.example/api/v1/admin/users",
            "actor_alias": "member-a",
            "proof_receipt_ids": [r_api_me["receipt_id"]],
            "control_receipt_ids": [r_anon_403["receipt_id"]],
            "evidence_value": "api_admin_token_2222",
            "summary": "API origin BFLA",
        }))
        assert res_app["accepted"] is True and not res_app.get("duplicate")
        assert res_api["accepted"] is True and not res_api.get("duplicate")

        # 4. Live dedup respects distinct GraphQL operations on /graphql
        r_gql_q = store.record(
            actor="member-a",
            method="POST",
            url="https://api.target.example/graphql",
            path="/graphql",
            query="",
            request_headers={},
            request_body=json.dumps({"operationName": "GetSecrets", "query": "query GetSecrets { secrets { val } }"}),
            status=200,
            elapsed_ms=5.0,
            response_headers={},
            content_type="application/json",
            response_text='{"data":{"secrets":[{"val":"gql_query_secret_1"}]}}',
            raw_response_bytes=b'{"data":{"secrets":[{"val":"gql_query_secret_1"}]}}',
        )
        r_gql_m = store.record(
            actor="member-a",
            method="POST",
            url="https://api.target.example/graphql",
            path="/graphql",
            query="",
            request_headers={},
            request_body=json.dumps({"operationName": "PromoteAdmin", "query": "mutation PromoteAdmin { promoteAdmin { ok } }"}),
            status=200,
            elapsed_ms=5.0,
            response_headers={},
            content_type="application/json",
            response_text='{"data":{"promoteAdmin":{"ok":true,"token":"gql_mut_secret_2"}}}',
            raw_response_bytes=b'{"data":{"promoteAdmin":{"ok":true,"token":"gql_mut_secret_2"}}}',
        )
        res_gql1 = json.loads(disp.dispatch("record_finding", {
            "title": "GQL query BFLA",
            "class_type": "bfla",
            "method": "POST",
            "url": "https://api.target.example/graphql",
            "actor_alias": "member-a",
            "proof_receipt_ids": [r_gql_q["receipt_id"]],
            "control_receipt_ids": [r_anon_403["receipt_id"]],
            "evidence_value": "gql_query_secret_1",
            "summary": "GraphQL query unauthorized",
        }))
        res_gql2 = json.loads(disp.dispatch("record_finding", {
            "title": "GQL mutation BFLA",
            "class_type": "bfla",
            "method": "POST",
            "url": "https://api.target.example/graphql",
            "actor_alias": "member-a",
            "proof_receipt_ids": [r_gql_m["receipt_id"]],
            "control_receipt_ids": [r_anon_403["receipt_id"]],
            "evidence_value": "gql_mut_secret_2",
            "summary": "GraphQL mutation unauthorized",
        }))
        assert res_gql1["accepted"] is True and not res_gql1.get("duplicate")
        assert res_gql2["accepted"] is True and not res_gql2.get("duplicate")
    finally:
        client.close()


def test_tools_concurrent_check_burst_id_waf_pivot_and_concurrent_burst_kwarg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, client, _ = _make_deps(tmp_path)
    try:
        pivot = WAFPivotTracker(threshold=2)
        disp = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path, waf_pivot=pivot)
        seen_kwargs: list[dict[str, Any]] = []
        counter = [0]

        def _fake_request(
            *,
            method: str,
            url: str,
            actor: str = "anon",
            headers: dict[str, str] | None = None,
            query: dict[str, Any] | None = None,
            json_body: Any = None,
            form_body: dict[str, Any] | None = None,
            raw_body: str | None = None,
            force: bool = False,
            concurrent_burst: bool = False,
        ) -> dict[str, Any]:
            seen_kwargs.append({
                "method": method,
                "url": url,
                "actor": actor,
                "headers": headers,
                "query": query,
                "json_body": json_body,
                "form_body": form_body,
                "raw_body": raw_body,
                "force": force,
                "concurrent_burst": concurrent_burst,
            })
            counter[0] += 1
            return {
                "receipt_id": f"req-{counter[0]:04d}",
                "actor": actor,
                "method": method,
                "url": "http://127.0.0.1:18080/api/redeem",
                "path": "/api/redeem",
                "status": 403,
                "elapsed_ms": 5.0,
                "response_sha256": "abcd1234abcd1234",
                "content_type": "text/html",
                "response_headers": {"CF-Ray": "8abc111-SJC"},
                "body": "Attention Required! | Cloudflare",
            }

        monkeypatch.setattr(client, "request", _fake_request)
        raw = disp.dispatch("concurrent_check", {
            "url": "/api/redeem",
            "method": "POST",
            "actor": "anon",
            "count": 3,
        })
        assert len(seen_kwargs) == 3
        assert all(kw["concurrent_burst"] is True for kw in seen_kwargs)
        payload = json.loads(
            raw.split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1].rsplit("\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1)[0]
        )
        burst_id = payload["concurrent_burst_id"]
        assert burst_id.startswith("burst-")
        assert all(item["concurrent_burst_id"] == burst_id for item in payload["results"])
        assert all("waf_block" in item for item in payload["results"])
        assert pivot.total_blocks == 3
        assert pivot.should_pivot() is True
        assert "waf_pivot_guidance" in payload
        assert "cloudflare" in payload["waf_pivot_guidance"].lower()

        # Also verify graceful omission when http.request does not declare concurrent_burst
        legacy_calls: list[dict[str, Any]] = []

        def _legacy_request(
            *,
            method: str,
            url: str,
            actor: str = "anon",
            headers: dict[str, str] | None = None,
            query: dict[str, Any] | None = None,
            json_body: Any = None,
            form_body: dict[str, Any] | None = None,
            raw_body: str | None = None,
            force: bool = False,
        ) -> dict[str, Any]:
            legacy_calls.append({"method": method, "url": url, "actor": actor, "force": force})
            return {
                "receipt_id": "req-0099",
                "actor": actor,
                "method": method,
                "url": "http://127.0.0.1:18080/api/redeem",
                "path": "/api/redeem",
                "status": 200,
                "elapsed_ms": 2.0,
                "response_sha256": "1111222233334444",
                "content_type": "application/json",
                "response_headers": {},
                "body": '{"ok":true}',
            }

        monkeypatch.setattr(client, "request", _legacy_request)
        raw2 = disp.dispatch("concurrent_check", {"url": "/api/redeem", "method": "POST", "count": 2})
        payload2 = json.loads(
            raw2.split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1].rsplit("\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1)[0]
        )
        assert len(legacy_calls) == 2
        assert payload2["count"] == 2
    finally:
        client.close()


def test_tools_signature_safe_scope_kwargs_forwarding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, client, _ = _make_deps(
        tmp_path,
        base_url="https://app.target.example",
        in_scope_assets=("https://api.target.example",),
        out_of_scope_assets=("https://logout.target.example",),
        excluded_paths=("/admin/health",),
    )
    try:
        tracker_init_kwargs: list[dict[str, Any]] = []
        hints_kwargs: list[dict[str, Any]] = []
        summary_kwargs: list[dict[str, Any]] = []

        orig_tracker_cls = agentic_tools.SurfaceFrontierTracker

        class _AcceptingTracker(orig_tracker_cls):  # type: ignore[misc]
            def __init__(
                self,
                *,
                base_url: str,
                allowed_methods: list[str],
                actor_summaries: list[dict[str, Any]],
                in_scope_assets: tuple[str, ...] = (),
                out_of_scope_assets: tuple[str, ...] = (),
                excluded_paths: tuple[str, ...] = (),
            ) -> None:
                tracker_init_kwargs.append({
                    "base_url": base_url,
                    "allowed_methods": allowed_methods,
                    "actor_summaries": actor_summaries,
                    "in_scope_assets": in_scope_assets,
                    "out_of_scope_assets": out_of_scope_assets,
                    "excluded_paths": excluded_paths,
                })
                extra = agentic_tools._supported_kwargs(
                    orig_tracker_cls,
                    {
                        "in_scope_assets": in_scope_assets,
                        "out_of_scope_assets": out_of_scope_assets,
                        "excluded_paths": excluded_paths,
                    },
                )
                super().__init__(
                    base_url=base_url,
                    allowed_methods=allowed_methods,
                    actor_summaries=actor_summaries,
                    **extra,
                )

        def _fake_hints(
            receipt: dict[str, Any],
            base_url: str,
            *,
            in_scope_assets: tuple[str, ...] = (),
            out_of_scope_assets: tuple[str, ...] = (),
        ) -> dict[str, Any]:
            _ = (receipt, base_url)
            hints_kwargs.append({
                "in_scope_assets": in_scope_assets,
                "out_of_scope_assets": out_of_scope_assets,
            })
            return {"links_count": 1}

        def _fake_summary(
            receipt: dict[str, Any],
            base_url: str,
            *,
            in_scope_assets: tuple[str, ...] = (),
            out_of_scope_assets: tuple[str, ...] = (),
        ) -> dict[str, Any]:
            summary_kwargs.append({
                "in_scope_assets": in_scope_assets,
                "out_of_scope_assets": out_of_scope_assets,
            })
            return {"receipt_id": receipt["receipt_id"], "url": receipt["url"], "content_type": "text/html", "base": base_url}

        monkeypatch.setattr(agentic_tools, "SurfaceFrontierTracker", _AcceptingTracker)
        monkeypatch.setattr(agentic_tools, "_build_surface_hints", _fake_hints)
        monkeypatch.setattr(agentic_tools, "_extract_surface_summary", _fake_summary)

        rec = store.record(
            actor="anon",
            method="GET",
            url="https://app.target.example/page",
            path="/page",
            query="",
            request_headers={},
            request_body="",
            status=200,
            elapsed_ms=4.0,
            response_headers={},
            content_type="text/html",
            response_text="<a href='/api/users'>users</a>",
            raw_response_bytes=b"<a href='/api/users'>users</a>",
        )
        monkeypatch.setattr(client, "request", lambda **_kw: rec)

        disp = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path)
        assert tracker_init_kwargs == [{
            "base_url": client.base_url,
            "allowed_methods": sorted(client.allowed_methods),
            "actor_summaries": client.actors.summaries(),
            "in_scope_assets": ("https://api.target.example",),
            "out_of_scope_assets": ("https://logout.target.example",),
            "excluded_paths": ("/admin/health",),
        }]

        raw_http = disp.dispatch("http_request", {"url": "/page", "method": "GET"})
        assert '"error"' not in raw_http
        assert hints_kwargs == [{
            "in_scope_assets": ("https://api.target.example",),
            "out_of_scope_assets": ("https://logout.target.example",),
        }]

        raw_ext = disp.dispatch("extract_surface", {"receipt_id": rec["receipt_id"]})
        assert '"error"' not in raw_ext
        assert summary_kwargs == [{
            "in_scope_assets": ("https://api.target.example",),
            "out_of_scope_assets": ("https://logout.target.example",),
        }]
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 4. Runner: --tui Ctrl-C cancel_event, resume auth, initial_waf_vendors, shard rescue, exit codes
# ---------------------------------------------------------------------------


def test_runner_tui_ctrl_c_sets_cancel_event_and_exits_130_without_hanging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = tmp_path / "llm.json"
    cfg.write_text(
        json.dumps({
            "schema": "cco-llm/1",
            "model": "local/test-model",
            "providers": {
                "local": {
                    "base_url": "http://127.0.0.1:19999/v1",
                    "models": ["test-model"],
                    "api_key_env": "TEST_RUNNER_KEY",
                    "api_key_header": "Authorization",
                }
            },
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("TEST_RUNNER_KEY", "dummy-local-key")

    captured_cancel: list[threading.Event | None] = []

    def _fake_run_target(**kwargs: Any) -> tuple[Path, dict[str, Any]]:
        ev = kwargs.get("cancel_event")
        captured_cancel.append(ev)
        assert ev is not None
        assert ev.wait(timeout=3.0) is True
        out_dir = Path(kwargs["output_dir"])
        out_dir.mkdir(parents=True, exist_ok=True)
        mpath = out_dir / "manifest.json"
        doc = {
            "mode": "agentic",
            "status": "interrupted",
            "target": kwargs["target"],
            "llm_calls": 1,
            "target_requests": 0,
            "findings_count": 0,
            "findings_artifact": str(out_dir / "findings.json"),
        }
        mpath.write_text(json.dumps(doc), encoding="utf-8")
        return mpath, doc

    monkeypatch.setattr(agentic_runner, "run_agentic_target", _fake_run_target)
    monkeypatch.setattr(agentic_tui, "watch_run_dir", lambda *_a, **_kw: 0)  # simulate early Ctrl-C exit

    out_dir = tmp_path / "tui-ctrlc"
    t0 = time.monotonic()
    rc = agentic_runner.main([
        "--target", "http://127.0.0.1:18080/",
        "--provider-config", str(cfg),
        "--output-dir", str(out_dir),
        "--execute",
        "--tui",
    ])
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert rc == 130
    assert len(captured_cancel) == 1
    assert captured_cancel[0] is not None and captured_cancel[0].is_set()


def test_runner_resume_authenticates_actors_passes_waf_vendors_and_rescues_shard_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login_calls: list[str] = []

    class _TargetHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            login_calls.append(body)
            payload = json.dumps({"token": "tok-resumed"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            payload = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    cfg = tmp_path / "llm.json"
    cfg.write_text(
        json.dumps({
            "schema": "cco-llm/1",
            "model": "local/test-model",
            "providers": {
                "local": {
                    "base_url": "http://127.0.0.1:19999/v1",
                    "models": ["test-model"],
                    "api_key_env": "TEST_RUNNER_KEY2",
                    "api_key_header": "Authorization",
                }
            },
        }),
        encoding="utf-8",
    )
    creds = tmp_path / "creds.json"
    creds.write_text(
        json.dumps({
            "target_url": f"http://127.0.0.1:{srv.server_port}/",
            "login_path": "/api/login",
            "test_accounts": [
                {"alias": "member-a", "email": "a@example.test", "password": "pw", "role": "member"}
            ],
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("TEST_RUNNER_KEY2", "dummy-local-key")

    out_dir = tmp_path / "run-rescue"
    out_dir.mkdir(parents=True)
    (out_dir / "checkpoint.json").write_text(
        json.dumps({"turn": 2, "status": "interrupted"}),
        encoding="utf-8",
    )
    (out_dir / "prescan-summary.json").write_text(
        json.dumps({
            "schema": "agentic-prescan/1",
            "status": "ok",
            "leads": [],
            "waf_vendors_seen": ["cloudflare"],
        }),
        encoding="utf-8",
    )

    seen_waf_vendors: list[tuple[str, ...]] = []
    orig_inv_cls = agentic_runner.AgenticInvestigator

    class _AbortingInvestigator(orig_inv_cls):  # type: ignore[misc]
        def __init__(self, **kwargs: Any) -> None:
            seen_waf_vendors.append(tuple(kwargs.get("initial_waf_vendors") or ()))
            super().__init__(**kwargs)

        def run(self, *, resume: bool = False) -> dict[str, Any]:
            shard_dir = self.root_dir / "shards" / "shard-1"
            shard_dir.mkdir(parents=True, exist_ok=True)
            (shard_dir / "findings.json").write_text(
                json.dumps([{
                    "finding_id": "F-001",
                    "title": "Rescued shard BOLA",
                    "class_type": "bola",
                    "route_template": "/api/orders/{id}",
                    "method": "GET",
                    "url": f"http://127.0.0.1:{srv.server_port}/api/orders/1",
                    "path": "/api/orders/1",
                    "actor": "member-a",
                    "evidence_value": "rescued_secret_888",
                    "proof_receipt_ids": [],
                    "control_receipt_ids": [],
                }]),
                encoding="utf-8",
            )
            raise KeyboardInterrupt()

    monkeypatch.setattr(agentic_runner, "AgenticInvestigator", _AbortingInvestigator)
    try:
        _, manifest = agentic_runner.run_agentic_target(
            credentials_file=creds,
            provider_config=cfg,
            output_dir=out_dir,
            execute=True,
            resume=True,
            max_turns=4,
        )
        assert len(login_calls) == 1
        assert seen_waf_vendors == [("cloudflare",)]
        assert manifest["status"] == "interrupted"
        assert manifest["findings_count"] == 1
        rescued = json.loads((out_dir / "findings.json").read_text(encoding="utf-8"))
        assert len(rescued) == 1
        assert rescued[0]["evidence_value"] == "rescued_secret_888"
    finally:
        srv.shutdown()
        srv.server_close()

    # Exit codes in agentic_runner.main
    for status_val, expected_rc in (
        ("finished", 0),
        ("completed", 0),
        ("budget_exhausted", 0),
        ("service_degraded", 0),
        ("interrupted", 130),
        ("failed", 1),
    ):
        monkeypatch.setattr(
            agentic_runner,
            "run_agentic_target",
            lambda _st=status_val, **_kw: (
                tmp_path / "manifest.json",
                {"mode": "agentic", "status": _st, "target": "http://127.0.0.1:18080/"},
            ),
        )
        rc = agentic_runner.main([
            "--target", "http://127.0.0.1:18080/",
            "--provider-config", str(cfg),
            "--output-dir", str(tmp_path / f"exit-{status_val}"),
        ])
        assert rc == expected_rc
