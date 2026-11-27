"""Faz 5 (Stage 2.5) unit and integration tests for selective retry, DeadEndDigest, budgets, cache, model escalation, and lead promotion."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = _ROOT / "scripts"
for _p in (_SCRIPTS, _ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agentic_fact_graph import SharedFactGraph  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
import agentic_investigator  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_report import generate_run_reports, render_markdown_report, render_sarif_report  # noqa: E402
import agentic_runner  # noqa: E402
from agentic_sharding import SubsystemCluster  # noqa: E402
from agentic_stage25 import (  # noqa: E402
    build_dead_end_digest,
    build_stage25_retry_prompts,
    evaluate_stage25_retry_candidates,
)
from agentic_surface import SurfaceFrontierTracker  # noqa: E402
from agentic_tools import ToolDispatcher, reconcile_promoted_leads  # noqa: E402
from agentic_waf import WAFPivotTracker  # noqa: E402
from full_agent_budget import BudgetError, SharedBudget  # noqa: E402


def _make_tool_msg(call_id: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "choices": [{
            "message": {
                "content": "",
                "tool_calls": [{
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args)},
                }],
            }
        }],
        "usage": {"prompt_tokens": 180, "completion_tokens": 40, "total_tokens": 220},
    }


class _NoopTransport:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, body: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        self.calls += 1
        return {
            "choices": [{"message": {"content": "done", "tool_calls": []}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60},
        }


def test_stage25_trigger_evaluation_scoring_and_guards() -> None:
    c1 = SubsystemCluster(
        shard_id="shard-1",
        name="orders",
        families=["orders"],
        routes=["GET /api/orders/{id}", "POST /api/orders"],
        write_ops=["POST /api/orders"],
        objects=[],
        params={},
    )
    c2 = SubsystemCluster(
        shard_id="shard-2",
        name="billing",
        families=["billing", "webhooks"],
        routes=[
            "GET /api/billing/a",
            "GET /api/billing/b",
            "POST /api/billing/pay",
            "POST /api/webhooks/register",
        ],
        write_ops=["POST /api/billing/pay", "POST /api/webhooks/register"],
        objects=[],
        params={},
    )
    c3 = SubsystemCluster(
        shard_id="shard-3",
        name="health",
        families=["health"],
        routes=["GET /health"],
        write_ops=[],
        objects=[],
        params={},
    )

    sf = SharedFactGraph()
    sf.publish(
        "auth_header",
        "header:x-early",
        "X-Early-Token",
        source_shard="shard-2",
        target_families=("*",),
    )
    seq_at_c1_close = sf.current_seq()
    sf.publish(
        "actor_capability",
        "actor:shadow_admin",
        "alias=shadow_admin role=admin",
        source_shard="shard-2",
        target_families=("orders",),
    )
    # Non-mutating verification: cursors unchanged and facts_after respects exclude_shard/families
    assert sf.cursor_for("shard-1") == 0
    assert len(sf.facts_after(seq_at_c1_close, exclude_shard="shard-1", families=["orders"])) == 1
    assert len(sf.facts_after(seq_at_c1_close, exclude_shard="shard-2", families=["orders"])) == 0

    shard_results = [
        {
            "shard_id": "shard-1",
            "status": "finished",
            "findings": [],
            "closed_at_seq": seq_at_c1_close,
            "tokens": 5_000,
            "shard_token_quota": 50_000,
            "epoch_advancements": 0,
            "surface_counts": {"routes": 2, "write_ops": 1, "untested_writes": 0, "opaque_slices": 0},
        },
        {
            "shard_id": "shard-2",
            "status": "max_turns_reached",
            "findings": [],
            "closed_at_seq": sf.current_seq(),
            "tokens": 42_000,
            "shard_token_quota": 50_000,
            "epoch_advancements": 1,
            "surface_counts": {"routes": 4, "write_ops": 2, "untested_writes": 2, "opaque_slices": 1},
        },
        {
            # Low-surface genuine clean 0-finding shard -> must NOT trigger retry!
            "shard_id": "shard-3",
            "status": "finished",
            "findings": [],
            "closed_at_seq": sf.current_seq(),
            "tokens": 2_000,
            "shard_token_quota": 50_000,
            "epoch_advancements": 0,
            "surface_counts": {"routes": 1, "write_ops": 0, "untested_writes": 0, "opaque_slices": 0},
        },
    ]
    active_leads = [
        {
            "lead_id": "L-001",
            "source_shard": "shard-1",
            "class_type": "bola",
            "method": "GET",
            "route_template": "/api/orders/{id}",
            "signal_type": "multistep_budget_exceeded",
        },
        {
            # Already promoted lead should be ignored.
            "lead_id": "L-002",
            "source_shard": "shard-3",
            "class_type": "info",
            "method": "GET",
            "route_template": "/health",
            "promoted_to_finding_id": "F-001",
        },
    ]

    ranked = evaluate_stage25_retry_candidates(
        clusters=[c1, c2, c3],
        shard_results=shard_results,
        active_leads=active_leads,
        shared_facts=sf,
        remaining_http=60,
        remaining_tokens=200_000,
        remaining_seconds=120.0,
        stage3_http_reserve=12,
        stage3_token_reserve=25_000,
        retry_budget_ratio=0.20,
        max_retry_shards=2,
        max_shard_retries=1,
        retry_model="reasoner-v2",
        primary_model="worker-v1",
    )
    assert [d["shard_id"] for d in ranked] == ["shard-1", "shard-2"]
    assert ranked[0]["priority_score"] == 150  # 60 + 50 + 40 combo bonus
    assert ranked[0]["triggers"] == ["lead_followup", "late_shared_fact_unlocked"]
    assert ranked[0]["lead_ids"] == ["L-001"]
    assert ranked[0]["retry_model"] == "reasoner-v2"
    assert ranked[1]["priority_score"] == 30
    assert ranked[1]["triggers"] == ["high_surface_zero_findings"]

    # Hard cap to max_retry_shards=1 keeps only top priority shard-1
    capped = evaluate_stage25_retry_candidates(
        clusters=[c1, c2, c3],
        shard_results=shard_results,
        active_leads=active_leads,
        shared_facts=sf,
        remaining_http=60,
        remaining_tokens=200_000,
        remaining_seconds=120.0,
        stage3_http_reserve=12,
        stage3_token_reserve=25_000,
        max_retry_shards=1,
    )
    assert [d["shard_id"] for d in capped] == ["shard-1"]

    # Disabled via max_shard_retries=0 or protected Stage 3 budget floors
    assert evaluate_stage25_retry_candidates(
        clusters=[c1, c2],
        shard_results=shard_results,
        active_leads=active_leads,
        shared_facts=sf,
        remaining_http=60,
        remaining_tokens=200_000,
        remaining_seconds=120.0,
        stage3_http_reserve=12,
        stage3_token_reserve=25_000,
        max_shard_retries=0,
    ) == []
    assert evaluate_stage25_retry_candidates(
        clusters=[c1],
        shard_results=shard_results,
        active_leads=active_leads,
        shared_facts=sf,
        remaining_http=15,  # <= stage3_http_reserve (12) + 4
        remaining_tokens=200_000,
        remaining_seconds=120.0,
        stage3_http_reserve=12,
        stage3_token_reserve=25_000,
    ) == []
    assert evaluate_stage25_retry_candidates(
        clusters=[c1],
        shard_results=shard_results,
        active_leads=active_leads,
        shared_facts=sf,
        remaining_http=60,
        remaining_tokens=30_000,  # <= stage3_token_reserve (25000) + 12000
        remaining_seconds=120.0,
        stage3_http_reserve=12,
        stage3_token_reserve=25_000,
    ) == []


def test_dead_end_digest_bounded_redacted_and_orthogonal_prompts(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    secret_tok = "tok_live_top9988"
    r1 = store.record(
        actor="anon",
        method="GET",
        url="http://127.0.0.1:9000/api/orders/1?page=1&sort=asc",
        path="/api/orders/1",
        query="page=1&sort=asc",
        request_headers={"Authorization": f"Bearer {secret_tok}"},
        request_body="",
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        response_headers={},
        raw_response_bytes=b'{"ok":true}',
        response_text='{"ok":true}',
        secret_values=(secret_tok,),
    )
    r2 = store.record(
        actor="bob",
        method="GET",
        url="http://127.0.0.1:9000/api/orders/1?page=2&sort=desc",
        path="/api/orders/1",
        query="page=2&sort=desc",
        request_headers={},
        request_body="",
        status=200,
        elapsed_ms=2.0,
        content_type="application/json",
        response_headers={},
        raw_response_bytes=b'{"ok":true}',
        response_text='{"ok":true}',
        secret_values=(secret_tok,),
    )
    r3 = store.record(
        actor="alice",
        method="POST",
        url="http://127.0.0.1:9000/api/orders/webhook",
        path="/api/orders/webhook",
        query="",
        request_headers={},
        request_body=json.dumps({"url": "http://169.254.169.254/"}),
        status=403,
        elapsed_ms=2.0,
        content_type="text/html",
        response_headers={"CF-Mitigated": "challenge"},
        raw_response_bytes=b"<html>Attention Required! | Cloudflare</html>",
        response_text="<html>Attention Required! | Cloudflare</html>",
        secret_values=(secret_tok,),
    )

    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:9000",
        allowed_methods=["GET", "POST", "PATCH"],
    )
    tracker.declared_write_ops.add(("PATCH", "/api/orders/{id}"))
    tracker.discovered_write_ops[("PATCH", "/api/orders/{id}")] = "/api/orders/1"
    tracker.opaque_js_slices.append({
        "receipt_id": r1["receipt_id"],
        "url": "http://127.0.0.1:9000/static/app.js",
        "char_start": 0,
        "char_end": 1200,
        "anchor": "decoder_preamble",
    })
    waf = WAFPivotTracker()
    waf.record_block("cloudflare", "/api/orders/webhook")

    rejections = [
        {
            "class_type": "sqli",
            "method": "GET",
            "route_template": "/api/orders/{id}",
            "actor": "alice",
            "verdict": "REFUTED",
            "deception_detected": False,
            "stage": "stage1_control:identical",
            "reason": f"Control identical using Bearer {secret_tok}",
        },
        {
            "class_type": "bfla",
            "method": "GET",
            "route_template": "/admin/{id}",
            "actor": "alice",
            "verdict": "DECEPTION_DETECTED",
            "deception_detected": True,
            "stage": "stage1_deception",
            "reason": "SPA catchall 200 matches unknown path",
        },
    ]

    digest = build_dead_end_digest(
        shard_id="shard-1",
        receipts=store,
        shard_receipt_ids=[r1["receipt_id"], r2["receipt_id"], r3["receipt_id"]],
        oracle_rejections=rejections,
        waf_pivot=waf,
        surface_tracker=tracker,
        cluster_families=["orders"],
        active_actors=["anon", "alice", "bob"],
        newly_unlocked_facts=[{
            "fact_id": "sf_003",
            "fact_type": "actor_capability",
            "summary": "alias=shadow_admin role=admin",
        }],
        max_chars=1200,
        secret_values=(secret_tok,),
    )
    rendered = digest["rendered_prompt_block"]
    assert digest["schema"] == "agentic-dead-end-digest/1"
    assert rendered.startswith("[DEAD-END DIGEST")
    assert len(rendered) <= 1200
    assert secret_tok not in rendered
    assert secret_tok not in json.dumps(digest)
    assert len(digest["oracle_refutations"]) == 1
    assert len(digest["deception_traps"]) == 1
    assert any("PATCH /api/orders/" in a for a in digest["untried_angles"])
    assert any("opaque_js" in a for a in digest["untried_angles"])
    # Framing must scope to refuted class/vector rather than blacklisting entire route.
    assert "do not touch" not in rendered.lower()

    sys_p, usr_p = build_stage25_retry_prompts(
        cluster=SubsystemCluster(
            shard_id="shard-1",
            name="orders",
            families=["orders"],
            routes=["GET /api/orders/{id}", "PATCH /api/orders/{id}"],
            write_ops=["PATCH /api/orders/{id}"],
            objects=[],
            params={},
        ),
        candidate={
            "shard_id": "shard-1",
            "priority_score": 150,
            "triggers": ["lead_followup", "late_shared_fact_unlocked"],
            "objective": "Verify lead L-001 with newly discovered actor",
        },
        base_system_prompt="BASE PROMPT\n\nSUBSYSTEM SHARD SCOPE (old):",
        shared_facts_snapshot="[SHARED-FACTS SNAPSHOT (1/1)]\n- sf_003 [actor_capability@shard-2] alias=shadow_admin role=admin",
        dead_end_digest=digest,
        active_actors=[{"alias": "alice", "role": "member", "tenant": "alpha"}],
        state_banner="\n[STATE] http_budget: 25/40 left",
        active_leads_for_shard=[{
            "lead_id": "L-001",
            "signal_type": "multistep_budget_exceeded",
            "class_type": "bola",
            "method": "GET",
            "route_template": "/api/orders/{id}",
            "proof_receipt_ids": [r1["receipt_id"]],
            "control_receipt_ids": [r2["receipt_id"]],
            "verification_blocker": "failed_multistep_budget",
        }],
    )
    assert "STAGE 2.5 FOCUSED VERIFICATION PASS (shard-1:" in sys_p
    assert "SUBSYSTEM SHARD SCOPE (old):" not in sys_p
    assert "[STAGE 2.5 TRIGGER & OBJECTIVE]" in usr_p
    assert "[SHARED FACTS & ACTIVE ACTORS]" in usr_p
    assert "[DEAD-END DIGEST" in usr_p
    assert "force=true" in usr_p


def test_invalidate_get_cache_and_http400_sampling_recovery(tmp_path: Path) -> None:
    counts = {"a": 0, "b": 0, "static": 0}

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/api/orders/1":
                counts["a"] += 1
                body = json.dumps({"n": counts["a"]}).encode("utf-8")
            elif path == "/api/orders":
                counts["b"] += 1
                body = json.dumps({"list": counts["b"]}).encode("utf-8")
            else:
                counts["static"] += 1
                body = json.dumps({"static": counts["static"]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    store = ReceiptStore(tmp_path / "r")
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{srv.server_port}",
        receipt_store=store,
        actors=ActorManager([
            {"alias": "alice", "role": "member", "auth_header": "Bearer tok-a"},
            {"alias": "shadow", "role": "admin", "auth_header": "Bearer tok-s"},
        ]),
        allowed_methods=("GET",),
        max_requests=20,
    )
    try:
        r1 = client.request(method="GET", url="/api/orders/1", actor="alice")
        r1_cached = client.request(method="GET", url="/api/orders/1", actor="alice")
        client.request(method="GET", url="/api/orders", actor="alice")
        client.request(method="GET", url="/api/static-info", actor="alice")
        client.request(method="GET", url="/api/static-info", actor="shadow")
        assert r1_cached["cached"] is True
        assert counts["a"] == 1

        evicted = client.invalidate_get_cache(paths=["/api/orders/1", "/api/orders"], actors=["shadow"])
        assert evicted == 3  # /api/orders/1 + /api/orders for alice, /api/static-info for shadow

        # Static path for alice stays cached; invalidated routes/actor fetch fresh from wire
        still_cached = client.request(method="GET", url="/api/static-info", actor="alice")
        assert still_cached["cached"] is True
        r1_fresh = client.request(method="GET", url="/api/orders/1", actor="alice")
        assert r1_fresh["cached"] is False
        assert r1_fresh["receipt_id"] != r1["receipt_id"]
        assert counts["a"] == 2
        assert client.invalidate_get_cache() == 2
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()

    # HTTP 400 fallback automatically strips seed/temperature sampling params
    class _SamplingRejectTransport:
        def __init__(self) -> None:
            self.calls = 0
            self.seen_bodies: list[dict[str, Any]] = []

        def complete(self, body: dict[str, Any], **_kw: Any) -> dict[str, Any]:
            self.calls += 1
            self.seen_bodies.append(dict(body))
            if "seed" in body or "temperature" in body:
                raise BudgetError("provider HTTP 400; response body withheld", code="provider_http_error")
            return {
                "choices": [{"message": {"content": "ok", "tool_calls": []}}],
                "usage": {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60},
            }

    s_store = ReceiptStore(tmp_path / "r2")
    s_client = AgenticHTTPClient(
        base_url="http://127.0.0.1:1",
        receipt_store=s_store,
        actors=ActorManager([]),
        allowed_methods=("GET",),
        max_requests=5,
    )
    try:
        t_http400 = _SamplingRejectTransport()
        inv = AgenticInvestigator(
            http_client=s_client,
            receipt_store=s_store,
            transport=t_http400,  # type: ignore[arg-type]
            budget=SharedBudget(tokens=50_000),
            model="reasoner-model",
            root_dir=tmp_path / "r2_out",
            execution_mode="monolithic",
        )
        inv._last_provider_status = lambda: 400  # type: ignore[method-assign]
        resp = inv._complete_with_retry(
            [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}],
            sampling_seed=2026,
            temperature_override=0.2,
        )
        assert resp["choices"][0]["message"]["content"] == "ok"
        assert len(t_http400.seen_bodies) == 2
        assert t_http400.seen_bodies[0]["seed"] == 2026
        assert t_http400.seen_bodies[0]["temperature"] == 0.2
        assert "seed" not in t_http400.seen_bodies[1]
        assert "temperature" not in t_http400.seen_bodies[1]
    finally:
        s_client.close()


def test_runner_retry_model_seviye_a_and_plan_defaults(tmp_path: Path) -> None:
    cfg = tmp_path / "llm.json"
    cfg.write_text(
        json.dumps({
            "schema": "cco-llm/1",
            "model": "p1/worker-fast",
            "providers": {
                "p1": {
                    "base_url": "https://api.example.test/v1",
                    "models": ["worker-fast", "retry-deep"],
                    "api_key_env": "TEST_KEY_ENV",
                    "api_key_header": "Authorization",
                },
                "p2": {
                    "base_url": "https://other.example.test/v1",
                    "models": ["other-model"],
                    "api_key_env": "OTHER_KEY_ENV",
                    "api_key_header": "Authorization",
                },
            },
        }),
        encoding="utf-8",
    )

    out_ok = tmp_path / "plan_ok"
    rc = agentic_runner.main([
        "--target", "http://127.0.0.1:18899",
        "--provider-config", str(cfg),
        "--output-dir", str(out_ok),
        "--execution-mode", "sharded",
        "--max-shard-retries", "1",
        "--retry-model", "p1/retry-deep",
        "--retry-budget-ratio", "0.20",
        "--max-retry-shards", "1",
    ])
    assert rc == 0
    plan = json.loads((out_ok / "agentic-plan.json").read_text(encoding="utf-8"))
    assert plan["sharding"]["retry_model"] == "p1/retry-deep"
    assert plan["sharding"]["retry_budget_ratio"] == 0.20
    assert plan["sharding"]["max_retry_shards"] == 1

    # Cross-provider --retry-model rejected cleanly under Seviye A single-provider rule.
    with pytest.raises(ValueError, match="one provider"):
        agentic_runner.main([
            "--target", "http://127.0.0.1:18899",
            "--provider-config", str(cfg),
            "--output-dir", str(tmp_path / "plan_bad"),
            "--execution-mode", "sharded",
            "--retry-model", "p2/other-model",
        ])


def test_lead_promotion_and_report_stage25_rendering(tmp_path: Path) -> None:
    findings = [
        {
            "finding_id": "F-001",
            "title": "Verified IDOR",
            "class_type": "bola",
            "method": "GET",
            "url": "http://127.0.0.1:9000/api/orders/1",
            "path": "/api/orders/1",
            "route_template": "/api/orders/{id}",
            "actor": "bob",
            "severity": "high",
            "evidence": "owner_secret",
            "summary": "Bob can read Alice order.",
            "proof_receipt_ids": ["req-0005"],
            "control_receipt_ids": ["req-0002"],
        }
    ]
    leads = [
        {
            "lead_id": "L-001",
            "title": "Possible IDOR",
            "class_type": "bola",
            "method": "GET",
            "url": "http://127.0.0.1:9000/api/orders/1",
            "path": "/api/orders/1",
            "route_template": "/api/orders/{id}",
            "signal_type": "multistep_budget_exceeded",
            "passed_stages": ["stage1_control", "stage2_diff"],
            "verification_blocker": "failed_multistep_budget",
            "proof_receipt_ids": ["req-0001"],
            "control_receipt_ids": [],
            "source_shard": "shard-1",
        },
        {
            "lead_id": "L-002",
            "title": "Unpromoted Admin Timing",
            "class_type": "sqli",
            "method": "POST",
            "url": "http://127.0.0.1:9000/api/admin/search",
            "path": "/api/admin/search",
            "route_template": "/api/admin/search",
            "signal_type": "timing_anomaly_borderline",
            "passed_stages": ["stage1_control", "stage2_diff"],
            "verification_blocker": "failed_timing_overlap",
            "proof_receipt_ids": ["req-0009"],
            "control_receipt_ids": ["req-0008"],
            "source_shard": "shard-2",
        },
    ]

    active_leads, promoted = reconcile_promoted_leads(findings, leads)
    assert len(promoted) == 1
    assert promoted[0]["promoted_to_finding_id"] == "F-001"
    assert promoted[0]["status"] == "promoted"
    assert len(active_leads) == 1
    assert active_leads[0]["lead_id"] == "L-001"
    assert active_leads[0]["signal_type"] == "timing_anomaly_borderline"

    artifacts = {
        "run_dir": str(tmp_path),
        "manifest": {
            "target": "http://127.0.0.1:9000",
            "run_id": "run-s25",
            "status": "finished",
            "finished": True,
            "execution_mode": "sharded",
            "models": {"worker": "deepseek-chat", "retry_model": "deepseek-reasoner"},
            "http_requests_used": 18,
            "http_requests_limit": 80,
            "llm_calls": 9,
            "token_usage": {"prompt_tokens": 2000, "completion_tokens": 500, "total_tokens": 2500},
            "sharding_summary": {
                "bootstrap_turns": 2,
                "bootstrap_calls": 2,
                "bootstrap_tokens": 400,
                "bootstrap_findings": 0,
                "retry_model": "deepseek-reasoner",
                "shards": [
                    {
                        "shard_id": "shard-1",
                        "families": ["orders"],
                        "status": "finished",
                        "calls": 3,
                        "tokens": 900,
                        "findings": 0,
                    },
                    {
                        "shard_id": "shard-2",
                        "families": ["admin"],
                        "status": "max_turns_reached",
                        "calls": 2,
                        "tokens": 600,
                        "findings": 0,
                    },
                ],
                "stage2_5_retries": [
                    {
                        "shard_id": "shard-1",
                        "attempt": 1,
                        "families": ["orders"],
                        "status": "finished",
                        "triggers": ["lead_followup", "late_shared_fact_unlocked"],
                        "retry_model": "deepseek-reasoner",
                        "calls": 2,
                        "tokens": 600,
                        "findings": 1,
                        "promoted_leads": 1,
                    }
                ],
                "stage3_synthesis": None,
            },
        },
        "checkpoint": {},
        "findings": findings,
        # Include promoted lead in raw artifacts too -> report layer must filter it out!
        "leads": [*active_leads, *promoted],
        "process_metrics": {},
        "receipts": {},
        "missing_artifacts": [],
    }

    md = render_markdown_report(artifacts)
    assert "`stage2.5:shard-1-retry1`" in md
    assert "triggers=lead_followup, late_shared_fact_unlocked; model=`deepseek-reasoner`" in md
    assert "Verified IDOR" in md
    assert "Unpromoted Admin Timing" in md
    assert "Possible IDOR" not in md

    sarif = render_sarif_report(artifacts)
    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    tiers = {r["properties"]["verification_tier"] for r in results}
    assert tiers == {"CONFIRMED", "NEEDS_VERIFICATION"}
    review_msgs = [r["message"]["text"] for r in results if r["kind"] == "review"]
    assert len(review_msgs) == 1
    assert "Unpromoted Admin Timing" in review_msgs[0]
    assert "Possible IDOR" not in review_msgs[0]


def test_end_to_end_sharded_stage25_retry_fresh_context_budget_and_promotion(tmp_path: Path) -> None:
    lock = threading.Lock()
    state = {"order_status": "open", "cache_reads": 0}

    class _AppHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            auth = str(self.headers.get("Authorization") or "")
            if parsed.path in {"/", "/orders", "/admin"}:
                body = b"<html><a href='/api/orders/1'>o</a><a href='/api/admin/audit'>a</a></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path == "/api/orders/1":
                with lock:
                    state["cache_reads"] += 1
                    cur_st = state["order_status"]
                if "tok-bob" in auth or "tok-alice" in auth:
                    payload = json.dumps({"id": 1, "secret_note": "ALICE_PRIVATE_ORDER_SECRET", "state": cur_st}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
                return
            if parsed.path == "/api/admin/audit":
                if "tok-alice" in auth:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "11")
                    self.end_headers()
                    self.wfile.write(b'{"audit":1}')
                    return
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self) -> None:
            if urlsplit(self.path).path == "/api/orders/1/cancel":
                with lock:
                    state["order_status"] = "cancelled"
                payload = b'{"cancelled":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _AppHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base_url = f"http://127.0.0.1:{srv.server_port}"

    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-alice"},
        {"alias": "bob", "role": "member", "tenant": "beta", "auth_header": "Bearer tok-bob"},
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=60,
    )

    class _ScriptedTransport:
        def __init__(self) -> None:
            self._lock = threading.Lock()
            self.calls = 0
            self.recorded_requests: list[dict[str, Any]] = []
            self.stage25_requests: list[dict[str, Any]] = []

        def complete(self, body: dict[str, Any], **_kw: Any) -> dict[str, Any]:
            with self._lock:
                self.calls += 1
                self.recorded_requests.append(body)

            sys_text = str((body.get("messages") or [{}])[0].get("content") or "")
            user_text = str((body.get("messages") or [{}])[1].get("content") or "")
            tool_msgs = [m for m in (body.get("messages") or []) if m.get("role") == "tool"]

            # Stage 1 Bootstrap
            if "Stage 1 Surface & Session Discovery" in user_text or (
                "SUBSYSTEM SHARD SCOPE" not in sys_text
                and "STAGE 2.5" not in sys_text
                and "CROSS-SHARD" not in sys_text
                and "STAGE 3" not in user_text
            ):
                if len(tool_msgs) == 0:
                    return _make_tool_msg("boot_1", "finish", {
                        "summary": "Stage 1 complete",
                        "untested_areas": [],
                    })
                return {
                    "choices": [{"message": {"content": "boot done", "tool_calls": []}}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110},
                }

            # Stage 2.5 Retry (Shard-1 only)
            if "STAGE 2.5 FOCUSED VERIFICATION PASS" in sys_text:
                with self._lock:
                    self.stage25_requests.append(body)
                if len(tool_msgs) == 0:
                    # Assert fresh context: ZERO carried Stage 2 assistant/tool turns!
                    roles = [m.get("role") for m in (body.get("messages") or [])]
                    assert roles == ["system", "user"]
                    assert "[DEAD-END DIGEST" in user_text
                    assert "[SHARED FACTS & ACTIVE ACTORS]" in user_text
                    # Re-read mutated route (verifying GET cache invalidation) + confirm finding!
                    return _make_tool_msg("r25_1", "http_request", {
                        "method": "GET",
                        "url": "/api/orders/1",
                        "actor": "bob",
                    })
                if len(tool_msgs) == 1:
                    r_id = json.loads(
                        tool_msgs[0]["content"].split("\n")[1]
                    )["receipt_id"]
                    ctrl_ids = [
                        rid
                        for rid in store.list_ids()
                        if store.get(rid).get("actor") == "anon"
                        and "/api/orders/1" in str(store.get(rid).get("url") or "")
                    ]
                    return _make_tool_msg("r25_2", "record_finding", {
                        "title": "Broken Function Level Auth on Orders",
                        "class_type": "bfla",
                        "method": "GET",
                        "url": "/api/orders/1",
                        "actor_alias": "bob",
                        "proof_receipt_ids": [r_id],
                        "control_receipt_ids": ctrl_ids[:1],
                        "evidence_value": "ALICE_PRIVATE_ORDER_SECRET",
                        "summary": "Non-privileged actor bob can read protected order endpoint where anon is 401.",
                    })
                return _make_tool_msg("r25_3", "finish", {
                    "summary": "Stage 2.5 confirmed BFLA finding and promoted lead",
                    "untested_areas": [],
                })

            # Stage 2 Orders Shard: mutates order, gets baseline reads
            if "SUBSYSTEM SHARD SCOPE (" in sys_text and "/api/orders/" in sys_text:
                if len(tool_msgs) == 0:
                    return _make_tool_msg("s1_1", "http_request", {
                        "method": "GET",
                        "url": "/api/orders/1",
                        "actor": "anon",
                    })
                if len(tool_msgs) == 1:
                    return _make_tool_msg("s1_2", "http_request", {
                        "method": "GET",
                        "url": "/api/orders/1",
                        "actor": "bob",
                    })
                if len(tool_msgs) == 2:
                    # Mutate route to test GET cache invalidation before Stage 2.5!
                    return _make_tool_msg("s1_3", "http_request", {
                        "method": "POST",
                        "url": "/api/orders/1/cancel",
                        "actor": "alice",
                        "json_body": {"reason": "test"},
                    })
                if len(tool_msgs) == 3:
                    return _make_tool_msg("s1_4", "finish", {
                        "summary": "Shard explored orders",
                        "untested_areas": [],
                    })

            # Stage 2 Admin Shard
            if "SUBSYSTEM SHARD SCOPE (" in sys_text and "/api/admin/" in sys_text:
                if len(tool_msgs) == 0:
                    return _make_tool_msg("s2_1", "http_request", {
                        "method": "GET",
                        "url": "/api/admin/audit",
                        "actor": "alice",
                    })
                return _make_tool_msg("s2_2", "finish", {
                    "summary": "Shard finished admin",
                    "untested_areas": [],
                })

            # Stage 3 synthesis or fallback
            return _make_tool_msg("fin_x", "finish", {"summary": "done", "untested_areas": []})

    seed_surface = {
        "links": [
            {"method": "GET", "url": f"{base_url}/api/orders/1"},
            {"method": "GET", "url": f"{base_url}/api/orders/2"},
            {"method": "GET", "url": f"{base_url}/api/orders/list"},
            {"method": "GET", "url": f"{base_url}/api/orders/export"},
            {"method": "POST", "url": f"{base_url}/api/orders/1/cancel"},
            {"method": "GET", "url": f"{base_url}/api/admin/audit"},
            {"method": "GET", "url": f"{base_url}/api/admin/users"},
            {"method": "GET", "url": f"{base_url}/api/admin/config"},
            {"method": "GET", "url": f"{base_url}/api/admin/stats"},
        ]
    }
    try:
        transport = _ScriptedTransport()
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=SharedBudget(tokens=300_000, seconds=120),
            model="deepseek-chat",
            root_dir=tmp_path / "run",
            execution_mode="sharded",
            bootstrap_turns=4,
            shard_turns=8,
            max_shards=2,
            max_shard_retries=1,
            retry_model="deepseek-reasoner",
            retry_budget_ratio=0.15,
            max_retry_shards=1,
            seed_surface=seed_surface,
        )

        orig_eval = agentic_investigator.evaluate_stage25_retry_candidates
        orders_shard_holder: dict[str, str] = {"shard_id": "shard-1"}

        def _seed_lead_and_eval(**kwargs: Any) -> list[dict[str, Any]]:
            for cl in kwargs.get("clusters") or ():
                if "orders" in (getattr(cl, "families", None) or ()):
                    orders_shard_holder["shard_id"] = cl.shard_id
                    break
            target_sid = orders_shard_holder["shard_id"]
            if not inv.dispatcher.leads:
                bob_rids = [
                    rid
                    for rid in store.list_ids()
                    if store.get(rid).get("actor") == "bob"
                    and "/api/orders/1" in str(store.get(rid).get("url") or "")
                ]
                anon_rids = [
                    rid
                    for rid in store.list_ids()
                    if store.get(rid).get("actor") == "anon"
                    and "/api/orders/1" in str(store.get(rid).get("url") or "")
                ]
                inv.dispatcher.leads = [{
                    "lead_id": "L-001",
                    "title": "Orders BFLA needs clean verification",
                    "class_type": "bfla",
                    "method": "GET",
                    "url": f"{base_url}/api/orders/1",
                    "path": "/api/orders/1",
                    "route_template": "/api/orders/{id}",
                    "signal_type": "multistep_budget_exceeded",
                    "passed_stages": ["stage1_control", "stage2_diff"],
                    "verification_blocker": "stage3_clean_replay:failed_multistep_budget",
                    "proof_receipt_ids": bob_rids[:1],
                    "control_receipt_ids": anon_rids[:1],
                    "source_shard": target_sid,
                }]
                inv.dispatcher._save_leads()
                kwargs["active_leads"] = inv.dispatcher.leads
            return orig_eval(**kwargs)

        old_eval = agentic_investigator.evaluate_stage25_retry_candidates
        agentic_investigator.evaluate_stage25_retry_candidates = _seed_lead_and_eval  # type: ignore[assignment]
        try:
            summary = inv.run(resume=False)
        finally:
            agentic_investigator.evaluate_stage25_retry_candidates = old_eval  # type: ignore[assignment]

        target_sid = orders_shard_holder["shard_id"]
        assert summary["status"] == "finished"
        assert summary["findings_count"] == 1
        assert summary["leads_count"] == 0  # Promoted out of active leads!
        assert len(transport.stage25_requests) >= 1
        assert all(req["model"] == "deepseek-reasoner" for req in transport.stage25_requests)

        s25_retries = summary["sharding_summary"]["stage2_5_retries"]
        assert len(s25_retries) == 1
        assert s25_retries[0]["shard_id"] == target_sid
        assert s25_retries[0]["retry_model"] == "deepseek-reasoner"
        assert s25_retries[0]["findings"] == 1
        assert s25_retries[0]["promoted_leads"] == 1
        assert summary["sharding_summary"]["promoted_leads"] == 1
        assert summary["sharding_summary"]["retry_model"] == "deepseek-reasoner"

        # GET cache was invalidated for mutated /api/orders/1 -> Retry hit wire fresh
        assert state["cache_reads"] >= 2

        # Reports show Stage 2.5 row + confirmed finding, and NO stale lead duplicate!
        (tmp_path / "run" / "manifest.json").write_text(
            json.dumps({**summary, "target": base_url, "run_id": "test-s25"}),
            encoding="utf-8",
        )
        generate_run_reports(tmp_path / "run")
        md_text = (tmp_path / "run" / "report.md").read_text(encoding="utf-8")
        sarif_doc = json.loads((tmp_path / "run" / "report.sarif").read_text(encoding="utf-8"))
        assert f"`stage2.5:{target_sid}-retry1`" in md_text
        assert "deepseek-reasoner" in md_text
        assert "Broken Function Level Auth on Orders" in md_text
        assert "Orders BFLA needs clean verification" not in md_text
        assert len(sarif_doc["runs"][0]["results"]) == 1
        assert sarif_doc["runs"][0]["results"][0]["properties"]["verification_tier"] == "CONFIRMED"
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()
