"""Phase 5D tests: high-risk input surface prioritization, active-probe tracking, and bounded Stage 2 shard nudge."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_sharding import (  # noqa: E402
    SubsystemCluster,
    build_cross_shard_synthesis_prompts,
    build_shard_prompts,
    cluster_discovered_surface,
    collect_cross_shard_synthesis_context,
)
from agentic_surface import SurfaceFrontierTracker  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import SessionGate  # noqa: E402


def _tool_resp(
    call_id: str,
    name: str,
    args: dict[str, Any],
    *,
    prompt_tokens: int = 200,
    completion_tokens: int = 40,
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
    prompt_tokens: int = 200,
    completion_tokens: int = 40,
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


# ---------------------------------------------------------------------------
# 1. SurfaceFrontierTracker high-risk scoring, family filter, & active probing
# ---------------------------------------------------------------------------


def test_high_risk_unprobed_routes_ranking_family_filter_and_active_probe_clearing() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=("GET", "POST", "PUT", "DELETE"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )

    tracker.ingest_surface(
        {
            "url": "http://127.0.0.1:8080/",
            "links": [
                {"method": "GET", "url": "/about"},
                {"method": "GET", "url": "/help"},
                {"method": "GET", "url": "/catalog/list"},
                {"method": "GET", "url": "/articles/latest"},
                {"method": "GET", "url": "/articles/view?id=1&cate=news", "params": ["id", "cate"]},
                {"method": "GET", "url": "/files/download?file=report.pdf", "params": ["file"]},
                {"method": "GET", "url": "/catalog/search?q=widget&sort=asc", "params": ["q", "sort"]},
                {"method": "GET", "url": "/pages/render?page=home&view=full", "params": ["page", "view"]},
                {"method": "POST", "url": "/auth/logout"},
                {"method": "POST", "url": "/system/reboot"},
            ],
            "forms": [
                {
                    "method": "POST",
                    "url": "/files/upload",
                    "multipart_schema": {"files": ["file"], "fields": ["folder"]},
                },
                {
                    "method": "POST",
                    "url": "/admin/login",
                    "params": ["username", "password"],
                },
            ],
        },
        actor="anon",
    )

    ranked_a = tracker.high_risk_unprobed_routes(limit=12)
    ranked_b = tracker.high_risk_unprobed_routes(limit=12)
    assert ranked_a == ranked_b

    templates = [item["route_template"] for item in ranked_a]
    assert templates[0] == "/files/upload"
    assert "/admin/login" in templates
    assert "/articles/view" in templates
    assert "/files/download" in templates
    assert "/catalog/search" in templates
    assert "/pages/render" in templates

    # Parameterless informational GET pages & logout/reboot routes must never appear
    for excluded in ("/about", "/help", "/catalog/list", "/articles/latest", "/auth/logout", "/system/reboot"):
        assert excluded not in templates

    # Verify required schema fields and descending risk_score order
    scores = [item["risk_score"] for item in ranked_a]
    assert scores == sorted(scores, reverse=True)
    for item in ranked_a:
        assert set(item.keys()) == {"route_template", "methods", "params", "risk_score", "reason"}
        assert isinstance(item["risk_score"], int) and item["risk_score"] > 0
        assert isinstance(item["methods"], list) and item["methods"]
        assert isinstance(item["reason"], str) and item["reason"]

    # Upload score strictly exceeds plain parameterized GET routes and parameterless pages
    upload_score, _ = tracker.score_route_risk("/files/upload")
    download_score, _ = tracker.score_route_risk("/files/download")
    about_score, _ = tracker.score_route_risk("/about")
    assert upload_score > download_score > about_score

    # Family filtering
    files_only = tracker.high_risk_unprobed_routes(allowed_families={"files"})
    assert [item["route_template"] for item in files_only] == ["/files/upload", "/files/download"]
    articles_only = tracker.high_risk_unprobed_routes(allowed_families={"articles"})
    assert [item["route_template"] for item in articles_only] == ["/articles/view"]
    assert tracker.high_risk_unprobed_routes(allowed_families=set()) == []

    # Passive baseline GET on upload page does NOT clear POST /files/upload
    tracker.ingest_receipt({
        "url": "http://127.0.0.1:8080/files/upload",
        "method": "GET",
        "status": 200,
        "content_type": "text/html",
        "actor": "alice",
        "body": "<form method='POST' action='/files/upload' enctype='multipart/form-data'><input type='file' name='file'/></form>",
    })
    assert "/files/upload" in [r["route_template"] for r in tracker.high_risk_unprobed_routes(allowed_families={"files"})]

    # Active POST clears /files/upload
    tracker.ingest_receipt({
        "url": "http://127.0.0.1:8080/files/upload",
        "method": "POST",
        "status": 200,
        "content_type": "application/json",
        "actor": "alice",
        "body": '{"ok": true}',
    })
    assert "/files/upload" not in [r["route_template"] for r in tracker.high_risk_unprobed_routes(allowed_families={"files"})]

    # Single benign baseline GET on /files/download?file=report.pdf (dot in filename!) does NOT clear it
    tracker.ingest_receipt({
        "url": "http://127.0.0.1:8080/files/download?file=report.pdf",
        "method": "GET",
        "status": 200,
        "content_type": "text/plain",
        "actor": "alice",
        "body": "report",
    })
    assert "/files/download" in [r["route_template"] for r in tracker.high_risk_unprobed_routes(allowed_families={"files"})]

    # 2nd distinct query value variant clears /files/download
    tracker.ingest_receipt({
        "url": "http://127.0.0.1:8080/files/download?file=other.pdf",
        "method": "GET",
        "status": 200,
        "content_type": "text/plain",
        "actor": "alice",
        "body": "other",
    })
    assert tracker.high_risk_unprobed_routes(allowed_families={"files"}) == []

    # Single benign GET on /articles/view?id=1 does NOT clear; special-char probe clears immediately
    tracker.ingest_receipt({
        "url": "http://127.0.0.1:8080/articles/view?id=1",
        "method": "GET",
        "status": 200,
        "content_type": "text/html",
        "actor": "alice",
        "body": "<html>article 1</html>",
    })
    assert "/articles/view" in [r["route_template"] for r in tracker.high_risk_unprobed_routes(allowed_families={"articles"})]

    tracker.ingest_receipt({
        "url": "http://127.0.0.1:8080/articles/view?id=1'",
        "method": "GET",
        "status": 500,
        "content_type": "text/html",
        "actor": "alice",
        "body": "SQL syntax error",
    })
    assert tracker.high_risk_unprobed_routes(allowed_families={"articles"}) == []

    # Checkpoint serialization round-trip preserves active-probe & form state
    restored = SurfaceFrontierTracker.from_dict(tracker.to_dict())
    restored_tmpls = [r["route_template"] for r in restored.high_risk_unprobed_routes(limit=12)]
    assert "/files/upload" not in restored_tmpls
    assert "/files/download" not in restored_tmpls
    assert "/articles/view" not in restored_tmpls
    assert "/catalog/search" in restored_tmpls
    assert "/admin/login" in restored_tmpls


# ---------------------------------------------------------------------------
# 2. Risk-sorted shard routes & [MUST-TEST HIGH-RISK INPUTS] in build_shard_prompts
# ---------------------------------------------------------------------------


def test_cluster_and_build_shard_prompts_prioritize_high_risk_routes_and_emit_must_test_block() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=("GET", "POST"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )

    # Inject 40 distinct parameterless GET pages that sort alphabetically BEFORE high-risk routes
    links: list[dict[str, Any]] = [
        {"method": "GET", "url": f"/portal/aaa-info-{chr(97 + i // 26)}{chr(97 + i % 26)}"}
        for i in range(40)
    ]
    links.extend([
        {"method": "GET", "url": "/portal/zzz-download?file=guide.pdf", "params": ["file"]},
        {"method": "GET", "url": "/portal/zzz-search?q=hello&sort=desc", "params": ["q", "sort"]},
        {"method": "GET", "url": "/portal/zzz-article?id=5&cate=tech", "params": ["id", "cate"]},
        {"method": "POST", "url": "/portal/logout"},
    ])
    forms = [
        {
            "method": "POST",
            "url": "/portal/zzz-upload",
            "multipart_schema": {"files": ["attachment"], "fields": ["folder"]},
        },
        {
            "method": "POST",
            "url": "/portal/zzz-admin/login",
            "params": ["username", "password"],
        },
    ]
    tracker.ingest_surface({"url": "http://127.0.0.1:8080/", "links": links, "forms": forms})

    clusters = cluster_discovered_surface(tracker, max_shards=1, min_routes_for_sharding=8)
    assert len(clusters) == 1
    cluster = clusters[0]

    # Top of cluster.routes MUST be the high-risk parameterized/upload/auth routes, never buried behind /portal/aaa-info-*
    top_five = cluster.routes[:5]
    assert top_five[0] == "/portal/zzz-upload"
    assert set(top_five) == {
        "/portal/zzz-upload",
        "/portal/zzz-admin/login",
        "/portal/zzz-download",
        "/portal/zzz-search",
        "/portal/zzz-article",
    }

    sys_p, usr_p = build_shard_prompts(
        cluster,
        base_system_prompt="BASE PROMPT",
        surface_tracker=tracker,
    )
    assigned_routes_section = sys_p.split("- Assigned routes:\n", 1)[1].split("\n- ", 1)[0]
    for hr_route in (
        "/portal/zzz-upload",
        "/portal/zzz-admin/login",
        "/portal/zzz-download",
        "/portal/zzz-search",
        "/portal/zzz-article",
    ):
        assert hr_route in assigned_routes_section

    # High-risk routes appear BEFORE parameterless informational pages in Assigned routes (and are never truncated at 35)
    assert len(cluster.routes) > 35
    assert assigned_routes_section.index("/portal/zzz-upload") < assigned_routes_section.index("/portal/aaa-info-aa")
    assert assigned_routes_section.index("/portal/zzz-download") < assigned_routes_section.index("/portal/aaa-info-aa")

    # Initial user prompt contains concise [MUST-TEST HIGH-RISK INPUTS] block with methods + routes + params
    assert "[MUST-TEST HIGH-RISK INPUTS]" in usr_p
    must_test_section = usr_p.split("[MUST-TEST HIGH-RISK INPUTS]", 1)[1].split("\n[RELEVANT BOOTSTRAP RECEIPTS]", 1)[0]
    assert "POST /portal/zzz-upload" in must_test_section
    assert "POST /portal/zzz-admin/login" in must_test_section
    assert "GET /portal/zzz-download" in must_test_section
    assert "file" in must_test_section
    assert "q" in must_test_section
    assert "id" in must_test_section
    assert "/portal/logout" not in must_test_section
    assert "/portal/aaa-info-aa" not in must_test_section

    # Manually constructed unsorted SubsystemCluster (no surface_tracker) also risk-sorts and emits [MUST-TEST HIGH-RISK INPUTS]
    manual_cluster = SubsystemCluster(
        shard_id="shard-1",
        name="app",
        families=["app"],
        routes=["/app/about", "/app/help", "/app/search", "/app/upload"],
        write_ops=["POST /app/upload"],
        objects=[],
        params={"/app/search": ["q", "cate"]},
    )
    manual_sys, manual_usr = build_shard_prompts(manual_cluster, base_system_prompt="BASE")
    manual_routes_sec = manual_sys.split("- Assigned routes:\n", 1)[1].split("\n- ", 1)[0]
    assert manual_routes_sec.index("/app/upload") < manual_routes_sec.index("/app/about")
    assert manual_routes_sec.index("/app/search") < manual_routes_sec.index("/app/about")
    assert "[MUST-TEST HIGH-RISK INPUTS]" in manual_usr
    assert "POST /app/upload" in manual_usr
    assert "GET /app/search" in manual_usr

    # Parameterless-only cluster does not emit noisy [MUST-TEST HIGH-RISK INPUTS]
    plain_cluster = SubsystemCluster(
        shard_id="shard-2",
        name="info",
        families=["info"],
        routes=["/info/about", "/info/faq"],
        write_ops=[],
        objects=[],
        params={},
    )
    _, plain_usr = build_shard_prompts(plain_cluster, base_system_prompt="BASE")
    assert "[MUST-TEST HIGH-RISK INPUTS]" not in plain_usr


# ---------------------------------------------------------------------------
# 3. collect_cross_shard_synthesis_context surfaces remaining high-risk routes
# ---------------------------------------------------------------------------


def test_collect_cross_shard_synthesis_context_surfaces_high_risk_unprobed_routes(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path)
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=("GET", "POST"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )
    tracker.ingest_surface({
        "url": "http://127.0.0.1:8080/",
        "links": [
            {"method": "GET", "url": "/files/dl?file=a.txt", "params": ["file"]},
            {"method": "GET", "url": "/articles/show?id=1", "params": ["id"]},
            {"method": "GET", "url": "/catalog/find?q=book", "params": ["q"]},
            {"method": "GET", "url": "/catalog/list?sort=price", "params": ["sort"]},
            {"method": "GET", "url": "/nav/jump?next=/home", "params": ["next"]},
            {"method": "GET", "url": "/reports/view?template=default", "params": ["template"]},
            {"method": "GET", "url": "/pages/load?page=intro", "params": ["page"]},
            {"method": "GET", "url": "/probed/search?search=ok", "params": ["search"]},
        ],
        "forms": [
            {
                "method": "POST",
                "url": "/files/upload",
                "multipart_schema": {"files": ["file"], "fields": ["dir"]},
            }
        ],
    })
    # Actively probe /probed/search (special char) so it must NOT appear in synthesis context
    tracker.ingest_receipt({
        "url": "http://127.0.0.1:8080/probed/search?search=' OR 1=1--",
        "method": "GET",
        "status": 200,
        "actor": "alice",
        "body": "ok",
    })

    shard_results = [
        {"shard_id": "shard-1", "finish_summary": "checked files", "untested_areas": []},
        {"shard_id": "shard-2", "finish_summary": "checked articles", "untested_areas": []},
    ]
    ctx = collect_cross_shard_synthesis_context(
        shard_results=shard_results,
        findings=[],
        receipts=store,
        surface_tracker=tracker,
    )
    assert ctx["should_trigger"] is True
    hr = ctx["high_risk_unprobed_routes"]
    assert len(hr) == 6
    assert hr[0]["route_template"] == "/files/upload"
    assert all(entry["route_template"] != "/probed/search" for entry in hr)
    assert [entry["risk_score"] for entry in hr] == sorted((entry["risk_score"] for entry in hr), reverse=True)

    # Single shard still does not trigger Stage 3
    single_ctx = collect_cross_shard_synthesis_context(
        shard_results=[shard_results[0]],
        findings=[],
        receipts=store,
        surface_tracker=tracker,
    )
    assert single_ctx["should_trigger"] is False
    assert len(single_ctx["high_risk_unprobed_routes"]) == 6

    # Stage 3 prompt embeds high_risk_unprobed_routes in user prompt payload while keeping sys prompt compact
    synth_sys, synth_usr = build_cross_shard_synthesis_prompts(
        base_system_prompt="BASE SYSTEM PROMPT",
        synthesis_context=ctx,
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
        http_budget_remaining=30,
    )
    assert len(synth_sys) < 1800
    assert "high_risk_unprobed_routes" in synth_usr
    assert "/files/upload" in synth_usr
    assert "/probed/search" not in synth_usr


# ---------------------------------------------------------------------------
# 4. AgenticInvestigator Stage 2 bounded shard high-risk coverage nudge
# ---------------------------------------------------------------------------


def _start_parameterized_multi_family_server() -> tuple[ThreadingHTTPServer, str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == "/":
                html = (
                    "<html><body>"
                    "<a href='/files/list'>Files</a>"
                    "<a href='/files/about'>Files About</a>"
                    "<a href='/files/download?file=readme.txt'>Download</a>"
                    "<form method='POST' action='/files/upload' enctype='multipart/form-data'>"
                    "<input type='file' name='file'/><input name='folder'/></form>"
                    "<a href='/articles/list'>Articles</a>"
                    "<a href='/articles/about'>Articles About</a>"
                    "<a href='/articles/view?id=1&cate=news'>View Article</a>"
                    "<a href='/articles/search?q=hello'>Search Articles</a>"
                    "<a href='/catalog/list'>Catalog</a>"
                    "<a href='/catalog/about'>Catalog About</a>"
                    "<a href='/catalog/items?sort=asc'>Catalog Sort</a>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            payload = json.dumps({"path": path, "query": parsed.query, "ok": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            _ = self.rfile.read(length)
            payload = json.dumps({"uploaded": True, "path": urlsplit(self.path).path}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def _parse_finish_tool_reply(messages: list[dict[str, Any]], call_id: str) -> dict[str, Any] | None:
    for msg in messages:
        if msg.get("role") == "tool" and msg.get("tool_call_id") == call_id:
            raw = str(msg.get("content") or "")
            json_part = raw.split("\n[", 1)[0].strip()
            try:
                parsed = json.loads(json_part)
            except ValueError:
                return None
            return parsed if isinstance(parsed, dict) else None
    return None


def test_stage2_shard_nudge_rejects_once_then_accepts_second_finish_and_probing_clears(
    tmp_path: Path,
) -> None:
    srv, base_url = _start_parameterized_multi_family_server()
    try:
        # Case 1: Premature finish rejected ONCE (strict 1-nudge bound), 2nd finish accepted immediately
        dir_a = tmp_path / "case_strict_bound"
        dir_a.mkdir()
        store_a = ReceiptStore(dir_a)
        client_a = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store_a,
            actors=ActorManager([{"alias": "alice", "role": "member", "tenant": "t1"}]),
            allowed_methods=("GET", "POST"),
            max_requests=80,
        )
        budget_a = SharedBudget(http=80, tokens=240_000, seconds=120)
        lock = threading.Lock()
        boot_step = [0]
        shard_steps: dict[str, int] = {}
        shard_first_finish_replies: dict[str, dict[str, Any]] = {}
        shard_user_prompts: dict[str, str] = {}

        class _BoundTransport:
            def __init__(self) -> None:
                self.calls = 0
                self.provider_responses: list[dict[str, Any]] = []
                self.session_gate = SessionGate()

            def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
                with lock:
                    self.calls += 1
                msgs = body.get("messages") or []
                sys_msg = str((msgs[0] if msgs else {}).get("content") or "")
                usr_msg = str((msgs[1] if len(msgs) > 1 else {}).get("content") or "")

                if "SUBSYSTEM SHARD SCOPE (" not in sys_msg:
                    with lock:
                        boot_step[0] += 1
                        step = boot_step[0]
                    if step == 1:
                        return _tool_resp("b1", "http_request", {"method": "GET", "url": "/", "actor": "alice"})
                    if step == 2:
                        return _tool_resp("b2", "extract_surface", {"receipt_id": "req-0001"})
                    return _tool_resp("b3", "finish", {"summary": "stage 1 done"})

                marker = "SUBSYSTEM SHARD SCOPE ("
                shard_id = sys_msg[sys_msg.index(marker) + len(marker) :].split(":", 1)[0].strip()
                with lock:
                    shard_user_prompts.setdefault(shard_id, usr_msg)
                    step = shard_steps.get(shard_id, 0) + 1
                    shard_steps[shard_id] = step

                if step == 1:
                    return _tool_resp(f"{shard_id}_fin1", "finish", {"summary": "premature finish 1"})
                if step == 2:
                    reply = _parse_finish_tool_reply(msgs, f"{shard_id}_fin1")
                    if reply is not None:
                        with lock:
                            shard_first_finish_replies[shard_id] = reply
                    # Still call finish without probing to prove strict max-1 nudge bound
                    return _tool_resp(f"{shard_id}_fin2", "finish", {"summary": "second finish accepted"})
                raise AssertionError(f"Shard {shard_id} looped past 2nd finish (step={step})")

        inv_a = AgenticInvestigator(
            http_client=client_a,
            receipt_store=store_a,
            transport=_BoundTransport(),  # type: ignore[arg-type]
            budget=budget_a,
            model="test-model",
            root_dir=dir_a,
            discovery_hints=["/"],
            max_turns=30,
            execution_mode="sharded",
            max_shards=2,
            bootstrap_turns=5,
            shard_turns=8,
            enable_cross_shard_synthesis=False,
            sleep_fn=lambda _s: None,
        )
        res_a = inv_a.run()
        client_a.close()

        assert res_a["status"] == "finished"
        shards_a = res_a["sharding_summary"]["shards"]
        assert len(shards_a) == 2
        for s_row in shards_a:
            sid = s_row["shard_id"]
            assert s_row["status"] == "finished"
            assert s_row["calls"] == 2
            assert "[MUST-TEST HIGH-RISK INPUTS]" in shard_user_prompts[sid]
            rej = shard_first_finish_replies[sid]
            assert rej["rejected"] is True
            assert rej["finished"] is False
            assert rej["nudge_type"] == "shard_high_risk_coverage"
            assert rej["nudge_count"] == 1
            assert rej["max_nudges"] == 1
            assert rej["unprobed_high_risk_routes"]
            # Every nudged route belongs to that shard's assigned families
            fams = set(s_row["families"])
            for route_info in rej["unprobed_high_risk_routes"]:
                first_seg = route_info["route_template"].strip("/").split("/", 1)[0]
                assert first_seg in fams

        # Case 2: Shard probes its nudged routes after Turn 1 rejection, clearing unprobed tracker entries
        dir_b = tmp_path / "case_probe_clears"
        dir_b.mkdir()
        store_b = ReceiptStore(dir_b)
        client_b = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store_b,
            actors=ActorManager([{"alias": "alice", "role": "member", "tenant": "t1"}]),
            allowed_methods=("GET", "POST"),
            max_requests=80,
        )
        budget_b = SharedBudget(http=80, tokens=240_000, seconds=120)
        boot_b = [0]
        shard_b_steps: dict[str, int] = {}

        class _ProbeAfterNudgeTransport:
            def __init__(self) -> None:
                self.calls = 0
                self.provider_responses: list[dict[str, Any]] = []
                self.session_gate = SessionGate()

            def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
                with lock:
                    self.calls += 1
                msgs = body.get("messages") or []
                sys_msg = str((msgs[0] if msgs else {}).get("content") or "")
                if "SUBSYSTEM SHARD SCOPE (" not in sys_msg:
                    with lock:
                        boot_b[0] += 1
                        step = boot_b[0]
                    if step == 1:
                        return _tool_resp("b1", "http_request", {"method": "GET", "url": "/", "actor": "alice"})
                    if step == 2:
                        return _tool_resp("b2", "extract_surface", {"receipt_id": "req-0001"})
                    return _tool_resp("b3", "finish", {"summary": "boot done"})

                marker = "SUBSYSTEM SHARD SCOPE ("
                shard_id = sys_msg[sys_msg.index(marker) + len(marker) :].split(":", 1)[0].strip()
                with lock:
                    step = shard_b_steps.get(shard_id, 0) + 1
                    shard_b_steps[shard_id] = step
                if step == 1:
                    return _tool_resp(f"{shard_id}_fin1", "finish", {"summary": "early"})
                if step == 2:
                    rej = _parse_finish_tool_reply(msgs, f"{shard_id}_fin1")
                    assert rej is not None and rej["rejected"] is True
                    probe_calls: list[tuple[str, str, dict[str, Any]]] = []
                    for i, entry in enumerate(rej["unprobed_high_risk_routes"]):
                        tmpl = entry["route_template"]
                        if "POST" in entry["methods"]:
                            probe_calls.append((
                                f"{shard_id}_p{i}",
                                "http_request",
                                {"method": "POST", "url": tmpl, "actor": "alice", "form_body": {"folder": "test"}},
                            ))
                        else:
                            pname = entry["params"][0] if entry["params"] else "id"
                            probe_calls.append((
                                f"{shard_id}_p{i}",
                                "http_request",
                                {"method": "GET", "url": f"{tmpl}?{pname}=../../etc/passwd", "actor": "alice"},
                            ))
                    return _multi_resp(probe_calls)
                return _tool_resp(f"{shard_id}_fin2", "finish", {"summary": "probed high-risk routes"})

        inv_b = AgenticInvestigator(
            http_client=client_b,
            receipt_store=store_b,
            transport=_ProbeAfterNudgeTransport(),  # type: ignore[arg-type]
            budget=budget_b,
            model="test-model",
            root_dir=dir_b,
            discovery_hints=["/"],
            max_turns=30,
            execution_mode="sharded",
            max_shards=2,
            bootstrap_turns=5,
            shard_turns=8,
            enable_cross_shard_synthesis=False,
            sleep_fn=lambda _s: None,
        )
        res_b = inv_b.run()
        client_b.close()

        assert res_b["status"] == "finished"
        assert inv_b.dispatcher.surface_tracker.high_risk_unprobed_routes() == []
    finally:
        srv.shutdown()
        srv.server_close()


def test_stage2_shard_nudge_skipped_when_turns_http_or_tokens_are_low_and_monolithic_unaffected(
    tmp_path: Path,
) -> None:
    srv, base_url = _start_parameterized_multi_family_server()
    lock = threading.Lock()

    def _run_sharded_immediate_finish(
        subdir: str,
        *,
        http_limit: int,
        token_limit: int,
        shard_turns: int,
        drain_tokens_before_shard: int = 0,
    ) -> dict[str, Any]:
        run_dir = tmp_path / subdir
        run_dir.mkdir()
        store = ReceiptStore(run_dir)
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=ActorManager([{"alias": "alice", "role": "member", "tenant": "t1"}]),
            allowed_methods=("GET", "POST"),
            max_requests=http_limit,
        )
        budget = SharedBudget(http=http_limit, tokens=token_limit, seconds=120)
        boot_step = [0]
        shard_calls_seen: dict[str, int] = {}

        class _ImmediateFinishTransport:
            def __init__(self) -> None:
                self.calls = 0
                self.provider_responses: list[dict[str, Any]] = []
                self.session_gate = SessionGate()

            def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
                with lock:
                    self.calls += 1
                msgs = body.get("messages") or []
                sys_msg = str((msgs[0] if msgs else {}).get("content") or "")
                if "SUBSYSTEM SHARD SCOPE (" not in sys_msg:
                    with lock:
                        boot_step[0] += 1
                        step = boot_step[0]
                    if step == 1:
                        return _tool_resp("b1", "http_request", {"method": "GET", "url": "/", "actor": "alice"})
                    if step == 2:
                        return _tool_resp("b2", "extract_surface", {"receipt_id": "req-0001"})
                    return _tool_resp("b3", "finish", {"summary": "boot done"})

                marker = "SUBSYSTEM SHARD SCOPE ("
                shard_id = sys_msg[sys_msg.index(marker) + len(marker) :].split(":", 1)[0].strip()
                with lock:
                    if drain_tokens_before_shard > 0 and budget.used["tokens"] < drain_tokens_before_shard:
                        budget.used["tokens"] = drain_tokens_before_shard
                    cnt = shard_calls_seen.get(shard_id, 0) + 1
                    shard_calls_seen[shard_id] = cnt
                if cnt > 1:
                    raise AssertionError(f"Expected no nudge for {subdir}/{shard_id}, got call #{cnt}")
                return _tool_resp(f"{shard_id}_fin", "finish", {"summary": "done under tight budget"})

        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_ImmediateFinishTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=run_dir,
            discovery_hints=["/"],
            max_turns=30,
            execution_mode="sharded",
            max_shards=2,
            bootstrap_turns=5,
            shard_turns=shard_turns,
            enable_cross_shard_synthesis=False,
            sleep_fn=lambda _s: None,
        )
        try:
            return inv.run()
        finally:
            client.close()

    try:
        # 1. Remaining shard turns < 3 (shard_turns=3 -> turn 1 has 2 turns left) -> skips nudge
        res_low_turns = _run_sharded_immediate_finish(
            "low_turns",
            http_limit=80,
            token_limit=240_000,
            shard_turns=3,
        )
        assert res_low_turns["status"] == "finished"
        assert len(res_low_turns["sharding_summary"]["shards"]) == 2
        assert all(s["calls"] == 1 for s in res_low_turns["sharding_summary"]["shards"])

        # 2. Remaining shared HTTP budget < 6 (limit=6, bootstrap uses 1 -> rem=5 < 6) -> skips nudge
        res_low_http = _run_sharded_immediate_finish(
            "low_http",
            http_limit=6,
            token_limit=240_000,
            shard_turns=8,
        )
        assert res_low_http["status"] == "finished"
        assert len(res_low_http["sharding_summary"]["shards"]) == 2
        assert all(s["calls"] == 1 for s in res_low_http["sharding_summary"]["shards"])

        # 3. Remaining global tokens low (< 15% / < 12k) -> skips nudge
        res_low_tokens = _run_sharded_immediate_finish(
            "low_tokens",
            http_limit=80,
            token_limit=100_000,
            shard_turns=8,
            drain_tokens_before_shard=90_000,
        )
        assert res_low_tokens["status"] == "finished"
        assert len(res_low_tokens["sharding_summary"]["shards"]) == 2
        assert all(s["calls"] == 1 for s in res_low_tokens["sharding_summary"]["shards"])

        # 4. Direct guard check: monolithic (shard_cluster=None) never triggers Stage 2 shard nudge
        mono_dir = tmp_path / "mono_check"
        mono_dir.mkdir()
        mono_store = ReceiptStore(mono_dir)
        mono_client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=mono_store,
            actors=ActorManager(),
            allowed_methods=("GET", "POST"),
            max_requests=80,
        )
        mono_budget = SharedBudget(http=80, tokens=200_000, seconds=120)
        try:
            inv_mono = AgenticInvestigator(
                http_client=mono_client,
                receipt_store=mono_store,
                transport=object(),  # type: ignore[arg-type]
                budget=mono_budget,
                model="test-model",
                root_dir=mono_dir,
            )
            inv_mono.dispatcher.surface_tracker.ingest_surface({
                "url": base_url,
                "links": [{"method": "GET", "url": "/files/download?file=a.txt", "params": ["file"]}],
            })
            assert (
                inv_mono._maybe_nudge_shard_high_risk_finish(
                    dispatcher=inv_mono.dispatcher,
                    shard_cluster=None,
                    turn=1,
                    max_turns=10,
                    shard_high_risk_nudges=0,
                    shard_token_quota=None,
                    shard_tokens_used=0,
                )
                is None
            )
        finally:
            mono_client.close()
    finally:
        srv.shutdown()
        srv.server_close()
