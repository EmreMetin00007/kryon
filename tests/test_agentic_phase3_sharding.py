"""Phase 3 tests: thread-safe shared infrastructure, subsystem clustering, and sharded execution."""
from __future__ import annotations

import concurrent.futures
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

import agentic_runner  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_sharding import (  # noqa: E402
    build_shard_prompts,
    cluster_discovered_surface,
    extract_resource_family,
)
from agentic_surface import SurfaceFrontierTracker  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import MeteredProviderTransport, SessionGate  # noqa: E402


# ---------------------------------------------------------------------------
# 1. Pure URL-path family extraction & balanced bin-packing
# ---------------------------------------------------------------------------


def test_extract_resource_family_and_clustering_bin_packing() -> None:
    assert extract_resource_family("/") == "root"
    assert extract_resource_family("/robots.txt") == "root"
    assert extract_resource_family("/favicon.ico") == "root"
    assert extract_resource_family("/api/v1/orders/42") == "orders"
    assert extract_resource_family("/orders/42") == "orders"
    assert extract_resource_family("/rest/v2/invoices/{id}") == "invoices"
    assert extract_resource_family("/api/users/me?tab=profile") == "users"

    # Tiny target (< min_routes_for_sharding=8) falls back to 1 cluster
    tiny = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:9000/",
        allowed_methods=("GET",),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )
    for route in ("/", "/robots.txt", "/api/v1/orders", "/api/v1/users"):
        tiny.discovered_routes[("GET", route)] = route
    tiny_clusters = cluster_discovered_surface(tiny, max_shards=3, min_routes_for_sharding=8)
    assert len(tiny_clusters) == 1
    assert tiny_clusters[0].shard_id == "shard-1"

    # Rich multi-family surface (UI + /api/v1/...) splits cleanly into 3 balanced shards
    rich = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:9000/",
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )
    routes = [
        ("GET", "/"),
        ("GET", "/robots.txt"),
        ("GET", "/orders"),
        ("GET", "/orders/101"),
        ("GET", "/api/v1/orders"),
        ("GET", "/api/v1/orders/101"),
        ("GET", "/api/v1/invoices"),
        ("GET", "/api/v1/invoices/202"),
        ("GET", "/api/v1/tickets"),
        ("GET", "/api/v1/tickets/303"),
        ("GET", "/api/v1/reports/export"),
        ("GET", "/users/profile"),
    ]
    for method, path in routes:
        rich.discovered_routes[(method, path)] = path
    rich.declared_write_ops.add(("PUT", "/api/v1/orders/{id}"))
    rich.declared_write_ops.add(("POST", "/api/v1/tickets"))
    rich.discovered_objects["/api/v1/orders/101"] = {
        "path": "/api/v1/orders/101",
        "template": "/api/v1/orders/{id}",
        "owner_actor": "alice",
        "seen_by": {"alice"},
        "listed_by": {"alice"},
        "tested_by": set(),
        "verified_2xx": True,
    }
    rich.discovered_objects["/api/v1/invoices/202"] = {
        "path": "/api/v1/invoices/202",
        "template": "/api/v1/invoices/{id}",
        "owner_actor": "alice",
        "seen_by": {"alice"},
        "listed_by": {"alice"},
        "tested_by": set(),
        "verified_2xx": True,
    }
    rich.discovered_params["/api/v1/reports/export"] = {"sort", "format"}

    clusters = cluster_discovered_surface(rich, max_shards=3, min_routes_for_sharding=8)
    assert len(clusters) == 3
    assert [c.shard_id for c in clusters] == ["shard-1", "shard-2", "shard-3"]

    # Every family appears in exactly one shard, and UI + API routes for `orders` stay together
    all_fams = [fam for c in clusters for fam in c.families]
    assert len(all_fams) == len(set(all_fams))
    assert "orders" in all_fams
    orders_cluster = next(c for c in clusters if "orders" in c.families)
    assert "/orders/{id}" in orders_cluster.routes
    assert "/api/v1/orders/{id}" in orders_cluster.routes
    assert "PUT /api/v1/orders/{id}" in orders_cluster.write_ops
    assert "/api/v1/orders/101" in orders_cluster.objects

    sys_p, usr_p = build_shard_prompts(
        orders_cluster,
        base_system_prompt="BASE SYSTEM PROMPT",
        bootstrap_findings=[
            {
                "finding_id": "F-001",
                "class_type": "auth_bypass",
                "method": "GET",
                "path": "/api/v1/invoices",
                "actor": "anon",
                "evidence_value": "invoice_secret",
            }
        ],
    )
    assert "BASE SYSTEM PROMPT" in sys_p
    assert "SUBSYSTEM SHARD SCOPE" in sys_p
    assert "F-001" in sys_p
    assert "/api/v1/orders/{id}" in sys_p
    assert orders_cluster.shard_id in usr_p


# ---------------------------------------------------------------------------
# 2. Thread safety of ReceiptStore, ActorManager, and AgenticHTTPClient
# ---------------------------------------------------------------------------


def test_receipt_store_and_http_client_concurrent_thread_safety(tmp_path: Path) -> None:
    session_ids_seen: set[int] = set()
    lock = threading.Lock()

    class _ConcurrentHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            qs = parse_qs(parsed.query)
            payload = json.dumps({"path": parsed.path, "idx": qs.get("i", [""])[0]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "sid=secret-cookie-value-1234; Path=/")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            payload = json.dumps({"ok": True, "echo": raw, "access_token": "tok-" + raw}).encode("utf-8")
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    class _ConcurrentServer(ThreadingHTTPServer):
        request_queue_size = 64

    srv = _ConcurrentServer(("127.0.0.1", 0), _ConcurrentHandler)
    port = srv.server_address[1]
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()

    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer alice-secret-token"},
    ])
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{port}/",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=200,
    )

    try:
        def _worker(tid: int) -> tuple[str, str]:
            with lock:
                session_ids_seen.add(id(client._get_session()))
            r1 = client.request(method="GET", url=f"/items?i={tid}", actor="alice", force=True)
            r2 = client.request(
                method="POST",
                url="/signup",
                actor="anon",
                json_body={"user": f"u{tid}"},
                save_session_as=f"dyn-{tid}",
            )
            _ = actors.summaries()
            _ = actors.all_secrets()
            return r1["receipt_id"], r2["receipt_id"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(_worker, range(20)))

        all_rids = [rid for pair in results for rid in pair]
        assert len(all_rids) == 40
        assert len(set(all_rids)) == 40
        assert sorted(all_rids) == [f"req-{i:04d}" for i in range(1, 41)]
        assert store.count() == 40
        assert client.budget.used == 40
        # Thread-local sessions should be distinct across worker threads (<=20, >1)
        assert len(session_ids_seen) > 1
        assert len(actors.summaries()) == 22  # anon + alice + 20 dyn-i
    finally:
        client.close()
        assert client._sessions == []
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 3. MeteredProviderTransport true concurrent provider I/O + settlement
# ---------------------------------------------------------------------------


def test_metered_provider_transport_concurrent_in_flight(tmp_path: Path) -> None:
    inflight_lock = threading.Lock()
    inflight = 0
    max_inflight = 0

    class _DelayedProviderHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_POST(self) -> None:
            nonlocal inflight, max_inflight
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            with inflight_lock:
                inflight += 1
                max_inflight = max(max_inflight, inflight)
            try:
                time.sleep(0.22)
            finally:
                with inflight_lock:
                    inflight -= 1
            body = json.dumps({
                "id": "cmpl-conc",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _DelayedProviderHandler)
    port = srv.server_address[1]
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()

    private_dir = tmp_path / "private"
    private_dir.mkdir(parents=True, exist_ok=True)
    budget = SharedBudget(http=20, tokens=40_000, seconds=60)
    transport = MeteredProviderTransport(
        budget=budget,
        private=private_dir,
        provider=f"http://127.0.0.1:{port}/v1",
        models={"test-model"},
        api_key="loopback-key",
        session_gate=SessionGate(),
    )

    try:
        def _call(idx: int) -> dict[str, Any]:
            return transport.complete({
                "model": "test-model",
                "messages": [{"role": "user", "content": f"ping {idx}"}],
                "max_tokens": 64,
            })

        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(_call, 1)
            f2 = pool.submit(_call, 2)
            r1 = f1.result()
            r2 = f2.result()
        elapsed = time.monotonic() - started

        assert r1["choices"][0]["message"]["content"] == "ok"
        assert r2["choices"][0]["message"]["content"] == "ok"
        assert max_inflight == 2
        assert elapsed < 0.40
        snap = budget.snapshot()
        assert snap["used"]["tokens"] == 300
        assert snap["reserved"]["tokens"] == 0
        assert transport.calls == 2
        assert len(transport.provider_requests) == 2
        assert len(transport.provider_responses) == 2
        assert {row["call"] for row in transport.provider_responses} == {1, 2}
        assert transport.upstream is None
        assert len(transport._active_upstreams) == 0
    finally:
        transport.close_upstream()
        srv.shutdown()
        srv.server_close()


def test_metered_provider_transport_close_upstream_multi(tmp_path: Path) -> None:
    private_dir = tmp_path / "private"
    private_dir.mkdir(parents=True, exist_ok=True)
    transport = MeteredProviderTransport(
        budget=SharedBudget(http=10, tokens=10_000, seconds=60),
        private=private_dir,
        provider="http://127.0.0.1:1/v1",
        models={"m"},
        api_key="k",
    )
    closed: list[str] = []

    class _FakeUpstream:
        def __init__(self, label: str, stall: bool = False) -> None:
            self.label = label
            self.stall = stall

        def close(self) -> None:
            if self.stall:
                time.sleep(2.0)
            closed.append(self.label)

    u1 = _FakeUpstream("u1")
    u2 = _FakeUpstream("u2", stall=True)
    transport._active_upstreams.update({u1, u2})
    transport.upstream = u2

    t0 = time.monotonic()
    transport.close_upstream()
    dt = time.monotonic() - t0
    assert dt < 0.5
    assert "u1" in closed
    assert transport.upstream is None
    assert len(transport._active_upstreams) == 0


# ---------------------------------------------------------------------------
# 4. End-to-end Sharded Execution + Fallback + Runner Plan-Only
# ---------------------------------------------------------------------------


def _tool_call_resp(call_id: str, name: str, args: dict[str, Any], tokens: int = 120) -> dict[str, Any]:
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
            "prompt_tokens": tokens // 2,
            "completion_tokens": tokens - (tokens // 2),
            "total_tokens": tokens,
        },
    }


def _multi_tool_resp(calls: list[tuple[str, str, dict[str, Any]]], tokens: int = 120) -> dict[str, Any]:
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
            "prompt_tokens": tokens // 2,
            "completion_tokens": tokens - (tokens // 2),
            "total_tokens": tokens,
        },
    }


def test_sharded_end_to_end_parallel_execution_and_merge(tmp_path: Path) -> None:
    class _MultiFamilyAppHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            path = parsed.path
            auth = self.headers.get("Authorization", "")
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
                    "<a href='/api/v1/reports?sort=name'>Reports</a>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            if path in {"/api/v1/orders", "/api/v1/orders/101"}:
                # Intentional auth_bypass: accessible as anon
                body = json.dumps({"order_id": 101, "secret_code": "ORD_SECRET_991"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path in {"/api/v1/invoices", "/api/v1/invoices/202"}:
                # Intentional auth_bypass: accessible as anon
                body = json.dumps({"invoice_id": 202, "secret_code": "INV_SECRET_882"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path in {"/api/v1/tickets", "/api/v1/tickets/303"}:
                # Intentional auth_bypass: accessible as anon
                body = json.dumps({"ticket_id": 303, "secret_code": "TKT_SECRET_773"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/api/v1/reports":
                if not auth:
                    self.send_response(401)
                    self.end_headers()
                    return
                body = json.dumps({"reports": []}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MultiFamilyAppHandler)
    port = srv.server_address[1]
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()

    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-alice"},
    ])
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{port}/",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=200,
    )
    budget = SharedBudget(http=200, tokens=200_000, seconds=120)
    shard_barrier = threading.Barrier(3, timeout=3.0)
    shard_threads_seen: set[int] = set()
    state_lock = threading.Lock()

    class _ScriptedShardedTransport:
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
                # Stage 1 Bootstrap
                with state_lock:
                    self._boot_step += 1
                    step = self._boot_step
                if step == 1:
                    return _multi_tool_resp([
                        ("b1", "http_request", {"method": "GET", "url": "/", "actor": "alice"}),
                        ("b2", "http_request", {"method": "GET", "url": "/api/v1/orders/101", "actor": "anon"}),
                        ("b3", "http_request", {"method": "GET", "url": "/nonexistent-ctrl", "actor": "anon"}),
                    ])
                if step == 2:
                    return _multi_tool_resp([
                        ("b4", "extract_surface", {"receipt_id": "req-0001"}),
                        (
                            "b5",
                            "record_finding",
                            {
                                "class_type": "auth_bypass",
                                "title": "Orders unauthenticated access",
                                "method": "GET",
                                "url": "/api/v1/orders/101",
                                "actor": "anon",
                                "severity": "high",
                                "evidence_value": "ORD_SECRET_991",
                                "excerpt": "ORD_SECRET_991",
                                "summary": "Bootstrap verified auth bypass on orders.",
                                "proof_receipt_ids": ["req-0002"],
                                "control_receipt_ids": ["req-0001"],
                            },
                        ),
                    ])
                return _tool_call_resp("b6", "finish", {"summary": "bootstrap mapped routes"})

            # Stage 2 Shard
            marker = "SUBSYSTEM SHARD SCOPE ("
            start = sys_msg.index(marker) + len(marker)
            shard_id = sys_msg[start:].split(":", 1)[0].strip()
            with state_lock:
                shard_threads_seen.add(threading.get_ident())
                step = self._shard_steps.get(shard_id, 0) + 1
                self._shard_steps[shard_id] = step

            if step == 1:
                # Prove true parallel execution across shards via barrier!
                shard_barrier.wait()
                if "invoices" in sys_msg.split("Assigned routes:", 1)[1]:
                    return _tool_call_resp(
                        f"{shard_id}-1",
                        "http_request",
                        {"method": "GET", "url": "/api/v1/invoices/202", "actor": "anon"},
                    )
                if "tickets" in sys_msg.split("Assigned routes:", 1)[1]:
                    return _tool_call_resp(
                        f"{shard_id}-1",
                        "http_request",
                        {"method": "GET", "url": "/api/v1/tickets/303", "actor": "anon"},
                    )
                return _tool_call_resp(
                    f"{shard_id}-1",
                    "http_request",
                    {"method": "GET", "url": "/api/v1/orders/101", "actor": "anon"},
                )

            if step == 2:
                # Extract the receipt JSON from the last tool response in this shard's messages
                last_tool = [m for m in body["messages"] if m.get("role") == "tool"][-1]["content"]
                rec_json = last_tool.split("<<<UNTRUSTED_TARGET_RESPONSE>>>", 1)[1].split(
                    "<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1
                )[0]
                rec_obj = json.loads(rec_json)
                rec_id = rec_obj["receipt_id"]
                rec_url = str(rec_obj.get("url") or "")
                if "/api/v1/invoices/202" in rec_url:
                    return _tool_call_resp(
                        f"{shard_id}-2",
                        "record_finding",
                        {
                            "class_type": "auth_bypass",
                            "title": "Invoices unauthenticated access",
                            "method": "GET",
                            "url": "/api/v1/invoices/202",
                            "actor": "anon",
                            "severity": "high",
                            "evidence_value": "INV_SECRET_882",
                            "excerpt": "INV_SECRET_882",
                            "summary": "Shard verified auth bypass on invoices.",
                            "proof_receipt_ids": [rec_id],
                            "control_receipt_ids": ["req-0001"],
                        },
                    )
                if "/api/v1/tickets/303" in rec_url:
                    return _tool_call_resp(
                        f"{shard_id}-2",
                        "record_finding",
                        {
                            "class_type": "auth_bypass",
                            "title": "Tickets unauthenticated access",
                            "method": "GET",
                            "url": "/api/v1/tickets/303",
                            "actor": "anon",
                            "severity": "high",
                            "evidence_value": "TKT_SECRET_773",
                            "excerpt": "TKT_SECRET_773",
                            "summary": "Shard verified auth bypass on tickets.",
                            "proof_receipt_ids": [rec_id],
                            "control_receipt_ids": ["req-0001"],
                        },
                    )
                # Orders shard intentionally records a duplicate of bootstrap finding to test deduplication
                return _tool_call_resp(
                    f"{shard_id}-2",
                    "record_finding",
                    {
                        "class_type": "auth_bypass",
                        "title": "Duplicate orders finding",
                        "method": "GET",
                        "url": "/api/v1/orders/101",
                        "actor": "anon",
                        "severity": "high",
                        "evidence_value": "ORD_SECRET_991",
                        "excerpt": "ORD_SECRET_991",
                        "summary": "Duplicate to verify deduplication.",
                        "proof_receipt_ids": [rec_id],
                        "control_receipt_ids": ["req-0001"],
                    },
                )

            return _tool_call_resp(f"{shard_id}-3", "finish", {"summary": f"{shard_id} complete"})

    try:
        transport = _ScriptedShardedTransport()
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=transport,  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            discovery_hints=["/"],
            max_turns=30,
            execution_mode="sharded",
            max_shards=3,
            bootstrap_turns=6,
            shard_turns=10,
            verification_gate="llm_self_judge",
        )
        res = inv.run()

        assert res["execution_mode"] == "sharded"
        assert res["status"] == "finished"
        assert len(shard_threads_seen) == 3
        summary = res["sharding_summary"]
        assert summary["bootstrap_turns"] >= 2
        assert summary["bootstrap_calls"] >= 2
        assert summary["bootstrap_findings"] == 1
        assert summary["fallback_to_monolithic"] is False
        assert len(summary["shards"]) == 3
        assert all(s["status"] == "finished" for s in summary["shards"])

        # Merged and deduplicated findings saved to findings.json (3 unique endpoints)
        saved_findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
        assert len(saved_findings) == 3
        paths = {f["path"] for f in saved_findings}
        assert paths == {"/api/v1/orders/101", "/api/v1/invoices/202", "/api/v1/tickets/303"}
        assert res["findings_count"] == 3

        # Per-shard artifact directories created
        assert (tmp_path / "shards" / "shard-1" / "findings.json").is_file()
        assert (tmp_path / "shards" / "shard-2" / "findings.json").is_file()
        assert (tmp_path / "shards" / "shard-3" / "findings.json").is_file()
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_sharded_fallback_to_monolithic_on_tiny_target(tmp_path: Path) -> None:
    class _TinyHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            body = b"<html><body><h1>Tiny App</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _TinyHandler)
    port = srv.server_address[1]
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()

    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{port}/",
        receipt_store=store,
        actors=ActorManager(),
        allowed_methods=("GET",),
        max_requests=50,
    )
    budget = SharedBudget(http=50, tokens=100_000, seconds=60)

    class _FallbackTransport:
        def __init__(self) -> None:
            self.calls = 0
            self.provider_responses: list[dict[str, Any]] = []
            self.session_gate = SessionGate()

        def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
            self.calls += 1
            sys_msg = str((body.get("messages") or [{}])[0].get("content") or "")
            assert "SUBSYSTEM SHARD SCOPE" not in sys_msg
            if self.calls == 1:
                return _tool_call_resp("c1", "http_request", {"method": "GET", "url": "/"})
            if self.calls < 5:
                return _tool_call_resp(f"c{self.calls}", "http_request", {"method": "GET", "url": "/health"})
            return _tool_call_resp(f"c{self.calls}", "finish", {"summary": "tiny fallback complete"})

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_FallbackTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=12,
            execution_mode="sharded",
            max_shards=3,
            bootstrap_turns=4,
            shard_turns=5,
        )
        res = inv.run()
        assert res["status"] == "finished"
        assert res["execution_mode"] == "sharded"
        assert res["sharding_summary"]["fallback_to_monolithic"] is True
        assert res["sharding_summary"]["shards"] == []
        assert not (tmp_path / "shards").exists()
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_runner_sharded_plan_only(tmp_path: Path) -> None:
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
    out = tmp_path / "out_sharded"
    rc = agentic_runner.main([
        "--target", "http://127.0.0.1:18899",
        "--provider-config", str(cfg),
        "--output-dir", str(out),
        "--execution-mode", "sharded",
        "--max-shards", "3",
        "--bootstrap-turns", "10",
        "--shard-turns", "20",
    ])
    assert rc == 0
    plan = json.loads((out / "agentic-plan.json").read_text(encoding="utf-8"))
    assert plan["ablation"]["execution_mode"] == "sharded"
    assert plan["sharding"] == {
        "max_shards": 3,
        "bootstrap_turns": 10,
        "shard_turns": 20,
    }
