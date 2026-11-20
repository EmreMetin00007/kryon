"""Unit and integration tests for the 5-layer Thin-Control, Thick-State architecture."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_bsag import (  # noqa: E402
    EDGE_NAVIGATES_TO,
    EDGE_REFUTES,
    NODE_ARTIFACT,
    NODE_AUTH_CONTEXT,
    NODE_ENDPOINT,
    NODE_HYPOTHESIS,
    STATUS_CLAIMED,
    STATUS_REFUTED,
    STATUS_SUSPECT_DECOY,
    STATUS_VERIFIED,
    BeliefStateAttackGraph,
)
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_oracle import DifferentialOracle, mask_dynamic_fields  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_runner import main as runner_main, run_agentic_target  # noqa: E402
from agentic_scheduler import (  # noqa: E402
    AntiBiasUCBScheduler,
    LazyInterventionMonitor,
    shannon_entropy,
)
from agentic_telemetry import TelemetryLogger, compute_process_metrics  # noqa: E402
from agentic_tools import ToolDispatcher  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import SessionGate  # noqa: E402


class _FakeTransport:
    def __init__(self, responses: list[dict[str, Any]]):
        self._responses = list(responses)
        self.calls = 0
        self.seen_requests: list[dict[str, Any]] = []
        self.session_gate = SessionGate()

    def complete(self, request_body: dict[str, Any], *, minimum_output_tokens: int = 16) -> dict[str, Any]:
        del minimum_output_tokens
        self.calls += 1
        self.seen_requests.append(request_body)
        if not self._responses:
            return {"choices": [{"message": {"content": "", "tool_calls": []}}]}
        return self._responses.pop(0)


class _ThinControlMockHandler(BaseHTTPRequestHandler):
    """Generic mock web/API server with dynamic signup, BOLA, decoy/catchall, and timestamp-only responses."""

    state: dict[str, Any] = {}

    def log_message(self, *_args: Any) -> None:
        pass

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str = "application/json",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _actor_from_request(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        cookie = self.headers.get("Cookie", "")
        sessions = self.state.setdefault("sessions", {})
        for alias, tok in sessions.items():
            if auth == f"Bearer {tok}" or f"sid={tok}" in cookie:
                return alias
        return None

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else "{}"
        if parsed.path == "/api/signup":
            data = json.loads(raw)
            username = str(data.get("username") or f"user_{len(self.state.setdefault('users', {})) + 1}")
            idx = len(self.state.setdefault("users", {})) + 1
            tok = f"dyn-tok-{idx}-secret"
            csrf = f"dyn-csrf-{idx}-secret"
            self.state["users"][username] = {"id": f"rec-{idx}", "username": username}
            self.state.setdefault("sessions", {})[username] = tok
            self._send(
                201,
                json.dumps({
                    "user": username,
                    "access_token": tok,
                    "csrf_token": csrf,
                    "record_id": f"rec-{idx}",
                }).encode(),
                extra_headers={"Set-Cookie": f"sid={tok}; HttpOnly; Path=/"},
            )
            return

        if parsed.path == "/api/records":
            actor = self._actor_from_request()
            if not actor:
                self._send(401, b'{"error":"unauthorized"}')
                return
            data = json.loads(raw)
            rec_id = f"rec-{100 + len(self.state.setdefault('records', {}))}"
            self.state["records"][rec_id] = {
                "id": rec_id,
                "owner": actor,
                "note": str(data.get("note") or "private-note"),
            }
            self._send(201, json.dumps(self.state["records"][rec_id]).encode())
            return

        self._send(404, b'{"error":"not_found"}')

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        actor = self._actor_from_request()

        if parsed.path == "/":
            html = (
                "<html><body>"
                "<form action='/api/signup' method='POST'><input name='username'><input name='password'></form>"
                "<a href='/api/profile'>Profile</a>"
                "<a href='/api/search?q=test'>Search</a>"
                "<a href='/api/decoy?probe=1'>Status</a>"
                "<a href='/api/volatile?mode=a'>Volatile</a>"
                "</body></html>"
            ).encode()
            self._send(200, html, content_type="text/html; charset=utf-8")
            return

        if parsed.path == "/api/profile":
            if not actor:
                self._send(401, b'{"error":"unauthorized"}')
                return
            self._send(200, json.dumps({"username": actor, "authenticated": True}).encode())
            return

        if parsed.path.startswith("/api/records/"):
            if not actor:
                self._send(401, b'{"error":"unauthorized"}')
                return
            rec_id = parsed.path.rsplit("/", 1)[-1]
            rec = self.state.get("records", {}).get(rec_id)
            if not rec:
                self._send(404, b'{"error":"not_found"}')
                return
            # Deliberate BOLA: any authenticated actor can read rec-100
            self._send(200, json.dumps(rec).encode())
            return

        if parsed.path == "/api/search":
            q = qs.get("q", [""])[0]
            self._send(200, f"<html><body>Result: {q}</body></html>".encode(), content_type="text/html; charset=utf-8")
            return

        if parsed.path == "/api/decoy":
            # Always returns identical inert JSON regardless of query parameter
            self._send(200, b'{"status":"ok","message":"inert-static-marker"}')
            return

        if parsed.path == "/api/volatile":
            # Differs ONLY in timestamp and request_id
            seq = self.state.get("vol_seq", 0) + 1
            self.state["vol_seq"] = seq
            self._send(
                200,
                json.dumps({
                    "timestamp": f"2026-11-19T12:00:{seq:02d}Z",
                    "request_id": f"00000000-0000-0000-0000-{seq:012d}",
                    "data": "same-payload",
                }).encode(),
            )
            return

        if parsed.path == "/api/flaky":
            count = self.state.get("flaky_count", 0) + 1
            self.state["flaky_count"] = count
            if count == 1:
                self._send(200, b'{"secret":"EPHEMERAL-ONCE-ONLY"}')
            else:
                self._send(403, b'{"error":"forbidden_on_clean_replay"}')
            return

        # Catch-all HTML SPA page for /spa/*
        if parsed.path.startswith("/spa/") or parsed.path.endswith("-control-check"):
            if parsed.path.startswith("/spa/"):
                self._send(200, b"<html><body><div id='app'>SPA Shell</div></body></html>", content_type="text/html")
                return
            if self.state.get("catchall_mode"):
                self._send(200, b"<html><body><div id='app'>SPA Shell</div></body></html>", content_type="text/html")
                return
        self._send(404, b'{"error":"not_found"}')


@pytest.fixture()
def mock_target():
    _ThinControlMockHandler.state = {"records": {"rec-100": {"id": "rec-100", "owner": "u1", "note": "RECORD-CANARY-100"}}}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ThinControlMockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_layer1_bsag_persistence_normalization_and_slice(tmp_path: Path) -> None:
    bsag = BeliefStateAttackGraph(
        base_url="http://127.0.0.1:9999",
        root_dir=tmp_path,
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[{"alias": "member-a", "role": "member", "tenant": "t1"}],
    )
    dv1, de1 = bsag.ingest_receipt({
        "receipt_id": "req-0001",
        "actor": "member-a",
        "method": "GET",
        "url": "http://127.0.0.1:9999/api/v1/orders/101?expand=items",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({"id": "101", "next_url": "/api/v1/orders/102"}),
    })
    assert dv1 >= 2
    assert de1 >= 1

    dv2, _ = bsag.ingest_receipt({
        "receipt_id": "req-0002",
        "actor": "member-a",
        "method": "GET",
        "url": "http://127.0.0.1:9999/api/v1/orders/102",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({"id": "102"}),
    })
    # Route normalization folds /orders/101 and /orders/102 into one ENDPOINT node
    ep_id = "ep:/api/v1/orders/{id}"
    assert ep_id in bsag.nodes
    ep_node = bsag.nodes[ep_id]
    assert ep_node.node_type == NODE_ENDPOINT
    assert set(ep_node.attributes["sample_paths"]) == {"/api/v1/orders/101", "/api/v1/orders/102"}
    assert ep_node.visit_count == 2

    # Ingest surface + worker delta + refuted hypothesis
    dv_s, de_s = bsag.ingest_surface(
        {
            "receipt_id": "req-0001",
            "url": "http://127.0.0.1:9999/api/v1/orders/101",
            "forms": [{"method": "PUT", "url": "/api/v1/orders/101", "params": ["status"]}],
            "spec_urls": ["/openapi.json"],
        },
        actor="member-a",
    )
    assert dv_s >= 1 and de_s >= 1

    hyp, _, _ = bsag.register_hypothesis(
        endpoint_node_id=ep_id,
        category="object_isolation",
        vuln_class="bola",
        summary="Prior negative check",
        status=STATUS_REFUTED,
    )
    bsag.apply_oracle_verdict(
        hypothesis_id=hyp.node_id,
        endpoint_node_id=ep_id,
        verdict=STATUS_REFUTED,
        deception_detected=False,
    )
    assert any(e.edge_type == EDGE_REFUTES and e.dst == ep_id for e in bsag.edges.values())

    # Slice preserves target, neighbors, refuted history, global artifacts, and active auth contexts
    slice_json = json.loads(bsag.slice_for_arm(ep_id, "object_isolation", max_chars=2400))
    assert slice_json["assigned_arm"]["node_id"] == ep_id
    assert len(slice_json["refuted_history"]) == 1
    assert any(a["alias"] == "member-a" for a in slice_json["auth_contexts"])
    assert len(slice_json["global_artifacts"]) >= 1

    # Save to SQLite + JSON and reload cleanly
    bsag.save()
    assert (tmp_path / "bsag.sqlite").is_file()
    assert (tmp_path / "bsag.json").is_file()

    reloaded = BeliefStateAttackGraph(base_url="http://127.0.0.1:9999", root_dir=tmp_path)
    assert reloaded.load_sqlite() is True
    assert ep_id in reloaded.nodes
    assert reloaded.nodes[ep_id].visit_count == 2
    assert any(n.node_type == NODE_ARTIFACT for n in reloaded.nodes.values())
    assert any(n.node_type == NODE_AUTH_CONTEXT for n in reloaded.nodes.values())
    assert any(n.node_type == NODE_HYPOTHESIS for n in reloaded.nodes.values())
    assert any(e.edge_type == EDGE_NAVIGATES_TO for e in reloaded.edges.values())


def test_layer1_dynamic_save_session_as_redacted_and_authenticated(tmp_path: Path, mock_target: str) -> None:
    store = ReceiptStore(tmp_path)
    actors = ActorManager()
    client = AgenticHTTPClient(
        base_url=mock_target,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=20,
    )
    bsag = BeliefStateAttackGraph(
        base_url=mock_target,
        root_dir=tmp_path,
        allowed_methods=("GET", "POST"),
        actor_summaries=actors.summaries(),
    )
    dispatcher = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path, bsag=bsag)
    try:
        out_signup = dispatcher.dispatch(
            "http_request",
            {
                "method": "POST",
                "url": "/api/signup",
                "actor": "anon",
                "json_body": {"username": "user-1"},
                "save_session_as": "user-1",
            },
        )
        assert "saved_session" in out_signup
        # Raw tokens and cookies MUST NOT appear in tool output or receipts on disk!
        assert "dyn-tok-1-secret" not in out_signup
        assert "dyn-csrf-1-secret" not in out_signup
        rec_raw = (tmp_path / "receipts" / "req-0001.json").read_text(encoding="utf-8")
        assert "dyn-tok-1-secret" not in rec_raw
        assert "dyn-csrf-1-secret" not in rec_raw
        assert "auth:user-1" in bsag.nodes
        assert bsag.nodes["auth:user-1"].attributes["dynamic"] is True

        # Anonymous access still denied while user-1 succeeds using captured harness session
        out_anon = dispatcher.dispatch("http_request", {"method": "GET", "url": "/api/profile", "actor": "anon"})
        assert '"status":401' in out_anon
        out_user1 = dispatcher.dispatch("http_request", {"method": "GET", "url": "/api/profile", "actor": "user-1"})
        assert '"status":200' in out_user1
        assert "user-1" in out_user1
    finally:
        client.close()


def test_layer2_ucb_scheduler_entropy_and_lazy_monitor(tmp_path: Path) -> None:
    bsag = BeliefStateAttackGraph(
        base_url="http://127.0.0.1:9000",
        root_dir=tmp_path,
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[
            {"alias": "u1", "role": "member", "tenant": "t1"},
            {"alias": "u2", "role": "member", "tenant": "t1"},
        ],
    )
    bsag.ensure_endpoint("/api/items", method="GET")
    bsag.ensure_endpoint("/api/items/{id}", method="PUT", declared_write=True)
    bsag.ensure_endpoint("/api/decoy", method="GET")
    bsag.apply_oracle_verdict(
        hypothesis_id="hyp:none",
        endpoint_node_id="ep:/api/decoy",
        verdict="DECEPTION_DETECTED",
        deception_detected=True,
    )
    assert bsag.nodes["ep:/api/decoy"].status == STATUS_SUSPECT_DECOY

    sched = AntiBiasUCBScheduler(mode="ucb", entropy_threshold=0.85, cooldown_window=8, cooldown_steps=3)
    arm1 = sched.select_arm(bsag)
    assert arm1 is not None
    assert arm1.node_id != "ep:/api/decoy"
    assert sched.score_arm(bsag, "ep:/api/items/{id}", "state_mutation") > sched.score_arm(bsag, "ep:/api/decoy", "surface_discovery")

    # Entropy cooldown triggers when skewed toward a single category
    for _ in range(5):
        sched.record_selection("ep:/api/items", "surface_discovery")
    assert shannon_entropy(sched.recent_categories) < 0.85
    arm_after_cool = sched.select_arm(bsag)
    assert arm_after_cool is not None
    assert arm_after_cool.category != "surface_discovery"

    # Ablation modes: round_robin and prompt_only
    rr = AntiBiasUCBScheduler(mode="round_robin")
    a1, a2 = rr.select_arm(bsag), rr.select_arm(bsag)
    assert a1 is not None and a2 is not None and (a1.node_id, a1.category) != (a2.node_id, a2.category)
    po = AntiBiasUCBScheduler(mode="prompt_only")
    assert po.select_arm(bsag) is not None

    # LazyInterventionMonitor triggers
    sched_bal = AntiBiasUCBScheduler(mode="ucb", entropy_threshold=0.85)
    for cat_i in ("surface_discovery", "access_control", "object_isolation", "state_mutation"):
        sched_bal.record_selection("ep:/api/items", cat_i)
    mon = LazyInterventionMonitor(mode="lazy", stagnation_k=4, micro_budget=10, early_stop_budget_pct=0.25)
    # Passive while delta_v > 0 or delta_e > 0
    assert mon.evaluate_step(delta_v=1, delta_e=0, worker_steps=1, scheduler=sched_bal).intervene is False
    # Stagnation after k=4 zero-delta steps
    for step_i in range(1, 4):
        assert mon.evaluate_step(delta_v=0, delta_e=0, worker_steps=step_i, scheduler=sched_bal).intervene is False
    dec_stag = mon.evaluate_step(delta_v=0, delta_e=0, worker_steps=4, scheduler=sched_bal)
    assert dec_stag.intervene is True and dec_stag.trigger == "stagnation"

    # Low entropy trigger on skewed scheduler
    mon.reset_worker_window()
    dec_ent = mon.evaluate_step(delta_v=0, delta_e=0, worker_steps=1, scheduler=sched)
    assert dec_ent.intervene is True and dec_ent.trigger == "low_entropy"

    # Micro-budget trigger
    mon.reset_worker_window()
    dec_mb = mon.evaluate_step(delta_v=1, delta_e=0, worker_steps=10, scheduler=sched_bal)
    assert dec_mb.intervene is True and dec_mb.trigger == "micro_budget"

    # Claim routing & early finish block
    dec_claim = mon.evaluate_step(delta_v=0, delta_e=0, worker_steps=2, scheduler=sched_bal, claim_submitted=True)
    assert dec_claim.intervene is True and dec_claim.action == "route_to_oracle"
    dec_early = mon.evaluate_step(
        delta_v=0, delta_e=0, worker_steps=2, scheduler=sched_bal, finish_requested=True, bsag=bsag, http_remaining_ratio=0.70
    )
    assert dec_early.intervene is True and dec_early.action == "block_early_finish"

    # Always-on vs off
    mon_on = LazyInterventionMonitor(mode="always_on")
    assert mon_on.evaluate_step(delta_v=1, delta_e=0, worker_steps=1, scheduler=sched_bal).intervene is True
    mon_off = LazyInterventionMonitor(mode="off")
    assert mon_off.evaluate_step(delta_v=0, delta_e=0, worker_steps=5, scheduler=sched_bal, finish_requested=True, bsag=bsag).intervene is False


def test_layer4_differential_oracle_all_three_stages(tmp_path: Path, mock_target: str) -> None:
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "u1", "role": "member", "tenant": "t1"},
        {"alias": "u2", "role": "member", "tenant": "t1"},
    ])
    # Bind tokens cleanly in harness memory
    actors.register_dynamic_session("u1", bearer_token=_ThinControlMockHandler.state.setdefault("sessions", {}).setdefault("u1", "tok-u1"))
    actors.register_dynamic_session("u2", bearer_token=_ThinControlMockHandler.state["sessions"].setdefault("u2", "tok-u2"))

    client = AgenticHTTPClient(
        base_url=mock_target,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=40,
    )
    bsag = BeliefStateAttackGraph(base_url=mock_target, root_dir=tmp_path, actor_summaries=actors.summaries())
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential")
    dispatcher = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path, bsag=bsag, oracle=oracle)
    try:
        # 1. Stage 1 deception detection on inert decoy endpoint
        r_probe = client.request(method="GET", url="/api/decoy?probe=xss", actor="u1")
        r_ctrl = client.request(method="GET", url="/api/decoy?probe=1", actor="u1")
        rej_decoy = json.loads(dispatcher.dispatch("record_finding", {
            "title": "False positive on inert endpoint",
            "class_type": "sqli_read",
            "method": "GET",
            "url": "/api/decoy?probe=xss",
            "actor_alias": "u1",
            "proof_receipt_ids": [r_probe["receipt_id"]],
            "control_receipt_ids": [r_ctrl["receipt_id"]],
            "evidence_value": "inert-static-marker",
            "summary": "Claims difference on inert endpoint",
        }))
        assert rej_decoy["rejected"] is True

        # 2. Stage 2 masked structural diff rejects timestamp/UUID-only differences
        v1 = client.request(method="GET", url="/api/volatile?mode=a", actor="u1")
        v2 = client.request(method="GET", url="/api/volatile?mode=b", actor="u1")
        assert mask_dynamic_fields(v1["body"]) == mask_dynamic_fields(v2["body"])
        rej_vol = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Timestamp diff only",
            "class_type": "sqli_read",
            "method": "GET",
            "url": "/api/volatile?mode=a",
            "actor_alias": "u1",
            "proof_receipt_ids": [v1["receipt_id"]],
            "control_receipt_ids": [v2["receipt_id"]],
            "evidence_value": "same-payload",
            "summary": "Only timestamps differ",
        }))
        assert rej_vol["rejected"] is True
        assert rej_vol["oracle_verdict"] == "DECEPTION_DETECTED"
        assert bsag.nodes["ep:/api/volatile"].status == STATUS_SUSPECT_DECOY

        # 3. Stage 3 clean-session replay rejects non-reproducible / flaky response
        f1 = client.request(method="GET", url="/api/flaky", actor="u1")
        f_ctrl = client.request(method="GET", url="/api/flaky", actor="anon")
        rej_flaky = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Non-reproducible exposure",
            "class_type": "info_disclosure",
            "method": "GET",
            "url": "/api/flaky",
            "actor_alias": "u1",
            "proof_receipt_ids": [f1["receipt_id"]],
            "control_receipt_ids": [f_ctrl["receipt_id"]],
            "evidence_value": "EPHEMERAL-ONCE-ONLY",
            "summary": "Transient exposure",
        }))
        assert rej_flaky["rejected"] is True
        assert rej_flaky["oracle_verdict"] == "REFUTED"

        # 4. Valid BOLA passes all 3 stages + clean replay
        b_proof = client.request(method="GET", url="/api/records/rec-100", actor="u2")
        b_ctrl = client.request(method="GET", url="/api/records/rec-100", actor="anon")
        acc = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Peer object read across users",
            "class_type": "bola",
            "method": "GET",
            "url": "/api/records/rec-100",
            "actor_alias": "u2",
            "proof_receipt_ids": [b_proof["receipt_id"]],
            "control_receipt_ids": [b_ctrl["receipt_id"]],
            "evidence_value": "RECORD-CANARY-100",
            "summary": "u2 reads u1 record rec-100 while anon is denied 401",
        }))
        assert acc["accepted"] is True
        assert bsag.nodes["ep:/api/records/{id}"].status == STATUS_VERIFIED

        # 5. llm_self_judge ablation skips differential gate
        oracle_self = DifferentialOracle(http_client=client, receipt_store=store, mode="llm_self_judge")
        verdict_self = oracle_self.verify(
            canonical_class="sqli_read",
            primary_proof=v1,
            proof_receipts=[v1],
            control_receipts=[v2],
            evidence_value="same-payload",
        )
        assert verdict_self.verified is True
        assert verdict_self.stages["stage3_clean_replay"] == "skipped"
    finally:
        client.close()


def test_layer3_and_5_ephemeral_workers_synthesis_and_metrics(tmp_path: Path, mock_target: str) -> None:
    store = ReceiptStore(tmp_path)
    actors = ActorManager()
    client = AgenticHTTPClient(
        base_url=mock_target,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=40,
    )
    budget = SharedBudget(http=40, tokens=200_000, seconds=120)
    transport = _FakeTransport([
        # Worker 1: surface discovery on /
        {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "w1_1", "type": "function", "function": {"name": "http_request", "arguments": '{"url": "/", "actor": "anon"}'}}
        ]}}]},
        {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "w1_2", "type": "function", "function": {"name": "finish", "arguments": '{"summary": "mapped root"}'}}
        ]}}]},
        # Worker 2: auth_session dynamic signup via save_session_as
        {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "w2_1", "type": "function", "function": {"name": "http_request", "arguments": json.dumps({
                "method": "POST", "url": "/api/signup", "actor": "anon",
                "json_body": {"username": "dyn-user-1"}, "save_session_as": "dyn-user-1"
            })}}
        ]}}]},
        {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "w2_2", "type": "function", "function": {"name": "finish", "arguments": '{"summary": "registered dyn-user-1"}'}}
        ]}}]},
        # Synthesis pass triggered because new AUTH_CONTEXT was created!
        {"choices": [{"message": {"content": json.dumps([
            {"endpoint": "/api/records/rec-100", "category": "object_isolation", "vuln_class": "bola", "summary": "Test rec-100 with dyn-user-1"}
        ])}}]},
        # Worker 3: tests /api/search XSS and records finding
        {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "w3_1", "type": "function", "function": {"name": "http_request", "arguments": '{"url": "/api/search?q=benign", "actor": "anon"}'}},
            {"id": "w3_2", "type": "function", "function": {"name": "http_request", "arguments": '{"url": "/api/search?q=<probe_tag>", "actor": "anon"}'}}
        ]}}]},
        {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "w3_3", "type": "function", "function": {"name": "record_finding", "arguments": json.dumps({
                "title": "Unescaped search output", "class_type": "reflected_xss", "method": "GET",
                "url": "/api/search?q=<probe_tag>", "actor_alias": "anon",
                "proof_receipt_ids": ["req-0004"], "control_receipt_ids": ["req-0003"],
                "evidence_value": "<probe_tag>", "summary": "Search parameter reflected unescaped in HTML"
            })}},
            {"id": "w3_4", "type": "function", "function": {"name": "finish", "arguments": '{"summary": "verified search"}'}}
        ]}}]},
    ])
    inv = AgenticInvestigator(
        http_client=client,
        receipt_store=store,
        transport=transport,  # type: ignore[arg-type]
        budget=budget,
        model="fake-model",
        root_dir=tmp_path,
        discovery_hints=["/"],
        max_turns=8,
        use_bsag=True,
        scheduler_mode="ucb",
        verification_gate="differential",
        intervention_mode="lazy",
        execution_mode="ephemeral",
        micro_budget=6,
        synthesis_interval=3,
    )
    try:
        res = inv.run()
        assert res["execution_mode"] == "ephemeral"
        assert res["findings_count"] == 1
        assert (tmp_path / "telemetry.jsonl").is_file()
        assert (tmp_path / "process_metrics.json").is_file()
        assert (tmp_path / "process_metrics.md").is_file()
        assert (tmp_path / "bsag.sqlite").is_file()

        # Verify dynamic session + synthesis hypothesis + metrics
        assert inv.bsag is not None
        assert "auth:dyn-user-1" in inv.bsag.nodes
        assert any(
            n.node_type == NODE_HYPOTHESIS and n.attributes.get("multi_hop")
            for n in inv.bsag.nodes.values()
        )
        metrics = json.loads((tmp_path / "process_metrics.json").read_text(encoding="utf-8"))
        assert metrics["exposure_rate"]["unique_endpoints_discovered"] >= 4
        assert metrics["verification_precision"] == 1.0
        assert metrics["category_entropy"] > 0.0
        assert metrics["tokens_per_verified_finding"] is not None

        events = TelemetryLogger(tmp_path).events()
        event_types = {e["event"] for e in events}
        assert {"worker_start", "worker_end", "http_event", "oracle_verdict", "synthesis"}.issubset(event_types)
    finally:
        client.close()


def test_runner_ablation_cli_flags_and_plan_only(tmp_path: Path) -> None:
    cfg = tmp_path / "llm.json"
    cfg.write_text(json.dumps({
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
    }), encoding="utf-8")

    # 1. Default runner plan uses monolithic + differential (no BSAG/intervention)
    out_default = tmp_path / "out_default"
    rc = runner_main([
        "--target", "http://127.0.0.1:18899",
        "--provider-config", str(cfg),
        "--output-dir", str(out_default),
    ])
    assert rc == 0
    plan_default = json.loads((out_default / "agentic-plan.json").read_text(encoding="utf-8"))
    assert plan_default["ablation"] == {
        "use_bsag": False,
        "scheduler": "prompt_only",
        "verification_gate": "differential",
        "intervention": "off",
        "execution_mode": "monolithic",
    }

    # 2. Explicit ablation override flags parse cleanly (ephemeral + bsag + ucb + llm_self_judge + lazy)
    out_abl = tmp_path / "out_abl"
    rc2 = runner_main([
        "--target", "http://127.0.0.1:18899",
        "--provider-config", str(cfg),
        "--output-dir", str(out_abl),
        "--use-bsag=true",
        "--scheduler=ucb",
        "--verification-gate=llm_self_judge",
        "--intervention=lazy",
        "--execution-mode=ephemeral",
    ])
    assert rc2 == 0
    plan_abl = json.loads((out_abl / "agentic-plan.json").read_text(encoding="utf-8"))
    assert plan_abl["ablation"] == {
        "use_bsag": True,
        "scheduler": "ucb",
        "verification_gate": "llm_self_judge",
        "intervention": "lazy",
        "execution_mode": "ephemeral",
    }

    # 3. Direct compute_process_metrics handles zero claims gracefully
    m_empty = compute_process_metrics(events=[], findings=[], token_usage={"total_tokens": 100})
    assert m_empty["verification_precision"] == 0.0
    assert m_empty["tokens_per_verified_finding"] is None
    _ = STATUS_CLAIMED
    _ = run_agentic_target


def test_bsag_behavioral_progress_prevents_false_stagnation(tmp_path: Path) -> None:
    """Novel cross-actor controls, second object IDs, and write probes count as progress; exact repeats yield (0, 0)."""
    bsag = BeliefStateAttackGraph(
        base_url="http://127.0.0.1:9999/",
        allowed_methods=("GET", "PUT"),
        root_dir=tmp_path,
    )
    # 1. Initial GET /api/v1/items/1 as user-a creates endpoint + auth + behavior.
    dv1, de1 = bsag.ingest_receipt({
        "receipt_id": "req-0001", "actor": "user-a", "method": "GET",
        "url": "http://127.0.0.1:9999/api/v1/items/1", "status": 200, "body": '{"id":1}', "content_type": "application/json",
    })
    assert dv1 > 0 and de1 > 0

    # 2. Exact identical repeat produces (0, 0) so true stagnation is still detected.
    dv_dup, de_dup = bsag.ingest_receipt({
        "receipt_id": "req-0002", "actor": "user-a", "method": "GET",
        "url": "http://127.0.0.1:9999/api/v1/items/1", "status": 200, "body": '{"id":1}', "content_type": "application/json",
    })
    assert (dv_dup, de_dup) == (0, 0)

    # 3. Cross-actor negative control (403 as user-b) is novel behavioral progress!
    dv_ctrl, de_ctrl = bsag.ingest_receipt({
        "receipt_id": "req-0003", "actor": "user-b", "method": "GET",
        "url": "http://127.0.0.1:9999/api/v1/items/1", "status": 403, "body": '{"error":"forbidden"}', "content_type": "application/json",
    })
    assert de_ctrl > 0

    # 4. Second concrete object ID (/api/v1/items/2) under same template is novel behavioral progress!
    dv_obj2, de_obj2 = bsag.ingest_receipt({
        "receipt_id": "req-0004", "actor": "user-b", "method": "GET",
        "url": "http://127.0.0.1:9999/api/v1/items/2", "status": 200, "body": '{"id":2}', "content_type": "application/json",
    })
    assert de_obj2 > 0

    # 5. Write probe returning 405 on existing template is novel behavioral progress once, then (0, 0) on repeat.
    _, de_w1 = bsag.ingest_receipt({
        "receipt_id": "req-0005", "actor": "user-a", "method": "PUT",
        "url": "http://127.0.0.1:9999/api/v1/items/1", "status": 405, "body": "", "content_type": "text/plain",
    })
    assert de_w1 > 0
    dv_w2, de_w2 = bsag.ingest_receipt({
        "receipt_id": "req-0006", "actor": "user-a", "method": "PUT",
        "url": "http://127.0.0.1:9999/api/v1/items/1", "status": 405, "body": "", "content_type": "text/plain",
    })
    assert (dv_w2, de_w2) == (0, 0)


def test_monolithic_mode_enables_differential_oracle(tmp_path: Path, mock_target: str) -> None:
    """Monolithic mode with use_bsag=False must still instantiate and wire DifferentialOracle."""
    store = ReceiptStore(tmp_path)
    actors = ActorManager()
    client = AgenticHTTPClient(
        base_url=mock_target,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET",),
        max_requests=40,
    )
    try:
        budget = SharedBudget(http=40, tokens=200_000, seconds=120)
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_FakeTransport([]),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path / "mono_oracle",
            execution_mode="monolithic",
            use_bsag=False,
            verification_gate="differential",
        )
        assert inv.bsag is None
        assert inv.oracle is not None
        assert inv.oracle.mode == "differential"
        assert inv.dispatcher.oracle is inv.oracle
    finally:
        client.close()


def test_differential_oracle_stateful_mutating_clean_replay(tmp_path: Path) -> None:
    """Non-idempotent PUT transferring ownership must verify via cross-actor GET or stateful fallback, never false-404."""
    state: dict[str, Any] = {
        "org_slug": "org-alpha",
        "tier": "basic",
        "put_calls": 0,
    }

    class _StatefulTransferHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def _actor_org(self) -> str:
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer tok-alpha":
                return "org-alpha"
            if auth == "Bearer tok-beta":
                return "org-beta"
            return ""

        def _send_json(self, code: int, payload: dict[str, Any]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            org = self._actor_org()
            if self.path == "/api/v1/records/1" and org == state["org_slug"]:
                self._send_json(200, {"id": 1, "org_slug": state["org_slug"], "tier": state["tier"]})
                return
            self._send_json(404, {"error": "not_found"})

        def do_PUT(self) -> None:  # noqa: N802
            state["put_calls"] += 1
            org = self._actor_org()
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            try:
                body = json.loads(raw_body)
            except ValueError:
                body = {}
            if self.path == "/api/v1/records/1" and org == state["org_slug"]:
                if "org_slug" in body:
                    state["org_slug"] = str(body["org_slug"])
                if "tier" in body:
                    state["tier"] = str(body["tier"])
                self._send_json(200, {"id": 1, "org_slug": state["org_slug"], "tier": state["tier"]})
                return
            self._send_json(404, {"error": "not_found"})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _StatefulTransferHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    try:
        store = ReceiptStore(tmp_path / "stateful_oracle")
        actors = ActorManager([
            {"alias": "user-alpha", "role": "member", "tenant": "org-alpha"},
            {"alias": "user-beta", "role": "member", "tenant": "org-beta"},
        ])
        actors.register_dynamic_session("user-alpha", bearer_token="tok-alpha")
        actors.register_dynamic_session("user-beta", bearer_token="tok-beta")
        client = AgenticHTTPClient(
            base_url=base,
            receipt_store=store,
            actors=actors,
            allowed_methods=("GET", "PUT"),
            max_requests=40,
        )
        try:
            oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential")

            # Control before mutation: user-beta receives 404.
            ctrl_before = client.request(method="GET", url="/api/v1/records/1", actor="user-beta")
            assert ctrl_before["status"] == 404

            # Non-idempotent PUT by user-alpha transfers org_slug to org-beta (revoking user-alpha's access).
            put_proof = client.request(
                method="PUT",
                url="/api/v1/records/1",
                actor="user-alpha",
                json_body={"org_slug": "org-beta", "tier": "enterprise"},
            )
            assert put_proof["status"] == 200
            assert state["put_calls"] == 1

            # Follow-up persistence GET by user-beta now returns 200 with mutated fields.
            get_proof = client.request(method="GET", url="/api/v1/records/1", actor="user-beta")
            assert get_proof["status"] == 200

            # Case 1: With cross-actor GET in proof_receipts -> replays GET (not PUT), verifies cleanly, no extra PUT!
            v1 = oracle.verify(
                canonical_class="mass_assignment",
                primary_proof=put_proof,
                proof_receipts=[put_proof, get_proof],
                control_receipts=[ctrl_before],
                evidence_value="org-beta",
            )
            assert v1.verified is True
            assert v1.verdict == "VERIFIED"
            assert v1.stages["stage3_clean_replay"] == "passed"
            assert state["put_calls"] == 1  # Never re-executed destructive PUT

            # Case 2: Without GET in proof_receipts -> PUT replay returns 404 (old owner lost access),
            # stateful persistence fallback replays clean GET as previously-denied control actor (user-beta) -> VERIFIED!
            v2 = oracle.verify(
                canonical_class="mass_assignment",
                primary_proof=put_proof,
                proof_receipts=[put_proof],
                control_receipts=[ctrl_before],
                evidence_value="org-beta",
            )
            assert v2.verified is True
            assert v2.verdict == "VERIFIED"
            assert v2.stages["stage3_clean_replay"] == "passed_stateful_persistence"
            assert state["put_calls"] == 2

            # Case 3: Truly non-existent resource where neither original actor nor control actor reads 2xx -> REFUTED!
            fake_ctrl = client.request(method="GET", url="/api/v1/records/999", actor="user-beta")
            assert fake_ctrl["status"] == 404
            fake_put = {
                "receipt_id": "req-fake",
                "actor": "user-alpha",
                "method": "PUT",
                "url": f"{base}/api/v1/records/999",
                "path": "/api/v1/records/999",
                "status": 200,
                "body": '{"id":999,"org_slug":"org-beta"}',
                "request_headers": {},
                "request_body": '{"org_slug":"org-beta"}',
            }
            v3 = oracle.verify(
                canonical_class="mass_assignment",
                primary_proof=fake_put,
                proof_receipts=[fake_put],
                control_receipts=[fake_ctrl],
                evidence_value="org-beta",
            )
            assert v3.verified is False
            assert v3.verdict == "REFUTED"
            assert v3.stages["stage3_clean_replay"] == "failed_status_404"
        finally:
            client.close()
    finally:
        srv.shutdown()
        srv.server_close()


