"""Tests for Faz 1: Two-Tier Verification (CONFIRMED vs NEEDS_VERIFICATION) and Late-Hit OOB Reconciliation."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_investigator  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_oob import LoopbackCallbackServer  # noqa: E402
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
import agentic_report  # noqa: E402
from agentic_tools import (  # noqa: E402
    TOOL_SCHEMAS,
    ToolDispatcher,
    canonicalize_and_deduplicate_leads,
    reconcile_late_oob_hits,
)
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import SessionGate  # noqa: E402


def _start_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[str, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", srv


def _stop_server(srv: ThreadingHTTPServer) -> None:
    srv.shutdown()
    srv.server_close()


def _make_oracle_env(
    tmp_path: Path,
    base_url: str,
    *,
    max_requests: int = 80,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
    timing_min_delta_ms: float = 120.0,
    timing_min_ratio: float = 3.0,
    timing_replay_pairs: int = 2,
    oob_server: LoopbackCallbackServer | None = None,
) -> tuple[ReceiptStore, AgenticHTTPClient, DifferentialOracle]:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-alice"},
        {"alias": "bob", "role": "member", "tenant": "beta", "auth_header": "Bearer tok-bob"},
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
    )
    oracle = DifferentialOracle(
        http_client=client,
        receipt_store=store,
        mode="differential",
        timing_min_delta_ms=timing_min_delta_ms,
        timing_min_ratio=timing_min_ratio,
        timing_replay_pairs=timing_replay_pairs,
        oob_server=oob_server,
    )
    return store, client, oracle


class _DummyTransport:
    def __init__(self) -> None:
        self.session_gate = SessionGate()
        self.provider_responses: list[dict[str, Any]] = []
        self.provider_lock = threading.Lock()
        self.calls = 0

    def complete(self, _body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": f"call_fin_{self.calls}",
                                "type": "function",
                                "function": {"name": "finish", "arguments": '{"summary":"done"}'},
                            }
                        ],
                    }
                }
            ],
            "usage": {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60},
        }

    def close_upstream(self) -> None:
        return


def _unwrap_tool_json(raw: str) -> dict[str, Any]:
    text = raw
    if "<<<UNTRUSTED_TARGET_RESPONSE>>>\n" in text:
        text = text.split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1].rsplit(
            "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>",
            1,
        )[0]
    return json.loads(text)


# ---------------------------------------------------------------------------
# 1. All 6 NEEDS_VERIFICATION qualifiers + orthogonal OracleVerdict contract
# ---------------------------------------------------------------------------


def test_oracle_q1_q2_multistep_qualifiers(tmp_path: Path) -> None:
    state = {"wf_seq": 0, "committed": set(), "block_step1_status": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            if self.path == "/api/orders/draft":
                if state["block_step1_status"]:
                    self.send_response(state["block_step1_status"])
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"quota or stale state"}')
                    return
                state["wf_seq"] += 1
                oid = f"ORD-{state['wf_seq']}"
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"id": oid}).encode("utf-8"))
                return
            if self.path.startswith("/api/orders/") and self.path.endswith("/finalize"):
                oid = self.path.split("/")[3]
                if "bad_coupon" in body:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"invalid"}')
                    return
                if oid in state["committed"]:
                    self.send_response(409)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"already finalized"}')
                    return
                state["committed"].add(oid)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "discount_stacked", "id": oid}).encode("utf-8"))
                return
            self.send_response(404)
            self.end_headers()

    base_url, srv = _start_server(Handler)
    try:
        # Q1: budget allows 4 requests total: draft (1), control (2), proof (3), single-step replay (4 -> 409),
        # leaving 0 requests for the 2-step multi-step precursor chain -> failed_multistep_budget!
        q1_dir = tmp_path / "q1"
        q1_dir.mkdir()
        _, c1, o1 = _make_oracle_env(q1_dir, base_url, max_requests=4)
        try:
            draft_rec = c1.request(actor="alice", method="POST", url="/api/orders/draft", json_body={"item": "x"})
            ctrl_rec = c1.request(
                actor="alice",
                method="POST",
                url="/api/orders/ORD-1/finalize",
                json_body={"coupon": "bad_coupon"},
            )
            proof_rec = c1.request(
                actor="alice",
                method="POST",
                url="/api/orders/ORD-1/finalize",
                json_body={"coupon": "FREE99"},
            )
            v1 = o1.verify(
                canonical_class="mass_assignment",
                primary_proof=proof_rec,
                proof_receipts=[draft_rec, proof_rec],
                control_receipts=[ctrl_rec],
                evidence_value="discount_stacked",
            )
            assert v1.verified is False
            assert v1.verdict == "REFUTED"
            assert v1.needs_verification is True
            assert v1.verification_tier == "NEEDS_VERIFICATION"
            assert v1.signal_type == "multistep_budget_exceeded"
            assert v1.verification_blocker == "stage3_clean_replay:failed_multistep_budget"
            assert v1.suggested_manual_verification
        finally:
            c1.close()

        # Q2: precursor blocked with 429 during multi-step replay
        q2_dir = tmp_path / "q2"
        q2_dir.mkdir()
        _, c2, o2 = _make_oracle_env(q2_dir, base_url, max_requests=30)
        try:
            draft2 = c2.request(actor="alice", method="POST", url="/api/orders/draft", json_body={"item": "y"})
            ctrl2 = c2.request(
                actor="alice",
                method="POST",
                url="/api/orders/ORD-2/finalize",
                json_body={"coupon": "bad_coupon"},
            )
            proof2 = c2.request(
                actor="alice",
                method="POST",
                url="/api/orders/ORD-2/finalize",
                json_body={"coupon": "FREE99"},
            )
            state["block_step1_status"] = 429
            v2 = o2.verify(
                canonical_class="mass_assignment",
                primary_proof=proof2,
                proof_receipts=[draft2, proof2],
                control_receipts=[ctrl2],
                evidence_value="discount_stacked",
            )
            assert v2.verified is False
            assert v2.verdict == "REFUTED"
            assert v2.needs_verification is True
            assert v2.verification_tier == "NEEDS_VERIFICATION"
            assert v2.signal_type == "multistep_precursor_blocked"
            assert v2.verification_blocker == "stage3_clean_replay:failed_multistep_precursor_429"
            assert "429" in v2.suggested_manual_verification
        finally:
            c2.close()
    finally:
        _stop_server(srv)


def test_oracle_q3_oneshot_state_exhausted_and_404_corroboration_rule(tmp_path: Path) -> None:
    used_tokens: set[str] = set()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_PUT(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            if self.path == "/api/promo/redeem":
                if "invalid" in body:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"bad promo"}')
                    return
                if "VIP50" in used_tokens:
                    self.send_response(409)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"already redeemed"}')
                    return
                used_tokens.add("VIP50")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"redeemed":true,"credit_awarded":50}')
                return
            if self.path == "/api/never-existed":
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"not found"}')
                return
            self.send_response(404)
            self.end_headers()

    base_url, srv = _start_server(Handler)
    try:
        store, client, oracle = _make_oracle_env(tmp_path, base_url, max_requests=30)
        try:
            ctrl = client.request(actor="alice", method="PUT", url="/api/promo/redeem", json_body={"code": "invalid"})
            proof = client.request(actor="alice", method="PUT", url="/api/promo/redeem", json_body={"code": "VIP50"})
            v_q3 = oracle.verify(
                canonical_class="mass_assignment",
                primary_proof=proof,
                proof_receipts=[proof],
                control_receipts=[ctrl],
                evidence_value="credit_awarded",
            )
            assert v_q3.verified is False
            assert v_q3.verdict == "REFUTED"
            assert v_q3.needs_verification is True
            assert v_q3.verification_tier == "NEEDS_VERIFICATION"
            assert v_q3.signal_type == "one_shot_state_exhausted"
            assert v_q3.verification_blocker == "stage3_clean_replay:failed_status_409"

            # Disqualifier check: PUT returning 404 on replay with a 404 control (no prior 2xx observation, no non-404 control) -> NOT Q3!
            ctrl_404 = client.request(actor="alice", method="PUT", url="/api/never-existed", json_body={"x": 1})
            synth_200 = {
                "receipt_id": "R-SYNTH",
                "actor": "alice",
                "method": "PUT",
                "url": f"{base_url}/api/never-existed",
                "path": "/api/never-existed",
                "status": 200,
                "body": '{"credit_awarded": 50}',
                "request_body": '{"x": 9}',
                "request_headers": {},
                "response_headers": {"content-type": "application/json"},
                "elapsed_ms": 5.0,
            }
            v_404_disq = oracle.verify(
                canonical_class="mass_assignment",
                primary_proof=synth_200,
                proof_receipts=[synth_200],
                control_receipts=[ctrl_404],
                evidence_value="credit_awarded",
            )
            assert v_404_disq.verified is False
            assert v_404_disq.needs_verification is False
            assert v_404_disq.verification_tier == "REFUTED"
        finally:
            client.close()
    finally:
        _stop_server(srv)


def test_oracle_q4_timing_borderline_vs_jitter_and_spike_disqualifiers(tmp_path: Path) -> None:
    mode = {"case": "borderline"}
    counts = {"ctrl": 0, "proof": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            if "SLEEP" in q:
                counts["proof"] += 1
                if mode["case"] == "borderline":
                    time.sleep(0.22)  # ~220ms vs ~90ms ctrl: ratio ~2.4x (< 3.0x, >= 1.5x), delta ~130ms >= 120ms, non-overlapping!
                elif mode["case"] == "spike":
                    time.sleep(0.30 if counts["proof"] == 1 else 0.01)  # second replay fast -> min_p <= max_c or low median
                elif mode["case"] == "jitter":
                    time.sleep(0.22 if counts["proof"] == 1 else 0.14)  # overlaps with noisy ctrl=0.18!
            else:
                counts["ctrl"] += 1
                if mode["case"] == "borderline":
                    time.sleep(0.09)
                elif mode["case"] == "spike":
                    time.sleep(0.01)
                elif mode["case"] == "jitter":
                    time.sleep(0.01 if counts["ctrl"] == 1 else 0.18)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"rows":[]}')

    base_url, srv = _start_server(Handler)
    try:
        # Q4 borderline -> NEEDS_VERIFICATION
        d_b = tmp_path / "borderline"
        d_b.mkdir()
        _, c_b, o_b = _make_oracle_env(d_b, base_url, timing_min_delta_ms=120.0, timing_min_ratio=3.0, timing_replay_pairs=2)
        try:
            ctrl_b = {
                "receipt_id": "R-C1",
                "actor": "alice",
                "method": "GET",
                "url": f"{base_url}/api/items?q=safe",
                "path": "/api/items",
                "status": 200,
                "body": '{"rows":[]}',
                "request_headers": {},
                "response_headers": {},
                "elapsed_ms": 10.0,
            }
            proof_b = {
                "receipt_id": "R-P1",
                "actor": "alice",
                "method": "GET",
                "url": f"{base_url}/api/items?q=1'+AND+SLEEP(1)--",
                "path": "/api/items",
                "status": 200,
                "body": '{"rows":[]}',
                "request_headers": {},
                "response_headers": {},
                "elapsed_ms": 300.0,
            }
            v_q4 = o_b.verify(
                canonical_class="sqli",
                primary_proof=proof_b,
                proof_receipts=[proof_b],
                control_receipts=[ctrl_b],
                evidence_value="",
            )
            assert v_q4.verified is False
            assert v_q4.verdict == "REFUTED"
            assert v_q4.needs_verification is True
            assert v_q4.verification_tier == "NEEDS_VERIFICATION"
            assert v_q4.signal_type == "timing_anomaly_borderline"
            assert v_q4.verification_blocker == "stage3_clean_replay:failed_timing_overlap"
        finally:
            c_b.close()

        # Disqualifier: random single spike
        mode["case"] = "spike"
        counts["ctrl"] = 0
        counts["proof"] = 0
        d_s = tmp_path / "spike"
        d_s.mkdir()
        _, c_s, o_s = _make_oracle_env(d_s, base_url, timing_min_delta_ms=180.0, timing_min_ratio=3.0, timing_replay_pairs=2)
        try:
            v_spike = o_s.verify(
                canonical_class="sqli",
                primary_proof=proof_b,
                proof_receipts=[proof_b],
                control_receipts=[ctrl_b],
                evidence_value="",
            )
            assert v_spike.verified is False
            assert v_spike.needs_verification is False
            assert v_spike.verification_tier == "REFUTED"
        finally:
            c_s.close()

        # Disqualifier: overlapping jitter
        mode["case"] = "jitter"
        counts["ctrl"] = 0
        counts["proof"] = 0
        d_j = tmp_path / "jitter"
        d_j.mkdir()
        _, c_j, o_j = _make_oracle_env(d_j, base_url, timing_min_delta_ms=120.0, timing_min_ratio=3.0, timing_replay_pairs=2)
        try:
            v_jitter = o_j.verify(
                canonical_class="sqli",
                primary_proof=proof_b,
                proof_receipts=[proof_b],
                control_receipts=[ctrl_b],
                evidence_value="",
            )
            assert v_jitter.verified is False
            assert v_jitter.needs_verification is False
            assert v_jitter.verification_tier == "REFUTED"
        finally:
            c_j.close()
    finally:
        _stop_server(srv)


def test_oracle_q5_async_oob_unreplayed_and_q6_server_5xx_differential(tmp_path: Path) -> None:
    calls = {"fetch": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            if self.path.startswith("/api/fetch"):
                calls["fetch"] += 1
                cb = parse_qs(urlsplit(self.path).query).get("url", [""])[0]
                if calls["fetch"] <= 2 and cb.startswith("http://127.0.0.1:"):
                    requests.get(cb, timeout=2.0)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"queued":true}')
                    return
                # Clean replay returns 404 (one-time/queued SSRF link expired) -> Stage 3 fails!
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            if self.path == "/api/search":
                if "'" in body:
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"unhandled sql syntax fault"}')
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"items":[]}')
                return
            if self.path == "/api/items":
                if "crash" in body:
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"internal failure"}')
                    return
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"validation"}')
                return
            if self.path == "/api/orders/1":
                self.send_response(403 if "bob" in (self.headers.get("Authorization") or "") else 500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"err"}')
                return
            self.send_response(404)
            self.end_headers()

        def do_DELETE(self) -> None:
            auth = self.headers.get("Authorization") or ""
            if "bob" in auth:
                self.send_response(403)
                self.end_headers()
                return
            # AN4 pattern: initial proof 500 -> clean replay 404
            self.send_response(404)
            self.end_headers()

    base_url, srv = _start_server(Handler)
    oob = LoopbackCallbackServer()
    oob.start()
    try:
        tok_info = oob.create_token("ssrf-probe")
        store, client, oracle = _make_oracle_env(tmp_path, base_url, max_requests=40, oob_server=oob)
        try:
            # Q5: verified OOB hit received, yet Stage 3 GET replay fails with 404
            oob_ctrl = client.request(actor="alice", method="GET", url="/api/fetch?url=https://example.invalid/x")
            oob_proof = client.request(actor="alice", method="GET", url=f"/api/fetch?url={tok_info['url']}")
            hits = oob.poll(tok_info["token"])["hits"]
            assert len(hits) == 1

            v_q5 = oracle.verify(
                canonical_class="ssrf",
                primary_proof=oob_proof,
                proof_receipts=[oob_proof],
                control_receipts=[oob_ctrl],
                evidence_value=tok_info["token"],
                oob_hits=hits,
            )
            assert v_q5.verified is False
            assert v_q5.verdict == "REFUTED"
            assert v_q5.needs_verification is True
            assert v_q5.verification_tier == "NEEDS_VERIFICATION"
            assert v_q5.signal_type == "async_oob_unreplayed"
            assert "failed_status_404" in v_q5.verification_blocker

            # Q6(a): Primary proof 500, replay ALSO 500, same-path control 200
            c_200 = client.request(actor="alice", method="POST", url="/api/search", json_body={"q": "normal"})
            p_500 = client.request(actor="alice", method="POST", url="/api/search", json_body={"q": "a' OR 1=1--"})
            v_q6a = oracle.verify(
                canonical_class="sqli",
                primary_proof=p_500,
                proof_receipts=[p_500],
                control_receipts=[c_200],
                evidence_value="unhandled sql syntax fault",
            )
            assert v_q6a.verified is False
            assert v_q6a.verdict == "REFUTED"
            assert v_q6a.needs_verification is True
            assert v_q6a.verification_tier == "NEEDS_VERIFICATION"
            assert v_q6a.signal_type == "server_5xx_differential"
            assert "proof_500_vs_control_200" in v_q6a.verification_blocker

            # Q6(b): Primary proof 500, non-auth-denial control 400 (< 500, not in 401/403/404)
            c_400 = client.request(actor="alice", method="POST", url="/api/items", json_body={"x": "bad"})
            p2_500 = client.request(actor="alice", method="POST", url="/api/items", json_body={"x": "crash"})
            v_q6b = oracle.verify(
                canonical_class="business_logic",
                primary_proof=p2_500,
                proof_receipts=[p2_500],
                control_receipts=[c_400],
                evidence_value="internal failure",
            )
            assert v_q6b.verified is False
            assert v_q6b.needs_verification is True
            assert v_q6b.signal_type == "server_5xx_differential"

            # Disqualifier (AN4 pattern): DELETE 500 primary vs 403 auth-denial control -> 404 replay => NOT Q6!
            del_ctrl_403 = client.request(actor="bob", method="DELETE", url="/api/orders/1")
            del_synth_500 = {
                "receipt_id": "R-DEL500",
                "actor": "alice",
                "method": "DELETE",
                "url": f"{base_url}/api/orders/1",
                "path": "/api/orders/1",
                "status": 500,
                "body": '{"error":"server err"}',
                "request_headers": {},
                "response_headers": {},
                "elapsed_ms": 5.0,
            }
            v_an4 = oracle.verify(
                canonical_class="bola",
                primary_proof=del_synth_500,
                proof_receipts=[del_synth_500],
                control_receipts=[del_ctrl_403],
                evidence_value="server err",
            )
            assert v_an4.verified is False
            assert v_an4.needs_verification is False
            assert v_an4.verification_tier == "REFUTED"
        finally:
            client.close()
    finally:
        oob.close()
        _stop_server(srv)


def test_oracle_hard_disqualifiers_remain_refuted_or_deception(tmp_path: Path) -> None:
    req_idx = {"redirect": 0, "xss": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            if self.path.startswith("/redirect"):
                req_idx["redirect"] += 1
                self.send_response(302)
                # Proof redirected off-host; replay redirects locally -> failed_redirect_host!
                loc = "https://evil.example/pwn" if req_idx["redirect"] == 1 else "/home"
                self.send_header("Location", loc)
                self.end_headers()
                return
            if self.path.startswith("/profile"):
                req_idx["xss"] += 1
                self.send_response(200)
                if "safe" in self.path:
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body>hello safe</body></html>")
                    return
                if req_idx["xss"] == 1:
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><svg onload=alert(1)></body></html>")
                else:
                    # Clean 200 GET replay missing evidence -> must remain REFUTED!
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body>escaped</body></html>")
                return
            if self.path == "/same":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"static":"ok","nonce":"11111111-1111-4111-8111-111111111111"}')
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            if self.path == "/login":
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

    base_url, srv = _start_server(Handler)
    try:
        store, client, oracle = _make_oracle_env(tmp_path, base_url, max_requests=40)
        try:
            # 1. GET open redirect host mismatch
            r_ctrl = client.request(actor="alice", method="GET", url="/same")
            r_proof = client.request(actor="alice", method="GET", url="/redirect?next=https://evil.example/pwn")
            v_redir = oracle.verify(
                canonical_class="open_redirect",
                primary_proof=r_proof,
                proof_receipts=[r_proof],
                control_receipts=[r_ctrl],
                evidence_value="evil.example",
            )
            assert v_redir.verified is False
            assert v_redir.needs_verification is False
            assert v_redir.verdict == "REFUTED"

            # 2. GET 200 missing evidence
            x_ctrl = client.request(actor="alice", method="GET", url="/profile?name=safe")
            x_proof = client.request(actor="alice", method="GET", url="/profile?name=<svg>")
            v_get = oracle.verify(
                canonical_class="reflected_xss",
                primary_proof=x_proof,
                proof_receipts=[x_proof],
                control_receipts=[x_ctrl],
                evidence_value="<svg onload=alert(1)>",
            )
            assert v_get.verified is False
            assert v_get.needs_verification is False
            assert v_get.verdict == "REFUTED"

            # 3. Deception detected (identical masked body)
            d1 = client.request(actor="alice", method="GET", url="/same?a=1")
            d2 = client.request(actor="alice", method="GET", url="/same?a=2")
            v_dec = oracle.verify(
                canonical_class="sqli",
                primary_proof=d2,
                proof_receipts=[d2],
                control_receipts=[d1],
                evidence_value="static",
            )
            assert v_dec.verified is False
            assert v_dec.deception_detected is True
            assert v_dec.needs_verification is False
            assert v_dec.verification_tier == "DECEPTION_DETECTED"

            # 4. Redacted credential body POST -> 404 replay stays REFUTED (not one-shot lead)
            l_ctrl = {
                "receipt_id": "R-LC",
                "actor": "anon",
                "method": "POST",
                "url": f"{base_url}/login",
                "path": "/login",
                "status": 401,
                "body": '{"error":"bad"}',
                "request_headers": {},
                "response_headers": {},
            }
            l_proof = {
                "receipt_id": "R-LP",
                "actor": "anon",
                "method": "POST",
                "url": f"{base_url}/login",
                "path": "/login",
                "status": 200,
                "body": '{"logged_in":true}',
                "request_body": '{"email":"a@example.test","password":"<REDACTED_SECRET>"}',
                "request_headers": {},
                "response_headers": {},
            }
            v_login = oracle.verify(
                canonical_class="business_logic",
                primary_proof=l_proof,
                proof_receipts=[l_proof],
                control_receipts=[l_ctrl],
                evidence_value="logged_in",
            )
            assert v_login.verified is False
            assert v_login.needs_verification is False
        finally:
            client.close()
    finally:
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 2. ToolDispatcher lead isolation, schema preservation, and dedup/redaction
# ---------------------------------------------------------------------------


def test_tool_dispatcher_records_leads_without_polluting_findings(tmp_path: Path) -> None:
    assert len(TOOL_SCHEMAS) == 12
    redeemed = {"done": False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_PUT(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            if self.path == "/api/coupon":
                if "invalid" in body:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"invalid"}')
                    return
                if redeemed["done"]:
                    self.send_response(409)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"exhausted"}')
                    return
                redeemed["done"] = True
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"discount":99,"applied":true}')
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            if self.path == "/api/report-crash":
                if "payload" in body:
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"db_syntax_fault"}')
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
                return
            self.send_response(404)
            self.end_headers()

    base_url, srv = _start_server(Handler)
    try:
        store, client, oracle = _make_oracle_env(tmp_path, base_url, max_requests=40)
        disp = ToolDispatcher(
            http_client=client,
            receipt_store=store,
            root_dir=tmp_path,
            oracle=oracle,
        )
        try:
            # 1. One-shot state exhausted via record_finding (PUT -> 409)
            c1 = _unwrap_tool_json(disp.dispatch("http_request", {
                "method": "PUT",
                "url": "/api/coupon",
                "actor": "alice",
                "json_body": {"code": "invalid"},
            }))
            p1 = _unwrap_tool_json(disp.dispatch("http_request", {
                "method": "PUT",
                "url": "/api/coupon",
                "actor": "alice",
                "json_body": {"code": "ONCE"},
            }))
            res1 = json.loads(disp.dispatch("record_finding", {
                "title": "Privilege attribute overwrite via PUT",
                "class_type": "mass_assignment",
                "method": "PUT",
                "url": "/api/coupon",
                "actor_alias": "alice",
                "proof_receipt_ids": [p1["receipt_id"]],
                "control_receipt_ids": [c1["receipt_id"]],
                "evidence_value": "discount",
                "summary": "Updating restricted field via PUT succeeded once before 409 state conflict on replay.",
            }))
            assert res1["rejected"] is True
            assert res1["accepted"] is False
            assert res1["recorded_as_lead"] is True
            assert res1["verification_tier"] == "NEEDS_VERIFICATION"
            assert res1["signal_type"] == "one_shot_state_exhausted"
            assert res1["lead_id"] == "L-001"

            # 2. Server 5xx differential via record_finding
            c2 = _unwrap_tool_json(disp.dispatch("http_request", {
                "method": "POST",
                "url": "/api/report-crash",
                "actor": "alice",
                "json_body": {"q": "ok"},
            }))
            p2 = _unwrap_tool_json(disp.dispatch("http_request", {
                "method": "POST",
                "url": "/api/report-crash",
                "actor": "alice",
                "json_body": {"q": "payload'"},
            }))
            res2 = json.loads(disp.dispatch("record_finding", {
                "title": "SQL syntax 500 differential on report endpoint",
                "class_type": "sqli",
                "method": "POST",
                "url": "/api/report-crash",
                "actor_alias": "alice",
                "proof_receipt_ids": [p2["receipt_id"]],
                "control_receipt_ids": [c2["receipt_id"]],
                "evidence_value": "db_syntax_fault",
                "summary": "Quote payload caused 500 vs 200 control.",
            }))
            assert res2["rejected"] is True
            assert res2["recorded_as_lead"] is True
            assert res2["verification_tier"] == "NEEDS_VERIFICATION"
            assert res2["signal_type"] == "server_5xx_differential"

            # Isolated persistence check: NEVER written to self.findings or findings.json
            assert disp.findings == []
            assert not (tmp_path / "findings.json").exists()
            assert (tmp_path / "leads.json").is_file()
            persisted_leads = json.loads((tmp_path / "leads.json").read_text(encoding="utf-8"))
            assert len(persisted_leads) == 2
            # Stronger signal ranked first: server_5xx_differential (L-001) before one_shot_state_exhausted (L-002)
            assert persisted_leads[0]["lead_id"] == "L-001"
            assert persisted_leads[0]["signal_type"] == "server_5xx_differential"
            assert persisted_leads[1]["lead_id"] == "L-002"
            assert persisted_leads[1]["signal_type"] == "one_shot_state_exhausted"
            assert all(lead["verification_tier"] == "NEEDS_VERIFICATION" for lead in persisted_leads)
        finally:
            disp.close()
            client.close()
    finally:
        _stop_server(srv)


def test_canonicalize_and_deduplicate_leads_redacts_sorts_and_caps() -> None:
    raw = [
        {
            "title": "Budget lead",
            "class_type": "business_logic",
            "method": "POST",
            "url": "http://127.0.0.1:8080/api/orders/1/confirm?token=superrawtoken99",
            "signal_type": "multistep_budget_exceeded",
            "severity": "medium",
            "evidence": "Authorization: Bearer rawjwtsecrettoken1234",
            "proof_receipt_ids": ["R-1"],
        },
        {
            "title": "Budget lead duplicate",
            "class_type": "business_logic",
            "method": "POST",
            "url": "http://127.0.0.1:8080/api/orders/2/confirm?token=anotherrawsecret",
            "signal_type": "multistep_budget_exceeded",
            "severity": "high",
            "evidence": "Longer evidence Cookie: session=rawcookiedata1234567",
            "proof_receipt_ids": ["R-2"],
        },
        {
            "title": "OOB lead",
            "class_type": "ssrf",
            "method": "POST",
            "url": "http://127.0.0.1:8080/api/webhooks",
            "signal_type": "async_oob_unreplayed",
            "severity": "high",
            "oob_hit_count": 2,
            "proof_receipt_ids": ["R-3"],
        },
    ]
    out = canonicalize_and_deduplicate_leads(raw, max_leads=2)
    assert len(out) == 2
    assert out[0]["lead_id"] == "L-001"
    assert out[0]["signal_type"] == "async_oob_unreplayed"
    assert out[1]["lead_id"] == "L-002"
    assert out[1]["proof_receipt_ids"] == ["R-1", "R-2"]
    dumped = json.dumps(out)
    for raw_sec in ("superrawtoken99", "anotherrawsecret", "rawjwtsecrettoken1234", "rawcookiedata1234567"):
        assert raw_sec not in dumped


# ---------------------------------------------------------------------------
# 3. Late-Hit OOB Reconciliation (unit + AgenticInvestigator end-to-end)
# ---------------------------------------------------------------------------


def test_reconcile_late_oob_hits_skips_confirmed_and_dedups_existing(tmp_path: Path) -> None:
    oob = LoopbackCallbackServer()
    oob.start()
    try:
        t_confirmed = oob.create_token("ssrf-confirmed")
        t_late = oob.create_token("xxe-late")
        t_already_lead = oob.create_token("ssrf-existing-lead")

        requests.get(f"{t_confirmed['url']}?ok=1", timeout=2.0)
        requests.post(
            t_late["url"],
            data="ping",
            headers={"Authorization": "Bearer supersecretlateoob999"},
            timeout=2.0,
        )
        requests.get(t_already_lead["url"], timeout=2.0)

        receipts = {
            "R-0001": {
                "receipt_id": "R-0001",
                "actor": "alice",
                "method": "POST",
                "url": "http://127.0.0.1:9000/api/hooks",
                "path": "/api/hooks",
                "request_body": json.dumps({"cb": t_confirmed["url"]}),
                "request_headers": {},
            },
            "R-0009": {
                "receipt_id": "R-0009",
                "actor": "bob",
                "method": "POST",
                "url": f"http://127.0.0.1:9000/api/xml?secret=rawurlsec999&cb={t_late['token']}",
                "path": "/api/xml",
                "request_body": f"<x>{t_late['url']}</x>",
                "request_headers": {},
            },
        }
        findings = [
            {
                "finding_id": "F-001",
                "class_type": "ssrf",
                "proof_receipt_ids": ["R-0001"],
                "evidence": "matched",
            }
        ]
        existing_leads = [
            {
                "lead_id": "L-001",
                "signal_type": "async_oob_unreplayed",
                "oob_token": t_already_lead["token"],
            }
        ]

        reconciled = reconcile_late_oob_hits(
            oob,
            findings=findings,
            leads=existing_leads,
            receipts=receipts,
            base_url="http://127.0.0.1:9000",
        )
        assert len(reconciled) == 1
        lead = reconciled[0]
        assert lead["verification_tier"] == "NEEDS_VERIFICATION"
        assert lead["oracle_verdict"] == "NEEDS_VERIFICATION"
        assert lead["signal_type"] == "async_oob_unreplayed"
        assert lead["verification_blocker"] == "late_oob_hit_after_shard_close"
        assert lead["passed_stages"] == ["oob_callback_received"]
        assert lead["oob_token"] == t_late["token"]
        assert lead["oob_hit_count"] == 1
        assert lead["method"] == "POST"
        assert lead["actor"] == "bob"
        assert lead["class_type"] == "xxe"
        assert lead["proof_receipt_ids"] == ["R-0009"]
        dumped = json.dumps(lead)
        assert "supersecretlateoob999" not in dumped
        assert "rawurlsec999" not in dumped
    finally:
        oob.close()


def test_investigator_sharded_reconciles_late_oob_before_closing_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-alice"},
    ])
    client = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=40,
    )
    budget = SharedBudget(tokens=400_000)
    seed_surface = {
        "links": [
            {"method": "GET", "url": "http://127.0.0.1:18080/api/orders/1"},
            {"method": "POST", "url": "http://127.0.0.1:18080/api/orders"},
            {"method": "GET", "url": "http://127.0.0.1:18080/api/orders/history"},
            {"method": "GET", "url": "http://127.0.0.1:18080/api/orders/export"},
            {"method": "GET", "url": "http://127.0.0.1:18080/api/invoices/1"},
            {"method": "POST", "url": "http://127.0.0.1:18080/api/invoices"},
            {"method": "GET", "url": "http://127.0.0.1:18080/api/invoices/pdf"},
            {"method": "GET", "url": "http://127.0.0.1:18080/api/invoices/status"},
        ]
    }
    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            execution_mode="sharded",
            seed_surface=seed_surface,
        )
        oob_ref: dict[str, Any] = {}
        s1_ready = threading.Event()

        def _fake_exec(**kwargs: Any) -> tuple[str, int, list[dict[str, Any]]]:
            disp = kwargs["dispatcher"]
            cluster = kwargs.get("shard_cluster")
            if cluster is not None and cluster.shard_id == "shard-1":
                cb = json.loads(disp.dispatch("callback_listener", {"action": "create_url", "label": "late-ssrf"}))
                rec = store.record(
                    actor="alice",
                    method="POST",
                    url="http://127.0.0.1:18080/api/orders/webhook",
                    path="/api/orders/webhook",
                    query="",
                    request_headers={},
                    request_body=json.dumps({"url": cb["url"]}),
                    status=202,
                    elapsed_ms=5.0,
                    content_type="application/json",
                    response_headers={},
                    raw_response_bytes=b'{"queued":true}',
                    response_text='{"queued":true}',
                )
                oob_ref["server"] = disp._get_oob_server(start=False)
                oob_ref["url"] = cb["url"]
                oob_ref["token"] = cb["token"]
                # Record an existing shard lead directly too so shard-lead merging is also verified.
                disp.leads.append({
                    "title": "Shard precursor blocked",
                    "class_type": "business_logic",
                    "method": "POST",
                    "url": "http://127.0.0.1:18080/api/orders/checkout",
                    "signal_type": "multistep_precursor_blocked",
                    "passed_stages": ["stage1_control", "stage2_diff"],
                    "verification_blocker": "stage3_clean_replay:failed_multistep_precursor_409",
                    "suggested_manual_verification": "Re-seed checkout cart state before replay.",
                    "proof_receipt_ids": [rec["receipt_id"]],
                })
                disp._save_leads()
                s1_ready.set()
            elif cluster is not None and cluster.shard_id == "shard-2":
                # Simulate delayed OOB callback hitting shared server across shard lifetime.
                assert s1_ready.wait(timeout=5.0)
                assert oob_ref["server"].is_running is True
                requests.get(oob_ref["url"], timeout=2.0)
            return "finished", int(kwargs.get("start_turn", 1)), kwargs["messages"]

        monkeypatch.setattr(inv, "_execute_monolithic_loop", _fake_exec)
        monkeypatch.setattr(
            agentic_investigator,
            "collect_cross_shard_synthesis_context",
            lambda **_kw: {
                "should_trigger": False,
                "findings": [],
                "internal_urls": [],
                "extracted_values": [],
                "auth_capabilities": [],
                "blockers": [],
                "untested_writes_and_blocked": [],
                "high_risk_unprobed_routes": [],
            },
        )
        res = inv.run(resume=False)
        assert res["status"] == "finished"
        assert res["findings_count"] == 0
        assert res["leads_count"] == 2
        assert Path(res["leads_path"]) == (tmp_path / "leads.json").resolve()
        assert oob_ref["server"].is_running is False
        assert not (tmp_path / "findings.json").exists() or json.loads(
            (tmp_path / "findings.json").read_text(encoding="utf-8")
        ) == []

        saved_leads = json.loads((tmp_path / "leads.json").read_text(encoding="utf-8"))
        assert len(saved_leads) == 2
        sig_types = [lead["signal_type"] for lead in saved_leads]
        assert sig_types == ["async_oob_unreplayed", "multistep_precursor_blocked"]
        assert saved_leads[0]["oob_token"] == oob_ref["token"]
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 4. Reporting isolation (Markdown + SARIF 2.1.0 + secret redaction)
# ---------------------------------------------------------------------------


def test_reports_separate_confirmed_findings_from_needs_verification_leads(tmp_path: Path) -> None:
    run_dir = tmp_path / "run1"
    (run_dir / "receipts").mkdir(parents=True)
    (run_dir / "shards" / "shard-1").mkdir(parents=True)

    (run_dir / "manifest.json").write_text(json.dumps({
        "schema": "agentic-target-run/1",
        "run_id": "run-leads-001",
        "target": "http://127.0.0.1:9000",
        "status": "finished",
        "finished": True,
        "execution_mode": "sharded",
    }), encoding="utf-8")
    (run_dir / "process_metrics.json").write_text(json.dumps({
        "exposure_rate": 0.75,
        "unique_endpoints_visited": 3,
        "unique_endpoints_discovered": 4,
    }), encoding="utf-8")
    (run_dir / "receipts" / "R-0001.json").write_text(json.dumps({
        "receipt_id": "R-0001",
        "actor": "alice",
        "method": "GET",
        "url": "http://127.0.0.1:9000/api/orders/1",
        "path": "/api/orders/1",
        "status": 200,
        "request_headers": {"Authorization": "<REDACTED:bearer>"},
        "response_headers": {},
        "body": '{"secret":"confirmed_order"}',
    }), encoding="utf-8")
    (run_dir / "findings.json").write_text(json.dumps([
        {
            "finding_id": "F-001",
            "title": "Confirmed BOLA on order endpoint",
            "class_type": "bola",
            "route_template": "/api/orders/{id}",
            "method": "GET",
            "url": "http://127.0.0.1:9000/api/orders/1",
            "path": "/api/orders/1",
            "actor": "alice",
            "severity": "high",
            "oracle_verdict": "VERIFIED",
            "proof_receipt_ids": ["R-0001"],
            "control_receipt_ids": [],
            "evidence": "confirmed_order",
        }
    ]), encoding="utf-8")

    # 1. Without leads.json -> NOT treated as missing artifact & Markdown keeps standard headings
    art_no_leads = agentic_report.load_run_artifacts(run_dir)
    assert "leads.json" not in art_no_leads["missing_artifacts"]
    assert art_no_leads["leads"] == []
    md_no_leads = agentic_report.render_markdown_report(art_no_leads)
    assert "Leads Requiring Manual Verification" not in md_no_leads
    assert "## 4. NOT TESTED & Coverage Visibility" in md_no_leads

    # 2. With root leads.json + shard leads.json containing raw secrets -> rendered & redacted cleanly
    (run_dir / "leads.json").write_text(json.dumps([
        {
            "lead_id": "L-001",
            "title": "Delayed webhook SSRF callback",
            "class_type": "ssrf",
            "route_template": "/api/webhooks",
            "method": "POST",
            "url": "http://127.0.0.1:9000/api/webhooks?token=rawsecretleadtok1",
            "path": "/api/webhooks",
            "actor": "alice",
            "severity": "high",
            "verification_tier": "NEEDS_VERIFICATION",
            "signal_type": "async_oob_unreplayed",
            "passed_stages": ["oob_callback_received"],
            "verification_blocker": "late_oob_hit_after_shard_close",
            "suggested_manual_verification": "Replay with fresh OOB listener.",
            "oob_token": "tok-late-1",
            "oob_hit_count": 1,
            "evidence": "Authorization: Bearer supersecretleadbearer99",
            "proof_receipt_ids": ["R-0001"],
            "control_receipt_ids": [],
        }
    ]), encoding="utf-8")
    (run_dir / "shards" / "shard-1" / "leads.json").write_text(json.dumps([
        {
            "lead_id": "L-001",
            "title": "Precursor blocked workflow",
            "class_type": "business_logic",
            "route_template": "/api/checkout/confirm",
            "method": "POST",
            "url": "http://127.0.0.1:9000/api/checkout/confirm",
            "path": "/api/checkout/confirm",
            "actor": "alice",
            "severity": "medium",
            "verification_tier": "NEEDS_VERIFICATION",
            "signal_type": "multistep_precursor_blocked",
            "passed_stages": ["stage1_control", "stage2_diff"],
            "verification_blocker": "stage3_clean_replay:failed_multistep_precursor_409",
            "suggested_manual_verification": "Create fresh draft order before replaying.",
            "proof_receipt_ids": ["R-0001"],
            "control_receipt_ids": [],
        }
    ]), encoding="utf-8")

    summary = agentic_report.generate_run_reports(run_dir)
    assert summary["findings_count"] == 1
    assert summary["leads_count"] == 2

    md_text = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "## 4. Leads Requiring Manual Verification (NEEDS_VERIFICATION)" in md_text
    assert "## 5. NOT TESTED & Coverage Visibility" in md_text
    assert "async_oob_unreplayed" in md_text
    assert "multistep_precursor_blocked" in md_text
    assert "rawsecretleadtok1" not in md_text
    assert "supersecretleadbearer99" not in md_text

    sarif = json.loads((run_dir / "report.sarif").read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    assert len(results) == 3
    confirmed_res = [r for r in results if r["properties"]["verification_tier"] == "CONFIRMED"]
    lead_res = [r for r in results if r["properties"]["verification_tier"] == "NEEDS_VERIFICATION"]
    assert len(confirmed_res) == 1
    assert confirmed_res[0]["kind"] == "fail"
    assert len(lead_res) == 2
    for lr in lead_res:
        assert lr["kind"] == "review"
        assert lr["level"] == "note"
        assert lr["partialFingerprints"]["canonicalKey"].startswith("lead:")
    sarif_str = json.dumps(sarif)
    assert "rawsecretleadtok1" not in sarif_str
    assert "supersecretleadbearer99" not in sarif_str
