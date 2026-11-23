"""Tests for Faz 5B: Statistical Timing-Differential Verification and Multi-Step N-Step Stateful Workflow Replay."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit
import uuid

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_oracle import (  # noqa: E402
    _TIMING_ELIGIBLE_CLASSES,
    DifferentialOracle,
    _apply_id_substitutions_to_request,
    _discover_precursor_chain,
    _extract_minted_id_substitutions,
    _extract_response_resource_ids,
    _is_safe_precursor_receipt,
    _is_timing_pair_significant,
    _receipt_elapsed_ms,
)
from agentic_receipts import ReceiptStore  # noqa: E402


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
    )
    return store, client, oracle


# ---------------------------------------------------------------------------
# 1. Pure helper unit tests
# ---------------------------------------------------------------------------


def test_timing_and_multistep_helper_units() -> None:
    for cls_name in ("sqli_read", "sqli", "rce", "cmd_injection", "command_injection", "ssti", "ssrf"):
        assert cls_name in _TIMING_ELIGIBLE_CLASSES
    assert "other" not in _TIMING_ELIGIBLE_CLASSES

    assert _receipt_elapsed_ms({"elapsed_ms": 152.4}) == 152.4
    assert _receipt_elapsed_ms({"elapsed_ms": 0}) == 0.0
    assert _receipt_elapsed_ms({"elapsed_ms": -5.0}) is None
    assert _receipt_elapsed_ms({"elapsed_ms": True}) is None
    assert _receipt_elapsed_ms({}) is None

    assert _is_timing_pair_significant(200.0, 5.0, min_delta_ms=120.0, min_ratio=3.0) is True
    # Delta too small
    assert _is_timing_pair_significant(100.0, 5.0, min_delta_ms=120.0, min_ratio=3.0) is False
    # Delta OK (130 >= 120), ratio too small (230 < 3 * 100)
    assert _is_timing_pair_significant(230.0, 100.0, min_delta_ms=120.0, min_ratio=3.0) is False
    # Control below floor uses max(control_ms, 20.0): 3 * 20 = 60, delta=120 -> 130 passes
    assert _is_timing_pair_significant(130.0, 1.0, min_delta_ms=120.0, min_ratio=3.0) is True

    # Location + nested JSON ID extraction
    orig_step = {
        "method": "POST",
        "url": "http://127.0.0.1:9999/orders",
        "redirect_location": "/orders/ord-101",
        "response_headers": {"Location": "/orders/ord-101"},
        "body": json.dumps({
            "id": 1,
            "data": {"order_id": "ord-101", "draft_id": "drf-9"},
            "csrf_token": "csrf-aaa",
        }),
    }
    replay_step = {
        "method": "POST",
        "url": "http://127.0.0.1:9999/orders",
        "redirect_location": "/orders/ord-202",
        "response_headers": {"Location": "/orders/ord-202"},
        "body": json.dumps({
            "id": 2,
            "data": {"order_id": "ord-202", "draft_id": "drf-9"},  # draft_id unchanged
            "csrf_token": "csrf-bbb",
        }),
    }
    slots = _extract_response_resource_ids(orig_step)
    assert slots[("location",)] == "ord-101"
    assert slots[("json", "id")] == "1"
    assert slots[("json", "data", "order_id")] == "ord-101"
    assert ("json", "csrf_token") not in slots

    downstream = {
        "method": "POST",
        "url": "http://127.0.0.1:9999/orders/ord-101/items?id=1&page=1",
        "request_body": json.dumps({"order_id": "ord-101", "id": 1, "qty": 1, "draft_id": "drf-9"}),
    }
    subs = _extract_minted_id_substitutions(orig_step, replay_step, [downstream])
    assert subs == {"ord-101": "ord-202", "1": "2"}

    # Clean substitution preserves unrelated short numeric fields (qty=1, page=1) while replacing IDs
    new_url, new_body = _apply_id_substitutions_to_request(
        downstream["url"],
        downstream["request_body"],
        subs,
    )
    assert "/orders/ord-202/items" in new_url
    assert "id=2" in new_url
    assert "page=1" in new_url
    parsed_body = json.loads(new_body)
    assert parsed_body == {"order_id": "ord-202", "id": 2, "qty": 1, "draft_id": "drf-9"}

    # Form-urlencoded body substitution
    _, form_sub = _apply_id_substitutions_to_request(
        "http://127.0.0.1:9999/submit",
        "order_id=ord-101&qty=1",
        subs,
    )
    assert form_sub == "order_id=ord-202&qty=1"

    # Precursor safety checks reject DELETE, logout, destructive lifecycle, and multipart
    assert _is_safe_precursor_receipt({"method": "POST", "url": "/drafts", "status": 201}) is True
    assert _is_safe_precursor_receipt({"method": "DELETE", "url": "/drafts/1", "status": 200}) is False
    assert _is_safe_precursor_receipt({"method": "POST", "url": "/auth/logout", "status": 200}) is False
    assert _is_safe_precursor_receipt({"method": "POST", "url": "/admin/reset-db", "status": 200}) is False
    assert _is_safe_precursor_receipt({
        "method": "POST",
        "url": "/upload",
        "status": 201,
        "request_body": 'multipart/form-data {"files":[{"filename":"a.txt"}]}',
    }) is False


# ---------------------------------------------------------------------------
# 2. Statistical Timing-Differential Verification (Positive & Fail-Closed Negative)
# ---------------------------------------------------------------------------


def test_timing_differential_positive_and_alternating_clean_replay(tmp_path: Path) -> None:
    lock = threading.Lock()
    replay_sequence: list[str] = []

    class _TimingHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _send_json(self, status: int, obj: Any) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            qs = parse_qs(parsed.query)
            q = (qs.get("q") or [""])[0]
            if parsed.path == "/api/blind":
                is_delayed = "SLEEP" in q
                with lock:
                    replay_sequence.append("proof" if is_delayed else "control")
                if is_delayed:
                    time.sleep(0.145)
                # Identical body except rotating dynamic request_id/timestamp (masked in Stage 2)
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "items": [],
                        "request_id": str(uuid.uuid4()),
                    },
                )
                return
            self._send_json(404, {"error": "not_found"})

    base_url, srv = _start_server(_TimingHandler)
    store, client, oracle = _make_oracle_env(
        tmp_path,
        base_url,
        timing_min_delta_ms=120.0,
        timing_min_ratio=3.0,
        timing_replay_pairs=2,
    )
    try:
        ctrl = client.request(method="GET", url="/api/blind?q=benign", actor="alice")
        proof = client.request(method="GET", url="/api/blind?q=1_SLEEP", actor="alice")
        assert ctrl["status"] == 200
        assert proof["status"] == 200
        assert proof["elapsed_ms"] >= 130.0

        replay_sequence.clear()
        verdict = oracle.verify(
            canonical_class="sqli_read",
            primary_proof=proof,
            proof_receipts=[proof],
            control_receipts=[ctrl],
            evidence_value="ok",
        )
        assert verdict.verified is True
        assert verdict.verdict == "VERIFIED"
        assert verdict.stages["stage1_control"] == "passed"
        assert verdict.stages["stage2_diff"] == "passed_timing_differential"
        assert verdict.stages["stage3_clean_replay"] == "passed_timing_statistical"
        assert replay_sequence == ["control", "proof", "control", "proof"]

        # Timing summary fields recorded cleanly in stages
        assert verdict.stages["control_ms"] < 60.0
        assert verdict.stages["proof_ms"] >= 130.0
        assert verdict.stages["delta_ms"] >= 120.0
        summary = verdict.stages["timing_summary"]
        assert summary["pairs"] == 2
        assert len(summary["control_samples_ms"]) == 2
        assert len(summary["proof_samples_ms"]) == 2
        assert summary["min_gap_ms"] >= 120.0
        assert store.get(verdict.clean_replay_receipt_id)["elapsed_ms"] >= 130.0

        # Also works for alias/eligible class names such as "cmd_injection"
        oracle_cmd = DifferentialOracle(
            http_client=client,
            receipt_store=store,
            mode="differential",
            timing_min_delta_ms=120.0,
            timing_min_ratio=3.0,
            timing_replay_pairs=1,
        )
        replay_sequence.clear()
        verdict_cmd = oracle_cmd.verify(
            canonical_class="cmd_injection",
            primary_proof=proof,
            proof_receipts=[proof],
            control_receipts=[ctrl],
            evidence_value="",
        )
        assert verdict_cmd.verified is True
        assert verdict_cmd.stages["stage2_diff"] == "passed_timing_differential"
        assert verdict_cmd.stages["stage3_clean_replay"] == "passed_timing_statistical"
        assert replay_sequence == ["control", "proof"]
    finally:
        client.close()
        _stop_server(srv)


def test_timing_differential_negative_spike_jitter_ineligible_and_budget(tmp_path: Path) -> None:
    lock = threading.Lock()
    state: dict[str, Any] = {
        "mode": "single_spike",  # single_spike | fast_proof_jitter | slow_ctrl_jitter | constant_slow | status_500
        "proof_calls": 0,
        "ctrl_calls": 0,
    }

    class _NoisyTimingHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _send_json(self, status: int, obj: Any) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            qs = parse_qs(parsed.query)
            q = (qs.get("q") or [""])[0]
            is_probe = "DELAY" in q
            with lock:
                mode = state["mode"]
                if is_probe:
                    state["proof_calls"] += 1
                    call_n = state["proof_calls"]
                else:
                    state["ctrl_calls"] += 1
                    call_n = state["ctrl_calls"]

            if mode == "single_spike":
                # Replays are all fast (no delay) despite original proof spike
                pass
            elif mode == "fast_proof_jitter":
                # Replay 1 slow, replay 2 fast -> overlap!
                if is_probe and call_n == 1:
                    time.sleep(0.08)
            elif mode == "slow_ctrl_jitter":
                # Proof slow, but control replay 2 spikes slow -> overlap!
                if is_probe:
                    time.sleep(0.08)
                elif call_n == 2:
                    time.sleep(0.07)
            elif mode == "ratio_fail":
                # Control ~45ms, proof ~120ms -> delta=75>=60, but 120 < 3*45=135 -> fails ratio!
                if is_probe:
                    time.sleep(0.115)
                else:
                    time.sleep(0.045)
            elif mode == "status_500":
                if is_probe:
                    self._send_json(500, {"error": "backend_error"})
                    return

            self._send_json(200, {"status": "ok"})

    base_url, srv = _start_server(_NoisyTimingHandler)
    store, client, oracle = _make_oracle_env(
        tmp_path,
        base_url,
        timing_min_delta_ms=60.0,
        timing_min_ratio=3.0,
        timing_replay_pairs=2,
    )

    def _rec_pair(tag: str) -> tuple[dict[str, Any], dict[str, Any]]:
        c = store.record(
            actor="alice",
            method="GET",
            url=f"{base_url}/api/t?q=normal_{tag}",
            path="/api/t",
            query=f"q=normal_{tag}",
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            raw_response_bytes=b'{"status":"ok"}',
            response_text='{"status":"ok"}',
        )
        p = store.record(
            actor="alice",
            method="GET",
            url=f"{base_url}/api/t?q=DELAY_{tag}",
            path="/api/t",
            query=f"q=DELAY_{tag}",
            status=200,
            elapsed_ms=140.0,
            content_type="application/json",
            raw_response_bytes=b'{"status":"ok"}',
            response_text='{"status":"ok"}',
        )
        return c, p

    try:
        # 1. Single random network spike on original request -> replays are fast -> REFUTED
        ctrl_spike, proof_spike = _rec_pair("spike")
        v_spike = oracle.verify(
            canonical_class="sqli",
            primary_proof=proof_spike,
            proof_receipts=[proof_spike],
            control_receipts=[ctrl_spike],
            evidence_value="ok",
        )
        assert v_spike.verified is False
        assert v_spike.verdict == "REFUTED"
        assert v_spike.stages["stage2_diff"] == "passed_timing_differential"
        assert v_spike.stages["stage3_clean_replay"] == "failed_timing_overlap"

        # 2. Overlapping jitter: one proof replay is fast -> REFUTED
        with lock:
            state.update({"mode": "fast_proof_jitter", "proof_calls": 0, "ctrl_calls": 0})
        ctrl_j1, proof_j1 = _rec_pair("j1")
        v_j1 = oracle.verify(
            canonical_class="ssti",
            primary_proof=proof_j1,
            proof_receipts=[proof_j1],
            control_receipts=[ctrl_j1],
            evidence_value="ok",
        )
        assert v_j1.verified is False
        assert v_j1.verdict == "REFUTED"
        assert v_j1.stages["stage3_clean_replay"] == "failed_timing_overlap"

        # 3. Overlapping jitter: one control replay is slow -> REFUTED
        with lock:
            state.update({"mode": "slow_ctrl_jitter", "proof_calls": 0, "ctrl_calls": 0})
        ctrl_j2, proof_j2 = _rec_pair("j2")
        v_j2 = oracle.verify(
            canonical_class="ssrf",
            primary_proof=proof_j2,
            proof_receipts=[proof_j2],
            control_receipts=[ctrl_j2],
            evidence_value="ok",
        )
        assert v_j2.verified is False
        assert v_j2.verdict == "REFUTED"
        assert v_j2.stages["stage3_clean_replay"] == "failed_timing_overlap"

        # 4. Ratio separation failure (delta passes, ratio fails) -> REFUTED
        with lock:
            state.update({"mode": "ratio_fail", "proof_calls": 0, "ctrl_calls": 0})
        ctrl_r, proof_r = _rec_pair("ratio")
        v_ratio = oracle.verify(
            canonical_class="rce",
            primary_proof=proof_r,
            proof_receipts=[proof_r],
            control_receipts=[ctrl_r],
            evidence_value="ok",
        )
        assert v_ratio.verified is False
        assert v_ratio.verdict == "REFUTED"
        assert v_ratio.stages["stage3_clean_replay"] == "failed_timing_overlap"

        # 5. Replay status inconsistency (500 during timing replay) -> REFUTED
        with lock:
            state.update({"mode": "status_500", "proof_calls": 0, "ctrl_calls": 0})
        ctrl_st, proof_st = _rec_pair("500")
        v_st = oracle.verify(
            canonical_class="sqli_read",
            primary_proof=proof_st,
            proof_receipts=[proof_st],
            control_receipts=[ctrl_st],
            evidence_value="ok",
        )
        assert v_st.verified is False
        assert v_st.verdict == "REFUTED"
        assert v_st.stages["stage3_clean_replay"] == "failed_timing_status"

        # 6. Non-timing-eligible class ("other" and "reflected_xss") -> REFUTED / rejected
        ctrl_ok, proof_ok = _rec_pair("elig")
        v_other = oracle.verify(
            canonical_class="other",
            primary_proof=proof_ok,
            proof_receipts=[proof_ok],
            control_receipts=[ctrl_ok],
            evidence_value="ok",
        )
        assert v_other.verified is False
        assert v_other.verdict == "REFUTED"
        assert v_other.stages["stage2_diff"] == "failed_masked_equivalence"

        v_xss = oracle.verify(
            canonical_class="reflected_xss",
            primary_proof=proof_ok,
            proof_receipts=[proof_ok],
            control_receipts=[ctrl_ok],
            evidence_value="ok",
        )
        assert v_xss.verified is False
        assert v_xss.stages["stage1_control"] == "deception_identical_control"

        # 7. Insufficient HTTP budget (< 2 * pairs remaining) -> REFUTED, zero replay calls!
        tight_store, tight_client, tight_oracle = _make_oracle_env(
            tmp_path / "tight_timing",
            base_url,
            max_requests=3,
            timing_min_delta_ms=60.0,
            timing_min_ratio=3.0,
            timing_replay_pairs=2,
        )
        try:
            t_ctrl = tight_store.record(
                actor="alice",
                method="GET",
                url=f"{base_url}/api/t?q=normal_budget",
                path="/api/t",
                query="q=normal_budget",
                status=200,
                elapsed_ms=2.0,
                content_type="application/json",
                raw_response_bytes=b'{"status":"ok"}',
                response_text='{"status":"ok"}',
            )
            t_proof = tight_store.record(
                actor="alice",
                method="GET",
                url=f"{base_url}/api/t?q=DELAY_budget",
                path="/api/t",
                query="q=DELAY_budget",
                status=200,
                elapsed_ms=140.0,
                content_type="application/json",
                raw_response_bytes=b'{"status":"ok"}',
                response_text='{"status":"ok"}',
            )
            # Budget limit is 3 -> 3 remaining, need 4 for 2 pairs!
            budget_before = tight_client.budget.used
            v_budget = tight_oracle.verify(
                canonical_class="sqli_read",
                primary_proof=t_proof,
                proof_receipts=[t_proof],
                control_receipts=[t_ctrl],
                evidence_value="ok",
            )
            assert v_budget.verified is False
            assert v_budget.verdict == "REFUTED"
            assert v_budget.stages["stage2_diff"] == "passed_timing_differential"
            assert v_budget.stages["stage3_clean_replay"] == "failed_timing_budget"
            assert tight_client.budget.used == budget_before
        finally:
            tight_client.close()
    finally:
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 3. Multi-Step N-Step Stateful Workflow Replay in Stage 3 (Positive & Negative)
# ---------------------------------------------------------------------------


def test_multistep_3step_draft_workflow_explicit_and_store_discovery(tmp_path: Path) -> None:
    lock = threading.Lock()
    drafts: dict[str, dict[str, Any]] = {}
    seq = {"draft": 0}
    behavior = {
        "direct_replay_status": 409,
        "fail_items_status": 0,
        "drop_evidence_after_first": False,
        "finalize_calls": 0,
        "items_calls": 0,
        "create_calls": 0,
    }
    observed_qtys: list[Any] = []

    class _DraftWorkflowHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _actor(self) -> str:
            auth = self.headers.get("Authorization", "")
            return {"Bearer tok-alice": "alice", "Bearer tok-bob": "bob"}.get(auth, "anon")

        def _send_json(self, status: int, obj: Any, extra_headers: dict[str, str] | None = None) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path.rstrip("/")
            actor = self._actor()
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            data = json.loads(raw) if raw.strip().startswith("{") else {}

            if actor == "anon":
                self._send_json(401, {"error": "unauthorized"})
                return

            if path == "/drafts":
                with lock:
                    behavior["create_calls"] += 1
                    seq["draft"] += 1
                    did = f"draft-{seq['draft']}"
                    drafts[did] = {"id": did, "owner": actor, "items": [], "finalized": False}
                self._send_json(
                    201,
                    {"id": did, "status": "open"},
                    extra_headers={"Location": f"/drafts/{did}"},
                )
                return

            parts = [p for p in path.split("/") if p]
            if len(parts) == 3 and parts[0] == "drafts" and parts[2] == "items":
                did = parts[1]
                with lock:
                    behavior["items_calls"] += 1
                    if behavior["fail_items_status"] and behavior["items_calls"] > 1:
                        self._send_json(behavior["fail_items_status"], {"error": "step2_blocked"})
                        return
                    rec = drafts.get(did)
                    if rec is None or rec["finalized"]:
                        self._send_json(404, {"error": "draft_not_open"})
                        return
                    observed_qtys.append(data.get("qty"))
                    rec["items"].append(data)
                self._send_json(200, {"draft_id": did, "item_count": len(rec["items"])})
                return

            if len(parts) == 3 and parts[0] == "drafts" and parts[2] == "finalize":
                did = parts[1]
                if actor == "bob":
                    self._send_json(403, {"error": "forbidden_finalize"})
                    return
                with lock:
                    behavior["finalize_calls"] += 1
                    rec = drafts.get(did)
                    if rec is None:
                        self._send_json(404, {"error": "draft_not_found"})
                        return
                    if rec["finalized"]:
                        self._send_json(behavior["direct_replay_status"], {"error": "already_finalized"})
                        return
                    if not rec["items"]:
                        self._send_json(400, {"error": "draft_empty"})
                        return
                    rec["finalized"] = True
                    drop_ev = behavior["drop_evidence_after_first"] and behavior["finalize_calls"] > 1
                if drop_ev:
                    self._send_json(200, {"draft_id": did, "status": "finalized", "discount": 0})
                else:
                    self._send_json(
                        200,
                        {"draft_id": did, "status": "finalized", "coupon": "FINALIZED_DISCOUNT_99"},
                    )
                return

            self._send_json(404, {"error": "not_found"})

    base_url, srv = _start_server(_DraftWorkflowHandler)
    store, client, oracle = _make_oracle_env(tmp_path, base_url)
    try:
        # Step 1 -> Step 2 -> Step 3 original workflow
        s1 = client.request(method="POST", url="/drafts", actor="alice", json_body={"title": "order-a"})
        assert s1["status"] == 201
        d1 = json.loads(s1["body"])["id"]
        assert d1 == "draft-1"

        s2 = client.request(
            method="POST",
            url=f"/drafts/{d1}/items",
            actor="alice",
            json_body={"sku": "WIDGET", "qty": 1},
        )
        assert s2["status"] == 200

        ctrl_403 = client.request(method="POST", url=f"/drafts/{d1}/finalize", actor="bob", json_body={})
        assert ctrl_403["status"] == 403

        s3 = client.request(method="POST", url=f"/drafts/{d1}/finalize", actor="alice", json_body={})
        assert s3["status"] == 200
        assert "FINALIZED_DISCOUNT_99" in s3["body"]

        # Positive 1: Explicit 3-step chain [s1, s2, s3], direct replay hits 409 -> dynamically substitutes draft-1 -> draft-2!
        v_explicit = oracle.verify(
            canonical_class="bfla",
            primary_proof=s3,
            proof_receipts=[s1, s2, s3],
            control_receipts=[ctrl_403],
            evidence_value="FINALIZED_DISCOUNT_99",
        )
        assert v_explicit.verified is True
        assert v_explicit.verdict == "VERIFIED"
        assert v_explicit.stages["stage1_control"] == "passed"
        assert v_explicit.stages["stage2_diff"] == "passed"
        assert v_explicit.stages["stage3_clean_replay"] == "passed_multistep_replay"
        assert v_explicit.stages["stage3_multistep_count"] == 3
        assert len(v_explicit.stages["stage3_precursor_replay_receipt_ids"]) == 2
        assert v_explicit.stages["stage3_id_substitutions"] == {"draft-1": "draft-2"}
        final_replayed = store.get(v_explicit.clean_replay_receipt_id)
        assert final_replayed["path"] == "/drafts/draft-2/finalize"
        assert "FINALIZED_DISCOUNT_99" in final_replayed["body"]
        assert observed_qtys[-1] == 1

        # Positive 2: Implicit discovery from receipt_store (caller only passes [s3]!) with direct replay 404!
        behavior["direct_replay_status"] = 404
        v_store = oracle.verify(
            canonical_class="bfla",
            primary_proof=s3,
            proof_receipts=[s3],
            control_receipts=[ctrl_403],
            evidence_value="FINALIZED_DISCOUNT_99",
        )
        assert v_store.verified is True
        assert v_store.stages["stage3_clean_replay"] == "passed_multistep_replay"
        assert v_store.stages["stage3_multistep_count"] == 3
        assert v_store.stages["stage3_id_substitutions"] == {"draft-1": "draft-3"}
        assert store.get(v_store.clean_replay_receipt_id)["path"] == "/drafts/draft-3/finalize"

        # Negative 1: Missing evidence_value on final replayed step -> REFUTED!
        behavior["direct_replay_status"] = 409
        behavior["drop_evidence_after_first"] = True
        v_missing_ev = oracle.verify(
            canonical_class="bfla",
            primary_proof=s3,
            proof_receipts=[s1, s2, s3],
            control_receipts=[ctrl_403],
            evidence_value="FINALIZED_DISCOUNT_99",
        )
        assert v_missing_ev.verified is False
        assert v_missing_ev.verdict == "REFUTED"
        assert v_missing_ev.stages["stage3_clean_replay"] == "failed_missing_evidence"
        behavior["drop_evidence_after_first"] = False

        # Negative 2: Precursor step fails with 403 and 500 -> strictly REFUTED (never falls back to 409 conflict!)
        for err_status in (403, 500):
            behavior["fail_items_status"] = err_status
            fin_before = behavior["finalize_calls"]
            v_prec_fail = oracle.verify(
                canonical_class="bfla",
                primary_proof=s3,
                proof_receipts=[s1, s2, s3],
                control_receipts=[ctrl_403],
                evidence_value="FINALIZED_DISCOUNT_99",
            )
            assert v_prec_fail.verified is False
            assert v_prec_fail.verdict == "REFUTED"
            assert v_prec_fail.stages["stage3_clean_replay"] == f"failed_multistep_precursor_{err_status}"
            assert v_prec_fail.stages["stage3_multistep_failed_step"] == 2
            # Direct replay ran 1 finalize call; step 2 failed so step 3 was NOT re-executed
            assert behavior["finalize_calls"] == fin_before + 1
        behavior["fail_items_status"] = 0

        # Negative 3: Budget exceeded for 3-step chain -> REFUTED without sending orphaned precursor writes!
        _, tight_client, tight_oracle = _make_oracle_env(tmp_path / "tight_ms", base_url, max_requests=6)
        try:
            t_s1 = tight_client.request(method="POST", url="/drafts", actor="alice", json_body={"title": "b"})
            t_did = json.loads(t_s1["body"])["id"]
            t_s2 = tight_client.request(
                method="POST",
                url=f"/drafts/{t_did}/items",
                actor="alice",
                json_body={"sku": "B", "qty": 1},
            )
            t_ctrl = tight_client.request(method="POST", url=f"/drafts/{t_did}/finalize", actor="bob", json_body={})
            t_s3 = tight_client.request(method="POST", url=f"/drafts/{t_did}/finalize", actor="alice", json_body={})
            # Used 4 of 6 -> 2 left: direct replay uses 1 (leaving 1 < 3 needed for 3-step chain)
            creates_before = behavior["create_calls"]
            v_budget = tight_oracle.verify(
                canonical_class="bfla",
                primary_proof=t_s3,
                proof_receipts=[t_s1, t_s2, t_s3],
                control_receipts=[t_ctrl],
                evidence_value="FINALIZED_DISCOUNT_99",
            )
            assert v_budget.verified is False
            assert v_budget.verdict == "REFUTED"
            assert v_budget.stages["stage3_clean_replay"] == "failed_multistep_budget"
            assert behavior["create_calls"] == creates_before
        finally:
            tight_client.close()
    finally:
        client.close()
        _stop_server(srv)


def test_multistep_4step_chained_ids_and_max_3_precursor_bound(tmp_path: Path) -> None:
    lock = threading.Lock()
    orders: dict[str, dict[str, Any]] = {}
    seq = {"order": 100, "item": 500}

    class _FourStepHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _actor(self) -> str:
            return "alice" if self.headers.get("Authorization") == "Bearer tok-alice" else "anon"

        def _send_json(self, status: int, obj: Any) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            return json.loads(raw) if raw.strip().startswith("{") else {}

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            path = parsed.path.rstrip("/")
            qs = parse_qs(parsed.query)
            data = self._read_json()
            if self._actor() == "anon":
                self._send_json(401, {"error": "unauthorized"})
                return
            if path == "/orders":
                with lock:
                    seq["order"] += 1
                    oid = str(seq["order"])
                    orders[oid] = {"items": {}, "confirmed": False}
                self._send_json(201, {"data": {"order_id": oid}})
                return
            parts = [p for p in path.split("/") if p]
            if len(parts) == 3 and parts[0] == "orders" and parts[2] == "items":
                oid = parts[1]
                with lock:
                    ord_rec = orders.get(oid)
                    if ord_rec is None or ord_rec["confirmed"]:
                        self._send_json(404, {"error": "order_missing"})
                        return
                    seq["item"] += 1
                    iid = f"itm-{seq['item']}"
                    ord_rec["items"][iid] = {"patched": False, "sku": data.get("sku")}
                self._send_json(201, {"item_id": iid, "order_id": oid})
                return
            if len(parts) == 3 and parts[0] == "orders" and parts[2] == "confirm":
                oid = parts[1]
                iid = (qs.get("item_id") or [""])[0]
                with lock:
                    ord_rec = orders.get(oid)
                    if ord_rec is None or ord_rec["confirmed"]:
                        self._send_json(409, {"error": "already_confirmed"})
                        return
                    item = ord_rec["items"].get(iid)
                    if not item or not item["patched"]:
                        self._send_json(400, {"error": "item_not_patched"})
                        return
                    ord_rec["confirmed"] = True
                self._send_json(200, {"confirmed": True, "order_id": oid, "flag": "FOUR_STEP_CONFIRMED_OK"})
                return
            self._send_json(404, {"error": "not_found"})

        def do_PATCH(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path.rstrip("/")
            data = self._read_json()
            parts = [p for p in path.split("/") if p]
            if len(parts) == 4 and parts[0] == "orders" and parts[2] == "items":
                oid, iid = parts[1], parts[3]
                with lock:
                    ord_rec = orders.get(oid)
                    if ord_rec is None or iid not in ord_rec["items"] or str(data.get("order_id")) != oid:
                        self._send_json(404, {"error": "item_missing"})
                        return
                    ord_rec["items"][iid]["patched"] = True
                self._send_json(200, {"patched": True, "item_id": iid})
                return
            self._send_json(404, {"error": "not_found"})

    base_url, srv = _start_server(_FourStepHandler)
    store, client, oracle = _make_oracle_env(tmp_path, base_url)
    try:
        st1 = client.request(method="POST", url="/orders", actor="alice", json_body={})
        oid1 = json.loads(st1["body"])["data"]["order_id"]
        st2 = client.request(method="POST", url=f"/orders/{oid1}/items", actor="alice", json_body={"sku": "X"})
        iid1 = json.loads(st2["body"])["item_id"]
        st3 = client.request(
            method="PATCH",
            url=f"/orders/{oid1}/items/{iid1}",
            actor="alice",
            json_body={"order_id": oid1, "discount": 50},
        )
        ctrl = client.request(method="POST", url=f"/orders/{oid1}/confirm?item_id={iid1}", actor="anon", json_body={})
        st4 = client.request(method="POST", url=f"/orders/{oid1}/confirm?item_id={iid1}", actor="alice", json_body={})
        assert st4["status"] == 200

        verdict = oracle.verify(
            canonical_class="bfla",
            primary_proof=st4,
            proof_receipts=[st1, st2, st3, st4],
            control_receipts=[ctrl],
            evidence_value="FOUR_STEP_CONFIRMED_OK",
        )
        assert verdict.verified is True
        assert verdict.stages["stage3_clean_replay"] == "passed_multistep_replay"
        assert verdict.stages["stage3_multistep_count"] == 4
        assert len(verdict.stages["stage3_precursor_replay_receipt_ids"]) == 3
        subs = verdict.stages["stage3_id_substitutions"]
        assert subs[oid1] != oid1
        assert subs[iid1] != iid1
        final_rec = store.get(verdict.clean_replay_receipt_id)
        assert subs[oid1] in final_rec["path"]
        assert subs[iid1] in final_rec["query"]

        # Precursor discovery strictly enforces max 3 precursors and skips logout/lifecycle/DELETE steps.
        extra_writes = [
            {
                "receipt_id": "req-0001",
                "actor": "alice",
                "method": "POST",
                "url": f"{base_url}/orders",
                "status": 201,
                "body": '{"id":"ord-z"}',
            },
            {
                "receipt_id": "req-0002",
                "actor": "alice",
                "method": "POST",
                "url": f"{base_url}/auth/logout",
                "status": 200,
                "body": '{"id":"ord-z"}',
            },
            {
                "receipt_id": "req-0003",
                "actor": "alice",
                "method": "POST",
                "url": f"{base_url}/admin/reset-db",
                "status": 200,
                "body": '{"id":"ord-z"}',
            },
            {
                "receipt_id": "req-0004",
                "actor": "alice",
                "method": "POST",
                "url": f"{base_url}/orders/ord-z/step1",
                "status": 200,
                "body": '{"ok":true}',
            },
            {
                "receipt_id": "req-0005",
                "actor": "alice",
                "method": "POST",
                "url": f"{base_url}/orders/ord-z/step2",
                "status": 200,
                "body": '{"ok":true}',
            },
            {
                "receipt_id": "req-0006",
                "actor": "alice",
                "method": "POST",
                "url": f"{base_url}/orders/ord-z/step3",
                "status": 200,
                "body": '{"ok":true}',
            },
        ]
        target_rec = {
            "receipt_id": "req-0007",
            "actor": "alice",
            "method": "POST",
            "url": f"{base_url}/orders/ord-z/finalize",
            "status": 200,
            "body": '{"ok":true}',
        }
        chain = _discover_precursor_chain(
            target_rec,
            [*extra_writes, target_rec],
            None,
            allowed_methods=frozenset({"GET", "POST", "PUT", "PATCH"}),
        )
        assert len(chain) == 3
        urls = [str(r["url"]) for r in chain]
        assert not any("logout" in u or "reset-db" in u for u in urls)
    finally:
        client.close()
        _stop_server(srv)
