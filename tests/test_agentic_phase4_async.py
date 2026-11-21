"""Phase 4 tests: loopback callback listener, concurrent_check, and oracle verification."""
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

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_oob import DEFAULT_MAX_BODY_CHARS, DEFAULT_MAX_HITS, LoopbackCallbackServer  # noqa: E402
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import TOOL_SCHEMAS, ToolDispatcher  # noqa: E402


def _unwrap_tool_payload(raw: str) -> dict[str, Any]:
    prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw.startswith(prefix)
    assert raw.rstrip().endswith(suffix.strip())
    body = raw[len(prefix) :].rsplit(suffix, 1)[0]
    return json.loads(body)


def _make_target_server() -> tuple[str, dict[str, Any], ThreadingHTTPServer]:
    """Local loopback target simulating async webhooks, in-band proxy SSRF, and non-atomic promo redemption."""
    state: dict[str, Any] = {
        "redeemed_codes": set(),
        "redeem_calls": 0,
        "webhook_calls": 0,
        "balance": 0,
    }
    lock = threading.Lock()

    class _TargetHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send_json(self, status: int, obj: Any) -> None:
            payload = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path == "/api/proxy":
                qs = parse_qs(parsed.query)
                target = (qs.get("url") or [""])[0]
                if target.startswith("http://127.0.0.1:"):
                    try:
                        r = requests.get(target, timeout=2.0)
                        self._send_json(200, {"proxied_status": r.status_code, "body": r.text})
                        return
                    except Exception as exc:
                        self._send_json(502, {"error": str(exc)})
                        return
                if "internal" in target:
                    self._send_json(200, {"proxied_status": 200, "body": "INTERNAL_META_SECRET_991"})
                    return
                self._send_json(200, {"proxied_status": 200, "body": "PUBLIC_SAFE_PAGE"})
                return
            self._send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            parsed = urlsplit(self.path)
            raw_len = int(self.headers.get("Content-Length") or "0")
            body_bytes = self.rfile.read(raw_len) if raw_len > 0 else b""
            try:
                data = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except ValueError:
                data = {}

            if parsed.path == "/api/webhooks/dispatch":
                with lock:
                    state["webhook_calls"] += 1
                cb_url = str(data.get("callback_url") or "")
                # Simulate an async/blind server-side fetch only for loopback /cb/ URLs when execute=true.
                if cb_url.startswith("http://127.0.0.1:") and bool(data.get("execute", True)):
                    def _bg_fetch() -> None:
                        try:
                            requests.post(
                                cb_url,
                                json={"event": "webhook_ping", "secret": "oob-ping-77"},
                                headers={"X-Worker": "target-bg-worker"},
                                timeout=2.0,
                            )
                        except Exception:
                            pass

                    threading.Thread(target=_bg_fetch, daemon=True).start()
                # Both real SSRF and benign control return identical 202 JSON.
                self._send_json(202, {"queued": True, "echo": cb_url})
                return

            if parsed.path == "/api/promo/redeem":
                code = str(data.get("code") or "").strip()
                with lock:
                    state["redeem_calls"] += 1
                    already = code in state["redeemed_codes"]
                if already:
                    self._send_json(409, {"error": "already redeemed", "code": code})
                    return
                # Intentional TOCTOU window between read and write without lock.
                time.sleep(0.08)
                with lock:
                    state["redeemed_codes"].add(code)
                    state["balance"] += 100
                    bal = state["balance"]
                self._send_json(200, {"status": "redeemed", "code": code, "balance": bal})
                return

            self._send_json(404, {"error": "not_found"})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", state, srv


def _make_env(
    tmp_path: Path,
    base_url: str,
    *,
    allowed_methods: tuple[str, ...] = ("GET", "POST"),
    max_requests: int = 50,
    oob_server: LoopbackCallbackServer | None = None,
):
    store = ReceiptStore(tmp_path / "store")
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-alice"},
        {"alias": "bob", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-bob"},
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
    )
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential")
    dispatcher = ToolDispatcher(
        http_client=client,
        receipt_store=store,
        root_dir=tmp_path,
        oracle=oracle,
        oob_server=oob_server,
    )
    return store, client, oracle, dispatcher


def test_tool_schemas_descriptions_concise_and_bounded() -> None:
    names = [t["function"]["name"] for t in TOOL_SCHEMAS]
    assert "callback_listener" in names
    assert "concurrent_check" in names
    for tool in TOOL_SCHEMAS:
        desc = tool["function"]["description"]
        assert len(desc) <= 140, f"{tool['function']['name']} description exceeds 140 chars ({len(desc)})"


def test_loopback_callback_server_security_caps_and_lifecycle() -> None:
    with pytest.raises(ValueError):
        LoopbackCallbackServer(host="0.0.0.0")
    with pytest.raises(ValueError):
        LoopbackCallbackServer(host="localhost")
    with pytest.raises(ValueError):
        LoopbackCallbackServer(host="192.168.1.5")

    srv = LoopbackCallbackServer(max_hits=5, max_body_chars=128)
    assert srv.start() is srv
    assert srv.start() is srv  # idempotent
    assert srv.is_running
    assert srv.port > 0
    try:
        tok_info = srv.create_token(label="unit-test")
        tok = tok_info["token"]
        assert tok_info["url"] == f"http://127.0.0.1:{srv.port}/cb/{tok}"
        assert tok_info["label"] == "unit-test"

        # Unknown token returns 404 and is not recorded.
        r_unknown = requests.get(f"http://127.0.0.1:{srv.port}/cb/nonexistent", timeout=2.0)
        assert r_unknown.status_code == 404
        assert srv.poll()["total_hits"] == 0

        # GET, POST (with oversized body + sensitive auth header), PUT, HEAD all succeed.
        r_get = requests.get(f"{tok_info['url']}?k=1", timeout=2.0)
        assert r_get.status_code == 200
        assert r_get.json() == {"ok": True}

        r_post = requests.post(
            tok_info["url"],
            data="X" * 5000,
            headers={"Authorization": "Bearer super-secret-token-value", "X-Custom": "abc"},
            timeout=2.0,
        )
        assert r_post.status_code == 200

        r_put = requests.put(tok_info["url"], data="put-body", timeout=2.0)
        assert r_put.status_code == 200

        r_head = requests.head(tok_info["url"], timeout=2.0)
        assert r_head.status_code == 200
        assert r_head.content == b""

        polled = srv.poll(tok)
        assert polled["hit_count"] == 4
        post_hit = polled["hits"][1]
        assert post_hit["method"] == "POST"
        assert len(post_hit["body_preview"]) <= 128
        assert "super-secret-token-value" not in json.dumps(post_hit["headers"])
        assert "<REDACTED:" in post_hit["headers"]["Authorization"]
        assert post_hit["remote_addr"] == "127.0.0.1"
        assert post_hit["timestamp"]

        # Verify hit count cap (max_hits=5 here; defaults are 200 / 2048).
        assert DEFAULT_MAX_HITS == 200
        assert DEFAULT_MAX_BODY_CHARS == 2048
        for _ in range(10):
            requests.get(tok_info["url"], timeout=2.0)
        summary = srv.poll()
        assert summary["total_hits"] == 5
        assert len(summary["hits"]) == 5
        assert summary["dropped_hits"] == 9
    finally:
        srv.close()
        srv.close()  # idempotent
        assert not srv.is_running


def test_callback_listener_ssrf_positive_negative_and_non_oob_preserved(tmp_path: Path) -> None:
    base_url, state, srv = _make_target_server()
    store, client, oracle, dispatcher = _make_env(tmp_path, base_url, max_requests=40)
    try:
        # 1. Negative test: create_url + target echoes /cb/<tok> without actually fetching -> 0 hits -> rejected!
        budget_before = client.budget.used
        cb_zero = json.loads(dispatcher.dispatch("callback_listener", {"action": "create_url", "label": "echo-only"}))
        assert client.budget.used == budget_before  # 0 target HTTP budget cost

        echo_proof = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "POST",
            "url": "/api/webhooks/dispatch",
            "actor": "alice",
            "json_body": {"callback_url": cb_zero["url"], "execute": False},
        }))
        echo_ctrl = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "POST",
            "url": "/api/webhooks/dispatch",
            "actor": "alice",
            "json_body": {"callback_url": "https://example.invalid/noop", "execute": False},
        }))
        poll_zero = _unwrap_tool_payload(dispatcher.dispatch("callback_listener", {"action": "poll", "token": cb_zero["token"]}))
        assert poll_zero["hit_count"] == 0
        assert client.budget.used == budget_before + 2  # poll also costs 0 target HTTP budget

        rej_zero = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Echoed callback URL without SSRF execution",
            "class_type": "ssrf",
            "method": "POST",
            "url": "/api/webhooks/dispatch",
            "actor_alias": "alice",
            "proof_receipt_ids": [echo_proof["receipt_id"]],
            "control_receipt_ids": [echo_ctrl["receipt_id"]],
            "evidence_value": cb_zero["token"],
            "summary": "Claiming callback execution despite 0 hits.",
        }))
        assert rej_zero["rejected"] is True
        assert "0 hits" in rej_zero["reason"]

        # 2. Positive OOB SSRF: target fetches callback_url asynchronously and returns identical 202 JSON.
        cb_real = json.loads(dispatcher.dispatch("callback_listener", {"action": "create_url", "label": "real-ssrf"}))
        oob_proof = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "POST",
            "url": "/api/webhooks/dispatch",
            "actor": "alice",
            "json_body": {"callback_url": cb_real["url"], "execute": True},
        }))
        # Wait briefly for async daemon fetch to arrive.
        deadline = time.monotonic() + 2.0
        polled_real: dict[str, Any] = {"hit_count": 0}
        while time.monotonic() < deadline:
            polled_real = _unwrap_tool_payload(
                dispatcher.dispatch("callback_listener", {"action": "poll", "token": cb_real["token"]})
            )
            if polled_real["hit_count"] >= 1:
                break
            time.sleep(0.05)
        assert polled_real["hit_count"] == 1
        assert polled_real["hits"][0]["method"] == "POST"

        acc_oob = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Blind webhook SSRF confirmed via loopback callback",
            "class_type": "ssrf",
            "method": "POST",
            "url": "/api/webhooks/dispatch",
            "actor_alias": "alice",
            "proof_receipt_ids": [oob_proof["receipt_id"]],
            "control_receipt_ids": [echo_ctrl["receipt_id"]],
            "evidence_value": cb_real["token"],
            "summary": "Webhook endpoint executed outbound POST to loopback callback URL.",
        }))
        assert acc_oob.get("accepted") is True

        # 3. Existing non-OOB in-band SSRF proof still works without callback_listener.
        inband_proof = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "GET",
            "url": "/api/proxy?url=http://internal.service/meta",
            "actor": "alice",
        }))
        inband_ctrl = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "GET",
            "url": "/api/proxy?url=https://public.example/",
            "actor": "alice",
        }))
        acc_inband = json.loads(dispatcher.dispatch("record_finding", {
            "title": "In-band SSRF returns internal metadata",
            "class_type": "ssrf",
            "method": "GET",
            "url": "/api/proxy",
            "actor_alias": "alice",
            "proof_receipt_ids": [inband_proof["receipt_id"]],
            "control_receipt_ids": [inband_ctrl["receipt_id"]],
            "evidence_value": "INTERNAL_META_SECRET_991",
            "summary": "Proxy endpoint returned internal service body.",
        }))
        assert acc_inband.get("accepted") is True
        assert len(dispatcher.findings) == 2
    finally:
        dispatcher.close()
        client.close()
        srv.shutdown()
        srv.server_close()


def test_concurrent_check_toctou_race_and_oracle_stage3_safe(tmp_path: Path) -> None:
    base_url, state, srv = _make_target_server()
    store, client, oracle, dispatcher = _make_env(tmp_path, base_url, max_requests=25)
    try:
        # Passing count=99 clamps strictly to 5; passing count=1 clamps strictly to 2.
        burst = _unwrap_tool_payload(dispatcher.dispatch("concurrent_check", {
            "url": "/api/promo/redeem",
            "method": "POST",
            "actor": "alice",
            "json_body": {"code": "PROMO-SINGLE-USE"},
            "count": 99,
        }))
        assert burst["count"] == 5
        assert client.budget.used == 5
        assert len(set(burst["receipt_ids"])) == 5
        assert int(burst["status_counts"].get("200", 0)) >= 2
        assert state["redeem_calls"] == 5

        # Sequential retry after the race returns 409 Conflict.
        seq_ctrl = _unwrap_tool_payload(dispatcher.dispatch("http_request", {
            "method": "POST",
            "url": "/api/promo/redeem",
            "actor": "alice",
            "json_body": {"code": "PROMO-SINGLE-USE"},
        }))
        assert seq_ctrl["status"] == 409
        assert client.budget.used == 6

        redeem_calls_before_record = state["redeem_calls"]
        budget_before_record = client.budget.used

        # Single-receipt race_condition claim must be rejected.
        rej_single = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Single request cannot be race condition",
            "class_type": "race_condition",
            "method": "POST",
            "url": "/api/promo/redeem",
            "actor_alias": "alice",
            "proof_receipt_ids": [burst["receipt_ids"][0]],
            "control_receipt_ids": [seq_ctrl["receipt_id"]],
            "evidence_value": "redeemed",
            "summary": "Only one receipt.",
        }))
        assert rej_single["rejected"] is True

        # Multi-receipt concurrent proof + 409 sequential control verifies cleanly without Stage 3 burst replay!
        acc_race = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Non-atomic promo code redemption race condition",
            "class_type": "race_condition",
            "method": "POST",
            "url": "/api/promo/redeem",
            "actor_alias": "alice",
            "proof_receipt_ids": burst["receipt_ids"],
            "control_receipt_ids": [seq_ctrl["receipt_id"]],
            "evidence_value": "redeemed",
            "summary": "Parallel POST burst succeeded multiple times before sequential 409.",
        }))
        assert acc_race.get("accepted") is True
        assert state["redeem_calls"] == redeem_calls_before_record
        assert client.budget.used == budget_before_record

        # Also verify business_logic class on a separate endpoint path or fresh dispatcher.
        _, client2, _, disp2 = _make_env(tmp_path / "bl", base_url, max_requests=20)
        try:
            burst2 = _unwrap_tool_payload(disp2.dispatch("concurrent_check", {
                "url": "/api/promo/redeem",
                "method": "POST",
                "actor": "bob",
                "json_body": {"code": "PROMO-BL-2"},
                "count": 1,  # clamped to 2
            }))
            assert burst2["count"] == 2
            assert client2.budget.used == 2
            ctrl2 = _unwrap_tool_payload(disp2.dispatch("http_request", {
                "method": "POST",
                "url": "/api/promo/redeem",
                "actor": "bob",
                "json_body": {"code": "PROMO-BL-2"},
            }))
            assert ctrl2["status"] == 409
            calls_before_bl = state["redeem_calls"]
            acc_bl = json.loads(disp2.dispatch("record_finding", {
                "title": "Single-use promo idempotency bypass",
                "class_type": "business_logic",
                "method": "POST",
                "url": "/api/promo/redeem",
                "actor_alias": "bob",
                "proof_receipt_ids": burst2["receipt_ids"],
                "control_receipt_ids": [ctrl2["receipt_id"]],
                "evidence_value": "redeemed",
                "summary": "Concurrent requests bypassed single-use redemption check.",
            }))
            assert acc_bl.get("accepted") is True
            assert state["redeem_calls"] == calls_before_bl
        finally:
            disp2.close()
            client2.close()
    finally:
        dispatcher.close()
        client.close()
        srv.shutdown()
        srv.server_close()


def test_concurrent_check_guards_method_scope_and_budget(tmp_path: Path) -> None:
    base_url, state, srv = _make_target_server()
    store, client, oracle, dispatcher = _make_env(
        tmp_path,
        base_url,
        allowed_methods=("GET",),
        max_requests=2,
    )
    try:
        # Disallowed method rejected before consuming budget.
        bad_method = json.loads(dispatcher.dispatch("concurrent_check", {
            "url": "/api/promo/redeem",
            "method": "POST",
            "actor": "alice",
            "count": 2,
        }))
        assert bad_method["error"] == "MethodNotAllowedError"
        assert client.budget.used == 0

        # Out-of-scope URL rejected before consuming budget.
        bad_scope = json.loads(dispatcher.dispatch("concurrent_check", {
            "url": "https://evil.example/steal",
            "method": "GET",
            "actor": "alice",
            "count": 2,
        }))
        assert bad_scope["error"] == "ScopeViolationError"
        assert client.budget.used == 0

        # Insufficient budget for count=3 when max_requests=2 -> rejected before firing partial burst!
        low_budget = json.loads(dispatcher.dispatch("concurrent_check", {
            "url": "/api/proxy?url=https://public.example/",
            "method": "GET",
            "actor": "alice",
            "count": 3,
        }))
        assert low_budget["error"] == "BudgetExhaustedError"
        assert client.budget.used == 0
    finally:
        dispatcher.close()
        client.close()
        srv.shutdown()
        srv.server_close()
