"""Tests for DifferentialOracle & agentic_evidence extensions:
1. Default desktop browser User-Agent in DifferentialOracle._run_clean_session_request.
2. Safe multipart/form-data handling in Stage 3 Clean Replay.
3. Destructive DELETE persistence verification in Stage 3.
4. Generalized OOB callback verification classes (ssrf, xxe, ssti, command_injection).
5. Expanded canonical finding classes, CORS header diff/replay, and jwt_weakness verification.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_evidence import _CLASS_ALIASES, normalize_vuln_class  # noqa: E402
from agentic_http import DEFAULT_BROWSER_USER_AGENT, ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_oob import LoopbackCallbackServer  # noqa: E402
from agentic_oracle import (  # noqa: E402
    _INPUT_DIFF_CLASSES,
    _OOB_ELIGIBLE_CLASSES,
    DifferentialOracle,
    _is_multipart_receipt,
)
from agentic_receipts import ReceiptStore  # noqa: E402


def _start_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[str, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", srv


def _stop_server(srv: ThreadingHTTPServer) -> None:
    srv.shutdown()
    srv.server_close()


def _make_oracle_env(
    tmp_path: Path,
    base_url: str,
    *,
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"),
    max_requests: int = 60,
    oob_server: LoopbackCallbackServer | None = None,
) -> tuple[ReceiptStore, ActorManager, AgenticHTTPClient, DifferentialOracle]:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager(
        accounts
        if accounts is not None
        else [
            {"alias": "alice", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-alice"},
            {"alias": "bob", "role": "member", "tenant": "beta", "auth_header": "Bearer tok-bob"},
        ]
    )
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
        oob_server=oob_server,
    )
    return store, actors, client, oracle


# ---------------------------------------------------------------------------
# 1. Default Desktop Browser User-Agent in Clean Replay
# ---------------------------------------------------------------------------


def test_clean_replay_sends_default_browser_user_agent_and_preserves_custom_ua(tmp_path: Path) -> None:
    recorded_uas: list[tuple[str, str]] = []

    class _UAHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            ua = self.headers.get("User-Agent", "")
            recorded_uas.append((self.path, ua))
            qs = parse_qs(urlsplit(self.path).query)
            q = (qs.get("q") or [""])[0]
            payload = json.dumps({"echo": q, "ua": ua}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

    base_url, srv = _start_server(_UAHandler)
    store, _, client, oracle = _make_oracle_env(tmp_path, base_url)
    try:
        # Synthetic proof without a User-Agent header ensures clean replay applies DEFAULT_BROWSER_USER_AGENT.
        proof = store.record(
            actor="alice",
            method="GET",
            url=f"{base_url}/search?q=SQLI_MARKER_99",
            path="/search",
            query="q=SQLI_MARKER_99",
            request_headers={},
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"echo":"SQLI_MARKER_99"}',
            response_text='{"echo":"SQLI_MARKER_99"}',
        )
        ctrl = store.record(
            actor="alice",
            method="GET",
            url=f"{base_url}/search?q=benign",
            path="/search",
            query="q=benign",
            request_headers={},
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"echo":"benign"}',
            response_text='{"echo":"benign"}',
        )
        verdict = oracle.verify(
            canonical_class="sqli_read",
            primary_proof=proof,
            proof_receipts=[proof],
            control_receipts=[ctrl],
            evidence_value="SQLI_MARKER_99",
        )
        assert verdict.verified is True
        assert verdict.stages["stage3_clean_replay"] == "passed"
        assert len(recorded_uas) == 1
        replay_ua = recorded_uas[0][1]
        assert replay_ua == DEFAULT_BROWSER_USER_AGENT
        assert "python-requests" not in replay_ua.lower()
        replay_rec = store.get(verdict.clean_replay_receipt_id)
        assert replay_rec["request_headers"].get("User-Agent") == DEFAULT_BROWSER_USER_AGENT

        # Explicit custom User-Agent (case-insensitive key) must be preserved during clean replay.
        recorded_uas.clear()
        custom_ua = "CustomPartnerAgent/4.2"
        custom_proof = store.record(
            actor="alice",
            method="GET",
            url=f"{base_url}/search?q=CUSTOM_UA_PROOF",
            path="/search",
            query="q=CUSTOM_UA_PROOF",
            request_headers={"user-agent": custom_ua},
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"echo":"CUSTOM_UA_PROOF"}',
            response_text='{"echo":"CUSTOM_UA_PROOF"}',
        )
        verdict_custom = oracle.verify(
            canonical_class="sqli_read",
            primary_proof=custom_proof,
            proof_receipts=[custom_proof],
            control_receipts=[ctrl],
            evidence_value="CUSTOM_UA_PROOF",
        )
        assert verdict_custom.verified is True
        assert recorded_uas == [("/search?q=CUSTOM_UA_PROOF", custom_ua)]
    finally:
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 2. Safe multipart/form-data Handling in Stage 3 Clean Replay
# ---------------------------------------------------------------------------


def test_is_multipart_receipt_detection_helper() -> None:
    assert _is_multipart_receipt({"request_body": 'multipart/form-data {"files":[{"filename":"a.php"}]}'}) is True
    assert _is_multipart_receipt({"request_body": "  MULTIPART/FORM-DATA summary"}) is True
    assert _is_multipart_receipt({
        "request_body": "",
        "request_headers": {"Content-Type": "multipart/form-data; boundary=----abc123"},
    }) is True
    assert _is_multipart_receipt({
        "request_body": "",
        "request_headers": {"content-type": "MULTIPART/FORM-DATA; boundary=xyz"},
    }) is True
    assert _is_multipart_receipt({
        "request_body": '{"name":"file"}',
        "request_headers": {"Content-Type": "application/json"},
    }) is False
    assert _is_multipart_receipt({"request_body": "", "request_headers": {}}) is False


def test_multipart_upload_skips_corrupt_replay_or_replays_followup_get(tmp_path: Path) -> None:
    state: dict[str, Any] = {"post_calls": 0, "uploads": {}, "bad_multipart_calls": 0}

    class _UploadHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _send_json(self, status: int, obj: Any) -> None:
            payload = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            state["post_calls"] += 1
            raw_len = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(raw_len) if raw_len > 0 else b""
            ctype = self.headers.get("Content-Type", "")
            if not ctype.lower().startswith("multipart/form-data") or b"boundary=" not in ctype.encode():
                self._send_json(415, {"error": "multipart_required"})
                return
            boundary = ctype.split("boundary=", 1)[1].strip()
            if f"--{boundary}".encode() not in body:
                # Corrupted replay sending the summary string instead of real MIME parts.
                state["bad_multipart_calls"] += 1
                self._send_json(400, {"error": "corrupted_multipart_boundary"})
                return
            text = body.decode("utf-8", errors="replace")
            if 'filename="blocked.exe"' in text:
                self._send_json(415, {"error": "extension_blocked"})
                return
            if 'filename="poc.svg"' in text:
                state["uploads"]["/uploads/poc.svg"] = "<svg onload=alert(1)><!-- UPLOAD_MARKER_77 --></svg>"
                self._send_json(201, {"stored": "/uploads/poc.svg", "marker": "UPLOAD_MARKER_77"})
                return
            self._send_json(201, {"stored": "/uploads/other.bin"})

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path in state["uploads"]:
                payload = state["uploads"][path].encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
                return
            self._send_json(404, {"error": "not_found"})

    base_url, srv = _start_server(_UploadHandler)
    store, _, client, oracle = _make_oracle_env(tmp_path, base_url)
    try:
        upload_proof = client.request(
            method="POST",
            url="/api/upload",
            actor="alice",
            files=[{
                "field": "file",
                "filename": "poc.svg",
                "content_type": "image/svg+xml",
                "content": "<svg onload=alert(1)></svg>",
            }],
        )
        assert upload_proof["status"] == 201
        assert _is_multipart_receipt(upload_proof) is True

        blocked_ctrl = client.request(
            method="POST",
            url="/api/upload",
            actor="alice",
            files=[{
                "field": "file",
                "filename": "blocked.exe",
                "content_type": "application/octet-stream",
                "content": "MZ",
            }],
        )
        assert blocked_ctrl["status"] == 415

        posts_before_verify = state["post_calls"]
        # Case A: No follow-up GET -> skips non-replayable multipart replay cleanly after Stages 1-2!
        v_skip = oracle.verify(
            canonical_class="file_upload",
            primary_proof=upload_proof,
            proof_receipts=[upload_proof],
            control_receipts=[blocked_ctrl],
            evidence_value="UPLOAD_MARKER_77",
        )
        assert v_skip.verified is True
        assert v_skip.verdict == "VERIFIED"
        assert v_skip.stages["stage1_control"] == "passed"
        assert v_skip.stages["stage2_diff"] == "passed"
        assert v_skip.stages["stage3_clean_replay"] == "skipped_non_replayable_multipart"
        assert state["post_calls"] == posts_before_verify
        assert state["bad_multipart_calls"] == 0

        # Case B: Follow-up GET proof IS present -> Stage 3 replays the GET (not the POST)!
        followup_get = client.request(method="GET", url="/uploads/poc.svg", actor="alice")
        assert followup_get["status"] == 200
        v_get = oracle.verify(
            canonical_class="file_upload",
            primary_proof=upload_proof,
            proof_receipts=[upload_proof, followup_get],
            control_receipts=[blocked_ctrl],
            evidence_value="UPLOAD_MARKER_77",
        )
        assert v_get.verified is True
        assert v_get.stages["stage3_clean_replay"] == "passed"
        assert v_get.clean_replay_receipt_id
        assert store.get(v_get.clean_replay_receipt_id)["method"] == "GET"
        assert state["post_calls"] == posts_before_verify
        assert state["bad_multipart_calls"] == 0

        # Case C: Identical control still gets caught by Stage 1 BEFORE multipart skip!
        same_ctrl = client.request(
            method="POST",
            url="/api/upload",
            actor="alice",
            files=[{
                "field": "file",
                "filename": "poc.svg",
                "content_type": "image/svg+xml",
                "content": "<svg onload=alert(1)></svg>",
            }],
        )
        v_deception = oracle.verify(
            canonical_class="file_upload",
            primary_proof=upload_proof,
            proof_receipts=[upload_proof],
            control_receipts=[same_ctrl],
            evidence_value="UPLOAD_MARKER_77",
        )
        assert v_deception.verified is False
        assert v_deception.verdict == "DECEPTION_DETECTED"
        assert v_deception.stages["stage1_control"] == "deception_identical_control"
    finally:
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 3. Destructive DELETE Persistence Verification in Stage 3
# ---------------------------------------------------------------------------


def test_destructive_delete_persistence_verified_and_false_positives_refuted(tmp_path: Path) -> None:
    docs: dict[str, dict[str, Any]] = {
        "42": {"id": "42", "owner": "alice", "tenant": "alpha", "secret": "DOC_42_PRIVATE"},
        "43": {"id": "43", "owner": "alice", "tenant": "alpha", "secret": "DOC_43_GONE", "gone_status": 410},
        "44": {"id": "44", "owner": "alice", "tenant": "alpha", "secret": "DOC_44_STILL_ALIVE"},
        "45": {"id": "45", "owner": "bob", "tenant": "beta", "secret": "DOC_45_SINGLE_ACTOR"},
    }
    gone_ids: set[str] = set()
    bob_revoked_44 = {"revoked": False}
    seen_get_actors: list[tuple[str, str, str]] = []

    class _DeleteHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _actor_from_auth(self) -> str:
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer tok-alice":
                return "alice"
            if auth == "Bearer tok-bob":
                return "bob"
            if auth == "Bearer tok-charlie":
                return "charlie"
            return "anon"

        def _send_json(self, status: int, obj: Any) -> None:
            payload = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            actor = self._actor_from_auth()
            ua = self.headers.get("User-Agent", "")
            path = urlsplit(self.path).path
            seen_get_actors.append((path, actor, ua))
            doc_id = path.rsplit("/", 1)[-1]
            if doc_id in gone_ids:
                self._send_json(410, {"error": "gone"})
                return
            doc = docs.get(doc_id)
            if not doc:
                self._send_json(404, {"error": "not_found"})
                return
            if actor == "anon":
                self._send_json(401, {"error": "unauthorized"})
                return
            if actor == "charlie":
                self._send_json(403, {"error": "forbidden"})
                return
            self._send_json(200, doc)

        def do_DELETE(self) -> None:
            actor = self._actor_from_auth()
            path = urlsplit(self.path).path
            doc_id = path.rsplit("/", 1)[-1]
            if actor == "anon":
                self._send_json(401, {"error": "unauthorized"})
                return
            if actor == "charlie":
                self._send_json(403, {"error": "forbidden"})
                return
            if doc_id in gone_ids:
                self._send_json(410, {"error": "already_gone"})
                return
            if doc_id == "44":
                # Simulate a bogus DELETE that does NOT delete the resource for alice,
                # only returns 404 to bob on replay!
                if not bob_revoked_44["revoked"]:
                    bob_revoked_44["revoked"] = True
                    self._send_json(200, {"deleted": True, "id": "44"})
                else:
                    self._send_json(404, {"error": "not_found_for_bob"})
                return
            doc = docs.pop(doc_id, None)
            if doc is None:
                self._send_json(404, {"error": "not_found"})
                return
            if doc.get("gone_status") == 410:
                gone_ids.add(doc_id)
            self._send_json(200, {"deleted": True, "id": doc_id})

    base_url, srv = _start_server(_DeleteHandler)
    accounts = [
        {"alias": "alice", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-alice"},
        {"alias": "bob", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-bob"},
        {"alias": "charlie", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-charlie"},
    ]
    actor_meta = {a["alias"]: {"role": a["role"], "tenant": a["tenant"]} for a in accounts}
    store, _, client, oracle = _make_oracle_env(tmp_path, base_url, accounts=accounts)
    try:
        # 1. Positive BOLA DELETE -> 404 on replay -> fresh owner GET returns 404 -> VERIFIED!
        alice_get_42 = client.request(method="GET", url="/api/v1/docs/42", actor="alice")
        assert alice_get_42["status"] == 200
        charlie_ctrl_42 = client.request(method="DELETE", url="/api/v1/docs/42", actor="charlie")
        assert charlie_ctrl_42["status"] == 403
        bob_del_42 = client.request(method="DELETE", url="/api/v1/docs/42", actor="bob")
        assert bob_del_42["status"] == 200

        seen_get_actors.clear()
        v_del = oracle.verify(
            canonical_class="bola",
            primary_proof=bob_del_42,
            proof_receipts=[bob_del_42],
            control_receipts=[charlie_ctrl_42, alice_get_42],
            evidence_value="deleted",
            actor_meta_map=actor_meta,
        )
        assert v_del.verified is True
        assert v_del.verdict == "VERIFIED"
        assert v_del.stages["stage3_clean_replay"] == "passed_delete_persistence"
        fresh_rec = store.get(v_del.clean_replay_receipt_id)
        assert fresh_rec["method"] == "GET"
        assert fresh_rec["actor"] == "alice"
        assert fresh_rec["status"] == 404
        assert seen_get_actors == [("/api/v1/docs/42", "alice", DEFAULT_BROWSER_USER_AGENT)]

        # 2. Positive 410 Gone DELETE persistence check.
        alice_get_43 = client.request(method="GET", url="/api/v1/docs/43", actor="alice")
        assert alice_get_43["status"] == 200
        bob_del_43 = client.request(method="DELETE", url="/api/v1/docs/43", actor="bob")
        assert bob_del_43["status"] == 200
        v_410 = oracle.verify(
            canonical_class="bola",
            primary_proof=bob_del_43,
            proof_receipts=[bob_del_43],
            control_receipts=[charlie_ctrl_42],
            evidence_value="deleted",
            actor_meta_map=actor_meta,
        )
        assert v_410.verified is True
        assert v_410.stages["stage3_clean_replay"] == "passed_delete_persistence"
        assert store.get(v_410.clean_replay_receipt_id)["status"] == 410

        # 3. Single-actor DELETE persistence (only p_actor had a prior 2xx GET, e.g. arbitrary_file_delete).
        bob_get_45 = client.request(method="GET", url="/api/v1/docs/45", actor="bob")
        assert bob_get_45["status"] == 200
        anon_ctrl_45 = client.request(method="DELETE", url="/api/v1/docs/45", actor="anon")
        assert anon_ctrl_45["status"] == 401
        bob_del_45 = client.request(method="DELETE", url="/api/v1/docs/45", actor="bob")
        assert bob_del_45["status"] == 200
        v_single = oracle.verify(
            canonical_class="path_traversal",
            primary_proof=bob_del_45,
            proof_receipts=[bob_del_45],
            control_receipts=[anon_ctrl_45],
            evidence_value="deleted",
        )
        assert v_single.verified is True
        assert v_single.stages["stage3_clean_replay"] == "passed_delete_persistence"
        assert store.get(v_single.clean_replay_receipt_id)["actor"] == "bob"

        # 4. Negative: resource was NOT actually deleted (owner fresh GET still returns 200) -> REFUTED!
        alice_get_44 = client.request(method="GET", url="/api/v1/docs/44", actor="alice")
        assert alice_get_44["status"] == 200
        bob_del_44 = client.request(method="DELETE", url="/api/v1/docs/44", actor="bob")
        assert bob_del_44["status"] == 200
        v_alive = oracle.verify(
            canonical_class="bola",
            primary_proof=bob_del_44,
            proof_receipts=[bob_del_44],
            control_receipts=[charlie_ctrl_42],
            evidence_value="44",
            actor_meta_map=actor_meta,
        )
        assert v_alive.verified is False
        assert v_alive.verdict == "REFUTED"
        assert v_alive.stages["stage3_clean_replay"] == "failed_status_404"

        # 5. Negative: no earlier 2xx GET existed on path -> REFUTED!
        fake_del_999 = store.record(
            actor="bob",
            method="DELETE",
            url=f"{base_url}/api/v1/docs/999",
            path="/api/v1/docs/999",
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"deleted":true,"id":"999"}',
            response_text='{"deleted":true,"id":"999"}',
        )
        v_no_prior = oracle.verify(
            canonical_class="bola",
            primary_proof=fake_del_999,
            proof_receipts=[fake_del_999],
            control_receipts=[charlie_ctrl_42],
            evidence_value="deleted",
            actor_meta_map=actor_meta,
        )
        assert v_no_prior.verified is False
        assert v_no_prior.verdict == "REFUTED"
        assert v_no_prior.stages["stage3_clean_replay"] == "failed_status_404"
    finally:
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 4. Generalized OOB Callback Verification Classes
# ---------------------------------------------------------------------------


def test_generalized_oob_callback_verification_for_xxe_ssti_and_command_injection(tmp_path: Path) -> None:
    assert _OOB_ELIGIBLE_CLASSES == frozenset({"ssrf", "xxe", "ssti", "command_injection"})

    class _OOBTargetHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _send_json(self, status: int, obj: Any) -> None:
            payload = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def _trigger_callback_if_requested(self, text: str) -> None:
            import re

            if "NO_EXEC" in text:
                return
            match = re.search(r"http://127\.0\.0\.1:\d+/cb/[A-Za-z0-9_-]+", text)
            if match:
                cb_url = match.group(0)
                try:
                    requests.get(cb_url, timeout=2.0)
                except Exception:
                    pass

        def do_POST(self) -> None:
            raw_len = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(raw_len).decode("utf-8", errors="replace") if raw_len > 0 else ""
            self._trigger_callback_if_requested(body)
            # Identical blind 200 response for both payload and benign control!
            self._send_json(200, {"status": "accepted"})

        def do_GET(self) -> None:
            qs = parse_qs(urlsplit(self.path).query)
            tpl = (qs.get("tpl") or [""])[0]
            self._trigger_callback_if_requested(tpl)
            self._send_json(200, {"rendered": "ok"})

    base_url, srv = _start_server(_OOBTargetHandler)
    oob = LoopbackCallbackServer().start()
    store, _, client, oracle = _make_oracle_env(tmp_path, base_url, oob_server=oob)
    try:
        # 1. Blind XXE (POST) with real callback hit -> VERIFIED!
        tok_xxe = oob.create_token(label="xxe-hit")
        xml_payload = f'<!DOCTYPE r [<!ENTITY x SYSTEM "{tok_xxe["url"]}">]><r>&x;</r>'
        xxe_proof = client.request(
            method="POST",
            url="/api/xml",
            actor="alice",
            headers={"Content-Type": "application/xml"},
            raw_body=xml_payload,
        )
        xxe_ctrl = client.request(
            method="POST",
            url="/api/xml",
            actor="alice",
            headers={"Content-Type": "application/xml"},
            raw_body="<r>benign</r>",
        )
        assert oob.poll(tok_xxe["token"])["hit_count"] == 1
        v_xxe = oracle.verify(
            canonical_class="xxe",
            primary_proof=xxe_proof,
            proof_receipts=[xxe_proof],
            control_receipts=[xxe_ctrl],
            evidence_value=tok_xxe["token"],
        )
        assert v_xxe.verified is True
        assert v_xxe.stages["stage1_control"] == "passed_oob_callback"
        assert v_xxe.stages["stage2_diff"] == "passed_oob_callback"
        assert v_xxe.stages["stage3_clean_replay"] == "passed_oob_verified"

        # 2. Blind XXE with 0 callback hits -> REFUTED!
        tok_xxe_zero = oob.create_token(label="xxe-zero")
        xxe_zero_proof = client.request(
            method="POST",
            url="/api/xml",
            actor="alice",
            headers={"Content-Type": "application/xml"},
            raw_body=f'<!-- NO_EXEC --><!DOCTYPE r [<!ENTITY x SYSTEM "{tok_xxe_zero["url"]}">]><r/>',
        )
        v_xxe_zero = oracle.verify(
            canonical_class="xxe",
            primary_proof=xxe_zero_proof,
            proof_receipts=[xxe_zero_proof],
            control_receipts=[xxe_ctrl],
            evidence_value=tok_xxe_zero["token"],
        )
        assert v_xxe_zero.verified is False
        assert v_xxe_zero.verdict == "REFUTED"
        assert v_xxe_zero.stages["stage1_control"] == "failed_oob_zero_hits"
        assert "0 hits" in v_xxe_zero.reason

        # 3. Blind SSTI (GET) with OOB hit -> replays GET and verifies via passed_oob_verified!
        tok_ssti = oob.create_token(label="ssti-hit")
        ssti_proof = client.request(
            method="GET",
            url=f"/api/render?tpl={{{{fetch('{tok_ssti['url']}')}}}}",
            actor="alice",
        )
        ssti_ctrl = client.request(method="GET", url="/api/render?tpl=hello", actor="alice")
        assert oob.poll(tok_ssti["token"])["hit_count"] >= 1
        v_ssti = oracle.verify(
            canonical_class="ssti",
            primary_proof=ssti_proof,
            proof_receipts=[ssti_proof],
            control_receipts=[ssti_ctrl],
            evidence_value=tok_ssti["token"],
        )
        assert v_ssti.verified is True
        assert v_ssti.stages["stage1_control"] == "passed_oob_callback"
        assert v_ssti.stages["stage2_diff"] == "passed_oob_callback"
        assert v_ssti.stages["stage3_clean_replay"] == "passed_oob_verified"

        # 4. Blind command_injection (POST) with OOB hit and zero-hit refutation.
        tok_cmd = oob.create_token(label="cmd-hit")
        cmd_proof = client.request(
            method="POST",
            url="/api/ping",
            actor="alice",
            json_body={"host": f"127.0.0.1; curl {tok_cmd['url']}"},
        )
        cmd_ctrl = client.request(method="POST", url="/api/ping", actor="alice", json_body={"host": "127.0.0.1"})
        v_cmd = oracle.verify(
            canonical_class="command_injection",
            primary_proof=cmd_proof,
            proof_receipts=[cmd_proof],
            control_receipts=[cmd_ctrl],
            evidence_value=tok_cmd["token"],
        )
        assert v_cmd.verified is True
        assert v_cmd.stages["stage3_clean_replay"] == "passed_oob_verified"

        tok_cmd_zero = oob.create_token(label="cmd-zero")
        cmd_zero = client.request(
            method="POST",
            url="/api/ping",
            actor="alice",
            json_body={"host": f"NO_EXEC {tok_cmd_zero['url']}"},
        )
        v_cmd_zero = oracle.verify(
            canonical_class="command_injection",
            primary_proof=cmd_zero,
            proof_receipts=[cmd_zero],
            control_receipts=[cmd_ctrl],
            evidence_value=tok_cmd_zero["token"],
        )
        assert v_cmd_zero.verified is False
        assert v_cmd_zero.stages["stage1_control"] == "failed_oob_zero_hits"

        # 5. SSRF zero-hit preserves exact existing message prefix.
        tok_ssrf_zero = oob.create_token(label="ssrf-zero")
        ssrf_zero = client.request(
            method="POST",
            url="/api/hook",
            actor="alice",
            json_body={"url": f"NO_EXEC {tok_ssrf_zero['url']}"},
        )
        v_ssrf_zero = oracle.verify(
            canonical_class="ssrf",
            primary_proof=ssrf_zero,
            proof_receipts=[ssrf_zero],
            control_receipts=[cmd_ctrl],
            evidence_value=tok_ssrf_zero["token"],
        )
        assert v_ssrf_zero.verified is False
        assert v_ssrf_zero.reason.startswith("SSRF callback claim rejected:")
    finally:
        oob.close()
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 5. Expanded Canonical Finding Classes, CORS Header Diff/Replay & JWT Weakness
# ---------------------------------------------------------------------------


def test_canonical_class_aliases_and_input_diff_classes() -> None:
    expected_aliases = {
        "cors": "cors_misconfiguration",
        "cors_reflection": "cors_misconfiguration",
        "arbitrary_origin_cors": "cors_misconfiguration",
        "xml_external_entity": "xxe",
        "blind_xxe": "xxe",
        "unrestricted_file_upload": "file_upload",
        "arbitrary_file_upload": "file_upload",
        "file_overwrite": "file_upload",
        "weak_jwt": "jwt_weakness",
        "jwt_none_alg": "jwt_weakness",
        "jwt_forgery": "jwt_weakness",
        "token_weakness": "jwt_weakness",
        "os_command_injection": "command_injection",
        "rce": "command_injection",
        "lfi": "path_traversal",
        "directory_traversal": "path_traversal",
        "arbitrary_file_read": "path_traversal",
        "arbitrary_file_delete": "path_traversal",
    }
    for alias, canonical in expected_aliases.items():
        assert _CLASS_ALIASES[alias] == canonical
        assert normalize_vuln_class(alias) == canonical
        assert normalize_vuln_class(alias.replace("_", "-").upper()) == canonical
        assert normalize_vuln_class(alias.replace("_", " ")) == canonical

    for cls_name in ("cors_misconfiguration", "xxe", "file_upload", "jwt_weakness", "command_injection"):
        assert cls_name in _INPUT_DIFF_CLASSES


def test_cors_misconfiguration_header_only_diff_and_clean_replay_verification(tmp_path: Path) -> None:
    cors_mode = {"reflect": True}

    class _CORSHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            origin = self.headers.get("Origin", "")
            payload = json.dumps({"user": "alice", "email": "alice@example.test"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            if path == "/api/profile/reflect" and origin and cors_mode["reflect"]:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            elif path == "/api/profile/wildcard" and origin:
                self.send_header("Access-Control-Allow-Origin", "*")
            elif path == "/api/profile/fixed-origin" and origin:
                self.send_header("Access-Control-Allow-Origin", "https://trusted.example")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

    base_url, srv = _start_server(_CORSHandler)
    store, _, client, oracle = _make_oracle_env(tmp_path, base_url)
    try:
        # 1. Identical JSON body, differing ONLY in CORS headers -> VERIFIED!
        evil_origin = "https://evil.example"
        cors_proof = client.request(
            method="GET",
            url="/api/profile/reflect",
            actor="alice",
            headers={"Origin": evil_origin},
        )
        cors_ctrl = client.request(
            method="GET",
            url="/api/profile/reflect",
            actor="alice",
        )
        assert cors_proof["body"] == cors_ctrl["body"]
        assert cors_proof["response_headers"]["Access-Control-Allow-Origin"] == evil_origin
        assert "Access-Control-Allow-Origin" not in cors_ctrl["response_headers"]

        v_reflect = oracle.verify(
            canonical_class="cors_misconfiguration",
            primary_proof=cors_proof,
            proof_receipts=[cors_proof],
            control_receipts=[cors_ctrl],
            evidence_value=evil_origin,
        )
        assert v_reflect.verified is True
        assert v_reflect.verdict == "VERIFIED"
        assert v_reflect.stages["stage1_control"] == "passed"
        assert v_reflect.stages["stage2_diff"] == "passed"
        assert v_reflect.stages["stage3_clean_replay"] == "passed"

        # 2. Wildcard '*' ACAO on origin request vs absent on control -> VERIFIED!
        wild_proof = client.request(
            method="GET",
            url="/api/profile/wildcard",
            actor="alice",
            headers={"Origin": evil_origin},
        )
        wild_ctrl = client.request(method="GET", url="/api/profile/wildcard", actor="alice")
        v_wild = oracle.verify(
            canonical_class="cors_misconfiguration",
            primary_proof=wild_proof,
            proof_receipts=[wild_proof],
            control_receipts=[wild_ctrl],
            evidence_value="*",
        )
        assert v_wild.verified is True
        assert v_wild.stages["stage3_clean_replay"] == "passed"

        # 3. Negative: fixed trusted origin (does NOT match reflected evil origin or '*') -> REFUTED in Stage 3!
        fixed_proof = client.request(
            method="GET",
            url="/api/profile/fixed-origin",
            actor="alice",
            headers={"Origin": evil_origin},
        )
        fixed_ctrl = client.request(method="GET", url="/api/profile/fixed-origin", actor="alice")
        v_fixed = oracle.verify(
            canonical_class="cors_misconfiguration",
            primary_proof=fixed_proof,
            proof_receipts=[fixed_proof],
            control_receipts=[fixed_ctrl],
            evidence_value="https://trusted.example",
        )
        assert v_fixed.verified is False
        assert v_fixed.verdict == "REFUTED"
        assert v_fixed.stages["stage3_clean_replay"] == "failed_cors_origin"

        # 4. Negative: reflection disappears on Stage 3 clean replay -> REFUTED!
        cors_mode["reflect"] = False
        v_flaky = oracle.verify(
            canonical_class="cors_misconfiguration",
            primary_proof=cors_proof,
            proof_receipts=[cors_proof],
            control_receipts=[cors_ctrl],
            evidence_value=evil_origin,
        )
        assert v_flaky.verified is False
        assert v_flaky.verdict == "REFUTED"
        assert v_flaky.stages["stage3_clean_replay"] == "failed_cors_origin"

        # 5. Negative: identical CORS headers + identical body -> DECEPTION_DETECTED in Stage 1!
        cors_mode["reflect"] = True
        dup_ctrl = client.request(
            method="GET",
            url="/api/profile/reflect",
            actor="alice",
            headers={"Origin": evil_origin},
            force=True,
        )
        v_dup = oracle.verify(
            canonical_class="cors_misconfiguration",
            primary_proof=cors_proof,
            proof_receipts=[cors_proof],
            control_receipts=[dup_ctrl],
            evidence_value=evil_origin,
        )
        assert v_dup.verified is False
        assert v_dup.verdict == "DECEPTION_DETECTED"
        assert v_dup.stages["stage1_control"] == "deception_identical_control"
    finally:
        client.close()
        _stop_server(srv)


def test_jwt_weakness_input_diff_and_redacted_auth_override_verification(tmp_path: Path) -> None:
    forged_none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."

    class _JWTHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
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
            auth = self.headers.get("Authorization", "")
            qs = parse_qs(parsed.query)
            q_tok = (qs.get("token") or [""])[0]

            if parsed.path == "/api/admin/jwt-query":
                if q_tok == forged_none_jwt:
                    self._send_json(200, {"role": "admin", "secret": "JWT_QUERY_ADMIN_SECRET_88"})
                else:
                    self._send_json(401, {"error": "invalid_token"})
                return

            if parsed.path == "/api/admin/jwt-header":
                if auth == f"Bearer {forged_none_jwt}":
                    self._send_json(200, {"role": "admin", "secret": "JWT_HEADER_ADMIN_SECRET_99"})
                else:
                    self._send_json(401, {"error": "invalid_token"})
                return

            if parsed.path == "/api/public/no-jwt-check":
                self._send_json(200, {"status": "public_info", "note": "PUBLIC_TEXT_123"})
                return

            self._send_json(404, {"error": "not_found"})

    base_url, srv = _start_server(_JWTHandler)
    store, _, client, oracle = _make_oracle_env(tmp_path, base_url)
    try:
        # 1. Forged JWT in query param -> full clean replay reproduces 200 + secret -> VERIFIED!
        q_proof = client.request(
            method="GET",
            url=f"/api/admin/jwt-query?token={forged_none_jwt}",
            actor="anon",
        )
        q_ctrl = client.request(
            method="GET",
            url="/api/admin/jwt-query?token=invalid.jwt.sig",
            actor="anon",
        )
        assert q_proof["status"] == 200
        assert q_ctrl["status"] == 401
        v_q = oracle.verify(
            canonical_class="jwt_weakness",
            primary_proof=q_proof,
            proof_receipts=[q_proof],
            control_receipts=[q_ctrl],
            evidence_value="JWT_QUERY_ADMIN_SECRET_88",
        )
        assert v_q.verified is True
        assert v_q.stages["stage1_control"] == "passed"
        assert v_q.stages["stage2_diff"] == "passed"
        assert v_q.stages["stage3_clean_replay"] == "passed"

        # 2. Forged alg=none JWT in overridden Authorization header (redacted by ReceiptStore):
        #    Stage 1/2 verify 200 vs 401 diff, Stage 3 confirms live 401 rejection without forged header!
        h_proof = client.request(
            method="GET",
            url="/api/admin/jwt-header",
            actor="anon",
            headers={"Authorization": f"Bearer {forged_none_jwt}"},
        )
        h_ctrl = client.request(
            method="GET",
            url="/api/admin/jwt-header",
            actor="anon",
            headers={"Authorization": "Bearer invalid.jwt.signature"},
        )
        assert h_proof["status"] == 200
        assert "<REDACTED:" in h_proof["request_headers"]["Authorization"]
        assert h_ctrl["status"] == 401
        v_h = oracle.verify(
            canonical_class="jwt_weakness",
            primary_proof=h_proof,
            proof_receipts=[h_proof],
            control_receipts=[h_ctrl],
            evidence_value="JWT_HEADER_ADMIN_SECRET_99",
        )
        assert v_h.verified is True
        assert v_h.verdict == "VERIFIED"
        assert v_h.stages["stage3_clean_replay"] == "passed_redacted_auth_override"

        # 3. Negative: public endpoint ignoring JWT returns identical 200 for forged and invalid -> DECEPTION_DETECTED!
        pub_proof = client.request(
            method="GET",
            url="/api/public/no-jwt-check",
            actor="anon",
            headers={"Authorization": f"Bearer {forged_none_jwt}"},
        )
        pub_ctrl = client.request(
            method="GET",
            url="/api/public/no-jwt-check",
            actor="anon",
            headers={"Authorization": "Bearer invalid.jwt.signature"},
        )
        v_pub = oracle.verify(
            canonical_class="jwt_weakness",
            primary_proof=pub_proof,
            proof_receipts=[pub_proof],
            control_receipts=[pub_ctrl],
            evidence_value="PUBLIC_TEXT_123",
        )
        assert v_pub.verified is False
        assert v_pub.verdict == "DECEPTION_DETECTED"
        assert v_pub.stages["stage1_control"] == "deception_identical_control"
    finally:
        client.close()
        _stop_server(srv)
