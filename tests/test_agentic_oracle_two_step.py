"""Tests for Two-Step Clean Replay Fallback in DifferentialOracle Stage 3."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_oracle import (  # noqa: E402
    DifferentialOracle,
    _find_prior_setup_write_receipt,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import ToolDispatcher  # noqa: E402


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
    max_requests: int = 80,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
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
    )
    return store, client, oracle


def test_find_prior_setup_write_receipt_selection_and_bounds() -> None:
    get_target = {
        "receipt_id": "req-0005",
        "timestamp": "2026-01-01T00:00:05+00:00",
        "method": "GET",
        "url": "http://127.0.0.1:9999/queue/data?session_hash=sess_abc123",
        "path": "/queue/data",
        "query": "session_hash=sess_abc123",
        "status": 200,
    }
    earlier_matching = {
        "receipt_id": "req-0002",
        "timestamp": "2026-01-01T00:00:02+00:00",
        "method": "POST",
        "url": "http://127.0.0.1:9999/queue/join",
        "path": "/queue/join",
        "request_body": '{"session_hash":"sess_abc123","data":["../../etc/passwd"]}',
        "status": 200,
    }
    closer_unrelated = {
        "receipt_id": "req-0004",
        "timestamp": "2026-01-01T00:00:04+00:00",
        "method": "POST",
        "url": "http://127.0.0.1:9999/other/ping",
        "path": "/other/ping",
        "request_body": '{"hello":"world"}',
        "status": 200,
    }
    later_write = {
        "receipt_id": "req-0006",
        "timestamp": "2026-01-01T00:00:06+00:00",
        "method": "POST",
        "url": "http://127.0.0.1:9999/queue/join",
        "path": "/queue/join",
        "request_body": '{"session_hash":"sess_abc123"}',
        "status": 200,
    }
    multipart_write = {
        "receipt_id": "req-0003",
        "timestamp": "2026-01-01T00:00:03+00:00",
        "method": "POST",
        "url": "http://127.0.0.1:9999/queue/join",
        "path": "/queue/join",
        "request_body": 'multipart/form-data {"files":[{"filename":"a.txt"}]}',
        "status": 200,
    }
    failed_write = {
        "receipt_id": "req-0003",
        "timestamp": "2026-01-01T00:00:03+00:00",
        "method": "POST",
        "url": "http://127.0.0.1:9999/queue/join",
        "path": "/queue/join",
        "request_body": '{"session_hash":"sess_abc123"}',
        "status": 500,
    }
    delete_write = {
        "receipt_id": "req-0003",
        "timestamp": "2026-01-01T00:00:03+00:00",
        "method": "DELETE",
        "url": "http://127.0.0.1:9999/queue/join",
        "path": "/queue/join",
        "status": 200,
    }

    # Prefers candidate sharing correlation token + parent path over closer unrelated write,
    # while skipping later writes, multipart writes, 5xx writes, and DELETEs.
    picked = _find_prior_setup_write_receipt(
        get_target,
        [earlier_matching, multipart_write, failed_write, delete_write, closer_unrelated, get_target, later_write],
        None,
    )
    assert picked is earlier_matching

    # Non-GET replay_target returns None immediately.
    assert _find_prior_setup_write_receipt(earlier_matching, [earlier_matching, get_target], None) is None

    # Falls back to closest earlier write in proof_receipts when no token/prefix overlaps.
    fallback = _find_prior_setup_write_receipt(get_target, [closer_unrelated, get_target], None)
    assert fallback is closer_unrelated

    # Timestamp fallback works when receipts do not have req-NNNN sequence IDs.
    ts_setup = {
        "receipt_id": "custom-a",
        "timestamp": "2026-01-01T00:00:01Z",
        "method": "PUT",
        "url": "http://127.0.0.1:9999/jobs/setup",
        "status": 201,
        "request_body": '{"job":"j99"}',
    }
    ts_get = {
        "receipt_id": "custom-b",
        "timestamp": "2026-01-01T00:00:02+00:00",
        "method": "GET",
        "url": "http://127.0.0.1:9999/jobs/result?job=j99",
        "status": 200,
    }
    assert _find_prior_setup_write_receipt(ts_get, [ts_setup, ts_get], None) is ts_setup
    assert _find_prior_setup_write_receipt(ts_get, [ts_get, {**ts_setup, "timestamp": "2026-01-01T00:00:09Z"}], None) is None


def test_two_step_one_shot_queue_sse_workflow_verifies_and_respects_idempotent_fast_path(tmp_path: Path) -> None:
    lock = threading.Lock()
    queues: dict[str, list[str]] = {}
    stats = {"post_join": 0, "get_data": 0, "post_idempotent": 0}

    class _QueueHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            try:
                data = json.loads(raw)
            except ValueError:
                data = {}
            if path == "/queue/join":
                with lock:
                    stats["post_join"] += 1
                    sess = str(data.get("session_hash") or "")
                    payload = str(data.get("path") or "")
                    if payload == "/etc/shadow":
                        queues.setdefault(sess, []).append('data: {"msg":"process_completed","output":"ROOT_SECRET_HASH_99"}\n\n')
                    else:
                        queues.setdefault(sess, []).append('data: {"msg":"process_completed","output":"benign_readme"}\n\n')
                self._send(200, json.dumps({"event_id": f"evt-{sess}"}).encode("utf-8"), "application/json")
                return
            if path == "/idempotent/setup":
                with lock:
                    stats["post_idempotent"] += 1
                self._send(201, b'{"ok":true}', "application/json")
                return
            self._send(404, b'{"error":"not_found"}', "application/json")

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            qs = parse_qs(parsed.query)
            if parsed.path == "/queue/data":
                sess = (qs.get("session_hash") or [""])[0]
                with lock:
                    stats["get_data"] += 1
                    items = queues.get(sess) or []
                    event = items.pop(0) if items else ""
                # One-shot SSE drain: second standalone GET returns empty 200!
                self._send(200, event.encode("utf-8"), "text/event-stream")
                return
            if parsed.path == "/idempotent/read":
                mode = (qs.get("mode") or ["benign"])[0]
                body = '{"result":"IDEMPOTENT_MARKER_11"}' if mode == "vuln" else '{"result":"clean"}'
                self._send(200, body.encode("utf-8"), "application/json")
                return
            self._send(404, b'{"error":"not_found"}', "application/json")

    base_url, srv = _start_server(_QueueHandler)
    store, client, oracle = _make_oracle_env(tmp_path, base_url)
    try:
        # Control workflow (benign enqueue + drain)
        ctrl_post = client.request(
            method="POST",
            url="/queue/join",
            actor="alice",
            json_body={"session_hash": "ctrl1", "path": "README.md"},
        )
        assert ctrl_post["status"] == 200
        ctrl_get = client.request(method="GET", url="/queue/data?session_hash=ctrl1", actor="alice")
        assert "benign_readme" in ctrl_get["body"]

        # Attack workflow: Step 1 enqueues, Step 2 drains and returns secret
        post_rec = client.request(
            method="POST",
            url="/queue/join",
            actor="alice",
            json_body={"session_hash": "s1", "path": "/etc/shadow"},
        )
        assert post_rec["status"] == 200
        get_rec = client.request(method="GET", url="/queue/data?session_hash=s1", actor="alice")
        assert get_rec["status"] == 200
        assert "ROOT_SECRET_HASH_99" in get_rec["body"]

        # Verify standalone second GET really is drained (empty 200)
        drained_check = client.request(method="GET", url="/queue/data?session_hash=s1", actor="alice", force=True)
        assert drained_check["status"] == 200
        assert drained_check["body"] == ""

        # Case 1: primary_proof = GET, proof_receipts = [post_rec, get_rec]
        joins_before = stats["post_join"]
        verdict = oracle.verify(
            canonical_class="path_traversal",
            primary_proof=get_rec,
            proof_receipts=[post_rec, get_rec],
            control_receipts=[ctrl_get],
            evidence_value="ROOT_SECRET_HASH_99",
        )
        assert verdict.verified is True
        assert verdict.verdict == "VERIFIED"
        assert verdict.stages["stage1_control"] == "passed"
        assert verdict.stages["stage2_diff"] == "passed"
        assert verdict.stages["stage3_clean_replay"] == "passed_two_step_replay"
        assert verdict.stages["stage3_setup_replay_receipt_id"]
        setup_replayed = store.get(verdict.stages["stage3_setup_replay_receipt_id"])
        step2_replayed = store.get(verdict.clean_replay_receipt_id)
        assert setup_replayed["method"] == "POST"
        assert setup_replayed["path"] == "/queue/join"
        assert step2_replayed["method"] == "GET"
        assert step2_replayed["path"] == "/queue/data"
        assert "ROOT_SECRET_HASH_99" in step2_replayed["body"]
        assert stats["post_join"] == joins_before + 1

        # Case 2: primary_proof = POST, proof_receipts = [post_rec, get_rec] also works!
        joins_before_2 = stats["post_join"]
        verdict_from_post = oracle.verify(
            canonical_class="path_traversal",
            primary_proof=post_rec,
            proof_receipts=[post_rec, get_rec],
            control_receipts=[ctrl_get],
            evidence_value="ROOT_SECRET_HASH_99",
        )
        assert verdict_from_post.verified is True
        assert verdict_from_post.stages["stage3_clean_replay"] == "passed_two_step_replay"
        assert stats["post_join"] == joins_before_2 + 1

        # Case 3: Normal idempotent GET succeeds on single-step replay with ZERO setup replay cost!
        idem_post = client.request(method="POST", url="/idempotent/setup", actor="alice", json_body={"k": "v"})
        idem_get = client.request(method="GET", url="/idempotent/read?mode=vuln", actor="alice")
        idem_ctrl = client.request(method="GET", url="/idempotent/read?mode=benign", actor="alice")
        post_count_before = stats["post_idempotent"]
        verdict_idem = oracle.verify(
            canonical_class="path_traversal",
            primary_proof=idem_get,
            proof_receipts=[idem_post, idem_get],
            control_receipts=[idem_ctrl],
            evidence_value="IDEMPOTENT_MARKER_11",
        )
        assert verdict_idem.verified is True
        assert verdict_idem.stages["stage3_clean_replay"] == "passed"
        assert "stage3_setup_replay_receipt_id" not in verdict_idem.stages
        assert stats["post_idempotent"] == post_count_before
    finally:
        client.close()
        _stop_server(srv)


def test_two_step_one_shot_404_and_410_after_consume_workflows(tmp_path: Path) -> None:
    lock = threading.Lock()
    tokens_404: dict[str, str] = {}
    tokens_410: dict[str, str] = {}
    consumed_410: set[str] = set()

    class _TokenHandler(BaseHTTPRequestHandler):
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

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            data = json.loads(raw) if raw.strip().startswith("{") else {}
            tok_id = str(data.get("id") or "")
            with lock:
                if path == "/tokens":
                    tokens_404[tok_id] = f"ONE_TIME_SECRET_{tok_id}"
                    self._send_json(201, {"created": tok_id})
                    return
                if path == "/tokens-gone":
                    consumed_410.discard(tok_id)
                    tokens_410[tok_id] = f"GONE_SECRET_{tok_id}"
                    self._send_json(201, {"created": tok_id})
                    return
            self._send_json(404, {"error": "not_found"})

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            tok_id = (parse_qs(parsed.query).get("id") or [""])[0]
            with lock:
                if parsed.path == "/tokens/consume":
                    secret = tokens_404.pop(tok_id, None)
                    if secret is None:
                        self._send_json(404, {"error": "token_not_found_or_consumed"})
                        return
                    self._send_json(200, {"id": tok_id, "secret": secret})
                    return
                if parsed.path == "/tokens-gone/consume":
                    secret = tokens_410.pop(tok_id, None)
                    if secret is None:
                        status = 410 if tok_id in consumed_410 else 404
                        self._send_json(status, {"error": "token_gone"})
                        return
                    consumed_410.add(tok_id)
                    self._send_json(200, {"id": tok_id, "secret": secret})
                    return
            self._send_json(404, {"error": "not_found"})

    base_url, srv = _start_server(_TokenHandler)
    store, client, oracle = _make_oracle_env(tmp_path, base_url)
    try:
        # 1. One-shot 404-after-consume workflow
        ctrl_404 = client.request(method="GET", url="/tokens/consume?id=missing", actor="alice")
        assert ctrl_404["status"] == 404

        post_tok = client.request(method="POST", url="/tokens", actor="alice", json_body={"id": "t1"})
        assert post_tok["status"] == 201
        get_tok = client.request(method="GET", url="/tokens/consume?id=t1", actor="alice")
        assert get_tok["status"] == 200
        assert "ONE_TIME_SECRET_t1" in get_tok["body"]

        verdict_404 = oracle.verify(
            canonical_class="auth_bypass",
            primary_proof=get_tok,
            proof_receipts=[post_tok, get_tok],
            control_receipts=[ctrl_404],
            evidence_value="ONE_TIME_SECRET_t1",
        )
        assert verdict_404.verified is True
        assert verdict_404.verdict == "VERIFIED"
        assert verdict_404.stages["stage3_clean_replay"] == "passed_two_step_replay"
        assert store.get(verdict_404.stages["stage3_setup_replay_receipt_id"])["path"] == "/tokens"
        assert "ONE_TIME_SECRET_t1" in store.get(verdict_404.clean_replay_receipt_id)["body"]

        # 2. One-shot 410-after-consume workflow
        post_gone = client.request(method="POST", url="/tokens-gone", actor="alice", json_body={"id": "g1"})
        assert post_gone["status"] == 201
        get_gone = client.request(method="GET", url="/tokens-gone/consume?id=g1", actor="alice")
        assert get_gone["status"] == 200
        assert "GONE_SECRET_g1" in get_gone["body"]

        verdict_410 = oracle.verify(
            canonical_class="auth_bypass",
            primary_proof=get_gone,
            proof_receipts=[post_gone, get_gone],
            control_receipts=[ctrl_404],
            evidence_value="GONE_SECRET_g1",
        )
        assert verdict_410.verified is True
        assert verdict_410.stages["stage3_clean_replay"] == "passed_two_step_replay"
        assert "GONE_SECRET_g1" in store.get(verdict_410.clean_replay_receipt_id)["body"]
    finally:
        client.close()
        _stop_server(srv)


def test_two_step_negative_cases_hallucination_missing_setup_multipart_and_budget(tmp_path: Path) -> None:
    lock = threading.Lock()
    queues: dict[str, list[str]] = {}
    stats = {"post_join": 0, "post_upload": 0, "bad_multipart": 0}

    class _NegHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length) if length > 0 else b""
            if path == "/queue/join":
                data = json.loads(body.decode("utf-8", errors="replace") or "{}")
                sess = str(data.get("session_hash") or "")
                with lock:
                    stats["post_join"] += 1
                    queues.setdefault(sess, []).append('{"output":"REAL_SERVER_VALUE"}')
                self._send(200, json.dumps({"queued": sess}).encode("utf-8"))
                return
            if path == "/upload":
                ctype = self.headers.get("Content-Type", "")
                with lock:
                    stats["post_upload"] += 1
                    if not ctype.lower().startswith("multipart/form-data") or "boundary=" not in ctype:
                        stats["bad_multipart"] += 1
                        self._send(400, b'{"error":"bad_multipart"}')
                        return
                    boundary = ctype.split("boundary=", 1)[1].strip()
                    if f"--{boundary}".encode() not in body:
                        stats["bad_multipart"] += 1
                        self._send(400, b'{"error":"corrupt_multipart"}')
                        return
                    queues.setdefault("up1", []).append('{"output":"UPLOADED_ONE_SHOT_MARKER"}')
                self._send(201, b'{"uploaded":"up1"}')
                return
            self._send(404, b'{"error":"not_found"}')

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            qs = parse_qs(parsed.query)
            if parsed.path == "/queue/data":
                sess = (qs.get("session_hash") or [""])[0]
                with lock:
                    items = queues.get(sess) or []
                    payload = items.pop(0) if items else ""
                self._send(200, payload.encode("utf-8"))
                return
            if parsed.path == "/upload/result":
                key = (qs.get("id") or [""])[0]
                with lock:
                    items = queues.get(key) or []
                    payload = items.pop(0) if items else ""
                if not payload:
                    self._send(404, b'{"error":"already_consumed"}')
                    return
                self._send(200, payload.encode("utf-8"))
                return
            self._send(404, b'{"error":"not_found"}')

    base_url, srv = _start_server(_NegHandler)
    store, client, oracle = _make_oracle_env(tmp_path, base_url)
    try:
        ctrl_get = client.request(method="GET", url="/queue/data?session_hash=empty", actor="alice")
        assert ctrl_get["status"] == 200
        assert ctrl_get["body"] == ""

        # 1. Negative: Hallucinated evidence_value not returned even after fresh 2-step replay -> REFUTED!
        post_real = client.request(
            method="POST",
            url="/queue/join",
            actor="alice",
            json_body={"session_hash": "s_halluc"},
        )
        fake_get = store.record(
            actor="alice",
            method="GET",
            url=f"{base_url}/queue/data?session_hash=s_halluc",
            path="/queue/data",
            query="session_hash=s_halluc",
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"output":"HALLUCINATED_SECRET_XYZ"}',
            response_text='{"output":"HALLUCINATED_SECRET_XYZ"}',
        )
        # Drain the queued item so first GET is empty, triggering two-step replay.
        client.request(method="GET", url="/queue/data?session_hash=s_halluc", actor="alice", force=True)
        joins_before_halluc = stats["post_join"]
        v_halluc = oracle.verify(
            canonical_class="path_traversal",
            primary_proof=fake_get,
            proof_receipts=[post_real, fake_get],
            control_receipts=[ctrl_get],
            evidence_value="HALLUCINATED_SECRET_XYZ",
        )
        assert stats["post_join"] == joins_before_halluc + 1  # Two-step ran...
        assert v_halluc.verified is False
        assert v_halluc.verdict == "REFUTED"
        assert v_halluc.stages["stage3_clean_replay"] == "failed_missing_evidence"

        # 2. Negative: Unrelated GET with NO prior write in proof_receipts (even though store has POST /queue/join!)
        #    MUST NOT guess writes from ReceiptStore and MUST remain REFUTED.
        post_stored = client.request(
            method="POST",
            url="/queue/join",
            actor="alice",
            json_body={"session_hash": "s_only_get"},
        )
        assert post_stored["status"] == 200
        get_only = client.request(method="GET", url="/queue/data?session_hash=s_only_get", actor="alice")
        assert "REAL_SERVER_VALUE" in get_only["body"]

        joins_before_only_get = stats["post_join"]
        v_no_setup = oracle.verify(
            canonical_class="path_traversal",
            primary_proof=get_only,
            proof_receipts=[get_only],  # post_stored intentionally omitted!
            control_receipts=[ctrl_get],
            evidence_value="REAL_SERVER_VALUE",
        )
        assert stats["post_join"] == joins_before_only_get  # Never touched POST /queue/join!
        assert v_no_setup.verified is False
        assert v_no_setup.verdict == "REFUTED"
        assert v_no_setup.stages["stage3_clean_replay"] == "failed_missing_evidence"

        # 3. Negative: Multipart setup write is safely skipped (never sent as corrupt raw summary).
        mp_post = client.request(
            method="POST",
            url="/upload",
            actor="alice",
            files=[{
                "field": "file",
                "filename": "note.txt",
                "content_type": "text/plain",
                "content": "hello",
            }],
        )
        assert mp_post["status"] == 201
        mp_get = client.request(method="GET", url="/upload/result?id=up1", actor="alice")
        assert mp_get["status"] == 200
        assert "UPLOADED_ONE_SHOT_MARKER" in mp_get["body"]

        uploads_before = stats["post_upload"]
        v_mp = oracle.verify(
            canonical_class="file_upload",
            primary_proof=mp_get,
            proof_receipts=[mp_post, mp_get],
            control_receipts=[ctrl_get],
            evidence_value="UPLOADED_ONE_SHOT_MARKER",
        )
        assert stats["post_upload"] == uploads_before
        assert stats["bad_multipart"] == 0
        assert v_mp.verified is False
        assert v_mp.verdict == "REFUTED"
        assert v_mp.stages["stage3_clean_replay"] == "failed_status_404"

        # 4. Negative: Insufficient budget (< 2 remaining after single-step GET) does not send orphaned POST.
        _, tight_client, tight_oracle = _make_oracle_env(tmp_path / "tight", base_url, max_requests=4)
        try:
            t_ctrl = tight_client.request(method="GET", url="/queue/data?session_hash=empty", actor="alice")
            t_post = tight_client.request(
                method="POST",
                url="/queue/join",
                actor="alice",
                json_body={"session_hash": "s_budget"},
            )
            t_get = tight_client.request(method="GET", url="/queue/data?session_hash=s_budget", actor="alice")
            # Budget used = 3 of 4; 1 left for single-step GET replay, 0 left after -> cannot do 2-step.
            joins_before_budget = stats["post_join"]
            v_budget = tight_oracle.verify(
                canonical_class="path_traversal",
                primary_proof=t_get,
                proof_receipts=[t_post, t_get],
                control_receipts=[t_ctrl],
                evidence_value="REAL_SERVER_VALUE",
            )
            assert stats["post_join"] == joins_before_budget
            assert v_budget.verified is False
            assert v_budget.verdict == "REFUTED"
            assert v_budget.stages["stage3_clean_replay"] == "failed_missing_evidence"
        finally:
            tight_client.close()
    finally:
        client.close()
        _stop_server(srv)


def test_two_step_stored_xss_enforces_html_verbatim_check_on_step2(tmp_path: Path) -> None:
    lock = threading.Lock()
    inbox: dict[str, list[str]] = {}
    escape_on_replay = {"enabled": False}

    class _OneShotXSSHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or "0")
            data = json.loads(self.rfile.read(length).decode("utf-8", errors="replace") or "{}")
            sid = str(data.get("sid") or "")
            msg = str(data.get("msg") or "")
            with lock:
                inbox.setdefault(sid, []).append(msg)
            self._send(201, b'{"ok":true}', "application/json")

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            sid = (parse_qs(parsed.query).get("sid") or [""])[0]
            with lock:
                items = inbox.get(sid) or []
                msg = items.pop(0) if items else ""
                do_escape = escape_on_replay["enabled"]
            rendered = html.escape(msg) if do_escape else msg
            doc = f"<html><body><div id='flash'>{rendered}</div></body></html>"
            self._send(200, doc.encode("utf-8"), "text/html; charset=utf-8")

    base_url, srv = _start_server(_OneShotXSSHandler)
    _store, client, oracle = _make_oracle_env(tmp_path, base_url)
    try:
        base_get = client.request(method="GET", url="/flash?sid=x1", actor="alice")
        post_xss = client.request(
            method="POST",
            url="/flash",
            actor="alice",
            json_body={"sid": "x1", "msg": "<svg/onload=1>"},
        )
        get_xss = client.request(method="GET", url="/flash?sid=x1", actor="alice", force=True)
        assert "<svg/onload=1>" in get_xss["body"]

        # Positive: one-shot flash message reproduces verbatim HTML via 2-step replay -> VERIFIED!
        v_ok = oracle.verify(
            canonical_class="stored_xss",
            primary_proof=post_xss,
            proof_receipts=[post_xss, get_xss],
            control_receipts=[base_get],
            evidence_value="<svg/onload=1>",
        )
        assert v_ok.verified is True
        assert v_ok.stages["stage3_clean_replay"] == "passed_two_step_replay"

        # Negative: if replay escapes HTML on step 2 -> REFUTED (anti-hallucination preserved)!
        escape_on_replay["enabled"] = True
        v_esc = oracle.verify(
            canonical_class="stored_xss",
            primary_proof=post_xss,
            proof_receipts=[post_xss, get_xss],
            control_receipts=[base_get],
            evidence_value="<svg/onload=1>",
        )
        assert v_esc.verified is False
        assert v_esc.verdict == "REFUTED"
        assert v_esc.stages["stage3_clean_replay"] == "failed_missing_evidence"
    finally:
        client.close()
        _stop_server(srv)


def test_tool_dispatcher_record_finding_preserves_two_step_setup_receipt(tmp_path: Path) -> None:
    """ToolDispatcher._tool_record_finding preserves cross-endpoint setup write receipts for two-step replay."""
    lock = threading.Lock()
    tokens: dict[str, bool] = {}

    class _ShareHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _send(self, status: int, payload: Any) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if urlsplit(self.path).path != "/api/share":
                self._send(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length") or "0")
            data = json.loads(self.rfile.read(length).decode("utf-8", errors="replace") or "{}")
            code = str(data.get("code") or "c1")
            with lock:
                tokens[code] = False
            self._send(200, {"code": code})

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path != "/api/consume":
                self._send(404, {"error": "not found"})
                return
            code = (parse_qs(parsed.query).get("code") or [""])[0]
            with lock:
                if code not in tokens:
                    self._send(404, {"error": "missing"})
                    return
                if tokens[code]:
                    self._send(410, {"error": "consumed"})
                    return
                tokens[code] = True
            self._send(200, {"secret": "ONESHOT_TOOL_SECRET_77"})

    base_url, srv = _start_server(_ShareHandler)
    store, client, oracle = _make_oracle_env(tmp_path, base_url)
    dispatcher = ToolDispatcher(
        http_client=client,
        receipt_store=store,
        root_dir=tmp_path,
        oracle=oracle,
    )
    try:
        setup_rec = client.request(
            method="POST",
            url="/api/share",
            actor="alice",
            json_body={"code": "tok-1"},
        )
        consume_rec = client.request(method="GET", url="/api/consume?code=tok-1", actor="anon")
        ctrl_rec = client.request(method="GET", url="/api/consume?code=missing", actor="bob")

        res = json.loads(
            dispatcher.dispatch(
                "record_finding",
                {
                    "title": "Unauthenticated One-Shot Consume",
                    "class_type": "auth_bypass",
                    "method": "GET",
                    "url": "/api/consume",
                    "actor_alias": "anon",
                    "proof_receipt_ids": [setup_rec["receipt_id"], consume_rec["receipt_id"]],
                    "control_receipt_ids": [ctrl_rec["receipt_id"]],
                    "evidence_value": "ONESHOT_TOOL_SECRET_77",
                    "summary": "Anonymous consume reads one-shot secret created by alice.",
                    "severity": "high",
                },
            )
        )
        assert res.get("accepted") is True, res
    finally:
        dispatcher.close()
        client.close()
        _stop_server(srv)
