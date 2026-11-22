"""Tests for closed record_finding.class_type enum and Stage 3 ephemeral/dynamic ID warning."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit
import uuid

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_oracle import (  # noqa: E402
    DifferentialOracle,
    _detect_ephemeral_evidence_mismatch,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import (  # noqa: E402
    RECORD_FINDING_CLASS_ENUM,
    TOOL_SCHEMAS,
    ToolDispatcher,
)


def _start_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[str, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", srv


def _stop_server(srv: ThreadingHTTPServer) -> None:
    srv.shutdown()
    srv.server_close()


def _make_env(
    tmp_path: Path,
    base_url: str,
    *,
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
    max_requests: int = 80,
) -> tuple[ReceiptStore, AgenticHTTPClient, DifferentialOracle, ToolDispatcher]:
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
    )
    dispatcher = ToolDispatcher(
        http_client=client,
        receipt_store=store,
        root_dir=tmp_path,
        oracle=oracle,
    )
    return store, client, oracle, dispatcher


# ---------------------------------------------------------------------------
# 1. Closed enum for record_finding.class_type & backward-compatible aliases
# ---------------------------------------------------------------------------


def test_record_finding_class_type_closed_enum_and_schema_bounds() -> None:
    expected_classes = [
        "auth_bypass",
        "bfla",
        "bola",
        "tenant_isolation",
        "mass_assignment",
        "reflected_xss",
        "stored_xss",
        "sqli",
        "sqli_read",
        "open_redirect",
        "ssrf",
        "xxe",
        "ssti",
        "path_traversal",
        "file_upload",
        "cors_misconfiguration",
        "csrf",
        "jwt_weakness",
        "command_injection",
        "race_condition",
        "business_logic",
        "other",
    ]
    assert RECORD_FINDING_CLASS_ENUM == expected_classes
    assert len(TOOL_SCHEMAS) == 11

    serialized = json.dumps(TOOL_SCHEMAS, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(serialized) <= 16_384

    for tool in TOOL_SCHEMAS:
        fn = tool["function"]
        name = fn["name"]
        assert len(fn["description"]) <= 140, f"{name} description exceeds 140 chars"
        props = fn.get("parameters", {}).get("properties", {})
        for prop_name, prop_schema in props.items():
            desc = prop_schema.get("description")
            if isinstance(desc, str):
                assert len(desc) <= 140, f"{name}.{prop_name} description exceeds 140 chars ({len(desc)})"

    rf_tool = next(t["function"] for t in TOOL_SCHEMAS if t["function"]["name"] == "record_finding")
    class_prop = rf_tool["parameters"]["properties"]["class_type"]
    assert class_prop["type"] == "string"
    assert class_prop["enum"] == RECORD_FINDING_CLASS_ENUM
    for required_cls in (
        "file_upload",
        "path_traversal",
        "cors_misconfiguration",
        "jwt_weakness",
        "xxe",
        "command_injection",
        "race_condition",
        "business_logic",
        "other",
    ):
        assert required_cls in class_prop["enum"]
    assert len(class_prop["description"]) <= 140


def test_record_finding_alias_normalization_remains_backward_compatible(tmp_path: Path) -> None:
    victim_uuid = "11111111-2222-4333-8444-555555555555"

    class _AliasHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _send_json(self, status: int, obj: Any, extra_headers: dict[str, str] | None = None) -> None:
            payload = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            auth = self.headers.get("Authorization", "")
            if path == f"/api/records/{victim_uuid}":
                if auth in {"Bearer tok-alice", "Bearer tok-bob"}:
                    self._send_json(200, {"id": victim_uuid, "owner": "bob", "tenant": "beta", "secret": "VICTIM_SECRET_42"})
                    return
                self._send_json(401, {"error": "unauthorized"})
                return
            if path == "/api/cors-check":
                origin = self.headers.get("Origin", "")
                if origin == "https://evil.example":
                    self._send_json(
                        200,
                        {"ok": True},
                        extra_headers={
                            "Access-Control-Allow-Origin": origin,
                            "Access-Control-Allow-Credentials": "true",
                        },
                    )
                    return
                self._send_json(200, {"ok": True})
                return
            self._send_json(404, {"error": "not_found"})

    base_url, srv = _start_server(_AliasHandler)
    _, client, _, dispatcher = _make_env(tmp_path, base_url)
    try:
        # "idor" alias still normalizes to "bola"
        proof_rec = client.request(method="GET", url=f"/api/records/{victim_uuid}", actor="alice")
        ctrl_rec = client.request(method="GET", url=f"/api/records/{victim_uuid}", actor="anon")
        res = json.loads(
            dispatcher.dispatch(
                "record_finding",
                {
                    "title": "IDOR cross-user record read",
                    "class_type": "idor",
                    "method": "GET",
                    "url": f"/api/records/{victim_uuid}",
                    "actor_alias": "alice",
                    "proof_receipt_ids": [proof_rec["receipt_id"]],
                    "control_receipt_ids": [ctrl_rec["receipt_id"]],
                    "evidence_value": "VICTIM_SECRET_42",
                    "summary": "Alice reads Bob's record via direct ID",
                },
            )
        )
        assert res["accepted"] is True
        assert res["class_type"] == "bola"

        # "cors" alias still normalizes to "cors_misconfiguration"
        cors_proof = client.request(
            method="GET",
            url="/api/cors-check",
            actor="alice",
            headers={"Origin": "https://evil.example"},
        )
        cors_ctrl = client.request(
            method="GET",
            url="/api/cors-check",
            actor="alice",
            headers={"Origin": "https://trusted.local"},
        )
        res_cors = json.loads(
            dispatcher.dispatch(
                "record_finding",
                {
                    "title": "Arbitrary origin CORS reflection",
                    "class_type": "cors",
                    "method": "GET",
                    "url": "/api/cors-check",
                    "actor_alias": "alice",
                    "proof_receipt_ids": [cors_proof["receipt_id"]],
                    "control_receipt_ids": [cors_ctrl["receipt_id"]],
                    "evidence_value": "https://evil.example",
                    "summary": "Reflected evil Origin with credentials enabled",
                },
            )
        )
        assert res_cors["accepted"] is True
        assert res_cors["class_type"] == "cors_misconfiguration"
    finally:
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 2. Actionable Stage 3 Ephemeral/Dynamic ID Warning
# ---------------------------------------------------------------------------


def test_stage3_ephemeral_event_id_and_uuid_warning_vs_static_evidence(tmp_path: Path) -> None:
    static_victim_uuid = "22222222-3333-4444-8555-666666666666"
    call_state = {"flaky_hits": 0, "run_seq": 0}
    lock = threading.Lock()

    class _EphemeralHandler(BaseHTTPRequestHandler):
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

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            qs = parse_qs(parsed.query)
            auth = self.headers.get("Authorization", "")

            # 1. Endpoint returning fresh 32-char hex event_id + static "hidden_flag"
            if parsed.path == "/api/trigger":
                if auth != "Bearer tok-alice":
                    self._send_json(403, {"ok": False, "error": "forbidden"})
                    return
                mode = (qs.get("mode") or ["benign"])[0]
                if mode == "exploit":
                    self._send_json(
                        200,
                        {
                            "ok": True,
                            "event_id": uuid.uuid4().hex,
                            "handler": "hidden_flag",
                        },
                    )
                    return
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "event_id": uuid.uuid4().hex,
                        "handler": "default_handler",
                    },
                )
                return

            # 2. Endpoint returning rotating UUID in a non-ephemeral JSON key
            if parsed.path == "/api/uuid-rotating":
                if auth != "Bearer tok-alice":
                    self._send_json(403, {"error": "forbidden"})
                    return
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "record_ref": str(uuid.uuid4()),
                        "handler": "hidden_flag",
                    },
                )
                return

            # 3. Endpoint returning non-hex rotating ephemeral JSON key (run_id)
            if parsed.path == "/api/run-rotating":
                if auth != "Bearer tok-alice":
                    self._send_json(403, {"error": "forbidden"})
                    return
                with lock:
                    call_state["run_seq"] += 1
                    seq = call_state["run_seq"]
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "run_id": f"run-seq-{seq:04d}",
                        "handler": "hidden_flag",
                    },
                )
                return

            # 4. BOLA endpoint returning a STATIC victim UUID on every replay
            if parsed.path == f"/api/victim-records/{static_victim_uuid}":
                if auth in {"Bearer tok-alice", "Bearer tok-bob"}:
                    self._send_json(
                        200,
                        {
                            "id": static_victim_uuid,
                            "owner": "bob",
                            "tenant": "beta",
                            "status": "confidential",
                        },
                    )
                    return
                self._send_json(401, {"error": "unauthorized"})
                return

            # 5. Non-matching / hallucinated replay structure
            if parsed.path == "/api/divergent":
                if auth != "Bearer tok-alice":
                    self._send_json(403, {"error": "forbidden"})
                    return
                with lock:
                    call_state["flaky_hits"] += 1
                    hit = call_state["flaky_hits"]
                if hit == 1:
                    self._send_json(
                        200,
                        {
                            "ok": True,
                            "event_id": uuid.uuid4().hex,
                            "handler": "hidden_flag",
                        },
                    )
                else:
                    self._send_json(
                        200,
                        {
                            "status": "idle",
                            "items": [],
                        },
                    )
                return

            self._send_json(404, {"error": "not_found"})

    base_url, srv = _start_server(_EphemeralHandler)
    _, client, oracle, dispatcher = _make_env(tmp_path, base_url)
    try:
        # Case A: Rotating 32-char hex event_id -> REFUTED with failed_ephemeral_evidence + actionable warning
        proof_evt = client.request(method="GET", url="/api/trigger?mode=exploit", actor="alice")
        ctrl_evt = client.request(method="GET", url="/api/trigger?mode=benign", actor="alice")
        ctrl_evt_anon = client.request(method="GET", url="/api/trigger?mode=exploit", actor="anon")
        first_event_id = json.loads(proof_evt["body"])["event_id"]
        assert len(first_event_id) == 32

        v_eph = oracle.verify(
            canonical_class="bfla",
            primary_proof=proof_evt,
            proof_receipts=[proof_evt],
            control_receipts=[ctrl_evt_anon],
            evidence_value=first_event_id,
        )
        assert v_eph.verified is False
        assert v_eph.verdict == "REFUTED"
        assert v_eph.stages["stage3_clean_replay"] == "failed_ephemeral_evidence"
        assert "dynamic/ephemeral ID" in v_eph.reason
        assert "static" in v_eph.reason
        assert v_eph.clean_replay_receipt_id

        # Also check through ToolDispatcher.dispatch("record_finding", ...) for both input-diff and bfla
        rej_disp = json.loads(
            dispatcher.dispatch(
                "record_finding",
                {
                    "title": "Hidden handler invocation",
                    "class_type": "bfla",
                    "method": "GET",
                    "url": "/api/trigger?mode=exploit",
                    "actor_alias": "alice",
                    "proof_receipt_ids": [proof_evt["receipt_id"]],
                    "control_receipt_ids": [ctrl_evt_anon["receipt_id"]],
                    "evidence_value": first_event_id,
                    "summary": "Invoked hidden handler using rotating event_id as evidence",
                },
            )
        )
        assert rej_disp["rejected"] is True
        assert rej_disp["oracle_verdict"] == "REFUTED"
        assert rej_disp["stages"]["stage3_clean_replay"] == "failed_ephemeral_evidence"
        assert "dynamic/ephemeral ID" in rej_disp["reason"]
        assert "static" in rej_disp["reason"]

        # Case B: Re-submitting static "hidden_flag" -> VERIFIED (stage3_clean_replay == "passed")
        v_static = oracle.verify(
            canonical_class="bfla",
            primary_proof=proof_evt,
            proof_receipts=[proof_evt],
            control_receipts=[ctrl_evt_anon],
            evidence_value="hidden_flag",
        )
        assert v_static.verified is True
        assert v_static.verdict == "VERIFIED"
        assert v_static.stages["stage3_clean_replay"] == "passed"

        # Input-diff class with benign same-actor control also gets failed_ephemeral_evidence then VERIFIED
        v_input_eph = oracle.verify(
            canonical_class="path_traversal",
            primary_proof=proof_evt,
            proof_receipts=[proof_evt],
            control_receipts=[ctrl_evt],
            evidence_value=first_event_id,
        )
        assert v_input_eph.verified is False
        assert v_input_eph.verdict == "REFUTED"
        assert v_input_eph.stages["stage3_clean_replay"] == "failed_ephemeral_evidence"

        acc_disp = json.loads(
            dispatcher.dispatch(
                "record_finding",
                {
                    "title": "Hidden handler invocation",
                    "class_type": "bfla",
                    "method": "GET",
                    "url": "/api/trigger?mode=exploit",
                    "actor_alias": "alice",
                    "proof_receipt_ids": [proof_evt["receipt_id"]],
                    "control_receipt_ids": [ctrl_evt_anon["receipt_id"]],
                    "evidence_value": "hidden_flag",
                    "summary": "Invoked hidden handler using static evidence",
                },
            )
        )
        assert acc_disp["accepted"] is True
        assert acc_disp["class_type"] == "bfla"

        # Case C: Rotating UUID in an arbitrary JSON field -> REFUTED with failed_ephemeral_evidence
        proof_uuid = client.request(method="GET", url="/api/uuid-rotating", actor="alice")
        ctrl_uuid = client.request(method="GET", url="/api/uuid-rotating", actor="anon")
        first_uuid = json.loads(proof_uuid["body"])["record_ref"]

        v_rot_uuid = oracle.verify(
            canonical_class="bfla",
            primary_proof=proof_uuid,
            proof_receipts=[proof_uuid],
            control_receipts=[ctrl_uuid],
            evidence_value=first_uuid,
        )
        assert v_rot_uuid.verified is False
        assert v_rot_uuid.verdict == "REFUTED"
        assert v_rot_uuid.stages["stage3_clean_replay"] == "failed_ephemeral_evidence"
        assert "dynamic/ephemeral ID" in v_rot_uuid.reason

        # Case D: Rotating non-hex value in ephemeral JSON key (run_id) -> REFUTED with failed_ephemeral_evidence
        proof_run = client.request(method="GET", url="/api/run-rotating", actor="alice")
        ctrl_run = client.request(method="GET", url="/api/run-rotating", actor="anon")
        first_run_id = json.loads(proof_run["body"])["run_id"]

        v_rot_run = oracle.verify(
            canonical_class="bfla",
            primary_proof=proof_run,
            proof_receipts=[proof_run],
            control_receipts=[ctrl_run],
            evidence_value=first_run_id,
        )
        assert v_rot_run.verified is False
        assert v_rot_run.verdict == "REFUTED"
        assert v_rot_run.stages["stage3_clean_replay"] == "failed_ephemeral_evidence"

        # Case E: Static victim UUID in BOLA still passes VERIFIED!
        proof_bola = client.request(method="GET", url=f"/api/victim-records/{static_victim_uuid}", actor="alice")
        ctrl_bola = client.request(method="GET", url=f"/api/victim-records/{static_victim_uuid}", actor="anon")
        v_bola = oracle.verify(
            canonical_class="bola",
            primary_proof=proof_bola,
            proof_receipts=[proof_bola],
            control_receipts=[ctrl_bola],
            evidence_value=static_victim_uuid,
            actor_meta_map={
                "alice": {"alias": "alice", "role": "member", "tenant": "alpha"},
                "bob": {"alias": "bob", "role": "member", "tenant": "beta"},
            },
        )
        assert v_bola.verified is True
        assert v_bola.verdict == "VERIFIED"
        assert v_bola.stages["stage3_clean_replay"] == "passed"

        # Case F: Divergent/non-matching replay body -> standard failed_missing_evidence (NOT failed_ephemeral_evidence)
        proof_div = client.request(method="GET", url="/api/divergent", actor="alice")
        ctrl_div = client.request(method="GET", url="/api/divergent", actor="anon")
        div_event_id = json.loads(proof_div["body"])["event_id"]

        v_div = oracle.verify(
            canonical_class="bfla",
            primary_proof=proof_div,
            proof_receipts=[proof_div],
            control_receipts=[ctrl_div],
            evidence_value=div_event_id,
        )
        assert v_div.verified is False
        assert v_div.verdict == "REFUTED"
        assert v_div.stages["stage3_clean_replay"] == "failed_missing_evidence"
        assert v_div.reason == "Clean-session replay did not reproduce the claimed evidence_value."
    finally:
        client.close()
        _stop_server(srv)


def test_detect_ephemeral_evidence_mismatch_edge_cases() -> None:
    hex_a = "a" * 32
    hex_b = "b" * 32
    uuid_a = "550e8400-e29b-41d4-a716-446655440000"
    uuid_b = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

    # 1. Non-2xx status -> False
    assert _detect_ephemeral_evidence_mismatch(
        hex_a,
        {"status": 302, "body": json.dumps({"event_id": hex_a})},
        {"status": 302, "body": json.dumps({"event_id": hex_b})},
    ) is False

    # 2. Empty body -> False
    assert _detect_ephemeral_evidence_mismatch(
        hex_a,
        {"status": 200, "body": ""},
        {"status": 200, "body": ""},
    ) is False

    # 3. Hallucinated UUID not present in replay_target (even when both bodies are identical static JSON) -> False
    assert _detect_ephemeral_evidence_mismatch(
        uuid_a,
        {"status": 200, "body": '{"ok":true,"handler":"static"}'},
        {"status": 200, "body": '{"ok":true,"handler":"static"}'},
    ) is False

    # 4. Nested ephemeral JSON key rotation with identical surrounding structure -> True
    assert _detect_ephemeral_evidence_mismatch(
        "job-001",
        {"status": 200, "body": json.dumps({"meta": {"job_id": "job-001", "timestamp": "2026-01-01T00:00:01Z"}, "ok": True})},
        {"status": 200, "body": json.dumps({"meta": {"job_id": "job-002", "timestamp": "2026-01-01T00:00:05Z"}, "ok": True})},
    ) is True

    # 5. Plain-text rotating UUID with identical surrounding text -> True
    assert _detect_ephemeral_evidence_mismatch(
        uuid_a,
        {"status": 200, "body": f"status=ok trace={uuid_a} handler=hidden_flag"},
        {"status": 200, "body": f"status=ok trace={uuid_b} handler=hidden_flag"},
    ) is True

    # 6. Plain-text rotating 32-hex with DIFFERENT surrounding text -> False
    assert _detect_ephemeral_evidence_mismatch(
        hex_a,
        {"status": 200, "body": f"status=ok event_id={hex_a} handler=hidden_flag"},
        {"status": 200, "body": f"status=error event_id={hex_b} detail=missing"},
    ) is False

    # 7. Non-ephemeral static token missing on replay -> False
    assert _detect_ephemeral_evidence_mismatch(
        "SECRET_ADMIN_FLAG",
        {"status": 200, "body": '{"ok":true,"flag":"SECRET_ADMIN_FLAG"}'},
        {"status": 200, "body": '{"ok":true,"flag":"PUBLIC_DEFAULT"}'},
    ) is False
