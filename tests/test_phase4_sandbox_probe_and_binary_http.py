"""Phase 4 tests: air-gapped `run_sandbox_probe` (`python_pure`) + binary/gRPC-Web HTTP transport."""
from __future__ import annotations

import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import struct
import subprocess
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentic_http import (  # noqa: E402
    ActorManager,
    AgenticHTTPClient,
    BudgetExhaustedError,
    ScopeViolationError,
)
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_sandbox import _BOOTSTRAP, run_python_pure_sandbox  # noqa: E402
from agentic_telemetry import TelemetryLogger  # noqa: E402
from agentic_tools import TOOL_SCHEMAS, ToolDispatcher  # noqa: E402
from kryon_core.protocol.grpc_web import (  # noqa: E402
    decode_grpc_web_frames,
    encode_grpc_web_frame,
    encode_grpc_web_trailers,
)


def _unwrap_untrusted(raw: str) -> dict[str, Any]:
    prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw.startswith(prefix) and raw.endswith(suffix)
    return json.loads(raw[len(prefix) : -len(suffix)])


def _start_binary_grpc_server(hmac_secret: bytes) -> tuple[ThreadingHTTPServer, list[dict[str, Any]]]:
    recorded: list[dict[str, Any]] = []
    lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _handle(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length) if length > 0 else b""
            parsed = urlsplit(self.path)
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            with lock:
                recorded.append({
                    "method": method,
                    "path": parsed.path,
                    "query": parsed.query,
                    "headers": hdrs,
                    "body": body,
                })

            if parsed.path == "/grpc.EchoService/Check":
                auth_val = hdrs.get("authorization", "")
                if "anon-deny" in auth_val or not auth_val:
                    err_frame = encode_grpc_web_trailers(
                        {"grpc-status": "7", "grpc-message": "unauthorized"},
                        text_mode=False,
                    )
                    self.send_response(403)
                    self.send_header("Content-Type", "application/grpc-web+proto")
                    self.send_header("Content-Length", str(len(err_frame)))
                    self.end_headers()
                    self.wfile.write(err_frame)
                    return

                decoded = decode_grpc_web_frames(body, content_type=hdrs.get("content-type", ""))
                data_frames = decoded.get("data_frames") or []
                if not data_frames:
                    self.send_response(400)
                    self.end_headers()
                    return
                inner_payload = base64.b64decode(data_frames[0]["payload_base64"])
                expected_sig = hmac.new(hmac_secret, inner_payload, hashlib.sha256).hexdigest()
                if hdrs.get("x-signature") != expected_sig:
                    self.send_response(401)
                    self.end_headers()
                    return

                is_text = "grpc-web-text" in hdrs.get("content-type", "").lower()
                reply_payload = b"ok:" + inner_payload + b":PROOF_BIN_8842"
                resp_wire = encode_grpc_web_frame(reply_payload, text_mode=is_text) + encode_grpc_web_trailers(
                    {"grpc-status": "0", "grpc-message": "OK"},
                    text_mode=is_text,
                )
                resp_ct = "application/grpc-web-text+proto" if is_text else "application/grpc-web+proto"
                self.send_response(200)
                self.send_header("Content-Type", resp_ct)
                self.send_header("Content-Length", str(len(resp_wire)))
                self.end_headers()
                self.wfile.write(resp_wire)
                return

            if parsed.path == "/api/raw-echo":
                out = json.dumps({
                    "method": method,
                    "query": parse_qs(parsed.query),
                    "len": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "content_type": hdrs.get("content-type", ""),
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
                return

            self.send_response(404)
            self.end_headers()

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, recorded


def test_tool_schemas_12_tools_bounds_and_phase4_schema() -> None:
    assert len(TOOL_SCHEMAS) == 12
    serialized = json.dumps(TOOL_SCHEMAS, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(serialized) <= 16_384

    for tool in TOOL_SCHEMAS:
        fn = tool["function"]
        name = fn["name"]
        assert len(fn["description"]) <= 140, f"{name} description > 140 chars"
        props = fn.get("parameters", {}).get("properties", {})
        for prop_name, prop_schema in props.items():
            desc = prop_schema.get("description")
            if isinstance(desc, str):
                assert len(desc) <= 140, f"{name}.{prop_name} description > 140 chars ({len(desc)})"

    http_props = next(
        t["function"]["parameters"]["properties"]
        for t in TOOL_SCHEMAS
        if t["function"]["name"] == "http_request"
    )
    assert http_props["raw_body_base64"]["type"] == "string"
    assert http_props["grpc_web_mode"]["enum"] == ["binary", "text"]

    sbx_tool = next(t["function"] for t in TOOL_SCHEMAS if t["function"]["name"] == "run_sandbox_probe")
    sbx_props = sbx_tool["parameters"]["properties"]
    assert sbx_props["runtime"]["enum"] == ["python_pure"]
    assert sbx_props["output_contract"]["enum"] == ["http_transform", "decode_only"]
    assert "code" in sbx_tool["parameters"]["required"]


def test_sandbox_hmac_protobuf_http_grpc_web_replay_and_oracle(tmp_path: Path) -> None:
    signing_bytes = b"sandbox-signing-key-2026"
    srv, recorded = _start_binary_grpc_server(signing_bytes)
    store = ReceiptStore(tmp_path / "run")
    cred_a = "user-a-" + "cred-1122"
    cred_b = "user-b-" + "cred-3344"
    actors = ActorManager([
        {"alias": "member_a", "auth_header": "Bearer " + cred_a, "role": "member"},
        {"alias": "member_b", "auth_header": "Bearer " + cred_b, "role": "member"},
    ])
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{srv.server_port}",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=30,
    )
    telemetry = TelemetryLogger(tmp_path / "run" / "telemetry.jsonl")
    dispatcher = ToolDispatcher(
        http_client=client,
        receipt_store=store,
        root_dir=tmp_path / "run",
        telemetry=telemetry,
    )
    try:
        probe_code = """
import base64
import hashlib
import hmac
import struct

def transform(inputs):
    p = inputs["params"]
    raw_bytes = struct.pack(">BH", 8, p["item_id"]) + b"\\x12\\x05hello\\x00\\xff"
    sig = hmac.new(p["key"].encode("utf-8"), raw_bytes, hashlib.sha256).hexdigest()
    return {
        "body_base64": base64.b64encode(raw_bytes).decode("ascii"),
        "headers": {"X-Signature": sig},
        "query": {"v": "2"},
        "decoded": {"payload_len": len(raw_bytes)},
    }
"""
        sbx_raw = dispatcher.dispatch(
            "run_sandbox_probe",
            {
                "runtime": "python_pure",
                "code": probe_code,
                "inputs": {"params": {"item_id": 42, "key": signing_bytes.decode("ascii")}},
                "output_contract": "http_transform",
            },
        )
        sbx = _unwrap_untrusted(sbx_raw)
        assert sbx["ok"] is True
        assert sbx["runtime"] == "python_pure"
        assert sbx["transform_id"].startswith("tx_")
        assert sbx["decoded"] == {"payload_len": 12}
        expected_raw = struct.pack(">BH", 8, 42) + b"\x12\x05hello\x00\xff"
        assert len(expected_raw) == 12
        assert base64.b64decode(sbx["body_base64"]) == expected_raw
        assert any(ev.get("event") == "sandbox_probe" and ev.get("ok") is True for ev in telemetry.events())

        # Control request (anon denied 403)
        ctrl_out = _unwrap_untrusted(
            dispatcher.dispatch(
                "http_request",
                {
                    "method": "POST",
                    "url": "/grpc.EchoService/Check",
                    "actor": "anon",
                    "raw_body_base64": sbx["body_base64"],
                    "grpc_web_mode": "binary",
                    "headers": sbx["headers"],
                    "query": sbx["query"],
                },
            )
        )
        assert ctrl_out["status"] == 403
        ctrl_rid = ctrl_out["receipt_id"]

        # Proof request (member_a 200)
        proof_out = _unwrap_untrusted(
            dispatcher.dispatch(
                "http_request",
                {
                    "method": "POST",
                    "url": "/grpc.EchoService/Check",
                    "actor": "member_a",
                    "raw_body_base64": sbx["body_base64"],
                    "grpc_web_mode": "binary",
                    "headers": sbx["headers"],
                    "query": sbx["query"],
                },
            )
        )
        assert proof_out["status"] == 200
        proof_rid = proof_out["receipt_id"]

        expected_framed = encode_grpc_web_frame(expected_raw, text_mode=False)
        proof_wire = recorded[-1]
        assert proof_wire["body"] == expected_framed
        assert proof_wire["headers"]["content-type"] == "application/grpc-web+proto"
        assert proof_wire["headers"]["x-grpc-web"] == "1"
        assert proof_wire["query"] == "v=2"

        # Verify persisted receipt survives reload from disk
        reloaded_store = ReceiptStore(tmp_path / "run")
        reloaded_rec = reloaded_store.get(proof_rid)
        assert reloaded_rec["request_body"].startswith("<binary 17 bytes sha256=")
        assert base64.b64decode(reloaded_rec["request_body_base64"]) == expected_framed
        decoded_resp_json = json.loads(reloaded_rec["body"])
        assert decoded_resp_json["grpc_status"] == 0
        assert "PROOF_BIN_8842" in decoded_resp_json["data_frames"][0]["text_preview"]

        # Text mode gRPC-Web request
        txt_out = _unwrap_untrusted(
            dispatcher.dispatch(
                "http_request",
                {
                    "method": "POST",
                    "url": "/grpc.EchoService/Check",
                    "actor": "member_a",
                    "raw_body_base64": sbx["body_base64"],
                    "grpc_web_mode": "text",
                    "headers": sbx["headers"],
                },
            )
        )
        assert txt_out["status"] == 200
        assert recorded[-1]["headers"]["content-type"] == "application/grpc-web-text+proto"
        assert recorded[-1]["body"] == encode_grpc_web_frame(expected_raw, text_mode=True)

        # replay_as replays exact binary framed bytes without double-framing
        replay_out = _unwrap_untrusted(
            dispatcher.dispatch(
                "replay_as",
                {
                    "receipt_id": proof_rid,
                    "actor": "member_b",
                },
            )
        )
        assert replay_out["replay"]["status"] == 200
        assert recorded[-1]["body"] == expected_framed
        assert recorded[-1]["headers"]["content-type"] == "application/grpc-web+proto"

        # DifferentialOracle Stage 1-3 verifies binary gRPC-Web receipt via clean replay
        oracle = DifferentialOracle(http_client=client, receipt_store=store)
        proof_rec = store.get(proof_rid)
        ctrl_rec = store.get(ctrl_rid)
        verdict = oracle.verify(
            canonical_class="auth_bypass",
            primary_proof=proof_rec,
            proof_receipts=[proof_rec],
            control_receipts=[ctrl_rec],
            evidence_value="PROOF_BIN_8842",
        )
        assert verdict.verified is True
        assert verdict.verdict == "VERIFIED"
        assert verdict.stages["stage3_clean_replay"] == "passed"
        assert recorded[-1]["body"] == expected_framed
        clean_rec = store.get(verdict.clean_replay_receipt_id)
        assert base64.b64decode(clean_rec["request_body_base64"]) == expected_framed

        # ScopeGuard & WireBudget still enforce limits on raw_body_base64 requests
        with pytest.raises(ScopeViolationError):
            client.request(
                method="POST",
                url="http://127.0.0.1:19999/other",
                raw_body_base64=sbx["body_base64"],
            )
        client.budget.limit = client.budget.used
        with pytest.raises(BudgetExhaustedError):
            client.request(
                method="POST",
                url="/api/raw-echo",
                raw_body_base64=sbx["body_base64"],
            )
    finally:
        dispatcher.close()
        client.close()
        srv.shutdown()
        srv.server_close()


def test_python_pure_sandbox_security_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRYON_TEST_HOST_SECRET", "host-secret-should-stay-hidden")

    blocked_cases = [
        "import socket\nRESULT = {'x': 1}",
        "from urllib import request\nRESULT = {'x': 1}",
        "import os\nRESULT = {'env': dict(os.environ)}",
        "import subprocess\nRESULT = {'x': 1}",
        "import shutil\nRESULT = {'x': 1}",
        "import ctypes\nRESULT = {'x': 1}",
        "RESULT = {'data': open('/etc/passwd').read()}",
        "RESULT = {'x': eval('1+1')}",
        "exec('x=1')\nRESULT = {'x': 1}",
        "RESULT = {'x': __import__('os').name}",
        "RESULT = {'x': getattr((), '__class__')}",
        "RESULT = {'x': vars()}",
        "RESULT = {'x': globals()}",
        "RESULT = {'x': ().__class__.__mro__[1].__subclasses__()}",
        "def f(): return 1\nRESULT = {'x': f.__globals__}",
        "RESULT = {'x': __builtins__}",
    ]
    for bad_code in blocked_cases:
        res = run_python_pure_sandbox(bad_code)
        assert res["ok"] is False, f"expected rejection for: {bad_code!r}"

    # Verify Layer 3 child bootstrap directly enforces audit hook + empty env + RLIMIT_FSIZE=0
    probe_payload = json.dumps({
        "code": "import builtins\nRESULT = {'ok': True}",
        "inputs": {},
        "max_output_bytes": 4096,
    })
    assert run_python_pure_sandbox(json.loads(probe_payload)["code"])["ok"] is False

    layer3_audit_check = """
import json, resource, sys
payload = json.dumps({"code": "RESULT = {'a': 1}", "inputs": {}, "max_output_bytes": 4096})
"""
    _ = layer3_audit_check
    proc = subprocess.run(
        [sys.executable, "-I", "-c", _BOOTSTRAP],
        input=json.dumps({
            "code": "import os\nRESULT = {'env': os.environ.get('KRYON_TEST_HOST_SECRET')}",
            "inputs": {},
            "max_output_bytes": 4096,
        }).encode("utf-8"),
        capture_output=True,
        env={},
        timeout=2.0,
        check=False,
    )
    assert proc.returncode == 0
    child_doc = json.loads(proc.stdout.decode("utf-8"))
    assert child_doc["ok"] is False
    assert "ImportError" in child_doc["error"]

    # Verify audit hook blocks `open` even if user code somehow received a handle/builtin inside _BOOTSTRAP
    audit_proc = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import resource, sys\n"
            "def h(ev, a):\n"
            "    if ev == 'open' or ev.startswith(('socket.', 'subprocess.')):\n"
            "        raise PermissionError(ev)\n"
            "sys.addaudithook(h)\n"
            "open('/etc/passwd', 'r')\n",
        ],
        capture_output=True,
        env={},
        timeout=2.0,
        check=False,
    )
    assert audit_proc.returncode != 0
    assert b"PermissionError" in audit_proc.stderr

    # Timeout killed cleanly
    timeout_res = run_python_pure_sandbox("while True:\n    pass\n", timeout_ms=250)
    assert timeout_res["ok"] is False
    assert "timed out" in timeout_res["error"].lower()

    # Output cap on stdout and decoded payload
    cap_stdout = run_python_pure_sandbox("print('A' * 5000)\nRESULT = {'decoded': 'ok'}", max_output_bytes=256)
    assert cap_stdout["ok"] is True
    assert len(cap_stdout["stdout_preview"].encode("utf-8")) <= 256

    cap_decoded = run_python_pure_sandbox("RESULT = {'decoded': 'B' * 5000}", max_output_bytes=256)
    assert cap_decoded["ok"] is False
    assert "max_output_bytes" in cap_decoded["error"]

    # CR/LF and NUL header injection rejected
    for bad_hdr in ({"X-Inject": "val\r\nEvil: 1"}, {"X-Inject": "val\x00x"}, {"Bad\nKey": "1"}):
        inj_res = run_python_pure_sandbox(f"RESULT = {{'headers': {bad_hdr!r}}}")
        assert inj_res["ok"] is False

    # Oversized (>256KB) and invalid base64 rejected
    oversize_res = run_python_pure_sandbox(
        "import base64\nRESULT = {'body_base64': base64.b64encode(b'x' * (256 * 1024 + 1)).decode()}"
    )
    assert oversize_res["ok"] is False
    bad_b64_res = run_python_pure_sandbox("RESULT = {'body_base64': '!!!not-base64!!!'}")
    assert bad_b64_res["ok"] is False

    # Pure-compute stdlib modules work cleanly via RESULT
    pure_ok = run_python_pure_sandbox(
        "import base64, binascii, collections, copy, datetime, decimal, functools, gzip, "
        "hashlib, hmac, itertools, json, math, re, string, struct, time, urllib.parse, uuid, zlib\n"
        "dt = datetime.datetime.strptime('2026/11/27', '%Y/%m/%d').strftime('%Y%m%d')\n"
        "q = urllib.parse.urlencode({'k': 'a b', 'd': dt})\n"
        "zlen = len(zlib.compress(q.encode('utf-8')))\n"
        "glen = len(gzip.compress(b'hi'))\n"
        "dec_v = str(decimal.Decimal('1.25') + 2)\n"
        "uid = str(uuid.uuid4())\n"
        "RESULT = {'decoded': {'q': q, 'zlen': zlen, 'glen': glen, 'dec': dec_v, 'uid_len': len(uid)}}\n"
    )
    assert pure_ok["ok"] is True
    assert pure_ok["decoded"]["q"] == "k=a+b&d=20261127"
    assert pure_ok["decoded"]["zlen"] > 0
    assert pure_ok["decoded"]["glen"] > 0
    assert pure_ok["decoded"]["dec"] == "3.25"
    assert pure_ok["decoded"]["uid_len"] == 36


def test_http_client_raw_body_base64_validation_and_get_cache(tmp_path: Path) -> None:
    srv, recorded = _start_binary_grpc_server(b"k")
    store = ReceiptStore(tmp_path / "receipts")
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{srv.server_port}",
        receipt_store=store,
        actors=ActorManager([]),
        allowed_methods=("GET", "POST"),
        max_requests=20,
    )
    try:
        sample_b64 = base64.b64encode(b"\x01\x02\x03\x04").decode("ascii")
        # Mutual exclusion checks
        for extra in (
            {"json_body": {"a": 1}},
            {"form_body": {"a": "1"}},
            {"raw_body": "abc"},
            {"files": [{"field": "f", "filename": "a.txt", "content": "x"}]},
        ):
            with pytest.raises(ValueError):
                client.request(method="POST", url="/api/raw-echo", raw_body_base64=sample_b64, **extra)

        with pytest.raises(ValueError):
            client.request(method="POST", url="/api/raw-echo", raw_body_base64="***invalid***")

        too_big_b64 = base64.b64encode(b"z" * (1024 * 1024 + 1)).decode("ascii")
        with pytest.raises(ValueError):
            client.request(method="POST", url="/api/raw-echo", raw_body_base64=too_big_b64)

        with pytest.raises(ValueError):
            client.request(method="POST", url="/api/raw-echo", raw_body_base64=sample_b64, grpc_web_mode="xml")

        # Default Content-Type: application/octet-stream
        r_oct = client.request(method="POST", url="/api/raw-echo", raw_body_base64=sample_b64)
        assert r_oct["status"] == 200
        assert recorded[-1]["headers"]["content-type"] == "application/octet-stream"
        assert recorded[-1]["body"] == b"\x01\x02\x03\x04"

        # Custom Content-Type preserved
        r_proto = client.request(
            method="POST",
            url="/api/raw-echo",
            raw_body_base64=sample_b64,
            headers={"Content-Type": "application/x-protobuf"},
        )
        assert r_proto["status"] == 200
        assert recorded[-1]["headers"]["content-type"] == "application/x-protobuf"

        # Explicit grpc-web Content-Type preserved when grpc_web_mode="binary"
        r_grpc_custom = client.request(
            method="POST",
            url="/api/raw-echo",
            raw_body_base64=sample_b64,
            grpc_web_mode="binary",
            headers={"Content-Type": "application/grpc-web"},
        )
        assert r_grpc_custom["status"] == 200
        assert recorded[-1]["headers"]["content-type"] == "application/grpc-web"

        # GET cache key differentiates distinct raw_body_base64 payloads
        b64_a = base64.b64encode(b"alpha").decode("ascii")
        b64_b = base64.b64encode(b"bravo").decode("ascii")
        g1 = client.request(method="GET", url="/api/raw-echo", raw_body_base64=b64_a)
        g2 = client.request(method="GET", url="/api/raw-echo", raw_body_base64=b64_b)
        g3 = client.request(method="GET", url="/api/raw-echo", raw_body_base64=b64_a)
        assert g1.get("cached") is False
        assert g2.get("cached") is False
        assert g3.get("cached") is True
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_receipt_hygiene_and_sandbox_receipt_hydration(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    actor_cred = "actor-cred-value-9911"
    actor_cookie = "sid-secret-cookie-8822"
    actors = ActorManager([
        {
            "alias": "alice",
            "auth_header": "Bearer " + actor_cred,
            "cookies": {"session": actor_cookie},
            "role": "member",
        }
    ])
    client = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080",
        receipt_store=store,
        actors=actors,
        max_requests=20,
    )
    dispatcher = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path)
    try:
        # ReceiptStore omits request_body_base64 if binary payload contains an actor secret verbatim
        secret_b64 = base64.b64encode(b"\x01\x02" + actor_cred.encode("utf-8")).decode("ascii")
        redacted_rec = store.record(
            actor="alice",
            method="POST",
            url="http://127.0.0.1:18080/api/check",
            path="/api/check",
            request_body="<binary>",
            request_body_base64=secret_b64,
            status=200,
            elapsed_ms=1.5,
            secret_values=actors.all_secrets(),
        )
        assert "request_body_base64" not in redacted_rec
        reloaded = ReceiptStore(tmp_path / "receipts").get(redacted_rec["receipt_id"])
        assert "request_body_base64" not in reloaded

        # Normal receipt hydration strips sensitive headers and bounds body to <= 4096 chars
        large_body = ("echo:" + actor_cred + ":" + actor_cookie + ":") + ("Z" * 5000)
        rec_normal = store.record(
            actor="alice",
            method="GET",
            url="http://127.0.0.1:18080/api/data",
            path="/api/data",
            response_headers={
                "Content-Type": "application/json",
                "Set-Cookie": "session=" + actor_cookie,
                "Authorization": "Bearer " + actor_cred,
                "X-Custom": "safe-header-value",
            },
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            response_text=large_body,
            secret_values=actors.all_secrets(),
        )
        sbx_raw = dispatcher.dispatch(
            "run_sandbox_probe",
            {
                "runtime": "python_pure",
                "code": (
                    "def transform(inputs):\n"
                    "    r = inputs['receipts'][0]\n"
                    "    return {'decoded': {\n"
                    "        'receipt_id': r['receipt_id'],\n"
                    "        'body_len': len(r['body']),\n"
                    "        'headers': r['response_headers'],\n"
                    "        'body_head': r['body'][:120],\n"
                    "    }}\n"
                ),
                "inputs": {"receipt_refs": [rec_normal["receipt_id"]]},
                "output_contract": "decode_only",
            },
        )
        sbx = _unwrap_untrusted(sbx_raw)
        assert sbx["ok"] is True
        dec = sbx["decoded"]
        assert dec["receipt_id"] == rec_normal["receipt_id"]
        assert dec["body_len"] <= 4096
        assert actor_cred not in sbx_raw
        assert actor_cookie not in sbx_raw
        assert "<REDACTED" in dec["headers"]["Set-Cookie"]
        assert "<REDACTED" in dec["headers"]["Authorization"]
        assert dec["headers"]["X-Custom"] == "safe-header-value"
    finally:
        dispatcher.close()
        client.close()
