"""Tests for PayPulse-motivated improvements: insecure_deserialization, JWT testing/auth isolation, concurrency JSON parsing, and OOB bridge config."""
from __future__ import annotations

import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_crypto  # noqa: E402
import agentic_report  # noqa: E402
import agentic_runner  # noqa: E402
from agentic_context import build_system_prompt, build_worker_system_prompt  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_oob import LoopbackCallbackServer  # noqa: E402
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_telemetry import TelemetryLogger  # noqa: E402
from agentic_tools import RECORD_FINDING_CLASS_ENUM, ToolDispatcher  # noqa: E402


def _start_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[str, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", srv


def _stop_server(srv: ThreadingHTTPServer) -> None:
    srv.shutdown()
    srv.server_close()


def _unwrap_tool(raw: str) -> dict[str, Any]:
    start = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    end = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw.startswith(start) and raw.endswith(end)
    return json.loads(raw[len(start) : -len(end)])


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode((seg + "=" * (-len(seg) % 4)).encode("ascii"))


# ---------------------------------------------------------------------------
# 1. insecure_deserialization enum, node-serialize detection, oracle, report
# ---------------------------------------------------------------------------


def test_insecure_deserialization_detection_oracle_and_report(tmp_path: Path) -> None:
    assert "insecure_deserialization" in RECORD_FINDING_CLASS_ENUM

    raw_nd = '{"probe":"_$$ND_FUNC$$_function(){return 424242}()"}'
    b64_nd = base64.b64encode(raw_nd.encode("utf-8")).decode("ascii")
    detected_b64 = agentic_crypto.analyze_token(b64_nd, kind="auto")
    assert detected_b64["kind"] == "serialization"
    assert detected_b64["detected"] is True
    assert detected_b64["format"] == "node_serialize"
    assert detected_b64["class_name"] == "IIFE"

    class _DeserHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            if urlsplit(self.path).path != "/api/v1/settlements/batch-job":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length") or "0")
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            decoded = base64.b64decode(str(body.get("batchConfig") or "")).decode("utf-8", "replace")
            if "_$$ND_FUNC$$_" in decoded and "424242" in decoded:
                resp = json.dumps({"status": "BATCH_JOB_QUEUED", "jobConfigResult": {"probe": 424242}}).encode("utf-8")
            else:
                resp = json.dumps({"status": "BATCH_JOB_QUEUED", "jobConfigResult": {"tier": "STANDARD"}}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(resp)

    base_url, srv = _start_server(_DeserHandler)
    run_dir = tmp_path / "run-deser"
    store = ReceiptStore(run_dir)
    actors = ActorManager([{"alias": "merchant-a", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-a"}])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=25,
    )
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential")
    telemetry = TelemetryLogger(run_dir)
    dispatcher = ToolDispatcher(
        http_client=client,
        receipt_store=store,
        root_dir=run_dir,
        oracle=oracle,
        telemetry=telemetry,
    )
    try:
        ctrl = _unwrap_tool(
            dispatcher.dispatch(
                "http_request",
                {
                    "method": "POST",
                    "url": "/api/v1/settlements/batch-job",
                    "actor": "merchant-a",
                    "json_body": {"batchConfig": base64.b64encode(b'{"tier":"STANDARD"}').decode("ascii")},
                },
            )
        )
        proof = _unwrap_tool(
            dispatcher.dispatch(
                "http_request",
                {
                    "method": "POST",
                    "url": "/api/v1/settlements/batch-job",
                    "actor": "merchant-a",
                    "json_body": {"batchConfig": b64_nd},
                },
            )
        )
        recorded = json.loads(
            dispatcher.dispatch(
                "record_finding",
                {
                    "title": "Unsafe node-serialize deserialization RCE in batchConfig",
                    "class_type": "insecure_deserialization",
                    "method": "POST",
                    "url": "/api/v1/settlements/batch-job",
                    "actor_alias": "merchant-a",
                    "proof_receipt_ids": [proof["receipt_id"]],
                    "control_receipt_ids": [ctrl["receipt_id"]],
                    "evidence_value": "424242",
                    "severity": "critical",
                    "summary": "Untrusted base64 node-serialize payload executed inline via batchConfig.",
                },
            )
        )
        assert recorded["accepted"] is True
        assert recorded["class_type"] == "insecure_deserialization"
        assert dispatcher.findings[-1]["oracle_verdict"] == "VERIFIED"

        rep = agentic_report.generate_run_reports(run_dir, formats=("markdown", "sarif"))
        md_text = Path(rep["markdown_path"]).read_text(encoding="utf-8")
        sarif_doc = json.loads(Path(rep["sarif_path"]).read_text(encoding="utf-8"))
        assert "CWE-502" in md_text
        assert "OWASP A08:2021" in md_text
        assert "cwe-502" in " ".join(sarif_doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]).lower()
    finally:
        dispatcher.close()
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 2. JWT key confusion (PEM + JWKS + actor claims) & Cookie/Bearer isolation
# ---------------------------------------------------------------------------


def test_jwt_key_confusion_tooling_and_cookie_precedence_isolation(tmp_path: Path) -> None:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    pub_nums = priv.public_key().public_numbers()
    n_bytes = pub_nums.n.to_bytes((pub_nums.n.bit_length() + 7) // 8, "big")
    e_bytes = pub_nums.e.to_bytes((pub_nums.e.bit_length() + 7) // 8, "big")
    jwks_doc = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "k1",
                "n": _b64url(n_bytes),
                "e": _b64url(e_bytes),
            }
        ]
    }
    merchant_cookie_jwt = (
        f"{_b64url(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode())}."
        f"{_b64url(json.dumps({'email': 'm@alpha.test', 'role': 'merchant_user', 'secret_note': 'HIDDEN_VAL'}).encode())}."
        "valid_rs256_sig"
    )
    flag_val = "FLAG{jwt_confusion_end_to_end_ok}"
    seen_ledger_headers: list[tuple[str, str]] = []

    class _JWTConfHandler(BaseHTTPRequestHandler):
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
            if urlsplit(self.path).path == "/api/v1/auth/login":
                length = int(self.headers.get("Content-Length") or "0")
                _ = self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"token={merchant_cookie_jwt}; Path=/; HttpOnly")
                body = b'{"ok":true}'
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                return
            self._send_json(404, {"error": "not_found"})

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/api/v1/auth/public-key.pem":
                raw = pub_pem.encode("ascii")
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pem-file")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
                return
            if path == "/.well-known/jwks.json":
                self._send_json(200, jwks_doc)
                return
            if path == "/api/v1/bearer-vs-cookie-echo":
                self._send_json(
                    200,
                    {
                        "cookie": self.headers.get("Cookie", ""),
                        "has_cookie": "Cookie" in self.headers,
                        "auth": self.headers.get("Authorization", ""),
                        "has_auth": "Authorization" in self.headers,
                    },
                )
                return
            if path == "/api/v1/compliance/master-ledger":
                cookie_hdr = self.headers.get("Cookie", "")
                auth_hdr = self.headers.get("Authorization", "")
                seen_ledger_headers.append((cookie_hdr, auth_hdr))
                # Mirror PayPulse exact precedence: req.cookies.token || req.headers.authorization
                token = ""
                for part in cookie_hdr.split(";"):
                    if "=" in part:
                        ck, cv = part.strip().split("=", 1)
                        if ck == "token":
                            token = cv.strip()
                            break
                if not token and auth_hdr.startswith("Bearer "):
                    token = auth_hdr[7:].strip()
                if not token:
                    self._send_json(401, {"error": "Missing token"})
                    return
                if token == merchant_cookie_jwt:
                    self._send_json(403, {"error": "Requires role platform_auditor", "currentRole": "merchant_user"})
                    return
                parts = token.split(".")
                if len(parts) != 3:
                    self._send_json(401, {"error": "Malformed token"})
                    return
                hdr = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
                pay = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
                if str(hdr.get("alg") or "") == "HS256":
                    expected = _b64url(
                        hmac.new(
                            pub_pem.encode("utf-8"),
                            f"{parts[0]}.{parts[1]}".encode("ascii"),
                            hashlib.sha256,
                        ).digest()
                    )
                    if not hmac.compare_digest(expected, parts[2]):
                        self._send_json(401, {"error": "Invalid or forged token signature"})
                        return
                elif str(hdr.get("alg") or "").lower() != "none":
                    self._send_json(401, {"error": "Bad signature"})
                    return
                if pay.get("role") != "platform_auditor":
                    self._send_json(403, {"error": "Requires role platform_auditor", "currentRole": pay.get("role")})
                    return
                self._send_json(200, {"ledger": "VERIFIED", "flag": flag_val})
                return
            self._send_json(404, {"error": "not_found"})

    base_url, srv = _start_server(_JWTConfHandler)
    run_dir = tmp_path / "run-jwt"
    store = ReceiptStore(run_dir)
    actors = ActorManager(
        [
            {"alias": "merchant-a", "email": "m@alpha.test", "password": "pw", "role": "member", "tenant": "alpha"},
            {"alias": "bearer-user", "role": "member", "auth_header": "Bearer original-bearer-tok"},
        ],
        login_path="/api/v1/auth/login",
    )
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=30,
    )
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential")
    telemetry = TelemetryLogger(run_dir)
    dispatcher = ToolDispatcher(
        http_client=client,
        receipt_store=store,
        root_dir=run_dir,
        oracle=oracle,
        telemetry=telemetry,
    )
    try:
        assert client.authenticate_actor("merchant-a") is True
        pem_rec = _unwrap_tool(
            dispatcher.dispatch("http_request", {"method": "GET", "url": "/api/v1/auth/public-key.pem", "actor": "anon"})
        )
        jwks_rec = _unwrap_tool(
            dispatcher.dispatch("http_request", {"method": "GET", "url": "/.well-known/jwks.json", "actor": "anon"})
        )
        ctrl_rec = _unwrap_tool(
            dispatcher.dispatch(
                "http_request",
                {"method": "GET", "url": "/api/v1/compliance/master-ledger", "actor": "merchant-a"},
            )
        )
        assert ctrl_rec["status"] == 403

        # 1. Inspect actor cookie JWT safely (claims revealed, original signature/cookie/sensitive note withheld).
        actor_inspect = json.loads(dispatcher.dispatch("analyze_token", {"value": "actor:merchant-a"}))
        assert actor_inspect["valid_jwt"] is True
        assert actor_inspect["header"]["alg"] == "RS256"
        assert actor_inspect["payload"]["role"] == "merchant_user"
        assert "secret_note" not in actor_inspect["payload"]
        assert "valid_rs256_sig" not in json.dumps(actor_inspect)

        # 2. Forge HS256 key-confusion token from receipt PEM + actor claims in one zero-HTTP tool call.
        budget_before = client.budget.used
        forged_out = json.loads(
            dispatcher.dispatch(
                "analyze_token",
                {
                    "value": "actor:merchant-a",
                    "kind": "jwt_test",
                    "alg": "confusion",
                    "hmac_key": f"receipt:{pem_rec['receipt_id']}",
                    "claim_overrides": {"role": "platform_auditor"},
                },
            )
        )
        assert client.budget.used == budget_before
        assert forged_out["kind"] == "jwt_test"
        assert forged_out["alg"] == "HS256"
        assert pub_pem not in json.dumps(forged_out)
        forged_tok = forged_out["token"]

        # 3. Also test JWKS RSA JSON -> SPKI PEM conversion produces matching HMAC key sha256!
        forged_jwks = json.loads(
            dispatcher.dispatch(
                "analyze_token",
                {
                    "value": '{"email":"auditor@example.test","role":"platform_auditor"}',
                    "kind": "jwt_test",
                    "alg": "HS256",
                    "hmac_key": jwks_rec["receipt_id"],
                },
            )
        )
        assert forged_jwks["hmac_key_source"] == "jwks_rsa_pem"
        assert forged_jwks["hmac_key_sha256_8"] == forged_out["hmac_key_sha256_8"]

        # 4. Calling replay_as on merchant-a's 403 receipt with Authorization override MUST NOT leak Cookie!
        proof_replay = _unwrap_tool(
            dispatcher.dispatch(
                "replay_as",
                {
                    "receipt_id": ctrl_rec["receipt_id"],
                    "header_overrides": {"Authorization": f"Bearer {forged_tok}"},
                },
            )
        )
        assert proof_replay["replay"]["status"] == 200
        assert flag_val in proof_replay["replay"]["body_preview"]
        assert seen_ledger_headers[-1] == ("", f"Bearer {forged_tok}")

        # 5. Direct http_request as merchant-a with Authorization override also omits Cookie and reaches 200!
        proof_direct = _unwrap_tool(
            dispatcher.dispatch(
                "http_request",
                {
                    "method": "GET",
                    "url": "/api/v1/compliance/master-ledger",
                    "actor": "merchant-a",
                    "headers": {"Authorization": f"Bearer {forged_tok}"},
                    "force": True,
                },
            )
        )
        assert proof_direct["status"] == 200
        assert seen_ledger_headers[-1] == ("", f"Bearer {forged_tok}")

        # 6. Empty header stripping + Cookie overriding bearer-user suppresses Authorization cleanly.
        strip_echo = _unwrap_tool(
            dispatcher.dispatch(
                "http_request",
                {
                    "method": "GET",
                    "url": "/api/v1/bearer-vs-cookie-echo",
                    "actor": "merchant-a",
                    "headers": {"Cookie": ""},
                },
            )
        )
        assert json.loads(strip_echo["body_preview"])["has_cookie"] is False

        cookie_echo = _unwrap_tool(
            dispatcher.dispatch(
                "http_request",
                {
                    "method": "GET",
                    "url": "/api/v1/bearer-vs-cookie-echo",
                    "actor": "bearer-user",
                    "headers": {"Cookie": f"token={forged_tok}"},
                },
            )
        )
        cookie_json = json.loads(cookie_echo["body_preview"])
        assert cookie_json["has_auth"] is False
        assert cookie_json["cookie"] == f"token={forged_tok}"

        # 7. Oracle verifies jwt_weakness via DifferentialOracle -> passed_redacted_auth_override!
        recorded = json.loads(
            dispatcher.dispatch(
                "record_finding",
                {
                    "title": "JWT RS256 to HS256 algorithm confusion allows auditor escalation",
                    "class_type": "jwt_weakness",
                    "method": "GET",
                    "url": "/api/v1/compliance/master-ledger",
                    "actor_alias": "merchant-a",
                    "proof_receipt_ids": [proof_replay["replay"]["receipt_id"]],
                    "control_receipt_ids": [ctrl_rec["receipt_id"]],
                    "evidence_value": flag_val,
                    "severity": "critical",
                    "summary": "Public RSA PEM accepted as HMAC-SHA256 key on master-ledger.",
                },
            )
        )
        assert recorded["accepted"] is True
        assert recorded["class_type"] == "jwt_weakness"
        assert dispatcher.findings[-1]["oracle_verdict"] == "VERIFIED"
        telemetry_events = [
            json.loads(line)
            for line in (run_dir / "telemetry.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        verdicts = [e for e in telemetry_events if e.get("event") == "oracle_verdict"]
        assert verdicts[-1]["stages"]["stage3_clean_replay"] == "passed_redacted_auth_override"
    finally:
        dispatcher.close()
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# 3. concurrent_check JSON-string coercion & OOB host-loopback / CLI bridge
# ---------------------------------------------------------------------------


def test_concurrent_check_coerces_json_string_args_without_double_encoding(tmp_path: Path) -> None:
    seen_payloads: list[Any] = []
    seen_headers: list[str] = []
    seen_queries: list[str] = []
    lock = threading.Lock()

    class _StrictJsonHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            parsed = urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length).decode("utf-8")
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                err = b'{"error":"double_encoded_json_string"}'
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(err)
                return
            with lock:
                seen_payloads.append(obj)
                seen_headers.append(self.headers.get("X-Race-Tag", ""))
                seen_queries.append((parse_qs(parsed.query).get("mode") or [""])[0])
            ok = json.dumps({"accepted": True, "email": obj.get("email")}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(ok)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(ok)

    base_url, srv = _start_server(_StrictJsonHandler)
    run_dir = tmp_path / "run-race"
    store = ReceiptStore(run_dir)
    actors = ActorManager([{"alias": "alice", "role": "member", "auth_header": "Bearer tok-a"}])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=10,
    )
    dispatcher = ToolDispatcher(http_client=client, receipt_store=store, root_dir=run_dir)
    try:
        res = _unwrap_tool(
            dispatcher.dispatch(
                "concurrent_check",
                {
                    "url": "/api/v1/auth/signup",
                    "method": "POST",
                    "actor": "anon",
                    "headers": '{"X-Race-Tag": "burst-1"}',
                    "query": '{"mode": "parallel"}',
                    "json_body": '{"email": "race@example.test", "count": 1}',
                    "count": 3,
                },
            )
        )
        assert res["status_counts"] == {"200": 3}
        assert seen_payloads == [{"email": "race@example.test", "count": 1}] * 3
        assert seen_headers == ["burst-1", "burst-1", "burst-1"]
        assert seen_queries == ["parallel", "parallel", "parallel"]
    finally:
        dispatcher.close()
        client.close()
        _stop_server(srv)


def test_oob_bind_scope_prompts_and_runner_cli_bridge_plan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CCO_OOB_BIND_HOST", raising=False)
    monkeypatch.delenv("CCO_OOB_ADVERTISE_HOST", raising=False)

    loop_srv = LoopbackCallbackServer.from_config()
    try:
        loop_tok = loop_srv.create_token(label="default-loopback")
        assert loop_tok["bind_scope"] == "loopback"
        assert "Docker" in loop_tok["reachability_note"]
    finally:
        loop_srv.close()

    bridge_srv = LoopbackCallbackServer.from_config(bind_host="127.0.0.1", advertise_host="host.docker.internal")
    try:
        bridge_tok = bridge_srv.create_token(label="docker-bridge")
        assert bridge_tok["bind_scope"] == "bridge"
        assert "reachability_note" not in bridge_tok
        assert bridge_tok["url"].startswith("http://host.docker.internal:")
    finally:
        bridge_srv.close()

    # Prompts cover new in-band preference, jwt_test, and insecure_deserialization alongside existing tokens.
    sys_prompt = build_system_prompt(
        base_url="http://127.0.0.1:8090/",
        allowed_methods=["GET", "POST"],
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "alpha"}],
        discovery_hints=["/"],
        http_budget=80,
    )
    worker_prompt = build_worker_system_prompt(
        base_url="http://127.0.0.1:8090/",
        allowed_methods=["GET", "POST"],
        http_budget_remaining=40,
        micro_budget=8,
    )
    for prompt in (sys_prompt, worker_prompt):
        assert "jwt_test" in prompt
        assert "insecure_deserialization" in prompt
        assert "in-band" in prompt

    # Runner validates --oob-bind-host fail-closed and writes oob_listener into agentic-plan.json.
    cfg = tmp_path / "llm.json"
    cfg.write_text(
        json.dumps(
            {
                "schema": "cco-llm/1",
                "model": "local/qwen-test",
                "providers": {
                    "local": {
                        "base_url": "http://127.0.0.1:18080/v1",
                        "models": ["qwen-test"],
                        "api_key_env": "CCO_LLM_API_KEY",
                        "api_key_header": "Authorization",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="LoopbackCallbackServer"):
        agentic_runner.run_agentic_target(
            target="http://127.0.0.1:8090",
            provider_config=cfg,
            output_dir=tmp_path / "bad-plan",
            execute=False,
            oob_bind_host="0.0.0.0",
        )

    plan_path, plan = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:8090",
        provider_config=cfg,
        output_dir=tmp_path / "good-plan",
        execute=False,
        oob_bind_host="127.0.0.1",
        oob_advertise_host="host.docker.internal",
    )
    assert plan_path.is_file()
    assert plan["oob_listener"] == {
        "bind_host": "127.0.0.1",
        "advertise_host": "host.docker.internal",
        "bind_scope": "bridge",
    }
