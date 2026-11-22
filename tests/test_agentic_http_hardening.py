"""Unit and loopback integration tests for HTTP transport & session hardening."""
from __future__ import annotations

import base64
from email.parser import BytesParser
from email.policy import default as email_default_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_runner  # noqa: E402
from agentic_http import (  # noqa: E402
    DEFAULT_BROWSER_USER_AGENT,
    ActorManager,
    AgenticHTTPClient,
    BudgetExhaustedError,
    ServiceDegradationError,
    _encode_multipart_form_data,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import TOOL_SCHEMAS, ToolDispatcher  # noqa: E402


def _unwrap_tool_response(raw: str) -> dict[str, Any]:
    prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw.startswith(prefix) and raw.endswith(suffix)
    return json.loads(raw[len(prefix) : -len(suffix)])


def _parse_multipart(content_type: str, body_bytes: bytes) -> list[dict[str, Any]]:
    """Parse an HTTP multipart/form-data payload using the stdlib MIME parser."""
    raw_msg = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body_bytes
    msg = BytesParser(policy=email_default_policy).parsebytes(raw_msg)
    assert msg.is_multipart(), f"not multipart: {content_type}"
    out: list[dict[str, Any]] = []
    for part in msg.iter_parts():
        payload = part.get_payload(decode=True)
        out.append({
            "name": part.get_param("name", header="content-disposition"),
            "filename": part.get_filename(),
            "content_type": part.get_content_type(),
            "payload": payload if isinstance(payload, bytes) else b"",
            "disposition": str(part.get("Content-Disposition") or ""),
        })
    return out


def _reserve_closed_loopback_port() -> int:
    """Return an ephemeral loopback port that refuses TCP connections immediately."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# ---------------------------------------------------------------------------
# 1. Default standard desktop browser User-Agent + explicit overrides
# ---------------------------------------------------------------------------


def test_default_browser_user_agent_and_overrides(tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []
    seen_lock = threading.Lock()

    class _UAHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def _record(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b""
            with seen_lock:
                seen.append({
                    "method": method,
                    "path": urlsplit(self.path).path,
                    "ua": self.headers.get("User-Agent", ""),
                    "body": raw.decode("utf-8", errors="replace"),
                })
            if urlsplit(self.path).path == "/api/v1/access/sign-in":
                resp = json.dumps({"access_token": "tok-ua-1"}).encode("utf-8")
            else:
                resp = json.dumps({"ua": self.headers.get("User-Agent", "")}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def do_GET(self) -> None:
            self._record("GET")

        def do_POST(self) -> None:
            self._record("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _UAHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {
            "alias": "default-user",
            "email": "u1@example.test",
            "password": "PassWord123!",
            "role": "member",
        },
        {
            "alias": "custom-ua-actor",
            "email": "u2@example.test",
            "password": "PassWord456!",
            "role": "member",
            "headers": {"User-Agent": "ActorCustomUA/1.0"},
        },
    ])
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{srv.server_port}/",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=20,
    )
    try:
        # Session itself defaults to DEFAULT_BROWSER_USER_AGENT.
        assert client._get_session().headers["User-Agent"] == DEFAULT_BROWSER_USER_AGENT

        # 1. Default anon request uses DEFAULT_BROWSER_USER_AGENT (wire + receipt).
        rec_default = client.request(method="GET", url="/probe-default", actor="anon")
        assert rec_default["status"] == 200
        assert json.loads(rec_default["body"])["ua"] == DEFAULT_BROWSER_USER_AGENT
        assert rec_default["request_headers"]["User-Agent"] == DEFAULT_BROWSER_USER_AGENT

        # 2. Explicit caller User-Agent overrides default (both standard & lowercase keys).
        rec_override = client.request(
            method="GET",
            url="/probe-override",
            actor="anon",
            headers={"User-Agent": "CallerScanner/2.0"},
        )
        assert json.loads(rec_override["body"])["ua"] == "CallerScanner/2.0"

        rec_lower = client.request(
            method="GET",
            url="/probe-lower",
            actor="anon",
            headers={"user-agent": "LowerCaseAgent/3.0"},
        )
        assert json.loads(rec_lower["body"])["ua"] == "LowerCaseAgent/3.0"

        # 3. Default actor login and request use DEFAULT_BROWSER_USER_AGENT.
        rec_actor = client.request(method="GET", url="/probe-actor", actor="default-user")
        assert json.loads(rec_actor["body"])["ua"] == DEFAULT_BROWSER_USER_AGENT
        login_hits = [row for row in seen if row["path"] == "/api/v1/access/sign-in"]
        assert len(login_hits) == 1
        assert login_hits[0]["ua"] == DEFAULT_BROWSER_USER_AGENT

        # 4. Actor base_headers User-Agent wins over default (for login & requests),
        #    while explicit caller override wins over actor base_headers case-insensitively.
        assert client.authenticate_actor("custom-ua-actor", force_login=True) is True
        login_hits = [row for row in seen if row["path"] == "/api/v1/access/sign-in"]
        assert len(login_hits) == 2
        assert login_hits[1]["ua"] == "ActorCustomUA/1.0"

        rec_actor_ua = client.request(method="GET", url="/probe-actor-ua", actor="custom-ua-actor")
        assert json.loads(rec_actor_ua["body"])["ua"] == "ActorCustomUA/1.0"

        rec_caller_beats_actor = client.request(
            method="GET",
            url="/probe-caller-beats-actor",
            actor="custom-ua-actor",
            headers={"user-agent": "ExplicitCallerWins/9.9"},
        )
        assert json.loads(rec_caller_beats_actor["body"])["ua"] == "ExplicitCallerWins/9.9"
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 2. Connection-error (status == 0) degradation tracking
# ---------------------------------------------------------------------------


def test_connection_error_status_zero_degradation_and_reset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Part A: Real unreachable loopback port triggers status == 0 and trips ServiceDegradationError.
    closed_port = _reserve_closed_loopback_port()
    dead_url = f"http://127.0.0.1:{closed_port}/"
    store_dead = ReceiptStore(tmp_path / "dead")
    client_dead = AgenticHTTPClient(
        base_url=dead_url,
        receipt_store=store_dead,
        allowed_methods=("GET",),
        max_requests=20,
        timeout_s=1.0,
        max_degradation_streak=3,
    )
    try:
        r1 = client_dead.request(method="GET", url="/a", force=True)
        r2 = client_dead.request(method="GET", url="/b", force=True)
        assert r1["status"] == 0 and r1["error"]
        assert r2["status"] == 0 and r2["error"]
        with pytest.raises(ServiceDegradationError, match=r"3 consecutive.*status=0"):
            client_dead.request(method="GET", url="/c", force=True)
        # All 3 failed receipts (including the triggering one) must be persisted.
        recorded = [store_dead.get(rid)["status"] for rid in store_dead.list_ids()]
        assert recorded == [0, 0, 0]
    finally:
        client_dead.close()

    # Part B: Healthy 200 resets a status==0 streak, and mixed status==0 + 503 trips streak.
    class _HealthyHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            status = 503 if path.startswith("/degraded") else 200
            body = b'{"ok":true}' if status == 200 else b"busy"
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _HealthyHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    store_mix = ReceiptStore(tmp_path / "mix")
    client_mix = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{srv.server_port}/",
        receipt_store=store_mix,
        allowed_methods=("GET",),
        max_requests=20,
        max_degradation_streak=3,
    )
    try:
        sess = client_mix._get_session()
        real_req = sess.request
        fail_paths = {"/conn-1", "/conn-2", "/conn-3", "/conn-4"}

        def _flaky_request(method: str, url: str, **kwargs: Any) -> Any:
            if urlsplit(url).path in fail_paths:
                raise OSError("simulated connection refused")
            return real_req(method, url, **kwargs)

        monkeypatch.setattr(sess, "request", _flaky_request)

        # Two connection errors, then a healthy 200 resets the streak to 0.
        assert client_mix.request(method="GET", url="/conn-1", force=True)["status"] == 0
        assert client_mix.request(method="GET", url="/conn-2", force=True)["status"] == 0
        assert client_mix.request(method="GET", url="/healthy", force=True)["status"] == 200

        # Next two connection errors + one 503 hit streak=3 and raise ServiceDegradationError.
        assert client_mix.request(method="GET", url="/conn-3", force=True)["status"] == 0
        assert client_mix.request(method="GET", url="/conn-4", force=True)["status"] == 0
        with pytest.raises(ServiceDegradationError, match=r"3 consecutive.*status=503"):
            client_mix.request(method="GET", url="/degraded", force=True)
    finally:
        client_mix.close()
        srv.shutdown()
        srv.server_close()

    # Part C: max_degradation_streak=0 disables status==0 degradation raising cleanly.
    store_off = ReceiptStore(tmp_path / "off")
    client_off = AgenticHTTPClient(
        base_url=dead_url,
        receipt_store=store_off,
        allowed_methods=("GET",),
        max_requests=10,
        timeout_s=1.0,
        max_degradation_streak=0,
    )
    try:
        for idx in range(4):
            rec = client_off.request(method="GET", url=f"/off/{idx}", force=True)
            assert rec["status"] == 0
    finally:
        client_off.close()


# ---------------------------------------------------------------------------
# 3. Eager multi-actor session initialization (authenticate_all_actors + runner)
# ---------------------------------------------------------------------------


def test_authenticate_all_actors_eager_login_and_error_handling(tmp_path: Path) -> None:
    login_calls: list[str] = []
    seen_get_auth: list[str] = []
    login_lock = threading.Lock()

    class _AuthHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            payload = json.loads(raw)
            email = str(payload.get("email") or payload.get("username") or "")
            with login_lock:
                login_calls.append(email)
            if payload.get("password") == "valid-pass":
                resp = json.dumps({
                    "access_token": f"tok-{email}",
                    "csrf_token": f"csrf-{email}",
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"sid=cookie-{email}; Path=/")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
                return
            resp = b'{"error":"invalid_credentials"}'
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def do_GET(self) -> None:
            with login_lock:
                seen_get_auth.append(self.headers.get("Authorization", ""))
            body = json.dumps({
                "auth": self.headers.get("Authorization", ""),
                "cookie": self.headers.get("Cookie", ""),
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}/"
    store = ReceiptStore(tmp_path / "run1")
    actors = ActorManager([
        {"alias": "member-a", "email": "a@example.test", "password": "valid-pass", "role": "member"},
        {"alias": "bad-user", "email": "bad@example.test", "password": "wrong-pass", "role": "member"},
        {"alias": "admin-1", "email": "adm@example.test", "password": "valid-pass", "role": "admin"},
        {"alias": "preauth", "auth_header": "Bearer preauth-tok", "password": "valid-pass", "email": "pre@example.test"},
        {"alias": "nopass", "email": "nopass@example.test", "role": "member"},
    ])
    client = AgenticHTTPClient(
        base_url=base,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=20,
    )
    try:
        res = client.authenticate_all_actors()
        assert res == {"member-a": True, "bad-user": False, "admin-1": True}
        assert login_calls == ["a@example.test", "bad@example.test", "adm@example.test"]
        assert client.budget.used == 3

        # Browser auth state is immediately available for authenticated actors.
        a_state = actors.get_browser_auth_state("member-a")
        assert a_state["headers"]["Authorization"] == "Bearer tok-a@example.test"
        assert a_state["cookies"] == {"sid": "cookie-a@example.test"}

        # Subsequent request as member-a sends the eager bearer token and does NOT re-trigger login.
        rec = client.request(method="GET", url="/api/me", actor="member-a")
        assert seen_get_auth == ["Bearer tok-a@example.test"]
        assert "tok-a@example.test" not in rec["body"]  # Redacted in receipt storage
        assert len(login_calls) == 3

        # Re-calling authenticate_all_actors skips already authenticated actors.
        res2 = client.authenticate_all_actors()
        assert res2 == {"bad-user": False}
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()

    # BudgetExhaustedError must propagate out of authenticate_all_actors.
    store_b = ReceiptStore(tmp_path / "budget")
    actors_b = ActorManager([
        {"alias": "m1", "email": "m1@example.test", "password": "pw"},
    ])
    client_b = AgenticHTTPClient(
        base_url=base,
        receipt_store=store_b,
        actors=actors_b,
        allowed_methods=("GET",),
        max_requests=0,
    )
    try:
        with pytest.raises(BudgetExhaustedError):
            client_b.authenticate_all_actors()
    finally:
        client_b.close()

    # ServiceDegradationError must propagate out of authenticate_all_actors.
    closed_port = _reserve_closed_loopback_port()
    store_d = ReceiptStore(tmp_path / "degraded")
    actors_d = ActorManager([
        {"alias": "m1", "email": "m1@example.test", "password": "pw"},
        {"alias": "m2", "email": "m2@example.test", "password": "pw"},
    ])
    client_d = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{closed_port}/",
        receipt_store=store_d,
        actors=actors_d,
        allowed_methods=("GET",),
        max_requests=10,
        timeout_s=1.0,
        max_degradation_streak=2,
    )
    try:
        with pytest.raises(ServiceDegradationError):
            client_d.authenticate_all_actors()
    finally:
        client_d.close()

    # Unexpected per-actor error (e.g., ScopeViolationError on excluded login_path) returns False.
    store_s = ReceiptStore(tmp_path / "excluded")
    actors_s = ActorManager([
        {"alias": "m1", "email": "m1@example.test", "password": "pw"},
    ])
    client_s = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{closed_port}/",
        receipt_store=store_s,
        actors=actors_s,
        allowed_methods=("GET",),
        excluded_paths=("/api/v1/access/sign-in",),
    )
    try:
        assert client_s.authenticate_all_actors() == {"m1": False}
    finally:
        client_s.close()


def test_runner_eagerly_authenticates_actors_unless_resuming(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login_seen: list[str] = []
    lock = threading.Lock()

    class _TargetHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            data = json.loads(raw)
            with lock:
                login_seen.append(str(data.get("email") or ""))
            resp = json.dumps({"access_token": f"tok-{data.get('email', '')}"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def do_GET(self) -> None:
            body = b"<html><body>home</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class _ProviderHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            resp = {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call_finish_1",
                                    "type": "function",
                                    "function": {
                                        "name": "finish",
                                        "arguments": json.dumps({"summary": "done", "untested_areas": []}),
                                    },
                                }
                            ],
                        }
                    }
                ],
                "usage": {"prompt_tokens": 80, "completion_tokens": 15, "total_tokens": 95},
            }
            payload = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    target_srv = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    prov_srv = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    threading.Thread(target=target_srv.serve_forever, daemon=True).start()
    threading.Thread(target=prov_srv.serve_forever, daemon=True).start()

    cfg = tmp_path / "llm.json"
    cfg.write_text(
        json.dumps({
            "schema": "cco-llm/1",
            "model": "local/test-model",
            "providers": {
                "local": {
                    "base_url": f"http://127.0.0.1:{prov_srv.server_port}/v1",
                    "models": ["test-model"],
                    "api_key_env": "TEST_EAGER_KEY",
                    "api_key_header": "Authorization",
                }
            },
        }),
        encoding="utf-8",
    )
    creds = tmp_path / "creds.json"
    creds.write_text(
        json.dumps({
            "target_url": f"http://127.0.0.1:{target_srv.server_port}/",
            "test_accounts": [
                {"alias": "member-1", "email": "m1@example.test", "password": "secret-1", "role": "member", "tenant": "t1"},
                {"alias": "member-2", "email": "m2@example.test", "password": "secret-2", "role": "member", "tenant": "t2"},
            ],
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("TEST_EAGER_KEY", "dummy-local-key")

    try:
        # 1. Fresh run (resume=False): eagerly authenticates both credentialed actors before investigator.run().
        _, manifest_fresh = agentic_runner.run_agentic_target(
            credentials_file=creds,
            provider_config=cfg,
            output_dir=tmp_path / "run-fresh",
            execute=True,
            resume=False,
            max_turns=3,
        )
        assert manifest_fresh["status"] == "finished"
        assert sorted(login_seen) == ["m1@example.test", "m2@example.test"]

        # 2. Resume run (resume=True): does NOT call authenticate_all_actors eagerly.
        login_seen.clear()
        _, manifest_resume = agentic_runner.run_agentic_target(
            credentials_file=creds,
            provider_config=cfg,
            output_dir=tmp_path / "run-resume",
            execute=True,
            resume=True,
            max_turns=3,
        )
        assert manifest_resume["status"] == "finished"
        assert login_seen == []

        # 3. Unreachable target during eager auth surfaces status="service_degraded".
        closed_port = _reserve_closed_loopback_port()
        dead_creds = tmp_path / "dead-creds.json"
        dead_creds.write_text(
            json.dumps({
                "target_url": f"http://127.0.0.1:{closed_port}/",
                "test_accounts": [
                    {"alias": "member-1", "email": "m1@example.test", "password": "secret-1", "role": "member"},
                    {"alias": "member-2", "email": "m2@example.test", "password": "secret-2", "role": "member"},
                ],
            }),
            encoding="utf-8",
        )
        _, manifest_degraded = agentic_runner.run_agentic_target(
            credentials_file=dead_creds,
            provider_config=cfg,
            output_dir=tmp_path / "run-degraded",
            execute=True,
            resume=False,
            max_degradation_streak=2,
            max_turns=3,
        )
        assert manifest_degraded["status"] == "service_degraded"
        assert manifest_degraded["error"] == "ServiceDegradationError"
    finally:
        prov_srv.shutdown()
        prov_srv.server_close()
        target_srv.shutdown()
        target_srv.server_close()


# ---------------------------------------------------------------------------
# 4. Multipart/form-data encoding, upload, auth/CSRF retries, and tool dispatch
# ---------------------------------------------------------------------------


def test_encode_multipart_form_data_unit_and_validation() -> None:
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe\xfd"
    body, ct, preview = _encode_multipart_form_data(
        [
            {
                "field": "doc\r\nX-Injected: 1",
                "filename": 'report"2026.txt\r\n',
                "content": "hello world",
                "content_type": "text/plain\r\nX-Bad: yes",
            },
            {
                "field": "avatar",
                "filename": "pic.png",
                "content_base64": base64.b64encode(png_bytes).decode("ascii"),
                "content_type": "image/png",
            },
        ],
        form_fields={"title": "Demo Upload", "category": "docs"},
    )
    assert ct.startswith("multipart/form-data; boundary=")
    parts = _parse_multipart(ct, body)
    assert len(parts) == 4

    # Form fields appear before file parts.
    assert parts[0]["name"] == "title" and parts[0]["filename"] is None and parts[0]["payload"] == b"Demo Upload"
    assert parts[1]["name"] == "category" and parts[1]["filename"] is None and parts[1]["payload"] == b"docs"

    # File 1: CRLF stripped from field/filename/content_type; quote safely escaped in filename header.
    assert parts[2]["name"] == "docX-Injected: 1"
    assert parts[2]["filename"] == 'report"2026.txt'
    assert parts[2]["content_type"] == "text/plainx-bad: yes"
    assert parts[2]["payload"] == b"hello world"
    assert b"\r\nX-Injected:" not in body
    assert b"\r\nX-Bad:" not in body
    assert b'filename="report\\"2026.txt"' in body

    # File 2: exact binary bytes preserved.
    assert parts[3]["name"] == "avatar"
    assert parts[3]["filename"] == "pic.png"
    assert parts[3]["content_type"] == "image/png"
    assert parts[3]["payload"] == png_bytes

    # Body preview is compact metadata summary and never contains raw binary bytes.
    assert "multipart/form-data " in preview
    summary = json.loads(preview.split("multipart/form-data ", 1)[1])
    assert summary["fields"] == ["title", "category"]
    assert summary["files"] == [
        {"field": "docX-Injected: 1", "filename": 'report"2026.txt', "content_type": "text/plainX-Bad: yes", "bytes": 11},
        {"field": "avatar", "filename": "pic.png", "content_type": "image/png", "bytes": len(png_bytes)},
    ]
    assert "IHDR" not in preview
    assert "hello world" not in preview

    # Defaults when optional file keys are omitted.
    d_body, d_ct, _ = _encode_multipart_form_data([{"content": "abc"}])
    d_parts = _parse_multipart(d_ct, d_body)
    assert d_parts[0]["name"] == "file"
    assert d_parts[0]["filename"] == "upload.bin"
    assert d_parts[0]["content_type"] == "application/octet-stream"
    assert d_parts[0]["payload"] == b"abc"

    # Security & bounds rejections.
    with pytest.raises(ValueError, match="NUL"):
        _encode_multipart_form_data([{"field": "f\x00x", "content": "a"}])
    with pytest.raises(ValueError, match="NUL"):
        _encode_multipart_form_data([{"filename": "a\x00.png", "content": "a"}])
    with pytest.raises(ValueError, match="NUL"):
        _encode_multipart_form_data([{"content_type": "text/plain\x00", "content": "a"}])
    with pytest.raises(ValueError, match="NUL"):
        _encode_multipart_form_data([{"content": "a"}], form_fields={"bad\x00k": "v"})
    with pytest.raises(ValueError, match="exceeds limit of 8"):
        _encode_multipart_form_data([{"content": "x"} for _ in range(9)])
    with pytest.raises(ValueError, match="per-file limit"):
        _encode_multipart_form_data([{"content": "A" * (256 * 1024 + 1)}])
    with pytest.raises(ValueError, match="per-file limit"):
        _encode_multipart_form_data([
            {"content_base64": base64.b64encode(b"B" * (256 * 1024 + 1)).decode("ascii")}
        ])
    with pytest.raises(ValueError, match="total limit"):
        _encode_multipart_form_data([
            {"filename": f"f{i}.bin", "content": "C" * (200 * 1024)} for i in range(3)
        ])
    with pytest.raises(ValueError, match="invalid base64"):
        _encode_multipart_form_data([{"content_base64": "!!!not-base64!!!"}])
    with pytest.raises(ValueError, match="cannot specify both"):
        _encode_multipart_form_data([{"content": "hi", "content_base64": "aGk="}])


def test_multipart_upload_live_server_auth_csrf_retry_and_tool_dispatcher(tmp_path: Path) -> None:
    uploads: list[dict[str, Any]] = []
    state = {"upload_attempts": 0, "csrf_attempts": 0}
    lock = threading.Lock()

    class _UploadHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/api/v1/access/session":
                resp = json.dumps({"csrf_token": "fresh-csrf-token-2"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-CSRF-Token", "fresh-csrf-token-2")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
                return
            resp = json.dumps({"method": "GET", "path": path}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length) if length > 0 else b""
            ct = self.headers.get("Content-Type", "")
            auth = self.headers.get("Authorization", "")
            csrf = self.headers.get("X-CSRF-Token", "")

            if path == "/api/v1/access/sign-in":
                resp = json.dumps({
                    "access_token": "fresh-bearer-2",
                    "csrf_token": "initial-csrf-1",
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
                return

            if path == "/upload-auth-retry":
                with lock:
                    state["upload_attempts"] += 1
                    attempt = state["upload_attempts"]
                if attempt == 1 or auth != "Bearer fresh-bearer-2":
                    resp = b'{"error":"token_expired"}'
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp)))
                    self.end_headers()
                    self.wfile.write(resp)
                    return

            if path == "/upload-csrf-retry":
                with lock:
                    state["csrf_attempts"] += 1
                if csrf != "fresh-csrf-token-2":
                    resp = b'{"error":"invalid csrf token"}'
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp)))
                    self.end_headers()
                    self.wfile.write(resp)
                    return

            parsed_parts = (
                _parse_multipart(ct, raw_body)
                if ct.lower().startswith("multipart/form-data")
                else []
            )
            with lock:
                uploads.append({
                    "path": path,
                    "content_type": ct,
                    "auth": auth,
                    "csrf": csrf,
                    "parts": parsed_parts,
                })
            resp = json.dumps({
                "ok": True,
                "path": path,
                "part_count": len(parsed_parts),
                "filenames": [p["filename"] for p in parsed_parts if p["filename"]],
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _UploadHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {
            "alias": "uploader",
            "email": "up@example.test",
            "password": "upload-password",
            "auth_header": "Bearer stale-bearer-1",
            "csrf_token": "stale-csrf-1",
        }
    ])
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{srv.server_port}/",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=30,
    )
    disp = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path)

    raw_bin = b"\x00\x01\x02BINARY_SECRET_BLOB\xff\xfe"
    b64_bin = base64.b64encode(raw_bin).decode("ascii")

    try:
        # 1. ToolDispatcher dispatches http_request with files, inferring method="POST".
        out_raw = disp.dispatch(
            "http_request",
            {
                "url": "/upload-tool",
                "actor": "anon",
                "form_body": {"folder": "avatars"},
                "files": [
                    {"field": "note", "filename": "hello.txt", "content": "plain-text-body", "content_type": "text/plain"},
                    {"field": "img", "filename": "raw.bin", "content_base64": b64_bin, "content_type": "application/octet-stream"},
                ],
            },
        )
        preview = _unwrap_tool_response(out_raw)
        assert preview["status"] == 200
        assert preview["method"] == "POST"
        assert len(uploads) == 1
        assert [p["name"] for p in uploads[0]["parts"]] == ["folder", "note", "img"]
        assert uploads[0]["parts"][0]["payload"] == b"avatars"
        assert uploads[0]["parts"][1]["payload"] == b"plain-text-body"
        assert uploads[0]["parts"][2]["payload"] == raw_bin

        # Stored receipt must NOT dump raw binary content.
        rec_on_disk = store.get(preview["receipt_id"])
        assert rec_on_disk["request_body"].startswith("multipart/form-data ")
        assert "BINARY_SECRET_BLOB" not in rec_on_disk["request_body"]
        assert "raw.bin" in rec_on_disk["request_body"]

        # 2. Empty files=[] with omitted method stays GET.
        out_empty = disp.dispatch("http_request", {"url": "/just-get", "actor": "anon", "files": []})
        empty_preview = _unwrap_tool_response(out_empty)
        assert empty_preview["method"] == "GET"
        assert empty_preview["status"] == 200

        # 3. Invalid files inputs return structured JSON tool errors cleanly.
        for bad_files in ("not-a-list", {"filename": "a.txt"}, ["not-a-dict"], [123]):
            err_out = json.loads(disp.dispatch("http_request", {"url": "/upload-tool", "files": bad_files}))
            assert err_out["error"] == "ValueError"
            assert "files" in err_out["message"].lower()

        # 4. Explicit Content-Type override wins when caller sets custom content-type.
        rec_custom_ct = client.request(
            method="POST",
            url="/upload-custom-ct",
            actor="anon",
            headers={"content-type": "multipart/mixed; boundary=custom-override"},
            files=[{"filename": "a.txt", "content": "ok"}],
        )
        assert rec_custom_ct["status"] == 200
        assert uploads[-1]["content_type"] == "multipart/mixed; boundary=custom-override"

        # 5. Multipart upload survives 401 auto re-auth cleanly with intact payload bytes.
        rec_401 = client.request(
            method="POST",
            url="/upload-auth-retry",
            actor="uploader",
            form_body={"step": "reauth"},
            files=[{"field": "bin", "filename": "retry.bin", "content_base64": b64_bin}],
        )
        assert rec_401["status"] == 200
        assert uploads[-1]["path"] == "/upload-auth-retry"
        assert uploads[-1]["auth"] == "Bearer fresh-bearer-2"
        assert uploads[-1]["parts"][1]["payload"] == raw_bin

        # 6. Multipart upload survives 403 CSRF refresh cleanly with intact payload bytes.
        rec_403 = client.request(
            method="POST",
            url="/upload-csrf-retry",
            actor="uploader",
            form_body={"step": "csrf"},
            files=[{"field": "bin", "filename": "csrf.bin", "content_base64": b64_bin}],
        )
        assert rec_403["status"] == 200
        assert uploads[-1]["path"] == "/upload-csrf-retry"
        assert uploads[-1]["csrf"] == "fresh-csrf-token-2"
        assert uploads[-1]["parts"][1]["payload"] == raw_bin
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_tool_schemas_size_and_files_property_bounds() -> None:
    serialized = json.dumps(TOOL_SCHEMAS, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(serialized) <= 16_384
    assert len(TOOL_SCHEMAS) == 11

    http_tool = next(t["function"] for t in TOOL_SCHEMAS if t["function"]["name"] == "http_request")
    files_prop = http_tool["parameters"]["properties"]["files"]
    assert files_prop["type"] == "array"
    assert files_prop["items"] == {"type": "object"}
    assert len(files_prop["description"]) <= 140

    for tool in TOOL_SCHEMAS:
        fn = tool["function"]
        assert len(fn["description"]) <= 140
    for prop_name, prop_schema in http_tool["parameters"].get("properties", {}).items():
        desc = prop_schema.get("description")
        if isinstance(desc, str):
            assert len(desc) <= 140, f"http_request.{prop_name} description exceeds 140 chars ({len(desc)})"
