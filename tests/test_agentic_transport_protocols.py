"""Unit and loopback integration tests for SSE, max_rps, redirects, actor auth, WebSocket, and gRPC-Web."""
from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import time
from typing import Any
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import agentic_runner  # noqa: E402
from agentic_http import (  # noqa: E402
    DEFAULT_BROWSER_USER_AGENT,
    ActorManager,
    AgenticHTTPClient,
    MethodNotAllowedError,
    ScopeViolationError,
    _read_sse_bounded,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from kryon_core.protocol import (  # noqa: E402
    decode_grpc_web_frames,
    encode_client_frame,
    encode_grpc_web_frame,
    encode_grpc_web_trailers,
    is_grpc_web_content_type,
    probe_websocket,
)

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ---------------------------------------------------------------------------
# 1. Safe Bounded SSE (text/event-stream) Response Reading
# ---------------------------------------------------------------------------


def test_sse_open_ended_stream_returns_200_quickly_without_degradation(tmp_path: Path) -> None:
    stop_event = threading.Event()

    class _SSEHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/events-raw":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                try:
                    self.wfile.write(b"event: status\ndata: hello-sse-1\n\n")
                    self.wfile.flush()
                    self.wfile.write(b"data: hello-sse-2\n\n")
                    self.wfile.flush()
                    # Hold connection open like a real live SSE endpoint until test ends.
                    stop_event.wait(timeout=10.0)
                except OSError:
                    pass
                return

            if path == "/events-chunked":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                try:
                    chunk = b"event: tick\ndata: chunked-sse-1\n\n"
                    self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n")
                    self.wfile.flush()
                    stop_event.wait(timeout=10.0)
                except OSError:
                    pass
                return

            if path == "/events-flood":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                line = b"data: " + (b"X" * 200) + b"\n\n"
                try:
                    for _ in range(300):
                        if stop_event.is_set():
                            break
                        self.wfile.write(line)
                        self.wfile.flush()
                except OSError:
                    pass
                return

            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SSEHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{srv.server_port}/",
        receipt_store=store,
        allowed_methods=("GET",),
        max_requests=20,
        timeout_s=15.0,
        max_degradation_streak=2,
    )
    try:
        # 1. Open-ended non-chunked SSE returns 200 quickly (< 3s) with captured events.
        t0 = time.monotonic()
        rec1 = client.request(method="GET", url="/events-raw", force=True)
        dt1 = time.monotonic() - t0
        assert rec1["status"] == 200
        assert rec1["error"] == ""
        assert rec1["content_type"] == "text/event-stream"
        assert "hello-sse-1" in rec1["body"]
        assert "hello-sse-2" in rec1["body"]
        assert dt1 < 3.0, f"SSE read took too long: {dt1:.2f}s"

        # 2. Chunked open-ended SSE also returns 200 quickly and does NOT trip degradation streak=2.
        t1 = time.monotonic()
        rec2 = client.request(method="GET", url="/events-chunked", force=True)
        dt2 = time.monotonic() - t1
        assert rec2["status"] == 200
        assert rec2["error"] == ""
        assert "chunked-sse-1" in rec2["body"]
        assert dt2 < 3.0, f"Chunked SSE read took too long: {dt2:.2f}s"

        # 3. High-volume continuous SSE stream stops cleanly at 16384-byte cap.
        t2 = time.monotonic()
        rec3 = client.request(method="GET", url="/events-flood", force=True)
        dt3 = time.monotonic() - t2
        assert rec3["status"] == 200
        assert rec3["response_length"] == 16384
        assert dt3 < 3.0
    finally:
        stop_event.set()
        client.close()
        srv.shutdown()
        srv.server_close()


def test_read_sse_bounded_unit_timeout_and_cap() -> None:
    class _FakeRaw:
        chunked = False

        def __init__(self) -> None:
            self.calls = 0
            self.closed = False

        def read1(self, amt: int, decode_content: bool = False) -> bytes:
            _ = amt, decode_content
            self.calls += 1
            if self.calls == 1:
                return b"data: first\n\n"
            raise TimeoutError("simulated idle sse timeout")

        def close(self) -> None:
            self.closed = True

    class _FakeResp:
        def __init__(self, raw: Any) -> None:
            self.raw = raw

    fake_raw = _FakeRaw()
    data = _read_sse_bounded(_FakeResp(fake_raw), max_bytes=1024, max_duration_s=1.0)
    assert data == b"data: first\n\n"
    assert fake_raw.closed is True


# ---------------------------------------------------------------------------
# 2. Configurable Thread-Safe RPS Rate Limiter (--max-rps)
# ---------------------------------------------------------------------------


def test_max_rps_validation_monotonic_pacing_and_runner_plan(tmp_path: Path) -> None:
    class _OkHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}/"
    store = ReceiptStore(tmp_path / "rps")

    # Invalid max_rps values rejected fail-closed.
    for bad in (-0.5, float("nan"), float("inf"), float("-inf"), True):
        with pytest.raises(ValueError, match="max_rps"):
            AgenticHTTPClient(base_url=base, receipt_store=store, max_rps=bad)  # type: ignore[arg-type]

    # Deterministic injected clock + sleep recorder.
    clock = [100.0]
    sleeps: list[float] = []

    def _fake_monotonic() -> float:
        return clock[0]

    def _fake_sleep(sec: float) -> None:
        sleeps.append(round(sec, 6))
        clock[0] += sec

    client = AgenticHTTPClient(
        base_url=base,
        receipt_store=store,
        allowed_methods=("GET",),
        max_requests=20,
        max_rps=4.0,  # 0.25s between requests
        _sleep_fn=_fake_sleep,
        _monotonic_fn=_fake_monotonic,
    )
    try:
        for i in range(4):
            rec = client.request(method="GET", url=f"/p/{i}", force=True)
            assert rec["status"] == 200
        # 1st call runs immediately; calls 2..4 sleep 0.25s each.
        assert sleeps == [0.25, 0.25, 0.25]

        # If wall time jumps forward beyond next_allowed_at, next call does not sleep.
        clock[0] += 5.0
        rec5 = client.request(method="GET", url="/p/after-gap", force=True)
        assert rec5["status"] == 200
        assert sleeps == [0.25, 0.25, 0.25]
    finally:
        client.close()

    # Disabled max_rps=0.0 never invokes _sleep_fn.
    zero_sleeps: list[float] = []
    client_zero = AgenticHTTPClient(
        base_url=base,
        receipt_store=ReceiptStore(tmp_path / "rps-zero"),
        allowed_methods=("GET",),
        max_requests=10,
        max_rps=0.0,
        _sleep_fn=lambda s: zero_sleeps.append(s),
    )
    try:
        for i in range(3):
            assert client_zero.request(method="GET", url=f"/z/{i}", force=True)["status"] == 200
        assert zero_sleeps == []
    finally:
        client_zero.close()
        srv.shutdown()
        srv.server_close()

    # Runner plan records limits["max_rps"] via both Python API and CLI --max-rps.
    cfg = REPO_ROOT / "config" / "llm.example.json"
    plan_path, plan = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18080/",
        provider_config=cfg,
        output_dir=tmp_path / "plan-api",
        max_rps=2.5,
        execute=False,
    )
    assert plan_path.is_file()
    assert plan["limits"]["max_rps"] == 2.5

    with pytest.raises(ValueError, match="max_rps"):
        agentic_runner.run_agentic_target(
            target="http://127.0.0.1:18080/",
            provider_config=cfg,
            output_dir=tmp_path / "plan-bad",
            max_rps=-1.0,
            execute=False,
        )

    cli_out = tmp_path / "plan-cli"
    rc = agentic_runner.main([
        "--target", "http://127.0.0.1:18080/",
        "--provider-config", str(cfg),
        "--output-dir", str(cli_out),
        "--max-rps", "3.25",
    ])
    assert rc == 0
    cli_plan = json.loads((cli_out / "agentic-plan.json").read_text(encoding="utf-8"))
    assert cli_plan["limits"]["max_rps"] == 3.25

    with pytest.raises(SystemExit):
        agentic_runner.main([
            "--target", "http://127.0.0.1:18080/",
            "--provider-config", str(cfg),
            "--output-dir", str(tmp_path / "plan-cli-bad"),
            "--max-rps", "-5",
        ])


# ---------------------------------------------------------------------------
# 3. Scope-Locked Optional follow_redirects
# ---------------------------------------------------------------------------


def test_follow_redirects_in_scope_cookies_method_semantics_and_scope_lock(tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []
    lock = threading.Lock()

    class _RedirectHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def _handle(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
            parsed = urlsplit(self.path)
            path = parsed.path
            with lock:
                seen.append({
                    "method": method,
                    "path": path,
                    "query": parsed.query,
                    "cookie": self.headers.get("Cookie", ""),
                    "body": raw,
                })

            if path == "/app/start":
                self.send_response(302)
                self.send_header("Set-Cookie", "hop1=alpha-cookie; Path=/")
                self.send_header("Location", "step2")  # relative to /app/start -> /app/step2
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if path == "/app/step2":
                self.send_response(303)
                self.send_header("Set-Cookie", "hop2=beta-cookie; Path=/")
                self.send_header("Location", "/final?done=1")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if path == "/final":
                body = json.dumps({
                    "method": method,
                    "cookie": self.headers.get("Cookie", ""),
                    "query": parsed.query,
                    "body": raw,
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/preserve-307":
                self.send_response(307)
                self.send_header("Location", "/preserve-target")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if path == "/preserve-target":
                body = json.dumps({"method": method, "body": raw}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/open-redirect":
                self.send_response(302)
                self.send_header("Location", "https://evil.example/phish")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if path == "/scheme-rel-redirect":
                self.send_response(302)
                self.send_header("Location", "//evil.example/steal")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if path == "/to-excluded":
                self.send_response(302)
                self.send_header("Location", "/logout")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if path == "/to-ws":
                self.send_response(302)
                self.send_header("Location", f"ws://127.0.0.1:{self.server.server_port}/ws")  # type: ignore[attr-defined]
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if path == "/loop":
                self.send_response(302)
                self.send_header("Location", "/loop")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "user-a", "cookies": {"base": "baseval-1234"}},
    ])
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{srv.server_port}/",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=50,
        excluded_paths=("/logout",),
    )
    try:
        # 1. Default follow_redirects=False returns 302 intact (preserves open_redirect detection).
        rec_no_follow = client.request(method="GET", url="/open-redirect", actor="anon")
        assert rec_no_follow["status"] == 302
        assert rec_no_follow["redirect_location"] == "https://evil.example/phish"
        assert "redirect_chain" not in rec_no_follow

        # 2. follow_redirects=True across POST -> 302 (switches to GET, drops body, preserves cookies) -> 303 -> 200.
        seen.clear()
        rec_chain = client.request(
            method="POST",
            url="/app/start",
            actor="user-a",
            json_body={"action": "login"},
            follow_redirects=True,
        )
        assert rec_chain["status"] == 200
        assert len(rec_chain["redirect_chain"]) == 2
        assert rec_chain["redirect_chain"][0]["status"] == 302
        assert rec_chain["redirect_chain"][1]["status"] == 303
        assert [row["method"] for row in seen] == ["POST", "GET", "GET"]
        assert [row["path"] for row in seen] == ["/app/start", "/app/step2", "/final"]
        assert seen[1]["body"] == ""
        assert "hop1=alpha-cookie" in seen[1]["cookie"]
        assert "base=baseval-1234" in seen[1]["cookie"]
        assert "hop1=alpha-cookie" in seen[2]["cookie"]
        assert "hop2=beta-cookie" in seen[2]["cookie"]

        # 3. 307 preserves POST method and body intact.
        seen.clear()
        rec_307 = client.request(
            method="POST",
            url="/preserve-307",
            actor="anon",
            json_body={"keep": "payload"},
            follow_redirects=True,
        )
        assert rec_307["status"] == 200
        assert json.loads(rec_307["body"]) == {"method": "POST", "body": '{"keep": "payload"}'}
        assert len(rec_307["redirect_chain"]) == 1

        # 3b. Anon follow_redirects preserves cookies across hops in-chain without leaking to later anon requests.
        seen.clear()
        rec_anon_chain = client.request(
            method="GET",
            url="/app/start",
            actor="anon",
            follow_redirects=True,
        )
        assert rec_anon_chain["status"] == 200
        assert "hop1=alpha-cookie" in seen[1]["cookie"]
        assert "hop2=beta-cookie" in seen[2]["cookie"]
        seen.clear()
        rec_anon_after = client.request(method="GET", url="/final", actor="anon", force=True)
        assert rec_anon_after["status"] == 200
        assert seen[0]["cookie"] == ""

        # 4. Out-of-scope redirect, scheme-relative redirect, excluded-path redirect, and ws:// redirect all fail closed!
        with pytest.raises(ScopeViolationError):
            client.request(method="GET", url="/open-redirect", actor="anon", force=True, follow_redirects=True)
        with pytest.raises(ScopeViolationError):
            client.request(method="GET", url="/scheme-rel-redirect", actor="anon", force=True, follow_redirects=True)
        seen.clear()
        with pytest.raises(ScopeViolationError):
            client.request(method="GET", url="/to-excluded", actor="anon", force=True, follow_redirects=True)
        assert [row["path"] for row in seen] == ["/to-excluded"]  # /logout never hit!
        with pytest.raises(ScopeViolationError):
            client.request(method="GET", url="/to-ws", actor="anon", force=True, follow_redirects=True)

        # 5. Infinite redirect loop stops cleanly after max_redirects=5 hops.
        seen.clear()
        rec_loop = client.request(method="GET", url="/loop", actor="anon", force=True, follow_redirects=True)
        assert rec_loop["status"] == 302
        assert len(rec_loop["redirect_chain"]) == 5
        assert len(seen) == 6  # 1 initial + 5 redirect hops
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 4. Enhanced Actor Session & Login Flows (local_storage, CSRF harvest, GraphQL)
# ---------------------------------------------------------------------------


def test_actor_local_storage_redaction_and_browser_auth_state(tmp_path: Path) -> None:
    class _EchoHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            body = json.dumps({"leaked": "ls-super-secret-value-9876"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    actors = ActorManager([
        {
            "alias": "spa-user",
            "role": "member",
            "local_storage": {
                "app_session": "ls-super-secret-value-9876",
                "short_flag": "1",
            },
        },
        {
            "alias": "plain-user",
            "role": "member",
            "cookies": {"sid": "cookie-plain-1234"},
        },
    ])
    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{srv.server_port}/",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET",),
    )
    try:
        spa = actors.get("spa-user")
        assert spa.authenticated is True
        assert spa.local_storage == {"app_session": "ls-super-secret-value-9876", "short_flag": "1"}

        secrets = spa.collect_secrets()
        assert "ls-super-secret-value-9876" in secrets
        assert "1" not in secrets  # len < 4 excluded

        browser_state = actors.get_browser_auth_state("spa-user")
        assert browser_state["cookies"] == {}
        assert browser_state["headers"] == {}
        assert browser_state["local_storage"] == {
            "app_session": "ls-super-secret-value-9876",
            "short_flag": "1",
        }
        # Mutating returned local_storage dict does not mutate internal state.
        browser_state["local_storage"]["app_session"] = "tampered"
        assert actors.get_browser_auth_state("spa-user")["local_storage"]["app_session"] == "ls-super-secret-value-9876"

        # Actor without local_storage preserves exact backward-compatible keys.
        plain_state = actors.get_browser_auth_state("plain-user")
        assert plain_state == {"cookies": {"sid": "cookie-plain-1234"}, "headers": {}}

        # Receipts redact local_storage secret values!
        rec = client.request(method="GET", url="/echo", actor="spa-user")
        assert "ls-super-secret-value-9876" not in rec["body"]
        assert "<REDACTED_SECRET:" in rec["body"]
        raw_disk = (tmp_path / "receipts" / f"{rec['receipt_id']}.json").read_text(encoding="utf-8")
        assert "ls-super-secret-value-9876" not in raw_disk
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_authenticate_actor_csrf_harvest_and_graphql_login(tmp_path: Path) -> None:
    events: list[dict[str, Any]] = []
    lock = threading.Lock()

    class _LoginHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            with lock:
                events.append({"method": "GET", "path": path})
            if path == "/login-with-get":
                body = b'<html><head><meta content="csrf-from-login-page" name="csrf-token"></head></html>'
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", "csrftoken=csrf-from-login-page; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/login-post-only":
                self.send_response(405)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/":
                body = b"<html><body>home</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", "csrftoken=csrf-from-root; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            csrf = self.headers.get("X-CSRF-Token", "")
            cookie = self.headers.get("Cookie", "")
            with lock:
                events.append({
                    "method": "POST",
                    "path": path,
                    "csrf": csrf,
                    "cookie": cookie,
                    "body": raw,
                })

            if path == "/login-with-get":
                if csrf != "csrf-from-login-page" or "csrftoken=csrf-from-login-page" not in cookie:
                    body = b'{"error":"invalid csrf token"}'
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = json.dumps({"access_token": "tok-csrf-ok-1"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/login-post-only":
                if csrf != "csrf-from-root" or "csrftoken=csrf-from-root" not in cookie:
                    body = b'{"error":"missing CSRF verification"}'
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = json.dumps({"access_token": "tok-root-csrf-ok-2"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/graphql":
                doc = json.loads(raw)
                variables = doc.get("variables") or {}
                if "mutation Login" in str(doc.get("query") or "") and variables.get("password") == "good-gql-pass":
                    body = json.dumps({
                        "data": {
                            "login": {
                                "accessToken": "tok-gql-bearer-99",
                                "csrfToken": "csrf-gql-99",
                            }
                        }
                    }).encode("utf-8")
                else:
                    body = json.dumps({
                        "data": {"login": None},
                        "errors": [{"message": "Invalid credentials"}],
                    }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LoginHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}/"

    try:
        # Case A: Pre-login CSRF harvest via GET login_path -> retry POST succeeds.
        actors_a = ActorManager(
            [{"alias": "u1", "email": "u1@example.test", "password": "pw1"}],
            login_path="/login-with-get",
        )
        client_a = AgenticHTTPClient(base_url=base, receipt_store=ReceiptStore(tmp_path / "a"), actors=actors_a)
        try:
            assert client_a.authenticate_actor("u1") is True
            assert actors_a.get("u1").access_token == "tok-csrf-ok-1"
            assert actors_a.get("u1").csrf_token == "csrf-from-login-page"
            assert [(e["method"], e["path"]) for e in events] == [
                ("POST", "/login-with-get"),
                ("GET", "/login-with-get"),
                ("POST", "/login-with-get"),
            ]
        finally:
            client_a.close()

        # Case B: GET login_path returns 405 -> falls back to GET "/" -> retry POST succeeds.
        events.clear()
        actors_b = ActorManager(
            [{"alias": "u2", "email": "u2@example.test", "password": "pw2"}],
            login_path="/login-post-only",
        )
        client_b = AgenticHTTPClient(base_url=base, receipt_store=ReceiptStore(tmp_path / "b"), actors=actors_b)
        try:
            assert client_b.authenticate_actor("u2") is True
            assert actors_b.get("u2").access_token == "tok-root-csrf-ok-2"
            assert [(e["method"], e["path"]) for e in events] == [
                ("POST", "/login-post-only"),
                ("GET", "/login-post-only"),
                ("GET", "/"),
                ("POST", "/login-post-only"),
            ]
        finally:
            client_b.close()

        # Case C: GraphQL login mutation with nested data.login.accessToken extraction & error handling.
        events.clear()
        gql_query = "mutation Login($email: String!, $password: String!) { login(email: $email, password: $password) { accessToken csrfToken } }"
        actors_gql = ActorManager(
            [
                {
                    "alias": "gql-ok",
                    "email": "gql@example.test",
                    "password": "good-gql-pass",
                    "login_graphql_query": gql_query,
                },
                {
                    "alias": "gql-bad",
                    "email": "gql@example.test",
                    "password": "wrong-gql-pass",
                    "login_graphql_query": gql_query,
                },
            ],
            login_path="/graphql",
        )
        client_gql = AgenticHTTPClient(base_url=base, receipt_store=ReceiptStore(tmp_path / "gql"), actors=actors_gql)
        try:
            assert client_gql.authenticate_actor("gql-ok") is True
            assert actors_gql.get("gql-ok").access_token == "tok-gql-bearer-99"
            assert actors_gql.get("gql-ok").csrf_token == "csrf-gql-99"
            sent_body = json.loads(events[0]["body"])
            assert sent_body["query"] == gql_query
            assert sent_body["variables"] == {"email": "gql@example.test", "password": "good-gql-pass"}

            # GraphQL 200 with errors and no tokens returns False.
            assert client_gql.authenticate_actor("gql-bad") is False
            assert actors_gql.get("gql-bad").authenticated is False
        finally:
            client_gql.close()
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 5. Pure-Python RFC-6455 WebSocket Probe & AgenticHTTPClient Integration
# ---------------------------------------------------------------------------


def _ws_server_frame(opcode: int, payload: bytes = b"") -> bytes:
    """Encode an unmasked server-to-client RFC-6455 frame."""
    b0 = 0x80 | (opcode & 0x0F)
    n = len(payload)
    if n < 126:
        return struct.pack("!BB", b0, n) + payload
    if n < 65536:
        return struct.pack("!BBH", b0, 126, n) + payload
    return struct.pack("!BBQ", b0, 127, n) + payload


def _read_exact_sock(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError("closed")
        buf.extend(chunk)
    return bytes(buf)


def _read_client_ws_frame(conn: socket.socket) -> tuple[int, bytes]:
    """Read and unmask a single client-to-server RFC-6455 frame."""
    h = _read_exact_sock(conn, 2)
    opcode = h[0] & 0x0F
    masked = bool(h[1] & 0x80)
    assert masked, "RFC-6455 requires client frames to be masked"
    length = h[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", _read_exact_sock(conn, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _read_exact_sock(conn, 8))[0]
    mask = _read_exact_sock(conn, 4)
    payload = _read_exact_sock(conn, length) if length > 0 else b""
    unmasked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    return opcode, unmasked


class _LoopbackWSServer:
    """Minimal pure-stdlib RFC-6455 loopback server for integration tests."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self.port: int = int(self._sock.getsockname()[1])
        self._stop = threading.Event()
        self.seen_requests: list[dict[str, Any]] = []
        self.pong_payloads: list[bytes] = []
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(3.0)
            req_buf = bytearray()
            while b"\r\n\r\n" not in req_buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                req_buf.extend(chunk)
            sep = req_buf.find(b"\r\n\r\n")
            head = req_buf[:sep].decode("iso-8859-1", errors="replace").split("\r\n")
            target = head[0].split(" ")[1]
            hdrs: dict[str, str] = {}
            for line in head[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()
            with self._lock:
                self.seen_requests.append({"target": target, "headers": hdrs})

            path = urlsplit(target).path
            if path == "/reject":
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            if path == "/bad-accept":
                conn.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\n"
                    b"Connection: Upgrade\r\n"
                    b"Sec-WebSocket-Accept: invalid-accept-value\r\n\r\n"
                )
                return

            ws_key = hdrs.get("sec-websocket-key", "")
            accept = base64.b64encode(hashlib.sha1((ws_key + _WS_GUID).encode("ascii")).digest()).decode("ascii")
            conn.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n"
                    "X-WS-Server: loopback-test\r\n\r\n"
                ).encode("ascii")
            )

            if path == "/ping-and-binary":
                # Send a Ping frame first, expect masked Pong back, then send binary + Close(1000).
                conn.sendall(_ws_server_frame(0x9, b"hb-1"))
                op, pong_data = _read_client_ws_frame(conn)
                if op == 0xA:
                    with self._lock:
                        self.pong_payloads.append(pong_data)
                conn.sendall(_ws_server_frame(0x2, b"\x00\x01\x02hello"))
                conn.sendall(_ws_server_frame(0x8, struct.pack("!H", 1000) + b"bye"))
                return

            # Default /ws echo server: read one client frame, echo JSON envelope, and close cleanly.
            op, payload = _read_client_ws_frame(conn)
            if op == 0x1:
                text = payload.decode("utf-8", errors="replace")
                reply = json.dumps({
                    "echo": json.loads(text) if text.startswith("{") else text,
                    "auth_seen": bool(hdrs.get("authorization")),
                }).encode("utf-8")
                conn.sendall(_ws_server_frame(0x1, reply))
                conn.sendall(_ws_server_frame(0x8, struct.pack("!H", 1000) + b"done"))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def test_encode_client_frame_unit() -> None:
    mask = b"\x37\xfa\x21\x3d"
    frame = encode_client_frame(0x1, b"Hello", mask_key=mask)
    assert frame[0] == 0x81  # FIN + text opcode
    assert frame[1] == (0x80 | 5)  # MASK bit + len 5
    assert frame[2:6] == mask
    unmasked = bytes(b ^ mask[i & 3] for i, b in enumerate(frame[6:]))
    assert unmasked == b"Hello"

    # Extended 16-bit payload length (>= 126 bytes).
    big = b"A" * 300
    big_frame = encode_client_frame(0x2, big, mask_key=mask)
    assert big_frame[0] == 0x82
    assert big_frame[1] == (0x80 | 126)
    assert struct.unpack("!H", big_frame[2:4])[0] == 300


def test_websocket_probe_and_http_client_scope_locked_integration(tmp_path: Path) -> None:
    ws_srv = _LoopbackWSServer()
    ws_srv.start()
    base = f"http://127.0.0.1:{ws_srv.port}/"
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {
            "alias": "user-a",
            "role": "member",
            "access_token": "ws-secret-bearer-token-4444",
            "cookies": {"sid": "ws-secret-cookie-5555"},
        },
    ])
    client = AgenticHTTPClient(
        base_url=base,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET",),
        max_requests=20,
        excluded_paths=("/logout",),
    )
    try:
        # 1. Direct probe_websocket: Ping->Pong, binary frame, Close(1000).
        res_pb = probe_websocket(f"ws://127.0.0.1:{ws_srv.port}/ping-and-binary", timeout_s=3.0)
        assert res_pb["status"] == 101
        assert res_pb["upgraded"] is True
        assert res_pb["close_code"] == 1000
        assert ws_srv.pong_payloads == [b"hb-1"]
        assert res_pb["frames_received"][0]["type"] == "binary"
        assert base64.b64decode(res_pb["frames_received"][0]["data_base64"]) == b"\x00\x01\x02hello"

        # 2. Direct probe_websocket: 403 rejection and invalid Sec-WebSocket-Accept.
        res_rej = probe_websocket(f"ws://127.0.0.1:{ws_srv.port}/reject", timeout_s=3.0)
        assert res_rej["status"] == 403 and res_rej["upgraded"] is False and res_rej["error"] == ""

        res_bad = probe_websocket(f"ws://127.0.0.1:{ws_srv.port}/bad-accept", timeout_s=3.0)
        assert res_bad["status"] == 101 and res_bad["upgraded"] is False
        assert "Sec-WebSocket-Accept" in res_bad["error"]

        # 3. Seamless AgenticHTTPClient.request(url="ws://...", actor="user-a", json_body={"ping": 1}).
        ws_srv.seen_requests.clear()
        rec = client.request(
            url=f"ws://127.0.0.1:{ws_srv.port}/ws",
            actor="user-a",
            json_body={"ping": 1},
        )
        assert rec["status"] == 101
        assert rec["method"] == "WS"
        assert rec["content_type"] == "application/json"
        body_doc = json.loads(rec["body"])
        assert body_doc["upgraded"] is True
        assert body_doc["close_code"] == 1000
        assert body_doc["frames_received"][0]["type"] == "text"
        echo_payload = json.loads(body_doc["frames_received"][0]["data"])
        assert echo_payload == {"echo": {"ping": 1}, "auth_seen": True}

        # Auth headers + default browser UA + Origin were sent on the wire, and secrets redacted on disk!
        wire_hdrs = ws_srv.seen_requests[-1]["headers"]
        assert wire_hdrs["authorization"] == "Bearer ws-secret-bearer-token-4444"
        assert "sid=ws-secret-cookie-5555" in wire_hdrs["cookie"]
        assert wire_hdrs["user-agent"] == DEFAULT_BROWSER_USER_AGENT
        assert wire_hdrs["origin"] == f"http://127.0.0.1:{ws_srv.port}"

        raw_receipt = (tmp_path / "receipts" / f"{rec['receipt_id']}.json").read_text(encoding="utf-8")
        assert "ws-secret-bearer-token-4444" not in raw_receipt
        assert "ws-secret-cookie-5555" not in raw_receipt

        # 4. Strict scope lock: out-of-scope host, wss:// against http:// origin, wrong port, excluded path all rejected!
        budget_before = client.budget.used
        for bad_ws in (
            "ws://evil.example/ws",
            f"wss://127.0.0.1:{ws_srv.port}/ws",
            f"ws://127.0.0.1:{ws_srv.port + 1}/ws",
            f"ws://127.0.0.1:{ws_srv.port}/logout",
            f"ws://user:pass@127.0.0.1:{ws_srv.port}/ws",
        ):
            with pytest.raises(ScopeViolationError):
                client.request(url=bad_ws, actor="user-a")
        assert client.budget.used == budget_before

        # Method allowlist still enforced for disallowed methods.
        with pytest.raises(MethodNotAllowedError):
            client.request(method="DELETE", url=f"ws://127.0.0.1:{ws_srv.port}/ws", actor="user-a")
    finally:
        client.close()
        ws_srv.stop()


# ---------------------------------------------------------------------------
# 6. Pure-Python gRPC-Web Frame Codec & Live Loopback Decoding
# ---------------------------------------------------------------------------


def test_grpc_web_binary_and_text_encode_decode_unit() -> None:
    assert is_grpc_web_content_type("application/grpc-web") is True
    assert is_grpc_web_content_type("application/grpc-web+proto") is True
    assert is_grpc_web_content_type("application/grpc-web-text; charset=utf-8") is True
    assert is_grpc_web_content_type("application/json") is False

    # Binary mode: 1 data frame + 1 trailer frame.
    msg_payload = b"\x0a\x0bhello-world"
    bin_stream = (
        encode_grpc_web_frame(msg_payload, text_mode=False)
        + encode_grpc_web_trailers({"grpc-status": "0", "grpc-message": "all%20good", "x-custom": "val1"}, text_mode=False)
    )
    decoded_bin = decode_grpc_web_frames(bin_stream, content_type="application/grpc-web+proto")
    assert decoded_bin["protocol"] == "grpc-web"
    assert decoded_bin["text_mode"] is False
    assert decoded_bin["truncated"] is False
    assert decoded_bin["error"] == ""
    assert decoded_bin["grpc_status"] == 0
    assert decoded_bin["grpc_message"] == "all good"
    assert decoded_bin["trailers"]["x-custom"] == "val1"
    assert len(decoded_bin["data_frames"]) == 1
    assert base64.b64decode(decoded_bin["data_frames"][0]["payload_base64"]) == msg_payload
    assert "hello-world" in decoded_bin["data_frames"][0]["text_preview"]

    # Base64 text mode with concatenated padded segments (data frame + trailer frame encoded separately).
    text_stream = (
        encode_grpc_web_frame(b"item-42", text_mode=True)
        + encode_grpc_web_trailers({"grpc-status": "7", "grpc-message": "permission%20denied"}, text_mode=True)
    )
    decoded_txt = decode_grpc_web_frames(text_stream, content_type="application/grpc-web-text")
    assert decoded_txt["text_mode"] is True
    assert decoded_txt["truncated"] is False
    assert decoded_txt["grpc_status"] == 7
    assert decoded_txt["grpc_message"] == "permission denied"
    assert len(decoded_txt["data_frames"]) == 1
    assert base64.b64decode(decoded_txt["data_frames"][0]["payload_base64"]) == b"item-42"

    # Malformed base64 & truncated binary fail cleanly without raising.
    bad_b64 = decode_grpc_web_frames(b"!!!invalid!!!", content_type="application/grpc-web-text")
    assert bad_b64["truncated"] is True and bad_b64["error"]

    trunc_bin = decode_grpc_web_frames(b"\x00\x00\x00\x00\x10short", content_type="application/grpc-web")
    assert trunc_bin["truncated"] is True and trunc_bin["data_frames"] == []


def test_grpc_web_text_live_loopback_http_decoding(tmp_path: Path) -> None:
    response_wire = (
        encode_grpc_web_frame(b"\x0a\x0dsecret-record", text_mode=True)
        + encode_grpc_web_trailers({"grpc-status": "0", "grpc-message": "OK"}, text_mode=True)
    )

    class _GrpcWebHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length) if length > 0 else b""
            self.send_response(200)
            self.send_header("Content-Type", "application/grpc-web-text")
            self.send_header("Content-Length", str(len(response_wire)))
            self.end_headers()
            self.wfile.write(response_wire)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _GrpcWebHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{srv.server_port}/",
        receipt_store=store,
        allowed_methods=("GET", "POST"),
        max_requests=10,
    )
    try:
        req_frame = encode_grpc_web_frame(b"\x08\x01", text_mode=True).decode("ascii")
        rec = client.request(
            method="POST",
            url="/acme.BillingService/GetInvoice",
            headers={"Content-Type": "application/grpc-web-text"},
            raw_body=req_frame,
        )
        assert rec["status"] == 200
        assert rec["content_type"] == "application/grpc-web-text"
        assert rec["response_length"] == len(response_wire)  # Raw wire bytes preserved!
        decoded = json.loads(rec["body"])
        assert decoded["protocol"] == "grpc-web"
        assert decoded["text_mode"] is True
        assert decoded["grpc_status"] == 0
        assert decoded["grpc_message"] == "OK"
        assert len(decoded["data_frames"]) == 1
        assert "secret-record" in decoded["data_frames"][0]["text_preview"]
        assert base64.b64decode(decoded["data_frames"][0]["payload_base64"]) == b"\x0a\x0dsecret-record"
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()
