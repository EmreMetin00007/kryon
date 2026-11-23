"""Tests for Faz 5A: framework-aware CSRF handling, adaptive 429 Retry-After backoff, and mid-run session refresh."""
from __future__ import annotations

from contextlib import contextmanager
from email.parser import BytesParser
from email.policy import default as email_default_policy
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any, Callable, Iterator
from urllib.parse import parse_qsl, quote, quote_plus, urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import (  # noqa: E402
    ActorManager,
    ActorSession,
    AgenticHTTPClient,
    ServiceDegradationError,
    _extract_session_material_details,
    _extract_session_material_from_response,
    _parse_retry_after_seconds,
)
from agentic_receipts import ReceiptStore  # noqa: E402


@contextmanager
def _start_loopback_server(
    router: Callable[[str, str, dict[str, str], bytes], tuple[int, str, bytes | str, dict[str, str]]],
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    requests_log: list[dict[str, Any]] = []
    log_lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            path_only = urlsplit(self.path).path
            with log_lock:
                requests_log.append({
                    "method": self.command,
                    "path": path_only,
                    "headers": hdrs,
                    "body": body.decode("utf-8", errors="replace"),
                    "raw_body": body,
                })
            status, ctype, payload, extra_hdrs = router(self.command, path_only, hdrs, body)
            raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            for hk, hv in (extra_hdrs or {}).items():
                self.send_header(hk, hv)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

        def do_GET(self) -> None:
            self._handle()

        def do_HEAD(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def do_PUT(self) -> None:
            self._handle()

        def do_PATCH(self) -> None:
            self._handle()

        def do_DELETE(self) -> None:
            self._handle()

        def log_message(self, _fmt: str, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/", requests_log
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


def _parse_multipart(content_type: str, body_bytes: bytes) -> dict[str, bytes]:
    raw_msg = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body_bytes
    msg = BytesParser(policy=email_default_policy).parsebytes(raw_msg)
    assert msg.is_multipart()
    parts: dict[str, bytes] = {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        payload = part.get_payload(decode=True)
        if isinstance(name, str):
            parts[name] = payload if isinstance(payload, bytes) else b""
    return parts


# ---------------------------------------------------------------------------
# 1. Framework-Aware CSRF Extraction & Header/Form/Multipart Injection
# ---------------------------------------------------------------------------


def test_extract_session_material_backward_compat_and_framework_metadata() -> None:
    # Backward-compatible 4-tuple unpack still works cleanly.
    c4, b4, r4, csrf4 = _extract_session_material_from_response(
        headers={"X-CSRFToken": "hdr-dj-1"},
        cookies={"csrftoken": "cookie-dj-1"},
        body_text="",
    )
    assert (c4, b4, r4, csrf4) == ({"csrftoken": "cookie-dj-1"}, "", "", "hdr-dj-1")

    # Response headers map to framework header names.
    for hdr_key, expected_hdr in (
        ("X-CSRF-Token-Next", "X-CSRF-Token"),
        ("X-CSRF-Token", "X-CSRF-Token"),
        ("X-CSRFToken", "X-CSRFToken"),
        ("X-XSRF-TOKEN", "X-XSRF-TOKEN"),
    ):
        _, _, _, tok, hdr_name, field_name = _extract_session_material_details(
            headers={hdr_key: "tok-from-hdr"},
            cookies={},
            body_text="",
        )
        assert tok == "tok-from-hdr"
        assert hdr_name == expected_hdr
        assert field_name == ""

    # HTML <meta> tags (various names and reversed attribute order).
    meta_cases = [
        ('<meta name="csrf-token" content="m-csrf">', "m-csrf", "X-CSRF-Token", ""),
        ('<meta content="m-xsrf" name="xsrf-token">', "m-xsrf", "X-XSRF-TOKEN", ""),
        ('<meta name="csrfmiddlewaretoken" content="m-dj">', "m-dj", "X-CSRFToken", "csrfmiddlewaretoken"),
        ('<meta name="_token" content="m-lar">', "m-lar", "X-CSRF-Token", "_token"),
        ('<meta content="m-rails" name="authenticity_token">', "m-rails", "X-CSRF-Token", "authenticity_token"),
    ]
    for html_body, exp_tok, exp_hdr, exp_field in meta_cases:
        _, _, _, tok, hdr_name, field_name = _extract_session_material_details(
            headers={}, cookies={}, body_text=f"<html><head>{html_body}</head></html>"
        )
        assert (tok, hdr_name, field_name) == (exp_tok, exp_hdr, exp_field)

    # HTML <input> hidden fields across frameworks (preserving exact field case).
    input_cases = [
        ('<input type="hidden" name="csrfmiddlewaretoken" value="dj-in">', "dj-in", "X-CSRFToken", "csrfmiddlewaretoken"),
        ('<input value="lar-in" type="hidden" name="_token">', "lar-in", "X-CSRF-Token", "_token"),
        ('<input type="hidden" name="authenticity_token" value="rails-in">', "rails-in", "X-CSRF-Token", "authenticity_token"),
        ('<input type="hidden" name="__token__" value="tp-in">', "tp-in", "X-CSRF-Token", "__token__"),
        ('<input name="__RequestVerificationToken" type="hidden" value="asp-in">', "asp-in", "X-CSRF-Token", "__RequestVerificationToken"),
        ('<input type="hidden" name="csrf_token" value="gen-1">', "gen-1", "X-CSRF-Token", "csrf_token"),
        ('<input type="hidden" name="_csrf" value="gen-2">', "gen-2", "X-CSRF-Token", "_csrf"),
        ('<input type="hidden" name="csrf" value="gen-3">', "gen-3", "X-CSRF-Token", "csrf"),
        ('<input type="hidden" name="xsrf_token" value="gen-4">', "gen-4", "X-XSRF-TOKEN", "xsrf_token"),
    ]
    for html_input, exp_tok, exp_hdr, exp_field in input_cases:
        _, _, _, tok, hdr_name, field_name = _extract_session_material_details(
            headers={}, cookies={}, body_text=f"<form>{html_input}</form>"
        )
        assert (tok, hdr_name, field_name) == (exp_tok, exp_hdr, exp_field)

    # Cookies (including percent-decoded XSRF-TOKEN).
    _, _, _, dj_tok, dj_hdr, _ = _extract_session_material_details(
        headers={}, cookies={"csrftoken": "dj-cookie-val"}, body_text=""
    )
    assert (dj_tok, dj_hdr) == ("dj-cookie-val", "X-CSRFToken")

    _, _, _, lar_tok, lar_hdr, _ = _extract_session_material_details(
        headers={}, cookies={"XSRF-TOKEN": "enc%2Bval%2F123%3D"}, body_text=""
    )
    assert (lar_tok, lar_hdr) == ("enc+val/123=", "X-XSRF-TOKEN")

    _, _, _, other_tok, other_hdr, _ = _extract_session_material_details(
        headers={}, cookies={"_csrf_token": "under-csrf-val"}, body_text=""
    )
    assert (other_tok, other_hdr) == ("under-csrf-val", "X-CSRF-Token")


def test_actor_session_build_headers_csrf_precedence_and_secret_redaction() -> None:
    session = ActorSession(
        alias="u1",
        csrf_token="tok+with/chars=99",
        csrf_header_name="X-CSRFToken",
        csrf_field_name="csrfmiddlewaretoken",
    )
    # Non-mutating methods never get CSRF headers.
    assert "X-CSRFToken" not in session.build_headers("GET")
    assert "X-CSRF-Token" not in session.build_headers("HEAD")

    # Mutating methods inject csrf_header_name (default X-CSRF-Token when unset).
    for m in ("POST", "PUT", "PATCH", "DELETE"):
        hdrs = session.build_headers(m)
        assert hdrs["X-CSRFToken"] == "tok+with/chars=99"
        assert "X-CSRF-Token" not in hdrs

    # Explicit caller CSRF header (any variant or empty string suppression) is respected.
    for override_hdr in ("X-CSRF-Token", "X-CSRFToken", "X-XSRF-TOKEN"):
        custom = session.build_headers("POST", {override_hdr: "caller-supplied"})
        assert custom[override_hdr] == "caller-supplied"
        assert sum(1 for k in custom if k.lower() in {"x-csrf-token", "x-csrftoken", "x-xsrf-token"}) == 1

        suppressed = session.build_headers("POST", {override_hdr: ""})
        assert not any(k.lower() in {"x-csrf-token", "x-csrftoken", "x-xsrf-token"} for k in suppressed)

    # collect_secrets includes both raw and URL-encoded CSRF token forms for strict redaction.
    secrets = session.collect_secrets()
    assert "tok+with/chars=99" in secrets
    assert quote_plus("tok+with/chars=99") in secrets
    assert quote("tok+with/chars=99", safe="") in secrets


def test_framework_csrf_live_django_laravel_rails_thinkphp_and_override_protection(tmp_path: Path) -> None:
    dj_secret = "dj-secret+tok/123="
    lar_cookie_raw = "lar-cookie%2Benc%3D99"
    lar_cookie_decoded = "lar-cookie+enc=99"
    lar_form_secret = "lar-form-secret-456"
    rails_secret = "rails-auth-secret-789"
    tp_secret = "tp-md5-secret-012"

    def _router(method: str, path: str, hdrs: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if method == "GET" and path == "/django/form":
            html_page = (
                '<html><body><form method="post">'
                f'<input type="hidden" name="csrfmiddlewaretoken" value="{dj_secret}">'
                "</form></body></html>"
            )
            return 200, "text/html", html_page, {"Set-Cookie": "csrftoken=dj-cookie-secret; Path=/"}

        if method == "POST" and path == "/django/submit":
            ct = hdrs.get("content-type", "")
            hdr_tok = hdrs.get("x-csrftoken", "")
            if ct.startswith("multipart/form-data"):
                parts = _parse_multipart(ct, body)
                field_tok = parts.get("csrfmiddlewaretoken", b"").decode("utf-8", errors="replace")
            else:
                parsed = dict(parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True))
                field_tok = parsed.get("csrfmiddlewaretoken", "")
            if hdr_tok == dj_secret and field_tok == dj_secret:
                return 200, "application/json", '{"framework":"django","ok":true}', {}
            return 403, "application/json", json.dumps({"hdr": hdr_tok, "field": field_tok}), {}

        if method == "GET" and path == "/laravel/sanctum":
            return 204, "text/plain", "", {"Set-Cookie": f"XSRF-TOKEN={lar_cookie_raw}; Path=/"}

        if method == "POST" and path == "/laravel/api":
            if hdrs.get("x-xsrf-token") == lar_cookie_decoded:
                return 200, "application/json", '{"framework":"laravel-spa","ok":true}', {}
            return 403, "application/json", '{"error":"xsrf mismatch"}', {}

        if method == "GET" and path == "/laravel/form":
            html_page = (
                f'<html><head><meta name="csrf-token" content="{lar_form_secret}"></head>'
                f'<body><form><input type="hidden" name="_token" value="{lar_form_secret}"></form></body></html>'
            )
            return 200, "text/html", html_page, {"Set-Cookie": f"XSRF-TOKEN={lar_cookie_raw}; Path=/"}

        if method == "POST" and path == "/laravel/submit":
            parsed = dict(parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True))
            if hdrs.get("x-csrf-token") == lar_form_secret and parsed.get("_token") == lar_form_secret:
                return 200, "application/json", '{"framework":"laravel-form","ok":true}', {}
            return 403, "application/json", json.dumps({"parsed": parsed}), {}

        if method == "GET" and path == "/rails/form":
            html_page = f'<form><input type="hidden" name="authenticity_token" value="{rails_secret}"></form>'
            return 200, "text/html", html_page, {}

        if method == "POST" and path == "/rails/submit":
            parsed = dict(parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True))
            if parsed.get("authenticity_token") == rails_secret and hdrs.get("x-csrf-token") == rails_secret:
                return 200, "application/json", '{"framework":"rails","ok":true}', {}
            return 403, "application/json", '{"error":"invalid authenticity_token"}', {}

        if method == "GET" and path == "/thinkphp/form":
            html_page = f'<form><input type="hidden" name="__token__" value="{tp_secret}"></form>'
            return 200, "text/html", html_page, {}

        if method == "POST" and path == "/thinkphp/submit":
            parsed = dict(parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True))
            if parsed.get("__token__") == tp_secret and hdrs.get("x-csrf-token") == tp_secret:
                return 200, "application/json", '{"framework":"thinkphp","ok":true}', {}
            return 403, "application/json", '{"error":"invalid __token__"}', {}

        if method == "POST" and path == "/echo":
            return 200, "application/json", json.dumps({
                "headers": {k: v for k, v in hdrs.items() if "csrf" in k or "xsrf" in k},
                "body": body.decode("utf-8", errors="replace"),
            }), {}

        return 404, "application/json", '{"error":"not found"}', {}

    with _start_loopback_server(_router) as (base_url, _req_log):
        store = ReceiptStore(tmp_path / "csrf-live")
        actors = ActorManager([
            {"alias": "dj", "cookies": {"sessionid": "dj-sid-1"}},
            {"alias": "lar-spa", "cookies": {"laravel_session": "lar-sid-1"}},
            {"alias": "lar-web", "cookies": {"laravel_session": "lar-sid-2"}},
            {"alias": "rails", "cookies": {"_app_session": "rails-sid-1"}},
            {"alias": "tp", "cookies": {"PHPSESSID": "tp-sid-1"}},
        ])
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=actors,
            allowed_methods=("GET", "POST", "PUT", "PATCH", "DELETE"),
            max_requests=40,
        )
        try:
            # --- Django: form_body, raw_body urlencoded, multipart (with & without form_body), redaction ---
            assert client.request(method="GET", url="/django/form", actor="dj")["status"] == 200
            dj_sess = actors.get("dj")
            assert dj_sess.csrf_header_name == "X-CSRFToken"
            assert dj_sess.csrf_field_name == "csrfmiddlewaretoken"

            caller_form = {"title": "hello"}
            rec_dj_form = client.request(method="POST", url="/django/submit", actor="dj", form_body=caller_form)
            assert rec_dj_form["status"] == 200
            assert caller_form == {"title": "hello"}  # Caller dict MUST NOT be mutated!

            # Strict redaction: neither raw nor URL-encoded CSRF secret leaks in receipt on disk!
            dj_receipt_raw = (tmp_path / "csrf-live" / "receipts" / f"{rec_dj_form['receipt_id']}.json").read_text(
                encoding="utf-8"
            )
            assert dj_secret not in dj_receipt_raw
            assert quote_plus(dj_secret) not in dj_receipt_raw

            # Raw urlencoded string body injection.
            rec_dj_raw = client.request(
                method="POST",
                url="/django/submit",
                actor="dj",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                raw_body="title=rawmode",
            )
            assert rec_dj_raw["status"] == 200

            # Multipart injection with caller form_body (without mutating it) AND with form_body=None.
            mp_fields = {"note": "doc"}
            rec_dj_mp1 = client.request(
                method="POST",
                url="/django/submit",
                actor="dj",
                form_body=mp_fields,
                files=[{"field": "upload", "filename": "a.txt", "content": "abc"}],
            )
            assert rec_dj_mp1["status"] == 200
            assert mp_fields == {"note": "doc"}

            rec_dj_mp2 = client.request(
                method="POST",
                url="/django/submit",
                actor="dj",
                files=[{"field": "upload", "filename": "b.txt", "content": "xyz"}],
            )
            assert rec_dj_mp2["status"] == 200

            # Explicit caller CSRF field and CSRF header MUST NOT be overwritten.
            rec_override = client.request(
                method="POST",
                url="/echo",
                actor="dj",
                headers={"X-CSRFToken": "manual-header-tok"},
                form_body={"title": "keep", "csrfmiddlewaretoken": "manual-field-tok"},
            )
            echo_doc = json.loads(rec_override["body"])
            assert echo_doc["headers"] == {"x-csrftoken": "manual-header-tok"}
            assert dict(parse_qsl(echo_doc["body"]))["csrfmiddlewaretoken"] == "manual-field-tok"

            # --- Laravel SPA cookie (URL-decoded XSRF-TOKEN -> X-XSRF-TOKEN) ---
            assert client.request(method="GET", url="/laravel/sanctum", actor="lar-spa")["status"] == 204
            assert actors.get("lar-spa").csrf_header_name == "X-XSRF-TOKEN"
            assert actors.get("lar-spa").csrf_token == lar_cookie_decoded
            assert client.request(method="POST", url="/laravel/api", actor="lar-spa", json_body={"a": 1})["status"] == 200

            # --- Laravel form (_token + X-CSRF-Token) ---
            assert client.request(method="GET", url="/laravel/form", actor="lar-web")["status"] == 200
            assert actors.get("lar-web").csrf_field_name == "_token"
            assert client.request(method="POST", url="/laravel/submit", actor="lar-web", form_body={"k": "v"})["status"] == 200

            # --- Rails (authenticity_token + X-CSRF-Token) ---
            assert client.request(method="GET", url="/rails/form", actor="rails")["status"] == 200
            assert actors.get("rails").csrf_field_name == "authenticity_token"
            assert client.request(method="POST", url="/rails/submit", actor="rails", form_body={"k": "v"})["status"] == 200

            # --- ThinkPHP (__token__ + X-CSRF-Token) ---
            assert client.request(method="GET", url="/thinkphp/form", actor="tp")["status"] == 200
            assert actors.get("tp").csrf_field_name == "__token__"
            assert client.request(method="POST", url="/thinkphp/submit", actor="tp", form_body={"k": "v"})["status"] == 200
        finally:
            client.close()


# ---------------------------------------------------------------------------
# 2. Adaptive 429 Retry-After Backoff & Circuit Breaker Preservation
# ---------------------------------------------------------------------------


def test_parse_retry_after_seconds_numeric_http_date_and_clamping() -> None:
    now_ts = 1_800_000_000.0
    assert _parse_retry_after_seconds({}) is None
    assert _parse_retry_after_seconds({"Retry-After": "2"}) == 2.0
    assert _parse_retry_after_seconds({"retry-after": "0.5"}) == 0.5
    assert _parse_retry_after_seconds({"Retry-After": "0"}) == 0.0
    assert _parse_retry_after_seconds({"Retry-After": "-4"}) == 0.0
    assert _parse_retry_after_seconds({"Retry-After": "3600"}) == 5.0  # Clamped to default 5.0s!
    assert _parse_retry_after_seconds({"Retry-After": "12"}, max_retry_after_s=3.0) == 3.0
    assert _parse_retry_after_seconds({"Retry-After": "nan"}) is None
    assert _parse_retry_after_seconds({"Retry-After": "inf"}) is None
    assert _parse_retry_after_seconds({"Retry-After": "not-a-date"}) is None

    # RFC 7231 HTTP-date: future within cap, far-future clamped, past clamped to 0.0.
    date_plus_3 = formatdate(now_ts + 3.0, usegmt=True)
    parsed_3 = _parse_retry_after_seconds({"Retry-After": date_plus_3}, now=now_ts)
    assert parsed_3 is not None and abs(parsed_3 - 3.0) < 0.01

    date_plus_600 = formatdate(now_ts + 600.0, usegmt=True)
    assert _parse_retry_after_seconds({"Retry-After": date_plus_600}, now=now_ts) == 5.0

    date_past = formatdate(now_ts - 60.0, usegmt=True)
    assert _parse_retry_after_seconds({"Retry-After": date_past}, now=now_ts) == 0.0


def test_429_and_503_retry_after_backoff_recovery_and_adaptive_decay(tmp_path: Path) -> None:
    counters = {
        "num429": 0,
        "clamped429": 0,
        "date429": 0,
        "nohdr429": 0,
        "retry503": 0,
        "bare503": 0,
    }
    lock = threading.Lock()

    def _router(_method: str, path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        with lock:
            if path == "/num-429":
                counters["num429"] += 1
                if counters["num429"] == 1:
                    return 429, "application/json", '{"error":"slow down"}', {"Retry-After": "2"}
                return 200, "application/json", '{"ok":true}', {}
            if path == "/clamped-429":
                counters["clamped429"] += 1
                if counters["clamped429"] == 1:
                    return 429, "application/json", '{"error":"hostile wait"}', {"Retry-After": "9999"}
                return 200, "application/json", '{"ok":true}', {}
            if path == "/date-429":
                counters["date429"] += 1
                if counters["date429"] == 1:
                    future_hdr = formatdate(time.time() + 120.0, usegmt=True)
                    return 429, "application/json", '{"error":"date wait"}', {"Retry-After": future_hdr}
                return 200, "application/json", '{"ok":true}', {}
            if path == "/no-hdr-429":
                counters["nohdr429"] += 1
                if counters["nohdr429"] <= 2:
                    return 429, "application/json", '{"error":"burst limit"}', {}
                return 200, "application/json", '{"ok":true}', {}
            if path == "/retry-503":
                counters["retry503"] += 1
                if counters["retry503"] == 1:
                    return 503, "application/json", '{"error":"restarting"}', {"Retry-After": "1.5"}
                return 200, "application/json", '{"ok":true}', {}
            if path == "/bare-503":
                counters["bare503"] += 1
                return 503, "text/plain", "unavailable", {}
        return 200, "application/json", '{"ok":true}', {}

    with _start_loopback_server(_router) as (base_url, _req_log):
        # 1. Numeric Retry-After=2 recovers cleanly and engages adaptive pacing that decays on 2xx.
        clock = [100.0]
        sleeps: list[float] = []

        def _fake_sleep(sec: float) -> None:
            sleeps.append(sec)
            clock[0] += sec

        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=ReceiptStore(tmp_path / "num"),
            allowed_methods=("GET",),
            max_requests=40,
            max_degradation_streak=2,
            _sleep_fn=_fake_sleep,
            _monotonic_fn=lambda: clock[0],
        )
        try:
            rec = client.request(method="GET", url="/num-429", force=True)
            assert rec["status"] == 200
            assert sleeps == [2.0]
            assert 0.0 < client._adaptive_delay_s <= 1.0
            initial_adaptive = client._adaptive_delay_s

            # Consecutive healthy 2xx requests pace gently and decay adaptive delay back to 0.0.
            sleeps.clear()
            for idx in range(6):
                assert client.request(method="GET", url=f"/ok/{idx}", force=True)["status"] == 200
            assert sleeps and sleeps[0] == pytest.approx(initial_adaptive, abs=1e-6)
            assert client._adaptive_delay_s == 0.0

            # Once decayed to 0.0, subsequent 200 requests incur zero sleep.
            sleeps.clear()
            assert client.request(method="GET", url="/ok/after-decay", force=True)["status"] == 200
            assert sleeps == []
        finally:
            client.close()

        # 2. Hostile Retry-After=9999 and far-future HTTP-date are both clamped to <= 5.0s.
        sleeps_clamp: list[float] = []
        clock_clamp = [500.0]

        def _sleep_clamp(sec: float) -> None:
            sleeps_clamp.append(sec)
            clock_clamp[0] += sec + 10.0  # Advance well past adaptive delay so only retry sleeps are measured.

        client_clamp = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=ReceiptStore(tmp_path / "clamp"),
            allowed_methods=("GET",),
            max_requests=40,
            _sleep_fn=_sleep_clamp,
            _monotonic_fn=lambda: clock_clamp[0],
        )
        try:
            assert client_clamp.request(method="GET", url="/clamped-429", force=True)["status"] == 200
            assert sleeps_clamp == [5.0]

            sleeps_clamp.clear()
            clock_clamp[0] += 10.0  # Clear adaptive pacing window between independent retry cases.
            assert client_clamp.request(method="GET", url="/date-429", force=True)["status"] == 200
            assert sleeps_clamp == [5.0]

            # 3. 429 without Retry-After uses exponential jittered fallback across up to 2 retries.
            sleeps_clamp.clear()
            clock_clamp[0] += 10.0
            assert client_clamp.request(method="GET", url="/no-hdr-429", force=True)["status"] == 200
            assert len(sleeps_clamp) == 2
            assert 0.4 <= sleeps_clamp[0] <= 0.65
            assert 0.8 <= sleeps_clamp[1] <= 1.25
            assert sleeps_clamp[1] > sleeps_clamp[0]

            # 4. 503 WITH Retry-After retries and succeeds; bare 503 without Retry-After does NOT retry.
            sleeps_clamp.clear()
            clock_clamp[0] += 10.0
            assert client_clamp.request(method="GET", url="/retry-503", force=True)["status"] == 200
            assert sleeps_clamp == [1.5]

            sleeps_clamp.clear()
            clock_clamp[0] += 10.0
            assert client_clamp.request(method="GET", url="/bare-503", force=True)["status"] == 503
            assert counters["bare503"] == 1
            assert sleeps_clamp == []
        finally:
            client_clamp.close()


def test_persistent_429_preserves_service_degradation_circuit_breaker_and_wall_budget(tmp_path: Path) -> None:
    def _always_429(
        _method: str, _path: str, _hdrs: dict[str, str], _body: bytes
    ) -> tuple[int, str, str, dict[str, str]]:
        return 429, "application/json", '{"error":"rate limit exceeded"}', {"Retry-After": "1"}

    with _start_loopback_server(_always_429) as (base_url, req_log):
        # Case A: max_degradation_streak=2 still raises ServiceDegradationError on 2nd logical failure!
        sleeps_a: list[float] = []
        client_a = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=ReceiptStore(tmp_path / "streak2"),
            allowed_methods=("GET",),
            max_requests=30,
            max_degradation_streak=2,
            _sleep_fn=sleeps_a.append,
        )
        try:
            rec1 = client_a.request(method="GET", url="/limited/1", force=True)
            assert rec1["status"] == 429
            # 1 initial + 2 retries = 3 wire calls on call 1.
            assert len(req_log) == 3

            with pytest.raises(ServiceDegradationError, match=r"2 consecutive.*status=429"):
                client_a.request(method="GET", url="/limited/2", force=True)
            assert len(req_log) == 6
        finally:
            client_a.close()

        # Case B: max_degradation_streak=1 raises immediately once retries exhaust on persistent 429.
        req_log.clear()
        client_b = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=ReceiptStore(tmp_path / "streak1"),
            allowed_methods=("GET",),
            max_requests=30,
            max_degradation_streak=1,
            _sleep_fn=lambda _s: None,
        )
        try:
            with pytest.raises(ServiceDegradationError, match=r"1 consecutive.*status=429"):
                client_b.request(method="GET", url="/limited/one", force=True)
            assert len(req_log) == 3
        finally:
            client_b.close()

        # Case C: Wall-clock deadline prevents sleeping/retrying beyond remaining budget.
        req_log.clear()
        sleeps_c: list[float] = []
        client_c = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=ReceiptStore(tmp_path / "deadline"),
            allowed_methods=("GET",),
            max_requests=30,
            max_degradation_streak=5,
            deadline_monotonic=100.5,
            _sleep_fn=sleeps_c.append,
            _monotonic_fn=lambda: 100.0,
        )
        try:
            rec_c = client_c.request(method="GET", url="/limited/deadline", force=True)
            assert rec_c["status"] == 429
            assert len(req_log) == 1  # Retry-After=1.0 > remaining 0.5s -> skipped fail-closed!
            assert sleeps_c == []
        finally:
            client_c.close()


# ---------------------------------------------------------------------------
# 3. Automatic Mid-Run Session Renewal (refresh_token & Fallback Re-Login)
# ---------------------------------------------------------------------------


def test_mid_run_401_triggers_refresh_token_renewal_with_cookies(tmp_path: Path) -> None:
    def _router(method: str, path: str, hdrs: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if method == "POST" and path == "/api/auth/refresh":
            payload = json.loads(body.decode("utf-8") or "{}")
            cookie_hdr = hdrs.get("cookie", "")
            if payload.get("refresh_token") == "rt-initial-secret" and "sid=old-cookie-1" in cookie_hdr:
                return (
                    200,
                    "application/json",
                    json.dumps({
                        "access_token": "jwt-refreshed-2",
                        "refresh_token": "rt-rotated-secret-2",
                    }),
                    {"Set-Cookie": "sid=refreshed-cookie-2; Path=/; HttpOnly"},
                )
            return 401, "application/json", '{"error":"bad refresh token"}', {}

        if method == "POST" and path == "/api/auth/login":
            return 200, "application/json", '{"access_token":"should-not-hit-login"}', {}

        if method == "GET" and path == "/api/protected":
            if hdrs.get("authorization") == "Bearer jwt-refreshed-2" and "sid=refreshed-cookie-2" in hdrs.get("cookie", ""):
                return 200, "application/json", '{"data":"protected-ok"}', {}
            return 401, "application/json", '{"error":"expired"}', {}

        return 404, "application/json", '{"error":"not found"}', {}

    with _start_loopback_server(_router) as (base_url, req_log):
        store = ReceiptStore(tmp_path / "refresh")
        actors = ActorManager(
            [
                {
                    "alias": "member1",
                    "email": "m1@example.test",
                    "password": "MemberPassword1!",
                    "access_token": "jwt-expired-1",
                    "refresh_token": "rt-initial-secret",
                    "refresh_path": "/api/auth/refresh",
                    "cookies": {"sid": "old-cookie-1"},
                }
            ],
            login_path="/api/auth/login",
        )
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=actors,
            allowed_methods=("GET", "POST"),
            max_requests=20,
        )
        try:
            rec = client.request(method="GET", url="/api/protected", actor="member1")
            assert rec["status"] == 200
            assert json.loads(rec["body"]) == {"data": "protected-ok"}

            # Exact sequence: 401 on protected -> POST /api/auth/refresh -> replay GET /api/protected (200).
            assert [(r["method"], r["path"]) for r in req_log] == [
                ("GET", "/api/protected"),
                ("POST", "/api/auth/refresh"),
                ("GET", "/api/protected"),
            ]
            sess = actors.get("member1")
            assert sess.access_token == "jwt-refreshed-2"
            assert sess.refresh_token == "rt-rotated-secret-2"
            assert sess.cookies["sid"] == "refreshed-cookie-2"

            # Neither expired nor refreshed secrets appear in stored receipts.
            for rid in store.list_ids():
                raw_rec = (tmp_path / "refresh" / "receipts" / f"{rid}.json").read_text(encoding="utf-8")
                for secret in ("jwt-refreshed-2", "rt-initial-secret", "rt-rotated-secret-2", "refreshed-cookie-2"):
                    assert secret not in raw_rec
        finally:
            client.close()


def test_mid_run_401_falls_back_to_relogin_when_refresh_fails_or_absent(tmp_path: Path) -> None:
    def _router(method: str, path: str, hdrs: dict[str, str], body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if method == "POST" and path == "/api/auth/refresh":
            return 401, "application/json", '{"error":"refresh_expired"}', {}
        if method == "POST" and path == "/api/auth/login":
            data = json.loads(body.decode("utf-8") or "{}")
            if data.get("password") == "ValidPass123!":
                return 200, "application/json", '{"access_token":"jwt-relogin-fresh"}', {}
            return 401, "application/json", '{"error":"bad creds"}', {}
        if method == "GET" and path == "/api/orders":
            if hdrs.get("authorization") == "Bearer jwt-relogin-fresh":
                return 200, "application/json", '{"orders":[1,2]}', {}
            return 401, "application/json", '{"error":"session expired"}', {}
        return 404, "application/json", '{"error":"not found"}', {}

    with _start_loopback_server(_router) as (base_url, req_log):
        # Case A: refresh_path returns 401 -> falls back cleanly to login_path ONCE (no duplicate refresh call!).
        actors_a = ActorManager(
            [
                {
                    "alias": "m1",
                    "email": "m1@example.test",
                    "password": "ValidPass123!",
                    "access_token": "jwt-stale",
                    "refresh_token": "rt-dead",
                    "refresh_path": "/api/auth/refresh",
                }
            ],
            login_path="/api/auth/login",
            refresh_path="/api/v1/access/refresh",
        )
        client_a = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=ReceiptStore(tmp_path / "fallback-a"),
            actors=actors_a,
            allowed_methods=("GET", "POST"),
            max_requests=20,
        )
        try:
            rec_a = client_a.request(method="GET", url="/api/orders", actor="m1")
            assert rec_a["status"] == 200
            assert [(r["method"], r["path"]) for r in req_log] == [
                ("GET", "/api/orders"),
                ("POST", "/api/auth/refresh"),
                ("POST", "/api/auth/login"),
                ("GET", "/api/orders"),
            ]
        finally:
            client_a.close()

        # Case B: No refresh_token configured -> skips refresh and re-logs in directly.
        req_log.clear()
        actors_b = ActorManager(
            [
                {
                    "alias": "m2",
                    "email": "m2@example.test",
                    "password": "ValidPass123!",
                    "access_token": "jwt-stale-2",
                }
            ],
            login_path="/api/auth/login",
        )
        client_b = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=ReceiptStore(tmp_path / "fallback-b"),
            actors=actors_b,
            allowed_methods=("GET", "POST"),
            max_requests=20,
        )
        try:
            rec_b = client_b.request(method="GET", url="/api/orders", actor="m2")
            assert rec_b["status"] == 200
            assert [(r["method"], r["path"]) for r in req_log] == [
                ("GET", "/api/orders"),
                ("POST", "/api/auth/login"),
                ("GET", "/api/orders"),
            ]
        finally:
            client_b.close()


def test_mid_run_401_guards_auth_overrides_self_routes_reentrancy_and_scope(tmp_path: Path) -> None:
    def _router(method: str, path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, str, str, dict[str, str]]:
        if path in {"/api/protected", "/api/auth/login", "/api/auth/refresh"}:
            return 401, "application/json", '{"error":"unauthorized"}', {}
        return 200, "application/json", '{"ok":true}', {}

    with _start_loopback_server(_router) as (base_url, req_log):
        actors = ActorManager(
            [
                {
                    "alias": "m1",
                    "email": "m1@example.test",
                    "password": "ValidPass123!",
                    "access_token": "jwt-active",
                    "refresh_token": "rt-valid",
                    "refresh_path": "/api/auth/refresh",
                },
                {
                    "alias": "unauth",
                    "email": "u@example.test",
                    "password": "ValidPass123!",
                },
                {
                    "alias": "bad-scope",
                    "access_token": "jwt-active-2",
                    "refresh_token": "rt-valid-2",
                    "refresh_path": "https://evil.example/steal-refresh",
                },
            ],
            login_path="/api/auth/login",
        )
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=ReceiptStore(tmp_path / "guards"),
            actors=actors,
            allowed_methods=("GET", "POST"),
            max_requests=30,
        )
        try:
            # 1. Explicit Authorization override MUST NOT trigger refresh or re-login.
            rec_auth_ov = client.request(
                method="GET",
                url="/api/protected",
                actor="m1",
                headers={"Authorization": "Bearer forged-token"},
                force=True,
            )
            assert rec_auth_ov["status"] == 401
            assert [(r["method"], r["path"]) for r in req_log] == [("GET", "/api/protected")]

            # 2. Explicit Cookie override MUST NOT trigger refresh or re-login.
            req_log.clear()
            rec_cookie_ov = client.request(
                method="GET",
                url="/api/protected",
                actor="m1",
                headers={"Cookie": "sid=other-session"},
                force=True,
            )
            assert rec_cookie_ov["status"] == 401
            assert [(r["method"], r["path"]) for r in req_log] == [("GET", "/api/protected")]

            # 3. Explicit empty Authorization header (stripping auth for bypass test) MUST NOT refresh.
            req_log.clear()
            rec_strip = client.request(
                method="GET",
                url="/api/protected",
                actor="m1",
                headers={"Authorization": ""},
                force=True,
            )
            assert rec_strip["status"] == 401
            assert [(r["method"], r["path"]) for r in req_log] == [("GET", "/api/protected")]

            # 4. 401 on login_path or refresh_path itself MUST NOT trigger auto-refresh.
            req_log.clear()
            assert client.request(method="POST", url="/api/auth/login", actor="m1", json_body={})["status"] == 401
            assert client.request(method="POST", url="/api/auth/refresh", actor="m1", json_body={})["status"] == 401
            assert [(r["method"], r["path"]) for r in req_log] == [
                ("POST", "/api/auth/login"),
                ("POST", "/api/auth/refresh"),
            ]

            # 5. anon actor NEVER triggers refresh.
            req_log.clear()
            assert client.request(method="GET", url="/api/protected", actor="anon", force=True)["status"] == 401
            assert [(r["method"], r["path"]) for r in req_log] == [("GET", "/api/protected")]

            # 6. Never-authenticated actor returns False from _try_refresh_actor_session with 0 wire calls.
            req_log.clear()
            assert client._try_refresh_actor_session("unauth") is False
            assert req_log == []

            # 7. Re-entrancy flag blocks nested refresh attempts immediately.
            client._in_session_refresh = True
            try:
                assert client._try_refresh_actor_session("m1") is False
                assert req_log == []
            finally:
                client._in_session_refresh = False

            # 8. Out-of-scope refresh_path fails closed with zero wire calls.
            req_log.clear()
            assert client._try_refresh_actor_session("bad-scope") is False
            assert req_log == []
        finally:
            client.close()
