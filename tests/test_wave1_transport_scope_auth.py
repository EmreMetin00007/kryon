"""Comprehensive Wave 1 tests for target_bootstrap, agentic_http, agentic_auth_import, and save_browser_auth."""
from __future__ import annotations

from contextlib import contextmanager
from email.parser import BytesParser
from email.policy import default as email_default_policy
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any, Callable, Iterator
from urllib.parse import parse_qsl, urlsplit
import zlib

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_auth_import as auth_import  # noqa: E402
import agentic_http  # noqa: E402
from agentic_http import (  # noqa: E402
    ActorManager,
    ActorSession,
    AgenticHTTPClient,
    ScopeViolationError,
    _decode_raw_response,
    _parse_set_cookie_header,
    normalize_origin,
)
from agentic_receipts import ReceiptStore  # noqa: E402
import save_browser_auth  # noqa: E402
import target_bootstrap as tb  # noqa: E402


@contextmanager
def _start_raw_server(
    handler_fn: Callable[[str, str, dict[str, str], bytes], tuple[int, list[tuple[str, str]], bytes]],
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    observed: list[dict[str, Any]] = []
    lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length) if length > 0 else b""
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            with lock:
                observed.append({
                    "method": self.command,
                    "path": self.path,
                    "headers": hdrs,
                    "body": body,
                })
            status, resp_headers, raw = handler_fn(self.command, self.path, hdrs, body)
            self.send_response(status)
            has_cl = any(hk.lower() == "content-length" for hk, _ in resp_headers)
            for hk, hv in resp_headers:
                self.send_header(hk, hv)
            if not has_cl:
                self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

        def do_GET(self) -> None:
            self._dispatch()

        def do_POST(self) -> None:
            self._dispatch()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}/", observed
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=3.0)


# ---------------------------------------------------------------------------
# 1. target_bootstrap: wildcards, fail-closed exclusions, IPv6, DNS SSRF, accounts
# ---------------------------------------------------------------------------


def test_target_bootstrap_safe_wildcards_and_fail_closed_exclusions(tmp_path: Path) -> None:
    guard = tb.ScopeGuard(
        "https://www.target.com",
        in_scope_assets=("*.target.com",),
        out_of_scope_assets=(
            "admin-*.target.com",
            "*staging*.target.com",
            "*.internal.target.com",
        ),
    )
    assert guard.check_origin("https", "api.target.com", 443) is True
    assert guard.check_origin("https", "admin-eu.target.com", 443) is False
    assert guard.check_origin("https", "dev-staging-01.target.com", 443) is False
    assert guard.check_origin("https", "staging.target.com", 443) is False
    assert guard.check_origin("https", "db.internal.target.com", 443) is False
    assert guard.check_origin("https", "target.com", 443) is False

    # Unsafe wildcards fail closed in out_of_scope_assets and excluded_assets.
    for bad_entry in (
        "*.com",
        "*",
        "*.*",
        "*target.com",
        "ftp://bad.target.com",
        "bad..host.com",
        "::::",
        "admin-[a].target.com",
        "https://bad host.com",
        {"unknown": "evil.com"},
        {"asset": "bad..host"},
    ):
        with pytest.raises(ValueError):
            tb.ScopeGuard("https://www.target.com", out_of_scope_assets=(bad_entry,))  # type: ignore[arg-type]

    # excluded_assets rejects prose too, while out_of_scope still permits policy prose.
    bad_scope = tmp_path / "bad_scope.json"
    bad_scope.write_text(
        json.dumps({
            "in_scope": ["https://www.target.com"],
            "excluded_assets": ["DoS / load testing"],
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        tb.load_scope_file(bad_scope)

    bad_oos = tmp_path / "bad_oos.json"
    bad_oos.write_text(
        json.dumps({
            "in_scope": ["https://www.target.com"],
            "out_of_scope": ["ftp://evil.com"],
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        tb.resolve_target_origin("https://www.target.com", scope_file=bad_oos, allow_non_loopback=True)


def test_target_bootstrap_ipv6_validation_and_canonicalization(tmp_path: Path) -> None:
    assert tb._is_valid_host("::1") is True
    assert tb._is_valid_host("0:0:0:0:0:0:0:1") is True
    assert tb._is_valid_host("::::") is False
    assert tb._is_valid_host("fe80::1%eth0") is False

    origin, scheme, host, port = tb._normalize_explicit_origin("http://[0:0:0:0:0:0:0:1]:80/")
    assert (origin, scheme, host, port) == ("http://[::1]/", "http", "::1", 80)

    # Both bracketed and unbracketed IPv6 work in _parse_scope_asset and canonicalize.
    rule_unbracketed = tb._parse_scope_asset("0:0:0:0:0:0:0:1")
    rule_bracketed = tb._parse_scope_asset("[0:0:0:0:0:0:0:1]:8080")
    assert rule_unbracketed is not None and rule_unbracketed.host_pattern == "::1"
    assert rule_bracketed is not None and rule_bracketed.host_pattern == "::1" and rule_bracketed.port == 8080

    guard = tb.ScopeGuard(
        "http://[0:0:0:0:0:0:0:1]:8080/",
        in_scope_assets=("https://[2001:0db8:0000:0000:0000:0000:0000:0001]:443",),
        out_of_scope_assets=("2001:db8:0:0:0:0:0:2",),
    )
    assert guard.base_origin == "http://[::1]:8080/"
    assert guard.check_origin("http", "::1", 8080) is True
    assert guard.check_origin("http", "0:0:0:0:0:0:0:1", 8080) is True
    assert guard.check_origin("https", "2001:db8::1", 443) is True
    assert guard.check_origin("https", "[2001:db8::1]", 443) is True
    assert guard.check_origin("https", "2001:db8::2", 443) is False
    guard.check_url("http://[::1]:8080/api/items")
    guard.check_url("http://[0:0:0:0:0:0:0:1]:8080/api/items")

    scope_file = tmp_path / "ipv6_scope.json"
    scope_file.write_text(
        json.dumps({"in_scope": ["2001:0db8::1"]}),
        encoding="utf-8",
    )
    resolved_origin, _ = tb.resolve_target_origin(
        "https://[2001:db8:0:0::1]:443/",
        scope_file=scope_file,
        allow_non_loopback=True,
    )
    assert resolved_origin == "https://[2001:db8::1]/"


def test_target_bootstrap_dns_ssrf_guard_blocks_private_imds_cgnat_and_mapped_ipv6() -> None:
    guard_remote = tb.ScopeGuard("https://app.example.com/")
    assert guard_remote.loopback_only is False

    blocked_ips = [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.10.2",
        "192.168.1.50",
        "169.254.169.254",
        "100.64.0.1",
        "100.127.255.254",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "::",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        "::ffff:100.64.1.1",
    ]
    for bad_ip in blocked_ips:
        # Direct IP literal
        with pytest.raises(ValueError, match="DNS resolution blocked"):
            tb.check_dns_safety(bad_ip, 443)
        # Resolved hostname
        def _fake_res(_h: str, p: int, ip: str = bad_ip) -> list[tuple[Any, ...]]:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            return [(fam, socket.SOCK_STREAM, 6, "", (ip, p))]

        with pytest.raises(ValueError, match="DNS resolution blocked"):
            guard_remote.check_dns_safety("rebind.example.com", 443, resolver=_fake_res)

    # Public IPs succeed.
    for ok_ip in ("93.184.216.34", "2606:2800:220:1::"):
        tb.check_dns_safety(ok_ip, 443)
        guard_remote.check_dns_safety(
            "public.example.com",
            443,
            resolver=lambda _h, p, ip=ok_ip: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, p))],
        )

    # Loopback ScopeGuard stays unaffected.
    guard_lb = tb.ScopeGuard("http://127.0.0.1:8080/")
    assert guard_lb.loopback_only is True
    guard_lb.check_dns_safety("127.0.0.1", 8080)


def test_select_representative_accounts_keeps_preauth_without_password() -> None:
    accounts = [
        {"alias": "hdr-user", "tenant": "t1", "role": "member", "headers": {"X-API-Key": "k1"}},
        {"alias": "cookie-user", "tenant": "t2", "role": "member", "cookies": {"sid": "s1"}},
        {"alias": "access-user", "tenant": "t3", "role": "member", "access_token": "tok-1"},
        {"alias": "bearer-user", "tenant": "t4", "role": "member", "bearer_token": "tok-2"},
        {"alias": "ls-user", "tenant": "t5", "role": "admin", "local_storage": {"token": "ls-1"}},
        {"alias": "empty-user", "tenant": "t6", "role": "member", "password": ""},
    ]
    selected = tb.select_representative_accounts(accounts, max_members=10, max_admins=5)
    aliases = [a["alias"] for a in selected]
    assert aliases == ["hdr-user", "cookie-user", "access-user", "bearer-user", "ls-user"]


# ---------------------------------------------------------------------------
# 2. agentic_http: zstd/br/chained encoding, case-insensitive headers, cookies, redirects
# ---------------------------------------------------------------------------


def test_decode_raw_response_zstd_chained_and_accept_encoding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.dumps({"msg": "compressed-ok", "n": 42}).encode("utf-8")
    if agentic_http._stdlib_zstd is not None:
        zstd_bytes = agentic_http._stdlib_zstd.compress(payload)
        assert _decode_raw_response(zstd_bytes, "zstd") == payload

    # Chained encoding: "gzip, deflate" (inner gzip -> outer deflate).
    chained_bytes = zlib.compress(gzip.compress(payload))
    assert _decode_raw_response(chained_bytes, "gzip, deflate") == payload

    # Session Accept-Encoding advertises zstd only when runtime zstd support exists, never br when absent.
    store = ReceiptStore(tmp_path / "enc")
    client = AgenticHTTPClient(base_url="http://127.0.0.1:18080/", receipt_store=store)
    try:
        ae = client._get_session().headers["Accept-Encoding"].lower()
        assert "gzip" in ae and "deflate" in ae
        if agentic_http._stdlib_zstd is not None or agentic_http._zstandard is not None:
            assert "zstd" in ae
        else:
            assert "zstd" not in ae
        if agentic_http._brotli is None:
            assert "br" not in ae
    finally:
        client.close()

    # Fake brotli and stdlib zstd modules work end-to-end when importable (including on Python 3.12).
    monkeypatch.setattr(
        agentic_http,
        "_brotli",
        SimpleNamespace(decompress=lambda b: b.removeprefix(b"BR:")),
    )
    assert _decode_raw_response(b"BR:hello-br", "br") == b"hello-br"
    monkeypatch.setattr(
        agentic_http,
        "_stdlib_zstd",
        SimpleNamespace(decompress=lambda b: b.removeprefix(b"ZS:"), ZstdError=ValueError),
    )
    assert _decode_raw_response(b"ZS:hello-zstd", "zstd") == b"hello-zstd"


def test_live_zstd_and_case_insensitive_headers(tmp_path: Path) -> None:
    if agentic_http._stdlib_zstd is not None:
        encoding_name = "zstd"
        body_bytes = agentic_http._stdlib_zstd.compress(b'{"hello":"zstd"}')
    else:
        encoding_name = "gzip"
        body_bytes = gzip.compress(b'{"hello":"zstd"}')

    def _handler(_method: str, path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        if path == "/zstd":
            return (
                200,
                [
                    ("content-type", "application/json; charset=utf-8"),
                    ("content-encoding", encoding_name),
                ],
                body_bytes,
            )
        if path == "/redir":
            return (
                302,
                [
                    ("location", "/zstd"),
                    ("set-cookie", "hop_ck=v1; Path=/"),
                ],
                b"",
            )
        return 404, [("content-type", "text/plain")], b"missing"

    with _start_raw_server(_handler) as (base_url, _obs):
        store = ReceiptStore(tmp_path / "ci")
        client = AgenticHTTPClient(base_url=base_url, receipt_store=store, allowed_methods=("GET",))
        try:
            rec = client.request(method="GET", url="/redir", follow_redirects=True)
            assert rec["status"] == 200
            assert rec["content_type"] == "application/json"
            assert json.loads(rec["body"]) == {"hello": "zstd"}
        finally:
            client.close()


def test_actor_session_multi_origin_cookie_scoping_deletion_and_header_helpers(tmp_path: Path) -> None:
    # 1. normalize_origin lowercases host and strips default :80 / :443.
    assert normalize_origin("HTTPS://WWW.Example.COM:443/path") == "https://www.example.com/"
    assert normalize_origin("HTTP://Example.COM:80") == "http://example.com/"
    assert normalize_origin("http://[0:0:0:0:0:0:0:1]:80/") == "http://[::1]/"
    assert normalize_origin("https://api.example.com:8443") == "https://api.example.com:8443/"

    # 2. _parse_set_cookie_header preserves Expires HTTP-date commas and honors deletion.
    parsed_sc = _parse_set_cookie_header(
        "dead=gone; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/, "
        "alive=ok123; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Path=/, "
        "zero=bye; Max-Age=0; Path=/"
    )
    assert parsed_sc == {"alive": "ok123"}

    # 3. ActorSession.build_headers filters cookie_records by domain, path, secure, and falls back to ad-hoc cookies.
    session = ActorSession(
        alias="u1",
        cookies={"host_a": "va", "sub_dom": "vs", "sec_only": "vsec", "admin_only": "vadm", "adhoc": "vadhoc"},
        cookie_records=[
            {"name": "host_a", "value": "va", "domain": "a.target.com", "path": "/", "secure": False, "host_only": True},
            {"name": "sub_dom", "value": "vs", "domain": ".target.com", "path": "/", "secure": False, "host_only": False},
            {"name": "sec_only", "value": "vsec", "domain": ".target.com", "path": "/", "secure": True, "host_only": False},
            {"name": "admin_only", "value": "vadm", "domain": ".target.com", "path": "/admin", "secure": False, "host_only": False},
        ],
    )
    hdr_a_https = session.build_headers("GET", target_url="https://a.target.com/admin/users")
    assert hdr_a_https["Cookie"] == "adhoc=vadhoc; admin_only=vadm; host_a=va; sec_only=vsec; sub_dom=vs"

    hdr_b_http = session.build_headers("GET", target_url="http://b.target.com/admin-info")
    # host_a (host_only a.target.com), sec_only (secure=True over http), and admin_only (/admin vs /admin-info) excluded!
    assert hdr_b_http["Cookie"] == "adhoc=vadhoc; sub_dom=vs"

    # 4. ActorManager.set_global_headers does NOT overwrite existing actor auth headers.
    mgr = ActorManager([
        {
            "alias": "api-actor",
            "auth_header_name": "X-Custom-Token",
            "headers": {"X-Custom-Token": "actor-secret-tok", "X-API-Key": "actor-key"},
        }
    ])
    mgr.set_global_headers({"X-Custom-Token": "global-override", "X-API-Key": "global-key", "Pentest": "Cyberbounty"})
    built = mgr.get("api-actor").build_headers("GET")
    assert built["X-Custom-Token"] == "actor-secret-tok"
    assert built["X-API-Key"] == "actor-key"
    assert built["Pentest"] == "Cyberbounty"

    # 5. Cookie deletion via live Set-Cookie Max-Age=0 + cache invalidation.
    state = {"logged_out": False, "version": 1}

    def _router(method: str, path: str, hdrs: dict[str, str], _body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        if path == "/profile":
            cookie_hdr = hdrs.get("cookie", "")
            return (
                200,
                [("Content-Type", "application/json")],
                json.dumps({"cookie": cookie_hdr, "v": state["version"]}).encode("utf-8"),
            )
        if path == "/drop-cookie":
            state["logged_out"] = True
            state["version"] = 2
            return (
                200,
                [
                    ("Content-Type", "application/json"),
                    ("Set-Cookie", "sid=deleted; Path=/; Max-Age=0"),
                ],
                b'{"dropped":true}',
            )
        return 404, [("Content-Type", "text/plain")], b"nf"

    with _start_raw_server(_router) as (base_url, obs):
        actors = ActorManager([{"alias": "u1", "cookies": {"sid": "live-sid-1", "keep": "yes"}}])
        store = ReceiptStore(tmp_path / "del")
        client = AgenticHTTPClient(base_url=base_url, receipt_store=store, actors=actors, allowed_methods=("GET", "POST"))
        try:
            r1 = client.request(method="GET", url="/profile", actor="u1")
            assert r1["cached"] is False
            assert "sid=live-sid-1" in obs[-1]["headers"]["cookie"]
            assert "live-sid-1" not in r1["body"]

            r_cached = client.request(method="GET", url="/profile", actor="u1")
            assert r_cached["cached"] is True

            # Trigger Set-Cookie deletion -> removes sid AND invalidates u1 cache.
            client.request(method="GET", url="/drop-cookie", actor="u1")
            assert "sid" not in actors.get("u1").cookies
            r2 = client.request(method="GET", url="/profile", actor="u1")
            assert r2["cached"] is False
            assert "sid=" not in obs[-1]["headers"]["cookie"]
            assert "keep=yes" in obs[-1]["headers"]["cookie"]
        finally:
            client.close()


def test_http_redirects_strip_cross_origin_auth_and_stop_on_out_of_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Part A: Out-of-scope redirect stops cleanly and returns 302 receipt with redirect_location.
    def _handler(_method: str, path: str, _hdrs: dict[str, str], _body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        if path == "/sso-external":
            return (
                302,
                [("Location", "https://idp.external.example/oauth/authorize?client_id=1")],
                b"",
            )
        return 200, [("Content-Type", "text/plain")], b"ok"

    with _start_raw_server(_handler) as (base_url, _obs):
        store = ReceiptStore(tmp_path / "ext_redir")
        client = AgenticHTTPClient(base_url=base_url, receipt_store=store, allowed_methods=("GET",))
        try:
            # Default follow_redirects=True stays fail-closed on external hosts.
            with pytest.raises(ScopeViolationError):
                client.request(method="GET", url="/sso-external", follow_redirects=True)
            # Explicit opt-in stop_on_out_of_scope_redirect=True returns the 302 receipt cleanly.
            rec = client.request(
                method="GET",
                url="/sso-external",
                follow_redirects=True,
                stop_on_out_of_scope_redirect=True,
                force=True,
            )
            assert rec["status"] == 302
            assert rec["redirect_location"] == "https://idp.external.example/oauth/authorize?client_id=1"
        finally:
            client.close()

    # Part B: Cross-origin & HTTPS->HTTP downgrade redirects strip auth headers & hop cookies.
    sent_calls: list[dict[str, Any]] = []

    def _make_mock_resp(status: int, headers: dict[str, str], body: bytes) -> Any:
        raw_obj = SimpleNamespace(
            read=lambda *_a, **_kw: body,
            headers=SimpleNamespace(getlist=lambda name: [headers[k] for k in headers if k.lower() == name.lower()]),
        )
        return SimpleNamespace(
            status_code=status,
            headers=headers,
            raw=raw_obj,
            cookies=[],
            close=lambda: None,
        )

    store_b = ReceiptStore(tmp_path / "cross_redir")
    actors_b = ActorManager([
        {
            "alias": "m1",
            "access_token": "actor-jwt-secret",
            "cookie_records": [
                {"name": "host_a", "value": "only-a", "domain": "app.target.example", "path": "/", "secure": True, "host_only": True},
                {"name": "shared", "value": "for-both", "domain": ".target.example", "path": "/", "secure": True, "host_only": False},
            ],
        }
    ])
    client_b = AgenticHTTPClient(
        base_url="https://app.target.example/",
        receipt_store=store_b,
        actors=actors_b,
        in_scope_assets=("*.target.example", "http://plain.target.example"),
    )
    try:
        sess = client_b._get_session()

        def _mock_request(method: str, url: str, headers: dict[str, str], **_kwargs: Any) -> Any:
            sent_calls.append({"method": method, "url": url, "headers": dict(headers)})
            if url == "https://app.target.example/start":
                return _make_mock_resp(
                    302,
                    {
                        "Location": "https://bff.target.example/step2",
                        "Set-Cookie": "hop_a=hopval; Path=/",
                    },
                    b"",
                )
            if url == "https://bff.target.example/step2":
                return _make_mock_resp(
                    302,
                    {"Location": "http://plain.target.example/downgraded"},
                    b"",
                )
            return _make_mock_resp(200, {"Content-Type": "application/json"}, b'{"done":true}')

        monkeypatch.setattr(sess, "request", _mock_request)
        rec = client_b.request(
            method="GET",
            url="/start",
            actor="m1",
            headers={"Authorization": "Bearer caller-secret", "Cookie": "caller=c1", "X-Trace": "keep"},
            follow_redirects=True,
        )
        assert rec["status"] == 200
        assert len(sent_calls) == 3

        # Hop 1 -> app.target.example: caller override sent.
        assert sent_calls[0]["headers"]["Authorization"] == "Bearer caller-secret"
        assert sent_calls[0]["headers"]["Cookie"] == "caller=c1"

        # Hop 2 -> bff.target.example: caller Authorization/Cookie and hop_a stripped; only .target.example cookie sent.
        h2 = {k.lower(): v for k, v in sent_calls[1]["headers"].items()}
        assert h2["authorization"] == "Bearer actor-jwt-secret"
        assert "caller=c1" not in h2.get("cookie", "")
        assert "hop_a=" not in h2.get("cookie", "")
        assert "only-a" not in h2.get("cookie", "")
        assert "shared=for-both" in h2.get("cookie", "")
        assert h2["x-trace"] == "keep"

        # Hop 3 -> http://plain.target.example (HTTPS->HTTP downgrade): NO Authorization and NO Cookie sent!
        h3 = {k.lower(): v for k, v in sent_calls[2]["headers"].items()}
        assert "authorization" not in h3
        assert "cookie" not in h3

        # Also verify live DNS guard blocks private/IMDS resolutions in _send_wire while gaierror passes through to mock.
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda _h, p, *_a, **_kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", p))],
        )
        with pytest.raises(ScopeViolationError, match="DNS resolution blocked"):
            client_b.request(method="GET", url="/imds-ssrf", actor="anon", force=True)
    finally:
        client_b.close()


def test_http_refresh_csrf_multipart_and_concurrent_burst(tmp_path: Path) -> None:
    burst_times: list[float] = []
    lock = threading.Lock()

    def _handler(method: str, path: str, hdrs: dict[str, str], body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        if path == "/api/v1/access/sign-in" and method == "POST":
            return (
                200,
                [("Content-Type", "application/json")],
                b'{"access_token":"fresh-login-tok"}',
            )
        if path == "/api/custom-cookie-refresh" and method == "POST":
            if "sid=old-ck" in hdrs.get("cookie", ""):
                return (
                    200,
                    [("Content-Type", "application/json"), ("Set-Cookie", "sid=new-ck; Path=/")],
                    b'{"ok":true}',
                )
            return 401, [("Content-Type", "application/json")], b'{"err":"no"}'
        if path == "/cookie-protected":
            if "sid=new-ck" in hdrs.get("cookie", ""):
                return 200, [("Content-Type", "application/json")], b'{"protected":true}'
            return 401, [("Content-Type", "application/json")], b'{"err":"expired"}'
        if path == "/upload":
            ct = hdrs.get("content-type", "")
            raw_msg = f"Content-Type: {ct}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
            msg = BytesParser(policy=email_default_policy).parsebytes(raw_msg)
            assert msg.is_multipart()
            return 200, [("Content-Type", "application/json")], json.dumps({"ct": ct}).encode("utf-8")
        if path == "/echo-form":
            return 200, [("Content-Type", "application/json")], json.dumps(dict(parse_qsl(body.decode("utf-8")))).encode("utf-8")
        if path == "/burst":
            with lock:
                burst_times.append(time.monotonic())
            return 503, [("Content-Type", "text/plain")], b"busy"
        return 404, [("Content-Type", "text/plain")], b"nf"

    with _start_raw_server(_handler) as (base_url, obs):
        actors = ActorManager(
            [
                {
                    "alias": "ck-user",
                    "cookies": {"sid": "old-ck"},
                },
                {
                    "alias": "csrf-user",
                    "email": "csrf@example.test",
                    "password": "pw",
                    "csrf_token": "live-csrf-token-999",
                    "csrf_field_name": "csrf_token",
                    "access_token": "tok-csrf",
                },
            ],
            refresh_path="/api/custom-cookie-refresh",
        )
        store = ReceiptStore(tmp_path / "misc")
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=actors,
            allowed_methods=("GET", "POST"),
            max_rps=0.5,  # 2 seconds between normal requests!
            max_degradation_streak=5,
            max_requests=40,
        )
        try:
            # 1. Non-default ActorManager.refresh_path enables cookie-only refresh.
            rec_ck = client.request(method="GET", url="/cookie-protected", actor="ck-user")
            assert rec_ck["status"] == 200
            assert actors.get("ck-user").cookies["sid"] == "new-ck"

            # 2. Bare "Content-Type: multipart/form-data" without boundary is replaced with valid boundary header.
            rec_mp = client.request(
                method="POST",
                url="/upload",
                actor="anon",
                headers={"Content-Type": "multipart/form-data"},
                files=[{"field": "f", "filename": "a.txt", "content": "hi"}],
            )
            assert rec_mp["status"] == 200
            assert "boundary=" in json.loads(rec_mp["body"])["ct"]

            # 3. raw_body with <REDACTED...> in csrf_field substitutes live session.csrf_token.
            rec_raw = client.request(
                method="POST",
                url="/echo-form",
                actor="csrf-user",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                raw_body="name=alice&csrf_token=<REDACTED:len=10,sha256_8=12345678>",
            )
            assert rec_raw["status"] == 200
            echo_req = next(row for row in reversed(obs) if row["path"] == "/echo-form")
            assert dict(parse_qsl(echo_req["body"].decode("utf-8")))["csrf_token"] == "live-csrf-token-999"
            assert "live-csrf-token-999" not in rec_raw["body"]

            # 4. concurrent_burst=True skips max_rps pacing (0.5 RPS -> 4 serial calls would take ~6s)
            #    AND coalesces 503 degradation streak in a single burst without tripping streak=5.
            t0 = time.monotonic()
            barrier = threading.Barrier(4)
            results: list[dict[str, Any]] = []
            res_lock = threading.Lock()

            def _worker() -> None:
                barrier.wait(timeout=5.0)
                r = client.request(method="GET", url="/burst", actor="anon", force=True, concurrent_burst=True)
                with res_lock:
                    results.append(r)

            threads = [threading.Thread(target=_worker) for _ in range(4)]
            for th in threads:
                th.start()
            for th in threads:
                th.join(timeout=5.0)
            elapsed = time.monotonic() - t0
            assert len(results) == 4
            assert all(r["status"] == 503 for r in results)
            assert elapsed < 1.5
            assert client._degradation_streak == 1

            # 5. Per-actor refresh lock: refreshing actor A does NOT block actor B,
            #    and refresh success invalidates cached GET receipts for that actor only.
            actors.get("csrf-user").cookies["k"] = "1"
            client._cache[("ck-user", "GET", f"{base_url.rstrip('/')}/cookie-protected", (), False)] = {"status": 200}
            client._cache[("csrf-user", "GET", f"{base_url.rstrip('/')}/keep-cached", (), False)] = {"status": 200}
            ck_sess = actors.get("ck-user")
            ck_sess.cookies["sid"] = "old-ck"
            ck_sess.cookie_records.clear()
            client._refreshing_actors.add("csrf-user")
            try:
                assert client._try_refresh_actor_session("csrf-user") is False
                assert client._try_refresh_actor_session("ck-user") is True
                assert ("ck-user", "GET", f"{base_url.rstrip('/')}/cookie-protected", (), False) not in client._cache
                assert ("csrf-user", "GET", f"{base_url.rstrip('/')}/keep-cached", (), False) in client._cache
            finally:
                client._refreshing_actors.discard("csrf-user")

            # 6. authenticate_actor(force_login=True) invalidates cached entries for that actor.
            assert ("csrf-user", "GET", f"{base_url.rstrip('/')}/keep-cached", (), False) in client._cache
            assert client.authenticate_actor("csrf-user", force_login=True) is True
            assert ("csrf-user", "GET", f"{base_url.rstrip('/')}/keep-cached", (), False) not in client._cache
        finally:
            client.close()


# ---------------------------------------------------------------------------
# 3. agentic_auth_import: cookie_records, local_storage_by_origin, apex, JSON tokens
# ---------------------------------------------------------------------------


def test_agentic_auth_import_cookie_records_apex_rejection_and_json_blob_tokens() -> None:
    state = {
        "cookies": [
            # Host-only apex cookie when only *.target.com is in scope -> MUST be rejected!
            {"name": "apex_host_only", "value": "reject-me", "domain": "target.com", "path": "/", "secure": True},
            # Leading-dot domain cookie for .target.com -> MUST be accepted!
            {"name": "sso_shared", "value": "keep-me", "domain": ".target.com", "path": "/app", "secure": True},
        ],
        "origins": [
            {
                "origin": "https://www.target.com",
                "localStorage": [
                    {"name": "id_token", "value": "base-id-tok"},
                    {"name": "xsrf_token", "value": "base-xsrf-tok"},
                ],
            },
            {
                "origin": "https://auth.target.com",
                "localStorage": [
                    # Sibling has higher-priority key name, but base_url origin_tier MUST win!
                    {"name": "access_token", "value": "sibling-access-tok"},
                    {"name": "csrf_token", "value": "sibling-csrf-tok"},
                ],
            },
        ],
    }

    actor = auth_import.load_storage_state_actor(
        state,
        base_url="https://www.target.com/",
        in_scope_assets=("*.target.com",),
    )
    assert actor["cookies"] == {"sso_shared": "keep-me"}
    assert actor["cookie_records"] == [
        {
            "name": "sso_shared",
            "value": "keep-me",
            "domain": ".target.com",
            "path": "/app",
            "secure": True,
            "host_only": False,
        }
    ]
    assert actor["local_storage_by_origin"] == {
        "https://www.target.com": {"id_token": "base-id-tok", "xsrf_token": "base-xsrf-tok"},
        "https://auth.target.com": {"access_token": "sibling-access-tok", "csrf_token": "sibling-csrf-tok"},
    }
    assert actor["access_token"] == "base-id-tok"
    assert actor["csrf_token"] == "base-xsrf-tok"

    # Nested JSON blob extraction (Auth0 / MSAL / Firebase / Supabase) never emits Bearer {...}.
    auth0_state = {
        "cookies": [],
        "origins": [
            {
                "origin": "https://spa.example.com",
                "localStorage": [
                    {"name": "token", "value": json.dumps({"expires": 99999, "body": {"access_token": "Bearer real-nested-jwt"}})},
                    {"name": "firebase:authUser:abc", "value": json.dumps({"stsTokenManager": {"accessToken": "fb-tok"}})},
                ],
            }
        ],
    }
    auth0_actor = auth_import.load_storage_state_actor(auth0_state, base_url="https://spa.example.com/")
    assert auth0_actor["access_token"] == "real-nested-jwt"
    assert auth0_actor["auth_header"] == "Bearer real-nested-jwt"

    # A JSON blob under "token" key without any nested token must NOT produce Bearer {...}.
    bad_json_state = {
        "cookies": [],
        "origins": [
            {
                "origin": "https://spa.example.com",
                "localStorage": [{"name": "token", "value": json.dumps({"foo": "bar"})}],
            }
        ],
    }
    bad_actor = auth_import.load_storage_state_actor(bad_json_state, base_url="https://spa.example.com/")
    assert bad_actor["access_token"] == ""
    assert bad_actor["auth_header"] == ""


# ---------------------------------------------------------------------------
# 4. save_browser_auth: default proxy off, --proxy, SSO popup, WAF titles, OTP sleep
# ---------------------------------------------------------------------------


def test_save_browser_auth_proxy_default_off_waf_titles_popup_and_otp_sleep(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Default PROXY is empty when CCO_PROXY is not set.
    monkeypatch.delenv("CCO_PROXY", raising=False)
    assert save_browser_auth.os.environ.get("CCO_PROXY", "").strip() == ""
    monkeypatch.setattr(save_browser_auth, "PROXY", "")
    assert save_browser_auth._proxy_args() == {}

    # --proxy flag passes resolved proxy when reachable.
    monkeypatch.setattr(
        save_browser_auth,
        "_resolve_proxy_args",
        lambda u: {"proxy": {"server": u}} if u else {},
    )

    state: dict[str, Any] = {"context_kwargs": None, "popup_filled": []}

    class _FakePopupPage:
        url = "https://idp.example.com/otp"

        def set_default_timeout(self, _ms: int) -> None:
            return

        def wait_for_load_state(self, *_a: Any, **_kw: Any) -> None:
            return

        def wait_for_selector(self, *_a: Any, **_kw: Any) -> None:
            return

        def is_visible(self, sel: str, **_kw: Any) -> bool:
            return sel == "#popup-otp"

        def fill(self, sel: str, val: str) -> None:
            state["popup_filled"].append((sel, val))

        def click(self, *_a: Any, **_kw: Any) -> None:
            return

        def wait_for_timeout(self, _ms: int) -> None:
            return

        def title(self) -> str:
            return "SSO Complete"

        def is_closed(self) -> bool:
            return False

    class _FakeMainPage:
        url = "https://app.example.com/login"

        def set_default_timeout(self, _ms: int) -> None:
            return

        def goto(self, *_a: Any, **_kw: Any) -> Any:
            return SimpleNamespace(status=200)

        def wait_for_timeout(self, _ms: int) -> None:
            return

        def title(self) -> str:
            return "Sign In"

        def fill(self, *_a: Any, **_kw: Any) -> None:
            return

        def click(self, *_a: Any, **_kw: Any) -> None:
            # Trigger popup SSO page on submit.
            for cb in state["on_page_callbacks"]:
                cb(_FakePopupPage())

        def is_visible(self, *_a: Any, **_kw: Any) -> bool:
            return False

        def is_closed(self) -> bool:
            return False

    state["on_page_callbacks"] = []

    class _FakeCtx:
        def on(self, event: str, cb: Any) -> None:
            if event == "page":
                state["on_page_callbacks"].append(cb)

        def new_page(self) -> _FakeMainPage:
            return _FakeMainPage()

        def storage_state(self, path: str) -> None:
            Path(path).write_text('{"cookies":[],"origins":[]}', encoding="utf-8")

        def cookies(self) -> list[Any]:
            return []

        def close(self) -> None:
            return

    class _FakeBrowser:
        def new_context(self, **kwargs: Any) -> _FakeCtx:
            state["context_kwargs"] = dict(kwargs)
            return _FakeCtx()

        def close(self) -> None:
            return

    class _FakePlaywrightCM:
        def __enter__(self) -> Any:
            return SimpleNamespace(chromium=SimpleNamespace(launch=lambda **_kw: _FakeBrowser()))

        def __exit__(self, *_a: Any) -> bool:
            return False

    monkeypatch.setitem(
        sys.modules,
        "playwright.sync_api",
        SimpleNamespace(sync_playwright=lambda: _FakePlaywrightCM()),
    )

    # Test popup SSO OTP + don't sleep after last failed OTP attempt.
    sleeps: list[float] = []
    monkeypatch.setattr(save_browser_auth.time, "sleep", sleeps.append)
    otp_calls = {"n": 0}

    def _fake_otp(**_kw: Any) -> dict[str, Any]:
        otp_calls["n"] += 1
        if otp_calls["n"] < 3:
            raise save_browser_auth.OtpError("not yet")
        return {"code": "654321", "age_seconds": 2}

    monkeypatch.setattr(save_browser_auth, "fetch_latest_otp", _fake_otp)
    login_file = tmp_path / "login.json"
    login_file.write_text('{"username":"u","password":"p"}', encoding="utf-8")
    login_file.chmod(0o600)

    rc = save_browser_auth.main([
        "--program", "p1",
        "--login-url", "https://app.example.com/login",
        "--user-selector", "#u",
        "--pass-selector", "#p",
        "--submit-selector", "#s",
        "--otp-selector", "#popup-otp",
        "--otp-retries", "3",
        "--otp-wait", "7",
        "--proxy", "http://127.0.0.1:9999",
        "--login-file", str(login_file),
        "--storage", str(tmp_path / "storage.json"),
    ])
    assert rc == 0
    assert state["context_kwargs"]["proxy"] == {"server": "http://127.0.0.1:9999"}
    assert state["popup_filled"] == [("#popup-otp", "654321")]
    assert sleeps == [7, 7]

    # When all 3 OTP retries fail, sleep is called ONLY twice (never after final attempt).
    sleeps.clear()
    monkeypatch.setattr(
        save_browser_auth,
        "fetch_latest_otp",
        lambda **_kw: (_ for _ in ()).throw(save_browser_auth.OtpError("missing")),
    )
    rc_fail = save_browser_auth.main([
        "--program", "p1",
        "--login-url", "https://app.example.com/login",
        "--user-selector", "#u",
        "--pass-selector", "#p",
        "--submit-selector", "#s",
        "--otp-selector", "#popup-otp",
        "--otp-retries", "3",
        "--otp-wait", "5",
        "--login-file", str(login_file),
        "--storage", str(tmp_path / "storage2.json"),
    ])
    assert rc_fail == 2
    assert sleeps == [5, 5]

    # Broader WAF titles return exit code 3.
    for waf_title in ("Attention Required! | Cloudflare", "Access Denied", "Just a moment..."):
        _FakeMainPage.title = lambda _self, t=waf_title: t  # type: ignore[assignment]
        rc_waf = save_browser_auth.main([
            "--program", "p1",
            "--login-url", "https://app.example.com/login",
            "--user-selector", "#u",
            "--pass-selector", "#p",
            "--submit-selector", "#s",
            "--login-file", str(login_file),
            "--storage", str(tmp_path / "storage3.json"),
        ])
        assert rc_waf == 3
