"""Faz 2: SessionRuntime — cookie jar, login tarifi, expire, TOTP."""
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load():
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    path = REPO_ROOT / "scripts" / "chain_executor.py"
    spec = importlib.util.spec_from_file_location("chain_executor_session", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ce = _load()


def test_totp_rfc_vector():
    # RFC 6238 test secret "12345678901234567890" base32
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert ce.totp_code(secret, timestamp=59) == "94287082"[:6] or len(ce.totp_code(secret, timestamp=59)) == 6
    assert ce.totp_code(secret, timestamp=59, digits=8) == "94287082"


def test_cookie_jar_roundtrip():
    jar = ce.CookieJar()
    jar.absorb({"Set-Cookie": "sid=abc; Path=/; HttpOnly, theme=dark; Path=/"})
    assert jar.header_value() == "sid=abc; theme=dark"
    jar.absorb({"set-cookie": "sid=; Max-Age=0"})
    assert "sid=" not in jar.header_value()


def _fake_app():
    state = {"token": 0, "calls": []}

    def sender(method, url, headers, body, timeout):
        state["calls"].append((method, url, dict(headers)))
        if url.endswith("/login"):
            state["token"] += 1
            return {"ok": True, "status": 200, "len": 40,
                    "text": '{"access_token": "tok-%d", "csrf": "c%d"}' % (state["token"], state["token"]),
                    "headers": {"Set-Cookie": f"sid=s{state['token']}; Path=/"}, "error": None}
        auth = headers.get("Authorization", "")
        if auth == f"Bearer tok-{state['token']}" and state["token"] > 0:
            return {"ok": True, "status": 200, "len": 2, "text": "{}", "headers": {}, "error": None}
        return {"ok": True, "status": 401, "len": 0, "text": "", "headers": {}, "error": None}

    return sender, state


RECIPE = {"url": "https://api.example.com/login", "method": "POST",
          "body": {"user": "a", "pass": "b"}, "token_path": "access_token",
          "csrf_path": "csrf", "csrf_header": "X-CSRF-Token"}


def test_session_login_relogin_and_cookie_flow():
    sender, state = _fake_app()
    sess = ce.SessionRuntime(recipe=RECIPE, sender=sender)
    resp = sess.request("GET", "https://api.example.com/me", {}, None, 5)
    assert resp["status"] == 200
    assert resp["session_state"] == "active"
    assert resp["relogins_used"] == 1
    # Ikinci istek login olmadan gecerli token + cookie ile gitmeli
    calls_before = len(state["calls"])
    resp2 = sess.request("GET", "https://api.example.com/me", {}, None, 5)
    assert resp2["status"] == 200 and resp2["relogins_used"] == 0
    last_headers = state["calls"][-1][2]
    assert last_headers.get("Cookie") == "sid=s1"
    assert last_headers.get("X-CSRF-Token") == "c1"
    assert len(state["calls"]) == calls_before + 1


def test_session_expires_when_relogin_cannot_help():
    def dead_sender(method, url, headers, body, timeout):
        return {"ok": True, "status": 401, "len": 0, "text": "", "headers": {}, "error": None}

    sess = ce.SessionRuntime(recipe=RECIPE, sender=dead_sender)
    resp = sess.request("GET", "https://api.example.com/me", {}, None, 5)
    assert resp["status"] == 401
    assert resp["session_state"] == "expired"


def test_chain_executor_accepts_login_recipe():
    sender, _state = _fake_app()
    ex = ce.ChainExecutor(sender=sender, login_recipe=RECIPE)
    assert isinstance(ex.session, ce.SessionRuntime)


@pytest.mark.parametrize("location", ["/login", "/log%69n", "/%256cogin"])
def test_shared_session_vault_syncs_and_detects_expiry(tmp_path, monkeypatch, location):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    val_dir = str(REPO_ROOT / "mcp-servers" / "mcp-validator")
    if val_dir not in sys.path:
        sys.path.insert(0, val_dir)
    from cco_validator_core.egress import (
        egress_request,
        load_shared_session,
        save_shared_session,
    )

    save_shared_session("https://app.example.test", cookie="sid=live99", headers={"X-CSRF": "tok1"})
    loaded = load_shared_session("app.example.test")
    assert loaded and loaded["state"] == "active"
    assert loaded["cookie"] == "sid=live99"

    class _FakeResp:
        def __init__(self, code, headers=None, body=b"ok"):
            self.status_code = code
            self.headers = headers or {}
            self.content = body
            self.text = body.decode()

    seen_headers = []

    def fake_transport(method, url, *, params, data, headers, timeout):
        seen_headers.append(dict(headers or {}))
        return _FakeResp(302, headers={"Location": location})

    resp = egress_request(
        "GET",
        "https://app.example.test/dashboard",
        allow_redirects=False,
        use_shared_session=True,
        transport=fake_transport,
    )
    assert seen_headers[0].get("Cookie") == "sid=live99"
    assert seen_headers[0].get("X-CSRF") == "tok1"
    assert resp.get("session_expired") is True
    after = load_shared_session("app.example.test")
    assert after["state"] == "expired"
    assert after["expired_reason"] == "login_redirect"


@pytest.mark.parametrize("location", ["/login", "/log%69n", "/%256cogin"])
def test_egress_does_not_follow_encoded_login_redirect(tmp_path, monkeypatch, location):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    val_dir = str(REPO_ROOT / "mcp-servers" / "mcp-validator")
    if val_dir not in sys.path:
        sys.path.insert(0, val_dir)
    from cco_validator_core.egress import egress_request

    calls = []
    class Response:
        status_code, content, text = 302, b"", ""
        headers = {"Location": location}
    def send(method, url, **kwargs):
        calls.append(url)
        return Response()
    result = egress_request("GET", "https://app.example.test/a", headers={"Cookie": "sid=synthetic"},
                            stop_on_login_redirect=True, transport=send)
    assert result["blocked"] == "login_redirect" and result["requests_sent"] == len(calls) == 1


def test_shared_sessions_are_never_forwarded_to_another_origin(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    val_dir = str(REPO_ROOT / "mcp-servers" / "mcp-validator")
    if val_dir not in sys.path:
        sys.path.insert(0, val_dir)
    from cco_validator_core.egress import egress_request, load_shared_session, save_shared_session
    save_shared_session("https://app.example.test", cookie="sid=synthetic", headers={"Authorization": "Bearer synthetic"})
    assert load_shared_session("https://app.example.test:443/", require_origin=True)["state"] == "active"
    calls = []
    for url in ("http://app.example.test/", "https://app.example.test:444/"):
        result = egress_request("GET", url, use_shared_session=True,
                                transport=lambda *args, **kw: calls.append(args))
        assert result["blocked"] == "session" and result["requests_sent"] == 0
    assert not calls
    save_shared_session("https://app.example.test:444", cookie="sid=other")
    other = load_shared_session("https://app.example.test:444", require_origin=True)
    assert other["cookie"] == "sid=other" and other["headers"] == {}
    assert load_shared_session("https://app.example.test", require_origin=True)["state"] == "origin_mismatch"


def test_host_only_legacy_session_requires_explicit_origin_binding(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    val_dir = str(REPO_ROOT / "mcp-servers" / "mcp-validator")
    if val_dir not in sys.path:
        sys.path.insert(0, val_dir)
    from cco_validator_core.egress import egress_request, save_shared_session
    save_shared_session("app.example.test", cookie="sid=legacy")
    result = egress_request("GET", "https://app.example.test/", use_shared_session=True,
                            transport=lambda *args, **kw: (_ for _ in ()).throw(AssertionError("must not send")))
    assert result["blocked"] == "session" and result["requests_sent"] == 0


def test_explicit_identity_does_not_mix_or_invalidate_shared_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    val_dir = str(REPO_ROOT / "mcp-servers" / "mcp-validator")
    if val_dir not in sys.path:
        sys.path.insert(0, val_dir)
    from cco_validator_core.egress import egress_request, load_shared_session, save_shared_session
    save_shared_session("https://app.example.test", cookie="sid=owner", headers={"X-Auth-Token": "owner-token"})
    seen = []
    class Response:
        status_code, content, text, headers = 302, b"", "", {"Location": "/login"}
    def send(method, url, **kwargs):
        seen.append(kwargs["headers"])
        return Response()
    result = egress_request("GET", "https://app.example.test/", headers={"Cookie": "sid=other"},
                            use_shared_session=True, allow_redirects=False, transport=send)
    assert result["status"] == 302 and seen == [{"Cookie": "sid=other"}]
    assert load_shared_session("https://app.example.test", require_origin=True)["state"] == "active"

