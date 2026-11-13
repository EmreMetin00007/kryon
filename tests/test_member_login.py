"""A published ordinary login is gated; session material stays in the vault."""
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import member_login as login  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402

TARGET = "https://lab.example:8899"
LOGIN = TARGET + "/auth/quick-login"
FORM = """<form method="post" action="/auth/quick-login">
<input type="hidden" name="csrf_token" value="synthetic-csrf">
<select name="who"><option value="member-a">Member A</option>
<option value="member-b">Member B</option><option value="admin">Administrator</option></select>
</form>"""


class Response:
    def __init__(self, status=200, text="", headers=None):
        self.status_code, self.encoding = status, "utf-8"
        self.body, self.headers = text.encode(), headers or {}

    def iter_content(self, size):
        yield self.body

    def close(self):
        pass


@pytest.fixture
def setup(tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": TARGET}], "allow_loopback": False,
                                 "allow_osint": False, "allow_public_labs": False}))
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"blocked_http_methods": ["POST", "PUT", "PATCH", "DELETE"],
                                  "member_login": {"login_url": LOGIN, "accounts": ["member-a", "member-b"],
                                                   "test_data_only": True},
                                  "rate_limits": {"default": {"window_seconds": 60, "max_calls": 1000}}}))
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    monkeypatch.delenv("CCO_VAULT_KEY", raising=False)
    monkeypatch.setenv("CCO_USE_KEYRING", "0")
    engine = PolicyEngine()
    grant = engine.grant_approval(login.TOOL, "lab.example", ttl_seconds=600, reason="owned test")
    calls, configuration = [], {"root": FORM, "private": True, "profile_status": 200, "role": "member", "location": "/dashboard"}

    class Client(requests.Session):
        def send(self, prepared, **kwargs):
            calls.append(prepared)
            path = urlsplit(prepared.url).path
            if path == "/":
                return Response(text=configuration["root"])
            if path == "/auth/quick-login":
                body = prepared.body.decode() if isinstance(prepared.body, bytes) else prepared.body
                values = parse_qs(body or urlsplit(prepared.url).query)
                identity = values.get("who", [""])[0]
                assert identity in {"member-a", "member-b"}
                self.cookies.set("lab_session", "synthetic-cookie-" + identity,
                                 domain="lab.example", path="/")
                return Response(302, headers={"Location": configuration["location"]})
            if path == "/dashboard":
                cookie = prepared.headers.get("Cookie", "")
                if not cookie and configuration["private"]:
                    return Response(401)
                identity = "member-b" if "member-b" in cookie else "member-a"
                body = json.dumps({"username": identity, "role": configuration["role"]})
                return Response(configuration["profile_status"], body)
            raise AssertionError("Unexpected target path")

    monkeypatch.setattr(login.requests, "Session", Client)
    monkeypatch.setattr(login.time, "sleep", lambda _: None)
    return engine, grant, calls, configuration, tmp_path, policy


def test_form_uses_one_published_member_and_preserves_csrf():
    method, url, data, markers = login.published_flow(FORM, TARGET + "/", LOGIN, "member-a")
    assert method == "POST" and url == LOGIN
    assert data == {"who": "member-a", "csrf_token": "synthetic-csrf"}
    assert "member-a" in markers and "admin" not in data.values()


def test_published_get_link_and_button_are_supported():
    method, url, data, _ = login.published_flow(
        '<a href="/auth/quick-login?who=member-a">Member A</a>', TARGET + "/", LOGIN, "member-a")
    assert method == "GET" and url.endswith("?who=member-a") and data == {}
    method, _, data, _ = login.published_flow(
        '<form action="/auth/quick-login" method="post"><button name="who" value="member-a">Member A</button></form>',
        TARGET + "/", LOGIN, "member-a")
    assert method == "POST" and data == {"who": "member-a"}


@pytest.mark.parametrize("html,reason", [
    ('<form action="https://other.example/auth/quick-login"><input name="who" value="member-a"></form>', "published_member_login_missing"),
    ('<form action="/auth/quick-login"><input type="password" name="password"></form>', "credentials_required"),
    ('<a href="/auth/quick-login?who=member-a&action=delete">Member A</a>', "published_member_login_missing"),
    ('<form action="/auth/quick-login"><select name="who"><option value="member-a" data-role="admin">Member A</option></select></form>', "published_member_login_missing"),
])
def test_unsafe_or_password_flow_is_not_attempted(html, reason):
    with pytest.raises(login.LoginStopped, match=reason):
        login.published_flow(html, TARGET + "/", LOGIN, "member-a")


def test_two_members_receive_separate_encrypted_verified_sessions(setup):
    _, _, calls, _, tmp, _ = setup
    first = login.login_member(TARGET, "member-a")
    second = login.login_member(TARGET, "member-b")
    assert first["ok"] and second["ok"]
    assert first["status"] == second["status"] == "fresh"
    assert first["actual_requests"] == second["actual_requests"] == 5
    assert [call.method for call in calls].count("POST") == 2
    assert "synthetic-cookie" not in json.dumps([first, second])
    index = (tmp / "home/session_vault.json").read_text()
    assert "synthetic-cookie" not in index and '"secret_backend": "fernet"' in index
    from cco_surface_core import session_store
    assert session_store.verified_session(TARGET, "member-a") is not None
    assert session_store.verified_session(TARGET, "member-b") is not None


def test_existing_session_is_rechecked_without_another_login(setup):
    _, _, calls, _, _, _ = setup
    assert login.login_member(TARGET, "member-a")["ok"]
    again = login.login_member(TARGET, "member-a")
    assert again["ok"] and again["actual_requests"] == 1
    assert [call.method for call in calls].count("POST") == 1


@pytest.mark.parametrize("identity", ["admin", "root", "other-member"])
def test_unapproved_identity_never_reaches_transport(setup, identity):
    _, _, calls, _, _, _ = setup
    out = login.login_member(TARGET, identity)
    assert not out["ok"] and out["actual_requests"] == 0 and calls == []


def test_cross_origin_target_never_reaches_transport(setup):
    _, _, calls, _, _, _ = setup
    out = login.login_member("https://other.example", "member-a")
    assert not out["ok"] and calls == []


def test_revoked_grant_blocks_before_transport(setup):
    engine, grant, calls, _, _, _ = setup
    engine.revoke_approval(grant.id)
    out = login.login_member(TARGET, "member-a")
    assert out["reason"] == "policy:blocked_approval_required" and calls == []


@pytest.mark.parametrize("method,url,tool", [
    ("POST", TARGET + "/documents", login.TOOL),
    ("DELETE", LOGIN, login.TOOL),
    ("PUT", LOGIN, login.TOOL),
    ("POST", LOGIN, "kali-tools_curl_request"),
])
def test_login_exception_cannot_widen_other_methods_or_tools(setup, method, url, tool):
    engine, _, _, _, _, _ = setup
    out = engine.validate_wire_invocation(tool, {"target": url, "url": url, "method": method})
    assert out["allowed"] is False and out["reason"] == "blocked_http_method"


def test_login_exception_keeps_scope_and_grant_checks(setup):
    engine, _, _, _, _, _ = setup
    allowed = engine.validate_wire_invocation(login.TOOL, {"target": LOGIN, "url": LOGIN, "method": "POST"})
    assert allowed["allowed"]
    outside = engine.validate_wire_invocation(login.TOOL, {
        "target": "https://other.example/auth/quick-login", "method": "POST"})
    assert not outside["allowed"] and outside["reason"] == "blocked_scope"


@pytest.mark.parametrize("status,role,private,reason", [
    (500, "member", True, "service_stop_http_500"),
    (429, "member", True, "service_stop_http_429"),
    (200, "admin", True, "privileged_session_denied"),
    (200, "member", False, "profile_check_not_private"),
])
def test_degradation_privileged_or_public_profile_stops(setup, status, role, private, reason):
    _, _, _, config, tmp, _ = setup
    config.update(profile_status=status, role=role, private=private)
    out = login.login_member(TARGET, "member-a")
    assert not out["ok"] and out["reason"] == reason
    assert not (tmp / "home/session_vault.json").exists()


@pytest.mark.parametrize("rule", [
    {"login_url": LOGIN, "accounts": ["member-a"], "test_data_only": False},
    {"login_url": TARGET + "/documents", "accounts": ["member-a"], "test_data_only": True},
    {"login_url": LOGIN + "?action=delete", "accounts": ["member-a"], "test_data_only": True},
    {"login_url": LOGIN, "accounts": ["member-a", "member-a"], "test_data_only": True},
])
def test_malformed_login_policy_fails_closed(setup, rule):
    _, _, _, _, _, policy = setup
    data = json.loads(policy.read_text())
    data["member_login"] = rule
    policy.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        PolicyEngine()


def test_native_mcp_bridge_exposes_no_password_or_cookie_arguments(setup, monkeypatch):
    import inspect
    from conftest import load_server
    from orchestration_spec import CORE_TOOLS
    server = load_server("kali-tools")
    monkeypatch.setattr(login, "login_member", lambda target, identity: {
        "ok": True, "identity": identity, "target": target, "security_finding": False})
    assert set(inspect.signature(server.member_login).parameters) == {"target", "identity"}
    assert json.loads(server.member_login(TARGET, "member-a"))["ok"]
    assert len(CORE_TOOLS) == 29 and login.TOOL not in CORE_TOOLS


@pytest.mark.parametrize("location", ["https://other.example/dashboard", "/logout", "/admin/dashboard"])
def test_unsafe_redirect_is_rejected_before_a_followup_request(setup, location):
    _, _, calls, config, tmp, _ = setup
    config["location"] = location
    out = login.login_member(TARGET, "member-a")
    assert not out["ok"] and len(calls) == 2
    assert not (tmp / "home/session_vault.json").exists()
    assert all(urlsplit(call.url).hostname == "lab.example" for call in calls)


def test_failed_login_is_not_replayed_as_bruteforce(setup):
    _, _, calls, config, _, _ = setup
    config["profile_status"] = 401
    assert not login.login_member(TARGET, "member-a")["ok"]
    second = login.login_member(TARGET, "member-a")
    assert second["reason"] == "login_attempt_budget_exhausted"
    assert [call.method for call in calls].count("POST") == 1


def test_member_pacing_is_shared_between_tool_instances(tmp_path, monkeypatch):
    clock, sleeps = [10.0], []
    monkeypatch.setattr(login.time, "monotonic", lambda: clock[0])
    def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay
    monkeypatch.setattr(login.time, "sleep", sleep)
    login._pace(tmp_path)
    login._pace(tmp_path)
    login._pace(tmp_path)
    assert sleeps == [0.0, 0.5, 0.5]
