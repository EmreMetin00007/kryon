"""The web loop must recheck final request scope, headers, and redirects."""

import json
from pathlib import Path
import sys

import pytest

from conftest import load_server
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-validator"))
from policy_engine import PolicyEngine


@pytest.fixture
def policy(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://own.test/allowed"}],
                                 "allow_loopback": False, "allow_public_labs": False,
                                 "allow_osint": False}))
    program = tmp_path / "policy.json"
    program.write_text(json.dumps({"allow_loopback": False,
                                   "blocked_http_methods": ["PATCH"],
                                   "required_request_headers": {"X-Research": "researcher"}}))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(program))
    engine = PolicyEngine(cco_home=str(tmp_path / "home"), scope_file=str(scope),
                          program_policy_file=str(program))
    engine.grant_approval("hunter_run_web_loop", "own.test", ttl_seconds=600, reason="test")

    def gate(method, url, headers):
        result = engine.validate_wire_invocation("hunter_run_web_loop", {
            "target": url, "url": url, "method": method, "headers": headers})
        return result["allowed"], result["reason"]

    return engine, gate


def test_fuzz_wire_denies_scope_headers_and_method_before_sending(policy, monkeypatch):
    hunter = load_server("hunter")
    from cco_hunter_core.request_context import bind_policy_gate

    calls = []

    class Response:
        status_code = 200
        content = b"ok"
        text = "ok"
        headers = {}

    monkeypatch.setattr(hunter.requests, "request", lambda *a, **kw: calls.append((a, kw)) or Response())
    _, gate = policy
    with bind_policy_gate(gate):
        allowed = hunter._live_request("GET", "https://own.test/allowed/a",
                                       headers={"X-Research": "researcher", "Cookie": "session=synthetic"})
        outside = hunter._live_request("GET", "https://own.test/outside",
                                       headers={"X-Research": "researcher"})
        traversal = hunter._live_request("GET", "https://own.test/allowed/%2e%2e/outside",
                                         headers={"X-Research": "researcher"})
        missing = hunter._live_request("GET", "https://own.test/allowed/a", headers={})
        method = hunter._live_request("PATCH", "https://own.test/allowed/a",
                                      headers={"X-Research": "researcher"})
    assert allowed["ok"] and len(calls) == 1
    assert all(not item["ok"] and item.get("blocked") == "policy" for item in (outside, traversal, missing, method))


def test_validator_redirect_is_checked_before_second_wire_request(policy):
    from cco_validator_core.egress import egress_request, scoped_wire_gate

    calls = []

    class Response:
        status_code = 302
        content = b""
        text = ""
        headers = {"Location": "/outside"}

    def sender(method, url, **kwargs):
        calls.append((method, url))
        return Response()

    _, gate = policy
    with scoped_wire_gate(gate):
        result = egress_request("GET", "https://own.test/allowed/a",
                                headers={"X-Research": "researcher"}, transport=sender)
    assert result["blocked"] == "policy"
    assert calls == [("GET", "https://own.test/allowed/a")]
    assert result["requests_sent"] == 1


def test_gate_counts_only_authorized_request_attempts(policy):
    load_server("hunter")
    from cco_hunter_core.request_context import current_policy_gate, policy_scoped

    @policy_scoped("hunter_run_web_loop")
    def execute():
        gate = current_policy_gate()
        assert gate("GET", "https://own.test/allowed/a", {"X-Research": "researcher"})[0]
        assert not gate("GET", "https://own.test/outside", {"X-Research": "researcher"})[0]
        assert not gate("POST", "https://own.test/allowed/a", {"X-Research": "researcher"})[0]
        return gate.authorized_requests()

    assert execute() == 1


def test_revoked_grant_stops_remaining_requests(policy):
    load_server("hunter")
    from cco_hunter_core.request_context import current_policy_gate, policy_scoped
    engine, _ = policy

    @policy_scoped("hunter_run_web_loop")
    def execute():
        gate = current_policy_gate()
        headers = {"X-Research": "researcher"}
        assert gate("GET", "https://own.test/allowed/a", headers)[0]
        approval = engine.list_approvals()[0]
        engine.revoke_approval(approval["id"])
        assert not gate("GET", "https://own.test/allowed/b", headers)[0]
        return gate.stop_reason(), gate.authorized_requests()

    reason, count = execute()
    assert "policy gate" in reason and count == 1


@pytest.mark.parametrize("location", ["/login", "/log%69n", "/%256cogin"])
def test_encoded_login_redirect_stops_next_authenticated_request(policy, location):
    load_server("hunter")
    from cco_hunter_core.request_context import current_policy_gate, policy_scoped

    @policy_scoped("hunter_run_web_loop")
    def execute():
        gate = current_policy_gate()
        headers = {"X-Research": "researcher", "Cookie": "session=synthetic"}
        assert gate("GET", "https://own.test/allowed/a", headers)[0]
        gate.observe(headers, {"ok": True, "status": 302, "location": location})
        assert not gate("GET", "https://own.test/allowed/b", headers)[0]
        return gate.stop_reason(), gate.authorized_requests()

    reason, count = execute()
    assert "redirected to login" in reason and count == 1


@pytest.mark.parametrize("budget,expected", [("2", 2), ("0", 0), ("invalid", 0)])
def test_campaign_wire_budget_stops_before_next_transport(policy, monkeypatch, budget, expected):
    load_server("hunter")
    from cco_hunter_core.request_context import current_policy_gate, policy_scoped
    from cco_validator_core.egress import egress_request, scoped_wire_gate

    monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", budget)
    calls = []
    class Response:
        status_code, content, text, headers = 200, b"ok", "ok", {}

    def sender(method, url, **kwargs):
        calls.append(url)
        return Response()

    @policy_scoped("hunter_run_web_loop")
    def execute():
        gate = current_policy_gate()
        with scoped_wire_gate(gate):
            results = [egress_request("GET", "https://own.test/allowed/a",
                                      headers={"X-Research": "researcher"},
                                      transport=sender, observe_session=False) for _ in range(3)]
        return results, gate.authorized_requests(), gate.stop_reason()

    results, count, reason = execute()
    assert len(calls) == count == expected
    assert "budget exhausted" in reason
    assert results[expected]["blocked"] == "policy"


@pytest.mark.parametrize("status", [401, 429])
def test_validator_stops_run_after_session_expiry_or_rate_limit(policy, status):
    load_server("hunter")
    from cco_hunter_core.request_context import current_policy_gate, policy_scoped
    from cco_validator_core.egress import egress_request, scoped_wire_gate

    calls = []

    class Response:
        status_code = status
        content = b""
        text = ""
        headers = {}

    def sender(method, url, **kwargs):
        calls.append(url)
        return Response()

    @policy_scoped("hunter_run_web_loop")
    def execute():
        gate = current_policy_gate()
        with scoped_wire_gate(gate):
            headers = {"X-Research": "researcher", "Cookie": "session=synthetic"}
            first = egress_request("GET", "https://own.test/allowed/a", headers=headers,
                                   transport=sender, observe_session=False)
            second = egress_request("GET", "https://own.test/allowed/b", headers=headers,
                                    transport=sender, observe_session=False)
        return first, second

    first, second = execute()
    assert first["status"] == status
    assert second["blocked"] == "policy" and len(calls) == 1


def test_anonymous_401_control_does_not_stop_validator_run(policy):
    load_server("hunter")
    from cco_hunter_core.request_context import current_policy_gate, policy_scoped
    from cco_validator_core.egress import egress_request, scoped_wire_gate

    calls = []

    class Response:
        status_code = 401
        content = b""
        text = ""
        headers = {}

    def sender(method, url, **kwargs):
        calls.append(url)
        return Response()

    @policy_scoped("hunter_run_web_loop")
    def execute():
        with scoped_wire_gate(current_policy_gate()):
            headers = {"X-Research": "researcher"}
            egress_request("GET", "https://own.test/allowed/a", headers=headers,
                           transport=sender, observe_session=False)
            return egress_request("GET", "https://own.test/allowed/b", headers=headers,
                                  transport=sender, observe_session=False)

    result = execute()
    assert result["status"] == 401 and len(calls) == 2


def test_discovery_checks_each_redirect_before_sending_and_keeps_cookie_on_origin(policy, monkeypatch):
    hunter = load_server("hunter")
    kali = load_server("kali-tools")
    from cco_hunter_core.request_context import bind_policy_gate

    calls = []

    class Response:
        status_code = 302
        headers = {"Location": "https://elsewhere.test/leak"}
        content = b""
        text = ""
        cookies = []
        url = "https://own.test/allowed"

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr(kali.requests, "get", get)
    monkeypatch.setattr(hunter, "_load_peer", lambda *a: kali)
    _, gate = policy
    with bind_policy_gate(gate):
        result = json.loads(hunter._loop_discover(
            "https://own.test/allowed", cookie="session=synthetic",
            headers='{"X-Research":"researcher"}'))
    assert len(calls) == 1
    assert calls[0][1]["allow_redirects"] is False
    assert calls[0][1]["headers"]["Cookie"] == "session=synthetic"
    assert result.get("error")


def test_discovery_stops_after_unauthorized_session(policy, monkeypatch):
    hunter = load_server("hunter")
    kali = load_server("kali-tools")
    from cco_hunter_core.request_context import bind_policy_gate

    calls = []

    class Response:
        status_code = 401
        headers = {}
        content = b"unauthorized"
        text = "unauthorized"
        cookies = []
        url = "https://own.test/allowed"

    monkeypatch.setattr(kali.requests, "get", lambda url, **kw: calls.append(url) or Response())
    monkeypatch.setattr(hunter, "_load_peer", lambda *a: kali)
    _, gate = policy
    with bind_policy_gate(gate):
        result = json.loads(hunter._loop_discover(
            "https://own.test/allowed", cookie="session=synthetic",
            headers='{"X-Research":"researcher"}'))
    assert calls == ["https://own.test/allowed"]
    assert any("401" in error for error in result.get("errors", []))


def test_discovery_skips_denied_paths_and_probes_allowed_links(policy, monkeypatch):
    hunter = load_server("hunter")
    kali = load_server("kali-tools")
    from cco_hunter_core.request_context import bind_policy_gate

    calls = []

    class Response:
        status_code = 200
        headers = {"Content-Type": "text/html"}
        content = b'<a href="/outside">outside</a><a href="/allowed/good">good</a>'
        text = content.decode()
        cookies = []

        def __init__(self, url):
            self.url = url

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return Response(url)

    monkeypatch.setattr(kali.requests, "get", get)
    monkeypatch.setattr(hunter, "_load_peer", lambda *a: kali)
    _, gate = policy
    with bind_policy_gate(gate):
        result = json.loads(hunter._loop_discover(
            "https://own.test/allowed", headers='{"X-Research":"researcher"}'))
    assert result.get("ingested")
    assert any(url.endswith("/allowed/good") for url, _ in calls)
    assert all(url.startswith("https://own.test/allowed") for url, _ in calls)
    assert all(kwargs["allow_redirects"] is False for _, kwargs in calls)


def test_failed_discovery_stops_the_remaining_web_loop(monkeypatch):
    hunter = load_server("hunter")
    monkeypatch.setattr(hunter, "_loop_discover", lambda *a, **kw: {
        "error": "unauthorized", "stop_reason": "discovery stopped: HTTP 401"})
    monkeypatch.setattr(hunter, "_loop_fuzz", lambda *a, **kw: pytest.fail("fuzz after dead session"))
    result = json.loads(hunter.run_web_loop("https://own.test", live=True, crawl=False))
    assert result["ok"] is False
    assert any(step.get("step") == "remaining" for step in result["skipped"] if isinstance(step, dict))


def test_guarded_crawl_runs_but_ungated_zap_is_explicitly_skipped(monkeypatch):
    hunter = load_server("hunter")
    monkeypatch.setattr(hunter, "_loop_discover", lambda *a, **kw: {"ok": True})
    monkeypatch.setattr(hunter, "_loop_fuzz", lambda *a, **kw: {"probes": 0, "validator_queue": []})
    monkeypatch.setattr(hunter, "_loop_crawl", lambda *a, **kw: {"ok": True, "page_count": 1})
    monkeypatch.setattr(hunter, "_loop_zap", lambda *a, **kw: pytest.fail("ungated ZAP called"))
    out = json.loads(hunter.run_web_loop("https://own.test", live=True, crawl=True, zap=True))
    steps = {row.get("step") for row in out["skipped"] if isinstance(row, dict)}
    assert "zap" in steps and "crawl" not in steps and out["crawl"]["page_count"] == 1


def test_authz_controls_inherit_program_header_without_leaking_identity(policy, monkeypatch):
    hunter = load_server("hunter")
    url = "https://own.test/allowed/orders/owned-uuid"
    record = {"fingerprint": "owned", "url": url, "method": "GET", "params": [],
              "suggested_classes": ["bola"], "tested_classes": []}
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    monkeypatch.setattr(hunter, "_loop_discover", lambda *a, **kw: {"ok": True})
    calls = []

    class Response:
        def __init__(self, status, body):
            self.status_code = status
            self.text = body
            self.content = body.encode()
            self.headers = {}

    def request(method, request_url, **kwargs):
        headers = kwargs.get("headers") or {}
        calls.append((method, request_url, headers))
        if headers.get("Cookie") in {"session=alice", "session=bob"}:
            return Response(200, "alice-owned-marker")
        return Response(403, "denied")

    monkeypatch.setattr(hunter.requests, "request", request)
    identities = {
        "alice": {"headers": {"Cookie": "session=alice"},
                  "objects": [{"url": url, "marker": "alice-owned-marker"}]},
        "bob": {"headers": {"Cookie": "session=bob"}},
    }
    out = json.loads(hunter.run_web_loop("https://own.test/allowed", live=True, crawl=False,
                                         headers='{"X-Research":"researcher"}',
                                         identities=json.dumps(identities), sleep_s=0))
    assert out["confirmed"] and len(calls) == 3
    assert all(headers.get("X-Research") == "researcher" for _, _, headers in calls)
    assert "Cookie" not in calls[2][2] and "Authorization" not in calls[2][2]


def test_fake_transport_discovery_through_uuid_authz_and_signed_coverage(policy, monkeypatch):
    """Exercise real adapters together while replacing every HTTP transport."""
    import hashlib
    import requests
    from urllib.parse import urlsplit
    from cco_validator_core import artifact_is_current
    from python_candidate_runtime import authorization_controls_complete

    base = "https://own.test/allowed"
    alice_uuid = "5080c899-12bf-4523-89ce-d91a5ce3d1f4"
    bob_uuid = "c534cae2-f5c9-41bc-b77a-de99aa2df907"
    alice_url = f"{base}/api/orders/{alice_uuid}"
    bob_url = f"{base}/api/orders/{bob_uuid}"
    admin_url = f"{base}/admin/export"
    seen = []

    class Response:
        cookies = []

        def __init__(self, url, status, body, content_type="application/json"):
            self.url, self.status_code = url, status
            self.text = body
            self.content = body.encode()
            self.headers = {"Content-Type": content_type}

    def send(method, url, **kwargs):
        headers = dict(kwargs.get("headers") or {})
        seen.append((method, url, headers))
        assert method.upper() == "GET" and url.startswith(base)
        assert headers.get("X-Research") == "researcher"
        cookie = headers.get("Cookie", "")
        if urlsplit(url).path == "/allowed":
            html = (f'<a href="{alice_url}">alice</a><a href="{bob_url}">bob</a>'
                    f'<a href="{admin_url}">export</a>')
            return Response(url, 200, html, "text/html")
        if url == alice_url and cookie in {"session=alice", "session=bob"}:
            return Response(url, 200, '{"marker":"alice-owned-canary"}')
        if url == bob_url and cookie == "session=bob":
            return Response(url, 200, '{"marker":"bob-owned-canary"}')
        if url == admin_url and cookie in {"session=alice", "session=bob"}:
            return Response(url, 200, '{"marker":"admin-owned-canary"}')
        return Response(url, 403, '{"error":"denied"}')

    monkeypatch.setattr(requests, "request", send)
    monkeypatch.setattr(requests, "get", lambda url, **kwargs: send("GET", url, **kwargs))
    hunter = load_server("hunter")
    identities = {
        "alice": {"role": "admin", "headers": {"Cookie": "session=alice"},
                  "functions": [{"url": admin_url, "marker": "admin-owned-canary",
                                 "test_data_only": True, "denied_roles": ["member"]}],
                  "objects": [{"url": alice_url, "marker": "alice-owned-canary"},
                              {"url": admin_url, "marker": "admin-owned-canary"}]},
        "bob": {"role": "member", "headers": {"Cookie": "session=bob"},
                "objects": [{"url": bob_url, "marker": "bob-owned-canary"}]},
    }
    raw = hunter.run_web_loop(base, live=True, crawl=False, cookie="session=alice",
                              headers='{"X-Research":"researcher"}',
                              identities=json.dumps(identities), sleep_s=0)
    result = json.loads(raw)
    assert result["discover"].get("ingested")
    assert "session=alice" not in raw and "session=bob" not in raw
    assert alice_uuid not in raw and bob_uuid not in raw
    assert "alice-owned-canary" not in raw and "bob-owned-canary" not in raw
    assert "admin-owned-canary" not in raw
    alice_key = hashlib.sha256(alice_url.encode()).hexdigest()
    bob_key = hashlib.sha256(bob_url.encode()).hexdigest()
    admin_key = hashlib.sha256(admin_url.encode()).hexdigest()
    expected_targets = {alice_key: alice_url, bob_key: bob_url, admin_key: admin_url}
    rows = {row["url_sha256"]: row for row in result["validations"]}
    assert set(rows) == set(expected_targets)
    assert rows[alice_key]["verdict"] == "CONFIRMED"
    assert rows[bob_key]["verdict"] == "UNCONFIRMED"
    assert rows[admin_key]["verdict"] == "CONFIRMED"
    assert all(row["coverage_recorded"] for row in rows.values())
    for key, raw_url in expected_targets.items():
        row = rows[key]
        assert row["url"] != raw_url and "{value}" in row["url"]
        artifact = hunter.load_validation(row["validation_id"])
        assert artifact and artifact_is_current(artifact)
        assert hunter.validator_artifact_is_valid(artifact, expected_target=raw_url)
        assert artifact["target"] == raw_url
        if key == admin_key:
            assert {r["role"] for r in artifact["request_evidence"]} >= {"owner", "other", "anonymous"}
        else:
            assert authorization_controls_complete(artifact)
    coverage = json.loads(hunter.coverage_report_run(base, result["run_id"]))
    assert {row["endpoint"] for row in coverage["per_endpoint"]} >= {alice_url, bob_url, admin_url}
    assert seen
