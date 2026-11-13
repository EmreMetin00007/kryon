"""All scope entry points must agree without making HTTP requests."""
import json
import sys
from pathlib import Path

import pytest

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import live_run  # noqa: E402
import agent_browse  # noqa: E402
import mitm_scope  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402


@pytest.mark.parametrize("url,allowed", [
    ("https://owned.test:9443/allowed/a", True),
    ("https://owned.test:9443/outside", False),
    ("https://owned.test:9443/allowed/%2e%2e/outside", False),
    ("https://owned.test:9444/allowed/a", False),
    ("https://excluded.test/allowed/a", False),
    ("https://child.wild.test/path", True),
    ("https://wild.test.evil.test/path", False),
])
def test_live_and_browser_scope_match_wire_policy(tmp_path, monkeypatch, url, allowed):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({
        "in_scope": [{"asset": "https://owned.test:9443/allowed"},
                     {"asset": "https://excluded.test/allowed"}, {"asset": "*.wild.test"}],
        "excluded_assets": ["excluded.test"],
        "allow_loopback": False, "allow_osint": False, "allow_public_labs": False,
    }))
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"allow_loopback": False, "allow_osint": False,
                                  "allow_public_labs": False}))
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    engine = PolicyEngine(cco_home=str(tmp_path / "home"), scope_file=str(scope),
                          program_policy_file=str(policy))
    engine.grant_approval("hunter_run_web_loop", "*", ttl_seconds=600, reason="synthetic test")
    decision = engine.validate_wire_invocation("hunter_run_web_loop", {
        "target": url, "url": url, "method": "GET", "headers": {}})
    browser = load_server("browser")
    assert decision["allowed"] is allowed
    assert browser._host_in_scope(url, browser._scope_allowlist()) is allowed
    assert agent_browse.central_scope_permits(url) is allowed
    assert mitm_scope.url_in_scope(url) is allowed
    if allowed:
        assert live_run.gate_target(url, scope)
    else:
        with pytest.raises(SystemExit, match="KAPSAM DISI"):
            live_run.gate_target(url, scope)


def test_browser_scope_fails_closed_when_scope_is_unreadable(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(tmp_path / "missing.json"))
    browser = load_server("browser")
    assert browser._host_in_scope("https://owned.test/path", browser._scope_allowlist()) is False


def test_session_capture_does_not_return_out_of_scope_requests(tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test/allowed"}]}))
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    browser = load_server("browser")
    monkeypatch.setattr(browser, "_session_guard", lambda: "")
    monkeypatch.setattr(browser, "HAS_SURFACE", False)
    class FakeSession:
        def call(self, fn):
            return {"requests": [{"url": "https://owned.test/allowed/a", "method": "GET"},
                                 {"url": "https://owned.test/outside", "method": "GET",
                                  "post_data": "synthetic-private-value"}]}
    monkeypatch.setattr(browser, "_BROWSER_SESSION", FakeSession())
    output = browser.browser_session_requests()
    assert "synthetic-private-value" not in output
    data = json.loads(output)
    assert data["scope_filtered_out"] == 1
    assert len(data["collected"]["requests"]) == 1


@pytest.mark.parametrize("scope_asset,url,allowed", [
    ("https://owned.test/allowed", "https://owned.test:443/allowed/a", True),
    ("https://owned.test:443/allowed", "https://owned.test/allowed/a", True),
    ("https://owned.test/allowed", "https://owned.test:444/allowed/a", False),
    ("http://owned.test/allowed", "http://owned.test:80/allowed/a", True),
    ("http://owned.test/allowed", "http://owned.test:8080/allowed/a", False),
])
def test_scope_default_ports_are_equivalent_but_other_ports_are_not(tmp_path, monkeypatch, scope_asset, url, allowed):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": scope_asset}], "allow_loopback": False,
                                 "allow_public_labs": False, "allow_osint": False}))
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    engine = PolicyEngine(cco_home=str(tmp_path / "home"), scope_file=str(scope))
    engine.grant_approval("hunter_run_web_loop", "owned.test", ttl_seconds=600, reason="synthetic test")
    decision = engine.validate_wire_invocation("hunter_run_web_loop", {
        "target": url, "url": url, "method": "GET", "headers": {}})
    assert decision["allowed"] is allowed
    assert agent_browse.central_scope_permits(url) is allowed
