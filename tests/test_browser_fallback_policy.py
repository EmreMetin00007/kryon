"""Fallback browser requests must obey the same wire policy as the operator."""
import json
import sys
from pathlib import Path

import pytest
import requests

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-validator"))
from policy_engine import PolicyEngine  # noqa: E402
from cco_validator_core.egress import save_shared_session  # noqa: E402


class Response:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = headers or {}


@pytest.fixture
def browser(tmp_path, monkeypatch):
    home = tmp_path / "home"
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test/allowed"}],
                                 "allow_loopback": False, "allow_public_labs": False,
                                 "allow_osint": False}))
    program = tmp_path / "policy.json"
    program.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"}}))
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(program))
    monkeypatch.setenv("HACKERONE_HANDLE", "researcher")
    monkeypatch.setenv("CCO_RESEARCH_HEADER", "X-Research")
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(program))
    engine.grant_approval("browser_browser_extract_links", "owned.test", ttl_seconds=600, reason="test")
    save_shared_session("https://owned.test", cookie="session=synthetic-value", headers={"X-Session": "synthetic"})
    mod = load_server("browser")
    monkeypatch.setattr(mod, "HAS_PLAYWRIGHT", False)
    monkeypatch.setattr(mod, "HAS_SURFACE", False)
    monkeypatch.setattr(mod, "CCO_PROXY", "http://proxy.test:8080")
    monkeypatch.setattr(mod, "_proxy_available", lambda: True)
    return mod


def test_missing_playwright_preserves_session_headers_and_proxy(browser, monkeypatch):
    calls = []
    def send(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return Response(text='<a href="/allowed/child">child</a>')
    monkeypatch.setattr(requests, "request", send)
    raw = browser.browser_extract_links("https://owned.test/allowed/start")
    data = json.loads(raw)
    assert data["fallback_reason"] == "playwright_unavailable"
    assert data["internal_links"] == ["https://owned.test/allowed/child"]
    assert data["status"] == 200 and data["requests_sent"] == 1
    assert calls[0][2]["headers"]["X-Research"] == "researcher"
    assert calls[0][2]["headers"]["Cookie"] == "session=synthetic-value"
    assert calls[0][2]["headers"]["X-Session"] == "synthetic"
    assert calls[0][2]["proxies"]["https"] == "http://proxy.test:8080"
    assert calls[0][2]["allow_redirects"] is False
    assert "synthetic-value" not in raw
    assert "JavaScript is not executed" in data["limitations"]


def test_missing_header_or_outside_path_never_reaches_sender(browser, monkeypatch):
    calls = []
    monkeypatch.setattr(requests, "request", lambda *a, **kw: calls.append(a) or Response())
    monkeypatch.delenv("HACKERONE_HANDLE")
    missing = json.loads(browser.browser_extract_links("https://owned.test/allowed/a"))
    monkeypatch.setenv("HACKERONE_HANDLE", "researcher")
    outside = json.loads(browser.browser_extract_links("https://owned.test/outside"))
    assert missing["blocked"] == outside["blocked"] == "policy"
    assert calls == []


@pytest.mark.parametrize("location", ["/outside", "https://elsewhere.test/leak", "/allowed/login"])
def test_redirect_is_stopped_before_outside_or_login_request(browser, monkeypatch, location):
    calls = []
    def send(method, url, **kwargs):
        calls.append(url)
        return Response(status=302, headers={"Location": location})
    monkeypatch.setattr(requests, "request", send)
    data = json.loads(browser.browser_extract_links("https://owned.test/allowed/start"))
    assert data["error"] == "request_blocked"
    assert data["requests_sent"] == 1
    assert calls == ["https://owned.test/allowed/start"]


@pytest.mark.parametrize("status", [401, 429])
def test_error_status_never_becomes_a_surface(browser, monkeypatch, status):
    monkeypatch.setattr(requests, "request", lambda *a, **kw: Response(status=status, text="private"))
    raw = browser.browser_extract_links("https://owned.test/allowed/a")
    data = json.loads(raw)
    assert data["error"] == "http_status" and data["status"] == status
    assert "private" not in raw


def test_playwright_failure_uses_the_same_fallback(browser, monkeypatch):
    monkeypatch.setattr(browser, "HAS_PLAYWRIGHT", True)
    monkeypatch.setattr(browser, "_playwright_sync", lambda *a: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr(requests, "request", lambda *a, **kw: Response(text="ok"))
    data = json.loads(browser.browser_extract_links("https://owned.test/allowed/a"))
    assert data["fallback_reason"] == "playwright_error" and data["status"] == 200
