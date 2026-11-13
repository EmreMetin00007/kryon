"""Real Chromium integration for an isolated, read-only test session."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-validator"))
from conftest import load_server  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from cco_validator_core.egress import save_shared_session  # noqa: E402

browser = load_server("browser")


def _playwright_ready() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True, args=["--no-sandbox"])
            b.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _playwright_ready(), reason="playwright/chromium unavailable")


class _App(BaseHTTPRequestHandler):
    post_calls = 0

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if "sid=ok" not in (self.headers.get("Cookie") or ""):
            return self._send(401, "login gerekli")
        if self.path.startswith("/orders"):
            return self._send(200, "<html><title>Siparisler</title>siparis listesi</html>")
        if self.path.startswith("/api/orders"):
            return self._send(200, '{"orders": []}')
        return self._send(200, """<html><title>Panel</title>gizli panel
          <input id="filter" name="filter"><a href="/orders?user=1">Siparislerim</a>
          <script>
            fetch('/api/orders').catch(() => {});
            fetch('/api/orders', {method:'POST', body:'synthetic'}).catch(() => {});
          </script></html>""")

    def do_POST(self):
        type(self).post_calls += 1
        self._send(200, "unexpected")


@pytest.fixture()
def app(tmp_path, monkeypatch):
    _App.post_calls = 0
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    home = tmp_path / "home"
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": base}], "allow_loopback": True,
                                 "allow_osint": False, "allow_public_labs": False}))
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"allow_loopback": True}))
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    monkeypatch.setenv("CCO_PROXY", "")
    monkeypatch.setenv("CCO_SURFACE_AUTO_INGEST", "0")
    PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy)).grant_approval(
        "browser_*", "127.0.0.1", ttl_seconds=600, reason="loopback test")
    save_shared_session(base, cookie="sid=ok")
    yield base
    browser.browser_session_close()
    srv.shutdown()
    srv.server_close()


@pytest.fixture(autouse=True)
def _close_session():
    yield
    browser.browser_session_close()


def test_authenticated_session_and_readonly_crawl(app):
    url = app + "/dashboard"
    out = json.loads(browser.browser_session_open(url))
    assert out["url"] == url and out["session_state"] == "restored"
    snap = json.loads(browser.browser_session_snapshot(url=url))
    assert "filter" in {e["name"] for e in snap["elements"]}
    assert json.loads(browser.browser_session_fill("#filter", "owned", url=url))["filled"] == "#filter"
    assert "gizli panel" in json.loads(browser.browser_session_text(url=url))["text"]
    crawl = json.loads(browser.browser_session_crawl(max_pages=5, url=url))["crawl"]
    assert url in crawl["pages"] and app + "/orders?user=1" in crawl["pages"]
    assert _App.post_calls == 0


def test_session_collects_requests_without_sending_post(app):
    url = app + "/dashboard"
    json.loads(browser.browser_session_open(url))
    out = json.loads(browser.browser_session_requests(url=url))
    assert any(r["method"] == "GET" and r["url"] == url for r in out["collected"]["requests"])
    assert _App.post_calls == 0
    assert json.loads(browser.browser_session_requests(clear=True, url=url))["collected"]["total_captured"] >= 1
    assert json.loads(browser.browser_session_requests(url=url))["collected"]["total_captured"] == 0


def test_session_requires_open_first():
    assert browser.browser_session_click("#missing", url="http://127.0.0.1/").startswith("HATA")


def test_cdp_attach_keeps_user_browser_alive(app, tmp_path):
    import subprocess
    import time
    import urllib.request
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        exe = p.chromium.executable_path
    port = 19333
    proc = subprocess.Popen(
        [exe, f"--remote-debugging-port={port}", "--no-sandbox",
         f"--user-data-dir={tmp_path}/prof", "--headless=new", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 15
        while True:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2):
                    break
            except Exception:
                if time.time() > deadline:
                    pytest.skip("Chrome CDP port could not start")
                time.sleep(0.3)
        out = json.loads(browser.browser_session_open(app + "/dashboard", cdp_url=f"http://127.0.0.1:{port}"))
        assert out["mode"] == "cdp-isolated" and out["session_state"] == "restored"
        browser.browser_session_close()
        assert proc.poll() is None
    finally:
        proc.terminate()
        proc.wait(timeout=5)
