"""Proxy katmanı (mitm_scope) + katana sarmalı testleri."""
import importlib.util
import json
import os
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))
from conftest import load_server  # noqa: E402


def _load_scope_addon():
    path = os.path.join(REPO_ROOT, "scripts", "mitm_scope.py")
    spec = importlib.util.spec_from_file_location("mitm_scope_test", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_scope_host_matching_and_redaction(tmp_path, monkeypatch):
    mod = _load_scope_addon()
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"targets": ["*.example.com", "api.test.local"]}))
    monkeypatch.setattr(mod, "SCOPE_FILE", scope)
    monkeypatch.setattr(mod, "_SCOPE_MTIME", 0)
    assert mod.host_in_scope("www.example.com") is True
    assert mod.host_in_scope("example.com") is True
    assert mod.host_in_scope("api.test.local") is True
    assert mod.host_in_scope("evil-example.com") is False
    assert mod.host_in_scope("other.org") is False
    cleaned = mod._clean({"Authorization": "Bearer x", "Accept": "text/html"})
    assert cleaned["Authorization"] == "<redacted>"
    assert cleaned["Accept"] == "text/html"
    q = mod._clean_query("/p?user=1&access_token=abc")
    assert "abc" not in q and "user=1" not in q and "user=" in q


class _Site(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = {
            "/": '<html><a href="/a">A</a><a href="/b?user=1">B</a></html>',
            "/a": "<html>sayfa a</html>",
            "/b?user=1": "<html>sayfa b</html>",
        }.get(self.path, "<html>404</html>")
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.mark.skipif(not shutil.which("katana"), reason="katana yok")
def test_katana_crawl_finds_endpoints():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        kali = load_server("kali-tools")
        out = kali.katana_crawl(f"http://127.0.0.1:{srv.server_address[1]}/",
                                depth=1, timeout=120)
        assert "/a" in out and "/b?user=1" in out
    finally:
        srv.shutdown()
