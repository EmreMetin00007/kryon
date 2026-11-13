"""Cookie taşıyıcı: keşif kaydı + canary + validate_sqli(carrier='cookie')."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-memory-server"))
from conftest import load_server  # noqa: E402

validator = load_server("validator")
kali = load_server("kali-tools")

from cco_surface_core.fuzz import build_canary_plan  # noqa: E402
from cco_surface_core.store import memory_db_path, next_work  # noqa: E402


class _App(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, cookie=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        cookie = self.headers.get("Cookie") or ""
        value = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("TrackingId="):
                value = part.split("=", 1)[1]
        if not value:
            return self._send(200, "<html>magaza urun listesi dolu sayfa icerigi</html>",
                              "TrackingId=abc123; Path=/")
        if "1=2" in value or "1'='2" in value:
            return self._send(200, "<html>sonuc yok</html>")
        return self._send(200, "<html>magaza urun listesi dolu sayfa icerigi</html>")


@pytest.fixture()
def app():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_validate_sqli_cookie_carrier_confirms(app):
    out = validator.validate_sqli(app + "/", param="TrackingId", carrier="cookie")
    assert "CONFIRMED" in out


def test_validate_sqli_cookie_carrier_safe_target(app):
    # Ayni sunucu: yanlis kosul sayfayi bosalttigi icin zranabilir; guvenli
    # varyant: TrackingId'i yok sayan sayfa -> hukum CONFIRMED olmamali
    out = validator.validate_sqli(app + "/diger", param="YokOyleCookie", carrier="cookie")
    assert '"verdict": "CONFIRMED"' not in out


def test_canary_plan_includes_cookie_param():
    record = {"url": "http://t.local/", "method": "GET",
              "params": [{"name": "TrackingId", "in": "cookie", "sample": "abc"}],
              "suggested_classes": ["sql_injection"]}
    probes = [p for p in build_canary_plan(record) if p.get("location") == "cookie"]
    assert probes
    assert probes[0]["cookies"] == {"TrackingId": probes[0]["payload"]}


def test_discover_records_set_cookie_params(app, tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    out = json.loads(kali.discover_web_surface(app + "/", mode="passive"))
    assert out.get("ingested", 0) >= 1
    queue = next_work(app, limit=10, db_path=memory_db_path())
    params = [p for rec in queue["queue"] for p in (rec.get("params") or [])]
    cookie_params = [p for p in params if p.get("in") == "cookie"]
    assert any(p["name"] == "TrackingId" for p in cookie_params), params
