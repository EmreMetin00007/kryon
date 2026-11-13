"""Header/path taşıyıcı + blind OOB genelleştirme + CSRF validator."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-memory-server"))
from conftest import load_server  # noqa: E402

validator = load_server("validator")
from cco_surface_core.fuzz import build_canary_plan  # noqa: E402

FULL = "<html>urun listesi dolu sayfa icerigi burada</html>"
EMPTY = "<html>sonuc yok</html>"


def _bool_page(value: str) -> str:
    return EMPTY if ("1=2" in value or "1'='2" in value) else FULL


class _HeaderApp(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/users/"):
            return self._send(_bool_page(unquote(self.path.split("/users/", 1)[1])))
        return self._send(_bool_page(self.headers.get("X-User-Id") or ""))


class _CsrfApp(BaseHTTPRequestHandler):
    enforce = False

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        return self._send(200, '<form method="POST"><input type="hidden" '
                               'name="csrf_token" value="REAL"></form>')

    def do_POST(self):
        from urllib.parse import parse_qs
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        fields = {k: v[0] for k, v in parse_qs(body).items()}
        if self.enforce and fields.get("csrf_token") != "REAL":
            return self._send(403, "CSRF hatasi")
        return self._send(200, "Kaydedildi")


@pytest.fixture()
def serve():
    servers = []

    def _start(handler):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    yield _start
    for srv in servers:
        srv.shutdown()


def test_sqli_header_carrier(serve):
    out = validator.validate_sqli(serve(_HeaderApp) + "/", param="X-User-Id",
                                  carrier="header")
    assert '"verdict": "CONFIRMED"' in out


def test_sqli_path_carrier(serve):
    out = validator.validate_sqli(serve(_HeaderApp) + "/users/{id}", param="id",
                                  carrier="path")
    assert '"verdict": "CONFIRMED"' in out


def test_canary_header_and_path_probes():
    record = {"url": "http://t.local/users/{id}", "method": "GET",
              "params": [{"name": "id", "in": "path", "sample": "1"},
                         {"name": "X-Api-Key", "in": "header", "sample": "k"}],
              "suggested_classes": ["sql_injection"]}
    probes = build_canary_plan(record)
    locs = {p["location"] for p in probes}
    assert {"path", "header"} <= locs
    path_probe = next(p for p in probes if p["location"] == "path")
    assert "{id}" not in path_probe["url"]
    header_probe = next(p for p in probes if p["location"] == "header")
    assert header_probe["headers"]["X-Api-Key"] == header_probe["payload"]


def test_blind_oob_is_disabled_without_trusted_collector(monkeypatch):
    monkeypatch.setattr(validator, "_send_payload", lambda *a, **kw: pytest.fail("must not send"))
    out = json.loads(validator.validate_blind_oob(
        "http://t.local/?u=1", param="u", vuln_type="sql_injection",
        oob_domain="ornek.oast.test", carrier="query"))
    assert out["verdict"] == "INCONCLUSIVE"
    assert "unavailable" in out["evidence"]["error"] and not out["guard"]["transport_ok"]


def test_csrf_vulnerable_and_safe(serve):
    vuln = type("V", (_CsrfApp,), {"enforce": False})
    safe = type("S", (_CsrfApp,), {"enforce": True})
    out = validator.validate_csrf(serve(vuln) + "/settings",
                                  data_template="email=a@b.c&csrf_token=x",
                                  success_marker="Kaydedildi")
    assert '"verdict": "CONFIRMED"' in out
    out2 = validator.validate_csrf(serve(safe) + "/settings",
                                   data_template="email=a@b.c&csrf_token=x",
                                   success_marker="Kaydedildi")
    assert '"verdict": "CONFIRMED"' not in out2
