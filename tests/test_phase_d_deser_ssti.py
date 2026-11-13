"""Faz D: PHP/pickle deser oracle + SSTI Jinja/Twig ayırt etme."""
import base64
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-validator"))
from conftest import load_server  # noqa: E402

validator = load_server("validator")

PHP_RAW = b'O:4:"User":1:{s:4:"name";s:5:"wiener";}'
PHP_SAMPLE = base64.b64encode(PHP_RAW).decode()
PICKLE_RAW = b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x8c\x04test\x94."
PICKLE_SAMPLE = base64.b64encode(PICKLE_RAW).decode()


class _SerHandler(BaseHTTPRequestHandler):
    valid = b""

    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie") or ""
        if "session=" not in cookie:
            return self._send(401)
        value = cookie.split("session=", 1)[1].split(";")[0]
        try:
            raw = base64.b64decode(value + "=" * (-len(value) % 4))
        except Exception:
            return self._send(500)
        return self._send(200 if raw == self.valid else 500)

    def _send(self, code):
        body = b"ok-page-content" if code == 200 else b"err"
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def serve():
    servers = []

    def _start(valid: bytes):
        handler = type("H", (_SerHandler,), {"valid": valid})
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}/me"

    yield _start
    for srv in servers:
        srv.shutdown()


def test_php_deser_confirmed(serve):
    out = validator.validate_deserialization(serve(PHP_RAW), PHP_SAMPLE)
    assert "CONFIRMED" in out and '"format": "php"' in out


def test_pickle_deser_confirmed(serve):
    out = validator.validate_deserialization(serve(PICKLE_RAW), PICKLE_SAMPLE)
    assert "CONFIRMED" in out and '"format": "python_pickle"' in out


def test_dotnet_stays_inconclusive(serve):
    raw = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff" + b"A" * 20
    out = validator.validate_deserialization(
        serve(raw), base64.b64encode(raw).decode())
    assert "INCONCLUSIVE" in out


class _TemplateHandler(BaseHTTPRequestHandler):
    mode = "jinja"

    def log_message(self, *a):
        pass

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
        body = q
        import re
        m = re.search(r"\{\{(\d+)\*(\d+)\}\}", q)
        if m:
            body = str(int(m.group(1)) * int(m.group(2)))
        elif "{{7*'7'}}" in q:
            body = "7777777" if self.mode == "jinja" else "49"
        elif "{{" in q and "*}}" in q:
            body = "template error page"
        data = ("<html>" + body + "</html>").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def serve_tpl():
    servers = []

    def _start(mode: str):
        handler = type("T", (_TemplateHandler,), {"mode": mode})
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}/greet?q=hello"

    yield _start
    for srv in servers:
        srv.shutdown()


def test_ssti_discrimination_jinja(serve_tpl):
    out = validator.validate_ssti(serve_tpl("jinja"), param="q")
    assert "CONFIRMED" in out and "Jinja2/Nunjucks" in out


def test_ssti_discrimination_twig(serve_tpl):
    out = validator.validate_ssti(serve_tpl("twig"), param="q")
    assert "CONFIRMED" in out and "Twig" in out
