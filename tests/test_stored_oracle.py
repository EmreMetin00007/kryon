"""Stored oracle: yaz->oku canary (ham / encode / saklamayan yuzeyler)."""
import html
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from conftest import load_server  # noqa: E402

validator = load_server("validator")

STORE: list[str] = []
MODE = {"kind": "raw"}


class _App(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(n).decode())
        val = (form.get("comment") or [""])[0]
        if MODE["kind"] != "drop":
            STORE.append(val)
        self._send(200, "ok")

    def do_GET(self):
        if MODE["kind"] == "encoded":
            items = "".join(f"<p>{html.escape(v)}</p>" for v in STORE)
        else:
            items = "".join(f"<p>{v}</p>" for v in STORE)
        self._send(200, f"<html><body>{items}</body></html>")


def _run(mode):
    MODE["kind"] = mode
    STORE.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        out = json.loads(validator.validate_stored_reflection(
            base + "/post", base + "/view", field="comment"))
        return out
    finally:
        srv.shutdown()


def test_stored_raw_confirms_primitive_not_execution():
    out = _run("raw")
    ev = out.get("evidence") or {}
    assert ev.get("primitive_confirmed") == "stored_unescaped_reflection"
    assert ev["reflection"]["verdict"] == "CONFIRMED"
    assert out["verdict"] == "INCONCLUSIVE"  # execution kaniti yok


def test_stored_encoded_is_unconfirmed():
    assert _run("encoded")["verdict"] == "UNCONFIRMED"


def test_stored_dropped_is_unconfirmed():
    assert _run("drop")["verdict"] == "UNCONFIRMED"
