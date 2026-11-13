"""Oracle lehçesi zaman oracle'ı: DBMS_PIPE koşullu bekleme (cookie taşıyıcı)."""
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from conftest import load_server  # noqa: E402

validator = load_server("validator")


class _OracleApp(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie") or ""
        m = re.search(r"DBMS_PIPE\.receive_message\(\('a'\),(\d+)\)", cookie)
        if m and "(1=1)" in cookie:
            time.sleep(int(m.group(1)))
        body = b"<html>magaza sayfasi normal icerik</html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def app():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _OracleApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_oracle_dialect_timing_confirms(app):
    # Simülasyon yalnız DBMS_PIPE'a uyuyor; MySQL SLEEP dalı sessiz kalır,
    # hüküm Oracle dalından gelmeli.
    import json
    out = json.loads(validator.validate_sqli(
        app + "/", param="TrackingId", carrier="cookie",
        headers_json='{"Cookie": "TrackingId=abc123"}'))
    assert out["verdict"] == "CONFIRMED", out
    assert out["evidence"].get("dialect") == "oracle_dbms_pipe"
