"""İskelet kapanışları: stored oracle + XML/multipart canary + exploit merdiveni."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-memory-server"))
from conftest import load_server  # noqa: E402

validator = load_server("validator")
hunter = load_server("hunter")
from cco_surface_core.fuzz import build_canary_plan  # noqa: E402


class _Guestbook(BaseHTTPRequestHandler):
    comments: list = []

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        joined = " | ".join(type(self).comments)
        return self._send(200, f"<html>yorumlar: {joined}</html>")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        fields = {k: v[0] for k, v in parse_qs(body).items()}
        if fields.get("comment"):
            type(self).comments.append(fields["comment"])
        return self._send(200, "ok")


@pytest.fixture()
def guestbook():
    _Guestbook.comments = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Guestbook)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_second_order_confirms_stored_flow(guestbook):
    out = json.loads(validator.validate_second_order(
        guestbook + "/yaz", guestbook + "/oku", data_template="comment={{PAYLOAD}}"))
    assert out["verdict"] == "CONFIRMED"
    assert out["evidence"]["hit_urls"]


def test_second_order_unconfirmed_when_not_rendered(guestbook):
    out = json.loads(validator.validate_second_order(
        guestbook + "/yaz", guestbook + "/baska-sayfa",
        data_template="comment={{PAYLOAD}}"))
    # /baska-sayfa da ayni handler'a duser (yorumlar) -> render eder; gercek
    # olumsuz kontrol: yazma sablonsuz endpoint'e degil, okuma bos sayfaya
    out2 = json.loads(validator.validate_second_order(
        guestbook + "/yaz", guestbook + "/oku", data_template="diger={{PAYLOAD}}"))
    assert out2["verdict"] == "UNCONFIRMED"


def test_xml_and_multipart_canary_probes():
    record = {"url": "http://t.local/api/import", "method": "POST",
              "params": [{"name": "file", "in": "body", "sample": ""}],
              "suggested_classes": ["xxe", "file_upload"]}
    probes = build_canary_plan(record)
    xxe = [p for p in probes if p["vuln_class"] == "xxe"]
    up = [p for p in probes if p["vuln_class"] == "file_upload"]
    assert xxe and xxe[0]["headers"]["Content-Type"] == "application/xml"
    assert up and up[0]["files"]["file"][0] == "cco_probe.txt"


def test_exploit_ladder_replays_confirmed(guestbook):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "tc", os.path.join(os.path.dirname(__file__), "test_cookie_carrier.py"))
    tc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tc)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), tc._App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        v = load_server("validator")
        h = load_server("hunter")
        out = json.loads(v.validate_sqli(base + "/", param="TrackingId",
                                         carrier="cookie"))
        assert out["verdict"] == "CONFIRMED"
        res = json.loads(h.exploit_confirmed(out["validation_id"], live=True))
        assert res["ok"] is True, res.get("error")
        assert res["replay"]["status"] == 200
        assert res["deepen"]["allowed"] is True
    finally:
        srv.shutdown()
