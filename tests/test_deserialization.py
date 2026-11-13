"""Faz 1: validate_deserialization — uc falsal oracle + tetikleyiciler."""
import base64
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-validator"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-memory-server"))

from cco_validator_core.deser import detect_format, java_class_name, looks_serialized  # noqa: E402
from cco_surface_core.normalize import suggested_classes  # noqa: E402
from conftest import load_server  # noqa: E402

VALID_RAW = b"\xac\xed\x00\x05sr\x00\x17com.example.SessionUser\x00\x00\x00\x00\x00\x00\x00\x01"
SAMPLE = base64.b64encode(VALID_RAW).decode()


def test_detect_and_class_name():
    assert detect_format(VALID_RAW) == "java"
    assert java_class_name(VALID_RAW) == "com.example.SessionUser"
    assert looks_serialized(SAMPLE)
    assert not looks_serialized("sade-metin-deger")


def test_suggested_classes_flags_serialized_cookie():
    record = {"url": "http://t.local/my-account", "params": [
        {"name": "session", "in": "cookie", "sample": SAMPLE}]}
    assert suggested_classes(record)[0] == "deserialization"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie") or ""
        if "session=" not in cookie:
            return self._send(401, b"login required")
        value = cookie.split("session=", 1)[1].split(";")[0]
        try:
            raw = base64.b64decode(value + "=" * (-len(value) % 4))
        except Exception:
            return self._send(500, b"Internal Server Error")
        if raw == VALID_RAW:
            return self._send(200, b"hello wiener, your orders page")
        return self._send(500, b"Internal Server Error")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


import pytest  # noqa: E402


@pytest.fixture(scope="module")
def lab_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_validator_confirms_sink(lab_url):
    validator = load_server("validator")
    out = json.loads(validator.validate_deserialization(
        f"{lab_url}/account", SAMPLE, carrier="cookie", name="session"))
    assert out["verdict"] == "CONFIRMED"
    assert out["evidence"]["class_name"] == "com.example.SessionUser"
    assert out["evidence"]["corrupted_status"] == 500


def test_validator_unconfirmed_for_plain_value(lab_url):
    validator = load_server("validator")
    out = json.loads(validator.validate_deserialization(
        f"{lab_url}/account", "duz-metin", carrier="cookie", name="session"))
    assert out["verdict"] == "UNCONFIRMED"


def test_loop_requires_sample_then_validates(lab_url):
    hunter = load_server("hunter")
    missing = hunter._loop_validate({"vuln_class": "deserialization", "url": f"{lab_url}/account"})
    assert missing["verdict"] == "INCONCLUSIVE"
    got = hunter._loop_validate({"vuln_class": "deserialization",
                                 "url": f"{lab_url}/account",
                                 "sample_value": SAMPLE, "param": "session"})
    assert got["verdict"] == "CONFIRMED"
