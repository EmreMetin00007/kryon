"""Faz 5: authz otonomisi + file-upload validator + JWT kid/jku."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-hunter"))

from cco_hunter_core.loop import execute_web_loop  # noqa: E402
from conftest import load_server  # noqa: E402


# ---------- loop authz ----------

def _fuzz_with_bola(target, **kw):
    return {"validator_queue": [
        {"vuln_class": "bola", "url": "http://t.local/orders/7", "method": "GET"}]}


def test_loop_authz_confirms_with_identities():
    out = execute_web_loop(
        "http://t.local", live=True, fuzz=_fuzz_with_bola,
        identities={"owner": {"Authorization": "Bearer A"},
                    "attacker": {"Authorization": "Bearer B"}},
        authz_validate=lambda item, ids: {"verdict": "CONFIRMED", "validation_id": "v1"})
    assert out["confirmed"] and out["confirmed"][0]["hook"] == "authz_oracle"


def test_loop_authz_skips_without_identities():
    out = execute_web_loop("http://t.local", live=True, fuzz=_fuzz_with_bola,
                           authz_validate=lambda i, ids: {"verdict": "CONFIRMED"})
    assert not out["confirmed"]
    assert any(isinstance(s, dict) and "identities" in s["reason"] for s in out["skipped"])


# ---------- yerel loopback sunucu ----------

FILES: dict[str, bytes] = {}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # sessiz
        pass

    def do_GET(self):
        if self.path.startswith("/files/"):
            data = FILES.get(self.path.split("/files/", 1)[1])
            if data is None:
                return self._send(404, b"nope")
            return self._send(200, data)
        if self.path == "/orders/7":
            body = json.dumps({"order": {"id": 7, "total": 100, "owner": "a@x.com"},
                               "csrf_token": self.headers.get("Authorization", "")}).encode()
            return self._send(200, body)
        return self._send(404, b"nope")

    def do_POST(self):
        if self.path == "/upload":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", "ignore")
            import re
            m = re.search(r'filename="([^"]+)"', raw)
            if not m:
                return self._send(400, b"bad")
            name = m.group(1)
            FILES[name] = raw.encode()
            return self._send(201, json.dumps({"url": f"/files/{name}"}).encode())
        return self._send(404, b"nope")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


import pytest  # noqa: E402


@pytest.fixture(scope="module")
def lab_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_loop_authz_validate_confirms_bola(lab_url):
    hunter = load_server("hunter")
    url = f"{lab_url}/orders/7"
    out = hunter._loop_authz_validate(
        {"vuln_class": "bola", "url": url, "owned_object": True,
         "owner_identity": "owner", "attacker_identity": "attacker",
         "owner_marker": "a@x.com"},
        {"owner": {"headers": {"Authorization": "Bearer own-tok"},
                           "objects": [{"url": url, "marker": "a@x.com"}]},
                 "attacker": {"headers": {"Authorization": "Bearer atk-tok"}}})
    assert out["verdict"] == "CONFIRMED"
    assert out["oracle"] == "content_match"


def test_validate_file_upload_confirmed(lab_url):
    validator = load_server("validator")
    out = json.loads(validator.validate_file_upload(f"{lab_url}/upload"))
    assert out["verdict"] == "CONFIRMED"
    assert out["evidence"]["public_fetch"] is True


# ---------- JWT kid / jku ----------

def _make_token(mod):
    import base64

    def enc(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{enc({'alg': 'RS256', 'typ': 'JWT', 'kid': 'k1'})}.{enc({'sub': '7', 'role': 'user'})}.fakesig"


def test_jwt_attack_kid_variants():
    mod = load_server("web-advanced")
    out = mod.jwt_attack_kid(_make_token(mod), '{"role":"admin"}')
    assert "kid injection" in out
    assert out.count("eyJ") >= 6


def test_jwt_attack_jku_package_verifies():
    mod = load_server("web-advanced")
    out = mod.jwt_attack_jku(_make_token(mod), "https://attacker.example/jwks.json")
    assert "JWKS" in out
    jwks = json.loads(out.split("[JWKS", 1)[1].split("]\n  ", 1)[1].split("\n", 1)[0])
    tok = out.split("[jku token]\n  ", 1)[1].split("\n", 1)[0]
    # JWKS public key ile RS256 imzasini dogrula
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.hazmat.primitives import hashes
    import base64

    def dec(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    jwk = jwks["keys"][0]
    numbers = RSAPublicNumbers(int.from_bytes(dec(jwk["e"]), "big"),
                               int.from_bytes(dec(jwk["n"]), "big"))
    h, p, s = tok.split(".")
    numbers.public_key().verify(dec(s), f"{h}.{p}".encode(), PKCS1v15(), hashes.SHA256())
