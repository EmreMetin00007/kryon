"""Faz B: jwt_kid_jku_verify — kid (dosya/SQLi) ve jku yerel kabul testleri."""
import base64
import hashlib
import hmac
import json
import re
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))
from conftest import load_server  # noqa: E402

web = load_server("web-advanced")
REAL = b"real-secret-key"


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _hs_ok(tok: str, key: bytes) -> bool:
    try:
        h, p, s = tok.split(".")
        sig = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
        return hmac.compare_digest(sig, _b64d(s))
    except Exception:
        return False


def _kid_key(kid: str) -> bytes:
    if kid.endswith("/dev/null"):
        return b""
    if "UNION SELECT 'secret'" in kid:
        return b"secret"
    if "UNION SELECT 'key'" in kid:
        return b"key"
    return REAL


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a):  # sessiz
        pass

    def _tok(self) -> str:
        return (self.headers.get("Authorization") or "").replace("Bearer ", "")

    def _send(self, code: int):
        body = b'{"ok":true}' if code == 200 else b'{"error":"no"}'
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class KidVuln(_Base):
    def do_GET(self):
        tok = self._tok()
        try:
            header = json.loads(_b64d(tok.split(".")[0]))
        except Exception:
            return self._send(401)
        self._send(200 if _hs_ok(tok, _kid_key(str(header.get("kid") or ""))) else 401)


class Strict(_Base):
    def do_GET(self):
        self._send(200 if _hs_ok(self._tok(), REAL) else 401)


class JkuVuln(_Base):
    def do_GET(self):
        tok = self._tok()
        try:
            h, p, s = tok.split(".")
            header = json.loads(_b64d(h))
            jku = header.get("jku") or header.get("x5u")
            if not jku:
                return self._send(200 if _hs_ok(tok, REAL) else 401)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(jku, timeout=5) as resp:  # yerel test sunucusu
                jwks = json.loads(resp.read())
            from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

            def _uint(v: str) -> int:
                return int.from_bytes(_b64d(v), "big")

            jwk = next(k for k in jwks["keys"] if k["kid"] == header.get("kid"))
            pub = RSAPublicNumbers(_uint(jwk["e"]), _uint(jwk["n"])).public_key()
            pub.verify(_b64d(s), f"{h}.{p}".encode(), PKCS1v15(), hashes.SHA256())
            return self._send(200)
        except Exception:
            return self._send(401)


@pytest.fixture()
def serve():
    servers = []

    def _start(handler, routes=None):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    yield _start
    for srv in servers:
        srv.shutdown()


def _orig_token() -> str:
    return web._hs_sign({"alg": "HS256", "typ": "JWT", "kid": "1"},
                        {"sub": "user1", "role": "user"}, REAL)


def test_kid_verify_confirms_vulnerable(serve):
    url = serve(KidVuln) + "/api/me"
    out = web.jwt_kid_jku_verify(_orig_token(), url)
    assert "CONFIRMED kid/jku" in out
    assert "kid=/dev/null" in out


def test_kid_verify_strict_server_clean(serve):
    url = serve(Strict) + "/api/me"
    out = web.jwt_kid_jku_verify(_orig_token(), url)
    assert "CONFIRMED" not in out
    assert "kabul edilmedi" in out


def test_jku_verify_confirms_with_hosted_jwks(serve):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    pack = web.jwt_attack_jku(_orig_token(), "PLACEHOLDER", key_pem=pem)
    jwks_json = re.search(r"\[JWKS[^\]]*\]\s*(\{.*\})", pack).group(1)

    class Jwks(_Base):
        def do_GET(self):
            body = jwks_json.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    jku_url = serve(Jwks) + "/jwks.json"
    url = serve(JkuVuln) + "/api/me"
    out = web.jwt_kid_jku_verify(_orig_token(), url, jku_url=jku_url,
                                 jku_key_pem=pem)
    assert "CONFIRMED kid/jku" in out
    assert "jku spoof" in out
