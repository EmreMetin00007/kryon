"""Faz E: gRPC reflection gerçek mod + WS cookie/subprotocol kimlik aktarımı."""
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))
from conftest import load_server  # noqa: E402

web = load_server("web-advanced")


@pytest.fixture()
def grpc_server():
    grpc = pytest.importorskip("grpc")
    from concurrent import futures

    from grpc_reflection.v1alpha import reflection
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    reflection.enable_server_reflection(
        ["grpc.reflection.v1alpha.ServerReflection"], server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield port
    server.stop(grace=0)


def test_grpc_reflection_probe_lists_services(grpc_server):
    out = web.grpc_reflection_probe("127.0.0.1", port=grpc_server, timeout=5)
    assert "REFLECTION AÇIK" in out
    assert "grpc.reflection.v1alpha.ServerReflection" in out


@pytest.fixture()
def ws_server():
    from websockets.sync.server import serve

    def handler(ws):
        req = ws.request
        cookie = (req.headers.get("Cookie") or "") if req else ""
        proto = (req.headers.get("Sec-WebSocket-Protocol") or "") if req else ""
        for _msg in ws:
            if "good" in cookie or "good" in proto:
                ws.send("secret-data")
            else:
                ws.send("public")

    server = serve(handler, "127.0.0.1", 0)
    port = server.socket.getsockname()[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"ws://127.0.0.1:{port}/"
    server.shutdown()


def test_ws_authz_cookie_mode(ws_server):
    out = web.websocket_authz_matrix(
        ws_server, message="get", timeout=5, auth_via="cookie",
        tokens='{"anon": "", "userA": "good"}')
    assert "anon" in out and "userA" in out
    assert "WS mesaj authz YOK" not in out


def test_ws_authz_subprotocol_mode(ws_server):
    out = web.websocket_authz_matrix(
        ws_server, message="get", timeout=5, auth_via="subprotocol",
        tokens='{"anon": "", "userA": "good"}')
    assert "userA" in out
