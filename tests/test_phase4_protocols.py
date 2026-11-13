"""Faz 4: WS mesaj authz matrisi (yerel echo server) + gRPC probe degrade."""
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))
from conftest import load_server  # noqa: E402

web = load_server("web-advanced")


@pytest.fixture()
def ws_server():
    from websockets.sync.server import serve

    def handler(ws):
        token = (ws.request.headers.get("Authorization") or "") if ws.request else ""
        for msg in ws:
            ws.send("secret-data" if "Bearer good" in token else "public")

    server = serve(handler, "127.0.0.1", 0)
    port = server.socket.getsockname()[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"ws://127.0.0.1:{port}/"
    server.shutdown()


def test_ws_authz_matrix_flags_open_endpoint(ws_server):
    out = web.websocket_authz_matrix(
        ws_server, message="get", timeout=5,
        tokens='{"anon": "", "userA": "good", "userB": "good"}')
    assert "anon" in out and "userA" in out
    # anon 'public', good kimlikler 'secret-data' → hashler ayrışmalı, alarm YOK
    assert "WS mesaj authz YOK" not in out


def test_ws_authz_matrix_alarms_when_all_same(ws_server, monkeypatch):
    # token'sız davranan ikinci senaryo: hepsi aynı tokenı kullanırsa aynı yanıt
    out = web.websocket_authz_matrix(
        ws_server, message="get", timeout=5,
        tokens='{"anon": "good", "userA": "good"}')
    assert "aynı yanıt" in out


def test_grpc_probe_closed_port():
    out = web.grpc_reflection_probe("127.0.0.1", port=59999, timeout=3)
    assert "kurulamadı" in out
