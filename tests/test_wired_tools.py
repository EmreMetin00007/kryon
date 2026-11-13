"""6 tetik-olusu tool baglantisi: XXE/SSRF/authz genisleme/yuzey kancalari."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-hunter"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-memory-server"))

from cco_hunter_core.loop import execute_web_loop  # noqa: E402
from conftest import load_server  # noqa: E402


def _fuzz_of(*items):
    def _f(target, **kw):
        return {"validator_queue": list(items)}
    return _f


IDS2 = {"owner": {"Authorization": "Bearer A"}, "attacker": {"Authorization": "Bearer B"}}


def test_xxe_auto_validates():
    seen = {}

    def fake_validate(item, headers="", cookie=""):
        seen["cls"] = item["vuln_class"]
        return {"verdict": "CONFIRMED"}

    out = execute_web_loop("http://t.local", live=True,
                           fuzz=_fuzz_of({"vuln_class": "xxe", "url": "http://t.local/x",
                                          "method": "POST"}),
                           validate=fake_validate)
    assert seen["cls"] == "xxe"
    assert out["confirmed"]


def test_ssrf_needs_oob_then_confirms():
    item = {"vuln_class": "ssrf", "url": "http://t.local/fetch?u=x", "param": "u"}
    out = execute_web_loop("http://t.local", live=True, fuzz=_fuzz_of(item))
    assert any("oob" in str(s.get("reason", "")) for s in out["skipped"] if isinstance(s, dict))
    out2 = execute_web_loop("http://t.local", live=True, fuzz=_fuzz_of(item),
                            oob_validate=lambda i: {"verdict": "CONFIRMED"})
    assert out2["confirmed"] and out2["confirmed"][0]["hook"] == "oob_oracle"


def test_auth_bypass_single_identity_and_bfla():
    calls = []

    def fake_authz(item, identities):
        calls.append(item["vuln_class"])
        return {"verdict": "CONFIRMED"}

    out = execute_web_loop(
        "http://t.local", live=True,
        fuzz=_fuzz_of({"vuln_class": "authentication_bypass", "url": "http://t.local/admin"},
                      {"vuln_class": "bfla", "url": "http://t.local/admin/users"}),
        identities={"admin": {"Authorization": "Bearer ADM"}},
        authz_validate=fake_authz)
    # auth_bypass 1 kimlikle kosar; bfla 2 ister -> atlanir
    assert calls == ["authentication_bypass"]
    out2 = execute_web_loop(
        "http://t.local", live=True,
        fuzz=_fuzz_of({"vuln_class": "bfla", "url": "http://t.local/admin/users"}),
        identities=IDS2, authz_validate=fake_authz)
    assert calls[-1] == "bfla" and out2["confirmed"]


def test_deferred_surface_hooks_do_not_execute_or_claim_coverage():
    fired = []
    out = execute_web_loop(
        "http://t.local", live=True, crawl=True,
        crawl_fn=lambda t, **kw: {"ok": True, "urls_sample": ["http://t.local/graphql", "http://t.local/a"]},
        fuzz=_fuzz_of(),
        surface_hooks={"smuggling": lambda u: fired.append(("smug", u)) or "probe-ok",
                       "graphql_suggestion": lambda u: fired.append(("gql", u)) or "gql-ok"})
    assert out["surface_probes"] == [] and fired == []
    assert {row["step"] for row in out["skipped"]
            if row.get("reason") == "active_adapter_deferred"} == {"smuggling", "graphql_suggestion"}
    assert not out["confirmed"]


def test_ssrf_validate_requires_oob_domain(monkeypatch):
    monkeypatch.delenv("CCO_OOB_DOMAIN", raising=False)
    hunter = load_server("hunter")
    out = hunter._loop_ssrf_validate({"url": "http://t.local/f", "param": "u"})
    assert out["verdict"] == "INCONCLUSIVE"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/admin/export":
            if self.headers.get("Authorization") == "Bearer admin":
                return self._send(200, b"SECRET-EXPORT")
            return self._send(401, b"denied")
        return self._send(404, b"nope")

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


def test_auth_bypass_wiring_unconfirmed_on_safe(lab_url):
    hunter = load_server("hunter")
    out = hunter._loop_authz_validate(
        {"vuln_class": "authentication_bypass", "url": f"{lab_url}/admin/export"},
        {"admin": {"Authorization": "Bearer admin"}})
    assert out["verdict"] in {"UNCONFIRMED", "INCONCLUSIVE"}
    assert out["verdict"] != "CONFIRMED"
