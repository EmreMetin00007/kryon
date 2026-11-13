"""Owned loopback lab: discovery inventory -> authz validator -> coverage."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from conftest import load_server

ALICE_ID = "5080c899-12bf-4523-89ce-d91a5ce3d1f4"
BOB_ID = "c534cae2-f5c9-41bc-b77a-de99aa2df907"


class _OwnedLab(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        if self.path == "/admin/export" and cookie in {"session=alice", "session=bob"}:
            return self._send(200, {"report": "admin-owned-canary"})
        if self.path == f"/api/orders/{ALICE_ID}" and cookie in {"session=alice", "session=bob"}:
            return self._send(200, {"id": ALICE_ID, "marker": "alice-owned-canary"})
        if self.path == f"/api/orders/{BOB_ID}" and cookie == "session=bob":
            return self._send(200, {"id": BOB_ID, "marker": "bob-owned-canary"})
        return self._send(403, {"error": "forbidden"})

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def test_owned_cookie_uuid_authz_reaches_signed_validator_and_coverage(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_GRAPH_BACKEND", "networkx")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OwnedLab)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        alice_url, bob_url = f"{base}/api/orders/{ALICE_ID}", f"{base}/api/orders/{BOB_ID}"
        admin_url = f"{base}/admin/export"
        scope = tmp_path / "scope.json"
        policy = tmp_path / "policy.json"
        scope.write_text(json.dumps({"in_scope": [{"asset": base}], "allow_loopback": True}))
        policy.write_text(json.dumps({"allow_loopback": True}))
        monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
        monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
        hunter = load_server("hunter")
        from cco_surface_core.store import ingest_records

        ingest_records([{"url": alice_url, "method": "GET"}, {"url": bob_url, "method": "GET"},
                        {"url": admin_url, "method": "GET"}],
                       target=base, db_path=hunter.MEM_DB)
        monkeypatch.setattr(hunter, "_loop_discover", lambda *a, **kw: {"ok": True})
        monkeypatch.setattr(hunter, "_loop_smuggling", lambda *a: "not part of this lab test")
        identities = {
            "alice": {"role": "admin", "headers": {"Cookie": "session=alice"},
                      "functions": [{"url": admin_url, "marker": "admin-owned-canary",
                                     "test_data_only": True, "denied_roles": ["member"]}],
                      "objects": [{"url": alice_url, "marker": "alice-owned-canary"},
                                  {"url": admin_url, "marker": "admin-owned-canary"}]},
            "bob": {"role": "member", "headers": {"Cookie": "session=bob"},
                    "objects": [{"url": bob_url, "marker": "bob-owned-canary"}]},
        }
        raw = hunter.run_web_loop(base, live=True, crawl=False, sleep_s=0,
                                  identities=json.dumps(identities), max_validations=6)
        report = json.loads(raw)
        assert "session=alice" not in raw and "session=bob" not in raw
        by_url = {item["url"]: item for item in report["validations"]}
        assert by_url[alice_url]["verdict"] == "CONFIRMED"
        assert by_url[bob_url]["verdict"] == "UNCONFIRMED"
        assert by_url[admin_url]["vuln_class"] == "bfla" and by_url[admin_url]["verdict"] == "CONFIRMED"
        assert all(item["coverage_recorded"] for item in by_url.values())
        for item in by_url.values():
            artifact = hunter.load_validation(item["validation_id"])
            assert hunter.validator_artifact_is_valid(artifact, expected_target=item["url"])
        coverage = json.loads(hunter.coverage_report(base))
        rows = {item["endpoint"]: item for item in coverage["per_endpoint"]}
        assert "bola" in rows[alice_url]["tested"] and "bola" in rows[bob_url]["tested"]
        assert "bfla" in rows[admin_url]["tested"]
        alice_observation = next(item for item in rows[alice_url]["observations"]
                                 if item["vuln_class"] == "bola")
        assert alice_observation["status"] == "confirmed"
        assert alice_observation["identity"] == "bob"
        assert alice_observation["resource_owner"] == "alice"
        assert not (tmp_path / "home" / "session-jar.json").exists()
    finally:
        server.shutdown()
        server.server_close()
