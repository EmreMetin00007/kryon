"""Tests for external owned loopback target runner."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

import pytest

import external_target_runner as ext
from test_full_agent_e6_benchmark import _write_llm_config


def test_normalize_loopback_origin_and_policy_config():
    assert ext.normalize_loopback_origin("http://127.0.0.1:18901") == "http://127.0.0.1:18901/"
    assert ext.normalize_loopback_origin("http://127.0.0.1:18901/") == "http://127.0.0.1:18901/"
    with pytest.raises(ValueError):
        ext.normalize_loopback_origin("https://example.com/")
    with pytest.raises(ValueError):
        ext.normalize_loopback_origin("http://127.0.0.1:18901/api")

    scope, policy = ext.external_policy_config(
        "http://127.0.0.1:18901",
        allowed_methods=["GET", "POST", "PUT"],
        max_seconds=900,
        max_requests=550,
    )
    assert scope["in_scope"] == [{"asset": "http://127.0.0.1:18901/"}]
    assert "POST" not in policy["blocked_http_methods"]
    assert "PUT" not in policy["blocked_http_methods"]
    assert set(policy["blocked_http_methods"]) == {"PATCH", "DELETE", "CONNECT", "TRACE"}
    assert policy["blind_discovery"]["differential_ownership"] is True


def test_select_representative_accounts_covers_tenants_roles_and_admins():
    accounts = [
        {"alias": "ops-admin", "tenant": "tenant-north", "role": "platform_admin", "password": "p1"},
        {"alias": "north-admin", "tenant": "tenant-north", "role": "tenant_admin", "password": "p2"},
        {"alias": "tech-north-a", "tenant": "tenant-north", "role": "technician", "password": "p3"},
        {"alias": "tech-north-b", "tenant": "tenant-north", "role": "technician", "password": "p4"},
        {"alias": "viewer-north", "tenant": "tenant-north", "role": "viewer", "password": "p5"},
        {"alias": "tech-south-a", "tenant": "tenant-south", "role": "technician", "password": "p6"},
        {"alias": "viewer-depot", "tenant": "tenant-depot", "role": "viewer", "password": "p7"},
    ]
    selected = ext.select_representative_accounts(accounts, max_members=4, max_admins=1)
    aliases = [row["alias"] for row in selected]
    assert len(selected) == 5
    assert "ops-admin" in aliases
    assert "tech-north-a" in aliases
    assert "tech-south-a" in aliases
    assert "viewer-depot" in aliases or "viewer-north" in aliases


def test_plan_only_and_remote_authorization_gate(tmp_path):
    cfg = _write_llm_config(tmp_path / "llm.json", "https://api.example.test/v1", "test-model")
    creds = tmp_path / "creds.json"
    creds.write_text(json.dumps({
        "target_url": "http://127.0.0.1:18901",
        "scope_rules": {"allowed_methods": ["GET", "POST", "PUT"]},
        "discovery": ["/", "/api/v1/discovery", "/openapi.json"],
        "test_accounts": [
            {"alias": "tech-a", "work_email": "tech-a@example.test", "password": "secret-pw-value", "tenant": "t1", "role": "technician"},
            {"alias": "tech-b", "work_email": "tech-b@example.test", "password": "secret-pw-value-2", "tenant": "t1", "role": "technician"},
        ],
    }), encoding="utf-8")

    out_dir = tmp_path / "out"
    plan_path, plan = ext.run_external_target(
        credentials_file=creds,
        provider_config=cfg,
        output_dir=out_dir,
        execute=False,
    )
    assert plan["mode"] == "plan_only"
    assert plan["llm_calls"] == 0
    assert plan["target_requests"] == 0
    raw = plan_path.read_text(encoding="utf-8")
    assert "secret-pw-value" not in raw
    assert plan["discovery_hints"] == ["/", "/api/v1/discovery", "/openapi.json"]

    with pytest.raises(PermissionError):
        ext.run_external_target(
            credentials_file=creds,
            provider_config=cfg,
            output_dir=out_dir,
            execute=True,
            authorize_live_provider=False,
        )


def test_sign_in_accounts_extracts_bearer_csrf_and_marker():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            assert self.path == "/api/v1/access/sign-in"
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            payload = json.dumps({
                "access_token": f"tok-{body['work_email']}",
                "csrf_token": "csrf-123",
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            assert self.path == "/api/v1/access/session"
            auth = self.headers.get("Authorization", "")
            alias = "tech-a" if "tech-a" in auth else "unknown"
            payload = json.dumps({"alias": alias, "tenant": "tenant-north", "role": "technician"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        signed = ext.sign_in_accounts(
            f"http://127.0.0.1:{srv.server_port}/",
            [{"alias": "tech-a", "work_email": "tech-a@example.test", "password": "pw", "tenant": "tenant-north", "role": "technician"}],
        )
        assert signed["tech-a"]["headers"] == {
            "Authorization": "Bearer tok-tech-a@example.test",
            "X-CSRF-Token": "csrf-123",
        }
        assert signed["tech-a"]["marker"] == "tech-a"
        assert signed["tech-a"]["role"] == "member"
        assert signed["tech-a"]["app_role"] == "technician"
        assert signed["tech-a"]["tenant"] == "tenant-north"
    finally:
        srv.shutdown()
        thread.join(timeout=5)
        srv.server_close()
