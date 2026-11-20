"""Comprehensive offline unit & integration tests for Middle-Ground Sprint E."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
VALIDATOR_DIR = ROOT / "mcp-servers" / "mcp-validator"
HUNTER_DIR = ROOT / "mcp-servers" / "mcp-hunter"
MEMORY_DIR = ROOT / "mcp-servers" / "mcp-memory-server"
for p in (SCRIPTS, VALIDATOR_DIR, HUNTER_DIR, MEMORY_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import evidence_trust as trust  # noqa: E402
import qa_expectation_policy as qapol  # noqa: E402
import verdict_ledger as ledger  # noqa: E402
import write_isolation as wiso  # noqa: E402
from cco_hunter_core.blind_discovery import (  # noqa: E402
    canonical_resource_type,
    discover_typed_resources,
    hydrate_template_url,
    normalize_owner_values,
    normalize_tenant_values,
)
from cco_validator_core import artifact_is_valid, load_validation  # noqa: E402

_VAL_SPEC = importlib.util.spec_from_file_location("mcp_validator_server", VALIDATOR_DIR / "server.py")
assert _VAL_SPEC is not None and _VAL_SPEC.loader is not None
validator_server = importlib.util.module_from_spec(_VAL_SPEC)
_VAL_SPEC.loader.exec_module(validator_server)


def _isolate_validator_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, run_id: str = "run-test-1") -> Path:
    state_home = tmp_path / "state"
    state_home.mkdir(parents=True, exist_ok=True)
    scope_file = tmp_path / "scope.json"
    policy_file = tmp_path / "policy.json"
    scope_file.write_text(json.dumps({
        "in_scope": [{"asset": "http://127.0.0.1/"}],
        "scope_policy": "explicit_only",
        "allow_loopback": True,
    }), encoding="utf-8")
    policy_file.write_text(json.dumps({
        "blocked_http_methods": ["DELETE", "PATCH", "CONNECT", "TRACE"],
        "background_network_jobs": "deny",
    }), encoding="utf-8")
    monkeypatch.setenv("CCO_HOME", str(state_home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope_file))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy_file))
    monkeypatch.setenv("CCO_RUN_ID", run_id)
    monkeypatch.setattr(validator_server, "VALID_DIR", str(state_home / "validations"))
    trust.prepare()
    return state_home


class _DualSaasMock:
    """Generic multi-tenant SaaS test server with randomized routes/fields & rotating CSRF."""

    def __init__(self, *, resource_a: str = "widgets", resource_b: str = "tickets", export_path: str = "org-dump",
                 tier_field: str = "privilege_rank", secret_field: str = "secret_memo") -> None:
        self.resource_a = resource_a
        self.resource_b = resource_b
        self.export_path = export_path
        self.tier_field = tier_field
        self.secret_field = secret_field
        self.write_requests: list[tuple[str, str, dict[str, Any]]] = []
        self.get_requests: list[str] = []
        self.csrf_by_token = {
            "tok-n1": "csrf-n1-0",
            "tok-n2": "csrf-n2-0",
            "tok-s1": "csrf-s1-0",
            "tok-adm": "csrf-adm-0",
        }
        self.widgets: dict[int, dict[str, Any]] = {
            1: {"id": 1, "name": "Item-1", "tenant_id": "t-north", "custodian_alias": "user-n1",
                tier_field: "basic", secret_field: "north-custodian-only", "notes": "ok"},
            2: {"id": 2, "name": "Item-2", "tenant_id": "t-south", "custodian_alias": "user-s1",
                tier_field: "basic", secret_field: "south-custodian-only", "notes": "ok"},
        }
        self.tickets: list[dict[str, Any]] = [
            {"id": 1, "widget_id": 1, "title": "Init", "tenant_id": "t-north", "custodian_alias": "user-n1", tier_field: "basic"},
        ]
        self.next_ticket_id = 2

    def token_info(self, headers) -> tuple[str, str, str, str]:
        auth = str(headers.get("Authorization") or "")
        tok = auth.removeprefix("Bearer ").strip()
        mapping = {
            "tok-n1": ("user-n1", "t-north", "member"),
            "tok-n2": ("user-n2", "t-north", "member"),
            "tok-s1": ("user-s1", "t-south", "member"),
            "tok-adm": ("user-adm", "t-north", "platform_admin"),
        }
        alias, tenant, role = mapping.get(tok, ("", "", ""))
        return tok, alias, tenant, role


def _start_mock_server(mock: _DualSaasMock) -> tuple[ThreadingHTTPServer, str]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _send(self, code: int, payload: Any, extra_headers: dict[str, str] | None = None):
            body = json.dumps(payload).encode("utf-8") if not isinstance(payload, str) else payload.encode("utf-8")
            ctype = "text/plain" if isinstance(payload, str) else "application/json"
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            mock.get_requests.append(self.path)
            if self.path == "/":
                return self._send(200, "<!doctype html><html><body>SPA Shell</body></html>")
            if self.path == "/api/v1/discovery":
                return self._send(200, {
                    "openapi": "/openapi.json",
                    "endpoints": [
                        f"/api/v1/{mock.resource_a}",
                        f"/api/v1/{mock.resource_b}",
                        f"/api/v1/{mock.export_path}",
                        "/api/v1/admin-audit",
                    ],
                })
            if self.path == "/openapi.json":
                return self._send(200, {
                    "openapi": "3.0.3",
                    "paths": {
                        f"/api/v1/{mock.resource_a}": {"get": {"operationId": "listA"}},
                        f"/api/v1/{mock.resource_a}/{{item_id}}": {
                            "get": {"operationId": "getA", "parameters": [{"name": "item_id", "in": "path", "required": True, "schema": {"type": "integer"}}]},
                            "put": {
                                "operationId": "putA",
                                "parameters": [{"name": "item_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                                "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {
                                    "notes": {"type": "string"},
                                    mock.tier_field: {"type": "string", "enum": ["basic", "vip"]},
                                }}}}},
                            },
                        },
                        f"/api/v1/{mock.resource_b}": {
                            "get": {"operationId": "listB"},
                            "post": {
                                "operationId": "postB",
                                "requestBody": {"content": {"application/json": {"schema": {"type": "object", "required": ["widget_id", "title"], "properties": {
                                    "widget_id": {"type": "integer"},
                                    "title": {"type": "string"},
                                }}}}},
                            },
                        },
                        f"/api/v1/{mock.resource_b}/{{ticket_id}}": {
                            "get": {"operationId": "getB", "parameters": [{"name": "ticket_id", "in": "path", "required": True, "schema": {"type": "integer"}}]},
                        },
                        f"/api/v1/{mock.export_path}": {"get": {"operationId": "exportAll"}},
                        "/api/v1/admin-audit": {"get": {"operationId": "adminAudit"}},
                    },
                })
            tok, alias, tenant, role = mock.token_info(self.headers)
            if self.path == "/api/v1/access/session":
                if not alias:
                    return self._send(401, {"error": "unauthorized"})
                return self._send(200, {"alias": alias, "tenant": tenant, "role": role, "csrf_token": mock.csrf_by_token[tok]})

            if not alias:
                return self._send(401, {"error": "unauthorized"})

            if self.path == f"/api/v1/{mock.resource_a}":
                items = [
                    {k: v for k, v in w.items() if k != mock.secret_field}
                    for w in mock.widgets.values()
                    if role == "platform_admin" or w["tenant_id"] == tenant
                ]
                return self._send(200, {"items": items})

            if self.path.startswith(f"/api/v1/{mock.resource_a}/"):
                wid = int(self.path.rsplit("/", 1)[-1])
                item = mock.widgets.get(wid)
                if not item:
                    return self._send(404, {"error": "not found"})
                # Intentional cross-tenant & same-tenant private-field leak for tests
                return self._send(200, item)

            if self.path == f"/api/v1/{mock.resource_b}":
                items = [t for t in mock.tickets if role == "platform_admin" or t["tenant_id"] == tenant]
                return self._send(200, {"items": items})

            if self.path.startswith(f"/api/v1/{mock.resource_b}/"):
                tid = int(self.path.rsplit("/", 1)[-1])
                t = next((x for x in mock.tickets if x["id"] == tid), None)
                if not t or (t["tenant_id"] != tenant and role != "platform_admin"):
                    return self._send(403, {"error": "forbidden"})
                return self._send(200, t)

            if self.path == f"/api/v1/{mock.export_path}":
                # Unsafe multi-tenant dump accessible to non-admin
                return self._send(200, {"items": list(mock.widgets.values())})

            if self.path == "/api/v1/admin-audit":
                if role != "platform_admin":
                    return self._send(403, {"error": "forbidden: admin only"})
                return self._send(200, {"audit": ["ok"]})

            if self.path == "/api/v1/telemetry-gate":
                return self._send(403, {"error": "telemetry challenge required"}, {"X-Telemetry-Challenge": "1"})

            return self._send(404, {"error": "not found"})

        def do_PUT(self):
            tok, alias, tenant, _role = mock.token_info(self.headers)
            if not alias:
                return self._send(401, {"error": "unauthorized"})
            if self.headers.get("X-CSRF-Token") != mock.csrf_by_token.get(tok):
                return self._send(403, {"error": "csrf mismatch"})
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            body = json.loads(raw or "{}")
            mock.write_requests.append(("PUT", self.path, body))
            next_csrf = f"csrf-{tok}-{len(mock.write_requests)}"
            mock.csrf_by_token[tok] = next_csrf
            wid = int(self.path.rsplit("/", 1)[-1])
            item = mock.widgets[wid]
            if "notes" in body:
                item["notes"] = body["notes"]
            if mock.tier_field in body:
                # Deliberate mass assignment persistence verified via independent GET
                item[mock.tier_field] = body[mock.tier_field]
            return self._send(200, {"ok": True}, {"X-CSRF-Token-Next": next_csrf})

        def do_POST(self):
            if self.path == "/api/v1/access/sign-in":
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                body = json.loads(raw or "{}")
                email = str(body.get("work_email") or "")
                tok_map = {
                    "n1@test": "tok-n1",
                    "n2@test": "tok-n2",
                    "s1@test": "tok-s1",
                    "adm@test": "tok-adm",
                }
                tok = tok_map.get(email)
                if not tok:
                    return self._send(401, {"error": "invalid credentials"})
                return self._send(200, {"access_token": tok, "csrf_token": mock.csrf_by_token[tok]})
            tok, alias, tenant, _role = mock.token_info(self.headers)
            if not alias:
                return self._send(401, {"error": "unauthorized"})
            if self.headers.get("X-CSRF-Token") != mock.csrf_by_token.get(tok):
                return self._send(403, {"error": "csrf mismatch"})
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            body = json.loads(raw or "{}")
            mock.write_requests.append(("POST", self.path, body))
            next_csrf = f"csrf-{tok}-{len(mock.write_requests)}"
            mock.csrf_by_token[tok] = next_csrf
            # Safe POST: ignores restricted tier_field on creation
            rec = {
                "id": mock.next_ticket_id,
                "widget_id": body.get("widget_id", 1),
                "title": body.get("title", "new"),
                "tenant_id": tenant,
                "custodian_alias": alias,
                mock.tier_field: "basic",
            }
            mock.next_ticket_id += 1
            mock.tickets.append(rec)
            return self._send(201, rec, {"X-CSRF-Token-Next": next_csrf})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def test_five_status_ledger_and_probable_operator_review_signature(tmp_path, monkeypatch):
    _isolate_validator_env(tmp_path, monkeypatch)
    entries = [
        {"status": ledger.verdict_to_ledger_status("INCONCLUSIVE", blocked_reason="write_isolation_unattested")},
        {"status": ledger.verdict_to_ledger_status("ERROR", execution_error="timeout")},
        {"status": ledger.verdict_to_ledger_status("INCONCLUSIVE", oracle_gap_reason="missing_policy_rule")},
        {"status": ledger.verdict_to_ledger_status("UNCONFIRMED")},
        {"status": ledger.verdict_to_ledger_status("CONFIRMED")},
        {"status": ledger.verdict_to_ledger_status("PROBABLE")},
    ]
    summary = ledger.summarize_ledger(entries, planned=6)
    assert summary["blocked"] == 1
    assert summary["execution_error"] == 1
    assert summary["oracle_gap"] == 1
    assert summary["verified_pass"] == 1
    assert summary["confirmed_violation"] == 1
    assert summary["probable_review"] == 1
    assert summary["planned"] == 6
    assert summary["adjudication_coverage"] == pytest.approx(2 / 6, abs=1e-4)

    mock = _DualSaasMock()
    srv, base = _start_mock_server(mock)
    try:
        raw_prob = validator_server.validate_access_control(
            target_url=f"{base}/api/v1/org-dump",
            check_category="function_role_access",
            caller_headers_json=json.dumps({"Authorization": "Bearer tok-n1"}),
            caller_alias="user-n1",
            caller_role="technician",
            caller_tenant="t-north",
            owner_headers_json=json.dumps({"Authorization": "Bearer tok-adm"}),
            owner_alias="user-adm",
            mode="blind",
        )
        prob_res = json.loads(raw_prob)
        assert prob_res["verdict"] == "PROBABLE"
        assert prob_res["reportable"] is False
        rec = load_validation(prob_res["validation_id"])
        assert rec is not None
        assert rec["verdict"] == "PROBABLE"
        assert rec["reportable"] is False
        assert artifact_is_valid(rec)
        # Signed specifically under "operator-review", NOT "validator-artifact"
        from cco_validator_core.evidence import _integrity_payload, _signature_is_valid
        assert rec["artifact"]["signature"]["purpose"] == "operator-review"
        assert _signature_is_valid(rec) is True
        sig_envelope = {
            "signature_alg": rec["artifact"]["signature"]["algorithm"],
            "key_id": rec["artifact"]["signature"]["key_id"],
            "signature": rec["artifact"]["signature"]["value"],
        }
        assert trust.verify(_integrity_payload(rec), sig_envelope, "operator-review") is True
        assert trust.verify(_integrity_payload(rec), sig_envelope, "validator-artifact") is False
    finally:
        srv.shutdown()
        srv.server_close()


def test_typed_resource_discovery_short_ids_non_colliding_and_hydration():
    mock = _DualSaasMock()
    srv, base = _start_mock_server(mock)
    try:
        assert canonical_resource_type(f"{base}/api/v1/widgets/{{widget_id}}") == "/api/v1/widgets"
        assert canonical_resource_type(f"{base}/api/v1/tickets/{{ticket_id}}") == "/api/v1/tickets"
        assert hydrate_template_url(f"{base}/api/v1/widgets/{{widget_id}}", "1") == f"{base}/api/v1/widgets/1"
        assert normalize_owner_values({"custodian_alias": "alice", "created_by_id": 7}) == {"alice", "7"}
        assert normalize_tenant_values({"org_slug": "north", "tenant_id": "t-north"}) == {"north", "t-north"}

        import requests as req
        sess = req.Session()
        sess.trust_env = False

        def fetch(url, headers):
            r = sess.get(url, headers=headers, timeout=5)
            return {"ok": True, "status": r.status_code, "text": r.text, "headers": dict(r.headers)}

        report = discover_typed_resources(
            base,
            {
                "user-n1": {"headers": {"Authorization": "Bearer tok-n1"}},
                "user-s1": {"headers": {"Authorization": "Bearer tok-s1"}},
            },
            fetch,
            lambda u: u.startswith(base),
            collection_urls=[f"{base}/api/v1/widgets", f"{base}/api/v1/tickets"],
            template_routes=[
                {"url": f"{base}/api/v1/widgets/{{widget_id}}", "method": "GET"},
                {"url": f"{base}/api/v1/tickets/{{ticket_id}}", "method": "GET"},
            ],
        )
        # Both resource families use short int ID '1' without colliding
        assert "/api/v1/widgets::1" in report["resources"]
        assert "/api/v1/tickets::1" in report["resources"]
        assert "/api/v1/widgets::2" in report["resources"]
        assert report["resources"]["/api/v1/widgets::1"]["tenants"] == ["t-north"]
        assert report["resources"]["/api/v1/widgets::2"]["tenants"] == ["t-south"]
        assert f"{base}/api/v1/widgets/1" in report["resources"]["/api/v1/widgets::1"]["detail_urls"]
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize("names", [
    ("widgets", "tickets", "org-dump", "privilege_rank", "secret_memo"),
    ("z9x_items", "q4_entries", "global-snapshot", "z_tier_level", "z_internal_note"),
])
def test_blind_mode_verdicts_and_zero_fp_under_route_field_substitution(tmp_path, monkeypatch, names):
    run_id = "run-blind-sub"
    _isolate_validator_env(tmp_path, monkeypatch, run_id=run_id)
    res_a, res_b, exp_p, tier_f, sec_f = names
    mock = _DualSaasMock(resource_a=res_a, resource_b=res_b, export_path=exp_p, tier_field=tier_f, secret_field=sec_f)
    srv, base = _start_mock_server(mock)
    try:
        # 1. Cross-tenant object read -> CONFIRMED
        ct = json.loads(validator_server.validate_access_control(
            target_url=f"{base}/api/v1/{res_a}/1",
            check_category="cross_tenant_read",
            caller_headers_json=json.dumps({"Authorization": "Bearer tok-s1"}),
            caller_alias="user-s1",
            caller_tenant="t-south",
            owner_alias="user-n1",
            owner_tenant="t-north",
            absent_from_caller_collection=True,
            mode="blind",
        ))
        assert ct["verdict"] == "CONFIRMED"
        assert ct["reportable"] is True

        # 2. Same-tenant cross-custodian private field -> PROBABLE
        st = json.loads(validator_server.validate_access_control(
            target_url=f"{base}/api/v1/{res_a}/1",
            check_category="same_tenant_peer_read",
            caller_headers_json=json.dumps({"Authorization": "Bearer tok-n2"}),
            caller_alias="user-n2",
            caller_tenant="t-north",
            owner_headers_json=json.dumps({"Authorization": "Bearer tok-n1"}),
            owner_alias="user-n1",
            owner_tenant="t-north",
            list_fields_json=json.dumps(["id", "name", "tenant_id", "custodian_alias", tier_f, "notes"]),
            mode="blind",
        ))
        assert st["verdict"] == "PROBABLE"
        assert st["reportable"] is False

        # 3. Parameterless multi-tenant dump -> PROBABLE
        role_diff = json.loads(validator_server.validate_access_control(
            target_url=f"{base}/api/v1/{exp_p}",
            check_category="function_role_access",
            caller_headers_json=json.dumps({"Authorization": "Bearer tok-n1"}),
            caller_alias="user-n1",
            caller_role="member",
            caller_tenant="t-north",
            owner_headers_json=json.dumps({"Authorization": "Bearer tok-adm"}),
            owner_alias="user-adm",
            mode="blind",
        ))
        assert role_diff["verdict"] == "PROBABLE"
        assert role_diff["reportable"] is False

        # 4. Safe tenant-scoped & admin-only controls -> UNCONFIRMED (0 FP)
        safe_admin = json.loads(validator_server.validate_access_control(
            target_url=f"{base}/api/v1/admin-audit",
            check_category="function_role_access",
            caller_headers_json=json.dumps({"Authorization": "Bearer tok-n1"}),
            caller_alias="user-n1",
            caller_role="member",
            caller_tenant="t-north",
            mode="blind",
        ))
        assert safe_admin["verdict"] == "UNCONFIRMED"

        safe_ct = json.loads(validator_server.validate_access_control(
            target_url=f"{base}/api/v1/{res_b}/1",
            check_category="cross_tenant_read",
            caller_headers_json=json.dumps({"Authorization": "Bearer tok-s1"}),
            caller_alias="user-s1",
            caller_tenant="t-south",
            owner_tenant="t-north",
            absent_from_caller_collection=True,
            mode="blind",
        ))
        assert safe_ct["verdict"] == "UNCONFIRMED"

        # 5. Field binding with valid attestation & CSRF rotation -> PUT PROBABLE, safe POST UNCONFIRMED
        att = wiso.issue_attestation(base, run_id)
        fb_vuln = json.loads(validator_server.validate_field_binding(
            target_url=f"{base}/api/v1/{res_a}/1",
            method="PUT",
            read_url=f"{base}/api/v1/{res_a}/1",
            headers_json=json.dumps({"Authorization": "Bearer tok-n1", "X-CSRF-Token": "stale"}),
            allowed_payload_json=json.dumps({"notes": "ctrl"}),
            candidate_fields_json=json.dumps([{"name": tier_f, "value": "vip"}]),
            write_isolation_json=json.dumps(att),
            expected_run_id=run_id,
            session_check_url=f"{base}/api/v1/access/session",
            mode="blind",
        ))
        assert fb_vuln["verdict"] == "PROBABLE"
        assert fb_vuln["reportable"] is False
        assert mock.widgets[1][tier_f] == "vip"

        fb_safe = json.loads(validator_server.validate_field_binding(
            target_url=f"{base}/api/v1/{res_b}",
            method="POST",
            read_url=f"{base}/api/v1/{res_b}",
            headers_json=json.dumps({"Authorization": "Bearer tok-n1"}),
            allowed_payload_json=json.dumps({"widget_id": 1, "title": "routine"}),
            candidate_fields_json=json.dumps([{"name": tier_f, "value": "vip"}]),
            write_isolation_json=json.dumps(att),
            expected_run_id=run_id,
            session_check_url=f"{base}/api/v1/access/session",
            mode="blind",
        ))
        assert fb_safe["verdict"] == "UNCONFIRMED"
    finally:
        srv.shutdown()
        srv.server_close()


def test_write_isolation_blocks_missing_stale_wrong_run_with_zero_requests(tmp_path, monkeypatch):
    run_id = "run-iso-check"
    _isolate_validator_env(tmp_path, monkeypatch, run_id=run_id)
    mock = _DualSaasMock()
    srv, base = _start_mock_server(mock)
    try:
        stale_att = wiso.issue_attestation(base, run_id, ttl_seconds=1.0, now=time.time() - 120.0)
        wrong_run_att = wiso.issue_attestation(base, "other-run-999")
        for bad_att in ("", json.dumps(stale_att), json.dumps(wrong_run_att)):
            res = json.loads(validator_server.validate_field_binding(
                target_url=f"{base}/api/v1/widgets/1",
                method="PUT",
                headers_json=json.dumps({"Authorization": "Bearer tok-n1"}),
                allowed_payload_json=json.dumps({"notes": "ctrl"}),
                candidate_fields_json=json.dumps(["privilege_rank"]),
                write_isolation_json=bad_att,
                expected_run_id=run_id,
            ))
            assert res["verdict"] == "INCONCLUSIVE"
            assert res["evidence"]["blocked"] is True
            assert res["evidence"]["blocked_reason"] == "write_isolation_unattested"
            assert res["evidence"]["writes_emitted"] == 0
        # Zero HTTP requests of ANY kind reached the mock target!
        assert mock.write_requests == []
        assert mock.get_requests == []
    finally:
        srv.shutdown()
        srv.server_close()


def test_policy_mode_full_partial_empty_and_oracle_gap_zero_side_effects(tmp_path, monkeypatch):
    run_id = "run-policy-mode"
    _isolate_validator_env(tmp_path, monkeypatch, run_id=run_id)
    mock = _DualSaasMock()
    srv, base = _start_mock_server(mock)
    try:
        # Empty policy -> missing rule returns oracle_gap with 0 HTTP requests
        empty_policy = {"schema": "qa-expectation-policy/1", "access_rules": [], "field_binding_rules": [], "telemetry_controls": []}
        assert qapol.match_access_rule(empty_policy, method="GET", path=f"{base}/api/v1/widgets/1", category="cross_tenant_read")[1] == "oracle_gap:missing_policy_rule"
        assert qapol.match_field_binding_rule(empty_policy, method="PUT", path=f"{base}/api/v1/widgets/1")[1] == "oracle_gap:missing_policy_rule"

        # Conflicting policy rules -> oracle_gap:conflicting_policy_rule
        conflict_policy = {
            "schema": "qa-expectation-policy/1",
            "access_rules": [
                {"path_pattern": "/api/v1/widgets/{id}", "method": "GET", "category": "cross_tenant_read", "expect": "deny_cross_tenant"},
                {"path_pattern": "/api/v1/widgets/*", "method": "GET", "category": "cross_tenant_read", "expect": "allow_authenticated"},
            ],
        }
        assert qapol.match_access_rule(conflict_policy, method="GET", path="/api/v1/widgets/1", category="cross_tenant_read")[1] == "oracle_gap:conflicting_policy_rule"

        gap_res = json.loads(validator_server.validate_access_control(
            target_url=f"{base}/api/v1/widgets/1",
            check_category="cross_tenant_read",
            caller_headers_json=json.dumps({"Authorization": "Bearer tok-s1"}),
            mode="policy",
            expected_rule_json="{}",
        ))
        assert gap_res["verdict"] == "INCONCLUSIVE"
        assert gap_res["evidence"]["oracle_gap"] is True
        assert mock.get_requests == []
        assert mock.write_requests == []

        # Telemetry control distinct check -> UNCONFIRMED
        tc_rule = {"path_pattern": "/api/v1/telemetry-gate", "method": "GET", "category": "telemetry_control", "expect": "challenge_or_authz_distinct"}
        tc_res = json.loads(validator_server.validate_access_control(
            target_url=f"{base}/api/v1/telemetry-gate",
            check_category="telemetry_control",
            caller_headers_json=json.dumps({"Authorization": "Bearer tok-n1"}),
            mode="policy",
            expected_rule_json=json.dumps(tc_rule),
        ))
        assert tc_res["verdict"] == "UNCONFIRMED"

        # Policy-verified CONFIRMED cross-tenant & field binding
        ct_rule = {"path_pattern": "/api/v1/widgets/{id}", "method": "GET", "category": "cross_tenant_read", "expect": "deny_cross_tenant"}
        ct_res = json.loads(validator_server.validate_access_control(
            target_url=f"{base}/api/v1/widgets/1",
            check_category="cross_tenant_read",
            caller_headers_json=json.dumps({"Authorization": "Bearer tok-s1"}),
            caller_alias="user-s1",
            caller_tenant="t-south",
            owner_tenant="t-north",
            mode="policy",
            expected_rule_json=json.dumps(ct_rule),
        ))
        assert ct_res["verdict"] == "CONFIRMED"
        assert ct_res["reportable"] is True

        att = wiso.issue_attestation(base, run_id)
        fb_rule = {"path_pattern": "/api/v1/widgets/{id}", "method": "PUT", "expect": "deny_restricted_fields", "restricted_fields": ["privilege_rank"]}
        fb_res = json.loads(validator_server.validate_field_binding(
            target_url=f"{base}/api/v1/widgets/1",
            method="PUT",
            read_url=f"{base}/api/v1/widgets/1",
            headers_json=json.dumps({"Authorization": "Bearer tok-n1"}),
            allowed_payload_json=json.dumps({"notes": "ctrl"}),
            candidate_fields_json=json.dumps([{"name": "privilege_rank", "value": "vip"}]),
            write_isolation_json=json.dumps(att),
            expected_run_id=run_id,
            session_check_url=f"{base}/api/v1/access/session",
            mode="policy",
            expected_rule_json=json.dumps(fb_rule),
        ))
        assert fb_res["verdict"] == "CONFIRMED"
        assert fb_res["reportable"] is True
    finally:
        srv.shutdown()
        srv.server_close()


def _start_loopback_llm_driver():
    """Minimal loopback OpenAI chat-completions driver for testing full external_target_runner."""
    class DriverHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            req = json.loads(raw or "{}")
            ctx = json.loads(req["messages"][1]["content"])
            spec = ctx.get("task_spec") or {}
            phase = spec.get("phase")
            steps = spec.get("steps") or []
            recent = ctx.get("recent_results") or []
            if phase == "recon" and not recent:
                call = {
                    "id": "call_recon_1",
                    "type": "function",
                    "function": {"name": "kali-tools_curl_request", "arguments": json.dumps({"url": spec["target"]})},
                }
            else:
                sum_status = "partial" if phase == "access" else "done"
                step_status = "not_tested" if phase == "access" else "done"
                model_steps = [s for s in steps if not s.get("host_managed")]
                payload = {
                    "status": sum_status,
                    "steps": [{"id": s["id"], "status": step_status} for s in model_steps],
                    "next": "proceed" if phase != "report" else "complete",
                }
                call = {
                    "id": f"call_sum_{phase}",
                    "type": "function",
                    "function": {"name": "submit_phase_summary", "arguments": json.dumps(payload)},
                }
            resp = {
                "id": "chatcmpl-driver",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "", "tool_calls": [call]}, "finish_reason": "tool_calls"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            }
            out = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), DriverHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/v1"


def test_external_target_runner_e2e_blind_mode_and_member_batches(tmp_path, monkeypatch):
    import external_target_runner as ext
    from full_agent_python_solver import PythonSolver

    mock = _DualSaasMock()
    srv, base = _start_mock_server(mock)
    llm_srv, llm_url = _start_loopback_llm_driver()
    try:
        cfg_path = tmp_path / "llm.json"
        cfg_path.write_text(json.dumps({
            "schema": "cco-llm/1",
            "model": "local/test-driver",
            "providers": {
                "local": {
                    "base_url": llm_url,
                    "models": ["test-driver"],
                    "api_key_env": "TEST_LOOPBACK_LLM_KEY",
                    "api_key_header": "Authorization",
                }
            },
        }), encoding="utf-8")
        monkeypatch.setenv("TEST_LOOPBACK_LLM_KEY", "dummy-local-key")

        creds_path = tmp_path / "creds.json"
        creds_path.write_text(json.dumps({
            "target_url": base,
            "scope_rules": {"allowed_methods": ["GET", "POST", "PUT"]},
            "discovery": ["/", "/api/v1/discovery", "/openapi.json"],
            "test_accounts": [
                {"alias": "user-n1", "work_email": "n1@test", "password": "pw", "tenant": "t-north", "role": "technician"},
                {"alias": "user-n2", "work_email": "n2@test", "password": "pw", "tenant": "t-north", "role": "viewer"},
                {"alias": "user-s1", "work_email": "s1@test", "password": "pw", "tenant": "t-south", "role": "technician"},
                {"alias": "user-adm", "work_email": "adm@test", "password": "pw", "tenant": "t-north", "role": "platform_admin"},
            ],
        }), encoding="utf-8")

        out_dir = tmp_path / "runner-out"
        manifest_path, manifest = ext.run_external_target(
            credentials_file=creds_path,
            provider_config=cfg_path,
            output_dir=out_dir,
            execute=True,
        )
        assert manifest["qa_mode"] == "blind"
        assert manifest["status"] in {"python_finished_verified", "python_tasks_finished", "python_inconclusive"}
        confirmed = json.loads(Path(manifest["findings_artifact"]).read_text(encoding="utf-8"))
        probable = json.loads(Path(manifest["probable_findings_artifact"]).read_text(encoding="utf-8"))
        assert len(confirmed) >= 1
        assert all(row["verdict"] == "CONFIRMED" and row["reportable"] is True for row in confirmed)
        assert len(probable) >= 3
        assert all(row["verdict"] == "PROBABLE" and row["review_tier"] == "operator-review" and row["reportable"] is False for row in probable)
        # Ensure CONFIRMED and PROBABLE stay strictly separated
        assert {row["validation_id"] for row in confirmed}.isdisjoint({row["validation_id"] for row in probable})
        assert manifest["verdict_ledger"]["confirmed_violation"] >= 1
        assert manifest["verdict_ledger"]["probable_review"] >= 3
        assert manifest["verdict_ledger"]["verified_pass"] >= 1
        assert manifest["verdict_ledger"]["adjudication_coverage"] > 0

        # Ensure E6 member_batches invariant still projects only role == 'member'
        origin = base.rstrip("/") + "/"
        bindings = {
            "user-n1": {"role": "member", "target": origin, "test_data_only": True, "owned_objects_private": True},
            "user-n2": {"role": "member", "target": origin, "test_data_only": True, "owned_objects_private": True},
            "user-s1": {"role": "member", "target": origin, "test_data_only": True, "owned_objects_private": True},
            "user-adm": {"role": "admin", "target": origin, "test_data_only": True, "owned_objects_private": True},
        }
        class _DummyTasks:
            def __init__(self, b):
                self.bindings = b
        class _DummySpec:
            target = origin
        class _DummyBroker:
            def __init__(self, b):
                self.tasks = _DummyTasks(b)
            def session_checks(self, s):
                return [{"target": s.target, "identity": k} for k, v in sorted(self.tasks.bindings.items()) if v["target"] == s.target]
        class _DummySolver:
            member_pair_categories = PythonSolver.member_pair_categories
            def __init__(self, b):
                self.broker = _DummyBroker(b)
        batches = PythonSolver.member_batches(_DummySolver(bindings), _DummySpec())
        assert sorted(tuple(sorted(b)) for b in batches) == [
            ("user-n1", "user-n2"),
            ("user-n1", "user-s1"),
            ("user-n2", "user-s1"),
        ]
        assert all("user-adm" not in pair for pair in batches)
    finally:
        llm_srv.shutdown()
        llm_srv.server_close()
        srv.shutdown()
        srv.server_close()


def test_high_recall_unlocks_search_redirect_and_sqli_while_preserving_e6_defaults():
    import hashlib
    from types import SimpleNamespace
    from urllib.parse import parse_qsl, urlsplit
    import python_candidate_runtime as cand

    target = "http://127.0.0.1:18899/"
    spec = SimpleNamespace(
        id="access-3",
        target=target,
        vector="access",
        tools={
            "hunter_run_web_loop",
            "validator_validate_sqli",
            "validator_validate_ssti",
            "validator_validate_path_traversal",
            "validator_validate_xss_reflection",
            "validator_validate_open_redirect",
        },
    )
    bindings = {
        "member-a": {
            "target": target,
            "role": "member",
            "test_data_only": True,
            "owned_objects_private": True,
        }
    }

    def _rec(url: str, params: list[dict[str, Any]] | None = None, identity: str = "member-a") -> dict[str, Any]:
        out: dict[str, Any] = {
            "url": url,
            "method": "GET",
            "identity_ref": identity,
            "source_spec_id": "enum-2",
            "source_artifact": "/tmp/enum.json",
            "source_sha256": hashlib.sha256(url.encode()).hexdigest(),
        }
        if params is not None:
            out["params"] = params
        return out

    records = [
        _rec(f"{target}documents/search?q=alpha"),
        _rec(f"{target}auth/continue", params=[{"name": "next", "in": "query", "sample": ""}]),
        _rec(f"{target}documents?sort=score"),
        _rec(f"{target}items?id=1"),
    ]
    allow_all = lambda *_a, **_kw: {"eligible": True, "reason_code": ""}

    # 1. Strict E6 defaults (high_recall=False) remain unchanged.
    strict_rows = cand.parameter_candidates(spec, records, bindings, profile_eligibility=allow_all, high_recall=False)
    strict_by_key = {(urlsplit(r["route"]).path, r["param"], r.get("validation_profile")): r for r in strict_rows}
    assert ("/documents/search", "q", "readonly_xss_reflection") not in strict_by_key
    assert strict_by_key[("/auth/continue", "next", "readonly_open_redirect")]["eligible"] is False
    assert strict_by_key[("/auth/continue", "next", "readonly_open_redirect")]["reason_code"] == "missing_observed_query_sample"
    assert strict_by_key[("/documents", "sort", "readonly_sqli_boolean")]["eligible"] is False
    assert strict_by_key[("/items", "id", "readonly_sqli_boolean")]["recipes"]["hunter_run_web_loop"].get("high_recall") is None

    # 2. High-recall mode unlocks search XSS, sample-less redirect form/link params, and full SQLi.
    hr_rows = cand.parameter_candidates(spec, records, bindings, profile_eligibility=allow_all, high_recall=True)
    hr_by_key = {(urlsplit(r["route"]).path, r["param"], r.get("validation_profile")): r for r in hr_rows}
    assert hr_by_key[("/documents/search", "q", "readonly_xss_reflection")]["eligible"] is True
    assert hr_by_key[("/documents/search", "q", "readonly_sqli_boolean")]["eligible"] is True
    redir_row = hr_by_key[("/auth/continue", "next", "readonly_open_redirect")]
    assert redir_row["eligible"] is True
    assert redir_row["reason_code"] == ""
    assert dict(parse_qsl(urlsplit(redir_row["route"]).query))["next"] == "/dashboard"
    sqli_row = hr_by_key[("/documents", "sort", "readonly_sqli_boolean")]
    assert sqli_row["eligible"] is True
    assert sqli_row["arguments"].get("high_recall") is True
    # Direct recipe (when anonymous) also sets boolean_only=False under high_recall=True.
    anon_hr = cand.parameter_candidates(
        spec,
        [_rec(f"{target}documents?sort=score", identity="anon")],
        {},
        profile_eligibility=allow_all,
        high_recall=True,
    )
    anon_sqli = next(r for r in anon_hr if r.get("validation_profile") == "readonly_sqli_boolean")
    assert anon_sqli["arguments"]["boolean_only"] is False


def test_template_free_concrete_uuid_html_and_admin_exclusive_without_openapi(tmp_path, monkeypatch):
    import external_target_runner as ext

    doc_a = "11111111-1111-4111-8111-111111111111"
    doc_b = "22222222-2222-4222-8222-222222222222"

    class HtmlApiHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _send(self, code: int, body: Any, ctype: str = "text/html", location: str = ""):
            raw = (json.dumps(body) if not isinstance(body, str) else body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json" if not isinstance(body, str) else ctype)
            self.send_header("Content-Length", str(len(raw)))
            if location:
                self.send_header("Location", location)
            self.end_headers()
            self.wfile.write(raw)

        def _actor(self) -> tuple[str, str, str]:
            cookie = self.headers.get("Cookie") or ""
            mapping = {
                "sid=ma": ("member-a", "t-north", "member"),
                "sid=mb": ("member-b", "t-north", "member"),
                "sid=mc": ("member-c", "t-south", "member"),
                "sid=adm": ("admin-a", "t-north", "platform_admin"),
            }
            for k, v in mapping.items():
                if k in cookie:
                    return v
            return ("", "", "")

        def do_POST(self):
            if self.path == "/login":
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                data = json.loads(body) if body.startswith("{") else {}
                email = data.get("work_email", "")
                sid = {"ma@t": "ma", "mb@t": "mb", "mc@t": "mc", "adm@t": "adm"}.get(email, "")
                if not sid:
                    return self._send(401, {"error": "invalid"})
                raw = json.dumps({"ok": True}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"sid={sid}; Path=/")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            self._send(404, "not found")

        def do_GET(self):
            alias, tenant, role = self._actor()
            if self.path == "/openapi.json":
                return self._send(404, {"error": "not found"})
            if self.path == "/api/session":
                if not alias:
                    return self._send(401, {"error": "unauthorized"})
                return self._send(200, {"alias": alias, "tenant": tenant, "role": role})
            if self.path == "/api/v1/telemetry/overview":
                # Intentional Auth Bypass: returns structured JSON anonymously
                return self._send(200, {"tenants": ["t-north", "t-south"], "active_docs": 2})
            if not alias:
                return self._send(302, "login required", location="/login")
            if self.path == "/":
                return self._send(302, "redirecting", location="/dashboard")
            if self.path == "/dashboard":
                adm_link = '<a href="/api/v1/admin/audit-export">Audit Export</a>' if role == "platform_admin" else ""
                return self._send(
                    200,
                    f"<html><body><nav><a href='/documents'>Docs</a><a href='/reports'>Reports</a><a href='/api/v1/telemetry/overview'>Telemetry</a>{adm_link}</nav></body></html>",
                )
            if self.path == "/reports":
                # Plain HTML nav shell (must NOT trigger noisy PROBABLE)
                return self._send(
                    200,
                    "<html><body><h1>Reports Menu</h1><p>Select a report</p><ul><li>Summary</li><li>Monthly</li></ul></body></html>",
                )
            if self.path == "/documents":
                if alias == "member-a":
                    return self._send(200, f"<html><body><a href='/documents/{doc_a}'>Doc A</a></body></html>")
                if alias == "member-b":
                    return self._send(200, f"<html><body><a href='/documents/{doc_b}'>Doc B</a></body></html>")
                return self._send(200, "<html><body>No docs</body></html>")
            if self.path == f"/documents/{doc_a}":
                # Intentional BOLA + Cross-Tenant leak on HTML detail without JSON
                return self._send(200, f"<html><body><h1>Document {doc_a}</h1><p>Owner: member-a</p><p>Tenant: t-north</p><p>Secret: private-north-a</p></body></html>")
            if self.path == f"/documents/{doc_b}":
                return self._send(200, f"<html><body><h1>Document {doc_b}</h1><p>Owner: member-b</p><p>Tenant: t-north</p></body></html>")
            if self.path == "/api/v1/admin/audit-export":
                if role != "platform_admin":
                    return self._send(403, {"error": "admin only"})
                return self._send(200, {"audit": [{"actor": "member-a"}]})
            return self._send(404, "not found")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), HtmlApiHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}/"
    llm_srv, llm_url = _start_loopback_llm_driver()
    try:
        cfg_path = tmp_path / "llm.json"
        cfg_path.write_text(json.dumps({
            "schema": "cco-llm/1",
            "model": "local/test-driver",
            "providers": {"local": {"base_url": llm_url, "models": ["test-driver"], "api_key_env": "TEST_LOOPBACK_LLM_KEY"}},
        }), encoding="utf-8")
        monkeypatch.setenv("TEST_LOOPBACK_LLM_KEY", "dummy-key")
        creds_path = tmp_path / "creds.json"
        creds_path.write_text(json.dumps({
            "target_url": base,
            "scope_rules": {"allowed_methods": ["GET"]},
            "discovery": ["/"],
            "test_accounts": [
                {"alias": "member-a", "work_email": "ma@t", "password": "pw", "tenant": "t-north", "role": "member"},
                {"alias": "member-b", "work_email": "mb@t", "password": "pw", "tenant": "t-north", "role": "member"},
                {"alias": "member-c", "work_email": "mc@t", "password": "pw", "tenant": "t-south", "role": "member"},
                {"alias": "admin-a", "work_email": "adm@t", "password": "pw", "tenant": "t-north", "role": "platform_admin"},
            ],
        }), encoding="utf-8")
        _, manifest = ext.run_external_target(
            credentials_file=creds_path,
            provider_config=cfg_path,
            output_dir=tmp_path / "out",
            login_path="/login",
            session_check_path="/api/session",
            execute=True,
        )
        confirmed = json.loads(Path(manifest["findings_artifact"]).read_text(encoding="utf-8"))
        probable = json.loads(Path(manifest["probable_findings_artifact"]).read_text(encoding="utf-8"))
        assert any(r["oracle"] == "unauthenticated_api_access" and "/api/v1/telemetry/overview" in r["target"] for r in confirmed)
        assert any(r["oracle"] == "cross_tenant_isolation" and f"/documents/{doc_a}" in r["target"] for r in confirmed)
        assert any(f"/documents/{doc_a}" in r["target"] for r in probable)
        # /reports plain HTML nav page must NOT produce noisy PROBABLE
        assert not any(r["target"].endswith("/reports") for r in [*confirmed, *probable])
    finally:
        llm_srv.shutdown()
        llm_srv.server_close()
        srv.shutdown()
        srv.server_close()


