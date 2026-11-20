"""Tests for lab-agnostic multi-receipt evidence selection, specificity scoring, and finding deduplication."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import (  # noqa: E402
    ToolDispatcher,
    canonicalize_and_deduplicate_findings,
    score_evidence_value,
    select_primary_proof,
)


class _MultiReceiptHandler(BaseHTTPRequestHandler):
    """Minimal generic HTTP handler for multi-receipt differential oracle verification."""

    def log_message(self, *_args: object) -> None:
        pass

    def _send(self, status: int, payload: bytes, ctype: str = "application/json", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        auth = self.headers.get("Authorization", "")
        if parsed.path == "/api/v1/projects/proj-10":
            self._send(
                200,
                json.dumps({
                    "id": "proj-10",
                    "code": "PRJ-10",
                    "owner": "owner-gamma",
                    "tenant": "gamma",
                    "status": "active",
                }).encode(),
            )
            return
        if parsed.path == "/api/v1/projects/proj-20":
            self._send(
                200,
                json.dumps({
                    "id": "proj-20",
                    "code": "PRJ-20",
                    "owner": "owner-gamma",
                    "tenant": "gamma",
                    "secret": "sec_a5e2dfbe613db66340a5",
                }).encode(),
            )
            return
        if parsed.path == "/api/v1/projects/own":
            if not auth:
                self._send(401, b'{"error":"unauthorized"}')
                return
            self._send(200, json.dumps({"id": "own", "code": "PRJ-01", "status": "active"}).encode())
            return
        if parsed.path == "/api/v1/reports/1001":
            self._send(
                200,
                json.dumps({
                    "id": "1001",
                    "code": "RPT-1001",
                    "title": "Standard Report",
                    "app_hash": "0123456789abcdef",
                }).encode(),
            )
            return
        if parsed.path == "/api/v1/reports/1002":
            self._send(
                200,
                json.dumps({
                    "id": "1002",
                    "code": "RPT-1002",
                    "title": "Standard Report",
                    "app_hash": "0123456789abcdef",
                    "audit_hash": "f7c8e9a1b2d304569871",
                }).encode(),
            )
            return
        if parsed.path == "/api/v1/reports/own":
            self._send(
                200,
                json.dumps({
                    "id": "own",
                    "code": "RPT-0001",
                    "title": "Own Report",
                    "app_hash": "0123456789abcdef",
                }).encode(),
            )
            return
        if parsed.path == "/search":
            q = parse_qs(parsed.query).get("q", [""])[0]
            body = f"<html><body>Results: {q} <span data-id='550e8400-e29b-41d4-a716-446655440000'>ok</span></body></html>"
            self._send(200, body.encode(), ctype="text/html; charset=utf-8")
            return
        if parsed.path == "/redirect":
            dest = parse_qs(parsed.query).get("next", ["/"])[0]
            self._send(302, b"", ctype="text/plain", headers={"Location": dest})
            return
        self._send(404, b'{"error":"not_found"}')


@pytest.fixture()
def mock_base_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MultiReceiptHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


def _build_env(tmp_path: Path, base_url: str, *, with_oracle: bool = False):
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "user-alpha", "role": "member", "tenant": "alpha", "auth_header": "Bearer alpha-tok"},
        {"alias": "user-beta", "role": "member", "tenant": "beta", "auth_header": "Bearer beta-tok"},
        {"alias": "viewer-1", "role": "viewer", "tenant": "alpha", "auth_header": "Bearer viewer-tok"},
        {"alias": "admin-1", "role": "admin", "tenant": "alpha", "auth_header": "Bearer admin-tok"},
        {"alias": "owner-gamma", "role": "member", "tenant": "gamma", "auth_header": "Bearer gamma-tok"},
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "HEAD", "POST"),
        max_requests=50,
    )
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential") if with_oracle else None
    dispatcher = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path, oracle=oracle)
    return store, actors, client, dispatcher


def test_score_evidence_value_specificity_levels() -> None:
    assert score_evidence_value("") == 0
    assert score_evidence_value("200") == 0
    assert score_evidence_value("2026-11-20T12:06:36Z") < 20
    assert score_evidence_value("PRJ-10") < 40
    assert score_evidence_value("export_status") < 40
    assert score_evidence_value("quarterly-report-2026") < 40

    assert score_evidence_value("<svg/onload=1>") >= 90
    assert score_evidence_value("https://external.example/callback") >= 85
    assert score_evidence_value("' OR 1=1--") >= 80
    assert score_evidence_value("sec_a5e2dfbe613db66340a5") >= 80
    assert score_evidence_value("f7c8e9a1b2d304569871") >= 80
    assert score_evidence_value("vault_9xK2mP8qR4vW7zN3") >= 75
    assert score_evidence_value("payroll-override", key_name="private_note") >= 60


def test_multi_receipt_explicit_evidence_promotes_matching_receipt_and_passes_oracle(tmp_path: Path, mock_base_url: str) -> None:
    store, _, client, dispatcher = _build_env(tmp_path, mock_base_url, with_oracle=True)
    try:
        r1 = client.request(method="GET", url="/api/v1/projects/proj-10", actor="user-alpha")
        r2 = client.request(method="GET", url="/api/v1/projects/proj-20", actor="user-beta")
        ctrl = client.request(method="GET", url="/api/v1/projects/own", actor="anon")

        res = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Cross-tenant project access",
            "class_type": "tenant_isolation",
            "method": "GET",
            "url": "/api/v1/projects/proj-10",
            "actor_alias": "user-alpha",
            "proof_receipt_ids": [r1["receipt_id"], r2["receipt_id"]],
            "control_receipt_ids": [ctrl["receipt_id"]],
            "evidence_value": "sec_a5e2dfbe613db66340a5",
            "summary": "Cross-tenant read exposes project secret",
        }))
        assert res["accepted"] is True
        assert res["primary_actor"] == "user-beta"

        finding = dispatcher.findings[-1]
        assert finding["actor"] == "user-beta"
        assert finding["actor_alias"] == "user-beta"
        assert finding["path"] == "/api/v1/projects/proj-20"
        assert finding["url"].endswith("/api/v1/projects/proj-20")
        assert finding["observed_status"] == 200
        assert finding["evidence_value"] == "sec_a5e2dfbe613db66340a5"
        assert finding["marker"] == "sec_a5e2dfbe613db66340a5"
        assert finding["proof_receipt_ids"] == [r1["receipt_id"], r2["receipt_id"]]
        assert len(finding["evidence_excerpts"]) == 2
        assert finding["supporting_actors"] == ["user-beta", "user-alpha"]
    finally:
        client.close()


def test_multi_receipt_generic_evidence_promotes_unique_secret_and_ignores_control_tokens(tmp_path: Path, mock_base_url: str) -> None:
    store, _, client, dispatcher = _build_env(tmp_path, mock_base_url, with_oracle=True)
    try:
        r1 = client.request(method="GET", url="/api/v1/reports/1001", actor="user-alpha")
        r2 = client.request(method="GET", url="/api/v1/reports/1002", actor="user-beta")
        ctrl = client.request(method="GET", url="/api/v1/reports/own", actor="user-alpha")

        # Agent passes generic short code from receipt 0; app_hash is shared with control so must be ignored.
        res = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Cross-tenant report leak",
            "class_type": "tenant_isolation",
            "method": "GET",
            "url": "/api/v1/reports/1001",
            "actor_alias": "user-alpha",
            "proof_receipt_ids": [r1["receipt_id"], r2["receipt_id"]],
            "control_receipt_ids": [ctrl["receipt_id"]],
            "evidence_value": "RPT-1001",
            "summary": "Unauthorized cross-tenant report access",
        }))
        assert res["accepted"] is True
        assert res["primary_actor"] == "user-beta"

        finding = dispatcher.findings[-1]
        assert finding["actor"] == "user-beta"
        assert finding["actor_alias"] == "user-beta"
        assert finding["path"] == "/api/v1/reports/1002"
        assert finding["observed_status"] == 200
        assert finding["evidence_value"] == "f7c8e9a1b2d304569871"
        assert finding["marker"] == "f7c8e9a1b2d304569871"
        assert finding["proof_receipt_ids"] == [r1["receipt_id"], r2["receipt_id"]]
        assert len(finding["evidence_excerpts"]) == 2
        assert finding["supporting_actors"] == ["user-beta", "user-alpha"]
    finally:
        client.close()


def test_multi_receipt_empty_evidence_promotes_sensitive_field_while_single_empty_rejects(tmp_path: Path, mock_base_url: str) -> None:
    store, _, client, dispatcher = _build_env(tmp_path, mock_base_url)
    try:
        r1 = store.record(
            actor="user-alpha",
            method="GET",
            url=f"{mock_base_url}/api/v1/notes/1",
            path="/api/v1/notes/1",
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            raw_response_bytes=b'{"code":"N-1","status":"ok"}',
            response_text='{"code":"N-1","status":"ok"}',
        )
        r2 = store.record(
            actor="user-beta",
            method="GET",
            url=f"{mock_base_url}/api/v1/notes/2",
            path="/api/v1/notes/2",
            status=201,
            elapsed_ms=2.0,
            content_type="application/json",
            raw_response_bytes=b'{"code":"N-2","private_note":"executive-payroll-override"}',
            response_text='{"code":"N-2","private_note":"executive-payroll-override"}',
        )
        ctrl = store.record(
            actor="anon",
            method="GET",
            url=f"{mock_base_url}/api/v1/notes/1",
            path="/api/v1/notes/1",
            status=401,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"error":"unauthorized"}',
            response_text='{"error":"unauthorized"}',
        )

        # Single-receipt empty evidence_value must still be rejected.
        rej_single = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Single empty",
            "class_type": "bola",
            "method": "GET",
            "url": "/api/v1/notes/1",
            "actor_alias": "user-alpha",
            "proof_receipt_ids": [r1["receipt_id"]],
            "control_receipt_ids": [ctrl["receipt_id"]],
            "evidence_value": "",
            "summary": "missing evidence",
        }))
        assert rej_single["rejected"] is True

        # Multi-receipt empty evidence_value promotes the sensitive JSON field and its receipt.
        acc_multi = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Multi empty promoted",
            "class_type": "bola",
            "method": "GET",
            "url": "/api/v1/notes/1",
            "actor_alias": "user-alpha",
            "proof_receipt_ids": [r1["receipt_id"], r2["receipt_id"]],
            "control_receipt_ids": [ctrl["receipt_id"]],
            "evidence_value": "",
            "summary": "cross-user note access",
        }))
        assert acc_multi["accepted"] is True
        finding = dispatcher.findings[-1]
        assert finding["evidence_value"] == "executive-payroll-override"
        assert finding["marker"] == "executive-payroll-override"
        assert finding["actor"] == "user-beta"
        assert finding["observed_status"] == 201
        assert finding["path"] == "/api/v1/notes/2"
        assert finding["supporting_actors"] == ["user-beta", "user-alpha"]
    finally:
        client.close()


def test_never_downgrades_xss_redirect_sqli_high_entropy_or_single_receipt(tmp_path: Path, mock_base_url: str) -> None:
    store, _, client, dispatcher = _build_env(tmp_path, mock_base_url, with_oracle=True)
    try:
        # 1. Reflected XSS payload preserved even when body has a UUID and multiple proof receipts exist.
        x_ctrl = client.request(method="GET", url="/search?q=benign", actor="anon")
        x_p1 = client.request(method="GET", url="/search?q=<svg/onload=1>", actor="anon")
        x_p2 = client.request(method="GET", url="/search?q=<svg/onload=1>", actor="user-alpha")
        xss_res = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Reflected XSS",
            "class_type": "reflected_xss",
            "method": "GET",
            "url": "/search?q=<svg/onload=1>",
            "actor_alias": "anon",
            "proof_receipt_ids": [x_p1["receipt_id"], x_p2["receipt_id"]],
            "control_receipt_ids": [x_ctrl["receipt_id"]],
            "evidence_value": "<svg/onload=1>",
            "summary": "Reflected SVG payload in HTML search output",
        }))
        assert xss_res["accepted"] is True
        assert dispatcher.findings[-1]["evidence_value"] == "<svg/onload=1>"

        # 2. Open redirect URL preserved.
        r_ctrl = client.request(method="GET", url="/redirect?next=/home", actor="anon")
        r_p1 = client.request(method="GET", url="/redirect?next=https://external.example/callback", actor="anon")
        r_p2 = client.request(method="GET", url="/redirect?next=https://external.example/callback", actor="user-alpha")
        redir_res = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Open redirect",
            "class_type": "open_redirect",
            "method": "GET",
            "url": "/redirect?next=https://external.example/callback",
            "actor_alias": "anon",
            "proof_receipt_ids": [r_p1["receipt_id"], r_p2["receipt_id"]],
            "control_receipt_ids": [r_ctrl["receipt_id"]],
            "evidence_value": "https://external.example/callback",
            "summary": "External redirect via next parameter",
        }))
        assert redir_res["accepted"] is True
        assert dispatcher.findings[-1]["evidence_value"] == "https://external.example/callback"

        # 3. Already-unique high-entropy token provided by agent is never replaced by another receipt's field.
        t1 = store.record(
            actor="user-alpha",
            method="GET",
            url=f"{mock_base_url}/api/v1/vault/1",
            path="/api/v1/vault/1",
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            raw_response_bytes=b'{"vault_key":"vault_9xK2mP8qR4vW7zN3"}',
            response_text='{"vault_key":"vault_9xK2mP8qR4vW7zN3"}',
        )
        t2 = store.record(
            actor="user-beta",
            method="GET",
            url=f"{mock_base_url}/api/v1/vault/2",
            path="/api/v1/vault/2",
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            raw_response_bytes=b'{"secret":"other_0a1b2c3d4e5f6a7b8c9d"}',
            response_text='{"secret":"other_0a1b2c3d4e5f6a7b8c9d"}',
        )
        t_ctrl = store.record(
            actor="anon",
            method="GET",
            url=f"{mock_base_url}/api/v1/vault/1",
            path="/api/v1/vault/1",
            status=401,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"error":"unauthorized"}',
            response_text='{"error":"unauthorized"}',
        )
        # Switch off oracle for synthetic non-HTTP routes
        dispatcher.oracle = None
        vault_res = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Vault read",
            "class_type": "bola",
            "method": "GET",
            "url": "/api/v1/vault/1",
            "actor_alias": "user-alpha",
            "proof_receipt_ids": [t1["receipt_id"], t2["receipt_id"]],
            "control_receipt_ids": [t_ctrl["receipt_id"]],
            "evidence_value": "vault_9xK2mP8qR4vW7zN3",
            "summary": "Exposed vault key",
        }))
        assert vault_res["accepted"] is True
        assert dispatcher.findings[-1]["evidence_value"] == "vault_9xK2mP8qR4vW7zN3"
        assert dispatcher.findings[-1]["actor"] == "user-alpha"

        # 4. Single-receipt generic evidence_value preserved as-is.
        s1 = store.record(
            actor="user-alpha",
            method="GET",
            url=f"{mock_base_url}/api/v1/single/1",
            path="/api/v1/single/1",
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            raw_response_bytes=b'{"export_status":"ready","secret":"sec_1122334455667788"}',
            response_text='{"export_status":"ready","secret":"sec_1122334455667788"}',
        )
        single_res = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Single receipt export",
            "class_type": "bfla",
            "method": "GET",
            "url": "/api/v1/single/1",
            "actor_alias": "user-alpha",
            "proof_receipt_ids": [s1["receipt_id"]],
            "control_receipt_ids": [t_ctrl["receipt_id"]],
            "evidence_value": "export_status",
            "summary": "Non-admin accesses export",
        }))
        assert single_res["accepted"] is True
        assert dispatcher.findings[-1]["evidence_value"] == "export_status"
    finally:
        client.close()


def test_bfla_keeps_non_admin_over_admin_even_with_admin_secret(tmp_path: Path, mock_base_url: str) -> None:
    store, actors, client, dispatcher = _build_env(tmp_path, mock_base_url)
    try:
        r_admin = store.record(
            actor="admin-1",
            method="GET",
            url=f"{mock_base_url}/api/v1/admin/export",
            path="/api/v1/admin/export",
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            raw_response_bytes=b'{"code":"EXP-1","secret":"sec_9988776655443322"}',
            response_text='{"code":"EXP-1","secret":"sec_9988776655443322"}',
        )
        r_viewer = store.record(
            actor="viewer-1",
            method="GET",
            url=f"{mock_base_url}/api/v1/admin/export",
            path="/api/v1/admin/export",
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            raw_response_bytes=b'{"code":"EXP-1","status":"exported"}',
            response_text='{"code":"EXP-1","status":"exported"}',
        )
        r_ctrl = store.record(
            actor="anon",
            method="GET",
            url=f"{mock_base_url}/api/v1/admin/export",
            path="/api/v1/admin/export",
            status=401,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"error":"unauthorized"}',
            response_text='{"error":"unauthorized"}',
        )
        actor_meta = {r["alias"]: {"alias": r["alias"], "role": r["role"].lower(), "tenant": r["tenant"].lower()} for r in actors.summaries()}
        primary, ordered = select_primary_proof(
            "bfla",
            [r_admin, r_viewer],
            [r_ctrl],
            actor_meta_map=actor_meta,
            receipt_store=store,
            route_template="/api/v1/admin/export",
            evidence_value="EXP-1",
        )
        assert primary["actor"] == "viewer-1"
        assert ordered == ["viewer-1", "admin-1"]

        res = json.loads(dispatcher.dispatch("record_finding", {
            "title": "BFLA admin export",
            "class_type": "bfla",
            "method": "GET",
            "url": "/api/v1/admin/export",
            "actor_alias": "admin-1",
            "proof_receipt_ids": [r_admin["receipt_id"], r_viewer["receipt_id"]],
            "control_receipt_ids": [r_ctrl["receipt_id"]],
            "evidence_value": "EXP-1",
            "summary": "Viewer accesses admin export",
        }))
        assert res["accepted"] is True
        assert res["primary_actor"] == "viewer-1"
        assert dispatcher.findings[-1]["evidence_value"] == "EXP-1"
    finally:
        client.close()


def test_canonicalize_and_deduplicate_promotes_stronger_evidence_without_store() -> None:
    actor_meta = {
        "user-alpha": {"alias": "user-alpha", "role": "member", "tenant": "alpha"},
        "user-beta": {"alias": "user-beta", "role": "member", "tenant": "beta"},
    }
    findings = [
        {
            "title": "Cross-tenant item read (weak)",
            "class_type": "tenant_isolation",
            "method": "GET",
            "url": "/api/v1/items/101",
            "path": "/api/v1/items/101",
            "actor": "user-alpha",
            "actor_alias": "user-alpha",
            "observed_status": 200,
            "evidence_value": "ITM-101",
            "marker": "ITM-101",
            "evidence": '{"code":"ITM-101"}',
            "proof_receipt_ids": ["req-0001"],
            "control_receipt_ids": ["req-0010"],
            "supporting_actors": ["user-alpha"],
            "evidence_excerpts": [{"receipt_id": "req-0001", "actor": "user-alpha", "excerpt": "ITM-101"}],
        },
        {
            "title": "Cross-tenant item read (strong)",
            "class_type": "tenant_isolation",
            "method": "GET",
            "url": "/api/v1/items/202",
            "path": "/api/v1/items/202",
            "actor": "user-beta",
            "actor_alias": "user-beta",
            "observed_status": 201,
            "evidence_value": "tok_7f8a9b0c1d2e3f4a5b6c",
            "marker": "tok_7f8a9b0c1d2e3f4a5b6c",
            "evidence": '{"secret":"tok_7f8a9b0c1d2e3f4a5b6c"}',
            "proof_receipt_ids": ["req-0002"],
            "control_receipt_ids": ["req-0011"],
            "supporting_actors": ["user-beta"],
            "evidence_excerpts": [{"receipt_id": "req-0002", "actor": "user-beta", "excerpt": "tok_7f8a9b0c1d2e3f4a5b6c"}],
        },
    ]
    merged = canonicalize_and_deduplicate_findings(findings, actor_meta_map=actor_meta, receipt_store=None)
    assert len(merged) == 1
    m = merged[0]
    assert m["evidence_value"] == "tok_7f8a9b0c1d2e3f4a5b6c"
    assert m["marker"] == "tok_7f8a9b0c1d2e3f4a5b6c"
    assert m["actor"] == "user-beta"
    assert m["actor_alias"] == "user-beta"
    assert m["url"] == "/api/v1/items/202"
    assert m["path"] == "/api/v1/items/202"
    assert m["observed_status"] == 201
    assert m["proof_receipt_ids"] == ["req-0001", "req-0002"]
    assert m["control_receipt_ids"] == ["req-0010", "req-0011"]
    assert m["supporting_actors"] == ["user-beta", "user-alpha"]
    assert len(m["evidence_excerpts"]) == 2


def test_canonicalize_and_deduplicate_promotes_stronger_receipt_secret_with_store(tmp_path: Path, mock_base_url: str) -> None:
    store, actors, client, dispatcher = _build_env(tmp_path, mock_base_url)
    try:
        r1 = store.record(
            actor="user-alpha",
            method="GET",
            url=f"{mock_base_url}/api/v1/items/101",
            path="/api/v1/items/101",
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            raw_response_bytes=b'{"code":"ITM-101","title":"Generic"}',
            response_text='{"code":"ITM-101","title":"Generic"}',
        )
        r2 = store.record(
            actor="user-beta",
            method="GET",
            url=f"{mock_base_url}/api/v1/items/202",
            path="/api/v1/items/202",
            status=200,
            elapsed_ms=2.0,
            content_type="application/json",
            raw_response_bytes=b'{"code":"ITM-202","api_key":"ak_live_4d5e6f7a8b9c0d1e2f3a"}',
            response_text='{"code":"ITM-202","api_key":"ak_live_4d5e6f7a8b9c0d1e2f3a"}',
        )
        ctrl = store.record(
            actor="anon",
            method="GET",
            url=f"{mock_base_url}/api/v1/items/101",
            path="/api/v1/items/101",
            status=401,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"error":"unauthorized"}',
            response_text='{"error":"unauthorized"}',
        )

        findings = [
            {
                "title": "Read 1",
                "class_type": "tenant_isolation",
                "method": "GET",
                "url": f"{mock_base_url}/api/v1/items/101",
                "path": "/api/v1/items/101",
                "actor": "user-alpha",
                "actor_alias": "user-alpha",
                "observed_status": 200,
                "evidence_value": "ITM-101",
                "marker": "ITM-101",
                "proof_receipt_ids": [r1["receipt_id"]],
                "control_receipt_ids": [ctrl["receipt_id"]],
                "supporting_actors": ["user-alpha"],
            },
            {
                "title": "Read 2",
                "class_type": "tenant_isolation",
                "method": "GET",
                "url": f"{mock_base_url}/api/v1/items/202",
                "path": "/api/v1/items/202",
                "actor": "user-beta",
                "actor_alias": "user-beta",
                "observed_status": 200,
                "evidence_value": "ITM-202",
                "marker": "ITM-202",
                "proof_receipt_ids": [r2["receipt_id"]],
                "control_receipt_ids": [ctrl["receipt_id"]],
                "supporting_actors": ["user-beta"],
            },
        ]
        actor_meta = {r["alias"]: {"alias": r["alias"], "role": r["role"].lower(), "tenant": r["tenant"].lower()} for r in actors.summaries()}
        merged = canonicalize_and_deduplicate_findings(findings, actor_meta_map=actor_meta, receipt_store=store)
        assert len(merged) == 1
        m = merged[0]
        assert m["evidence_value"] == "ak_live_4d5e6f7a8b9c0d1e2f3a"
        assert m["marker"] == "ak_live_4d5e6f7a8b9c0d1e2f3a"
        assert m["actor"] == "user-beta"
        assert m["actor_alias"] == "user-beta"
        assert m["path"] == "/api/v1/items/202"
        assert m["proof_receipt_ids"] == [r1["receipt_id"], r2["receipt_id"]]
        assert m["supporting_actors"] == ["user-beta", "user-alpha"]
        assert len(m["evidence_excerpts"]) == 2

        # Also verify sequential record_finding calls merge & promote the stronger finding.
        res1 = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Seq read 1",
            "class_type": "tenant_isolation",
            "method": "GET",
            "url": "/api/v1/items/101",
            "actor_alias": "user-alpha",
            "proof_receipt_ids": [r1["receipt_id"]],
            "control_receipt_ids": [ctrl["receipt_id"]],
            "evidence_value": "ITM-101",
            "summary": "First weak report",
        }))
        assert res1["accepted"] is True

        res2 = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Seq read 2",
            "class_type": "tenant_isolation",
            "method": "GET",
            "url": "/api/v1/items/202",
            "actor_alias": "user-beta",
            "proof_receipt_ids": [r2["receipt_id"]],
            "control_receipt_ids": [ctrl["receipt_id"]],
            "evidence_value": "ak_live_4d5e6f7a8b9c0d1e2f3a",
            "summary": "Second strong report",
        }))
        assert res2["accepted"] is True
        assert res2["merged"] is True
        assert res2["primary_actor"] == "user-beta"
        saved = dispatcher.findings[0]
        assert saved["evidence_value"] == "ak_live_4d5e6f7a8b9c0d1e2f3a"
        assert saved["marker"] == "ak_live_4d5e6f7a8b9c0d1e2f3a"
        assert saved["path"] == "/api/v1/items/202"
        assert saved["proof_receipt_ids"] == [r1["receipt_id"], r2["receipt_id"]]
        assert saved["supporting_actors"] == ["user-beta", "user-alpha"]
    finally:
        client.close()
