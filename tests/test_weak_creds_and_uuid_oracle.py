"""Tests for Faz 3A: weak_credentials verification, dynamic-UUID JSON masking, and scoped HTML-unescape matching."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import parse_qs
import uuid

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_evidence import normalize_vuln_class  # noqa: E402
from agentic_http import AgenticHTTPClient  # noqa: E402
from agentic_oracle import (  # noqa: E402
    DifferentialOracle,
    _collect_ephemeral_json_values,
    _mask_for_ephemeral_replay_comparison,
    _receipt_contains_evidence,
    mask_dynamic_fields,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_report import _CLASS_METADATA, render_markdown_report, render_sarif_report  # noqa: E402


class _Faz3AHandler(BaseHTTPRequestHandler):
    """Thread-safe loopback HTTP handler for Faz 3A oracle integration tests."""

    server_version = "Faz3ATest/1.0"
    counter = 0
    lock = threading.Lock()
    login_mode = "normal"  # normal | accept_all | fail_replay | soft_200_fail

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    @classmethod
    def next_seq(cls) -> int:
        with cls.lock:
            cls.counter += 1
            return cls.counter

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return ""
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def _send(
        self,
        status: int,
        body: str,
        *,
        content_type: str = "application/json",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        path, _, query = self.path.partition("?")
        if path == "/search":
            # Dynamically HTML-escape query param like a real app so reflected_xss MUST be REFUTED in Stage 3.
            q_val = parse_qs(query, keep_blank_values=True).get("q", [""])[0]
            escaped = html.escape(q_val, quote=True)
            self._send(
                200,
                f"<html><body><p>Results for {escaped}</p></body></html>",
                content_type="text/html; charset=utf-8",
            )
            return
        if path == "/posts":
            self._send(
                200,
                "<html><body><div class='post'>&lt;svg/onload=1&gt;</div></body></html>",
                content_type="text/html; charset=utf-8",
            )
            return
        if path == "/debug":
            if "baseline_value" in query:
                self._send(200, "<html><body><pre>Query OK</pre></body></html>", content_type="text/html")
            else:
                self._send(
                    200,
                    (
                        "<html><body><pre>SQL trace: ORDER BY &#39;x&#39; &gt; "
                        "&quot;y&quot; &amp; &lt;z&gt;</pre></body></html>"
                    ),
                    content_type="text/html; charset=utf-8",
                )
            return
        self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self) -> None:  # noqa: N802
        path, _, _ = self.path.partition("?")
        raw_body = self._read_body()
        try:
            payload = json.loads(raw_body) if raw_body.strip().startswith("{") else {}
        except ValueError:
            payload = {}

        if path == "/api/prompt":
            if payload.get("bad"):
                self._send(400, json.dumps({"error": "invalid workflow"}))
                return
            seq = self.next_seq()
            self._send(
                200,
                json.dumps({
                    "prompt_id": str(uuid.uuid4()),
                    "number": seq,
                    "node_errors": {},
                }),
            )
            return

        if path == "/api/wallet":
            seq = self.next_seq()
            bal = 100 if payload.get("control") else 50
            self._send(
                200,
                json.dumps({
                    "prompt_id": str(uuid.uuid4()),
                    "number": seq,
                    "balance": bal,
                }),
            )
            return

        if path == "/api/login":
            user = str(payload.get("username") or "")
            secret = str(payload.get("passcode") or payload.get("password") or "")
            seq = self.next_seq()
            if self.login_mode == "accept_all":
                self._send(
                    200,
                    json.dumps({"ok": True, "user": user or "guest", "token": f"tok_{uuid.uuid4().hex}"}),
                    extra_headers={"Set-Cookie": f"sid=sess_{seq}; Path=/; HttpOnly"},
                )
                return
            if self.login_mode == "fail_replay" and seq > 1:
                self._send(401, json.dumps({"ok": False, "error": "invalid credentials"}))
                return
            if user == "admin" and secret == "admin":
                self._send(
                    200,
                    json.dumps({"ok": True, "user": "admin", "token": f"tok_{uuid.uuid4().hex}"}),
                    extra_headers={"Set-Cookie": f"sid=sess_{seq}; Path=/; HttpOnly"},
                )
                return
            if self.login_mode == "soft_200_fail":
                self._send(200, json.dumps({"ok": False, "error": "invalid credentials"}))
                return
            self._send(401, json.dumps({"ok": False, "error": "invalid credentials"}))
            return

        if path == "/form-login":
            user = str(payload.get("username") or "")
            secret = str(payload.get("passcode") or "")
            seq = self.next_seq()
            if user == "admin" and secret == "admin" and not (self.login_mode == "fail_replay" and seq > 1):
                self._send(
                    302,
                    "",
                    content_type="text/plain",
                    extra_headers={
                        "Location": "/dashboard",
                        "Set-Cookie": f"sid=form_{seq}; Path=/; HttpOnly",
                    },
                )
                return
            self._send(
                302,
                "",
                content_type="text/plain",
                extra_headers={"Location": "/login?err=1"},
            )
            return

        if path == "/posts":
            self._send(201, json.dumps({"status": "created"}))
            return

        self._send(404, json.dumps({"error": "not found"}))


@pytest.fixture()
def loopback_server():
    _Faz3AHandler.counter = 0
    _Faz3AHandler.login_mode = "normal"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Faz3AHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        srv.server_close()


def _make_client_and_oracle(base_url: str, tmp_path: Path, *, max_requests: int = 40):
    receipts = ReceiptStore(tmp_path / "receipts")
    http = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=receipts,
        allowed_methods=("GET", "HEAD", "POST"),
        max_requests=max_requests,
    )
    oracle = DifferentialOracle(http_client=http, receipt_store=receipts, mode="differential")
    return receipts, http, oracle


# ---------------------------------------------------------------------------
# 1. Canonical class & aliases (agentic_evidence.py)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_name",
    [
        "weak_credentials",
        "default_credentials",
        "default_creds",
        "default_password",
        "weak_password",
        "weak_creds",
        "Default-Credentials",
        "Weak Creds",
    ],
)
def test_weak_credentials_class_normalization_and_aliases(raw_name: str) -> None:
    assert normalize_vuln_class(raw_name) == "weak_credentials"


# ---------------------------------------------------------------------------
# 2. Report metadata & Markdown / SARIF rendering (agentic_report.py)
# ---------------------------------------------------------------------------


def test_weak_credentials_report_metadata_and_rendering() -> None:
    meta = _CLASS_METADATA["weak_credentials"]
    assert meta["name"] == "Weak / Default Credentials"
    assert "A07:2021" in meta["owasp"]
    assert meta["cwe"] == "CWE-521"

    artifacts: dict[str, Any] = {
        "run_id": "run-weak-creds",
        "target_url": "http://127.0.0.1:8080",
        "findings": [
            {
                "finding_id": "F-001",
                "class_type": "weak_credentials",
                "severity": "high",
                "confidence": "high",
                "status": "VERIFIED",
                "title": "Default admin credentials accepted at /api/login",
                "summary": "Endpoint accepted admin/admin and issued an authenticated session.",
                "method": "POST",
                "endpoint": "/api/login",
                "url": "http://127.0.0.1:8080/api/login",
                "evidence_excerpt": '{"ok":true,"user":"admin"}',
                "reproduction": "POST /api/login",
            }
        ],
        "not_tested": [],
    }

    md = render_markdown_report(artifacts)
    assert "Weak / Default Credentials" in md
    assert "CWE-521" in md
    assert "A07:2021" in md
    assert "**Remediation:**" in md

    sarif = render_sarif_report(artifacts)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "weak_credentials"
    assert rules[0]["name"] == "Weak / Default Credentials"
    assert rules[0]["properties"]["cwe"] == "CWE-521"
    assert "A07:2021" in rules[0]["properties"]["owasp"]
    assert "remediation" in rules[0]["properties"]


# ---------------------------------------------------------------------------
# 3. Dynamic-UUID JSON masking & queue/financial key separation
# ---------------------------------------------------------------------------


def test_mask_dynamic_fields_masks_json_uuids_and_preserves_values() -> None:
    preserved_uuid = "550e8400-e29b-41d4-a716-446655440000"
    dynamic_uuid = "660e8400-e29b-41d4-a716-446655440001"
    body = json.dumps({
        "owner_id": preserved_uuid,
        "nested": {"trace": dynamic_uuid, "items": [dynamic_uuid]},
        "msg": f"created {dynamic_uuid}",
    })

    masked_all = mask_dynamic_fields(body)
    assert preserved_uuid not in masked_all
    assert dynamic_uuid not in masked_all
    assert masked_all.count("<UUID>") == 4

    masked_preserved = mask_dynamic_fields(body, preserve_values=(preserved_uuid,))
    assert preserved_uuid in masked_preserved
    assert dynamic_uuid not in masked_preserved
    assert masked_preserved.count("<UUID>") == 3


def test_mask_dynamic_fields_and_replay_masking_queue_vs_financial_keys() -> None:
    job_payload_a = json.dumps({
        "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
        "queue_id": "q-101",
        "session_id": "sess-aaa",
        "correlation_id": "corr-aaa",
        "receipt_id": "rcpt-aaa",
        "number": 1,
        "queue_number": 10,
        "seq": 100,
        "balance": 100,
        "amount": 25,
        "price": 9.99,
        "total": 500,
        "count": 3,
        "credits": 42,
        "quota": 1000,
    })
    job_payload_b = json.dumps({
        "prompt_id": "660e8400-e29b-41d4-a716-446655440001",
        "queue_id": "q-202",
        "session_id": "sess-bbb",
        "correlation_id": "corr-bbb",
        "receipt_id": "rcpt-bbb",
        "number": 2,
        "queue_number": 11,
        "seq": 101,
        "balance": 100,
        "amount": 25,
        "price": 9.99,
        "total": 500,
        "count": 3,
        "credits": 42,
        "quota": 1000,
    })

    # mask_dynamic_fields masks UUIDs and sibling queue seq keys when job/prompt ID key is present,
    # while leaving financial/quota keys completely untouched.
    m_a = mask_dynamic_fields(job_payload_a)
    parsed_m_a = json.loads(m_a)
    assert parsed_m_a["prompt_id"] == "<UUID>"
    assert parsed_m_a["number"] == "<MASKED>"
    assert parsed_m_a["queue_number"] == "<MASKED>"
    assert parsed_m_a["seq"] == "<MASKED>"
    for fin_key, expected in (
        ("balance", 100),
        ("amount", 25),
        ("price", 9.99),
        ("total", 500),
        ("count", 3),
        ("credits", 42),
        ("quota", 1000),
    ):
        assert parsed_m_a[fin_key] == expected

    # Without a job/prompt/task ID sibling, number/queue_number/seq are NOT masked.
    non_job_a = json.dumps({"page": 1, "number": 1, "queue_number": 2, "seq": 3, "balance": 100})
    non_job_b = json.dumps({"page": 1, "number": 2, "queue_number": 2, "seq": 3, "balance": 50})
    assert json.loads(mask_dynamic_fields(non_job_a))["number"] == 1
    assert json.loads(mask_dynamic_fields(non_job_a))["seq"] == 3
    assert mask_dynamic_fields(non_job_a) != mask_dynamic_fields(non_job_b)

    # Replay comparison masks all dynamic queue/session/correlation/receipt IDs + sibling seq,
    # making job_payload_a and job_payload_b equal when financial fields match...
    assert _mask_for_ephemeral_replay_comparison(job_payload_a) == _mask_for_ephemeral_replay_comparison(job_payload_b)

    # ...while any financial balance difference is NOT masked!
    job_payload_diff_balance = json.dumps({**json.loads(job_payload_b), "balance": 50})
    assert _mask_for_ephemeral_replay_comparison(job_payload_a) != _mask_for_ephemeral_replay_comparison(
        job_payload_diff_balance
    )
    assert mask_dynamic_fields(job_payload_a) != mask_dynamic_fields(job_payload_diff_balance)

    # _collect_ephemeral_json_values collects the queue/session IDs and sibling seq, never financial keys.
    collected = _collect_ephemeral_json_values(json.loads(job_payload_a))
    for key in ("prompt_id", "queue_id", "session_id", "correlation_id", "receipt_id", "number", "queue_number", "seq"):
        assert (key,) in collected
    for fin_key in ("balance", "amount", "price", "total", "count", "credits", "quota"):
        assert (fin_key,) not in collected

    # Without job ID sibling, _collect_ephemeral_json_values ignores number/queue_number/seq.
    collected_non_job = _collect_ephemeral_json_values(json.loads(non_job_a))
    assert ("number",) not in collected_non_job
    assert ("queue_number",) not in collected_non_job
    assert ("seq",) not in collected_non_job


def test_oracle_loopback_ephemeral_prompt_id_refuted_and_financial_diff_verified(
    loopback_server: str, tmp_path: Path
) -> None:
    _, http, oracle = _make_client_and_oracle(loopback_server, tmp_path)

    ctrl = http.request(method="POST", url="/api/prompt", json_body={"bad": True})
    proof = http.request(method="POST", url="/api/prompt", json_body={"prompt": "hi"})
    prompt_uuid = json.loads(proof["body"])["prompt_id"]

    # Claiming ephemeral rotating prompt_id UUID as evidence must be REFUTED.
    verdict_eph = oracle.verify(
        canonical_class="other",
        primary_proof=proof,
        proof_receipts=[proof],
        control_receipts=[ctrl],
        evidence_value=prompt_uuid,
    )
    assert verdict_eph.verified is False
    assert verdict_eph.verdict == "REFUTED"
    assert verdict_eph.stages["stage3_clean_replay"] == "failed_ephemeral_evidence"

    # Claiming static structural key succeeds.
    verdict_static = oracle.verify(
        canonical_class="other",
        primary_proof=proof,
        proof_receipts=[proof],
        control_receipts=[ctrl],
        evidence_value="node_errors",
    )
    assert verdict_static.verified is True
    assert verdict_static.verdict == "VERIFIED"

    # Financial balance diff (100 vs 50) alongside rotating prompt_id + number must NOT be masked as equivalent.
    wallet_ctrl = http.request(method="POST", url="/api/wallet", json_body={"control": True})
    wallet_proof = http.request(method="POST", url="/api/wallet", json_body={"control": False})
    verdict_wallet = oracle.verify(
        canonical_class="business_logic",
        primary_proof=wallet_proof,
        proof_receipts=[wallet_proof],
        control_receipts=[wallet_ctrl],
        evidence_value="50",
    )
    assert verdict_wallet.verified is True
    assert verdict_wallet.verdict == "VERIFIED"


# ---------------------------------------------------------------------------
# 4. Scoped HTML-entity-unescaped evidence matching (sqli_read/sqli/other ONLY)
# ---------------------------------------------------------------------------


def test_receipt_contains_evidence_html_unescape_scope() -> None:
    sql_trace_html = {
        "content_type": "text/html; charset=utf-8",
        "response_headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": "<pre>SQL trace: &#39;x&#39; &gt; &quot;y&quot; &amp; &lt;z&gt;</pre>",
        "redirect_location": "",
    }
    ev_sql = "'x' > \"y\" & <z>"
    assert _receipt_contains_evidence(sql_trace_html, ev_sql, canonical_class="sqli_read") is True
    assert _receipt_contains_evidence(sql_trace_html, ev_sql, canonical_class="sqli") is True
    assert _receipt_contains_evidence(sql_trace_html, ev_sql, canonical_class="other") is True

    xss_escaped_html = {
        "content_type": "text/html; charset=utf-8",
        "response_headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": "<p>Search: &lt;svg/onload=1&gt;</p>",
        "redirect_location": "",
    }
    assert _receipt_contains_evidence(xss_escaped_html, "<svg/onload=1>", canonical_class="reflected_xss") is False
    assert _receipt_contains_evidence(xss_escaped_html, "<svg/onload=1>", canonical_class="stored_xss") is False

    # Non-HTML content types must not apply HTML unescaping.
    json_escaped = {
        "content_type": "application/json",
        "response_headers": {"Content-Type": "application/json"},
        "body": json.dumps({"msg": "&lt;z&gt;"}),
        "redirect_location": "",
    }
    assert _receipt_contains_evidence(json_escaped, "<z>", canonical_class="sqli_read") is False


def test_oracle_loopback_html_escaped_xss_refuted_and_sqli_read_verified(
    loopback_server: str, tmp_path: Path
) -> None:
    _, http, oracle = _make_client_and_oracle(loopback_server, tmp_path)

    # Reflected XSS with HTML-escaped &lt;svg/onload=1&gt; MUST remain REFUTED.
    xss_proof = http.request(method="GET", url="/search", query={"q": "<svg/onload=1>"})
    verdict_rxss = oracle.verify(
        canonical_class="reflected_xss",
        primary_proof=xss_proof,
        proof_receipts=[xss_proof],
        control_receipts=[],
        evidence_value="<svg/onload=1>",
    )
    assert verdict_rxss.verified is False
    assert verdict_rxss.verdict == "REFUTED"
    assert verdict_rxss.stages["stage3_clean_replay"] == "failed_missing_evidence"

    # Stored XSS with HTML-escaped &lt;svg/onload=1&gt; MUST also remain REFUTED.
    post_write = http.request(method="POST", url="/posts", json_body={"body": "<svg/onload=1>"})
    post_read = http.request(method="GET", url="/posts")
    verdict_sxss = oracle.verify(
        canonical_class="stored_xss",
        primary_proof=post_write,
        proof_receipts=[post_write, post_read],
        control_receipts=[],
        evidence_value="<svg/onload=1>",
    )
    assert verdict_sxss.verified is False
    assert verdict_sxss.verdict == "REFUTED"

    # sqli_read with HTML-escaped trace output MUST be VERIFIED.
    sqli_ctrl = http.request(method="GET", url="/debug", query={"sort": "baseline_value"})
    sqli_proof = http.request(method="GET", url="/debug", query={"sort": "'x' > \"y\" & <z>"})
    verdict_sqli = oracle.verify(
        canonical_class="sqli_read",
        primary_proof=sqli_proof,
        proof_receipts=[sqli_proof],
        control_receipts=[sqli_ctrl],
        evidence_value="'x' > \"y\" & <z>",
    )
    assert verdict_sqli.verified is True
    assert verdict_sqli.verdict == "VERIFIED"


# ---------------------------------------------------------------------------
# 5. weak_credentials end-to-end oracle verification & negative tests
# ---------------------------------------------------------------------------


def test_oracle_weak_credentials_missing_control_refuted(
    loopback_server: str, tmp_path: Path
) -> None:
    _, http, oracle = _make_client_and_oracle(loopback_server, tmp_path)
    proof = http.request(method="POST", url="/api/login", json_body={"username": "admin", "passcode": "admin"})
    verdict = oracle.verify(
        canonical_class="weak_credentials",
        primary_proof=proof,
        proof_receipts=[proof],
        control_receipts=[],
        evidence_value="admin",
    )
    assert verdict.verified is False
    assert verdict.verdict == "REFUTED"
    assert verdict.stages["stage1_control"] == "failed_missing_control"


def test_oracle_loopback_weak_credentials_verified_rotating_token_and_cookie(
    loopback_server: str, tmp_path: Path
) -> None:
    _, http, oracle = _make_client_and_oracle(loopback_server, tmp_path)
    ctrl = http.request(method="POST", url="/api/login", json_body={"username": "admin", "passcode": "wrong"})
    proof = http.request(method="POST", url="/api/login", json_body={"username": "admin", "passcode": "admin"})
    issued_token = json.loads(proof["body"])["token"]

    # Even when the evidence_value is the issued token that rotates on clean replay,
    # clean replay succeeds deterministically via _weak_credentials_replay_matches_evidence.
    verdict = oracle.verify(
        canonical_class="weak_credentials",
        primary_proof=proof,
        proof_receipts=[proof],
        control_receipts=[ctrl],
        evidence_value=issued_token,
    )
    assert verdict.verified is True
    assert verdict.verdict == "VERIFIED"
    assert verdict.stages["stage3_clean_replay"] == "passed"


def test_oracle_loopback_weak_credentials_redirect_login_and_mismatch_refuted(
    loopback_server: str, tmp_path: Path
) -> None:
    _, http, oracle = _make_client_and_oracle(loopback_server, tmp_path)
    ctrl = http.request(method="POST", url="/form-login", json_body={"username": "admin", "passcode": "wrong"})
    proof = http.request(method="POST", url="/form-login", json_body={"username": "admin", "passcode": "admin"})

    verdict = oracle.verify(
        canonical_class="weak_credentials",
        primary_proof=proof,
        proof_receipts=[proof],
        control_receipts=[ctrl],
        evidence_value="/dashboard",
    )
    assert verdict.verified is True
    assert verdict.verdict == "VERIFIED"

    # Negative: if replay later fails and redirects to /login?err=1, Stage 3 must REFUTE.
    _Faz3AHandler.counter = 1
    _Faz3AHandler.login_mode = "fail_replay"
    verdict_fail = oracle.verify(
        canonical_class="weak_credentials",
        primary_proof=proof,
        proof_receipts=[proof],
        control_receipts=[ctrl],
        evidence_value="/dashboard",
    )
    assert verdict_fail.verified is False
    assert verdict_fail.verdict == "REFUTED"
    assert verdict_fail.stages["stage3_clean_replay"] == "failed_login_redirect_mismatch"


@pytest.mark.parametrize("login_mode", ["normal", "soft_200_fail"])
def test_oracle_loopback_weak_credentials_redacted_password_body_verified(
    loopback_server: str, tmp_path: Path, login_mode: str
) -> None:
    _Faz3AHandler.login_mode = login_mode
    _, http, oracle = _make_client_and_oracle(loopback_server, tmp_path)

    # ReceiptStore scrubs JSON "password" to <REDACTED_SECRET>; Stage 3 clean replay
    # sends the scrubbed placeholder and verifies live auth enforcement on rejection.
    ctrl = http.request(method="POST", url="/api/login", json_body={"username": "admin", "password": "wrong"})
    proof = http.request(method="POST", url="/api/login", json_body={"username": "admin", "password": "admin"})
    assert "<REDACTED" in proof["request_body"]

    verdict = oracle.verify(
        canonical_class="weak_credentials",
        primary_proof=proof,
        proof_receipts=[proof],
        control_receipts=[ctrl],
        evidence_value="admin",
    )
    assert verdict.verified is True
    assert verdict.verdict == "VERIFIED"
    assert verdict.stages["stage3_clean_replay"] == "passed_redacted_credential_body"


def test_oracle_loopback_weak_credentials_negative_invalid_creds_also_accepted(
    loopback_server: str, tmp_path: Path
) -> None:
    _Faz3AHandler.login_mode = "accept_all"
    _, http, oracle = _make_client_and_oracle(loopback_server, tmp_path)

    ctrl = http.request(method="POST", url="/api/login", json_body={"username": "admin", "passcode": "wrong"})
    proof = http.request(method="POST", url="/api/login", json_body={"username": "admin", "passcode": "admin"})

    # Same-actor control where invalid creds also succeed (only token/Set-Cookie rotate)
    # must fail Stage 1 with deception_identical_control.
    verdict = oracle.verify(
        canonical_class="weak_credentials",
        primary_proof=proof,
        proof_receipts=[proof],
        control_receipts=[ctrl],
        evidence_value="ok",
    )
    assert verdict.verified is False
    assert verdict.deception_detected is True
    assert verdict.stages["stage1_control"] == "deception_identical_control"

    # Non-same-actor control returning identical masked auth state must fail Stage 2 as REFUTED.
    other_actor_ctrl = {**ctrl, "actor": "reviewer"}
    verdict_stage2 = oracle.verify(
        canonical_class="weak_credentials",
        primary_proof=proof,
        proof_receipts=[proof],
        control_receipts=[other_actor_ctrl],
        evidence_value="ok",
    )
    assert verdict_stage2.verified is False
    assert verdict_stage2.verdict == "REFUTED"
    assert verdict_stage2.stages["stage2_diff"] == "failed_masked_equivalence"

    # And if login succeeds during proof capture but clean replay returns 401 -> REFUTED.
    _Faz3AHandler.login_mode = "normal"
    _Faz3AHandler.counter = 0
    real_ctrl = http.request(method="POST", url="/api/login", json_body={"username": "admin", "passcode": "wrong"})
    real_proof = http.request(method="POST", url="/api/login", json_body={"username": "admin", "passcode": "admin"})
    _Faz3AHandler.counter = 1
    _Faz3AHandler.login_mode = "fail_replay"
    verdict_replay_fail = oracle.verify(
        canonical_class="weak_credentials",
        primary_proof=real_proof,
        proof_receipts=[real_proof],
        control_receipts=[real_ctrl],
        evidence_value="admin",
    )
    assert verdict_replay_fail.verified is False
    assert verdict_replay_fail.verdict == "REFUTED"
    assert verdict_replay_fail.stages["stage3_clean_replay"] == "failed_status_401"
