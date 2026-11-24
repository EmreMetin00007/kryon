"""Tests for Faz 6B: Generalized Fail-Closed Redacted-Credential Login Replay Guard in Stage 3 Oracle."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_oracle import (  # noqa: E402
    DifferentialOracle,
    _can_accept_redacted_credential_body_replay,
    _has_redacted_credential_body,
)
from agentic_receipts import ReceiptStore  # noqa: E402


class _Faz6BHandler(BaseHTTPRequestHandler):
    """Thread-safe loopback HTTP handler for Faz 6B redacted-credential replay tests."""

    server_version = "Faz6BTest/1.0"
    replay_status_override: dict[str, tuple[int, dict[str, Any]]] = {}
    unredacted_calls: dict[str, int] = {}
    lock = threading.Lock()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return ""
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def _send(
        self,
        status: int,
        payload: Any,
        *,
        content_type: str = "application/json",
    ) -> None:
        text = payload if isinstance(payload, str) else json.dumps(payload)
        raw = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        raw_body = self._read_body()
        ctype = (self.headers.get("Content-Type") or "").lower()

        if path in self.replay_status_override:
            ov_status, ov_body = self.replay_status_override[path]
            self._send(ov_status, ov_body)
            return

        if path == "/api/authorize/login":
            try:
                data = json.loads(raw_body) if raw_body.strip().startswith("{") else {}
            except ValueError:
                data = {}
            user = str(data.get("username") or "")
            password = str(data.get("password") or "")
            expires = int(data.get("expires") or 3600)
            if user == "admin" and password == "SuperSecret123":
                self._send(
                    200,
                    {
                        "status": 200,
                        "result": {
                            "user": {"username": "admin", "role": "admin"},
                            "expires": expires,
                            "token": "tok-live-session",
                        },
                    },
                )
                return
            self._send(400, {"status": 400, "code": "illegal_password", "message": "Invalid password"})
            return

        if path == "/api/auth/login-401":
            try:
                data = json.loads(raw_body) if raw_body.strip().startswith("{") else {}
            except ValueError:
                data = {}
            user = str(data.get("username") or "")
            password = str(data.get("password") or "")
            expires = int(data.get("expires") or 3600)
            if user == "admin" and password == "SuperSecret123":
                self._send(200, {"ok": True, "user": "admin", "expires": expires})
                return
            self._send(401, {"error": "invalid credentials"})
            return

        if path == "/login":
            if "application/x-www-form-urlencoded" in ctype or "=" in raw_body:
                parsed = parse_qs(raw_body, keep_blank_values=True)
                user = (parsed.get("username") or [""])[0]
                password = (parsed.get("password") or [""])[0]
                expires = int((parsed.get("expires") or ["3600"])[0])
            else:
                user, password, expires = "", "", 3600
            if user == "admin" and password == "SuperSecret123":
                self._send(200, {"logged_in": True, "user": "admin", "expires": expires})
                return
            self._send(401, {"error": "invalid credentials"})
            return

        if path == "/api/unredacted-login":
            try:
                data = json.loads(raw_body) if raw_body.strip().startswith("{") else {}
            except ValueError:
                data = {}
            with self.lock:
                self.unredacted_calls[path] = self.unredacted_calls.get(path, 0) + 1
                call_num = self.unredacted_calls[path]
            expires = int(data.get("expires") or 3600)
            # First two calls (control + proof) succeed, clean replay returns 401 even though body was unredacted.
            if call_num <= 2:
                self._send(200, {"ok": True, "user": "admin", "expires": expires})
                return
            self._send(401, {"error": "invalid credentials"})
            return

        if path == "/api/notes/create":
            try:
                data = json.loads(raw_body) if raw_body.strip().startswith("{") else {}
            except ValueError:
                data = {}
            note = str(data.get("note") or "")
            if "<REDACTED" in note:
                self._send(400, {"error": "bad_request", "detail": "invalid note content"})
                return
            self._send(200, {"saved": True, "note": note, "role": data.get("role", "member")})
            return

        if path == "/api/authorize/login-identical":
            try:
                data = json.loads(raw_body) if raw_body.strip().startswith("{") else {}
            except ValueError:
                data = {}
            if str(data.get("password") or "") == "SuperSecret123":
                # Ignores client-supplied expires completely -> Stage 1/2 deception/equivalence!
                self._send(200, {"ok": True, "user": "admin", "expires": 3600})
                return
            self._send(400, {"code": "illegal_password", "message": "Invalid password"})
            return

        self._send(404, {"error": "not_found"})


@pytest.fixture()
def loopback_server():
    _Faz6BHandler.replay_status_override = {}
    _Faz6BHandler.unredacted_calls = {}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Faz6BHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        srv.server_close()


def _make_env(
    base_url: str,
    tmp_path: Path,
    *,
    accounts: list[dict[str, Any]] | None = None,
    max_requests: int = 60,
) -> tuple[ReceiptStore, AgenticHTTPClient, DifferentialOracle]:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager(
        accounts
        if accounts is not None
        else [
            {
                "alias": "admin",
                "role": "admin",
                "tenant": "default",
                "password": "SuperSecret123",
            }
        ]
    )
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "HEAD", "POST", "PUT", "PATCH"),
        max_requests=max_requests,
    )
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential")
    return store, client, oracle


# ---------------------------------------------------------------------------
# 1. Unit tests for _has_redacted_credential_body & _can_accept_redacted_credential_body_replay
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("request_body", "expected"),
    [
        ('{"username": "admin", "password": "<REDACTED_SECRET>", "expires": 999999999}', True),
        ('{"username": "admin", "password": "<REDACTED_SECRET:sha256_8=12345678>"}', True),
        ('{"username": "admin", "passwd": "<REDACTED>"}', True),
        ('{"user": {"pwd": "<REDACTED_SECRET>"}}', True),
        ('{"client_secret": "<REDACTED_SECRET>"}', True),
        ('{"pass": "<REDACTED>", "credential": "abc"}', True),
        ('{"pin": "<REDACTED_SECRET>"}', True),
        ('{"otp": "<REDACTED_SECRET>"}', True),
        ('{"code": "<REDACTED_SECRET>"}', True),
        ('{"verifyCode": "<REDACTED_SECRET>"}', True),
        ("username=admin&password=<REDACTED_SECRET>&expires=999999999", True),
        ("username=admin&password=<REDACTED_SECRET:sha256_8=deadbeef>", True),
        ("username=admin&otp=<REDACTED>", True),
        # Negative cases: unredacted or non-credential keys
        ('{"username": "admin", "password": "SuperSecret123", "expires": 999999999}', False),
        ('{"note": "<REDACTED_SECRET>"}', False),
        ('{"description": "password=<REDACTED_SECRET>"}', False),
        ('{"postal_code": "<REDACTED_SECRET>"}', False),
        ('{"bypass": "<REDACTED_SECRET>"}', False),
        ("username=admin&note=<REDACTED_SECRET>", False),
        ("", False),
    ],
)
def test_has_redacted_credential_body_unit(request_body: str, expected: bool) -> None:
    assert _has_redacted_credential_body({"request_body": request_body}) is expected


def test_can_accept_redacted_credential_body_replay_unit_guards() -> None:
    base_target = {
        "method": "POST",
        "url": "http://127.0.0.1/api/authorize/login",
        "path": "/api/authorize/login",
        "status": 200,
        "request_body": '{"username":"admin","password":"<REDACTED_SECRET>","expires":999999999}',
        "body": '{"status":200,"result":{"expires":999999999}}',
    }
    base_replay_400 = {
        "status": 400,
        "body": '{"status":400,"code":"illegal_password"}',
    }

    assert _can_accept_redacted_credential_body_replay(
        base_target, base_replay_400, evidence_value="999999999", canonical_class="mass_assignment"
    ) is True

    # PUT and PATCH with 2xx/3xx also accepted; GET and DELETE rejected.
    for method, ok in (("POST", True), ("PUT", True), ("PATCH", True), ("GET", False), ("DELETE", False)):
        assert _can_accept_redacted_credential_body_replay(
            {**base_target, "method": method},
            base_replay_400,
            evidence_value="999999999",
            canonical_class="mass_assignment",
        ) is ok

    # Original status must be 2xx/3xx.
    for orig_st, ok in ((200, True), (201, True), (302, True), (400, False), (401, False), (500, False)):
        assert _can_accept_redacted_credential_body_replay(
            {**base_target, "status": orig_st},
            base_replay_400,
            evidence_value="999999999",
            canonical_class="mass_assignment",
        ) is ok

    # Replay status strictly {400, 401, 403}; NEVER 404, 405, 500, 0.
    for rep_st, ok in ((400, True), (401, True), (403, True), (404, False), (405, False), (500, False), (0, False)):
        assert _can_accept_redacted_credential_body_replay(
            base_target,
            {"status": rep_st, "body": '{"code":"illegal_password"}'},
            evidence_value="999999999",
            canonical_class="mass_assignment",
        ) is ok

    # Non-login endpoint returning generic 400 without auth/credential rejection indicator -> False.
    non_login_target = {
        **base_target,
        "url": "http://127.0.0.1/api/profile/update",
        "path": "/api/profile/update",
    }
    assert _can_accept_redacted_credential_body_replay(
        non_login_target,
        {"status": 400, "body": '{"error":"bad_request","detail":"malformed email"}'},
        evidence_value="999999999",
        canonical_class="mass_assignment",
    ) is False
    # Same non-login endpoint returning explicit password rejection 400 -> True.
    assert _can_accept_redacted_credential_body_replay(
        non_login_target,
        {"status": 400, "body": '{"error":"invalid_password","detail":"current password invalid"}'},
        evidence_value="999999999",
        canonical_class="mass_assignment",
    ) is True

    # Missing evidence_value in original replay_target -> False.
    assert _can_accept_redacted_credential_body_replay(
        base_target,
        base_replay_400,
        evidence_value="NOT_IN_RECEIPT",
        canonical_class="mass_assignment",
    ) is False


# ---------------------------------------------------------------------------
# 2. End-to-end loopback integration tests — Positive cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("canonical_class", ["mass_assignment", "business_logic", "session_management"])
def test_positive_json_login_redacted_password_400_illegal_password(
    loopback_server: str, tmp_path: Path, canonical_class: str
) -> None:
    _, client, oracle = _make_env(loopback_server, tmp_path)
    try:
        ctrl = client.request(
            method="POST",
            url="/api/authorize/login",
            actor="anon",
            json_body={"username": "admin", "password": "SuperSecret123", "expires": 3600},
        )
        proof = client.request(
            method="POST",
            url="/api/authorize/login",
            actor="anon",
            json_body={"username": "admin", "password": "SuperSecret123", "expires": 999999999},
        )
        assert ctrl["status"] == 200
        assert proof["status"] == 200
        assert "<REDACTED_SECRET" in proof["request_body"]

        verdict = oracle.verify(
            canonical_class=canonical_class,
            primary_proof=proof,
            proof_receipts=[proof],
            control_receipts=[ctrl],
            evidence_value="999999999",
        )
        assert verdict.verified is True
        assert verdict.verdict == "VERIFIED"
        assert verdict.stages["stage1_control"] == "passed"
        assert verdict.stages["stage2_diff"] == "passed"
        assert verdict.stages["stage3_clean_replay"] == "passed_redacted_credential_replay_exempt"
        assert "redacted" in verdict.reason.lower()
    finally:
        client.close()


@pytest.mark.parametrize("canonical_class", ["mass_assignment", "business_logic"])
def test_positive_json_login_401_and_form_encoded_login_401(
    loopback_server: str, tmp_path: Path, canonical_class: str
) -> None:
    _, client, oracle = _make_env(loopback_server, tmp_path)
    try:
        # JSON POST /api/auth/login-401 returning 401 invalid credentials on replay
        ctrl_json = client.request(
            method="POST",
            url="/api/auth/login-401",
            actor="anon",
            json_body={"username": "admin", "password": "SuperSecret123", "expires": 3600},
        )
        proof_json = client.request(
            method="POST",
            url="/api/auth/login-401",
            actor="anon",
            json_body={"username": "admin", "password": "SuperSecret123", "expires": 8640000},
        )
        assert proof_json["status"] == 200
        assert "<REDACTED_SECRET" in proof_json["request_body"]
        v_json = oracle.verify(
            canonical_class=canonical_class,
            primary_proof=proof_json,
            proof_receipts=[proof_json],
            control_receipts=[ctrl_json],
            evidence_value="8640000",
        )
        assert v_json.verified is True
        assert v_json.verdict == "VERIFIED"
        assert v_json.stages["stage3_clean_replay"] == "passed_redacted_credential_replay_exempt"

        # Form-encoded POST /login (`password=<REDACTED_SECRET...>`) returning 401 invalid credentials on replay
        ctrl_form = client.request(
            method="POST",
            url="/login",
            actor="anon",
            form_body={"username": "admin", "password": "SuperSecret123", "expires": "3600"},
        )
        proof_form = client.request(
            method="POST",
            url="/login",
            actor="anon",
            form_body={"username": "admin", "password": "SuperSecret123", "expires": "7777777"},
        )
        assert ctrl_form["status"] == 200
        assert proof_form["status"] == 200
        assert "password=<REDACTED_SECRET" in proof_form["request_body"]
        v_form = oracle.verify(
            canonical_class=canonical_class,
            primary_proof=proof_form,
            proof_receipts=[proof_form],
            control_receipts=[ctrl_form],
            evidence_value="7777777",
        )
        assert v_form.verified is True
        assert v_form.verdict == "VERIFIED"
        assert v_form.stages["stage3_clean_replay"] == "passed_redacted_credential_replay_exempt"
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 3. End-to-end loopback integration tests — Negative fail-closed cases
# ---------------------------------------------------------------------------


def test_negative_unredacted_request_body_returning_401_still_refuted(
    loopback_server: str, tmp_path: Path
) -> None:
    _, client, oracle = _make_env(loopback_server, tmp_path, accounts=[])
    try:
        # Field name "passphrase_hint" is NOT redacted by ReceiptStore; clean replay returns 401 -> REFUTED!
        ctrl = client.request(
            method="POST",
            url="/api/unredacted-login",
            actor="anon",
            json_body={"username": "admin", "passphrase_hint": "not-redacted", "expires": 3600},
        )
        proof = client.request(
            method="POST",
            url="/api/unredacted-login",
            actor="anon",
            json_body={"username": "admin", "passphrase_hint": "not-redacted", "expires": 999999999},
        )
        assert ctrl["status"] == 200
        assert proof["status"] == 200
        assert "<REDACTED" not in proof["request_body"]

        verdict = oracle.verify(
            canonical_class="mass_assignment",
            primary_proof=proof,
            proof_receipts=[proof],
            control_receipts=[ctrl],
            evidence_value="999999999",
        )
        assert verdict.verified is False
        assert verdict.verdict == "REFUTED"
        assert verdict.stages["stage3_clean_replay"] == "failed_status_401"
    finally:
        client.close()


@pytest.mark.parametrize("canonical_class", ["mass_assignment", "business_logic"])
def test_negative_redacted_password_missing_evidence_still_refuted(
    loopback_server: str, tmp_path: Path, canonical_class: str
) -> None:
    _, client, oracle = _make_env(loopback_server, tmp_path)
    try:
        ctrl = client.request(
            method="POST",
            url="/api/authorize/login",
            actor="anon",
            json_body={"username": "admin", "password": "SuperSecret123", "expires": 3600},
        )
        proof = client.request(
            method="POST",
            url="/api/authorize/login",
            actor="anon",
            json_body={"username": "admin", "password": "SuperSecret123", "expires": 999999999},
        )
        assert "<REDACTED_SECRET" in proof["request_body"]

        verdict = oracle.verify(
            canonical_class=canonical_class,
            primary_proof=proof,
            proof_receipts=[proof],
            control_receipts=[ctrl],
            evidence_value="HALLUCINATED_VALUE_NOT_IN_RECEIPT",
        )
        assert verdict.verified is False
        assert verdict.verdict == "REFUTED"
        assert verdict.stages["stage3_clean_replay"] == "failed_status_400"
    finally:
        client.close()


@pytest.mark.parametrize("replay_status", [404, 500])
def test_negative_redacted_password_replay_404_or_500_still_refuted(
    loopback_server: str, tmp_path: Path, replay_status: int
) -> None:
    _, client, oracle = _make_env(loopback_server, tmp_path)
    try:
        ctrl = client.request(
            method="POST",
            url="/api/authorize/login",
            actor="anon",
            json_body={"username": "admin", "password": "SuperSecret123", "expires": 3600},
        )
        proof = client.request(
            method="POST",
            url="/api/authorize/login",
            actor="anon",
            json_body={"username": "admin", "password": "SuperSecret123", "expires": 999999999},
        )
        assert proof["status"] == 200
        assert "<REDACTED_SECRET" in proof["request_body"]

        # Force server to return 404 or 500 during Stage 3 clean replay -> MUST remain REFUTED!
        _Faz6BHandler.replay_status_override["/api/authorize/login"] = (
            replay_status,
            {"error": "server_error" if replay_status == 500 else "not_found"},
        )
        verdict = oracle.verify(
            canonical_class="mass_assignment",
            primary_proof=proof,
            proof_receipts=[proof],
            control_receipts=[ctrl],
            evidence_value="999999999",
        )
        assert verdict.verified is False
        assert verdict.verdict == "REFUTED"
        assert verdict.stages["stage3_clean_replay"] == f"failed_status_{replay_status}"
    finally:
        client.close()


def test_negative_redacted_non_credential_field_on_non_login_endpoint_400_refuted(
    loopback_server: str, tmp_path: Path
) -> None:
    _, client, oracle = _make_env(loopback_server, tmp_path)
    try:
        # "note" contains actor secret "SuperSecret123", so ReceiptStore redacts "note" to "<REDACTED_SECRET:...>".
        # Because "note" is NOT a credential key and /api/notes/create returns generic 400 -> MUST stay REFUTED!
        ctrl = client.request(
            method="POST",
            url="/api/notes/create",
            actor="anon",
            json_body={"note": "normal-note", "role": "member"},
        )
        proof = client.request(
            method="POST",
            url="/api/notes/create",
            actor="anon",
            json_body={"note": "SuperSecret123", "role": "admin"},
        )
        assert ctrl["status"] == 200
        assert proof["status"] == 200
        assert "<REDACTED_SECRET" in proof["request_body"]

        verdict = oracle.verify(
            canonical_class="mass_assignment",
            primary_proof=proof,
            proof_receipts=[proof],
            control_receipts=[ctrl],
            evidence_value="admin",
        )
        assert verdict.verified is False
        assert verdict.verdict == "REFUTED"
        assert verdict.stages["stage3_clean_replay"] == "failed_status_400"
    finally:
        client.close()


@pytest.mark.parametrize("canonical_class", ["mass_assignment", "business_logic", "session_management"])
def test_negative_stage1_or_stage2_identical_control_still_rejected(
    loopback_server: str, tmp_path: Path, canonical_class: str
) -> None:
    _, client, oracle = _make_env(loopback_server, tmp_path)
    try:
        ctrl = client.request(
            method="POST",
            url="/api/authorize/login-identical",
            actor="anon",
            json_body={"username": "admin", "password": "SuperSecret123", "expires": 3600},
        )
        proof = client.request(
            method="POST",
            url="/api/authorize/login-identical",
            actor="anon",
            json_body={"username": "admin", "password": "SuperSecret123", "expires": 999999999},
        )
        assert ctrl["status"] == 200
        assert proof["status"] == 200
        assert "<REDACTED_SECRET" in proof["request_body"]

        verdict = oracle.verify(
            canonical_class=canonical_class,
            primary_proof=proof,
            proof_receipts=[proof],
            control_receipts=[ctrl],
            evidence_value="3600",
        )
        assert verdict.verified is False
        assert verdict.verdict in {"REFUTED", "DECEPTION_DETECTED"}
        assert verdict.deception_detected is True
        assert "stage3_clean_replay" not in verdict.stages
    finally:
        client.close()


def test_weak_credentials_existing_redacted_body_path_preserved(
    loopback_server: str, tmp_path: Path
) -> None:
    _, client, oracle = _make_env(loopback_server, tmp_path)
    try:
        ctrl = client.request(
            method="POST",
            url="/api/auth/login-401",
            actor="anon",
            json_body={"username": "admin", "password": "wrongpassword"},
        )
        proof = client.request(
            method="POST",
            url="/api/auth/login-401",
            actor="anon",
            json_body={"username": "admin", "password": "SuperSecret123"},
        )
        assert ctrl["status"] == 401
        assert proof["status"] == 200
        assert "<REDACTED_SECRET" in proof["request_body"]

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
    finally:
        client.close()
