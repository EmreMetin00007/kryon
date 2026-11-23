"""Regression tests for context-aware secret redaction hygiene in receipts and reports."""
from __future__ import annotations

import json
from pathlib import Path
import sys

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_receipts import ReceiptStore, redact_secrets  # noqa: E402
import agentic_report  # noqa: E402

SAMPLE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcmFkbWluIn0."
    "sigPart9876543210abcdef"
)
SAMPLE_PHPSESSID = "011449283e551fca6397e315ed5199f8"
SAMPLE_API_KEY = "sk_live_9f8a7b6c5d4e3f2a"
SAMPLE_STRONG_PW = "SuperSecret-2026!"
SAMPLE_VAULT_PW = "VaultAlice-2026!"


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Real-world benchmark regressions (SiyuCMS & ComfyUI)
# ---------------------------------------------------------------------------


def test_siyucms_admin_probe_redacts_password_param_without_mangling_paths_or_prose(tmp_path: Path) -> None:
    """Probing `?password=admin&username=admin` redacts `password=<REDACTED>` while preserving `/admin/...` and prose."""
    run_dir = tmp_path / "run-siyucms"
    _write_json(
        run_dir / "manifest.json",
        {
            "run_id": "run-siyucms-001",
            "target": "http://127.0.0.1:8080",
            "status": "finished",
            "finished": True,
            "untested_areas": [
                "Admin panel backup download at /admin/Database/export.html not tested",
            ],
        },
    )
    _write_json(
        run_dir / "receipts" / "req-0001.json",
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0001",
            "actor": "anon",
            "method": "GET",
            "url": "http://127.0.0.1:8080/admin/Login/checkLogin.html?password=admin&username=admin",
            "path": "/admin/Login/checkLogin.html",
            "query": "password=admin&username=admin",
            "request_headers": {"Accept": "application/json"},
            "request_body": "",
            "status": 200,
            "response_headers": {
                "Content-Type": "application/json",
                "Set-Cookie": f"PHPSESSID={SAMPLE_PHPSESSID}; HttpOnly; Path=/",
            },
            "body": '{"code": 1, "msg": "login ok", "url": "/admin/Index/index.html"}',
        },
    )
    _write_json(
        run_dir / "receipts" / "req-0002.json",
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0002",
            "actor": "admin",
            "method": "POST",
            "url": "http://127.0.0.1:8080/admin/upload/index.html",
            "path": "/admin/upload/index.html",
            "request_headers": {
                "Cookie": f"PHPSESSID={SAMPLE_PHPSESSID}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "request_body": "dir=admin&file=shell.php",
            "status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "body": '{"status": "uploaded", "path": "/admin/upload/index.html"}',
        },
    )
    _write_json(
        run_dir / "findings.json",
        [
            {
                "finding_id": "F-001",
                "title": "Unrestricted file upload in admin panel",
                "class_type": "bfla",
                "severity": "critical",
                "method": "POST",
                "url": "http://127.0.0.1:8080/admin/upload/index.html",
                "path": "/admin/upload/index.html",
                "route_template": "/admin/upload/index.html",
                "actor": "admin",
                "status": "verified",
                "oracle_verdict": "VERIFIED",
                "evidence": f"Uploaded to /admin/upload/index.html via admin panel; cookie={SAMPLE_PHPSESSID}",
                "summary": "The admin panel endpoint /admin/upload/index.html accepts arbitrary uploads after login.",
                "proof_receipt_ids": ["req-0002"],
                "control_receipt_ids": ["req-0001"],
            }
        ],
    )

    artifacts = agentic_report.load_run_artifacts(run_dir)
    collected = agentic_report._collect_secret_values(artifacts)
    assert "admin" not in collected
    assert SAMPLE_PHPSESSID in collected

    summary = agentic_report.generate_run_reports(run_dir)
    md_text = Path(summary["markdown_path"]).read_text(encoding="utf-8")
    sarif_raw = Path(summary["sarif_path"]).read_text(encoding="utf-8")

    # Path segments and prose stay intact.
    assert "/admin/upload/index.html" in md_text
    assert "/admin/Login/checkLogin.html?password=<REDACTED>&username=admin" in md_text
    assert "admin panel" in md_text
    assert "/admin/Database/export.html" in md_text
    assert "/admin/upload/index.html" in sarif_raw

    # Password query value and real PHPSESSID are completely redacted.
    assert "password=admin" not in md_text
    assert "password=admin" not in sarif_raw
    assert SAMPLE_PHPSESSID not in md_text
    assert SAMPLE_PHPSESSID not in sarif_raw
    assert "8c6976e5" not in md_text  # sha256("admin")[:8] must never appear


def test_comfyui_probe_query_value_does_not_corrupt_filenames_or_identifiers(tmp_path: Path) -> None:
    """A benign `probe` query value under a sensitive key must not corrupt `probe.txt`, `Shard2.Probe`, or `probe-value-123`."""
    run_dir = tmp_path / "run-comfyui"
    _write_json(
        run_dir / "manifest.json",
        {
            "run_id": "run-comfyui-001",
            "target": "http://127.0.0.1:8188",
            "status": "finished",
            "finished": True,
        },
    )
    _write_json(
        run_dir / "receipts" / "req-0001.json",
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0001",
            "actor": "anon",
            "method": "GET",
            "url": "http://127.0.0.1:8188/api/userdata/probe.txt?token=probe&key=probe.txt",
            "path": "/api/userdata/probe.txt",
            "query": "token=probe&key=probe.txt",
            "request_headers": {"X-API-Key": "probe", "Accept": "application/json"},
            "request_body": "",
            "status": 200,
            "response_headers": {"Content-Type": "text/plain"},
            "body": "Shard2.Probe wrote probe-value-123 into probe.txt",
        },
    )
    _write_json(
        run_dir / "findings.json",
        [
            {
                "finding_id": "F-001",
                "title": "Unauthenticated userdata write for probe.txt",
                "class_type": "auth_bypass",
                "severity": "high",
                "method": "GET",
                "url": "http://127.0.0.1:8188/api/userdata/probe.txt?token=probe&key=probe.txt",
                "path": "/api/userdata/probe.txt",
                "route_template": "/api/userdata/{file}",
                "actor": "anon",
                "status": "verified",
                "oracle_verdict": "VERIFIED",
                "evidence": "Shard2.Probe read probe-value-123 from /api/userdata/probe.txt",
                "summary": "Endpoint /api/userdata/probe.txt returned probe-value-123 for Shard2.Probe.",
                "proof_receipt_ids": ["req-0001"],
                "control_receipt_ids": [],
            }
        ],
    )

    artifacts = agentic_report.load_run_artifacts(run_dir)
    collected = agentic_report._collect_secret_values(artifacts)
    assert "probe" not in collected
    assert "probe.txt" not in collected

    summary = agentic_report.generate_run_reports(run_dir)
    md_text = Path(summary["markdown_path"]).read_text(encoding="utf-8")
    sarif_raw = Path(summary["sarif_path"]).read_text(encoding="utf-8")

    assert "/api/userdata/probe.txt?token=<REDACTED>&key=<REDACTED>" in md_text
    assert "probe.txt" in md_text
    assert "Shard2.Probe" in md_text
    assert "probe-value-123" in md_text
    assert "ba9c736f" not in md_text  # sha256("probe")[:8] must never appear
    assert "ba9c736f" not in sarif_raw
    assert '-H "X-API-Key: <REDACTED_HEADER>"' in md_text


# ---------------------------------------------------------------------------
# 2. Real opaque / high-entropy secrets MUST stay 100% redacted everywhere
# ---------------------------------------------------------------------------


def test_real_opaque_secrets_redacted_everywhere_including_paths_curl_and_excerpts(tmp_path: Path) -> None:
    """Real passwords, JWTs, API keys, and session IDs are redacted across paths, query strings, curl, MD, and SARIF."""
    run_dir = tmp_path / "run-real-secrets"
    _write_json(
        run_dir / "manifest.json",
        {
            "run_id": "run-real-001",
            "target": "http://127.0.0.1:9000",
            "status": "finished",
            "finished": True,
        },
    )
    _write_json(
        run_dir / "receipts" / "req-0001.json",
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0001",
            "actor": "member_a",
            "method": "POST",
            "url": (
                f"http://alice:{SAMPLE_STRONG_PW}@127.0.0.1:9000"
                f"/reset/{SAMPLE_JWT}/session/{SAMPLE_PHPSESSID}/key/{SAMPLE_API_KEY}"
                f"?password={SAMPLE_STRONG_PW}&api_key={SAMPLE_API_KEY}&next=/admin/upload"
            ),
            "path": f"/reset/{SAMPLE_JWT}/session/{SAMPLE_PHPSESSID}/key/{SAMPLE_API_KEY}",
            "request_headers": {
                "Authorization": f"Bearer {SAMPLE_JWT}",
                "Cookie": f"PHPSESSID={SAMPLE_PHPSESSID}; theme=dark",
                "X-API-Key": SAMPLE_API_KEY,
                "Content-Type": "application/json",
            },
            "request_body": json.dumps({
                "note": f"leaked {SAMPLE_STRONG_PW} and {SAMPLE_API_KEY}",
                "session": SAMPLE_PHPSESSID,
                "token": SAMPLE_JWT,
            }),
            "status": 200,
            "response_headers": {
                "Content-Type": "application/json",
                "Set-Cookie": f"PHPSESSID={SAMPLE_PHPSESSID}; HttpOnly; Path=/",
            },
            "body": (
                f"ok pw={SAMPLE_STRONG_PW} jwt={SAMPLE_JWT} "
                f"key={SAMPLE_API_KEY} sid={SAMPLE_PHPSESSID} path=/admin/upload"
            ),
        },
    )
    _write_json(
        run_dir / "findings.json",
        [
            {
                "finding_id": "F-001",
                "title": "Credential exposure across reset flow",
                "class_type": "info_disclosure",
                "severity": "critical",
                "method": "POST",
                "url": (
                    f"http://127.0.0.1:9000/reset/{SAMPLE_JWT}/session/{SAMPLE_PHPSESSID}"
                    f"?password={SAMPLE_STRONG_PW}&api_key={SAMPLE_API_KEY}"
                ),
                "path": f"/reset/{SAMPLE_JWT}/session/{SAMPLE_PHPSESSID}",
                "actor": "member_a",
                "status": "verified",
                "oracle_verdict": "VERIFIED",
                "evidence": (
                    f"Echoed {SAMPLE_STRONG_PW}, {SAMPLE_JWT}, {SAMPLE_API_KEY}, {SAMPLE_PHPSESSID} "
                    "on /admin/upload"
                ),
                "summary": "Reset flow exposes secrets in URL path and response body.",
                "proof_receipt_ids": ["req-0001"],
                "control_receipt_ids": [],
            }
        ],
    )

    summary = agentic_report.generate_run_reports(run_dir)
    md_text = Path(summary["markdown_path"]).read_text(encoding="utf-8")
    sarif_raw = Path(summary["sarif_path"]).read_text(encoding="utf-8")

    for secret in (SAMPLE_STRONG_PW, SAMPLE_JWT, SAMPLE_API_KEY, SAMPLE_PHPSESSID):
        assert secret not in md_text, f"Leaked secret in report.md: {secret}"
        assert secret not in sarif_raw, f"Leaked secret in report.sarif: {secret}"

    assert "<REDACTED_CREDENTIALS>@127.0.0.1:9000" in md_text
    assert "password=<REDACTED>" in md_text
    assert "api_key=<REDACTED>" in md_text
    assert "/admin/upload" in md_text
    assert '-H "Authorization: <REDACTED_AUTH_HEADER>"' in md_text
    assert '-H "Cookie: <REDACTED_COOKIE>"' in md_text
    assert '-H "X-API-Key: <REDACTED_HEADER>"' in md_text


# ---------------------------------------------------------------------------
# 3. Direct unit tests for URL extraction & sanitization helpers
# ---------------------------------------------------------------------------


def test_extract_secrets_from_url_filters_common_probe_words_and_payloads() -> None:
    sink: set[str] = set()
    benign_urls = [
        "http://127.0.0.1/login?password=admin&token=probe&secret=test&key=root",
        "http://127.0.0.1/login?password=password&token=token&secret=secret&auth=guest",
        "http://127.0.0.1/login?password=1234&passwd=123456&key=true&token=false&sig=null&sid=none",
        "http://127.0.0.1/login?key=demo&secret=default&token=check&password=value",
        "http://127.0.0.1/api?key=probe.txt&token=../../../../etc/passwd&secret=http://127.0.0.1/admin",
        "http://127.0.0.1/api?key=<script>alert(1)</script>&token={{7*7}}",
        "http://admin:admin@127.0.0.1/admin/panel",
    ]
    for url in benign_urls:
        agentic_report._extract_secrets_from_url(url, sink)
    assert sink == set()

    real_urls = [
        f"http://127.0.0.1/login?password={SAMPLE_STRONG_PW}",
        f"http://127.0.0.1/api?token={SAMPLE_JWT}",
        f"http://127.0.0.1/api?api_key={SAMPLE_API_KEY}",
        "http://127.0.0.1/api?api_key=key-12345",
        f"http://alice:{SAMPLE_VAULT_PW}@127.0.0.1/admin",
    ]
    for url in real_urls:
        agentic_report._extract_secrets_from_url(url, sink)
    assert sink == {SAMPLE_STRONG_PW, SAMPLE_JWT, SAMPLE_API_KEY, "key-12345", SAMPLE_VAULT_PW}


def test_sanitize_url_preserves_paths_against_short_secrets_but_redacts_opaque_path_tokens() -> None:
    short_secrets = ("admin", "probe", "test", "secret", "password", "administrator")

    sanitized_admin = agentic_report._sanitize_url(
        "http://127.0.0.1:8080/admin/Login/checkLogin.html?password=admin&username=admin",
        short_secrets,
    )
    assert sanitized_admin == "http://127.0.0.1:8080/admin/Login/checkLogin.html?password=<REDACTED>&username=admin"

    sanitized_upload = agentic_report._sanitize_url(
        "http://127.0.0.1:8080/admin/upload/index.html",
        short_secrets,
    )
    assert sanitized_upload == "http://127.0.0.1:8080/admin/upload/index.html"

    sanitized_probe = agentic_report._sanitize_url(
        "http://127.0.0.1:8188/api/userdata/probe.txt?token=probe",
        short_secrets,
    )
    assert sanitized_probe == "http://127.0.0.1:8188/api/userdata/probe.txt?token=<REDACTED>"

    sanitized_creds = agentic_report._sanitize_url(
        "http://admin:admin@127.0.0.1:8080/admin/panel",
        short_secrets,
    )
    assert sanitized_creds == "http://<REDACTED_CREDENTIALS>@127.0.0.1:8080/admin/panel"

    # Real opaque secrets in URL paths ARE redacted.
    sanitized_jwt_path = agentic_report._sanitize_url(f"http://127.0.0.1:8080/reset/{SAMPLE_JWT}", ())
    assert SAMPLE_JWT not in sanitized_jwt_path
    assert "/reset/<REDACTED_JWT>" in sanitized_jwt_path

    sanitized_hex_path = agentic_report._sanitize_url(
        f"http://127.0.0.1:8080/sessions/{SAMPLE_PHPSESSID}/status",
        (SAMPLE_PHPSESSID,),
    )
    assert SAMPLE_PHPSESSID not in sanitized_hex_path
    assert sanitized_hex_path.startswith("http://127.0.0.1:8080/sessions/<REDACTED_SECRET:")
    assert sanitized_hex_path.endswith("/status")


# ---------------------------------------------------------------------------
# 4. Direct unit tests for `redact_secrets()` and `ReceiptStore`
# ---------------------------------------------------------------------------


def test_redact_secrets_short_plain_words_are_context_aware() -> None:
    text = (
        "GET /admin/upload/index.html | admin panel | administrator | shard2_probe | "
        "probe.txt | Shard2.Probe | probe-value-123 | username=admin | role=admin | "
        "password=admin | api_key=probe | Authorization: Bearer admin | "
        '{"password": "admin", "secret": "probe", "user": "admin"} | '
        "http://alice:admin@127.0.0.1/admin/home"
    )
    out = redact_secrets(text, ["admin", "probe", "test"])

    # Paths, prose, filenames, larger identifiers, and non-secret fields are preserved.
    assert "/admin/upload/index.html" in out
    assert "admin panel" in out
    assert "administrator" in out
    assert "shard2_probe" in out
    assert "probe.txt" in out
    assert "Shard2.Probe" in out
    assert "probe-value-123" in out
    assert "username=admin" in out
    assert "role=admin" in out
    assert '"user": "admin"' in out
    assert "/admin/home" in out

    # Credential contexts ARE redacted.
    assert "password=admin" not in out
    assert "api_key=probe" not in out
    assert "Bearer admin" not in out
    assert '"password": "admin"' not in out
    assert '"secret": "probe"' not in out
    assert "alice:admin@" not in out
    assert "password=<REDACTED_SECRET:sha256_8=8c6976e5>" in out
    assert "api_key=<REDACTED_SECRET:sha256_8=ba9c736f>" in out
    assert "Bearer <REDACTED_SECRET:sha256_8=8c6976e5>" in out
    assert "alice:<REDACTED_SECRET:sha256_8=8c6976e5>@" in out


def test_redact_secrets_preserves_full_exact_redaction_for_real_secrets_and_receipts(tmp_path: Path) -> None:
    secrets = [SAMPLE_VAULT_PW, SAMPLE_API_KEY, SAMPLE_PHPSESSID, "tok-a1", "AbCd1"]
    payload = (
        f"pw={SAMPLE_VAULT_PW} raw {SAMPLE_VAULT_PW} path=/x/{SAMPLE_API_KEY}/y "
        f"sid={SAMPLE_PHPSESSID} shortmix=tok-a1 mixed=AbCd1"
    )
    out = redact_secrets(payload, secrets)
    for sec in secrets:
        assert sec not in out

    # ReceiptStore with an actor whose password is 'admin' still scrubs login password
    # without corrupting `/admin/...` response bodies or redirects.
    store = ReceiptStore(tmp_path)
    rec = store.record(
        actor="admin",
        method="POST",
        url="http://127.0.0.1:8080/admin/Login/checkLogin.html",
        path="/admin/Login/checkLogin.html",
        request_headers={"Cookie": f"PHPSESSID={SAMPLE_PHPSESSID}"},
        request_body="username=admin&password=admin",
        status=302,
        elapsed_ms=5.0,
        response_headers={"Location": "/admin/Index/index.html"},
        redirect_location="/admin/Index/index.html",
        raw_response_bytes=b"redirecting to admin panel /admin/upload/index.html",
        response_text=f"redirecting to admin panel /admin/upload/index.html leaked={SAMPLE_VAULT_PW}",
        secret_values=["admin", SAMPLE_VAULT_PW, SAMPLE_PHPSESSID],
    )
    assert "password=admin" not in rec["request_body"]
    assert "username=admin" in rec["request_body"]
    assert rec["redirect_location"] == "/admin/Index/index.html"
    assert "/admin/upload/index.html" in rec["body"]
    assert "admin panel" in rec["body"]
    assert SAMPLE_VAULT_PW not in rec["body"]
    assert SAMPLE_PHPSESSID not in json.dumps(rec["request_headers"])


def test_extract_secrets_from_headers_and_spa_fragment_edge_cases() -> None:
    sink: set[str] = set()
    agentic_report._extract_secrets_from_headers(
        {
            "Authorization": "Bearer admin",
            "Cookie": f"theme=dark; lang=en-US; sid=admin; PHPSESSID={SAMPLE_PHPSESSID}",
            "Set-Cookie": "role=admin; Path=/; HttpOnly",
            "X-API-Key": "probe",
            "X-Auth-Mode": "admin",
            "WWW-Authenticate": 'Basic realm="admin"',
        },
        sink,
    )
    assert "admin" not in sink
    assert "probe" not in sink
    assert "dark" not in sink
    assert "en-US" not in sink
    assert "Bearer admin" in sink
    assert "sid=admin" in sink
    assert SAMPLE_PHPSESSID in sink

    # SPA hash route fragments preserve path segments while redacting sensitive query params.
    spa_url = agentic_report._sanitize_url(
        "http://127.0.0.1:8080/#/admin/upload?password=admin&username=admin",
        ("admin",),
    )
    assert spa_url == "http://127.0.0.1:8080/#/admin/upload?password=<REDACTED>&username=admin"

    # Short-secret credential context does not cross newline boundaries into prose.
    multiline = "Reset Password:\nadmin panel instructions\npassword: admin"
    scrubbed = redact_secrets(multiline, ["admin"])
    assert "admin panel instructions" in scrubbed
    assert "password: <REDACTED_SECRET:sha256_8=8c6976e5>" in scrubbed

