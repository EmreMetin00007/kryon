"""Tests for multipart/form-data curl -F report reproductions and replay_as multipart guards."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shlex
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import (  # noqa: E402
    ActorManager,
    AgenticHTTPClient,
    _encode_multipart_form_data,
)
from agentic_receipts import ReceiptStore  # noqa: E402
import agentic_report  # noqa: E402
from agentic_tools import TOOL_SCHEMAS, ToolDispatcher  # noqa: E402


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _unwrap_tool_response(raw: str) -> dict[str, Any]:
    prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw.startswith(prefix) and raw.endswith(suffix)
    return json.loads(raw[len(prefix) : -len(suffix)])


def _extract_flag_values(curl_cmd: str, flag: str) -> list[str]:
    tokens = shlex.split(curl_cmd)
    out: list[str] = []
    idx = 0
    while idx < len(tokens):
        if tokens[idx] == flag and idx + 1 < len(tokens):
            out.append(tokens[idx + 1])
            idx += 2
        else:
            idx += 1
    return out


# ---------------------------------------------------------------------------
# 1. agentic_report: curl -F reproduction for multipart/form-data receipts
# ---------------------------------------------------------------------------


def test_report_curl_multipart_files_and_fields_and_redaction(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-multipart"
    _, ct_header, body_summary = _encode_multipart_form_data(
        [
            {
                "field": "files",
                "filename": "probe.txt",
                "content": "hello world",
                "content_type": "text/plain",
            },
            {
                "field": "avatar",
                "filename": "pic.png",
                "content": "pngbytes",
                "content_type": "image/png",
            },
        ],
        form_fields={"foo": "v1", "bar": "v2"},
    )

    _write_json(
        run_dir / "manifest.json",
        {
            "run_id": "run-mp-001",
            "target": "http://127.0.0.1:9100",
            "status": "finished",
            "finished": True,
        },
    )
    _write_json(
        run_dir / "receipts" / "req-mp-1.json",
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-mp-1",
            "actor": "member_b",
            "method": "POST",
            "url": "http://127.0.0.1:9100/api/v1/uploads",
            "path": "/api/v1/uploads",
            "request_headers": {
                "Authorization": "Bearer super-secret-bearer-token",
                "Cookie": "sid=super-secret-cookie",
                "X-API-Key": "secret-api-key-999",
                "X-Request-Id": "req-trace-42",
                "Content-Type": ct_header,
            },
            "request_body": body_summary,
            "status": 201,
            "response_headers": {"Content-Type": "application/json"},
            "body": '{"uploaded": true, "id": "u-1"}',
        },
    )
    _write_json(
        run_dir / "findings.json",
        [
            {
                "finding_id": "F-101",
                "title": "Unrestricted file upload via multipart form",
                "class_type": "bfla",
                "severity": "high",
                "method": "POST",
                "url": "http://127.0.0.1:9100/api/v1/uploads",
                "path": "/api/v1/uploads",
                "actor": "member_b",
                "status": "verified",
                "oracle_verdict": "VERIFIED",
                "evidence": '{"uploaded": true, "id": "u-1"}',
                "summary": "Low-privilege user uploaded files to admin upload endpoint.",
                "proof_receipt_ids": ["req-mp-1"],
                "control_receipt_ids": [],
            }
        ],
    )

    summary = agentic_report.generate_run_reports(run_dir)
    md_text = Path(summary["markdown_path"]).read_text(encoding="utf-8")
    sarif_raw = Path(summary["sarif_path"]).read_text(encoding="utf-8")
    sarif_doc = json.loads(sarif_raw)

    curl_cmd = sarif_doc["runs"][0]["results"][0]["properties"]["reproduction_curl"]
    assert curl_cmd in md_text

    # No stale multipart Content-Type header and no --data-raw with the compact summary string.
    assert "multipart/form-data" not in curl_cmd
    assert "--data-raw" not in curl_cmd
    headers_emitted = _extract_flag_values(curl_cmd, "-H")
    assert not any(h.lower().startswith("content-type:") for h in headers_emitted)

    # Proper -F arguments for both fields and files.
    form_args = _extract_flag_values(curl_cmd, "-F")
    assert form_args == [
        "foo=<value>",
        "bar=<value>",
        "files=@probe.txt;type=text/plain",
        "avatar=@pic.png;type=image/png",
    ]
    assert "-F 'foo=<value>'" in curl_cmd
    assert "-F 'bar=<value>'" in curl_cmd
    assert "-F 'files=@probe.txt;type=text/plain'" in curl_cmd
    assert "-F 'avatar=@pic.png;type=image/png'" in curl_cmd

    # Sensitive headers remain redacted and non-sensitive headers are preserved.
    assert "Authorization: <REDACTED_AUTH_HEADER>" in headers_emitted
    assert "Cookie: <REDACTED_COOKIE>" in headers_emitted
    assert "X-API-Key: <REDACTED_HEADER>" in headers_emitted
    assert "X-Request-Id: req-trace-42" in headers_emitted
    for secret in ("super-secret-bearer-token", "super-secret-cookie", "secret-api-key-999"):
        assert secret not in md_text
        assert secret not in sarif_raw


def test_report_curl_multipart_edge_cases_and_fallbacks() -> None:
    finding = {"method": "POST", "path": "/upload", "url": "http://127.0.0.1:9100/upload"}

    # 1. Defaults (missing field/filename/content_type) + control-char & secret sanitization.
    rec_sanitized = {
        "method": "POST",
        "url": "http://127.0.0.1:9100/upload",
        "request_headers": {"content-type": "MULTIPART/FORM-DATA; boundary=abc123"},
        "request_body": "multipart/form-data "
        + json.dumps({
            "fields": ["note\r\nInjected", "   ", 123],
            "files": [
                {"filename": "onlyname.txt"},
                {"content_type": "application/pdf"},
                {"field": "doc\x00\n", "filename": "secret-tok-123\r\n.txt", "content_type": "text/plain\nX-Bad: 1"},
                {},
            ],
        }),
    }
    curl_sanitized, from_rec = agentic_report._build_curl_reproduction(
        finding,
        rec_sanitized,
        base_url="http://127.0.0.1:9100",
        secret_values=("secret-tok-123",),
    )
    assert from_rec is True
    assert "\n" not in curl_sanitized and "\r" not in curl_sanitized
    assert "secret-tok-123" not in curl_sanitized
    assert "--data-raw" not in curl_sanitized
    assert "content-type" not in curl_sanitized.lower()
    form_args = _extract_flag_values(curl_sanitized, "-F")
    assert form_args[0] == "noteInjected=<value>"
    assert form_args[1] == "file=@onlyname.txt"
    assert form_args[2] == "file=@upload.bin;type=application/pdf"
    assert form_args[3].startswith("doc=@") and "secret-tok-123" not in form_args[3]
    assert form_args[3].endswith(";type=text/plainX-Bad: 1")
    assert form_args[4] == "file=@upload.bin"

    # 2. Malformed / empty / non-summary multipart receipts fall back cleanly to -F 'file=@upload.bin'.
    fallback_cases = [
        {
            "method": "POST",
            "url": "http://127.0.0.1:9100/upload",
            "request_headers": {"Content-Type": "multipart/form-data; boundary=xyz"},
            "request_body": "multipart/form-data {not-valid-json",
        },
        {
            "method": "POST",
            "url": "http://127.0.0.1:9100/upload",
            "request_headers": {"Content-Type": "multipart/form-data; boundary=xyz"},
            "request_body": 'multipart/form-data ["not-a-dict"]',
        },
        {
            "method": "POST",
            "url": "http://127.0.0.1:9100/upload",
            "request_headers": {"Content-Type": "multipart/form-data; boundary=xyz"},
            "request_body": 'multipart/form-data {"files":[],"fields":[]}',
        },
        {
            "method": "POST",
            "url": "http://127.0.0.1:9100/upload",
            "request_headers": {"Content-Type": "multipart/form-data; boundary=xyz"},
            "request_body": "",
        },
    ]
    for rec in fallback_cases:
        cmd, ok = agentic_report._build_curl_reproduction(
            finding, rec, base_url="http://127.0.0.1:9100", secret_values=()
        )
        assert ok is True
        assert "-F 'file=@upload.bin'" in cmd
        assert "--data-raw" not in cmd
        assert "boundary=xyz" not in cmd
        assert _extract_flag_values(cmd, "-F") == ["file=@upload.bin"]


def test_report_curl_non_multipart_json_form_raw_regression() -> None:
    finding = {"method": "POST", "path": "/api/items", "url": "http://127.0.0.1:9100/api/items"}

    # JSON receipt preserves Content-Type and --data-raw with secret redaction.
    json_rec = {
        "method": "POST",
        "url": "http://127.0.0.1:9100/api/items",
        "request_headers": {
            "Content-Type": "application/json",
            "Authorization": "Bearer json-secret-1",
        },
        "request_body": '{"name":"widget","password":"my-password-1"}',
    }
    json_cmd, ok = agentic_report._build_curl_reproduction(
        finding, json_rec, base_url="http://127.0.0.1:9100", secret_values=("json-secret-1",)
    )
    assert ok is True
    assert '-H "Content-Type: application/json"' in json_cmd
    assert '-H "Authorization: <REDACTED_AUTH_HEADER>"' in json_cmd
    assert "--data-raw" in json_cmd
    assert "-F " not in json_cmd
    assert "my-password-1" not in json_cmd
    assert '"name":"widget"' in json_cmd

    # Form-urlencoded receipt preserves Content-Type and --data-raw.
    form_rec = {
        "method": "POST",
        "url": "http://127.0.0.1:9100/api/items",
        "request_headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "request_body": "title=alpha&role=member",
    }
    form_cmd, ok2 = agentic_report._build_curl_reproduction(
        finding, form_rec, base_url="http://127.0.0.1:9100", secret_values=()
    )
    assert ok2 is True
    assert '-H "Content-Type: application/x-www-form-urlencoded"' in form_cmd
    assert "--data-raw" in form_cmd
    assert "title=alpha&role=member" in form_cmd
    assert "-F " not in form_cmd


# ---------------------------------------------------------------------------
# 2. agentic_tools: replay_as guard for multipart/form-data receipts
# ---------------------------------------------------------------------------


def _start_echo_server() -> tuple[ThreadingHTTPServer, list[dict[str, Any]], threading.Lock]:
    seen: list[dict[str, Any]] = []
    lock = threading.Lock()

    class _EchoHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def _handle(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b""
            rec = {
                "method": method,
                "path": urlsplit(self.path).path,
                "content_type": self.headers.get("Content-Type", ""),
                "x_custom": self.headers.get("X-Custom", ""),
                "body": raw.decode("utf-8", errors="replace"),
                "body_len": len(raw),
            }
            with lock:
                seen.append(rec)
            payload = json.dumps({"ok": True, "echo": rec}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(payload)

        def do_GET(self) -> None:
            self._handle("GET")

        def do_HEAD(self) -> None:
            self._handle("HEAD")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_PUT(self) -> None:
            self._handle("PUT")

        def do_PATCH(self) -> None:
            self._handle("PATCH")

        def do_DELETE(self) -> None:
            self._handle("DELETE")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen, lock


def test_replay_as_multipart_guard_and_safe_overrides(tmp_path: Path) -> None:
    srv, seen, _ = _start_echo_server()
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "member_a", "auth_header": "Bearer tok-a", "role": "member"},
        {"alias": "member_b", "auth_header": "Bearer tok-b", "role": "member"},
    ])
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{srv.server_port}/",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        max_requests=40,
    )
    disp = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path)

    try:
        # Create a real multipart POST receipt via http_request.
        upload_out = disp.dispatch(
            "http_request",
            {
                "method": "POST",
                "url": "/api/uploads",
                "actor": "member_a",
                "headers": {"X-Custom": "keep-me"},
                "form_body": {"folder": "docs"},
                "files": [
                    {"field": "files", "filename": "probe.txt", "content": "hello world", "content_type": "text/plain"}
                ],
            },
        )
        mp_preview = _unwrap_tool_response(upload_out)
        mp_rid = mp_preview["receipt_id"]
        assert len(seen) == 1

        # Create a baseline receipt detected solely via Content-Type header (empty request_body).
        header_only_mp = store.record(
            actor="member_a",
            method="POST",
            url=f"http://127.0.0.1:{srv.server_port}/api/uploads-hdr",
            path="/api/uploads-hdr",
            query="",
            request_headers={"Content-Type": "multipart/form-data; boundary=manual123", "X-Custom": "hdr-only"},
            request_body="",
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            response_headers={"Content-Type": "application/json"},
            redirect_location="",
            raw_response_bytes=b'{"ok":true}',
            response_text='{"ok":true}',
        )
        hdr_mp_rid = header_only_mp["receipt_id"]

        # 1. Direct mutating replay (default POST, explicit POST/PUT/PATCH) raises actionable ValueError.
        for rid in (mp_rid, hdr_mp_rid):
            for replay_args in (
                {"receipt_id": rid, "actor": "member_b"},
                {"receipt_id": rid, "actor": "member_b", "method": "POST"},
                {"receipt_id": rid, "actor": "member_b", "method": "PUT"},
                {"receipt_id": rid, "actor": "member_b", "method": "PATCH"},
            ):
                with pytest.raises(ValueError) as exc_info:
                    disp._tool_replay_as(replay_args)
                msg = str(exc_info.value).lower()
                assert "multipart/form-data" in msg
                assert "http_request" in msg
                assert "files" in msg

                # Also verify structured dispatch error response.
                err_doc = json.loads(disp.dispatch("replay_as", replay_args))
                assert err_doc["error"] == "ValueError"
                assert "http_request" in err_doc["message"]
                assert "files" in err_doc["message"]

        # Zero extra HTTP requests were sent for rejected multipart replays.
        assert len(seen) == 1

        # 2. Switching method to GET / HEAD / DELETE strips stale multipart Content-Type and sends no body.
        for safe_method in ("GET", "HEAD", "DELETE"):
            out_raw = disp.dispatch(
                "replay_as",
                {"receipt_id": mp_rid, "actor": "member_b", "method": safe_method},
            )
            res = _unwrap_tool_response(out_raw)
            assert res["replay"]["status"] == 200
            wire = seen[-1]
            assert wire["method"] == safe_method
            assert "multipart/form-data" not in wire["content_type"].lower()
            assert wire["body"] == ""
            assert wire["body_len"] == 0
            assert wire["x_custom"] == "keep-me"

        # 3. Supplying json_overrides strips stale multipart Content-Type and sends clean JSON.
        out_json = disp.dispatch(
            "replay_as",
            {
                "receipt_id": mp_rid,
                "actor": "member_b",
                "json_overrides": {"title": "replaced"},
            },
        )
        res_json = _unwrap_tool_response(out_json)
        assert res_json["replay"]["status"] == 200
        wire_json = seen[-1]
        assert wire_json["method"] == "POST"
        assert wire_json["content_type"] == "application/json"
        assert json.loads(wire_json["body"]) == {"title": "replaced"}
        assert "multipart/form-data" not in wire_json["body"]
        assert wire_json["x_custom"] == "keep-me"

        # 4. Supplying json_merge strips stale multipart Content-Type and sends clean JSON.
        out_merge = disp.dispatch(
            "replay_as",
            {
                "receipt_id": mp_rid,
                "actor": "member_b",
                "json_merge": {"merged": True},
            },
        )
        res_merge = _unwrap_tool_response(out_merge)
        assert res_merge["replay"]["status"] == 200
        wire_merge = seen[-1]
        assert wire_merge["content_type"] == "application/json"
        assert json.loads(wire_merge["body"]) == {"merged": True}

        # 5. Supplying base_receipt_id strips stale multipart Content-Type and uses base JSON.
        json_base_rec = client.request(
            method="POST",
            url="/api/items",
            actor="member_a",
            json_body={"kind": "doc", "owner": "a"},
        )
        out_base = disp.dispatch(
            "replay_as",
            {
                "receipt_id": mp_rid,
                "actor": "member_b",
                "base_receipt_id": json_base_rec["receipt_id"],
            },
        )
        res_base = _unwrap_tool_response(out_base)
        assert res_base["replay"]["status"] == 200
        wire_base = seen[-1]
        assert wire_base["content_type"] == "application/json"
        assert json.loads(wire_base["body"]) == {"ok": True, "echo": seen[-2]}

        # 6. Explicit header_overrides Content-Type is respected when replacing body.
        out_custom_ct = disp.dispatch(
            "replay_as",
            {
                "receipt_id": mp_rid,
                "actor": "member_b",
                "json_overrides": {"patch": 1},
                "header_overrides": {"Content-Type": "application/merge-patch+json"},
            },
        )
        assert _unwrap_tool_response(out_custom_ct)["replay"]["status"] == 200
        assert seen[-1]["content_type"] == "application/merge-patch+json"
        assert json.loads(seen[-1]["body"]) == {"patch": 1}

        # 7. Non-multipart JSON POST replay remains 100% unaffected.
        out_normal = disp.dispatch(
            "replay_as",
            {"receipt_id": json_base_rec["receipt_id"], "actor": "member_b"},
        )
        assert _unwrap_tool_response(out_normal)["replay"]["status"] == 200
        assert seen[-1]["content_type"] == "application/json"
        assert json.loads(seen[-1]["body"]) == {"kind": "doc", "owner": "a"}
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_tool_schemas_invariants_preserved() -> None:
    serialized = json.dumps(TOOL_SCHEMAS, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(TOOL_SCHEMAS) == 11
    assert len(serialized) <= 16_384
