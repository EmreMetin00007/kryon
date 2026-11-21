"""Tests for persistent Write->Read (POST/PUT/PATCH -> GET) proof verification and ToolDispatcher isolation."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
from pathlib import Path
import sys
import threading
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import ToolDispatcher  # noqa: E402


def _make_persistence_server() -> tuple[str, dict[str, object], ThreadingHTTPServer]:
    state: dict[str, object] = {
        "items": {
            "1": {"comments": ["initial comment"], "escaped_comments": ["initial safe"], "note": "clean", "tier": "free"},
            "2": {"comments": ["hello"], "escaped_comments": ["hello"], "note": "clean", "tier": "free"},
        },
        "post_calls": 0,
        "patch_calls": 0,
        "get_calls": 0,
    }
    lock = threading.Lock()

    class _PersistenceHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def _send(
            self,
            status: int,
            payload: bytes,
            ctype: str = "text/html; charset=utf-8",
            headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            if headers:
                for k, v in headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path.rstrip("/") or "/"
            with lock:
                state["get_calls"] = int(state["get_calls"]) + 1
                items = state["items"]
                assert isinstance(items, dict)

                if path in {"/items/1", "/items/2"}:
                    item_id = path.rsplit("/", 1)[-1]
                    rec = items[item_id]
                    body_items = "".join(f"<li>{c}</li>" for c in rec["comments"])
                    html_doc = f"<html><body><h1>Item {item_id}</h1><ul>{body_items}</ul><p>{rec['note']}</p></body></html>"
                    self._send(200, html_doc.encode("utf-8"), ctype="text/html; charset=utf-8")
                    return

                if path in {"/escaped/1", "/escaped/2"}:
                    item_id = path.rsplit("/", 1)[-1]
                    rec = items[item_id]
                    body_items = "".join(f"<li>{html.escape(c)}</li>" for c in rec["escaped_comments"])
                    html_doc = f"<html><body><h1>Safe {item_id}</h1><ul>{body_items}</ul></body></html>"
                    self._send(200, html_doc.encode("utf-8"), ctype="text/html; charset=utf-8")
                    return

                if path == "/items/1/json-only":
                    rec = items["1"]
                    self._send(
                        200,
                        json.dumps({"comments": rec["comments"]}).encode("utf-8"),
                        ctype="application/json",
                    )
                    return

                if path == "/items/1/meta":
                    rec = items["1"]
                    self._send(
                        200,
                        json.dumps({"id": 1, "tier": rec["tier"], "note": rec["note"]}).encode("utf-8"),
                        ctype="application/json",
                    )
                    return

                if path.startswith("/static-xss"):
                    self._send(
                        200,
                        b"<html><body><div><svg/onload=1></div></body></html>",
                        ctype="text/html; charset=utf-8",
                    )
                    return

                if path == "/search-echo":
                    q = urlsplit(self.path).query
                    if "svg" in q or "%3C" in q or "<" in q:
                        self._send(200, b"<html><body><svg/onload=1></body></html>", ctype="text/html")
                    else:
                        self._send(200, b"<html><body>benign</body></html>", ctype="text/html")
                    return

                if path == "/api/check":
                    self._send(200, b'{"status":"ok","value":"alpha"}', ctype="application/json")
                    return

            self._send(404, b'{"error":"not_found"}', ctype="application/json")

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path.rstrip("/") or "/"
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
            try:
                data = json.loads(raw) if raw.strip().startswith("{") else {"comment": raw}
            except ValueError:
                data = {"comment": raw}

            with lock:
                state["post_calls"] = int(state["post_calls"]) + 1
                items = state["items"]
                assert isinstance(items, dict)

                if path in {"/items/1/comments", "/items/2/comments"}:
                    item_id = path.split("/")[2]
                    rec = items[item_id]
                    comment = str(data.get("comment") or data.get("body") or "")
                    rec["comments"].append(comment)
                    # Return a 302 redirect (or JSON ack) that does NOT echo rendered HTML.
                    if data.get("mode") == "json":
                        self._send(
                            201,
                            json.dumps({"ok": True, "item_id": item_id}).encode("utf-8"),
                            ctype="application/json",
                        )
                    else:
                        self._send(
                            302,
                            b"Redirecting...",
                            ctype="text/plain",
                            headers={"Location": f"/items/{item_id}"},
                        )
                    return

                if path in {"/escaped/1/comments", "/escaped/2/comments"}:
                    item_id = path.split("/")[2]
                    rec = items[item_id]
                    comment = str(data.get("comment") or "")
                    rec["escaped_comments"].append(comment)
                    # JSON ack echoes raw string, while follow-up HTML GET properly escapes it!
                    self._send(
                        201,
                        json.dumps({"ok": True, "stored": comment}).encode("utf-8"),
                        ctype="application/json",
                    )
                    return

                if path == "/items/1/json-only/comments":
                    rec = items["1"]
                    rec["comments"].append(str(data.get("comment") or ""))
                    self._send(201, b'{"ok":true}', ctype="application/json")
                    return

                if path == "/items/1/note":
                    rec = items["1"]
                    tpl = str(data.get("note") or "")
                    rec["note"] = "17689" if "{{133*133}}" in tpl else tpl
                    self._send(202, b'{"queued":true}', ctype="application/json")
                    return

            self._send(404, b'{"error":"not_found"}', ctype="application/json")

        def do_PATCH(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path.rstrip("/") or "/"
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            try:
                data = json.loads(raw)
            except ValueError:
                data = {}
            with lock:
                state["patch_calls"] = int(state["patch_calls"]) + 1
                items = state["items"]
                assert isinstance(items, dict)
                if path == "/items/1/meta":
                    rec = items["1"]
                    if "tier" in data:
                        rec["tier"] = str(data["tier"])
                    self._send(204, b"", ctype="text/plain")
                    return
            self._send(404, b'{"error":"not_found"}', ctype="application/json")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _PersistenceHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", state, srv


def _make_env(
    tmp_path: Path,
    base_url: str,
    *,
    with_oracle: bool = True,
    findings_path: Path | None = None,
    persist_findings: bool = True,
):
    store = ReceiptStore(tmp_path / "store")
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-alice"},
        {"alias": "bob", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-bob"},
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST", "PUT", "PATCH"),
        max_requests=80,
    )
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential") if with_oracle else None
    dispatcher = ToolDispatcher(
        http_client=client,
        receipt_store=store,
        root_dir=tmp_path,
        oracle=oracle,
        findings_path=findings_path,
        persist_findings=persist_findings,
    )
    return store, client, oracle, dispatcher


def test_stored_xss_write_then_read_verified_and_replays_get_only(tmp_path: Path) -> None:
    base_url, state, srv = _make_persistence_server()
    store, client, oracle, dispatcher = _make_env(tmp_path, base_url, with_oracle=True)
    assert oracle is not None
    try:
        baseline_get = client.request(method="GET", url="/items/1", actor="alice")
        assert baseline_get["status"] == 200
        assert "<svg/onload=1>" not in baseline_get["body"]

        # POST returns 302 redirect (does NOT echo HTML payload).
        post_write = client.request(
            method="POST",
            url="/items/1/comments",
            actor="alice",
            json_body={"comment": "<svg/onload=1>"},
        )
        assert post_write["status"] == 302
        assert state["post_calls"] == 1

        render_get = client.request(method="GET", url="/items/1", actor="alice", force=True)
        assert render_get["status"] == 200
        assert "<svg/onload=1>" in render_get["body"]

        # 1. Direct DifferentialOracle.verify() on Write -> Read proof pair:
        verdict = oracle.verify(
            canonical_class="stored_xss",
            primary_proof=post_write,
            proof_receipts=[post_write, render_get],
            control_receipts=[baseline_get],
            evidence_value="<svg/onload=1>",
        )
        assert verdict.verified is True
        assert verdict.verdict == "VERIFIED"
        assert verdict.stages["stage1_control"] == "passed"
        assert verdict.stages["stage2_diff"] == "passed"
        assert verdict.stages["stage3_clean_replay"] == "passed"
        # Clean replay MUST replay the GET render receipt, never re-posting duplicate POST mutations!
        assert state["post_calls"] == 1
        replay_rec = store.get(verdict.clean_replay_receipt_id)
        assert replay_rec["method"] == "GET"
        assert replay_rec["path"] == "/items/1"

        # 2. ToolDispatcher record_finding with [post_rid, get_rid]:
        res = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Stored XSS in item comments",
            "class_type": "stored_xss",
            "method": "POST",
            "url": "/items/1/comments",
            "actor_alias": "alice",
            "proof_receipt_ids": [post_write["receipt_id"], render_get["receipt_id"]],
            "control_receipt_ids": [baseline_get["receipt_id"]],
            "evidence_value": "<svg/onload=1>",
            "summary": "Comment payload submitted via POST renders unescaped in GET /items/1 HTML",
        }))
        assert res["accepted"] is True
        assert res["class_type"] == "stored_xss"
        assert state["post_calls"] == 1  # Still never re-executed POST during clean replay!
        saved = dispatcher.findings[-1]
        assert post_write["receipt_id"] in saved["proof_receipt_ids"]
        assert render_get["receipt_id"] in saved["proof_receipt_ids"]
        assert saved["oracle_verdict"] == "VERIFIED"
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_stored_xss_rejected_when_followup_get_html_escapes_or_non_html_or_in_baseline(tmp_path: Path) -> None:
    base_url, state, srv = _make_persistence_server()
    _store, client, oracle, dispatcher = _make_env(tmp_path, base_url, with_oracle=True)
    assert oracle is not None
    try:
        # Case A: Follow-up GET properly HTML-escapes &lt;svg/onload=1&gt;
        # (even though POST JSON ack echoed raw "<svg/onload=1>"!)
        base_esc = client.request(method="GET", url="/escaped/1", actor="alice")
        post_esc = client.request(
            method="POST",
            url="/escaped/1/comments",
            actor="alice",
            json_body={"comment": "<svg/onload=1>"},
        )
        assert post_esc["status"] == 201
        assert "<svg/onload=1>" in post_esc["body"]  # Raw string in JSON ack only!
        get_esc = client.request(method="GET", url="/escaped/1", actor="alice", force=True)
        assert get_esc["status"] == 200
        assert "&lt;svg/onload=1&gt;" in get_esc["body"]
        assert "<svg/onload=1>" not in get_esc["body"]

        # DifferentialOracle rejects escaped GET.
        v_esc = oracle.verify(
            canonical_class="stored_xss",
            primary_proof=post_esc,
            proof_receipts=[post_esc, get_esc],
            control_receipts=[base_esc],
            evidence_value="<svg/onload=1>",
        )
        assert v_esc.verified is False
        assert v_esc.verdict == "REFUTED"

        # record_finding rejects escaped GET (no FP).
        rec_esc = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Escaped stored XSS negative control",
            "class_type": "stored_xss",
            "method": "POST",
            "url": "/escaped/1/comments",
            "actor_alias": "alice",
            "proof_receipt_ids": [post_esc["receipt_id"], get_esc["receipt_id"]],
            "control_receipt_ids": [base_esc["receipt_id"]],
            "evidence_value": "<svg/onload=1>",
            "summary": "Escaped output should be rejected",
        }))
        assert rec_esc["rejected"] is True

        # Case B: Non-HTML (application/json) follow-up GET must be rejected for stored_xss.
        base_json = client.request(method="GET", url="/items/1/json-only", actor="alice")
        post_json = client.request(
            method="POST",
            url="/items/1/json-only/comments",
            actor="alice",
            json_body={"comment": "<svg/onload=1>"},
        )
        get_json = client.request(method="GET", url="/items/1/json-only", actor="alice", force=True)
        assert "<svg/onload=1>" in get_json["body"]
        rec_json = json.loads(dispatcher.dispatch("record_finding", {
            "title": "JSON content-type stored XSS FP",
            "class_type": "stored_xss",
            "method": "POST",
            "url": "/items/1/json-only/comments",
            "actor_alias": "alice",
            "proof_receipt_ids": [post_json["receipt_id"], get_json["receipt_id"]],
            "control_receipt_ids": [base_json["receipt_id"]],
            "evidence_value": "<svg/onload=1>",
            "summary": "JSON endpoint should not pass stored_xss",
        }))
        assert rec_json["rejected"] is True

        # Case C: Payload already present in baseline GET control -> rejected.
        static_base = client.request(method="GET", url="/static-xss", actor="alice")
        static_after = client.request(method="GET", url="/static-xss?v=2", actor="alice")
        rec_static = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Static baseline stored XSS FP",
            "class_type": "stored_xss",
            "method": "GET",
            "url": "/static-xss?v=2",
            "actor_alias": "alice",
            "proof_receipt_ids": [static_after["receipt_id"]],
            "control_receipt_ids": [static_base["receipt_id"]],
            "evidence_value": "<svg/onload=1>",
            "summary": "Static marker present in baseline",
        }))
        assert rec_static["rejected"] is True
        assert state["post_calls"] == 2
        assert dispatcher.findings == []
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_stored_xss_auto_attaches_followup_get_from_receipt_store(tmp_path: Path) -> None:
    base_url, state, srv = _make_persistence_server()
    _store, client, _oracle, dispatcher = _make_env(tmp_path, base_url, with_oracle=True)
    try:
        baseline_get = client.request(method="GET", url="/items/2", actor="alice")
        # JSON ack mode: POST returns 201 {"ok":true,"item_id":"2"} with no payload echo.
        post_write = client.request(
            method="POST",
            url="/items/2/comments",
            actor="alice",
            json_body={"comment": "<svg/onload=1>", "mode": "json"},
        )
        assert post_write["status"] == 201
        assert "<svg/onload=1>" not in post_write["body"]

        # Subsequent GET /items/2 is already in ReceiptStore, but caller passes ONLY [post_rid].
        render_get = client.request(method="GET", url="/items/2", actor="alice", force=True)
        assert "<svg/onload=1>" in render_get["body"]

        res = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Auto-attached stored XSS GET proof",
            "class_type": "stored_xss",
            "method": "POST",
            "url": "/items/2/comments",
            "actor_alias": "alice",
            "proof_receipt_ids": [post_write["receipt_id"]],
            "control_receipt_ids": [baseline_get["receipt_id"]],
            "evidence_value": "<svg/onload=1>",
            "summary": "Caller passed only POST receipt; ReceiptStore holds newer GET render receipt",
        }))
        assert res["accepted"] is True
        assert state["post_calls"] == 1
        saved = dispatcher.findings[-1]
        assert saved["proof_receipt_ids"] == [post_write["receipt_id"], render_get["receipt_id"]]
        assert saved["oracle_verdict"] == "VERIFIED"
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_ssti_and_mass_assignment_write_then_read_persistence(tmp_path: Path) -> None:
    base_url, state, srv = _make_persistence_server()
    _store, client, _oracle, dispatcher = _make_env(tmp_path, base_url, with_oracle=True)
    try:
        # 1. SSTI: POST /items/1/note (202 {"queued":true}) -> GET /items/1 (HTML containing 17689)
        base_html = client.request(method="GET", url="/items/1", actor="alice")
        post_ssti = client.request(
            method="POST",
            url="/items/1/note",
            actor="alice",
            json_body={"note": "{{133*133}}"},
        )
        assert post_ssti["status"] == 202
        get_ssti = client.request(method="GET", url="/items/1", actor="alice", force=True)
        assert "17689" in get_ssti["body"]

        res_ssti = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Persistent SSTI in item note",
            "class_type": "ssti",
            "method": "POST",
            "url": "/items/1/note",
            "actor_alias": "alice",
            "proof_receipt_ids": [post_ssti["receipt_id"]],
            "control_receipt_ids": [base_html["receipt_id"]],
            "evidence_value": "17689",
            "summary": "Template payload {{133*133}} evaluates to 17689 on follow-up GET /items/1",
        }))
        assert res_ssti["accepted"] is True
        assert state["post_calls"] == 1
        assert get_ssti["receipt_id"] in dispatcher.findings[-1]["proof_receipt_ids"]

        # 2. Mass assignment: PATCH /items/1/meta (204 empty) -> GET /items/1/meta (JSON with tier=enterprise)
        base_meta = client.request(method="GET", url="/items/1/meta", actor="alice")
        patch_meta = client.request(
            method="PATCH",
            url="/items/1/meta",
            actor="alice",
            json_body={"tier": "enterprise"},
        )
        assert patch_meta["status"] == 204
        get_meta = client.request(method="GET", url="/items/1/meta", actor="alice", force=True)
        assert "enterprise" in get_meta["body"]

        res_ma = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Mass assignment on item tier",
            "class_type": "mass_assignment",
            "method": "PATCH",
            "url": "/items/1/meta",
            "actor_alias": "alice",
            "proof_receipt_ids": [patch_meta["receipt_id"], get_meta["receipt_id"]],
            "control_receipt_ids": [base_meta["receipt_id"]],
            "evidence_value": "enterprise",
            "summary": "PATCH 204 silently elevates tier to enterprise confirmed via GET",
        }))
        assert res_ma["accepted"] is True
        assert state["patch_calls"] == 1
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_tool_dispatcher_findings_path_isolation_and_thread_safety(tmp_path: Path) -> None:
    base_url, _state, srv = _make_persistence_server()
    shared_root = tmp_path / "shared"
    shared_root.mkdir(parents=True, exist_ok=True)
    shard_a_path = shared_root / "shards" / "shard_a_findings.json"
    shard_b_path = shared_root / "shards" / "shard_b_findings.json"

    store_a, client_a, _, disp_a = _make_env(shared_root, base_url, with_oracle=False, findings_path=shard_a_path)
    store_b, client_b, _, disp_b = _make_env(shared_root, base_url, with_oracle=False, findings_path=shard_b_path)
    _store_mem, client_mem, _, disp_mem = _make_env(
        shared_root,
        base_url,
        with_oracle=False,
        persist_findings=False,
    )
    try:
        # 1. Shard isolation: shard_a and shard_b write to their own findings_path without touching shared_root/findings.json.
        ctrl_a = client_a.request(method="GET", url="/search-echo?q=benign", actor="alice")
        proof_a = client_a.request(method="GET", url="/search-echo?q=%3Csvg/onload=1%3E", actor="alice")
        res_a = json.loads(disp_a.dispatch("record_finding", {
            "title": "Shard A finding",
            "class_type": "reflected_xss",
            "method": "GET",
            "url": "/search-echo?q=%3Csvg/onload=1%3E",
            "actor_alias": "alice",
            "proof_receipt_ids": [proof_a["receipt_id"]],
            "control_receipt_ids": [ctrl_a["receipt_id"]],
            "evidence_value": "<svg/onload=1>",
            "summary": "Shard A XSS",
        }))
        assert res_a["accepted"] is True

        ctrl_b = client_b.request(method="GET", url="/api/check", actor="bob")
        proof_b = store_b.record(
            actor="bob",
            method="GET",
            url=f"{base_url}/api/leaked-secret",
            path="/api/leaked-secret",
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"secret":"tok_9988776655443322"}',
            response_text='{"secret":"tok_9988776655443322"}',
        )
        res_b = json.loads(disp_b.dispatch("record_finding", {
            "title": "Shard B finding",
            "class_type": "info_disclosure",
            "method": "GET",
            "url": "/api/leaked-secret",
            "actor_alias": "bob",
            "proof_receipt_ids": [proof_b["receipt_id"]],
            "control_receipt_ids": [ctrl_b["receipt_id"]],
            "evidence_value": "tok_9988776655443322",
            "summary": "Shard B disclosure",
        }))
        assert res_b["accepted"] is True

        assert not (shared_root / "findings.json").exists()
        data_a = json.loads(shard_a_path.read_text(encoding="utf-8"))
        data_b = json.loads(shard_b_path.read_text(encoding="utf-8"))
        assert len(data_a) == 1 and data_a[0]["title"] == "Shard A finding"
        assert len(data_b) == 1 and data_b[0]["title"] == "Shard B finding"

        # 2. persist_findings=False keeps findings strictly in memory and never touches disk.
        ctrl_m = client_mem.request(method="GET", url="/search-echo?q=benign", actor="alice")
        proof_m = client_mem.request(method="GET", url="/search-echo?q=%3Csvg/onload=1%3E", actor="alice")
        res_m = json.loads(disp_mem.dispatch("record_finding", {
            "title": "Memory only finding",
            "class_type": "reflected_xss",
            "method": "GET",
            "url": "/search-echo?q=%3Csvg/onload=1%3E",
            "actor_alias": "alice",
            "proof_receipt_ids": [proof_m["receipt_id"]],
            "control_receipt_ids": [ctrl_m["receipt_id"]],
            "evidence_value": "<svg/onload=1>",
            "summary": "In-memory only",
        }))
        assert res_m["accepted"] is True
        assert len(disp_mem.findings) == 1
        assert not (shared_root / "findings.json").exists()

        # 3. Concurrent record_finding calls on a single ToolDispatcher remain race-free & lossless.
        concurrent_path = tmp_path / "concurrent_findings.json"
        store_c, client_c, _, disp_c = _make_env(
            tmp_path / "conc",
            base_url,
            with_oracle=False,
            findings_path=concurrent_path,
        )
        try:
            c_ctrl = client_c.request(method="GET", url="/api/check", actor="alice")
            seg_names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"]
            items_to_record: list[tuple[int, str, dict[str, object]]] = []
            for idx, seg in enumerate(seg_names):
                tok = f"sec_{idx:02d}_abcdef0123456789"
                rec = store_c.record(
                    actor="alice",
                    method="GET",
                    url=f"{base_url}/api/{seg}/secret",
                    path=f"/api/{seg}/secret",
                    status=200,
                    elapsed_ms=1.0,
                    content_type="application/json",
                    raw_response_bytes=json.dumps({"secret": tok}).encode("utf-8"),
                    response_text=json.dumps({"secret": tok}),
                )
                items_to_record.append((idx, seg, rec))

            def _submit(item: tuple[int, str, dict[str, object]]) -> dict[str, object]:
                idx, seg, rec = item
                tok = f"sec_{idx:02d}_abcdef0123456789"
                return json.loads(disp_c.dispatch("record_finding", {
                    "title": f"Concurrent leak {idx}",
                    "class_type": "info_disclosure",
                    "method": "GET",
                    "url": f"/api/{seg}/secret",
                    "actor_alias": "alice",
                    "proof_receipt_ids": [str(rec["receipt_id"])],
                    "control_receipt_ids": [c_ctrl["receipt_id"]],
                    "evidence_value": tok,
                    "summary": f"Concurrent leak {idx}",
                }))

            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(_submit, items_to_record))

            assert all(r.get("accepted") is True for r in results)
            assert len(disp_c.findings) == 8
            persisted = json.loads(concurrent_path.read_text(encoding="utf-8"))
            assert len(persisted) == 8
            assert len({f["finding_id"] for f in persisted}) == 8
        finally:
            client_c.close()
    finally:
        client_a.close()
        client_b.close()
        client_mem.close()
        srv.shutdown()
        srv.server_close()
