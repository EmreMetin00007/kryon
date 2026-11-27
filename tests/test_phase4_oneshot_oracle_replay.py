"""Tests for Faz 4B: Idempotent Verification for Non-Idempotent HTTP State Transitions in Stage 3 Replay."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_oracle import (  # noqa: E402
    DifferentialOracle,
    _is_one_shot_create_conflict,
    _is_unrelated_route_not_found,
)
from agentic_receipts import ReceiptStore  # noqa: E402


def _start_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[str, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", srv


def _stop_server(srv: ThreadingHTTPServer) -> None:
    srv.shutdown()
    srv.server_close()


def _make_oracle_env(
    tmp_path: Path,
    base_url: str,
    *,
    accounts: list[dict[str, Any]] | None = None,
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
    max_requests: int = 80,
) -> tuple[ReceiptStore, AgenticHTTPClient, DifferentialOracle, dict[str, dict[str, str]]]:
    acct_list = (
        accounts
        if accounts is not None
        else [
            {"alias": "alice", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-alice"},
            {"alias": "bob", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-bob"},
            {"alias": "charlie", "role": "member", "tenant": "alpha", "auth_header": "Bearer tok-charlie"},
            {"alias": "admin", "role": "admin", "tenant": "alpha", "auth_header": "Bearer tok-admin"},
        ]
    )
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager(acct_list)
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=allowed_methods,
        max_requests=max_requests,
    )
    oracle = DifferentialOracle(
        http_client=client,
        receipt_store=store,
        mode="differential",
    )
    actor_meta = {
        str(a["alias"]): {"role": str(a.get("role") or ""), "tenant": str(a.get("tenant") or "")}
        for a in acct_list
    }
    return store, client, oracle, actor_meta


# ---------------------------------------------------------------------------
# Unit tests for Stage 3 state-transition helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (409, '{"error":"conflict"}', True),
        (409, "", True),
        (400, '{"error":"User already exists"}', True),
        (400, '{"code":"EMAIL_ALREADY_EXISTS"}', True),
        (400, '{"detail":"Username is already taken"}', True),
        (400, '{"error":"duplicate_entry","field":"email"}', True),
        (400, '{"message":"Resource conflict on slug"}', True),
        (400, '{"error":"validation_error","detail":"missing required field email"}', False),
        (400, '{"error":"invalid_json"}', False),
        (400, "", False),
        (422, '{"error":"already exists"}', True),
        (422, '{"error":"validation_error","detail":"invalid field"}', False),
        (403, '{"error":"conflict"}', False),
        (500, '{"error":"duplicate"}', False),
        (201, '{"status":"created"}', False),
    ],
)
def test_is_one_shot_create_conflict_helper(status: int, body: str, expected: bool) -> None:
    assert _is_one_shot_create_conflict({"status": status, "body": body}) is expected


@pytest.mark.parametrize(
    ("body", "method", "expected"),
    [
        ("Cannot DELETE /api/items/42", "DELETE", True),
        ("<!doctype html><p>The requested URL was not found on the server.</p>", "DELETE", True),
        ('{"error":"route not found"}', "DELETE", True),
        ('{"error":"unknown endpoint"}', "DELETE", True),
        ("404 page not found\n", "DELETE", True),
        ('{"error":"not_found"}', "DELETE", False),
        ('{"detail":"Item 42 not found"}', "DELETE", False),
        ('{"error":"gone"}', "DELETE", False),
        ("", "DELETE", False),
    ],
)
def test_is_unrelated_route_not_found_helper(body: str, method: str, expected: bool) -> None:
    assert _is_unrelated_route_not_found({"status": 404, "body": body}, method) is expected


# ---------------------------------------------------------------------------
# Case A: Single-use DELETE (2xx -> 404/410 on clean replay)
# ---------------------------------------------------------------------------


def test_case_a_one_shot_delete_positive_scenarios(tmp_path: Path) -> None:
    lock = threading.Lock()
    items: dict[str, dict[str, Any]] = {
        "10": {"id": "10", "owner": "alice", "secret": "ITEM_10_SECRET"},
        "20": {"id": "20", "owner": "alice", "secret": "ITEM_20_FROM_LIST"},
        "30": {"id": "30", "owner": "alice", "secret": "ITEM_30_DELETE_ONLY"},
        "40": {"id": "40", "owner": "alice", "secret": "ITEM_40_PRE_GET"},
    }
    gone_ids: set[str] = set()
    next_id = {"val": 100}

    class _DeleteStateHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _actor(self) -> str:
            auth = self.headers.get("Authorization", "")
            mapping = {
                "Bearer tok-alice": "alice",
                "Bearer tok-bob": "bob",
                "Bearer tok-charlie": "charlie",
                "Bearer tok-admin": "admin",
            }
            return mapping.get(auth, "anon")

        def _send_json(self, status: int, obj: Any | None) -> None:
            payload = b"" if obj is None else json.dumps(obj).encode("utf-8")
            self.send_response(status)
            if obj is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            if payload:
                self.wfile.write(payload)

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            data = json.loads(raw) if raw.strip().startswith("{") else {}
            if path == "/api/items":
                with lock:
                    nid = str(next_id["val"])
                    next_id["val"] += 1
                    rec = {
                        "id": nid,
                        "owner": self._actor(),
                        "secret": str(data.get("secret") or f"CREATED_SECRET_{nid}"),
                        "gone_on_delete": bool(data.get("gone_on_delete")),
                    }
                    items[nid] = rec
                self._send_json(201, rec)
                return
            self._send_json(404, {"error": "not_found"})

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            actor = self._actor()
            if path == "/api/items":
                with lock:
                    listing = [v for k, v in items.items() if k != "30"]
                self._send_json(200, {"items": listing})
                return
            if path.startswith("/api/delete-only/"):
                self._send_json(405, {"error": "method_not_allowed"})
                return
            if path.startswith("/api/items/"):
                item_id = path.rsplit("/", 1)[-1]
                if actor == "anon":
                    self._send_json(401, {"error": "unauthorized"})
                    return
                with lock:
                    if item_id in gone_ids:
                        self._send_json(410, {"error": "gone"})
                        return
                    rec = items.get(item_id)
                if rec is None:
                    self._send_json(404, {"error": "not_found"})
                    return
                self._send_json(200, rec)
                return
            self._send_json(404, {"error": "not_found"})

        def do_DELETE(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            actor = self._actor()
            if actor == "anon":
                self._send_json(401, {"error": "unauthorized"})
                return
            if actor == "charlie":
                self._send_json(403, {"error": "forbidden"})
                return
            if path.startswith("/api/delete-only/"):
                item_id = path.rsplit("/", 1)[-1]
                with lock:
                    rec = items.pop(item_id, None)
                if rec is None:
                    self._send_json(404, {"error": "not_found"})
                    return
                self._send_json(200, {"deleted": True, "id": item_id})
                return
            if path.startswith("/api/items/"):
                item_id = path.rsplit("/", 1)[-1]
                with lock:
                    if item_id in gone_ids:
                        self._send_json(410, {"error": "already_gone"})
                        return
                    rec = items.pop(item_id, None)
                    if rec is None:
                        self._send_json(404, {"error": "not_found"})
                        return
                    if rec.get("gone_on_delete"):
                        gone_ids.add(item_id)
                        self._send_json(204, None)
                        return
                self._send_json(200, {"deleted": True, "id": item_id})
                return
            self._send_json(404, {"error": "not_found"})

    base_url, srv = _start_server(_DeleteStateHandler)
    store, client, oracle, actor_meta = _make_oracle_env(tmp_path, base_url)
    try:
        # A1: No prior GET, same-path 403 control, DELETE 200 -> replay 404 + clean GET readback 404.
        ctrl_10 = client.request(method="DELETE", url="/api/items/10", actor="charlie")
        assert ctrl_10["status"] == 403
        del_10 = client.request(method="DELETE", url="/api/items/10", actor="bob")
        assert del_10["status"] == 200
        v_a1 = oracle.verify(
            canonical_class="bola",
            primary_proof=del_10,
            proof_receipts=[del_10],
            control_receipts=[ctrl_10],
            evidence_value="deleted",
            actor_meta_map=actor_meta,
            inferred_owner="alice",
        )
        assert v_a1.verified is True
        assert v_a1.verdict == "VERIFIED"
        assert v_a1.stages["stage1_control"] == "passed"
        assert v_a1.stages["stage2_diff"] == "passed"
        assert v_a1.stages["stage3_clean_replay"] == "passed_one_shot_delete_state_transition"
        assert store.get(v_a1.clean_replay_receipt_id)["method"] == "GET"
        assert store.get(v_a1.clean_replay_receipt_id)["status"] == 404

        # A2: Prior POST create (201) -> DELETE 204 (empty body) -> replay 410 + clean GET readback 410.
        created = client.request(
            method="POST",
            url="/api/items",
            actor="alice",
            json_body={"secret": "CREATED_SECRET_100", "gone_on_delete": True},
        )
        assert created["status"] == 201
        cid = json.loads(created["body"])["id"]
        ctrl_created = client.request(method="DELETE", url=f"/api/items/{cid}", actor="charlie")
        assert ctrl_created["status"] == 403
        del_created = client.request(method="DELETE", url=f"/api/items/{cid}", actor="bob")
        assert del_created["status"] == 204
        v_a2 = oracle.verify(
            canonical_class="bola",
            primary_proof=del_created,
            proof_receipts=[del_created],
            control_receipts=[ctrl_created],
            evidence_value="CREATED_SECRET_100",
            actor_meta_map=actor_meta,
            inferred_owner="alice",
        )
        assert v_a2.verified is True
        assert v_a2.stages["stage3_clean_replay"] == "passed_one_shot_delete_state_transition"
        assert store.get(v_a2.clean_replay_receipt_id)["status"] == 410

        # A3: DELETE-only endpoint where GET returns 405, corroborated by same-path 401 control.
        ctrl_30 = client.request(method="DELETE", url="/api/delete-only/30", actor="anon")
        assert ctrl_30["status"] == 401
        del_30 = client.request(method="DELETE", url="/api/delete-only/30", actor="bob")
        assert del_30["status"] == 200
        v_a3 = oracle.verify(
            canonical_class="bfla",
            primary_proof=del_30,
            proof_receipts=[del_30],
            control_receipts=[ctrl_30],
            evidence_value="deleted",
            actor_meta_map=actor_meta,
        )
        assert v_a3.verified is True
        assert v_a3.stages["stage3_clean_replay"] == "passed_one_shot_delete_state_transition"
        assert store.get(v_a3.clean_replay_receipt_id)["status"] == 404

        # A4: Prior collection GET listing item 20 -> DELETE 200 -> replay 404 + clean GET 404.
        list_rec = client.request(method="GET", url="/api/items", actor="alice")
        assert list_rec["status"] == 200
        ctrl_20 = client.request(method="DELETE", url="/api/items/20", actor="charlie")
        del_20 = client.request(method="DELETE", url="/api/items/20", actor="bob")
        assert del_20["status"] == 200
        v_a4 = oracle.verify(
            canonical_class="bola",
            primary_proof=del_20,
            proof_receipts=[del_20],
            control_receipts=[ctrl_20],
            evidence_value="deleted",
            actor_meta_map=actor_meta,
            inferred_owner="alice",
        )
        assert v_a4.verified is True
        assert v_a4.stages["stage3_clean_replay"] == "passed_one_shot_delete_state_transition"
        assert store.get(v_a4.clean_replay_receipt_id)["status"] == 404

        # A5: proof_receipts contains [prior_get, delete_rec] -> does NOT replay pre-DELETE GET; verifies cleanly.
        pre_get_40 = client.request(method="GET", url="/api/items/40", actor="alice")
        assert pre_get_40["status"] == 200
        ctrl_40 = client.request(method="DELETE", url="/api/items/40", actor="charlie")
        del_40 = client.request(method="DELETE", url="/api/items/40", actor="bob")
        assert del_40["status"] == 200
        v_a5 = oracle.verify(
            canonical_class="bola",
            primary_proof=del_40,
            proof_receipts=[pre_get_40, del_40],
            control_receipts=[ctrl_40],
            evidence_value="deleted",
            actor_meta_map=actor_meta,
            inferred_owner="alice",
        )
        assert v_a5.verified is True
        assert v_a5.stages["stage3_clean_replay"] == "passed_delete_persistence"
    finally:
        client.close()
        _stop_server(srv)


def test_case_a_one_shot_delete_negative_fail_closed_guards(tmp_path: Path) -> None:
    still_alive_deleted_once = {"done": False}
    deleted_ids: set[str] = set()

    class _NegDeleteHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path == "/api/items/alive":
                self._send(200, b'{"id":"alive","owner":"alice"}')
                return
            if path == "/api/items/evcheck" and "evcheck" not in deleted_ids:
                self._send(200, b'{"id":"evcheck","owner":"alice"}')
                return
            self._send(404, b'{"error":"not_found"}')

        def do_DELETE(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer tok-charlie":
                self._send(403, b'{"error":"forbidden"}')
                return
            if path == "/api/items/alive":
                if not still_alive_deleted_once["done"]:
                    still_alive_deleted_once["done"] = True
                    self._send(200, b'{"deleted":true,"id":"alive"}')
                else:
                    self._send(404, b'{"error":"not_found_for_bob"}')
                return
            if path == "/api/items/evcheck":
                if "evcheck" not in deleted_ids:
                    deleted_ids.add("evcheck")
                    self._send(200, b'{"deleted":true,"id":"evcheck"}')
                else:
                    self._send(404, b'{"error":"not_found"}')
                return
            if path == "/api/route-err/77":
                # Express-style missing route error on replay!
                self._send(404, b"Cannot DELETE /api/route-err/77", ctype="text/plain")
                return
            self._send(404, b'{"error":"not_found"}')

    base_url, srv = _start_server(_NegDeleteHandler)
    store, client, oracle, actor_meta = _make_oracle_env(tmp_path, base_url)
    try:
        # AN1: Resource still alive on clean GET readback -> REFUTED even with same-path 403 control!
        ctrl_alive = client.request(method="DELETE", url="/api/items/alive", actor="charlie")
        del_alive = client.request(method="DELETE", url="/api/items/alive", actor="bob")
        assert del_alive["status"] == 200
        v_alive = oracle.verify(
            canonical_class="bola",
            primary_proof=del_alive,
            proof_receipts=[del_alive],
            control_receipts=[ctrl_alive],
            evidence_value="deleted",
            actor_meta_map=actor_meta,
            inferred_owner="alice",
        )
        assert v_alive.verified is False
        assert v_alive.verdict == "REFUTED"
        assert v_alive.stages["stage3_clean_replay"] == "failed_status_404"

        # AN2: Hallucinated evidence_value not in original 200 DELETE receipt -> REFUTED!
        ctrl_ev = client.request(method="DELETE", url="/api/items/evcheck", actor="charlie")
        del_ev = client.request(method="DELETE", url="/api/items/evcheck", actor="bob")
        assert del_ev["status"] == 200
        v_bad_ev = oracle.verify(
            canonical_class="bola",
            primary_proof=del_ev,
            proof_receipts=[del_ev],
            control_receipts=[ctrl_ev],
            evidence_value="COMPLETELY_HALLUCINATED_MARKER",
            actor_meta_map=actor_meta,
            inferred_owner="alice",
        )
        assert v_bad_ev.verified is False
        assert v_bad_ev.verdict == "REFUTED"
        assert v_bad_ev.stages["stage3_clean_replay"] == "failed_status_404"

        # AN3: Unrelated route error ("Cannot DELETE ...") on 404 replay -> REFUTED!
        ctrl_route = client.request(method="DELETE", url="/api/route-err/77", actor="charlie")
        synth_del_route = store.record(
            actor="bob",
            method="DELETE",
            url=f"{base_url}/api/route-err/77",
            path="/api/route-err/77",
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"deleted":true}',
            response_text='{"deleted":true}',
        )
        v_route = oracle.verify(
            canonical_class="bfla",
            primary_proof=synth_del_route,
            proof_receipts=[synth_del_route],
            control_receipts=[ctrl_route],
            evidence_value="deleted",
            actor_meta_map=actor_meta,
        )
        assert v_route.verified is False
        assert v_route.verdict == "REFUTED"
        assert v_route.stages["stage3_clean_replay"] == "failed_status_404"

        # AN4: Original DELETE is NOT 2xx (e.g. 500) -> REFUTED!
        synth_500 = store.record(
            actor="bob",
            method="DELETE",
            url=f"{base_url}/api/items/evcheck",
            path="/api/items/evcheck",
            status=500,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"error":"deleted"}',
            response_text='{"error":"deleted"}',
        )
        v_500 = oracle.verify(
            canonical_class="bfla",
            primary_proof=synth_500,
            proof_receipts=[synth_500],
            control_receipts=[ctrl_ev],
            evidence_value="deleted",
            actor_meta_map=actor_meta,
        )
        assert v_500.verified is False
        assert v_500.verdict == "REFUTED"
        assert v_500.stages["stage3_clean_replay"] == "failed_status_404"

        # AN5: No prior observation and control is on a DIFFERENT path -> REFUTED!
        synth_unrelated = store.record(
            actor="bob",
            method="DELETE",
            url=f"{base_url}/api/items/never-existed",
            path="/api/items/never-existed",
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"deleted":true}',
            response_text='{"deleted":true}',
        )
        v_unrelated = oracle.verify(
            canonical_class="bfla",
            primary_proof=synth_unrelated,
            proof_receipts=[synth_unrelated],
            control_receipts=[ctrl_ev],  # /api/items/evcheck != /api/items/never-existed
            evidence_value="deleted",
            actor_meta_map=actor_meta,
        )
        assert v_unrelated.verified is False
        assert v_unrelated.verdict == "REFUTED"
        assert v_unrelated.stages["stage3_clean_replay"] == "failed_status_404"

        # AN6: Stage 2 failure (admin actor for BFLA) blocks before Stage 3!
        admin_del = store.record(
            actor="admin",
            method="DELETE",
            url=f"{base_url}/api/items/evcheck",
            path="/api/items/evcheck",
            status=200,
            elapsed_ms=1.0,
            content_type="application/json",
            raw_response_bytes=b'{"deleted":true}',
            response_text='{"deleted":true}',
        )
        v_stage2 = oracle.verify(
            canonical_class="bfla",
            primary_proof=admin_del,
            proof_receipts=[admin_del],
            control_receipts=[ctrl_ev],
            evidence_value="deleted",
            actor_meta_map=actor_meta,
        )
        assert v_stage2.verified is False
        assert v_stage2.stages["stage2_diff"] == "failed_admin_actor_for_bfla"
        assert "stage3_clean_replay" not in v_stage2.stages
    finally:
        client.close()
        _stop_server(srv)


# ---------------------------------------------------------------------------
# Case B: Single-use POST create (200/201 -> 409 or 400 conflict/duplicate)
# ---------------------------------------------------------------------------


def test_case_b_one_shot_post_create_conflict_positive_and_negative(tmp_path: Path) -> None:
    lock = threading.Lock()
    created_keys: set[str] = set()

    class _CreateConflictHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _actor(self) -> str:
            auth = self.headers.get("Authorization", "")
            return {
                "Bearer tok-alice": "alice",
                "Bearer tok-bob": "bob",
                "Bearer tok-charlie": "charlie",
                "Bearer tok-admin": "admin",
            }.get(auth, "anon")

        def _send_json(self, status: int, obj: Any | None) -> None:
            payload = b"" if obj is None else json.dumps(obj).encode("utf-8")
            self.send_response(status)
            if obj is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            if payload:
                self.wfile.write(payload)

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            actor = self._actor()
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            data = json.loads(raw) if raw.strip().startswith("{") else {}
            key = str(data.get("slug") or "")
            mode = str(data.get("mode") or "409")

            if actor == "anon":
                self._send_json(401, {"error": "unauthorized"})
                return
            if actor == "charlie":
                self._send_json(403, {"error": "forbidden"})
                return

            if path == "/api/projects":
                with lock:
                    if key in created_keys:
                        if mode == "409":
                            self._send_json(409, {"error": "project_conflict", "slug": key})
                        elif mode == "400_exists":
                            self._send_json(400, {"error": "Project already exists"})
                        elif mode == "400_taken":
                            self._send_json(400, {"detail": "Slug is already taken"})
                        elif mode == "400_dup":
                            self._send_json(400, {"error": "duplicate_key"})
                        elif mode == "400_conflict":
                            self._send_json(400, {"message": "Resource conflict"})
                        elif mode == "400_generic":
                            self._send_json(400, {"error": "validation_error", "detail": "invalid payload"})
                        elif mode == "422_dup":
                            self._send_json(422, {"error": "already exists"})
                        elif mode == "422_generic":
                            self._send_json(422, {"error": "validation_error", "detail": "invalid field"})
                        elif mode == "500":
                            self._send_json(500, {"error": "internal_server_error"})
                        return
                    created_keys.add(key)
                if mode == "204_orig":
                    self._send_json(204, None)
                    return
                ok_status = 200 if mode == "400_exists" else 201
                self._send_json(ok_status, {"created": True, "slug": key, "role": "admin"})
                return
            self._send_json(404, {"error": "not_found"})

    base_url, srv = _start_server(_CreateConflictHandler)
    store, client, oracle, actor_meta = _make_oracle_env(tmp_path, base_url)
    try:
        ctrl_403 = client.request(
            method="POST",
            url="/api/projects",
            actor="charlie",
            json_body={"slug": "ctrl-proj"},
        )
        assert ctrl_403["status"] == 403

        # B1: POST 201 -> replay 409 Conflict -> VERIFIED!
        p_409 = client.request(
            method="POST",
            url="/api/projects",
            actor="bob",
            json_body={"slug": "proj-409", "mode": "409"},
        )
        assert p_409["status"] == 201
        v_409 = oracle.verify(
            canonical_class="bfla",
            primary_proof=p_409,
            proof_receipts=[p_409],
            control_receipts=[ctrl_403],
            evidence_value="proj-409",
            actor_meta_map=actor_meta,
        )
        assert v_409.verified is True
        assert v_409.verdict == "VERIFIED"
        assert v_409.stages["stage1_control"] == "passed"
        assert v_409.stages["stage2_diff"] == "passed"
        assert v_409.stages["stage3_clean_replay"] == "passed_one_shot_create_conflict"
        assert store.get(v_409.clean_replay_receipt_id)["status"] == 409

        # B2 & B3: POST 200/201 -> replay 400 with explicit duplicate/conflict indicators -> VERIFIED!
        for mode in ("400_exists", "400_taken", "400_dup", "400_conflict"):
            slug = f"proj-{mode}"
            p_rec = client.request(
                method="POST",
                url="/api/projects",
                actor="bob",
                json_body={"slug": slug, "mode": mode},
            )
            assert p_rec["status"] in {200, 201}
            v_ok = oracle.verify(
                canonical_class="bfla",
                primary_proof=p_rec,
                proof_receipts=[p_rec],
                control_receipts=[ctrl_403],
                evidence_value=slug,
                actor_meta_map=actor_meta,
            )
            assert v_ok.verified is True, f"Expected VERIFIED for mode={mode}: {v_ok}"
            assert v_ok.stages["stage3_clean_replay"] == "passed_one_shot_create_conflict"
            assert store.get(v_ok.clean_replay_receipt_id)["status"] == 400

        # BN1: Generic 400 validation error WITHOUT conflict indicator -> REFUTED!
        p_gen = client.request(
            method="POST",
            url="/api/projects",
            actor="bob",
            json_body={"slug": "proj-generic-400", "mode": "400_generic"},
        )
        assert p_gen["status"] == 201
        v_gen = oracle.verify(
            canonical_class="bfla",
            primary_proof=p_gen,
            proof_receipts=[p_gen],
            control_receipts=[ctrl_403],
            evidence_value="proj-generic-400",
            actor_meta_map=actor_meta,
        )
        assert v_gen.verified is False
        assert v_gen.verdict == "REFUTED"
        assert v_gen.stages["stage3_clean_replay"] == "failed_status_400"

        # BN2: Missing/hallucinated evidence_value on original POST -> REFUTED!
        v_missing_ev = oracle.verify(
            canonical_class="bfla",
            primary_proof=p_409,
            proof_receipts=[p_409],
            control_receipts=[ctrl_403],
            evidence_value="NOT_IN_ORIGINAL_POST_RECEIPT",
            actor_meta_map=actor_meta,
        )
        assert v_missing_ev.verified is False
        assert v_missing_ev.verdict == "REFUTED"
        assert v_missing_ev.stages["stage3_clean_replay"] == "failed_status_409"

        # BN3: Non-200/201 original POST (e.g. 204 or 500) -> REFUTED!
        p_204 = client.request(
            method="POST",
            url="/api/projects",
            actor="bob",
            json_body={"slug": "proj-204-orig", "mode": "204_orig"},
        )
        assert p_204["status"] == 204
        v_204 = oracle.verify(
            canonical_class="bfla",
            primary_proof=p_204,
            proof_receipts=[p_204],
            control_receipts=[ctrl_403],
            evidence_value="",
            actor_meta_map=actor_meta,
        )
        assert v_204.verified is False
        assert v_204.verdict == "REFUTED"

        # B4: POST 201 -> replay 422 with explicit conflict wording -> VERIFIED!
        p_422_dup = client.request(
            method="POST",
            url="/api/projects",
            actor="bob",
            json_body={"slug": "proj-422_dup", "mode": "422_dup"},
        )
        assert p_422_dup["status"] == 201
        v_422_dup = oracle.verify(
            canonical_class="bfla",
            primary_proof=p_422_dup,
            proof_receipts=[p_422_dup],
            control_receipts=[ctrl_403],
            evidence_value="proj-422_dup",
            actor_meta_map=actor_meta,
        )
        assert v_422_dup.verified is True
        assert v_422_dup.stages["stage3_clean_replay"] == "passed_one_shot_create_conflict"

        # BN4: Replay status generic 422 (no conflict indicator) or 500 -> REFUTED!
        for mode, exp_stage in (("422_generic", "failed_status_422"), ("500", "failed_status_500")):
            p_other = client.request(
                method="POST",
                url="/api/projects",
                actor="bob",
                json_body={"slug": f"proj-{mode}", "mode": mode},
            )
            assert p_other["status"] == 201
            v_other = oracle.verify(
                canonical_class="bfla",
                primary_proof=p_other,
                proof_receipts=[p_other],
                control_receipts=[ctrl_403],
                evidence_value=f"proj-{mode}",
                actor_meta_map=actor_meta,
            )
            assert v_other.verified is False
            assert v_other.verdict == "REFUTED"
            assert v_other.stages["stage3_clean_replay"] == exp_stage

        # BN5: Stage 1 / Stage 2 failure (deception_identical_control & admin BFLA) blocks before Stage 3!
        v_stage1_fail = oracle.verify(
            canonical_class="mass_assignment",
            primary_proof=p_409,
            proof_receipts=[p_409],
            control_receipts=[p_409],
            evidence_value="proj-409",
            actor_meta_map=actor_meta,
        )
        assert v_stage1_fail.verified is False
        assert v_stage1_fail.verdict == "DECEPTION_DETECTED"
        assert v_stage1_fail.stages["stage1_control"] == "deception_identical_control"
        assert "stage3_clean_replay" not in v_stage1_fail.stages

        p_admin = client.request(
            method="POST",
            url="/api/projects",
            actor="admin",
            json_body={"slug": "proj-admin-409", "mode": "409"},
        )
        assert p_admin["status"] == 201
        v_stage2_fail = oracle.verify(
            canonical_class="bfla",
            primary_proof=p_admin,
            proof_receipts=[p_admin],
            control_receipts=[ctrl_403],
            evidence_value="proj-admin-409",
            actor_meta_map=actor_meta,
        )
        assert v_stage2_fail.verified is False
        assert v_stage2_fail.stages["stage2_diff"] == "failed_admin_actor_for_bfla"
        assert "stage3_clean_replay" not in v_stage2_fail.stages
    finally:
        client.close()
        _stop_server(srv)


def test_empty_body_write_readback_in_store_and_json_whitespace_evidence(tmp_path: Path) -> None:
    lock = threading.Lock()
    state: dict[str, Any] = {}

    class _SettingsHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _send(self, status: int, body: str, ctype: str = "application/json") -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            if body:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            if data:
                self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            if urlsplit(self.path).path == "/settings":
                with lock:
                    body = json.dumps(state)
                self._send(200, body)
                return
            self._send(404, '{"error": "not_found"}')

        def do_POST(self) -> None:  # noqa: N802
            if urlsplit(self.path).path == "/settings":
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
                data = json.loads(raw)
                with lock:
                    state.update(data)
                self._send(200, "")
                return
            self._send(404, '{"error": "not_found"}')

    base_url, srv = _start_server(_SettingsHandler)
    try:
        store = ReceiptStore(tmp_path)
        actors = ActorManager([])
        client = AgenticHTTPClient(
            base_url=base_url,
            receipt_store=store,
            actors=actors,
            allowed_methods=["GET", "POST"],
            max_requests=40,
        )
        oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential")

        ctrl_get = client.request(method="GET", url="/settings", actor="anon")
        post_write = client.request(
            method="POST",
            url="/settings",
            actor="anon",
            json_body={"security_level": "weak", "port": 1},
        )
        assert post_write["status"] == 200
        assert post_write["body"] == ""

        readback = client.request(method="GET", url="/settings", actor="anon")
        assert '"security_level": "weak"' in readback["body"]

        v_ok = oracle.verify(
            canonical_class="mass_assignment",
            primary_proof=post_write,
            proof_receipts=[post_write],
            control_receipts=[ctrl_get],
            evidence_value='"security_level":"weak"',
        )
        assert v_ok.verified is True
        assert v_ok.verdict == "VERIFIED"
        assert v_ok.stages["stage3_clean_replay"] == "passed"

        v_bad = oracle.verify(
            canonical_class="mass_assignment",
            primary_proof=post_write,
            proof_receipts=[post_write],
            control_receipts=[ctrl_get],
            evidence_value='"nonexistent_field":"value"',
        )
        assert v_bad.verified is False
        assert v_bad.verdict == "REFUTED"
        assert v_bad.stages["stage3_clean_replay"] == "failed_missing_evidence"
    finally:
        client.close()
        _stop_server(srv)
