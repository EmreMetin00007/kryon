"""Phase 1 hardening tests: provider_options, concrete object/parity frontier, param depth, BOLA/BFLA oracle hygiene, wrapup gate, and CLI dispatch."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agent_cli  # noqa: E402
import agentic_runner  # noqa: E402
import llm_config  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_surface import SurfaceFrontierTracker  # noqa: E402
from agentic_tools import ToolDispatcher, canonicalize_and_deduplicate_findings  # noqa: E402
from full_agent_budget import SharedBudget, completion_request  # noqa: E402
from full_agent_provider import MeteredProviderTransport, SessionGate  # noqa: E402


# ---------------------------------------------------------------------------
# 1. provider_options config validation, snapshot, and payload injection
# ---------------------------------------------------------------------------


def _write_provider_config(tmp_path: Path, provider_block: dict[str, Any]) -> Path:
    cfg_path = tmp_path / "llm.json"
    cfg_path.write_text(
        json.dumps({
            "schema": llm_config.SCHEMA,
            "model": "gw/test-model",
            "providers": {"gw": provider_block},
        }),
        encoding="utf-8",
    )
    return cfg_path


def test_provider_options_validation_credential_rejection_and_snapshot(tmp_path: Path) -> None:
    valid_opts = {"gateway": {"order": ["route-a", "route-b"], "allow_fallbacks": False}}
    cfg = _write_provider_config(
        tmp_path,
        {
            "base_url": "http://127.0.0.1:4000/v1",
            "models": ["test-model"],
            "api_key_env": "TEST_LLM_KEY",
            "api_key_header": "Authorization",
            "provider_options": valid_opts,
        },
    )
    loaded = llm_config.load_config(cfg)
    assert loaded["providers"]["gw"]["provider_options"] == valid_opts

    models = llm_config.model_selection(cfg)
    settings = llm_config.provider_settings(cfg, models)
    assert settings["provider_options"] == valid_opts

    snap = llm_config.snapshot(cfg, models)
    assert snap["providers"]["gw"]["provider_options"] == valid_opts

    # Non-dict provider_options must be rejected.
    bad_type_cfg = _write_provider_config(
        tmp_path,
        {
            "base_url": "http://127.0.0.1:4000/v1",
            "models": ["test-model"],
            "api_key_env": "TEST_LLM_KEY",
            "provider_options": ["not-an-object"],
        },
    )
    with pytest.raises(ValueError, match="provider_options must be an object"):
        llm_config.load_config(bad_type_cfg)

    # Credential-bearing keys anywhere inside provider_options must be rejected.
    for forbidden_key in ("api_key", "apikey", "authorization", "secret", "password", "token"):
        bad_cred_cfg = _write_provider_config(
            tmp_path,
            {
                "base_url": "http://127.0.0.1:4000/v1",
                "models": ["test-model"],
                "api_key_env": "TEST_LLM_KEY",
                "provider_options": {"nested": {forbidden_key: "leaked-val"}},
            },
        )
        with pytest.raises(ValueError, match="must not contain credentials"):
            llm_config.load_config(bad_cred_cfg)


def test_metered_provider_transport_injects_provider_options(tmp_path: Path) -> None:
    captured_bodies: list[dict[str, Any]] = []

    class _StubProviderHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            captured_bodies.append(json.loads(raw))
            resp = json.dumps({
                "id": "cmpl-1",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _StubProviderHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        opts = {"gateway": {"order": ["upstream-1"], "require_parameters": True}}
        # Verify budget validator accepts providerOptions explicitly.
        req, _reserve = completion_request(
            {
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 32,
                "providerOptions": opts,
            },
            models={"test-model"},
            remaining=10_000,
        )
        assert req["providerOptions"] == opts

        budget = SharedBudget(http=10, tokens=10_000, seconds=60)
        private_dir = tmp_path / "private"
        private_dir.mkdir(parents=True, exist_ok=True)
        transport = MeteredProviderTransport(
            budget=budget,
            private=private_dir,
            provider=f"http://127.0.0.1:{port}/v1",
            models={"test-model"},
            api_key="loopback-key",
            session_gate=SessionGate(),
            provider_options=opts,
        )
        try:
            transport.complete({
                "model": "test-model",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 32,
            })
            # Explicit providerOptions in request body should be preserved rather than overwritten.
            custom_opts = {"gateway": {"order": ["custom-override"]}}
            transport.complete({
                "model": "test-model",
                "messages": [{"role": "user", "content": "ping 2"}],
                "max_tokens": 32,
                "providerOptions": custom_opts,
            })
        finally:
            transport.close_upstream()

        assert len(captured_bodies) == 2
        assert captured_bodies[0]["providerOptions"] == opts
        assert captured_bodies[1]["providerOptions"] == custom_opts
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 2. Concrete Object ID x Actor (Peer & Cross-Tenant) x UI/API Parity Frontier
# ---------------------------------------------------------------------------


def test_concrete_multi_object_peer_and_cross_tenant_frontier_and_finish_gate(tmp_path: Path) -> None:
    actors_meta = [
        {"alias": "alice", "role": "member", "tenant": "t1"},
        {"alias": "bob", "role": "member", "tenant": "t1"},
        {"alias": "carol", "role": "member", "tenant": "t2"},
    ]
    tracker = SurfaceFrontierTracker(
        base_url="http://app.local",
        allowed_methods=("GET", "HEAD"),
        actor_summaries=actors_meta,
    )
    # Collection lists 2 concrete UUID objects owned by alice (t1).
    uid1 = "11111111-1111-4111-8111-111111111111"
    uid2 = "22222222-2222-4222-8222-222222222222"
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "GET",
        "url": "/api/v1/records",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps([
            {"id": uid1, "owner": "alice", "title": "First"},
            {"id": uid2, "owner": "alice", "title": "Second"},
        ]),
    })
    tracker.ingest_receipt({"actor": "anon", "method": "GET", "url": "/api/v1/records", "status": 401})

    # Agent tests ONLY uid1 as bob (403) and carol (404), leaving uid2 untested!
    tracker.ingest_receipt({"actor": "bob", "method": "GET", "url": f"/api/v1/records/{uid1}", "status": 403})
    tracker.ingest_receipt({"actor": "carol", "method": "GET", "url": f"/api/v1/records/{uid1}", "status": 404})

    untested = tracker.untested_cross_actor_objects()
    assert not any(uid1 in item for item in untested)
    assert any(uid2 in item and "bob" in item and "carol" in item for item in untested)
    assert tracker.has_high_value_frontier() is True
    assert uid2 in tracker.format_frontier_banner(max_chars=1000)

    # Testing uid2 only as bob still leaves cross-tenant carol missing.
    tracker.ingest_receipt({"actor": "bob", "method": "GET", "url": f"/api/v1/records/{uid2}", "status": 403})
    untested_after_bob = tracker.untested_cross_actor_objects()
    assert any(uid2 in item and "carol" in item and "bob" not in item for item in untested_after_bob)
    assert tracker.has_high_value_frontier() is True

    # Testing uid2 as carol completes both peer & cross-tenant dimensions.
    tracker.ingest_receipt({"actor": "carol", "method": "GET", "url": f"/api/v1/records/{uid2}", "status": 404})
    assert tracker.untested_cross_actor_objects() == []
    assert tracker.has_high_value_frontier() is False


def test_ui_api_concrete_object_parity_and_template_cap() -> None:
    actors_meta = [
        {"alias": "alice", "role": "member", "tenant": "t1"},
        {"alias": "bob", "role": "member", "tenant": "t1"},
        {"alias": "carol", "role": "member", "tenant": "t2"},
    ]
    tracker = SurfaceFrontierTracker(
        base_url="http://app.local",
        allowed_methods=("GET",),
        actor_summaries=actors_meta,
    )
    # Known API family /api/v1/orders exists.
    tracker.ingest_receipt({"actor": "alice", "method": "GET", "url": "/api/v1/orders", "status": 200, "body": "[]"})
    tracker.ingest_receipt({"actor": "anon", "method": "GET", "url": "/api/v1/orders", "status": 401})

    # UI lists two concrete orders /orders/ord-101 and /orders/ord-102.
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "GET",
        "url": "/orders",
        "status": 200,
        "content_type": "text/html",
        "body": '<a href="/orders/ord-101">One</a><a href="/orders/ord-102">Two</a>',
    })

    untested = tracker.untested_cross_actor_objects()
    assert any("/api/v1/orders/ord-101" in item and "bob" in item and "carol" in item for item in untested)
    assert any("/api/v1/orders/ord-102" in item and "bob" in item and "carol" in item for item in untested)
    assert tracker.was_object_listed_for_actor("/orders/ord-101", "alice") is True
    assert tracker.was_object_listed_for_actor("/api/v1/orders/ord-101", "alice") is True

    # Verify per-template concrete object cap (6) while collection_listed_objects tracks all items.
    big_items = [{"id": f"itm-{i:03d}", "owner": "alice"} for i in range(1, 13)]
    tracker.ingest_receipt({
        "actor": "alice",
        "method": "GET",
        "url": "/api/v1/items",
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps(big_items),
    })
    item_objs = [p for p, info in tracker.discovered_objects.items() if info["template"] == "/api/v1/items/{id}"]
    assert len(item_objs) == 6
    assert tracker.was_object_listed_for_actor("/api/v1/items/itm-012", "alice") is True

    # Checkpoint roundtrip preserves listed_by, collection_listed_objects, and concrete API siblings.
    restored = SurfaceFrontierTracker.from_dict(tracker.to_dict())
    assert restored.was_object_listed_for_actor("/api/v1/items/itm-012", "alice") is True
    assert any("/api/v1/orders/ord-102" in item for item in restored.untested_cross_actor_objects())


# ---------------------------------------------------------------------------
# 3. Differential Parameter Probe Depth Tracking
# ---------------------------------------------------------------------------


def test_differential_param_probe_depth_tracking_and_clearing() -> None:
    tracker = SurfaceFrontierTracker(base_url="http://app.local", allowed_methods=("GET",))
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/lookup",
        "status": 200,
        "content_type": "text/html",
        "body": '<html><body><form action="/lookup" method="GET"><input name="q"><input name="page"></form></body></html>',
    })
    # Before sending q, it appears in unvisited_routes.
    assert any("/lookup?" in r and "q=" in r for r in tracker.unvisited_routes())

    # Sending a single benign alphanumeric value marks q as shallow in unprobed_params (while ignoring pagination `page`).
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/lookup?q=manifest&page=1",
        "status": 200,
        "content_type": "text/html",
        "body": "<html><body>Results: manifest</body></html>",
    })
    assert tracker.unvisited_routes() == []
    unprobed = tracker.unprobed_params()
    assert len(unprobed) == 1
    assert "/lookup?q=" in unprobed[0]
    assert "page=" not in unprobed[0]
    assert tracker.has_high_value_frontier() is True
    assert "unprobed_params" in tracker.format_frontier_banner(max_chars=1000)

    # Checkpoint roundtrip preserves shallow probe state.
    restored = SurfaceFrontierTracker.from_dict(tracker.to_dict())
    assert restored.unprobed_params() == unprobed

    # Case A: sending a special-character probe clears unprobed_params immediately.
    tracker.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/lookup?q=%3Csvg/onload=1%3E",
        "status": 200,
        "content_type": "text/html",
        "body": "<html><body>Results: <svg/onload=1></body></html>",
    })
    assert tracker.unprobed_params() == []
    assert tracker.has_high_value_frontier() is False

    # Case B: sending a second distinct benign value also clears unprobed_params (cannot infinite-loop).
    restored.ingest_receipt({
        "actor": "anon",
        "method": "GET",
        "url": "/lookup?q=other_term",
        "status": 200,
        "content_type": "text/html",
        "body": "<html><body>Results: other_term</body></html>",
    })
    assert restored.unprobed_params() == []
    assert restored.has_high_value_frontier() is False


# ---------------------------------------------------------------------------
# 4. Oracle BOLA False-Positive Guard & BFLA -> auth_bypass Promotion
# ---------------------------------------------------------------------------


class _Phase1MockHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        pass

    def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _actor(self) -> str:
        auth = self.headers.get("Authorization", "")
        return {
            "Bearer tok-alice": "alice",
            "Bearer tok-bob": "bob",
            "Bearer tok-carol": "carol",
            "Bearer tok-admin": "admin-t1",
        }.get(auth, "anon")

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        actor = self._actor()

        # Tenant-shared collection: both alice and bob (t1) legitimately see proj-shared-1.
        if parsed.path == "/api/v1/projects":
            if actor in {"alice", "bob", "admin-t1"}:
                self._send(200, json.dumps([{"id": "proj-shared-1", "owner": "alice", "tenant": "t1"}]).encode())
            elif actor == "carol":
                self._send(200, json.dumps([{"id": "proj-t2-1", "owner": "carol", "tenant": "t2"}]).encode())
            else:
                self._send(401, b'{"error":"unauthorized"}')
            return

        if parsed.path == "/api/v1/projects/proj-shared-1":
            if actor in {"alice", "bob", "admin-t1"}:
                self._send(
                    200,
                    json.dumps({
                        "id": "proj-shared-1",
                        "owner": "alice",
                        "tenant": "t1",
                        "shared_code": "SHD-9911-ALPHA",
                    }).encode(),
                )
            elif actor == "carol":
                self._send(404, b'{"error":"not_found"}')
            else:
                self._send(401, b'{"error":"unauthorized"}')
            return

        # Genuine BOLA: private record owned by alice (t1), NOT in bob's collection, readable by bob.
        if parsed.path == "/api/v1/projects/proj-priv-2":
            if actor in {"alice", "bob", "admin-t1"}:
                self._send(
                    200,
                    json.dumps({
                        "id": "proj-priv-2",
                        "owner": "alice",
                        "tenant": "t1",
                        "private_token": "prv_88aa77bb66cc55dd44ee",
                    }).encode(),
                )
            elif actor == "carol":
                self._send(404, b'{"error":"not_found"}')
            else:
                self._send(401, b'{"error":"unauthorized"}')
            return

        # Properly restricted same-tenant object (bob denied 403).
        if parsed.path == "/api/v1/projects/proj-denied":
            if actor in {"alice", "admin-t1"}:
                self._send(200, b'{"id":"proj-denied","owner":"alice","tenant":"t1"}')
            elif actor == "bob":
                self._send(403, b'{"error":"forbidden"}')
            elif actor == "carol":
                self._send(404, b'{"error":"not_found"}')
            else:
                self._send(401, b'{"error":"unauthorized"}')
            return

        # Unauthenticated auth_bypass endpoint (both member and anon get 200).
        if parsed.path == "/api/v1/ops/metrics-dump":
            self._send(200, b'{"export_state":"ready","dump_token":"dmp_1a2b3c4d5e6f7a8b9c0d"}')
            return

        # Genuine BFLA endpoint (anon gets 401, member gets 200).
        if parsed.path == "/api/v1/ops/admin-only":
            if actor == "anon":
                self._send(401, b'{"error":"unauthorized"}')
            else:
                self._send(200, b'{"audit_state":"ok","audit_token":"aud_9f8e7d6c5b4a3210fedc"}')
            return

        if parsed.path == "/search":
            q = parse_qs(parsed.query).get("q", [""])[0]
            self._send(200, f"<html><body>Query: {q}</body></html>".encode(), ctype="text/html; charset=utf-8")
            return

        self._send(404, b'{"error":"not_found"}')


@pytest.fixture()
def phase1_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Phase1MockHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


def _make_phase1_env(tmp_path: Path, base_url: str, *, with_oracle: bool = True):
    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-alice"},
        {"alias": "bob", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-bob"},
        {"alias": "carol", "role": "member", "tenant": "t2", "auth_header": "Bearer tok-carol"},
        {"alias": "admin-t1", "role": "admin", "tenant": "t1", "auth_header": "Bearer tok-admin"},
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "HEAD"),
        max_requests=60,
    )
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential") if with_oracle else None
    dispatcher = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path, oracle=oracle)
    return store, actors, client, dispatcher


def test_bola_fp_guard_rejects_cross_tenant_control_and_shared_collection_but_accepts_genuine_bola(
    tmp_path: Path,
    phase1_server: str,
) -> None:
    _store, _actors, client, dispatcher = _make_phase1_env(tmp_path, phase1_server, with_oracle=True)
    try:
        # 1. Cross-tenant-only control on same-tenant BOLA -> REFUTED by DifferentialOracle.
        p_priv = json.loads(dispatcher.dispatch("http_request", {"url": "/api/v1/projects/proj-priv-2", "actor": "bob"}).split("\n", 1)[1].rsplit("\n", 1)[0])
        c_carol = json.loads(dispatcher.dispatch("http_request", {"url": "/api/v1/projects/proj-priv-2", "actor": "carol"}).split("\n", 1)[1].rsplit("\n", 1)[0])
        c_anon = json.loads(dispatcher.dispatch("http_request", {"url": "/api/v1/projects/proj-priv-2", "actor": "anon"}).split("\n", 1)[1].rsplit("\n", 1)[0])

        rej_xt = json.loads(dispatcher.dispatch("record_finding", {
            "title": "BOLA with cross-tenant control",
            "class_type": "bola",
            "method": "GET",
            "url": "/api/v1/projects/proj-priv-2",
            "actor_alias": "bob",
            "proof_receipt_ids": [p_priv["receipt_id"]],
            "control_receipt_ids": [c_carol["receipt_id"]],
            "evidence_value": "prv_88aa77bb66cc55dd44ee",
            "summary": "bob reads alice project while cross-tenant carol gets 404",
        }))
        assert rej_xt["rejected"] is True
        assert rej_xt["oracle_verdict"] == "REFUTED"
        assert rej_xt["stages"]["stage2_diff"] == "failed_bola_cross_tenant_only_control"

        # 2. Anon-only control in multi-tenant app on same-tenant BOLA -> REFUTED.
        rej_anon = json.loads(dispatcher.dispatch("record_finding", {
            "title": "BOLA with anon-only control",
            "class_type": "bola",
            "method": "GET",
            "url": "/api/v1/projects/proj-priv-2",
            "actor_alias": "bob",
            "proof_receipt_ids": [p_priv["receipt_id"]],
            "control_receipt_ids": [c_anon["receipt_id"]],
            "evidence_value": "prv_88aa77bb66cc55dd44ee",
            "summary": "bob reads alice project while anon gets 401",
        }))
        assert rej_anon["rejected"] is True
        assert rej_anon["oracle_verdict"] == "REFUTED"
        assert rej_anon["stages"]["stage2_diff"] == "failed_bola_anon_only_control"

        # 3. Shared-tenant collection guard: bob receives proj-shared-1 in bob's own 2xx collection listing.
        dispatcher.dispatch("http_request", {"url": "/api/v1/projects", "actor": "bob"})
        p_shared = json.loads(dispatcher.dispatch("http_request", {"url": "/api/v1/projects/proj-shared-1", "actor": "bob"}).split("\n", 1)[1].rsplit("\n", 1)[0])
        c_bob_403 = json.loads(dispatcher.dispatch("http_request", {"url": "/api/v1/projects/proj-denied", "actor": "bob"}).split("\n", 1)[1].rsplit("\n", 1)[0])

        rej_shared = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Shared-tenant resource falsely claimed as BOLA",
            "class_type": "bola",
            "method": "GET",
            "url": "/api/v1/projects/proj-shared-1",
            "actor_alias": "bob",
            "proof_receipt_ids": [p_shared["receipt_id"]],
            "control_receipt_ids": [c_bob_403["receipt_id"]],
            "evidence_value": "SHD-9911-ALPHA",
            "summary": "bob reads shared tenant project",
        }))
        assert rej_shared["rejected"] is True
        assert rej_shared["oracle_verdict"] == "REFUTED"
        assert rej_shared["stages"]["stage2_diff"] == "failed_bola_shared_collection_resource"

        # 4. Genuine BOLA (not in bob's collection + same-tenant denied control c_bob_403) -> VERIFIED!
        acc = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Genuine BOLA on private project",
            "class_type": "bola",
            "method": "GET",
            "url": "/api/v1/projects/proj-priv-2",
            "actor_alias": "bob",
            "proof_receipt_ids": [p_priv["receipt_id"]],
            "control_receipt_ids": [c_bob_403["receipt_id"]],
            "evidence_value": "prv_88aa77bb66cc55dd44ee",
            "summary": "bob reads alice private project while bob is denied 403 on proj-denied",
        }))
        assert acc["accepted"] is True
        assert acc["class_type"] == "bola"
        assert acc["primary_actor"] == "bob"
    finally:
        client.close()


def test_bfla_to_auth_bypass_bidirectional_promotion(tmp_path: Path, phase1_server: str) -> None:
    store, actors, client, dispatcher = _make_phase1_env(tmp_path, phase1_server, with_oracle=True)
    try:
        r_bob = client.request(method="GET", url="/api/v1/ops/metrics-dump", actor="bob")
        r_anon = client.request(method="GET", url="/api/v1/ops/metrics-dump", actor="anon")
        r_ctrl_auth = client.request(method="GET", url="/api/v1/ops/admin-only", actor="admin-t1")

        # Case A: model submits bfla with BOTH member 200 and anon 200 in proof_receipt_ids -> promoted to auth_bypass!
        res = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Unprotected metrics dump",
            "class_type": "bfla",
            "method": "GET",
            "url": "/api/v1/ops/metrics-dump",
            "actor_alias": "bob",
            "proof_receipt_ids": [r_bob["receipt_id"], r_anon["receipt_id"]],
            "control_receipt_ids": [r_ctrl_auth["receipt_id"]],
            "evidence_value": "dmp_1a2b3c4d5e6f7a8b9c0d",
            "summary": "bob and anon both read metrics dump",
        }))
        assert res["accepted"] is True
        assert res["class_type"] == "auth_bypass"
        assert res["primary_actor"] == "anon"
        saved = dispatcher.findings[-1]
        assert saved["class_type"] == "auth_bypass"
        assert saved["actor"] == "anon"
        assert saved["actor_alias"] == "anon"
        assert r_anon["receipt_id"] in saved["proof_receipt_ids"]

        # Case B: standalone bfla in canonicalize_and_deduplicate_findings with only bob's receipt
        # while anon 200 exists in ReceiptStore -> promoted to auth_bypass with anon receipt added!
        actor_meta = {
            row["alias"]: {"alias": row["alias"], "role": row["role"].lower(), "tenant": row["tenant"].lower()}
            for row in actors.summaries()
        }
        canon = canonicalize_and_deduplicate_findings(
            [{
                "title": "Post-run bfla mislabel",
                "class_type": "bfla",
                "method": "GET",
                "url": r_bob["url"],
                "path": "/api/v1/ops/metrics-dump",
                "actor": "bob",
                "actor_alias": "bob",
                "observed_status": 200,
                "evidence_value": "dmp_1a2b3c4d5e6f7a8b9c0d",
                "proof_receipt_ids": [r_bob["receipt_id"]],
                "control_receipt_ids": [r_ctrl_auth["receipt_id"]],
            }],
            actor_meta_map=actor_meta,
            receipt_store=store,
        )
        assert len(canon) == 1
        assert canon[0]["class_type"] == "auth_bypass"
        assert canon[0]["actor"] == "anon"
        assert canon[0]["actor_alias"] == "anon"
        assert r_anon["receipt_id"] in canon[0]["proof_receipt_ids"]

        # Case C: genuine BFLA where anon got 401 stays bfla!
        r_bfla_bob = client.request(method="GET", url="/api/v1/ops/admin-only", actor="bob")
        r_bfla_anon = client.request(method="GET", url="/api/v1/ops/admin-only", actor="anon")
        res_bfla = json.loads(dispatcher.dispatch("record_finding", {
            "title": "Admin endpoint accessible to member",
            "class_type": "bfla",
            "method": "GET",
            "url": "/api/v1/ops/admin-only",
            "actor_alias": "bob",
            "proof_receipt_ids": [r_bfla_bob["receipt_id"]],
            "control_receipt_ids": [r_bfla_anon["receipt_id"]],
            "evidence_value": "aud_9f8e7d6c5b4a3210fedc",
            "summary": "bob gets 200 while anon gets 401",
        }))
        assert res_bfla["accepted"] is True
        assert res_bfla["class_type"] == "bfla"
        assert res_bfla["primary_actor"] == "bob"
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 5. [BUDGET-WRAPUP] <-> coverage_gate_enabled alignment
# ---------------------------------------------------------------------------


class _FakeWrapupTransport:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self._responses = list(responses)
        self.calls = 0
        self.bodies: list[dict[str, Any]] = []
        self.session_gate = SessionGate()
        self.provider_responses: list[dict[str, Any]] = []

    def complete(self, request_body: dict[str, Any], *, minimum_output_tokens: int = 16) -> dict[str, Any]:
        del minimum_output_tokens
        self.calls += 1
        self.bodies.append(dict(request_body))
        if not self._responses:
            return {"choices": [{"message": {"content": "", "tool_calls": []}}]}
        return self._responses.pop(0)


def test_budget_wrapup_disables_coverage_gate_and_allows_finish(tmp_path: Path, phase1_server: str) -> None:
    store = ReceiptStore(tmp_path)
    actors = ActorManager([{"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-alice"}])
    client = AgenticHTTPClient(
        base_url=phase1_server,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET",),
        max_requests=100,
    )
    budget = SharedBudget(http=100, tokens=1_000_000, seconds=600)
    transport = _FakeWrapupTransport([
        {
            "choices": [{
                "message": {
                    "content": "Wrapping up due to low token budget.",
                    "tool_calls": [{
                        "id": "call_finish_1",
                        "type": "function",
                        "function": {
                            "name": "finish",
                            "arguments": json.dumps({"summary": "Wrapped up cleanly", "untested_areas": ["/unvisited"]}),
                        },
                    }],
                },
            }],
            "usage": {"prompt_tokens": 500, "completion_tokens": 100, "total_tokens": 600},
        }
    ])
    inv = AgenticInvestigator(
        http_client=client,
        receipt_store=store,
        transport=transport,
        budget=budget,
        model="test-model",
        root_dir=tmp_path,
        max_turns=50,
    )
    try:
        # Seed an unvisited high-value route so coverage gate WOULD reject finish if enabled.
        inv.dispatcher.surface_tracker._register_discovered_url("/api/v1/unvisited-surface", method="GET")
        assert inv.dispatcher.surface_tracker.has_high_value_frontier() is True

        # With plenty of tokens (>15% remaining), coverage gate stays enabled and finish is rejected.
        inv._sync_coverage_gate(turn=2)
        assert inv.dispatcher.coverage_gate_enabled is True
        rej = json.loads(inv.dispatcher.dispatch("finish", {"summary": "too early"}))
        assert rej["rejected"] is True
        inv.dispatcher.finish_rejections = 0

        # Burn 86% of token budget -> 14% left (<= 15% wrapup threshold).
        budget.used["tokens"] = 860_000
        banner = inv._state_banner(turn=2)
        assert "[BUDGET-WRAPUP]" in banner
        assert inv.dispatcher.coverage_gate_enabled is False

        # Running the investigator loop now accepts finish immediately with 0 rejections.
        res = inv.run()
        assert res["status"] == "finished"
        assert inv.dispatcher.finished is True
        assert inv.dispatcher.finish_rejections == 0
    finally:
        client.close()


def test_premature_finish_rejected_for_second_concrete_object_and_shallow_param(
    tmp_path: Path,
    phase1_server: str,
) -> None:
    _store, _actors, client, dispatcher = _make_phase1_env(tmp_path, phase1_server, with_oracle=False)
    try:
        uid1 = "aaaaaaaa-1111-4111-8111-111111111111"
        uid2 = "bbbbbbbb-2222-4222-8222-222222222222"
        dispatcher.surface_tracker.ingest_receipt({
            "actor": "alice",
            "method": "GET",
            "url": "/api/v1/records",
            "status": 200,
            "content_type": "application/json",
            "body": json.dumps([
                {"id": uid1, "owner": "alice"},
                {"id": uid2, "owner": "alice"},
            ]),
        })
        dispatcher.surface_tracker.ingest_receipt({"actor": "anon", "method": "GET", "url": "/api/v1/records", "status": 401})
        dispatcher.surface_tracker.ingest_receipt({"actor": "bob", "method": "GET", "url": f"/api/v1/records/{uid1}", "status": 403})
        dispatcher.surface_tracker.ingest_receipt({"actor": "carol", "method": "GET", "url": f"/api/v1/records/{uid1}", "status": 404})

        # Premature finish rejected while uid2 remains untested.
        rej_obj = json.loads(dispatcher.dispatch("finish", {"summary": "done after 1st object"}))
        assert rej_obj["rejected"] is True
        assert any(uid2 in item for item in rej_obj["remaining_frontier"]["untested_cross_actor_objects"])

        # Complete uid2 testing, then send only 1 benign alphanumeric param to HTML /search?q=manifest.
        dispatcher.surface_tracker.ingest_receipt({"actor": "bob", "method": "GET", "url": f"/api/v1/records/{uid2}", "status": 403})
        dispatcher.surface_tracker.ingest_receipt({"actor": "carol", "method": "GET", "url": f"/api/v1/records/{uid2}", "status": 404})
        dispatcher.dispatch("http_request", {"url": "/search?q=manifest", "actor": "anon"})

        rej_param = json.loads(dispatcher.dispatch("finish", {"summary": "done after benign search"}))
        assert rej_param["rejected"] is True
        assert any("/search?q=" in item for item in rej_param["remaining_frontier"]["unprobed_params"])

        # Probing with special chars clears unprobed_params and lets finish succeed.
        dispatcher.dispatch("http_request", {"url": "/search?q=%3Csvg/onload=1%3E", "actor": "anon"})
        fin_ok = json.loads(dispatcher.dispatch("finish", {"summary": "all covered"}))
        assert fin_ok["finished"] is True
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 6. agent_cli.py official `agentic` subcommand dispatch
# ---------------------------------------------------------------------------


def test_agent_cli_agentic_subcommand_dispatch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert "agentic" in agent_cli.COMMANDS
    assert agent_cli.COMMANDS["agentic"] == ("agentic_runner", [])

    captured: list[list[str]] = []
    monkeypatch.setattr(agentic_runner, "main", lambda argv: captured.append(list(argv)) or 0)

    out_dir = tmp_path / "agentic-out"
    rc = agent_cli.main([
        "agentic",
        "--target",
        "http://127.0.0.1:8080",
        "--output-dir",
        str(out_dir),
        "--max-turns",
        "25",
    ])
    assert rc == 0
    assert captured == [[
        "--target",
        "http://127.0.0.1:8080",
        "--output-dir",
        str(out_dir),
        "--max-turns",
        "25",
    ]]


# ---------------------------------------------------------------------------
# 7. Two-phase asymmetric scout -> deep handoff
# ---------------------------------------------------------------------------


def test_two_phase_scout_to_deep_handoff(tmp_path: Path, phase1_server: str) -> None:
    store, _actors, client, _disp = _make_phase1_env(tmp_path, phase1_server, with_oracle=False)
    budget = SharedBudget(http=100, tokens=400_000, seconds=600)
    transport = _FakeWrapupTransport([
        # Turn 1 (scout): fetch /search?q=manifest
        {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "tc_s1",
                        "type": "function",
                        "function": {"name": "http_request", "arguments": json.dumps({"url": "/search?q=manifest", "actor": "anon"})},
                    }],
                },
            }],
            "usage": {"prompt_tokens": 500, "completion_tokens": 80, "total_tokens": 580},
        },
        # Turn 2 (scout): calls finish -> triggers handoff to deep-model
        {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "tc_s2",
                        "type": "function",
                        "function": {"name": "finish", "arguments": json.dumps({"summary": "scout mapped search"})},
                    }],
                },
            }],
            "usage": {"prompt_tokens": 600, "completion_tokens": 90, "total_tokens": 690},
        },
        # Turn 3 (deep): receives fresh handoff packet and probes the unprobed param
        {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "tc_d1",
                        "type": "function",
                        "function": {"name": "http_request", "arguments": json.dumps({"url": "/search?q=%3Csvg/onload=1%3E", "actor": "anon"})},
                    }],
                },
            }],
            "usage": {"prompt_tokens": 700, "completion_tokens": 100, "total_tokens": 800},
        },
        # Turn 4 (deep): finishes cleanly once frontier is cleared
        {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "tc_d2",
                        "type": "function",
                        "function": {"name": "finish", "arguments": json.dumps({"summary": "deep pass verified"})},
                    }],
                },
            }],
            "usage": {"prompt_tokens": 750, "completion_tokens": 80, "total_tokens": 830},
        },
    ])
    inv = AgenticInvestigator(
        http_client=client,
        receipt_store=store,
        transport=transport,
        budget=budget,
        model="deep-model",
        scout_model="scout-model",
        scout_max_turns=2,
        scout_token_share=0.40,
        root_dir=tmp_path,
        max_turns=10,
    )
    try:
        res = inv.run()
        assert res["status"] == "finished"
        assert len(transport.bodies) == 4
        assert transport.bodies[0]["model"] == "scout-model"
        assert transport.bodies[1]["model"] == "scout-model"
        assert transport.bodies[2]["model"] == "deep-model"
        assert transport.bodies[3]["model"] == "deep-model"
        # Phase 2 starts with fresh 2-message handoff (no raw scout transcript)
        p2_msgs = transport.bodies[2]["messages"]
        assert len(p2_msgs) == 2
        assert "PHASE 2 DEEP VERIFICATION HANDOFF" in p2_msgs[0]["content"]
        assert "[HANDOFF SUMMARY]" in p2_msgs[1]["content"]
        assert "req-0001" in p2_msgs[1]["content"]
        hs = res["handoff_summary"]
        assert hs["scout_model"] == "scout-model"
        assert hs["deep_model"] == "deep-model"
        assert hs["scout_calls"] == 2
        assert hs["deep_calls"] == 2
        assert hs["scout_tokens"] == 1270
        assert hs["deep_tokens"] == 1630
    finally:
        client.close()


def test_agentic_runner_scout_model_validates_same_provider(tmp_path: Path) -> None:
    cfg = tmp_path / "llm.json"
    cfg.write_text(
        json.dumps({
            "schema": "cco-llm/1",
            "model": "gw/deep-model",
            "providers": {
                "gw": {
                    "base_url": "https://gateway.example.invalid/v1",
                    "models": ["deep-model", "scout-model"],
                    "api_key_env": "GW_KEY",
                    "api_key_header": "Authorization",
                },
                "other": {
                    "base_url": "https://other.example.invalid/v1",
                    "models": ["other-scout"],
                    "api_key_env": "OTHER_KEY",
                    "api_key_header": "Authorization",
                },
            },
        }),
        encoding="utf-8",
    )
    plan_path, plan = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18899/",
        provider_config=cfg,
        model="gw/deep-model",
        scout_model="gw/scout-model",
        output_dir=tmp_path / "plan-ok",
        execute=False,
    )
    assert plan_path.is_file()
    assert plan["models"]["scout"] == "gw/scout-model"

    with pytest.raises(ValueError, match="one provider"):
        agentic_runner.run_agentic_target(
            target="http://127.0.0.1:18899/",
            provider_config=cfg,
            model="gw/deep-model",
            scout_model="other/other-scout",
            output_dir=tmp_path / "plan-bad",
            execute=False,
        )
