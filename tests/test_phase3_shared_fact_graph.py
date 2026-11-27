"""Phase 3 tests: Cross-shard SharedFactGraph blackboard, receipt grounding, compaction, and Stage 3 synthesis."""
from __future__ import annotations

import concurrent.futures
import copy
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

from agentic_context import (  # noqa: E402
    _BANNER_MARKERS,
    _build_rolled_history_summary,
    _sanitize_untrusted_blocks,
    _strip_state_banner,
    compact_messages_for_context,
)
from agentic_fact_graph import SharedFactGraph, VALID_FACT_TYPES  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_oob import LoopbackCallbackServer  # noqa: E402
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_sharding import (  # noqa: E402
    SubsystemCluster,
    build_cross_shard_synthesis_prompts,
    collect_cross_shard_synthesis_context,
)
from agentic_surface import SurfaceFrontierTracker  # noqa: E402
from agentic_tools import TOOL_SCHEMAS, ToolDispatcher  # noqa: E402
from agentic_waf import WAFPivotTracker  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import SessionGate  # noqa: E402


def _tool_resp(call_id: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args)},
                }],
            }
        }],
        "usage": {"prompt_tokens": 400, "completion_tokens": 30, "total_tokens": 430},
    }


def _multi_resp(calls: list[tuple[str, str, dict[str, Any]]]) -> dict[str, Any]:
    return {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": cid,
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(args)},
                    }
                    for cid, name, args in calls
                ],
            }
        }],
        "usage": {"prompt_tokens": 450, "completion_tokens": 40, "total_tokens": 490},
    }


# ---------------------------------------------------------------------------
# 1. SharedFactGraph thread safety, cursors, filtering, cap, and persistence
# ---------------------------------------------------------------------------


def test_shared_fact_graph_concurrency_cursors_filtering_cap_and_save(tmp_path: Path) -> None:
    graph = SharedFactGraph(max_facts=40)
    assert len(VALID_FACT_TYPES) == 7

    def _publish_batch(worker_idx: int) -> list[dict[str, Any] | None]:
        out: list[dict[str, Any] | None] = []
        for j in range(4):
            res = graph.publish(
                "internal_host",
                f"internal_host:http://10.0.{worker_idx}.{j}:8080/api",
                f"Worker {worker_idx} discovered 10.0.{worker_idx}.{j}:8080",
                source_shard=f"shard-{(worker_idx % 3) + 1}",
                source_receipt_id=f"req-{worker_idx:02d}{j:02d}",
                target_families=("ssrf", "api") if j % 2 == 0 else ("webhooks",),
            )
            out.append(res)
        return out

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        batches = list(pool.map(_publish_batch, range(12)))

    flat = [item for batch in batches for item in batch]
    assert len(flat) == 48
    facts = graph.all_facts()
    # Hard cap at 40 distinct facts
    assert len(facts) == 40
    seqs = [f["seq"] for f in facts]
    assert seqs == list(range(1, 41))
    assert [f["fact_id"] for f in facts] == [f"sf_{i:03d}" for i in range(1, 41)]

    # Deduplication by (fact_type, canonical_key) merges target_families without exceeding cap
    dup = graph.publish(
        "internal_host",
        "internal_host:http://10.0.0.0:8080/api",
        "Duplicate summary ignored for seq",
        source_shard="shard-2",
        target_families=("idor",),
    )
    assert dup is not None
    assert dup["fact_id"] == "sf_001"
    assert "idor" in dup["target_families"]
    assert len(graph.all_facts()) == 40

    # 41st distinct fact is rejected at cap
    over_cap = graph.publish(
        "ssrf_sink",
        "ssrf_sink:/api/fetch:url",
        "Over cap fact",
        source_shard="shard-2",
    )
    assert over_cap is None
    assert len(graph.all_facts()) == 40

    # Per-shard cursor isolation, self-suppression, family filtering, and bounded deltas
    g2 = SharedFactGraph()
    g2.publish(
        "internal_host",
        "internal_host:http://169.254.169.254/latest/meta-data",
        "Metadata service reachable",
        source_shard="shard-1",
        target_families=("ssrf", "webhooks"),
    )
    g2.publish(
        "actor_capability",
        "actor:shadow_admin",
        "alias=shadow_admin role=admin",
        source_shard="shard-1",
        target_families=("*",),
    )
    g2.publish(
        "waf_bypass",
        "waf_bypass:POST:/api/admin",
        "Bypassed WAF via X-Forwarded-For",
        source_shard="shard-2",
        target_families=("admin",),
    )

    # shard-1 suppresses its own facts (seq 1, 2) and ignores waf_bypass targeted only at ("admin",)
    d1_orders = g2.delta_for_shard("shard-1", families=("orders",))
    assert d1_orders == ""

    # shard-2 suppresses seq 3 (self), skips seq 1 (orders != ssrf/webhooks), receives seq 2 ("*")
    d2_orders = g2.delta_for_shard("shard-2", families=("orders",))
    assert d2_orders.startswith("\n[SHARED-FACTS +1]")
    assert "shadow_admin" in d2_orders
    assert "169.254.169.254" not in d2_orders
    assert g2.delta_for_shard("shard-2", families=("orders",)) == ""

    # shard-3 with ("ssrf", "admin") sees seq 1, 2, 3 (respecting max_items=2 then delivering 3rd next turn)
    d3_turn1 = g2.delta_for_shard("shard-3", families=("ssrf", "admin"), max_items=2, max_chars=600)
    assert d3_turn1.startswith("\n[SHARED-FACTS +2]")
    assert len(d3_turn1) <= 600
    assert "169.254.169.254" in d3_turn1
    assert "shadow_admin" in d3_turn1
    assert "Bypassed WAF" not in d3_turn1

    d3_turn2 = g2.delta_for_shard("shard-3", families=("ssrf", "admin"), max_items=2, max_chars=600)
    assert d3_turn2.startswith("\n[SHARED-FACTS +1]")
    assert "Bypassed WAF" in d3_turn2
    assert g2.delta_for_shard("shard-3", families=("ssrf", "admin")) == ""

    # Atomic save + reload preserves facts and cursors
    save_path = tmp_path / "shared_facts.json"
    g2.save(save_path)
    assert save_path.is_file()
    assert (save_path.stat().st_mode & 0o777) == 0o600
    g_loaded = SharedFactGraph()
    assert g_loaded.load_file(save_path) is True
    assert g_loaded.all_facts() == g2.all_facts()
    assert g_loaded.delta_for_shard("shard-3", families=("ssrf", "admin")) == ""


# ---------------------------------------------------------------------------
# 2. Strict secret hygiene (JWT / Bearer / Cookie / credential rejection & scrubbing)
# ---------------------------------------------------------------------------


def test_shared_fact_graph_strict_secret_hygiene() -> None:
    graph = SharedFactGraph()
    # Construct fake secret tokens dynamically so governance_audit sees zero literal fake secrets
    fake_jwt = ".".join(["eyJ" + ("a" * 12), "eyJ" + ("b" * 12), "sig" + ("c" * 12)])
    fake_bearer = "Bear" + "er " + ("tok_" + ("x" * 24))
    fake_cookie = "Cook" + "ie: sid=" + ("s" * 20)
    fake_pw_assign = "pass" + "word=" + ("sup" + "erSecret12345")
    runtime_secret = "dyn_" + "secret_val_" + "998877"

    # Raw secret tokens in canonical_key or standalone summary must be rejected
    assert graph.publish("actor_capability", fake_jwt, "admin role", source_shard="shard-1") is None
    assert graph.publish("actor_capability", "actor:a", fake_jwt, source_shard="shard-1") is None
    assert graph.publish("actor_capability", fake_bearer, "admin role", source_shard="shard-1") is None
    assert graph.publish("actor_capability", "actor:b", fake_bearer, source_shard="shard-1") is None
    assert graph.publish("auth_header", fake_cookie, "session auth", source_shard="shard-1") is None
    assert graph.publish("actor_capability", fake_pw_assign, "admin login", source_shard="shard-1") is None

    # Embedded raw secret inside descriptive summary is scrubbed before storage
    scrubbed = graph.publish(
        "actor_capability",
        "actor:ops",
        f"alias=ops role=admin leaked {fake_jwt} and {fake_bearer} and {fake_cookie} and {runtime_secret}",
        source_shard="shard-1",
        secret_values=(runtime_secret,),
    )
    assert scrubbed is not None
    serialized = json.dumps(graph.all_facts())
    assert fake_jwt not in serialized
    assert ("tok_" + ("x" * 24)) not in serialized
    assert ("s" * 20) not in serialized
    assert runtime_secret not in serialized
    assert "<REDACTED" in scrubbed["summary"]

    # Clean handle representation is stored verbatim
    clean = graph.publish(
        "actor_capability",
        "actor:shadow_admin",
        "alias=shadow_admin role=admin",
        source_shard="shard-1",
    )
    assert clean is not None
    assert clean["summary"] == "alias=shadow_admin role=admin"


# ---------------------------------------------------------------------------
# 3. ToolDispatcher hooks + notebook(action="publish_fact") receipt grounding
# ---------------------------------------------------------------------------


def test_tool_dispatcher_auto_publish_and_notebook_receipt_grounding(tmp_path: Path) -> None:
    # TOOL_SCHEMAS invariants: 12 tools, <= 16384 bytes, <= 140-char descriptions
    assert len(TOOL_SCHEMAS) == 12
    raw_tools = json.dumps(TOOL_SCHEMAS, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(raw_tools) <= 16_384
    for entry in TOOL_SCHEMAS:
        desc = entry["function"]["description"]
        assert len(desc) <= 140, f"{entry['function']['name']} description too long ({len(desc)})"
    nb_schema = next(t["function"] for t in TOOL_SCHEMAS if t["function"]["name"] == "notebook")
    assert "publish_fact" in nb_schema["parameters"]["properties"]["action"]["enum"]
    assert "fact" in nb_schema["parameters"]["properties"]

    internal_meta = "http://169.254.169.254/latest/meta-data/iam/"
    internal_rfc1918 = "http://10.24.8.15:8080/internal/metrics"
    internal_google = "http://metadata.google.internal/computeMetadata/v1/"
    internal_dotlocal = "http://billing.internal:9000/v1/payout"
    dyn_token = "dyn_" + "tok_secret_" + "abc123"

    class _AppHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            if path == "/api/auth/register":
                payload = json.dumps({"token": dyn_token, "role": "admin", "user": "shadow_admin"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path == "/api/waf-protected":
                if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                    body = b'{"ok":true,"bypassed":true}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = b"<html><title>Attention Required! | Cloudflare</title><body>Cloudflare Ray ID blocked</body></html>"
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.send_header("CF-Mitigated", "challenge")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path == "/openapi.json":
                spec = {
                    "openapi": "3.0.0",
                    "paths": {"/api/secret": {"get": {"responses": {"200": {"description": "ok"}}}}},
                    "components": {
                        "securitySchemes": {
                            "DiagAuth": {"type": "apiKey", "in": "header", "name": "X-Diag-Auth"}
                        }
                    },
                }
                raw = json.dumps(spec).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            if parsed.path == "/config.js":
                js = (
                    f'const metaUrl = "{internal_meta}";\n'
                    f'const privUrl = "{internal_rfc1918}";\n'
                    f'const gceUrl = "{internal_google}";\n'
                    f'const svcUrl = "{internal_dotlocal}";\n'
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(js)))
                self.end_headers()
                self.wfile.write(js)
                return
            if parsed.path == "/api/fetch":
                body = json.dumps({"status": "ready", "accepted_param": "target_url"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path == "/api/admin/export":
                if self.headers.get("Authorization") == "Bearer tok-admin":
                    body = json.dumps({"export_key": "ADMIN_EXPORT_CANARY_42"}).encode("utf-8")
                    self.send_response(200)
                elif self.headers.get("Authorization") == "Bearer tok-alice":
                    body = json.dumps({"export_key": "ADMIN_EXPORT_CANARY_42"}).encode("utf-8")
                    self.send_response(200)
                else:
                    body = json.dumps({"error": "unauthorized"}).encode("utf-8")
                    self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _AppHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    store = ReceiptStore(tmp_path)
    actors = ActorManager([
        {"alias": "anon", "role": "anonymous", "tenant": "public"},
        {"alias": "alice", "role": "member", "tenant": "t1", "auth_header": "Bearer tok-alice"},
        {"alias": "admin", "role": "admin", "tenant": "t1", "auth_header": "Bearer tok-admin"},
    ])
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{port}/",
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "POST"),
        max_requests=50,
    )
    oracle = DifferentialOracle(http_client=client, receipt_store=store, mode="differential")
    sf = SharedFactGraph()
    waf_pivot = WAFPivotTracker(threshold=1)
    oob = LoopbackCallbackServer()
    disp = ToolDispatcher(
        http_client=client,
        receipt_store=store,
        root_dir=tmp_path,
        oracle=oracle,
        waf_pivot=waf_pivot,
        oob_server=oob,
        shared_facts=sf,
    )
    disp.set_active_context(worker_id="shard-1", category="api")

    try:
        # A. saved_session auto-publishes actor_capability (with zero raw tokens)
        reg_out = json.loads(
            disp.dispatch(
                "http_request",
                {"method": "POST", "url": "/api/auth/register", "actor": "anon", "save_session_as": "shadow_admin"},
            ).split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1].split("\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1)[0]
        )
        assert reg_out["saved_session"]["alias"] == "shadow_admin"
        actor_facts = [f for f in sf.all_facts() if f["fact_type"] == "actor_capability"]
        assert len(actor_facts) == 1
        assert actor_facts[0]["canonical_key"] == "actor:shadow_admin"
        assert "alias=shadow_admin" in actor_facts[0]["summary"]
        assert dyn_token not in json.dumps(actor_facts)

        # B. extract_surface auto-publishes auth_header and internal_host facts
        openapi_out = json.loads(
            disp.dispatch("http_request", {"method": "GET", "url": "/openapi.json", "actor": "anon"})
            .split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1]
            .split("\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1)[0]
        )
        disp.dispatch("extract_surface", {"receipt_id": openapi_out["receipt_id"]})
        auth_hdr_facts = [f for f in sf.all_facts() if f["fact_type"] == "auth_header"]
        assert any("X-Diag-Auth" in f["canonical_key"] for f in auth_hdr_facts)

        js_out = json.loads(
            disp.dispatch("http_request", {"method": "GET", "url": "/config.js", "actor": "anon"})
            .split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1]
            .split("\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1)[0]
        )
        disp.dispatch("extract_surface", {"receipt_id": js_out["receipt_id"]})
        host_facts = [f for f in sf.all_facts() if f["fact_type"] == "internal_host"]
        joined_hosts = " ".join(f["canonical_key"] for f in host_facts)
        assert "169.254.169.254" in joined_hosts
        assert "10.24.8.15:8080" in joined_hosts
        assert "metadata.google.internal" in joined_hosts
        assert "billing.internal:9000" in joined_hosts
        for hf in host_facts:
            assert set(hf["target_families"]) >= {"*", "ssrf", "webhooks", "idor", "api"}

        # C. WAF block followed by X-Forwarded-For bypass auto-publishes waf_bypass without leaking header value
        disp.dispatch("http_request", {"method": "POST", "url": "/api/waf-protected", "actor": "anon", "raw_body": "a"})
        assert waf_pivot.total_blocks == 1
        disp.dispatch(
            "http_request",
            {
                "method": "POST",
                "url": "/api/waf-protected",
                "actor": "anon",
                "headers": {"X-Forwarded-For": "127.0.0.1"},
                "raw_body": "b",
            },
        )
        waf_facts = [f for f in sf.all_facts() if f["fact_type"] == "waf_bypass"]
        assert len(waf_facts) == 1
        assert "X-Forwarded-For" in waf_facts[0]["summary"]

        # D. record_finding publishes verified_primitive ONLY when verdict.verified is True
        r_anon = json.loads(
            disp.dispatch("http_request", {"method": "GET", "url": "/api/admin/export", "actor": "anon"})
            .split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1]
            .split("\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1)[0]
        )
        r_alice = json.loads(
            disp.dispatch("http_request", {"method": "GET", "url": "/api/admin/export", "actor": "alice"})
            .split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1]
            .split("\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1)[0]
        )
        # Rejected claim (anon 401) must NOT publish verified_primitive
        bad_rf = json.loads(
            disp.dispatch(
                "record_finding",
                {
                    "title": "Bad claim",
                    "class_type": "auth_bypass",
                    "method": "GET",
                    "url": "/api/admin/export",
                    "actor_alias": "anon",
                    "proof_receipt_ids": [r_anon["receipt_id"]],
                    "control_receipt_ids": [r_alice["receipt_id"]],
                    "evidence_value": "ADMIN_EXPORT_CANARY_42",
                    "summary": "Should fail",
                },
            )
        )
        assert bad_rf["rejected"] is True
        assert not [f for f in sf.all_facts() if f["fact_type"] == "verified_primitive"]

        # Verified BFLA finding publishes verified_primitive
        ok_rf = json.loads(
            disp.dispatch(
                "record_finding",
                {
                    "title": "Admin export BFLA",
                    "class_type": "bfla",
                    "method": "GET",
                    "url": "/api/admin/export",
                    "actor_alias": "alice",
                    "proof_receipt_ids": [r_alice["receipt_id"]],
                    "control_receipt_ids": [r_anon["receipt_id"]],
                    "evidence_value": "ADMIN_EXPORT_CANARY_42",
                    "summary": "Member alice accessed admin export",
                },
            )
        )
        assert ok_rf["accepted"] is True
        vp_facts = [f for f in sf.all_facts() if f["fact_type"] == "verified_primitive"]
        assert len(vp_facts) == 1
        assert vp_facts[0]["canonical_key"] == "bfla:GET:/api/admin/export"
        assert "bfla GET /api/admin/export actor=alice" in vp_facts[0]["summary"]

        # E. notebook(action="publish_fact") receipt grounding checks
        fetch_out = json.loads(
            disp.dispatch("http_request", {"method": "GET", "url": "/api/fetch?target_url=http://example.com", "actor": "alice"})
            .split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1]
            .split("\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1)[0]
        )
        fetch_rid = fetch_out["receipt_id"]

        # Ungrounded hallucination -> rejected cleanly
        ungrounded = json.loads(
            disp.dispatch(
                "notebook",
                {
                    "action": "publish_fact",
                    "fact": {
                        "fact_type": "ssrf_sink",
                        "key": "ssrf_sink:/api/phantom_endpoint:webhook_callback",
                        "summary": "Hallucinated SSRF sink",
                        "source_receipt_id": fetch_rid,
                    },
                },
            )
        )
        assert ungrounded == {"rejected": True, "reason": "fact_not_grounded_in_receipt"}

        # Invalid fact_type and missing receipt -> rejected cleanly
        bad_type = json.loads(
            disp.dispatch(
                "notebook",
                {
                    "action": "publish_fact",
                    "fact": {
                        "fact_type": "made_up_type",
                        "key": "/api/fetch",
                        "summary": "Bad type",
                        "source_receipt_id": fetch_rid,
                    },
                },
            )
        )
        assert bad_type["rejected"] is True

        missing_rid = json.loads(
            disp.dispatch(
                "notebook",
                {
                    "action": "publish_fact",
                    "fact": {
                        "fact_type": "ssrf_sink",
                        "key": "/api/fetch:target_url",
                        "summary": "Missing receipt",
                        "source_receipt_id": "req-9999",
                    },
                },
            )
        )
        assert missing_rid["rejected"] is True

        # Grounded claim -> accepted, stored with provenance="model_receipt_verified", and noted in notebook
        grounded = json.loads(
            disp.dispatch(
                "notebook",
                {
                    "action": "publish_fact",
                    "fact": {
                        "fact_type": "ssrf_sink",
                        "key": "ssrf_sink:/api/fetch:target_url",
                        "summary": "GET /api/fetch accepts target_url SSRF parameter",
                        "source_receipt_id": fetch_rid,
                        "target_families": ["fetch", "ssrf"],
                    },
                },
            )
        )
        assert grounded["published"] is True
        assert grounded["fact"]["provenance"] == "model_receipt_verified"
        assert grounded["fact"]["source_receipt_id"] == fetch_rid
        assert any(grounded["fact"]["fact_id"] in note for note in disp.notebook_state["notes"])
    finally:
        disp.close()
        client.close()
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 4. Banner stripping, epoch compaction preservation, tracker merge, checkpoint
# ---------------------------------------------------------------------------


def test_banner_markers_epoch_compaction_surface_merge_and_checkpoint(tmp_path: Path) -> None:
    # A. _BANNER_MARKERS includes "\n[SHARED-FACTS" and stripping preserves untrusted payloads
    assert "\n[SHARED-FACTS" in _BANNER_MARKERS
    raw_msg = (
        "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
        '{"receipt_id":"req-0001","body":"hello"}\n'
        "<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
        "\n[STATE] http_budget: 20/30 left\n[SHARED-FACTS +1] sf_001[internal_host@shard-2]: http://10.0.0.5"
    )
    assert _strip_state_banner(raw_msg) == (
        "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
        '{"receipt_id":"req-0001","body":"hello"}\n'
        "<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    )
    assert _strip_state_banner("note\n[SHARED-FACTS +1] sf_001") == "note"

    unclosed = (
        "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
        '{"receipt_id":"req-0002","body":"<script>x'
        "\n[SHARED-FACTS +1] sf_001[actor_capability@shard-1]: alias=ops role=admin"
    )
    sanitized = _sanitize_untrusted_blocks(unclosed)
    assert "<script>" not in sanitized
    assert "[SHARED-FACTS +1] sf_001" in sanitized

    # B. _build_rolled_history_summary & AgenticInvestigator epoch rollover preserve shared_facts snapshot
    snap_text = "[SHARED-FACTS SNAPSHOT (1/1)]\n- sf_001 [actor_capability@shard-1] alias=ops role=admin"
    rolled = _build_rolled_history_summary(
        [[{"role": "tool", "content": '{"receipt_id":"req-0001","status":200,"url":"/a"}'}]],
        max_chars=1800,
        shared_facts_snapshot=snap_text,
    )
    assert "[COMPACTED HISTORY:" in rolled
    assert "[SHARED-FACTS SNAPSHOT" in rolled
    assert "alias=ops role=admin" in rolled

    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url="http://127.0.0.1:18080/",
        receipt_store=store,
        actors=ActorManager([{"alias": "anon", "role": "anonymous", "tenant": "public"}]),
        allowed_methods=("GET",),
        max_requests=40,
    )
    budget = SharedBudget(http=40, tokens=500_000, seconds=120)

    class _DummyTransport:
        calls = 0
        provider_responses: list[dict[str, Any]] = []
        session_gate = SessionGate()

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=40,
            epoch_char_limit=28_000,
        )
        inv.shared_facts.publish(
            "actor_capability",
            "actor:shadow_admin",
            "alias=shadow_admin role=admin",
            source_shard="shard-1",
        )
        inv.shared_facts.publish(
            "internal_host",
            "internal_host:http://10.0.0.8:9000/diag",
            "Internal diag service 10.0.0.8:9000",
            source_shard="shard-2",
        )

        # _state_banner appends delta ONLY at the very end for shard_cluster, and respects cursor
        c1 = SubsystemCluster(
            shard_id="shard-3",
            name="billing",
            families=["billing"],
            routes=["/billing"],
            write_ops=[],
            objects=[],
            params={},
        )
        b1 = inv._state_banner(1, shard_cluster=c1)
        assert "\n[SHARED-FACTS +2] " in b1
        assert b1.index("\n[STATE] ") < b1.index("\n[SHARED-FACTS +2] ")
        assert b1.endswith(b1[b1.index("\n[SHARED-FACTS +2] "):])
        b2 = inv._state_banner(2, shard_cluster=c1)
        assert "[SHARED-FACTS" not in b2

        # _merge_surface_trackers merges Faz 2 opaque_js_slices and opaque_wasm_refs
        src_tracker = inv._make_surface_tracker()
        src_tracker._record_opaque_js_slice({
            "receipt_id": "req-0005",
            "url": "http://127.0.0.1:18080/app.js",
            "region_id": "reg-1",
            "anchor": "crypto.subtle",
            "char_start": 10,
            "char_end": 510,
            "reason": "obfuscated_crypto",
        })
        src_tracker._record_opaque_wasm_refs(["/static/signer.wasm", "/static/signer.wasm"])
        inv._merge_surface_trackers(inv.dispatcher.surface_tracker, src_tracker)
        assert len(inv.dispatcher.surface_tracker.opaque_js_slices) == 1
        assert inv.dispatcher.surface_tracker.opaque_js_slices[0]["anchor"] == "crypto.subtle"
        assert inv.dispatcher.surface_tracker.opaque_wasm_refs == ["/static/signer.wasm"]

        # Trigger epoch compaction above 28,000 bytes and confirm shared_facts snapshot survives rollover
        msgs: list[dict[str, Any]] = [
            {"role": "system", "content": "S" * 1000},
            {"role": "user", "content": "Investigate.\n[STATE] http_budget: 40/40 left | turn: 1/40"},
        ]
        for t in range(1, 12):
            msgs.append({
                "role": "assistant",
                "content": f"Turn {t}",
                "tool_calls": [{"id": f"c_{t}", "type": "function", "function": {"name": "http_request", "arguments": '{"url":"/x"}'}}],
            })
            payload = json.dumps({
                "receipt_id": f"req-{t:04d}",
                "actor": "anon",
                "method": "GET",
                "url": f"http://127.0.0.1:18080/r/{t}",
                "status": 200,
                "body_preview": "X" * 2800,
            })
            msgs.append({
                "role": "tool",
                "tool_call_id": f"c_{t}",
                "content": f"<<<UNTRUSTED_TARGET_RESPONSE>>>\n{payload}\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>\n[STATE] turn: {t + 1}/40",
            })
            body = inv._prepare_bounded_body(msgs)
            # Ensure compact_messages_for_context strips intermediate banners cleanly
            comp = compact_messages_for_context(msgs, keep_recent_turns=2)
            assert "\n[SHARED-FACTS" not in comp[1]["content"]
        assert inv._epoch_advancements >= 1
        assert "[SHARED-FACTS SNAPSHOT" in inv._epoch_summary_text
        assert "shadow_admin" in inv._epoch_summary_text
        assert "10.0.0.8:9000" in body["messages"][1]["content"]

        # Checkpoint save/load roundtrip persists shared_facts.json and restores state
        inv._save_checkpoint(turn=5, status="in_progress", messages=msgs[:4])
        assert (tmp_path / "shared_facts.json").is_file()

        inv2 = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_DummyTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=40,
        )
        assert inv2._load_checkpoint() is not None
        assert len(inv2.shared_facts.all_facts()) == 2
        # Cursor for shard-3 was restored so already-seen facts are not re-sent
        assert inv2.shared_facts.delta_for_shard("shard-3", families=("billing",)) == ""
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 5. collect_cross_shard_synthesis_context & Stage 3 integration
# ---------------------------------------------------------------------------


def test_collect_cross_shard_synthesis_context_with_shared_facts() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=("GET", "POST"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )
    shard_results = [
        {"shard_id": "shard-1", "status": "finished", "finish_summary": "done", "untested_areas": []},
        {"shard_id": "shard-2", "status": "finished", "finish_summary": "done", "untested_areas": []},
    ]

    # 1. internal_host + ssrf_sink triggers Stage 3 and enriches internal_urls / extracted_values / shared_facts
    sf_ssrf = SharedFactGraph()
    sf_ssrf.publish(
        "internal_host",
        "internal_host:http://169.254.169.254/latest/meta-data",
        "Metadata host http://169.254.169.254/latest/meta-data",
        source_shard="shard-1",
    )
    sf_ssrf.publish(
        "ssrf_sink",
        "ssrf_sink:/api/webhooks/test:callback_url",
        "POST /api/webhooks/test fetches callback_url",
        source_shard="shard-2",
    )
    ctx_ssrf = collect_cross_shard_synthesis_context(
        shard_results=shard_results,
        findings=[],
        receipts=None,
        surface_tracker=tracker,
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
        shared_facts=sf_ssrf,
    )
    assert ctx_ssrf["should_trigger"] is True
    assert "http://169.254.169.254/latest/meta-data" in ctx_ssrf["internal_urls"]
    assert any("callback_url" in v for v in ctx_ssrf["extracted_values"])
    assert len(ctx_ssrf["shared_facts"]) == 2

    # Single shard still never triggers Stage 3
    ctx_single = collect_cross_shard_synthesis_context(
        shard_results=[shard_results[0]],
        findings=[],
        receipts=None,
        surface_tracker=tracker,
        shared_facts=sf_ssrf,
    )
    assert ctx_single["should_trigger"] is False

    # 2. New actor_capability triggers Stage 3 and enriches auth_capabilities
    sf_actor = SharedFactGraph()
    sf_actor.publish(
        "actor_capability",
        "actor:shadow_admin",
        "alias=shadow_admin role=admin",
        source_shard="shard-1",
    )
    ctx_actor = collect_cross_shard_synthesis_context(
        shard_results=shard_results,
        findings=[],
        receipts=None,
        surface_tracker=tracker,
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
        shared_facts=sf_actor,
    )
    assert ctx_actor["should_trigger"] is True
    assert any("shadow_admin" in c for c in ctx_actor["auth_capabilities"])

    # 3. verified_primitive across shards + waf_bypass enrich and trigger Stage 3
    sf_vp = SharedFactGraph()
    sf_vp.publish(
        "verified_primitive",
        "bfla:GET:/api/admin/tokens",
        "bfla GET /api/admin/tokens actor=alice",
        source_shard="shard-1",
    )
    sf_vp.publish(
        "verified_primitive",
        "sqli:GET:/api/reports",
        "sqli GET /api/reports actor=alice",
        source_shard="shard-2",
    )
    sf_vp.publish(
        "waf_bypass",
        "waf_bypass:POST:/api/admin/exec",
        "Bypassed WAF via X-Original-URL",
        source_shard="shard-2",
    )
    ctx_vp = collect_cross_shard_synthesis_context(
        shard_results=shard_results,
        findings=[],
        receipts=None,
        surface_tracker=tracker,
        shared_facts=sf_vp,
    )
    assert ctx_vp["should_trigger"] is True
    assert len(ctx_vp["verified_primitives"]) == 2
    assert len(ctx_vp["waf_bypasses"]) == 1

    _, s3_usr = build_cross_shard_synthesis_prompts(
        base_system_prompt="BASE SYS",
        synthesis_context=ctx_vp,
        actor_summaries=[],
        http_budget_remaining=30,
    )
    assert "waf_bypasses" in s3_usr
    assert "verified_primitives" in s3_usr
    assert "X-Original-URL" in s3_usr


def test_end_to_end_sharded_run_propagates_shared_facts_across_shards_and_stage3(tmp_path: Path) -> None:
    class _E2EHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/":
                html = (
                    "<html><body>"
                    "<a href='/api/v1/orders/101'>Orders</a>"
                    "<a href='/api/v1/webhooks/ping?url=https://example.org'>Webhooks</a>"
                    "<a href='/api/v1/invoices/202'>Invoices</a>"
                    "<a href='/api/v1/tickets/303'>Tickets</a>"
                    "<a href='/api/v1/users/profile'>Users</a>"
                    "<a href='/api/v1/reports/daily'>Reports</a>"
                    "<a href='/api/v1/audit/log'>Audit</a>"
                    "<a href='/api/v1/billing/plan'>Billing</a>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            if path == "/api/v1/orders/101":
                body = json.dumps({"id": 101, "internal": "http://169.254.169.254/latest/meta-data"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/api/v1/webhooks/ping":
                body = json.dumps({"ok": True, "url": "https://example.org"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = json.dumps({"path": path, "ok": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _E2EHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    store = ReceiptStore(tmp_path)
    client = AgenticHTTPClient(
        base_url=f"http://127.0.0.1:{port}/",
        receipt_store=store,
        actors=ActorManager([{"alias": "alice", "role": "member", "tenant": "t1"}]),
        allowed_methods=("GET", "POST"),
        max_requests=100,
    )
    budget = SharedBudget(http=100, tokens=250_000, seconds=120)
    lock = threading.Lock()
    s3_prompts: list[str] = []

    class _E2ETransport:
        def __init__(self) -> None:
            self.calls = 0
            self.provider_responses: list[dict[str, Any]] = []
            self.session_gate = SessionGate()
            self._boot_step = 0
            self._shard_steps: dict[str, int] = {}
            self._s3_step = 0

        def complete(self, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
            with lock:
                self.calls += 1
            msgs = body.get("messages") or []
            sys_msg = str((msgs[0] if msgs else {}).get("content") or "")

            if "UNIFIED CROSS-SHARD CHAIN SYNTHESIS (Stage 3)" in sys_msg:
                with lock:
                    self._s3_step += 1
                    s3_prompts.append(str(msgs[1].get("content") or ""))
                return _tool_resp("s3_fin", "finish", {"summary": "Stage 3 received shared facts"})

            if "SUBSYSTEM SHARD SCOPE (" in sys_msg:
                marker = "SUBSYSTEM SHARD SCOPE ("
                shard_id = sys_msg[sys_msg.index(marker) + len(marker):].split(":", 1)[0].strip()
                with lock:
                    step = self._shard_steps.get(shard_id, 0) + 1
                    self._shard_steps[shard_id] = step
                routes_txt = sys_msg.split("Assigned routes:", 1)[1]
                if "orders" in routes_txt:
                    if step == 1:
                        return _tool_resp(f"{shard_id}_1", "http_request", {"method": "GET", "url": "/api/v1/orders/101", "actor": "alice"})
                    if step == 2:
                        last_tool = [m for m in msgs if m.get("role") == "tool"][-1]["content"]
                        rid = json.loads(
                            last_tool.split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1].split("\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1)[0]
                        )["receipt_id"]
                        return _tool_resp(f"{shard_id}_2", "extract_surface", {"receipt_id": rid})
                elif "webhooks" in routes_txt:
                    if step == 1:
                        return _tool_resp(
                            f"{shard_id}_1",
                            "http_request",
                            {"method": "GET", "url": "/api/v1/webhooks/ping?url=https://example.org", "actor": "alice"},
                        )
                    if step == 2:
                        last_tool = [m for m in msgs if m.get("role") == "tool"][-1]["content"]
                        rid = json.loads(
                            last_tool.split("<<<UNTRUSTED_TARGET_RESPONSE>>>\n", 1)[1].split("\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>", 1)[0]
                        )["receipt_id"]
                        return _tool_resp(
                            f"{shard_id}_2",
                            "notebook",
                            {
                                "action": "publish_fact",
                                "fact": {
                                    "fact_type": "ssrf_sink",
                                    "key": "ssrf_sink:/api/v1/webhooks/ping:url",
                                    "summary": "GET /api/v1/webhooks/ping accepts url parameter",
                                    "source_receipt_id": rid,
                                },
                            },
                        )
                return _tool_resp(f"{shard_id}_fin", "finish", {"summary": f"{shard_id} done"})

            with lock:
                self._boot_step += 1
                step = self._boot_step
            if step == 1:
                return _tool_resp("b1", "http_request", {"method": "GET", "url": "/", "actor": "alice"})
            if step == 2:
                return _tool_resp("b2", "extract_surface", {"receipt_id": "req-0001"})
            return _tool_resp("b3", "finish", {"summary": "boot done"})

    try:
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_E2ETransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=30,
            execution_mode="sharded",
            max_shards=3,
            bootstrap_turns=6,
            shard_turns=6,
            sleep_fn=lambda _s: None,
        )
        res = inv.run()
        assert res["status"] == "finished"
        assert (tmp_path / "shared_facts.json").is_file()
        fact_types = {f["fact_type"] for f in inv.shared_facts.all_facts()}
        assert "internal_host" in fact_types
        assert "ssrf_sink" in fact_types
        assert res["sharding_summary"]["stage3_synthesis"]["triggered"] is True
        assert s3_prompts
        assert "169.254.169.254" in s3_prompts[0]
        assert "ssrf_sink" in s3_prompts[0]
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()
