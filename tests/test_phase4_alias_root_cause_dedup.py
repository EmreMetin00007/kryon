"""Unit and live integration tests for Faz 4D alias and root-cause finding deduplication."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import permutations
import json
from pathlib import Path
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from agentic_evidence import (  # noqa: E402
    canonicalize_and_deduplicate_findings,
    strip_single_api_prefix,
)
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import ToolDispatcher  # noqa: E402


def _rec(
    store: ReceiptStore,
    *,
    actor: str,
    method: str,
    url: str,
    status: int = 200,
    body: str = "{}",
    request_body: str = "",
    content_type: str = "application/json",
    response_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    path = urlsplit(url).path or "/"
    return store.record(
        actor=actor,
        method=method,
        url=url,
        path=path,
        status=status,
        elapsed_ms=2.0,
        content_type=content_type,
        request_body=request_body,
        response_headers=response_headers or {"Content-Type": content_type},
        raw_response_bytes=body.encode("utf-8"),
        response_text=body,
    )


def test_strip_single_api_prefix_rules() -> None:
    """Only a single leading `/api/` segment with non-empty sub-path is stripped."""
    assert strip_single_api_prefix("/api/view") == "/view"
    assert strip_single_api_prefix("/view") == "/view"
    assert strip_single_api_prefix("/api/settings") == "/settings"
    assert strip_single_api_prefix("/api/userdata/{id}") == "/userdata/{id}"
    assert strip_single_api_prefix("/api/api/view") == "/api/view"
    assert strip_single_api_prefix("/api") == "/api"
    assert strip_single_api_prefix("/") == "/"


def test_view_vs_api_view_path_traversal_collapse_keeps_critical_order_independently(tmp_path: Path) -> None:
    """`/view` and `/api/view` same-class path_traversal collapse keeping `critical` over `high` in all orders."""
    base_url = "http://127.0.0.1:49457"
    actor_meta = {"anon": {"alias": "anon", "role": "anonymous", "tenant": ""}}
    passwd_body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

    f_view = {
        "finding_id": "F-001",
        "title": "Arbitrary file read via /view traversal",
        "class_type": "path_traversal",
        "severity": "high",
        "method": "GET",
        "url": f"{base_url}/view?filename=passwd&subfolder=..%252F..%252Fetc",
        "path": "/view",
        "actor": "anon",
        "observed_status": 200,
        "evidence_value": "root:x:0:0:root:/root:/bin/bash",
        "proof_receipt_ids": ["req-0101"],
        "control_receipt_ids": ["req-0100"],
        "evidence_excerpts": [
            {
                "receipt_id": "req-0101",
                "actor": "anon",
                "method": "GET",
                "url": f"{base_url}/view?filename=passwd&subfolder=..%252F..%252Fetc",
                "status": 200,
                "excerpt": passwd_body,
            },
        ],
    }
    f_api_view = {
        "finding_id": "F-002",
        "title": "Critical arbitrary file read via /api/view traversal",
        "class_type": "path_traversal",
        "severity": "critical",
        "method": "GET",
        "url": f"{base_url}/api/view?filename=passwd&subfolder=..%252f..%252fetc",
        "path": "/api/view",
        "actor": "anon",
        "observed_status": 200,
        "evidence_value": "root:x:0:0:root:/root:/bin/bash",
        "proof_receipt_ids": ["req-0201"],
        "control_receipt_ids": ["req-0200"],
        "evidence_excerpts": [
            {
                "receipt_id": "req-0201",
                "actor": "anon",
                "method": "GET",
                "url": f"{base_url}/api/view?filename=passwd&subfolder=..%252f..%252fetc",
                "status": 200,
                "excerpt": passwd_body,
            },
        ],
    }

    for perm in permutations([f_view, f_api_view]):
        merged = canonicalize_and_deduplicate_findings(
            list(perm),
            actor_meta_map=actor_meta,
            receipt_store=None,
        )
        assert len(merged) == 1
        f = merged[0]
        assert f["finding_id"] == "F-001"
        assert f["class_type"] == "path_traversal"
        assert f["severity"] == "critical"
        assert f["route_template"] == "/api/view"
        assert f["route_aliases"] == ["/view"]
        assert "/view" in str(f.get("notes") or "")
        assert set(f["proof_receipt_ids"]) == {"req-0101", "req-0201"}
        assert set(f["control_receipt_ids"]) == {"req-0100", "req-0200"}

    # Verify with ReceiptStore populated as well.
    store = ReceiptStore(tmp_path / "receipts")
    r_ctrl1 = _rec(store, actor="anon", method="GET", url=f"{base_url}/view?filename=missing", status=404, body="not found", content_type="text/plain")
    r_ctrl2 = _rec(store, actor="anon", method="GET", url=f"{base_url}/api/view?filename=missing", status=404, body="not found", content_type="text/plain")
    r_p1 = _rec(
        store,
        actor="anon",
        method="GET",
        url=f"{base_url}/view?filename=passwd&subfolder=..%252F..%252Fetc",
        status=200,
        body=passwd_body,
        content_type="text/plain",
    )
    r_p2 = _rec(
        store,
        actor="anon",
        method="GET",
        url=f"{base_url}/api/view?filename=passwd&subfolder=..%252f..%252fetc",
        status=200,
        body=passwd_body,
        content_type="text/plain",
    )
    store_findings = [
        {
            **f_view,
            "proof_receipt_ids": [r_p1["receipt_id"]],
            "control_receipt_ids": [r_ctrl1["receipt_id"]],
        },
        {
            **f_api_view,
            "proof_receipt_ids": [r_p2["receipt_id"]],
            "control_receipt_ids": [r_ctrl2["receipt_id"]],
        },
    ]
    for perm in permutations(store_findings):
        merged_store = canonicalize_and_deduplicate_findings(
            list(perm),
            actor_meta_map=actor_meta,
            receipt_store=store,
        )
        assert len(merged_store) == 1
        f = merged_store[0]
        assert f["severity"] == "critical"
        assert f["route_template"] == "/api/view"
        assert f["path"] == "/api/view"
        assert f["route_aliases"] == ["/view"]
        assert set(f["proof_receipt_ids"]) == {r_p1["receipt_id"], r_p2["receipt_id"]}
        assert set(f["control_receipt_ids"]) == {r_ctrl1["receipt_id"], r_ctrl2["receipt_id"]}


def test_settings_vs_api_settings_mass_assignment_and_cross_class_alias_collapse(tmp_path: Path) -> None:
    """`/settings` vs `/api/settings` collapses for same-class mass_assignment and cross-class Faz 1D pairs."""
    base_url = "http://127.0.0.1:49457"
    actor_meta = {"anon": {"alias": "anon", "role": "anonymous", "tenant": ""}}
    store = ReceiptStore(tmp_path / "receipts")

    r_ctrl_s = _rec(store, actor="anon", method="GET", url=f"{base_url}/settings", body="{}")
    r_ctrl_api = _rec(store, actor="anon", method="GET", url=f"{base_url}/api/settings", body="{}")
    r_w1 = _rec(store, actor="anon", method="POST", url=f"{base_url}/settings", request_body='{"theme": "pwned"}', body='{"ok": true}')
    r_r1 = _rec(store, actor="anon", method="GET", url=f"{base_url}/settings", body='{"theme": "pwned"}')
    r_w2 = _rec(store, actor="anon", method="POST", url=f"{base_url}/api/settings", request_body='{"theme": "override"}', body='{"ok": true}')
    r_r2 = _rec(store, actor="anon", method="GET", url=f"{base_url}/api/settings", body='{"theme": "override"}')

    # Case 1: Same-class mass_assignment on `/settings` (medium) vs `/api/settings` (high).
    f_plain = {
        "title": "Settings mass assignment on /settings",
        "class_type": "mass_assignment",
        "severity": "medium",
        "method": "POST",
        "url": f"{base_url}/settings",
        "actor": "anon",
        "evidence_value": '"theme": "pwned"',
        "proof_receipt_ids": [r_w1["receipt_id"], r_r1["receipt_id"]],
        "control_receipt_ids": [r_ctrl_s["receipt_id"]],
    }
    f_api = {
        "title": "Settings mass assignment on /api/settings",
        "class_type": "mass_assignment",
        "severity": "high",
        "method": "POST",
        "url": f"{base_url}/api/settings",
        "actor": "anon",
        "evidence_value": '"theme": "override"',
        "proof_receipt_ids": [r_w2["receipt_id"], r_r2["receipt_id"]],
        "control_receipt_ids": [r_ctrl_api["receipt_id"]],
    }

    for perm in permutations([f_plain, f_api]):
        merged = canonicalize_and_deduplicate_findings(
            list(perm),
            actor_meta_map=actor_meta,
            receipt_store=store,
        )
        assert len(merged) == 1
        f = merged[0]
        assert f["class_type"] == "mass_assignment"
        assert f["severity"] == "high"
        assert f["route_template"] == "/api/settings"
        assert f["route_aliases"] == ["/settings"]
        assert set(f["proof_receipt_ids"]) == {
            r_w1["receipt_id"],
            r_r1["receipt_id"],
            r_w2["receipt_id"],
            r_r2["receipt_id"],
        }

    # Case 2: Cross-class Faz 1D pair (`other` on `/settings` vs `mass_assignment` on `/api/settings`).
    f_other_plain = {
        **f_plain,
        "title": "Generic settings persistence on /settings",
        "class_type": "other",
    }
    for perm in permutations([f_other_plain, f_api]):
        merged_cross = canonicalize_and_deduplicate_findings(
            list(perm),
            actor_meta_map=actor_meta,
            receipt_store=store,
        )
        assert len(merged_cross) == 1
        assert merged_cross[0]["class_type"] == "mass_assignment"
        assert merged_cross[0]["route_template"] == "/api/settings"
        assert merged_cross[0]["route_aliases"] == ["/settings"]


def test_same_family_userdata_variant_collapse_shared_proof_and_identical_evidence() -> None:
    """`/api/userdata` vs `/api/userdata/{id}` (or encoded subpath) collapses on shared proof or leaked artifact."""
    base_url = "http://127.0.0.1:49457"
    actor_meta = {"anon": {"alias": "anon", "role": "anonymous", "tenant": ""}}

    # Case A: Query listing `/api/userdata?dir=.&full_info=true` vs encoded path `/api/userdata/ComfyUI-Manager%2Fconfig.ini`
    # sharing identical target artifact / leaked evidence (`config.ini` / `[default]\nsecurity_level = normal`).
    f_query = {
        "title": "Userdata directory traversal exposing config.ini",
        "class_type": "path_traversal",
        "severity": "high",
        "method": "GET",
        "url": f"{base_url}/api/userdata?dir=.&full_info=true",
        "actor": "anon",
        "observed_status": 200,
        "evidence_value": "ComfyUI-Manager/config.ini",
        "proof_receipt_ids": ["req-0301"],
        "control_receipt_ids": ["req-0300"],
    }
    f_subpath = {
        "title": "Userdata %2F path traversal reading config.ini",
        "class_type": "path_traversal",
        "severity": "high",
        "method": "GET",
        "url": f"{base_url}/api/userdata/ComfyUI-Manager%2Fconfig.ini",
        "actor": "anon",
        "observed_status": 200,
        "evidence_value": "[default]\nsecurity_level = normal",
        "proof_receipt_ids": ["req-0302"],
        "control_receipt_ids": ["req-0300"],
    }
    for perm in permutations([f_query, f_subpath]):
        merged = canonicalize_and_deduplicate_findings(list(perm), actor_meta_map=actor_meta)
        assert len(merged) == 1
        f = merged[0]
        assert f["class_type"] == "path_traversal"
        assert f["severity"] == "high"
        # Cleaner/more direct endpoint `/api/userdata` wins over percent-encoded subpath when severity & evidence score tie.
        assert f["route_template"] == "/api/userdata"
        assert f["route_aliases"] == ["/api/userdata/comfyui-manager%2fconfig.ini"]
        assert set(f["proof_receipt_ids"]) == {"req-0301", "req-0302"}

    # Case B: `/api/userdata` vs `/api/userdata/{id}` sharing a proof receipt, with higher severity on `{id}`.
    f_root = {
        "title": "Userdata traversal root",
        "class_type": "path_traversal",
        "severity": "medium",
        "method": "GET",
        "url": f"{base_url}/api/userdata?file=secret.ini",
        "actor": "anon",
        "observed_status": 200,
        "evidence_value": "secret_cfg_value=alpha",
        "proof_receipt_ids": ["req-0401", "req-0402"],
        "control_receipt_ids": ["req-0400"],
    }
    f_param_id = {
        "title": "Userdata traversal via item endpoint",
        "class_type": "path_traversal",
        "severity": "critical",
        "method": "GET",
        "url": f"{base_url}/api/userdata/12345",
        "actor": "anon",
        "observed_status": 200,
        "evidence_value": "secret_cfg_value=alpha",
        "proof_receipt_ids": ["req-0402", "req-0403"],
        "control_receipt_ids": ["req-0400"],
    }
    for perm in permutations([f_root, f_param_id]):
        merged_id = canonicalize_and_deduplicate_findings(list(perm), actor_meta_map=actor_meta)
        assert len(merged_id) == 1
        f = merged_id[0]
        assert f["severity"] == "critical"
        assert f["route_template"] == "/api/userdata/{id}"
        assert f["route_aliases"] == ["/api/userdata"]
        assert set(f["proof_receipt_ids"]) == {"req-0401", "req-0402", "req-0403"}

    # Case C: 3-way chain (`/userdata` + `/api/userdata` + `/api/userdata/ComfyUI-Manager%2Fconfig.ini`)
    # must collapse identically across all 6 permutations.
    f_chain_1 = {
        "title": "Userdata leak via /userdata",
        "class_type": "path_traversal",
        "severity": "medium",
        "method": "GET",
        "url": f"{base_url}/userdata?file=config.ini",
        "actor": "anon",
        "observed_status": 200,
        "evidence_value": "[default] security_level=normal",
        "proof_receipt_ids": ["req-0501"],
        "control_receipt_ids": ["req-0500"],
    }
    f_chain_2 = {
        "title": "Userdata leak via /api/userdata",
        "class_type": "path_traversal",
        "severity": "high",
        "method": "GET",
        "url": f"{base_url}/api/userdata?file=config.ini",
        "actor": "anon",
        "observed_status": 200,
        "evidence_value": "[default] security_level=normal",
        "proof_receipt_ids": ["req-0502"],
        "control_receipt_ids": ["req-0500"],
    }
    f_chain_3 = {
        "title": "Userdata leak via subpath",
        "class_type": "path_traversal",
        "severity": "critical",
        "method": "GET",
        "url": f"{base_url}/api/userdata/ComfyUI-Manager%2Fconfig.ini",
        "actor": "anon",
        "observed_status": 200,
        "evidence_value": "[default] security_level=normal",
        "proof_receipt_ids": ["req-0503"],
        "control_receipt_ids": ["req-0500"],
    }
    for perm in permutations([f_chain_1, f_chain_2, f_chain_3]):
        merged_chain = canonicalize_and_deduplicate_findings(list(perm), actor_meta_map=actor_meta)
        assert len(merged_chain) == 1
        f = merged_chain[0]
        assert f["severity"] == "critical"
        assert f["route_template"] == "/api/userdata/comfyui-manager%2fconfig.ini"
        assert f["route_aliases"] == ["/api/userdata", "/userdata"]
        assert set(f["proof_receipt_ids"]) == {"req-0501", "req-0502", "req-0503"}


def test_negative_distinct_classes_actors_methods_and_unrelated_evidence_stay_separate() -> None:
    """Distinct classes, different actors, unrelated methods/evidence, and sibling named routes MUST NOT merge."""
    base_url = "http://127.0.0.1:8080"
    actor_meta = {
        "anon": {"alias": "anon", "role": "anonymous", "tenant": ""},
        "alice": {"alias": "alice", "role": "member", "tenant": "t1"},
        "bob": {"alias": "bob", "role": "member", "tenant": "t2"},
    }

    # 1. GET /view (path_traversal) vs POST /api/view (file_upload) -> MUST remain 2 separate findings!
    view_distinct = [
        {
            "title": "Path traversal on GET /view",
            "class_type": "path_traversal",
            "severity": "critical",
            "method": "GET",
            "url": f"{base_url}/view?filename=passwd&subfolder=..%252Fetc",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "root:x:0:0:root",
            "proof_receipt_ids": ["req-0010"],
            "control_receipt_ids": ["req-0001"],
        },
        {
            "title": "Arbitrary file upload on POST /api/view",
            "class_type": "file_upload",
            "severity": "high",
            "method": "POST",
            "url": f"{base_url}/api/view",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "shell_probe.txt",
            "proof_receipt_ids": ["req-0020"],
            "control_receipt_ids": ["req-0002"],
        },
    ]
    res_view = canonicalize_and_deduplicate_findings(view_distinct, actor_meta_map=actor_meta)
    assert len(res_view) == 2
    assert {f["class_type"] for f in res_view} == {"path_traversal", "file_upload"}

    # 2. Different actors (alice vs bob) on `/view` vs `/api/view` -> MUST remain 2 separate findings!
    diff_actors = [
        {
            "title": "Alice path traversal on /view",
            "class_type": "path_traversal",
            "severity": "high",
            "method": "GET",
            "url": f"{base_url}/view?filename=passwd",
            "actor": "alice",
            "observed_status": 200,
            "evidence_value": "root:x:0:0:root",
            "proof_receipt_ids": ["req-0101"],
            "control_receipt_ids": ["req-0100"],
        },
        {
            "title": "Bob path traversal on /api/view",
            "class_type": "path_traversal",
            "severity": "high",
            "method": "GET",
            "url": f"{base_url}/api/view?filename=passwd",
            "actor": "bob",
            "observed_status": 200,
            "evidence_value": "root:x:0:0:root",
            "proof_receipt_ids": ["req-0102"],
            "control_receipt_ids": ["req-0100"],
        },
    ]
    res_actors = canonicalize_and_deduplicate_findings(diff_actors, actor_meta_map=actor_meta)
    assert len(res_actors) == 2
    assert {f["actor"] for f in res_actors} == {"alice", "bob"}

    # 3. `/docs` vs `/api/docs` with unrelated methods (GET vs POST) -> MUST stay separate!
    docs_diff_method = [
        {
            "title": "Docs HTML info leak",
            "class_type": "info_disclosure",
            "severity": "low",
            "method": "GET",
            "url": f"{base_url}/docs",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "internal_help_build_99",
            "proof_receipt_ids": ["req-0201"],
            "control_receipt_ids": ["req-0200"],
        },
        {
            "title": "API docs POST debug leak",
            "class_type": "info_disclosure",
            "severity": "medium",
            "method": "POST",
            "url": f"{base_url}/api/docs",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "openapi_internal_schema_v3",
            "proof_receipt_ids": ["req-0202"],
            "control_receipt_ids": ["req-0203"],
        },
    ]
    res_docs_method = canonicalize_and_deduplicate_findings(docs_diff_method, actor_meta_map=actor_meta)
    assert len(res_docs_method) == 2

    # 4. `/docs` vs `/api/docs` with SAME method (GET) and SAME status (200) but unrelated params & evidence -> MUST stay separate!
    docs_unrelated_ev = [
        {
            "title": "Docs portal debug header leak",
            "class_type": "info_disclosure",
            "severity": "low",
            "method": "GET",
            "url": f"{base_url}/docs?section=faq",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "HTML_HELP_BUILD_4412",
            "proof_receipt_ids": ["req-0301"],
            "control_receipt_ids": ["req-0300"],
            "evidence_excerpts": [
                {
                    "receipt_id": "req-0301",
                    "actor": "anon",
                    "method": "GET",
                    "url": f"{base_url}/docs?section=faq",
                    "status": 200,
                    "excerpt": "<html><body>Docs FAQ HTML_HELP_BUILD_4412</body></html>",
                },
            ],
        },
        {
            "title": "API docs OpenAPI spec exposure",
            "class_type": "info_disclosure",
            "severity": "medium",
            "method": "GET",
            "url": f"{base_url}/api/docs?format=json",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "openapi_3_1_internal_routes",
            "proof_receipt_ids": ["req-0302"],
            "control_receipt_ids": ["req-0303"],
            "evidence_excerpts": [
                {
                    "receipt_id": "req-0302",
                    "actor": "anon",
                    "method": "GET",
                    "url": f"{base_url}/api/docs?format=json",
                    "status": 200,
                    "excerpt": '{"openapi":"3.1.0","info":{"title":"openapi_3_1_internal_routes"}}',
                },
            ],
        },
    ]
    res_docs_ev = canonicalize_and_deduplicate_findings(docs_unrelated_ev, actor_meta_map=actor_meta)
    assert len(res_docs_ev) == 2

    # 5. Same-family `/api/userdata` vs `/api/userdata/{id}` with disjoint proofs & distinct leaked files -> MUST stay separate!
    userdata_unrelated = [
        {
            "title": "Userdata alpha leak",
            "class_type": "path_traversal",
            "severity": "high",
            "method": "GET",
            "url": f"{base_url}/api/userdata?file=alpha.txt",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "ALPHA_SECRET_KEY_111111",
            "proof_receipt_ids": ["req-0401"],
            "control_receipt_ids": ["req-0400"],
        },
        {
            "title": "Userdata beta leak",
            "class_type": "path_traversal",
            "severity": "high",
            "method": "GET",
            "url": f"{base_url}/api/userdata/999",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "BETA_PRIVATE_TOKEN_999999",
            "proof_receipt_ids": ["req-0402"],
            "control_receipt_ids": ["req-0400"],
        },
    ]
    res_userdata_unrelated = canonicalize_and_deduplicate_findings(userdata_unrelated, actor_meta_map=actor_meta)
    assert len(res_userdata_unrelated) == 2

    # 6. Distinct named sibling routes `/api/admin/users` vs `/api/admin/settings` -> MUST stay separate!
    sibling_named = [
        {
            "title": "Admin users auth bypass",
            "class_type": "auth_bypass",
            "severity": "high",
            "method": "GET",
            "url": f"{base_url}/api/admin/users",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "admin_secret_9a8b7c6d5e4f",
            "proof_receipt_ids": ["req-0501"],
            "control_receipt_ids": ["req-0500"],
        },
        {
            "title": "Admin settings auth bypass",
            "class_type": "auth_bypass",
            "severity": "high",
            "method": "GET",
            "url": f"{base_url}/api/admin/settings",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "admin_secret_9a8b7c6d5e4f",
            "proof_receipt_ids": ["req-0502"],
            "control_receipt_ids": ["req-0500"],
        },
    ]
    res_siblings = canonicalize_and_deduplicate_findings(sibling_named, actor_meta_map=actor_meta)
    assert len(res_siblings) == 2


def _start_live_alias_server() -> tuple[str, ThreadingHTTPServer]:
    settings_state: dict[str, Any] = {}
    lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            del format, args

        def _send(self, code: int, body: str, content_type: str = "application/json") -> None:
            raw = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path in {"/view", "/api/view"}:
                if "passwd" in parsed.query:
                    self._send(
                        200,
                        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
                        "text/plain",
                    )
                    return
                self._send(404, "not found", "text/plain")
                return
            if parsed.path in {"/settings", "/api/settings"}:
                with lock:
                    snap = dict(settings_state)
                self._send(200, json.dumps(snap))
                return
            if parsed.path == "/api/userdata":
                if "dir=." in parsed.query:
                    self._send(200, json.dumps([{"path": "ComfyUI-Manager/config.ini", "size": 64}]))
                    return
                self._send(404, json.dumps({"error": "missing"}))
                return
            if parsed.path.startswith("/api/userdata/"):
                if "config.ini" in parsed.path.lower():
                    self._send(200, "[default]\nsecurity_level = normal\n", "text/plain")
                    return
                self._send(404, "not found", "text/plain")
                return
            if parsed.path == "/docs":
                self._send(200, "<html><body>Docs Portal HTML_HELP_BUILD_4412</body></html>", "text/html")
                return
            if parsed.path == "/api/docs":
                self._send(200, json.dumps({"openapi": "3.1.0", "spec_id": "openapi_3_1_internal_routes"}))
                return
            self._send(404, json.dumps({"error": "not found"}))

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
            if parsed.path in {"/settings", "/api/settings"}:
                data = json.loads(body or "{}")
                with lock:
                    settings_state.update(data)
                self._send(200, json.dumps({"updated": True}))
                return
            if parsed.path == "/api/view":
                self._send(200, json.dumps({"uploaded": "shell_probe.txt"}))
                return
            self._send(404, json.dumps({"error": "not found"}))

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return f"http://127.0.0.1:{port}", srv


def _make_live_dispatcher(tmp_path: Path, base_url: str) -> tuple[ReceiptStore, AgenticHTTPClient, ToolDispatcher]:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager([
        {"alias": "anon", "role": "anonymous", "tenant": ""},
        {"alias": "alice", "role": "member", "tenant": "t1"},
        {"alias": "bob", "role": "member", "tenant": "t2"},
    ])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        max_requests=100,
    )
    dispatcher = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path)
    return store, client, dispatcher


def test_live_try_merge_parity_for_alias_family_and_negatives(tmp_path: Path) -> None:
    """Live ToolDispatcher.record_finding matches post-hoc dedup in both arrival orders and preserves negatives."""
    base_url, srv = _start_live_alias_server()
    try:
        # 1. `/view` (high) vs `/api/view` (critical) in BOTH arrival orders.
        results_by_order: list[dict[str, Any]] = []
        for idx, order_flag in enumerate(("view_first", "api_first")):
            _, client, disp = _make_live_dispatcher(tmp_path / f"view_{order_flag}_{idx}", base_url)
            try:
                c_view = client.request(method="GET", url="/view?filename=missing", actor="anon")
                c_api = client.request(method="GET", url="/api/view?filename=missing", actor="anon")
                p_view = client.request(method="GET", url="/view?filename=passwd&subfolder=..%252Fetc", actor="anon")
                p_api = client.request(method="GET", url="/api/view?filename=passwd&subfolder=..%252fetc", actor="anon")

                call_view = {
                    "title": "Traversal on /view",
                    "class_type": "path_traversal",
                    "severity": "high",
                    "method": "GET",
                    "url": "/view?filename=passwd&subfolder=..%252Fetc",
                    "actor_alias": "anon",
                    "proof_receipt_ids": [p_view["receipt_id"]],
                    "control_receipt_ids": [c_view["receipt_id"]],
                    "evidence_value": "root:x:0:0:root:/root:/bin/bash",
                    "summary": "Path traversal via /view.",
                }
                call_api = {
                    "title": "Critical traversal on /api/view",
                    "class_type": "path_traversal",
                    "severity": "critical",
                    "method": "GET",
                    "url": "/api/view?filename=passwd&subfolder=..%252fetc",
                    "actor_alias": "anon",
                    "proof_receipt_ids": [p_api["receipt_id"]],
                    "control_receipt_ids": [c_api["receipt_id"]],
                    "evidence_value": "root:x:0:0:root:/root:/bin/bash",
                    "summary": "Path traversal via /api/view.",
                }
                calls = [call_view, call_api] if order_flag == "view_first" else [call_api, call_view]
                r1 = json.loads(disp.dispatch("record_finding", calls[0]))
                r2 = json.loads(disp.dispatch("record_finding", calls[1]))
                assert r1["accepted"] is True and r1.get("merged") is not True
                assert r2["accepted"] is True and r2.get("merged") is True
                assert len(disp.findings) == 1
                f = disp.findings[0]
                assert f["severity"] == "critical"
                assert f["route_template"] == "/api/view"
                assert f["path"] == "/api/view"
                assert f["route_aliases"] == ["/view"]
                assert "/view" in str(f.get("notes") or "")
                assert set(f["proof_receipt_ids"]) == {p_view["receipt_id"], p_api["receipt_id"]}
                assert set(f["control_receipt_ids"]) == {c_view["receipt_id"], c_api["receipt_id"]}
                results_by_order.append(f)

                # Negative: POST /api/view (`file_upload`) MUST stay separate from GET /api/view (`path_traversal`)!
                c_post_404 = client.request(method="POST", url="/missing", actor="anon")
                p_upload = client.request(method="POST", url="/api/view", actor="anon", json_body={"file": "shell_probe.txt"})
                r_up = json.loads(disp.dispatch("record_finding", {
                    "title": "File upload on POST /api/view",
                    "class_type": "file_upload",
                    "severity": "high",
                    "method": "POST",
                    "url": "/api/view",
                    "actor_alias": "anon",
                    "proof_receipt_ids": [p_upload["receipt_id"]],
                    "control_receipt_ids": [c_post_404["receipt_id"]],
                    "evidence_value": "shell_probe.txt",
                    "summary": "Unauthenticated upload via POST /api/view.",
                }))
                assert r_up["accepted"] is True and r_up.get("merged") is not True
                assert len(disp.findings) == 2

                # Negative: GET /docs vs GET /api/docs with unrelated evidence MUST stay separate!
                c_404 = client.request(method="GET", url="/missing", actor="anon")
                p_docs = client.request(method="GET", url="/docs", actor="anon")
                p_api_docs = client.request(method="GET", url="/api/docs", actor="anon")
                r_d1 = json.loads(disp.dispatch("record_finding", {
                    "title": "Docs HTML build info disclosure",
                    "class_type": "info_disclosure",
                    "severity": "low",
                    "method": "GET",
                    "url": "/docs",
                    "actor_alias": "anon",
                    "proof_receipt_ids": [p_docs["receipt_id"]],
                    "control_receipt_ids": [c_404["receipt_id"]],
                    "evidence_value": "HTML_HELP_BUILD_4412",
                    "summary": "Build string leaked on /docs.",
                }))
                r_d2 = json.loads(disp.dispatch("record_finding", {
                    "title": "API docs OpenAPI disclosure",
                    "class_type": "info_disclosure",
                    "severity": "medium",
                    "method": "GET",
                    "url": "/api/docs",
                    "actor_alias": "anon",
                    "proof_receipt_ids": [p_api_docs["receipt_id"]],
                    "control_receipt_ids": [c_404["receipt_id"]],
                    "evidence_value": "openapi_3_1_internal_routes",
                    "summary": "OpenAPI spec exposed on /api/docs.",
                }))
                assert r_d1["accepted"] is True and r_d1.get("merged") is not True
                assert r_d2["accepted"] is True and r_d2.get("merged") is not True
                assert len(disp.findings) == 4
            finally:
                client.close()

        assert results_by_order[0]["route_template"] == results_by_order[1]["route_template"] == "/api/view"
        assert results_by_order[0]["severity"] == results_by_order[1]["severity"] == "critical"
        assert results_by_order[0]["route_aliases"] == results_by_order[1]["route_aliases"] == ["/view"]

        # 2. Live `/settings` vs `/api/settings` `mass_assignment` + `/api/userdata` family collapse in both orders.
        for order_flag in ("query_first", "subpath_first"):
            _, client, disp = _make_live_dispatcher(tmp_path / f"live_family_{order_flag}", base_url)
            try:
                c_s = client.request(method="GET", url="/settings", actor="anon")
                p_sw = client.request(method="POST", url="/settings", actor="anon", json_body={"theme": "dark_probe"})
                p_sr = client.request(method="GET", url="/settings", actor="anon")
                p_asw = client.request(method="POST", url="/api/settings", actor="anon", json_body={"theme": "api_probe"})
                p_asr = client.request(method="GET", url="/api/settings", actor="anon")

                rs1 = json.loads(disp.dispatch("record_finding", {
                    "title": "Settings mass assignment via /settings",
                    "class_type": "mass_assignment",
                    "severity": "medium",
                    "method": "POST",
                    "url": "/settings",
                    "actor_alias": "anon",
                    "proof_receipt_ids": [p_sw["receipt_id"], p_sr["receipt_id"]],
                    "control_receipt_ids": [c_s["receipt_id"]],
                    "evidence_value": "dark_probe",
                    "summary": "Settings overwrite via /settings.",
                }))
                rs2 = json.loads(disp.dispatch("record_finding", {
                    "title": "Settings mass assignment via /api/settings",
                    "class_type": "mass_assignment",
                    "severity": "high",
                    "method": "POST",
                    "url": "/api/settings",
                    "actor_alias": "anon",
                    "proof_receipt_ids": [p_asw["receipt_id"], p_asr["receipt_id"]],
                    "control_receipt_ids": [c_s["receipt_id"]],
                    "evidence_value": "api_probe",
                    "summary": "Settings overwrite via /api/settings.",
                }))
                assert rs1["accepted"] is True and rs2["accepted"] is True and rs2.get("merged") is True
                assert len(disp.findings) == 1
                assert disp.findings[0]["severity"] == "high"
                assert disp.findings[0]["route_template"] == "/api/settings"
                assert disp.findings[0]["route_aliases"] == ["/settings"]

                c_ud = client.request(method="GET", url="/api/userdata?dir=missing", actor="anon")
                p_ud_q = client.request(method="GET", url="/api/userdata?dir=.&full_info=true", actor="anon")
                p_ud_p = client.request(method="GET", url="/api/userdata/ComfyUI-Manager%2Fconfig.ini", actor="anon")

                ud_call_q = {
                    "title": "Userdata traversal listing config.ini",
                    "class_type": "path_traversal",
                    "severity": "high",
                    "method": "GET",
                    "url": "/api/userdata?dir=.&full_info=true",
                    "actor_alias": "anon",
                    "proof_receipt_ids": [p_ud_q["receipt_id"]],
                    "control_receipt_ids": [c_ud["receipt_id"]],
                    "evidence_value": "ComfyUI-Manager/config.ini",
                    "summary": "Lists config.ini via userdata dir traversal.",
                }
                ud_call_p = {
                    "title": "Userdata %2F traversal reading config.ini",
                    "class_type": "path_traversal",
                    "severity": "high",
                    "method": "GET",
                    "url": "/api/userdata/ComfyUI-Manager%2Fconfig.ini",
                    "actor_alias": "anon",
                    "proof_receipt_ids": [p_ud_p["receipt_id"]],
                    "control_receipt_ids": [c_ud["receipt_id"]],
                    "evidence_value": "security_level = normal",
                    "summary": "Reads config.ini via %2F path traversal.",
                }
                ud_calls = [ud_call_q, ud_call_p] if order_flag == "query_first" else [ud_call_p, ud_call_q]
                ru1 = json.loads(disp.dispatch("record_finding", ud_calls[0]))
                ru2 = json.loads(disp.dispatch("record_finding", ud_calls[1]))
                assert ru1["accepted"] is True and ru1.get("merged") is not True
                assert ru2["accepted"] is True and ru2.get("merged") is True
                assert len(disp.findings) == 2
                ud_finding = disp.findings[1]
                assert ud_finding["class_type"] == "path_traversal"
                assert ud_finding["route_template"] == "/api/userdata"
                assert ud_finding["route_aliases"] == ["/api/userdata/comfyui-manager%2fconfig.ini"]
                assert set(ud_finding["proof_receipt_ids"]) == {p_ud_q["receipt_id"], p_ud_p["receipt_id"]}
            finally:
                client.close()
    finally:
        srv.shutdown()
        srv.server_close()
