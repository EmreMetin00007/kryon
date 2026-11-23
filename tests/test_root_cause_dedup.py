"""Unit and integration tests for Faz 1D root-cause cross-class finding deduplication."""
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

from agentic_evidence import canonicalize_and_deduplicate_findings  # noqa: E402
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
    content_type: str = "application/json",
    response_headers: dict[str, str] | None = None,
    redirect_location: str = "",
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
        response_headers=response_headers or {"Content-Type": content_type},
        redirect_location=redirect_location,
        raw_response_bytes=body.encode("utf-8"),
        response_text=body,
    )


def _make_comfyui_shared_control_triple(base_url: str = "http://127.0.0.1:49457") -> list[dict[str, Any]]:
    """Build the ComfyUI /api/settings triple sharing baseline control req-0016."""
    f_mass = {
        "finding_id": "F-005",
        "title": "Unauthenticated settings tampering via POST /api/settings/{id}",
        "class_type": "mass_assignment",
        "route_template": "/api/settings",
        "method": "GET",
        "url": f"{base_url}/api/settings",
        "path": "/api/settings",
        "actor": "anon",
        "actor_alias": "anon",
        "observed_status": 200,
        "evidence_value": '"Comfy.InstalledVersion": {"value": "9.9.9-shard2"}',
        "marker": '"Comfy.InstalledVersion": {"value": "9.9.9-shard2"}',
        "proof_receipt_ids": ["req-0308", "req-0313"],
        "control_receipt_ids": ["req-0016"],
        "supporting_actors": ["anon"],
        "evidence_excerpts": [
            {
                "receipt_id": "req-0308",
                "actor": "anon",
                "method": "POST",
                "url": f"{base_url}/api/settings/Comfy.InstalledVersion",
                "status": 200,
                "excerpt": "{}",
            },
            {
                "receipt_id": "req-0313",
                "actor": "anon",
                "method": "GET",
                "url": f"{base_url}/api/settings",
                "status": 200,
                "excerpt": '{"Comfy.InstalledVersion": {"value": "9.9.9-shard2"}}',
            },
        ],
        "control_excerpts": [
            {
                "receipt_id": "req-0016",
                "actor": "anon",
                "method": "GET",
                "url": f"{base_url}/api/settings",
                "status": 200,
                "excerpt": "{}",
            },
        ],
    }
    f_other = {
        "finding_id": "F-007",
        "title": "Unauthenticated persistent write to /api/settings",
        "class_type": "other",
        "route_template": "/api/settings",
        "method": "GET",
        "url": f"{base_url}/api/settings",
        "path": "/api/settings",
        "actor": "anon",
        "actor_alias": "anon",
        "observed_status": 200,
        "evidence_value": '{"test.setting": "probe-value-123"}',
        "marker": '{"test.setting": "probe-value-123"}',
        "proof_receipt_ids": ["req-0060", "req-0076"],
        "control_receipt_ids": ["req-0016", "req-0039"],
        "supporting_actors": ["anon"],
        "evidence_excerpts": [
            {
                "receipt_id": "req-0060",
                "actor": "anon",
                "method": "POST",
                "url": f"{base_url}/api/settings",
                "status": 200,
                "excerpt": "{}",
            },
            {
                "receipt_id": "req-0076",
                "actor": "anon",
                "method": "GET",
                "url": f"{base_url}/api/settings",
                "status": 200,
                "excerpt": '{"test.setting": "probe-value-123"}',
            },
        ],
        "control_excerpts": [
            {
                "receipt_id": "req-0016",
                "actor": "anon",
                "method": "GET",
                "url": f"{base_url}/api/settings",
                "status": 200,
                "excerpt": "{}",
            },
            {
                "receipt_id": "req-0039",
                "actor": "anon",
                "method": "GET",
                "url": f"{base_url}/api/settings",
                "status": 200,
                "excerpt": "{}",
            },
        ],
    }
    f_logic = {
        "finding_id": "F-008",
        "title": "Unauthenticated write to server-global settings store",
        "class_type": "business_logic",
        "route_template": "/api/settings",
        "method": "GET",
        "url": f"{base_url}/api/settings",
        "path": "/api/settings",
        "actor": "anon",
        "actor_alias": "anon",
        "observed_status": 200,
        "evidence_value": "shard4_test_value",
        "marker": "shard4_test_value",
        "proof_receipt_ids": ["req-0303", "req-0345"],
        "control_receipt_ids": ["req-0016"],
        "supporting_actors": ["anon"],
        "evidence_excerpts": [
            {
                "receipt_id": "req-0303",
                "actor": "anon",
                "method": "POST",
                "url": f"{base_url}/api/settings",
                "status": 200,
                "excerpt": "{}",
            },
            {
                "receipt_id": "req-0345",
                "actor": "anon",
                "method": "GET",
                "url": f"{base_url}/api/settings",
                "status": 200,
                "excerpt": '{"shard4.key": "shard4_test_value"}',
            },
        ],
        "control_excerpts": [
            {
                "receipt_id": "req-0016",
                "actor": "anon",
                "method": "GET",
                "url": f"{base_url}/api/settings",
                "status": 200,
                "excerpt": "{}",
            },
        ],
    }
    return [f_mass, f_other, f_logic]


def test_comfyui_triple_shared_control_collapses_all_permutations(tmp_path: Path) -> None:
    """mass_assignment + other + business_logic on GET /api/settings with shared control collapse to 1 mass_assignment."""
    base_url = "http://127.0.0.1:49457"
    triple = _make_comfyui_shared_control_triple(base_url)
    actor_meta = {"anon": {"alias": "anon", "role": "anonymous", "tenant": ""}}

    # Without ReceiptStore: all 6 arrival permutations collapse identically to 1 mass_assignment finding.
    for perm in permutations(triple):
        merged = canonicalize_and_deduplicate_findings(
            list(perm),
            actor_meta_map=actor_meta,
            receipt_store=None,
        )
        assert len(merged) == 1
        f = merged[0]
        assert f["finding_id"] == "F-001"
        assert f["class_type"] == "mass_assignment"
        assert f["route_template"] == "/api/settings"
        assert f["actor"] == "anon"
        assert set(f["proof_receipt_ids"]) == {
            "req-0308",
            "req-0313",
            "req-0060",
            "req-0076",
            "req-0303",
            "req-0345",
        }
        assert set(f["control_receipt_ids"]) == {"req-0016", "req-0039"}
        assert len(f["evidence_excerpts"]) == 6
        assert len(f["control_excerpts"]) == 2
        assert f["supporting_actors"] == ["anon"]

    # With ReceiptStore populated with real receipts: still collapses to 1 mass_assignment finding.
    store = ReceiptStore(tmp_path / "receipts")
    r_ctrl_1 = _rec(store, actor="anon", method="GET", url=f"{base_url}/api/settings", body="{}")
    r_ctrl_2 = _rec(store, actor="anon", method="GET", url=f"{base_url}/api/settings", body="{}")
    r_p_ma_w = _rec(store, actor="anon", method="POST", url=f"{base_url}/api/settings/Comfy.InstalledVersion", body="")
    r_p_ma_r = _rec(
        store,
        actor="anon",
        method="GET",
        url=f"{base_url}/api/settings",
        body='{"Comfy.InstalledVersion": {"value": "9.9.9-shard2"}}',
    )
    r_p_ot_w = _rec(store, actor="anon", method="POST", url=f"{base_url}/api/settings", body="")
    r_p_ot_r = _rec(
        store,
        actor="anon",
        method="GET",
        url=f"{base_url}/api/settings",
        body='{"test.setting": "probe-value-123"}',
    )
    r_p_bl_w = _rec(store, actor="anon", method="POST", url=f"{base_url}/api/settings", body="")
    r_p_bl_r = _rec(
        store,
        actor="anon",
        method="GET",
        url=f"{base_url}/api/settings",
        body='{"shard4.key": "shard4_test_value"}',
    )

    store_findings = [
        {
            "title": "Settings mass assignment",
            "class_type": "mass_assignment",
            "method": "GET",
            "url": f"{base_url}/api/settings",
            "actor": "anon",
            "evidence_value": '"Comfy.InstalledVersion": {"value": "9.9.9-shard2"}',
            "proof_receipt_ids": [r_p_ma_w["receipt_id"], r_p_ma_r["receipt_id"]],
            "control_receipt_ids": [r_ctrl_1["receipt_id"]],
        },
        {
            "title": "Settings persistent write",
            "class_type": "other",
            "method": "GET",
            "url": f"{base_url}/api/settings",
            "actor": "anon",
            "evidence_value": '{"test.setting": "probe-value-123"}',
            "proof_receipt_ids": [r_p_ot_w["receipt_id"], r_p_ot_r["receipt_id"]],
            "control_receipt_ids": [r_ctrl_1["receipt_id"], r_ctrl_2["receipt_id"]],
        },
        {
            "title": "Settings business logic tampering",
            "class_type": "business_logic",
            "method": "GET",
            "url": f"{base_url}/api/settings",
            "actor": "anon",
            "evidence_value": "shard4_test_value",
            "proof_receipt_ids": [r_p_bl_w["receipt_id"], r_p_bl_r["receipt_id"]],
            "control_receipt_ids": [r_ctrl_1["receipt_id"]],
        },
    ]
    for perm in permutations(store_findings):
        merged_store = canonicalize_and_deduplicate_findings(
            list(perm),
            actor_meta_map=actor_meta,
            receipt_store=store,
        )
        assert len(merged_store) == 1
        assert merged_store[0]["class_type"] == "mass_assignment"
        assert set(merged_store[0]["proof_receipt_ids"]) == {
            r_p_ma_w["receipt_id"],
            r_p_ma_r["receipt_id"],
            r_p_ot_w["receipt_id"],
            r_p_ot_r["receipt_id"],
            r_p_bl_w["receipt_id"],
            r_p_bl_r["receipt_id"],
        }
        assert set(merged_store[0]["control_receipt_ids"]) == {r_ctrl_1["receipt_id"], r_ctrl_2["receipt_id"]}


def test_comfyui_separate_control_snapshots_collapse_order_independently() -> None:
    """Real ComfyUI shape: F-005 uses pre-write snapshot req-0250 while F-007/F-008 share req-0016."""
    base_url = "http://127.0.0.1:49457"
    f_mass, f_other, f_logic = _make_comfyui_shared_control_triple(base_url)
    # Give mass_assignment its own pre-write GET /api/settings snapshot (req-0250), disjoint from req-0016.
    f_mass["control_receipt_ids"] = ["req-0250"]
    f_mass["control_excerpts"] = [
        {
            "receipt_id": "req-0250",
            "actor": "anon",
            "method": "GET",
            "url": f"{base_url}/api/settings",
            "status": 200,
            "excerpt": '{"test.setting": "probe-value-123"}',
        },
    ]
    # Include an unrelated route finding to ensure it stays untouched.
    f_upload = {
        "finding_id": "F-001",
        "title": "Unauthenticated upload",
        "class_type": "file_upload",
        "route_template": "/api/upload/image",
        "method": "POST",
        "url": f"{base_url}/api/upload/image",
        "path": "/api/upload/image",
        "actor": "anon",
        "observed_status": 200,
        "evidence_value": "probe.txt",
        "proof_receipt_ids": ["req-0034"],
        "control_receipt_ids": ["req-0010"],
    }

    actor_meta = {"anon": {"alias": "anon", "role": "anonymous", "tenant": ""}}
    for perm in permutations([f_mass, f_other, f_logic]):
        merged = canonicalize_and_deduplicate_findings(
            [f_upload, *perm],
            actor_meta_map=actor_meta,
            receipt_store=None,
        )
        assert len(merged) == 2
        by_route = {f["route_template"]: f for f in merged}
        assert by_route["/api/upload/image"]["class_type"] == "file_upload"
        settings_f = by_route["/api/settings"]
        assert settings_f["class_type"] == "mass_assignment"
        assert set(settings_f["proof_receipt_ids"]) == {
            "req-0308",
            "req-0313",
            "req-0060",
            "req-0076",
            "req-0303",
            "req-0345",
        }
        assert set(settings_f["control_receipt_ids"]) == {"req-0250", "req-0016", "req-0039"}


def test_distinct_classes_on_same_route_stay_separate() -> None:
    """Never collapse genuinely distinct vulnerability classes on the same route."""
    actor_meta = {
        "anon": {"alias": "anon", "role": "anonymous", "tenant": ""},
        "alice": {"alias": "alice", "role": "member", "tenant": "t1"},
    }

    # 1. sqli_read + reflected_xss + cors_misconfiguration + open_redirect on /search
    #    MUST remain 4 distinct findings even when sharing a baseline control receipt!
    search_findings = [
        {
            "title": "SQLi on /search",
            "class_type": "sqli_read",
            "method": "GET",
            "url": "http://127.0.0.1:8080/search?q=1'+OR+1=1--",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "secret-row-1",
            "proof_receipt_ids": ["req-0010"],
            "control_receipt_ids": ["req-0001"],
        },
        {
            "title": "Reflected XSS on /search",
            "class_type": "reflected_xss",
            "method": "GET",
            "url": "http://127.0.0.1:8080/search?q=<svg+onload=alert(1)>",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "<svg onload=alert(1)>",
            "proof_receipt_ids": ["req-0011"],
            "control_receipt_ids": ["req-0001"],
        },
        {
            "title": "CORS wildcard on /search",
            "class_type": "cors_misconfiguration",
            "method": "GET",
            "url": "http://127.0.0.1:8080/search",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "https://attacker.example",
            "proof_receipt_ids": ["req-0012"],
            "control_receipt_ids": ["req-0001"],
        },
        {
            "title": "Open redirect on /search",
            "class_type": "open_redirect",
            "method": "GET",
            "url": "http://127.0.0.1:8080/search?next=https://attacker.example",
            "actor": "anon",
            "observed_status": 302,
            "evidence_value": "https://attacker.example",
            "proof_receipt_ids": ["req-0013"],
            "control_receipt_ids": ["req-0001"],
        },
    ]
    merged_search = canonicalize_and_deduplicate_findings(search_findings, actor_meta_map=actor_meta)
    assert [f["class_type"] for f in merged_search] == [
        "sqli_read",
        "reflected_xss",
        "cors_misconfiguration",
        "open_redirect",
    ]

    # 2. bola + stored_xss on /api/v1/notes/{id} MUST stay distinct.
    notes_findings = [
        {
            "title": "BOLA reading peer note",
            "class_type": "bola",
            "method": "GET",
            "url": "http://127.0.0.1:8080/api/v1/notes/42",
            "actor": "alice",
            "observed_status": 200,
            "evidence_value": "note_secret_8f9a0b1c2d3e",
            "proof_receipt_ids": ["req-0100"],
            "control_receipt_ids": ["req-0099"],
        },
        {
            "title": "Stored XSS in note render",
            "class_type": "stored_xss",
            "method": "GET",
            "url": "http://127.0.0.1:8080/api/v1/notes/42",
            "actor": "alice",
            "observed_status": 200,
            "evidence_value": "<img src=x onerror=alert(1)>",
            "proof_receipt_ids": ["req-0101", "req-0102"],
            "control_receipt_ids": ["req-0099"],
        },
    ]
    merged_notes = canonicalize_and_deduplicate_findings(notes_findings, actor_meta_map=actor_meta)
    assert [f["class_type"] for f in merged_notes] == ["bola", "stored_xss"]

    # 3. race_condition + business_logic with disjoint proof receipts stay distinct,
    #    but identical proof_receipt_ids collapse under race_condition.
    race_disjoint = [
        {
            "title": "Promo race condition",
            "class_type": "race_condition",
            "method": "POST",
            "url": "http://127.0.0.1:8080/api/promo/redeem",
            "actor": "alice",
            "observed_status": 200,
            "evidence_value": "redeemed-twice",
            "proof_receipt_ids": ["req-0201", "req-0202"],
            "control_receipt_ids": ["req-0200"],
        },
        {
            "title": "Negative discount business logic flaw",
            "class_type": "business_logic",
            "method": "POST",
            "url": "http://127.0.0.1:8080/api/promo/redeem",
            "actor": "alice",
            "observed_status": 200,
            "evidence_value": "discount=-500",
            "proof_receipt_ids": ["req-0210"],
            "control_receipt_ids": ["req-0200"],
        },
    ]
    merged_race_disjoint = canonicalize_and_deduplicate_findings(race_disjoint, actor_meta_map=actor_meta)
    assert [f["class_type"] for f in merged_race_disjoint] == ["race_condition", "business_logic"]

    race_identical = [
        race_disjoint[0],
        {
            **race_disjoint[1],
            "proof_receipt_ids": ["req-0201", "req-0202"],
        },
    ]
    merged_race_same = canonicalize_and_deduplicate_findings(race_identical, actor_meta_map=actor_meta)
    assert len(merged_race_same) == 1
    assert merged_race_same[0]["class_type"] == "race_condition"

    # 4. Disjoint mass_assignment (PATCH) vs business_logic (POST) stay separate.
    profile_findings = [
        {
            "title": "Mass assignment on profile role",
            "class_type": "mass_assignment",
            "method": "PATCH",
            "url": "http://127.0.0.1:8080/api/profile",
            "actor": "alice",
            "observed_status": 200,
            "evidence_value": "role=admin",
            "proof_receipt_ids": ["req-0301"],
            "control_receipt_ids": ["req-0300"],
        },
        {
            "title": "Business logic credit top-up bypass",
            "class_type": "business_logic",
            "method": "POST",
            "url": "http://127.0.0.1:8080/api/profile",
            "actor": "alice",
            "observed_status": 200,
            "evidence_value": "credits=9999",
            "proof_receipt_ids": ["req-0311"],
            "control_receipt_ids": ["req-0310"],
        },
    ]
    merged_profile = canonicalize_and_deduplicate_findings(profile_findings, actor_meta_map=actor_meta)
    assert [f["class_type"] for f in merged_profile] == ["mass_assignment", "business_logic"]


def test_rule1_other_subsumption_and_disjoint_surface_preservation() -> None:
    """Rule 1 merges `other` on overlap/same surface, but keeps disjoint method/surface `other` separate."""
    actor_meta = {
        "anon": {"alias": "anon", "role": "anonymous", "tenant": ""},
        "bob": {"alias": "bob", "role": "member", "tenant": "t1"},
    }

    # Case A: GET /uploads/ directory listing (`other`) vs POST /uploads/ (`file_upload`) -> SEPARATE!
    # Also test when file_upload has a POST + follow-up GET write-read pair while `other` is read-only GET.
    uploads_disjoint = [
        {
            "title": "Directory listing on /uploads/",
            "class_type": "other",
            "method": "GET",
            "url": "http://127.0.0.1:8080/uploads/",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "Index of /uploads/",
            "proof_receipt_ids": ["req-0401"],
            "control_receipt_ids": ["req-0400"],
            "evidence_excerpts": [
                {"receipt_id": "req-0401", "actor": "anon", "method": "GET", "url": "http://127.0.0.1:8080/uploads/", "status": 200, "excerpt": "Index of /uploads/"}
            ],
        },
        {
            "title": "Arbitrary file upload via POST /uploads/",
            "class_type": "file_upload",
            "method": "POST",
            "url": "http://127.0.0.1:8080/uploads/",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "probe.txt",
            "proof_receipt_ids": ["req-0410", "req-0411"],
            "control_receipt_ids": ["req-0409"],
            "evidence_excerpts": [
                {"receipt_id": "req-0410", "actor": "anon", "method": "POST", "url": "http://127.0.0.1:8080/uploads/", "status": 200, "excerpt": "uploaded"},
                {"receipt_id": "req-0411", "actor": "anon", "method": "GET", "url": "http://127.0.0.1:8080/uploads/probe.txt", "status": 200, "excerpt": "probe.txt"},
            ],
        },
    ]
    merged_uploads = canonicalize_and_deduplicate_findings(uploads_disjoint, actor_meta_map=actor_meta)
    assert [f["class_type"] for f in merged_uploads] == ["other", "file_upload"]

    # Case B: `other` on GET /search (debug banner, no query params) vs `sqli_read` on GET /search?q=... -> SEPARATE!
    search_disjoint = [
        {
            "title": "Debug banner disclosure on /search",
            "class_type": "other",
            "method": "GET",
            "url": "http://127.0.0.1:8080/search",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "DEBUG_BUILD_912",
            "proof_receipt_ids": ["req-0501"],
            "control_receipt_ids": ["req-0500"],
        },
        {
            "title": "SQL injection on /search q param",
            "class_type": "sqli_read",
            "method": "GET",
            "url": "http://127.0.0.1:8080/search?q=1'+OR+1=1--",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "union-row-99",
            "proof_receipt_ids": ["req-0510"],
            "control_receipt_ids": ["req-0509"],
        },
    ]
    merged_search_disjoint = canonicalize_and_deduplicate_findings(search_disjoint, actor_meta_map=actor_meta)
    assert [f["class_type"] for f in merged_search_disjoint] == ["other", "sqli_read"]

    # Case C: `other` sharing proof or control receipt with `file_upload` merges into `file_upload`.
    uploads_overlap = [
        uploads_disjoint[1],
        {
            **uploads_disjoint[0],
            "control_receipt_ids": ["req-0409"],
        },
    ]
    merged_overlap = canonicalize_and_deduplicate_findings(uploads_overlap, actor_meta_map=actor_meta)
    assert len(merged_overlap) == 1
    assert merged_overlap[0]["class_type"] == "file_upload"
    assert set(merged_overlap[0]["proof_receipt_ids"]) == {"req-0410", "req-0411", "req-0401"}

    # Case D: Different actors (`anon` vs `bob`) on same route do NOT merge under Rule 1.
    diff_actor = [
        {
            "title": "Anon info leak",
            "class_type": "other",
            "method": "GET",
            "url": "http://127.0.0.1:8080/api/stats",
            "actor": "anon",
            "observed_status": 200,
            "evidence_value": "stats_v1",
            "proof_receipt_ids": ["req-0601"],
            "control_receipt_ids": ["req-0600"],
        },
        {
            "title": "Bob BFLA on stats",
            "class_type": "bfla",
            "method": "GET",
            "url": "http://127.0.0.1:8080/api/stats",
            "actor": "bob",
            "observed_status": 200,
            "evidence_value": "admin_metric_77",
            "proof_receipt_ids": ["req-0602"],
            "control_receipt_ids": ["req-0600"],
        },
    ]
    merged_diff_actor = canonicalize_and_deduplicate_findings(diff_actor, actor_meta_map=actor_meta)
    assert [f["class_type"] for f in merged_diff_actor] == ["other", "bfla"]


def test_auth_bypass_vs_bfla_preserved_and_auth_bypass_state_overlap(tmp_path: Path) -> None:
    """Existing auth_bypass vs bfla resolution is untouched; auth_bypass + state-tampering handles overlap safely."""
    store = ReceiptStore(tmp_path / "receipts")
    base_url = "http://127.0.0.1:9000"
    actor_meta = {
        "anon": {"alias": "anon", "role": "anonymous", "tenant": ""},
        "bob": {"alias": "bob", "role": "member", "tenant": "t1"},
        "admin": {"alias": "admin", "role": "admin", "tenant": "t1"},
    }

    # 1. Existing auth_bypass vs bfla behavior: anon denied 401 while bob gets 200 -> resolves to bfla.
    r_anon_401 = _rec(store, actor="anon", method="GET", url=f"{base_url}/api/admin/audit", status=401, body='{"error":"denied"}')
    r_bob_200 = _rec(store, actor="bob", method="GET", url=f"{base_url}/api/admin/audit", status=200, body='{"audit_secret":"aud_1122334455667788"}')
    resolved_bfla = canonicalize_and_deduplicate_findings(
        [
            {
                "title": "Auth bypass claim",
                "class_type": "auth_bypass",
                "method": "GET",
                "url": f"{base_url}/api/admin/audit",
                "actor": "bob",
                "proof_receipt_ids": [r_bob_200["receipt_id"]],
                "control_receipt_ids": [r_anon_401["receipt_id"]],
                "evidence_value": "aud_1122334455667788",
            },
            {
                "title": "BFLA claim",
                "class_type": "bfla",
                "method": "GET",
                "url": f"{base_url}/api/admin/audit",
                "actor": "bob",
                "proof_receipt_ids": [r_bob_200["receipt_id"]],
                "control_receipt_ids": [r_anon_401["receipt_id"]],
                "evidence_value": "aud_1122334455667788",
            },
        ],
        actor_meta_map=actor_meta,
        receipt_store=store,
    )
    assert len(resolved_bfla) == 1
    assert resolved_bfla[0]["class_type"] == "bfla"
    assert resolved_bfla[0]["actor"] == "bob"

    # 2. Existing auth_bypass vs bfla behavior: anon genuine 200 -> resolves to auth_bypass.
    r_anon_200 = _rec(store, actor="anon", method="GET", url=f"{base_url}/api/admin/open", status=200, body='{"export_token":"exp_abcdef1234567890"}')
    r_admin_200 = _rec(store, actor="admin", method="GET", url=f"{base_url}/api/admin/open", status=200, body='{"export_token":"exp_abcdef1234567890"}')
    resolved_ab = canonicalize_and_deduplicate_findings(
        [
            {
                "title": "BFLA on open",
                "class_type": "bfla",
                "method": "GET",
                "url": f"{base_url}/api/admin/open",
                "actor": "bob",
                "proof_receipt_ids": [r_anon_200["receipt_id"]],
                "control_receipt_ids": [r_admin_200["receipt_id"]],
                "evidence_value": "exp_abcdef1234567890",
            },
            {
                "title": "Auth bypass on open",
                "class_type": "auth_bypass",
                "method": "GET",
                "url": f"{base_url}/api/admin/open",
                "actor": "anon",
                "proof_receipt_ids": [r_anon_200["receipt_id"]],
                "control_receipt_ids": [r_admin_200["receipt_id"]],
                "evidence_value": "exp_abcdef1234567890",
            },
        ],
        actor_meta_map=actor_meta,
        receipt_store=store,
    )
    assert len(resolved_ab) == 1
    assert resolved_ab[0]["class_type"] == "auth_bypass"
    assert resolved_ab[0]["actor"] == "anon"

    # 3. auth_bypass + mass_assignment sharing a proof receipt on same (route, anon) -> merges under mass_assignment.
    r_post = _rec(store, actor="anon", method="POST", url=f"{base_url}/api/config", status=200, body='{"ok":true}')
    r_get = _rec(store, actor="anon", method="GET", url=f"{base_url}/api/config", status=200, body='{"mode":"tampered"}')
    r_ctrl_admin = _rec(store, actor="admin", method="GET", url=f"{base_url}/api/config", status=200, body='{"mode":"safe"}')
    merged_ab_ma = canonicalize_and_deduplicate_findings(
        [
            {
                "title": "Unauthenticated config access",
                "class_type": "auth_bypass",
                "method": "GET",
                "url": f"{base_url}/api/config",
                "actor": "anon",
                "proof_receipt_ids": [r_get["receipt_id"]],
                "control_receipt_ids": [r_ctrl_admin["receipt_id"]],
                "evidence_value": "tampered",
            },
            {
                "title": "Unauthenticated config mass assignment",
                "class_type": "mass_assignment",
                "method": "GET",
                "url": f"{base_url}/api/config",
                "actor": "anon",
                "proof_receipt_ids": [r_post["receipt_id"], r_get["receipt_id"]],
                "control_receipt_ids": [r_ctrl_admin["receipt_id"]],
                "evidence_value": "tampered",
            },
        ],
        actor_meta_map=actor_meta,
        receipt_store=store,
    )
    assert len(merged_ab_ma) == 1
    assert merged_ab_ma[0]["class_type"] == "mass_assignment"


def _start_live_test_server() -> tuple[str, ThreadingHTTPServer]:
    settings_state: dict[str, Any] = {}
    lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            del format, args

        def _send_json(self, code: int, payload: Any) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path == "/api/settings":
                with lock:
                    snap = dict(settings_state)
                self._send_json(200, snap)
                return
            if parsed.path == "/uploads/":
                raw = b"<html><body>Index of /uploads/ backup.tar</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            if parsed.path == "/search":
                q = parsed.query
                if "1=1" in q:
                    body = "<html><body>rows: sql_secret_row_77</body></html>"
                elif "svg" in q:
                    body = "<html><body>result: <svg onload=alert(1)></body></html>"
                else:
                    body = "<html><body>empty search</body></html>"
                raw = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            self._send_json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
            if parsed.path == "/api/settings":
                data = json.loads(body or "{}")
                with lock:
                    settings_state.update(data)
                self._send_json(200, {"updated": True})
                return
            if parsed.path.startswith("/api/settings/"):
                key = parsed.path.split("/api/settings/", 1)[1]
                data = json.loads(body or "{}")
                with lock:
                    settings_state[key] = data
                self._send_json(200, {"updated": key})
                return
            if parsed.path == "/uploads/":
                self._send_json(200, {"name": "probe.txt", "stored": True})
                return
            self._send_json(404, {"error": "not found"})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return f"http://127.0.0.1:{port}", srv


def _make_live_dispatcher(tmp_path: Path, base_url: str) -> tuple[ReceiptStore, AgenticHTTPClient, ToolDispatcher]:
    store = ReceiptStore(tmp_path / "receipts")
    actors = ActorManager([{"alias": "anon", "role": "anonymous", "tenant": ""}])
    client = AgenticHTTPClient(
        base_url=base_url,
        receipt_store=store,
        actors=actors,
        allowed_methods=("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        max_requests=100,
    )
    dispatcher = ToolDispatcher(http_client=client, receipt_store=store, root_dir=tmp_path)
    return store, client, dispatcher


def test_live_record_finding_merges_comfyui_triple_and_keeps_distinct_separate(tmp_path: Path) -> None:
    """Live ToolDispatcher.record_finding merges cross-class settings duplicates in both orders and keeps distinct bugs separate."""
    base_url, srv = _start_live_test_server()
    try:
        # Order A: mass_assignment -> other -> business_logic
        _, client_a, disp_a = _make_live_dispatcher(tmp_path / "order_a", base_url)
        try:
            ctrl_0 = client_a.request(method="GET", url="/api/settings", actor="anon")
            p_ma_w = client_a.request(
                method="POST",
                url="/api/settings/Comfy.InstalledVersion",
                actor="anon",
                json_body={"value": "9.9.9"},
            )
            p_ma_r = client_a.request(method="GET", url="/api/settings", actor="anon")
            p_ot_w = client_a.request(
                method="POST",
                url="/api/settings",
                actor="anon",
                json_body={"test.setting": "probe-123"},
            )
            p_ot_r = client_a.request(method="GET", url="/api/settings", actor="anon")
            p_bl_w = client_a.request(
                method="POST",
                url="/api/settings",
                actor="anon",
                json_body={"shard4.key": "shard4_val"},
            )
            p_bl_r = client_a.request(method="GET", url="/api/settings", actor="anon")

            r1 = json.loads(disp_a.dispatch("record_finding", {
                "title": "Settings mass assignment",
                "class_type": "mass_assignment",
                "method": "GET",
                "url": "/api/settings",
                "actor_alias": "anon",
                "proof_receipt_ids": [p_ma_w["receipt_id"], p_ma_r["receipt_id"]],
                "control_receipt_ids": [ctrl_0["receipt_id"]],
                "evidence_value": "Comfy.InstalledVersion",
                "summary": "Unauthenticated settings overwrite via /api/settings/{id}.",
            }))
            assert r1["accepted"] is True
            assert r1["class_type"] == "mass_assignment"

            r2 = json.loads(disp_a.dispatch("record_finding", {
                "title": "Persistent write to /api/settings",
                "class_type": "other",
                "method": "POST",
                "url": "/api/settings",
                "actor_alias": "anon",
                "proof_receipt_ids": [p_ot_w["receipt_id"], p_ot_r["receipt_id"]],
                "control_receipt_ids": [ctrl_0["receipt_id"]],
                "evidence_value": "probe-123",
                "summary": "Unauthenticated write persisted to /api/settings.",
            }))
            assert r2["accepted"] is True
            assert r2["merged"] is True
            assert r2["class_type"] == "mass_assignment"

            r3 = json.loads(disp_a.dispatch("record_finding", {
                "title": "Global settings business logic tamper",
                "class_type": "business_logic",
                "method": "POST",
                "url": "/api/settings",
                "actor_alias": "anon",
                "proof_receipt_ids": [p_bl_w["receipt_id"], p_bl_r["receipt_id"]],
                "control_receipt_ids": [ctrl_0["receipt_id"]],
                "evidence_value": "shard4_val",
                "summary": "Unauthenticated write persisted via POST /api/settings.",
            }))
            assert r3["accepted"] is True
            assert r3["merged"] is True
            assert r3["class_type"] == "mass_assignment"

            assert len(disp_a.findings) == 1
            saved = disp_a.findings[0]
            assert saved["class_type"] == "mass_assignment"
            assert set(saved["proof_receipt_ids"]) == {
                p_ma_w["receipt_id"],
                p_ma_r["receipt_id"],
                p_ot_w["receipt_id"],
                p_ot_r["receipt_id"],
                p_bl_w["receipt_id"],
                p_bl_r["receipt_id"],
            }
            assert saved["control_receipt_ids"] == [ctrl_0["receipt_id"]]

            # Distinct classes on /uploads/ (GET dir listing `other` vs POST `file_upload`) stay separate.
            u_ctrl_404 = client_a.request(method="GET", url="/missing", actor="anon")
            u_get = client_a.request(method="GET", url="/uploads/", actor="anon")
            u_post = client_a.request(method="POST", url="/uploads/", actor="anon", json_body={"name": "probe.txt"})
            u_ctrl_post_404 = client_a.request(method="POST", url="/missing", actor="anon")

            ru1 = json.loads(disp_a.dispatch("record_finding", {
                "title": "Directory listing on /uploads/",
                "class_type": "other",
                "method": "GET",
                "url": "/uploads/",
                "actor_alias": "anon",
                "proof_receipt_ids": [u_get["receipt_id"]],
                "control_receipt_ids": [u_ctrl_404["receipt_id"]],
                "evidence_value": "Index of /uploads/",
                "summary": "Unauthenticated directory listing.",
            }))
            assert ru1["accepted"] is True
            assert ru1.get("merged") is not True

            ru2 = json.loads(disp_a.dispatch("record_finding", {
                "title": "Arbitrary file upload on /uploads/",
                "class_type": "file_upload",
                "method": "POST",
                "url": "/uploads/",
                "actor_alias": "anon",
                "proof_receipt_ids": [u_post["receipt_id"]],
                "control_receipt_ids": [u_ctrl_post_404["receipt_id"]],
                "evidence_value": "probe.txt",
                "summary": "Unauthenticated file upload.",
            }))
            assert ru2["accepted"] is True
            assert ru2.get("merged") is not True

            # Distinct classes on /search (sqli_read + reflected_xss) stay separate even with shared control!
            s_ctrl = client_a.request(method="GET", url="/search?q=normal", actor="anon")
            s_sqli = client_a.request(method="GET", url="/search?q=1=1", actor="anon")
            s_xss = client_a.request(method="GET", url="/search?q=svg", actor="anon")
            rs1 = json.loads(disp_a.dispatch("record_finding", {
                "title": "SQLi on /search",
                "class_type": "sqli_read",
                "method": "GET",
                "url": "/search?q=1=1",
                "actor_alias": "anon",
                "proof_receipt_ids": [s_sqli["receipt_id"]],
                "control_receipt_ids": [s_ctrl["receipt_id"]],
                "evidence_value": "sql_secret_row_77",
                "summary": "SQL injection in search query.",
            }))
            rs2 = json.loads(disp_a.dispatch("record_finding", {
                "title": "Reflected XSS on /search",
                "class_type": "reflected_xss",
                "method": "GET",
                "url": "/search?q=svg",
                "actor_alias": "anon",
                "proof_receipt_ids": [s_xss["receipt_id"]],
                "control_receipt_ids": [s_ctrl["receipt_id"]],
                "evidence_value": "<svg onload=alert(1)>",
                "summary": "Reflected XSS in search query.",
            }))
            assert rs1["accepted"] is True and rs1.get("merged") is not True
            assert rs2["accepted"] is True and rs2.get("merged") is not True
            assert [f["class_type"] for f in disp_a.findings] == [
                "mass_assignment",
                "other",
                "file_upload",
                "sqli_read",
                "reflected_xss",
            ]
        finally:
            client_a.close()

        # Order B (reverse specificity arrival): other -> business_logic -> mass_assignment
        # Must live-upgrade class_type and title to mass_assignment with 1 single finding.
        _, client_b, disp_b = _make_live_dispatcher(tmp_path / "order_b", base_url)
        try:
            b_ctrl = client_b.request(method="GET", url="/api/settings", actor="anon")
            b_ot_w = client_b.request(method="POST", url="/api/settings", actor="anon", json_body={"k1": "v1-other"})
            b_ot_r = client_b.request(method="GET", url="/api/settings", actor="anon")
            b_bl_w = client_b.request(method="POST", url="/api/settings", actor="anon", json_body={"k2": "v2-logic"})
            b_bl_r = client_b.request(method="GET", url="/api/settings", actor="anon")
            b_ma_w = client_b.request(
                method="POST",
                url="/api/settings/Comfy.AdminFlag",
                actor="anon",
                json_body={"value": "v3-mass"},
            )
            b_ma_r = client_b.request(method="GET", url="/api/settings", actor="anon")

            rb1 = json.loads(disp_b.dispatch("record_finding", {
                "title": "Generic settings write",
                "class_type": "other",
                "method": "POST",
                "url": "/api/settings",
                "actor_alias": "anon",
                "proof_receipt_ids": [b_ot_w["receipt_id"], b_ot_r["receipt_id"]],
                "control_receipt_ids": [b_ctrl["receipt_id"]],
                "evidence_value": "v1-other",
                "summary": "Generic write.",
            }))
            assert rb1["accepted"] is True and rb1["class_type"] == "other"

            rb2 = json.loads(disp_b.dispatch("record_finding", {
                "title": "Settings business logic tamper",
                "class_type": "business_logic",
                "method": "POST",
                "url": "/api/settings",
                "actor_alias": "anon",
                "proof_receipt_ids": [b_bl_w["receipt_id"], b_bl_r["receipt_id"]],
                "control_receipt_ids": [b_ctrl["receipt_id"]],
                "evidence_value": "v2-logic",
                "summary": "Business logic write.",
            }))
            assert rb2["accepted"] is True and rb2["merged"] is True
            assert rb2["class_type"] == "business_logic"

            rb3 = json.loads(disp_b.dispatch("record_finding", {
                "title": "Settings mass assignment override",
                "class_type": "mass_assignment",
                "method": "GET",
                "url": "/api/settings",
                "actor_alias": "anon",
                "proof_receipt_ids": [b_ma_w["receipt_id"], b_ma_r["receipt_id"]],
                "control_receipt_ids": [b_ctrl["receipt_id"]],
                "evidence_value": "Comfy.AdminFlag",
                "summary": "Mass assignment write.",
            }))
            assert rb3["accepted"] is True and rb3["merged"] is True
            assert rb3["class_type"] == "mass_assignment"

            assert len(disp_b.findings) == 1
            assert disp_b.findings[0]["class_type"] == "mass_assignment"
            assert disp_b.findings[0]["title"] == "Settings mass assignment override"
            assert set(disp_b.findings[0]["proof_receipt_ids"]) == {
                b_ot_w["receipt_id"],
                b_ot_r["receipt_id"],
                b_bl_w["receipt_id"],
                b_bl_r["receipt_id"],
                b_ma_w["receipt_id"],
                b_ma_r["receipt_id"],
            }
        finally:
            client_b.close()
    finally:
        srv.shutdown()
        srv.server_close()
