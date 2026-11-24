"""Faz 7D tests: risk-bucketed OpenAPI sharding, family-diverse prompt slicing, and compact CRUD tags."""
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_sharding import (  # noqa: E402
    SubsystemCluster,
    _rank_routes_by_input_risk,
    _select_diverse_top_routes,
    build_shard_prompts,
    cluster_discovered_surface,
)
from agentic_surface import SurfaceFrontierTracker  # noqa: E402


def _alpha_tag(idx: int) -> str:
    """Return a deterministic two-letter alphabetic suffix (aa..zz) that is never treated as a numeric ID."""
    return f"{chr(97 + (idx // 26) % 26)}{chr(97 + (idx % 26))}"


def _build_large_openapi_tracker() -> SurfaceFrontierTracker:
    """Build a 120-route synthetic OpenAPI tracker mirroring JetLinks-style skewed family sizes."""
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8848/",
        allowed_methods=("GET", "POST", "PUT", "PATCH", "DELETE"),
        actor_summaries=[
            {"alias": "admin", "role": "admin", "tenant": "t1"},
            {"alias": "member1", "role": "member", "tenant": "t1"},
        ],
    )

    # 80 noisy device routes (many mutating/parameterized/metadata/count endpoints)
    for i in range(40):
        tag = _alpha_tag(i)
        path = f"/api/device/op/{tag}"
        tracker.discovered_routes[("POST", path)] = path
        tracker.declared_write_ops.add(("POST", path))
        tracker.discovered_params[path] = {f"dev_param_{tag}"}
    for i in range(25):
        tag = _alpha_tag(i)
        path = f"/api/device/{{id}}/sub/{tag}"
        tracker.discovered_routes[("PUT", path)] = path
        tracker.declared_write_ops.add(("PUT", path))
    for i in range(15):
        tag = _alpha_tag(i)
        path = f"/api/device/metadata/info/{tag}"
        tracker.discovered_routes[("GET", path)] = path

    # 4 small high-risk security families (5 routes each = 20 routes)
    small_high_risk: dict[str, list[tuple[str, str, set[str]]]] = {
        "role": [
            ("GET", "/api/role", set()),
            ("POST", "/api/role", {"name", "permissions"}),
            ("GET", "/api/role/{id}", set()),
            ("PUT", "/api/role/{id}", {"name", "role"}),
            ("DELETE", "/api/role/{id}", set()),
        ],
        "user": [
            ("POST", "/api/user/_query", {"query"}),
            ("POST", "/api/user", {"username", "role"}),
            ("GET", "/api/user/{id}", set()),
            ("PUT", "/api/user/{id}", {"email"}),
            ("DELETE", "/api/user/{id}", set()),
        ],
        "file": [
            ("POST", "/api/file/upload", {"file"}),
            ("GET", "/api/file/download", {"file"}),
            ("GET", "/api/file/{id}", set()),
            ("POST", "/api/file/import", {"url"}),
            ("DELETE", "/api/file/{id}", set()),
        ],
        "permission": [
            ("GET", "/api/permission", set()),
            ("POST", "/api/permission", {"action"}),
            ("POST", "/api/permission/_query", {"query"}),
            ("PUT", "/api/permission/{id}", {"role"}),
            ("DELETE", "/api/permission/{id}", set()),
        ],
    }
    for routes in small_high_risk.values():
        for method, path, pnames in routes:
            tracker.discovered_routes[(method, path)] = path
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                tracker.declared_write_ops.add((method, path))
            if pnames:
                tracker.discovered_params[path] = set(pnames)

    # 20 noisy read-only dictionary/count/metadata routes across extra families
    for idx in range(20):
        fam = "dictionary" if idx < 10 else "stats"
        path = f"/api/{fam}/count/{_alpha_tag(idx)}"
        tracker.discovered_routes[("GET", path)] = path

    return tracker


def test_select_diverse_top_routes_avoids_large_family_starvation_and_is_deterministic() -> None:
    entries: list[dict[str, Any]] = [
        {
            "route_template": f"/api/device/ep/{_alpha_tag(i)}",
            "methods": ["POST"],
            "params": ["name"],
            "risk_score": 50 - (i // 4),
        }
        for i in range(60)
    ]
    for fam in ("role", "user", "file", "permission"):
        for j in range(5):
            entries.append({
                "route_template": f"/api/{fam}/op/{_alpha_tag(j)}",
                "methods": ["POST"],
                "params": ["id"],
                "risk_score": 32 - j,
            })

    selected_a = _select_diverse_top_routes(entries, limit=35, max_per_family_pass1=3)
    selected_b = _select_diverse_top_routes(list(reversed(entries)), limit=35, max_per_family_pass1=3)

    assert len(selected_a) == 35
    assert selected_a == selected_b

    templates = [item["route_template"] for item in selected_a]
    for fam in ("device", "role", "user", "file", "permission"):
        fam_hits = [t for t in templates if t.startswith(f"/api/{fam}/")]
        assert len(fam_hits) >= 3, f"expected >=3 routes for {fam}, got {fam_hits}"

    assert len(templates) == len(set(templates)) == 35


def test_large_openapi_cluster_prompt_includes_all_small_high_risk_families() -> None:
    tracker = _build_large_openapi_tracker()
    clusters = cluster_discovered_surface(tracker, max_shards=1, min_routes_for_sharding=8)
    assert len(clusters) == 1
    cluster = clusters[0]
    assert len(cluster.routes) >= 110

    sys_prompt, usr_prompt = build_shard_prompts(
        cluster,
        base_system_prompt="BASE SYSTEM PROMPT",
        surface_tracker=tracker,
    )

    assert "SUBSYSTEM SHARD SCOPE (" in sys_prompt
    assert "- Assigned routes:\n" in sys_prompt
    assert "- Assigned write operations:\n" in sys_prompt
    assert "- Assigned parameters" in sys_prompt

    assigned_routes_sec = sys_prompt.split("- Assigned routes:\n", 1)[1].split("\n- ", 1)[0]
    assigned_writes_sec = sys_prompt.split("- Assigned write operations:\n", 1)[1].split("\n- ", 1)[0]
    assigned_params_sec = sys_prompt.split("- Assigned parameters", 1)[1].split("\n- ", 1)[0]

    # Small high-risk families must NEVER be starved out by 80 device routes
    for required_route in ("/api/role", "/api/role/{id}", "/api/user/_query", "/api/file/upload", "/api/permission"):
        assert required_route in assigned_routes_sec, f"{required_route} missing from Assigned routes"

    for fam_write in ("/api/role", "/api/user/_query", "/api/file/upload", "/api/permission"):
        assert fam_write in assigned_writes_sec, f"{fam_write} missing from Assigned write operations"

    for fam_param in ("/api/role", "/api/user/_query", "/api/file/upload", "/api/permission"):
        assert fam_param in assigned_params_sec, f"{fam_param} missing from Assigned parameters"

    # Low-risk metadata/count routes must not displace high-risk routes in top-35
    assert "/api/dictionary/count/aa" not in assigned_routes_sec
    assert "/api/stats/count/ak" not in assigned_routes_sec
    assert "lower-priority routes omitted;" in assigned_routes_sec
    assert "[MUST-TEST HIGH-RISK INPUTS]" in usr_prompt

    # Multi-shard clustering also preserves all families in their respective shard prompts
    multi_clusters = cluster_discovered_surface(tracker, max_shards=2, min_routes_for_sharding=8)
    assert len(multi_clusters) == 2
    for shard in multi_clusters:
        s_sys, _ = build_shard_prompts(shard, base_system_prompt="BASE", surface_tracker=tracker)
        s_routes_sec = s_sys.split("- Assigned routes:\n", 1)[1].split("\n- ", 1)[0]
        for fam in shard.families:
            if fam in {"role", "user", "file", "permission", "device"}:
                assert f"/api/{fam}" in s_routes_sec, f"{fam} starved in {shard.shard_id}: {s_routes_sec}"


def test_single_family_large_shard_fills_limit_in_descending_risk_order() -> None:
    routes: list[str] = []
    write_ops: list[str] = []
    params: dict[str, list[str]] = {}
    for i in range(60):
        tmpl = f"/api/device/item-{_alpha_tag(i)}"
        routes.append(tmpl)
        if i < 10:
            write_ops.append(f"POST {tmpl}")
            params[tmpl] = ["file", "cmd"]
        elif i < 25:
            write_ops.append(f"PUT {tmpl}")
        elif i < 40:
            params[tmpl] = ["q"]

    cluster = SubsystemCluster(
        shard_id="shard-1",
        name="device",
        families=["device"],
        routes=routes,
        write_ops=write_ops,
        objects=[],
        params=params,
    )

    ranked = _rank_routes_by_input_risk(
        cluster.routes,
        write_ops=cluster.write_ops,
        params=cluster.params,
    )
    selected = _select_diverse_top_routes(ranked, limit=35, max_per_family_pass1=3)
    assert len(selected) == 35
    scores = [int(item["risk_score"]) for item in selected]
    assert scores == sorted(scores, reverse=True)

    sys_prompt, _ = build_shard_prompts(cluster, base_system_prompt="BASE")
    assigned_routes_sec = sys_prompt.split("- Assigned routes:\n", 1)[1].split("\n- ", 1)[0]
    route_lines = [
        line.strip()
        for line in assigned_routes_sec.splitlines()
        if line.strip() and not line.strip().startswith("(+")
    ]
    assert len(route_lines) == 35
    assert "(+25 of 60 total lower-priority routes omitted;" in assigned_routes_sec


def test_compact_method_tags_and_omitted_route_summary_rendering() -> None:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:8848/",
        allowed_methods=("GET", "POST", "PUT", "DELETE"),
        actor_summaries=[{"alias": "admin", "role": "admin", "tenant": "t1"}],
    )
    for method in ("GET", "PUT", "DELETE"):
        tracker.discovered_routes[(method, "/api/role/42")] = "/api/role/42"
    tracker.declared_write_ops.add(("PUT", "/api/role/{id}"))
    tracker.declared_write_ops.add(("DELETE", "/api/role/{id}"))
    for i in range(10):
        tracker.discovered_routes[("GET", f"/api/device/ep-{_alpha_tag(i)}")] = f"/api/device/ep-{_alpha_tag(i)}"

    clusters = cluster_discovered_surface(tracker, max_shards=1, min_routes_for_sharding=8)
    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster.methods_by_route.get("/api/role/{id}") == ["PUT", "DELETE", "GET"]

    # Even without surface_tracker, build_shard_prompts renders compact multi-method tags
    sys_prompt, _ = build_shard_prompts(cluster, base_system_prompt="BASE")
    assigned_routes_sec = sys_prompt.split("- Assigned routes:\n", 1)[1].split("\n- ", 1)[0]
    assert "/api/role/{id} [PUT, DELETE, GET]" in assigned_routes_sec
    assert "/api/device/ep-aa [GET]" in assigned_routes_sec
    # <= 35 routes -> no omitted-route summary line
    assert "lower-priority routes omitted" not in assigned_routes_sec


def test_security_bucket_ranking_prioritizes_security_routes_over_metadata_gets() -> None:
    ranked = _rank_routes_by_input_risk(
        [
            "/api/device-instance/_count",
            "/api/device-instance/dictionary",
            "/api/device-instance/metadata",
            "/api/user/{id}",
            "/api/user/_query",
            "/api/role/{id}",
            "/api/script/exec",
            "/api/file/upload",
        ],
        write_ops=[
            "POST /api/user/_query",
            "PUT /api/role/{id}",
            "DELETE /api/role/{id}",
            "POST /api/script/exec",
            "POST /api/file/upload",
        ],
    )
    score_by_route = {item["route_template"]: int(item["risk_score"]) for item in ranked}
    assert score_by_route["/api/file/upload"] > score_by_route["/api/device-instance/_count"]
    assert score_by_route["/api/role/{id}"] > score_by_route["/api/device-instance/dictionary"]
    assert score_by_route["/api/user/_query"] > score_by_route["/api/device-instance/metadata"]
    assert score_by_route["/api/script/exec"] > score_by_route["/api/device-instance/_count"]
    assert score_by_route["/api/user/{id}"] > score_by_route["/api/device-instance/_count"]
