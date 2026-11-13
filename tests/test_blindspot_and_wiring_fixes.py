"""Comprehensive regression tests for blind-spot closures, dead-code wiring, and surface integration."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

from conftest import load_server

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))


def test_campaign_worker_resolves_browser_and_all_mcp_prefixes(tmp_path):
    import campaign_worker

    # Both single-prefixed ('browser_security_headers') and double-prefixed
    # ('browser_browser_security_headers') must resolve to mcp-browser's function.
    res1 = campaign_worker._invoke_local_mcp_tool(
        "browser_security_headers", {"url": "ftp://invalid"}, tmp_path
    )
    res2 = campaign_worker._invoke_local_mcp_tool(
        "browser_browser_security_headers", {"url": "ftp://invalid"}, tmp_path
    )
    assert isinstance(res1, str) and ("HATA" in res1 or "playwright" in res1.lower())
    assert res1 == res2
    for prefix in ("agent-browse_", "otp_", "osint-tools_", "ad-tools_", "container-tools_", "ctf-platform_"):
        assert prefix in campaign_worker.TOOL_SERVER_PREFIXES


def test_js_route_queue_blocks_actual_web_advanced_jwt_tools():
    import js_route_queue

    for tool_name in (
        "web-advanced_jwt_attack_alg_none",
        "web-advanced_jwt_rs_to_hs_confusion",
        "web-advanced_jwt_brute_hs256",
        "web-advanced_jwt_attack_kid",
        "web-advanced_jwt_attack_jku",
        "web-advanced_jwt_kid_jku_verify",
    ):
        assert js_route_queue.is_diversion(tool_name, {}), f"{tool_name} should be blocked as diversion"


def test_reasoning_reads_url_targets_attack_surface_and_dead_ends(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    reasoning = load_server("reasoning")
    reasoning.CCO_HOME = str(tmp_path)
    reasoning.MEM_DB = str(tmp_path / "agent_memory.db")
    reasoning.LESSONS_DB = str(tmp_path / "lessons.db")

    mem_dir = str(REPO_ROOT / "mcp-servers" / "mcp-memory-server")
    if mem_dir not in sys.path:
        sys.path.insert(0, mem_dir)
    from cco_surface_core.store import ingest_records

    # Ingest surface records under hostname '127.0.0.1'
    ingest_records(
        [
            {
                "url": "http://127.0.0.1:8899/login",
                "method": "POST",
                "params": [{"name": "username", "in": "body", "sample": "admin"}],
                "source": "crawl",
            }
        ],
        target="127.0.0.1",
        db_path=reasoning.MEM_DB,
    )

    # Record a dead-end lesson for authentication_bypass on 127.0.0.1:8899
    reasoning.record_lesson(
        context="http://127.0.0.1:8899/login form",
        technique="authentication_bypass",
        action="POST /login wiener:peter",
        outcome="401 invalid credentials",
        worked=False,
        tags="127.0.0.1:8899",
    )

    # Query with full URL 'http://127.0.0.1:8899' — must match '127.0.0.1' in DB!
    plan = json.loads(reasoning.plan_attack_tree(target="http://127.0.0.1:8899", expand=False))
    assert plan["endpoints_count"] >= 1
    assert plan["dead_ends"]
    assert plan["dead_ends"][0]["action"] == "POST /login wiener:peter"
    auth_actions = [a for a in plan["ranked_actions"] if a["technique"] == "authentication_bypass"]
    assert auth_actions
    assert "POST /login wiener:peter" in (auth_actions[0].get("avoid_actions") or [])


def test_web_advanced_openapi_and_postman_ingest_into_attack_surface(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    web_adv = load_server("web-advanced")
    web_adv.CCO_HOME = str(tmp_path)
    web_adv.LOG_DIR = str(tmp_path / "web_advanced")
    os.makedirs(web_adv.LOG_DIR, exist_ok=True)

    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0"},
                "servers": [{"url": "https://api.example.test"}],
                "paths": {
                    "/v1/orders": {
                        "post": {
                            "parameters": [{"name": "tenant", "in": "query", "example": "acme"}],
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "order_id": {"type": "integer", "example": 1001},
                                                "coupon": {"type": "string", "default": "WELCOME"},
                                            },
                                        }
                                    }
                                }
                            },
                        }
                    }
                },
            }
        )
    )
    out = web_adv.openapi_ingest(str(spec_file))
    assert "attack_surface tablosuna işlendi" in out

    conn = sqlite3.connect(tmp_path / "agent_memory.db")
    row = conn.execute(
        "SELECT params_json FROM attack_surface WHERE target='api.example.test'"
    ).fetchone()
    conn.close()
    assert row is not None
    params = json.loads(row[0])
    by_name = {p["name"]: (p["in"], p["sample"]) for p in params}
    assert by_name["tenant"] == ("query", "acme")
    assert by_name["order_id"] == ("json", "1001")
    assert by_name["coupon"] == ("json", "WELCOME")


def test_campaign_untested_routes_honours_attack_surface_tested_and_scope(tmp_path):
    from campaign_runtime import CampaignRuntime

    cco = tmp_path / ".cco"
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({"in_scope": [{"asset": "scoped.test", "type": "web"}]}))

    runtime = CampaignRuntime(str(cco))
    cid = runtime.create_campaign("cov-scope", str(scope_file), 50, 0.0)

    mem = sqlite3.connect(cco / "agent_memory.db")
    mem.execute("CREATE TABLE endpoints (id INTEGER PRIMARY KEY, target TEXT, url_or_port TEXT)")
    mem.execute("CREATE TABLE attack_surface (id INTEGER PRIMARY KEY, target TEXT, url TEXT, tested_classes TEXT)")
    mem.executemany(
        "INSERT INTO endpoints (target, url_or_port) VALUES (?, ?)",
        [
            ("scoped.test", "https://scoped.test/api/v1"),
            ("scoped.test", "https://scoped.test/api/v2"),
            ("other-old-target.test", "https://other-old-target.test/legacy"),
        ],
    )
    mem.execute(
        "INSERT INTO attack_surface (target, url, tested_classes) VALUES (?, ?, ?)",
        ("scoped.test", "https://scoped.test/api/v1", json.dumps(["sql_injection"])),
    )
    mem.commit()
    mem.close()

    cov = runtime.untested_routes(cid)
    assert cov["total"] == 2
    assert cov["tested"] == ["https://scoped.test/api/v1"]
    assert cov["untested"] == ["https://scoped.test/api/v2"]


def test_autonomous_bounty_plan_campaign_skips_lab_vectors_on_external_target(tmp_path):
    import autonomous_bounty
    from campaign_runtime import CampaignRuntime

    runtime = CampaignRuntime(str(tmp_path / ".cco"))
    cid_ext = runtime.create_campaign("ext", "", 100, 1.0)
    ext_tasks = autonomous_bounty.plan_campaign(runtime, cid_ext, "https://app.example.com")
    rows_ext = runtime.list_tasks(cid_ext)
    urls_ext = " ".join(r.get("args_json", "") for r in rows_ext)
    assert "/api/orders/1001" not in urls_ext
    assert "alice@lab.local" not in urls_ext
    assert len(ext_tasks) == 5

    cid_lab = runtime.create_campaign("lab", "", 100, 1.0)
    lab_tasks = autonomous_bounty.plan_campaign(runtime, cid_lab, "http://127.0.0.1:8899")
    assert len(lab_tasks) == 11
