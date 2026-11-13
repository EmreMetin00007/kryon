"""Reasoning/Hunter facade contracts after pure-policy extraction."""

import asyncio
import importlib
import inspect
import os
import subprocess
import sys

from conftest import load_server


REASONING_TOOLS = [
    "plan_attack_tree",
    "next_best_action",
    "critic_review",
    "reason_reflexion",
    "record_lesson",
    "recall_lessons",
    "lesson_stats",
    "deep_think",
    "compose_attack_chains",
    "kill_chain_report",
    "evolve_payload",
    "record_payload_result",
    "exploitability_score",
    "recommend_skills",
    "fingerprint_waf",
    "classify_response",
    "discover_origin",
    "adaptive_evasion_step",
    "verify_origin",
    "generate_state_hypotheses",
]

HUNTER_TOOLS = [
    "predict_vulnerabilities",
    "build_authz_matrix",
    "analyze_authz_result",
    "generate_abuse_cases",
    "hunt_variants",
    "harvest_identifiers",
    "idor_id_candidates",
    "oauth_discovery_checklist",
    "test_access_matrix",
    "coverage_report",
    "coverage_report_run",
    "fuzz_attack_surface",
    "auto_fanout_variants",
    "exploit_confirmed",
    "run_web_loop",
    "enrich_with_rag",
]

RAG_TOOLS = [
    "rag_search",
    "rag_similar_exploits",
    "rag_ingest_exploitdb",
    "rag_ingest_writeup",
    "rag_ingest_cve",
    "rag_bulk_ingest",
    "rag_stats",
]


def _tool_names(module):
    return [tool.name for tool in asyncio.run(module.mcp.list_tools())]


def test_reasoning_facade_preserves_mcp_contract():
    module = load_server("reasoning")
    assert module.mcp.name == "reasoning"
    assert _tool_names(module) == REASONING_TOOLS
    assert list(inspect.signature(module.deep_think).parameters) == [
        "task", "target", "scope", "context", "reflexion"
    ]
    assert list(inspect.signature(module.verify_origin).parameters) == [
        "domain", "candidate_ips", "cdn_fingerprint", "expected_markers",
        "responses_json", "timeout", "live"
    ]


def test_hunter_facade_preserves_mcp_contract():
    module = load_server("hunter")
    assert module.mcp.name == "hunter"
    assert _tool_names(module) == HUNTER_TOOLS
    assert list(inspect.signature(module.auto_fanout_variants).parameters) == [
        "finding_type", "target", "param", "endpoint", "payload", "live",
        "max_requests", "headers", "allow_mutations"
    ]
    assert list(inspect.signature(module.fuzz_attack_surface).parameters) == [
        "target", "limit", "max_requests", "live", "headers", "sleep_s", "sample_limit", "sql_only",
        "ssti_only", "traversal_only"
    ]
    assert list(inspect.signature(module.coverage_report).parameters) == [
        "target", "enqueue_gaps", "campaign_id", "session_bindings", "headers", "request_cost", "max_attempts"
    ]
    assert list(inspect.signature(module.coverage_report_run).parameters) == ["target", "run_id"]
    assert list(inspect.signature(module.exploit_confirmed).parameters) == [
        "validation_id", "validation_artifact", "live", "allow_deepen", "headers"
    ]
    assert list(inspect.signature(module.run_web_loop).parameters) == [
        "target", "live", "crawl", "zap", "cookie", "headers", "fuzz_limit",
        "max_validations", "sleep_s", "identities", "blind_discovery", "blind_differential", "blind_max_requests", "session_bindings", "gap_ref", "candidate_sample_limit", "validation_profile",
    ]
    parameters = inspect.signature(module.run_web_loop).parameters
    assert parameters["blind_discovery"].default is False
    assert parameters["blind_differential"].default is False
    assert parameters["blind_max_requests"].default == 24
    assert parameters["session_bindings"].default == ""
    assert parameters["gap_ref"].default == ""
    assert parameters["candidate_sample_limit"].default == 4
    assert inspect.signature(module.fuzz_attack_surface).parameters["sample_limit"].default == 4
    assert inspect.signature(module.coverage_report).parameters["campaign_id"].default == 0


def test_hunter_facade_loads_in_fresh_process_outside_checkout(tmp_path):
    server = os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-hunter", "server.py")
    env = dict(os.environ, CCO_HOME=str(tmp_path / "state"), CCO_GRAPH_BACKEND="networkx",
               CCO_USE_KEYRING="0", PYTHONDONTWRITEBYTECODE="1")
    env.pop("PYTHONPATH", None)
    code = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location("cold_hunter", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
assert module.HAS_SURFACE
assert callable(module.run_web_loop)
print(module.mcp.name)
"""
    result = subprocess.run([sys.executable, "-c", code, os.path.abspath(server)],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "hunter"


def test_rag_facade_preserves_mcp_contract():
    module = load_server("rag-engine")
    assert module.mcp.name == "rag-engine"
    assert _tool_names(module) == RAG_TOOLS
    assert list(inspect.signature(module.rag_search).parameters) == [
        "query", "collection", "top_k"
    ]


def test_core_modules_are_pure_and_facades_reexport_helpers():
    reasoning = load_server("reasoning")
    hunter = load_server("hunter")
    reasoning_catalog = importlib.import_module("cco_reasoning_core.catalog")
    hunter_catalog = importlib.import_module("cco_hunter_core.catalog")
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-memory-server"))
    surface_store = importlib.import_module("cco_surface_core.store")

    assert not hasattr(reasoning_catalog, "mcp")
    assert not hasattr(hunter_catalog, "mcp")
    assert not hasattr(surface_store, "mcp")
    assert reasoning._normalize_tech is reasoning_catalog.normalize_tech
    assert hunter._norm_class is hunter_catalog.normalize_class
