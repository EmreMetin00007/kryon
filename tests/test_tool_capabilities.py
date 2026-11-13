import json
from fnmatch import fnmatch
from pathlib import Path

from conftest import load_server, list_tool_names
from test_mcp_servers import EXPECTED_TOOL_COUNTS


REPO_ROOT = Path(__file__).resolve().parents[1]


def _capabilities():
    return json.loads((REPO_ROOT / "config" / "tool-capabilities.json").read_text())


def _match_capability(tool_name, capabilities):
    if tool_name in capabilities.get("tools", {}):
        return capabilities["tools"][tool_name]
    for rule in capabilities.get("patterns", []):
        if fnmatch(tool_name, rule.get("pattern", "")):
            return rule
    return None


def test_all_mcp_tools_have_capability_coverage():
    capabilities = _capabilities()
    missing = []
    for server in EXPECTED_TOOL_COUNTS:
        for tool in list_tool_names(load_server(server)):
            qualified = f"{server}_{tool}"
            if _match_capability(qualified, capabilities) is None:
                missing.append(qualified)
    assert missing == []


def test_high_risk_capability_overrides():
    capabilities = _capabilities()
    drop = _match_capability("memory-server_drop_target_memory", capabilities)
    sqli = _match_capability("validator_validate_sqli", capabilities)
    report = _match_capability("validator_generate_validation_report", capabilities)
    assert drop["destructive"] is True
    assert drop["requires_approval"] is True
    assert sqli["request_multiplier"] >= 8
    assert sqli["requires_scope"] is True
    assert report["network"] is False
    fuzz = _match_capability("hunter_fuzz_attack_surface", capabilities)
    fanout = _match_capability("hunter_auto_fanout_variants", capabilities)
    exploit = _match_capability("hunter_exploit_confirmed", capabilities)
    assert fuzz["network"] is True
    assert fuzz["requires_scope"] is True
    assert fuzz["requires_approval"] is True
    assert fanout["network"] is True
    assert exploit["network"] is True
    assert exploit["requires_approval"] is True
    loop = _match_capability("hunter_run_web_loop", capabilities)
    assert loop["network"] is True
    assert loop["requires_scope"] is True
    assert loop["requires_approval"] is True
    assert loop["request_multiplier"] >= 8
    zap = _match_capability("kali-tools_zap_map_surface", capabilities)
    assert zap["network"] is True
    assert zap["requires_scope"] is True
    assert zap["requires_approval"] is True
    assert zap["request_multiplier"] >= 4
    compose = _match_capability("kali-tools_compose_js_routes", capabilities)
    assert compose["network"] is False
    assert compose["requires_scope"] is False
    assert compose["requires_approval"] is False
    handoff = _match_capability("kali-tools_ledger_prepare_handoff", capabilities)
    assert handoff["network"] is False and handoff["requires_scope"] is True
    assert handoff["requires_approval"] is False and handoff["mutates_local_state"] is True


def test_rag_ingestion_and_retrieval_capabilities_are_explicit():
    capabilities = _capabilities()
    bulk = _match_capability("rag-engine_rag_bulk_ingest", capabilities)
    search = _match_capability("rag-engine_rag_search", capabilities)
    enrich = _match_capability("hunter_enrich_with_rag", capabilities)

    assert bulk["requires_approval"] is True
    assert bulk["mutates_local_state"] is True
    assert search["untrusted_output"] is True
    assert search["sensitive_output"] is True
    assert enrich["untrusted_output"] is True
