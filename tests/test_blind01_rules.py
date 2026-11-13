"""blind-01 5 kural: saf fonksiyon testleri (ag/LLM yok)."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "mcp-servers" / "mcp-hunter"))
sys.path.insert(0, str(REPO / "mcp-servers" / "mcp-reasoning"))

from cco_hunter_core.identifiers import extract_identifiers
from cco_reasoning_core.payloads import (
    FAMILY_OPS,
    OAUTH_DISCOVERY,
    idor_id_candidates,
    oauth_discovery_checklist,
)


def test_harvester_uuid_and_ids():
    body = ('{"id": "b0b0b0b0-4444-4444-4444-cccccccccccc", "account_id": "ACCT-ADMIN-001",'
            '"user_id": 9921, "email": "audit.admin@fiserv.com"}')
    out = extract_identifiers(body)
    assert out["uuids"] == ["b0b0b0b0-4444-4444-4444-cccccccccccc"]
    assert "9921" in out["numeric_ids"]
    assert "ACCT-ADMIN-001" in out["account_ids"]
    assert "audit.admin@fiserv.com" in out["emails"]


def test_harvester_empty_safe():
    for bad in (None, "", 123):
        out = extract_identifiers(bad)
        assert out["uuids"] == [] and out["numeric_ids"] == []


def test_harvester_skips_nil_uuid():
    out = extract_identifiers("id=00000000-0000-0000-0000-000000000000")
    assert out["uuids"] == []


def test_xss_families_have_encode_chain():
    for fam in ("xss_reflected", "xss_stored"):
        for op in ("double_url_encode", "html_entity", "hex_char"):
            assert op in FAMILY_OPS[fam], f"{op} yok: {fam}"


def test_idor_candidates_cover_corporate_ranges():
    c = idor_id_candidates()
    assert 1 in c and 5 in c
    assert 1005 in c and 5005 in c and 10005 in c
    assert len(c) < 200


def test_idor_candidates_seed_neighbors():
    c = idor_id_candidates(extra_seeds=("1102", "gecersiz", None))
    assert 1100 in c and 1102 in c and 1107 in c


def test_oauth_discovery_order():
    assert OAUTH_DISCOVERY["probe_order"][-1] == "generic"
    assert "/.well-known/openid-configuration" in OAUTH_DISCOVERY["wellknown_paths"]
    steps = oauth_discovery_checklist()
    assert len(steps) == 5 and "well-known" in steps[0].lower()


def test_harvester_js_identifiers():
    js = ('const cfg = {client_id: "acme-partner-portal", ep: "/api/orders/list", '
          'o2: "/oauth/authorize", k: "MAPS_API_KEY=xyz123 secret"}; '
          'var MAPS_API_KEY="fsv_live_maps_abc";')
    out = extract_identifiers(js)
    assert "acme-partner-portal" in out["client_ids"]
    assert "/api/orders/list" in out["api_paths"]
    assert "/oauth/authorize" in out["api_paths"]
    assert "fsv_live_maps_abc" in out["secret_hints"]


def test_harvester_js_empty_safe():
    out = extract_identifiers("düz metin, kimlik yok")
    assert out["client_ids"] == [] and out["api_paths"] == [] and out["secret_hints"] == []


def test_diff_verdict_finds_bola():
    from cco_hunter_core.identity_pool import diff_verdict
    r = diff_verdict({
        "alice": {"status": 200, "body": '{"owner":"bob","x":1}'},
        "bob": {"status": 200, "body": '{"owner":"bob","x":1}'},
        "anon": {"status": 401, "body": "nope"},
    })
    assert r["isolation_ok"] is False
    assert len(r["violations"]) == 1
    assert set(r["violations"][0]["pair"]) == {"alice", "bob"}


def test_diff_verdict_clean_isolation():
    from cco_hunter_core.identity_pool import diff_verdict
    r = diff_verdict({
        "alice": {"status": 200, "body": '{"owner":"alice"}'},
        "bob": {"status": 403, "body": "denied"},
    })
    assert r["isolation_ok"] is True and r["violations"] == []


def test_diff_verdict_empty_safe():
    from cco_hunter_core.identity_pool import diff_verdict
    r = diff_verdict({})
    assert r["isolation_ok"] is True
