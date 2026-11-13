"""Action manifest şema doğrulama testleri (offline)."""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from action_manifest import validate_manifest, manifest_hash


def _base_manifest():
    return {
        "schema_version": "action-manifest/1.0",
        "objective": "validate_candidate",
        "target_ref": "scope-asset-3",
        "risk": "active_read_only",
        "budget": {"max_requests": 10, "max_duration_seconds": 120},
        "identity_refs": ["owner", "attacker"],
        "steps": [
            {
                "id": "fetch-owner",
                "tool": "http_get",
                "args": {"path": "/order/9"},
                "expect": {"oracle": "status_code"},
                "on_success": "fetch-attacker",
                "on_failure": "abort",
                "max_requests": 1,
            },
            {
                "id": "fetch-attacker",
                "tool": "http_get",
                "args": {"path": "/order/9"},
                "expect": {"oracle": "differential_content"},
                "on_success": "succeed",
                "on_failure": "fail",
            },
        ],
    }


def test_valid_chain_passes():
    out = validate_manifest(_base_manifest())
    assert out["valid"] is True
    assert out["errors"] == []
    assert len(out["manifest_hash"]) == 64
    assert out["stats"]["steps"] == 2


def test_valid_json_string_passes():
    out = validate_manifest(json.dumps(_base_manifest()))
    assert out["valid"] is True


def test_hash_is_stable():
    first = manifest_hash(_base_manifest())
    second = validate_manifest(json.loads(json.dumps(_base_manifest())))["manifest_hash"]
    assert first == second


def test_unknown_goto_rejected():
    manifest = _base_manifest()
    manifest["steps"][0]["on_success"] = "nope"
    out = validate_manifest(manifest)
    assert out["valid"] is False
    assert any("tanımsız hedef" in e for e in out["errors"])


def test_unknown_oracle_rejected():
    manifest = _base_manifest()
    manifest["steps"][1]["expect"]["oracle"] = "vibes"
    out = validate_manifest(manifest)
    assert out["valid"] is False
    assert any("oracle" in e for e in out["errors"])


def test_step_budget_cannot_exceed_manifest():
    manifest = _base_manifest()
    manifest["steps"][0]["max_requests"] = 99
    out = validate_manifest(manifest)
    assert out["valid"] is False
    assert any("bütçe" in e for e in out["errors"])


def test_bad_risk_and_schema_rejected():
    manifest = _base_manifest()
    manifest["risk"] = "yolo"
    manifest["schema_version"] = "v9"
    out = validate_manifest(manifest)
    assert out["valid"] is False
    assert len(out["errors"]) >= 2


def test_duplicate_and_empty_steps_rejected():
    manifest = _base_manifest()
    manifest["steps"][1]["id"] = "fetch-owner"
    out = validate_manifest(manifest)
    assert out["valid"] is False
    assert any("tekrarlanan" in e for e in out["errors"])

    manifest["steps"] = []
    out = validate_manifest(manifest)
    assert out["valid"] is False

    out = validate_manifest("not-json{")
    assert out["valid"] is False


def test_route_cap_validated():
    manifest = _base_manifest()
    manifest["budget"]["route_cap"] = 10
    assert validate_manifest(manifest)["valid"] is True
    manifest["budget"]["route_cap"] = -1
    out = validate_manifest(manifest)
    assert out["valid"] is False
    assert any("route_cap" in e for e in out["errors"])
