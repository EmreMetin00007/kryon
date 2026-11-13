"""Standalone OOB probes must gate the actual request before transport."""
import json
import sys
from pathlib import Path

import pytest
import requests

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from policy_engine import PolicyEngine  # noqa: E402


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home = tmp_path / "home"
    scope = tmp_path / "scope.json"
    policy = tmp_path / "policy.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test/allowed"},
                                              {"asset": "*.callback.test"}],
                                 "allow_osint": False, "allow_public_labs": False, "allow_loopback": False}))
    policy.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"}}))
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
    engine.grant_approval("validator_validate_ssrf_oob", "owned.test", ttl_seconds=600, reason="synthetic")
    validator = load_server("validator")
    calls = []
    class Response:
        status_code, content, text, headers = 200, b"ok", "ok", {}
    def send(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return Response()
    monkeypatch.setattr(requests, "request", send)
    return validator, engine, calls, monkeypatch


def test_standalone_probe_checks_final_url_scope_headers_and_grant(setup):
    validator, engine, calls, _ = setup
    target = "https://owned.test/allowed/fetch?url=original"
    out = json.loads(validator.validate_ssrf_oob(
        target, "callback.test", param="url", headers_json='{"X-Research":"researcher"}'))
    assert out["verdict"] == "INCONCLUSIVE" and len(calls) == 1
    assert out["evidence"]["collector_binding"]["probe_binding"]
    assert calls[0][0] == "GET" and calls[0][2]["allow_redirects"] is False

    no_header = json.loads(validator.validate_ssrf_oob(target, "callback.test", param="url"))
    outside = json.loads(validator.validate_ssrf_oob(
        "https://owned.test/outside?url=original", "callback.test", param="url",
        headers_json='{"X-Research":"researcher"}'))
    engine.revoke_approval(engine.list_approvals()[0]["id"])
    revoked = json.loads(validator.validate_ssrf_oob(
        target, "callback.test", param="url", headers_json='{"X-Research":"researcher"}'))
    assert all(out["verdict"] == "INCONCLUSIVE" and not out["guard"]["transport_ok"]
               for out in (no_header, outside, revoked))
    assert len(calls) == 1


def test_hunter_parent_gate_is_inherited_and_can_stop_before_transport(setup):
    validator, _, calls, monkeypatch = setup
    from cco_validator_core.egress import scoped_wire_gate
    monkeypatch.setattr(validator, "_standalone_oob_gate", lambda *args: pytest.fail("must inherit parent"))
    checked = []
    def parent(method, url, headers):
        checked.append((method, url))
        return False, "campaign budget exhausted"
    with scoped_wire_gate(parent):
        out = json.loads(validator.validate_ssrf_oob(
            "https://owned.test/allowed/fetch?url=original", "callback.test", param="url",
            headers_json='{"X-Research":"researcher"}'))
    assert len(checked) == 1 and calls == []
    assert out["verdict"] == "INCONCLUSIVE" and not out["guard"]["transport_ok"]


@pytest.mark.parametrize("url", ["http://[invalid?url=x", "https://name:password@owned.test/allowed?url=x",
                                  "https://owned.test/allowed?url=x#fragment", "file:///local?url=x"])
def test_invalid_target_is_rejected_without_transport(setup, url):
    validator, _, calls, _ = setup
    out = json.loads(validator.validate_ssrf_oob(url, "callback.test", param="url"))
    assert out["verdict"] == "INCONCLUSIVE" and not out["guard"]["transport_ok"] and calls == []
