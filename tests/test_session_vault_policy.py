"""Final session check URL, headers and fresh grant are gated before I/O."""
import json
import sys
from pathlib import Path

import pytest

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from policy_engine import PolicyEngine  # noqa: E402


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home = tmp_path / "home"
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://t.example/allowed"}],
                                 "allow_loopback": False, "allow_public_labs": False,
                                 "allow_osint": False}))
    program = tmp_path / "policy.json"
    program.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"}}))
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(program))
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(program))
    engine.grant_approval("validator_session_vault_check", "t.example", ttl_seconds=600, reason="test")
    validator = load_server("validator")
    calls = []
    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return {"ok": True, "status": 200, "text": "synthetic-account-marker"}
    monkeypatch.setattr(validator, "_request", request)
    return validator, engine, calls


def _store(validator, check_url, research="researcher"):
    return validator.session_vault_put(
        "https://t.example/allowed", "alice", headers_json=json.dumps({"X-Research": research}),
        cookies_json=json.dumps({"session": "synthetic-session"}), check_url=check_url,
        marker="synthetic-account-marker")


def test_scoped_check_is_gated_and_uses_only_one_request(setup):
    validator, _, calls = setup
    _store(validator, "https://t.example/allowed/me")
    out = json.loads(validator.session_vault_check("https://t.example/allowed", "alice"))
    assert out["status"] == "fresh" and out["verdict"] == "CONFIRMED"
    assert len(calls) == 1 and calls[0][2]["allow_redirects"] is False
    assert "synthetic-session" not in json.dumps(out)


@pytest.mark.parametrize("check,research", [
    ("https://t.example/outside", "researcher"),
    ("https://t.example/allowed/me", "wrong"),
    ("https://other.example/allowed/me", "researcher"),
])
def test_scope_origin_and_required_header_fail_before_wire(setup, check, research):
    validator, _, calls = setup
    _store(validator, check, research)
    out = json.loads(validator.session_vault_check("https://t.example/allowed", "alice"))
    assert out["status"] != "fresh" and out["verdict"] == "INCONCLUSIVE"
    assert calls == []


def test_revoked_grant_fails_before_wire(setup):
    validator, engine, calls = setup
    _store(validator, "https://t.example/allowed/me")
    engine.revoke_approval(engine.list_approvals()[0]["id"])
    out = json.loads(validator.session_vault_check("https://t.example/allowed", "alice"))
    assert out["status"] == "blocked" and out["reason"] == "policy_denied" and calls == []


def test_failed_transport_cannot_attest_even_if_it_contains_marker(setup, monkeypatch):
    validator, _, calls = setup
    _store(validator, "https://t.example/allowed/me")
    def failed(*args, **kwargs):
        calls.append(args)
        return {"ok": False, "status": 200, "text": "synthetic-account-marker"}
    monkeypatch.setattr(validator, "_request", failed)
    out = json.loads(validator.session_vault_check("https://t.example/allowed", "alice"))
    assert out["status"] == "stale" and out["verdict"] == "INCONCLUSIVE" and len(calls) == 1
    assert validator._session_store().verified_session("https://t.example/allowed", "alice") is None


@pytest.mark.parametrize("inherited", [False, True])
def test_session_check_counts_policy_once_at_actual_transport(setup, monkeypatch, inherited):
    from cco_validator_core.egress import current_wire_gate, scoped_wire_gate
    validator, engine, calls = setup
    _store(validator, "https://t.example/allowed/me")
    def request(method, url, **kwargs):
        allowed, reason = current_wire_gate()(method, url, kwargs["headers"])
        assert allowed, reason
        calls.append(url)
        return {"ok": True, "status": 200, "text": "synthetic-account-marker"}
    monkeypatch.setattr(validator, "_request", request)
    def gate(method, url, headers):
        result = engine.validate_wire_invocation("validator_session_vault_check", {
            "url": url, "target": url, "method": method, "headers": headers})
        return result["allowed"], result["reason"]
    with scoped_wire_gate(gate if inherited else None):
        result = json.loads(validator.session_vault_check("https://t.example/allowed", "alice"))
    assert result["status"] == "fresh" and len(calls) == 1
    with engine._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM stuck_probes").fetchone()[0] == 1
        assert conn.execute("SELECT SUM(weight) FROM rate_limit_reservations").fetchone()[0] == 1
