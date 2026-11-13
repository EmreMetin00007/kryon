"""Host-side ledger + race-check MCP tools (sandbox-proof custody)."""

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_server():
    path = REPO_ROOT / "mcp-servers" / "mcp-kali-tools" / "server.py"
    spec = importlib.util.spec_from_file_location("kali_server_ledger_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_policy_engine():
    path = REPO_ROOT / "scripts" / "policy_engine.py"
    spec = importlib.util.spec_from_file_location("policy_engine_ledger_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _make_run(tmp_path):
    run = tmp_path / "run"
    (run / "ev").mkdir(parents=True)
    (run / "ev" / "probe.body").write_text("probe-body")
    (run / "hypotheses.json").write_text(json.dumps({
        "target": "http://192.0.2.10:8080",
        "target_key": "192.0.2.10:8080",
        "hypotheses": [],
    }))
    return run


def test_ledger_add_then_add_chain_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / ".cco"))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path))
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    server = _load_server()
    run = _make_run(tmp_path)
    first = server.ledger_attempt_add_impl(
        str(run), "authz-idor", "/items/1", "own", "control_own_200",
        status=200, size=10, artifact="ev/probe.body")
    second = server.ledger_attempt_add_impl(
        str(run), "authz-idor", "/items/2", "own", "probe_404_no_foreign_read",
        status=404, size=9)
    assert first["seq"] == 1
    assert second["seq"] == 2
    stored = server._attempt_ledger_mod().read_records(run / "attempts.jsonl")
    assert [r["seq"] for r in stored] == [1, 2]
    assert stored[1]["prev_hash"] == stored[0]["record_hash"]
    covered = server.ledger_coverage_impl(str(run), "authz-idor")
    assert covered["integrity_errors"] == []
    assert covered["trusted_records"] == 2


def test_ledger_add_rejects_workdir_escape(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / ".cco"))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path))
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    server = _load_server()
    run = _make_run(tmp_path)
    for bad in ("/etc/hostname", "../outside.body", "ev/../../outside.body"):
        try:
            server.ledger_attempt_add_impl(
                str(run), "authz-idor", "/items/1", "own", "control_own_200",
                status=200, artifact=bad)
        except ValueError as exc:
            assert "workdir" in str(exc)
        else:
            raise AssertionError(f"escape accepted: {bad}")


def test_race_check_grant_matrix(tmp_path, monkeypatch):
    home = tmp_path / ".cco"
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path))
    server = _load_server()
    engine_mod = _load_policy_engine()
    run = _make_run(tmp_path)

    assert server.race_check_impl(str(run))["allowed"] is False

    engine = engine_mod.PolicyEngine(cco_home=str(home), repo_root=str(tmp_path))
    grant = engine.grant_approval("race_burst", "192.0.2.10", ttl_seconds=600,
                                 reason="test")
    allowed = server.race_check_impl(str(run))
    assert allowed["allowed"] is True
    assert allowed["approval_id"] == grant.id

    engine.revoke_approval(grant.id)
    assert server.race_check_impl(str(run))["allowed"] is False

    stale = engine.grant_approval("race_burst", "192.0.2.10", ttl_seconds=600,
                                 reason="stale")
    conn = sqlite3.connect(home / "audit.db")
    conn.execute("UPDATE approval_grants SET expires_at=? WHERE id=?",
                 ("2000-01-01T00:00:00+00:00", stale.id))
    conn.commit()
    conn.close()
    assert server.race_check_impl(str(run))["allowed"] is False


def test_race_check_rejects_port_pattern_grant(tmp_path, monkeypatch):
    home = tmp_path / ".cco"
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path))
    server = _load_server()
    engine_mod = _load_policy_engine()
    run = _make_run(tmp_path)
    engine = engine_mod.PolicyEngine(cco_home=str(home), repo_root=str(tmp_path))
    engine.grant_approval("race_burst", "192.0.2.10:8080", ttl_seconds=600,
                         reason="port pattern never matches bare host")
    assert server.race_check_impl(str(run))["allowed"] is False


def test_race_check_fails_closed_without_run_target(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / ".cco"))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path))
    server = _load_server()
    run = tmp_path / "empty-run"
    run.mkdir()
    assert server.race_check_impl(str(run))["allowed"] is False


def test_ledger_tools_reject_workdir_outside_cco_workdir(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / ".cco"))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path / "work"))
    (tmp_path / "work").mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    server = _load_server()
    for call in (lambda: server.ledger_attempt_add_impl(
                     str(outside), "csrf", "/support", "own", "probe"),
                 lambda: server.ledger_coverage_impl(str(outside), "csrf"),
                 lambda: server.race_check_impl(str(outside))):
        try:
            call()
        except ValueError as exc:
            assert "CCO_WORKDIR" in str(exc)
        else:
            raise AssertionError("outside workdir accepted")


def test_race_check_denies_on_store_failure(tmp_path, monkeypatch):
    server = _load_server()
    home_file = tmp_path / "notadir"
    home_file.write_text("x")
    monkeypatch.setenv("CCO_HOME", str(home_file))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path))
    run = _make_run(tmp_path)
    decision = server.race_check_impl(str(run))
    assert decision["allowed"] is False


def test_ledger_tools_registered_in_core_group():
    server = _load_server()
    for name in ("ledger_attempt_add", "ledger_coverage", "race_check"):
        assert server.KALI_TOOL_GROUPS.get(name) == "core"
