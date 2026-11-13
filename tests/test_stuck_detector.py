"""Stuck-detector testleri: imza, esik, makbuz sifirlama, pencere, fail-open."""

import importlib.util
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name, relpath):
    path = REPO_ROOT / relpath
    spec = importlib.util.spec_from_file_location(f"{name}_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _detector():
    return _load("stuck_detector", "scripts/stuck_detector.py")


def _mem():
    conn = sqlite3.connect(":memory:")
    return conn


def test_signature_strips_query_and_groups_shell():
    det = _detector()
    a = det.signature_for("bash", ["https://example.com/api/v2/system/telemetry-export?snapshot_ref=x"], [])
    b = det.signature_for("kali-tools_python_exec", ["https://example.com/api/v2/system/telemetry-export?snapshot_ref=y"], [])
    assert a == b == "shell-probe|example.com/api/v2/system"


def test_signature_keeps_mcp_tool_identity():
    det = _detector()
    url = ["https://example.com/app/login"]
    sqli = det.signature_for("validator_validate_sqli", url, [])
    xss = det.signature_for("validator_validate_xss_reflection", url, [])
    assert sqli != xss
    assert sqli.startswith("validator_validate_sqli|")


def test_signature_none_without_target():
    det = _detector()
    assert det.signature_for("bash", [], []) is None
    assert det.signature_for("read", [], []) is None


def test_signature_falls_back_to_targets():
    det = _detector()
    assert det.signature_for("kali-tools_nmap_scan_structured", [], ["10.0.0.5"]) == \
        "kali-tools_nmap_scan_structured|10.0.0.5|"


def test_receipt_tool_detection():
    det = _detector()
    assert det.is_receipt_tool("reasoning_reason_reflexion") is True
    assert det.is_receipt_tool("reasoning_deep_think") is True
    assert det.is_receipt_tool("kali-tools_curl_request") is False
    assert det.is_receipt_tool("bash") is False


def test_threshold_blocks_eleventh_probe(monkeypatch):
    det = _detector()
    monkeypatch.setenv("CCO_STUCK_THRESHOLD", "10")
    monkeypatch.setenv("CCO_STUCK_WINDOW_MINUTES", "30")
    monkeypatch.setenv("CCO_STUCK_ENABLED", "1")
    conn = _mem()
    url = ["https://example.com/api/v2/system/telemetry-export"]
    for _ in range(10):
        allowed, _ = det.evaluate_probe(conn, "kali-tools_curl_request", url, [])
        assert allowed is True
    allowed, detail = det.evaluate_probe(conn, "kali-tools_curl_request", url, [])
    assert allowed is False
    assert "reasoning_reason_reflexion" in detail
    assert "example.com/api/v2/system" in detail


def test_receipt_resets_counter(monkeypatch):
    det = _detector()
    monkeypatch.setenv("CCO_STUCK_THRESHOLD", "2")
    monkeypatch.setenv("CCO_STUCK_ENABLED", "1")
    conn = _mem()
    url = ["https://example.com/app"]
    det.evaluate_probe(conn, "bash", url, [])
    det.evaluate_probe(conn, "bash", url, [])
    blocked, _ = det.evaluate_probe(conn, "bash", url, [])
    assert blocked is False
    allowed, _ = det.evaluate_probe(conn, "reasoning_reason_reflexion", [], ["example.com"])
    assert allowed is True
    allowed, _ = det.evaluate_probe(conn, "bash", url, [])
    assert allowed is True


def test_old_probes_expire(monkeypatch):
    det = _detector()
    monkeypatch.setenv("CCO_STUCK_THRESHOLD", "2")
    monkeypatch.setenv("CCO_STUCK_WINDOW_MINUTES", "30")
    monkeypatch.setenv("CCO_STUCK_ENABLED", "1")
    conn = _mem()
    det._ensure_tables(conn)
    old = (datetime.now(timezone.utc) - timedelta(minutes=60)).isoformat()
    conn.execute("INSERT INTO stuck_probes (ts, signature) VALUES (?, ?)",
                 (old, "shell-probe|example.com/app"))
    conn.execute("INSERT INTO stuck_probes (ts, signature) VALUES (?, ?)",
                 (old, "shell-probe|example.com/app"))
    conn.commit()
    allowed, _ = det.evaluate_probe(conn, "bash", ["https://example.com/app"], [])
    assert allowed is True


def test_disabled_always_allows(monkeypatch):
    det = _detector()
    monkeypatch.setenv("CCO_STUCK_ENABLED", "0")
    monkeypatch.setenv("CCO_STUCK_THRESHOLD", "1")
    conn = _mem()
    for _ in range(5):
        allowed, _ = det.evaluate_probe(conn, "bash", ["https://example.com/app"], [])
        assert allowed is True


def test_fail_open_on_broken_connection():
    det = _detector()
    conn = _mem()
    conn.close()
    allowed, _ = det.evaluate_probe(conn, "bash", ["https://example.com/app"], [])
    assert allowed is True


def test_policy_engine_blocks_stuck_family(tmp_path):
    engine_mod = _load("policy_engine", "scripts/policy_engine.py")
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "scope.json").write_text(json.dumps({
        "in_scope": [{"asset": "example.com", "type": "web"}],
    }))
    engine = engine_mod.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    url = "https://example.com/api/v2/system/telemetry-export"
    last = None
    for _ in range(11):
        last = engine.validate_tool_invocation("kali-tools_curl_request", {"url": url})
    assert last["allowed"] is False
    assert last["reason"].startswith("blocked_stuck_detected")
    assert "reasoning_reason_reflexion" in last["reason"]


def test_policy_engine_receipt_unblocks(tmp_path):
    engine_mod = _load("policy_engine", "scripts/policy_engine.py")
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "scope.json").write_text(json.dumps({
        "in_scope": [{"asset": "example.com", "type": "web"}],
    }))
    engine = engine_mod.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    url = "https://example.com/api/v2/system/telemetry-export"
    for _ in range(10):
        engine.validate_tool_invocation("kali-tools_curl_request", {"url": url})
    assert engine.validate_tool_invocation(
        "reasoning_plan_attack_tree", {"target": "https://example.com"})["allowed"] is True
    nxt = engine.validate_tool_invocation("kali-tools_curl_request", {"url": url})
    assert nxt["allowed"] is True
