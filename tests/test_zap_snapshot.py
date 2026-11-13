"""ZAP snapshot import is offline, scope-bound and strips request values."""
import json
import sys
from pathlib import Path

import pytest
from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-memory-server"))
from cco_surface_core.zap import run_zap_map  # noqa: E402
from cco_surface_core.zap_snapshot import import_zap_snapshot  # noqa: E402


@pytest.fixture
def scope(tmp_path, monkeypatch):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test/allowed"}],
                                      "allow_loopback": False, "allow_osint": False,
                                      "allow_public_labs": False}))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope_file))
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))


def test_import_keeps_only_same_origin_scoped_readonly_metadata(scope):
    snapshot = {
        "urls": ["https://owned.test/allowed/a?q=synthetic-secret", "https://owned.test/outside",
                 "https://owned.test:444/allowed", "https://other.test/allowed"],
        "alerts": [{"url": "https://owned.test/allowed/a?q=synthetic-secret", "method": "GET",
                    "alert": "XSS", "evidence": "synthetic-secret"},
                   {"url": "https://owned.test/allowed/a", "method": "POST", "alert": "write"}],
    }
    result = import_zap_snapshot("https://owned.test/allowed", json.dumps(snapshot))
    assert result["ok"] and result["mode"] == "offline_snapshot" and result["discarded"] == 4
    assert result["records"] and len(result["alerts"]) == 1
    assert "synthetic-secret" not in json.dumps(result)
    assert result["calls"] == [] and result["verdict"] is None


def test_zap_live_refuses_before_any_api_call(scope):
    result = run_zap_map("https://owned.test/allowed", allow_ascan=True,
                         request_fn=lambda *args: pytest.fail("ZAP API must not be called"))
    assert not result["ok"] and not result["ascan"]["ran"]


def test_snapshot_rejects_invalid_and_out_of_scope_targets(scope):
    assert not import_zap_snapshot("https://owned.test/outside", '{"urls": [], "alerts": []}')["ok"]
    assert not import_zap_snapshot("https://owned.test/allowed", "not-json")["ok"]


def test_kali_tool_imports_existing_snapshot_without_starting_zap(scope, monkeypatch):
    kali = load_server("kali-tools")
    monkeypatch.setattr(kali, "run_zap_map", lambda *args, **kw: pytest.fail("live ZAP API called"))
    snapshot = {"urls": ["https://owned.test/allowed/a?q=private-value",
                         "https://owned.test/outside"], "alerts": []}
    out = json.loads(kali.zap_map_surface("https://owned.test/allowed", snapshot_json=json.dumps(snapshot)))
    assert out["ok"] and out["mode"] == "offline_snapshot" and out["discarded"] == 1
    assert out["ingested"] >= 1 and "private-value" not in json.dumps(out)
