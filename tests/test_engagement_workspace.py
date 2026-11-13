"""Different engagements never reuse the same state or work directories."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from engagement_workspace import engagement_environment, mcp_config_overlay  # noqa: E402


def test_distinct_engagements_and_scope_paths_produce_distinct_namespaces(tmp_path):
    scope1, scope2 = tmp_path / "scope1.json", tmp_path / "scope2.json"
    scope1.write_text("{}")
    scope2.write_text("{}")
    common = (str(tmp_path / "state"), str(tmp_path / "work"))
    a = engagement_environment("one", str(scope1), *common)
    b = engagement_environment("two", str(scope1), *common)
    c = engagement_environment("one", str(scope2), *common)
    assert len({a["CCO_HOME"], b["CCO_HOME"], c["CCO_HOME"]}) == 3
    assert len({a["CCO_WORKDIR"], b["CCO_WORKDIR"], c["CCO_WORKDIR"]}) == 3
    assert engagement_environment("one", str(scope1), *common) == a
    assert not (tmp_path / "state").exists()


def test_launcher_creates_private_dirs_and_removes_foreign_policy(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text("{}")
    env = os.environ.copy()
    env["CCO_PROGRAM_POLICY_FILE"] = "/foreign/program/policy"
    code = ("import json,os,pathlib; "
            "pathlib.Path(os.environ['CCO_HOME'],'sentinel').write_text('local'); "
            "print(json.dumps({k:os.environ.get(k) for k in "
            "['CCO_HOME','CCO_WORKDIR','CCO_ENGAGEMENT_ID','CCO_PROGRAM_POLICY_FILE']}))")
    cmd = [sys.executable, str(ROOT / "scripts" / "engagement_workspace.py"), "--id", "one",
           "--scope", str(scope), "--home-root", str(tmp_path / "state"),
           "--work-root", str(tmp_path / "work"), "--", sys.executable, "-c", code]
    result = subprocess.run(cmd, text=True, capture_output=True, env=env, timeout=20, check=True)
    child = json.loads(result.stdout)
    assert child["CCO_ENGAGEMENT_ID"] == "one" and child["CCO_PROGRAM_POLICY_FILE"] is None
    assert Path(child["CCO_HOME"], "sentinel").read_text() == "local"
    assert Path(child["CCO_HOME"]).stat().st_mode & 0o077 == 0
    assert Path(child["CCO_WORKDIR"]).stat().st_mode & 0o077 == 0


def test_overlapping_roots_and_missing_files_are_rejected(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text("{}")
    with pytest.raises(ValueError, match="overlap"):
        engagement_environment("one", str(scope), str(tmp_path), str(tmp_path / "nested"))
    with pytest.raises(ValueError, match="scope file"):
        engagement_environment("one", str(tmp_path / "missing"), str(tmp_path / "state"), str(tmp_path / "work"))


def test_mcp_server_environment_cannot_override_isolation(tmp_path):
    scope, project = tmp_path / "scope.json", tmp_path / "opencode.json"
    scope.write_text("{}")
    project.write_text(json.dumps({"mcp": {
        "browser": {"type": "local", "command": ["python3", "server.py"], "enabled": True,
                    "environment": {"CCO_HOME": ".cco", "OTHER": "kept"}},
        "remote": {"type": "remote", "url": "https://example.test/mcp", "enabled": False}}}))
    isolated = engagement_environment("one", str(scope), str(tmp_path / "state"), str(tmp_path / "work"))
    original = json.dumps({"mcp": {"browser": {"environment": {"CCO_HOME": "/foreign", "EXTRA": "kept"}}}})
    result = json.loads(mcp_config_overlay(project, isolated, original))
    server = result["mcp"]["browser"]
    assert server["command"] == ["python3", "server.py"] and server["enabled"] is True
    assert server["environment"]["CCO_HOME"] == isolated["CCO_HOME"]
    assert server["environment"]["CCO_WORKDIR"] == isolated["CCO_WORKDIR"]
    assert server["environment"]["CCO_SCOPE_FILE"] == isolated["CCO_SCOPE_FILE"]
    assert server["environment"]["CCO_ENGAGEMENT_ID"] == "one"
    assert server["environment"]["CCO_PROGRAM_POLICY_FILE"] == ""
    assert server["environment"]["OTHER"] == server["environment"]["EXTRA"] == "kept"
    assert "environment" not in result["mcp"]["remote"]


def test_real_project_mcp_servers_receive_isolated_environment(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text("{}")
    isolated = engagement_environment("one", str(scope), str(tmp_path / "state"), str(tmp_path / "work"))
    result = json.loads(mcp_config_overlay(ROOT / "config/mcp-servers.json", isolated))
    locals_ = [server for server in result["mcp"].values() if server.get("type") == "local"]
    assert len(locals_) == 16
    assert all(server["environment"]["CCO_HOME"] == isolated["CCO_HOME"] and
               server["environment"]["CCO_WORKDIR"] == isolated["CCO_WORKDIR"] and
               server["environment"]["CCO_SCOPE_FILE"] == isolated["CCO_SCOPE_FILE"]
               for server in locals_)
