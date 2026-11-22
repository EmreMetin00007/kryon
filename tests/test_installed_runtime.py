"""Build and smoke-test the wheel outside the source checkout without network."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from release_artifacts import _stage_release_source  # noqa: E402


def _run(args: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 90) -> str:
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, (result.stdout + result.stderr)[-3000:]
    return result.stdout


def test_installed_wheel_exposes_kryon_core_and_active_cli(tmp_path: Path) -> None:
    pytest.importorskip("build")
    stage, dist = tmp_path / "source", tmp_path / "dist"
    _stage_release_source(stage)

    env = dict(
        os.environ,
        CCO_HOME=str(tmp_path / "home"),
        PIP_DISABLE_PIP_VERSION_CHECK="1",
    )
    env.pop("PYTHONPATH", None)
    env.pop("CCO_VAULT_KEY", None)
    env["CCO_USE_KEYRING"] = "0"

    _run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(dist)],
        cwd=stage,
        env=env,
    )
    wheels = list(dist.glob("*.whl"))
    assert len(wheels) == 1

    with zipfile.ZipFile(wheels[0]) as archive:
        packaged = set(archive.namelist())

    expected_members = (
        "scripts/agentic_runner.py",
        "scripts/target_bootstrap.py",
        "kryon_core/surface/extract.py",
        "kryon_core/browser/hooks.py",
        "kryon_core/js/client_logic.py",
        "kryon_core/waf/waf_profiles.py",
        "kryon_core/validator/oob_collector.py",
        "kryon_core/vault/credential_vault.py",
    )
    for member in expected_members:
        assert member in packaged, f"missing expected wheel member: {member}"

    assert any(name.endswith("/config/llm.example.json") for name in packaged), "missing config/llm.example.json"
    assert not any("mcp-servers/" in name for name in packaged), "retired mcp-servers/ leaked into wheel"

    venv = tmp_path / "venv"
    _run([sys.executable, "-m", "venv", "--system-site-packages", str(venv)], cwd=tmp_path, env=env)
    py, bindir = venv / "bin" / "python", venv / "bin"
    _run([str(py), "-m", "pip", "install", "--no-deps", str(wheels[0])], cwd=tmp_path, env=env)

    for cli in ("cco-agent", "cco-governance", "cco-release-check", "cco-release-artifacts"):
        _run([str(bindir / cli), "--help"], cwd=tmp_path, env=env)

    llm_example = venv / "share" / "hackagent" / "config" / "llm.example.json"
    assert llm_example.is_file()
    checked = json.loads(
        _run(
            [str(bindir / "cco-agent"), "check-config", "--provider-config", str(llm_example)],
            cwd=tmp_path,
            env=env,
        )
    )
    assert checked["status"] == "valid"
    assert checked["credential_read"] is False
    assert checked["network_requests"] == 0

    gate_list = _run([str(bindir / "cco-release-check"), "--list"], cwd=tmp_path, env=env)
    assert "pytest" in gate_list
    assert "kryon_core" in gate_list

    smoke_script = tmp_path / "smoke_installed.py"
    smoke_script.write_text(
        """
import json
import os
from pathlib import Path
import sys

import kryon_core
from kryon_core.browser import hooks
from kryon_core.js.client_logic import build_client_logic_map
from kryon_core.surface import extract
from kryon_core.validator.oob_collector import verify_collector_event
from kryon_core.vault.credential_vault import CredentialVault
from kryon_core.waf import waf_profiles

import scripts
scripts_dir = str(Path(scripts.__file__).resolve().parent)
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

import scripts.agentic_runner as runner
import agentic_auth_import
import agentic_seed

vault = CredentialVault(os.environ["CCO_HOME"])
secret_ref = vault.store_secret("smoke", "synthetic-value")
assert vault.get_secret(secret_ref) == "synthetic-value"

js_map = build_client_logic_map("fetch('/api/v1/items')", parser="static")
assert js_map["endpoints"]

oob = verify_collector_event(
    {},
    "{}",
    "{}",
    str(Path(os.environ["CCO_HOME"]) / "oob-smoke.db"),
    scope_revision="scope",
    policy_hash="policy",
)
assert oob["authenticated"] is False

print(json.dumps({
    "ok": True,
    "kryon_core": bool(kryon_core),
    "runner": callable(runner.main),
    "auth_import": bool(agentic_auth_import),
    "seed": bool(agentic_seed),
    "surface": bool(extract),
    "hooks": bool(hooks),
    "waf": bool(waf_profiles),
}))
""",
        encoding="utf-8",
    )
    smoke_out = json.loads(_run([str(py), str(smoke_script)], cwd=tmp_path, env=env, timeout=90))
    assert smoke_out["ok"] is True
    assert all(smoke_out.values())
