import importlib.util
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_release_check():
    path = REPO_ROOT / "scripts" / "release_check.py"
    spec = importlib.util.spec_from_file_location("release_check_gate_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_pyproject_central_ruff_and_mypy_configuration():
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    ruff_select = set(data["tool"]["ruff"]["lint"]["select"])
    assert {"E9", "F63", "F7", "F82"}.issubset(ruff_select)
    assert {"F541", "F841", "E722", "F601", "F602", "F621", "F622"}.issubset(ruff_select)

    mypy_cfg = data["tool"]["mypy"]
    assert mypy_cfg.get("check_untyped_defs") is True
    assert mypy_cfg.get("ignore_errors") is not True
    assert not mypy_cfg.get("disable_error_code")

    checked_files = set(mypy_cfg.get("files", []))
    required_core = {
        "scripts/policy_engine.py",
        "scripts/tool_counts.py",
        "scripts/agent_cli.py",
        "scripts/llm_config.py",
        "scripts/full_agent_budget.py",
        "scripts/full_agent_provider.py",
        "scripts/full_agent_executor.py",
        "scripts/full_agent_python_broker.py",
        "scripts/full_agent_python_solver.py",
        "scripts/full_agent_preflight.py",
        "scripts/full_agent_launcher.py",
        "scripts/full_agent_tasks.py",
        "scripts/full_agent_runtime_policy.py",
        "scripts/wire_budget.py",
        "scripts/orchestration_spec.py",
        "scripts/release_check.py",
    }
    assert required_core.issubset(checked_files)
    assert len(checked_files) >= len(required_core)

    for override in mypy_cfg.get("overrides", []):
        modules = override.get("module", [])
        if isinstance(modules, str):
            modules = [modules]
        assert not any(m == "scripts" or m.startswith("scripts.") for m in modules)
        assert override.get("ignore_errors") is not True


def test_quality_gate_wires_central_ruff_and_mypy():
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    gates = list(data["tool"]["cco"]["quality_gate"])

    ruff_gates = [g for g in gates if "ruff check" in g]
    mypy_gates = [g for g in gates if "mypy" in g]
    assert ruff_gates, "quality_gate must include ruff check"
    assert mypy_gates, "quality_gate must include mypy"
    assert all("--select" not in g for g in ruff_gates)
    assert all(
        "--ignore-errors" not in g and "scripts/policy_engine.py" not in g
        for g in mypy_gates
    )


def test_ci_and_release_workflows_use_central_ruff_and_mypy():
    ci = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    steps = ci["jobs"]["tests"]["steps"]
    runs = [step.get("run", "") for step in steps if isinstance(step, dict) and step.get("run")]

    ruff_runs = [r for r in runs if "ruff check" in r]
    mypy_runs = [r for r in runs if "mypy" in r and "pip install" not in r]
    assert ruff_runs, "CI must run ruff check"
    assert mypy_runs, "CI must run mypy"
    assert all("--select" not in r for r in ruff_runs)
    assert all(
        "--ignore-errors" not in r and "scripts/policy_engine.py" not in r
        for r in mypy_runs
    )

    release = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    release_runs = [
        step.get("run", "")
        for step in release["jobs"]["build-sign-verify"]["steps"]
        if isinstance(step, dict) and step.get("run")
    ]
    assert any("scripts/release_check.py" in r for r in release_runs)


def test_release_check_propagates_ruff_and_mypy_failures(tmp_path, monkeypatch):
    mod = _load_release_check()

    bad_lint = tmp_path / "bad_lint.py"
    bad_lint.write_text("def fn() -> int:\n    unused = 1\n    return 2\n", encoding="utf-8")

    bad_type = tmp_path / "bad_type.py"
    bad_type.write_text('def fn() -> int:\n    return "wrong"\n', encoding="utf-8")

    marker = tmp_path / "should_not_run.txt"
    monkeypatch.setattr(
        mod,
        "_quality_gate",
        lambda: [
            f"{sys.executable} -m ruff check --config {REPO_ROOT / 'pyproject.toml'} {bad_lint}",
            f"{sys.executable} -c \"from pathlib import Path; Path('{marker}').write_text('ran')\"",
        ],
    )
    assert mod.main([]) != 0
    assert not marker.exists()

    monkeypatch.setattr(
        mod,
        "_quality_gate",
        lambda: [
            f"{sys.executable} -m mypy --config-file {REPO_ROOT / 'pyproject.toml'} {bad_type}",
            f"{sys.executable} -c \"from pathlib import Path; Path('{marker}').write_text('ran')\"",
        ],
    )
    assert mod.main([]) != 0
    assert not marker.exists()

    monkeypatch.setattr(mod, "_quality_gate", lambda: [])
    assert mod.main([]) != 0


def test_pytest_ini_has_no_missing_gi_config_warning_and_preserves_warnings(tmp_path):
    probe = tmp_path / "test_warn_probe.py"
    probe.write_text(
        "import warnings\n"
        "def test_ok():\n"
        "    warnings.warn('real deprecation', DeprecationWarning)\n"
        "    assert True\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(REPO_ROOT / "pytest.ini"),
            "-W",
            "default",
            str(probe),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    combined = proc.stdout + "\n" + proc.stderr
    assert proc.returncode == 0
    assert "Failed to import filter module 'gi'" not in combined
    assert "real deprecation" in combined
