import importlib.util
import os
import sys
import tomllib


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_release_check():
    path = os.path.join(REPO_ROOT, "scripts", "release_check.py")
    spec = importlib.util.spec_from_file_location("release_check_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_pyproject_has_installable_operator_entrypoints():
    with open(os.path.join(REPO_ROOT, "pyproject.toml"), "rb") as handle:
        data = tomllib.load(handle)
    scripts = data["project"]["scripts"]
    assert scripts["cco-worker"] == "scripts.campaign_worker:main"
    assert scripts["cco-worker-soak"] == "scripts.worker_soak:main"
    assert scripts["cco-governance"] == "scripts.governance_audit:main"
    assert scripts["cco-release-check"] == "scripts.release_check:main"
    assert scripts["cco-release-artifacts"] == "scripts.release_artifacts:main"
    assert scripts["cco-rag-bootstrap"] == "scripts.rag_bootstrap:main"
    setuptools = data["tool"]["setuptools"]
    assert setuptools["packages"] == ["scripts", "cco_rag_core"]
    assert setuptools["package-dir"] == {
        "cco_rag_core": "mcp-servers/mcp-rag-engine/cco_rag_core"
    }
    assert any(requirement.startswith("chromadb>=1.5") for requirement in data["project"]["dependencies"])
    rag_data = setuptools["data-files"]
    assert "share/hackagent/mcp-servers/mcp-rag-engine" in rag_data
    assert "share/hackagent/mcp-servers/mcp-rag-engine/cco_rag_core" in rag_data


def test_release_check_discovers_quality_gates():
    mod = _load_release_check()
    gates = mod._quality_gate()
    assert "python3 -m pytest tests -q" in gates
    assert any("worker_soak.py" in gate for gate in gates)
    assert any("governance_audit.py" in gate for gate in gates)
    assert any("agent_cli.py check-config" in gate for gate in gates)
    assert all("opencode" not in gate for gate in gates)
    assert mod._quality_gate() == gates
