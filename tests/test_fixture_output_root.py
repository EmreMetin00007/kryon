"""Output path controls do not need to launch a native client."""
import pytest

from fixtures import output_root as roots
from fixtures.output_root import output_root


@pytest.mark.parametrize("name", ["full-agent-integration", "full-agent-python-integration", "full-agent-python-holdout"])
def test_fixture_output_root_prefers_workflow(monkeypatch, tmp_path, name):
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path / "workflow"))
    monkeypatch.setenv("TMPDIR", str(tmp_path / "temporary"))
    assert output_root(name) == tmp_path / "workflow" / name


@pytest.mark.parametrize("name", ["full-agent-integration", "full-agent-python-integration", "full-agent-python-holdout"])
def test_fixture_output_root_falls_back_to_tmpdir(monkeypatch, tmp_path, name):
    monkeypatch.delenv("CCO_WORKDIR", raising=False)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    assert output_root(name) == tmp_path / name


def test_fixture_output_root_falls_back_to_system_temp(monkeypatch, tmp_path):
    monkeypatch.delenv("CCO_WORKDIR", raising=False)
    monkeypatch.delenv("TMPDIR", raising=False)
    monkeypatch.setattr(roots.tempfile, "gettempdir", lambda: str(tmp_path))
    assert output_root("full-agent-python-holdout") == tmp_path / "full-agent-python-holdout"


def test_fixture_output_root_ignores_empty_controls(monkeypatch, tmp_path):
    monkeypatch.setenv("CCO_WORKDIR", "")
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    assert output_root("full-agent-python-holdout") == tmp_path / "full-agent-python-holdout"
