"""Output path controls do not need to launch a native client."""
from fixtures.output_root import output_root


def test_fixture_output_root_prefers_workflow(monkeypatch, tmp_path):
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path / "workflow"))
    monkeypatch.setenv("TMPDIR", str(tmp_path / "temporary"))
    assert output_root("full-agent-integration") == tmp_path / "workflow/full-agent-integration"


def test_fixture_output_root_falls_back_to_tmpdir(monkeypatch, tmp_path):
    monkeypatch.delenv("CCO_WORKDIR", raising=False)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    assert output_root("full-agent-integration") == tmp_path / "full-agent-integration"
