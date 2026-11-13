"""Archived work data must not regain an exception in the repository gate."""
import pytest

from scripts.check_repo_layout import main, violations


@pytest.mark.parametrize("name", [
    "recon", "reports", "new-program-bb", "lab-new", "codex-session-new.md",
    ".tmp_new_run.md", "skills~new",
    "hepsiburada-bb", ".worker", ".tmp_runD_summary.md",
    "codex-session-01a18828-1878-7482-bd3d-c3cf899127ba.md",
    "codex-session-01a1929c-9ccf-77c0-b056-7d537ac944a2.md",
    "codex-session-01a1939e-d563-7aa1-98ee-d825dd5afb61.md",
])
def test_new_runtime_artifacts_fail_layout(tmp_path, name):
    (tmp_path / name).touch()
    assert violations(tmp_path) == [name]


def test_product_directories_and_build_output_are_allowed(tmp_path):
    for name in ["scripts", "tests", "docs", "config", "mcp-servers", "build"]:
        (tmp_path / name).mkdir()
    assert violations(tmp_path) == []


@pytest.mark.parametrize("populated", [False, True])
def test_worker_directory_is_rejected_even_with_former_pending_files(tmp_path, populated):
    worker = tmp_path / ".worker"
    worker.mkdir()
    if populated:
        (worker / "probe_keyenv.py").touch()
        (worker / "summary-close-5.md").touch()
    assert violations(tmp_path) == [".worker"]


@pytest.mark.parametrize("name", [
    "hepsiburada-bb", ".worker",
    "codex-session-01a18828-1878-7482-bd3d-c3cf899127ba.md",
])
def test_former_pending_name_does_not_allow_symlink(tmp_path, name):
    (tmp_path / name).symlink_to(tmp_path / "docs")
    assert violations(tmp_path) == [name]


def test_failure_reports_previously_exempt_engagement(tmp_path, monkeypatch, capsys):
    (tmp_path / "hepsiburada-bb").mkdir()
    monkeypatch.setattr("sys.argv", ["check_repo_layout", "--root", str(tmp_path)])
    assert main() == 1
    output = capsys.readouterr().out
    assert "hepsiburada-bb" in output
    assert "kökte çalışma verisi yok" not in output


def test_clean_repository_reports_success(tmp_path, monkeypatch, capsys):
    (tmp_path / "docs").mkdir()
    monkeypatch.setattr("sys.argv", ["check_repo_layout", "--root", str(tmp_path)])
    assert main() == 0
    assert "kökte çalışma verisi yok" in capsys.readouterr().out
