import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_runtime_artifacts_are_gitignored():
    paths = [
        ".cco/validations/sample.json",
        ".cco/reports/sample.md",
        ".cco/audit.log",
        ".opencode/node_modules/example/package.json",
        "engagements/example/notes.md",
        "example-bb/reports/report.md",
    ]
    for path in paths:
        result = subprocess.run(
            ["git", "check-ignore", "-q", "--no-index", path],
            cwd=REPO_ROOT,
            text=True,
        )
        assert result.returncode == 0, path
