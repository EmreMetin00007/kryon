import importlib.util
import json
import os
import sys

import pytest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_governance():
    path = os.path.join(REPO_ROOT, "scripts", "governance_audit.py")
    spec = importlib.util.spec_from_file_location("governance_audit_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_governance_audit_redacts_secret_values_and_skips_env(tmp_path):
    mod = _load_governance()
    (tmp_path / "app.py").write_text("API_KEY = 'super-secret-token-12345'\nuser='alice@example.com'\n")
    (tmp_path / ".env").write_text("PASSWORD=do-not-read-this-secret\n")

    result = mod.run_audit(tmp_path)

    assert result["summary"]["high"] == 1
    assert result["summary"]["medium"] == 1
    assert result["skipped_sensitive_files"] == [".env"]
    assert "super-secret-token" not in str(result)
    assert "alice@example.com" not in str(result)
    assert "<redacted>" in result["findings"][0]["excerpt"]


def test_governance_audit_ignores_expression_assignments_but_detects_bare_secrets(tmp_path):
    mod = _load_governance()
    (tmp_path / "app.py").write_text(
        "self.api_key = self._get_api_key()\n"
        "token = match.group(0).strip()\n"
        "PASSWORD=abcdefghijklmnop\n"
    )

    result = mod.run_audit(tmp_path)

    assert result["summary"]["high"] == 1
    assert result["findings"][0]["line"] == 3


def test_governance_audit_can_exclude_runtime_dirs(tmp_path):
    mod = _load_governance()
    runtime_dir = tmp_path / ".cco"
    runtime_dir.mkdir()
    (runtime_dir / "artifact.json").write_text('{"token":"runtime-secret-token-12345"}')

    excluded = mod.run_audit(tmp_path, include_runtime=False)
    included = mod.run_audit(tmp_path, include_runtime=True)

    assert excluded["summary"]["total"] == 0
    assert included["summary"]["high"] == 1


@pytest.mark.parametrize("value,expected", [
    ("{env:CCO_BENCHMARK_API_KEY}", 0),
    ("{env:CCO_BENCHMARK_API_KEY}suffix", 1),
    ("{env:123_INVALID_VARIABLE}", 1),
    ("{env:INVALID-VARIABLE-NAME}", 1),
    ("${env:CCO_BENCHMARK_API_KEY}", 1),
    ("literal-synthetic-secret-12345", 1),
])
def test_governance_distinguishes_exact_environment_references(tmp_path, value, expected):
    mod = _load_governance()
    (tmp_path / "config.json").write_text(json.dumps({"apiKey": value}))
    result = mod.run_audit(tmp_path)
    assert result["summary"]["high"] == expected


def test_environment_reference_cannot_hide_literal_secret_on_same_line(tmp_path):
    mod = _load_governance()
    (tmp_path / "config.json").write_text(json.dumps({
        "apiKey": "{env:CCO_BENCHMARK_API_KEY}", "token": "literal-synthetic-secret-12345"}))
    result = mod.run_audit(tmp_path)
    assert result["summary"]["high"] == 1
    assert "literal-synthetic-secret" not in str(result)


def test_governance_baseline_suppresses_known_findings(tmp_path):
    mod = _load_governance()
    (tmp_path / "app.py").write_text("API_KEY = 'super-secret-token-12345'\n")
    first = mod.run_audit(tmp_path)
    baseline = tmp_path / "baseline.json"
    mod.write_baseline(first, baseline)

    second = mod.run_audit(tmp_path, baseline_file=baseline)

    assert first["summary"]["high"] == 1
    assert second["summary"]["total"] == 0
    assert second["suppressed_findings"][0]["suppressed_by"] == "baseline"


def test_governance_allowlist_suppresses_by_path_and_rule(tmp_path):
    mod = _load_governance()
    (tmp_path / "fixtures.md").write_text("Contact: security@example.com\n")
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text(json.dumps({
        "allow": [{"path": "fixtures.md", "rule": "email_pii", "reason": "documentation fixture"}],
    }))

    result = mod.run_audit(tmp_path, allowlist_file=allowlist)

    assert result["summary"]["total"] == 0
    assert result["suppressed_findings"][0]["suppressed_by"] == "allowlist"
