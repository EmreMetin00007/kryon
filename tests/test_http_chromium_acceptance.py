"""Offline result-gate tests; these do not count as real browser acceptance."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import http_chromium_acceptance as acceptance


@pytest.fixture
def evidence(tmp_path):
    junit = tmp_path / "junit.xml"
    junit.write_text('<testsuites><testsuite tests="37" errors="0" failures="0" skipped="0"/></testsuites>')
    directory = tmp_path / "tests"
    first = None
    for seed in acceptance.SEEDS:
        path = directory / f"test_real_chromium_surface_to_{seed}"
        path.mkdir(parents=True)
        row = {"seed": seed, "mode": "real_http_chromium", "requests": 3,
               "preparation_requests": 1, "browser_requests": 1, "discovery_requests": 0, "campaign_requests": 1,
               "score": {"proven": 6, "positives": 8, "negatives_clean": 8,
                         "negatives_evaluated": 8, "fp_rate": 0, "negative_coverage": 1}}
        (path / "automatic-campaign-controls.json").write_text(json.dumps(row))
        (path / "received-wire.json").write_text(json.dumps({"mode": row["mode"], "seed": seed,
            "base": "http://127.0.0.1:18999/", "received_requests": 3,
            "requests": [{"method": "GET", "program_header_present": True,
                          "url": "http://127.0.0.1:18999/"}] * 3}))
        (path / "chromium-discovery.json").write_text(json.dumps({
            "fallback": False, "requests": 1, "parameterized_links": 4, "ingest": {"inserted": 4}}))
        first = first or path
    return junit, directory, first


def test_complete_seed_reports_and_pytest_current_alias_are_counted_once(evidence):
    junit, directory, first = evidence
    (directory / "test_real_chromium_surface_to_current").symlink_to(first, target_is_directory=True)
    result = acceptance.assess_results(junit, directory)
    assert [row["seed"] for row in result["runs"]] == acceptance.SEEDS


@pytest.mark.parametrize("counts", [
    {"tests": 37, "skipped": 1}, {"tests": 37, "errors": 1},
    {"tests": 37, "failures": 1}, {"tests": 36},
])
def test_skip_failure_or_incomplete_suite_cannot_pass(evidence, counts):
    junit, directory, _ = evidence
    attributes = " ".join(f'{key}="{value}"' for key, value in counts.items())
    junit.write_text(f"<testsuites><testsuite {attributes}/></testsuites>")
    with pytest.raises(ValueError, match="incomplete or failing"):
        acceptance.assess_results(junit, directory)


@pytest.mark.parametrize("artifact,change", [
    ("automatic-campaign-controls.json", {"mode": "in_memory"}),
    ("automatic-campaign-controls.json", {"browser_requests": 0}),
    ("automatic-campaign-controls.json", {"requests": 301}),
    ("automatic-campaign-controls.json", {"score": {"proven": 6, "positives": 8, "negatives_clean": 8,
                                                   "negatives_evaluated": 8, "fp_rate": 1, "negative_coverage": 1}}),
    ("received-wire.json", {"received_requests": 2}),
    ("received-wire.json", {"base": "https://external.test/"}),
    ("chromium-discovery.json", {"fallback": True}),
    ("chromium-discovery.json", {"ingest": {"error": "not ingested"}}),
])
def test_mock_mode_bad_accounting_or_missing_browser_proof_cannot_pass(evidence, artifact, change):
    junit, directory, first = evidence
    path = first / artifact
    row = json.loads(path.read_text())
    path.write_text(json.dumps({**row, **change}))
    with pytest.raises(ValueError):
        acceptance.assess_results(junit, directory)


def test_missing_seed_artifact_cannot_pass(evidence):
    junit, directory, first = evidence
    (first / "automatic-campaign-controls.json").unlink()
    with pytest.raises(ValueError, match="five distinct"):
        acceptance.assess_results(junit, directory)


def test_unavailable_environment_records_failure_without_starting_pytest(tmp_path, monkeypatch):
    monkeypatch.setattr(acceptance, "preflight", lambda: [
        {"name": "loopback_socket", "ok": False, "error": "PermissionError", "errno": 1}])
    monkeypatch.setattr(acceptance.subprocess, "run", lambda *a, **kw: pytest.fail("must not run pytest"))
    assert acceptance.main(["--output-dir", str(tmp_path)]) == 2
    manifests = list(tmp_path.glob("run-*/acceptance.json"))
    assert len(manifests) == 1
    result = json.loads(manifests[0].read_text())
    assert result["status"] == "environment_unavailable" and "runs" not in result
