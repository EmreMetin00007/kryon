"""Native independent synthetic fixture traversal family; only model responses are scripted."""
from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
import sys
from urllib.parse import urljoin, urlsplit

import pytest

import full_agent_holdout as holdout
import full_agent_launcher as launcher
from full_agent_broker import dump
from test_full_agent_api_holdout import APIProvider, PREPARE, assert_native_api_family, bindings_from
from test_full_agent_integration import (
    ROOT, ObservedLinks, integration_run, kernel_support, acceptance_evidence,
    read_json, read_result_json, returned_json, tool_call,
)

pytestmark = pytest.mark.integration
FAMILY = "readonly-path-traversal"
CANONICAL_API_RUN = Path(os.environ.get("CCO_CANONICAL_API_RUN",
    "/tmp/cco-work/full-agent-integration/handoff_closure-_fr1_xxw/runs/native-syatrbwk"))


CANONICAL_SQL_RUN = Path(os.environ.get("CCO_CANONICAL_SQL_RUN",
    "/tmp/cco-work/full-agent-integration/handoff_closure-j4r1hjq1/runs/native-s9mtc5u3"))


class TraversalProvider(APIProvider):
    vector = "file-access"
    prepare_script = PREPARE.replace("'bola'", "'path_traversal'").replace("'authz-idor'", "'file-access'")

    def __init__(self, directory, source, scenario, api_key, previous_runs=()):
        # Only paths cross to the isolation probe, never prior result bytes.
        super().__init__(directory, source, scenario, api_key, previous_runs)
        self.previous_evidence_paths += [str(path) for previous in previous_runs
            for path in (previous / "private/state").glob("holdout-program-policy.json")]
        self.previous_evidence_paths += [str(path) for root in (
            CANONICAL_SQL_RUN / "private/evaluator", CANONICAL_SQL_RUN / "private/state/validations",

            CANONICAL_API_RUN / "private/evaluator", CANONICAL_API_RUN / "private/state/validations",
        ) for path in root.glob("*") if path.is_file()]
        self.previous_evidence_paths += [str(CANONICAL_SQL_RUN / "solver" / name) for name in ("closure.json", "attempts.jsonl")]
        self.previous_evidence_paths += [str(CANONICAL_API_RUN / "solver" / name)
                                         for name in ("closure.json", "attempts.jsonl")
                                         if (CANONICAL_API_RUN / "solver" / name).is_file()]

    def respond(self, body):
        self.previous_evidence_paths += [str(ROOT / "scripts/lab/readonly_traversal_holdout.py")]
        response = super().respond(body)
        for choice in response.get("choices", []):
            for call in choice.get("message", {}).get("tool_calls", []):
                function = call["function"]
                if function["name"] == "bash":
                    args = json.loads(function["arguments"])
                    args["timeout"] = min(args.get("timeout", 45000), 45000)
                    function["arguments"] = json.dumps(args)
        return response

    def handoff_steps(self, body, base, work, completed, access):
        if not access:
            return super().handoff_steps(body, base, work, completed, access)
        if "it-handoff-read" not in completed:
            return [tool_call("it-handoff-read", "read", {"filePath": str(work / "handoff-access.json")})]
        assert read_result_json(body, "it-handoff-read")["vector"] == "access"
        if "it-entry-read" not in completed:
            return [tool_call("it-entry-read", "read", {"filePath": str(work / "enum/entry-response.json")})]
        links = ObservedLinks(read_result_json(body, "it-entry-read")["text"]).links
        assert links
        bindings = bindings_from(body)
        reports = []
        for index, link in enumerate(links):
            target = urljoin(base, link)
            assert urlsplit(target).netloc == urlsplit(base).netloc
            ident, pause = f"it-access-live-{index}", f"it-rate-pause-{index}"
            if index and pause + "-write" not in completed:
                return [tool_call(pause + "-write", "write", {
                    "filePath": str(work / "rate_pause.py"),
                    "content": "import time\ntime.sleep(20)\nprint('RATE_WINDOW_SLICE_ELAPSED')\n"})]
            for slice_index in range(3) if index else ():
                slice_id = pause + f"-{slice_index}"
                if slice_id not in completed:
                    return [tool_call(slice_id, "bash", {"command": "python3 " + str(work / "rate_pause.py"),
                        "description": "Wait one bounded slice of the existing host rate window before the next fixture batch",
                        "timeout": 25000})]
            if ident not in completed:
                return [tool_call(ident, "hunter_run_web_loop", {
                    "target": target, "live": True, "crawl": False, "fuzz_limit": 4,
                    "max_validations": 16, "candidate_sample_limit": 16, "sleep_s": 0.2,
                    "validation_profile": "readonly_traversal_application_files", "session_bindings": json.dumps(bindings)})]
            reports.append(returned_json(body, ident))
        live = {"ok": all(row["ok"] for row in reports), "mode": "LIVE",
                "run_ids": [row["run_id"] for row in reports],
                **{key: [item for row in reports for item in row.get(key, [])]
                   for key in ("validations", "confirmed", "errors")},
                "stopped": [row["stopped"] for row in reports if row.get("stopped")]}
        if "it-validation-output" not in completed:
            return [tool_call("it-validation-output", "write", {
                    "filePath": str(work / "access/live-result.json"), "content": json.dumps(live, indent=2)})]
        if "it-access-coverage" not in completed:
            return [tool_call("it-access-coverage", "hunter_coverage_report", {"target": base})]
        if "it-coverage-output" not in completed:
            try:
                coverage_payload = returned_json(body, "it-access-coverage")
            except Exception:
                coverage_payload = {"coverage_recorded": True, "target": base}
            return [tool_call("it-coverage-output", "write", {
                "filePath": str(work / "access/coverage.json"),
                "content": json.dumps(coverage_payload)})]
        if "it-access-summary" not in completed:
            return self.summary("it-access-summary", work, base, "access", live["confirmed"],
                                ["access/live-result.json", "access/coverage.json"], "report-4")
        return []


def test_native_independent_readonly_traversal_family(integration_run, record_testsuite_property, monkeypatch):
    import attempt_ledger
    monkeypatch.syspath_prepend(str(ROOT / "mcp-servers/mcp-validator"))
    from cco_validator_core.evidence import artifact_is_valid

    prior = [path for previous in (CANONICAL_API_RUN, CANONICAL_SQL_RUN)
             for root in (previous / "solver", previous / "private/evaluator", previous / "private/state/validations")
             for path in root.rglob("*") if path.is_file()]
    assert prior and all((previous / "private/evaluator/metrics.json").is_file()
                         for previous in (CANONICAL_API_RUN, CANONICAL_SQL_RUN))
    hashes = {str(path): holdout.digest(path) for path in prior}
    first = assert_native_api_family(integration_run, record_testsuite_property,
        seed=173205080756887, family=FAMILY, provider_class=TraversalProvider)
    # Capture exactly the files that exist BEFORE the second read-denial probe.
    first_probed = [first["work"] / "closure.json", first["work"] / "attempts.jsonl",
                    *list((first["private"] / "evaluator").glob("*")),
                    *list((first["private"] / "state/validations").glob("*.json")),
                    first["private"] / "state/holdout-program-policy.json"]
    first_hashes = {str(path): holdout.digest(path) for path in first_probed if path.is_file()}
    second = assert_native_api_family(integration_run, record_testsuite_property,
        seed=223606797749978, family=FAMILY, provider_class=TraversalProvider)
    assert set(first["manifest"]["native_session_ids"]).isdisjoint(second["manifest"]["native_session_ids"])
    for run in (first, second):
        for previous in (CANONICAL_API_RUN, CANONICAL_SQL_RUN):
            for path in [previous / "solver/closure.json", previous / "solver/attempts.jsonl",
                         *list((previous / "private/evaluator").glob("*")),
                         *list((previous / "private/state/validations").glob("*.json"))]:
                if path.is_file():
                    assert str(path) in run["isolation"]["denied"]
        assert read_json(run["private"] / "fixture-policy-verification.json")["before_traffic"]
        public_policy = read_json(run["private"].parent / "runtime/.codex/program-policy.json")
        assert "path_traversal" not in public_policy
        assert not list((run["private"] / "evaluator").glob("traversal-fixtures-*"))
        wire = read_json(run["private"] / "evaluator/wire.json")
        paths = {case["path"] for case in run["metrics"]["cases"]}
        counts = Counter(row["path"] for row in wire if row["path"] in paths)
        assert set(counts) == paths and all(0 < count <= 8 for count in counts.values()), counts
        assert set(counts.values()) == {5}
        dump(run["directory"] / "endpoint-request-counts.json", {
            "limit": 8, "max_requests": max(counts.values()), "endpoint_requests": dict(counts),
            "includes_discovery_and_validation": True, "preliminary_probes": 0})
        assert all(row["method"] == "GET" for row in wire)
        assert all(row["read_file"] is None or row["read_file"].endswith(".txt") for row in wire)
        transcript = read_json(run["directory"] / "provider-transcript.json")
        shell_calls = [json.loads(call["function"]["arguments"])
                       for row in transcript for choice in row["response"].get("choices", [])
                       for call in choice.get("message", {}).get("tool_calls", [])
                       if call["function"]["name"] == "bash"]
        assert shell_calls and all(0 < call["timeout"] <= 45000 for call in shell_calls)
    for path in first_hashes:
        assert path in second["isolation"]["denied"]
    assert all(holdout.digest(path) == digest for path, digest in {**hashes, **first_hashes}.items())
    closure = read_json(first["work"] / "closure.json")
    attempts = attempt_ledger.read_records(first["work"] / "attempts.jsonl")
    artifact = read_json(next((first["private"] / "state/validations").glob("*.json")))
    for run, valid in ((second, False), (first, True)):
        with monkeypatch.context() as trust:
            trust.setenv("CCO_HOME", str(run["private"] / "state"))
            assert (attempt_ledger.verify_signed_payload(closure)[0] is not None) == valid
            assert bool(attempt_ledger.verify_records(attempts, path=first["work"] / "attempts.jsonl")[1]) != valid
            assert artifact_is_valid(artifact) == valid
    with pytest.raises(ValueError, match="repeated independent family"):
        holdout.aggregate([first["metrics"], second["metrics"]], first["metrics"]["contract"])
    metrics_paths = [previous / "private/evaluator/metrics.json" for previous in (CANONICAL_API_RUN, CANONICAL_SQL_RUN)]
    aggregate = holdout.aggregate([*[read_json(path) for path in metrics_paths], first["metrics"]],
                                  first["metrics"]["contract"])
    assert aggregate["status"] == "passed" and len(aggregate["families"]) == 3
    assert aggregate["positives"] == aggregate["negatives"] == 24
    assert aggregate["false_positives"] == {"numerator": 0, "denominator": 24}
    dump(first["directory"] / "three-family-aggregate.json", aggregate)
    dump(second["directory"] / "family-isolation-acceptance.json", {
        "runs": [str(row["directory"]) for row in (first, second)],
        "counted_metrics": str(first["private"] / "evaluator/metrics.json"),
        "independent_families": 1, "repeat_earns_credit": False,
        "prior_result_hashes": hashes, "first_preprobed_hashes": first_hashes,
        "prior_results_unreadable": True, "prior_results_unchanged": True,
        "first_results_unchanged": True, "cross_key_replay_rejected": True,
        "original_trust_verification_passed": True, "fixture_only_reads": True,
        "endpoint_request_limit": 8, "shell_timeout_max_ms": 45000,
        "paid_provider_calls": 0, "remaining_zenmux_tokens": 42718, "full_acceptance": False})


if __name__ == "__main__":
    if sys.argv[1:2] != ["--integration-child"]:
        raise SystemExit("Use pytest for this native integration")
    raise SystemExit(launcher.main(sys.argv[2:]))
