"""Native third independent family; only model responses are scripted."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
import sys
from urllib.parse import urljoin, urlsplit

import pytest

import full_agent_holdout as holdout
import full_agent_launcher as launcher
from fixtures.holdout_references import (
    API_FAMILY,
    SQL_FAMILY,
    bind_prior_runs,
    collect_prior_evidence_paths,
    collect_prior_hashes,
    ensure_api_and_sql_reference_runs,
    load_reference_metrics,
    reference_probed_files,
)
from full_agent_broker import dump
from test_full_agent_api_holdout import APIProvider, PREPARE, assert_native_api_family, bindings_from
from test_full_agent_integration import (
    ROOT, ObservedLinks, integration_run, kernel_support, acceptance_evidence,
    read_json, read_result_json, returned_json, tool_call,
)
from test_full_agent_sqli_holdout import SQLProvider

pytestmark = pytest.mark.integration
FAMILY = "readonly-template-injection"


class SSTIProvider(APIProvider):
    vector = "injection-ssti"
    prepare_script = PREPARE.replace("'bola'", "'ssti'").replace("'authz-idor'", "'injection-ssti'")
    prior_reference_runs: tuple[Path, ...] = ()

    def __init__(self, directory, source, scenario, api_key, previous_runs=(), *, prior_reference_runs=None):
        # Only paths cross to the isolation probe, never prior result bytes.
        super().__init__(directory, source, scenario, api_key, previous_runs)
        refs = self.prior_reference_runs if prior_reference_runs is None else prior_reference_runs
        self.previous_evidence_paths = list(dict.fromkeys([
            *self.previous_evidence_paths,
            *collect_prior_evidence_paths(refs),
        ]))

    def respond(self, body):
        self.previous_evidence_paths += [str(ROOT / "scripts/lab/readonly_ssti_holdout.py")]
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
                        "description": "Wait one bounded slice of the existing host rate window before the next SSTI batch",
                        "timeout": 25000})]
            if ident not in completed:
                return [tool_call(ident, "hunter_run_web_loop", {
                    "target": target, "live": True, "crawl": False, "fuzz_limit": 4,
                    "max_validations": 16, "candidate_sample_limit": 16, "sleep_s": 0.2,
                    "validation_profile": "readonly_ssti_arithmetic", "session_bindings": json.dumps(bindings)})]
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
            return [tool_call("it-coverage-output", "write", {
                "filePath": str(work / "access/coverage.json"),
                "content": json.dumps(returned_json(body, "it-access-coverage"))})]
        if "it-access-summary" not in completed:
            return self.summary("it-access-summary", work, base, "access", live["confirmed"],
                                ["access/live-result.json", "access/coverage.json"], "report-4")
        return []


def test_native_independent_readonly_ssti_family(integration_run, record_testsuite_property, monkeypatch):
    import attempt_ledger
    monkeypatch.syspath_prepend(str(ROOT / "mcp-servers/mcp-validator"))
    from cco_validator_core.evidence import artifact_is_valid

    api_ref, sql_ref = ensure_api_and_sql_reference_runs(
        integration_run,
        record_testsuite_property,
        runner=assert_native_api_family,
        api_provider_class=APIProvider,
        sql_provider_class=SQLProvider,
    )
    prior_runs = (api_ref["run_dir"], sql_ref["run_dir"])
    prior, hashes = collect_prior_hashes(prior_runs, digest_fn=holdout.digest)
    ssti_provider = bind_prior_runs(SSTIProvider, prior_runs)
    first = assert_native_api_family(
        integration_run,
        record_testsuite_property,
        seed=271828182845904,
        family=FAMILY,
        provider_class=ssti_provider,
    )
    second = assert_native_api_family(
        integration_run,
        record_testsuite_property,
        seed=161803398874989,
        family=FAMILY,
        provider_class=ssti_provider,
    )
    assert set(first["manifest"]["native_session_ids"]).isdisjoint(second["manifest"]["native_session_ids"])
    probed_prior_paths = [path for canon in prior_runs for path in reference_probed_files(canon)]
    for run in (first, second):
        for path in probed_prior_paths:
            assert str(path) in run["isolation"]["denied"]
        for case in run["metrics"]["cases"]:
            assert case["family"] == FAMILY and case["evidence"]
        wire = read_json(run["private"] / "evaluator/wire.json")
        case_paths = {case["path"] for case in read_json(run["private"] / "evaluator/truth.json")}
        endpoint_requests = Counter(row["path"] for row in wire if row["path"] in case_paths)
        assert set(endpoint_requests) == case_paths
        assert all(0 < count <= 8 for count in endpoint_requests.values()), endpoint_requests
        dump(run["directory"] / "endpoint-request-counts.json", {
            "limit": 8, "max_requests": max(endpoint_requests.values()),
            "endpoint_requests": dict(endpoint_requests), "includes_discovery_and_validation": True})
        assert all(row["method"] == "GET" for row in wire)
        transcript = read_json(run["directory"] / "provider-transcript.json")
        shell_calls = [json.loads(call["function"]["arguments"])
                       for row in transcript for choice in row["response"].get("choices", [])
                       for call in choice.get("message", {}).get("tool_calls", [])
                       if call["function"]["name"] == "bash"]
        assert shell_calls and all(0 < call["timeout"] <= 45000 for call in shell_calls)
    for path in [first["work"] / "closure.json", first["work"] / "attempts.jsonl",
                 *list((first["private"] / "evaluator").glob("*")),
                 *list((first["private"] / "state/validations").glob("*.json"))]:
        assert str(path) in second["isolation"]["denied"]
    assert all(holdout.digest(path) == digest for path, digest in hashes.items())
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

    # Full aggregate evaluation across all 3 independent holdout families
    api_metrics, sql_metrics = load_reference_metrics(
        prior_runs,
        expected_families=(API_FAMILY, SQL_FAMILY),
    )
    ssti_metrics = first["metrics"]
    full_summary = holdout.aggregate([api_metrics, sql_metrics, ssti_metrics], first["metrics"]["contract"])
    assert full_summary["status"] == "passed"
    assert len(full_summary["families"]) == 3
    assert full_summary["positives"] == full_summary["negatives"] == 24
    assert full_summary["overall_recall"] == {"numerator": 24, "denominator": 24}
    assert full_summary["negative_coverage"] == {"numerator": 24, "denominator": 24}
    assert full_summary["false_positives"] == {"numerator": 0, "denominator": 24}
    assert all(full_summary["checks"].values())

    dump(second["directory"] / "family-isolation-acceptance.json", {
        "runs": [str(row["directory"]) for row in (first, second)],
        "counted_metrics": str(first["private"] / "evaluator/metrics.json"),
        "independent_families": 1, "repeat_earns_credit": False,
        "prior_results_unreadable": bool(prior), "prior_result_hashes": hashes,
        "prior_results_unchanged": True, "prior_ssti_results_unreadable": True,
        "cross_key_replay_rejected": True, "original_trust_verification_passed": True,
        "ssti_endpoint_request_limit": 8, "shell_timeout_max_ms": 45000,
        "paid_provider_calls": 0, "remaining_zenmux_tokens": 42718, "full_acceptance": False})
    dump(first["directory"] / "three-family-aggregate.json", full_summary)


if __name__ == "__main__":
    if sys.argv[1:2] != ["--integration-child"]:
        raise SystemExit("Use pytest for this native integration")
    raise SystemExit(launcher.main(sys.argv[2:]))
