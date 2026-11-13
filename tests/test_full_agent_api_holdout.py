"""Real native first independent family. Only model responses are scripted."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

import pytest

import full_agent_launcher as launcher
import full_agent_holdout as holdout
from full_agent_broker import dump
from test_full_agent_integration import (
    CLOSURE_INTEGRITY, ROOT, ScriptedProvider, assert_isolated, finished,
    integration_run, kernel_support, acceptance_evidence, message_text, read_json,
    read_result_json, returned_json, returned_text, tool_call,
)

pytestmark = pytest.mark.integration

PREPARE = r'''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import brain
work = Path(sys.argv[2])
live = json.loads((work / 'access/live-result.json').read_text())
row = next(row for row in live['validations'] if row['verdict'] == 'CONFIRMED')
assert row['vuln_class'] == 'bola'
ledger = brain.ledger_mod.load_ledger(work)
for entry in ledger['hypotheses']:
    vector = entry['vector']
    args = ['hypotheses', 'mark', '--workdir', str(work), '--vector', vector,
            '--evidence', 'access/live-result.json']
    if vector == 'authz-idor':
        args += ['--status', 'confirmed', '--validation-id', row['validation_id']]
    else:
        args += ['--status', 'not_applicable', '--note',
                 'not_tested: auth:recovered: fresh synthetic sessions checked through '
                 'session_vault_check; this read-only slice parks ' + vector +
                 '; broader security coverage remains NOT TESTED']
    assert brain.main(args) == 0
print('CLOSURE_VECTORS_PREPARED')
'''

# Reuse all existing post-closure mutations with a multi-record signed chain.
# Mutate one record and retain the remainder, so verdict/signature checks do
# not accidentally become mere whole-ledger removal checks.
INTEGRITY = CLOSURE_INTEGRITY.replace(
    "record, = [json.loads(line) for line in original_attempts.splitlines()]",
    "records = [json.loads(line) for line in original_attempts.splitlines()]\nrecord = records[0]").replace(
    "attempt_path.write_text(json.dumps(changed) + '\\n')",
    "attempt_path.write_text('\\n'.join(json.dumps(item) for item in [changed, *records[1:]]) + '\\n')").replace(
    "changed['verdict'] = 'UNCONFIRMED'",
    "changed['verdict'] = 'UNCONFIRMED' if record['verdict'] != 'UNCONFIRMED' else 'CONFIRMED'")


def bindings_from(body):
    contents = "\n".join(message_text(row.get("content", "")) for row in body["messages"])
    match = re.search(r"(?m)^Synthetic session references \(host-owned\): (.+)$", contents)
    assert match
    return json.loads(match.group(1))


class APIProvider(ScriptedProvider):
    """A solver driven only by prompt references and actual native tool output.

    No access to family registry, truth, expected counts, seed or prior bytes.
    The generic validation ceiling is a budget, not an expected case count.
    """
    vector = "authz-idor"
    prepare_script = PREPARE

    def __init__(self, directory, source, scenario, api_key, previous_runs=()):
        super().__init__(directory, source, scenario, api_key, previous_runs)
        self.previous_evidence_paths.extend(str(path) for previous in previous_runs
                                            for path in (previous / "private/evaluator").glob("*") if path.is_file())

    def respond(self, body):
        launches = list((self.directory / "runs").glob("native-*/private/evaluator"))
        if launches:
            evaluator = launches[0]
            paths = [evaluator / name for name in (
                "selection.json", "truth.json", "expected-counts.json", "lab-source.py")]
            paths += [ROOT / "scripts/full_agent_holdout.py", ROOT / "scripts/lab/readonly_api_holdout.py"]
            # Only paths are supplied to the native isolation probe.
            self.previous_evidence_paths = list(dict.fromkeys([*self.previous_evidence_paths, *map(str, paths)]))
        return super().respond(body)

    def handoff_steps(self, body, base, work, completed, access):
        if access:
            if "it-handoff-read" not in completed:
                return [tool_call("it-handoff-read", "read", {"filePath": str(work / "handoff-access.json")})]
            assert read_result_json(body, "it-handoff-read")["vector"] == "access"
            bindings = bindings_from(body)
            labels = sorted(bindings)
            batches = [labels[index:index + 2] for index in range(0, len(labels), 2)]
            reports = []
            for index, batch in enumerate(batches):
                ident = f"it-access-live-{index}"
                pause_id = f"it-rate-pause-{index}"
                if index and pause_id + "-write" not in completed:
                    return [tool_call(pause_id + "-write", "write", {
                        "filePath": str(work / "rate_pause.py"),
                        "content": "import time\ntime.sleep(60)\nprint('RATE_WINDOW_ELAPSED')\n"})]
                if index and pause_id not in completed:
                    return [tool_call(pause_id, "bash", {
                        "command": "python3 " + str(work / "rate_pause.py"),
                        "description": "Respect the existing host rate window before the next bounded comparison batch",
                        "timeout": 70000})]
                if index:
                    assert "RATE_WINDOW_ELAPSED" in returned_text(body, pause_id)
                if ident not in completed:
                    return [tool_call(ident, "hunter_run_web_loop", {
                        "target": base, "live": True, "crawl": False, "blind_discovery": True,
                        "blind_max_requests": 24, "fuzz_limit": 0, "max_validations": 64,
                        "candidate_sample_limit": 0, "sleep_s": 0.2,
                        "session_bindings": json.dumps({name: bindings[name] for name in batch})})]
                reports.append(returned_json(body, ident))
            live = {"ok": all(row["ok"] for row in reports), "mode": "LIVE",
                    "run_ids": [row["run_id"] for row in reports],
                    "validations": [item for row in reports for item in row.get("validations", [])],
                    "confirmed": [item for row in reports for item in row.get("confirmed", [])],
                    "errors": [item for row in reports for item in row.get("errors", [])],
                    "identity_discovery": [row.get("identity_discovery") for row in reports],
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
                return self.summary("it-access-summary", work, base, "access", live.get("confirmed", []),
                                    ["access/live-result.json", "access/coverage.json"], "report-4")
            return []
        if "it-enum-http" not in completed:
            return [tool_call("it-enum-http", "kali-tools_curl_request", {"url": base, "method": "GET"})]
        observed = returned_json(body, "it-enum-http")
        assert observed["ok"] and observed["status"] == 200
        bindings = bindings_from(body)
        for label in bindings:
            ident = "it-session-" + label
            if ident not in completed:
                return [tool_call(ident, "validator_session_vault_check", {"target": base, "identity": label})]
            assert returned_json(body, ident)["status"] == "fresh"
        if "it-session-evidence" not in completed:
            return [tool_call("it-session-evidence", "write", {
                "filePath": str(work / "enum/session-checks.json"),
                "content": json.dumps({name: returned_json(body, "it-session-" + name) for name in bindings})})]
        if "it-enum-evidence" not in completed:
            return [tool_call("it-enum-evidence", "write", {
                "filePath": str(work / "enum/entry-response.json"), "content": json.dumps(observed)})]
        if "it-enum-summary" not in completed:
            summary = {"phase": "enum", "target": base, "status": "partial", "findings": [],
                       "evidence": [str(work / "enum/entry-response.json"), str(work / "enum/session-checks.json")],
                       "next": "access-3", "steps": [{"id": "entry", "status": "done"},
                                                        {"id": "owned-object-discovery", "status": "not_tested"}],
                       "surface": {"routes": [base], "params": [], "docs": [], "docs_probes": [], "id_formats": []}}
            return [tool_call("it-enum-summary", "write", {
                "filePath": str(work / "summaries/enum-2.json"), "content": json.dumps(summary)})]
        if "it-prepare-handoff" not in completed:
            return [tool_call("it-prepare-handoff", "kali-tools_ledger_prepare_handoff", {
                "target": base, "workdir": str(work), "summary_file": str(work / "summaries/enum-2.json"),
                "vector": "access", "own_ids_json": "[]", "session_bindings_json": json.dumps(bindings)})]
        assert returned_json(body, "it-prepare-handoff")["ok"]
        return []

    def report_steps(self, body, base, work, completed):
        if "it-report-live-read" not in completed:
            return [tool_call("it-report-live-read", "read", {
                "filePath": str(work / "access/live-result.json"), "limit": 2000})]
        live = read_result_json(body, "it-report-live-read")
        if "it-access-ledger" not in completed:
            items = [{"vector": self.vector, "endpoint": row["url"], "identity": row["identity"],
                      "verdict": row["verdict"], "artifact": "access/live-result.json", "note": row["validation_id"]}
                     for row in live.get("validations", []) if row.get("validation_id")]
            assert items
            return [tool_call("it-access-ledger", "kali-tools_ledger_attempt_add_batch", {
                "workdir": str(work), "items_json": json.dumps(items)})]
        if "it-attestations" not in completed:
            return [tool_call("it-attestations", "read", {"filePath": str(work / "hypotheses.json")})]
        if "it-session-recovery-ledger" not in completed:
            ledger = read_result_json(body, "it-attestations")
            items = [{"vector": row["vector"], "endpoint": base, "identity": "member-a",
                      "verdict": "session-recovery", "artifact": "enum/session-checks.json",
                      "note": "Actual native session_vault_check outputs are fresh for supplied synthetic identities"}
                     for row in ledger["hypotheses"] if row["vector"] != self.vector]
            return [tool_call("it-session-recovery-ledger", "kali-tools_ledger_attempt_add_batch", {
                "workdir": str(work), "items_json": json.dumps(items)})]
        calls = self.closure_script_steps(body, work, completed, "prepare", self.prepare_script)
        if calls:
            return calls
        if "it-checkpoint" not in completed:
            return [tool_call("it-checkpoint", "kali-tools_ledger_checkpoint", {"workdir": str(work), "seal": True})]
        checkpoint = returned_json(body, "it-checkpoint")
        assert checkpoint["sealed"] and checkpoint["check_exit"] == 0, checkpoint
        calls = self.closure_script_steps(body, work, completed, "integrity", INTEGRITY)
        if calls:
            return calls
        if "it-report-evidence" not in completed:
            return [tool_call("it-report-evidence", "write", {
                "filePath": str(work / "report/ledger.json"), "content": json.dumps({"checkpoint": checkpoint})})]
        if "it-report-summary" not in completed:
            return self.summary("it-report-summary", work, base, "report", [],
                                ["closure.json", "report/closure-integrity.json", "report/ledger.json"],
                                "broader security coverage remains NOT TESTED")
        return []

    def summary(self, ident, work, base, phase, findings, evidence, next_step):
        number = "3" if phase == "access" else "4"
        summary = {"phase": phase, "target": base, "status": "partial", "findings": findings,
                   "evidence": [str(work / path) for path in evidence], "next": next_step,
                   "steps": [{"id": "native-evidence", "status": "done"},
                             {"id": "broader-coverage", "status": "not_tested"}]}
        return [tool_call(ident, "write", {"filePath": str(work / f"summaries/{phase}-{number}.json"),
                                           "content": json.dumps(summary)})]


def assert_native_api_family(integration_run, record_testsuite_property, *, seed,
                             family="readonly-api-access-control", provider_class=APIProvider):
    with integration_run("handoff_closure", provider_class=provider_class,
                         holdout_family=family, holdout_seed=seed,
                         child_script=Path(sys.modules[provider_class.__module__].__file__).resolve()) as run:
        record_testsuite_property("independent_readonly_api_family", str(run["directory"]))
        manifest, private, budget, tools = finished(run, "native_finished_unverified", 0, delegations=4)
        assert_isolated(run, private)
        work = private.parent / "solver"
        assert manifest["independent_family"] == family
        assert manifest["holdout"] == "not_evaluated" and not manifest["acceptance_passed"]
        proof = read_json(work / "isolation-proof.json")
        for name in ("selection.json", "truth.json", "expected-counts.json", "lab-source.py"):
            path = private / "evaluator" / name
            assert path.stat().st_size and str(path) in proof["denied"]
        live = read_json(work / "access/live-result.json")
        assert live["ok"] and not live.get("stopped") and not live["errors"], live
        if family == "readonly-api-access-control":
            assert all(row["status"] == "ready" and not row["budget_limited"] for row in live["identity_discovery"])
        assert all(row["coverage_recorded"] for row in live["validations"])
        metrics, summary = holdout.audit_run(private.parent / "launch.json")
        assert metrics["recall"] == {"numerator": 8, "denominator": 8, "value": 1.0}
        assert metrics["negative_coverage"] == {"numerator": 8, "denominator": 8, "value": 1.0}
        assert metrics["false_positives"] == {"numerator": 0, "denominator": 8, "value": 0.0}
        assert not metrics["rejected_evidence"] and not metrics["unexpected_artifacts"]
        assert all(case["evidence"] for case in metrics["cases"])
        # Re-score actual signed HTTP evidence, then remove or tamper evidence
        # copies. No substitute signer/transport or assumed clean case is used.
        from cco_validator_core.evidence import artifact_is_current
        truth = read_json(private / "evaluator/truth.json")
        wire = read_json(private / "evaluator/wire.json")
        artifacts = [{"path": str(path), "sha256": holdout.digest(path), "record": read_json(path)}
                     for path in (private / "state/validations").glob("*.json")]
        with launcher.host_environment(private / "state", work, private.parent / "runtime"):
            def verify(record):
                expected_finding = holdout.finding_type(family)
                return artifact_is_current(record, trusted_root=str(private / "state/validations"),
                                           expected_target=record["target"], expected_finding_type=expected_finding)
            missing_path = next(case["path"] for case in truth if case["expected"] == "negative")
            limited = [item for item in artifacts if urlsplit(item["record"]["target"]).path != missing_path]
            partial = holdout.evaluate(truth, wire, limited, target=manifest["target"],
                                       run_id=live["run_ids"], verify_artifact=verify)
            assert partial["negative_coverage"] == {"numerator": 7, "denominator": 8, "value": 0.875}
            changed = json.loads(json.dumps(artifacts))
            for item in changed:
                item["record"]["verdict"] = "CONFIRMED" if item["record"]["verdict"] != "CONFIRMED" else "UNCONFIRMED"
            tampered = holdout.evaluate(truth, wire, changed, target=manifest["target"],
                                        run_id=live["run_ids"], verify_artifact=verify)
            assert tampered["recall"]["numerator"] == tampered["negative_coverage"]["numerator"] == 0
            assert len(tampered["rejected_evidence"]) == len(artifacts)
            # Current run provenance also rejects otherwise valid old records.
            stale = holdout.evaluate(truth, wire, artifacts, target=manifest["target"],
                                     run_id="run-unrelated", verify_artifact=verify)
            assert stale["recall"]["numerator"] == stale["negative_coverage"]["numerator"] == 0
            mismatched = holdout.evaluate(truth, [], artifacts, target=manifest["target"],
                                          run_id=live["run_ids"], verify_artifact=verify)
            assert mismatched["recall"]["numerator"] == mismatched["negative_coverage"]["numerator"] == 0
        dump(private / "evaluator/scoring-integrity.json", {
            "missing_negative": partial, "tampered_copies": tampered,
            "stale_run": stale, "missing_wire": mismatched})
        assert summary["status"] == "incomplete" and len(summary["families"]) == 1
        assert not summary["checks"]["minimum_families"] and not summary["checks"]["minimum_positives"]
        assert not summary["checks"]["minimum_negatives"] and not summary["full_acceptance"]
        integrity = read_json(work / "report/closure-integrity.json")
        assert integrity["original_bytes_restored"] and integrity["baseline"]["exit_code"] == 0
        assert integrity["restored"]["exit_code"] == 0
        assert len(integrity["tampered"]) == 5
        assert all(row["exit_code"] == 2 and row["restored"]["exit_code"] == 0
                   for row in integrity["tampered"].values())
        assert read_json(work / "report/ledger.json")["checkpoint"]["sealed"]
        assert budget["used"]["http"] == manifest["target_requests"] <= 300
        gates = read_json(private / "native-gates.json")
        assert [row["canonical_spec_id"] for row in gates if row["tool"] == "task" and row["allowed"]] == [
            "recon-1", "enum-2", "access-3", "report-4"]
        closure = read_json(work / "closure.json")["payload"]
        assert closure["validations"][0]["vector"] == provider_class.vector
        assert len(closure["not_tested"]) == len(read_json(work / "hypotheses.json")["hypotheses"]) - 1
        assert all("auth:recovered" in row["justification"] for row in closure["not_tested"])
        worker_request = next(row["request"] for row in run["provider"].requests
                              if row["request"]["model"] == "worker")
        session_checks = read_json(work / "enum/session-checks.json")
        assert set(session_checks) == set(bindings_from(worker_request))
        assert all(row["status"] == "fresh" for row in session_checks.values())
        # Only references, observed resources and public validator proofs may
        # cross the solver boundary. Never source, seed or evaluator labels.
        forbidden = [str(manifest["seed"]), '"expected": "positive"', '"expected": "negative"',
                     '"missing-owner-check"',
                     '"negative_behavior":', '"minimum_positives":']
        visible = [private / "native-events.jsonl", run["directory"] / "provider-transcript.json"]
        visible += [path for root in (work, private.parent / "runtime") for path in root.rglob("*") if path.is_file()]
        for path in visible:
            assert not any(value in path.read_text(errors="replace") for value in forbidden), path
        dump(run["directory"] / "independent-family-acceptance.json", {
            "metrics": str(private / "evaluator/metrics.json"), "aggregate": summary,
            "closure_verified": True, "post_closure_integrity": integrity,
            "isolation_verified": True, "attestations_backed_by_native_session_checks": True,
            "target_requests": manifest["target_requests"], "paid_provider_calls": 0,
            "full_acceptance": False, "remaining_zenmux_tokens": 42718})
        return {"directory": run["directory"], "private": private, "work": work,
                "manifest": manifest, "metrics": metrics, "summary": summary,
                "isolation": proof}


def test_native_independent_readonly_api_family(integration_run, record_testsuite_property, monkeypatch):
    import attempt_ledger
    monkeypatch.syspath_prepend(str(ROOT / "mcp-servers/mcp-validator"))
    from cco_validator_core.evidence import artifact_is_valid

    first = assert_native_api_family(integration_run, record_testsuite_property, seed=271828182845904)
    prior_paths = [path for root in (first["work"], first["private"] / "state/validations",
                                    first["private"] / "evaluator")
                   for path in root.rglob("*") if path.is_file()]
    prior_hashes = {str(path): holdout.digest(path) for path in prior_paths}
    second = assert_native_api_family(integration_run, record_testsuite_property, seed=161803398874989)
    assert set(first["manifest"]["native_session_ids"]).isdisjoint(second["manifest"]["native_session_ids"])
    for path in [first["work"] / "closure.json", first["work"] / "attempts.jsonl",
                 *list((first["private"] / "evaluator").glob("*")),
                 *list((first["private"] / "state/validations").glob("*.json"))]:
        assert path.stat().st_size and str(path) in second["isolation"]["denied"]
    assert all(holdout.digest(Path(path)) == digest for path, digest in prior_hashes.items())
    closure = read_json(first["work"] / "closure.json")
    records = attempt_ledger.read_records(first["work"] / "attempts.jsonl")
    artifact = read_json(next((first["private"] / "state/validations").glob("*.json")))
    with monkeypatch.context() as current_trust:
        current_trust.setenv("CCO_HOME", str(second["private"] / "state"))
        assert attempt_ledger.verify_signed_payload(closure)[0] is None
        assert attempt_ledger.verify_records(records, path=first["work"] / "attempts.jsonl")[1]
        assert not artifact_is_valid(artifact)
    with monkeypatch.context() as original_trust:
        original_trust.setenv("CCO_HOME", str(first["private"] / "state"))
        assert attempt_ledger.verify_signed_payload(closure)[0] is not None
        assert not attempt_ledger.verify_records(records, path=first["work"] / "attempts.jsonl")[1]
        assert artifact_is_valid(artifact)
    with pytest.raises(ValueError, match="repeated independent family"):
        holdout.aggregate([first["metrics"], second["metrics"]], first["metrics"]["contract"])
    dump(second["directory"] / "family-isolation-acceptance.json", {
        "runs": [str(row["directory"]) for row in (first, second)],
        "independent_families": 1, "counted_metrics": str(first["private"] / "evaluator/metrics.json"),
        "prior_results_unreadable": True, "prior_result_hashes": prior_hashes,
        "prior_results_unchanged": True, "fresh_sessions": True,
        "cross_key_replay_rejected": True, "original_trust_verification_passed": True,
        "reseeded_family_double_count_rejected": True, "paid_provider_calls": 0, "full_acceptance": False})


if __name__ == "__main__":
    if sys.argv[1:2] != ["--integration-child"]:
        raise SystemExit("Use pytest for this native integration")
    # This is the production launcher and independent registered lab, with
    # no substituted executor, HTTP response, signer, gate or runtime.
    raise SystemExit(launcher.main(sys.argv[2:]))
