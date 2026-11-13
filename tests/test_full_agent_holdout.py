"""Holdout registration, fail-closed replay, and actual loopback lab controls."""
import copy
import json
from pathlib import Path
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest

import full_agent_holdout as holdout
import full_agent_launcher as launcher
import full_agent_preflight as preflight
from full_agent_broker import dump
from test_full_agent_preflight import prepared_snapshot, baseline, runtime_source, acceptance_evidence

FAMILY = "readonly-api-access-control"


def test_family_registration_cannot_be_renamed_or_reseeded_into_family_credit():
    first, second = holdout.selection(FAMILY, 123), holdout.selection(FAMILY, 456)
    assert first["family"] == second["family"] and first["lab_sha256"] == second["lab_sha256"]
    for family, seed in (("renamed-seed-family", 123), (FAMILY, True), (FAMILY, -1), (FAMILY, 2**63)):
        with pytest.raises(ValueError):
            holdout.selection(family, seed)
    metrics = {"family": FAMILY, "recall": {"numerator": 8, "denominator": 8, "value": 1.0},
               "negative_coverage": {"numerator": 8, "denominator": 8, "value": 1.0}}
    contract = preflight.native_contract({}, {}, 100)["holdout"]
    with pytest.raises(ValueError, match="repeated independent family"):
        holdout.aggregate([metrics, metrics], contract)
    summary = holdout.aggregate([metrics], contract)
    assert summary["status"] == "incomplete" and not summary["full_acceptance"]
    assert summary["positives"] == summary["negatives"] == 8


@pytest.mark.parametrize("fault", ["lab_sha256", "evaluator_sha256", "lab_version", "seed", "minimum_families"])
def test_frozen_family_contract_rejects_source_or_requirement_drift(prepared_snapshot, fault):
    directory = prepared_snapshot["manifest_path"].parent
    contract = copy.deepcopy(prepared_snapshot["contract"])
    selected = holdout.selection(FAMILY, 271828)
    contract["holdout_run"] = selected
    dump(directory / "contract.json", contract)
    manifest = json.loads((directory / "preflight.json").read_text())
    manifest["contract_sha256"] = preflight.sha256(directory / "contract.json")
    dump(directory / "preflight.json", manifest)
    prepared = launcher.prepared_run(directory)
    launcher.check_seed(prepared["contract"], 271828)
    with pytest.raises(ValueError, match="frozen independent holdout"):
        launcher.check_seed(prepared["contract"], prepared["contract"]["baseline"]["seeds"][0])
    if fault == "minimum_families":
        contract["holdout"][fault] = 1
    else:
        contract["holdout_run"][fault] = -1 if fault == "seed" else "changed"
    dump(directory / "contract.json", contract)
    manifest["contract_sha256"] = preflight.sha256(directory / "contract.json")
    dump(directory / "preflight.json", manifest)
    with pytest.raises(ValueError):
        launcher.prepared_run(directory)


def test_family_source_and_evaluator_are_excluded_from_runtime():
    for name in ("scripts/full_agent_holdout.py", "scripts/lab/readonly_api_holdout.py",
                 "tests/test_full_agent_api_holdout.py", "tests/test_full_agent_holdout.py"):
        assert not preflight.runtime_file(Path(name))


def test_scorer_does_not_credit_missing_evidence_and_counts_unsupported_claim_as_fp():
    truth = [{"case": "positive", "path": "/api/records/positive", "owner": "alice",
              "marker": "positive", "denied_identities": ["bob"], "expected": "positive"},
             {"case": "negative", "path": "/api/records/negative", "owner": "alice",
              "marker": "negative", "denied_identities": ["bob"], "expected": "negative"}]
    empty = holdout.evaluate(truth, [], [], target="http://127.0.0.1:12345/", run_id="run-current",
                             verify_artifact=lambda record: False)
    assert empty["recall"] == {"numerator": 0, "denominator": 1, "value": 0.0}
    assert empty["negative_coverage"] == {"numerator": 0, "denominator": 1, "value": 0.0}
    assert empty["false_positives"]["value"] is None and empty["false_positives"]["denominator"] == 0
    reported = holdout.evaluate(truth, [], [], target="http://127.0.0.1:12345/", run_id="run-current",
                                verify_artifact=lambda record: False, claims=[{
                                    "url": "http://127.0.0.1:12345/api/records/negative", "verdict": "CONFIRMED"}])
    assert reported["negative_coverage"] == empty["negative_coverage"]
    assert reported["false_positives"] == {"numerator": 1, "denominator": 1, "value": 1.0}
    assert reported["cases"][1]["outcome"] == "false_positive"
    assert not reported["cases"][1]["evidence"]


def test_actual_http_owner_positive_and_secure_negative_controls(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    server = holdout.start(holdout.selection(FAMILY, 987654321), private)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    base = f"http://127.0.0.1:{server.server_port}/"
    # Check an exact, ephemeral project scope before the first HTTP request.
    runtime = tmp_path / "runtime"
    (runtime / ".codex").mkdir(parents=True)
    scope, policy = launcher.lab_policy(base)
    dump(runtime / ".codex/scope.json", scope)
    dump(runtime / ".codex/program-policy.json", policy)
    assert launcher.verify_lab_scope(runtime, base)["before_traffic"]
    thread.start()

    def get(path, identity=None):
        headers = {"Authorization": "Bearer " + server.blind_state["accounts"][identity]["token"]} if identity else {}
        try:
            response = urlopen(Request(base.rstrip("/") + path, headers=headers), timeout=3)
        except HTTPError as response:
            with response:
                return response.code, json.loads(response.read())
        with response:
            return response.status, json.loads(response.read())

    try:
        assert not get("/")[1].get("records")
        for case in server.blind_state["truth"]:
            owner_status, owner = get(case["path"], case["owner"])
            attacker_status, attacker = get(case["path"], case["denied_identities"][0])
            assert owner_status == 200 and owner["id"] == case["marker"]
            assert get(case["path"])[0] == 401
            if case["expected"] == "positive":
                assert attacker_status == 200 and attacker == owner
            else:
                assert attacker_status == (200 if case["negative_behavior"] == "redact" else 403)
                assert case["marker"] not in json.dumps(attacker)
        assert len(server.blind_state["wire"]) == server.blind_state["requests"] == 49
        assert all(row["method"] == "GET" for row in server.blind_state["wire"])
        assert get("/api/records/nonexistent")[0] == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.parametrize('fault', ['false_positive', 'missing_closure', 'unverified_closure'])
def test_aggregate_cannot_pass_with_fp_or_unverified_closure(fault):
    metrics = [{'family': family, 'closure_verified': True,
                'recall': {'numerator': 8, 'denominator': 8, 'value': 1.0},
                'negative_coverage': {'numerator': 8, 'denominator': 8, 'value': 1.0},
                'false_positives': {'numerator': 0, 'denominator': 8, 'value': 0.0}}
               for family in list(holdout.FAMILIES)[:3]]
    contract = preflight.native_contract({}, {}, 100)['holdout']
    assert holdout.aggregate(metrics, contract)['status'] == 'passed'
    if fault == 'false_positive':
        metrics[0]['false_positives'] = {'numerator': 1, 'denominator': 8, 'value': 0.125}
    elif fault == 'missing_closure':
        metrics[0].pop('closure_verified')
    else:
        metrics[0]['closure_verified'] = False
    result = holdout.aggregate(metrics, contract)
    assert result['status'] == 'incomplete' and not all(result['checks'].values())
    assert not result['full_acceptance']
