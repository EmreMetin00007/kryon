"""Frozen traversal identity, actual fixture/HTTP controls and fail-closed scoring."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from urllib.parse import urlsplit

import pytest

import full_agent_holdout as holdout
import full_agent_launcher as launcher
import full_agent_preflight as preflight
from full_agent_broker import dump
from conftest import load_server
from test_full_agent_preflight import prepared_snapshot, baseline, runtime_source, acceptance_evidence
from test_full_agent_holdout import test_frozen_family_contract_rejects_source_or_requirement_drift as frozen_check

FAMILY = "readonly-path-traversal"


@pytest.fixture
def traversal_lab(tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir()
    lab = holdout.start(holdout.selection(FAMILY, 987654321), private)
    base = f"http://127.0.0.1:{lab.server_port}/"
    runtime = tmp_path / "runtime"
    (runtime / ".codex").mkdir(parents=True)
    scope, policy = launcher.lab_policy(base)
    from lab.readonly_traversal_holdout import declaration
    policy["path_traversal"] = declaration(lab.blind_state, base)
    dump(runtime / ".codex/scope.json", scope)
    dump(runtime / ".codex/program-policy.json", policy)
    assert json.loads((runtime / ".codex/scope.json").read_text()) == scope
    assert all(urlsplit(row["url"]).netloc == urlsplit(base).netloc for row in policy["path_traversal"]["files"])
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(runtime / ".codex/scope.json"))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(runtime / ".codex/program-policy.json"))
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    try:
        yield lab, base, private
    finally:
        lab.shutdown()
        lab.server_close()
        thread.join(timeout=5)
        lab.blind_state["fixtures"].cleanup()

def test_traversal_identity_and_duplicate_or_renamed_credit():
    first, repeat = holdout.selection(FAMILY, 123), holdout.selection(FAMILY, 456)
    assert first["family"] == repeat["family"] and first["lab_sha256"] == repeat["lab_sha256"]
    assert first["family"] != "readonly-api-access-control"
    for family in ("renamed-readonly-traversal", "readonly-traversal/123"):
        with pytest.raises(ValueError):
            holdout.selection(family, 123)
    metrics = {"family": FAMILY, "recall": {"numerator": 8, "denominator": 8, "value": 1.0},
               "negative_coverage": {"numerator": 8, "denominator": 8, "value": 1.0},
               "false_positives": {"numerator": 0, "denominator": 8, "value": 0.0}}
    contract = preflight.native_contract({}, {}, 100)["holdout"]
    with pytest.raises(ValueError, match="repeated"):
        holdout.aggregate([metrics, metrics], contract)
    api = {**metrics, "family": "readonly-api-access-control"}
    summary = holdout.aggregate([api, metrics], contract)
    assert summary["positives"] == summary["negatives"] == 16
    assert len(summary["families"]) == 2 and summary["status"] == "incomplete"
    assert summary["false_positives"] == {"numerator": 0, "denominator": 16}


@pytest.mark.parametrize("fault", ["lab_sha256", "evaluator_sha256", "lab_version", "seed", "minimum_families"])
def test_frozen_sql_contract(prepared_snapshot, fault, monkeypatch):
    # Reuse the same replay mutation test with the second registered identity.
    with monkeypatch.context() as family:
        family.setitem(frozen_check.__globals__, "FAMILY", FAMILY)
        frozen_check(prepared_snapshot, fault)


def test_traversal_family_excluded_from_solver():
    for path in ("scripts/full_agent_holdout.py", "scripts/lab/readonly_traversal_holdout.py",
                 "tests/test_full_agent_traversal_holdout.py", "graphify-out/graph.json"):
        assert not preflight.runtime_file(Path(path))


def test_actual_fixture_http_and_signed_five_controls(traversal_lab):
    lab, base, private = traversal_lab
    validator = load_server("validator")
    from cco_validator_core.egress import scoped_wire_gate
    from cco_validator_core.evidence import artifact_is_current, validation_context
    artifacts = []
    state = lab.blind_state
    with scoped_wire_gate(lambda method, url, headers: (
            method == "GET" and urlsplit(url).netloc == urlsplit(base).netloc, "owned loopback")):
        for case in state["truth"]:
            context = {"run_id": "run-fixture-controls", "vuln_class": "path_traversal", "method": "GET",
                       "param": "file", "carrier": "query", "identity": "anonymous", "resource_owner": "unspecified"}
            with validation_context(context):
                record = json.loads(validator.validate_path_traversal(
                    base.rstrip("/") + case["path"] + "?file=notes.txt", param="file"))
            assert record["verdict"] == ("CONFIRMED" if case["expected"] == "positive" else "UNCONFIRMED"), case
            assert len(record["request_evidence"]) == 5
            assert case["marker"] not in json.dumps(record)
            assert artifact_is_current(record, expected_target=record["target"], expected_finding_type="path_traversal")
            path = record["artifact"]["path"]
            artifacts.append({"record": record, "path": path, "sha256": holdout.digest(path)})
    def verify(record):
        return artifact_is_current(record, expected_target=record["target"], expected_finding_type="path_traversal")
    result = holdout.evaluate(state["truth"], state["wire"], artifacts, target=base,
                              run_id="run-fixture-controls", verify_artifact=verify)
    assert result["recall"]["numerator"] == result["negative_coverage"]["numerator"] == 8
    assert result["false_positives"] == {"numerator": 0, "denominator": 8, "value": 0.0}
    assert not result["rejected_evidence"]
    assert len(state["wire"]) == state["requests"] == 80
    for fault in ("reflection", "generic_error", "wrong_file", "failed_transport", "wrong_payload"):
        changed = copy.deepcopy(state["wire"])
        for row in changed:
            if fault == "reflection":
                row["response"] = row["request_path"]
                row["read_file"] = None
            elif fault == "generic_error":
                row["read_file"] = None
            elif fault == "wrong_file":
                row["read_file"] = "unrelated/synthetic.txt"
            elif fault == "failed_transport":
                row["status"] = 503
            else:
                row["request_path"] = row["path"] + "?file=unrelated.txt"
        denied = holdout.evaluate(state["truth"], changed, artifacts, target=base,
                                  run_id="run-fixture-controls", verify_artifact=verify)
        assert denied["recall"]["numerator"] == denied["negative_coverage"]["numerator"] == 0
    dump(private / "infra-metrics.json", result)


@pytest.mark.parametrize("depth", [1, 2])
def test_traversal_loop_only_signed_fixture_controls(traversal_lab, monkeypatch, depth):
    from collections import Counter
    hunter = load_server("hunter")
    from cco_hunter_core.request_context import bind_policy_gate
    from cco_validator_core.evidence import artifact_is_current
    lab, base, _ = traversal_lab
    state = lab.blind_state
    catalog = next(case["path"].rsplit("/", 1)[0] for case in state["truth"] if case["depth"] == depth)
    cases = [case for case in state["truth"] if case["path"].startswith(catalog + "/")]
    def no_light_probe(*args, **kwargs):
        pytest.fail("fixture candidates must go directly to the five-control validator")
    monkeypatch.setattr(hunter, "_live_request", no_light_probe)
    with bind_policy_gate(lambda method, url, headers: (
            method == "GET" and urlsplit(url).netloc == urlsplit(base).netloc, "owned loopback")):
        result = json.loads(hunter.run_web_loop(base.rstrip("/") + catalog, live=True, crawl=False,
            fuzz_limit=4, max_validations=4, candidate_sample_limit=4,
            validation_profile="readonly_traversal_application_files"))
    assert result["ok"] and not result["errors"]
    assert result["fuzz"]["executed_live"] == 0 and not result["exploits"]
    assert len(result["validations"]) == 4 and all(row["coverage_recorded"] for row in result["validations"])
    assert len(result["confirmed"]) == 2
    counts = Counter(row["path"] for row in state["wire"])
    assert all(counts[case["path"]] == 5 for case in cases)
    artifacts = [{"path": str(path), "sha256": holdout.digest(path), "record": json.loads(path.read_text())}
                 for path in (Path(hunter.CCO_HOME) / "validations").glob("*.json")]
    metrics = holdout.evaluate(cases, state["wire"], artifacts, target=base, run_id=result["run_id"],
        verify_artifact=lambda record: artifact_is_current(record, expected_target=record["target"],
                                                          expected_finding_type="path_traversal"))
    assert metrics["recall"]["value"] == metrics["negative_coverage"]["value"] == 1.0
    assert not metrics["rejected_evidence"] and metrics["false_positives"]["numerator"] == 0


@pytest.mark.parametrize("mode", ["normalized-join", "decoded-join", "contained", "allowlisted"])
def test_normalization_never_opens_outside_declared_fixture(traversal_lab, tmp_path, mode):
    from lab.readonly_traversal_holdout import resolve_fixture
    lab, _, _ = traversal_lab
    state = lab.blind_state
    case = next(case for case in state["truth"] if case["normalization"] == mode)
    route = state["routes"][case["path"]]
    root, public, allowed = state["fixture_root"], route["public"], route["allowed"]
    assert resolve_fixture(root, public, "notes.txt", mode, allowed) in allowed
    canary = resolve_fixture(root, public, case["traversal"], mode, allowed)
    assert bool(canary) == mode.endswith("join")
    # These are only generated synthetic paths; no real system file is read.
    outside = tmp_path / "outside-synthetic.txt"
    outside.write_text("synthetic boundary sentinel")
    link = public / "escape.txt"
    link.symlink_to(outside)
    for value in (str(outside), "../" * 8 + "outside-synthetic.txt", "escape.txt", "", "notes.txt\x00"):
        assert resolve_fixture(root, public, value, mode, {*allowed, outside}) is None
    if mode == "decoded-join":
        assert resolve_fixture(root, public, case["traversal"].replace("/", "%2f"), mode, allowed) == canary
        assert resolve_fixture(root, public, case["traversal"].replace("/", "\\"), mode, allowed) == canary


def test_fixture_identity_is_frozen():
    from lab import readonly_traversal_holdout as lab
    assert lab.FAMILY == FAMILY and lab.VERSION == "readonly-traversal/1"
    assert holdout.finding_type(FAMILY) == "path_traversal"


@pytest.mark.parametrize("rule", [None, {}, {"mode": "application_files", "files": []},
                                  {"mode": "application_files", "files": [{"path": "../synthetic.txt"}]}])
def test_traversal_profile_requires_valid_declarations_before_traffic(tmp_path, monkeypatch, rule):
    hunter = load_server("hunter")
    base = "http://127.0.0.1:1/"
    scope, policy = launcher.lab_policy(base)
    if rule is not None:
        policy["path_traversal"] = rule
    dump(tmp_path / "scope.json", scope)
    dump(tmp_path / "policy.json", policy)
    monkeypatch.setenv("CCO_SCOPE_FILE", str(tmp_path / "scope.json"))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(tmp_path / "policy.json"))
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "state"))
    def no_request(*args, **kwargs):
        pytest.fail("invalid declarations must fail before discovery")
    monkeypatch.setattr(hunter, "_loop_discover", no_request)
    result = json.loads(hunter.run_web_loop(base, live=True,
                                          validation_profile="readonly_traversal_application_files"))
    assert not result["ok"] and result["requests_authorized"] == 0


def test_standalone_hunter_imports_fixture_validator_before_discovery(traversal_lab, tmp_path):
    lab, base, _ = traversal_lab
    source = Path(__file__).resolve().parents[1]
    catalog = lab.blind_state["truth"][0]["path"].rsplit("/", 1)[0]
    code = '''import importlib.util, json, sys
from urllib.parse import urlsplit
source, target = sys.argv[1:]
sys.path.insert(0, source + '/mcp-servers/mcp-hunter')
spec = importlib.util.spec_from_file_location('standalone_hunter', source + '/mcp-servers/mcp-hunter/server.py')
hunter = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = hunter
spec.loader.exec_module(hunter)
from cco_hunter_core.request_context import bind_policy_gate
assert 'cco_validator_core.traversal' not in sys.modules
with bind_policy_gate(lambda method, url, headers: (method == 'GET' and urlsplit(url).netloc == urlsplit(target).netloc, 'owned lab')):
    result = json.loads(hunter.run_web_loop(target, live=True, crawl=False, fuzz_limit=4,
        max_validations=4, candidate_sample_limit=4, validation_profile='readonly_traversal_application_files'))
assert result['ok'] and not result['errors'], result
assert len(result['validations']) == 4
assert all(row['coverage_recorded'] for row in result['validations'])
assert len(result['confirmed']) == 2
print('STANDALONE_FIXTURE_VALIDATION_PASSED')
'''
    result = subprocess.run([sys.executable, "-c", code, str(source), base.rstrip("/") + catalog],
        cwd=tmp_path, env={**os.environ, "CCO_HOME": str(tmp_path / "child-state"),
                          "PYTHONPATH": str(source / "scripts")}, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "STANDALONE_FIXTURE_VALIDATION_PASSED" in result.stdout


def test_shared_holdout_preflight_provisioning_contract_and_cross_target_rejection(tmp_path):
    """Holdout and preflight share one private-policy contract with strict run isolation."""
    for family in (*holdout.FAMILIES, ""):
        assert holdout.private_policy_contract(family) == preflight.holdout_policy_contract(family)
    trav_contract = preflight.holdout_policy_contract(FAMILY)
    assert trav_contract["requires_private_policy"] is True
    assert trav_contract["policy_section"] == "path_traversal"
    assert trav_contract["cross_run_reuse_forbidden"] is True

    # Non-traversal family cleans up any stale private policy and does not provision one.
    home_sqli = tmp_path / "home-sqli"
    priv_sqli = tmp_path / "priv-sqli"
    home_sqli.mkdir()
    priv_sqli.mkdir()
    stale = home_sqli / "holdout-program-policy.json"
    stale.write_text("{\"path_traversal\": {\"files\": []}}", encoding="utf-8")
    _, base_policy = launcher.lab_policy("http://127.0.0.1:41001/")
    sqli_res = preflight.provision_holdout_policy(
        family="readonly-sql-injection",
        lab=None,
        base="http://127.0.0.1:41001/",
        home=home_sqli,
        private=priv_sqli,
        base_policy=base_policy,
    )
    assert sqli_res["provisioned"] is False
    assert not stale.exists()

    # Traversal family provisions run-scoped policy and rejects cross-target / stale reuse.
    priv_a = tmp_path / "priv-a"
    home_a = tmp_path / "home-a"
    priv_a.mkdir()
    home_a.mkdir()
    lab_a = holdout.start(holdout.selection(FAMILY, 111111), priv_a)
    try:
        base_a = f"http://127.0.0.1:{lab_a.server_port}/"
        _, pub_policy_a = launcher.lab_policy(base_a)
        assert "path_traversal" not in pub_policy_a
        prov = preflight.provision_holdout_policy(
            family=FAMILY,
            lab=lab_a,
            base=base_a,
            home=home_a,
            private=priv_a,
            base_policy=pub_policy_a,
        )
        policy_path = Path(prov["policy_file"])
        assert prov["provisioned"] is True and prov["host_only"] is True
        assert policy_path == home_a / "holdout-program-policy.json"
        assert holdout.verify_run_scoped_policy(policy_path, base_a) is True
        assert holdout.verify_run_scoped_policy(policy_path, "http://127.0.0.1:59999/") is False

        # Cross-target scope mismatch rejected fail-closed.
        with pytest.raises(ValueError):
            holdout.provision_private_policy(
                family=FAMILY,
                lab=lab_a,
                base="http://localhost:9999/",
                home=home_a,
                private=priv_a,
                base_policy=pub_policy_a,
            )

        # Teardown removes private policy cleanly.
        holdout.cleanup_private_policy(home_a)
        assert not policy_path.exists()
        assert holdout.verify_run_scoped_policy(policy_path, base_a) is False
    finally:
        lab_a.server_close()
        lab_a.blind_state["fixtures"].cleanup()


def test_traversal_eligibility_gating_declared_vs_missing_and_zero_leakage(tmp_path, monkeypatch):
    """Trusted host check accepts declared run policy, excludes missing/cross-target, and never leaks markers."""
    from cco_validator_core.traversal import check_traversal_policy_eligibility
    from lab.readonly_traversal_holdout import declaration

    priv = tmp_path / "priv"
    home = tmp_path / "home"
    priv.mkdir()
    home.mkdir()
    lab = holdout.start(holdout.selection(FAMILY, 222222), priv)
    try:
        base = f"http://127.0.0.1:{lab.server_port}/"
        _, pub_policy = launcher.lab_policy(base)
        scope, _ = launcher.lab_policy(base)
        decl = declaration(lab.blind_state, base)
        target_row = decl["files"][0]
        target_url = target_row["url"]
        marker = target_row["marker"]
        secret_rel = target_row["path"]
        permits = lambda url: urlsplit(url).netloc == urlsplit(base).netloc

        # Missing policy -> excluded with controlled reason_code and zero leaked paths/markers.
        res_missing = check_traversal_policy_eligibility(None, target_url, target_row["param"], "query", permits)
        assert res_missing == {"eligible": False, "reason_code": "traversal_policy_not_declared"}
        res_empty = check_traversal_policy_eligibility({}, target_url, target_row["param"], "query", permits)
        assert res_empty == {"eligible": False, "reason_code": "traversal_policy_not_declared"}

        # Cross-target / invalid policy -> traversal_policy_invalid, no URL/marker leak.
        bad_rule = copy.deepcopy(decl)
        bad_rule["files"][0]["url"] = "http://127.0.0.1:59999/files/x?file=notes.txt"
        res_bad = check_traversal_policy_eligibility(bad_rule, bad_rule["files"][0]["url"], "file", "query", permits)
        assert res_bad["eligible"] is False
        assert res_bad["reason_code"] in {"traversal_policy_invalid", "traversal_policy_not_declared"}
        assert marker not in json.dumps(res_bad) and secret_rel not in json.dumps(res_bad)

        # Declared policy -> eligible for declared file endpoint, not_declared for unrelated endpoint.
        res_ok = check_traversal_policy_eligibility(decl, target_url, target_row["param"], "query", permits)
        assert res_ok == {"eligible": True, "reason_code": ""}
        res_other = check_traversal_policy_eligibility(decl, f"{base}lookup/abc?id=1", "id", "query", permits)
        assert res_other == {"eligible": False, "reason_code": "traversal_policy_not_declared"}

        # Verify provisioned private policy never enters public scope/program-policy.
        prov = holdout.provision_private_policy(
            family=FAMILY, lab=lab, base=base, home=home, private=priv, base_policy=pub_policy
        )
        assert Path(prov["policy_file"]).is_file()
        assert "path_traversal" not in pub_policy
        assert marker not in json.dumps(scope) and secret_rel not in json.dumps(pub_policy)
    finally:
        lab.server_close()
        lab.blind_state["fixtures"].cleanup()


def test_traversal_solver_discovers_only_via_root_crawl_without_leaking_declaration(tmp_path):
    """Lab root page exposes links solely through HTTP crawl from '/'; declarations stay host-private."""
    import urllib.request

    priv = tmp_path / "priv"
    priv.mkdir()
    lab = holdout.start(holdout.selection(FAMILY, 333333), priv)
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{lab.server_port}/"
        root_html = urllib.request.urlopen(base, timeout=5).read().decode("utf-8")
        assert "/files/" in root_html
        # Root HTML must not expose secret filesystem paths or sentinel markers.
        for item in lab.blind_state["truth"]:
            assert item["marker"] not in root_html
            assert item["traversal"] not in root_html
            assert Path(item["fixture_file"]).name not in root_html
    finally:
        lab.shutdown()
        lab.server_close()
        thread.join(timeout=5)
        lab.blind_state["fixtures"].cleanup()
