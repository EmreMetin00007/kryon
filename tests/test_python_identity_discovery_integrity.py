"""Production provenance contracts, using owned loopback validator controls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from conftest import load_server
from evidence_trust import attest, canonical_bytes
from full_agent_budget import BudgetError
from full_agent_python_solver import PythonSolver
import python_identity_discovery as discovery
from test_full_agent_python_solver import python_broker, terminal
from test_python_candidate_runtime import FROZEN, observe, replay_lab


@pytest.fixture
def provenance(replay_lab, monkeypatch):
    load_server("hunter")
    broker, target, wire = replay_lab
    for key in (discovery.CONTEXT_ENV, discovery.STATE_ENV):
        monkeypatch.delenv(key, raising=False)
    broker.tasks.bindings = {name: {"target": target, "role": "member", "test_data_only": True,
                                   "owned_objects_private": True}
                             for name in ("first", "second", "third", "fourth")}
    solver = PythonSolver(broker, model="model")
    upstream, spec = broker.tasks.specs[1:3]
    observe(broker, solver, upstream, FROZEN["identity_pages"])
    broker.tasks.active_spec = spec
    row = solver.plan_candidates(spec)[0]
    names = list(json.loads(row["arguments"]["session_bindings"]))

    def actors(selected, observed_at=None):
        return {name: {"headers": {"Cookie": "identity=" + name}, "role": "member",
                       "test_data_only": True, "owned_objects_private": True,
                       "objects": [{"url": target + "objects/" + name, "marker": "owned-" + name}],
                       "resources": [{"url": target + "objects/" + name, "owner": name}],
                       "identity_facts": [{"field": "principal", "value": name,
                                           "source": "response_metadata", "confidence": "observed"}],
                       **({"_discovery_observed_at": observed_at} if observed_at is not None else {})}
                for name in selected}

    def arguments(selected):
        return {**row["arguments"], "session_bindings": json.dumps({
            name: broker.tasks.bindings[name] for name in selected})}

    def execute(selected, observed_at=None):
        original = type(broker.executor).__call__

        def with_state(self, task):
            result = original(self, task)
            result["result"]["output"]["identity_discovery_state"] = discovery.capture_state(
                actors(selected, observed_at))
            return result

        with monkeypatch.context() as patch:
            patch.setattr(type(broker.executor), "__call__", with_state)
            broker.invoke(row["tool"], arguments(selected))

    execute(names)
    overlap = [names[0], next(name for name in broker.tasks.bindings if name not in names)]
    path = discovery.prepare_discovery(broker, spec, arguments(overlap))
    payload = json.loads(path.read_bytes())["payload"]
    assert set(payload["states"]) == {names[0]}
    assert payload["sources"][0]["bindings"] == sorted(names)
    return SimpleNamespace(broker=broker, solver=solver, spec=spec, target=target, wire=wire, names=names,
                           overlap=overlap, path=path, payload=payload,
                           actors=actors, arguments=arguments, execute=execute)


def resign(case, payload):
    case.path.write_bytes(canonical_bytes(attest(payload, discovery.PURPOSE)))


def reference(path, value):
    raw = canonical_bytes(value)
    path.write_bytes(raw)
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


@pytest.mark.parametrize("change", [
    "binding_superset", "control_subset", "objects", "resources", "facts", "age",
    "session", "role", "private", "unrelated_source", "task_id", "task_tools", "invocation_arguments",
])
def test_signed_envelope_requires_exact_source_and_expected_task(provenance, tmp_path, change):
    case = provenance
    payload = copy.deepcopy(case.payload)
    source = payload["sources"][0]
    state = payload["states"][case.names[0]]
    if change == "binding_superset":
        source["bindings"].append(case.overlap[1])
        payload["states"].update(discovery.capture_state(case.actors([case.overlap[1]])))
    elif change == "control_subset":
        source["validation_ids"] = source["validation_ids"][:1]
    elif change in {"objects", "resources"}:
        state[change][0]["url"] += "-not-observed"
    elif change == "facts":
        state["identity_facts"][0]["value"] = case.overlap[1]
    elif change == "age":
        state["observed_at"] = 1.0
    elif change == "session":
        state["request_binding"] = discovery.capture_state(case.actors([case.overlap[1]]))[case.overlap[1]]["request_binding"]
    elif change == "role":
        state["role"] = "admin"
    elif change == "private":
        state["owned_objects_private"] = False
    elif change == "unrelated_source":
        source["reference"] = reference(tmp_path / "unrelated.json", {
            "identity_discovery_state": {}, "validation_queue": [], "validations": []})
    elif change == "task_id":
        payload["task_spec"]["id"] += "-foreign"
    elif change == "task_tools":
        payload["task_spec"]["tools"] = []
    else:
        payload["arguments"]["max_validations"] += 1
    resign(case, payload)
    before = len(case.wire)
    with pytest.raises(ValueError):
        discovery.load_discovery(case.target, case.actors(case.overlap), 24)
    assert len(case.wire) == before


@pytest.mark.parametrize("change", ["task", "origin", "cost", "source_pair", "queue_subset",
                                        "validation_duplicate", "validation_target", "validation_actor"])
def test_rehashed_receipt_cannot_replace_original_task_pair_or_queue(provenance, tmp_path, change):
    case = provenance
    payload = copy.deepcopy(case.payload)
    source = payload["sources"][0]
    receipt = json.loads(Path(source["execution_reference"]["path"]).read_bytes())
    report = json.loads(Path(source["reference"]["path"]).read_bytes())
    if change == "task":
        receipt["task_spec_id"] += "-foreign"
    elif change == "origin":
        receipt["origin"] = "model"
    elif change == "cost":
        receipt["execution"].pop("actual_request_cost")
    elif change == "source_pair":
        bindings = json.loads(receipt["arguments"]["session_bindings"])
        bindings[case.overlap[1]] = case.broker.tasks.bindings[case.overlap[1]]
        receipt["arguments"]["session_bindings"] = json.dumps(bindings)
        source["bindings"] = sorted(bindings)
    elif change == "queue_subset":
        report["validation_queue"] = report["validation_queue"][:1]
        report["validations"] = report["validations"][:1]
        source["validation_ids"] = [report["validations"][0]["validation_id"]]
    elif change == "validation_duplicate":
        report["validations"].append(copy.deepcopy(report["validations"][0]))
    elif change == "validation_target":
        for key in ("validation_queue", "validations"):
            report[key][0]["url"] += "-unexecuted"
    else:
        for key in ("validation_queue", "validations"):
            report[key][0]["identity"], report[key][0]["resource_owner"] = (
                report[key][0]["resource_owner"], report[key][0]["identity"])
    receipt["execution"]["result"]["output"] = report
    source["reference"] = reference(tmp_path / "source.json", report)
    source["execution_reference"] = reference(tmp_path / "receipt.json", receipt)
    resign(case, payload)
    before = len(case.wire)
    with pytest.raises(ValueError):
        discovery.load_discovery(case.target, case.actors(case.overlap), 24)
    assert len(case.wire) == before


def test_exact_expired_observation_is_consumed_without_refreshing_age(provenance):
    case = provenance
    case.execute(case.names, observed_at=time.time() - discovery.TTL_SECONDS - 1)
    case.path = discovery.prepare_discovery(case.broker, case.spec, case.arguments(case.overlap))
    payload = json.loads(case.path.read_bytes())["payload"]
    original_at = payload["states"][case.names[0]]["observed_at"]
    assert original_at < payload["prepared_at"] - discovery.TTL_SECONDS
    before = len(case.wire)
    assert discovery.load_discovery(case.target, case.actors(case.overlap), 24) == {}
    assert not case.path.exists() and len(case.wire) == before


@pytest.mark.parametrize("age", [True, "future"])
def test_exact_source_still_requires_finite_nonfuture_observation_time(provenance, age):
    case = provenance
    case.execute(case.names, observed_at=time.time() + 60 if age == "future" else age)
    path = discovery.prepare_discovery(case.broker, case.spec, case.arguments(case.overlap))
    before = len(case.wire)
    with pytest.raises(ValueError, match="observation timestamp invalid"):
        discovery.load_discovery(case.target, case.actors(case.overlap), 24)
    assert path.exists() and len(case.wire) == before


@pytest.mark.parametrize("field", ["headers", "role", "owned_objects_private"])
def test_exact_source_still_requires_current_session_role_and_private_ownership(provenance, field):
    case = provenance
    actors = case.actors(case.overlap)
    actors[case.names[0]][field] = {"Cookie": "identity=replaced"} if field == "headers" else (
        "admin" if field == "role" else False)
    before = len(case.wire)
    with pytest.raises(ValueError, match="session context changed"):
        discovery.load_discovery(case.target, actors, 24)
    assert len(case.wire) == before


def test_overlapping_sources_cover_only_each_latest_exact_state(provenance):
    case = provenance
    case.execute([case.names[0], case.overlap[1]])
    selected = [case.names[0], case.names[1]]
    path = discovery.prepare_discovery(case.broker, case.spec, case.arguments(selected))
    payload = json.loads(path.read_bytes())["payload"]
    assert len(payload["sources"]) == 2
    before = len(case.wire)
    assert discovery.load_discovery(case.target, case.actors(selected), 24) == payload["states"]
    assert not path.exists() and len(case.wire) == before


def test_state_cannot_be_substituted_from_another_selected_overlapping_source(provenance):
    case = provenance
    case.execute([case.names[0], case.overlap[1]])
    selected = case.names
    case.path = discovery.prepare_discovery(case.broker, case.spec, case.arguments(selected))
    payload = json.loads(case.path.read_bytes())["payload"]
    older = next(source for source in payload["sources"] if case.names[1] in source["state_names"])
    report = json.loads(Path(older["reference"]["path"]).read_bytes())
    old_state = report["identity_discovery_state"][case.names[0]]
    assert old_state != payload["states"][case.names[0]]
    payload["states"][case.names[0]] = old_state
    resign(case, payload)
    before = len(case.wire)
    with pytest.raises(ValueError, match="sources missing"):
        discovery.load_discovery(case.target, case.actors(selected), 24)
    assert len(case.wire) == before


@pytest.mark.parametrize("change", ["target", "max_requests", "prepared_ttl"])
def test_valid_cache_mismatch_and_prepared_expiry_are_consumed_without_traffic(provenance, monkeypatch, change):
    case = provenance
    target, limit = case.target, 24
    if change == "target":
        target += "other"
    elif change == "max_requests":
        limit = 12
    else:
        monkeypatch.setattr(discovery, "time", SimpleNamespace(
            time=lambda: case.payload["prepared_at"] + discovery.TTL_SECONDS))
    before = len(case.wire)
    assert discovery.load_discovery(target, case.actors(case.overlap), limit) == {}
    assert not case.path.exists() and len(case.wire) == before


def test_unknown_cost_receipt_cannot_prepare_reuse(provenance):
    case = provenance
    receipt_path = Path(case.broker.tools[-1]["artifact"])
    receipt = json.loads(receipt_path.read_bytes())
    receipt["execution"].pop("actual_request_cost")
    receipt_path.write_bytes(canonical_bytes(receipt))
    path = discovery.prepare_discovery(case.broker, case.spec, case.arguments(case.overlap))
    payload = json.loads(path.read_bytes())["payload"]
    assert payload["states"] == {} and payload["sources"] == []
    before = len(case.wire)
    assert discovery.load_discovery(case.target, case.actors(case.overlap), 24) == {}
    assert not path.exists() and len(case.wire) == before


def test_reused_observations_and_raw_confirmed_results_are_not_validation_executions(provenance):
    from cco_validator_core import load_validation
    case = provenance
    # Select the replay lab's independently defined positive/negative pair;
    # planner priority among four identities need not select that pair first.
    names = ["first", "second"]
    case.execute(names)
    path = discovery.prepare_discovery(case.broker, case.spec, case.arguments(names))
    payload = json.loads(path.read_bytes())["payload"]
    report = case.broker.read_reference(case.broker.results[-1]["content_ref"])
    assert {load_validation(item["validation_id"])["verdict"] for item in report["validations"]} == {
        "CONFIRMED", "UNCONFIRMED"}
    case.broker.tools.clear()
    before = len(case.wire), case.broker.budget.used["http"]
    assert discovery.load_discovery(case.target, case.actors(names), 24) == payload["states"]
    summary = case.solver.compile_summary(case.spec, terminal(case.spec))
    assert not case.broker.validation_attempts(case.spec)
    assert not summary["findings"] and not summary["validation_outcomes"]
    assert not summary["validation_funnel"]["evidence_accepted"]
    assert all(row["status"] == "NOT TESTED" for row in summary["identity_comparisons"])
    assert not case.broker.tools and (len(case.wire), case.broker.budget.used["http"]) == before


def test_invocation_restores_other_broker_contract_and_is_single_use(provenance, monkeypatch, tmp_path):
    case = provenance
    context = os.environ[discovery.CONTEXT_ENV]
    other_spec = copy.deepcopy(case.spec)
    other_spec.id += "-other-broker"
    other = SimpleNamespace(private=tmp_path / "other-private", workdir=tmp_path / "other-work",
                            validation_attempts=lambda _spec: [], tools=[], results=[])
    other_path = discovery.prepare_discovery(other, other_spec, case.arguments(case.overlap))
    assert other_path != case.path
    monkeypatch.setenv(discovery.STATE_ENV, str(case.path))
    monkeypatch.setenv(discovery.CONTEXT_ENV, context)
    before = len(case.wire)
    assert discovery.load_discovery(case.target, case.actors(case.overlap), 24) == case.payload["states"]
    assert not case.path.exists() and other_path.exists()
    assert discovery.load_discovery(case.target, case.actors(case.overlap), 24) == {}
    assert len(case.wire) == before


def test_broker_restores_armed_contract_after_failed_dispatch(provenance, monkeypatch):
    case = provenance
    context = os.environ[discovery.CONTEXT_ENV]

    def fail(self, task):
        raise ValueError("owned dispatch failure")

    monkeypatch.setattr(type(case.broker.executor), "__call__", fail)
    before = len(case.wire)
    # An interrupted dispatch has unknown usage; keep the existing fail-closed
    # budget exception instead of weakening it to expose the executor's error.
    with pytest.raises(BudgetError, match="missing or invalid http usage"):
        case.broker.invoke("hunter_run_web_loop", case.arguments(case.overlap))
    assert os.environ[discovery.CONTEXT_ENV] == context
    assert os.environ[discovery.STATE_ENV] == str(case.path)
    assert discovery.load_discovery(case.target, case.actors(case.overlap), 24) == case.payload["states"]
    assert len(case.wire) == before
