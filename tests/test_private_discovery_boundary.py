"""Public semantic exports and exact signed host-private discovery handoffs."""
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidence_trust import attest, canonical_bytes
from full_agent_python_broker import READ_TOOL, _DiscoveryOutputAdapter
import python_identity_discovery as discovery
from test_blind_discovery_integration import (
    BASE, IDS,
    setup as blind_setup,
    test_blind_discovery_reaches_signed_authz_validation_without_operator_object_list as _explicit_discovery,
    test_differential_discovery_confirms_bola_without_explicit_owner as _differential_discovery,
)
from test_python_identity_discovery_integrity import provenance
from test_full_agent_python_solver import python_broker
from test_python_candidate_runtime import replay_lab


CANARIES = ("synthetic-principal-boundary", "synthetic-contact-boundary@lab",
            "synthetic-cookie-boundary", "synthetic-object-boundary")


@pytest.fixture(autouse=True)
def isolated_discovery_context(monkeypatch):
    # prepare_discovery is also a host API used outside invoke by integrity
    # fixtures. Own this file's environment changes without altering theirs.
    for key in (discovery.CONTEXT_ENV, discovery.STATE_ENV):
        monkeypatch.setenv(key, "")
        monkeypatch.delenv(key)


def assert_public(value):
    raw = json.dumps(value)
    assert not any(canary in raw for canary in CANARIES)
    assert "identity_facts" not in raw


@pytest.mark.parametrize("run", [_explicit_discovery, _differential_discovery])
def test_unchanged_discovery_assertions_also_cover_persisted_public_reports(blind_setup, tmp_path, run):
    hunter, _, monkeypatch = blind_setup
    outputs = []

    def persist(report, **_kwargs):
        path = tmp_path / (str(len(outputs)) + ".json")
        path.write_text(json.dumps(report))
        outputs.append(path)
        return str(path)

    monkeypatch.setattr(hunter, "write_artifact", persist)
    run(blind_setup)
    assert outputs
    for path in outputs:
        raw = path.read_text()
        assert "alice-subject" not in raw and "bob-subject" not in raw
        assert "alice-marker@lab" not in raw and "bob-marker@lab" not in raw
        assert "alice-secret" not in raw and "bob-secret" not in raw
        assert "identity_facts" not in raw


@pytest.mark.parametrize("run", [_explicit_discovery, _differential_discovery])
def test_hunter_publishes_signed_private_observations_outside_its_public_json(
        python_broker, blind_setup, tmp_path, run):
    hunter, _, monkeypatch = blind_setup
    original = hunter.run_web_loop
    observed = []

    def with_host_invocation(target, **arguments):
        spec = copy.deepcopy(python_broker.tasks.specs[2])
        spec.target = target
        host = SimpleNamespace(private=tmp_path / "producer-private", workdir=tmp_path,
                               validation_attempts=lambda _spec: [], tools=[], results=[])
        discovery.prepare_discovery(host, spec, {"target": target, **arguments})
        expected = json.loads(os.environ[discovery.CONTEXT_ENV])
        raw = original(target, **arguments)
        report = json.loads(raw)
        path = Path(expected["result_path"])
        observation = discovery._signed_reference(discovery._reference(path), discovery.OBSERVATION_PURPOSE)
        assert observation["invocation"] == expected["invocation"]
        assert observation["task_spec_sha256"] == expected["task_spec_sha256"]
        assert observation["arguments_sha256"] == expected["arguments_sha256"]
        assert observation["public_output_sha256"] == hashlib.sha256(canonical_bytes(report)).hexdigest()
        assert discovery.public_state(observation["states"]) == report["identity_discovery_state"]
        from privacy_contract_assertions import assert_route_contract
        private_report = observation["operational_report"]
        assert_route_contract(report, private_report, {
            BASE + "orders/" + IDS["alice"]: ("alice", "bob", "CONFIRMED"),
            BASE + "orders/" + IDS["bob"]: ("bob", "alice", "UNCONFIRMED"),
        }, private_values=(*IDS.values(), "alice-subject", "bob-subject",
                           "alice-secret", "bob-secret", "alice-marker@lab", "bob-marker@lab"))
        assert len(discovery._completed_queue(private_report, set(IDS))) == 2
        assert str(path) not in raw and "identity_facts" not in raw
        assert path.stat().st_mode & 0o777 == 0o600
        assert all("headers" not in state for state in observation["states"].values())
        observed.append(observation)
        return raw

    monkeypatch.setattr(hunter, "run_web_loop", with_host_invocation)
    # Exact private controls plus public hash refs; original scope/grant and
    # synthetic transport remain intact.
    run(blind_setup)
    assert len(observed) == 1
    private_raw = json.dumps(observed[0]["states"])
    expected_marker = "alice-subject" if run is _explicit_discovery else "alice-marker@lab"
    assert expected_marker in private_raw
    assert "alice-secret" not in private_raw and "bob-secret" not in private_raw


def test_discovery_output_adapter_preserves_non_json_failures_and_measured_cost():
    execution = {"actual_request_cost": 4, "execution_failed": True,
                 "result": {"output": "synthetic non-JSON transport failure"}}
    adapter = _DiscoveryOutputAdapter(lambda _task: execution)
    assert adapter({}) is execution


def test_discovery_output_adapter_preserves_timeout_and_host_termination():
    terminated = []
    executor = SimpleNamespace(timeout_seconds=900, terminate=lambda: terminated.append(True))
    adapter = _DiscoveryOutputAdapter(executor)
    adapter.timeout_seconds = 3
    assert executor.timeout_seconds == adapter.timeout_seconds == 3
    adapter.terminate()
    assert terminated == [True]


def test_core_returns_only_semantic_cards_and_keeps_operational_state_private(monkeypatch):
    from cco_hunter_core.loop import execute_web_loop
    target = "http://owned.invalid/objects/one"
    actors = {"actor": {"headers": {"Cookie": CANARIES[2]}, "role": "member",
        "test_data_only": True, "owned_objects_private": True,
        "identity_facts": [{"field": "principal", "value": CANARIES[0]}],
        "objects": [{"url": target + "?contact=" + CANARIES[1], "marker": CANARIES[3],
                     "method": "GET", "param": "contact", "state_key": "observed",
                     "contact": CANARIES[1], "headers": {"Cookie": CANARIES[2]},
                     "provenance": {"source": "response_metadata", "contact": CANARIES[1]}}],
        "resources": [{"resource_id": CANARIES[3], "contact": CANARIES[1], "family": "/objects"}]}}
    original = copy.deepcopy(actors)
    private = {}
    report = execute_web_loop(target, live=True, crawl=False, fuzz_limit=0,
        identity_discover=lambda *_args: ({"status": "ready"}, actors, []),
        on_discovery_state=private.update)
    assert_public(report)
    assert actors == original
    state = private["actor"]
    assert state["identity_facts"][0]["value"] == CANARIES[0]
    assert state["objects"][0]["marker"] == CANARIES[3]
    card = report["identity_discovery_state"]["actor"]
    assert len(card["identity_ref"]) >= 24
    assert card["objects"][0]["method"] == "GET"
    assert card["objects"][0]["param"] == "contact"
    assert card["objects"][0]["state_key"] == "observed"
    assert card["objects"][0]["provenance"] == {"source": "response_metadata"}
    assert card["resources"][0]["family"] == "/objects"
    assert "headers" not in state  # no actor credentials were captured


def test_signed_private_state_hydrates_but_model_archives_and_reader_cannot_access_it(provenance):
    case = provenance
    report = case.broker.read_reference(case.broker.results[-1]["content_ref"])
    assert "identity_facts" not in json.dumps(report)
    assert "owned-" not in json.dumps(report)
    source = case.payload["sources"][0]
    seal = discovery._signed_reference(source["private_reference"], discovery.SOURCE_PURPOSE)
    observation = discovery._signed_reference(seal["producer_reference"], discovery.OBSERVATION_PURPOSE)
    assert observation["states"][case.names[0]]["identity_facts"][0]["value"] == case.names[0]
    assert observation["public_output_sha256"] == hashlib.sha256(canonical_bytes(report)).hexdigest()
    receipt = discovery._read_reference(source["execution_reference"])
    assert receipt["execution"]["result"]["output"] == report
    assert receipt["execution"]["actual_request_cost"] == len(case.wire) > 0
    for ref in (source["private_reference"], seal["producer_reference"]):
        assert ref["path"] not in case.broker.references
        assert Path(ref["path"]).stat().st_mode & 0o777 == 0o600
        with pytest.raises(ValueError):
            case.broker.invoke(READ_TOOL, {"path": ref["path"]})
    view = case.broker.view({"nested": {"identity_discovery_state": {
        "actor": {"identity_facts": [{"value": CANARIES[0]}],
                  "objects": [{"url": case.target, "marker": CANARIES[3], "contact": CANARIES[1],
                               "headers": {"Cookie": CANARIES[2]}}]}}}})
    assert_public(view)
    assert_public(case.broker.read_reference(view["content_ref"]))
    before = len(case.wire)
    assert discovery.load_discovery(case.target, case.actors(case.overlap), 24) == case.payload["states"]
    assert len(case.wire) == before


@pytest.mark.parametrize("change", ["missing", "bytes", "signature", "envelope", "symlink", "parent_symlink",
                                    "public_digest", "invocation", "task", "arguments", "expired", "receipt"])
def test_private_source_changes_fail_closed_before_hydration(provenance, tmp_path, change):
    case = provenance
    source = case.payload["sources"][0]
    seal_path = Path(source["private_reference"]["path"])
    seal = discovery._signed_reference(source["private_reference"], discovery.SOURCE_PURPOSE)
    path = Path(seal["producer_reference"]["path"])
    if change == "missing":
        path.unlink()
    elif change == "bytes":
        path.write_bytes(path.read_bytes() + b" ")
    elif change == "signature":
        envelope = json.loads(path.read_bytes())
        envelope["signature"] = "00" * 64
        path.write_bytes(canonical_bytes(envelope))
    elif change == "envelope":
        path.write_text('{"payload":[]}')
    elif change == "symlink":
        saved = tmp_path / "producer.json"
        saved.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(saved)
    elif change == "parent_symlink":
        private = path.parent
        moved = private.with_name(private.name + "-moved")
        private.rename(moved)
        private.symlink_to(moved, target_is_directory=True)
    elif change == "receipt":
        receipt_path = Path(source["execution_reference"]["path"])
        receipt = json.loads(receipt_path.read_bytes())
        receipt["execution"].pop("actual_request_cost")
        receipt_path.write_bytes(canonical_bytes(receipt))
    else:
        observation = discovery._signed_reference(seal["producer_reference"], discovery.OBSERVATION_PURPOSE)
        key = {"public_digest": "public_output_sha256", "invocation": "invocation", "task": "task_spec_sha256",
               "arguments": "arguments_sha256", "expired": "produced_at"}[change]
        observation[key] = 1.0 if change == "expired" else "changed"
        path.write_bytes(canonical_bytes(attest(observation, discovery.OBSERVATION_PURPOSE)))
        # Even re-signing/re-hashing cannot replace the host's original private
        # source expectation supplied independently of the reuse envelope.
        seal["producer_reference"] = discovery._reference(path)
        seal_path.write_bytes(canonical_bytes(attest(seal, discovery.SOURCE_PURPOSE)))
    before = len(case.wire)
    with pytest.raises((ValueError, OSError)):
        discovery.load_discovery(case.target, case.actors(case.overlap), 24)
    assert len(case.wire) == before


def test_private_producer_expiry_cannot_prepare_new_reuse(provenance, monkeypatch):
    case = provenance
    source = case.payload["sources"][0]
    seal = discovery._signed_reference(source["private_reference"], discovery.SOURCE_PURPOSE)
    observation = discovery._signed_reference(seal["producer_reference"], discovery.OBSERVATION_PURPOSE)
    monkeypatch.setattr(discovery, "time", SimpleNamespace(time=lambda: observation["produced_at"] + discovery.TTL_SECONDS))
    path = discovery.prepare_discovery(case.broker, case.spec, case.arguments(case.overlap))
    assert json.loads(path.read_bytes())["payload"]["states"] == {}


def test_private_handoff_and_archive_limits_remain_byte_bounded(tmp_path):
    path = tmp_path / "private.json"
    with pytest.raises(ValueError, match="archive limit"):
        discovery._write_bounded(path, b"x" * (discovery.MAX_BYTES + 1))
    assert not path.exists()
    path.write_bytes(b"x" * (discovery.MAX_BYTES + 1))
    with pytest.raises(ValueError, match="archive limit"):
        discovery._read_bounded(path)


def test_new_result_context_is_restored_after_dispatch(provenance, monkeypatch):
    case = provenance
    expected = os.environ[discovery.CONTEXT_ENV]
    case.execute(case.names)
    assert os.environ[discovery.CONTEXT_ENV] == expected
