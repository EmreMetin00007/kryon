"""Useful public decisions/route refs, with exact current signed private controls."""
import hashlib
import json
from pathlib import Path
import os

import pytest

from evidence_trust import canonical_bytes
from full_agent_python_broker import READ_TOOL
import python_identity_discovery as discovery
from privacy_contract_assertions import assert_route_contract
from test_full_agent_python_solver import python_broker
from test_python_candidate_runtime import replay_lab
from test_python_identity_discovery_integrity import provenance


@pytest.mark.parametrize("diagnostic,expected", [
    ("invalid_session_bindings_json", "invalid_session_bindings_json"),
    ("invalid_session_binding", "invalid_session_binding"),
    ("mixed_session_material", "mixed_session_material"),
    ("session_not_recently_verified", "session_not_recently_verified"),
    ("run stopped: policy gate unavailable: synthetic-contact@lab", "policy gate unavailable"),
    ("run stopped: policy gate synthetic-contact@lab", "policy gate denied"),
    ("run stopped: session unavailable, synthetic-contact@lab", "session unavailable"),
])
def test_public_host_diagnostics_keep_only_fixed_decision_semantics(diagnostic, expected):
    public = discovery.public_export({"validation_queue": [], "skipped": [{"reason_code": diagnostic}],
                                      "stopped": diagnostic, "value": diagnostic})
    assert public["skipped"][0]["reason_code"] == public["stopped"] == expected
    assert public["value"].startswith("opaque:")
    assert "synthetic-contact@lab" not in json.dumps(public)
    assert discovery.public_export(public) == public
    # Appended data cannot inherit an exact enum's public status.
    tainted = discovery.public_export({"validation_queue": [], "reason_code": expected + " synthetic-contact@lab"})
    assert tainted["reason_code"].startswith("opaque:")


def test_signed_loopback_queue_keeps_exact_objects_and_controls_while_public_refs_remain_useful(provenance):
    case = provenance
    # Use the unchanged replay lab's independent positive/negative pair. The
    # fixture, scope, observation corpus and transport responses are untouched.
    case.execute(["first", "second"])
    row = case.broker.results[-1]
    public = case.broker.read_reference(row["content_ref"])
    private = case.broker.private_discovery_report(case.spec, row["content_ref"])
    expected = {case.target + "objects/first": ("first", "second", "CONFIRMED"),
                case.target + "objects/second": ("second", "first", "UNCONFIRMED")}
    assert_route_contract(public, private, expected, private_values=("owned-first", "owned-second",
                                                                  "identity=first", "identity=second"))
    assert {"/objects/first", "/objects/second"} <= {item["path"] for item in case.wire}
    assert len(case.broker.validation_attempts(case.spec)) == 4  # both actual directed runs
    path = discovery.prepare_discovery(case.broker, case.spec, case.arguments(["first", "second"]))
    payload = json.loads(path.read_bytes())["payload"]
    source = payload["sources"][0]
    receipt = discovery._read_reference(source["execution_reference"])
    observation = discovery._source_observation(source, case.spec.to_dict(), public, receipt)
    assert observation["operational_report"] == private
    assert observation["states"] == payload["states"]
    assert observation["public_output_sha256"] == hashlib.sha256(canonical_bytes(public)).hexdigest()
    assert receipt["execution"]["result"]["output"] == public
    assert receipt["execution"]["actual_request_cost"] > 0
    seal = discovery._signed_reference(source["private_reference"], discovery.SOURCE_PURPOSE)
    for ref in (source["private_reference"], seal["producer_reference"]):
        assert ref["path"] not in case.broker.references
        assert Path(ref["path"]).stat().st_mode & 0o777 == 0o600
        with pytest.raises(ValueError):
            case.broker.invoke(READ_TOOL, {"path": ref["path"]})
    before = len(case.wire)
    assert discovery.load_discovery(case.target, case.actors(["first", "second"]), 24) == payload["states"]
    assert len(case.wire) == before and not Path(os.environ[discovery.STATE_ENV]).exists()
