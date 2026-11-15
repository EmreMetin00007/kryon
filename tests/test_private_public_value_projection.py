"""Whole-report value privacy without disabling signed host-owned validation."""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
from urllib.parse import quote, unquote

import pytest

from evidence_trust import attest, canonical_bytes
from conftest import load_server
from full_agent_python_broker import READ_TOOL, _DiscoveryOutputAdapter
import python_identity_discovery as discovery
from test_full_agent_python_solver import python_broker
from test_private_discovery_boundary import isolated_discovery_context
from test_python_candidate_runtime import replay_lab
from test_python_identity_discovery_integrity import provenance


def atom():
    return "synthetic-" + secrets.token_hex(12) + '@lab/"\\'


def assert_absent(value, private):
    text = json.dumps(value, ensure_ascii=True)
    for _ in range(4):
        assert private not in text
        assert json.dumps(private)[1:-1] not in text
        text = unquote(text)


def sample(private):
    url = "http://127.0.0.1:18765/users/" + quote(quote(private, safe=""), safe="") + "?contact=" + quote(private, safe="")
    state = {"actor": {"identity_ref": private, "role": "member", "owned_objects_private": True,
                       "observed_at": 1.0, "identity_facts": [{"field": "principal", "value": private}],
                       "objects": [{"url": url, "marker": private, "method": "GET", "param": "contact",
                                    "state_key": "observed", "resource_key": private,
                                    "provenance": {"source": "response_metadata", "source_artifact": private}}]}}
    row = {"url": url, "method": "GET", "vuln_class": "sqli", "param": "contact",
           "candidate_source": private, "candidate_reason": private, "operation_id": private,
           "observation_id": private, "resource_key": private, "resource_family": private,
           "state_key": private, "variant_key": private, "run_id": private,
           "provenance": {"source": private, "source_spec_id": private, "source_artifact": private,
                          "source_sha256": private, "scope_revision": private, "policy_hash": private},
           "extra": private, private: private}
    return url, state, row


@pytest.mark.parametrize("encoding", ["plain", "percent", "double-percent", "json", "unicode-json"])
def test_all_public_pipeline_fields_are_value_safe_and_idempotent(encoding):
    private = atom()
    _, state, row = sample(private)
    encoded = {"plain": private, "percent": quote(private, safe=""),
               "double-percent": quote(quote(private, safe=""), safe=""),
               "json": json.dumps(private), "unicode-json": json.dumps(private).replace("s", "\\u0073")}[encoding]
    row["extra"] = encoded
    report = {"identity_discovery_state": state, "ok": True,
              **{field: [copy.deepcopy(row)] for field in ("discovery_operations", "validation_candidates",
                    "validation_queue", "skipped", "validations", "confirmed", "surface_probes", "exploits",
                    "revisit_candidates", "feedback_queue")},
              **{field: {"url": row["url"], "scalar": encoded, "provenance": row["provenance"]}
                 for field in ("discover", "crawl", "zap", "fuzz", "replan", "identity_matrix")}}
    original = copy.deepcopy(report)
    public = discovery.public_export(report)
    assert_absent(public, private)
    assert public == discovery.public_export(public)
    assert report == original
    for field in ("discovery_operations", "validation_candidates", "validation_queue", "skipped"):
        assert public[field][0]["method"] == "GET"
        assert public[field][0]["param"] == "contact"
        assert len(public[field]) == len(report[field])
        assert public[field][0]["url_sha256"] == hashlib.sha256(row["url"].encode()).hexdigest()


def test_loop_projects_early_returns_and_keeps_exact_validator_arguments():
    load_server("hunter")
    from cco_hunter_core.loop import execute_web_loop
    private = atom()
    url, _, row = sample(private)
    row["vuln_class"] = "sql_injection"
    actors = {"actor": {"headers": {}, "role": "member", "test_data_only": True,
                       "owned_objects_private": True, "objects": [{"url": url, "marker": private}],
                       "identity_facts": [{"field": "principal", "value": private}]}}
    actual, raw, states = [], {}, {}

    def validate(item, **_kwargs):
        actual.append(copy.deepcopy(item))
        return {"verdict": "INCONCLUSIVE"}

    report = execute_web_loop("http://127.0.0.1:18765/", live=True, crawl=False, fuzz_limit=0,
        identity_discover=lambda *_a: ({"status": "ready"}, actors, [row]),
        validate=validate, on_discovery_state=states.update, on_private_report=raw.update)
    assert actual and actual[0]["url"] == url
    assert states["actor"]["objects"][0]["marker"] == private
    assert raw["validation_queue"][0]["url"] == url
    assert_absent(report, private)
    blocked = execute_web_loop(url, live=True, crawl=False, fuzz_limit=0,
        identity_discover=lambda *_a: ({"status": "blocked", "reasons": [private]}, {}, []))
    assert not blocked["ok"]
    assert_absent(blocked, private)


def test_unknown_scalar_types_do_not_masquerade_as_semantics_or_digests():
    private = secrets.token_hex(32)
    report = {"validation_queue": [], "extra": private, "other": 123456789,
              "untrusted_state": "ready", "resource_key": 123456789,
              "tuple": (private,), "bytes": private.encode()}
    safe = discovery.public_export(report)
    assert private not in json.dumps(safe)
    assert "123456789" not in json.dumps(safe)
    assert "ready" not in json.dumps(safe)
    assert safe == discovery.public_export(safe)
    state = discovery.public_state({"actor": {"observed_at": private}})
    assert private not in json.dumps(state)


def test_hunter_session_failure_projects_target_and_nested_replan(monkeypatch):
    hunter = load_server("hunter")
    private = atom()
    target, _, row = sample(private)

    def unavailable(*_args, **_kwargs):
        raise ValueError(private)

    monkeypatch.setattr(hunter, "_vault_test_identities", unavailable)
    monkeypatch.setattr(hunter, "replan_web_report", lambda _report: {"extra": private, "url": row["url"]})
    report = json.loads(hunter.run_web_loop(target, live=True, session_bindings='{"actor":{}}'))
    assert not report["ok"] and report["requests_authorized"] == 0
    assert_absent(report, private)


@pytest.mark.parametrize("writer_error", [False, True])
def test_hunter_persists_only_public_report_and_projects_writer_errors(monkeypatch, tmp_path, writer_error):
    hunter = load_server("hunter")
    private = atom()
    target, state, row = sample(private)
    raw = {"ok": True, "errors": [], "skipped": [], "identity_discovery_state": state,
           "validation_queue": [row]}
    persisted = tmp_path / "public-report.json"

    def loop(*_args, **kwargs):
        kwargs["on_private_report"](copy.deepcopy(raw))
        return discovery.public_export(raw)

    def write(report, **_kwargs):
        persisted.write_text(json.dumps(report))
        if writer_error:
            raise ValueError(private)
        return private

    monkeypatch.setattr(hunter, "execute_web_loop", loop)
    monkeypatch.setattr(hunter, "write_artifact", write)
    monkeypatch.setattr(hunter, "replan_web_report", lambda _report: {"extra": private})
    report = json.loads(hunter.run_web_loop(target))
    assert report["ok"]
    assert_absent(report, private)
    assert_absent(json.loads(persisted.read_text()), private)
    assert ("artifact_error" in report) is writer_error


@pytest.mark.parametrize("live", [False, True])
def test_hunter_coverage_gap_early_results_project_every_public_branch(monkeypatch, live):
    hunter = load_server("hunter")
    from cco_hunter_core import campaign_gaps, feedback
    private = atom()
    target, _, row = sample(private)

    def unavailable(*_args, **_kwargs):
        raise ValueError("blocked_scope")

    monkeypatch.setattr(campaign_gaps, "load_request", unavailable)
    monkeypatch.setattr(feedback, "persist_feedback", lambda *_a, **_kw: [{"url": row["url"], "extra": private}])
    monkeypatch.setattr(hunter, "_verified_coverage_events", lambda *_args: [])
    monkeypatch.setattr(hunter, "replan_web_report", lambda _report: {"extra": private, "url": row["url"]})
    report = json.loads(hunter.run_web_loop(target, live=live, gap_ref=private))
    assert report["ok"] is (not live)
    assert report["coverage_gap"]["coverage_recorded"] is False
    assert report["requests_authorized"] == 0
    assert_absent(report, private)


@pytest.mark.parametrize("serialized", [False, True])
def test_archive_views_and_model_context_project_arguments_results_and_labels(python_broker, serialized):
    private = atom()
    _, state, row = sample(private)
    report = {"identity_discovery_state": state, "discovery_operations": [row]}
    execution = {"actual_request_cost": 7, "result": {"output": json.dumps(report) if serialized else report}}
    emitted = _DiscoveryOutputAdapter(lambda _task: execution)({})
    assert emitted["actual_request_cost"] == 7
    assert_absent(emitted, private)
    value = {"tool": "hunter_run_web_loop", "arguments": {"target": row["url"], "scalar": private},
             "result": emitted["result"]["output"]}
    view = python_broker.view(value, label=private)
    assert_absent(view, private)
    assert Path(view["content_ref"]["path"]).name.split("-")[0] == hashlib.sha256(private.encode()).hexdigest()[:16]
    stored = python_broker.read_reference(view["content_ref"])
    assert_absent(stored, private)
    archived = python_broker._read_reference_bytes(view["content_ref"])
    assert json.loads(archived) == stored
    assert hashlib.sha256(archived).hexdigest() == view["content_ref"]["sha256"]
    spec = python_broker.tasks.specs[2]
    body = {"messages": [{"role": "system", "content": "host"}, {"role": "user", "content": json.dumps({
                "schema": "python-workflow-v1", "task_spec": spec.to_dict(), "recent_results": [value]})}],
            "tools": [], "model": "model"}
    wire, _, _ = python_broker.project_runtime_context(body, spec, None)
    assert_absent(wire, private)


def test_signed_private_pipeline_hydration_keeps_current_owned_loopback_controls(provenance):
    case = provenance
    # The unchanged fixture has already executed production signed validators
    # over real loopback HTTP under scope/wire/TaskSpec admission.
    assert case.wire
    source = case.payload["sources"][0]
    receipt = discovery._read_reference(source["execution_reference"])
    public = case.broker.read_reference(case.broker.results[-1]["content_ref"])
    observation = discovery._source_observation(source, case.spec.to_dict(), public, receipt)
    assert observation["public_output_sha256"] == hashlib.sha256(canonical_bytes(public)).hexdigest()
    assert receipt["execution"]["result"]["output"] == public
    assert receipt["execution"]["actual_request_cost"] == len(case.wire)
    assert observation["operational_report"]["validation_queue"][0]["url"] != public["validation_queue"][0]["url"]
    assert case.broker.validation_attempts(case.spec)
    raw = case.broker.private_discovery_report(case.spec, case.broker.results[-1]["content_ref"])
    completed = discovery._completed_queue(raw, set(case.names))
    trusted = {item["record"]["validation_id"] for item in case.broker.validation_attempts(case.spec)}
    assert completed and {item["validation_id"] for item in completed.values()} <= trusted
    assert set(case.payload["states"]) == {case.names[0]}
    for ref in (source["private_reference"], discovery._signed_reference(source["private_reference"],
                discovery.SOURCE_PURPOSE)["producer_reference"]):
        assert ref["path"] not in case.broker.references
        with pytest.raises(ValueError):
            case.broker.invoke(READ_TOOL, {"path": ref["path"]})
    before = len(case.wire)
    assert discovery.load_discovery(case.target, case.actors(case.overlap), 24) == case.payload["states"]
    assert len(case.wire) == before
    assert not Path(os.environ[discovery.STATE_ENV]).exists()


def test_resigned_operational_pipeline_still_requires_exact_public_projection(provenance):
    case = provenance
    source = case.payload["sources"][0]
    seal_path = Path(source["private_reference"]["path"])
    seal = discovery._signed_reference(source["private_reference"], discovery.SOURCE_PURPOSE)
    producer_path = Path(seal["producer_reference"]["path"])
    observation = discovery._signed_reference(seal["producer_reference"], discovery.OBSERVATION_PURPOSE)
    observation["operational_report"]["validation_queue"][0]["url"] += "-not-observed"
    producer_path.write_bytes(canonical_bytes(attest(observation, discovery.OBSERVATION_PURPOSE)))
    seal["producer_reference"] = discovery._reference(producer_path)
    seal_path.write_bytes(canonical_bytes(attest(seal, discovery.SOURCE_PURPOSE)))
    case.broker.private_discovery_sources[source["execution_reference"]["path"]] = discovery._reference(seal_path)
    before = len(case.wire)
    with pytest.raises(ValueError, match="provenance unavailable"):
        case.broker.private_discovery_report(case.spec, case.broker.results[-1]["content_ref"])
    assert len(case.wire) == before
