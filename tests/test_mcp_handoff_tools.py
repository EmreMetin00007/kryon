"""Native handoff preparation with isolated scope, custody and session stores."""
import hashlib
import json

import pytest

from test_mcp_ledger_tools import _load_server, _make_run

TARGET = "http://192.0.2.10:8080"
OBJECT_ID = "d94e5fbb-862f-4a15-a811-4252eb9fccb5"


@pytest.fixture
def handoff_run(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path))
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": TARGET}], "allow_loopback": False,
                                 "allow_osint": False, "allow_public_labs": False}))
    policy = tmp_path / "policy.json"
    policy.write_text("{}")
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    server = _load_server()
    monkeypatch.setattr(server.requests, "request", lambda *a, **kw: pytest.fail("handoff must never send HTTP"))
    run = _make_run(tmp_path)
    (run / "summaries").mkdir()
    summary = {"phase": "enum", "target": TARGET, "status": "done", "evidence": ["ev/probe.body"],
               "findings": [], "next": "access", "surface": {
                   "routes": ["/items/" + OBJECT_ID], "params": [], "docs": [],
                   "id_formats": [{"family": "items", "format": "uuid", "example": OBJECT_ID}]}}
    path = run / "summaries" / "enum-2.json"
    path.write_text(json.dumps(summary))
    return server, run, path, summary, monkeypatch


def _prepare(fixture, **kwargs):
    server, run, *_ = fixture
    return server.ledger_prepare_handoff_impl(TARGET, str(run), **kwargs)


def _fresh_bindings(fixture):
    from cco_surface_core import session_store
    bindings = {}
    for name in ("alice", "bob"):
        session_store.put_session(TARGET, name, cookies={"sid": name + "-synthetic-secret"},
                                  check_url=TARGET + "/me", marker=name + "-private-check-marker")
        session_store.refresh_status(TARGET, name, lambda *_, name=name: (200, name + "-private-check-marker"))
        bindings[name] = {"target": TARGET, "role": "member", "test_data_only": True,
                          "owned_objects_private": True}
    return bindings


def test_uuid_and_opaque_ids_preserve_ledger_and_produce_fresh_standard_handoffs(handoff_run):
    server, run, *_ = handoff_run
    before = (run / "hypotheses.json").read_bytes()
    owned = [{"family": "items", "format": "uuid", "value": OBJECT_ID},
             {"family": "items", "format": "opaque", "value": "item-opaque-abc"}]
    result = _prepare(handoff_run, own_ids_json=json.dumps(owned), vector="authz-idor")
    assert result["ok"] and not result["sealed"] and result["declared_own_ids"] == 2
    assert (run / "hypotheses.json").read_bytes() == before
    pool = json.loads((run / "object-pool.json").read_text())
    assert {json.dumps(item, sort_keys=True) for item in pool["candidates"]} == {
        json.dumps(item, sort_keys=True) for item in owned}
    assert not pool["empty_tenant"]
    brain = __import__("brain")
    spec = next(spec for spec in brain.build_plan(TARGET, str(run)) if spec.phase == "access")
    spec.vector = "authz-idor"
    assert brain._handoff_gate_error(spec) is None
    assert set(result["handoffs"]) == {"authz", "authz-idor", "file-access"}
    for label, path in result["handoffs"].items():
        packet = json.loads((run / ("handoff-" + label + ".json")).read_text())
        assert packet["vector"] == label and path.endswith("handoff-" + label + ".json")
        assert packet["pool_sha256"] == result["pool_sha256"]


def test_empty_owned_ids_keep_observed_candidates_unowned(handoff_run):
    result = _prepare(handoff_run)
    run = handoff_run[1]
    pool = json.loads((run / "object-pool.json").read_text())
    assert result["candidates"] == 1 and result["declared_own_ids"] == 0
    assert pool["own_ids"] == [] and pool["empty_tenant"]
    assert pool["candidates"][0]["value"] == OBJECT_ID
    assert result["identities"] == result["session_references_bound"] == 0


def test_helper_initializes_only_a_missing_ledger(handoff_run):
    run = handoff_run[1]
    (run / "hypotheses.json").unlink()
    assert _prepare(handoff_run)["ok"]
    ledger = json.loads((run / "hypotheses.json").read_text())
    assert ledger["target"] == TARGET and ledger["hypotheses"]


def test_verified_sessions_transfer_references_and_preserve_existing_jobs(handoff_run):
    server, run, *_ = handoff_run
    mod = server._attempt_ledger_mod()
    state = {"identities": [], "jobs": []}
    mod.add_job(state, "export", "synthetic-job")
    mod.save_state(run, state)
    bindings = _fresh_bindings(handoff_run)
    result = _prepare(handoff_run, session_bindings_json=json.dumps(bindings))
    stored = mod.load_state(run)
    assert result["session_references_bound"] == result["identities"] == 2
    assert stored["jobs"] == state["jobs"]
    assert stored["identities"] == [
        {"name": name, "pointer": "session-vault:" + hashlib.sha256((TARGET + "::" + name).encode()).hexdigest()}
        for name in ("alice", "bob")]
    public = json.dumps(result) + mod.state_path(run).read_text() + (run / "handoff-access.json").read_text()
    assert "synthetic-secret" not in public and "private-check-marker" not in public
    brain = __import__("brain")
    spec = next(spec for spec in brain.build_plan(TARGET, str(run), kind="authed") if spec.phase == "authz")
    assert brain._handoff_gate_error(spec) is None


@pytest.mark.parametrize("kwargs,match", [
    ({"vector": "../outside"}, "vector"),
    ({"budget_calls": 31}, "budget_calls"),
    ({"budget_calls": True}, "budget_calls"),
    ({"max_chars": 100}, "max_chars"),
    ({"own_ids_json": "{}"}, "owned IDs"),
    ({"own_ids_json": "[true]"}, "boolean"),
    ({"own_ids_json": '["token=synthetic-secret"]'}, "credential material"),
    ({"session_bindings_json": "[]"}, "test account references"),
    ({"session_bindings_json": '{"alice":{"target":"http://192.0.2.10:8080","test_data_only":false}}'}, "binding"),
    ({"session_bindings_json": '{"alice":{"target":"http://192.0.2.10:8081","test_data_only":true}}'}, "origin"),
    ({"session_bindings_json": '{"alice":{"target":"http://192.0.2.10:8080","test_data_only":true,"cookie":"secret"}}'}, "binding"),
    ({"session_bindings_json": '{"alice":{"target":"http://192.0.2.10:8080","test_data_only":true}}'}, "not recently verified"),
])
def test_invalid_inputs_never_publish_pool_or_handoff(handoff_run, kwargs, match):
    with pytest.raises(ValueError, match=match):
        _prepare(handoff_run, **kwargs)
    run = handoff_run[1]
    assert not (run / "object-pool.json").exists() and not list(run.glob("handoff-*.json"))


@pytest.mark.parametrize("change,match", [
    ({"target": "http://192.0.2.10:8081"}, "target"),
    ({"phase": "access"}, "terminal"),
    ({"status": "partial"}, "steps"),
    ({"status": "in_progress"}, "status"),
    ({"surface": {"routes": [], "params": []}}, "empty"),
])
def test_summary_contract_is_checked_before_mutation(handoff_run, change, match):
    _, run, path, summary, _ = handoff_run
    path.write_text(json.dumps({**summary, **change}))
    with pytest.raises(ValueError, match=match):
        _prepare(handoff_run)
    assert not (run / "object-pool.json").exists()


def test_active_scope_and_existing_ledger_target_must_match(handoff_run):
    server, run, *_ = handoff_run
    with pytest.raises(ValueError, match="outside active scope"):
        server.ledger_prepare_handoff_impl("http://192.0.2.10:8081", str(run))
    (run / "hypotheses.json").write_text(json.dumps({"target": "http://192.0.2.11:8080", "hypotheses": []}))
    with pytest.raises(ValueError, match="ledger target"):
        _prepare(handoff_run)


@pytest.mark.parametrize("name", ["object-pool.json", "handoff-access.json", "run-state.json", "attempts.jsonl"])
def test_symlink_destinations_and_attempts_are_rejected(handoff_run, tmp_path, name):
    run = handoff_run[1]
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (run / name).symlink_to(outside)
    with pytest.raises(ValueError, match="regular file"):
        _prepare(handoff_run)
    assert outside.read_text() == "{}"


def test_secret_symlink_and_escaped_summary_paths_are_rejected(handoff_run, tmp_path):
    _, run, path, *_ = handoff_run
    secret_alias = run / ".env.json"
    secret_alias.symlink_to(path)
    inside_alias = run / "summary-alias.json"
    inside_alias.symlink_to(path)
    outside = tmp_path / "outside-summary.json"
    outside.write_bytes(path.read_bytes())
    for name in (str(secret_alias), str(inside_alias), str(outside), "../outside-summary.json"):
        with pytest.raises(ValueError):
            _prepare(handoff_run, summary_file=name)


def test_tampered_attempt_chain_cannot_be_hidden_by_new_handoff(handoff_run):
    server, run, *_ = handoff_run
    server.ledger_attempt_add_impl(str(run), "authz-idor", "/items/" + OBJECT_ID,
                                   "alice", "control_own_200", status=200, artifact="ev/probe.body")
    path = run / "attempts.jsonl"
    record = json.loads(path.read_text())
    record["verdict"] = "forged-result"
    path.write_text(json.dumps(record) + "\n")
    with pytest.raises(ValueError, match="integrity"):
        _prepare(handoff_run)
    assert not (run / "object-pool.json").exists()


def test_incomplete_handoff_is_rejected_before_publishing(handoff_run):
    with pytest.raises(ValueError, match="exceeds max_chars"):
        _prepare(handoff_run, max_chars=512)
    run = handoff_run[1]
    assert not (run / "object-pool.json").exists() and not list(run.glob("handoff-*.json"))


def test_session_rotation_during_preparation_leaves_no_published_files(handoff_run):
    from cco_surface_core import session_store
    bindings = _fresh_bindings(handoff_run)
    monkeypatch = handoff_run[-1]
    monkeypatch.setattr(session_store, "same_verified_session", lambda *_: False)
    with pytest.raises(ValueError, match="changed while preparing"):
        _prepare(handoff_run, session_bindings_json=json.dumps(bindings))
    run = handoff_run[1]
    assert not (run / "object-pool.json").exists() and not list(run.glob(".handoff-*"))
    assert not (run / "run-state.json").exists()
