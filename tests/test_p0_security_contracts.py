"""Security-boundary regressions: fake transport, real policy and signed artifacts."""
import copy
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-validator"))

import brain
import hypothesis_ledger as hypotheses
from chain_executor import ChainExecutor
from cco_validator_core import evidence
from policy_engine import PolicyEngine


def response(status=200, text="synthetic response"):
    return {"ok": True, "status": status, "text": text, "len": len(text),
            "headers": {}, "location": "", "error": None}


def manifest(tool="http_get", args=None, budget=10):
    return {"schema_version": "action-manifest/1.0", "objective": "offline regression",
            "target_ref": "own", "risk": "active_read_only", "identity_refs": [],
            "budget": {"max_requests": budget, "max_duration_seconds": 30},
            "steps": [{"id": "probe", "tool": tool, "args": args or {"path": "/own"},
                       "expect": {"oracle": "status_code", "status": 200},
                       "on_success": "succeed", "on_failure": "fail"}]}


@pytest.fixture
def policy(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    codex = tmp_path / ".codex"
    codex.mkdir()
    scope = codex / "scope.json"
    scope.write_text(json.dumps({"scope_policy": "explicit_only",
        "allow_osint": False, "allow_public_labs": False, "allow_loopback": False,
        "in_scope": [{"asset": "security-review.test"}]}))
    policy_path = codex / "program-policy.json"
    policy_path.write_text("{}")
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy_path))
    engine = PolicyEngine(cco_home=str(tmp_path / "policy-state"), repo_root=str(tmp_path))
    engine.grant_approval("chain_runner_*", "security-review.test", ttl_seconds=600,
                          reason="offline test with fake transport")
    return engine


def runner(policy, sender, **kwargs):
    return ChainExecutor(policy_engine=policy, sender=sender,
        target_bases={"own": "https://security-review.test"}, **kwargs)


@pytest.mark.parametrize("tool,args,blocked", [
    ("http_post", {"path": "/own", "method": "PATCH"}, "PATCH"),
    ("mailbox_poll", {"path": "/own", "email": "own@example.test"}, "GET"),
    ("batch_probe", {"requests": [{"path": "/own", "method": "OPTIONS"}]}, "OPTIONS"),
    ("race_burst", {"approval_ref": "offline", "rounds": 1,
                    "requests": [{"path": "/own", "method": "PATCH"}]}, "PATCH"),
])
def test_final_method_is_gated_before_any_send(policy, tool, args, blocked):
    policy.program_policy_file.write_text(json.dumps({"blocked_http_methods": [blocked]}))
    calls = []
    out = runner(policy, lambda *a: calls.append(a) or response()).execute(manifest(tool, args))
    assert out["terminal"] == "abort"
    assert "blocked_http_method" in out["terminal_error"]
    assert calls == [] and out["requests_sent"] == 0


@pytest.mark.parametrize("headers,allowed", [
    ({}, False), ({"X-Wrong": "researcher"}, False),
    ({"X-Research": "wrong"}, False), ({"x-research": "researcher"}, True),
])
def test_required_header_checks_final_name_and_value(policy, headers, allowed):
    policy.program_policy_file.write_text(json.dumps({
        "required_request_headers": {"X-Research": "researcher"}}))
    task = manifest()
    task["steps"][0]["identity_refs"] = ["own-session"]
    calls = []
    out = runner(policy, lambda *a: calls.append(a) or response(),
                 identities={"own-session": headers}).execute(task)
    assert out["success"] is allowed
    assert len(calls) == int(allowed)
    if not allowed:
        assert "blocked_missing_headers" in out["terminal_error"]


def test_out_of_scope_relogin_is_never_sent(policy):
    calls = []
    def send(method, url, headers, body, timeout):
        calls.append(url)
        return response(401) if url.endswith("/own") else response(200, '{"token":"mock"}')
    out = runner(policy, send, login_recipe={
        "url": "https://outside-scope.test/login", "token_path": "token"}).execute(manifest())
    assert out["terminal"] == "abort"
    assert "blocked_scope" in out["terminal_error"]
    assert calls == ["https://security-review.test/own"]
    assert out["requests_sent"] == 1


@pytest.mark.parametrize("budget,step_budget,expected_calls,success", [
    (2, None, 2, False), (3, None, 3, True), (5, 1, 1, False),
])
def test_login_and_retry_share_wire_budget(policy, budget, step_budget, expected_calls, success):
    calls = []
    def send(method, url, headers, body, timeout):
        calls.append(url)
        if url.endswith("/login"):
            return response(200, '{"token":"mock"}')
        return response(200 if headers.get("Authorization") == "Bearer mock" else 401)
    task = manifest(budget=budget)
    if step_budget:
        task["steps"][0]["max_requests"] = step_budget
    out = runner(policy, send, login_recipe={
        "url": "https://security-review.test/login", "token_path": "token"}).execute(task)
    assert out["success"] is success
    assert len(calls) == out["requests_sent"] == expected_calls
    if not success:
        assert "bütçe" in out["terminal_error"]


def test_partial_batch_preserves_actual_request_count(policy):
    calls = []
    task = manifest("batch_probe", {"requests": [
        {"path": "/own"}, {"url": "https://outside-scope.test/"}]})
    out = runner(policy, lambda *a: calls.append(a) or response(), sleeper=lambda _: None).execute(task)
    assert out["terminal"] == "abort"
    assert len(calls) == out["requests_sent"] == 1


def test_retry_is_reauthorized_after_grant_revocation(policy):
    calls = []
    def send(*args):
        calls.append(args)
        for grant in policy.list_approvals():
            policy.revoke_approval(grant["id"])
        return response(401)
    out = runner(policy, send, login_provider=lambda: {
        "headers": {"Authorization": "Bearer mock"}}).execute(manifest())
    assert out["terminal"] == "abort"
    assert "blocked_approval_required" in out["terminal_error"]
    assert len(calls) == out["requests_sent"] == 1


@pytest.fixture
def run_files(tmp_path, policy):
    workdir = tmp_path / "run"
    workdir.mkdir()
    ledger = hypotheses.init_ledger("https://security-review.test", vectors=("csrf",))
    hypotheses.save_ledger(workdir, ledger)
    specs = workdir / "specs.json"
    specs.write_text(brain.dump_specs(brain.build_plan(
        ledger["target"], str(workdir), phases=("access",))))
    return workdir, specs, ledger


def artifact(target="https://security-review.test", kind="csrf", verdict="CONFIRMED"):
    import uuid
    return evidence.persist_result({
        "schema_version": evidence.SCHEMA_VERSION, "validation_id": str(uuid.uuid4()),
        "target": target, "vuln_type": kind, "verdict": verdict,
        "oracle": "offline-test", "evidence": {"marker": "synthetic"}},
        str(Path(os.environ["CCO_HOME"]) / "validations"))


def close(workdir, specs):
    return brain.main(["check", "--spec", str(specs), "--workdir", str(workdir), "--closure"])


def test_cli_cannot_mark_confirmed_without_validation(run_files):
    workdir, _, _ = run_files
    assert brain.main(["hypotheses", "mark", "--workdir", str(workdir),
        "--vector", "csrf", "--status", "confirmed"]) == 2
    assert hypotheses.load_ledger(workdir)["hypotheses"][0]["status"] == "untried"


def test_closure_revalidates_directly_edited_confirmed_status(run_files):
    workdir, specs, ledger = run_files
    hypotheses.mark(ledger, "csrf", "confirmed")
    hypotheses.save_ledger(workdir, ledger)
    assert close(workdir, specs) == 2
    assert not (workdir / "closure.json").exists()


@pytest.mark.parametrize("target,kind,verdict", [
    ("https://other.test", "csrf", "CONFIRMED"),
    ("https://security-review.test", "sql_injection", "CONFIRMED"),
    ("https://security-review.test", "csrf", "UNCONFIRMED"),
])
def test_cli_rejects_wrong_target_type_and_verdict(run_files, target, kind, verdict):
    workdir, _, _ = run_files
    record = artifact(target, kind, verdict)
    assert brain.main(["hypotheses", "mark", "--workdir", str(workdir),
        "--vector", "csrf", "--status", "confirmed", "--validation-id", record["validation_id"]]) == 2


def confirm(workdir):
    record = artifact()
    assert brain.main(["hypotheses", "mark", "--workdir", str(workdir),
        "--vector", "csrf", "--status", "confirmed", "--validation-id", record["validation_id"]]) == 0
    return record


def test_valid_confirmation_is_persisted_and_sealed(run_files):
    workdir, specs, _ = run_files
    record = confirm(workdir)
    entry = hypotheses.load_ledger(workdir)["hypotheses"][0]
    assert entry["validation_id"] == record["validation_id"]
    assert close(workdir, specs) == 0
    assert brain.main(["closure", "verify", "--workdir", str(workdir)]) == 0


@pytest.mark.parametrize("change", ["artifact_deleted", "artifact_tampered", "ledger_changed", "policy_changed", "scope_changed"])
def test_closure_verification_detects_evidence_or_binding_drift(run_files, policy, change):
    workdir, specs, _ = run_files
    record = confirm(workdir)
    assert close(workdir, specs) == 0
    if change == "artifact_deleted":
        Path(record["artifact"]["path"]).unlink()
    elif change == "artifact_tampered":
        changed = copy.deepcopy(record)
        changed["evidence"] = {"marker": "changed"}
        Path(record["artifact"]["path"]).write_text(json.dumps(changed))
    elif change == "policy_changed":
        policy.program_policy_file.write_text('{"blocked_http_methods":["PATCH"]}')
    elif change == "scope_changed":
        policy.scope_file.write_text('{"in_scope":[{"asset":"other.test"}]}')
    else:
        ledger = hypotheses.load_ledger(workdir)
        ledger["hypotheses"][0]["note"] = "changed after closure"
        hypotheses.save_ledger(workdir, ledger)
    assert brain.main(["closure", "verify", "--workdir", str(workdir)]) == 2


def test_finding_type_in_summary_cannot_override_vector_binding(run_files):
    _, _, ledger = run_files
    record = artifact(kind="sql_injection")
    summary = {"target": ledger["target"], "findings": [
        {"type": "sql_injection", "validation_id": record["validation_id"]}]}
    valid, _ = brain._validator_confirmation(summary, "csrf", ledger)
    assert valid is False


def test_boolean_claim_cannot_confirm_without_a_real_artifact(run_files):
    _, _, ledger = run_files
    entry = brain.ingest_access_summary(ledger, {"vector": "csrf", "status": "done",
        "findings": [{"band": "CONFIRMED"}]}, validator_verified=True)
    assert entry["status"] == "blocked"


def test_ingestion_keeps_the_verified_reference_not_an_untrusted_first_id(run_files):
    _, _, ledger = run_files
    record = artifact()
    summary = {"vector": "csrf", "status": "done", "findings": [
        {"band": "CONFIRMED", "validation_id": "missing"},
        {"band": "CONFIRMED", "validation_id": record["validation_id"]}]}
    entry = brain.ingest_access_summary(ledger, copy.deepcopy(summary))
    assert entry["status"] == "confirmed"
    assert entry["validation_id"] == record["validation_id"]


def test_closure_excludes_unrelated_artifacts(run_files):
    workdir, specs, _ = run_files
    own = confirm(workdir)
    artifact(target="https://unrelated.test")
    assert close(workdir, specs) == 0
    payload = json.loads((workdir / "closure.json").read_text())["payload"]
    assert [item["validation_id"] for item in payload["validations"]] == [own["validation_id"]]


def test_old_signed_closure_needs_revalidation(run_files):
    workdir, specs, _ = run_files
    confirm(workdir)
    assert close(workdir, specs) == 0
    payload = json.loads((workdir / "closure.json").read_text())["payload"]
    payload["schema"] = "closure/1"
    (workdir / "closure.json").write_text(json.dumps(brain.attempts_mod.sign_payload(payload)))
    assert brain.main(["closure", "verify", "--workdir", str(workdir)]) == 2


def test_parallel_wire_reservations_never_exceed_budget():
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from chain_transport import ChainAbort, ChainTransport

    calls = []
    lock = threading.Lock()
    def send(*args):
        with lock:
            calls.append(args)
        return response()
    transport = ChainTransport(send, lambda *a: (True, ""))
    transport.begin({"max_requests": 3, "max_duration_seconds": 30})
    transport.begin_step({"tool": "race_burst"})
    def fire(_):
        try:
            transport.request("GET", "https://security-review.test/own", {}, "", 5)
        except ChainAbort:
            return False
        return True
    with ThreadPoolExecutor(max_workers=8) as pool:
        allowed = list(pool.map(fire, range(8)))
    assert sum(allowed) == len(calls) == transport.finish()["sent"] == 3


def test_policy_latency_cannot_send_after_step_deadline(monkeypatch):
    from types import SimpleNamespace
    import chain_transport

    now = [0]
    monkeypatch.setattr(chain_transport, "time", SimpleNamespace(monotonic=lambda: now[0]))
    def gate(*args):
        now[0] = 2
        return True, ""
    calls = []
    transport = chain_transport.ChainTransport(lambda *a: calls.append(a), gate)
    transport.begin({"max_requests": 5, "max_duration_seconds": 30})
    transport.begin_step({"tool": "http_get", "max_duration_seconds": 1})
    with pytest.raises(chain_transport.ChainAbort, match="süre bütçesi"):
        transport.request("GET", "https://security-review.test/own", {}, "", 5)
    assert calls == [] and transport.finish()["sent"] == 0


def test_login_recipe_headers_are_subject_to_the_same_policy(policy):
    policy.program_policy_file.write_text(json.dumps({
        "required_request_headers": {"X-Research": "researcher"}}))
    calls = []
    def send(method, url, headers, body, timeout):
        calls.append((url, headers))
        if url.endswith("/login"):
            return response(200, '{"token":"mock"}')
        return response(200 if headers.get("Authorization") == "Bearer mock" else 401)
    task = manifest()
    task["steps"][0]["identity_refs"] = ["research"]
    out = runner(policy, send, identities={"research": {"X-Research": "researcher"}},
        login_recipe={"url": "https://security-review.test/login", "token_path": "token",
                      "headers": {"x-research": "researcher"}}).execute(task)
    assert out["success"] is True
    assert len(calls) == out["requests_sent"] == 3


def test_goto_cannot_reset_a_steps_request_budget(policy):
    calls = []
    task = manifest(budget=5)
    task["steps"][0].update(max_requests=1, on_success="probe")
    out = runner(policy, lambda *a: calls.append(a) or response()).execute(task)
    assert out["terminal"] == "abort" and "adım istek bütçesi" in out["terminal_error"]
    assert len(calls) == out["requests_sent"] == 1


def test_manifest_dispatch_is_not_mistaken_for_a_wire_request(policy):
    policy.program_policy_file.write_text(json.dumps({
        "required_request_headers": {"X-Research": "researcher"}}))
    decision = policy.validate_tool_invocation("chain_runner_execute", {
        "url": "https://security-review.test/own"})
    assert decision["allowed"] is True


@pytest.mark.parametrize("vector,kind,expected", [
    ("authz-idor", "BOLA", True), ("authz-idor", "BFLA", True),
    ("authn-session", "Open Redirect", True),
    ("authn-session", "Token Differential (Opaque Carrier)", True),
    ("authn-session", "Token Round-Trip (Application Flow)", True),
    ("file-access", "Unrestricted File Upload", True), ("file-access", "XXE", True),
    # Persistence alone does not prove XSS, even with a signed canary artifact.
    ("xss-stored", "Second-Order (Stored)", False),
])
def test_related_validator_types_keep_their_vector_binding(run_files, vector, kind, expected):
    _, _, ledger = run_files
    record = artifact(kind=kind)
    valid, _ = brain._validator_confirmation({"validation_id": record["validation_id"]}, vector, ledger)
    assert valid is expected


def test_empty_findings_closure_still_binds_active_policy(run_files, policy):
    workdir, specs, ledger = run_files
    hypotheses.mark(ledger, "csrf", "not_applicable", note="auth:not-required: no form surface")
    hypotheses.save_ledger(workdir, ledger)
    assert close(workdir, specs) == 0
    policy.program_policy_file.write_text('{"blocked_http_methods":["PATCH"]}')
    assert brain.main(["closure", "verify", "--workdir", str(workdir)]) == 2
