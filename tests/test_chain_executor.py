"""Chain executor testleri (offline — sahte gate/sender + gerçek policy engine)."""

import importlib.util
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from chain_executor import ChainExecutor


def test_expired_shared_session_is_not_reused(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    validator_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "mcp-servers", "mcp-validator")
    sys.path.insert(0, validator_dir)
    from cco_validator_core.egress import save_shared_session
    from chain_executor import ChainAbort
    save_shared_session("http://lab.test/", cookie="sid=synthetic", state="expired")
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=_sender_factory({}))
    with pytest.raises(ChainAbort, match="expired or stale"):
        runner._headers_for({}, "http://lab.test/")
    save_shared_session("http://lab.test/", cookie="sid=renewed", state="active")
    assert runner._headers_for({}, "http://lab.test/")["Cookie"] == "sid=renewed"


def _load_policy_engine():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts", "policy_engine.py",
    )
    spec = importlib.util.spec_from_file_location("policy_engine_chain_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _AllowGate:
    def __init__(self, seen):
        self.seen = seen

    def validate_tool_invocation(self, tool_name, args=None, **kwargs):
        self.seen.append((tool_name, (args or {}).get("url")))
        return {"allowed": True}


class _DenyGate:
    def validate_tool_invocation(self, tool_name, args=None, **kwargs):
        return {"allowed": False, "reason": "kapsam dışı"}


def _sender_factory(routes):
    def sender(method, url, headers, body, timeout):
        if url not in routes:
            return {"ok": False, "status": None, "len": 0, "text": "",
                    "headers": {}, "location": "", "error": "bilinmeyen rota"}
        status, text = routes[url]
        return {"ok": True, "status": status, "len": len(text), "text": text,
                "headers": {}, "location": "", "error": None}

    return sender


def _manifest(steps):
    return {
        "schema_version": "action-manifest/1.0",
        "objective": "test-chain",
        "target_ref": "scope-asset-1",
        "risk": "active_read_only",
        "budget": {"max_requests": 10, "max_duration_seconds": 30},
        "identity_refs": ["owner", "attacker"],
        "steps": steps,
    }


def test_bola_chain_succeeds_with_differential_oracle():
    seen = []
    routes = {
        "http://lab.test/order/9": (200, "order of alice@example.com"),
    }
    manifest = _manifest([
        {"id": "fetch-owner", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "fetch-attacker", "on_failure": "abort"},
        {"id": "fetch-attacker", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "differential_content", "owner_step": "fetch-owner",
                    "attacker_step": "fetch-attacker", "marker": "alice@example.com"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(
        policy_engine=_AllowGate(seen),
        sender=_sender_factory(routes),
        identities={"owner": {"Cookie": "o=1"}, "attacker": {"Cookie": "a=2"}},
        target_bases={"scope-asset-1": "http://lab.test"},
    )
    out = runner.execute(manifest)
    assert out["success"] is True
    assert out["terminal"] == "succeed"
    assert out["requests_sent"] == 2
    assert [s["id"] for s in out["steps_executed"]] == ["fetch-owner", "fetch-attacker"]
    assert all(s["oracle_passed"] for s in out["steps_executed"])
    assert seen[0][0] == "chain_runner_http_get"
    assert "fulltext" not in json.dumps(out["steps_executed"])


def test_gate_deny_aborts_chain():
    runner = ChainExecutor(
        policy_engine=_DenyGate(),
        sender=_sender_factory({}),
        target_bases={"scope-asset-1": "http://lab.test"},
    )
    manifest = _manifest([
        {"id": "only", "tool": "http_get", "args": {"path": "/"},
         "expect": {"oracle": "status_code"}, "on_success": "succeed", "on_failure": "fail"},
    ])
    out = runner.execute(manifest)
    assert out["success"] is False
    assert out["terminal"] == "abort"
    assert "gate reddetti" in out["terminal_error"]
    assert out["requests_sent"] == 0


def test_oracle_miss_follows_on_failure_branch():
    seen = []
    routes = {"http://lab.test/order/9": (200, "order of alice@example.com")}
    manifest = _manifest([
        {"id": "fetch-owner", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "fetch-attacker", "on_failure": "abort"},
        {"id": "fetch-attacker", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "differential_content", "owner_step": "fetch-owner",
                    "attacker_step": "fetch-attacker", "marker": "mallory@x.test"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(
        policy_engine=_AllowGate(seen), sender=_sender_factory(routes),
        target_bases={"scope-asset-1": "http://lab.test"},
    )
    out = runner.execute(manifest)
    assert out["success"] is False
    assert out["terminal"] == "fail"
    assert out["steps_executed"][-1]["oracle_passed"] is False


def test_request_budget_aborts():
    routes = {"http://lab.test/": (200, "ok")}
    manifest = _manifest([
        {"id": "a", "tool": "http_get", "args": {"path": "/"},
         "expect": {"oracle": "status_code"}, "on_success": "b", "on_failure": "fail"},
        {"id": "b", "tool": "http_get", "args": {"path": "/"},
         "expect": {"oracle": "status_code"}, "on_success": "succeed", "on_failure": "fail"},
    ])
    manifest["budget"]["max_requests"] = 1
    runner = ChainExecutor(
        policy_engine=_AllowGate([]), sender=_sender_factory(routes),
        target_bases={"scope-asset-1": "http://lab.test"},
    )
    out = runner.execute(manifest)
    assert out["terminal"] == "abort"
    assert "bütçe" in out["terminal_error"]
    assert out["requests_sent"] == 1


def test_oob_poll_matches_token():
    manifest = _manifest([
        {"id": "poll", "tool": "oob_poll",
         "args": {"token": "abc123", "callbacks_text": "dns abc123.oast hit"},
         "expect": {"oracle": "oob_callback"}, "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]))
    out = runner.execute(manifest)
    assert out["success"] is True
    assert out["requests_sent"] == 0


def test_unknown_identity_aborts():
    manifest = _manifest([
        {"id": "a", "tool": "http_get", "args": {"url": "http://lab.test/"},
         "identity_refs": ["ghost"],
         "expect": {"oracle": "status_code"}, "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({"http://lab.test/": (200, "ok")}))
    out = runner.execute(manifest)
    assert out["terminal"] == "abort"
    assert "identity_ref" in out["terminal_error"]


def test_plan_resolves_without_network():
    def boom(*args, **kwargs):
        raise AssertionError("dry-run ağa dokunmamalı")

    manifest = _manifest([
        {"id": "a", "tool": "http_get", "args": {"path": "/x"},
         "expect": {"oracle": "status_code"}, "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=None, sender=boom,
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.plan(manifest)
    assert out["valid"] is True
    assert out["plan"][0]["url"] == "http://lab.test/x"


def test_step_reference_templating():
    seen_urls = []

    def sender(method, url, headers, body, timeout):
        seen_urls.append(url)
        return {"ok": True, "status": 200, "len": 2, "text": "ok",
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "first", "tool": "http_get", "args": {"path": "/a"},
         "expect": {"oracle": "status_code"}, "on_success": "second", "on_failure": "fail"},
        {"id": "second", "tool": "http_post",
         "args": {"url": "http://lab.test/echo", "body": {"prev": "{{steps.first.status}}"}},
         "expect": {"oracle": "status_code"}, "on_success": "succeed", "on_failure": "fail"},
    ])
    bodies = []
    orig = sender

    def capture(method, url, headers, body, timeout):
        bodies.append(body)
        return orig(method, url, headers, body, timeout)

    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=capture,
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    assert json.loads(bodies[-1]) == {"prev": "200"}


def test_real_policy_engine_gates_chain(tmp_path):
    module = _load_policy_engine()
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "scope.json").write_text(json.dumps({
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "lab.test", "type": "web"}],
    }))
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("chain_runner_*", "lab.test", ttl_seconds=600, reason="test")

    routes = {"http://lab.test/order/9": (200, "order of alice@example.com")}
    manifest = _manifest([
        {"id": "fetch-owner", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "fetch-attacker", "on_failure": "abort"},
        {"id": "fetch-attacker", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "differential_content", "owner_step": "fetch-owner",
                    "attacker_step": "fetch-attacker", "marker": "alice@example.com"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(
        policy_engine=engine, sender=_sender_factory(routes),
        target_bases={"scope-asset-1": "http://lab.test"},
    )
    out = runner.execute(manifest)
    assert out["success"] is True

    evil = _manifest([
        {"id": "evil", "tool": "http_get", "args": {"url": "http://evil.example/steal"},
         "expect": {"oracle": "status_code"}, "on_success": "succeed", "on_failure": "fail"},
    ])
    out = runner.execute(evil)
    assert out["success"] is False
    assert out["terminal"] == "abort"
    assert "gate reddetti" in out["terminal_error"]
    assert out["requests_sent"] == 0


def test_validate_and_store_close_the_loop_with_fakes():
    seen = []

    def fake_validate(payload):
        seen.append(("validate", payload["verdict"], payload["oracle"]))
        return {"verdict": payload["verdict"], "validation_id": "v123",
                "artifact_path": "/tmp/cco_pytest_artifact.json", "oracle": payload["oracle"]}

    def fake_store(payload):
        seen.append(("store", payload["type"], payload["validation_artifact_path"]))
        return {"finding_id": 7, "validation_state": "verified",
                "validation_verdict": "CONFIRMED", "reportable": True}

    routes = {"http://lab.test/order/9": (200, "order of alice@example.com")}
    manifest = _manifest([
        {"id": "fetch-owner", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "fetch-attacker", "on_failure": "abort"},
        {"id": "fetch-attacker", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "confirm", "on_failure": "abort"},
        {"id": "confirm", "tool": "validate",
         "args": {"vuln_type": "IDOR", "target_url": "http://lab.test/order/9",
                  "oracle": "differential_content",
                  "oracle_args": {"owner_step": "fetch-owner", "attacker_step": "fetch-attacker",
                                  "marker": "alice@example.com"}},
         "expect": {"oracle": "validator_verdict", "verdict": "CONFIRMED"},
         "on_success": "persist", "on_failure": "fail"},
        {"id": "persist", "tool": "store_finding",
         "args": {"target": "lab.test", "type": "idor", "severity": "high",
                  "description": "chain-proven IDOR", "validation_step": "confirm"},
         "expect": {"oracle": "validator_verdict", "verdict": "CONFIRMED"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(
        policy_engine=_AllowGate([]), sender=_sender_factory(routes),
        target_bases={"scope-asset-1": "http://lab.test"},
        validate_provider=fake_validate, finding_store=fake_store,
    )
    out = runner.execute(manifest)
    assert out["success"] is True
    assert [s["id"] for s in out["steps_executed"]] == [
        "fetch-owner", "fetch-attacker", "confirm", "persist"]
    assert ("validate", "CONFIRMED", "differential_content") in seen
    assert ("store", "idor", "/tmp/cco_pytest_artifact.json") in seen
    assert out["steps_executed"][-1]["oracle_detail"]["reportable"] is True
    assert out["requests_sent"] == 2


def test_default_providers_produce_reportable_finding(tmp_path, monkeypatch):
    import chain_executor as executor_mod

    cco = tmp_path / "cco-default"
    cco.mkdir()
    monkeypatch.setenv("CCO_HOME", str(cco))
    monkeypatch.setattr(executor_mod, "_SERVER_MODULES", {})

    routes = {"http://chain.test/order/9": (200, "order of alice@example.com")}
    manifest = _manifest([
        {"id": "fetch-owner", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "fetch-attacker", "on_failure": "abort"},
        {"id": "fetch-attacker", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "confirm", "on_failure": "abort"},
        {"id": "confirm", "tool": "validate",
         "args": {"vuln_type": "IDOR", "target_url": "http://chain.test/order/9",
                  "oracle": "differential_content",
                  "oracle_args": {"owner_step": "fetch-owner", "attacker_step": "fetch-attacker",
                                  "marker": "alice@example.com"}},
         "expect": {"oracle": "validator_verdict", "verdict": "CONFIRMED"},
         "on_success": "persist", "on_failure": "fail"},
        {"id": "persist", "tool": "store_finding",
         "args": {"target": "chain.test", "type": "idor", "severity": "high",
                  "description": "chain-proven IDOR", "validation_step": "confirm"},
         "expect": {"oracle": "validator_verdict", "verdict": "CONFIRMED"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(
        policy_engine=_AllowGate([]), sender=_sender_factory(routes),
        target_bases={"scope-asset-1": "http://chain.test"},
    )
    out = runner.execute(manifest)
    assert out["success"] is True
    validate_rec = [s for s in out["steps_executed"] if s["id"] == "confirm"][0]
    assert validate_rec["result"]["validation_id"]
    assert os.path.exists(validate_rec["result"]["artifact_path"])
    store_rec = [s for s in out["steps_executed"] if s["id"] == "persist"][0]
    assert store_rec["result"]["finding_id"]
    assert store_rec["result"]["reportable"] is True


def test_execute_and_complete_closes_runtime_task(tmp_path):
    import sqlite3

    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
    import campaign_runtime as runtime_mod
    import chain_executor as executor_mod

    cco = tmp_path / "cco-runtime"
    codex = tmp_path / ".codex"
    codex.mkdir()
    scope_file = codex / "scope.json"
    scope_file.write_text(json.dumps({
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "lab.test", "type": "web"}],
    }))
    runtime = runtime_mod.CampaignRuntime(cco_home=str(cco))
    policy = _load_policy_engine().PolicyEngine(cco_home=str(cco), repo_root=str(tmp_path))
    policy.grant_approval("chain_runner_*", "lab.test", ttl_seconds=600, reason="test")
    campaign_id = runtime.create_campaign("chain-test", scope_file=str(scope_file))
    runtime.set_campaign_status(campaign_id, "active")
    task_id = runtime.enqueue_task(
        campaign_id, "chain", tool_name="chain_runner_http_get",
        args={"url": "http://lab.test/order/9"}, request_cost=2,
    )
    claimed = runtime.claim_next_task("worker-1", campaign_id=campaign_id)
    assert claimed and claimed["id"] == task_id

    routes = {"http://lab.test/order/9": (200, "ok")}
    manifest = _manifest([
        {"id": "probe", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = executor_mod.ChainExecutor(
        policy_engine=policy, sender=_sender_factory(routes),
        target_bases={"scope-asset-1": "http://lab.test"},
    )
    out = executor_mod.execute_and_complete(
        runtime, task_id, "worker-1", claimed["lease_token"], manifest, executor=runner)
    assert out["success"] is True

    conn = sqlite3.connect(runtime.db_path)
    row = conn.execute("SELECT status, result_json FROM tasks WHERE id=?", (task_id,)).fetchone()
    conn.close()
    assert row[0] == "done"
    result = json.loads(row[1])
    assert result["manifest_hash"] == out["manifest_hash"]
    assert result["success"] is True
    assert result["requests_sent"] == 1


def test_session_guardian_relogins_and_retries_once():
    calls = {"n": 0, "logins": 0}

    def sender(method, url, headers, body, timeout):
        calls["n"] += 1
        if headers.get("Authorization") == "Bearer fresh":
            return {"ok": True, "status": 200, "len": 2, "text": "ok",
                    "headers": {}, "location": "", "error": None}
        return {"ok": False if False else True, "status": 401, "len": 0, "text": "expired",
                "headers": {}, "location": "", "error": None}

    def login_provider():
        calls["logins"] += 1
        return {"headers": {"Authorization": "Bearer fresh"}}

    manifest = _manifest([
        {"id": "probe", "tool": "http_get", "args": {"url": "http://lab.test/me"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender,
                           login_provider=login_provider)
    out = runner.execute(manifest)
    assert out["success"] is True
    assert calls == {"n": 2, "logins": 1}
    assert out["requests_sent"] == 2
    assert out["steps_executed"][0]["result"]["relogins_used"] == 1


def test_session_guardian_gives_up_after_retry():
    def sender(method, url, headers, body, timeout):
        return {"ok": True, "status": 401, "len": 0, "text": "expired",
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "probe", "tool": "http_get", "args": {"url": "http://lab.test/me"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender,
                           login_provider=lambda: {"headers": {"Authorization": "Bearer x"}})
    out = runner.execute(manifest)
    assert out["success"] is False
    assert out["terminal"] == "fail"
    assert out["requests_sent"] == 2


def test_session_guardian_inert_without_provider():
    seen = []

    def sender(method, url, headers, body, timeout):
        seen.append(dict(headers))
        return {"ok": True, "status": 401, "len": 0, "text": "expired",
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "probe", "tool": "http_get", "args": {"url": "http://lab.test/me"},
         "expect": {"oracle": "status_code", "status": 401},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender)
    out = runner.execute(manifest)
    assert out["success"] is True
    assert len(seen) == 1


def test_mailbox_poll_extracts_otp():
    seen = []
    inbox = {"items": [
        {"To": ["other@x.test"], "Content": {"Body": "hello"}},
        {"To": ["victim@lab.test"], "Content": {"Body": "Kodunuz: 482910. 5 dk geçerli."}},
    ]}

    def sender(method, url, headers, body, timeout):
        seen.append(url)
        return {"ok": True, "status": 200, "len": 9, "text": json.dumps(inbox),
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "otp", "tool": "mailbox_poll",
         "args": {"url": "http://mail.lab.test/api/v2/messages", "email": "victim@lab.test"},
         "expect": {"oracle": "marker_present", "marker": "482910"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender)
    out = runner.execute(manifest)
    assert out["success"] is True
    rec = out["steps_executed"][0]
    assert rec["result"]["otp"] == "482910"
    assert rec["result"]["found"] is True
    assert seen == ["http://mail.lab.test/api/v2/messages"]


def test_mailbox_poll_miss_goes_to_failure_branch():
    inbox = {"items": []}

    def sender(method, url, headers, body, timeout):
        return {"ok": True, "status": 200, "len": 2, "text": json.dumps(inbox),
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "otp", "tool": "mailbox_poll",
         "args": {"url": "http://mail.lab.test/api/v2/messages", "email": "nobody@lab.test"},
         "expect": {"oracle": "marker_present", "marker": "482910"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender)
    out = runner.execute(manifest)
    assert out["terminal"] == "fail"
    assert out["steps_executed"][0]["result"]["found"] is False


def test_schema_reflection_repairs_400_once():
    bodies = []

    def sender(method, url, headers, body, timeout):
        bodies.append(json.loads(body))
        if "session_id" in bodies[-1]:
            return {"ok": True, "status": 200, "len": 2, "text": "ok",
                    "headers": {}, "location": "", "error": None}
        return {"ok": True, "status": 400, "len": 7, "text": "missing",
                "headers": {}, "location": "", "error": None}

    spec = 'POST /ask {"message": "hi", "session_id": "abc"} // chatbot spec'
    manifest = _manifest([
        {"id": "ask", "tool": "http_post",
         "args": {"url": "http://lab.test/ask", "body": {"message": "hi"},
                  "reflect": {"spec": spec, "endpoint": "/ask"}},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender)
    out = runner.execute(manifest)
    assert out["success"] is True
    assert out["requests_sent"] == 2
    assert bodies[0] == {"message": "hi"}
    assert bodies[1] == {"message": "hi", "session_id": ""}
    assert out["steps_executed"][0]["result"]["reflected_keys"] == ["session_id"]


def test_schema_reflection_without_spec_does_not_retry():
    calls = []

    def sender(method, url, headers, body, timeout):
        calls.append(body)
        return {"ok": True, "status": 400, "len": 7, "text": "missing",
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "ask", "tool": "http_post",
         "args": {"url": "http://lab.test/ask", "body": {"message": "hi"}},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender)
    out = runner.execute(manifest)
    assert out["terminal"] == "fail"
    assert len(calls) == 1


def test_batch_probe_runs_bounded_rate_limited():
    seen = []
    sleeps = []
    routes = {
        "http://lab.test/a": (200, "alpha marker-x"),
        "http://lab.test/b": (404, "missing"),
        "http://lab.test/c": (200, "gamma"),
    }

    def sender(method, url, headers, body, timeout):
        seen.append(url)
        status, text = routes[url]
        return {"ok": True, "status": status, "len": len(text), "text": text,
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "sweep", "tool": "batch_probe",
         "args": {"max_rps": 4, "requests": [
             {"path": "/a"}, {"path": "/b"}, {"path": "/c"}]},
         "expect": {"oracle": "marker_present", "marker": "marker-x"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender,
                           target_bases={"scope-asset-1": "http://lab.test"},
                           sleeper=sleeps.append)
    out = runner.execute(manifest)
    assert out["success"] is True
    assert out["requests_sent"] == 3
    assert seen == ["http://lab.test/a", "http://lab.test/b", "http://lab.test/c"]
    assert sleeps == [0.25, 0.25]
    rec = out["steps_executed"][0]
    assert rec["result"]["count"] == 3
    assert rec["oracle_detail"]["matched_urls"] == ["http://lab.test/a"]
    assert len(rec["result"]["items"][0]["excerpt"]) <= 200


def test_batch_probe_gate_deny_and_method_cap():
    manifest = _manifest([
        {"id": "sweep", "tool": "batch_probe",
         "args": {"requests": [{"method": "POST", "path": "/a"}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({"http://lab.test/a": (200, "ok")}),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["terminal"] == "abort"
    assert "yazan metod" in out["terminal_error"]

    manifest2 = _manifest([
        {"id": "sweep", "tool": "batch_probe",
         "args": {"requests": [{"url": "http://evil.example/"}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner2 = ChainExecutor(policy_engine=_DenyGate(),
                            sender=_sender_factory({}),
                            target_bases={"scope-asset-1": "http://lab.test"})
    out2 = runner2.execute(manifest2)
    assert out2["terminal"] == "abort"
    assert "gate reddetti" in out2["terminal_error"]
    assert out2["requests_sent"] == 0


def test_batch_probe_budget_precheck():
    manifest = _manifest([
        {"id": "sweep", "tool": "batch_probe",
         "args": {"requests": [{"path": "/a"}, {"path": "/b"}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    manifest["budget"]["max_requests"] = 1
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({}),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["terminal"] == "abort"
    assert "bütçe" in out["terminal_error"]
    assert out["requests_sent"] == 0


def test_cli_plan_lists_resolved_flow(tmp_path):
    import subprocess

    manifest = _manifest([
        {"id": "probe", "tool": "http_get", "args": {"path": "/order/9"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    manifest_file = tmp_path / "m.json"
    manifest_file.write_text(json.dumps(manifest))
    bases_file = tmp_path / "bases.json"
    bases_file.write_text(json.dumps({"scope-asset-1": "http://lab.test"}))
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, CCO_HOME=str(tmp_path / "cco-cli"))
    proc = subprocess.run(
        [sys.executable, os.path.join(repo_root, "scripts", "chain_executor.py"),
         "plan", str(manifest_file), "--target-bases", str(bases_file)],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["valid"] is True
    assert out["plan"][0]["url"] == "http://lab.test/order/9"


def test_cli_run_rejects_invalid_manifest(tmp_path):
    import subprocess

    manifest = _manifest([])
    manifest_file = tmp_path / "bad.json"
    manifest_file.write_text(json.dumps(manifest))
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, CCO_HOME=str(tmp_path / "cco-cli-bad"))
    proc = subprocess.run(
        [sys.executable, os.path.join(repo_root, "scripts", "chain_executor.py"),
         "run", str(manifest_file)],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    assert out["success"] is False
    assert out["terminal"] == "invalid_manifest"


def test_race_burst_releases_parallel_and_counts_rounds():
    import threading
    import time

    lock = threading.Lock()
    arrival = []

    def sender(method, url, headers, body, timeout):
        with lock:
            arrival.append(time.monotonic())
        text = "admin panel" if url.endswith("/admin") else "login page"
        return {"ok": True, "status": 200, "len": len(text), "text": text,
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "race", "tool": "race_burst",
         "args": {"approval_ref": "lab-race-001", "rounds": 2, "concurrency": 4,
                  "requests": [{"path": "/admin"}, {"path": "/login"}]},
         "expect": {"oracle": "marker_present", "marker": "admin panel"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender,
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    assert out["requests_sent"] == 4
    rec = out["steps_executed"][0]
    assert rec["result"]["round_count"] == 2
    assert rec["result"]["approval_ref"] == "lab-race-001"
    assert len(arrival) == 4
    assert max(arrival) - min(arrival) < 5.0


def test_race_burst_requires_approval_ref():
    manifest = _manifest([
        {"id": "race", "tool": "race_burst",
         "args": {"rounds": 1, "requests": [{"path": "/a"}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({"http://lab.test/a": (200, "ok")}),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["terminal"] == "abort"
    assert "approval_ref" in out["terminal_error"]
    assert out["requests_sent"] == 0


def test_race_burst_method_and_budget_caps():
    base = {"approval_ref": "lab-race-002", "requests": [{"method": "DELETE", "path": "/a"}]}
    manifest = _manifest([
        {"id": "race", "tool": "race_burst", "args": dict(base),
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({"http://lab.test/a": (200, "ok")}),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["terminal"] == "abort"
    assert "metoda kapalı" in out["terminal_error"]

    # PUT and PATCH are allowed in race_burst when approval_ref is present
    manifest_put = _manifest([
        {"id": "race-put", "tool": "race_burst",
         "args": {"approval_ref": "lab-race-put", "rounds": 1,
                  "requests": [{"method": "PUT", "path": "/a"}, {"method": "PATCH", "path": "/a"}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    out_put = runner.execute(manifest_put)
    assert out_put["success"] is True

    manifest2 = _manifest([
        {"id": "race", "tool": "race_burst",
         "args": {"approval_ref": "lab-race-003", "rounds": 99,
                  "requests": [{"path": "/a"}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    out2 = runner.execute(manifest2)
    assert out2["terminal"] == "abort"
    assert "rounds" in out2["terminal_error"]


def test_http_get_supports_head_and_options():
    seen_methods = []

    def sender(method, url, headers, body, timeout):
        seen_methods.append(method)
        return {"ok": True, "status": 200, "len": 0, "text": "",
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "h", "tool": "http_get", "args": {"path": "/a", "method": "HEAD"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "o", "on_failure": "fail"},
        {"id": "o", "tool": "http_get", "args": {"path": "/a", "method": "OPTIONS"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender,
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    assert seen_methods == ["HEAD", "OPTIONS"]


def test_race_burst_allows_post_for_flicker():
    def sender(method, url, headers, body, timeout):
        return {"ok": True, "status": 200, "len": 2, "text": "ok",
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "race", "tool": "race_burst",
         "args": {"approval_ref": "lab-race-004", "rounds": 1,
                  "requests": [{"method": "POST", "path": "/login",
                                "body": {"u": "test"}}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender,
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    assert out["requests_sent"] == 1


def test_route_cap_parks_decoy_route():
    manifest = _manifest([
        {"id": "a", "tool": "http_get", "args": {"path": "/wifi"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "b", "on_failure": "fail"},
        {"id": "b", "tool": "http_get", "args": {"path": "/wifi?x=1"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "c", "on_failure": "fail"},
        {"id": "c", "tool": "http_get", "args": {"path": "/wifi?x=2"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    manifest["budget"]["route_cap"] = 2
    def ok_sender(method, url, headers, body, timeout):
        return {"ok": True, "status": 200, "len": 2, "text": "ok",
                "headers": {}, "location": "", "error": None,
                "relogins_used": 0}

    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=ok_sender,
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["terminal"] == "abort"
    assert "rota bütçesi tükendi: /wifi" in out["terminal_error"]
    assert "park et" in out["terminal_error"]
    assert out["requests_sent"] == 2
    assert out["route_counts"] == {"/wifi": 2}


def test_race_burst_exempt_from_route_cap():
    manifest = _manifest([
        {"id": "race", "tool": "race_burst",
         "args": {"approval_ref": "r", "rounds": 2,
                  "requests": [{"path": "/panel"}, {"path": "/panel"}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    manifest["budget"]["route_cap"] = 2
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({"http://lab.test/panel": (200, "ok")}),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    assert out["requests_sent"] == 4


def test_route_cap_zero_means_unlimited():
    manifest = _manifest([
        {"id": "a", "tool": "http_get", "args": {"path": "/x"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    manifest["budget"]["route_cap"] = 0
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({"http://lab.test/x": (200, "ok")}),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True


def test_race_burst_timing_probe_and_gc_restore():
    import gc
    manifest = _manifest([
        {"id": "race", "tool": "race_burst",
         "args": {"approval_ref": "lab-probe", "rounds": 1, "concurrency": 2,
                  "timing_probe": 2,
                  "requests": [{"path": "/a"}, {"path": "/a"}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({"http://lab.test/a": (200, "ok")}),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    assert out["requests_sent"] == 4  # 2 prob + 1 tur x 2
    rec = out["steps_executed"][0]
    assert len(rec["result"]["timing_probe_ms"]) == 2
    assert rec["result"]["gc_disabled"] is True
    assert gc.isenabled()


def test_race_burst_timing_probe_out_of_range():
    manifest = _manifest([
        {"id": "race", "tool": "race_burst",
         "args": {"approval_ref": "lab-probe", "rounds": 1, "timing_probe": 9,
                  "requests": [{"path": "/a"}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({"http://lab.test/a": (200, "ok")}),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["terminal"] == "abort"
    assert "timing_probe" in out["terminal_error"]


def test_race_burst_degrades_on_429():
    manifest = _manifest([
        {"id": "race", "tool": "race_burst",
         "args": {"approval_ref": "lab-429", "rounds": 3, "concurrency": 4,
                  "requests": [{"path": "/a"}] * 4},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    manifest["budget"]["max_requests"] = 15
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({"http://lab.test/a": (429, "limit")}),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    rec = out["steps_executed"][0]
    assert [r["concurrency"] for r in rec["result"]["rounds"]] == [4, 2, 1]
    assert rec["result"]["degraded"] == [
        {"round": 0, "concurrency": 2, "rate_limited": 4},
        {"round": 1, "concurrency": 1, "rate_limited": 4},
    ]
    assert out["requests_sent"] == 12


def test_race_burst_stops_on_divergence():
    routes = {
        "http://lab.test/a": (200, "ok"),
        "http://lab.test/b": (500, "boom"),
    }
    manifest = _manifest([
        {"id": "race", "tool": "race_burst",
         "args": {"approval_ref": "lab-div", "rounds": 3, "concurrency": 2,
                  "stop_on_divergence": True,
                  "requests": [{"path": "/a"}, {"path": "/b"}]},
         "expect": {"oracle": "response_divergence"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory(routes),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    assert out["terminal"] == "succeed"
    rec = out["steps_executed"][0]
    assert rec["result"]["stopped_early"] is True
    assert rec["result"]["round_count"] == 1
    assert out["requests_sent"] == 2
    assert rec["result"]["rounds"][0]["diverge_reason"].startswith("status:")


def test_race_burst_delay_ms_shapes_two_arm_release():
    manifest = _manifest([
        {"id": "race", "tool": "race_burst",
         "args": {"approval_ref": "lab-delay", "rounds": 1, "concurrency": 2,
                  "requests": [{"path": "/a"}, {"path": "/a", "delay_ms": 250}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({"http://lab.test/a": (200, "ok")}),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    items = out["steps_executed"][0]["result"]["items"]
    delayed = max(items, key=lambda r: r["elapsed_ms"])
    assert delayed["elapsed_ms"] >= 150


def test_race_burst_delay_ms_out_of_range():
    manifest = _manifest([
        {"id": "race", "tool": "race_burst",
         "args": {"approval_ref": "lab-delay", "rounds": 1,
                  "requests": [{"path": "/a", "delay_ms": 9999}]},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]),
                           sender=_sender_factory({"http://lab.test/a": (200, "ok")}),
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["terminal"] == "abort"
    assert "delay_ms" in out["terminal_error"]


def test_extract_feeds_later_step_via_refs():
    seen_bodies = []

    def sender(method, url, headers, body, timeout):
        if url.endswith("/form"):
            return {"ok": True, "status": 200, "len": 60,
                    "text": '<input name="csrf" value="TOK123">',
                    "headers": {}, "location": "", "error": None}
        seen_bodies.append(body)
        return {"ok": True, "status": 200, "len": 11, "text": '{"ok":true}',
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "get-form", "tool": "http_get", "args": {"path": "/form"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "grab", "on_failure": "abort"},
        {"id": "grab", "tool": "extract",
         "args": {"from_step": "get-form", "pattern": 'value="([^"]+)"',
                  "save_as": "csrf"},
         "expect": {"oracle": "extract_ok"},
         "on_success": "submit", "on_failure": "fail"},
        {"id": "submit", "tool": "http_post",
         "args": {"path": "/submit", "body": {"csrf": "{{extracted.csrf}}"}},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender,
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    assert out["terminal"] == "succeed"
    assert seen_bodies and '"csrf": "TOK123"' in seen_bodies[0]


def test_extract_no_match_fails_oracle():
    manifest = _manifest([
        {"id": "get-form", "tool": "http_get", "args": {"path": "/form"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "grab", "on_failure": "abort"},
        {"id": "grab", "tool": "extract",
         "args": {"from_step": "get-form", "pattern": "no-such-thing-([0-9]+)",
                  "save_as": "tok"},
         "expect": {"oracle": "extract_ok"},
         "on_success": "succeed", "on_failure": "fail"},
    ])

    def sender(method, url, headers, body, timeout):
        return {"ok": True, "status": 200, "len": 4, "text": "abcd",
                "headers": {}, "location": "", "error": None}

    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender,
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is False
    assert out["terminal"] == "fail"


def test_resilient_session_jar_persists_cookies():
    seen = []

    def sender(method, url, headers, body, timeout):
        seen.append(dict(headers))
        if len(seen) == 1:
            return {"ok": True, "status": 200, "len": 2, "text": "ok",
                    "headers": {"Set-Cookie": "session=ABC123; Path=/"}, "location": "",
                    "error": None}
        return {"ok": True, "status": 200, "len": 2, "text": "ok",
                "headers": {}, "location": "", "error": None}

    manifest = _manifest([
        {"id": "login", "tool": "http_post", "args": {"path": "/login", "body": {"u": "a"}},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "authed", "on_failure": "abort"},
        {"id": "authed", "tool": "http_get", "args": {"path": "/me"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender,
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    assert seen[1].get("Cookie") == "session=ABC123"


def test_validate_rejects_bad_extract_args():
    from action_manifest import validate_manifest
    m = _manifest([
        {"id": "grab", "tool": "extract", "args": {"from_step": "x"},
         "expect": {"oracle": "extract_ok"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    v = validate_manifest(m)
    assert v["valid"] is False
    assert any("save_as" in e for e in v["errors"])


def test_extract_all_collects_catalog():
    manifest = _manifest([
        {"id": "get-shop", "tool": "http_get", "args": {"path": "/"},
         "expect": {"oracle": "status_code", "status": 200},
         "on_success": "grab", "on_failure": "abort"},
        {"id": "grab", "tool": "extract",
         "args": {"from_step": "get-shop", "mode": "all",
                  "pattern": "\\$(\\d+\\.\\d\\d)", "group": 1, "save_as": "prices"},
         "expect": {"oracle": "extract_ok"},
         "on_success": "succeed", "on_failure": "fail"},
    ])
    body = "<h3>A</h3>$10.00<a>x</a><h3>B</h3>$5.50<a>y</a>"

    def sender(method, url, headers, body_, timeout):
        return {"ok": True, "status": 200, "len": len(body), "text": body,
                "headers": {}, "location": "", "error": None}

    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender,
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    rec = out["steps_executed"][1]
    assert rec["result"]["value"] == ["10.00", "5.50"]
    assert "10.00 | 5.50" in rec["result"]["value_preview"]


def test_extract_location_source():
    manifest = _manifest([
        {"id": "go", "tool": "http_post", "args": {"path": "/cart/checkout", "body": {}},
         "expect": {"oracle": "status_code", "status": [302, 303]},
         "on_success": "grab", "on_failure": "fail"},
        {"id": "grab", "tool": "extract",
         "args": {"from_step": "go", "source": "location",
                  "pattern": "(/cart/order-confirmation[^\\s\"']*)", "save_as": "conf"},
         "expect": {"oracle": "extract_ok"},
         "on_success": "succeed", "on_failure": "fail"},
    ])

    def sender(method, url, headers, body, timeout):
        return {"ok": True, "status": 303, "len": 0,
                "text": "", "headers": {},
                "location": "/cart/order-confirmation?order-confirmation=true",
                "error": None}

    runner = ChainExecutor(policy_engine=_AllowGate([]), sender=sender,
                           target_bases={"scope-asset-1": "http://lab.test"})
    out = runner.execute(manifest)
    assert out["success"] is True
    rec = out["steps_executed"][1]
    assert rec["result"]["value"] == "/cart/order-confirmation?order-confirmation=true"
