"""Focused RED/GREEN regressions for BLK-01 duplicate-probe and freshness remediation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
from urllib.parse import urlsplit

import pytest

_ROOT = Path(__file__).resolve().parents[1]
for _rel in ("mcp-servers/mcp-hunter", "mcp-servers/mcp-memory-server"):
    _path = str(_ROOT / _rel)
    if _path not in sys.path:
        sys.path.insert(0, _path)

from cco_hunter_core.blind_discovery import discover_owned_resources
from cco_surface_core import session_store
from full_agent_budget import BudgetError, provider_json
from full_agent_launcher import setup_sessions
from full_agent_python_broker import (
    CRAWL_TOOL,
    MAX_ARCHIVE_BYTES,
    READ_TOOL,
    SESSION_CHECK_TOOL,
    SessionBindingError,
)
from full_agent_python_solver import PythonSolver
import stuck_detector
from test_full_agent_python_solver import handoff_setup, python_broker  # noqa: F401


def _install_vault_executor(python_broker, monkeypatch, home, *, check_behavior=None):
    """Run real session_store.refresh_status and track every executed tool call."""
    calls = []
    python_broker.catalog["kali-tools"].append(
        {"name": "crawl_web_surface", "inputSchema": {"type": "object"}}
    )
    python_broker.catalog["kali-tools"].append(
        {"name": "ledger_prepare_handoff", "inputSchema": {"type": "object"}}
    )
    python_broker.engine.tool_capability = lambda tool: {"network": tool in {SESSION_CHECK_TOOL, CRAWL_TOOL}}

    def execute(self, task):
        self.tasks.append(task)
        tool = task["tool_name"]
        args = json.loads(task["args_json"])
        calls.append((tool, args))
        if tool == SESSION_CHECK_TOOL:
            if check_behavior is not None:
                output = check_behavior(args)
            else:
                output = session_store.refresh_status(
                    args["target"],
                    args["identity"],
                    lambda _url, _hdrs, _cookies: (200, args["identity"]),
                    home=str(home),
                )
            return {"actual_request_cost": 1, "result": {"output": output}}
        if tool == CRAWL_TOOL:
            return {"actual_request_cost": 1, "result": {"output": {"crawled": args["target"], "identity": args["identity"]}}}
        if tool == "kali-tools_ledger_prepare_handoff":
            (python_broker.workdir / "handoff-access.json").write_text(
                json.dumps({"target": args["target"]}), encoding="utf-8"
            )
            python_broker.handoffs["access"] = {
                "producer_spec_id": python_broker.tasks.active_spec.id,
                "files": [],
            }
            return {"actual_request_cost": 0, "result": {"output": {"ok": True}}}
        raise AssertionError(f"unexpected tool call: {tool}")

    monkeypatch.setattr(type(python_broker.executor), "__call__", execute)
    return calls


def _register_accounts(broker, accounts, base, home, *, verify_checks):
    """Register synthetic accounts through setup_sessions using an executor-less shim."""
    called = []

    class SetupShim:
        def call_tool(self, server, name, args, origin="setup"):
            assert server == "validator" and name == "session_vault_check" and origin == "setup"
            called.append(dict(args))
            res = session_store.refresh_status(
                args["target"],
                args["identity"],
                lambda _u, _h, _c: (200, args["identity"]),
                home=str(home),
            )
            return {"isError": False, "content": [{"text": json.dumps(res)}]}

    bindings = setup_sessions(SetupShim(), accounts, base, home, verify_checks=verify_checks)
    return bindings, called


def _write_enum_summary(broker, spec):
    """Write a minimal valid host enum summary so ledger_prepare_handoff succeeds."""
    path = broker.workdir / f"summaries/{spec.id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"task_spec_id": spec.id, "phase": spec.phase, "target": spec.target, "status": "complete"}))


def test_setup_sessions_modes_preserve_native_and_eliminate_redundant_python_checks(tmp_path, monkeypatch):
    """Native verify_checks=True checks all; crawl_only checks 1 member; False checks 0."""
    base = "http://127.0.0.1:18765/"
    accounts = {
        "admin-a": {"role": "admin", "token": "tok-admin-a"},
        "member-b": {"role": "member", "token": "tok-member-b"},
        "member-a": {"role": "member", "token": "tok-member-a"},
        "member-c": {"role": "member", "token": "tok-member-c"},
    }

    home_native = tmp_path / "native-home"
    monkeypatch.setenv("CCO_HOME", str(home_native))
    bindings_native, native_calls = _register_accounts(None, accounts, base, home_native, verify_checks=True)
    assert len(native_calls) == 4
    assert all(session_store.verified_session(base, label, home=str(home_native)) is not None for label in accounts)
    assert all("token" not in str(binding) for binding in bindings_native.values())

    home_crawl = tmp_path / "crawl-home"
    monkeypatch.setenv("CCO_HOME", str(home_crawl))
    bindings_crawl, crawl_calls = _register_accounts(None, accounts, base, home_crawl, verify_checks="crawl_only")
    assert crawl_calls == [{"target": base, "identity": "member-a"}]
    assert session_store.verified_session(base, "member-a", home=str(home_crawl)) is not None
    for other in ("admin-a", "member-b", "member-c"):
        assert session_store.verified_session(base, other, home=str(home_crawl)) is None
    assert set(bindings_crawl) == set(accounts)
    assert all(bindings_crawl[k]["owned_objects_private"] is True for k in accounts)

    home_reg = tmp_path / "reg-home"
    monkeypatch.setenv("CCO_HOME", str(home_reg))
    bindings_reg, reg_calls = _register_accounts(None, accounts, base, home_reg, verify_checks=False)
    assert reg_calls == []
    assert all(session_store.verified_session(base, label, home=str(home_reg)) is None for label in accounts)
    assert set(bindings_reg) == set(accounts)

    with pytest.raises(ValueError, match="verify_checks"):
        _register_accounts(None, accounts, base, home_reg, verify_checks="invalid")


def test_precrawl_host_check_and_handoff_check_remaining_identities_once(python_broker, tmp_path, monkeypatch):
    """Registration-only setup runs 1 real pre-crawl check on member-a; handoff checks remaining once."""
    home = tmp_path / "vault-home"
    monkeypatch.setenv("CCO_HOME", str(home))
    spec = handoff_setup(python_broker)
    accounts = {
        "member-a": {"role": "member", "token": "tok-a"},
        "member-b": {"role": "member", "token": "tok-b"},
        "admin-a": {"role": "admin", "token": "tok-admin"},
    }
    bindings, setup_calls = _register_accounts(python_broker, accounts, spec.target, home, verify_checks=False)
    python_broker.tasks.bindings = bindings
    assert setup_calls == []

    calls = _install_vault_executor(python_broker, monkeypatch, home)
    python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})
    assert [row[0] for row in calls] == [SESSION_CHECK_TOOL, CRAWL_TOOL]
    assert calls[0][1] == {"target": spec.target, "identity": "member-a"}
    assert session_store.verified_session(spec.target, "member-a", home=str(home)) is not None

    _write_enum_summary(python_broker, spec)
    python_broker.handoff()
    session_checks = [args["identity"] for tool, args in calls if tool == SESSION_CHECK_TOOL]
    assert sorted(session_checks) == ["admin-a", "member-a", "member-b"]
    assert len(session_checks) == 3  # Zero duplicate check for fresh same-task member-a.

    evidence = json.loads((python_broker.workdir / "enum/session-checks.json").read_text())
    assert set(evidence) == {"admin-a", "member-a", "member-b"}
    assert all(row["status"] == "fresh" for row in evidence.values())


def test_expired_precrawl_session_is_not_skipped_on_handoff(python_broker, tmp_path, monkeypatch):
    """If pre-checked session expires (>=300s), handoff must perform a real charged refresh."""
    home = tmp_path / "expired-home"
    monkeypatch.setenv("CCO_HOME", str(home))
    spec = handoff_setup(python_broker)
    accounts = {
        "member-a": {"role": "member", "token": "tok-a"},
        "member-b": {"role": "member", "token": "tok-b"},
        "admin-a": {"role": "admin", "token": "tok-admin"},
    }
    python_broker.tasks.bindings, _ = _register_accounts(python_broker, accounts, spec.target, home, verify_checks=False)
    calls = _install_vault_executor(python_broker, monkeypatch, home)

    python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})
    assert len([t for t, _ in calls if t == SESSION_CHECK_TOOL]) == 1

    # Simulate expiry (> 300s) before handoff.
    real_time = time.time
    monkeypatch.setattr(session_store.time, "time", lambda: real_time() + 370)
    _write_enum_summary(python_broker, spec)
    python_broker.handoff()

    checked_identities = [args["identity"] for tool, args in calls if tool == SESSION_CHECK_TOOL]
    assert checked_identities.count("member-a") == 2  # Pre-crawl + mandatory expired refresh.
    assert len(checked_identities) == 4


def test_freshness_reuse_is_fail_closed_across_task_scope_and_tamper(python_broker, tmp_path, monkeypatch):
    """Cross-task receipt, target mismatch, archive tamper, or vault check_id mismatch force real re-check."""
    home = tmp_path / "tamper-home"
    monkeypatch.setenv("CCO_HOME", str(home))
    spec = handoff_setup(python_broker)
    accounts = {
        "member-a": {"role": "member", "token": "tok-a"},
        "member-b": {"role": "member", "token": "tok-b"},
        "admin-a": {"role": "admin", "token": "tok-admin"},
    }
    python_broker.tasks.bindings, _ = _register_accounts(python_broker, accounts, spec.target, home, verify_checks=False)
    _install_vault_executor(python_broker, monkeypatch, home)

    python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is True

    # 1. Cross-task provenance must not satisfy current task.
    other_spec = python_broker.tasks.specs[0]
    assert python_broker._fresh_task_session_check(other_spec, {"target": spec.target, "identity": "member-a"}) is False

    # 2. Cross-target binding must not satisfy check.
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target + "other", "identity": "member-a"}) is False

    # 3. Vault check_id rotation/mismatch fails closed.
    latest_row = next(r for r in reversed(python_broker.results) if r["tool"] == SESSION_CHECK_TOOL)
    ref_path = python_broker.workdir / latest_row["content_ref"]["path"]
    original_bytes = ref_path.read_bytes()
    tampered = json.loads(original_bytes)
    tampered["check_id"] = "wrong-check-id"
    ref_path.write_bytes(json.dumps(tampered).encode())
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is False

    # 4. Changing archived file digest fails sha256 check; restoring original bytes recovers;
    # rotating session_store invalidates prior verification so handoff re-checks member-a.
    ref_path.write_bytes(original_bytes + b" ")
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is False
    ref_path.write_bytes(original_bytes)
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is True
    session_store.put_session(
        spec.target, "member-a", headers={"Authorization": "Bearer tok-a-rotated"},
        check_url=spec.target, marker="member-a", home=str(home),
    )
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is False

    # 5. Re-executing handoff refreshes member-a (plus member-b/admin-a) instead of skipping.
    _write_enum_summary(python_broker, spec)
    python_broker.handoff()
    evidence = json.loads((python_broker.workdir / "enum/session-checks.json").read_text())
    assert set(evidence) == {"admin-a", "member-a", "member-b"}


def test_precrawl_session_failure_or_budget_denial_blocks_crawl(python_broker, tmp_path, monkeypatch):
    """Failed pre-crawl session check or exhausted budget blocks crawl_web_surface without running crawl."""
    home = tmp_path / "deny-home"
    monkeypatch.setenv("CCO_HOME", str(home))
    spec = handoff_setup(python_broker)
    accounts = {"member-a": {"role": "member", "token": "tok-a"}}
    python_broker.tasks.bindings, _ = _register_accounts(python_broker, accounts, spec.target, home, verify_checks=False)

    calls = _install_vault_executor(
        python_broker,
        monkeypatch,
        home,
        check_behavior=lambda args: {"present": True, "status": "stale", "target": args["target"], "identity": args["identity"]},
    )
    with pytest.raises(SessionBindingError):
        python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})
    assert [tool for tool, _ in calls] == [SESSION_CHECK_TOOL]

    # Budget denial also blocks pre-crawl and crawl.
    python_broker.runtime_policy.tool_calls[spec.id] = spec.max_calls
    with pytest.raises(BudgetError):
        python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})
    assert [tool for tool, _ in calls] == [SESSION_CHECK_TOOL]


def test_collection_proved_elision_and_k4_pair_budget_stay_below_stuck_threshold(tmp_path):
    """Exact scoped collection proof elides redundant detail GETs while keeping K_4 6-pair order & <10 stuck probes."""
    base = "http://127.0.0.1:18888/"
    db = sqlite3.connect(":memory:")
    actors = ("member-a", "member-b", "member-c", "member-d")
    records = {actor: f"{actor}-11111111-2222-3333-4444-555555555555" for actor in actors}
    fetches = []

    def perm(url):
        parsed = urlsplit(url)
        return parsed.scheme == "http" and parsed.netloc == "127.0.0.1:18888"

    def fetch(url, headers):
        actor = headers["Authorization"].split()[-1].removeprefix("tok-")
        fetches.append((actor, url))
        if url == base:
            rec_id = records[actor]
            body = json.dumps({
                "service": "record archive",
                "links": [],
                "current_user": {"id": actor},
                "records": [{"id": rec_id, "owner_id": actor, "href": f"/api/records/{rec_id}"}],
            })
            return {"ok": True, "status": 200, "text": body}
        raise AssertionError(f"redundant detail GET should be elided for proven collection entry: {url}")

    identities = {
        actor: {"headers": {"Authorization": f"Bearer tok-{actor}"}, "owned_objects_private": True, "test_data_only": True}
        for actor in actors
    }
    summary, enriched, candidates = discover_owned_resources(
        base, identities, fetch, perm, allow_private_owned=True, max_requests=16, per_identity=4
    )
    assert summary["status"] == "ready"
    assert summary["requests"] == 4  # Exactly 1 collection GET per actor; 0 detail GETs.
    assert len(fetches) == 4 and all(url == base for _, url in fetches)
    assert len(candidates) == 4
    for actor in actors:
        assert enriched[actor]["objects"] == [{"url": f"{base}api/records/{records[actor]}", "marker": records[actor]}]

    # Verify K_4 pair order (first-cover preserved) and StuckDetector counts across all 6 pairs even after expiry re-discovery.
    solver_stub = type("SolverStub", (), {
        "broker": type("BrokerStub", (), {
            "session_checks": lambda _self, _s: [{"target": base, "identity": a} for a in actors],
            "tasks": type("TasksStub", (), {
                "bindings": {
                    a: {"target": base, "role": "member", "test_data_only": True, "owned_objects_private": True}
                    for a in actors
                },
            })(),
        })(),
        "member_pair_categories": lambda _self, _pair: ["same_tenant_other_user"],
    })()
    spec_pairs = PythonSolver.member_batches(solver_stub, object())
    assert [list(pair) for pair in spec_pairs] == [
        ["member-a", "member-b"],
        ["member-c", "member-d"],
        ["member-a", "member-c"],
        ["member-a", "member-d"],
        ["member-b", "member-c"],
        ["member-b", "member-d"],
    ]

    # Simulate K_4 6-pair session checks (crawl_only=1 setup + 4 enum + 2 expiry refresh) < 10.
    for _ in range(1 + 4 + 2):
        ok, detail = stuck_detector.evaluate_probe(db, "validator_session_vault_check", None, [base])
        assert ok, detail
    # Across all 3 pairs touching member-b (Pair 1, Pair 4, Pair 6 * 3 requests = 9), zero detail GETs keeps probes < 10.
    obj_b = f"{base}api/records/{records['member-b']}"
    for _ in range(9):
        ok, detail = stuck_detector.evaluate_probe(db, "validator_validate_idor", [obj_b], None)
        assert ok, detail
    assert stuck_detector.threshold() == 10 and stuck_detector.window_minutes() == 30
    ok10, _ = stuck_detector.evaluate_probe(db, "validator_validate_idor", [obj_b], None)
    assert ok10
    allowed11, _ = stuck_detector.evaluate_probe(db, "validator_validate_idor", [obj_b], None)
    assert not allowed11


@pytest.mark.parametrize("case", [
    "disjoint_nodes",
    "conflicting_owners",
    "duplicate_json_key",
    "missing_current_user",
    "conflicting_current_user",
    "public_visibility",
    "owned_objects_private_false",
    "out_of_scope_url",
    "url_missing_id",
])
def test_collection_elision_negative_controls_fail_closed(case):
    """Negative controls must NEVER falsely elide detail probes or credit unverified private ownership."""
    base = "http://127.0.0.1:18888/"
    rec_a = "aaaaaaaa-1111-2222-3333-444444444444"
    rec_b = "bbbbbbbb-1111-2222-3333-444444444444"
    detail_fetched = []

    def perm(url):
        parsed = urlsplit(url)
        return parsed.scheme == "http" and parsed.netloc == "127.0.0.1:18888"

    def make_payload(actor):
        rec_id = rec_a if actor == "member-a" else rec_b
        if case == "disjoint_nodes":
            return json.dumps({
                "current_user": {"id": actor},
                "records": [{"owner_id": actor}, {"id": rec_id, "href": f"/api/records/{rec_id}"}],
            })
        if case == "conflicting_owners":
            return json.dumps({
                "current_user": {"id": actor},
                "records": [
                    {"id": rec_id, "owner_id": actor, "href": f"/api/records/{rec_id}"},
                    {"id": rec_id, "owner_id": "someone-else", "href": f"/api/records/{rec_id}"},
                ],
            })
        if case == "duplicate_json_key":
            return (
                f'{{"current_user": {{"id": "{actor}"}}, "current_user": {{"id": "spoof"}}, '
                f'"records": [{{"id": "{rec_id}", "owner_id": "{actor}", "href": "/api/records/{rec_id}"}}]}}'
            )
        if case == "missing_current_user":
            return json.dumps({
                "records": [{"id": rec_id, "owner_id": actor, "href": f"/api/records/{rec_id}"}],
            })
        if case == "conflicting_current_user":
            return json.dumps({
                "current_user": {"id": actor},
                "viewer": {"id": "other-principal"},
                "records": [{"id": rec_id, "owner_id": actor, "href": f"/api/records/{rec_id}"}],
            })
        if case == "public_visibility":
            return json.dumps({
                "current_user": {"id": actor},
                "records": [{
                    "id": rec_id,
                    "owner_id": actor,
                    "visibility": "public",
                    "href": f"/api/records/{rec_id}",
                }],
            })
        if case == "owned_objects_private_false":
            return json.dumps({
                "current_user": {"id": actor},
                "records": [{"id": rec_id, "owner_id": actor, "href": f"/api/records/{rec_id}"}],
            })
        if case == "out_of_scope_url":
            return json.dumps({
                "current_user": {"id": actor},
                "records": [{"id": rec_id, "owner_id": actor, "href": f"https://evil.example/api/records/{rec_id}"}],
            })
        if case == "url_missing_id":
            return json.dumps({
                "current_user": {"id": actor},
                "records": [{"id": rec_id, "owner_id": actor, "href": "/api/records/latest"}],
            })
        raise AssertionError(case)

    def fetch(url, headers):
        actor = headers["Authorization"].split()[-1].removeprefix("tok-")
        if url == base:
            return {"ok": True, "status": 200, "text": make_payload(actor)}
        detail_fetched.append((actor, url))
        return {"ok": True, "status": 200, "text": json.dumps({"note": "unattributed detail"})}

    identities = {
        "member-a": {
            "headers": {"Authorization": "Bearer tok-member-a"},
            "owned_objects_private": case != "owned_objects_private_false",
            "test_data_only": True,
        },
        "member-b": {
            "headers": {"Authorization": "Bearer tok-member-b"},
            "owned_objects_private": case != "owned_objects_private_false",
            "test_data_only": True,
        },
    }
    _summary, enriched, candidates = discover_owned_resources(
        base, identities, fetch, perm, allow_private_owned=True, max_requests=10, per_identity=5
    )

    assert candidates == []
    assert all(not enriched[actor].get("objects") for actor in identities)
    if case in {"disjoint_nodes", "conflicting_owners", "owned_objects_private_false", "url_missing_id"}:
        assert detail_fetched  # Must NOT elide detail fetch when proof/policy is absent or conflicting.
    if case == "out_of_scope_url":
        assert detail_fetched == []  # Out-of-scope URL must neither elide nor be fetched.


def test_out_of_band_rotation_refresh_and_context_redaction(python_broker, tmp_path, monkeypatch):
    """Real out-of-band refresh after credential rotation invalidates pre-rotation reuse; secrets never leak."""
    home = tmp_path / "rot-home"
    monkeypatch.setenv("CCO_HOME", str(home))
    spec = handoff_setup(python_broker)
    accounts = {
        "member-a": {"role": "member", "token": "tok-a-v1-secret"},
        "member-b": {"role": "member", "token": "tok-b-v1-secret"},
        "admin-a": {"role": "admin", "token": "tok-admin-v1-secret"},
    }
    python_broker.tasks.bindings, _ = _register_accounts(python_broker, accounts, spec.target, home, verify_checks=False)
    calls = _install_vault_executor(python_broker, monkeypatch, home)

    python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})
    check_row = next(r for r in python_broker.results if r["tool"] == SESSION_CHECK_TOOL)
    assert "check_id" not in check_row["result"]
    assert "session_check_fingerprint" in check_row
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is True

    # Host-private fingerprint and vault secret_ref must never enter solver context or cards.
    solver = PythonSolver(python_broker, model="model")
    ctx = solver.context(spec)
    ctx_json = provider_json(ctx).decode()
    for secret in ("tok-a-v1-secret", "secret_ref", "session_check_fingerprint", check_row["session_check_fingerprint"]):
        assert secret not in ctx_json

    # Rotate credentials and verify out-of-band (real refresh_status, so verified_session is fresh!).
    session_store.put_session(
        spec.target, "member-a", headers={"Authorization": "Bearer tok-a-v2-rotated"},
        check_url=spec.target, marker="member-a", home=str(home),
    )
    rotated_out = session_store.refresh_status(
        spec.target, "member-a", lambda _u, _h, _c: (200, "member-a"), home=str(home),
    )
    assert rotated_out["status"] == "fresh" and "check_id" not in rotated_out
    assert session_store.verified_session(spec.target, "member-a", home=str(home)) is not None
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is False

    # Handoff must re-check member-a along with member-b and admin-a.
    _write_enum_summary(python_broker, spec)
    python_broker.handoff()
    checked = [args["identity"] for tool, args in calls if tool == SESSION_CHECK_TOOL]
    assert checked.count("member-a") == 2
    assert sorted(set(checked)) == ["admin-a", "member-a", "member-b"]


def test_freshness_linkage_and_target_identity_fail_closed(python_broker, tmp_path, monkeypatch):
    """Matching SHA metadata with missing/wrong linkage or missing target/identity never certifies freshness."""
    home = tmp_path / "link-home"
    monkeypatch.setenv("CCO_HOME", str(home))
    spec = handoff_setup(python_broker)
    accounts = {"member-a": {"role": "member", "token": "tok-a"}}
    python_broker.tasks.bindings, _ = _register_accounts(python_broker, accounts, spec.target, home, verify_checks=True)
    verified = session_store.verified_session(spec.target, "member-a", home=str(home))
    assert verified is not None
    current_fp = session_store.check_fingerprint(spec.target, "member-a", home=str(home), entry=verified)
    real_out = session_store.summarize(verified)
    ref_valid = python_broker.archive(real_out, "tool-result")

    # 1. Valid SHA metadata but missing host-private linkage.
    python_broker.results.append({
        "spec_id": spec.id,
        "tool": SESSION_CHECK_TOOL,
        "arguments": {"target": spec.target, "identity": "member-a"},
        "content_ref": ref_valid,
    })
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is False
    assert python_broker.session_check_evidence(spec) == {}

    # 2. Valid SHA metadata but wrong host-private linkage.
    python_broker.results.append({
        "spec_id": spec.id,
        "tool": SESSION_CHECK_TOOL,
        "arguments": {"target": spec.target, "identity": "member-a"},
        "content_ref": ref_valid,
        "session_check_fingerprint": "0" * 64,
    })
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is False

    # 3. Missing target/identity or mismatched identity in payload even with matching fingerprint.
    for bad_payload in (
        {"status": "fresh"},
        {"status": "fresh", "target": spec.target},
        {"status": "fresh", "identity": "member-a"},
        {"status": "fresh", "target": spec.target, "identity": "member-b"},
    ):
        bad_ref = python_broker.archive(bad_payload, "tool-result")
        python_broker.results.append({
            "spec_id": spec.id,
            "tool": SESSION_CHECK_TOOL,
            "arguments": {"target": spec.target, "identity": "member-a"},
            "content_ref": bad_ref,
            "session_check_fingerprint": current_fp,
        })
        assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is False

    # 4. Exact complete host-linked entry certifies freshness.
    python_broker.results.append({
        "spec_id": spec.id,
        "tool": SESSION_CHECK_TOOL,
        "arguments": {"target": spec.target, "identity": "member-a"},
        "content_ref": ref_valid,
        "session_check_fingerprint": current_fp,
    })
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is True


@pytest.mark.parametrize("attack", [
    "missing_sha_bytes",
    "unregistered_ref",
    "missing_reg_sha",
    "missing_reg_bytes",
    "bool_reg_bytes",
    "bad_reg_sha_hex",
    "mismatched_reg_bytes",
    "rel_traversal",
    "embedded_dotdot",
    "abs_outside",
    "abs_inside_workdir",
    "parent_symlink",
    "leaf_symlink",
    "oversize_file",
    "fifo_nonblock",
    "directory_target",
])
def test_read_reference_and_freshness_reject_archive_escapes_and_nonregular_files(
    python_broker, tmp_path, monkeypatch, attack
):
    """Hardened host archive helper rejects missing digests, traversal, symlinks, >16MiB, and FIFOs without blocking."""
    home = tmp_path / "hard-home"
    monkeypatch.setenv("CCO_HOME", str(home))
    spec = handoff_setup(python_broker)
    accounts = {"member-a": {"role": "member", "token": "tok-a"}}
    python_broker.tasks.bindings, _ = _register_accounts(python_broker, accounts, spec.target, home, verify_checks=True)
    verified = session_store.verified_session(spec.target, "member-a", home=str(home))
    current_fp = session_store.check_fingerprint(spec.target, "member-a", home=str(home), entry=verified)

    fresh_obj = {"status": "fresh", "target": spec.target, "identity": "member-a"}
    fresh_bytes = provider_json(fresh_obj)
    fresh_sha = hashlib.sha256(fresh_bytes).hexdigest()
    archive_dir = python_broker.workdir / "context-archive"
    archive_dir.mkdir(exist_ok=True)
    outside = tmp_path / "outside-fresh.json"
    outside.write_bytes(fresh_bytes)

    if attack == "missing_sha_bytes":
        target_file = archive_dir / "nosha.json"
        target_file.write_bytes(fresh_bytes)
        ref = {"path": "context-archive/nosha.json"}
    elif attack == "unregistered_ref":
        target_file = archive_dir / "unreg.json"
        target_file.write_bytes(fresh_bytes)
        ref = {"path": "context-archive/unreg.json", "sha256": fresh_sha, "bytes": len(fresh_bytes)}
    elif attack in {"missing_reg_sha", "missing_reg_bytes", "bool_reg_bytes", "bad_reg_sha_hex", "mismatched_reg_bytes"}:
        ref = python_broker.archive(fresh_obj, "tool-result")
        rel = ref["path"]
        if attack == "missing_reg_sha":
            bad_ref = {"path": rel, "bytes": ref["bytes"]}
        elif attack == "missing_reg_bytes":
            bad_ref = {"path": rel, "sha256": ref["sha256"]}
        elif attack == "bool_reg_bytes":
            bad_ref = {"path": rel, "sha256": ref["sha256"], "bytes": True}
        elif attack == "bad_reg_sha_hex":
            bad_ref = {"path": rel, "sha256": "z" * 64, "bytes": ref["bytes"]}
        else:
            bad_ref = {"path": rel, "sha256": ref["sha256"], "bytes": ref["bytes"] + 1}
        python_broker.references[rel] = bad_ref
        ref = bad_ref
    elif attack == "rel_traversal":
        rel = "../../outside-fresh.json"
        ref = {"path": rel, "sha256": fresh_sha, "bytes": len(fresh_bytes)}
        python_broker.references[rel] = ref
    elif attack == "embedded_dotdot":
        rel = "context-archive/../../outside-fresh.json"
        ref = {"path": rel, "sha256": fresh_sha, "bytes": len(fresh_bytes)}
        python_broker.references[rel] = ref
    elif attack == "abs_outside":
        rel = str(outside)
        ref = {"path": rel, "sha256": fresh_sha, "bytes": len(fresh_bytes)}
        python_broker.references[rel] = ref
    elif attack == "abs_inside_workdir":
        target_file = archive_dir / "inside.json"
        target_file.write_bytes(fresh_bytes)
        rel = str(target_file)
        ref = {"path": rel, "sha256": fresh_sha, "bytes": len(fresh_bytes)}
        python_broker.references[rel] = ref
    elif attack == "parent_symlink":
        ext_dir = tmp_path / "ext_dir"
        ext_dir.mkdir()
        (ext_dir / "fresh.json").write_bytes(fresh_bytes)
        (python_broker.workdir / "linked_sub").symlink_to(ext_dir)
        rel = "linked_sub/fresh.json"
        ref = {"path": rel, "sha256": fresh_sha, "bytes": len(fresh_bytes)}
        python_broker.references[rel] = ref
    elif attack == "leaf_symlink":
        leaf = archive_dir / "leaf.json"
        leaf.symlink_to(outside)
        rel = "context-archive/leaf.json"
        ref = {"path": rel, "sha256": fresh_sha, "bytes": len(fresh_bytes)}
        python_broker.references[rel] = ref
    elif attack == "oversize_file":
        big_file = archive_dir / "oversize.json"
        payload = json.dumps({
            "status": "fresh", "target": spec.target, "identity": "member-a",
            "pad": "a" * (MAX_ARCHIVE_BYTES + 128),
        }).encode()
        big_file.write_bytes(payload)
        rel = "context-archive/oversize.json"
        ref = {"path": rel, "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
        python_broker.references[rel] = ref
    elif attack == "fifo_nonblock":
        fifo_path = archive_dir / "fifo.json"
        os.mkfifo(fifo_path)
        rel = "context-archive/fifo.json"
        ref = {"path": rel, "sha256": fresh_sha, "bytes": len(fresh_bytes)}
        python_broker.references[rel] = ref
    elif attack == "directory_target":
        dir_path = archive_dir / "subdir.json"
        dir_path.mkdir()
        rel = "context-archive/subdir.json"
        ref = {"path": rel, "sha256": fresh_sha, "bytes": len(fresh_bytes)}
        python_broker.references[rel] = ref
    else:
        raise AssertionError(attack)

    python_broker.results.append({
        "spec_id": spec.id,
        "tool": SESSION_CHECK_TOOL,
        "arguments": {"target": spec.target, "identity": "member-a"},
        "content_ref": ref,
        "session_check_fingerprint": current_fp,
    })
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is False
    with pytest.raises(ValueError):
        python_broker.read_reference(ref)
    if isinstance(ref, dict) and isinstance(ref.get("path"), str) and ref["path"] in python_broker.references:
        with pytest.raises(ValueError, match="invalid artifact reference"):
            python_broker.invoke(READ_TOOL, {"path": ref["path"], "offset": 0, "limit": 100})


def test_read_tool_preserves_bounded_progress_and_precrawl_denial_accounting(python_broker, tmp_path, monkeypatch):
    """READ_TOOL keeps progress/stall bounds; pre-crawl denial updates consecutive failure brake without expanding reserves."""
    home = tmp_path / "acct-home"
    monkeypatch.setenv("CCO_HOME", str(home))
    spec = handoff_setup(python_broker)
    accounts = {"member-a": {"role": "member", "token": "tok-a"}}
    python_broker.tasks.bindings, _ = _register_accounts(python_broker, accounts, spec.target, home, verify_checks=False)

    # Preserve READ_TOOL progress + stall semantics.
    large_ref = python_broker.archive({"blob": "x" * 3500}, "tool-result")
    p1 = python_broker.invoke(READ_TOOL, {"path": large_ref["path"], "offset": 0, "limit": 3000})["result"]
    assert p1["next_offset"] == 3000 and not p1["eof"]
    p2 = python_broker.invoke(READ_TOOL, {"path": large_ref["path"], "offset": 0, "limit": 3000})["result"]
    p3 = python_broker.invoke(READ_TOOL, {"path": large_ref["path"], "offset": 0, "limit": 3000})["result"]
    assert p2["next_offset"] == 3000
    assert p3["reason_code"] == "archive_read_no_progress"

    # Pre-crawl stale check (or unverified fresh claim) records CRAWL_TOOL denial and trips brake after 2 failures.
    python_broker.runtime_policy.reserve_handoff(spec, len(python_broker.session_checks(spec)))
    reserve_before = python_broker.runtime_policy.handoff_reserves[spec.id]
    _install_vault_executor(
        python_broker,
        monkeypatch,
        home,
        check_behavior=lambda args: {"present": True, "status": "fresh", "target": args["target"], "identity": args["identity"]},
    )
    with pytest.raises(SessionBindingError):
        python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})
    assert python_broker.runtime_policy.consecutive_failures[spec.id] == 1
    assert python_broker.runtime_policy.tool_failures[(spec.id, CRAWL_TOOL)] == 1
    assert python_broker.runtime_policy.handoff_reserves[spec.id] == reserve_before

    with pytest.raises(SessionBindingError):
        python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})
    assert python_broker.runtime_policy.tool_failures[(spec.id, CRAWL_TOOL)] == 2
    assert python_broker.runtime_policy.consecutive_failures[spec.id] == 1

    # When pre-crawl SESSION_CHECK_TOOL itself fails execution, consecutive_failures reaches 2 and trips the brake.
    _install_vault_executor(
        python_broker,
        monkeypatch,
        home,
        check_behavior=lambda _args: {"execution_failed": True, "error": "vault_error"},
    )
    with pytest.raises(SessionBindingError):
        python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})
    assert python_broker.runtime_policy.consecutive_failures[spec.id] == 3
    with pytest.raises(BudgetError, match="consecutive_tool_failure_limit"):
        python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})


def test_signed_checkpoint_preserves_host_linkage_and_rejects_tamper_or_rotation(python_broker, tmp_path, monkeypatch):
    """Signed checkpoint preserves host-private fingerprint on restore and still fails closed on tamper or rotation."""
    home = tmp_path / "ckpt-home"
    monkeypatch.setenv("CCO_HOME", str(home))
    spec = handoff_setup(python_broker)
    accounts = {"member-a": {"role": "member", "token": "tok-a-v1"}}
    python_broker.tasks.bindings, _ = _register_accounts(python_broker, accounts, spec.target, home, verify_checks=False)
    _install_vault_executor(python_broker, monkeypatch, home)

    python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})
    solver = PythonSolver(python_broker, model="model")
    solver.checkpoint.acquire()
    solver._checkpoint_active = True
    try:
        solver.save_checkpoint()
    finally:
        solver.checkpoint.release()

    # Checkpoint state binds session_check_fingerprint inside private state_ref, not in public checkpoint.json.
    ckpt_text = (python_broker.workdir / "checkpoint.json").read_text()
    assert "session_check_fingerprint" not in ckpt_text
    assert "tok-a-v1" not in ckpt_text

    # Restore into a fresh broker/solver: reuse remains valid while vault is unchanged.
    python_broker.results.clear()
    solver.restore_checkpoint()
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is True

    # Out-of-band credential rotation + refresh before resume invalidates restored reuse.
    session_store.put_session(
        spec.target, "member-a", headers={"Authorization": "Bearer tok-a-v2"},
        check_url=spec.target, marker="member-a", home=str(home),
    )
    session_store.refresh_status(spec.target, "member-a", lambda _u, _h, _c: (200, "member-a"), home=str(home))
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is False

    # Tampering checkpoint state_ref fails checkpoint verification.
    ckpt_payload = solver.checkpoint.read()
    state_path = python_broker.workdir.parent / ckpt_payload["state_ref"]["path"]
    state_path.write_text("{}")
    with pytest.raises(ValueError, match="checkpoint evidence integrity mismatch"):
        solver.checkpoint.read()


def test_python_broker_rejects_symlinked_workdir_or_ancestor_at_init_and_forbids_rebind(tmp_path, monkeypatch):
    """PythonBroker anchors lexical root/ancestors at construction and keeps workdir immutable."""
    from types import SimpleNamespace
    from full_agent_budget import SharedBudget
    from full_agent_python_broker import PythonBroker

    real_root = tmp_path / "real-solver"
    real_root.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    engine = SimpleNamespace(_is_known_tool=lambda _n: True, _rate_limit_for=lambda _n: (0, 60))

    class NoOpExecutor:
        timeout_seconds = 300
        def __call__(self, _task):
            raise AssertionError("unused")
        def terminate(self):
            pass

    symlink_root = tmp_path / "symlink-solver"
    symlink_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(ValueError, match="invalid workdir root"):
        PythonBroker(
            budget=SharedBudget(tokens=1000, http=5, seconds=60),
            engine=engine,
            executor=NoOpExecutor(),
            workdir=symlink_root,
            private=private,
            provider="https://provider.invalid/v1",
            models={"model"},
            api_key="synthetic",
        )

    real_parent = tmp_path / "real-parent"
    (real_parent / "solver").mkdir(parents=True)
    symlink_parent = tmp_path / "symlink-parent"
    symlink_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ValueError, match="invalid workdir root"):
        PythonBroker(
            budget=SharedBudget(tokens=1000, http=5, seconds=60),
            engine=engine,
            executor=NoOpExecutor(),
            workdir=symlink_parent / "solver",
            private=private,
            provider="https://provider.invalid/v1",
            models={"model"},
            api_key="synthetic",
        )

    broker = PythonBroker(
        budget=SharedBudget(tokens=1000, http=5, seconds=60),
        engine=engine,
        executor=NoOpExecutor(),
        workdir=real_root,
        private=private,
        provider="https://provider.invalid/v1",
        models={"model"},
        api_key="synthetic",
    )
    try:
        assert broker.workdir == real_root
        with pytest.raises(AttributeError):
            broker.workdir = tmp_path / "other"
        assert broker.workdir == real_root
    finally:
        broker.close()


@pytest.mark.parametrize("attack", [
    "workdir_symlink",
    "workdir_parent_symlink",
    "workdir_grandparent_symlink",
    "workdir_dir_replacement",
    "workdir_parent_dir_replacement",
    "deterministic_root_open_swap",
    "deterministic_parent_open_swap",
])
def test_immutable_root_anchoring_rejects_root_and_ancestor_symlinks_and_replacements(
    tmp_path, monkeypatch, attack
):
    """Root/ancestor symlinks, directory swaps, and deterministic root-open races all fail closed."""
    import shutil
    from types import SimpleNamespace
    from full_agent_budget import SharedBudget
    from full_agent_python_broker import PythonBroker
    from full_agent_launcher import bootstrap_plan
    from full_agent_tasks import TaskRegistry

    base_tree = tmp_path / "outer" / "inner"
    work = base_tree / "solver"
    private = tmp_path / "private"
    home = tmp_path / "home"
    for p in (work, private, home):
        p.mkdir(parents=True)
    monkeypatch.setenv("CCO_HOME", str(home))

    target, identity = "http://127.0.0.1:18765/", "member-a"
    engine = SimpleNamespace(
        _is_known_tool=lambda _name: True,
        _rate_limit_for=lambda _name: (0, 60),
        tool_capability=lambda name: {"network": name == SESSION_CHECK_TOOL},
        validate_tool_invocation=lambda *_a, **_kw: {"allowed": True, "reason": "allowed"},
    )

    class VaultExecutor:
        timeout_seconds = 300
        def __call__(self, task):
            args = json.loads(task["args_json"])
            out = session_store.refresh_status(
                args["target"],
                args["identity"],
                lambda _u, _h, _c: (200, args["identity"]),
                home=str(home),
            )
            return {"actual_request_cost": 1, "result": {"output": out}}
        def terminate(self):
            pass

    broker = PythonBroker(
        budget=SharedBudget(tokens=150000, http=50, seconds=300),
        engine=engine,
        executor=VaultExecutor(),
        workdir=work,
        private=private,
        provider="https://provider.invalid/v1",
        models={"model"},
        api_key="synthetic",
    )
    try:
        specs = bootstrap_plan(target, work, solver_mode="python_loop")
        bindings, _ = _register_accounts(broker, {identity: {"role": "member", "token": "tok-a"}}, target, home, verify_checks=False)
        broker.tasks = TaskRegistry(specs, work, bindings, setup_checks_passed=False)
        spec = next(s for s in specs if s.id == "enum-2")
        broker.tasks.active_spec = spec

        args = {"target": target, "identity": identity}
        broker.invoke(SESSION_CHECK_TOOL, args)
        ref = broker.results[-1]["content_ref"]
        assert broker.read_reference(ref)["status"] == "fresh"
        assert broker._fresh_task_session_check(spec, args) is True

        parent = work.parent
        grandparent = parent.parent
        parent_id = (os.lstat(parent).st_dev, os.lstat(parent).st_ino)
        grandparent_id = (os.lstat(grandparent).st_dev, os.lstat(grandparent).st_ino)

        if attack == "workdir_symlink":
            moved = tmp_path / "relocated-solver"
            work.rename(moved)
            work.symlink_to(moved, target_is_directory=True)
        elif attack == "workdir_parent_symlink":
            moved = tmp_path / "relocated-parent"
            parent.rename(moved)
            parent.symlink_to(moved, target_is_directory=True)
        elif attack == "workdir_grandparent_symlink":
            moved = tmp_path / "relocated-grandparent"
            grandparent.rename(moved)
            grandparent.symlink_to(moved, target_is_directory=True)
        elif attack == "workdir_dir_replacement":
            moved = tmp_path / "copied-solver-src"
            work.rename(moved)
            shutil.copytree(moved, work)
        elif attack == "workdir_parent_dir_replacement":
            moved = tmp_path / "copied-parent-src"
            parent.rename(moved)
            shutil.copytree(moved, parent)
        elif attack == "deterministic_root_open_swap":
            orig_open = os.open
            moved = tmp_path / "race-solver"
            observed_flags = []

            def race_root_open(path, flags, *oargs, **okwargs):
                dir_fd = okwargs.get("dir_fd")
                if dir_fd is not None and path == work.name and not work.is_symlink():
                    st = os.fstat(dir_fd)
                    if (st.st_dev, st.st_ino) == parent_id:
                        observed_flags.append(bool(flags & os.O_NOFOLLOW))
                        work.rename(moved)
                        work.symlink_to(moved, target_is_directory=True)
                return orig_open(path, flags, *oargs, **okwargs)

            monkeypatch.setattr(os, "open", race_root_open)
        elif attack == "deterministic_parent_open_swap":
            orig_open = os.open
            moved = tmp_path / "race-parent"
            observed_flags = []

            def race_parent_open(path, flags, *oargs, **okwargs):
                dir_fd = okwargs.get("dir_fd")
                if dir_fd is not None and path == parent.name and not parent.is_symlink():
                    st = os.fstat(dir_fd)
                    if (st.st_dev, st.st_ino) == grandparent_id:
                        observed_flags.append(bool(flags & os.O_NOFOLLOW))
                        parent.rename(moved)
                        parent.symlink_to(moved, target_is_directory=True)
                return orig_open(path, flags, *oargs, **okwargs)

            monkeypatch.setattr(os, "open", race_parent_open)

        with pytest.raises(ValueError, match="invalid artifact reference"):
            broker.read_reference(ref)
        assert broker._fresh_task_session_check(spec, args) is False
        with pytest.raises(ValueError, match="invalid artifact reference"):
            broker.invoke(READ_TOOL, {"path": ref["path"], "offset": 0, "limit": 100})
        if attack.startswith("deterministic_"):
            assert observed_flags == [True]
    finally:
        broker.close()


def test_intact_root_restore_and_close_lifecycle_preserve_reuse_without_fd_leaks(
    python_broker, tmp_path, monkeypatch
):
    """Intact anchored root/ancestors preserve checkpoint restore/reuse and close() releases fds cleanly."""
    import errno
    home = tmp_path / "intact-home"
    monkeypatch.setenv("CCO_HOME", str(home))
    spec = handoff_setup(python_broker)
    accounts = {"member-a": {"role": "member", "token": "tok-a"}}
    python_broker.tasks.bindings, _ = _register_accounts(python_broker, accounts, spec.target, home, verify_checks=False)
    _install_vault_executor(python_broker, monkeypatch, home)

    python_broker.invoke(CRAWL_TOOL, {"target": spec.target, "max_pages": 1})
    ref = next(r["content_ref"] for r in python_broker.results if r["tool"] == SESSION_CHECK_TOOL)

    orig_open = os.open
    opened_parts = []

    def trace_open(path, flags, *oargs, **okwargs):
        opened_parts.append((str(path), "dir_fd" in okwargs, bool(flags & os.O_NOFOLLOW), bool(flags & os.O_DIRECTORY)))
        return orig_open(path, flags, *oargs, **okwargs)

    with monkeypatch.context() as mc:
        mc.setattr(os, "open", trace_open)
        assert python_broker.read_reference(ref)["status"] == "fresh"
    # Every component after '/' is opened via dir_fd with O_NOFOLLOW; all root/ancestor/archive dirs use O_DIRECTORY.
    assert len(opened_parts) == len(python_broker.workdir.parts) + 2
    assert all(nofollow for _, _, nofollow, _ in opened_parts)
    assert all(is_dir for _, _, _, is_dir in opened_parts[:-1])

    solver = PythonSolver(python_broker, model="model")
    solver.checkpoint.acquire()
    solver._checkpoint_active = True
    try:
        solver.save_checkpoint()
    finally:
        solver.checkpoint.release()

    python_broker.results.clear()
    python_broker.references.clear()
    solver.restore_checkpoint()
    assert python_broker._fresh_task_session_check(spec, {"target": spec.target, "identity": "member-a"}) is True
    assert python_broker.invoke(READ_TOOL, {"path": ref["path"], "offset": 0, "limit": 3000})["result"]["eof"] is True

    anchored_fd = python_broker._workdir_fd
    assert anchored_fd is not None
    python_broker.close()
    python_broker.close()  # Idempotent close without double-close OSError.
    assert python_broker._workdir_fd is None
    with pytest.raises(OSError) as fd_err:
        os.fstat(anchored_fd)
    assert fd_err.value.errno == errno.EBADF
