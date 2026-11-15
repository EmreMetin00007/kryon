"""Generic RC1/RC2/RC3 public/private operational contract regressions & equivalence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

import pytest

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
for rel in ("scripts", "mcp-servers/mcp-hunter", "mcp-servers/mcp-validator"):
    path = str(ROOT / rel)
    if path not in sys.path:
        sys.path.insert(0, path)

from cco_hunter_core.request_context import public_discovery_report  # noqa: E402
from campaign_runtime import CampaignRuntime  # noqa: E402
from campaign_worker import CampaignWorker  # noqa: E402
from policy_engine import PolicyEngine, ScopeResolver  # noqa: E402
from python_candidate_runtime import authorization_controls_complete  # noqa: E402
from test_private_public_value_projection import assert_absent  # noqa: E402


def _load_blind_validate():
    spec = importlib.util.spec_from_file_location("blind_validate_equiv", ROOT / "scripts" / "blind-validate.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_typed_subtree_contract_preserves_operational_enums_and_rejects_injections():
    """Fixed enums/bounded statuses survive only in typed containers; injections hash/strip."""
    secret = "synthetic-secret-marker-xyz"
    raw_url = "https://owned.test/orders/c534cae2-f5c9-41bc-b77a-de99aa2df907"
    digest_hex = hashlib.sha256(b"digest").hexdigest()
    vid = "a1b2c3d4e5f60718a1b2c3d4e5f60718"
    run_id = "run-a1b2c3d4e5f60718"

    payload = {
        "ok": True,
        "run_id": run_id,
        "target": raw_url,
        "steps": ["discover", "zap", "fuzz", "validate", "exploit"],
        "coverage_gap": {
            "status": "tested_clean",
            "fingerprint": digest_hex,
            "validation_id": vid,
            "coverage_recorded": True,
            "extra_secret": secret,
        },
        "replan": {
            "status": "blocked",
            "automatic_retry": False,
            "run_id": run_id,
            "note": "A run is not fully covered merely because no finding was confirmed.",
            "categories": ["budget", "rate_limit"],
            "actions": [
                {
                    "category": "budget",
                    "action": "review_budget",
                    "reason": "request or validation budget capped execution",
                },
                {
                    "category": "rate_limit",
                    "action": "wait_and_reassess",
                    "reason": f"leaked {secret}",
                },
            ],
        },
        "feedback_queue": [
            {
                "url": raw_url,
                "vuln_class": "bola",
                "identity": "member-a",
                "resource_owner": "member-b",
                "status": "tested_no_violation",
                "reason_code": "verified_validator_evidence",
                "next_action": "none",
                "preconditions": ["denied_role_rule", "owner_marker"],
                "hypothesis_fingerprint": digest_hex,
                "bound_refs": [digest_hex],
                "validation_id": vid,
                "candidate_source": "bounded_sampling",
            },
            {
                "url": raw_url,
                "status": f"confirmed {secret}",
                "reason_code": secret,
                "next_action": secret,
                "preconditions": [secret],
                "bound_refs": [secret],
            },
        ],
        "skipped": [
            {
                "step": "zap",
                "reason": "ZAP request-level policy unavailable",
                "preconditions": ["denied_role_rule"],
                "reason_code": "policy_blocked",
            },
            {
                "step": secret,
                "reason": f"blocked_custom {secret}",
                "preconditions": [f"denied_role_rule {secret}"],
            },
        ],
        "fuzz": {
            "fanout": [
                {"status": 404, "triage_verdict": "INCONCLUSIVE", "coverage_status": "not_tested", "next_action": "probe"},
                {"status": 200, "triage_verdict": "LIKELY", "coverage_status": "confirmed"},
                {"status": 999, "triage_verdict": secret, "coverage_status": "confirmed"},
                {"status": 99},
                {"status": 123456789},
            ],
            "candidate_sampling": {"limit": 4, "selected": 2},
        },
        "crawl": {"ok": True, "page_count": 3, "ingested": 5},
        "validations": [
            {"url": raw_url, "vuln_class": "bola", "verdict": "UNCONFIRMED", "hook": "authz_oracle", "validation_id": vid}
        ],
        "validation_candidates": [],
        # Adversarial / negative control injections outside valid typed containers:
        "untrusted_state": "ready",
        "untrusted_container": {"status": "confirmed", "next_action": "none", "reason": "ZAP request-level policy unavailable"},
        "other": 123456789,
        "owner_marker": secret,
        "identity_facts": [{"value": secret}],
        "request_fields": {"token": secret},
        "headers": {"Authorization": f"Bearer {secret}"},
    }

    projected = public_discovery_report(payload, strict=True)
    assert projected == public_discovery_report(projected, strict=True)

    # All secrets and private structural keys are stripped or opaque-hashed.
    assert_absent(projected, secret)
    assert_absent(projected, "c534cae2-f5c9-41bc-b77a-de99aa2df907")
    for private_key in ("owner_marker", "identity_facts", "request_fields", "headers", "untrusted_state", "untrusted_container", "other"):
        assert private_key not in projected
    dumped = json.dumps(projected)
    assert '"ready"' not in dumped
    assert "123456789" not in dumped
    assert "999" not in dumped
    assert projected["run_id"] == run_id

    # Valid typed metadata survives cleanly in exact context.
    assert projected["steps"] == ["discover", "zap", "fuzz", "validate", "exploit"]
    assert projected["coverage_gap"]["status"] == "tested_clean"
    assert projected["coverage_gap"]["validation_id"] == vid
    assert projected["replan"]["status"] == "blocked"
    assert projected["replan"]["note"] == "A run is not fully covered merely because no finding was confirmed."
    assert projected["replan"]["categories"] == ["budget", "rate_limit"]
    assert projected["replan"]["actions"][0] == {
        "category": "budget",
        "action": "review_budget",
        "reason": "request or validation budget capped execution",
    }
    assert projected["replan"]["actions"][1]["reason"].startswith("opaque:")

    fb0, fb1 = projected["feedback_queue"]
    assert fb0["status"] == "tested_no_violation"
    assert fb0["reason_code"] == "verified_validator_evidence"
    assert fb0["next_action"] == "none"
    assert fb0["preconditions"] == ["denied_role_rule", "owner_marker"]
    assert fb0["identity"] == "member-a" and fb0["resource_owner"] == "member-b"
    assert fb0["hypothesis_fingerprint"] == digest_hex
    assert fb0["bound_refs"] == [digest_hex]
    assert fb0["url_sha256"] == hashlib.sha256(raw_url.encode()).hexdigest()
    assert "{value}" in fb0["url"]
    assert fb1["status"].startswith("opaque:")
    assert fb1["reason_code"].startswith("opaque:")
    assert fb1["next_action"].startswith("opaque:")
    assert fb1["preconditions"][0].startswith("opaque:")
    assert fb1["bound_refs"][0].startswith("opaque:")

    assert projected["skipped"][0]["step"] == "zap"
    assert projected["skipped"][0]["preconditions"] == ["denied_role_rule"]
    assert projected["skipped"][1]["step"].startswith("opaque:")
    assert projected["skipped"][1]["reason"].startswith("opaque:")

    fanout = projected["fuzz"]["fanout"]
    assert fanout[0]["status"] == 404 and fanout[1]["status"] == 200
    assert str(fanout[2]["status"]).startswith("opaque:")
    assert str(fanout[3]["status"]).startswith("opaque:")
    assert str(fanout[4]["status"]).startswith("opaque:")
    assert projected["fuzz"]["candidate_sampling"] == {"limit": 4, "selected": 2}
    assert projected["crawl"] == {"ok": True, "page_count": 3, "ingested": 5}
    assert projected["validations"][0]["hook"] == "authz_oracle"


@pytest.mark.parametrize("clean", [True, False])
def test_campaign_worker_resume_preserves_clean_confirmed_gap_and_private_controls(tmp_path, monkeypatch, clean):
    """Blocked gap resumes via CampaignWorker to done while keeping exact private URL/controls."""
    import requests
    from cco_hunter_core.campaign_gaps import versions
    from cco_hunter_core.gap_queue import plan_gaps
    from cco_validator_core import artifact_is_current

    home = tmp_path / "home"
    base = "https://owned.test/allowed/"
    uuid_path = "5080c899-12bf-4523-89ce-d91a5ce3d1f4"
    target_url = f"{base}api/orders/{uuid_path}"
    marker = "private-synthetic-order-canary"
    scope = tmp_path / "scope.json"
    policy = tmp_path / "policy.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": base}]}))
    policy.write_text(json.dumps({
        "required_request_headers": {"X-Research": "researcher"},
        "blind_discovery": {"synthetic_accounts_only": True, "owned_objects_private": True},
    }))
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    monkeypatch.delenv("CCO_SCOPE_REVISION", raising=False)
    monkeypatch.delenv("CCO_POLICY_HASH", raising=False)

    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
    engine.grant_approval("hunter_run_web_loop", "owned.test", ttl_seconds=600, reason="synthetic")
    hunter = load_server("hunter")
    from cco_surface_core import session_store

    runtime = CampaignRuntime(str(home))
    campaign = runtime.create_campaign("synthetic", scope_file=str(scope), budget_requests=24)

    bindings = {}
    for label in ("alice", "bob"):
        session_store.put_session(
            base, label, cookies={"sid": f"{label}-synthetic-secret"},
            headers={"X-Research": "researcher"}, check_url=f"{base}me", marker=f"{label}-acct",
        )
        session_store.refresh_status(base, label, lambda *a, actor=label: (200, f"{actor}-acct"))
        bindings[label] = {
            "target": base, "role": "member", "test_data_only": True, "owned_objects_private": True,
        }
    bindings_json = json.dumps(bindings)

    run_id = "run-0123456789abcdef"
    item = {
        "url": target_url, "method": "GET", "location": "query", "vuln_class": "bola",
        "param": "", "identity": "bob", "owner_identity": "alice", "attacker_identity": "bob",
        "resource_owner": "alice", "owner_role": "member", "attacker_role": "member",
        "owner_marker": marker, "authz_candidate": True, "owned_object": True, "run_id": run_id,
    }
    assert hunter._record_coverage_plan(base, item)
    gap = {
        "endpoint": hunter._coverage_url(target_url), "vuln_class": "bola",
        **{k: hunter._coverage_context(item)[k] for k in ("method", "param", "carrier", "identity", "resource_owner", "run_id")},
    }
    assert plan_gaps(hunter.MEM_DB, base, [gap], ScopeResolver(), versions()[0])[0][0]["fingerprint"]

    scheduled = runtime.schedule_coverage_gaps(
        campaign, base, headers='{"X-Research":"researcher"}', session_bindings=bindings_json,
        request_cost=4, run_id=run_id,
    )
    assert len(scheduled["scheduled"]) == 1

    # Phase 1: owner check succeeds, attacker session expires (401) -> blocked worker state.
    calls = []

    def wire_phase1(method, url, **kwargs):
        assert method == "GET" and url == target_url
        cookie = (kwargs.get("headers") or {}).get("Cookie", "")
        calls.append(cookie)
        resp = type("Resp", (), {"headers": {}})()
        if "alice" in cookie:
            resp.status_code, resp.text = 401, "session expired"
        else:
            resp.status_code, resp.text = 200, marker
        resp.content = resp.text.encode()
        return resp

    monkeypatch.setattr(requests, "request", wire_phase1)
    outputs = []

    def exec_task(task):
        monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", str(task["reserved_request_cost"]))
        raw = hunter.run_web_loop(**json.loads(task["args_json"]))
        parsed = json.loads(raw)
        outputs.append(parsed)
        return {"result": {"mode": "local_mcp", "output": raw}, "actual_request_cost": parsed["requests_authorized"]}

    w = CampaignWorker(runtime, "worker-reg", exec_task)
    first = w.run_once(campaign)
    assert first["status"] == "blocked"
    assert len(calls) >= 1
    assert outputs[-1]["coverage_gap"]["status"] == "inconclusive"
    assert outputs[-1]["replan"]["status"] in {"blocked", "incomplete"}
    assert uuid_path not in json.dumps(outputs[-1]) and marker not in json.dumps(outputs[-1])

    # Phase 2: resume with clean or confirmed response and verify final state + private controls.
    for label in ("alice", "bob"):
        session_store.refresh_status(base, label, lambda *a, actor=label: (200, f"{actor}-acct"))
    resumed = runtime.resume_coverage_gaps(campaign, base, run_id=run_id)
    assert len(resumed["resumed"]) == 1 or runtime.list_tasks(campaign)[0]["status"] == "pending"

    def wire_phase2(method, url, **kwargs):
        assert method == "GET" and url == target_url
        cookie = (kwargs.get("headers") or {}).get("Cookie", "")
        resp = type("Resp", (), {"headers": {}})()
        if "alice" in cookie:
            resp.status_code, resp.text = 200, marker
        elif clean or not cookie:
            resp.status_code, resp.text = 403, "denied"
        else:
            resp.status_code, resp.text = 200, marker
        resp.content = resp.text.encode()
        return resp

    monkeypatch.setattr(requests, "request", wire_phase2)
    second = w.run_once(campaign)
    assert second["status"] == "done"
    final_report = outputs[-1]
    expected_gap_status = "tested_clean" if clean else "confirmed"
    expected_fb_status = "tested_no_violation" if clean else "confirmed"
    assert final_report["coverage_gap"]["status"] == expected_gap_status
    assert final_report["coverage_gap"]["coverage_recorded"] is True
    assert any(row["status"] == expected_fb_status for row in final_report["feedback_queue"])

    raw_dump = json.dumps(final_report)
    assert uuid_path not in raw_dump and marker not in raw_dump and "synthetic-secret" not in raw_dump

    vid = final_report["coverage_gap"]["validation_id"]
    artifact = hunter.load_validation(vid)
    assert artifact and artifact_is_current(artifact)
    assert artifact["target"] == target_url
    assert artifact["verdict"] == ("UNCONFIRMED" if clean else "CONFIRMED")
    assert authorization_controls_complete(artifact)


def test_blind_validate_public_private_equivalence_without_aliasing():
    """Projected loop + url_sha256 gives exact same blind-validate score without aliasing."""
    scorer = _load_blind_validate()
    target = "http://127.0.0.1:49999"
    run_id = "run-0123456789abcdef"
    order_a = f"{target}/orders/5080c899-12bf-4523-89ce-d91a5ce3d1f4"
    order_b = f"{target}/orders/c534cae2-f5c9-41bc-b77a-de99aa2df907"
    order_c = f"{target}/orders/11111111-2222-3333-4444-555555555555"
    safe_a = f"{target}/safe/a"
    search_item = f"{target}/item?q=1"

    truth = [
        {"case": "bola-a", "expected": "positive", "path": urlsplit(order_a).path, "class": "bola",
         "method": "GET", "param": "", "carrier": "", "actor": "member-b", "owner": "member-a"},
        {"case": "ctrl-b", "expected": "negative", "path": urlsplit(order_b).path, "class": "bola",
         "method": "GET", "param": "", "carrier": "", "actor": "member-a", "owner": "member-b"},
        {"case": "ctrl-c-untested", "expected": "negative", "path": urlsplit(order_c).path, "class": "bola",
         "method": "GET", "param": "", "carrier": "", "actor": "member-a", "owner": "member-c"},
        {"case": "sqli-safe", "expected": "positive", "path": "/safe/a", "class": "sql_injection",
         "method": "POST", "param": "id", "carrier": "json"},
        {"case": "sqli-item", "expected": "positive", "path": "/item", "class": "sql_injection",
         "method": "GET", "param": "q", "carrier": "query"},
    ]
    inventory = {
        "run_id": run_id,
        "source": "isolated_run_surface_snapshot",
        "complete": True,
        "records": [
            {"url": order_a, "method": "GET"},
            {"url": order_b, "method": "GET"},
            {"url": order_c, "method": "GET"},
            {"url": safe_a, "method": "POST"},
            {"url": search_item, "method": "GET"},
        ],
    }
    events = [
        {"schema": "hunter-coverage/1", "run_id": run_id, "url": order_a, "vuln_class": "bola",
         "method": "GET", "param": "", "carrier": "", "identity": "member-b", "resource_owner": "member-a",
         "status": "confirmed", "validation_id": "a" * 32},
        {"schema": "hunter-coverage/1", "run_id": run_id, "url": order_b, "vuln_class": "bola",
         "method": "GET", "param": "", "carrier": "", "identity": "member-a", "resource_owner": "member-b",
         "status": "tested_clean", "validation_id": "b" * 32},
    ]
    raw_loop = {
        "target": target,
        "run_id": run_id,
        "ok": True,
        "discovery_operations": [{"url": search_item, "method": "GET", "run_id": run_id}],
        "validation_candidates": [
            {"url": order_a, "method": "GET", "vuln_class": "bola", "param": "", "carrier": "", "run_id": run_id},
            {"url": safe_a, "method": "POST", "vuln_class": "sql_injection", "param": "id", "location": "json", "run_id": run_id},
        ],
        "validation_queue": [
            {"url": safe_a, "method": "POST", "vuln_class": "sql_injection", "param": "id", "location": "json", "run_id": run_id},
        ],
        "validations": [
            {"url": order_a, "method": "GET", "vuln_class": "bola", "param": "", "carrier": "",
             "identity": "member-b", "resource_owner": "member-a", "validation_id": "a" * 32},
            {"url": order_b, "method": "GET", "vuln_class": "bola", "param": "", "carrier": "",
             "identity": "member-a", "resource_owner": "member-b", "validation_id": "b" * 32},
        ],
        "skipped": [{"url": safe_a, "method": "POST", "vuln_class": "sql_injection", "param": "id",
                     "carrier": "json", "reason": "max_validations", "run_id": run_id}],
        "fuzz": {"likely_hits": [], "validator_queue": [], "fanout": []},
    }
    public_loop = public_discovery_report(raw_loop, strict=True)
    # Public loop must hide raw UUIDs and /safe/a segments via templates while preserving url_sha256.
    public_json = json.dumps(public_loop)
    assert "5080c899-12bf-4523-89ce-d91a5ce3d1f4" not in public_json
    assert "/safe/a" not in public_json

    private_score = scorer.evaluate(truth, raw_loop, verified_coverage=events, surface_inventory=inventory)
    public_score = scorer.evaluate(truth, public_loop, verified_coverage=events, surface_inventory=inventory)
    assert public_score == private_score

    # Non-aliasing guarantee: ctrl-c-untested shares identical public template `/orders/{value}`
    # with order_a yet stays candidate_generated=False and result="not_tested".
    cases_pub = {c["case"]: c for c in public_score["cases"]}
    assert cases_pub["bola-a"]["pipeline"]["candidate_generated"] is True
    assert cases_pub["ctrl-b"]["result"] == "clean"
    assert cases_pub["ctrl-c-untested"]["pipeline"]["candidate_generated"] is False
    assert cases_pub["ctrl-c-untested"]["result"] == "not_tested"
    assert cases_pub["sqli-safe"]["loss_stage"] == "validation_budget"
    assert cases_pub["sqli-item"]["pipeline"]["surface_observed"] is True
