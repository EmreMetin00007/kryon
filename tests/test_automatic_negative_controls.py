"""Observed surfaces → bounded controls → signed coverage, with no solver truth.

Transport is the versioned lab handler in memory. Access rules and application
file declarations are explicit operator inputs; no candidate queue is injected.
"""
import json
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit

import pytest
import requests

from conftest import load_server
from test_campaign_gap_bridge import CampaignRuntime, CampaignWorker, PolicyEngine, ScopeResolver
from test_negative_coverage import scorer

BASE = "https://owned.test/"
HEADERS = {"X-Research": "researcher"}
SEEDS = [20261104, 20261105, 20261106, 20261107, 20261108]


def campaign_environment(tmp_path, monkeypatch, *, base=BASE, fast=True):
    scope, policy = tmp_path / "scope.json", tmp_path / "policy.json"
    home = tmp_path / "home"
    scope.write_text(json.dumps({"in_scope": [{"asset": base}], "allow_loopback": False,
                                 "allow_osint": False, "allow_public_labs": False}))
    policy.write_text(json.dumps({
        "required_request_headers": HEADERS,
        "rate_limits": {"default": {"window_seconds": 60, "max_calls": 1000},
                        "conservative": {"window_seconds": 60, "max_calls": 1000}},
        "blind_discovery": {"synthetic_accounts_only": True, "owned_objects_private": True},
        "path_traversal": {"mode": "application_files", "files": [
            {"url": base + path, "param": "name", "carrier": "query", "path": "../secret.txt",
             "marker": "root:x:0:0:synthetic:/root:/bin/bash", "test_data_only": True, "outside_root": True}
            for path in ("file", "safe/file")]},
    }))
    for name, value in {"CCO_HOME": home, "CCO_SCOPE_FILE": scope, "CCO_PROGRAM_POLICY_FILE": policy,
                        "CCO_GRAPH_BACKEND": "networkx", "CCO_HUNTER_ENABLE_LLM": "0",
                        "CCO_STUCK_THRESHOLD": "10000", "CCO_CAMPAIGN_WIRE_BUDGET": "300"}.items():
        monkeypatch.setenv(name, str(value))
    monkeypatch.delenv("CCO_SCOPE_REVISION", raising=False)
    monkeypatch.delenv("CCO_POLICY_HASH", raising=False)
    if fast:
        monkeypatch.setattr(time, "sleep", lambda _: None)
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
    for tool in ("hunter_run_web_loop", "validator_session_vault_check"):
        engine.grant_approval(tool, urlsplit(base).hostname, ttl_seconds=900, reason="test-owned lab")
    return load_server("hunter"), home, scope


@pytest.fixture
def environment(tmp_path, monkeypatch):
    return campaign_environment(tmp_path, monkeypatch)


def transport(monkeypatch, handler):
    calls = []

    def request(session, method, url, **kwargs):
        assert method.upper() == "GET" and url.startswith(BASE)
        assert kwargs.get("allow_redirects") is False
        assert (kwargs.get("headers") or {}).get("X-Research") == "researcher"
        if kwargs.get("params"):
            url += ("&" if "?" in url else "?") + urlencode(kwargs["params"], doseq=True)
        parsed = urlsplit(url)
        instance = handler.__new__(handler)
        instance.path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        instance.headers = kwargs.get("headers") or {}
        response = requests.Response()
        response.url, response.encoding, response._content_consumed = url, "utf-8", True

        def send(code, body, ctype="text/html", extra=None):
            response.status_code = code
            response._content = body.encode() if isinstance(body, str) else body
            response.headers.update({"Content-Type": ctype, **(extra or {})})

        instance._send = send
        instance.do_GET()
        calls.append(url)
        return response

    monkeypatch.setattr(requests.Session, "request", request)
    return calls


def prepare_sessions(hunter, accounts, *, base=BASE):
    """Read operator-owned resources and bind their observed markers to vaults.

    The operator supplies access expectations, never which routes are vulnerable
    or which tests should be queued. Objects/UUIDs are left to blind discovery.
    """
    from cco_hunter_core.request_context import policy_scoped
    from cco_surface_core import session_store
    validator = hunter._load_peer("validator_web_loop", "mcp-validator")

    @policy_scoped("hunter_run_web_loop")
    def observe(path, headers):
        result = hunter._blind_discovery_get(base + path, headers)
        assert result.get("ok") and result["status"] == 200
        return result["text"]

    bindings = {}
    for label, account in accounts.items():
        headers = {**HEADERS, "Authorization": "Bearer " + account["token"]}
        session_store.put_session(base, label, headers=headers, check_url=base, marker=label)
        declarations = {"role": account["role"]}
        if label == "admin-a":
            declarations["functions"] = []
            for path, field in (("admin/users", "users"), ("admin/export", "export")):
                body = json.loads(observe(path, headers))
                marker = body[field][0] if isinstance(body[field], list) else body[field]
                declarations["functions"].append({"url": base + path, "marker": marker,
                    "test_data_only": True, "denied_roles": ["member"]})
        if label == "member-a":
            declarations["protected_resources"] = []
            for path, field in (("account/settings", "settings"), ("account/statement", "statement")):
                marker = json.loads(observe(path, headers))[field]
                declarations["protected_resources"].append({"url": base + path, "marker": marker,
                    "test_data_only": True, "authentication_required": True})
        session_store.bind_resources(base, label, declarations, permits=ScopeResolver().permits_url)
        checked = json.loads(validator.session_vault_check(base, label))
        assert checked["status"] == "fresh", checked
        bindings[label] = {"target": base, "role": account["role"], "test_data_only": True,
                           "owned_objects_private": True}
    return json.dumps(bindings)


def run_observed(hunter, bindings, *, base=BASE, **options):
    return json.loads(hunter.run_web_loop(base, live=True, crawl=False, headers=json.dumps(HEADERS),
        session_bindings=bindings, blind_discovery=True, blind_max_requests=40,
        fuzz_limit=32, candidate_sample_limit=20, max_validations=options.pop("max_validations", 30),
        sleep_s=0, **options))


@pytest.mark.parametrize("seed", SEEDS)
def test_automatically_selected_negative_controls(environment, monkeypatch, tmp_path, seed):
    from scripts.lab.blind_lab import make_lab
    from scripts.lab.blind_agent_run import benchmark_payload

    hunter, *_ = environment
    handler, state = make_lab(seed, version="blind-lab/2")
    try:
        calls = transport(monkeypatch, handler)
        bindings = prepare_sessions(hunter, state["accounts"])
        preparation_requests = len(calls)
        monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", str(300 - preparation_requests))
        result = run_observed(hunter, bindings)
        assert result["ok"], {key: result.get(key) for key in ("errors", "stopped", "skipped")}
        assert result["requests_authorized"] == len(calls) - preparation_requests
        assert len(calls) <= 300
        exported = benchmark_payload(hunter, result, BASE)
        # Truth is first consulted here, after discovery and all validation.
        score = scorer().evaluate(state["truth"], result, verified_coverage=exported["verified_coverage"])
        assert score["negatives_evaluated"] == score["negatives_clean"] == 8, score
        assert score["negative_coverage"] == 1 and score["fp_rate"] == 0
        assert all(case["validation_ids"] for case in score["cases"] if case["expected"] == "negative")
        clean_ids = {event["validation_id"] for event in exported["verified_coverage"]
                     if event["status"] == "tested_clean"}
        assert clean_ids <= {row["validation_id"] for row in result["feedback_queue"]
                             if row["status"] == "tested_no_violation"}
        sampled = [row for row in result["validation_candidates"] if row.get("candidate_source") == "bounded_sampling"]
        assert {"xss_reflected", "open_redirect"} <= {row["vuln_class"] for row in sampled}
        assert all(row["identity"] == "member-a" for row in result["validations"]
                   if row["vuln_class"] in {"sql_injection", "xss_reflected", "ssti", "open_redirect", "path_traversal"})
        assert all(account["token"] not in json.dumps(exported) for account in state["accounts"].values())
        for path in (Path(environment[1]) / "artifacts" / "surface").glob("exploit-*.json"):
            assert all(account["token"] not in path.read_text() for account in state["accounts"].values())
        (tmp_path / "automatic-negative-controls.json").write_text(json.dumps({
            "lab_version": state["lab_version"], "mode": "observed_surfaces_with_declared_test_resources",
            "seed": seed, "preparation_requests": preparation_requests, "requests": len(calls), "score": score}, indent=2))
    finally:
        state["db"].close()


def assert_observed_campaign_controls(environment, monkeypatch, tmp_path, seed, state, calls,
                                     *, base=BASE, before_discovery=None, mode="in_memory"):
    """One acceptance contract shared by synthetic and real transports."""
    from scripts.lab.blind_agent_run import benchmark_payload

    hunter, home, scope = environment
    bindings = prepare_sessions(hunter, state["accounts"], base=base)
    preparation_requests = len(calls)
    browser_requests = before_discovery(bindings) if before_discovery else 0
    monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", str(300 - len(calls)))
    source = run_observed(hunter, bindings, base=base, max_validations=0)
    assert source["ok"] and source["validation_queue"] and not source["validations"]
    assert source["requests_authorized"] == len(calls) - preparation_requests - browser_requests
    assert not hunter._verified_coverage_events(base)
    source_requests = len(calls)
    runtime = CampaignRuntime(str(home))
    campaign = runtime.create_campaign("automatic-negative-controls", scope_file=str(scope),
                                       budget_requests=300 - source_requests)
    reports = []

    def execute(task):
        monkeypatch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", str(task["reserved_request_cost"]))
        report = json.loads(hunter.run_web_loop(**json.loads(task["args_json"])))
        reports.append(report)
        return {"result": {"mode": "local_mcp", "output": json.dumps(report)},
                "actual_request_cost": report["requests_authorized"]}

    worker = CampaignWorker(runtime, "negative-control-worker", execute)
    scheduled_ids = set()
    for step in range(40):
        scheduled = runtime.schedule_coverage_gaps(campaign, base, session_bindings=bindings,
            request_cost=30, limit=100, run_id=source["run_id"])
        scheduled_ids.update(row["task_id"] for row in scheduled["scheduled"])
        tasks = runtime.list_tasks(campaign)
        if not any(task["status"] == "pending" for task in tasks):
            break
        worker.run_once(campaign)
        if step in {1, 3}:
            before = runtime.show_campaign(campaign)
            task_state = [(task["id"], task["args_json"], task["attempts"], task["status"])
                          for task in runtime.list_tasks(campaign)]
            runtime = CampaignRuntime(str(home))
            worker = CampaignWorker(runtime, "negative-control-worker", execute)
            after = runtime.show_campaign(campaign)
            assert [(task["id"], task["args_json"], task["attempts"], task["status"])
                    for task in runtime.list_tasks(campaign)] == task_state
            assert all(after[key] == before[key] for key in ("requests_used", "requests_reserved"))
    else:
        pytest.fail("bounded automatic campaign did not settle")
    assert scheduled_ids and reports, scheduled
    assert runtime.show_campaign(campaign)["requests_used"] == len(calls) - source_requests
    assert len(calls) <= 300
    merged = {**source, "validations": [row for report in reports for row in report["validations"]],
              "confirmed": [row for report in reports for row in report["confirmed"]]}
    exported = benchmark_payload(hunter, merged, base)
    score = scorer().evaluate(state["truth"], merged, verified_coverage=exported["verified_coverage"])
    assert score["negatives_clean"] == score["negatives_evaluated"] == 8, score
    assert score["proven"] >= 6 and score["positives"] == 8, score
    assert score["fp_rate"] == 0 and score["negative_coverage"] == 1
    clean_reports = [report for report in reports if report["coverage_gap"]["status"] == "tested_clean"]
    assert clean_reports and all(report["feedback_queue"] for report in clean_reports)
    assert all(report["run_id"] == source["run_id"] for report in reports)
    assert all(report["steps"] == ["validate_coverage_gap"] for report in reports)
    clean_refs = {report["coverage_gap"]["fingerprint"] for report in clean_reports}
    assert all(task["status"] == "done" for task in runtime.list_tasks(campaign)
               if json.loads(task["args_json"])["gap_ref"] in clean_refs)
    tasks = runtime.list_tasks(campaign)
    assert len(tasks) == len(scheduled_ids) == len({task["idempotency_key"] for task in tasks})
    assert all(json.loads(task["args_json"])["headers"] == "" for task in tasks)
    assert all(account["token"] not in json.dumps(tasks) for account in state["accounts"].values())
    assert runtime.show_campaign(campaign)["requests_reserved"] == 0
    assert not runtime.schedule_coverage_gaps(campaign, base, session_bindings=bindings,
        request_cost=30, limit=100, run_id=source["run_id"])["scheduled"]
    payload = {
        "lab_version": state["lab_version"], "seed": seed, "mode": mode, "requests": len(calls),
        "preparation_requests": preparation_requests, "browser_requests": browser_requests,
        "discovery_requests": source_requests - preparation_requests - browser_requests,
        "campaign_requests": len(calls) - source_requests, "tasks": len(scheduled_ids), "score": score}
    assert payload["requests"] == sum(payload[key] for key in (
        "preparation_requests", "browser_requests", "discovery_requests", "campaign_requests"))
    (tmp_path / "automatic-campaign-controls.json").write_text(json.dumps(payload, indent=2))
    return payload


@pytest.mark.parametrize("seed", SEEDS)
def test_observed_controls_resume_as_campaign_tasks(environment, monkeypatch, tmp_path, seed):
    from scripts.lab.blind_lab import make_lab

    handler, state = make_lab(seed, version="blind-lab/2")
    try:
        calls = transport(monkeypatch, handler)
        assert_observed_campaign_controls(environment, monkeypatch, tmp_path, seed, state, calls)
    finally:
        state["db"].close()
