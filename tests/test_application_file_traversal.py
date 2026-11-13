"""Declared synthetic file reads with real adapters and no network sockets."""
import copy
import importlib.util
import json
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
import requests

from conftest import load_server
from test_campaign_gap_bridge import BASE, plan, setup  # noqa: F401
from test_access_resource_resume import worker

ENDPOINT = BASE + "file"
URL = ENDPOINT + "?name=notes.txt&tenant=7"
FILE = "../private/traversal-canary.txt"
MARKER = "synthetic-application-file-marker-7391"
HEADERS = '{"X-Research":"researcher"}'


def rule(*, endpoint=ENDPOINT, carrier="query", path=FILE):
    return {"mode": "application_files", "files": [{"url": endpoint, "param": "name", "carrier": carrier,
        "path": path, "marker": MARKER, "test_data_only": True, "outside_root": True}]}


def configure(setup, declared=None):
    policy = setup[4]
    current = json.loads(policy.read_text())
    current["path_traversal"] = rule() if declared is None else declared
    policy.write_text(json.dumps(current))


def item(url=URL, carrier="query"):
    return {"url": url, "method": "GET", "param": "name", "location": carrier,
            "vuln_class": "path_traversal", "identity": "anonymous", "run_id": "source-run"}


def wire(monkeypatch, *, behavior="vulnerable", faults=None, carrier="query", on_response=None):
    calls, probes = [], [0]

    def request(method, url, **kwargs):
        assert method == "GET"
        parsed = urlsplit(url)
        assert parsed.scheme == "https" and parsed.netloc == "owned.test"
        assert (kwargs.get("headers") or {}).get("X-Research") == "researcher"
        if carrier == "query":
            query = parse_qs(parsed.query)
            assert parsed.path == "/allowed/file" and query["tenant"] == ["7"]
            value = query["name"][0]
        else:
            assert parsed.path.startswith("/allowed/download/")
            value = unquote(parsed.path.removeprefix("/allowed/download/"))
        role = ("baseline" if value == "notes.txt" else "direct-name" if value == FILE.rsplit("/", 1)[1]
                else "missing-file" if "cco-missing-" in value else "traversal-probe")
        if role == "traversal-probe":
            probes[0] += 1
            if probes[0] > 1:
                role = "traversal-repeat"
        calls.append((role, value, url))
        if role == "baseline":
            status, body = 200, "application note"
        elif role in {"traversal-probe", "traversal-repeat"}:
            status, body = (200, MARKER) if behavior != "safe" else (403, "path rejected")
        else:
            status, body = 404, "no file"
        if behavior == "static" or (behavior == "basename" and role == "direct-name") or (
                behavior == "wildcard" and role == "missing-file"):
            status, body = 200, MARKER
        if behavior == "flaky" and role == "traversal-repeat":
            status, body = 404, "no file"
        if role in (faults or {}):
            status, body = faults[role]
        if status is None:
            raise requests.ConnectionError("synthetic file transport failure")
        response = requests.Response()
        response.status_code, response._content, response.encoding = status, body.encode(), "utf-8"
        response.headers["Content-Type"] = "text/plain"
        if on_response:
            on_response(role)
        return response

    monkeypatch.setattr(requests, "request", request)
    return calls


def validate(hunter, candidate=None):
    raw = hunter._loop_validate(item() if candidate is None else candidate, headers=HEADERS)
    return json.loads(raw) if isinstance(raw, str) else raw


@pytest.mark.parametrize("behavior,verdict", [("vulnerable", "CONFIRMED"), ("safe", "UNCONFIRMED")])
def test_application_file_controls_produce_current_signed_coverage(setup, monkeypatch, behavior, verdict):
    hunter, *_ = setup
    configure(setup)
    calls = wire(monkeypatch, behavior=behavior)
    result = validate(hunter)
    assert result["verdict"] == verdict and len(calls) == 5
    assert [role for role, *_ in calls] == ["baseline", "direct-name", "missing-file", "traversal-probe", "traversal-repeat"]
    assert [e["role"] for e in result["request_evidence"]] == [role for role, *_ in calls]
    assert all(e["method"] == "GET" and e["transport_ok"] and not e["excerpt"] for e in result["request_evidence"])
    assert MARKER not in json.dumps(result)
    assert hunter._record_coverage_validation(BASE, item(), result)
    events = hunter._verified_coverage_events(BASE)
    assert len(events) == 1 and events[0]["status"] == ("confirmed" if verdict == "CONFIRMED" else "tested_clean")
    assert load_server("validator").artifact_is_valid(result)
    assert all("passwd" not in value and "win.ini" not in value for _, value, _ in calls)


@pytest.mark.parametrize("behavior,count", [("static", 1), ("basename", 2), ("wildcard", 3), ("flaky", 5)])
def test_static_public_wildcard_and_unstable_content_cannot_confirm(setup, monkeypatch, behavior, count):
    configure(setup)
    calls = wire(monkeypatch, behavior=behavior)
    result = validate(setup[0])
    assert result["verdict"] == "INCONCLUSIVE" and not result["reportable"] and len(calls) == count


@pytest.mark.parametrize("role,status", [
    ("baseline", 404), ("direct-name", 429), ("missing-file", 503),
    ("traversal-probe", None), ("traversal-repeat", 429), ("traversal-probe", 302),
    ("traversal-probe", 403),
])
def test_incomplete_controls_never_close_coverage(setup, monkeypatch, role, status):
    hunter, *_ = setup
    configure(setup)
    calls = wire(monkeypatch, faults={role: (status, MARKER if status == 403 else "error")})
    result = validate(hunter)
    assert result["verdict"] == "INCONCLUSIVE" and calls
    assert not result["guard"]["transport_ok"]
    assert hunter._record_coverage_validation(BASE, item(), result)
    assert not any(e["status"] in {"confirmed", "tested_clean"} for e in hunter._verified_coverage_events(BASE))


@pytest.mark.parametrize("change", [
    {"path": "/etc/passwd"}, {"path": "private/canary.txt"}, {"path": "../.env"},
    {"path": "../.ssh/canary.txt"}, {"path": "../private/canary.pem"},
    {"path": "..%2fprivate/canary.txt"}, {"path": "../private/../canary.txt"},
    {"marker": ""}, {"marker": "short"}, {"test_data_only": False}, {"outside_root": False},
    {"url": "https://outside.test/file"}, {"url": "https://owned.test/outside"},
    {"url": "http://owned.test/allowed/file"}, {"url": ENDPOINT + "#fragment"},
    {"carrier": "body"}, {"extra": True},
])
def test_invalid_declarations_send_no_requests(setup, monkeypatch, change):
    declared = rule()
    declared["files"][0].update(change)
    configure(setup, declared)
    calls = wire(monkeypatch)
    result = validate(setup[0])
    assert result["verdict"] == "INCONCLUSIVE" and calls == []


@pytest.mark.parametrize("declared", [{}, {"mode": "application_files", "files": []},
                                      {"mode": "application_files", "files": [rule()["files"][0]] * 3}])
def test_missing_or_over_budget_file_declarations_do_not_fall_back_to_system_files(setup, monkeypatch, declared):
    configure(setup, declared)
    calls = wire(monkeypatch)
    assert validate(setup[0])["verdict"] == "INCONCLUSIVE" and not calls


@pytest.mark.parametrize("file_index", [3, 4])
def test_scope_or_policy_change_during_controls_stops_before_next_request(setup, monkeypatch, file_index):
    configure(setup)
    path = setup[file_index]
    calls = wire(monkeypatch, on_response=lambda _: path.write_text(path.read_text() + "\n"))
    assert validate(setup[0])["verdict"] == "INCONCLUSIVE" and len(calls) == 1


@pytest.mark.parametrize("url", [ENDPOINT, ENDPOINT + "?name=", URL + "&name=other.txt"])
def test_missing_empty_or_ambiguous_baseline_never_sends_a_probe(setup, monkeypatch, url):
    configure(setup)
    calls = wire(monkeypatch)
    assert validate(setup[0], item(url))["verdict"] == "INCONCLUSIVE" and not calls


def test_path_carrier_uses_observed_sample_and_exact_reproduction(setup, monkeypatch):
    from cco_hunter_core.request_context import request_binding, store_context
    from cco_surface_core.fuzz import apply_canary

    endpoint = BASE + "download/{name}"
    configure(setup, rule(endpoint=endpoint, carrier="path"))
    record = {"url": endpoint, "method": "GET", "params": [{"name": "name", "in": "path", "sample": "notes.txt"}]}
    canary = apply_canary(record, "name", "path", "unused")
    assert canary["baseline_value"] == "notes.txt"
    candidate = item(endpoint, "path")
    context = {**candidate, "baseline_value": canary["baseline_value"], "binding": request_binding(json.loads(HEADERS))}
    candidate["request_ref"] = store_context(context)
    calls = wire(monkeypatch, carrier="path")
    result = validate(setup[0], candidate)
    assert result["verdict"] == "CONFIRMED" and len(calls) == 5
    assert "../private/traversal-canary.txt" == calls[-1][1]
    assert "%2Fprivate%2Ftraversal-canary.txt" in result["reproduction"][0]
    assert "{name}" not in result["reproduction"][0] and "?name=" not in result["reproduction"][0]
    assert setup[0]._record_coverage_validation(BASE, candidate, result)


@pytest.mark.parametrize("behavior,budget,expected", [("vulnerable", 5, "done"), ("safe", 5, "done"), ("vulnerable", 4, "blocked")])
def test_campaign_accounts_for_every_control_and_only_closes_completed_checks(setup, monkeypatch, behavior, budget, expected):
    hunter, runtime, campaign, *_ = setup
    configure(setup)
    _, ref = plan(hunter, url=URL, param="name", vuln_class="path_traversal")
    scheduled = runtime.schedule_coverage_gaps(campaign, BASE, headers=HEADERS, request_cost=budget)
    assert len(scheduled["scheduled"]) == 1 and scheduled["requests_sent"] == 0
    calls = wire(monkeypatch, behavior=behavior)
    reports = []
    out = worker(hunter, runtime, monkeypatch, reports).run_once(campaign)
    assert out["status"] == expected and len(calls) == budget
    assert runtime.show_campaign(campaign)["requests_used"] == len(calls)
    assert reports[0]["coverage_gap"]["fingerprint"] == ref
    assert reports[0]["coverage_gap"]["status"] == (
        "inconclusive" if expected == "blocked" else "confirmed" if behavior == "vulnerable" else "tested_clean")
    feedback = [row for row in reports[0]["feedback_queue"] if row["validation_id"] == reports[0]["coverage_gap"]["validation_id"]]
    assert len(feedback) == 1
    assert feedback[0]["status"] == (
        "inconclusive" if expected == "blocked" else "confirmed" if behavior == "vulnerable" else "tested_no_violation")
    assert "notes.txt" not in json.dumps(reports[0]) and "tenant=7" not in json.dumps(reports[0])


def test_completed_safe_file_control_gets_evaluator_credit_from_signed_evidence(setup, monkeypatch):
    hunter, *_ = setup
    configure(setup)
    wire(monkeypatch, behavior="safe")
    result = validate(hunter)
    assert hunter._record_coverage_validation(BASE, item(), result)
    scorer_path = Path(__file__).resolve().parents[1] / "scripts" / "blind-validate.py"
    spec = importlib.util.spec_from_file_location("traversal_score", scorer_path)
    scorer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scorer)
    score = scorer.evaluate([{"case": "controlled-file", "expected": "negative", "class": "path_traversal",
                             "path": "/allowed/file", "owner": None, "actor": None}],
        {"target": BASE, "run_id": "source-run", "ok": True}, verified_coverage=hunter._verified_coverage_events(BASE))
    assert score["negatives_clean"] == score["negatives_evaluated"] == 1
    assert score["cases"][0]["validation_ids"] == [result["validation_id"]]


def test_two_declared_files_share_one_baseline_and_stay_within_nine_requests(setup, monkeypatch):
    declared = rule()
    second = {**declared["files"][0], "path": "../private/second-canary.txt"}
    declared["files"].append(second)
    configure(setup, declared)
    calls = wire(monkeypatch, behavior="safe")
    result = validate(setup[0])
    assert result["verdict"] == "UNCONFIRMED" and result["evidence"]["application_files_tested"] == 2
    assert len(calls) == len(result["request_evidence"]) == 9
    assert sum(row["role"] == "baseline" for row in result["request_evidence"]) == 1


@pytest.mark.parametrize("failure", [None, 429, 503])
def test_legacy_signature_corpus_requires_complete_controls(setup, monkeypatch, failure):
    calls = []

    def request(method, url, **kwargs):
        value = parse_qs(urlsplit(url).query)["name"][0]
        calls.append(value)
        assert method == "GET"
        if value == "notes.txt":
            status, text = 200, "application note"
        else:
            status, text = (404, "no file") if failure is None else (failure, "error")
        response = requests.Response()
        response.status_code, response._content, response.encoding = status, text.encode(), "utf-8"
        return response

    monkeypatch.setattr(requests, "request", request)
    result = validate(setup[0])
    assert calls[0] == "notes.txt" and "index" not in calls
    assert result["verdict"] == ("UNCONFIRMED" if failure is None else "INCONCLUSIVE")
    assert len(calls) == (9 if failure is None else 2)
    assert len(result["request_evidence"]) == len(calls)
    assert setup[0]._record_coverage_validation(BASE, item(), result)
    events = setup[0]._verified_coverage_events(BASE)
    assert events[0]["status"] == ("tested_clean" if failure is None else "inconclusive")


def test_original_blind_lab_basename_read_is_not_promoted_to_traversal(setup, monkeypatch):
    from scripts.lab.blind_lab import make_lab

    handler, state = make_lab(20261103)
    declared = rule(path="../secret.txt")
    declared["files"][0]["marker"] = "root:x:0:0:synthetic:/root:/bin/bash"
    configure(setup, declared)
    calls = []

    def request(method, url, **kwargs):
        assert method == "GET"
        instance = handler.__new__(handler)
        parsed = urlsplit(url)
        assert parsed.path == "/allowed/file"
        instance.path = "/file?" + parsed.query
        instance.headers = kwargs.get("headers") or {}
        response = requests.Response()
        response.encoding = "utf-8"

        def send(code, body, ctype="text/html", extra=None):
            response.status_code, response._content = code, body.encode()
            response.headers.update({"Content-Type": ctype, **(extra or {})})

        instance._send = send
        instance.do_GET()
        calls.append(parse_qs(parsed.query)["name"][0])
        return response

    monkeypatch.setattr(requests, "request", request)
    try:
        result = validate(setup[0])
        assert result["verdict"] == "INCONCLUSIVE" and calls == ["notes.txt", "secret.txt"]
        assert not result["reportable"]
    finally:
        state["db"].close()
