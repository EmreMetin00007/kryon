"""Contract tests for the LLM discovery loop (offline, scripted transport).

Proves: POST body + session are carried to the lab, research state is
persisted and re-injected, the progress brake stops a stuck loop with a
partial report, and budget exhaustion also yields a partial report.
Compact forced closure spends a protected reserve at token/turn limits;
unaffordable or invalid closure responses preserve state without claiming
model submission or executing additional requests.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "lab"))

from discovery_lab import B_ARCHIVED, DiscoveryLab  # noqa: E402
from discovery_loop import DiscoveryLoop  # noqa: E402
from full_agent_budget import prompt_bound  # noqa: E402


def _outputs(body: dict) -> str:
    return json.dumps(body.get("input", []))


class RuleFakeModel:
    """Scripted stand-in that reacts to tool outputs like a model would."""

    def __init__(self):
        self.step = 0
        self.saw_state_blob = False

    def __call__(self, body: dict) -> dict:
        self.step += 1
        blob = _outputs(body)
        if "RESEARCH STATE" in blob and "member_a" in blob and self.step > 5:
            self.saw_state_blob = True
        csrf = (re.search(r'csrf_token\\?":\s*\\?"([0-9a-f]+)', blob) or [None, None])[1]
        session = (re.search(r'session\\?":\s*\\?"(sess_[0-9a-f]+)', blob) or [None, None])[1]

        def call(name, args):
            return {"usage": {"total_tokens": 100}, "text": "",
                    "function_calls": [{"call_id": f"c{self.step}", "name": name,
                                         "arguments": json.dumps(args)}]}

        if self.step == 1:
            return call("fetch_route", {"path": "/"})
        if self.step == 2:
            return call("fetch_route", {"path": "/assets/app.js"})
        if self.step == 3:
            return call("fetch_route", {"path": "/auth/signin"})
        if self.step == 4:
            assert csrf, "executor must return the sign-in body to the model"
            return call("fetch_route", {"path": "/auth/session", "method": "POST",
                                        "body": {"username": "member_a", "password": "pass-a",
                                                 "csrf_token": csrf}})
        if self.step == 5:
            assert session, "login must have produced a session in tool output"
            return call("update_research_state", {
                "observed_facts": ["signin issues csrf; login returns session"],
                "identity_object_map": {"member_a": "session held"},
                "open_hypotheses": ["orders may lack ownership checks"],
                "tried_controls": ["none yet"],
                "next_experiment": "list own orders, then look for other owners' ids"})
        if self.step == 6:
            return call("fetch_route", {"path": "/api/orders?page=1", "session": session})
        if self.step == 7:
            return call("fetch_route", {"path": "/api/reviews", "session": session})
        if self.step == 8:
            return call("fetch_route", {"path": f"/api/orders/{B_ARCHIVED}", "session": session})
        return call("submit_analysis_summary", {
            "detected_differences": [{"endpoint": "/api/orders/{id}", "family": "access_control",
                                      "observation": "cross-account read via leaked id"}],
            "confirmed_matches": []})


class SamePathModel:
    def __call__(self, body: dict) -> dict:
        return {"usage": {"total_tokens": 50}, "text": "",
                "function_calls": [{"call_id": "x", "name": "fetch_route",
                                     "arguments": json.dumps({"path": "/catalog"})}]}


def test_body_session_and_state_are_carried():
    lab = DiscoveryLab()
    try:
        fake = RuleFakeModel()
        loop = DiscoveryLoop(lab.base, fake, max_turns=12)
        result = loop.run()
        assert result["stop_reason"] == "submitted"
        assert result["final_report"] is not None
        assert fake.saw_state_blob, "research state must be re-injected in later turns"
        posts = [e for e in lab.log if e["path"] == "/auth/session"]
        assert posts and posts[0]["body"]["username"] == "member_a"
        assert posts[0]["body"]["csrf_token"], "POST body must reach the lab intact"
        cross = [e for e in lab.log if e["path"] == f"/api/orders/{B_ARCHIVED}"]
        assert cross and cross[0]["user"] == "member_a" and cross[0]["status"] == 200, \
            "session must be carried so the cross-account read authenticates"
        assert result["candidate_origins"]["llm"] >= 6
    finally:
        lab.close()


class SameTemplateModel:
    """Fresh id-shaped path each turn: novel evidence, same signature."""

    def __init__(self):
        self.n = 0

    def __call__(self, body: dict) -> dict:
        self.n += 1
        fake_id = f"{self.n:032x}"
        return {"usage": {"total_tokens": 50}, "text": "",
                "function_calls": [{"call_id": f"t{self.n}", "name": "fetch_route",
                                     "arguments": json.dumps({"path": f"/api/orders/{fake_id}"})}]}


def test_progress_brake_yields_partial_report():
    lab = DiscoveryLab()
    try:
        loop = DiscoveryLoop(lab.base, SamePathModel(), max_turns=20, brake_window=3)
        result = loop.run()
        assert result["stop_reason"] == "progress_brake:novelty"
        assert result["final_report"] is not None
        assert result["closure_trigger"]["summary_origin"] == "host_research_state"
        assert result["partial_report"] is not None
        assert result["partial_report"]["reason"] == "progress_brake:novelty"
    finally:
        lab.close()


def test_hypothesis_brake_stops_same_template_repetition():
    lab = DiscoveryLab()
    try:
        loop = DiscoveryLoop(lab.base, SameTemplateModel(), max_turns=20,
                             brake_window=3, brake_mode="hypothesis")
        result = loop.run()
        assert result["stop_reason"] == "progress_brake:hypothesis"
        assert result["partial_report"] is not None
        # novelty brake would NOT have stopped: every id is new evidence
        loop2 = DiscoveryLoop(lab.base, SameTemplateModel(), max_turns=6,
                              brake_window=3, brake_mode="novelty")
        result2 = loop2.run()
        assert result2["stop_reason"] == "turn_cap"
    finally:
        lab.close()


def test_run_record_carries_settings_state_and_closure():
    lab = DiscoveryLab()
    try:
        loop = DiscoveryLoop(lab.base, RuleFakeModel(), max_turns=12)
        result = loop.run()
        assert result["settings"]["brake_mode"] == "novelty"
        assert result["settings"]["model"]
        assert result["closure_trigger"]["submitted"] is True
        assert result["turn_log"], "turn log must be persisted in the run record"
        for entry in result["turn_log"]:
            assert "state_after" in entry and "closure_injected" in entry
    finally:
        lab.close()


def test_token_budget_yields_partial_report():
    lab = DiscoveryLab()
    try:
        loop = DiscoveryLoop(lab.base, SamePathModel(), token_budget=10)
        result = loop.run()
        assert result["stop_reason"] == "token_budget"
        assert result["partial_report"] is not None
        assert result["final_report"] == {"detected_differences": [], "confirmed_matches": []}
        assert result["closure_trigger"]["summary_origin"] == "host_research_state"
        assert result["closure_trigger"]["submitted"] is False
    finally:
        lab.close()


def _call_response(step, name, args, tokens=1000):
    return {"usage": {"total_tokens": tokens}, "text": "",
            "function_calls": [{"call_id": f"c{step}", "name": name,
                                "arguments": json.dumps(args)}]}


@pytest.mark.parametrize("discovery_allowance, expected_turns", [(4196, 2), (4195, 1), (8000, 5)])
def test_remaining_budget_preserves_a_forced_closing_call(monkeypatch, discovery_allowance, expected_turns):
    monkeypatch.setattr("discovery_loop.prompt_bound", lambda raw: (100, {"test": True}))
    monkeypatch.setattr("discovery_loop.time.sleep", lambda seconds: None)
    prompts = []

    def model(body):
        prompts.append(body)
        if body.get("tool_choice"):
            assert body["tool_choice"] == "required"
            assert [t["name"] for t in body["tools"]] == ["submit_analysis_summary"]
            if len(prompts) > 1:
                assert "recorded observation" in _outputs(body)
            return _call_response(len(prompts), "submit_analysis_summary", {
                "detected_differences": [], "confirmed_matches": []})
        return _call_response(len(prompts), "update_research_state", {
            "observed_facts": ["recorded observation"]})

    protected = 22240
    token_budget = protected + discovery_allowance
    loop = DiscoveryLoop("http://127.0.0.1:1", model, token_budget=token_budget, max_turns=18)
    result = loop.run()
    assert result["stop_reason"] == "submitted"
    assert result["turns"] == expected_turns
    assert [t["closure_injected"] for t in result["turn_log"]] == [False] * (expected_turns - 1) + [True]
    assert result["closure_trigger"]["trigger"] == "remaining_budget"
    assert result["token_accounting"]["charged_total"] == expected_turns * 1000
    assert result["token_accounting"]["reserved_total"] == (expected_turns - 1) * 4196 + protected
    assert loop.budget.snapshot()["reserved"]["tokens"] == 0
    assert loop.budget.available("tokens") == token_budget - expected_turns * 1000


def test_forced_closing_prompt_fits_its_reserve(monkeypatch):
    monkeypatch.setattr("discovery_loop.time.sleep", lambda seconds: None)
    request = []

    def model(body):
        request.append(body)
        return _call_response(1, "submit_analysis_summary", {
            "detected_differences": [], "confirmed_matches": []}, tokens=100)

    loop = DiscoveryLoop("http://127.0.0.1:1", model, max_turns=1)
    result = loop.run()
    expected, _ = prompt_bound(json.dumps(request[0]).encode())
    assert result["turn_log"][0]["prompt_bound"] == expected
    assert result["turn_log"][0]["estimated_request_tokens"] == expected + 8192
    assert result["turn_log"][0]["reserve_tokens"] >= expected + 8192
    assert result["closure_trigger"]["trigger"] == "remaining_turns"
    assert request[0]["max_output_tokens"] == 8192
    assert request[0]["parallel_tool_calls"] is False
    assert request[0]["reasoning"] == {"effort": "low"}
    assert "reasoning" not in loop._request_body(1), "discovery reasoning must remain unchanged"
    assert len(json.dumps(request[0]).encode()) <= loop.closure_prompt_limit


def test_insufficient_budget_keeps_facts_and_hypotheses_without_provider_call(monkeypatch):
    def model(body):
        raise AssertionError("an unaffordable provider call must not run")

    loop = DiscoveryLoop("http://127.0.0.1:1", model, token_budget=10)
    loop.state = {"observed_facts": ["/api/orders returned 200"],
                  "open_hypotheses": ["ownership checks might be absent"]}
    result = loop.run()
    assert result["llm_tokens"] == 0 and result["http_requests"] == 0
    assert result["final_report"]["detected_differences"] == [
        {"endpoint": "", "family": "other", "observation": "/api/orders returned 200"}]
    assert result["final_report"]["confirmed_matches"] == []
    assert result["research_state"]["open_hypotheses"] == loop.state["open_hypotheses"]
    assert result["closure_trigger"]["report_completed"] is True
    assert result["closure_trigger"]["submitted"] is False
    assert result["closure_trigger"]["trigger"] == "insufficient_closure_reserve"


@pytest.mark.parametrize("offset", [-1, 0])
def test_tight_budget_only_calls_provider_when_compact_closure_fits(offset):
    calls = []
    def model(body):
        calls.append(body)
        return _call_response(1, "submit_analysis_summary", {
            "detected_differences": [], "confirmed_matches": []}, tokens=100)
    prototype = DiscoveryLoop("http://127.0.0.1:1", model)
    request = prototype._closure_body()
    bound, _ = prompt_bound(json.dumps(request).encode())
    needed = bound + 8192
    loop = DiscoveryLoop("http://127.0.0.1:1", model, token_budget=needed + offset)
    result = loop.run()
    assert len(calls) == (1 if offset == 0 else 0)
    assert result["closure_trigger"]["submitted"] is (offset == 0)
    assert result["llm_tokens"] == (100 if offset == 0 else 0)
    assert loop.budget.snapshot()["reserved"]["tokens"] == 0


@pytest.mark.parametrize("unexpected_tool", ["fetch_route", "update_research_state"])
def test_model_ignoring_forced_closure_cannot_execute_tools_or_change_state(monkeypatch, unexpected_tool):
    monkeypatch.setattr("discovery_loop.prompt_bound", lambda raw: (100, {}))
    monkeypatch.setattr("discovery_loop.time.sleep", lambda seconds: None)
    prompts = []

    def model(body):
        prompts.append(body)
        if body.get("tool_choice"):
            return _call_response(len(prompts), unexpected_tool, {
                "path": "/must-not-fetch", "observed_facts": ["untrusted closing state"]})
        return _call_response(len(prompts), "update_research_state", {
            "observed_facts": [f"fact from turn {len(prompts)}"]})

    loop = DiscoveryLoop("http://127.0.0.1:1", model, token_budget=22240 + 5000)
    def no_fetch(args):
        raise AssertionError("a closing fetch must never execute")
    monkeypatch.setattr(loop, "_execute_fetch", no_fetch)
    result = loop.run()
    assert result["turns"] == 2 and result["llm_tokens"] == 2000
    assert result["closure_trigger"]["closing_injected"] is True
    assert result["closure_trigger"]["submitted"] is False
    assert result["final_report"]["detected_differences"][0]["observation"] == "fact from turn 1"
    assert result["closure_trigger"]["error"]["type"] == "invalid_summary_or_tool_choice"


def test_post_signature_distinguishes_controls_without_exposing_values():
    body = {"username": "member_a", "password": "wrong", "csrf_token": "lab-token"}
    sig = DiscoveryLoop._signature("POST", "/auth/session", body)
    assert sig == DiscoveryLoop._signature("post", "/auth/session", dict(reversed(list(body.items()))))
    assert sig != DiscoveryLoop._signature("POST", "/auth/session", {**body, "password": "pass-a"})
    assert sig != DiscoveryLoop._signature("POST", "/auth/session", {"username": "member_a", "password": "wrong"})
    assert "member_a" not in sig and "wrong" not in sig and "lab-token" not in sig
    assert DiscoveryLoop._signature("GET", "/catalog", body) == DiscoveryLoop._signature("GET", "/catalog")


def test_hypothesis_brake_allows_distinct_login_bodies_but_stops_identical_retries(monkeypatch):
    monkeypatch.setattr("discovery_loop.time.sleep", lambda seconds: None)
    bodies = [{"username": "member_a", "password": "wrong"},
              {"username": "member_a", "password": "wrong", "csrf_token": "lab-token"},
              {"username": "member_a", "password": "pass-a", "csrf_token": "lab-token"}]
    calls = []

    def model(body):
        args = {"path": "/auth/session", "method": "POST",
                "body": bodies[min(len(calls), 2)]}
        calls.append(args)
        return _call_response(len(calls), "fetch_route", args, tokens=100)

    loop = DiscoveryLoop("http://127.0.0.1:1", model, brake_window=1, brake_mode="hypothesis")
    monkeypatch.setattr(loop, "_execute_fetch", lambda args: {
        "method": "POST", "path": "/auth/session", "status": 200, "body": {}})
    result = loop.run()
    assert result["stop_reason"] == "progress_brake:hypothesis"
    assert result["phase_turns"]["discovery"] == 4, "all three controls must run before an identical retry trips the brake"
    assert result["phase_turns"]["closure"] == 1


def _login_step(user, session, *, csrf="initial-csrf", status=200):
    return ({"path": "/auth/session", "method": "POST",
             "body": {"username": user, "password": "synthetic-password", "csrf_token": csrf}},
            {"status": status, "body": {"session": session, "user": user}})


def _get_step(path, session=None):
    args = {"path": path}
    if session is not None:
        args["session"] = session
    # Identical replies isolate request identity from response novelty.
    return args, {"status": 200, "body": {"orders": []}}


def _run_identity_brake_script(monkeypatch, requests, *, brake_window=1):
    """Replay request/response pairs without HTTP or provider calls."""
    monkeypatch.setattr("discovery_loop.prompt_bound", lambda raw: (100, {}))
    monkeypatch.setattr("discovery_loop.time.sleep", lambda seconds: None)
    executed = []

    def model(body):
        step = len(executed) + 1
        if body.get("tool_choice") or len(executed) == len(requests):
            return _call_response(step, "submit_analysis_summary", {
                "detected_differences": [], "confirmed_matches": []}, tokens=100)
        return _call_response(step, "fetch_route", requests[len(executed)][0], tokens=100)

    def execute(args):
        expected, reply = requests[len(executed)]
        assert args == expected
        executed.append(args)
        return {"method": args.get("method", "GET"), "path": args["path"], **reply}

    loop = DiscoveryLoop("http://127.0.0.1:1", model, max_turns=24,
                         brake_mode="hypothesis", brake_window=brake_window)
    loop.state = {"tried_controls": ["initial control"]}
    monkeypatch.setattr(loop, "_execute_fetch", execute)
    return loop, loop.run(), executed


def test_hypothesis_brake_keeps_first_identity_controls_on_seen_routes(monkeypatch):
    requests = [_login_step("member_a", "synthetic-session-a"),
                _login_step("member_b", "synthetic-session-b"),
                _get_step("/api/orders"), _get_step("/billing/orders"),
                _get_step("/api/orders", "synthetic-session-a"),
                _get_step("/api/orders", "synthetic-session-b"),
                _get_step("/billing/orders", "synthetic-session-a"),
                _get_step("/billing/orders", "synthetic-session-b")]
    loop, result, executed = _run_identity_brake_script(monkeypatch, requests, brake_window=4)
    assert executed == [args for args, _ in requests]
    assert result["closure_trigger"]["trigger"] is None, "first identity controls must not force closure"
    assert result["phase_turns"] == {"discovery": 9, "closure": 0}
    assert result["research_state"]["tried_controls"] == ["initial control"]
    for turn in result["turn_log"][4:8]:
        assert turn["hypothesis_progress"] == {
            "new_signature": True, "controls_grew": False,
            "progressed": True, "stale_turns": 0}
    signatures = "\n".join(loop.signatures)
    for value in ("member_a", "member_b", "synthetic-session-a", "synthetic-session-b"):
        assert value not in signatures, "progress signatures must not expose identity or session values"


def test_hypothesis_brake_still_stops_revisited_identity_controls(monkeypatch):
    requests = [_login_step("member_a", "synthetic-session-a"),
                _login_step("member_b", "synthetic-session-b"),
                _get_step("/api/orders", "synthetic-session-a"),
                _get_step("/api/orders", "synthetic-session-b"),
                _get_step("/api/orders", "synthetic-session-a"),
                _get_step("/api/orders", "synthetic-session-b")]
    _, result, executed = _run_identity_brake_script(monkeypatch, requests)
    assert executed == [args for args, _ in requests[:5]]
    assert result["closure_trigger"]["trigger"] == "progress_brake:hypothesis"
    assert result["phase_turns"] == {"discovery": 5, "closure": 1}
    assert result["turn_log"][4]["hypothesis_progress"]["stale_turns"] == 1


def test_hypothesis_brake_session_rotation_is_not_a_new_identity_control(monkeypatch):
    requests = [_login_step("member_a", "synthetic-old-session"),
                _login_step("member_a", "synthetic-new-session", csrf="renewed-csrf"),
                _get_step("/api/orders", "synthetic-old-session"),
                _get_step("/api/orders", "synthetic-new-session"),
                _get_step("/api/orders", "synthetic-old-session")]
    _, result, executed = _run_identity_brake_script(monkeypatch, requests)
    assert executed == [args for args, _ in requests[:4]]
    assert result["closure_trigger"]["trigger"] == "progress_brake:hypothesis"
    assert result["phase_turns"] == {"discovery": 4, "closure": 1}


def test_hypothesis_brake_unknown_sessions_cannot_keep_discovery_alive(monkeypatch):
    requests = [_get_step("/api/orders", f"unobserved-session-{n}") for n in range(5)]
    _, result, executed = _run_identity_brake_script(monkeypatch, requests, brake_window=2)
    assert executed == [args for args, _ in requests[:3]]
    assert result["closure_trigger"]["trigger"] == "progress_brake:hypothesis"
    assert result["phase_turns"] == {"discovery": 3, "closure": 1}


def test_hypothesis_brake_failed_login_receipts_do_not_bind_identities(monkeypatch):
    requests = [_login_step("member_a", "synthetic-denied-a", status=401),
                _login_step("member_b", "synthetic-denied-b", status=403),
                _get_step("/api/orders", "synthetic-denied-a"),
                _get_step("/api/orders", "synthetic-denied-b")]
    _, result, executed = _run_identity_brake_script(monkeypatch, requests)
    assert executed == [args for args, _ in requests]
    assert result["closure_trigger"]["trigger"] == "progress_brake:hypothesis"
    assert result["phase_turns"] == {"discovery": 4, "closure": 1}


def test_turn_limit_preserves_final_research_state_with_host_fallback(monkeypatch):
    monkeypatch.setattr("discovery_loop.time.sleep", lambda seconds: None)
    count = 0
    def model(body):
        nonlocal count
        count += 1
        return _call_response(count, "update_research_state", {
            "observed_facts": [f"recorded fact {count}"]}, tokens=100)
    loop = DiscoveryLoop("http://127.0.0.1:1", model, max_turns=3)
    result = loop.run()
    assert result["turns"] == 3
    assert result["stop_reason"] == "turn_cap"
    assert result["closure_trigger"]["report_completed"] is True
    assert result["closure_trigger"]["submitted"] is False
    assert result["final_report"]["detected_differences"][0]["observation"] == "recorded fact 2"
    assert loop.state["observed_facts"] == ["recorded fact 2"]


def test_early_model_summary_releases_unused_closing_reserve():
    def model(body):
        assert "tool_choice" not in body
        return _call_response(1, "submit_analysis_summary", {
            "detected_differences": [], "confirmed_matches": []}, tokens=100)
    loop = DiscoveryLoop("http://127.0.0.1:1", model)
    result = loop.run()
    assert result["closure_trigger"]["submitted"] is True
    assert result["phase_turns"]["closure"] == 0
    assert result["closure_request"] is None
    assert loop.budget.snapshot()["reserved"]["tokens"] == 0
    assert loop.budget.snapshot()["events"][-1]["executed"] is False


@pytest.mark.parametrize("arguments", ["{}", "[]", "not-json", json.dumps({
    "detected_differences": [{"endpoint": "/test", "family": "invented", "observation": "claim"}],
    "confirmed_matches": []})])
def test_invalid_closing_summary_is_not_counted_as_model_submission(arguments):
    def model(body):
        response = _call_response(1, "submit_analysis_summary", {}, tokens=100)
        response["function_calls"][0]["arguments"] = arguments
        return response
    result = DiscoveryLoop("http://127.0.0.1:1", model, max_turns=1).run()
    assert result["closure_trigger"]["submitted"] is False
    assert result["closure_trigger"]["report_completed"] is True
    assert result["closure_trigger"]["summary_origin"] == "host_research_state"


def test_closing_provider_failure_preserves_state_and_charges_reservation():
    def model(body):
        raise urllib.error.HTTPError("https://provider.invalid", 400, "invalid request", {}, None)
    loop = DiscoveryLoop("http://127.0.0.1:1", model, max_turns=1)
    loop.state = {"observed_facts": ["recorded fact"]}
    result = loop.run()
    assert result["closure_trigger"]["error"]["http_status"] == 400
    assert result["closure_trigger"]["submitted"] is False
    assert result["llm_tokens"] == loop.closure_reserve_tokens
    assert result["final_report"]["detected_differences"][0]["observation"] == "recorded fact"
    assert loop.budget.snapshot()["reserved"]["tokens"] == 0


def test_invalid_closing_usage_fails_closed():
    def model(body):
        return _call_response(1, "submit_analysis_summary", {
            "detected_differences": [], "confirmed_matches": []}, tokens=22241)
    loop = DiscoveryLoop("http://127.0.0.1:1", model, max_turns=1)
    result = loop.run()
    assert result["closure_trigger"]["submitted"] is False
    assert result["closure_trigger"]["error"]["type"] == "invalid_usage"
    assert result["llm_tokens"] == 22240
    assert loop.budget.blocked
    assert loop.budget.snapshot()["reserved"]["tokens"] == 0


@pytest.mark.parametrize("provider_status, submitted", [("completed", True), ("incomplete", False)])
def test_provider_completion_status_controls_report_acceptance(provider_status, submitted):
    def model(body):
        response = _call_response(1, "submit_analysis_summary", {
            "detected_differences": [], "confirmed_matches": []}, tokens=100)
        response["response_status"] = provider_status
        return response
    result = DiscoveryLoop("http://127.0.0.1:1", model, max_turns=1).run()
    assert result["closure_trigger"]["submitted"] is submitted
    assert result["closure_trigger"]["report_completed"] is True


def test_compact_closure_retains_old_cross_account_evidence_and_reference_source():
    loop = DiscoveryLoop("http://127.0.0.1:1", lambda body: None)
    foreign = "b" * 32
    session = "test-session-value"
    def evidence(call_id, args, reply, status=200):
        loop.history.append({"call_id": call_id, "name": "fetch_route", "arguments": json.dumps(args),
                             "output": json.dumps({"method": args.get("method", "GET"), "path": args["path"],
                                                   "status": status, "body": reply}), "origin": "llm"})
    evidence("login", {"method": "POST", "path": "/auth/session", "body": {
        "username": "member_a", "password": "test-password"}}, {"user": "member_a", "session": session})
    evidence("reference", {"path": "/public-notes"}, {"notes": [{"object_ref": foreign}]})
    evidence("cross", {"path": "/objects/" + foreign, "session": session}, {
        "owner": "member_b", "id": foreign, "private_note": "test-data"})
    evidence("denied", {"path": "/guarded/" + foreign, "session": session}, {"error": "forbidden"}, 403)
    for n in range(80):
        evidence(f"noise-{n}", {"path": f"/catalog-{n}"}, "noise " * 300)
    loop.state = {"observed_facts": ["Türkçe araştırma notu " * 500],
                  "identity_object_map": {"member_a": {"session": session, "password": "test-password"}}}
    original = json.loads(json.dumps(loop.history))
    body = loop._closure_body()
    raw = json.dumps(body)
    assert len(raw.encode()) <= loop.closure_prompt_limit
    assert len(raw) < len(json.dumps(loop._request_body(18))) / 2
    assert session not in raw and "test-password" not in raw
    assert not any(item.get("type") in ("function_call", "function_call_output") for item in body["input"])
    context = json.loads(body["input"][0]["content"])
    selected = {e["source_call_id"]: e for e in context["selected_request_response_evidence"]}
    assert {"cross", "reference", "denied"} <= set(selected)
    assert selected["cross"]["request"]["actor"] == "member_a"
    assert selected["cross"]["request"]["actor_source_call_id"] == "login"
    assert context["omitted_evidence_count"] > 0
    assert context["research_state_truncated"] is True
    assert loop.history == original, "the compact view must not modify archived evidence"
