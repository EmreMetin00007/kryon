"""Multi-identity discovery, wire gate and validator with synthetic transport."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys

import pytest
import requests

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from policy_engine import PolicyEngine  # noqa: E402
from scripts.lab.blind_agent_run import benchmark_payload  # noqa: E402

BASE = "https://owned.test/allowed/"
IDS = {"alice": "d94e5fbb-862f-4a15-a811-4252eb9fccb5",
       "bob": "602532ac-42ba-4cc4-851e-326b4ed0ea91"}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home = tmp_path / "home"
    scope = tmp_path / "scope.json"
    policy = tmp_path / "policy.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": BASE}], "allow_loopback": False,
                                 "allow_osint": False, "allow_public_labs": False}))
    policy.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"},
                                  "blind_discovery": {"synthetic_accounts_only": True,
                                                      "owned_objects_private": True}}))
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    monkeypatch.setenv("CCO_GRAPH_BACKEND", "networkx")
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
    engine.grant_approval("hunter_run_web_loop", "owned.test", ttl_seconds=600, reason="synthetic")
    hunter = load_server("hunter")
    monkeypatch.setattr(hunter, "_loop_discover", lambda *a, **kw: {"ok": True, "ingested": 1})
    monkeypatch.setattr(hunter, "_loop_fuzz", lambda *a, **kw: {"probes": 0, "validator_queue": []})
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    identities = {name: {"headers": {"Cookie": f"session={name}-secret"}, "role": "member",
                         "test_data_only": True, "owned_objects_private": True} for name in IDS}
    return hunter, identities, monkeypatch


class Response:
    def __init__(self, url, status, payload):
        self.url, self.status_code = url, status
        self.text = json.dumps(payload)
        self.content = self.text.encode()
        self.headers = {"Content-Type": "application/json"}
        self.encoding = "utf-8"
        self.closed = False

    def iter_content(self, chunk_size):
        yield self.content

    def close(self):
        self.closed = True


def test_blind_discovery_reaches_signed_authz_validation_without_operator_object_list(setup):
    hunter, identities, monkeypatch = setup
    seen = []

    def send(method, url, **kwargs):
        assert method == "GET" and url.startswith(BASE) and kwargs["allow_redirects"] is False
        headers = kwargs.get("headers") or {}
        assert headers.get("X-Research") == "researcher"
        cookie = headers.get("Cookie") or ""
        actor = next((name for name in IDS if cookie == f"session={name}-secret"), "anon")
        seen.append((actor, url))
        if url == BASE and actor != "anon":
            return Response(url, 200, {"current_user": {"id": f"{actor}-subject"},
                                       "links": [{"href": "/allowed/orders"}]})
        if url == BASE + "orders" and actor != "anon":
            return Response(url, 200, {"results": [{"href": f"/allowed/orders/{IDS[actor]}"}]})
        if url == BASE + "orders/" + IDS["alice"] and actor in {"alice", "bob"}:
            return Response(url, 200, {"id": IDS["alice"], "owner_id": "alice-subject"})
        if url == BASE + "orders/" + IDS["bob"] and actor == "bob":
            return Response(url, 200, {"id": IDS["bob"], "owner_id": "bob-subject"})
        return Response(url, 403, {"error": "forbidden"})

    monkeypatch.setattr(requests, "request", send)
    raw = hunter.run_web_loop(BASE, live=True, crawl=False, blind_discovery=True,
                              identities=json.dumps(identities), headers='{"X-Research":"researcher"}',
                              sleep_s=0, max_validations=4)
    result = json.loads(raw)
    assert result["identity_discovery"]["status"] == "ready"
    assert result["identity_discovery"]["owned_objects_observed"] == 2
    assert {row["url"] for row in result["discovery_operations"]} == {
        BASE + "orders/" + IDS["alice"], BASE + "orders/" + IDS["bob"]}
    rows = {row["url"]: row for row in result["validations"]}
    assert rows[BASE + "orders/" + IDS["alice"]]["verdict"] == "CONFIRMED"
    assert rows[BASE + "orders/" + IDS["bob"]]["verdict"] == "UNCONFIRMED"
    assert all(row["coverage_recorded"] for row in rows.values())
    assert result["requests_authorized"] == len(seen)
    assert "alice-secret" not in raw and "bob-secret" not in raw and "alice-subject" not in raw
    assert identities["alice"].get("objects") is None

    # The benchmark must consume actual signed coverage, including the safe
    # owner's negative control, instead of inferring clean from no finding.
    payload = benchmark_payload(hunter, result, BASE)
    assert len(payload["verified_coverage"]) == 2
    spec = importlib.util.spec_from_file_location("blind_scoring_integration", ROOT / "scripts/blind-validate.py")
    scorer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scorer)
    truth = [
        {"case": "positive", "expected": "positive", "class": "bola",
         "path": "/allowed/orders/" + IDS["alice"], "owner": "alice", "actor": "bob"},
        {"case": "negative", "expected": "negative", "class": "bola",
         "path": "/allowed/orders/" + IDS["bob"], "owner": "bob", "actor": "alice"},
    ]
    score = scorer.evaluate(truth, result, verified_coverage=payload["verified_coverage"])
    assert score["proven"] == score["negatives_clean"] == 1
    assert score["negative_coverage"] == 1 and score["fp_rate"] == 0
    assert all(case["pipeline"]["surface_observed"] is True for case in score["cases"])
    assert benchmark_payload(hunter, {**result, "run_id": "different-run"}, BASE)["verified_coverage"] == []

    # Altering the stored status invalidates its signature; the export and
    # scorer must lose that credit rather than accepting an unsigned claim.
    with sqlite3.connect(hunter.MEM_DB) as conn:
        for event_id, raw_event in conn.execute("SELECT id, signed_json FROM hunter_coverage_events").fetchall():
            signed = json.loads(raw_event)
            if signed["payload"].get("status") == "tested_clean":
                signed["payload"]["status"] = "confirmed"
                conn.execute("UPDATE hunter_coverage_events SET signed_json=? WHERE id=?",
                             (json.dumps(signed), event_id))
    after = benchmark_payload(hunter, result, BASE)
    score = scorer.evaluate(truth, result, verified_coverage=after["verified_coverage"])
    assert score["proven"] == 1 and score["negatives_evaluated"] == 0
    assert score["false_positives"] == 0 and score["fp_rate"] is None


@pytest.mark.parametrize("differential", [False, True])
@pytest.mark.parametrize("invalid", ["missing", "false", "string", "duplicate", "no_credentials"])
def test_blind_preflight_requires_synthetic_identity_declaration_before_network(setup, invalid, differential):
    hunter, identities, monkeypatch = setup
    if invalid == "missing":
        del identities["bob"]["test_data_only"]
    elif invalid == "false":
        identities["bob"]["test_data_only"] = False
    elif invalid == "string":
        identities["bob"]["test_data_only"] = "true"
    elif invalid == "duplicate":
        identities["bob"]["headers"] = dict(identities["alice"]["headers"])
    else:
        identities["bob"]["headers"] = {}
    if differential:
        policy = Path(os.environ["CCO_PROGRAM_POLICY_FILE"])
        data = json.loads(policy.read_text())
        data["blind_discovery"]["differential_ownership"] = True
        policy.write_text(json.dumps(data))
    monkeypatch.setattr(requests, "request", lambda *a, **kw: pytest.fail("must not send"))
    monkeypatch.setattr(hunter, "_loop_discover", lambda *a, **kw: pytest.fail("must not continue discovery"))
    monkeypatch.setattr(hunter, "_loop_fuzz", lambda *a, **kw: pytest.fail("must not continue fuzzing"))
    result = json.loads(hunter.run_web_loop(BASE, live=True, crawl=False, blind_discovery=True,
                                            blind_differential=differential,
                                            identities=json.dumps(identities), sleep_s=0))
    assert result["ok"] is False and result["identity_discovery"]["requests"] == 0
    assert result["identity_discovery"]["status"] == "blocked"
    assert result["requests_authorized"] == 0


def test_blind_discovery_requires_operator_program_policy_before_network(setup):
    hunter, identities, monkeypatch = setup
    policy = Path(os.environ["CCO_PROGRAM_POLICY_FILE"])
    policy.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"}}))
    monkeypatch.setattr(requests, "request", lambda *a, **kw: pytest.fail("must not send"))
    result = json.loads(hunter.run_web_loop(BASE, live=True, crawl=False, blind_discovery=True,
                                            identities=json.dumps(identities), sleep_s=0))
    assert result["ok"] is False and result["identity_discovery"]["requests"] == 0
    assert result["requests_authorized"] == 0


def test_unknown_owner_access_policy_never_runs_cross_identity_validation(setup):
    hunter, identities, monkeypatch = setup
    policy = Path(os.environ["CCO_PROGRAM_POLICY_FILE"])
    policy.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"},
                                  "blind_discovery": {"synthetic_accounts_only": True,
                                                      "owned_objects_private": False}}))
    seen = []
    def send(method, url, **kwargs):
        cookie = (kwargs.get("headers") or {}).get("Cookie", "")
        actor = next(name for name in IDS if cookie == f"session={name}-secret")
        seen.append((actor, url))
        if url == BASE:
            body = {"current_user": {"id": f"{actor}-subject"}, "links": [{"href": "/allowed/orders"}]}
        elif url == BASE + "orders":
            body = {"results": [{"href": f"/allowed/orders/{IDS[actor]}"}]}
        else:
            assert url == BASE + "orders/" + IDS[actor]
            body = {"id": IDS[actor], "owner_id": f"{actor}-subject"}
        return Response(url, 200, body)
    monkeypatch.setattr(requests, "request", send)
    result = json.loads(hunter.run_web_loop(BASE, live=True, crawl=False, blind_discovery=True,
                                            identities=json.dumps(identities),
                                            headers='{"X-Research":"researcher"}', sleep_s=0))
    assert result["identity_discovery"]["owned_objects_observed"] == 2
    assert result["identity_discovery"]["eligible_candidates"] == 0
    assert len(seen) == 6 and not result["validations"] and not result["confirmed"]


def test_policy_revocation_stops_blind_run_before_next_request(setup):
    hunter, identities, monkeypatch = setup
    policy = Path(os.environ["CCO_PROGRAM_POLICY_FILE"])
    seen = []
    def send(method, url, **kwargs):
        seen.append(url)
        policy.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"},
                                      "blind_discovery": {"synthetic_accounts_only": False,
                                                          "owned_objects_private": True}}))
        return Response(url, 200, {"current_user": {"id": "alice-subject"},
                                   "links": [{"href": "/allowed/orders"}]})
    monkeypatch.setattr(requests, "request", send)
    result = json.loads(hunter.run_web_loop(BASE, live=True, crawl=False, blind_discovery=True,
                                            identities=json.dumps(identities),
                                            headers='{"X-Research":"researcher"}', sleep_s=0))
    assert result["ok"] is False and result["identity_discovery"]["status"] == "blocked"
    assert result["requests_authorized"] == len(seen) == 1
    assert "policy gate" in result["stopped"]


def test_invalid_policy_during_blind_run_stops_before_next_request(setup):
    hunter, identities, monkeypatch = setup
    policy = Path(os.environ["CCO_PROGRAM_POLICY_FILE"])
    seen = []
    def send(method, url, **kwargs):
        seen.append(url)
        policy.write_text("invalid policy")
        return Response(url, 200, {"current_user": {"id": "alice-subject"},
                                   "links": [{"href": "/allowed/orders"}]})
    monkeypatch.setattr(requests, "request", send)
    result = json.loads(hunter.run_web_loop(BASE, live=True, crawl=False, blind_discovery=True,
                                            identities=json.dumps(identities),
                                            headers='{"X-Research":"researcher"}', sleep_s=0))
    assert result["ok"] is False and result["identity_discovery"]["status"] == "blocked"
    assert result["requests_authorized"] == len(seen) == 1
    assert "policy gate unavailable" in result["stopped"]


def test_blind_streaming_response_is_bounded_and_closed(setup):
    hunter, _, monkeypatch = setup
    from cco_hunter_core.request_context import bind_policy_gate

    response = Response(BASE, 200, {"unused": "value"})
    response.headers["Content-Length"] = "999999"
    monkeypatch.setattr(requests, "request", lambda *a, **kw: response)
    with bind_policy_gate(lambda method, url, headers: (True, "allowed")):
        result = hunter._blind_discovery_get(BASE, {"Cookie": "session=synthetic"})
    assert result["ok"] and result["truncated"] and not result["text"] and response.closed


def _fresh_vault_bindings(identities):
    from cco_surface_core import session_store
    bindings = {}
    for actor, identity in identities.items():
        session_store.put_session(BASE, actor, headers=identity["headers"],
                                  check_url=BASE + "me", marker=actor + "-synthetic-marker")
        session_store.refresh_status(BASE, actor, lambda *_: (200, actor + "-synthetic-marker"))
        bindings[actor] = {"target": BASE, "role": "member", "test_data_only": True,
                           "owned_objects_private": True}
    return bindings


def test_verified_vault_bindings_feed_blind_discovery_without_queue_secrets(setup):
    hunter, identities, monkeypatch = setup
    bindings = _fresh_vault_bindings(identities)
    seen = []
    def send(method, url, **kwargs):
        actor = next(name for name in IDS if kwargs["headers"].get("Cookie") == f"session={name}-secret")
        seen.append((actor, url))
        if url == BASE:
            body = {"current_user": {"id": actor + "-subject"}, "links": [{"href": "/allowed/orders"}]}
        elif url == BASE + "orders":
            body = {"results": [{"href": "/allowed/orders/" + IDS[actor]}]}
        else:
            body = {"id": IDS[actor], "owner_id": actor + "-subject"}
        return Response(url, 200, body)
    monkeypatch.setattr(requests, "request", send)
    args = json.dumps(bindings)
    result = hunter.run_web_loop(BASE, live=True, crawl=False, blind_discovery=True, sleep_s=0,
                                 headers='{"X-Research":"researcher"}', session_bindings=args,
                                 max_validations=0)
    report = json.loads(result)
    assert report["identity_discovery"]["owned_objects_observed"] == 2
    assert report["requests_authorized"] == len(seen) == 6
    assert "alice-secret" not in args + result and "bob-secret" not in args + result


def test_vault_binding_rejects_unverified_mixed_and_wrong_origin_before_network(setup):
    hunter, identities, monkeypatch = setup
    from cco_surface_core import session_store
    bindings = _fresh_vault_bindings(identities)
    monkeypatch.setattr(requests, "request", lambda *a, **kw: pytest.fail("must not send"))
    cases = [
        {"cookie": "session=other"},
        {"identities": json.dumps(identities)},
        {"headers": '{"Authorization":"Bearer other"}'},
    ]
    for kwargs in cases:
        opts = {"live": True, "crawl": False, "blind_discovery": True,
                "session_bindings": json.dumps(bindings), **kwargs}
        report = json.loads(hunter.run_web_loop(BASE, **opts))
        assert report["replan"]["status"] == "blocked" and report["requests_authorized"] == 0
    bindings["alice"]["target"] = "https://owned.test:444/allowed/"
    report = json.loads(hunter.run_web_loop(BASE, live=True, blind_discovery=True,
                                            session_bindings=json.dumps(bindings)))
    assert not report["ok"] and report["requests_authorized"] == 0
    session_store.put_session(BASE, "bob", headers=identities["bob"]["headers"],
                              check_url=BASE + "me", marker="rotated")
    bindings["alice"]["target"] = BASE
    report = json.loads(hunter.run_web_loop(BASE, live=True, blind_discovery=True,
                                            session_bindings=json.dumps(bindings)))
    assert not report["ok"] and report["requests_authorized"] == 0


def test_rotation_during_blind_run_stops_before_next_wire_request(setup):
    hunter, identities, monkeypatch = setup
    from cco_surface_core import session_store
    bindings = _fresh_vault_bindings(identities)
    seen = []
    def send(method, url, **kwargs):
        seen.append(url)
        session_store.put_session(BASE, "bob", headers={"Cookie": "session=rotated"},
                                  check_url=BASE + "me", marker="new marker")
        return Response(url, 200, {"current_user": {"id": "alice-subject"},
                                   "links": [{"href": "/allowed/orders"}]})
    monkeypatch.setattr(requests, "request", send)
    report = json.loads(hunter.run_web_loop(BASE, live=True, crawl=False, blind_discovery=True,
                                            session_bindings=json.dumps(bindings),
                                            headers='{"X-Research":"researcher"}', sleep_s=0))
    assert not report["ok"] and report["requests_authorized"] == len(seen) == 1
    assert "session unavailable" in report["stopped"]


def test_session_binding_diagnostics_distinguish_input_errors_from_stale_checks(setup):
    hunter, identities, monkeypatch = setup
    bindings = _fresh_vault_bindings(identities)
    monkeypatch.setattr(requests, "request", lambda *a, **kw: pytest.fail("must not send"))
    cases = [
        ("{", {}, "invalid_session_bindings_json"),
        (json.dumps({"alice": "vault:alice", "bob": "vault:bob"}), {}, "invalid_session_binding"),
        (json.dumps(bindings), {"cookie": "synthetic-private-cookie"}, "mixed_session_material"),
    ]
    for raw, extra, expected in cases:
        report = json.loads(hunter.run_web_loop(BASE, live=True, blind_discovery=True,
                                               session_bindings=raw, **extra))
        assert report["requests_authorized"] == 0
        assert report["skipped"][0]["reason_code"] == expected
        assert "synthetic-private-cookie" not in json.dumps(report)
    from cco_surface_core import session_store
    session_store.put_session(BASE, "bob", headers=identities["bob"]["headers"],
                              check_url=BASE + "me", marker="unverified")
    report = json.loads(hunter.run_web_loop(BASE, live=True, blind_discovery=True,
                                           session_bindings=json.dumps(bindings)))
    assert report["skipped"][0]["reason_code"] == "session_not_recently_verified"


def test_differential_discovery_confirms_bola_without_explicit_owner(setup):
    hunter, identities, monkeypatch = setup
    policy = Path(os.environ["CCO_PROGRAM_POLICY_FILE"])
    policy.write_text(json.dumps({"required_request_headers": {"X-Research": "researcher"},
                                  "blind_discovery": {"synthetic_accounts_only": True,
                                                      "differential_ownership": True}}))
    for identity in identities.values():
        identity.pop("owned_objects_private", None)
    seen = []

    def send(method, url, **kwargs):
        assert method == "GET" and url.startswith(BASE)
        headers = kwargs.get("headers") or {}
        cookie = headers.get("Cookie") or ""
        actor = next((name for name in IDS if cookie == f"session={name}-secret"), "anon")
        seen.append((actor, url))
        if url == BASE:
            return Response(url, 200, {"links": [{"href": "/allowed/orders"}]})
        if url == BASE + "orders":
            if actor == "anon":
                return Response(url, 401, {"error": "login required"})
            return Response(url, 200, {"results": [
                {"id": IDS[actor], "href": f"/allowed/orders/{IDS[actor]}"}]})
        if url == BASE + "orders/" + IDS["alice"]:
            if actor == "anon":
                return Response(url, 401, {"error": "login required"})
            return Response(url, 200, {"id": IDS["alice"], "total": 50,
                                       "contact": "alice-marker@lab"})
        if url == BASE + "orders/" + IDS["bob"]:
            if actor != "bob":
                return Response(url, 403, {"error": "forbidden"})
            return Response(url, 200, {"id": IDS["bob"], "total": 60,
                                       "contact": "bob-marker@lab"})
        return Response(url, 404, {"error": "missing"})

    monkeypatch.setattr(requests, "request", send)
    raw = hunter.run_web_loop(BASE, live=True, crawl=False, blind_discovery=True,
                              blind_differential=True,
                              identities=json.dumps(identities),
                              headers='{"X-Research":"researcher"}',
                              sleep_s=0, max_validations=4)
    result = json.loads(raw)
    assert result["identity_discovery"]["status"] == "ready", result["identity_discovery"]
    assert result["identity_discovery"]["differential_candidates"] == 2
    rows = {row["url"]: row for row in result["validations"]}
    assert rows[BASE + "orders/" + IDS["alice"]]["verdict"] == "CONFIRMED"
    assert rows[BASE + "orders/" + IDS["bob"]]["verdict"] == "UNCONFIRMED"
    assert "alice-secret" not in raw and "alice-marker@lab" not in raw


def test_differential_requires_program_policy_opt_in(setup):
    hunter, identities, monkeypatch = setup
    monkeypatch.setattr(requests, "request",
                        lambda *a, **kw: pytest.fail("must not send"))
    result = json.loads(hunter.run_web_loop(BASE, live=True, crawl=False,
                                            blind_discovery=True, blind_differential=True,
                                            identities=json.dumps(identities), sleep_s=0))
    assert result["ok"] is False
    assert result["identity_discovery"]["status"] == "blocked"
    assert result["requests_authorized"] == 0


def test_program_policy_differential_key_is_fail_closed(setup, tmp_path):
    policy = Path(os.environ["CCO_PROGRAM_POLICY_FILE"])
    scope = Path(os.environ["CCO_SCOPE_FILE"])
    policy.write_text(json.dumps({"blind_discovery": {"synthetic_accounts_only": True,
                                                      "differential_ownership": True}}))
    PolicyEngine(cco_home=str(tmp_path / "h"), scope_file=str(scope),
                 program_policy_file=str(policy))
    policy.write_text(json.dumps({"blind_discovery": {"synthetic_accounts_only": True,
                                                      "unknown_key": True}}))
    with pytest.raises(ValueError):
        PolicyEngine(cco_home=str(tmp_path / "h"), scope_file=str(scope),
                     program_policy_file=str(policy))


def test_campaign_worker_uses_vault_bindings_with_a_shared_bounded_budget(setup):
    from campaign_runtime import CampaignRuntime
    from campaign_worker import CampaignWorker, LocalMCPExecutor

    hunter, identities, monkeypatch = setup
    bindings = _fresh_vault_bindings(identities)
    sent = []
    def send(method, url, **kwargs):
        cookie = kwargs["headers"]["Cookie"]
        actor = next(name for name in IDS if cookie == f"session={name}-secret")
        sent.append((actor, url))
        if url == BASE:
            body = {"current_user": {"id": actor + "-subject"}, "links": [{"href": "/allowed/orders"}]}
        else:
            body = {"results": [{"href": "/allowed/orders/" + IDS[actor]}]}
        return Response(url, 200, body)
    monkeypatch.setattr(requests, "request", send)
    runtime = CampaignRuntime(os.environ["CCO_HOME"])
    campaign = runtime.create_campaign("synthetic", scope_file=os.environ["CCO_SCOPE_FILE"], budget_requests=4)
    args = {"target": BASE, "live": True, "crawl": False, "blind_discovery": True,
            "blind_max_requests": 4, "sleep_s": 0, "max_validations": 0,
            "headers": '{"X-Research":"researcher"}', "session_bindings": json.dumps(bindings)}
    task = runtime.enqueue_task(campaign, "web", "hunter_run_web_loop", args, request_cost=4)
    executor = LocalMCPExecutor(os.environ["CCO_HOME"])
    def in_process_child(command, payload, *, env, limits):
        assert env["CCO_CAMPAIGN_WIRE_BUDGET"] == "4"
        with monkeypatch.context() as patch:
            patch.setenv("CCO_CAMPAIGN_WIRE_BUDGET", env["CCO_CAMPAIGN_WIRE_BUDGET"])
            output = hunter.run_web_loop(**payload["args"])
        return {"ok": True, "output": output}, {}
    monkeypatch.setattr(executor, "_run_subprocess", in_process_child)
    outcome = CampaignWorker(runtime, "worker", executor).run_once(campaign)
    assert outcome["task_id"] == task and outcome["status"] == "blocked"
    assert len(sent) == 4 and runtime.show_campaign(campaign)["requests_used"] == 4
    stored = runtime.list_tasks(campaign)[0]
    assert stored["status"] == "blocked" and runtime.claim_next_task("worker", campaign_id=campaign) is None
    assert "alice-secret" not in json.dumps(stored) and "bob-secret" not in json.dumps(stored)
