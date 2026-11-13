"""Contracts for authenticated web/API execution; all data are synthetic."""

import json
from types import SimpleNamespace

import pytest

from conftest import load_server


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    import requests

    def denied(*args, **kwargs):
        raise AssertionError("network is disabled in these contract tests")

    monkeypatch.setattr(requests, "request", denied)


@pytest.fixture
def hunter(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_GRAPH_BACKEND", "networkx")
    return load_server("hunter")


def test_loop_carries_cookie_to_fuzz_without_putting_it_in_output(hunter):
    from cco_hunter_core.loop import execute_web_loop

    seen = {}

    def fuzz(target, **kwargs):
        seen.update(kwargs)
        return {"probes": 0, "validator_queue": []}

    cookie = "session=synthetic-private-cookie"
    result = execute_web_loop("https://own.test", live=True, crawl=False,
                              cookie=cookie, fuzz=fuzz)
    assert seen["cookie"] == cookie
    assert cookie not in json.dumps(result)


def test_fuzz_passes_cookie_to_transport_but_redacts_results(hunter, monkeypatch):
    seen = []
    record = {"fingerprint": "synthetic", "url": "https://own.test/search?q=1",
              "method": "GET", "params": [{"name": "q", "in": "query", "sample": "1"}],
              "suggested_classes": ["xss_reflected"], "tested_classes": []}
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "mark_tested", lambda *a, **kw: None)
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: seen.append(kw) or {
        "ok": True, "status": 200, "len": 2, "text": "ok", "headers": {}})
    monkeypatch.setattr(hunter, "write_artifact", lambda payload, **kw: "")
    secret = "synthetic-private-cookie"
    raw = hunter._loop_fuzz("https://own.test", cookie=f"session={secret}",
                           live=True, limit=1, sleep_s=0)
    assert seen and all(secret in h["headers"].get("Cookie", "") for h in seen)
    assert secret not in raw


def test_json_candidate_preserves_body_and_types_to_validator(hunter, monkeypatch):
    record = {"fingerprint": "json", "url": "https://own.test/api/search", "method": "POST",
              "params": [{"name": "filter", "in": "json", "sample": "apple"},
                         {"name": "tenant", "in": "json", "sample": 7},
                         {"name": "settings", "in": "json", "sample": {"active": True}}],
              "suggested_classes": ["sql_injection"], "tested_classes": []}
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "mark_tested", lambda *a, **kw: None)
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: {
        "ok": True, "status": 200, "len": 2, "text": "ok", "headers": {}})
    monkeypatch.setattr(hunter, "_light_oracle", lambda *a: ("LIKELY", "synthetic"))
    monkeypatch.setattr(hunter, "write_artifact", lambda payload, **kw: "")
    fuzzed = json.loads(hunter.fuzz_attack_surface("https://own.test", live=True,
                                                 limit=1, max_requests=2, sleep_s=0,
                                                 headers='{"Cookie":"session=synthetic"}'))
    queued = next(item for item in fuzzed["validator_queue"] if item["param"] == "filter")
    observed = {}

    def validate_sqli(target_url, param="", method="GET", body_template="",
                      headers_json="{}", carrier="query"):
        observed.update(target_url=target_url, param=param, method=method,
                        body_template=body_template, headers=json.loads(headers_json),
                        carrier=carrier)
        return json.dumps({"verdict": "INCONCLUSIVE"})

    monkeypatch.setattr(hunter, "_load_peer", lambda *a: SimpleNamespace(validate_sqli=validate_sqli))
    hunter._loop_validate(queued, cookie="session=synthetic")
    body = json.loads(observed["body_template"].replace("{{PAYLOAD}}", "marker"))
    assert body == {"filter": "marker", "tenant": 7, "settings": {"active": True}}
    assert observed["method"] == "POST"
    assert observed["headers"]["Content-Type"] == "application/json"
    assert observed["headers"]["Cookie"] == "session=synthetic"


def test_canary_preserves_recorded_method_and_typed_json(hunter):
    from cco_surface_core.fuzz import apply_canary

    record = {"url": "https://own.test/api/items", "method": "PATCH",
              "params": [{"name": "name", "in": "json", "sample": "before"},
                         {"name": "count", "in": "json", "sample": 2},
                         {"name": "options", "in": "json", "sample": {"active": True}}]}
    probe = apply_canary(record, "name", "json", "marker")
    assert probe["method"] == probe["baseline_method"] == "PATCH"
    assert probe["baseline_json"] == {"name": "before", "count": 2, "options": {"active": True}}
    assert probe["json_body"] == {"name": "marker", "count": 2, "options": {"active": True}}


def test_validator_keeps_method_body_and_other_headers_for_header_probe(monkeypatch):
    validator = load_server("validator")
    seen = {}

    def request(method, url, **kwargs):
        seen.update(method=method, url=url, **kwargs)
        return {"ok": True, "status": 200}

    monkeypatch.setattr(validator, "_request", request)
    validator._send_payload("https://own.test/api/search", "marker", param="X-Search",
                            method="PATCH", body_template='{"tenant":7}',
                            headers={"Content-Type": "application/json", "Cookie": "s=own"},
                            carrier="header")
    assert seen["method"] == "PATCH"
    assert json.loads(seen["data"]) == {"tenant": 7}
    assert seen["headers"]["Cookie"] == "s=own"
    assert seen["headers"]["X-Search"] == "marker"


def test_uuid_authz_uses_full_cookie_identities_and_explicit_owner(hunter, monkeypatch):
    url = "https://own.test/api/orders/5080c899-12bf-4523-89ce-d91a5ce3d1f4"
    identities = {
        "alice": {"headers": {"Cookie": "session=alice"},
                  "objects": [{"url": url, "marker": "alice-owned-marker"}]},
        "bob": {"headers": {"Cookie": "session=bob"}, "objects": []},
    }
    item = {"vuln_class": "bola", "url": url, "method": "GET",
            "owner_identity": "alice", "attacker_identity": "bob",
            "owner_marker": "alice-owned-marker", "owned_object": True}
    seen = {}

    def validate_idor(object_url, owner_headers_json, attacker_headers_json, owner_marker=""):
        seen.update(url=object_url, owner=json.loads(owner_headers_json),
                    attacker=json.loads(attacker_headers_json), marker=owner_marker)
        return json.dumps({"verdict": "UNCONFIRMED"})

    monkeypatch.setattr(hunter, "_load_peer", lambda *a: SimpleNamespace(validate_idor=validate_idor))
    out = hunter._loop_authz_validate(item, identities)
    assert out["verdict"] == "UNCONFIRMED"
    assert seen == {"url": url, "owner": {"Cookie": "session=alice"},
                    "attacker": {"Cookie": "session=bob"}, "marker": "alice-owned-marker"}


def test_authz_does_not_infer_ownership_from_two_sessions(hunter, monkeypatch):
    calls = []
    monkeypatch.setattr(hunter, "_load_peer", lambda *a: calls.append(a))
    item = {"vuln_class": "bola", "url": "https://own.test/api/orders/123",
            "method": "GET", "authz_candidate": True}
    out = hunter._loop_authz_validate(item, {
        "alice": {"Cookie": "session=alice"}, "bob": {"Cookie": "session=bob"}})
    assert out["verdict"] == "INCONCLUSIVE"
    assert "ownership" in out["error"].lower()
    assert not calls


def test_legacy_authz_candidate_without_ownership_never_probes(hunter, monkeypatch):
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: pytest.fail("unowned resource probed"))
    item = {"vuln_class": "bola", "url": "https://own.test/api/orders/123", "method": "GET"}
    identities = {"alice": {"Cookie": "session=alice"}, "bob": {"Cookie": "session=bob"}}
    result = hunter._loop_authz_validate(item, identities)
    assert result["verdict"] == "INCONCLUSIVE"
    assert "ownership" in result["error"].lower()


def test_observed_owned_uuid_reaches_authz_validator(hunter, monkeypatch):
    from cco_hunter_core.loop import execute_web_loop

    url = "https://own.test/api/orders/5080c899-12bf-4523-89ce-d91a5ce3d1f4"
    record = {"fingerprint": "object", "url": url, "method": "GET", "params": [],
              "suggested_classes": ["bola", "idor"], "tested_classes": []}
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "write_artifact", lambda payload, **kw: "")
    identities = {
        "alice": {"headers": {"Cookie": "session=alice"},
                  "objects": [{"url": url, "marker": "alice-owned-marker"}]},
        "bob": {"headers": {"Cookie": "session=bob"}, "objects": []},
    }
    called = []

    def authz(item, identities):
        called.append(item)
        return {"verdict": "UNCONFIRMED"}

    out = execute_web_loop("https://own.test", live=True, crawl=False,
                           fuzz=lambda target, **kw: hunter._loop_fuzz(target, **kw),
                           identities=identities, authz_validate=authz)
    assert called and called[0]["url"] == url
    assert called[0]["owner_identity"] == "alice"
    assert called[0]["attacker_identity"] == "bob"
    assert out["validations"] and out["validations"][0]["hook"] == "authz_oracle"


def test_coverage_does_not_spread_between_endpoints_or_global_lessons(hunter, monkeypatch):
    from cco_surface_core.store import ingest_records

    target = "own.test"
    first = "http://own.test/search?id=1"
    second = "http://own.test/search?id=2"
    ingest_records([{"url": first}, {"url": second}], target=target, db_path=hunter.MEM_DB)
    validator = load_server("validator")
    item = {"vuln_class": "sql_injection", "url": first, "method": "GET",
            "param": "id", "location": "query", "identity": "alice",
            "resource_owner": "alice", "run_id": "synthetic-run"}
    from cco_validator_core.evidence import validation_context
    with validation_context(hunter._coverage_context(item)):
        result = json.loads(validator._result(
            "SQL Injection", first, "UNCONFIRMED", "differential_boolean", {}, "-",
            guard={"transport_ok": True},
            request_evidence=[{"role": "baseline", "transport_ok": True, "status": 200,
                               "method": "GET", "request_url": first}]))
    assert hunter._record_coverage_validation(target, item, result)
    assert not hunter._record_coverage_validation(target, {**item, "param": "other"}, result)
    assert not hunter._record_coverage_validation(target, {**item, "identity": "bob"}, result)
    report = json.loads(hunter.coverage_report(target))
    per = {row["endpoint"]: row for row in report["per_endpoint"]}
    assert "sql_injection" in per[first]["tested"]
    assert "sql_injection" not in per[second]["tested"]

    import sqlite3
    with sqlite3.connect(hunter.LESSONS_DB) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS lessons (technique TEXT)")
        conn.execute("INSERT INTO lessons (technique) VALUES (?)", ("sql_injection",))
    other = "other.test"
    other_url = "http://other.test/search?id=1"
    ingest_records([{"url": other_url}], target=other, db_path=hunter.MEM_DB)
    other_report = json.loads(hunter.coverage_report(other))
    assert "sql_injection" not in other_report["per_endpoint"][0]["tested"]


def test_coverage_rejects_unpersisted_or_mismatched_artifact(hunter):
    item = {"vuln_class": "sql_injection", "url": "https://own.test/search?id=1",
            "method": "GET", "param": "id", "location": "query"}
    assert not hunter._record_coverage_validation("own.test", item, {
        "verdict": "CONFIRMED", "validation_id": "invented"})


def test_parameterless_probe_is_not_recorded_as_tested(hunter, monkeypatch):
    record = {"fingerprint": "no-params", "url": "https://own.test/search",
              "method": "GET", "params": [], "suggested_classes": ["sql_injection"],
              "tested_classes": []}
    marked = []
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "mark_tested", lambda *a, **kw: marked.append(a))
    monkeypatch.setattr(hunter, "write_artifact", lambda payload, **kw: "")
    out = json.loads(hunter.fuzz_attack_surface("https://own.test", live=True, sleep_s=0))
    assert not marked
    assert out["marked_tested"] == []


def test_recorded_json_path_changes_only_the_selected_nested_field(hunter):
    from cco_surface_core.fuzz import apply_canary
    from cco_surface_core.normalize import normalize_record

    source = {"url": "https://own.test/api/search", "method": "POST", "params": [
        {"name": "filter.term", "in": "json", "path": ["filter", "term"], "sample": "apple"},
        {"name": "filter.count", "in": "json", "path": ["filter", "count"], "sample": 2},
        {"name": "enabled", "in": "json", "sample": True},
    ]}
    record = normalize_record(source, target="own.test")
    probe = apply_canary(record, "filter.term", "json", "marker")
    assert probe["baseline_json"] == {"filter": {"term": "apple", "count": 2}, "enabled": True}
    assert probe["json_body"] == {"filter": {"term": "marker", "count": 2}, "enabled": True}
    assert probe["parameter_path"] == ["filter", "term"]


def test_expired_request_reference_stops_validator(hunter, monkeypatch):
    calls = []
    monkeypatch.setattr(hunter, "load_context", lambda ref: None)
    monkeypatch.setattr(hunter, "_load_peer", lambda *args: SimpleNamespace(
        validate_sqli=lambda *a, **kw: calls.append((a, kw))))
    result = hunter._loop_validate({"vuln_class": "sql_injection", "url": "https://own.test/search",
                                    "param": "q", "method": "POST", "location": "json",
                                    "request_ref": "expired"})
    assert result["verdict"] == "INCONCLUSIVE"
    assert "expired" in result["error"]
    assert not calls


def test_fuzz_budget_counts_baseline_and_probe_separately(hunter, monkeypatch):
    record = {"fingerprint": "budget", "url": "https://own.test/search?q=1", "method": "GET",
              "params": [{"name": "q", "in": "query", "sample": "1"}],
              "suggested_classes": ["xss_reflected"], "tested_classes": []}
    calls = []
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: calls.append(a) or {
        "ok": True, "status": 200, "text": "ok", "len": 2, "headers": {}})
    no_room = json.loads(hunter.fuzz_attack_surface("https://own.test", live=True,
                                                   max_requests=1, sleep_s=0))
    assert no_room["requests_sent"] == 0 and not calls
    enough = json.loads(hunter.fuzz_attack_surface("https://own.test", live=True,
                                                  max_requests=2, sleep_s=0))
    assert enough["requests_sent"] == len(calls) == 2


def test_non_get_canary_deferred_without_stopping_fuzz(hunter, monkeypatch):
    record = {"fingerprint": "defer-post", "url": "https://own.test/search?q=1", "method": "GET",
              "params": [{"name": "q", "in": "query", "sample": "1"}],
              "suggested_classes": ["xxe", "xss_reflected"], "tested_classes": []}
    calls = []
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: calls.append(a) or {
        "ok": True, "status": 200, "text": "ok", "len": 2, "headers": {}})
    result = json.loads(hunter.fuzz_attack_surface("https://own.test", live=True, sleep_s=0))
    assert result["stopped"] == ""
    deferred = [r for r in result["fanout"] if "read-only" in str(r.get("reason") or "")]
    assert deferred and all(r["coverage_status"] == "not_tested" for r in deferred)
    assert len(calls) == 2  # yalnız GET (xss) baseline + sonda calisti


def test_primary_identity_reaches_discovery(hunter, monkeypatch):
    seen = {}

    def discover(target, cookie="", headers=""):
        seen["headers"] = headers
        return {"ok": True}

    monkeypatch.setattr(hunter, "_loop_discover", discover)
    monkeypatch.setattr(hunter, "_loop_fuzz",
                        lambda *a, **kw: {"probes": 0, "validator_queue": []})
    identities = json.dumps({"member-a": {"headers": {"Authorization": "Bearer " + "tok" + "-a"}},
                             "member-b": {"headers": {"Authorization": "Bearer " + "tok" + "-b"}}})
    result = json.loads(hunter.run_web_loop(
        "https://own.test", live=True, crawl=False, identities=identities))
    assert result["ok"] is True
    assert "tok-a" in str(seen.get("headers") or "")


def test_dead_session_stops_before_mutated_request(hunter, monkeypatch):
    record = {"fingerprint": "dead-session", "url": "https://own.test/search?q=1", "method": "GET",
              "params": [{"name": "q", "in": "query", "sample": "1"}],
              "suggested_classes": ["xss_reflected"], "tested_classes": []}
    calls = []
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: calls.append(a) or {
        "ok": True, "status": 401, "text": "login", "len": 5, "headers": {}})
    result = json.loads(hunter.fuzz_attack_surface("https://own.test", live=True,
                                                 headers='{"Cookie":"session=expired"}',
                                                 max_requests=10, sleep_s=0))
    assert len(calls) == result["requests_sent"] == 1
    assert "session" in result["stopped"]
    assert result["fanout"][0]["coverage_status"] == "not_tested"


@pytest.mark.parametrize("failure", [
    {"ok": True, "status": 429, "text": "rate limited", "headers": {}},
    {"ok": True, "status": 401, "text": "session expired", "headers": {}},
    {"ok": True, "status": 302, "text": "", "headers": {}, "location": "/login"},
    {"ok": False, "status": None, "error": "transport failed"},
])
def test_probe_failure_or_session_loss_stops_before_another_request(hunter, monkeypatch, failure):
    record = {"fingerprint": "stop", "url": "https://own.test/search?q=1", "method": "GET",
              "params": [{"name": "q", "in": "query", "sample": "1"}],
              "suggested_classes": ["sql_injection"], "tested_classes": []}
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    calls = []

    def request(*args, **kwargs):
        calls.append((args, kwargs))
        return ({"ok": True, "status": 200, "text": "ok", "headers": {}}
                if len(calls) == 1 else failure)

    monkeypatch.setattr(hunter, "_live_request", request)
    result = json.loads(hunter.fuzz_attack_surface("https://own.test", live=True, sleep_s=0))
    assert len(calls) == 2
    assert result["stopped"]
    assert result["fanout"][0]["coverage_status"] == "not_tested"


def test_web_loop_does_not_validate_after_fuzz_stops():
    from cco_hunter_core.loop import execute_web_loop

    item = {"vuln_class": "sql_injection", "url": "https://own.test/search?q=1", "param": "q"}
    calls = []
    result = execute_web_loop(
        "https://own.test", live=True, crawl=False,
        fuzz=lambda *a, **kw: {"probes": 1, "stopped": "baseline rate limited", "validator_queue": [item]},
        validate=lambda *a, **kw: calls.append(a),
    )
    assert result["ok"] is False and not calls and not result["validations"]
    assert any(row.get("step") == "remaining" for row in result["skipped"] if isinstance(row, dict))


def test_authz_does_not_use_an_owned_url_from_another_origin(hunter):
    from cco_hunter_core.loop import execute_web_loop

    called = []
    owned = "https://other.test/api/orders/123"
    ids = {"alice": {"headers": {"Cookie": "s=a"}, "objects": [{"url": owned, "marker": "a"}]},
           "bob": {"headers": {"Cookie": "s=b"}}}
    result = execute_web_loop("https://own.test", live=True, crawl=False, identities=ids,
                              fuzz=lambda target, **kw: {"validator_queue": [{
                                  "authz_candidate": True, "vuln_class": "bola", "url": owned}]},
                              authz_validate=lambda *a: called.append(a))
    assert not called
    assert any("outside target origin" in str(item) for item in result["skipped"])


def test_fuzz_never_forwards_session_to_other_origin(hunter, monkeypatch):
    record = {"fingerprint": "foreign", "url": "https://other.test/search?q=1", "method": "GET",
              "params": [{"name": "q", "in": "query", "sample": "1"}],
              "suggested_classes": ["xss_reflected"], "tested_classes": []}
    calls = []
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: calls.append((a, kw)))
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    result = json.loads(hunter.fuzz_attack_surface("https://own.test", live=True,
                                                 headers='{"Cookie":"session=private"}', sleep_s=0))
    assert not calls and result["requests_sent"] == 0
    assert "outside the requested target origin" in json.dumps(result)


def test_coverage_untrusted_or_modified_event_never_counts(hunter, tmp_path):
    import sqlite3
    from cco_surface_core.store import ingest_records

    url = "http://own.test/search?id=1"
    ingest_records([{"url": url}], target="own.test", db_path=hunter.MEM_DB)
    validator = load_server("validator")
    item = {"vuln_class": "sql_injection", "url": url, "method": "GET",
            "param": "id", "location": "query"}
    from cco_validator_core.evidence import validation_context
    with validation_context(hunter._coverage_context(item)):
        artifact = json.loads(validator._result(
            "SQL Injection", url, "UNCONFIRMED", "differential_boolean", {}, "-",
            guard={"transport_ok": True},
            request_evidence=[{"role": "baseline", "transport_ok": True, "status": 200,
                               "method": "GET", "request_url": url}]))
    assert not hunter._record_coverage_validation("other.test", item, artifact)
    assert hunter._record_coverage_validation("own.test", item, artifact)
    with sqlite3.connect(hunter.MEM_DB) as conn:
        raw = conn.execute("SELECT signed_json FROM hunter_coverage_events").fetchone()[0]
        forged = json.loads(raw)
        forged["payload"]["url"] = "http://own.test/other?id=1"
        conn.execute("UPDATE hunter_coverage_events SET signed_json=?", (json.dumps(forged),))
    assert not hunter._verified_coverage_events("own.test")


def test_artifact_with_other_http_method_cannot_close_coverage(hunter):
    validator = load_server("validator")
    url = "http://own.test/search?q=1"
    item = {"vuln_class": "sql_injection", "url": url, "method": "GET", "param": "q"}
    from cco_validator_core.evidence import validation_context
    with validation_context(hunter._coverage_context(item)):
        artifact = json.loads(validator._result(
            "SQL Injection", url, "UNCONFIRMED", "differential_boolean", {}, "-",
            guard={"transport_ok": True},
            request_evidence=[{"role": "baseline", "transport_ok": True, "status": 200,
                               "method": "POST", "request_url": url}]))
    assert hunter._record_coverage_validation("own.test", item, artifact)
    events = hunter._verified_coverage_events("own.test")
    assert events[0]["status"] == "inconclusive"


def test_path_parameter_coverage_requires_the_observed_route(hunter):
    validator = load_server("validator")
    item = {"vuln_class": "sql_injection", "url": "http://own.test/items/{item_id}/view",
            "method": "GET", "param": "item_id", "location": "path"}
    from cco_validator_core.evidence import validation_context

    def artifact_for(observed_url):
        with validation_context(hunter._coverage_context(item)):
            return json.loads(validator._result(
                "SQL Injection", item["url"], "UNCONFIRMED", "differential_boolean", {}, "-",
                guard={"transport_ok": True}, request_evidence=[{
                    "role": "probe", "transport_ok": True, "status": 200,
                    "method": "GET", "request_url": observed_url}]))

    assert hunter._record_coverage_validation(
        "own.test", item, artifact_for("http://own.test/items/probe-value/view"))
    assert hunter._verified_coverage_events("own.test")[-1]["status"] == "tested_clean"
    assert hunter._record_coverage_validation(
        "own.test", item, artifact_for("http://own.test/items/probe-value/delete"))
    assert hunter._verified_coverage_events("own.test")[-1]["status"] == "inconclusive"


def test_confirmed_result_without_verified_evidence_does_not_enter_report_or_exploit():
    from cco_hunter_core.loop import execute_web_loop

    item = {"vuln_class": "sql_injection", "url": "https://own.test/search?q=1", "param": "q"}
    calls = []
    report = execute_web_loop(
        "https://own.test", live=True, crawl=False,
        fuzz=lambda *a, **kw: {"probes": 1, "validator_queue": [item]},
        validate=lambda *a, **kw: {"verdict": "CONFIRMED", "validation_id": "untrusted"},
        exploit=lambda *a: calls.append(a),
        on_validation=lambda *a: False,
        on_confirmation=lambda *a: False,
    )
    assert report["confirmed"] == [] and calls == []
    assert report["validations"][0]["verdict"] == "INCONCLUSIVE"


def test_confirmation_requires_signed_observation_on_expected_route(hunter):
    validator = load_server("validator")
    item = {"vuln_class": "sql_injection", "url": "http://own.test/items/{id}",
            "method": "GET", "param": "id", "location": "path"}
    from cco_validator_core.evidence import validation_context

    def artifact_for(url):
        with validation_context(hunter._coverage_context(item)):
            return json.loads(validator._result(
                "SQL Injection", item["url"], "CONFIRMED", "differential_boolean", {}, "-",
                guard={"transport_ok": True}, request_evidence=[{
                    "role": "probe", "transport_ok": True, "status": 200,
                    "method": "GET", "request_url": url}]))

    assert hunter._confirmed_validation_is_valid("own.test", item, artifact_for("http://own.test/items/marker"))
    assert not hunter._confirmed_validation_is_valid("own.test", item, artifact_for("http://own.test/other/marker"))


def test_idor_transport_failure_is_inconclusive(monkeypatch):
    validator = load_server("validator")
    replies = iter([
        {"ok": True, "status": 200, "text": "own marker", "len": 10, "headers": {}},
        {"ok": False, "status": None, "text": "", "len": 0, "headers": {}, "error": "timeout"},
    ])
    monkeypatch.setattr(validator, "_request", lambda *a, **kw: next(replies))
    result = json.loads(validator.validate_idor(
        "https://own.test/api/orders/1", '{"Cookie":"session=a"}',
        '{"Cookie":"session=b"}', owner_marker="own marker"))
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["guard"]["transport_ok"] is False


def test_redacted_required_field_is_not_guessed_or_sent(hunter, monkeypatch):
    record = {"fingerprint": "csrf", "url": "https://own.test/search", "method": "POST",
              "params": [{"name": "q", "in": "body", "sample": "apple"},
                         {"name": "csrf_token", "in": "body", "sample": "<redacted>"}],
              "suggested_classes": ["sql_injection"], "tested_classes": []}
    calls = []
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: calls.append((a, kw)))
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    result = json.loads(hunter.fuzz_attack_surface("https://own.test", live=True, sleep_s=0))
    assert not calls
    assert any("request field" in str(item.get("reason", "")) for item in result["fanout"])
    assert result["marked_tested"] == []


def test_session_fields_are_in_memory_and_bound_to_matching_identity(hunter, monkeypatch):
    from cco_hunter_core.loop import execute_web_loop
    from urllib.parse import parse_qs

    record = {"fingerprint": "csrf", "url": "https://own.test/search", "method": "POST",
              "params": [{"name": "q", "in": "body", "sample": "apple"},
                         {"name": "csrf_token", "in": "body", "sample": "<redacted>"}],
              "suggested_classes": ["sql_injection"], "tested_classes": []}
    calls, artifacts = [], []
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: calls.append(kw) or {
        "ok": True, "status": 200, "text": "ok", "len": 2, "headers": {}})
    monkeypatch.setattr(hunter, "write_artifact", lambda body, **kw: artifacts.append(body) or "")
    ids = {"alice": {"headers": {"Cookie": "session=alice"},
                     "request_fields": {"body:csrf_token": "synthetic-private-csrf"}}}
    result = execute_web_loop("https://own.test", live=True, crawl=False,
                              cookie="session=alice", identities=ids, fuzz=hunter._loop_fuzz)
    assert calls and all(parse_qs(call["data"])["csrf_token"] == ["synthetic-private-csrf"] for call in calls
                         if "csrf_token" in parse_qs(call["data"]))
    assert "synthetic-private-csrf" not in json.dumps(result)
    assert "synthetic-private-csrf" not in json.dumps(artifacts)
    assert "session=alice" not in json.dumps(artifacts)
    calls.clear()
    execute_web_loop("https://own.test", live=True, crawl=False,
                     cookie="session=other", identities=ids, fuzz=hunter._loop_fuzz)
    assert not calls


def test_captured_nested_json_retains_types_and_redacts_tokens():
    from workflow_compiler import _extract_params

    params = _extract_params("https://own.test/search", json.dumps({
        "filter": {"term": "apple", "limit": 7}, "enabled": True,
        "csrf_token": "synthetic-private-csrf"}), "application/json")
    by_name = {item["name"]: item for item in params}
    assert by_name["filter.limit"]["path"] == ["filter", "limit"]
    assert by_name["filter.limit"]["sample"] == 7
    assert by_name["enabled"]["sample"] is True
    assert by_name["csrf_token"]["sample"] == "<redacted>"
    assert "synthetic-private-csrf" not in json.dumps(params)


def test_sensitive_query_is_rehydrated_only_for_matching_session(hunter, monkeypatch):
    from cco_hunter_core.loop import execute_web_loop
    from cco_surface_core.normalize import normalize_record

    secret = "synthetic-private-query-token"
    record = normalize_record({"url": f"https://own.test/search?q=apple&csrf={secret}",
                               "method": "GET"}, target="own.test")
    assert secret not in json.dumps(record)
    record["suggested_classes"] = ["sql_injection"]
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    calls = []
    monkeypatch.setattr(hunter, "_live_request", lambda method, url, **kw: calls.append(url) or {
        "ok": True, "status": 200, "text": "ok", "len": 2, "headers": {}})
    monkeypatch.setattr(hunter, "_light_oracle", lambda *a: ("LIKELY", "synthetic"))
    validated = []

    def validate_sqli(target_url, param="", method="GET", body_template="",
                      headers_json="{}", carrier="query"):
        validated.append(target_url)
        return json.dumps({"verdict": "INCONCLUSIVE"})

    monkeypatch.setattr(hunter, "_load_peer", lambda *a: SimpleNamespace(validate_sqli=validate_sqli))
    identities = {"alice": {"headers": {"Cookie": "session=alice"},
                            "request_fields": {"query:csrf": secret}}}
    report = execute_web_loop("https://own.test", live=True, crawl=False,
                              cookie="session=alice", identities=identities,
                              fuzz=hunter._loop_fuzz, validate=hunter._loop_validate)
    assert calls and all(secret in url for url in calls)
    assert validated and secret in validated[0]
    assert secret not in json.dumps(report)


def test_path_candidate_keeps_template_and_sibling_json(hunter, monkeypatch):
    record = {"fingerprint": "path", "url": "https://own.test/items/{id}/view", "method": "PATCH",
              "params": [{"name": "id", "in": "path", "sample": "owned"},
                         {"name": "tenant", "in": "json", "sample": 7}],
              "suggested_classes": ["sql_injection"], "tested_classes": []}
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: {
        "ok": True, "status": 200, "len": 2, "text": "ok", "headers": {}})
    monkeypatch.setattr(hunter, "_light_oracle", lambda *a: ("LIKELY", "synthetic"))
    fuzzed = json.loads(hunter.fuzz_attack_surface("https://own.test", live=True,
                                                 max_requests=2, sleep_s=0))
    item = next(item for item in fuzzed["validator_queue"] if item["location"] == "path")
    seen = {}

    def validate_sqli(target_url, param="", method="GET", body_template="",
                      headers_json="{}", carrier="query"):
        seen.update(url=target_url, method=method, body=body_template, carrier=carrier)
        return json.dumps({"verdict": "INCONCLUSIVE"})

    monkeypatch.setattr(hunter, "_load_peer", lambda *a: SimpleNamespace(validate_sqli=validate_sqli))
    hunter._loop_validate(item)
    assert seen["url"] == "https://own.test/items/{id}/view"
    assert seen["method"] == "PATCH" and seen["carrier"] == "path"
    assert json.loads(seen["body"]) == {"tenant": 7}


def test_function_candidate_requires_explicit_distinct_roles(hunter, monkeypatch):
    from cco_hunter_core.loop import execute_web_loop

    url = "https://own.test/admin/export"
    record = {"fingerprint": "admin", "url": url, "method": "GET", "params": [],
              "suggested_classes": ["bfla"], "tested_classes": []}
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    identities = {
        "admin": {"role": "admin", "headers": {"Cookie": "session=admin"},
                  "functions": [{"url": url, "marker": "admin-marker", "test_data_only": True,
                                 "denied_roles": ["member"]}]},
        "member": {"role": "member", "headers": {"Cookie": "session=member"}},
    }
    calls = []
    out = execute_web_loop("https://own.test", live=True, crawl=False, identities=identities,
                           fuzz=hunter._loop_fuzz,
                           authz_validate=lambda item, ids: calls.append(item) or {"verdict": "UNCONFIRMED"})
    assert calls and calls[0]["vuln_class"] == "bfla"
    assert calls[0]["owner_role"] == "admin" and calls[0]["attacker_role"] == "member"
    assert out["validations"][0]["hook"] == "authz_oracle"
    identities["member"].pop("role")
    calls.clear()
    out = execute_web_loop("https://own.test", live=True, crawl=False, identities=identities,
                           fuzz=hunter._loop_fuzz,
                           authz_validate=lambda item, ids: calls.append(item))
    assert not calls and out["skipped"]


def test_bfla_public_content_is_inconclusive(monkeypatch):
    validator = load_server("validator")
    replies = iter([
        {"ok": True, "status": 200, "text": "admin-marker", "len": 12, "headers": {}},
        {"ok": True, "status": 200, "text": "admin-marker", "len": 12, "headers": {}},
        {"ok": True, "status": 200, "text": "admin-marker", "len": 12, "headers": {}},
    ])
    monkeypatch.setattr(validator, "_request", lambda *a, **kw: next(replies))
    result = json.loads(validator._validate_bfla_readonly(
        "https://own.test/admin/export", '{"Cookie":"session=admin"}',
        '{"Cookie":"session=member"}', "admin-marker"))
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["reportable"] is False


def _coverage_result(hunter, item):
    validator = load_server("validator")
    from cco_validator_core.evidence import validation_context
    with validation_context(hunter._coverage_context(item)):
        return json.loads(validator._result(
            "SQL Injection", item["url"], "UNCONFIRMED", "differential_boolean", {}, "-",
            guard={"transport_ok": True}, request_evidence=[{
                "role": "baseline", "transport_ok": True, "status": 200,
                "method": item["method"], "request_url": item["url"]}]))


def test_coverage_keeps_unprobed_parameters_open(hunter):
    from cco_surface_core.store import ingest_records, query_surface

    url = "http://own.test/search?q=apple&sort=date"
    ingest_records([{"url": url}], target="own.test", db_path=hunter.MEM_DB)
    base = {"vuln_class": "sql_injection", "url": url, "method": "GET", "location": "query",
            "operation_id": query_surface("own.test", db_path=hunter.MEM_DB)[0]["operation_id"],
            "observation_id": query_surface("own.test", db_path=hunter.MEM_DB)[0]["observation_id"],
            "identity": "alice", "run_id": "run1"}
    first = {**base, "param": "q"}
    assert hunter._record_coverage_validation("own.test", first, _coverage_result(hunter, first))
    row = json.loads(hunter.coverage_report("own.test"))["per_endpoint"][0]
    assert "sql_injection" in row["partial"] and "sql_injection" not in row["tested"]
    assert any(cell["param"] == "sort" and cell["status"] == "not_tested"
               for cell in row["dimensions"] if cell["vuln_class"] == "sql_injection")
    second = {**base, "param": "sort"}
    assert hunter._record_coverage_validation("own.test", second, _coverage_result(hunter, second))
    row = json.loads(hunter.coverage_report("own.test"))["per_endpoint"][0]
    assert "sql_injection" in row["tested"] and "sql_injection" not in row["partial"]


def test_planned_identity_is_not_covered_by_another_identity(hunter):
    from cco_surface_core.store import ingest_records, query_surface

    url = "http://own.test/search?q=apple"
    ingest_records([{"url": url}], target="own.test", db_path=hunter.MEM_DB)
    base = {"vuln_class": "sql_injection", "url": url, "method": "GET", "location": "query",
            "operation_id": query_surface("own.test", db_path=hunter.MEM_DB)[0]["operation_id"],
            "observation_id": query_surface("own.test", db_path=hunter.MEM_DB)[0]["observation_id"],
            "param": "q", "resource_owner": "alice", "run_id": "run1"}
    bob, carol = {**base, "identity": "bob"}, {**base, "identity": "carol"}
    assert hunter._record_coverage_plan("own.test", bob)
    assert hunter._record_coverage_plan("own.test", carol)
    assert hunter._record_coverage_validation("own.test", bob, _coverage_result(hunter, bob))
    row = json.loads(hunter.coverage_report("own.test"))["per_endpoint"][0]
    assert "sql_injection" in row["partial"]
    cells = [cell for cell in row["dimensions"] if cell["vuln_class"] == "sql_injection"]
    assert {(c["identity"], c["status"]) for c in cells} == {("bob", "tested_clean"), ("carol", "not_tested")}


def test_coverage_can_select_one_run_without_inheriting_another(hunter):
    from cco_surface_core.store import ingest_records, query_surface

    url = "http://own.test/search?q=apple"
    ingest_records([{"url": url}], target="own.test", db_path=hunter.MEM_DB)
    base = {"vuln_class": "sql_injection", "url": url, "method": "GET", "location": "query",
            "operation_id": query_surface("own.test", db_path=hunter.MEM_DB)[0]["operation_id"],
            "observation_id": query_surface("own.test", db_path=hunter.MEM_DB)[0]["observation_id"],
            "param": "q", "resource_owner": "alice"}
    first = {**base, "identity": "bob", "run_id": "run1"}
    second = {**base, "identity": "carol", "run_id": "run2"}
    assert hunter._record_coverage_plan("own.test", first)
    assert hunter._record_coverage_validation("own.test", first, _coverage_result(hunter, first))
    assert hunter._record_coverage_plan("own.test", second)
    current = json.loads(hunter.coverage_report("own.test"))
    previous = json.loads(hunter.coverage_report_run("own.test", "run1"))
    assert current["run_id"] == "run2"
    assert "sql_injection" not in current["per_endpoint"][0]["tested"]
    assert previous["run_id"] == "run1"
    assert "sql_injection" in previous["per_endpoint"][0]["tested"]
    missing = json.loads(hunter.coverage_report_run("own.test", "missing-run"))
    assert missing["error"] == "run not found for target"
