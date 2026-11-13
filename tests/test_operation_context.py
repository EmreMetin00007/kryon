"""Operation/observation identity and valid request reconstruction contracts."""
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import load_server

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mcp-servers/mcp-memory-server"))
from cco_surface_core.extract import extract_js_calls
from cco_surface_core.fuzz import apply_canary
from cco_surface_core.normalize import normalize_record
from cco_surface_core.parsers import parse_browser_crawl, parse_xhr
from cco_surface_core.store import ingest_records, query_surface, query_observations


def _xhr(query, value=1, operation_name=""):
    return {"url": "https://api.test/graphql", "method": "POST", "content_type": "application/json",
            "body": json.dumps({"query": query, "variables": {"id": value},
                                **({"operationName": operation_name} if operation_name else {})})}


def test_graphql_operations_separate_and_same_operation_preserves_observations(tmp_path):
    first = _xhr("query Order($id: ID!) { order(id: $id) { id } }", 1)
    second = _xhr("query Order($id: ID!) { order(id: $id) { id } }", 2)
    other = _xhr("query User($id: ID!) { user(id: $id) { id } }", 1)
    db = str(tmp_path / "memory.db")
    result = ingest_records(parse_xhr([first, second, other]), db_path=db)
    assert result["inserted"] == 2 and result["updated"] == 1
    records = query_surface("api.test", db_path=db)
    assert len({r["operation_id"] for r in records}) == 2
    order = next(r for r in records if r["operation"]["name"] == "Order")
    observations = query_observations(order["fingerprint"], db_path=db)
    assert len(observations) == 2
    assert {p["sample"] for obs in observations for p in obs["params"] if p["name"] == "variables.id"} == {1, 2}
    assert all(obs["request_state"] == "observed_request" for obs in observations)
    assert next(p["sample"] for p in order["params"] if p["name"] == "variables.id") == 2


def test_browser_capture_keeps_two_operations_at_same_url():
    records = parse_browser_crawl({"api_requests": [_xhr("query A { a }"), _xhr("query B { b }")]})
    assert len(records) == 2


@pytest.mark.parametrize("carrier", ["graphql", "json", "body", "header"])
def test_browser_capture_preserves_observation_values_and_repeated_order(tmp_path, carrier):
    if carrier == "graphql":
        first = _xhr("query Order($id: ID!) { order(id: $id) { id } }", "opaque:alpha")
        other = _xhr("query Order($id: ID!) { order(id: $id) { id } }", "opaque:beta")
        name = "variables.id"
    else:
        first = {"url": "https://api.test/search", "method": "POST"}
        other = dict(first)
        name = "q"
        if carrier == "header":
            first["headers"], other["headers"] = {"q": "alpha"}, {"q": "beta"}
        elif carrier == "body":
            first["content_type"] = other["content_type"] = "application/x-www-form-urlencoded"
            first["body"], other["body"] = "q=alpha", "q=beta"
        else:
            first["content_type"] = other["content_type"] = "application/json"
            first["body"], other["body"] = {"q": "alpha"}, {"q": "beta"}
    records = parse_browser_crawl({"api_requests": [first, other, first]})
    assert len(records) == 3
    db = str(tmp_path / "memory.db")
    result = ingest_records(records, db_path=db)
    assert result["inserted"] == 1 and result["updated"] == 2
    current = query_surface("api.test", db_path=db)[0]
    observations = query_observations(current["fingerprint"], db_path=db)
    assert current["observation_count"] == len(observations) == 2
    def sample(record):
        return next(p["sample"] for p in record["params"] if p["name"] == name)

    assert sample(current) == sample(records[0])
    assert len({sample(obs) for obs in observations}) == 2
    assert sample(next(obs for obs in observations if obs["id"] == current["observation_id"])) == sample(current)
    assert all(set(obs["sources"]) == {"xhr", "crawl"} for obs in observations)


def test_browser_route_dedup_does_not_discard_captured_request_source(tmp_path):
    url = "https://api.test/search?q=alpha"
    records = parse_browser_crawl({"pages": [{"url": url}], "links": [url],
                                   "api_requests": [{"url": url, "method": "GET"}]})
    assert len(records) == 2  # One route observation plus one actual capture.
    db = str(tmp_path / "memory.db")
    ingest_records(records, db_path=db)
    current = query_surface("api.test", db_path=db)[0]
    observations = query_observations(current["fingerprint"], db_path=db)
    assert len(observations) == 2
    latest = next(obs for obs in observations if obs["id"] == current["observation_id"])
    assert latest["request_state"] == "observed_request"
    assert set(latest["sources"]) == {"xhr", "crawl"}
    assert set(current["sources"]) == {"xhr", "crawl"}


def test_repeated_capture_becomes_current_without_duplicating_observation(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    hunter = load_server("hunter")
    first = {"url": "https://api.test/search?q=apple", "method": "GET"}
    other = {"url": "https://api.test/search?q=pear", "method": "GET"}
    ingest_records(parse_xhr([first]), db_path=hunter.MEM_DB)
    initial = query_surface("api.test", db_path=hunter.MEM_DB)[0]
    ingest_records(parse_xhr([other, first]), db_path=hunter.MEM_DB)
    current = query_surface("api.test", db_path=hunter.MEM_DB)[0]
    assert current["observation_id"] == initial["observation_id"]
    assert current["observation_count"] == 2
    assert current["url"] == first["url"]
    assert current["params"][0]["sample"] == "apple"
    inventory = hunter._coverage_inventory("api.test")
    assert inventory[0]["observation_id"] == current["observation_id"]


def test_schema_import_keeps_observed_request_binding_current(tmp_path):
    db = str(tmp_path / "memory.db")
    ingest_records(parse_xhr([{"url": "https://api.test/search?q=apple", "method": "GET"}]), db_path=db)
    initial = query_surface("api.test", db_path=db)[0]
    ingest_records([{"url": "https://api.test/search?q=schema", "method": "GET", "sources": ["openapi"],
                     "params": [{"name": "q", "in": "query", "sample": "schema",
                                 "sample_source": "openapi_example", "type": "string", "required": True}]}], db_path=db)
    current = query_surface("api.test", db_path=db)[0]
    assert current["observation_id"] == initial["observation_id"]
    assert current["observation_count"] == 2
    assert current["url"] == initial["url"]
    probe = apply_canary(current, "q", "query", "canary")
    assert probe["baseline_url"] == initial["url"]
    assert current["params"][0]["sample"] == "apple"
    assert current["params"][0]["required"] is True


def test_selected_operation_and_fragment_identity_ignore_unrelated_definitions():
    left = "query A($id: ID!) { node(id:$id) { ...Fields } } fragment Fields on Node { id } query B { b }"
    right = "query B { changed }\nfragment Fields on Node { id }\nquery A($id:ID!){node(id:$id){...Fields}}"
    a, b = [normalize_record(parse_xhr([_xhr(q, operation_name="A")])[0]) for q in (left, right)]
    assert a["operation_id"] == b["operation_id"]
    assert a["operation"]["kind"] == "query"
    assert a["operation"]["variables"] == [{"name": "id", "type": "ID!"}]
    changed = normalize_record(parse_xhr([_xhr(left.replace("{ id }", "{ id title }"), operation_name="A")])[0])
    assert changed["operation_id"] != a["operation_id"]


def test_ambiguous_graphql_document_is_not_assigned_an_operation():
    record = normalize_record(parse_xhr([_xhr("query A { a } query B { b }")])[0])
    assert record["operation"]["kind"] == "unknown"
    assert record["operation"]["selection"] == "ambiguous"


def test_js_operation_variables_do_not_leak_between_calls():
    js = """fetch('/graphql', {method:'POST', body:JSON.stringify({query:'query A($id: ID!) { a(id:$id) }', variables:{id:a}})});
    fetch('/graphql', {method:'POST', body:JSON.stringify({query:'query B($name: String!) { b(name:$name) }', variables:{name:b}})});"""
    records = extract_js_calls(js, "https://api.test")
    assert len(records) == 2
    params = {r["operation"]["name"]: {p["name"] for p in r["params"]} for r in records}
    assert "id" in params["A"] and "name" not in params["A"]
    assert "name" in params["B"] and "id" not in params["B"]


def test_origin_ports_and_parameter_carriers_have_distinct_fingerprints():
    base = {"url": "https://api.test:8443/search", "method": "GET",
            "params": [{"name": "q", "in": "query", "sample": "apple"}]}
    a = normalize_record(base, target="api.test")
    b = normalize_record({**base, "url": "https://api.test:9443/search"}, target="api.test")
    c = normalize_record({**base, "params": [{"name": "q", "in": "header", "sample": "apple"}]}, target="api.test")
    assert len({a["fingerprint"], b["fingerprint"], c["fingerprint"]}) == 3
    assert a["operation_id"] != b["operation_id"]


@pytest.mark.parametrize("url,method", [
    ("http://api.test/search", "GET"),
    ("https://other.test/search", "GET"),
    ("https://api.test:8443/search", "GET"),
    ("https://api.test/search", "POST"),
    ("https://api.test/other", "GET"),
])
def test_rest_operation_identity_retains_every_origin_and_route_dimension(url, method):
    original = normalize_record({"url": "https://api.test/search", "method": "GET"})
    changed = normalize_record({"url": url, "method": method})
    assert original["operation_id"] != changed["operation_id"]
    assert original["fingerprint"] != changed["fingerprint"]
    equivalent = normalize_record({"url": "https://API.TEST:443/search", "method": "GET"})
    assert original["operation_id"] == equivalent["operation_id"]


def test_same_named_query_body_and_header_fields_keep_their_opaque_values():
    record = normalize_record(parse_xhr([{
        "url": "https://api.test/search?id=tenant%3Aalpha%2Fitem%3A001",
        "method": "POST", "content_type": "application/x-www-form-urlencoded",
        "body": "id=body%3Abeta%2Fitem%3A002", "headers": {"id": "header:gamma/item:003"},
    }])[0])
    fields = {(p["in"], p["name"]): p["sample"] for p in record["params"]}
    assert fields == {("query", "id"): "tenant:alpha/item:001",
                      ("body", "id"): "body:beta/item:002",
                      ("header", "id"): "header:gamma/item:003"}


def test_legacy_record_is_readable_without_copying_tested_flags_to_new_operation(tmp_path):
    from cco_surface_core.store import SCHEMA_SQL
    db = str(tmp_path / "memory.db")
    with sqlite3.connect(db) as conn:
        legacy_schema = SCHEMA_SQL.replace("    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,", "    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP")
        legacy_schema = "\n".join(line for line in legacy_schema.splitlines() if not line.strip().startswith(("operation_json", "operation_id", "latest_observation_id")))
        conn.executescript(legacy_schema)
        conn.execute("INSERT INTO attack_surface (fingerprint,target,url,method,tested_classes) VALUES (?,?,?,?,?)",
                     ("legacy", "api.test", "https://api.test/graphql", "POST", '["sql_injection"]'))
    old = query_surface("api.test", db_path=db)[0]
    assert old["operation"]["kind"] == "legacy_unknown"
    ingest_records(parse_xhr([_xhr("query A { a }")]), db_path=db)
    new = next(r for r in query_surface("api.test", db_path=db) if r["fingerprint"] != "legacy")
    assert new["tested_classes"] == []


def test_xhr_post_keeps_query_body_and_header_parameters():
    request = {"url": "https://api.test/search?tenant=7", "method": "POST",
               "content_type": "application/json", "body": {"filter": "apple", "limit": 2},
               "headers": {"X-Tenant": "7", "Authorization": "Bearer private-token"}}
    record = normalize_record(parse_xhr([request])[0])
    assert {(p["in"], p["name"]) for p in record["params"]} >= {
        ("query", "tenant"), ("json", "filter"), ("json", "limit"), ("header", "X-Tenant")}
    assert "private-token" not in json.dumps(record)
    probe = apply_canary(record, "filter", "json", "canary")
    assert probe["baseline_url"] == request["url"]
    assert probe["baseline_json"] == {"filter": "apple", "limit": 2}
    assert probe["headers"]["X-Tenant"] == "7"


def test_schema_query_defaults_and_boolean_form_siblings_are_materialized():
    record = {"url": "https://api.test/search", "method": "POST", "params": [
        {"name": "q", "in": "query", "sample": "apple"},
        {"name": "limit", "in": "query", "sample": 7},
        {"name": "enabled", "in": "body", "sample": False},
        {"name": "filter", "in": "body", "sample": "all"}]}
    probe = apply_canary(record, "filter", "body", "canary")
    assert probe["baseline_url"] == "https://api.test/search?q=apple&limit=7"
    assert probe["baseline_data"] == "enabled=false&filter=all"
    assert probe["data"] == "enabled=false&filter=canary"


def test_validator_context_rejects_operation_and_session_swap(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    hunter = load_server("hunter")
    from cco_hunter_core.request_context import request_binding, store_context
    item = {"url": "https://api.test/search?q=apple", "method": "GET", "vuln_class": "sql_injection",
            "param": "q", "location": "query", "operation_id": "op-first"}
    context = {**item, "binding": request_binding({"Cookie": "session=alice"})}
    item["request_ref"] = store_context(context)
    calls = []
    monkeypatch.setattr(hunter, "_load_peer", lambda *a: SimpleNamespace(validate_sqli=lambda *a, **kw: calls.append(kw)))
    for swapped, cookie in (({**item, "operation_id": "op-other"}, "session=alice"), (item, "session=bob")):
        result = hunter._loop_validate(swapped, cookie=cookie)
        assert result["verdict"] == "INCONCLUSIVE"
    assert not calls


def test_graphql_errors_baseline_never_reaches_probe_or_candidate(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    hunter = load_server("hunter")
    record = normalize_record(parse_xhr([_xhr("query A($id: ID!) { a(id:$id) }", 1)])[0])
    record["suggested_classes"] = ["sql_injection"]
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    calls = []
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: calls.append((a, kw)) or {
        "ok": True, "status": 200, "text": '{"errors":[{"message":"invalid variable"}]}', "headers": {}})
    monkeypatch.setattr(hunter, "_light_oracle", lambda *a: pytest.fail("invalid baseline reached oracle"))
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    result = json.loads(hunter.fuzz_attack_surface("https://api.test", live=True, max_requests=2, sleep_s=0))
    assert len(calls) == 1
    assert result["validator_queue"] == []
    assert result["fanout"][0]["reason"] == "baseline_graphql_errors"


def test_required_field_without_sample_is_a_missing_prerequisite():
    from cco_hunter_core.request_context import materialize_record
    record = normalize_record({"url": "https://api.test/search", "params": [
        {"name": "q", "in": "query", "required": True}]})
    _, missing = materialize_record(record)
    assert missing == ["query:q"]


def test_signed_coverage_stays_on_its_graphql_operation(tmp_path, monkeypatch):
    from test_authenticated_web_api import _coverage_result
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    hunter = load_server("hunter")
    ingest_records(parse_xhr([_xhr("query A($id: ID!) { a(id:$id) }"),
                              _xhr("query B($id: ID!) { b(id:$id) }")]), db_path=hunter.MEM_DB)
    records = query_surface("api.test", db_path=hunter.MEM_DB)
    operation = records[0]["operation_id"]
    item = {"url": records[0]["url"], "method": "POST", "location": "json", "param": "variables.id",
            "observation_id": records[0]["observation_id"],
            "vuln_class": "sql_injection", "operation_id": operation, "run_id": "run-ops", "identity": "alice"}
    assert hunter._record_coverage_validation("api.test", item, _coverage_result(hunter, item))
    report = json.loads(hunter.coverage_report("api.test"))
    assert len(report["per_endpoint"]) == 2
    rows = {r["operation_id"]: r for r in report["per_endpoint"]}
    assert rows[operation]["observations"]
    assert all(not r["observations"] for key, r in rows.items() if key != operation)
    # A legacy event with no operation discriminator cannot close either new row.
    legacy = {**item, "run_id": "run-legacy"}
    legacy.pop("operation_id")
    assert hunter._record_coverage_validation("api.test", legacy, _coverage_result(hunter, legacy))
    assert all(not r["observations"] for r in json.loads(hunter.coverage_report("api.test"))["per_endpoint"])


def test_gap_keys_include_operation_identity():
    from cco_hunter_core.gap_queue import gap_plan
    base = {"endpoint": "https://api.test/graphql", "vuln_class": "sql_injection", "param": "id"}
    a, _ = gap_plan("api.test", {**base, "operation_id": "op-a"}, "scope-context")
    b, _ = gap_plan("api.test", {**base, "operation_id": "op-b"}, "scope-context")
    assert a != b


def test_request_binding_changes_with_scope_and_tenant(monkeypatch):
    from cco_hunter_core.request_context import request_binding
    from cco_validator_core import evidence
    first = request_binding({"Cookie": "session=alice", "X-Tenant": "a"})
    assert first != request_binding({"Cookie": "session=alice", "X-Tenant": "b"})
    monkeypatch.setattr(evidence, "current_scope_revision", lambda: "new-scope")
    assert first != request_binding({"Cookie": "session=alice", "X-Tenant": "a"})


def test_rest_query_body_is_not_misclassified_as_graphql():
    record = normalize_record(parse_xhr([{"url": "https://api.test/search", "method": "POST",
                                         "body": {"query": "apple"}}])[0])
    assert record["operation"]["protocol"] == "http"


def test_graphql_inline_secret_is_not_persisted(tmp_path):
    records = parse_xhr([_xhr('query A { signIn(password:"private-example") { id } }')])
    db = str(tmp_path / "memory.db")
    ingest_records(records, db_path=db)
    assert "private-example" not in json.dumps(query_surface("api.test", db_path=db))
    assert "private-example" not in json.dumps(query_observations(query_surface("api.test", db_path=db)[0]["fingerprint"], db_path=db))


def test_required_graphql_variable_missing_from_capture_has_reason():
    from cco_hunter_core.request_context import materialize_record
    record = normalize_record(parse_xhr([{"url": "https://api.test/graphql", "method": "POST",
                                         "body": {"query": "query A($id:ID!){a(id:$id)}", "variables": {}}}])[0])
    _, missing = materialize_record(record)
    assert "json:variables.id" in missing


def test_graphql_get_envelope_secrets_are_absent_from_url_and_observations(tmp_path):
    from urllib.parse import urlencode
    db = str(tmp_path / "memory.db")
    envelope = {"query": 'query A($password:String){a(password:$password, key:"inline-private")}',
                "variables": json.dumps({"password": "variable-private"})}
    ingest_records(parse_xhr([{"url": "https://api.test/graphql?" + urlencode(envelope),
                              "method": "GET"}]), db_path=db)
    record = query_surface("api.test", db_path=db)[0]
    assert record["operation"]["kind"] == "query"
    assert record["method"] == "GET"
    stored = json.dumps([record, query_observations(record["fingerprint"], db_path=db)])
    assert "inline-private" not in stored and "variable-private" not in stored


def test_loop_deduplication_does_not_drop_a_second_operation():
    from cco_hunter_core.loop import execute_web_loop
    base = {"url": "https://api.test/graphql", "method": "POST", "vuln_class": "sql_injection",
            "location": "json", "param": "id"}
    seen = []
    report = execute_web_loop("https://api.test", live=True, crawl=False,
                              fuzz=lambda *a, **kw: {"probes": 2, "validator_queue": [
                                  {**base, "operation_id": "op-a"}, {**base, "operation_id": "op-b"}]},
                              validate=lambda item, **kw: seen.append(item["operation_id"]) or {"verdict": "INCONCLUSIVE"})
    assert seen == ["op-a", "op-b"]
    assert len(report["validations"]) == 2


def test_previous_observation_cannot_close_a_new_capture(tmp_path, monkeypatch):
    from test_authenticated_web_api import _coverage_result
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    hunter = load_server("hunter")
    first = "https://api.test/search?q=apple"
    ingest_records(parse_xhr([{"url": first, "method": "GET"}]), db_path=hunter.MEM_DB)
    record = query_surface("api.test", db_path=hunter.MEM_DB)[0]
    item = {"url": first, "method": "GET", "location": "query", "param": "q", "vuln_class": "sql_injection",
            "operation_id": record["operation_id"], "observation_id": record["observation_id"],
            "run_id": "run-observations", "identity": "alice"}
    assert hunter._record_coverage_validation("api.test", item, _coverage_result(hunter, item))
    ingest_records(parse_xhr([{"url": "https://api.test/search?q=pear", "method": "GET"}]), db_path=hunter.MEM_DB)
    latest = query_surface("api.test", db_path=hunter.MEM_DB)[0]
    assert latest["operation_id"] == record["operation_id"]
    assert latest["observation_id"] != record["observation_id"]
    row = json.loads(hunter.coverage_report("api.test"))["per_endpoint"][0]
    assert "sql_injection" in row["partial"] and "sql_injection" not in row["tested"]
    assert any(cell["status"] == "not_tested" and cell["observation_id"] == str(latest["observation_id"])
               for cell in row["dimensions"] if cell["vuln_class"] == "sql_injection")
