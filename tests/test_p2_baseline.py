"""P2 schema and serialization contracts, using synthetic requests only."""
import json
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode

import pytest

from conftest import load_server
from test_capture_binding import capture, save

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-servers/mcp-memory-server"))
sys.path.insert(0, str(ROOT / "mcp-servers/mcp-hunter"))
from cco_surface_core.fuzz import apply_canary
from cco_surface_core.normalize import normalize_record
from cco_surface_core.parsers import parse_openapi, parse_xhr
from cco_surface_core.store import ingest_records, query_surface
from cco_hunter_core.request_context import baseline_error, materialize_record


def spec(schema, media="application/json"):
    return {"openapi": "3.1.0", "servers": [{"url": "https://api.test"}],
            "paths": {"/search": {"post": {"requestBody": {"required": True,
                "content": {media: {"schema": schema}}}}}}}


def multipart():
    return ('--fixture\r\nContent-Disposition: form-data; name="title"\r\n\r\napple\r\n'
            '--fixture\r\nContent-Disposition: form-data; name="attachment"; filename="a.txt"\r\n'
            'Content-Type: text/plain\r\n\r\nsynthetic content\r\n--fixture--\r\n')


def test_form_blank_and_repeated_siblings_survive_mutation():
    record = normalize_record(parse_xhr([{"url": "https://api.test/search", "method": "POST",
        "content_type": "application/x-www-form-urlencoded", "body": "q=apple&empty=&tag=a&tag=b"}])[0])
    probe = apply_canary(record, "q", "body", "canary")
    assert parse_qsl(probe["baseline_data"], keep_blank_values=True) == [
        ("q", "apple"), ("empty", ""), ("tag", "a"), ("tag", "b")]
    assert parse_qsl(probe["data"], keep_blank_values=True) == [
        ("q", "canary"), ("empty", ""), ("tag", "a"), ("tag", "b")]


def test_multipart_capture_keeps_file_and_text_parts():
    record = normalize_record(parse_xhr([{"url": "https://api.test/search", "method": "POST",
        "headers": {"Content-Type": "multipart/form-data; boundary=fixture"}, "body": multipart()}])[0])
    assert {(p["in"], p["name"]) for p in record["params"]} == {
        ("body", "title"), ("body", "attachment")}
    probe = apply_canary(record, "title", "body", "canary")
    assert probe["baseline_files"]["attachment"] == ("a.txt", "synthetic content", "text/plain")
    assert probe["files"]["title"] == (None, "canary")
    assert not any(k.lower() == "content-type" for k in probe["headers"])


def test_openapi_multipart_content_type_survives_storage(tmp_path):
    document = spec({"type": "object", "required": ["title", "attachment"], "properties": {
        "title": {"type": "string", "enum": ["apple", "pear"]},
        "attachment": {"type": "string", "format": "binary"}}}, "multipart/form-data")
    db = str(tmp_path / "memory.db")
    ingest_records(parse_openapi(document), db_path=db)
    record = query_surface("api.test", db_path=db)[0]
    assert record["content_type"] == "multipart/form-data"
    assert record["params"][0]["in"] == "body"
    assert record["params"][1]["sample"] == "<unavailable>"
    assert materialize_record(record)[1] == ["body:attachment"]


def test_nullable_enum_nested_arrays_keep_schema_and_types(tmp_path):
    document = spec({"type": "object", "properties": {
        "choice": {"type": ["string", "null"], "enum": [None, "apple"], "default": None},
        "rows": {"type": "array", "minItems": 1, "items": {"type": "array", "minItems": 1,
            "items": {"type": "object", "required": ["enabled"], "properties": {
                "enabled": {"type": "boolean", "default": False}}}}}}})
    db = str(tmp_path / "memory.db")
    ingest_records(parse_openapi(document), db_path=db)
    record = query_surface("api.test", db_path=db)[0]
    choice = next(p for p in record["params"] if p["name"] == "choice")
    assert choice["nullable"] is True and choice["enum"] == [None, "apple"]
    probe = apply_canary(record, "choice", "json", "canary")
    assert probe["baseline_json"] == {"choice": None, "rows": [[{"enabled": False}]]}


@pytest.mark.parametrize("body,ctype", [
    (urlencode({"query": "query A($id: ID!) { a(id:$id) }", "operationName": "A",
                "variables": json.dumps({"id": "opaque:a", "enabled": False})}),
     "application/x-www-form-urlencoded"),
    ("query A { a }", "application/graphql"),
])
def test_graphql_non_json_envelopes_are_recognized(body, ctype):
    record = normalize_record(parse_xhr([{"url": "https://api.test/graphql", "method": "POST",
        "body": body, "content_type": ctype}])[0])
    assert record["operation"]["protocol"] == "graphql"
    assert record["operation"]["name"] == "A"
    assert materialize_record(record)[1] == []


@pytest.mark.parametrize("payload", [{"status": False, "data": None},
    {"error": {"message": "invalid"}, "data": None}, {"success": False}])
def test_rest_application_errors_fail_baseline(payload):
    assert baseline_error({"ok": True, "status": 200, "text": json.dumps(payload)}, {}) == "baseline_application_error"


@pytest.mark.parametrize("status", [400, 422, 404, 500])
def test_invalid_http_baseline_never_sends_canary(status, tmp_path, monkeypatch):
    hunter = load_server("hunter")
    record = normalize_record({"url": "https://api.test/search?q=apple", "method": "GET",
                               "params": [{"name": "q", "in": "query", "sample": "apple"}]})
    record["suggested_classes"] = ["xss_reflected", "ssti"]
    monkeypatch.setattr(hunter, "next_work", lambda *a, **kw: {"queue": [record]})
    calls = []
    monkeypatch.setattr(hunter, "_live_request", lambda *a, **kw: calls.append((a, kw)) or {
        "ok": True, "status": status, "text": '{"detail":"invalid request"}', "headers": {}})
    monkeypatch.setattr(hunter, "_light_oracle", lambda *a, **kw: pytest.fail("invalid baseline reached oracle"))
    monkeypatch.setattr(hunter, "write_artifact", lambda *a, **kw: "")
    result = json.loads(hunter.fuzz_attack_surface("https://api.test", live=True, max_requests=6, sleep_s=0))
    assert len(calls) == 1 and result["validator_queue"] == []
    if status in {400, 422}:
        assert result["fanout"][0]["next_action"] == "schema_repair"
        assert len(result["schema_repair_queue"]) == 1
        assert "detail" not in json.dumps(result["schema_repair_queue"])


@pytest.mark.parametrize("payload,reason", [
    ({"data": {"a": "ok"}, "errors": []}, ""),
    ({"data": {"a": "ok"}, "errors": [{"message": "partial failure"}]}, "baseline_graphql_errors"),
    ({"errors": []}, "baseline_graphql_missing_data"),
    ({"data": None}, "baseline_graphql_missing_data"),
    ({"data": {}, "errors": {}}, "baseline_graphql_invalid_response"),
    ([{"data": {}}, {"errors": [{"message": "failed"}]}], "baseline_graphql_errors"),
])
def test_graphql_baseline_response_boundaries(payload, reason):
    assert baseline_error({"status": 200, "text": json.dumps(payload)}, {"protocol": "graphql"}) == reason


@pytest.mark.parametrize("variables,default,missing", [
    ({"input": {"id": "opaque:a"}}, "", []),
    ({"input": None}, "", ["json:variables.input"]),
    ({}, ' = {id: "fixture"}', []),
    ({"input": None}, ' = {id: "fixture"}', ["json:variables.input"]),
])
def test_graphql_required_object_and_default_semantics(variables, default, missing):
    record = normalize_record(parse_xhr([{"method": "GET",
        "url": "https://api.test/graphql?" + urlencode({
            "query": "query A($input: Filter!" + default + ") { a(input:$input) }",
            "variables": json.dumps(variables)})}])[0])
    # A document containing string literals requires encrypted binding, but
    # the schema/default prerequisite check remains independently testable.
    _, reasons = materialize_record(record)
    assert [reason for reason in reasons if reason.startswith("json:variables")] == missing


def test_schema_alternatives_remain_explicit_and_do_not_fabricate_a_branch(tmp_path):
    record = parse_openapi(spec({"properties": {"choice": {"oneOf": [
        {"type": "string", "enum": ["apple"]}, {"type": "integer", "minimum": 2}]}}}))[0]
    db = str(tmp_path / "memory.db")
    ingest_records([record], db_path=db)
    param = query_surface("api.test", db_path=db)[0]["params"][0]
    assert param["sample"] == "<unavailable>" and len(param["schema_context"]["oneOf"]) == 2


def test_schema_enum_metadata_withholds_sensitive_values():
    secret = "synthetic-never-export"
    records = parse_openapi(spec({"properties": {
        "api_key": {"type": "string", "enum": [secret]},
        "options": {"type": "array", "items": {"type": "object", "properties": {
            "password": {"type": "string", "enum": [secret]}}}}}}))
    assert secret not in json.dumps(records)


@pytest.mark.parametrize("body,ctype", [
    ("--missing--", "multipart/form-data"),
    ('{"invalid"', "application/json"),
    ("x" * (1024 * 1024 + 1), "application/x-www-form-urlencoded"),
], ids=["missing-boundary", "invalid-json", "over-limit"])
def test_malformed_or_oversized_bodies_are_missing_prerequisites(body, ctype):
    record = normalize_record(parse_xhr([{"url": "https://api.test/search", "method": "POST",
        "body": body, "content_type": ctype}])[0])
    assert materialize_record(record)[1]


def test_batch_envelope_is_preserved_and_inline_literals_are_withheld():
    from cco_surface_core.fuzz import build_canary_plan
    body = [{"query": 'query A { a(token:"synthetic-private") }'}, {"query": "query B { b }"}]
    record = normalize_record(parse_xhr([{"url": "https://api.test/graphql", "method": "POST",
        "body": body, "content_type": "application/json"}])[0])
    assert record["params"][0]["body_root"] is True
    assert "synthetic-private" not in json.dumps(record)
    record["suggested_classes"] = ["xss_reflected"]
    assert build_canary_plan(record)[0]["reason"] == "graphql_operation_not_read_only"


def test_captured_json_baseline_retains_fields_outside_bounded_inventory(capture):
    _, headers, *_ = capture
    body = {"q": "apple", **{f"extra{i}": i for i in range(40)}}
    record = save(capture, {"url": "https://api.test/search", "method": "POST",
        "body": body, "content_type": "application/json"})
    hydrated, missing = materialize_record(record, headers=headers)
    assert missing == []
    probe = apply_canary(hydrated, "q", "json", "canary")
    assert probe["baseline_json"] == body
    assert probe["json_body"] == {**body, "q": "canary"}
    assert probe["baseline_headers"]["cookie"] == headers["Cookie"]


def test_captured_form_baseline_keeps_exact_serialization(capture):
    _, headers, *_ = capture
    body = "q=apple%20pie&tag=a&empty=&tag=b"
    record = save(capture, {"url": "https://api.test/search", "method": "POST",
        "body": body, "content_type": "application/x-www-form-urlencoded"})
    hydrated, missing = materialize_record(record, headers=headers)
    assert not missing
    probe = apply_canary(hydrated, "q", "body", "canary")
    assert probe["baseline_data"] == body
    assert parse_qsl(probe["data"], keep_blank_values=True) == [
        ("q", "canary"), ("tag", "a"), ("empty", ""), ("tag", "b")]


def test_binary_multipart_capture_uses_encrypted_packet_for_baseline(capture):
    _, headers, *_ = capture
    body = multipart().encode().replace(b"synthetic content", b"\xff\x00\x01")
    record = save(capture, {"url": "https://api.test/search", "method": "POST",
        "body": body, "content_type": "multipart/form-data; boundary=fixture"})
    hydrated, missing = materialize_record(record, headers=headers)
    assert not missing
    probe = apply_canary(hydrated, "title", "body", "canary")
    assert probe["baseline_data"] == body
    assert probe["files"]["attachment"] == ("a.txt", b"\xff\x00\x01", "text/plain")


def test_spa_full_discovery_without_sockets(tmp_path, monkeypatch):
    from types import SimpleNamespace
    sys.path.insert(0, str(ROOT / "scripts/lab"))
    import spa_lab
    from cco_surface_core.wire import scoped_surface_requests
    from cco_surface_core.store import memory_db_path
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://api.test/"}],
        "allow_osint": False, "allow_public_labs": False, "allow_loopback": False}))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path))
    kali = load_server("kali-tools")
    calls = []
    def send(url, **kwargs):
        from urllib.parse import urlsplit
        calls.append(url)
        handler = object.__new__(spa_lab._Handler)
        handler.path = urlsplit(url).path
        handler._send = lambda status, body, ctype="application/json": SimpleNamespace(
            status_code=status, text=body, content=body.encode(), url=url,
            headers={"Content-Type": ctype}, cookies=[])
        return handler._route()
    monkeypatch.setattr(kali.requests, "get", send)
    with scoped_surface_requests(lambda *_: (True, "fixture"), "https://api.test/"):
        report = json.loads(kali.discover_web_surface("https://api.test/", mode="active", probe_limit=32))
    assert not report.get("stop_reason"), report
    rows = query_surface("https://api.test/", db_path=memory_db_path(), limit=200)
    score = spa_lab.score_surface(spa_lab.build_truth(), rows)
    assert score["routes_found"] == score["routes_total"] == 13, score
    assert score["params_found"] == score["params_total"] == 18, score
    assert calls and all(url.startswith("https://api.test/") for url in calls)


@pytest.mark.parametrize("body", [[], {}, False, 0, None], ids=["array", "object", "false", "zero", "null"])
def test_captured_root_json_values_retain_their_shape(body, capture):
    _, headers, *_ = capture
    record = save(capture, {"url": "https://api.test/search", "method": "POST",
        "body": body, "content_type": "application/json"})
    hydrated, missing = materialize_record(record, headers=headers)
    assert not missing
    probe = apply_canary(hydrated, "$body", "json", "canary")
    if body is None:
        assert probe["baseline_data"] == "null"
        assert probe["data"] == '"canary"'
    else:
        assert probe["baseline_json"] == body and type(probe["baseline_json"]) is type(body)


def test_declared_form_array_object_and_json_encodings():
    document = spec({"type": "object", "properties": {
        "tags": {"type": "array", "example": ["apple", "pear"], "items": {"type": "string"}},
        "filter": {"type": "object", "example": {"enabled": False}},
        "options": {"type": "object", "example": {"rows": [[1, 2]]}}}}, "application/x-www-form-urlencoded")
    media = document["paths"]["/search"]["post"]["requestBody"]["content"]["application/x-www-form-urlencoded"]
    media["encoding"] = {"tags": {"explode": False}, "filter": {"style": "deepObject"},
                         "options": {"contentType": "application/json"}}
    record = normalize_record(parse_openapi(document)[0])
    probe = apply_canary(record, "tags", "body", "canary")
    assert parse_qsl(probe["baseline_data"]) == [
        ("tags", "apple,pear"), ("filter[enabled]", "false"), ("options", '{"rows":[[1,2]]}')]
    assert parse_qsl(probe["data"])[0] == ("tags", "canary")


@pytest.mark.parametrize("part_name,missing", [("attachment", []), ("missing", ["body:operations", "json:variables.file"])])
def test_graphql_multipart_upload_map_references_existing_parts(part_name, missing, capture):
    _, headers, *_ = capture
    operations = json.dumps({"query": "query A($file: Upload!) { a(file:$file) }", "variables": {"file": None}})
    mapping = json.dumps({part_name: ["variables.file"]})
    prefix = ('--fixture\r\nContent-Disposition: form-data; name="operations"\r\n\r\n' + operations + '\r\n'
              '--fixture\r\nContent-Disposition: form-data; name="map"\r\n\r\n' + mapping + '\r\n')
    body = prefix + multipart()
    record = save(capture, {"url": "https://api.test/graphql", "method": "POST", "body": body,
        "content_type": "multipart/form-data; boundary=fixture"})
    hydrated, reasons = materialize_record(record, headers=headers)
    assert hydrated["operation"]["name"] == "A"
    assert reasons == missing
