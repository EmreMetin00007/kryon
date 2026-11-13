"""Cross-source request imports share identity without live traffic."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers/mcp-memory-server"))

from workflow_compiler import ingest_captured_requests  # noqa: E402
from cco_surface_core.normalize import normalize_record  # noqa: E402
from cco_surface_core.parsers import parse_browser_crawl, parse_xhr  # noqa: E402
from cco_surface_core.store import ingest_records, query_observations, query_surface  # noqa: E402


@pytest.mark.parametrize("source", ["agent_browse", "proxy", "mitm", "custom_capture"])
def test_compiler_and_browser_capture_share_observation_and_carriers(tmp_path, source):
    url = "https://api.test/search?id=query-object"
    headers = {"Content-Type": "application/json", "id": "header-object",
               "Authorization": "Bearer synthetic-private", "Cookie": "sid=synthetic-cookie"}
    request = {"url": url, "method": "POST", "content_type": "application/json",
               "body": {"id": "body-object"}, "headers": headers, "status": 200}
    db = str(tmp_path / "agent_memory.db")
    ingest_records(parse_browser_crawl({"api_requests": [request]}), db_path=db)
    original = query_surface("api.test", db_path=db)[0]
    result = ingest_captured_requests([{**request, "req_headers": headers,
                                        "req_body": request["body"]}], source=source,
                                      cco_home=str(tmp_path), allow={"api.test"})
    assert result["inserted"] == 0 and result["updated"] == 1
    current = query_surface("api.test", db_path=db)[0]
    assert current["fingerprint"] == original["fingerprint"]
    assert current["observation_id"] == original["observation_id"]
    observations = query_observations(current["fingerprint"], db_path=db)
    assert len(observations) == 1
    assert observations[0]["request_state"] == "observed_request"
    assert set(observations[0]["sources"]) == {"xhr", "crawl", source}
    fields = {(p["in"], p["name"]): p["sample"] for p in current["params"]}
    assert fields == {("query", "id"): "query-object", ("header", "id"): "header-object",
                      ("json", "id"): "body-object"}
    assert b"synthetic-private" not in Path(db).read_bytes()
    assert b"synthetic-cookie" not in Path(db).read_bytes()


def test_compiler_preserves_long_selected_graphql_descriptor_before_redaction(tmp_path):
    document = "query Order($id:ID!){order(id:$id){" + " ".join("field" + str(i) for i in range(35)) + "}} query Other{other{id}}"
    assert len(document) > 120
    envelope = {"query": document, "operationName": "Order", "variables": {"id": "opaque:tenant/item"}}
    request = {"url": "https://api.test/graphql", "method": "POST", "body": envelope,
               "content_type": "application/json"}
    expected = normalize_record(parse_xhr([request])[0])
    ingest_captured_requests([{**request, "req_body": json.dumps(envelope)}], cco_home=str(tmp_path))
    current = query_surface("api.test", db_path=str(tmp_path / "agent_memory.db"))[0]
    assert current["operation_id"] == expected["operation_id"]
    assert current["operation"]["selection"] == "selected"
    assert current["operation"]["name"] == "Order"
    assert next(p["sample"] for p in current["params"] if p["name"] == "query") == "<unavailable>"


def test_compiler_keeps_allowlist_and_explicit_parameter_samples(tmp_path):
    result = ingest_captured_requests([
        {"url": "https://api.test/search?q=from-url", "method": "GET",
         "params": [{"name": "q", "in": "query", "sample": "explicit"}],
         "req_headers": {"X-Tenant": "tenant-alpha"}},
        {"url": "https://outside.test/search?q=outside", "method": "GET"},
    ], cco_home=str(tmp_path), allow={"api.test"})
    assert result["filtered_out"] == 1
    current = query_surface("api.test", db_path=str(tmp_path / "agent_memory.db"))[0]
    assert next(p["sample"] for p in current["params"] if p["name"] == "q") == "explicit"
    assert next(p["sample"] for p in current["params"] if p["name"] == "X-Tenant") == "tenant-alpha"


def test_operation_field_union_keeps_observation_values_and_surface_flags(tmp_path):
    from cco_surface_core.store import mark_tested, next_work, query_operations

    db = str(tmp_path / "memory.db")
    request = {"url": "https://api.test/search?q=observed", "method": "GET"}
    ingest_records(parse_xhr([request]), db_path=db)
    original = query_surface("api.test", db_path=db)[0]
    mark_tested("api.test", original["fingerprint"], ["sql_injection"], db_path=db)
    ingest_records([{"url": "https://api.test/search", "sources": ["openapi"], "params": [
        {"name": "q", "in": "query", "sample": "schema", "sample_source": "openapi_example"},
        {"name": "limit", "in": "query", "sample": 10, "type": "integer", "required": False,
         "sample_source": "openapi_default"}]}], db_path=db)
    rows = query_surface("api.test", db_path=db)
    assert len(rows) == 2  # Stable historical surface identities stay readable.
    operations = query_operations("api.test", db_path=db)
    assert len(operations) == 1
    operation = operations[0]
    assert {f["name"] for f in operation["fields"]} == {"q", "limit"}
    assert len(operation["surface_records"]) == 2
    assert "observed" not in json.dumps(operation) and "schema" not in json.dumps(operation["fields"])
    assert all("sample" not in f and "tested_classes" not in f for f in operation["fields"])
    current = next(r for r in rows if r["fingerprint"] == original["fingerprint"])
    assert current["observation_id"] == original["observation_id"]
    assert current["params"][0]["sample"] == "observed"
    assert current["tested_classes"] == ["sql_injection"]
    assert all(not r["tested_classes"] for r in rows if r is not current)
    queue = next_work("api.test", db_path=db)
    assert queue["total_operations"] == 1
    assert queue["operations"] == operations
    assert all({f["name"] for f in r["operation_fields"]} == {"q", "limit"} for r in queue["queue"])


def test_operation_field_union_preserves_carriers_paths_and_operation_boundaries(tmp_path):
    from cco_surface_core.store import query_operations

    db = str(tmp_path / "memory.db")
    records = [{"url": "https://api.test/search", "method": "POST", "params": [
        {"name": "id", "in": carrier, "sample": carrier}]} for carrier in ("query", "header", "body")]
    records += [{"url": "https://api.test/search", "method": "POST", "params": [
        {"name": "obj.id", "in": "json", "path": path, "sample": "value"}]} for path in (["obj", "id"], ["obj.id"])]
    records += [{"url": "https://api.test:8443/search", "method": "POST"},
                {"url": "https://api.test/search", "method": "GET"}]
    ingest_records(records, target="api.test", db_path=db)
    operations = query_operations("api.test", db_path=db)
    assert len(operations) == 3
    shared = next(op for op in operations if len(op["surface_records"]) == 5)
    assert len(shared["fields"]) == 5
    assert {(f["in"], f["name"]) for f in shared["fields"]} >= {
        ("query", "id"), ("header", "id"), ("body", "id")}
    assert {tuple(f["path"]) for f in shared["fields"] if f["in"] == "json"} == {("obj", "id"), ("obj.id",)}
