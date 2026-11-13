"""Local OpenAPI references must survive ingestion and request reconstruction."""
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mcp-servers/mcp-memory-server"))
from cco_surface_core.fuzz import apply_canary
from cco_surface_core.parsers import parse_openapi
from cco_surface_core.store import ingest_records, query_surface


def _spec(schema):
    return {"openapi": "3.0.3", "servers": [{"url": "https://api.test"}],
            "paths": {"/search": {"post": {"requestBody": {"content": {
                "application/json": {"schema": schema}}}}}}, "components": {}}


def _params(spec):
    return {(p["in"], p["name"]): p for p in parse_openapi(spec)[0]["params"]}


def test_referenced_body_matches_inline_after_storage_and_canary(tmp_path):
    schema = {"type": "object", "required": ["quantity", "filter"], "properties": {
        "quantity": {"type": "integer", "minimum": 3},
        "enabled": {"type": "boolean", "default": False},
        "filter": {"type": "object", "required": ["term"], "properties": {
            "term": {"type": "string", "example": "apple"}}}}}
    inline = _spec(schema)
    ref = _spec({"$ref": "#/components/schemas/Search"})
    ref["components"] = {"schemas": {"Search": schema}}
    before = copy.deepcopy(ref)
    assert _params(ref) == _params(inline)
    assert ref == before
    db = str(tmp_path / "memory.db")
    ingest_records(parse_openapi(ref), db_path=db)
    record = query_surface("api.test", db_path=db)[0]
    params = {(p["in"], p["name"]): p for p in record["params"]}
    assert params[("json", "quantity")]["sample"] == 3
    assert params[("json", "quantity")]["type"] == "integer"
    assert params[("json", "quantity")]["required"] is True
    assert params[("json", "enabled")]["sample"] is False
    assert params[("json", "enabled")]["sample_source"] == "openapi_default"
    probe = apply_canary(record, "filter.term", "json", "cco-canary")
    assert probe["baseline_json"] == {"quantity": 3, "enabled": False, "filter": {"term": "apple"}}
    assert probe["json_body"] == {"quantity": 3, "enabled": False, "filter": {"term": "cco-canary"}}


def test_parameter_refs_path_inheritance_and_carrier_identity():
    spec = _spec({"type": "object", "properties": {"id": {"type": "integer", "example": 9}}})
    path = spec["paths"]["/search"]
    path["parameters"] = [{"$ref": "#/components/parameters/Id"},
                          {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 5}}]
    path["post"]["parameters"] = [
        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 10}},
        {"name": "id", "in": "header", "example": "header-id"}]
    spec["components"] = {"parameters": {"Id": {
        "name": "id", "in": "path", "required": True, "schema": {"type": "integer", "example": 7}}}}
    params = _params(spec)
    assert set(params) == {("path", "id"), ("header", "id"), ("json", "id"), ("query", "limit")}
    assert params[("query", "limit")]["sample"] == 10
    assert params[("path", "id")]["sample"] == 7


def test_request_body_refs_pointer_escapes_and_allof():
    spec = _spec({})
    spec["paths"]["/search"]["post"]["requestBody"] = {"$ref": "#/components/requestBodies/Search"}
    spec["components"] = {"requestBodies": {"Search": {"content": {"application/json": {
        "schema": {"allOf": [{"$ref": "#/components/schemas/a~1b~0c"},
                             {"type": "object", "properties": {"sort": {"type": "string", "enum": ["asc", "desc"]}}}]}}}}},
        "schemas": {"a/b~c": {"type": "object", "required": ["count"],
                               "properties": {"count": {"type": "integer", "default": 4}}}}}
    params = _params(spec)
    assert params[("json", "count")]["sample"] == 4
    assert params[("json", "count")]["required"] is True
    assert params[("json", "sort")]["sample"] == "asc"


@pytest.mark.parametrize("ref", ["https://external.test/schema.json", "#/missing", "#/components/schemas/Loop"])
def test_unresolved_and_cyclic_refs_do_not_fabricate_samples(ref):
    spec = _spec({"type": "object", "properties": {"item": {"$ref": ref}}})
    spec["components"] = {"schemas": {"Loop": {"$ref": "#/components/schemas/Loop"}}}
    param = _params(spec)[("json", "item")]
    assert param["sample"] == "<unavailable>"
    assert param["schema_unresolved"] is True


def test_recursive_schema_is_bounded_and_independent_fields_survive():
    spec = _spec({"$ref": "#/components/schemas/Node"})
    spec["components"] = {"schemas": {"Node": {"type": "object", "properties": {
        "label": {"type": "string", "example": "node"},
        "child": {"$ref": "#/components/schemas/Node"}}}}}
    params = _params(spec)
    assert params[("json", "label")]["sample"] == "node"
    assert len(params) <= 20
    assert any(p.get("schema_unresolved") for p in params.values())


def test_form_body_refs_and_secret_examples_are_redacted(tmp_path):
    spec = _spec({})
    spec["paths"]["/search"]["post"]["requestBody"] = {"content": {
        "application/x-www-form-urlencoded": {"schema": {"$ref": "#/components/schemas/Form"}}}}
    spec["components"] = {"schemas": {"Form": {"properties": {
        "query": {"type": "string", "example": "apple"},
        "api_key": {"type": "string", "example": "never-export-this"}}}}}
    records = parse_openapi(spec)
    assert "never-export-this" not in json.dumps(records)
    assert _params(spec)[("body", "api_key")]["sample"] == "<redacted>"
    db = str(tmp_path / "memory.db")
    ingest_records(records, db_path=db)
    assert query_surface("api.test", db_path=db)[0]["params"][0]["sample_source"] == "openapi_example"


@pytest.mark.parametrize("schema_first", [True, False])
def test_observed_values_take_precedence_without_losing_schema_metadata(tmp_path, schema_first):
    spec = _spec({"type": "object", "required": ["quantity"], "properties": {
        "quantity": {"type": "integer", "default": 3}}})
    schema_record = parse_openapi(spec)[0]
    observed = {"url": "https://api.test/search", "method": "POST", "sources": ["xhr"],
                "params": [{"name": "quantity", "in": "json", "sample": 7}]}
    records = [schema_record, observed] if schema_first else [observed, schema_record]
    db = str(tmp_path / "memory.db")
    for record in records:
        ingest_records([record], db_path=db)
    param = query_surface("api.test", db_path=db)[0]["params"][0]
    assert param["sample"] == 7
    assert "sample_source" not in param
    assert param["type"] == "integer" and param["required"] is True


def test_allof_repeated_property_keeps_type_and_example():
    spec = _spec({"allOf": [
        {"properties": {"quantity": {"type": "integer"}}},
        {"properties": {"quantity": {"example": 4}}}]})
    param = _params(spec)[("json", "quantity")]
    assert param["sample"] == 4 and param["type"] == "integer"


@pytest.mark.parametrize("schema", [{"properties": []}, {"properties": {"a": {"allOf": [None, False]}}},
                                  {"properties": {"a": {"type": {}, "required": True}}}])
def test_malformed_schema_nodes_do_not_crash_discovery(schema):
    assert isinstance(parse_openapi(_spec(schema)), list)


def test_operation_parameter_example_overrides_schema_and_preserves_false():
    spec = _spec({})
    spec["paths"]["/search"]["post"]["parameters"] = [
        {"name": "enabled", "in": "query", "example": False,
         "schema": {"type": "boolean", "default": True}}]
    param = _params(spec)[("query", "enabled")]
    assert param["sample"] is False and param["sample_source"] == "openapi_example"


def test_schema_generated_value_does_not_replace_explicit_example(tmp_path):
    explicit = _spec({"properties": {"quantity": {"type": "integer", "example": 7}}})
    generated = _spec({"properties": {"quantity": {"type": "integer"}}})
    db = str(tmp_path / "memory.db")
    ingest_records(parse_openapi(explicit), db_path=db)
    ingest_records(parse_openapi(generated), db_path=db)
    param = query_surface("api.test", db_path=db)[0]["params"][0]
    assert param["sample"] == 7 and param["sample_source"] == "openapi_example"


def test_local_path_item_reference_includes_inherited_parameters():
    spec = _spec({})
    spec["paths"] = {"/search": {"$ref": "#/components/pathItems/Search"}}
    spec["components"] = {"pathItems": {"Search": {
        "parameters": [{"name": "q", "in": "query", "schema": {"type": "string", "example": "apple"}}],
        "get": {}}}}
    assert _params(spec)[("query", "q")]["sample"] == "apple"


def test_cyclic_example_container_does_not_break_discovery():
    example = {}
    example["child"] = example
    spec = _spec({"properties": {"options": {"type": "object", "example": example}}})
    records = parse_openapi(spec)
    assert "<unavailable>" in json.dumps(records)


@pytest.mark.parametrize("schema, expected", [
    ({"type": "integer", "minimum": 1.5}, 2),
    ({"type": "integer", "minimum": float("inf")}, "<unavailable>"),
])
def test_numeric_schema_samples_handle_fractional_and_nonfinite_bounds(schema, expected):
    spec = _spec({"properties": {"quantity": schema}})
    assert _params(spec)[("json", "quantity")]["sample"] == expected
