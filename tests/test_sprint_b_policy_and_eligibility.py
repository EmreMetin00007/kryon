"""Sprint B Slice 2 tests: policy & applicability gating for authorized POST carriers."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from full_agent_python_solver import PythonSolver
from policy_engine import PolicyEngine
from python_candidate_runtime import matches_model_call, parameter_candidates
from test_full_agent_python_solver import python_broker
from test_python_candidate_runtime import catalog, observe

_HUNTER_DIR = Path(__file__).resolve().parents[1] / "mcp-servers/mcp-hunter"
if str(_HUNTER_DIR) not in sys.path:
    sys.path.append(str(_HUNTER_DIR))
from cco_hunter_core.experiments import readonly_permission


def _policy_engine(tmp_path: Path, monkeypatch, policy: dict, target: str = "http://127.0.0.1:9000/") -> PolicyEngine:
    codex = tmp_path / ".codex"
    codex.mkdir(exist_ok=True)
    scope_file = codex / "scope.json"
    policy_file = codex / "program-policy.json"
    scope_file.write_text(json.dumps({
        "in_scope": [{"asset": target}],
        "scope_policy": "explicit_only",
        "allow_loopback": False,
        "allow_osint": False,
        "allow_public_labs": False,
    }), encoding="utf-8")
    policy_file.write_text(json.dumps(policy), encoding="utf-8")
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope_file))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy_file))
    return PolicyEngine(
        cco_home=str(tmp_path),
        scope_file=str(scope_file),
        program_policy_file=str(policy_file),
    )


def test_policy_engine_readonly_operations_allows_exact_post_and_blocks_others(tmp_path, monkeypatch):
    target = "http://127.0.0.1:9000/"
    search_url = target + "api/search"
    engine = _policy_engine(tmp_path, monkeypatch, {
        "blocked_http_methods": ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"],
        "readonly_operations": [
            {
                "method": "POST",
                "url": search_url,
                "operation_id": "op-search",
                "carriers": ["json"],
                "read_only": True,
            }
        ],
    }, target=target)

    # Exact matching validator POST with json carrier is allowed.
    ok_sqli = engine.validate_tool_invocation("validator_validate_sqli", {
        "target_url": search_url,
        "param": "query",
        "method": "POST",
        "carrier": "json",
        "body_template": '{"query":"{{PAYLOAD}}"}',
        "headers_json": '{"Content-Type":"application/json"}',
        "boolean_only": True,
    }, _policy_preflight=True)
    assert ok_sqli["allowed"] is True

    # Wrong carrier (form when only json is declared) is denied.
    bad_carrier = engine.validate_tool_invocation("validator_validate_sqli", {
        "target_url": search_url,
        "param": "query",
        "method": "POST",
        "carrier": "form",
        "body_template": "query={{PAYLOAD}}",
        "headers_json": '{"Content-Type":"application/x-www-form-urlencoded"}',
        "boolean_only": True,
    }, _policy_preflight=True)
    assert bad_carrier["allowed"] is False
    assert bad_carrier["reason"] == "blocked_http_method"

    # Unlisted POST endpoint is denied.
    other_url = engine.validate_tool_invocation("validator_validate_ssti", {
        "target_url": target + "api/delete",
        "param": "id",
        "method": "POST",
        "carrier": "json",
        "body_template": '{"id":"{{PAYLOAD}}"}',
        "headers_json": '{"Content-Type":"application/json"}',
    }, _policy_preflight=True)
    assert other_url["allowed"] is False
    assert other_url["reason"] == "blocked_http_method"

    # Path traversal remains read-only GET; POST is denied.
    trav = engine.validate_tool_invocation("validator_validate_path_traversal", {
        "target_url": search_url,
        "param": "file",
        "method": "POST",
        "carrier": "json",
    }, _policy_preflight=True)
    assert trav["allowed"] is False
    assert trav["reason"] == "blocked_http_method"

    # Raw curl_request / bash cannot use readonly_operations to bypass blocked_http_methods.
    curl_post = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": search_url,
        "method": "POST",
        "data": '{"query":"1"}',
    }, _policy_preflight=True)
    assert curl_post["allowed"] is False
    assert curl_post["reason"] == "blocked_http_method"


def test_policy_engine_rejects_malformed_or_mutating_readonly_operations(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="readonly_operations"):
        _policy_engine(tmp_path, monkeypatch, {
            "readonly_operations": [
                {"method": "DELETE", "url": "http://127.0.0.1:9000/items", "operation_id": "op-del", "read_only": True}
            ]
        })
    with pytest.raises(ValueError, match="readonly_operations"):
        _policy_engine(tmp_path, monkeypatch, {
            "readonly_operations": [
                {"method": "POST", "url": "http://127.0.0.1:9000/items", "operation_id": "op-1", "read_only": False}
            ]
        })
    assert readonly_permission(
        {"method": "POST", "url": "http://127.0.0.1:9000/api/search"},
        {"readonly_operations": [{
            "method": "POST", "url": "http://127.0.0.1:9000/api/search",
            "operation_id": "op-search", "carriers": ["json"], "read_only": True,
        }]},
        "op-search",
        carrier="form",
    ) is False


def test_parameter_candidates_and_model_matching_for_authorized_post_form_and_json(python_broker, tmp_path, monkeypatch):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    form_url = spec.target + "api/search"
    json_url = spec.target + "api/render"

    # Provision private policy authorizing both POST endpoints.
    policy_file = tmp_path / "holdout-program-policy.json"
    policy_file.write_text(json.dumps({
        "blocked_http_methods": ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"],
        "readonly_operations": [
            {
                "method": "POST",
                "url": form_url,
                "operation_id": "op-search-form",
                "carriers": ["form"],
                "read_only": True,
            },
            {
                "method": "POST",
                "url": json_url,
                "operation_id": "op-render-json",
                "carriers": ["json"],
                "read_only": True,
            },
        ],
    }), encoding="utf-8")
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy_file))
    broker.engine.program_policy_file = policy_file
    broker.engine.program_policy = json.loads(policy_file.read_text(encoding="utf-8"))

    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [
        {
            "url": "/api/search",
            "method": "POST",
            "content_type": "application/x-www-form-urlencoded",
            "params": [
                {"name": "q", "in": "body", "sample": "alpha"},
                {"name": "cat", "in": "body", "sample": "books"},
            ],
        },
        {
            "url": "/api/render",
            "method": "POST",
            "content_type": "application/json",
            "params": [
                {"name": "tmpl", "in": "json", "sample": "welcome"},
                {"name": "mode", "in": "json", "sample": "preview"},
            ],
        },
        {
            "url": "/api/unauthorized",
            "method": "POST",
            "content_type": "application/json",
            "params": [{"name": "x", "in": "json", "sample": "1"}],
        },
    ])

    rows = solver.plan_candidates(spec)
    # Unauthorized POST remains ineligible.
    unauth = [r for r in rows if r["route"].endswith("/api/unauthorized")]
    assert unauth and all(not r["eligible"] and r["reason_code"] == "unsupported_readonly_method" for r in unauth)

    # Form POST SQLi candidate carries exact form body_template, headers_json, baseline_value.
    form_sqli = next(
        r for r in rows
        if r["route"].endswith("/api/search") and r["param"] == "q" and r["vector"] == "injection-sqli"
    )
    assert form_sqli["eligible"] is True
    assert form_sqli["method"] == "POST"
    assert form_sqli["carrier"] == "form"
    assert form_sqli["arguments"] == {
        "target_url": form_url,
        "param": "q",
        "method": "POST",
        "carrier": "form",
        "body_template": "q={{PAYLOAD}}&cat=books",
        "headers_json": '{"Content-Type":"application/x-www-form-urlencoded"}',
        "baseline_value": "alpha",
        "boolean_only": True,
    }
    assert matches_model_call(form_sqli, form_sqli["tool"], form_sqli["arguments"])
    assert not matches_model_call(form_sqli, form_sqli["tool"], {**form_sqli["arguments"], "method": "GET"})
    assert not matches_model_call(form_sqli, form_sqli["tool"], {**form_sqli["arguments"], "body_template": "q={{PAYLOAD}}"})

    # JSON POST SSTI candidate carries exact json body_template and headers_json.
    json_ssti = next(
        r for r in rows
        if r["route"].endswith("/api/render") and r["param"] == "tmpl" and r["vector"] == "injection-ssti"
    )
    assert json_ssti["eligible"] is True
    assert json_ssti["method"] == "POST"
    assert json_ssti["carrier"] == "json"
    assert json_ssti["arguments"] == {
        "target_url": json_url,
        "param": "tmpl",
        "method": "POST",
        "carrier": "json",
        "body_template": '{"tmpl":"{{PAYLOAD}}","mode":"preview"}',
        "headers_json": '{"Content-Type":"application/json"}',
    }
    assert matches_model_call(json_ssti, json_ssti["tool"], json_ssti["arguments"])

    # Traversal remains ineligible on POST even when surface param is named 'file'.
    assert all(r["vector"] != "file-access" or not r["eligible"] for r in rows)


def test_conflicting_post_carriers_fail_closed(python_broker):
    broker = python_broker
    catalog(broker)
    source, spec = broker.tasks.specs[1:3]
    solver = PythonSolver(broker, model="model")
    observe(broker, solver, source, [
        {"url": "/api/search", "method": "POST", "params": [{"name": "q", "in": "form", "sample": "1"}]},
        {"url": "/api/search", "method": "POST", "params": [{"name": "q", "in": "json", "sample": "1"}]},
    ])
    rows = parameter_candidates(
        spec,
        solver.discovery(spec)["records"],
        {},
        profile_eligibility=lambda *_a, **_kw: {"eligible": True, "reason_code": ""},
    )
    assert rows and all(not r["eligible"] and r["reason_code"] == "conflicting_parameter_carrier" for r in rows)
