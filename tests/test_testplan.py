"""Neuro-symbolic test-plan DSL (offline; injected transport)."""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "mcp-servers", "mcp-hunter"))

from cco_hunter_core.testplan import (
    execute_test_plan,
    plan_from_hypothesis,
    validate_test_plan,
)


def _plan():
    return {
        "schema": "cco-test-plan/1",
        "target": "https://example.test",
        "hypothesis": {"class": "negative_quantity", "endpoint": "/api/checkout"},
        "budget": {"max_requests": 5, "max_concurrency": 3, "timeout_ms": 1000},
        "steps": [
            {"id": "base", "type": "request", "method": "POST", "path": "/api/checkout",
             "json": {"quantity": 1}},
            {"id": "neg", "type": "mutate", "base": "base",
             "overrides": [{"json": {"quantity": -1}}, {"json": {"quantity": 0}}]},
            {"id": "race", "type": "race", "count": 3,
             "request": {"method": "POST", "path": "/api/checkout", "json": {"quantity": 1}}},
        ],
    }


def test_validate_and_execute_with_fake_transport():
    plan = validate_test_plan(_plan())
    assert plan["valid"] is True

    def transport(request):
        qty = (request.get("json") or {}).get("quantity", 1)
        if qty == -1:
            return {"status": 200, "elapsed_ms": 25, "body": '{"accepted":true,"SECRET":"x"}'}
        return {"status": 200, "elapsed_ms": 20, "body": '{"accepted":true}'}

    out = execute_test_plan(_plan(), transport)
    assert out["schema"] == "cco-test-execution/1"
    assert out["requests_executed"] == 5  # budget caps race expansion
    assert out["truncated"] is True
    assert any(a["step_id"] == "neg" for a in out["anomalies"])
    assert "SECRET" not in repr(out)


def test_plan_from_hypothesis_is_bounded_and_typed():
    endpoint = {
        "method": "GET", "path": "/api/search", "param": "q", "location": "query",
        "url": "https://example.test/api/search?q=observed", "mutation": "probe",
        "request_context": {"url": "https://example.test/api/search?q=observed", "method": "GET"},
    }
    plan = plan_from_hypothesis(endpoint, "sql_injection", capabilities={"validate_sqli": True})
    assert plan["schema"] == "cco-test-plan/1"
    assert validate_test_plan(plan)["valid"] is True
    assert plan["budget"]["max_requests"] <= 20
    assert plan["experiment"]["status"] == "ready"
    assert [s["role"] for s in plan["experiment"]["stages"]] == ['baseline', 'mutation', 'negative_control', 'oracle']
    assert not any(step["type"] == "race" for step in plan["steps"])


def test_invalid_plans_fail_closed():
    bad = _plan()
    bad["steps"][0]["path"] = "https://evil.test/steal"
    result = validate_test_plan(bad)
    assert result["valid"] is False
    assert result["diagnostics"]

    destructive = _plan()
    destructive["steps"] = [{"id": "d", "type": "request", "method": "DELETE", "path": "/api/x"}]
    result = validate_test_plan(destructive)
    assert result["valid"] is False
    assert any("mutation" in d for d in result["diagnostics"])


def test_execute_rejects_invalid_plan_without_calling_transport():
    called = []
    out = execute_test_plan({"schema": "bad"}, lambda req: called.append(req) or {})
    assert out["requests_executed"] == 0
    assert called == []
    assert out["diagnostics"]
