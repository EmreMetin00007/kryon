"""Typed neuro-symbolic test plans.

An LLM (or deterministic planner) proposes a bounded JSON plan. This module
validates that plan and interprets it through an injected transport. It never
uses eval/exec and never executes generated Python. The transport owns the
actual network or sandbox boundary; this core enforces plan shape, budgets
and anomaly-only feedback.
"""

from __future__ import annotations

import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable
from urllib.parse import urlparse

PLAN_SCHEMA = "cco-test-plan/1"
EXECUTION_SCHEMA = "cco-test-execution/1"
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
MUTATING_METHODS = {"PUT", "PATCH", "DELETE"}
MAX_STEPS = 50
MAX_VARIANTS = 50
MAX_RACE = 50


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_request(req: Any, where: str, allow_mutations: bool, out: list[str]) -> None:
    if not isinstance(req, dict):
        out.append(f"{where}: request must be an object")
        return
    method = str(req.get("method") or "").upper()
    if method not in METHODS:
        out.append(f"{where}: unsupported method {method or '<empty>'}")
    if method in MUTATING_METHODS and not allow_mutations:
        out.append(f"{where}: mutating method {method} requires allow_mutations=true")
    path = str(req.get("path") or "")
    if not path.startswith("/") or path.startswith("//") or "://" in path:
        out.append(f"{where}: path must be a site-relative path")
    for field in ("query", "json", "headers"):
        if field in req and not isinstance(req[field], dict):
            out.append(f"{where}: {field} must be an object")


def validate_test_plan(plan: Any) -> dict[str, Any]:
    """Validate a test plan without executing anything."""
    diagnostics: list[str] = []
    if not isinstance(plan, dict):
        return {"valid": False, "diagnostics": ["plan must be an object"], "plan": None}
    if plan.get("status") == "draft_hypothesis" or plan.get("synthetic"):
        diagnostics.append("draft_hypothesis requires observed_context")
    if plan.get("schema") != PLAN_SCHEMA:
        diagnostics.append(f"schema must be {PLAN_SCHEMA}")
    target = str(plan.get("target") or "")
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        diagnostics.append("target must be an absolute http(s) origin")
    budget = plan.get("budget") or {}
    if not isinstance(budget, dict):
        diagnostics.append("budget must be an object")
        budget = {}
    max_requests = budget.get("max_requests", 20)
    max_concurrency = budget.get("max_concurrency", 4)
    timeout_ms = budget.get("timeout_ms", 5000)
    if not _is_int(max_requests) or not 1 <= max_requests <= 200:
        diagnostics.append("budget.max_requests must be between 1 and 200")
    if not _is_int(max_concurrency) or not 1 <= max_concurrency <= 20:
        diagnostics.append("budget.max_concurrency must be between 1 and 20")
    if not _is_int(timeout_ms) or not 1 <= timeout_ms <= 10000:
        diagnostics.append("budget.timeout_ms must be between 1 and 10000")
    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        diagnostics.append("steps must be a non-empty list")
        steps = []
    if len(steps) > MAX_STEPS:
        diagnostics.append(f"steps exceeds {MAX_STEPS}")
    if "experiment" in plan:
        experiment = plan["experiment"]
        if not isinstance(experiment, dict) or experiment.get("status") != "ready":
            diagnostics.append("experiment prerequisites are not ready")
        else:
            origin = (parsed.scheme, parsed.netloc)
            for stage in experiment.get("stages") or []:
                if "request" in stage:
                    url = urlparse(str(stage["request"].get("url") or ""))
                    if (url.scheme, url.netloc) != origin:
                        diagnostics.append("experiment request outside target origin")
    allow_mutations = bool(plan.get("allow_mutations"))
    seen: dict[str, dict[str, Any]] = {}
    for idx, step in enumerate(steps):
        where = f"steps[{idx}]"
        if not isinstance(step, dict):
            diagnostics.append(f"{where}: step must be an object")
            continue
        step_id = str(step.get("id") or "")
        if not step_id:
            diagnostics.append(f"{where}: id is required")
        elif step_id in seen:
            diagnostics.append(f"{where}: duplicate step id {step_id}")
        kind = str(step.get("type") or "")
        if kind == "request":
            _validate_request(step, where, allow_mutations, diagnostics)
        elif kind == "mutate":
            base = seen.get(str(step.get("base") or ""))
            if not base or base.get("type") != "request":
                diagnostics.append(f"{where}: mutate.base must reference a previous request step")
            overrides = step.get("overrides")
            if not isinstance(overrides, list) or not overrides:
                diagnostics.append(f"{where}: overrides must be a non-empty list")
            elif len(overrides) > MAX_VARIANTS:
                diagnostics.append(f"{where}: overrides exceeds {MAX_VARIANTS}")
            else:
                for override in overrides:
                    if not isinstance(override, dict):
                        diagnostics.append(f"{where}: each override must be an object")
        elif kind == "race":
            count = step.get("count")
            if not _is_int(count) or not 2 <= count <= MAX_RACE:
                diagnostics.append(f"{where}: race.count must be between 2 and {MAX_RACE}")
            _validate_request(step.get("request"), f"{where}.request", allow_mutations, diagnostics)
        elif kind == "delay":
            ms = step.get("ms")
            if not _is_int(ms) or not 0 <= ms <= 5000:
                diagnostics.append(f"{where}: delay.ms must be between 0 and 5000")
        else:
            diagnostics.append(f"{where}: unsupported type {kind or '<empty>'}")
        if step_id:
            seen[step_id] = step
    return {"valid": not diagnostics, "diagnostics": diagnostics, "plan": plan if not diagnostics else None}


def plan_from_hypothesis(
    endpoint: dict[str, Any],
    hypothesis_class: str,
    target: str = "https://example.test",
    *, capabilities=None, prerequisites=None, policy=None,
) -> dict[str, Any]:
    """Compile a P5 hypothesis and its private observed request into a P6 plan.

    Names from a schema are inventory, not a valid request. Missing context
    produces a blocked plan. No body values, operations or races are invented.
    """
    from .experiments import build_experiment
    context = endpoint.get("request_context") or {}
    item = {**endpoint, "vuln_class": hypothesis_class}
    experiment = build_experiment(item, context, endpoint.get("mutation"),
        control=endpoint.get("negative_control"), capabilities=capabilities,
        prerequisites=prerequisites, policy=policy)
    if endpoint.get("synthetic") or endpoint.get("status") == "draft_hypothesis":
        experiment.update(status="blocked", reason="draft_hypothesis_requires_observed_context", stages=[])
    if "mutation" not in endpoint:
        experiment.update(status="blocked", reason="observed_mutation_required", stages=[])
    return {
        "schema": PLAN_SCHEMA,
        "target": target,
        "hypothesis": {"class": hypothesis_class, "endpoint": endpoint.get("path"),
                       "status": "draft_hypothesis"},
        "budget": {"max_requests": 3, "max_concurrency": 1, "timeout_ms": 5000},
        "experiment": experiment,
        "steps": [{"id": s["role"], "type": "request", "method": s["request"]["method"],
                   "path": urlparse(s["request"]["url"]).path or "/"}
                  for s in experiment["stages"] if "request" in s],
    }


def _shape(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): _shape(value[k], depth + 1) for k in sorted(value)}
    if isinstance(value, list):
        return [_shape(value[0], depth + 1)] if value else []
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if value is None:
        return "null"
    return "string"


def _body_schema(body: Any) -> str:
    if body is None:
        return "empty"
    if isinstance(body, (dict, list)):
        shape = _shape(body)
    elif isinstance(body, str):
        try:
            shape = _shape(json.loads(body))
        except Exception:
            return f"text:{'small' if len(body) < 128 else 'large'}"
    else:
        return type(body).__name__
    return hashlib.sha256(
        json.dumps(shape, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]


def _request_from_step(step: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": str(step.get("method") or "GET").upper(),
        "path": str(step.get("path") or "/"),
        "query": copy.deepcopy(step.get("query") or {}),
        "json": copy.deepcopy(step.get("json") or {}),
        "headers": copy.deepcopy(step.get("headers") or {}),
    }


def _merge_override(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    req = copy.deepcopy(base)
    for field in ("query", "json", "headers"):
        if isinstance(override.get(field), dict):
            req[field] = {**(req.get(field) or {}), **copy.deepcopy(override[field])}
    if override.get("path"):
        req["path"] = str(override["path"])
    if override.get("method"):
        req["method"] = str(override["method"]).upper()
    return req


def _expand(plan: dict[str, Any]) -> list[tuple[str, int, dict[str, Any], bool]]:
    out: list[tuple[str, int, dict[str, Any], bool]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for step in plan.get("steps") or []:
        step_id = str(step.get("id") or "")
        kind = step.get("type")
        if kind == "request":
            req = _request_from_step(step)
            by_id[step_id] = req
            out.append((step_id, 0, req, False))
        elif kind == "mutate":
            base = by_id.get(str(step.get("base") or ""), {})
            for idx, override in enumerate(step.get("overrides") or []):
                out.append((step_id, idx, _merge_override(base, override), False))
        elif kind == "race":
            req = _request_from_step(step.get("request") or {})
            for idx in range(int(step.get("count") or 0)):
                out.append((step_id, idx, copy.deepcopy(req), True))
    return out


def _observe(step_id: str, variant: int, req: dict[str, Any], response: Any) -> dict[str, Any]:
    if not isinstance(response, dict):
        response = {"status": 0, "body": ""}
    body = response.get("body", response.get("text", ""))
    length = response.get("response_length", response.get("length"))
    if length is None:
        length = len(body.encode("utf-8", "ignore")) if isinstance(body, str) else len(str(body))
    return {
        "step_id": step_id,
        "variant": variant,
        "method": req["method"],
        "path": req["path"],
        "status": int(response.get("status") or 0),
        "elapsed_ms": float(response.get("elapsed_ms") or response.get("duration_ms") or 0),
        "response_length": int(length or 0),
        "body_schema": _body_schema(body),
        "error": str(response.get("error") or "")[:80],
    }


def execute_test_plan(
    plan: Any,
    transport: Callable[[dict[str, Any]], dict[str, Any]],
    *, oracle=None, verify=None,
) -> dict[str, Any]:
    """Interpret a validated plan through an injected transport.

    The transport is the sandbox/network boundary. This function enforces the
    request budget and returns metadata-only observations.
    """
    validation = validate_test_plan(plan)
    if not validation["valid"]:
        return {
            "schema": EXECUTION_SCHEMA,
            "valid": False,
            "requests_executed": 0,
            "truncated": False,
            "observations": [],
            "anomalies": [],
            "diagnostics": validation["diagnostics"],
        }
    budget = plan.get("budget") or {}
    max_requests = int(budget.get("max_requests", 20))
    if "experiment" in plan:
        from .experiments import execute_experiment
        execution = execute_experiment(plan["experiment"], transport,
            oracle or (lambda *_: {}), verify or (lambda *_: False), max_requests=max_requests)
        return {"schema": EXECUTION_SCHEMA, "valid": True, "truncated": False,
                "observations": execution["stages"], "anomalies": [], "diagnostics": [], **execution}
    max_concurrency = int(budget.get("max_concurrency", 4))
    expanded = _expand(plan)
    selected = expanded[:max_requests]
    truncated = len(expanded) > len(selected)

    def run(item: tuple[str, int, dict[str, Any], bool]) -> dict[str, Any]:
        step_id, variant, req, _is_race = item
        try:
            response = transport(copy.deepcopy(req))
        except Exception as exc:  # transport boundary: report type only
            response = {"status": 0, "body": "", "error": type(exc).__name__}
        return _observe(step_id, variant, req, response)

    observations: list[dict[str, Any]] = []
    sequential = [item for item in selected if not item[3]]
    races = [item for item in selected if item[3]]
    observations.extend(run(item) for item in sequential)
    if races:
        with ThreadPoolExecutor(max_workers=min(max_concurrency, len(races))) as pool:
            observations.extend(pool.map(run, races))
    observations.sort(key=lambda o: (o["step_id"], o["variant"]))

    baselines: dict[tuple[str, str], dict[str, Any]] = {}
    anomalies: list[dict[str, Any]] = []
    for obs in observations:
        key = (obs["method"], obs["path"])
        base = baselines.setdefault(key, obs)
        if obs is base:
            continue
        signals = []
        if obs["status"] != base["status"]:
            signals.append("status")
        if obs["body_schema"] != base["body_schema"]:
            signals.append("body_schema")
        delta = obs["response_length"] - base["response_length"]
        if abs(delta) >= 8 and abs(delta) / max(base["response_length"], 1) >= 0.20:
            signals.append("response_length")
        if signals:
            anomalies.append({
                "step_id": obs["step_id"],
                "variant": obs["variant"],
                "signals": signals,
            })
    race_groups: dict[str, list[dict[str, Any]]] = {}
    for item, obs in zip(selected, sorted(observations, key=lambda o: (o["step_id"], o["variant"]))):
        if item[3]:
            race_groups.setdefault(obs["step_id"], []).append(obs)
    for step_id, group in race_groups.items():
        statuses = {o["status"] for o in group}
        schemas = {o["body_schema"] for o in group}
        if len(statuses) > 1 or len(schemas) > 1:
            anomalies.append({
                "step_id": step_id,
                "variant": None,
                "signals": ["race_divergence"],
            })
    return {
        "schema": EXECUTION_SCHEMA,
        "valid": True,
        "requests_executed": len(observations),
        "truncated": truncated,
        "observations": observations,
        "anomalies": anomalies,
        "diagnostics": [],
        "notes": ["Only response metadata is returned; bodies and header values are omitted."],
    }
