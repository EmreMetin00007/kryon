"""P6 experiment routing. Plans describe prerequisites; they never grant access."""
from __future__ import annotations

import copy
import hashlib
import json
from urllib.parse import urlsplit

SCHEMA = "cco-web-experiment/1"
CARRIERS = ("query", "json", "form", "header", "cookie", "path")


def _route(tool, oracle, *, carriers=CARRIERS, permissions=("scope", "approval", "wire_budget"), prerequisites=()):
    return {"tool": tool, "carriers": carriers, "surfaces": ("rest", "graphql"),
            "permissions": permissions, "oracle": oracle, "prerequisites": prerequisites}


ROUTES = {
    "sql_injection": _route("validate_sqli", ("boolean_differential", "error_control", "timing_repeat")),
    "ssti": _route("validate_ssti", ("arithmetic_two_rounds", "literal_negative_control")),
    "path_traversal": _route("validate_path_traversal", ("declared_file_signature", "missing_file_control")),
    "xss_reflected": _route("validate_xss_reflection", ("browser_execution", "silent_controls"),
                            prerequisites=("browser_execution",)),
    "ssrf": _route("validate_ssrf_oob", ("signed_callback_provenance", "probe_correlation"),
                   carriers=("query",), prerequisites=("oob_collector",)),
    "open_redirect": _route("validate_open_redirect", ("destination_host", "allowlist_control"), carriers=("query",)),
    "bola": _route("validate_idor", ("p4_identity_object_matrix", "owner_marker", "denied_access_rule"),
                   prerequisites=("access_context",)),
    "bfla": _route("_validate_bfla_readonly", ("p4_identity_function_matrix", "denied_role_rule"),
                   prerequisites=("access_context",)),
    "field_authorization": _route("existing_authz_oracle", ("p4_identity_field_matrix", "denied_field_rule"),
                                  prerequisites=("access_context", "field_oracle")),
    "authentication_bypass": _route("validate_auth_bypass", ("p4_anonymous_matrix", "protected_marker"),
                                   prerequisites=("access_context",)),
    "jwt": _route("jwt_kid_jku_verify", ("observed_token_flow", "deterministic_validator"),
                  prerequisites=("jwt_flow",)),
    "oauth": _route("oauth_discovery_checklist", ("observed_oauth_flow", "deterministic_validator"),
                    prerequisites=("oauth_flow", "oauth_oracle")),
}
ALIASES = {"lfi": "path_traversal", "idor": "bola"}
PASSIVE_ADAPTERS = ("websocket", "grpc", "smuggling", "cache")


def protocol_access(item):
    """Access dimensions are names observed in an operation, never active probes."""
    operation = item.get("operation") or {}
    if operation.get("protocol") == "graphql":
        return {"protocol": "graphql", "operation": operation.get("name") or "",
                "selection": operation.get("selection") or "unavailable",
                "fields": list(operation.get("fields") or []),
                "variables": [v["name"] for v in operation.get("variables") or [] if isinstance(v, dict) and v.get("name")],
                "dimensions": ["operation", "field", "variable"]}
    return {"protocol": "rest", "dimensions": ["object", "function", "field"],
            "resource_family": item.get("resource_family") or "", "version": item.get("api_version") or ""}


def tool_lifecycle(*, available=False, applicable=False, runnable=False, executed=False, validated=False, reason=""):
    available = bool(available)
    applicable = available and bool(applicable)
    runnable = applicable and bool(runnable)
    executed = runnable and bool(executed)
    validated = executed and bool(validated)
    return {"available": available, "applicable": applicable, "runnable": runnable,
            "executed": executed, "validated": validated, "reason": reason}


def route_experiment(item, capabilities, prerequisites=None):
    kind = ALIASES.get(item.get("vuln_class"), item.get("vuln_class"))
    prerequisites = prerequisites or {}
    if kind in PASSIVE_ADAPTERS:
        return {"class": kind, "mode": "passive_inventory", **tool_lifecycle(
            available=capabilities.get(kind, False), applicable=item.get("protocol") == kind,
            reason="active_adapter_deferred")}
    route = ROUTES.get(kind)
    if route is None:
        return {"class": kind, **tool_lifecycle(reason="unsupported_class")}
    carrier = {"body": "form"}.get(item.get("location") or item.get("carrier") or "query",
                                    item.get("location") or item.get("carrier") or "query")
    available = bool(capabilities.get(route["tool"]))
    flow_missing = kind in {"jwt", "oauth"} and not prerequisites.get(kind + "_flow")
    applicable = carrier in route["carriers"] and not flow_missing
    missing = [p for p in route["prerequisites"] if not prerequisites.get(p)]
    reason = ("validator_unavailable" if not available else "observed_flow_required" if flow_missing else
              "unsupported_carrier" if not applicable else "missing_" + missing[0] if missing else "")
    return {"class": kind, **copy.deepcopy(route), **tool_lifecycle(
        available=available, applicable=applicable, runnable=not reason, reason=reason)}


def readonly_permission(request, policy, operation_id="", *, carrier=""):
    """Only exact operator policy declarations admit POST; schema flags cannot."""
    method = str(request.get("method") or "").upper()
    if method in {"GET", "HEAD", "OPTIONS"}:
        return True
    norm_carrier = {"body": "form"}.get(str(carrier or "").strip().lower(), str(carrier or "").strip().lower())
    if method != "POST" or (not operation_id and norm_carrier not in {"form", "json"}):
        return False
    declarations = policy.get("readonly_operations") or []
    return isinstance(declarations, list) and any(
        isinstance(row, dict) and row.get("method") == method and row.get("url") == request.get("url")
        and (row.get("operation_id") == operation_id if operation_id else True)
        and row.get("read_only") is True
        and (not norm_carrier or not isinstance(row.get("carriers"), list) or norm_carrier in row["carriers"])
        for row in declarations)


def request_from_context(item, context):
    """Private request packet; callers must not put it into reports or queues."""
    request = {"url": context.get("url") or item.get("url") or "",
               "method": str(context.get("method") or item.get("method") or "GET").upper(),
               "headers": copy.deepcopy(context.get("baseline_headers") or {}),
               "json_body": copy.deepcopy(context.get("baseline_json")), "data": context.get("baseline_data")}
    if request["json_body"] is not None and request["data"] is not None:
        raise ValueError("ambiguous_request_body")
    if request["json_body"] is not None and not any(k.lower() == "content-type" for k in request["headers"]):
        request["headers"]["Content-Type"] = "application/json"
    if context.get("baseline_cookies"):
        if any(k.lower() == "cookie" for k in request["headers"]):
            raise ValueError("ambiguous_cookie_context")
        request["headers"]["Cookie"] = "; ".join(f"{k}={v}" for k, v in context["baseline_cookies"].items())
    parsed = urlsplit(request["url"])
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.fragment:
        raise ValueError("invalid_baseline_url")
    carrier = {"body": "form"}.get(item.get("location") or item.get("carrier") or "query",
                                    item.get("location") or item.get("carrier") or "query")
    path = context.get("parameter_path")
    if carrier == "path":
        template = context.get("template_url") or request["url"]
        segments = urlsplit(template).path.split("/")
        slot = "{" + str(item.get("param") or "") + "}"
        if segments.count(slot) != 1 or context.get("baseline_value") is None:
            raise ValueError("missing_path_slot")
        path = [segments.index(slot)]
        if slot in urlsplit(request["url"]).path.split("/"):
            from urllib.parse import quote, urlunsplit
            request["url"] = urlunsplit(parsed._replace(path=parsed.path.replace(slot, quote(str(context["baseline_value"]), safe=""))))
    operation = context.get("operation") or item.get("operation") or {}
    body = request.get("json_body")
    document = body.get("query") if isinstance(body, dict) else None
    if operation.get("protocol") == "graphql" or isinstance(document, str):
        from cco_surface_core.operation import graphql_operation
        selected = graphql_operation(document, body.get("operationName") or "") if isinstance(body, dict) else {}
        if selected.get("kind") != "query" or selected.get("selection") != "selected":
            raise ValueError("graphql_readonly_operation_required")
        if operation.get("document_hash") and selected.get("document_hash") != operation["document_hash"]:
            raise ValueError("graphql_operation_context_mismatch")
        if carrier == "json" and item.get("vuln_class") not in {
                "bola", "idor", "bfla", "authentication_bypass", "field_authorization"}:
            variables = {v["name"] for v in selected.get("variables") or []}
            if not path or len(path) < 2 or path[0] != "variables" or path[1] not in variables:
                raise ValueError("graphql_observed_variable_required")
    return request, carrier, path


def build_experiment(item, context, mutation, *, control=None, capabilities=None, prerequisites=None, policy=None):
    """Derive all stages from an observed packet, retaining the P5 identity key."""
    from cco_surface_core.mutation import mutate_request, request_slot
    route = route_experiment(item, capabilities or {}, prerequisites)
    plan = {"schema": SCHEMA, "route": route, "status": "blocked", "reason": route["reason"],
            "stages": [], "binding": {k: item[k] for k in (
                "operation_id", "observation_id", "identity", "resource_owner", "resource_key",
                "resource_family", "state_key", "variant_key", "run_id", "vuln_class", "param",
                "location", "method", "access_rule_hash") if k in item}}
    if not route["runnable"]:
        return plan
    try:
        baseline, carrier, path = request_from_context(item, context)
        if not readonly_permission(baseline, policy or {}, item.get("operation_id", "")):
            raise ValueError("readonly_operation_permission_required")
        name, occurrence = item.get("param") or "", context.get("parameter_occurrence")
        value = request_slot(baseline, carrier, name, path, occurrence)
        if mutation == value and type(mutation) is type(value):
            raise ValueError("mutation_matches_baseline")
        probe = mutate_request(baseline, carrier, name, mutation, path, occurrence)
        # The unchanged baseline is a valid negative control for any input type.
        negative = copy.deepcopy(baseline) if control is None else mutate_request(
            baseline, carrier, name, control, path, occurrence)
        if negative == probe:
            raise ValueError("control_matches_mutation")
        plan.update(status="ready", reason="", stages=[
            {"role": "baseline", "request": baseline}, {"role": "mutation", "request": probe},
            {"role": "negative_control", "request": negative}, {"role": "oracle", "tool": route["tool"]}],
            carrier=carrier, parameter_path=path, parameter_occurrence=occurrence,
            baseline_value=copy.deepcopy(value), operation=copy.deepcopy(context.get("operation") or {}))
        # Complete request bytes separate content variants even if a caller omitted variant_key.
        plan["experiment_id"] = hashlib.sha256(json.dumps(
            [plan["binding"], plan["stages"], carrier, path], sort_keys=True, default=str).encode()).hexdigest()
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        plan["reason"] = str(exc) if isinstance(exc, ValueError) else "invalid_observed_request"
    return plan


def build_authz_experiment(item, context, identities, resources, *, capabilities=None, policy=None):
    """Swap the actor on one P4 matrix cell with an evidenced denial rule."""
    from authz_matrix import build_identity_matrix
    from cco_surface_core.hypotheses import digest
    route = route_experiment(item, capabilities or {}, {"access_context": True})
    plan = {"schema": SCHEMA, "status": "blocked", "reason": route["reason"], "route": route,
            "binding": {}, "stages": []}
    if not route["runnable"]:
        return plan
    rows = build_identity_matrix(identities, resources)["matrix"]
    actor = item.get("attacker_identity") or item.get("identity")
    row = next((r for r in rows if r["resource_key"] == item.get("resource_key")
                and r["identity"] == actor and r["category"] == item.get("category")
                and r["test_type"] == ALIASES.get(item.get("vuln_class"), item.get("vuln_class"))), None)
    if not row or row["status"] != "ready" or row["expectation"] != "deny":
        plan["reason"] = "explicit_denied_access_rule_required"
        return plan
    try:
        baseline, _, _ = request_from_context(item, context)
        resource = next(r for r in resources if r.get("owner_identity") == row["owner_identity"]
                        and r.get("url") == baseline["url"])
        from authz_matrix import resource_key
        if (resource_key(resource) != row["resource_key"]
                or item.get("resource_owner") != row["owner_identity"]):
            raise ValueError("authz_resource_context_mismatch")
        if not readonly_permission(baseline, policy or {}, item.get("operation_id", "")):
            raise ValueError("readonly_operation_permission_required")
        owner = identities[row["owner_identity"]]
        if not owner.get("headers") or actor != "anonymous" and not identities[actor].get("headers"):
            raise ValueError("session_unavailable")
        # The identity is the sole experimental variable. Common headers/body,
        # resource, GraphQL document, field and operation remain identical.
        credential_keys = {k.lower() for identity in identities.values() for k in identity.get("headers", {})}
        common = {k: v for k, v in baseline["headers"].items() if k.lower() not in credential_keys}
        baseline["headers"] = {**common, **copy.deepcopy(owner["headers"])}
        mutation = copy.deepcopy(baseline)
        mutation["headers"] = {**common, **copy.deepcopy(identities[actor]["headers"] if actor != "anonymous" else {})}
        plan.update(status="ready", reason="", binding={**row, "operation_id": item.get("operation_id"),
            "observation_id": item.get("observation_id"), "variant_key": item.get("variant_key"),
            "state_key": item.get("state_key")}, operation=copy.deepcopy(context.get("operation") or {}),
            stages=[{"role": "baseline", "request": baseline}, {"role": "mutation", "request": mutation},
                    {"role": "negative_control", "request": copy.deepcopy(baseline)},
                    {"role": "oracle", "tool": route["tool"]}])
        plan["experiment_id"] = digest([plan["binding"], plan["stages"]])
    except (ValueError, TypeError, KeyError, StopIteration):
        plan.update(status="blocked", reason="invalid_authz_context")
    return plan


def execute_experiment(plan, transport, oracle, verify, *, max_requests=3):
    """Injected boundaries only. Budget and invalid baseline never mean clean."""
    from .request_context import baseline_decision
    result = {"status": "blocked", "reason": plan.get("reason") or "", "requests_executed": 0,
              "stages": [], "validation_id": "", "lifecycle": tool_lifecycle(
                  **{k: plan.get("route", {}).get(k, False) for k in ("available", "applicable", "runnable")})}
    if plan.get("status") != "ready" or plan.get("schema") != SCHEMA:
        return result
    stages = plan.get("stages") or []
    if (len(stages) != 4 or [s.get("role") for s in stages] != ["baseline", "mutation", "negative_control", "oracle"]
            or any(not isinstance(s.get("request"), dict) for s in stages[:3])):
        result["reason"] = "invalid_experiment_stages"
        return result
    baseline = stages[0]["request"]
    if (any(s["request"].get("method") != baseline.get("method") for s in stages[:3])
            or any((urlsplit(s["request"].get("url") or "").scheme, urlsplit(s["request"].get("url") or "").netloc)
                   != (urlsplit(baseline.get("url") or "").scheme, urlsplit(baseline.get("url") or "").netloc)
                   for s in stages[:3]) or stages[1]["request"] == baseline):
        result["reason"] = "experiment_request_context_mismatch"
        return result
    from cco_surface_core.mutation import request_slot, mutate_request
    if plan.get("carrier"):
        try:
            baseline = stages[0]["request"]
            name = plan["binding"].get("param") or ""
            for stage in stages[1:3]:
                changed = stage["request"]
                value = request_slot(changed, plan["carrier"], name, plan.get("parameter_path"), plan.get("parameter_occurrence"))
                expected = mutate_request(baseline, plan["carrier"], name, value,
                                          plan.get("parameter_path"), plan.get("parameter_occurrence"))
                if changed != baseline and changed != expected:
                    raise ValueError("sibling_changed")
        except (ValueError, TypeError, KeyError, IndexError):
            result["reason"] = "experiment_request_context_mismatch"
            return result
    if not isinstance(max_requests, int) or isinstance(max_requests, bool) or max_requests < 3:
        result["reason"] = "budget_exhausted"
        return result
    responses = []
    for stage in plan["stages"][:3]:
        result["requests_executed"] += 1
        result["lifecycle"]["executed"] = True
        try:
            response = transport(copy.deepcopy(stage["request"]))
        except Exception:
            result.update(status="inconclusive", reason="transport_failed")
            return result
        if not isinstance(response, dict):
            result.update(status="inconclusive", reason="invalid_response")
            return result
        result["stages"].append({"role": stage["role"], "status": response.get("status")})
        responses.append(response)
        if stage["role"] in {"baseline", "negative_control"}:
            decision = baseline_decision(response, plan.get("operation") or {},
                                         allow_redirect=plan["route"]["class"] == "open_redirect")
            if not decision["eligible"]:
                result.update(status="inconclusive", reason=stage["role"] + ":" + decision["reason"])
                return result
        elif not response.get("ok") or response.get("status") == 429 or (
                response.get("status") in {401, 403} and plan["route"]["class"] not in {
                    "bola", "bfla", "field_authorization", "authentication_bypass"}):
            result.update(status="inconclusive", reason="mutation_transport_or_access_failed")
            return result
    result["lifecycle"]["executed"] = True
    try:
        receipt = oracle(copy.deepcopy(responses), copy.deepcopy(plan["binding"]))
        trusted = isinstance(receipt, dict) and receipt.get("validation_id") and verify(receipt, plan)
    except Exception:
        trusted = False
    if not trusted or receipt.get("verdict") not in {"CONFIRMED", "UNCONFIRMED"}:
        result.update(status="inconclusive", reason="unverified_oracle_evidence")
        return result
    result.update(status="confirmed" if receipt["verdict"] == "CONFIRMED" else "tested_no_violation",
                  validation_id=receipt["validation_id"], reason="")
    result["lifecycle"]["validated"] = True
    return result
