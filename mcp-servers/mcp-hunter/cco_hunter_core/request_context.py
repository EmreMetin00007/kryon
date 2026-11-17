"""Short-lived request context shared by the hunter's in-process adapters.

The public queue contains only an opaque reference. Bodies and header samples
must not be copied into summaries or artifacts. A missing/expired reference is
an explicit prerequisite failure, never permission to guess a request shape.
"""
from __future__ import annotations

import copy
import base64
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
import secrets
import threading
import time
import sys
import re
import os
import hashlib
import json
from typing import Any, Callable
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

_LOCK = threading.Lock()
_CONTEXTS: dict[str, tuple[float, dict]] = {}
_TTL_SECONDS = 300.0
_MAX_CONTEXTS = 1024
_FIELDS: ContextVar[dict] = ContextVar("hunter_request_fields", default={})
_POLICY_GATE: ContextVar = ContextVar("hunter_request_policy", default=None)
_READONLY_OPERATION: ContextVar = ContextVar("hunter_readonly_operation", default="")


class RequestPolicyGate:
    """Callable wire gate with explicit observer and accounting contracts."""

    def __init__(self, request: Callable[..., tuple[bool, str]], *,
                 observe: Callable[[dict[str, Any], dict[str, Any]], None],
                 program_policy: Callable[[], dict[str, Any]],
                 stop_reason: Callable[[], str], authorized_requests: Callable[[], int],
                 require_blind_policy: Callable[[bool], None],
                 require_session_guard: Callable[[Callable[[], bool]], None]):
        self.request = request
        self.observe = observe
        self.accounts_campaign_requests = True
        self.program_policy = program_policy
        self.stop_reason = stop_reason
        self.authorized_requests = authorized_requests
        self.require_blind_policy = require_blind_policy
        self.require_session_guard = require_session_guard

    def __call__(self, method: str, url: str, headers: dict[str, Any]) -> tuple[bool, str]:
        return self.request(method, url, headers)


@contextmanager
def readonly_operation(operation_id):
    token = _READONLY_OPERATION.set(operation_id or "")
    try:
        yield
    finally:
        _READONLY_OPERATION.reset(token)


def current_policy_gate():
    return _POLICY_GATE.get()


@contextmanager
def bind_policy_gate(gate):
    token = _POLICY_GATE.set(gate)
    try:
        yield
    finally:
        _POLICY_GATE.reset(token)


def policy_scoped(tool_name: str):
    """Inherit the parent grant; validate each request on its final context."""
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if _POLICY_GATE.get() is not None:
                return function(*args, **kwargs)
            engine = None
            stopped = ""
            authorized_requests = 0
            blind_policy = None
            session_guard = None
            wire_lock = threading.Lock()
            raw_budget = os.environ.get("CCO_CAMPAIGN_WIRE_BUDGET")
            if raw_budget is None:
                budget = None
            else:
                try:
                    budget = int(raw_budget)
                    if budget < 0:
                        raise ValueError("negative budget")
                except ValueError:
                    budget = 0

            def gate(method, url, headers):
                nonlocal engine, authorized_requests, stopped
                with wire_lock:
                    if stopped:
                        return False, stopped
                    if budget is not None and authorized_requests >= budget:
                        stopped = "run stopped: campaign request budget exhausted"
                        return False, stopped
                    try:
                        if engine is None:
                            scripts = str(Path(__file__).resolve().parents[3] / "scripts")
                            if scripts not in sys.path:
                                sys.path.insert(0, scripts)
                            from policy_engine import PolicyEngine
                            engine = PolicyEngine()
                        from .experiments import readonly_permission
                        ctype = next(
                            (str(v).split(";", 1)[0].strip().lower()
                             for k, v in (headers or {}).items() if str(k).lower() == "content-type"),
                            "",
                        )
                        req_carrier = (
                            "json" if ctype == "application/json"
                            else ("form" if ctype == "application/x-www-form-urlencoded" else "")
                        )
                        if not readonly_permission({"url": url, "method": method}, engine.program_policy,
                                                   _READONLY_OPERATION.get(), carrier=req_carrier):
                            return False, "blocked policy: hunter permits read-only methods only; exact POST declaration required"
                        result = engine.validate_wire_invocation(tool_name, {
                            "target": url, "endpoint": url, "url": url,
                            "method": method, "headers": dict(headers or {}),
                        })
                        if result.get("allowed") and session_guard is not None and not session_guard():
                            stopped = "run stopped: session unavailable, replaced or no longer verified"
                            engine._log(tool_name, "session_guard", [url], "deny", True,
                                        "blocked_session_changed", {"reason": stopped})
                            return False, stopped
                        if result.get("allowed") and blind_policy is not None:
                            rule = engine.program_policy.get("blind_discovery")
                            if (not isinstance(rule, dict) or rule.get("synthetic_accounts_only") is not True
                                    or (blind_policy and rule.get("owned_objects_private") is not True)):
                                stopped = "run stopped: policy gate blind discovery authorization changed"
                                engine._log(tool_name, "blind_discovery", [url], "deny", True,
                                            "blocked_blind_discovery_policy", {"reason": stopped})
                                return False, stopped
                        if result.get("allowed"):
                            from wire_budget import consume_request
                            permitted, budget_reason = consume_request()
                            if not permitted:
                                stopped = "run stopped: " + budget_reason
                                return False, stopped
                            authorized_requests += 1
                            return True, str(result.get("reason") or "allowed")
                        stopped = "run stopped: policy gate " + str(result.get("reason") or "blocked")
                        return False, stopped
                    except Exception as exc:
                        stopped = f"run stopped: policy gate unavailable: {type(exc).__name__}"
                        return False, stopped

            def observe(headers, response):
                nonlocal stopped
                status = response.get("status")
                credential = any(re.search(r"auth|cookie|token|session|credential|api[-_]?key",
                                           str(key), re.I) for key in (headers or {}))
                location = str(response.get("location") or "")
                for _ in range(4):
                    decoded = unquote(location)
                    if decoded == location:
                        break
                    location = decoded
                with wire_lock:
                    if stopped:
                        return
                    if status == 429:
                        stopped = "run stopped: HTTP 429"
                    elif status == 401 and credential:
                        stopped = "run stopped: authenticated session returned HTTP 401"
                    elif (credential and status in (301, 302, 303, 307, 308)
                          and re.search(r"/(login|signin|sign-in|sso|auth/login)\b", location, re.I)):
                        stopped = "run stopped: authenticated session redirected to login"
                    elif not response.get("ok"):
                        stopped = "run stopped: transport failure"

            def require_blind_policy(private_required):
                nonlocal blind_policy
                with wire_lock:
                    blind_policy = bool(private_required)
            def require_session_guard(guard):
                nonlocal session_guard
                with wire_lock:
                    session_guard = guard
            wire_gate = RequestPolicyGate(gate, observe=observe,
                program_policy=lambda: dict(engine.program_policy) if engine is not None else {},
                stop_reason=lambda: stopped, authorized_requests=lambda: authorized_requests,
                require_blind_policy=require_blind_policy, require_session_guard=require_session_guard)
            token = _POLICY_GATE.set(wire_gate)
            try:
                return function(*args, **kwargs)
            finally:
                _POLICY_GATE.reset(token)
        return wrapped
    return decorate


@contextmanager
def request_fields(values: dict | None):
    token = _FIELDS.set(copy.deepcopy(values or {}))
    try:
        yield
    finally:
        _FIELDS.reset(token)


def _unavailable(value) -> bool:
    if isinstance(value, dict):
        return any(_unavailable(item) for item in value.values())
    if isinstance(value, list):
        return any(_unavailable(item) for item in value)
    return value in ("<redacted>", "<unavailable>")


def _capture_packet(record, headers):
    memory = str(Path(__file__).resolve().parents[2] / "mcp-memory-server")
    if memory not in sys.path:
        sys.path.insert(0, memory)
    from cco_surface_core.request_store import load_capture
    return load_capture(record["capture_ref"], operation_id=record.get("operation_id"),
                        observation_id=record.get("observation_id"), headers=headers)


def capture_error(record, headers):
    if record.get("operation_id") and record.get("observation_id") is not None:
        import sqlite3
        try:
            path = Path(os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))) / "agent_memory.db"
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
                row = conn.execute("SELECT observation_id FROM surface_operation_heads WHERE operation_id=?",
                                   (record["operation_id"],)).fetchone()
            if not row or str(row[0]) != str(record["observation_id"]):
                return "request observation is missing or no longer current"
        except (sqlite3.Error, OSError):
            return "request observation cannot be verified"
    if not record.get("capture_ref"):
        return ""
    try:
        _capture_packet(record, headers)
        return ""
    except (ValueError, OSError):
        return "captured request is missing, stale or mismatched"


@contextmanager
def capture_wire_guard(record):
    """Keep the parent policy and recheck a durable capture on every wire hop."""
    if not record.get("capture_ref") and not (record.get("operation_id") and record.get("observation_id") is not None):
        yield
        return
    parent = current_policy_gate()

    def gate(method, url, headers):
        reason = capture_error(record, headers)
        if reason:
            return False, reason
        if parent is None:
            return False, "capture requires the caller's wire policy"
        return parent(method, url, headers)

    for name in ("observe", "accounts_campaign_requests", "stop_reason", "authorized_requests",
                 "require_blind_policy", "require_session_guard"):
        if parent is not None and hasattr(parent, name):
            setattr(gate, name, getattr(parent, name))
    with bind_policy_gate(gate):
        yield


def captured_request(record, sender, method, url, **kwargs):
    reason = capture_error(record, kwargs.get("headers") or {})
    if reason:
        return {"ok": False, "status": None, "blocked": "policy", "error": reason}
    with capture_wire_guard(record), readonly_operation(record.get("operation_id")):
        return sender(method, url, **kwargs)


def materialize_record(record: dict, headers: dict | None = None) -> tuple[dict, list[str]]:
    """Replace redacted samples only from the matched session's transient fields."""
    current = _FIELDS.get()
    clean = copy.deepcopy(record)
    missing = []
    if clean.get("capture_ref"):
        try:
            packet = _capture_packet(clean, headers or {})
            wire = packet["request"]
            if wire.get("body_encoding") == "base64":
                wire["body"] = base64.b64decode(wire["body"], validate=True)
            clean["url"] = wire["url"]
            clean["content_type"] = wire["content_type"]
            clean["_captured_wire"] = copy.deepcopy(wire)
            from cco_surface_core.serialization import media_type, multipart_parts, decoded_body
            def grouped(pairs):
                out: dict[str, list[Any]] = {}
                for name, value in pairs:
                    out.setdefault(name, []).append(value)
                return {name: values[0] if len(values) == 1 else values for name, values in out.items()}
            query = grouped(parse_qsl(urlsplit(wire["url"]).query, keep_blank_values=True))
            kind = media_type(wire["content_type"])
            form = (grouped(multipart_parts(wire["body"], wire["content_type"])) if kind == "multipart/form-data" else
                    {"query": wire["body"]} if kind == "application/graphql" else
                    grouped(parse_qsl(wire["body"], keep_blank_values=True)) if isinstance(wire["body"], str) else {})
            body = decoded_body(wire["body"], wire["content_type"]) if wire["body"] != "" else {}
            clean["params"] = [p for p in clean.get("params") or [] if not (
                p.get("name") == "truncated_request" and p.get("sample") == "<unavailable>" and not p.get("path"))]
            for param in clean.get("params") or []:
                location, name = param.get("in"), param.get("name")
                if location == "json":
                    value = body
                    if not param.get("body_root"):
                        for part in param.get("path") or [name]:
                            value = value[part]
                elif location == "query":
                    value = query[name]
                elif location == "body":
                    value = form[name]
                elif location == "header":
                    value = wire["headers"][name.lower()]
                else:
                    continue
                param["sample"] = copy.deepcopy(value)
                param.pop("sample_available", None)
        except (ValueError, OSError, KeyError, TypeError, IndexError, LookupError):
            return copy.deepcopy(record), ["captured request missing, stale, mismatched or unsupported"]
    for param in clean.get("params") or []:
        if not isinstance(param, dict) or (param.get("sample_available") is not False and
                                          not _unavailable(param.get("sample"))):
            continue
        name, location = str(param.get("name") or ""), str(param.get("in") or "query")
        key = f"{location}:{name}"
        found = key in current or name in current
        value = current[key] if key in current else current.get(name)
        if not found or _unavailable(value):
            missing.append(key)
        else:
            param["sample"] = copy.deepcopy(value)
            param.pop("sample_available", None)
    operation = clean.get("operation") or {}
    if operation.get("protocol") == "graphql":
        params = [p for p in clean.get("params") or [] if isinstance(p, dict)]
        paths = {tuple(p.get("path") or [p.get("name")]): p.get("sample") for p in params}
        envelope_variables: Any = next((p.get("sample") for p in params if p.get("name") == "variables"), {})
        try:
            if isinstance(envelope_variables, str):
                envelope_variables = json.loads(envelope_variables)
        except ValueError:
            envelope_variables = {}
            missing.append("json:variables")
        if not isinstance(envelope_variables, dict):
            missing.append("json:variables")
        operations_field = next((p.get("sample") for p in params if p.get("name") == "operations"), None)
        if isinstance(operations_field, str):
            from cco_surface_core.serialization import graphql_envelope
            multipart = {p["name"]: p.get("sample") for p in params if p.get("in") == "body"}
            envelope = graphql_envelope(multipart, clean.get("content_type"))
            if envelope:
                envelope_variables = envelope.get("variables", {})
            else:
                missing.append("body:operations")
        for variable in operation.get("variables") or []:
            name = variable["name"]
            prefix = ("variables", name)
            present = any(path[:2] == prefix and value is not None for path, value in paths.items())
            explicit_null = prefix in paths and paths[prefix] is None
            if isinstance(envelope_variables, dict) and envelope_variables.get(name) is not None:
                present = True
            if isinstance(envelope_variables, dict) and name in envelope_variables and envelope_variables[name] is None:
                explicit_null = True
            if variable.get("type", "").endswith("!") and not present and (
                    explicit_null or variable.get("has_default") is not True):
                reason = "json:variables." + name
                if reason not in missing:
                    missing.append(reason)
    try:
        parsed = urlsplit(str(clean.get("url") or ""))
        pairs = []
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            if _unavailable(value):
                key = f"query:{name}"
                found = key in current or name in current
                replacement = current[key] if key in current else current.get(name)
                if not found or _unavailable(replacement):
                    if key not in missing:
                        missing.append(key)
                else:
                    value = str(replacement)
            pairs.append((name, value))
        clean["url"] = urlunsplit(parsed._replace(query=urlencode(pairs, doseq=True)))
    except ValueError:
        missing.append("invalid request URL")
    return clean, missing


def store_context(context: dict) -> str:
    now = time.monotonic()
    with _LOCK:
        for key in [key for key, (expires, _) in _CONTEXTS.items() if expires <= now]:
            del _CONTEXTS[key]
        while len(_CONTEXTS) >= _MAX_CONTEXTS:
            del _CONTEXTS[next(iter(_CONTEXTS))]
        ref = secrets.token_urlsafe(24)
        _CONTEXTS[ref] = (now + _TTL_SECONDS, copy.deepcopy(context))
        return ref


def load_context(ref: str) -> dict | None:
    now = time.monotonic()
    with _LOCK:
        stored = _CONTEXTS.get(str(ref or ""))
        if not stored:
            return None
        if stored[0] <= now:
            del _CONTEXTS[str(ref)]
            return None
        return copy.deepcopy(stored[1])


def request_binding(headers: dict) -> dict:
    """Opaque session/tenant binding plus the existing scope and policy revisions."""
    validator_path = str(Path(__file__).resolve().parents[2] / "mcp-validator")
    if validator_path not in sys.path:
        sys.path.insert(0, validator_path)
    from cco_validator_core.evidence import current_policy_hash, current_scope_revision
    canonical = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    return {"session_sha256": hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest(),
            "scope_revision": current_scope_revision(), "policy_hash": current_policy_hash()}


def capture_state(identities: dict) -> dict:
    """Host-private synthetic observations. Never serialize this as a tool report."""
    return {name: {"identity_ref": secrets.token_urlsafe(24),
                   "request_binding": request_binding(actor.get("headers", {})),
                   "role": actor.get("role"), "owned_objects_private": actor.get("owned_objects_private"),
                   "observed_at": actor.get("_discovery_observed_at", time.time()),
                   **{key: copy.deepcopy(actor[key]) for key in ("objects", "resources", "identity_facts") if key in actor}}
             for name, actor in identities.items() if isinstance(actor, dict) and actor.get("test_data_only") is True}


_PUBLIC_ATOM = re.compile(r"(?:[0-9a-f]{64}|opaque:[0-9a-f]{64})\Z")
# These are semantic types, not samples taken from a target or a fixture.
_PUBLIC_TYPES = {
    "vuln_type": {"SQL Injection", "SSTI", "IDOR", "BOLA", "Auth Bypass", "Open Redirect"},
    "oracle": {"differential_boolean", "arithmetic_eval", "authz_oracle", "oob_oracle"},
    "method": {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
    "carrier": {"query", "path", "body", "form", "json", "header", "cookie"},
    "role": {"member", "admin", "anonymous", "user", "guest", "owner"},
    "source": {"response_metadata", "identity_discovery", "capture", "observed", "declared"},
    "confidence": {"observed", "declared", "verified", "inferred", "unknown"},
    "state_key": {"observed", "declared", "unknown"},
    "vuln_class": {"sqli", "sql_injection", "ssti", "path_traversal", "lfi", "xss_reflected",
                   "open_redirect", "command_injection", "xxe", "deserialization", "opaque_token",
                   "idor", "bola", "bfla", "authentication_bypass", "ssrf", "csrf",
                   "broken_access_control"},
    "param": {"id", "user", "user_id", "object", "object_id", "account", "account_id", "contact",
              "email", "query", "q", "search", "page", "limit", "offset", "sort", "filter",
              "name", "file", "path", "url", "redirect", "next", "return", "template"},
    "candidate_source": {"light_oracle", "bounded_sampling", "surface_applicability", "identity_discovery",
                         "observed", "declared"},
    "candidate_reason": {"observed_signal", "valid_baseline_without_light_signal", "readonly_traversal_validator",
                         "readonly_ssti_validator", "readonly_boolean_validator", "observed_access_surface"},
}
_PUBLIC_PATH_WORDS = {"api", "v1", "v2", "v3", "users", "user", "objects", "object", "accounts",
                      "account", "resources", "resource", "profile", "me", "self", "search",
                      "files", "file", "orders", "order", "invoices", "invoice", "items", "item"}
_PRIVATE_EXPORT_KEYS = {"identity_facts", "headers", "cookie", "cookies", "authorization", "marker",
                        "owner_marker", "request_fields", "request_field_values", "request_context_ref",
                        "request_ref", "request_samples", "baseline_json", "baseline_body", "baseline_form",
                        "secret_ref", "private_reference", "producer_reference", "execution_reference",
                        "result_path", "source_references", "operational_report", "states",
                        "signed_completion", "signed_completions"}
_VALUE_FIELDS = {"param", "carrier", "location", "role", "owner_role", "attacker_role", "operation_id",
                 "observation_id", "candidate_source", "candidate_reason", "resource_key", "resource_family",
                 "family", "state_key", "variant_key", "source", "confidence", "source_spec_id",
                 "source_artifact", "provenance", "ownership_evidence", "resource_id", "tenant",
                 "principal", "contact", "email", "value", "fingerprint", "run_id"}
_PUBLIC_FIELDS = set("""ok engine target mode plan allow_deepen ascan steps discover discovery_operations crawl zap fuzz
validations validation_candidates validation_queue budgets validation_limit validations_used confirmed surface_probes
tool_states skipped exploits errors next identity_matrix identity_discovery identity_discovery_state replan feedback_queue
requests_authorized stopped artifact artifact_error url url_sha256 baseline_url target_url method vuln_class param carrier location
identity resource_owner owner_identity attacker_identity run_id fingerprint operation_id observation_id candidate_source
candidate_reason access_rule_hash resource_key resource_family family state_key variant_key sources source confidence
source_spec_id source_artifact source_sha256 scope_revision policy_hash provenance ownership_evidence identity_ref
request_binding session_sha256 role owned_objects_private observed_at objects resources step tool optional skip_if classes
authz_classes authz_note oob_classes oob_note surface_hooks passive_adapters skip if available adapter reason reason_code
preconditions status requests reasons budget_limited truncated_responses owned_objects_observed eligible_candidates
differential_candidates complete_coverage feedback_reason tool_lifecycle executed validated coverage_recorded verdict validation_id hook
access_dimensions live status_code baseline_eligible triage_verdict coverage_status candidate_sampling likely_hits
validator_queue probes executed_live requests_sent marked_tested fanout truncated stop_reason ingested runnable applicable
disabled_surface_hooks candidates tests family_id resource_id tenant principal contact email value count total limit
offset bytes sha256 path content_ref eof next_offset text schema spec_id tool arguments result output execution_failed
items fields omitted summary_feedback candidate_cards candidate_count coverage_gaps coverage_gap coverage_gap_count source_ref
context_archive_ref recent_results task_spec session_bindings bindings owners pairs comparisons dimensions identities
matrix expectations observations outcomes authz_matrix permission expected_access actor owner source identity_names
attacker_role owner_role validation_outcomes reportable success transport_ok operation protocol action effect control
tool_budget http_budget request_budget requests_used elapsed_seconds discovery_requests replayed reused state_names
task_spec_id origin actual_request_cost error summary findings evidence validated_findings notes evidence_accepted
vuln_type oracle schema_version artifact content_sha256 execution_context request_evidence guard differential
transport_ok response_sha256 response_length request_url elapsed_ms persisted binding records route
actions category categories next_action automatic_retry note hypothesis_fingerprint bound_refs page_count xhr_count
selected confirm_now waf_blocked surface_queued schema_repair_queue revisit_candidates review_coverage validate_with
expectation test_type missing_coverage blocked_identities authz_candidate
""".split())
_PUBLIC_DECISIONS = {"ready", "blocked", "planned", "incomplete", "unknown", "fresh", "stale", "expired",
                     "LIVE", "PLAN", "CONFIRMED", "UNCONFIRMED", "INCONCLUSIVE", "NOT TESTED", "TESTED",
                     "observed", "declared", "anonymous", "anon", "unspecified", "passive_inventory",
                     "discover", "crawl", "fuzz", "validate", "exploit", "identity_discovery", "remaining",
                     "query", "path", "body", "json", "form", "header", "cookie", "authz_oracle", "oob_oracle"}
_LOOP_STEPS = {
    "identity_discovery", "discover", "crawl", "zap", "fuzz", "validate", "exploit",
    "validate_coverage_gap", "coverage_gap", "jwt_kid_jku", "session", "remaining",
    "advanced_surface_hooks", "websocket", "grpc", "smuggling", "cache", "graphql_suggestion",
}
_COVERAGE_GAP_STATUSES = {"not_tested", "confirmed", "tested_clean", "inconclusive"}
_REPLAN_STATUSES = {"invalid", "planned", "blocked", "incomplete", "review_coverage"}
_REPLAN_CATEGORIES = {
    "rate_limit", "session", "policy", "schema", "transport", "budget", "identity", "surface", "unavailable",
}
_REPLAN_ACTIONS = {
    "wait_and_reassess", "restore_test_session", "review_scope_and_grant", "repair_request_context",
    "inspect_transport", "review_budget", "bind_declared_test_resource", "review_probe_controls",
    "inspect_tool_state",
}
_REPLAN_REASONS = {
    "429/rate-limit threshold stopped live probing",
    "401 or login redirect interrupted the authenticated session",
    "policy/WAF block interrupted probing",
    "400/422 or response schema failure prevented clean baseline comparison",
    "transport/network failure interrupted probing",
    "request or validation budget capped execution",
    "declared test identity or owned object prerequisite missing",
    "surface discovery or probe execution left gaps",
    "tool adapter unavailable or error state recorded",
}
_REPLAN_NOTE = "A run is not fully covered merely because no finding was confirmed."
_FEEDBACK_STATUSES = {"confirmed", "tested_no_violation", "proposed", "ready", "blocked", "inconclusive"}
_FEEDBACK_REASON_CODES = {
    "budget_exhausted", "rate_limited", "session_unavailable", "missing_access_context",
    "invalid_request_context", "policy_blocked", "transport_unavailable", "waf_blocked",
    "validator_inconclusive", "probe_without_candidate", "candidate_proposed", "candidate_ready",
    "verified_validator_evidence", "evidence_unavailable", "access_context_bound",
}
_FEEDBACK_NEXT_ACTIONS = {
    "review_budget", "wait_and_reassess", "restore_test_session", "bind_declared_test_resource",
    "repair_request_context", "review_scope_and_grant", "inspect_transport", "review_probe_controls",
    "schedule_bounded_validation", "bind_request_context", "validate_with_fresh_budget", "none",
}
_FANOUT_NEXT_ACTIONS = _FEEDBACK_NEXT_ACTIONS | {
    "stop", "session_recovery", "backoff", "schema_repair", "baseline_repair", "probe",
}
_PRECONDITIONS = {
    "authorized_test_identity", "protected_test_resource", "authentication_required", "protected_marker",
    "distinct_test_identities", "distinct_roles", "function_test_resource", "denied_role_rule",
    "owned_test_object", "owner_marker", "fresh_scope_and_grant", "request_context", "campaign_budget",
}
_TRIAGE_VERDICTS = {
    "LIKELY", "UNLIKELY", "INCONCLUSIVE", "SKIPPED", "DEFERRED", "WAF_BLOCKED", "ERROR", "CLEAN", "NOT_TESTED",
}
_FANOUT_COVERAGE_STATUSES = {"not_tested", "blocked", "inconclusive", "tested", "tested_clean", "confirmed"}
_FANOUT_REASONS = {
    "probe outside the requested target origin", "declared application file context changed",
    "baseline transport failed", "baseline rate limited", "session unavailable or login redirect",
    "probe rate limited", "probe transport failed", "request budget cannot fit baseline and probe",
    "baseline_transport_failed", "baseline_session_unavailable", "baseline_rate_limited",
    "baseline_schema_repair_required", "baseline_graphql_invalid_response", "baseline_graphql_errors",
    "baseline_graphql_missing_data", "baseline_application_error", "baseline_http_error",
}
_NON_GET_DEFERRED_RE = re.compile(
    r"read-only hunter gate: non-GET canary deferred \((?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\)"
)
_SKIPPED_REASONS = {
    "ZAP request-level policy unavailable",
    "run advanced probes separately with their own scope and grant",
    "unverified targeted validation",
    "oob auto: needs oob_validate (CCO_OOB_DOMAIN)",
    "crawl: no crawl_fn",
    "yuzey kuyrugu bos (0 probe) — discover/crawl kaydi yok veya hedef anahtari uyumsuz",
    "declared application file context changed",
    "request context missing, expired or mismatched",
    "session unavailable or not recently verified",
    "explicit private synthetic objects required",
    "campaign request budget exhausted",
    "session unavailable for planned identity",
    "session unavailable or ownership context mismatched",
    "blocked policy: synthetic ownership authorization required",
    "request context cannot contain raw identity headers",
    "attempt limit exhausted",
    "verified session block record unavailable",
    "active campaign required",
    "coverage dimension already complete",
    "task dependency unavailable",
    "session changed during admission",
    "new session verification required for each bound account",
    "declared test resource unavailable or changed",
    "candidate binding limit exceeded",
    "observed access candidate unavailable",
    "request context unavailable",
    "second identity unavailable",
}
_SKIP_IF_REASONS = {
    "crawl=False or playwright missing",
    "request-level policy integration unavailable",
    "Playwright or Chromium unavailable",
}
_VALIDATOR_HOOKS = {
    "validate_sqli", "validate_ssti", "validate_open_redirect", "validate_path_traversal",
    "validate_xss_reflection", "validate_command_injection", "validate_xxe", "validate_deserialization",
    "validate_token_differential", "authz_oracle", "oob_oracle",
}
_VALIDATOR_VERDICTS = {"CONFIRMED", "UNCONFIRMED", "INCONCLUSIVE", "SKIPPED"}
_PUBLIC_DIAGNOSTICS = {
    "max_validations", "no validator", "not auto-validated", "active_adapter_deferred", "missing_access_context",
    "candidate outside target origin", "authz auto: only GET", "authz auto: no authz validator",
    "authz auto: needs 1 identities", "authz auto: needs 2 identities", "signed coverage plan unavailable",
    "identity-only slice has its own observed discovery", "identity discovery blocked", "identity discovery unavailable",
    "identity discovery unavailable", "owned object discovery incomplete", "identity discovery blocked",
    "authz test identities or declared test resource prerequisites missing", "request budget exhausted",
    "tool budget exhausted", "time budget exhausted", "token budget exhausted", "feedback persistence unavailable",
    "session_not_recently_verified", "active_adapter_deferred", "observed_flow_required", "jwt_validator_failed",
    "invalid_session_bindings_json", "invalid_session_binding_count", "invalid_session_binding",
    "mixed_session_material", "session_target_outside_scope", "session_origin_mismatch",
    "session_guard_unavailable", "invalid_session_role", "invalid_session_material",
    "ambiguous_session_material", "session_reference_unavailable",
    "policy gate denied", "policy gate unavailable", "session unavailable",
}
_DECISION_FIELDS = {"status", "verdict", "mode", "step", "steps", "sources", "hook", "coverage_status",
                    "triage_verdict", "feedback_reason", "state_key", "carrier", "location", "identity_ref"}
_DIAGNOSTIC_FIELDS = {"reason", "reasons", "reason_code", "error", "errors", "feedback_reason", "stopped", "stop_reason"}
_NUMERIC_FIELDS = {"observed_at", "requests", "requests_sent", "requests_authorized", "requests_used",
                   "actual_request_cost", "probes", "status_code", "count", "total", "limit", "offset", "bytes",
                   "validation_limit", "validations_used", "owned_objects_observed", "eligible_candidates",
                    "differential_candidates", "elapsed_seconds", "candidate_count", "coverage_gap_count",
                    "response_length", "elapsed_ms"}
_DIGEST_FIELDS = {"sha256", "url_sha256", "source_sha256", "scope_revision", "policy_hash", "session_sha256",
                    "access_rule_hash", "fingerprint", "hypothesis_fingerprint", "bound_refs",
                    "content_sha256", "response_sha256"}
_PUBLIC_SERIALIZED_BYTES = 16 * 1024 * 1024
_PUBLIC_PROJECTION_DEPTH = 64


def _typed_public_scalar(value: Any, field: str, container: tuple[str, ...]) -> tuple[bool, Any]:
    """Allow fixed operational enums and bounded ints only in their typed field/subtree."""
    parent = container[-1] if container else ""
    grandparent = container[-2] if len(container) >= 2 else ""
    if type(value) is int:
        if parent == "fanout" and field == "status" and 100 <= value <= 599:
            return True, value
        if (parent in {"crawl", "discover", "fuzz", "candidate_sampling"}
                and field in {"page_count", "xhr_count", "ingested", "selected", "executed",
                              "executed_live", "marked_tested",
                              "surface_queued", "waf_blocked", "likely_hits"}
                and value >= 0):
            return True, value
        if parent == "identity_discovery" and field in {"identities", "truncated_responses"} and value >= 0:
            return True, value
        if parent == "identity_matrix" and field in {"count", "total"} and value >= 0:
            return True, value
        return False, None
    if not isinstance(value, str):
        return False, None
    if parent == "coverage_gap" and field == "status" and value in _COVERAGE_GAP_STATUSES:
        return True, value
    if parent == "replan" and field == "status" and value in _REPLAN_STATUSES:
        return True, value
    if parent == "replan" and field == "note" and value == _REPLAN_NOTE:
        return True, value
    if parent == "categories" and grandparent == "replan" and field == "categories" and value in _REPLAN_CATEGORIES:
        return True, value
    if parent == "actions" and grandparent == "replan":
        if field == "category" and value in _REPLAN_CATEGORIES:
            return True, value
        if field == "action" and value in _REPLAN_ACTIONS:
            return True, value
        if field == "reason" and value in _REPLAN_REASONS:
            return True, value
    if parent == "feedback_queue":
        if field == "status" and value in _FEEDBACK_STATUSES:
            return True, value
        if field == "reason_code" and value in (_FEEDBACK_REASON_CODES | _PUBLIC_DIAGNOSTICS):
            return True, value
        if field == "next_action" and value in _FEEDBACK_NEXT_ACTIONS:
            return True, value
    if parent == "preconditions" and grandparent in {"feedback_queue", "skipped"} and value in _PRECONDITIONS:
        return True, value
    if parent == "fanout":
        if field == "triage_verdict" and value in _TRIAGE_VERDICTS:
            return True, value
        if field == "coverage_status" and value in _FANOUT_COVERAGE_STATUSES:
            return True, value
        if field == "next_action" and value in _FANOUT_NEXT_ACTIONS:
            return True, value
        if field == "reason" and (
                value in (_PUBLIC_DIAGNOSTICS | _FANOUT_REASONS) or _NON_GET_DEFERRED_RE.fullmatch(value)):
            return True, value
    if parent == "skipped":
        if field == "reason_code" and value in (_FEEDBACK_REASON_CODES | _PUBLIC_DIAGNOSTICS):
            return True, value
        if field == "reason" and (
                value in (_PUBLIC_DIAGNOSTICS | _SKIPPED_REASONS) or re.fullmatch(r"blocked_[a-z_]+", value)):
            return True, value
    if field in {"steps", "step"} and parent in {"steps", "plan", "skipped"} and value in _LOOP_STEPS:
        return True, value
    if field == "disabled_surface_hooks" and parent == "disabled_surface_hooks" and grandparent in {"", "plan"} and value in _LOOP_STEPS:
        return True, value
    if parent == "plan" and field == "skip_if" and value in _SKIP_IF_REASONS:
        return True, value
    if parent in {"classes", "authz_classes", "oob_classes", "skip"} and grandparent == "plan" and value in _PUBLIC_TYPES["vuln_class"]:
        return True, value
    if parent in {"validations", "confirmed"}:
        if field == "hook" and value in _VALIDATOR_HOOKS:
            return True, value
        if field == "verdict" and value in _VALIDATOR_VERDICTS:
            return True, value
    if parent == "surface_probes" and field == "hook" and value in _LOOP_STEPS:
        return True, value
    if parent in {"crawl", "discover"} and field in {"reason", "stop_reason"} and value in _PUBLIC_DIAGNOSTICS:
        return True, value
    return False, None


def public_value_ref(value) -> str:
    """Non-reversible, idempotent value reference; never an executable private ref."""
    if isinstance(value, str) and value.startswith("opaque:") and _PUBLIC_ATOM.fullmatch(value):
        return value
    return "opaque:" + hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                                default=str).encode()).hexdigest()


def public_discovery_url(value) -> str:
    """Allowlisted route shape only. Every other path atom and query value is a template."""
    try:
        parsed = urlsplit(value)
        if parsed.username is not None or parsed.password is not None:
            return public_value_ref(value)
        if parsed.scheme not in {"http", "https", ""}:
            return public_value_ref(value)
        path = "/".join(part if part in _PUBLIC_PATH_WORDS or not part or part == "{value}"
                        else "{value}" for part in parsed.path.split("/"))
        query = urlencode([(name if name in _PUBLIC_TYPES["param"] else public_value_ref(name), "<redacted>")
                           for name, _ in parse_qsl(parsed.query, keep_blank_values=True)])
        # DNS labels are not identity/resource values; credentials/fragments never survive.
        return urlunsplit(parsed._replace(path=path, query=query, fragment=""))
    except (TypeError, ValueError):
        return public_value_ref(value)


def _public_metadata(value, field=""):
    if isinstance(value, dict):
        return {key if key in _PUBLIC_FIELDS else public_value_ref(key): _public_metadata(item, key)
                for key, item in value.items()
                if key not in _PRIVATE_EXPORT_KEYS}
    if isinstance(value, list):
        return [_public_metadata(item, field) for item in value]
    if value is None or isinstance(value, bool) or field == "observed_at" and type(value) in {int, float}:
        return value
    if not isinstance(value, str):
        return public_value_ref(value)
    if not value:
        return value
    if _PUBLIC_ATOM.fullmatch(value) and (value.startswith("opaque:") or field in _DIGEST_FIELDS):
        return value
    if field == "run_id" and re.fullmatch(r"run-[0-9a-f]{8,64}", value):
        return value
    if field in {"url", "target", "baseline_url"} or value.startswith(("http://", "https://")):
        return public_discovery_url(value)
    semantic = {"location": "carrier", "owner_role": "role", "attacker_role": "role"}.get(field, field)
    if value in _PUBLIC_TYPES.get(semantic, set()):
        return value
    if field in {"family", "resource_family"} and value.startswith("/"):
        return public_discovery_url(value)
    return public_value_ref(value)


def public_validator_report(value: Any) -> Any:
    """Value-safe validator view, never a replacement for canonical signed evidence.

    Verdicts, IDs, digests and request semantics survive. Marker arrays, excerpts,
    principals and operational URL values cannot become public by omitting a
    discovery envelope. This projection carries no signature/host authority.
    """
    return public_discovery_report(value, strict=True)


def public_discovery_report(value: Any, field: str = "", *, strict: bool = False,
                            _depth: int = 0, _container: tuple[str, ...] = ()) -> Any:
    """Project every public report branch, not merely cards or credential-named keys.

    Operational routes and arbitrary metadata are retained separately by the host.
    Fixed decisions/counts and public session/validator references remain useful;
    resource/provenance values cannot gain public authority from an allowed key.
    """
    if _depth >= _PUBLIC_PROJECTION_DEPTH:
        # Do not serialize an arbitrarily deep/cyclic object to make this ref.
        return public_value_ref("public projection depth limit")
    if isinstance(value, dict):
        if not strict and ("validation_id" in value or "verdict" in value and (
                {"vuln_type", "oracle", "request_evidence", "differential"} & value.keys())):
            strict = True
        strict = strict or bool({"identity_discovery_state", "discovery_operations", "validation_candidates",
                                 "validation_queue"} & value.keys())
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key in _PRIVATE_EXPORT_KEYS:
                continue
            public_key = key if not strict or key in _PUBLIC_FIELDS or _PUBLIC_ATOM.fullmatch(str(key)) else public_value_ref(key)
            child_container = (*_container, str(key)) if isinstance(item, (dict, list)) else _container
            if key == "identity_discovery_state" and isinstance(item, dict):
                result[public_key] = public_discovery_state(item)
            elif strict and key in _VALUE_FIELDS:
                result[public_key] = _public_metadata(item, key)
            elif strict and isinstance(item, str) and (key in {"url", "target", "baseline_url"}
                                           or item.startswith(("http://", "https://"))):
                result[public_key] = public_discovery_url(item)
                if "url_sha256" not in value and "url_sha256" not in result:
                    sha_source = next(
                        (value[k] for k in ("url", "target", "baseline_url", "target_url")
                         if isinstance(value.get(k), str)),
                        next(
                            (v for _, v in sorted(value.items())
                             if isinstance(v, str) and v.startswith(("http://", "https://"))),
                            item,
                        ),
                    )
                    result["url_sha256"] = hashlib.sha256(sha_source.encode()).hexdigest()
            else:
                result[public_key] = public_discovery_report(item, key, strict=strict or (
                    key == "arguments" and (value.get("tool") == "hunter_run_web_loop"
                        or str(value.get("tool", "")).startswith("validator_validate_"))),
                    _depth=_depth + 1, _container=child_container)
        return result
    if isinstance(value, list):
        return [public_discovery_report(item, field, strict=strict, _depth=_depth + 1,
                                        _container=_container) for item in value]
    if strict and isinstance(value, str) and value.startswith(("http://", "https://")):
        return public_discovery_url(value)
    if isinstance(value, str) and value:
        # JSON permits four leading whitespace characters and string-wrapped
        # reports. Recognize those at every nesting level, not just envelopes.
        # Oversize/decoder-depth failures cannot fall back to public raw text.
        if value.lstrip(" \t\r\n").startswith(("{", "[", '"')):
            if (len(value) > _PUBLIC_SERIALIZED_BYTES
                    or len(value.encode("utf-8")) > _PUBLIC_SERIALIZED_BYTES):
                return public_value_ref(value)
            try:
                decoded = json.loads(value)
                next_container = (*_container, field) if field and isinstance(decoded, (dict, list)) else _container
                safe = public_discovery_report(decoded, field, strict=strict, _depth=_depth + 1,
                                               _container=next_container)
                if strict or safe != decoded:
                    return json.dumps(safe, sort_keys=True)
            except RecursionError:
                return public_value_ref(value)
            except (ValueError, TypeError):
                pass
        if not strict:
            return value
        if _PUBLIC_ATOM.fullmatch(value) and (value.startswith("opaque:") or field in _DIGEST_FIELDS):
            return value
        if field in _DIAGNOSTIC_FIELDS:
            # Preserve host decision semantics, never the dynamic policy/error
            # suffix (which may include an operational URL or private value).
            for prefix, decision in (
                ("run stopped: policy gate unavailable:", "policy gate unavailable"),
                ("run stopped: policy gate ", "policy gate denied"),
                ("run stopped: session unavailable,", "session unavailable"),
            ):
                if value.startswith(prefix):
                    return decision
        allowed_typed, typed_value = _typed_public_scalar(value, field, _container)
        if allowed_typed:
            return typed_value
        if (field in _DECISION_FIELDS and value in _PUBLIC_DECISIONS
                or field in _DIAGNOSTIC_FIELDS and value in _PUBLIC_DIAGNOSTICS
                or value in _PUBLIC_TYPES.get(field, set())):
            return value
        # Public identity labels are host-registered session *references*, not
        # principal/contact facts. They retain the existing vault-lookup ABI.
        if field in {"identity", "resource_owner", "owner_identity", "attacker_identity"} and re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_-]{0,31}", value):
            return value
        if field == "run_id" and (value == "unspecified" or re.fullmatch(r"run-[0-9a-f]{8,64}", value)):
            return value
        if field == "validation_id" and re.fullmatch(r"[0-9a-f]{32}", value):
            return value
        if field == "path" and re.fullmatch(
                r"context-archive/(?:tool-result|index|coverage-gaps|invalid-summary|provider-context|validator|handoff|branch-handoff|[0-9a-f]{16}|[0-9a-f]{64})-[0-9a-f]{64}\.json",
                value):
            return value
        return public_value_ref(value)
    if strict and type(value) in {int, float}:
        allowed_typed, typed_value = _typed_public_scalar(value, field, _container)
        if allowed_typed:
            return typed_value
        if field not in _NUMERIC_FIELDS:
            return public_value_ref(value)
    if strict and value is not None and not isinstance(value, (str, bool, int, float)):
        return public_value_ref(value)
    return value


def public_discovery_state(states: dict) -> dict:
    """Semantic cards only: no principals, contact/object markers or request samples.

    This is deliberately an allowlist, not key-name credential redaction. The
    operational objects/facts remain in the independently signed private state.
    """
    fields = ("identity_ref", "request_binding", "role", "owned_objects_private", "observed_at")
    resource_fields = ("url", "method", "param", "carrier", "operation_id", "observation_id",
                       "candidate_source", "candidate_reason", "resource_key", "resource_family",
                       "family", "state_key", "variant_key")

    def provenance(value):
        if isinstance(value, list):
            return [provenance(item) for item in value if isinstance(item, dict)]
        if not isinstance(value, dict):
            return {}
        allowed = ("source", "confidence", "source_spec_id", "source_artifact", "source_sha256",
                   "operation_id", "observation_id", "scope_revision", "policy_hash")
        return {key: _public_metadata(value[key], key) for key in allowed
                if key in value and isinstance(value[key], (str, int))}

    result = {}
    for name, state in states.items():
        if not isinstance(state, dict):
            continue
        card = {key: _public_metadata(state[key], key) for key in fields if key in state}
        if isinstance(card.get("request_binding"), dict):
            card["request_binding"] = {key: value for key, value in card["request_binding"].items()
                                       if key in ("session_sha256", "scope_revision", "policy_hash")}
        for key in ("objects", "resources"):
            if key in state:
                card[key] = []
                for item in state[key] if isinstance(state[key], list) else []:
                    if not isinstance(item, dict):
                        continue
                    resource = {field: _public_metadata(item[field], field) for field in resource_fields
                                 if field in item and isinstance(item[field], (str, int))}
                    for field in ("provenance", "ownership_evidence"):
                        if field in item:
                            resource[field] = provenance(item[field])
                    card[key].append(resource)
        result[name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", str(name)) else public_value_ref(name)] = card
    return result


def baseline_error(response: dict, operation: dict) -> str:
    """A 2xx transport response can still be an application-level failure."""
    status = response.get("status")
    if status in {400, 422}:
        return "baseline_schema_repair_required"
    try:
        payload = json.loads(response.get("text") or "")
    except (TypeError, ValueError):
        return "baseline_graphql_invalid_response" if operation.get("protocol") == "graphql" else ""
    if operation.get("protocol") == "graphql":
        if isinstance(payload, list):
            if not payload:
                return "baseline_graphql_invalid_response"
            for child in payload:
                reason = baseline_error({"text": json.dumps(child)}, operation)
                if reason:
                    return reason
            return ""
        if not isinstance(payload, dict) or payload.get("errors"):
            return "baseline_graphql_errors"
        if "errors" in payload and not isinstance(payload["errors"], list):
            return "baseline_graphql_invalid_response"
        if "data" not in payload or payload["data"] is None:
            return "baseline_graphql_missing_data"
    if isinstance(payload, dict) and (payload.get("success") is False or payload.get("status") is False or
                                     payload.get("error")):
        return "baseline_application_error"
    return ""


def baseline_decision(response: dict, operation: dict, *, allow_redirect=False) -> dict:
    """Classify one observed response; repair is a plan and sends no traffic."""
    status = response.get("status")
    if not response.get("ok"):
        return {"eligible": False, "reason": "baseline_transport_failed", "next_action": "stop"}
    if status == 401:
        return {"eligible": False, "reason": "baseline_session_unavailable", "next_action": "session_recovery"}
    if status == 429:
        return {"eligible": False, "reason": "baseline_rate_limited", "next_action": "backoff"}
    reason = baseline_error(response, operation)
    if reason:
        return {"eligible": False, "reason": reason, "next_action": (
            "schema_repair" if reason == "baseline_schema_repair_required" else "baseline_repair")}
    eligible = (isinstance(status, int) and not isinstance(status, bool) and
                (200 <= status < 300 or allow_redirect and status in {301, 302, 303, 307, 308}))
    return {"eligible": eligible, "reason": "" if eligible else "baseline_http_error",
            "next_action": "probe" if eligible else "baseline_repair"}
