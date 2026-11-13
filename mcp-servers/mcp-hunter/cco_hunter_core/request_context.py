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
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

_LOCK = threading.Lock()
_CONTEXTS: dict[str, tuple[float, dict]] = {}
_TTL_SECONDS = 300.0
_MAX_CONTEXTS = 1024
_FIELDS: ContextVar[dict] = ContextVar("hunter_request_fields", default={})
_POLICY_GATE: ContextVar = ContextVar("hunter_request_policy", default=None)
_READONLY_OPERATION: ContextVar = ContextVar("hunter_readonly_operation", default="")


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
                        if not readonly_permission({"url": url, "method": method}, engine.program_policy,
                                                   _READONLY_OPERATION.get()):
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

            gate.observe = observe
            gate.accounts_campaign_requests = True
            gate.program_policy = lambda: dict(engine.program_policy) if engine is not None else {}
            gate.stop_reason = lambda: stopped
            gate.authorized_requests = lambda: authorized_requests
            def require_blind_policy(private_required):
                nonlocal blind_policy
                with wire_lock:
                    blind_policy = bool(private_required)
            gate.require_blind_policy = require_blind_policy
            def require_session_guard(guard):
                nonlocal session_guard
                with wire_lock:
                    session_guard = guard
            gate.require_session_guard = require_session_guard
            token = _POLICY_GATE.set(gate)
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
                out = {}
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
        envelope_variables = next((p.get("sample") for p in params if p.get("name") == "variables"), {})
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
