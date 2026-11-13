"""Redacted OpenTelemetry trace summaries for grey-box testing.

The adapter accepts OTLP/JSON-like payloads and emits service, route,
database-operation and exception summaries. Raw trace IDs, SQL text, HTTP
targets, headers, messages and attribute values outside a small allowlist
are never copied into the output.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any
from urllib.parse import urlparse

SCHEMA = "cco-greybox-telemetry/1"

ALLOWED_STRING_ATTRS = {
    "http.request.method", "http.method", "http.route",
    "db.system", "db.operation", "rpc.system", "rpc.service", "rpc.method",
    "messaging.system", "exception.type", "error.type",
}
ALLOWED_NUMBER_ATTRS = {"http.status_code", "http.response.status_code"}


def _hash_id(value: Any) -> str:
    text = str(value or "")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12] if text else ""


def _attr_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in value:
            raw = value[key]
            if key == "intValue":
                try:
                    return int(raw)
                except Exception:
                    return raw
            return raw
    return None


def _attrs(items: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, dict) and item.get("key"):
            out[str(item["key"])] = _attr_value(item.get("value"))
    return out


def _service_name(resource: Any) -> str:
    if not isinstance(resource, dict):
        return "unknown"
    attrs = _attrs(resource.get("attributes"))
    return str(attrs.get("service.name") or "unknown")[:120]


def _iter_spans(payload: Any) -> list[tuple[str, dict[str, Any]]]:
    spans: list[tuple[str, dict[str, Any]]] = []
    if isinstance(payload, list):
        return [("unknown", s) for s in payload if isinstance(s, dict)]
    if not isinstance(payload, dict):
        raise ValueError("payload must be an OTLP object or span list")
    if isinstance(payload.get("spans"), list):
        return [("unknown", s) for s in payload["spans"] if isinstance(s, dict)]
    resource_spans = payload.get("resourceSpans")
    if not isinstance(resource_spans, list):
        raise ValueError("resourceSpans must be a list")
    for resource_span in resource_spans:
        if not isinstance(resource_span, dict):
            continue
        service = _service_name(resource_span.get("resource"))
        scope_spans = resource_span.get("scopeSpans") or resource_span.get("instrumentationLibrarySpans") or []
        if not isinstance(scope_spans, list):
            continue
        for scope in scope_spans:
            if not isinstance(scope, dict):
                continue
            for span in scope.get("spans") or []:
                if isinstance(span, dict):
                    spans.append((service, span))
    return spans


def _route(attrs: dict[str, Any]) -> str:
    route = str(attrs.get("http.route") or "")
    if route:
        return route[:200]
    target = str(attrs.get("http.target") or attrs.get("url.path") or "")
    if target:
        return (urlparse(target).path or target.split("?", 1)[0])[:200]
    return ""


def _duration_ms(span: dict[str, Any]) -> float:
    try:
        return max(0.0, (int(span.get("endTimeUnixNano")) - int(span.get("startTimeUnixNano"))) / 1_000_000)
    except Exception:
        return 0.0


def summarize_otel_trace(payload: Any) -> dict[str, Any]:
    """Summarize an OTLP payload without emitting raw telemetry values."""
    diagnostics: list[str] = []
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            diagnostics.append("payload JSON could not be parsed")
    try:
        raw_spans = [] if diagnostics else _iter_spans(payload)
    except Exception as exc:
        diagnostics.append(str(exc))
        raw_spans = []
    if not diagnostics and not raw_spans:
        diagnostics.append("no spans found")

    spans: list[dict[str, Any]] = []
    by_span_id: dict[str, dict[str, Any]] = {}
    for service, span in raw_spans:
        attrs = _attrs(span.get("attributes"))
        safe_attrs = {
            key: attrs[key] for key in ALLOWED_STRING_ATTRS | ALLOWED_NUMBER_ATTRS
            if key in attrs and attrs[key] not in (None, "")
        }
        item = {
            "trace_ref": _hash_id(span.get("traceId")),
            "span_ref": _hash_id(span.get("spanId")),
            "parent_ref": _hash_id(span.get("parentSpanId")),
            "service": service,
            "name": str(span.get("name") or "")[:200],
            "duration_ms": round(_duration_ms(span), 3),
            "attributes": safe_attrs,
            "events": span.get("events") or [],
            "_parent_raw": str(span.get("parentSpanId") or ""),
            "_span_raw": str(span.get("spanId") or ""),
        }
        spans.append(item)
        if item["_span_raw"]:
            by_span_id[item["_span_raw"]] = item

    services = sorted({s["service"] for s in spans})
    traces = {s["trace_ref"] for s in spans if s["trace_ref"]}
    edges: Counter[tuple[str, str]] = Counter()
    for span in spans:
        parent = by_span_id.get(span["_parent_raw"])
        if parent and parent["service"] != span["service"]:
            edges[(parent["service"], span["service"])] += 1

    routes: Counter[tuple[str, str, str, int]] = Counter()
    databases: Counter[tuple[str, str]] = Counter()
    exceptions: Counter[tuple[str, str]] = Counter()
    operations: Counter[tuple[str, str]] = Counter()
    for span in spans:
        attrs = span["attributes"]
        operations[(span["service"], span["name"])] += 1
        method = str(attrs.get("http.request.method") or attrs.get("http.method") or "")
        route = _route(attrs)
        if method or route:
            status = attrs.get("http.status_code", attrs.get("http.response.status_code", 0))
            try:
                status_int = int(status)
            except Exception:
                status_int = 0
            routes[(span["service"], method.upper(), route, status_int)] += 1
        if attrs.get("db.system") or attrs.get("db.operation"):
            databases[(str(attrs.get("db.system") or "unknown"), str(attrs.get("db.operation") or "unknown").upper())] += 1
        exc_type = str(attrs.get("exception.type") or attrs.get("error.type") or "")
        if exc_type:
            exceptions[(span["service"], exc_type)] += 1
        for event in span["events"]:
            if not isinstance(event, dict) or event.get("name") != "exception":
                continue
            event_attrs = _attrs(event.get("attributes"))
            exc_type = str(event_attrs.get("exception.type") or event_attrs.get("error.type") or "")
            if exc_type:
                exceptions[(span["service"], exc_type)] += 1

    return {
        "schema": SCHEMA,
        "valid": not diagnostics,
        "diagnostics": diagnostics,
        "traces": len(traces),
        "spans": len(spans),
        "services": services,
        "service_graph": [
            {"from": src, "to": dst, "calls": count}
            for (src, dst), count in sorted(edges.items())
        ],
        "http_routes": [
            {"service": svc, "method": method, "route": route, "status": status, "count": count}
            for (svc, method, route, status), count in sorted(routes.items())
        ],
        "database_operations": [
            {"system": system, "operation": operation, "count": count}
            for (system, operation), count in sorted(databases.items())
        ],
        "exceptions": [
            {"service": svc, "type": exc_type, "count": count}
            for (svc, exc_type), count in sorted(exceptions.items())
        ],
        "operations": [
            {"service": svc, "name": name, "count": count}
            for (svc, name), count in sorted(operations.items())
        ],
        "notes": [
            "Trace and span IDs are hashed; SQL text, targets, headers and messages are omitted.",
            "Grey-box telemetry is evidence about internal behavior, not a standalone vulnerability verdict.",
        ],
    }
