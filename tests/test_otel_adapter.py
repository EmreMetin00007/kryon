"""Grey-box OpenTelemetry adapter (offline, redacted summaries)."""

import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "mcp-servers", "mcp-telemetry"))

from cco_telemetry_core.otel import summarize_otel_trace


def _span(trace, span, parent, name, service, attrs=None, events=None):
    attributes = [
        {"key": k, "value": {"stringValue": str(v)}} for k, v in (attrs or {}).items()
    ]
    return {
        "traceId": trace,
        "spanId": span,
        "parentSpanId": parent,
        "name": name,
        "startTimeUnixNano": "1000000000",
        "endTimeUnixNano": "1250000000",
        "attributes": attributes,
        "events": events or [],
        "_service": service,
    }


def _otlp(spans):
    # Test helper groups spans by the private _service marker into resources.
    resources = {}
    for span in spans:
        service = span.pop("_service")
        resources.setdefault(service, []).append(span)
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": [
                    {"key": "service.name", "value": {"stringValue": service}}
                ]},
                "scopeSpans": [{"spans": items}],
            }
            for service, items in resources.items()
        ]
    }


def test_otel_summary_correlates_services_without_raw_data():
    payload = _otlp([
        _span("trace-secret", "a", "", "POST /checkout", "api", {
            "http.request.method": "POST",
            "http.route": "/checkout",
            "http.status_code": 200,
            "http.target": "/checkout?token=SECRET",
            "authorization": "Bearer [REDACTED]",
        }),
        _span("trace-secret", "b", "a", "SELECT orders", "api", {
            "db.system": "postgresql",
            "db.operation": "SELECT",
            "db.statement": "SELECT * FROM users WHERE token='SECRET'",
        }),
        _span("trace-secret", "c", "a", "payments.Charge", "payments", {
            "rpc.system": "grpc",
            "rpc.service": "payments",
            "rpc.method": "Charge",
        }, events=[{
            "name": "exception",
            "attributes": [
                {"key": "exception.type", "value": {"stringValue": "NullPointerException"}},
                {"key": "exception.message", "value": {"stringValue": "SECRET_MESSAGE"}},
            ],
        }]),
    ])
    out = summarize_otel_trace(payload)
    assert out["schema"] == "cco-greybox-telemetry/1"
    assert out["valid"] is True
    assert out["traces"] == 1
    assert out["spans"] == 3
    assert out["services"] == ["api", "payments"]
    assert any(e["type"] == "NullPointerException" for e in out["exceptions"])
    assert out["database_operations"][0]["operation"] == "SELECT"
    assert "SECRET" not in repr(out)
    assert "trace-secret" not in repr(out)


def test_otel_malformed_input_fails_closed():
    out = summarize_otel_trace({"resourceSpans": "bad"})
    assert out["valid"] is False
    assert out["diagnostics"]


def test_telemetry_registers_otel_tool():
    from conftest import list_tool_names, load_server

    assert "summarize_otel_trace" in list_tool_names(load_server("telemetry"))
