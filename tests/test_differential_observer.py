"""Differential behavior observer (offline, deterministic)."""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "mcp-servers", "mcp-validator"))

from cco_validator_core.observer import analyze_differential_observations


def _sample(label, **overrides):
    sample = {
        "label": label,
        "status": 200,
        "elapsed_ms": 20,
        "response_length": 100,
        "headers": {"Content-Type": "application/json", "X-Request-Id": "abc"},
        "body": '{"ok":true,"value":1}',
        "cookies": [{"name": "sid", "length": 24}],
    }
    sample.update(overrides)
    return sample


BASELINE = [_sample("b1"), _sample("b2", elapsed_ms=22), _sample("b3", elapsed_ms=19)]


def test_stable_probe_has_no_anomaly():
    out = analyze_differential_observations(BASELINE, [_sample("stable")])
    assert out["schema"] == "cco-differential-observations/1"
    assert out["anomalies"] == []
    assert out["clusters"][0]["verdict"] == "normal"


def test_timing_schema_and_status_deviations_are_clustered():
    probes = [
        _sample("slow", elapsed_ms=180),
        _sample("shape", body='{"ok":true,"value":1,"debug":{"sql":"SECRET_QUERY"}}'),
        _sample("status", status=500, body='{"error":"SECRET_MESSAGE"}'),
    ]
    out = analyze_differential_observations(BASELINE, probes)
    by_label = {a["label"]: a for a in out["anomalies"]}
    assert "timing" in by_label["slow"]["signals"]
    assert "body_schema" in by_label["shape"]["signals"]
    assert "status" in by_label["status"]["signals"]
    assert "SECRET_QUERY" not in repr(out)
    assert "SECRET_MESSAGE" not in repr(out)
    assert out["baseline"]["samples"] == 3


def test_insufficient_baseline_suppresses_timing_claim():
    out = analyze_differential_observations([_sample("only")], [_sample("slow", elapsed_ms=500)])
    assert out["anomalies"] == []
    assert any("baseline" in item for item in out["unknowns"])


def test_header_order_and_cookie_shape_are_metadata_only():
    probe = _sample(
        "meta",
        headers={"X-Request-Id": "different-value", "Content-Type": "application/json"},
        cookies=[{"name": "sid", "length": 48}, {"name": "prefs", "length": 10}],
    )
    out = analyze_differential_observations(BASELINE, [probe])
    anomaly = out["anomalies"][0]
    assert "header_order" in anomaly["signals"] or "header_set" in anomaly["signals"]
    assert "cookie_shape" in anomaly["signals"]
    assert "different-value" not in repr(out)


def test_validator_registers_observer_tool():
    from conftest import list_tool_names, load_server

    assert "analyze_differential_observations" in list_tool_names(load_server("validator"))
