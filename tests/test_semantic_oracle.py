"""Faz 1: semantik oracle — alan-seviyesi diff ve alan-esdegerligi.

Fixtures:
- personalised BOLA: ayni veri, farkli volatil alanlar -> ihlal bulunmali
- farkli veri: ayni sema, farkli degerler -> ihlal bulunmamali
- volatile-only degisim: observer anomalisi uretmemeli
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-validator"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-hunter"))

from cco_validator_core.observer import analyze_differential_observations, field_diff  # noqa: E402
from cco_hunter_core.identity_pool import diff_verdict, field_equivalent  # noqa: E402
from conftest import load_server  # noqa: E402


BASELINE = [
    {"label": f"b{i}", "status": 200, "elapsed_ms": 40 + i, "response_length": 60,
     "body": json.dumps({"order": {"id": 7, "total": 100, "owner": "a@x.com"},
                         "csrf_token": f"t{i}"})}
    for i in range(3)
]


def test_field_diff_reports_changed_data_paths():
    diff = field_diff(BASELINE[0]["body"],
                      json.dumps({"order": {"id": 7, "total": 999, "owner": "a@x.com"}}))
    assert diff["comparable"] is True
    assert "order.total" in diff["changed"]


def test_observer_flags_field_level_change():
    probe = {"label": "p1", "status": 200, "elapsed_ms": 42, "response_length": 60,
             "body": json.dumps({"order": {"id": 7, "total": 999, "owner": "a@x.com"},
                                 "csrf_token": "zz"})}
    out = analyze_differential_observations(BASELINE, [probe])
    assert out["anomalies"], "alan degisimi anomali olmali"
    assert "field_diff" in out["anomalies"][0]["signals"]
    assert "999" not in json.dumps(out), "govde degerleri sizmamali"


def test_observer_ignores_volatile_only_change():
    probe = {"label": "p1", "status": 200, "elapsed_ms": 42, "response_length": 60,
             "body": json.dumps({"order": {"id": 7, "total": 100, "owner": "a@x.com"},
                                 "csrf_token": "baska", "request_id": "r-1"})}
    out = analyze_differential_observations(BASELINE, [probe])
    assert not out["anomalies"]


def test_repeated_labels_median_suppresses_timing_outlier():
    probes = [
        {"label": "t", "status": 200, "elapsed_ms": ms, "response_length": 60,
         "body": BASELINE[0]["body"]}
        for ms in (41, 43, 4000)
    ]
    out = analyze_differential_observations(BASELINE, probes)
    timing = [a for a in out["anomalies"] if "timing" in a["signals"]]
    assert not timing, "tek outlier median ile elenmeli"


def _resp(total, csrf):
    return {"status": 200, "body": json.dumps(
        {"order": {"id": 7, "total": total, "owner": "a@x.com"}, "csrf_token": csrf})}


def test_personalised_bola_is_field_equivalent():
    assert field_equivalent(_resp(100, "a")["body"], _resp(100, "b")["body"])
    verdict = diff_verdict({"owner": _resp(100, "a"), "attacker": _resp(100, "b")})
    assert verdict["isolation_ok"] is False
    assert verdict["violations"][0]["match"] == "field_equivalent"


def test_different_data_is_not_equivalent():
    assert not field_equivalent(_resp(100, "a")["body"], _resp(250, "a")["body"])
    verdict = diff_verdict({"owner": _resp(100, "a"), "attacker": _resp(250, "a")})
    assert verdict["isolation_ok"] is True


def test_authz_oracle_confirms_field_equivalent_bola():
    hunter = load_server("hunter")
    out = json.loads(hunter.analyze_authz_result(json.dumps({
        "test_type": "bola",
        "authorized": {"identity": "userA", "status": 200,
                       "body": _resp(100, "a")["body"]},
        "attacker": {"identity": "userB", "status": 200,
                     "body": _resp(100, "b")["body"]},
    })))
    assert out["verdict"] == "CONFIRMED"
    assert out["evidence_grade"] == "field_equivalent"
