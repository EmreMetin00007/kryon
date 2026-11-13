import json
import os

from conftest import load_server


def test_report_target_does_not_match_host_substrings():
    memory = load_server("memory-server")
    kali = load_server("kali-tools")
    memory.store_finding("report-boundary.test", "xss", "low", "own finding")
    memory.store_finding("report-boundary.test.evil.test", "xss", "low", "other finding")
    report = json.loads(kali.generate_pentest_report("report-boundary.test", output_format="json"))
    assert report["hypotheses_count"] == 1
    assert report["hypotheses"][0]["description"] == "own finding"


def test_generate_pentest_report_filters_unvalidated_findings():
    memory_server = load_server("memory-server")
    validator = load_server("validator")
    hunter = load_server("hunter")
    kali_tools = load_server("kali-tools")

    artifact = validator._result(
        "SQL Injection (boolean-based)",
        "http://reportable.test/item?id=1",
        validator.CONFIRMED,
        "differential_boolean",
        {"true_payload": "1 AND 1=1"},
        ["curl -sk 'http://reportable.test/item?id=1%20AND%201=1'"],
        notes="verified",
    )
    memory_server.store_finding(
        "reportable.test",
        "sql_injection",
        "high",
        "validated",
        payload="1' AND 1=1",
        validation_result_json=artifact,
    )
    authz_artifact = hunter.analyze_authz_result(json.dumps({
        "target": "reportable.test",
        "test_type": "unauth",
        "protected_markers": ["all-customer-pii"],
        "attacker": {"identity": "anon", "status": 200, "markers": ["all-customer-pii"]},
    }))
    memory_server.store_finding(
        "reportable.test",
        "broken_access_control",
        "high",
        "authz validated",
        payload="GET /admin/export",
        validation_result_json=authz_artifact,
    )
    memory_server.store_finding("reportable.test", "xss", "medium", "hypothesis", "<svg>")

    report_json = json.loads(kali_tools.generate_pentest_report(
        "reportable.test", report_type="findings", output_format="json"
    ))
    assert report_json["reportable_findings_count"] == 2
    assert report_json["hypotheses_count"] == 1
    assert len(report_json["findings"]) == 2
    assert {item["type"] for item in report_json["findings"]} == {"sql_injection", "broken_access_control"}
    assert report_json["validation_summary"]["by_verdict"]["CONFIRMED"] == 2
    assert report_json["validation_summary"]["by_evidence_grade"]["differential_boolean"] == 1
    assert report_json["validation_summary"]["by_evidence_grade"]["marker_matched"] == 1
    assert any(item.get("validation_excerpt") for item in report_json["findings"])

    report_md = kali_tools.generate_pentest_report("reportable.test", report_type="findings")
    assert "Hariç Tutulan Hipotezler" in report_md
    assert "artifact-backed doğrulama" in report_md
    assert "Evidence Grade" in report_md
    assert "Validation Report" in report_md
    assert "Validation Excerpt" in report_md


def test_generate_pentest_report_revalidates_artifact_freshness():
    memory_server = load_server("memory-server")
    validator = load_server("validator")
    kali_tools = load_server("kali-tools")

    artifact = validator._result(
        "SQL Injection (boolean-based)",
        "http://stale-artifact.test/item?id=1",
        validator.CONFIRMED,
        "differential_boolean",
        {"true_payload": "1 AND 1=1"},
        ["curl -sk 'http://stale-artifact.test/item?id=1%20AND%201=1'"],
        notes="verified",
    )
    memory_server.store_finding(
        "stale-artifact.test",
        "sql_injection",
        "high",
        "validated",
        payload="1' AND 1=1",
        validation_result_json=artifact,
    )
    artifact_path = json.loads(artifact)["artifact"]["path"]
    os.remove(artifact_path)

    report_json = json.loads(kali_tools.generate_pentest_report(
        "stale-artifact.test", report_type="findings", output_format="json"
    ))
    assert report_json["reportable_findings_count"] == 0
    assert report_json["hypotheses_count"] == 1
    assert report_json["hypotheses"][0]["validation_state"] == "stale_or_invalid_artifact"


def test_generate_pentest_report_redacts_secrets():
    memory_server = load_server("memory-server")
    validator = load_server("validator")
    kali_tools = load_server("kali-tools")

    artifact = validator._result(
        "SQL Injection (boolean-based)",
        "http://redact.test/item?id=1",
        validator.CONFIRMED,
        "differential_boolean",
        {"true_payload": "1 AND 1=1"},
        ["curl -sk 'http://redact.test/item?id=1%20AND%201=1'"],
        notes="Authorization: Bearer SECRET123",
    )
    memory_server.store_finding(
        "redact.test",
        "sql_injection",
        "high",
        "cookie sess=ABCDEF123456 session=xyz",
        payload="password=hunter2 api_key=AKIA-SECRET",
        validation_result_json=artifact,
    )
    memory_server.store_finding(
        "redact.test", "xss", "medium", "hypothesis token=LEAKME", "plain"
    )

    report_json = json.loads(kali_tools.generate_pentest_report(
        "redact.test", report_type="findings", output_format="json"
    ))
    blob = json.dumps(report_json)
    assert "SECRET123" not in blob
    assert "hunter2" not in blob
    assert "AKIA-SECRET" not in blob
    assert "ABCDEF123456" not in blob
    assert "LEAKME" not in blob
    assert "[REDACTED]" in blob
    assert report_json["reportable_findings_count"] == 1

    report_md = kali_tools.generate_pentest_report("redact.test", report_type="findings")
    for secret in ("SECRET123", "hunter2", "AKIA-SECRET", "ABCDEF123456", "LEAKME"):
        assert secret not in report_md
    assert "[REDACTED]" in report_md


def _load_runtime():
    import importlib.util
    import sys
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts",
                        "campaign_runtime.py")
    spec = importlib.util.spec_from_file_location("campaign_runtime_report_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_campaign_report_requires_close_out(tmp_path):
    memory_server = load_server("memory-server")
    kali_tools = load_server("kali-tools")
    runtime_mod = _load_runtime()
    runtime = runtime_mod.CampaignRuntime(cco_home=os.environ["CCO_HOME"])
    campaign_id = runtime.create_campaign("gate-report", "", 0, 0.0, "")
    memory_server.store_finding("gatereport.test", "xss", "medium", "hipotez", "p")

    blocked = kali_tools.generate_pentest_report(
        "gatereport.test", report_type="findings", campaign_id=campaign_id)
    assert "Rapor Engellendi" in blocked

    note = tmp_path / "v.md"
    note.write_text("# Hüküm\nTamam.")
    runtime.record_verdict(campaign_id, "final", str(note))
    closed = runtime.close_out(campaign_id, require_brain_review=True,
                               waive_untested="test feragati")
    assert closed["closed"] is True
    passed = kali_tools.generate_pentest_report(
        "gatereport.test", report_type="findings", campaign_id=campaign_id)
    assert "Rapor Engellendi" not in passed

    opened = kali_tools.generate_pentest_report("gatereport.test", report_type="findings")
    assert "Rapor Engellendi" not in opened
