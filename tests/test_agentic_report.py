"""Tests for Markdown + SARIF 2.1.0 security QA report generator and `agent_cli.py report`."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agent_cli  # noqa: E402
import agentic_report  # noqa: E402
from agentic_surface import SurfaceFrontierTracker  # noqa: E402


SAMPLE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ1c2VyLTIiLCJyb2xlIjoiYWRtaW4ifQ."
    "sigpart123456789"
)

FORBIDDEN_RAW_SECRETS = (
    "secret-jwt-token-xyz",
    "supersecretcookie",
    "key-12345",
    "urltokensecret99",
    "pw-secret-999",
    SAMPLE_JWT,
)


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _build_synthetic_run(run_dir: Path) -> Path:
    tracker = SurfaceFrontierTracker(
        base_url="http://127.0.0.1:9000",
        allowed_methods=["GET", "POST", "PUT", "DELETE"],
        actor_summaries=[
            {"alias": "member_a", "role": "member", "tenant": "alpha"},
            {"alias": "member_b", "role": "member", "tenant": "beta"},
        ],
    )
    tracker.discovered_routes[("GET", "/api/v1/admin/audit")] = "/api/v1/admin/audit"
    tracker.discovered_write_ops[("PUT", "/api/v1/orders/{id}")] = "/api/v1/orders/101"
    tracker.visited_method_templates.add(("GET", "/api/v1/search"))
    tracker.visited_method_paths.add(("GET", "/api/v1/search"))
    tracker.discovered_params["/api/v1/search"] = {"q"}
    tracker.tested_params_by_template["/api/v1/search"] = {"q"}
    tracker.param_probes_by_template["/api/v1/search"] = {
        "q": {"values": {"orders"}, "has_special": False}
    }

    manifest = {
        "schema": "agentic-target-run/1",
        "run_id": "run-synthetic-001",
        "target": "http://127.0.0.1:9000",
        "status": "finished",
        "finished": True,
        "execution_mode": "sharded",
        "models": {
            "worker": "openai/gpt-5-mini",
            "bootstrap_model": "openai/gpt-5-nano",
            "shard_model": "openai/gpt-5-mini",
        },
        "wall_clock_seconds": 42.5,
        "http_requests_used": 64,
        "http_requests_limit": 200,
        "llm_calls": 18,
        "token_usage": {
            "total_tokens": 125000,
            "prompt_tokens": 98000,
            "completion_tokens": 27000,
            "cached_prompt_tokens": 60000,
            "uncached_prompt_tokens": 38000,
            "cache_hit_rate": 0.612,
            "reasoning_tokens": 4200,
        },
        "sharding_summary": {
            "bootstrap_turns": 8,
            "bootstrap_calls": 6,
            "bootstrap_tokens": 31000,
            "bootstrap_findings": 1,
            "bootstrap_model": "openai/gpt-5-nano",
            "shard_model": "openai/gpt-5-mini",
            "fallback_to_monolithic": False,
            "shards": [
                {
                    "shard_id": "shard-1",
                    "name": "orders",
                    "families": ["/api/v1/orders", "/api/v1/comments"],
                    "status": "finished",
                    "calls": 7,
                    "tokens": 54000,
                    "findings": 2,
                },
                {
                    "shard_id": "shard-2",
                    "name": "webhooks",
                    "families": ["/api/v1/webhooks"],
                    "status": "finished",
                    "calls": 5,
                    "tokens": 40000,
                    "findings": 1,
                },
            ],
        },
        "untested_areas": [
            "DELETE /api/v1/orders/{id} not exercised due to scope guard",
            "Admin audit log export endpoint unverified",
        ],
        "surface_frontier": tracker.to_dict(),
    }
    _write_json(run_dir / "manifest.json", manifest)

    process_metrics = {
        "schema": "agentic-process-metrics/1",
        "exposure_rate": {
            "unique_endpoints_discovered": 10,
            "unique_endpoints_visited": 7,
            "coverage_ratio": 0.7,
            "reference_matched": 7,
            "reference_total": 10,
            "reference_exposure_rate": 0.7,
        },
        "counts": {"total_tokens": 125000},
    }
    _write_json(run_dir / "process_metrics.json", process_metrics)

    receipts = [
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0001",
            "actor": "member_b",
            "method": "GET",
            "url": "http://127.0.0.1:9000/api/v1/orders/101?token=urltokensecret99&view=full",
            "path": "/api/v1/orders/101",
            "query": "token=urltokensecret99&view=full",
            "request_headers": {
                "Authorization": "Bearer secret-jwt-token-xyz",
                "Cookie": "sid=supersecretcookie",
                "X-API-Key": "key-12345",
                "Accept": "application/json",
            },
            "request_body": "",
            "status": 200,
            "response_headers": {
                "Content-Type": "application/json",
                "Set-Cookie": "sid=supersecretcookie; HttpOnly; Path=/",
            },
            "body": json.dumps({
                "id": 101,
                "owner": "member_a",
                "api_key": "key-12345",
                "password": "pw-secret-999",
                "jwt": SAMPLE_JWT,
                "total": 499.0,
            }),
        },
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0002",
            "actor": "member_a",
            "method": "GET",
            "url": "http://127.0.0.1:9000/api/v1/orders/101",
            "path": "/api/v1/orders/101",
            "request_headers": {"Authorization": "Bearer owner-valid-token"},
            "request_body": "",
            "status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "body": '{"id": 101, "owner": "member_a"}',
        },
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0003",
            "actor": "member_a",
            "method": "POST",
            "url": "http://127.0.0.1:9000/api/v1/comments",
            "path": "/api/v1/comments",
            "request_headers": {
                "Cookie": "sid=supersecretcookie",
                "Content-Type": "application/json",
            },
            "request_body": '{"body":"<img src=x onerror=alert(1)>","token":"secret-jwt-token-xyz"}',
            "status": 201,
            "response_headers": {"Content-Type": "application/json"},
            "body": '{"id": 9, "status": "created"}',
        },
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0004",
            "actor": "member_b",
            "method": "GET",
            "url": "http://127.0.0.1:9000/comments",
            "path": "/comments",
            "request_headers": {"Accept": "text/html"},
            "request_body": "",
            "status": 200,
            "response_headers": {"Content-Type": "text/html"},
            "body": "<div><img src=x onerror=alert(1)></div>",
        },
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0005",
            "actor": "member_a",
            "method": "POST",
            "url": "http://127.0.0.1:9000/api/v1/webhooks/test",
            "path": "/api/v1/webhooks/test",
            "request_headers": {
                "X-API-Key": "key-12345",
                "Content-Type": "application/json",
            },
            "request_body": '{"callback_url":"http://127.0.0.1:19999/oob-cb"}',
            "status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "body": '{"fetched": true, "upstream_status": 200}',
        },
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0006",
            "actor": "anon",
            "method": "POST",
            "url": "http://127.0.0.1:9000/api/v1/webhooks/test",
            "path": "/api/v1/webhooks/test",
            "request_headers": {"Content-Type": "application/json"},
            "request_body": '{"callback_url":"https://example.invalid/"}',
            "status": 401,
            "response_headers": {"Content-Type": "application/json"},
            "body": '{"error":"unauthorized"}',
        },
    ]
    for rec in receipts:
        _write_json(run_dir / "receipts" / f"{rec['receipt_id']}.json", rec)

    findings = [
        {
            "finding_id": "F-001",
            "title": "Cross-user order read via BOLA",
            "class_type": "bola",
            "severity": "high",
            "method": "GET",
            "url": "http://127.0.0.1:9000/api/v1/orders/101?token=urltokensecret99&view=full",
            "path": "/api/v1/orders/101",
            "route_template": "/api/v1/orders/{id}",
            "actor": "member_b",
            "status": "verified",
            "oracle_verdict": "VERIFIED",
            "evidence": (
                f"Authorization: Bearer secret-jwt-token-xyz leaked order owned by member_a; "
                f"jwt={SAMPLE_JWT}; key=key-12345; Cookie: sid=supersecretcookie"
            ),
            "summary": "member_b retrieved member_a order 101 without ownership check.",
            "proof_receipt_ids": ["req-0001"],
            "control_receipt_ids": ["req-0002"],
        },
        {
            "finding_id": "F-002",
            "title": "Stored XSS in comments view",
            "class_type": "stored_xss",
            "severity": "medium",
            "method": "POST",
            "url": "http://127.0.0.1:9000/api/v1/comments",
            "path": "/api/v1/comments",
            "route_template": "/api/v1/comments",
            "actor": "member_a",
            "status": "verified",
            "oracle_verdict": "VERIFIED",
            "evidence": "<div><img src=x onerror=alert(1)></div>",
            "summary": "HTML payload stored via API renders unescaped on /comments.",
            "proof_receipt_ids": ["req-0003", "req-0004"],
            "control_receipt_ids": ["req-0002"],
        },
        {
            "finding_id": "F-003",
            "title": "Server-side request forgery in webhook tester",
            "class_type": "ssrf",
            "severity": "critical",
            "method": "POST",
            "url": "http://127.0.0.1:9000/api/v1/webhooks/test",
            "path": "/api/v1/webhooks/test",
            "route_template": "/api/v1/webhooks/test",
            "actor": "member_a",
            "status": "verified",
            "oracle_verdict": "VERIFIED",
            "evidence": "OOB callback hit received from server.",
            "summary": "Webhook test endpoint fetches attacker-supplied internal URL.",
            "proof_receipt_ids": ["req-0005"],
            "control_receipt_ids": ["req-0006"],
        },
    ]
    _write_json(run_dir / "findings.json", findings)
    return run_dir


def test_full_markdown_and_sarif_generation_and_redaction(tmp_path: Path) -> None:
    run_dir = _build_synthetic_run(tmp_path / "run-001")
    summary = agentic_report.generate_run_reports(run_dir)

    assert summary["status"] == "finished"
    assert summary["findings_count"] == 3
    assert summary["untested_count"] == 2
    assert summary["exposure_rate"] == pytest.approx(0.7)

    md_path = Path(summary["markdown_path"])
    sarif_path = Path(summary["sarif_path"])
    assert md_path.is_file()
    assert sarif_path.is_file()

    md_text = md_path.read_text(encoding="utf-8")
    sarif_raw = sarif_path.read_text(encoding="utf-8")
    sarif_doc = json.loads(sarif_raw)

    # Zero raw secret leakage across both report artifacts.
    for secret in FORBIDDEN_RAW_SECRETS:
        assert secret not in md_text, f"Leaked secret in report.md: {secret}"
        assert secret not in sarif_raw, f"Leaked secret in report.sarif: {secret}"

    # Executive summary & models (including bootstrap/shard + token cache metrics).
    assert "run-synthetic-001" in md_text
    assert "openai/gpt-5-nano" in md_text
    assert "openai/gpt-5-mini" in md_text
    assert "cached_prompt_tokens=60000" in md_text
    assert "uncached_prompt_tokens=38000" in md_text
    assert "cache_hit_rate=61.2%" in md_text
    assert "reasoning_tokens=4200" in md_text
    assert "70.00%" in md_text

    # Severity sorting: F-003 (critical) before F-001 (high) before F-002 (medium).
    pos_f003 = md_text.index("### F-003:")
    pos_f001 = md_text.index("### F-001:")
    pos_f002 = md_text.index("### F-002:")
    assert pos_f003 < pos_f001 < pos_f002

    # OWASP + CWE labels and minimal redacted curl reproductions.
    assert "CWE-639" in md_text and "OWASP API1:2023" in md_text
    assert "CWE-79" in md_text
    assert "CWE-918" in md_text
    assert '-H "Authorization: <REDACTED_AUTH_HEADER>"' in md_text
    assert '-H "Cookie: <REDACTED_COOKIE>"' in md_text
    assert '-H "X-API-Key: <REDACTED_HEADER>"' in md_text
    assert "curl -sS -i -X GET" in md_text
    assert "curl -sS -i -X POST" in md_text

    # Shard summary and explicit NOT TESTED visibility.
    assert "## 4. Shard Execution Summary" in md_text
    assert "shard-1" in md_text and "shard-2" in md_text
    assert "NOT TESTED & Coverage Visibility" in md_text
    assert "DELETE /api/v1/orders/{id} not exercised due to scope guard" in md_text
    assert "/api/v1/admin/audit" in md_text
    assert "PUT /api/v1/orders/101" in md_text
    assert "/api/v1/search?q=" in md_text

    # SARIF 2.1.0 validation.
    assert sarif_doc["version"] == "2.1.0"
    assert sarif_doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    run_obj = sarif_doc["runs"][0]
    driver = run_obj["tool"]["driver"]
    assert driver["name"] == "Kryon Agentic Engine"
    assert driver["semanticVersion"] == "0.4.0"
    assert driver["informationUri"] == "https://github.com/EmreMetin00007/kryon"

    rule_ids = [r["id"] for r in driver["rules"]]
    assert len(rule_ids) == len(set(rule_ids)) == 3
    assert set(rule_ids) == {"ssrf", "bola", "stored_xss"}
    for rule in driver["rules"]:
        assert rule["shortDescription"]["text"]
        assert rule["fullDescription"]["text"]
        assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note"}
        assert any(t.startswith("CWE-") for t in rule["properties"]["tags"])

    results = run_obj["results"]
    assert len(results) == 3
    assert [r["properties"]["finding_id"] for r in results] == ["F-003", "F-001", "F-002"]
    assert results[0]["level"] == "error"
    assert results[1]["level"] == "error"
    assert results[2]["level"] == "warning"
    for res in results:
        assert res["partialFingerprints"]["primaryLocationLineHash"]
        assert res["partialFingerprints"]["canonicalKey"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert res["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
        assert res["properties"]["reproduction_curl"].startswith("curl ")

    inv = run_obj["invocations"][0]
    assert inv["executionSuccessful"] is True
    assert inv["properties"]["run_id"] == "run-synthetic-001"
    assert inv["properties"]["coverage_complete"] is False
    assert inv["properties"]["exposure_rate"] == pytest.approx(0.7)
    assert len(inv["properties"]["untested_areas"]) == 2


def test_zero_findings_and_launch_json_fallback(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-empty"
    run_dir.mkdir(parents=True)
    _write_json(
        run_dir / "launch.json",
        {
            "run_id": "run-empty-01",
            "target": "http://127.0.0.1:8080",
            "status": "max_turns_reached",
            "models": {"worker": "openai/gpt-5-mini"},
            "untested_areas": ["GraphQL endpoint untested"],
        },
    )
    _write_json(run_dir / "findings.json", [])

    summary = agentic_report.generate_run_reports(run_dir)
    assert summary["findings_count"] == 0
    assert summary["untested_count"] == 1
    assert summary["exposure_rate"] is None

    md_text = Path(summary["markdown_path"]).read_text(encoding="utf-8")
    assert "No verified findings recorded." in md_text
    assert "NOT TESTED & Coverage Visibility" in md_text
    assert "GraphQL endpoint untested" in md_text

    sarif_doc = json.loads(Path(summary["sarif_path"]).read_text(encoding="utf-8"))
    assert sarif_doc["runs"][0]["results"] == []
    assert sarif_doc["runs"][0]["tool"]["driver"]["rules"] == []
    assert sarif_doc["runs"][0]["invocations"][0]["executionSuccessful"] is True
    assert sarif_doc["runs"][0]["invocations"][0]["properties"]["coverage_complete"] is False


def test_missing_receipts_and_corrupt_files_graceful_fallback(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-partial"
    (run_dir / "receipts").mkdir(parents=True)
    (run_dir / "manifest.json").write_text("{corrupt json", encoding="utf-8")
    (run_dir / "receipts" / "req-9999.json").write_text("{bad", encoding="utf-8")
    _write_json(
        run_dir / "findings.json",
        [
            {
                "finding_id": "F-010",
                "title": "Unclassified header weakness",
                "class_type": "custom_unknown_class",
                "severity": "low",
                "method": "DELETE",
                "url": "http://127.0.0.1:9001/api/items/5?api_key=key-12345",
                "actor": "member_a",
                "proof_receipt_ids": ["req-0404"],
                "control_receipt_ids": [],
                "evidence": "deleted item",
            }
        ],
    )

    summary = agentic_report.generate_run_reports(run_dir, formats=("markdown", "sarif"))
    assert summary["findings_count"] == 1
    md_text = Path(summary["markdown_path"]).read_text(encoding="utf-8")
    sarif_doc = json.loads(Path(summary["sarif_path"]).read_text(encoding="utf-8"))

    assert "key-12345" not in md_text
    assert "CWE-693" in md_text
    assert "Proof receipt JSON was unavailable on disk" in md_text
    assert "curl -sS -i -X DELETE" in md_text
    assert sarif_doc["runs"][0]["results"][0]["level"] == "note"


def test_class_owasp_cwe_mapping_coverage() -> None:
    expected_classes = (
        "bola",
        "bfla",
        "auth_bypass",
        "tenant_isolation",
        "stored_xss",
        "reflected_xss",
        "sqli",
        "sqli_read",
        "ssrf",
        "ssti",
        "mass_assignment",
        "open_redirect",
        "path_traversal",
        "csrf",
        "race_condition",
        "business_logic",
    )
    for cls_name in expected_classes:
        meta = agentic_report._class_metadata(cls_name)
        assert "OWASP" in meta["owasp"]
        assert meta["cwe"].startswith("CWE-")


def test_agent_cli_report_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run_dir = _build_synthetic_run(tmp_path / "run-cli")
    out_dir = tmp_path / "reports-out"

    assert "report" in agent_cli.COMMANDS
    assert agent_cli.COMMANDS["report"] == ("agentic_report", [])

    rc = agent_cli.main([
        "report",
        str(run_dir),
        "--output-dir",
        str(out_dir),
        "--format",
        "all",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["findings_count"] == 3
    assert Path(payload["markdown_path"]) == out_dir.resolve() / "report.md"
    assert Path(payload["sarif_path"]) == out_dir.resolve() / "report.sarif"
    assert (out_dir / "report.md").is_file()
    assert (out_dir / "report.sarif").is_file()


def test_agentic_report_missing_run_dir_returns_nonzero(tmp_path: Path) -> None:
    rc = agentic_report.main([str(tmp_path / "does-not-exist")])
    assert rc != 0
