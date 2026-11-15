"""E6 multi-family benchmark, shared-ceiling before/after comparison, and auth gates."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading

import pytest

import agent_cli
import full_agent_e6_benchmark as e6
import full_agent_holdout as holdout
import full_agent_launcher as launcher
import full_agent_preflight as preflight
from full_agent_broker import dump
from full_agent_python_broker import READ_TOOL, SUMMARY_TOOL
from test_full_agent_python_solver import acceptance_evidence as acceptance_evidence, baseline as baseline


def _write_llm_config(path: Path, base_url: str, model_id: str = "model") -> Path:
    dump(path, {
        "schema": "cco-llm/1",
        "model": f"owned/{model_id}",
        "providers": {
            "owned": {
                "base_url": base_url,
                "models": [model_id],
                "api_key_env": "CCO_BENCHMARK_API_KEY",
            }
        },
    })
    return path


def _fit_tool_args(body: dict, tool_name: str, args):
    """Filter scripted tool arguments to advertised JSON schema properties when closed."""
    if not isinstance(args, dict):
        return args
    for row in body.get("tools", []):
        fn = row.get("function", {})
        if fn.get("name") == tool_name:
            params = fn.get("parameters", {})
            props = params.get("properties")
            if isinstance(props, dict) and params.get("additionalProperties") is False:
                return {key: value for key, value in args.items() if key in props}
            return args
    return args


def _make_fake_provider(mode: str, *, fail_families: set[str] | None = None):
    """Build a deterministic OpenAI-compatible HTTP handler for loopback cohort tests."""
    fail_on = set(fail_families or ())

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            context = json.loads(body["messages"][1]["content"])
            spec = context["task_spec"]
            results = context.get("recent_results", [])
            allowed = {row["function"]["name"] for row in body.get("tools", [])}
            target = spec["target"]
            bindings_map = context.get("session_bindings") or {}
            if allowed == {SUMMARY_TOOL}:
                tool, args = SUMMARY_TOOL, {
                    "status": "partial" if spec["phase"] in {"access", "report"} else "done",
                    "next": "Broader coverage remains NOT TESTED.",
                    "steps": [{"id": step["id"], "status": "done"}
                              for step in spec["steps"] if not step["host_managed"]],
                }
            elif spec["phase"] == "recon" and not results:
                tool, args = "kali-tools_curl_request", {"url": target}
            elif spec["phase"] == "enum" and not results:
                tool, args = "kali-tools_crawl_web_surface", {
                    "target": target, "max_pages": 2 if mode == "before" else 5,
                }
            elif spec["phase"] == "access":
                discovery = context.get("discovery") or {}
                read_results = [r for r in results if r.get("tool") == READ_TOOL]
                have_loop = any(r.get("tool") == "hunter_run_web_loop" for r in results)
                read_texts = " ".join(
                    (r.get("result") or {}).get("text", "") for r in read_results
                )
                candidate_cards = context.get("candidate_cards") or []
                surface_text = (
                    json.dumps(discovery)
                    + " "
                    + read_texts
                    + " "
                    + json.dumps(candidate_cards)
                )
                has_sqli = "id=" in surface_text or any(
                    isinstance(card, dict) and card.get("param") == "id"
                    for card in candidate_cards
                )
                has_ssti = "name=" in surface_text or any(
                    isinstance(card, dict) and card.get("param") == "name"
                    for card in candidate_cards
                )
                last_read = (read_results[-1].get("result") or {}) if read_results else {}
                need_more_read = bool(
                    discovery.get("content_ref")
                    and not (has_sqli or has_ssti)
                    and (
                        not read_results
                        or (not last_read.get("eof") and isinstance(last_read.get("next_offset"), int))
                    )
                )
                if not have_loop and len(bindings_map) == 1 and need_more_read:
                    next_offset = last_read.get("next_offset", 0) if read_results else 0
                    tool, args = READ_TOOL, {
                        "path": discovery["content_ref"]["path"], "offset": next_offset, "limit": 3000,
                    }
                elif not have_loop:
                    if "ssti" in fail_on and has_ssti:
                        # Trigger a deterministic second-batch protocol failure cleanly.
                        tool, args = "kali-tools_curl_request", "not-an-object"
                    elif mode == "before" and len(bindings_map) >= 2:
                        # Baseline strategy tests only first pair with small blind budget.
                        bindings = dict(list(bindings_map.items())[:2])
                        tool, args = "hunter_run_web_loop", {
                            "target": target, "live": True, "crawl": False,
                            "blind_discovery": True, "blind_max_requests": 12,
                            "fuzz_limit": 0, "candidate_sample_limit": 0,
                            "max_validations": 8, "sleep_s": 0.2,
                            "session_bindings": json.dumps(bindings),
                        }
                    elif has_sqli:
                        tool, args = "hunter_run_web_loop", {
                            "target": target, "live": True, "crawl": False,
                            "fuzz_limit": 4, "candidate_sample_limit": 16,
                            "max_validations": 16, "sleep_s": 0.2,
                            "validation_profile": "readonly_sqli_boolean",
                            "session_bindings": json.dumps(bindings_map),
                        }
                    elif has_ssti:
                        tool, args = "hunter_run_web_loop", {
                            "target": target, "live": True, "crawl": False,
                            "fuzz_limit": 4, "candidate_sample_limit": 16,
                            "max_validations": 16, "sleep_s": 0.2,
                            "validation_profile": "readonly_ssti_arithmetic",
                            "session_bindings": json.dumps(bindings_map),
                        }
                    else:
                        bindings = dict(list(bindings_map.items())[:2])
                        tool, args = "hunter_run_web_loop", {
                            "target": target, "live": True, "crawl": False,
                            "blind_discovery": True, "blind_max_requests": 24,
                            "fuzz_limit": 0, "candidate_sample_limit": 0,
                            "max_validations": 16, "sleep_s": 0.2,
                            "session_bindings": json.dumps(bindings),
                        }
                else:
                    tool, args = SUMMARY_TOOL, {
                        "status": "partial",
                        "next": "Broader coverage remains NOT TESTED.",
                        "steps": [{"id": step["id"], "status": "done"}
                                  for step in spec["steps"] if not step["host_managed"]],
                    }
            elif spec["phase"] == "report" and not results:
                tool, args = "hunter_coverage_report", {"target": target}
            else:
                if isinstance(context.get("protocol_feedback"), dict) and context["protocol_feedback"].get("reason_code"):
                    tool, args = "kali-tools_curl_request", "still-not-an-object"
                else:
                    tool, args = SUMMARY_TOOL, {
                        "status": "partial" if spec["phase"] in {"access", "report"} else "done",
                        "next": "Broader coverage remains NOT TESTED.",
                        "steps": [{"id": step["id"], "status": "done"}
                                  for step in spec["steps"] if not step["host_managed"]],
                    }
            fitted_args = _fit_tool_args(body, tool, args)
            payload = {
                "choices": [{"message": {"tool_calls": [{
                    "function": {
                        "name": tool,
                        "arguments": json.dumps(fitted_args) if isinstance(fitted_args, dict) else "{",
                    }
                }]}}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200},
            }
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return Provider


def test_validate_suite_requires_three_distinct_registered_families():
    with pytest.raises(ValueError, match="at least 3"):
        e6.validate_suite(["readonly-api-access-control", "readonly-sql-injection"])
    with pytest.raises(ValueError, match="at least 3"):
        e6.validate_suite(["readonly-api-access-control", "readonly-api-access-control", "readonly-sql-injection"])
    with pytest.raises(ValueError, match="unregistered"):
        e6.validate_suite(["readonly-api-access-control", "readonly-sql-injection", "renamed-family"])
    suite = e6.validate_suite()
    assert len(suite["families"]) == 3
    assert len(suite["selections"]) == 3


def test_runtime_snapshot_excludes_e6_benchmark_harness():
    assert not preflight.runtime_file(Path("scripts/full_agent_e6_benchmark.py"))


def test_live_remote_provider_requires_explicit_authorization(baseline, tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_BENCHMARK_API_KEY", "synthetic-unused-secret")
    config = _write_llm_config(tmp_path / "remote.json", "https://provider.invalid/v1")
    out_plan = tmp_path.parent / (tmp_path.name + "-e6-plan")
    out_run = tmp_path.parent / (tmp_path.name + "-e6-run")

    # Plan-only succeeds offline with 0 LLM/HTTP calls even for remote HTTPS configs.
    assert agent_cli.main([
        "benchmark", "plan", "--label", "remote-plan",
        "--baseline", str(baseline), "--provider-config", str(config),
        "--output-dir", str(out_plan), "--token-budget", "100000", "--http-budget", "200",
    ]) == 0
    plan = json.loads((out_plan / "suite-plan.json").read_text())
    assert plan["executed"] is False and plan["llm_calls"] == 0 and plan["target_requests"] == 0

    # Executing against a remote provider without explicit authorization fails closed.
    with pytest.raises(PermissionError, match="explicit operator authorization"):
        e6.run_cohort(
            "unauthorized-remote", baseline=baseline, provider_config=config,
            output_dir=out_run, execute=True,
        )
    assert not out_run.exists()

    # Authorization without a non-empty reason still fails closed.
    with pytest.raises(PermissionError, match="explicit operator authorization"):
        e6.authorize_provider(config, execute=True, authorize_live_provider=True, live_authorization_reason="   ")

    # Explicit authorization + reason passes the provider gate without leaking secrets.
    auth = e6.authorize_provider(
        config, execute=True, authorize_live_provider=True,
        live_authorization_reason="User approved remote model E6 benchmark",
    )
    assert auth["live_provider_authorized"] is True
    assert auth["provider_kind"] == "remote"
    assert "synthetic-unused-secret" not in json.dumps(auth)


def test_unknown_cost_is_never_zero_and_mismatch_checks_fail_closed(tmp_path):
    # Unknown cost must remain None across usage extraction and aggregation.
    usage = holdout._extract_run_usage(tmp_path, {"target_requests": 10, "llm_calls": 2, "wall_clock_seconds": 3.5}, 10)
    assert usage["cost_usd"] is None and usage["cost_known"] is False and usage["unknown_cost_is_zero"] is False

    contract = preflight.native_contract({}, {"planner": "owned/a", "worker": "owned/a"}, 100000)["holdout"]
    families = list(holdout.FAMILIES)[:3]
    metrics = []
    for idx, fam in enumerate(families):
        metrics.append({
            "family": fam,
            "closure_verified": True,
            "failed": False,
            "recall": {"numerator": 8, "denominator": 8, "value": 1.0},
            "negative_coverage": {"numerator": 8, "denominator": 8, "value": 1.0},
            "false_positives": {"numerator": 0, "denominator": 8, "value": 0.0},
            "models": {"planner": "owned/a", "worker": "owned/a"},
            "effective_limits": {"http_requests_per_seed": 200, "llm_tokens_per_seed": 100000, "seconds_per_seed": 300},
            "usage": {
                "llm_calls": 5, "http_requests": 40, "tokens_used": 1000,
                "prompt_tokens": 600, "completion_tokens": 400,
                "wall_clock_seconds": 1.0,
                "cost_usd": 0.05 if idx < 2 else None,
                "cost_known": idx < 2, "unknown_cost_is_zero": False,
            },
            "not_tested": {"untested_dimensions": ["paid_remote_model_generalization"]},
        })
    agg = holdout.aggregate(metrics, contract)
    assert agg["usage"]["cost_usd"] is None
    assert agg["usage"]["cost_complete"] is False
    assert agg["usage"]["unknown_cost_is_zero"] is False
    assert agg["requests_per_verified_finding"] == pytest.approx(120 / 24)
    assert agg["tokens_per_verified_finding"] == pytest.approx(3000 / 24)
    assert agg["failed_runs"] == {"numerator": 0, "denominator": 3, "value": 0.0}

    # Build two minimal cohorts and verify compare rejects mismatched ceilings/families.
    def _cohort(http_limit, fam_list):
        return {
            "schema": e6.SCHEMA_COHORT,
            "label": "c",
            "ceilings": {"http_requests_per_seed": http_limit, "llm_tokens_per_seed": 100000, "seconds_per_seed": 300},
            "families": fam_list,
            "models": ["owned/a"],
            "provider_kinds": ["loopback"],
            "paid_provider_calls": 0,
            "recall": agg["overall_recall"],
            "false_positives": agg["false_positives"],
            "negative_coverage": agg["negative_coverage"],
            "failed_run_rate": agg["failed_runs"],
            "verified_findings": 24,
            "requests_per_verified_finding": 5.0,
            "tokens_per_verified_finding": 125.0,
            "usage": agg["usage"],
            "aggregate_status": "passed",
            "paid_model_generalization": "not_evaluated",
            "per_family": {f: agg["per_family"][f] for f in fam_list if f in agg["per_family"]},
            "runs": [],
            "not_tested_dimensions": ["paid_remote_model_generalization"],
        }

    with pytest.raises(ValueError, match="identical token, HTTP, and duration ceilings"):
        e6.compare_cohorts(_cohort(200, families), _cohort(250, families))
    alt_families = [families[0], families[1], "readonly-path-traversal"]
    with pytest.raises(ValueError, match="same >=3 independent families"):
        e6.compare_cohorts(_cohort(200, families), _cohort(200, alt_families))


def test_failed_run_audit_counts_failure_rate_and_rejects_evaluator_tampering(baseline, tmp_path):
    base_work = tmp_path.parent / (tmp_path.name + "-failed-audit")
    config = _write_llm_config(tmp_path / "loopback.json", "http://127.0.0.1:1/v1")
    plan_path, plan = e6.prepare_cohort(
        "failed-check", baseline=baseline, provider_config=config,
        output_dir=base_work, http_budget=200, token_budget=100000, seconds_budget=120,
    )
    run_dir = base_work / "runs/mock-failed"
    private = run_dir / "private"
    solver = run_dir / "solver"
    private.mkdir(parents=True)
    solver.mkdir(parents=True)

    selected = holdout.selection("readonly-api-access-control", plan["runs"][0]["seed"])
    lab = holdout.start(selected, private)
    try:
        dump(private / "evaluator/wire.json", [])
    finally:
        lab.server_close()
        if lab.blind_state.get("db") is not None:
            lab.blind_state["db"].close()

    dump(private / "budget.json", {
        "limits": {"http": 200, "tokens": 100000},
        "used": {"http": 2, "tokens": 400},
        "events": [
            {"kind": "tokens", "reserved": 500, "charged": 200, "measurement_valid": True,
             "usage": {"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200}},
            {"kind": "tokens", "reserved": 500, "charged": 200, "measurement_valid": True,
             "usage": {"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200}},
        ],
    })
    manifest = {
        "schema": launcher.SCHEMA,
        "status": "launch_failed",
        "stop_reason": "protocol_repair_exhausted",
        "seed": selected["seed"],
        "preflight": plan["runs"][0]["preflight"],
        "models": plan["models"],
        "llm_cost_usd": None,
        "llm_calls": 2,
        "target_requests": 2,
        "wall_clock_seconds": 1.25,
        "solver_mode": "python_loop",
        "provider_kind": "loopback",
        "effective_limits": plan["ceilings"],
        "target": "http://127.0.0.1:1/",
    }
    manifest_path = run_dir / "launch.json"
    dump(manifest_path, manifest)

    metrics, _ = holdout.audit_run_status(manifest_path)
    assert metrics["failed"] is True
    assert metrics["failure_reason"] == "protocol_repair_exhausted"
    assert metrics["closure_verified"] is False
    assert metrics["recall"] == {"numerator": 0, "denominator": 8, "value": 0.0}
    assert metrics["usage"]["tokens_used"] == 400
    assert metrics["usage"]["cost_usd"] is None
    assert "incomplete_run_before_closure" in metrics["not_tested"]["untested_dimensions"]

    # Tampered evaluator source must still raise ValueError fail-closed.
    lab_src = private / "evaluator/lab-source.py"
    lab_src.write_text("# tampered")
    with pytest.raises(ValueError, match="lab source changed"):
        holdout.audit_run_status(manifest_path)


@pytest.mark.integration
def test_e6_before_after_comparison_across_three_families_under_shared_ceilings(baseline, tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_BENCHMARK_API_KEY", "host-only-local-fixture")
    work_base = Path(os.environ.get("CCO_WORKDIR", str(tmp_path.parent))).expanduser().resolve()
    work_base.mkdir(parents=True, exist_ok=True)
    work_root = Path(tempfile.mkdtemp(prefix="e6-bench-", dir=str(work_base)))
    shared_ceilings = {"http_budget": 250, "token_budget": 150000, "seconds_budget": 260}

    before_srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_fake_provider("before", fail_families={"ssti"}))
    after_srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_fake_provider("after"))
    before_thread = threading.Thread(target=before_srv.serve_forever, daemon=True)
    after_thread = threading.Thread(target=after_srv.serve_forever, daemon=True)
    before_thread.start()
    after_thread.start()
    try:
        before_cfg = _write_llm_config(work_root / "before-llm.json", f"http://127.0.0.1:{before_srv.server_port}/v1", "before-model")
        after_cfg = _write_llm_config(work_root / "after-llm.json", f"http://127.0.0.1:{after_srv.server_port}/v1", "after-model")

        before_dir = work_root / "cohort-before"
        after_dir = work_root / "cohort-after"
        before_path, before_report = e6.run_cohort(
            "before-baseline", baseline=baseline, provider_config=before_cfg,
            output_dir=before_dir, execute=True, **shared_ceilings,
        )
        after_path, after_report = e6.run_cohort(
            "after-candidate", baseline=baseline, provider_config=after_cfg,
            output_dir=after_dir, execute=True,
            treatment={"name": "after-candidate", "role": "treatment", "changed_dimensions": ["provider_config"]},
            **shared_ceilings,
        )

        # Verify CLI compare subcommand works via cco-agent entrypoint cleanly.
        cmp_dir = work_root / "comparison-out"
        assert agent_cli.main([
            "benchmark", "compare",
            "--before", str(before_path),
            "--after", str(after_path),
            "--output-dir", str(cmp_dir),
        ]) == 0
        comparison = json.loads((cmp_dir / "comparison.json").read_text())
        markdown = (cmp_dir / "comparison.md").read_text()

        assert comparison["strict_paired"] is True
        assert comparison["reaudited_from_artifacts"] is True
        assert comparison["comparison_mode"] == "strict_paired"
        assert comparison["treatment"]["allowed_differences"] == ["provider_config"]
        assert comparison["ceilings_matched"] is True
        assert comparison["families"] == sorted(e6.DEFAULT_FAMILIES)
        assert comparison["models"] == {"before": ["owned/before-model"], "after": ["owned/after-model"]}
        assert comparison["before"]["recall"]["numerator"] < 24
        assert comparison["before"]["failed_run_rate"]["numerator"] == 1
        assert comparison["before"]["failed_run_rate"]["denominator"] == 3
        assert comparison["after"]["recall"] == {"numerator": 24, "denominator": 24, "value": 1.0}
        assert comparison["after"]["negative_coverage"] == {"numerator": 24, "denominator": 24, "value": 1.0}
        assert comparison["after"]["false_positives"]["numerator"] == 0
        assert comparison["after"]["failed_run_rate"] == {"numerator": 0, "denominator": 3, "value": 0.0}
        assert comparison["after"]["requests_per_verified_finding"] > 0
        assert comparison["after"]["tokens_per_verified_finding"] > 0
        assert comparison["deltas"]["recall"] > 0
        assert comparison["deltas"]["failed_run_rate"] < 0
        assert comparison["before"]["usage"]["cost_usd"] is None
        assert comparison["after"]["usage"]["cost_usd"] is None
        assert comparison["deltas"]["cost_usd"] is None
        assert "unknown (not zero)" in markdown
        assert "paid_remote_model_generalization" in comparison["not_tested_dimensions"]
        assert len(comparison["evidence"]["before_runs"]) == 3
        assert len(comparison["evidence"]["after_runs"]) == 3
    finally:
        before_srv.shutdown()
        after_srv.shutdown()
        before_thread.join(timeout=5)
        after_thread.join(timeout=5)
        before_srv.server_close()
        after_srv.server_close()
