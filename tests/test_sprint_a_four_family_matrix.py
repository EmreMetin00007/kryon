"""Sprint A Task 4 offline verification: 4-family x 3-repeat matrix under loopback provider."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

import pytest

import full_agent_e6_benchmark as e6
import full_agent_holdout as holdout
from full_agent_python_broker import READ_TOOL, SUMMARY_TOOL
from test_full_agent_e6_benchmark import _fit_tool_args, _write_llm_config
from test_full_agent_python_solver import acceptance_evidence as acceptance_evidence, baseline as baseline


def _make_matrix_provider(observed_prompts: list[str]):
    """Loopback OpenAI-compatible handler covering all 4 holdout families without paid LLM calls."""

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            raw_body = self.rfile.read(int(self.headers["Content-Length"])).decode("utf-8")
            observed_prompts.append(raw_body)
            body = json.loads(raw_body)
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
                tool, args = "kali-tools_crawl_web_surface", {"target": target, "max_pages": 6}
            elif spec["phase"] == "access":
                discovery = context.get("discovery") or {}
                read_results = [r for r in results if r.get("tool") == READ_TOOL]
                have_loop = any(r.get("tool") == "hunter_run_web_loop" for r in results)
                read_texts = " ".join((r.get("result") or {}).get("text", "") for r in read_results)
                candidate_cards = context.get("candidate_cards") or []
                surface_text = json.dumps(discovery) + " " + read_texts + " " + json.dumps(candidate_cards)
                has_sqli = "id=" in surface_text or any(
                    isinstance(card, dict) and card.get("param") == "id" for card in candidate_cards
                )
                has_ssti = "name=" in surface_text or any(
                    isinstance(card, dict) and card.get("param") == "name" for card in candidate_cards
                )
                has_trav = "file=" in surface_text or any(
                    isinstance(card, dict) and card.get("param") == "file" for card in candidate_cards
                )
                last_read = (read_results[-1].get("result") or {}) if read_results else {}
                need_more_read = bool(
                    discovery.get("content_ref")
                    and not (has_sqli or has_ssti or has_trav)
                    and (not read_results or (not last_read.get("eof") and isinstance(last_read.get("next_offset"), int)))
                )
                if not have_loop and len(bindings_map) == 1 and need_more_read:
                    next_offset = last_read.get("next_offset", 0) if read_results else 0
                    tool, args = READ_TOOL, {
                        "path": discovery["content_ref"]["path"], "offset": next_offset, "limit": 3000,
                    }
                elif not have_loop:
                    if has_trav:
                        tool, args = "hunter_run_web_loop", {
                            "target": target, "live": True, "crawl": False,
                            "fuzz_limit": 4, "candidate_sample_limit": 16,
                            "max_validations": 16, "sleep_s": 0.2,
                            "validation_profile": "readonly_traversal_application_files",
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


@pytest.mark.integration
def test_task4_offline_four_family_three_repeat_matrix(baseline, tmp_path_factory, monkeypatch):
    """4 holdout families x 3 repeats = 12 runs: 100% recall, 100% negative coverage, 0 FP, zero secret leakage."""
    monkeypatch.setenv("CCO_BENCHMARK_API_KEY", "test-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    work_root = tmp_path_factory.mktemp("sprint_a_matrix")
    observed_prompts: list[str] = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_matrix_provider(observed_prompts))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = _write_llm_config(work_root / "matrix-llm.json", f"http://127.0.0.1:{srv.server_port}/v1", "matrix-model")
        out_dir = work_root / "cohort-4x3"
        families = [
            "readonly-api-access-control",
            "readonly-sql-injection",
            "readonly-template-injection",
            "readonly-path-traversal",
        ]
        seeds = [2026040101, 2026040202, 2026040303, 2026040404]
        manifest_path, report = e6.run_cohort(
            "sprint-a-4x3-matrix",
            baseline=baseline,
            provider_config=cfg,
            output_dir=out_dir,
            families=families,
            seeds=seeds,
            repetitions=3,
            http_budget=180,
            token_budget=140_000,
            seconds_budget=240,
            execute=True,
        )
        assert Path(manifest_path).is_file()
        assert len(report["runs"]) == 12
        assert report["failed_run_rate"]["numerator"] == 0
        assert report["recall"] == {"numerator": 96, "denominator": 96, "value": 1.0}
        assert report["negative_coverage"] == {"numerator": 96, "denominator": 96, "value": 1.0}
        assert report["false_positives"]["numerator"] == 0

        for run in report["runs"]:
            assert run["closure_verified"] is True, run
            assert run["status"] == "python_finished_verified", run
            assert run["recall"]["value"] == 1.0, run
            assert run["negative_coverage"]["value"] == 1.0, run
            assert run["false_positives"]["numerator"] == 0, run

        # Re-audit directly from on-disk artifacts.
        run_manifest_paths = [run["evidence_refs"]["manifest"]["path"] for run in report["runs"]]
        audited = e6.audit_cohort(
            "sprint-a-4x3-audit",
            run_manifest_paths,
            experiment_manifest=out_dir / "experiment-manifest.json",
            readonly=True,
        )
        assert audited["failed_run_rate"]["numerator"] == 0
        assert audited["recall"]["value"] == 1.0
        assert audited["negative_coverage"]["value"] == 1.0

        # Private policy provisioned ONLY for traversal runs and never leaked to model prompts.
        trav_policies = 0
        for run in report["runs"]:
            launch_path = Path(run["evidence_refs"]["manifest"]["path"])
            launch_data = json.loads(launch_path.read_text(encoding="utf-8"))
            run_dir = launch_path.parent
            runtime_policy = json.loads((run_dir / "private/runtime-policy.json").read_text(encoding="utf-8"))
            assert runtime_policy.get("provider_calls", {}).get("access-3", 0) <= 14, run
            policy_files = list(run_dir.rglob("holdout-program-policy.json"))
            if run["family"] == "readonly-path-traversal":
                assert len(policy_files) == 1
                trav_policies += 1
                assert holdout.verify_run_scoped_policy(policy_files[0], launch_data["target"]) is True
                priv_data = json.loads(policy_files[0].read_text(encoding="utf-8"))
                for entry in priv_data.get("path_traversal", {}).get("files", []):
                    marker = entry.get("marker") or ""
                    if marker:
                        assert not any(marker in p for p in observed_prompts)
            else:
                assert policy_files == []
        assert trav_policies == 3
    finally:
        srv.shutdown()
        thread.join(timeout=5)
        srv.server_close()
