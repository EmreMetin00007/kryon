"""Sprint B Slice 4 tests: POST carrier holdout fixture and offline E6 5-family matrix."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

import pytest

import full_agent_e6_benchmark as e6
import full_agent_holdout as holdout
import full_agent_launcher as launcher
import full_agent_preflight as preflight
from full_agent_python_broker import SUMMARY_TOOL
from test_full_agent_e6_benchmark import _fit_tool_args, _write_llm_config
from test_full_agent_python_solver import acceptance_evidence as acceptance_evidence, baseline as baseline
from test_sprint_a_four_family_matrix import _make_matrix_provider


def test_post_carrier_family_excluded_from_runtime_and_private_policy_isolated(tmp_path):
    for path in (
        "scripts/lab/post_carrier_holdout.py",
        "scripts/full_agent_holdout.py",
        "tests/test_sprint_b_post_holdout_and_matrix.py",
    ):
        assert not preflight.runtime_file(Path(path))

    contract = holdout.private_policy_contract("post-carrier-injection")
    assert contract["requires_private_policy"] is True
    assert contract["policy_section"] == "readonly_operations"
    assert contract["public_policy_unchanged"] is True

    private = tmp_path / "private"
    home = tmp_path / "home"
    private.mkdir()
    home.mkdir()
    lab = holdout.start(holdout.selection("post-carrier-injection", 424242), private)
    try:
        base = f"http://127.0.0.1:{lab.server_port}/"
        _, base_policy = launcher.lab_policy(base)
        assert "readonly_operations" not in base_policy
        prov = holdout.provision_private_policy(
            family="post-carrier-injection",
            lab=lab,
            base=base,
            home=home,
            private=private,
            base_policy=base_policy,
        )
        assert prov["provisioned"] is True
        assert prov["declarations_validated"] == 16
        policy_path = Path(prov["policy_file"])
        assert holdout.verify_run_scoped_policy(policy_path, base) is True
        assert holdout.verify_run_scoped_policy(policy_path, "http://127.0.0.1:9999/") is False
        # Public lab policy remains unchanged.
        assert "readonly_operations" not in launcher.lab_policy(base)[1]
    finally:
        lab.server_close()


def _make_five_family_provider(observed_prompts: list[str]):
    base_provider = _make_matrix_provider(observed_prompts)

    class Provider(base_provider):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            raw_body = self.rfile.read(length).decode("utf-8")
            body = json.loads(raw_body)
            context = json.loads(body["messages"][1]["content"])
            spec = context["task_spec"]
            results = context.get("recent_results", [])
            allowed = {row["function"]["name"] for row in body.get("tools", [])}
            target = spec["target"]
            cards = context.get("candidate_cards") or []
            has_post_cards = any(isinstance(c, dict) and c.get("method") == "POST" for c in cards)
            is_post_surface = (
                has_post_cards
                or "POST Surface" in json.dumps(results)
                or any(isinstance(r, dict) and "/lookup/" in json.dumps(r) for r in results)
            )

            if (
                allowed != {SUMMARY_TOOL}
                and spec["phase"] == "enum"
                and not results
                and "kali-tools_curl_request" in allowed
                and "kali-tools_crawl_web_surface" not in allowed
            ):
                observed_prompts.append(raw_body)
                fitted = _fit_tool_args(body, "kali-tools_curl_request", {"url": target})
                payload = {
                    "choices": [{"message": {"tool_calls": [{
                        "function": {"name": "kali-tools_curl_request", "arguments": json.dumps(fitted)}
                    }]}}],
                    "usage": {"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200},
                }
                raw = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return

            if (
                allowed != {SUMMARY_TOOL}
                and spec["phase"] == "access"
                and has_post_cards
                and is_post_surface
            ):
                # Trigger host dispatch_access_validation for all eligible POST form/json candidates.
                observed_prompts.append(raw_body)
                summary_args = {
                    "status": "partial",
                    "next": "Broader coverage remains NOT TESTED.",
                    "steps": [{"id": step["id"], "status": "done"}
                              for step in spec["steps"] if not step["host_managed"]],
                }
                fitted = _fit_tool_args(body, SUMMARY_TOOL, summary_args)
                payload = {
                    "choices": [{"message": {"tool_calls": [{
                        "function": {"name": SUMMARY_TOOL, "arguments": json.dumps(fitted)}
                    }]}}],
                    "usage": {"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200},
                }
                raw = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return

            # For enum-2 on post-carrier-injection, fetch target anonymously with curl_request
            # once crawl isn't needed or if curl_request yields POST surface links, let host continuation crawl.
            self.rfile_read_override = raw_body
            # Replay raw_body to base handler by wrapping rfile.
            import io
            self.headers["Content-Length"] = str(len(raw_body.encode("utf-8")))
            self.rfile = io.BytesIO(raw_body.encode("utf-8"))
            return super().do_POST()

    return Provider


@pytest.mark.integration
def test_sprint_b_offline_five_family_e6_matrix_with_post_carriers(baseline, tmp_path_factory, monkeypatch):
    """Run offline 5-family E6 cohort (4 Sprint A GET families + POST form/json family)."""
    monkeypatch.setenv("CCO_BENCHMARK_API_KEY", "test-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    work_root = tmp_path_factory.mktemp("sprint_b_matrix")
    observed_prompts: list[str] = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_five_family_provider(observed_prompts))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = _write_llm_config(work_root / "matrix-llm.json", f"http://127.0.0.1:{srv.server_port}/v1", "matrix-model")
        out_dir = work_root / "cohort-5fam"
        families = [
            "readonly-api-access-control",
            "readonly-sql-injection",
            "readonly-template-injection",
            "readonly-path-traversal",
            "post-carrier-injection",
        ]
        seeds = [2026040101, 2026040202, 2026040303, 2026040404, 424242]
        manifest_path, report = e6.run_cohort(
            "sprint-b-5fam-matrix",
            baseline=baseline,
            provider_config=cfg,
            output_dir=out_dir,
            families=families,
            seeds=seeds,
            repetitions=1,
            http_budget=180,
            token_budget=140_000,
            seconds_budget=240,
            execute=True,
        )
        assert Path(manifest_path).is_file()
        assert len(report["runs"]) == 5
        assert report["failed_run_rate"]["numerator"] == 0
        # 4 * 8 + 8 = 40 positives, 40 negatives
        assert report["recall"] == {"numerator": 40, "denominator": 40, "value": 1.0}
        assert report["negative_coverage"] == {"numerator": 40, "denominator": 40, "value": 1.0}
        assert report["false_positives"]["numerator"] == 0

        post_run = next(r for r in report["runs"] if r["family"] == "post-carrier-injection")
        assert post_run["closure_verified"] is True
        assert post_run["recall"]["value"] == 1.0
        assert post_run["negative_coverage"]["value"] == 1.0
        assert post_run["false_positives"]["numerator"] == 0

        # Re-audit directly from on-disk artifacts.
        run_manifest_paths = [run["evidence_refs"]["manifest"]["path"] for run in report["runs"]]
        audited = e6.audit_cohort(
            "sprint-b-5fam-audit",
            run_manifest_paths,
            experiment_manifest=out_dir / "experiment-manifest.json",
            readonly=True,
        )
        assert audited["failed_run_rate"]["numerator"] == 0
        assert audited["recall"] == {"numerator": 40, "denominator": 40, "value": 1.0}
        assert audited["negative_coverage"] == {"numerator": 40, "denominator": 40, "value": 1.0}

        # Verify private policy isolation for post-carrier-injection and no secret/marker leakage.
        post_manifest = Path(post_run["evidence_refs"]["manifest"]["path"])
        post_launch = json.loads(post_manifest.read_text(encoding="utf-8"))
        post_run_dir = post_manifest.parent
        policy_files = list(post_run_dir.rglob("holdout-program-policy.json"))
        assert len(policy_files) == 1
        assert holdout.verify_run_scoped_policy(policy_files[0], post_launch["target"]) is True
        assert not any("op-post-form-" in p or "op-post-json-" in p for p in observed_prompts)
    finally:
        srv.shutdown()
        thread.join(timeout=5)
        srv.server_close()
