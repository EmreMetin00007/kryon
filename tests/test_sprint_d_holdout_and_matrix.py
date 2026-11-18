"""Sprint D Slice 3 tests: SPA + Stateful Business Logic holdout fixture and 7-family offline E6 matrix."""
from __future__ import annotations

from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import threading

import pytest
import requests

import full_agent_e6_benchmark as e6
import full_agent_holdout as holdout
import full_agent_launcher as launcher
import full_agent_preflight as preflight
from full_agent_python_broker import SUMMARY_TOOL
from lab import spa_business_holdout
from test_full_agent_e6_benchmark import _fit_tool_args, _write_llm_config
from test_full_agent_python_solver import acceptance_evidence as acceptance_evidence, baseline as baseline
from test_sprint_c_holdout_and_matrix import _make_six_family_provider


def test_spa_business_family_excluded_from_runtime_private_policy_and_evidence_matches(tmp_path):
    for path in (
        "scripts/lab/spa_business_holdout.py",
        "scripts/full_agent_holdout.py",
        "tests/test_sprint_d_holdout_and_matrix.py",
    ):
        assert not preflight.runtime_file(Path(path))

    contract = holdout.private_policy_contract("spa-business-logic")
    assert contract["requires_private_policy"] is True
    assert contract["policy_section"] == "business_logic_operations"
    assert contract["public_policy_unchanged"] is True

    private = tmp_path / "private"
    home = private / "state"
    private.mkdir()
    home.mkdir()
    lab = holdout.start(holdout.selection("spa-business-logic", 616161), private)
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{lab.server_port}/"
        _, base_policy = launcher.lab_policy(base)
        assert "business_logic_operations" not in base_policy
        prov = holdout.provision_private_policy(
            family="spa-business-logic",
            lab=lab,
            base=base,
            home=home,
            private=private,
            base_policy=base_policy,
        )
        assert prov["provisioned"] is True
        assert prov["declarations_validated"] == 8
        assert holdout.verify_run_scoped_policy(Path(prov["policy_file"]), base) is True
        policy_data = json.loads(Path(prov["policy_file"]).read_text(encoding="utf-8"))
        declared_urls = {row["url"] for row in policy_data["business_logic_operations"]}
        assert f"{base.rstrip('/')}/biz/decoy/unauthorized" not in declared_urls

        # Pure SPA shell at / contains no <a href> API links in HTML; only JS bundle reference.
        home_resp = requests.get(base, timeout=5)
        assert home_resp.status_code == 200
        assert "<a " not in home_resp.text
        assert "/assets/app." in home_resp.text

        truth = lab.blind_state["truth"]
        assert len(truth) == 16
        assert sum(c["expected"] == "positive" for c in truth) == 8
        assert sum(c["expected"] == "negative" for c in truth) == 8
        assert sum(c["class"] == "xss_reflected" for c in truth) == 8
        assert sum(c["class"] == "business_logic" for c in truth) == 8

        # Evaluator rejects CONFIRMED XSS without browser_execution and rejects business logic without normal control.
        pos_xss = next(c for c in truth if c["class"] == "xss_reflected" and c["expected"] == "positive")
        err_xss, seqs_xss = spa_business_holdout.evidence_matches(
            pos_xss,
            {
                "verdict": "CONFIRMED",
                "oracle": "unescaped_reflection",
                "execution_context": {"vuln_class": "xss_reflected", "param": "q", "method": "GET", "carrier": "query"},
                "request_evidence": [],
            },
            lab.blind_state["wire"],
            base,
        )
        assert err_xss == "XSS holdout confirmation requires browser_execution oracle" and seqs_xss == []

        pos_biz = next(c for c in truth if c["class"] == "business_logic" and c["expected"] == "positive")
        err_biz, seqs_biz = spa_business_holdout.evidence_matches(
            pos_biz,
            {
                "verdict": "CONFIRMED",
                "oracle": "business_logic",
                "execution_context": {
                    "vuln_class": "business_logic",
                    "method": pos_biz["method"],
                    "carrier": "json",
                },
                "request_evidence": [],
            },
            lab.blind_state["wire"],
            base,
        )
        assert err_biz == "missing stateful business logic control/probe wire steps" and seqs_biz == []
    finally:
        lab.shutdown()
        thread.join(timeout=5)
        lab.server_close()


def _make_seven_family_provider(observed_prompts: list[str]):
    base_provider = _make_six_family_provider(observed_prompts)

    class Provider(base_provider):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            raw_body = self.rfile.read(length).decode("utf-8")
            body = json.loads(raw_body)
            context = json.loads(body["messages"][1]["content"])
            spec = context["task_spec"]
            allowed = {row["function"]["name"] for row in body.get("tools", [])}
            cards = context.get("candidate_cards") or []
            has_biz_cards = any(
                isinstance(c, dict) and c.get("vector") == "race-business"
                for c in cards
            )

            if (
                allowed != {SUMMARY_TOOL}
                and spec["phase"] == "access"
                and has_biz_cards
            ):
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

            import io
            self.headers["Content-Length"] = str(len(raw_body.encode("utf-8")))
            self.rfile = io.BytesIO(raw_body.encode("utf-8"))
            return super().do_POST()

    return Provider


@pytest.mark.integration
def test_sprint_d_offline_seven_family_e6_matrix_with_spa_and_business_logic(baseline, tmp_path_factory, monkeypatch):
    """Run offline 7-family E6 cohort (4 Sprint A GET + Sprint B POST + Sprint C XSS/Redirect + Sprint D SPA/Business)."""
    monkeypatch.setenv("CCO_BENCHMARK_API_KEY", "test-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    work_root = tmp_path_factory.mktemp("sprint_d_matrix")
    observed_prompts: list[str] = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_seven_family_provider(observed_prompts))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = _write_llm_config(work_root / "matrix-llm.json", f"http://127.0.0.1:{srv.server_port}/v1", "matrix-model")
        out_dir = work_root / "cohort-7fam"
        families = [
            "readonly-api-access-control",
            "readonly-sql-injection",
            "readonly-template-injection",
            "readonly-path-traversal",
            "post-carrier-injection",
            "readonly-xss-redirect",
            "spa-business-logic",
        ]
        seeds = [2026040101, 2026040202, 2026040303, 2026040404, 424242, 515151, 616161]
        manifest_path, report = e6.run_cohort(
            "sprint-d-7fam-matrix",
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
        assert len(report["runs"]) == 7
        assert report["failed_run_rate"]["numerator"] == 0
        # 7 * 8 = 56 positives, 56 negatives
        assert report["recall"] == {"numerator": 56, "denominator": 56, "value": 1.0}
        assert report["negative_coverage"] == {"numerator": 56, "denominator": 56, "value": 1.0}
        assert report["false_positives"]["numerator"] == 0

        sb_run = next(r for r in report["runs"] if r["family"] == "spa-business-logic")
        assert sb_run["closure_verified"] is True
        sb_metrics = json.loads(
            (Path(sb_run["evidence_refs"]["manifest"]["path"]).parent / "private/evaluator/metrics.json").read_text(
                encoding="utf-8"
            )
        )
        assert sb_metrics["accounting_matches"] is True
        assert sb_run["recall"] == {"numerator": 8, "denominator": 8, "value": 1.0}
        assert sb_run["negative_coverage"] == {"numerator": 8, "denominator": 8, "value": 1.0}
        assert sb_run["false_positives"]["numerator"] == 0
        assert "spa_and_declared_business_logic" in sb_run["not_tested"]["untested_dimensions"]
        assert "out_of_band_only" in sb_run["not_tested"]["untested_dimensions"]

        # Re-audit directly from on-disk artifacts.
        run_manifest_paths = [run["evidence_refs"]["manifest"]["path"] for run in report["runs"]]
        audited = e6.audit_cohort(
            "sprint-d-7fam-audit",
            run_manifest_paths,
            experiment_manifest=out_dir / "experiment-manifest.json",
            readonly=True,
        )
        assert audited["failed_run_rate"]["numerator"] == 0
        assert audited["recall"] == {"numerator": 56, "denominator": 56, "value": 1.0}
        assert audited["negative_coverage"] == {"numerator": 56, "denominator": 56, "value": 1.0}
        assert audited["false_positives"]["numerator"] == 0
    finally:
        srv.shutdown()
        thread.join(timeout=5)
        srv.server_close()
