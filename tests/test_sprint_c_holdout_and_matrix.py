"""Sprint C Slice 3 tests: XSS + Open Redirect holdout fixture and offline E6 6-family matrix."""
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
from lab import readonly_xss_redirect_holdout
from test_full_agent_e6_benchmark import _fit_tool_args, _write_llm_config
from test_full_agent_python_solver import acceptance_evidence as acceptance_evidence, baseline as baseline
from test_sprint_b_post_holdout_and_matrix import _make_five_family_provider


def test_xss_redirect_family_excluded_from_runtime_and_wire_evidence_matches(tmp_path):
    for path in (
        "scripts/lab/readonly_xss_redirect_holdout.py",
        "scripts/full_agent_holdout.py",
        "tests/test_sprint_c_holdout_and_matrix.py",
    ):
        assert not preflight.runtime_file(Path(path))

    contract = holdout.private_policy_contract("readonly-xss-redirect")
    assert contract["requires_private_policy"] is False
    assert contract["public_policy_unchanged"] is True

    private = tmp_path / "private"
    private.mkdir()
    lab = holdout.start(holdout.selection("readonly-xss-redirect", 515151), private)
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{lab.server_port}/"
        _, base_policy = launcher.lab_policy(base)
        assert base_policy["xss_execution"]["enabled"] is True

        truth = lab.blind_state["truth"]
        assert len(truth) == 16
        assert sum(c["expected"] == "positive" for c in truth) == 8
        assert sum(c["expected"] == "negative" for c in truth) == 8
        assert sum(c["class"] == "xss_reflected" for c in truth) == 8
        assert sum(c["class"] == "open_redirect" for c in truth) == 8

        # Mutating HTTP methods are strictly rejected with 405.
        post_resp = requests.post(base, timeout=5)
        assert post_resp.status_code == 405

        # Safe local home route responds 200 on same origin.
        home_resp = requests.get(f"{base}home", timeout=5)
        assert home_resp.status_code == 200

        # Positive XSS case reflects unescaped HTML; negative XSS escapes or strips tags.
        pos_xss = next(c for c in truth if c["class"] == "xss_reflected" and c["expected"] == "positive")
        neg_xss_esc = next(c for c in truth if c["class"] == "xss_reflected" and c["negative_behavior"] == "html_escaped")
        neg_xss_strip = next(c for c in truth if c["class"] == "xss_reflected" and c["negative_behavior"] == "tag_stripped")

        r_pos_xss = requests.get(f"{base.rstrip('/')}{pos_xss['path']}", params={"q": "<svg onload=alert(1)>"}, timeout=5)
        assert r_pos_xss.status_code == 200 and "<svg onload=alert(1)>" in r_pos_xss.text

        r_neg_esc = requests.get(f"{base.rstrip('/')}{neg_xss_esc['path']}", params={"q": "<svg>"}, timeout=5)
        assert r_neg_esc.status_code == 200 and "<svg>" not in r_neg_esc.text and "&lt;svg&gt;" in r_neg_esc.text

        r_neg_strip = requests.get(f"{base.rstrip('/')}{neg_xss_strip['path']}", params={"q": "<svg>"}, timeout=5)
        assert r_neg_strip.status_code == 200 and "<svg>" not in r_neg_strip.text and "svg" in r_neg_strip.text

        # Positive Redirect case returns 302 Location to sentinel; negatives do not redirect externally.
        pos_redir = next(c for c in truth if c["class"] == "open_redirect" and c["expected"] == "positive")
        neg_redir_allow = next(c for c in truth if c["class"] == "open_redirect" and c["negative_behavior"] == "allowlisted_path")
        neg_redir_fixed = next(c for c in truth if c["class"] == "open_redirect" and c["negative_behavior"] == "fixed_local_redirect")

        r_pos_redir = requests.get(
            f"{base.rstrip('/')}{pos_redir['path']}",
            params={"next": "https://abc123.cco-validate.test/"},
            allow_redirects=False,
            timeout=5,
        )
        assert r_pos_redir.status_code == 302
        assert r_pos_redir.headers.get("Location") == "https://abc123.cco-validate.test/"

        r_neg_allow = requests.get(
            f"{base.rstrip('/')}{neg_redir_allow['path']}",
            params={"next": "https://abc123.cco-validate.test/"},
            allow_redirects=False,
            timeout=5,
        )
        assert r_neg_allow.status_code == 400 and not r_neg_allow.headers.get("Location")

        r_neg_fixed = requests.get(
            f"{base.rstrip('/')}{neg_redir_fixed['path']}",
            params={"next": "https://abc123.cco-validate.test/"},
            allow_redirects=False,
            timeout=5,
        )
        assert r_neg_fixed.status_code == 200 and not r_neg_fixed.headers.get("Location")

        # Evaluator rejects CONFIRMED XSS without browser_execution oracle.
        err, seqs = readonly_xss_redirect_holdout.evidence_matches(
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
        assert err == "XSS holdout confirmation requires browser_execution oracle" and seqs == []
    finally:
        lab.shutdown()
        thread.join(timeout=5)
        lab.server_close()


def _make_six_family_provider(observed_prompts: list[str]):
    base_provider = _make_five_family_provider(observed_prompts)

    class Provider(base_provider):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            raw_body = self.rfile.read(length).decode("utf-8")
            body = json.loads(raw_body)
            context = json.loads(body["messages"][1]["content"])
            spec = context["task_spec"]
            allowed = {row["function"]["name"] for row in body.get("tools", [])}
            cards = context.get("candidate_cards") or []
            has_xss_or_redirect_cards = any(
                isinstance(c, dict) and c.get("vector") in {"xss-stored", "authn-session"}
                for c in cards
            )

            if (
                allowed != {SUMMARY_TOOL}
                and spec["phase"] == "access"
                and has_xss_or_redirect_cards
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
def test_sprint_c_offline_six_family_e6_matrix_with_xss_and_open_redirect(baseline, tmp_path_factory, monkeypatch):
    """Run offline 6-family E6 cohort (4 Sprint A GET + Sprint B POST + Sprint C XSS/Redirect)."""
    monkeypatch.setenv("CCO_BENCHMARK_API_KEY", "test-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    work_root = tmp_path_factory.mktemp("sprint_c_matrix")
    observed_prompts: list[str] = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_six_family_provider(observed_prompts))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = _write_llm_config(work_root / "matrix-llm.json", f"http://127.0.0.1:{srv.server_port}/v1", "matrix-model")
        out_dir = work_root / "cohort-6fam"
        families = [
            "readonly-api-access-control",
            "readonly-sql-injection",
            "readonly-template-injection",
            "readonly-path-traversal",
            "post-carrier-injection",
            "readonly-xss-redirect",
        ]
        seeds = [2026040101, 2026040202, 2026040303, 2026040404, 424242, 515151]
        manifest_path, report = e6.run_cohort(
            "sprint-c-6fam-matrix",
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
        assert len(report["runs"]) == 6
        assert report["failed_run_rate"]["numerator"] == 0
        # 6 * 8 = 48 positives, 48 negatives
        assert report["recall"] == {"numerator": 48, "denominator": 48, "value": 1.0}
        assert report["negative_coverage"] == {"numerator": 48, "denominator": 48, "value": 1.0}
        assert report["false_positives"]["numerator"] == 0

        xr_run = next(r for r in report["runs"] if r["family"] == "readonly-xss-redirect")
        assert xr_run["closure_verified"] is True
        assert xr_run["recall"] == {"numerator": 8, "denominator": 8, "value": 1.0}
        assert xr_run["negative_coverage"] == {"numerator": 8, "denominator": 8, "value": 1.0}
        assert xr_run["false_positives"]["numerator"] == 0

        # Re-audit directly from on-disk artifacts.
        run_manifest_paths = [run["evidence_refs"]["manifest"]["path"] for run in report["runs"]]
        audited = e6.audit_cohort(
            "sprint-c-6fam-audit",
            run_manifest_paths,
            experiment_manifest=out_dir / "experiment-manifest.json",
            readonly=True,
        )
        assert audited["failed_run_rate"]["numerator"] == 0
        assert audited["recall"] == {"numerator": 48, "denominator": 48, "value": 1.0}
        assert audited["negative_coverage"] == {"numerator": 48, "denominator": 48, "value": 1.0}
        assert audited["false_positives"]["numerator"] == 0
    finally:
        srv.shutdown()
        thread.join(timeout=5)
        srv.server_close()
