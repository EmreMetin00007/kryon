"""Offline frozen paired regressions for E6 multi-seed/repetition experiments."""
from __future__ import annotations

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading

import pytest

import agent_cli
import full_agent_e6_benchmark as e6
import full_agent_holdout as holdout
import full_agent_launcher as launcher
from full_agent_provider import dump
from full_agent_python_broker import READ_TOOL, SUMMARY_TOOL
from test_full_agent_e6_benchmark import _make_fake_provider, _write_llm_config
from test_full_agent_python_solver import acceptance_evidence as acceptance_evidence, baseline as baseline


def _work_dir(tmp_path: Path, name: str) -> Path:
    root = Path(os.environ.get("CCO_WORKDIR", str(tmp_path.parent))).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=f"{name}-", dir=str(root)))


def _build_offline_cohort(
    *,
    work_dir: Path,
    label: str,
    baseline_dir: Path,
    provider_config: Path,
    seeds: dict[str, list[int]],
    repetitions: int = 1,
    http_budget: int = 250,
    token_budget: int = 150000,
    seconds_budget: int = 900,
    treatment: dict | None = None,
    acceptance_criteria: dict | None = None,
    cost_by_unit: dict[str, float | None] | None = None,
    valid_tokens_by_unit: dict[str, bool] | None = None,
    funnel_by_unit: dict[str, dict | None] | None = None,
    stop_reason: str = "protocol_repair_exhausted",
) -> tuple[Path, dict, Path]:
    """Create a real prepared cohort and offline-auditable run directories without network traffic."""
    plan_path, plan = e6.prepare_cohort(
        label,
        baseline=baseline_dir,
        provider_config=provider_config,
        output_dir=work_dir,
        seeds=seeds,
        repetitions=repetitions,
        http_budget=http_budget,
        token_budget=token_budget,
        seconds_budget=seconds_budget,
        treatment=treatment,
        acceptance_criteria=acceptance_criteria,
    )
    exp_manifest_path = Path(plan["experiment_manifest"])
    exp_manifest = json.loads(exp_manifest_path.read_text(encoding="utf-8"))
    runs_dir = work_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    manifest_paths: list[Path] = []
    unit_runs: list[dict] = []
    for idx, unit in enumerate(exp_manifest["units"]):
        exp_id = unit["experiment_id"]
        run_dir = runs_dir / f"unit-{idx:02d}"
        private = run_dir / "private"
        solver = run_dir / "solver"
        summaries = solver / "summaries"
        private.mkdir(parents=True)
        summaries.mkdir(parents=True)

        selected = holdout.selection(unit["family"], unit["seed"])
        lab = holdout.start(selected, private)
        try:
            dump(private / "evaluator/wire.json", [])
        finally:
            lab.server_close()
            if lab.blind_state.get("db") is not None:
                lab.blind_state["db"].close()
            if lab.blind_state.get("fixtures") is not None:
                lab.blind_state["fixtures"].cleanup()

        tokens_valid = True if valid_tokens_by_unit is None else valid_tokens_by_unit.get(exp_id, True)
        dump(private / "budget.json", {
            "limits": {"http": http_budget, "tokens": token_budget},
            "used": {"http": 4, "tokens": 600},
            "events": [
                {
                    "kind": "tokens",
                    "reserved": 800,
                    "charged": 600,
                    "measurement_valid": tokens_valid,
                    "usage": {"prompt_tokens": 400, "completion_tokens": 200, "total_tokens": 600},
                }
            ],
        })
        if funnel_by_unit and exp_id in funnel_by_unit and funnel_by_unit[exp_id] is not None:
            dump(summaries / "access-3.json", {
                "phase": "access",
                "status": "partial",
                "validation_funnel": funnel_by_unit[exp_id],
            })

        cost_val = None if cost_by_unit is None else cost_by_unit.get(exp_id)
        launch = {
            "schema": launcher.SCHEMA,
            "status": "launch_failed",
            "stop_reason": stop_reason,
            "seed": unit["seed"],
            "preflight": unit["preflight"],
            "models": plan["models"],
            "llm_cost_usd": cost_val,
            "llm_calls": 2,
            "target_requests": 0,
            "wall_clock_seconds": 1.5,
            "solver_mode": "python_loop",
            "provider_kind": plan["provider_kind"],
            "effective_limits": plan["ceilings"],
            "target": "http://127.0.0.1:1/",
        }
        launch_path = run_dir / "launch.json"
        dump(launch_path, launch)
        manifest_paths.append(launch_path)
        unit_runs.append({
            "experiment_id": exp_id,
            "family": unit["family"],
            "seed": unit["seed"],
            "repetition": unit["repetition"],
            "manifest": str(launch_path),
            "manifest_sha256": holdout.digest(launch_path),
        })

    dump(work_dir / "unit-runs.json", {"schema": "full-agent-e6-unit-runs/1", "units": unit_runs})
    report = e6.audit_cohort(
        label,
        manifest_paths,
        expected_ceilings=plan["ceilings"],
        experiment_manifest=exp_manifest_path,
        unit_runs=unit_runs,
    )
    report_path = work_dir / "cohort-report.json"
    dump(report_path, report)
    return report_path, report, exp_manifest_path


def test_multi_seed_and_repetition_suite_preserves_one_seed_compat(baseline, tmp_path):
    # Preserve existing 1-seed defaults, dict, and list compatibility.
    default_suite = e6.validate_suite()
    assert len(default_suite["selections"]) == 3
    assert len(default_suite["units"]) == 3
    assert default_suite["repetitions"] == 1

    one_seed_dict = e6.validate_suite(seeds={
        "readonly-api-access-control": 101,
        "readonly-sql-injection": 202,
        "readonly-template-injection": 303,
    })
    assert one_seed_dict["seeds_by_family"] == {
        "readonly-api-access-control": [101],
        "readonly-sql-injection": [202],
        "readonly-template-injection": [303],
    }

    one_seed_list = e6.validate_suite(seeds=[101, 202, 303])
    assert one_seed_list["seeds_by_family"] == one_seed_dict["seeds_by_family"]

    # Multiple seeds per family + repetitions produce explicit family x seed x repetition identities.
    multi = e6.validate_suite(
        seeds={
            "readonly-api-access-control": [314159, 654321],
            "readonly-sql-injection": [271828, 828172],
            "readonly-template-injection": [141421, 124141],
        },
        repetitions=2,
    )
    assert len(multi["selections"]) == 6
    assert len(multi["units"]) == 12
    assert len({u["experiment_id"] for u in multi["units"]}) == 12
    assert multi["units"][0]["experiment_id"] == "readonly-api-access-control:314159:rep1"
    assert multi["units"][1]["experiment_id"] == "readonly-api-access-control:314159:rep2"

    # Reject duplicate seeds within a family, invalid repetitions, and invalid treatment dimensions.
    with pytest.raises(ValueError, match="duplicate seed"):
        e6.validate_suite(seeds={
            "readonly-api-access-control": [314159, 314159],
            "readonly-sql-injection": [271828],
            "readonly-template-injection": [141421],
        })
    with pytest.raises(ValueError, match="repetitions"):
        e6.validate_suite(repetitions=0)
    with pytest.raises(ValueError, match="unsupported treatment dimension"):
        e6.normalize_treatment({"name": "bad", "changed_dimensions": ["evaluator"]})

    # Verify CLI benchmark plan freezes multi-seed experiment-manifest.json with 0 LLM/HTTP calls.
    work = _work_dir(tmp_path, "plan-multi")
    cfg = _write_llm_config(work / "llm.json", "http://127.0.0.1:1/v1", "test-model")
    out_dir = work / "plan-out"
    assert agent_cli.main([
        "benchmark", "plan",
        "--label", "multi-plan",
        "--baseline", str(baseline),
        "--provider-config", str(cfg),
        "--output-dir", str(out_dir),
        "--seeds", "readonly-api-access-control=314159,654321",
        "--seeds", "readonly-sql-injection=271828,828172",
        "--seeds", "readonly-template-injection=141421,124141",
        "--repetitions", "2",
        "--treatment-name", "candidate-prompt",
        "--treatment-role", "treatment",
        "--treatment-diff", "prompt_catalog",
        "--min-overall-recall", "0.75",
    ]) == 0
    plan = json.loads((out_dir / "suite-plan.json").read_text(encoding="utf-8"))
    exp = json.loads((out_dir / "experiment-manifest.json").read_text(encoding="utf-8"))
    assert plan["executed"] is False and plan["llm_calls"] == 0 and plan["target_requests"] == 0
    assert len(plan["runs"]) == 12
    assert exp["schema"] == e6.SCHEMA_EXPERIMENT_MANIFEST
    assert exp["repetitions"] == 2
    assert exp["acceptance_criteria"]["overall_recall"] == 0.75
    assert exp["treatment"]["changed_dimensions"] == ["prompt_catalog"]
    assert set(exp["fingerprints"]) == {"runtime", "evaluator", "prompt_catalog", "provider_config"}


def test_multi_seed_repetition_failed_denominators_unknown_costs_and_funnel_aggregation(baseline, tmp_path):
    work = _work_dir(tmp_path, "multi-funnel")
    cfg = _write_llm_config(work / "llm.json", "http://127.0.0.1:1/v1", "shared-model")
    seeds = {
        "readonly-api-access-control": [314159, 654321],
        "readonly-sql-injection": [271828, 828172],
        "readonly-template-injection": [141421, 124141],
    }
    funnel_before = {
        f"{fam}:{seed}:rep{rep}": {
            "observed": 10, "eligible": 6, "admitted": 4, "executed": 2, "evidence_accepted": 0,
        }
        for fam, fam_seeds in seeds.items()
        for seed in fam_seeds
        for rep in (1, 2)
    }
    funnel_after = {
        f"{fam}:{seed}:rep{rep}": {
            "observed": 10, "eligible": 8, "admitted": 6, "executed": 5, "evidence_accepted": 3,
        }
        for fam, fam_seeds in seeds.items()
        for seed in fam_seeds
        for rep in (1, 2)
    }
    # One run has known cost (0.01), others unknown (None) -> total cost MUST remain None.
    costs = {"readonly-api-access-control:314159:rep1": 0.01}
    # One run has invalid token measurement -> cohort tokens_used MUST remain None.
    valid_tokens = {"readonly-sql-injection:271828:rep2": False}

    before_path, before_report, _ = _build_offline_cohort(
        work_dir=work / "before",
        label="paired-before",
        baseline_dir=baseline,
        provider_config=cfg,
        seeds=seeds,
        repetitions=2,
        cost_by_unit=costs,
        valid_tokens_by_unit=valid_tokens,
        funnel_by_unit=funnel_before,
    )
    after_path, after_report, _ = _build_offline_cohort(
        work_dir=work / "after",
        label="paired-after",
        baseline_dir=baseline,
        provider_config=cfg,
        seeds=seeds,
        repetitions=2,
        funnel_by_unit=funnel_after,
    )

    # Failed runs retain all 12 * 8 = 96 positive and 96 negative denominators.
    assert before_report["positives"] == 96 and before_report["negatives"] == 96
    assert before_report["recall"] == {"numerator": 0, "denominator": 96, "value": 0.0}
    assert before_report["failed_run_rate"] == {"numerator": 12, "denominator": 12, "value": 1.0}
    assert before_report["usage"]["cost_usd"] is None
    assert before_report["usage"]["cost_complete"] is False
    assert before_report["usage"]["unknown_cost_is_zero"] is False
    assert before_report["usage"]["tokens_used"] is None

    # Funnel aggregated cleanly across 12 units (observed=120, etc.).
    assert before_report["funnel"]["observed"] == 120
    assert before_report["funnel"]["executed"] == 24
    assert after_report["funnel"]["executed"] == 60
    assert after_report["funnel"]["evidence_accepted"] == 36
    assert after_report["funnel"]["rates"]["end_to_end_yield"] == pytest.approx(36 / 120)

    comparison = e6.compare_cohorts(before_path, after_path)
    assert comparison["strict_paired"] is True
    assert comparison["paired_units_count"] == 12
    assert comparison["funnel"]["deltas"]["executed"] == 36
    assert comparison["funnel"]["deltas"]["evidence_accepted"] == 36
    assert comparison["deltas"]["cost_usd"] is None

    # If any run is missing funnel data, aggregate funnel stages remain unknown (None, never zero).
    partial_funnel = dict(funnel_after)
    partial_funnel["readonly-api-access-control:314159:rep1"] = None
    partial_path, partial_report, _ = _build_offline_cohort(
        work_dir=work / "partial-funnel",
        label="partial-funnel",
        baseline_dir=baseline,
        provider_config=cfg,
        seeds=seeds,
        repetitions=2,
        funnel_by_unit=partial_funnel,
    )
    assert partial_report["funnel"]["observed"] is None
    assert partial_report["funnel"]["runs_with_funnel"] == 11
    assert partial_report["funnel"]["runs_total"] == 12


def test_strict_comparison_rejects_tamper_and_unverifiable_reports(baseline, tmp_path):
    work = _work_dir(tmp_path, "tamper")
    cfg = _write_llm_config(work / "llm.json", "http://127.0.0.1:1/v1", "shared-model")
    seeds = {
        "readonly-api-access-control": [314159, 654321],
        "readonly-sql-injection": [271828, 828172],
        "readonly-template-injection": [141421, 124141],
    }
    before_path, before_report, _ = _build_offline_cohort(
        work_dir=work / "before", label="b", baseline_dir=baseline, provider_config=cfg, seeds=seeds, repetitions=2,
    )
    after_path, after_report, after_exp_path = _build_offline_cohort(
        work_dir=work / "after", label="a", baseline_dir=baseline, provider_config=cfg, seeds=seeds, repetitions=2,
    )
    assert e6.compare_cohorts(before_path, after_path)["strict_paired"] is True

    # 1. Tamper cohort-report.json directly -> report_digest fails.
    tampered_report = copy.deepcopy(after_report)
    tampered_report["recall"]["numerator"] = 48
    tampered_path = work / "tampered-report.json"
    dump(tampered_path, tampered_report)
    with pytest.raises(ValueError, match="digest mismatch"):
        e6.compare_cohorts(before_path, tampered_path)

    # 2. Tamper cohort-report.json AND forge report_digest -> underlying re-audit rejects!
    forged = {k: v for k, v in tampered_report.items() if k != "report_digest"}
    forged["report_digest"] = e6._canonical_sha256(forged)
    dump(tampered_path, forged)
    with pytest.raises(ValueError, match="does not match re-audited"):
        e6.compare_cohorts(before_path, tampered_path)

    # 3. Missing provenance / unverified dict rejected.
    unverifiable = copy.deepcopy(after_report)
    unverifiable["provenance"]["mode"] = "manual"
    with pytest.raises(ValueError, match="unverifiable or legacy"):
        e6.compare_cohorts(before_path, unverifiable)

    # 4. Tamper underlying experiment-manifest.json on disk -> rejected!
    exp_backup = after_exp_path.read_text(encoding="utf-8")
    try:
        exp_obj = json.loads(exp_backup)
        exp_obj["label"] = "tampered-label"
        dump(after_exp_path, exp_obj)
        with pytest.raises(ValueError, match="digest mismatch"):
            e6.compare_cohorts(before_path, after_path)
    finally:
        after_exp_path.write_text(exp_backup, encoding="utf-8")

    # 5. Tamper underlying evaluator lab-source.py -> rejected!
    lab_src = Path(after_report["runs"][0]["evidence_refs"]["manifest"]["path"]).parent / "private/evaluator/lab-source.py"
    orig_lab = lab_src.read_bytes()
    try:
        lab_src.write_text("# tampered", encoding="utf-8")
        with pytest.raises(ValueError, match="lab source changed"):
            e6.compare_cohorts(before_path, after_path)
    finally:
        lab_src.write_bytes(orig_lab)


def test_strict_comparison_rejects_unpaired_seeds_repetitions_ceilings_denominators(baseline, tmp_path):
    work = _work_dir(tmp_path, "unpaired")
    cfg = _write_llm_config(work / "llm.json", "http://127.0.0.1:1/v1", "shared-model")
    seeds_a = {
        "readonly-api-access-control": [314159, 654321],
        "readonly-sql-injection": [271828, 828172],
        "readonly-template-injection": [141421, 124141],
    }
    seeds_diff = {
        "readonly-api-access-control": [314159, 999999],
        "readonly-sql-injection": [271828, 828172],
        "readonly-template-injection": [141421, 124141],
    }
    base_path, _, _ = _build_offline_cohort(
        work_dir=work / "base", label="base", baseline_dir=baseline, provider_config=cfg,
        seeds=seeds_a, repetitions=2,
    )
    diff_seed_path, _, _ = _build_offline_cohort(
        work_dir=work / "diff-seed", label="diff-seed", baseline_dir=baseline, provider_config=cfg,
        seeds=seeds_diff, repetitions=2,
    )
    diff_rep_path, _, _ = _build_offline_cohort(
        work_dir=work / "diff-rep", label="diff-rep", baseline_dir=baseline, provider_config=cfg,
        seeds=seeds_a, repetitions=1,
    )
    diff_cap_path, _, _ = _build_offline_cohort(
        work_dir=work / "diff-cap", label="diff-cap", baseline_dir=baseline, provider_config=cfg,
        seeds=seeds_a, repetitions=2, http_budget=200,
    )
    diff_acc_path, _, _ = _build_offline_cohort(
        work_dir=work / "diff-acc", label="diff-acc", baseline_dir=baseline, provider_config=cfg,
        seeds=seeds_a, repetitions=2, acceptance_criteria={"overall_recall": 0.4},
    )

    with pytest.raises(ValueError, match="paired family x seed x repetition"):
        e6.compare_cohorts(base_path, diff_seed_path)
    with pytest.raises(ValueError, match="counts mismatch|paired family x seed x repetition"):
        e6.compare_cohorts(base_path, diff_rep_path)
    with pytest.raises(ValueError, match="identical token, HTTP, and duration ceilings"):
        e6.compare_cohorts(base_path, diff_cap_path)
    with pytest.raises(ValueError, match="acceptance criteria must match"):
        e6.compare_cohorts(base_path, diff_acc_path)


def test_strict_comparison_allows_only_declared_treatment_differences(baseline, tmp_path, monkeypatch):
    work = _work_dir(tmp_path, "treatment")
    cfg_a = _write_llm_config(work / "llm-a.json", "http://127.0.0.1:1/v1", "model-a")
    cfg_b = _write_llm_config(work / "llm-b.json", "http://127.0.0.1:2/v1", "model-b")
    seeds = {
        "readonly-api-access-control": [314159],
        "readonly-sql-injection": [271828],
        "readonly-template-injection": [141421],
    }

    before_path, _, _ = _build_offline_cohort(
        work_dir=work / "before", label="before", baseline_dir=baseline, provider_config=cfg_a, seeds=seeds,
    )
    # 1. Accidental provider difference without declaring provider_config -> rejected.
    undeclared_prov_path, _, _ = _build_offline_cohort(
        work_dir=work / "undeclared-prov", label="after", baseline_dir=baseline, provider_config=cfg_b, seeds=seeds,
        treatment={"name": "accidental", "role": "treatment", "changed_dimensions": []},
    )
    with pytest.raises(ValueError, match="undeclared provider_config difference"):
        e6.compare_cohorts(before_path, undeclared_prov_path)

    # 2. Declared provider_config difference -> allowed.
    declared_prov_path, _, _ = _build_offline_cohort(
        work_dir=work / "declared-prov", label="after", baseline_dir=baseline, provider_config=cfg_b, seeds=seeds,
        treatment={"name": "model-b-eval", "role": "treatment", "changed_dimensions": ["provider_config"]},
    )
    cmp_prov = e6.compare_cohorts(before_path, declared_prov_path)
    assert cmp_prov["fingerprints"]["provider_config"]["matched"] is False
    assert cmp_prov["fingerprints"]["provider_config"]["declared_allowed"] is True
    assert cmp_prov["fingerprints"]["evaluator"]["matched"] is True

    # 3. Simulated prompt_catalog change (via preflight host_runtime hash): undeclared rejected, declared allowed.
    orig_inv = e6.preflight.python_host_inventory

    def _patched_prompt_inv():
        inv = dict(orig_inv())
        inv["scripts/full_agent_python_solver.py"] = "0" * 64
        return inv

    monkeypatch.setattr(e6.preflight, "python_host_inventory", _patched_prompt_inv)
    undeclared_prompt_path, _, _ = _build_offline_cohort(
        work_dir=work / "undeclared-prompt", label="after", baseline_dir=baseline, provider_config=cfg_a, seeds=seeds,
        treatment={"name": "prompt-only", "role": "treatment", "changed_dimensions": []},
    )
    declared_prompt_path, _, _ = _build_offline_cohort(
        work_dir=work / "declared-prompt", label="after", baseline_dir=baseline, provider_config=cfg_a, seeds=seeds,
        treatment={"name": "prompt-only", "role": "treatment", "changed_dimensions": ["prompt_catalog"]},
    )
    monkeypatch.undo()

    with pytest.raises(ValueError, match="undeclared prompt_catalog difference"):
        e6.compare_cohorts(before_path, undeclared_prompt_path)
    cmp_prompt = e6.compare_cohorts(before_path, declared_prompt_path)
    assert cmp_prompt["fingerprints"]["prompt_catalog"]["matched"] is False
    assert cmp_prompt["fingerprints"]["prompt_catalog"]["declared_allowed"] is True
    assert cmp_prompt["fingerprints"]["runtime"]["matched"] is True

    # 4. Simulated evaluator change -> ALWAYS rejected even if prompt_catalog is declared.
    orig_selection = holdout.selection

    def _patched_selection(family, seed):
        sel = dict(orig_selection(family, seed))
        sel["evaluator_sha256"] = "f" * 64
        return sel

    monkeypatch.setattr(holdout, "selection", _patched_selection)
    monkeypatch.setattr(holdout, "replay", lambda selected, seed=None: holdout.FAMILIES[selected["family"]])
    monkeypatch.setattr(holdout, "digest", lambda p: "f" * 64 if Path(p).name == "full_agent_holdout.py" else e6.preflight.sha256(p))
    # Build an after cohort with drifted evaluator hash, then restore holdout so compare detects mismatch.
    alt_eval_path, _, _ = _build_offline_cohort(
        work_dir=work / "alt-eval", label="alt-eval", baseline_dir=baseline, provider_config=cfg_a, seeds=seeds,
        treatment={"name": "prompt-only", "role": "treatment", "changed_dimensions": ["prompt_catalog"]},
    )
    monkeypatch.undo()
    with pytest.raises(ValueError):
        e6.compare_cohorts(before_path, alt_eval_path)


def test_legacy_reaudit_adapter_and_descriptive_vs_strict_comparison(baseline, tmp_path):
    work = _work_dir(tmp_path, "legacy")
    cfg = _write_llm_config(work / "llm.json", "http://127.0.0.1:1/v1", "meta/muse-spark-1.3-contributor")
    legacy_seeds = {
        "readonly-api-access-control": [314159],
        "readonly-sql-injection": [271828],
        "readonly-template-injection": [141421],
    }
    # Build a synthetic legacy cohort matching the legacy schema (without experiment-manifest or report_digest).
    legacy_dir = work / "legacy-archive"
    paired_seed_path, paired_seed_report, _ = _build_offline_cohort(
        work_dir=legacy_dir,
        label="legacy-before",
        baseline_dir=baseline,
        provider_config=cfg,
        seeds=legacy_seeds,
        repetitions=1,
        http_budget=250,
        token_budget=150000,
        seconds_budget=900,
    )
    legacy_report = copy.deepcopy(paired_seed_report)
    for key in (
        "seeds_by_family", "repetitions", "funnel", "fingerprints", "treatment",
        "acceptance_criteria", "acceptance", "provenance", "report_digest",
    ):
        legacy_report.pop(key, None)
    for row in legacy_report["runs"]:
        for key in ("experiment_id", "repetition", "funnel", "fingerprints", "effective_limits",
                    "recall", "negative_coverage", "false_positives", "verified_findings"):
            row.pop(key, None)
    dump(paired_seed_path, legacy_report)
    (legacy_dir / "experiment-manifest.json").unlink()
    (legacy_dir / "unit-runs.json").unlink()

    # Record archive snapshot before read-only re-audit to prove zero mutations.
    before_files = sorted(str(p.relative_to(legacy_dir)) for p in legacy_dir.rglob("*"))

    # Multi-seed candidate cohort to compare against legacy baseline.
    after_seeds = {
        "readonly-api-access-control": [314159, 654321],
        "readonly-sql-injection": [271828, 828172],
        "readonly-template-injection": [141421, 124141],
    }
    after_path, _, _ = _build_offline_cohort(
        work_dir=work / "after",
        label="multi-after",
        baseline_dir=baseline,
        provider_config=cfg,
        seeds=after_seeds,
        repetitions=2,
        http_budget=250,
        token_budget=150000,
        seconds_budget=900,
    )

    # 1. Strict comparison MUST reject legacy report (never silently relabel as strict paired).
    with pytest.raises(ValueError, match="unverifiable or legacy"):
        e6.compare_cohorts(paired_seed_path, after_path)

    # 2. Safe read-only legacy re-audit derives verifiable fingerprints & flags unrecoverable provenance.
    derived_out = work / "legacy-derived.json"
    assert agent_cli.main([
        "benchmark", "reaudit-legacy",
        "--report", str(paired_seed_path),
        "--output", str(derived_out),
    ]) == 0
    derived = json.loads(derived_out.read_text(encoding="utf-8"))
    after_files = sorted(str(p.relative_to(legacy_dir)) for p in legacy_dir.rglob("*"))
    assert before_files == after_files  # Zero writes into archived legacy directory!
    assert derived["schema"] == e6.SCHEMA_LEGACY_DERIVED
    assert derived["provenance"]["strict_paired_eligible"] is False
    assert derived["funnel"]["funnel_present"] is False
    assert derived["funnel"]["observed"] is None
    assert "no_pre_execution_experiment_manifest" in derived["unrecoverable_provenance"]
    assert "single_seed_per_family" in derived["unrecoverable_provenance"]
    assert "missing_runtime_funnel_metrics" in derived["unrecoverable_provenance"]
    assert set(derived["fingerprints"]) == {"runtime", "evaluator", "prompt_catalog", "provider_config"}

    # Even derived legacy artifact is still rejected by strict comparison!
    with pytest.raises(ValueError, match="unverifiable or legacy"):
        e6.compare_cohorts(derived_out, after_path)

    # 3. Descriptive comparison succeeds, preserves limitations, and computes overlapping-seed slice.
    cmp_dir = work / "descriptive-cmp"
    assert agent_cli.main([
        "benchmark", "compare",
        "--before", str(paired_seed_path),
        "--after", str(after_path),
        "--mode", "descriptive",
        "--output-dir", str(cmp_dir),
    ]) == 0
    cmp_data = json.loads((cmp_dir / "comparison.json").read_text(encoding="utf-8"))
    assert cmp_data["comparison_mode"] == "descriptive_legacy_baseline"
    assert cmp_data["strict_paired"] is False
    assert cmp_data["reaudited_from_artifacts"] is True
    assert cmp_data["descriptive_overlapping_seed_slice"]["available"] is True
    assert cmp_data["descriptive_overlapping_seed_slice"]["after_matching_runs_count"] == 6
    assert "non_strict_descriptive_comparison" in cmp_data["not_tested_dimensions"]
    assert cmp_data["funnel"]["before"]["observed"] is None

    # 4. --enforce-acceptance returns nonzero exit code 3 when frozen criteria are not met.
    assert agent_cli.main([
        "benchmark", "compare",
        "--before", str(paired_seed_path),
        "--after", str(after_path),
        "--mode", "descriptive",
        "--enforce-acceptance",
    ]) == 3

    # 5. Tampering with a legacy manifest causes reaudit_legacy_cohort to fail closed.
    first_launch = next((legacy_dir / "runs").glob("*/launch.json"))
    launch_data = json.loads(first_launch.read_text(encoding="utf-8"))
    launch_data["target_requests"] = 99
    dump(first_launch, launch_data)
    with pytest.raises(ValueError, match="digest mismatch"):
        e6.reaudit_legacy_cohort(paired_seed_path)


def _resign_report(report: dict) -> dict:
    updated = {k: v for k, v in report.items() if k != "report_digest"}
    updated["report_digest"] = e6._canonical_sha256(updated)
    return updated


def _resign_manifest(exp_manifest: dict) -> dict:
    updated = {k: v for k, v in exp_manifest.items() if k != "manifest_digest"}
    updated["manifest_digest"] = e6._canonical_sha256(updated)
    return updated


def test_adversarial_recomputation_and_frozen_commitment_attacks(baseline, tmp_path, monkeypatch):
    work = _work_dir(tmp_path, "adv")
    cfg = _write_llm_config(work / "llm.json", "http://127.0.0.1:1/v1", "meta/muse-spark-1.3-contributor")
    seeds = {
        "readonly-api-access-control": [314159, 654321],
        "readonly-sql-injection": [271828],
        "readonly-template-injection": [141421],
    }

    before_dir = work / "before"
    after_dir = work / "after"
    before_path, before_report, exp_before_path = _build_offline_cohort(
        work_dir=before_dir, label="adv-before", baseline_dir=baseline,
        provider_config=cfg, seeds=seeds, repetitions=2,
    )
    after_path, after_report, _ = _build_offline_cohort(
        work_dir=after_dir, label="adv-after", baseline_dir=baseline,
        provider_config=cfg, seeds=seeds, repetitions=2,
        treatment={"changed_dimensions": ["prompt_catalog"], "description": "prompt tuning"},
    )

    # Multi-repetition CLI `benchmark audit` succeeds without --unit-runs.
    cli_audit_out = work / "cli-audit.json"
    manifest_args: list[str] = []
    for row in after_report["runs"]:
        manifest_args.extend(["--manifest", row["evidence_refs"]["manifest"]["path"]])
    assert agent_cli.main([
        "benchmark", "audit",
        "--label", "cli-multi-rep",
        "--experiment-manifest", str(after_dir / "experiment-manifest.json"),
        "--output", str(cli_audit_out),
        *manifest_args,
    ]) == 0
    cli_audited = json.loads(cli_audit_out.read_text(encoding="utf-8"))
    assert len(cli_audited["runs"]) == 8
    assert cli_audited["repetitions"] == 2

    # 1. Recomputation attacks where attacker recomputes report_digest fail closed in strict compare.
    recomputed_attacks: list[tuple[str, dict]] = []
    pf_tamper = copy.deepcopy(after_report)
    pf_tamper["per_family"]["readonly-api-access-control"]["recall"]["value"] = 1.0
    recomputed_attacks.append(("per_family", _resign_report(pf_tamper)))

    run_tamper = copy.deepcopy(after_report)
    run_tamper["runs"][0]["failed"] = False
    recomputed_attacks.append(("runs[0].failed", _resign_report(run_tamper)))

    nt_tamper = copy.deepcopy(after_report)
    nt_tamper["not_tested_dimensions"] = []
    recomputed_attacks.append(("not_tested_dimensions", _resign_report(nt_tamper)))

    gen_tamper = copy.deepcopy(after_report)
    gen_tamper["paid_model_generalization"] = "passed"
    recomputed_attacks.append(("paid_model_generalization", _resign_report(gen_tamper)))

    zero_cost = copy.deepcopy(after_report)
    zero_cost["usage"]["cost_usd"] = 0.0
    recomputed_attacks.append(("unknown_cost_zeroed", _resign_report(zero_cost)))

    omit_run = copy.deepcopy(after_report)
    omit_run["runs"] = omit_run["runs"][:-1]
    recomputed_attacks.append(("omitted_failed_run", _resign_report(omit_run)))

    swap_rep = copy.deepcopy(after_report)
    r0_ref = copy.deepcopy(swap_rep["runs"][0]["evidence_refs"]["manifest"])
    swap_rep["runs"][0]["evidence_refs"]["manifest"] = copy.deepcopy(swap_rep["runs"][1]["evidence_refs"]["manifest"])
    swap_rep["runs"][1]["evidence_refs"]["manifest"] = r0_ref
    recomputed_attacks.append(("swapped_unit_manifests", _resign_report(swap_rep)))

    for name, forged in recomputed_attacks:
        with pytest.raises(ValueError, match="do not match|does not match|mismatch|count|legacy"):
            e6.compare_cohorts(before_report, forged, mode="strict")

    # Duplicate manifest path rejected by audit_cohort.
    all_manifests = [r["evidence_refs"]["manifest"]["path"] for r in before_report["runs"]]
    with pytest.raises(ValueError, match="duplicate"):
        e6.audit_cohort("dup-manifest", [all_manifests[0], all_manifests[0], all_manifests[2]])

    # 2. Tampering derived legacy report and recomputing its digest fails closed in descriptive mode.
    legacy_dir = work / "legacy-src"
    legacy_report_path, legacy_report, _ = _build_offline_cohort(
        work_dir=legacy_dir, label="legacy-src", baseline_dir=baseline,
        provider_config=cfg,
        seeds={f: [s[0]] for f, s in seeds.items()},
        repetitions=1,
    )
    for k in ("seeds_by_family", "repetitions", "funnel", "fingerprints", "treatment",
              "acceptance_criteria", "acceptance", "provenance", "report_digest"):
        legacy_report.pop(k, None)
    for pf_row in legacy_report.get("per_family", {}).values():
        for pf_drop in ("failed_runs", "run_count", "seeds", "repetitions", "funnel"):
            pf_row.pop(pf_drop, None)
    dump(legacy_report_path, legacy_report)
    (legacy_dir / "experiment-manifest.json").unlink()
    (legacy_dir / "unit-runs.json").unlink()
    derived = e6.reaudit_legacy_cohort(legacy_report_path)
    assert derived["schema"] == e6.SCHEMA_LEGACY_DERIVED
    assert derived["provenance"]["strict_paired_eligible"] is False
    assert derived["funnel"]["observed"] is None
    with pytest.raises(ValueError, match="unverifiable or legacy cohort report"):
        e6.compare_cohorts(derived, after_path, mode="strict")
    tampered_legacy_src = copy.deepcopy(legacy_report)
    first_fam = next(iter(tampered_legacy_src["per_family"]))
    tampered_legacy_src["per_family"][first_fam]["recall"]["value"] = 0.99
    tampered_legacy_src_path = legacy_dir / "tampered-legacy.json"
    dump(tampered_legacy_src_path, tampered_legacy_src)
    with pytest.raises(ValueError, match="per_family"):
        e6.reaudit_legacy_cohort(tampered_legacy_src_path)
    tampered_derived = copy.deepcopy(derived)
    tampered_derived["usage"]["cost_usd"] = 0.0
    tampered_derived["provenance"]["strict_paired_eligible"] = True
    tampered_derived = _resign_report(tampered_derived)
    with pytest.raises(ValueError, match="does not match"):
        e6.compare_cohorts(tampered_derived, after_path, mode="descriptive")

    # 3. Post-execution experiment-manifest tampering (acceptance/treatment/units) with recomputed digest fails closed.
    exp_copy_dir = work / "exp-tamper"
    shutil.copytree(after_dir, exp_copy_dir)
    exp_json_path = exp_copy_dir / "experiment-manifest.json"
    orig_exp = json.loads(exp_json_path.read_text(encoding="utf-8"))

    # Case A: acceptance changed post-execution against suite-plan.json
    tampered_exp = copy.deepcopy(orig_exp)
    tampered_exp["acceptance_criteria"]["max_failed_run_rate"] = 1.0
    dump(exp_json_path, _resign_manifest(tampered_exp))
    with pytest.raises(ValueError, match="suite-plan.json"):
        e6._verify_experiment_manifest(exp_json_path)

    # Case B: subset/missing unit even without suite-plan.json
    (exp_copy_dir / "suite-plan.json").unlink()
    subset_exp = copy.deepcopy(orig_exp)
    subset_exp["units"] = subset_exp["units"][:-1]
    dump(exp_json_path, _resign_manifest(subset_exp))
    with pytest.raises(ValueError, match="grid"):
        e6._verify_experiment_manifest(exp_json_path)

    # Restore valid experiment manifest without suite-plan for run_cohort pre-execution tamper check.
    dump(exp_json_path, orig_exp)

    # 4. Artifact-level tamper checks (non-readonly & readonly).
    art_dir = work / "art-tamper"
    shutil.copytree(after_dir, art_dir)
    art_manifests = [
        str(art_dir / Path(r["evidence_refs"]["manifest"]["path"]).relative_to(after_dir))
        for r in after_report["runs"]
    ]
    run0_dir = Path(art_manifests[0]).parent

    # Tamper launch effective_limits -> caught by _verify_run_manifest_and_artifacts in audit_cohort(readonly=False/True).
    launch0 = json.loads((run0_dir / "launch.json").read_text(encoding="utf-8"))
    orig_launch0 = copy.deepcopy(launch0)
    launch0["effective_limits"]["http_requests_per_seed"] = 999
    dump(run0_dir / "launch.json", launch0)
    with pytest.raises(ValueError, match="effective_limits"):
        e6.audit_cohort("art-limits", art_manifests, readonly=False)
    with pytest.raises(ValueError, match="effective_limits"):
        e6.audit_cohort("art-limits-ro", art_manifests, readonly=True)
    dump(run0_dir / "launch.json", orig_launch0)

    # Forged attempt-ledger without valid Ed25519 signature -> rejected by extract_run_funnel.
    ledger_path = run0_dir / "solver/attempt-ledger.json"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    dump(ledger_path, {
        "schema": "python-attempt-ledger/1",
        "payload": {"schema": "python-attempt-ledger/1", "producer": "host", "workflow_files": []},
        "signature": {"key_id": "forged", "signature": "deadbeef"},
    })
    with pytest.raises(ValueError, match="public trust|signature"):
        e6.extract_run_funnel(run0_dir, orig_launch0)
    ledger_path.unlink()

    # Tamper truth.json positive count -> rejected against expected-counts.json.
    truth_path = run0_dir / "private/evaluator/truth.json"
    orig_truth = json.loads(truth_path.read_text(encoding="utf-8"))
    dump(truth_path, orig_truth[:-1])
    with pytest.raises(ValueError, match="truth"):
        e6.audit_cohort("art-truth", art_manifests, readonly=False)
    dump(truth_path, orig_truth)

    # Tamper budget.json cap -> rejected.
    budget_path = run0_dir / "private/budget.json"
    orig_budget = json.loads(budget_path.read_text(encoding="utf-8"))
    bad_budget = copy.deepcopy(orig_budget)
    bad_budget["limits"]["tokens"] = orig_budget["limits"]["tokens"] + 50000
    dump(budget_path, bad_budget)
    with pytest.raises(ValueError, match="budget.json"):
        e6.audit_cohort("art-budget", art_manifests, readonly=True)
    dump(budget_path, orig_budget)

    # 5. Pre-execution tamper check in run_cohort: tampering frozen contract stops BEFORE launch_seed runs.
    monkeypatch.setenv("CCO_BENCHMARK_API_KEY", "synthetic-unused-secret")
    prep_dir = work / "prelaunch-tamper"
    plan_path, plan = e6.prepare_cohort(
        "prelaunch-tamper",
        baseline=baseline,
        provider_config=cfg,
        output_dir=prep_dir,
        seeds=seeds,
        repetitions=1,
        http_budget=250,
        token_budget=150000,
        seconds_budget=900,
    )
    exp_doc = json.loads(Path(plan["experiment_manifest"]).read_text(encoding="utf-8"))
    first_contract = Path(exp_doc["units"][0]["contract"])
    contract_doc = json.loads(first_contract.read_text(encoding="utf-8"))
    contract_doc["limits"]["llm_tokens_per_seed"] = 999999
    dump(first_contract, contract_doc)
    called = []
    monkeypatch.setattr(e6, "prepare_cohort", lambda *_a, **_kw: (plan_path, plan))
    monkeypatch.setattr(launcher, "launch_seed", lambda *_a, **_kw: called.append(1))
    with pytest.raises(ValueError, match="has changed|ceilings|digest|contract"):
        e6.run_cohort(
            "prelaunch-tamper",
            baseline=baseline,
            provider_config=cfg,
            output_dir=prep_dir,
            seeds=seeds,
            repetitions=1,
            http_budget=250,
            token_budget=150000,
            seconds_budget=900,
            execute=True,
        )
    assert called == []


def test_adversarial_derived_legacy_and_provenance_hardening(baseline, tmp_path):
    """Derived legacy checks cover provenance/runs, forged authorization, unit-runs bypass, and budget/symlink integrity."""
    work = _work_dir(tmp_path, "adv-hardening")
    cfg = _write_llm_config(work / "llm.json", "http://127.0.0.1:49999/v1")
    seeds = {
        "readonly-api-access-control": [314159],
        "readonly-sql-injection": [271828],
        "readonly-template-injection": [141421],
    }

    # 1. Legacy derived report with tampered provenance or runs + recomputed digest is rejected.
    legacy_dir = work / "legacy-src"
    legacy_path, legacy_report, _ = _build_offline_cohort(
        work_dir=legacy_dir, label="legacy-src", baseline_dir=baseline, provider_config=cfg, seeds=seeds,
    )
    (legacy_dir / "unit-runs.json").unlink()
    for drop_key in ("experiment_id", "repetition"):
        for r in legacy_report["runs"]:
            r.pop(drop_key, None)
    for top_drop in ("seeds_by_family", "repetitions", "fingerprints", "provenance", "treatment", "acceptance_criteria", "acceptance", "report_digest"):
        legacy_report.pop(top_drop, None)
    dump(legacy_path, legacy_report)

    derived = e6.reaudit_legacy_cohort(legacy_path)
    derived_forged_prov = copy.deepcopy(derived)
    derived_forged_prov["provenance"]["strict_paired_eligible"] = True
    derived_forged_prov["report_digest"] = e6._canonical_sha256({k: v for k, v in derived_forged_prov.items() if k != "report_digest"})

    paired_after_path, paired_after, _ = _build_offline_cohort(
        work_dir=work / "paired-after", label="paired-after", baseline_dir=baseline, provider_config=cfg, seeds=seeds,
    )
    with pytest.raises(ValueError, match="provenance"):
        e6.compare_cohorts(derived_forged_prov, paired_after_path, mode="descriptive")

    derived_forged_runs = copy.deepcopy(derived)
    derived_forged_runs["runs"][0]["failed"] = not derived_forged_runs["runs"][0]["failed"]
    derived_forged_runs["report_digest"] = e6._canonical_sha256({k: v for k, v in derived_forged_runs.items() if k != "report_digest"})
    with pytest.raises(ValueError, match="runs"):
        e6.compare_cohorts(derived_forged_runs, paired_after_path, mode="descriptive")

    # 2. Forged authorization on strict cohort report with recomputed digest is rejected.
    paired_before_path, paired_before, _ = _build_offline_cohort(
        work_dir=work / "paired-before", label="paired-before", baseline_dir=baseline, provider_config=cfg, seeds=seeds,
    )
    forged_auth = copy.deepcopy(paired_after)
    forged_auth["authorization"] = {
        "provider_kind": "remote",
        "provider_host": "api.example.invalid",
        "live_provider_authorized": True,
        "live_authorization_reason": "forged after execution",
    }
    forged_auth["report_digest"] = e6._canonical_sha256({k: v for k, v in forged_auth.items() if k != "report_digest"})
    with pytest.raises(ValueError, match="authorization"):
        e6.compare_cohorts(paired_before_path, forged_auth, mode="strict")

    # 3. Substituted manifest bypassing unit-runs.json in audit_cohort without explicit unit_runs fails closed.
    exp_dir = work / "paired-before"
    exp_manifest_path = exp_dir / "experiment-manifest.json"
    alt_manifests = [Path(r["evidence_refs"]["manifest"]["path"]) for r in paired_after["runs"]]
    with pytest.raises(ValueError, match="unit_runs"):
        e6.audit_cohort(
            "bypass-attempt",
            alt_manifests,
            expected_ceilings=paired_before["ceilings"],
            experiment_manifest=exp_manifest_path,
        )

    # 4. suite-plan.json family tamper or symlink beside experiment-manifest.json fails closed.
    suite_copy = copy.deepcopy(paired_before)
    assert suite_copy["families"]
    suite_plan_path = exp_dir / "suite-plan.json"
    suite_plan_doc = json.loads(suite_plan_path.read_text(encoding="utf-8"))
    orig_suite_plan_text = suite_plan_path.read_text(encoding="utf-8")
    suite_plan_doc["families"] = list(reversed(suite_plan_doc["families"]))
    dump(suite_plan_path, suite_plan_doc)
    with pytest.raises(ValueError, match="diverges from pre-execution suite-plan.json"):
        e6.compare_cohorts(paired_before_path, paired_after_path, mode="strict")
    suite_plan_path.write_text(orig_suite_plan_text, encoding="utf-8")

    # 5. Malformed budget.json limits (even with recomputed evidence digest) and budget symlink fail closed.
    budget_file = Path(paired_before["runs"][0]["evidence_refs"]["manifest"]["path"]).parent / "private/budget.json"
    orig_budget_text = budget_file.read_text(encoding="utf-8")
    budget_file.write_text(json.dumps({"used": {"http": 0}}), encoding="utf-8")
    recomputed_budget = copy.deepcopy(paired_before)
    recomputed_budget["runs"][0]["evidence_refs"]["budget"]["sha256"] = holdout.digest(budget_file)
    recomputed_budget["report_digest"] = e6._canonical_sha256({k: v for k, v in recomputed_budget.items() if k != "report_digest"})
    with pytest.raises(ValueError, match="valid limits"):
        e6.compare_cohorts(recomputed_budget, paired_after_path, mode="strict")
    with pytest.raises(ValueError, match="valid limits"):
        e6.audit_cohort(
            "bad-budget",
            [Path(r["evidence_refs"]["manifest"]["path"]) for r in paired_before["runs"]],
            expected_ceilings=paired_before["ceilings"],
            experiment_manifest=exp_manifest_path,
        )
    budget_file.write_text(orig_budget_text, encoding="utf-8")

    decoy_budget = work / "decoy-budget.json"
    decoy_budget.write_text(orig_budget_text, encoding="utf-8")
    budget_file.unlink()
    budget_file.symlink_to(decoy_budget)
    with pytest.raises(ValueError, match="symlink"):
        e6.audit_cohort(
            "symlink-budget",
            [Path(r["evidence_refs"]["manifest"]["path"]) for r in paired_before["runs"]],
            expected_ceilings=paired_before["ceilings"],
            experiment_manifest=exp_manifest_path,
        )


def _make_fast_loopback_provider():
    """Fast deterministic loopback OpenAI-compatible handler completing real python_loop verification."""

    class FastProvider(BaseHTTPRequestHandler):
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
                tool, args = "kali-tools_crawl_web_surface", {"target": target, "max_pages": 2}
            elif spec["phase"] == "access":
                discovery = context.get("discovery") or {}
                have_read = any(r.get("tool") == READ_TOOL for r in results)
                have_loop = any(r.get("tool") == "hunter_run_web_loop" for r in results)
                if not have_loop and len(bindings_map) == 1 and not have_read and discovery.get("content_ref"):
                    tool, args = READ_TOOL, {"path": discovery["content_ref"]["path"], "offset": 0, "limit": 800}
                elif not have_loop:
                    bindings = dict(list(bindings_map.items())[:1]) if bindings_map else {}
                    tool, args = "hunter_run_web_loop", {
                        "target": target, "live": True, "crawl": False,
                        "blind_discovery": True, "blind_max_requests": 2,
                        "fuzz_limit": 1, "candidate_sample_limit": 2,
                        "max_validations": 2, "sleep_s": 0.0,
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
            payload = {
                "choices": [{"message": {"tool_calls": [{
                    "function": {"name": tool, "arguments": json.dumps(args)}
                }]}}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200},
            }
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return FastProvider


@pytest.mark.integration
def test_offline_multi_seed_and_repetition_execution_under_unchanged_caps(baseline, tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_BENCHMARK_API_KEY", "synthetic-unused-secret")
    work = _work_dir(tmp_path, "multiseed-exec")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_fast_loopback_provider())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = _write_llm_config(work / "llm.json", f"http://127.0.0.1:{server.server_address[1]}/v1")
        seeds = {
            "readonly-api-access-control": [314159, 654321],
            "readonly-sql-injection": [271828],
            "readonly-template-injection": [141421],
        }
        out_dir = work / "cohort"
        report_path, report = e6.run_cohort(
            "offline-multiseed-rep2",
            baseline=baseline,
            provider_config=cfg,
            output_dir=out_dir,
            seeds=seeds,
            repetitions=2,
            http_budget=250,
            token_budget=150000,
            seconds_budget=900,
            treatment={"changed_dimensions": [], "description": "offline multi-seed verification"},
            execute=True,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert len(report["runs"]) == 8
    assert report["repetitions"] == 2
    assert report["seeds_by_family"]["readonly-api-access-control"] == [314159, 654321]
    assert report["ceilings"] == {
        "http_requests_per_seed": 250,
        "llm_tokens_per_seed": 150000,
        "seconds_per_seed": 900,
    }
    assert report["provider_kinds"] == ["loopback"]
    assert report["paid_provider_calls"] == 0
    assert report["usage"]["cost_usd"] is None
    for row in report["runs"]:
        assert row["effective_limits"] == report["ceilings"]
        assert row["usage"]["cost_usd"] is None
        assert isinstance(row["funnel"]["funnel_present"], bool)
        if not row["funnel"]["funnel_present"]:
            assert row["funnel"]["observed"] is None
            assert row["funnel"]["evidence_accepted"] is None
        else:
            assert isinstance(row["funnel"]["observed"], int)
            assert isinstance(row["funnel"]["evidence_accepted"], int)

    # Strict self-comparison re-audits all 8 executed manifests cleanly.
    strict_self = e6.compare_cohorts(report_path, report_path, mode="strict")
    assert strict_self["strict_paired"] is True
    assert strict_self["reaudited_from_artifacts"] is True

    # CLI audit without --unit-runs works on the live-executed multi-repetition cohort.
    unit_runs_doc = json.loads((out_dir / "unit-runs.json").read_text(encoding="utf-8"))
    re_out = work / "cli-reaudit.json"
    cli_args = [
        "benchmark", "audit",
        "--label", "offline-multiseed-rep2",
        "--experiment-manifest", str(out_dir / "experiment-manifest.json"),
        "--output", str(re_out),
    ]
    for unit in unit_runs_doc["units"]:
        cli_args.extend(["--manifest", unit["manifest"]])
    assert agent_cli.main(cli_args) == 0

    # Adversarial checks against real executed runtime artifacts (extra unsigned summary + staged runtime tamper).
    first_run_dir = Path(report["runs"][0]["evidence_refs"]["manifest"]["path"]).parent
    fake_summary = first_run_dir / "solver/summaries/zz-fake.json"
    fake_summary.write_text(json.dumps({
        "phase": "access", "status": "partial",
        "validation_funnel": {
            "schema": "python-validation-funnel/1",
            "unit": "deduplicated_task_candidate",
            "observed": 99,
            "eligible": 99,
            "admitted": 99,
            "executed": 99,
            "evidence_accepted": 99,
        },
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="attempt-ledger"):
        e6.compare_cohorts(report_path, report_path, mode="strict")
    fake_summary.unlink()

    staged_cfg = first_run_dir / "runtime/config/llm.json"
    staged_index = first_run_dir / "runtime-index.json"
    staged_cfg.chmod(0o600)
    staged_cfg.write_text(staged_cfg.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    idx_doc = json.loads(staged_index.read_text(encoding="utf-8"))
    for entry in idx_doc["files"]:
        if entry["path"] == "config/llm.json":
            entry["sha256"] = holdout.digest(staged_cfg)
    dump(staged_index, idx_doc)
    with pytest.raises(ValueError, match="diverges from frozen preflight snapshot"):
        e6.compare_cohorts(report_path, report_path, mode="strict")


def _write_signed_runtime_run(
    run_dir: Path,
    *,
    run_id: str = "run-rt-1",
    status: str = "python_finished_verified",
    candidates_by_task: dict | None = None,
    write_checkpoint: bool = True,
    write_ledger: bool = True,
    write_root_result: bool = True,
    root_funnels: dict | None = None,
    summaries: dict[str, dict] | None = None,
    include_evidence_file: bool = True,
) -> Path:
    import evidence_trust
    import workflow_checkpoint

    solver = run_dir / "solver"
    private_state = run_dir / "private/state"
    runtime_dir = run_dir / "runtime"
    (solver / "summaries").mkdir(parents=True, exist_ok=True)
    (solver / "context-archive").mkdir(parents=True, exist_ok=True)
    (run_dir / "private/checkpoint-state").mkdir(parents=True, exist_ok=True)
    private_state.mkdir(parents=True, exist_ok=True)
    runtime_dir.mkdir(parents=True, exist_ok=True)

    with launcher.host_environment(private_state, solver, runtime_dir):
        evidence_trust.prepare()

    if include_evidence_file:
        ev_file = solver / "context-archive/val-1.json"
        dump(ev_file, {"validation_id": "val-1", "state": "TESTED", "ok": True})
        ev_sha = holdout.digest(ev_file)
    else:
        ev_sha = "0" * 64

    workflow_files = []
    if summaries:
        for name, content in sorted(summaries.items()):
            spath = solver / "summaries" / name
            dump(spath, content)
            rel = f"summaries/{name}"
            if content.get("validation_funnel") is not None or "validation_funnels" in content or status == "python_finished_verified":
                workflow_files.append({
                    "path": rel,
                    "sha256": holdout.digest(spath),
                    "bytes": spath.stat().st_size,
                })

    if candidates_by_task is None:
        candidates_by_task = {
            "access-3": {
                "cand-1": {
                    "candidate_id": "cand-1",
                    "observed": True,
                    "eligible": True,
                    "admitted": True,
                    "executed": True,
                    "evidence_accepted": True,
                    "validation_state": "TESTED",
                    "evidence_refs": [
                        {
                            "validation_id": "val-1",
                            "source_artifact": "context-archive/val-1.json",
                            "source_sha256": ev_sha,
                        }
                    ],
                },
                "cand-2": {
                    "candidate_id": "cand-2",
                    "observed": True,
                    "eligible": True,
                    "admitted": False,
                    "executed": False,
                    "evidence_accepted": False,
                    "validation_state": "NOT_TESTED",
                    "evidence_refs": [],
                },
            }
        }

    if write_checkpoint:
        state_payload = {
            "candidates_by_task": candidates_by_task,
            "summaries": {k.removesuffix(".json"): v for k, v in (summaries or {}).items()},
        }
        state_bytes = evidence_trust.canonical_bytes(state_payload)
        import hashlib
        state_sha = hashlib.sha256(state_bytes).hexdigest()
        state_path = run_dir / "private/checkpoint-state" / f"{state_sha}.json"
        state_path.write_bytes(state_bytes)
        evidence_refs = [workflow_checkpoint.file_ref(run_dir, state_path)]
        for wf in workflow_files:
            if wf["path"].startswith("summaries/"):
                evidence_refs.append(workflow_checkpoint.file_ref(run_dir, solver / wf["path"]))
        cp_payload = {
            "schema": workflow_checkpoint.SCHEMA,
            "run_id": run_id,
            "state_ref": evidence_refs[0],
            "evidence": evidence_refs,
            "summary_ids": [Path(wf["path"]).stem for wf in workflow_files if wf["path"].startswith("summaries/")],
            "context": {"policy_hashes": {}},
        }
        with launcher.host_environment(private_state, solver, runtime_dir):
            cp = workflow_checkpoint.WorkflowCheckpoint(solver)
            cp.acquire()
            try:
                cp.write(cp_payload)
            finally:
                cp.release()

    if write_ledger:
        ledger_payload = {
            "schema": "python-attempt-ledger/1",
            "producer": "host",
            "target": "http://127.0.0.1:1/",
            "records": [],
            "artifacts": [],
            "workflow_files": workflow_files,
        }
        with launcher.host_environment(private_state, solver, runtime_dir):
            dump(solver / "attempt-ledger.json", evidence_trust.attest(ledger_payload, "python-attempt-ledger"))

    if write_root_result:
        if root_funnels is None:
            root_funnels = {
                task_id: {
                    "schema": "python-validation-funnel/1",
                    "unit": "deduplicated_task_candidate",
                    "observed": len(rows),
                    "eligible": sum(1 for r in rows.values() if r["eligible"]),
                    "admitted": sum(1 for r in rows.values() if r["admitted"]),
                    "executed": sum(1 for r in rows.values() if r["executed"]),
                    "evidence_accepted": sum(1 for r in rows.values() if r["evidence_accepted"]),
                    "candidates": list(rows.values()),
                }
                for task_id, rows in sorted(candidates_by_task.items())
            }
        dump(run_dir / "run-result.json", {
            "schema": "python-workflow-v1",
            "run_id": run_id,
            "status": status,
            "checkpoint": str(solver / "checkpoint.json"),
            "validation_funnels": root_funnels,
        })

    return run_dir


def test_runtime_funnel_root_checkpoint_dedup_and_failed_run_extraction(tmp_path):
    """Exact main runtime schema (root run-result.json + signed checkpoint + cumulative summaries) works and fails closed on tamper."""
    work = _work_dir(tmp_path, "rt-funnel")

    # 1. Verified runtime run with ROOT run-result.json (plural validation_funnels), signed checkpoint,
    #    cumulative report-4.json duplicating access-3 funnel, and model prose claiming fake findings.
    access_funnel = {
        "schema": "python-validation-funnel/1",
        "unit": "deduplicated_task_candidate",
        "observed": 2,
        "eligible": 2,
        "admitted": 1,
        "executed": 1,
        "evidence_accepted": 1,
    }
    full_dir = _write_signed_runtime_run(
        work / "full-run",
        run_id="run-full",
        status="python_finished_verified",
        summaries={
            "access-3.json": {
                "task_id": "access-3",
                "phase": "access",
                "status": "partial",
                "next": "Verified 99 SQLi findings!",
                "findings": [{"id": f"fake-{i}"} for i in range(5)],
                "validation_funnel": access_funnel,
            },
            "report-4.json": {
                "task_id": "report-4",
                "phase": "report",
                "status": "done",
                "next": "All 50 endpoints vulnerable.",
                "validation_funnels": {"access-3": copy.deepcopy(access_funnel)},
            },
        },
    )
    assert not (full_dir / "solver/run-result.json").exists()
    extracted = e6.extract_run_funnel(full_dir, {"run_id": "run-full", "status": "python_finished_verified"})
    assert extracted == {
        "funnel_present": True,
        "status": "complete",
        "observed": 2,
        "eligible": 2,
        "admitted": 1,
        "executed": 1,
        "evidence_accepted": 1,
        "rates": {
            "eligible_rate": 1.0,
            "admitted_rate": 0.5,
            "executed_rate": 1.0,
            "accepted_rate": 1.0,
            "end_to_end_yield": 0.5,
        },
    }

    # 2. Failed runtime run matching test_exact_failed_runtime_funn0 layout:
    #    no attempt-ledger, blocked access-3 summary without validation_funnel,
    #    signed checkpoint + ROOT run-result.json with observed=2, eligible=2, admitted=0.
    failed_candidates = {
        "access-3": {
            "cand-a": {
                "candidate_id": "cand-a",
                "observed": True,
                "eligible": True,
                "admitted": False,
                "executed": False,
                "evidence_accepted": False,
                "validation_state": "NOT_TESTED",
                "evidence_refs": [],
            },
            "cand-b": {
                "candidate_id": "cand-b",
                "observed": True,
                "eligible": True,
                "admitted": False,
                "executed": False,
                "evidence_accepted": False,
                "validation_state": "NOT_TESTED",
                "evidence_refs": [],
            },
        }
    }
    failed_dir = _write_signed_runtime_run(
        work / "failed-run",
        run_id="run-fail",
        status="blocked",
        candidates_by_task=failed_candidates,
        write_ledger=False,
        include_evidence_file=False,
        summaries={
            "access-3.json": {
                "phase": "access",
                "status": "blocked",
                "blocked_by": "validation_budget_exhausted",
                "next": "Runtime blocked after observing 2 eligible candidates.",
            }
        },
    )
    # Emulate shutil.copytree with stale absolute checkpoint path prefix in run-result.json
    copied_dir = work / "failed-run-copied"
    shutil.copytree(failed_dir, copied_dir)
    failed_extracted = e6.extract_run_funnel(copied_dir, {"run_id": "run-fail", "status": "python_inconclusive"})
    assert failed_extracted["funnel_present"] is True
    assert failed_extracted["status"] == "complete"
    assert (failed_extracted["observed"], failed_extracted["eligible"], failed_extracted["admitted"],
            failed_extracted["executed"], failed_extracted["evidence_accepted"]) == (2, 2, 0, 0, 0)

    # 3. Current failed run before access-3 (explicit empty validation_funnels: {}) => explicit 0s, NOT None.
    early_dir = _write_signed_runtime_run(
        work / "early-fail",
        run_id="run-early",
        status="blocked",
        candidates_by_task={},
        write_ledger=False,
        include_evidence_file=False,
        summaries={"recon-1.json": {"phase": "recon", "status": "blocked"}},
    )
    early_extracted = e6.extract_run_funnel(early_dir, {"run_id": "run-early", "status": "python_inconclusive"})
    assert early_extracted["funnel_present"] is True
    assert early_extracted["status"] == "complete"
    assert (early_extracted["observed"], early_extracted["evidence_accepted"]) == (0, 0)

    # 4. Legacy missing format (no candidates_by_task, no validation_funnels/validation_funnel/funnel anywhere) => unknown None.
    legacy_dir = work / "legacy-run"
    (legacy_dir / "solver/summaries").mkdir(parents=True)
    dump(legacy_dir / "run-result.json", {"schema": "legacy-v0", "status": "done", "next": "Observed 10 candidates"})
    dump(legacy_dir / "solver/summaries/recon-1.json", {"phase": "recon", "status": "done", "findings": ["SQLi"]})
    legacy_extracted = e6.extract_run_funnel(legacy_dir, {"status": "python_inconclusive"})
    assert legacy_extracted == e6._unknown_funnel()

    # 5. Adversarial fail-closed runtime funnel tampering checks.
    # 5a. Contradictory ROOT run-result.json against signed checkpoint.
    t_root = work / "tamper-root"
    shutil.copytree(full_dir, t_root)
    rr = json.loads((t_root / "run-result.json").read_text(encoding="utf-8"))
    rr["validation_funnels"]["access-3"]["evidence_accepted"] = 0
    rr["validation_funnels"]["access-3"]["candidates"][0]["evidence_accepted"] = False
    rr["validation_funnels"]["access-3"]["candidates"][0]["validation_state"] = "NOT TESTED"
    rr["validation_funnels"]["access-3"]["candidates"][0]["evidence_refs"] = []
    dump(t_root / "run-result.json", rr)
    with pytest.raises(ValueError, match="contradict signed checkpoint"):
        e6.extract_run_funnel(t_root, {"run_id": "run-full", "status": "python_finished_verified"})

    # 5b. Tampered checkpoint state_ref claiming evidence_accepted=True without validation_state='TESTED'.
    t_state = work / "tamper-state"
    shutil.copytree(full_dir, t_state)
    cp_doc = json.loads((t_state / "solver/checkpoint.json").read_text(encoding="utf-8"))
    st_path = t_state / cp_doc["payload"]["state_ref"]["path"]
    st_doc = json.loads(st_path.read_text(encoding="utf-8"))
    st_doc["candidates_by_task"]["access-3"]["cand-1"]["validation_state"] = "NOT_TESTED"
    st_path.write_text(json.dumps(st_doc), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity mismatch"):
        e6.extract_run_funnel(t_state, {"run_id": "run-full", "status": "python_finished_verified"})

    # 5c. Unsigned run-result.json claiming evidence_accepted=True without evidence_refs or with bad sha256.
    t_unverified = _write_signed_runtime_run(
        work / "tamper-evref",
        run_id="run-evref",
        write_checkpoint=False,
        write_ledger=False,
        include_evidence_file=True,
        root_funnels={
            "access-3": {
                "schema": "python-validation-funnel/1",
                "unit": "deduplicated_task_candidate",
                "observed": 1, "eligible": 1, "admitted": 1, "executed": 1, "evidence_accepted": 1,
                "candidates": [{
                    "candidate_id": "c1",
                    "observed": True, "eligible": True, "admitted": True, "executed": True,
                    "evidence_accepted": True, "validation_state": "TESTED",
                    "evidence_refs": [{"validation_id": "v1", "source_artifact": "context-archive/val-1.json", "source_sha256": "f" * 64}],
                }],
            }
        },
    )
    with pytest.raises(ValueError, match="digest mismatch"):
        e6.extract_run_funnel(t_unverified, {"run_id": "run-evref"})

    # 5d. Unsigned checkpoint.json asserting candidates_by_task fails closed.
    t_unsigned_cp = work / "tamper-unsigned-cp"
    shutil.copytree(legacy_dir, t_unsigned_cp)
    dump(t_unsigned_cp / "solver/checkpoint.json", {"candidates_by_task": {"access-3": {}}})
    with pytest.raises(ValueError, match="unsigned checkpoint"):
        e6.extract_run_funnel(t_unsigned_cp, {})

    # 5e. Non-monotonic / negative / bool funnel counts fail closed.
    for bad_funnel in (
        {"observed": 1, "eligible": 2, "admitted": 0, "executed": 0, "evidence_accepted": 0},
        {"observed": -1, "eligible": 0, "admitted": 0, "executed": 0, "evidence_accepted": 0},
        {"observed": True, "eligible": 0, "admitted": 0, "executed": 0, "evidence_accepted": 0},
    ):
        with pytest.raises(ValueError, match="non-monotonic|invalid host funnel count"):
            e6._normalize_funnel_dict(bad_funnel)

    # 5f. Contradictory duplicate task entry inside cumulative report-4.json (without checkpoint masking).
    t_dup_sum = work / "tamper-dupsum"
    (t_dup_sum / "solver/summaries").mkdir(parents=True)
    dump(t_dup_sum / "solver/summaries/access-3.json", {
        "task_id": "access-3",
        "validation_funnel": {"observed": 2, "eligible": 1, "admitted": 1, "executed": 1, "evidence_accepted": 0},
    })
    dump(t_dup_sum / "solver/summaries/report-4.json", {
        "task_id": "report-4",
        "validation_funnels": {
            "access-3": {"observed": 2, "eligible": 2, "admitted": 1, "executed": 1, "evidence_accepted": 0},
        },
    })
    with pytest.raises(ValueError, match="contradictory duplicate"):
        e6.extract_run_funnel(t_dup_sum, {})

    # 5g. Symlinked run-result.json or checkpoint.json fails closed.
    t_sym = work / "tamper-sym"
    shutil.copytree(legacy_dir, t_sym)
    (t_sym / "run-result.json").unlink()
    (t_sym / "run-result.json").symlink_to(legacy_dir / "run-result.json")
    with pytest.raises(ValueError, match="symlink"):
        e6.extract_run_funnel(t_sym, {})


def test_adversarial_manifest_remote_auth_and_legacy_row_hardening(baseline, tmp_path):
    """Harden symlinked manifests, suite-plan executed status, verified python fields, budget used/events, remote auth, and legacy run rows."""
    work = _work_dir(tmp_path, "adv-extra")
    cfg = _write_llm_config(work / "llm.json", "http://127.0.0.1:49999/v1")
    seeds = {
        "readonly-api-access-control": [314159],
        "readonly-sql-injection": [271828],
        "readonly-template-injection": [141421],
    }

    cdir = work / "cohort"
    report_path, report, exp_manifest_path = _build_offline_cohort(
        work_dir=cdir,
        label="adv-extra",
        baseline_dir=baseline,
        provider_config=cfg,
        seeds=seeds,
    )
    suite_plan_path = cdir / "suite-plan.json"
    orig_suite_plan = suite_plan_path.read_text(encoding="utf-8")

    # 1. Symlinked experiment-manifest.json fails closed.
    sym_exp = work / "sym-exp.json"
    sym_exp.symlink_to(exp_manifest_path)
    with pytest.raises(ValueError, match="symlink"):
        e6._verify_experiment_manifest(sym_exp)

    # 2. suite-plan.json claiming executed=True is rejected even when digest/runs match.
    sp = json.loads(orig_suite_plan)
    sp["executed"] = True
    dump(suite_plan_path, sp)
    with pytest.raises(ValueError, match="plan_only"):
        e6.compare_cohorts(report_path, report_path, mode="strict")
    suite_plan_path.write_text(orig_suite_plan, encoding="utf-8")

    # 3. suite-plan.json per-unit preflight_sha256 mismatch is rejected.
    sp = json.loads(orig_suite_plan)
    sp["runs"][0]["preflight_sha256"] = "0" * 64
    dump(suite_plan_path, sp)
    with pytest.raises(ValueError, match="diverge"):
        e6.compare_cohorts(report_path, report_path, mode="strict")
    suite_plan_path.write_text(orig_suite_plan, encoding="utf-8")

    # 4. private/budget.json negative used counter and malformed events list are rejected during cohort audit.
    first_run_dir = Path(report["runs"][0]["evidence_refs"]["manifest"]["path"]).parent
    budget_path = first_run_dir / "private/budget.json"
    orig_budget = budget_path.read_text(encoding="utf-8")
    run_manifests = [Path(r["evidence_refs"]["manifest"]["path"]) for r in report["runs"]]
    bdoc = json.loads(orig_budget)
    bdoc["used"]["http"] = -1
    dump(budget_path, bdoc)
    with pytest.raises(ValueError, match="nonnegative integers"):
        e6.audit_cohort(
            "adv-budget-used",
            run_manifests,
            expected_ceilings=report["ceilings"],
            experiment_manifest=exp_manifest_path,
            readonly=True,
        )
    bdoc = json.loads(orig_budget)
    bdoc["events"] = {"invalid": True}
    dump(budget_path, bdoc)
    with pytest.raises(ValueError, match="list of dicts"):
        e6.audit_cohort(
            "adv-budget-events",
            run_manifests,
            expected_ceilings=report["ceilings"],
            experiment_manifest=exp_manifest_path,
            readonly=True,
        )
    budget_path.write_text(orig_budget, encoding="utf-8")

    # 5. Verified python_loop launch manifest stripped of provider_kind fails closed.
    first_launch_path = Path(report["runs"][0]["evidence_refs"]["manifest"]["path"])
    prepared = e6._load_archived_prepared_run(json.loads(first_launch_path.read_text(encoding="utf-8"))["preflight"])
    truth = json.loads((first_run_dir / "private/evaluator/truth.json").read_text(encoding="utf-8"))
    stripped_launch = json.loads(first_launch_path.read_text(encoding="utf-8"))
    stripped_launch["status"] = "python_finished_verified"
    stripped_launch["independent_family"] = prepared["contract"]["holdout_run"]["family"]
    stripped_launch["lab_version"] = prepared["contract"]["holdout_run"]["lab_version"]
    stripped_launch["runtime_index"] = str(first_run_dir / "runtime-index.json")
    stripped_launch["runtime_index_sha256"] = "0" * 64
    stripped_launch.pop("provider_kind", None)
    with pytest.raises(ValueError, match="missing required field 'provider_kind'"):
        e6._verify_run_manifest_and_artifacts(
            first_run_dir, stripped_launch, prepared, truth, verified_run=True, wire=[]
        )

    # 6. Remote experiment manifest paired with authorization=None cohort report fails closed.
    forged_exp = json.loads(exp_manifest_path.read_text(encoding="utf-8"))
    forged_exp["provider_kind"] = "remote"
    forged_exp["provider_host"] = "api.example.invalid"
    forged_exp.pop("manifest_digest", None)
    forged_exp["manifest_digest"] = e6._canonical_sha256(forged_exp)
    rem_exp_path = work / "remote-exp.json"
    dump(rem_exp_path, forged_exp)
    forged_rep = copy.deepcopy(report)
    forged_rep["authorization"] = None
    forged_rep["provenance"]["experiment_manifest"] = {
        "path": str(rem_exp_path),
        "sha256": holdout.digest(rem_exp_path),
    }
    forged_rep.pop("report_digest", None)
    forged_rep["report_digest"] = e6._canonical_sha256(forged_rep)
    with pytest.raises(ValueError, match="missing authorization metadata"):
        e6._reaudit_cohort_report(forged_rep)

    # 7. Legacy report with tampered runs[0].failed (leaving top-level failed_run_rate intact) + symlinked source fails closed.
    legacy_dir = work / "legacy"
    lpath, lrep, _ = _build_offline_cohort(
        work_dir=legacy_dir, label="legacy", baseline_dir=baseline, provider_config=cfg, seeds=seeds,
    )
    for r in lrep["runs"]:
        r.pop("experiment_id", None)
        r.pop("repetition", None)
    for k in ("seeds_by_family", "repetitions", "fingerprints", "provenance", "treatment", "acceptance_criteria", "acceptance", "report_digest"):
        lrep.pop(k, None)
    clean_legacy_path = work / "legacy-clean.json"
    dump(clean_legacy_path, lrep)
    derived_ok = e6.reaudit_legacy_cohort(clean_legacy_path)
    derived_extra_key = copy.deepcopy(derived_ok)
    derived_extra_key["unexpected_shadow"] = True
    derived_extra_key["report_digest"] = e6._canonical_sha256({k: v for k, v in derived_extra_key.items() if k != "report_digest"})
    with pytest.raises(ValueError, match="unexpected or missing top-level keys"):
        e6._verify_legacy_derived_report(derived_extra_key)

    lrep["runs"][0]["failed"] = not lrep["runs"][0]["failed"]
    tampered_legacy_path = work / "legacy-tampered-row.json"
    dump(tampered_legacy_path, lrep)
    with pytest.raises(ValueError, match=r"runs\[0\]\.failed"):
        e6.reaudit_legacy_cohort(tampered_legacy_path)

    sym_legacy = work / "sym-legacy.json"
    sym_legacy.symlink_to(lpath)
    with pytest.raises(ValueError, match="symlink"):
        e6.reaudit_legacy_cohort(sym_legacy)


def test_exact_runtime_space_not_tested_and_counter_hardening(baseline, tmp_path):
    """Exact merged runtime state strings ('NOT TESTED'/'TESTED'), failed run extraction without ledger, and counter validation."""
    work = _work_dir(tmp_path, "rt-exact-counters")

    # 1. Exact failed runtime layout matching main merged Python runtime:
    #    - root run-result.json with status='python_failed' and plural validation_funnels
    #    - validation_state='NOT TESTED' (space, not underscore)
    #    - blocked summaries/access-3.json with status='blocked' and no validation_funnel
    #    - no attempt-ledger.json, signed solver/checkpoint.json referencing candidates_by_task
    failed_candidates = {
        "access-3": {
            "cand-1": {
                "candidate_id": "cand-1",
                "observed": True,
                "eligible": True,
                "admitted": False,
                "executed": False,
                "evidence_accepted": False,
                "validation_state": "NOT TESTED",
                "evidence_refs": [],
            },
            "cand-2": {
                "candidate_id": "cand-2",
                "observed": True,
                "eligible": True,
                "admitted": False,
                "executed": False,
                "evidence_accepted": False,
                "validation_state": "NOT TESTED",
                "evidence_refs": [],
            },
        }
    }
    failed_dir = _write_signed_runtime_run(
        work / "exact-failed",
        run_id="run-exact-failed",
        status="python_failed",
        candidates_by_task=failed_candidates,
        write_checkpoint=True,
        write_ledger=False,
        write_root_result=True,
        summaries={
            "access-3.json": {
                "task_id": "access-3",
                "status": "blocked",
                "blocked_reason": "rate_limit_budget",
            },
        },
        include_evidence_file=False,
    )
    failed_funnel = e6.extract_run_funnel(failed_dir, {"run_id": "run-exact-failed", "status": "python_failed"})
    assert failed_funnel["funnel_present"] is True
    assert failed_funnel["status"] == "complete"
    assert (
        failed_funnel["observed"],
        failed_funnel["eligible"],
        failed_funnel["admitted"],
        failed_funnel["executed"],
        failed_funnel["evidence_accepted"],
    ) == (2, 2, 0, 0, 0)

    # 2. Verified runtime run using exact context-archive/tool-result-<sha>.json + 'TESTED' & 'NOT TESTED'.
    tool_run = work / "tool-result-verified"
    ev_path = tool_run / "solver/context-archive/tool-result-abc123.json"
    ev_path.parent.mkdir(parents=True, exist_ok=True)
    dump(ev_path, {"validation_id": "val-tool-1", "state": "TESTED", "status": "verified"})
    ev_sha = holdout.digest(ev_path)
    verified_candidates = {
        "access-3": {
            "cand-1": {
                "candidate_id": "cand-1",
                "observed": True,
                "eligible": True,
                "admitted": True,
                "executed": True,
                "evidence_accepted": True,
                "validation_state": "TESTED",
                "evidence_refs": [
                    {
                        "validation_id": "val-tool-1",
                        "source_artifact": "context-archive/tool-result-abc123.json",
                        "source_sha256": ev_sha,
                    }
                ],
            },
            "cand-2": {
                "candidate_id": "cand-2",
                "observed": True,
                "eligible": True,
                "admitted": True,
                "executed": False,
                "evidence_accepted": False,
                "validation_state": "NOT TESTED",
                "evidence_refs": [],
            },
        }
    }
    _write_signed_runtime_run(
        tool_run,
        run_id="run-tool-verified",
        status="python_finished_verified",
        candidates_by_task=verified_candidates,
        write_checkpoint=True,
        write_ledger=True,
        write_root_result=True,
        include_evidence_file=False,
    )
    verified_funnel = e6.extract_run_funnel(tool_run, {"run_id": "run-tool-verified", "status": "python_finished_verified"})
    assert verified_funnel["funnel_present"] is True
    assert verified_funnel["status"] == "complete"
    assert (
        verified_funnel["observed"],
        verified_funnel["eligible"],
        verified_funnel["admitted"],
        verified_funnel["executed"],
        verified_funnel["evidence_accepted"],
    ) == (2, 2, 2, 1, 1)

    # 3. Contradictory validation_state='TESTED' with evidence_accepted=False fails closed.
    bad_tested_dir = _write_signed_runtime_run(
        work / "bad-tested-flag",
        run_id="run-bad-tested-flag",
        status="python_failed",
        candidates_by_task={
            "access-3": {
                "cand-1": {
                    "candidate_id": "cand-1",
                    "observed": True,
                    "eligible": True,
                    "admitted": True,
                    "executed": True,
                    "evidence_accepted": False,
                    "validation_state": "TESTED",
                    "evidence_refs": [],
                }
            }
        },
        write_checkpoint=True,
        write_ledger=False,
        write_root_result=True,
        include_evidence_file=False,
    )
    with pytest.raises(ValueError, match="without evidence_accepted"):
        e6.extract_run_funnel(bad_tested_dir, {"run_id": "run-bad-tested-flag", "status": "python_failed"})

    # 4. Negative/bool launch usage counters and negative budget event charged counter fail closed.
    cfg = _write_llm_config(work / "llm.json", "http://127.0.0.1:49999/v1")
    seeds = {
        "readonly-api-access-control": [4141],
        "readonly-sql-injection": [4142],
        "readonly-template-injection": [4143],
    }
    _cohort_path, report, _ = _build_offline_cohort(
        work_dir=work / "cohort", label="after", baseline_dir=baseline, provider_config=cfg, seeds=seeds,
    )

    launch_path = Path(report["runs"][0]["evidence_refs"]["manifest"]["path"])
    run_dir = launch_path.parent
    manifest = json.loads(launch_path.read_text(encoding="utf-8"))
    prepared = e6._load_archived_prepared_run(manifest["preflight"])
    truth = json.loads((run_dir / "private/evaluator/truth.json").read_text(encoding="utf-8"))

    neg_calls = copy.deepcopy(manifest)
    neg_calls["llm_calls"] = -1
    with pytest.raises(ValueError, match="llm_calls"):
        e6._verify_run_manifest_and_artifacts(run_dir, neg_calls, prepared, truth, verified_run=False, wire=None)

    neg_wall = copy.deepcopy(manifest)
    neg_wall["wall_clock_seconds"] = -0.5
    with pytest.raises(ValueError, match="wall_clock_seconds"):
        e6._verify_run_manifest_and_artifacts(run_dir, neg_wall, prepared, truth, verified_run=False, wire=None)

    budget_path = run_dir / "private/budget.json"
    orig_budget = budget_path.read_text(encoding="utf-8")
    tampered_budget = json.loads(orig_budget)
    tampered_budget["events"] = [{"reserved": 1, "charged": -1, "measurement_valid": True}]
    budget_path.write_text(json.dumps(tampered_budget, indent=2) + "\n", encoding="utf-8")
    try:
        with pytest.raises(ValueError, match=r"events\[0\]\.charged"):
            e6._verify_run_manifest_and_artifacts(run_dir, manifest, prepared, truth, verified_run=False, wire=None)
    finally:
        budget_path.write_text(orig_budget, encoding="utf-8")
