"""Offline frozen paired regressions for E6 multi-seed/repetition experiments."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile

import pytest

import agent_cli
import full_agent_e6_benchmark as e6
import full_agent_holdout as holdout
import full_agent_launcher as launcher
from full_agent_provider import dump
from test_full_agent_e6_benchmark import _write_llm_config
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
