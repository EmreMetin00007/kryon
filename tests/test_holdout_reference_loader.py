"""UNITONLY offline regressions for the test-only holdout reference loader.

These tests use honest synthetic run directories and stub runners under pytest
tmp_path to verify fail-closed path/artifact validation, path-only isolation
wiring, and per-invocation lazy caching/reuse. They never count as measured
native or holdout recall evidence.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import full_agent_holdout as holdout
import full_agent_preflight as preflight
from fixtures.holdout_references import (
    API_FAMILY,
    CANONICAL_API_SEED,
    CANONICAL_SQL_SEED,
    SQL_FAMILY,
    bind_prior_runs,
    clear_reference_cache,
    collect_prior_evidence_paths,
    collect_prior_hashes,
    ensure_api_and_sql_reference_runs,
    ensure_api_reference_run,
    load_reference_metrics,
    reference_probed_files,
    register_reference_run,
    validate_reference_run_dir,
)
from test_full_agent_api_holdout import APIProvider
from test_full_agent_sqli_holdout import SQLProvider
from test_full_agent_ssti_holdout import SSTIProvider
from test_full_agent_traversal_holdout import TraversalProvider


def _synthetic_metrics(family: str, *, positives: int = 8, tp: int = 8, fp: int = 0,
                       closure_verified: bool = True, failed: bool = False) -> dict:
    return {
        "schema": "independent-holdout-metrics/1",
        "run_id": f"unitonly-{family}",
        "family": family,
        "recall": {"numerator": tp, "denominator": positives, "value": tp / positives},
        "negative_coverage": {"numerator": 8, "denominator": 8, "value": 1.0},
        "false_positives": {"numerator": fp, "denominator": 8, "value": fp / 8},
        "cases": [{"case": f"c-{i}", "path": f"/p/{i}", "family": family, "expected": "positive"} for i in range(positives)],
        "closure_verified": closure_verified,
        "failed": failed,
        "usage": {
            "llm_calls": 10,
            "http_requests": 40,
            "tokens_used": 1000,
            "prompt_tokens": 800,
            "completion_tokens": 200,
            "wall_clock_seconds": 1.0,
            "cost_usd": None,
            "cost_known": False,
            "unknown_cost_is_zero": False,
        },
        "provider_kind": "scripted_loopback",
        "paid_provider_calls": 0,
        "models": {"planner": "integration/planner", "worker": "integration/worker"},
        "effective_limits": {"http_requests_per_seed": 300},
        "not_tested": {"untested_dimensions": ["paid_remote_model_generalization"]},
        "contract": preflight.native_contract({}, {}, 100)["holdout"],
    }


def _write_synthetic_run(
    root: Path,
    family: str,
    *,
    canary: str = "CANARY_EVALUATOR_TRUTH_DO_NOT_LEAK",
    include_policy: bool = False,
    metrics_override: dict | None = None,
) -> Path:
    (root / "solver").mkdir(parents=True, exist_ok=True)
    (root / "private/evaluator").mkdir(parents=True, exist_ok=True)
    (root / "private/state/validations").mkdir(parents=True, exist_ok=True)
    (root / "solver/closure.json").write_text(json.dumps({"payload": {"canary": canary}}), encoding="utf-8")
    (root / "solver/attempts.jsonl").write_text(json.dumps({"note": canary}) + "\n", encoding="utf-8")
    (root / "private/evaluator/selection.json").write_text(json.dumps({"family": family, "canary": canary}), encoding="utf-8")
    (root / "private/evaluator/truth.json").write_text(json.dumps([{"expected": "positive", "canary": canary}]), encoding="utf-8")
    (root / "private/evaluator/wire.json").write_text(json.dumps([{"method": "GET", "path": "/x", "canary": canary}]), encoding="utf-8")
    (root / "private/evaluator/expected-counts.json").write_text(json.dumps({"positive": 8, "negative": 8}), encoding="utf-8")
    (root / "private/evaluator/lab-source.py").write_text(f"# synthetic unitonly stub {canary}\n", encoding="utf-8")
    metrics = metrics_override if metrics_override is not None else _synthetic_metrics(family)
    (root / "private/evaluator/metrics.json").write_text(json.dumps(metrics), encoding="utf-8")
    (root / "private/state/validations/val-1.json").write_text(json.dumps({"id": "val-1", "canary": canary}), encoding="utf-8")
    if include_policy:
        (root / "private/state/holdout-program-policy.json").write_text(json.dumps({"path_traversal": {}}), encoding="utf-8")
    return root


def test_unitonly_holdout_modules_have_no_hardcoded_tmp_canonical_runs():
    import test_full_agent_sqli_holdout as sqli_mod
    import test_full_agent_ssti_holdout as ssti_mod
    import test_full_agent_traversal_holdout as trav_mod

    for mod in (sqli_mod, ssti_mod, trav_mod):
        assert not hasattr(mod, "CANONICAL_API_RUN")
        assert not hasattr(mod, "CANONICAL_SQL_RUN")
        source = Path(mod.__file__).read_text(encoding="utf-8")
        assert "/tmp/cco-work/full-agent-integration/handoff_closure-" not in source
        assert "CCO_CANONICAL_" not in source
    assert SQLProvider.prior_reference_runs == ()
    assert SSTIProvider.prior_reference_runs == ()
    assert TraversalProvider.prior_reference_runs == ()


def test_unitonly_validate_reference_run_dir_accepts_complete_synthetic_run(tmp_path):
    run_dir = _write_synthetic_run(tmp_path / "native-api", API_FAMILY)
    assert validate_reference_run_dir(run_dir, API_FAMILY) == run_dir.resolve()


@pytest.mark.parametrize("fault", [
    "missing_dir",
    "symlink_dir",
    "missing_metrics",
    "missing_closure",
    "missing_validation",
    "empty_closure",
    "symlink_metrics",
    "wrong_family",
    "unverified_closure",
    "failed_run",
    "incomplete_recall",
    "false_positive",
])
def test_unitonly_validate_reference_run_dir_fails_closed(tmp_path, fault):
    run_dir = _write_synthetic_run(tmp_path / "native-api", API_FAMILY)
    if fault == "missing_dir":
        target = tmp_path / "does-not-exist"
        with pytest.raises(FileNotFoundError):
            validate_reference_run_dir(target, API_FAMILY)
        return
    if fault == "symlink_dir":
        link = tmp_path / "symlink-run"
        link.symlink_to(run_dir, target_is_directory=True)
        with pytest.raises(ValueError, match="symlink"):
            validate_reference_run_dir(link, API_FAMILY)
        return
    if fault == "missing_metrics":
        (run_dir / "private/evaluator/metrics.json").unlink()
        exc = FileNotFoundError
    elif fault == "missing_closure":
        (run_dir / "solver/closure.json").unlink()
        exc = FileNotFoundError
    elif fault == "missing_validation":
        (run_dir / "private/state/validations/val-1.json").unlink()
        exc = FileNotFoundError
    elif fault == "empty_closure":
        (run_dir / "solver/closure.json").write_bytes(b"")
        exc = ValueError
    elif fault == "symlink_metrics":
        metrics = run_dir / "private/evaluator/metrics.json"
        other = tmp_path / "other.json"
        other.write_text(metrics.read_text(encoding="utf-8"), encoding="utf-8")
        metrics.unlink()
        metrics.symlink_to(other)
        exc = ValueError
    else:
        overrides = {
            "wrong_family": _synthetic_metrics(SQL_FAMILY),
            "unverified_closure": _synthetic_metrics(API_FAMILY, closure_verified=False),
            "failed_run": _synthetic_metrics(API_FAMILY, failed=True),
            "incomplete_recall": _synthetic_metrics(API_FAMILY, tp=7),
            "false_positive": _synthetic_metrics(API_FAMILY, fp=1),
        }
        (run_dir / "private/evaluator/metrics.json").write_text(json.dumps(overrides[fault]), encoding="utf-8")
        exc = ValueError
    with pytest.raises(exc):
        validate_reference_run_dir(run_dir, API_FAMILY)


def test_unitonly_collect_prior_evidence_paths_exports_only_paths_never_truth_or_bytes(tmp_path):
    canary = "CANARY_EVALUATOR_TRUTH_DO_NOT_LEAK"
    api_dir = _write_synthetic_run(tmp_path / "api", API_FAMILY, canary=canary)
    sql_dir = _write_synthetic_run(tmp_path / "sql", SQL_FAMILY, canary=canary, include_policy=True)

    paths = collect_prior_evidence_paths((api_dir, sql_dir), include_policy=True)
    assert len(paths) == len(set(paths))
    assert str(api_dir / "solver/closure.json") in paths
    assert str(api_dir / "private/evaluator/truth.json") in paths
    assert str(api_dir / "private/state/validations/val-1.json") in paths
    assert str(sql_dir / "private/state/holdout-program-policy.json") in paths
    assert all(isinstance(item, str) and canary not in item for item in paths)

    source = tmp_path / "source"
    source.mkdir()
    for provider_cls, refs, expected_vector in (
        (SQLProvider, (api_dir,), "injection-sqli"),
        (SSTIProvider, (api_dir, sql_dir), "injection-ssti"),
        (TraversalProvider, (api_dir, sql_dir), "file-access"),
    ):
        bound_cls = bind_prior_runs(provider_cls, refs)
        assert bound_cls.__module__ == provider_cls.__module__
        assert bound_cls.vector == expected_vector
        assert provider_cls.prior_reference_runs == ()
        provider = bound_cls(tmp_path, source, "handoff_closure", "unitonly-key", previous_runs=())
        try:
            expected = {str(path) for ref in refs for path in reference_probed_files(ref, include_policy=(provider_cls is TraversalProvider))}
            assert expected <= set(provider.previous_evidence_paths)
            assert all(canary not in entry for entry in provider.previous_evidence_paths)
        finally:
            provider.close()


def test_unitonly_lazy_generation_and_per_invocation_reuse(tmp_path):
    clear_reference_cache()
    calls: list[tuple[str, int, tuple[Path, ...]]] = []

    def stub_runner(_integration_run, _prop, *, seed, family, provider_class):
        calls.append((family, seed, getattr(provider_class, "prior_reference_runs", ())))
        run_dir = _write_synthetic_run(tmp_path / f"run-{len(calls)}-{family}", family)
        metrics = json.loads((run_dir / "private/evaluator/metrics.json").read_text(encoding="utf-8"))
        return {
            "directory": run_dir.parent,
            "private": run_dir / "private",
            "work": run_dir / "solver",
            "manifest": {"independent_family": family, "seed": seed},
            "metrics": metrics,
        }

    try:
        api_first = ensure_api_reference_run(
            None, None, runner=stub_runner, provider_class=APIProvider,
        )
        api_second = ensure_api_reference_run(
            None, None, runner=stub_runner, provider_class=APIProvider,
        )
        assert api_first["run_dir"] == api_second["run_dir"]
        assert len(calls) == 1 and calls[0] == (API_FAMILY, CANONICAL_API_SEED, ())

        api_ref, sql_ref = ensure_api_and_sql_reference_runs(
            None,
            None,
            runner=stub_runner,
            api_provider_class=APIProvider,
            sql_provider_class=SQLProvider,
        )
        assert api_ref["run_dir"] == api_first["run_dir"]
        assert len(calls) == 2
        assert calls[1] == (SQL_FAMILY, CANONICAL_SQL_SEED, (api_ref["run_dir"],))

        # Subsequent invocation within the same pytest process reuses both API & SQL.
        api_again, sql_again = ensure_api_and_sql_reference_runs(
            None,
            None,
            runner=stub_runner,
            api_provider_class=APIProvider,
            sql_provider_class=SQLProvider,
        )
        assert api_again["run_dir"] == api_ref["run_dir"]
        assert sql_again["run_dir"] == sql_ref["run_dir"]
        assert len(calls) == 2

        # Registering an actual SQL run directly (as test_full_agent_sqli_holdout does)
        # lets downstream SSTI/Traversal reuse it with zero extra SQL runs.
        clear_reference_cache()
        calls.clear()
        api_a = ensure_api_reference_run(None, None, runner=stub_runner, provider_class=APIProvider)
        explicit_sql_dir = _write_synthetic_run(tmp_path / "explicit-sql", SQL_FAMILY)
        register_reference_run(SQL_FAMILY, {
            "directory": explicit_sql_dir.parent,
            "private": explicit_sql_dir / "private",
            "work": explicit_sql_dir / "solver",
            "manifest": {"independent_family": SQL_FAMILY},
            "metrics": json.loads((explicit_sql_dir / "private/evaluator/metrics.json").read_text(encoding="utf-8")),
        })
        api_b, sql_b = ensure_api_and_sql_reference_runs(
            None,
            None,
            runner=stub_runner,
            api_provider_class=APIProvider,
            sql_provider_class=SQLProvider,
        )
        assert api_b["run_dir"] == api_a["run_dir"]
        assert sql_b["run_dir"] == explicit_sql_dir.resolve()
        assert len(calls) == 1

        # Deleting a cached metrics file invalidates the stale entry and regenerates cleanly.
        (api_a["run_dir"] / "private/evaluator/metrics.json").unlink()
        api_regen = ensure_api_reference_run(None, None, runner=stub_runner, provider_class=APIProvider)
        assert api_regen["run_dir"] != api_a["run_dir"]
        assert len(calls) == 2
    finally:
        clear_reference_cache()


def test_unitonly_load_reference_metrics_and_three_family_synthetic_aggregate(tmp_path):
    api_dir = _write_synthetic_run(tmp_path / "api", API_FAMILY)
    sql_dir = _write_synthetic_run(tmp_path / "sql", SQL_FAMILY)
    ssti_metrics = _synthetic_metrics("readonly-template-injection")

    prior, hashes = collect_prior_hashes((api_dir, sql_dir), digest_fn=holdout.digest)
    assert len(prior) >= 16 and len(hashes) == len(prior)

    api_metrics, sql_metrics = load_reference_metrics(
        (api_dir, sql_dir),
        expected_families=(API_FAMILY, SQL_FAMILY),
    )
    summary = holdout.aggregate([api_metrics, sql_metrics, ssti_metrics], ssti_metrics["contract"])
    assert summary["status"] == "passed"
    assert len(summary["families"]) == 3
    assert summary["positives"] == summary["negatives"] == 24
    assert summary["overall_recall"] == {"numerator": 24, "denominator": 24}
    assert summary["negative_coverage"] == {"numerator": 24, "denominator": 24}
    assert summary["false_positives"] == {"numerator": 0, "denominator": 24}


def test_unitonly_traversal_provider_also_probes_previous_runs_policy_and_hash_check_rejects_symlink(tmp_path):
    api_dir = _write_synthetic_run(tmp_path / "api", API_FAMILY)
    sql_dir = _write_synthetic_run(tmp_path / "sql", SQL_FAMILY)
    prev_trav = _write_synthetic_run(tmp_path / "prev-trav", "readonly-path-traversal", include_policy=True)
    source = tmp_path / "source"
    source.mkdir()

    bound_cls = bind_prior_runs(TraversalProvider, (api_dir, sql_dir))
    provider = bound_cls(tmp_path, source, "handoff_closure", "unitonly-key", previous_runs=(prev_trav,))
    try:
        assert str(prev_trav / "private/state/holdout-program-policy.json") in provider.previous_evidence_paths
        assert str(api_dir / "private/evaluator/metrics.json") in provider.previous_evidence_paths
        assert str(sql_dir / "private/evaluator/metrics.json") in provider.previous_evidence_paths
    finally:
        provider.close()

    secret = tmp_path / "secret.txt"
    secret.write_text("host-only", encoding="utf-8")
    (api_dir / "solver/leak.json").symlink_to(secret)
    with pytest.raises(ValueError, match="symlink"):
        collect_prior_hashes((api_dir,), digest_fn=holdout.digest)
