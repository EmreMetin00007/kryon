"""Test-only loader and lazy runner for independent holdout reference runs.

Historical holdout tests must never rely on hardcoded `/tmp/...` paths or
pre-existing host run state. This module validates reference run directories
fail-closed (no symlinks, no path escapes, non-empty signed/evaluator files),
lazily produces legitimate scripted-native + loopback API/SQL baseline runs
via the real integration runner when absent, reuses valid per-invocation runs
within the current pytest process, and exposes ONLY file paths to solver
isolation probes (never truth labels, prior bytes, or model answers).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable, Iterable, Sequence

API_FAMILY = "readonly-api-access-control"
SQL_FAMILY = "readonly-sql-injection"
CANONICAL_API_SEED = 271828182845904
CANONICAL_SQL_SEED = 314159265358979

REQUIRED_RUN_FILES = (
    "solver/closure.json",
    "solver/attempts.jsonl",
    "private/evaluator/metrics.json",
    "private/evaluator/selection.json",
    "private/evaluator/truth.json",
    "private/evaluator/wire.json",
    "private/evaluator/expected-counts.json",
    "private/evaluator/lab-source.py",
)

_SESSION_REFERENCE_RUNS: dict[tuple[int, str], dict] = {}


def clear_reference_cache() -> None:
    """Clear per-process reference run cache entries for the current PID."""
    pid = os.getpid()
    for key in [entry for entry in _SESSION_REFERENCE_RUNS if entry[0] == pid]:
        _SESSION_REFERENCE_RUNS.pop(key, None)


def _coerce_run_dir(entry: Path | str | dict) -> Path:
    if isinstance(entry, dict):
        if "run_dir" in entry:
            return Path(entry["run_dir"])
        if "private" in entry:
            return Path(entry["private"]).parent
    return Path(entry)


def _validated_run_file(root: Path, candidate: Path) -> Path:
    """Ensure candidate is a non-empty regular file strictly under root without symlinks."""
    if candidate.is_symlink():
        raise ValueError(f"reference run artifact must not be a symlink: {candidate}")
    root_resolved = root.resolve(strict=True)
    for parent in candidate.parents:
        if parent == root:
            break
        if root not in parent.parents:
            break
        if parent.is_symlink():
            raise ValueError(f"reference run directory must not be a symlink: {parent}")
    if not candidate.exists():
        raise FileNotFoundError(f"reference run artifact missing: {candidate}")
    resolved = candidate.resolve(strict=True)
    if root_resolved not in resolved.parents:
        raise ValueError(f"reference run artifact escapes run root: {candidate}")
    if not candidate.is_file():
        raise ValueError(f"reference run artifact must be a regular file: {candidate}")
    if candidate.stat().st_size <= 0:
        raise ValueError(f"reference run artifact must be non-empty: {candidate}")
    return candidate


def _validate_metrics_payload(metrics: dict, expected_family: str, metrics_path: Path) -> None:
    if not isinstance(metrics, dict):
        raise ValueError(f"invalid metrics payload in {metrics_path}")
    if metrics.get("schema") != "independent-holdout-metrics/1":
        raise ValueError(f"unexpected metrics schema in {metrics_path}: {metrics.get('schema')!r}")
    if metrics.get("family") != expected_family:
        raise ValueError(
            f"reference run family mismatch in {metrics_path}: "
            f"expected {expected_family!r}, got {metrics.get('family')!r}"
        )
    if metrics.get("closure_verified") is not True or metrics.get("failed") is True:
        raise ValueError(f"reference run did not verify clean closure: {metrics_path}")
    if metrics.get("recall") != {"numerator": 8, "denominator": 8, "value": 1.0}:
        raise ValueError(f"reference run recall incomplete in {metrics_path}: {metrics.get('recall')!r}")
    if metrics.get("negative_coverage") != {"numerator": 8, "denominator": 8, "value": 1.0}:
        raise ValueError(
            f"reference run negative_coverage incomplete in {metrics_path}: {metrics.get('negative_coverage')!r}"
        )
    if metrics.get("false_positives") != {"numerator": 0, "denominator": 8, "value": 0.0}:
        raise ValueError(
            f"reference run has false positives in {metrics_path}: {metrics.get('false_positives')!r}"
        )


def validate_reference_run_dir(run_dir: Path | str, expected_family: str) -> Path:
    """Fail-closed validation of a completed holdout reference run directory."""
    root = Path(run_dir)
    if root.is_symlink():
        raise ValueError(f"reference run directory must not be a symlink: {root}")
    if not root.is_dir():
        raise FileNotFoundError(f"reference run directory missing: {root}")
    for relative in REQUIRED_RUN_FILES:
        _validated_run_file(root, root / relative)
    validations_dir = root / "private/state/validations"
    if validations_dir.is_symlink() or not validations_dir.is_dir():
        raise FileNotFoundError(f"reference validations directory missing: {validations_dir}")
    validation_files = [
        _validated_run_file(root, path)
        for path in sorted(validations_dir.glob("*.json"))
    ]
    if not validation_files:
        raise FileNotFoundError(f"reference run has no signed validation artifacts: {validations_dir}")
    metrics_path = root / "private/evaluator/metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    _validate_metrics_payload(metrics, expected_family, metrics_path)
    return root.resolve(strict=True)


def reference_probed_files(run_dir: Path | str, *, include_policy: bool = False) -> list[Path]:
    """Return all host-only/prior files of a validated run that isolation probes must deny."""
    root = Path(run_dir)
    if root.is_symlink() or not root.is_dir():
        raise FileNotFoundError(f"reference run directory missing: {root}")
    candidates: list[Path] = [
        _validated_run_file(root, root / "solver/closure.json"),
        _validated_run_file(root, root / "solver/attempts.jsonl"),
    ]
    for folder in ("private/evaluator", "private/state/validations"):
        directory = root / folder
        if directory.is_symlink() or not directory.is_dir():
            raise FileNotFoundError(f"reference evidence directory missing: {directory}")
        pattern = "*.json" if folder.endswith("validations") else "*"
        entries = [
            _validated_run_file(root, path)
            for path in sorted(directory.glob(pattern))
            if not path.is_dir() or path.is_symlink()
        ]
        if not entries:
            raise FileNotFoundError(f"reference evidence directory is empty: {directory}")
        candidates.extend(entries)
    if include_policy:
        policy = root / "private/state/holdout-program-policy.json"
        if policy.exists() or policy.is_symlink():
            candidates.append(_validated_run_file(root, policy))
    return list(dict.fromkeys(candidates))


def collect_prior_evidence_paths(
    run_dirs: Iterable[Path | str | dict],
    *,
    include_policy: bool = False,
) -> list[str]:
    """Extract ONLY string file paths from prior reference runs for isolation probes.

    Never reads or forwards truth labels, prior evidence bytes, or model answers.
    """
    paths: list[str] = []
    for entry in run_dirs:
        root = _coerce_run_dir(entry)
        for path in reference_probed_files(root, include_policy=include_policy):
            paths.append(str(path))
    return list(dict.fromkeys(paths))


def collect_prior_hashes(
    run_dirs: Sequence[Path | str | dict],
    *,
    digest_fn: Callable[[Path | str], str],
) -> tuple[list[Path], dict[str, str]]:
    """Collect regular prior artifact paths and SHA-256 digests to verify immutability."""
    prior: list[Path] = []
    for entry in run_dirs:
        root = _coerce_run_dir(entry)
        _validated_run_file(root, root / "private/evaluator/metrics.json")
        for sub in ("solver", "private/evaluator", "private/state/validations"):
            subdir = root / sub
            if subdir.is_symlink() or not subdir.is_dir():
                raise FileNotFoundError(f"reference directory missing: {subdir}")
            for path in sorted(subdir.rglob("*")):
                if path.is_symlink():
                    raise ValueError(f"reference artifact must not be a symlink: {path}")
                if path.is_file():
                    # Zero-byte lock placeholders carry no evidence and are
                    # not run artifacts; every real artifact stays fail-closed.
                    if path.suffix == ".lock" and path.stat().st_size == 0:
                        continue
                    prior.append(_validated_run_file(root, path))
    if not prior:
        raise ValueError("no prior reference artifacts found")
    unique_prior = list(dict.fromkeys(prior))
    return unique_prior, {str(path): digest_fn(path) for path in unique_prior}


def load_reference_metrics(
    run_dirs: Sequence[Path | str | dict],
    *,
    expected_families: Sequence[str],
) -> list[dict]:
    """Validate each reference run directory and load ONLY its evaluator metrics.json."""
    if len(run_dirs) != len(expected_families):
        raise ValueError("run_dirs and expected_families must have matching lengths")
    loaded: list[dict] = []
    for entry, family in zip(run_dirs, expected_families):
        root = validate_reference_run_dir(_coerce_run_dir(entry), family)
        loaded.append(json.loads((root / "private/evaluator/metrics.json").read_text(encoding="utf-8")))
    return loaded


def bind_prior_runs(provider_class: type, prior_runs: Sequence[Path | str | dict]) -> type:
    """Return a provider subclass bound to explicit prior reference run paths only."""
    refs = tuple(_coerce_run_dir(entry) for entry in prior_runs)

    class BoundReferenceProvider(provider_class):  # type: ignore[valid-type, misc]
        __module__ = provider_class.__module__
        prior_reference_runs = refs

    BoundReferenceProvider.__name__ = f"Bound{provider_class.__name__}"
    BoundReferenceProvider.__qualname__ = f"Bound{provider_class.__qualname__}"
    return BoundReferenceProvider


def _build_reference_record(run: dict, expected_family: str) -> dict:
    run_dir = validate_reference_run_dir(Path(run["private"]).parent, expected_family)
    return {
        "family": expected_family,
        "run_dir": run_dir,
        "private": run_dir / "private",
        "work": run_dir / "solver",
        "directory": Path(run["directory"]),
        "manifest": run["manifest"],
        "metrics": run["metrics"],
    }


def register_reference_run(expected_family: str, run: dict) -> dict:
    """Validate and register an actual reference run for per-invocation reuse."""
    record = _build_reference_record(run, expected_family)
    _SESSION_REFERENCE_RUNS[(os.getpid(), expected_family)] = record
    return record


def _cached_reference_run(expected_family: str) -> dict | None:
    key = (os.getpid(), expected_family)
    cached = _SESSION_REFERENCE_RUNS.get(key)
    if cached is None:
        return None
    try:
        validate_reference_run_dir(cached["run_dir"], expected_family)
    except (OSError, ValueError, json.JSONDecodeError):
        _SESSION_REFERENCE_RUNS.pop(key, None)
        return None
    return cached


def ensure_api_reference_run(
    integration_run,
    record_testsuite_property,
    *,
    runner: Callable[..., dict],
    provider_class: type,
    seed: int = CANONICAL_API_SEED,
) -> dict:
    """Return a validated API reference run, lazily executing one if not yet cached."""
    cached = _cached_reference_run(API_FAMILY)
    if cached is not None:
        return cached
    run = runner(
        integration_run,
        record_testsuite_property,
        seed=seed,
        family=API_FAMILY,
        provider_class=provider_class,
    )
    return register_reference_run(API_FAMILY, run)


def ensure_sql_reference_run(
    integration_run,
    record_testsuite_property,
    *,
    runner: Callable[..., dict],
    api_provider_class: type,
    sql_provider_class: type,
    api_seed: int = CANONICAL_API_SEED,
    sql_seed: int = CANONICAL_SQL_SEED,
) -> dict:
    """Return a validated SQL reference run, lazily executing API+SQL as needed."""
    api_ref = ensure_api_reference_run(
        integration_run,
        record_testsuite_property,
        runner=runner,
        provider_class=api_provider_class,
        seed=api_seed,
    )
    cached = _cached_reference_run(SQL_FAMILY)
    if cached is not None:
        return cached
    bound_sql = bind_prior_runs(sql_provider_class, (api_ref["run_dir"],))
    run = runner(
        integration_run,
        record_testsuite_property,
        seed=sql_seed,
        family=SQL_FAMILY,
        provider_class=bound_sql,
    )
    return register_reference_run(SQL_FAMILY, run)


def ensure_api_and_sql_reference_runs(
    integration_run,
    record_testsuite_property,
    *,
    runner: Callable[..., dict],
    api_provider_class: type,
    sql_provider_class: type,
    api_seed: int = CANONICAL_API_SEED,
    sql_seed: int = CANONICAL_SQL_SEED,
) -> tuple[dict, dict]:
    """Return validated (API, SQL) reference runs, lazily creating and caching them."""
    api_ref = ensure_api_reference_run(
        integration_run,
        record_testsuite_property,
        runner=runner,
        provider_class=api_provider_class,
        seed=api_seed,
    )
    sql_ref = ensure_sql_reference_run(
        integration_run,
        record_testsuite_property,
        runner=runner,
        api_provider_class=api_provider_class,
        sql_provider_class=sql_provider_class,
        api_seed=api_seed,
        sql_seed=sql_seed,
    )
    return api_ref, sql_ref
