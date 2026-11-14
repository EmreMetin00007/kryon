#!/usr/bin/env python3
"""E6 real-model holdout benchmark runner, cohort auditor, and paired comparator.

Plan-only execution is the default (0 LLM calls, 0 target HTTP requests). Live
non-loopback provider usage is fail-closed unless explicitly authorized by the
operator. Unknown usage, funnel counts, or costs remain None and are never
coerced to zero. Strict paired comparison re-audits underlying manifests and
artifacts read-only from disk and rejects unverifiable, tampered, unpaired, or
legacy inputs.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import Any, Sequence
from urllib.parse import urlsplit

import full_agent_holdout as holdout
import full_agent_launcher as launcher
import full_agent_preflight as preflight
import llm_config
from full_agent_provider import dump
from runtime_paths import runtime_root

ROOT = runtime_root()
SCHEMA_SUITE = "full-agent-e6-suite/1"
SCHEMA_EXPERIMENT_MANIFEST = "full-agent-e6-experiment-manifest/1"
SCHEMA_COHORT = "full-agent-e6-cohort/1"
SCHEMA_COMPARE = "full-agent-e6-comparison/1"
SCHEMA_LEGACY_DERIVED = "full-agent-e6-legacy-derived/1"
DEFAULT_FAMILIES = (
    "readonly-api-access-control",
    "readonly-sql-injection",
    "readonly-template-injection",
)
DEFAULT_SEEDS = {
    "readonly-api-access-control": 314159,
    "readonly-sql-injection": 271828,
    "readonly-template-injection": 141421,
    "readonly-path-traversal": 161803,
}
MINIMUM_FAMILIES = 3
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
VALID_TREATMENT_DIMENSIONS = ("runtime", "prompt_catalog", "provider_config")
FUNNEL_STAGES = ("observed", "eligible", "admitted", "executed", "evidence_accepted")
EVALUATOR_RUNTIME_PATHS = frozenset({"scripts/full_agent_holdout.py"})
PROVIDER_EXCLUDED_RUNTIME_PATHS = frozenset({
    "config/llm.json",
    ".codex/scope.json",
    ".codex/program-policy.json",
})
PROMPT_CATALOG_PATHS = frozenset({
    "config/mcp-core-tools.json",
    "config/tool-capabilities.json",
    "config/mcp-servers.json",
    "config/profiles.json",
    "config/executor-contract.example.json",
    "scripts/full_agent_python_solver.py",
    "scripts/full_agent_python_broker.py",
    "scripts/full_agent_executor.py",
    "scripts/full_agent_provider.py",
    "scripts/full_agent_summary_feedback.py",
})


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _canonical_sha256(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _delta(before: Any, after: Any) -> int | float | None:
    """Return signed difference (after - before) when both measurements exist."""
    if (before is None or after is None or isinstance(before, bool) or isinstance(after, bool)
            or not isinstance(before, (int, float)) or not isinstance(after, (int, float))):
        return None
    return after - before


def _normalize_ceilings(limits: Any) -> dict[str, int] | None:
    """Extract the invariant token/HTTP/time ceilings shared across a cohort."""
    if not isinstance(limits, dict):
        return None
    keys = ("http_requests_per_seed", "llm_tokens_per_seed", "seconds_per_seed")
    if any(type(limits.get(key)) is not int or limits[key] <= 0 for key in keys):
        return None
    return {key: int(limits[key]) for key in keys}


def _output_outside_protected(output: str | Path, *protected_dirs: str | Path | None) -> Path:
    resolved = Path(output).expanduser().resolve()
    for protected in (ROOT, *(Path(p).expanduser().resolve() for p in protected_dirs if p is not None)):
        if resolved == protected or protected in resolved.parents or resolved in protected.parents:
            raise ValueError("output must remain outside repository, preflight, and baseline directories")
    return resolved


def _normalize_family_seeds(chosen: list[str], seeds: Any) -> dict[str, list[int]]:
    """Normalize single-seed or multi-seed inputs into validated per-family seed lists."""
    if seeds is None:
        return {family: [DEFAULT_SEEDS[family]] for family in chosen}
    seed_map: dict[str, list[int]] = {}
    if isinstance(seeds, dict):
        if set(seeds) != set(chosen):
            raise ValueError("seed mapping keys must match selected families")
        for family in chosen:
            raw = seeds[family]
            if type(raw) is int:
                seed_list = [raw]
            elif isinstance(raw, (list, tuple)) and raw:
                seed_list = list(raw)
            else:
                raise ValueError(f"invalid seed specification for family {family}")
            seed_map[family] = seed_list
    else:
        raw_list = list(seeds)
        if len(raw_list) != len(chosen):
            raise ValueError("seed count must match selected family count")
        for family, raw in zip(chosen, raw_list):
            if type(raw) is int:
                seed_list = [raw]
            elif isinstance(raw, (list, tuple)) and raw:
                seed_list = list(raw)
            else:
                raise ValueError(f"invalid seed specification for family {family}")
            seed_map[family] = seed_list
    for family, family_seeds in seed_map.items():
        if any(type(seed) is not int or not 0 <= seed < 2**63 for seed in family_seeds):
            raise ValueError(f"invalid holdout seed for family {family}")
        if len(set(family_seeds)) != len(family_seeds):
            raise ValueError(f"duplicate seed in family {family}; use repetitions for repeated runs")
    return seed_map


def validate_suite(families: list[str] | tuple[str, ...] | None = None,
                   seeds: Any = None, *,
                   repetitions: int = 1,
                   http_budget: int = preflight.MAX_REQUESTS,
                   token_budget: int = 150000,
                   seconds_budget: int = 900) -> dict[str, Any]:
    """Validate >=3 distinct registered families, multi-seed lists, repetitions, and shared ceilings."""
    chosen = list(families) if families else list(DEFAULT_FAMILIES)
    if len(chosen) < MINIMUM_FAMILIES or len(set(chosen)) != len(chosen):
        raise ValueError("E6 suite requires at least 3 distinct registered independent families")
    for family in chosen:
        if family not in holdout.FAMILIES:
            raise ValueError(f"unregistered independent family: {family}")
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("repetitions must be an integer >= 1")
    ceilings = _normalize_ceilings({
        "http_requests_per_seed": http_budget,
        "llm_tokens_per_seed": token_budget,
        "seconds_per_seed": seconds_budget,
    })
    if ceilings is None or http_budget > preflight.MAX_REQUESTS or seconds_budget > preflight.MAX_SECONDS:
        raise ValueError("invalid shared ceilings for E6 suite")
    seeds_by_family = _normalize_family_seeds(chosen, seeds)
    selections: list[dict[str, Any]] = []
    selection_by_pair: dict[tuple[str, int], dict[str, Any]] = {}
    for family in chosen:
        for seed in seeds_by_family[family]:
            sel = holdout.selection(family, seed)
            selections.append(sel)
            selection_by_pair[(family, seed)] = sel
    units: list[dict[str, Any]] = []
    for family in chosen:
        for seed in seeds_by_family[family]:
            sel = selection_by_pair[(family, seed)]
            for rep in range(1, repetitions + 1):
                units.append({
                    "experiment_id": f"{family}:{seed}:rep{rep}",
                    "family": family,
                    "seed": seed,
                    "repetition": rep,
                    "selection": sel,
                })
    compat_seeds: dict[str, int | list[int]] = {
        family: (vals[0] if len(vals) == 1 else list(vals))
        for family, vals in seeds_by_family.items()
    }
    return {
        "families": chosen,
        "seeds": compat_seeds,
        "seeds_by_family": seeds_by_family,
        "repetitions": repetitions,
        "ceilings": ceilings,
        "selections": selections,
        "units": units,
    }


def normalize_treatment(treatment: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate and canonicalize an explicit pre-execution treatment declaration."""
    if treatment is None:
        return {"name": "baseline", "role": "baseline", "description": "", "changed_dimensions": []}
    if not isinstance(treatment, dict):
        raise ValueError("treatment must be a mapping")
    role = treatment.get("role", "treatment" if treatment.get("changed_dimensions") else "baseline")
    if role not in {"baseline", "treatment", "control"}:
        raise ValueError("treatment role must be baseline, control, or treatment")
    name = str(treatment.get("name") or role).strip()
    if not name:
        raise ValueError("treatment name cannot be empty")
    description = str(treatment.get("description") or "").strip()
    raw_dims = treatment.get("changed_dimensions", [])
    if not isinstance(raw_dims, (list, tuple)):
        raise ValueError("treatment changed_dimensions must be a list")
    dims: list[str] = []
    for dim in raw_dims:
        if not isinstance(dim, str) or dim not in VALID_TREATMENT_DIMENSIONS:
            raise ValueError(
                f"unsupported treatment dimension {dim!r}; allowed: {', '.join(VALID_TREATMENT_DIMENSIONS)}"
            )
        if dim not in dims:
            dims.append(dim)
    return {
        "name": name,
        "role": role,
        "description": description,
        "changed_dimensions": sorted(dims),
    }


def normalize_acceptance_criteria(criteria: dict[str, Any] | None = None,
                                  holdout_contract: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate and canonicalize pre-execution E6 acceptance thresholds."""
    base_contract = holdout_contract if isinstance(holdout_contract, dict) else {}
    merged: dict[str, Any] = {
        "minimum_families": base_contract.get("minimum_families", MINIMUM_FAMILIES),
        "minimum_positives": base_contract.get("minimum_positives", 24),
        "minimum_negatives": base_contract.get("minimum_negatives", 24),
        "overall_recall": base_contract.get("overall_recall", 0.70),
        "per_family_recall": base_contract.get("per_family_recall", 0.50),
        "negative_coverage": base_contract.get("negative_coverage", 0.90),
        "zero_false_positives": True,
        "closure_verified": True,
        "max_failed_run_rate": 0.0,
    }
    if criteria is not None:
        if not isinstance(criteria, dict):
            raise ValueError("acceptance_criteria must be a mapping")
        unknown = set(criteria) - set(merged)
        if unknown:
            raise ValueError(f"unsupported acceptance criteria fields: {sorted(unknown)}")
        merged.update(criteria)
    for int_key, minimum in (("minimum_families", 3), ("minimum_positives", 24), ("minimum_negatives", 24)):
        if type(merged[int_key]) is not int or merged[int_key] < minimum:
            raise ValueError(f"invalid acceptance criterion {int_key}")
    for ratio_key in ("overall_recall", "per_family_recall", "negative_coverage", "max_failed_run_rate"):
        val = merged[ratio_key]
        if isinstance(val, bool) or not isinstance(val, (int, float)) or not 0.0 <= float(val) <= 1.0:
            raise ValueError(f"invalid acceptance ratio {ratio_key}")
        merged[ratio_key] = float(val)
    for bool_key in ("zero_false_positives", "closure_verified"):
        if type(merged[bool_key]) is not bool:
            raise ValueError(f"invalid acceptance boolean {bool_key}")
    return merged


def evaluate_acceptance(report: dict[str, Any], criteria: dict[str, Any] | None = None) -> dict[str, Any]:
    """Evaluate a cohort report against its frozen acceptance criteria."""
    frozen = normalize_acceptance_criteria(criteria or report.get("acceptance_criteria"))
    recall = _ratio_value(report["recall"])
    neg_cov = _ratio_value(report["negative_coverage"])
    failed_rate = _ratio_value(report["failed_run_rate"])
    per_family = report.get("per_family", {})
    runs = report.get("runs", [])
    checks = {
        "minimum_families": len(report.get("families", [])) >= frozen["minimum_families"],
        "minimum_positives": report.get("positives", 0) >= frozen["minimum_positives"],
        "minimum_negatives": report.get("negatives", 0) >= frozen["minimum_negatives"],
        "overall_recall": recall is not None and recall >= frozen["overall_recall"],
        "per_family_recall": bool(per_family) and all(
            _ratio_value(row["recall"]) is not None and _ratio_value(row["recall"]) >= frozen["per_family_recall"]
            for row in per_family.values()
        ),
        "negative_coverage": neg_cov is not None and neg_cov >= frozen["negative_coverage"],
        "zero_false_positives": (not frozen["zero_false_positives"]) or report["false_positives"]["numerator"] == 0,
        "closure_verified": (not frozen["closure_verified"]) or (
            bool(runs) and all(row.get("closure_verified") is True and not row.get("failed", False) for row in runs)
        ),
        "max_failed_run_rate": failed_rate is not None and failed_rate <= frozen["max_failed_run_rate"],
    }
    return {"passed": all(checks.values()), "criteria": frozen, "checks": checks}


def authorize_provider(provider_config: str | Path, *, model: str = "", worker_model: str = "",
                       execute: bool = False, authorize_live_provider: bool = False,
                       live_authorization_reason: str = "", api_key_env: str | None = None) -> dict[str, Any]:
    """Validate provider routing and fail-closed live remote authorization gate.

    Never reads or embeds credential secrets into return values or artifacts.
    """
    models = llm_config.model_selection(provider_config, model, worker_model)
    settings = llm_config.provider_settings(provider_config, models)
    host = urlsplit(settings["url"]).hostname or ""
    provider_kind = "loopback" if host in LOOPBACK_HOSTS else "remote"
    reason = live_authorization_reason.strip() if isinstance(live_authorization_reason, str) else ""
    env_name = api_key_env or settings["api_key_env"]
    if execute and provider_kind == "remote":
        if authorize_live_provider is not True or not reason:
            raise PermissionError(
                "live remote provider usage requires explicit operator authorization "
                "(--authorize-live-provider and non-empty --live-authorization-reason)")
    if execute and not os.environ.get(env_name, ""):
        raise ValueError(f"provider credential environment variable is empty: {env_name}")
    return {
        "models": models,
        "provider_name": settings["name"],
        "provider_host": host,
        "provider_kind": provider_kind,
        "api_key_env": env_name,
        "live_provider_authorized": bool(authorize_live_provider and reason) if provider_kind == "remote" else None,
        "live_authorization_reason": reason if (provider_kind == "remote" and authorize_live_provider and reason) else None,
    }


def _expected_counts(selections: list[dict[str, Any]], units: list[dict[str, Any]]) -> dict[str, int]:
    """Return minimum positive/negative controls for a suite selection without invoking labs."""
    return {
        "minimum_families": MINIMUM_FAMILIES,
        "selected_families": len({item["family"] for item in selections}),
        "selected_family_seeds": len(selections),
        "selected_units": len(units),
        "minimum_positives": 8 * len(units),
        "minimum_negatives": 8 * len(units),
    }


def _compute_unit_fingerprints(prepared: dict[str, Any]) -> dict[str, Any]:
    """Derive verifiable runtime, evaluator, prompt+catalog, and provider-config fingerprints."""
    manifest = prepared["manifest"]
    contract = prepared["contract"]
    index = prepared["index"]
    runtime = prepared["runtime"]

    host_runtime = manifest.get("host_runtime")
    if not isinstance(host_runtime, dict) or not host_runtime:
        raise ValueError("preflight manifest is missing host_runtime inventory")
    index_files = {row["path"]: row["sha256"] for row in index.get("files", [])}
    for rel_path, digest_val in index_files.items():
        if rel_path in host_runtime and host_runtime[rel_path] != digest_val:
            raise ValueError(f"preflight host_runtime/runtime-index mismatch for {rel_path}")
    combined: dict[str, str] = {**host_runtime, **index_files}

    prompt_catalog_files = {
        path: digest_val for path, digest_val in sorted(combined.items())
        if path in PROMPT_CATALOG_PATHS
    }
    runtime_files = {
        path: digest_val for path, digest_val in sorted(combined.items())
        if (path not in PROMPT_CATALOG_PATHS
            and path not in EVALUATOR_RUNTIME_PATHS
            and path not in PROVIDER_EXCLUDED_RUNTIME_PATHS)
    }

    llm_path = runtime / "config/llm.json"
    if not llm_path.is_file() or llm_path.is_symlink():
        raise ValueError("frozen runtime snapshot is missing config/llm.json")
    llm_snapshot = llm_config.load_config(llm_path)

    holdout_run = contract.get("holdout_run")
    if not isinstance(holdout_run, dict):
        raise ValueError("preflight contract is missing holdout_run selection")

    return {
        "runtime": _canonical_sha256({"schema": "e6-runtime-fingerprint/1", "files": runtime_files}),
        "prompt_catalog": _canonical_sha256({
            "schema": "e6-prompt-catalog-fingerprint/1",
            "files": prompt_catalog_files,
        }),
        "provider_config": _canonical_sha256({
            "schema": "e6-provider-config-fingerprint/1",
            "models": contract["models"],
            "llm_snapshot": llm_snapshot,
        }),
        "evaluator_family_record": {
            "family": holdout_run["family"],
            "lab_version": holdout_run["lab_version"],
            "lab_sha256": holdout_run["lab_sha256"],
            "evaluator_sha256": holdout_run["evaluator_sha256"],
        },
        "holdout_contract": contract["holdout"],
    }


def _aggregate_cohort_fingerprints(unit_fingerprints: list[dict[str, Any]]) -> dict[str, str]:
    """Ensure every run in a cohort shares identical runtime/prompt/provider/evaluator invariants."""
    if not unit_fingerprints:
        raise ValueError("cannot compute fingerprints for empty cohort")
    runtimes = {item["runtime"] for item in unit_fingerprints}
    prompts = {item["prompt_catalog"] for item in unit_fingerprints}
    providers = {item["provider_config"] for item in unit_fingerprints}
    contracts = {_canonical_sha256(item["holdout_contract"]) for item in unit_fingerprints}
    if len(runtimes) != 1:
        raise ValueError("runtime fingerprints differ across cohort units")
    if len(prompts) != 1:
        raise ValueError("prompt/catalog fingerprints differ across cohort units")
    if len(providers) != 1:
        raise ValueError("provider configuration fingerprints differ across cohort units")
    if len(contracts) != 1:
        raise ValueError("holdout contracts differ across cohort units")
    families: dict[str, dict[str, str]] = {}
    for item in unit_fingerprints:
        rec = item["evaluator_family_record"]
        fam = rec["family"]
        if fam in families and families[fam] != rec:
            raise ValueError(f"evaluator fingerprint differs within family {fam}")
        families[fam] = rec
    evaluator_fp = _canonical_sha256({
        "schema": "e6-evaluator-fingerprint/1",
        "holdout_contract": unit_fingerprints[0]["holdout_contract"],
        "families": {fam: families[fam] for fam in sorted(families)},
    })
    return {
        "runtime": next(iter(runtimes)),
        "evaluator": evaluator_fp,
        "prompt_catalog": next(iter(prompts)),
        "provider_config": next(iter(providers)),
    }


def _verify_experiment_manifest(manifest_path: str | Path) -> tuple[Path, dict[str, Any]]:
    path = Path(manifest_path).expanduser().resolve(strict=True)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA_EXPERIMENT_MANIFEST:
        raise ValueError("expected a full-agent-e6-experiment-manifest/1 file")
    recorded_digest = data.get("manifest_digest")
    payload = {k: v for k, v in data.items() if k != "manifest_digest"}
    if not isinstance(recorded_digest, str) or _canonical_sha256(payload) != recorded_digest:
        raise ValueError("experiment manifest digest mismatch (tampered experiment manifest)")
    return path, data


def prepare_cohort(label: str, *, baseline: str | Path, provider_config: str | Path,
                   output_dir: str | Path, families: list[str] | tuple[str, ...] | None = None,
                   seeds: Any = None, repetitions: int = 1, model: str = "", worker_model: str = "",
                   http_budget: int = preflight.MAX_REQUESTS, token_budget: int = 150000,
                   seconds_budget: int = 900, treatment: dict[str, Any] | None = None,
                   acceptance_criteria: dict[str, Any] | None = None) -> tuple[Path, dict[str, Any]]:
    """Create verified per-(family, seed) preflights and freeze experiment manifest; 0 LLM/HTTP calls."""
    if not isinstance(label, str) or not label.strip():
        raise ValueError("cohort label is required")
    suite = validate_suite(
        families, seeds, repetitions=repetitions, http_budget=http_budget,
        token_budget=token_budget, seconds_budget=seconds_budget,
    )
    normalized_treatment = normalize_treatment(treatment)
    auth = authorize_provider(provider_config, model=model, worker_model=worker_model, execute=False)
    output = _output_outside_protected(output_dir, baseline)
    preflight_root = output / "preflights"
    preflight_root.mkdir(parents=True, exist_ok=True)

    preflight_by_pair: dict[tuple[str, int], dict[str, Any]] = {}
    unit_fingerprints: list[dict[str, Any]] = []
    holdout_contract: dict[str, Any] | None = None

    for item in suite["selections"]:
        args = [
            "--baseline", str(baseline),
            "--provider-config", str(provider_config),
            "--token-budget", str(suite["ceilings"]["llm_tokens_per_seed"]),
            "--http-budget", str(suite["ceilings"]["http_requests_per_seed"]),
            "--seconds-budget", str(suite["ceilings"]["seconds_per_seed"]),
            "--solver-mode", "python_loop",
            "--holdout-family", item["family"],
            "--holdout-seed", str(item["seed"]),
            "--output-dir", str(preflight_root),
        ]
        if model:
            args.extend(["--model", model])
        if worker_model:
            args.extend(["--worker-model", worker_model])
        rc = preflight.main(args)
        if rc != 0:
            raise ValueError(f"preflight failed for family {item['family']} seed {item['seed']} (exit {rc})")
        manifests = sorted(preflight_root.glob("preflight-*/preflight.json"), key=lambda p: p.stat().st_mtime_ns)
        latest = manifests[-1].resolve(strict=True)
        prepared = launcher.prepared_run(latest)
        unit_fingerprints.append(_compute_unit_fingerprints(prepared))
        holdout_contract = prepared["contract"]["holdout"]
        preflight_by_pair[(item["family"], item["seed"])] = {
            "preflight": str(latest),
            "preflight_sha256": holdout.digest(latest),
            "contract": str(prepared["manifest"]["contract"]),
            "contract_sha256": prepared["manifest"]["contract_sha256"],
            "runtime_index": str(prepared["manifest"]["runtime_snapshot"]["index"]),
            "runtime_index_sha256": prepared["manifest"]["runtime_snapshot"]["index_sha256"],
            "holdout_selection_sha256": _canonical_sha256(item),
        }

    fingerprints = _aggregate_cohort_fingerprints(unit_fingerprints)
    frozen_criteria = normalize_acceptance_criteria(acceptance_criteria, holdout_contract)

    entries: list[dict[str, Any]] = []
    manifest_units: list[dict[str, Any]] = []
    for unit in suite["units"]:
        pf_info = preflight_by_pair[(unit["family"], unit["seed"])]
        entries.append({
            "experiment_id": unit["experiment_id"],
            "family": unit["family"],
            "seed": unit["seed"],
            "repetition": unit["repetition"],
            "preflight": pf_info["preflight"],
            "preflight_sha256": pf_info["preflight_sha256"],
        })
        manifest_units.append({
            "experiment_id": unit["experiment_id"],
            "family": unit["family"],
            "seed": unit["seed"],
            "repetition": unit["repetition"],
            **pf_info,
        })

    created_at = datetime.now(timezone.utc).isoformat()
    experiment_manifest_payload: dict[str, Any] = {
        "schema": SCHEMA_EXPERIMENT_MANIFEST,
        "label": label,
        "created_at": created_at,
        "families": suite["families"],
        "seeds_by_family": suite["seeds_by_family"],
        "repetitions": suite["repetitions"],
        "ceilings": suite["ceilings"],
        "models": auth["models"],
        "provider_kind": auth["provider_kind"],
        "provider_host": auth["provider_host"],
        "fingerprints": fingerprints,
        "treatment": normalized_treatment,
        "acceptance_criteria": frozen_criteria,
        "units": manifest_units,
    }
    experiment_manifest = {
        **experiment_manifest_payload,
        "manifest_digest": _canonical_sha256(experiment_manifest_payload),
    }
    experiment_manifest_path = output / "experiment-manifest.json"
    dump(experiment_manifest_path, experiment_manifest)

    plan = {
        "schema": SCHEMA_SUITE,
        "label": label,
        "created_at": created_at,
        "status": "plan_only",
        "executed": False,
        "llm_calls": 0,
        "target_requests": 0,
        "models": auth["models"],
        "provider_kind": auth["provider_kind"],
        "provider_host": auth["provider_host"],
        "families": suite["families"],
        "seeds_by_family": suite["seeds_by_family"],
        "repetitions": suite["repetitions"],
        "ceilings": suite["ceilings"],
        "fingerprints": fingerprints,
        "treatment": normalized_treatment,
        "acceptance_criteria": frozen_criteria,
        "experiment_manifest": str(experiment_manifest_path),
        "experiment_manifest_sha256": holdout.digest(experiment_manifest_path),
        "holdout_minimums": _expected_counts(suite["selections"], suite["units"]),
        "runs": entries,
    }
    plan_path = output / "suite-plan.json"
    dump(plan_path, plan)
    return plan_path, plan


def run_cohort(label: str, *, baseline: str | Path, provider_config: str | Path,
               output_dir: str | Path, families: list[str] | tuple[str, ...] | None = None,
               seeds: Any = None, repetitions: int = 1, model: str = "", worker_model: str = "",
               http_budget: int = preflight.MAX_REQUESTS, token_budget: int = 150000,
               seconds_budget: int = 900, execute: bool = False,
               authorize_live_provider: bool = False, live_authorization_reason: str = "",
               api_key_env: str | None = None, treatment: dict[str, Any] | None = None,
               acceptance_criteria: dict[str, Any] | None = None) -> tuple[Path, dict[str, Any]]:
    """Run (or plan when execute=False) an E6 >=3-family paired multi-seed cohort under shared ceilings."""
    auth = authorize_provider(
        provider_config, model=model, worker_model=worker_model, execute=execute,
        authorize_live_provider=authorize_live_provider,
        live_authorization_reason=live_authorization_reason, api_key_env=api_key_env)
    plan_path, plan = prepare_cohort(
        label, baseline=baseline, provider_config=provider_config, output_dir=output_dir,
        families=families, seeds=seeds, repetitions=repetitions, model=model, worker_model=worker_model,
        http_budget=http_budget, token_budget=token_budget, seconds_budget=seconds_budget,
        treatment=treatment, acceptance_criteria=acceptance_criteria)
    if not execute:
        return plan_path, plan
    output = plan_path.parent
    exp_manifest_path, exp_manifest = _verify_experiment_manifest(plan["experiment_manifest"])
    runs_dir = output / "runs"
    runs_dir.mkdir(exist_ok=True)
    api_key = os.environ[auth["api_key_env"]]
    manifest_paths: list[Path] = []
    unit_runs: list[dict[str, Any]] = []
    for unit in exp_manifest["units"]:
        prepared = launcher.prepared_run(unit["preflight"])
        provider = launcher.provider_settings(provider_config, prepared["contract"]["models"])
        manifest_path, _ = launcher.launch_seed(
            prepared, seed=unit["seed"], output=runs_dir,
            provider=provider, api_key=api_key, bwrap=None, opencode=None)
        manifest_paths.append(manifest_path)
        unit_runs.append({
            "experiment_id": unit["experiment_id"],
            "family": unit["family"],
            "seed": unit["seed"],
            "repetition": unit["repetition"],
            "manifest": str(manifest_path),
            "manifest_sha256": holdout.digest(manifest_path),
        })
    dump(output / "unit-runs.json", {"schema": "full-agent-e6-unit-runs/1", "units": unit_runs})
    report = audit_cohort(
        label, manifest_paths,
        expected_ceilings=plan["ceilings"],
        authorization={
            "provider_kind": auth["provider_kind"],
            "provider_host": auth["provider_host"],
            "live_provider_authorized": auth["live_provider_authorized"],
            "live_authorization_reason": auth["live_authorization_reason"],
        },
        experiment_manifest=exp_manifest_path,
        unit_runs=unit_runs,
    )
    report_path = output / "cohort-report.json"
    dump(report_path, report)
    (output / "cohort-report.md").write_text(render_cohort_markdown(report), encoding="utf-8")
    return report_path, report


def _unknown_funnel() -> dict[str, Any]:
    return {
        "funnel_present": False,
        "status": "unknown",
        "observed": None,
        "eligible": None,
        "admitted": None,
        "executed": None,
        "evidence_accepted": None,
        "rates": {
            "eligible_rate": None,
            "admitted_rate": None,
            "executed_rate": None,
            "accepted_rate": None,
            "end_to_end_yield": None,
        },
    }


def _normalize_funnel_dict(raw: dict[str, Any]) -> dict[str, Any]:
    aliases = {
        "observed": ("observed", "observed_candidates"),
        "eligible": ("eligible", "eligible_candidates"),
        "admitted": ("admitted", "admitted_candidates"),
        "executed": ("executed", "executed_validations"),
        "evidence_accepted": ("evidence_accepted", "accepted"),
    }
    counts: dict[str, int | None] = {}
    for stage, keys in aliases.items():
        val = None
        for key in keys:
            if key in raw:
                val = raw[key]
                break
        if val is not None and (type(val) is not int or val < 0):
            raise ValueError(f"invalid host funnel count for {stage}: {val!r}")
        counts[stage] = val
    present = any(counts[stage] is not None for stage in FUNNEL_STAGES)
    complete = all(counts[stage] is not None for stage in FUNNEL_STAGES)
    if not present:
        return _unknown_funnel()
    return {
        "funnel_present": True,
        "status": "complete" if complete else "partial",
        **counts,
        "rates": {
            "eligible_rate": holdout._ratio(counts["eligible"], counts["observed"]),
            "admitted_rate": holdout._ratio(counts["admitted"], counts["eligible"]),
            "executed_rate": holdout._ratio(counts["executed"], counts["admitted"]),
            "accepted_rate": holdout._ratio(counts["evidence_accepted"], counts["executed"]),
            "end_to_end_yield": holdout._ratio(counts["evidence_accepted"], counts["observed"]),
        },
    }


def extract_run_funnel(run_dir: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Read audited host runtime funnel metrics if present, leaving missing historical funnel unknown."""
    work = run_dir / "solver"
    ledger_hashes: dict[str, str] = {}
    attempt_ledger_path = work / "attempt-ledger.json"
    if attempt_ledger_path.is_file():
        signed = json.loads(attempt_ledger_path.read_text(encoding="utf-8"))
        for ref in signed.get("payload", {}).get("workflow_files", []):
            if isinstance(ref, dict) and isinstance(ref.get("path"), str) and isinstance(ref.get("sha256"), str):
                ledger_hashes[ref["path"]] = ref["sha256"]

    summary_funnels: list[dict[str, Any]] = []
    summaries_dir = work / "summaries"
    if summaries_dir.is_dir():
        for summary_path in sorted(summaries_dir.glob("*.json")):
            rel = f"summaries/{summary_path.name}"
            if rel in ledger_hashes and holdout.digest(summary_path) != ledger_hashes[rel]:
                raise ValueError(f"host summary artifact changed: {rel}")
            data = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                raw = data.get("validation_funnel", data.get("funnel"))
                if isinstance(raw, dict):
                    summary_funnels.append(_normalize_funnel_dict(raw))

    if summary_funnels:
        totals = {
            stage: holdout._sum_optional([item[stage] for item in summary_funnels])
            for stage in FUNNEL_STAGES
        }
        return _normalize_funnel_dict(totals)

    for candidate in (work / "run-result.json",):
        if candidate.is_file():
            data = json.loads(candidate.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                raw_run_funnel = data.get("validation_funnel", data.get("funnel"))
                if isinstance(raw_run_funnel, dict):
                    return _normalize_funnel_dict(raw_run_funnel)

    raw_manifest_funnel = manifest.get("validation_funnel", manifest.get("funnel"))
    if isinstance(raw_manifest_funnel, dict):
        return _normalize_funnel_dict(raw_manifest_funnel)
    return _unknown_funnel()


def _aggregate_funnel(funnels: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate host runtime funnel metrics; unknown stages remain None (never zero)."""
    if not funnels:
        return {**_unknown_funnel(), "runs_with_funnel": 0, "runs_total": 0}
    with_funnel = sum(1 for item in funnels if item.get("funnel_present"))
    if with_funnel == 0:
        return {**_unknown_funnel(), "runs_with_funnel": 0, "runs_total": len(funnels)}
    totals = {
        stage: holdout._sum_optional([item.get(stage) for item in funnels])
        for stage in FUNNEL_STAGES
    }
    complete = with_funnel == len(funnels) and all(totals[stage] is not None for stage in FUNNEL_STAGES)
    return {
        "funnel_present": True,
        "status": "complete" if complete else "partial",
        "runs_with_funnel": with_funnel,
        "runs_total": len(funnels),
        **totals,
        "rates": {
            "eligible_rate": holdout._ratio(totals["eligible"], totals["observed"]),
            "admitted_rate": holdout._ratio(totals["admitted"], totals["eligible"]),
            "executed_rate": holdout._ratio(totals["executed"], totals["admitted"]),
            "accepted_rate": holdout._ratio(totals["evidence_accepted"], totals["executed"]),
            "end_to_end_yield": holdout._ratio(totals["evidence_accepted"], totals["observed"]),
        },
    }


def _load_archived_prepared_run(path: str | Path) -> dict[str, Any]:
    """Verify a frozen preflight directory read-only without requiring host_runtime == current checkout."""
    preflight_path = Path(path).expanduser().resolve(strict=True)
    if preflight_path.is_dir():
        preflight_path = preflight_path / "preflight.json"
    manifest = json.loads(preflight_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != preflight.SCHEMA or manifest.get("mode") != "preflight_only":
        raise ValueError("a native preflight manifest is required")

    def artifact(name: str, digest_val: str) -> Path:
        raw = Path(name)
        resolved = raw.resolve(strict=True)
        if raw.is_symlink() or preflight_path.parent not in resolved.parents or preflight.sha256(resolved) != digest_val:
            raise ValueError("preflight artifact is outside its directory or has changed")
        return resolved

    contract_path = artifact(manifest["contract"], manifest["contract_sha256"])
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    solver_mode = contract.get("solver_mode", "native")
    supported = {"native": "native_opencode_planner_worker", "python_loop": "python-workflow-v1"}
    if contract.get("schema") != "full-agent-contract/1" or contract.get("solver") != supported.get(solver_mode):
        raise ValueError("unsupported native contract")
    reference = preflight.baseline_reference(Path(contract["baseline"]["manifest"]).parent)
    if reference != contract["baseline"]:
        raise ValueError("baseline evidence changed since preflight")
    tokens = contract["limits"]["llm_tokens_per_seed"]
    options: dict[str, Any] = (
        {"solver_mode": solver_mode, "seconds_budget": contract["limits"]["seconds_per_seed"],
         "http_budget": contract["limits"]["http_requests_per_seed"]}
        if solver_mode == "python_loop" else {}
    )
    expected = preflight.native_contract(reference, contract["models"], tokens, **options)
    if solver_mode == "python_loop" and (not isinstance(manifest.get("host_runtime"), dict) or not manifest["host_runtime"]):
        raise ValueError("archived Python preflight is missing host_runtime inventory")
    if "holdout_run" in contract:
        selected = contract["holdout_run"]
        holdout.replay(selected)
        expected["holdout_run"] = holdout.selection(selected["family"], selected["seed"])
    if contract != expected:
        raise ValueError("native contract does not match the supported limits and evidence requirements")
    snapshot = manifest["runtime_snapshot"]
    index_path = artifact(snapshot["index"], snapshot["index_sha256"])
    index = json.loads(index_path.read_text(encoding="utf-8"))
    runtime = Path(snapshot["path"]).resolve(strict=True)
    if (runtime != preflight_path.parent / "runtime" or Path(snapshot["path"]).is_symlink()
            or index.get("schema") != "full-agent-runtime-snapshot/1"
            or index.get("runnable") is not False or index.get("models") != contract["models"]):
        raise ValueError("invalid closed runtime snapshot")
    allowed_generated = {".codex/scope.json", ".codex/program-policy.json"}
    if solver_mode != "python_loop":
        allowed_generated.add("opencode.json")
    listed: set[str] = set()
    for row in index["files"]:
        relative = Path(row["path"])
        if (not relative.parts or relative.is_absolute() or ".." in relative.parts or row["path"] in listed
                or not (preflight.runtime_file(relative) or relative.as_posix() in allowed_generated)):
            raise ValueError("invalid runtime inventory")
        target = runtime / relative
        if target.is_symlink() or any(
            parent.is_symlink() for parent in target.parents if parent != runtime and runtime in parent.parents
        ):
            raise ValueError("runtime snapshot contains a symlink")
        if not target.is_file() or preflight.sha256(target) != row["sha256"]:
            raise ValueError("runtime file changed since preflight")
        listed.add(row["path"])
    actual: set[str] = set()
    for target in runtime.rglob("*"):
        if target.is_symlink():
            raise ValueError("runtime snapshot contains a symlink")
        if target.is_file():
            actual.add(target.relative_to(runtime).as_posix())
    if actual != listed or len(listed) != snapshot["files"]:
        raise ValueError("runtime inventory is incomplete")
    return {
        "manifest": manifest,
        "manifest_path": preflight_path,
        "contract": contract,
        "runtime": runtime,
        "index": index,
    }


def _audit_run_readonly(manifest_path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read-only equivalent of holdout.audit_run_status that never writes into the audited directory."""
    import attempt_ledger
    import brain
    import evidence_trust

    manifest_file = Path(manifest_path).resolve(strict=True)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    directory = manifest_file.parent
    private, work = directory / "private", directory / "solver"
    prepared = _load_archived_prepared_run(manifest["preflight"])
    selected = prepared["contract"]["holdout_run"]
    holdout.replay(selected, manifest["seed"])
    evaluator = private / "evaluator"
    if json.loads((evaluator / "selection.json").read_text(encoding="utf-8")) != selected:
        raise ValueError("lab selection does not match frozen preflight")
    if holdout.digest(evaluator / "lab-source.py") != selected["lab_sha256"]:
        raise ValueError("evaluated lab source changed")
    truth = json.loads((evaluator / "truth.json").read_text(encoding="utf-8"))
    wire_file = evaluator / "wire.json"

    if manifest.get("status") not in {"python_finished_verified", "native_finished_unverified"}:
        wire = json.loads(wire_file.read_text(encoding="utf-8")) if wire_file.is_file() else []
        target = manifest.get("target") or "http://127.0.0.1/"
        run_id = manifest.get("run_id") or f"failed-{manifest['seed']}"
        metrics = holdout.evaluate(truth, wire, [], target=target, run_id=run_id, verify_artifact=lambda _r: False)
        python = manifest.get("solver_mode") == "python_loop"
        provider_kind = manifest.get("provider_kind", "unknown") if python else "scripted_loopback"
        llm_calls = manifest.get("llm_calls")
        paid_calls = (0 if provider_kind == "loopback" else llm_calls
                      if provider_kind == "remote" else None) if python else 0
        usage = holdout._extract_run_usage(
            private, manifest, len(wire) if wire_file.is_file() else manifest.get("target_requests"))
        failure_reason = manifest.get("stop_reason") or manifest.get("failure_phase") or manifest.get("status") or "failed"
        not_tested = holdout._extract_not_tested(
            metrics, work, provider_kind=provider_kind, paid_calls=paid_calls,
            closure_payload=None, closure_verified=False)
        metrics.update(
            closure_verified=False,
            accounting_matches=bool(
                wire_file.is_file() and len(wire) == manifest.get("target_requests")
                and all(row.get("method") == "GET" for row in wire)),
            target_requests=len(wire) if wire_file.is_file() else manifest.get("target_requests"),
            paid_provider_calls=paid_calls,
            provider_kind=provider_kind,
            full_acceptance=False,
            failed=True,
            failure_reason=failure_reason,
            models=prepared["contract"]["models"],
            effective_limits=manifest.get("effective_limits", {}),
            usage=usage,
            verified_findings=0,
            requests_per_verified_finding=None,
            tokens_per_verified_finding=None,
            not_tested=not_tested,
            evidence_refs=holdout._collect_evidence_refs(manifest_file, work, evaluator, []),
            contract=prepared["contract"]["holdout"],
        )
        return metrics, holdout.aggregate([metrics], prepared["contract"]["holdout"])

    wire = json.loads(wire_file.read_text(encoding="utf-8"))
    live = json.loads((work / "access/live-result.json").read_text(encoding="utf-8"))
    tool_index = json.loads((private / "tool-index.json").read_text(encoding="utf-8"))
    live_tools = [
        json.loads(Path(row["artifact"]).read_text(encoding="utf-8"))
        for row in tool_index
        if row["tool"] == "hunter_run_web_loop" and row["task_spec_id"] == "access-3"
    ]
    native_reports = [
        json.loads(row["execution"]["result"]["output"])
        for row in live_tools
        if row["arguments"].get("live") and not row["error"]
    ]
    run_ids = [row["run_id"] for row in native_reports]
    if not run_ids or live.get("run_ids") != run_ids:
        raise ValueError("solver run IDs do not match production executor receipts")
    artifacts = [
        {"path": str(path), "sha256": holdout.digest(path), "record": json.loads(path.read_text(encoding="utf-8"))}
        for path in sorted((private / "state/validations").glob("*.json"))
    ]
    validator_dir = str(Path(__file__).resolve().parents[1] / "mcp-servers/mcp-validator")
    if validator_dir not in sys.path:
        sys.path.append(validator_dir)
    from cco_validator_core.evidence import artifact_is_current

    with launcher.host_environment(private / "state", work, directory / "runtime"):
        signed_events = []
        with sqlite3.connect(f"file:{private / 'state/agent_memory.db'}?mode=ro", uri=True) as conn:
            has_table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='hunter_coverage_events'"
            ).fetchone()
            if has_table:
                for (raw,) in conn.execute("SELECT signed_json FROM hunter_coverage_events ORDER BY id"):
                    signed = json.loads(raw)
                    payload = signed["payload"]
                    if evidence_trust.verify(evidence_trust.canonical_bytes(payload), signed, "coverage-attempt"):
                        signed_events.append(signed)

        def verified(record: dict[str, Any]) -> bool:
            expected_finding = holdout.finding_type(selected["family"])
            if not artifact_is_current(
                record, trusted_root=str(private / "state/validations"),
                expected_target=record["target"], expected_finding_type=expected_finding,
            ):
                return False
            return any(
                event["payload"].get("validation_id") == record["validation_id"]
                and event["payload"].get("artifact_sha256") == record["artifact"]["content_sha256"]
                and all(event["payload"].get(key) == value
                        for key, value in record.get("execution_context", {}).items())
                and event["payload"].get("status") == {
                    "CONFIRMED": "confirmed", "UNCONFIRMED": "tested_clean"}.get(record["verdict"])
                for event in signed_events
            )

        metrics = holdout.evaluate(
            truth, wire, artifacts, target=manifest["target"], run_id=run_ids, verify_artifact=verified,
            claims=[claim for row in native_reports for claim in row.get("confirmed", [])],
        )
        payload, error = attempt_ledger.verify_signed_payload(
            json.loads((work / "closure.json").read_text(encoding="utf-8")))
        records = attempt_ledger.read_records(work / "attempts.jsonl")
        trusted, errors = attempt_ledger.verify_records(records, path=work / "attempts.jsonl")
        if manifest.get("solver_mode") == "python_loop":
            holdout.verify_python_snapshot(work, manifest, trusted)
        verification_log = io.StringIO()
        with redirect_stdout(verification_log):
            verification_exit = brain.main(["closure", "verify", "--workdir", str(work)])
        closure_verified = (
            payload is not None and not error and not errors and len(trusted) == len(records)
            and verification_exit == 0
        )
        recovery_vectors = {row["vector"] for row in trusted if row.get("verdict") == "session-recovery"}
        if payload is None or any(row["vector"] not in recovery_vectors for row in payload["not_tested"]):
            raise ValueError("parked vectors lack trusted session-recovery attestations")
        checks = json.loads((work / "enum/session-checks.json").read_text(encoding="utf-8"))
        observed_checks = {}
        for row in tool_index:
            if row["tool"] != "validator_session_vault_check" or row["task_spec_id"] != "enum-2":
                continue
            receipt = json.loads(Path(row["artifact"]).read_text(encoding="utf-8"))
            check = json.loads(receipt["execution"]["result"]["output"])
            observed_checks[receipt["arguments"]["identity"]] = check
        if not observed_checks or observed_checks != checks or any(row["status"] != "fresh" for row in checks.values()):
            raise ValueError("attestation evidence does not match fresh native session checks")

    accounting = (
        len(wire) == manifest["target_requests"] == manifest["budget"]["used"]["http"]
        and all(row["method"] == "GET" for row in wire)
    )
    if not closure_verified or not accounting:
        raise ValueError("holdout requires signed closure and exact read-only wire accounting")
    python = manifest.get("solver_mode") == "python_loop"
    provider_kind = manifest.get("provider_kind", "unknown") if python else "scripted_loopback"
    paid_calls = (
        0 if provider_kind == "loopback" else manifest["llm_calls"] if provider_kind == "remote" else None
    ) if python else 0
    usage = holdout._extract_run_usage(private, manifest, len(wire))
    tp = metrics["recall"]["numerator"]
    not_tested = holdout._extract_not_tested(
        metrics, work, provider_kind=provider_kind, paid_calls=paid_calls,
        closure_payload=payload, closure_verified=True)
    metrics.update(
        closure_verified=True,
        accounting_matches=True,
        target_requests=len(wire),
        paid_provider_calls=paid_calls,
        provider_kind=provider_kind,
        full_acceptance=False,
        failed=False,
        failure_reason=None,
        models=prepared["contract"]["models"],
        effective_limits=manifest.get("effective_limits", {}),
        usage=usage,
        verified_findings=tp,
        requests_per_verified_finding=holdout._ratio(len(wire), tp),
        tokens_per_verified_finding=holdout._ratio(usage["tokens_used"], tp),
        not_tested=not_tested,
        evidence_refs=holdout._collect_evidence_refs(manifest_file, work, evaluator, artifacts),
        contract=prepared["contract"]["holdout"],
    )
    return metrics, holdout.aggregate([metrics], prepared["contract"]["holdout"])


def _merge_not_tested(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge per-run NOT TESTED details for a family without hiding gaps."""
    missed: list[str] = []
    untested_neg: list[str] = []
    closure_vectors: list[dict[str, Any]] = []
    access_reasons: list[dict[str, Any]] = []
    dimensions: list[str] = []
    seen_closure: set[str] = set()
    seen_access: set[str] = set()
    for row in runs:
        nt = row.get("not_tested") or {}
        for case_id in nt.get("missed_positive_cases", []):
            if case_id not in missed:
                missed.append(case_id)
        for case_id in nt.get("untested_negative_cases", []):
            if case_id not in untested_neg:
                untested_neg.append(case_id)
        for vec in nt.get("closure_not_tested_vectors", []):
            key = json.dumps(vec, sort_keys=True)
            if key not in seen_closure:
                seen_closure.add(key)
                closure_vectors.append(vec)
        for reason in nt.get("access_not_tested_reasons", []):
            key = json.dumps(reason, sort_keys=True)
            if key not in seen_access:
                seen_access.add(key)
                access_reasons.append(reason)
        for dim in nt.get("untested_dimensions", []):
            if dim not in dimensions:
                dimensions.append(dim)
    return {
        "missed_positive_cases": missed,
        "untested_negative_cases": untested_neg,
        "closure_not_tested_vectors": closure_vectors,
        "access_not_tested_reasons": access_reasons,
        "untested_dimensions": dimensions,
    }


def _aggregate_cohort_metrics(run_metrics: list[dict[str, Any]],
                              run_evidence: list[dict[str, Any]],
                              contract: dict[str, Any]) -> dict[str, Any]:
    """Aggregate multi-seed and multi-repetition run metrics per family and across the cohort."""
    by_family: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for metrics, evidence in zip(run_metrics, run_evidence):
        family = metrics["family"]
        if family not in holdout.FAMILIES:
            raise ValueError("unknown independent family")
        if any(case.get("family", family) != family for case in metrics.get("cases", [])):
            raise ValueError("renamed independent family cases")
        by_family.setdefault(family, []).append((metrics, evidence))

    positives = sum(row["recall"]["denominator"] for row in run_metrics)
    negatives = sum(row["negative_coverage"]["denominator"] for row in run_metrics)
    tp = sum(row["recall"]["numerator"] for row in run_metrics)
    fp = sum(row.get("false_positives", {}).get("numerator", 0) for row in run_metrics)
    fp_total = sum(row.get("false_positives", {}).get("denominator", 0) for row in run_metrics)
    tested = sum(row["negative_coverage"]["numerator"] for row in run_metrics)
    failed_count = sum(1 for row in run_metrics if row.get("failed") is True)

    usages = [row.get("usage") for row in run_metrics]
    has_usage = bool(run_metrics) and all(isinstance(row, dict) for row in usages)
    total_http = holdout._sum_optional([row["http_requests"] for row in usages if isinstance(row, dict)]) if has_usage else None
    total_tokens = holdout._sum_optional([row["tokens_used"] for row in usages if isinstance(row, dict)]) if has_usage else None
    total_prompt = holdout._sum_optional([row.get("prompt_tokens") for row in usages if isinstance(row, dict)]) if has_usage else None
    total_completion = holdout._sum_optional([row.get("completion_tokens") for row in usages if isinstance(row, dict)]) if has_usage else None
    total_seconds = holdout._sum_optional([row.get("wall_clock_seconds") for row in usages if isinstance(row, dict)]) if has_usage else None
    total_calls = holdout._sum_optional([row.get("llm_calls") for row in usages if isinstance(row, dict)]) if has_usage else None
    total_cost = holdout._sum_optional([row.get("cost_usd") for row in usages if isinstance(row, dict)]) if has_usage else None

    provider_kinds = sorted({row.get("provider_kind", "unknown") for row in run_metrics})
    per_family: dict[str, Any] = {}
    dimensions: list[str] = []
    for family, items in by_family.items():
        fam_metrics = [m for m, _ in items]
        fam_ev = [e for _, e in items]
        fam_pos = sum(m["recall"]["denominator"] for m in fam_metrics)
        fam_neg = sum(m["negative_coverage"]["denominator"] for m in fam_metrics)
        fam_tp = sum(m["recall"]["numerator"] for m in fam_metrics)
        fam_fp = sum(m.get("false_positives", {}).get("numerator", 0) for m in fam_metrics)
        fam_fp_den = sum(m.get("false_positives", {}).get("denominator", 0) for m in fam_metrics)
        fam_tested = sum(m["negative_coverage"]["numerator"] for m in fam_metrics)
        fam_failed = sum(1 for m in fam_metrics if m.get("failed") is True)
        fam_reasons = [str(m["failure_reason"]) for m in fam_metrics if m.get("failed") and m.get("failure_reason")]
        fam_usages = [m.get("usage") or {} for m in fam_metrics]
        fam_http = holdout._sum_optional([u.get("http_requests") for u in fam_usages])
        fam_tokens = holdout._sum_optional([u.get("tokens_used") for u in fam_usages])
        fam_cost = holdout._sum_optional([u.get("cost_usd") for u in fam_usages])
        fam_not_tested = _merge_not_tested(fam_metrics)
        for dim in fam_not_tested["untested_dimensions"]:
            if dim not in dimensions:
                dimensions.append(dim)
        per_family[family] = {
            "recall": {"numerator": fam_tp, "denominator": fam_pos, "value": holdout._ratio(fam_tp, fam_pos)},
            "negative_coverage": {
                "numerator": fam_tested,
                "denominator": fam_neg,
                "value": holdout._ratio(fam_tested, fam_neg),
            },
            "false_positives": {
                "numerator": fam_fp,
                "denominator": fam_fp_den,
                "value": holdout._ratio(fam_fp, fam_fp_den),
            },
            "verified_findings": fam_tp,
            "run_count": len(fam_metrics),
            "seeds": sorted({int(e["seed"]) for e in fam_ev}),
            "repetitions": sorted({int(e["repetition"]) for e in fam_ev}),
            "failed": fam_failed > 0,
            "failed_runs": {
                "numerator": fam_failed,
                "denominator": len(fam_metrics),
                "value": holdout._ratio(fam_failed, len(fam_metrics)),
            },
            "failure_reason": fam_reasons[0] if len(fam_reasons) == 1 else ("; ".join(fam_reasons) if fam_reasons else None),
            "closure_verified": all(m.get("closure_verified") is True and not m.get("failed", False) for m in fam_metrics),
            "http_requests": fam_http,
            "tokens_used": fam_tokens,
            "requests_per_verified_finding": holdout._ratio(fam_http, fam_tp),
            "tokens_per_verified_finding": holdout._ratio(fam_tokens, fam_tp),
            "cost_usd": fam_cost,
            "funnel": _aggregate_funnel([e["funnel"] for e in fam_ev]),
            "not_tested": fam_not_tested,
        }

    checks = {
        "minimum_families": len(by_family) >= contract["minimum_families"],
        "minimum_positives": positives >= contract["minimum_positives"],
        "minimum_negatives": negatives >= contract["minimum_negatives"],
        "overall_recall": bool(positives) and tp / positives >= contract["overall_recall"],
        "per_family_recall": bool(per_family) and all(
            pf["recall"]["value"] is not None and pf["recall"]["value"] >= contract["per_family_recall"]
            for pf in per_family.values()
        ),
        "negative_coverage": bool(negatives) and tested / negatives >= contract["negative_coverage"],
        "zero_false_positives": fp == 0,
        "closure_verified": bool(run_metrics) and all(
            row.get("closure_verified") is True and not row.get("failed", False) for row in run_metrics
        ),
    }

    if not run_metrics or all(kind in {"scripted_loopback", "loopback", "unknown"} for kind in provider_kinds):
        paid_generalization = "not_evaluated"
    elif all(row.get("provider_kind") == "remote" and (row.get("paid_provider_calls") or 0) > 0 for row in run_metrics):
        paid_generalization = "passed" if all(checks.values()) and failed_count == 0 else "evaluated_incomplete"
    else:
        paid_generalization = "partial_remote"

    models = sorted({
        value for row in run_metrics
        for key, value in (row.get("models") or {}).items()
        if key in {"planner", "worker"} and isinstance(value, str)
    })

    return {
        "status": "passed" if all(checks.values()) else "incomplete",
        "checks": checks,
        "families": list(by_family),
        "positives": positives,
        "negatives": negatives,
        "overall_recall": {"numerator": tp, "denominator": positives, "value": holdout._ratio(tp, positives)},
        "negative_coverage": {"numerator": tested, "denominator": negatives, "value": holdout._ratio(tested, negatives)},
        "false_positives": {"numerator": fp, "denominator": fp_total, "value": holdout._ratio(fp, fp_total)},
        "verified_findings": tp,
        "failed_runs": {
            "numerator": failed_count,
            "denominator": len(run_metrics),
            "value": holdout._ratio(failed_count, len(run_metrics)),
        },
        "models": models,
        "provider_kinds": provider_kinds,
        "usage": {
            "llm_calls": total_calls,
            "http_requests": total_http,
            "tokens_used": total_tokens,
            "prompt_tokens": total_prompt,
            "completion_tokens": total_completion,
            "wall_clock_seconds": total_seconds,
            "cost_usd": total_cost,
            "cost_complete": total_cost is not None,
            "unknown_cost_is_zero": False,
        },
        "requests_per_verified_finding": holdout._ratio(total_http, tp),
        "tokens_per_verified_finding": holdout._ratio(total_tokens, tp),
        "per_family": per_family,
        "not_tested_dimensions": dimensions,
        "paid_model_generalization": paid_generalization,
        "funnel": _aggregate_funnel([e["funnel"] for e in run_evidence]),
    }


def audit_cohort(label: str, manifest_paths: Sequence[str | Path], *,
                 expected_ceilings: dict[str, int] | None = None,
                 authorization: dict[str, Any] | None = None,
                 experiment_manifest: str | Path | None = None,
                 unit_runs: list[dict[str, Any]] | None = None,
                 readonly: bool = False,
                 created_at: str | None = None) -> dict[str, Any]:
    """Independently audit >=3 family manifests offline and build E6 cohort metrics."""
    if not isinstance(label, str) or not label.strip():
        raise ValueError("cohort label is required")
    paths = [Path(path).resolve(strict=True) for path in manifest_paths]
    if len(paths) < MINIMUM_FAMILIES:
        raise ValueError("E6 cohort audit requires at least 3 independent family runs")

    exp_manifest_path: Path | None = None
    exp_manifest: dict[str, Any] | None = None
    expected_units_by_id: dict[str, dict[str, Any]] = {}
    if experiment_manifest is not None:
        exp_manifest_path, exp_manifest = _verify_experiment_manifest(experiment_manifest)
        for u in exp_manifest.get("units", []):
            expected_units_by_id[u["experiment_id"]] = u
        if len(paths) != len(expected_units_by_id):
            raise ValueError("audited manifest count does not match frozen experiment manifest")

    unit_by_manifest: dict[str, dict[str, Any]] = {}
    if unit_runs is not None:
        for row in unit_runs:
            resolved = str(Path(row["manifest"]).resolve(strict=True))
            if "manifest_sha256" in row and holdout.digest(resolved) != row["manifest_sha256"]:
                raise ValueError(f"launch manifest digest changed for {row.get('experiment_id')}")
            unit_by_manifest[resolved] = row

    auditor = _audit_run_readonly if readonly else holdout.audit_run_status
    prepared_loader = _load_archived_prepared_run if readonly else launcher.prepared_run
    run_metrics: list[dict[str, Any]] = []
    contracts: list[dict[str, Any]] = []
    run_ceilings: list[dict[str, int]] = []
    unit_fingerprints: list[dict[str, Any]] = []
    run_evidence: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, int]] = set()
    seen_units: set[tuple[str, int, int]] = set()

    for path in paths:
        metrics, _ = auditor(path)
        ceilings = _normalize_ceilings(metrics.get("effective_limits"))
        if ceilings is None:
            raise ValueError(f"missing normalized ceiling limits in {path}")
        launch = json.loads(path.read_text(encoding="utf-8"))
        prepared = prepared_loader(launch["preflight"])
        contracts.append(prepared["contract"]["holdout"])
        unit_fingerprints.append(_compute_unit_fingerprints(prepared))
        run_ceilings.append(ceilings)
        run_metrics.append(metrics)

        family = metrics["family"]
        seed = int(launch["seed"])
        resolved_str = str(path)
        if resolved_str in unit_by_manifest:
            unit_meta = unit_by_manifest[resolved_str]
            if unit_meta["family"] != family or int(unit_meta["seed"]) != seed:
                raise ValueError(f"unit metadata mismatch for {path}")
            rep = int(unit_meta["repetition"])
            experiment_id = str(unit_meta["experiment_id"])
        else:
            if (family, seed) in seen_pairs and exp_manifest is None:
                raise ValueError(
                    f"duplicate (family, seed) ({family}, {seed}) requires frozen experiment manifest repetitions"
                )
            seen_pairs.add((family, seed))
            rep = 1
            experiment_id = f"{family}:{seed}:rep{rep}"

        unit_key = (family, seed, rep)
        if unit_key in seen_units:
            raise ValueError(f"duplicate experiment unit {experiment_id}")
        seen_units.add(unit_key)

        if exp_manifest is not None:
            frozen_unit = expected_units_by_id.get(experiment_id)
            if frozen_unit is None:
                raise ValueError(f"unexpected experiment unit not in frozen manifest: {experiment_id}")
            if (frozen_unit["family"] != family or int(frozen_unit["seed"]) != seed
                    or int(frozen_unit["repetition"]) != rep):
                raise ValueError(f"experiment unit identity mismatch for {experiment_id}")
            if holdout.digest(launch["preflight"]) != frozen_unit["preflight_sha256"]:
                raise ValueError(f"preflight digest mismatch for {experiment_id}")

        run_dir = path.parent
        funnel = extract_run_funnel(run_dir, launch)
        evidence_refs = dict(metrics.get("evidence_refs") or {})
        preflight_file = Path(launch["preflight"]).resolve(strict=True)
        evidence_refs["preflight"] = {"path": str(preflight_file), "sha256": holdout.digest(preflight_file)}
        contract_file = Path(prepared["manifest"]["contract"]).resolve(strict=True)
        evidence_refs["contract"] = {"path": str(contract_file), "sha256": holdout.digest(contract_file)}
        budget_file = run_dir / "private/budget.json"
        if budget_file.is_file():
            evidence_refs["budget"] = {"path": str(budget_file), "sha256": holdout.digest(budget_file)}

        run_evidence.append({
            "experiment_id": experiment_id,
            "family": family,
            "seed": seed,
            "repetition": rep,
            "status": launch.get("status"),
            "failed": metrics["failed"],
            "failure_reason": metrics.get("failure_reason"),
            "closure_verified": metrics["closure_verified"],
            "models": metrics.get("models"),
            "effective_limits": ceilings,
            "recall": metrics["recall"],
            "negative_coverage": metrics["negative_coverage"],
            "false_positives": metrics["false_positives"],
            "verified_findings": metrics["verified_findings"],
            "usage": metrics.get("usage"),
            "funnel": funnel,
            "evidence_refs": evidence_refs,
            "not_tested": metrics.get("not_tested"),
        })

    if any(contract != contracts[0] for contract in contracts):
        raise ValueError("holdout contracts differ across cohort")
    if any(ceiling != run_ceilings[0] for ceiling in run_ceilings):
        raise ValueError("effective HTTP/token/seconds ceilings differ across cohort runs")
    if expected_ceilings is not None and run_ceilings[0] != _normalize_ceilings(expected_ceilings):
        raise ValueError("cohort ceilings do not match expected shared ceilings")

    fingerprints = _aggregate_cohort_fingerprints(unit_fingerprints)
    summary = _aggregate_cohort_metrics(run_metrics, run_evidence, contracts[0])
    if len(summary["families"]) < MINIMUM_FAMILIES:
        raise ValueError("E6 cohort requires >=3 distinct registered families")

    if exp_manifest is not None:
        if set(expected_units_by_id) != {item["experiment_id"] for item in run_evidence}:
            raise ValueError("audited runs do not cover all frozen experiment units")
        if run_ceilings[0] != _normalize_ceilings(exp_manifest.get("ceilings")):
            raise ValueError("cohort ceilings differ from frozen experiment manifest")
        if fingerprints != exp_manifest.get("fingerprints"):
            raise ValueError("cohort fingerprints differ from frozen experiment manifest")
        treatment = normalize_treatment(exp_manifest.get("treatment"))
        acceptance_criteria = normalize_acceptance_criteria(exp_manifest.get("acceptance_criteria"), contracts[0])
        provenance_mode = "frozen_paired_experiment"
        strict_eligible = True
    else:
        treatment = normalize_treatment(None)
        acceptance_criteria = normalize_acceptance_criteria(None, contracts[0])
        provenance_mode = "audited_manifests_without_prefrozen_experiment_manifest"
        strict_eligible = False

    seeds_by_family: dict[str, list[int]] = {}
    repetitions_set: set[int] = set()
    for row in run_evidence:
        seeds_by_family.setdefault(row["family"], [])
        if row["seed"] not in seeds_by_family[row["family"]]:
            seeds_by_family[row["family"]].append(row["seed"])
        repetitions_set.add(row["repetition"])
    for fam in seeds_by_family:
        seeds_by_family[fam].sort()
    repetitions_count = max(repetitions_set) if repetitions_set else 1

    evidence_bundle_digest = _canonical_sha256([
        {"experiment_id": row["experiment_id"], "evidence_refs": row["evidence_refs"]}
        for row in sorted(run_evidence, key=lambda item: item["experiment_id"])
    ])

    report_body: dict[str, Any] = {
        "schema": SCHEMA_COHORT,
        "label": label,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "ceilings": run_ceilings[0],
        "families": summary["families"],
        "seeds_by_family": seeds_by_family,
        "repetitions": repetitions_count,
        "models": summary["models"],
        "provider_kinds": summary["provider_kinds"],
        "paid_provider_calls": holdout._sum_optional([row.get("paid_provider_calls") for row in run_metrics]),
        "authorization": authorization,
        "positives": summary["positives"],
        "negatives": summary["negatives"],
        "verified_findings": summary["verified_findings"],
        "recall": _with_ratio_value(summary["overall_recall"]),
        "false_positives": _with_ratio_value(summary["false_positives"]),
        "negative_coverage": _with_ratio_value(summary["negative_coverage"]),
        "failed_run_rate": summary["failed_runs"],
        "requests_per_verified_finding": summary["requests_per_verified_finding"],
        "tokens_per_verified_finding": summary["tokens_per_verified_finding"],
        "usage": summary["usage"],
        "funnel": summary["funnel"],
        "aggregate_status": summary["status"],
        "checks": summary["checks"],
        "paid_model_generalization": summary["paid_model_generalization"],
        "per_family": summary["per_family"],
        "not_tested_dimensions": summary["not_tested_dimensions"],
        "fingerprints": fingerprints,
        "treatment": treatment,
        "acceptance_criteria": acceptance_criteria,
        "runs": run_evidence,
        "provenance": {
            "mode": provenance_mode,
            "strict_paired_eligible": strict_eligible,
            "experiment_manifest": (
                {"path": str(exp_manifest_path), "sha256": holdout.digest(exp_manifest_path)}
                if exp_manifest_path is not None else None
            ),
            "evidence_bundle_digest": evidence_bundle_digest,
        },
    }
    report_body["acceptance"] = evaluate_acceptance(report_body, acceptance_criteria)
    report_body["report_digest"] = _canonical_sha256(report_body)
    return report_body


def _ratio_value(ratio: dict[str, Any]) -> float | None:
    if "value" in ratio:
        return ratio["value"]
    return holdout._ratio(ratio["numerator"], ratio["denominator"])


def _with_ratio_value(ratio: dict[str, Any]) -> dict[str, Any]:
    return {
        "numerator": ratio["numerator"],
        "denominator": ratio["denominator"],
        "value": _ratio_value(ratio),
    }


def _load_cohort_input(value: dict[str, Any] | str | Path) -> tuple[dict[str, Any], Path | None]:
    if isinstance(value, dict):
        data = value
        path = None
    else:
        path = Path(value).expanduser().resolve(strict=True)
        data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") not in {SCHEMA_COHORT, SCHEMA_LEGACY_DERIVED}:
        raise ValueError("expected a full-agent-e6-cohort/1 report")
    return data, path


def _verify_report_digest(data: dict[str, Any]) -> None:
    recorded = data.get("report_digest")
    if not isinstance(recorded, str) or not recorded:
        raise ValueError("cohort report is missing audited report_digest")
    payload = {k: v for k, v in data.items() if k != "report_digest"}
    if _canonical_sha256(payload) != recorded:
        raise ValueError("cohort report digest mismatch (tampered report)")


def _reaudit_cohort_report(data: dict[str, Any]) -> dict[str, Any]:
    """Re-audit a frozen paired cohort report read-only from its underlying manifests and artifacts."""
    _verify_report_digest(data)
    provenance = data.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("mode") != "frozen_paired_experiment":
        raise ValueError("strict paired comparison requires frozen_paired_experiment provenance")
    if provenance.get("strict_paired_eligible") is not True:
        raise ValueError("cohort report is not eligible for strict paired comparison")
    exp_ref = provenance.get("experiment_manifest")
    if not isinstance(exp_ref, dict) or not exp_ref.get("path") or not exp_ref.get("sha256"):
        raise ValueError("cohort report is missing experiment manifest reference")
    exp_path = Path(exp_ref["path"]).resolve(strict=True)
    if holdout.digest(exp_path) != exp_ref["sha256"]:
        raise ValueError("experiment manifest file digest mismatch")

    runs = data.get("runs")
    if not isinstance(runs, list) or len(runs) < MINIMUM_FAMILIES:
        raise ValueError("cohort report has insufficient verifiable run entries")

    manifest_paths: list[Path] = []
    unit_runs: list[dict[str, Any]] = []
    for row in runs:
        refs = row.get("evidence_refs") or {}
        mref = refs.get("manifest")
        if not isinstance(mref, dict) or not mref.get("path") or not mref.get("sha256"):
            raise ValueError("cohort run is missing verifiable launch manifest reference")
        mpath = Path(mref["path"]).resolve(strict=True)
        if holdout.digest(mpath) != mref["sha256"]:
            raise ValueError(f"launch manifest digest mismatch for {row.get('experiment_id', row.get('family'))}")
        for ref_key, ref_val in refs.items():
            if ref_key == "validation_artifacts_count" or not isinstance(ref_val, dict):
                continue
            rpath = Path(ref_val["path"]).resolve(strict=True)
            if holdout.digest(rpath) != ref_val["sha256"]:
                raise ValueError(f"evidence artifact digest mismatch ({ref_key}) in {row.get('experiment_id')}")
        manifest_paths.append(mpath)
        unit_runs.append({
            "experiment_id": row["experiment_id"],
            "family": row["family"],
            "seed": row["seed"],
            "repetition": row["repetition"],
            "manifest": str(mpath),
            "manifest_sha256": mref["sha256"],
        })

    reaudited = audit_cohort(
        data["label"],
        manifest_paths,
        expected_ceilings=data.get("ceilings"),
        authorization=data.get("authorization"),
        experiment_manifest=exp_path,
        unit_runs=unit_runs,
        readonly=True,
        created_at=data.get("created_at"),
    )
    immutable_keys = (
        "ceilings", "families", "seeds_by_family", "repetitions", "models",
        "positives", "negatives", "verified_findings", "recall", "false_positives",
        "negative_coverage", "failed_run_rate", "requests_per_verified_finding",
        "tokens_per_verified_finding", "usage", "funnel", "aggregate_status", "checks",
        "fingerprints", "treatment", "acceptance_criteria", "acceptance",
    )
    for key in immutable_keys:
        if reaudited.get(key) != data.get(key):
            raise ValueError(f"cohort report field {key!r} does not match re-audited artifacts")
    if reaudited["provenance"]["evidence_bundle_digest"] != provenance.get("evidence_bundle_digest"):
        raise ValueError("cohort evidence bundle digest does not match re-audited artifacts")
    return reaudited


def reaudit_legacy_cohort(report_path: str | Path, *, label: str | None = None) -> dict[str, Any]:
    """Safely re-audit a legacy full-agent-e6-cohort/1 report read-only without mutating archives.

    Derives verifiable fingerprints, denominators, usage, and provenance gaps from archived
    manifests/preflights. Never fabricates fingerprints or promotes a legacy report to
    strict_paired_eligible=True.
    """
    source_path = Path(report_path).expanduser().resolve(strict=True)
    legacy = json.loads(source_path.read_text(encoding="utf-8"))
    if not isinstance(legacy, dict) or legacy.get("schema") != SCHEMA_COHORT:
        raise ValueError("expected a legacy full-agent-e6-cohort/1 report")

    runs = legacy.get("runs")
    if not isinstance(runs, list) or len(runs) < MINIMUM_FAMILIES:
        raise ValueError("legacy report is missing run evidence entries")

    manifest_paths: list[Path] = []
    unit_runs: list[dict[str, Any]] = []
    for idx, row in enumerate(runs):
        refs = row.get("evidence_refs") or {}
        mref = refs.get("manifest")
        if not isinstance(mref, dict) or not mref.get("path") or not mref.get("sha256"):
            raise ValueError("legacy run entry is missing launch manifest evidence reference")
        mpath = Path(mref["path"]).resolve(strict=True)
        if holdout.digest(mpath) != mref["sha256"]:
            raise ValueError(f"legacy launch manifest digest mismatch for {row.get('family')}:{row.get('seed')}")
        for ref_key, ref_val in refs.items():
            if ref_key == "validation_artifacts_count" or not isinstance(ref_val, dict):
                continue
            rpath = Path(ref_val["path"]).resolve(strict=True)
            if holdout.digest(rpath) != ref_val["sha256"]:
                raise ValueError(f"legacy evidence artifact digest mismatch ({ref_key})")
        manifest_paths.append(mpath)
        rep = int(row.get("repetition", 1))
        family = row["family"]
        seed = int(row["seed"])
        unit_runs.append({
            "experiment_id": row.get("experiment_id") or f"{family}:{seed}:rep{rep}",
            "family": family,
            "seed": seed,
            "repetition": rep,
            "manifest": str(mpath),
            "manifest_sha256": mref["sha256"],
        })

    reaudited = audit_cohort(
        label or legacy["label"],
        manifest_paths,
        expected_ceilings=legacy.get("ceilings"),
        authorization=legacy.get("authorization"),
        unit_runs=unit_runs,
        readonly=True,
        created_at=legacy.get("created_at"),
    )
    for key in (
        "ceilings", "families", "positives", "negatives", "verified_findings",
        "recall", "false_positives", "negative_coverage", "failed_run_rate",
        "usage", "aggregate_status", "checks",
    ):
        if reaudited.get(key) != legacy.get(key):
            raise ValueError(f"legacy report field {key!r} does not match read-only re-audited artifacts")

    unrecoverable_provenance = [
        "no_pre_execution_experiment_manifest",
        "no_pre_frozen_treatment_or_acceptance_criteria",
    ]
    if all(len(s) <= 1 for s in reaudited["seeds_by_family"].values()):
        unrecoverable_provenance.append("single_seed_per_family")
    if reaudited["repetitions"] <= 1:
        unrecoverable_provenance.append("single_repetition")
    if not reaudited["funnel"].get("funnel_present"):
        unrecoverable_provenance.append("missing_runtime_funnel_metrics")

    not_tested = list(reaudited["not_tested_dimensions"])
    for extra in (
        "multi_seed_generalization",
        "multi_repetition_stability",
        "paired_pre_execution_manifest",
        "runtime_validation_funnel",
    ):
        if extra not in not_tested:
            not_tested.append(extra)

    derived: dict[str, Any] = {
        **reaudited,
        "schema": SCHEMA_LEGACY_DERIVED,
        "source_report": {"path": str(source_path), "sha256": holdout.digest(source_path)},
        "not_tested_dimensions": not_tested,
        "unrecoverable_provenance": unrecoverable_provenance,
        "provenance": {
            **reaudited["provenance"],
            "mode": "legacy_reaudited_derived",
            "strict_paired_eligible": False,
            "verifiable_from_archive": [
                "launch_manifests",
                "preflight_contracts_and_host_runtime_hashes",
                "evaluator_selections_truth_wire_and_lab_sources",
                "signed_attempt_ledgers_and_closures",
                "secret_free_provider_config_snapshots",
            ],
            "unrecoverable_provenance": unrecoverable_provenance,
        },
    }
    derived.pop("report_digest", None)
    derived["report_digest"] = _canonical_sha256(derived)
    return derived


def _is_legacy_input(data: dict[str, Any]) -> bool:
    if data.get("schema") == SCHEMA_LEGACY_DERIVED:
        return True
    prov = data.get("provenance")
    return not isinstance(prov, dict) or prov.get("mode") != "frozen_paired_experiment"


def _compute_descriptive_slice(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare overlapping (family, seed) pairs between a legacy baseline and a newer cohort."""
    b_pairs = {(r["family"], int(r["seed"])) for r in before["runs"]}
    a_matching = [r for r in after["runs"] if (r["family"], int(r["seed"])) in b_pairs]
    if not a_matching:
        return {"overlapping_pairs": [], "available": False}
    tp = sum(r["recall"]["numerator"] for r in a_matching)
    pos = sum(r["recall"]["denominator"] for r in a_matching)
    tested = sum(r["negative_coverage"]["numerator"] for r in a_matching)
    neg = sum(r["negative_coverage"]["denominator"] for r in a_matching)
    fp = sum(r["false_positives"]["numerator"] for r in a_matching)
    fp_den = sum(r["false_positives"]["denominator"] for r in a_matching)
    failed = sum(1 for r in a_matching if r.get("failed"))
    http_sum = holdout._sum_optional([(r.get("usage") or {}).get("http_requests") for r in a_matching])
    tok_sum = holdout._sum_optional([(r.get("usage") or {}).get("tokens_used") for r in a_matching])
    cost_sum = holdout._sum_optional([(r.get("usage") or {}).get("cost_usd") for r in a_matching])
    return {
        "available": True,
        "overlapping_pairs": sorted(f"{f}:{s}" for f, s in b_pairs if any(
            (r["family"], int(r["seed"])) == (f, s) for r in a_matching)),
        "after_matching_runs_count": len(a_matching),
        "after_matching": {
            "recall": {"numerator": tp, "denominator": pos, "value": holdout._ratio(tp, pos)},
            "negative_coverage": {"numerator": tested, "denominator": neg, "value": holdout._ratio(tested, neg)},
            "false_positives": {"numerator": fp, "denominator": fp_den, "value": holdout._ratio(fp, fp_den)},
            "failed_run_rate": {
                "numerator": failed,
                "denominator": len(a_matching),
                "value": holdout._ratio(failed, len(a_matching)),
            },
            "http_requests": http_sum,
            "tokens_used": tok_sum,
            "cost_usd": cost_sum,
        },
        "deltas_vs_before": {
            "recall": _delta(_ratio_value(before["recall"]), holdout._ratio(tp, pos)),
            "negative_coverage": _delta(_ratio_value(before["negative_coverage"]), holdout._ratio(tested, neg)),
            "false_positives_count": _delta(before["false_positives"]["numerator"], fp),
            "failed_run_rate": _delta(
                _ratio_value(before["failed_run_rate"]), holdout._ratio(failed, len(a_matching))),
            "http_requests": _delta(before["usage"]["http_requests"], http_sum),
            "tokens_used": _delta(before["usage"]["tokens_used"], tok_sum),
            "cost_usd": _delta(before["usage"]["cost_usd"], cost_sum),
        },
    }


def _build_funnel_comparison(b_funnel: dict[str, Any], a_funnel: dict[str, Any]) -> dict[str, Any]:
    deltas: dict[str, Any] = {}
    for stage in FUNNEL_STAGES:
        deltas[stage] = _delta(b_funnel.get(stage), a_funnel.get(stage))
    rate_deltas: dict[str, Any] = {}
    b_rates = b_funnel.get("rates") or {}
    a_rates = a_funnel.get("rates") or {}
    for rate_key in ("eligible_rate", "admitted_rate", "executed_rate", "accepted_rate", "end_to_end_yield"):
        rate_deltas[rate_key] = _delta(b_rates.get(rate_key), a_rates.get(rate_key))
    deltas["rates"] = rate_deltas
    return {"before": b_funnel, "after": a_funnel, "deltas": deltas}


def compare_cohorts(before: dict[str, Any] | str | Path,
                    after: dict[str, Any] | str | Path,
                    *, mode: str = "strict") -> dict[str, Any]:
    """Compare before/after E6 cohorts.

    In 'strict' mode (default), re-audits underlying manifests/artifacts read-only and
    rejects legacy, unverifiable, tampered, unpaired, or undeclared-difference inputs.
    In 'descriptive' mode, allows safe read-only re-audited legacy baseline comparison
    while preserving explicit unrecoverable provenance and NOT TESTED limitations.
    """
    if mode not in {"strict", "descriptive"}:
        raise ValueError(f"unsupported comparison mode: {mode!r}")

    raw_b, path_b = _load_cohort_input(before)
    raw_a, path_a = _load_cohort_input(after)

    if raw_b.get("ceilings") is None or raw_b.get("ceilings") != raw_a.get("ceilings"):
        raise ValueError("before/after cohorts must share identical token, HTTP, and duration ceilings")
    if set(raw_b.get("families", [])) != set(raw_a.get("families", [])) or len(raw_b["families"]) < MINIMUM_FAMILIES:
        raise ValueError("before/after cohorts must cover the same >=3 independent families")
    if mode == "strict":
        if _is_legacy_input(raw_b) or _is_legacy_input(raw_a):
            raise ValueError(
                "unverifiable or legacy cohort report cannot be used in strict paired comparison; "
                "use mode='descriptive' after read-only legacy re-audit"
            )
    for family in raw_b["families"]:
        bf, af = raw_b["per_family"][family], raw_a["per_family"][family]
        if (bf["recall"]["denominator"] != af["recall"]["denominator"]
                or bf["negative_coverage"]["denominator"] != af["negative_coverage"]["denominator"]):
            if mode == "strict":
                raise ValueError(f"before/after positive/negative counts mismatch for {family}")
    if mode == "strict":
        b = _reaudit_cohort_report(raw_b)
        a = _reaudit_cohort_report(raw_a)
    else:
        if raw_b.get("schema") == SCHEMA_LEGACY_DERIVED:
            _verify_report_digest(raw_b)
            b = reaudit_legacy_cohort(raw_b["source_report"]["path"], label=raw_b.get("label"))
        elif _is_legacy_input(raw_b):
            if path_b is None:
                raise ValueError("descriptive legacy re-audit requires a file path to cohort-report.json")
            b = reaudit_legacy_cohort(path_b)
        else:
            b = _reaudit_cohort_report(raw_b)

        if raw_a.get("schema") == SCHEMA_LEGACY_DERIVED:
            _verify_report_digest(raw_a)
            a = reaudit_legacy_cohort(raw_a["source_report"]["path"], label=raw_a.get("label"))
        elif _is_legacy_input(raw_a):
            if path_a is None:
                raise ValueError("descriptive legacy re-audit requires a file path to cohort-report.json")
            a = reaudit_legacy_cohort(path_a)
        else:
            a = _reaudit_cohort_report(raw_a)

    b_units = {(r["family"], int(r["seed"]), int(r["repetition"])): r for r in b["runs"]}
    a_units = {(r["family"], int(r["seed"]), int(r["repetition"])): r for r in a["runs"]}
    b_fp = b["fingerprints"]
    a_fp = a["fingerprints"]
    if b_fp["evaluator"] != a_fp["evaluator"]:
        raise ValueError("evaluator fingerprints differ between before and after cohorts")

    b_treatment = normalize_treatment(b.get("treatment"))
    a_treatment = normalize_treatment(a.get("treatment"))
    allowed_diffs = sorted(set(b_treatment["changed_dimensions"]) | set(a_treatment["changed_dimensions"]))

    fingerprint_diffs: dict[str, dict[str, Any]] = {}
    for dim in ("evaluator", "runtime", "prompt_catalog", "provider_config"):
        matched = b_fp[dim] == a_fp[dim]
        declared = dim in allowed_diffs
        if mode == "strict" and not matched and not declared:
            raise ValueError(f"undeclared {dim} difference between before and after cohorts")
        fingerprint_diffs[dim] = {
            "matched": matched,
            "declared_allowed": declared,
            "before": b_fp[dim],
            "after": a_fp[dim],
        }

    if mode == "strict":
        if set(b_units) != set(a_units):
            raise ValueError("before/after paired family x seed x repetition identities do not match")
        for key, bu in b_units.items():
            au = a_units[key]
            if (bu["recall"]["denominator"] != au["recall"]["denominator"]
                    or bu["negative_coverage"]["denominator"] != au["negative_coverage"]["denominator"]):
                raise ValueError(f"before/after positive/negative denominators mismatch for {key}")
        if b.get("acceptance_criteria") != a.get("acceptance_criteria"):
            raise ValueError("before/after acceptance criteria must match in strict paired comparison")

    per_family: dict[str, Any] = {}
    for family in sorted(b["families"]):
        bf, af = b["per_family"][family], a["per_family"][family]
        per_family[family] = {
            "before": bf,
            "after": af,
            "deltas": {
                "recall": _delta(bf["recall"]["value"], af["recall"]["value"]),
                "negative_coverage": _delta(bf["negative_coverage"]["value"], af["negative_coverage"]["value"]),
                "false_positives_count": _delta(bf["false_positives"]["numerator"], af["false_positives"]["numerator"]),
                "requests_per_verified_finding": _delta(
                    bf["requests_per_verified_finding"], af["requests_per_verified_finding"]),
                "tokens_per_verified_finding": _delta(
                    bf["tokens_per_verified_finding"], af["tokens_per_verified_finding"]),
            },
        }

    not_tested: list[str] = []
    for dim in (*b.get("not_tested_dimensions", []), *a.get("not_tested_dimensions", [])):
        if dim not in not_tested:
            not_tested.append(dim)

    unrecoverable: list[str] = []
    for item in (*b.get("unrecoverable_provenance", []), *a.get("unrecoverable_provenance", [])):
        if item not in unrecoverable:
            unrecoverable.append(item)
    if mode == "descriptive" and "non_strict_descriptive_comparison" not in not_tested:
        not_tested.append("non_strict_descriptive_comparison")

    paired_strict = mode == "strict"
    summary_keys = (
        "label", "models", "provider_kinds", "paid_provider_calls", "recall",
        "false_positives", "negative_coverage", "failed_run_rate", "verified_findings",
        "requests_per_verified_finding", "tokens_per_verified_finding", "usage",
        "funnel", "aggregate_status", "paid_model_generalization", "acceptance",
    )
    comparison: dict[str, Any] = {
        "schema": SCHEMA_COMPARE,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "comparison_mode": "strict_paired" if paired_strict else "descriptive_legacy_baseline",
        "strict_paired": paired_strict,
        "reaudited_from_artifacts": True,
        "ceilings": b["ceilings"],
        "ceilings_matched": True,
        "families": sorted(b["families"]),
        "seeds_by_family": {"before": b["seeds_by_family"], "after": a["seeds_by_family"]},
        "repetitions": {"before": b["repetitions"], "after": a["repetitions"]},
        "paired_units_count": len(a_units) if paired_strict else None,
        "models": {"before": b["models"], "after": a["models"]},
        "fingerprints": fingerprint_diffs,
        "treatment": {
            "before": b_treatment,
            "after": a_treatment,
            "allowed_differences": allowed_diffs,
        },
        "acceptance_criteria": a.get("acceptance_criteria"),
        "acceptance_passed": {
            "before": bool((b.get("acceptance") or {}).get("passed")),
            "after": bool((a.get("acceptance") or {}).get("passed")),
        },
        "before": {key: b.get(key) for key in summary_keys},
        "after": {key: a.get(key) for key in summary_keys},
        "deltas": {
            "recall": _delta(_ratio_value(b["recall"]), _ratio_value(a["recall"])),
            "negative_coverage": _delta(_ratio_value(b["negative_coverage"]), _ratio_value(a["negative_coverage"])),
            "false_positives_count": _delta(b["false_positives"]["numerator"], a["false_positives"]["numerator"]),
            "false_positives_rate": _delta(_ratio_value(b["false_positives"]), _ratio_value(a["false_positives"])),
            "failed_run_rate": _delta(_ratio_value(b["failed_run_rate"]), _ratio_value(a["failed_run_rate"])),
            "verified_findings": _delta(b["verified_findings"], a["verified_findings"]),
            "requests_per_verified_finding": _delta(
                b["requests_per_verified_finding"], a["requests_per_verified_finding"]),
            "tokens_per_verified_finding": _delta(
                b["tokens_per_verified_finding"], a["tokens_per_verified_finding"]),
            "http_requests": _delta(b["usage"]["http_requests"], a["usage"]["http_requests"]),
            "tokens_used": _delta(b["usage"]["tokens_used"], a["usage"]["tokens_used"]),
            "cost_usd": _delta(b["usage"]["cost_usd"], a["usage"]["cost_usd"]),
        },
        "funnel": _build_funnel_comparison(b["funnel"], a["funnel"]),
        "per_family": per_family,
        "evidence": {
            "before_runs": b["runs"],
            "after_runs": a["runs"],
            "before_report_digest": b.get("report_digest"),
            "after_report_digest": a.get("report_digest"),
        },
        "unrecoverable_provenance": unrecoverable,
        "not_tested_dimensions": not_tested,
    }
    if not paired_strict:
        comparison["descriptive_overlapping_seed_slice"] = _compute_descriptive_slice(b, a)
    return comparison


def _fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return "unknown (not zero)"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def render_cohort_markdown(report: dict[str, Any]) -> str:
    funnel = report.get("funnel") or _unknown_funnel()
    lines = [
        f"# E6 Cohort Report: {report['label']}",
        "",
        f"- Provenance Mode: `{(report.get('provenance') or {}).get('mode', 'unknown')}` "
        f"(`strict_paired_eligible={(report.get('provenance') or {}).get('strict_paired_eligible', False)}`)",
        f"- Models: `{', '.join(report['models']) or 'none'}` (`{', '.join(report['provider_kinds'])}`)",
        f"- Seeds/Family: `{json.dumps(report.get('seeds_by_family', {}), sort_keys=True)}` "
        f"(repetitions=`{report.get('repetitions', 1)}`)",
        f"- Ceilings (per seed): `http={report['ceilings']['http_requests_per_seed']}`, "
        f"`tokens={report['ceilings']['llm_tokens_per_seed']}`, `seconds={report['ceilings']['seconds_per_seed']}`",
        f"- Recall: `{report['recall']['numerator']}/{report['recall']['denominator']}` ({_fmt(_ratio_value(report['recall']))})",
        f"- False Positives: `{report['false_positives']['numerator']}/{report['false_positives']['denominator']}` "
        f"({_fmt(_ratio_value(report['false_positives']))})",
        f"- Negative Coverage: `{report['negative_coverage']['numerator']}/{report['negative_coverage']['denominator']}` "
        f"({_fmt(_ratio_value(report['negative_coverage']))})",
        f"- Failed Run Rate: `{report['failed_run_rate']['numerator']}/{report['failed_run_rate']['denominator']}` "
        f"({_fmt(_ratio_value(report['failed_run_rate']))})",
        f"- Requests / Verified Finding: `{_fmt(report['requests_per_verified_finding'])}`",
        f"- Tokens / Verified Finding: `{_fmt(report['tokens_per_verified_finding'])}`",
        f"- Cost (USD): `{_fmt(report['usage']['cost_usd'], 6)}` (`unknown_cost_is_zero=False`)",
        f"- Funnel (`{funnel.get('status', 'unknown')}`): "
        f"observed=`{_fmt(funnel.get('observed'), 0)}`, "
        f"eligible=`{_fmt(funnel.get('eligible'), 0)}`, "
        f"admitted=`{_fmt(funnel.get('admitted'), 0)}`, "
        f"executed=`{_fmt(funnel.get('executed'), 0)}`, "
        f"accepted=`{_fmt(funnel.get('evidence_accepted'), 0)}`",
        "",
        "## NOT TESTED Dimensions",
        *[f"- `{dim}`" for dim in report["not_tested_dimensions"]],
        "",
    ]
    return "\n".join(lines)


def render_comparison_markdown(comparison: dict[str, Any]) -> str:
    b, a, d = comparison["before"], comparison["after"], comparison["deltas"]
    c = comparison["ceilings"]
    lines = [
        f"# E6 Before/After Comparison: {b['label']} vs {a['label']}",
        "",
        f"- Mode: `{comparison.get('comparison_mode', 'strict_paired')}` "
        f"(`strict_paired={comparison.get('strict_paired', False)}`, "
        f"`reaudited_from_artifacts={comparison.get('reaudited_from_artifacts', False)}`)",
        f"- Shared Ceilings: `http={c['http_requests_per_seed']}`, "
        f"`tokens={c['llm_tokens_per_seed']}`, `seconds={c['seconds_per_seed']}` (`matched={comparison['ceilings_matched']}`)",
        f"- Families ({len(comparison['families'])}): `{', '.join(comparison['families'])}`",
        "",
        "| Metric | Before | After | Delta |",
        "|---|---:|---:|---:|",
        f"| Recall | {_fmt(_ratio_value(b['recall']))} | {_fmt(_ratio_value(a['recall']))} | {_fmt(d['recall'])} |",
        f"| False Positives | {b['false_positives']['numerator']} | {a['false_positives']['numerator']} | {_fmt(d['false_positives_count'], 0)} |",
        f"| Negative Coverage | {_fmt(_ratio_value(b['negative_coverage']))} | {_fmt(_ratio_value(a['negative_coverage']))} | {_fmt(d['negative_coverage'])} |",
        f"| Requests / Verified Finding | {_fmt(b['requests_per_verified_finding'])} | {_fmt(a['requests_per_verified_finding'])} | {_fmt(d['requests_per_verified_finding'])} |",
        f"| Tokens / Verified Finding | {_fmt(b['tokens_per_verified_finding'])} | {_fmt(a['tokens_per_verified_finding'])} | {_fmt(d['tokens_per_verified_finding'])} |",
        f"| Failed Run Rate | {_fmt(_ratio_value(b['failed_run_rate']))} | {_fmt(_ratio_value(a['failed_run_rate']))} | {_fmt(d['failed_run_rate'])} |",
        f"| Cost (USD) | {_fmt(b['usage']['cost_usd'], 6)} | {_fmt(a['usage']['cost_usd'], 6)} | {_fmt(d['cost_usd'], 6)} |",
        "",
        "## NOT TESTED Dimensions",
        *[f"- `{dim}`" for dim in comparison["not_tested_dimensions"]],
        "",
    ]
    return "\n".join(lines)


def _parse_cli_seeds(seed_args: list[str] | None) -> dict[str, list[int]] | None:
    if not seed_args:
        return None
    parsed: dict[str, list[int]] = {}
    for entry in seed_args:
        raw = entry.strip()
        if raw.startswith("{"):
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise ValueError("--seeds JSON must be an object mapping family to seed list")
            for fam, vals in obj.items():
                parsed[fam] = [int(vals)] if type(vals) is int else [int(v) for v in vals]
            continue
        if "=" not in raw:
            raise ValueError("--seeds entries must use FAMILY=SEED1,SEED2 format or a JSON object")
        fam, vals_str = raw.split("=", 1)
        fam = fam.strip()
        vals = [int(part.strip()) for part in vals_str.split(",") if part.strip()]
        if not fam or not vals:
            raise ValueError(f"invalid --seeds specification: {entry!r}")
        parsed.setdefault(fam, []).extend(vals)
    return parsed


def _parse_cli_treatment(args: argparse.Namespace) -> dict[str, Any] | None:
    if not (args.treatment_name or args.treatment_description or args.treatment_diff or args.treatment_role != "baseline"):
        return None
    return {
        "name": args.treatment_name or args.treatment_role,
        "role": args.treatment_role,
        "description": args.treatment_description,
        "changed_dimensions": list(args.treatment_diff or []),
    }


def _parse_cli_acceptance(args: argparse.Namespace) -> dict[str, Any] | None:
    overrides: dict[str, Any] = {}
    if args.min_overall_recall is not None:
        overrides["overall_recall"] = args.min_overall_recall
    if args.min_per_family_recall is not None:
        overrides["per_family_recall"] = args.min_per_family_recall
    if args.min_negative_coverage is not None:
        overrides["negative_coverage"] = args.min_negative_coverage
    if args.max_failed_run_rate is not None:
        overrides["max_failed_run_rate"] = args.max_failed_run_rate
    return overrides or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    for name in ("plan", "run"):
        p = sub.add_parser(name)
        p.add_argument("--label", required=True)
        p.add_argument("--baseline", type=Path, required=True)
        p.add_argument("--provider-config", type=Path, default=llm_config.default_config())
        p.add_argument("--output-dir", type=Path, required=True)
        p.add_argument("--family", action="append", dest="families")
        p.add_argument("--seeds", action="append", dest="seeds",
                       help="Per-family seeds as FAMILY=S1,S2,... or JSON object")
        p.add_argument("--repetitions", type=int, default=1)
        p.add_argument("--model", default="")
        p.add_argument("--worker-model", default="")
        p.add_argument("--http-budget", type=int, default=preflight.MAX_REQUESTS)
        p.add_argument("--token-budget", type=int, default=150000)
        p.add_argument("--seconds-budget", type=int, default=900)
        p.add_argument("--treatment-name", default="")
        p.add_argument("--treatment-role", choices=("baseline", "control", "treatment"), default="baseline")
        p.add_argument("--treatment-description", default="")
        p.add_argument("--treatment-diff", action="append", choices=VALID_TREATMENT_DIMENSIONS)
        p.add_argument("--min-overall-recall", type=float, default=None)
        p.add_argument("--min-per-family-recall", type=float, default=None)
        p.add_argument("--min-negative-coverage", type=float, default=None)
        p.add_argument("--max-failed-run-rate", type=float, default=None)
        if name == "run":
            p.add_argument("--execute", action="store_true")
            p.add_argument("--authorize-live-provider", action="store_true")
            p.add_argument("--live-authorization-reason", default="")
            p.add_argument("--api-key-env", default=None)
            p.add_argument("--enforce-acceptance", action="store_true")

    audit_p = sub.add_parser("audit")
    audit_p.add_argument("--label", required=True)
    audit_p.add_argument("--manifest", action="append", required=True)
    audit_p.add_argument("--experiment-manifest", type=Path, default=None)
    audit_p.add_argument("--output", type=Path, default=None)
    audit_p.add_argument("--enforce-acceptance", action="store_true")

    legacy_p = sub.add_parser("reaudit-legacy")
    legacy_p.add_argument("--report", type=Path, required=True)
    legacy_p.add_argument("--label", default=None)
    legacy_p.add_argument("--output", type=Path, default=None)

    cmp_p = sub.add_parser("compare")
    cmp_p.add_argument("--before", type=Path, required=True)
    cmp_p.add_argument("--after", type=Path, required=True)
    cmp_p.add_argument("--output-dir", type=Path, default=None)
    cmp_p.add_argument("--mode", choices=("strict", "descriptive"), default="strict")
    cmp_p.add_argument("--enforce-acceptance", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.action == "plan":
            path, plan = prepare_cohort(
                args.label, baseline=args.baseline, provider_config=args.provider_config,
                output_dir=args.output_dir, families=args.families, seeds=_parse_cli_seeds(args.seeds),
                repetitions=args.repetitions, model=args.model, worker_model=args.worker_model,
                http_budget=args.http_budget, token_budget=args.token_budget,
                seconds_budget=args.seconds_budget, treatment=_parse_cli_treatment(args),
                acceptance_criteria=_parse_cli_acceptance(args))
            print(json.dumps({"status": plan["status"], "artifact": str(path),
                              "experiment_manifest": plan["experiment_manifest"],
                              "llm_calls": 0, "target_requests": 0}))
            return 0
        if args.action == "run":
            path, payload = run_cohort(
                args.label, baseline=args.baseline, provider_config=args.provider_config,
                output_dir=args.output_dir, families=args.families, seeds=_parse_cli_seeds(args.seeds),
                repetitions=args.repetitions, model=args.model, worker_model=args.worker_model,
                http_budget=args.http_budget, token_budget=args.token_budget,
                seconds_budget=args.seconds_budget, execute=args.execute,
                authorize_live_provider=args.authorize_live_provider,
                live_authorization_reason=args.live_authorization_reason,
                api_key_env=args.api_key_env, treatment=_parse_cli_treatment(args),
                acceptance_criteria=_parse_cli_acceptance(args))
            print(json.dumps({"artifact": str(path), **{
                k: payload[k] for k in ("schema", "label", "status") if k in payload},
                "aggregate_status": payload.get("aggregate_status"),
                "failed_run_rate": payload.get("failed_run_rate"),
                "acceptance": payload.get("acceptance")}))
            if args.execute and args.enforce_acceptance and not (payload.get("acceptance") or {}).get("passed"):
                return 3
            return 0
        if args.action == "audit":
            report = audit_cohort(args.label, args.manifest, experiment_manifest=args.experiment_manifest)
            if args.output:
                out = _output_outside_protected(args.output)
                dump(out, report)
            print(json.dumps(report, ensure_ascii=False))
            if args.enforce_acceptance and not (report.get("acceptance") or {}).get("passed"):
                return 3
            return 0
        if args.action == "reaudit-legacy":
            derived = reaudit_legacy_cohort(args.report, label=args.label)
            if args.output:
                out = _output_outside_protected(args.output, args.report.parent)
                dump(out, derived)
            print(json.dumps(derived, ensure_ascii=False))
            return 0
        comparison = compare_cohorts(args.before, args.after, mode=args.mode)
        if args.output_dir:
            out = _output_outside_protected(args.output_dir)
            out.mkdir(parents=True, exist_ok=True)
            dump(out / "comparison.json", comparison)
            (out / "comparison.md").write_text(render_comparison_markdown(comparison), encoding="utf-8")
        print(json.dumps(comparison, ensure_ascii=False))
        if args.enforce_acceptance and not (comparison.get("acceptance_passed") or {}).get("after"):
            return 3
        return 0
    except (ValueError, PermissionError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
