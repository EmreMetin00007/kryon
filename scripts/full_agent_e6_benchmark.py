#!/usr/bin/env python3
"""E6 real-model holdout benchmark runner, cohort auditor, and before/after comparator.

Plan-only execution is the default (0 LLM calls, 0 target HTTP requests). Live
non-loopback provider usage is fail-closed unless explicitly authorized by the
operator. Unknown usage or costs remain None and are never coerced to zero.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import full_agent_holdout as holdout
import full_agent_launcher as launcher
import full_agent_preflight as preflight
import llm_config
from full_agent_broker import dump
from runtime_paths import runtime_root

ROOT = runtime_root()
SCHEMA_SUITE = "full-agent-e6-suite/1"
SCHEMA_COHORT = "full-agent-e6-cohort/1"
SCHEMA_COMPARE = "full-agent-e6-comparison/1"
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


def _delta(before, after):
    """Return signed difference (after - before) when both measurements exist."""
    if (before is None or after is None or isinstance(before, bool) or isinstance(after, bool)
            or not isinstance(before, (int, float)) or not isinstance(after, (int, float))):
        return None
    return after - before


def _normalize_ceilings(limits):
    """Extract the invariant token/HTTP/time ceilings shared across a cohort."""
    if not isinstance(limits, dict):
        return None
    keys = ("http_requests_per_seed", "llm_tokens_per_seed", "seconds_per_seed")
    if any(type(limits.get(key)) is not int or limits[key] <= 0 for key in keys):
        return None
    return {key: limits[key] for key in keys}


def _output_outside_protected(output, *protected_dirs):
    resolved = Path(output).expanduser().resolve()
    for protected in (ROOT, *(Path(p).expanduser().resolve() for p in protected_dirs if p is not None)):
        if resolved == protected or protected in resolved.parents or resolved in protected.parents:
            raise ValueError("output must remain outside repository, preflight, and baseline directories")
    return resolved


def validate_suite(families=None, seeds=None, *, http_budget=preflight.MAX_REQUESTS,
                   token_budget=150000, seconds_budget=900):
    """Validate >=3 distinct registered families and shared token/HTTP/time ceilings."""
    chosen = list(families) if families else list(DEFAULT_FAMILIES)
    if len(chosen) < MINIMUM_FAMILIES or len(set(chosen)) != len(chosen):
        raise ValueError("E6 suite requires at least 3 distinct registered independent families")
    for family in chosen:
        if family not in holdout.FAMILIES:
            raise ValueError(f"unregistered independent family: {family}")
    ceilings = _normalize_ceilings({
        "http_requests_per_seed": http_budget,
        "llm_tokens_per_seed": token_budget,
        "seconds_per_seed": seconds_budget,
    })
    if ceilings is None or http_budget > preflight.MAX_REQUESTS or seconds_budget > preflight.MAX_SECONDS:
        raise ValueError("invalid shared ceilings for E6 suite")
    if seeds is None:
        seed_map = {family: DEFAULT_SEEDS[family] for family in chosen}
    elif isinstance(seeds, dict):
        if set(seeds) != set(chosen):
            raise ValueError("seed mapping keys must match selected families")
        seed_map = dict(seeds)
    else:
        seed_list = list(seeds)
        if len(seed_list) != len(chosen):
            raise ValueError("seed count must match selected family count")
        seed_map = dict(zip(chosen, seed_list))
    selections = [holdout.selection(family, seed_map[family]) for family in chosen]
    return {"families": chosen, "seeds": seed_map, "ceilings": ceilings, "selections": selections}


def authorize_provider(provider_config, *, model="", worker_model="", execute=False,
                       authorize_live_provider=False, live_authorization_reason="", api_key_env=None):
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


def _expected_counts(selections):
    """Return total positive/negative controls for a suite selection without invoking labs."""
    # Each registered holdout family defines positive/negative truth dynamically at lab start,
    # while preflight contract enforces overall holdout minimums; actual counts come from truth.json.
    return {
        "minimum_families": MINIMUM_FAMILIES,
        "selected_families": len(selections),
        "minimum_positives": 24,
        "minimum_negatives": 24,
    }


def prepare_cohort(label, *, baseline, provider_config, output_dir, families=None, seeds=None,
                   model="", worker_model="", http_budget=preflight.MAX_REQUESTS,
                   token_budget=150000, seconds_budget=900):
    """Create verified per-family preflight contracts under shared ceilings; 0 LLM/HTTP calls."""
    if not isinstance(label, str) or not label.strip():
        raise ValueError("cohort label is required")
    suite = validate_suite(families, seeds, http_budget=http_budget,
                           token_budget=token_budget, seconds_budget=seconds_budget)
    auth = authorize_provider(provider_config, model=model, worker_model=worker_model, execute=False)
    output = _output_outside_protected(output_dir, baseline)
    preflight_root = output / "preflights"
    preflight_root.mkdir(parents=True, exist_ok=True)
    entries = []
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
            raise ValueError(f"preflight failed for family {item['family']} (exit {rc})")
        manifests = sorted(preflight_root.glob("preflight-*/preflight.json"), key=lambda p: p.stat().st_mtime_ns)
        latest = manifests[-1]
        entries.append({"family": item["family"], "seed": item["seed"], "preflight": str(latest)})
    plan = {
        "schema": SCHEMA_SUITE,
        "label": label,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "plan_only",
        "executed": False,
        "llm_calls": 0,
        "target_requests": 0,
        "models": auth["models"],
        "provider_kind": auth["provider_kind"],
        "provider_host": auth["provider_host"],
        "ceilings": suite["ceilings"],
        "holdout_minimums": _expected_counts(suite["selections"]),
        "runs": entries,
    }
    plan_path = output / "suite-plan.json"
    dump(plan_path, plan)
    return plan_path, plan


def run_cohort(label, *, baseline, provider_config, output_dir, families=None, seeds=None,
               model="", worker_model="", http_budget=preflight.MAX_REQUESTS,
               token_budget=150000, seconds_budget=900, execute=False,
               authorize_live_provider=False, live_authorization_reason="", api_key_env=None):
    """Run (or plan when execute=False) an E6 >=3-family cohort under shared ceilings."""
    auth = authorize_provider(
        provider_config, model=model, worker_model=worker_model, execute=execute,
        authorize_live_provider=authorize_live_provider,
        live_authorization_reason=live_authorization_reason, api_key_env=api_key_env)
    plan_path, plan = prepare_cohort(
        label, baseline=baseline, provider_config=provider_config, output_dir=output_dir,
        families=families, seeds=seeds, model=model, worker_model=worker_model,
        http_budget=http_budget, token_budget=token_budget, seconds_budget=seconds_budget)
    if not execute:
        return plan_path, plan
    output = plan_path.parent
    runs_dir = output / "runs"
    runs_dir.mkdir(exist_ok=True)
    api_key = os.environ[auth["api_key_env"]]
    manifest_paths = []
    for entry in plan["runs"]:
        prepared = launcher.prepared_run(entry["preflight"])
        provider = launcher.provider_settings(provider_config, prepared["contract"]["models"])
        manifest_path, _ = launcher.launch_seed(
            prepared, seed=entry["seed"], output=runs_dir,
            provider=provider, api_key=api_key, bwrap=None, opencode=None)
        manifest_paths.append(manifest_path)
    report = audit_cohort(
        label, manifest_paths,
        expected_ceilings=plan["ceilings"],
        authorization={
            "provider_kind": auth["provider_kind"],
            "provider_host": auth["provider_host"],
            "live_provider_authorized": auth["live_provider_authorized"],
            "live_authorization_reason": auth["live_authorization_reason"],
        })
    report_path = output / "cohort-report.json"
    dump(report_path, report)
    (output / "cohort-report.md").write_text(render_cohort_markdown(report))
    return report_path, report


def audit_cohort(label, manifest_paths, *, expected_ceilings=None, authorization=None):
    """Independently audit >=3 family manifests offline and build E6 cohort metrics."""
    if not isinstance(label, str) or not label.strip():
        raise ValueError("cohort label is required")
    paths = [Path(path).resolve(strict=True) for path in manifest_paths]
    if len(paths) < MINIMUM_FAMILIES:
        raise ValueError("E6 cohort audit requires at least 3 independent family runs")
    run_metrics = []
    contracts = []
    run_ceilings = []
    run_evidence = []
    for path in paths:
        metrics, _ = holdout.audit_run_status(path)
        ceilings = _normalize_ceilings(metrics.get("effective_limits"))
        if ceilings is None:
            raise ValueError(f"missing normalized ceiling limits in {path}")
        run_ceilings.append(ceilings)
        run_metrics.append(metrics)
        launch = json.loads(path.read_text())
        contracts.append(launcher.prepared_run(launch["preflight"])["contract"]["holdout"])
        run_evidence.append({
            "family": metrics["family"],
            "seed": launch["seed"],
            "status": launch.get("status"),
            "failed": metrics["failed"],
            "failure_reason": metrics.get("failure_reason"),
            "closure_verified": metrics["closure_verified"],
            "models": metrics.get("models"),
            "usage": metrics.get("usage"),
            "evidence_refs": metrics.get("evidence_refs"),
            "not_tested": metrics.get("not_tested"),
        })
    if any(contract != contracts[0] for contract in contracts):
        raise ValueError("holdout contracts differ across cohort")
    if any(ceiling != run_ceilings[0] for ceiling in run_ceilings):
        raise ValueError("effective HTTP/token/seconds ceilings differ across cohort runs")
    if expected_ceilings is not None and run_ceilings[0] != _normalize_ceilings(expected_ceilings):
        raise ValueError("cohort ceilings do not match expected shared ceilings")
    summary = holdout.aggregate(run_metrics, contracts[0])
    if len(summary["families"]) < MINIMUM_FAMILIES:
        raise ValueError("E6 cohort requires >=3 distinct registered families")
    return {
        "schema": SCHEMA_COHORT,
        "label": label,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "ceilings": run_ceilings[0],
        "families": summary["families"],
        "models": summary["models"],
        "provider_kinds": sorted({row.get("provider_kind", "unknown") for row in run_metrics}),
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
        "aggregate_status": summary["status"],
        "checks": summary["checks"],
        "paid_model_generalization": summary["paid_model_generalization"],
        "per_family": summary["per_family"],
        "not_tested_dimensions": summary["not_tested_dimensions"],
        "runs": run_evidence,
    }


def _ratio_value(ratio):
    if "value" in ratio:
        return ratio["value"]
    return holdout._ratio(ratio["numerator"], ratio["denominator"])


def _with_ratio_value(ratio):
    return {
        "numerator": ratio["numerator"],
        "denominator": ratio["denominator"],
        "value": _ratio_value(ratio),
    }


def _load_cohort_input(value):
    if isinstance(value, dict):
        data = value
    else:
        data = json.loads(Path(value).read_text())
    if data.get("schema") != SCHEMA_COHORT:
        raise ValueError("expected a full-agent-e6-cohort/1 report")
    return data


def compare_cohorts(before, after):
    """Compare before/after E6 cohorts under strictly matching ceilings and families."""
    b = _load_cohort_input(before)
    a = _load_cohort_input(after)
    if b.get("ceilings") is None or b.get("ceilings") != a.get("ceilings"):
        raise ValueError("before/after cohorts must share identical token, HTTP, and duration ceilings")
    if set(b.get("families", [])) != set(a.get("families", [])) or len(b["families"]) < MINIMUM_FAMILIES:
        raise ValueError("before/after cohorts must cover the same >=3 independent families")
    for family in b["families"]:
        bf, af = b["per_family"][family], a["per_family"][family]
        if (bf["recall"]["denominator"] != af["recall"]["denominator"]
                or bf["negative_coverage"]["denominator"] != af["negative_coverage"]["denominator"]):
            raise ValueError(f"before/after positive/negative counts mismatch for {family}")

    per_family = {}
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
    not_tested = []
    for dim in (*b.get("not_tested_dimensions", []), *a.get("not_tested_dimensions", [])):
        if dim not in not_tested:
            not_tested.append(dim)
    return {
        "schema": SCHEMA_COMPARE,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "ceilings": b["ceilings"],
        "ceilings_matched": True,
        "families": sorted(b["families"]),
        "models": {"before": b["models"], "after": a["models"]},
        "before": {key: b[key] for key in (
            "label", "models", "provider_kinds", "paid_provider_calls", "recall",
            "false_positives", "negative_coverage", "failed_run_rate", "verified_findings",
            "requests_per_verified_finding", "tokens_per_verified_finding", "usage",
            "aggregate_status", "paid_model_generalization")},
        "after": {key: a[key] for key in (
            "label", "models", "provider_kinds", "paid_provider_calls", "recall",
            "false_positives", "negative_coverage", "failed_run_rate", "verified_findings",
            "requests_per_verified_finding", "tokens_per_verified_finding", "usage",
            "aggregate_status", "paid_model_generalization")},
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
        "per_family": per_family,
        "evidence": {"before_runs": b["runs"], "after_runs": a["runs"]},
        "not_tested_dimensions": not_tested,
    }


def _fmt(value, digits=3):
    if value is None:
        return "unknown (not zero)"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def render_cohort_markdown(report):
    lines = [
        f"# E6 Cohort Report: {report['label']}",
        "",
        f"- Models: `{', '.join(report['models']) or 'none'}` (`{', '.join(report['provider_kinds'])}`)",
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
        "",
        "## NOT TESTED Dimensions",
        *[f"- `{dim}`" for dim in report["not_tested_dimensions"]],
        "",
    ]
    return "\n".join(lines)


def render_comparison_markdown(comparison):
    b, a, d = comparison["before"], comparison["after"], comparison["deltas"]
    c = comparison["ceilings"]
    lines = [
        f"# E6 Before/After Comparison: {b['label']} vs {a['label']}",
        "",
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    for name in ("plan", "run"):
        p = sub.add_parser(name)
        p.add_argument("--label", required=True)
        p.add_argument("--baseline", type=Path, required=True)
        p.add_argument("--provider-config", type=Path, default=llm_config.default_config())
        p.add_argument("--output-dir", type=Path, required=True)
        p.add_argument("--family", action="append", dest="families")
        p.add_argument("--model", default="")
        p.add_argument("--worker-model", default="")
        p.add_argument("--http-budget", type=int, default=preflight.MAX_REQUESTS)
        p.add_argument("--token-budget", type=int, default=150000)
        p.add_argument("--seconds-budget", type=int, default=900)
        if name == "run":
            p.add_argument("--execute", action="store_true")
            p.add_argument("--authorize-live-provider", action="store_true")
            p.add_argument("--live-authorization-reason", default="")
            p.add_argument("--api-key-env", default=None)

    audit_p = sub.add_parser("audit")
    audit_p.add_argument("--label", required=True)
    audit_p.add_argument("--manifest", action="append", required=True)
    audit_p.add_argument("--output", type=Path, default=None)

    cmp_p = sub.add_parser("compare")
    cmp_p.add_argument("--before", type=Path, required=True)
    cmp_p.add_argument("--after", type=Path, required=True)
    cmp_p.add_argument("--output-dir", type=Path, default=None)

    args = parser.parse_args(argv)
    try:
        if args.action == "plan":
            path, plan = prepare_cohort(
                args.label, baseline=args.baseline, provider_config=args.provider_config,
                output_dir=args.output_dir, families=args.families, model=args.model,
                worker_model=args.worker_model, http_budget=args.http_budget,
                token_budget=args.token_budget, seconds_budget=args.seconds_budget)
            print(json.dumps({"status": plan["status"], "artifact": str(path),
                              "llm_calls": 0, "target_requests": 0}))
            return 0
        if args.action == "run":
            path, payload = run_cohort(
                args.label, baseline=args.baseline, provider_config=args.provider_config,
                output_dir=args.output_dir, families=args.families, model=args.model,
                worker_model=args.worker_model, http_budget=args.http_budget,
                token_budget=args.token_budget, seconds_budget=args.seconds_budget,
                execute=args.execute, authorize_live_provider=args.authorize_live_provider,
                live_authorization_reason=args.live_authorization_reason,
                api_key_env=args.api_key_env)
            print(json.dumps({"artifact": str(path), **{
                k: payload[k] for k in ("schema", "label", "status") if k in payload},
                "aggregate_status": payload.get("aggregate_status"),
                "failed_run_rate": payload.get("failed_run_rate")}))
            return 0
        if args.action == "audit":
            report = audit_cohort(args.label, args.manifest)
            if args.output:
                dump(args.output, report)
            print(json.dumps(report, ensure_ascii=False))
            return 0
        comparison = compare_cohorts(args.before, args.after)
        if args.output_dir:
            out = _output_outside_protected(args.output_dir)
            out.mkdir(parents=True, exist_ok=True)
            dump(out / "comparison.json", comparison)
            (out / "comparison.md").write_text(render_comparison_markdown(comparison))
        print(json.dumps(comparison, ensure_ascii=False))
        return 0
    except (ValueError, PermissionError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
