"""Host-only independent family registry, frozen identities and evidence scorer.

Never staged in the solver runtime. Seed changes cannot create family credit.
The comparison baseline remains a separate prerequisite, never holdout truth.
"""
from __future__ import annotations

import hashlib
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import Any
from urllib.parse import urlsplit

from lab import (
    post_carrier_holdout,
    readonly_api_holdout,
    readonly_sqli_holdout,
    readonly_ssti_holdout,
    readonly_traversal_holdout,
    readonly_xss_redirect_holdout,
)

FAMILIES = {module.FAMILY: module for module in (
    readonly_api_holdout,
    readonly_sqli_holdout,
    readonly_ssti_holdout,
    readonly_traversal_holdout,
    post_carrier_holdout,
    readonly_xss_redirect_holdout,
)}


def finding_type(family):
    return {readonly_api_holdout.FAMILY: "idor", readonly_sqli_holdout.FAMILY: "sql_injection",
            readonly_ssti_holdout.FAMILY: "ssti", readonly_traversal_holdout.FAMILY: "path_traversal",
            post_carrier_holdout.FAMILY: "post_carrier_injection",
            readonly_xss_redirect_holdout.FAMILY: "xss_and_open_redirect"}[family]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def selection(family, seed):
    if family not in FAMILIES or type(seed) is not int or not 0 <= seed < 2**63:
        raise ValueError("unknown independent family or invalid holdout seed")
    module = FAMILIES[family]
    return {"schema": "independent-holdout-selection/1", "family": family,
            "lab_version": module.VERSION, "seed": seed,
            "lab_sha256": digest(module.__file__), "evaluator_sha256": digest(__file__)}


def replay(selected, seed=None):
    if not isinstance(selected, dict) or selected != selection(selected.get("family"), selected.get("seed")):
        raise ValueError("independent holdout selection/source changed since preflight")
    if seed is not None and seed != selected["seed"]:
        raise ValueError("seed is not part of the frozen independent holdout")
    return FAMILIES[selected["family"]]


def private_policy_contract(family: str) -> dict[str, Any]:
    """Canonical private-policy provisioning contract shared by holdout, preflight, and launcher."""
    if not isinstance(family, str) or (family and family not in FAMILIES):
        raise ValueError("unknown independent family")
    requires_traversal = family == readonly_traversal_holdout.FAMILY
    requires_post = family == post_carrier_holdout.FAMILY
    return {
        "schema": "holdout-private-policy-contract/1",
        "family": family,
        "requires_private_policy": requires_traversal or requires_post,
        "policy_section": (
            "path_traversal" if requires_traversal
            else ("readonly_operations" if requires_post else None)
        ),
        "host_only": True,
        "public_policy_unchanged": True,
        "test_data_only": True,
        "cross_run_reuse_forbidden": True,
    }


def _reject_symlink_path(path: Path) -> None:
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError("private policy path cannot traverse symlinks")


def verify_run_scoped_policy(policy_path: Path, expected_base: str) -> bool:
    """Verify a run-scoped holdout policy file matches only expected_base and contains no cross-target entries."""
    try:
        path = Path(policy_path)
        _reject_symlink_path(path)
        if not path.is_file():
            return False
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return False
        expected = urlsplit(expected_base)
        permits = lambda url: (
            urlsplit(url).scheme == expected.scheme
            and urlsplit(url).netloc == expected.netloc
        )
        ro_ops = data.get("readonly_operations")
        if isinstance(ro_ops, list) and ro_ops:
            for op in ro_ops:
                if (
                    not isinstance(op, dict)
                    or str(op.get("method") or "").upper() != "POST"
                    or op.get("read_only") is not True
                    or op.get("test_data_only") is not True
                    or not permits(str(op.get("url") or ""))
                ):
                    return False
            return True
        rule = data.get("path_traversal")
        if not isinstance(rule, dict):
            return False
        validator_dir = str(Path(__file__).resolve().parents[1] / "mcp-servers/mcp-validator")
        if validator_dir not in sys.path:
            sys.path.append(validator_dir)
        from cco_validator_core.traversal import check_traversal_policy_eligibility
        files = rule.get("files") if isinstance(rule.get("files"), list) else []
        if not files:
            return False
        for row in files:
            if not isinstance(row, dict) or not permits(str(row.get("url") or "")):
                return False
            res = check_traversal_policy_eligibility(
                rule, str(row.get("url") or ""), str(row.get("param") or ""), str(row.get("carrier") or "query"), permits
            )
            if not res.get("eligible"):
                return False
        return True
    except (ValueError, OSError, TypeError):
        return False


def cleanup_private_policy(home: Path) -> None:
    """Remove run-scoped holdout-program-policy.json cleanly on explicit teardown."""
    target = Path(home) / "holdout-program-policy.json"
    try:
        if not target.is_symlink() and target.exists():
            target.unlink()
    except OSError:
        pass


def provision_private_policy(
    *,
    family: str,
    lab: Any,
    base: str,
    home: Path,
    private: Path,
    base_policy: dict[str, Any],
    scope_permits: Any = None,
) -> dict[str, Any]:
    """Provision run-scoped private host/MCP policy for fixture #4 without exposing it to the solver."""
    import copy
    from full_agent_provider import dump

    contract = private_policy_contract(family)
    home = Path(home)
    private = Path(private)
    _reject_symlink_path(home)
    _reject_symlink_path(private)
    policy_path = home / "holdout-program-policy.json"
    if not contract["requires_private_policy"]:
        cleanup_private_policy(home)
        return {
            "provisioned": False,
            "family": family,
            "target": base,
            "policy_file": None,
            "host_only": True,
        }
    if contract["policy_section"] == "readonly_operations":
        if lab is None or lab.blind_state.get("lab_version") != post_carrier_holdout.VERSION:
            raise ValueError("post carrier provisioning requires post-carrier/1 lab")
        expected_origin = urlsplit(base)
        if (expected_origin.scheme != "http" or expected_origin.hostname != "127.0.0.1"
                or not expected_origin.port or expected_origin.path != "/"):
            raise ValueError("post carrier private policy requires exact loopback run base URL")
        if not isinstance(base_policy, dict):
            raise ValueError("base_policy must be a mapping")
        decl = post_carrier_holdout.declaration(lab.blind_state, base)
        for row in decl.get("readonly_operations", []):
            row_origin = urlsplit(str(row.get("url") or ""))
            if (row_origin.scheme, row_origin.netloc) != (expected_origin.scheme, expected_origin.netloc):
                raise ValueError("post policy declaration cross-target mismatch")
            if row.get("method") != "POST" or row.get("read_only") is not True or row.get("test_data_only") is not True:
                raise ValueError("post policy declaration requires read_only=True and test_data_only=True")
        policy = copy.deepcopy(base_policy)
        policy["readonly_operations"] = decl["readonly_operations"]
        dump(policy_path, policy)
        os.chmod(policy_path, 0o600)
        policy_digest = digest(policy_path)
        dump(private / "fixture-policy-verification.json", {
            "before_traffic": True,
            "declarations_validated": len(decl["readonly_operations"]),
            "sha256": policy_digest,
            "public_policy_unchanged": True,
            "host_only": True,
            "family": family,
            "target_origin": expected_origin.netloc,
        })
        return {
            "provisioned": True,
            "family": family,
            "target": base,
            "policy_file": str(policy_path),
            "sha256": policy_digest,
            "declarations_validated": len(decl["readonly_operations"]),
            "host_only": True,
        }
    if lab is None or lab.blind_state.get("lab_version") != readonly_traversal_holdout.VERSION:
        raise ValueError("readonly traversal provisioning requires readonly-traversal/1 lab")
    expected_origin = urlsplit(base)
    if (expected_origin.scheme != "http" or expected_origin.hostname != "127.0.0.1"
            or not expected_origin.port or expected_origin.path != "/"):
        raise ValueError("traversal private policy requires exact loopback run base URL")
    if not isinstance(base_policy, dict):
        raise ValueError("base_policy must be a mapping")
    validator_dir = str(Path(__file__).resolve().parents[1] / "mcp-servers/mcp-validator")
    if validator_dir not in sys.path:
        sys.path.append(validator_dir)
    from cco_validator_core.traversal import application_files

    decl = readonly_traversal_holdout.declaration(lab.blind_state, base)
    permits = scope_permits or (lambda url: url.startswith(base))
    for row in decl.get("files", []):
        row_origin = urlsplit(str(row.get("url") or ""))
        if (row_origin.scheme, row_origin.netloc) != (expected_origin.scheme, expected_origin.netloc):
            raise ValueError("traversal policy declaration cross-target mismatch")
        if row.get("test_data_only") is not True or row.get("outside_root") is not True:
            raise ValueError("traversal policy declaration requires synthetic test_data_only=True")
    for case in lab.blind_state["truth"]:
        application_files(
            decl,
            base.rstrip("/") + case["path"],
            case["param"],
            "query",
            permits,
        )
    policy = copy.deepcopy(base_policy)
    policy["path_traversal"] = decl
    dump(policy_path, policy)
    os.chmod(policy_path, 0o600)
    policy_digest = digest(policy_path)
    dump(private / "fixture-policy-verification.json", {
        "before_traffic": True,
        "declarations_validated": len(decl["files"]),
        "sha256": policy_digest,
        "public_policy_unchanged": True,
        "host_only": True,
        "family": family,
        "target_origin": expected_origin.netloc,
    })
    return {
        "provisioned": True,
        "family": family,
        "target": base,
        "policy_file": str(policy_path),
        "sha256": policy_digest,
        "declarations_validated": len(decl["files"]),
        "host_only": True,
    }


def start(selected, private):
    module = replay(selected)
    from full_agent_provider import dump
    evaluator = Path(private) / "evaluator"
    evaluator.mkdir(mode=0o700)
    lab = module.serve(selected["seed"], **({"fixture_parent": evaluator}
                       if module is readonly_traversal_holdout else {}))
    dump(evaluator / "selection.json", selected)
    dump(evaluator / "truth.json", lab.blind_state["truth"])
    dump(evaluator / "expected-counts.json", {
        kind: sum(case["expected"] == kind for case in lab.blind_state["truth"])
        for kind in ("positive", "negative")})
    (evaluator / "lab-source.py").write_bytes(Path(module.__file__).read_bytes())
    return lab


def evaluate(truth, wire, artifacts, *, target, run_id, verify_artifact, claims=()):
    """Credit only signed, current, exact HTTP comparisons from a registered family.

    verify_artifact must use the launch's pinned public trust and scope/policy
    binding. Missing, inconclusive, stale or tampered evidence earns no credit.
    FP rate uses tested negative cases, never all untested cases. Outcomes
    include explicit per-case evidence references and reject reasons.
    """
    if len({case["case"] for case in truth}) != len(truth):
        raise ValueError("duplicate evaluator cases")
    families = {case.get("family", readonly_api_holdout.FAMILY) for case in truth}
    if len(families) != 1 or not families <= FAMILIES.keys():
        raise ValueError("mixed or unknown evaluator families")
    family, = families
    outcomes, rejected, unexpected = [], [], []
    by_case = {case["path"]: [] for case in truth}
    for item in artifacts:
        record = item["record"]
        path = urlsplit(record.get("target", "")).path
        reason = ""
        if path not in by_case:
            unexpected.append({"artifact": item["path"], "verdict": record.get("verdict")})
            continue
        context = record.get("execution_context", {})
        if (context.get("run_id") not in ([run_id] if isinstance(run_id, str) else run_id)
                or record.get("verdict") not in {"CONFIRMED", "UNCONFIRMED"}
                or not record.get("guard", {}).get("transport_ok")
                or not verify_artifact(record)):
            reason = "invalid signature, binding, transport or verdict"
        case = next(case for case in truth if case["path"] == path)
        if family == readonly_sqli_holdout.FAMILY:
            sql_reason, matched = readonly_sqli_holdout.evidence_matches(case, record, wire, target)
            reason = reason or sql_reason
        elif family == readonly_ssti_holdout.FAMILY:
            ssti_reason, matched = readonly_ssti_holdout.evidence_matches(case, record, wire, target)
            reason = reason or ssti_reason
        elif family == readonly_traversal_holdout.FAMILY:
            traversal_reason, matched = readonly_traversal_holdout.evidence_matches(case, record, wire, target)
            reason = reason or traversal_reason
        elif family == post_carrier_holdout.FAMILY:
            post_reason, matched = post_carrier_holdout.evidence_matches(case, record, wire, target)
            reason = reason or post_reason
        elif family == readonly_xss_redirect_holdout.FAMILY:
            xr_reason, matched = readonly_xss_redirect_holdout.evidence_matches(case, record, wire, target)
            reason = reason or xr_reason
        else:
            if context.get("resource_owner") != case["owner"] or context.get("identity") not in case["denied_identities"]:
                reason = "authorization identity binding mismatch"
            roles = {}
            matched = []
            for response in record.get("request_evidence", []):
                url = urlsplit(response.get("request_url", ""))
                origin = urlsplit(target)
                matches = [row for row in wire if row["path"] == path
                           and row["method"] == response.get("method") == "GET"
                           and row["status"] == response.get("status")
                           and row["response_sha256"] == response.get("response_sha256")
                           and row["response_length"] == response.get("response_length")]
                role = response.get("role")
                matches = [row for row in matches if (
                    row["identity"] == case["owner"] if role == "owner" else
                    row["identity"] == context.get("identity") if role == "attacker" else
                    row["identity"] == "anonymous" if role == "anonymous" else False)]
                if (not response.get("transport_ok") or not matches
                        or (url.scheme, url.netloc) != (origin.scheme, origin.netloc)):
                    reason = "HTTP evidence does not match evaluator wire/identity"
                else:
                    roles[role] = matches[0]
                    matched.append(matches[0]["sequence"])
            owner, attacker = roles.get("owner"), roles.get("attacker")
            if not owner or not attacker or owner["status"] != 200:
                reason = "missing owner/attacker authorization controls"
            elif record["verdict"] == "CONFIRMED":
                if (attacker["status"] != 200 or case["marker"] not in json.dumps(attacker["response"])
                        or not roles.get("anonymous") or roles["anonymous"]["status"] != 401):
                    reason = "owner-data access or protected anonymous baseline not established"
            elif (attacker["status"] not in {200, 403, 404}
                  or case["marker"] in json.dumps(attacker["response"])):
                reason = "negative authorization control not established"
        if reason:
            rejected.append({"artifact": item["path"], "reason": reason})
        else:
            by_case[path].append({"artifact": item["path"], "sha256": item["sha256"],
                                  "validation_id": record["validation_id"], "verdict": record["verdict"],
                                  "wire_sequences": matched})
    for case in truth:
        evidence = by_case[case["path"]]
        confirmed = any(row["verdict"] == "CONFIRMED" for row in evidence)
        reported = [row for row in claims if urlsplit(row.get("url", "")).path == case["path"]
                    and row.get("verdict") == "CONFIRMED"]
        clean = bool(evidence) and not confirmed
        outcome = ("true_positive" if confirmed else "false_negative") if case["expected"] == "positive" else (
            "false_positive" if confirmed or reported else "true_negative" if clean else "not_tested")
        outcomes.append({**case, "outcome": outcome, "evidence": evidence, "reported_confirmations": reported})
    positives = sum(case["expected"] == "positive" for case in truth)
    negatives = len(truth) - positives
    tp = sum(row["outcome"] == "true_positive" for row in outcomes)
    fp = sum(row["outcome"] == "false_positive" for row in outcomes)
    tested = sum(row["expected"] == "negative" and bool(row["evidence"]) for row in outcomes)
    fp_denominator = sum(row["expected"] == "negative" and bool(row["evidence"] or row["reported_confirmations"])
                         for row in outcomes)
    return {"schema": "independent-holdout-metrics/1", "run_id": run_id,
            "family": family,
            "recall": {"numerator": tp, "denominator": positives, "value": tp / positives if positives else None},
            "negative_coverage": {"numerator": tested, "denominator": negatives,
                                  "value": tested / negatives if negatives else None},
            "false_positives": {"numerator": fp, "denominator": fp_denominator,
                                "value": fp / fp_denominator if fp_denominator else None},
            "cases": outcomes, "rejected_evidence": rejected, "unexpected_artifacts": unexpected}


def _sum_optional(values):
    """Sum numeric measurements, keeping unknown (None) distinct from zero."""
    total = 0
    saw_value = False
    for value in values:
        if value is None or isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        total += value
        saw_value = True
    return total if saw_value else None


def _ratio(numerator, denominator):
    if numerator is None or not denominator:
        return None
    return numerator / denominator


def _extract_run_usage(private, manifest, wire_count):
    """Read measured usage and cost from launch/budget artifacts; unknown cost is never zero."""
    budget = None
    budget_file = Path(private) / "budget.json"
    if budget_file.is_file():
        budget = json.loads(budget_file.read_text())
    elif isinstance(manifest.get("budget"), dict):
        budget = manifest["budget"]
    events = budget.get("events", []) if isinstance(budget, dict) else []
    token_events = [row for row in events if row.get("kind") == "tokens"]
    tokens_valid = isinstance(budget, dict) and all(row.get("measurement_valid") is True for row in token_events)
    tokens_used = (budget.get("used", {}).get("tokens")
                   if tokens_valid and type(budget.get("used", {}).get("tokens")) is int else None)
    prompt_tokens = _sum_optional([row.get("usage", {}).get("prompt_tokens") for row in token_events]) if token_events and tokens_valid else None
    completion_tokens = _sum_optional([row.get("usage", {}).get("completion_tokens") for row in token_events]) if token_events and tokens_valid else None
    cached_tokens = _sum_optional([
        (row.get("usage", {}).get("prompt_tokens_details") or {}).get("cached_tokens", 0)
        if row.get("usage", {}).get("prompt_tokens") is not None else None
        for row in token_events
    ]) if token_events and tokens_valid else None
    reasoning_tokens = _sum_optional([
        (row.get("usage", {}).get("completion_tokens_details") or {}).get("reasoning_tokens", 0)
        if row.get("usage", {}).get("completion_tokens") is not None else None
        for row in token_events
    ]) if token_events and tokens_valid else None
    raw_cost = manifest.get("llm_cost_usd")
    cost_known = not isinstance(raw_cost, bool) and isinstance(raw_cost, (int, float))
    cost_usd = float(raw_cost) if cost_known else None
    http_requests = wire_count if type(wire_count) is int else (
        manifest.get("target_requests") if type(manifest.get("target_requests")) is int else None)
    wall_clock = manifest.get("wall_clock_seconds")
    llm_calls = manifest.get("llm_calls")
    return {
        "llm_calls": llm_calls if type(llm_calls) is int else None,
        "tokens_used": tokens_used,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "cached_tokens": cached_tokens,
        "reasoning_tokens": reasoning_tokens,
        "http_requests": http_requests,
        "wall_clock_seconds": wall_clock if not isinstance(wall_clock, bool) and isinstance(wall_clock, (int, float)) else None,
        "cost_usd": cost_usd,
        "cost_known": cost_known,
        "unknown_cost_is_zero": False,
    }


def _extract_not_tested(metrics, work, *, provider_kind, paid_calls, closure_payload=None, closure_verified=False):
    """Collect untested cases, vectors, and generalization gaps without hiding them."""
    cases = metrics.get("cases", [])
    missed_positives = [row["case"] for row in cases if row.get("outcome") == "false_negative"]
    untested_negatives = [row["case"] for row in cases if row.get("outcome") == "not_tested"]
    access_reasons = []
    access_path = Path(work) / "summaries/access-3.json"
    if access_path.is_file():
        access_summary = json.loads(access_path.read_text())
        access_reasons = list(access_summary.get("not_tested_reasons", []))
    closure_vectors = list((closure_payload or {}).get("not_tested", []))
    transport_dim = (
        "readonly_get_and_declared_post_only"
        if metrics.get("family") == post_carrier_holdout.FAMILY
        else "readonly_get_only"
    )
    dimensions = [transport_dim, "synthetic_fixture_boundaries",
                  "out_of_band_and_multi_step_business_logic"]
    if provider_kind != "remote" or not paid_calls:
        dimensions.append("paid_remote_model_generalization")
    if not closure_verified:
        dimensions.append("incomplete_run_before_closure")
    if missed_positives:
        dimensions.append("missed_positive_controls")
    if untested_negatives:
        dimensions.append("untested_negative_controls")
    return {
        "missed_positive_cases": missed_positives,
        "untested_negative_cases": untested_negatives,
        "closure_not_tested_vectors": closure_vectors,
        "access_not_tested_reasons": access_reasons,
        "untested_dimensions": dimensions,
    }


def _collect_evidence_refs(manifest_path, work, evaluator, artifacts):
    work, evaluator = Path(work), Path(evaluator)
    refs = {
        "manifest": {"path": str(manifest_path), "sha256": digest(manifest_path)},
        "validation_artifacts_count": len(artifacts),
    }
    for key, path in (
        ("closure", work / "closure.json"),
        ("attempt_ledger", work / "attempt-ledger.json"),
        ("wire", evaluator / "wire.json"),
        ("selection", evaluator / "selection.json"),
    ):
        if path.is_file():
            refs[key] = {"path": str(path), "sha256": digest(path)}
    return refs


def aggregate(metrics, contract):
    """One result per registered family; renamed/reseeded runs earn no credit."""
    by_family = {}
    for result in metrics:
        family = result["family"]
        if family not in FAMILIES or family in by_family:
            raise ValueError("unknown or repeated independent family")
        if any(case.get("family", family) != family for case in result.get("cases", [])):
            raise ValueError("renamed independent family cases")
        by_family[family] = result
    positives = sum(row["recall"]["denominator"] for row in metrics)
    negatives = sum(row["negative_coverage"]["denominator"] for row in metrics)
    tp = sum(row["recall"]["numerator"] for row in metrics)
    fp = sum(row.get("false_positives", {}).get("numerator", 0) for row in metrics)
    fp_total = sum(row.get("false_positives", {}).get("denominator", 0) for row in metrics)
    tested = sum(row["negative_coverage"]["numerator"] for row in metrics)
    failed_count = sum(1 for row in metrics if row.get("failed") is True)
    checks = {"minimum_families": len(by_family) >= contract["minimum_families"],
              "minimum_positives": positives >= contract["minimum_positives"],
              "minimum_negatives": negatives >= contract["minimum_negatives"],
              "overall_recall": bool(positives) and tp / positives >= contract["overall_recall"],
              "per_family_recall": bool(metrics) and all(
                  row["recall"]["value"] is not None and row["recall"]["value"] >= contract["per_family_recall"]
                  for row in metrics),
              "negative_coverage": bool(negatives) and tested / negatives >= contract["negative_coverage"],
              "zero_false_positives": fp == 0,
              "closure_verified": bool(metrics) and all(
                  row.get("closure_verified") is True and not row.get("failed", False) for row in metrics)}
    usages = [row.get("usage") for row in metrics]
    has_usage = bool(metrics) and all(isinstance(row, dict) for row in usages)
    total_http = _sum_optional([row["http_requests"] for row in usages]) if has_usage else None
    total_tokens = _sum_optional([row["tokens_used"] for row in usages]) if has_usage else None
    total_prompt = _sum_optional([row.get("prompt_tokens") for row in usages]) if has_usage else None
    total_completion = _sum_optional([row.get("completion_tokens") for row in usages]) if has_usage else None
    total_seconds = _sum_optional([row.get("wall_clock_seconds") for row in usages]) if has_usage else None
    total_calls = _sum_optional([row.get("llm_calls") for row in usages]) if has_usage else None
    total_cost = _sum_optional([row.get("cost_usd") for row in usages]) if has_usage else None
    provider_kinds = sorted({row.get("provider_kind", "unknown") for row in metrics})
    if not metrics or all(kind in {"scripted_loopback", "loopback", "unknown"} for kind in provider_kinds):
        paid_generalization = "not_evaluated"
    elif all(kind == "remote" and (row.get("paid_provider_calls") or 0) > 0 for kind, row in zip(
            [r.get("provider_kind", "unknown") for r in metrics], metrics)):
        paid_generalization = "passed" if all(checks.values()) and failed_count == 0 else "evaluated_incomplete"
    else:
        paid_generalization = "partial_remote"
    per_family = {}
    models = sorted({
        value for row in metrics
        for key, value in (row.get("models") or {}).items()
        if key in {"planner", "worker"} and isinstance(value, str)
    })
    limit_tuples = {json.dumps(row["effective_limits"], sort_keys=True)
                    for row in metrics if isinstance(row.get("effective_limits"), dict) and row["effective_limits"]}
    common_limits = (json.loads(next(iter(limit_tuples))) if len(limit_tuples) == 1 and len(
        [r for r in metrics if r.get("effective_limits")]) == len(metrics)
        else "mismatch" if len(limit_tuples) > 1 else None)
    dimensions = []
    for row in metrics:
        for dim in (row.get("not_tested") or {}).get("untested_dimensions", []):
            if dim not in dimensions:
                dimensions.append(dim)
        u = row.get("usage") if isinstance(row.get("usage"), dict) else {}
        f_tp = row["recall"]["numerator"]
        per_family[row["family"]] = {
            "recall": row["recall"],
            "negative_coverage": row["negative_coverage"],
            "false_positives": row.get("false_positives"),
            "verified_findings": f_tp,
            "failed": bool(row.get("failed", False)),
            "failure_reason": row.get("failure_reason"),
            "closure_verified": bool(row.get("closure_verified")),
            "http_requests": u.get("http_requests"),
            "tokens_used": u.get("tokens_used"),
            "requests_per_verified_finding": _ratio(u.get("http_requests"), f_tp),
            "tokens_per_verified_finding": _ratio(u.get("tokens_used"), f_tp),
            "cost_usd": u.get("cost_usd"),
            "not_tested": row.get("not_tested"),
        }
    return {"status": "passed" if all(checks.values()) else "incomplete", "checks": checks,
            "families": list(by_family), "positives": positives, "negatives": negatives,
            "overall_recall": {"numerator": tp, "denominator": positives},
            "negative_coverage": {"numerator": tested, "denominator": negatives},
            "false_positives": {"numerator": fp, "denominator": fp_total},
            "verified_findings": tp,
            "failed_runs": {"numerator": failed_count, "denominator": len(metrics), "value": _ratio(failed_count, len(metrics))},
            "models": models,
            "effective_limits": common_limits,
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
            "requests_per_verified_finding": _ratio(total_http, tp),
            "tokens_per_verified_finding": _ratio(total_tokens, tp),
            "per_family": per_family,
            "not_tested_dimensions": dimensions,
            "full_acceptance": False, "paid_model_generalization": paid_generalization}


def verify_python_snapshot(work, manifest, records):
    """Verify host-owned Python files before using the independent scorer."""
    import evidence_trust
    from full_agent_python_solver import PHASE_IDS, SCHEMA
    from full_agent_summary_feedback import summary_feedback
    from orchestration_spec import load_specs
    signed = json.loads((work / "attempt-ledger.json").read_text())
    payload = signed.get("payload", {})
    if (not evidence_trust.verify(evidence_trust.canonical_bytes(payload), signed, "python-attempt-ledger")
            or payload.get("schema") != "python-attempt-ledger/1" or payload.get("producer") != "host"
            or payload.get("target") != manifest["target"] or payload.get("records") != records
            or manifest.get("solver") != SCHEMA or manifest.get("status") != "python_finished_verified"):
        raise ValueError("Python holdout requires a current signed host attempt snapshot")
    required = {"specs.json", "handoff.json", "handoff-access.json", "object-pool.json",
                "enum/session-checks.json", "access/live-result.json", *[f"summaries/{ident}.json" for ident in PHASE_IDS]}
    refs = payload.get("workflow_files", [])
    if not required <= {row["path"] for row in refs}:
        raise ValueError("Python holdout snapshot is incomplete")
    for ref in [*refs, *payload.get("artifacts", [])]:
        path = work / ref["path"]
        if (Path(ref["path"]).is_absolute() or work not in path.resolve().parents
                or any(p.is_symlink() for p in (path, *path.parents))):
            raise ValueError("Python holdout artifact path changed")
        raw = path.read_bytes()
        if len(raw) != ref["bytes"] or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
            raise ValueError("Python holdout artifact bytes changed")
    specs = load_specs((work / "specs.json").read_text())
    if tuple(spec.id for spec in specs) != PHASE_IDS:
        raise ValueError("Python holdout phase chain changed")
    for spec in specs:
        if spec.target != manifest["target"] or not summary_feedback(
                json.loads((work / f"summaries/{spec.id}.json").read_text()), spec)["valid"]:
            raise ValueError("Python holdout phase summary changed")
    if json.loads((work / "handoff.json").read_text()) != json.loads((work / "handoff-access.json").read_text()):
        raise ValueError("Python holdout handoff changed")


def extract_access_receipts_and_run_ids(
    family: str,
    live: dict[str, Any],
    tool_index: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> tuple[list[Any], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Resolve and verify access-3 execution receipts and run IDs for the given holdout family."""
    live_tools = [json.loads(Path(row["artifact"]).read_text(encoding="utf-8")) for row in tool_index
                  if row["tool"] == "hunter_run_web_loop" and row["task_spec_id"] == "access-3"]
    native_reports = [json.loads(row["execution"]["result"]["output"]) for row in live_tools
                      if row["arguments"].get("live") and not row["error"]]
    run_ids = [row["run_id"] for row in native_reports]
    validator_receipts: dict[str, dict[str, Any]] = {}
    if family in {post_carrier_holdout.FAMILY, readonly_xss_redirect_holdout.FAMILY}:
        for row in tool_index:
            if row.get("task_spec_id") == "access-3" and str(row.get("tool") or "").startswith("validator_validate_"):
                receipt = json.loads(Path(row["artifact"]).read_text(encoding="utf-8"))
                if receipt.get("error"):
                    continue
                out = (receipt.get("execution") or {}).get("result", {}).get("output")
                if isinstance(out, str):
                    try:
                        out = json.loads(out)
                    except ValueError:
                        out = None
                if isinstance(out, dict) and isinstance(out.get("validation_id"), str) and out["validation_id"]:
                    validator_receipts[out["validation_id"]] = receipt
        if validator_receipts:
            if live.get("direct_validation_ids") != list(validator_receipts):
                raise ValueError("solver validation IDs do not match production executor receipts")
            if manifest.get("run_id") and manifest["run_id"] not in run_ids:
                run_ids.append(manifest["run_id"])
            if "validator-standalone" not in run_ids:
                run_ids.append("validator-standalone")
        if native_reports and live.get("run_ids") != [row["run_id"] for row in native_reports]:
            raise ValueError("solver run IDs do not match production executor receipts")
        if not run_ids or (not native_reports and not validator_receipts):
            raise ValueError("solver run IDs do not match production executor receipts")
        return run_ids, native_reports, validator_receipts
    if not run_ids or live.get("run_ids") != run_ids:
        raise ValueError("solver run IDs do not match production executor receipts")
    return run_ids, native_reports, validator_receipts


def verify_holdout_artifact(
    family: str,
    record: dict[str, Any],
    *,
    trusted_root: str,
    signed_events: list[dict[str, Any]],
    validator_receipts: dict[str, dict[str, Any]],
    artifact_is_current_fn: Any,
) -> bool:
    """Verify signed validator artifact integrity and match it to production executor receipts."""
    if family == post_carrier_holdout.FAMILY:
        vtype = str(record.get("vuln_type") or "").lower()
        expected_finding = "sql_injection" if "sql" in vtype else ("ssti" if "template" in vtype or "ssti" in vtype else "")
        if not expected_finding or not artifact_is_current_fn(
            record, trusted_root=trusted_root,
            expected_target=record["target"], expected_finding_type=expected_finding,
        ):
            return False
        receipt = validator_receipts.get(str(record.get("validation_id") or ""))
        if receipt is not None:
            args = receipt.get("arguments") or {}
            ctx = record.get("execution_context") or {}
            return (
                args.get("target_url") == record.get("target")
                and ctx.get("param") == args.get("param")
                and ctx.get("method", "GET") == args.get("method", "GET")
                and ctx.get("carrier", "query") == args.get("carrier", "query")
            )
    elif family == readonly_xss_redirect_holdout.FAMILY:
        vtype = str(record.get("vuln_type") or "").lower()
        expected_finding = "xss" if "xss" in vtype else ("open_redirect" if "redirect" in vtype else "")
        if not expected_finding or not artifact_is_current_fn(
            record, trusted_root=trusted_root,
            expected_target=record["target"], expected_finding_type=expected_finding,
        ):
            return False
        receipt = validator_receipts.get(str(record.get("validation_id") or ""))
        if receipt is not None:
            args = receipt.get("arguments") or {}
            ctx = record.get("execution_context") or {}
            return (
                args.get("target_url") == record.get("target")
                and ctx.get("param") == args.get("param")
                and ctx.get("method", "GET") == args.get("method", "GET")
                and ctx.get("carrier", "query") == args.get("carrier", "query")
            )
    else:
        expected_finding = finding_type(family)
        if not artifact_is_current_fn(
            record, trusted_root=trusted_root,
            expected_target=record["target"], expected_finding_type=expected_finding,
        ):
            return False
    return any(event["payload"].get("validation_id") == record["validation_id"]
               and event["payload"].get("artifact_sha256") == record["artifact"]["content_sha256"]
               and all(event["payload"].get(key) == value
                       for key, value in record.get("execution_context", {}).items())
               and event["payload"].get("status") == {
                   "CONFIRMED": "confirmed", "UNCONFIRMED": "tested_clean"}.get(record["verdict"])
               for event in signed_events)


def wire_accounting_matches(
    family: str,
    wire: list[dict[str, Any]],
    manifest: dict[str, Any],
    truth: list[dict[str, Any]],
) -> bool:
    """Verify exact wire request counts and allowed HTTP methods for the audited family."""
    if len(wire) != manifest.get("target_requests") or len(wire) != (manifest.get("budget") or {}).get("used", {}).get("http"):
        return False
    if family == post_carrier_holdout.FAMILY:
        authorized_post_paths = {case["path"] for case in truth}
        return all(
            row.get("method") == "GET"
            or (row.get("method") == "POST" and row.get("path") in authorized_post_paths)
            for row in wire
        )
    return all(row.get("method") == "GET" for row in wire)


def audit_run(manifest_path):
    """Read completed native or Python artifacts under original trust; no traffic."""
    import full_agent_launcher as launcher
    import attempt_ledger
    import evidence_trust
    from full_agent_provider import dump
    manifest_path = Path(manifest_path).resolve(strict=True)
    directory = manifest_path.parent
    private, work = directory / "private", directory / "solver"
    manifest = json.loads(manifest_path.read_text())
    prepared = launcher.prepared_run(manifest["preflight"])
    selected = prepared["contract"]["holdout_run"]
    replay(selected, manifest["seed"])
    evaluator = private / "evaluator"
    if json.loads((evaluator / "selection.json").read_text()) != selected:
        raise ValueError("lab selection does not match frozen preflight")
    if digest(evaluator / "lab-source.py") != selected["lab_sha256"]:
        raise ValueError("evaluated lab source changed")
    truth = json.loads((evaluator / "truth.json").read_text())
    wire = json.loads((evaluator / "wire.json").read_text())
    live = json.loads((work / "access/live-result.json").read_text())
    tool_index = json.loads((private / "tool-index.json").read_text())
    run_ids, native_reports, validator_receipts = extract_access_receipts_and_run_ids(
        selected["family"], live, tool_index, manifest
    )
    artifacts = [{"path": str(path), "sha256": digest(path), "record": json.loads(path.read_text())}
                 for path in sorted((private / "state/validations").glob("*.json"))]
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
        def verified(record):
            return verify_holdout_artifact(
                selected["family"],
                record,
                trusted_root=str(private / "state/validations"),
                signed_events=signed_events,
                validator_receipts=validator_receipts,
                artifact_is_current_fn=artifact_is_current,
            )
        metrics = evaluate(truth, wire, artifacts, target=manifest["target"],
                           run_id=run_ids, verify_artifact=verified,
                           claims=[claim for row in native_reports for claim in row.get("confirmed", [])])
        payload, error = attempt_ledger.verify_signed_payload(json.loads((work / "closure.json").read_text()))
        records = attempt_ledger.read_records(work / "attempts.jsonl")
        trusted, errors = attempt_ledger.verify_records(records, path=work / "attempts.jsonl")
        if manifest.get("solver_mode") == "python_loop":
            verify_python_snapshot(work, manifest, trusted)
        import brain
        verification_log = io.StringIO()
        with redirect_stdout(verification_log):
            verification_exit = brain.main(["closure", "verify", "--workdir", str(work)])
        (evaluator / "closure-verification.txt").write_text(verification_log.getvalue())
        closure_verified = (payload is not None and not error and not errors and len(trusted) == len(records)
                            and verification_exit == 0)
        recovery_vectors = {row["vector"] for row in trusted if row.get("verdict") == "session-recovery"}
        if payload is None or any(row["vector"] not in recovery_vectors for row in payload["not_tested"]):
            raise ValueError("parked vectors lack trusted session-recovery attestations")
        checks = json.loads((work / "enum/session-checks.json").read_text())
        observed_checks = {}
        for row in tool_index:
            if row["tool"] != "validator_session_vault_check" or row["task_spec_id"] != "enum-2":
                continue
            receipt = json.loads(Path(row["artifact"]).read_text())
            check = json.loads(receipt["execution"]["result"]["output"])
            observed_checks[receipt["arguments"]["identity"]] = check
        if not observed_checks or observed_checks != checks or any(row["status"] != "fresh" for row in checks.values()):
            raise ValueError("attestation evidence does not match fresh native session checks")
    accounting = wire_accounting_matches(selected["family"], wire, manifest, truth)
    if not closure_verified or not accounting:
        raise ValueError("holdout requires signed closure and exact read-only wire accounting")
    python = manifest.get("solver_mode") == "python_loop"
    provider_kind = manifest.get("provider_kind", "unknown") if python else "scripted_loopback"
    paid_calls = (0 if provider_kind == "loopback" else manifest["llm_calls"]
                  if provider_kind == "remote" else None) if python else 0
    usage = _extract_run_usage(private, manifest, len(wire))
    tp = metrics["recall"]["numerator"]
    not_tested = _extract_not_tested(
        metrics, work, provider_kind=provider_kind, paid_calls=paid_calls,
        closure_payload=payload, closure_verified=True)
    metrics.update(closure_verified=True, accounting_matches=True, target_requests=len(wire),
                   paid_provider_calls=paid_calls, provider_kind=provider_kind, full_acceptance=False,
                   failed=False, failure_reason=None,
                   models=prepared["contract"]["models"],
                   effective_limits=manifest.get("effective_limits", {}),
                   usage=usage, verified_findings=tp,
                   requests_per_verified_finding=_ratio(len(wire), tp),
                   tokens_per_verified_finding=_ratio(usage["tokens_used"], tp),
                   not_tested=not_tested,
                   evidence_refs=_collect_evidence_refs(manifest_path, work, evaluator, artifacts),
                   contract=prepared["contract"]["holdout"])
    dump(evaluator / "verified-coverage.json", signed_events)
    dump(evaluator / "metrics.json", metrics)
    summary = aggregate([metrics], prepared["contract"]["holdout"])
    dump(evaluator / "aggregate.json", summary)
    return metrics, summary


def audit_run_status(manifest_path):
    """Audit a completed OR failed holdout launch without hiding failed runs.

    Tampered evaluator selections or lab sources always fail closed. Legitimate
    incomplete/aborted solver runs (e.g., budget_exhausted, protocol failure)
    return structured failed-run metrics preserving positive/negative denominators.
    """
    import full_agent_launcher as launcher
    from full_agent_provider import dump

    manifest_path = Path(manifest_path).resolve(strict=True)
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("status") in {"python_finished_verified", "native_finished_unverified"}:
        return audit_run(manifest_path)

    directory = manifest_path.parent
    private, work = directory / "private", directory / "solver"
    prepared = launcher.prepared_run(manifest["preflight"])
    selected = prepared["contract"]["holdout_run"]
    replay(selected, manifest["seed"])
    evaluator = private / "evaluator"
    if json.loads((evaluator / "selection.json").read_text()) != selected:
        raise ValueError("lab selection does not match frozen preflight")
    if digest(evaluator / "lab-source.py") != selected["lab_sha256"]:
        raise ValueError("evaluated lab source changed")
    truth = json.loads((evaluator / "truth.json").read_text())
    wire_file = evaluator / "wire.json"
    wire = json.loads(wire_file.read_text()) if wire_file.is_file() else []
    target = manifest.get("target") or "http://127.0.0.1/"
    run_id = manifest.get("run_id") or f"failed-{manifest['seed']}"
    metrics = evaluate(truth, wire, [], target=target, run_id=run_id, verify_artifact=lambda _r: False)
    python = manifest.get("solver_mode") == "python_loop"
    provider_kind = manifest.get("provider_kind", "unknown") if python else "scripted_loopback"
    llm_calls = manifest.get("llm_calls")
    paid_calls = (0 if provider_kind == "loopback" else llm_calls
                  if provider_kind == "remote" else None) if python else 0
    usage = _extract_run_usage(private, manifest, len(wire) if wire_file.is_file() else manifest.get("target_requests"))
    failure_reason = manifest.get("stop_reason") or manifest.get("failure_phase") or manifest.get("status") or "failed"
    not_tested = _extract_not_tested(
        metrics, work, provider_kind=provider_kind, paid_calls=paid_calls,
        closure_payload=None, closure_verified=False)
    metrics.update(closure_verified=False,
                   accounting_matches=bool(
                       wire_file.is_file() and wire_accounting_matches(selected["family"], wire, manifest, truth)
                   ),
                   target_requests=len(wire) if wire_file.is_file() else manifest.get("target_requests"),
                   paid_provider_calls=paid_calls, provider_kind=provider_kind, full_acceptance=False,
                   failed=True, failure_reason=failure_reason,
                   models=prepared["contract"]["models"],
                   effective_limits=manifest.get("effective_limits", {}),
                   usage=usage, verified_findings=0,
                   requests_per_verified_finding=None,
                   tokens_per_verified_finding=None,
                   not_tested=not_tested,
                   evidence_refs=_collect_evidence_refs(manifest_path, work, evaluator, []),
                   contract=prepared["contract"]["holdout"])
    dump(evaluator / "metrics.json", metrics)
    summary = aggregate([metrics], prepared["contract"]["holdout"])
    dump(evaluator / "aggregate.json", summary)
    return metrics, summary


def main(argv=None):
    import argparse
    import full_agent_launcher as launcher
    parser = argparse.ArgumentParser(description="Independently audit completed holdout launches; no traffic")
    parser.add_argument("action", choices=["audit", "aggregate"])
    parser.add_argument("--manifest", action="append", required=True)
    args = parser.parse_args(argv)
    if args.action == "audit" and len(args.manifest) != 1:
        parser.error("audit requires one launch manifest")
    metrics, contracts = [], []
    for path in args.manifest:
        result, _ = audit_run(path)
        metrics.append(result)
        launch = json.loads(Path(path).read_text())
        contracts.append(launcher.prepared_run(launch["preflight"])["contract"]["holdout"])
    if any(contract != contracts[0] for contract in contracts):
        parser.error("holdout contracts differ")
    summary = aggregate(metrics, contracts[0])
    print(json.dumps({"metrics": metrics, "aggregate": summary}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
