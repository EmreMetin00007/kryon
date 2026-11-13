"""Structured action manifest (chain-runner dili) — şema v1.

Planner serbest metin yerine bu şemayı üretir; executor (13b) çalıştırmadan
önce validate_manifest ile doğrular. Fail-closed: bilinmeyen oracle, tanımsız
goto hedefi, bütçe aşımı veya risk sınıfı hatası manifesti reddeder.
"""

from __future__ import annotations

import hashlib
import json

SCHEMA_VERSION = "action-manifest/1.0"

RISKS = frozenset({"passive", "active_read_only", "active_state_changing"})

# Executor'ın implemente ettiği oracle adları. Yeni oracle = executor + test.
ORACLES = frozenset({
    "differential_content",
    "status_code",
    "marker_present",
    "oob_callback",
    "validator_verdict",
    "artifact_exists",
    "state_invariant",
    "business_logic",
    "business_control",
    "response_divergence",
    "extract_ok",
    "evidence_observation",
    "evidence_effect",
})

TERMINALS = frozenset({"succeed", "fail", "abort"})

MAX_STEPS = 50
MAX_ID_LEN = 64
DEFAULT_ROUTE_CAP = 50


def _is_slug(value) -> bool:
    if not isinstance(value, str) or not value or len(value) > MAX_ID_LEN:
        return False
    return all(ch.isalnum() or ch in {"-", "_"} for ch in value)


def _canonical_json(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def manifest_hash(manifest: dict) -> str:
    """Kanonik manifest hash'i (permit/imza bağlaması için)."""
    clean = {k: v for k, v in manifest.items() if k != "manifest_hash"}
    return hashlib.sha256(_canonical_json(clean).encode("utf-8")).hexdigest()


def validate_manifest(candidate) -> dict:
    """Manifesti doğrula. Dönüş: {"valid", "errors", "manifest_hash", "stats"}."""
    errors: list[str] = []
    if isinstance(candidate, str):
        try:
            candidate = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            return {"valid": False, "errors": ["geçersiz JSON"], "manifest_hash": "", "stats": {}}
    if not isinstance(candidate, dict):
        return {"valid": False, "errors": ["manifest dict olmalı"], "manifest_hash": "", "stats": {}}

    if candidate.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version {SCHEMA_VERSION!r} olmalı")
    if not isinstance(candidate.get("objective"), str) or not candidate["objective"].strip():
        errors.append("objective boş olamaz")
    if not isinstance(candidate.get("target_ref"), str) or not candidate["target_ref"].strip():
        errors.append("target_ref boş olamaz")
    if candidate.get("risk") not in RISKS:
        errors.append(f"risk {sorted(RISKS)} içinden olmalı")

    try:
        from .business_logic import KINDS, manifest_errors
    except ImportError:
        from business_logic import KINDS, manifest_errors
    if candidate.get('kind') in KINDS or 'business_logic' in candidate:
        errors.extend(manifest_errors(candidate))
    if candidate.get('status') == 'draft_hypothesis' or candidate.get('synthetic'):
        errors.append('draft_hypothesis is not executable')
    if candidate.get('kind') == 'evidence_bound_read' or 'evidence_chain' in candidate:
        try:
            from .evidence_chaining import manifest_errors as chain_errors
        except ImportError:
            from evidence_chaining import manifest_errors as chain_errors
        errors.extend(chain_errors(candidate))
    elif isinstance(candidate.get('steps'), list) and any(
            isinstance(s, dict) and isinstance(s.get('expect'), dict) and
            s['expect'].get('oracle') in {'evidence_observation', 'evidence_effect'}
            for s in candidate['steps']):
        errors.append('evidence oracle requires evidence_chain')

    budget = candidate.get("budget")
    max_requests = 0
    max_duration = 0
    if not isinstance(budget, dict):
        errors.append("budget dict olmalı")
    else:
        max_requests = budget.get("max_requests", 0)
        max_duration = budget.get("max_duration_seconds", 0)
        if not isinstance(max_requests, int) or max_requests < 1:
            errors.append("budget.max_requests >= 1 tamsayı olmalı")
        if not isinstance(max_duration, int) or max_duration < 1:
            errors.append("budget.max_duration_seconds >= 1 tamsayı olmalı")
        route_cap = budget.get("route_cap", DEFAULT_ROUTE_CAP)
        if not isinstance(route_cap, int) or route_cap < 0:
            errors.append("budget.route_cap >= 0 tamsayı olmalı (0 = sınırsız)")

    identity_refs = candidate.get("identity_refs", [])
    if not isinstance(identity_refs, list) or any(not isinstance(i, str) or not i for i in identity_refs):
        errors.append("identity_refs str listesi olmalı")

    steps = candidate.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("steps boş olmayan liste olmalı")
        return {"valid": False, "errors": errors, "manifest_hash": "", "stats": {}}
    if len(steps) > MAX_STEPS:
        errors.append(f"steps en fazla {MAX_STEPS} olabilir")

    seen_ids: set[str] = set()
    for index, step in enumerate(steps):
        where = f"steps[{index}]"
        if not isinstance(step, dict):
            errors.append(f"{where} dict olmalı")
            continue
        step_id = step.get("id", "")
        if not _is_slug(step_id):
            errors.append(f"{where}.id slug olmalı")
        elif step_id in seen_ids:
            errors.append(f"tekrarlanan step id: {step_id!r}")
        else:
            seen_ids.add(step_id)
        if not isinstance(step.get("tool"), str) or not step["tool"].strip():
            errors.append(f"{where}.tool boş olamaz")
        if "args" in step and not isinstance(step["args"], dict):
            errors.append(f"{where}.args dict olmalı")
        expect = step.get("expect")
        if not isinstance(expect, dict):
            errors.append(f"{where}.expect dict olmalı")
        elif expect.get("oracle") not in ORACLES:
            errors.append(f"{where}.expect.oracle {sorted(ORACLES)} içinden olmalı")
        elif expect.get("oracle") == "state_invariant":
            has_num = bool(str(expect.get("numeric_field") or "").strip())
            has_mut = isinstance(expect.get("mutated_fields"), list) and len(expect["mutated_fields"]) > 0
            has_state = bool(str(expect.get("state_field") or "").strip()) and "expected_state" in expect
            if not (has_num or has_mut or has_state):
                errors.append(f"{where}.expect state_invariant en az bir kural (numeric_field/mutated_fields/state_field) gerektirir")
            rule = str(expect.get("rule") or "decreased").lower()
            if has_num and rule not in {"negative", "non_positive", "decreased", "increased", "delta_gt", "stable", "collapsed"}:
                errors.append(f"{where}.expect.rule geçersiz: {rule!r}")
        for key in ("on_success", "on_failure"):
            target = step.get(key)
            if not isinstance(target, str) or not target:
                errors.append(f"{where}.{key} boş olamaz")
        for key in ("max_requests", "max_duration_seconds"):
            if key in step and (not isinstance(step[key], int) or step[key] < 1):
                errors.append(f"{where}.{key} >= 1 tamsayı olmalı")
        if "requires" in step:
            req = step["requires"]
            if not isinstance(req, list) or any(not isinstance(r, str) or not r for r in req):
                errors.append(f"{where}.requires str listesi olmalı")
        if step.get("tool") == "extract":
            eargs = step.get("args") or {}
            for field in ("from_step", "pattern", "save_as"):
                if not isinstance(eargs.get(field), str) or not eargs[field].strip():
                    errors.append(f"{where}.args.{field} boş olamaz (extract)")
            if "group" in eargs:
                try:
                    if int(eargs["group"]) < 0:
                        errors.append(f"{where}.args.group >= 0 olmalı")
                except (TypeError, ValueError):
                    errors.append(f"{where}.args.group tamsayı olmalı")
        if isinstance(max_requests, int) and isinstance(step.get("max_requests"), int):
            if step["max_requests"] > max_requests:
                errors.append(f"{where}.max_requests manifest bütçesini aşamaz")
        if isinstance(max_duration, int) and isinstance(step.get("max_duration_seconds"), int):
            if step["max_duration_seconds"] > max_duration:
                errors.append(f"{where}.max_duration_seconds manifest bütçesini aşamaz")

    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        for key in ("on_success", "on_failure"):
            target = step.get(key)
            if isinstance(target, str) and target and target not in TERMINALS and target not in seen_ids:
                errors.append(f"steps[{index}].{key} tanımsız hedef: {target!r}")
        for req in step.get("requires") or []:
            if isinstance(req, str) and req not in seen_ids:
                errors.append(f"steps[{index}].requires tanımsız adım: {req!r}")

    stats = {"steps": len(steps), "risk": candidate.get("risk", ""), "objective": candidate.get("objective", "")}
    if errors:
        return {"valid": False, "errors": errors, "manifest_hash": "", "stats": stats}
    return {"valid": True, "errors": [], "manifest_hash": manifest_hash(candidate), "stats": stats}
