"""Aggregate phase-summary defects without admitting or inventing evidence."""
from __future__ import annotations

from orchestration_spec import validate_summary


def summary_errors(summary, spec):
    errors = validate_summary(summary)
    if isinstance(summary, dict):
        for field, expected in (("phase", spec.phase), ("target", spec.target)):
            if summary.get(field) != expected:
                errors.append(f"summary {field} must match the current TaskSpec")
        steps = summary.get("steps")
        if isinstance(steps, list) and all(isinstance(row, dict) for row in steps):
            if [row.get("id") for row in steps] != [step.id for step in spec.steps]:
                errors.append("summary steps must match TaskSpec order and IDs")
    return list(dict.fromkeys(errors))


def summary_feedback(summary, spec):
    errors = summary_errors(summary, spec)
    return {"schema": "host-summary-feedback/1", "valid": not errors, "errors": errors,
            "repair_limit": 1, "action": "Resubmit the summary once using existing evidence; no probes."}
