"""5-status terminal verdict ledger and operator-review accounting."""
from __future__ import annotations

from typing import Any, Sequence

TERMINAL_STATUSES = (
    "blocked",
    "execution_error",
    "oracle_gap",
    "verified_pass",
    "confirmed_violation",
)
REVIEW_TIER_STATUS = "probable_review"
ALL_LEDGER_STATUSES = (*TERMINAL_STATUSES, REVIEW_TIER_STATUS)
OPERATOR_REVIEW_PURPOSE = "operator-review"
VALIDATOR_ARTIFACT_PURPOSE = "validator-artifact"
SCHEMA = "verdict-ledger/1"


def verdict_to_ledger_status(
    verdict: str,
    *,
    blocked_reason: str = "",
    execution_error: str = "",
    oracle_gap_reason: str = "",
) -> str:
    """Map validator verdict and guard metadata to canonical ledger status."""
    if blocked_reason:
        return "blocked"
    upper = str(verdict or "").strip().upper()
    if execution_error or upper == "ERROR":
        return "execution_error"
    if oracle_gap_reason or upper == "INCONCLUSIVE":
        return "oracle_gap"
    if upper == "CONFIRMED":
        return "confirmed_violation"
    if upper == "UNCONFIRMED":
        return "verified_pass"
    if upper == "PROBABLE":
        return REVIEW_TIER_STATUS
    return "oracle_gap"


def summarize_ledger(
    entries: Sequence[dict[str, Any]],
    *,
    planned: int | None = None,
) -> dict[str, Any]:
    """Summarize 5 terminal statuses + probable_review and compute adjudication coverage."""
    counts = {status: 0 for status in ALL_LEDGER_STATUSES}
    for row in entries:
        if not isinstance(row, dict):
            continue
        status = str(row.get("ledger_status") or row.get("status") or "").strip()
        if status not in counts:
            status = verdict_to_ledger_status(
                str(row.get("verdict") or ""),
                blocked_reason=str(row.get("blocked_reason") or ""),
                execution_error=str(row.get("execution_error") or ""),
                oracle_gap_reason=str(row.get("oracle_gap_reason") or ""),
            )
        counts[status] += 1

    planned_count = int(planned) if planned is not None else len(entries)
    if planned_count < 0:
        planned_count = 0
    adjudicated = counts["verified_pass"] + counts["confirmed_violation"]
    adjudication_coverage = round(adjudicated / planned_count, 4) if planned_count > 0 else 0.0
    return {
        "schema": SCHEMA,
        "planned": planned_count,
        "counts": counts,
        "blocked": counts["blocked"],
        "execution_error": counts["execution_error"],
        "oracle_gap": counts["oracle_gap"],
        "verified_pass": counts["verified_pass"],
        "confirmed_violation": counts["confirmed_violation"],
        "probable_review": counts["probable_review"],
        "adjudicated": adjudicated,
        "adjudication_coverage": adjudication_coverage,
    }
