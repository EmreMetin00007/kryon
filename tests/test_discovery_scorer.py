"""Scorer v2 tests: normal observations are not FP; vuln claims bind to evidence."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "lab"))

from discovery_lab import B_LISTED  # noqa: E402
from discovery_experiment import score  # noqa: E402
from discovery_executor import LabExecutor  # noqa: E402
from discovery_lab import DiscoveryLab  # noqa: E402
from full_agent_budget import BudgetError, SharedBudget  # noqa: E402


def _log(*entries):
    return list(entries)


def test_normal_observations_are_not_false_positives():
    log = _log({"method": "GET", "path": "/api/reviews", "user": None, "status": 200})
    claims = [
        {"endpoint": "/api/orders compared with /billing/orders", "family": "other",
         "observation": "listings contain different datasets"},
        {"endpoint": "/api/reviews", "family": "access_control",
         "observation": "reviews expose order_ref identifiers"},
    ]
    s = score(log, claims)
    assert s["false_positive_claims"] == 0
    assert s["observations"] == 1
    assert s["supported_observations"] == 1


def test_access_claim_binds_to_cross_read_evidence():
    log = _log({"method": "GET", "path": f"/api/orders/{B_LISTED[0]}",
                "user": "member_a", "status": 200})
    claims = [{"endpoint": "/api/orders/{id}", "family": "access_control",
               "observation": "cross-account read succeeded"}]
    s = score(log, claims)
    assert s["detected"]["bola_listed"] is True
    assert s["supported_positives"] == 1
    assert s["false_positive_claims"] == 0


def test_access_claim_without_evidence_is_false_positive():
    log = _log({"method": "GET", "path": "/api/orders", "user": "member_a", "status": 200})
    claims = [{"endpoint": "/api/orders/{id}", "family": "access_control",
               "observation": "cross-account read succeeded"}]
    s = score(log, claims)
    assert s["supported_positives"] == 0
    assert s["false_positive_claims"] == 1


def test_billing_claim_when_control_held_is_false_positive():
    log = _log({"method": "GET", "path": f"/billing/orders/{B_LISTED[0]}",
                "user": "member_a", "status": 403})
    claims = [{"endpoint": "/billing/orders/{id}", "family": "access_control",
               "observation": "billing allows cross-account read"}]
    s = score(log, claims)
    assert s["false_positive_claims"] == 1


def test_shared_executor_budget_is_common_to_both_flows():
    lab = DiscoveryLab()
    try:
        budget = SharedBudget(http=2, tokens=1000, seconds=60)
        ex_a = LabExecutor(lab.base, budget)
        ex_b = LabExecutor(lab.base, budget)
        assert ex_a.fetch("GET", "/catalog")["status"] == 200
        assert ex_b.fetch("GET", "/catalog")["status"] == 200
        with pytest.raises(BudgetError):
            ex_a.fetch("GET", "/catalog")
    finally:
        lab.close()
