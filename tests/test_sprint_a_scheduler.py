"""Sprint A Task 3 offline tests: lazy deterministic budget-aware scheduler and atomic reservation."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from full_agent_budget import BudgetError, SharedBudget
import full_agent_python_broker as broker
import python_candidate_runtime as cand
import python_scheduler as sched


def test_task3_lazy_scheduler_bounds_queue_without_eager_materialization():
    """200 endpoints × 5 profiles (1000 pairs) stays lazily bounded at <= 64 queue items."""
    endpoints = [{"url": f"http://127.0.0.1:41000/ep-{i:03d}?p=1", "param": "p"} for i in range(200)]
    profiles = [f"profile_{j}" for j in range(5)]
    seen_calls = 0

    def eligibility(_ep, profile):
        nonlocal seen_calls
        seen_calls += 1
        return {"eligible": True, "reason_code": "eligible"}

    scheduler = sched.LazyBudgetScheduler(
        endpoints,
        profiles,
        eligibility_fn=eligibility,
        max_queue_size=64,
        call_budget=14,
        token_budget=37_500,
    )
    assert scheduler.materialized_count == 0
    q_len = scheduler.refill()
    assert q_len == 64
    assert scheduler.peak_queue_size == 64
    # Must NOT have eagerly evaluated all 1000 (E × P) combinations!
    assert seen_calls < 100
    assert scheduler.materialized_count <= 65

    dispatched = []
    for _ in range(14):
        item = scheduler.pop_next(estimated_tokens=1000)
        assert item is not None
        dispatched.append(item)
        scheduler.record_usage(calls=1, tokens=1000)
        assert scheduler.peak_queue_size <= 64

    # 15th pop exhausts call_budget=14 and defers the remaining eligible pairs cleanly.
    assert scheduler.pop_next(estimated_tokens=1000) is None
    assert len(dispatched) == 14
    assert scheduler.deferred_count == (200 * 5) - 14


def test_task3_deterministic_and_multi_profile_round_robin_fairness():
    """Same inputs produce identical schedules; profiles alternate round-robin rather than starving later ones."""
    endpoints = [f"http://127.0.0.1:41000/ep/{i}?id={i}" for i in range(6)]
    profiles = ["readonly_ssti_arithmetic", "readonly_sqli_boolean", "readonly_traversal_application_files"]

    def run_once(ep_order):
        s = sched.LazyBudgetScheduler(ep_order, profiles, max_queue_size=64, call_budget=9, token_budget=37_500)
        out = []
        while True:
            item = s.pop_next(estimated_tokens=500)
            if item is None:
                break
            out.append((item["profile"], item["endpoint"]))
            s.record_usage(calls=1, tokens=500)
        return out, s.deferred_count

    first, def1 = run_once(endpoints)
    reversed_order, def2 = run_once(list(reversed(endpoints)))
    assert first == reversed_order
    assert def1 == def2 == 9
    # All 3 profiles get fair turns in the first 3 dispatches!
    assert {p for p, _ in first[:3]} == set(profiles)
    # Exactly 3 dispatches per profile out of 9 calls.
    for p in profiles:
        assert sum(1 for prof, _ in first if prof == p) == 3


def test_task3_interleave_fair_work_balances_profiles_and_bounds_deferred():
    """interleave_fair_work alternates across profiles and marks overflow without mutating reason semantics."""
    rows = []
    for i in range(40):
        rows.append({"validation_profile": "readonly_sqli_boolean", "route": f"http://127.0.0.1:41000/a/{i}", "param": "id"})
        rows.append({"validation_profile": "readonly_ssti_arithmetic", "route": f"http://127.0.0.1:41000/b/{i}", "param": "name"})
    selected, deferred = sched.interleave_fair_work(rows, max_queue_size=10)
    assert len(selected) == 10 and len(deferred) == 70
    assert [r["validation_profile"] for r in selected[:4]] == [
        "readonly_sqli_boolean",
        "readonly_ssti_arithmetic",
        "readonly_sqli_boolean",
        "readonly_ssti_arithmetic",
    ]


def test_task3_concurrent_atomic_reservation_and_conservative_reconciliation():
    """Concurrent threads reserving against access caps never over-allocate; failures/uncertain retain charges."""
    policy = broker.PythonRuntimePolicy(SharedBudget(http=100, tokens=40_000, seconds=120))
    policy.limits["access"] = 10_000
    spec = SimpleNamespace(
        id="access-1",
        phase="access",
        max_calls=14,
        tools={"validator_validate_sqli"},
    )
    policy.handoff_reserves["access-1"] = 0
    policy.validation_reserves["access-1"] = 0
    policy.checkpoint_reserves["access-1"] = 0

    tickets: list[str] = []
    errors: list[Exception] = []
    lock = threading.Lock()
    barrier = threading.Barrier(6)

    def worker():
        try:
            barrier.wait(timeout=5)
            ticket = policy.reserve_execution(spec, calls=1, estimated_tokens=3000)
            with lock:
                tickets.append(ticket)
        except BudgetError as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    # 10,000 phase token cap -> at most 3 concurrent 3,000-token reservations succeed; 3 fail atomically.
    assert len(tickets) == 3
    assert len(errors) == 3

    # Reconcile one with measured 1,200 tokens, one with uncertain measurement (retains 3,000), one overrun (retains 3,000).
    policy.reconcile_execution(tickets[0], actual_calls=1, actual_tokens=1200, measurement_valid=True)
    policy.reconcile_execution(tickets[1], actual_calls=1, actual_tokens=None, measurement_valid=False)
    policy.reconcile_execution(tickets[2], actual_calls=1, actual_tokens=9999, measurement_valid=True)
    remaining, _, _ = policy.allowance(spec)
    # 10,000 - (1,200 + 3,000 + 3,000) = 2,800 remaining
    assert remaining == 2800


def test_task3_deferred_budget_distinct_from_invalid_evidence():
    """Budget-deferred rows never collapse into invalid_or_missing_signed_evidence."""
    deferred_row = {
        "observed": True,
        "eligible": True,
        "admitted": False,
        "executed": False,
        "evidence_accepted": False,
        "reason_code": "deferred_budget",
    }
    exhausted_row = {**deferred_row, "reason_code": "phase_tool_budget_exhausted"}
    invalid_row = {
        "observed": True,
        "eligible": True,
        "admitted": True,
        "executed": True,
        "evidence_accepted": False,
        "reason_code": "invalid_or_missing_signed_evidence",
    }
    assert cand.classify_candidate_outcome(deferred_row) == "budget_deferred"
    assert cand.classify_candidate_outcome(exhausted_row) == "budget_deferred"
    assert cand.classify_candidate_outcome(invalid_row) == "invalid_evidence"
    f = cand.funnel([deferred_row, exhausted_row, invalid_row])
    assert f["outcomes"]["budget_deferred"] == 2
    assert f["outcomes"]["invalid_evidence"] == 1
