"""Bounded candidate routing. A candidate is a hypothesis, never a finding."""
from __future__ import annotations

from collections import defaultdict, deque
from contextlib import contextmanager
from contextvars import ContextVar

_CANDIDATE_LISTENER = ContextVar("candidate_listener", default=None)


@contextmanager
def candidate_listener(callback):
    token = _CANDIDATE_LISTENER.set(callback)
    try:
        yield
    finally:
        _CANDIDATE_LISTENER.reset(token)


def publish_candidate(item):
    listener = _CANDIDATE_LISTENER.get()
    if listener is not None:
        listener(item)


SAMPLE_CLASSES = {"sql_injection", "ssti", "path_traversal", "lfi", "xss_reflected", "open_redirect"}


def sampling_limit(value):
    """Keep extra validation selection bounded independently of wire budgets."""
    if isinstance(value, bool):
        raise ValueError("sample limit must be an integer")
    limit = int(value)
    if limit != value or not 0 <= limit <= 20:
        raise ValueError("sample limit must be an integer between 0 and 20")
    return limit


def _eligible_probe(row):
    if (not row.get("live") or not row.get("baseline_eligible")
            or row.get("coverage_status") in {"blocked", "not_tested"}):
        return False
    status = row.get("status")
    # Older callers omit status; explicit failed responses must never become
    # samples merely because a light oracle returned INCONCLUSIVE.
    return "status" not in row or (isinstance(status, int) and not isinstance(status, bool)
                                   and (200 <= status < 400 or status in {400, 422}))


def interleave_probes(items):
    """Visit distinct operations before spending on another payload of one."""
    groups = defaultdict(deque)
    for item in items:
        key = (item.get("operation_id") or item.get("fingerprint") or
               item.get("baseline_url") or item.get("url"), item.get("observation_id"),
               item.get("baseline_method") or item.get("method") or "GET")
        groups[key].append(item)
    out = []
    while groups:
        for key in list(groups):
            out.append(groups[key].popleft())
            if not groups[key]:
                del groups[key]
    return out


def candidate_key(item):
    return ("path_traversal" if item.get("vuln_class") == "lfi" else item.get("vuln_class"),
            item.get("operation_id"), item.get("observation_id"),
            item.get("baseline_method") or item.get("method") or "GET",
            item.get("template_url") or item.get("baseline_url") or item.get("url"),
            item.get("location") or item.get("carrier") or "query", item.get("param"),
            item.get("identity"), item.get("resource_owner"),
            *(item.get(k) for k in ("resource_key", "resource_family", "state_key", "variant_key")))


def select_candidates(rows, sample_limit=4):
    """Signals first, then round-robin sampling across eligible classes.

    Sampling reuses completed canaries; it sends no extra requests. Blocked,
    unexecuted and invalid-baseline probes cannot consume validation budget.
    """
    limit = sampling_limit(sample_limit)
    signals, samples, seen = [], defaultdict(deque), set()
    for row in rows:
        if not _eligible_probe(row):
            continue
        key = candidate_key(row)
        if key in seen:
            continue
        verdict = row.get("triage_verdict")
        if verdict == "LIKELY":
            seen.add(key)
            signals.append({**row, "candidate_source": "light_oracle", "candidate_reason": "observed_signal"})
    for row in rows:
        key = candidate_key(row)
        if (key in seen or not _eligible_probe(row)
                or row.get("triage_verdict") != "INCONCLUSIVE"
                or row.get("vuln_class") not in SAMPLE_CLASSES
                or row.get("coverage_status") in {"blocked", "not_tested"}):
            continue
        seen.add(key)
        samples[key[0]].append({**row, "candidate_source": "bounded_sampling",
                               "candidate_reason": "valid_baseline_without_light_signal"})
    selected = []
    while samples and len(selected) < limit:
        for kind in list(samples):
            if len(selected) >= limit:
                break
            selected.append(samples[kind].popleft())
            if not samples[kind]:
                del samples[kind]
    return signals + selected


def fair_queue(items):
    """Deduplicate complete request dimensions and interleave test classes."""
    groups, seen = defaultdict(deque), set()
    for item in items:
        key = candidate_key({**item, "identity": item.get("attacker_identity") or item.get("identity"),
                             "resource_owner": item.get("owner_identity") or item.get("resource_owner")})
        if key not in seen:
            seen.add(key)
            groups[key[0]].append(item)
    queue = []
    while groups:
        for kind in list(groups):
            queue.append(groups[kind].popleft())
            if not groups[kind]:
                del groups[kind]
    from cco_surface_core.hypotheses import priority
    return sorted(queue, key=lambda item: priority({
        "status": "ready", "observation_quality": 3 if item.get("candidate_source") == "light_oracle" else 1,
        **item}))
