"""Independent inventory/policy oracles; no solver, ledger, or holdout execution."""
from itertools import combinations, permutations

import pytest

from test_full_agent_python_holdout import expected_validation_checks


@pytest.mark.parametrize("object_counts", [(2, 3), (1, 4, 2), (3, 1, 2, 4, 2)])
def test_directed_checks_follow_heterogeneous_inventory_and_policy(object_counts):
    identities = tuple(f"actor-{index}" for index in range(len(object_counts)))
    cases = []
    inventory = {}
    for owner, count in zip(identities, object_counts):
        inventory[owner] = []
        for index in range(count):
            path = f"/owned/{owner}/item-{index}"
            # Deliberately sparse policy: an allowed nonowner is not a denied check.
            denied = set(identities) - {owner}
            if index % 2:
                denied.discard(identities[0])
            verdict = "CONFIRMED" if index % 3 == 0 else "UNCONFIRMED"
            inventory[owner].append((path, denied, verdict))
            cases.append({"path": path, "owner": owner, "denied_identities": sorted(denied),
                          "expected": "positive" if verdict == "CONFIRMED" else "negative"})

    # Separate traversal: directed permutations and declared per-object policy.
    oracle = {(owner, attacker, path): verdict
              for owner, attacker in permutations(identities, 2)
              for path, denied, verdict in inventory[owner] if attacker in denied}
    actual = expected_validation_checks(cases, pairs=combinations(identities, 2))
    assert actual == oracle
    assert len(actual) == sum(len(denied) for objects in inventory.values()
                              for _path, denied, _verdict in objects)
    assert sum(verdict == "CONFIRMED" for verdict in actual.values()) == sum(
        len(denied) for objects in inventory.values()
        for _path, denied, verdict in objects if verdict == "CONFIRMED")


@pytest.mark.parametrize("positive_count,negative_count", [(1, 2), (3, 5), (8, 8)])
def test_parameter_checks_follow_declared_case_policy(positive_count, negative_count):
    positives = {f"/parameters/vulnerable-{index}" for index in range(positive_count)}
    negatives = {f"/parameters/safe-{index}" for index in range(negative_count)}
    cases = [{"path": path, "expected": expected}
             for paths, expected in ((positives, "positive"), (negatives, "negative"))
             for path in paths]
    actual = expected_validation_checks(cases)
    assert actual == {**{(None, None, path): "CONFIRMED" for path in positives},
                      **{(None, None, path): "UNCONFIRMED" for path in negatives}}
    assert len(actual) == positive_count + negative_count
    assert sum(verdict == "CONFIRMED" for verdict in actual.values()) == positive_count
    assert sum(verdict == "UNCONFIRMED" for verdict in actual.values()) == negative_count
