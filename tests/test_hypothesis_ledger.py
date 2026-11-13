import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_target_identity_unifies_spellings():
    ti = _load("target_identity")
    assert ti.canonical_target("HTTP://192.168.2.1:8080/docs") == "http://192.168.2.1:8080"
    assert ti.canonical_target("10.0.0.5") == "10.0.0.5"
    assert ti.target_key("http://192.168.2.1:8080") == "192.168.2.1:8080"
    assert ti.target_key("192.168.2.1:8080") == "192.168.2.1:8080"
    assert ti.target_key("https://Example.com/login") == "example.com:443"
    assert ti.target_key("192.168.2.1") == "192.168.2.1"


def test_ledger_rotation_exhausts_blocked_vector():
    hl = _load("hypothesis_ledger")
    ledger = hl.init_ledger("http://192.168.2.1:8080", vectors=["a", "b", "c"], max_attempts=2)
    assert ledger["target_key"] == "192.168.2.1:8080"

    first = hl.claim_next(ledger)
    assert first["vector"] == "a" and first["status"] == "active"
    assert hl.claim_next(ledger)["vector"] == "a"  # resume, not a new vector

    hl.mark(ledger, "a", "blocked")
    assert hl.claim_next(ledger)["vector"] == "b"  # rotation: fresher vector first
    hl.mark(ledger, "b", "confirmed", evidence="ev/b.bin")
    assert hl.claim_next(ledger)["vector"] == "c"  # confirmed closes only b
    hl.mark(ledger, "c", "blocked")
    assert hl.claim_next(ledger)["vector"] == "a"  # second pass: attempts left
    entry = hl.mark(ledger, "a", "blocked")
    assert entry["status"] == "exhausted" and entry["attempts"] == 2
    assert hl.claim_next(ledger)["vector"] == "c"
    hl.mark(ledger, "c", "not_applicable")
    assert hl.claim_next(ledger) is None
    assert hl.ledger_summary(ledger)["exhausted"] == 1


def test_ledger_terminal_and_unknown_vector_rejected():
    hl = _load("hypothesis_ledger")
    ledger = hl.init_ledger("h", vectors=["a"])
    hl.claim_next(ledger)
    hl.mark(ledger, "a", "confirmed")
    with pytest.raises(ValueError):
        hl.mark(ledger, "a", "active")
    with pytest.raises(KeyError):
        hl.mark(ledger, "ghost", "blocked")


def test_ledger_persists_and_brain_cli_roundtrip(tmp_path):
    hl = _load("hypothesis_ledger")
    brain = _load("brain")
    workdir = str(tmp_path / "run")
    assert brain.main(["hypotheses", "init", "--target",
                       "http://192.168.2.1:8080/", "--workdir", workdir]) == 0
    ledger = hl.load_ledger(workdir)
    assert ledger["target"] == "http://192.168.2.1:8080"
    assert brain.main(["hypotheses", "next", "--workdir", workdir]) == 0
    assert brain.main(["hypotheses", "mark", "--workdir", workdir,
                       "--vector", "authz-idor", "--status", "blocked"]) == 0
    assert brain.main(["hypotheses", "mark", "--workdir", workdir,
                       "--vector", "authz-idor", "--status", "blocked"]) == 0
    ledger = hl.load_ledger(workdir)
    assert ledger["hypotheses"][0]["status"] == "exhausted"
    assert hl.peek_next(ledger)["vector"] == "authn-session"
    assert brain.main(["hypotheses", "next", "--workdir", str(tmp_path / "nope")]) == 2


def test_reorder_puts_documents_idor_first():
    mod = _load("hypothesis_ledger")
    ledger = mod.init_ledger("http://x:8080")
    routes = ["/", "/docs", "/api/documents", "/api/documents/:id/download",
              "/api/webhooks", "/api/reports", "/api/billing/promo", "/support"]
    params = ["metaFields", "code", "url", "events"]
    mod.reorder_by_surface(ledger, routes, params)
    order = [e["vector"] for e in ledger["hypotheses"] if e["status"] == "untried"]
    assert order[0] == "authz-idor"
    assert set(order[:5]) >= {"authz-idor", "ssrf", "injection-sqli", "race-business", "xss-stored"}
    # Deterministic: same surface, same order.
    again = mod.init_ledger("http://x:8080")
    mod.reorder_by_surface(again, routes, params)
    assert [e["vector"] for e in again["hypotheses"]] == [e["vector"] for e in ledger["hypotheses"]]


def test_reorder_keeps_active_first_and_terminal_last():
    mod = _load("hypothesis_ledger")
    ledger = mod.init_ledger("http://x:8080")
    mod.mark(ledger, "csrf", "active")
    mod.mark(ledger, "authn-session", "confirmed")
    mod.reorder_by_surface(ledger, ["/api/documents"], [])
    vecs = [e["vector"] for e in ledger["hypotheses"]]
    assert vecs[0] == "csrf"
    assert vecs[-1] == "authn-session"


def test_score_no_substring_false_positives():
    mod = _load("hypothesis_ledger")
    assert mod.score_vectors(["/resource/codes"], [])["race-business"] == 0
    assert mod.score_vectors(["/encoder/decode"], [])["race-business"] == 0


def test_object_candidates_merge_routes_own_and_docs():
    mod = _load("hypothesis_ledger")
    pool = mod.object_candidates(
        routes=["/api/documents/1043/download", "/api/documents/:id/download"],
        own_ids=[37], docs_ids=[1001], radius=25)
    assert pool == sorted(pool) and len(pool) == len(set(pool))
    for value in (1043, 37, 1001):
        assert value in pool
        for window in (1, 2, 5, 10, 25):
            assert value - window in pool
            assert value + window in pool


def test_object_candidates_empty_and_radius():
    mod = _load("hypothesis_ledger")
    assert mod.object_candidates([], [], []) == []
    assert mod.object_candidates(None, None, None) == []
    tight = mod.object_candidates([], [50], [], radius=2)
    assert 48 in tight and 52 in tight
    assert 45 not in tight and 55 not in tight


def test_object_candidates_ignore_versions_ports_and_zero():
    mod = _load("hypothesis_ledger")
    pool = mod.object_candidates(
        routes=["http://h:8080/api/v2/documents/1043/download", "/api/v2/items"],
        own_ids=[0, -5], docs_ids=[], radius=25)
    assert 1043 in pool
    assert 8080 not in pool and 2 not in pool and 1 not in pool
    assert all(value >= 1 for value in pool)


def test_object_candidates_radius_none_and_priority_order():
    mod = _load("hypothesis_ledger")
    assert mod.object_candidates([], [50], [], radius=None) == \
        mod.object_candidates([], [50], [], radius=25)
    prio = mod.object_candidates([], [100, 200], [], priority_order=True)
    assert prio[:6] == [100, 200, 99, 101, 199, 201]


def test_object_candidates_cap_keeps_tight_windows():
    mod = _load("hypothesis_ledger")
    observed = [i * 100 for i in range(1, 61)]
    pool = mod.object_candidates([], observed, [], radius=25)
    assert len(pool) <= 200
    assert all(value in pool for value in observed)
    assert observed[0] - 1 in pool and observed[0] + 1 in pool
    assert observed[-1] + 25 not in pool


def test_score_still_hits_real_surface_words():
    mod = _load("hypothesis_ledger")
    assert mod.score_vectors(["/billing/promo"], [])["race-business"] > 0
    assert mod.score_vectors(["/support/messages"], [])["xss-stored"] > 0
    assert mod.score_vectors(["/api/documents/:id/download"], [])["authz-idor"] > 0
    assert mod.score_vectors(["/api/reports"], ["metaFields"])["injection-sqli"] > 0


def test_object_candidates_no_blind_neighbours_for_opaque_ids():
    mod = _load("hypothesis_ledger")
    pool = mod.object_candidates(
        routes=[], own_ids=[{"family": "shipments", "id": "fd7044b1-df54-42fc-b54b-4599a3484b5d"}],
        docs_ids=[], radius=25)
    assert pool == [{"family": "shipments", "format": "uuid",
                     "value": "fd7044b1-df54-42fc-b54b-4599a3484b5d"}]
    pool = mod.object_candidates(
        routes=[], own_ids=[{"family": "docs", "id": "1001"}],
        docs_ids=[], radius=25)
    for value in (1001, 1000, 1002, 996, 1006, 991, 1011, 976, 1026):
        assert {"family": "docs", "format": "int", "value": value} in pool


def test_object_candidates_accept_bare_and_tagged_ids():
    mod = _load("hypothesis_ledger")
    pool = mod.object_candidates(
        routes=[], own_ids=[37, {"family": "docs", "id": "1001"}, "  ",
                            {"family": "x", "id": ""}],
        docs_ids=[], radius=2)
    assert 37 in pool and {"family": "docs", "format": "int", "value": 1001} in pool
    assert 35 in pool and 39 in pool
    assert all({"family": "docs", "format": "int", "value": value} in pool for value in (999, 1003))
