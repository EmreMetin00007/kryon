"""Sprint A Tasks 1 & 2 offline tests: deterministic applicability gating and versioned signed_completion."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

import evidence_trust
import python_candidate_runtime as cand
import signed_completion as sc


def _make_record(url: str, *, source_artifact: str = "/tmp/disc.json") -> dict:
    sha = hashlib.sha256(url.encode()).hexdigest()
    return {
        "url": url,
        "method": "GET",
        "source_spec_id": "discover-1",
        "source_artifact": source_artifact,
        "source_sha256": sha,
    }


def _spec(target: str = "http://127.0.0.1:41000/", vector: str = "access") -> SimpleNamespace:
    return SimpleNamespace(
        id="access-1",
        target=target,
        vector=vector,
        tools={
            "hunter_run_web_loop",
            "validator_validate_sqli",
            "validator_validate_ssti",
            "validator_validate_path_traversal",
        },
    )


def test_task1_applicability_gating_excludes_non_matching_profiles_without_gaps():
    """SQLi surfaces skip SSTI/traversal, SSTI surfaces skip SQLi/traversal, and eligible pairs are preserved."""
    target = "http://127.0.0.1:41000/"
    spec = _spec(target)
    records = [
        _make_record(f"{target}lookup/abc/123?id=1"),
        _make_record(f"{target}templates/def/456?name=World"),
        _make_record(f"{target}search?q=hello"),
        _make_record(f"{target}files/ghi/789?file=notes.txt"),
    ]
    eligible_traversal = lambda _s, url, param, _c, _p: (
        {"eligible": True, "reason_code": "eligible"}
        if "/files/" in url and param == "file"
        else {"eligible": False, "reason_code": "traversal_policy_not_declared"}
    )
    rows = cand.parameter_candidates(spec, records, {}, profile_eligibility=eligible_traversal)
    by_pair = {(urlsplit(r["route"]).path, r["param"], r.get("validation_profile")): r for r in rows}

    # SQLi endpoint: SQLi eligible; SSTI materialized ineligible with profile_not_applicable_to_surface; traversal suppressed.
    sqli_on_lookup = by_pair[("/lookup/abc/123", "id", "readonly_sqli_boolean")]
    ssti_on_lookup = by_pair[("/lookup/abc/123", "id", "readonly_ssti_arithmetic")]
    assert sqli_on_lookup["eligible"] is True and sqli_on_lookup["reason_code"] == ""
    assert ssti_on_lookup["eligible"] is False
    assert ssti_on_lookup["reason_code"] == "profile_not_applicable_to_surface"
    assert ("/lookup/abc/123", "id", "readonly_traversal_application_files") not in by_pair

    # SSTI endpoint: SSTI eligible; SQLi ineligible with profile_not_applicable_to_surface; traversal suppressed.
    ssti_on_tpl = by_pair[("/templates/def/456", "name", "readonly_ssti_arithmetic")]
    sqli_on_tpl = by_pair[("/templates/def/456", "name", "readonly_sqli_boolean")]
    assert ssti_on_tpl["eligible"] is True and ssti_on_tpl["reason_code"] == ""
    assert sqli_on_tpl["eligible"] is False
    assert sqli_on_tpl["reason_code"] == "profile_not_applicable_to_surface"
    assert ("/templates/def/456", "name", "readonly_traversal_application_files") not in by_pair

    # Generic search endpoint: both SQLi and SSTI remain eligible; traversal not applicable.
    assert by_pair[("/search", "q", "readonly_sqli_boolean")]["eligible"] is True
    assert by_pair[("/search", "q", "readonly_ssti_arithmetic")]["eligible"] is True
    assert ("/search", "q", "readonly_traversal_application_files") not in by_pair

    # File endpoint: traversal eligible; SQLi and SSTI gated out as inapplicable.
    trav_on_file = by_pair[("/files/ghi/789", "file", "readonly_traversal_application_files")]
    assert trav_on_file["eligible"] is True and trav_on_file["reason_code"] == ""
    assert by_pair[("/files/ghi/789", "file", "readonly_sqli_boolean")]["reason_code"] == "profile_not_applicable_to_surface"
    assert by_pair[("/files/ghi/789", "file", "readonly_ssti_arithmetic")]["reason_code"] == "profile_not_applicable_to_surface"

    # Non-matching profiles map strictly to 'ineligible', never 'invalid_evidence'.
    f = cand.funnel(rows)
    assert f["denominators"]["discovered_pairs"] == len(rows)
    assert f["denominators"]["eligible_pairs"] == 5
    assert f["outcomes"]["ineligible"] == len(rows) - 5
    assert f["outcomes"]["invalid_evidence"] == 0


def test_task1_traversal_missing_or_invalid_policy_excludes_without_leaking():
    """Missing/invalid traversal policy excludes file candidates fail-closed with bounded safe reason codes."""
    target = "http://127.0.0.1:41000/"
    spec = _spec(target)
    records = [_make_record(f"{target}files/ghi/789?file=notes.txt")]

    # No profile_eligibility callback supplied -> fail closed as traversal_policy_not_declared.
    rows_no_cb = cand.parameter_candidates(spec, records, {}, profile_eligibility=None)
    trav_rows = [r for r in rows_no_cb if r.get("validation_profile") == "readonly_traversal_application_files"]
    assert len(trav_rows) == 1
    assert trav_rows[0]["eligible"] is False
    assert trav_rows[0]["reason_code"] == "traversal_policy_not_declared"

    # Malformed / cross-scope policy callback -> traversal_policy_invalid without leaking secret path or marker.
    rows_bad = cand.parameter_candidates(
        spec,
        records,
        {},
        profile_eligibility=lambda *_a: {"eligible": False, "reason_code": "traversal_policy_invalid"},
    )
    trav_bad = [r for r in rows_bad if r.get("validation_profile") == "readonly_traversal_application_files"][0]
    assert trav_bad["eligible"] is False
    assert trav_bad["reason_code"] == "traversal_policy_invalid"
    cards = cand.compact_cards(rows_bad)
    serialized = json.dumps(cards)
    assert "SECRET_MARKER" not in serialized
    assert "holdout-program-policy" not in serialized


def test_task1_funnel_denominators_and_distinct_outcomes():
    """Funnel exposes explicit denominators and non-overlapping outcome buckets while keeping historical fields."""
    rows = [
        {"observed": True, "eligible": False, "admitted": False, "executed": False, "evidence_accepted": False,
         "reason_code": "profile_not_applicable_to_surface"},
        {"observed": True, "eligible": True, "admitted": True, "executed": True, "evidence_accepted": True,
         "outcome": "negative_verified", "accepted_verdict": "UNCONFIRMED", "reason_code": ""},
        {"observed": True, "eligible": True, "admitted": True, "executed": True, "evidence_accepted": True,
         "outcome": "positive", "accepted_verdict": "CONFIRMED", "reason_code": ""},
        {"observed": True, "eligible": True, "admitted": False, "executed": False, "evidence_accepted": False,
         "reason_code": "deferred_budget"},
        {"observed": True, "eligible": True, "admitted": True, "executed": True, "evidence_accepted": False,
         "reason_code": "execution_failed"},
        {"observed": True, "eligible": True, "admitted": True, "executed": True, "evidence_accepted": False,
         "reason_code": "invalid_or_missing_signed_evidence"},
    ]
    report = cand.funnel(rows)
    assert report["observed"] == 6
    assert report["denominators"] == {
        "discovered_pairs": 6,
        "eligible_pairs": 5,
        "admitted_pairs": 4,
        "executed_pairs": 4,
        "evidence_accepted_executions": 2,
    }
    assert report["outcomes"] == {
        "ineligible": 1,
        "completed_negative": 1,
        "positive": 1,
        "budget_deferred": 1,
        "failed": 1,
        "invalid_evidence": 1,
        "pending": 0,
    }


@pytest.fixture
def trust_env(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "cco-home"))
    monkeypatch.delenv("CCO_PUBLIC_ONLY", raising=False)
    return tmp_path


def _sample_envelope(**overrides):
    rev = sc.compute_check_revision("scope-1", "policy-hash-1", "readonly_sqli_boolean", ["boolean_differential"])
    kwargs = {
        "run_id": "run-123",
        "target": "http://127.0.0.1:41000/",
        "profile": "readonly_sqli_boolean",
        "target_scope": "scope-1",
        "check_revision": rev,
        "required_checks": ["boolean_differential"],
        "completed_checks": ["boolean_differential"],
        "candidate_id": "cand-aaa",
        "url": "http://127.0.0.1:41000/lookup/abc?id=1",
        "param": "id",
        "method": "GET",
        "carrier": "query",
        "validation_ids": ["val-1"],
    }
    kwargs.update(overrides)
    return sc.build_signed_completion(**kwargs), rev


def test_task2_signed_completion_v1_verifies_and_fails_closed_on_every_mutation(trust_env, monkeypatch):
    """Valid signed_completion v1 verifies cleanly; every tamper/mismatch/version/contradiction fails closed."""
    env, rev = _sample_envelope()
    common_expected = {
        "expected_run_id": "run-123",
        "expected_candidate_id": "cand-aaa",
        "require_candidate_id": True,
        "expected_target": "http://127.0.0.1:41000/",
        "expected_url": "http://127.0.0.1:41000/lookup/abc?id=1",
        "expected_param": "id",
        "expected_method": "GET",
        "expected_carrier": "query",
        "expected_profile": "readonly_sqli_boolean",
        "expected_scope": "scope-1",
        "expected_check_revision": rev,
    }
    ok, payload, err = sc.verify_signed_completion(env, **common_expected)
    assert ok is True and payload is not None and err == ""
    assert payload["kind"] == "signed_completion" and payload["version"] == 1

    # Unsupported versions (int 2, str "1", 0) fail closed with unsupported_signed_completion_version.
    for bad_ver in (2, "1", 0, None):
        mutated = copy.deepcopy(env)
        mutated["version"] = bad_ver
        ok_v, _, err_v = sc.verify_signed_completion(mutated, **common_expected)
        assert ok_v is False and err_v == "unsupported_signed_completion_version"

    # Legacy empty dict / None -> invalid_or_missing_signed_evidence.
    for legacy in (None, {}, {"validations": []}):
        ok_l, _, err_l = sc.verify_signed_completion(legacy, **common_expected)
        assert ok_l is False and err_l == "invalid_or_missing_signed_evidence"

    # Tampered signature or payload field fails closed.
    tampered = copy.deepcopy(env)
    tampered["payload"]["run_id"] = "run-999"
    assert sc.verify_signed_completion(tampered, **common_expected)[0] is False

    unsigned = copy.deepcopy(env)
    unsigned.pop("signature", None)
    assert sc.verify_signed_completion(unsigned, **common_expected)[0] is False

    # Wrong run/target/profile/scope/check_revision/candidate replay all fail closed.
    assert sc.verify_signed_completion(env, **{**common_expected, "expected_run_id": "other-run"})[0] is False
    assert sc.verify_signed_completion(env, **{**common_expected, "expected_target": "http://127.0.0.1:49999/"})[0] is False
    assert sc.verify_signed_completion(env, **{**common_expected, "expected_profile": "readonly_ssti_arithmetic"})[0] is False
    assert sc.verify_signed_completion(env, **{**common_expected, "expected_scope": "scope-other"})[0] is False
    assert sc.verify_signed_completion(env, **{**common_expected, "expected_check_revision": "deadbeef"})[0] is False
    assert sc.verify_signed_completion(env, **{**common_expected, "expected_candidate_id": "cand-bbb"})[0] is False

    # Missing required candidate_id on candidate-less batch envelope rejected when require_candidate_id=True.
    batch_env, _ = _sample_envelope(candidate_id="")
    assert sc.verify_signed_completion(batch_env, **{**common_expected, "require_candidate_id": True})[0] is False

    # Contradictory positive finding NEVER overwritten by signed_completion.
    ok_c, _, err_c = sc.verify_signed_completion(env, **{**common_expected, "has_confirmed_finding": True})
    assert ok_c is False and err_c == "contradictory_positive_and_negative_evidence"

    # Oversized envelope (> 4096 bytes) rejected fail-closed.
    oversized = copy.deepcopy(env)
    oversized["padding"] = "x" * 5000
    assert sc.verify_signed_completion(oversized, **common_expected)[0] is False

    # Untrusted public-only boundary cannot forge a signed_completion envelope.
    monkeypatch.setattr(evidence_trust, "public_only", lambda: True)
    with pytest.raises(ValueError, match="trusted"):
        sc.build_signed_completion(
            run_id="run-123",
            target="http://127.0.0.1:41000/",
            profile="readonly_sqli_boolean",
            target_scope="scope-1",
            check_revision=rev,
            required_checks=["boolean_differential"],
            completed_checks=["boolean_differential"],
        )


def test_task2_partial_or_incomplete_checks_rejected_at_builder_and_verifier(trust_env):
    """Incomplete, non-clean, or non-zero-finding completions cannot produce/verify negative_verified."""
    rev = sc.compute_check_revision("scope-1", "policy-hash-1", "readonly_sqli_boolean", ["check_a", "check_b"])
    with pytest.raises(ValueError):
        sc.build_signed_completion(
            run_id="run-1",
            target="http://127.0.0.1:41000/",
            profile="readonly_sqli_boolean",
            target_scope="scope-1",
            check_revision=rev,
            required_checks=["check_a", "check_b"],
            completed_checks=["check_a"],
        )
    with pytest.raises(ValueError):
        sc.build_signed_completion(
            run_id="run-1",
            target="http://127.0.0.1:41000/",
            profile="readonly_sqli_boolean",
            target_scope="scope-1",
            check_revision=rev,
            required_checks=["check_a"],
            completed_checks=["check_a"],
            completion_status="deferred_budget",
        )
    with pytest.raises(ValueError):
        sc.build_signed_completion(
            run_id="run-1",
            target="http://127.0.0.1:41000/",
            profile="readonly_sqli_boolean",
            target_scope="scope-1",
            check_revision=rev,
            required_checks=["check_a"],
            completed_checks=["check_a"],
            findings_count=1,
        )


def test_task_registry_read_and_finalize_support_compacted_summaries_over_128kb(tmp_path):
    """Summaries exceeding 128 KiB (e.g. 80-candidate funnels in seal) load cleanly under bounded MAX_SUMMARY_BYTES."""
    import full_agent_launcher as launcher
    from full_agent_tasks import MAX_SUMMARY_BYTES, TaskRegistry

    base = "http://127.0.0.1:41000/"
    workdir = tmp_path / "solver"
    private = tmp_path / "private"
    workdir.mkdir()
    private.mkdir()
    specs = launcher.bootstrap_plan(base, workdir, solver_mode="python_loop")
    registry = TaskRegistry(specs, workdir, {}, setup_checks_passed=False)
    access_spec = specs[2]
    report_spec = specs[3]
    summary_path = registry.summary_path(access_spec)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    # Simulate an 80-candidate / ~180 KiB host-compiled access summary like readonly-path-traversal live run.
    filler_candidates = [
        {"candidate_id": f"cand-{i:03d}", "note": "x" * 2048}
        for i in range(90)
    ]
    payload = {
        "phase": access_spec.phase,
        "target": base,
        "status": "partial",
        "evidence": [],
        "findings": [],
        "next": "Broader coverage remains NOT TESTED.",
        "steps": [
            {"id": step.id, "status": "not_tested" if step.id == "broader-coverage" else "done"}
            for step in access_spec.steps
        ],
        "validation_funnel": {"candidates": filler_candidates},
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    assert 128 * 1024 < len(raw) < MAX_SUMMARY_BYTES
    summary_path.write_bytes(raw)

    loaded = registry.read_summary(access_spec)
    assert len(loaded["validation_funnel"]["candidates"]) == 90

    # finalize_active also preserves valid > 128 KiB terminal report summary without raising.
    report_path = registry.summary_path(report_spec)
    report_payload = {
        "phase": report_spec.phase,
        "target": base,
        "status": "partial",
        "evidence": [{"kind": "host_tool_result", "artifact": "context-archive/a.json"}],
        "findings": [],
        "next": "Broader coverage remains NOT TESTED.",
        "steps": [
            {"id": step.id, "status": "not_tested" if step.id == "unresolved-work" else "done"}
            for step in report_spec.steps
        ],
        "validation_funnels": {"access-3": {"candidates": filler_candidates}},
    }
    report_raw = json.dumps(report_payload, separators=(",", ":")).encode()
    assert 128 * 1024 < len(report_raw) < MAX_SUMMARY_BYTES
    report_path.write_bytes(report_raw)
    registry.active_spec = report_spec
    finalized = registry.finalize_active("test_stop", [], private)
    assert finalized["action"] == "terminal_summary_preserved"

    # Hard upper cap MAX_SUMMARY_BYTES is still enforced against unbounded inputs.
    oversized = tmp_path / "solver" / "summaries" / f"{access_spec.id}.json"
    oversized.write_bytes(b"{" + b" " * MAX_SUMMARY_BYTES + b"}")
    with pytest.raises(ValueError, match="native summary too large"):
        registry.read_summary(access_spec)
