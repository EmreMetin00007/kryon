"""Sprint C Slice 1 tests: discovery, profiles, and applicability gating for XSS & Open Redirect."""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

import brain
import hypothesis_ledger
import python_candidate_runtime as cand
from full_agent_launcher import lab_policy
from full_agent_provider import dump
from policy_engine import PolicyEngine
from test_full_agent_python_solver import python_broker


def _make_record(url: str, *, method: str = "GET", params: list | None = None, source_artifact: str = "/tmp/disc.json") -> dict:
    sha = hashlib.sha256(f"{method}:{url}".encode()).hexdigest()
    rec: dict = {
        "url": url,
        "method": method,
        "source_spec_id": "enum-2",
        "source_artifact": source_artifact,
        "source_sha256": sha,
    }
    if params is not None:
        rec["params"] = params
    return rec


def _spec(target: str = "http://127.0.0.1:41000/", vector: str = "access") -> SimpleNamespace:
    return SimpleNamespace(
        id="access-3",
        target=target,
        vector=vector,
        tools={
            "hunter_run_web_loop",
            "validator_validate_sqli",
            "validator_validate_ssti",
            "validator_validate_path_traversal",
            "validator_validate_xss_reflection",
            "validator_validate_open_redirect",
        },
    )


def test_sprint_c_profiles_and_oracle_contracts():
    assert cand.PROFILES["readonly_xss_reflection"] == (
        "xss-stored",
        "validator_validate_xss_reflection",
        "browser_execution",
    )
    assert cand.PROFILES["readonly_open_redirect"] == (
        "authn-session",
        "validator_validate_open_redirect",
        "redirect_location",
    )
    # Confirmed XSS strictly requires browser_execution; negative/inconclusive may report unescaped_reflection.
    assert cand.profile_oracles("readonly_xss_reflection", "CONFIRMED") == frozenset({"browser_execution"})
    assert cand.profile_oracles("readonly_xss_reflection", "UNCONFIRMED") == frozenset({
        "browser_execution",
        "unescaped_reflection",
    })
    assert cand.profile_oracles("readonly_open_redirect", "CONFIRMED") == frozenset({"redirect_location"})
    assert cand.profile_oracles("readonly_open_redirect", "UNCONFIRMED") == frozenset({"redirect_location"})


def test_sprint_c_surface_applicability_admits_xss_and_redirect_without_cross_firing():
    target = "http://127.0.0.1:41000/"
    spec = _spec(target)
    records = [
        _make_record(f"{target}xss/cat1/item1?q=hello"),
        _make_record(f"{target}reflect/cat1/item2?comment=greeting"),
        _make_record(f"{target}go/cat2/item3?next=/home"),
        _make_record(f"{target}redirect/cat2/item4?url=/dashboard"),
        _make_record(f"{target}lookup/cat3/item5?id=1"),
        _make_record(f"{target}templates/cat4/item6?name=World"),
        _make_record(f"{target}files/cat5/item7?file=notes.txt"),
    ]
    eligibility = lambda _s, url, param, _c, profile, **_kw: (
        {"eligible": True, "reason_code": ""}
        if (
            (profile == "readonly_traversal_application_files" and "/files/" in url and param == "file")
            or profile in {"readonly_xss_reflection", "readonly_open_redirect", "readonly_sqli_boolean", "readonly_ssti_arithmetic"}
        )
        else {"eligible": False, "reason_code": "traversal_policy_not_declared"}
    )
    rows = cand.parameter_candidates(spec, records, {}, profile_eligibility=eligibility)
    by_pair = {(urlsplit(r["route"]).path, r["param"], r.get("validation_profile")): r for r in rows}

    # XSS surfaces: only readonly_xss_reflection is eligible; SQLi/SSTI are ineligible; traversal/redirect suppressed.
    for path, param in (("/xss/cat1/item1", "q"), ("/reflect/cat1/item2", "comment")):
        xss_row = by_pair[(path, param, "readonly_xss_reflection")]
        assert xss_row["eligible"] is True and xss_row["reason_code"] == ""
        assert xss_row["vector"] == "xss-stored"
        assert xss_row["tool"] == "validator_validate_xss_reflection"
        assert by_pair[(path, param, "readonly_sqli_boolean")]["eligible"] is False
        assert by_pair[(path, param, "readonly_sqli_boolean")]["reason_code"] == "profile_not_applicable_to_surface"
        assert by_pair[(path, param, "readonly_ssti_arithmetic")]["eligible"] is False
        assert by_pair[(path, param, "readonly_ssti_arithmetic")]["reason_code"] == "profile_not_applicable_to_surface"
        assert (path, param, "readonly_traversal_application_files") not in by_pair
        assert (path, param, "readonly_open_redirect") not in by_pair

    # Open Redirect surfaces: only readonly_open_redirect is eligible; SQLi/SSTI are ineligible; traversal/xss suppressed.
    for path, param in (("/go/cat2/item3", "next"), ("/redirect/cat2/item4", "url")):
        redir_row = by_pair[(path, param, "readonly_open_redirect")]
        assert redir_row["eligible"] is True and redir_row["reason_code"] == ""
        assert redir_row["vector"] == "authn-session"
        assert redir_row["tool"] == "validator_validate_open_redirect"
        assert by_pair[(path, param, "readonly_sqli_boolean")]["eligible"] is False
        assert by_pair[(path, param, "readonly_sqli_boolean")]["reason_code"] == "profile_not_applicable_to_surface"
        assert by_pair[(path, param, "readonly_ssti_arithmetic")]["eligible"] is False
        assert by_pair[(path, param, "readonly_ssti_arithmetic")]["reason_code"] == "profile_not_applicable_to_surface"
        assert (path, param, "readonly_traversal_application_files") not in by_pair
        assert (path, param, "readonly_xss_reflection") not in by_pair

    # SQLi, SSTI, and Traversal surfaces do not materialize XSS or Open Redirect candidates.
    for path, param in (
        ("/lookup/cat3/item5", "id"),
        ("/templates/cat4/item6", "name"),
        ("/files/cat5/item7", "file"),
    ):
        assert (path, param, "readonly_xss_reflection") not in by_pair
        assert (path, param, "readonly_open_redirect") not in by_pair

    f = cand.funnel(rows)
    # 7 routes, each with exactly 1 eligible profile = 7 eligible pairs.
    assert f["denominators"]["eligible_pairs"] == 7
    assert f["outcomes"]["invalid_evidence"] == 0


def test_sprint_c_broker_profile_eligibility_for_xss_and_open_redirect(python_broker, tmp_path, monkeypatch):
    target = "http://127.0.0.1:41000/"
    spec = _spec(target)
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    scope, policy = lab_policy(target)
    dump(scope_dir / "scope.json", scope)
    dump(scope_dir / "program-policy.json", policy)
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope_dir / "scope.json"))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(scope_dir / "program-policy.json"))
    (python_broker.private / "state/permissions.json").write_text("{}", encoding="utf-8")

    def reload_engine(custom_policy: dict):
        dump(scope_dir / "program-policy.json", custom_policy)
        python_broker.engine = PolicyEngine(
            cco_home=str(python_broker.private / "state"),
            scope_file=str(scope_dir / "scope.json"),
            program_policy_file=str(scope_dir / "program-policy.json"),
        )

    reload_engine(policy)
    xss_url = f"{target}xss/1?q=hello"
    redir_url = f"{target}go/1?next=/home"

    # Standard lab_policy enables xss_execution and allows in-scope GET query open_redirect.
    assert python_broker.profile_eligibility(spec, xss_url, "q", "query", "readonly_xss_reflection") == {
        "eligible": True,
        "reason_code": "",
    }
    assert python_broker.profile_eligibility(spec, redir_url, "next", "query", "readonly_open_redirect") == {
        "eligible": True,
        "reason_code": "",
    }

    # Cross-origin and non-query carriers are rejected fail-closed.
    assert python_broker.profile_eligibility(
        spec, "http://127.0.0.1:49999/xss/1?q=hello", "q", "query", "readonly_xss_reflection"
    ) == {"eligible": False, "reason_code": "xss_policy_invalid"}
    assert python_broker.profile_eligibility(
        spec, "http://127.0.0.1:49999/go/1?next=/home", "next", "query", "readonly_open_redirect"
    ) == {"eligible": False, "reason_code": "redirect_policy_invalid"}
    assert python_broker.profile_eligibility(
        spec, xss_url, "q", "cookie", "readonly_xss_reflection"
    ) == {"eligible": False, "reason_code": "unsupported_parameter_carrier"}
    assert python_broker.profile_eligibility(
        spec, redir_url, "next", "header", "readonly_open_redirect"
    ) == {"eligible": False, "reason_code": "unsupported_parameter_carrier"}
    assert python_broker.profile_eligibility(
        spec, xss_url, "q", "form", "readonly_xss_reflection", method="POST"
    ) == {"eligible": False, "reason_code": "unsupported_readonly_method"}
    assert python_broker.profile_eligibility(
        spec, redir_url, "next", "form", "readonly_open_redirect", method="POST"
    ) == {"eligible": False, "reason_code": "unsupported_readonly_method"}

    # Disabling xss_execution or setting invalid bounds excludes readonly_xss_reflection fail-closed.
    disabled_policy = {**policy, "xss_execution": {"enabled": False}}
    reload_engine(disabled_policy)
    assert python_broker.profile_eligibility(spec, xss_url, "q", "query", "readonly_xss_reflection") == {
        "eligible": False,
        "reason_code": "xss_execution_disabled",
    }
    rows_disabled = cand.parameter_candidates(
        spec, [_make_record(xss_url)], {}, profile_eligibility=python_broker.profile_eligibility
    )
    xss_cand = next(r for r in rows_disabled if r.get("validation_profile") == "readonly_xss_reflection")
    assert xss_cand["eligible"] is False
    assert xss_cand["reason_code"] == "xss_execution_disabled"

    invalid_bounds = {**policy, "xss_execution": {"enabled": True, "max_browser_requests": 99, "wait_ms": 0}}
    reload_engine(invalid_bounds)
    assert python_broker.profile_eligibility(spec, xss_url, "q", "query", "readonly_xss_reflection") == {
        "eligible": False,
        "reason_code": "xss_policy_invalid",
    }


def test_sprint_c_brain_and_hypothesis_ledger_vector_alignment():
    assert brain._VALIDATOR_VECTOR_TYPES["xss-stored"] == "xss"
    assert "xss_reflected" in brain._VALIDATOR_VECTOR_ALIASES["xss-stored"]
    assert "open_redirect" in brain._VALIDATOR_VECTOR_ALIASES["authn-session"]

    authn_tpl = brain.broker_vector_template("authn-session")
    xss_tpl = brain.broker_vector_template("xss-stored")
    assert "validator_validate_open_redirect" in authn_tpl["tools"]
    assert "validator_validate_xss_reflection" in xss_tpl["tools"]

    scores = hypothesis_ledger.score_vectors(["/xss/reflect", "/go/redirect"], ["next=1", "preview"])
    assert scores["xss-stored"] > 0
    assert scores["authn-session"] > 0
