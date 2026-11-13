"""Focused regressions for the scripted provider MCP catalog contract.

The native host advertises the full TaskSpec catalog in ordinary phases and
only the closing subset once RuntimePolicy genuinely finalizes a task. The
test harness must accept the closing subset only with the explicit host
finalization marker, and must reject any returned call that was not
advertised. These tests exercise the pure contract helpers; no native
process, provider call or target traffic is involved.
"""
from __future__ import annotations

import json

import pytest

from test_full_agent_integration import (
    assert_calls_advertised,
    tool_call,
    validate_worker_catalog,
)

EXPECTED = {
    "hunter_run_web_loop",
    "hunter_coverage_report",
    "validator_session_vault_check",
    "kali-tools_ledger_checkpoint",
    "kali-tools_curl_request",
}
FILE_TOOLS = {"read", "write", "edit", "bash"}
# RuntimePolicy closing contract for the access phase (no bash).
CLOSING_ACCESS = {
    "read",
    "write",
    "edit",
    "validator_session_vault_check",
    "hunter_coverage_report",
    "kali-tools_ledger_checkpoint",
}


def _body(*, finalizing=False, phase="access", disabled=()):
    info = {
        "phase": phase,
        "spec_id": "access-3",
        "finalizing": finalizing,
        "disabled_tools": sorted(disabled),
        "remaining_tool_calls": 4 if finalizing else 20,
    }
    instruction = (
        " FINALIZE NOW: save a terminal summary from existing evidence."
        if finalizing
        else " Complete Commands; save terminal summary/handoff before exhaustion; no recon in ledger."
    )
    return {
        "model": "worker",
        "messages": [
            {"role": "user", "content": "Tools: " + ", ".join(sorted(EXPECTED)) + "\nCommands: run"},
            {"role": "user", "content": "Host runtime allowance: " + json.dumps(info) + instruction},
        ],
    }


def test_ordinary_full_catalog_accepted():
    validate_worker_catalog(set(EXPECTED) | FILE_TOOLS, set(EXPECTED), _body())


def test_missing_catalog_ordinary_rejected():
    available = (set(EXPECTED) | FILE_TOOLS) - {"kali-tools_curl_request"}
    with pytest.raises(AssertionError, match="Native MCP catalog incomplete"):
        validate_worker_catalog(available, set(EXPECTED), _body())


def test_valid_closing_subset_accepted():
    validate_worker_catalog(set(CLOSING_ACCESS), set(EXPECTED), _body(finalizing=True))


def test_closing_subset_without_finalization_marker_rejected():
    with pytest.raises(AssertionError, match="Native MCP catalog incomplete"):
        validate_worker_catalog(set(CLOSING_ACCESS), set(EXPECTED), _body(finalizing=False))


@pytest.mark.parametrize("missing", ["flag", "marker"])
def test_closing_subset_requires_both_host_finalization_signals(missing):
    body = _body(finalizing=True)
    content = body["messages"][-1]["content"]
    if missing == "flag":
        content = content.replace('"finalizing": true', '"finalizing": false')
    else:
        content = content.replace("FINALIZE NOW", "continue")
    body["messages"][-1]["content"] = content
    with pytest.raises(AssertionError, match="Native MCP catalog incomplete"):
        validate_worker_catalog(set(CLOSING_ACCESS), set(EXPECTED), body)


def test_report_closing_catalog_preserves_disabled_tool_and_shell_contract():
    body = _body(finalizing=True, phase="report", disabled={"edit"})
    available = (set(CLOSING_ACCESS) | {"bash"}) - {"edit"}
    validate_worker_catalog(available, set(EXPECTED), body)
    with pytest.raises(AssertionError, match="Closing catalog mismatch"):
        validate_worker_catalog(available | {"edit"}, set(EXPECTED), body)


def test_prior_hash_collection_ignores_empty_lock_but_rejects_empty_artifact(tmp_path):
    from fixtures.holdout_references import collect_prior_hashes

    root = tmp_path / "run"
    (root / "solver").mkdir(parents=True)
    (root / "private/evaluator").mkdir(parents=True)
    (root / "private/state/validations").mkdir(parents=True)
    (root / "private/evaluator/metrics.json").write_text("{}")
    (root / "solver/closure.json").write_text("{}")
    (root / "solver/attempts.jsonl").write_text("{}\n")
    (root / "solver/attempts.jsonl.lock").write_bytes(b"")
    prior, hashes = collect_prior_hashes((root,), digest_fn=lambda path: "digest")
    assert all(not str(path).endswith(".lock") for path in prior)
    assert str(root / "solver/attempts.jsonl") in hashes
    (root / "solver/closure.json").write_bytes(b"")
    with pytest.raises(ValueError, match="non-empty"):
        collect_prior_hashes((root,), digest_fn=lambda path: "digest")


def test_disallowed_call_during_closure_rejected():
    body = _body(finalizing=True)
    # A non-closing probe must never be advertised during closure.
    with pytest.raises(AssertionError, match="closing"):
        validate_worker_catalog(set(CLOSING_ACCESS) | {"hunter_run_web_loop"}, set(EXPECTED), body)
    # A returned call that was not advertised must fail even in closure.
    calls = [tool_call("it-x", "hunter_run_web_loop", {"target": "http://127.0.0.1:1/"})]
    with pytest.raises(AssertionError, match="not advertised"):
        assert_calls_advertised(calls, set(CLOSING_ACCESS))
    # An advertised closing write is accepted.
    assert_calls_advertised(
        [tool_call("it-y", "write", {"filePath": "/tmp/x.json", "content": "{}"})],
        set(CLOSING_ACCESS),
    )
