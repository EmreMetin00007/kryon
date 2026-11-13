"""Replanning must distinguish blocked work from completed coverage."""
import json
import sys
from pathlib import Path

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-hunter"))
from cco_hunter_core.replan import replan_web_report  # noqa: E402


def test_session_and_rate_limit_stop_automatic_retry():
    report = {"mode": "LIVE", "ok": False, "run_id": "run-1",
              "fuzz": {"stopped": "session unavailable or login redirect"},
              "errors": ["HTTP 429 rate limited"]}
    result = replan_web_report(report)
    assert result["status"] == "blocked" and result["automatic_retry"] is False
    assert [action["category"] for action in result["actions"]] == ["rate_limit", "session"]
    assert result["run_id"] == "run-1"


def test_schema_identity_and_policy_have_distinct_actions():
    report = {"mode": "LIVE", "ok": False,
              "errors": ["invalid schema", "policy gate denied"],
              "skipped": [{"reason": "requires two test identities and owned object"}]}
    result = replan_web_report(report)
    assert {a["category"] for a in result["actions"]} == {"schema", "policy", "identity"}
    assert result["status"] == "blocked"


def test_skipped_or_empty_surface_is_not_a_clean_result():
    report = {"mode": "LIVE", "ok": True,
              "skipped": [{"reason": "yuzey kuyrugu bos (0 probe)"},
                          {"reason": "browser request-level policy unavailable"}]}
    result = replan_web_report(report)
    assert result["status"] == "incomplete"
    assert {a["category"] for a in result["actions"]} == {"surface", "unavailable"}


def test_hunter_plan_exposes_read_only_replan_metadata():
    hunter = load_server("hunter")
    result = json.loads(hunter.run_web_loop("https://owned.test", live=False))
    assert result["replan"] == {"status": "planned", "automatic_retry": False, "actions": []}
