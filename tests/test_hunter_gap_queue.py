"""Durable gap plans retain coverage dimensions without credentials."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-hunter"))
from cco_hunter_core.gap_queue import plan_gaps, list_gaps  # noqa: E402


class Scope:
    def permits_url(self, url):
        return url.startswith(("https://owned.test/allowed/", "https://owned.test:444/allowed/"))


def test_gap_plans_preserve_dimensions_deduplicate_and_hide_values(tmp_path):
    db = str(tmp_path / "queue.db")
    base = {"endpoint": "https://owned.test/allowed/a?q=synthetic-secret", "method": "GET",
            "vuln_class": "bola", "param": "q", "carrier": "query", "run_id": "run-1",
            "identity": "member-b", "resource_owner": "member-a"}
    gaps = [base, {**base, "identity": "member-c"},
            {**base, "endpoint": "https://owned.test/allowed/a?q=other-object"},
            {**base, "endpoint": "https://owned.test:444/allowed/a"},
            {**base, "endpoint": "https://other.test/allowed/a"},
            {**base, "endpoint": "https://owned.test/outside"}, {**base, "method": "POST"}]
    first, admitted = plan_gaps(db, "https://owned.test", gaps, Scope(), "context-a")
    assert len(first) == len(admitted) == 3
    assert {plan["identity"] for plan in first} == {"member-b", "member-c"}
    assert "synthetic-secret" not in str(first)
    assert all(plan["preconditions"] == ["fresh_scope_and_grant", "request_context", "campaign_budget"]
               for plan in first)
    plan_gaps(db, "https://owned.test", gaps, Scope(), "context-a")
    assert len(list_gaps(db, "https://owned.test", "context-a")) == 3
    assert list_gaps(db, "https://owned.test", "context-b") == []
