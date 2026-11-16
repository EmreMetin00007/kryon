"""Tests for private DiscoveryState, semantic frontier projection, and enum hydration."""
from __future__ import annotations

import copy
import json
from urllib.parse import urlsplit

import pytest

from full_agent_budget import provider_json
from full_agent_python_broker import CRAWL_TOOL, READ_TOOL
from full_agent_python_solver import PythonSolver, WorkflowError
from python_discovery_runtime import (
    ACTION_STATUSES,
    FRONTIER_SCHEMA,
    SCHEMA,
    DiscoveryState,
    compact_frontier,
    discovery_state_key,
    project_discovery_frontier,
    stable_action_id,
)
from python_identity_discovery import public_export
from test_full_agent_python_solver import python_broker, terminal


def _prov(spec_id="recon-1", artifact="context-archive/tool-result-a.json", sha="a" * 64, tool="kali-tools_curl_request"):
    return {"source_spec_id": spec_id, "source_artifact": artifact, "source_sha256": sha, "tool": tool}


def test_discovery_state_schema_provenance_transitions_and_redaction():
    target = "http://127.0.0.1:18765/"
    state = DiscoveryState(task_spec_id="enum-2", target=target, identity_ref="member-a")
    assert state.schema == SCHEMA
    assert state.key == discovery_state_key("enum-2", target, "member-a")
    assert state.key != discovery_state_key("enum-2", target, "anon")
    assert discovery_state_key("enum-2", target, "anonymous") == discovery_state_key("enum-2", target, "anon")

    with pytest.raises(ValueError, match="missing_or_invalid_discovery_provenance"):
        state.record_action(url=target, provenance={"source_spec_id": "recon-1", "source_artifact": "x", "source_sha256": "bad"})

    root = state.record_action(
        url=target,
        method="GET",
        link_relation="entry",
        provenance=_prov(),
        status="completed",
        http_status=200,
    )
    child_url = target + "objects/alice-secret-42?token=synthetic-secret-canary&page=2#frag"
    child = state.record_action(
        url=child_url,
        method="GET",
        link_relation="discovered_link",
        parent_action_id=root["action_id"],
        provenance=_prov(),
        status="pending",
    )
    assert child["action_id"] == stable_action_id(
        "enum-2",
        target,
        "member-a",
        method="GET",
        url=child_url,
        kind="http_request",
        param_names=["token", "page"],
    )
    assert child["parent_action_id"] == root["action_id"]
    assert child["continuation_depth"] == 1
    assert state.actions[root["action_id"]]["child_action_ids"] == [child["action_id"]]

    # Re-observing the same URL as a pending link must not regress a completed/dispatched status.
    state.mark_dispatched(child["action_id"])
    state.record_action(url=child_url, method="GET", link_relation="crawl_link", provenance=_prov(sha="b" * 64), status="pending")
    assert state.actions[child["action_id"]]["status"] == "dispatched"
    assert state.actions[child["action_id"]]["link_relations"] == ["discovered_link", "crawl_link"]

    state.mark_completed(child["action_id"], http_status=200)
    assert state.counts() == {
        "total": 2,
        **{status: 0 for status in ACTION_STATUSES},
        "completed": 2,
    }

    blocked_url = target + "admin?debug=canary-admin-val"
    blocked = state.record_action(url=blocked_url, provenance=_prov(), status="pending")
    state.mark_blocked(blocked["action_id"], reason_code="http_403", http_status=403)

    indet_url = target + "slow?probe=canary-slow-val"
    indet = state.record_action(url=indet_url, provenance=_prov(), status="dispatched")
    assert state.mark_interrupted_dispatched_indeterminate() == 1
    assert state.actions[indet["action_id"]]["status"] == "indeterminate"

    projection = state.public_projection()
    assert projection["schema"] == FRONTIER_SCHEMA
    assert projection["counts"]["completed"] == 2
    assert projection["counts"]["blocked"] == 1
    assert projection["counts"]["indeterminate"] == 1
    raw_proj = json.dumps(projection)
    for forbidden in ("synthetic-secret-canary", "alice-secret-42", "canary-admin-val", "canary-slow-val", "#frag"):
        assert forbidden not in raw_proj
    assert public_export(projection) == projection

    child_card = next(item for item in projection["frontier"] if item["action_id"] == child["action_id"])
    assert child_card["route_shape"] == target + "objects/{value}"
    assert not urlsplit(child_card["route_shape"]).query
    assert child_card["param_names"] == ["token", "page"]
    assert child_card["link_relation"] == "discovered_link"
    assert child_card["parent_action_id"] == root["action_id"]

    # Private state resolves exact operational URL; redacted card never suffices.
    resolved = state.resolve_action(child["action_id"])
    assert resolved is not None and resolved["url"] == child_url
    assert state.resolve_action("0" * 64) is None


def test_discovery_frontier_bounds_and_compact_frontier():
    target = "http://127.0.0.1:18765/"
    anon = DiscoveryState(task_spec_id="enum-2", target=target, identity_ref="anon")
    member = DiscoveryState(task_spec_id="enum-2", target=target, identity_ref="member-a")
    for idx in range(15):
        anon.record_action(
            url=f"{target}api/items/{idx}?q=secret-{idx}",
            provenance=_prov(),
            status="pending",
        )
    member.record_action(url=f"{target}api/profile?tab=secret-tab", provenance=_prov(), status="indeterminate", reason_code="timeout")
    frontier = project_discovery_frontier([anon, member], task_spec_id="enum-2", target=target)
    assert frontier["counts"]["total"] == 16
    assert frontier["counts"]["pending"] == 15
    assert frontier["counts"]["indeterminate"] == 1
    assert frontier["truncated"] is True
    assert len(frontier["frontier"]) <= 12
    assert "secret-" not in json.dumps(frontier)
    compacted = compact_frontier(frontier)
    assert compacted is not None
    assert len(compacted["frontier"]) <= 4
    assert compacted["counts"] == frontier["counts"]
    assert compacted["truncated"] is True


def test_enum_hydrates_actionable_frontier_from_recon_and_current_receipts_without_read_artifact(python_broker):
    solver = PythonSolver(python_broker, model="model")
    recon, enum_spec = python_broker.tasks.specs[0], python_broker.tasks.specs[1]

    # Recon fetches entry point and receives HTML links + query params + POST form.
    recon_html = (
        '<a href="/api/items/99?search=canary-query-val&sort=desc">Items</a>'
        '<form action="/api/notes" method="POST"><input name="body" value="secret-default"></form>'
    )
    recon_view = python_broker.view({"status_code": 200, "text": recon_html})
    python_broker.results.append({
        "spec_id": recon.id,
        "tool": "kali-tools_curl_request",
        "arguments": {"url": recon.target, "follow_redirects": False},
        **recon_view,
    })
    recon_summary = solver.compile_summary(recon, terminal(recon))
    solver.summaries[recon.id] = recon_summary

    # Hydrate enum context without calling read_artifact on recon summary or discovery archive.
    context = solver.context(enum_spec)
    assert not any(row["tool"] == READ_TOOL for row in python_broker.results)
    frontier = context["discovery_frontier"]
    assert frontier["schema"] == FRONTIER_SCHEMA
    assert frontier["task_spec_id"] == enum_spec.id
    assert frontier["counts"] == {
        "total": 3,
        "pending": 1,
        "dispatched": 0,
        "completed": 1,
        "blocked": 1,
        "indeterminate": 0,
    }
    raw_context = json.dumps(context["discovery_frontier"])
    assert "canary-query-val" not in raw_context
    assert "secret-default" not in raw_context
    assert "/99" not in raw_context

    pending_item = next(item for item in frontier["frontier"] if item["status"] == "pending")
    assert pending_item["route_shape"] == enum_spec.target + "api/items/{value}"
    assert pending_item["param_names"] == ["search", "sort"]
    assert pending_item["link_relation"] == "discovered_link"
    entry_item = next(item for item in frontier["frontier"] if item["status"] == "completed")
    assert pending_item["parent_action_id"] == entry_item["action_id"]

    # Current enum receipt updates pending -> completed and adds newly discovered child links.
    next_html = '<a href="/api/orders?filter=canary-order">Orders</a>'
    enum_view = python_broker.view({"status_code": 200, "text": next_html})
    python_broker.results.append({
        "spec_id": enum_spec.id,
        "tool": "kali-tools_curl_request",
        "arguments": {"url": enum_spec.target + "api/items/99?search=canary-query-val&sort=desc"},
        **enum_view,
    })
    updated = solver.context(enum_spec)["discovery_frontier"]
    assert updated["counts"]["completed"] == 2
    assert updated["counts"]["pending"] == 1
    new_pending = next(item for item in updated["frontier"] if item["status"] == "pending")
    assert new_pending["route_shape"] == enum_spec.target + "api/orders"
    assert new_pending["param_names"] == ["filter"]
    assert new_pending["parent_action_id"] == pending_item["action_id"]
    assert "canary-order" not in json.dumps(updated)


def test_discovery_state_checkpoint_persistence_interruption_and_tamper_rejection(python_broker):
    solver = PythonSolver(python_broker, model="model")
    recon, enum_spec = python_broker.tasks.specs[0], python_broker.tasks.specs[1]
    recon_view = python_broker.view({"status_code": 200, "text": '<a href="/search?q=canary-val">Search</a>'})
    python_broker.results.append({
        "spec_id": recon.id,
        "tool": "kali-tools_curl_request",
        "arguments": {"url": recon.target},
        **recon_view,
    })
    recon_summary = solver.compile_summary(recon, terminal(recon))
    solver.summaries[recon.id] = recon_summary
    recon_path = python_broker.tasks.summary_path(recon)
    recon_path.parent.mkdir(parents=True, exist_ok=True)
    recon_path.write_bytes(provider_json(recon_summary))
    frontier = solver.context(enum_spec)["discovery_frontier"]
    pending_id = next(item["action_id"] for item in frontier["frontier"] if item["status"] == "pending")

    # Mark action dispatched on running enum task and save private checkpoint.
    state_obj = next(iter(solver.task_discovery_states(enum_spec).values()))
    state_obj.mark_dispatched(pending_id)
    solver.task_states[enum_spec.id] = "running"
    solver._checkpoint_active = True
    solver.checkpoint.acquire()
    solver.save_checkpoint()
    solver.checkpoint.release()

    # Private discovery states must never be written into model-readable archives.
    for ref_path in python_broker.references:
        assert "python-discovery-state/1" not in (python_broker.workdir / ref_path).read_text()

    # Restore on fresh solver: interrupted running task transitions dispatched -> indeterminate.
    restored = PythonSolver(python_broker, model="model", resume=True)
    restored.restore_checkpoint()
    restored_state = next(iter(restored.task_discovery_states(enum_spec).values()))
    assert restored_state.actions[pending_id]["status"] == "indeterminate"
    assert restored_state.actions[pending_id]["reason_code"] == "interrupted_dispatch"
    assert restored_state.resolve_action(pending_id)["url"] == enum_spec.target + "search?q=canary-val"

    # Tampering with verified source artifact fails closed on context hydration / restore.
    (python_broker.workdir / recon_view["content_ref"]["path"]).write_text("{}")
    with pytest.raises(WorkflowError, match="prior phase evidence changed"):
        restored.context(enum_spec)
    with pytest.raises(ValueError, match="checkpoint evidence integrity mismatch|prior phase evidence changed"):
        restored_tampered = PythonSolver(copy.copy(python_broker), model="model", resume=True)
        restored_tampered.restore_checkpoint()


def test_tampered_recon_summary_cannot_hydrate_enum_discovery_state(python_broker):
    solver = PythonSolver(python_broker, model="model")
    recon, enum_spec = python_broker.tasks.specs[0], python_broker.tasks.specs[1]
    view = python_broker.view({"status_code": 200, "text": '<a href="/search?q=1">Search</a>'})
    python_broker.results.append({
        "spec_id": recon.id,
        "tool": CRAWL_TOOL,
        "arguments": {"target": recon.target},
        **view,
    })
    solver.summaries[recon.id] = {**solver.compile_summary(recon, terminal(recon)), "status": "unknown"}
    with pytest.raises(WorkflowError, match="prior phase summary invalid"):
        solver.context(enum_spec)
