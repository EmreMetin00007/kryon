"""Faz 6: graf zamansalligi (valid_to/supersede) + kapili ogrenme (provenance)."""
import json

from conftest import load_server


def _kg(tmp_path):
    mem = load_server("memory-server")
    return mem.KnowledgeGraph(str(tmp_path / "agent_memory.db"))


def test_node_properties_merge_and_stamps(tmp_path):
    kg = _kg(tmp_path)
    kg.add_node("credential:1", "credential", "c1", {"service": "ssh"})
    kg.add_node("credential:1", "credential", "c1", {"user": "root"})
    props = kg._node_props("credential:1")
    assert props["service"] == "ssh" and props["user"] == "root"
    assert props["valid_from"] and props["updated_at"]


def test_superseded_node_hidden_from_neighbors(tmp_path):
    kg = _kg(tmp_path)
    kg.add_node("target:t", "target")
    kg.add_node("credential:old", "credential")
    kg.add_edge("target:t", "credential:old", "CONNECTED_TO")
    assert len(kg.query_neighbors("target:t", "out")["outgoing"]) == 1
    kg.supersede_node("credential:old", superseded_by="credential:new")
    assert kg.query_neighbors("target:t", "out")["outgoing"] == []
    assert len(kg.query_neighbors("target:t", "out", include_expired=True)["outgoing"]) == 1
    assert kg._node_props("credential:old")["superseded_by"] == "credential:new"


def test_lesson_provenance_gate():
    reasoning = load_server("reasoning")
    out = json.loads(reasoning.record_lesson(
        "lab ctx", "sql_injection", "dene", "calisti", True))
    assert out["provenance"] == "unverified"
    assert "warning" in out
    out2 = json.loads(reasoning.record_lesson(
        "lab ctx", "sql_injection", "dene2", "validator onayli", True,
        validation_id="abc123"))
    assert out2["provenance"] == "validator:abc123"
    stats = json.loads(reasoning.lesson_stats())
    assert stats["verified_lessons"] >= 1 and stats["unverified_lessons"] >= 1
    verified = json.loads(reasoning.recall_lessons(
        context="lab", technique="sql_injection", verified_only=True))
    assert verified["lessons"]
    assert all(l["provenance"].startswith("validator:") for l in verified["lessons"])
