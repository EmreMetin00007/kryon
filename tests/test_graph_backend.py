"""
KuzuDB Graph Backend Testleri
==============================
graph_backend.KuzuGraph'ın KnowledgeGraph (NetworkX) ile API uyumluluğunu
ve Cypher'a özgü davranışları doğrular. Tamamen offline çalışır.

Çalıştırma:
    pytest tests/test_graph_backend.py -q
"""
import importlib.util
import os

import pytest

BACKEND_PATH = os.path.join(
    os.path.dirname(__file__), "..", "mcp-servers", "mcp-memory-server",
    "graph_backend.py"
)
SPEC = importlib.util.spec_from_file_location("test_memory_graph_backend", BACKEND_PATH)
BACKEND = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BACKEND)
KuzuGraph = BACKEND.KuzuGraph
HAS_KUZU = BACKEND.HAS_KUZU

pytestmark = pytest.mark.skipif(not HAS_KUZU, reason="kuzu kurulu değil")


@pytest.fixture()
def kg(tmp_path):
    """Her test için izole KuzuDB instance'ı."""
    return KuzuGraph(str(tmp_path / "graph.kuzu"))


# ---------------------------------------------------------------
# Temel yazma/okuma
# ---------------------------------------------------------------

class TestBasicOps:
    def test_add_node(self, kg):
        kg.add_node("target:example.com", "target", "example.com")
        assert kg._node_exists("target:example.com")
        assert kg.get_node_type("target:example.com") == "target"

    def test_add_edge_auto_creates_nodes(self, kg):
        kg.add_edge("target:a.com", "service:a.com:80", "HAS_PORT", confidence=1.0)
        assert kg._node_exists("target:a.com")
        assert kg._node_exists("service:a.com:80")

    def test_query_neighbors_out(self, kg):
        kg.add_edge("a", "b", "RUNS", confidence=0.9)
        result = kg.query_neighbors("a", "out")
        assert len(result["outgoing"]) == 1
        assert result["outgoing"][0]["target"] == "b"
        assert result["outgoing"][0]["relationship"] == "RUNS"
        assert result["outgoing"][0]["confidence"] == pytest.approx(0.9)

    def test_query_neighbors_in(self, kg):
        kg.add_edge("a", "b", "RUNS")
        result = kg.query_neighbors("b", "in")
        assert len(result["incoming"]) == 1
        assert result["incoming"][0]["source"] == "a"

    def test_node_properties_roundtrip(self, kg):
        kg.add_node("cve:CVE-2024-1", "cve", "CVE-2024-1", {"cvss": 9.8})
        kg.add_edge("s", "cve:CVE-2024-1", "VULNERABLE_TO", {"verified": True})
        result = kg.query_neighbors("s", "out")
        assert result["outgoing"][0].get("verified") is True

    def test_add_edge_is_idempotent_and_updates(self, kg):
        first_id = kg.add_edge("a", "b", "RUNS", confidence=0.1)
        second_id = kg.add_edge("a", "b", "GRANTS", confidence=0.9)
        result = kg.query_neighbors("a", "out")
        assert first_id == second_id
        assert len(result["outgoing"]) == 1
        assert result["outgoing"][0]["relationship"] == "GRANTS"
        assert result["outgoing"][0]["confidence"] == pytest.approx(0.9)

    def test_edge_id_is_process_stable(self):
        assert KuzuGraph._stable_edge_id("a", "b") == KuzuGraph._stable_edge_id("a", "b")
        assert KuzuGraph._stable_edge_id("a", "b") != KuzuGraph._stable_edge_id("b", "a")


# ---------------------------------------------------------------
# Path sorguları (KuzuDB'nin asıl gücü)
# ---------------------------------------------------------------

class TestPaths:
    def _build_chain(self, kg):
        # target -> HAS_PORT -> service -> GRANTS -> privilege
        kg.add_edge("target:t", "service:t:ssh", "HAS_PORT", confidence=1.0)
        kg.add_edge("service:t:ssh", "privilege:root", "GRANTS", confidence=0.9)

    def test_shortest_path(self, kg):
        self._build_chain(kg)
        path = kg.find_shortest_path("target:t", "privilege:root")
        assert path == ["target:t", "service:t:ssh", "privilege:root"]

    def test_all_paths(self, kg):
        self._build_chain(kg)
        # İkinci yol: target -> endpoint -> service
        kg.add_edge("target:t", "endpoint:t:22", "HAS_PORT", confidence=1.0)
        kg.add_edge("endpoint:t:22", "service:t:ssh", "CONNECTED_TO", confidence=0.8)
        paths = kg.find_all_paths("target:t", "privilege:root", max_hops=4)
        assert len(paths) >= 2
        assert all(p[0] == "target:t" and p[-1] == "privilege:root" for p in paths)

    def test_no_path_returns_empty(self, kg):
        kg.add_node("a", "target")
        kg.add_node("b", "target")
        assert kg.find_all_paths("a", "b") == []

    def test_max_hops_respected(self, kg):
        # 4 hop'luk zincir
        for i in range(4):
            kg.add_edge(f"n{i}", f"n{i+1}", "LEADS_TO")
        assert kg.find_all_paths("n0", "n4", max_hops=2) == []
        assert len(kg.find_all_paths("n0", "n4", max_hops=4)) == 1
        with pytest.raises(ValueError, match="max_hops"):
            kg.find_all_paths("n0", "n4", max_hops=17)

    def test_attack_paths_scored_and_sorted(self, kg):
        self._build_chain(kg)
        scored = kg.get_attack_paths("target:t", "privilege:root")
        assert len(scored) == 1
        p = scored[0]
        assert p["hops"] == 2
        assert 0 < p["score"] <= 1.0
        assert p["edges"][0]["relationship"] == "HAS_PORT"
        assert p["edges"][1]["relationship"] == "GRANTS"


# ---------------------------------------------------------------
# Chain analizi
# ---------------------------------------------------------------

class TestChains:
    def test_credential_chain(self, kg):
        kg.add_edge("credential:admin@ssh:1", "service:t:ssh", "WORKS_ON", confidence=0.8)
        kg.add_edge("service:t:ssh", "privilege:root", "GRANTS", confidence=0.9)
        chains = kg.find_credential_chains("credential:admin@ssh:1")
        assert len(chains) == 1
        assert chains[0]["privilege"] == "privilege:root"
        assert chains[0]["confidence"] == pytest.approx(0.72)

    def test_exploit_chain_only_chains_with(self, kg):
        kg.add_edge("finding:sqli:1", "finding:rce:2", "CHAINS_WITH")
        kg.add_edge("finding:rce:2", "finding:privesc:3", "CHAINS_WITH")
        # Farklı ilişki tipi chain'e dahil olmamalı
        kg.add_edge("finding:rce:2", "finding:xss:9", "LEADS_TO")
        chains = kg.find_exploit_chains("finding:sqli:1")
        flat = [tuple(c) for c in chains]
        assert ("finding:sqli:1", "finding:rce:2") in flat
        assert ("finding:sqli:1", "finding:rce:2", "finding:privesc:3") in flat
        assert not any("finding:xss:9" in c for c in chains)


# ---------------------------------------------------------------
# Summary / suggest / iter
# ---------------------------------------------------------------

class TestSummary:
    def test_summary_counts(self, kg):
        kg.add_edge("target:t", "service:t:80", "HAS_PORT")
        kg.add_edge("target:t", "finding:xss:1", "VULNERABLE_TO")
        s = kg.get_graph_summary()
        assert s["total_nodes"] == 3
        assert s["nodes_by_type"]["target"] == 1
        assert s["edges_by_relationship"]["HAS_PORT"] == 1

    def test_summary_filter(self, kg):
        kg.add_edge("target:a.com", "service:a.com:80", "HAS_PORT")
        kg.add_edge("target:b.com", "service:b.com:80", "HAS_PORT")
        s = kg.get_graph_summary("a.com")
        assert s["nodes_by_type"]["target"] == 1

    def test_iter_nodes(self, kg):
        kg.add_node("target:a", "target")
        kg.add_node("target:b", "target")
        assert len(kg.iter_nodes()) == 2
        assert kg.iter_nodes(":a") == ["target:a"]

    def test_predecessors(self, kg):
        kg.add_edge("a", "b", "RUNS")
        kg.add_edge("c", "b", "RUNS")
        assert sorted(kg.get_predecessors("b")) == ["a", "c"]

    def test_suggest_finds_unscanned_service(self, kg):
        kg.add_edge("target:t", "service:t:80", "HAS_PORT")
        result = kg.suggest_next_action("t")
        assert any("Zafiyet taraması" in s["action"] for s in result["suggestions"])

    def test_suggest_empty_target(self, kg):
        result = kg.suggest_next_action("nonexistent")
        assert "suggestion" in result


# ---------------------------------------------------------------
# Migration ve silme
# ---------------------------------------------------------------

class TestMigration:
    def test_import_from_sqlite(self, kg, tmp_path):
        import sqlite3
        db = tmp_path / "mem.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE graph_nodes (id TEXT PRIMARY KEY, node_type TEXT, label TEXT, properties TEXT)")
        conn.execute("CREATE TABLE graph_edges (id INTEGER PRIMARY KEY, source_id TEXT, target_id TEXT, relationship TEXT, properties TEXT, weight REAL, confidence REAL)")
        conn.execute("INSERT INTO graph_nodes VALUES ('target:t', 'target', 't', '{}')")
        conn.execute("INSERT INTO graph_edges (source_id, target_id, relationship, properties, weight, confidence) VALUES ('target:t', 'service:t:22', 'HAS_PORT', '{}', 1.0, 1.0)")
        conn.commit()
        conn.close()

        result = kg.import_from_sqlite(str(db))
        assert result["nodes"] == 1
        assert result["edges"] == 1
        assert kg._node_exists("target:t")
        assert kg._node_exists("service:t:22")

    def test_import_is_idempotent_and_deduplicates_edges(self, kg, tmp_path):
        import sqlite3
        db = tmp_path / "dedupe.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE graph_nodes (id TEXT PRIMARY KEY, node_type TEXT, label TEXT, properties TEXT)")
        conn.execute("CREATE TABLE graph_edges (id INTEGER PRIMARY KEY, source_id TEXT, target_id TEXT, relationship TEXT, properties TEXT, weight REAL, confidence REAL)")
        conn.executemany(
            "INSERT INTO graph_nodes VALUES (?, 'unknown', ?, '{}')",
            [("a", "a"), ("b", "b")],
        )
        conn.execute("INSERT INTO graph_edges VALUES (1, 'a', 'b', 'RUNS', '{}', 1.0, 0.1)")
        conn.execute("INSERT INTO graph_edges VALUES (2, 'a', 'b', 'GRANTS', '{}', 1.0, 0.9)")
        conn.commit()
        conn.close()

        first = kg.import_from_sqlite(str(db))
        second = kg.import_from_sqlite(str(db))
        neighbors = kg.query_neighbors("a", "out")
        assert first == {"nodes": 2, "edges": 1, "source_edges": 2, "skipped": False}
        assert second["skipped"] is True
        assert len(neighbors["outgoing"]) == 1
        assert neighbors["outgoing"][0]["relationship"] == "GRANTS"

    def test_import_rolls_back_on_failure(self, kg, tmp_path, monkeypatch):
        import sqlite3
        db = tmp_path / "rollback.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE graph_nodes (id TEXT PRIMARY KEY, node_type TEXT, label TEXT, properties TEXT)")
        conn.execute("CREATE TABLE graph_edges (id INTEGER PRIMARY KEY, source_id TEXT, target_id TEXT, relationship TEXT, properties TEXT, weight REAL, confidence REAL)")
        conn.execute("INSERT INTO graph_nodes VALUES ('a', 'target', 'a', '{}')")
        conn.execute("INSERT INTO graph_nodes VALUES ('b', 'service', 'b', '{}')")
        conn.execute("INSERT INTO graph_edges VALUES (1, 'a', 'b', 'HAS_PORT', '{}', 1.0, 1.0)")
        conn.commit()
        conn.close()

        monkeypatch.setattr(kg, "_upsert_edge", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
        with pytest.raises(RuntimeError, match="boom"):
            kg.import_from_sqlite(str(db))
        assert not kg._node_exists("a")
        assert kg._get_meta("sqlite_migration_v1") == ""

    def test_remove_target_subgraph(self, kg):
        kg.add_edge("target:t", "service:t:80", "HAS_PORT")
        kg.add_edge("target:t-long", "service:t-long:80", "HAS_PORT")
        kg.add_edge("target:other", "service:other:80", "HAS_PORT")
        kg.remove_target_subgraph("target:t")
        # Exact node silinir; benzer isimli veya bağlı node'lar korunur.
        assert not kg._node_exists("target:t")
        assert kg._node_exists("target:t-long")
        assert kg._node_exists("service:t:80")
        assert kg._node_exists("target:other")
