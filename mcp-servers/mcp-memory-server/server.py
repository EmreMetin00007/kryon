#!/usr/bin/env python3
"""
MCP Memory Server v2.0 — HackerAgent Knowledge Graph Hafızası.
SQLite + NetworkX hibrit: flat tablolar (backward compat) + ilişkisel graph.

Yeni yetenekler:
- Multi-hop reasoning: "Bu SSH key ile S3 bucket'a erişilebilir mi?"
- Attack path planning: Shortest Path to Root
- Exploit chaining: Finding'ler arası zincir ilişkileri
- Credential chain discovery: Credential → Service → Privilege zinciri

Kullanım:
    python server.py
"""

import json
import importlib.util
import itertools
import os
import copy
import hashlib
import re
import tempfile
import threading
from functools import wraps
from pathlib import Path
import sqlite3
import sys
from mcp.server.fastmcp import FastMCP

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

# KuzuDB backend, server.py importlib ile doğrudan yüklendiğinde de çalışmalı.
_BACKEND_MODULE = "cco_memory_graph_backend"
_backend_path = Path(__file__).with_name("graph_backend.py")
try:
    _backend = sys.modules.get(_BACKEND_MODULE)
    if _backend is None:
        _spec = importlib.util.spec_from_file_location(_BACKEND_MODULE, _backend_path)
        _backend = importlib.util.module_from_spec(_spec)
        sys.modules[_BACKEND_MODULE] = _backend
        _spec.loader.exec_module(_backend)
    KuzuGraph = _backend.KuzuGraph
    HAS_KUZU = _backend.HAS_KUZU
except (ImportError, AttributeError, OSError):
    KuzuGraph = None
    HAS_KUZU = False

_VAULT_MODULE = "cco_memory_credential_vault"
_vault_path = Path(__file__).with_name("credential_vault.py")
try:
    _vault_mod = sys.modules.get(_VAULT_MODULE)
    if _vault_mod is None:
        _vault_spec = importlib.util.spec_from_file_location(_VAULT_MODULE, _vault_path)
        _vault_mod = importlib.util.module_from_spec(_vault_spec)
        sys.modules[_VAULT_MODULE] = _vault_mod
        _vault_spec.loader.exec_module(_vault_mod)
    CredentialVault = _vault_mod.CredentialVault
except (ImportError, AttributeError, OSError):
    CredentialVault = None

_SERVER_DIR = str(Path(__file__).resolve().parent)
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)
from cco_surface_core.parsers import parse_artifact
from cco_surface_core.store import ensure_schema as ensure_surface_schema
from cco_surface_core.store import ingest_records as ingest_surface_records
from cco_surface_core.store import next_work as next_surface_work_query

_SCRIPTS_DIR = str(Path(__file__).resolve().parents[2] / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
from target_identity import finding_context, finding_context_key, resource_identity, target_query_matches

_VALIDATOR_EVIDENCE_MODULE = "cco_validator_evidence"
_validator_evidence_path = Path(__file__).resolve().parents[1] / "mcp-validator" / "cco_validator_core" / "evidence.py"
try:
    _validator_mod = sys.modules.get(_VALIDATOR_EVIDENCE_MODULE)
    if _validator_mod is None:
        _validator_spec = importlib.util.spec_from_file_location(_VALIDATOR_EVIDENCE_MODULE, _validator_evidence_path)
        _validator_mod = importlib.util.module_from_spec(_validator_spec)
        sys.modules[_VALIDATOR_EVIDENCE_MODULE] = _validator_mod
        _validator_spec.loader.exec_module(_validator_mod)
    VALIDATOR_SCHEMA_VERSION = _validator_mod.SCHEMA_VERSION
    TRUSTED_ARTIFACT_SCHEMAS = set(_validator_mod.TRUSTED_ARTIFACT_SCHEMAS)
    validator_artifact_is_valid = _validator_mod.artifact_is_valid
    validator_artifact_is_current = _validator_mod.artifact_is_current
except (ImportError, AttributeError, OSError):
    VALIDATOR_SCHEMA_VERSION = ""
    TRUSTED_ARTIFACT_SCHEMAS = {""}
    validator_artifact_is_valid = None
    validator_artifact_is_current = None

_VALIDATOR_REPORT_MODULE = "cco_validator_report_server"
_validator_server_path = Path(__file__).resolve().parents[1] / "mcp-validator" / "server.py"
try:
    _validator_server_mod = sys.modules.get(_VALIDATOR_REPORT_MODULE)
    if _validator_server_mod is None:
        _validator_server_spec = importlib.util.spec_from_file_location(_VALIDATOR_REPORT_MODULE, _validator_server_path)
        _validator_server_mod = importlib.util.module_from_spec(_validator_server_spec)
        sys.modules[_VALIDATOR_REPORT_MODULE] = _validator_server_mod
        _validator_server_spec.loader.exec_module(_validator_server_mod)
    validator_generate_validation_report = _validator_server_mod.generate_validation_report
except (ImportError, AttributeError, OSError):
    validator_generate_validation_report = None

# Veritabanı dosya yolu (CCO_HOME env var > ~/.cco)
CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
DB_PATH = os.path.join(CCO_HOME, "agent_memory.db")
KUZU_PATH = os.path.join(CCO_HOME, "kuzu_graph")
VAULT_BACKEND = "fernet" if CredentialVault else "disabled"
VALIDATED_FINDING_REPORTS_DIR = os.path.join(CCO_HOME, "reports", "validated_findings")

# Graph backend seçimi: CCO_GRAPH_BACKEND=kuzu|networkx|auto (varsayılan: auto)
# auto → KuzuDB kuruluysa kuzu, değilse networkx (değilse graph kapalı)
GRAPH_BACKEND = os.environ.get("CCO_GRAPH_BACKEND", "auto").lower()

# Server oluştur
mcp = FastMCP(
    "memory-server",
    instructions="HackerAgent Knowledge Graph Hafızası v2.0 — İlişkisel graph + attack path planning"
)

# ============================================================
# KNOWLEDGE GRAPH ENGINE
# ============================================================

class KnowledgeGraph:
    """NetworkX + SQLite hibrit knowledge graph.

    Graph yapısı:
        (Target)-[HAS_PORT]->(Service)-[RUNS]->(Software)-[VULNERABLE_TO]->(CVE)
                                                           -[EXPLOITABLE_BY]->(Payload)
        (Credential)-[WORKS_ON]->(Service)-[GRANTS]->(Privilege)
        (Finding)-[CHAINS_WITH]->(Finding)
    """

    # Geçerli node tipleri
    NODE_TYPES = ["target", "service", "software", "cve", "credential", "finding", "privilege", "endpoint", "subdomain"]
    NODE_TYPES += ['evidence_relation', 'capture', 'reference', 'identity', 'resource', 'chain', 'effect']

    # Geçerli ilişki tipleri
    RELATIONSHIP_TYPES = [
        "HAS_PORT", "RUNS", "VULNERABLE_TO", "EXPLOITABLE_BY",
        "WORKS_ON", "GRANTS", "CHAINS_WITH", "CONNECTED_TO",
        "BELONGS_TO", "DISCOVERED_BY", "LEADS_TO", "REQUIRES"
    ]
    RELATIONSHIP_TYPES += ['produces_reference', 'consumes_reference', 'reads_resource',
                           'requires_identity', 'changes_state', 'validated_effect', 'EVIDENCE_TARGET']

    # Teknik bazlı varsayılan başarı olasılıkları (Attack Path Planner için)
    TECHNIQUE_SUCCESS_PROBS = {
        "sql_injection": 0.85,
        "sql_injection_blind": 0.65,
        "xss_stored": 0.90,
        "xss_reflected": 0.80,
        "xss_dom": 0.70,
        "rce": 0.95,
        "command_injection": 0.90,
        "ssrf": 0.70,
        "ssrf_blind": 0.50,
        "idor": 0.80,
        "lfi": 0.75,
        "rfi": 0.60,
        "file_upload": 0.65,
        "ssti": 0.75,
        "xxe": 0.70,
        "deserialization": 0.60,
        "buffer_overflow": 0.55,
        "format_string": 0.50,
        "heap_overflow": 0.45,
        "use_after_free": 0.40,
        "race_condition": 0.35,
        "authentication_bypass": 0.70,
        "privilege_escalation": 0.65,
        "default_credentials": 0.90,
        "weak_credentials": 0.80,
        "credential_reuse": 0.75,
        "subdomain_takeover": 0.85,
        "cors_misconfiguration": 0.60,
        "open_redirect": 0.50,
        "csrf": 0.55,
        "jwt_attack": 0.65,
        "path_traversal": 0.70,
    }

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.G = nx.DiGraph() if HAS_NETWORKX else None
        self._init_graph_tables()
        self._load_from_db()

    def _init_graph_tables(self):
        """Graph tablolarını oluştur."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute('''
            CREATE TABLE IF NOT EXISTS graph_nodes (
                id TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                label TEXT DEFAULT '',
                properties TEXT DEFAULT '{}',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS graph_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                properties TEXT DEFAULT '{}',
                weight REAL DEFAULT 1.0,
                confidence REAL DEFAULT 0.5,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (source_id) REFERENCES graph_nodes(id),
                FOREIGN KEY (target_id) REFERENCES graph_nodes(id)
            )
        ''')

        # Index'ler
        c.execute("CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_edges_rel ON graph_edges(relationship)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_nodes_type ON graph_nodes(node_type)")
        # NetworkX DiGraph bir source/target çifti için tek edge tutar. SQLite
        # projection da aynı semantiği kullanmalı; son yazılan edge kazanır.
        c.execute('''
            DELETE FROM graph_edges
            WHERE id NOT IN (
                SELECT MAX(id) FROM graph_edges GROUP BY source_id, target_id
            )
        ''')
        c.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_edges_pair "
            "ON graph_edges(source_id, target_id)"
        )

        conn.commit()
        conn.close()

    def _load_from_db(self):
        """SQLite'dan NetworkX graph'a yükle."""
        if self.G is None:
            return

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        for row in c.execute("SELECT * FROM graph_nodes"):
            props = json.loads(row["properties"]) if row["properties"] else {}
            self.G.add_node(
                row["id"],
                node_type=row["node_type"],
                label=row["label"],
                **props
            )

        for row in c.execute("SELECT * FROM graph_edges"):
            props = json.loads(row["properties"]) if row["properties"] else {}
            self.G.add_edge(
                row["source_id"],
                row["target_id"],
                relationship=row["relationship"],
                weight=row["weight"],
                confidence=row["confidence"],
                **props
            )

        conn.close()

    @staticmethod
    def _now_iso() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _props_expired(props: dict | None) -> bool:
        valid_to = (props or {}).get("valid_to")
        if not valid_to:
            return False
        return str(valid_to) < KnowledgeGraph._now_iso()

    def _node_props(self, node_id: str) -> dict:
        if self.G is not None and node_id in self.G:
            return dict(self.G.nodes[node_id])
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT properties FROM graph_nodes WHERE id=?", (node_id,)).fetchone()
        conn.close()
        if not row:
            return {}
        try:
            return json.loads(row[0] or "{}")
        except Exception:
            return {}

    def add_node(self, node_id: str, node_type: str, label: str = "", properties: dict = None) -> str:
        """Graph'a düğüm ekle (Faz 6: properties merge + gecerlilik damgalari)."""
        merged = self._node_props(node_id)
        merged.update(properties or {})
        # node_type/label ayri kolon/attr; properties JSON'ina sizmamali
        merged.pop("node_type", None)
        merged.pop("label", None)
        merged.setdefault("valid_from", self._now_iso())
        merged["updated_at"] = self._now_iso()
        props_json = json.dumps(merged)

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO graph_nodes (id, node_type, label, properties) VALUES (?, ?, ?, ?)",
            (node_id, node_type, label or node_id, props_json)
        )
        conn.commit()
        conn.close()

        if self.G is not None:
            g_props = {k: v for k, v in merged.items() if k not in ("node_type", "label")}
            self.G.add_node(node_id, node_type=node_type, label=label or node_id, **g_props)

        return node_id

    def supersede_node(self, node_id: str, superseded_by: str = "") -> str:
        """Dugumu gecersiz kil: valid_to=now, superseded_by isaretli (Faz 6)."""
        props = {"valid_to": self._now_iso()}
        if superseded_by:
            props["superseded_by"] = superseded_by
        node_type = "unknown"
        if self.G is not None and node_id in self.G:
            node_type = str(self.G.nodes[node_id].get("node_type") or "unknown")
        else:
            conn = sqlite3.connect(self.db_path)
            row = conn.execute("SELECT node_type FROM graph_nodes WHERE id=?", (node_id,)).fetchone()
            conn.close()
            if row:
                node_type = str(row[0])
        return self.add_node(node_id, str(node_type), properties=props)

    def add_edge(self, source_id: str, target_id: str, relationship: str,
                 properties: dict = None, weight: float = 1.0, confidence: float = 0.5) -> int:
        """Graph'a kenar (ilişki) ekle."""
        props = properties or {}
        props_json = json.dumps(props)

        # Node'lar yoksa otomatik oluştur
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("SELECT id FROM graph_nodes WHERE id=?", (source_id,))
        if not c.fetchone():
            stype = source_id.split(":")[0] if ":" in source_id else "unknown"
            self.add_node(source_id, stype)

        c.execute("SELECT id FROM graph_nodes WHERE id=?", (target_id,))
        if not c.fetchone():
            ttype = target_id.split(":")[0] if ":" in target_id else "unknown"
            self.add_node(target_id, ttype)

        c.execute('''
            INSERT INTO graph_edges
                (source_id, target_id, relationship, properties, weight, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_id, target_id) DO UPDATE SET
                relationship=excluded.relationship,
                properties=excluded.properties,
                weight=excluded.weight,
                confidence=excluded.confidence,
                timestamp=CURRENT_TIMESTAMP
        ''', (source_id, target_id, relationship, props_json, weight, confidence))
        c.execute(
            "SELECT id FROM graph_edges WHERE source_id=? AND target_id=?",
            (source_id, target_id)
        )
        edge_id = c.fetchone()[0]
        conn.commit()
        conn.close()

        if self.G is not None:
            self.G.add_edge(source_id, target_id, relationship=relationship,
                            weight=weight, confidence=confidence, **props)

        return edge_id

    def query_neighbors(self, node_id: str, direction: str = "both",
                        include_expired: bool = False) -> dict:
        """Bir düğümün komşularını getir (Faz 6: suresi dolmus komsular gizli)."""
        if self.G is not None and node_id in self.G:
            result = {"node": node_id, "outgoing": [], "incoming": []}
            if direction in ("out", "both"):
                for _, target, data in self.G.out_edges(node_id, data=True):
                    if not include_expired and self._props_expired(self._node_props(target)):
                        continue
                    result["outgoing"].append({"target": target, **data})
            if direction in ("in", "both"):
                for source, _, data in self.G.in_edges(node_id, data=True):
                    if not include_expired and self._props_expired(self._node_props(source)):
                        continue
                    result["incoming"].append({"source": source, **data})
            return result

        # Fallback: SQLite
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        result = {"node": node_id, "outgoing": [], "incoming": []}

        if direction in ("out", "both"):
            for row in c.execute("SELECT * FROM graph_edges WHERE source_id=?", (node_id,)):
                result["outgoing"].append(dict(row))
        if direction in ("in", "both"):
            for row in c.execute("SELECT * FROM graph_edges WHERE target_id=?", (node_id,)):
                result["incoming"].append(dict(row))

        conn.close()
        return result

    def find_shortest_path(self, source: str, target: str) -> list:
        """İki düğüm arası en kısa yol."""
        if self.G is None:
            return []
        try:
            return nx.shortest_path(self.G, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def find_all_paths(self, source: str, target: str, max_hops: int = 6) -> list:
        """İki düğüm arası tüm yolları bul (max_hops sınırıyla)."""
        if self.G is None:
            return []
        max_hops = int(max_hops)
        if max_hops < 1:
            return []
        if max_hops > 16:
            raise ValueError("max_hops 16'dan büyük olamaz")
        try:
            return list(itertools.islice(
                nx.all_simple_paths(self.G, source, target, cutoff=max_hops),
                100,
            ))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def get_attack_paths(self, target_node: str, goal: str = "root",
                         max_hops: int = 8) -> list:
        """Target'tan goal'a tüm attack path'leri bul ve skorla."""
        paths = self.find_all_paths(target_node, goal, max_hops=max_hops)

        scored_paths = []
        for path in paths:
            score = self._score_path(path)
            edges_info = []
            for i in range(len(path) - 1):
                edge_data = self.G.get_edge_data(path[i], path[i + 1]) if self.G is not None else {}
                edges_info.append({
                    "from": path[i],
                    "to": path[i + 1],
                    "relationship": edge_data.get("relationship", "?"),
                    "confidence": edge_data.get("confidence", 0.5)
                })
            scored_paths.append({
                "path": path,
                "edges": edges_info,
                "score": score,
                "hops": len(path) - 1
            })

        return sorted(scored_paths, key=lambda x: x["score"], reverse=True)

    def _score_path(self, path: list) -> float:
        """Bir attack path'in başarı olasılığını hesapla.
        P(path) = Π confidence(edge_i) × (1 / hops) complexity_bonus
        """
        if self.G is None or len(path) < 2:
            return 0.0

        probability = 1.0
        for i in range(len(path) - 1):
            edge_data = self.G.get_edge_data(path[i], path[i + 1]) or {}
            confidence = edge_data.get("confidence", 0.5)
            probability *= confidence

        # Kısa yolları tercih et (complexity bonus)
        hops = len(path) - 1
        complexity_factor = 1.0 / (1 + 0.1 * hops)

        return round(probability * complexity_factor, 4)

    def find_credential_chains(self, credential_node: str) -> list:
        """Bu credential ile hangi servislere → hangi privilege'lara ulaşılabilir?"""
        if self.G is None or credential_node not in self.G:
            return []

        chains = []
        # credential -> (WORKS_ON) -> service -> (GRANTS) -> privilege
        for _, service, edge1 in self.G.out_edges(credential_node, data=True):
            if edge1.get("relationship") == "WORKS_ON":
                for _, privilege, edge2 in self.G.out_edges(service, data=True):
                    if edge2.get("relationship") == "GRANTS":
                        chains.append({
                            "credential": credential_node,
                            "service": service,
                            "privilege": privilege,
                            "confidence": edge1.get("confidence", 0.5) * edge2.get("confidence", 0.5)
                        })
        return chains

    def remove_nodes(self, node_ids: list):
        """Exact node ID'lerini SQLite ve NetworkX'ten sil."""
        unique_ids = sorted(set(node_ids))
        if not unique_ids:
            return
        placeholders = ",".join("?" for _ in unique_ids)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            f"DELETE FROM graph_edges WHERE source_id IN ({placeholders}) "
            f"OR target_id IN ({placeholders})",
            unique_ids + unique_ids,
        )
        c.execute(
            f"DELETE FROM graph_nodes WHERE id IN ({placeholders})",
            unique_ids,
        )
        conn.commit()
        conn.close()
        if self.G is not None:
            self.G.remove_nodes_from(unique_ids)

    def find_exploit_chains(self, finding_node: str) -> list:
        """Bu finding hangi diğer finding'lerle chain edilebilir?"""
        if self.G is None or finding_node not in self.G:
            return []

        chains = []
        # finding -> (CHAINS_WITH) -> finding -> ...
        visited = set()
        stack = [(finding_node, [finding_node])]

        while stack:
            current, path = stack.pop()
            if current in visited and current != finding_node:
                continue
            visited.add(current)

            for _, next_node, data in self.G.out_edges(current, data=True):
                if data.get("relationship") == "CHAINS_WITH" and next_node not in visited:
                    new_path = path + [next_node]
                    chains.append(new_path)
                    stack.append((next_node, new_path))

        return chains

    def get_graph_summary(self, target_filter: str = "") -> dict:
        """Graph'ın genel özetini döndür."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        summary = {
            "total_nodes": 0,
            "total_edges": 0,
            "nodes_by_type": {},
            "edges_by_relationship": {},
            "targets": []
        }

        # Node istatistikleri
        if target_filter:
            rows = c.execute("SELECT node_type, COUNT(*) FROM graph_nodes WHERE id LIKE ? GROUP BY node_type",
                             (f"%{target_filter}%",)).fetchall()
        else:
            rows = c.execute("SELECT node_type, COUNT(*) FROM graph_nodes GROUP BY node_type").fetchall()
        for row in rows:
            summary["nodes_by_type"][row[0]] = row[1]
            summary["total_nodes"] += row[1]

        # Edge istatistikleri
        if target_filter:
            rows = c.execute(
                "SELECT relationship, COUNT(*) FROM graph_edges WHERE source_id LIKE ? OR target_id LIKE ? GROUP BY relationship",
                (f"%{target_filter}%", f"%{target_filter}%")).fetchall()
        else:
            rows = c.execute("SELECT relationship, COUNT(*) FROM graph_edges GROUP BY relationship").fetchall()
        for row in rows:
            summary["edges_by_relationship"][row[0]] = row[1]
            summary["total_edges"] += row[1]

        # Target listesi
        targets = c.execute("SELECT DISTINCT id FROM graph_nodes WHERE node_type='target'").fetchall()
        summary["targets"] = [t[0] for t in targets]

        conn.close()
        return summary

    def suggest_next_action(self, target: str) -> dict:
        """Graph'a bakarak en yüksek başarı olasılıklı sonraki adımı öner."""
        if self.G is None:
            return {"suggestion": "NetworkX kurulu değil, graph analizi yapılamıyor."}

        # Target ile ilişkili tüm node'ları bul
        target_nodes = [n for n in self.G.nodes() if target in n]
        if not target_nodes:
            return {"suggestion": f"'{target}' ile ilişkili veri bulunamadı. Önce keşif yapın."}

        suggestions = []

        # Keşfedilmemiş servisler
        for node in target_nodes:
            node_data = self.G.nodes[node]
            out_edges = list(self.G.out_edges(node, data=True))

            if node_data.get("node_type") == "service":
                has_vuln = any(e[2].get("relationship") == "VULNERABLE_TO" for e in out_edges)
                if not has_vuln:
                    suggestions.append({
                        "action": f"Zafiyet taraması yap: {node}",
                        "priority": "high",
                        "reason": "Servis keşfedildi ama zafiyet analizi yapılmadı"
                    })

            if node_data.get("node_type") == "cve":
                has_exploit = any(e[2].get("relationship") == "EXPLOITABLE_BY" for e in out_edges)
                if not has_exploit:
                    suggestions.append({
                        "action": f"Exploit ara: {node}",
                        "priority": "critical",
                        "reason": "CVE bulundu ama exploit henüz yok"
                    })

        # Credential chain fırsatları
        cred_nodes = [n for n in target_nodes if self.G.nodes[n].get("node_type") == "credential"]
        for cred in cred_nodes:
            chains = self.find_credential_chains(cred)
            if not chains:
                suggestions.append({
                    "action": f"Credential test et: {cred} → diğer servislerde dene",
                    "priority": "high",
                    "reason": "Credential bulundu ama başka servislerde denenmedi"
                })

        if not suggestions:
            suggestions.append({
                "action": "Daha fazla keşif yap (port scan, dizin tarama)",
                "priority": "medium",
                "reason": "Mevcut verilerle yeni saldırı vektörü bulunamadı"
            })

        return {
            "target": target,
            "suggestions": sorted(suggestions, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["priority"], 4)),
            "graph_stats": {
                "related_nodes": len(target_nodes),
                "total_graph_nodes": self.G.number_of_nodes(),
                "total_graph_edges": self.G.number_of_edges()
            }
        }


# ============================================================
# VERİTABANI BAŞLATMA
# ============================================================

def init_db():
    """Tüm veritabanı tablolarını oluştur (legacy + graph)."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ---- Legacy tablolar (backward compatibility) ----
    c.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            payload TEXT,
            validation_state TEXT DEFAULT 'unvalidated',
            validation_artifact TEXT DEFAULT '',
            validation_id TEXT DEFAULT '',
            validation_verdict TEXT DEFAULT '',
            validation_oracle TEXT DEFAULT '',
            validation_evidence_grade TEXT DEFAULT '',
            validation_report_path TEXT DEFAULT '',
            reportable INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    for column, default in (
        ("validation_state", "'unvalidated'"),
        ("validation_artifact", "''"),
        ("validation_id", "''"),
        ("validation_verdict", "''"),
        ("validation_oracle", "''"),
        ("validation_evidence_grade", "''"),
        ("validation_report_path", "''"),
        ("reportable", "0"),
    ):
        try:
            c.execute(f"ALTER TABLE findings ADD COLUMN {column} TEXT DEFAULT {default}" if column != "reportable"
                      else f"ALTER TABLE findings ADD COLUMN {column} INTEGER DEFAULT {default}")
        except sqlite3.OperationalError:
            pass

    # Existing rows remain untouched: their original program/run context is
    # unknown. New identities are reserved atomically within the write txn.
    c.execute('''
        CREATE TABLE IF NOT EXISTS finding_identity (
            identity_key TEXT PRIMARY KEY,
            finding_id INTEGER NOT NULL UNIQUE,
            context_key TEXT NOT NULL DEFAULT ''
        )
    ''')
    try:
        c.execute("ALTER TABLE finding_identity ADD COLUMN context_key TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    c.execute('''
        CREATE TABLE IF NOT EXISTS finding_validation_history (
            finding_id INTEGER NOT NULL,
            validation_id TEXT NOT NULL,
            validation_artifact TEXT NOT NULL,
            validation_state TEXT NOT NULL,
            validation_verdict TEXT NOT NULL,
            PRIMARY KEY (finding_id, validation_id, validation_artifact)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS finding_aliases (
            alias_id INTEGER PRIMARY KEY,
            canonical_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            secret_ref TEXT DEFAULT '',
            secret_backend TEXT DEFAULT '',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    for column, default in (("secret_ref", "''"), ("secret_backend", "''")):
        try:
            c.execute(f"ALTER TABLE credentials ADD COLUMN {column} TEXT DEFAULT {default}")
        except sqlite3.OperationalError:
            pass

    c.execute('''
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            url_or_port TEXT NOT NULL,
            protocol TEXT,
            state TEXT,
            technologies TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    ensure_surface_schema(conn)

    c.execute('''
        CREATE TABLE IF NOT EXISTS graph_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dedupe_key TEXT NOT NULL UNIQUE,
            operation TEXT NOT NULL,
            payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME
        )
    ''')
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_graph_outbox_status "
        "ON graph_outbox(status, attempts)"
    )

    c.execute('''
        CREATE TABLE IF NOT EXISTS vault_gc (
            secret_ref TEXT PRIMARY KEY,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


# Storage and the vault are initialized when a tool is first used, not when
# this module is imported for registration, inspection, or pytest collection.
vault = None


def _migrate_plaintext_credentials():
    if vault is None:
        return
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, target, service, username, password, secret_ref FROM credentials"
    ).fetchall()
    for row in rows:
        password = row["password"] or ""
        if row["secret_ref"] or password in {"", "[REDACTED]"}:
            continue
        secret_ref = ""
        try:
            secret_ref = vault.store_secret(
                "credential_password",
                password,
                {
                    "credential_id": row["id"],
                    "target": row["target"],
                    "service": row["service"],
                    "username": row["username"],
                },
            )
            conn.execute(
                "UPDATE credentials SET password='[REDACTED]', secret_ref=?, secret_backend=? WHERE id=?",
                (secret_ref, "fernet", row["id"]),
            )
        except Exception:
            if secret_ref:
                try:
                    vault.delete_secret(secret_ref)
                except Exception:
                    pass
            raise
    conn.commit()
    conn.close()


def _resolve_credential_secret(credential_id: int) -> str:
    _ensure_initialized()
    if vault is None:
        raise RuntimeError("credential vault etkin değil")
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT secret_ref FROM credentials WHERE id=?",
        (credential_id,),
    ).fetchone()
    conn.close()
    if not row or not row[0]:
        raise KeyError(credential_id)
    return vault.get_secret(row[0])


def _enqueue_vault_gc(conn, secret_ref: str):
    if not secret_ref:
        return
    conn.execute(
        "INSERT OR IGNORE INTO vault_gc (secret_ref) VALUES (?)",
        (secret_ref,),
    )


def _replay_vault_gc(limit: int = 100):
    if vault is None:
        return
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT secret_ref FROM vault_gc ORDER BY created_at LIMIT ?",
        (limit,),
    ).fetchall()
    for row in rows:
        secret_ref = row[0]
        try:
            vault.delete_secret(secret_ref)
        except Exception:
            continue
        conn.execute("DELETE FROM vault_gc WHERE secret_ref=?", (secret_ref,))
    conn.commit()
    conn.close()


# Knowledge Graph instance — backend seçimi
def _create_graph_backend():
    """CCO_GRAPH_BACKEND'e göre graph backend'i oluştur."""
    global GRAPH_BACKEND
    requested = GRAPH_BACKEND
    if requested not in {"auto", "kuzu", "networkx"}:
        raise ValueError(
            "CCO_GRAPH_BACKEND yalnızca auto, kuzu veya networkx olabilir"
        )

    kuzu_store_exists = os.path.exists(KUZU_PATH)
    if requested == "kuzu" and not (HAS_KUZU and KuzuGraph):
        raise RuntimeError("CCO_GRAPH_BACKEND=kuzu istendi ancak kuzu kurulu değil")
    if requested == "auto" and kuzu_store_exists and not (HAS_KUZU and KuzuGraph):
        raise RuntimeError(
            "Mevcut Kuzu graph açılamıyor; sessiz NetworkX fallback veri ayrıştırır. "
            "kuzu paketini kurun veya CCO_GRAPH_BACKEND=networkx'i açıkça seçin."
        )

    if requested == "kuzu" or (requested == "auto" and HAS_KUZU and KuzuGraph):
        # Kuzu init/migration hatası fail-closed'dur. Özellikle file-lock
        # hatasında NetworkX'e düşmek iki ayrı graph store üretir.
        kg_instance = KuzuGraph(KUZU_PATH)
        _auto_migrate_sqlite(kg_instance)
        GRAPH_BACKEND = "kuzu"
        return kg_instance

    if HAS_NETWORKX:
        GRAPH_BACKEND = "networkx"
        return KnowledgeGraph(DB_PATH)
    GRAPH_BACKEND = "none"
    return KnowledgeGraph(DB_PATH)  # NetworkX'siz de çalışır (G=None, sadece SQLite)


def _auto_migrate_sqlite(kuzu_instance):
    """SQLite projection'ını fingerprint ile idempotent olarak aktar."""
    kuzu_instance.import_from_sqlite(DB_PATH)


class _LazyGraph:
    def __getattr__(self, name):
        _ensure_initialized()
        return getattr(_graph_backend, name)

    def __setattr__(self, name, value):
        _ensure_initialized()
        setattr(_graph_backend, name, value)

    def __delattr__(self, name):
        _ensure_initialized()
        if name in vars(_graph_backend):
            delattr(_graph_backend, name)
            return
        if name in vars(self):
            object.__delattr__(self, name)
            return
        # Backend sınıfından gelen öznitelikte silinecek override yoktur.
        if hasattr(_graph_backend, name):
            return
        raise AttributeError(name)


kg = _LazyGraph()
_graph_backend = None
_initialized = False
_initialization_lock = threading.RLock()

# Graph sorguları için backend-agnostic erişim katmanı
HAS_GRAPH = GRAPH_BACKEND != "none"


def _graph_iter_nodes(id_filter: str = "") -> list:
    """Backend-agnostic node ID listesi (NetworkX kg.G.nodes() eşdeğeri)."""
    if GRAPH_BACKEND == "kuzu":
        return kg.iter_nodes(id_filter)
    if kg.G is not None:
        return [n for n in kg.G.nodes() if not id_filter or id_filter in n]
    return []


def _graph_node_type(node_id: str) -> str:
    """Backend-agnostic node tipi."""
    if GRAPH_BACKEND == "kuzu":
        return kg.get_node_type(node_id)
    if kg.G is not None and node_id in kg.G:
        return kg.G.nodes[node_id].get("node_type", "unknown")
    return "unknown"


def _graph_predecessors(node_id: str) -> list:
    """Backend-agnostic predecessor listesi."""
    if GRAPH_BACKEND == "kuzu":
        return kg.get_predecessors(node_id)
    if kg.G is not None:
        return list(kg.G.predecessors(node_id))
    return []


def _enqueue_graph_projection(conn, dedupe_key: str, operation: str,
                              payload: dict, force: bool = False) -> int:
    """Legacy kayıtla aynı SQLite transaction'ında projection işi oluştur."""
    conn.execute('''
        INSERT INTO graph_outbox (dedupe_key, operation, payload, status)
        VALUES (?, ?, ?, 'pending')
        ON CONFLICT(dedupe_key) DO UPDATE SET
            operation=excluded.operation,
            payload=excluded.payload,
            status=CASE WHEN ? THEN 'pending' ELSE graph_outbox.status END,
            last_error=CASE WHEN ? THEN '' ELSE graph_outbox.last_error END,
            completed_at=CASE WHEN ? THEN NULL ELSE graph_outbox.completed_at END
    ''', (
        dedupe_key,
        operation,
        json.dumps(payload),
        int(force),
        int(force),
        int(force),
    ))
    row = conn.execute(
        "SELECT id FROM graph_outbox WHERE dedupe_key=?",
        (dedupe_key,)
    ).fetchone()
    return row[0]


def _apply_graph_projection(operation: str, payload: dict):
    target = payload["target"]
    target_node = f"target:{target}"
    kg.add_node(target_node, "target", target)

    if operation == 'evidence_relation':
        from evidence_chaining import EvidenceGraph, EvidenceError
        graph = EvidenceGraph(DB_PATH)
        try:
            relation = graph.relation(payload['relation_id'])
            if relation != payload['relation']:
                raise EvidenceError('projection_evidence_mismatch')
            from datetime import datetime, timezone
            props = {**relation,
                     'valid_from': datetime.fromtimestamp(relation['observed_at'], timezone.utc).isoformat(),
                     'valid_to': datetime.fromtimestamp(relation['expires_at'], timezone.utc).isoformat()}
            edge_node = 'evidence-edge:' + payload['relation_id']
            kg.add_node(edge_node, 'evidence_relation', relation['kind'], props)
            kg.add_edge(relation['source'], edge_node, relation['kind'], props,
                        weight=1.0, confidence=1.0)
            kg.add_edge(edge_node, relation['target'], 'EVIDENCE_TARGET', props,
                        weight=1.0, confidence=1.0)
        finally:
            graph.close()
        return

    if operation == "finding":
        finding_node = f"finding:{payload['type']}:{payload['id']}"
        kg.add_node(
            finding_node,
            "finding",
            f"{payload['type']} ({payload['severity']})",
            {
                "target": target,
                "severity": payload["severity"],
                "description": payload["description"][:200],
                "payload": payload["payload"][:200],
            },
        )
        confidence_map = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.70,
            "low": 0.50,
            "info": 0.30,
        }
        confidence = confidence_map.get(payload["severity"].lower(), 0.5)
        vuln_type = payload["type"].lower().replace(" ", "_").replace("-", "_")
        probability = kg.TECHNIQUE_SUCCESS_PROBS.get(vuln_type, 0.5)
        kg.add_edge(
            target_node,
            finding_node,
            "VULNERABLE_TO",
            weight=probability,
            confidence=confidence,
        )
        return

    if operation == "credential":
        service_node = f"service:{target}:{payload['service']}"
        credential_node = (
            f"credential:{payload['username']}@{payload['service']}:{payload['id']}"
        )
        kg.add_node(service_node, "service", f"{payload['service']} on {target}")
        kg.add_node(
            credential_node,
            "credential",
            f"{payload['username']}:***",
            {
                "target": target,
                "username": payload["username"],
                "service": payload["service"],
            },
        )
        kg.add_edge(target_node, service_node, "HAS_PORT", confidence=1.0)
        kg.add_edge(credential_node, service_node, "WORKS_ON", confidence=0.8)
        return

    if operation == "endpoint":
        service_node = (
            f"service:{target}:{payload['url_or_port']}/{payload['protocol']}"
        )
        kg.add_node(
            service_node,
            "service",
            f"{payload['protocol']}://{target}:{payload['url_or_port']}",
            {
                "target": target,
                "port": payload["url_or_port"],
                "protocol": payload["protocol"],
                "state": payload["state"],
            },
        )
        kg.add_edge(target_node, service_node, "HAS_PORT", confidence=1.0)
        for technology in (payload.get("technologies") or "").split(","):
            technology = technology.strip()
            if technology:
                software_node = f"software:{technology.lower()}"
                kg.add_node(software_node, "software", technology)
                kg.add_edge(service_node, software_node, "RUNS", confidence=0.9)
        return

    raise ValueError(f"Bilinmeyen graph projection operation: {operation}")


def _process_graph_job(job_id: int) -> str:
    """Tek outbox işini uygula; hata metnini döndür, işi kaybetme."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT operation, payload FROM graph_outbox WHERE id=?",
        (job_id,)
    ).fetchone()
    conn.close()
    if not row:
        return ""

    try:
        _apply_graph_projection(row[0], json.loads(row[1]))
    except Exception as exc:
        error = str(exc)
        conn = sqlite3.connect(DB_PATH)
        conn.execute('''
            UPDATE graph_outbox
            SET status='failed', attempts=attempts+1, last_error=?
            WHERE id=?
        ''', (error[:1000], job_id))
        conn.commit()
        conn.close()
        return error

    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        UPDATE graph_outbox
        SET status='done', attempts=attempts+1, last_error='',
            completed_at=CURRENT_TIMESTAMP
        WHERE id=?
    ''', (job_id,))
    conn.commit()
    conn.close()
    return ""


def _replay_graph_outbox(limit: int = 100):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute('''
        SELECT id FROM graph_outbox
        WHERE status IN ('pending', 'failed') AND attempts < 10
        ORDER BY id LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    for row in rows:
        _process_graph_job(row[0])


def _ensure_initialized():
    """Initialize storage, migrate, and replay once on first actual use."""
    global _initialized, _graph_backend, vault, HAS_GRAPH
    with _initialization_lock:
        if _initialized:
            return
        init_db()
        vault = CredentialVault(CCO_HOME) if CredentialVault else None
        _migrate_plaintext_credentials()
        _replay_vault_gc()
        _graph_backend = _create_graph_backend()
        HAS_GRAPH = GRAPH_BACKEND != "none"
        _initialized = True  # Replay uses the proxy and must not recurse.
        try:
            _replay_graph_outbox()
        except Exception:
            _initialized = False
            raise


def memory_tool():
    """Register the same MCP signature while delaying state initialization."""
    def decorate(fn):
        @wraps(fn)
        def invoke(*args, **kwargs):
            _ensure_initialized()
            return fn(*args, **kwargs)
        return mcp.tool()(invoke)
    return decorate


def _normalize_reportable(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "confirmed", "reportable"}
    return False


def _generic_artifact_hash(record: dict) -> str:
    candidate = copy.deepcopy(record)
    candidate.setdefault("artifact", {})["content_sha256"] = ""
    payload = json.dumps(candidate, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _artifact_path_in_trusted_root(path: str) -> bool:
    try:
        candidate = Path(path).expanduser().resolve(strict=True)
        root = (Path(CCO_HOME) / "validations").expanduser().resolve()
        return os.path.commonpath([str(root), str(candidate)]) == str(root)
    except (OSError, ValueError):
        return False


def _generic_artifact_is_valid(record: dict, expected_target: str = "", expected_finding_type: str = "") -> bool:
    if validator_artifact_is_current:
        return bool(validator_artifact_is_current(
            record,
            expected_target=expected_target,
            expected_finding_type=expected_finding_type,
            expected_path=((record.get("artifact") or {}).get("path") or ""),
        ))
    return False


def _extract_validation_metadata(raw_payload: str, validation_result_json: str = "",
                                 validation_artifact_path: str = "",
                                 finding_target: str = "", finding_type: str = "") -> dict:
    payload_text = raw_payload or ""
    explicit_validation = bool((validation_result_json or "").strip() or (validation_artifact_path or "").strip())
    metadata = {
        "payload_to_store": payload_text,
        "validation_state": "unvalidated",
        "validation_artifact": "",
        "validation_id": "",
        "validation_verdict": "",
        "validation_oracle": "",
        "validation_evidence_grade": "",
        "reportable": 0,
    }
    candidate = None
    artifact_path = (validation_artifact_path or "").strip()
    stripped = (validation_result_json or payload_text).strip()
    if artifact_path and os.path.exists(artifact_path):
        try:
            with open(artifact_path, encoding="utf-8") as handle:
                candidate = json.load(handle)
        except Exception:
            candidate = None
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            candidate = json.loads(stripped)
        except Exception:
            candidate = None
    elif not candidate and stripped.endswith(".json") and os.path.exists(stripped):
        artifact_path = stripped
        try:
            with open(stripped, encoding="utf-8") as handle:
                candidate = json.load(handle)
        except Exception:
            candidate = None
    if not isinstance(candidate, dict):
        return metadata
    schema_version = str(candidate.get("schema_version") or "")
    if not schema_version:
        return metadata

    artifact = candidate.get("artifact") or {}
    artifact_path = artifact_path or candidate.get("audit_trail") or artifact.get("path") or ""
    if validator_artifact_is_current:
        is_valid = bool(validator_artifact_is_current(
            candidate,
            expected_target=finding_target,
            expected_finding_type=finding_type,
            expected_path=artifact_path or ((candidate.get("artifact") or {}).get("path") or ""),
        ))
    else:
        is_valid = _generic_artifact_is_valid(candidate, finding_target, finding_type)
    reportable = is_valid and _normalize_reportable(candidate.get("reportable")) and candidate.get("verdict") == "CONFIRMED"
    payload_to_store = payload_text
    if not payload_to_store and not explicit_validation:
        payload_to_store = artifact_path or payload_text
    metadata.update({
        "payload_to_store": payload_to_store,
        "validation_state": "verified" if is_valid else "unverified_artifact",
        "validation_artifact": artifact_path,
        "validation_id": str(candidate.get("validation_id") or ""),
        "validation_verdict": str(candidate.get("verdict") or ""),
        "validation_oracle": str(candidate.get("oracle") or candidate.get("validator") or ""),
        "validation_evidence_grade": str(candidate.get("evidence_grade") or candidate.get("oracle") or ""),
        "reportable": 1 if reportable else 0,
    })
    return metadata


def _serialize_finding_row(row) -> dict:
    entry = dict(row)
    entry["reportable"] = bool(entry.get("reportable"))
    entry["has_validation_artifact"] = bool(entry.get("validation_artifact"))
    entry["has_validation_report"] = bool(entry.get("validation_report_path"))
    if entry["reportable"]:
        current = _extract_validation_metadata(
            "", validation_artifact_path=entry.get("validation_artifact") or "",
            finding_target=entry.get("target") or "", finding_type=entry.get("type") or "")
        if not current["reportable"]:
            entry["stored_validation_state"] = entry.get("validation_state")
            entry["validation_state"] = "stale_or_invalid_artifact"
            entry["reportable"] = False
    return entry


def _persist_validated_report(markdown: str, target: str, finding_type: str, validation_id: str) -> str:
    if not (markdown or "").strip():
        return ""
    os.makedirs(VALIDATED_FINDING_REPORTS_DIR, mode=0o700, exist_ok=True)
    safe_target = re.sub(r"[^a-zA-Z0-9._-]+", "_", target).strip("_") or "target"
    safe_type = re.sub(r"[^a-zA-Z0-9._-]+", "_", finding_type).strip("_") or "finding"
    safe_validation = re.sub(r"[^a-zA-Z0-9._-]+", "_", validation_id).strip("_") or "validation"
    path = os.path.join(VALIDATED_FINDING_REPORTS_DIR, f"{safe_target}_{safe_type}_{safe_validation}.md")
    fd, temp_path = tempfile.mkstemp(prefix=".validated-finding-", suffix=".tmp", dir=VALIDATED_FINDING_REPORTS_DIR)
    try:
        os.chmod(temp_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(markdown)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        return path
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        return ""


def _format_store_finding_result(finding_id: int, validation_note: str, graph_error: str) -> str:
    if graph_error:
        return (
            f"Bulgu kaydedildi (ID: {finding_id}){validation_note}; graph projection beklemede: "
            f"{graph_error}"
        )
    return f"Bulgu kaydedildi (ID: {finding_id}){validation_note} + Knowledge Graph güncellendi ✓"


def _update_finding_validation_report_path(finding_id: int, report_path: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE findings SET validation_report_path=? WHERE id=?",
            (report_path or "", finding_id),
        )


def _finding_identity_key(target: str, finding_type: str, description: str, payload: str) -> str:
    resource = resource_identity(target)
    finding_type = str(finding_type or "").strip().lower()
    description = str(description or "").strip()
    if not resource or not finding_type or not description:
        return ""  # Ambiguous inputs must never collapse unrelated findings.
    scope_revision = _validator_mod.current_scope_revision() if validator_artifact_is_current else "scope:unknown"
    context = finding_context(scope_revision)
    value = ["finding-identity-v1", context, resource, finding_type, description, str(payload or "")]
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def _store_finding_internal(target: str, type: str, severity: str, description: str,
                            payload: str = "", validation_result_json: str = "",
                            validation_artifact_path: str = "") -> dict:
    _ensure_initialized()
    validation = _extract_validation_metadata(
        payload,
        validation_result_json,
        validation_artifact_path,
        finding_target=target,
        finding_type=type,
    )
    revision = _validator_mod.current_scope_revision() if validator_artifact_is_current else "scope:unknown"
    context_key = finding_context_key(revision)
    identity_key = _finding_identity_key(target, type, description, payload)
    current_revision = _validator_mod.current_scope_revision() if validator_artifact_is_current else "scope:unknown"
    if finding_context_key(current_revision) != context_key:
        raise ValueError("finding scope/context changed during storage")
    with sqlite3.connect(DB_PATH, timeout=30) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        existing = None
        if identity_key:
            existing = conn.execute(
                "SELECT f.* FROM finding_identity i JOIN findings f ON f.id=i.finding_id WHERE i.identity_key=?",
                (identity_key,),
            ).fetchone()
        if existing is None:
            cursor = conn.execute(
            "INSERT INTO findings "
            "(target, type, severity, description, payload, validation_state, validation_artifact, "
            "validation_id, validation_verdict, validation_oracle, validation_evidence_grade, validation_report_path, reportable) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                target,
                type,
                severity,
                description,
                validation["payload_to_store"],
                validation["validation_state"],
                validation["validation_artifact"],
                validation["validation_id"],
                validation["validation_verdict"],
                validation["validation_oracle"],
                validation["validation_evidence_grade"],
                "",
                validation["reportable"],
            )
            )
            finding_id = cursor.lastrowid
            if identity_key:
                # Clean up a dangling identity left by a legacy deletion.
                conn.execute("DELETE FROM finding_identity WHERE identity_key=?", (identity_key,))
                conn.execute("INSERT INTO finding_identity (identity_key, finding_id, context_key) VALUES (?, ?, ?)",
                             (identity_key, finding_id, context_key))
        else:
            finding_id = existing["id"]
            bound_context = conn.execute("SELECT context_key FROM finding_identity WHERE identity_key=?",
                                         (identity_key,)).fetchone()[0]
            if bound_context and bound_context != context_key:
                raise ValueError("finding identity has an inconsistent context")
            if not bound_context:
                conn.execute("UPDATE finding_identity SET context_key=? WHERE identity_key=?",
                             (context_key, identity_key))
            for old in (dict(existing), validation):
                if old.get("validation_id") and old.get("validation_artifact"):
                    conn.execute(
                        "INSERT OR IGNORE INTO finding_validation_history "
                        "(finding_id, validation_id, validation_artifact, validation_state, validation_verdict) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (finding_id, old["validation_id"], old["validation_artifact"],
                         old.get("validation_state") or "", old.get("validation_verdict") or ""))
            # A repeat without a current artifact must never downgrade a
            # validated finding. New current evidence may update it.
            if validation["reportable"]:
                next_state = "confirmed" if existing["validation_state"] == "confirmed" else validation["validation_state"]
                conn.execute(
                    "UPDATE findings SET severity=?, validation_state=?, validation_artifact=?, "
                    "validation_id=?, validation_verdict=?, validation_oracle=?, "
                    "validation_evidence_grade=?, reportable=? WHERE id=?",
                    (severity, next_state, validation["validation_artifact"], validation["validation_id"],
                     validation["validation_verdict"], validation["validation_oracle"],
                     validation["validation_evidence_grade"], validation["reportable"], finding_id))
            else:
                conn.execute("UPDATE findings SET severity=? WHERE id=?", (severity, finding_id))
        current_revision = _validator_mod.current_scope_revision() if validator_artifact_is_current else "scope:unknown"
        if finding_context_key(current_revision) != context_key:
            raise ValueError("finding scope/context changed during storage")
        if validation["reportable"]:
            current_validation = _extract_validation_metadata(
                "", validation_artifact_path=validation["validation_artifact"],
                finding_target=target, finding_type=type)
            if not current_validation["reportable"]:
                raise ValueError("finding artifact became stale during storage")
        current = dict(conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone())
        job_id = _enqueue_graph_projection(
            conn,
            f"finding:{finding_id}",
            "finding",
            {
                "id": finding_id,
                "target": current["target"],
                "type": current["type"],
                "severity": current["severity"],
                "description": current["description"] or "",
                "payload": current["payload"] or "",
                "validation_state": current["validation_state"],
                "validation_verdict": current["validation_verdict"],
                "validation_oracle": current["validation_oracle"],
                "validation_evidence_grade": current["validation_evidence_grade"],
                "reportable": bool(current["reportable"]),
            },
            force=existing is not None,
        )
    error = _process_graph_job(job_id)
    validation_note = ""
    if validation["validation_state"] == "verified":
        validation_note = " [validated artifact]"
    elif validation["validation_state"] == "unverified_artifact":
        validation_note = " [artifact present, unverified]"
    return {
        "finding_id": finding_id,
        "graph_error": error,
        "validation_note": validation_note,
        "validation": validation,
        "deduplicated": existing is not None,
    }


# Finding yaşam döngüsü: hypothesis -> candidate -> validating -> confirmed
#                                                             -> rejected / inconclusive
# Store-time legacy durumlar (unvalidated/verified/unverified_artifact) korunur.
FINDING_LIFECYCLE_TRANSITIONS = {
    "hypothesis": {"candidate", "rejected"},
    "candidate": {"validating", "rejected"},
    "validating": {"confirmed", "rejected", "inconclusive"},
    "confirmed": set(),
    "rejected": {"candidate"},
    "inconclusive": {"candidate", "validating"},
    "unvalidated": {"candidate", "validating", "confirmed", "rejected", "inconclusive"},
    "unverified_artifact": {"validating", "rejected", "inconclusive"},
    "verified": {"confirmed"},
}

_VERDICT_TO_LIFECYCLE_STATE = {
    "CONFIRMED": "confirmed",
    "UNCONFIRMED": "rejected",
    "INCONCLUSIVE": "inconclusive",
    "ERROR": "inconclusive",
}


def _resolve_lifecycle_transition(from_state: str, to_state: str) -> tuple[bool, str]:
    allowed = FINDING_LIFECYCLE_TRANSITIONS.get(from_state or "")
    if allowed is None:
        return False, f"bilinmeyen mevcut durum: {from_state!r}"
    if to_state not in FINDING_LIFECYCLE_TRANSITIONS:
        return False, f"bilinmeyen hedef durum: {to_state!r}"
    if to_state not in allowed:
        return False, f"geçiş yasak: {from_state} -> {to_state} (izinli: {sorted(allowed) or 'yok'})"
    return True, ""

# ============================================================
# LEGACY TOOL'LAR (v1 backward compatibility)
# ============================================================

@memory_tool()
def store_finding(
    target: str,
    type: str,
    severity: str,
    description: str,
    payload: str = "",
    validation_result_json: str = "",
    validation_artifact_path: str = "",
) -> str:
    """Hafızaya yeni bir zafiyet/bulgu (finding) kaydet.
    Otomatik olarak Knowledge Graph'a da eklenir.

    `validation_result_json` veya `validation_artifact_path` verilirse doğrulama
    artifact'i payload alanından ayrı işlenir; payload gerçek exploit girdisi olarak kalır.
    """
    try:
        stored = _store_finding_internal(
            target,
            type,
            severity,
            description,
            payload=payload,
            validation_result_json=validation_result_json,
            validation_artifact_path=validation_artifact_path,
        )
        return _format_store_finding_result(stored["finding_id"], stored["validation_note"], stored["graph_error"])
    except Exception as e:
        return f"HATA: Bulgu kaydedilemedi: {str(e)}"


@memory_tool()
def update_finding_validation(
    finding_id: int,
    validation_result_json: str = "",
    validation_artifact_path: str = "",
    state: str = "",
) -> str:
    """Var olan bir bulguya sonradan doğrulama ekle / yaşam döngüsünü ilerlet.

    Async akış: store_finding (hipotez) -> validate -> bu tool ile confirmed/
    rejected/inconclusive. Fail-closed: reportable=1 YALNIZCA geçerli artifact +
    CONFIRMED verdict ile olur; doğrulamasız explicit state reportable açmaz.
    """
    to_state = (state or "").strip().lower()
    has_validation = bool((validation_result_json or "").strip() or (validation_artifact_path or "").strip())
    if not has_validation and not to_state:
        return json.dumps({"updated": False, "error": "validation veya state gerekli"}, ensure_ascii=False)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        requested_id = finding_id
        alias = conn.execute("SELECT canonical_id FROM finding_aliases WHERE alias_id=?", (finding_id,)).fetchone()
        if alias:
            finding_id = int(alias["canonical_id"])
        if os.environ.get("CCO_ENGAGEMENT_ID", "").strip():
            revision = _validator_mod.current_scope_revision() if validator_artifact_is_current else "scope:unknown"
            binding = conn.execute("SELECT context_key FROM finding_identity WHERE finding_id=?", (finding_id,)).fetchone()
            if not binding or binding["context_key"] != finding_context_key(revision):
                return json.dumps({"updated": False, "error": "finding is not in the active engagement"})
        row = conn.execute(
            "SELECT * FROM findings WHERE id=?",
            (finding_id,),
        ).fetchone()
        if row is None:
            return json.dumps({"updated": False, "error": f"finding yok: {finding_id}"}, ensure_ascii=False)
        from_state = row["validation_state"] or "unvalidated"
        validation = None
        if has_validation:
            validation = _extract_validation_metadata(
                "",
                validation_result_json,
                validation_artifact_path,
                finding_target=row["target"],
                finding_type=row["type"],
            )
            if not validation["validation_id"] and not validation["validation_artifact"]:
                return json.dumps(
                    {"updated": False, "error": "parse edilebilen validation artifact yok"},
                    ensure_ascii=False,
                )
            verdict_state = _VERDICT_TO_LIFECYCLE_STATE.get(validation["validation_verdict"], "")
            if to_state and to_state != verdict_state:
                return json.dumps(
                    {"updated": False,
                     "error": f"state/verdict çelişkisi: state={to_state} verdict={validation['validation_verdict']}"},
                    ensure_ascii=False,
                )
            to_state = verdict_state
            if validation["validation_verdict"] == "CONFIRMED" and not validation["reportable"]:
                to_state = "inconclusive"
        if not to_state:
            return json.dumps({"updated": False, "error": "hedef state çözülemedi"}, ensure_ascii=False)
        ok, reason = _resolve_lifecycle_transition(from_state, to_state)
        if not ok:
            return json.dumps(
                {"updated": False, "error": reason, "from_state": from_state},
                ensure_ascii=False,
            )
        reportable = int(row["reportable"] or 0)
        if validation is not None:
            reportable = int(validation["reportable"])
        elif reportable:
            current = _extract_validation_metadata(
                "", validation_artifact_path=row["validation_artifact"] or "",
                finding_target=row["target"], finding_type=row["type"])
            reportable = int(current["reportable"])
        if to_state == "confirmed" and not reportable:
            return json.dumps(
                {"updated": False,
                 "error": "confirmed için geçerli CONFIRMED artifact şart",
                 "from_state": from_state},
                ensure_ascii=False,
            )
        if validation is not None:
            for old in (dict(row), validation):
                if old.get("validation_id") and old.get("validation_artifact"):
                    conn.execute(
                        "INSERT OR IGNORE INTO finding_validation_history "
                        "(finding_id, validation_id, validation_artifact, validation_state, validation_verdict) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (finding_id, old["validation_id"], old["validation_artifact"],
                         old.get("validation_state") or "", old.get("validation_verdict") or ""))
        if validation is not None:
            conn.execute(
                "UPDATE findings SET validation_state=?, validation_artifact=?, validation_id=?, "
                "validation_verdict=?, validation_oracle=?, validation_evidence_grade=?, reportable=? "
                "WHERE id=?",
                (to_state, validation["validation_artifact"], validation["validation_id"],
                 validation["validation_verdict"], validation["validation_oracle"],
                 validation["validation_evidence_grade"], reportable, finding_id),
            )
        else:
            conn.execute(
                "UPDATE findings SET validation_state=?, reportable=? WHERE id=?",
                (to_state, reportable, finding_id),
            )
        current = dict(conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone())
        job_id = _enqueue_graph_projection(
            conn, f"finding:{finding_id}", "finding",
            {"id": finding_id, "target": current["target"], "type": current["type"],
             "severity": current["severity"], "description": current["description"] or "",
             "payload": current["payload"] or "", "validation_state": to_state,
             "validation_verdict": current["validation_verdict"],
             "validation_oracle": current["validation_oracle"],
             "validation_evidence_grade": current["validation_evidence_grade"],
             "reportable": bool(reportable)}, force=True,
        )
    error = _process_graph_job(job_id)
    return json.dumps({
        "updated": True,
        "finding_id": finding_id,
        "requested_finding_id": requested_id,
        "from_state": from_state,
        "to_state": to_state,
        "reportable": bool(reportable),
        "graph_error": error,
    }, ensure_ascii=False)


@memory_tool()
def store_validated_finding(
    target: str,
    type: str,
    severity: str,
    description: str,
    validation_result_json: str = "",
    validation_artifact_path: str = "",
    payload: str = "",
    report_markdown: str = "",
) -> str:
    """Artifact-backed CONFIRMED bir doğrulamayı finding + markdown rapor olarak kaydet.

    Bu helper fail-closed çalışır: doğrulama artifact'i verified/reportable değilse
    kaydetmez. Rapor markdown'u verilmezse validator'ın generate_validation_report
    çıktısı kullanılarak otomatik üretilir.
    """
    validation = _extract_validation_metadata(
        payload,
        validation_result_json,
        validation_artifact_path,
        finding_target=target,
        finding_type=type,
    )
    if validation["validation_state"] != "verified" or not validation["reportable"]:
        return json.dumps({
            "stored": False,
            "error": "validation artifact verified/reportable değil",
            "validation_state": validation["validation_state"],
            "validation_verdict": validation["validation_verdict"],
        }, indent=2, ensure_ascii=False)

    report_source = (validation_result_json or "").strip()
    if not report_source and validation["validation_artifact"]:
        try:
            with open(validation["validation_artifact"], encoding="utf-8") as handle:
                report_source = handle.read()
        except Exception:
            report_source = ""

    report_text = report_markdown or ""
    if not report_text and report_source and validator_generate_validation_report is not None:
        report_text = validator_generate_validation_report(report_source, target=target)

    stored = _store_finding_internal(
        target,
        type,
        severity,
        description,
        payload=payload,
        validation_result_json=validation_result_json,
        validation_artifact_path=validation_artifact_path,
    )
    report_path = _persist_validated_report(
        report_text,
        target,
        type,
        stored["validation"]["validation_id"],
    )
    if report_path:
        _update_finding_validation_report_path(stored["finding_id"], report_path)
    return json.dumps({
        "stored": True,
        "finding_id": stored["finding_id"],
        "store_message": _format_store_finding_result(stored["finding_id"], stored["validation_note"], stored["graph_error"]),
        "validation_id": stored["validation"]["validation_id"],
        "validation_artifact": stored["validation"]["validation_artifact"],
        "report_path": report_path,
        "report_generated": bool(report_path),
    }, indent=2, ensure_ascii=False)


@memory_tool()
def store_credential(
    target: str,
    service: str,
    username: str,
    password: str
) -> str:
    """Hafızaya ele geçirilmiş kimlik bilgisi (credential) kaydet.
    Knowledge Graph'ta credential chain otomatik oluşturulur."""
    if vault is None:
        return "HATA: Credential vault kullanılamıyor; plaintext credential storage reddedildi."
    try:
        stored_password = password or ""
        secret_ref = ""
        secret_backend = ""
        secret_ref = vault.store_secret(
            "credential_password",
            stored_password,
            {"target": target, "service": service, "username": username},
        )
        stored_password = "[REDACTED]"
        secret_backend = "fernet"
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute(
                "INSERT INTO credentials "
                "(target, service, username, password, secret_ref, secret_backend) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (target, service, username, stored_password, secret_ref, secret_backend)
            )
            cred_id = cursor.lastrowid
            job_id = _enqueue_graph_projection(
                conn,
                f"credential:{cred_id}",
                "credential",
                {
                    "id": cred_id,
                    "target": target,
                    "service": service,
                    "username": username,
                },
            )
        error = _process_graph_job(job_id)
        if error:
            return (
                f"Credential kaydedildi (ID: {cred_id}); graph projection beklemede: "
                f"{error}"
            )
        return f"Credential kaydedildi (ID: {cred_id}) + Knowledge Graph güncellendi ✓"
    except Exception as e:
        if secret_ref and vault is not None:
            try:
                vault.delete_secret(secret_ref)
            except Exception:
                gc_conn = sqlite3.connect(DB_PATH)
                _enqueue_vault_gc(gc_conn, secret_ref)
                gc_conn.commit()
                gc_conn.close()
        return f"HATA: Credential kaydedilemedi: {str(e)}"


@memory_tool()
def store_endpoint(
    target: str,
    url_or_port: str,
    protocol: str = "http",
    state: str = "open",
    technologies: str = ""
) -> str:
    """Hafızaya yeni keşfedilmiş bir port, servis veya URL endpoint kaydet.
    Knowledge Graph'a otomatik servis/software düğümleri eklenir."""
    try:
        existed = False
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM endpoints WHERE target=? AND url_or_port=?",
                (target, url_or_port)
            ).fetchone()
            if row:
                existed = True
                endpoint = dict(row)
            else:
                cursor = conn.execute(
                    "INSERT INTO endpoints "
                    "(target, url_or_port, protocol, state, technologies) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (target, url_or_port, protocol, state, technologies)
                )
                endpoint = {
                    "id": cursor.lastrowid,
                    "target": target,
                    "url_or_port": url_or_port,
                    "protocol": protocol,
                    "state": state,
                    "technologies": technologies,
                }
            job_id = _enqueue_graph_projection(
                conn,
                f"endpoint:{endpoint['id']}",
                "endpoint",
                endpoint,
                force=existed,
            )
        error = _process_graph_job(job_id)
        if error:
            return (
                f"Endpoint kaydedildi (ID: {endpoint['id']}); graph projection "
                f"beklemede: {error}"
            )
        if existed:
            return f"Endpoint ({url_or_port}) zaten hafızada mevcut; graph senkronize edildi."
        return f"Endpoint kaydedildi (ID: {endpoint['id']}) + Knowledge Graph güncellendi ✓"
    except Exception as e:
        return f"HATA: Endpoint kaydedilemedi: {str(e)}"


@memory_tool()
def ingest_surface(
    target: str,
    records_json: str = "",
    artifact_path: str = "",
    source_format: str = "records",
    source: str = "",
    max_records: int = 800,
) -> str:
    """Keşif çıktısını attack_surface kuyruğuna yaz. LLM'in ffuf/gau metnini
    parse etmesine gerek yok — JSON artifact veya kayıt listesi yeter.

    source_format: records | ffuf | nuclei | gau | wayback | sqlmap | openapi | urls | browser | xhr | zap
    """
    if not (target or "").strip():
        return json.dumps({"error": "target gerekli"}, ensure_ascii=False)
    payload = records_json
    if artifact_path:
        if not os.path.isfile(artifact_path):
            return json.dumps({"error": f"artifact yok: {artifact_path}"}, ensure_ascii=False)
        payload = artifact_path
    try:
        if (source_format or "records").lower() in {"records", "record", ""}:
            data = json.loads(records_json) if records_json else []
            if isinstance(data, dict) and "records" in data:
                records = data["records"]
            elif isinstance(data, list):
                records = data
            elif isinstance(data, dict) and data.get("url"):
                records = [data]
            else:
                records = parse_artifact(payload, source_format or "records", target=target)
        else:
            records = parse_artifact(payload, source_format, target=target)
        if source:
            for rec in records:
                if isinstance(rec, dict):
                    rec.setdefault("sources", [])
                    if source not in rec["sources"]:
                        rec["sources"] = list(rec.get("sources") or []) + [source]
        result = ingest_surface_records(
            records, target=target, db_path=DB_PATH, max_records=max_records
        )
        queue = next_surface_work_query(target, limit=10, db_path=DB_PATH)
        result["work_queue"] = queue.get("queue", [])
        result["total_surface"] = queue.get("total_surface", result.get("total_touched", 0))
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)


@memory_tool()
def next_surface_work(
    target: str,
    limit: int = 15,
    untested_only: bool = True,
    min_ev: float = 0.0,
    class_hint: str = "",
) -> str:
    """Hedef için sıralı fuzz/exploit kuyruğu — en yüksek EV surface kayıtları.

    Ajan keşif metnini tekrar okumak yerine bu kuyruktan çalışır.
    """
    if not (target or "").strip():
        return json.dumps({"error": "target gerekli"}, ensure_ascii=False)
    try:
        result = next_surface_work_query(
            target,
            limit=limit,
            untested_only=untested_only,
            min_ev=min_ev,
            class_hint=class_hint,
            db_path=DB_PATH,
        )
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)



@memory_tool()
def get_target_memory(target: str, limit: int = 20, summary: bool = False) -> str:
    """Belirtilen hedefle ilgili bulgulari, credential'lari ve endpoint'leri getirir.

    Context disiplini: her bolum varsayilan ilk `limit` kayda kesilir
    (limit<=0 tam dokum, acikca istendiginde). `summary=True` sadece
    sayaclar + en ust 3 kaydi dondurur. Kesilen bolumlerde `truncated`
    ve `total` alanlari her zaman bildirilir — detay kaybi sessiz olmaz.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        cap = None if limit is not None and limit <= 0 else (3 if summary else max(limit, 1))
        result = {"target": target, "findings": [], "credentials": [], "endpoints": [],
                  "attack_surface": {"total": 0, "untested": 0, "top": []}}

        def _take(rows):
            rows = [row for row in rows if target_query_matches(target, row["target"])]
            total = len(rows)
            return rows[:cap] if cap is not None else rows, total

        try:
            aliases = {int(row[0]): int(row[1]) for row in c.execute(
                "SELECT alias_id, canonical_id FROM finding_aliases")}
        except sqlite3.OperationalError:  # legacy DBs may predate the alias table
            aliases = {}
        all_findings = list(c.execute("SELECT * FROM findings"))
        if os.environ.get("CCO_ENGAGEMENT_ID", "").strip():
            try:
                bindings = {int(row[0]): row[1] for row in c.execute(
                    "SELECT finding_id, context_key FROM finding_identity")}
            except sqlite3.OperationalError:
                bindings = {}
            revision = _validator_mod.current_scope_revision() if validator_artifact_is_current else "scope:unknown"
            current_context = finding_context_key(revision)
            all_findings = [row for row in all_findings
                            if bindings.get(aliases.get(int(row["id"]), int(row["id"]))) == current_context]
        frows, ftotal = _take(all_findings)
        for row in frows:
            entry = _serialize_finding_row(row)
            if row["id"] in aliases:
                entry["canonical_finding_id"] = aliases[row["id"]]
                entry["historical_reportable"] = entry["reportable"]
                entry["reportable"] = False
            result["findings"].append(entry)
        if ftotal > len(result["findings"]):
            result["findings_truncated"] = {"total": ftotal, "shown": len(result["findings"])}

        crows, ctotal = _take(c.execute("SELECT * FROM credentials"))
        for row in crows:
            entry = dict(row)
            entry["password"] = "[REDACTED]"
            entry["has_secret"] = bool(entry.get("secret_ref"))
            entry.pop("secret_ref", None)
            entry.pop("secret_backend", None)
            result["credentials"].append(entry)
        if ctotal > len(result["credentials"]):
            result["credentials_truncated"] = {"total": ctotal, "shown": len(result["credentials"])}

        erows, etotal = _take(c.execute("SELECT * FROM endpoints"))
        for row in erows:
            result["endpoints"].append(dict(row))
        if etotal > len(result["endpoints"]):
            result["endpoints_truncated"] = {"total": etotal, "shown": len(result["endpoints"])}

        try:
            surface = next_surface_work_query(target, limit=10, untested_only=False, db_path=DB_PATH)
            result["attack_surface"] = {
                "total": surface.get("total_surface", 0),
                "untested": surface.get("untested", 0),
                "top": surface.get("queue", []),
            }
        except sqlite3.OperationalError:
            pass

        conn.close()

        # v2.0: Graph summary ekle
        graph_summary = kg.get_graph_summary(target)
        result["knowledge_graph"] = graph_summary

        if not any([result["findings"], result["credentials"], result["endpoints"],
                    result["attack_surface"].get("total")]) and graph_summary["total_nodes"] == 0:
            return f"Hedef '{target}' için hafızada herhangi bir veri bulunamadı."

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return f"HATA: Hafıza okunamadı: {str(e)}"


@memory_tool()
def drop_target_memory(target: str) -> str:
    """Belirtilen hedefle ilgili tüm kayıtları hafızadan tamamen siler (legacy + graph)."""
    if not target:
        return "HATA: Hedef boş olamaz."
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        findings = [dict(row) for row in c.execute(
            "SELECT id, type FROM findings WHERE target=?", (target,)
        )]
        credentials = [dict(row) for row in c.execute(
            "SELECT id, service, username, secret_ref FROM credentials WHERE target=?", (target,)
        )]
        endpoints = [dict(row) for row in c.execute(
            "SELECT id, url_or_port, protocol FROM endpoints WHERE target=?", (target,)
        )]

        node_ids = {f"target:{target}"}
        node_ids.update(
            f"finding:{row['type']}:{row['id']}" for row in findings
        )
        for row in credentials:
            node_ids.add(f"service:{target}:{row['service']}")
            node_ids.add(
                f"credential:{row['username']}@{row['service']}:{row['id']}"
            )
        node_ids.update(
            f"service:{target}:{row['url_or_port']}/{row['protocol']}"
            for row in endpoints
        )

        # Legacy
        c.execute("DELETE FROM finding_aliases WHERE alias_id IN (SELECT id FROM findings WHERE target=?) "
                  "OR canonical_id IN (SELECT id FROM findings WHERE target=?)", (target, target))
        c.execute("DELETE FROM finding_identity WHERE finding_id IN (SELECT id FROM findings WHERE target=?)", (target,))
        c.execute("DELETE FROM finding_validation_history WHERE finding_id IN (SELECT id FROM findings WHERE target=?)", (target,))
        c.execute("DELETE FROM findings WHERE target=?", (target,))
        c.execute("DELETE FROM credentials WHERE target=?", (target,))
        c.execute("DELETE FROM endpoints WHERE target=?", (target,))
        try:
            c.execute("DELETE FROM attack_surface WHERE target=?", (target,))
        except sqlite3.OperationalError:
            pass
        outbox_keys = (
            [f"finding:{row['id']}" for row in findings]
            + [f"credential:{row['id']}" for row in credentials]
            + [f"endpoint:{row['id']}" for row in endpoints]
        )
        if outbox_keys:
            placeholders = ",".join("?" for _ in outbox_keys)
            c.execute(
                f"DELETE FROM graph_outbox WHERE dedupe_key IN ({placeholders})",
                outbox_keys,
            )
        conn.commit()
        conn.close()

        if vault is not None:
            for row in credentials:
                if row.get("secret_ref"):
                    try:
                        vault.delete_secret(row["secret_ref"])
                    except Exception:
                        gc_conn = sqlite3.connect(DB_PATH)
                        _enqueue_vault_gc(gc_conn, row["secret_ref"])
                        gc_conn.commit()
                        gc_conn.close()

        kg.remove_nodes(list(node_ids))

        return f"'{target}' ile ilgili tüm hafıza ve graph verisi TEMİZLENDİ."
    except Exception as e:
        return f"HATA: Hafıza silinemedi: {str(e)}"


# ============================================================
# KNOWLEDGE GRAPH TOOL'LARI (v2.0 — Yeni)
# ============================================================

@memory_tool()
def add_relationship(
    source: str,
    target: str,
    relationship: str,
    properties: str = "",
    weight: float = 1.0,
    confidence: float = 0.5
) -> str:
    """Knowledge Graph'a ilişki (kenar) ekle.

    Node ID formatı: "tip:değer" (ör: "target:10.10.10.5", "service:ssh:22", "cve:CVE-2024-1234")

    Args:
        source: Kaynak düğüm ID'si
        target: Hedef düğüm ID'si
        relationship: İlişki tipi (HAS_PORT, RUNS, VULNERABLE_TO, EXPLOITABLE_BY,
                      WORKS_ON, GRANTS, CHAINS_WITH, CONNECTED_TO, LEADS_TO, REQUIRES)
        properties: JSON formatında ek özellikler (opsiyonel)
        weight: Kenar ağırlığı (0.0-1.0, saldırı path scoring için)
        confidence: Güven skoru (0.0-1.0)
    """
    from evidence_chaining import RELATIONS
    if relationship.strip().lower() in RELATIONS:
        return 'HATA: typed evidence relations require EvidenceGraph source-hash validation'
    try:
        props = json.loads(properties) if properties else {}
    except json.JSONDecodeError:
        props = {"raw": properties}

    edge_id = kg.add_edge(source, target, relationship, props, weight, confidence)
    return f"İlişki eklendi (ID: {edge_id}): {source} -[{relationship}]-> {target} (conf: {confidence})"


@memory_tool()
def query_attack_paths(
    from_node: str,
    to_node: str = "root",
    max_hops: int = 6
) -> str:
    """Knowledge Graph'ta iki düğüm arasındaki tüm saldırı yollarını bul ve skorla.
    Attack Path Planner: Her yol başarı olasılığına göre sıralanır.

    Args:
        from_node: Başlangıç düğümü (ör: "target:10.10.10.5")
        to_node: Hedef düğüm (ör: "root", "privilege:admin")
        max_hops: Maksimum adım sayısı
    """
    if not HAS_GRAPH:
        return "HATA: Graph backend yok. pip install kuzu (önerilen) veya networkx"

    try:
        paths = kg.get_attack_paths(from_node, to_node, max_hops=max_hops)
    except ValueError as exc:
        return f"HATA: {exc}"

    if not paths:
        # Tüm 'privilege' veya 'root' düğümlerini dene
        all_paths = []
        goal_nodes = [n for n in _graph_iter_nodes()
                      if "root" in n.lower() or "admin" in n.lower()
                      or _graph_node_type(n) == "privilege"]
        for goal in goal_nodes:
            gp = kg.get_attack_paths(from_node, goal, max_hops=max_hops)
            all_paths.extend(gp)

        if not all_paths:
            return f"'{from_node}' → '{to_node}' arasında saldırı yolu bulunamadı.\nGraph'a daha fazla veri ekleyin (store_finding, store_endpoint, add_relationship)."
        paths = sorted(all_paths, key=lambda x: x["score"], reverse=True)

    output = f"🗡️ Attack Paths: {from_node} → {to_node}\n{'='*60}\n"
    for i, p in enumerate(paths[:10], 1):
        output += f"\n#{i} [Skor: {p['score']:.4f}] ({p['hops']} adım)\n"
        output += f"  Yol: {' → '.join(p['path'])}\n"
        for edge in p["edges"]:
            output += f"    {edge['from']} -[{edge['relationship']}]→ {edge['to']} (güven: {edge['confidence']:.2f})\n"

    return output


@memory_tool()
def find_exploitable_chains(target: str) -> str:
    """Bir hedef için credential chain'leri ve exploit chain'lerini bul.
    Multi-hop reasoning: 'Bu SSH key ile S3 bucket'a erişilebilir mi?'

    Args:
        target: Hedef IP/domain
    """
    if not HAS_GRAPH:
        return "HATA: Graph backend yok. pip install kuzu (önerilen) veya networkx"

    output = f"🔗 Exploit Chain Analizi: {target}\n{'='*60}\n"

    # Credential chains — credential node ID'si target içermez;
    # hedefin servislerine WORKS_ON ile bağlı credential'ları bul
    cred_set = set()
    for n in _graph_iter_nodes(target):
        if _graph_node_type(n) in ("service", "target"):
            for pred in _graph_predecessors(n):
                if "credential" in pred:
                    cred_set.add(pred)
        if "credential" in n:
            cred_set.add(n)
    cred_nodes = sorted(cred_set)
    if cred_nodes:
        output += f"\n📋 Credential Chain'ler ({len(cred_nodes)} credential):\n"
        for cred in cred_nodes:
            chains = kg.find_credential_chains(cred)
            if chains:
                for chain in chains:
                    output += f"  🔑 {chain['credential']} → {chain['service']} → {chain['privilege']} (güven: {chain['confidence']:.2f})\n"
            else:
                output += f"  🔑 {cred} → (chain bulunamadı — diğer servislerde deneyin)\n"
    else:
        output += "\n📋 Credential bulunamadı.\n"

    # Finding exploit chains
    finding_nodes = [n for n in _graph_iter_nodes() if "finding" in n]
    target_findings = [n for n in finding_nodes
                       if any(target in pred for pred in _graph_predecessors(n))]
    if target_findings:
        output += f"\n⚡ Exploit Chain'ler ({len(target_findings)} finding):\n"
        for finding in target_findings:
            chains = kg.find_exploit_chains(finding)
            if chains:
                for chain in chains:
                    output += f"  💥 {' → '.join(chain)}\n"
            else:
                output += f"  💥 {finding} → (zincir bulunamadı)\n"
    else:
        output += "\n⚡ Finding bulunamadı.\n"

    return output


@memory_tool()
def get_knowledge_graph_summary(target: str = "") -> str:
    """Knowledge Graph'ın genel özetini döndür.

    Args:
        target: Filtre (opsiyonel — boş bırakılırsa tüm graph)
    """
    summary = kg.get_graph_summary(target)

    output = f"📊 Knowledge Graph Özeti{f' ({target})' if target else ''}\n{'='*50}\n"
    output += f"Backend: {GRAPH_BACKEND} ({'KuzuDB Cypher — hızlı multi-hop' if GRAPH_BACKEND == 'kuzu' else 'NetworkX in-memory'})\n"
    output += f"Toplam düğüm: {summary['total_nodes']}\n"
    output += f"Toplam ilişki: {summary['total_edges']}\n"

    if summary["nodes_by_type"]:
        output += "\nDüğüm Tipleri:\n"
        for ntype, count in sorted(summary["nodes_by_type"].items()):
            emoji = {"target": "🎯", "service": "⚙️", "software": "📦", "cve": "🐛",
                     "credential": "🔑", "finding": "💥", "privilege": "👑", "endpoint": "🌐"}.get(ntype, "📍")
            output += f"  {emoji} {ntype}: {count}\n"

    if summary["edges_by_relationship"]:
        output += "\nİlişki Tipleri:\n"
        for rel, count in sorted(summary["edges_by_relationship"].items()):
            output += f"  → {rel}: {count}\n"

    if summary["targets"]:
        output += "\nKayıtlı Hedefler:\n"
        for t in summary["targets"]:
            output += f"  🎯 {t}\n"

    return output


@memory_tool()
def suggest_next_action(target: str) -> str:
    """Knowledge Graph'a bakarak hedef için en yüksek öncelikli sonraki adımı öner.
    Graph'taki boşlukları tespit eder ve akıllı öneriler sunar.

    Args:
        target: Hedef IP/domain
    """
    if not HAS_GRAPH:
        return "HATA: Graph backend yok. pip install kuzu (önerilen) veya networkx"

    result = kg.suggest_next_action(target)

    output = f"🧠 Akıllı Öneri: {target}\n{'='*50}\n"
    output += f"İlişkili düğüm: {result.get('graph_stats', {}).get('related_nodes', 0)}\n\n"

    if "suggestion" in result:
        output += f"💡 {result['suggestion']}\n"
    elif "suggestions" in result:
        for i, s in enumerate(result["suggestions"][:5], 1):
            priority_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(s["priority"], "⚪")
            output += f"{priority_emoji} #{i} [{s['priority'].upper()}] {s['action']}\n"
            output += f"   Gerekçe: {s['reason']}\n\n"

    return output


@memory_tool()
def suggest_lateral_moves(target: str) -> str:
    """Hedef icin yanal-hareket (lateral movement) plani oner — SADECE PLAN, calistirma yok.

    Vault'taki kimlikleri (secret DEGIL, referans), acik servisleri ve
    knowledge-graph saldiri yollarini birlestirip sirali somut adim listesi
    uretir. Her adim ayri onay ister (needs_approval=true); secret degerleri
    ciktiya ASLA girmez — yalnizca `vault:credentials#<id>` referansi.

    Args:
        target: Hedef IP/domain (credential/endpoint eslesmesi icin alt-string)
    """
    plan: dict = {"target": target, "moves": [], "attack_paths": [], "notes": []}
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        creds = [dict(r) for r in conn.execute(
            "SELECT id, target, service, username, timestamp FROM credentials "
            "WHERE target LIKE ? ORDER BY id", (f"%{target}%",))]
        endpoints = [dict(r) for r in conn.execute(
            "SELECT target, url_or_port, protocol, state, technologies FROM endpoints "
            "WHERE target LIKE ?", (f"%{target}%",))]
        conn.close()
    except Exception as exc:
        return json.dumps({"error": f"memory okuma hatasi: {exc}"}, ensure_ascii=False)

    services_by_host: dict[str, set[str]] = {}
    for e in endpoints:
        services_by_host.setdefault(e.get("target") or "", set()).add((e.get("protocol") or "").lower())

    def move(rank: int, action: str, tool: str, detail: str, risk: str = "medium",
             credential_ref: str = "") -> dict:
        return {"rank": rank, "action": action, "tool": tool, "detail": detail,
                "risk": risk, "credential_ref": credential_ref, "needs_approval": True}

    rank = 0
    # 1) Bilinen kimlik × acik servis eslesmesi
    for cred in creds:
        rank += 1
        svc = (cred.get("service") or "").lower()
        host_services = services_by_host.get(cred.get("target") or "", set())
        ref = f"vault:credentials#{cred['id']}"
        if svc in {"smb", "windows", "rdp", "winrm", "wmi"} or host_services & {"smb", "rdp", "winrm", "wmi"}:
            plan["moves"].append(move(
                rank, "reuse_credential", "ad-tools_ad_exec",
                f"{cred['username']}@{cred['target']} ile WMI/SMB komut denemesi",
                "high", ref))
        elif svc in {"ssh", "linux"} or "ssh" in host_services:
            plan["moves"].append(move(
                rank, "reuse_credential", "kali-tools_shell_exec",
                f"{cred['username']}@{cred['target']} ile SSH erisim denemesi (sshpass -e, vault'tan)",
                "high", ref))
        elif svc in {"ftp", "telnet", "smtp", "http-basic"}:
            plan["moves"].append(move(
                rank, "reuse_credential", "kali-tools_hydra_brute",
                f"{cred['service']} uzerinde bilinen kimlikle dogrulama denemesi",
                "medium", ref))
        else:
            plan["moves"].append(move(
                rank, "reuse_credential", "kali-tools_shell_exec",
                f"{cred['username']} kimligini {cred['service'] or 'acik servislere'} karsi dene",
                "medium", ref))

    # 2) Kimlik yoksa: privesc numaralandirma + spray adaylari
    if not creds:
        plan["notes"].append("Kayitli kimlik yok: once privesc_scan_local / ad_winpeas_run ile yerel numaralandirma yap.")
        users = sorted({(c.get("username") or "") for c in creds if c.get("username")})
        if users:
            rank += 1
            plan["moves"].append(move(
                rank, "password_spray", "osint-tools_password_spray_structured",
                f"{len(users)} bilinen kullaniciya dusuk-hizli spray adayi", "medium"))

    # 3) Graph saldiri yollari (best-effort zenginlestirme)
    if HAS_GRAPH:
        try:
            for goal in ("root", "privilege:admin", "domain-admin"):
                paths = kg.get_attack_paths(f"target:{target}", goal, max_hops=5)
                for p in (paths or [])[:3]:
                    plan["attack_paths"].append({
                        "goal": goal, "score": round(p.get("score", 0.0), 4),
                        "path": p.get("path", []),
                    })
                if plan["attack_paths"]:
                    break
        except (ValueError, AttributeError, KeyError):
            plan["notes"].append("Graph yolu bulunamadi: store_finding/store_endpoint ile graph'i besle.")

    plan["moves"].sort(key=lambda m: m["rank"])
    return json.dumps(plan, indent=2, ensure_ascii=False)


# ============================================================
# SERVER BAŞLAT
# ============================================================

if __name__ == "__main__":
    mcp.run()
