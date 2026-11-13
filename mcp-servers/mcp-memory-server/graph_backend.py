#!/usr/bin/env python3
"""
KuzuGraph — KuzuDB tabanlı Knowledge Graph backend'i.
NetworkX backend'iyle (KnowledgeGraph) API-uyumlu; drop-in replacement.

Avantajları:
- Cypher sorgu dili: multi-hop path sorguları DB katmanında çalışır (100-1000x hız)
- Embedded: ek servis gerekmez (SQLite gibi dosya tabanlı)
- ACID transaction'lar, kalıcı disk depolama
- Bellek sınırı yok: NetworkX tüm graph'ı RAM'de tutar, KuzuDB disk'ten stream eder

Şema:
    NODE TABLE Node(id, node_type, label, properties, PRIMARY KEY(id))
    REL  TABLE REL(FROM Node TO Node, relationship, properties, weight, confidence)
"""

import hashlib
import json
import os
import sqlite3

try:
    import kuzu
    HAS_KUZU = True
except ImportError:
    HAS_KUZU = False


class KuzuGraph:
    """KuzuDB knowledge graph — KnowledgeGraph (NetworkX) ile aynı public API."""

    NODE_TYPES = ["target", "service", "software", "cve", "credential", "finding", "privilege", "endpoint", "subdomain"]

    RELATIONSHIP_TYPES = [
        "HAS_PORT", "RUNS", "VULNERABLE_TO", "EXPLOITABLE_BY",
        "WORKS_ON", "GRANTS", "CHAINS_WITH", "CONNECTED_TO",
        "BELONGS_TO", "DISCOVERED_BY", "LEADS_TO", "REQUIRES"
    ]

    TECHNIQUE_SUCCESS_PROBS = {
        "sql_injection": 0.85, "sql_injection_blind": 0.65,
        "xss_stored": 0.90, "xss_reflected": 0.80, "xss_dom": 0.70,
        "rce": 0.95, "command_injection": 0.90,
        "ssrf": 0.70, "ssrf_blind": 0.50, "idor": 0.80,
        "lfi": 0.75, "rfi": 0.60, "file_upload": 0.65,
        "ssti": 0.75, "xxe": 0.70, "deserialization": 0.60,
        "buffer_overflow": 0.55, "format_string": 0.50,
        "heap_overflow": 0.45, "use_after_free": 0.40,
        "race_condition": 0.35, "authentication_bypass": 0.70,
        "privilege_escalation": 0.65, "default_credentials": 0.90,
        "weak_credentials": 0.80, "credential_reuse": 0.75,
        "subdomain_takeover": 0.85, "cors_misconfiguration": 0.60,
        "open_redirect": 0.50, "csrf": 0.55, "jwt_attack": 0.65,
        "path_traversal": 0.70,
    }

    def __init__(self, db_path: str):
        """db_path: KuzuDB dizini (ör. ~/.cco/kuzu_graph)."""
        if not HAS_KUZU:
            raise ImportError("kuzu kurulu değil. pip install kuzu")

        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path.rstrip("/")) or ".", exist_ok=True)
        self.db = kuzu.Database(db_path)
        self.conn = kuzu.Connection(self.db)
        self._init_schema()

    def _init_schema(self):
        """Node/REL/meta tablolarını oluştur ve mevcut şemayı yükselt."""
        try:
            self.conn.execute(
                "CREATE NODE TABLE Node("
                "  id STRING, node_type STRING, label STRING, properties STRING,"
                "  PRIMARY KEY(id)"
                ")"
            )
        except RuntimeError as e:
            if "already exists" not in str(e).lower():
                raise

        try:
            self.conn.execute(
                "CREATE REL TABLE REL("
                "  FROM Node TO Node,"
                "  relationship STRING, properties STRING,"
                "  weight DOUBLE, confidence DOUBLE, edge_id INT64"
                ")"
            )
        except RuntimeError as e:
            if "already exists" not in str(e).lower():
                raise

        try:
            self.conn.execute("ALTER TABLE REL ADD edge_id INT64 DEFAULT 0")
        except RuntimeError as e:
            message = str(e).lower()
            if "already exists" not in message and "already has property" not in message:
                raise

        try:
            self.conn.execute(
                "CREATE NODE TABLE GraphMeta("
                "  key STRING, value STRING, PRIMARY KEY(key)"
                ")"
            )
        except RuntimeError as e:
            if "already exists" not in str(e).lower():
                raise

        self._upgrade_schema()

    @staticmethod
    def _stable_edge_id(source_id: str, target_id: str) -> int:
        """DiGraph edge kimliği; process'ler arasında deterministiktir."""
        raw = f"{source_id}\0{target_id}".encode("utf-8")
        return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big") & ((1 << 63) - 1)

    def _get_meta(self, key: str) -> str:
        result = self.conn.execute(
            "MATCH (m:GraphMeta {key: $key}) RETURN m.value LIMIT 1",
            parameters={"key": key}
        )
        return result.get_next()[0] if result.has_next() else ""

    def _set_meta(self, key: str, value: str):
        self.conn.execute(
            "MERGE (m:GraphMeta {key: $key}) SET m.value = $value",
            parameters={"key": key, "value": value}
        )

    def _upgrade_schema(self):
        """Eski parallel edge'leri DiGraph semantiğine göre tekilleştir."""
        if self._get_meta("schema_version") == "2":
            return

        result = self.conn.execute(
            "MATCH (a:Node)-[e:REL]->(b:Node) "
            "RETURN a.id, b.id, e.relationship, e.properties, e.weight, e.confidence"
        )
        logical_edges = {}
        while result.has_next():
            row = result.get_next()
            logical_edges[(row[0], row[1])] = row[2:]

        self.conn.execute("BEGIN TRANSACTION")
        try:
            self.conn.execute("MATCH ()-[e:REL]->() DELETE e")
            for (source_id, target_id), edge in logical_edges.items():
                self._upsert_edge(
                    source_id,
                    target_id,
                    edge[0],
                    edge[1] or "{}",
                    edge[2],
                    edge[3],
                )
            self._set_meta("schema_version", "2")
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    # ---------------------------------------------------------------
    # Yazma
    # ---------------------------------------------------------------

    @staticmethod
    def _now_iso() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _props_expired(props: dict | None) -> bool:
        valid_to = (props or {}).get("valid_to")
        return bool(valid_to) and str(valid_to) < KuzuGraph._now_iso()

    def _get_node_props(self, node_id: str) -> dict:
        try:
            r = self.conn.execute(
                "MATCH (n:Node {id: $id}) RETURN n.properties", parameters={"id": node_id})
            if r.has_next():
                return json.loads(r.get_next()[0] or "{}")
        except Exception:
            pass
        return {}

    def add_node(self, node_id: str, node_type: str, label: str = "", properties: dict = None) -> str:
        merged = self._get_node_props(node_id)
        merged.update(properties or {})
        merged.setdefault("valid_from", self._now_iso())
        merged["updated_at"] = self._now_iso()
        self._upsert_node(node_id, node_type, label or node_id, json.dumps(merged))
        return node_id

    def supersede_node(self, node_id: str, superseded_by: str = "") -> str:
        props = {"valid_to": self._now_iso()}
        if superseded_by:
            props["superseded_by"] = superseded_by
        node_type = "unknown"
        try:
            node_type = str(self.get_node_type(node_id) or "unknown")
        except Exception:
            pass
        return self.add_node(node_id, node_type, properties=props)

    def _upsert_node(self, node_id: str, node_type: str, label: str, props_json: str):
        self.conn.execute(
            "MERGE (n:Node {id: $id}) "
            "SET n.node_type = $ntype, n.label = $label, n.properties = $props",
            parameters={"id": node_id, "ntype": node_type,
                        "label": label, "props": props_json}
        )

    def add_edge(self, source_id: str, target_id: str, relationship: str,
                 properties: dict = None, weight: float = 1.0, confidence: float = 0.5) -> int:
        # Node'lar yoksa otomatik oluştur
        self._ensure_node(source_id)
        self._ensure_node(target_id)

        props_json = json.dumps(properties or {})
        return self._upsert_edge(
            source_id, target_id, relationship, props_json, weight, confidence
        )

    def _upsert_edge(self, source_id: str, target_id: str, relationship: str,
                     props_json: str, weight: float, confidence: float) -> int:
        edge_id = self._stable_edge_id(source_id, target_id)
        self.conn.execute(
            "MATCH (a:Node {id: $src}), (b:Node {id: $dst}) "
            "MERGE (a)-[e:REL]->(b) "
            "SET e.relationship = $rel, e.properties = $props, "
            "    e.weight = $w, e.confidence = $c, e.edge_id = $edge_id",
            parameters={"src": source_id, "dst": target_id, "rel": relationship,
                        "props": props_json, "w": float(weight), "c": float(confidence),
                        "edge_id": edge_id}
        )
        return edge_id

    def _ensure_node(self, node_id: str):
        ntype = node_id.split(":")[0] if ":" in node_id else "unknown"
        self.conn.execute(
            "MERGE (n:Node {id: $id}) "
            "ON CREATE SET n.node_type = $ntype, n.label = $id, n.properties = '{}'",
            parameters={"id": node_id, "ntype": ntype}
        )

    def remove_nodes(self, node_ids: list):
        """Verilen exact node ID'lerini ve bağlı edge'leri sil."""
        unique_ids = sorted(set(node_ids))
        if not unique_ids:
            return
        self.conn.execute("BEGIN TRANSACTION")
        try:
            for node_id in unique_ids:
                self.conn.execute(
                    "MATCH (n:Node {id: $id}) DETACH DELETE n",
                    parameters={"id": node_id}
                )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def remove_target_subgraph(self, target_node_id: str):
        """Geriye uyumlu exact-node silme yardımcısı."""
        self.remove_nodes([target_node_id])

    # ---------------------------------------------------------------
    # Okuma — NetworkX uyumlu API
    # ---------------------------------------------------------------

    def _node_exists(self, node_id: str) -> bool:
        r = self.conn.execute(
            "MATCH (n:Node {id: $id}) RETURN count(n) AS c",
            parameters={"id": node_id}
        )
        return r.get_next()[0] > 0

    def query_neighbors(self, node_id: str, direction: str = "both",
                        include_expired: bool = False) -> dict:
        result = {"node": node_id, "outgoing": [], "incoming": []}

        if direction in ("out", "both"):
            r = self.conn.execute(
                "MATCH (a:Node {id: $id})-[e:REL]->(b:Node) "
                "RETURN b.id AS target, e.relationship AS relationship, "
                "       e.weight AS weight, e.confidence AS confidence, e.properties AS properties",
                parameters={"id": node_id}
            )
            while r.has_next():
                row = r.get_next()
                if not include_expired and self._props_expired(self._get_node_props(row[0])):
                    continue
                props = json.loads(row[4]) if row[4] else {}
                result["outgoing"].append({
                    "target": row[0], "relationship": row[1],
                    "weight": row[2], "confidence": row[3], **props
                })

        if direction in ("in", "both"):
            r = self.conn.execute(
                "MATCH (a:Node)-[e:REL]->(b:Node {id: $id}) "
                "RETURN a.id AS source, e.relationship AS relationship, "
                "       e.weight AS weight, e.confidence AS confidence, e.properties AS properties",
                parameters={"id": node_id}
            )
            while r.has_next():
                row = r.get_next()
                if not include_expired and self._props_expired(self._get_node_props(row[0])):
                    continue
                props = json.loads(row[4]) if row[4] else {}
                result["incoming"].append({
                    "source": row[0], "relationship": row[1],
                    "weight": row[2], "confidence": row[3], **props
                })

        return result

    def find_shortest_path(self, source: str, target: str) -> list:
        """Cypher SHORTEST — DB katmanında çalışır."""
        r = self.conn.execute(
            "MATCH p = (a:Node {id: $src})-[:REL* SHORTEST]->(b:Node {id: $dst}) "
            "RETURN list_transform(nodes(p), n -> n.id) AS path LIMIT 1",
            parameters={"src": source, "dst": target}
        )
        if r.has_next():
            return r.get_next()[0]
        return []

    def find_all_paths(self, source: str, target: str, max_hops: int = 6) -> list:
        """Tüm acyclic path'ler (max_hops sınırıyla) — Cypher'da çalışır."""
        max_hops = int(max_hops)
        if max_hops < 1:
            return []
        if max_hops > 16:
            raise ValueError("max_hops 16'dan büyük olamaz")
        if not (self._node_exists(source) and self._node_exists(target)):
            return []
        r = self.conn.execute(
            f"MATCH p = (a:Node {{id: $src}})-[:REL*1..{max_hops}]->(b:Node {{id: $dst}}) "
            "RETURN list_transform(nodes(p), n -> n.id) AS path LIMIT 100",
            parameters={"src": source, "dst": target}
        )
        paths = []
        while r.has_next():
            p = r.get_next()[0]
            if len(p) == len(set(p)):
                paths.append(p)
        return paths

    def get_attack_paths(self, target_node: str, goal: str = "root",
                         max_hops: int = 8) -> list:
        paths = self.find_all_paths(target_node, goal, max_hops=max_hops)

        scored = []
        for path in paths:
            edges_info = []
            probability = 1.0
            for i in range(len(path) - 1):
                edge = self._get_edge(path[i], path[i + 1])
                conf = edge.get("confidence", 0.5)
                probability *= conf
                edges_info.append({
                    "from": path[i], "to": path[i + 1],
                    "relationship": edge.get("relationship", "?"),
                    "confidence": conf
                })
            hops = len(path) - 1
            score = round(probability * (1.0 / (1 + 0.1 * hops)), 4)
            scored.append({"path": path, "edges": edges_info, "score": score, "hops": hops})

        return sorted(scored, key=lambda x: x["score"], reverse=True)

    def _get_edge(self, source: str, target: str) -> dict:
        r = self.conn.execute(
            "MATCH (a:Node {id: $src})-[e:REL]->(b:Node {id: $dst}) "
            "RETURN e.relationship, e.weight, e.confidence LIMIT 1",
            parameters={"src": source, "dst": target}
        )
        if r.has_next():
            row = r.get_next()
            return {"relationship": row[0], "weight": row[1], "confidence": row[2]}
        return {}

    def find_credential_chains(self, credential_node: str) -> list:
        """credential -[WORKS_ON]-> service -[GRANTS]-> privilege (tek Cypher sorgu)."""
        if not self._node_exists(credential_node):
            return []
        r = self.conn.execute(
            "MATCH (c:Node {id: $cred})-[e1:REL]->(s:Node)-[e2:REL]->(p:Node) "
            "WHERE e1.relationship = 'WORKS_ON' AND e2.relationship = 'GRANTS' "
            "RETURN s.id AS service, p.id AS privilege, "
            "       e1.confidence * e2.confidence AS chain_conf",
            parameters={"cred": credential_node}
        )
        chains = []
        while r.has_next():
            row = r.get_next()
            chains.append({
                "credential": credential_node,
                "service": row[0], "privilege": row[1],
                "confidence": row[2]
            })
        return chains

    def find_exploit_chains(self, finding_node: str) -> list:
        """CHAINS_WITH üzerinden tüm exploit zincirleri (variable-length)."""
        if not self._node_exists(finding_node):
            return []
        r = self.conn.execute(
            "MATCH p = (f:Node {id: $start})-[e:REL*1..5]->(g:Node) "
            "WHERE size(list_filter(relationships(p), x -> x.relationship <> 'CHAINS_WITH')) = 0 "
            "RETURN list_transform(nodes(p), n -> n.id) AS chain LIMIT 50",
            parameters={"start": finding_node}
        )
        chains = []
        while r.has_next():
            chain = r.get_next()[0]
            if len(chain) == len(set(chain)):
                chains.append(chain)
        return chains

    def get_graph_summary(self, target_filter: str = "") -> dict:
        summary = {
            "total_nodes": 0, "total_edges": 0,
            "nodes_by_type": {}, "edges_by_relationship": {},
            "targets": []
        }

        if target_filter:
            r = self.conn.execute(
                "MATCH (n:Node) WHERE n.id CONTAINS $f "
                "RETURN n.node_type AS t, count(*) AS c",
                parameters={"f": target_filter}
            )
        else:
            r = self.conn.execute(
                "MATCH (n:Node) RETURN n.node_type AS t, count(*) AS c"
            )
        while r.has_next():
            row = r.get_next()
            summary["nodes_by_type"][row[0]] = row[1]
            summary["total_nodes"] += row[1]

        if target_filter:
            r = self.conn.execute(
                "MATCH (a:Node)-[e:REL]->(b:Node) "
                "WHERE a.id CONTAINS $f OR b.id CONTAINS $f "
                "RETURN e.relationship AS rel, count(*) AS c",
                parameters={"f": target_filter}
            )
        else:
            r = self.conn.execute(
                "MATCH ()-[e:REL]->() RETURN e.relationship AS rel, count(*) AS c"
            )
        while r.has_next():
            row = r.get_next()
            summary["edges_by_relationship"][row[0]] = row[1]
            summary["total_edges"] += row[1]

        r = self.conn.execute(
            "MATCH (n:Node) WHERE n.node_type = 'target' RETURN DISTINCT n.id"
        )
        while r.has_next():
            summary["targets"].append(r.get_next()[0])

        return summary

    def suggest_next_action(self, target: str) -> dict:
        """Graph boşluklarını tespit edip öneri üret (Cypher'da)."""
        r = self.conn.execute(
            "MATCH (n:Node) WHERE n.id CONTAINS $t RETURN n.id AS id, n.node_type AS t",
            parameters={"t": target}
        )
        target_nodes = []
        while r.has_next():
            row = r.get_next()
            target_nodes.append((row[0], row[1]))

        if not target_nodes:
            return {"suggestion": f"'{target}' ile ilişkili veri bulunamadı. Önce keşif yapın."}

        suggestions = []

        # Zafiyet analizi yapılmamış servisler
        r = self.conn.execute(
            "MATCH (s:Node) WHERE s.id CONTAINS $t AND s.node_type = 'service' "
            "AND NOT EXISTS { MATCH (s)-[e:REL]->(:Node) WHERE e.relationship = 'VULNERABLE_TO' } "
            "RETURN s.id",
            parameters={"t": target}
        )
        while r.has_next():
            node = r.get_next()[0]
            suggestions.append({
                "action": f"Zafiyet taraması yap: {node}",
                "priority": "high",
                "reason": "Servis keşfedildi ama zafiyet analizi yapılmadı"
            })

        # Exploit'i olmayan CVE'ler
        r = self.conn.execute(
            "MATCH (c:Node) WHERE c.id CONTAINS $t AND c.node_type = 'cve' "
            "AND NOT EXISTS { MATCH (c)-[e:REL]->(:Node) WHERE e.relationship = 'EXPLOITABLE_BY' } "
            "RETURN c.id",
            parameters={"t": target}
        )
        while r.has_next():
            node = r.get_next()[0]
            suggestions.append({
                "action": f"Exploit ara: {node}",
                "priority": "critical",
                "reason": "CVE bulundu ama exploit henüz yok"
            })

        # Chain edilmemiş credential'lar
        for node_id, ntype in target_nodes:
            if ntype == "credential" and not self.find_credential_chains(node_id):
                suggestions.append({
                    "action": f"Credential test et: {node_id} → diğer servislerde dene",
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
            "suggestions": sorted(
                suggestions,
                key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["priority"], 4)
            ),
            "graph_stats": {
                "related_nodes": len(target_nodes),
                "total_graph_nodes": self.get_graph_summary()["total_nodes"],
                "total_graph_edges": self.get_graph_summary()["total_edges"]
            }
        }

    def iter_nodes(self, id_filter: str = "") -> list:
        """Node ID listesi döndür (server.py'deki NetworkX kg.G.nodes() kullanımının
        backend-agnostic eşdeğeri)."""
        if id_filter:
            r = self.conn.execute(
                "MATCH (n:Node) WHERE n.id CONTAINS $f RETURN n.id",
                parameters={"f": id_filter}
            )
        else:
            r = self.conn.execute("MATCH (n:Node) RETURN n.id")
        nodes = []
        while r.has_next():
            nodes.append(r.get_next()[0])
        return nodes

    def get_node_type(self, node_id: str) -> str:
        r = self.conn.execute(
            "MATCH (n:Node {id: $id}) RETURN n.node_type LIMIT 1",
            parameters={"id": node_id}
        )
        if r.has_next():
            return r.get_next()[0] or "unknown"
        return "unknown"

    def get_predecessors(self, node_id: str) -> list:
        r = self.conn.execute(
            "MATCH (a:Node)-[:REL]->(b:Node {id: $id}) RETURN a.id",
            parameters={"id": node_id}
        )
        preds = []
        while r.has_next():
            preds.append(r.get_next()[0])
        return preds

    # ---------------------------------------------------------------
    # SQLite → KuzuDB migration yardımcısı
    # ---------------------------------------------------------------

    @staticmethod
    def _sqlite_graph_rows(sqlite_db_path: str):
        conn = sqlite3.connect(sqlite_db_path)
        conn.row_factory = sqlite3.Row
        try:
            nodes = [dict(row) for row in conn.execute(
                "SELECT id, node_type, label, properties FROM graph_nodes ORDER BY id"
            )]
            edge_rows = [dict(row) for row in conn.execute(
                "SELECT id, source_id, target_id, relationship, properties, weight, confidence "
                "FROM graph_edges ORDER BY id"
            )]
        except sqlite3.OperationalError:
            nodes, edge_rows = [], []
        finally:
            conn.close()

        logical_edges = {}
        for row in edge_rows:
            logical_edges[(row["source_id"], row["target_id"])] = row
        return nodes, edge_rows, logical_edges

    @classmethod
    def sqlite_fingerprint(cls, sqlite_db_path: str) -> str:
        nodes, edge_rows, _ = cls._sqlite_graph_rows(sqlite_db_path)
        payload = json.dumps(
            {"nodes": nodes, "edges": edge_rows},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def import_from_sqlite(self, sqlite_db_path: str) -> dict:
        """SQLite graph projection'ını transaction ve fingerprint ile aktar."""
        nodes, edge_rows, logical_edges = self._sqlite_graph_rows(sqlite_db_path)
        if not nodes and not edge_rows:
            return {"nodes": 0, "edges": 0, "source_edges": 0, "skipped": True}

        fingerprint = self.sqlite_fingerprint(sqlite_db_path)
        if self._get_meta("sqlite_migration_v1") == fingerprint:
            return {
                "nodes": len(nodes),
                "edges": len(logical_edges),
                "source_edges": len(edge_rows),
                "skipped": True,
            }

        self.conn.execute("BEGIN TRANSACTION")
        try:
            for row in nodes:
                props = json.loads(row["properties"]) if row["properties"] else {}
                self._upsert_node(
                    row["id"], row["node_type"], row["label"] or row["id"],
                    json.dumps(props)
                )
            for row in logical_edges.values():
                self._ensure_node(row["source_id"])
                self._ensure_node(row["target_id"])
                props = json.loads(row["properties"]) if row["properties"] else {}
                self._upsert_edge(
                    row["source_id"], row["target_id"], row["relationship"],
                    json.dumps(props), row["weight"], row["confidence"]
                )

            current_nodes = set(self.iter_nodes())
            missing = {row["id"] for row in nodes} - current_nodes
            if missing:
                raise RuntimeError(f"Kuzu migration eksik node bıraktı: {sorted(missing)[:3]}")

            self._set_meta("sqlite_migration_v1", fingerprint)
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

        return {
            "nodes": len(nodes),
            "edges": len(logical_edges),
            "source_edges": len(edge_rows),
            "skipped": False,
        }
