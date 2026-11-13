"""Ortak tablo şema sözleşmesi (tek kaynak).

agent_memory.db'deki PAYLAŞILAN tablolar (birden çok MCP sunucusunun doğrudan
SQL ile okuduğu/yazdığı): attack_surface, endpoints, findings. Bu modül kolon
listelerinin kanonik kaynağıdır; tests/test_schema_contract.py tüm kaynak
ağacındaki INSERT/UPDATE/CREATE literallerini bu kayıtla karşılaştırır.
"""
from __future__ import annotations

SHARED_TABLES: dict[str, tuple[str, ...]] = {
    "attack_surface": (
        "id", "fingerprint", "target", "url", "method", "host", "path",
        "params_json", "status", "content_type", "title", "body_hash",
        "body_len", "auth_required", "tech_json", "sources_json",
        "ev_score", "tested_classes", "queued_classes", "created_at",
        "last_seen", "operation_json", "operation_id", "latest_observation_id",
    ),
    "endpoints": (
        "id", "target", "url_or_port", "protocol", "state", "technologies",
        "timestamp",
    ),
    "findings": (
        "id", "target", "type", "severity", "description", "payload",
        "validation_state", "validation_artifact", "validation_id",
        "validation_verdict", "validation_oracle", "validation_evidence_grade",
        "validation_report_path", "reportable", "timestamp",
    ),
}
