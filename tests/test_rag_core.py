import os
import stat
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
RAG_SERVER_DIR = REPO_ROOT / "mcp-servers" / "mcp-rag-engine"
if str(RAG_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(RAG_SERVER_DIR))

import cco_rag_core.storage as storage


class _FakeCollection:
    def __init__(self):
        self.items = {}
        self.upsert_calls = 0
        self.update_calls = 0

    def count(self):
        return len(self.items)

    def get(self, ids=None, include=None, where=None):
        selected = list(ids) if ids is not None else list(self.items)
        selected = [doc_id for doc_id in selected if doc_id in self.items]
        if where:
            selected = [
                doc_id
                for doc_id in selected
                if all(self.items[doc_id][1].get(key) == value for key, value in where.items())
            ]
        result = {"ids": selected}
        if include is None or "documents" in include:
            result["documents"] = [self.items[doc_id][0] for doc_id in selected]
        if include is None or "metadatas" in include:
            result["metadatas"] = [dict(self.items[doc_id][1]) for doc_id in selected]
        return result

    def upsert(self, ids, documents, metadatas):
        self.upsert_calls += 1
        for doc_id, document, metadata in zip(ids, documents, metadatas):
            self.items[doc_id] = (document, dict(metadata))

    def update(self, ids, metadatas):
        self.update_calls += 1
        for doc_id, metadata in zip(ids, metadatas):
            self.items[doc_id] = (self.items[doc_id][0], dict(metadata))

    def delete(self, ids):
        for doc_id in ids:
            self.items.pop(doc_id, None)


def _metadata(title="SQL injection guide", source_record_id="guide/sql.md"):
    return storage.build_metadata(
        title=title,
        source="test-source",
        source_record_id=source_record_id,
        source_url="https://example.invalid/source",
        source_revision="abc123",
        license_id="CC0-1.0",
        trust_tier="official",
        validation_status="advisory",
        category="web",
        tags="sql,injection",
    )


def test_semantic_chunks_are_heading_aware_and_ids_are_stable():
    content = "# SQL Injection\n\n" + ("Boolean oracle details. " * 180) + "\n\n# Remediation\n\nUse parameters."

    chunks = storage.semantic_chunks(content, max_chars=900, overlap=100)
    metadata = _metadata()
    first = storage.build_chunk_records(
        "writeups", title="SQL injection guide", content=content, metadata=metadata,
        max_chars=900, overlap=100,
    )
    second = storage.build_chunk_records(
        "writeups", title="SQL injection guide", content=content, metadata=metadata,
        max_chars=900, overlap=100,
    )

    assert len(chunks) > 1
    assert any("# Remediation" in chunk for chunk in chunks)
    assert [item["id"] for item in first] == [item["id"] for item in second]
    assert all(item["metadata"]["schema_version"] == storage.SCHEMA_VERSION for item in first)
    assert all(item["metadata"]["source_sha256"] for item in first)


def test_ingest_source_is_part_of_the_document_identity():
    recent = storage.build_metadata(
        title="CVE",
        source="nvd",
        source_record_id="CVE-2026-12345",
        ingest_source="nvd-recent",
    )
    seed = storage.build_metadata(
        title="CVE",
        source="nvd",
        source_record_id="CVE-2026-12345",
        ingest_source="nvd-seed",
    )

    recent_id = storage.build_chunk_records(
        "cves", title="CVE", content="A vulnerability record.", metadata=recent
    )[0]["id"]
    seed_id = storage.build_chunk_records(
        "cves", title="CVE", content="A vulnerability record.", metadata=seed
    )[0]["id"]

    assert recent_id != seed_id
    assert recent["source_key"] != seed["source_key"]


def test_extra_metadata_cannot_override_provenance():
    with pytest.raises(ValueError, match="reserved keys"):
        storage.build_metadata(
            title="unsafe",
            source="manual",
            source_record_id="one",
            extra={"trust_tier": "internal-validated"},
        )


def test_interrupted_dual_store_write_resumes_without_reembedding(tmp_path, monkeypatch):
    db_dir = tmp_path / "rag_db"
    fake = _FakeCollection()
    monkeypatch.setattr(
        storage,
        "get_collection",
        lambda name, **_kwargs: fake if name == "writeups" else None,
    )
    records = storage.build_chunk_records(
        "writeups",
        title="Resume guide",
        content="Deterministic resume behavior after a partial vector write.",
        metadata=_metadata(title="Resume guide", source_record_id="resume.md"),
    )
    real_lexical_upsert = storage.lexical_upsert
    failures = 0

    def fail_once(*_args, **_kwargs):
        nonlocal failures
        failures += 1
        raise RuntimeError("simulated interruption")

    monkeypatch.setattr(storage, "lexical_upsert", fail_once)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        storage.upsert_records("writeups", records, db_dir=db_dir)
    assert fake.upsert_calls == 1
    assert failures == 1

    monkeypatch.setattr(storage, "lexical_upsert", real_lexical_upsert)
    storage.upsert_records("writeups", records, db_dir=db_dir)

    assert fake.upsert_calls == 1
    assert set(storage._catalog_records([records[0]["id"]], db_dir=db_dir)) == {
        records[0]["id"]
    }


def test_source_manifest_requires_cross_store_completeness(tmp_path, monkeypatch):
    db_dir = tmp_path / "rag_db"
    fake = _FakeCollection()
    monkeypatch.setattr(
        storage,
        "get_collection",
        lambda name, **_kwargs: fake if name == "writeups" else None,
    )
    metadata = storage.build_metadata(
        title="Source",
        source="test-source",
        source_record_id="source.md",
        ingest_source="test-source",
    )
    records = storage.build_chunk_records(
        "writeups",
        title="Source",
        content="A complete source record for readiness validation.",
        metadata=metadata,
    )
    storage.reconcile_source_records(
        "writeups", records, ingest_source="test-source", db_dir=db_dir
    )
    storage.record_source_state(
        source_name="test-source",
        source_url="https://example.invalid/source",
        content_sha256="a" * 64,
        source_revision="one",
        record_count=1,
        chunk_count=len(records),
        status="ok",
        db_dir=db_dir,
    )

    assert storage.database_health(db_dir)["ready"] is True
    fake.items.clear()
    health = storage.database_health(db_dir)
    assert health["ready"] is False
    assert health["cross_store_consistent"] is False


def test_reconcile_deletes_stale_fts_rows_with_a_writable_connection(tmp_path, monkeypatch):
    db_dir = tmp_path / "rag_db"
    fake = _FakeCollection()
    monkeypatch.setattr(
        storage,
        "get_collection",
        lambda name, **_kwargs: fake if name == "writeups" else None,
    )
    metadata = storage.build_metadata(
        title="Stale",
        source="stale-source",
        source_record_id="stale.md",
        ingest_source="stale-source",
    )
    stale = storage.build_chunk_records(
        "writeups", title="Stale", content="This record will be removed.", metadata=metadata
    )
    storage.upsert_records("writeups", stale, db_dir=db_dir)

    storage.reconcile_source_records(
        "writeups", [], ingest_source="stale-source", db_dir=db_dir
    )

    assert fake.items == {}
    assert storage._catalog_records([stale[0]["id"]], db_dir=db_dir) == {}


def test_replace_repairs_catalog_only_stale_chunks_after_interruption(tmp_path, monkeypatch):
    db_dir = tmp_path / "rag_db"
    fake = _FakeCollection()
    monkeypatch.setattr(
        storage,
        "get_collection",
        lambda name, **_kwargs: fake if name == "writeups" else None,
    )
    metadata = storage.build_metadata(
        title="Replace",
        source="manual",
        source_record_id="replace.md",
        ingest_source="mcp-writeup",
    )
    old_records = storage.build_chunk_records(
        "writeups",
        title="Replace",
        content="# Long\n\n" + ("old content " * 500),
        metadata=metadata,
    )
    assert len(old_records) > 1
    storage.lexical_upsert("writeups", old_records, db_dir=db_dir)
    new_records = storage.build_chunk_records(
        "writeups",
        title="Replace",
        content="Short replacement content.",
        metadata=metadata,
    )

    storage.replace_source_documents(
        "writeups",
        new_records,
        source_key=str(metadata["source_key"]),
        db_dir=db_dir,
    )

    remaining = storage._catalog_records(
        [record["id"] for record in old_records], db_dir=db_dir
    )
    assert set(remaining) == {new_records[0]["id"]}


def test_secure_rag_permissions_restrict_existing_paths(tmp_path):
    db_dir = tmp_path / "rag_db"
    nested = db_dir / "raw"
    nested.mkdir(parents=True)
    snapshot = nested / "feed.json"
    snapshot.write_text("{}", encoding="utf-8")
    db_dir.chmod(0o775)
    nested.chmod(0o775)
    snapshot.chmod(0o664)

    storage.secure_rag_permissions(db_dir)

    assert stat.S_IMODE(db_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(nested.stat().st_mode) == 0o700
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600


def test_secure_permissions_do_not_follow_a_rag_db_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_text("keep", encoding="utf-8")
    outside.chmod(0o755)
    marker.chmod(0o644)
    linked = tmp_path / "rag_db"
    linked.symlink_to(outside, target_is_directory=True)

    storage.secure_rag_permissions(linked)

    assert stat.S_IMODE(outside.stat().st_mode) == 0o755
    assert stat.S_IMODE(marker.stat().st_mode) == 0o644
    with pytest.raises(ValueError, match="may not be a symlink"):
        storage.catalog_stats(linked)


def test_exact_vector_distance_has_full_relevance():
    assert storage.distance_to_relevance(0) == 1.0
    assert storage.distance_to_relevance(0.25) == 0.75
    assert storage.distance_to_relevance(2) == 0.0


def test_lexical_search_works_without_vector_runtime(tmp_path, monkeypatch):
    db_dir = tmp_path / "rag_db"
    metadata = _metadata()
    records = storage.build_chunk_records(
        "writeups",
        title="SQL injection guide",
        content="SQL injection authentication bypass with a deterministic boolean oracle.",
        metadata=metadata,
    )
    storage.lexical_upsert("writeups", records, db_dir=db_dir)
    monkeypatch.setattr(storage, "HAS_CHROMADB", False)

    result = storage.hybrid_search(
        "SQL injection authentication bypass",
        collection="all",
        top_k=3,
        min_relevance=0,
        db_dir=db_dir,
    )

    assert result["retrieval"] == "hybrid-vector-fts5-rrf"
    assert result["results"]
    assert result["results"][0]["metadata"]["source"] == "test-source"


def test_safe_file_iterator_rejects_symlinked_files(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.md").write_text("# Safe\n\n" + "content " * 20, encoding="utf-8")
    outside = tmp_path / "outside.md"
    outside.write_text("private", encoding="utf-8")
    (source / "leak.md").symlink_to(outside)

    files = list(storage.iter_safe_text_files(source))

    assert [path.name for path, _content, _truncated in files] == ["safe.md"]


def test_structured_kev_and_epss_risk_lookup(tmp_path):
    db_dir = tmp_path / "rag_db"
    storage.upsert_kev(
        [{
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        }],
        catalog_version="2026.07.22",
        db_dir=db_dir,
    )
    storage.upsert_epss(
        [{
            "cve": "CVE-2021-44228",
            "epss": 0.97,
            "percentile": 0.999,
            "score_date": "2026-07-22",
            "model_version": "v4",
        }],
        db_dir=db_dir,
    )

    risk = storage.lookup_risk(["CVE-2021-44228"], db_dir=db_dir)

    assert risk["CVE-2021-44228"]["known_exploited"] is True
    assert risk["CVE-2021-44228"]["epss"] == pytest.approx(0.97)


def test_nvd_normalization_supports_cvss_v4():
    cve_id, document, metadata = storage.normalize_nvd_record({
        "id": "CVE-2026-12345",
        "published": "2026-01-01T00:00:00Z",
        "lastModified": "2026-01-02T00:00:00Z",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Example issue"}],
        "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
        "references": [{"url": "https://example.invalid/advisory"}],
    })

    assert cve_id == "CVE-2026-12345"
    assert "metric: cvssMetricV40" in document
    assert metadata["severity"] == "critical"
    assert metadata["cwe"] == "CWE-78"


def test_nvd_normalization_prefers_primary_metric():
    _cve_id, document, metadata = storage.normalize_nvd_record({
        "id": "CVE-2026-54321",
        "descriptions": [{"lang": "en", "value": "Example issue"}],
        "metrics": {"cvssMetricV31": [
            {
                "type": "Secondary",
                "source": "vendor@example.invalid",
                "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"},
            },
            {
                "type": "Primary",
                "source": "nvd@nist.gov",
                "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
            },
        ]},
    })

    assert "CVSS: 9.8" in document
    assert metadata["severity"] == "critical"


@pytest.mark.parametrize("value", ["", "CVE-20-1", "CVE-2024-1", "--help", "CVE-2024-1234;id"])
def test_cve_validation_rejects_invalid_values(value):
    with pytest.raises(ValueError):
        storage.validate_cve_id(value)
