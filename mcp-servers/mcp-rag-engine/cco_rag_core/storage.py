"""Shared, deterministic storage primitives for the CCO security RAG.

Chroma remains the compatibility vector store. A small SQLite/FTS5 sidecar
provides exact-token retrieval and structured KEV/EPSS data without embedding
hundreds of thousands of numeric rows.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

try:
    import chromadb
    from chromadb.config import Settings

    HAS_CHROMADB = True
except ImportError:  # pragma: no cover - exercised by minimal installations
    chromadb = None
    Settings = None
    HAS_CHROMADB = False


SCHEMA_VERSION = "2.0"
TRANSFORM_VERSION = "rag-transform-2026-07-22.1"
EMBEDDING_FINGERPRINT = "chromadb-default/all-MiniLM-L6-v2"
ALLOWED_COLLECTIONS = ("exploits", "writeups", "cves")
CATALOG_FILENAME = "rag_catalog.sqlite3"
MAX_QUERY_CHARS = 2_000
MAX_TOP_K = 20
MAX_FILE_BYTES = 250_000
MAX_FILES = 5_000
MAX_CHUNKS_PER_DOCUMENT = 128
PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_SEARCH_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+:/#()'\-]{0,199}$")
_MARKDOWN_HEADING_RE = re.compile(r"^#{1,6}\s+\S")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db_dir(cco_home: str | os.PathLike[str] | None = None) -> Path:
    home = Path(cco_home) if cco_home is not None else Path(
        os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
    )
    return home.expanduser().resolve() / "rag_db"


def _db_root(db_dir: str | os.PathLike[str] | None = None) -> Path:
    raw = Path(db_dir).expanduser() if db_dir is not None else get_db_dir()
    root = raw if raw.is_absolute() else Path.cwd() / raw
    root = root.absolute()
    if root.is_symlink():
        raise ValueError(f"RAG database path may not be a symlink: {root}")
    return root


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    if not path.is_symlink():
        path.chmod(PRIVATE_DIR_MODE)


def secure_rag_permissions(db_dir: str | os.PathLike[str] | None = None) -> None:
    """Keep local RAG data private even when the caller has a permissive umask."""
    raw = Path(db_dir).expanduser() if db_dir is not None else get_db_dir()
    root = raw if raw.is_absolute() else Path.cwd() / raw
    root = root.absolute()
    if root.is_symlink() or not root.exists():
        return
    for current_root, directories, files in os.walk(root, followlinks=False):
        current = Path(current_root)
        current.chmod(PRIVATE_DIR_MODE)
        for directory in directories:
            path = current / directory
            if not path.is_symlink():
                path.chmod(PRIVATE_DIR_MODE)
        for filename in files:
            path = current / filename
            if not path.is_symlink():
                path.chmod(PRIVATE_FILE_MODE)


def _catalog_path(db_dir: str | os.PathLike[str] | None = None) -> Path:
    return _db_root(db_dir) / CATALOG_FILENAME


@contextmanager
def rag_write_lock(db_dir: str | os.PathLike[str] | None = None):
    """Serialize bootstrap and MCP writers across processes."""
    root = _db_root(db_dir)
    lock_dir = root.parent
    _ensure_private_directory(lock_dir)
    lock_path = lock_dir / ".rag-bootstrap.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, PRIVATE_FILE_MODE)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(f"another RAG writer holds {lock_path}") from exc
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _connect_catalog(
    db_dir: str | os.PathLike[str] | None = None, *, create: bool = True
) -> sqlite3.Connection | None:
    path = _catalog_path(db_dir)
    if not create and not path.is_file():
        return None
    if not create:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    _ensure_private_directory(path.parent)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS documents (
            doc_id TEXT PRIMARY KEY,
            collection_name TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            tags TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
            doc_id UNINDEXED,
            collection_name UNINDEXED,
            title,
            content,
            tags,
            tokenize='unicode61'
        );
        CREATE TABLE IF NOT EXISTS epss_current (
            cve_id TEXT PRIMARY KEY,
            epss REAL NOT NULL CHECK(epss >= 0 AND epss <= 1),
            percentile REAL NOT NULL CHECK(percentile >= 0 AND percentile <= 1),
            score_date TEXT NOT NULL,
            model_version TEXT NOT NULL,
            retrieved_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kev_catalog (
            cve_id TEXT PRIMARY KEY,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            vulnerability_name TEXT NOT NULL,
            date_added TEXT NOT NULL,
            due_date TEXT NOT NULL,
            ransomware_use TEXT NOT NULL,
            catalog_version TEXT NOT NULL,
            retrieved_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS source_state (
            source_name TEXT PRIMARY KEY,
            source_url TEXT NOT NULL,
            etag TEXT NOT NULL,
            last_modified TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            source_revision TEXT NOT NULL,
            record_count INTEGER NOT NULL,
            chunk_count INTEGER NOT NULL DEFAULT 0,
            retrieved_at TEXT NOT NULL,
            status TEXT NOT NULL,
            schema_version TEXT NOT NULL DEFAULT '',
            transform_version TEXT NOT NULL DEFAULT '',
            embedding_fingerprint TEXT NOT NULL DEFAULT ''
        );
        """
    )
    columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(source_state)")
    }
    migrations = {
        "chunk_count": "INTEGER NOT NULL DEFAULT 0",
        "schema_version": "TEXT NOT NULL DEFAULT ''",
        "transform_version": "TEXT NOT NULL DEFAULT ''",
        "embedding_fingerprint": "TEXT NOT NULL DEFAULT ''",
    }
    for column, definition in migrations.items():
        if column not in columns:
            conn.execute(f"ALTER TABLE source_state ADD COLUMN {column} {definition}")
    conn.commit()
    path.chmod(PRIVATE_FILE_MODE)
    return conn


def get_client(
    *, create: bool = False, db_dir: str | os.PathLike[str] | None = None
):
    if not HAS_CHROMADB:
        return None
    root = _db_root(db_dir)
    if not create and not root.is_dir():
        return None
    if create:
        _ensure_private_directory(root)
    settings = Settings(anonymized_telemetry=False) if Settings is not None else None
    return chromadb.PersistentClient(path=str(root), settings=settings)


def _collection_names(client: Any) -> set[str]:
    names = set()
    for item in client.list_collections():
        names.add(item if isinstance(item, str) else item.name)
    return names


def _legacy_collection_reconciled(
    collection: Any, *, db_dir: str | os.PathLike[str] | None = None
) -> bool:
    if collection.count() == 0:
        return True
    result = collection.get(include=["documents"])
    ids = [str(doc_id) for doc_id in result.get("ids") or []]
    documents = result.get("documents") or []
    catalog = _catalog_records(ids, db_dir=db_dir)
    if set(catalog) != set(ids):
        return False
    return all(
        _same_document(
            str(documents[index] if index < len(documents) else ""),
            catalog[doc_id][0],
        )
        for index, doc_id in enumerate(ids)
    )


def validate_collection(name: str, *, allow_all: bool = False) -> str:
    value = str(name or "").strip().lower()
    allowed = set(ALLOWED_COLLECTIONS)
    if allow_all:
        allowed.add("all")
    if value not in allowed:
        raise ValueError(f"collection must be one of: {', '.join(sorted(allowed))}")
    return value


def get_collection(
    name: str,
    *,
    create: bool = False,
    db_dir: str | os.PathLike[str] | None = None,
):
    collection_name = validate_collection(name)
    client = get_client(create=create, db_dir=db_dir)
    if client is None:
        return None
    if create:
        collection = client.get_or_create_collection(
            name=collection_name,
            metadata={
                "hnsw:space": "cosine",
                "cco_schema_version": SCHEMA_VERSION,
                "cco_embedding_model": EMBEDDING_FINGERPRINT,
            },
        )
    else:
        if collection_name not in _collection_names(client):
            return None
        collection = client.get_collection(collection_name)

    metadata = dict(collection.metadata or {})
    expected = {
        "cco_schema_version": SCHEMA_VERSION,
        "cco_embedding_model": EMBEDDING_FINGERPRINT,
    }
    mismatched = {
        key: (metadata.get(key), value)
        for key, value in expected.items()
        if metadata.get(key) != value
    }
    if mismatched:
        conflicting = any(metadata.get(key) not in {None, ""} for key in mismatched)
        allow_adopt = os.environ.get("CCO_RAG_ADOPT_LEGACY", "") == "1"
        if allow_adopt and not conflicting:
            if not _legacy_collection_reconciled(collection, db_dir=db_dir):
                raise RuntimeError(
                    f"legacy RAG collection '{collection_name}' is not mirrored in FTS; rebuild required"
                )
            mutable_metadata = {
                key: value for key, value in metadata.items() if not key.startswith("hnsw:")
            }
            collection.modify(metadata={**mutable_metadata, **expected})
        else:
            details = ", ".join(
                f"{key}={actual!r} (expected {wanted!r})"
                for key, (actual, wanted) in mismatched.items()
            )
            raise RuntimeError(
                f"incompatible RAG collection '{collection_name}': {details}"
            )
    return collection


def database_ready(db_dir: str | os.PathLike[str] | None = None) -> bool:
    return bool(database_health(db_dir)["ready"])


def validate_cve_id(cve_id: str) -> str:
    value = str(cve_id or "").strip().upper()
    if not _CVE_RE.fullmatch(value):
        raise ValueError("invalid CVE ID; expected CVE-YYYY-NNNN")
    return value


def validate_search_query(query: str, *, exploitdb: bool = False) -> str:
    value = str(query or "").strip()
    if not 2 <= len(value) <= MAX_QUERY_CHARS or "\x00" in value:
        raise ValueError(f"query length must be between 2 and {MAX_QUERY_CHARS} characters")
    if exploitdb:
        if len(value) > 200 or not _SEARCH_TOKEN_RE.fullmatch(value):
            raise ValueError("ExploitDB query contains unsupported characters")
        if any(token.startswith("-") for token in value.split()):
            raise ValueError("ExploitDB query options are not allowed")
    return value


def _bounded_top_k(top_k: int) -> int:
    try:
        value = int(top_k)
    except (TypeError, ValueError) as exc:
        raise ValueError("top_k must be an integer") from exc
    if not 1 <= value <= MAX_TOP_K:
        raise ValueError(f"top_k must be between 1 and {MAX_TOP_K}")
    return value


def distance_to_relevance(distance: Any) -> float:
    try:
        value = float(distance)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(value):
        return 0.0
    return round(max(0.0, min(1.0, 1.0 - value)), 4)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _canonical_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        str(key): _scalar_metadata(value)
        for key, value in metadata.items()
        if key not in {"ingested_at", "record_sha256"}
    }


def _record_sha256(document: str, metadata: dict[str, Any]) -> str:
    canonical = json.dumps(
        _canonical_metadata(metadata),
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return _sha256_text(f"{document}\x00{canonical}")


def stable_document_id(
    collection: str, source: str, source_record_id: str, chunk_index: int = 0
) -> str:
    collection_name = validate_collection(collection)
    identity = f"{collection_name}\x00{source.strip().lower()}\x00{source_record_id}\x00{int(chunk_index)}"
    return hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()[:32]


def _scalar_metadata(value: Any) -> str | int | float | bool:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def build_metadata(
    *,
    title: str,
    source: str,
    source_record_id: str,
    ingest_source: str = "",
    source_url: str = "",
    source_revision: str = "",
    license_id: str = "unknown",
    license_url: str = "",
    trust_tier: str = "untrusted",
    validation_status: str = "unverified",
    category: str = "misc",
    tags: str = "",
    published_at: str = "",
    modified_at: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, str | int | float | bool]:
    normalized_source = str(source).strip().lower()[:100]
    normalized_ingest_source = str(ingest_source or source).strip().lower()[:100]
    normalized_record_id = str(source_record_id).strip()[:500]
    source_key = _sha256_text(
        f"{normalized_source}\x00{normalized_ingest_source}\x00{normalized_record_id}"
    )[:24]
    metadata: dict[str, Any] = {
        "title": str(title).strip()[:500],
        "source": normalized_source,
        "source_record_id": normalized_record_id,
        "ingest_source": normalized_ingest_source,
        "source_key": source_key,
        "source_url": str(source_url).strip()[:2_000],
        "source_revision": str(source_revision).strip()[:200],
        "license_id": str(license_id).strip()[:100],
        "license_url": str(license_url).strip()[:2_000],
        "trust_tier": str(trust_tier).strip().lower()[:50],
        "validation_status": str(validation_status).strip().lower()[:50],
        "category": str(category).strip().lower()[:100],
        "tags": str(tags).strip()[:2_000],
        "published_at": str(published_at).strip()[:100],
        "modified_at": str(modified_at).strip()[:100],
        "schema_version": SCHEMA_VERSION,
        "transform_version": TRANSFORM_VERSION,
        "embedding_model": EMBEDDING_FINGERPRINT,
        "ingested_at": utc_now(),
    }
    if extra:
        reserved = sorted(set(extra).intersection(metadata))
        if reserved:
            raise ValueError(
                "extra metadata may not override reserved keys: " + ", ".join(reserved)
            )
        metadata.update(extra)
    return {str(key): _scalar_metadata(value) for key, value in metadata.items()}


def _split_window(text: str, max_chars: int, overlap: int) -> list[str]:
    chunks = []
    start = 0
    while start < len(text) and len(chunks) < MAX_CHUNKS_PER_DOCUMENT:
        end = min(len(text), start + max_chars)
        if end < len(text):
            boundary = max(text.rfind("\n", start + max_chars // 2, end), text.rfind(" ", start + max_chars // 2, end))
            if boundary > start:
                end = boundary
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(start + 1, end - overlap)
    return chunks


def semantic_chunks(
    content: str,
    *,
    max_chars: int = 3_000,
    overlap: int = 240,
    max_total_chars: int = 250_000,
) -> list[str]:
    if not 500 <= max_chars <= 12_000:
        raise ValueError("max_chars must be between 500 and 12000")
    if not 0 <= overlap < max_chars // 2:
        raise ValueError("overlap must be less than half max_chars")
    normalized = str(content or "").replace("\r\n", "\n").replace("\r", "\n")[:max_total_chars].strip()
    if not normalized:
        return []

    sections: list[str] = []
    current: list[str] = []
    in_fence = False
    for line in normalized.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
        if _MARKDOWN_HEADING_RE.match(line) and not in_fence and current:
            sections.append("\n".join(current).strip())
            current = []
        current.append(line)
    if current:
        sections.append("\n".join(current).strip())

    packed: list[str] = []
    buffer = ""
    for section in sections:
        if not section:
            continue
        candidate = f"{buffer}\n\n{section}".strip() if buffer else section
        if len(candidate) <= max_chars:
            buffer = candidate
            continue
        if buffer:
            packed.append(buffer)
            buffer = ""
        if len(section) <= max_chars:
            buffer = section
        else:
            packed.extend(_split_window(section, max_chars, overlap))
        if len(packed) >= MAX_CHUNKS_PER_DOCUMENT:
            break
    if buffer and len(packed) < MAX_CHUNKS_PER_DOCUMENT:
        packed.append(buffer)

    unique = []
    seen = set()
    for chunk in packed[:MAX_CHUNKS_PER_DOCUMENT]:
        digest = _sha256_text(chunk)
        if digest not in seen:
            seen.add(digest)
            unique.append(chunk)
    return unique


def build_chunk_records(
    collection: str,
    *,
    title: str,
    content: str,
    metadata: dict[str, Any],
    max_chars: int = 3_000,
    overlap: int = 240,
) -> list[dict[str, Any]]:
    collection_name = validate_collection(collection)
    source = str(metadata.get("source", "unknown"))
    identity_source = str(metadata.get("ingest_source") or source)
    source_record_id = str(metadata.get("source_record_id", title))
    chunks = semantic_chunks(content, max_chars=max_chars, overlap=overlap)
    source_sha256 = _sha256_text(content)
    records = []
    for index, chunk in enumerate(chunks):
        document = f"{title.strip()}\n\n{chunk}" if title.strip() else chunk
        chunk_metadata = dict(metadata)
        chunk_metadata.update(
            {
                "chunk_index": index,
                "chunk_count": len(chunks),
                "content_sha256": _sha256_text(document),
                "source_sha256": source_sha256,
            }
        )
        chunk_metadata["record_sha256"] = _record_sha256(document, chunk_metadata)
        records.append(
            {
                "id": stable_document_id(
                    collection_name, identity_source, source_record_id, index
                ),
                "document": document,
                "metadata": {key: _scalar_metadata(value) for key, value in chunk_metadata.items()},
            }
        )
    return records


def lexical_upsert(
    collection: str,
    records: Sequence[dict[str, Any]],
    *,
    db_dir: str | os.PathLike[str] | None = None,
) -> None:
    collection_name = validate_collection(collection)
    if not records:
        return
    conn = _connect_catalog(db_dir, create=True)
    assert conn is not None
    try:
        with conn:
            for record in records:
                metadata = dict(record.get("metadata") or {})
                doc_id = str(record["id"])
                title = str(metadata.get("title", ""))
                content = str(record.get("document", ""))
                tags = str(metadata.get("tags", ""))
                content_sha256 = str(metadata.get("content_sha256") or _sha256_text(content))
                metadata_json = json.dumps(metadata, sort_keys=True, ensure_ascii=True)
                conn.execute("DELETE FROM documents_fts WHERE doc_id = ?", (doc_id,))
                conn.execute(
                    """
                    INSERT INTO documents(
                        doc_id, collection_name, title, content, tags,
                        metadata_json, content_sha256, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(doc_id) DO UPDATE SET
                        collection_name=excluded.collection_name,
                        title=excluded.title,
                        content=excluded.content,
                        tags=excluded.tags,
                        metadata_json=excluded.metadata_json,
                        content_sha256=excluded.content_sha256,
                        updated_at=excluded.updated_at
                    """,
                    (
                        doc_id,
                        collection_name,
                        title,
                        content,
                        tags,
                        metadata_json,
                        content_sha256,
                        utc_now(),
                    ),
                )
                conn.execute(
                    "INSERT INTO documents_fts(doc_id, collection_name, title, content, tags) VALUES (?, ?, ?, ?, ?)",
                    (doc_id, collection_name, title, content, tags),
                )
    finally:
        conn.close()


def _delete_catalog_documents(
    doc_ids: Iterable[str], *, db_dir: str | os.PathLike[str] | None = None
) -> None:
    ids = [str(doc_id) for doc_id in doc_ids]
    if not ids:
        return
    if not _catalog_path(db_dir).is_file():
        return
    conn = _connect_catalog(db_dir, create=True)
    assert conn is not None
    try:
        with conn:
            conn.executemany("DELETE FROM documents_fts WHERE doc_id = ?", ((doc_id,) for doc_id in ids))
            conn.executemany("DELETE FROM documents WHERE doc_id = ?", ((doc_id,) for doc_id in ids))
    finally:
        conn.close()


def _catalog_source_key_ids(
    collection: str,
    source_key: str,
    *,
    db_dir: str | os.PathLike[str] | None = None,
) -> set[str]:
    if not source_key:
        return set()
    collection_name = validate_collection(collection)
    conn = _connect_catalog(db_dir, create=False)
    if conn is None:
        return set()
    try:
        output = set()
        for row in conn.execute(
            "SELECT doc_id, metadata_json FROM documents WHERE collection_name = ?",
            (collection_name,),
        ):
            metadata = json.loads(row["metadata_json"])
            if str(metadata.get("source_key", "")) == source_key:
                output.add(str(row["doc_id"]))
        return output
    finally:
        conn.close()


def replace_source_documents(
    collection: str,
    records: Sequence[dict[str, Any]],
    *,
    source_key: str,
    db_dir: str | os.PathLike[str] | None = None,
) -> int:
    collection_name = validate_collection(collection)
    target = get_collection(collection_name, create=True, db_dir=db_dir)
    if target is None:
        raise RuntimeError("ChromaDB is not installed")
    existing = target.get(where={"source_key": source_key}) if source_key else {"ids": []}
    old_ids = set(existing.get("ids") or []) | _catalog_source_key_ids(
        collection_name, source_key, db_dir=db_dir
    )
    new_ids = {str(record["id"]) for record in records}
    if records:
        target.upsert(
            ids=[str(record["id"]) for record in records],
            documents=[str(record["document"]) for record in records],
            metadatas=[dict(record["metadata"]) for record in records],
        )
        lexical_upsert(collection_name, records, db_dir=db_dir)
    stale = sorted(old_ids - new_ids)
    if stale:
        target.delete(ids=stale)
        _delete_catalog_documents(stale, db_dir=db_dir)
    return len(records)


def _vector_records(target: Any, ids: Sequence[str]) -> dict[str, tuple[str, dict[str, Any]]]:
    if not ids:
        return {}
    result = target.get(ids=list(ids), include=["documents", "metadatas"])
    found_ids = result.get("ids") or []
    documents = result.get("documents") or []
    metadatas = result.get("metadatas") or []
    return {
        str(doc_id): (
            str(documents[index] if index < len(documents) else ""),
            dict(metadatas[index] or {}) if index < len(metadatas) else {},
        )
        for index, doc_id in enumerate(found_ids)
    }


def _catalog_records(
    ids: Sequence[str], *, db_dir: str | os.PathLike[str] | None = None
) -> dict[str, tuple[str, dict[str, Any]]]:
    if not ids:
        return {}
    conn = _connect_catalog(db_dir, create=False)
    if conn is None:
        return {}
    found: dict[str, tuple[str, dict[str, Any]]] = {}
    try:
        for start in range(0, len(ids), 500):
            batch = list(ids[start:start + 500])
            placeholders = ",".join("?" for _ in batch)
            for row in conn.execute(
                f"SELECT doc_id, content, metadata_json FROM documents WHERE doc_id IN ({placeholders})",
                batch,
            ):
                found[str(row["doc_id"])] = (
                    str(row["content"]),
                    json.loads(row["metadata_json"]),
                )
        return found
    finally:
        conn.close()


def _same_document(left: str, right: str) -> bool:
    return _sha256_text(left) == _sha256_text(right)


def _same_record(
    existing_document: str,
    existing_metadata: dict[str, Any],
    expected_document: str,
    expected_metadata: dict[str, Any],
) -> bool:
    if not _same_document(existing_document, expected_document):
        return False
    existing_fingerprint = str(existing_metadata.get("record_sha256") or "")
    expected_fingerprint = str(expected_metadata.get("record_sha256") or "")
    if not existing_fingerprint:
        existing_fingerprint = _record_sha256(existing_document, existing_metadata)
    if not expected_fingerprint:
        expected_fingerprint = _record_sha256(expected_document, expected_metadata)
    return existing_fingerprint == expected_fingerprint


def upsert_records(
    collection: str,
    records: Sequence[dict[str, Any]],
    *,
    batch_size: int = 100,
    db_dir: str | os.PathLike[str] | None = None,
) -> int:
    collection_name = validate_collection(collection)
    if not records:
        return 0
    if not 1 <= int(batch_size) <= 500:
        raise ValueError("batch_size must be between 1 and 500")
    target = get_collection(collection_name, create=True, db_dir=db_dir)
    if target is None:
        raise RuntimeError("ChromaDB is not installed")
    for start in range(0, len(records), int(batch_size)):
        batch = records[start:start + int(batch_size)]
        ids = [str(record["id"]) for record in batch]
        vector_existing = _vector_records(target, ids)
        catalog_existing = _catalog_records(ids, db_dir=db_dir)

        vector_upserts = []
        vector_metadata_updates = []
        lexical_updates = []
        for record in batch:
            doc_id = str(record["id"])
            document = str(record["document"])
            metadata = dict(record["metadata"])
            vector_record = vector_existing.get(doc_id)
            if vector_record is None or not _same_document(vector_record[0], document):
                vector_upserts.append(record)
            elif not _same_record(vector_record[0], vector_record[1], document, metadata):
                vector_metadata_updates.append(record)

            catalog_record = catalog_existing.get(doc_id)
            if catalog_record is None or not _same_record(
                catalog_record[0], catalog_record[1], document, metadata
            ):
                lexical_updates.append(record)

        if vector_upserts:
            target.upsert(
                ids=[str(record["id"]) for record in vector_upserts],
                documents=[str(record["document"]) for record in vector_upserts],
                metadatas=[dict(record["metadata"]) for record in vector_upserts],
            )
        if vector_metadata_updates:
            target.update(
                ids=[str(record["id"]) for record in vector_metadata_updates],
                metadatas=[dict(record["metadata"]) for record in vector_metadata_updates],
            )
        if lexical_updates:
            lexical_upsert(collection_name, lexical_updates, db_dir=db_dir)
    return len(records)


def _source_document_ids(
    collection: str,
    ingest_source: str,
    *,
    db_dir: str | os.PathLike[str] | None = None,
) -> tuple[set[str], set[str]]:
    collection_name = validate_collection(collection)
    target = get_collection(collection_name, create=False, db_dir=db_dir)
    vector_ids: set[str] = set()
    if target is not None:
        result = target.get(include=["metadatas"])
        metadatas = result.get("metadatas") or []
        for index, doc_id in enumerate(result.get("ids") or []):
            metadata = dict(metadatas[index] or {}) if index < len(metadatas) else {}
            effective_source = metadata.get("ingest_source") or metadata.get("source")
            if str(effective_source) == ingest_source:
                vector_ids.add(str(doc_id))

    catalog_ids: set[str] = set()
    conn = _connect_catalog(db_dir, create=False)
    if conn is not None:
        try:
            for row in conn.execute(
                "SELECT doc_id, metadata_json FROM documents WHERE collection_name = ?",
                (collection_name,),
            ):
                metadata = json.loads(row["metadata_json"])
                effective_source = metadata.get("ingest_source") or metadata.get("source")
                if str(effective_source) == ingest_source:
                    catalog_ids.add(str(row["doc_id"]))
        finally:
            conn.close()
    return vector_ids, catalog_ids


def reconcile_source_records(
    collection: str,
    records: Sequence[dict[str, Any]],
    *,
    ingest_source: str,
    batch_size: int = 100,
    delete_stale: bool = True,
    db_dir: str | os.PathLike[str] | None = None,
) -> int:
    """Converge Chroma and FTS to the same authoritative source snapshot."""
    collection_name = validate_collection(collection)
    expected_ids = {str(record["id"]) for record in records}
    if len(expected_ids) != len(records):
        raise ValueError("source snapshot contains duplicate document IDs")
    upsert_records(
        collection_name,
        records,
        batch_size=batch_size,
        db_dir=db_dir,
    )

    vector_ids, catalog_ids = _source_document_ids(
        collection_name, ingest_source, db_dir=db_dir
    )
    stale = (vector_ids | catalog_ids) - expected_ids if delete_stale else set()
    if stale:
        target = get_collection(collection_name, create=False, db_dir=db_dir)
        if target is not None:
            target.delete(ids=sorted(stale))
        _delete_catalog_documents(stale, db_dir=db_dir)

    target = get_collection(collection_name, create=False, db_dir=db_dir)
    if target is None:
        if not expected_ids:
            return 0
        raise RuntimeError(f"RAG collection '{collection_name}' disappeared during reconciliation")
    expected_by_id = {str(record["id"]): record for record in records}
    vector_records = _vector_records(target, sorted(expected_ids))
    catalog_records = _catalog_records(sorted(expected_ids), db_dir=db_dir)
    missing_vector = expected_ids - set(vector_records)
    missing_catalog = expected_ids - set(catalog_records)
    mismatched = []
    for doc_id, record in expected_by_id.items():
        document = str(record["document"])
        metadata = dict(record["metadata"])
        vector = vector_records.get(doc_id)
        catalog = catalog_records.get(doc_id)
        if vector and not _same_record(vector[0], vector[1], document, metadata):
            mismatched.append(f"vector:{doc_id}")
        if catalog and not _same_record(catalog[0], catalog[1], document, metadata):
            mismatched.append(f"catalog:{doc_id}")
    if missing_vector or missing_catalog or mismatched:
        raise RuntimeError(
            "RAG source reconciliation failed: "
            f"missing_vector={len(missing_vector)}, "
            f"missing_catalog={len(missing_catalog)}, mismatched={len(mismatched)}"
        )
    return len(records)


def _lexical_query(query: str) -> str:
    tokens = re.findall(r"(?u)[\w][\w.+:/\-]{1,63}", query)[:12]
    return " OR ".join(f'"{token.replace(chr(34), "")}"' for token in tokens)


def _lexical_search(
    query: str,
    collections: Sequence[str],
    limit: int,
    *,
    db_dir: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    match = _lexical_query(query)
    if not match:
        return []
    conn = _connect_catalog(db_dir, create=False)
    if conn is None:
        return []
    placeholders = ",".join("?" for _ in collections)
    try:
        rows = conn.execute(
            f"""
            SELECT d.doc_id, d.collection_name, d.title, d.content,
                   d.metadata_json, bm25(documents_fts) AS lexical_rank
            FROM documents_fts
            JOIN documents d ON d.doc_id = documents_fts.doc_id
            WHERE documents_fts MATCH ?
              AND d.collection_name IN ({placeholders})
            ORDER BY lexical_rank
            LIMIT ?
            """,
            (match, *collections, limit),
        ).fetchall()
        return [
            {
                "id": row["doc_id"],
                "collection": row["collection_name"],
                "content": row["content"],
                "metadata": json.loads(row["metadata_json"]),
                "lexical_rank": index + 1,
            }
            for index, row in enumerate(rows)
        ]
    finally:
        conn.close()


def _vector_search(
    query: str,
    collections: Sequence[str],
    limit: int,
    *,
    db_dir: str | os.PathLike[str] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    hits: list[dict[str, Any]] = []
    errors: list[str] = []
    for collection_name in collections:
        try:
            collection = get_collection(collection_name, create=False, db_dir=db_dir)
            if collection is None or collection.count() == 0:
                continue
            result = collection.query(query_texts=[query], n_results=min(limit, collection.count()))
            ids = (result.get("ids") or [[]])[0]
            documents = (result.get("documents") or [[]])[0]
            metadatas = (result.get("metadatas") or [[]])[0]
            distances = (result.get("distances") or [[]])[0]
            for index, doc_id in enumerate(ids):
                hits.append(
                    {
                        "id": doc_id,
                        "collection": collection_name,
                        "content": documents[index] if index < len(documents) else "",
                        "metadata": metadatas[index] if index < len(metadatas) else {},
                        "vector_relevance": distance_to_relevance(
                            distances[index] if index < len(distances) else None
                        ),
                        "vector_rank": index + 1,
                    }
                )
        except Exception as exc:
            errors.append(f"{collection_name}: {type(exc).__name__}: {exc}")
    return hits, errors


_TRUST_WEIGHT = {
    "internal-validated": 1.0,
    "official": 0.98,
    "curated": 0.9,
    "community": 0.75,
    "user": 0.7,
    "untrusted": 0.55,
}


def hybrid_search(
    query: str,
    *,
    collection: str = "all",
    top_k: int = 5,
    min_relevance: float | None = None,
    db_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    normalized_query = validate_search_query(query)
    collection_name = validate_collection(collection, allow_all=True)
    limit = _bounded_top_k(top_k)
    collections = list(ALLOWED_COLLECTIONS) if collection_name == "all" else [collection_name]
    candidate_limit = min(MAX_TOP_K * 2, max(limit * 4, 12))
    vector_hits, errors = _vector_search(
        normalized_query, collections, candidate_limit, db_dir=db_dir
    )
    lexical_hits = _lexical_search(
        normalized_query, collections, candidate_limit, db_dir=db_dir
    )

    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for hit in vector_hits:
        key = (hit["collection"], str(hit["id"]))
        item = merged.setdefault(key, dict(hit))
        item["rrf"] = item.get("rrf", 0.0) + 0.65 / (60 + hit["vector_rank"])
    for hit in lexical_hits:
        key = (hit["collection"], str(hit["id"]))
        item = merged.setdefault(key, dict(hit))
        if not item.get("content"):
            item["content"] = hit["content"]
        if not item.get("metadata"):
            item["metadata"] = hit["metadata"]
        item["lexical_rank"] = hit["lexical_rank"]
        item["rrf"] = item.get("rrf", 0.0) + 0.35 / (60 + hit["lexical_rank"])

    maximum_rrf = (0.65 + 0.35) / 61
    threshold = float(
        min_relevance
        if min_relevance is not None
        else os.environ.get("CCO_RAG_MIN_RELEVANCE", "0.12")
    )
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("min_relevance must be a finite value between 0 and 1")
    results = []
    for item in merged.values():
        fused = min(1.0, item.get("rrf", 0.0) / maximum_rrf)
        vector_score = float(item.get("vector_relevance", 0.0))
        base = 0.75 * fused + 0.25 * vector_score
        trust = str((item.get("metadata") or {}).get("trust_tier", "untrusted"))
        relevance = round(base * (0.85 + 0.15 * _TRUST_WEIGHT.get(trust, 0.55)), 4)
        if relevance < threshold:
            continue
        item["relevance"] = relevance
        item.pop("rrf", None)
        results.append(item)
    results.sort(key=lambda item: item["relevance"], reverse=True)
    return {
        "query": normalized_query,
        "collection": collection_name,
        "results": results[:limit],
        "errors": errors,
        "retrieval": "hybrid-vector-fts5-rrf",
        "schema_version": SCHEMA_VERSION,
    }


def iter_safe_text_files(
    root: str | os.PathLike[str],
    *,
    max_files: int = MAX_FILES,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> Iterator[tuple[Path, str, bool]]:
    base = Path(root).expanduser()
    if base.is_symlink() or not base.is_dir():
        raise ValueError(f"source directory is not a regular directory: {base}")
    resolved_base = base.resolve()
    emitted = 0
    for current_root, directories, files in os.walk(resolved_base, followlinks=False):
        current = Path(current_root)
        directories[:] = sorted(
            directory
            for directory in directories
            if not directory.startswith(".") and not (current / directory).is_symlink()
        )
        for filename in sorted(files):
            if emitted >= max_files:
                return
            path = current / filename
            if path.suffix.lower() not in {".md", ".txt"} or path.is_symlink():
                continue
            resolved = path.resolve()
            if resolved_base not in resolved.parents:
                continue
            info = resolved.stat()
            if not stat.S_ISREG(info.st_mode):
                continue
            with resolved.open("rb") as handle:
                raw = handle.read(max_file_bytes + 1)
            truncated = len(raw) > max_file_bytes
            text = raw[:max_file_bytes].decode("utf-8", errors="replace")
            emitted += 1
            yield resolved, text, truncated


def _cvss_details(metrics: dict[str, Any]) -> tuple[str, str, str]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        metric = min(
            entries,
            key=lambda item: (
                str(item.get("type", "")).lower() != "primary",
                str(item.get("source", "")).lower() != "nvd@nist.gov",
            ),
        )
        data = metric.get("cvssData") or {}
        return (
            str(data.get("baseScore", "N/A")),
            str(data.get("baseSeverity") or metric.get("baseSeverity") or "unknown").lower(),
            key,
        )
    return "N/A", "unknown", "none"


def normalize_nvd_record(cve_data: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    cve_id = validate_cve_id(cve_data.get("id", ""))
    descriptions = cve_data.get("descriptions") or []
    description = next(
        (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
        "No English description available",
    )
    score, severity, metric_version = _cvss_details(cve_data.get("metrics") or {})
    cwes = sorted(
        {
            item.get("value", "")
            for weakness in cve_data.get("weaknesses") or []
            for item in weakness.get("description") or []
            if item.get("lang") == "en" and item.get("value")
        }
    )
    references = [item.get("url", "") for item in (cve_data.get("references") or [])[:10]]
    published = str(cve_data.get("published", ""))
    modified = str(cve_data.get("lastModified", ""))
    status = str(cve_data.get("vulnStatus", "unknown"))
    document = (
        f"CVE: {cve_id}\n"
        f"Status: {status}\n"
        f"Severity: {severity.upper()} (CVSS: {score}, metric: {metric_version})\n"
        f"Published: {published}\nModified: {modified}\n"
        f"CWE: {', '.join(cwes) or 'N/A'}\n"
        f"Description: {description}\n"
        f"References: {', '.join(reference for reference in references if reference)}"
    )
    extra = {
        "cve_id": cve_id,
        "cvss_score": score,
        "severity": severity,
        "cvss_metric": metric_version,
        "cwe": ", ".join(cwes) or "N/A",
        "vuln_status": status,
    }
    return cve_id, document, extra


def upsert_epss(
    rows: Iterable[dict[str, Any]],
    *,
    db_dir: str | os.PathLike[str] | None = None,
) -> int:
    normalized = []
    for row in rows:
        cve_id = validate_cve_id(row.get("cve") or row.get("cve_id") or "")
        epss = float(row["epss"])
        percentile = float(row["percentile"])
        if not 0 <= epss <= 1 or not 0 <= percentile <= 1:
            raise ValueError(f"invalid EPSS values for {cve_id}")
        normalized.append(
            (
                cve_id,
                epss,
                percentile,
                str(row.get("score_date") or row.get("date") or ""),
                str(row.get("model_version") or "unknown"),
                str(row.get("retrieved_at") or utc_now()),
            )
        )
    if not normalized:
        return 0
    conn = _connect_catalog(db_dir, create=True)
    assert conn is not None
    try:
        with conn:
            conn.executemany(
                """
                INSERT INTO epss_current(cve_id, epss, percentile, score_date, model_version, retrieved_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    epss=excluded.epss,
                    percentile=excluded.percentile,
                    score_date=excluded.score_date,
                    model_version=excluded.model_version,
                    retrieved_at=excluded.retrieved_at
                """,
                normalized,
            )
    finally:
        conn.close()
    return len(normalized)


def top_epss_cves(
    limit: int = 750, *, db_dir: str | os.PathLike[str] | None = None
) -> set[str]:
    bounded = int(limit)
    if not 1 <= bounded <= 10_000:
        raise ValueError("EPSS result limit must be between 1 and 10000")
    conn = _connect_catalog(db_dir, create=False)
    if conn is None:
        return set()
    try:
        return {
            str(row["cve_id"])
            for row in conn.execute(
                "SELECT cve_id FROM epss_current ORDER BY epss DESC, cve_id LIMIT ?",
                (bounded,),
            )
        }
    finally:
        conn.close()


def prune_epss_snapshot(
    retrieved_at: str, *, db_dir: str | os.PathLike[str] | None = None
) -> int:
    conn = _connect_catalog(db_dir, create=True)
    assert conn is not None
    try:
        with conn:
            cursor = conn.execute(
                "DELETE FROM epss_current WHERE retrieved_at <> ?", (str(retrieved_at),)
            )
        return max(0, int(cursor.rowcount))
    finally:
        conn.close()


def upsert_kev(
    rows: Iterable[dict[str, Any]],
    *,
    catalog_version: str,
    retrieved_at: str | None = None,
    db_dir: str | os.PathLike[str] | None = None,
) -> int:
    now = retrieved_at or utc_now()
    normalized = []
    for row in rows:
        normalized.append(
            (
                validate_cve_id(row.get("cveID") or row.get("cve_id") or ""),
                str(row.get("vendorProject", "")),
                str(row.get("product", "")),
                str(row.get("vulnerabilityName", "")),
                str(row.get("dateAdded", "")),
                str(row.get("dueDate", "")),
                str(row.get("knownRansomwareCampaignUse", "Unknown")),
                str(catalog_version),
                now,
            )
        )
    if not normalized:
        return 0
    conn = _connect_catalog(db_dir, create=True)
    assert conn is not None
    try:
        with conn:
            conn.executemany(
                """
                INSERT INTO kev_catalog(
                    cve_id, vendor, product, vulnerability_name, date_added,
                    due_date, ransomware_use, catalog_version, retrieved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    vendor=excluded.vendor,
                    product=excluded.product,
                    vulnerability_name=excluded.vulnerability_name,
                    date_added=excluded.date_added,
                    due_date=excluded.due_date,
                    ransomware_use=excluded.ransomware_use,
                    catalog_version=excluded.catalog_version,
                    retrieved_at=excluded.retrieved_at
                """,
                normalized,
            )
    finally:
        conn.close()
    return len(normalized)


def kev_cve_ids(*, db_dir: str | os.PathLike[str] | None = None) -> set[str]:
    conn = _connect_catalog(db_dir, create=False)
    if conn is None:
        return set()
    try:
        return {str(row["cve_id"]) for row in conn.execute("SELECT cve_id FROM kev_catalog")}
    finally:
        conn.close()


def prune_kev_snapshot(
    retrieved_at: str, *, db_dir: str | os.PathLike[str] | None = None
) -> int:
    conn = _connect_catalog(db_dir, create=True)
    assert conn is not None
    try:
        with conn:
            cursor = conn.execute(
                "DELETE FROM kev_catalog WHERE retrieved_at <> ?", (str(retrieved_at),)
            )
        return max(0, int(cursor.rowcount))
    finally:
        conn.close()


def lookup_risk(
    cve_ids: Iterable[str], *, db_dir: str | os.PathLike[str] | None = None
) -> dict[str, dict[str, Any]]:
    ids = sorted({validate_cve_id(cve_id) for cve_id in cve_ids})
    if not ids:
        return {}
    conn = _connect_catalog(db_dir, create=False)
    if conn is None:
        return {}
    placeholders = ",".join("?" for _ in ids)
    output = {cve_id: {} for cve_id in ids}
    try:
        for row in conn.execute(
            f"SELECT * FROM epss_current WHERE cve_id IN ({placeholders})", ids
        ):
            output[row["cve_id"]]["epss"] = row["epss"]
            output[row["cve_id"]]["epss_percentile"] = row["percentile"]
            output[row["cve_id"]]["epss_date"] = row["score_date"]
        for row in conn.execute(
            f"SELECT * FROM kev_catalog WHERE cve_id IN ({placeholders})", ids
        ):
            output[row["cve_id"]]["known_exploited"] = True
            output[row["cve_id"]]["kev_date_added"] = row["date_added"]
            output[row["cve_id"]]["ransomware_use"] = row["ransomware_use"]
        return {key: value for key, value in output.items() if value}
    finally:
        conn.close()


def record_source_state(
    *,
    source_name: str,
    source_url: str,
    content_sha256: str,
    source_revision: str,
    record_count: int,
    status: str,
    chunk_count: int = 0,
    etag: str = "",
    last_modified: str = "",
    retrieved_at: str | None = None,
    schema_version: str = SCHEMA_VERSION,
    transform_version: str = TRANSFORM_VERSION,
    embedding_fingerprint: str = EMBEDDING_FINGERPRINT,
    db_dir: str | os.PathLike[str] | None = None,
) -> None:
    conn = _connect_catalog(db_dir, create=True)
    assert conn is not None
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO source_state(
                    source_name, source_url, etag, last_modified, content_sha256,
                    source_revision, record_count, chunk_count, retrieved_at, status,
                    schema_version, transform_version, embedding_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_name) DO UPDATE SET
                    source_url=excluded.source_url,
                    etag=excluded.etag,
                    last_modified=excluded.last_modified,
                    content_sha256=excluded.content_sha256,
                    source_revision=excluded.source_revision,
                    record_count=excluded.record_count,
                    chunk_count=excluded.chunk_count,
                    retrieved_at=excluded.retrieved_at,
                    status=excluded.status,
                    schema_version=excluded.schema_version,
                    transform_version=excluded.transform_version,
                    embedding_fingerprint=excluded.embedding_fingerprint
                """,
                (
                    source_name,
                    source_url,
                    etag,
                    last_modified,
                    content_sha256,
                    source_revision,
                    int(record_count),
                    int(chunk_count),
                    retrieved_at or utc_now(),
                    status,
                    schema_version,
                    transform_version,
                    embedding_fingerprint,
                ),
            )
    finally:
        conn.close()


def get_source_state(
    source_name: str, *, db_dir: str | os.PathLike[str] | None = None
) -> dict[str, Any] | None:
    conn = _connect_catalog(db_dir, create=False)
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT * FROM source_state WHERE source_name = ?", (str(source_name),)
        ).fetchone()
        return dict(row) if row is not None else None
    finally:
        conn.close()


def database_health(db_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    root = _db_root(db_dir)
    health: dict[str, Any] = {
        "db_path": str(root),
        "ready": False,
        "has_data": False,
        "schema_compatible": True,
        "source_complete": False,
        "cross_store_consistent": True,
        "catalog_integrity": "missing",
        "documents": 0,
        "vectors": {name: 0 for name in ALLOWED_COLLECTIONS},
        "sources": [],
        "errors": [],
        "warnings": [],
    }
    catalog_ids: dict[str, set[str]] = {name: set() for name in ALLOWED_COLLECTIONS}
    catalog_records: dict[str, dict[str, tuple[str, dict[str, Any]]]] = {
        name: {} for name in ALLOWED_COLLECTIONS
    }
    source_doc_counts: dict[str, int] = {}
    kev_count = 0
    epss_count = 0
    conn = _connect_catalog(root, create=False)
    if conn is not None:
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()
            health["catalog_integrity"] = str(integrity[0] if integrity else "unknown")
            if health["catalog_integrity"] != "ok":
                health["errors"].append(
                    f"catalog integrity: {health['catalog_integrity']}"
                )
            for row in conn.execute(
                "SELECT doc_id, collection_name, content, metadata_json FROM documents"
            ):
                collection_name = str(row["collection_name"])
                metadata = json.loads(row["metadata_json"])
                if collection_name in catalog_ids:
                    doc_id = str(row["doc_id"])
                    catalog_ids[collection_name].add(doc_id)
                    catalog_records[collection_name][doc_id] = (
                        str(row["content"]),
                        metadata,
                    )
                source_name = str(metadata.get("ingest_source") or metadata.get("source") or "")
                if source_name:
                    source_doc_counts[source_name] = source_doc_counts.get(source_name, 0) + 1
            health["documents"] = sum(len(ids) for ids in catalog_ids.values())
            kev_count = int(conn.execute("SELECT COUNT(*) FROM kev_catalog").fetchone()[0])
            epss_count = int(conn.execute("SELECT COUNT(*) FROM epss_current").fetchone()[0])
            health["sources"] = [dict(row) for row in conn.execute(
                "SELECT * FROM source_state ORDER BY source_name"
            )]
        except (sqlite3.DatabaseError, ValueError, json.JSONDecodeError) as exc:
            health["errors"].append(f"catalog: {type(exc).__name__}: {exc}")
        finally:
            conn.close()

    vector_ids: dict[str, set[str]] = {name: set() for name in ALLOWED_COLLECTIONS}
    vector_records: dict[str, dict[str, tuple[str, dict[str, Any]]]] = {
        name: {} for name in ALLOWED_COLLECTIONS
    }
    for collection_name in ALLOWED_COLLECTIONS:
        try:
            collection = get_collection(collection_name, create=False, db_dir=root)
            if collection is None:
                continue
            result = collection.get(include=["documents", "metadatas"])
            vector_ids[collection_name] = {str(doc_id) for doc_id in result.get("ids") or []}
            documents = result.get("documents") or []
            metadatas = result.get("metadatas") or []
            for index, doc_id in enumerate(result.get("ids") or []):
                vector_records[collection_name][str(doc_id)] = (
                    str(documents[index] if index < len(documents) else ""),
                    dict(metadatas[index] or {}) if index < len(metadatas) else {},
                )
            health["vectors"][collection_name] = len(vector_ids[collection_name])
        except Exception as exc:
            health["schema_compatible"] = False
            health["errors"].append(
                f"{collection_name}: {type(exc).__name__}: {exc}"
            )

    for collection_name in ALLOWED_COLLECTIONS:
        missing_vectors = catalog_ids[collection_name] - vector_ids[collection_name]
        missing_catalog = vector_ids[collection_name] - catalog_ids[collection_name]
        if missing_vectors or missing_catalog:
            health["cross_store_consistent"] = False
            health["errors"].append(
                f"{collection_name}: missing_vectors={len(missing_vectors)}, "
                f"missing_catalog={len(missing_catalog)}"
            )
        mismatched = 0
        for doc_id in catalog_ids[collection_name] & vector_ids[collection_name]:
            catalog_document, catalog_metadata = catalog_records[collection_name][doc_id]
            vector_document, vector_metadata = vector_records[collection_name][doc_id]
            if not _same_record(
                vector_document,
                vector_metadata,
                catalog_document,
                catalog_metadata,
            ):
                mismatched += 1
        if mismatched:
            health["cross_store_consistent"] = False
            health["errors"].append(
                f"{collection_name}: content_or_metadata_mismatch={mismatched}"
            )

    sources = health["sources"]
    if not sources:
        health["warnings"].append("no completed source manifests")
    source_complete = bool(sources)
    for source in sources:
        source_name = str(source.get("source_name", ""))
        if source.get("status") != "ok":
            source_complete = False
            health["errors"].append(
                f"source {source_name}: status={source.get('status')}"
            )
        for field, expected in (
            ("schema_version", SCHEMA_VERSION),
            ("transform_version", TRANSFORM_VERSION),
            ("embedding_fingerprint", EMBEDDING_FINGERPRINT),
        ):
            actual = str(source.get(field, ""))
            if actual != expected:
                source_complete = False
                health["errors"].append(
                    f"source {source_name}: {field}={actual!r}, expected={expected!r}"
                )
        expected_chunks = int(source.get("chunk_count", 0) or 0)
        if expected_chunks and source_doc_counts.get(source_name, 0) != expected_chunks:
            source_complete = False
            health["errors"].append(
                f"source {source_name}: documents={source_doc_counts.get(source_name, 0)}, "
                f"expected={expected_chunks}"
            )
        expected_records = int(source.get("record_count", 0) or 0)
        if source_name == "cisa-kev" and kev_count != expected_records:
            source_complete = False
            health["errors"].append(
                f"source cisa-kev: structured={kev_count}, expected={expected_records}"
            )
        if source_name == "first-epss" and epss_count != expected_records:
            source_complete = False
            health["errors"].append(
                f"source first-epss: structured={epss_count}, expected={expected_records}"
            )
        if source_name in {"cisa-kev", "first-epss", "nvd-recent"}:
            expected_digest = str(source.get("content_sha256", ""))
            candidates = list((root / "raw").glob(f"{source_name}-{expected_digest[:16]}.*"))
            valid_snapshot = False
            for candidate in candidates:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                digest = hashlib.sha256()
                with candidate.open("rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                if digest.hexdigest() == expected_digest:
                    valid_snapshot = True
                    break
            if not valid_snapshot:
                source_complete = False
                health["errors"].append(
                    f"source {source_name}: pinned raw snapshot missing or invalid"
                )

    health["source_complete"] = source_complete
    health["has_data"] = bool(health["documents"])
    health["ready"] = bool(
        health["has_data"]
        and health["schema_compatible"]
        and health["source_complete"]
        and health["cross_store_consistent"]
        and health["catalog_integrity"] == "ok"
    )
    return health


def catalog_stats(db_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    stats: dict[str, Any] = {
        "documents": 0,
        "epss": 0,
        "kev": 0,
        "sources": [],
        "db_path": str(_db_root(db_dir)),
    }
    conn = _connect_catalog(db_dir, create=False)
    if conn is None:
        return stats
    try:
        stats["documents"] = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        stats["epss"] = conn.execute("SELECT COUNT(*) FROM epss_current").fetchone()[0]
        stats["kev"] = conn.execute("SELECT COUNT(*) FROM kev_catalog").fetchone()[0]
        stats["sources"] = [dict(row) for row in conn.execute(
            "SELECT source_name, source_revision, record_count, retrieved_at, status FROM source_state ORDER BY source_name"
        )]
        return stats
    finally:
        conn.close()
