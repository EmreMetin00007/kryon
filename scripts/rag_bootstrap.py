#!/usr/bin/env python3
"""Build and refresh the local CCO security RAG from trusted public sources."""

from __future__ import annotations

import argparse
import csv
import fcntl
import gzip
import hashlib
import heapq
import io
import json
import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import requests


try:
    from .runtime_paths import runtime_root
except ImportError:
    from runtime_paths import runtime_root
REPO_ROOT = runtime_root()
if "CCO_HOME" not in os.environ:
    project_home = Path.cwd() / ".cco"
    os.environ["CCO_HOME"] = str(
        project_home if (Path.cwd() / "pyproject.toml").is_file() else Path.home() / ".cco"
    )
RAG_SERVER_DIR = REPO_ROOT / "mcp-servers" / "mcp-rag-engine"
if str(RAG_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(RAG_SERVER_DIR))

from cco_rag_core import (  # noqa: E402
    HAS_CHROMADB,
    build_chunk_records,
    build_metadata,
    catalog_stats,
    database_health,
    get_db_dir,
    get_source_state,
    hybrid_search,
    iter_safe_text_files,
    kev_cve_ids,
    normalize_nvd_record,
    prune_epss_snapshot,
    prune_kev_snapshot,
    record_source_state,
    reconcile_source_records,
    secure_rag_permissions,
    top_epss_cves,
    upsert_epss,
    upsert_kev,
    validate_cve_id,
)


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_LICENSE_URL = "https://www.cisa.gov/sites/default/files/licenses/kev/license.txt"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAYLOADS_REPO_URL = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
MAX_DOWNLOAD_BYTES = 150 * 1024 * 1024
PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600

SEED_CVES = (
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2021-34527",
    "CVE-2020-1472",
    "CVE-2019-19781",
    "CVE-2021-26855",
    "CVE-2021-21985",
    "CVE-2022-1388",
    "CVE-2023-23397",
    "CVE-2023-20198",
    "CVE-2024-3400",
    "CVE-2024-21413",
    "CVE-2024-6387",
    "CVE-2024-4577",
)

HIGH_SIGNAL_PAYLOAD_TERMS = (
    "api key leaks",
    "command injection",
    "cors misconfiguration",
    "directory traversal",
    "file inclusion",
    "graphql injection",
    "insecure direct object references",
    "json web token",
    "mass assignment",
    "nosql injection",
    "oauth",
    "open redirect",
    "prototype pollution",
    "race condition",
    "request smuggling",
    "server side request forgery",
    "server side template injection",
    "sql injection",
    "web cache",
    "xss injection",
    "xxe injection",
)

EVALUATION_QUERIES = (
    {"query": "CVE-2021-44228 Log4Shell", "expected": r"CVE-2021-44228"},
    {"query": "known exploited vulnerability required action", "expected": r"Known Exploited|Required Action"},
    {"query": "SQL injection authentication bypass", "expected": r"SQL Injection|SQL injection"},
    {"query": "server side request forgery cloud metadata", "expected": r"Server Side Request Forgery|SSRF"},
    {"query": "IDOR BOLA authorization", "expected": r"IDOR|BOLA|Insecure Direct Object"},
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _private_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    path.parent.chmod(PRIVATE_DIR_MODE)
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        PRIVATE_FILE_MODE,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    os.replace(temporary, path)
    path.chmod(PRIVATE_FILE_MODE)


@contextmanager
def bootstrap_lock(db_dir: Path):
    lock_dir = db_dir.parent
    lock_dir.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    lock_dir.chmod(PRIVATE_DIR_MODE)
    lock_path = lock_dir / ".rag-bootstrap.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, PRIVATE_FILE_MODE)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(f"another RAG bootstrap holds {lock_path}") from exc
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@dataclass(frozen=True)
class FetchResult:
    source_name: str
    source_url: str
    content: bytes | None
    content_sha256: str
    etag: str
    last_modified: str
    snapshot_path: str
    not_modified: bool = False


class OfficialFetcher:
    def __init__(self, db_dir: Path, *, refresh: bool = False):
        self.db_dir = db_dir
        self.refresh = refresh
        self.raw_dir = db_dir / "raw"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CCO-RAG/2.0 (+local security research index)"})

    def _snapshot_path(self, source_name: str, digest: str, suffix: str) -> Path:
        return self.raw_dir / f"{source_name}-{digest[:16]}.{suffix}"

    @staticmethod
    def _validate_response_origin(requested_url: str, response: requests.Response) -> None:
        requested = urlparse(requested_url)
        final = urlparse(str(getattr(response, "url", "") or requested_url))
        if final.scheme != "https" or final.hostname != requested.hostname:
            response.close()
            raise RuntimeError(
                f"redirected source escaped trusted origin: {requested.hostname} -> {final.hostname}"
            )

    def _cached_snapshot(
        self,
        source_name: str,
        source_url: str,
        state: dict[str, Any],
        *,
        suffix: str,
        max_bytes: int,
        not_modified: bool = True,
    ) -> FetchResult:
        digest = str(state.get("content_sha256", ""))
        snapshot = self._snapshot_path(source_name, digest, suffix)
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not snapshot.is_file() or snapshot.is_symlink():
            raise RuntimeError(f"cached snapshot unavailable for {source_name}")
        content = snapshot.read_bytes()
        if len(content) > max_bytes or sha256_bytes(content) != digest:
            raise RuntimeError(f"cached snapshot failed integrity validation for {source_name}")
        return FetchResult(
            source_name,
            source_url,
            content,
            digest,
            str(state.get("etag", "")),
            str(state.get("last_modified", "")),
            str(snapshot),
            not_modified,
        )

    def _request(self, url: str, *, headers: dict[str, str] | None = None,
                 params: dict[str, Any] | None = None, stream: bool = False) -> requests.Response:
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = self.session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=(10, 90),
                    stream=stream,
                )
                self._validate_response_origin(url, response)
                if response.status_code == 429 or response.status_code >= 500:
                    retry_after = min(float(response.headers.get("Retry-After", "2")), 30.0)
                    response.close()
                    if attempt < 2:
                        time.sleep(max(1.0, retry_after))
                        continue
                response.raise_for_status()
                return response
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
                if attempt < 2:
                    time.sleep(2 ** attempt)
        raise RuntimeError(f"download failed for {url}: {last_error}")

    def probe(self, url: str) -> dict[str, Any]:
        response = self._request(url, headers={"Range": "bytes=0-0"}, stream=True)
        try:
            return {
                "url": url,
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "content_length": response.headers.get("Content-Length", ""),
            }
        finally:
            response.close()

    def fetch(self, source_name: str, url: str, *, suffix: str,
              max_bytes: int = MAX_DOWNLOAD_BYTES) -> FetchResult:
        state = get_source_state(source_name, db_dir=self.db_dir)
        if state and state.get("status") == "in_progress" and not self.refresh:
            return self._cached_snapshot(
                source_name,
                url,
                state,
                suffix=suffix,
                max_bytes=max_bytes,
            )
        headers: dict[str, str] = {}
        if state and not self.refresh:
            if state.get("etag"):
                headers["If-None-Match"] = str(state["etag"])
            if state.get("last_modified"):
                headers["If-Modified-Since"] = str(state["last_modified"])
        response = self.session.get(url, headers=headers, timeout=(10, 90), stream=True)
        self._validate_response_origin(url, response)
        if response.status_code == 304 and state:
            response.close()
            return self._cached_snapshot(
                source_name,
                url,
                state,
                suffix=suffix,
                max_bytes=max_bytes,
            )
        if response.status_code == 429 or response.status_code >= 500:
            response.close()
            response = self._request(url, headers=headers, stream=True)
        response.raise_for_status()
        declared_size = response.headers.get("Content-Length", "")
        if declared_size and int(declared_size) > max_bytes:
            response.close()
            raise ValueError(f"{source_name} download exceeds {max_bytes} bytes")
        chunks = []
        received = 0
        try:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                received += len(chunk)
                if received > max_bytes:
                    raise ValueError(f"{source_name} download exceeds {max_bytes} bytes")
                chunks.append(chunk)
        finally:
            response.close()
        content = b"".join(chunks)
        digest = sha256_bytes(content)
        self.raw_dir.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
        self.raw_dir.chmod(PRIVATE_DIR_MODE)
        snapshot = self._snapshot_path(source_name, digest, suffix)
        if not snapshot.exists():
            _private_write(snapshot, content)
        return FetchResult(
            source_name,
            url,
            content,
            digest,
            response.headers.get("ETag", ""),
            response.headers.get("Last-Modified", ""),
            str(snapshot),
        )


def fetch_from_snapshot(
    path: str | os.PathLike[str],
    *,
    source_name: str,
    source_url: str,
    max_bytes: int,
) -> FetchResult:
    snapshot = Path(path).expanduser()
    if snapshot.is_symlink() or not snapshot.is_file():
        raise ValueError(f"snapshot is not a regular file: {snapshot}")
    resolved = snapshot.resolve()
    if resolved.stat().st_size > max_bytes:
        raise ValueError(f"snapshot exceeds {max_bytes} bytes")
    content = resolved.read_bytes()
    return FetchResult(
        source_name=source_name,
        source_url=source_url,
        content=content,
        content_sha256=sha256_bytes(content),
        etag="",
        last_modified="",
        snapshot_path=str(resolved),
        not_modified=True,
    )


def stage(source: str, status: str, records: int = 0, chunks: int = 0,
          detail: str = "") -> dict[str, Any]:
    return {
        "source": source,
        "status": status,
        "records": int(records),
        "chunks": int(chunks),
        "detail": detail,
    }


def ingest_cisa_kev(
    fetcher: OfficialFetcher,
    *,
    snapshot_path: str | os.PathLike[str] | None = None,
) -> tuple[dict[str, Any], set[str]]:
    if snapshot_path:
        fetched = fetch_from_snapshot(
            snapshot_path,
            source_name="cisa-kev",
            source_url=CISA_KEV_URL,
            max_bytes=30 * 1024 * 1024,
        )
        local_snapshot = fetcher._snapshot_path("cisa-kev", fetched.content_sha256, "json")
        if not local_snapshot.exists():
            assert fetched.content is not None
            _private_write(local_snapshot, fetched.content)
        fetched = FetchResult(
            **{
                **fetched.__dict__,
                "snapshot_path": str(local_snapshot),
            }
        )
    else:
        fetched = fetcher.fetch(
            "cisa-kev", CISA_KEV_URL, suffix="json", max_bytes=30 * 1024 * 1024
        )
    assert fetched.content is not None
    payload = json.loads(fetched.content)
    vulnerabilities = payload.get("vulnerabilities") or []
    declared_count = int(payload.get("count", len(vulnerabilities)))
    if declared_count != len(vulnerabilities):
        raise ValueError(
            f"CISA KEV count mismatch: envelope={declared_count}, actual={len(vulnerabilities)}"
        )
    catalog_version = str(payload.get("catalogVersion", "unknown"))
    retrieved_at = utc_now()
    records: list[dict[str, Any]] = []
    cve_ids: set[str] = set()
    for item in vulnerabilities:
        cve_id = validate_cve_id(item.get("cveID", ""))
        cve_ids.add(cve_id)
        title = str(item.get("vulnerabilityName") or cve_id)
        cwes = item.get("cwes") or []
        document = (
            f"CVE: {cve_id}\nKnown Exploited: Yes (CISA KEV)\n"
            f"Vendor: {item.get('vendorProject', '')}\nProduct: {item.get('product', '')}\n"
            f"Vulnerability: {title}\nDate Added: {item.get('dateAdded', '')}\n"
            f"Required Action: {item.get('requiredAction', '')}\nDue Date: {item.get('dueDate', '')}\n"
            f"Known Ransomware Campaign Use: {item.get('knownRansomwareCampaignUse', 'Unknown')}\n"
            f"CWE: {', '.join(cwes)}\nDescription: {item.get('shortDescription', '')}\n"
            f"Notes: {item.get('notes', '')}"
        )
        metadata = build_metadata(
            title=f"{cve_id} - {title}",
            source="cisa-kev",
            source_record_id=f"kev:{cve_id}",
            ingest_source="cisa-kev",
            source_url=CISA_KEV_URL,
            source_revision=catalog_version,
            license_id="CC0-1.0",
            license_url=CISA_KEV_LICENSE_URL,
            trust_tier="official",
            validation_status="known-exploited",
            category="cve",
            tags=f"{cve_id},{','.join(cwes)},kev,known-exploited",
            published_at=str(item.get("dateAdded", "")),
            extra={
                "cve_id": cve_id,
                "vendor": item.get("vendorProject", ""),
                "product": item.get("product", ""),
                "kev": True,
                "ransomware_use": item.get("knownRansomwareCampaignUse", "Unknown"),
            },
        )
        records.extend(build_chunk_records("cves", title=title, content=document, metadata=metadata))
    state_fields = {
        "source_name": "cisa-kev",
        "source_url": CISA_KEV_URL,
        "content_sha256": fetched.content_sha256,
        "source_revision": catalog_version,
        "record_count": len(vulnerabilities),
        "chunk_count": len(records),
        "etag": fetched.etag,
        "last_modified": fetched.last_modified,
        "retrieved_at": retrieved_at,
        "db_dir": fetcher.db_dir,
    }
    record_source_state(status="in_progress", **state_fields)
    upsert_kev(
        vulnerabilities,
        catalog_version=catalog_version,
        retrieved_at=retrieved_at,
        db_dir=fetcher.db_dir,
    )
    chunks = reconcile_source_records(
        "cves",
        records,
        ingest_source="cisa-kev",
        db_dir=fetcher.db_dir,
    )
    prune_kev_snapshot(retrieved_at, db_dir=fetcher.db_dir)
    record_source_state(
        status="ok",
        **state_fields,
    )
    detail = f"{'cached ' if fetched.not_modified else ''}snapshot: {fetched.snapshot_path}"
    return stage("cisa-kev", "ok", len(vulnerabilities), chunks, detail), cve_ids


def _read_gzip_bounded(content: bytes, max_bytes: int = 200 * 1024 * 1024) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(content)) as archive:
        decompressed = archive.read(max_bytes + 1)
    if len(decompressed) > max_bytes:
        raise ValueError("decompressed EPSS data exceeds safety limit")
    return decompressed


def ingest_epss(fetcher: OfficialFetcher, *, top_k: int = 750) -> tuple[dict[str, Any], set[str]]:
    fetched = fetcher.fetch("first-epss", EPSS_URL, suffix="csv.gz")
    assert fetched.content is not None
    text = _read_gzip_bounded(fetched.content).decode("utf-8", errors="replace")
    lines = text.splitlines()
    comments = [line for line in lines if line.startswith("#")]
    data_lines = [line for line in lines if line and not line.startswith("#")]
    model_match = re.search(r"model_version\s*:\s*([^,\s]+)", " ".join(comments), re.I)
    date_match = re.search(r"score_date\s*:\s*([^,\s]+)", " ".join(comments), re.I)
    model_version = model_match.group(1) if model_match else "unknown"
    score_date = date_match.group(1) if date_match else datetime.now(timezone.utc).date().isoformat()
    retrieved_at = utc_now()
    reader = csv.DictReader(data_lines)
    if not {"cve", "epss", "percentile"}.issubset(set(reader.fieldnames or [])):
        raise ValueError("EPSS feed is missing required columns")
    state_fields = {
        "source_name": "first-epss",
        "source_url": EPSS_URL,
        "content_sha256": fetched.content_sha256,
        "source_revision": f"{model_version}:{score_date}",
        "record_count": max(0, len(data_lines) - 1),
        "chunk_count": 0,
        "etag": fetched.etag,
        "last_modified": fetched.last_modified,
        "retrieved_at": retrieved_at,
        "db_dir": fetcher.db_dir,
    }
    record_source_state(status="in_progress", **state_fields)
    total = 0
    rejected = 0
    batch: list[dict[str, Any]] = []
    highest: list[tuple[float, str]] = []
    for row in reader:
        try:
            cve_id = validate_cve_id(row.get("cve", ""))
            score = float(row["epss"])
            percentile = float(row["percentile"])
        except (ValueError, TypeError, KeyError):
            rejected += 1
            continue
        batch.append({
            "cve": cve_id,
            "epss": score,
            "percentile": percentile,
            "score_date": score_date,
            "model_version": model_version,
            "retrieved_at": retrieved_at,
        })
        if len(highest) < top_k:
            heapq.heappush(highest, (score, cve_id))
        elif score > highest[0][0]:
            heapq.heapreplace(highest, (score, cve_id))
        if len(batch) >= 20_000:
            total += upsert_epss(batch, db_dir=fetcher.db_dir)
            batch = []
    if batch:
        total += upsert_epss(batch, db_dir=fetcher.db_dir)
    if total == 0 or rejected > max(100, total // 100):
        raise ValueError(f"EPSS feed validation failed: accepted={total}, rejected={rejected}")
    prune_epss_snapshot(retrieved_at, db_dir=fetcher.db_dir)
    state_fields["record_count"] = total
    record_source_state(
        status="ok",
        **state_fields,
    )
    detail = f"{model_version}, {score_date}{', cached snapshot' if fetched.not_modified else ''}"
    return stage("first-epss", "ok", total, 0, detail), {
        cve_id for _score, cve_id in highest
    }


def _nvd_headers() -> dict[str, str]:
    headers = {"User-Agent": "CCO-RAG/2.0 (+local security research index)"}
    api_key = os.environ.get("NVD_API_KEY", "")
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _nvd_request(fetcher: OfficialFetcher, params: dict[str, Any]) -> dict[str, Any]:
    response = fetcher._request(NVD_API_URL, headers=_nvd_headers(), params=params)
    return response.json()


def _nvd_records_to_chunks(
    vulnerabilities: Iterable[dict[str, Any]], *, ingest_source: str
) -> tuple[list[dict[str, Any]], set[str]]:
    records: list[dict[str, Any]] = []
    cves: set[str] = set()
    for item in vulnerabilities:
        cve_data = item.get("cve") or {}
        try:
            cve_id, document, extra = normalize_nvd_record(cve_data)
        except ValueError:
            continue
        cves.add(cve_id)
        metadata = build_metadata(
            title=cve_id,
            source="nvd",
            source_record_id=cve_id,
            ingest_source=ingest_source,
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            source_revision=str(cve_data.get("lastModified", "")),
            license_id="NIST-PD",
            license_url="https://www.nist.gov/open/license",
            trust_tier="official",
            validation_status="advisory",
            category="cve",
            tags=f"{cve_id},{extra.get('cwe', '')}",
            published_at=str(cve_data.get("published", "")),
            modified_at=str(cve_data.get("lastModified", "")),
            extra=extra,
        )
        records.extend(build_chunk_records("cves", title=cve_id, content=document, metadata=metadata))
    return records, cves


def ingest_nvd_recent(fetcher: OfficialFetcher, *, count: int = 100) -> tuple[dict[str, Any], set[str]]:
    if not 1 <= count <= 2_000:
        raise ValueError("cve_count must be between 1 and 2000")
    state = get_source_state("nvd-recent", db_dir=fetcher.db_dir)
    resumed = bool(state and state.get("status") == "in_progress" and not fetcher.refresh)
    responses: list[dict[str, Any]]
    if resumed:
        cached = fetcher._cached_snapshot(
            "nvd-recent",
            NVD_API_URL,
            state,
            suffix="json",
            max_bytes=30 * 1024 * 1024,
        )
        assert cached.content is not None
        decoded = json.loads(cached.content)
        if not isinstance(decoded, list) or not all(isinstance(item, dict) for item in decoded):
            raise ValueError("cached NVD snapshot has an invalid envelope")
        responses = decoded
        canonical = cached.content
        revision = str(state.get("source_revision", ""))
        snapshot = Path(cached.snapshot_path)
    else:
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=119)
        per_severity = {"HIGH": (count + 1) // 2, "CRITICAL": count // 2}
        responses = []
        for severity, requested in per_severity.items():
            if requested == 0:
                continue
            params = {
                "resultsPerPage": requested,
                "startIndex": 0,
                "lastModStartDate": start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "lastModEndDate": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "cvssV3Severity": severity,
            }
            payload = _nvd_request(fetcher, params)
            responses.append(payload)
            if not os.environ.get("NVD_API_KEY") and severity != "CRITICAL":
                time.sleep(6)
        canonical = json.dumps(responses, sort_keys=True, separators=(",", ":")).encode("utf-8")
        revision = now.date().isoformat()
        digest = sha256_bytes(canonical)
        snapshot = Path(fetcher.db_dir) / "raw" / f"nvd-recent-{digest[:16]}.json"
        if not snapshot.exists():
            _private_write(snapshot, canonical)

    vulnerabilities: list[dict[str, Any]] = []
    for payload in responses:
        vulnerabilities.extend(payload.get("vulnerabilities") or [])
    records, cves = _nvd_records_to_chunks(
        vulnerabilities, ingest_source="nvd-recent"
    )
    digest = sha256_bytes(canonical)
    state_fields = {
        "source_name": "nvd-recent",
        "source_url": NVD_API_URL,
        "content_sha256": digest,
        "source_revision": revision,
        "record_count": len(cves),
        "chunk_count": len(records),
        "db_dir": fetcher.db_dir,
    }
    record_source_state(status="in_progress", **state_fields)
    chunks = reconcile_source_records(
        "cves",
        records,
        ingest_source="nvd-recent",
        db_dir=fetcher.db_dir,
    )
    record_source_state(
        status="ok",
        **state_fields,
    )
    return stage(
        "nvd-recent",
        "ok",
        len(cves),
        chunks,
        f"{'resumed ' if resumed else ''}last-modified 119-day window; snapshot: {snapshot}",
    ), cves


def ingest_seed_cves(fetcher: OfficialFetcher) -> tuple[dict[str, Any], set[str]]:
    vulnerabilities: list[dict[str, Any]] = []
    failures = []
    for index, cve_id in enumerate(SEED_CVES):
        try:
            payload = _nvd_request(fetcher, {"cveId": cve_id})
            vulnerabilities.extend(payload.get("vulnerabilities") or [])
        except Exception as exc:
            failures.append(f"{cve_id}: {type(exc).__name__}")
        if not os.environ.get("NVD_API_KEY") and index < len(SEED_CVES) - 1:
            time.sleep(6)
    records, cves = _nvd_records_to_chunks(vulnerabilities, ingest_source="nvd-seed")
    status = "ok" if not failures else "partial"
    state_fields = {
        "source_name": "nvd-seed",
        "source_url": NVD_API_URL,
        "content_sha256": sha256_bytes("\n".join(sorted(cves)).encode("ascii")),
        "source_revision": datetime.now(timezone.utc).date().isoformat(),
        "record_count": len(cves),
        "chunk_count": len(records),
        "db_dir": fetcher.db_dir,
    }
    record_source_state(status="in_progress", **state_fields)
    chunks = reconcile_source_records(
        "cves",
        records,
        ingest_source="nvd-seed",
        delete_stale=not failures,
        db_dir=fetcher.db_dir,
    )
    record_source_state(
        status=status,
        **state_fields,
    )
    return stage("nvd-seed", status, len(cves), chunks, "; ".join(failures[:3])), cves


def _run_git(arguments: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def ensure_payloads_repo(db_dir: Path, *, refresh: bool = False) -> tuple[Path, str]:
    configured = os.environ.get("CCO_RAG_PAYLOADS_DIR", "")
    target = Path(configured).expanduser() if configured else db_dir.parent / "rag_sources" / "PayloadsAllTheThings"
    if target.is_symlink():
        raise ValueError("PayloadsAllTheThings source may not be a symlink")
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        result = _run_git(["clone", "--depth=1", PAYLOADS_REPO_URL, str(target)])
        if result.returncode != 0:
            raise RuntimeError(f"PayloadsAllTheThings clone failed: {result.stderr[-500:]}")
    elif not (target / ".git").is_dir():
        raise ValueError(f"existing payload source is not a Git checkout: {target}")
    elif refresh:
        result = _run_git(["-C", str(target), "pull", "--ff-only"])
        if result.returncode != 0:
            raise RuntimeError(f"PayloadsAllTheThings update failed: {result.stderr[-500:]}")
    revision_result = _run_git(["-C", str(target), "rev-parse", "HEAD"], timeout=15)
    revision = revision_result.stdout.strip()
    if revision_result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError("could not resolve PayloadsAllTheThings commit")
    remote_result = _run_git(["-C", str(target), "remote", "get-url", "origin"], timeout=15)
    if remote_result.returncode != 0 or remote_result.stdout.strip().rstrip("/") != PAYLOADS_REPO_URL.rstrip("/"):
        raise RuntimeError("PayloadsAllTheThings origin does not match the trusted repository")
    status_result = _run_git(["-C", str(target), "status", "--porcelain"], timeout=15)
    if status_result.returncode != 0 or status_result.stdout.strip():
        raise RuntimeError("PayloadsAllTheThings checkout must be clean before ingestion")
    contains_result = _run_git(
        ["-C", str(target), "branch", "-r", "--contains", revision], timeout=15
    )
    remote_refs = [line.strip() for line in contains_result.stdout.splitlines()]
    if contains_result.returncode != 0 or not any(
        ref.startswith("origin/") for ref in remote_refs
    ):
        raise RuntimeError("PayloadsAllTheThings HEAD is not present in a fetched origin ref")
    return target.resolve(), revision


def _high_signal_payload_path(relative_path: str) -> bool:
    normalized = relative_path.lower().replace("-", " ").replace("_", " ")
    return any(term in normalized for term in HIGH_SIGNAL_PAYLOAD_TERMS)


def ingest_payloads(fetcher: OfficialFetcher, *, selected_only: bool = True) -> dict[str, Any]:
    root, revision = ensure_payloads_repo(fetcher.db_dir, refresh=fetcher.refresh)
    files = 0
    errors = 0
    all_records: list[dict[str, Any]] = []
    source_digest = hashlib.sha256()
    for file_path, content, truncated in iter_safe_text_files(root):
        relative_path = file_path.relative_to(root).as_posix()
        if selected_only and not _high_signal_payload_path(relative_path):
            continue
        if len(content.strip()) < 50:
            continue
        metadata = build_metadata(
            title=file_path.stem,
            source="payloads_allthethings",
            source_record_id=relative_path,
            ingest_source="payloads-all-the-things",
            source_url=f"https://github.com/swisskyrepo/PayloadsAllTheThings/blob/{revision}/{relative_path}",
            source_revision=revision,
            license_id="MIT",
            license_url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LICENSE",
            trust_tier="curated",
            validation_status="unverified",
            category="technique",
            tags=relative_path.replace("/", ","),
            extra={"file_path": relative_path, "truncated": truncated},
        )
        records = build_chunk_records(
            "writeups", title=file_path.stem, content=content, metadata=metadata
        )
        try:
            all_records.extend(records)
            source_digest.update(relative_path.encode("utf-8"))
            source_digest.update(b"\x00")
            source_digest.update(sha256_bytes(content.encode("utf-8")).encode("ascii"))
            files += 1
        except Exception:
            errors += 1
    status = "ok" if errors == 0 else "partial"
    state_fields = {
        "source_name": "payloads-all-the-things",
        "source_url": PAYLOADS_REPO_URL,
        "content_sha256": source_digest.hexdigest(),
        "source_revision": revision,
        "record_count": files,
        "chunk_count": len(all_records),
        "db_dir": fetcher.db_dir,
    }
    record_source_state(status="in_progress", **state_fields)
    chunks = reconcile_source_records(
        "writeups",
        all_records,
        ingest_source="payloads-all-the-things",
        delete_stale=not errors,
        db_dir=fetcher.db_dir,
    )
    record_source_state(
        status=status,
        **state_fields,
    )
    return stage("payloads-all-the-things", status, files, chunks, f"{errors} file errors")


def ingest_local_exploitdb(db_dir: Path, selected_cves: set[str], *, limit: int = 2_000) -> dict[str, Any]:
    csv_path = Path(os.environ.get("CCO_EXPLOITDB_CSV", "/usr/share/exploitdb/files_exploits.csv"))
    if csv_path.is_symlink() or not csv_path.is_file():
        return stage("exploitdb", "skipped", detail=f"metadata not found: {csv_path}")
    selected = {validate_cve_id(cve_id) for cve_id in selected_cves}
    records_by_id: dict[str, dict[str, Any]] = {}
    matched_rows = 0
    digest = hashlib.sha256()
    with csv_path.open("rb") as raw:
        for block in iter(lambda: raw.read(1024 * 1024), b""):
            digest.update(block)
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if matched_rows >= limit:
                break
            if str(row.get("verified", "")) != "1" or str(row.get("type", "")).lower() == "dos":
                continue
            cve_ids = {
                value.upper()
                for value in re.findall(r"CVE-\d{4}-\d{4,7}", str(row.get("codes", "")), re.I)
            }
            if selected and not cve_ids.intersection(selected):
                continue
            edb_id = str(row.get("id", "")).strip()
            title = str(row.get("description", ""))[:500]
            document = (
                f"ExploitDB ID: {edb_id}\nTitle: {title}\n"
                f"CVE: {', '.join(sorted(cve_ids))}\nType: {row.get('type', '')}\n"
                f"Platform: {row.get('platform', '')}\nAuthor: {row.get('author', '')}\n"
                f"Published: {row.get('date_published', '')}\nVerified by ExploitDB: Yes\n"
                "Exploit source is intentionally not embedded; retrieve and review the pinned local file on demand."
            )
            metadata = build_metadata(
                title=title,
                source="exploitdb",
                source_record_id=edb_id,
                ingest_source="exploitdb",
                source_url=f"https://www.exploit-db.com/exploits/{edb_id}",
                source_revision=digest.hexdigest()[:16],
                license_id="GPL-2.0-or-later",
                trust_tier="community",
                validation_status="source-verified",
                category="exploit",
                tags=f"{row.get('type', '')},{row.get('platform', '')},{','.join(sorted(cve_ids))}",
                published_at=str(row.get("date_published", "")),
                modified_at=str(row.get("date_updated", "")),
                extra={"edb_id": edb_id, "cve_ids": sorted(cve_ids), "file_path": row.get("file", "")},
            )
            candidate_records = build_chunk_records(
                "exploits", title=title, content=document, metadata=metadata
            )
            new_record = False
            for record in candidate_records:
                doc_id = str(record["id"])
                existing = records_by_id.get(doc_id)
                if existing is not None:
                    existing_hash = str(existing["metadata"].get("record_sha256", ""))
                    candidate_hash = str(record["metadata"].get("record_sha256", ""))
                    if existing_hash != candidate_hash:
                        raise ValueError(f"conflicting ExploitDB records for document ID {doc_id}")
                    continue
                records_by_id[doc_id] = record
                new_record = True
            matched_rows += int(new_record)
    records = list(records_by_id.values())
    state_fields = {
        "source_name": "exploitdb",
        "source_url": "https://gitlab.com/exploit-database/exploitdb",
        "content_sha256": digest.hexdigest(),
        "source_revision": digest.hexdigest()[:16],
        "record_count": matched_rows,
        "chunk_count": len(records),
        "db_dir": db_dir,
    }
    record_source_state(status="in_progress", **state_fields)
    chunks = reconcile_source_records(
        "exploits",
        records,
        ingest_source="exploitdb",
        db_dir=db_dir,
    )
    record_source_state(
        status="ok",
        **state_fields,
    )
    return stage("exploitdb", "ok", matched_rows, chunks, "verified metadata only")


def evaluate_index(db_dir: Path) -> dict[str, Any]:
    cases = []
    reciprocal_rank_total = 0.0
    hits = 0
    for definition in EVALUATION_QUERIES:
        result = hybrid_search(
            definition["query"], collection="all", top_k=5, min_relevance=0.0, db_dir=db_dir
        )
        rank = 0
        for index, item in enumerate(result["results"], 1):
            haystack = f"{item.get('content', '')}\n{json.dumps(item.get('metadata') or {})}"
            if re.search(definition["expected"], haystack, re.I):
                rank = index
                break
        if rank:
            hits += 1
            reciprocal_rank_total += 1.0 / rank
        cases.append({
            "query": definition["query"],
            "expected": definition["expected"],
            "rank": rank,
            "passed": bool(rank),
            "returned": len(result["results"]),
            "errors": result["errors"],
        })
    report = {
        "schema": "cco-rag-evaluation/1.0",
        "generated_at": utc_now(),
        "queries": len(cases),
        "hit_rate_at_5": round(hits / len(cases), 4),
        "mrr_at_5": round(reciprocal_rank_total / len(cases), 4),
        "cases": cases,
    }
    output = db_dir / "evaluation.json"
    _private_write(
        output,
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    report["artifact"] = str(output)
    return report


def print_stats(db_dir: Path, *, json_output: bool = False) -> dict[str, Any]:
    structured = catalog_stats(db_dir)
    health = database_health(db_dir)
    vectors = dict(health["vectors"])
    result = {
        "db_path": str(db_dir),
        "vectors": vectors,
        "catalog": structured,
        "health": health,
    }
    if json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("RAG database status")
        print("=" * 48)
        for name, count in vectors.items():
            print(f"  {name:12s}: {count:,} vector chunks")
        print(f"  {'fts':12s}: {structured['documents']:,} documents")
        print(f"  {'cisa-kev':12s}: {structured['kev']:,} records")
        print(f"  {'first-epss':12s}: {structured['epss']:,} records")
        print(f"  {'ready':12s}: {health['ready']}")
        if health["errors"]:
            print(f"  {'errors':12s}: {'; '.join(health['errors'])}")
        print(f"  path         : {db_dir}")
    return result


def dry_run(fetcher: OfficialFetcher, payloads_path: Path) -> list[dict[str, Any]]:
    checks = []
    for name, url in (("cisa-kev", CISA_KEV_URL), ("first-epss", EPSS_URL), ("nvd", NVD_API_URL)):
        try:
            checks.append({"source": name, "status": "ok", **fetcher.probe(url)})
        except Exception as exc:
            checks.append({"source": name, "status": "failed", "error": str(exc)})
    git_check = _run_git(["ls-remote", "--exit-code", PAYLOADS_REPO_URL, "HEAD"], timeout=30)
    checks.append({
        "source": "payloads-all-the-things",
        "status": "ok" if git_check.returncode == 0 else "failed",
        "path": str(payloads_path),
    })
    exploitdb_path = Path(os.environ.get("CCO_EXPLOITDB_CSV", "/usr/share/exploitdb/files_exploits.csv"))
    checks.append({
        "source": "exploitdb",
        "status": "ok" if exploitdb_path.is_file() and not exploitdb_path.is_symlink() else "skipped",
        "path": str(exploitdb_path),
    })
    return checks


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the CCO local security RAG")
    parser.add_argument("--dry-run", action="store_true", help="probe sources without writing data")
    parser.add_argument("--cve-only", action="store_true", help="ingest KEV and NVD CVE records only")
    parser.add_argument("--payloads-only", action="store_true", help="ingest PayloadsAllTheThings only")
    parser.add_argument("--seed-only", action="store_true", help="ingest the curated NVD seed CVEs only")
    parser.add_argument("--kev-only", action="store_true", help="ingest the CISA KEV catalog only")
    parser.add_argument("--epss-only", action="store_true", help="ingest FIRST EPSS structured scores only")
    parser.add_argument("--exploitdb-only", action="store_true", help="ingest local ExploitDB metadata only")
    parser.add_argument("--cve-count", type=int, default=100, help="recent HIGH/CRITICAL NVD records")
    parser.add_argument("--top-epss", type=int, default=750, help="EPSS CVEs retained for enrichment selection")
    parser.add_argument("--all-payloads", action="store_true", help="index every bounded Markdown/text payload file")
    parser.add_argument("--skip-payloads", action="store_true")
    parser.add_argument("--skip-epss", action="store_true")
    parser.add_argument("--skip-kev", action="store_true")
    parser.add_argument("--skip-exploitdb", action="store_true")
    parser.add_argument("--refresh", action="store_true", help="ignore conditional cache and refresh sources")
    parser.add_argument(
        "--from-snapshot",
        metavar="PATH",
        help="recover CISA KEV from a pinned local snapshot (requires --kev-only)",
    )
    parser.add_argument(
        "--adopt-legacy-collections",
        action="store_true",
        help="attach current schema metadata to legacy collections with no CCO metadata",
    )
    parser.add_argument("--stats", action="store_true", help="show database statistics and exit")
    parser.add_argument("--doctor", action="store_true", help="verify source and cross-store completeness")
    parser.add_argument("--evaluate-only", action="store_true", help="run retrieval evaluation and exit")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def _execute(args: argparse.Namespace, db_dir: Path, payloads_path: Path) -> int:
    fetcher = OfficialFetcher(db_dir, refresh=args.refresh)

    if args.dry_run:
        checks = dry_run(fetcher, payloads_path)
        if args.json:
            print(json.dumps({"dry_run": checks}, indent=2, sort_keys=True))
        else:
            for check in checks:
                print(f"{check['source']}: {check['status']}")
        return 0 if all(check["status"] in {"ok", "skipped"} for check in checks) else 1
    if args.stats:
        print_stats(db_dir, json_output=args.json)
        return 0
    if args.doctor:
        health = database_health(db_dir)
        print(json.dumps(health, indent=2, sort_keys=True))
        return 0 if health["ready"] else 1
    if args.evaluate_only:
        report = evaluate_index(db_dir)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["hit_rate_at_5"] >= 0.6 else 1
    if not HAS_CHROMADB:
        print("ERROR: chromadb is required; install the project runtime dependencies", file=sys.stderr)
        return 2
    if not 1 <= args.cve_count <= 2_000 or not 1 <= args.top_epss <= 10_000:
        print("ERROR: invalid cve-count/top-epss bounds", file=sys.stderr)
        return 2

    exclusive = [args.cve_only, args.payloads_only, args.seed_only, args.kev_only,
                 args.epss_only, args.exploitdb_only]
    if sum(bool(value) for value in exclusive) > 1:
        print("ERROR: source-only modes are mutually exclusive", file=sys.stderr)
        return 2

    stages: list[dict[str, Any]] = []
    selected_cves = (
        set(SEED_CVES)
        | kev_cve_ids(db_dir=db_dir)
        | top_epss_cves(args.top_epss, db_dir=db_dir)
    )
    started = time.monotonic()

    def run_source(name: str, callback):
        try:
            return callback()
        except Exception as exc:
            stages.append(stage(name, "failed", detail=f"{type(exc).__name__}: {exc}"))
            return None

    if args.payloads_only:
        result = run_source(
            "payloads-all-the-things",
            lambda: ingest_payloads(fetcher, selected_only=not args.all_payloads),
        )
        if result:
            stages.append(result)
    elif args.seed_only:
        result = run_source("nvd-seed", lambda: ingest_seed_cves(fetcher))
        if result:
            source_stage, cves = result
            stages.append(source_stage)
            selected_cves.update(cves)
    elif args.kev_only:
        result = run_source(
            "cisa-kev",
            lambda: ingest_cisa_kev(fetcher, snapshot_path=args.from_snapshot),
        )
        if result:
            source_stage, cves = result
            stages.append(source_stage)
            selected_cves.update(cves)
    elif args.epss_only:
        result = run_source("first-epss", lambda: ingest_epss(fetcher, top_k=args.top_epss))
        if result:
            source_stage, _cves = result
            stages.append(source_stage)
    elif args.exploitdb_only:
        stages.append(ingest_local_exploitdb(db_dir, selected_cves))
    else:
        if not args.skip_kev:
            result = run_source("cisa-kev", lambda: ingest_cisa_kev(fetcher))
            if result:
                source_stage, cves = result
                stages.append(source_stage)
                selected_cves.update(cves)
        if not args.skip_epss and not args.cve_only:
            result = run_source("first-epss", lambda: ingest_epss(fetcher, top_k=args.top_epss))
            if result:
                source_stage, cves = result
                stages.append(source_stage)
                selected_cves.update(cves)
        result = run_source("nvd-recent", lambda: ingest_nvd_recent(fetcher, count=args.cve_count))
        if result:
            source_stage, cves = result
            stages.append(source_stage)
            selected_cves.update(cves)
        if not args.cve_only and not args.skip_payloads:
            result = run_source(
                "payloads-all-the-things",
                lambda: ingest_payloads(fetcher, selected_only=not args.all_payloads),
            )
            if result:
                stages.append(result)
        if not args.cve_only and not args.skip_exploitdb:
            result = run_source(
                "exploitdb", lambda: ingest_local_exploitdb(db_dir, selected_cves)
            )
            if result:
                stages.append(result)

    evaluation = None
    if stages and not args.epss_only and all(
        item["status"] in {"ok", "skipped"} for item in stages
    ):
        try:
            evaluation = evaluate_index(db_dir)
        except Exception as exc:
            stages.append(stage("evaluation", "failed", detail=f"{type(exc).__name__}: {exc}"))

    summary = {
        "schema": "cco-rag-bootstrap/2.0",
        "db_path": str(db_dir),
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "stages": stages,
        "evaluation": evaluation,
        "stats": print_stats(db_dir, json_output=False) if not args.json else None,
    }
    if args.json:
        health = database_health(db_dir)
        summary["stats"] = {
            "catalog": catalog_stats(db_dir),
            "vectors": health["vectors"],
            "health": health,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("\nBootstrap stages")
        print("=" * 48)
        for item in stages:
            print(
                f"  {item['source']:28s} {item['status']:12s} "
                f"records={item['records']:,} chunks={item['chunks']:,} {item['detail']}"
            )
        if evaluation:
            print(
                f"  evaluation: hit@5={evaluation['hit_rate_at_5']:.2f} "
                f"MRR@5={evaluation['mrr_at_5']:.2f}"
            )
    failed = [
        item for item in stages if item["status"] in {"failed", "partial", "interrupted"}
    ]
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    db_dir = get_db_dir()
    payloads_path = Path(os.environ.get("CCO_RAG_PAYLOADS_DIR", "")) if os.environ.get(
        "CCO_RAG_PAYLOADS_DIR"
    ) else db_dir.parent / "rag_sources" / "PayloadsAllTheThings"

    if args.adopt_legacy_collections:
        os.environ["CCO_RAG_ADOPT_LEGACY"] = "1"
    if args.from_snapshot and not args.kev_only:
        print("ERROR: --from-snapshot requires --kev-only", file=sys.stderr)
        return 2

    read_only = (args.dry_run or args.stats or args.doctor) and not args.adopt_legacy_collections
    try:
        if read_only:
            return _execute(args, db_dir, payloads_path)
        with bootstrap_lock(db_dir):
            return _execute(args, db_dir, payloads_path)
    except KeyboardInterrupt:
        message = {
            "schema": "cco-rag-bootstrap/2.0",
            "db_path": str(db_dir),
            "status": "interrupted",
            "detail": "active source remains in_progress and can be resumed",
        }
        if args.json:
            print(json.dumps(message, indent=2, sort_keys=True))
        else:
            print("RAG bootstrap interrupted; rerun to resume the in-progress source.", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        if args.json:
            print(json.dumps({"status": "failed", "error": str(exc)}, indent=2, sort_keys=True))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        secure_rag_permissions(db_dir)


if __name__ == "__main__":
    raise SystemExit(main())
