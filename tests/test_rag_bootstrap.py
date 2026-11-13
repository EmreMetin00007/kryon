import csv
import gzip
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def _module():
    from scripts import rag_bootstrap

    return rag_bootstrap


class FakeFetcher:
    def __init__(self, db_dir, content):
        self.db_dir = Path(db_dir)
        self.refresh = False
        self.content = content

    def fetch(self, source_name, source_url, **_kwargs):
        mod = _module()
        return mod.FetchResult(
            source_name=source_name,
            source_url=source_url,
            content=self.content,
            content_sha256="a" * 64,
            etag="etag",
            last_modified="Wed, 22 Jul 2026 00:00:00 GMT",
            snapshot_path="/tmp/snapshot",
        )


class _NotModifiedResponse:
    status_code = 304
    headers = {}

    def close(self):
        return None


def test_cisa_kev_ingest_validates_count_and_preserves_provenance(tmp_path, monkeypatch):
    mod = _module()
    payload = {
        "catalogVersion": "2026.07.22",
        "count": 1,
        "vulnerabilities": [{
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "shortDescription": "Remote code execution",
            "requiredAction": "Apply updates",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "cwes": ["CWE-502"],
        }],
    }
    captured = {}
    monkeypatch.setattr(mod, "upsert_kev", lambda rows, **kwargs: captured.setdefault("kev", list(rows)) and 1)
    monkeypatch.setattr(
        mod,
        "reconcile_source_records",
        lambda _name, records, **_kwargs: captured.setdefault("records", records) and len(records),
    )
    monkeypatch.setattr(mod, "record_source_state", lambda **kwargs: captured.setdefault("state", kwargs))

    result, cves = mod.ingest_cisa_kev(FakeFetcher(tmp_path / "rag_db", json.dumps(payload).encode()))

    assert result["status"] == "ok"
    assert cves == {"CVE-2021-44228"}
    assert captured["records"][0]["metadata"]["source"] == "cisa-kev"
    assert captured["records"][0]["metadata"]["license_id"] == "CC0-1.0"
    assert captured["state"]["source_revision"] == "2026.07.22"


def test_cisa_kev_rejects_mismatched_envelope_count(tmp_path):
    mod = _module()
    payload = {"catalogVersion": "1", "count": 2, "vulnerabilities": []}

    try:
        mod.ingest_cisa_kev(FakeFetcher(tmp_path / "rag_db", json.dumps(payload).encode()))
    except ValueError as exc:
        assert "count mismatch" in str(exc)
    else:
        raise AssertionError("mismatched CISA count was accepted")


def test_conditional_304_rehydrates_the_pinned_snapshot(tmp_path, monkeypatch):
    mod = _module()
    db_dir = tmp_path / "rag_db"
    content = b'{"count":0,"vulnerabilities":[]}'
    digest = hashlib.sha256(content).hexdigest()
    raw_dir = db_dir / "raw"
    raw_dir.mkdir(parents=True)
    snapshot = raw_dir / f"cisa-kev-{digest[:16]}.json"
    snapshot.write_bytes(content)
    mod.record_source_state(
        source_name="cisa-kev",
        source_url=mod.CISA_KEV_URL,
        content_sha256=digest,
        source_revision="one",
        record_count=0,
        status="ok",
        db_dir=db_dir,
    )
    fetcher = mod.OfficialFetcher(db_dir)
    monkeypatch.setattr(fetcher.session, "get", lambda *_args, **_kwargs: _NotModifiedResponse())

    fetched = fetcher.fetch("cisa-kev", mod.CISA_KEV_URL, suffix="json")

    assert fetched.not_modified is True
    assert fetched.content == content
    assert fetched.snapshot_path == str(snapshot)


def test_official_fetcher_rejects_cross_origin_redirect(tmp_path):
    mod = _module()
    response = SimpleNamespace(url="https://evil.example/feed", closed=False)
    response.close = lambda: setattr(response, "closed", True)

    with pytest.raises(RuntimeError, match="escaped trusted origin"):
        mod.OfficialFetcher._validate_response_origin(mod.CISA_KEV_URL, response)

    assert response.closed is True


def test_kev_snapshot_recovery_never_calls_network(tmp_path, monkeypatch):
    mod = _module()
    payload = {
        "catalogVersion": "2026.07.22",
        "count": 1,
        "vulnerabilities": [{
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "shortDescription": "Remote code execution",
            "requiredAction": "Apply updates",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "cwes": ["CWE-502"],
        }],
    }
    snapshot = tmp_path / "kev.json"
    snapshot.write_text(json.dumps(payload), encoding="utf-8")
    fetcher = mod.OfficialFetcher(tmp_path / "cco" / "rag_db")
    monkeypatch.setattr(
        fetcher,
        "fetch",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network used")),
    )
    monkeypatch.setattr(mod, "upsert_kev", lambda rows, **_kwargs: len(rows))
    monkeypatch.setattr(
        mod, "reconcile_source_records", lambda _name, records, **_kwargs: len(records)
    )
    states = []
    monkeypatch.setattr(mod, "record_source_state", lambda **kwargs: states.append(kwargs))

    result, cves = mod.ingest_cisa_kev(fetcher, snapshot_path=snapshot)

    assert result["status"] == "ok"
    assert cves == {"CVE-2021-44228"}
    assert [item["status"] for item in states] == ["in_progress", "ok"]
    assert Path(result["detail"].split("snapshot: ", 1)[1]).is_file()


def test_bootstrap_lock_is_single_writer(tmp_path):
    mod = _module()
    db_dir = tmp_path / "cco" / "rag_db"

    with mod.bootstrap_lock(db_dir):
        with pytest.raises(RuntimeError, match="another RAG bootstrap"):
            with mod.bootstrap_lock(db_dir):
                pass


def test_snapshot_cli_requires_kev_only(tmp_path, monkeypatch):
    mod = _module()
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "cco"))

    assert mod.main(["--from-snapshot", str(tmp_path / "missing.json")]) == 2


def test_legacy_adoption_uses_the_writer_lock(tmp_path, monkeypatch):
    mod = _module()
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "cco"))
    entered = []

    class FakeLock:
        def __enter__(self):
            entered.append(True)

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(mod, "bootstrap_lock", lambda _db_dir: FakeLock())
    monkeypatch.setattr(mod, "_execute", lambda *_args: 0)
    monkeypatch.setattr(mod, "secure_rag_permissions", lambda _db_dir: None)

    assert mod.main(["--doctor", "--adopt-legacy-collections", "--json"]) == 0
    assert entered == [True]


def test_payload_checkout_requires_head_in_fetched_origin_ref(tmp_path, monkeypatch):
    mod = _module()
    checkout = tmp_path / "PayloadsAllTheThings"
    (checkout / ".git").mkdir(parents=True)
    monkeypatch.setenv("CCO_RAG_PAYLOADS_DIR", str(checkout))
    revision = "a" * 40

    def fake_git(arguments, **_kwargs):
        command = arguments[2:]
        if command == ["rev-parse", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout=revision + "\n", stderr="")
        if command == ["remote", "get-url", "origin"]:
            return SimpleNamespace(returncode=0, stdout=mod.PAYLOADS_REPO_URL + "\n", stderr="")
        if command == ["status", "--porcelain"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command == ["branch", "-r", "--contains", revision]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(command)

    monkeypatch.setattr(mod, "_run_git", fake_git)

    with pytest.raises(RuntimeError, match="not present in a fetched origin ref"):
        mod.ensure_payloads_repo(tmp_path / "rag_db")


def test_epss_is_kept_structured_and_returns_top_cves(tmp_path, monkeypatch):
    mod = _module()
    content = (
        "#model_version:v4,score_date:2026-07-22\n"
        "cve,epss,percentile\n"
        "CVE-2024-1111,0.10,0.50\n"
        "CVE-2024-2222,0.90,0.99\n"
    ).encode()
    batches = []
    monkeypatch.setattr(mod, "upsert_epss", lambda rows, **_kwargs: batches.extend(rows) or len(rows))
    monkeypatch.setattr(mod, "record_source_state", lambda **_kwargs: None)

    result, top = mod.ingest_epss(
        FakeFetcher(tmp_path / "rag_db", gzip.compress(content)), top_k=1
    )

    assert result["records"] == 2
    assert top == {"CVE-2024-2222"}
    assert batches[0]["model_version"] == "v4"


def test_nvd_recent_odd_count_fetches_one_record(tmp_path, monkeypatch):
    mod = _module()
    requests_seen = []

    def fake_request(_fetcher, params):
        requests_seen.append(params)
        return {"vulnerabilities": [{"cve": {
            "id": "CVE-2026-12345",
            "published": "2026-07-20T00:00:00Z",
            "lastModified": "2026-07-21T00:00:00Z",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Example"}],
            "metrics": {},
            "weaknesses": [],
            "references": [],
        }}]}

    monkeypatch.setattr(mod, "_nvd_request", fake_request)
    monkeypatch.setattr(
        mod, "reconcile_source_records", lambda _name, records, **_kwargs: len(records)
    )
    monkeypatch.setattr(mod, "record_source_state", lambda **_kwargs: None)
    monkeypatch.setattr(mod.time, "sleep", lambda _seconds: None)

    result, cves = mod.ingest_nvd_recent(SimpleNamespace(db_dir=tmp_path / "rag_db"), count=1)

    assert requests_seen[0]["resultsPerPage"] == 1
    assert cves == {"CVE-2026-12345"}
    assert result["records"] == 1


def test_nvd_in_progress_run_resumes_from_raw_snapshot(tmp_path, monkeypatch):
    mod = _module()
    db_dir = tmp_path / "rag_db"
    responses = [{"vulnerabilities": [{"cve": {
        "id": "CVE-2026-12345",
        "published": "2026-07-20T00:00:00Z",
        "lastModified": "2026-07-21T00:00:00Z",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Example"}],
        "metrics": {},
        "weaknesses": [],
        "references": [],
    }}]}]
    canonical = json.dumps(responses, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    raw_dir = db_dir / "raw"
    raw_dir.mkdir(parents=True)
    snapshot = raw_dir / f"nvd-recent-{digest[:16]}.json"
    snapshot.write_bytes(canonical)
    mod.record_source_state(
        source_name="nvd-recent",
        source_url=mod.NVD_API_URL,
        content_sha256=digest,
        source_revision="2026-07-22",
        record_count=1,
        chunk_count=1,
        status="in_progress",
        db_dir=db_dir,
    )
    fetcher = mod.OfficialFetcher(db_dir)
    monkeypatch.setattr(
        mod,
        "_nvd_request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network used")),
    )
    monkeypatch.setattr(
        mod, "reconcile_source_records", lambda _name, records, **_kwargs: len(records)
    )

    result, cves = mod.ingest_nvd_recent(fetcher, count=100)

    assert result["status"] == "ok"
    assert "resumed" in result["detail"]
    assert cves == {"CVE-2026-12345"}


def test_exploitdb_ingests_verified_matching_metadata_only(tmp_path, monkeypatch):
    mod = _module()
    csv_path = tmp_path / "files_exploits.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "id", "file", "description", "date_published", "author", "type", "platform",
            "date_updated", "verified", "codes",
        ])
        writer.writeheader()
        writer.writerow({
            "id": "99999", "file": "exploits/linux/remote/99999.py",
            "description": "Example RCE", "date_published": "2026-01-01", "author": "Researcher",
            "type": "remote", "platform": "linux", "date_updated": "2026-01-02",
            "verified": "1", "codes": "CVE-2026-12345",
        })
        writer.writerow({
            "id": "99999", "file": "exploits/linux/remote/99999.py",
            "description": "Example RCE", "date_published": "2026-01-01", "author": "Researcher",
            "type": "remote", "platform": "linux", "date_updated": "2026-01-02",
            "verified": "1", "codes": "CVE-2026-12345",
        })
        writer.writerow({
            "id": "99998", "file": "exploits/linux/dos/99998.py",
            "description": "DoS", "type": "dos", "platform": "linux", "verified": "1",
            "codes": "CVE-2026-12345",
        })
    monkeypatch.setenv("CCO_EXPLOITDB_CSV", str(csv_path))
    captured = []
    monkeypatch.setattr(
        mod,
        "reconcile_source_records",
        lambda _name, records, **_kwargs: captured.extend(records) or len(records),
    )
    monkeypatch.setattr(mod, "record_source_state", lambda **_kwargs: None)

    result = mod.ingest_local_exploitdb(tmp_path / "rag_db", {"CVE-2026-12345"})

    assert result["records"] == 1
    assert len(captured) == 1
    assert "intentionally not embedded" in captured[0]["document"]
