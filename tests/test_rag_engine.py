import asyncio
import inspect
import json
from types import SimpleNamespace

from conftest import load_server


RAG_TOOLS = [
    "rag_search",
    "rag_similar_exploits",
    "rag_ingest_exploitdb",
    "rag_ingest_writeup",
    "rag_ingest_cve",
    "rag_bulk_ingest",
    "rag_stats",
]


def test_rag_facade_preserves_tool_contract():
    module = load_server("rag-engine")

    assert [tool.name for tool in asyncio.run(module.mcp.list_tools())] == RAG_TOOLS
    assert list(inspect.signature(module.rag_search).parameters) == ["query", "collection", "top_k"]
    assert list(inspect.signature(module.rag_bulk_ingest).parameters) == ["source", "path"]


def test_searchsploit_uses_argument_vector_without_shell(monkeypatch):
    module = load_server("rag-engine")
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"RESULTS_EXPLOIT": [{"Title": "Apache example", "Path": ""}]}),
            stderr="",
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    def fake_replace(_name, records, **_kwargs):
        captured["metadata"] = records[0]["metadata"]
        return len(records)

    monkeypatch.setattr(module, "replace_source_documents", fake_replace)
    monkeypatch.setattr(module, "get_collection", lambda *_args, **_kwargs: SimpleNamespace(count=lambda: 1))

    output = module.rag_ingest_exploitdb("apache 2.4", max_results=3)

    assert captured["args"] == ["searchsploit", "-j", "apache", "2.4"]
    assert "shell" not in captured["kwargs"]
    assert captured["metadata"]["ingest_source"] == "mcp-exploitdb"
    assert "1 chunk" in output


def test_searchsploit_rejects_option_and_shell_syntax(monkeypatch):
    module = load_server("rag-engine")
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    assert "HATA" in module.rag_ingest_exploitdb("apache; id")
    assert "HATA" in module.rag_ingest_exploitdb("--update")
    assert called is False


def test_rag_search_includes_provenance_and_untrusted_notice(monkeypatch):
    module = load_server("rag-engine")
    monkeypatch.setattr(module, "hybrid_search", lambda *_args, **_kwargs: {
        "query": "Log4Shell",
        "retrieval": "hybrid-vector-fts5-rrf",
        "schema_version": "2.0",
        "errors": [],
        "results": [{
            "collection": "cves",
            "id": "one",
            "relevance": 1.0,
            "content": "CVE-2021-44228 remote code execution",
            "metadata": {
                "title": "Log4Shell",
                "source": "cisa-kev",
                "source_url": "https://example.invalid/kev",
                "trust_tier": "official",
                "validation_status": "known-exploited",
            },
        }],
    })
    monkeypatch.setattr(module, "lookup_risk", lambda *_args, **_kwargs: {
        "CVE-2021-44228": {"known_exploited": True}
    })

    output = module.rag_search("Log4Shell")

    assert "UNTRUSTED DATA" in output
    assert "Source: cisa-kev" in output
    assert "known_exploited" in output


def test_manual_writeup_cannot_self_assign_validated_trust(monkeypatch):
    module = load_server("rag-engine")
    captured = {}

    def fake_replace(_name, records, **_kwargs):
        captured["metadata"] = records[0]["metadata"]
        return len(records)

    monkeypatch.setattr(module, "replace_source_documents", fake_replace)

    output = module.rag_ingest_writeup(
        "Claimed validator output",
        "This is caller-controlled content and must remain unverified. " * 2,
        source="internal-validated",
    )

    assert "yüklendi" in output
    assert captured["metadata"]["trust_tier"] == "user"
    assert captured["metadata"]["validation_status"] == "unverified"
    assert captured["metadata"]["ingest_source"] == "mcp-writeup"


def test_mcp_ingest_uses_the_shared_single_writer_lock():
    module = load_server("rag-engine")

    with module.rag_write_lock(module.DB_DIR):
        output = module.rag_ingest_writeup(
            "Blocked concurrent write",
            "This write must not interleave with an active bootstrap writer. " * 2,
        )

    assert "writer kilidi" in output


def test_payload_bulk_ingest_rejects_an_untrusted_checkout(tmp_path):
    module = load_server("rag-engine")
    source = tmp_path / "PayloadsAllTheThings"
    source.mkdir()
    (source / "SQL Injection.md").write_text("# SQL\n\n" + "content " * 20, encoding="utf-8")

    output = module.rag_bulk_ingest("payloads", str(source))

    assert "origin/cleanliness validation failed" in output


def test_trusted_git_revision_rejects_local_only_commits(monkeypatch):
    module = load_server("rag-engine")
    revision = "a" * 40

    def fake_run(args, **_kwargs):
        command = args[3:]
        if command == ["rev-parse", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout=revision + "\n", stderr="")
        if command == ["remote", "get-url", "origin"]:
            return SimpleNamespace(
                returncode=0,
                stdout="https://github.com/swisskyrepo/PayloadsAllTheThings.git\n",
                stderr="",
            )
        if command == ["status", "--porcelain"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command == ["branch", "-r", "--contains", revision]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(command)

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    assert module._trusted_git_revision(
        "/tmp/payloads", "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    ) == ""


def test_directory_bulk_ingests_are_namespaced_by_root(tmp_path, monkeypatch):
    module = load_server("rag-engine")
    roots = [tmp_path / "one", tmp_path / "two"]
    for root in roots:
        root.mkdir()
        (root / "report.md").write_text("# Report\n\n" + "content " * 20, encoding="utf-8")
    namespaces = []

    def fake_replace(_name, records, **_kwargs):
        namespaces.append(records[0]["metadata"]["ingest_source"])
        return len(records)

    monkeypatch.setattr(module, "replace_source_documents", fake_replace)

    for root in roots:
        assert "1 dosya" in module.rag_bulk_ingest("directory", str(root))

    assert len(set(namespaces)) == 2
