"""Finding identity is conservative and transactionally reserved."""
from concurrent.futures import ThreadPoolExecutor
import json
import importlib.util
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import load_server, make_signed_validation

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from target_identity import resource_identity, target_query_matches  # noqa: E402


@pytest.fixture
def memory(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_GRAPH_BACKEND", "networkx")
    monkeypatch.setenv("CCO_SCOPE_REVISION", "test-scope")
    monkeypatch.setenv("CCO_POLICY_HASH", "test-policy")
    monkeypatch.delenv("CCO_ENGAGEMENT_ID", raising=False)
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path / "run"))
    mod = load_server("memory-server")
    monkeypatch.setattr(mod, "_process_graph_job", lambda _: "")
    return mod


def test_resource_identity_retains_path_query_scheme_and_nondefault_port():
    assert resource_identity("https://EXAMPLE.test:443/a?p=1") == "https://example.test/a?p=1"
    assert resource_identity("https://example.test/a?p=1") != resource_identity("https://example.test/a?p=2")
    assert resource_identity("https://example.test/a") != resource_identity("https://example.test/b")
    assert resource_identity("https://example.test/a") != resource_identity("http://example.test/a")
    assert resource_identity("https://user:pw@example.test/a") == ""
    assert target_query_matches("example.test", "https://example.test:443/a")
    assert not target_query_matches("https://example.test/a", "https://example.test/b")


def test_default_port_dedup_and_distinct_findings(memory, monkeypatch):
    def store(target, description="same", kind="idor", payload="object-a"):
        return memory._store_finding_internal(target, kind, "high", description, payload)
    first = store("https://owned.test:443/api/a?id=1")
    second = store("https://owned.test/api/a?id=1")
    assert first["finding_id"] == second["finding_id"]
    assert second["deduplicated"] is True
    variants = [store("https://owned.test/api/b?id=1"),
                store("https://owned.test/api/a?id=2"),
                store("http://owned.test/api/a?id=1"),
                store("https://owned.test/api/a?id=1", payload="object-b"),
                store("https://owned.test/api/a?id=1", kind="xss")]
    assert len({first["finding_id"], *(row["finding_id"] for row in variants)}) == 6
    monkeypatch.setenv("CCO_ENGAGEMENT_ID", "another-program")
    assert store("https://owned.test/api/a?id=1")["finding_id"] != first["finding_id"]
    monkeypatch.delenv("CCO_ENGAGEMENT_ID")
    monkeypatch.setenv("CCO_SCOPE_REVISION", "another-scope")
    assert store("https://owned.test/api/a?id=1")["finding_id"] != first["finding_id"]
    found = json.loads(memory.get_target_memory("owned.test", limit=0))["findings"]
    assert len(found) == 8
    scoped = json.loads(memory.get_target_memory("https://owned.test/api/b?id=1"))["findings"]
    assert len(scoped) == 1


def test_concurrent_duplicate_writes_share_a_canonical_row(memory):
    def store(_):
        return memory._store_finding_internal("https://owned.test/api", "xss", "medium", "same", "marker")
    with ThreadPoolExecutor(max_workers=8) as executor:
        rows = list(executor.map(store, range(24)))
    assert len({row["finding_id"] for row in rows}) == 1
    with sqlite3.connect(memory.DB_PATH) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM finding_identity").fetchone()[0] == 1


def test_active_engagement_filters_findings_in_memory_and_report(memory, tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test/api"}]}))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_ENGAGEMENT_ID", "program-a")
    first = memory._store_finding_internal("https://owned.test/api/a", "xss", "low", "program a")
    monkeypatch.setenv("CCO_ENGAGEMENT_ID", "program-b")
    second = memory._store_finding_internal("https://owned.test/api/a", "xss", "low", "program b")
    current = json.loads(memory.get_target_memory("owned.test"))["findings"]
    assert [item["id"] for item in current] == [second["finding_id"]]
    kali = load_server("kali-tools")
    report = json.loads(kali.generate_pentest_report("owned.test", output_format="json"))
    assert [item["description"] for item in report["hypotheses"]] == ["program b"]
    spec = importlib.util.spec_from_file_location("tui_engagement_test", ROOT / "scripts/tui_snapshot.py")
    snapshot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(snapshot)
    monkeypatch.setattr(snapshot, "CCO", tmp_path / "home")
    counts, _ = snapshot.finding_snapshot(Path(memory.DB_PATH))
    assert sum(counts.values()) == 1
    monkeypatch.setenv("CCO_ENGAGEMENT_ID", "program-a")
    current = json.loads(memory.get_target_memory("owned.test"))["findings"]
    assert [item["id"] for item in current] == [first["finding_id"]]
    forbidden = json.loads(memory.update_finding_validation(second["finding_id"], state="candidate"))
    assert forbidden["updated"] is False


def test_repeat_does_not_downgrade_validated_finding(memory):
    artifact = make_signed_validation("https://owned.test:443/api", "xss")
    first = memory._store_finding_internal("https://owned.test/api", "xss", "high", "same", "marker",
                                            validation_result_json=json.dumps(artifact))
    assert first["validation"]["reportable"] == 1
    second = memory._store_finding_internal("https://owned.test:443/api", "xss", "medium", "same", "marker")
    assert second["finding_id"] == first["finding_id"]
    with sqlite3.connect(memory.DB_PATH) as conn:
        assert conn.execute("SELECT reportable FROM findings WHERE id=?", (first["finding_id"],)).fetchone()[0] == 1


def test_historical_artifact_compares_default_ports_without_crossing_paths(memory):
    artifact = make_signed_validation("https://owned.test/api/a?x=1", "xss")
    validator = load_server("validator")
    assert validator.artifact_is_valid(artifact, expected_target="https://owned.test:443/api/a?x=1")
    assert not validator.artifact_is_valid(artifact, expected_target="https://owned.test/api/b?x=1")
    assert not validator.artifact_is_valid(artifact, expected_target="http://owned.test/api/a?x=1")
    assert validator.artifact_is_valid(artifact), "original signature remains valid"


def test_explicit_legacy_migration_preserves_rows_and_resolves_alias(memory, tmp_path, monkeypatch):
    from finding_migration import migrate_findings
    from policy_engine import ScopeResolver

    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test/api"}]}))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_ENGAGEMENT_ID", "explicit-test-program")
    memory._ensure_initialized()
    with sqlite3.connect(memory.DB_PATH) as conn:
        conn.executemany("INSERT INTO findings (target,type,severity,description,payload) VALUES (?,?,?,?,?)", [
            ("https://owned.test:443/api/a?id=1", "idor", "high", "same", "marker"),
            ("https://owned.test/api/a?id=1", "idor", "high", "same", "marker"),
            ("https://owned.test/outside", "idor", "high", "same", "marker"),
        ])
        ids = [row[0] for row in conn.execute("SELECT id FROM findings ORDER BY id")]
    resolver = ScopeResolver(scope_file=scope)
    plan = migrate_findings(Path(memory.DB_PATH), memory, resolver)
    assert plan["mode"] == "preview" and plan["skipped"] == 1
    assert plan["groups"][0]["selected_ids"] == ids[:2]
    cli = subprocess.run([sys.executable, str(ROOT / "scripts/finding_migration.py"),
                          "--cco-home", str(tmp_path / "home"), "--scope-file", str(scope),
                          "--workdir", str(tmp_path / "run"), "--engagement-id", "explicit-test-program",
                          "--ids", ",".join(map(str, ids[:2]))], capture_output=True, text=True, timeout=30)
    assert cli.returncode == 0, cli.stderr
    assert json.loads(cli.stdout)["groups"][0]["selected_ids"] == ids[:2]
    assert "marker" not in cli.stdout
    with sqlite3.connect(memory.DB_PATH) as conn:
        assert conn.execute("SELECT COUNT(*) FROM finding_aliases").fetchone()[0] == 0
    with pytest.raises(ValueError, match="explicitly selected"):
        migrate_findings(Path(memory.DB_PATH), memory, resolver, apply=True)
    applied = migrate_findings(Path(memory.DB_PATH), memory, resolver, ids[:2], apply=True)
    assert applied["groups"][0]["canonical_id"] == ids[0]
    with sqlite3.connect(memory.DB_PATH) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3
        assert conn.execute("SELECT alias_id, canonical_id FROM finding_aliases").fetchone() == (ids[1], ids[0])
    findings = json.loads(memory.get_target_memory("https://owned.test/api/a?id=1"))["findings"]
    alias = next(item for item in findings if item["id"] == ids[1])
    assert alias["canonical_finding_id"] == ids[0] and alias["reportable"] is False
    kali = load_server("kali-tools")
    report = json.loads(kali.generate_pentest_report("https://owned.test/api/a?id=1", output_format="json"))
    assert report["hypotheses_count"] == 1
    updated = json.loads(memory.update_finding_validation(ids[1], state="candidate"))
    assert updated["updated"] and updated["finding_id"] == ids[0]
    assert updated["requested_finding_id"] == ids[1]
    same = memory._store_finding_internal("https://owned.test/api/a?id=1", "idor", "high", "same", "marker")
    assert same["finding_id"] == ids[0] and same["deduplicated"]


def test_legacy_plan_prefers_current_signed_evidence(memory, tmp_path, monkeypatch):
    from finding_migration import migrate_findings
    from policy_engine import ScopeResolver

    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test/api"}]}))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_ENGAGEMENT_ID", "explicit-test-program")
    memory._ensure_initialized()
    artifact = make_signed_validation("https://owned.test/api/a", "xss")
    with sqlite3.connect(memory.DB_PATH) as conn:
        first = conn.execute("INSERT INTO findings (target,type,severity,description,payload) VALUES (?,?,?,?,?)",
                             ("https://owned.test/api/a", "xss", "high", "same", "marker")).lastrowid
        second = conn.execute("INSERT INTO findings (target,type,severity,description,payload,validation_artifact, "
                              "validation_id, validation_state, validation_verdict, reportable) "
                              "VALUES (?,?,?,?,?,?,?,?,?,?)",
                              ("https://owned.test:443/api/a", "xss", "high", "same", "marker",
                               artifact["artifact"]["path"], artifact["validation_id"], "verified", "CONFIRMED", 1)).lastrowid
    plan = migrate_findings(Path(memory.DB_PATH), memory, ScopeResolver(scope_file=scope), [first, second])
    assert plan["groups"][0]["canonical_id"] == second
