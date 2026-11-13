"""Memory server backend seçimi, outbox ve exact-target regresyonları."""

import json
import os
import shutil
import sqlite3
import subprocess
import sys

import pytest

from conftest import load_server


@pytest.fixture(scope="module")
def memory_server():
    return load_server("memory-server")


def test_lazy_graph_deletion_restores_backend_method(memory_server):
    original = memory_server.kg.add_node
    replacement = lambda *args, **kwargs: None
    memory_server.kg.add_node = replacement
    assert memory_server.kg.add_node is replacement
    del memory_server.kg.add_node
    assert memory_server.kg.add_node == original
    with pytest.raises(AttributeError):
        del memory_server.kg.nonexistent_proxy_attribute


def test_invalid_backend_is_rejected(memory_server):
    original = memory_server.GRAPH_BACKEND
    memory_server.GRAPH_BACKEND = "invalid"
    try:
        with pytest.raises(ValueError, match="CCO_GRAPH_BACKEND"):
            memory_server._create_graph_backend()
    finally:
        memory_server.GRAPH_BACKEND = original


def test_explicit_missing_kuzu_is_rejected(memory_server, monkeypatch):
    original = memory_server.GRAPH_BACKEND
    memory_server.GRAPH_BACKEND = "kuzu"
    monkeypatch.setattr(memory_server, "HAS_KUZU", False)
    monkeypatch.setattr(memory_server, "KuzuGraph", None)
    try:
        with pytest.raises(RuntimeError, match="kuzu kurulu değil"):
            memory_server._create_graph_backend()
    finally:
        memory_server.GRAPH_BACKEND = original


def test_auto_backend_does_not_silently_fallback(memory_server, monkeypatch):
    original = memory_server.GRAPH_BACKEND
    memory_server.GRAPH_BACKEND = "auto"
    monkeypatch.setattr(memory_server, "HAS_KUZU", True)
    monkeypatch.setattr(
        memory_server,
        "KuzuGraph",
        lambda path: (_ for _ in ()).throw(RuntimeError("database locked")),
    )
    try:
        with pytest.raises(RuntimeError, match="database locked"):
            memory_server._create_graph_backend()
    finally:
        memory_server.GRAPH_BACKEND = original


def test_kuzu_server_loads_via_importlib_spec(tmp_path):
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    server_path = os.path.join(
        repo_root, "mcp-servers", "mcp-memory-server", "server.py"
    )
    code = """
import importlib.util
import sys
spec = importlib.util.spec_from_file_location('isolated_memory_server', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert mod.GRAPH_BACKEND == 'kuzu'
result = mod.store_endpoint('kuzu.test', '443', 'https', 'open', 'nginx')
assert 'güncellendi' in result
assert mod.kg._node_exists('target:kuzu.test')
"""
    env = os.environ.copy()
    env["CCO_HOME"] = str(tmp_path / "cco")
    env["CCO_GRAPH_BACKEND"] = "kuzu"
    result = subprocess.run(
        [sys.executable, "-c", code, server_path],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_outbox_replays_failed_projection(memory_server, monkeypatch):
    original_add_node = memory_server.kg.add_node
    monkeypatch.setattr(
        memory_server.kg,
        "add_node",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("projection down")),
    )
    result = memory_server.store_finding(
        "outbox.test", "xss_reflected", "medium", "reflection", "<x>"
    )
    assert "graph projection beklemede" in result

    conn = sqlite3.connect(memory_server.DB_PATH)
    finding_count = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE target='outbox.test'"
    ).fetchone()[0]
    job_id, status = conn.execute(
        "SELECT id, status FROM graph_outbox WHERE dedupe_key LIKE 'finding:%' "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert finding_count == 1
    assert status == "failed"

    monkeypatch.setattr(memory_server.kg, "add_node", original_add_node)
    assert memory_server._process_graph_job(job_id) == ""
    conn = sqlite3.connect(memory_server.DB_PATH)
    status = conn.execute(
        "SELECT status FROM graph_outbox WHERE id=?", (job_id,)
    ).fetchone()[0]
    conn.close()
    assert status == "done"


def test_endpoint_retry_repairs_projection(memory_server):
    target = "repair.test"
    memory_server.store_endpoint(target, "443", "https", "open", "nginx")
    target_node = f"target:{target}"
    service_node = f"service:{target}:443/https"
    memory_server.kg.remove_nodes([target_node, service_node])

    result = memory_server.store_endpoint(target, "443", "https", "open", "nginx")
    assert "graph senkronize edildi" in result
    assert target_node in memory_server.kg.G
    assert service_node in memory_server.kg.G


def test_drop_target_is_exact_and_removes_owned_nodes(memory_server):
    memory_server.store_finding("example.test", "sqli", "high", "one")
    memory_server.store_credential("example.test", "ssh", "alice", "secret")
    memory_server.store_endpoint("api.example.test", "443", "https")

    result = memory_server.drop_target_memory("example.test")
    assert "TEMİZLENDİ" in result
    assert "target:example.test" not in memory_server.kg.G
    assert all(
        data.get("target") != "example.test"
        for _, data in memory_server.kg.G.nodes(data=True)
    )
    remaining = json.loads(memory_server.get_target_memory("api.example.test"))
    assert len(remaining["endpoints"]) == 1


def test_credential_storage_uses_vault(memory_server):
    result = memory_server.store_credential("vaulted.test", "ssh", "alice", "s3cr3t")
    assert "Credential kaydedildi" in result

    conn = sqlite3.connect(memory_server.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT id, password, secret_ref, secret_backend FROM credentials WHERE target='vaulted.test' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert row["password"] == "[REDACTED]"
    assert row["secret_ref"]
    assert row["secret_backend"] == "fernet"
    assert memory_server._resolve_credential_secret(row["id"]) == "s3cr3t"

    dumped = json.loads(memory_server.get_target_memory("vaulted.test"))
    assert dumped["credentials"][0]["password"] == "[REDACTED]"
    assert dumped["credentials"][0]["has_secret"] is True
    assert "secret_ref" not in dumped["credentials"][0]
    assert "secret_backend" not in dumped["credentials"][0]


def test_store_finding_tracks_verified_validation_artifact(memory_server):
    validator = load_server("validator")
    artifact = validator._result(
        "SQL Injection (boolean-based)",
        "http://verified.test/item?id=1",
        validator.CONFIRMED,
        "differential_boolean",
        {"true_payload": "1 AND 1=1"},
        ["curl -sk 'http://verified.test/item?id=1%20AND%201=1'"],
        notes="verified",
    )
    result = memory_server.store_finding(
        "verified.test",
        "sql_injection",
        "high",
        "validated finding",
        payload="1' AND 1=1",
        validation_result_json=artifact,
    )
    assert "validated artifact" in result

    conn = sqlite3.connect(memory_server.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT validation_state, validation_artifact, validation_verdict, validation_oracle, "
        "validation_evidence_grade, reportable, payload "
        "FROM findings WHERE target='verified.test' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert row["validation_state"] == "verified"
    assert row["validation_verdict"] == "CONFIRMED"
    assert row["validation_oracle"] == "differential_boolean"
    assert row["validation_evidence_grade"] == "differential_boolean"
    assert row["reportable"] == 1
    assert row["validation_artifact"]
    assert row["payload"] == "1' AND 1=1"

    dumped = json.loads(memory_server.get_target_memory("verified.test"))
    assert dumped["findings"][0]["reportable"] is True
    assert dumped["findings"][0]["has_validation_artifact"] is True


def test_store_finding_rejects_tampered_validation_record(memory_server):
    validator = load_server("validator")
    artifact = json.loads(validator._result(
        "SQL Injection (boolean-based)",
        "http://tamper.test/item?id=1",
        validator.UNCONFIRMED,
        "differential_boolean",
        {"tested": "none"},
        "-",
        notes="unconfirmed",
    ))
    artifact["verdict"] = "CONFIRMED"
    artifact["reportable"] = True
    result = memory_server.store_finding(
        "tamper.test",
        "sql_injection",
        "high",
        "tampered validation",
        payload="1'",
        validation_result_json=json.dumps(artifact),
    )
    assert "artifact present, unverified" in result

    conn = sqlite3.connect(memory_server.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT validation_state, reportable FROM findings WHERE target='tamper.test' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert row["validation_state"] == "unverified_artifact"
    assert row["reportable"] == 0


def test_store_finding_rejects_target_tamper(memory_server):
    validator = load_server("validator")
    artifact = json.loads(validator._result(
        "SQL Injection (boolean-based)",
        "http://target-tamper.test/item?id=1",
        validator.CONFIRMED,
        "differential_boolean",
        {"true_payload": "1 AND 1=1"},
        "-",
        notes="verified",
    ))
    artifact["target"] = "http://evil.test/item?id=1"
    result = memory_server.store_finding(
        "target-tamper.test",
        "sql_injection",
        "high",
        "target tampered",
        validation_result_json=json.dumps(artifact),
    )
    assert "artifact present, unverified" in result
    dumped = json.loads(memory_server.get_target_memory("target-tamper.test"))
    assert dumped["findings"][0]["reportable"] is False
    assert dumped["findings"][0]["validation_state"] == "unverified_artifact"


def test_store_finding_rejects_evidence_tamper(memory_server):
    validator = load_server("validator")
    artifact = json.loads(validator._result(
        "SQL Injection (boolean-based)",
        "http://evidence-tamper.test/item?id=1",
        validator.CONFIRMED,
        "differential_boolean",
        {"true_payload": "1 AND 1=1"},
        "-",
        notes="verified",
    ))
    artifact["evidence"]["true_payload"] = "1 AND 2=2"
    result = memory_server.store_finding(
        "evidence-tamper.test",
        "sql_injection",
        "high",
        "evidence tampered",
        validation_result_json=json.dumps(artifact),
    )
    assert "artifact present, unverified" in result
    dumped = json.loads(memory_server.get_target_memory("evidence-tamper.test"))
    assert dumped["findings"][0]["reportable"] is False
    assert dumped["findings"][0]["validation_state"] == "unverified_artifact"


def test_store_finding_rejects_unknown_artifact_schema(memory_server):
    validator = load_server("validator")
    artifact = json.loads(validator._result(
        "SQL Injection (boolean-based)",
        "http://unknown-schema.test/item?id=1",
        validator.CONFIRMED,
        "differential_boolean",
        {"true_payload": "1 AND 1=1"},
        "-",
        notes="verified",
    ))
    artifact["schema_version"] = "unknown/9.9"
    result = memory_server.store_finding(
        "unknown-schema.test",
        "sql_injection",
        "high",
        "unknown schema",
        validation_result_json=json.dumps(artifact),
    )
    assert "artifact present, unverified" in result
    dumped = json.loads(memory_server.get_target_memory("unknown-schema.test"))
    assert dumped["findings"][0]["reportable"] is False
    assert dumped["findings"][0]["validation_state"] == "unverified_artifact"


def test_store_finding_rejects_artifact_copied_to_untrusted_path(memory_server, tmp_path):
    validator = load_server("validator")
    artifact = json.loads(validator._result(
        "SQL Injection (boolean-based)",
        "http://moved-artifact.test/item?id=1",
        validator.CONFIRMED,
        "differential_boolean",
        {"true_payload": "1 AND 1=1"},
        "-",
        notes="verified",
    ))
    moved = tmp_path / "copied-artifact.json"
    shutil.copyfile(artifact["artifact"]["path"], moved)
    result = memory_server.store_finding(
        "moved-artifact.test",
        "sql_injection",
        "high",
        "moved artifact",
        validation_artifact_path=str(moved),
    )
    assert "artifact present, unverified" in result
    dumped = json.loads(memory_server.get_target_memory("moved-artifact.test"))
    assert dumped["findings"][0]["reportable"] is False
    assert dumped["findings"][0]["validation_state"] == "unverified_artifact"


def test_store_validated_finding_generates_report(memory_server):
    validator = load_server("validator")
    artifact = validator._result(
        "SQL Injection (boolean-based)",
        "http://validated-tool.test/item?id=1",
        validator.CONFIRMED,
        "differential_boolean",
        {"true_payload": "1 AND 1=1"},
        ["curl -sk 'http://validated-tool.test/item?id=1%20AND%201=1'"],
        notes="verified",
    )
    out = json.loads(memory_server.store_validated_finding(
        target="validated-tool.test",
        type="sql_injection",
        severity="high",
        description="validated through helper",
        payload="1' AND 1=1",
        validation_result_json=artifact,
    ))
    assert out["stored"] is True
    assert out["report_generated"] is True
    assert os.path.exists(out["report_path"])

    conn = sqlite3.connect(memory_server.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT validation_report_path FROM findings WHERE target='validated-tool.test' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert row["validation_report_path"] == out["report_path"]

    dumped = json.loads(memory_server.get_target_memory("validated-tool.test"))
    assert dumped["findings"][0]["validation_verdict"] == "CONFIRMED"
    assert dumped["findings"][0]["validation_report_path"] == out["report_path"]
    assert dumped["findings"][0]["has_validation_report"] is True


def test_store_credential_fails_closed_without_vault(memory_server, monkeypatch):
    original_vault = memory_server.vault
    monkeypatch.setattr(memory_server, "vault", None)
    result = memory_server.store_credential("novault.test", "ssh", "alice", "plaintext")
    monkeypatch.setattr(memory_server, "vault", original_vault)
    assert "plaintext credential storage reddedildi" in result

    conn = sqlite3.connect(memory_server.DB_PATH)
    count = conn.execute("SELECT COUNT(*) FROM credentials WHERE target='novault.test'").fetchone()[0]
    conn.close()
    assert count == 0


def test_query_attack_paths_honors_max_hops(memory_server):
    source = "target:hops.test"
    middle = "service:hops.test:ssh"
    goal = "privilege:hops-root"
    memory_server.add_relationship(source, middle, "HAS_PORT", confidence=1.0)
    memory_server.add_relationship(middle, goal, "GRANTS", confidence=0.9)

    too_short = memory_server.query_attack_paths(source, goal, max_hops=1)
    enough = memory_server.query_attack_paths(source, goal, max_hops=2)
    assert "saldırı yolu bulunamadı" in too_short
    assert "Attack Paths" in enough


def _last_finding_id(memory_server, target):
    conn = sqlite3.connect(memory_server.DB_PATH)
    row = conn.execute(
        "SELECT id FROM findings WHERE target=? ORDER BY id DESC LIMIT 1", (target,)
    ).fetchone()
    conn.close()
    return row[0]


def _finding_row(memory_server, finding_id):
    conn = sqlite3.connect(memory_server.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT validation_state, validation_verdict, reportable FROM findings WHERE id=?",
        (finding_id,),
    ).fetchone()
    conn.close()
    return row


def test_update_finding_validation_confirms_async(memory_server):
    validator = load_server("validator")
    memory_server.store_finding("lifecycle.test", "sql_injection", "high", "hypothesis")
    finding_id = _last_finding_id(memory_server, "lifecycle.test")
    assert _finding_row(memory_server, finding_id)["reportable"] == 0

    artifact = validator._result(
        "SQL Injection (boolean-based)",
        "http://lifecycle.test/item?id=1",
        validator.CONFIRMED,
        "differential_boolean",
        {"true_payload": "1 AND 1=1"},
        ["curl -sk 'http://lifecycle.test/item?id=1%20AND%201=1'"],
        notes="async-confirm",
    )
    out = json.loads(memory_server.update_finding_validation(
        finding_id, validation_result_json=artifact))
    assert out["graph_error"] == ""
    assert out["updated"] is True
    assert out["from_state"] == "unvalidated"
    assert out["to_state"] == "confirmed"
    assert out["reportable"] is True

    row = _finding_row(memory_server, finding_id)
    assert row["validation_state"] == "confirmed"
    assert row["validation_verdict"] == "CONFIRMED"
    assert row["reportable"] == 1


def test_update_finding_validation_marks_unconfirmed_rejected(memory_server):
    validator = load_server("validator")
    memory_server.store_finding("lifecycle-reject.test", "sql_injection", "high", "hypothesis")
    finding_id = _last_finding_id(memory_server, "lifecycle-reject.test")

    artifact = validator._result(
        "SQL Injection (boolean-based)",
        "http://lifecycle-reject.test/item?id=1",
        validator.UNCONFIRMED,
        "differential_boolean",
        {"tested": "none"},
        "-",
        notes="async-reject",
    )
    out = json.loads(memory_server.update_finding_validation(
        finding_id, validation_result_json=artifact))
    assert out["updated"] is True
    assert out["to_state"] == "rejected"
    assert out["reportable"] is False

    row = _finding_row(memory_server, finding_id)
    assert row["validation_state"] == "rejected"
    assert row["reportable"] == 0


def test_update_finding_validation_fails_closed_without_artifact(memory_server):
    memory_server.store_finding("lifecycle-nogate.test", "xss", "medium", "hypothesis")
    finding_id = _last_finding_id(memory_server, "lifecycle-nogate.test")

    out = json.loads(memory_server.update_finding_validation(finding_id, state="confirmed"))
    assert out["updated"] is False
    assert _finding_row(memory_server, finding_id)["reportable"] == 0

    out = json.loads(memory_server.update_finding_validation(finding_id, state="candidate"))
    assert out["updated"] is True
    assert out["to_state"] == "candidate"


def test_update_finding_validation_rejects_illegal_transition(memory_server):
    validator = load_server("validator")
    memory_server.store_finding("lifecycle-terminal.test", "sql_injection", "high", "hypothesis")
    finding_id = _last_finding_id(memory_server, "lifecycle-terminal.test")
    artifact = validator._result(
        "SQL Injection (boolean-based)",
        "http://lifecycle-terminal.test/item?id=1",
        validator.CONFIRMED,
        "differential_boolean",
        {"true_payload": "1 AND 1=1"},
        ["curl -sk 'http://lifecycle-terminal.test/item?id=1'"],
        notes="terminal",
    )
    out = json.loads(memory_server.update_finding_validation(
        finding_id, validation_result_json=artifact))
    assert out["to_state"] == "confirmed"

    out = json.loads(memory_server.update_finding_validation(finding_id, state="candidate"))
    assert out["updated"] is False
    assert "yasak" in out["error"]
    assert _finding_row(memory_server, finding_id)["validation_state"] == "confirmed"
