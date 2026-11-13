"""WS7 mühürlü yazma kümesi: defter yaşam döngüsü + kapı kararı testleri."""
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import write_set  # noqa: E402


def _load_policy_engine():
    path = REPO_ROOT / "scripts" / "policy_engine.py"
    spec = importlib.util.spec_from_file_location("policy_engine_ws7", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ALICE = {"Authorization": "Bearer alice-token"}
BOB = {"Authorization": "Bearer bob-token"}
EVE = {"Authorization": "Bearer eve-token"}
URL = "http://127.0.0.1:18899/docs/doc-1"
BINDING = {'run_id': 'ws7-run', 'session_id': 'ws7-session'}
SEAL_BINDING = {**BINDING, 'test_account': True, 'ownership_evidence': {'created_by': 'member-a'}}


def _sealed_db(tmp_path):
    db = str(tmp_path / "write_set.db")
    write_set.seal_object(
        db, object_url=URL, identity_label="member-a",
        run_fingerprints=[write_set.fingerprint_credentials(ALICE),
                          write_set.fingerprint_credentials(BOB)],
        task_ref="task-1", ttl_seconds=600, now=1000.0, **SEAL_BINDING)
    write_set.mark_state(db, URL, 'pre_state', evidence={'observed': True}, **BINDING)
    return db


def test_seal_lifecycle_and_mutation_permission(tmp_path):
    db = _sealed_db(tmp_path)
    assert write_set.is_sealed(db, URL, now=1001.0)
    # Koşudaki test kimlikleri mühürlü nesneye yazma deneyebilir (yazma-BOLA probu).
    ok, _ = write_set.mutation_permitted(
        db, URL, write_set.fingerprint_credentials(BOB), now=1001.0, **BINDING)
    assert ok is True
    # Koşu dışı kimlik ve mühürsüz nesne reddedilir.
    ok, reason = write_set.mutation_permitted(
        db, URL, write_set.fingerprint_credentials(EVE), now=1001.0, **BINDING)
    assert ok is False and "identity" in reason
    ok, _ = write_set.mutation_permitted(
        db, "http://127.0.0.1:18899/docs/other",
        write_set.fingerprint_credentials(BOB), now=1001.0, **BINDING)
    assert ok is False
    # Süre dolumu ve teardown sonrası izin biter.
    assert write_set.is_sealed(db, URL, now=2000.0) is False
    write_set.mark_state(db, URL, 'experiment', evidence={'attempt': True}, **BINDING)
    write_set.mark_state(db, URL, 'post_state', evidence={'observed': True}, **BINDING)
    write_set.mark_state(db, URL, 'torn_down', evidence={'disposed': True}, **BINDING)
    ok, _ = write_set.mutation_permitted(
        db, URL, write_set.fingerprint_credentials(BOB), now=1001.0, **BINDING)
    assert ok is False


def test_creation_cap_per_task(tmp_path):
    db = str(tmp_path / "write_set.db")
    fp = write_set.fingerprint_credentials(ALICE)
    for index in range(2):
        write_set.seal_object(db, object_url=f"http://h/docs/{index}",
                              identity_label="a", run_fingerprints=[fp],
                              task_ref="t", ttl_seconds=60, now=0.0, **SEAL_BINDING)
    try:
        write_set.seal_object(db, object_url="http://h/docs/2",
                              identity_label="a", run_fingerprints=[fp],
                              task_ref="t", ttl_seconds=60, now=0.0,
                              max_per_task=2, **SEAL_BINDING)
        raise AssertionError("cap must refuse third object")
    except write_set.WriteSetError:
        pass


def _engine(tmp_path, policy, monkeypatch=None):
    module = _load_policy_engine()
    if monkeypatch is not None:
        monkeypatch.setenv('CCO_RUN_ID', BINDING['run_id'])
        monkeypatch.setenv('CCO_SESSION_ID', BINDING['session_id'])
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"allow_loopback": True, "allow_public_labs": True}))
    program = tmp_path / "policy.json"
    program.write_text(json.dumps(policy))
    if monkeypatch is not None:
        monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
        monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(program))
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"),
                                 scope_file=str(scope),
                                 program_policy_file=str(program))
    engine.grant_approval("kali-tools_curl_request", "127.0.0.1",
                          ttl_seconds=600, reason="test")
    return engine


WRITE_POLICY = {
    "blocked_http_methods": ["DELETE"],
    "write_set": {"enabled": True,
                  "create_allowlist": [{"method": "POST", "path": "/docs"}],
                  "max_objects_per_task": 3, "ttl_seconds": 600},
}


def _wire(engine, method, url, headers):
    return engine.validate_wire_invocation("kali-tools_curl_request", {
        "target": url, "url": url, "method": method, "headers": headers})


def test_gate_blocks_unsealed_mutation_and_allows_sealed(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_WRITE_SET_NOW", "1000")
    engine = _engine(tmp_path, WRITE_POLICY, monkeypatch)
    # Mühürsüz nesneye PUT kapıdan geçemez.
    result = _wire(engine, "PUT", URL, BOB)
    assert result["allowed"] is False
    assert result["reason"] == "blocked_unsealed_mutation"
    # Mühürlenince koşu kimliği yazabilir; mühürlü DELETE, metot yasağını aşar.
    db = str(Path(engine.cco_home) / "write_set.db")
    write_set.seal_object(
        db, object_url=URL, identity_label="member-a",
        run_fingerprints=[write_set.fingerprint_credentials(ALICE),
                          write_set.fingerprint_credentials(BOB)],
        task_ref="task-1", ttl_seconds=600, now=1000.0, **SEAL_BINDING)
    write_set.mark_state(db, URL, 'pre_state', evidence={'observed': True}, **BINDING)
    assert _wire(engine, "PUT", URL, BOB)["allowed"] is True
    assert _wire(engine, "DELETE", URL, BOB)["allowed"] is True
    # Koşu dışı kimlik mühürlü nesneye de yazamaz.
    result = _wire(engine, "PUT", URL, EVE)
    assert result["allowed"] is False
    assert result["reason"] == "blocked_unsealed_mutation"


def test_gate_write_set_policy_is_fail_closed(tmp_path, monkeypatch):
    bad = dict(WRITE_POLICY)
    bad["write_set"] = {"enabled": True, "unknown": 1}
    try:
        _engine(tmp_path, bad, monkeypatch)
        raise AssertionError("unknown write_set key must fail closed")
    except ValueError:
        pass
    # write_set kapalıyken mühür şartı uygulanmaz (mevcut davranış korunur).
    engine = _engine(tmp_path, {"blocked_http_methods": ["DELETE"]}, monkeypatch)
    assert _wire(engine, "PUT", URL, BOB)["allowed"] is True


def test_gate_rejects_cross_run_with_reused_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv('CCO_WRITE_SET_NOW', '1000')
    engine = _engine(tmp_path, WRITE_POLICY, monkeypatch)
    db = str(Path(engine.cco_home) / 'write_set.db')
    write_set.seal_object(db, object_url=URL, identity_label='member-a',
        run_fingerprints=[write_set.fingerprint_credentials(BOB)], task_ref='task',
        now=1000, **SEAL_BINDING)
    write_set.mark_state(db, URL, 'pre_state', evidence={'observed': True}, **BINDING)
    assert _wire(engine, 'PUT', URL, BOB)['allowed'] is True
    monkeypatch.setenv('CCO_RUN_ID', 'another-run')
    result = _wire(engine, 'PUT', URL, BOB)
    assert result['allowed'] is False and result['reason'] == 'blocked_unsealed_mutation'
    monkeypatch.setenv('CCO_RUN_ID', BINDING['run_id'])
    monkeypatch.setenv('CCO_SESSION_ID', 'another-session')
    assert _wire(engine, 'PUT', URL, BOB)['allowed'] is False
