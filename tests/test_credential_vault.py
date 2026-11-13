import importlib.util
import os
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_vault():
    path = os.path.join(REPO_ROOT, "mcp-servers", "mcp-memory-server", "credential_vault.py")
    spec = importlib.util.spec_from_file_location("credential_vault_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_vault_roundtrip_and_delete(tmp_path):
    module = _load_vault()
    vault = module.CredentialVault(str(tmp_path))
    secret_id = vault.store_secret("credential_password", "hunter2", {"target": "x"})
    assert vault.get_secret(secret_id) == "hunter2"
    assert vault.delete_secret(secret_id) is True
    try:
        vault.get_secret(secret_id)
    except KeyError:
        pass
    else:
        assert False, "deleted secret should not resolve"


def test_concurrent_initialization_publishes_one_complete_key(tmp_path, monkeypatch):
    monkeypatch.delenv("CCO_VAULT_KEY", raising=False)
    monkeypatch.delenv("CCO_USE_KEYRING", raising=False)
    module = _load_vault()
    with ThreadPoolExecutor(max_workers=8) as pool:
        vaults = list(pool.map(lambda _: module.CredentialVault(str(tmp_path)), range(16)))
    assert len({vault.key for vault in vaults}) == 1
    ref = vaults[0].store_secret("test", "synthetic")
    assert all(vault.get_secret(ref) == "synthetic" for vault in vaults)


def test_reading_without_vault_key_never_creates_a_replacement(tmp_path, monkeypatch):
    monkeypatch.delenv("CCO_VAULT_KEY", raising=False)
    monkeypatch.setenv("CCO_USE_KEYRING", "0")
    module = _load_vault()
    vault = module.CredentialVault(str(tmp_path))
    vault.store_secret("test", "synthetic")
    vault.key_path.unlink()
    with pytest.raises(ValueError, match="key unavailable"):
        module.CredentialVault(str(tmp_path), create_key=False)
    assert not vault.key_path.exists()


def test_plaintext_credentials_can_be_migrated_to_vault(tmp_path):
    cco_home = tmp_path / "cco"
    cco_home.mkdir()
    db_path = cco_home / "agent_memory.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, service TEXT, username TEXT, password TEXT, secret_ref TEXT DEFAULT '', secret_backend TEXT DEFAULT '', timestamp TEXT)"
    )
    conn.execute(
        "INSERT INTO credentials (target, service, username, password) VALUES ('legacy.test', 'ssh', 'bob', 'plaintext')"
    )
    conn.commit()
    conn.close()

    server_path = os.path.join(REPO_ROOT, "mcp-servers", "mcp-memory-server", "server.py")
    spec = importlib.util.spec_from_file_location("memory_server_migrate_test", server_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    old_home = os.environ.get("CCO_HOME")
    old_backend = os.environ.get("CCO_GRAPH_BACKEND")
    os.environ["CCO_HOME"] = str(cco_home)
    os.environ["CCO_GRAPH_BACKEND"] = "networkx"
    try:
        spec.loader.exec_module(module)
        module._ensure_initialized()
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT id, password, secret_ref, secret_backend FROM credentials WHERE target='legacy.test'"
        ).fetchone()
        conn.close()
        assert row[1] == "[REDACTED]"
        assert row[2]
        assert row[3] == "fernet"
        assert module._resolve_credential_secret(row[0]) == "plaintext"
    finally:
        if old_home is None:
            os.environ.pop("CCO_HOME", None)
        else:
            os.environ["CCO_HOME"] = old_home
        if old_backend is None:
            os.environ.pop("CCO_GRAPH_BACKEND", None)
        else:
            os.environ["CCO_GRAPH_BACKEND"] = old_backend
