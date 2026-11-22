from concurrent.futures import ThreadPoolExecutor

import pytest

from kryon_core.vault.credential_vault import CredentialVault


def test_vault_roundtrip_and_delete(tmp_path):
    vault = CredentialVault(str(tmp_path))
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
    with ThreadPoolExecutor(max_workers=8) as pool:
        vaults = list(pool.map(lambda _: CredentialVault(str(tmp_path)), range(16)))
    assert len({vault.key for vault in vaults}) == 1
    ref = vaults[0].store_secret("test", "synthetic")
    assert all(vault.get_secret(ref) == "synthetic" for vault in vaults)


def test_reading_without_vault_key_never_creates_a_replacement(tmp_path, monkeypatch):
    monkeypatch.delenv("CCO_VAULT_KEY", raising=False)
    monkeypatch.setenv("CCO_USE_KEYRING", "0")
    vault = CredentialVault(str(tmp_path))
    vault.store_secret("test", "synthetic")
    vault.key_path.unlink()
    with pytest.raises(ValueError, match="key unavailable"):
        CredentialVault(str(tmp_path), create_key=False)
    assert not vault.key_path.exists()
