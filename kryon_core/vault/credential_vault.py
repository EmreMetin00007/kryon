#!/usr/bin/env python3
"""Encrypted credential vault for memory-server."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet


class CredentialVault:
    def __init__(self, cco_home: str, *, create_key: bool = True, initialize_db: bool = True):
        self.cco_home = Path(cco_home)
        if not create_key and not self.cco_home.is_dir():
            raise ValueError("credential vault home unavailable")
        self.cco_home.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cco_home / "credential_vault.db"
        self.key_path = self.cco_home / "vault.key"
        self.key = self._load_or_create_key(create_key=create_key)
        self.fernet = Fernet(self.key)
        if initialize_db:
            if not create_key and not self.db_path.is_file():
                raise ValueError("credential vault database unavailable")
            if create_key:
                self._init_db()

    def _load_or_create_key(self, *, create_key: bool = True) -> bytes:
        env_key = os.environ.get("CCO_VAULT_KEY")
        if env_key:
            return env_key.encode()
        use_keyring = os.environ.get("CCO_USE_KEYRING", "0") == "1"
        if use_keyring:
            try:
                import keyring  # type: ignore[import-not-found]

                existing = keyring.get_password("cco", "credential_vault_key")
                if existing:
                    return existing.encode()
            except Exception:
                pass
        if self.key_path.exists():
            return self.key_path.read_text().strip().encode()

        if not create_key:
            raise ValueError("credential vault key unavailable")
        key = Fernet.generate_key()
        if use_keyring:
            try:
                import keyring  # type: ignore[import-not-found]

                keyring.set_password("cco", "credential_vault_key", key.decode())
                return key
            except Exception:
                pass
        # Publish a complete key atomically: concurrent server starts must not
        # overwrite one another or observe a half-written key.
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", dir=self.cco_home, prefix=".vault-key-",
                                             delete=False) as handle:
                temporary = Path(handle.name)
                os.fchmod(handle.fileno(), 0o600)
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, self.key_path)
                return key
            except FileExistsError:
                return self.key_path.read_text().strip().encode()
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_secrets (
                id TEXT PRIMARY KEY,
                secret_type TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                metadata TEXT DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                deleted_at TEXT DEFAULT ''
            )
            """
        )
        conn.commit()
        conn.close()

    def store_secret(self, secret_type: str, plaintext: str, metadata: dict | None = None) -> str:
        secret_id = secrets.token_urlsafe(24)
        ciphertext = self.fernet.encrypt((plaintext or "").encode("utf-8"))
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO vault_secrets (id, secret_type, ciphertext, metadata) VALUES (?, ?, ?, ?)",
            (secret_id, secret_type, ciphertext, json.dumps(metadata or {})),
        )
        conn.commit()
        conn.close()
        return secret_id

    def get_secret(self, secret_id: str) -> str:
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT ciphertext FROM vault_secrets WHERE id=? AND deleted_at=''",
            (secret_id,),
        ).fetchone()
        conn.close()
        if not row:
            raise KeyError(secret_id)
        return self.fernet.decrypt(row[0]).decode("utf-8")

    def delete_secret(self, secret_id: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute(
            "UPDATE vault_secrets SET deleted_at=CURRENT_TIMESTAMP WHERE id=? AND deleted_at=''",
            (secret_id,),
        )
        conn.commit()
        conn.close()
        return cur.rowcount > 0
