"""Bridge to encrypted local credential vault, offline Ed25519 OOB verification, and OTP core.

Starts no MCP servers and keeps read paths strictly fail-closed.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Iterator

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = _REPO_ROOT / "scripts"
_MEMORY_DIR = _REPO_ROOT / "mcp-servers" / "mcp-memory-server"
_VALIDATOR_DIR = _REPO_ROOT / "mcp-servers" / "mcp-validator"
_OTP_DIR = _REPO_ROOT / "mcp-servers" / "mcp-otp"

_INDEX_FILENAME = "agentic_vault_index.json"
_LOCK_FILENAME = ".agentic_vault_index.lock"
_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9_.:/@-]{1,128}$")


def _ensure_sys_path(directory: Path) -> None:
    text = str(directory)
    if directory.is_dir() and text not in sys.path:
        sys.path.insert(0, text)


def _load_credential_vault_cls() -> Any:
    _ensure_sys_path(_MEMORY_DIR)
    from credential_vault import CredentialVault  # type: ignore[import-not-found]

    return CredentialVault


def _load_oob_verifier() -> Any:
    _ensure_sys_path(_SCRIPTS_DIR)
    _ensure_sys_path(_VALIDATOR_DIR)
    from cco_validator_core.oob_collector import (  # type: ignore[import-not-found]
        verify_collector_event,
    )

    return verify_collector_event


def _load_otp_core() -> Any:
    _ensure_sys_path(_OTP_DIR)
    import otp_core  # type: ignore[import-not-found]

    return otp_core


def _validate_key_name(key_name: str) -> str:
    clean = str(key_name or "").strip()
    if not clean or not _KEY_NAME_RE.fullmatch(clean):
        raise ValueError(f"invalid vault key_name: {key_name!r}")
    return clean


@contextmanager
def _index_lock(home: Path) -> Iterator[None]:
    home.mkdir(parents=True, exist_ok=True)
    lock_path = home / _LOCK_FILENAME
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_index(home: Path) -> dict[str, str]:
    index_path = home / _INDEX_FILENAME
    if not index_path.is_file():
        return {}
    try:
        raw = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("credential vault index unreadable") from exc
    if not isinstance(raw, dict):
        raise ValueError("credential vault index must be a JSON object")
    return {str(k): str(v) for k, v in raw.items() if isinstance(k, str) and isinstance(v, str)}


def _write_index(home: Path, index: dict[str, str]) -> None:
    index_path = home / _INDEX_FILENAME
    home.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=home,
            prefix=".agentic-vault-idx-",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            json.dump(index, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, index_path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_vault_credentials(cco_home: Path | str, key_name: str, payload: dict[str, Any]) -> None:
    """Encrypt and persist a named JSON credential payload via CredentialVault."""
    clean_key = _validate_key_name(key_name)
    if not isinstance(payload, dict):
        raise ValueError("vault credential payload must be a dict")

    home = Path(cco_home)
    vault_cls = _load_credential_vault_cls()
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False)

    with _index_lock(home):
        vault = vault_cls(str(home), create_key=True)
        index = _read_index(home)
        old_ref = index.get(clean_key)
        new_ref = str(
            vault.store_secret(
                "agentic_credentials",
                serialized,
                metadata={"key_name": clean_key},
            )
        )
        try:
            index[clean_key] = new_ref
            _write_index(home, index)
        except Exception:
            vault.delete_secret(new_ref)
            raise
        if old_ref and old_ref != new_ref:
            vault.delete_secret(old_ref)


def load_vault_credentials(cco_home: Path | str, key_name: str) -> dict[str, Any]:
    """Load and decrypt a named JSON credential payload fail-closed (create_key=False)."""
    clean_key = _validate_key_name(key_name)
    home = Path(cco_home)
    vault_cls = _load_credential_vault_cls()

    # Open vault with create_key=False first so missing home/key/db fails closed
    # without ever creating a replacement key or database file.
    vault = vault_cls(str(home), create_key=False)
    index = _read_index(home)
    secret_ref = index.get(clean_key)
    if not secret_ref:
        raise KeyError(clean_key)

    plaintext = vault.get_secret(secret_ref)
    try:
        parsed = json.loads(plaintext)
    except ValueError as exc:
        raise ValueError("decrypted credential payload is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("decrypted credential payload must be a JSON object")
    return parsed


def verify_external_oob_event(
    challenge: dict[str, Any],
    raw_event: str,
    trusted_keys: str,
    replay_db: Path | str,
    *,
    scope_revision: str,
    policy_hash: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify an Ed25519-signed external OOB collector event offline with replay protection."""
    try:
        verify_fn = _load_oob_verifier()
    except Exception:
        return {"authenticated": False, "reason": "collector verifier unavailable"}

    result = verify_fn(
        challenge,
        raw_event,
        trusted_keys,
        str(Path(replay_db)),
        scope_revision=scope_revision,
        policy_hash=policy_hash,
        now=now,
    )
    if isinstance(result, dict):
        return dict(result)
    return {"authenticated": False, "reason": "collector evidence invalid or unavailable"}


def fetch_latest_otp(**kwargs: Any) -> dict[str, Any]:
    """Lazily invoke mcp-otp's otp_core.fetch_latest_otp and return strictly bounded fields."""
    otp_mod = _load_otp_core()
    raw = otp_mod.fetch_latest_otp(**kwargs)
    if not isinstance(raw, dict) or not raw.get("code"):
        raise ValueError("OTP lookup returned an invalid result")
    return {
        "code": str(raw["code"]).strip()[:16],
        "age_seconds": int(raw.get("age_seconds") or 0),
    }
