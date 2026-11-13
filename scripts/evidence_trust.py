"""Host signing and pinned, read-only public verification for evidence.

The sandbox receives only public-trust/. Its mount is authoritative even
if a command clears its environment or changes CCO_HOME.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ALGORITHM = "ed25519:v1"
PINNED_DIR = Path("/tmp/cco-trust")
BUNDLE_NAME = "verification.json"
PRIVATE_NAME = "evidence_signing.key"


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pinned_bundle() -> Path | None:
    try:
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            fields = line.split()
            if len(fields) >= 6 and fields[4] == str(PINNED_DIR) and "ro" in fields[5].split(","):
                return PINNED_DIR / BUNDLE_NAME
    except OSError as exc:
        if os.environ.get("CCO_BASH_SANDBOXED") == "1":
            raise ValueError("sandbox trust mount unavailable") from exc
    if os.environ.get("CCO_BASH_SANDBOXED") == "1":
        raise ValueError("sandbox requires its pinned public trust mount")
    return None


def public_only() -> bool:
    return pinned_bundle() is not None


@contextmanager
def file_lock(path: Path, *, shared: bool = False):
    """One lock inode for the full transaction, including atomic replace."""
    flags = os.O_RDONLY if shared else (os.O_CREAT | os.O_RDWR)
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("lock must be a regular file")
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def atomic_write(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".evidence-", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _home() -> Path:
    return Path(os.environ.get("CCO_HOME", "~/.cco")).expanduser().resolve()


def _read_private(path: Path) -> Ed25519PrivateKey:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("signing key must be a regular file")
        raw = handle.read(33)
    if len(raw) != 32:
        raise ValueError("invalid evidence signing key")
    return Ed25519PrivateKey.from_private_bytes(raw)


def prepare() -> dict:
    """Host-only bootstrap; never regenerate an existing or invalid key."""
    if public_only():
        raise ValueError("signing is host-only; sandbox has public verification only")
    home = _home()
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    with file_lock(home / "evidence_signing.lock"):
        private_path = home / PRIVATE_NAME
        if not private_path.exists() and not private_path.is_symlink():
            if (home / "public-trust" / BUNDLE_NAME).exists():
                raise ValueError("existing public trust requires restoring its original signing key")
            key = Ed25519PrivateKey.generate()
            raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption())
            atomic_write(private_path, raw)
        key = _read_private(private_path)
        raw_public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_id = hashlib.sha256(raw_public).hexdigest()
        bundle = {"schema": "evidence-trust/1", "algorithm": ALGORITHM,
                  "active_key_id": key_id, "keys": {key_id: raw_public.hex()}}
        public_dir = home / "public-trust"
        if public_dir.is_symlink():
            raise ValueError("public trust directory cannot be a symlink")
        public_dir.mkdir(mode=0o755, exist_ok=True)
        if any(item.name != BUNDLE_NAME for item in public_dir.iterdir()):
            raise ValueError("public trust export contains unexpected files")
        bundle_path = public_dir / BUNDLE_NAME
        if bundle_path.exists():
            if bundle_path.is_symlink() or json.loads(bundle_path.read_text()) != bundle:
                raise ValueError("public trust bundle does not match the host signing key")
        else:
            atomic_write(bundle_path, canonical_bytes(bundle) + b"\n", mode=0o444)
        return {"key_id": key_id, "public_dir": str(public_dir), "bundle": str(bundle_path)}


def signing_identity() -> str:
    return prepare()["key_id"]


def _message(purpose: str, data: bytes) -> bytes:
    return b"CCO-evidence-v1\0" + purpose.encode("ascii") + b"\0" + data


def sign(data: bytes, purpose: str) -> dict:
    identity = prepare()
    key = _read_private(_home() / PRIVATE_NAME)
    return {"signature_alg": ALGORITHM, "key_id": identity["key_id"],
            "signature": key.sign(_message(purpose, data)).hex()}


def verify(data: bytes, signature: dict, purpose: str) -> bool:
    if signature.get("signature_alg") != ALGORITHM:
        return False
    try:
        path = pinned_bundle() or (_home() / "public-trust" / BUNDLE_NAME)
        bundle = json.loads(path.read_text())
        if bundle.get("schema") != "evidence-trust/1" or bundle.get("algorithm") != ALGORITHM:
            return False
        key_id = signature["key_id"]
        raw = bytes.fromhex(bundle["keys"][key_id])
        if hashlib.sha256(raw).hexdigest() != key_id:
            return False
        key = Ed25519PublicKey.from_public_bytes(raw)
        key.verify(bytes.fromhex(signature["signature"]), _message(purpose, data))
        return True
    except (OSError, ValueError, KeyError, TypeError, InvalidSignature):
        return False


def attest(payload: dict, purpose: str) -> dict:
    return {"payload": payload, **sign(canonical_bytes(payload), purpose)}


def receipt_path(path: Path) -> Path:
    return path.with_name(path.name + ".receipt.json")


def publish_receipt(path: Path, content: object, purpose: str) -> None:
    payload = {"schema": "evidence-receipt/1", "path": str(path.resolve()),
               "content_sha256": hashlib.sha256(canonical_bytes(content)).hexdigest()}
    atomic_write(receipt_path(path), canonical_bytes(attest(payload, purpose)) + b"\n")


def verify_receipt(path: Path, content: object, purpose: str) -> bool:
    try:
        receipt = json.loads(receipt_path(path).read_text())
        expected = {"schema": "evidence-receipt/1", "path": str(path.resolve()),
                    "content_sha256": hashlib.sha256(canonical_bytes(content)).hexdigest()}
        return receipt.get("payload") == expected and verify(canonical_bytes(expected), receipt, purpose)
    except (OSError, ValueError, TypeError):
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootstrap host evidence signing and export public trust")
    parser.add_argument("action", choices=["prepare"])
    parser.parse_args()
    print(json.dumps(prepare()))
