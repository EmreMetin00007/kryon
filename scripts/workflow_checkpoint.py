"""Host-signed atomic workflow state, shared by the solver and campaign queue."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat

from evidence_trust import atomic_write, attest, canonical_bytes, verify

PURPOSE = "python-workflow-checkpoint"
SCHEMA = "python-workflow-checkpoint/1"


def file_ref(root, path):
    root, path = Path(root).resolve(), Path(path)
    if not path.is_absolute():
        path = root / path
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("checkpoint artifact symlink")
    path = path.resolve()
    if root not in path.parents:
        raise ValueError("checkpoint artifact escapes run")
    raw = path.read_bytes()
    return {"path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw)}


class WorkflowCheckpoint:
    def __init__(self, workdir):
        self.workdir = Path(workdir).resolve()
        self.path = self.workdir / "checkpoint.json"
        self.fd = None

    def acquire(self):
        if self.fd is not None:
            raise ValueError('checkpoint lock already held')
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.workdir / "checkpoint.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(self.fd).st_mode):
                raise ValueError("invalid checkpoint lock")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.release()
            raise ValueError("workflow already running or locked") from None

    def release(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def write(self, payload):
        if self.fd is None:
            raise ValueError("checkpoint requires exclusive run lock")
        if self.path.is_symlink() or payload.get("schema") != SCHEMA:
            raise ValueError("invalid checkpoint destination or schema")
        atomic_write(self.path, canonical_bytes(attest(payload, PURPOSE)))

    def read(self):
        if self.path.is_symlink():
            raise ValueError("checkpoint symlink")
        signed = json.loads(self.path.read_bytes())
        payload = signed["payload"]
        if payload.get("schema") != SCHEMA or not verify(canonical_bytes(payload), signed, PURPOSE):
            raise ValueError("checkpoint signature mismatch")
        if payload['state_ref'] not in payload['evidence']:
            raise ValueError('checkpoint state lacks evidence binding')
        for name, digest in payload['context']['policy_hashes'].items():
            path = Path(name)
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('checkpoint policy context changed')
        root = self.workdir.parent
        for ref in payload["evidence"]:
            if file_ref(root, ref["path"]) != ref:
                raise ValueError("checkpoint evidence integrity mismatch")
        return payload
