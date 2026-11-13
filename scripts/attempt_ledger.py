"""Attempt ledger: the run blackboard every probe writes to.

Worker summaries are lossy prose; this file is the lossless record the
brain decides from. Each probe appends one validated record
(vector/endpoint/identity/candidate/control/status/size/artifact/sha/
verdict); coverage is computed from these records, never from claims.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

import evidence_trust as trust
from object_identity import normalize_object_id, object_id_key, object_id_sort_key

ATTEMPTS_NAME = "attempts.jsonl"
STATE_NAME = "run-state.json"
LEGACY_ALGORITHM = "hmac-sha256:v1"
SIGNATURE_ALGORITHM = trust.ALGORITHM
GENESIS_HASH = "0" * 64

REQUIRED_STRINGS = ("vector", "endpoint", "identity", "verdict")
OPTIONAL_INTS = ("status", "size")
OPTIONAL_IDS = ("candidate", "control")
OPTIONAL_STRINGS = ("artifact", "sha256", "note")
INTEGRITY_STRINGS = ("prev_hash", "record_hash", "signature", "signature_alg", "key_id", "ledger_id")
NON_PROBE_VERDICTS = {
    "never-probed", "never_probed", "not-probed", "not_probed", "not-run",
    "not_run", "untested", "skipped", "not-tested", "not_tested",
}

_JOB_TRANSITIONS = {
    "pending": ("done", "failed", "expired"),
    "done": (),
    "failed": (),
    "expired": (),
}
_JOB_STATUSES = frozenset(_JOB_TRANSITIONS)
_POINTER_RE = re.compile(
    r"(?:vault|session-vault|credential-vault|state):"
    r"[A-Za-z0-9][A-Za-z0-9_./-]{0,120}|evidence/[A-Za-z0-9][A-Za-z0-9_./-]{0,120}"
)
_HEX64_RE = re.compile(r"[0-9a-f]{64}")


def ledger_path(workdir: str | Path) -> Path:
    return Path(workdir) / ATTEMPTS_NAME


def state_path(workdir: str | Path) -> Path:
    return Path(workdir) / STATE_NAME


def validate_record(record: object) -> dict:
    """Return a normalized record or raise ValueError on bad schema."""
    if not isinstance(record, dict):
        raise ValueError("attempt record must be a JSON object")
    known = (set(REQUIRED_STRINGS) | set(OPTIONAL_INTS) | set(OPTIONAL_IDS) | set(OPTIONAL_STRINGS)
             | set(INTEGRITY_STRINGS) | {"seq"})
    unknown = sorted(set(record) - known)
    if unknown:
        raise ValueError(f"unknown attempt fields: {', '.join(unknown)}")
    clean: dict = {}
    for key in REQUIRED_STRINGS:
        value = record.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"attempt {key} must be a non-empty string")
        clean[key] = value.strip()
    for key in OPTIONAL_INTS:
        value = record.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            raise ValueError(f"attempt {key} must be an integer or omitted")
        if value is not None:
            clean[key] = value
    for key in OPTIONAL_IDS:
        value = record.get(key)
        if value is not None:
            try:
                clean[key] = normalize_object_id(value)
            except ValueError as exc:
                raise ValueError(f"attempt {key}: {exc}") from exc
    if clean.get("status") is not None and not 0 <= clean["status"] <= 599:
        raise ValueError("attempt status must be between 0 and 599")
    if clean.get("size") is not None and clean["size"] < 0:
        raise ValueError("attempt size must not be negative")
    for key in OPTIONAL_STRINGS:
        value = record.get(key, "")
        if not isinstance(value, str):
            raise ValueError(f"attempt {key} must be a string")
        if value:
            clean[key] = value
    if clean.get("sha256") and not _HEX64_RE.fullmatch(clean["sha256"]):
        raise ValueError("attempt sha256 must be lowercase hex SHA-256")
    seq = record.get("seq")
    if seq is not None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
            raise ValueError("attempt seq must be a positive integer")
        clean["seq"] = seq
    for key in INTEGRITY_STRINGS:
        value = record.get(key, "")
        if value in ("", None):
            continue
        if not isinstance(value, str):
            raise ValueError(f"attempt {key} must be a string")
        if key not in ("signature_alg", "signature") and not _HEX64_RE.fullmatch(value):
            raise ValueError(f"attempt {key} must be lowercase hex SHA-256")
        if key == "signature_alg" and value not in (SIGNATURE_ALGORITHM, LEGACY_ALGORITHM):
            raise ValueError("unsupported attempt signature algorithm")
        if key == "signature":
            length = 128 if record.get("signature_alg") == SIGNATURE_ALGORITHM else 64
            if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
                raise ValueError("invalid attempt signature encoding")
        clean[key] = value
    return clean


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _base_record(record: dict) -> dict:
    clean = validate_record(record)
    for key in INTEGRITY_STRINGS + ("seq",):
        clean.pop(key, None)
    return clean


def _signing_key(create: bool = True) -> bytes:
    """Legacy HMAC only; never expose or generate it in the sandbox."""
    if trust.public_only():
        raise ValueError("legacy signing key is host-only")
    env_key = os.environ.get("CCO_ATTEMPT_HMAC_KEY", "")
    if env_key:
        return env_key.encode("utf-8")
    cco_home = Path(os.environ.get("CCO_HOME", os.path.expanduser("~/.cco")))
    key_path = cco_home / "attempt_ledger_hmac.key"
    try:
        if not key_path.exists() and create:
            cco_home.mkdir(mode=0o700, parents=True, exist_ok=True)
            with trust.file_lock(cco_home / "attempt_ledger_hmac.lock"):
                if not key_path.exists():
                    trust.atomic_write(key_path, os.urandom(32))
        fd = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise ValueError("attempt signing key unavailable") from exc


def _record_hash(payload: dict) -> str:
    material = payload["prev_hash"] + "\n" + _canonical_json(payload)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _signature(record_hash: str) -> str:
    return hmac.new(_signing_key(), record_hash.encode("ascii"), hashlib.sha256).hexdigest()


def _ledger_id(path: str | Path) -> str:
    return hashlib.sha256(str(Path(path).resolve()).encode("utf-8")).hexdigest()


def _legacy_prefix(records: list[dict]) -> list[dict]:
    prefix = []
    for record in records:
        if not isinstance(record, dict) or record.get("signature_alg") != LEGACY_ALGORITHM:
            break
        prefix.append(record)
    return prefix


def _legacy_error(records: list[dict], path: str | Path | None,
                  force_private: bool = False) -> str:
    prefix = _legacy_prefix(records)
    if not prefix:
        return ""
    if path is not None and not force_private and trust.receipt_path(Path(path)).exists():
        return "" if trust.verify_receipt(Path(path), prefix, "legacy-ledger") else "legacy ledger receipt invalid"
    try:
        if trust.public_only():
            return "legacy ledger needs a host checkpoint"
        key = _signing_key(create=False)
        for record in prefix:
            expected = hmac.new(key, record["record_hash"].encode("ascii"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(record.get("signature", ""), expected):
                return "legacy signature mismatch"
    except (OSError, ValueError, KeyError) as exc:
        return str(exc)
    return ""


def verify_records(records: list[dict], *, path: str | Path | None = None,
                   _legacy_private: bool = False) -> tuple[list[dict], list[str]]:
    """Return the signed hash-chain prefix and integrity errors.

    Records appended by hand, edited after the fact, or carrying a
    foreign signature are not evidence. Verification stops at the first
    broken link because later records no longer have a trusted parent.
    """
    verified: list[dict] = []
    errors: list[str] = []
    previous_hash = GENESIS_HASH
    try:
        # Also enforce missing pinned trust on an empty sandbox snapshot.
        trust.public_only()
        legacy_error = _legacy_error(records, path, _legacy_private)
    except ValueError as exc:
        return [], [str(exc)]
    if legacy_error:
        return [], [legacy_error]
    seen_public = False
    for index, raw in enumerate(records, start=1):
        try:
            record = validate_record(raw)
        except ValueError as exc:
            errors.append(f"record {index}: {exc}")
            break
        missing = [key for key in ("seq", "prev_hash", "record_hash",
                                   "signature", "signature_alg")
                   if key not in record]
        if missing:
            errors.append(f"record {index}: missing integrity fields: {', '.join(missing)}")
            break
        payload = {**_base_record(record), "seq": record["seq"],
                   "prev_hash": record["prev_hash"]}
        if record["signature_alg"] == SIGNATURE_ALGORITHM:
            if not record.get("key_id") or not record.get("ledger_id"):
                errors.append(f"record {index}: missing public signature binding")
                break
            if path is not None and record["ledger_id"] != _ledger_id(path):
                errors.append(f"record {index}: ledger path mismatch")
                break
            payload.update(key_id=record["key_id"], ledger_id=record["ledger_id"])
            seen_public = True
        elif seen_public:
            errors.append(f"record {index}: legacy algorithm after a public signature")
            break
        if record["seq"] != index:
            errors.append(f"record {index}: sequence mismatch")
            break
        if record["prev_hash"] != previous_hash:
            errors.append(f"record {index}: previous-hash mismatch")
            break
        expected_hash = _record_hash(payload)
        if not hmac.compare_digest(record["record_hash"], expected_hash):
            errors.append(f"record {index}: record-hash mismatch")
            break
        if record["signature_alg"] == SIGNATURE_ALGORITHM and not trust.verify(
                expected_hash.encode("ascii"), record, "attempt-record"):
            errors.append(f"record {index}: signature mismatch")
            break
        verified.append(record)
        previous_hash = expected_hash
    return verified, errors


def chain_errors(records: list[dict]) -> list[str]:
    return verify_records(records)[1]


def sign_payload(payload: dict) -> dict:
    """Host-only gate seal; its public verification key is safe to mount."""
    return trust.attest(payload, "gate-payload")


def verify_signed_payload(signed: object) -> tuple[dict | None, str]:
    """Return (payload, "") when the signature holds, else (None, reason)."""
    if not isinstance(signed, dict) or not isinstance(
            signed.get("payload"), dict):
        return None, "not a signed gate payload"
    if signed.get("signature_alg") == SIGNATURE_ALGORITHM:
        return ((signed["payload"], "") if trust.verify(
            trust.canonical_bytes(signed["payload"]), signed, "gate-payload")
            else (None, "signature mismatch"))
    if signed.get("signature_alg") != LEGACY_ALGORITHM:
        return None, "unknown signature algorithm"
    body = _canonical_json(signed["payload"])
    digest = hashlib.sha256(
        ("signed-payload-v1\n" + body).encode("utf-8")).hexdigest()
    try:
        expected = hmac.new(_signing_key(create=False), digest.encode("ascii"),
                            hashlib.sha256).hexdigest()
    except ValueError as exc:
        return None, str(exc)
    if not hmac.compare_digest(str(signed.get("signature", "")), expected):
        return None, "signature mismatch"
    return signed["payload"], ""


def _confined_artifact_path(workdir: str | Path, artifact: object) -> Path | None:
    if not isinstance(artifact, str) or not artifact.strip():
        return None
    try:
        root = Path(workdir).expanduser().resolve()
        raw = Path(artifact.strip()).expanduser()
        candidate = raw if raw.is_absolute() else root / raw
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    if resolved != root and root not in resolved.parents:
        return None
    return resolved


def resolve_artifact(workdir: str | Path, artifact: object) -> Path | None:
    """Resolve an existing evidence artifact only inside the run workdir."""
    resolved = _confined_artifact_path(workdir, artifact)
    return resolved if resolved is not None and resolved.is_file() else None


def append_record(path: str | Path, record: dict) -> dict:
    """Serialize read/verify/sequence/sign/commit across processes."""
    target = Path(path).absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise ValueError("attempt ledger cannot be a symlink")
    target = target.parent.resolve() / target.name
    with trust.file_lock(target.with_suffix(target.suffix + ".lock")):
        return _append_locked(target, record)


def _append_locked(target: Path, record: dict) -> dict:
    existing = _read_records_unlocked(target)
    _, errors = verify_records(existing, path=target)
    if errors:
        raise ValueError(f"attempt ledger chain is invalid: {'; '.join(errors)}")
    clean = _base_record(record)
    if clean.get("artifact") and _confined_artifact_path(
            target.parent, clean["artifact"]) is None:
        raise ValueError("attempt artifact must stay inside the run workdir")
    artifact_path = resolve_artifact(target.parent, clean.get("artifact", ""))
    if artifact_path is not None:
        clean["sha256"] = sha256_of(artifact_path)
    key_id = trust.signing_identity()
    prefix = _legacy_prefix(existing)
    if prefix and not trust.receipt_path(target).exists():
        trust.publish_receipt(target, prefix, "legacy-ledger")
    payload = {
        **clean,
        "seq": len(existing) + 1,
        "prev_hash": existing[-1]["record_hash"] if existing else GENESIS_HASH,
        "key_id": key_id, "ledger_id": _ledger_id(target),
    }
    record_hash = _record_hash(payload)
    stored = {
        **payload,
        "record_hash": record_hash,
        "signature_alg": SIGNATURE_ALGORITHM,
        **trust.sign(record_hash.encode("ascii"), "attempt-record"),
    }
    stored = validate_record(stored)
    previous = target.read_bytes() if target.exists() else b""
    separator = b"\n" if previous and not previous.endswith(b"\n") else b""
    trust.atomic_write(target, previous + separator + trust.canonical_bytes(stored) + b"\n")
    return stored


def read_records(path: str | Path) -> list[dict]:
    target = Path(path)
    if target.is_symlink():
        raise ValueError("attempt ledger cannot be a symlink")
    if not target.is_file():
        return []
    lock = target.with_suffix(target.suffix + ".lock")
    if lock.is_symlink():
        raise ValueError("attempt ledger lock cannot be a symlink")
    if not lock.exists():
        # Historical/exported snapshots may have no lock. New writers create
        # one before modifying anything and commit with atomic replace.
        return _read_records_unlocked(target)
    with trust.file_lock(lock, shared=True):
        return _read_records_unlocked(target)


def _read_records_unlocked(target: Path) -> list[dict]:
    if not target.exists():
        return []
    records: list[dict] = []
    for line_number, line in enumerate(
            target.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"attempt record line {line_number}: invalid JSON") from exc
        try:
            records.append(validate_record(parsed))
        except ValueError as exc:
            raise ValueError(f"attempt record line {line_number}: {exc}") from exc
    return records


def checkpoint(path: str | Path) -> dict:
    """Host migration attests an existing legacy prefix without rewriting it."""
    if trust.public_only():
        raise ValueError("checkpoint signing is host-only")
    target = Path(path).absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise ValueError("attempt ledger cannot be a symlink")
    with trust.file_lock(target.with_suffix(target.suffix + ".lock")):
        records = _read_records_unlocked(target)
        _, errors = verify_records(records, path=target, _legacy_private=True)
        if errors:
            raise ValueError("invalid ledger: " + "; ".join(errors))
        trust.prepare()
        prefix = _legacy_prefix(records)
        if prefix:
            trust.publish_receipt(target, prefix, "legacy-ledger")
        return {"records": len(records), "legacy_records": len(prefix),
                "head": records[-1]["record_hash"] if records else ""}


def sha256_of(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_probe_record(record: dict) -> bool:
    status = record.get("status")
    verdict = str(record.get("verdict", "")).strip().lower()
    if verdict in NON_PROBE_VERDICTS:
        return False
    return isinstance(status, int) and 100 <= status <= 599


def is_probe_record(record: dict) -> bool:
    return _is_probe_record(record)


def _endpoint_mentions_candidate(endpoint: object, candidate) -> bool:
    text = str(endpoint or "")
    if isinstance(candidate, int):
        if any(token in text for token in ("{id}", ":id", "{candidate}", ":candidate")):
            return True
        return re.search(rf"(?<![0-9]){candidate}(?![0-9])", text) is not None
    try:
        ref = normalize_object_id(candidate)
        if not isinstance(ref, dict):
            return False
        parsed = urlsplit(text)
        segments = [unquote(part) for part in parsed.path.split("/") if part]
        values = segments + [value for _, value in parse_qsl(parsed.query, keep_blank_values=True)]
        return (not ref["family"] or ref["family"] in segments) and str(ref["value"]) in values
    except (TypeError, ValueError):
        return False


def coverage(records: list[dict], vector: str,
             expected: list | tuple = (), *, path: str | Path | None = None) -> dict:
    """Tried/untried/control counts from the signed chain only."""
    verified, errors = verify_records(records, path=path)
    tried: dict[str, object] = {}
    control_ids: dict[str, object] = {}
    for record in verified:
        if record.get("vector") != vector or not _is_probe_record(record):
            continue
        candidate = record.get("candidate")
        control = record.get("control")
        if candidate is not None and _endpoint_mentions_candidate(record.get("endpoint"), candidate):
            tried[object_id_key(candidate)] = candidate
        if control is not None and (candidate is None or object_id_key(candidate) == object_id_key(control)):
            if isinstance(control, int) or _endpoint_mentions_candidate(record.get("endpoint"), control):
                control_ids[object_id_key(control)] = control
    wanted_by_key = {object_id_key(value): normalize_object_id(value) for value in expected}
    wanted = sorted(wanted_by_key.values(), key=object_id_sort_key)
    return {
        "vector": vector,
        "tried": sorted(tried.values(), key=object_id_sort_key),
        "untried": [value for value in wanted if object_id_key(value) not in tried],
        "controls": len(control_ids),
        "control_ids": sorted(control_ids.values(), key=object_id_sort_key),
        "trusted_records": len(verified),
        "integrity_errors": errors,
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _valid_pointer(pointer: object) -> bool:
    return isinstance(pointer, str) and _POINTER_RE.fullmatch(pointer.strip()) is not None


def validate_state(data: object) -> dict:
    if not isinstance(data, dict):
        raise ValueError("run state must be a JSON object")
    identities = data.get("identities", [])
    jobs = data.get("jobs", [])
    if not isinstance(identities, list) or not isinstance(jobs, list):
        raise ValueError("run state identities and jobs must be lists")
    clean_identities: list[dict] = []
    for item in identities:
        if not isinstance(item, dict):
            raise ValueError("run state identity must be an object")
        name = item.get("name")
        pointer = item.get("pointer")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("run state identity name must be non-empty")
        if not _valid_pointer(pointer):
            raise ValueError("run state identity pointer must be a reference")
        clean_identities.append({"name": name.strip(), "pointer": str(pointer).strip()})
    clean_jobs: list[dict] = []
    for item in jobs:
        if not isinstance(item, dict):
            raise ValueError("run state job must be an object")
        kind = item.get("kind")
        ref = item.get("ref")
        status = item.get("status")
        updated_at = item.get("updated_at", "")
        if not isinstance(kind, str) or not kind.strip():
            raise ValueError("run state job kind must be non-empty")
        if not isinstance(ref, str) or not ref.strip():
            raise ValueError("run state job ref must be non-empty")
        if status not in _JOB_STATUSES:
            raise ValueError("run state job status is invalid")
        if not isinstance(updated_at, str):
            raise ValueError("run state job updated_at must be a string")
        clean_jobs.append({
            "kind": kind.strip(), "ref": ref.strip(), "status": status,
            "updated_at": updated_at,
        })
    return {"identities": clean_identities, "jobs": clean_jobs}


def load_state(workdir: str | Path) -> dict:
    path = state_path(workdir)
    if not path.is_file():
        return {"identities": [], "jobs": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"unreadable run state: {exc}") from exc
    return validate_state(data)


def save_state(workdir: str | Path, state: dict) -> Path:
    path = state_path(workdir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(validate_state(state), ensure_ascii=False))
    return path


def set_identity(state: dict, name: str, pointer: str) -> dict:
    """Register an identity by reference only — never a session secret."""
    if not name.strip():
        raise ValueError("identity name must be non-empty")
    if not _valid_pointer(pointer):
        raise ValueError("identity pointer must be a reference, not a session value")
    entry = {"name": name.strip(), "pointer": pointer.strip()}
    identities = [item for item in state.get("identities", [])
                  if item.get("name") != entry["name"]]
    identities.append(entry)
    state["identities"] = identities
    return entry


def add_job(state: dict, kind: str, ref: str) -> dict:
    if not kind.strip() or not ref.strip():
        raise ValueError("job kind and ref must be non-empty")
    for existing in state.get("jobs", []):
        if existing.get("ref") == ref.strip():
            if existing.get("status") != "pending":
                raise ValueError(f"job {ref} is terminal; use job-reopen explicitly")
            if existing.get("kind") != kind.strip():
                raise ValueError(f"job {ref}: kind cannot change")
            existing["updated_at"] = _utc_now()
            return existing
    job = {"kind": kind.strip(), "ref": ref.strip(), "status": "pending",
           "updated_at": _utc_now()}
    state.setdefault("jobs", []).append(job)
    return job


def reopen_job(state: dict, ref: str, kind: str = "") -> dict:
    for job in state.get("jobs", []):
        if job.get("ref") == ref:
            if job.get("status") == "pending":
                raise ValueError(f"job {ref}: already pending")
            if kind and job.get("kind") != kind.strip():
                raise ValueError(f"job {ref}: kind cannot change")
            job["status"] = "pending"
            job["updated_at"] = _utc_now()
            return job
    raise KeyError(f"unknown job ref: {ref}")


def set_job(state: dict, ref: str, status: str) -> dict:
    for job in state.get("jobs", []):
        if job.get("ref") == ref:
            allowed = _JOB_TRANSITIONS.get(str(job.get("status")), ())
            if status not in allowed:
                raise ValueError(f"job {ref}: {job.get('status')} cannot move to {status}")
            job["status"] = status
            job["updated_at"] = _utc_now()
            return job
    raise KeyError(f"unknown job ref: {ref}")


def pending_jobs(state: dict) -> list[dict]:
    return [job for job in state.get("jobs", []) if job.get("status") == "pending"]
