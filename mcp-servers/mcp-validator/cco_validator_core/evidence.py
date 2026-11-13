"""Validator V2 evidence schema, redaction, and atomic persistence."""

from __future__ import annotations

import copy
from contextlib import contextmanager
from contextvars import ContextVar
import hmac
import hashlib
import json
import os
import re
import shlex
import tempfile
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SCRIPTS = str(Path(__file__).resolve().parents[3] / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.append(_SCRIPTS)
import evidence_trust as trust  # noqa: E402
from target_identity import resource_identity  # noqa: E402


SCHEMA_VERSION = "2.0"
VALIDATOR_VERSION = "2.0.0"
REDACTED = "<redacted>"
HUNTER_AUTHZ_SCHEMA_VERSION = "hunter-authz/2.0"
HTTP_COLLECTOR_SCHEMA_VERSION = "collector-http/1.0"
TRUSTED_ARTIFACT_SCHEMAS = {
    SCHEMA_VERSION,
    HUNTER_AUTHZ_SCHEMA_VERSION,
    HTTP_COLLECTOR_SCHEMA_VERSION,
}
LEGACY_SIGNATURE_ALGORITHM = "hmac-sha256:v1"
SIGNATURE_ALGORITHM = trust.ALGORITHM
_EXECUTION_CONTEXT: ContextVar = ContextVar("validator_execution_context", default=None)


@contextmanager
def validation_context(context: dict | None):
    """Bind request dimensions to the validator artifact before it is signed."""
    token = _EXECUTION_CONTEXT.set(copy.deepcopy(context) if context else None)
    try:
        yield
    finally:
        _EXECUTION_CONTEXT.reset(token)


def current_validation_context() -> dict:
    """Return the bound run dimensions without exposing the mutable context."""
    return copy.deepcopy(_EXECUTION_CONTEXT.get() or {})

_SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "cookie",
    "csrf",
    "csrf_token",
    "id_token",
    "password",
    "passwd",
    "proxy_authorization",
    "refresh_token",
    "secret",
    "session",
    "sessionid",
    "session_id",
    "set_cookie",
    "token",
    "x_api_key",
    "x_csrf_token",
    "xsrf",
    "xsrf_token",
}
_TEXT_PATTERNS = (
    re.compile(r"(?i)(\b(?:authorization|proxy-authorization)\s*:\s*)(?:bearer|basic)\s+[^\s'\"`]+"),
    re.compile(r"(?i)(\b(?:cookie|set-cookie|x-api-key|api-key)\s*:\s*)[^\r\n]+"),
    re.compile(
        r'(?i)([\"\']?(?:access_token|api_key|apikey|client_secret|csrf|csrf_token|id_token|password|passwd|refresh_token|secret|sessionid|session_id|token|xsrf|xsrf_token)[\"\']?\s*[:=]\s*)'
        r'([\"\']?)[^\s,;&}\]\"\']+\2'
    ),
)


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


def _is_sensitive_key(value: Any) -> bool:
    key = _normalized_key(value)
    return key in _SENSITIVE_KEYS or key.endswith(("_token", "_password", "_secret", "_api_key"))


def _record(redactions: list[str], path: str) -> None:
    if path and path not in redactions:
        redactions.append(path)


def _repo_root() -> Path:
    try:
        return Path(__file__).resolve().parents[3]
    except Exception:
        return Path.cwd()


def _first_existing_file(paths: list[Path]) -> Path | None:
    for path in paths:
        try:
            if path and path.expanduser().exists():
                return path.expanduser()
        except OSError:
            continue
    return None


def _file_hash_or_missing(kind: str, paths: list[Path]) -> str:
    path = _first_existing_file(paths)
    if not path:
        return f"{kind}:missing"
    try:
        data = path.read_bytes()
    except OSError:
        return f"{kind}:unreadable"
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def current_scope_revision() -> str:
    if os.environ.get("CCO_SCOPE_REVISION"):
        return os.environ["CCO_SCOPE_REVISION"]
    repo = _repo_root()
    cco_home = Path(os.environ.get("CCO_HOME", os.path.expanduser("~/.cco")))
    env_path = Path(os.environ["CCO_SCOPE_FILE"]) if os.environ.get("CCO_SCOPE_FILE") else None
    candidates = ([env_path] if env_path else
                  [repo / ".codex" / "scope.json", repo / ".codex" / "scope-xbow-labs.json", cco_home / "scope.json"])
    return _file_hash_or_missing("scope", candidates)


def current_policy_hash() -> str:
    if os.environ.get("CCO_POLICY_HASH"):
        return os.environ["CCO_POLICY_HASH"]
    repo = _repo_root()
    cco_home = Path(os.environ.get("CCO_HOME", os.path.expanduser("~/.cco")))
    env_path = Path(os.environ["CCO_PROGRAM_POLICY_FILE"]) if os.environ.get("CCO_PROGRAM_POLICY_FILE") else None
    if env_path:
        value = _file_hash_or_missing("policy", [env_path])
        return "policy:unreadable" if value == "policy:missing" else value
    return _file_hash_or_missing("policy", [repo / ".codex" / "program-policy.json", cco_home / "program_policy.json"])


def canonical_target(value: Any) -> str:
    raw = str(value or "").strip().lower().rstrip("/")
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw)
        if parsed.scheme and parsed.hostname:
            host = parsed.hostname.lower()
            return f"{host}:{parsed.port}" if parsed.port else host
    except Exception:
        pass
    return raw.split("/", 1)[0]


def normalize_finding_type(value: Any) -> str:
    text = re.sub(r"[^a-z0-9]+", "", str(value or "").lower())
    if not text:
        return ""
    if "sql" in text and "inject" in text:
        return "sql_injection"
    if "xss" in text or "crosssitescript" in text:
        return "xss"
    if "template" in text and "inject" in text:
        return "ssti"
    if "command" in text and "inject" in text:
        return "command_injection"
    if "pathtraversal" in text or "directorytraversal" in text or text == "lfi" or "localfileinclusion" in text:
        return "path_traversal"
    if "openredirect" in text:
        return "open_redirect"
    if "xxe" in text or "xmlexternalentity" in text:
        return "xxe"
    if "ssrf" in text:
        return "ssrf"
    if "idor" in text or "directobjectreference" in text:
        return "idor"
    if text == "bola":
        return "bola"
    if text == "bfla":
        return "bfla"
    if "brokenaccesscontrol" in text or "authbypass" in text or "authorizationbypass" in text or "authenticationbypass" in text:
        return "broken_access_control"
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def _binding_for(record: dict) -> dict:
    binding = dict(record.get("binding") or {})
    raw_target = binding.get("target") or record.get("target") or record.get("resource") or record.get("endpoint") or ""
    raw_type = (
        binding.get("finding_type")
        or record.get("vuln_type")
        or record.get("vuln_class")
        or record.get("finding_type")
        or record.get("test_type")
        or record.get("collector_type")
        or ""
    )
    binding.update({
        "target": canonical_target(raw_target),
        "finding_type": normalize_finding_type(raw_type),
        "scope_revision": binding.get("scope_revision") or current_scope_revision(),
        "policy_hash": binding.get("policy_hash") or current_policy_hash(),
    })
    return binding


def redact_url(value: str, redactions: list[str] | None = None, path: str = "url") -> str:
    """Redact credentials and sensitive query values from a URL."""
    redactions = redactions if redactions is not None else []
    try:
        parsed = urlsplit(value)
    except Exception:
        return value
    if not parsed.scheme or not parsed.netloc:
        return value

    hostname = parsed.hostname or ""
    if parsed.port:
        hostname = f"{hostname}:{parsed.port}"
    if parsed.username is not None:
        hostname = f"{parsed.username}:{REDACTED}@{hostname}"
        _record(redactions, f"{path}.userinfo")

    query = []
    for key, item in parse_qsl(parsed.query, keep_blank_values=True):
        if _is_sensitive_key(key):
            query.append((key, REDACTED))
            _record(redactions, f"{path}.query.{key}")
        else:
            query.append((key, item))
    return urlunsplit((parsed.scheme, hostname, parsed.path, urlencode(query, doseq=True), parsed.fragment))


def _redact_text(value: str, redactions: list[str], path: str) -> str:
    text = redact_url(value, redactions, path) if "://" in value and "\n" not in value else value
    for pattern in _TEXT_PATTERNS:
        def replace(match):
            _record(redactions, path)
            return f"{match.group(1)}{REDACTED}"

        text = pattern.sub(replace, text)
    return text


def redact_value(value: Any, redactions: list[str] | None = None, path: str = "result") -> Any:
    """Recursively redact known secret-bearing fields and text patterns."""
    redactions = redactions if redactions is not None else []
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            child = f"{path}.{key}"
            if _is_sensitive_key(key):
                clean[key] = REDACTED
                _record(redactions, child)
            else:
                clean[key] = redact_value(item, redactions, child)
        return clean
    if isinstance(value, (list, tuple)):
        return [redact_value(item, redactions, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, str):
        return _redact_text(value, redactions, path)
    return value


def redact_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Return headers safe for display or a reproduction command."""
    clean = {}
    for key, value in (headers or {}).items():
        if key.lower() == "user-agent":
            continue
        clean[key] = REDACTED if _is_sensitive_key(key) else str(value)
    return clean


def safe_curl(method: str, url: str, body: str = "", headers: dict | None = None) -> str:
    """Build a shell-safe reproduction command without embedding credentials."""
    parts = ["curl", "-sk"]
    if method.upper() != "GET":
        parts.extend(["-X", method.upper()])
    for key, value in redact_headers(headers).items():
        parts.extend(["-H", f"{key}: {value}"])
    if body:
        parts.extend(["--data", redact_value(body, [])])
    parts.append(redact_url(url))
    return " ".join(shlex.quote(str(part)) for part in parts)


def response_evidence(response: dict, role: str = "probe", excerpt_limit: int = 256) -> dict:
    """Reduce a raw HTTP response to bounded, redacted, reproducible metadata."""
    text = str(response.get("text") or "")
    redactions: list[str] = []
    excerpt = _redact_text(text[:excerpt_limit], redactions, f"response.{role}.excerpt")
    content_type = ""
    headers = response.get("headers") or {}
    if isinstance(headers, dict):
        content_type = str(headers.get("Content-Type") or headers.get("content-type") or "")
    return {
        "role": role,
        "transport_ok": bool(response.get("ok")),
        "method": str(response.get("request_method") or "").upper(),
        "request_url": redact_url(str(response.get("final_url") or "")),
        "status": response.get("status"),
        "response_length": int(response.get("len") or len(text.encode("utf-8", "ignore"))),
        "response_sha256": hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest(),
        "elapsed_ms": round(float(response.get("time") or 0.0) * 1000, 3),
        "content_type": content_type,
        "redirect_target": redact_url(str(response.get("location") or "")),
        "excerpt": excerpt,
        "error_kind": type(response.get("error")).__name__ if response.get("error") else "",
    }


def _strip_integrity_fields(record: dict) -> dict:
    candidate = copy.deepcopy(record)
    artifact = candidate.setdefault("artifact", {})
    artifact["content_sha256"] = ""
    artifact.setdefault("signature", {})["value"] = ""
    return candidate


def _integrity_payload(record: dict) -> bytes:
    payload = json.dumps(_strip_integrity_fields(record), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return payload.encode("utf-8")


def _canonical_hash(record: dict) -> str:
    return hashlib.sha256(_integrity_payload(record)).hexdigest()


def _canonical_json(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _signing_key(create: bool = True) -> bytes:
    if trust.public_only():
        raise RuntimeError("legacy signing key is host-only")
    env_key = os.environ.get("CCO_ARTIFACT_HMAC_KEY", "")
    if env_key:
        return env_key.encode("utf-8")
    cco_home = Path(os.environ.get("CCO_HOME", os.path.expanduser("~/.cco")))
    key_path = cco_home / "validation_artifact_hmac.key"
    try:
        if not key_path.exists() and create:
            cco_home.mkdir(mode=0o700, parents=True, exist_ok=True)
            with trust.file_lock(cco_home / "validation_artifact_hmac.lock"):
                if not key_path.exists():
                    trust.atomic_write(key_path, os.urandom(32))
        fd = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise RuntimeError("artifact signing key unavailable") from exc


def _signature_for(record: dict) -> str:
    return hmac.new(_signing_key(create=False), _integrity_payload(record), hashlib.sha256).hexdigest()


def _ensure_signature(record: dict) -> None:
    artifact = record.setdefault("artifact", {})
    signature = artifact.setdefault("signature", {})
    signature["algorithm"] = SIGNATURE_ALGORITHM
    signature["key_id"] = trust.signing_identity()
    signature["value"] = ""
    artifact["content_sha256"] = _canonical_hash(record)
    signature["value"] = trust.sign(_integrity_payload(record), "validator-artifact")["signature"]


def _signature_is_valid(record: dict, legacy_private: bool = False) -> bool:
    artifact = record.get("artifact") or {}
    signature = artifact.get("signature") or {}
    if signature.get("algorithm") == SIGNATURE_ALGORITHM:
        return trust.verify(_integrity_payload(record), {
            "signature_alg": signature["algorithm"], "key_id": signature.get("key_id"),
            "signature": signature.get("value")}, "validator-artifact")
    if signature.get("algorithm") != LEGACY_SIGNATURE_ALGORITHM:
        return False
    supplied = str(signature.get("value") or "")
    if not supplied:
        return False
    try:
        path = Path(artifact.get("path") or "")
        if not legacy_private and trust.receipt_path(path).exists():
            return trust.verify_receipt(path, record, "legacy-validation")
        if trust.public_only():
            return False
        return hmac.compare_digest(supplied, _signature_for(record))
    except (OSError, ValueError, RuntimeError):
        return False


def _trusted_roots(extra_root: str | None = None) -> list[Path]:
    roots = []
    if extra_root:
        roots.append(Path(extra_root))
    env_roots = os.environ.get("CCO_VALIDATION_ROOTS", "")
    roots.extend(Path(item) for item in env_roots.split(os.pathsep) if item)
    cco_home = Path(os.environ.get("CCO_HOME", os.path.expanduser("~/.cco")))
    roots.append(cco_home / "validations")
    resolved = []
    for root in roots:
        try:
            resolved.append(root.expanduser().resolve())
        except OSError:
            pass
    return resolved


def _path_in_trusted_root(path: str, trusted_root: str | None = None) -> bool:
    try:
        candidate = Path(path).expanduser().resolve(strict=True)
    except OSError:
        return False
    for root in _trusted_roots(trusted_root):
        try:
            if os.path.commonpath([str(root), str(candidate)]) == str(root):
                return True
        except ValueError:
            continue
    return False


def persist_result(result: dict, directory: str) -> dict:
    """Redact and atomically persist a V2 result, returning the stored record."""
    redactions: list[str] = []
    source = dict(result)
    context = _EXECUTION_CONTEXT.get()
    if isinstance(context, dict):
        source["execution_context"] = context
    clean = redact_value(source, redactions)
    clean["binding"] = _binding_for(clean)
    clean["redactions"] = sorted(set(redactions))
    clean.setdefault("artifact", {})
    clean["artifact"].update({
        "persisted": True,
        "path": "",
        "content_sha256": "",
        "signature": {"algorithm": SIGNATURE_ALGORITHM, "value": ""},
        "error": "",
    })

    target_dir = Path(directory)
    slug_source = clean.get("vuln_type") or clean.get("vuln_class") or clean.get("test_type") or clean.get("collector_type") or "finding"
    slug = re.sub(r"[^a-z0-9]+", "-", str(slug_source).lower()).strip("-")[:32]
    path = target_dir / f"{clean['validation_id']}_{slug or 'finding'}.json"
    clean["audit_trail"] = str(path)
    clean["artifact"]["path"] = str(path)
    clean["reportable"] = clean.get("verdict") == "CONFIRMED"
    temp_path = ""
    try:
        _ensure_signature(clean)
        target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(target_dir, 0o700)
        fd, temp_path = tempfile.mkstemp(prefix=".validator-", suffix=".tmp", dir=target_dir)
        os.chmod(temp_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(clean, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        temp_path = ""
        return clean
    except Exception as exc:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        clean["audit_trail"] = ""
        clean["artifact"].update({
            "persisted": False,
            "path": "",
            "content_sha256": "",
            "error": type(exc).__name__,
        })
        clean["reportable"] = False
        return clean


def load_validation(validation_id: str, directory: str | None = None) -> dict | None:
    """Load a persisted V2 artifact by validation_id from trusted validation roots."""
    vid = str(validation_id or "").strip()
    if not vid or any(token in vid for token in ("/", "\\", "..")):
        return None
    roots = [Path(directory)] if directory else list(_trusted_roots())
    needle = vid.lower()
    for root in roots:
        try:
            if not root.exists():
                continue
            for path in root.rglob("*.json"):
                name = path.name.lower()
                if not name.startswith(needle):
                    continue
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if isinstance(data, dict) and str(data.get("validation_id") or "") == vid:
                    return data
        except OSError:
            continue
    return None


def artifact_is_valid(record: dict, trusted_root: str | None = None,
                      expected_target: str = "", expected_finding_type: str = "",
                      expected_scope_revision: str = "", expected_policy_hash: str = "",
                      expected_path: str = "", _legacy_private: bool = False) -> bool:
    """Verify a V2 artifact's schema, identity, and canonical content hash."""
    if str(record.get("schema_version") or "") not in TRUSTED_ARTIFACT_SCHEMAS:
        return False
    artifact = record.get("artifact") or {}
    path = artifact.get("path")
    expected = artifact.get("content_sha256")
    if not artifact.get("persisted") or not path or not expected:
        return False
    if not _path_in_trusted_root(path, trusted_root):
        return False
    try:
        resolved_path = Path(path).expanduser().resolve(strict=True)
        stored = json.loads(resolved_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    if expected_path:
        try:
            if Path(expected_path).expanduser().resolve(strict=True) != resolved_path:
                return False
        except Exception:
            return False
    stored_artifact = stored.get("artifact") or {}
    try:
        stored_path = Path(stored_artifact.get("path") or "").expanduser().resolve(strict=True)
    except Exception:
        return False
    if stored_path != resolved_path:
        return False
    if stored.get("validation_id") != record.get("validation_id"):
        return False
    if stored.get("schema_version") != record.get("schema_version"):
        return False
    if stored_artifact.get("content_sha256") != expected:
        return False
    if _canonical_json(stored) != _canonical_json(record):
        return False
    if _canonical_hash(stored) != expected:
        return False
    if not _signature_is_valid(stored, _legacy_private):
        return False
    binding = stored.get("binding") or {}
    if expected_target:
        bound_target = binding.get("target") or ""
        raw_target = str(stored.get("target") or stored.get("resource") or stored.get("endpoint") or "")
        # Legacy signed bindings contain only host/port. Compare the signed raw
        # URL when available, without rewriting the historical signed bytes.
        if "://" in raw_target and "://" in str(expected_target) and canonical_target(raw_target) == bound_target:
            actual_key, expected_key = resource_identity(raw_target), resource_identity(str(expected_target))
            if not actual_key or not expected_key:
                return False
            actual, wanted = urlsplit(actual_key), urlsplit(expected_key)
            if (actual.scheme, actual.netloc) != (wanted.scheme, wanted.netloc):
                return False
            if wanted.path not in ("", "/") and actual.path != wanted.path:
                return False
            if wanted.query and actual.query != wanted.query:
                return False
        elif bound_target != canonical_target(expected_target):
            return False
    if expected_finding_type and binding.get("finding_type") != normalize_finding_type(expected_finding_type):
        return False
    if expected_scope_revision and binding.get("scope_revision") != expected_scope_revision:
        return False
    if expected_policy_hash and binding.get("policy_hash") != expected_policy_hash:
        return False
    if not binding.get("scope_revision") or not binding.get("policy_hash"):
        return False
    return True


def artifact_is_current(record: dict, trusted_root: str | None = None,
                        expected_target: str = "", expected_finding_type: str = "",
                        expected_path: str = "") -> bool:
    """Verify historical integrity and its binding to the current policy."""
    if (isinstance(record, dict) and str(record.get("verdict") or "").upper() == "CONFIRMED"
            and str(record.get("oracle") or "").lower() == "oob_correlation"):
        # Legacy callback text was not authenticated as collector output.
        # Keep historical signature verification but do not promote it.
        return False
    scope_revision = current_scope_revision()
    policy_hash = current_policy_hash()
    if scope_revision in {"scope:missing", "scope:unreadable"} or policy_hash == "policy:unreadable":
        return False
    return artifact_is_valid(
        record, trusted_root=trusted_root, expected_target=expected_target,
        expected_finding_type=expected_finding_type, expected_path=expected_path,
        expected_scope_revision=scope_revision, expected_policy_hash=policy_hash)


def publish_legacy_receipt(record: dict) -> bool:
    """Attest an intact historical HMAC artifact; preserve its ID and bytes."""
    if trust.public_only():
        raise ValueError("legacy artifact checkpoint is host-only")
    if ((record.get("artifact") or {}).get("signature") or {}).get("algorithm") != LEGACY_SIGNATURE_ALGORITHM:
        return False
    if not artifact_is_valid(record, _legacy_private=True):
        raise ValueError("legacy validator artifact is invalid")
    trust.publish_receipt(Path(record["artifact"]["path"]), record, "legacy-validation")
    return True
