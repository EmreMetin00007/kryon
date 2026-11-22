#!/usr/bin/env python3
"""Generate production Markdown (report.md) and SARIF 2.1.0 (report.sarif) QA reports."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile
from typing import Any, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from agentic_receipts import (  # noqa: E402
    SENSITIVE_HEADER_NAMES,
    redact_headers,
    redact_secrets,
)
from agentic_surface import SurfaceFrontierTracker  # noqa: E402

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Kryon Agentic Engine"
TOOL_SEMANTIC_VERSION = "0.4.0"
TOOL_INFO_URI = "https://github.com/EmreMetin00007/kryon"

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_VALID_SEVERITIES = frozenset(_SEVERITY_ORDER)

_EXTRA_SENSITIVE_HEADERS = frozenset({
    "api-key",
    "apikey",
    "x-access-token",
    "x-api-secret",
    "x-refresh-token",
    "x-secret",
    "x-session-token",
    "x-token",
})
_ALL_SENSITIVE_HEADERS = SENSITIVE_HEADER_NAMES | _EXTRA_SENSITIVE_HEADERS

_SENSITIVE_QUERY_KEYS = frozenset({
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "auth_token",
    "client_secret",
    "credential",
    "credentials",
    "id_token",
    "jwt",
    "key",
    "passwd",
    "password",
    "private_key",
    "pwd",
    "refresh_token",
    "secret",
    "session",
    "session_id",
    "sid",
    "sig",
    "signature",
    "token",
})

_COOKIE_ATTR_WORDS = frozenset({
    "domain",
    "expires",
    "httponly",
    "lax",
    "max-age",
    "none",
    "path",
    "samesite",
    "secure",
    "strict",
})

_CURL_SKIP_HEADERS = frozenset({
    "accept-encoding",
    "connection",
    "content-length",
    "host",
})

_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}={0,2}(?![A-Za-z0-9_-])"
)
_HEADER_LINE_RE = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|x-csrf-token(?:-next)?|x-xsrf-token)\s*:\s*)(.+)$"
)
_INLINE_AUTH_HEADER_RE = re.compile(
    r"(?i)\b((?:proxy-)?authorization\s*:\s*(?:bearer|basic|token|digest|apikey)\s+)([^\s,;\"'`]+)"
)
_INLINE_KEY_HEADER_RE = re.compile(
    r"(?i)\b((?:x-api-key|x-auth-token|x-access-token|x-session-token|set-cookie|cookie)\s*:\s*)([^\r\n;\"'`]+)"
)
_JSON_SECRET_FIELD_RE = re.compile(
    r'(?i)(["\']?(?:api_key|apikey|access_token|refresh_token|id_token|client_secret|private_key|session_id|secret|password|passwd|token|jwt)["\']?\s*:\s*["\'])([^"\']+)(["\'])'
)
_KV_SECRET_RE = re.compile(
    r"(?i)\b(api_key|apikey|access_token|refresh_token|client_secret|private_key|password|passwd|secret|token|sid)=([^\s&;\"'`,]+)"
)
_SAFE_SHELL_VALUE_RE = re.compile(r"^[A-Za-z0-9_./:@+=,<>\- ]+$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")
_MULTIPART_SUMMARY_PREFIX = "multipart/form-data "

_SUCCESSFUL_STATUSES = frozenset({
    "finished",
    "max_turns_reached",
    "budget_exhausted",
    "http_budget_exhausted",
})

# General OWASP + CWE metadata keyed by canonical vulnerability class.
_VULN_CLASS_METADATA: dict[str, dict[str, Any]] = {
    "bola": {
        "name": "Broken Object Level Authorization (BOLA / IDOR)",
        "owasp": "OWASP API1:2023 / A01:2021",
        "cwe": "CWE-639",
        "default_severity": "high",
        "description": "Endpoint permits an actor to access or mutate a resource object belonging to another user without object-level authorization.",
    },
    "bfla": {
        "name": "Broken Function Level Authorization (BFLA)",
        "owasp": "OWASP API5:2023 / A01:2021",
        "cwe": "CWE-285",
        "default_severity": "high",
        "description": "Privileged or administrative function is accessible to a lower-privileged authenticated actor.",
    },
    "auth_bypass": {
        "name": "Authentication Bypass",
        "owasp": "OWASP API2:2023 / A07:2021",
        "cwe": "CWE-306",
        "default_severity": "critical",
        "description": "Protected endpoint or action succeeds without valid authentication credentials.",
    },
    "tenant_isolation": {
        "name": "Cross-Tenant Isolation Failure",
        "owasp": "OWASP API1:2023 / A01:2021",
        "cwe": "CWE-284",
        "default_severity": "critical",
        "description": "Actor in one tenant can read or modify resources owned by a different tenant.",
    },
    "stored_xss": {
        "name": "Stored Cross-Site Scripting (Stored XSS)",
        "owasp": "OWASP A03:2021 (Injection)",
        "cwe": "CWE-79",
        "default_severity": "high",
        "description": "Untrusted input is persisted and rendered unescaped in a subsequent response context.",
    },
    "reflected_xss": {
        "name": "Reflected Cross-Site Scripting (Reflected XSS)",
        "owasp": "OWASP A03:2021 (Injection)",
        "cwe": "CWE-79",
        "default_severity": "medium",
        "description": "Untrusted request input is reflected unescaped in an HTML/script response.",
    },
    "sqli": {
        "name": "SQL Injection (SQLi)",
        "owasp": "OWASP A03:2021 (Injection)",
        "cwe": "CWE-89",
        "default_severity": "critical",
        "description": "Untrusted input alters backend SQL query syntax or execution.",
    },
    "sqli_read": {
        "name": "Read-Path SQL Injection",
        "owasp": "OWASP A03:2021 (Injection)",
        "cwe": "CWE-89",
        "default_severity": "high",
        "description": "Read/query parameter alters backend SQL query behavior, sorting, or error/boolean output.",
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "owasp": "OWASP A10:2021 / API7:2023",
        "cwe": "CWE-918",
        "default_severity": "high",
        "description": "Server fetches or connects to an attacker-influenced URL or internal network destination.",
    },
    "ssti": {
        "name": "Server-Side Template Injection (SSTI)",
        "owasp": "OWASP A03:2021 (Injection)",
        "cwe": "CWE-1336",
        "default_severity": "critical",
        "description": "Untrusted input is evaluated as server-side template expressions.",
    },
    "mass_assignment": {
        "name": "Mass Assignment / Property Overposting",
        "owasp": "OWASP API3:2023",
        "cwe": "CWE-915",
        "default_severity": "high",
        "description": "Request binds client-supplied fields to privileged or restricted internal object properties.",
    },
    "open_redirect": {
        "name": "Open Redirect",
        "owasp": "OWASP A01:2021",
        "cwe": "CWE-601",
        "default_severity": "medium",
        "description": "Application redirects users to an untrusted external URL supplied in request parameters.",
    },
    "path_traversal": {
        "name": "Path Traversal",
        "owasp": "OWASP A01:2021",
        "cwe": "CWE-22",
        "default_severity": "high",
        "description": "User-controlled file path input allows reading or accessing files outside the intended directory.",
    },
    "csrf": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "owasp": "OWASP A01:2021",
        "cwe": "CWE-352",
        "default_severity": "medium",
        "description": "State-changing request executes without adequate anti-CSRF token or origin verification.",
    },
    "race_condition": {
        "name": "Race Condition (TOCTOU)",
        "owasp": "OWASP A04:2021 / API6:2023",
        "cwe": "CWE-362",
        "default_severity": "medium",
        "description": "Concurrent requests bypass state, quota, or idempotency invariants.",
    },
    "business_logic": {
        "name": "Business Logic Flaw",
        "owasp": "OWASP A04:2021 / API6:2023",
        "cwe": "CWE-840",
        "default_severity": "medium",
        "description": "Application workflow permits unintended state transitions or business-rule abuse.",
    },
    "xxe": {
        "name": "XML External Entity Injection (XXE)",
        "owasp": "OWASP A05:2021",
        "cwe": "CWE-611",
        "default_severity": "high",
        "description": "XML parser processes external entity references from untrusted input.",
    },
    "jwt_weakness": {
        "name": "JWT Verification / Key Confusion Weakness",
        "owasp": "OWASP API2:2023 / A07:2021",
        "cwe": "CWE-347",
        "default_severity": "critical",
        "description": "Application accepts forged, unsigned (alg=none), or algorithm-confused JSON Web Tokens.",
    },
    "insecure_deserialization": {
        "name": "Insecure Deserialization",
        "owasp": "OWASP A08:2021 (Software and Data Integrity Failures)",
        "cwe": "CWE-502",
        "default_severity": "critical",
        "description": "Application deserializes untrusted input into executable functions, gadgets, or unintended objects.",
    },
    "info_disclosure": {
        "name": "Sensitive Information Exposure",
        "owasp": "OWASP A01:2021 / API3:2023",
        "cwe": "CWE-200",
        "default_severity": "medium",
        "description": "Endpoint exposes sensitive internal data or metadata to unauthorized actors.",
    },
}

_GENERIC_CLASS_META: dict[str, Any] = {
    "name": "Security Control Weakness",
    "owasp": "OWASP Top 10 / API Security",
    "cwe": "CWE-693",
    "default_severity": "medium",
    "description": "Verified security policy or input validation discrepancy observed against comparative control.",
}


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".report-", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _read_json_safe(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _normalize_class_type(raw_class: Any) -> str:
    text = str(raw_class or "").strip().lower().replace("-", "_").replace(" ", "_")
    return text or "other"


def _normalize_severity(raw_severity: Any, class_type: str) -> str:
    sev = str(raw_severity or "").strip().lower()
    if sev in _VALID_SEVERITIES:
        return sev
    meta = _VULN_CLASS_METADATA.get(class_type, _GENERIC_CLASS_META)
    return str(meta.get("default_severity") or "medium")


def _class_metadata(class_type: str) -> dict[str, Any]:
    meta = _VULN_CLASS_METADATA.get(class_type)
    if meta is not None:
        return meta
    pretty = class_type.replace("_", " ").title() if class_type and class_type != "other" else "Security Finding"
    return {
        **_GENERIC_CLASS_META,
        "name": f"{pretty} ({_GENERIC_CLASS_META['name']})",
    }


def _sarif_level(severity: str) -> str:
    sev = str(severity or "").strip().lower()
    if sev in {"critical", "high"}:
        return "error"
    if sev == "medium":
        return "warning"
    return "note"


def _is_already_redacted(val: str) -> bool:
    return "<REDACTED" in val


def _extract_secrets_from_headers(headers: Any, sink: set[str]) -> None:
    if not isinstance(headers, dict):
        return
    for raw_k, raw_v in headers.items():
        name = str(raw_k or "").strip().lower()
        val = str(raw_v or "").strip()
        if not val or _is_already_redacted(val):
            continue
        if name in _ALL_SENSITIVE_HEADERS or any(tok in name for tok in ("token", "secret", "api-key", "apikey", "cookie", "auth")):
            if name in {"x-actor-alias", "x-authenticated-user", "x-user"}:
                continue
            if len(val) >= 4:
                sink.add(val)
            if name in {"authorization", "proxy-authorization"}:
                parts = val.split(None, 1)
                if len(parts) == 2 and len(parts[1].strip()) >= 4:
                    sink.add(parts[1].strip())
            elif name in {"cookie", "set-cookie"}:
                for segment in val.split(";"):
                    seg = segment.strip()
                    if "=" not in seg:
                        continue
                    ck_name, ck_val = seg.split("=", 1)
                    if ck_name.strip().lower() in _COOKIE_ATTR_WORDS:
                        continue
                    ck_val_clean = ck_val.strip()
                    if len(ck_val_clean) >= 4:
                        sink.add(ck_val_clean)
                        sink.add(seg)


def _extract_secrets_from_url(url: str, sink: set[str]) -> None:
    raw = str(url or "").strip()
    if not raw:
        return
    try:
        parts = urlsplit(raw)
    except ValueError:
        return
    if parts.password and len(parts.password) >= 4 and not _is_already_redacted(parts.password):
        sink.add(parts.password)
    if parts.query:
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            kl = k.strip().lower()
            if (kl in _SENSITIVE_QUERY_KEYS or any(t in kl for t in ("token", "secret", "password", "apikey", "api_key"))) and len(v) >= 4:
                if not _is_already_redacted(v):
                    sink.add(v)


def _collect_secret_values(artifacts: dict[str, Any]) -> tuple[str, ...]:
    secrets: set[str] = set()
    receipts = artifacts.get("receipts") or {}
    if isinstance(receipts, dict):
        for rec in receipts.values():
            if not isinstance(rec, dict):
                continue
            _extract_secrets_from_headers(rec.get("request_headers"), secrets)
            _extract_secrets_from_headers(rec.get("response_headers"), secrets)
            _extract_secrets_from_url(str(rec.get("url") or ""), secrets)
            _extract_secrets_from_url(str(rec.get("redirect_location") or ""), secrets)
    findings = artifacts.get("findings") or []
    if isinstance(findings, list):
        for f in findings:
            if isinstance(f, dict):
                _extract_secrets_from_url(str(f.get("url") or ""), secrets)
    return tuple(sorted(secrets, key=len, reverse=True))


def _sanitize_url(raw_url: str, secret_values: Sequence[str] = ()) -> str:
    text = str(raw_url or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        return _sanitize_text(text, secret_values)

    netloc = parts.netloc
    if parts.username or parts.password:
        host_port = parts.hostname or ""
        if parts.port is not None:
            host_port = f"{host_port}:{parts.port}"
        netloc = f"<REDACTED_CREDENTIALS>@{host_port}" if host_port else "<REDACTED_CREDENTIALS>"

    query = parts.query
    if query:
        redacted_pairs: list[tuple[str, str]] = []
        for k, v in parse_qsl(query, keep_blank_values=True):
            kl = k.strip().lower()
            is_sensitive_key = (
                kl in _SENSITIVE_QUERY_KEYS
                or any(tok in kl for tok in ("token", "secret", "password", "passwd", "apikey", "api_key"))
            )
            if is_sensitive_key and v and not _is_already_redacted(v):
                redacted_pairs.append((k, "<REDACTED>"))
            else:
                redacted_pairs.append((k, _sanitize_text(v, secret_values)))
        query = urlencode(redacted_pairs, doseq=True)

    rebuilt = urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))
    return _sanitize_text(rebuilt, secret_values)


def _sanitize_text(text: Any, secret_values: Sequence[str] = ()) -> str:
    raw = str(text or "")
    if not raw:
        return ""
    cleaned = redact_secrets(raw, secret_values)
    cleaned = _JWT_RE.sub("<REDACTED_JWT>", cleaned)
    cleaned = _HEADER_LINE_RE.sub(lambda m: f"{m.group(1)}<REDACTED_HEADER>", cleaned)
    cleaned = _INLINE_AUTH_HEADER_RE.sub(lambda m: f"{m.group(1)}<REDACTED_TOKEN>", cleaned)
    cleaned = _INLINE_KEY_HEADER_RE.sub(
        lambda m: m.group(0) if _is_already_redacted(m.group(2)) else f"{m.group(1)}<REDACTED_HEADER>",
        cleaned,
    )
    cleaned = _JSON_SECRET_FIELD_RE.sub(
        lambda m: m.group(0) if _is_already_redacted(m.group(2)) else f"{m.group(1)}<REDACTED_SECRET>{m.group(3)}",
        cleaned,
    )
    cleaned = _KV_SECRET_RE.sub(
        lambda m: m.group(0) if _is_already_redacted(m.group(2)) else f"{m.group(1)}=<REDACTED_SECRET>",
        cleaned,
    )
    return cleaned


def _sanitize_header_dict(headers: Any, secret_values: Sequence[str] = ()) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    base = redact_headers({str(k): str(v) for k, v in headers.items()})
    out: dict[str, str] = {}
    for k, v in base.items():
        kl = k.strip().lower()
        if kl in _ALL_SENSITIVE_HEADERS and kl not in SENSITIVE_HEADER_NAMES:
            out[k] = "<REDACTED_HEADER>"
        else:
            out[k] = _sanitize_text(v, secret_values)
    return out


def load_run_artifacts(run_dir: Path) -> dict[str, Any]:
    """Load run artifacts (`manifest.json`/`launch.json`, `findings.json`, `process_metrics.json`, `receipts/*.json`)."""
    root = Path(run_dir).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"run directory not found: {run_dir}")

    missing_artifacts: list[str] = []

    manifest_raw = _read_json_safe(root / "manifest.json")
    if not isinstance(manifest_raw, dict):
        manifest_raw = _read_json_safe(root / "launch.json")
    if not isinstance(manifest_raw, dict):
        missing_artifacts.append("manifest.json")
        manifest: dict[str, Any] = {}
    else:
        manifest = manifest_raw

    checkpoint_raw = _read_json_safe(root / "checkpoint.json")
    checkpoint = checkpoint_raw if isinstance(checkpoint_raw, dict) else {}

    findings_raw = _read_json_safe(root / "findings.json")
    if isinstance(findings_raw, list):
        findings = [dict(item) for item in findings_raw if isinstance(item, dict)]
    elif isinstance(checkpoint.get("findings"), list):
        findings = [dict(item) for item in checkpoint["findings"] if isinstance(item, dict)]
        missing_artifacts.append("findings.json")
    else:
        findings = []
        missing_artifacts.append("findings.json")

    metrics_raw = _read_json_safe(root / "process_metrics.json")
    if isinstance(metrics_raw, dict):
        process_metrics = metrics_raw
    elif isinstance(manifest.get("process_metrics"), dict):
        process_metrics = dict(manifest["process_metrics"])
    else:
        process_metrics = {}
        missing_artifacts.append("process_metrics.json")

    receipts: dict[str, dict[str, Any]] = {}
    receipts_dir = root / "receipts"
    if receipts_dir.is_dir():
        for rpath in sorted(receipts_dir.glob("*.json")):
            rdata = _read_json_safe(rpath)
            if isinstance(rdata, dict):
                rid = str(rdata.get("receipt_id") or rpath.stem).strip() or rpath.stem
                receipts[rid] = rdata
    else:
        missing_artifacts.append("receipts/")

    return {
        "run_dir": str(root),
        "manifest": manifest,
        "checkpoint": checkpoint,
        "findings": findings,
        "process_metrics": process_metrics,
        "receipts": receipts,
        "missing_artifacts": missing_artifacts,
    }


def _select_proof_receipt(finding: dict[str, Any], receipts: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    proof_ids = [str(x).strip() for x in (finding.get("proof_receipt_ids") or []) if str(x).strip()]
    actor = str(finding.get("actor") or finding.get("actor_alias") or "").strip()
    candidates = [receipts[rid] for rid in proof_ids if rid in receipts]
    if not candidates:
        return None
    for rec in candidates:
        if actor and str(rec.get("actor") or "").strip() == actor and 200 <= int(rec.get("status", 0) or 0) < 400:
            return rec
    for rec in candidates:
        if 200 <= int(rec.get("status", 0) or 0) < 400:
            return rec
    return candidates[0]


def _select_control_receipts(finding: dict[str, Any], receipts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    ctrl_ids = [str(x).strip() for x in (finding.get("control_receipt_ids") or []) if str(x).strip()]
    return [receipts[rid] for rid in ctrl_ids if rid in receipts]


def _format_curl_header_arg(name: str, value: str) -> str:
    combined = f"{name}: {value}"
    if _SAFE_SHELL_VALUE_RE.match(combined) and '"' not in combined:
        return f'-H "{combined}"'
    return f"-H {shlex.quote(combined)}"


def _is_multipart_receipt(req_body: str, headers: dict[str, str]) -> bool:
    """Return True when a receipt represents a multipart/form-data upload."""
    if req_body.startswith(_MULTIPART_SUMMARY_PREFIX):
        return True
    for k, v in headers.items():
        if str(k).strip().lower() == "content-type":
            if str(v or "").strip().lower().startswith("multipart/form-data"):
                return True
    return False


def _sanitize_curl_multipart_token(raw: Any, secret_values: Sequence[str]) -> str:
    """Sanitize a multipart field name, filename, or content-type for safe single-line curl -F output."""
    cleaned = _sanitize_text(str(raw or ""), secret_values)
    cleaned = _CONTROL_CHARS_RE.sub("", cleaned)
    return cleaned.strip()


def _build_multipart_curl_args(req_body: str, secret_values: Sequence[str]) -> list[str]:
    """Build deterministic `curl -F` arguments from a multipart/form-data receipt summary."""
    fallback = ["-F", "'file=@upload.bin'"]
    if not req_body.startswith(_MULTIPART_SUMMARY_PREFIX):
        return fallback
    payload_raw = req_body[len(_MULTIPART_SUMMARY_PREFIX) :].strip()
    if not payload_raw:
        return fallback
    try:
        parsed = json.loads(payload_raw)
    except ValueError:
        return fallback
    if not isinstance(parsed, dict):
        return fallback

    args: list[str] = []
    raw_fields = parsed.get("fields")
    if isinstance(raw_fields, list):
        for raw_name in raw_fields:
            if not isinstance(raw_name, str):
                continue
            name = _sanitize_curl_multipart_token(raw_name, secret_values)
            if not name:
                continue
            args.extend(["-F", shlex.quote(f"{name}=<value>")])

    raw_files = parsed.get("files")
    if isinstance(raw_files, list):
        for item in raw_files:
            if not isinstance(item, dict):
                continue
            raw_field = item.get("field")
            field = _sanitize_curl_multipart_token(raw_field, secret_values) if raw_field is not None else ""
            if not field:
                field = "file"
            raw_filename = item.get("filename")
            filename = (
                _sanitize_curl_multipart_token(raw_filename, secret_values) if raw_filename is not None else ""
            )
            if not filename:
                filename = "upload.bin"
            raw_ct = item.get("content_type")
            content_type = _sanitize_curl_multipart_token(raw_ct, secret_values) if raw_ct is not None else ""
            spec = f"{field}=@{filename};type={content_type}" if content_type else f"{field}=@{filename}"
            args.extend(["-F", shlex.quote(spec)])

    return args if args else fallback


def _build_curl_reproduction(
    finding: dict[str, Any],
    proof_receipt: dict[str, Any] | None,
    *,
    base_url: str,
    secret_values: Sequence[str],
) -> tuple[str, bool]:
    """Return `(curl_command, from_receipt)` built deterministically from receipt data."""
    if proof_receipt is not None:
        method = str(proof_receipt.get("method") or finding.get("method") or "GET").strip().upper()
        raw_url = str(proof_receipt.get("url") or "").strip()
        if not raw_url:
            path = str(proof_receipt.get("path") or finding.get("path") or "/")
            query = str(proof_receipt.get("query") or "")
            joined = f"{base_url.rstrip('/')}{path}" if base_url else path
            raw_url = f"{joined}?{query}" if query else joined
        safe_url = _sanitize_url(raw_url, secret_values)

        parts: list[str] = ["curl", "-sS", "-i", "-X", method, shlex.quote(safe_url)]
        safe_headers = _sanitize_header_dict(proof_receipt.get("request_headers"), secret_values)
        req_body = str(proof_receipt.get("request_body") or "")
        is_multipart = _is_multipart_receipt(req_body, safe_headers)
        for k in sorted(safe_headers.keys(), key=lambda x: str(x).lower()):
            name = str(k).strip()
            nl = name.lower()
            if not name or nl in _CURL_SKIP_HEADERS:
                continue
            if is_multipart and nl == "content-type":
                continue
            if nl in {"authorization", "proxy-authorization"}:
                parts.append(_format_curl_header_arg(name, "<REDACTED_AUTH_HEADER>"))
            elif nl == "cookie":
                parts.append(_format_curl_header_arg(name, "<REDACTED_COOKIE>"))
            elif nl in _ALL_SENSITIVE_HEADERS or any(t in nl for t in ("token", "secret", "api-key", "apikey")):
                parts.append(_format_curl_header_arg(name, "<REDACTED_HEADER>"))
            else:
                safe_val = safe_headers[k]
                if safe_val:
                    parts.append(_format_curl_header_arg(name, safe_val))

        if is_multipart:
            parts.extend(_build_multipart_curl_args(req_body, secret_values))
        elif req_body:
            safe_body = _sanitize_text(req_body, secret_values)
            if len(safe_body) > 2000:
                safe_body = safe_body[:2000] + "...<truncated>"
            parts.extend(["--data-raw", shlex.quote(safe_body)])
        return " ".join(parts), True

    # Fallback when proof receipt JSON is missing on disk: use only known endpoint/method.
    method = str(finding.get("method") or "GET").strip().upper()
    raw_url = str(finding.get("url") or finding.get("path") or "/")
    if raw_url.startswith("/") and base_url:
        raw_url = f"{base_url.rstrip('/')}{raw_url}"
    safe_url = _sanitize_url(raw_url, secret_values)
    return f"curl -sS -i -X {method} {shlex.quote(safe_url)}", False


def _extract_run_metadata(artifacts: dict[str, Any], secret_values: Sequence[str]) -> dict[str, Any]:
    manifest = artifacts.get("manifest") or {}
    checkpoint = artifacts.get("checkpoint") or {}
    metrics = artifacts.get("process_metrics") or {}
    receipts = artifacts.get("receipts") or {}

    target = str(manifest.get("target") or "").strip()
    if not target and isinstance(checkpoint.get("surface_frontier"), dict):
        target = str(checkpoint["surface_frontier"].get("base_url") or "").strip()
    if not target and receipts:
        first_rec = next(iter(receipts.values()))
        parsed = urlsplit(str(first_rec.get("url") or ""))
        if parsed.scheme and parsed.netloc:
            target = f"{parsed.scheme}://{parsed.netloc}"
    safe_target = _sanitize_url(target, secret_values) if target else "unknown"

    run_id = str(manifest.get("run_id") or Path(str(artifacts.get("run_dir") or ".")).name or "unknown").strip()
    status = str(manifest.get("status") or checkpoint.get("status") or "unknown").strip()

    ablation_raw = manifest.get("ablation")
    ablation: dict[str, Any] = ablation_raw if isinstance(ablation_raw, dict) else {}
    execution_mode = str(
        manifest.get("execution_mode")
        or ablation.get("execution_mode")
        or checkpoint.get("execution_mode")
        or manifest.get("mode")
        or "agentic"
    ).strip()

    models_raw = manifest.get("models")
    models: dict[str, Any] = models_raw if isinstance(models_raw, dict) else {}
    sharding_raw = manifest.get("sharding_summary")
    sharding_summary: dict[str, Any] | None = sharding_raw if isinstance(sharding_raw, dict) else None
    handoff_raw = manifest.get("handoff_summary")
    handoff_summary: dict[str, Any] | None = handoff_raw if isinstance(handoff_raw, dict) else None

    model_entries: dict[str, str] = {}
    for key in ("worker", "model", "scout", "bootstrap_model", "shard_model"):
        val = models.get(key)
        if val:
            model_entries[key] = str(val)
    if handoff_summary:
        if handoff_summary.get("scout_model") and "scout" not in model_entries:
            model_entries["scout"] = str(handoff_summary["scout_model"])
        if handoff_summary.get("deep_model") and "worker" not in model_entries:
            model_entries["worker"] = str(handoff_summary["deep_model"])
    if sharding_summary:
        if sharding_summary.get("bootstrap_model"):
            model_entries["bootstrap_model"] = str(sharding_summary["bootstrap_model"])
        if sharding_summary.get("shard_model"):
            model_entries["shard_model"] = str(sharding_summary["shard_model"])

    wall_clock = manifest.get("wall_clock_seconds")
    budget_raw = manifest.get("budget")
    budget: dict[str, Any] = budget_raw if isinstance(budget_raw, dict) else {}
    limits_raw = manifest.get("limits")
    limits: dict[str, Any] = limits_raw if isinstance(limits_raw, dict) else {}

    http_used = manifest.get("http_requests_used")
    if http_used is None:
        http_used = manifest.get("target_requests")
    if http_used is None:
        http_used = checkpoint.get("http_used")
    if http_used is None:
        http_used = budget.get("http_used")
    if http_used is None:
        http_used = len(receipts)

    http_limit = manifest.get("http_requests_limit")
    if http_limit is None:
        http_limit = limits.get("http_requests")
    if http_limit is None:
        http_limit = checkpoint.get("http_limit")
    if http_limit is None:
        http_limit = budget.get("http_limit")

    llm_calls = manifest.get("llm_calls")
    if llm_calls is None:
        llm_calls = checkpoint.get("llm_calls")
    if llm_calls is None:
        llm_calls = budget.get("llm_calls")

    token_usage_m = manifest.get("token_usage")
    token_usage_c = checkpoint.get("token_usage")
    token_usage: dict[str, Any] = (
        dict(token_usage_m)
        if isinstance(token_usage_m, dict)
        else (dict(token_usage_c) if isinstance(token_usage_c, dict) else {})
    )
    for opt_key in (
        "total_tokens",
        "prompt_tokens",
        "completion_tokens",
        "cached_prompt_tokens",
        "uncached_prompt_tokens",
        "cache_hit_rate",
        "reasoning_tokens",
    ):
        if opt_key not in token_usage and opt_key in budget:
            token_usage[opt_key] = budget[opt_key]
    if "total_tokens" not in token_usage and isinstance(metrics.get("counts"), dict):
        if metrics["counts"].get("total_tokens") is not None:
            token_usage["total_tokens"] = metrics["counts"]["total_tokens"]

    exp_raw = metrics.get("exposure_rate")
    exp_block: dict[str, Any] = exp_raw if isinstance(exp_raw, dict) else {}
    exposure_ratio_raw = exp_block.get("coverage_ratio")
    exposure_rate = float(exposure_ratio_raw) if isinstance(exposure_ratio_raw, (int, float)) else None

    untested_m = manifest.get("untested_areas")
    untested_c = checkpoint.get("untested_areas")
    raw_untested: list[Any] = (
        untested_m
        if isinstance(untested_m, list)
        else (untested_c if isinstance(untested_c, list) else [])
    )
    untested_areas = [_sanitize_text(str(item), secret_values) for item in raw_untested if str(item).strip()]

    surface_gaps = _extract_surface_gaps(manifest, checkpoint, metrics, secret_values)

    has_gaps = bool(untested_areas) or any(bool(v) for v in surface_gaps.values())
    finished_flag = manifest.get("finished")
    if finished_flag is None:
        finished_flag = checkpoint.get("finished")
    coverage_complete = bool(
        status == "finished"
        and (finished_flag is not False)
        and not has_gaps
        and (exposure_rate is not None and exposure_rate >= 1.0)
    )

    return {
        "target": safe_target,
        "raw_target": target,
        "run_id": run_id,
        "status": status,
        "finished": finished_flag,
        "execution_mode": execution_mode,
        "models": model_entries,
        "wall_clock_seconds": wall_clock,
        "http_used": http_used,
        "http_limit": http_limit,
        "llm_calls": llm_calls,
        "token_usage": token_usage,
        "exposure_block": exp_block,
        "exposure_rate": exposure_rate,
        "sharding_summary": sharding_summary,
        "untested_areas": untested_areas,
        "surface_gaps": surface_gaps,
        "coverage_complete": coverage_complete,
    }


def _extract_surface_gaps(
    manifest: dict[str, Any],
    checkpoint: dict[str, Any],
    metrics: dict[str, Any],
    secret_values: Sequence[str],
) -> dict[str, list[str]]:
    gap_keys = (
        "unvisited_routes",
        "untested_write_ops",
        "untested_cross_actor_objects",
        "unprobed_params",
        "api_parity_untested",
        "untested_actors",
    )
    gaps: dict[str, list[str]] = {k: [] for k in gap_keys}

    sf_dict: dict[str, Any] | None = None
    for container in (manifest, metrics, checkpoint):
        cand = container.get("surface_frontier") or container.get("remaining_frontier")
        if isinstance(cand, dict):
            if any(k in cand for k in gap_keys) and "discovered_routes" not in cand:
                for k in gap_keys:
                    vals = cand.get(k)
                    if isinstance(vals, list):
                        gaps[k] = [_sanitize_text(str(x), secret_values) for x in vals if str(x).strip()]
                return gaps
            sf_dict = cand
            break

    if sf_dict is not None:
        try:
            tracker = SurfaceFrontierTracker.from_dict(sf_dict)
            frontier = tracker.high_value_frontier()
            for k in gap_keys:
                gaps[k] = [_sanitize_text(str(x), secret_values) for x in (frontier.get(k) or []) if str(x).strip()]
        except (ValueError, TypeError, KeyError):
            pass
    return gaps


def _sorted_findings(artifacts: dict[str, Any], secret_values: Sequence[str], *, base_url: str) -> list[dict[str, Any]]:
    raw_findings = artifacts.get("findings") or []
    receipts = artifacts.get("receipts") or {}
    enriched: list[dict[str, Any]] = []

    for idx, f in enumerate(raw_findings):
        if not isinstance(f, dict):
            continue
        cls_type = _normalize_class_type(f.get("class_type"))
        severity = _normalize_severity(f.get("severity"), cls_type)
        meta = _class_metadata(cls_type)
        fid = str(f.get("finding_id") or f"F-{idx + 1:03d}").strip()
        title = _sanitize_text(str(f.get("title") or meta["name"]), secret_values)
        method = str(f.get("method") or "GET").strip().upper()
        raw_endpoint = str(f.get("path") or f.get("url") or "/").strip()
        safe_endpoint = _sanitize_url(raw_endpoint, secret_values) or "/"
        raw_url = str(f.get("url") or raw_endpoint).strip()
        safe_url = _sanitize_url(raw_url, secret_values) or safe_endpoint
        route_template = _sanitize_text(str(f.get("route_template") or safe_endpoint), secret_values)
        actor = str(f.get("actor") or f.get("actor_alias") or "unknown").strip() or "unknown"
        supporting_actors = [str(a) for a in (f.get("supporting_actors") or []) if str(a).strip()]

        verification = str(f.get("oracle_verdict") or f.get("status") or "verified").strip()
        summary = _sanitize_text(str(f.get("summary") or meta["description"]), secret_values)

        proof_ids = [str(x).strip() for x in (f.get("proof_receipt_ids") or []) if str(x).strip()]
        control_ids = [str(x).strip() for x in (f.get("control_receipt_ids") or []) if str(x).strip()]
        clean_replay_id = str(f.get("clean_replay_receipt_id") or "").strip()

        proof_rec = _select_proof_receipt(f, receipts)
        ctrl_recs = _select_control_receipts(f, receipts)

        raw_evidence = str(f.get("evidence") or f.get("evidence_value") or "").strip()
        if not raw_evidence and proof_rec is not None:
            raw_evidence = str(proof_rec.get("body") or "")[:1000]
            if not raw_evidence and isinstance(proof_rec.get("response_headers"), dict):
                raw_evidence = json.dumps(_sanitize_header_dict(proof_rec.get("response_headers"), secret_values))
        if not raw_evidence and isinstance(f.get("evidence_excerpts"), list) and f["evidence_excerpts"]:
            first_ex = f["evidence_excerpts"][0]
            if isinstance(first_ex, dict):
                raw_evidence = str(first_ex.get("excerpt") or "")
        safe_evidence = _sanitize_text(raw_evidence, secret_values)
        if len(safe_evidence) > 1500:
            safe_evidence = safe_evidence[:1500] + "\n...<truncated>"

        # Build comparative control summary from receipts or stored control_excerpts.
        ctrl_notes: list[str] = []
        if ctrl_recs:
            for cre in ctrl_recs:
                c_id = str(cre.get("receipt_id") or "")
                c_actor = str(cre.get("actor") or "control")
                c_method = str(cre.get("method") or method).upper()
                c_url = _sanitize_url(str(cre.get("url") or cre.get("path") or safe_endpoint), secret_values)
                c_status = cre.get("status")
                c_body = _sanitize_text(str(cre.get("body") or "")[:240], secret_values).replace("\n", " ")
                if not c_body and isinstance(cre.get("response_headers"), dict):
                    c_body = json.dumps(_sanitize_header_dict(cre.get("response_headers"), secret_values))[:240]
                note = f"{c_id} (actor=`{c_actor}`): `{c_method} {c_url}` -> HTTP {c_status}"
                if c_body:
                    note += f" | excerpt: `{c_body}`"
                ctrl_notes.append(note)
        elif isinstance(f.get("control_excerpts"), list) and f["control_excerpts"]:
            for cex in f["control_excerpts"]:
                if not isinstance(cex, dict):
                    continue
                c_id = str(cex.get("receipt_id") or "")
                c_actor = str(cex.get("actor") or "control")
                c_method = str(cex.get("method") or method).upper()
                c_url = _sanitize_url(str(cex.get("url") or safe_endpoint), secret_values)
                c_status = cex.get("status")
                c_ex = _sanitize_text(str(cex.get("excerpt") or "")[:240], secret_values).replace("\n", " ")
                note = f"{c_id} (actor=`{c_actor}`): `{c_method} {c_url}` -> HTTP {c_status}"
                if c_ex:
                    note += f" | excerpt: `{c_ex}`"
                ctrl_notes.append(note)

        curl_cmd, curl_from_receipt = _build_curl_reproduction(
            f, proof_rec, base_url=base_url, secret_values=secret_values
        )

        # Clean path for SARIF artifactLocation.uri
        parsed_ep = urlsplit(safe_url if "://" in safe_url else safe_endpoint)
        sanitized_path = parsed_ep.path or "/"
        if parsed_ep.query:
            sanitized_path = f"{sanitized_path}?{parsed_ep.query}"

        enriched.append({
            "index": idx,
            "finding_id": fid,
            "title": title,
            "class_type": cls_type,
            "severity": severity,
            "owasp": meta["owasp"],
            "cwe": meta["cwe"],
            "rule_name": meta["name"],
            "rule_description": meta["description"],
            "method": method,
            "endpoint": safe_endpoint,
            "url": safe_url,
            "sanitized_path": sanitized_path,
            "route_template": route_template,
            "actor": actor,
            "supporting_actors": supporting_actors,
            "verification": verification,
            "summary": summary,
            "evidence": safe_evidence,
            "proof_receipt_ids": proof_ids,
            "control_receipt_ids": control_ids,
            "clean_replay_receipt_id": clean_replay_id,
            "control_notes": ctrl_notes,
            "reproduction_curl": curl_cmd,
            "curl_from_receipt": curl_from_receipt,
            "primary_proof_receipt": str(proof_rec.get("receipt_id") if proof_rec else (proof_ids[0] if proof_ids else "")),
            "primary_control_receipt": control_ids[0] if control_ids else "",
        })

    enriched.sort(key=lambda item: (_SEVERITY_ORDER.get(item["severity"], 99), item["finding_id"], item["index"]))
    return enriched


def _format_token_usage(token_usage: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    total = token_usage.get("total_tokens")
    prompt = token_usage.get("prompt_tokens")
    completion = token_usage.get("completion_tokens")
    if total is not None or prompt is not None or completion is not None:
        lines.append(
            f"| Token Usage | total={total if total is not None else 0}, "
            f"prompt={prompt if prompt is not None else 0}, "
            f"completion={completion if completion is not None else 0} |"
        )
    cache_parts: list[str] = []
    if token_usage.get("cached_prompt_tokens") is not None:
        cache_parts.append(f"cached_prompt_tokens={token_usage['cached_prompt_tokens']}")
    if token_usage.get("uncached_prompt_tokens") is not None:
        cache_parts.append(f"uncached_prompt_tokens={token_usage['uncached_prompt_tokens']}")
    if token_usage.get("cache_hit_rate") is not None:
        rate = token_usage["cache_hit_rate"]
        if isinstance(rate, (int, float)):
            pct = rate * 100.0 if rate <= 1.0 else float(rate)
            cache_parts.append(f"cache_hit_rate={pct:.1f}%")
        else:
            cache_parts.append(f"cache_hit_rate={rate}")
    if token_usage.get("reasoning_tokens") is not None:
        cache_parts.append(f"reasoning_tokens={token_usage['reasoning_tokens']}")
    if cache_parts:
        lines.append(f"| Token Cache & Reasoning | {', '.join(cache_parts)} |")
    return lines


def render_markdown_report(artifacts: dict[str, Any]) -> str:
    """Render a production-grade Markdown security QA report from loaded run artifacts."""
    secret_values = _collect_secret_values(artifacts)
    meta = _extract_run_metadata(artifacts, secret_values)
    findings = _sorted_findings(artifacts, secret_values, base_url=meta["raw_target"])

    sev_counts = Counter(f["severity"] for f in findings)
    severity_summary = ", ".join(
        f"{sev}={sev_counts.get(sev, 0)}" for sev in ("critical", "high", "medium", "low", "info")
    )

    models_str = (
        ", ".join(f"{k}=`{v}`" for k, v in meta["models"].items())
        if meta["models"]
        else "unknown"
    )
    http_str = (
        f"{meta['http_used']} / {meta['http_limit']}"
        if meta["http_limit"] is not None
        else f"{meta['http_used']} / unknown"
    )

    exp = meta["exposure_block"]
    if meta["exposure_rate"] is not None:
        visited = exp.get("unique_endpoints_visited", "?")
        discovered = exp.get("unique_endpoints_discovered", "?")
        exposure_str = f"{meta['exposure_rate']:.2%} ({visited}/{discovered} endpoints)"
        if exp.get("reference_exposure_rate") is not None:
            exposure_str += (
                f"; reference={float(exp['reference_exposure_rate']):.2%} "
                f"({exp.get('reference_matched', '?')}/{exp.get('reference_total', '?')})"
            )
    else:
        exposure_str = "unavailable (no process_metrics.json)"

    lines: list[str] = [
        f"# Security QA Report: {meta['target']}",
        "",
        "## 1. Executive Summary",
        "",
        "| Field | Value |",
        "| :--- | :--- |",
        f"| Target | `{meta['target']}` |",
        f"| Run ID | `{meta['run_id']}` |",
        f"| Status | `{meta['status']}` |",
        f"| Execution Mode | `{meta['execution_mode']}` |",
        f"| Model(s) | {models_str} |",
        f"| Wall-Clock Seconds | {meta['wall_clock_seconds'] if meta['wall_clock_seconds'] is not None else 'unknown'} |",
        f"| HTTP Requests (used / limit) | {http_str} |",
        f"| LLM Calls | {meta['llm_calls'] if meta['llm_calls'] is not None else 'unknown'} |",
        *_format_token_usage(meta["token_usage"]),
        f"| Findings Breakdown | total={len(findings)} ({severity_summary}) |",
        f"| Surface Exposure Rate | {exposure_str} |",
        "",
        "## 2. Findings Summary",
        "",
    ]

    if not findings:
        lines.extend([
            "No verified findings recorded.",
            "",
        ])
    else:
        lines.extend([
            "| ID | Severity | Class | Endpoint | Actor | Verification |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for f in findings:
            ep_display = f"{f['method']} {f['sanitized_path']}"
            lines.append(
                f"| {f['finding_id']} | {f['severity'].upper()} | `{f['class_type']}` | "
                f"`{ep_display}` | `{f['actor']}` | {f['verification']} |"
            )
        lines.append("")

    lines.extend([
        "## 3. Detailed Verified Findings",
        "",
    ])
    if not findings:
        lines.extend([
            "No verified findings to detail for this run.",
            "",
        ])
    else:
        for f in findings:
            lines.extend([
                f"### {f['finding_id']}: {f['title']}",
                "",
                f"- **Severity:** `{f['severity'].upper()}`",
                f"- **Class:** `{f['class_type']}` ({f['rule_name']})",
                f"- **Mapping:** {f['owasp']} | `{f['cwe']}`",
                f"- **Endpoint:** `{f['method']} {f['url']}`",
                f"- **Actor:** `{f['actor']}`"
                + (
                    f" (supporting: {', '.join(f'`{a}`' for a in f['supporting_actors'] if a != f['actor'])})"
                    if any(a != f["actor"] for a in f["supporting_actors"])
                    else ""
                ),
                f"- **Verification:** `{f['verification']}`",
                f"- **Receipts:** proof={', '.join(f'`{r}`' for r in f['proof_receipt_ids']) or 'none'}"
                + (f"; control={', '.join(f'`{r}`' for r in f['control_receipt_ids'])}" if f["control_receipt_ids"] else "")
                + (f"; clean_replay=`{f['clean_replay_receipt_id']}`" if f["clean_replay_receipt_id"] else ""),
                "",
                f"**Summary:** {f['summary']}",
                "",
            ])
            if f["evidence"]:
                lines.extend([
                    "**Redacted Evidence Excerpt:**",
                    "",
                    "```text",
                    f["evidence"],
                    "```",
                    "",
                ])
            if f["control_notes"]:
                lines.append("**Comparative Control Summary:**")
                lines.append("")
                for note in f["control_notes"]:
                    lines.append(f"- {note}")
                lines.append("")

            lines.extend([
                "**Minimal Reproduction (`curl`):**",
                "",
                "```bash",
                f["reproduction_curl"],
                "```",
                "",
            ])
            if not f["curl_from_receipt"]:
                lines.append(
                    "_Note: Proof receipt JSON was unavailable on disk; command reflects recorded method and endpoint only._"
                )
                lines.append("")
            if f["control_notes"]:
                first_ctrl = f["control_notes"][0]
                lines.append(f"**Control Comparison Note:** Proof (`{f['primary_proof_receipt'] or 'n/a'}`) succeeded for actor `{f['actor']}` while comparative control {first_ctrl}.")
                lines.append("")

    sharding = meta["sharding_summary"]
    if isinstance(sharding, dict):
        lines.extend([
            "## 4. Shard Execution Summary",
            "",
        ])
        if sharding.get("fallback_to_monolithic"):
            lines.append(
                f"Monolithic fallback active (`fallback_reason`: `{sharding.get('fallback_reason', 'unknown')}`)."
            )
            lines.append("")
        boot_findings_raw = sharding.get("bootstrap_findings", 0)
        boot_findings_cnt = len(boot_findings_raw) if isinstance(boot_findings_raw, list) else int(boot_findings_raw or 0)
        lines.extend([
            "| Execution Unit | Families | Status | Calls | Tokens | Findings |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
            f"| bootstrap | - | finished/handoff (turns={sharding.get('bootstrap_turns', '?')}) | "
            f"{sharding.get('bootstrap_calls', 0)} | {sharding.get('bootstrap_tokens', 0)} | "
            f"{boot_findings_cnt} |",
        ])
        for shard in sharding.get("shards") or []:
            if not isinstance(shard, dict):
                continue
            fams = ", ".join(str(x) for x in (shard.get("families") or [])) or "-"
            s_findings_raw = shard.get("findings", 0)
            s_findings_cnt = len(s_findings_raw) if isinstance(s_findings_raw, list) else int(s_findings_raw or 0)
            lines.append(
                f"| `{shard.get('shard_id', 'shard')}` | `{fams}` | `{shard.get('status', 'unknown')}` | "
                f"{shard.get('calls', 0)} | {shard.get('tokens', 0)} | {s_findings_cnt} |"
            )
        lines.append("")

    not_tested_section_num = 5 if isinstance(sharding, dict) else 4
    lines.extend([
        f"## {not_tested_section_num}. NOT TESTED & Coverage Visibility",
        "",
        f"> **Closure vs. Coverage:** Run closure status is `{meta['status']}` (`finished={meta['finished']}`), "
        f"which is distinct from complete security coverage (`coverage_complete={meta['coverage_complete']}`).",
        "",
        "### Explicitly Untested Areas (`untested_areas`)",
        "",
    ])
    if meta["untested_areas"]:
        for area in meta["untested_areas"]:
            lines.append(f"- {area}")
    else:
        lines.append("- No explicit `untested_areas` entries recorded in `manifest.json`; review surface coverage metrics and frontier gaps below.")
    lines.append("")

    lines.extend([
        "### Remaining Surface Coverage Gaps",
        "",
        f"- **Exposure Rate:** {exposure_str}",
    ])
    gaps = meta["surface_gaps"]
    gap_labels = (
        ("unvisited_routes", "Unvisited Routes"),
        ("untested_write_ops", "Untested Write Operations"),
        ("untested_cross_actor_objects", "Untested Cross-Actor Objects"),
        ("unprobed_params", "Unprobed Parameters"),
        ("api_parity_untested", "API Parity Untested"),
        ("untested_actors", "Untested Actors"),
    )
    any_frontier_gap = False
    for gkey, glabel in gap_labels:
        items = gaps.get(gkey) or []
        if items:
            any_frontier_gap = True
            preview = ", ".join(f"`{x}`" for x in items[:25])
            extra = f" (+{len(items) - 25} more)" if len(items) > 25 else ""
            lines.append(f"- **{glabel} ({len(items)}):** {preview}{extra}")
    if not any_frontier_gap:
        lines.append("- No remaining `surface_frontier` gaps recorded (or `surface_frontier` was not persisted in run artifacts).")
    lines.append("")

    return "\n".join(lines)


def render_sarif_report(artifacts: dict[str, Any]) -> dict[str, Any]:
    """Render a SARIF 2.1.0 report dictionary from loaded run artifacts."""
    secret_values = _collect_secret_values(artifacts)
    meta = _extract_run_metadata(artifacts, secret_values)
    findings = _sorted_findings(artifacts, secret_values, base_url=meta["raw_target"])

    rules: list[dict[str, Any]] = []
    rule_index_by_class: dict[str, int] = {}

    for f in findings:
        cls_type = f["class_type"]
        if cls_type in rule_index_by_class:
            continue
        cls_meta = _class_metadata(cls_type)
        rule_id = cls_type
        rule_index_by_class[cls_type] = len(rules)
        rules.append({
            "id": rule_id,
            "name": cls_meta["name"],
            "shortDescription": {"text": cls_meta["name"]},
            "fullDescription": {"text": cls_meta["description"]},
            "defaultConfiguration": {
                "level": _sarif_level(str(cls_meta.get("default_severity") or "medium")),
            },
            "properties": {
                "tags": [
                    "security",
                    cls_meta["owasp"],
                    cls_meta["cwe"],
                    cls_type,
                ],
                "owasp": cls_meta["owasp"],
                "cwe": cls_meta["cwe"],
            },
        })

    results: list[dict[str, Any]] = []
    for f in findings:
        cls_type = f["class_type"]
        rule_idx = rule_index_by_class[cls_type]
        canonical_key = f"{cls_type}:{f['method']}:{f['route_template']}"
        line_hash = hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()[:16]

        msg_parts = [f"{f['finding_id']} [{f['severity'].upper()}] {f['title']} at {f['method']} {f['sanitized_path']} (actor={f['actor']})"]
        if f["summary"]:
            msg_parts.append(f["summary"])
        if f["evidence"]:
            msg_parts.append(f"Evidence: {f['evidence'][:400]}")
        message_text = _sanitize_text(" — ".join(msg_parts), secret_values)

        results.append({
            "ruleId": cls_type,
            "ruleIndex": rule_idx,
            "level": _sarif_level(f["severity"]),
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f["sanitized_path"],
                        }
                    },
                    "logicalLocations": [
                        {
                            "name": f["sanitized_path"],
                            "fullyQualifiedName": f"{f['method']} {f['sanitized_path']}",
                            "kind": "endpoint",
                        }
                    ],
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": line_hash,
                "canonicalKey": canonical_key,
            },
            "properties": {
                "finding_id": f["finding_id"],
                "severity": f["severity"],
                "actor": f["actor"],
                "method": f["method"],
                "endpoint": f["sanitized_path"],
                "owasp": f["owasp"],
                "cwe": f["cwe"],
                "proof_receipt": f["primary_proof_receipt"],
                "proof_receipt_ids": f["proof_receipt_ids"],
                "control_receipt": f["primary_control_receipt"],
                "control_receipt_ids": f["control_receipt_ids"],
                "verification": f["verification"],
                "reproduction_curl": f["reproduction_curl"],
            },
        })

    invocation: dict[str, Any] = {
        "executionSuccessful": meta["status"] in _SUCCESSFUL_STATUSES,
        "properties": {
            "run_id": meta["run_id"],
            "target": meta["target"],
            "status": meta["status"],
            "exposure_rate": meta["exposure_rate"] if meta["exposure_rate"] is not None else 0.0,
            "untested_areas": meta["untested_areas"],
            "coverage_complete": meta["coverage_complete"],
            "surface_gaps": meta["surface_gaps"],
        },
    }

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "semanticVersion": TOOL_SEMANTIC_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [invocation],
            }
        ],
    }


def generate_run_reports(
    run_dir: Path,
    *,
    output_dir: Path | None = None,
    formats: Sequence[str] = ("markdown", "sarif"),
) -> dict[str, Any]:
    """Generate `report.md` and/or `report.sarif` for a run directory and return a compact summary."""
    resolved_run = Path(run_dir).expanduser().resolve()
    artifacts = load_run_artifacts(resolved_run)
    dest_dir = Path(output_dir).expanduser().resolve() if output_dir is not None else resolved_run
    dest_dir.mkdir(parents=True, exist_ok=True)

    norm_formats = {str(fmt).strip().lower() for fmt in formats if str(fmt).strip()}
    if "all" in norm_formats:
        norm_formats = {"markdown", "sarif"}
    want_md = bool(norm_formats & {"markdown", "md"})
    want_sarif = "sarif" in norm_formats

    md_path: Path | None = None
    sarif_path: Path | None = None

    if want_md:
        md_text = render_markdown_report(artifacts)
        md_path = dest_dir / "report.md"
        _atomic_write_text(md_path, md_text)

    if want_sarif:
        sarif_doc = render_sarif_report(artifacts)
        sarif_path = dest_dir / "report.sarif"
        _atomic_write_text(
            sarif_path,
            json.dumps(sarif_doc, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        )

    secret_values = _collect_secret_values(artifacts)
    meta = _extract_run_metadata(artifacts, secret_values)

    return {
        "status": meta["status"],
        "run_dir": str(resolved_run),
        "findings_count": len(artifacts.get("findings") or []),
        "markdown_path": str(md_path) if md_path is not None else None,
        "sarif_path": str(sarif_path) if sarif_path is not None else None,
        "untested_count": len(meta["untested_areas"]),
        "exposure_rate": meta["exposure_rate"],
    }


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for generating Markdown and SARIF reports for an agentic run."""
    parser = argparse.ArgumentParser(
        prog="agentic_report",
        description="Generate Markdown (report.md) and SARIF 2.1.0 (report.sarif) QA reports for an agentic run.",
    )
    parser.add_argument("run_dir", type=Path, help="Completed (or partial) agentic run directory")
    parser.add_argument("--output-dir", type=Path, default=None, help="Output directory (defaults to run_dir)")
    parser.add_argument(
        "--format",
        choices=("all", "markdown", "sarif"),
        default="all",
        help="Report format(s) to generate",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    formats: tuple[str, ...]
    if args.format == "all":
        formats = ("markdown", "sarif")
    elif args.format == "markdown":
        formats = ("markdown",)
    else:
        formats = ("sarif",)

    try:
        summary = generate_run_reports(
            args.run_dir,
            output_dir=args.output_dir,
            formats=formats,
        )
    except FileNotFoundError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    except OSError as exc:
        print(json.dumps({"error": f"failed to generate reports: {exc}"}), file=sys.stderr)
        return 1

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
