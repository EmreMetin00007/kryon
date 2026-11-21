"""General-purpose investigation and QA verification tools with anti-hallucination verification."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
from difflib import SequenceMatcher
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from agentic_http import (
    AgenticHTTPClient,
    BudgetExhaustedError,
    MethodNotAllowedError,
    ScopeViolationError,
    is_static_asset_url,
)
from agentic_oob import LoopbackCallbackServer
from agentic_oracle import (
    check_bola_false_positive,
    find_persistent_render_get_receipt,
    is_html_receipt,
    is_persistent_read_path_related,
    receipt_body_contains_verbatim,
)
from agentic_receipts import DEFAULT_PREVIEW_CHARS, ReceiptStore
from agentic_surface import SurfaceFrontierTracker

MAX_PROOF_EXCERPT_CHARS = 4096
MAX_CONTROL_EXCERPT_CHARS = 1024
_RECORD_OWNER_KEYS = (
    "owner",
    "owner_id",
    "owner_alias",
    "requested_by",
    "created_by",
    "author",
    "user",
    "username",
    "actor",
    "assigned_to",
)
_RECORD_TENANT_KEYS = (
    "tenant",
    "tenant_slug",
    "tenant_id",
    "org",
    "organization",
    "company",
)
_ACTOR_IDENTITY_HEADERS = ("x-actor-alias", "x-authenticated-user", "x-user")
_PUBLIC_LANDING_PATHS = frozenset({"/", "/login", "/signin", "/sign-in", "/health", "/healthz"})

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SURFACE_CORE_PARENT = _REPO_ROOT / "mcp-servers" / "mcp-memory-server"
if str(_SURFACE_CORE_PARENT) not in sys.path:
    sys.path.insert(0, str(_SURFACE_CORE_PARENT))

from cco_surface_core.extract import (  # noqa: E402
    extract_html,
    extract_inline_scripts,
    extract_js,
    extract_js_calls,
    extract_json_hypermedia,
    extract_robots,
    extract_sitemap,
    extract_spa_routes,
    find_spec_urls,
)
from cco_surface_core.openapi import LocalSchema  # noqa: E402

_SKIP_REPLAY_HEADERS = frozenset({
    "authorization",
    "cookie",
    "x-csrf-token",
    "x-xsrf-token",
    "content-length",
    "host",
})
_TRIVIAL_EVIDENCE = frozenset({"200", "201", "204", "302", "ok", "true", "false", "success", "null", "none"})
_ID_VALUE_RE = re.compile(
    r"\b(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z]+-[a-z0-9_-]{3,24}|\d{1,10})\b",
    re.I,
)
_ID_KEY_HINTS = ("id", "uuid", "code", "tag", "serial", "slug", "key", "ref", "number")
_SENSITIVE_JSON_EXACT_KEYS = frozenset({
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "auth_key",
    "session_key",
    "signing_key",
    "encryption_key",
    "password",
    "passwd",
    "credential",
    "credentials",
    "audit_hash",
    "hmac",
    "signature",
    "bearer",
    "jwt",
    "ssn",
    "tax_id",
    "iban",
    "pin_code",
})
_SENSITIVE_JSON_KEY_PREFIXES = (
    "private_",
    "internal_",
    "confidential_",
    "restricted_",
    "secret_",
    "sensitive_",
)
_SENSITIVE_JSON_KEY_SUFFIXES = (
    "_secret",
    "_token",
    "_api_key",
    "_apikey",
    "_key",
    "_hash",
    "_password",
    "_credential",
    "_credentials",
    "_signature",
)
_IGNORED_EVIDENCE_JSON_KEYS = frozenset({
    "timestamp",
    "created_at",
    "updated_at",
    "expires_at",
    "date",
    "time",
    "request_id",
    "trace_id",
    "correlation_id",
    "span_id",
    "nonce",
    "csrf_token",
    "csrf",
    "xsrf_token",
    "etag",
    "iat",
    "exp",
    "jti",
    "token_type",
    "hash_alg",
    "algorithm",
})
_IGNORED_EVIDENCE_KEY_PREFIXES = ("is_", "has_", "can_")
_IGNORED_EVIDENCE_KEY_SUFFIXES = ("_count", "_type", "_enabled", "_alg", "_format", "_url", "_path", "_uri")
_ISO_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$"
)
_UUID_FULL_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
_JWT_FULL_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}$")
_HEX_SEGMENT_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
_RAW_TOKEN_SCAN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-.:/+=$]{6,128}[A-Za-z0-9=]")
_LOWER_SLUG_YEAR_RE = re.compile(r"^[a-z]+(?:-[a-z]+)*-\d{4}$")
_SQLI_EVIDENCE_HINTS = ("union select", "' or ", "\" or ", "1=1", "sql syntax", "sqlite", "postgresql", "mysql")
_XSS_EVENT_HINTS = ("onload=", "onerror=", "onfocus=", "onmouseover=", "onclick=", "javascript:")
_HIGH_SPEC_THRESHOLD = 60

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send scope-locked HTTP request as actor (or 'anon'). GETs cached unless force=true.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "description": "HTTP method (defaults GET; POST if body)."},
                    "url": {"type": "string", "description": "Path or same-origin URL."},
                    "actor": {"type": "string", "description": "Actor alias or 'anon'."},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Extra headers."},
                    "query": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Query params."},
                    "json_body": {"description": "JSON body."},
                    "base_receipt_id": {"type": "string", "description": "GET receipt_id for base JSON."},
                    "json_merge": {"type": "object", "description": "JSON keys to deep-merge."},
                    "form_body": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Form body."},
                    "raw_body": {"type": "string", "description": "Raw body."},
                    "force": {"type": "boolean", "description": "Bypass GET cache."},
                    "save_session_as": {"type": "string", "description": "Alias for captured session."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_receipt",
            "description": "Read stored receipt body at 0 HTTP cost via offset/limit or regex.",
            "parameters": {
                "type": "object",
                "properties": {
                    "receipt_id": {"type": "string", "description": "Receipt ID."},
                    "offset": {"type": "integer", "description": "Start offset (default 0)."},
                    "limit": {"type": "integer", "description": "Max chars (default 4000)."},
                    "regex": {"type": "string", "description": "Regex filter."},
                },
                "required": ["receipt_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "replay_as",
            "description": "Replay a receipt_id as another actor or with overrides; returns diff.",
            "parameters": {
                "type": "object",
                "properties": {
                    "receipt_id": {"type": "string", "description": "Baseline receipt_id."},
                    "actor": {"type": "string", "description": "Target actor or 'anon'."},
                    "method": {"type": "string", "description": "Method override."},
                    "url": {"type": "string", "description": "URL/path override."},
                    "query_overrides": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Query overrides."},
                    "header_overrides": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Header overrides."},
                    "base_receipt_id": {"type": "string", "description": "GET receipt_id for base JSON."},
                    "json_merge": {"type": "object", "description": "JSON keys to deep-merge."},
                    "json_overrides": {"type": "object", "description": "JSON fields to merge."},
                    "force": {"type": "boolean", "description": "Bypass GET cache."},
                },
                "required": ["receipt_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_surface",
            "description": "Extract links, forms, JS routes, OpenAPI ops, and IDs from a receipt_id at 0 HTTP cost.",
            "parameters": {
                "type": "object",
                "properties": {
                    "receipt_id": {"type": "string", "description": "Stored receipt_id."},
                },
                "required": ["receipt_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "notebook",
            "description": "Maintain investigation notebook (surface_notes, hypotheses, notes). 0 HTTP cost.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "update", "add_hypothesis", "update_hypothesis", "add_note"],
                        "description": "Notebook action.",
                    },
                    "surface_notes": {"type": "string", "description": "Surface summary."},
                    "hypothesis": {"type": "object", "description": "{id,target,vuln_class,status,notes}."},
                    "note": {"type": "string", "description": "Note text."},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "callback_listener",
            "description": "Local loopback OOB callback URLs (create_url/poll) for SSRF/webhook checks. 0 HTTP cost.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["create_url", "poll"], "description": "create_url or poll."},
                    "label": {"type": "string", "description": "Callback label."},
                    "token": {"type": "string", "description": "Token (empty=all)."},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "concurrent_check",
            "description": "Send 2-5 synchronized parallel requests to test idempotency and race conditions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Path or same-origin URL."},
                    "method": {"type": "string", "description": "HTTP method."},
                    "actor": {"type": "string", "description": "Actor alias or 'anon'."},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Extra headers."},
                    "query": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Query params."},
                    "json_body": {"description": "JSON body."},
                    "form_body": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Form body."},
                    "raw_body": {"type": "string", "description": "Raw body."},
                    "count": {"type": "integer", "description": "Parallel count (2-5, default 3)."},
                },
                "required": ["url", "method", "actor"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "record_finding",
            "description": "Record a verified finding backed by proof_receipt_ids, control_receipt_ids, and evidence_value.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Title."},
                    "class_type": {
                        "type": "string",
                        "description": "Class: bola, tenant_isolation, bfla, auth_bypass, mass_assignment, reflected_xss, stored_xss, sqli_read, sqli, open_redirect, csrf, ssti, xxe, ssrf, path_traversal, info_disclosure, business_logic, race_condition, other.",
                    },
                    "method": {"type": "string", "description": "HTTP method."},
                    "url": {"type": "string", "description": "Endpoint path or URL."},
                    "actor_alias": {"type": "string", "description": "Proof actor."},
                    "proof_receipt_ids": {"type": "array", "items": {"type": "string"}, "description": "Proof IDs."},
                    "control_receipt_ids": {"type": "array", "items": {"type": "string"}, "description": "Control IDs."},
                    "evidence_value": {"type": "string", "description": "Observed evidence."},
                    "summary": {"type": "string", "description": "Summary."},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                },
                "required": [
                    "title",
                    "class_type",
                    "method",
                    "url",
                    "actor_alias",
                    "proof_receipt_ids",
                    "control_receipt_ids",
                    "evidence_value",
                    "summary",
                ],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "Complete investigation and summarize findings plus untested areas.",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string", "description": "Final summary."},
                    "untested_areas": {"type": "array", "items": {"type": "string"}, "description": "Untested areas."},
                },
                "required": ["summary"],
            },
        },
    },
]


def wrap_untrusted(payload: Any) -> str:
    """Wrap target-derived content in explicit prompt-injection isolation markers."""
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return (
        "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
        f"{text}\n"
        "<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    )


def _atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".tool-", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _norm_path(url_or_path: str) -> str:
    parsed = urlsplit(str(url_or_path or ""))
    path = parsed.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return path.lower()


_UUID_SEG_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_ID_SEG_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_PREFIXED_ID_SEG_RE = re.compile(r"^[a-z]{1,12}[-_][0-9a-z_-]*\d[0-9a-z_-]*$", re.I)
_TEMPLATE_SEG_RE = re.compile(r"^\{[^}]+\}$")

_CLASS_ALIASES = {
    "idor": "bola",
    "broken_object_level_authorization": "bola",
    "broken_function_level_authorization": "bfla",
    "privilege_escalation": "bfla",
    "unauthenticated_access": "auth_bypass",
    "authentication_bypass": "auth_bypass",
    "missing_auth": "auth_bypass",
    "missing_authentication": "auth_bypass",
    "cross_tenant": "tenant_isolation",
    "cross_tenant_access": "tenant_isolation",
    "tenant_bypass": "tenant_isolation",
    "field_binding": "mass_assignment",
    "overposting": "mass_assignment",
    "unvalidated_redirect": "open_redirect",
    "redirect": "open_redirect",
    "sql_injection": "sqli",
    "server_side_request_forgery": "ssrf",
    "toctou": "race_condition",
    "race": "race_condition",
    "concurrency": "race_condition",
}
_READ_SQLI_HINTS = ("order by", "order_by", "sort", "read", "differential", "boolean", "error-based", "error based", "case when")
_ADMIN_ROLE_TOKENS = ("admin", "superadmin", "administrator", "root", "superuser", "sysadmin", "staff")
_READONLY_ROLES = frozenset({"viewer", "readonly", "read_only", "guest", "auditor", "observer"})
_PERSISTENT_VULN_CLASSES = frozenset({"stored_xss", "mass_assignment", "ssti"})
_MUTATING_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _deep_merge_json(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge `patch` into `base`, preserving existing unpatched keys."""
    merged = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_json(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def normalize_route_template(url_or_path: str) -> str:
    """Normalize concrete resource ID path segments into `{id}` route templates."""
    parsed = urlsplit(str(url_or_path or ""))
    path = (parsed.path or "/").strip()
    if len(path) > 1:
        path = path.rstrip("/")
    if path == "/":
        return "/"
    segments: list[str] = []
    for seg in path.split("/"):
        if not seg:
            continue
        low = seg.lower()
        if (
            low.isdigit()
            or _UUID_SEG_RE.fullmatch(low)
            or _HEX_ID_SEG_RE.fullmatch(low)
            or _PREFIXED_ID_SEG_RE.fullmatch(low)
            or _TEMPLATE_SEG_RE.fullmatch(low)
        ):
            segments.append("{id}")
        else:
            segments.append(low)
    return "/" + "/".join(segments)


def normalize_vuln_class(
    class_type: str,
    *,
    method: str = "",
    title: str = "",
    summary: str = "",
) -> str:
    """Normalize OWASP vulnerability class aliases into canonical class names."""
    raw = str(class_type or "").strip().lower().replace("-", "_").replace(" ", "_")
    norm = _CLASS_ALIASES.get(raw, raw)
    context_text = f"{title} {summary}".lower()
    if norm == "xss":
        return "stored_xss" if "stored" in context_text else "reflected_xss"
    if norm == "sqli":
        if str(method or "").upper() in {"GET", "HEAD"} or any(h in context_text for h in _READ_SQLI_HINTS):
            return "sqli_read"
    return norm


def _is_admin_role(role: str) -> bool:
    low = str(role or "").strip().lower()
    return any(tok in low for tok in _ADMIN_ROLE_TOKENS)


def _is_readonly_role(role: str) -> bool:
    return str(role or "").strip().lower() in _READONLY_ROLES


def build_receipt_excerpt(
    receipt: dict[str, Any],
    evidence_value: str = "",
    *,
    max_chars: int = MAX_PROOF_EXCERPT_CHARS,
) -> str:
    """Build a bounded, redacted proof/control receipt excerpt (up to 4096 chars)."""
    body = str(receipt.get("body") or "")
    loc = str(receipt.get("redirect_location") or "")
    if loc and not body:
        full_text = f"Location: {loc}"
    elif loc and body:
        full_text = f"Location: {loc}\n{body}"
    else:
        full_text = body
    if not full_text:
        headers_text = json.dumps(receipt.get("response_headers") or {}, ensure_ascii=False)
        return headers_text[:max_chars]
    if len(full_text) <= max_chars:
        return full_text

    needle = str(evidence_value or "").strip()
    if needle:
        last_idx = full_text.rfind(needle)
        if last_idx == -1:
            last_idx = full_text.lower().rfind(needle.lower())
        if last_idx != -1 and last_idx + len(needle) > max_chars:
            head = full_text[:1200]
            tail_budget = max(400, max_chars - len(head) - 25)
            win_start = max(1200, min(last_idx - 300, len(full_text) - tail_budget))
            return f"{head}\n...[truncated]...\n{full_text[win_start : win_start + tail_budget]}"
    return full_text[:max_chars]


def compose_finding_evidence(
    primary_proof: dict[str, Any],
    all_proofs: list[dict[str, Any]],
    control_receipts: list[dict[str, Any]],
    evidence_value: str = "",
    *,
    max_proof_chars: int = MAX_PROOF_EXCERPT_CHARS,
    max_control_chars: int = MAX_CONTROL_EXCERPT_CHARS,
) -> str:
    """Compose primary proof excerpt (up to 4096 chars) plus secondary proof/control excerpts."""
    primary_ex = build_receipt_excerpt(primary_proof, evidence_value, max_chars=max_proof_chars)
    parts: list[str] = [primary_ex]
    seen_sha = {primary_proof.get("response_sha256")}
    added_sec = 0
    for r in all_proofs:
        if r.get("receipt_id") == primary_proof.get("receipt_id"):
            continue
        r_sha = r.get("response_sha256")
        if r_sha in seen_sha and r.get("url") == primary_proof.get("url"):
            continue
        seen_sha.add(r_sha)
        sec_ex = build_receipt_excerpt(r, evidence_value, max_chars=min(2048, max_proof_chars))
        parts.append(
            f"---[proof:{r.get('receipt_id')} actor={r.get('actor')} status={r.get('status')}]---\n{sec_ex}"
        )
        added_sec += 1
        if added_sec >= 2:
            break
    if control_receipts:
        c = control_receipts[0]
        ctrl_ex = build_receipt_excerpt(c, "", max_chars=max_control_chars)
        parts.append(
            f"---[control:{c.get('receipt_id')} actor={c.get('actor')} status={c.get('status')}]---\n{ctrl_ex}"
        )
    return "\n".join(parts)


def _extract_record_owner_and_tenant(
    receipt: dict[str, Any],
    actor_meta_map: dict[str, dict[str, str]],
) -> tuple[str, str]:
    """Extract explicit record owner alias and tenant from a JSON response body if present."""
    body = str(receipt.get("body") or "").strip()
    if not body.startswith("{"):
        return "", ""
    try:
        parsed = json.loads(body)
    except ValueError:
        return "", ""
    if not isinstance(parsed, dict):
        return "", ""

    owner_actor = ""
    for key in _RECORD_OWNER_KEYS:
        val = parsed.get(key)
        if isinstance(val, str):
            clean = val.strip()
            if clean and clean != "anon" and (clean in actor_meta_map or not actor_meta_map):
                owner_actor = clean
                break

    record_tenant = ""
    for key in _RECORD_TENANT_KEYS:
        val = parsed.get(key)
        if isinstance(val, str) and val.strip():
            record_tenant = val.strip().lower()
            break
    if not record_tenant and owner_actor and owner_actor in actor_meta_map:
        record_tenant = str(actor_meta_map[owner_actor].get("tenant") or "").lower()
    return owner_actor, record_tenant


def _is_genuine_anon_2xx(
    receipt: dict[str, Any],
    actor_meta_map: dict[str, dict[str, str]] | None = None,
) -> bool:
    """Return True only if receipt was executed by 'anon', returned substantive 2xx, and has no leaked auth identity."""
    if str(receipt.get("actor") or "").strip() != "anon":
        return False
    status = int(receipt.get("status") or 0)
    if not (200 <= status < 300):
        return False
    body = str(receipt.get("body") or "").strip()
    if len(body) <= 2:
        return False
    path = _norm_path(str(receipt.get("url") or receipt.get("path") or ""))
    ctype = str(receipt.get("content_type") or "").lower()
    if "html" in ctype and path in _PUBLIC_LANDING_PATHS:
        return False
    resp_headers = {str(k).lower(): str(v).strip() for k, v in (receipt.get("response_headers") or {}).items()}
    known_non_anon = {a for a in (actor_meta_map or {}) if a and a != "anon"}
    for hname in _ACTOR_IDENTITY_HEADERS:
        hval = resp_headers.get(hname, "")
        if hval and hval != "anon" and (hval in known_non_anon or not known_non_anon):
            return False
    return True


def _infer_owner_actor(
    proof_receipts: list[dict[str, Any]],
    control_receipts: list[dict[str, Any]],
    *,
    receipt_store: ReceiptStore | None = None,
    route_template: str = "",
    evidence_value: str = "",
    actor_meta_map: dict[str, dict[str, str]] | None = None,
    target_path: str = "",
) -> str:
    """Infer the resource owner actor from JSON body metadata, control receipts, or earliest discovery receipt."""
    meta_map = actor_meta_map or {}
    # 1. Explicit owner field in the JSON record itself
    for rec in [*proof_receipts, *control_receipts]:
        explicit_owner, _ = _extract_record_owner_and_tenant(rec, meta_map)
        if explicit_owner:
            return explicit_owner

    proof_actors = {str(r.get("actor") or "") for r in proof_receipts}
    norm_target = _norm_path(target_path or (proof_receipts[0].get("url", "") if proof_receipts else ""))

    # 2. Control receipt by a different authenticated actor returning 2xx
    for c in control_receipts:
        actor = str(c.get("actor") or "")
        if actor and actor != "anon" and actor not in proof_actors and 200 <= int(c.get("status", 0)) < 300:
            return actor

    # 3. Chronological scan of receipt_store for earliest authenticated discovery/baseline GET of this concrete object
    if receipt_store is not None:
        ev = evidence_value.strip()
        target_id_seg = norm_target.rsplit("/", 1)[-1] if "/" in norm_target else ""
        first_exact_actor = ""
        first_template_actor = ""
        for rid in receipt_store.list_ids():
            try:
                rec = receipt_store.get(rid)
            except (KeyError, ValueError):
                continue
            actor = str(rec.get("actor") or "")
            if not actor or actor == "anon":
                continue
            if not (200 <= int(rec.get("status", 0)) < 300) or str(rec.get("method") or "").upper() != "GET":
                continue
            explicit_owner, _ = _extract_record_owner_and_tenant(rec, meta_map)
            rec_path = _norm_path(str(rec.get("url") or ""))
            if explicit_owner and rec_path == norm_target:
                return explicit_owner
            if norm_target and rec_path == norm_target and not first_exact_actor:
                first_exact_actor = actor
            body_str = str(rec.get("body") or "")
            if target_id_seg and len(target_id_seg) >= 3 and f'"{target_id_seg}"' in body_str and actor not in proof_actors:
                return actor
            if ev and len(ev) >= 4 and ev in body_str and actor not in proof_actors:
                return actor
            rec_tmpl = normalize_route_template(str(rec.get("url") or ""))
            if route_template and rec_tmpl == route_template and actor not in proof_actors and not first_template_actor:
                first_template_actor = actor
        same_target_actors = {
            str(r.get("actor") or "")
            for r in proof_receipts
            if _norm_path(str(r.get("url") or "")) == norm_target
        }
        if first_exact_actor and (len(same_target_actors) > 1 or first_exact_actor not in proof_actors):
            return first_exact_actor
        if first_template_actor:
            return first_template_actor
    return ""


def _actor_priority_key(
    canonical_class: str,
    actor_alias: str,
    *,
    actor_meta_map: dict[str, dict[str, str]],
    owner_actor: str = "",
) -> tuple[int, int, str]:
    """Return sort key (lower = higher priority) for primary-actor selection."""
    meta = actor_meta_map.get(actor_alias) or {}
    role = str(meta.get("role") or ("anonymous" if actor_alias == "anon" else "member")).lower()
    tenant = str(meta.get("tenant") or "").lower()
    is_anon = actor_alias == "anon"
    is_admin = _is_admin_role(role)
    is_ro = _is_readonly_role(role)

    if canonical_class == "auth_bypass":
        tier = 0 if is_anon else (2 if is_admin else 1)
        return (tier, 0, actor_alias)

    if canonical_class == "bfla":
        # Non-admin authenticated actor preferred (lowest-privilege read-only/viewer first proves widest BFLA impact); admin last.
        tier = 1 if is_anon else (2 if is_admin else 0)
        return (tier, 0 if is_ro else 1, actor_alias)

    if canonical_class == "bola":
        if is_anon:
            return (4, 0, actor_alias)
        if owner_actor and actor_alias == owner_actor:
            return (5, 0, actor_alias)
        if is_admin:
            return (3, 0, actor_alias)
        owner_meta = actor_meta_map.get(owner_actor) or {}
        owner_tenant = str(owner_meta.get("tenant") or "").lower()
        owner_role = str(owner_meta.get("role") or "").lower()
        if owner_meta:
            if owner_tenant and tenant == owner_tenant and owner_role and role == owner_role:
                return (0, 0, actor_alias)
            if owner_tenant and tenant == owner_tenant:
                return (1, 1 if is_ro else 0, actor_alias)
            return (2, 1 if is_ro else 0, actor_alias)
        return (1 if is_ro else 0, 0, actor_alias)

    if canonical_class == "tenant_isolation":
        if is_anon:
            return (3, 0, actor_alias)
        if owner_actor and actor_alias == owner_actor:
            return (4, 0, actor_alias)
        owner_meta = actor_meta_map.get(owner_actor) or {}
        owner_tenant = str(owner_meta.get("tenant") or "").lower()
        if owner_tenant and tenant and tenant != owner_tenant:
            return (1 if is_admin else 0, 1 if is_ro else 0, actor_alias)
        if owner_tenant and tenant == owner_tenant:
            return (2, 0, actor_alias)
        return (1 if is_admin else 0, 1 if is_ro else 0, actor_alias)

    if canonical_class == "mass_assignment":
        tier = 2 if is_admin else (1 if is_anon else 0)
        return (tier, 1 if is_ro else 0, actor_alias)

    # Injection / open_redirect / info_disclosure / other: unauthenticated or non-admin first.
    tier = 0 if is_anon else (2 if is_admin else 1)
    return (tier, 0, actor_alias)


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())


def _is_sensitive_json_key(key_name: str) -> bool:
    """Return True if a JSON key name indicates a secret, token, private, or internal field."""
    lk = str(key_name or "").strip().lower()
    if not lk or lk in _IGNORED_EVIDENCE_JSON_KEYS:
        return False
    if lk.startswith(_IGNORED_EVIDENCE_KEY_PREFIXES) or lk.endswith(_IGNORED_EVIDENCE_KEY_SUFFIXES):
        return False
    if lk in _SENSITIVE_JSON_EXACT_KEYS:
        return True
    if lk.startswith(_SENSITIVE_JSON_KEY_PREFIXES) or lk.endswith(_SENSITIVE_JSON_KEY_SUFFIXES):
        return True
    return False


def _is_ignored_json_key(key_name: str) -> bool:
    """Return True for ephemeral or non-secret metadata JSON keys."""
    lk = str(key_name or "").strip().lower()
    if not lk:
        return False
    return (
        lk in _IGNORED_EVIDENCE_JSON_KEYS
        or lk.startswith(_IGNORED_EVIDENCE_KEY_PREFIXES)
        or lk.endswith(_IGNORED_EVIDENCE_KEY_SUFFIXES)
    )


def _is_hex_secret_token(val: str) -> tuple[bool, int]:
    """Detect pure or prefixed/segmented hex tokens (>= 8 hex chars with digits+alpha or >= 16 hex)."""
    if not val or any(ch.isspace() for ch in val):
        return False, 0
    for seg in (val, *re.split(r"[-_.:/+]", val)):
        if not _HEX_SEGMENT_RE.fullmatch(seg):
            continue
        has_digit = any(ch.isdigit() for ch in seg)
        has_alpha = any("a" <= ch.lower() <= "f" for ch in seg)
        if (has_digit and has_alpha) or len(seg) >= 16:
            return True, (85 if len(seg) >= 12 or len(val) >= 14 else 78)
    return False, 0


def _is_high_entropy_token(val: str, *, strict_extraction: bool = False) -> tuple[bool, int]:
    """Detect cryptographic/random high-entropy tokens in a lab-agnostic manner."""
    if not val or any(ch.isspace() for ch in val):
        return False, 0
    if _JWT_FULL_RE.fullmatch(val):
        return True, 95
    if _UUID_FULL_RE.fullmatch(val):
        return True, 80
    is_hex, hex_score = _is_hex_secret_token(val)
    if is_hex:
        return True, hex_score
    if len(val) < 14 or _LOWER_SLUG_YEAR_RE.fullmatch(val):
        return False, 0
    has_lower = any("a" <= ch <= "z" for ch in val)
    has_upper = any("A" <= ch <= "Z" for ch in val)
    has_digit = any(ch.isdigit() for ch in val)
    has_sym = any(ch in "-_.:/+=$" for ch in val)
    num_classes = sum((has_lower, has_upper, has_digit, has_sym))
    unique_chars = len(set(val))
    entropy = _shannon_entropy(val)
    if strict_extraction:
        if unique_chars < 7 or entropy < 2.8:
            return False, 0
        if has_upper and has_lower and has_digit:
            return True, (80 if len(val) >= 18 else 75)
        digit_cnt = sum(1 for ch in val if ch.isdigit())
        if num_classes >= 3 and has_digit and digit_cnt >= 4:
            return True, (78 if len(val) >= 18 else 72)
        return False, 0
    if unique_chars >= 6 and entropy >= 2.7 and num_classes >= 3 and (has_digit or (has_lower and has_upper)):
        return True, (80 if len(val) >= 18 else 75)
    return False, 0


def score_evidence_value(value: str, *, key_name: str = "") -> int:
    """Score evidence specificity on a 0-100 scale without lab-specific rules."""
    val = str(value or "").strip()
    if not val or len(val) < 3 or val.lower() in _TRIVIAL_EVIDENCE:
        return 0
    if _ISO_TIMESTAMP_RE.fullmatch(val):
        return 5
    low = val.lower()
    if ("<" in val and ">" in val) or any(h in low for h in _XSS_EVENT_HINTS):
        return 95
    if low.startswith(("http://", "https://")) and urlsplit(val).netloc:
        return 90
    if any(h in low for h in _SQLI_EVIDENCE_HINTS):
        return 85
    _, token_score = _is_high_entropy_token(val, strict_extraction=False)
    if _is_sensitive_json_key(key_name):
        if len(val) >= 4 and not val.startswith("/") and not low.startswith(("http://", "https://")):
            if token_score > 0:
                return min(100, token_score + 10)
            return 65
    if token_score > 0:
        return token_score
    if len(val) < 10:
        return 15 if any(ch.isspace() for ch in val) or val.isalpha() else 22
    if len(val) < 14 and "-" in val and any(ch.isdigit() for ch in val):
        return 25
    return 20


def _build_control_haystacks(control_receipts: list[dict[str, Any]]) -> list[str]:
    """Build lowercased searchable texts from control receipts."""
    haystacks: list[str] = []
    for rec in control_receipts:
        parts = [
            str(rec.get("body") or ""),
            str(rec.get("redirect_location") or ""),
            json.dumps(rec.get("response_headers") or {}, ensure_ascii=False),
        ]
        joined = "\n".join(p for p in parts if p).lower()
        if joined:
            haystacks.append(joined)
    return haystacks


def _value_in_controls(val: str, control_haystacks: list[str]) -> bool:
    """Return True if `val` appears in any control receipt."""
    v_low = str(val or "").strip().lower()
    if not v_low or not control_haystacks:
        return False
    if len(v_low) < 8:
        pat = re.compile(rf"(?<![a-z0-9]){re.escape(v_low)}(?![a-z0-9])")
        return any(bool(pat.search(ct)) for ct in control_haystacks)
    return any(v_low in ct for ct in control_haystacks)


def _receipt_contains_value(receipt: dict[str, Any], value: str) -> bool:
    """Return True if `value` appears in receipt body, redirect_location, or response headers."""
    needle = str(value or "").strip()
    if not needle:
        return False
    lower_needle = needle.lower()
    body = str(receipt.get("body") or "")
    loc = str(receipt.get("redirect_location") or "")
    if needle in body or lower_needle in body.lower():
        return True
    if needle in loc or lower_needle in loc.lower():
        return True
    headers_text = json.dumps(receipt.get("response_headers") or {}, ensure_ascii=False)
    return lower_needle in headers_text.lower()


def _extract_receipt_secret_candidates(
    receipt: dict[str, Any],
    control_haystacks: list[str],
) -> list[tuple[int, str]]:
    """Extract unique high-specificity tokens or sensitive JSON values absent from controls."""
    body = str(receipt.get("body") or "").strip()
    if not body:
        return []
    candidates: dict[str, int] = {}

    def _add(val: str, score: int) -> None:
        clean = val.strip()
        if not clean or len(clean) < 4 or len(clean) > 256 or clean.lower() in _TRIVIAL_EVIDENCE:
            return
        if _ISO_TIMESTAMP_RE.fullmatch(clean) or clean.startswith("/"):
            return
        if clean.lower().startswith(("http://", "https://")):
            return
        if _value_in_controls(clean, control_haystacks):
            return
        prev = candidates.get(clean, 0)
        if score > prev:
            candidates[clean] = score

    def _walk_json(obj: Any, key_name: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                sk = str(k)
                if _is_ignored_json_key(sk):
                    continue
                _walk_json(v, sk)
        elif isinstance(obj, list):
            for item in obj:
                _walk_json(item, key_name)
        elif isinstance(obj, str):
            clean = obj.strip()
            if not clean or len(clean) < 4 or len(clean) > 256:
                return
            if _is_sensitive_json_key(key_name):
                sc = score_evidence_value(clean, key_name=key_name)
                if sc >= _HIGH_SPEC_THRESHOLD:
                    _add(clean, sc)
            else:
                ok, sc = _is_high_entropy_token(clean, strict_extraction=True)
                if ok and sc >= _HIGH_SPEC_THRESHOLD:
                    _add(clean, sc)
            for tok in _RAW_TOKEN_SCAN_RE.findall(clean):
                if tok == clean:
                    continue
                ok, sc = _is_high_entropy_token(tok, strict_extraction=True)
                if ok and sc >= _HIGH_SPEC_THRESHOLD:
                    _add(tok, sc)

    parsed_json: Any = None
    if body.startswith(("{", "[")):
        try:
            parsed_json = json.loads(body)
        except ValueError:
            parsed_json = None
    if parsed_json is not None:
        _walk_json(parsed_json)
    else:
        for tok in _RAW_TOKEN_SCAN_RE.findall(body):
            if "/" in tok and tok.count("/") >= 1 and "." in tok:
                continue
            ok, sc = _is_high_entropy_token(tok, strict_extraction=True)
            if ok and sc >= _HIGH_SPEC_THRESHOLD:
                _add(tok, sc)

    ranked = sorted(candidates.items(), key=lambda kv: (-kv[1], -len(kv[0]), kv[0]))
    return [(sc, val) for val, sc in ranked]


def _best_secret_for_receipt(
    receipt: dict[str, Any],
    control_haystacks: list[str],
) -> tuple[int, str]:
    """Return (highest_score, token_value) for a receipt, or (0, '')."""
    cands = _extract_receipt_secret_candidates(receipt, control_haystacks)
    return cands[0] if cands else (0, "")


def _filter_class_eligible_proofs(
    canonical_class: str,
    proofs: list[dict[str, Any]],
    control_receipts: list[dict[str, Any]],
    *,
    actor_meta_map: dict[str, dict[str, str]],
    receipt_store: ReceiptStore | None = None,
    route_template: str = "",
    evidence_value: str = "",
) -> list[dict[str, Any]]:
    """Filter proofs to actors eligible to represent primary proof for `canonical_class`."""
    if not proofs:
        return []
    candidates = list(proofs)
    if canonical_class == "auth_bypass":
        anon_only = [r for r in candidates if _is_genuine_anon_2xx(r, actor_meta_map)]
        return anon_only if anon_only else candidates
    if canonical_class == "bfla":
        non_anon = [r for r in candidates if str(r.get("actor") or "") != "anon"]
        if non_anon:
            candidates = non_anon
        non_admin = [
            r for r in candidates
            if not _is_admin_role((actor_meta_map.get(str(r.get("actor") or "")) or {}).get("role", ""))
        ]
        return non_admin if non_admin else candidates
    if canonical_class in {"bola", "tenant_isolation"}:
        non_anon = [r for r in candidates if str(r.get("actor") or "") != "anon"]
        if non_anon:
            candidates = non_anon
        filtered: list[dict[str, Any]] = []
        for r in candidates:
            explicit_owner, _ = _extract_record_owner_and_tenant(r, actor_meta_map)
            if explicit_owner and str(r.get("actor") or "") == explicit_owner:
                continue
            filtered.append(r)
        if filtered:
            candidates = filtered
        target_p = _norm_path(str(candidates[0].get("url") or "")) if candidates else ""
        owner_actor = _infer_owner_actor(
            candidates,
            control_receipts,
            receipt_store=receipt_store,
            route_template=route_template,
            evidence_value=evidence_value,
            actor_meta_map=actor_meta_map,
            target_path=target_p,
        )
        if owner_actor:
            non_owner = [r for r in candidates if str(r.get("actor") or "") != owner_actor]
            if non_owner:
                candidates = non_owner
        non_admin = [
            r for r in candidates
            if not _is_admin_role((actor_meta_map.get(str(r.get("actor") or "")) or {}).get("role", ""))
        ]
        return non_admin if non_admin else candidates
    return candidates


def _select_stronger_evidence_from_receipts(
    canonical_class: str,
    current_evidence: str,
    candidate_receipts: list[dict[str, Any]],
    control_receipts: list[dict[str, Any]],
) -> tuple[str, dict[str, Any] | None]:
    """Promote a strictly higher-specificity unique secret from candidate_receipts when current_evidence is weak/empty."""
    ev_clean = str(current_evidence or "").strip()
    if canonical_class in {"open_redirect", "reflected_xss", "stored_xss"} and ev_clean:
        return ev_clean, None
    current_score = score_evidence_value(ev_clean)
    if current_score >= _HIGH_SPEC_THRESHOLD:
        return ev_clean, None
    ctrl_haystacks = _build_control_haystacks(control_receipts)
    if ev_clean and _value_in_controls(ev_clean, ctrl_haystacks):
        current_score = min(current_score, 10)

    best_score = 0
    best_val = ""
    best_rec: dict[str, Any] | None = None
    for rec in candidate_receipts:
        sc, val = _best_secret_for_receipt(rec, ctrl_haystacks)
        if sc > best_score or (sc == best_score and len(val) > len(best_val)):
            best_score = sc
            best_val = val
            best_rec = rec
    if best_rec is not None and best_score >= _HIGH_SPEC_THRESHOLD and best_score > current_score + 15:
        return best_val, best_rec
    return ev_clean, None


def select_primary_proof(
    canonical_class: str,
    valid_proofs: list[dict[str, Any]],
    control_receipts: list[dict[str, Any]],
    *,
    actor_meta_map: dict[str, dict[str, str]],
    receipt_store: ReceiptStore | None = None,
    route_template: str = "",
    evidence_value: str = "",
) -> tuple[dict[str, Any], list[str]]:
    """Choose the most direct unauthorized actor proof and ordered supporting actor list."""
    owner_actor = ""
    candidates = list(valid_proofs)
    ev_clean = str(evidence_value or "").strip()
    if canonical_class in {"bola", "tenant_isolation"}:
        # Remove proofs where the receipt explicitly shows the caller's own record (when peer proofs exist).
        non_self = []
        for r in candidates:
            exp_owner, _ = _extract_record_owner_and_tenant(r, actor_meta_map)
            if exp_owner and str(r.get("actor") or "") == exp_owner:
                continue
            non_self.append(r)
        if non_self:
            candidates = non_self
        ev_matching = [r for r in candidates if ev_clean and _receipt_contains_value(r, ev_clean)]
        owner_probe_recs = ev_matching if ev_matching else candidates
        target_p = _norm_path(str(owner_probe_recs[0].get("url") or "")) if owner_probe_recs else ""
        owner_actor = _infer_owner_actor(
            candidates,
            control_receipts,
            receipt_store=receipt_store,
            route_template=route_template,
            evidence_value=evidence_value,
            actor_meta_map=actor_meta_map,
            target_path=target_p,
        )
        if owner_actor:
            non_owner = [r for r in candidates if str(r.get("actor") or "") != owner_actor]
            if non_owner:
                candidates = non_owner
    elif canonical_class == "bfla":
        non_anon = [r for r in candidates if str(r.get("actor") or "") != "anon"]
        if non_anon:
            candidates = non_anon
    elif canonical_class == "auth_bypass":
        anon_only = [r for r in candidates if _is_genuine_anon_2xx(r, actor_meta_map)]
        if anon_only:
            candidates = anon_only

    ctrl_haystacks = _build_control_haystacks(control_receipts)
    ev_low_spec = score_evidence_value(ev_clean) < _HIGH_SPEC_THRESHOLD

    def _rank_key(r: dict[str, Any]) -> tuple[int, int, int, int, tuple[int, int, str]]:
        actor = str(r.get("actor") or "")
        meta = actor_meta_map.get(actor) or {}
        role = str(meta.get("role") or ("anonymous" if actor == "anon" else "member")).lower()
        is_admin = _is_admin_role(role)
        if canonical_class == "bfla":
            elig_tier = 1 if actor == "anon" else (2 if is_admin else 0)
        elif canonical_class in {"bola", "tenant_isolation"}:
            if owner_actor and actor == owner_actor:
                elig_tier = 3
            elif actor == "anon":
                elig_tier = 2
            elif is_admin:
                elig_tier = 1
            else:
                elig_tier = 0
        else:
            elig_tier = 0

        if canonical_class == "stored_xss":
            render_tier = 0 if (str(r.get("method") or "").upper() == "GET" and is_html_receipt(r)) else 1
        else:
            render_tier = 0

        ev_match_rank = 0 if (not ev_clean or _receipt_contains_value(r, ev_clean)) else 1
        if ev_low_spec:
            sec_score, _ = _best_secret_for_receipt(r, ctrl_haystacks)
            spec_rank = -sec_score
        else:
            spec_rank = 0

        return (
            elig_tier,
            render_tier,
            ev_match_rank,
            spec_rank,
            _actor_priority_key(
                canonical_class,
                actor,
                actor_meta_map=actor_meta_map,
                owner_actor=owner_actor,
            ),
        )

    ranked = sorted(candidates, key=_rank_key)
    primary = ranked[0]
    ordered_actors: list[str] = []
    for r in ranked:
        a = str(r.get("actor") or "")
        if a and a not in ordered_actors:
            ordered_actors.append(a)
    return primary, ordered_actors


def _find_exact_route_anon_2xx(
    norm_path: str,
    method: str,
    proof_recs: list[dict[str, Any]],
    ctrl_recs: list[dict[str, Any]],
    *,
    actor_meta_map: dict[str, dict[str, str]],
    receipt_store: ReceiptStore | None = None,
    evidence_value: str = "",
) -> tuple[dict[str, Any] | None, bool]:
    """Find a genuine `anon` 2xx receipt on the exact `(norm_path, method)` if `anon` was not denied (401/403).

    Returns `(best_anon_2xx_receipt, anon_was_denied)`.
    """
    target_path = _norm_path(norm_path)
    target_method = str(method or "GET").strip().upper()
    candidates: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    def _consider(rec: dict[str, Any]) -> None:
        rid = str(rec.get("receipt_id") or "")
        if rid and rid in seen_ids:
            return
        if _norm_path(str(rec.get("url") or rec.get("path") or "")) != target_path:
            return
        rec_method = str(rec.get("method") or "GET").strip().upper()
        if target_method and rec_method != target_method:
            return
        if rid:
            seen_ids.add(rid)
        candidates.append(rec)

    for rec in [*proof_recs, *ctrl_recs]:
        _consider(rec)
    if receipt_store is not None:
        for rid in receipt_store.list_ids():
            if rid in seen_ids:
                continue
            try:
                rec = receipt_store.get(rid)
            except (KeyError, ValueError):
                continue
            _consider(rec)

    anon_denied = any(
        str(r.get("actor") or "").strip() == "anon" and int(r.get("status") or 0) in {401, 403}
        for r in candidates
    )
    if anon_denied:
        return None, True

    anon_2xx = [r for r in candidates if _is_genuine_anon_2xx(r, actor_meta_map)]
    if not anon_2xx:
        return None, False

    ev = str(evidence_value or "").strip()
    if ev:
        for r in anon_2xx:
            if _receipt_contains_value(r, ev):
                return r, False
    return anon_2xx[0], False


def _resolve_route_auth_bypass_vs_bfla(
    route_template: str,
    proof_recs: list[dict[str, Any]],
    ctrl_recs: list[dict[str, Any]],
    *,
    actor_meta_map: dict[str, dict[str, str]],
    receipt_store: ReceiptStore | None = None,
    exact_path: str = "",
    method: str = "",
) -> str:
    """Deterministically resolve auth_bypass vs bfla on a route from observed receipts.

    If `anon` gets 401/403 (or has no genuine 2xx proof) and a non-admin authenticated actor
    gets 200 -> `bfla`. If `anon` genuinely gets 200 on protected data (and was not denied 401/403)
    -> `auth_bypass`.
    """
    norm_exact = _norm_path(exact_path) if exact_path else ""
    norm_method = str(method or "").strip().upper()
    all_recs = [*proof_recs, *ctrl_recs]
    if receipt_store is not None:
        seen_ids = {r.get("receipt_id") for r in all_recs}
        for rid in receipt_store.list_ids():
            if rid in seen_ids:
                continue
            try:
                rec = receipt_store.get(rid)
            except (KeyError, ValueError):
                continue
            rec_url = str(rec.get("url") or rec.get("path") or "")
            if norm_exact:
                if _norm_path(rec_url) != norm_exact:
                    continue
                if norm_method and str(rec.get("method") or "").strip().upper() != norm_method:
                    continue
            elif normalize_route_template(rec_url) != route_template:
                continue
            all_recs.append(rec)

    anon_denied = any(
        str(r.get("actor") or "") == "anon" and int(r.get("status") or 0) in {401, 403}
        for r in all_recs
    )
    anon_genuine_2xx = any(
        _is_genuine_anon_2xx(r, actor_meta_map)
        for r in (all_recs if norm_exact else proof_recs)
    )
    non_admin_2xx = any(
        str(r.get("actor") or "") not in {"", "anon"}
        and not _is_admin_role((actor_meta_map.get(str(r.get("actor") or "")) or {}).get("role", ""))
        and 200 <= int(r.get("status") or 0) < 300
        for r in all_recs
    )
    if anon_denied or not anon_genuine_2xx:
        if non_admin_2xx or any(str(r.get("actor") or "") != "anon" and 200 <= int(r.get("status") or 0) < 300 for r in proof_recs):
            return "bfla"
    if anon_genuine_2xx and not anon_denied:
        return "auth_bypass"
    return "bfla" if non_admin_2xx else "auth_bypass"


def canonicalize_and_deduplicate_findings(
    findings: list[dict[str, Any]],
    *,
    actor_meta_map: dict[str, dict[str, str]],
    receipt_store: ReceiptStore | None = None,
) -> list[dict[str, Any]]:
    """Normalize classes/routes, resolve auth_bypass/bfla overlap, deduplicate by (route_template, class), and rank primary actors."""
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []

    def _is_actor_eligible_over(cls_name: str, cand_actor: str, ref_actor: str) -> bool:
        if not cand_actor:
            return False
        cand_role = str((actor_meta_map.get(cand_actor) or {}).get("role") or ("anonymous" if cand_actor == "anon" else "member")).lower()
        ref_role = str((actor_meta_map.get(ref_actor) or {}).get("role") or ("anonymous" if ref_actor == "anon" else "member")).lower()
        if cls_name == "bfla":
            ref_non_admin = bool(ref_actor) and ref_actor != "anon" and not _is_admin_role(ref_role)
            cand_bad = cand_actor == "anon" or _is_admin_role(cand_role)
            if ref_non_admin and cand_bad:
                return False
        elif cls_name == "auth_bypass":
            if ref_actor == "anon" and cand_actor != "anon":
                return False
        return True

    def _find_finding_primary_receipt(finding_dict: dict[str, Any]) -> dict[str, Any] | None:
        if receipt_store is None:
            return None
        f_actor = str(finding_dict.get("actor") or finding_dict.get("actor_alias") or "").strip()
        f_path = _norm_path(str(finding_dict.get("url") or finding_dict.get("path") or ""))
        recs: list[dict[str, Any]] = []
        for rid in (finding_dict.get("proof_receipt_ids") or []):
            try:
                rec = receipt_store.get(str(rid))
                if 200 <= int(rec.get("status", 0)) < 400:
                    recs.append(rec)
            except (KeyError, ValueError):
                continue
        for rec in recs:
            if f_actor and str(rec.get("actor") or "") == f_actor and (not f_path or _norm_path(str(rec.get("url") or "")) == f_path):
                return rec
        return recs[0] if recs else None

    def _merge_entries(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
        for list_field in ("proof_receipt_ids", "control_receipt_ids"):
            merged_ids = list(dict.fromkeys([
                *(existing.get(list_field) or []),
                *(incoming.get(list_field) or []),
            ]))
            existing[list_field] = merged_ids
        for excerpt_field in ("evidence_excerpts", "control_excerpts"):
            seen_ex = {
                (e.get("receipt_id"), e.get("actor"))
                for e in (existing.get(excerpt_field) or [])
                if isinstance(e, dict)
            }
            for ex in (incoming.get(excerpt_field) or []):
                if isinstance(ex, dict) and (ex.get("receipt_id"), ex.get("actor")) not in seen_ex:
                    existing.setdefault(excerpt_field, []).append(ex)
                    seen_ex.add((ex.get("receipt_id"), ex.get("actor")))

        existing_actor = str(existing.get("actor") or existing.get("actor_alias") or "").strip()
        incoming_actor = str(incoming.get("actor") or incoming.get("actor_alias") or "").strip()

        cls_name = str(existing.get("class_type") or "")
        ex_ev = str(existing.get("evidence_value") or existing.get("marker") or "").strip()
        in_ev = str(incoming.get("evidence_value") or incoming.get("marker") or "").strip()
        ex_best_val = ex_ev
        in_best_val = in_ev
        ex_score = score_evidence_value(ex_ev)
        in_score = score_evidence_value(in_ev)

        if receipt_store is not None:
            ctrl_recs_for_merge: list[dict[str, Any]] = []
            for rid in (existing.get("control_receipt_ids") or []):
                try:
                    ctrl_recs_for_merge.append(receipt_store.get(str(rid)))
                except (KeyError, ValueError):
                    continue
            ctrl_haystacks = _build_control_haystacks(ctrl_recs_for_merge)
            if ex_ev and _value_in_controls(ex_ev, ctrl_haystacks) and ex_score < _HIGH_SPEC_THRESHOLD:
                ex_score = min(ex_score, 10)
            if in_ev and _value_in_controls(in_ev, ctrl_haystacks) and in_score < _HIGH_SPEC_THRESHOLD:
                in_score = min(in_score, 10)

            ex_rec = _find_finding_primary_receipt(existing)
            if ex_rec is not None and ex_score < _HIGH_SPEC_THRESHOLD and cls_name not in {"open_redirect", "reflected_xss", "stored_xss"}:
                sec_sc, sec_val = _best_secret_for_receipt(ex_rec, ctrl_haystacks)
                if sec_sc >= _HIGH_SPEC_THRESHOLD and sec_sc > ex_score + 15:
                    ex_score = sec_sc
                    ex_best_val = sec_val
            in_rec = _find_finding_primary_receipt(incoming)
            if in_rec is not None and in_score < _HIGH_SPEC_THRESHOLD and cls_name not in {"open_redirect", "reflected_xss", "stored_xss"}:
                sec_sc, sec_val = _best_secret_for_receipt(in_rec, ctrl_haystacks)
                if sec_sc >= _HIGH_SPEC_THRESHOLD and sec_sc > in_score + 15:
                    in_score = sec_sc
                    in_best_val = sec_val

        promote_incoming = False
        if _is_actor_eligible_over(cls_name, incoming_actor, existing_actor) or not existing_actor:
            if not ex_ev and in_best_val:
                promote_incoming = True
            elif in_score >= _HIGH_SPEC_THRESHOLD and in_score > ex_score:
                promote_incoming = True
            elif in_score >= ex_score + 15:
                promote_incoming = True

        if promote_incoming:
            if in_best_val:
                existing["evidence_value"] = in_best_val
                existing["marker"] = in_best_val
            if incoming_actor:
                existing["actor"] = incoming_actor
                existing["actor_alias"] = incoming_actor
            for field in ("url", "path", "observed_status", "method", "evidence"):
                val = incoming.get(field)
                if val is not None and val != "":
                    existing[field] = val
            merged_actors = list(dict.fromkeys([
                *([incoming_actor] if incoming_actor else []),
                *(incoming.get("supporting_actors") or []),
                *(existing.get("supporting_actors") or ([existing_actor] if existing_actor else [])),
            ]))
        else:
            if ex_best_val and ex_best_val != ex_ev and ex_score >= _HIGH_SPEC_THRESHOLD:
                existing["evidence_value"] = ex_best_val
                existing["marker"] = ex_best_val
            merged_actors = list(dict.fromkeys([
                *(existing.get("supporting_actors") or ([existing_actor] if existing_actor else [])),
                *(incoming.get("supporting_actors") or ([incoming_actor] if incoming_actor else [])),
            ]))
        existing["supporting_actors"] = [a for a in merged_actors if a]

    for raw_f in findings:
        if not isinstance(raw_f, dict):
            continue
        f = copy.deepcopy(raw_f)
        method = str(f.get("method") or "").upper()
        url_val = str(f.get("url") or f.get("path") or "")
        route_template = normalize_route_template(url_val)
        canonical_class = normalize_vuln_class(
            str(f.get("class_type") or ""),
            method=method,
            title=str(f.get("title") or ""),
            summary=str(f.get("summary") or ""),
        )
        f["class_type"] = canonical_class
        f["route_template"] = route_template
        fallback_actor = str(f.get("actor") or f.get("actor_alias") or "").strip()
        if fallback_actor:
            f["actor"] = fallback_actor
            f["actor_alias"] = fallback_actor

        key = (route_template, canonical_class)
        if key not in grouped:
            grouped[key] = f
            order.append(key)
        else:
            _merge_entries(grouped[key], f)

    # Resolve any (route_template, auth_bypass) vs (route_template, bfla) overlap deterministically.
    routes_with_both = {
        tmpl
        for (tmpl, cls) in list(order)
        if cls in {"auth_bypass", "bfla"}
        and ((tmpl, "auth_bypass") in grouped and (tmpl, "bfla") in grouped)
    }
    for tmpl in routes_with_both:
        ab_entry = grouped[(tmpl, "auth_bypass")]
        bf_entry = grouped[(tmpl, "bfla")]
        combined_proof_ids = list(dict.fromkeys([
            *(ab_entry.get("proof_receipt_ids") or []),
            *(bf_entry.get("proof_receipt_ids") or []),
        ]))
        combined_ctrl_ids = list(dict.fromkeys([
            *(ab_entry.get("control_receipt_ids") or []),
            *(bf_entry.get("control_receipt_ids") or []),
        ]))
        proof_recs: list[dict[str, Any]] = []
        ctrl_recs: list[dict[str, Any]] = []
        if receipt_store is not None:
            for rid in combined_proof_ids:
                try:
                    proof_recs.append(receipt_store.get(str(rid)))
                except (KeyError, ValueError):
                    continue
            for rid in combined_ctrl_ids:
                try:
                    ctrl_recs.append(receipt_store.get(str(rid)))
                except (KeyError, ValueError):
                    continue
        winner_class = _resolve_route_auth_bypass_vs_bfla(
            tmpl,
            proof_recs,
            ctrl_recs,
            actor_meta_map=actor_meta_map,
            receipt_store=receipt_store,
        )
        loser_class = "bfla" if winner_class == "auth_bypass" else "auth_bypass"
        _merge_entries(grouped[(tmpl, winner_class)], grouped[(tmpl, loser_class)])
        del grouped[(tmpl, loser_class)]
        order = [k for k in order if k != (tmpl, loser_class)]

    out: list[dict[str, Any]] = []
    for idx, key in enumerate(order, start=1):
        entry = grouped[key]
        entry["finding_id"] = f"F-{idx:03d}"
        if receipt_store is not None:
            proof_recs = []
            for rid in (entry.get("proof_receipt_ids") or []):
                try:
                    rec = receipt_store.get(str(rid))
                    if 200 <= int(rec.get("status", 0)) < 400:
                        proof_recs.append(rec)
                except (KeyError, ValueError):
                    continue
            ctrl_recs = []
            for rid in (entry.get("control_receipt_ids") or []):
                try:
                    ctrl_recs.append(receipt_store.get(str(rid)))
                except (KeyError, ValueError):
                    continue

            # If a standalone auth_bypass finding lacks any genuine anon 2xx receipt, reclassify to bfla if non-admin 2xx exists, else drop.
            if entry["class_type"] == "auth_bypass":
                resolved_cls = _resolve_route_auth_bypass_vs_bfla(
                    entry["route_template"],
                    proof_recs,
                    ctrl_recs,
                    actor_meta_map=actor_meta_map,
                    receipt_store=receipt_store,
                    exact_path=str(entry.get("url") or entry.get("path") or ""),
                    method=str(entry.get("method") or "GET"),
                )
                if resolved_cls == "bfla":
                    non_anon_proofs = [r for r in proof_recs if str(r.get("actor") or "") != "anon"]
                    if non_anon_proofs:
                        entry["class_type"] = "bfla"
                        proof_recs = non_anon_proofs
                    else:
                        continue
            elif entry["class_type"] == "bfla":
                # Bidirectional bfla -> auth_bypass promotion when anon received a genuine 2xx on this exact route
                # and was NOT denied with 401/403.
                entry_url = str((proof_recs[0].get("url") if proof_recs else "") or entry.get("url") or entry.get("path") or "")
                entry_method = str((proof_recs[0].get("method") if proof_recs else "") or entry.get("method") or "GET")
                ev_hint = str(entry.get("evidence_value") or "").strip()
                anon_rec, anon_denied = _find_exact_route_anon_2xx(
                    entry_url,
                    entry_method,
                    proof_recs,
                    ctrl_recs,
                    actor_meta_map=actor_meta_map,
                    receipt_store=receipt_store,
                    evidence_value=ev_hint,
                )
                if anon_rec is not None and not anon_denied:
                    entry["class_type"] = "auth_bypass"
                    anon_rid = str(anon_rec.get("receipt_id") or "")
                    seen_p_ids = {str(r.get("receipt_id") or "") for r in proof_recs}
                    ctrl_id_set = set(entry.get("control_receipt_ids") or [])
                    if anon_rid and anon_rid not in seen_p_ids:
                        proof_recs.append(anon_rec)
                    if anon_rid and anon_rid not in (entry.get("proof_receipt_ids") or []) and anon_rid not in ctrl_id_set:
                        entry.setdefault("proof_receipt_ids", []).append(anon_rid)
                    if ev_hint and not _receipt_contains_value(anon_rec, ev_hint):
                        promoted_anon_ev, _ = _select_stronger_evidence_from_receipts(
                            "auth_bypass",
                            "",
                            [anon_rec],
                            ctrl_recs,
                        )
                        if promoted_anon_ev:
                            entry["evidence_value"] = promoted_anon_ev
                            entry["marker"] = promoted_anon_ev

            # For BOLA, if receipt_store also has a same-path 2xx receipt from a higher-priority peer actor containing evidence_value, include it.
            if entry["class_type"] == "bola" and proof_recs:
                target_norm_p = _norm_path(str(proof_recs[0].get("url") or entry.get("url") or ""))
                ev_val = str(entry.get("evidence_value") or "").strip()
                seen_proof_ids = {r["receipt_id"] for r in proof_recs}
                for rid in receipt_store.list_ids():
                    if rid in seen_proof_ids or rid in (entry.get("control_receipt_ids") or []):
                        continue
                    try:
                        cand = receipt_store.get(rid)
                    except (KeyError, ValueError):
                        continue
                    if (
                        200 <= int(cand.get("status") or 0) < 300
                        and _norm_path(str(cand.get("url") or "")) == target_norm_p
                        and str(cand.get("method") or "").upper() == str(entry.get("method") or "GET").upper()
                        and (not ev_val or ev_val in str(cand.get("body") or ""))
                    ):
                        proof_recs.append(cand)
                        seen_proof_ids.add(rid)
                        if rid not in entry["proof_receipt_ids"]:
                            entry["proof_receipt_ids"].append(rid)

            if proof_recs:
                ev_str = str(entry.get("evidence_value") or "").strip()
                if len(proof_recs) > 1 or not ev_str:
                    eligible_proofs = _filter_class_eligible_proofs(
                        entry["class_type"],
                        proof_recs,
                        ctrl_recs,
                        actor_meta_map=actor_meta_map,
                        receipt_store=receipt_store,
                        route_template=entry["route_template"],
                        evidence_value=ev_str,
                    )
                    promoted_ev, _ = _select_stronger_evidence_from_receipts(
                        entry["class_type"],
                        ev_str,
                        eligible_proofs,
                        ctrl_recs,
                    )
                    if promoted_ev and promoted_ev != ev_str:
                        ev_str = promoted_ev
                        entry["evidence_value"] = promoted_ev
                        entry["marker"] = promoted_ev

                primary, ordered_actors = select_primary_proof(
                    entry["class_type"],
                    proof_recs,
                    ctrl_recs,
                    actor_meta_map=actor_meta_map,
                    receipt_store=receipt_store,
                    route_template=entry["route_template"],
                    evidence_value=ev_str,
                )
                primary_actor = str(primary.get("actor") or entry.get("actor") or entry.get("actor_alias") or "anon").strip() or "anon"
                entry["actor"] = primary_actor
                entry["actor_alias"] = primary_actor
                entry["observed_status"] = primary["status"]
                entry["url"] = primary["url"]
                entry["path"] = primary["path"]
                entry["method"] = primary["method"]
                prior_actors = [str(a) for a in (entry.get("supporting_actors") or []) if str(a)]
                entry["supporting_actors"] = list(dict.fromkeys([*ordered_actors, *prior_actors]))
                entry["evidence_excerpts"] = [
                    {
                        "receipt_id": r["receipt_id"],
                        "actor": r["actor"],
                        "method": r["method"],
                        "url": r["url"],
                        "status": r["status"],
                        "excerpt": build_receipt_excerpt(r, ev_str, max_chars=MAX_PROOF_EXCERPT_CHARS),
                    }
                    for r in proof_recs
                ]
                entry["control_excerpts"] = [
                    {
                        "receipt_id": c["receipt_id"],
                        "actor": c["actor"],
                        "method": c["method"],
                        "url": c["url"],
                        "status": c["status"],
                        "excerpt": build_receipt_excerpt(c, "", max_chars=MAX_CONTROL_EXCERPT_CHARS),
                    }
                    for c in ctrl_recs
                ]
                entry["evidence"] = compose_finding_evidence(
                    primary,
                    proof_recs,
                    ctrl_recs,
                    ev_str,
                    max_proof_chars=MAX_PROOF_EXCERPT_CHARS,
                    max_control_chars=MAX_CONTROL_EXCERPT_CHARS,
                )
        det_actor = str(entry.get("actor") or entry.get("actor_alias") or "anon").strip() or "anon"
        entry["actor"] = det_actor
        entry["actor_alias"] = det_actor
        if not entry.get("supporting_actors"):
            entry["supporting_actors"] = [det_actor]
        out.append(entry)
    return out


def _notable_headers(headers: dict[str, str]) -> dict[str, str]:
    keep = {}
    for k, v in (headers or {}).items():
        lk = k.lower()
        if lk in {
            "location", "content-type", "retry-after", "x-challenge",
            "x-lab-injected", "x-lab-stream-cut", "www-authenticate", "cache-control",
        }:
            keep[k] = v
    return keep


_EVENT_OR_JS_RE = re.compile(r"(?:\bon[a-z]+\s*=|javascript\s*:)", re.I)
_SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.I | re.S)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_STYLE_BLOCK_RE = re.compile(r"<style\b[^>]*>.*?</style>", re.I | re.S)
_SVG_OPEN_RE = re.compile(r"<svg(?=[\s/>])", re.I)
_SVG_CLOSE_RE = re.compile(r"</svg\s*>", re.I)
_HTML_TAG_RE = re.compile(r"""<([a-zA-Z][a-zA-Z0-9:-]*)(\s+(?:"[^"]*"|'[^']*'|[^>"'])*)?>""")
_TAG_ATTR_RE = re.compile(
    r"""\s+([a-zA-Z_:][a-zA-Z0-9_.:-]*)(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?"""
)


def _find_tag_end(text: str, start: int) -> int:
    """Return index of closing '>' for an HTML tag starting at `start`, respecting quotes."""
    quote = ""
    i = start + 1
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == quote:
                quote = ""
        else:
            if ch in ('"', "'"):
                quote = ch
            elif ch == ">":
                return i
        i += 1
    return -1


def _strip_passive_svgs(html: str, *, protected_marker: str = "") -> str:
    """Strip passive decorative <svg> blocks while preserving any with event handlers, javascript:, or scripts."""
    out: list[str] = []
    pos = 0
    n = len(html)
    while pos < n:
        match = _SVG_OPEN_RE.search(html, pos)
        if not match:
            out.append(html[pos:])
            break
        start = match.start()
        out.append(html[pos:start])
        tag_end = _find_tag_end(html, start)
        if tag_end == -1:
            out.append(html[start:])
            break
        open_tag = html[start : tag_end + 1]
        if _EVENT_OR_JS_RE.search(open_tag):
            out.append(open_tag)
            pos = tag_end + 1
            continue
        if open_tag.rstrip()[:-1].rstrip().endswith("/"):
            pos = tag_end + 1
            continue
        depth = 1
        scan = tag_end + 1
        end_pos = -1
        while depth > 0 and scan < n:
            next_open = _SVG_OPEN_RE.search(html, scan)
            next_close = _SVG_CLOSE_RE.search(html, scan)
            if not next_close:
                break
            if next_open and next_open.start() < next_close.start():
                sub_end = _find_tag_end(html, next_open.start())
                if sub_end == -1:
                    break
                sub_tag = html[next_open.start() : sub_end + 1]
                if not sub_tag.rstrip()[:-1].rstrip().endswith("/"):
                    depth += 1
                scan = sub_end + 1
            else:
                depth -= 1
                scan = next_close.end()
                if depth == 0:
                    end_pos = scan
                    break
        if end_pos == -1:
            out.append(open_tag)
            pos = tag_end + 1
            continue
        block = html[start:end_pos]
        has_script = "<script" in block.lower() or (bool(protected_marker) and protected_marker in block)
        if _EVENT_OR_JS_RE.search(block) or has_script:
            out.append(block)
        pos = end_pos
    return "".join(out)


def _strip_inline_style_attrs(html: str) -> str:
    """Remove inline style='...' / style=\"...\" attributes from tags without event handlers or javascript:."""
    def _clean_tag(match: re.Match[str]) -> str:
        full_tag = match.group(0)
        if _EVENT_OR_JS_RE.search(full_tag):
            return full_tag
        attrs = match.group(2)
        if not attrs or "style" not in attrs.lower():
            return full_tag
        rebuilt: list[str] = []
        last = 0
        for attr_m in _TAG_ATTR_RE.finditer(attrs):
            if attr_m.group(1).lower() == "style":
                rebuilt.append(attrs[last : attr_m.start()])
                last = attr_m.end()
        if last == 0:
            return full_tag
        rebuilt.append(attrs[last:])
        return f"<{match.group(1)}{''.join(rebuilt)}>"

    return _HTML_TAG_RE.sub(_clean_tag, html)


def prune_html_for_preview(html: str) -> str:
    """Prune CSS/comment/decorative-SVG noise from HTML for display preview only.

    Preserves <script> blocks, forms, inputs, links, tables, resource IDs, and
    any tag containing inline event handlers (`on*=`) or `javascript:` URIs verbatim.
    """
    if not html:
        return ""
    sentinel_prefix = "__KRYON_SCRIPT_BLOCK_"
    while sentinel_prefix in html:
        sentinel_prefix += "_"

    script_blocks: list[str] = []

    def _protect_script(match: re.Match[str]) -> str:
        idx = len(script_blocks)
        script_blocks.append(match.group(0))
        return f"{sentinel_prefix}{idx}__"

    text = _SCRIPT_BLOCK_RE.sub(_protect_script, html)
    text = _HTML_COMMENT_RE.sub("", text)
    text = _STYLE_BLOCK_RE.sub(
        lambda m: m.group(0) if _EVENT_OR_JS_RE.search(m.group(0)) else "",
        text,
    )
    text = _strip_passive_svgs(text, protected_marker=sentinel_prefix)
    text = _strip_inline_style_attrs(text)

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    compact_lines: list[str] = []
    for line in text.split("\n"):
        cleaned = re.sub(r"[ \t]{2,}", " ", line).strip()
        if cleaned:
            compact_lines.append(cleaned)
    text = "\n".join(compact_lines)

    for idx, script_block in enumerate(script_blocks):
        text = text.replace(f"{sentinel_prefix}{idx}__", script_block)
    return text


def _format_receipt_preview(receipt: dict[str, Any], *, preview_chars: int = 2400) -> dict[str, Any]:
    body = receipt.get("body") or ""
    ctype = (receipt.get("content_type") or "").lower()
    is_html = "html" in ctype or body.lstrip().startswith(("<!", "<html", "<HTML"))
    preview_source = prune_html_for_preview(body) if (is_html and body) else body
    shown = preview_source[:preview_chars]
    remaining = max(0, len(preview_source) - len(shown))
    out: dict[str, Any] = {
        "receipt_id": receipt["receipt_id"],
        "cached": bool(receipt.get("cached", False)),
        "actor": receipt["actor"],
        "method": receipt["method"],
        "url": receipt["url"],
        "status": receipt["status"],
        "elapsed_ms": receipt["elapsed_ms"],
        "content_type": receipt["content_type"],
        "response_length": receipt["response_length"],
        "redirect_location": receipt.get("redirect_location", ""),
        "notable_headers": _notable_headers(receipt.get("response_headers") or {}),
        "body_preview": shown if shown else "<empty>",
    }
    if receipt.get("saved_session"):
        out["saved_session"] = receipt["saved_session"]
    if receipt.get("error"):
        out["error"] = receipt["error"]
    if remaining > 0:
        if is_html and len(preview_source) != len(body):
            out["truncation_note"] = (
                f"Pruned HTML preview truncated; {remaining} more pruned chars "
                f"({len(body)} raw chars in store). Use read_receipt('{receipt['receipt_id']}', offset=0) or regex."
            )
        else:
            out["truncation_note"] = (
                f"Body truncated; {remaining} more chars in store. "
                f"Use read_receipt('{receipt['receipt_id']}', offset={len(shown)}) or regex."
            )
    return out


def _flatten_json_keys(obj: Any, prefix: str = "", out: dict[str, str] | None = None, limit: int = 200) -> dict[str, str]:
    if out is None:
        out = {}
    if len(out) >= limit:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                _flatten_json_keys(v, key, out, limit)
            else:
                out[key] = repr(v)[:80]
                if len(out) >= limit:
                    break
    elif isinstance(obj, list):
        out[f"{prefix}[]"] = f"len={len(obj)}"
        for idx, item in enumerate(obj[:5]):
            _flatten_json_keys(item, f"{prefix}[{idx}]", out, limit)
    else:
        out[prefix or "$"] = repr(obj)[:80]
    return out


def _compute_structural_diff(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    diff: dict[str, Any] = {
        "status_diff": [baseline.get("status"), current.get("status")],
        "length_diff": int(current.get("response_length", 0)) - int(baseline.get("response_length", 0)),
        "sha256_same": baseline.get("response_sha256") == current.get("response_sha256"),
        "redirect_diff": [baseline.get("redirect_location", ""), current.get("redirect_location", "")],
    }
    b_body = baseline.get("body") or ""
    c_body = current.get("body") or ""
    try:
        b_json = json.loads(b_body)
        c_json = json.loads(c_body)
    except ValueError:
        b_json = None
        c_json = None

    if b_json is not None and c_json is not None:
        b_flat = _flatten_json_keys(b_json)
        c_flat = _flatten_json_keys(c_json)
        b_keys = set(b_flat)
        c_keys = set(c_flat)
        added = sorted(c_keys - b_keys)[:20]
        removed = sorted(b_keys - c_keys)[:20]
        changed = [
            {"key": k, "baseline": b_flat[k], "replay": c_flat[k]}
            for k in sorted(b_keys & c_keys)
            if b_flat[k] != c_flat[k]
        ][:20]
        diff["json_diff"] = {
            "json_equal": b_json == c_json,
            "added_keys": added,
            "removed_keys": removed,
            "changed_values": changed,
        }
    else:
        sample_b = b_body[:8000]
        sample_c = c_body[:8000]
        ratio = SequenceMatcher(None, sample_b, sample_c).ratio()
        diff["text_similarity"] = round(ratio, 3)
        if sample_b != sample_c:
            mismatch = next((i for i, (x, y) in enumerate(zip(sample_b, sample_c)) if x != y), min(len(sample_b), len(sample_c)))
            diff["first_diff_offset"] = mismatch
            diff["replay_diff_snippet"] = sample_c[max(0, mismatch - 40) : mismatch + 200]
    return diff


def _extract_openapi_operations(spec: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    """Extract normalized endpoints, methods, params, and body fields from OpenAPI 2/3 JSON."""
    resolver = LocalSchema(spec)
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    operations: list[dict[str, Any]] = []
    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(path_item, dict):
            continue
        raw_path_params = path_item.get("parameters")
        path_params = raw_path_params if isinstance(raw_path_params, list) else []
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            params: list[dict[str, str]] = []
            raw_op_params = op.get("parameters")
            op_params = raw_op_params if isinstance(raw_op_params, list) else []
            for p in [*path_params, *op_params]:
                resolved_p = resolver.resolve(p) if isinstance(p, dict) else {}
                pname = resolved_p.get("name")
                if pname:
                    params.append({"name": str(pname), "in": str(resolved_p.get("in") or "query")})
            body_fields: list[str] = []
            req_body = resolver.resolve(op.get("requestBody")) if isinstance(op.get("requestBody"), dict) else {}
            raw_content = req_body.get("content")
            content = raw_content if isinstance(raw_content, dict) else {}
            for media in content.values():
                if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                    schema = resolver.schema(media["schema"])
                    props = schema.get("properties")
                    if isinstance(props, dict):
                        body_fields.extend(str(k) for k in props.keys())
            operations.append({
                "method": method.upper(),
                "path": raw_path,
                "url": base_url.rstrip("/") + (raw_path if raw_path.startswith("/") else "/" + raw_path),
                "params": params[:25],
                "body_fields": list(dict.fromkeys(body_fields))[:25],
                "summary": str(op.get("summary") or "")[:120],
            })
            if len(operations) >= 120:
                return operations
    return operations


def _extract_candidate_ids(obj: Any, *, limit: int = 40) -> list[dict[str, str]]:
    """Collect sample resource IDs / tags from JSON payloads to aid cross-actor testing."""
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 6 or len(found) >= limit:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                lk = str(k).lower()
                if isinstance(v, (str, int)) and not isinstance(v, bool):
                    sval = str(v).strip()
                    if sval and len(sval) <= 64 and (
                        lk == "id" or any(h in lk for h in _ID_KEY_HINTS)
                    ):
                        if _ID_VALUE_RE.fullmatch(sval) or len(sval) <= 36:
                            pair = (str(k), sval)
                            if pair not in seen:
                                seen.add(pair)
                                found.append({"field": str(k), "value": sval})
                elif isinstance(v, (dict, list)):
                    walk(v, depth + 1)
        elif isinstance(node, list):
            for item in node[:20]:
                walk(item, depth + 1)

    walk(obj)
    return found


def _extract_surface_summary(receipt: dict[str, Any], base_url: str) -> dict[str, Any]:
    """Extract normalized attack-surface artifacts from a stored receipt at 0 HTTP cost."""
    body = receipt.get("body") or ""
    url = receipt["url"]
    ctype = (receipt.get("content_type") or "").lower()
    base = base_url

    links: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    js_calls: list[dict[str, Any]] = []
    spa_routes: list[dict[str, Any]] = []
    spec_urls: list[str] = []
    openapi_ops: list[dict[str, Any]] = []
    candidate_ids: list[dict[str, str]] = []

    stripped = body.lstrip()
    if "json" in ctype or stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            if isinstance(parsed, dict) and "paths" in parsed and ("openapi" in parsed or "swagger" in parsed):
                openapi_ops = _extract_openapi_operations(parsed, base)
            hypermedia, _ = extract_json_hypermedia(parsed, url, origin_url=base)
            for item in hypermedia:
                if not is_static_asset_url(item.get("url", "")):
                    links.append(item)
            candidate_ids = _extract_candidate_ids(parsed)
            spec_urls = find_spec_urls(body, url)

    if "html" in ctype or "<html" in body[:512].lower() or "<form" in body.lower() or "href=" in body.lower():
        for rec in extract_html(body, url):
            if rec.get("sources") == ["form"]:
                forms.append(rec)
            elif not is_static_asset_url(rec.get("url", "")):
                links.append(rec)
        for script in extract_inline_scripts(body):
            js_calls.extend(extract_js_calls(script, url, limit=40))
            spa_routes.extend(extract_spa_routes(script, url, limit=40))
            spec_urls.extend(find_spec_urls(script, url))
        # Also capture concrete UUID/resource IDs appearing inside HTML links/attributes.
        seen_html_ids = {(c["field"], c["value"]) for c in candidate_ids}
        for link_item in links:
            for seg in urlsplit(link_item.get("url", "")).path.split("/"):
                if len(seg) >= 8 and _ID_VALUE_RE.fullmatch(seg) and any(ch.isdigit() for ch in seg):
                    if ("path_id", seg) not in seen_html_ids and len(candidate_ids) < 40:
                        seen_html_ids.add(("path_id", seg))
                        candidate_ids.append({"field": "path_id", "value": seg})

    if "javascript" in ctype or urlsplit(url).path.lower().endswith((".js", ".mjs")):
        js_calls.extend(extract_js_calls(body, url, limit=80))
        for rec in extract_js(body, url, limit=60):
            if not is_static_asset_url(rec.get("url", "")):
                links.append(rec)
        spa_routes.extend(extract_spa_routes(body, url, limit=60))
        spec_urls.extend(find_spec_urls(body, url))

    if urlsplit(url).path.lower().endswith("/robots.txt"):
        links.extend(extract_robots(body, url))
    if "xml" in ctype or "<urlset" in body[:512].lower() or "<sitemapindex" in body[:512].lower():
        links.extend(extract_sitemap(body, url))

    # Deduplicate and compact links/forms so high-signal routes, forms, and IDs appear first without verbose boilerplate.
    base_netloc = urlsplit(base).netloc

    def _compact_surface_item(item: dict[str, Any]) -> dict[str, Any]:
        raw_u = str(item.get("url") or "")
        parsed_u = urlsplit(raw_u)
        if not parsed_u.netloc or parsed_u.netloc == base_netloc:
            short_u = (parsed_u.path or "/") + (f"?{parsed_u.query}" if parsed_u.query else "")
        else:
            short_u = raw_u
        p_list: list[str] = []
        for p in (item.get("params") or []):
            pname = str(p.get("name") if isinstance(p, dict) else p or "").strip()
            if pname and pname not in p_list:
                p_list.append(pname)
        compact: dict[str, Any] = {"method": str(item.get("method") or "GET").upper(), "url": short_u}
        if p_list:
            compact["params"] = p_list[:15]
        return compact

    dedup_links: list[dict[str, Any]] = []
    seen_links: set[tuple[str, str]] = set()
    for item in links:
        comp = _compact_surface_item(item)
        key = (comp["method"], comp["url"])
        if key not in seen_links:
            seen_links.add(key)
            dedup_links.append(comp)

    # Sort deeper/API/parameterized links ahead of 1-segment top nav links
    dedup_links.sort(
        key=lambda x: (
            0 if ("/api/" in x["url"] or "?" in x["url"] or x.get("params") or x["url"].count("/") >= 2) else 1,
            x["url"],
        )
    )
    compact_forms = [_compact_surface_item(f) for f in forms[:30]]

    return {
        "receipt_id": receipt["receipt_id"],
        "url": url,
        "content_type": ctype,
        "forms": compact_forms,
        "openapi_operations": openapi_ops[:80],
        "js_calls": js_calls[:60],
        "candidate_ids": candidate_ids[:40],
        "spec_urls": list(dict.fromkeys(spec_urls))[:20],
        "spa_routes": spa_routes[:40],
        "links": dedup_links[:60],
    }


def _build_surface_hints(
    receipt: dict[str, Any],
    base_url: str,
    *,
    max_chars: int = 900,
) -> dict[str, Any]:
    """Build a compact, strictly bounded surface_hints dict for inline http_request previews."""
    summary = _extract_surface_summary(receipt, base_url)
    base_netloc = urlsplit(base_url).netloc
    ctype = (receipt.get("content_type") or "").lower()
    url_path = urlsplit(str(receipt.get("url") or "")).path.lower()
    is_js = "javascript" in ctype or "ecmascript" in ctype or url_path.endswith((".js", ".mjs"))

    def _short_same_origin(raw_u: str) -> tuple[str, str, bool]:
        parsed_u = urlsplit(str(raw_u or "").strip())
        same_origin = not parsed_u.netloc or parsed_u.netloc == base_netloc
        path = parsed_u.path or "/"
        short = path + (f"?{parsed_u.query}" if parsed_u.query else "")
        return path[:120], short[:120], same_origin

    forms: list[dict[str, Any]] = []
    for f in (summary.get("forms") or [])[:4]:
        forms.append({
            "method": str(f.get("method") or "GET").upper(),
            "url": str(f.get("url") or "")[:120],
            "params": [str(p)[:32] for p in (f.get("params") or [])[:8]],
        })

    openapi_ops: list[str] = []
    seen_ops: set[str] = set()
    for op in summary.get("openapi_operations") or []:
        op_str = f"{str(op.get('method') or '').upper()} {str(op.get('path') or '')}".strip()[:120]
        if op_str and op_str not in seen_ops:
            seen_ops.add(op_str)
            openapi_ops.append(op_str)
            if len(openapi_ops) >= 10:
                break

    api_endpoints: list[str] = []
    api_path_set: set[str] = set()

    def _add_api(raw_u: str) -> None:
        if len(api_endpoints) >= 8:
            return
        path, _, same_origin = _short_same_origin(raw_u)
        if not same_origin or not path or path == "/" or is_static_asset_url(path):
            return
        if path not in api_path_set:
            api_path_set.add(path)
            api_endpoints.append(path)

    for op in summary.get("openapi_operations") or []:
        _add_api(str(op.get("path") or ""))
    for call in summary.get("js_calls") or []:
        _add_api(str(call.get("url") or ""))
    for spec_u in summary.get("spec_urls") or []:
        _add_api(str(spec_u))
    for item in summary.get("links") or []:
        u = str(item.get("url") or "")
        path, _, _ = _short_same_origin(u)
        if is_js or "/api/" in path or path.startswith("/api") or "/graphql" in path:
            _add_api(u)

    ids: list[str] = []
    seen_ids: set[str] = set()
    for cand in summary.get("candidate_ids") or []:
        val = str(cand.get("value") or "").strip()[:48]
        if val and val not in seen_ids:
            seen_ids.add(val)
            ids.append(val)
            if len(ids) >= 6:
                break

    links: list[str] = []
    seen_links: set[str] = set()
    for item in [*(summary.get("links") or []), *(summary.get("spa_routes") or [])]:
        if len(links) >= 6:
            break
        raw_u = str(item.get("url") or "")
        path, short, same_origin = _short_same_origin(raw_u)
        if not same_origin or is_static_asset_url(raw_u):
            continue
        if path == "/" and "?" not in short:
            continue
        if path in api_path_set or short in api_path_set:
            continue
        if short not in seen_links:
            seen_links.add(short)
            links.append(short)

    hints: dict[str, Any] = {}
    if forms:
        hints["forms"] = forms
    if api_endpoints:
        hints["api_endpoints"] = api_endpoints
    if openapi_ops:
        hints["openapi_ops"] = openapi_ops
    if ids:
        hints["ids"] = ids
    if links:
        hints["links"] = links

    trim_order = ("links", "ids", "api_endpoints", "openapi_ops", "forms")
    while hints and len(json.dumps(hints, ensure_ascii=False)) > max_chars:
        trimmed = False
        for key in trim_order:
            seq = hints.get(key)
            if isinstance(seq, list) and seq:
                seq.pop()
                if not seq:
                    del hints[key]
                trimmed = True
                break
        if not trimmed:
            break
    return hints


class ToolDispatcher:
    """Executes investigation and QA verification tools against the harness."""

    def __init__(
        self,
        *,
        http_client: AgenticHTTPClient,
        receipt_store: ReceiptStore,
        root_dir: str | Path,
        bsag: Any | None = None,
        oracle: Any | None = None,
        telemetry: Any | None = None,
        findings_path: str | Path | None = None,
        persist_findings: bool = True,
        oob_server: LoopbackCallbackServer | None = None,
    ):
        self.http = http_client
        self.receipts = receipt_store
        self.root_dir = Path(root_dir).expanduser().resolve()
        self.bsag = bsag
        self.oracle = oracle
        self.telemetry = telemetry
        self._oob_server: LoopbackCallbackServer | None = oob_server
        self._owns_oob_server: bool = False
        self._oob_lock = threading.Lock()
        self.active_worker_id: str = ""
        self.active_node_id: str = ""
        self.active_category: str = ""
        self._step_delta_v: int = 0
        self._step_delta_e: int = 0
        self._step_claim_submitted: bool = False
        self._findings_lock = threading.RLock()
        self._notebook_lock = threading.RLock()
        self.persist_findings: bool = bool(persist_findings)
        self.notebook_path = self.root_dir / "notebook.json"
        self.findings_path = (
            Path(findings_path).expanduser().resolve()
            if findings_path is not None
            else (self.root_dir / "findings.json")
        )
        self.notebook_state: dict[str, Any] = self._load_json(
            self.notebook_path,
            default={"surface_notes": "", "hypotheses": [], "notes": []},
        )
        self.findings: list[dict[str, Any]] = (
            self._load_json(self.findings_path, default=[])
            if self.persist_findings
            else []
        )
        self.surface_tracker = SurfaceFrontierTracker(
            base_url=self.http.base_url,
            allowed_methods=sorted(self.http.allowed_methods),
            actor_summaries=self.http.actors.summaries(),
        )
        self.coverage_gate_enabled: bool = True
        self.discovery_finish_gate: bool = False
        self._auth_barrier_or_write_seen: bool = False
        self._non_anon_2xx_reads: int = 0
        self.finish_rejections: int = 0
        self.max_finish_rejections: int = 3
        self.finished: bool = False
        self.finish_summary: str = ""
        self.untested_areas: list[str] = []

    def set_active_context(self, *, worker_id: str = "", node_id: str = "", category: str = "") -> None:
        self.active_worker_id = worker_id
        self.active_node_id = node_id
        self.active_category = category

    def consume_step_deltas(self) -> tuple[int, int, bool]:
        dv = self._step_delta_v
        de = self._step_delta_e
        claimed = self._step_claim_submitted
        self._step_delta_v = 0
        self._step_delta_e = 0
        self._step_claim_submitted = False
        return dv, de, claimed

    def _ingest_receipt_hooks(self, receipt: dict[str, Any]) -> None:
        self.surface_tracker.ingest_receipt(receipt)
        saved = receipt.get("saved_session")
        if isinstance(saved, dict) and saved.get("alias"):
            alias = str(saved["alias"])
            self.surface_tracker.actors[alias] = {
                "alias": alias,
                "role": str(saved.get("role") or "member").lower(),
                "tenant": "",
            }
            if self.bsag is not None:
                _, ac_v = self.bsag.register_auth_context(
                    alias=alias,
                    role=str(saved.get("role") or "member"),
                    authenticated=bool(saved.get("authenticated", True)),
                    dynamic=True,
                    source_receipt_id=str(saved.get("source_receipt_id") or receipt.get("receipt_id") or ""),
                )
                self._step_delta_v += ac_v
        dv, de = (0, 0)
        if self.bsag is not None:
            dv, de = self.bsag.ingest_receipt(receipt)
            self._step_delta_v += dv
            self._step_delta_e += de
        status = int(receipt.get("status") or 0)
        actor = str(receipt.get("actor") or "anon")
        method = str(receipt.get("method") or "GET").upper()
        if (
            status in {401, 403}
            or (300 <= status < 400 and actor == "anon")
            or bool(self.surface_tracker.declared_write_ops)
            or bool(self.surface_tracker.discovered_write_ops)
        ):
            self._auth_barrier_or_write_seen = True
        if actor != "anon" and method == "GET" and 200 <= status < 300:
            self._non_anon_2xx_reads += 1
        if self.telemetry is not None:
            ep_id = self.bsag.endpoint_node_id(receipt.get("url") or "/") if self.bsag is not None else self.active_node_id
            self.telemetry.emit(
                "http_event",
                worker_id=self.active_worker_id,
                node_id=self.active_node_id or ep_id,
                endpoint_id=ep_id,
                category=self.active_category,
                method=receipt.get("method"),
                path=receipt.get("path"),
                route_template=normalize_route_template(str(receipt.get("url") or "/")),
                actor=receipt.get("actor"),
                status=receipt.get("status"),
                cached=bool(receipt.get("cached", False)),
                delta_v=dv,
                delta_e=de,
                receipt_id=receipt.get("receipt_id"),
            )

    @staticmethod
    def _load_json(path: Path, default: Any) -> Any:
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
        return json.loads(json.dumps(default))

    def _save_notebook(self) -> None:
        with self._notebook_lock:
            _atomic_write_json(self.notebook_path, self.notebook_state)

    def _save_findings(self) -> None:
        if not self.persist_findings:
            return
        with self._findings_lock:
            _atomic_write_json(self.findings_path, self.findings)

    def _get_oob_server(self, *, start: bool = False) -> LoopbackCallbackServer | None:
        with self._oob_lock:
            if self._oob_server is None:
                if not start:
                    return None
                self._oob_server = LoopbackCallbackServer()
                self._owns_oob_server = True
            if start:
                self._oob_server.start()
            return self._oob_server

    def close(self) -> None:
        """Cleanly shut down any lazily created loopback callback server."""
        with self._oob_lock:
            srv = self._oob_server
            owns = self._owns_oob_server
            if owns:
                self._oob_server = None
                self._owns_oob_server = False
        if srv is not None and owns:
            srv.close()

    def dispatch(self, name: str, args: dict[str, Any]) -> str:
        handlers = {
            "http_request": self._tool_http_request,
            "read_receipt": self._tool_read_receipt,
            "replay_as": self._tool_replay_as,
            "extract_surface": self._tool_extract_surface,
            "notebook": self._tool_notebook,
            "callback_listener": self._tool_callback_listener,
            "concurrent_check": self._tool_concurrent_check,
            "record_finding": self._tool_record_finding,
            "finish": self._tool_finish,
        }
        fn = handlers.get(name)
        if fn is None:
            return json.dumps({"error": f"unknown tool: {name}"})
        try:
            return fn(args or {})
        except (ScopeViolationError, MethodNotAllowedError, BudgetExhaustedError, KeyError, ValueError) as exc:
            return json.dumps({"error": type(exc).__name__, "message": str(exc)})
        except Exception as exc:
            return json.dumps({"error": type(exc).__name__, "message": str(exc)[:300]})

    def _actor_meta_map(self) -> dict[str, dict[str, str]]:
        return {
            row["alias"]: {
                "alias": row["alias"],
                "role": str(row.get("role") or "").lower(),
                "tenant": str(row.get("tenant") or "").lower(),
            }
            for row in self.http.actors.summaries()
        }

    def _load_receipt_json_object(self, receipt_id: str) -> dict[str, Any]:
        rec = self.receipts.get(receipt_id)
        for field_name in ("body", "request_body"):
            raw = (rec.get(field_name) or "").strip()
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                return parsed
        raise ValueError(f"receipt {receipt_id} does not contain a JSON object")

    def _tool_http_request(self, args: dict[str, Any]) -> str:
        json_body = args.get("json_body")
        if isinstance(json_body, str) and json_body.lstrip().startswith(("{", "[")):
            try:
                parsed_json = json.loads(json_body)
            except ValueError:
                parsed_json = None
            if isinstance(parsed_json, (dict, list)):
                json_body = parsed_json
        form_body = args.get("form_body")
        if isinstance(form_body, str) and form_body.lstrip().startswith("{"):
            try:
                parsed_form = json.loads(form_body)
            except ValueError:
                parsed_form = None
            if isinstance(parsed_form, dict):
                form_body = parsed_form
        raw_body = args.get("raw_body")
        base_receipt_id = str(args.get("base_receipt_id") or "").strip()
        json_merge = args.get("json_merge") if isinstance(args.get("json_merge"), dict) else (
            args.get("mutate_json") if isinstance(args.get("mutate_json"), dict) else None
        )
        if base_receipt_id:
            merged_obj = self._load_receipt_json_object(base_receipt_id)
            if isinstance(json_body, dict):
                merged_obj = _deep_merge_json(merged_obj, json_body)
            if json_merge is not None:
                merged_obj = _deep_merge_json(merged_obj, json_merge)
            json_body = merged_obj
        elif json_merge is not None:
            if isinstance(json_body, dict):
                json_body = _deep_merge_json(json_body, json_merge)
            else:
                json_body = copy.deepcopy(json_merge)

        raw_method = str(args.get("method") or "").strip().upper()
        has_payload = (
            json_body is not None
            or form_body is not None
            or raw_body is not None
            or bool(base_receipt_id)
            or (json_merge is not None)
        )
        if raw_method:
            eff_method = raw_method
        elif has_payload and "POST" in self.http.allowed_methods:
            eff_method = "POST"
        else:
            eff_method = "GET"

        receipt = self.http.request(
            method=eff_method,
            url=str(args.get("url") or ""),
            actor=str(args.get("actor") or "anon"),
            headers=args.get("headers"),
            query=args.get("query"),
            json_body=json_body,
            form_body=form_body,
            raw_body=raw_body,
            force=bool(args.get("force", False)),
            save_session_as=str(args.get("save_session_as") or ""),
        )
        self._ingest_receipt_hooks(receipt)
        preview = _format_receipt_preview(receipt)
        if eff_method == "GET" and has_payload:
            preview["method_warning"] = (
                "GET request sent with request body; set method='POST' for form/JSON submissions."
            )
        status = int(receipt.get("status") or 0)
        ctype = (receipt.get("content_type") or "").lower()
        if 200 <= status < 400 and (
            "html" in ctype
            or "javascript" in ctype
            or "ecmascript" in ctype
            or "json" in ctype
            or "openapi" in ctype
        ):
            hints = _build_surface_hints(receipt, self.http.base_url)
            if hints:
                preview["surface_hints"] = hints
        return wrap_untrusted(preview)

    def _tool_read_receipt(self, args: dict[str, Any]) -> str:
        safe_limit = max(1, min(int(args.get("limit", DEFAULT_PREVIEW_CHARS)), 4096))
        res = self.receipts.read_slice(
            str(args.get("receipt_id") or ""),
            offset=int(args.get("offset", 0)),
            limit=safe_limit,
            regex=str(args.get("regex") or ""),
        )
        if isinstance(res, dict) and "offset" in res and "returned_chars" in res:
            res["next_offset"] = int(res["offset"]) + int(res["returned_chars"])
        return wrap_untrusted(res)

    def _tool_replay_as(self, args: dict[str, Any]) -> str:
        baseline = self.receipts.get(str(args.get("receipt_id") or ""))
        target_actor = str(args.get("actor") or baseline["actor"])
        method = str(args.get("method") or baseline["method"]).upper()
        url = str(args.get("url") or baseline["url"])

        # Preserve safe non-auth request headers when replaying.
        req_headers: dict[str, str] = {}
        for k, v in (baseline.get("request_headers") or {}).items():
            if k.lower() not in _SKIP_REPLAY_HEADERS and "<REDACTED" not in str(v):
                req_headers[k] = str(v)
        if isinstance(args.get("header_overrides"), dict):
            for k, v in args["header_overrides"].items():
                req_headers[str(k)] = str(v)

        query_overrides = args.get("query_overrides") if isinstance(args.get("query_overrides"), dict) else None
        json_overrides = args.get("json_overrides") if isinstance(args.get("json_overrides"), dict) else None
        json_merge = args.get("json_merge") if isinstance(args.get("json_merge"), dict) else (
            args.get("mutate_json") if isinstance(args.get("mutate_json"), dict) else None
        )
        patch_obj: dict[str, Any] | None = None
        if json_overrides is not None and json_merge is not None:
            patch_obj = _deep_merge_json(json_overrides, json_merge)
        elif json_merge is not None:
            patch_obj = json_merge
        elif json_overrides is not None:
            patch_obj = json_overrides

        base_receipt_id = str(args.get("base_receipt_id") or "").strip()
        json_body = None
        raw_body = None
        base_body_str = baseline.get("request_body") or ""
        if base_receipt_id:
            base_obj = self._load_receipt_json_object(base_receipt_id)
            json_body = _deep_merge_json(base_obj, patch_obj) if patch_obj is not None else base_obj
        elif patch_obj is not None:
            parsed: Any = None
            if base_body_str:
                try:
                    parsed = json.loads(base_body_str)
                except ValueError:
                    parsed = None
            elif baseline.get("method") == "GET" and method in {"PUT", "PATCH", "POST"}:
                # Preserve existing JSON fields from baseline GET response when mutating via PUT/PATCH/POST.
                try:
                    resp_parsed = json.loads(baseline.get("body") or "")
                    if isinstance(resp_parsed, dict):
                        parsed = resp_parsed
                except ValueError:
                    parsed = None
            if isinstance(parsed, dict):
                json_body = _deep_merge_json(parsed, patch_obj)
            else:
                json_body = copy.deepcopy(patch_obj)
        elif base_body_str:
            try:
                json_body = json.loads(base_body_str)
            except ValueError:
                raw_body = base_body_str

        current = self.http.request(
            method=method,
            url=url,
            actor=target_actor,
            headers=req_headers or None,
            query=query_overrides,
            json_body=json_body,
            raw_body=raw_body,
            force=bool(args.get("force", False)),
        )
        self.surface_tracker.ingest_receipt(baseline)
        self._ingest_receipt_hooks(current)
        out = {
            "baseline_receipt_id": baseline["receipt_id"],
            "baseline_actor": baseline["actor"],
            "replay": _format_receipt_preview(current, preview_chars=1800),
            "diff": _compute_structural_diff(baseline, current),
        }
        return wrap_untrusted(out)

    def _tool_extract_surface(self, args: dict[str, Any]) -> str:
        receipt = self.receipts.get(str(args.get("receipt_id") or ""))
        surface = _extract_surface_summary(receipt, self.http.base_url)
        self.surface_tracker.ingest_receipt(receipt)
        self.surface_tracker.ingest_surface(surface, actor=str(receipt.get("actor") or ""))
        if self.bsag is not None:
            dv1, de1 = self.bsag.ingest_receipt(receipt, mark_visited=False)
            dv2, de2 = self.bsag.ingest_surface(surface, actor=str(receipt.get("actor") or ""))
            self._step_delta_v += dv1 + dv2
            self._step_delta_e += de1 + de2
        compact_surface = {
            k: v
            for k, v in surface.items()
            if k in {"receipt_id", "url", "content_type"} or bool(v)
        }
        return wrap_untrusted(compact_surface)

    def _tool_notebook(self, args: dict[str, Any]) -> str:
        action = str(args.get("action") or "read").strip().lower()
        with self._notebook_lock:
            if action == "update" and args.get("surface_notes") is not None:
                self.notebook_state["surface_notes"] = str(args["surface_notes"])[:6000]
            elif action in {"add_hypothesis", "update_hypothesis"}:
                hyp = args.get("hypothesis")
                if not isinstance(hyp, dict) or not hyp.get("id"):
                    return json.dumps({"error": "hypothesis object with 'id' is required"})
                hid = str(hyp["id"])
                existing = [h for h in self.notebook_state["hypotheses"] if h.get("id") != hid]
                existing.append({
                    "id": hid,
                    "target": str(hyp.get("target") or ""),
                    "vuln_class": str(hyp.get("vuln_class") or ""),
                    "status": str(hyp.get("status") or "open"),
                    "notes": str(hyp.get("notes") or "")[:500],
                })
                self.notebook_state["hypotheses"] = existing[-50:]
            elif action == "add_note":
                note = str(args.get("note") or "").strip()
                if note:
                    self.notebook_state["notes"] = [*self.notebook_state.get("notes", []), note[:400]][-40:]
            elif action != "read":
                return json.dumps({"error": f"unsupported notebook action: {action}"})
            self._save_notebook()
            return json.dumps(self.notebook_state, ensure_ascii=False)

    def _tool_callback_listener(self, args: dict[str, Any]) -> str:
        action = str(args.get("action") or "").strip().lower()
        if action == "create_url":
            srv = self._get_oob_server(start=True)
            assert srv is not None
            info = srv.create_token(label=str(args.get("label") or ""))
            return json.dumps(info, ensure_ascii=False)
        if action == "poll":
            tok = str(args.get("token") or "").strip()
            srv = self._get_oob_server(start=False)
            if srv is None:
                return wrap_untrusted({
                    "token": tok,
                    "registered": False,
                    "hit_count": 0,
                    "total_hits": 0,
                    "hits": [],
                })
            return wrap_untrusted(srv.poll(tok))
        raise ValueError(f"unsupported callback_listener action: {action!r}; expected 'create_url' or 'poll'")

    def _tool_concurrent_check(self, args: dict[str, Any]) -> str:
        url = str(args.get("url") or "").strip()
        norm_method = str(args.get("method") or "GET").strip().upper()
        actor = str(args.get("actor") or "anon").strip() or "anon"

        raw_count = args.get("count", 3)
        if isinstance(raw_count, bool):
            raise ValueError("count must be an integer between 2 and 5")
        try:
            count_val = int(raw_count) if raw_count is not None else 3
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid count: {raw_count!r}") from exc
        count = max(2, min(5, count_val))

        if norm_method not in self.http.allowed_methods:
            raise MethodNotAllowedError(
                f"HTTP method {norm_method!r} not allowed; permitted: {sorted(self.http.allowed_methods)}"
            )
        headers = args.get("headers") if isinstance(args.get("headers"), dict) else None
        query = args.get("query") if isinstance(args.get("query"), dict) else None
        json_body = args.get("json_body")
        form_body = args.get("form_body") if isinstance(args.get("form_body"), dict) else None
        raw_body = str(args["raw_body"]) if args.get("raw_body") is not None else None

        clean_url, _, _ = self.http._merge_query(url, query)
        session = self.http.actors.get(actor)
        has_auth_override = any(str(k).lower() in {"authorization", "cookie"} for k in (headers or {}))
        if actor != "anon" and not has_auth_override and not session.authenticated:
            self.http.authenticate_actor(actor, force_login=False)

        remaining = self.http._budget_remaining()
        if remaining < count:
            raise BudgetExhaustedError(
                f"concurrent_check requires {count} HTTP requests, only {remaining} remaining in budget"
            )

        barrier = threading.Barrier(count, timeout=10.0)

        def _worker() -> dict[str, Any]:
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass
            return self.http.request(
                method=norm_method,
                url=url,
                actor=actor,
                headers=headers,
                query=query,
                json_body=json_body,
                form_body=form_body,
                raw_body=raw_body,
                force=True,
            )

        with ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(_worker) for _ in range(count)]
            receipts = [fut.result() for fut in futures]

        for rec in receipts:
            self._ingest_receipt_hooks(rec)

        status_counts: dict[str, int] = {}
        receipt_ids: list[str] = []
        distinct_hashes: list[str] = []
        seen_hashes: set[str] = set()
        results: list[dict[str, Any]] = []
        for rec in receipts:
            rid = str(rec.get("receipt_id") or "")
            st_key = str(int(rec.get("status") or 0))
            status_counts[st_key] = status_counts.get(st_key, 0) + 1
            if rid:
                receipt_ids.append(rid)
            sha = str(rec.get("response_sha256") or "")
            if sha and sha not in seen_hashes:
                seen_hashes.add(sha)
                distinct_hashes.append(sha)
            preview_body = str(rec.get("body") or "")[:300]
            item: dict[str, Any] = {
                "receipt_id": rid,
                "status": int(rec.get("status") or 0),
                "elapsed_ms": rec.get("elapsed_ms"),
                "response_sha256": sha[:16],
                "body_preview": preview_body if preview_body else "<empty>",
            }
            if rec.get("error"):
                item["error"] = rec["error"]
            results.append(item)

        return wrap_untrusted({
            "count": len(receipts),
            "method": norm_method,
            "url": clean_url,
            "actor": actor,
            "status_counts": status_counts,
            "receipt_ids": receipt_ids,
            "distinct_body_hashes": distinct_hashes,
            "results": results,
        })

    def _receipt_contains_evidence(self, receipt: dict[str, Any], evidence: str) -> tuple[bool, str]:
        needle = evidence.strip()
        lower_needle = needle.lower()
        body = receipt.get("body") or ""
        loc = receipt.get("redirect_location") or ""
        headers_text = json.dumps(receipt.get("response_headers") or {}, ensure_ascii=False)

        if needle in body or lower_needle in body.lower():
            return True, build_receipt_excerpt(receipt, needle, max_chars=MAX_PROOF_EXCERPT_CHARS)
        if needle in loc or lower_needle in loc.lower():
            return True, build_receipt_excerpt(receipt, needle, max_chars=MAX_PROOF_EXCERPT_CHARS)
        if lower_needle in headers_text.lower():
            return True, headers_text[:MAX_PROOF_EXCERPT_CHARS]
        return False, ""

    def _collect_oob_ssrf_context(
        self,
        proof_receipts: list[dict[str, Any]],
        evidence_value: str,
    ) -> tuple[str, list[str], list[dict[str, Any]]]:
        """Inspect proof receipts and evidence for callback_listener tokens/hits."""
        oob_srv = self._oob_server
        ev = str(evidence_value or "").strip()
        cb_pat = re.compile(r"/cb/([A-Za-z0-9_-]{6,})")
        cb_refs: list[str] = list(cb_pat.findall(ev))
        for rec in proof_receipts:
            req_blob = "\n".join([
                str(rec.get("url") or ""),
                str(rec.get("query") or ""),
                str(rec.get("request_body") or ""),
                json.dumps(rec.get("request_headers") or {}, ensure_ascii=False),
            ])
            cb_refs.extend(cb_pat.findall(req_blob))

        if oob_srv is None:
            if cb_refs:
                return "missing_server", list(dict.fromkeys(cb_refs)), []
            return "none", [], []

        reg_tokens = oob_srv.registered_tokens()
        matched_tokens: list[str] = []
        for tok in reg_tokens:
            if not tok:
                continue
            if tok in ev or any(
                tok in str(r.get("url") or "")
                or tok in str(r.get("query") or "")
                or tok in str(r.get("request_body") or "")
                or tok in json.dumps(r.get("request_headers") or {}, ensure_ascii=False)
                for r in proof_receipts
            ):
                matched_tokens.append(tok)

        if not matched_tokens and cb_refs:
            return "zero_hits", list(dict.fromkeys(cb_refs)), []
        if not matched_tokens:
            return "none", [], []

        matching_hits: list[dict[str, Any]] = []
        for tok in matched_tokens:
            polled = oob_srv.poll(tok)
            matching_hits.extend(polled.get("hits") or [])
        if not matching_hits:
            return "zero_hits", matched_tokens, []
        return "verified_hits", matched_tokens, matching_hits

    def _find_followup_persistent_get(
        self,
        *,
        primary: dict[str, Any],
        canonical_class: str,
        evidence_value: str,
        exclude_ids: set[str],
    ) -> dict[str, Any] | None:
        """Locate a newer 2xx GET render/persistence receipt in ReceiptStore for a write proof."""
        p_rid = str(primary.get("receipt_id") or "")
        p_seq = int(p_rid[4:]) if p_rid.startswith("req-") and p_rid[4:].isdigit() else 0
        p_ts = str(primary.get("timestamp") or "")
        ev = str(evidence_value or "").strip()
        candidates: list[dict[str, Any]] = []
        for rid in self.receipts.list_ids():
            if rid in exclude_ids:
                continue
            try:
                cand = self.receipts.get(rid)
            except (KeyError, ValueError):
                continue
            c_seq = int(rid[4:]) if rid.startswith("req-") and rid[4:].isdigit() else 0
            if p_seq > 0 and c_seq > 0:
                if c_seq <= p_seq:
                    continue
            elif p_ts and str(cand.get("timestamp") or "") < p_ts:
                continue
            if str(cand.get("method") or "").upper() != "GET":
                continue
            if not (200 <= int(cand.get("status") or 0) < 300):
                continue
            c_url = str(cand.get("url") or cand.get("path") or "")
            if not is_persistent_read_path_related(primary, c_url):
                continue
            if canonical_class == "stored_xss":
                if not is_html_receipt(cand):
                    continue
                if ev and not receipt_body_contains_verbatim(cand, ev):
                    continue
            elif ev and not self._receipt_contains_evidence(cand, ev)[0]:
                continue
            candidates.append(cand)
        if not candidates:
            return None
        return find_persistent_render_get_receipt(
            primary,
            candidates,
            ev,
            canonical_class=canonical_class,
        )

    def _try_merge_existing_finding_locked(
        self,
        *,
        canonical_class: str,
        route_template: str,
        raw_url: str,
        method: str,
        effective_actor: str,
        effective_norm_path: str,
        evidence_value: str,
        proof_ids: list[str],
        control_ids: list[str],
        actor_meta: dict[str, dict[str, str]],
    ) -> dict[str, Any] | None:
        """Merge into an existing finding sharing `(route_template, class_type)` under `_findings_lock`."""
        for existing in self.findings:
            existing_class = normalize_vuln_class(
                str(existing.get("class_type") or ""),
                method=str(existing.get("method") or ""),
                title=str(existing.get("title") or ""),
                summary=str(existing.get("summary") or ""),
            )
            existing_tmpl = str(
                existing.get("route_template")
                or normalize_route_template(str(existing.get("url") or existing.get("path") or ""))
            )
            same_or_overlap = existing_tmpl == route_template and (
                existing_class == canonical_class
                or ({existing_class, canonical_class} == {"auth_bypass", "bfla"})
            )
            if not same_or_overlap:
                continue

            merged_proof_ids = list(dict.fromkeys([*(existing.get("proof_receipt_ids") or []), *proof_ids]))
            merged_ctrl_ids = list(dict.fromkeys([*(existing.get("control_receipt_ids") or []), *control_ids]))
            all_proof_recs: list[dict[str, Any]] = []
            for rid in merged_proof_ids:
                try:
                    rec = self.receipts.get(rid)
                    if 200 <= int(rec.get("status", 0)) < 400:
                        all_proof_recs.append(rec)
                except (KeyError, ValueError):
                    continue
            all_ctrl_recs: list[dict[str, Any]] = []
            for rid in merged_ctrl_ids:
                try:
                    all_ctrl_recs.append(self.receipts.get(rid))
                except (KeyError, ValueError):
                    continue

            resolved_class = canonical_class
            if {existing_class, canonical_class} == {"auth_bypass", "bfla"}:
                resolved_class = _resolve_route_auth_bypass_vs_bfla(
                    route_template,
                    all_proof_recs,
                    all_ctrl_recs,
                    actor_meta_map=actor_meta,
                    receipt_store=self.receipts,
                    exact_path=effective_norm_path,
                    method=method,
                )
            existing["class_type"] = resolved_class
            existing["route_template"] = route_template
            existing["proof_receipt_ids"] = merged_proof_ids
            existing["control_receipt_ids"] = merged_ctrl_ids
            existing_ev = str(existing.get("evidence_value") or existing.get("marker") or "").strip()
            ex_score = score_evidence_value(existing_ev)
            in_score = score_evidence_value(evidence_value)
            ctrl_haystacks = _build_control_haystacks(all_ctrl_recs)
            if existing_ev and _value_in_controls(existing_ev, ctrl_haystacks) and ex_score < _HIGH_SPEC_THRESHOLD:
                ex_score = min(ex_score, 10)
            if evidence_value and _value_in_controls(evidence_value, ctrl_haystacks) and in_score < _HIGH_SPEC_THRESHOLD:
                in_score = min(in_score, 10)
            if not existing_ev or (in_score >= _HIGH_SPEC_THRESHOLD and in_score > ex_score) or (in_score >= ex_score + 15):
                ev_str = evidence_value
            else:
                ev_str = existing_ev
            if all_proof_recs and resolved_class not in {"open_redirect", "reflected_xss", "stored_xss"}:
                eligible_all = _filter_class_eligible_proofs(
                    resolved_class,
                    all_proof_recs,
                    all_ctrl_recs,
                    actor_meta_map=actor_meta,
                    receipt_store=self.receipts,
                    route_template=route_template,
                    evidence_value=ev_str,
                )
                promoted_ev, _ = _select_stronger_evidence_from_receipts(
                    resolved_class,
                    ev_str,
                    eligible_all,
                    all_ctrl_recs,
                )
                if promoted_ev:
                    ev_str = promoted_ev
            existing["evidence_value"] = ev_str
            existing["marker"] = ev_str

            if all_proof_recs:
                best, ordered_actors = select_primary_proof(
                    resolved_class,
                    all_proof_recs,
                    all_ctrl_recs,
                    actor_meta_map=actor_meta,
                    receipt_store=self.receipts,
                    route_template=route_template,
                    evidence_value=ev_str,
                )
                best_actor = str(best.get("actor") or effective_actor or "anon").strip() or "anon"
                existing["actor"] = best_actor
                existing["actor_alias"] = best_actor
                resolved_best_url, clean_best_path, _ = self.http.resolve_in_scope(best["url"] or raw_url)
                existing["observed_status"] = best["status"]
                existing["url"] = resolved_best_url
                existing["path"] = clean_best_path
                existing["method"] = best["method"]
                prior_actors = [str(a) for a in (existing.get("supporting_actors") or []) if str(a)]
                existing["supporting_actors"] = list(dict.fromkeys([*ordered_actors, *prior_actors]))
                existing["evidence_excerpts"] = [
                    {
                        "receipt_id": r["receipt_id"],
                        "actor": r["actor"],
                        "method": r["method"],
                        "url": r["url"],
                        "status": r["status"],
                        "excerpt": build_receipt_excerpt(r, ev_str, max_chars=MAX_PROOF_EXCERPT_CHARS),
                    }
                    for r in all_proof_recs
                ]
                existing["control_excerpts"] = [
                    {
                        "receipt_id": c["receipt_id"],
                        "actor": c["actor"],
                        "method": c["method"],
                        "url": c["url"],
                        "status": c["status"],
                        "excerpt": build_receipt_excerpt(c, "", max_chars=MAX_CONTROL_EXCERPT_CHARS),
                    }
                    for c in all_ctrl_recs
                ]
                existing["evidence"] = compose_finding_evidence(
                    best,
                    all_proof_recs,
                    all_ctrl_recs,
                    ev_str,
                    max_proof_chars=MAX_PROOF_EXCERPT_CHARS,
                    max_control_chars=MAX_CONTROL_EXCERPT_CHARS,
                )
            self._save_findings()
            return {
                "accepted": True,
                "duplicate": True,
                "merged": True,
                "finding_id": existing["finding_id"],
                "class_type": existing["class_type"],
                "primary_actor": existing.get("actor"),
                "supporting_actors": existing.get("supporting_actors", []),
            }
        return None

    def _tool_record_finding(self, args: dict[str, Any]) -> str:
        title = str(args.get("title") or "").strip()
        raw_class_type = str(args.get("class_type") or "").strip().lower().replace("-", "_")
        method = str(args.get("method") or "").strip().upper()
        raw_url = str(args.get("url") or "").strip()
        actor_alias = str(args.get("actor_alias") or args.get("actor") or "").strip()
        proof_ids = list(dict.fromkeys(str(r).strip() for r in (args.get("proof_receipt_ids") or []) if str(r).strip()))
        control_ids = list(dict.fromkeys(str(r).strip() for r in (args.get("control_receipt_ids") or []) if str(r).strip()))
        evidence_value = str(args.get("evidence_value") or "").strip()
        summary = str(args.get("summary") or "").strip()
        severity = str(args.get("severity") or "high").strip().lower()

        if not title or not raw_class_type or not method or not raw_url or not actor_alias or not summary:
            return json.dumps({"rejected": True, "reason": "all required string fields must be non-empty"})
        if not proof_ids or not control_ids:
            return json.dumps({"rejected": True, "reason": "both proof_receipt_ids and control_receipt_ids are required"})
        if set(proof_ids) & set(control_ids):
            return json.dumps({"rejected": True, "reason": "proof_receipt_ids and control_receipt_ids must not overlap"})

        canonical_class = normalize_vuln_class(raw_class_type, method=method, title=title, summary=summary)
        route_template = normalize_route_template(raw_url)
        actor_meta = self._actor_meta_map()

        try:
            proof_receipts = [self.receipts.get(rid) for rid in proof_ids]
            control_receipts = [self.receipts.get(rid) for rid in control_ids]
        except (KeyError, ValueError) as exc:
            return json.dumps({"rejected": True, "reason": str(exc)})

        # Resolve proof matching claimed actor_alias and target URL/path (anti-hallucination check).
        target_norm_path = _norm_path(raw_url)
        matching_proofs = [
            r for r in proof_receipts
            if r["actor"] == actor_alias and _norm_path(r["url"]) == target_norm_path
        ]
        if not matching_proofs:
            return json.dumps({
                "rejected": True,
                "reason": (
                    f"no proof receipt matches actor_alias={actor_alias!r} and path={target_norm_path!r}; "
                    f"proof receipts had: {[(r['receipt_id'], r['actor'], r['path']) for r in proof_receipts]}"
                ),
            })
        write_primary = matching_proofs[0]
        primary = write_primary
        if primary["method"] != method and not (canonical_class == "mass_assignment" and primary["method"] == "GET"):
            return json.dumps({
                "rejected": True,
                "reason": f"proof receipt {primary['receipt_id']} method {primary['method']} does not match {method}",
            })
        if not (200 <= primary["status"] < 400):
            return json.dumps({
                "rejected": True,
                "reason": f"primary proof receipt {primary['receipt_id']} has non-success status {primary['status']}",
            })

        # For persistent Write -> Read classes, auto-attach a newer 2xx GET render/persistence
        # receipt from ReceiptStore when the caller passed only the mutating write receipt.
        if (
            canonical_class in _PERSISTENT_VULN_CLASSES
            and str(write_primary.get("method") or "").upper() in _MUTATING_WRITE_METHODS
        ):
            existing_render = find_persistent_render_get_receipt(
                write_primary,
                proof_receipts,
                evidence_value,
                canonical_class=canonical_class,
            )
            if existing_render is None:
                followup_get = self._find_followup_persistent_get(
                    primary=write_primary,
                    canonical_class=canonical_class,
                    evidence_value=evidence_value,
                    exclude_ids=set(proof_ids) | set(control_ids),
                )
                if followup_get is not None:
                    proof_receipts.append(followup_get)
                    proof_ids.append(str(followup_get["receipt_id"]))

        def _is_compatible_proof_receipt(r: dict[str, Any]) -> bool:
            r_method = str(r.get("method") or "").upper()
            r_status = int(r.get("status") or 0)
            if not (200 <= r_status < 400):
                return False
            is_persistent_get = (
                canonical_class in _PERSISTENT_VULN_CLASSES
                and str(write_primary.get("method") or "").upper() in _MUTATING_WRITE_METHODS
                and r_method == "GET"
                and 200 <= r_status < 300
                and is_persistent_read_path_related(write_primary, str(r.get("url") or r.get("path") or ""))
            )
            if not is_persistent_get:
                if normalize_route_template(r["url"]) != route_template:
                    return False
                if r_method != method and not (canonical_class == "mass_assignment" and r_method == "GET"):
                    return False
            if canonical_class == "auth_bypass" and not _is_genuine_anon_2xx(r, actor_meta):
                return False
            return True

        compatible_proofs = [r for r in proof_receipts if _is_compatible_proof_receipt(r)]
        original_evidence_value = evidence_value
        excerpt = ""
        found_in_proof = False
        matching_oob_hits: list[dict[str, Any]] = []
        oob_matched_tokens: list[str] = []

        if canonical_class == "ssrf":
            oob_status, oob_matched_tokens, matching_oob_hits = self._collect_oob_ssrf_context(
                compatible_proofs or proof_receipts,
                evidence_value,
            )
            if oob_status in {"missing_server", "zero_hits"}:
                return json.dumps({
                    "rejected": True,
                    "reason": (
                        "SSRF callback claim rejected: callback_listener poll recorded 0 hits "
                        f"for submitted token(s) {oob_matched_tokens}"
                    ),
                })

        if not evidence_value or evidence_value.lower() in _TRIVIAL_EVIDENCE or len(evidence_value) < 3:
            if len(proof_receipts) > 1 and compatible_proofs:
                eligible_init = _filter_class_eligible_proofs(
                    canonical_class,
                    compatible_proofs,
                    control_receipts,
                    actor_meta_map=actor_meta,
                    receipt_store=self.receipts,
                    route_template=route_template,
                    evidence_value="",
                )
                promoted_ev, promoted_rec = _select_stronger_evidence_from_receipts(
                    canonical_class,
                    "",
                    eligible_init,
                    control_receipts,
                )
                if promoted_rec is not None and promoted_ev:
                    evidence_value = promoted_ev
                    primary = promoted_rec
                    excerpt = build_receipt_excerpt(primary, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)
                    found_in_proof = True
            if not evidence_value or evidence_value.lower() in _TRIVIAL_EVIDENCE or len(evidence_value) < 3:
                return json.dumps({"rejected": True, "reason": "evidence_value must be a real observed value, not a status/placeholder"})

        if not found_in_proof:
            if canonical_class == "ssrf" and matching_oob_hits:
                ev_low = evidence_value.lower()
                oob_hit_match = any(
                    tok == evidence_value
                    or tok in evidence_value
                    or ev_low in json.dumps(h, ensure_ascii=False).lower()
                    for tok in oob_matched_tokens
                    for h in matching_oob_hits
                )
                if oob_hit_match:
                    found_in_proof = True
                    hit0 = matching_oob_hits[0]
                    hit_summary = (
                        f"OOB callback hit: {hit0.get('method')} {hit0.get('path')} "
                        f"from {hit0.get('remote_addr')} body={hit0.get('body_preview', '')[:300]}"
                    )
                    base_ex = build_receipt_excerpt(primary, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS // 2)
                    excerpt = f"{base_ex}\n{hit_summary}"[:MAX_PROOF_EXCERPT_CHARS]
            if not found_in_proof and canonical_class == "stored_xss":
                get_candidates: list[dict[str, Any]] = []
                seen_get_rids: set[str] = set()
                for r in [primary, *compatible_proofs]:
                    rid = str(r.get("receipt_id") or "")
                    if rid in seen_get_rids:
                        continue
                    seen_get_rids.add(rid)
                    if str(r.get("method") or "").upper() == "GET" and 200 <= int(r.get("status") or 0) < 300:
                        get_candidates.append(r)
                html_get_candidates = [r for r in get_candidates if is_html_receipt(r)]
                if not html_get_candidates:
                    return json.dumps({
                        "rejected": True,
                        "reason": (
                            "stored_xss requires a 2xx text/html GET render receipt "
                            "containing evidence_value unescaped verbatim"
                        ),
                    })
                for r in html_get_candidates:
                    if receipt_body_contains_verbatim(r, evidence_value):
                        found_in_proof = True
                        primary = r
                        excerpt = build_receipt_excerpt(r, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)
                        break
                if not found_in_proof:
                    return json.dumps({
                        "rejected": True,
                        "reason": (
                            f"evidence_value {evidence_value!r} was not found unescaped verbatim "
                            "in HTML GET render receipt(s)"
                        ),
                    })
            else:
                # Verify evidence_value appears verbatim in matching_proofs first, then any compatible proof receipt.
                for r in matching_proofs:
                    ok, ex = self._receipt_contains_evidence(r, evidence_value)
                    if ok:
                        found_in_proof = True
                        excerpt = ex
                        primary = r
                        break
                if not found_in_proof:
                    for r in compatible_proofs:
                        ok, ex = self._receipt_contains_evidence(r, evidence_value)
                        if ok:
                            found_in_proof = True
                            excerpt = ex
                            primary = r
                            break
        if not found_in_proof:
            return json.dumps({
                "rejected": True,
                "reason": f"evidence_value {evidence_value!r} was not found verbatim in proof receipt(s) for {actor_alias}",
            })

        # Multi-receipt specificity promotion: upgrade generic/low-specificity evidence when another
        # class-eligible proof receipt exposes a strictly higher-specificity unique secret (not in controls).
        if (
            len(proof_receipts) > 1
            and compatible_proofs
            and canonical_class not in {"open_redirect", "reflected_xss", "stored_xss", "race_condition"}
            and not matching_oob_hits
        ):
            eligible_proofs = _filter_class_eligible_proofs(
                canonical_class,
                compatible_proofs,
                control_receipts,
                actor_meta_map=actor_meta,
                receipt_store=self.receipts,
                route_template=route_template,
                evidence_value=evidence_value,
            )
            promoted_ev, promoted_rec = _select_stronger_evidence_from_receipts(
                canonical_class,
                evidence_value,
                eligible_proofs,
                control_receipts,
            )
            if promoted_rec is not None and promoted_ev:
                evidence_value = promoted_ev
                primary = promoted_rec
                excerpt = build_receipt_excerpt(primary, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)

        effective_actor = str(primary.get("actor") or actor_alias).strip() or actor_alias
        effective_norm_path = _norm_path(primary["url"])

        # Class-specific anti-false-positive checks.
        if canonical_class == "open_redirect":
            loc = primary.get("redirect_location") or ""
            if not (300 <= primary["status"] < 400 and loc):
                return json.dumps({"rejected": True, "reason": "open_redirect requires 3xx status with Location header"})
            loc_host = urlsplit(loc).netloc
            base_host = urlsplit(self.http.base_url).netloc
            if not loc_host or loc_host == base_host:
                return json.dumps({"rejected": True, "reason": f"redirect Location {loc!r} is not an external host"})
            if all(urlsplit(c.get("redirect_location") or "").netloc == loc_host for c in control_receipts):
                return json.dumps({"rejected": True, "reason": "control receipt also redirected to same external host"})

        elif canonical_class in {"reflected_xss", "stored_xss"}:
            ctype = (primary.get("content_type") or "").lower()
            if "json" in ctype:
                return json.dumps({"rejected": True, "reason": "JSON content-type reflection is not executable HTML XSS"})
            if canonical_class == "stored_xss" and not is_html_receipt(primary):
                return json.dumps({"rejected": True, "reason": "stored_xss requires HTML (text/html) content-type on render GET receipt"})
            if not any(c.get("response_sha256") != primary.get("response_sha256") for c in control_receipts):
                return json.dumps({"rejected": True, "reason": "control receipt is identical to proof receipt"})
            p_body = str(primary.get("body") or "")
            needle_low = evidence_value.lower()
            p_count = p_body.lower().count(needle_low)
            ctrl_pool = (
                [c for c in control_receipts if str(c.get("method") or "").upper() == "GET"] or control_receipts
                if canonical_class == "stored_xss"
                else control_receipts
            )
            c_counts = [str(c.get("body") or "").lower().count(needle_low) for c in ctrl_pool]
            if c_counts and p_count <= min(c_counts):
                return json.dumps({
                    "rejected": True,
                    "reason": (
                        f"evidence_value {evidence_value!r} appears {p_count} time(s) in proof and "
                        f"{min(c_counts)} time(s) in control receipt (static template markup); "
                        "specify the exact reflected payload string that only appears in the proof response"
                    ),
                })

        elif canonical_class in {"sqli", "sqli_read"}:
            if not any(
                c.get("response_sha256") != primary.get("response_sha256") or c.get("status") != primary.get("status")
                for c in control_receipts
            ):
                return json.dumps({"rejected": True, "reason": "SQLi requires differential between proof and control receipts"})

        elif canonical_class == "auth_bypass":
            # Strictly require primary proof receipt executed by 'anon' with substantive 2xx response.
            if effective_actor != "anon" or str(primary.get("actor") or "") != "anon":
                return json.dumps({
                    "rejected": True,
                    "reason": (
                        f"auth_bypass requires primary proof receipt executed by 'anon' (got actor_alias={effective_actor!r}); "
                        "use 'bfla' when anon is denied (401/403) and a non-admin authenticated actor gets 200"
                    ),
                })
            if not (200 <= int(primary.get("status") or 0) < 300):
                return json.dumps({
                    "rejected": True,
                    "reason": f"auth_bypass requires a substantive 2xx response from 'anon' (got status {primary.get('status')})",
                })
            if not _is_genuine_anon_2xx(primary, actor_meta):
                return json.dumps({
                    "rejected": True,
                    "reason": "auth_bypass rejected: public HTML landing/login page, empty body, or non-anon actor identity header present",
                })
            if not any(c["actor"] != "anon" for c in control_receipts):
                return json.dumps({"rejected": True, "reason": "anon auth_bypass requires an authenticated baseline control receipt"})

        elif canonical_class in {"bfla", "bola", "tenant_isolation"}:
            if canonical_class == "bfla" and effective_actor == "anon":
                # If anon genuinely got 2xx on protected data, it is auth_bypass, not bfla.
                if _is_genuine_anon_2xx(primary, actor_meta):
                    canonical_class = "auth_bypass"
                else:
                    return json.dumps({
                        "rejected": True,
                        "reason": "bfla requires an authenticated non-admin proof receipt (not 'anon')",
                    })
            if effective_actor != "anon":
                if not any(
                    c["actor"] != effective_actor or _norm_path(c["url"]) != effective_norm_path or c["status"] != primary["status"]
                    for c in control_receipts
                ):
                    return json.dumps({"rejected": True, "reason": "access-control finding requires cross-actor or differential control receipt"})

        elif canonical_class == "mass_assignment":
            if not any(c.get("response_sha256") != primary.get("response_sha256") or c["method"] != primary["method"] or c["actor"] == effective_actor for c in control_receipts):
                return json.dumps({"rejected": True, "reason": "mass_assignment requires baseline control receipt"})

        elif canonical_class in {"race_condition", "business_logic"}:
            if canonical_class == "race_condition":
                distinct_success_rids = {
                    str(r.get("receipt_id") or "")
                    for r in compatible_proofs
                    if r.get("receipt_id") and 200 <= int(r.get("status") or 0) < 400
                }
                if len(distinct_success_rids) < 2:
                    return json.dumps({
                        "rejected": True,
                        "reason": "race_condition requires at least 2 distinct 2xx/3xx proof receipts (e.g. from concurrent_check)",
                    })
            if not any(
                c.get("status") != primary.get("status")
                or c.get("response_sha256") != primary.get("response_sha256")
                or str(c.get("method") or "").upper() != str(primary.get("method") or "").upper()
                or c.get("actor") != effective_actor
                for c in control_receipts
            ):
                return json.dumps({
                    "rejected": True,
                    "reason": f"{canonical_class} requires a differential sequential or state control receipt",
                })

        # Collect all valid proofs among proof_receipts (across actors) on the same route_template.
        valid_proof_records: list[tuple[dict[str, Any], str]] = [(primary, excerpt)]
        seen_rids = {primary["receipt_id"]}
        for r in proof_receipts:
            if r["receipt_id"] in seen_rids:
                continue
            if not _is_compatible_proof_receipt(r):
                continue
            ok, ex = self._receipt_contains_evidence(r, evidence_value)
            if not ok and original_evidence_value and original_evidence_value != evidence_value:
                ok, ex = self._receipt_contains_evidence(r, original_evidence_value)
            if (
                not ok
                and canonical_class in _PERSISTENT_VULN_CLASSES
                and str(r.get("method") or "").upper() in _MUTATING_WRITE_METHODS
                and _norm_path(r["url"]) == target_norm_path
                and 200 <= int(r.get("status") or 0) < 400
            ):
                ok = True
                ex = build_receipt_excerpt(r, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)
            if not ok and len(proof_receipts) > 1 and canonical_class not in {"open_redirect", "reflected_xss", "stored_xss"}:
                ok = True
                ex = build_receipt_excerpt(r, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)
            if ok:
                valid_proof_records.append((r, ex))
                seen_rids.add(r["receipt_id"])

        valid_receipts_only = [r for r, _ in valid_proof_records]

        # For bola / tenant_isolation: ensure proof receipt shows another owner's data rather than the caller's own record.
        inferred_bola_owner = ""
        if canonical_class in {"bola", "tenant_isolation"}:
            explicit_owner, explicit_tenant = _extract_record_owner_and_tenant(primary, actor_meta)
            inferred_owner = _infer_owner_actor(
                valid_receipts_only,
                control_receipts,
                receipt_store=self.receipts,
                route_template=route_template,
                evidence_value=evidence_value,
                actor_meta_map=actor_meta,
                target_path=effective_norm_path,
            )
            eff_owner = explicit_owner or inferred_owner
            inferred_bola_owner = eff_owner
            if eff_owner and all(str(r.get("actor") or "") == eff_owner for r in valid_receipts_only):
                return json.dumps({
                    "rejected": True,
                    "reason": (
                        f"proof receipt shows {eff_owner!r}'s own record accessed by {eff_owner!r}; "
                        f"{canonical_class} requires a proof receipt executed by a non-owner peer/cross-tenant actor accessing another owner's data"
                    ),
                })
            if canonical_class == "tenant_isolation" and explicit_tenant:
                caller_tenant = str((actor_meta.get(effective_actor) or {}).get("tenant") or "").lower()
                if caller_tenant and caller_tenant == explicit_tenant:
                    if eff_owner and eff_owner != effective_actor:
                        canonical_class = "bola"
                    else:
                        return json.dumps({
                            "rejected": True,
                            "reason": (
                                f"proof receipt record belongs to caller's own tenant ({explicit_tenant!r}); "
                                "tenant_isolation requires accessing a record owned by a different tenant"
                            ),
                        })

        # Resolve auth_bypass <-> bfla bidirectionally and deterministically from observed receipts.
        if canonical_class == "bfla":
            anon_rec, anon_denied = _find_exact_route_anon_2xx(
                effective_norm_path,
                method,
                valid_receipts_only,
                control_receipts,
                actor_meta_map=actor_meta,
                receipt_store=self.receipts,
                evidence_value=evidence_value,
            )
            if anon_rec is not None and not anon_denied:
                canonical_class = "auth_bypass"
                anon_rid = str(anon_rec.get("receipt_id") or "")
                if anon_rid and anon_rid not in seen_rids:
                    anon_ex = build_receipt_excerpt(anon_rec, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)
                    valid_proof_records.append((anon_rec, anon_ex))
                    valid_receipts_only.append(anon_rec)
                    seen_rids.add(anon_rid)
                if anon_rid and anon_rid not in proof_ids and anon_rid not in control_ids:
                    proof_ids.append(anon_rid)
                if evidence_value and not _receipt_contains_value(anon_rec, evidence_value):
                    promoted_anon_ev, _ = _select_stronger_evidence_from_receipts(
                        "auth_bypass",
                        "",
                        [anon_rec],
                        control_receipts,
                    )
                    if promoted_anon_ev:
                        evidence_value = promoted_anon_ev
        elif canonical_class == "auth_bypass":
            resolved_cls = _resolve_route_auth_bypass_vs_bfla(
                route_template,
                valid_receipts_only,
                control_receipts,
                actor_meta_map=actor_meta,
                receipt_store=self.receipts,
                exact_path=effective_norm_path,
                method=method,
            )
            if resolved_cls == "bfla":
                return json.dumps({
                    "rejected": True,
                    "reason": (
                        f"route {route_template} denied 'anon' (401/403) in observed receipts while allowing authenticated non-admin access; "
                        "record this finding as 'bfla' with the non-admin authenticated actor"
                    ),
                })
            canonical_class = resolved_cls

        excerpt_by_rid = {r["receipt_id"]: ex for r, ex in valid_proof_records}

        # Deduplicate & merge by route_template for auth_bypass/bfla overlap or identical canonical_class.
        with self._findings_lock:
            merged_resp = self._try_merge_existing_finding_locked(
                canonical_class=canonical_class,
                route_template=route_template,
                raw_url=raw_url,
                method=method,
                effective_actor=effective_actor,
                effective_norm_path=effective_norm_path,
                evidence_value=evidence_value,
                proof_ids=proof_ids,
                control_ids=control_ids,
                actor_meta=actor_meta,
            )
            if merged_resp is not None:
                return json.dumps(merged_resp)

        best_primary, ordered_actors = select_primary_proof(
            canonical_class,
            valid_receipts_only,
            control_receipts,
            actor_meta_map=actor_meta,
            receipt_store=self.receipts,
            route_template=route_template,
            evidence_value=evidence_value,
        )
        best_actor = str(best_primary.get("actor") or actor_alias or "anon").strip() or "anon"

        if canonical_class == "bola" and self.oracle is None:
            bola_fp = check_bola_false_positive(
                primary_proof=best_primary,
                proof_receipts=valid_receipts_only,
                control_receipts=control_receipts,
                actor_meta_map=actor_meta,
                receipt_store=self.receipts,
                surface_tracker=self.surface_tracker,
                inferred_owner=inferred_bola_owner,
            )
            if bola_fp is not None:
                return json.dumps({"rejected": True, "reason": bola_fp[1]})

        self._step_claim_submitted = True
        oracle_verdict_str = "verified"
        clean_replay_rid = ""
        if self.oracle is not None:
            ep_node_id = f"ep:{route_template}"
            hyp_id = ""
            if self.bsag is not None:
                ep_n, ep_dv = self.bsag.ensure_endpoint(best_primary["url"] or raw_url, method=best_primary["method"])
                ep_node_id = ep_n.node_id
                self._step_delta_v += ep_dv
                hyp_node, h_dv, h_de = self.bsag.register_hypothesis(
                    endpoint_node_id=ep_node_id,
                    category=self.active_category or canonical_class,
                    vuln_class=canonical_class,
                    actor=best_actor,
                    summary=summary,
                    status="CLAIMED",
                    proof_receipt_ids=proof_ids,
                    control_receipt_ids=control_ids,
                    evidence_value=evidence_value,
                )
                hyp_id = hyp_node.node_id
                self._step_delta_v += h_dv
                self._step_delta_e += h_de
            verdict = self.oracle.verify(
                canonical_class=canonical_class,
                primary_proof=best_primary,
                proof_receipts=valid_receipts_only,
                control_receipts=control_receipts,
                evidence_value=evidence_value,
                actor_meta_map=actor_meta,
                surface_tracker=self.surface_tracker,
                inferred_owner=inferred_bola_owner,
                oob_server=self._oob_server,
                oob_hits=matching_oob_hits,
            )
            if self.bsag is not None and hyp_id:
                self.bsag.apply_oracle_verdict(
                    hypothesis_id=hyp_id,
                    endpoint_node_id=ep_node_id,
                    verdict=verdict.verdict,
                    reason=verdict.reason,
                    deception_detected=verdict.deception_detected,
                )
            if self.telemetry is not None:
                self.telemetry.emit(
                    "oracle_verdict",
                    worker_id=self.active_worker_id,
                    hypothesis_id=hyp_id,
                    node_id=ep_node_id,
                    class_type=canonical_class,
                    verdict=verdict.verdict,
                    deception_detected=verdict.deception_detected,
                    mode=verdict.mode,
                    stages=verdict.stages,
                    clean_replay_receipt_id=verdict.clean_replay_receipt_id,
                )
            if not verdict.verified:
                return json.dumps({
                    "rejected": True,
                    "oracle_verdict": verdict.verdict,
                    "deception_detected": verdict.deception_detected,
                    "reason": verdict.reason,
                    "stages": verdict.stages,
                })
            oracle_verdict_str = verdict.verdict
            clean_replay_rid = verdict.clean_replay_receipt_id

        best_evidence = compose_finding_evidence(
            best_primary,
            valid_receipts_only,
            control_receipts,
            evidence_value,
            max_proof_chars=MAX_PROOF_EXCERPT_CHARS,
            max_control_chars=MAX_CONTROL_EXCERPT_CHARS,
        )
        if matching_oob_hits:
            hit0 = matching_oob_hits[0]
            oob_note = (
                f"---[oob_callback:token={hit0.get('token')} hits={len(matching_oob_hits)}]---\n"
                f"{hit0.get('method')} {hit0.get('path')} query={hit0.get('query') or ''} "
                f"remote={hit0.get('remote_addr')} body={hit0.get('body_preview') or ''}"
            )
            best_evidence = f"{best_evidence}\n{oob_note}" if best_evidence else oob_note
        resolved_url, clean_path, _ = self.http.resolve_in_scope(best_primary["url"] or raw_url)
        with self._findings_lock:
            merged_resp = self._try_merge_existing_finding_locked(
                canonical_class=canonical_class,
                route_template=route_template,
                raw_url=raw_url,
                method=method,
                effective_actor=effective_actor,
                effective_norm_path=effective_norm_path,
                evidence_value=evidence_value,
                proof_ids=proof_ids,
                control_ids=control_ids,
                actor_meta=actor_meta,
            )
            if merged_resp is not None:
                return json.dumps(merged_resp)

            finding_id = f"F-{len(self.findings) + 1:03d}"
            finding = {
                "finding_id": finding_id,
                "title": title,
                "class_type": canonical_class,
                "route_template": route_template,
                "method": best_primary["method"],
                "url": resolved_url,
                "path": clean_path,
                "actor": best_actor,
                "actor_alias": best_actor,
                "observed_status": best_primary["status"],
                "status": "verified",
                "oracle_verdict": oracle_verdict_str,
                "clean_replay_receipt_id": clean_replay_rid,
                "severity": severity if severity in {"critical", "high", "medium", "low"} else "high",
                "evidence_value": evidence_value,
                "marker": evidence_value,
                "evidence": best_evidence or excerpt_by_rid.get(best_primary["receipt_id"], excerpt),
                "summary": summary,
                "proof_receipt_ids": proof_ids,
                "control_receipt_ids": control_ids,
                "supporting_actors": ordered_actors,
                "evidence_excerpts": [
                    {
                        "receipt_id": r["receipt_id"],
                        "actor": r["actor"],
                        "method": r["method"],
                        "url": r["url"],
                        "status": r["status"],
                        "excerpt": ex[:MAX_PROOF_EXCERPT_CHARS],
                    }
                    for r, ex in valid_proof_records
                ],
                "control_excerpts": [
                    {
                        "receipt_id": c["receipt_id"],
                        "actor": c["actor"],
                        "method": c["method"],
                        "url": c["url"],
                        "status": c["status"],
                        "excerpt": build_receipt_excerpt(c, "", max_chars=MAX_CONTROL_EXCERPT_CHARS),
                    }
                    for c in control_receipts
                ],
            }
            self.findings.append(finding)
            self._save_findings()
            total_findings = len(self.findings)
        return json.dumps({
            "accepted": True,
            "finding_id": finding_id,
            "class_type": canonical_class,
            "primary_actor": best_actor,
            "total_findings": total_findings,
        })

    def _tool_finish(self, args: dict[str, Any]) -> str:
        http_rem = self.http.budget.limit - self.http.budget.used
        rem_ratio = http_rem / max(1, self.http.budget.limit)
        if (
            self.coverage_gate_enabled
            and rem_ratio > 0.30
            and self.finish_rejections < self.max_finish_rejections
            and self.surface_tracker.has_high_value_frontier()
        ):
            self.finish_rejections += 1
            frontier = self.surface_tracker.high_value_frontier()
            return json.dumps({
                "finished": False,
                "rejected": True,
                "nudge_count": self.finish_rejections,
                "max_nudges": self.max_finish_rejections,
                "http_budget_remaining": http_rem,
                "http_budget_limit": self.http.budget.limit,
                "http_budget_remaining_pct": round(rem_ratio * 100, 1),
                "reason": (
                    f"Premature finish rejected ({self.finish_rejections}/{self.max_finish_rejections}): "
                    f"{round(rem_ratio * 100, 1)}% HTTP budget remaining ({http_rem}/{self.http.budget.limit}) "
                    "and high-value attack-surface frontier items remain untested. "
                    "Test the remaining_frontier items before calling finish."
                ),
                "remaining_frontier": frontier,
            })
        elif (
            self.discovery_finish_gate
            and rem_ratio > 0.20
            and self.finish_rejections < self.max_finish_rejections
        ):
            non_anon_actors = [a for a in self.surface_tracker.actors if a != "anon"]
            if self._auth_barrier_or_write_seen and (len(non_anon_actors) == 0 or self._non_anon_2xx_reads == 0):
                self.finish_rejections += 1
                return json.dumps({
                    "finished": False,
                    "rejected": True,
                    "nudge_count": self.finish_rejections,
                    "max_nudges": self.max_finish_rejections,
                    "http_budget_remaining": http_rem,
                    "http_budget_limit": self.http.budget.limit,
                    "http_budget_remaining_pct": round(rem_ratio * 100, 1),
                    "reason": (
                        f"Premature finish rejected ({self.finish_rejections}/{self.max_finish_rejections}): "
                        f"{round(rem_ratio * 100, 1)}% HTTP budget remaining ({http_rem}/{self.http.budget.limit}). "
                        "Auth barriers, redirects, or write/form endpoints were observed without an authenticated "
                        "post-auth GET 2xx crawl yet; register/sign in an actor via "
                        "http_request(method='POST', ..., save_session_as=...) and fetch post-auth pages before calling finish."
                    ),
                })

        self.finished = True
        self.finish_summary = str(args.get("summary") or "").strip()
        raw_untested = args.get("untested_areas")
        self.untested_areas = [str(x) for x in raw_untested] if isinstance(raw_untested, list) else []
        with self._findings_lock:
            total_findings = len(self.findings)
        return json.dumps({
            "finished": True,
            "total_findings": total_findings,
            "untested_areas": self.untested_areas,
        })
