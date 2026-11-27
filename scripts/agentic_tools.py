"""General-purpose investigation and QA verification tools with anti-hallucination verification."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import inspect
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, Callable, Sequence
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit
import uuid

from full_agent_budget import compact_json_text

from agentic_fact_graph import VALID_FACT_TYPES, SharedFactGraph, _scrub_secret_text

from agentic_evidence import (
    MAX_CONTROL_EXCERPT_CHARS as MAX_CONTROL_EXCERPT_CHARS,
    MAX_PROOF_EXCERPT_CHARS as MAX_PROOF_EXCERPT_CHARS,
    _ACTOR_IDENTITY_HEADERS as _ACTOR_IDENTITY_HEADERS,
    _ADMIN_ROLE_TOKENS as _ADMIN_ROLE_TOKENS,
    _CLASS_ALIASES as _CLASS_ALIASES,
    _HEX_ID_SEG_RE as _HEX_ID_SEG_RE,
    _HEX_SEGMENT_RE as _HEX_SEGMENT_RE,
    _HIGH_SPEC_THRESHOLD as _HIGH_SPEC_THRESHOLD,
    _IGNORED_EVIDENCE_JSON_KEYS as _IGNORED_EVIDENCE_JSON_KEYS,
    _IGNORED_EVIDENCE_KEY_PREFIXES as _IGNORED_EVIDENCE_KEY_PREFIXES,
    _IGNORED_EVIDENCE_KEY_SUFFIXES as _IGNORED_EVIDENCE_KEY_SUFFIXES,
    _ISO_TIMESTAMP_RE as _ISO_TIMESTAMP_RE,
    _JWT_FULL_RE as _JWT_FULL_RE,
    _LOWER_SLUG_YEAR_RE as _LOWER_SLUG_YEAR_RE,
    _PREFIXED_ID_SEG_RE as _PREFIXED_ID_SEG_RE,
    _PUBLIC_LANDING_PATHS as _PUBLIC_LANDING_PATHS,
    _RAW_TOKEN_SCAN_RE as _RAW_TOKEN_SCAN_RE,
    _READ_SQLI_HINTS as _READ_SQLI_HINTS,
    _READONLY_ROLES as _READONLY_ROLES,
    _RECORD_OWNER_KEYS as _RECORD_OWNER_KEYS,
    _RECORD_TENANT_KEYS as _RECORD_TENANT_KEYS,
    _SENSITIVE_JSON_EXACT_KEYS as _SENSITIVE_JSON_EXACT_KEYS,
    _SENSITIVE_JSON_KEY_PREFIXES as _SENSITIVE_JSON_KEY_PREFIXES,
    _SENSITIVE_JSON_KEY_SUFFIXES as _SENSITIVE_JSON_KEY_SUFFIXES,
    _SEVERITY_RANK as _SEVERITY_RANK,
    _SQLI_EVIDENCE_HINTS as _SQLI_EVIDENCE_HINTS,
    _STATE_TAMPERING_CLASS_RANK as _STATE_TAMPERING_CLASS_RANK,
    _TEMPLATE_SEG_RE as _TEMPLATE_SEG_RE,
    _TRIVIAL_EVIDENCE as _TRIVIAL_EVIDENCE,
    _UUID_FULL_RE as _UUID_FULL_RE,
    _UUID_SEG_RE as _UUID_SEG_RE,
    _XSS_EVENT_HINTS as _XSS_EVENT_HINTS,
    _actor_priority_key as _actor_priority_key,
    _best_secret_for_receipt as _best_secret_for_receipt,
    _build_control_haystacks as _build_control_haystacks,
    _canonical_entry_rank as _canonical_entry_rank,
    _extract_receipt_secret_candidates as _extract_receipt_secret_candidates,
    _extract_record_owner_and_tenant as _extract_record_owner_and_tenant,
    _filter_class_eligible_proofs as _filter_class_eligible_proofs,
    _find_exact_route_anon_2xx as _find_exact_route_anon_2xx,
    _infer_owner_actor as _infer_owner_actor,
    _is_admin_role as _is_admin_role,
    _is_genuine_anon_2xx as _is_genuine_anon_2xx,
    _is_hex_secret_token as _is_hex_secret_token,
    _is_high_entropy_token as _is_high_entropy_token,
    _is_ignored_json_key as _is_ignored_json_key,
    _is_readonly_role as _is_readonly_role,
    _is_sensitive_json_key as _is_sensitive_json_key,
    _norm_path as _norm_path,
    _receipt_contains_value as _receipt_contains_value,
    _record_route_aliases as _record_route_aliases,
    _resolve_alias_or_family_overlap as _resolve_alias_or_family_overlap,
    _resolve_cross_class_overlap as _resolve_cross_class_overlap,
    _resolve_route_auth_bypass_vs_bfla as _resolve_route_auth_bypass_vs_bfla,
    _select_stronger_evidence_from_receipts as _select_stronger_evidence_from_receipts,
    _severity_rank as _severity_rank,
    _shannon_entropy as _shannon_entropy,
    _value_in_controls as _value_in_controls,
    build_receipt_excerpt as build_receipt_excerpt,
    canonicalize_and_deduplicate_findings as canonicalize_and_deduplicate_findings,
    compose_finding_evidence as compose_finding_evidence,
    normalize_route_template as normalize_route_template,
    normalize_vuln_class as normalize_vuln_class,
    score_evidence_value as score_evidence_value,
    select_primary_proof as select_primary_proof,
    strip_single_api_prefix as strip_single_api_prefix,
)
from agentic_browser import (
    inspect_rendered_page as inspect_rendered_page,
    run_browser_crawl as run_browser_crawl,
    verify_dom_sink_in_browser as verify_dom_sink_in_browser,
)
from agentic_crypto import (
    _b64url_decode_segment as _b64url_decode_segment,
    _sanitize_claims as _sanitize_claims,
    _strip_bearer as _strip_bearer,
    analyze_jwt as analyze_jwt,
    analyze_token as analyze_token,
    build_jwt_test_variants as build_jwt_test_variants,
)
from agentic_http import (
    AgenticHTTPClient,
    BudgetExhaustedError,
    MethodNotAllowedError,
    ScopeViolationError,
    ServiceDegradationError,
    is_static_asset_url as is_static_asset_url,
)
from agentic_oob import LoopbackCallbackServer
from agentic_waf import (
    WAFPivotTracker,
    detect_waf_block as detect_waf_block,
)
from agentic_oracle import (
    check_bola_false_positive,
    find_persistent_render_get_receipt,
    is_html_receipt,
    is_persistent_read_path_related,
    receipt_body_contains_verbatim,
)
from agentic_preview import (
    _EVENT_OR_JS_RE as _EVENT_OR_JS_RE,
    _HTML_COMMENT_RE as _HTML_COMMENT_RE,
    _HTML_TAG_RE as _HTML_TAG_RE,
    _ID_KEY_HINTS as _ID_KEY_HINTS,
    _ID_VALUE_RE as _ID_VALUE_RE,
    _REPO_ROOT as _REPO_ROOT,
    _SCRIPT_BLOCK_RE as _SCRIPT_BLOCK_RE,
    _STYLE_BLOCK_RE as _STYLE_BLOCK_RE,
    _SVG_CLOSE_RE as _SVG_CLOSE_RE,
    _SVG_OPEN_RE as _SVG_OPEN_RE,
    _TAG_ATTR_RE as _TAG_ATTR_RE,
    LocalSchema as LocalSchema,
    _build_surface_hints as _build_surface_hints,
    _compute_structural_diff as _compute_structural_diff,
    _extract_candidate_ids as _extract_candidate_ids,
    _extract_openapi_operations as _extract_openapi_operations,
    _extract_surface_summary as _extract_surface_summary,
    _find_tag_end as _find_tag_end,
    _flatten_json_keys as _flatten_json_keys,
    _format_receipt_preview as _format_receipt_preview,
    _notable_headers as _notable_headers,
    _strip_inline_style_attrs as _strip_inline_style_attrs,
    _strip_passive_svgs as _strip_passive_svgs,
    extract_css as extract_css,
    extract_html as extract_html,
    extract_http_headers as extract_http_headers,
    extract_inline_scripts as extract_inline_scripts,
    extract_js as extract_js,
    extract_js_calls as extract_js_calls,
    extract_json_hypermedia as extract_json_hypermedia,
    extract_robots as extract_robots,
    extract_sitemap as extract_sitemap,
    extract_spa_routes as extract_spa_routes,
    find_spec_urls as find_spec_urls,
    prune_html_for_preview as prune_html_for_preview,
)
from agentic_receipts import DEFAULT_PREVIEW_CHARS, ReceiptStore, redact_headers, redact_secrets
from agentic_sandbox import run_python_pure_sandbox
from agentic_surface import SurfaceFrontierTracker, is_virgin_state_sensitive_path
from kryon_core.surface.openapi import extract_openapi_header_auth_names

_SKIP_REPLAY_HEADERS = frozenset({
    "authorization",
    "cookie",
    "x-access-token",
    "x-auth-token",
    "x-api-key",
    "x-token",
    "x-session-token",
    "x-api-token",
    "x-csrf-token",
    "x-csrftoken",
    "x-xsrf-token",
    "content-length",
    "host",
})
_HTTP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$")
_PERSISTENT_VULN_CLASSES = frozenset({"stored_xss", "mass_assignment", "ssti"})
_OOB_CALLBACK_CLASSES = frozenset({"ssrf", "xxe", "ssti", "command_injection", "insecure_deserialization"})
_MUTATING_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
_URL_SCAN_RE = re.compile(r"https?://[^\s\"'<>\\)`]+", re.IGNORECASE)
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "0.0.0.0", "localhost.localdomain"})
_BYPASS_EVASION_HEADER_NAMES = frozenset({
    "x-forwarded-for",
    "x-forwarded-host",
    "x-original-url",
    "x-rewrite-url",
    "x-custom-ip-authorization",
    "x-real-ip",
    "x-originating-ip",
    "x-remote-ip",
    "x-remote-addr",
    "forwarded",
    "x-http-method-override",
})
_FACT_KEY_PREFIXES: tuple[str, ...] = (
    "internal_host:",
    "actor_capability:",
    "ssrf_sink:",
    "auth_header:",
    "verified_primitive:",
    "cross_tenant_id:",
    "waf_bypass:",
    "host:",
    "internal:",
    "header:",
    "actor:",
    "ssrf:",
    "tenant:",
    "cross_tenant:",
    "waf:",
    "key:",
    "url:",
    "endpoint:",
    "route:",
    "param:",
    "id:",
)


def _is_internal_or_metadata_url(raw_url: str, *, base_url: str) -> str | None:
    """Return normalized URL if `raw_url` points to a non-target internal/private/metadata host."""
    cand = str(raw_url or "").strip().rstrip(",;.'\"")
    if not cand or "<redacted" in cand.lower():
        return None
    try:
        parsed = urlsplit(cand)
        port = parsed.port
    except ValueError:
        return None
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if scheme not in {"http", "https"} or not host or not parsed.netloc:
        return None

    try:
        base_parsed = urlsplit(base_url or "")
        base_port = base_parsed.port
    except ValueError:
        base_parsed = urlsplit("")
        base_port = None
    base_host = (base_parsed.hostname or "").strip().lower().rstrip(".")
    if base_parsed.netloc and (scheme, parsed.netloc.lower()) == (
        base_parsed.scheme.lower(),
        base_parsed.netloc.lower(),
    ):
        return None
    if (
        base_port is not None
        and port is not None
        and port == base_port
        and host in _LOOPBACK_HOSTS
        and base_host in _LOOPBACK_HOSTS
    ):
        return None

    is_internal = False
    try:
        ip_obj = ipaddress.ip_address(host)
        is_internal = bool(
            ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        if host == "metadata.google.internal" or host in {"localhost", "localhost.localdomain"}:
            is_internal = True
        elif host.endswith((".internal", ".local", ".localhost", ".intranet", ".corp")):
            is_internal = True

    if not is_internal:
        return None
    clean_path = parsed.path or ""
    return f"{scheme}://{parsed.netloc}{clean_path}"


def _extract_internal_host_urls(
    receipt: dict[str, Any],
    surface: dict[str, Any],
    *,
    base_url: str,
    limit: int = 10,
) -> list[str]:
    """Collect unique internal/private/metadata URLs from extracted surface and receipt text."""
    candidates: list[str] = []
    for item in (surface.get("internal_urls") or ()):
        if isinstance(item, str):
            candidates.append(item)
        elif isinstance(item, dict) and item.get("url"):
            candidates.append(str(item["url"]))
    for key in ("links", "js_calls", "forms"):
        for item in (surface.get(key) or ()):
            if isinstance(item, dict) and item.get("url"):
                candidates.append(str(item["url"]))
            elif isinstance(item, str):
                candidates.append(item)
    for item in (surface.get("spec_urls") or ()):
        if isinstance(item, str):
            candidates.append(item)
        elif isinstance(item, dict) and item.get("url"):
            candidates.append(str(item["url"]))

    redir = str(receipt.get("redirect_location") or "")
    if redir:
        candidates.extend(_URL_SCAN_RE.findall(redir))
    resp_hdrs = receipt.get("response_headers") or {}
    if isinstance(resp_hdrs, dict) and resp_hdrs:
        candidates.extend(_URL_SCAN_RE.findall(json.dumps(resp_hdrs, ensure_ascii=False)))
    body = str(receipt.get("body") or "")[:500_000]
    if body:
        candidates.extend(_URL_SCAN_RE.findall(body))

    out: list[str] = []
    seen: set[str] = set()
    for raw_cand in candidates:
        norm = _is_internal_or_metadata_url(raw_cand, base_url=base_url)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
            if len(out) >= limit:
                break
    return out


def _is_fact_grounded_in_receipt(
    raw_key: str,
    fact_type: str,
    receipt: dict[str, Any],
    *,
    oob_hits: Sequence[dict[str, Any]] = (),
) -> bool:
    """Verify key tokens (ignoring punctuation) appear in receipt fields or OOB hits."""
    key_body = str(raw_key or "").strip()
    if not key_body:
        return False
    low_body = key_body.lower()
    ft_prefix = f"{fact_type.lower()}:"
    if low_body.startswith(ft_prefix):
        key_body = key_body[len(ft_prefix):].strip()
    else:
        for prefix in _FACT_KEY_PREFIXES:
            if low_body.startswith(prefix):
                key_body = key_body[len(prefix):].strip()
                break

    raw_tokens = re.findall(r"[a-z0-9]+", key_body.lower())
    filtered = [tok for tok in raw_tokens if tok not in {"http", "https"}]
    key_tokens = filtered if filtered else raw_tokens
    if not key_tokens:
        return False

    parts: list[str] = [
        str(receipt.get("method") or ""),
        str(receipt.get("url") or ""),
        str(receipt.get("path") or ""),
        str(receipt.get("query") or ""),
        str(receipt.get("redirect_location") or ""),
        unquote(str(receipt.get("url") or "")),
        unquote(str(receipt.get("query") or "")),
        str(receipt.get("request_body") or ""),
        unquote(str(receipt.get("request_body") or ""))[:100_000],
        str(receipt.get("body") or ""),
        json.dumps(receipt.get("request_headers") or {}, ensure_ascii=False),
        json.dumps(receipt.get("response_headers") or {}, ensure_ascii=False),
    ]
    saved = receipt.get("saved_session")
    if isinstance(saved, dict):
        parts.append(str(saved.get("alias") or ""))
        parts.append(str(saved.get("role") or ""))
    if oob_hits:
        parts.append(json.dumps(list(oob_hits), ensure_ascii=False))

    haystack_lower = "\n".join(parts).lower()
    haystack_tokens = set(re.findall(r"[a-z0-9]+", haystack_lower))
    for tok in key_tokens:
        if len(tok) >= 3:
            if tok not in haystack_tokens and tok not in haystack_lower:
                return False
        elif tok not in haystack_tokens:
            return False
    return True

RECORD_FINDING_CLASS_ENUM: list[str] = [
    "auth_bypass",
    "bfla",
    "bola",
    "tenant_isolation",
    "mass_assignment",
    "reflected_xss",
    "stored_xss",
    "sqli",
    "sqli_read",
    "open_redirect",
    "ssrf",
    "xxe",
    "ssti",
    "path_traversal",
    "file_upload",
    "cors_misconfiguration",
    "csrf",
    "jwt_weakness",
    "command_injection",
    "insecure_deserialization",
    "race_condition",
    "weak_credentials",
    "business_logic",
    "other",
]

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Scope-locked HTTP/WS request as actor ('anon'). GET cached unless force.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "description": "Method (GET; POST if body)."},
                    "url": {"type": "string", "description": "In-scope http(s)/ws(s) URL."},
                    "actor": {"type": "string"},
                    "headers": {
                        "type": "object",
                        "description": "Auth headers override actor auth.",
                    },
                    "query": {"type": "object"},
                    "json_body": {},
                    "base_receipt_id": {"type": "string"},
                    "json_merge": {"type": "object"},
                    "form_body": {"type": "object"},
                    "raw_body": {"type": "string"},
                    "raw_body_base64": {"type": "string", "description": "Base64 binary body (<=1MB)."},
                    "grpc_web_mode": {"type": "string", "enum": ["binary", "text"]},
                    "files": {
                        "type": "array",
                        "description": "Multipart [{field,filename,content|content_base64,content_type}].",
                        "items": {"type": "object"},
                    },
                    "follow_redirects": {"type": "boolean"},
                    "force": {"type": "boolean"},
                    "save_session_as": {"type": "string"},
                    "auth_header": {"type": "string", "description": "Custom token header name."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_receipt",
            "description": "Read receipt body at 0 HTTP cost (offset/limit/regex).",
            "parameters": {
                "type": "object",
                "properties": {
                    "receipt_id": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
                    "regex": {"type": "string"},
                },
                "required": ["receipt_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "replay_as",
            "description": "Replay receipt_id with actor/overrides; returns diff.",
            "parameters": {
                "type": "object",
                "properties": {
                    "receipt_id": {"type": "string"},
                    "actor": {"type": "string"},
                    "method": {"type": "string"},
                    "url": {"type": "string"},
                    "query_overrides": {"type": "object"},
                    "header_overrides": {
                        "type": "object",
                        "description": "Auth overrides actor ('' strips).",
                    },
                    "base_receipt_id": {"type": "string"},
                    "json_merge": {"type": "object"},
                    "json_overrides": {"type": "object"},
                    "raw_body_base64": {"type": "string"},
                    "force": {"type": "boolean"},
                },
                "required": ["receipt_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_surface",
            "description": "Extract links, forms, JS logic, specs, and IDs (0 HTTP cost).",
            "parameters": {
                "type": "object",
                "properties": {"receipt_id": {"type": "string"}},
                "required": ["receipt_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "notebook",
            "description": "Update notebook or publish_fact (0 HTTP cost).",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "update", "add_hypothesis", "update_hypothesis", "add_note", "publish_fact"],
                    },
                    "surface_notes": {"type": "string"},
                    "hypothesis": {"type": "object", "description": "{id,target,vuln_class,status,notes}"},
                    "note": {"type": "string"},
                    "fact": {"type": "object", "description": "{fact_type,key,summary,source_receipt_id}"},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "callback_listener",
            "description": "OOB callbacks (create_url/poll); loopback default.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["create_url", "poll"]},
                    "label": {"type": "string"},
                    "token": {"type": "string"},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "concurrent_check",
            "description": "Send 2-5 parallel requests for race/idempotency.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string"},
                    "actor": {"type": "string"},
                    "headers": {"type": "object"},
                    "query": {"type": "object"},
                    "json_body": {},
                    "form_body": {"type": "object"},
                    "raw_body": {"type": "string"},
                    "count": {"type": "integer", "description": "2-5."},
                },
                "required": ["url", "method", "actor"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_crawl",
            "description": "Read-only SPA/DOM crawl, inspect, or dom_verify.",
            "parameters": {
                "type": "object",
                "properties": {
                    "mode": {"type": "string", "enum": ["crawl", "inspect", "dom_verify"]},
                    "url": {"type": "string"},
                    "actor": {"type": "string"},
                    "max_pages": {"type": "integer", "description": "1-12."},
                    "marker": {"type": "string"},
                    "source": {"type": "string", "enum": ["hash", "query", "postmessage"]},
                    "param_name": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_token",
            "description": "Offline JWT/token inspector and JWT test builder.",
            "parameters": {
                "type": "object",
                "properties": {
                    "value": {"type": "string", "description": "Token, blob, JSON, or 'actor:<alias>'."},
                    "kind": {"type": "string", "enum": ["auto", "jwt", "opaque", "serialization", "jwt_test"]},
                    "alg": {"type": "string", "description": "none/HS256/384/512/confusion/strip_sig."},
                    "hmac_key": {"type": "string", "description": "HMAC key or 'receipt:<id>'."},
                    "claim_overrides": {"type": "object"},
                },
                "required": ["value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sandbox_probe",
            "description": "Air-gapped python_pure compute (HMAC/protobuf/pack); 0 net.",
            "parameters": {
                "type": "object",
                "properties": {
                    "runtime": {"type": "string", "enum": ["python_pure"]},
                    "code": {"type": "string", "description": "transform(inputs) or RESULT."},
                    "inputs": {"type": "object", "description": "{receipt_refs?:[id],params?:obj}"},
                    "timeout_ms": {"type": "integer"},
                    "output_contract": {"type": "string", "enum": ["http_transform", "decode_only"]},
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "record_finding",
            "description": "Record verified finding backed by proof/control receipt IDs and evidence_value.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "class_type": {
                        "type": "string",
                        "enum": RECORD_FINDING_CLASS_ENUM,
                        "description": "Canonical class (avoid 'other' when specific fits).",
                    },
                    "method": {"type": "string"},
                    "url": {"type": "string"},
                    "actor_alias": {"type": "string"},
                    "proof_receipt_ids": {"type": "array", "items": {"type": "string"}},
                    "control_receipt_ids": {"type": "array", "items": {"type": "string"}},
                    "evidence_value": {"type": "string"},
                    "summary": {"type": "string"},
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
            "description": "Finish investigation with summary and untested_areas.",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                    "untested_areas": {"type": "array", "items": {"type": "string"}},
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
    """Atomically write JSON with 0600 permissions to `path`."""
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


def _deep_merge_json(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge `patch` into `base`, preserving existing unpatched keys."""
    merged = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_json(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _coerce_json_payload(value: Any) -> Any:
    """Decode stringified JSON objects/arrays once so callers avoid double-encoded JSON strings."""
    if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(value)
        except ValueError:
            return value
        if isinstance(parsed, (dict, list)):
            return parsed
    return value


def _coerce_mapping_arg(value: Any) -> dict[str, Any] | None:
    """Return a dict from either a dict or a JSON-encoded object string, else None."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.lstrip().startswith("{"):
        try:
            parsed = json.loads(value)
        except ValueError:
            return None
        if isinstance(parsed, dict):
            return parsed
    return None


def _is_multipart_receipt(receipt: dict[str, Any]) -> bool:
    """Return True if a receipt represents a multipart/form-data upload."""
    req_body = str(receipt.get("request_body") or "")
    if req_body.startswith("multipart/form-data "):
        return True
    req_headers = receipt.get("request_headers")
    if isinstance(req_headers, dict):
        for k, v in req_headers.items():
            if str(k).strip().lower() == "content-type":
                if str(v or "").strip().lower().startswith("multipart/form-data"):
                    return True
    return False


_JSON_ESCAPE_RE = re.compile(r'\\(u[0-9a-fA-F]{4}|["\\/bfnrt])')
_JSON_SIMPLE_UNESCAPE: dict[str, str] = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}
_GRAPHQL_OP_RE = re.compile(
    r"^\s*(?:(query|mutation|subscription)\b(?:\s+([A-Za-z_][A-Za-z0-9_]*))?[^\{]*)?\{\s*([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)
_NON_ANCHORED_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")


def _supported_kwargs(fn: Any, candidate_kwargs: dict[str, Any]) -> dict[str, Any]:
    """Filter optional kwargs against `fn`'s current signature for cross-module compatibility."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return {}
    params = sig.parameters
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return dict(candidate_kwargs)
    return {k: v for k, v in candidate_kwargs.items() if k in params}


def _unescape_json_escapes(text: str) -> str:
    """Decode single-pass JSON string escapes (``\\\"``, ``\\/``, ``\\uXXXX``, etc.)."""
    def _repl(match: re.Match[str]) -> str:
        tok = match.group(1)
        if tok.startswith("u"):
            return chr(int(tok[1:], 16))
        return _JSON_SIMPLE_UNESCAPE.get(tok, match.group(0))

    return _JSON_ESCAPE_RE.sub(_repl, text)


def _extract_finding_origin(url_or_path: str, base_url: str = "") -> str:
    """Return normalized ``scheme://host:port`` origin for finding deduplication."""
    raw = str(url_or_path or "").strip()
    parsed = urlsplit(raw)
    if (not parsed.scheme or not parsed.netloc) and base_url:
        parsed = urlsplit(urljoin(base_url, raw))
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port is None:
        port = 443 if scheme == "https" else 80
    host_part = f"[{hostname}]" if ":" in hostname else hostname
    return f"{scheme}://{host_part}:{port}"


def _parse_graphql_op_from_payload(op_name: str, query_str: str) -> str:
    clean_name = str(op_name or "").strip()
    clean_query = str(query_str or "").strip()
    if clean_query:
        m = _GRAPHQL_OP_RE.search(clean_query)
        if m:
            kind = str(m.group(1) or "query").lower()
            named = str(m.group(2) or "").strip()
            root_field = str(m.group(3) or "").strip()
            target_name = clean_name or named or root_field
            if target_name:
                return f"{kind}:{target_name}"
        if clean_name:
            return f"query:{clean_name}"
    if clean_name:
        return clean_name
    return ""


def _extract_graphql_op(
    route_template: str,
    receipts: Sequence[dict[str, Any]],
    *,
    raw_url: str = "",
    existing_finding: dict[str, Any] | None = None,
) -> str:
    """Extract normalized GraphQL operation identifier from finding metadata or proof receipts."""
    if isinstance(existing_finding, dict):
        saved_op = str(existing_finding.get("graphql_op") or "").strip()
        if saved_op:
            return saved_op
    tmpl_low = str(route_template or "").lower()
    looks_gql = "graphql" in tmpl_low or tmpl_low.endswith("/gql") or "/gql/" in tmpl_low
    for rec in receipts:
        if not isinstance(rec, dict):
            continue
        req_body = str(rec.get("request_body") or "").strip()
        if req_body.startswith("{"):
            try:
                parsed = json.loads(req_body)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict) and ("query" in parsed or "operationName" in parsed):
                op = _parse_graphql_op_from_payload(
                    str(parsed.get("operationName") or ""),
                    str(parsed.get("query") or ""),
                )
                if op:
                    return op
        elif req_body.startswith("["):
            try:
                parsed_list = json.loads(req_body)
            except ValueError:
                parsed_list = None
            if isinstance(parsed_list, list):
                ops: list[str] = []
                for item in parsed_list:
                    if isinstance(item, dict) and ("query" in item or "operationName" in item):
                        op = _parse_graphql_op_from_payload(
                            str(item.get("operationName") or ""),
                            str(item.get("query") or ""),
                        )
                        if op and op not in ops:
                            ops.append(op)
                if ops:
                    return ",".join(ops[:3])
        elif looks_gql and req_body:
            op = _parse_graphql_op_from_payload("", req_body)
            if op:
                return op
        rec_url = str(rec.get("url") or "")
        if rec_url and ("?" in rec_url or looks_gql):
            q_map = dict(parse_qsl(urlsplit(rec_url).query, keep_blank_values=False))
            if "query" in q_map or "operationName" in q_map:
                op = _parse_graphql_op_from_payload(
                    str(q_map.get("operationName") or ""),
                    str(q_map.get("query") or ""),
                )
                if op:
                    return op
    if raw_url and "?" in raw_url:
        q_map = dict(parse_qsl(urlsplit(raw_url).query, keep_blank_values=False))
        if "query" in q_map or "operationName" in q_map:
            op = _parse_graphql_op_from_payload(
                str(q_map.get("operationName") or ""),
                str(q_map.get("query") or ""),
            )
            if op:
                return op
    return ""


_LEAD_SIGNAL_RANK: dict[str, int] = {
    "async_oob_unreplayed": 0,
    "server_5xx_differential": 1,
    "timing_anomaly_borderline": 2,
    "one_shot_state_exhausted": 3,
    "multistep_precursor_blocked": 4,
    "multistep_budget_exceeded": 5,
}
_LEAD_SENSITIVE_QUERY_KEYS = frozenset({
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pass",
    "pwd",
    "api_key",
    "apikey",
    "auth",
    "session",
    "session_id",
    "jwt",
})
_OOB_CLASS_HINTS = (
    ("xxe", "xxe"),
    ("ssti", "ssti"),
    ("sqli", "sqli"),
    ("sql", "sqli"),
    ("rce", "cmd_injection"),
    ("cmd", "cmd_injection"),
    ("ssrf", "ssrf"),
)


_LEAD_INLINE_HEADER_SECRET_RE = re.compile(
    r"(?im)\b((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token)\s*:\s*)([^\r\n]+)"
)
_LEAD_INLINE_KV_SECRET_RE = re.compile(
    r"(?i)\b(token|access_token|refresh_token|secret|client_secret|password|passwd|apikey|api_key|session|session_id|jwt)(\s*[:=]\s*['\"]?)([^'\"\s&;,<>]+)"
)


def _redact_lead_url(raw_url: str, extra_secrets: Sequence[str] = ()) -> str:
    text = str(raw_url or "").strip()
    if not text:
        return ""
    cleaned = redact_secrets(text, extra_secrets)
    parts = urlsplit(cleaned)
    if not parts.query:
        return cleaned
    redacted_pairs: list[tuple[str, str]] = []
    changed = False
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        kl = k.strip().lower()
        if (
            kl in _LEAD_SENSITIVE_QUERY_KEYS
            or any(tok in kl for tok in ("token", "secret", "password", "passwd", "apikey", "api_key"))
        ) and v and "<REDACTED" not in v:
            redacted_pairs.append((k, "<REDACTED_SECRET>"))
            changed = True
        else:
            redacted_pairs.append((k, v))
    if not changed:
        return cleaned
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(redacted_pairs), parts.fragment))


def _redact_lead_text(text: Any, extra_secrets: Sequence[str] = (), *, limit: int = 0) -> str:
    s = redact_secrets(str(text or ""), extra_secrets).strip()
    if s:
        s = _LEAD_INLINE_HEADER_SECRET_RE.sub(
            lambda m: m.group(0) if "<REDACTED" in m.group(2) else f"{m.group(1)}<REDACTED_SECRET>",
            s,
        )
        s = _LEAD_INLINE_KV_SECRET_RE.sub(
            lambda m: m.group(0) if "<REDACTED" in m.group(3) else f"{m.group(1)}{m.group(2)}<REDACTED_SECRET>",
            s,
        )
    if limit > 0 and len(s) > limit:
        s = s[:limit].rstrip()
    return s


def _sanitize_oob_hits_preview(
    hits: Sequence[dict[str, Any]],
    extra_secrets: Sequence[str] = (),
    *,
    limit: int = 3,
) -> list[dict[str, Any]]:
    preview: list[dict[str, Any]] = []
    for hit in hits[:limit]:
        if not isinstance(hit, dict):
            continue
        raw_hdrs = hit.get("headers") if isinstance(hit.get("headers"), dict) else {}
        safe_hdrs = {
            str(k): _redact_lead_text(v, extra_secrets, limit=256)
            for k, v in redact_headers(raw_hdrs).items()
        }
        raw_query = str(hit.get("query") or "")
        safe_query = _redact_lead_url(f"/?{raw_query}", extra_secrets).split("?", 1)[1] if raw_query else ""
        entry: dict[str, Any] = {
            "token": str(hit.get("token") or ""),
            "method": str(hit.get("method") or "GET").upper(),
            "path": _redact_lead_text(hit.get("path") or "/", extra_secrets, limit=240),
            "query": _redact_lead_text(safe_query, extra_secrets, limit=300),
            "headers": safe_hdrs,
            "body_preview": _redact_lead_text(hit.get("body_preview") or "", extra_secrets, limit=300),
            "remote_addr": str(hit.get("remote_addr") or ""),
            "timestamp": str(hit.get("timestamp") or ""),
        }
        preview.append(entry)
    return preview


def _redact_lead_record(raw: dict[str, Any], extra_secrets: Sequence[str] = ()) -> dict[str, Any]:
    out = dict(raw)
    out["url"] = _redact_lead_url(str(out.get("url") or out.get("path") or "/"), extra_secrets)
    out["path"] = _redact_lead_url(str(out.get("path") or out["url"] or "/"), extra_secrets)
    out["title"] = _redact_lead_text(out.get("title") or "", extra_secrets, limit=240)
    out["summary"] = _redact_lead_text(out.get("summary") or "", extra_secrets, limit=1200)
    out["evidence"] = _redact_lead_text(out.get("evidence") or "", extra_secrets, limit=1200)
    out["evidence_value"] = _redact_lead_text(out.get("evidence_value") or "", extra_secrets, limit=300)
    out["marker"] = _redact_lead_text(out.get("marker") or out["evidence_value"], extra_secrets, limit=300)
    out["verification_blocker"] = _redact_lead_text(out.get("verification_blocker") or "", extra_secrets, limit=300)
    out["suggested_manual_verification"] = _redact_lead_text(
        out.get("suggested_manual_verification") or "",
        extra_secrets,
        limit=600,
    )
    if out.get("oracle_reason"):
        out["oracle_reason"] = _redact_lead_text(out.get("oracle_reason"), extra_secrets, limit=600)
    if isinstance(out.get("evidence_excerpts"), list):
        cleaned_excerpts: list[dict[str, Any]] = []
        for ex in out["evidence_excerpts"][:8]:
            if not isinstance(ex, dict):
                continue
            c_ex = dict(ex)
            c_ex["url"] = _redact_lead_url(str(c_ex.get("url") or ""), extra_secrets)
            c_ex["excerpt"] = _redact_lead_text(c_ex.get("excerpt") or "", extra_secrets, limit=MAX_PROOF_EXCERPT_CHARS)
            cleaned_excerpts.append(c_ex)
        out["evidence_excerpts"] = cleaned_excerpts
    if isinstance(out.get("control_excerpts"), list):
        cleaned_ctrls: list[dict[str, Any]] = []
        for ex in out["control_excerpts"][:8]:
            if not isinstance(ex, dict):
                continue
            c_ex = dict(ex)
            c_ex["url"] = _redact_lead_url(str(c_ex.get("url") or ""), extra_secrets)
            c_ex["excerpt"] = _redact_lead_text(c_ex.get("excerpt") or "", extra_secrets, limit=MAX_CONTROL_EXCERPT_CHARS)
            cleaned_ctrls.append(c_ex)
        out["control_excerpts"] = cleaned_ctrls
    if isinstance(out.get("oob_hits_preview"), list):
        out["oob_hits_preview"] = _sanitize_oob_hits_preview(out["oob_hits_preview"], extra_secrets)
    out["verification_tier"] = "NEEDS_VERIFICATION"
    out["oracle_verdict"] = "NEEDS_VERIFICATION"
    return out


def canonicalize_and_deduplicate_leads(
    leads: Sequence[dict[str, Any]],
    *,
    actor_meta_map: dict[str, dict[str, str]] | None = None,
    receipt_store: Any | None = None,
    max_leads: int = 15,
) -> list[dict[str, Any]]:
    """Deduplicate, sanitize, rank strongest-first, cap, and assign deterministic L-001..L-NNN IDs."""
    _ = actor_meta_map, receipt_store
    if max_leads <= 0 or not leads:
        return []

    raw_items = [dict(item) for item in leads if isinstance(item, dict)]
    if not raw_items:
        return []

    origins = {
        _extract_finding_origin(str(item.get("url") or item.get("path") or ""))
        for item in raw_items
    }
    origins.discard("")
    multi_origin = len(origins) > 1

    grouped: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for item in raw_items:
        redacted = _redact_lead_record(item)
        raw_class = str(redacted.get("class_type") or "").strip()
        method = str(redacted.get("method") or "GET").strip().upper() or "GET"
        norm_class = normalize_vuln_class(
            raw_class,
            method=method,
            title=str(redacted.get("title") or ""),
            summary=str(redacted.get("summary") or ""),
        ) if raw_class else "business_logic"
        raw_route = str(redacted.get("route_template") or redacted.get("url") or redacted.get("path") or "/")
        route_tmpl = normalize_route_template(raw_route)
        signal_type = str(redacted.get("signal_type") or "unverified_signal").strip().lower() or "unverified_signal"
        origin = _extract_finding_origin(str(redacted.get("url") or redacted.get("path") or ""))
        dedup_key = (origin if multi_origin else "", norm_class, method, route_tmpl, signal_type)

        redacted["class_type"] = norm_class
        redacted["method"] = method
        redacted["route_template"] = route_tmpl
        redacted["signal_type"] = signal_type
        if origin and not redacted.get("origin"):
            redacted["origin"] = origin

        proof_ids = [str(r).strip() for r in (redacted.get("proof_receipt_ids") or []) if str(r).strip()]
        control_ids = [str(r).strip() for r in (redacted.get("control_receipt_ids") or []) if str(r).strip()]
        passed_stages = [str(s).strip() for s in (redacted.get("passed_stages") or []) if str(s).strip()]
        supporting_actors = [str(a).strip() for a in (redacted.get("supporting_actors") or []) if str(a).strip()]
        actor_val = str(redacted.get("actor") or redacted.get("actor_alias") or "").strip()
        if actor_val and actor_val not in supporting_actors:
            supporting_actors.insert(0, actor_val)

        redacted["proof_receipt_ids"] = list(dict.fromkeys(proof_ids))
        redacted["control_receipt_ids"] = list(dict.fromkeys(control_ids))
        redacted["passed_stages"] = list(dict.fromkeys(passed_stages))
        redacted["supporting_actors"] = list(dict.fromkeys(supporting_actors))

        existing = grouped.get(dedup_key)
        if existing is None:
            grouped[dedup_key] = redacted
            continue

        existing["proof_receipt_ids"] = list(dict.fromkeys([
            *(existing.get("proof_receipt_ids") or []),
            *redacted["proof_receipt_ids"],
        ]))
        existing["control_receipt_ids"] = list(dict.fromkeys([
            *(existing.get("control_receipt_ids") or []),
            *redacted["control_receipt_ids"],
        ]))
        existing["passed_stages"] = list(dict.fromkeys([
            *(existing.get("passed_stages") or []),
            *redacted["passed_stages"],
        ]))
        existing["supporting_actors"] = list(dict.fromkeys([
            *(existing.get("supporting_actors") or []),
            *redacted["supporting_actors"],
        ]))

        if len(str(redacted.get("evidence") or "")) > len(str(existing.get("evidence") or "")):
            existing["evidence"] = redacted["evidence"]
        if len(redacted.get("evidence_excerpts") or []) > len(existing.get("evidence_excerpts") or []):
            existing["evidence_excerpts"] = redacted["evidence_excerpts"]
        if not existing.get("verification_blocker") and redacted.get("verification_blocker"):
            existing["verification_blocker"] = redacted["verification_blocker"]
        if not existing.get("suggested_manual_verification") and redacted.get("suggested_manual_verification"):
            existing["suggested_manual_verification"] = redacted["suggested_manual_verification"]
        if not existing.get("clean_replay_receipt_id") and redacted.get("clean_replay_receipt_id"):
            existing["clean_replay_receipt_id"] = redacted["clean_replay_receipt_id"]
        if int(redacted.get("oob_hit_count") or 0) > int(existing.get("oob_hit_count") or 0):
            existing["oob_hit_count"] = int(redacted.get("oob_hit_count") or 0)
        if not existing.get("oob_token") and redacted.get("oob_token"):
            existing["oob_token"] = redacted["oob_token"]
        if redacted.get("oob_hits_preview") and len(redacted["oob_hits_preview"]) > len(existing.get("oob_hits_preview") or []):
            existing["oob_hits_preview"] = redacted["oob_hits_preview"]
        if _severity_rank(redacted) < _severity_rank(existing):
            existing["severity"] = redacted["severity"]

    sorted_leads = sorted(
        grouped.values(),
        key=lambda item: (
            _LEAD_SIGNAL_RANK.get(str(item.get("signal_type") or ""), 50),
            -int(item.get("oob_hit_count") or 0),
            -len(item.get("passed_stages") or []),
            _severity_rank(item),
            str(item.get("class_type") or ""),
            str(item.get("method") or ""),
            str(item.get("route_template") or ""),
        ),
    )[: int(max_leads)]

    final_leads: list[dict[str, Any]] = []
    for idx, entry in enumerate(sorted_leads, start=1):
        out = dict(entry)
        out["lead_id"] = f"L-{idx:03d}"
        final_leads.append(out)
    return final_leads


def _receipt_contains_oob_token(receipt: dict[str, Any], token: str) -> bool:
    if not token:
        return False
    return (
        token in str(receipt.get("url") or "")
        or token in str(receipt.get("query") or "")
        or token in str(receipt.get("request_body") or "")
        or token in json.dumps(receipt.get("request_headers") or {}, ensure_ascii=False)
    )


def _infer_class_from_oob_label(label: str) -> str:
    low = str(label or "").strip().lower()
    for hint, cls_name in _OOB_CLASS_HINTS:
        if hint in low:
            return cls_name
    return "ssrf"


def reconcile_late_oob_hits(
    oob_server: Any | None,
    *,
    findings: Sequence[dict[str, Any]],
    leads: Sequence[dict[str, Any]],
    receipts: Any,
    base_url: str = "",
) -> list[dict[str, Any]]:
    """Convert late-arriving unconfirmed OOB hits into redacted NEEDS_VERIFICATION leads."""
    if oob_server is None or not hasattr(oob_server, "poll"):
        return []
    try:
        polled = oob_server.poll("")
    except Exception:
        return []
    if not isinstance(polled, dict):
        return []

    tokens_meta = polled.get("tokens")
    if not isinstance(tokens_meta, dict) or not tokens_meta:
        return []
    all_hits = [h for h in (polled.get("hits") or []) if isinstance(h, dict)]

    receipt_list: list[dict[str, Any]] = []
    receipt_by_id: dict[str, dict[str, Any]] = {}
    if hasattr(receipts, "list_ids") and hasattr(receipts, "get"):
        for rid in receipts.list_ids():
            try:
                rec = receipts.get(rid)
            except (KeyError, ValueError):
                continue
            if isinstance(rec, dict):
                receipt_list.append(rec)
                if rid:
                    receipt_by_id[str(rid)] = rec
    elif isinstance(receipts, dict):
        for k, rec in receipts.items():
            if isinstance(rec, dict):
                receipt_list.append(rec)
                rid = str(rec.get("receipt_id") or k).strip()
                if rid:
                    receipt_by_id[rid] = rec
    elif isinstance(receipts, (list, tuple)):
        for rec in receipts:
            if isinstance(rec, dict):
                receipt_list.append(rec)
                rid = str(rec.get("receipt_id") or "").strip()
                if rid:
                    receipt_by_id[rid] = rec

    confirmed_rids: set[str] = set()
    confirmed_blobs: list[str] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        for rid in f.get("proof_receipt_ids") or ():
            s_rid = str(rid).strip()
            if s_rid:
                confirmed_rids.add(s_rid)
                rec = receipt_by_id.get(s_rid)
                if rec is not None:
                    confirmed_blobs.append(str(rec.get("url") or ""))
                    confirmed_blobs.append(str(rec.get("query") or ""))
                    confirmed_blobs.append(str(rec.get("request_body") or ""))
        for field_name in ("evidence", "evidence_value", "marker", "url", "oob_token", "title", "summary"):
            val = str(f.get(field_name) or "")
            if val:
                confirmed_blobs.append(val)
        for ex in f.get("evidence_excerpts") or ():
            if isinstance(ex, dict):
                confirmed_blobs.append(str(ex.get("excerpt") or ""))
                confirmed_blobs.append(str(ex.get("url") or ""))
    findings_haystack = "\n".join(confirmed_blobs)

    existing_lead_tokens: set[str] = set()
    existing_lead_blobs: list[str] = []
    for lead in leads:
        if not isinstance(lead, dict):
            continue
        tok_val = str(lead.get("oob_token") or "").strip()
        if tok_val:
            existing_lead_tokens.add(tok_val)
        for field_name in ("evidence", "evidence_value", "marker", "url"):
            val = str(lead.get(field_name) or "")
            if val:
                existing_lead_blobs.append(val)
    leads_haystack = "\n".join(existing_lead_blobs)

    new_leads: list[dict[str, Any]] = []
    for tok in sorted(tokens_meta):
        info = tokens_meta.get(tok)
        if not isinstance(info, dict):
            continue
        tok_hits = [h for h in all_hits if str(h.get("token") or "") == tok]
        hit_count = max(int(info.get("hit_count") or 0), len(tok_hits))
        if hit_count <= 0:
            continue
        if tok in findings_haystack or tok in existing_lead_tokens or tok in leads_haystack:
            continue

        matched_receipts = [r for r in receipt_list if _receipt_contains_oob_token(r, tok)]
        matched_rids = [str(r.get("receipt_id") or "").strip() for r in matched_receipts if r.get("receipt_id")]
        if matched_rids and any(rid in confirmed_rids for rid in matched_rids):
            continue

        primary_rec: dict[str, Any] | None = None
        if matched_receipts:
            primary_rec = sorted(
                matched_receipts,
                key=lambda r: (
                    0 if 200 <= int(r.get("status") or 0) < 400 else 1,
                    int(r.get("receipt_id", "0").lstrip("R-") or 0)
                    if str(r.get("receipt_id") or "").lstrip("R-").isdigit()
                    else 0,
                ),
            )[0]

        method = str(primary_rec.get("method") or "GET").upper() if primary_rec else "GET"
        raw_url = (
            str(primary_rec.get("url") or primary_rec.get("path") or base_url or "/")
            if primary_rec
            else (base_url.rstrip("/") + "/" if base_url else "/")
        )
        actor = str(primary_rec.get("actor") or "anon").strip() if primary_rec else "anon"
        label = str(info.get("label") or "").strip()
        inferred_class = _infer_class_from_oob_label(label)
        url_path = urlsplit(raw_url).path or "/"
        route_tmpl = normalize_route_template(raw_url)
        preview_hits = _sanitize_oob_hits_preview(tok_hits)
        hit0 = preview_hits[0] if preview_hits else {}
        oob_summary = (
            f"---[late_oob_callback:token={tok} hits={hit_count}]---\n"
            f"{hit0.get('method', 'GET')} {hit0.get('path', '/')} "
            f"query={hit0.get('query') or ''} remote={hit0.get('remote_addr') or ''}"
        ).strip()
        if primary_rec is not None:
            rec_excerpt = build_receipt_excerpt(primary_rec, tok, max_chars=500)
            if rec_excerpt:
                oob_summary = f"{oob_summary}\n{rec_excerpt}"

        lead_entry: dict[str, Any] = {
            "title": f"Late asynchronous OOB callback hit ({inferred_class})",
            "class_type": inferred_class,
            "route_template": route_tmpl,
            "method": method,
            "url": raw_url,
            "path": url_path,
            "actor": actor,
            "actor_alias": actor,
            "severity": "high",
            "status": "needs_verification",
            "verification_tier": "NEEDS_VERIFICATION",
            "oracle_verdict": "NEEDS_VERIFICATION",
            "signal_type": "async_oob_unreplayed",
            "passed_stages": ["oob_callback_received"],
            "verification_blocker": "late_oob_hit_after_shard_close",
            "suggested_manual_verification": (
                f"Replay {method} {url_path} with a fresh callback_listener URL and allow extra "
                f"time for delayed asynchronous OOB callback delivery (observed {hit_count} late hit(s) "
                f"for token {tok})."
            ),
            "oob_token": tok,
            "oob_hit_count": hit_count,
            "oob_hits_preview": preview_hits,
            "evidence_value": tok,
            "marker": tok,
            "evidence": oob_summary,
            "summary": (
                f"Out-of-band callback listener received {hit_count} late hit(s) for token {tok}"
                + (f" (label={label})" if label else "")
                + " after probe submission."
            ),
            "proof_receipt_ids": matched_rids,
            "control_receipt_ids": [],
            "supporting_actors": [actor] if actor else [],
        }
        new_leads.append(_redact_lead_record(lead_entry))

    return new_leads


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
        oob_provider: Callable[..., LoopbackCallbackServer | None] | None = None,
        waf_pivot: WAFPivotTracker | None = None,
        bootstrap_stage1_virgin_guard: bool = False,
        http_reserve_floor: int = 0,
        shared_facts: SharedFactGraph | None = None,
    ):
        self.http = http_client
        self.receipts = receipt_store
        self.root_dir = Path(root_dir).expanduser().resolve()
        self.bsag = bsag
        self.oracle = oracle
        self.telemetry = telemetry
        self.shared_facts: SharedFactGraph | None = shared_facts
        self._oob_server: LoopbackCallbackServer | None = oob_server
        self._oob_provider = oob_provider
        self._owns_oob_server: bool = False
        self._oob_lock = threading.Lock()
        self.bootstrap_stage1_virgin_guard: bool = bool(bootstrap_stage1_virgin_guard)
        self.http_reserve_floor: int = max(0, int(http_reserve_floor))
        self.active_worker_id: str = ""
        self.active_node_id: str = ""
        self.active_category: str = ""
        self._step_delta_v: int = 0
        self._step_delta_e: int = 0
        self._step_claim_submitted: bool = False
        self._findings_lock = threading.RLock()
        self._leads_lock = threading.RLock()
        self._notebook_lock = threading.RLock()
        self.persist_findings: bool = bool(persist_findings)
        self.notebook_path = self.root_dir / "notebook.json"
        self.findings_path = (
            Path(findings_path).expanduser().resolve()
            if findings_path is not None
            else (self.root_dir / "findings.json")
        )
        self.leads_path = (
            self.findings_path.parent / "leads.json"
            if findings_path is not None
            else (self.root_dir / "leads.json")
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
        self.leads: list[dict[str, Any]] = (
            self._load_json(self.leads_path, default=[])
            if self.persist_findings
            else []
        )
        tracker_extra = _supported_kwargs(
            SurfaceFrontierTracker,
            {
                "in_scope_assets": tuple(getattr(self.http, "in_scope_assets", ()) or ()),
                "out_of_scope_assets": tuple(getattr(self.http, "out_of_scope_assets", ()) or ()),
                "excluded_paths": tuple(getattr(self.http, "excluded_paths", ()) or ()),
            },
        )
        self.surface_tracker = SurfaceFrontierTracker(
            base_url=self.http.base_url,
            allowed_methods=sorted(self.http.allowed_methods),
            actor_summaries=self.http.actors.summaries(),
            **tracker_extra,
        )
        self.waf_pivot = waf_pivot if waf_pivot is not None else WAFPivotTracker()
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
        source_shard = self.active_worker_id or "bootstrap"
        saved = receipt.get("saved_session")
        if isinstance(saved, dict) and saved.get("alias"):
            alias = str(saved["alias"])
            role = str(saved.get("role") or "member").lower()
            self.surface_tracker.actors[alias] = {
                "alias": alias,
                "role": role,
                "tenant": "",
            }
            if self.shared_facts is not None:
                self.shared_facts.publish(
                    "actor_capability",
                    f"actor:{alias}",
                    f"alias={alias} role={role}",
                    source_shard=source_shard,
                    source_receipt_id=str(saved.get("source_receipt_id") or receipt.get("receipt_id") or ""),
                    provenance="host_extracted",
                    target_families=("*",),
                    confidence="deterministic",
                    secret_values=self.http.actors.all_secrets(),
                )
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
        if self.shared_facts is not None:
            disc_hdr = str(getattr(self.http.actors, "discovered_auth_header", "") or "").strip()
            if disc_hdr:
                self.shared_facts.publish(
                    "auth_header",
                    f"header:{disc_hdr}",
                    f"Custom auth header {disc_hdr} active",
                    source_shard=source_shard,
                    source_receipt_id=str(receipt.get("receipt_id") or ""),
                    provenance="host_extracted",
                    target_families=("*",),
                    confidence="deterministic",
                    secret_values=self.http.actors.all_secrets(),
                )
            if (
                200 <= status < 400
                and self.waf_pivot is not None
                and self.waf_pivot.total_blocks > 0
                and detect_waf_block(receipt) is None
            ):
                norm_tmpl = normalize_route_template(str(receipt.get("url") or receipt.get("path") or "/"))
                waf_summary = self.waf_pivot.summary()
                blocked_paths = set(waf_summary.get("blocked_paths") or ())
                req_hdrs = receipt.get("request_headers") or {}
                evasion_hdrs = (
                    [
                        str(k)
                        for k, v in req_hdrs.items()
                        if str(k).strip().lower() in _BYPASS_EVASION_HEADER_NAMES and str(v or "").strip()
                    ]
                    if isinstance(req_hdrs, dict)
                    else []
                )
                raw_u_low = str(receipt.get("url") or "").lower()
                encoded_probe = any(tok in raw_u_low for tok in ("%252f", "%2f", "..;"))
                if norm_tmpl in blocked_paths or evasion_hdrs or encoded_probe:
                    hdr_note = f" via headers={','.join(evasion_hdrs)}" if evasion_hdrs else ""
                    self.shared_facts.publish(
                        "waf_bypass",
                        f"waf_bypass:{method}:{norm_tmpl}",
                        f"2xx/3xx {method} {norm_tmpl} bypassed prior WAF block{hdr_note}",
                        source_shard=source_shard,
                        source_receipt_id=str(receipt.get("receipt_id") or ""),
                        provenance="host_extracted",
                        target_families=("*",),
                        confidence="deterministic",
                        secret_values=self.http.actors.all_secrets(),
                    )
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

    def _save_leads(self) -> None:
        if not self.persist_findings:
            return
        with self._leads_lock:
            _atomic_write_json(self.leads_path, self.leads)

    def _record_needs_verification_lead(
        self,
        *,
        verdict: Any,
        title: str,
        canonical_class: str,
        route_template: str,
        method: str,
        raw_url: str,
        primary: dict[str, Any],
        valid_proof_records: list[tuple[dict[str, Any], str]],
        control_receipts: list[dict[str, Any]],
        evidence_value: str,
        default_excerpt: str,
        summary: str,
        severity: str,
        best_actor: str,
        ordered_actors: list[str],
        proof_ids: list[str],
        control_ids: list[str],
        matching_oob_hits: Sequence[dict[str, Any]] = (),
        oob_matched_tokens: Sequence[str] = (),
    ) -> tuple[str, int]:
        valid_receipts_only = [r for r, _ in valid_proof_records]
        excerpt_by_rid = {r["receipt_id"]: ex for r, ex in valid_proof_records if r.get("receipt_id")}
        best_evidence = compose_finding_evidence(
            primary,
            valid_receipts_only,
            control_receipts,
            evidence_value,
            max_proof_chars=MAX_PROOF_EXCERPT_CHARS,
            max_control_chars=MAX_CONTROL_EXCERPT_CHARS,
        ) or excerpt_by_rid.get(primary.get("receipt_id", ""), default_excerpt)
        resolved_url, clean_path, _ = self.http.resolve_in_scope(primary.get("url") or raw_url)
        resolved_origin = _extract_finding_origin(resolved_url, self.http.base_url)

        passed_stages: list[str] = []
        stages_map = getattr(verdict, "stages", None) or {}
        if str(stages_map.get("stage1_control") or "").startswith("passed"):
            passed_stages.append("stage1_control")
        if str(stages_map.get("stage2_diff") or "").startswith("passed"):
            passed_stages.append("stage2_diff")
        if verdict.signal_type == "async_oob_unreplayed":
            passed_stages.append("oob_callback_received")
        elif verdict.signal_type == "server_5xx_differential":
            passed_stages.append("primary_5xx_vs_control")

        lead_entry: dict[str, Any] = {
            "title": title,
            "class_type": canonical_class,
            "route_template": route_template,
            "method": str(primary.get("method") or method).upper(),
            "url": resolved_url,
            "path": clean_path,
            "actor": best_actor,
            "actor_alias": best_actor,
            "observed_status": primary.get("status"),
            "status": "needs_verification",
            "verification_tier": "NEEDS_VERIFICATION",
            "oracle_verdict": "NEEDS_VERIFICATION",
            "signal_type": str(getattr(verdict, "signal_type", "") or ""),
            "passed_stages": passed_stages,
            "verification_blocker": str(getattr(verdict, "verification_blocker", "") or ""),
            "suggested_manual_verification": str(getattr(verdict, "suggested_manual_verification", "") or ""),
            "oracle_reason": str(getattr(verdict, "reason", "") or ""),
            "oracle_stages": dict(stages_map),
            "clean_replay_receipt_id": str(getattr(verdict, "clean_replay_receipt_id", "") or ""),
            "severity": severity if severity in {"critical", "high", "medium", "low"} else "high",
            "evidence_value": evidence_value,
            "marker": evidence_value,
            "evidence": best_evidence,
            "summary": summary,
            "proof_receipt_ids": list(proof_ids),
            "control_receipt_ids": list(control_ids),
            "supporting_actors": list(ordered_actors),
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
        if resolved_origin:
            lead_entry["origin"] = resolved_origin
        if matching_oob_hits:
            tok = (
                oob_matched_tokens[0]
                if oob_matched_tokens
                else str(matching_oob_hits[0].get("token") or "")
            )
            lead_entry["oob_token"] = tok
            lead_entry["oob_hit_count"] = len(matching_oob_hits)
            lead_entry["oob_hits_preview"] = _sanitize_oob_hits_preview(
                matching_oob_hits,
                self.http.actors.all_secrets(),
            )

        redacted_new = _redact_lead_record(lead_entry, self.http.actors.all_secrets())
        target_sig = (
            redacted_new.get("class_type", ""),
            redacted_new.get("method", ""),
            normalize_route_template(str(redacted_new.get("route_template") or resolved_url)),
            redacted_new.get("signal_type", ""),
        )
        with self._leads_lock:
            actor_meta = self._actor_meta_map()
            self.leads = canonicalize_and_deduplicate_leads(
                [*self.leads, redacted_new],
                actor_meta_map=actor_meta,
                receipt_store=self.receipts,
            )
            self._save_leads()
            assigned_id = ""
            for item in self.leads:
                item_sig = (
                    item.get("class_type", ""),
                    item.get("method", ""),
                    item.get("route_template", ""),
                    item.get("signal_type", ""),
                )
                if item_sig == target_sig:
                    assigned_id = str(item.get("lead_id") or "")
                    break
            if not assigned_id and self.leads:
                assigned_id = str(self.leads[-1].get("lead_id") or "L-001")
            total_leads = len(self.leads)
        return assigned_id or "L-001", total_leads

    def _get_oob_server(self, *, start: bool = False) -> LoopbackCallbackServer | None:
        with self._oob_lock:
            if self._oob_server is None:
                if self._oob_provider is not None:
                    srv = self._oob_provider(start=start)
                    if srv is not None:
                        self._oob_server = srv
                        self._owns_oob_server = False
                        return self._oob_server
                if not start:
                    return None
                if (
                    str(os.environ.get("CCO_OOB_BIND_HOST") or "").strip()
                    or str(os.environ.get("CCO_OOB_ADVERTISE_HOST") or "").strip()
                ):
                    self._oob_server = LoopbackCallbackServer.from_env()
                else:
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

    def _enforce_http_reserve_floor(self, needed: int = 1) -> None:
        """Raise BudgetExhaustedError if spending `needed` requests would cross below `http_reserve_floor`."""
        if self.http_reserve_floor <= 0:
            return
        lock = getattr(self.http.budget, "_lock", None)
        if lock is not None:
            with lock:
                remaining = int(self.http.budget.limit - self.http.budget.used)
        else:
            remaining = int(self.http.budget.limit - self.http.budget.used)
        if remaining - needed < self.http_reserve_floor:
            raise BudgetExhaustedError(
                f"stage-reserved HTTP floor reached ({self.http_reserve_floor} requests reserved for cross-shard synthesis)"
            )

    def dispatch(self, name: str, args: dict[str, Any]) -> str:
        handlers = {
            "http_request": self._tool_http_request,
            "read_receipt": self._tool_read_receipt,
            "replay_as": self._tool_replay_as,
            "extract_surface": self._tool_extract_surface,
            "browser_crawl": self._tool_browser_crawl,
            "analyze_token": self._tool_analyze_token,
            "run_sandbox_probe": self._tool_run_sandbox_probe,
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
        except ServiceDegradationError:
            raise
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
        json_body = _coerce_json_payload(args.get("json_body"))
        form_body = _coerce_mapping_arg(args.get("form_body"))
        raw_body = args.get("raw_body")
        raw_body_base64 = args.get("raw_body_base64")
        grpc_web_mode = str(args.get("grpc_web_mode") or "").strip().lower()
        raw_files = args.get("files")
        if isinstance(raw_files, str) and raw_files.lstrip().startswith("["):
            try:
                raw_files = json.loads(raw_files)
            except ValueError:
                pass
        files: list[dict[str, Any]] | None = None
        if raw_files is not None:
            if not isinstance(raw_files, list) or not all(isinstance(item, dict) for item in raw_files):
                raise ValueError("files must be a list of file objects")
            if raw_files:
                files = raw_files
        base_receipt_id = str(args.get("base_receipt_id") or "").strip()
        json_merge = _coerce_mapping_arg(args.get("json_merge")) or _coerce_mapping_arg(args.get("mutate_json"))
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
            or raw_body_base64 is not None
            or bool(grpc_web_mode)
            or files is not None
            or bool(base_receipt_id)
            or (json_merge is not None)
        )
        if raw_method:
            eff_method = raw_method
        elif has_payload and "POST" in self.http.allowed_methods:
            eff_method = "POST"
        else:
            eff_method = "GET"

        target_url = str(args.get("url") or "")
        if (
            self.bootstrap_stage1_virgin_guard
            and eff_method in {"POST", "PUT", "PATCH", "DELETE"}
            and not str(args.get("save_session_as") or "").strip()
            and not bool(args.get("confirm_virgin_mutation", False))
            and is_virgin_state_sensitive_path(target_url)
        ):
            return wrap_untrusted(
                json.dumps({
                    "blocked": True,
                    "reason": "virgin_state_preserved_for_concurrency_or_shard",
                    "method": eff_method,
                    "url": target_url,
                    "guidance": (
                        "Sequential single writes to race/one-shot endpoints are skipped during Stage 1 "
                        "bootstrap to avoid consuming virgin actor state; invoke concurrent_check or defer "
                        "to the assigned Stage 2 shard."
                    ),
                })
            )

        headers = _coerce_mapping_arg(args.get("headers"))
        query = _coerce_mapping_arg(args.get("query"))
        raw_auth_header = args.get("auth_header")
        auth_header_name = ""
        if raw_auth_header is not None:
            if not isinstance(raw_auth_header, str):
                raise ValueError("auth_header must be a string")
            if "\r" in raw_auth_header or "\n" in raw_auth_header or "\x00" in raw_auth_header:
                raise ValueError("auth_header must not contain control characters")
            auth_header_name = raw_auth_header.strip()
            if auth_header_name and not _HTTP_HEADER_NAME_RE.fullmatch(auth_header_name):
                raise ValueError(f"invalid auth_header name: {raw_auth_header!r}")
        follow_redirects = bool(args.get("follow_redirects", False))
        request_kwargs: dict[str, Any] = {
            "method": eff_method,
            "url": target_url,
            "actor": str(args.get("actor") or "anon"),
            "headers": headers,
            "query": query,
            "json_body": json_body,
            "form_body": form_body,
            "raw_body": raw_body,
            "files": files,
            "force": bool(args.get("force", False)),
            "save_session_as": str(args.get("save_session_as") or ""),
        }
        if follow_redirects:
            request_kwargs["follow_redirects"] = True
        if auth_header_name:
            request_kwargs["auth_header_name"] = auth_header_name
        if raw_body_base64 is not None:
            request_kwargs["raw_body_base64"] = raw_body_base64
        if grpc_web_mode:
            request_kwargs["grpc_web_mode"] = grpc_web_mode
        self._enforce_http_reserve_floor(needed=1)
        receipt = self.http.request(**request_kwargs)
        if (
            auth_header_name
            and isinstance(receipt.get("saved_session"), dict)
            and not receipt["saved_session"].get("auth_header")
        ):
            receipt = dict(receipt)
            receipt["saved_session"] = {**receipt["saved_session"], "auth_header": auth_header_name}
        self._ingest_receipt_hooks(receipt)
        preview = _format_receipt_preview(receipt)
        if eff_method == "GET" and has_payload:
            preview["method_warning"] = (
                "GET request sent with request body; set method='POST' for form/JSON submissions."
            )
        status = int(receipt.get("status") or 0)
        ctype = (receipt.get("content_type") or "").lower()
        resp_headers = receipt.get("response_headers") or receipt.get("headers") or {}
        has_discovery_headers = (
            isinstance(resp_headers, dict)
            and any(
                str(k).lower() in {"link", "content-location", "refresh", "location"}
                and str(v or "").strip()
                for k, v in resp_headers.items()
            )
        ) or bool(str(receipt.get("redirect_location") or "").strip())
        url_path = urlsplit(str(receipt.get("url") or "")).path.lower()
        if 200 <= status < 400 and (
            "html" in ctype
            or "javascript" in ctype
            or "ecmascript" in ctype
            or "json" in ctype
            or "openapi" in ctype
            or "css" in ctype
            or url_path.endswith(".css")
            or has_discovery_headers
        ):
            hints_extra = _supported_kwargs(
                _build_surface_hints,
                {
                    "in_scope_assets": tuple(getattr(self.http, "in_scope_assets", ()) or ()),
                    "out_of_scope_assets": tuple(getattr(self.http, "out_of_scope_assets", ()) or ()),
                },
            )
            hints = _build_surface_hints(receipt, self.http.base_url, **hints_extra)
            if hints:
                preview["surface_hints"] = hints
        waf_info = detect_waf_block(receipt)
        if waf_info is not None:
            preview["waf_block"] = waf_info
            self.waf_pivot.record_block(
                str(waf_info.get("vendor") or "generic"),
                str(receipt.get("path") or receipt.get("url") or "/"),
            )
            if self.waf_pivot.should_pivot():
                preview["waf_pivot_guidance"] = self.waf_pivot.guidance()
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
        method = str(args.get("method") or baseline["method"]).strip().upper()
        url = str(args.get("url") or baseline["url"])
        base_body_str = str(baseline.get("request_body") or "")
        base_body_b64 = str(baseline.get("request_body_base64") or "").strip()
        arg_raw_body_b64 = args.get("raw_body_base64")
        baseline_is_multipart = _is_multipart_receipt(baseline)

        query_overrides = _coerce_mapping_arg(args.get("query_overrides"))
        json_overrides = _coerce_mapping_arg(args.get("json_overrides"))
        json_merge = _coerce_mapping_arg(args.get("json_merge")) or _coerce_mapping_arg(args.get("mutate_json"))
        patch_obj: dict[str, Any] | None = None
        if json_overrides is not None and json_merge is not None:
            patch_obj = _deep_merge_json(json_overrides, json_merge)
        elif json_merge is not None:
            patch_obj = json_merge
        elif json_overrides is not None:
            patch_obj = json_overrides

        base_receipt_id = str(args.get("base_receipt_id") or "").strip()
        if arg_raw_body_b64 is not None and (base_receipt_id or patch_obj is not None):
            raise ValueError(
                "raw_body_base64 cannot be combined with base_receipt_id, json_overrides, or json_merge"
            )
        has_body_replacement = bool(base_receipt_id) or (patch_obj is not None) or (arg_raw_body_b64 is not None)
        if baseline_is_multipart and method in _MUTATING_WRITE_METHODS and not has_body_replacement:
            raise ValueError(
                f"receipt {baseline.get('receipt_id', '')} is a multipart/form-data upload whose stored "
                "request_body is a redacted non-binary summary and cannot be replayed directly via "
                "replay_as; send the upload via http_request with the files=[...] parameter instead."
            )

        # Preserve safe non-auth request headers when replaying.
        skip_replay_headers = set(_SKIP_REPLAY_HEADERS)
        try:
            baseline_sess = self.http.actors.get(str(baseline.get("actor") or "anon"))
            if getattr(baseline_sess, "auth_header_name", "").strip():
                skip_replay_headers.add(baseline_sess.auth_header_name.strip().lower())
        except ValueError:
            pass
        req_headers: dict[str, str] = {}
        for k, v in (baseline.get("request_headers") or {}).items():
            kl = str(k).strip().lower()
            if kl in skip_replay_headers or "<REDACTED" in str(v):
                continue
            if baseline_is_multipart and kl == "content-type":
                continue
            req_headers[k] = str(v)
        header_overrides = _coerce_mapping_arg(args.get("header_overrides"))
        if header_overrides is not None:
            for k, v in header_overrides.items():
                key_str = str(k)
                key_low = key_str.lower()
                for existing_key in [ek for ek in req_headers if ek.lower() == key_low and ek != key_str]:
                    req_headers.pop(existing_key, None)
                req_headers[key_str] = "" if v is None else str(v)

        json_body = None
        raw_body = None
        raw_body_base64_arg: Any = None
        if arg_raw_body_b64 is not None:
            raw_body_base64_arg = arg_raw_body_b64
        elif base_receipt_id:
            base_obj = self._load_receipt_json_object(base_receipt_id)
            json_body = _deep_merge_json(base_obj, patch_obj) if patch_obj is not None else base_obj
        elif patch_obj is not None:
            parsed: Any = None
            if base_body_str and not baseline_is_multipart:
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
        elif base_body_b64 and not baseline_is_multipart:
            raw_body_base64_arg = base_body_b64
        elif base_body_str and not baseline_is_multipart:
            try:
                json_body = json.loads(base_body_str)
            except ValueError:
                raw_body = base_body_str

        self._enforce_http_reserve_floor(needed=1)
        replay_req_kwargs: dict[str, Any] = {
            "method": method,
            "url": url,
            "actor": target_actor,
            "headers": req_headers or None,
            "query": query_overrides,
            "json_body": json_body,
            "raw_body": raw_body,
            "force": bool(args.get("force", False)),
        }
        if raw_body_base64_arg is not None:
            replay_req_kwargs["raw_body_base64"] = raw_body_base64_arg
        current = self.http.request(**replay_req_kwargs)
        self.surface_tracker.ingest_receipt(baseline)
        self._ingest_receipt_hooks(current)
        replay_preview = _format_receipt_preview(current, preview_chars=1800)
        waf_info = detect_waf_block(current)
        if waf_info is not None:
            replay_preview["waf_block"] = waf_info
            self.waf_pivot.record_block(
                str(waf_info.get("vendor") or "generic"),
                str(current.get("path") or current.get("url") or "/"),
            )
            if self.waf_pivot.should_pivot():
                replay_preview["waf_pivot_guidance"] = self.waf_pivot.guidance()
        out = {
            "baseline_receipt_id": baseline["receipt_id"],
            "baseline_actor": baseline["actor"],
            "replay": replay_preview,
            "diff": _compute_structural_diff(baseline, current),
        }
        return wrap_untrusted(out)

    def _tool_browser_crawl(self, args: dict[str, Any]) -> str:
        mode = str(args.get("mode") or "crawl").strip().lower()
        url = str(args.get("url") or "/").strip() or "/"
        actor = str(args.get("actor") or "anon").strip() or "anon"
        if mode == "inspect":
            result = inspect_rendered_page(
                self.http,
                url=url,
                actor=actor,
                marker=str(args.get("marker") or ""),
            )
            return wrap_untrusted(result)
        if mode == "dom_verify":
            source = str(args.get("source") or "hash").strip().lower() or "hash"
            param_name = str(args.get("param_name") or "").strip()
            try:
                result = verify_dom_sink_in_browser(
                    self.http,
                    url=url,
                    actor=actor,
                    source=source,
                    param_name=param_name,
                )
            except (ScopeViolationError, BudgetExhaustedError):
                raise
            except ValueError as exc:
                result = {
                    "ok": False,
                    "verified_dom_injection": False,
                    "dom_element_parsed": False,
                    "matched_sinks": [],
                    "postmessage_listeners": [],
                    "source": source,
                    "url": url,
                    "actor": actor,
                    "error": str(exc),
                }
            return wrap_untrusted(result)
        raw_max_pages = args.get("max_pages", 6)
        try:
            max_pages = int(raw_max_pages)
        except (TypeError, ValueError):
            max_pages = 6
        result = run_browser_crawl(
            self.http,
            self.surface_tracker,
            url=url,
            actor=actor,
            max_pages=max_pages,
        )
        return wrap_untrusted(result)

    def _resolve_hmac_key_arg(self, raw_key: Any) -> str:
        text = "" if raw_key is None else str(raw_key)
        stripped = text.strip()
        if not stripped:
            return ""
        cand_rid = ""
        if stripped.lower().startswith("receipt:"):
            cand_rid = stripped.split(":", 1)[1].strip()
        else:
            try:
                cand_rid = ReceiptStore.validate_receipt_id(stripped)
            except ValueError:
                cand_rid = ""
        if cand_rid:
            rec = self.receipts.get(cand_rid)
            return str(rec.get("body") or "")
        return text

    def _extract_actor_jwt_claims(self, alias: str) -> tuple[dict[str, Any], dict[str, Any], list[str]] | None:
        session = self.http.actors.get(alias)
        candidates: list[str] = []

        def _collect_local_storage_map(ls_map: Any) -> tuple[list[str], list[str]]:
            primary_ls: list[str] = []
            secondary_ls: list[str] = []
            if not isinstance(ls_map, dict):
                return primary_ls, secondary_ls
            for lk, lv in ls_map.items():
                val_str = str(lv or "").strip()
                if not val_str:
                    continue
                bucket = secondary_ls if "refresh" in str(lk or "").lower() else primary_ls
                bucket.append(val_str)
                if val_str.startswith(("{", "[")):
                    for jwt_match in _NON_ANCHORED_JWT_RE.findall(val_str):
                        bucket.append(jwt_match)
            return primary_ls, secondary_ls

        with session._lock:
            if session.access_token:
                candidates.append(session.access_token)
            for k, v in session.base_headers.items():
                if str(k).strip().lower() == "authorization" and v:
                    candidates.append(str(v))
            for cv in session.cookies.values():
                if cv:
                    candidates.append(str(cv))
            ls_primary: list[str] = []
            ls_secondary: list[str] = []
            p1, s1 = _collect_local_storage_map(getattr(session, "local_storage", None))
            ls_primary.extend(p1)
            ls_secondary.extend(s1)
            ls_by_origin = getattr(session, "local_storage_by_origin", None)
            if isinstance(ls_by_origin, dict):
                for origin_map in ls_by_origin.values():
                    p2, s2 = _collect_local_storage_map(origin_map)
                    ls_primary.extend(p2)
                    ls_secondary.extend(s2)
            candidates.extend(ls_primary)
            candidates.extend(ls_secondary)
        for raw_cand in candidates:
            tok = _strip_bearer(raw_cand)
            parts = tok.split(".")
            if len(parts) != 3:
                continue
            hb = _b64url_decode_segment(parts[0])
            pb = _b64url_decode_segment(parts[1])
            if hb is None or pb is None:
                continue
            try:
                h_obj = json.loads(hb.decode("utf-8"))
                p_obj = json.loads(pb.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue
            if not isinstance(h_obj, dict) or not isinstance(p_obj, dict):
                continue
            safe_payload = {
                str(k): v
                for k, v in p_obj.items()
                if not _is_sensitive_json_key(str(k))
            }
            findings = analyze_jwt(tok).get("findings") or []
            return dict(h_obj), safe_payload, list(findings)
        return None

    def _tool_analyze_token(self, args: dict[str, Any]) -> str:
        value = str(args.get("value") or "")
        kind = str(args.get("kind") or "auto").strip().lower() or "auto"
        alg = str(args.get("alg") or "").strip()
        hmac_key = self._resolve_hmac_key_arg(args.get("hmac_key"))
        claim_overrides = _coerce_mapping_arg(args.get("claim_overrides"))

        if value.strip().lower().startswith("actor:"):
            alias = value.split(":", 1)[1].strip() or "anon"
            extracted = self._extract_actor_jwt_claims(alias)
            if extracted is None:
                return json.dumps(
                    {"kind": "jwt", "valid_jwt": False, "actor": alias, "error": "no JWT found in actor session"},
                    ensure_ascii=False,
                )
            base_hdr, safe_pay, findings = extracted
            want_test = kind in {"jwt_test", "jwt_forge", "jwt_confusion"} or bool(
                alg or hmac_key or claim_overrides is not None
            )
            if want_test:
                result = build_jwt_test_variants(
                    "",
                    alg=alg,
                    hmac_key=hmac_key,
                    claim_overrides=claim_overrides,
                    base_header=base_hdr,
                    base_payload=safe_pay,
                )
                return json.dumps(result, ensure_ascii=False)
            return json.dumps(
                {
                    "kind": "jwt",
                    "valid_jwt": True,
                    "source": "actor_session",
                    "actor": alias,
                    "header": _sanitize_claims(base_hdr),
                    "payload": _sanitize_claims(safe_pay),
                    "findings": findings,
                },
                ensure_ascii=False,
            )

        result = analyze_token(
            value,
            kind=kind,
            alg=alg,
            hmac_key=hmac_key,
            claim_overrides=claim_overrides,
        )
        return json.dumps(result, ensure_ascii=False)

    def _hydrate_sandbox_receipt_refs(self, raw_refs: Any) -> list[dict[str, Any]]:
        if raw_refs is None:
            return []
        if not isinstance(raw_refs, list):
            raise ValueError("inputs.receipt_refs must be a list of receipt IDs")
        if len(raw_refs) > 10:
            raise ValueError("inputs.receipt_refs exceeds maximum of 10 receipts")

        all_secrets = self.http.actors.all_secrets()
        extra_sensitive_hdrs = {
            str(h).strip().lower() for h in self.http.actors.sensitive_header_names()
        } | _SKIP_REPLAY_HEADERS
        hydrated: list[dict[str, Any]] = []
        for raw_rid in raw_refs:
            if not isinstance(raw_rid, str) or not raw_rid.strip():
                raise ValueError("each entry in inputs.receipt_refs must be a non-empty receipt_id string")
            rec = self.receipts.get(raw_rid.strip())
            red_resp_hdrs = redact_headers(rec.get("response_headers") or {})
            safe_resp_hdrs: dict[str, str] = {}
            for hk, hv in red_resp_hdrs.items():
                hk_str = str(hk)
                if hk_str.strip().lower() in extra_sensitive_hdrs and not str(hv).startswith("<REDACTED"):
                    safe_resp_hdrs[hk_str] = "<REDACTED>"
                else:
                    safe_resp_hdrs[hk_str] = redact_secrets(str(hv), all_secrets)
            hydrated.append({
                "receipt_id": str(rec.get("receipt_id") or ""),
                "status": int(rec.get("status") or 0),
                "method": str(rec.get("method") or ""),
                "url": redact_secrets(str(rec.get("url") or ""), all_secrets),
                "content_type": str(rec.get("content_type") or ""),
                "response_headers": safe_resp_hdrs,
                "body": redact_secrets(str(rec.get("body") or ""), all_secrets)[:4096],
            })
        return hydrated

    def _tool_run_sandbox_probe(self, args: dict[str, Any]) -> str:
        runtime = str(args.get("runtime") or "python_pure").strip().lower() or "python_pure"
        if runtime != "python_pure":
            raise ValueError(f"unsupported sandbox runtime: {runtime!r}; expected 'python_pure'")
        output_contract = str(args.get("output_contract") or "http_transform").strip().lower() or "http_transform"
        if output_contract not in {"http_transform", "decode_only"}:
            raise ValueError(
                f"unsupported output_contract: {output_contract!r}; expected 'http_transform' or 'decode_only'"
            )
        raw_code = args.get("code")
        if not isinstance(raw_code, str):
            raise ValueError("code must be a string")

        raw_timeout = args.get("timeout_ms", 1500)
        if isinstance(raw_timeout, bool):
            raise ValueError("timeout_ms must be an integer")
        try:
            timeout_ms = int(raw_timeout) if raw_timeout is not None else 1500
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid timeout_ms: {raw_timeout!r}") from exc

        raw_inputs_arg = args.get("inputs")
        if raw_inputs_arg is None:
            raw_inputs: dict[str, Any] = {}
        else:
            coerced = _coerce_mapping_arg(raw_inputs_arg)
            if coerced is None:
                raise ValueError("inputs must be an object")
            raw_inputs = coerced

        hydrated_receipts = self._hydrate_sandbox_receipt_refs(raw_inputs.get("receipt_refs"))
        sandbox_inputs: dict[str, Any] = {
            str(k): copy.deepcopy(v)
            for k, v in raw_inputs.items()
            if k != "receipt_refs"
        }
        if hydrated_receipts:
            sandbox_inputs["receipts"] = hydrated_receipts

        all_secrets = self.http.actors.all_secrets()
        res = run_python_pure_sandbox(
            raw_code,
            inputs=sandbox_inputs,
            timeout_ms=timeout_ms,
            secret_values=all_secrets,
        )
        res["output_contract"] = output_contract
        if self.telemetry is not None:
            self.telemetry.emit(
                "sandbox_probe",
                worker_id=self.active_worker_id,
                node_id=self.active_node_id,
                category=self.active_category,
                runtime=runtime,
                output_contract=output_contract,
                ok=bool(res.get("ok")),
                elapsed_ms=res.get("elapsed_ms"),
                receipt_ref_count=len(hydrated_receipts),
            )
        return wrap_untrusted(res)

    def _tool_extract_surface(self, args: dict[str, Any]) -> str:
        receipt = self.receipts.get(str(args.get("receipt_id") or ""))
        body = str(receipt.get("body") or "")
        discovered_hdr_for_fact = str(getattr(self.http.actors, "discovered_auth_header", "") or "").strip()
        if (
            200 <= int(receipt.get("status") or 0) < 300
            and len(body) <= 2_000_000
            and body.lstrip().startswith("{")
            and ('"securitySchemes"' in body or '"securityDefinitions"' in body)
            and not discovered_hdr_for_fact
        ):
            try:
                parsed_spec = json.loads(body)
            except ValueError:
                parsed_spec = None
            if isinstance(parsed_spec, dict):
                for hdr_name in extract_openapi_header_auth_names(parsed_spec):
                    if hdr_name.lower() != "authorization":
                        self.http.register_discovered_auth_header(hdr_name)
                        discovered_hdr_for_fact = hdr_name
                        break
        summary_extra = _supported_kwargs(
            _extract_surface_summary,
            {
                "in_scope_assets": tuple(getattr(self.http, "in_scope_assets", ()) or ()),
                "out_of_scope_assets": tuple(getattr(self.http, "out_of_scope_assets", ()) or ()),
            },
        )
        surface = _extract_surface_summary(receipt, self.http.base_url, **summary_extra)
        self.surface_tracker.ingest_receipt(receipt)
        self.surface_tracker.ingest_surface(surface, actor=str(receipt.get("actor") or ""))
        if self.bsag is not None:
            dv1, de1 = self.bsag.ingest_receipt(receipt, mark_visited=False)
            dv2, de2 = self.bsag.ingest_surface(surface, actor=str(receipt.get("actor") or ""))
            self._step_delta_v += dv1 + dv2
            self._step_delta_e += de1 + de2
        if self.shared_facts is not None:
            source_shard = self.active_worker_id or "bootstrap"
            src_rid = str(receipt.get("receipt_id") or "")
            all_secrets = self.http.actors.all_secrets()
            if discovered_hdr_for_fact:
                self.shared_facts.publish(
                    "auth_header",
                    f"header:{discovered_hdr_for_fact}",
                    f"Custom auth header {discovered_hdr_for_fact} discovered",
                    source_shard=source_shard,
                    source_receipt_id=src_rid,
                    provenance="host_extracted",
                    target_families=("*",),
                    confidence="deterministic",
                    secret_values=all_secrets,
                )
            for internal_url in _extract_internal_host_urls(receipt, surface, base_url=self.http.base_url):
                self.shared_facts.publish(
                    "internal_host",
                    f"internal_host:{internal_url}",
                    f"Internal/metadata host {internal_url} referenced in {receipt.get('url') or ''}",
                    source_shard=source_shard,
                    source_receipt_id=src_rid,
                    provenance="host_extracted",
                    target_families=("*", "ssrf", "webhooks", "idor", "api"),
                    confidence="deterministic",
                    secret_values=all_secrets,
                )
        compact_surface = {
            k: v
            for k, v in surface.items()
            if k in {"receipt_id", "url", "content_type"} or bool(v)
        }
        return wrap_untrusted(compact_surface)

    def _tool_notebook(self, args: dict[str, Any]) -> str:
        action = str(args.get("action") or "read").strip().lower()
        if action == "publish_fact":
            raw_fact = args.get("fact")
            if not isinstance(raw_fact, dict):
                return json.dumps({"rejected": True, "reason": "fact dict is required"})
            fact_type = str(raw_fact.get("fact_type") or "").strip().lower()
            if fact_type not in VALID_FACT_TYPES:
                return json.dumps({"rejected": True, "reason": f"invalid fact_type: {fact_type!r}"})
            raw_key = str(raw_fact.get("key") or raw_fact.get("canonical_key") or "").strip()
            raw_summary = str(raw_fact.get("summary") or "").strip()
            source_rid = str(raw_fact.get("source_receipt_id") or "").strip()
            if not raw_key or not raw_summary:
                return json.dumps({"rejected": True, "reason": "fact key and summary are required"})
            if not source_rid:
                return json.dumps({"rejected": True, "reason": "source_receipt_id is required"})
            try:
                receipt = self.receipts.get(source_rid)
            except (KeyError, ValueError):
                return json.dumps({"rejected": True, "reason": f"source_receipt_id {source_rid!r} not found"})

            oob_hits: list[dict[str, Any]] = []
            oob_srv = self._get_oob_server(start=False)
            if oob_srv is not None:
                try:
                    polled = oob_srv.poll("")
                    if isinstance(polled, dict):
                        oob_hits = [h for h in (polled.get("hits") or ()) if isinstance(h, dict)]
                except Exception:
                    oob_hits = []

            if not _is_fact_grounded_in_receipt(raw_key, fact_type, receipt, oob_hits=oob_hits):
                return json.dumps({"rejected": True, "reason": "fact_not_grounded_in_receipt"})

            raw_tf = raw_fact.get("target_families")
            target_families: tuple[str, ...]
            if isinstance(raw_tf, (list, tuple)):
                cleaned_tf = tuple(str(x).strip().lower() for x in raw_tf if str(x).strip())
                target_families = cleaned_tf or ("*",)
            elif isinstance(raw_tf, str) and raw_tf.strip():
                cleaned_tf = tuple(s.strip().lower() for s in raw_tf.split(",") if s.strip())
                target_families = cleaned_tf or ("*",)
            else:
                target_families = ("*",)

            all_secrets = self.http.actors.all_secrets()
            source_shard = self.active_worker_id or "bootstrap"
            published_fact: dict[str, Any] | None
            if self.shared_facts is not None:
                published_fact = self.shared_facts.publish(
                    fact_type,
                    raw_key,
                    raw_summary,
                    source_shard=source_shard,
                    source_receipt_id=source_rid,
                    provenance="model_receipt_verified",
                    target_families=target_families,
                    confidence="model_receipt_verified",
                    secret_values=all_secrets,
                )
                if published_fact is None:
                    return json.dumps({"rejected": True, "reason": "fact_rejected_by_shared_fact_graph"})
            else:
                safe_key = _scrub_secret_text(raw_key, all_secrets)[:220]
                safe_sum = _scrub_secret_text(raw_summary, all_secrets)[:280]
                if not safe_key or not safe_sum or "<REDACTED" in safe_key:
                    return json.dumps({"rejected": True, "reason": "fact_rejected_by_secret_hygiene"})
                published_fact = {
                    "fact_id": "sf_000",
                    "seq": 0,
                    "fact_type": fact_type,
                    "canonical_key": safe_key,
                    "summary": safe_sum,
                    "source_shard": source_shard,
                    "source_receipt_id": source_rid,
                    "provenance": "model_receipt_verified",
                    "target_families": list(target_families),
                    "confidence": "model_receipt_verified",
                }

            note_entry = f"[{published_fact['fact_id']}] {fact_type}: {published_fact['summary']}"[:400]
            with self._notebook_lock:
                self.notebook_state["notes"] = [*self.notebook_state.get("notes", []), note_entry][-40:]
                self._save_notebook()
            return json.dumps({"published": True, "fact": published_fact}, ensure_ascii=False)

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
        headers = _coerce_mapping_arg(args.get("headers"))
        query = _coerce_mapping_arg(args.get("query"))
        json_body = _coerce_json_payload(args.get("json_body"))
        form_body = _coerce_mapping_arg(args.get("form_body"))
        raw_body = str(args["raw_body"]) if args.get("raw_body") is not None else None

        clean_url, _, _ = self.http._merge_query(url, query)
        session = self.http.actors.get(actor)
        auth_override_keys = {"authorization", "cookie"}
        with session._lock:
            if getattr(session, "auth_header_name", "").strip():
                auth_override_keys.add(session.auth_header_name.strip().lower())
        has_auth_override = any(str(k).strip().lower() in auth_override_keys for k in (headers or {}))
        self._enforce_http_reserve_floor(needed=count)
        if actor != "anon" and not has_auth_override and not session.authenticated:
            self.http.authenticate_actor(actor, force_login=False)

        remaining = self.http._budget_remaining()
        if remaining < count:
            raise BudgetExhaustedError(
                f"concurrent_check requires {count} HTTP requests, only {remaining} remaining in budget"
            )
        self._enforce_http_reserve_floor(needed=count)

        barrier = threading.Barrier(count, timeout=10.0)
        req_extra = _supported_kwargs(self.http.request, {"concurrent_burst": True})

        def _worker() -> dict[str, Any]:
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass
            return self.http.request(
                method=norm_method,
                url=url,
                actor=actor,
                headers=copy.deepcopy(headers) if headers is not None else None,
                query=copy.deepcopy(query) if query is not None else None,
                json_body=copy.deepcopy(json_body) if json_body is not None else None,
                form_body=copy.deepcopy(form_body) if form_body is not None else None,
                raw_body=raw_body,
                force=True,
                **req_extra,
            )

        with ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(_worker) for _ in range(count)]
            receipts = [fut.result() for fut in futures]

        for rec in receipts:
            self._ingest_receipt_hooks(rec)

        burst_id = f"burst-{uuid.uuid4().hex[:12]}"
        status_counts: dict[str, int] = {}
        receipt_ids: list[str] = []
        distinct_hashes: list[str] = []
        seen_hashes: set[str] = set()
        results: list[dict[str, Any]] = []
        any_waf_block = False
        for rec in receipts:
            rec["concurrent_burst_id"] = burst_id
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
                "concurrent_burst_id": burst_id,
                "status": int(rec.get("status") or 0),
                "elapsed_ms": rec.get("elapsed_ms"),
                "response_sha256": sha[:16],
                "body_preview": preview_body if preview_body else "<empty>",
            }
            waf_info = detect_waf_block(rec)
            if waf_info is not None:
                any_waf_block = True
                item["waf_block"] = waf_info
                self.waf_pivot.record_block(
                    str(waf_info.get("vendor") or "generic"),
                    str(rec.get("path") or rec.get("url") or "/"),
                )
            if rec.get("error"):
                item["error"] = rec["error"]
            results.append(item)

        payload: dict[str, Any] = {
            "concurrent_burst_id": burst_id,
            "count": len(receipts),
            "method": norm_method,
            "url": clean_url,
            "actor": actor,
            "status_counts": status_counts,
            "receipt_ids": receipt_ids,
            "distinct_body_hashes": distinct_hashes,
            "results": results,
        }
        if any_waf_block and self.waf_pivot.should_pivot():
            payload["waf_pivot_guidance"] = self.waf_pivot.guidance()
        return wrap_untrusted(payload)

    @staticmethod
    def _format_response_headers(receipt: dict[str, Any]) -> str:
        raw_headers = receipt.get("response_headers") or {}
        if not isinstance(raw_headers, dict) or not raw_headers:
            return ""
        return "\n".join(f"{k}: {v}" for k, v in raw_headers.items())

    @staticmethod
    def _is_genuine_anon_proof(
        receipt: dict[str, Any],
        actor_meta: dict[str, dict[str, str]],
    ) -> bool:
        if _is_genuine_anon_2xx(receipt, actor_meta):
            return True
        if (
            str(receipt.get("actor") or "").strip() == "anon"
            and str(receipt.get("method") or "").upper() == "DELETE"
            and int(receipt.get("status") or 0) == 204
        ):
            resp_headers = {
                str(k).lower(): str(v).strip()
                for k, v in (receipt.get("response_headers") or {}).items()
            }
            known_non_anon = {a for a in actor_meta if a and a != "anon"}
            for hname in _ACTOR_IDENTITY_HEADERS:
                hval = resp_headers.get(hname, "")
                if hval and hval != "anon" and (hval in known_non_anon or not known_non_anon):
                    return False
            return True
        return False

    @staticmethod
    def _delete_204_evidence_supported(
        primary: dict[str, Any],
        control_receipts: list[dict[str, Any]],
        evidence_value: str,
    ) -> bool:
        ev_low = str(evidence_value or "").strip().lower()
        if not ev_low:
            return False
        if not any(int(c.get("status") or 0) != 204 for c in control_receipts):
            return False
        p_path = _norm_path(str(primary.get("url") or primary.get("path") or ""))
        status_desc = f"http 204 no content delete {p_path} deleted"
        if ev_low in status_desc or ev_low in p_path or ev_low in str(primary.get("url") or "").lower():
            return True
        for ctrl in control_receipts:
            c_body = str(ctrl.get("body") or "").lower()
            c_hdrs = json.dumps(ctrl.get("response_headers") or {}, ensure_ascii=False).lower()
            if ev_low in c_body or ev_low in c_hdrs:
                return True
        return False

    def _receipt_contains_evidence(self, receipt: dict[str, Any], evidence: str) -> tuple[bool, str]:
        needle = evidence.strip()
        if not needle:
            return False, ""
        lower_needle = needle.lower()
        body = str(receipt.get("body") or "")
        loc = str(receipt.get("redirect_location") or "")
        raw_headers = receipt.get("response_headers") or {}
        headers_lines = self._format_response_headers(receipt)
        headers_text = json.dumps(raw_headers, ensure_ascii=False)

        if needle in body or lower_needle in body.lower():
            return True, build_receipt_excerpt(receipt, needle, max_chars=MAX_PROOF_EXCERPT_CHARS)
        if body:
            compacted_needle = compact_json_text(needle)
            try:
                parsed_body = json.loads(body)
            except ValueError:
                parsed_body = None
            if parsed_body is not None:
                redumped_body = json.dumps(parsed_body, ensure_ascii=False, separators=(",", ":"))
                if (
                    needle in redumped_body
                    or lower_needle in redumped_body.lower()
                    or compacted_needle in redumped_body
                    or compacted_needle.lower() in redumped_body.lower()
                ):
                    return True, build_receipt_excerpt(receipt, needle, max_chars=MAX_PROOF_EXCERPT_CHARS)
            unescaped_body = _unescape_json_escapes(body)
            if needle in unescaped_body or lower_needle in unescaped_body.lower():
                esc_hint = json.dumps(needle, ensure_ascii=True)[1:-1]
                excerpt_needle = esc_hint if esc_hint in body else needle
                return True, build_receipt_excerpt(receipt, excerpt_needle, max_chars=MAX_PROOF_EXCERPT_CHARS)
            compacted_body = compact_json_text(body)
            if (
                compacted_needle in compacted_body
                or compacted_needle.lower() in compacted_body.lower()
            ):
                return True, build_receipt_excerpt(receipt, needle, max_chars=MAX_PROOF_EXCERPT_CHARS)
            compacted_unescaped = compact_json_text(unescaped_body)
            if (
                compacted_needle in compacted_unescaped
                or compacted_needle.lower() in compacted_unescaped.lower()
            ):
                return True, build_receipt_excerpt(receipt, needle, max_chars=MAX_PROOF_EXCERPT_CHARS)
        if needle in loc or lower_needle in loc.lower():
            return True, build_receipt_excerpt(receipt, needle, max_chars=MAX_PROOF_EXCERPT_CHARS)
        if headers_lines and lower_needle in headers_lines.lower():
            return True, headers_lines[:MAX_PROOF_EXCERPT_CHARS]
        if lower_needle in headers_text.lower():
            return True, headers_text[:MAX_PROOF_EXCERPT_CHARS]
        return False, ""

    def _collect_oob_ssrf_context(
        self,
        proof_receipts: list[dict[str, Any]],
        evidence_value: str,
    ) -> tuple[str, list[str], list[dict[str, Any]]]:
        """Inspect proof receipts and evidence for callback_listener tokens/hits."""
        oob_srv = self._get_oob_server(start=False)
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
        title: str = "",
        summary: str = "",
        severity: str = "",
        origin: str = "",
        graphql_op: str = "",
    ) -> dict[str, Any] | None:
        """Merge into an existing finding sharing `(origin, route_template, graphql_op, class_type)`, cross-class overlap, or alias/family root cause under `_findings_lock`."""
        cur_origin = origin or _extract_finding_origin(raw_url, self.http.base_url)
        cur_graphql_op = str(graphql_op or "").strip()
        norm_sev = str(severity or "").strip().lower()
        incoming_stub: dict[str, Any] = {
            "class_type": canonical_class,
            "route_template": route_template,
            "origin": cur_origin,
            "graphql_op": cur_graphql_op,
            "method": method,
            "url": raw_url,
            "path": effective_norm_path,
            "actor": effective_actor,
            "actor_alias": effective_actor,
            "evidence_value": evidence_value,
            "marker": evidence_value,
            "proof_receipt_ids": list(proof_ids),
            "control_receipt_ids": list(control_ids),
        }
        if norm_sev in _SEVERITY_RANK:
            incoming_stub["severity"] = norm_sev

        matched_existing: dict[str, Any] | None = None
        matched_existing_class = ""
        matched_existing_tmpl = ""
        matched_resolved_class = ""
        matched_kind = ""
        best_match_rank: tuple[int, int, int] | None = None

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
            existing_origin = str(
                existing.get("origin")
                or _extract_finding_origin(
                    str(existing.get("url") or existing.get("path") or ""),
                    self.http.base_url,
                )
            )
            if cur_origin and existing_origin and existing_origin != cur_origin:
                continue

            existing_graphql_op = str(existing.get("graphql_op") or "").strip()
            if not existing_graphql_op and (
                cur_graphql_op
                or "graphql" in existing_tmpl.lower()
                or existing_tmpl.lower().endswith("/gql")
                or "/gql/" in existing_tmpl.lower()
            ):
                ex_proof_recs: list[dict[str, Any]] = []
                for rid in (existing.get("proof_receipt_ids") or []):
                    try:
                        ex_proof_recs.append(self.receipts.get(str(rid)))
                    except (KeyError, ValueError):
                        continue
                existing_graphql_op = _extract_graphql_op(
                    existing_tmpl,
                    ex_proof_recs,
                    raw_url=str(existing.get("url") or existing.get("path") or ""),
                    existing_finding=existing,
                )
            if existing_graphql_op != cur_graphql_op:
                continue

            existing_norm = {
                **existing,
                "class_type": existing_class,
                "route_template": existing_tmpl,
            }
            if existing_tmpl == route_template:
                if existing_class == canonical_class or {existing_class, canonical_class} == {"auth_bypass", "bfla"}:
                    matched_existing = existing
                    matched_existing_class = existing_class
                    matched_existing_tmpl = existing_tmpl
                    matched_resolved_class = canonical_class
                    matched_kind = "exact"
                    break

                cross = _resolve_cross_class_overlap(
                    existing_norm,
                    incoming_stub,
                    receipt_store=self.receipts,
                )
                if cross is not None:
                    winner_cls, match_prio = cross
                    spec_rank = _STATE_TAMPERING_CLASS_RANK.get(winner_cls, -1)
                    rank = (0, match_prio, spec_rank)
                    if best_match_rank is None or rank < best_match_rank:
                        best_match_rank = rank
                        matched_existing = existing
                        matched_existing_class = existing_class
                        matched_existing_tmpl = existing_tmpl
                        matched_resolved_class = winner_cls
                        matched_kind = "cross_class"
                continue

            alias_overlap = _resolve_alias_or_family_overlap(
                existing_norm,
                incoming_stub,
                receipt_store=self.receipts,
            )
            if alias_overlap is not None:
                winner_cls, match_prio, alias_kind = alias_overlap
                kind_tier = 1 if alias_kind == "api_alias" else 2
                spec_rank = _STATE_TAMPERING_CLASS_RANK.get(winner_cls, -1)
                rank = (kind_tier, match_prio, spec_rank)
                if best_match_rank is None or rank < best_match_rank:
                    best_match_rank = rank
                    matched_existing = existing
                    matched_existing_class = existing_class
                    matched_existing_tmpl = existing_tmpl
                    matched_resolved_class = winner_cls
                    matched_kind = alias_kind

        if matched_existing is None:
            return None

        existing = matched_existing
        if cur_origin and not existing.get("origin"):
            existing["origin"] = cur_origin
        if cur_graphql_op and not existing.get("graphql_op"):
            existing["graphql_op"] = cur_graphql_op
        existing_class = matched_existing_class
        existing_tmpl = matched_existing_tmpl
        existing_norm_for_rank = {
            **existing,
            "class_type": existing_class,
            "route_template": existing_tmpl,
        }

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

        resolved_class = matched_resolved_class
        if matched_kind == "exact" and {existing_class, canonical_class} == {"auth_bypass", "bfla"}:
            resolved_class = _resolve_route_auth_bypass_vs_bfla(
                route_template,
                all_proof_recs,
                all_ctrl_recs,
                actor_meta_map=actor_meta,
                receipt_store=self.receipts,
                exact_path=effective_norm_path,
                method=method,
            )

        incoming_higher_sev = _severity_rank(incoming_stub) < _severity_rank(existing)
        if incoming_higher_sev and norm_sev in _SEVERITY_RANK:
            existing["severity"] = norm_sev

        if matched_kind in {"api_alias", "route_family"}:
            ex_canon_rank = _canonical_entry_rank(existing_norm_for_rank, preferred_class=resolved_class)
            in_canon_rank = _canonical_entry_rank(incoming_stub, preferred_class=resolved_class)
            if in_canon_rank < ex_canon_rank:
                canonical_route_template = route_template
                secondary_route = existing_tmpl
                if title:
                    existing["title"] = title
                if summary:
                    existing["summary"] = summary
            else:
                canonical_route_template = existing_tmpl
                secondary_route = route_template
                if resolved_class != existing_class and resolved_class == canonical_class:
                    if title:
                        existing["title"] = title
                    if summary:
                        existing["summary"] = summary
            existing["route_template"] = canonical_route_template
            _record_route_aliases(existing, secondary_route)
        else:
            canonical_route_template = route_template
            existing["route_template"] = canonical_route_template
            if (resolved_class != existing_class and resolved_class == canonical_class) or (
                incoming_higher_sev and resolved_class == canonical_class
            ):
                if title:
                    existing["title"] = title
                if summary:
                    existing["summary"] = summary

        existing["class_type"] = resolved_class
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
                route_template=canonical_route_template,
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
                route_template=canonical_route_template,
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
        explicit_target_origin = (
            _extract_finding_origin(raw_url, self.http.base_url)
            if urlsplit(raw_url).netloc
            else ""
        )
        matching_proofs = [
            r for r in proof_receipts
            if r["actor"] == actor_alias
            and _norm_path(r["url"]) == target_norm_path
            and (
                not explicit_target_origin
                or _extract_finding_origin(r["url"], self.http.base_url) == explicit_target_origin
            )
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
        primary_origin = _extract_finding_origin(primary["url"], self.http.base_url)
        if primary["method"] != method and not (canonical_class == "mass_assignment" and primary["method"] == "GET"):
            return json.dumps({
                "rejected": True,
                "reason": f"proof receipt {primary['receipt_id']} method {primary['method']} does not match {method}",
            })
        allow_5xx_lead_probe = (
            self.oracle is not None
            and getattr(self.oracle, "mode", "") == "differential"
            and 500 <= int(primary["status"]) < 600
        )
        if not (200 <= primary["status"] < 400) and not allow_5xx_lead_probe:
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
            if not (200 <= r_status < 400) and not (allow_5xx_lead_probe and 500 <= r_status < 600):
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
                if primary_origin and _extract_finding_origin(r["url"], self.http.base_url) != primary_origin:
                    return False
                if r_method != method and not (canonical_class == "mass_assignment" and r_method == "GET"):
                    return False
            if canonical_class == "auth_bypass" and not self._is_genuine_anon_proof(r, actor_meta):
                return False
            return True

        compatible_proofs = [r for r in proof_receipts if _is_compatible_proof_receipt(r)]
        original_evidence_value = evidence_value
        excerpt = ""
        found_in_proof = False
        matching_oob_hits: list[dict[str, Any]] = []
        oob_matched_tokens: list[str] = []

        if canonical_class in _OOB_CALLBACK_CLASSES:
            oob_status, oob_matched_tokens, matching_oob_hits = self._collect_oob_ssrf_context(
                compatible_proofs or proof_receipts,
                evidence_value,
            )
            if oob_status in {"missing_server", "zero_hits"}:
                class_label = "SSRF" if canonical_class == "ssrf" else canonical_class.upper()
                return json.dumps({
                    "rejected": True,
                    "reason": (
                        f"{class_label} callback claim rejected: callback_listener poll recorded 0 hits "
                        f"for submitted token(s) {oob_matched_tokens}"
                    ),
                })

        is_empty_delete_204 = (
            str(primary.get("method") or "").upper() == "DELETE"
            and int(primary.get("status") or 0) == 204
            and not str(primary.get("body") or "").strip()
        )
        ev_clean = evidence_value.strip()
        is_cors_wildcard = (
            canonical_class == "cors_misconfiguration"
            and ev_clean == "*"
            and any(
                str(k).strip().lower() == "access-control-allow-origin" and str(v).strip() == "*"
                for r in (compatible_proofs or [primary])
                for k, v in (r.get("response_headers") or {}).items()
            )
        )
        is_cors_null_origin = (
            canonical_class == "cors_misconfiguration"
            and ev_clean.lower() == "null"
            and any(
                str(k).strip().lower() == "access-control-allow-origin"
                and str(v).strip().lower() == "null"
                for r in (compatible_proofs or [primary])
                for k, v in (r.get("response_headers") or {}).items()
            )
        )
        is_cors_exempt = is_cors_wildcard or is_cors_null_origin
        allow_delete_204_ev = is_empty_delete_204 and self._delete_204_evidence_supported(
            primary,
            control_receipts,
            evidence_value,
        )

        if not is_cors_exempt and not allow_delete_204_ev and (
            not evidence_value or evidence_value.lower() in _TRIVIAL_EVIDENCE or len(evidence_value) < 3
        ):
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
            if is_cors_wildcard:
                for r in [*matching_proofs, *compatible_proofs]:
                    raw_hdrs = r.get("response_headers") or {}
                    if any(
                        str(k).strip().lower() == "access-control-allow-origin" and str(v).strip() == "*"
                        for k, v in raw_hdrs.items()
                    ):
                        found_in_proof = True
                        primary = r
                        excerpt = self._format_response_headers(r)[:MAX_PROOF_EXCERPT_CHARS]
                        break
            elif is_cors_null_origin:
                for r in [*matching_proofs, *compatible_proofs]:
                    raw_hdrs = r.get("response_headers") or {}
                    if any(
                        str(k).strip().lower() == "access-control-allow-origin"
                        and str(v).strip().lower() == "null"
                        for k, v in raw_hdrs.items()
                    ):
                        found_in_proof = True
                        primary = r
                        excerpt = self._format_response_headers(r)[:MAX_PROOF_EXCERPT_CHARS]
                        break
            if not found_in_proof and canonical_class in _OOB_CALLBACK_CLASSES and matching_oob_hits:
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
            elif not found_in_proof:
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
                if not found_in_proof and allow_delete_204_ev:
                    found_in_proof = True
                    hdr_lines = self._format_response_headers(primary)
                    status_line = f"HTTP 204 No Content (DELETE {primary.get('url') or primary.get('path') or ''})"
                    excerpt = f"{status_line}\n{hdr_lines}"[:MAX_PROOF_EXCERPT_CHARS] if hdr_lines else status_line
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
            and canonical_class not in {"open_redirect", "reflected_xss", "stored_xss", "race_condition", "cors_misconfiguration"}
            and not matching_oob_hits
            and not is_empty_delete_204
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
        finding_origin = _extract_finding_origin(primary["url"] or raw_url, self.http.base_url)
        finding_graphql_op = _extract_graphql_op(
            route_template,
            [primary, *compatible_proofs],
            raw_url=raw_url,
        )

        # Class-specific anti-false-positive checks.
        if canonical_class == "open_redirect":
            loc = primary.get("redirect_location") or ""
            if not (300 <= primary["status"] < 400 and loc):
                return json.dumps({"rejected": True, "reason": "open_redirect requires 3xx status with Location header"})
            loc_str = str(loc).strip()
            if loc_str.startswith("//"):
                base_scheme = urlsplit(str(primary.get("url") or self.http.base_url)).scheme or "https"
                parsed_loc = urlsplit(f"{base_scheme}:{loc_str}")
            else:
                parsed_loc = urlsplit(loc_str)
            loc_host = parsed_loc.netloc
            base_host = urlsplit(self.http.base_url).netloc
            if not loc_host or loc_host == base_host:
                return json.dumps({"rejected": True, "reason": f"redirect Location {loc!r} is not an external host"})
            scope_guard = getattr(self.http, "scope_guard", None)
            if scope_guard is not None:
                loc_scheme = (parsed_loc.scheme or urlsplit(self.http.base_url).scheme or "http").lower()
                loc_hostname = (parsed_loc.hostname or "").strip().lower().rstrip(".")
                try:
                    loc_port = parsed_loc.port
                except ValueError:
                    loc_port = None
                if loc_port is None:
                    loc_port = 443 if loc_scheme == "https" else (80 if loc_scheme == "http" else None)
                if (
                    loc_scheme in {"http", "https"}
                    and loc_hostname
                    and isinstance(loc_port, int)
                    and scope_guard.check_origin(loc_scheme, loc_hostname, loc_port)
                ):
                    return json.dumps({
                        "rejected": True,
                        "reason": f"redirect Location {loc!r} targets an authorized in-scope origin, not an external host",
                    })
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
            if not self._is_genuine_anon_proof(primary, actor_meta):
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

        # Deduplicate & merge by (origin, route_template, graphql_op), cross-class overlap, or alias/family root cause.
        norm_severity = severity if severity in {"critical", "high", "medium", "low"} else "high"
        if not allow_5xx_lead_probe:
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
                    title=title,
                    summary=summary,
                    severity=norm_severity,
                    origin=finding_origin,
                    graphql_op=finding_graphql_op,
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
            valid_rids = {
                str(r.get("receipt_id") or "")
                for r in valid_receipts_only
                if r.get("receipt_id")
            }
            caller_setup_receipts = [
                r
                for r in proof_receipts
                if str(r.get("receipt_id") or "") not in valid_rids
                and str(r.get("method") or "").upper() in _MUTATING_WRITE_METHODS
                and 200 <= int(r.get("status") or 0) < 400
                and not _is_multipart_receipt(r)
            ]
            verdict = self.oracle.verify(
                canonical_class=canonical_class,
                primary_proof=best_primary,
                proof_receipts=valid_receipts_only,
                control_receipts=control_receipts,
                evidence_value=evidence_value,
                actor_meta_map=actor_meta,
                surface_tracker=self.surface_tracker,
                inferred_owner=inferred_bola_owner,
                oob_server=self._get_oob_server(start=False),
                oob_hits=matching_oob_hits,
                setup_receipts=caller_setup_receipts,
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
                if getattr(verdict, "needs_verification", False):
                    lead_id, total_leads = self._record_needs_verification_lead(
                        verdict=verdict,
                        title=title,
                        canonical_class=canonical_class,
                        route_template=route_template,
                        method=method,
                        raw_url=raw_url,
                        primary=best_primary,
                        valid_proof_records=valid_proof_records,
                        control_receipts=control_receipts,
                        evidence_value=evidence_value,
                        default_excerpt=excerpt,
                        summary=summary,
                        severity=norm_severity,
                        best_actor=best_actor,
                        ordered_actors=ordered_actors,
                        proof_ids=proof_ids,
                        control_ids=control_ids,
                        matching_oob_hits=matching_oob_hits,
                        oob_matched_tokens=oob_matched_tokens,
                    )
                    return json.dumps({
                        "rejected": True,
                        "accepted": False,
                        "recorded_as_lead": True,
                        "lead_id": lead_id,
                        "verification_tier": "NEEDS_VERIFICATION",
                        "oracle_verdict": verdict.verdict,
                        "signal_type": verdict.signal_type,
                        "reason": verdict.reason,
                        "stages": verdict.stages,
                        "total_leads": total_leads,
                    })
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
        hdr_lines = self._format_response_headers(best_primary)
        if hdr_lines and (
            canonical_class == "cors_misconfiguration"
            or (
                evidence_value
                and evidence_value.lower() not in (best_evidence or "").lower()
                and evidence_value.lower() in hdr_lines.lower()
            )
        ):
            hdr_note = f"---[response_headers]---\n{hdr_lines[:1024]}"
            best_evidence = f"{hdr_note}\n{best_evidence}" if best_evidence else hdr_note
        if (
            str(best_primary.get("method") or "").upper() == "DELETE"
            and int(best_primary.get("status") or 0) == 204
            and not str(best_primary.get("body") or "").strip()
            and "204" not in (best_evidence or "")
        ):
            del_status_line = f"HTTP 204 No Content (DELETE {best_primary.get('url') or best_primary.get('path') or ''})"
            best_evidence = f"{del_status_line}\n{best_evidence}" if best_evidence else del_status_line
        if matching_oob_hits:
            hit0 = matching_oob_hits[0]
            oob_note = (
                f"---[oob_callback:token={hit0.get('token')} hits={len(matching_oob_hits)}]---\n"
                f"{hit0.get('method')} {hit0.get('path')} query={hit0.get('query') or ''} "
                f"remote={hit0.get('remote_addr')} body={hit0.get('body_preview') or ''}"
            )
            best_evidence = f"{best_evidence}\n{oob_note}" if best_evidence else oob_note
        resolved_url, clean_path, _ = self.http.resolve_in_scope(best_primary["url"] or raw_url)
        resolved_origin = _extract_finding_origin(resolved_url, self.http.base_url) or finding_origin
        resolved_graphql_op = _extract_graphql_op(
            route_template,
            valid_receipts_only,
            raw_url=resolved_url,
        ) or finding_graphql_op
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
                title=title,
                summary=summary,
                severity=norm_severity,
                origin=resolved_origin,
                graphql_op=resolved_graphql_op,
            )
            if merged_resp is not None:
                if self.shared_facts is not None:
                    self.shared_facts.publish(
                        "verified_primitive",
                        f"{canonical_class}:{best_primary['method']}:{route_template}",
                        f"{canonical_class} {best_primary['method']} {route_template} actor={best_actor}",
                        source_shard=self.active_worker_id or "bootstrap",
                        source_receipt_id=str(best_primary.get("receipt_id") or ""),
                        provenance="host_extracted",
                        target_families=("*",),
                        confidence="deterministic",
                        secret_values=self.http.actors.all_secrets(),
                    )
                return json.dumps(merged_resp)

            finding_id = f"F-{len(self.findings) + 1:03d}"
            finding: dict[str, Any] = {
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
            if resolved_origin:
                finding["origin"] = resolved_origin
            if resolved_graphql_op:
                finding["graphql_op"] = resolved_graphql_op
            self.findings.append(finding)
            self._save_findings()
            total_findings = len(self.findings)
        if self.shared_facts is not None:
            self.shared_facts.publish(
                "verified_primitive",
                f"{canonical_class}:{best_primary['method']}:{route_template}",
                f"{canonical_class} {best_primary['method']} {route_template} actor={best_actor}",
                source_shard=self.active_worker_id or "bootstrap",
                source_receipt_id=str(best_primary.get("receipt_id") or ""),
                provenance="host_extracted",
                target_families=("*",),
                confidence="deterministic",
                secret_values=self.http.actors.all_secrets(),
            )
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
