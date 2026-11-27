"""Layer 4: Protocol-level, vuln-class-agnostic 3-stage Clean-Replay Differential Oracle."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
import html
import json
import math
import re
import statistics
import time
from typing import Any, Callable, Sequence
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit
import uuid

import requests

from agentic_http import (
    DEFAULT_BROWSER_USER_AGENT,
    AgenticHTTPClient,
    BudgetExhaustedError,
    ScopeViolationError,
    _decode_raw_response,
    _header_get,
)
from agentic_receipts import ReceiptStore, redact_header_value
from agentic_surface import is_id_segment, normalize_path, route_template_of
from target_bootstrap import is_destructive_lifecycle_route, is_logout_route

VALID_VERIFICATION_GATES = frozenset({"differential", "llm_self_judge"})

_BOLA_OWNER_KEYS = (
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
_BOLA_TENANT_KEYS = (
    "tenant",
    "tenant_slug",
    "tenant_id",
    "org",
    "organization",
    "company",
)

_EPHEMERAL_JSON_KEYS = frozenset({
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
})
_JOB_QUEUE_ID_KEYS = frozenset({
    "prompt_id",
    "job_id",
    "task_id",
    "run_id",
    "execution_id",
    "queue_id",
})
_JOB_QUEUE_SEQ_KEYS = frozenset({
    "number",
    "queue_number",
    "seq",
})
_EPHEMERAL_REPLAY_JSON_KEYS = _EPHEMERAL_JSON_KEYS | _JOB_QUEUE_ID_KEYS | frozenset({
    "event_id",
    "session_id",
    "correlation_id",
    "receipt_id",
})
_WEAK_CRED_TOKEN_KEYS = frozenset({
    "token",
    "access_token",
    "auth_token",
    "session_token",
    "jwt",
    "sid",
    "session",
    "session_id",
    "csrf_token",
})
_HTML_UNESCAPE_EVIDENCE_CLASSES = frozenset({"sqli_read", "sqli", "other"})
_ISO_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_HEX_EPHEMERAL_RE = re.compile(r"[0-9a-fA-F]{16,64}")
_HEX_MASK_RE = re.compile(r"\b[0-9a-fA-F]{24,64}\b")
_NON_REPLAY_REQ_HEADERS = frozenset({
    "authorization",
    "cookie",
    "x-csrf-token",
    "x-xsrf-token",
    "content-length",
    "host",
})
_INPUT_DIFF_CLASSES = frozenset({
    "reflected_xss",
    "stored_xss",
    "sqli",
    "sqli_read",
    "open_redirect",
    "mass_assignment",
    "ssti",
    "path_traversal",
    "csrf",
    "ssrf",
    "cors_misconfiguration",
    "xxe",
    "file_upload",
    "jwt_weakness",
    "weak_credentials",
    "command_injection",
    "insecure_deserialization",
})
_OOB_ELIGIBLE_CLASSES = frozenset({"ssrf", "xxe", "ssti", "command_injection", "insecure_deserialization"})
_TIMING_ELIGIBLE_CLASSES = frozenset({
    "sqli_read",
    "sqli",
    "rce",
    "cmd_injection",
    "command_injection",
    "ssti",
    "ssrf",
})
_ACCESS_CLASSES = frozenset({"auth_bypass", "bfla", "bola", "tenant_isolation"})
_CONCURRENCY_CLASSES = frozenset({"race_condition", "business_logic"})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
_PERSISTENT_CLASSES = frozenset({"stored_xss", "mass_assignment", "ssti"})
_MAX_MULTISTEP_PRECURSORS = 3
_MULTISTEP_STORE_LOOKBACK = 60
_MULTISTEP_ID_EXACT_KEYS = frozenset({
    "id",
    "uid",
    "uuid",
    "guid",
    "token",
    "code",
    "slug",
    "key",
    "order_id",
    "orderid",
    "draft_id",
    "draftid",
    "item_id",
    "itemid",
    "cart_id",
    "cartid",
    "checkout_id",
    "checkoutid",
    "session_id",
    "sessionid",
    "job_id",
    "jobid",
    "task_id",
    "taskid",
    "workflow_id",
    "workflowid",
    "ticket_id",
    "invoice_id",
    "payment_id",
    "booking_id",
    "record_id",
    "resource_id",
    "object_id",
    "document_id",
    "doc_id",
    "project_id",
    "run_id",
})
_MULTISTEP_ID_SUFFIXES = ("_id", "_uid", "_uuid", "_token")
_MULTISTEP_EXCLUDED_ID_KEYS = frozenset({
    "csrf_token",
    "xsrf_token",
    "access_token",
    "refresh_token",
    "id_token",
    "trace_id",
    "span_id",
    "correlation_id",
    "request_id",
})
_CAMEL_ID_KEY_RE = re.compile(r"^[a-z][a-zA-Z0-9]*(?:Id|Uid|Uuid|Token)$")
_API_PREFIX_SEGMENTS = frozenset({"api", "v1", "v2", "v3", "v4"})
_API_VERSION_SEG_RE = re.compile(r"^v\d+$", re.I)
_CREATE_CONFLICT_INDICATOR_RE = re.compile(
    r"(?<![a-z0-9])(?:already[\s_-]+exists?|already[\s_-]+taken|"
    r"already[\s_-]+registered|already[\s_-]+in[\s_-]+use|"
    r"already[\s_-]+redeemed|already[\s_-]+used|already[\s_-]+applied|"
    r"already[\s_-]+processed|limit[\s_-]+reached|"
    r"duplicate|conflict)(?![a-z0-9])",
    re.IGNORECASE,
)
_UNRELATED_ROUTE_ERROR_RE = re.compile(
    r"(?:cannot\s+(?:get|post|put|patch|delete|head|options)\s+|"
    r"\bno\s+route\b|\broute\s+not\s+found\b|\bunknown\s+route\b|"
    r"\bunknown\s+endpoint\b|\bendpoint\s+not\s+found\b|"
    r"requested\s+url\s+was\s+not\s+found|\bno\s+handler\b|"
    r"\b404\s+page\s+not\s+found\b)",
    re.IGNORECASE,
)
_TRIVIAL_CORRELATION_TOKENS = frozenset({
    "0",
    "1",
    "true",
    "false",
    "null",
    "none",
    "yes",
    "no",
    "on",
    "off",
    "ok",
    "all",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "json",
    "html",
    "text",
    "utf-8",
    "asc",
    "desc",
    "en",
    "us",
})
_OWNER_TENANT_ENVELOPE_KEYS = frozenset({
    "data",
    "result",
    "user",
    "account",
    "order",
    "item",
    "record",
    "profile",
    "payload",
})


def _extract_origin(url_or_path: str) -> str:
    """Return normalized `scheme://netloc` origin for an explicit HTTP(S)/WS(S) URL, else ''."""
    raw = str(url_or_path or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "ws", "wss"} or not parsed.netloc:
        return ""
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    default_port = 80 if scheme in {"http", "ws"} else 443
    host_part = f"[{host}]" if ":" in host else host
    netloc = f"{host_part}:{port}" if (port is not None and port != default_port) else host_part
    return f"{scheme}://{netloc}"


def _is_graphql_error_envelope(receipt: dict[str, Any]) -> bool:
    """Return True if receipt JSON body is a GraphQL error-only envelope (`errors` with empty/null `data`)."""
    body = str(receipt.get("body") or "").strip()
    if not body.startswith("{"):
        return False
    parsed = _try_parse_json_body(body)
    if not isinstance(parsed, dict):
        return False
    errors = parsed.get("errors")
    if not isinstance(errors, list) or len(errors) == 0:
        return False
    if "data" not in parsed or parsed["data"] is None:
        return True
    data = parsed["data"]
    if isinstance(data, dict):
        return all(v is None for v in data.values())
    return False


def _is_denied_control_receipt(receipt: dict[str, Any]) -> bool:
    """Return True for HTTP 401/403/404 denials or HTTP-2xx GraphQL error-only responses."""
    status = int(receipt.get("status") or 0)
    if status in {401, 403, 404}:
        return True
    if 200 <= status < 300 and _is_graphql_error_envelope(receipt):
        return True
    return False


def _extract_owner_and_tenant_from_receipt(
    receipt: dict[str, Any],
    actor_meta_map: dict[str, dict[str, str]],
) -> tuple[str, str]:
    """Extract explicit owner alias and tenant string from top-level or nested JSON envelope receipts."""
    body = str(receipt.get("body") or "").strip()
    if not body.startswith(("{", "[")):
        return "", ""
    try:
        parsed = json.loads(body)
    except ValueError:
        return "", ""
    if not isinstance(parsed, (dict, list)):
        return "", ""

    owner_actor = ""
    record_tenant = ""
    queue: list[tuple[Any, int]] = [(parsed, 0)]
    q_idx = 0
    visited = 0
    while q_idx < len(queue) and visited < 120:
        node, depth = queue[q_idx]
        q_idx += 1
        visited += 1
        if isinstance(node, dict):
            if not owner_actor:
                for key in _BOLA_OWNER_KEYS:
                    val = node.get(key)
                    if isinstance(val, str):
                        clean = val.strip()
                        if clean and clean != "anon" and (clean in actor_meta_map or not actor_meta_map):
                            owner_actor = clean
                            break
            if not record_tenant:
                for key in _BOLA_TENANT_KEYS:
                    val = node.get(key)
                    if isinstance(val, str) and val.strip():
                        record_tenant = val.strip().lower()
                        break
            if owner_actor and record_tenant:
                break
            if depth < 3:
                for k, v in node.items():
                    if str(k).lower() in _OWNER_TENANT_ENVELOPE_KEYS and isinstance(v, (dict, list)):
                        queue.append((v, depth + 1))
        elif isinstance(node, list) and 1 <= len(node) <= 5 and depth < 3:
            for item in node:
                if isinstance(item, (dict, list)):
                    queue.append((item, depth + 1))

    if not record_tenant and owner_actor and owner_actor in actor_meta_map:
        record_tenant = str(actor_meta_map[owner_actor].get("tenant") or "").strip().lower()
    return owner_actor, record_tenant


def _receipt_store_lists_object_for_actor(
    receipt_store: ReceiptStore,
    concrete_path: str,
    actor: str,
) -> bool:
    """Return True if `receipt_store` shows `actor` received this concrete object ID in a 2xx collection response."""
    norm_p = normalize_path(concrete_path)
    parts = [seg for seg in norm_p.split("/") if seg]
    if len(parts) < 2 or not is_id_segment(parts[-1]):
        return False
    concrete_id = parts[-1]
    concrete_id_low = concrete_id.lower()
    resource_family = parts[-2].lower()
    parent_path = "/" + "/".join(parts[:-1])
    singular = resource_family[:-1] if len(resource_family) > 2 and resource_family.endswith("s") else resource_family
    short_singular = singular.replace("-", "_").split("_")[-1]
    id_keys = {"id", "uuid", f"{singular}_id", f"{short_singular}_id"}
    html_link_re = re.compile(
        rf"""(?:{re.escape(parent_path)}|/{re.escape(resource_family)})/{re.escape(concrete_id)}(?:["'/?#\s>]|$)""",
        re.IGNORECASE,
    )

    for rid in receipt_store.list_ids():
        try:
            rec = receipt_store.get(rid)
        except (KeyError, ValueError):
            continue
        if str(rec.get("actor") or "").strip() != actor:
            continue
        if str(rec.get("method") or "").upper() != "GET":
            continue
        if not (200 <= int(rec.get("status") or 0) < 300):
            continue
        rec_path = normalize_path(str(rec.get("url") or rec.get("path") or ""))
        if "{id}" in route_template_of(rec_path):
            continue
        if not (
            rec_path == parent_path
            or rec_path == f"/{resource_family}"
            or rec_path.endswith(f"/{resource_family}")
        ):
            continue
        body = str(rec.get("body") or "")
        if not body:
            continue
        stripped = body.lstrip()
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
            items: list[dict[str, Any]] = []
            if isinstance(parsed, list):
                items = [x for x in parsed[:100] if isinstance(x, dict)]
            elif isinstance(parsed, dict):
                for v in parsed.values():
                    if isinstance(v, list):
                        items.extend(x for x in v[:100] if isinstance(x, dict))
            for item in items:
                for k, v in item.items():
                    if str(k).lower() in id_keys and isinstance(v, (str, int)) and not isinstance(v, bool):
                        if str(v).strip().lower() == concrete_id_low:
                            return True
        ctype = str(rec.get("content_type") or "").lower()
        if ("html" in ctype or "href=" in body.lower()) and html_link_re.search(body):
            return True
    return False


def check_bola_false_positive(
    *,
    primary_proof: dict[str, Any],
    proof_receipts: Sequence[dict[str, Any]],
    control_receipts: Sequence[dict[str, Any]],
    actor_meta_map: dict[str, dict[str, str]] | None,
    receipt_store: ReceiptStore | None = None,
    surface_tracker: Any | None = None,
    inferred_owner: str = "",
) -> tuple[str, str] | None:
    """Detect common BOLA false positives; return `(stage_code, reason)` if rejected, else None."""
    p_actor = str(primary_proof.get("actor") or "").strip()
    meta_map = actor_meta_map or {}
    p_tenant = str((meta_map.get(p_actor) or {}).get("tenant") or "").strip().lower()
    p_method = str(primary_proof.get("method") or "GET").strip().upper()
    p_path = normalize_path(str(primary_proof.get("url") or primary_proof.get("path") or ""))
    p_tmpl = route_template_of(p_path)

    # Guard 2: Read-only GET/HEAD BOLA cannot claim a shared-tenant resource that appeared in the
    # claiming actor's own 2xx collection listing.
    if p_method in {"GET", "HEAD"} and p_actor and p_actor != "anon" and "{id}" in p_tmpl:
        listed_in_tracker = (
            surface_tracker is not None
            and hasattr(surface_tracker, "was_object_listed_for_actor")
            and bool(surface_tracker.was_object_listed_for_actor(p_path, p_actor))
        )
        listed_in_store = (
            receipt_store is not None
            and _receipt_store_lists_object_for_actor(receipt_store, p_path, p_actor)
        )
        if listed_in_tracker or listed_in_store:
            return (
                "failed_bola_shared_collection_resource",
                (
                    f"Read-only BOLA rejected: actor {p_actor!r} legitimately received concrete object "
                    f"{p_path!r} in its own 2xx collection listing (shared-tenant resource, not BOLA)."
                ),
            )

    # Guard 1: Same-tenant BOLA cannot rely solely on cross-tenant or anon denied controls.
    explicit_owner, record_tenant = _extract_owner_and_tenant_from_receipt(primary_proof, meta_map)
    eff_owner = explicit_owner or str(inferred_owner or "").strip()
    if not eff_owner and surface_tracker is not None:
        obj_entry = (getattr(surface_tracker, "discovered_objects", None) or {}).get(p_path)
        if isinstance(obj_entry, dict):
            eff_owner = str(obj_entry.get("owner_actor") or "").strip()
    if not eff_owner:
        proof_actors = {str(r.get("actor") or "").strip() for r in proof_receipts}
        for ctrl in control_receipts:
            c_actor = str(ctrl.get("actor") or "").strip()
            if (
                c_actor
                and c_actor != "anon"
                and c_actor not in proof_actors
                and 200 <= int(ctrl.get("status") or 0) < 300
                and not _is_graphql_error_envelope(ctrl)
            ):
                eff_owner = c_actor
                break
    owner_tenant = record_tenant or str((meta_map.get(eff_owner) or {}).get("tenant") or "").strip().lower()

    if p_tenant and owner_tenant and p_tenant == owner_tenant:
        denied_controls = [c for c in control_receipts if _is_denied_control_receipt(c)]
        if denied_controls:
            has_same_tenant_denied = False
            has_cross_tenant_denied = False
            for ctrl in denied_controls:
                c_actor = str(ctrl.get("actor") or "").strip()
                c_tenant = str((meta_map.get(c_actor) or {}).get("tenant") or "").strip().lower()
                if c_actor and c_actor != "anon":
                    if c_tenant == p_tenant:
                        has_same_tenant_denied = True
                    elif c_tenant and c_tenant != p_tenant:
                        has_cross_tenant_denied = True
            distinct_tenants = {
                str(m.get("tenant") or "").strip().lower()
                for m in meta_map.values()
                if str(m.get("tenant") or "").strip()
            }
            if not has_same_tenant_denied:
                if has_cross_tenant_denied:
                    return (
                        "failed_bola_cross_tenant_only_control",
                        (
                            "Same-tenant BOLA rejected: all denied control receipts belong only to cross-tenant "
                            "actors or 'anon'. Cross-tenant denial proves tenant isolation, not same-tenant peer "
                            "restriction; provide a same-tenant peer denial control (403/404) or verify "
                            "cross-tenant access as 'tenant_isolation'."
                        ),
                    )
                if len(distinct_tenants) >= 2 or not explicit_owner:
                    return (
                        "failed_bola_anon_only_control",
                        (
                            "Same-tenant BOLA rejected: all denied control receipts belong only to 'anon' with "
                            "no same-tenant peer denial control. Anonymous denial proves authentication, not "
                            "same-tenant peer restriction; provide a same-tenant peer denial control (403/404)."
                        ),
                    )
    return None


def _receipt_contains_evidence(
    receipt: dict[str, Any],
    evidence_value: str,
    *,
    canonical_class: str = "",
) -> bool:
    ev = str(evidence_value or "").strip().lower()
    if not ev:
        return True
    body = str(receipt.get("body") or "")
    loc = str(receipt.get("redirect_location") or "")
    resp_headers = receipt.get("response_headers") or {}
    hdrs = json.dumps(resp_headers, ensure_ascii=False)
    hdr_lines = "\n".join(f"{k}: {v}" for k, v in resp_headers.items()) if isinstance(resp_headers, dict) else ""
    if ev in f"{body}\n{loc}\n{hdrs}\n{hdr_lines}".lower():
        return True
    if canonical_class in _HTML_UNESCAPE_EVIDENCE_CLASSES and is_html_receipt(receipt) and body:
        unescaped = html.unescape(body).lower()
        if ev in unescaped:
            return True
        if re.sub(r"\s+", " ", ev) in re.sub(r"\s+", " ", unescaped):
            return True
    ctype = _receipt_content_type(receipt)
    if (ctype == "application/json" or ctype.endswith("+json") or body.lstrip().startswith(("{", "["))) and body:
        compact_body = re.sub(r"\s*([:,\[\]{}])\s*", r"\1", body).lower()
        compact_ev = re.sub(r"\s*([:,\[\]{}])\s*", r"\1", ev)
        if compact_ev and compact_ev in compact_body:
            return True
    return False


def _receipt_content_type(receipt: dict[str, Any]) -> str:
    """Return normalized lowercase media type from receipt metadata or Content-Type header."""
    ctype = str(receipt.get("content_type") or "").strip().lower()
    if ctype:
        return ctype.split(";", 1)[0].strip()
    headers = receipt.get("response_headers") or {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == "content-type":
                return str(v).split(";", 1)[0].strip().lower()
    return ""


def is_html_receipt(receipt: dict[str, Any]) -> bool:
    """Return True if the receipt has an HTML content-type (e.g. text/html or application/xhtml+xml)."""
    return "html" in _receipt_content_type(receipt)


def _is_multipart_receipt(receipt: dict[str, Any]) -> bool:
    """Return True if a receipt represents a multipart/form-data upload with a non-binary body summary."""
    req_body = str(receipt.get("request_body") or "").lstrip().lower()
    if req_body.startswith("multipart/form-data "):
        return True
    req_headers = receipt.get("request_headers") or {}
    if isinstance(req_headers, dict):
        for k, v in req_headers.items():
            if str(k).strip().lower() == "content-type":
                if str(v or "").strip().lower().startswith("multipart/form-data"):
                    return True
    return False


def _response_header_ci(receipt: dict[str, Any], header_name: str) -> str:
    """Return a response header value matched case-insensitively, stripped."""
    target = header_name.strip().lower()
    headers = receipt.get("response_headers") or {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).strip().lower() == target:
                return str(v or "").strip()
    return ""


def _request_header_ci(receipt: dict[str, Any], header_name: str) -> str:
    """Return a request header value matched case-insensitively, stripped."""
    target = header_name.strip().lower()
    headers = receipt.get("request_headers") or {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).strip().lower() == target:
                return str(v or "").strip()
    return ""


def _cors_header_signature(receipt: dict[str, Any]) -> tuple[str, str]:
    """Return `(Access-Control-Allow-Origin, Access-Control-Allow-Credentials)` for CORS diffing."""
    acao = _response_header_ci(receipt, "access-control-allow-origin").lower()
    acac = _response_header_ci(receipt, "access-control-allow-credentials").lower()
    return acao, acac


_VOLATILE_RESPONSE_HEADERS = frozenset({
    "date",
    "etag",
    "last-modified",
    "age",
    "connection",
    "keep-alive",
    "content-length",
    "transfer-encoding",
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "x-amzn-requestid",
    "x-amz-request-id",
    "x-amz-id-2",
    "cf-ray",
    "x-runtime",
    "x-response-time",
    "server-timing",
    "x-envoy-upstream-service-time",
})
_COOKIE_ATTR_LOWER = frozenset({
    "path",
    "domain",
    "expires",
    "max-age",
    "secure",
    "httponly",
    "samesite",
    "partitioned",
})


def _normalize_set_cookie_signature(raw_val: str, *, preserve_values: Sequence[str] = ()) -> str:
    """Normalize Set-Cookie header so rotating token values match while cookie names/flags stay distinct."""
    preserved_low = [str(p).strip().lower() for p in preserve_values if isinstance(p, str) and len(p) >= 3]
    parts_out: list[str] = []
    for cookie_item in str(raw_val or "").split(","):
        seg = cookie_item.strip()
        if not seg:
            continue
        attrs = [a.strip() for a in seg.split(";") if a.strip()]
        if not attrs:
            continue
        norm_attrs: list[str] = []
        for idx, attr in enumerate(attrs):
            if "=" in attr:
                ak, av = attr.split("=", 1)
                akl = ak.strip().lower()
                av_clean = av.strip()
                if idx == 0 or akl not in _COOKIE_ATTR_LOWER:
                    if any(pv in av_clean.lower() for pv in preserved_low):
                        norm_attrs.append(f"{akl}={av_clean}")
                    else:
                        norm_attrs.append(f"{akl}=<COOKIE_VAL>")
                elif akl in {"expires", "max-age"}:
                    norm_attrs.append(f"{akl}=<TTL>")
                else:
                    norm_attrs.append(f"{akl}={av_clean.lower()}")
            else:
                norm_attrs.append(attr.lower())
        parts_out.append(";".join(norm_attrs))
    return "|".join(sorted(parts_out))


def _response_headers_signature(
    receipt: dict[str, Any],
    *,
    preserve_values: Sequence[str] = (),
) -> tuple[tuple[str, str], ...]:
    """Return canonicalized non-volatile response header signature for Stage 1/2 diffing."""
    headers = receipt.get("response_headers") or {}
    if not isinstance(headers, dict):
        return ()
    sig: list[tuple[str, str]] = []
    for k, v in headers.items():
        lk = str(k or "").strip().lower()
        if not lk or lk in _VOLATILE_RESPONSE_HEADERS:
            continue
        val_str = str(v or "").strip()
        if lk == "set-cookie":
            norm_val = _normalize_set_cookie_signature(val_str, preserve_values=preserve_values)
        else:
            norm_val = mask_dynamic_fields(val_str, preserve_values=preserve_values).lower()
        sig.append((lk, norm_val))
    sig.sort()
    return tuple(sig)


def _is_sensitive_authenticated_receipt(
    receipt: dict[str, Any],
    eff_controls: Sequence[dict[str, Any]] = (),
) -> bool:
    """Return True if a CORS proof carries authenticated/sensitive data rather than anonymous public output."""
    actor = str(receipt.get("actor") or "").strip()
    status = int(receipt.get("status") or 0)
    if not (200 <= status < 300):
        return False
    req_headers = receipt.get("request_headers") or {}
    has_auth_hdr = isinstance(req_headers, dict) and any(
        str(k).strip().lower() in {"authorization", "cookie", "x-api-key", "x-auth-token"} and str(v or "").strip()
        for k, v in req_headers.items()
    )
    if (actor and actor != "anon") or has_auth_hdr:
        body = str(receipt.get("body") or "").strip()
        if len(body) > 2:
            return True
    for ctrl in eff_controls:
        c_actor = str(ctrl.get("actor") or "").strip()
        if c_actor == "anon" and _is_denied_control_receipt(ctrl):
            return True
    return False


def _is_exempt_static_cors_control(
    diff_target: dict[str, Any],
    ctrl: dict[str, Any],
    eff_controls: Sequence[dict[str, Any]],
) -> bool:
    """Allow static `ACAO: *` (with ACAC:true or sensitive auth data) and `Origin: null` -> `ACAO: null` when control uses a different Origin."""
    p_acao, p_acac = _cors_header_signature(diff_target)
    p_origin = _request_header_ci(diff_target, "origin").lower()
    c_origin = _request_header_ci(ctrl, "origin").lower()
    if c_origin == p_origin:
        return False
    is_static_wildcard = p_acao == "*" and (
        p_acac == "true" or _is_sensitive_authenticated_receipt(diff_target, eff_controls)
    )
    is_null_origin = p_origin == "null" and p_acao == "null" and (
        p_acac == "true" or _is_sensitive_authenticated_receipt(diff_target, eff_controls)
    )
    return is_static_wildcard or is_null_origin


_OVERRIDDEN_AUTH_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-auth-token",
    "x-api-key",
})
_CREDENTIAL_BODY_KEY_EXACT = frozenset({
    "password",
    "passwd",
    "pwd",
    "pass",
    "passcode",
    "passphrase",
    "secret",
    "credential",
    "credentials",
    "cred",
    "creds",
    "pin",
    "pincode",
    "otp",
    "totp",
    "mfa",
    "code",
    "verifycode",
    "verificationcode",
    "authcode",
    "clientsecret",
    "appsecret",
    "csrf_token",
    "csrf",
    "xsrf_token",
    "xsrf",
    "csrftoken",
    "csrfmiddlewaretoken",
    "_csrf",
    "_token",
    "authenticity_token",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "id_token",
    "idtoken",
    "auth_token",
    "authtoken",
    "session_token",
    "sessiontoken",
    "api_key",
    "apikey",
    "token",
    "jwt",
    "bearer",
})
_CREDENTIAL_BODY_KEY_TOKENS = frozenset({
    "password",
    "passwd",
    "pwd",
    "pass",
    "passcode",
    "passphrase",
    "secret",
    "credential",
    "credentials",
    "cred",
    "creds",
    "pin",
    "otp",
    "totp",
    "mfa",
    "csrf",
    "xsrf",
    "csrftoken",
    "authenticity",
    "token",
    "apikey",
    "jwt",
})
_CREDENTIAL_CODE_PREFIX_TOKENS = frozenset({
    "verify",
    "verification",
    "auth",
    "authentication",
    "login",
    "signin",
    "mfa",
    "2fa",
    "twofa",
    "sms",
    "security",
    "access",
    "otp",
    "totp",
    "pin",
    "pass",
})
_CAMEL_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")
_REDACTED_CRED_JSON_PAIR_RE = re.compile(
    r"""["']([A-Za-z0-9_.-]{1,64})["']\s*:\s*["']([^"']*<(?:REDACTED_SECRET[^"']*|REDACTED)>[^"']*)["']"""
)
_AUTH_ENDPOINT_PATH_RE = re.compile(
    r"/(?:login|log[-_]?in|signin|sign[-_]?in|auth(?:enticate|entication|orize|orization)?|"
    r"tokens?|oauth2?|jwt|sessions?|sso|oidc|mfa|2fa|otp)(?:/|$)",
    re.IGNORECASE,
)
_AUTH_REJECTION_BODY_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    r"(?:illegal|invalid|wrong|bad|incorrect|missing|expired|failed|mismatch(?:ed)?)[_\s-]*"
    r"(?:password|passwd|pwd|passcode|passphrase|credentials?|secret|pin|otp|totp|token|login|auth(?:entication)?|grant|client|code|csrf|xsrf|authenticity(?:[_\s-]*token)?|api[_\s-]*key)"
    r"|(?:password|passwd|pwd|passcode|passphrase|credentials?|login|signin|sign[-_]?in|auth(?:entication|orization)?|unauthenticated|unauthorized|otp|totp|mfa|pin|csrf|xsrf|authenticity(?:[_\s-]*token)?|api[_\s-]*key|access[_\s-]*token)[_\s-]*"
    r"(?:error|fail(?:ed|ure)?|invalid|illegal|incorrect|wrong|denied|reject(?:ed)?|mismatch(?:ed)?|required|expired|validation|check)"
    r"|illegal_password|bad_credentials|invalid_grant|access_denied|unauthorized|unauthenticated|authentication|credential"
    r"|password|passwd|passcode|csrf|xsrf"
    r")(?![a-z0-9])",
    re.IGNORECASE,
)
_CSRF_BODY_FIELD_KEYS = frozenset({
    "csrf",
    "csrf_token",
    "xsrf_token",
    "xsrf",
    "csrftoken",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "_csrf",
    "_token",
    "__token__",
    "__requestverificationtoken",
})


def _has_redacted_credential_placeholder(value: str) -> bool:
    """Return True if a value contains a ReceiptStore redacted credential placeholder."""
    return "<REDACTED_SECRET" in value or "<REDACTED>" in value


def _is_credential_body_key(raw_key: str) -> bool:
    """Return True if a JSON or form field key denotes a password/secret/credential/CSRF/API-token input."""
    clean = str(raw_key or "").strip()
    if not clean:
        return False
    low = clean.lower()
    if low in _CREDENTIAL_BODY_KEY_EXACT:
        return True
    normalized = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", clean).lower()
    tokens = [tok for tok in re.split(r"[^a-z0-9]+", normalized) if tok]
    if not tokens:
        return False
    if any(tok in _CREDENTIAL_BODY_KEY_TOKENS for tok in tokens):
        return True
    if "api" in tokens and "key" in tokens:
        return True
    if "code" in tokens and any(tok in _CREDENTIAL_CODE_PREFIX_TOKENS for tok in tokens):
        return True
    return False


def _contains_redacted_placeholder_in_obj(obj: Any, *, max_nodes: int = 100) -> bool:
    stack: list[Any] = [obj]
    visited = 0
    while stack and visited < max_nodes:
        cur = stack.pop()
        visited += 1
        if isinstance(cur, str):
            if _has_redacted_credential_placeholder(cur):
                return True
        elif isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur[:50])
    return False


def _has_redacted_credential_body(receipt: dict[str, Any]) -> bool:
    """Return True if `receipt`'s saved request_body has a redacted placeholder on a credential/token/CSRF key or ReceiptStore secret digest."""
    raw_body = str(receipt.get("request_body") or "").strip()
    if not raw_body or "REDACTED" not in raw_body:
        return False
    # ReceiptStore always tags scrubbed registered secrets (password/token/CSRF) with `<REDACTED_SECRET:sha256_8=...>`.
    if "<REDACTED_SECRET:" in raw_body:
        return True

    parsed_json = _try_parse_json_body(raw_body)
    if parsed_json is not None:
        stack: list[Any] = [parsed_json]
        visited = 0
        while stack and visited < 200:
            cur = stack.pop()
            visited += 1
            if isinstance(cur, dict):
                for k, v in cur.items():
                    if _is_credential_body_key(str(k)):
                        if isinstance(v, str) and _has_redacted_credential_placeholder(v):
                            return True
                        if isinstance(v, (dict, list)) and _contains_redacted_placeholder_in_obj(v):
                            return True
                    if isinstance(v, (dict, list)):
                        stack.append(v)
            elif isinstance(cur, list):
                for item in cur[:50]:
                    if isinstance(item, (dict, list)):
                        stack.append(item)
        return False

    if "=" in raw_body and not raw_body.startswith("<") and "\n" not in raw_body[:256]:
        for k, v in parse_qsl(raw_body, keep_blank_values=True):
            if _is_credential_body_key(k) and _has_redacted_credential_placeholder(v):
                return True
        return False

    # Fallback for truncated JSON bodies where ReceiptStore clipped the preview before closing braces.
    if raw_body.lstrip().startswith(("{", "[")):
        for match in _REDACTED_CRED_JSON_PAIR_RE.finditer(raw_body):
            if _is_credential_body_key(match.group(1)):
                return True
    return False


def _restore_session_csrf_in_body(raw_body: str, session_obj: Any) -> str:
    """Replace redacted CSRF field values in a replay request body with the actor's live CSRF token if available."""
    if not raw_body or "<REDACTED" not in raw_body or session_obj is None:
        return raw_body
    csrf_tok = str(getattr(session_obj, "csrf_token", "") or "")
    if not csrf_tok:
        return raw_body
    csrf_keys = set(_CSRF_BODY_FIELD_KEYS)
    session_field = str(getattr(session_obj, "csrf_field_name", "") or "").strip().lower()
    if session_field:
        csrf_keys.add(session_field)

    stripped = raw_body.strip()
    parsed_json = _try_parse_json_body(stripped)
    if parsed_json is not None:
        changed = False

        def _replace_json(obj: Any) -> Any:
            nonlocal changed
            if isinstance(obj, dict):
                out: dict[str, Any] = {}
                for k, v in obj.items():
                    if str(k).strip().lower() in csrf_keys and isinstance(v, str) and _has_redacted_credential_placeholder(v):
                        out[k] = csrf_tok
                        changed = True
                    else:
                        out[k] = _replace_json(v)
                return out
            if isinstance(obj, list):
                return [_replace_json(item) for item in obj]
            return obj

        updated = _replace_json(parsed_json)
        if changed:
            return json.dumps(updated, ensure_ascii=False, separators=(",", ":"))
        return raw_body

    if "=" in raw_body and not stripped.startswith("<") and "\n" not in raw_body[:256]:
        pairs = parse_qsl(raw_body, keep_blank_values=True)
        changed = False
        new_pairs: list[tuple[str, str]] = []
        for k, v in pairs:
            if k.strip().lower() in csrf_keys and _has_redacted_credential_placeholder(v):
                new_pairs.append((k, csrf_tok))
                changed = True
            else:
                new_pairs.append((k, v))
        if changed:
            return urlencode(new_pairs, doseq=True)
    return raw_body


def _can_accept_redacted_credential_body_replay(
    replay_target: dict[str, Any],
    replay_rec: dict[str, Any],
    *,
    evidence_value: str,
    canonical_class: str,
) -> bool:
    """Fail-closed Stage 3 guard when clean replay fails solely due to a redacted body credential.

    Returns True ONLY when:
    1. `replay_target` is a mutating (`POST`/`PUT`/`PATCH`) request with 2xx/3xx status.
    2. `replay_target`'s saved `request_body` explicitly contains a redacted credential placeholder
       (`<REDACTED_SECRET...>` or `<REDACTED>`) associated with a credential/password/secret key.
    3. `replay_rec` returned an auth/validation rejection status (`400`, `401`, or `403`).
    4. When `replay_rec` status is `400`, either its response body contains an auth/credential/
       password/login rejection indicator or `replay_target` targets a login/auth/token/session endpoint.
    5. Non-empty `evidence_value` is corroborated in the original `replay_target` receipt.
    """
    method = str(replay_target.get("method") or "").upper()
    if method not in _WRITE_METHODS:
        return False
    orig_status = int(replay_target.get("status") or 0)
    if not (200 <= orig_status < 400):
        return False
    if not _has_redacted_credential_body(replay_target):
        return False

    replay_status = int(replay_rec.get("status") or 0)
    if replay_status not in {400, 401, 403}:
        return False

    if replay_status == 400:
        replay_body = str(replay_rec.get("body") or "")
        target_path = _norm_url_path(str(replay_target.get("url") or replay_target.get("path") or ""))
        if not (_AUTH_REJECTION_BODY_RE.search(replay_body) or _AUTH_ENDPOINT_PATH_RE.search(target_path)):
            return False

    ev = str(evidence_value or "").strip()
    if ev and not _receipt_contains_evidence(replay_target, ev, canonical_class=canonical_class):
        return False

    if canonical_class == "cors_misconfiguration":
        orig_acao = _response_header_ci(replay_target, "access-control-allow-origin")
        proof_origin = _request_header_ci(replay_target, "origin")
        return bool(
            orig_acao
            and (orig_acao == "*" or (bool(proof_origin) and orig_acao.lower() == proof_origin.lower()))
        )

    return True


def _has_overridden_redacted_auth_header(
    receipt: dict[str, Any],
    session_obj: Any,
    method: str,
) -> bool:
    """Return True if receipt sent a redacted auth/cookie header differing from the actor's default session."""
    req_headers = receipt.get("request_headers") or {}
    if not isinstance(req_headers, dict):
        return False
    session_headers = session_obj.build_headers(method)
    session_redacted = {
        str(k).strip().lower(): redact_header_value(str(k), str(v))
        for k, v in session_headers.items()
    }
    for k, v in req_headers.items():
        lk = str(k).strip().lower()
        val = str(v or "")
        if lk in _OVERRIDDEN_AUTH_HEADERS and "<REDACTED" in val:
            if val == redact_header_value(lk, ""):
                continue
            if session_redacted.get(lk, "") != val:
                return True
    return False


def _can_accept_redacted_auth_override(
    *,
    canonical_class: str,
    replay_target: dict[str, Any],
    diff_controls: Sequence[dict[str, Any]],
    eff_controls: Sequence[dict[str, Any]],
    is_oob_verified: bool,
    evidence_value: str,
    ev_in_oob: bool,
    p_status: int,
    p_masked: str,
    p_loc: str,
    p_cors_sig: tuple[str, str],
) -> bool:
    """Return True if a 401/403 clean replay with an overridden redacted auth header may verify."""
    if canonical_class in {"jwt_weakness", "auth_bypass"}:
        return True
    if canonical_class == "weak_credentials":
        if not eff_controls:
            return False
        if evidence_value and not _receipt_contains_evidence(
            replay_target, evidence_value, canonical_class=canonical_class
        ):
            return False
        return True
    # Authorization-boundary classes test the actor's own session; a 401/403 clean replay
    # with an overridden auth header means the actor's real session was properly denied.
    if canonical_class in {"bola", "bfla", "tenant_isolation"}:
        return False

    baseline_controls = (
        diff_controls
        if (canonical_class in _INPUT_DIFF_CLASSES and not is_oob_verified)
        else eff_controls
    )
    if is_oob_verified:
        has_valid_baseline = True
    elif canonical_class in _INPUT_DIFF_CLASSES:
        has_valid_baseline = any(
            200 <= int(c.get("status") or 0) < 300
            and (
                int(c.get("status") or 0) != p_status
                or mask_dynamic_fields(str(c.get("body") or ""), preserve_values=(evidence_value,)) != p_masked
                or urlsplit(str(c.get("redirect_location") or "")).netloc != urlsplit(p_loc).netloc
                or (
                    canonical_class == "cors_misconfiguration"
                    and (
                        _cors_header_signature(c) != p_cors_sig
                        or _is_exempt_static_cors_control(replay_target, c, eff_controls)
                    )
                )
                or (
                    canonical_class != "weak_credentials"
                    and _response_headers_signature(c, preserve_values=(evidence_value,))
                    != _response_headers_signature(replay_target, preserve_values=(evidence_value,))
                )
            )
            for c in baseline_controls
        )
    else:
        has_valid_baseline = any(
            200 <= int(c.get("status") or 0) < 300
            for c in baseline_controls
        )
    if not has_valid_baseline:
        return False

    if evidence_value and not ev_in_oob and not _receipt_contains_evidence(
        replay_target, evidence_value, canonical_class=canonical_class
    ):
        return False

    if canonical_class == "cors_misconfiguration":
        orig_acao = _response_header_ci(replay_target, "access-control-allow-origin")
        proof_origin = _request_header_ci(replay_target, "origin")
        return bool(
            orig_acao
            and (orig_acao == "*" or (bool(proof_origin) and orig_acao.lower() == proof_origin.lower()))
        )
    return True


def receipt_body_contains_verbatim(receipt: dict[str, Any], evidence_value: str) -> bool:
    """Return True if non-empty `evidence_value` appears verbatim (unescaped) in the receipt body."""
    ev = str(evidence_value or "").strip()
    if not ev:
        return False
    body = str(receipt.get("body") or "")
    return ev in body or ev.lower() in body.lower()


def _receipt_seq_num(receipt: dict[str, Any]) -> int:
    rid = str(receipt.get("receipt_id") or "").strip()
    if rid.startswith("req-") and rid[4:].isdigit():
        return int(rid[4:])
    return 0


def _norm_url_path(url_or_path: str) -> str:
    path = urlsplit(str(url_or_path or "")).path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return path.lower()


def _strip_api_prefix(segs: list[str]) -> list[str]:
    idx = 0
    while idx < len(segs):
        seg = segs[idx]
        if seg in _API_PREFIX_SEGMENTS or _API_VERSION_SEG_RE.fullmatch(seg):
            idx += 1
        else:
            break
    return segs[idx:] if idx < len(segs) else segs


def _segments_related(w_segs: list[str], r_segs: list[str]) -> bool:
    if w_segs == r_segs:
        return True
    # Parent/ancestor read: /<res>/<id>/reply -> /<res>/<id> or /<res>
    if r_segs and len(r_segs) < len(w_segs) and w_segs[: len(r_segs)] == r_segs:
        return True
    # Top-level collection write rendering on root page: /posts -> /
    if not r_segs and len(w_segs) == 1:
        return True
    # Child read after collection write: /<res> -> /<res>/<id>
    if w_segs and len(w_segs) < len(r_segs) and r_segs[: len(w_segs)] == w_segs:
        return True
    # Sibling under same non-API-root parent: /<res>/<id>/reply -> /<res>/<id>/thread
    if len(w_segs) >= 2 and len(r_segs) >= 2 and w_segs[:-1] == r_segs[:-1]:
        parent = w_segs[-2]
        if parent not in _API_PREFIX_SEGMENTS and not _API_VERSION_SEG_RE.fullmatch(parent):
            return True
    return False


def is_persistent_read_path_related(
    write_receipt_or_url: dict[str, Any] | str,
    read_url_or_path: str,
) -> bool:
    """Return True if a read GET path is on the same origin (when explicit) and same, parent, child, sibling, or redirect target of a write."""
    r_url = str(read_url_or_path or "")
    r_origin = _extract_origin(r_url)
    if isinstance(write_receipt_or_url, dict):
        w_url = str(write_receipt_or_url.get("url") or write_receipt_or_url.get("path") or "")
        w_origin = _extract_origin(w_url)
        redir = str(write_receipt_or_url.get("redirect_location") or "").strip()
        if redir and _norm_url_path(redir) == _norm_url_path(r_url):
            redir_origin = _extract_origin(redir) or w_origin
            if not (redir_origin and r_origin and redir_origin != r_origin):
                return True
    else:
        w_url = str(write_receipt_or_url or "")
        w_origin = _extract_origin(w_url)

    if w_origin and r_origin and w_origin != r_origin:
        return False

    w_path = _norm_url_path(w_url)
    r_path = _norm_url_path(r_url)
    if w_path == r_path:
        return True

    w_segs = [s for s in w_path.split("/") if s]
    r_segs = [s for s in r_path.split("/") if s]
    if _segments_related(w_segs, r_segs):
        return True

    w_stripped = _strip_api_prefix(w_segs)
    r_stripped = _strip_api_prefix(r_segs)
    if (w_stripped != w_segs or r_stripped != r_segs) and _segments_related(w_stripped, r_stripped):
        return True
    return False


def find_persistent_render_get_receipt(
    write_receipt: dict[str, Any],
    candidates: Sequence[dict[str, Any]],
    evidence_value: str,
    *,
    canonical_class: str = "",
) -> dict[str, Any] | None:
    """Select the strongest 2xx GET persistence/render proof matching a mutating write receipt."""
    w_actor = str(write_receipt.get("actor") or "")
    w_path = _norm_url_path(str(write_receipt.get("url") or write_receipt.get("path") or ""))
    ev = str(evidence_value or "").strip()

    matched: list[dict[str, Any]] = []
    for r in candidates:
        if str(r.get("method") or "").upper() != "GET":
            continue
        status = int(r.get("status") or 0)
        if not (200 <= status < 300):
            continue
        r_url = str(r.get("url") or r.get("path") or "")
        if not is_persistent_read_path_related(write_receipt, r_url):
            continue
        if canonical_class == "stored_xss":
            if not is_html_receipt(r):
                continue
            if ev and not receipt_body_contains_verbatim(r, ev):
                continue
        elif ev and not _receipt_contains_evidence(r, ev, canonical_class=canonical_class):
            continue
        matched.append(r)

    if not matched:
        return None
    matched.sort(
        key=lambda r: (
            1 if (ev and receipt_body_contains_verbatim(r, ev)) else 0,
            1 if is_html_receipt(r) else 0,
            1 if _norm_url_path(str(r.get("url") or r.get("path") or "")) == w_path else 0,
            1 if str(r.get("actor") or "") == w_actor else 0,
            _receipt_seq_num(r),
        ),
        reverse=True,
    )
    return matched[0]


def _select_mutating_get_proof(
    primary_proof: dict[str, Any],
    proof_receipts: list[dict[str, Any]],
    evidence_value: str,
    *,
    canonical_class: str = "",
) -> dict[str, Any] | None:
    """Select the best 2xx GET persistence proof for a mutating primary receipt.

    Non-idempotent mutations (e.g. ownership/tenant transfers or stored XSS/SSTI
    writes) may be unsafe to replay directly or may render on a parent/sibling GET
    endpoint, so replaying the follow-up 2xx GET is safer and more accurate.
    """
    p_method = str(primary_proof.get("method") or "").upper()
    if p_method not in _MUTATING_METHODS:
        return None
    p_actor = str(primary_proof.get("actor") or "")
    p_path = _norm_url_path(str(primary_proof.get("url") or primary_proof.get("path") or ""))
    ev = str(evidence_value or "").strip()

    if canonical_class == "stored_xss":
        return find_persistent_render_get_receipt(
            primary_proof,
            proof_receipts,
            ev,
            canonical_class="stored_xss",
        )

    candidates = [
        r
        for r in proof_receipts
        if str(r.get("method") or "").upper() == "GET"
        and 200 <= int(r.get("status") or 0) < 300
        and not (p_method == "DELETE" and _is_strictly_earlier_receipt(r, primary_proof))
    ]
    if not candidates:
        return None
    if ev:
        ev_matching = [r for r in candidates if _receipt_contains_evidence(r, ev, canonical_class=canonical_class)]
        if ev_matching:
            candidates = ev_matching
    candidates.sort(
        key=lambda r: (
            1 if (ev and _receipt_contains_evidence(r, ev, canonical_class=canonical_class)) else 0,
            1 if is_persistent_read_path_related(primary_proof, str(r.get("url") or r.get("path") or "")) else 0,
            1 if _norm_url_path(str(r.get("url") or r.get("path") or "")) == p_path else 0,
            1 if str(r.get("actor") or "") == p_actor else 0,
            _receipt_seq_num(r),
        ),
        reverse=True,
    )
    return candidates[0]


def _find_readback_get_in_store(
    primary_proof: dict[str, Any],
    receipt_store: ReceiptStore | None,
    evidence_value: str,
    *,
    canonical_class: str = "",
) -> dict[str, Any] | None:
    """Find a corroborating 2xx GET readback receipt in `receipt_store` for empty/write-only mutations."""
    if receipt_store is None:
        return None
    p_method = str(primary_proof.get("method") or "").upper()
    if p_method not in {"POST", "PUT", "PATCH"}:
        return None
    ev = str(evidence_value or "").strip()
    if not ev:
        return None
    p_path = _norm_url_path(str(primary_proof.get("url") or primary_proof.get("path") or ""))
    p_actor = str(primary_proof.get("actor") or "")
    try:
        rids = list(receipt_store.list_ids())
    except Exception:
        return None
    candidates: list[dict[str, Any]] = []
    for rid in reversed(rids[-200:]):
        try:
            rec = receipt_store.get(rid)
        except Exception:
            continue
        if not isinstance(rec, dict):
            continue
        if str(rec.get("method") or "").upper() != "GET":
            continue
        if not (200 <= int(rec.get("status") or 0) < 300):
            continue
        if _is_strictly_earlier_receipt(rec, primary_proof):
            continue
        r_path = _norm_url_path(str(rec.get("url") or rec.get("path") or ""))
        if r_path != p_path and not is_persistent_read_path_related(primary_proof, str(rec.get("url") or rec.get("path") or "")):
            continue
        if _receipt_contains_evidence(rec, ev, canonical_class=canonical_class):
            candidates.append(rec)
    if not candidates:
        return None
    candidates.sort(
        key=lambda r: (
            1 if _norm_url_path(str(r.get("url") or r.get("path") or "")) == p_path else 0,
            1 if str(r.get("actor") or "") == p_actor else 0,
            _receipt_seq_num(r),
        ),
        reverse=True,
    )
    return candidates[0]


def _parse_receipt_timestamp(ts: str) -> datetime | None:
    raw = str(ts or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _is_strictly_earlier_receipt(candidate: dict[str, Any], target: dict[str, Any]) -> bool:
    """Return True if `candidate` was recorded strictly before `target` by seq ID or timestamp."""
    c_seq = _receipt_seq_num(candidate)
    t_seq = _receipt_seq_num(target)
    if c_seq > 0 and t_seq > 0:
        return c_seq < t_seq
    c_ts_str = str(candidate.get("timestamp") or "").strip()
    t_ts_str = str(target.get("timestamp") or "").strip()
    if c_ts_str and t_ts_str:
        c_dt = _parse_receipt_timestamp(c_ts_str)
        t_dt = _parse_receipt_timestamp(t_ts_str)
        if c_dt is not None and t_dt is not None and (c_dt.tzinfo is None) == (t_dt.tzinfo is None):
            return c_dt < t_dt
        return c_ts_str < t_ts_str
    return False


def _add_correlation_token(tokens: set[str], value: Any) -> None:
    if isinstance(value, bool) or value is None:
        return
    if not isinstance(value, (str, int)):
        return
    s = str(value).strip()
    if 2 <= len(s) <= 128 and s.lower() not in _TRIVIAL_CORRELATION_TOKENS:
        tokens.add(s.lower())


def _extract_body_correlation_tokens(raw_text: str, tokens: set[str]) -> None:
    text = str(raw_text or "").strip()
    if not text:
        return
    if text.startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if parsed is not None:
            stack: list[Any] = [parsed]
            visited = 0
            while stack and visited < 120:
                cur = stack.pop()
                visited += 1
                if isinstance(cur, dict):
                    for v in cur.values():
                        stack.append(v)
                elif isinstance(cur, list):
                    for item in cur[:50]:
                        stack.append(item)
                else:
                    _add_correlation_token(tokens, cur)
            return
    if "=" in text and not text.startswith("<") and "\n" not in text[:256]:
        for _, v in parse_qsl(text, keep_blank_values=False):
            _add_correlation_token(tokens, v)


def _extract_receipt_correlation_tokens(
    receipt: dict[str, Any],
    *,
    include_response: bool = False,
) -> set[str]:
    """Extract non-trivial query, ID path segment, and body correlation tokens from a receipt."""
    tokens: set[str] = set()
    url = str(receipt.get("url") or receipt.get("path") or "")
    parsed = urlsplit(url)
    query_str = parsed.query or str(receipt.get("query") or "")
    if query_str:
        for _, v in parse_qsl(query_str, keep_blank_values=False):
            _add_correlation_token(tokens, v)
    for seg in parsed.path.split("/"):
        if seg and is_id_segment(seg):
            _add_correlation_token(tokens, seg)
    _extract_body_correlation_tokens(str(receipt.get("request_body") or ""), tokens)
    if include_response:
        redir = str(receipt.get("redirect_location") or "").strip()
        if redir:
            r_parsed = urlsplit(redir)
            if r_parsed.query:
                for _, v in parse_qsl(r_parsed.query, keep_blank_values=False):
                    _add_correlation_token(tokens, v)
            for seg in r_parsed.path.split("/"):
                if seg and is_id_segment(seg):
                    _add_correlation_token(tokens, seg)
        _extract_body_correlation_tokens(str(receipt.get("body") or ""), tokens)
    return tokens


def _find_prior_setup_write_receipt(
    replay_target: dict[str, Any],
    proof_receipts: Sequence[dict[str, Any]],
    receipt_store: ReceiptStore | None = None,
) -> dict[str, Any] | None:
    """Return the best strictly-earlier non-multipart write receipt in `proof_receipts` for a GET target.

    Strictly bounded to receipts explicitly provided in `proof_receipts` so two-step clean
    replay never guesses unrelated mutating writes across the wider receipt store.
    """
    if str(replay_target.get("method") or "").upper() != "GET":
        return None

    t_rid = str(replay_target.get("receipt_id") or "").strip()
    target_url = str(replay_target.get("url") or replay_target.get("path") or "")
    target_tokens = _extract_receipt_correlation_tokens(replay_target, include_response=False)

    candidates: list[tuple[int, int, int, str, dict[str, Any]]] = []
    seen_keys: set[str] = set()
    for raw_rec in proof_receipts:
        if not isinstance(raw_rec, dict):
            continue
        rec = raw_rec
        r_rid = str(rec.get("receipt_id") or "").strip()
        if not rec.get("method") and r_rid and receipt_store is not None:
            try:
                rec = receipt_store.get(r_rid)
            except (KeyError, ValueError):
                continue
        if rec is replay_target or (t_rid and r_rid and r_rid == t_rid):
            continue
        dedup_key = r_rid or f"obj:{id(rec)}"
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        if str(rec.get("method") or "").upper() not in _WRITE_METHODS:
            continue
        status = int(rec.get("status") or 0)
        if not (200 <= status < 400):
            continue
        if _is_multipart_receipt(rec):
            continue
        if not _is_strictly_earlier_receipt(rec, replay_target):
            continue

        cand_tokens = _extract_receipt_correlation_tokens(rec, include_response=True)
        shares_token = bool(target_tokens and (target_tokens & cand_tokens))
        if not shares_token and target_tokens:
            cand_haystack = "\n".join(
                part
                for part in (
                    str(rec.get("url") or ""),
                    str(rec.get("request_body") or ""),
                    str(rec.get("body") or ""),
                    str(rec.get("redirect_location") or ""),
                )
                if part
            ).lower()
            if cand_haystack:
                shares_token = any(
                    len(tok) >= 4
                    and re.search(rf"(?<![a-z0-9_-]){re.escape(tok)}(?![a-z0-9_-])", cand_haystack)
                    for tok in target_tokens
                )
        same_path_family = is_persistent_read_path_related(rec, target_url)
        candidates.append((
            1 if shares_token else 0,
            1 if same_path_family else 0,
            _receipt_seq_num(rec),
            str(rec.get("timestamp") or ""),
            rec,
        ))

    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3]), reverse=True)
    return candidates[0][4]


def _receipt_elapsed_ms(receipt: dict[str, Any]) -> float | None:
    """Return finite non-negative elapsed_ms recorded on a receipt, or None if absent/invalid."""
    raw = receipt.get("elapsed_ms")
    if isinstance(raw, bool) or raw is None:
        return None
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(val) or val < 0.0:
        return None
    return val


def _is_timing_pair_significant(
    proof_ms: float | None,
    control_ms: float | None,
    *,
    min_delta_ms: float,
    min_ratio: float,
) -> bool:
    """Return True when proof latency exceeds control latency by both absolute delta and ratio."""
    if proof_ms is None or control_ms is None:
        return False
    return (
        (proof_ms - control_ms) >= min_delta_ms
        and proof_ms >= min_ratio * max(control_ms, 20.0)
    )


def _is_resource_id_key(raw_key: str) -> bool:
    """Return True if a JSON/query field name represents a resource identifier."""
    clean = str(raw_key or "").strip()
    if not clean:
        return False
    low = clean.lower()
    if low in _MULTISTEP_EXCLUDED_ID_KEYS:
        return False
    if low in _MULTISTEP_ID_EXACT_KEYS:
        return True
    if any(low.endswith(sfx) for sfx in _MULTISTEP_ID_SUFFIXES):
        return True
    return bool(_CAMEL_ID_KEY_RE.fullmatch(clean))


def _clean_id_scalar(value: Any) -> str:
    """Return a clean identifier string for scalar str/int values, or empty string if unusable."""
    if isinstance(value, bool) or value is None:
        return ""
    if not isinstance(value, (str, int)):
        return ""
    text = str(value).strip()
    if not text or len(text) > 128:
        return ""
    if "<REDACTED" in text or any(ch.isspace() or ch in "/\\?#\x00" for ch in text):
        return ""
    return text


def _is_short_numeric_id(id_val: str) -> bool:
    return len(id_val) <= 2 and id_val.isdigit()


def _extract_response_resource_ids(receipt: dict[str, Any]) -> dict[tuple[Any, ...], str]:
    """Extract candidate resource identifier slots from a receipt's Location header and JSON response body."""
    slots: dict[tuple[Any, ...], str] = {}

    loc = str(receipt.get("redirect_location") or _response_header_ci(receipt, "location") or "").strip()
    if loc:
        loc_segs = [unquote(seg) for seg in urlsplit(loc).path.split("/") if seg]
        if loc_segs:
            last_seg = _clean_id_scalar(loc_segs[-1])
            if last_seg and (len(loc_segs) >= 2 or is_id_segment(last_seg)):
                slots[("location",)] = last_seg

    body = str(receipt.get("body") or "").strip()
    parsed = _try_parse_json_body(body) if body else None
    if parsed is not None:
        stack: list[tuple[tuple[Any, ...], Any, int]] = [(("json",), parsed, 0)]
        visited = 0
        while stack and visited < 120:
            path_key, cur, depth = stack.pop(0)
            visited += 1
            if depth > 4:
                continue
            if isinstance(cur, dict):
                for k, v in cur.items():
                    sk = str(k)
                    child_path = (*path_key, sk.lower())
                    if _is_resource_id_key(sk):
                        clean_val = _clean_id_scalar(v)
                        if clean_val:
                            slots[child_path] = clean_val
                    if isinstance(v, (dict, list)) and depth < 4:
                        stack.append((child_path, v, depth + 1))
            elif isinstance(cur, list):
                for idx, item in enumerate(cur[:20]):
                    if isinstance(item, (dict, list)) and depth < 4:
                        stack.append(((*path_key, idx), item, depth + 1))
    return slots


def _value_matches_id_str(raw_val: str, id_val: str, *, allow_short_numeric: bool = True) -> bool:
    if not raw_val or not id_val:
        return False
    if raw_val == id_val:
        return allow_short_numeric or not _is_short_numeric_id(id_val)
    if "/" in raw_val and raw_val.startswith(("/", "http://", "https://")):
        segs = [unquote(s) for s in urlsplit(raw_val).path.split("/") if s]
        if id_val in segs:
            return True
    return False


def _step_references_id(step: dict[str, Any], id_val: str) -> bool:
    """Return True if `step`'s request URL (path/query) or request body references `id_val`."""
    if not id_val:
        return False
    short_num = _is_short_numeric_id(id_val)
    url = str(step.get("url") or step.get("path") or "")
    parsed = urlsplit(url)
    for seg in parsed.path.split("/"):
        if seg and (seg == id_val or unquote(seg) == id_val):
            return True
    query_str = parsed.query or str(step.get("query") or "")
    if query_str:
        for k, v in parse_qsl(query_str, keep_blank_values=True):
            if _value_matches_id_str(v, id_val, allow_short_numeric=(not short_num or _is_resource_id_key(k))):
                return True

    raw_body = str(step.get("request_body") or "").strip()
    if not raw_body:
        return False
    parsed_body = _try_parse_json_body(raw_body)
    if parsed_body is not None:
        stack: list[tuple[str, Any]] = [("", parsed_body)]
        visited = 0
        while stack and visited < 120:
            enclosing_key, cur = stack.pop()
            visited += 1
            if isinstance(cur, dict):
                for k, v in cur.items():
                    stack.append((str(k), v))
            elif isinstance(cur, list):
                for item in cur[:50]:
                    stack.append((enclosing_key, item))
            elif isinstance(cur, bool) or cur is None:
                continue
            elif isinstance(cur, (str, int)):
                allow_short = not short_num or _is_resource_id_key(enclosing_key)
                if _value_matches_id_str(str(cur), id_val, allow_short_numeric=allow_short):
                    return True
        return False

    if "=" in raw_body and not raw_body.startswith("<") and "\n" not in raw_body[:256]:
        for k, v in parse_qsl(raw_body, keep_blank_values=True):
            if _value_matches_id_str(v, id_val, allow_short_numeric=(not short_num or _is_resource_id_key(k))):
                return True
    return False


def _extract_newly_minted_ids(receipt: dict[str, Any]) -> dict[tuple[Any, ...], str]:
    """Return response resource IDs minted by `receipt` that were NOT already present in its own request."""
    slots = _extract_response_resource_ids(receipt)
    if not slots:
        return {}
    minted: dict[tuple[Any, ...], str] = {}
    for slot, val in slots.items():
        if val.lower() in _TRIVIAL_CORRELATION_TOKENS and not val.isdigit():
            continue
        if _step_references_id(receipt, val):
            continue
        minted[slot] = val
    return minted


def _extract_minted_id_substitutions(
    orig_step: dict[str, Any],
    replayed_step: dict[str, Any],
    subsequent_steps: Sequence[dict[str, Any]],
) -> dict[str, str]:
    """Return `{old_id: new_id}` pairs for IDs that changed on replay and are referenced downstream."""
    orig_ids = _extract_response_resource_ids(orig_step)
    if not orig_ids:
        return {}
    replay_ids = _extract_response_resource_ids(replayed_step)
    if not replay_ids:
        return {}
    subs: dict[str, str] = {}
    for slot, old_val in orig_ids.items():
        new_val = replay_ids.get(slot)
        if not new_val or new_val == old_val:
            continue
        if any(_step_references_id(step, old_val) for step in subsequent_steps):
            subs[old_val] = new_val
    return subs


def _replace_path_segments(path: str, id_map: dict[str, str]) -> str:
    if not path or not id_map:
        return path
    parts = path.split("/")
    changed = False
    out: list[str] = []
    for seg in parts:
        if not seg:
            out.append(seg)
            continue
        if seg in id_map:
            out.append(quote(id_map[seg], safe="-_.~"))
            changed = True
            continue
        decoded = unquote(seg)
        if decoded in id_map:
            out.append(quote(id_map[decoded], safe="-_.~"))
            changed = True
            continue
        out.append(seg)
    return "/".join(out) if changed else path


def _substitute_scalar_or_path_str(
    val: str,
    id_map: dict[str, str],
    *,
    allow_short_numeric: bool = True,
) -> str:
    if not val or not id_map:
        return val
    if val in id_map:
        if allow_short_numeric or not _is_short_numeric_id(val):
            return id_map[val]
        return val
    if "/" in val and val.startswith(("/", "http://", "https://")):
        parsed = urlsplit(val)
        new_path = _replace_path_segments(parsed.path, id_map)
        new_query = parsed.query
        if parsed.query:
            q_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            new_q_pairs = [
                (
                    qk,
                    _substitute_scalar_or_path_str(
                        qv,
                        id_map,
                        allow_short_numeric=(not _is_short_numeric_id(qv) or _is_resource_id_key(qk)),
                    ),
                )
                for qk, qv in q_pairs
            ]
            if new_q_pairs != q_pairs:
                new_query = urlencode(new_q_pairs, doseq=True)
        if new_path != parsed.path or new_query != parsed.query:
            return urlunsplit((parsed.scheme, parsed.netloc, new_path, new_query, parsed.fragment))
    return val


def _apply_id_substitutions_to_request(
    url: str,
    raw_body: str,
    id_map: dict[str, str],
) -> tuple[str, str]:
    """Substitute minted resource IDs into a subsequent step's URL (path/query) and JSON/form body."""
    if not id_map:
        return url, raw_body

    new_url = url
    if url:
        parsed = urlsplit(url)
        new_path = _replace_path_segments(parsed.path, id_map)
        new_query = parsed.query
        if parsed.query:
            q_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            new_q_pairs = [
                (
                    k,
                    _substitute_scalar_or_path_str(
                        v,
                        id_map,
                        allow_short_numeric=(not _is_short_numeric_id(v) or _is_resource_id_key(k)),
                    ),
                )
                for k, v in q_pairs
            ]
            if new_q_pairs != q_pairs:
                new_query = urlencode(new_q_pairs, doseq=True)
        if new_path != parsed.path or new_query != parsed.query:
            new_url = urlunsplit((parsed.scheme, parsed.netloc, new_path, new_query, parsed.fragment))

    new_body = raw_body
    stripped = str(raw_body or "").strip()
    if stripped:
        parsed_body = _try_parse_json_body(stripped)
        if parsed_body is not None:
            body_changed = False

            def _sub_json(obj: Any, key_name: str = "") -> Any:
                nonlocal body_changed
                if isinstance(obj, dict):
                    return {k: _sub_json(v, str(k)) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [_sub_json(item, key_name) for item in obj]
                if isinstance(obj, bool) or obj is None:
                    return obj
                if isinstance(obj, int):
                    s = str(obj)
                    if s in id_map and (not _is_short_numeric_id(s) or _is_resource_id_key(key_name)):
                        repl = id_map[s]
                        body_changed = True
                        if repl.lstrip("-").isdigit() and not (len(repl) > 1 and repl.startswith("0")):
                            return int(repl)
                        return repl
                    return obj
                if isinstance(obj, str):
                    allow_short = not _is_short_numeric_id(obj) or _is_resource_id_key(key_name)
                    replaced = _substitute_scalar_or_path_str(obj, id_map, allow_short_numeric=allow_short)
                    if replaced != obj:
                        body_changed = True
                    return replaced
                return obj

            transformed = _sub_json(parsed_body)
            if body_changed:
                new_body = json.dumps(transformed, ensure_ascii=False, separators=(",", ":"))
        elif "=" in stripped and not stripped.startswith("<") and "\n" not in stripped[:256]:
            f_pairs = parse_qsl(raw_body, keep_blank_values=True)
            new_f_pairs = [
                (
                    k,
                    _substitute_scalar_or_path_str(
                        v,
                        id_map,
                        allow_short_numeric=(not _is_short_numeric_id(v) or _is_resource_id_key(k)),
                    ),
                )
                for k, v in f_pairs
            ]
            if new_f_pairs != f_pairs:
                new_body = urlencode(new_f_pairs, doseq=True)

    return new_url, new_body


def _is_safe_precursor_receipt(
    rec: dict[str, Any],
    *,
    allowed_methods: frozenset[str] | None = None,
    require_2xx_only: bool = False,
) -> bool:
    """Return True if a receipt is a safe, replayable in-scope write precursor."""
    if not isinstance(rec, dict):
        return False
    method = str(rec.get("method") or "").upper()
    if method not in _WRITE_METHODS:
        return False
    if allowed_methods is not None and method not in allowed_methods:
        return False
    status = int(rec.get("status") or 0)
    if require_2xx_only:
        if not (200 <= status < 300):
            return False
    else:
        if not (200 <= status < 400):
            return False
    if _is_multipart_receipt(rec):
        return False
    url = str(rec.get("url") or rec.get("path") or "").strip()
    if not url:
        return False
    if is_logout_route(url) or is_destructive_lifecycle_route(url):
        return False
    return True


def _receipt_sort_key(rec: dict[str, Any]) -> tuple[int, str]:
    return (_receipt_seq_num(rec), str(rec.get("timestamp") or ""))


def _receipt_dedup_key(rec: dict[str, Any]) -> str:
    rid = str(rec.get("receipt_id") or "").strip()
    return rid or f"obj:{id(rec)}"


def _receipts_share_correlation(cand: dict[str, Any], downstream: dict[str, Any]) -> bool:
    target_tokens = _extract_receipt_correlation_tokens(downstream, include_response=False)
    if not target_tokens:
        return False
    cand_tokens = _extract_receipt_correlation_tokens(cand, include_response=True)
    if target_tokens & cand_tokens:
        return True
    cand_haystack = "\n".join(
        part
        for part in (
            str(cand.get("url") or ""),
            str(cand.get("request_body") or ""),
            str(cand.get("body") or ""),
            str(cand.get("redirect_location") or ""),
        )
        if part
    ).lower()
    if not cand_haystack:
        return False
    return any(
        len(tok) >= 4
        and re.search(rf"(?<![a-z0-9_-]){re.escape(tok)}(?![a-z0-9_-])", cand_haystack)
        for tok in target_tokens
    )


def _receipt_mints_id_for(cand: dict[str, Any], downstream: dict[str, Any]) -> list[str]:
    minted = _extract_newly_minted_ids(cand)
    if not minted:
        return []
    matched: list[str] = []
    for val in dict.fromkeys(minted.values()):
        if _step_references_id(downstream, val):
            matched.append(val)
    return matched


def _bound_precursor_chain(
    precursors: Sequence[dict[str, Any]],
    *,
    max_precursors: int = _MAX_MULTISTEP_PRECURSORS,
) -> list[dict[str, Any]]:
    ordered = sorted(precursors, key=_receipt_sort_key)
    cap = max(1, int(max_precursors))
    if len(ordered) <= cap:
        return ordered
    if cap == 1:
        return [ordered[-1]]
    return [ordered[0], *ordered[-(cap - 1) :]]


def _discover_precursor_chain(
    replay_target: dict[str, Any],
    explicit_receipts: Sequence[dict[str, Any]],
    receipt_store: ReceiptStore | None = None,
    *,
    allowed_methods: frozenset[str] | None = None,
    resolve_scope_fn: Callable[[str], tuple[str, str, str]] | None = None,
    max_precursors: int = _MAX_MULTISTEP_PRECURSORS,
) -> list[dict[str, Any]]:
    """Discover up to `max_precursors` ordered in-scope precursor writes before `replay_target`.

    Discovery order:
    1. Explicitly supplied earlier safe writes in `proof_receipts` / `setup_receipts` linked via
       minted resource IDs, correlation tokens, or related path family (preserving single-step
       GET fallback semantics from `_find_prior_setup_write_receipt`).
    2. Recent prior 2xx writes by the proof actor in `receipt_store` whose response body or
       `Location` header newly minted an identifier referenced downstream (plus intermediate
       2xx writes by the proof actor mutating that same minted identifier).
    """
    cap = max(1, min(_MAX_MULTISTEP_PRECURSORS, int(max_precursors)))
    t_rid = str(replay_target.get("receipt_id") or "").strip()
    t_key = _receipt_dedup_key(replay_target)
    t_actor = str(replay_target.get("actor") or "anon")
    t_method = str(replay_target.get("method") or "GET").upper()
    t_norm_path = _norm_url_path(str(replay_target.get("url") or replay_target.get("path") or ""))

    def _in_scope(rec: dict[str, Any]) -> bool:
        if resolve_scope_fn is None:
            return True
        try:
            resolve_scope_fn(str(rec.get("url") or rec.get("path") or ""))
            return True
        except (ScopeViolationError, ValueError):
            return False

    # 1. Explicit ordered candidates from proof_receipts / setup_receipts.
    explicit_writes: list[dict[str, Any]] = []
    seen_explicit: set[str] = {t_key}
    for raw_rec in explicit_receipts:
        if not isinstance(raw_rec, dict):
            continue
        rec = raw_rec
        r_rid = str(rec.get("receipt_id") or "").strip()
        if not rec.get("method") and r_rid and receipt_store is not None:
            try:
                rec = receipt_store.get(r_rid)
            except (KeyError, ValueError):
                continue
        r_key = _receipt_dedup_key(rec)
        if rec is replay_target or (t_rid and r_rid and r_rid == t_rid) or r_key in seen_explicit:
            continue
        seen_explicit.add(r_key)
        if not _is_safe_precursor_receipt(rec, allowed_methods=allowed_methods, require_2xx_only=False):
            continue
        if not _is_strictly_earlier_receipt(rec, replay_target):
            continue
        if not _in_scope(rec):
            continue
        explicit_writes.append(rec)

    explicit_writes.sort(key=_receipt_sort_key)

    selected_explicit: dict[str, dict[str, Any]] = {}
    tracked_explicit_ids: set[str] = set()
    if explicit_writes:
        chain_nodes: list[dict[str, Any]] = [replay_target]
        changed = True
        while changed and len(selected_explicit) < cap:
            changed = False
            for cand in reversed(explicit_writes):
                ckey = _receipt_dedup_key(cand)
                if ckey in selected_explicit:
                    continue
                c_method = str(cand.get("method") or "").upper()
                c_norm_path = _norm_url_path(str(cand.get("url") or cand.get("path") or ""))
                linked = False
                for node in chain_nodes:
                    if not _is_strictly_earlier_receipt(cand, node):
                        continue
                    n_method = str(node.get("method") or "").upper()
                    n_url = str(node.get("url") or node.get("path") or "")
                    n_norm_path = _norm_url_path(n_url)
                    minted_matches = _receipt_mints_id_for(cand, node)
                    if minted_matches:
                        tracked_explicit_ids.update(minted_matches)
                        linked = True
                        break
                    if c_method == n_method and c_norm_path == n_norm_path:
                        continue
                    if _receipts_share_correlation(cand, node) or is_persistent_read_path_related(cand, n_url):
                        linked = True
                        break
                if linked:
                    selected_explicit[ckey] = cand
                    chain_nodes.append(cand)
                    changed = True
                    if len(selected_explicit) >= cap:
                        break

        if not selected_explicit and t_method == "GET":
            fallback_one = _find_prior_setup_write_receipt(replay_target, explicit_writes, receipt_store)
            if fallback_one is not None and _is_safe_precursor_receipt(
                fallback_one, allowed_methods=allowed_methods, require_2xx_only=False
            ) and _in_scope(fallback_one):
                selected_explicit[_receipt_dedup_key(fallback_one)] = fallback_one

    # 2. Implicit minted-ID chain discovery from recent prior 2xx writes by proof actor in receipt_store.
    store_selected: dict[str, dict[str, Any]] = {}
    if receipt_store is not None and len(selected_explicit) < cap:
        all_rids = receipt_store.list_ids()
        prior_store_writes: list[dict[str, Any]] = []
        for rid in reversed(all_rids):
            if len(prior_store_writes) >= _MULTISTEP_STORE_LOOKBACK:
                break
            if t_rid and rid == t_rid:
                continue
            try:
                rec = receipt_store.get(rid)
            except (KeyError, ValueError):
                continue
            if str(rec.get("actor") or "anon") != t_actor:
                continue
            if not _is_safe_precursor_receipt(rec, allowed_methods=allowed_methods, require_2xx_only=True):
                continue
            if not _is_strictly_earlier_receipt(rec, replay_target):
                continue
            if not _in_scope(rec):
                continue
            prior_store_writes.append(rec)

        if prior_store_writes:
            prior_store_writes.sort(key=_receipt_sort_key)
            frontier: list[dict[str, Any]] = (
                list(selected_explicit.values()) if selected_explicit else [replay_target]
            )
            tracked_store_ids: set[str] = set(tracked_explicit_ids)
            for _ in range(cap):
                next_frontier: list[dict[str, Any]] = []
                for node in frontier:
                    covered_ids_for_node: set[str] = set()
                    for cand in reversed(prior_store_writes):
                        if (len(selected_explicit) + len(store_selected)) >= cap:
                            break
                        ckey = _receipt_dedup_key(cand)
                        if ckey in selected_explicit or ckey in store_selected:
                            continue
                        if not _is_strictly_earlier_receipt(cand, node):
                            continue
                        minted_matches = [
                            mid for mid in _receipt_mints_id_for(cand, node) if mid not in covered_ids_for_node
                        ]
                        if minted_matches:
                            store_selected[ckey] = cand
                            covered_ids_for_node.update(minted_matches)
                            tracked_store_ids.update(minted_matches)
                            next_frontier.append(cand)
                if not next_frontier or (len(selected_explicit) + len(store_selected)) >= cap:
                    break
                frontier = next_frontier

            # Include intermediate 2xx writes by the same proof actor mutating the newly-minted resource ID.
            if tracked_store_ids and (len(selected_explicit) + len(store_selected)) < cap:
                combined_producers = [*selected_explicit.values(), *store_selected.values()]
                earliest_prod = min(combined_producers, key=_receipt_sort_key)
                for cand in prior_store_writes:
                    if (len(selected_explicit) + len(store_selected)) >= cap:
                        break
                    ckey = _receipt_dedup_key(cand)
                    if ckey in selected_explicit or ckey in store_selected:
                        continue
                    if not _is_strictly_earlier_receipt(earliest_prod, cand):
                        continue
                    c_method = str(cand.get("method") or "").upper()
                    c_norm_path = _norm_url_path(str(cand.get("url") or cand.get("path") or ""))
                    if c_method == t_method and c_norm_path == t_norm_path:
                        continue
                    if any(_step_references_id(cand, mid) for mid in tracked_store_ids):
                        store_selected[ckey] = cand

    merged_map: dict[str, dict[str, Any]] = {**selected_explicit, **store_selected}
    if not merged_map:
        return []
    return _bound_precursor_chain(list(merged_map.values()), max_precursors=cap)


def mask_dynamic_fields(text: str, *, preserve_values: Sequence[str] = ()) -> str:
    """Mask ephemeral timestamps, nonces, and request/trace UUIDs before structural comparison."""
    raw = str(text or "")
    if not raw:
        return ""
    preserved = [str(p) for p in preserve_values if isinstance(p, str) and len(p) >= 3]
    placeholders: dict[str, str] = {}
    working = raw
    for idx, val in enumerate(preserved):
        if val in working:
            token = f"__PRESERVE_{idx}__"
            placeholders[token] = val
            working = working.replace(val, token)

    def _restore_placeholders(s: str) -> str:
        out_s = s
        for token, orig in placeholders.items():
            if token in out_s:
                out_s = out_s.replace(token, orig)
        return out_s

    stripped = working.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(working)
        except ValueError:
            parsed = None
        if parsed is not None:
            def _scrub(obj: Any) -> Any:
                if isinstance(obj, dict):
                    out: dict[str, Any] = {}
                    restored_keys = {str(k): _restore_placeholders(str(k)).lower() for k in obj}
                    has_job_id = any(lk in _JOB_QUEUE_ID_KEYS for lk in restored_keys.values())
                    for k, v in sorted(obj.items(), key=lambda kv: str(kv[0])):
                        sk = str(k)
                        lk = restored_keys[sk]
                        if lk in _EPHEMERAL_JSON_KEYS or (has_job_id and lk in _JOB_QUEUE_SEQ_KEYS):
                            out[sk] = "<MASKED>"
                        else:
                            out[sk] = _scrub(v)
                    return out
                if isinstance(obj, list):
                    return [_scrub(x) for x in obj]
                if isinstance(obj, str):
                    s = _ISO_TS_RE.sub("<TS>", obj)
                    s = _UUID_RE.sub("<UUID>", s)
                    return s
                return obj

            working = json.dumps(_scrub(parsed), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            return _restore_placeholders(working)

    working = _ISO_TS_RE.sub("<TS>", working)
    working = _UUID_RE.sub("<UUID>", working)
    working = re.sub(r"\s+", " ", working).strip()
    return _restore_placeholders(working)


def _try_parse_json_body(text: str) -> Any | None:
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _collect_ephemeral_json_values(
    obj: Any,
    path: tuple[str, ...] = (),
    *,
    extra_keys: frozenset[str] = frozenset(),
) -> dict[tuple[str, ...], list[str]]:
    found: dict[tuple[str, ...], list[str]] = {}
    if isinstance(obj, dict):
        has_job_id = any(str(k).lower() in _JOB_QUEUE_ID_KEYS for k in obj)
        for k, v in obj.items():
            kl = str(k).lower()
            child_path = (*path, kl)
            is_ephemeral = (
                kl in _EPHEMERAL_REPLAY_JSON_KEYS
                or kl in extra_keys
                or (has_job_id and kl in _JOB_QUEUE_SEQ_KEYS)
            )
            if (
                is_ephemeral
                and isinstance(v, (str, int, float))
                and not isinstance(v, bool)
            ):
                val_str = str(v).strip()
                if val_str:
                    found.setdefault(child_path, []).append(val_str)
            if isinstance(v, (dict, list)):
                for sub_path, vals in _collect_ephemeral_json_values(
                    v, child_path, extra_keys=extra_keys
                ).items():
                    found.setdefault(sub_path, []).extend(vals)
    elif isinstance(obj, list):
        for item in obj[:100]:
            if isinstance(item, (dict, list)):
                for sub_path, vals in _collect_ephemeral_json_values(
                    item, (*path, "[]"), extra_keys=extra_keys
                ).items():
                    found.setdefault(sub_path, []).extend(vals)
    return found


def _mask_for_ephemeral_replay_comparison(
    text: str,
    parsed_json: Any | None = None,
    *,
    extra_keys: frozenset[str] = frozenset(),
) -> str:
    """Mask UUIDs, timestamps, ephemeral JSON keys, and 24-64 char hex IDs for replay comparison."""
    raw = str(text or "")
    if not raw:
        return ""
    parsed = parsed_json if parsed_json is not None else _try_parse_json_body(raw)
    if parsed is not None:
        def _scrub(obj: Any) -> Any:
            if isinstance(obj, dict):
                out: dict[str, Any] = {}
                has_job_id = any(str(k).lower() in _JOB_QUEUE_ID_KEYS for k in obj)
                for k, v in sorted(obj.items(), key=lambda kv: str(kv[0])):
                    lk = str(k).lower()
                    if (
                        lk in _EPHEMERAL_REPLAY_JSON_KEYS
                        or lk in extra_keys
                        or (has_job_id and lk in _JOB_QUEUE_SEQ_KEYS)
                    ):
                        out[str(k)] = "<MASKED>"
                    else:
                        out[str(k)] = _scrub(v)
                return out
            if isinstance(obj, list):
                return [_scrub(x) for x in obj]
            if isinstance(obj, str):
                s = _ISO_TS_RE.sub("<TS>", obj)
                s = _UUID_RE.sub("<UUID>", s)
                s = _HEX_MASK_RE.sub("<HEX>", s)
                return s
            return obj

        return json.dumps(_scrub(parsed), ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    working = _ISO_TS_RE.sub("<TS>", raw)
    working = _UUID_RE.sub("<UUID>", working)
    working = _HEX_MASK_RE.sub("<HEX>", working)
    return re.sub(r"\s+", " ", working).strip()


def _weak_credentials_controls_equivalent(
    proof: dict[str, Any],
    ctrl: dict[str, Any],
    *,
    ev: str,
) -> bool:
    """Return True if a weak_credentials proof and control show no auth-state differential."""
    if int(ctrl.get("status") or 0) != int(proof.get("status") or 0):
        return False
    p_loc = mask_dynamic_fields(str(proof.get("redirect_location") or ""), preserve_values=(ev,))
    c_loc = mask_dynamic_fields(str(ctrl.get("redirect_location") or ""), preserve_values=(ev,))
    if c_loc != p_loc:
        return False
    if bool(_response_header_ci(ctrl, "set-cookie")) != bool(_response_header_ci(proof, "set-cookie")):
        return False
    p_body = _mask_for_ephemeral_replay_comparison(
        str(proof.get("body") or ""),
        extra_keys=_WEAK_CRED_TOKEN_KEYS,
    )
    c_body = _mask_for_ephemeral_replay_comparison(
        str(ctrl.get("body") or ""),
        extra_keys=_WEAK_CRED_TOKEN_KEYS,
    )
    return c_body == p_body


def _weak_credentials_replay_matches_evidence(
    ev: str,
    replay_target: dict[str, Any],
    replay_rec: dict[str, Any],
) -> bool:
    """Return True if clean login replay preserves evidence or dynamic session cookie/token behavior."""
    if not ev or _receipt_contains_evidence(replay_rec, ev, canonical_class="weak_credentials"):
        return True
    t_cookie = _response_header_ci(replay_target, "set-cookie")
    r_cookie = _response_header_ci(replay_rec, "set-cookie")
    if t_cookie and r_cookie and ev.lower() in t_cookie.lower():
        t_masked = _mask_for_ephemeral_replay_comparison(
            str(replay_target.get("body") or ""),
            extra_keys=_WEAK_CRED_TOKEN_KEYS,
        )
        r_masked = _mask_for_ephemeral_replay_comparison(
            str(replay_rec.get("body") or ""),
            extra_keys=_WEAK_CRED_TOKEN_KEYS,
        )
        if t_masked == r_masked:
            return True
    if _detect_ephemeral_evidence_mismatch(ev, replay_target, replay_rec):
        return True
    t_body = str(replay_target.get("body") or "").strip()
    r_body = str(replay_rec.get("body") or "").strip()
    t_json = _try_parse_json_body(t_body)
    r_json = _try_parse_json_body(r_body)
    if t_json is not None and r_json is not None:
        ev_low = ev.lower()
        t_toks = _collect_ephemeral_json_values(t_json, extra_keys=_WEAK_CRED_TOKEN_KEYS)
        r_toks = _collect_ephemeral_json_values(r_json, extra_keys=_WEAK_CRED_TOKEN_KEYS)
        token_rotated = any(
            any(v.lower() == ev_low for v in vals) and bool(r_toks.get(kp))
            for kp, vals in t_toks.items()
        )
        if token_rotated:
            t_masked = _mask_for_ephemeral_replay_comparison(
                t_body, parsed_json=t_json, extra_keys=_WEAK_CRED_TOKEN_KEYS
            )
            r_masked = _mask_for_ephemeral_replay_comparison(
                r_body, parsed_json=r_json, extra_keys=_WEAK_CRED_TOKEN_KEYS
            )
            if bool(t_masked) and t_masked == r_masked:
                return True
    return False


def _weak_credentials_redacted_body_rejected(
    replay_target: dict[str, Any],
    replay_rec: dict[str, Any],
    eff_controls: Sequence[dict[str, Any]],
    *,
    ev: str,
) -> bool:
    """Return True when replaying a login receipt with redacted credentials is rejected live."""
    if "<REDACTED" not in str(replay_target.get("request_body") or ""):
        return False
    if not eff_controls:
        return False
    if ev and not _receipt_contains_evidence(replay_target, ev, canonical_class="weak_credentials"):
        return False
    r_status = int(replay_rec.get("status") or 0)
    if r_status in {400, 401, 403, 422}:
        return True
    if 200 <= r_status < 400:
        if any(
            _weak_credentials_controls_equivalent(ctrl, replay_rec, ev=ev)
            for ctrl in eff_controls
        ) and not _weak_credentials_controls_equivalent(replay_target, replay_rec, ev=ev):
            return True
    return False


def _is_unrelated_route_not_found(receipt: dict[str, Any], method: str = "") -> bool:
    """Return True if a 404/410 response body indicates a missing route rather than a deleted resource."""
    body = str(receipt.get("body") or "")
    if not body:
        return False
    if method and f"cannot {method.strip().lower()} " in body.lower():
        return True
    return bool(_UNRELATED_ROUTE_ERROR_RE.search(body))


def _is_one_shot_create_conflict(replay_rec: dict[str, Any]) -> bool:
    """Return True if a POST clean replay returned 409 Conflict or 400/422 with an explicit duplicate/conflict indicator."""
    r_status = int(replay_rec.get("status") or 0)
    if r_status == 409:
        return True
    if r_status in {400, 422}:
        return bool(_CREATE_CONFLICT_INDICATOR_RE.search(str(replay_rec.get("body") or "")))
    return False


def _receipt_observes_resource_before_delete(
    cand: dict[str, Any],
    target_norm_path: str,
) -> bool:
    """Return True if an earlier 2xx receipt observed or created the resource at `target_norm_path`."""
    c_method = str(cand.get("method") or "").upper()
    c_path = _norm_url_path(str(cand.get("url") or cand.get("path") or ""))
    if c_path == target_norm_path and c_method in {"GET", "POST", "PUT", "PATCH"}:
        return True

    parts = [seg for seg in target_norm_path.split("/") if seg]
    if len(parts) < 2:
        return False
    concrete_key = parts[-1].lower()
    if concrete_key in _API_PREFIX_SEGMENTS or _API_VERSION_SEG_RE.fullmatch(concrete_key):
        return False
    parent_path = "/" + "/".join(parts[:-1])
    resource_family = parts[-2].lower()
    if not (
        c_path == parent_path
        or c_path == f"/{resource_family}"
        or c_path.endswith(f"/{resource_family}")
    ):
        return False

    if c_method in {"POST", "PUT"}:
        loc = str(cand.get("redirect_location") or _response_header_ci(cand, "location") or "").strip()
        if loc and _norm_url_path(loc) == target_norm_path:
            return True

    body = str(cand.get("body") or "")
    if not body:
        return False

    singular = resource_family[:-1] if len(resource_family) > 2 and resource_family.endswith("s") else resource_family
    short_singular = singular.replace("-", "_").split("_")[-1]
    id_keys = {"id", "uuid", "slug", "key", "name", "username", f"{singular}_id", f"{short_singular}_id"}

    stripped = body.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        if c_method in {"POST", "PUT"} and isinstance(parsed, dict):
            dicts_to_check: list[dict[str, Any]] = [parsed]
            for v in parsed.values():
                if isinstance(v, dict):
                    dicts_to_check.append(v)
            for item in dicts_to_check:
                for k, v in item.items():
                    if str(k).lower() in id_keys and isinstance(v, (str, int)) and not isinstance(v, bool):
                        if str(v).strip().lower() == concrete_key:
                            return True
        elif c_method == "GET" and "{id}" not in route_template_of(c_path):
            items: list[dict[str, Any]] = []
            if isinstance(parsed, list):
                items = [x for x in parsed[:100] if isinstance(x, dict)]
            elif isinstance(parsed, dict):
                for v in parsed.values():
                    if isinstance(v, list):
                        items.extend(x for x in v[:100] if isinstance(x, dict))
            for item in items:
                for k, v in item.items():
                    if str(k).lower() in id_keys and isinstance(v, (str, int)) and not isinstance(v, bool):
                        if str(v).strip().lower() == concrete_key:
                            return True

    if c_method == "GET":
        ctype = str(cand.get("content_type") or "").lower()
        html_link_re = re.compile(
            rf"""(?:{re.escape(parent_path)}|/{re.escape(resource_family)})/{re.escape(concrete_key)}(?:["'/?#\s>]|$)""",
            re.IGNORECASE,
        )
        if ("html" in ctype or "href=" in body.lower()) and html_link_re.search(body):
            return True
    return False


def _delete_original_evidence_ok(
    *,
    primary_proof: dict[str, Any],
    evidence_value: str,
    ev_in_oob: bool,
    canonical_class: str,
    prior_observations: Sequence[dict[str, Any]],
    eff_controls: Sequence[dict[str, Any]],
    has_same_path_denied_control: bool,
) -> bool:
    """Return True if `evidence_value` is corroborated by the original 2xx DELETE (or 204 + prior/control state)."""
    ev = str(evidence_value or "").strip()
    if not ev or ev_in_oob:
        return True
    if _receipt_contains_evidence(primary_proof, ev, canonical_class=canonical_class):
        return True
    t_status = int(primary_proof.get("status") or 0)
    if t_status == 204 and not str(primary_proof.get("body") or "").strip():
        if any(
            _receipt_contains_evidence(obs, ev, canonical_class=canonical_class)
            for obs in prior_observations
        ):
            return True
        if (prior_observations or has_same_path_denied_control) and any(
            int(c.get("status") or 0) != 204 for c in eff_controls
        ):
            p_norm_path = _norm_url_path(str(primary_proof.get("url") or primary_proof.get("path") or ""))
            status_desc = f"http 204 no content delete {p_norm_path} deleted"
            ev_low = ev.lower()
            if (
                ev_low in status_desc
                or ev_low in p_norm_path
                or ev_low in str(primary_proof.get("url") or "").lower()
            ):
                return True
    return False


def _detect_ephemeral_evidence_mismatch(
    evidence_value: str,
    replay_target: dict[str, Any],
    replay_rec: dict[str, Any],
) -> bool:
    """Return True if Stage 3 replay reproduced the same masked response while only an ephemeral ID rotated."""
    ev = str(evidence_value or "").strip()
    if not ev:
        return False

    t_status = int(replay_target.get("status") or 0)
    r_status = int(replay_rec.get("status") or 0)
    if not (200 <= t_status < 300 and 200 <= r_status < 300):
        return False

    t_body = str(replay_target.get("body") or "").strip()
    r_body = str(replay_rec.get("body") or "").strip()
    if not t_body or not r_body:
        return False

    ev_low = ev.lower()
    if ev_low in r_body.lower():
        return False

    t_json = _try_parse_json_body(t_body)
    r_json = _try_parse_json_body(r_body)

    rotated_ephemeral_key = False
    if t_json is not None and r_json is not None:
        t_eph = _collect_ephemeral_json_values(t_json)
        r_eph = _collect_ephemeral_json_values(r_json)
        for key_path, t_vals in t_eph.items():
            if any(v.lower() == ev_low for v in t_vals):
                r_vals = r_eph.get(key_path) or []
                if r_vals and all(rv.lower() != ev_low for rv in r_vals):
                    rotated_ephemeral_key = True
                    break

    is_ephemeral_token = bool(
        _UUID_RE.fullmatch(ev)
        or _HEX_EPHEMERAL_RE.fullmatch(ev)
        or rotated_ephemeral_key
    )
    if not is_ephemeral_token:
        return False

    if not rotated_ephemeral_key and ev_low not in t_body.lower():
        return False

    t_masked = _mask_for_ephemeral_replay_comparison(t_body, parsed_json=t_json)
    r_masked = _mask_for_ephemeral_replay_comparison(r_body, parsed_json=r_json)
    return bool(t_masked) and t_masked == r_masked


def _control_probe_url_for_proof(receipt: dict[str, Any], suffix: str) -> str:
    """Resolve a Stage 1 control/decoy path against `receipt['url']`'s origin when absolute."""
    proof_url = str(receipt.get("url") or receipt.get("path") or "").strip()
    if _extract_origin(proof_url):
        return urljoin(proof_url, f"/{suffix.lstrip('/')}")
    return f"/{suffix.lstrip('/')}"


def _has_race_concurrency_evidence(
    proof_receipts: Sequence[dict[str, Any]],
    control_receipts: Sequence[dict[str, Any]],
    *,
    preserve_values: Sequence[str] = (),
) -> tuple[bool, str]:
    """Verify that `race_condition` proofs reflect genuine concurrency rather than sequential reads."""
    success_proofs: list[dict[str, Any]] = []
    seen_rids: set[str] = set()
    for rec in proof_receipts:
        rid = str(rec.get("receipt_id") or "").strip()
        if not rid or rid in seen_rids:
            continue
        status = int(rec.get("status") or 0)
        if 200 <= status < 400:
            seen_rids.add(rid)
            success_proofs.append(rec)

    if len(success_proofs) < 2:
        return False, "race_condition requires at least 2 distinct 2xx/3xx concurrent proof receipts."

    burst_counts = Counter(
        str(r.get("concurrent_burst_id") or "").strip()
        for r in success_proofs
        if str(r.get("concurrent_burst_id") or "").strip()
    )
    has_shared_burst_id = any(cnt >= 2 for cnt in burst_counts.values())

    def _within_window(recs: Sequence[dict[str, Any]], max_delta_s: float = 2.0) -> bool:
        by_ep: dict[tuple[str, str], list[tuple[str, datetime]]] = {}
        for r in recs:
            u = str(r.get("url") or r.get("path") or "")
            ep_key = (_norm_url_path(u), str(r.get("method") or "").upper())
            dt = _parse_receipt_timestamp(str(r.get("timestamp") or ""))
            if dt is not None:
                by_ep.setdefault(ep_key, []).append((_extract_origin(u), dt))
        for items in by_ep.values():
            if len(items) < 2:
                continue
            for i in range(len(items)):
                orig_i, dt_i = items[i]
                for j in range(i + 1, len(items)):
                    orig_j, dt_j = items[j]
                    if orig_i and orig_j and orig_i != orig_j:
                        continue
                    if (dt_i.tzinfo is None) != (dt_j.tzinfo is None):
                        continue
                    if abs((dt_j - dt_i).total_seconds()) <= max_delta_s:
                        return True
        return False

    mutating_success = [
        r for r in success_proofs if str(r.get("method") or "").upper() in _MUTATING_METHODS
    ]
    if len(mutating_success) >= 2:
        if has_shared_burst_id or _within_window(mutating_success, 2.0):
            return True, ""
        return (
            False,
            "race_condition requires shared concurrent_burst_id or >= 2 same-endpoint mutating proofs within 2.0s.",
        )

    # Purely read-only GET/HEAD proofs must NOT pass unless backed by BOTH concurrency and state-change evidence.
    has_tight_pair = has_shared_burst_id or _within_window(success_proofs, 2.0)
    has_mutating_proof = any(
        str(r.get("method") or "").upper() in _MUTATING_METHODS for r in proof_receipts
    )
    distinct_ro_states = {
        (
            int(r.get("status") or 0),
            mask_dynamic_fields(str(r.get("body") or ""), preserve_values=preserve_values),
        )
        for r in success_proofs
    }
    has_mutating_ctrl = any(
        str(c.get("method") or "").upper() in _MUTATING_METHODS for c in control_receipts
    )
    if has_tight_pair and (has_mutating_proof or len(distinct_ro_states) >= 2 or has_mutating_ctrl):
        return True, ""
    return (
        False,
        "race_condition rejected: purely read-only GET/HEAD receipts require concurrency and state-change evidence.",
    )


@dataclass
class OracleVerdict:
    """Result of Layer 4 Differential Oracle verification."""

    verified: bool
    verdict: str  # VERIFIED | REFUTED | DECEPTION_DETECTED
    reason: str = ""
    deception_detected: bool = False
    mode: str = "differential"
    stages: dict[str, Any] = field(default_factory=dict)
    clean_replay_receipt_id: str = ""
    control_probe_receipt_id: str = ""


class DifferentialOracle:
    """3-stage protocol-level verification gate: Control/Falsification -> Masked Diff -> Clean Replay."""

    def __init__(
        self,
        *,
        http_client: AgenticHTTPClient,
        receipt_store: ReceiptStore,
        mode: str = "differential",
        timeout_s: float = 15.0,
        oob_server: Any | None = None,
        timing_min_delta_ms: float = 1500.0,
        timing_min_ratio: float = 3.0,
        timing_replay_pairs: int = 2,
    ):
        norm_mode = str(mode or "differential").strip().lower()
        if norm_mode not in VALID_VERIFICATION_GATES:
            raise ValueError(f"invalid verification_gate mode: {mode!r}")
        self.http = http_client
        self.receipts = receipt_store
        self.mode = norm_mode
        self.timeout_s = float(timeout_s)
        self.oob_server = oob_server
        self.timing_min_delta_ms = max(1.0, float(timing_min_delta_ms))
        self.timing_min_ratio = max(1.0, float(timing_min_ratio))
        self.timing_replay_pairs = max(1, int(timing_replay_pairs))

    def _has_budget(self, needed: int = 1) -> bool:
        return (self.http.budget.limit - self.http.budget.used) >= needed

    def _run_clean_session_request(
        self,
        *,
        actor: str,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        raw_body: str = "",
    ) -> dict[str, Any]:
        """Execute a single HTTP request inside a brand-new isolated requests.Session()."""
        allowed, reason = self.http.budget.consume()
        if not allowed:
            raise BudgetExhaustedError(reason)

        clean_url, path, query = self.http.resolve_in_scope(url)
        session_obj = self.http.actors.get(actor)
        safe_extra = {
            str(k): str(v)
            for k, v in (headers or {}).items()
            if k.lower() not in _NON_REPLAY_REQ_HEADERS and "<REDACTED" not in str(v)
        }
        req_headers = session_obj.build_headers(method, safe_extra)
        if not any(k.lower() == "user-agent" for k in req_headers):
            req_headers["User-Agent"] = DEFAULT_BROWSER_USER_AGENT
        body_bytes = raw_body.encode("utf-8") if raw_body else None

        fresh = requests.Session()
        fresh.trust_env = False
        fresh.headers["User-Agent"] = DEFAULT_BROWSER_USER_AGENT
        status = 0
        resp_headers: dict[str, str] = {}
        raw_bytes = b""
        text = ""
        content_type = ""
        redirect_location = ""
        error = ""
        started = time.monotonic()
        try:
            resp = fresh.request(
                method=method,
                url=clean_url,
                headers=req_headers,
                data=body_bytes,
                allow_redirects=False,
                timeout=self.timeout_s,
                stream=True,
            )
            try:
                status = int(resp.status_code)
                resp_headers = {str(k): str(v) for k, v in resp.headers.items()}
                content_type = _header_get(resp_headers, "Content-Type").split(";", 1)[0].strip().lower()
                redirect_location = _header_get(resp_headers, "Location")
                raw_stream = resp.raw.read(self.http.max_response_bytes + 1, decode_content=False)
                if len(raw_stream) > self.http.max_response_bytes:
                    raw_stream = raw_stream[: self.http.max_response_bytes]
                raw_bytes = _decode_raw_response(raw_stream, _header_get(resp_headers, "Content-Encoding"))
                text = raw_bytes.decode("utf-8", errors="replace")
            finally:
                resp.close()
        except Exception as exc:
            error = f"{type(exc).__name__}: {str(exc)[:200]}"
        finally:
            fresh.cookies.clear()
            fresh.close()
        elapsed_ms = max(0.0, (time.monotonic() - started) * 1000.0)

        return self.receipts.record(
            actor=actor,
            method=method,
            url=clean_url,
            path=path,
            query=query,
            request_headers=req_headers,
            request_body=raw_body,
            status=status,
            elapsed_ms=elapsed_ms,
            content_type=content_type,
            response_headers=resp_headers,
            redirect_location=redirect_location,
            raw_response_bytes=raw_bytes,
            response_text=text,
            error=error,
            secret_values=self.http.actors.all_secrets(),
        )

    def _run_timing_statistical_replay(
        self,
        *,
        canonical_class: str,
        diff_target: dict[str, Any],
        timing_control: dict[str, Any],
        stages: dict[str, Any],
        ctrl_probe_rid: str,
    ) -> OracleVerdict:
        """Execute fail-closed alternating clean-session timing replay pairs in Stage 3."""
        pairs = max(1, int(self.timing_replay_pairs))
        needed_requests = 2 * pairs
        if not self._has_budget(needed_requests):
            stages["stage3_clean_replay"] = "failed_timing_budget"
            return OracleVerdict(
                verified=False,
                verdict="REFUTED",
                reason=(
                    f"Statistical timing verification requires {needed_requests} HTTP requests for "
                    f"{pairs} alternating clean-session replay pairs, but remaining budget is insufficient."
                ),
                mode=self.mode,
                stages=stages,
                control_probe_receipt_id=ctrl_probe_rid,
            )

        ctrl_method = str(timing_control.get("method") or "GET").upper()
        proof_method = str(diff_target.get("method") or "GET").upper()
        if ctrl_method not in self.http.allowed_methods or proof_method not in self.http.allowed_methods:
            stages["stage3_clean_replay"] = "failed_timing_method_not_allowed"
            return OracleVerdict(
                verified=False,
                verdict="REFUTED",
                reason=(
                    f"Statistical timing verification skipped: HTTP method(s) "
                    f"{ctrl_method!r}/{proof_method!r} not in allowed_methods."
                ),
                mode=self.mode,
                stages=stages,
                control_probe_receipt_id=ctrl_probe_rid,
            )

        orig_ctrl_status = int(timing_control.get("status") or 0)
        orig_proof_status = int(diff_target.get("status") or 0)
        ctrl_samples: list[float] = []
        proof_samples: list[float] = []
        ctrl_recs: list[dict[str, Any]] = []
        proof_recs: list[dict[str, Any]] = []

        def _record_summary() -> tuple[float, float, float, float]:
            ctrl_med_val = float(statistics.median(ctrl_samples)) if ctrl_samples else 0.0
            proof_med_val = float(statistics.median(proof_samples)) if proof_samples else 0.0
            ctrl_med_r = round(ctrl_med_val, 2)
            proof_med_r = round(proof_med_val, 2)
            delta_r = round(proof_med_val - ctrl_med_val, 2)
            min_gap_val = (
                (min(proof_samples) - max(ctrl_samples))
                if (ctrl_samples and proof_samples)
                else 0.0
            )
            stages["control_ms"] = ctrl_med_r
            stages["proof_ms"] = proof_med_r
            stages["delta_ms"] = delta_r
            stages["timing_summary"] = {
                "control_ms": ctrl_med_r,
                "proof_ms": proof_med_r,
                "delta_ms": delta_r,
                "min_gap_ms": round(min_gap_val, 2),
                "control_samples_ms": [round(x, 2) for x in ctrl_samples],
                "proof_samples_ms": [round(x, 2) for x in proof_samples],
                "pairs": pairs,
            }
            return ctrl_med_val, proof_med_val, delta_r, min_gap_val

        for _ in range(pairs):
            try:
                t0 = time.monotonic()
                c_rec = self._run_clean_session_request(
                    actor=str(timing_control.get("actor") or "anon"),
                    method=ctrl_method,
                    url=str(timing_control.get("url") or "/"),
                    headers=timing_control.get("request_headers") or {},
                    raw_body=str(timing_control.get("request_body") or ""),
                )
                c_wall_ms = max(0.0, (time.monotonic() - t0) * 1000.0)
            except BudgetExhaustedError:
                _record_summary()
                stages["stage3_clean_replay"] = "failed_timing_budget"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="HTTP budget exhausted during statistical timing differential replay.",
                    mode=self.mode,
                    stages=stages,
                    control_probe_receipt_id=ctrl_probe_rid,
                )
            c_ms = _receipt_elapsed_ms(c_rec)
            ctrl_samples.append(c_ms if c_ms is not None else c_wall_ms)
            ctrl_recs.append(c_rec)
            c_status = int(c_rec.get("status") or 0)
            if (
                c_status <= 0
                or bool(c_rec.get("error"))
                or (c_status // 100) != (orig_ctrl_status // 100)
            ):
                _record_summary()
                stages["stage3_clean_replay"] = "failed_timing_status"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason=(
                        f"Timing control replay returned inconsistent/error status {c_status} "
                        f"(expected {orig_ctrl_status // 100}xx)."
                    ),
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=proof_recs[-1]["receipt_id"] if proof_recs else "",
                    control_probe_receipt_id=ctrl_probe_rid or str(c_rec.get("receipt_id") or ""),
                )

            try:
                t1 = time.monotonic()
                p_rec = self._run_clean_session_request(
                    actor=str(diff_target.get("actor") or "anon"),
                    method=proof_method,
                    url=str(diff_target.get("url") or "/"),
                    headers=diff_target.get("request_headers") or {},
                    raw_body=str(diff_target.get("request_body") or ""),
                )
                p_wall_ms = max(0.0, (time.monotonic() - t1) * 1000.0)
            except BudgetExhaustedError:
                _record_summary()
                stages["stage3_clean_replay"] = "failed_timing_budget"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="HTTP budget exhausted during statistical timing differential replay.",
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=proof_recs[-1]["receipt_id"] if proof_recs else "",
                    control_probe_receipt_id=ctrl_probe_rid or str(c_rec.get("receipt_id") or ""),
                )
            p_ms = _receipt_elapsed_ms(p_rec)
            proof_samples.append(p_ms if p_ms is not None else p_wall_ms)
            proof_recs.append(p_rec)
            p_status = int(p_rec.get("status") or 0)
            if (
                p_status <= 0
                or bool(p_rec.get("error"))
                or (p_status // 100) != (orig_proof_status // 100)
            ):
                _record_summary()
                stages["stage3_clean_replay"] = "failed_timing_status"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason=(
                        f"Timing proof replay returned inconsistent/error status {p_status} "
                        f"(expected {orig_proof_status // 100}xx)."
                    ),
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=str(p_rec.get("receipt_id") or ""),
                    control_probe_receipt_id=ctrl_probe_rid or str(c_rec.get("receipt_id") or ""),
                )

        ctrl_med, proof_med, delta_r, min_gap = _record_summary()
        last_proof_rid = str(proof_recs[-1].get("receipt_id") or "")
        last_ctrl_rid = ctrl_probe_rid or str(ctrl_recs[-1].get("receipt_id") or "")

        zero_overlap_ok = min_gap >= self.timing_min_delta_ms
        ratio_ok = proof_med >= self.timing_min_ratio * max(ctrl_med, 20.0)
        if zero_overlap_ok and ratio_ok:
            stages["stage3_clean_replay"] = "passed_timing_statistical"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason=(
                    f"Verified {canonical_class} via statistical timing differential across {pairs} "
                    f"alternating clean-session replay pairs (control={ctrl_med:.1f}ms, "
                    f"proof={proof_med:.1f}ms, delta={delta_r:.1f}ms, min_gap={min_gap:.1f}ms)."
                ),
                mode=self.mode,
                stages=stages,
                clean_replay_receipt_id=last_proof_rid,
                control_probe_receipt_id=last_ctrl_rid,
            )

        stages["stage3_clean_replay"] = "failed_timing_overlap"
        return OracleVerdict(
            verified=False,
            verdict="REFUTED",
            reason=(
                f"Statistical timing differential refuted across {pairs} alternating clean-session "
                f"replay pairs (control_median={ctrl_med:.1f}ms, proof_median={proof_med:.1f}ms, "
                f"min_gap={min_gap:.1f}ms < {self.timing_min_delta_ms:.1f}ms or ratio < {self.timing_min_ratio:.1f}x)."
            ),
            mode=self.mode,
            stages=stages,
            clean_replay_receipt_id=last_proof_rid,
            control_probe_receipt_id=last_ctrl_rid,
        )

    def _benign_control_url(self, url: str) -> str:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs:
            return url
        benign_pairs = [(k, "baseline_value") for k, _ in pairs]
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(benign_pairs), ""))

    def verify(
        self,
        *,
        canonical_class: str,
        primary_proof: dict[str, Any],
        proof_receipts: list[dict[str, Any]],
        control_receipts: list[dict[str, Any]],
        evidence_value: str,
        actor_meta_map: dict[str, dict[str, str]] | None = None,
        surface_tracker: Any | None = None,
        inferred_owner: str = "",
        oob_server: Any | None = None,
        oob_hits: Sequence[dict[str, Any]] | None = None,
        setup_receipts: Sequence[dict[str, Any]] | None = None,
    ) -> OracleVerdict:
        """Run verification gate before promoting a CLAIMED hypothesis to VERIFIED."""
        if self.mode == "llm_self_judge":
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason="llm_self_judge mode: accepted after receipt structural check",
                mode=self.mode,
                stages={"stage1_control": "skipped", "stage2_diff": "skipped", "stage3_clean_replay": "skipped"},
            )

        stages: dict[str, Any] = {}
        ev = str(evidence_value or "").strip()
        active_oob = oob_server if oob_server is not None else self.oob_server
        effective_oob_hits: list[dict[str, Any]] = [dict(h) for h in (oob_hits or []) if isinstance(h, dict)]
        oob_tokens_submitted: list[str] = []
        if canonical_class in _OOB_ELIGIBLE_CLASSES and active_oob is not None and hasattr(active_oob, "registered_tokens"):
            try:
                reg_tokens = list(active_oob.registered_tokens())
            except Exception:
                reg_tokens = []
            for tok in reg_tokens:
                if not tok:
                    continue
                if any(
                    tok in str(r.get("url") or "")
                    or tok in str(r.get("query") or "")
                    or tok in str(r.get("request_body") or "")
                    or tok in json.dumps(r.get("request_headers") or {}, ensure_ascii=False)
                    for r in proof_receipts
                ):
                    oob_tokens_submitted.append(tok)
                    if not effective_oob_hits and hasattr(active_oob, "poll"):
                        polled = active_oob.poll(tok)
                        effective_oob_hits.extend(polled.get("hits") or [])
            if oob_tokens_submitted and not effective_oob_hits:
                stages["stage1_control"] = "failed_oob_zero_hits"
                class_label = "SSRF" if canonical_class == "ssrf" else canonical_class
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason=f"{class_label} callback claim rejected: callback_listener recorded 0 hits for submitted token(s).",
                    mode=self.mode,
                    stages=stages,
                )
        is_oob_verified = canonical_class in _OOB_ELIGIBLE_CLASSES and bool(effective_oob_hits)
        render_proof: dict[str, Any] | None = None
        if canonical_class == "stored_xss":
            if str(primary_proof.get("method") or "").upper() == "GET" and 200 <= int(primary_proof.get("status") or 0) < 300:
                render_proof = primary_proof
            else:
                render_proof = _select_mutating_get_proof(
                    primary_proof,
                    proof_receipts,
                    ev,
                    canonical_class="stored_xss",
                )
            if render_proof is None:
                stages["stage1_control"] = "failed_missing_render_get"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="stored_xss requires a 2xx text/html GET render receipt containing evidence_value unescaped verbatim.",
                    mode=self.mode,
                    stages=stages,
                )
            if not is_html_receipt(render_proof):
                stages["stage1_control"] = "failed_non_html_render"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="stored_xss render GET receipt must have HTML (text/html) content-type.",
                    mode=self.mode,
                    stages=stages,
                )
            if ev and not receipt_body_contains_verbatim(render_proof, ev):
                stages["stage1_control"] = "failed_missing_unescaped_evidence"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="stored_xss render GET receipt does not contain evidence_value unescaped verbatim in HTML body.",
                    mode=self.mode,
                    stages=stages,
                )
        elif canonical_class in _PERSISTENT_CLASSES:
            render_proof = _select_mutating_get_proof(
                primary_proof,
                proof_receipts,
                ev,
                canonical_class=canonical_class,
            )
            if (
                ev
                and not is_oob_verified
                and not _receipt_contains_evidence(primary_proof, ev, canonical_class=canonical_class)
                and (
                    render_proof is None
                    or not _receipt_contains_evidence(render_proof, ev, canonical_class=canonical_class)
                )
            ):
                store_readback = _find_readback_get_in_store(
                    primary_proof,
                    self.receipts,
                    ev,
                    canonical_class=canonical_class,
                )
                if store_readback is not None:
                    render_proof = store_readback

        diff_target = primary_proof
        if canonical_class == "stored_xss" and render_proof is not None:
            diff_target = render_proof
        elif (
            canonical_class in _PERSISTENT_CLASSES
            and render_proof is not None
            and (
                not ev
                or not _receipt_contains_evidence(primary_proof, ev, canonical_class=canonical_class)
                or any(str(c.get("method") or "").upper() == "GET" for c in control_receipts)
            )
        ):
            diff_target = render_proof

        p_actor = str(diff_target.get("actor") or "anon")
        p_status = int(diff_target.get("status") or 0)
        p_masked = mask_dynamic_fields(str(diff_target.get("body") or ""), preserve_values=(ev,))
        p_loc = str(diff_target.get("redirect_location") or "")
        p_cors_sig = _cors_header_signature(diff_target) if canonical_class == "cors_misconfiguration" else ("", "")

        # --- Stage 1: Falsification / Control Baseline Check ---
        input_diff_eligible = (
            canonical_class in _INPUT_DIFF_CLASSES or canonical_class in _TIMING_ELIGIBLE_CLASSES
        )
        ctrl_probe_rid = ""
        eff_controls = list(control_receipts)
        if (
            not eff_controls
            and not is_oob_verified
            and canonical_class not in _CONCURRENCY_CLASSES
            and canonical_class != "weak_credentials"
            and self._has_budget(2)
        ):
            try:
                if input_diff_eligible:
                    ctrl_url = self._benign_control_url(str(diff_target.get("url") or "/"))
                    probe = self._run_clean_session_request(
                        actor=p_actor,
                        method="GET" if diff_target.get("method") == "GET" else str(diff_target.get("method") or "GET"),
                        url=ctrl_url,
                    )
                    ctrl_probe_rid = probe["receipt_id"]
                    eff_controls.append(probe)
                elif canonical_class == "auth_bypass":
                    probe = self._run_clean_session_request(
                        actor="anon",
                        method="GET",
                        url=_control_probe_url_for_proof(
                            primary_proof,
                            f"{uuid.uuid4().hex[:12]}-control-check",
                        ),
                    )
                    ctrl_probe_rid = probe["receipt_id"]
                    eff_controls.append(probe)
            except Exception:
                pass

        diff_controls = eff_controls
        if str(diff_target.get("method") or "").upper() == "GET":
            get_ctrls = [c for c in eff_controls if str(c.get("method") or "").upper() == "GET"]
            if get_ctrls:
                diff_controls = get_ctrls

        # Catch-all / soft-404 decoy check for auth_bypass HTML responses
        if (
            canonical_class == "auth_bypass"
            and "html" in str(primary_proof.get("content_type") or "").lower()
            and self._has_budget(2)
        ):
            try:
                catchall_probe = self._run_clean_session_request(
                    actor="anon",
                    method="GET",
                    url=_control_probe_url_for_proof(
                        primary_proof,
                        f"{uuid.uuid4().hex[:12]}-control-check",
                    ),
                )
                ctrl_probe_rid = catchall_probe["receipt_id"]
                c_masked = mask_dynamic_fields(str(catchall_probe.get("body") or ""), preserve_values=(ev,))
                if int(catchall_probe.get("status") or 0) == p_status and c_masked == p_masked:
                    stages["stage1_control"] = "deception_catchall_html"
                    return OracleVerdict(
                        verified=False,
                        verdict="DECEPTION_DETECTED",
                        reason="Catch-all HTML response returned identical output on non-existent control path.",
                        deception_detected=True,
                        mode=self.mode,
                        stages=stages,
                        control_probe_receipt_id=ctrl_probe_rid,
                    )
            except Exception:
                pass

        # Check benign control equivalence and stored_xss baseline absence for input/mutation classes
        if input_diff_eligible and not is_oob_verified:
            if canonical_class == "weak_credentials" and not eff_controls:
                stages["stage1_control"] = "failed_missing_control"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason=(
                        "weak_credentials requires at least one comparative control receipt "
                        "(e.g. failed login with invalid credentials or unauthenticated denial on a protected endpoint)."
                    ),
                    mode=self.mode,
                    stages=stages,
                )
            if canonical_class == "stored_xss" and ev:
                p_count = str(diff_target.get("body") or "").lower().count(ev.lower())
                for ctrl in diff_controls:
                    c_count = str(ctrl.get("body") or "").lower().count(ev.lower())
                    if c_count >= p_count or c_count > 0 and p_count <= c_count:
                        stages["stage1_control"] = "failed_evidence_in_baseline"
                        return OracleVerdict(
                            verified=False,
                            verdict="REFUTED",
                            reason="Benign baseline GET control already contains the claimed stored_xss evidence_value.",
                            mode=self.mode,
                            stages=stages,
                            control_probe_receipt_id=ctrl_probe_rid,
                        )
            same_actor_ctrls = [c for c in diff_controls if str(c.get("actor") or "") == p_actor]
            p_elapsed = _receipt_elapsed_ms(diff_target)
            p_diff_rid = str(diff_target.get("receipt_id") or "").strip()
            p_hdr_sig = (
                _response_headers_signature(diff_target, preserve_values=(ev,))
                if canonical_class != "weak_credentials"
                else ()
            )
            for ctrl in same_actor_ctrls:
                if canonical_class == "weak_credentials":
                    is_equivalent = _weak_credentials_controls_equivalent(diff_target, ctrl, ev=ev)
                else:
                    c_masked = mask_dynamic_fields(str(ctrl.get("body") or ""), preserve_values=(ev,))
                    c_status = int(ctrl.get("status") or 0)
                    c_loc = str(ctrl.get("redirect_location") or "")
                    cors_same = (
                        True
                        if canonical_class != "cors_misconfiguration"
                        else _cors_header_signature(ctrl) == p_cors_sig
                    )
                    hdrs_same = _response_headers_signature(ctrl, preserve_values=(ev,)) == p_hdr_sig
                    is_equivalent = (
                        c_status == p_status
                        and c_masked == p_masked
                        and urlsplit(c_loc).netloc == urlsplit(p_loc).netloc
                        and cors_same
                        and hdrs_same
                    )
                    if (
                        is_equivalent
                        and canonical_class == "cors_misconfiguration"
                        and _is_exempt_static_cors_control(diff_target, ctrl, eff_controls)
                    ):
                        is_equivalent = False
                if is_equivalent:
                    c_rid = str(ctrl.get("receipt_id") or "").strip()
                    if (
                        canonical_class in _TIMING_ELIGIBLE_CLASSES
                        and ctrl is not diff_target
                        and not (p_diff_rid and c_rid and c_rid == p_diff_rid)
                        and p_status > 0
                        and int(ctrl.get("status") or 0) > 0
                        and not _is_multipart_receipt(diff_target)
                        and not _is_multipart_receipt(ctrl)
                        and _is_timing_pair_significant(
                            p_elapsed,
                            _receipt_elapsed_ms(ctrl),
                            min_delta_ms=self.timing_min_delta_ms,
                            min_ratio=self.timing_min_ratio,
                        )
                    ):
                        continue
                    stages["stage1_control"] = "deception_identical_control"
                    return OracleVerdict(
                        verified=False,
                        verdict="DECEPTION_DETECTED",
                        reason="Benign control returned identical masked status, body, and redirect as claimed proof.",
                        deception_detected=True,
                        mode=self.mode,
                        stages=stages,
                        control_probe_receipt_id=ctrl_probe_rid,
                    )
        elif canonical_class in _CONCURRENCY_CLASSES:
            if canonical_class == "race_condition":
                race_ok, race_reason = _has_race_concurrency_evidence(
                    proof_receipts,
                    eff_controls,
                    preserve_values=(ev,),
                )
                if not race_ok:
                    stages["stage1_control"] = (
                        "failed_missing_concurrent_proofs"
                        if "at least 2 distinct" in race_reason
                        else "failed_missing_concurrency_evidence"
                    )
                    return OracleVerdict(
                        verified=False,
                        verdict="REFUTED",
                        reason=race_reason,
                        mode=self.mode,
                        stages=stages,
                    )
            if not eff_controls:
                stages["stage1_control"] = "failed_missing_control"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason=f"{canonical_class} requires at least one sequential or baseline control receipt.",
                    mode=self.mode,
                    stages=stages,
                )
            p_method = str(diff_target.get("method") or "").upper()
            if all(
                int(c.get("status") or 0) == p_status
                and mask_dynamic_fields(str(c.get("body") or ""), preserve_values=(ev,)) == p_masked
                and str(c.get("method") or "").upper() == p_method
                and str(c.get("actor") or "") == p_actor
                for c in eff_controls
            ):
                stages["stage1_control"] = "deception_identical_control"
                return OracleVerdict(
                    verified=False,
                    verdict="DECEPTION_DETECTED",
                    reason=f"{canonical_class} control receipt is identical to primary proof.",
                    deception_detected=True,
                    mode=self.mode,
                    stages=stages,
                )
        elif canonical_class in _ACCESS_CLASSES:
            if _is_graphql_error_envelope(primary_proof):
                stages["stage1_control"] = "failed_graphql_error_proof"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason=f"{canonical_class} primary proof returned a GraphQL error-only envelope.",
                    mode=self.mode,
                    stages=stages,
                    control_probe_receipt_id=ctrl_probe_rid,
                )
            # Check if a negative control (e.g. different path returning 403/404, or anon returning 401/403)
            # accidentally returned the exact same masked body + evidence_value for an unrelated/denied check.
            for ctrl in eff_controls:
                c_actor = str(ctrl.get("actor") or "")
                c_status = int(ctrl.get("status") or 0)
                c_path = str(ctrl.get("path") or "")
                p_path = str(primary_proof.get("path") or "")
                if (
                    c_actor == p_actor
                    and c_path != p_path
                    and 200 <= c_status < 300
                    and c_status == p_status
                ):
                    c_masked = mask_dynamic_fields(str(ctrl.get("body") or ""), preserve_values=(ev,))
                    if c_masked == p_masked and ev and ev.lower() in str(ctrl.get("body") or "").lower():
                        stages["stage1_control"] = "deception_static_access_response"
                        return OracleVerdict(
                            verified=False,
                            verdict="DECEPTION_DETECTED",
                            reason="Different control path returned identical masked body and evidence_value.",
                            deception_detected=True,
                            mode=self.mode,
                            stages=stages,
                            control_probe_receipt_id=ctrl_probe_rid,
                        )
        stages["stage1_control"] = "passed_oob_callback" if is_oob_verified else "passed"

        # --- Stage 2: Dynamic-Field-Masked Structural & Access-Boundary Diff ---
        timing_differential_control: dict[str, Any] | None = None
        if (
            input_diff_eligible or canonical_class not in (_CONCURRENCY_CLASSES | _ACCESS_CLASSES)
        ) and not is_oob_verified:
            has_masked_diff = False
            p_hdr_sig_s2 = (
                _response_headers_signature(diff_target, preserve_values=(ev,))
                if canonical_class != "weak_credentials"
                else ()
            )
            for ctrl in diff_controls:
                if canonical_class == "weak_credentials":
                    ctrl_differs = not _weak_credentials_controls_equivalent(diff_target, ctrl, ev=ev)
                else:
                    c_masked = mask_dynamic_fields(str(ctrl.get("body") or ""), preserve_values=(ev,))
                    c_status = int(ctrl.get("status") or 0)
                    c_loc = str(ctrl.get("redirect_location") or "")
                    cors_diff = (
                        canonical_class == "cors_misconfiguration"
                        and (
                            _cors_header_signature(ctrl) != p_cors_sig
                            or _is_exempt_static_cors_control(diff_target, ctrl, eff_controls)
                        )
                    )
                    hdrs_diff = _response_headers_signature(ctrl, preserve_values=(ev,)) != p_hdr_sig_s2
                    ctrl_differs = (
                        c_status != p_status
                        or c_masked != p_masked
                        or urlsplit(c_loc).netloc != urlsplit(p_loc).netloc
                        or cors_diff
                        or hdrs_diff
                    )
                if ctrl_differs:
                    has_masked_diff = True
                    break
            if diff_controls and not has_masked_diff:
                if canonical_class in _TIMING_ELIGIBLE_CLASSES and p_status > 0 and not _is_multipart_receipt(diff_target):
                    p_elapsed = _receipt_elapsed_ms(diff_target)
                    p_diff_rid = str(diff_target.get("receipt_id") or "").strip()
                    timing_candidates: list[tuple[int, float, dict[str, Any]]] = []
                    for ctrl in diff_controls:
                        c_rid = str(ctrl.get("receipt_id") or "").strip()
                        if ctrl is diff_target or (p_diff_rid and c_rid and c_rid == p_diff_rid):
                            continue
                        if int(ctrl.get("status") or 0) <= 0 or _is_multipart_receipt(ctrl):
                            continue
                        c_elapsed = _receipt_elapsed_ms(ctrl)
                        if _is_timing_pair_significant(
                            p_elapsed,
                            c_elapsed,
                            min_delta_ms=self.timing_min_delta_ms,
                            min_ratio=self.timing_min_ratio,
                        ):
                            same_act = 1 if str(ctrl.get("actor") or "") == p_actor else 0
                            timing_candidates.append((same_act, -(c_elapsed or 0.0), ctrl))
                    if timing_candidates:
                        timing_candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
                        timing_differential_control = timing_candidates[0][2]
                if timing_differential_control is None:
                    stages["stage2_diff"] = "failed_masked_equivalence"
                    return OracleVerdict(
                        verified=False,
                        verdict="REFUTED",
                        reason="Proof and control differ only in masked dynamic fields (timestamps/nonces/request IDs).",
                        deception_detected=True,
                        mode=self.mode,
                        stages=stages,
                        control_probe_receipt_id=ctrl_probe_rid,
                    )
        elif canonical_class in _CONCURRENCY_CLASSES:
            p_method = str(diff_target.get("method") or "").upper()
            has_diff = any(
                int(c.get("status") or 0) != p_status
                or mask_dynamic_fields(str(c.get("body") or ""), preserve_values=(ev,)) != p_masked
                or str(c.get("method") or "").upper() != p_method
                or str(c.get("actor") or "") != p_actor
                for c in eff_controls
            )
            if not has_diff:
                stages["stage2_diff"] = "failed_masked_equivalence"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason=f"{canonical_class} proof and control receipts show no differential behavior.",
                    deception_detected=True,
                    mode=self.mode,
                    stages=stages,
                )
        elif canonical_class in _ACCESS_CLASSES:
            meta_map = actor_meta_map or {}
            if canonical_class == "bfla":
                role = str((meta_map.get(p_actor) or {}).get("role") or "").lower()
                if any(tok in role for tok in ("admin", "superadmin", "superuser")):
                    stages["stage2_diff"] = "failed_admin_actor_for_bfla"
                    return OracleVerdict(
                        verified=False,
                        verdict="REFUTED",
                        reason="BFLA proof cannot rely on an admin actor.",
                        mode=self.mode,
                        stages=stages,
                    )
            elif canonical_class == "bola":
                bola_fp = check_bola_false_positive(
                    primary_proof=primary_proof,
                    proof_receipts=proof_receipts,
                    control_receipts=eff_controls,
                    actor_meta_map=meta_map,
                    receipt_store=self.receipts,
                    surface_tracker=surface_tracker,
                    inferred_owner=inferred_owner,
                )
                if bola_fp is not None:
                    stage_code, reason = bola_fp
                    stages["stage2_diff"] = stage_code
                    return OracleVerdict(
                        verified=False,
                        verdict="REFUTED",
                        reason=reason,
                        mode=self.mode,
                        stages=stages,
                        control_probe_receipt_id=ctrl_probe_rid,
                    )
        if timing_differential_control is not None:
            stages["stage2_diff"] = "passed_timing_differential"
        else:
            stages["stage2_diff"] = "passed_oob_callback" if is_oob_verified else "passed"

        # --- Stage 3: Clean-Session Replay in fresh isolated requests.Session() ---
        if canonical_class == "race_condition" or (
            canonical_class == "business_logic"
            and (
                len(proof_receipts) >= 2
                or (
                    str(primary_proof.get("method") or "").upper() in _MUTATING_METHODS
                    and not _has_redacted_credential_body(primary_proof)
                )
            )
        ):
            stages["stage3_clean_replay"] = "skipped_non_idempotent_concurrency"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason="Verified across concurrency proof receipts and sequential/state control without re-triggering mutating bursts.",
                mode=self.mode,
                stages=stages,
                control_probe_receipt_id=ctrl_probe_rid,
            )

        if is_oob_verified and str(primary_proof.get("method") or "").upper() in _MUTATING_METHODS:
            stages["stage3_clean_replay"] = "passed_oob_verified"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason="Verified by recorded out-of-band loopback callback hit(s) matching submitted token.",
                mode=self.mode,
                stages=stages,
                control_probe_receipt_id=ctrl_probe_rid,
            )

        if timing_differential_control is not None:
            return self._run_timing_statistical_replay(
                canonical_class=canonical_class,
                diff_target=diff_target,
                timing_control=timing_differential_control,
                stages=stages,
                ctrl_probe_rid=ctrl_probe_rid,
            )

        # Prefer replaying a 2xx GET persistence proof receipt when one is present
        # (including cross-actor GETs after non-idempotent ownership/tenant transfers
        # and read/render GETs for stored_xss / ssti / mass_assignment / file_upload).
        # For weak_credentials, replay the login request itself in a fresh isolated session.
        replay_target = (
            primary_proof
            if canonical_class == "weak_credentials"
            else (
                render_proof
                or _select_mutating_get_proof(
                    primary_proof,
                    proof_receipts,
                    ev,
                    canonical_class=canonical_class,
                )
                or primary_proof
            )
        )

        # Do not replay compact non-binary multipart/form-data summary strings as raw_body.
        if (
            _is_multipart_receipt(replay_target)
            and str(replay_target.get("method") or "").upper() in _MUTATING_METHODS
        ):
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason="Verified by control baseline and masked differential (non-replayable binary multipart upload).",
                mode=self.mode,
                stages={**stages, "stage3_clean_replay": "skipped_non_replayable_multipart"},
                control_probe_receipt_id=ctrl_probe_rid,
            )

        if not self._has_budget(1):
            stages["stage3_clean_replay"] = "skipped_budget"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason="Verified by Stages 1-2 (budget too low for clean replay).",
                mode=self.mode,
                stages=stages,
                control_probe_receipt_id=ctrl_probe_rid,
            )

        replayed_via_stateful_fallback = False
        replayed_via_two_step = False
        replayed_via_multistep = False
        two_step_setup_rid = ""
        multistep_step_count = 0
        multistep_precursor_rids: list[str] = []
        multistep_substitutions: dict[str, str] = {}
        attempted_precursor_chain = False

        replay_raw_body = str(replay_target.get("request_body") or "")
        if canonical_class != "csrf" and "<REDACTED" in replay_raw_body:
            try:
                csrf_session_obj = self.http.actors.get(str(replay_target.get("actor") or "anon"))
            except ValueError:
                csrf_session_obj = None
            replay_raw_body = _restore_session_csrf_in_body(replay_raw_body, csrf_session_obj)

        try:
            replay_rec = self._run_clean_session_request(
                actor=str(replay_target.get("actor") or "anon"),
                method=str(replay_target.get("method") or "GET"),
                url=str(replay_target.get("url") or "/"),
                headers=replay_target.get("request_headers") or {},
                raw_body=replay_raw_body,
            )
        except BudgetExhaustedError:
            stages["stage3_clean_replay"] = "skipped_budget"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason="Verified by Stages 1-2 (HTTP budget exhausted before clean replay).",
                mode=self.mode,
                stages=stages,
                control_probe_receipt_id=ctrl_probe_rid,
            )

        r_status = int(replay_rec.get("status") or 0)
        t_status = int(replay_target.get("status") or 0)
        ev_in_oob = bool(
            ev
            and is_oob_verified
            and any(
                ev.lower() in json.dumps(h, ensure_ascii=False).lower()
                for h in effective_oob_hits
            )
        )

        # When a proof sent an explicit forged/overridden auth header (Authorization,
        # Cookie, X-Auth-Token, X-Api-Key, Proxy-Authorization) that ReceiptStore
        # redacted, clean-session replay drops it and receives 401/403 live.
        has_redacted_auth_override = False
        if 200 <= t_status < 300 and r_status in {401, 403}:
            try:
                replay_session_obj = self.http.actors.get(str(replay_target.get("actor") or "anon"))
            except ValueError:
                replay_session_obj = None
            has_redacted_auth_override = (
                replay_session_obj is not None
                and _has_overridden_redacted_auth_header(
                    replay_target,
                    replay_session_obj,
                    str(replay_target.get("method") or "GET"),
                )
            )
            if has_redacted_auth_override and _can_accept_redacted_auth_override(
                canonical_class=canonical_class,
                replay_target=replay_target,
                diff_controls=diff_controls,
                eff_controls=eff_controls,
                is_oob_verified=is_oob_verified,
                evidence_value=ev,
                ev_in_oob=ev_in_oob,
                p_status=p_status,
                p_masked=p_masked,
                p_loc=p_loc,
                p_cors_sig=p_cors_sig,
            ):
                stages["stage3_clean_replay"] = "passed_redacted_auth_override"
                if canonical_class in {"jwt_weakness", "auth_bypass", "weak_credentials"}:
                    reason = (
                        f"Verified {canonical_class} via control differential and live unprivileged "
                        "clean-session rejection (forged auth header redacted in receipt)."
                    )
                else:
                    reason = (
                        f"Verified {canonical_class} via Stage 1-2 baseline/OOB differential and live "
                        "unprivileged clean-session rejection (overridden auth header redacted in receipt)."
                    )
                return OracleVerdict(
                    verified=True,
                    verdict="VERIFIED",
                    reason=reason,
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=replay_rec["receipt_id"],
                    control_probe_receipt_id=ctrl_probe_rid,
                )

        # When a weak_credentials login proof sent a JSON password field that ReceiptStore
        # scrubbed to <REDACTED_SECRET>, clean replay sends the redacted placeholder and live
        # rejection (400/401/403/422 or failed-login control match) confirms auth enforcement.
        if (
            canonical_class == "weak_credentials"
            and 200 <= t_status < 400
            and _weak_credentials_redacted_body_rejected(
                replay_target,
                replay_rec,
                eff_controls,
                ev=ev,
            )
        ):
            stages["stage3_clean_replay"] = "passed_redacted_credential_body"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason=(
                    "Verified weak_credentials via Stage 1-2 login differential and live "
                    "clean-session rejection when credential field is redacted in receipt."
                ),
                mode=self.mode,
                stages=stages,
                clean_replay_receipt_id=replay_rec["receipt_id"],
                control_probe_receipt_id=ctrl_probe_rid,
            )

        # Generalized fail-closed redacted-credential body replay guard for non-weak_credentials
        # classes (e.g. mass_assignment / business_logic / session_management on login endpoints):
        # Stage 1 control and Stage 2 masked diff already passed, and clean replay could not
        # resend the redacted credential body verbatim, triggering a live 400/401/403 rejection.
        if (
            canonical_class != "weak_credentials"
            and not has_redacted_auth_override
            and (bool(eff_controls) or is_oob_verified)
            and _can_accept_redacted_credential_body_replay(
                replay_target,
                replay_rec,
                evidence_value=ev,
                canonical_class=canonical_class,
            )
        ):
            stages["stage3_clean_replay"] = "passed_redacted_credential_replay_exempt"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason=(
                    f"Verified {canonical_class} via Stage 1-2 differential; Stage 3 clean replay "
                    f"returned {r_status} because the saved request body's credential field is "
                    "redacted and could not be resent verbatim."
                ),
                mode=self.mode,
                stages=stages,
                clean_replay_receipt_id=replay_rec["receipt_id"],
                control_probe_receipt_id=ctrl_probe_rid,
            )

        # Case A — Destructive / one-shot DELETE state-transition verification:
        # When re-executing a 2xx DELETE returns 404/410 because the resource was
        # removed, verify original evidence_value and confirm removal via either:
        #   (1) an earlier 2xx GET on the exact path + fresh clean-session GET
        #       returning 404/410 (`passed_delete_persistence`), or
        #   (2) an earlier 2xx resource observation (GET/POST/PUT/collection listing)
        #       or a same-path denied control (401/403/404), confirmed by clean-session
        #       GET readback returning 404/410 (or 405/501 when GET is unsupported, or
        #       when GET budget/method is unavailable) while rejecting any 2xx "still
        #       alive" readback or unrelated route errors
        #       (`passed_one_shot_delete_state_transition`).
        if (
            replay_target is primary_proof
            and str(primary_proof.get("method") or "").upper() == "DELETE"
            and 200 <= t_status < 300
            and r_status in {404, 410}
            and not _is_unrelated_route_not_found(replay_rec, "DELETE")
        ):
            p_norm_path = _norm_url_path(str(primary_proof.get("url") or primary_proof.get("path") or ""))
            p_rid = str(primary_proof.get("receipt_id") or "")
            r_rid = str(replay_rec.get("receipt_id") or "")
            p_seq = _receipt_seq_num(primary_proof)
            r_seq = _receipt_seq_num(replay_rec)
            p_ts = str(primary_proof.get("timestamp") or "")
            ctrl_actors = {
                str(c.get("actor") or "").strip()
                for c in eff_controls
                if str(c.get("actor") or "").strip()
            }
            known_actors = {
                str(a.get("alias") or "").strip()
                for a in self.http.actors.summaries()
                if str(a.get("alias") or "").strip()
            }
            meta_map = actor_meta_map or {}
            explicit_owner, _ = _extract_owner_and_tenant_from_receipt(primary_proof, meta_map)
            eff_owner = explicit_owner or str(inferred_owner or "").strip()
            if not eff_owner and surface_tracker is not None:
                p_surface_path = normalize_path(str(primary_proof.get("url") or primary_proof.get("path") or ""))
                obj_entry = (getattr(surface_tracker, "discovered_objects", None) or {}).get(p_surface_path)
                if isinstance(obj_entry, dict):
                    eff_owner = str(obj_entry.get("owner_actor") or "").strip()

            prior_gets: list[dict[str, Any]] = []
            prior_observations: list[dict[str, Any]] = []
            seen_prior_rids: set[str] = set()
            cand_pool: list[dict[str, Any]] = []
            for rid in self.receipts.list_ids():
                if rid in {p_rid, r_rid}:
                    continue
                try:
                    cand_pool.append(self.receipts.get(rid))
                except (KeyError, ValueError):
                    continue
            for extra_rec in (*proof_receipts, *eff_controls):
                if isinstance(extra_rec, dict):
                    cand_pool.append(extra_rec)

            for cand in cand_pool:
                c_rid = str(cand.get("receipt_id") or "")
                dedup_key = c_rid or f"obj:{id(cand)}"
                if dedup_key in seen_prior_rids or (c_rid and c_rid in {p_rid, r_rid}) or cand is primary_proof:
                    continue
                c_seq = _receipt_seq_num(cand)
                c_ts = str(cand.get("timestamp") or "")
                if p_seq > 0 and c_seq > 0:
                    if c_seq >= p_seq:
                        continue
                elif p_ts and c_ts:
                    if c_ts >= p_ts:
                        continue
                elif r_seq > 0 and c_seq >= r_seq:
                    continue
                if not (200 <= int(cand.get("status") or 0) < 300):
                    continue
                c_method = str(cand.get("method") or "").upper()
                c_norm_path = _norm_url_path(str(cand.get("url") or cand.get("path") or ""))
                if c_method == "GET" and c_norm_path == p_norm_path:
                    seen_prior_rids.add(dedup_key)
                    prior_gets.append(cand)
                    prior_observations.append(cand)
                    if not eff_owner:
                        cand_owner, _ = _extract_owner_and_tenant_from_receipt(cand, meta_map)
                        if cand_owner:
                            eff_owner = cand_owner
                elif _receipt_observes_resource_before_delete(cand, p_norm_path):
                    seen_prior_rids.add(dedup_key)
                    prior_observations.append(cand)
                    if not eff_owner:
                        cand_owner, _ = _extract_owner_and_tenant_from_receipt(cand, meta_map)
                        if cand_owner:
                            eff_owner = cand_owner

            same_path_denied_controls = [
                c
                for c in eff_controls
                if _is_denied_control_receipt(c)
                and _norm_url_path(str(c.get("url") or c.get("path") or "")) == p_norm_path
            ]
            has_same_path_denied_control = bool(same_path_denied_controls)

            if _delete_original_evidence_ok(
                primary_proof=primary_proof,
                evidence_value=ev,
                ev_in_oob=ev_in_oob,
                canonical_class=canonical_class,
                prior_observations=prior_observations,
                eff_controls=eff_controls,
                has_same_path_denied_control=has_same_path_denied_control,
            ):
                delete_readback_alive = False
                readback_attempted = False

                if prior_gets and self._has_budget(1):
                    prior_gets.sort(
                        key=lambda rec: (
                            1 if str(rec.get("actor") or "").strip() in known_actors else 0,
                            1 if (eff_owner and str(rec.get("actor") or "").strip() == eff_owner) else 0,
                            1 if (
                                str(rec.get("actor") or "").strip() in ctrl_actors
                                and str(rec.get("actor") or "").strip() != p_actor
                            ) else 0,
                            1 if str(rec.get("actor") or "").strip() not in {"", "anon", p_actor} else 0,
                            1 if str(rec.get("actor") or "").strip() not in {"", p_actor} else 0,
                            _receipt_seq_num(rec),
                        ),
                        reverse=True,
                    )
                    chosen_actor = str(prior_gets[0].get("actor") or "").strip()
                    if not chosen_actor or chosen_actor not in known_actors:
                        chosen_actor = p_actor
                    readback_attempted = True
                    try:
                        fresh_get_rec = self._run_clean_session_request(
                            actor=chosen_actor,
                            method="GET",
                            url=str(primary_proof.get("url") or "/"),
                        )
                    except BudgetExhaustedError:
                        fresh_get_rec = None
                    if fresh_get_rec is not None:
                        fg_status = int(fresh_get_rec.get("status") or 0)
                        if fg_status in {404, 410} and not _is_unrelated_route_not_found(fresh_get_rec, "GET"):
                            stages["stage3_clean_replay"] = "passed_delete_persistence"
                            return OracleVerdict(
                                verified=True,
                                verdict="VERIFIED",
                                reason=(
                                    "Verified destructive DELETE persistence: resource returned 2xx before "
                                    "DELETE and 404/410 on fresh clean-session GET afterward."
                                ),
                                mode=self.mode,
                                stages=stages,
                                clean_replay_receipt_id=fresh_get_rec["receipt_id"],
                                control_probe_receipt_id=ctrl_probe_rid,
                            )
                        if 200 <= fg_status < 300:
                            delete_readback_alive = True

                if (
                    not delete_readback_alive
                    and (bool(prior_observations) or has_same_path_denied_control)
                ):
                    if (
                        not readback_attempted
                        and self._has_budget(1)
                        and "GET" in self.http.allowed_methods
                    ):
                        rb_candidates: list[str] = []
                        if eff_owner and eff_owner in known_actors:
                            rb_candidates.append(eff_owner)
                        for obs in prior_observations:
                            obs_actor = str(obs.get("actor") or "").strip()
                            if obs_actor and obs_actor in known_actors and obs_actor not in rb_candidates:
                                rb_candidates.append(obs_actor)
                        if p_actor and p_actor not in rb_candidates:
                            rb_candidates.append(p_actor)
                        for ca in sorted(ctrl_actors):
                            if ca in known_actors and ca not in {"", "anon"} and ca not in rb_candidates:
                                rb_candidates.append(ca)

                        rb_confirmed_absent = False
                        rb_unsupported_get = False
                        rb_receipt_id = replay_rec["receipt_id"]
                        for rb_actor in rb_candidates[:2]:
                            if not self._has_budget(1):
                                break
                            try:
                                rb_rec = self._run_clean_session_request(
                                    actor=rb_actor,
                                    method="GET",
                                    url=str(primary_proof.get("url") or "/"),
                                )
                            except BudgetExhaustedError:
                                break
                            rb_status = int(rb_rec.get("status") or 0)
                            if 200 <= rb_status < 300:
                                delete_readback_alive = True
                                break
                            if rb_status in {404, 410} and not _is_unrelated_route_not_found(rb_rec, "GET"):
                                rb_confirmed_absent = True
                                rb_receipt_id = rb_rec["receipt_id"]
                                break
                            if rb_status in {405, 501}:
                                rb_unsupported_get = True
                                break

                        if not delete_readback_alive and (rb_confirmed_absent or rb_unsupported_get):
                            stages["stage3_clean_replay"] = "passed_one_shot_delete_state_transition"
                            if rb_confirmed_absent:
                                stages["stage3_delete_replay_receipt_id"] = replay_rec["receipt_id"]
                            return OracleVerdict(
                                verified=True,
                                verdict="VERIFIED",
                                reason=(
                                    "Verified one-shot DELETE state transition: original 2xx DELETE "
                                    "returned 404/410 on clean replay and clean GET readback confirmed "
                                    "resource absence."
                                    if rb_confirmed_absent
                                    else "Verified one-shot DELETE state transition: original 2xx DELETE "
                                    "returned 404/410 on clean replay with corroborating prior/control "
                                    "state (GET unsupported on target route)."
                                ),
                                mode=self.mode,
                                stages=stages,
                                clean_replay_receipt_id=rb_receipt_id,
                                control_probe_receipt_id=ctrl_probe_rid,
                            )
                    elif not readback_attempted:
                        stages["stage3_clean_replay"] = "passed_one_shot_delete_state_transition"
                        return OracleVerdict(
                            verified=True,
                            verdict="VERIFIED",
                            reason=(
                                "Verified one-shot DELETE state transition: original 2xx DELETE "
                                "returned 404/410 on clean replay with corroborating prior/control state."
                            ),
                            mode=self.mode,
                            stages=stages,
                            clean_replay_receipt_id=replay_rec["receipt_id"],
                            control_probe_receipt_id=ctrl_probe_rid,
                        )
        # Multi-step stateful workflow replay (up to 3 ordered precursor steps + dynamic ID substitution):
        # When direct single-step replay fails status or evidence verification (e.g. one-shot queue
        # drains, consumed tokens, or multi-step draft/order finalize chains returning 409/404),
        # replay the discovered precursor chain in fresh sessions, extract newly minted IDs, and
        # substitute old_id -> new_id cleanly into subsequent step URLs and bodies.
        target_method_upper = str(replay_target.get("method") or "GET").upper()
        single_step_status_failed = (
            not (200 <= r_status < 400) or (r_status // 100) != (t_status // 100)
        )
        single_step_evidence_failed = (
            200 <= r_status < 300
            and bool(ev)
            and not ev_in_oob
            and (
                (canonical_class == "stored_xss" and not receipt_body_contains_verbatim(replay_rec, ev))
                or (
                    canonical_class != "stored_xss"
                    and not _receipt_contains_evidence(replay_rec, ev, canonical_class=canonical_class)
                )
            )
        )
        single_step_needs_multistep = (
            not has_redacted_auth_override
            and target_method_upper != "DELETE"
            and canonical_class not in {"open_redirect", "cors_misconfiguration", "weak_credentials"}
            and 200 <= t_status < 400
            and (single_step_status_failed or single_step_evidence_failed)
        )
        if single_step_needs_multistep:
            precursor_chain = _discover_precursor_chain(
                replay_target,
                [*proof_receipts, *(setup_receipts or ())],
                self.receipts,
                allowed_methods=self.http.allowed_methods,
                resolve_scope_fn=self.http.resolve_in_scope,
                max_precursors=_MAX_MULTISTEP_PRECURSORS,
            )
            if precursor_chain:
                attempted_precursor_chain = True
                total_chain_steps = len(precursor_chain) + 1
                if not self._has_budget(total_chain_steps):
                    if total_chain_steps >= 3 or target_method_upper != "GET":
                        stages["stage3_clean_replay"] = "failed_multistep_budget"
                        stages["stage3_multistep_count"] = total_chain_steps
                        return OracleVerdict(
                            verified=False,
                            verdict="REFUTED",
                            reason=(
                                f"Multi-step replay requires {total_chain_steps} HTTP requests "
                                f"({len(precursor_chain)} precursor step(s) + final step), "
                                "but remaining budget is insufficient."
                            ),
                            mode=self.mode,
                            stages=stages,
                            clean_replay_receipt_id=replay_rec["receipt_id"],
                            control_probe_receipt_id=ctrl_probe_rid,
                        )
                else:
                    id_map: dict[str, str] = {}
                    replayed_rids: list[str] = []
                    all_chain_steps = [*precursor_chain, replay_target]
                    precursor_failed = False
                    failed_step_num = 0
                    failed_step_status = 0
                    failed_step_rid = ""

                    for step_idx, orig_step in enumerate(precursor_chain):
                        sub_url, sub_body = _apply_id_substitutions_to_request(
                            str(orig_step.get("url") or "/"),
                            str(orig_step.get("request_body") or ""),
                            id_map,
                        )
                        step_method = str(orig_step.get("method") or "POST").upper()
                        try:
                            step_replay_rec = self._run_clean_session_request(
                                actor=str(orig_step.get("actor") or "anon"),
                                method=step_method,
                                url=sub_url,
                                headers=orig_step.get("request_headers") or {},
                                raw_body=sub_body,
                            )
                        except (BudgetExhaustedError, ValueError):
                            precursor_failed = True
                            failed_step_num = step_idx + 1
                            break

                        step_status = int(step_replay_rec.get("status") or 0)
                        step_rid = str(step_replay_rec.get("receipt_id") or "")
                        if not (200 <= step_status < 400):
                            precursor_failed = True
                            failed_step_num = step_idx + 1
                            failed_step_status = step_status
                            failed_step_rid = step_rid
                            break

                        if step_rid:
                            replayed_rids.append(step_rid)
                        new_subs = _extract_minted_id_substitutions(
                            orig_step,
                            step_replay_rec,
                            all_chain_steps[step_idx + 1 :],
                        )
                        if new_subs:
                            id_map.update(new_subs)

                    if precursor_failed:
                        stages["stage3_clean_replay"] = (
                            f"failed_multistep_precursor_{failed_step_status}"
                            if failed_step_status > 0
                            else "failed_multistep_precursor"
                        )
                        stages["stage3_multistep_count"] = total_chain_steps
                        stages["stage3_multistep_failed_step"] = failed_step_num
                        if replayed_rids:
                            stages["stage3_precursor_replay_receipt_ids"] = replayed_rids
                        return OracleVerdict(
                            verified=False,
                            verdict="REFUTED",
                            reason=(
                                f"Multi-step replay precursor step {failed_step_num}/{total_chain_steps} "
                                f"failed with status {failed_step_status}."
                            ),
                            mode=self.mode,
                            stages=stages,
                            clean_replay_receipt_id=failed_step_rid or replay_rec["receipt_id"],
                            control_probe_receipt_id=ctrl_probe_rid,
                        )

                    final_url, final_body = _apply_id_substitutions_to_request(
                        str(replay_target.get("url") or "/"),
                        str(replay_target.get("request_body") or ""),
                        id_map,
                    )
                    try:
                        final_replay_rec = self._run_clean_session_request(
                            actor=str(replay_target.get("actor") or "anon"),
                            method=target_method_upper,
                            url=final_url,
                            headers=replay_target.get("request_headers") or {},
                            raw_body=final_body,
                        )
                    except (BudgetExhaustedError, ValueError):
                        final_replay_rec = None

                    if final_replay_rec is not None:
                        replay_rec = final_replay_rec
                        r_status = int(final_replay_rec.get("status") or 0)
                        if total_chain_steps == 2:
                            replayed_via_two_step = True
                            two_step_setup_rid = replayed_rids[0] if replayed_rids else ""
                        else:
                            replayed_via_multistep = True
                            multistep_step_count = total_chain_steps
                            multistep_precursor_rids = replayed_rids
                            multistep_substitutions = dict(id_map)

        # Case B — Single-use POST create conflict verification:
        # When re-executing a 200/201 POST returns 409 Conflict (or 400/422
        # with an explicit duplicate/conflict/already-redeemed indicator) because the resource
        # or one-shot action was already consumed by the original request, verify after Stages 1-2 passed.
        if (
            not attempted_precursor_chain
            and not has_redacted_auth_override
            and replay_target is primary_proof
            and str(primary_proof.get("method") or "").upper() == "POST"
            and t_status in {200, 201}
            and canonical_class not in {"open_redirect", "cors_misconfiguration", "weak_credentials"}
            and _is_one_shot_create_conflict(replay_rec)
            and (
                not ev
                or ev_in_oob
                or _receipt_contains_evidence(primary_proof, ev, canonical_class=canonical_class)
            )
        ):
            stages["stage3_clean_replay"] = "passed_one_shot_create_conflict"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason=(
                    f"Verified one-shot POST create state transition: original {t_status} POST "
                    f"returned {r_status} conflict/duplicate on clean-session replay."
                ),
                mode=self.mode,
                stages=stages,
                clean_replay_receipt_id=replay_rec["receipt_id"],
                control_probe_receipt_id=ctrl_probe_rid,
            )
        # Stateful persistence fallback: when re-executing a non-idempotent write as
        # the original actor returns 403/404/409 (e.g. ownership/tenant already moved),
        # check previously-denied control actors on the same path and (when evidence is
        # specified) up to 2 distinct-tenant/admin actors from the harness roster to
        # verify the mutated state persisted in a fresh clean session.
        elif (
            not attempted_precursor_chain
            and not has_redacted_auth_override
            and replay_target is primary_proof
            and str(primary_proof.get("method") or "").upper() in _WRITE_METHODS
            and (r_status in {403, 404, 409} or _is_graphql_error_envelope(replay_rec))
            and self._has_budget(1)
        ):
            p_url_str = str(primary_proof.get("url") or primary_proof.get("path") or "")
            p_origin = _extract_origin(p_url_str)
            p_path = urlsplit(p_url_str).path.rstrip("/")
            actor_rows = list(self.http.actors.summaries())
            actor_by_alias = {str(a.get("alias") or ""): a for a in actor_rows}
            p_tenant = str((actor_by_alias.get(p_actor) or {}).get("tenant") or "").strip().lower()

            fallback_actors: list[str] = []
            for ctrl in eff_controls:
                c_actor = str(ctrl.get("actor") or "")
                c_url_str = str(ctrl.get("url") or ctrl.get("path") or "")
                c_origin = _extract_origin(c_url_str)
                c_path = urlsplit(c_url_str).path.rstrip("/")
                if (
                    c_actor
                    and c_actor != p_actor
                    and c_actor in actor_by_alias
                    and c_actor not in fallback_actors
                    and _is_denied_control_receipt(ctrl)
                    and c_path == p_path
                    and not (p_origin and c_origin and p_origin != c_origin)
                ):
                    fallback_actors.append(c_actor)

            if ev:
                roster_candidates = [
                    a
                    for a in actor_rows
                    if str(a.get("alias") or "") not in {"", "anon", p_actor}
                    and str(a.get("alias") or "") not in fallback_actors
                ]
                roster_candidates.sort(
                    key=lambda a: (
                        1 if (p_tenant and str(a.get("tenant") or "").strip().lower() not in {"", p_tenant}) else 0,
                        1 if "admin" in str(a.get("role") or "").lower() else 0,
                    ),
                    reverse=True,
                )
                for row in roster_candidates[:2]:
                    fallback_actors.append(str(row.get("alias") or ""))

            for fb_actor in fallback_actors[:3]:
                if not self._has_budget(1):
                    break
                try:
                    fb_rec = self._run_clean_session_request(
                        actor=fb_actor,
                        method="GET",
                        url=str(primary_proof.get("url") or "/"),
                    )
                except BudgetExhaustedError:
                    break
                fb_status = int(fb_rec.get("status") or 0)
                if (
                    200 <= fb_status < 300
                    and not _is_graphql_error_envelope(fb_rec)
                    and _receipt_contains_evidence(fb_rec, ev, canonical_class=canonical_class)
                ):
                    replay_rec = fb_rec
                    r_status = fb_status
                    t_status = 200
                    replayed_via_stateful_fallback = True
                    break

        if not (200 <= r_status < 400) or (r_status // 100) != (t_status // 100):
            stages["stage3_clean_replay"] = f"failed_status_{r_status}"
            return OracleVerdict(
                verified=False,
                verdict="REFUTED",
                reason=f"Clean-session replay returned status {r_status} (expected {t_status // 100}xx).",
                mode=self.mode,
                stages=stages,
                clean_replay_receipt_id=replay_rec["receipt_id"],
                control_probe_receipt_id=ctrl_probe_rid,
            )

        if not _is_graphql_error_envelope(replay_target) and _is_graphql_error_envelope(replay_rec):
            stages["stage3_clean_replay"] = "failed_graphql_error_envelope"
            return OracleVerdict(
                verified=False,
                verdict="REFUTED",
                reason="Clean-session replay returned a GraphQL error-only envelope.",
                mode=self.mode,
                stages=stages,
                clean_replay_receipt_id=replay_rec["receipt_id"],
                control_probe_receipt_id=ctrl_probe_rid,
            )

        if canonical_class == "open_redirect":
            orig_host = urlsplit(str(replay_target.get("redirect_location") or "")).netloc
            rep_host = urlsplit(str(replay_rec.get("redirect_location") or "")).netloc
            if not rep_host or rep_host != orig_host:
                stages["stage3_clean_replay"] = "failed_redirect_host"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="Clean-session replay did not reproduce external redirect Location host.",
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=replay_rec["receipt_id"],
                    control_probe_receipt_id=ctrl_probe_rid,
                )
        elif canonical_class == "cors_misconfiguration":
            orig_acao = _response_header_ci(replay_target, "access-control-allow-origin")
            rep_acao = _response_header_ci(replay_rec, "access-control-allow-origin")
            proof_origin = _request_header_ci(replay_target, "origin")
            valid_acao = bool(
                orig_acao
                and rep_acao
                and rep_acao.lower() == orig_acao.lower()
                and (rep_acao == "*" or (bool(proof_origin) and rep_acao.lower() == proof_origin.lower()))
            )
            if not valid_acao:
                stages["stage3_clean_replay"] = "failed_cors_origin"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason=(
                        "Clean-session replay did not reproduce Access-Control-Allow-Origin "
                        "matching proof (* or reflected Origin)."
                    ),
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=replay_rec["receipt_id"],
                    control_probe_receipt_id=ctrl_probe_rid,
                )
        elif canonical_class == "stored_xss":
            if not is_html_receipt(replay_rec):
                stages["stage3_clean_replay"] = "failed_non_html_replay"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="Clean-session GET replay did not return HTML (text/html) content-type.",
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=replay_rec["receipt_id"],
                    control_probe_receipt_id=ctrl_probe_rid,
                )
            if ev and not receipt_body_contains_verbatim(replay_rec, ev):
                stages["stage3_clean_replay"] = "failed_missing_evidence"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="Clean-session GET replay did not persist unescaped evidence_value in HTML body.",
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=replay_rec["receipt_id"],
                    control_probe_receipt_id=ctrl_probe_rid,
                )
        elif canonical_class == "weak_credentials":
            orig_loc = str(replay_target.get("redirect_location") or "")
            rep_loc = str(replay_rec.get("redirect_location") or "")
            if 300 <= t_status < 400 and orig_loc:
                if (
                    urlsplit(rep_loc).netloc != urlsplit(orig_loc).netloc
                    or _norm_url_path(rep_loc) != _norm_url_path(orig_loc)
                ):
                    stages["stage3_clean_replay"] = "failed_login_redirect_mismatch"
                    return OracleVerdict(
                        verified=False,
                        verdict="REFUTED",
                        reason="Clean-session login replay did not reproduce expected authenticated redirect destination.",
                        mode=self.mode,
                        stages=stages,
                        clean_replay_receipt_id=replay_rec["receipt_id"],
                        control_probe_receipt_id=ctrl_probe_rid,
                    )
            if (
                any(_weak_credentials_controls_equivalent(ctrl, replay_rec, ev=ev) for ctrl in eff_controls)
                and not _weak_credentials_controls_equivalent(replay_target, replay_rec, ev=ev)
            ):
                stages["stage3_clean_replay"] = "failed_replay_matched_control"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="Clean-session login replay matched failed-login control instead of authenticated proof.",
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=replay_rec["receipt_id"],
                    control_probe_receipt_id=ctrl_probe_rid,
                )
            if ev and not _weak_credentials_replay_matches_evidence(ev, replay_target, replay_rec):
                stages["stage3_clean_replay"] = "failed_missing_evidence"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="Clean-session login replay did not reproduce claimed evidence or session behavior.",
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=replay_rec["receipt_id"],
                    control_probe_receipt_id=ctrl_probe_rid,
                )
        else:
            if ev and not _receipt_contains_evidence(replay_rec, ev, canonical_class=canonical_class):
                if not ev_in_oob:
                    if _detect_ephemeral_evidence_mismatch(ev, replay_target, replay_rec):
                        return OracleVerdict(
                            verified=False,
                            verdict="REFUTED",
                            reason=(
                                "Clean-session replay reproduced the same response structure, "
                                "but evidence_value appears to be a per-request dynamic/ephemeral ID "
                                "(UUID/event_id/request_id) that changes on every request; re-submit "
                                "with a static or structural evidence_value from the response body instead."
                            ),
                            mode=self.mode,
                            stages={**stages, "stage3_clean_replay": "failed_ephemeral_evidence"},
                            clean_replay_receipt_id=replay_rec["receipt_id"],
                            control_probe_receipt_id=ctrl_probe_rid,
                        )
                    stages["stage3_clean_replay"] = "failed_missing_evidence"
                    return OracleVerdict(
                        verified=False,
                        verdict="REFUTED",
                        reason="Clean-session replay did not reproduce the claimed evidence_value.",
                        mode=self.mode,
                        stages=stages,
                        clean_replay_receipt_id=replay_rec["receipt_id"],
                        control_probe_receipt_id=ctrl_probe_rid,
                    )

        if replayed_via_multistep:
            stages["stage3_clean_replay"] = "passed_multistep_replay"
            stages["stage3_multistep_count"] = multistep_step_count
            if multistep_precursor_rids:
                stages["stage3_precursor_replay_receipt_ids"] = multistep_precursor_rids
            if multistep_substitutions:
                stages["stage3_id_substitutions"] = dict(multistep_substitutions)
        elif replayed_via_two_step:
            stages["stage3_clean_replay"] = "passed_two_step_replay"
            if two_step_setup_rid:
                stages["stage3_setup_replay_receipt_id"] = two_step_setup_rid
        elif is_oob_verified:
            stages["stage3_clean_replay"] = "passed_oob_verified"
        elif replayed_via_stateful_fallback:
            stages["stage3_clean_replay"] = "passed_stateful_persistence"
        else:
            stages["stage3_clean_replay"] = "passed"
        if replayed_via_multistep:
            verdict_reason = (
                f"Verified across control baseline, masked structural diff, and "
                f"{multistep_step_count}-step stateful clean-session replay."
            )
        elif replayed_via_two_step:
            verdict_reason = "Verified across control baseline, masked structural diff, and two-step clean-session replay."
        else:
            verdict_reason = "Verified across control baseline, masked structural diff, and isolated clean-session replay."
        return OracleVerdict(
            verified=True,
            verdict="VERIFIED",
            reason=verdict_reason,
            mode=self.mode,
            stages=stages,
            clean_replay_receipt_id=replay_rec["receipt_id"],
            control_probe_receipt_id=ctrl_probe_rid,
        )
