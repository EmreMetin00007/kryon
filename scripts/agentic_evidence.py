"""Pure evidence extraction, specificity scoring, actor ranking, and finding deduplication."""
from __future__ import annotations

import copy
import json
import math
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from agentic_oracle import is_html_receipt, is_persistent_read_path_related
from agentic_receipts import ReceiptStore

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

_TRIVIAL_EVIDENCE = frozenset({"200", "201", "204", "302", "ok", "true", "false", "success", "null", "none"})
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
    "cors": "cors_misconfiguration",
    "cors_reflection": "cors_misconfiguration",
    "arbitrary_origin_cors": "cors_misconfiguration",
    "xml_external_entity": "xxe",
    "blind_xxe": "xxe",
    "unrestricted_file_upload": "file_upload",
    "arbitrary_file_upload": "file_upload",
    "file_overwrite": "file_upload",
    "weak_jwt": "jwt_weakness",
    "jwt_none_alg": "jwt_weakness",
    "jwt_forgery": "jwt_weakness",
    "token_weakness": "jwt_weakness",
    "os_command_injection": "command_injection",
    "rce": "command_injection",
    "lfi": "path_traversal",
    "directory_traversal": "path_traversal",
    "arbitrary_file_read": "path_traversal",
    "arbitrary_file_delete": "path_traversal",
    "deserialization": "insecure_deserialization",
    "unsafe_deserialization": "insecure_deserialization",
    "object_deserialization": "insecure_deserialization",
    "node_serialize": "insecure_deserialization",
    "pickle_deserialization": "insecure_deserialization",
    "java_deserialization": "insecure_deserialization",
    "php_deserialization": "insecure_deserialization",
    "default_credentials": "weak_credentials",
    "default_creds": "weak_credentials",
    "default_password": "weak_credentials",
    "weak_password": "weak_credentials",
    "weak_creds": "weak_credentials",
}
_READ_SQLI_HINTS = ("order by", "order_by", "sort", "read", "differential", "boolean", "error-based", "error based", "case when")
_ADMIN_ROLE_TOKENS = ("admin", "superadmin", "administrator", "root", "superuser", "sysadmin", "staff")
_READONLY_ROLES = frozenset({"viewer", "readonly", "read_only", "guest", "auditor", "observer"})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_READ_METHODS = frozenset({"GET", "HEAD"})
# Overlapping state-tampering family specificity rank (lower value = higher specificity).
_STATE_TAMPERING_CLASS_RANK: dict[str, int] = {
    "mass_assignment": 0,
    "auth_bypass": 1,
    "business_logic": 2,
    "other": 3,
}
_STATE_TAMPERING_CONTROL_CLASSES = frozenset({"mass_assignment", "business_logic"})
# Classes whose root cause is orthogonal to generic HTTP body disclosures on the same method
# unless they explicitly share proof or control receipts.
_OTHER_RECEIPT_ONLY_CLASSES = frozenset({"cors_misconfiguration", "race_condition"})


def _norm_path(url_or_path: str) -> str:
    """Normalize a URL or path string to a lowercase path without trailing slash."""
    parsed = urlsplit(str(url_or_path or ""))
    path = parsed.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return path.lower()


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


def _finding_actor(
    entry: dict[str, Any],
    *,
    receipt_store: ReceiptStore | None = None,
) -> str:
    """Return the normalized primary actor alias for a finding entry."""
    direct = str(entry.get("actor") or entry.get("actor_alias") or "").strip()
    if direct:
        return direct
    for actor in (entry.get("supporting_actors") or []):
        clean = str(actor or "").strip()
        if clean:
            return clean
    if receipt_store is not None:
        for rid in (entry.get("proof_receipt_ids") or []):
            try:
                rec = receipt_store.get(str(rid))
            except (KeyError, ValueError):
                continue
            rec_actor = str(rec.get("actor") or "").strip()
            if rec_actor:
                return rec_actor
    for ex in (entry.get("evidence_excerpts") or []):
        if isinstance(ex, dict):
            ex_actor = str(ex.get("actor") or "").strip()
            if ex_actor:
                return ex_actor
    return ""


def _collect_finding_receipt_meta(
    entry: dict[str, Any],
    *,
    is_control: bool,
    receipt_store: ReceiptStore | None = None,
) -> list[tuple[str, str, int]]:
    """Extract `(METHOD, url_or_path, status)` tuples for proof or control receipts of a finding."""
    id_field = "control_receipt_ids" if is_control else "proof_receipt_ids"
    excerpt_field = "control_excerpts" if is_control else "evidence_excerpts"
    rids = [str(r).strip() for r in (entry.get(id_field) or []) if str(r).strip()]
    excerpts_by_id: dict[str, dict[str, Any]] = {}
    fallback_excerpts: list[dict[str, Any]] = []
    for ex in (entry.get(excerpt_field) or []):
        if not isinstance(ex, dict):
            continue
        fallback_excerpts.append(ex)
        ex_rid = str(ex.get("receipt_id") or "").strip()
        if ex_rid:
            excerpts_by_id[ex_rid] = ex

    meta: list[tuple[str, str, int]] = []
    seen_rids: set[str] = set()
    for rid in rids:
        if rid in seen_rids:
            continue
        seen_rids.add(rid)
        rec: dict[str, Any] | None = None
        if receipt_store is not None:
            try:
                rec = receipt_store.get(rid)
            except (KeyError, ValueError):
                rec = None
        if rec is None:
            rec = excerpts_by_id.get(rid)
        if rec is None:
            continue
        m = str(rec.get("method") or "").strip().upper()
        u = str(rec.get("url") or rec.get("path") or "").strip()
        try:
            st = int(rec.get("status") or 0)
        except (TypeError, ValueError):
            st = 0
        if m or u:
            meta.append((m, u, st))

    if not meta:
        for ex in fallback_excerpts:
            m = str(ex.get("method") or "").strip().upper()
            u = str(ex.get("url") or ex.get("path") or "").strip()
            try:
                st = int(ex.get("status") or 0)
            except (TypeError, ValueError):
                st = 0
            if m or u:
                meta.append((m, u, st))

    if not meta and not is_control:
        m = str(entry.get("method") or "").strip().upper()
        u = str(entry.get("url") or entry.get("path") or "").strip()
        try:
            st = int(entry.get("observed_status") or 0)
        except (TypeError, ValueError):
            st = 0
        if m or u:
            meta.append((m, u, st))
    return meta


def _url_related_to_route(url_or_path: str, route_template: str) -> bool:
    """Return True if `url_or_path` maps to `route_template` or is persistently path-related to it."""
    if not url_or_path or not route_template:
        return False
    if normalize_route_template(url_or_path) == route_template:
        return True
    return is_persistent_read_path_related(url_or_path, route_template)


def _extract_write_read_pairs(
    proof_meta: list[tuple[str, str, int]],
    route_template: str,
) -> set[tuple[str, str]]:
    """Return `(WRITE_METHOD, READ_METHOD)` pairs observed on `route_template` (or related paths)."""
    write_methods = {
        m
        for m, u, _ in proof_meta
        if m in _MUTATING_METHODS and (not u or _url_related_to_route(u, route_template))
    }
    read_methods = {
        m
        for m, u, _ in proof_meta
        if m in _READ_METHODS and (not u or _url_related_to_route(u, route_template))
    }
    return {(w, r) for w in write_methods for r in read_methods}


def _has_baseline_read_control(
    ctrl_meta: list[tuple[str, str, int]],
    route_template: str,
) -> bool:
    """Return True if controls include a GET/HEAD baseline receipt on `route_template`."""
    return any(
        m in _READ_METHODS and (not u or _url_related_to_route(u, route_template))
        for m, u, _ in ctrl_meta
    )


def _has_same_http_method_surface(
    entry_a: dict[str, Any],
    proof_meta_a: list[tuple[str, str, int]],
    entry_b: dict[str, Any],
    proof_meta_b: list[tuple[str, str, int]],
    route_template: str,
) -> bool:
    """Return True when two findings exercise the same underlying HTTP method or write-read surface."""
    wr_a = _extract_write_read_pairs(proof_meta_a, route_template)
    wr_b = _extract_write_read_pairs(proof_meta_b, route_template)
    if wr_a or wr_b:
        return bool(wr_a & wr_b)

    methods_a = {m for m, _, _ in proof_meta_a if m}
    if not methods_a:
        m_a = str(entry_a.get("method") or "").strip().upper()
        if m_a:
            methods_a.add(m_a)
    methods_b = {m for m, _, _ in proof_meta_b if m}
    if not methods_b:
        m_b = str(entry_b.get("method") or "").strip().upper()
        if m_b:
            methods_b.add(m_b)
    if not methods_a or not methods_b or methods_a != methods_b:
        return False

    status_fam_a = {st // 100 for _, _, st in proof_meta_a if st >= 100}
    status_fam_b = {st // 100 for _, _, st in proof_meta_b if st >= 100}
    if status_fam_a and status_fam_b and not (status_fam_a & status_fam_b):
        return False

    if methods_a <= _READ_METHODS:
        qkeys_a = frozenset(
            k.strip().lower()
            for _, u, _ in proof_meta_a
            for k, _ in parse_qsl(urlsplit(u).query, keep_blank_values=True)
            if k.strip()
        )
        qkeys_b = frozenset(
            k.strip().lower()
            for _, u, _ in proof_meta_b
            for k, _ in parse_qsl(urlsplit(u).query, keep_blank_values=True)
            if k.strip()
        )
        if qkeys_a != qkeys_b:
            return False

    return True


def _resolve_cross_class_overlap(
    entry_a: dict[str, Any],
    entry_b: dict[str, Any],
    *,
    receipt_store: ReceiptStore | None = None,
) -> tuple[str, int] | None:
    """Resolve root-cause cross-class overlap on the same `(route_template, actor)`.

    Returns `(winning_class, match_priority)` (lower priority = stronger match) when `entry_a`
    and `entry_b` represent the same underlying vulnerability reported under overlapping classes,
    or `None` when they represent distinct vulnerabilities that must remain separate.
    """
    cls_a = str(entry_a.get("class_type") or "").strip().lower()
    cls_b = str(entry_b.get("class_type") or "").strip().lower()
    if not cls_a or not cls_b or cls_a == cls_b or {cls_a, cls_b} == {"auth_bypass", "bfla"}:
        return None

    tmpl_a = str(
        entry_a.get("route_template")
        or normalize_route_template(str(entry_a.get("url") or entry_a.get("path") or ""))
    )
    tmpl_b = str(
        entry_b.get("route_template")
        or normalize_route_template(str(entry_b.get("url") or entry_b.get("path") or ""))
    )
    if not tmpl_a or tmpl_a != tmpl_b:
        return None

    actor_a = _finding_actor(entry_a, receipt_store=receipt_store)
    actor_b = _finding_actor(entry_b, receipt_store=receipt_store)
    if not actor_a or actor_a != actor_b:
        return None

    proof_ids_a = {str(r).strip() for r in (entry_a.get("proof_receipt_ids") or []) if str(r).strip()}
    proof_ids_b = {str(r).strip() for r in (entry_b.get("proof_receipt_ids") or []) if str(r).strip()}
    ctrl_ids_a = {str(r).strip() for r in (entry_a.get("control_receipt_ids") or []) if str(r).strip()}
    ctrl_ids_b = {str(r).strip() for r in (entry_b.get("control_receipt_ids") or []) if str(r).strip()}
    shares_proof = bool(proof_ids_a & proof_ids_b)
    shares_control = bool(ctrl_ids_a & ctrl_ids_b)

    # Rule 1: Generic `other` subsumption on the same (route_template, actor).
    if "other" in {cls_a, cls_b}:
        specific_cls = cls_b if cls_a == "other" else cls_a
        if shares_proof:
            return specific_cls, 1
        if shares_control:
            return specific_cls, 2
        if specific_cls not in _OTHER_RECEIPT_ONLY_CLASSES:
            proof_meta_a = _collect_finding_receipt_meta(entry_a, is_control=False, receipt_store=receipt_store)
            proof_meta_b = _collect_finding_receipt_meta(entry_b, is_control=False, receipt_store=receipt_store)
            if _has_same_http_method_surface(entry_a, proof_meta_a, entry_b, proof_meta_b, tmpl_a):
                return specific_cls, 3
        return None

    # Rule 2a: Overlapping state-tampering family (`mass_assignment` vs `business_logic`).
    if {cls_a, cls_b} == _STATE_TAMPERING_CONTROL_CLASSES:
        winner = "mass_assignment"
        if shares_proof:
            return winner, 1
        if shares_control:
            return winner, 2
        proof_meta_a = _collect_finding_receipt_meta(entry_a, is_control=False, receipt_store=receipt_store)
        proof_meta_b = _collect_finding_receipt_meta(entry_b, is_control=False, receipt_store=receipt_store)
        wr_a = _extract_write_read_pairs(proof_meta_a, tmpl_a)
        wr_b = _extract_write_read_pairs(proof_meta_b, tmpl_a)
        if wr_a & wr_b:
            ctrl_meta_a = _collect_finding_receipt_meta(entry_a, is_control=True, receipt_store=receipt_store)
            ctrl_meta_b = _collect_finding_receipt_meta(entry_b, is_control=True, receipt_store=receipt_store)
            if _has_baseline_read_control(ctrl_meta_a, tmpl_a) and _has_baseline_read_control(ctrl_meta_b, tmpl_a):
                return winner, 3
        return None

    # Rule 2b: `auth_bypass` overlapping with `mass_assignment` or `business_logic` on shared proofs
    # (or shared control + identical HTTP method/write-read surface).
    if "auth_bypass" in {cls_a, cls_b} and ({cls_a, cls_b} - {"auth_bypass"}) <= _STATE_TAMPERING_CONTROL_CLASSES:
        winner = cls_a if _STATE_TAMPERING_CLASS_RANK[cls_a] < _STATE_TAMPERING_CLASS_RANK[cls_b] else cls_b
        if shares_proof:
            return winner, 1
        if shares_control:
            proof_meta_a = _collect_finding_receipt_meta(entry_a, is_control=False, receipt_store=receipt_store)
            proof_meta_b = _collect_finding_receipt_meta(entry_b, is_control=False, receipt_store=receipt_store)
            if _has_same_http_method_surface(entry_a, proof_meta_a, entry_b, proof_meta_b, tmpl_a):
                return winner, 2
        return None

    # Rule 2c: `race_condition` vs `business_logic` stays distinct unless exact same proof receipts.
    if {cls_a, cls_b} == {"race_condition", "business_logic"}:
        if proof_ids_a and proof_ids_a == proof_ids_b:
            return "race_condition", 1
        return None

    return None


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
        if not str(existing.get("clean_replay_receipt_id") or "").strip():
            in_replay = str(incoming.get("clean_replay_receipt_id") or "").strip()
            if in_replay:
                existing["clean_replay_receipt_id"] = in_replay

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

    # Resolve cross-class root-cause duplicates on the same (route_template, actor)
    # (Rule 1: `other` subsumption; Rule 2: state-tampering family & identical-proof race/logic overlap).
    cross_changed = True
    while cross_changed:
        cross_changed = False
        by_route: dict[str, list[tuple[str, str]]] = {}
        for k in order:
            by_route.setdefault(k[0], []).append(k)

        for route_keys in by_route.values():
            if len(route_keys) < 2:
                continue
            best_merge: tuple[int, int, tuple[str, str], tuple[str, str]] | None = None
            for i in range(len(route_keys)):
                k1 = route_keys[i]
                if k1 not in grouped:
                    continue
                for j in range(i + 1, len(route_keys)):
                    k2 = route_keys[j]
                    if k2 not in grouped:
                        continue
                    overlap = _resolve_cross_class_overlap(
                        grouped[k1],
                        grouped[k2],
                        receipt_store=receipt_store,
                    )
                    if overlap is None:
                        continue
                    winner_cls, match_prio = overlap
                    is_other_pair = 1 if ("other" in {k1[1], k2[1]}) else 0
                    winner_key = k1 if k1[1] == winner_cls else k2
                    loser_key = k2 if winner_key == k1 else k1
                    cand = (is_other_pair, match_prio, winner_key, loser_key)
                    if best_merge is None or cand[:2] < best_merge[:2]:
                        best_merge = cand
            if best_merge is not None:
                _, _, winner_key, loser_key = best_merge
                _merge_entries(grouped[winner_key], grouped[loser_key])
                del grouped[loser_key]
                order = [k for k in order if k != loser_key]
                cross_changed = True
                break

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
