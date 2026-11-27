#!/usr/bin/env python3
"""Canonical multi-origin Site Map reconciler and `cco-agent map` CLI.

Purely offline (0 network requests) reconciliation of receipts, seed surfaces,
Stage 0 browser crawl outputs, HAR multi-step flows, recon AssetGraphs,
deterministic prescan leads, and `SurfaceFrontierTracker` state into one
scope-filtered, secret-redacted `cco-surface-map/1` artifact (`surface-map.json`
+ `surface-map.md`).
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import errno
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

_REPO_ROOT = _SCRIPTS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agentic_http import is_static_asset_url  # noqa: E402
from agentic_surface import (  # noqa: E402
    _extract_graphql_op_name,
    _fit_body_template_budget,
    _is_secret_key,
    _sanitize_json_template,
    is_high_risk_param_name,
    route_template_of,
)
from agentic_waf import detect_waf_block  # noqa: E402
from target_bootstrap import (  # noqa: E402
    ScopeGuard,
    _canonicalize_host,
    _default_port,
    _extract_excluded_paths,
    _extract_scope_asset_lists,
    _is_loopback_host,
    _is_valid_host,
    _parse_scope_asset,
    load_scope_file,
    normalize_path,
    resolve_target_origin,
)
from tech_routes import detect_tech  # noqa: E402

SCHEMA = "cco-surface-map/1"

VALID_SOURCES: frozenset[str] = frozenset({
    "recon",
    "seed",
    "stage0",
    "har",
    "prescan",
    "tracker",
    "live",
})

_VALID_HTTP_METHODS: frozenset[str] = frozenset({
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
})
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_VALID_ROLES: frozenset[str] = frozenset({
    "api",
    "auth",
    "storefront",
    "admin",
    "graphql",
    "cdn",
    "unknown",
})
_LEAD_SEVERITY_RANK: dict[str, int] = {"high": 0, "medium": 1, "low": 2}

_MAX_FILE_BYTES = 20 * 1024 * 1024  # 20 MiB hard cap for offline JSON artifacts
_MAX_PARAMS_PER_ENDPOINT = 64
_MAX_HEADERS_PER_ENDPOINT = 16
_MAX_HEADER_VALUE_CHARS = 192
_MAX_TEMPLATE_DEPTH = 5
_MAX_TEMPLATE_KEYS = 24
_MAX_TEMPLATE_LIST = 6
_MAX_TEMPLATE_STR_LEN = 128

_CAMEL_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_SAFE_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]$]{1,64}$")
_GQL_OP_NAME_RE = re.compile(r"^[_A-Za-z][_0-9A-Za-z]{0,127}$")
_METHOD_TARGET_KEY_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)$",
    re.IGNORECASE,
)
_MULTIPART_CD_LINE_RE = re.compile(r"Content-Disposition\s*:\s*([^\r\n]+)", re.IGNORECASE)
_MULTIPART_NAME_RE = re.compile(
    r'(?:^|[;\s])name\s*=\s*(?:"([^"\r\n]{1,64})"|([^;\s\r\n]{1,64}))',
    re.IGNORECASE,
)
_MULTIPART_FILENAME_RE = re.compile(r"(?:^|[;\s])filename\*?\s*=", re.IGNORECASE)
_API_PATH_RE = re.compile(
    r"^/(?:(?:ajax[-_]?)?api(?:/v\d+(?:\.\d+)?)?|v\d+(?:\.\d+)?|rest|rpc|bff|graphql|gql)(?:/|$)",
    re.IGNORECASE,
)
_GRAPHQL_PATH_RE = re.compile(r"(?:^|/)(?:graphql|gql|graphiql)(?:/|$)", re.IGNORECASE)
_AUTH_PATH_RE = re.compile(
    r"^/(?:\.well-known/openid-configuration|oauth\d?/|oidc/|sso/|saml/|auth(?:/|$)|login(?:/|$)|signin(?:/|$))",
    re.IGNORECASE,
)
_ADMIN_PATH_RE = re.compile(r"^/(?:admin|administrator|backoffice|console|mgmt)(?:/|$)", re.IGNORECASE)

# Secret / sensitive value detectors (structured to stay clean under governance_audit).
_JWT_VALUE_RE = re.compile(
    r"(?:^|(?<![A-Za-z0-9_-]))eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*(?:$|(?![A-Za-z0-9_-]))"
)
_EMAIL_VALUE_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,128}\.[A-Za-z]{2,24}$")
_AWS_KEY_VALUE_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_KNOWN_TOKEN_VALUE_RE = re.compile(
    r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{12,}"
    r"|github_pat_[A-Za-z0-9_]{12,}"
    r"|sk_(?:live|test)_[0-9A-Za-z]{8,}"
    r"|xox[baprs]-[0-9A-Za-z-]{8,}"
    r"|AIza[0-9A-Za-z_-]{16,})\b"
)
_PRIVATE_KEY_MARKER_RE = re.compile(r"-----BEGIN\s+[A-Z0-9 ]+-----")
_COOKIE_PAIR_VALUE_RE = re.compile(
    r"(?:^|;\s*)[A-Za-z0-9_.-]{1,48}=[^;\s]{1,256}\s*;\s*"
    r"(?:[A-Za-z0-9_.-]{1,48}=[^;\s]{1,256}|(?:httponly|secure|samesite|path|domain|max-age|expires)\b)",
    re.IGNORECASE,
)

_STRIPPED_EXACT_HEADERS: frozenset[str] = frozenset({
    # Auth / session / CSRF / secret headers
    "authorization",
    "proxy-authorization",
    "cookie",
    "cookie2",
    "set-cookie",
    "set-cookie2",
    "x-api-key",
    "x-apikey",
    "api-key",
    "apikey",
    "x-auth-token",
    "auth-token",
    "x-access-token",
    "access-token",
    "x-token",
    "x-session-token",
    "x-api-token",
    "x-refresh-token",
    "x-csrf-token",
    "x-csrftoken",
    "x-xsrf-token",
    "x-csrf-token-next",
    "csrf-token",
    "xsrf-token",
    "x-auth",
    "x-session-id",
    "x-session",
    "x-user-token",
    "x-jwt",
    "x-bearer-token",
    "x-client-secret",
    "x-secret-key",
    "x-secret",
    "x-private-key",
    "x-signature",
    # Hop-by-hop / standard HTTP / browser boilerplate
    "host",
    "content-type",
    "content-length",
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "referer",
    "origin",
    "cache-control",
    "pragma",
    "priority",
    "dnt",
    "upgrade-insecure-requests",
    "if-modified-since",
    "if-none-match",
    "if-match",
    "if-unmodified-since",
    "range",
    "expect",
    # Dynamic tracing noise
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "traceparent",
    "tracestate",
    "x-amzn-trace-id",
    "x-cloud-trace-context",
})
_STRIPPED_HEADER_PREFIXES: tuple[str, ...] = ("sec-", "x-b3-", "x-amz-", ":")
_SECRET_HEADER_TOKENS: frozenset[str] = frozenset({
    "auth",
    "authorization",
    "token",
    "secret",
    "password",
    "passwd",
    "cookie",
    "jwt",
    "bearer",
    "apikey",
    "credential",
    "credentials",
    "private",
    "signature",
    "sig",
    "hmac",
    "session",
    "sessionid",
    "sid",
    "csrf",
    "xsrf",
    "otp",
    "pin",
    "key",
})
_SECRET_HEADER_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "apikey",
    "api_key",
    "csrf",
    "xsrf",
    "auth",
    "session",
    "jwt",
    "bearer",
    "credential",
    "private_key",
    "signature",
    "hmac",
)

_SENSITIVE_JSON_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "private_key",
    "privatekey",
    "access_key",
    "accesskey",
    "cookie",
    "jwt",
    "bearer",
    "card_number",
    "card_no",
    "credit_card",
    "phone_number",
    "csrf",
    "xsrf",
    "session",
    "signature",
    "hmac",
)
_SENSITIVE_JSON_TOKENS: frozenset[str] = frozenset({
    "pwd",
    "auth",
    "authorization",
    "csrf",
    "xsrf",
    "session",
    "session_id",
    "sessionid",
    "sid",
    "otp",
    "pin",
    "email",
    "e_mail",
    "mail",
    "phone",
    "mobile",
    "telephone",
    "tel",
    "card",
    "pan",
    "cvv",
    "cvc",
    "iban",
    "ssn",
    "signature",
    "sig",
    "hmac",
})

_ADMIN_RISK_TOKENS: frozenset[str] = frozenset({
    "admin",
    "administrator",
    "backoffice",
    "internal",
    "manage",
    "management",
    "mgmt",
    "console",
    "debug",
    "actuator",
    "config",
    "audit",
    "role",
    "roles",
    "permission",
    "permissions",
    "staff",
    "ops",
    "superuser",
})
_AUTH_RISK_TOKENS: frozenset[str] = frozenset({
    "auth",
    "oauth",
    "oauth2",
    "sso",
    "login",
    "signin",
    "signup",
    "register",
    "token",
    "refresh",
    "password",
    "passwd",
    "reset",
    "verify",
    "mfa",
    "otp",
    "session",
    "sessions",
    "account",
    "accounts",
    "user",
    "users",
    "profile",
    "profiles",
    "me",
})
_BUSINESS_RISK_TOKENS: frozenset[str] = frozenset({
    "checkout",
    "payment",
    "payments",
    "pay",
    "billing",
    "invoice",
    "invoices",
    "order",
    "orders",
    "cart",
    "basket",
    "wallet",
    "transfer",
    "refund",
    "coupon",
    "coupons",
    "promo",
    "voucher",
    "redeem",
    "upload",
    "uploads",
    "download",
    "downloads",
    "import",
    "export",
    "file",
    "files",
    "webhook",
    "webhooks",
    "proxy",
    "fetch",
    "redirect",
    "render",
    "template",
})
_LOW_SIGNAL_EXACT_PATHS: frozenset[str] = frozenset({
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/livez",
    "/ping",
})
_EXTRA_HIGH_RISK_PARAM_TOKENS: frozenset[str] = frozenset({
    "price",
    "total",
    "amount",
    "discount",
    "balance",
    "credit",
    "quantity",
    "qty",
    "role",
    "roles",
    "admin",
    "status",
    "permission",
    "permissions",
    "scope",
    "scopes",
    "user_id",
    "owner_id",
    "account_id",
    "tenant_id",
    "org_id",
    "order_id",
    "cart_id",
    "invoice_id",
    "coupon",
})
_HOST_ROLE_LABELS: tuple[tuple[str, frozenset[str]], ...] = (
    ("graphql", frozenset({"graphql", "gql"})),
    ("auth", frozenset({"auth", "oauth", "oauth2", "sso", "login", "signin", "idp", "identity", "accounts"})),
    ("admin", frozenset({"admin", "backoffice", "panel", "console", "internal", "manage", "mgmt", "staff", "ops"})),
    ("api", frozenset({"api", "bff", "sfapi", "rest", "rpc", "gateway", "gw", "backend", "service", "services"})),
    ("cdn", frozenset({"cdn", "static", "assets", "asset", "img", "images", "media", "js", "css", "fonts"})),
    ("storefront", frozenset({"www", "shop", "store", "web", "m", "catalog"})),
)


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ch == "\x7f" for ch in value)


def _sanitize_single_line(raw: Any, *, max_len: int = 160) -> str:
    text = re.sub(r"[\r\n\t\x00-\x1f\x7f]+", " ", str(raw or "")).strip()
    text = re.sub(r"\s{2,}", " ", text)
    return text[:max_len]


def _to_snake_tokens(name: str) -> tuple[str, list[str]]:
    snake = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", str(name or "")).strip().lower().replace("-", "_")
    tokens = [tok for tok in _TOKEN_SPLIT_RE.split(snake) if tok]
    return snake, tokens


def _format_origin(scheme: str, host: str, port: int) -> str:
    host_netloc = f"[{host}]" if ":" in host else host
    if port == _default_port(scheme):
        return f"{scheme}://{host_netloc}"
    return f"{scheme}://{host_netloc}:{port}"


def _filter_loopback_scope_assets(assets: Sequence[str] | Any) -> list[str]:
    """Keep strictly loopback-host entries from scope asset rules (fail-closed in loopback mode)."""
    if not isinstance(assets, (list, tuple)):
        return []
    out: list[str] = []
    for raw_entry in assets:
        entry = str(raw_entry or "").strip()
        if not entry:
            continue
        rule = _parse_scope_asset(entry)
        if rule is not None and rule.host_pattern and not rule.host_pattern.startswith("*.") and _is_loopback_host(rule.host_pattern):
            if entry not in out:
                out.append(entry)
    return out


def _normalize_base_origin(raw_url: str) -> str:
    """Normalize a base target URL (with or without path) to clean ``scheme://netloc/``."""
    raw = str(raw_url or "").strip()
    if not raw or any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise ValueError(f"invalid base_url: {raw_url!r}")
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"base_url must use http:// or https://: {raw_url!r}")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("base_url must not embed credentials")
    raw_host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not raw_host or not _is_valid_host(raw_host):
        raise ValueError(f"base_url has invalid hostname: {raw_url!r}")
    host = _canonicalize_host(raw_host)
    port_val = parsed.port
    if port_val is not None and not (1 <= port_val <= 65535):
        raise ValueError(f"base_url has invalid port: {raw_url!r}")
    eff_port = port_val if port_val is not None else _default_port(scheme)
    return _format_origin(scheme, host, eff_port) + "/"


def _coerce_status(raw: Any) -> int | None:
    if isinstance(raw, bool) or raw is None:
        return None
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return None
    return val if 100 <= val <= 599 else None


def _normalize_method(raw: Any, default: str = "GET") -> str:
    cleaned = str(raw or "").strip().upper()
    return cleaned if cleaned in _VALID_HTTP_METHODS else default


def _normalize_content_type(raw: Any) -> str:
    text = str(raw or "").split(";", 1)[0].strip().lower()
    if not text or "/" not in text or len(text) > 96 or _has_control_chars(text):
        return ""
    if any(ch.isspace() for ch in text):
        return ""
    return text


def _sanitize_param_name(raw: Any) -> str:
    name = str(raw or "").strip()
    if not name:
        return ""
    if name.startswith("path:"):
        name = name[5:].rstrip("=").strip()
    if not name or not _SAFE_PARAM_NAME_RE.fullmatch(name):
        return ""
    return name


def _is_graphql_path(path: str) -> bool:
    norm = str(path or "").strip().lower().rstrip("/")
    if not norm:
        return False
    return bool(_GRAPHQL_PATH_RE.search(norm))


def _is_secret_header_name(header_name: str) -> bool:
    low = header_name.strip().lower()
    if not low:
        return True
    if low in _STRIPPED_EXACT_HEADERS:
        return True
    if any(low.startswith(prefix) for prefix in _STRIPPED_HEADER_PREFIXES):
        return True
    snake, tokens = _to_snake_tokens(low)
    if snake in _SECRET_HEADER_TOKENS or any(tok in _SECRET_HEADER_TOKENS for tok in tokens):
        return True
    return any(sub in snake for sub in _SECRET_HEADER_SUBSTRINGS)


def _is_secret_value(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    low = stripped.lower()
    if "<redacted" in low:
        return True
    if low.startswith(("bearer ", "basic ", "digest ", "token ")) and len(stripped) > 8:
        return True
    if "aws4-hmac-sha256" in low:
        return True
    if _JWT_VALUE_RE.search(stripped):
        return True
    if _EMAIL_VALUE_RE.fullmatch(stripped):
        return True
    if _AWS_KEY_VALUE_RE.search(stripped) or _KNOWN_TOKEN_VALUE_RE.search(stripped):
        return True
    if _PRIVATE_KEY_MARKER_RE.search(stripped):
        return True
    if _COOKIE_PAIR_VALUE_RE.search(stripped):
        return True
    return False


def _sanitize_app_headers(raw_headers: Any) -> dict[str, str]:
    """Extract strictly non-secret, non-boilerplate application headers."""
    pairs: list[tuple[str, str]] = []
    if isinstance(raw_headers, dict):
        for k, v in raw_headers.items():
            if isinstance(k, str) and v is not None:
                pairs.append((k.strip(), str(v).strip()))
    elif isinstance(raw_headers, list):
        for item in raw_headers:
            if isinstance(item, dict):
                name = item.get("name")
                val = item.get("value")
                if isinstance(name, str) and val is not None:
                    pairs.append((name.strip(), str(val).strip()))

    cleaned: dict[str, str] = {}
    for name, value in pairs:
        if not name or _has_control_chars(name) or len(name) > 128:
            continue
        if not value or _has_control_chars(value):
            continue
        if _is_secret_header_name(name) or _is_secret_value(value):
            continue
        for existing in [ek for ek in cleaned if ek.lower() == name.lower() and ek != name]:
            cleaned.pop(existing, None)
        cleaned[name] = value[:_MAX_HEADER_VALUE_CHARS]
        if len(cleaned) >= _MAX_HEADERS_PER_ENDPOINT:
            break
    return dict(sorted(cleaned.items(), key=lambda kv: kv[0].lower()))


def _merge_app_headers(existing: dict[str, str], incoming: dict[str, str]) -> None:
    """Case-insensitively merge sanitized non-secret app headers into ``existing``."""
    for name, value in incoming.items():
        if not name or not value:
            continue
        for ek in [k for k in existing if k.lower() == name.lower() and k != name]:
            existing.pop(ek, None)
        if name in existing or len(existing) < _MAX_HEADERS_PER_ENDPOINT:
            existing[name] = value


def _is_sensitive_json_key(key: str) -> bool:
    if _is_secret_key(key):
        return True
    snake, tokens = _to_snake_tokens(key)
    if not snake:
        return False
    if any(sub in snake for sub in _SENSITIVE_JSON_SUBSTRINGS):
        return True
    return snake in _SENSITIVE_JSON_TOKENS or any(tok in _SENSITIVE_JSON_TOKENS for tok in tokens)


def _sanitize_json_value(obj: Any, *, depth: int = 0) -> Any:
    """Recursively redact secret/PII fields and secret-shaped string values."""
    if isinstance(obj, dict):
        if depth >= _MAX_TEMPLATE_DEPTH:
            return {}
        out: dict[str, Any] = {}
        for k, v in list(obj.items())[:_MAX_TEMPLATE_KEYS]:
            key_s = str(k)[:64]
            if not key_s:
                continue
            if _is_sensitive_json_key(key_s):
                out[key_s] = "<redacted>"
            else:
                out[key_s] = _sanitize_json_value(v, depth=depth + 1)
        return out
    if isinstance(obj, list):
        if depth >= _MAX_TEMPLATE_DEPTH:
            return []
        return [_sanitize_json_value(item, depth=depth + 1) for item in obj[:_MAX_TEMPLATE_LIST]]
    if isinstance(obj, str):
        if _is_secret_value(obj):
            return "<redacted>"
        if len(obj) > _MAX_TEMPLATE_STR_LEN:
            return obj[: _MAX_TEMPLATE_STR_LEN - 3] + "..."
        return obj
    if isinstance(obj, bool) or obj is None or isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else 0.0
    return str(obj)[:_MAX_TEMPLATE_STR_LEN]


def _sanitize_body_template(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict) or not raw:
        return None
    step1 = _sanitize_json_template(raw)
    step2 = _sanitize_json_value(step1)
    if not isinstance(step2, dict) or not step2:
        return None
    fitted = _fit_body_template_budget(step2)
    return fitted if isinstance(fitted, dict) and fitted else None


def _body_template_richness(doc: dict[str, Any]) -> tuple[int, int]:
    try:
        ser_len = len(json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    except (TypeError, ValueError):
        ser_len = 0
    return (len(doc), ser_len)


def _merge_body_templates(
    existing: dict[str, Any] | None,
    incoming: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if incoming is None:
        return existing
    if existing is None:
        return incoming
    if _body_template_richness(incoming) > _body_template_richness(existing):
        return incoming
    return existing


def _sanitize_multipart_schema(raw: Any) -> dict[str, list[str]] | None:
    if not isinstance(raw, dict):
        return None

    def _clean(items: Any) -> list[str]:
        if not isinstance(items, (list, tuple, set)):
            return []
        out: set[str] = set()
        for item in items:
            cand = item.get("name") if isinstance(item, dict) else (item if isinstance(item, str) else "")
            clean = _sanitize_param_name(cand)
            if clean:
                out.add(clean)
        return sorted(out)[:_MAX_PARAMS_PER_ENDPOINT]

    fields = _clean(raw.get("fields"))
    files = _clean(raw.get("files"))
    if not fields and not files:
        return None
    return {"fields": fields, "files": files}


def _merge_multipart_schemas(
    existing: dict[str, list[str]] | None,
    incoming: dict[str, list[str]] | None,
) -> dict[str, list[str]] | None:
    if incoming is None:
        return existing
    if existing is None:
        return incoming
    fields = sorted(set(existing.get("fields") or ()) | set(incoming.get("fields") or ()))[:_MAX_PARAMS_PER_ENDPOINT]
    files = sorted(set(existing.get("files") or ()) | set(incoming.get("files") or ()))[:_MAX_PARAMS_PER_ENDPOINT]
    if not fields and not files:
        return None
    return {"fields": fields, "files": files}


def _extract_multipart_from_text(body_text: str) -> dict[str, list[str]] | None:
    if not body_text or "Content-Disposition:" not in body_text:
        return None
    fields: set[str] = set()
    files: set[str] = set()
    for m in _MULTIPART_CD_LINE_RE.finditer(body_text[:16384]):
        line = m.group(1)
        nm = _MULTIPART_NAME_RE.search(line)
        if not nm:
            continue
        clean = _sanitize_param_name(nm.group(1) or nm.group(2) or "")
        if not clean:
            continue
        if _MULTIPART_FILENAME_RE.search(line):
            files.add(clean)
        else:
            fields.add(clean)
    if not fields and not files:
        return None
    return {"fields": sorted(fields)[:_MAX_PARAMS_PER_ENDPOINT], "files": sorted(files)[:_MAX_PARAMS_PER_ENDPOINT]}


def _extract_json_param_names(doc: Any, *, depth: int = 0) -> list[str]:
    if depth > 4:
        return []
    out: list[str] = []
    seen: set[str] = set()

    def _add(cand: Any) -> None:
        clean = _sanitize_param_name(cand)
        if clean and clean not in seen and len(out) < _MAX_PARAMS_PER_ENDPOINT:
            seen.add(clean)
            out.append(clean)

    if isinstance(doc, dict):
        for k, v in doc.items():
            _add(k)
            if isinstance(v, (dict, list)) and len(out) < _MAX_PARAMS_PER_ENDPOINT:
                for sub in _extract_json_param_names(v, depth=depth + 1):
                    _add(sub)
    elif isinstance(doc, list):
        for item in doc[:4]:
            if isinstance(item, (dict, list)) and len(out) < _MAX_PARAMS_PER_ENDPOINT:
                for sub in _extract_json_param_names(item, depth=depth + 1):
                    _add(sub)
    return out


def _sanitize_sample_path(norm_path: str) -> str:
    """Redact secret path segments and secret `key=value` segments before exposing a sample URL."""
    parts: list[str] = []
    for seg in norm_path.split("/"):
        if not seg:
            parts.append(seg)
            continue
        if "=" in seg:
            k, _, v = seg.partition("=")
            if k and v and _SAFE_PARAM_NAME_RE.fullmatch(k):
                if _is_sensitive_json_key(k) or _is_secret_value(v):
                    parts.append(f"{k}=<REDACTED>")
                    continue
        if _is_secret_value(seg):
            parts.append("<REDACTED>")
            continue
        parts.append(seg)
    return "/".join(parts) or "/"


def _extract_graphql_op_from_query(query_str: str) -> str:
    if not query_str:
        return ""
    pairs = dict(parse_qsl(query_str, keep_blank_values=True))
    op_name = str(pairs.get("operationName") or pairs.get("operation_name") or "").strip()
    if op_name and _GQL_OP_NAME_RE.fullmatch(op_name):
        return op_name
    raw_query = pairs.get("query")
    if isinstance(raw_query, str) and raw_query.strip():
        return _extract_graphql_op_name({"query": raw_query, "operationName": op_name})
    return ""


def _extract_graphql_op_from_payload(payload: Any) -> str:
    if isinstance(payload, dict):
        op = _extract_graphql_op_name(payload)
        if op and _GQL_OP_NAME_RE.fullmatch(op):
            return op
    elif isinstance(payload, list) and payload and isinstance(payload[0], dict):
        op = _extract_graphql_op_name(payload[0])
        if op and _GQL_OP_NAME_RE.fullmatch(op):
            return op
    return ""


def _infer_origin_role(host: str, sample_paths: Sequence[str] = ()) -> str:
    clean = str(host or "").strip().lower().rstrip(".")
    labels: set[str] = set()
    if clean and ":" not in clean:
        parts = [p for p in clean.split(".") if p]
        prefix_parts = parts[:-2] if len(parts) > 2 else parts[:1]
        for part in prefix_parts:
            for tok in part.split("-"):
                if tok:
                    labels.add(tok)
    for role_name, token_set in _HOST_ROLE_LABELS:
        if labels & token_set:
            return role_name
    if any(_GRAPHQL_PATH_RE.search(p) for p in sample_paths):
        return "graphql"
    if any(_API_PATH_RE.match(p) for p in sample_paths):
        return "api"
    if any(_AUTH_PATH_RE.match(p) for p in sample_paths):
        return "auth"
    if any(_ADMIN_PATH_RE.match(p) for p in sample_paths):
        return "admin"
    return "unknown"


def _is_high_risk_param(param_name: str) -> bool:
    clean = _sanitize_param_name(param_name)
    if not clean:
        return False
    if is_high_risk_param_name(clean):
        return True
    snake, tokens = _to_snake_tokens(clean)
    if snake in _EXTRA_HIGH_RISK_PARAM_TOKENS:
        return True
    return any(tok in _EXTRA_HIGH_RISK_PARAM_TOKENS for tok in tokens)


@dataclass
class _OriginMeta:
    origin: str
    host: str
    role: str = "unknown"
    waf_vendor: str = ""
    tech_signals: set[str] = field(default_factory=set)

    def merge(
        self,
        *,
        role: str = "",
        waf_vendor: str = "",
        tech_signals: Sequence[str] = (),
    ) -> None:
        clean_role = str(role or "").strip().lower()
        if clean_role in _VALID_ROLES and clean_role != "unknown":
            if self.role == "unknown" or (
                self.role == "storefront" and clean_role in {"api", "graphql", "auth", "admin"}
            ):
                self.role = clean_role
        clean_waf = _sanitize_single_line(waf_vendor, max_len=64)
        if clean_waf and not self.waf_vendor:
            self.waf_vendor = clean_waf
        for sig in tech_signals or ():
            clean_sig = _sanitize_single_line(sig, max_len=64)
            if clean_sig and not _is_secret_value(clean_sig):
                self.tech_signals.add(clean_sig)


@dataclass
class _EndpointRecord:
    origin: str
    method: str
    path_template: str
    graphql_op: str
    sample_url: str
    query_params: set[str] = field(default_factory=set)
    body_params: set[str] = field(default_factory=set)
    body_template: dict[str, Any] | None = None
    multipart_schema: dict[str, list[str]] | None = None
    required_app_headers: dict[str, str] = field(default_factory=dict)
    content_types: set[str] = field(default_factory=set)
    statuses_seen: set[int] = field(default_factory=set)
    actors_seen: set[str] = field(default_factory=set)
    anon_statuses: set[int] = field(default_factory=set)
    auth_statuses: set[int] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    prescan_leads: dict[tuple[str, str, str], dict[str, str]] = field(default_factory=dict)
    visited: bool = False

    def maybe_update_sample_url(self, candidate_url: str) -> None:
        if not candidate_url:
            return
        cur_path = urlsplit(self.sample_url).path or "/"
        cand_path = urlsplit(candidate_url).path or "/"
        cur_rank = ("{" in cur_path, len(cur_path), cur_path)
        cand_rank = ("{" in cand_path, len(cand_path), cand_path)
        if cand_rank < cur_rank:
            self.sample_url = candidate_url

    def infer_auth_required(self) -> str:
        anon_denied = 401 in self.anon_statuses or 403 in self.anon_statuses
        anon_ok = any(200 <= s < 300 for s in self.anon_statuses)
        auth_ok = any(200 <= s < 300 for s in self.auth_statuses)
        if anon_denied and auth_ok:
            return "true"
        if anon_ok:
            return "false"
        if anon_denied:
            return "true"
        return "unknown"

    def compute_risk_score(self) -> int:
        score = 0
        if self.method in {"PUT", "PATCH", "DELETE"}:
            score += 28
        elif self.method == "POST":
            score += 25
        elif self.method == "GET":
            score += 5
        else:
            score += 1

        if "{" in self.path_template and "}" in self.path_template:
            score += 15

        path_low = self.path_template.lower()
        path_tokens = {tok for tok in _TOKEN_SPLIT_RE.split(path_low) if tok}
        if path_tokens & _ADMIN_RISK_TOKENS:
            score += 20
        if path_tokens & _AUTH_RISK_TOKENS:
            score += 15
        if path_tokens & _BUSINESS_RISK_TOKENS:
            score += 12
        if _API_PATH_RE.match(self.path_template):
            score += 8

        if _is_graphql_path(self.path_template) or self.graphql_op:
            score += 12
            if self.graphql_op:
                _, op_tokens = _to_snake_tokens(self.graphql_op)
                if any(tok in _ADMIN_RISK_TOKENS or tok in _BUSINESS_RISK_TOKENS for tok in op_tokens):
                    score += 10

        lead_score = 0
        for lead in self.prescan_leads.values():
            sev = lead.get("severity_hint", "low").lower()
            if sev == "high":
                lead_score += 30
            elif sev == "medium":
                lead_score += 18
            else:
                lead_score += 8
        score += min(60, lead_score)

        all_params = self.query_params | self.body_params
        high_risk_params = [p for p in all_params if _is_high_risk_param(p)]
        if high_risk_params:
            score += min(24, len(high_risk_params) * 6)
            if not self.visited:
                score += 12
        if all_params:
            score += min(10, len(all_params) * 2)

        if self.body_template:
            score += 5
        if self.multipart_schema:
            score += 15 if self.multipart_schema.get("files") else 6

        if self.infer_auth_required() == "true":
            score += 8
        if not self.visited:
            score += 6

        if path_low in _LOW_SIGNAL_EXACT_PATHS:
            score -= 15
        if any(
            marker in path_low
            for marker in ("{catalog_category}", "{catalog_product}", "{catalog_brand}", "{catalog_campaign}")
        ):
            score -= 10

        return max(0, int(score))

    def to_dict(self) -> dict[str, Any]:
        sorted_leads = sorted(
            self.prescan_leads.values(),
            key=lambda item: (
                _LEAD_SEVERITY_RANK.get(item.get("severity_hint", "low"), 9),
                item.get("kind", ""),
                item.get("receipt_id", ""),
            ),
        )
        return {
            "origin": self.origin,
            "method": self.method,
            "path_template": self.path_template,
            "sample_url": self.sample_url,
            "graphql_op": self.graphql_op,
            "query_params": sorted(self.query_params)[:_MAX_PARAMS_PER_ENDPOINT],
            "body_params": sorted(self.body_params)[:_MAX_PARAMS_PER_ENDPOINT],
            "body_template": self.body_template,
            "multipart_schema": self.multipart_schema,
            "required_app_headers": dict(sorted(self.required_app_headers.items(), key=lambda kv: kv[0].lower())),
            "content_types": sorted(self.content_types),
            "statuses_seen": sorted(self.statuses_seen),
            "actors_seen": sorted(self.actors_seen),
            "auth_required": self.infer_auth_required(),
            "sources": sorted(s for s in self.sources if s in VALID_SOURCES),
            "prescan_leads": sorted_leads,
            "visited": bool(self.visited),
            "risk_score": self.compute_risk_score(),
        }


def _resolve_scoped_url(
    raw_url: str,
    guard: ScopeGuard,
) -> tuple[str, str, str, str, str, str] | None:
    """Resolve and scope-check ``raw_url`` against ``guard``.

    Returns ``(origin, host, norm_path, path_template, query_str, gql_frag_op)``
    when in scope, or ``None`` when out of scope / invalid.
    """
    raw = str(raw_url or "").strip()
    if not raw or raw.startswith(("javascript:", "mailto:", "data:", "blob:", "tel:", "about:")):
        return None
    if raw.lower().startswith(("ws://", "wss://")):
        return None

    gql_frag_op = ""
    check_target = raw
    if "#" in raw:
        before_frag, frag = raw.split("#", 1)
        check_target = before_frag or "/"
        clean_frag = frag.strip()
        if clean_frag and _GQL_OP_NAME_RE.fullmatch(clean_frag):
            frag_path = urlsplit(check_target).path or "/"
            if _is_graphql_path(frag_path):
                gql_frag_op = clean_frag

    try:
        guard.check_url(check_target, allow_lifecycle_routes=True)
    except ValueError:
        return None

    resolved = urljoin(guard.base_origin, check_target)
    parsed = urlsplit(resolved)
    scheme = parsed.scheme.lower()
    raw_host = (parsed.hostname or "").strip().lower().rstrip(".")
    if scheme not in {"http", "https"} or not raw_host or not _is_valid_host(raw_host):
        return None
    host = _canonicalize_host(raw_host)
    try:
        port_val = parsed.port
    except ValueError:
        return None
    eff_port = port_val if port_val is not None else _default_port(scheme)
    origin = _format_origin(scheme, host, eff_port)

    try:
        norm_path = normalize_path(parsed.path or "/")
    except ValueError:
        return None

    path_template = route_template_of(norm_path)
    return origin, host, norm_path, path_template, parsed.query or "", gql_frag_op


def _tracker_get(tracker: Any, attr: str, default: Any = None) -> Any:
    if isinstance(tracker, dict):
        return tracker.get(attr, default)
    return getattr(tracker, attr, default)


def _parse_json_object(raw_text: str) -> Any:
    stripped = str(raw_text or "").strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except ValueError:
        return None


def build_surface_map(
    *,
    base_url: str,
    receipts: Sequence[dict[str, Any]] = (),
    seed_surface: dict[str, Any] | None = None,
    stage0_result: dict[str, Any] | None = None,
    har_flows: dict[str, Any] | None = None,
    asset_graph: dict[str, Any] | None = None,
    prescan_doc: dict[str, Any] | None = None,
    surface_tracker: Any | None = None,
    in_scope_assets: Sequence[str] = (),
    out_of_scope_assets: Sequence[str] = (),
    excluded_paths: Sequence[str] = (),
) -> dict[str, Any]:
    """Reconcile all collected surface intelligence into one canonical ``cco-surface-map/1`` dict."""
    norm_base = _normalize_base_origin(base_url)
    guard = ScopeGuard(
        base_origin=norm_base,
        excluded_paths=tuple(str(p).strip() for p in (excluded_paths or ()) if str(p or "").strip()),
        in_scope_assets=tuple(str(a).strip() for a in (in_scope_assets or ()) if str(a or "").strip()),
        out_of_scope_assets=tuple(str(a).strip() for a in (out_of_scope_assets or ()) if str(a or "").strip()),
    )
    base_parsed = urlsplit(guard.base_origin)
    base_scheme = base_parsed.scheme.lower()
    base_host = _canonicalize_host(base_parsed.hostname or "")
    base_port = base_parsed.port if base_parsed.port is not None else _default_port(base_scheme)
    base_origin_no_slash = _format_origin(base_scheme, base_host, base_port)

    origins_meta: dict[str, _OriginMeta] = {}
    endpoints: dict[tuple[str, str, str, str], _EndpointRecord] = {}
    receipt_index: dict[str, tuple[str, str, str, str]] = {}
    dropped_out_of_scope = 0

    def _ensure_origin(origin: str, host: str) -> _OriginMeta:
        meta = origins_meta.get(origin)
        if meta is None:
            meta = _OriginMeta(origin=origin, host=host)
            origins_meta[origin] = meta
        return meta

    def _upsert_endpoint(
        *,
        origin: str,
        host: str,
        method: str,
        norm_path: str,
        path_template: str,
        graphql_op: str,
        source: str,
        visited: bool = False,
    ) -> _EndpointRecord:
        _ensure_origin(origin, host)
        clean_op = graphql_op if (graphql_op and _GQL_OP_NAME_RE.fullmatch(graphql_op)) else ""
        key = (origin, method, path_template, clean_op)
        sample_url = f"{origin}{_sanitize_sample_path(norm_path)}"
        rec = endpoints.get(key)
        if rec is None:
            rec = _EndpointRecord(
                origin=origin,
                method=method,
                path_template=path_template,
                graphql_op=clean_op,
                sample_url=sample_url,
            )
            endpoints[key] = rec
        else:
            rec.maybe_update_sample_url(sample_url)
        if source in VALID_SOURCES:
            rec.sources.add(source)
        if visited:
            rec.visited = True
        return rec

    def _ingest_seed_like(doc: dict[str, Any], *, source_tag: str) -> None:
        nonlocal dropped_out_of_scope
        if not isinstance(doc, dict):
            return

        doc_app_headers: dict[str, str] = {}
        for hkey in ("observed_app_headers", "app_headers"):
            raw_dh = doc.get(hkey)
            if isinstance(raw_dh, dict) and raw_dh:
                _merge_app_headers(doc_app_headers, _sanitize_app_headers(raw_dh))

        # Account for out-of-scope routes already dropped upstream by agentic_seed.
        raw_stats = doc.get("stats")
        if isinstance(raw_stats, dict):
            pre_dropped = raw_stats.get("routes_dropped_scope")
            if isinstance(pre_dropped, int) and not isinstance(pre_dropped, bool) and pre_dropped > 0:
                dropped_out_of_scope += pre_dropped

        def _ingest_route_entry(entry: Any, *, default_method: str) -> None:
            nonlocal dropped_out_of_scope
            raw_u = ""
            method = default_method
            params_raw: Any = ()
            status_raw: Any = None
            bt_raw: Any = None
            mp_raw: Any = None
            headers_raw: Any = None
            ct_raw: Any = ""
            gql_explicit = ""

            if isinstance(entry, str):
                raw_u = entry.strip()
            elif isinstance(entry, dict):
                raw_u = str(entry.get("url") or entry.get("path") or "").strip()
                method = _normalize_method(entry.get("method"), default=default_method)
                params_raw = entry.get("params") or ()
                status_raw = entry.get("status")
                bt_raw = entry.get("body_template") or entry.get("json_template")
                mp_raw = entry.get("multipart_schema")
                headers_raw = (
                    entry.get("required_app_headers")
                    or entry.get("headers")
                    or entry.get("app_headers")
                    or entry.get("observed_app_headers")
                )
                ct_raw = entry.get("content_type") or ""
                gql_explicit = str(entry.get("graphql_op") or entry.get("operationName") or "").strip()
            if not raw_u:
                return

            resolved = _resolve_scoped_url(raw_u, guard)
            if resolved is None:
                dropped_out_of_scope += 1
                return
            origin, host, norm_path, path_template, query_str, gql_frag_op = resolved
            if is_static_asset_url(norm_path):
                return

            gql_op = ""
            if _is_graphql_path(norm_path):
                gql_op = (
                    gql_explicit
                    or gql_frag_op
                    or _extract_graphql_op_from_payload(bt_raw)
                    or _extract_graphql_op_from_query(query_str)
                )

            rec = _upsert_endpoint(
                origin=origin,
                host=host,
                method=method,
                norm_path=norm_path,
                path_template=path_template,
                graphql_op=gql_op,
                source=source_tag,
            )

            for qk, _ in parse_qsl(query_str, keep_blank_values=True):
                clean_qk = _sanitize_param_name(qk)
                if clean_qk:
                    rec.query_params.add(clean_qk)

            if isinstance(params_raw, (list, tuple, set)):
                for p in params_raw:
                    cand_p = p.get("name") if isinstance(p, dict) else p
                    clean_p = _sanitize_param_name(cand_p)
                    if not clean_p:
                        continue
                    if method in _WRITE_METHODS:
                        rec.body_params.add(clean_p)
                    else:
                        rec.query_params.add(clean_p)

            sanitized_bt = _sanitize_body_template(bt_raw)
            if sanitized_bt is not None:
                rec.body_template = _merge_body_templates(rec.body_template, sanitized_bt)
                rec.body_params.update(_extract_json_param_names(sanitized_bt))
                rec.content_types.add("application/json")

            sanitized_mp = _sanitize_multipart_schema(mp_raw)
            if sanitized_mp is not None:
                rec.multipart_schema = _merge_multipart_schemas(rec.multipart_schema, sanitized_mp)
                rec.body_params.update(sanitized_mp.get("fields") or ())
                rec.body_params.update(sanitized_mp.get("files") or ())
                rec.content_types.add("multipart/form-data")

            if doc_app_headers:
                _merge_app_headers(rec.required_app_headers, doc_app_headers)
            if headers_raw:
                _merge_app_headers(rec.required_app_headers, _sanitize_app_headers(headers_raw))

            norm_ct = _normalize_content_type(ct_raw)
            if norm_ct:
                rec.content_types.add(norm_ct)

            coerced_st = _coerce_status(status_raw)
            if coerced_st is not None:
                rec.statuses_seen.add(coerced_st)

        for item in doc.get("links") or []:
            _ingest_route_entry(item, default_method="GET")
        for item in doc.get("forms") or []:
            _ingest_route_entry(item, default_method="POST")
        for key_name in ("routes", "endpoints"):
            for item in doc.get(key_name) or []:
                _ingest_route_entry(item, default_method="GET")
        for hint in doc.get("discovery_hints") or []:
            if isinstance(hint, str) and hint.strip():
                _ingest_route_entry(hint.strip(), default_method="GET")

        raw_bt_map = doc.get("body_templates")
        if isinstance(raw_bt_map, dict):
            for key_str, tmpl_val in raw_bt_map.items():
                m_match = _METHOD_TARGET_KEY_RE.fullmatch(str(key_str or "").strip())
                if not m_match:
                    continue
                meth = m_match.group(1).upper()
                target_u = m_match.group(2)
                resolved = _resolve_scoped_url(target_u, guard)
                if resolved is None:
                    dropped_out_of_scope += 1
                    continue
                origin, host, norm_path, path_template, query_str, gql_frag_op = resolved
                if is_static_asset_url(norm_path):
                    continue
                sanitized_bt = _sanitize_body_template(tmpl_val)
                if sanitized_bt is None:
                    continue
                gql_op = ""
                if _is_graphql_path(norm_path):
                    gql_op = gql_frag_op or _extract_graphql_op_from_payload(tmpl_val) or _extract_graphql_op_from_query(query_str)
                rec = _upsert_endpoint(
                    origin=origin,
                    host=host,
                    method=meth,
                    norm_path=norm_path,
                    path_template=path_template,
                    graphql_op=gql_op,
                    source=source_tag,
                )
                rec.body_template = _merge_body_templates(rec.body_template, sanitized_bt)
                rec.body_params.update(_extract_json_param_names(sanitized_bt))
                rec.content_types.add("application/json")
                if doc_app_headers:
                    _merge_app_headers(rec.required_app_headers, doc_app_headers)

        raw_mp_map = doc.get("multipart_schemas")
        if isinstance(raw_mp_map, dict):
            for key_str, mp_val in raw_mp_map.items():
                m_match = _METHOD_TARGET_KEY_RE.fullmatch(str(key_str or "").strip())
                if not m_match:
                    continue
                meth = m_match.group(1).upper()
                target_u = m_match.group(2)
                resolved = _resolve_scoped_url(target_u, guard)
                if resolved is None:
                    dropped_out_of_scope += 1
                    continue
                origin, host, norm_path, path_template, _q, gql_frag_op = resolved
                sanitized_mp = _sanitize_multipart_schema(mp_val)
                if sanitized_mp is None:
                    continue
                rec = _upsert_endpoint(
                    origin=origin,
                    host=host,
                    method=meth,
                    norm_path=norm_path,
                    path_template=path_template,
                    graphql_op=gql_frag_op if _is_graphql_path(norm_path) else "",
                    source=source_tag,
                )
                rec.multipart_schema = _merge_multipart_schemas(rec.multipart_schema, sanitized_mp)
                rec.body_params.update(sanitized_mp.get("fields") or ())
                rec.body_params.update(sanitized_mp.get("files") or ())
                rec.content_types.add("multipart/form-data")
                if doc_app_headers:
                    _merge_app_headers(rec.required_app_headers, doc_app_headers)

        # Stage 0 discovered_api_hosts
        for host_item in doc.get("discovered_api_hosts") or []:
            if not isinstance(host_item, dict):
                continue
            raw_orig = str(host_item.get("origin") or host_item.get("host") or "").strip()
            if not raw_orig:
                continue
            cand_orig = raw_orig if "://" in raw_orig else f"{base_scheme}://{raw_orig}"
            resolved_root = _resolve_scoped_url(cand_orig, guard)
            if resolved_root is None:
                dropped_out_of_scope += 1
                continue
            orig_s, h_s, _p, _pt, _q, _g = resolved_root
            _ensure_origin(orig_s, h_s)
            for sp in host_item.get("sample_paths") or []:
                if not isinstance(sp, str) or not sp.strip():
                    continue
                full_sp = sp.strip() if "://" in sp else f"{orig_s}/{sp.strip().lstrip('/')}"
                _ingest_route_entry(full_sp, default_method="GET")

    # 1. AssetGraph ("recon")
    if asset_graph is not None:
        graph_doc: dict[str, Any] | None = None
        if isinstance(asset_graph, dict):
            graph_doc = asset_graph
        elif hasattr(asset_graph, "to_dict") and callable(asset_graph.to_dict):
            raw_d = asset_graph.to_dict()
            if isinstance(raw_d, dict):
                graph_doc = raw_d

        if graph_doc is not None:
            raw_nodes = graph_doc.get("nodes")
            raw_in_scope_hosts = graph_doc.get("in_scope_hosts")
            node_entries: list[dict[str, Any]] = []
            if isinstance(raw_nodes, list):
                node_entries.extend(n for n in raw_nodes if isinstance(n, dict))
            elif isinstance(raw_in_scope_hosts, list):
                node_entries.extend(n for n in raw_in_scope_hosts if isinstance(n, dict))
                g_stats = graph_doc.get("stats")
                if isinstance(g_stats, dict):
                    pre_oos = g_stats.get("dropped_out_of_scope")
                    if isinstance(pre_oos, int) and not isinstance(pre_oos, bool) and pre_oos > 0:
                        dropped_out_of_scope += pre_oos

            for node in node_entries:
                raw_origin = str(node.get("origin") or "").strip()
                if not raw_origin and node.get("host"):
                    n_scheme = str(node.get("scheme") or base_scheme).strip().lower() or base_scheme
                    n_host = str(node.get("host") or "").strip()
                    n_port = node.get("port")
                    if isinstance(n_port, int) and not isinstance(n_port, bool) and n_port > 0:
                        raw_origin = _format_origin(n_scheme, n_host, n_port)
                    else:
                        raw_origin = f"{n_scheme}://{n_host}"
                if not raw_origin:
                    continue
                if "://" not in raw_origin:
                    raw_origin = f"{base_scheme}://{raw_origin}"
                try:
                    p_orig = urlsplit(raw_origin)
                    n_scheme = p_orig.scheme.lower()
                    n_host_raw = (p_orig.hostname or "").strip().lower().rstrip(".")
                    n_port_val = p_orig.port
                except ValueError:
                    dropped_out_of_scope += 1
                    continue
                if n_scheme not in {"http", "https"} or not n_host_raw or not _is_valid_host(n_host_raw):
                    dropped_out_of_scope += 1
                    continue
                n_host = _canonicalize_host(n_host_raw)
                eff_n_port = n_port_val if n_port_val is not None else _default_port(n_scheme)
                if not guard.check_origin(n_scheme, n_host, eff_n_port):
                    dropped_out_of_scope += 1
                    continue

                canon_origin = _format_origin(n_scheme, n_host, eff_n_port)
                meta = _ensure_origin(canon_origin, n_host)
                raw_techs = [str(t) for t in (node.get("tech_signals") or []) if str(t).strip()]
                if node.get("server"):
                    raw_techs.append(f"server:{_sanitize_single_line(node.get('server'), max_len=48)}")
                if node.get("powered_by"):
                    raw_techs.append(f"powered_by:{_sanitize_single_line(node.get('powered_by'), max_len=48)}")
                meta.merge(
                    role=str(node.get("role") or ""),
                    waf_vendor=str(node.get("waf_vendor") or ""),
                    tech_signals=raw_techs,
                )

                node_status = _coerce_status(node.get("status"))
                sample_paths = [
                    str(sp).strip()
                    for sp in (node.get("sample_paths") or [])
                    if isinstance(sp, str) and sp.strip()
                ]
                for sp in sample_paths:
                    full_u = sp if "://" in sp else f"{canon_origin}/{sp.lstrip('/')}"
                    resolved = _resolve_scoped_url(full_u, guard)
                    if resolved is None:
                        dropped_out_of_scope += 1
                        continue
                    r_orig, r_host, r_norm, r_tmpl, r_q, r_gql = resolved
                    if is_static_asset_url(r_norm):
                        continue
                    gql_op = r_gql or (_extract_graphql_op_from_query(r_q) if _is_graphql_path(r_norm) else "")
                    rec = _upsert_endpoint(
                        origin=r_orig,
                        host=r_host,
                        method="GET",
                        norm_path=r_norm,
                        path_template=r_tmpl,
                        graphql_op=gql_op,
                        source="recon",
                    )
                    for qk, _ in parse_qsl(r_q, keep_blank_values=True):
                        clean_qk = _sanitize_param_name(qk)
                        if clean_qk:
                            rec.query_params.add(clean_qk)
                    if r_norm == "/" and node_status is not None:
                        rec.statuses_seen.add(node_status)

            for hint in graph_doc.get("discovery_hints") or []:
                if not isinstance(hint, str) or not hint.strip():
                    continue
                resolved = _resolve_scoped_url(hint.strip(), guard)
                if resolved is None:
                    dropped_out_of_scope += 1
                    continue
                r_orig, r_host, r_norm, r_tmpl, r_q, r_gql = resolved
                if is_static_asset_url(r_norm):
                    continue
                gql_op = r_gql or (_extract_graphql_op_from_query(r_q) if _is_graphql_path(r_norm) else "")
                _upsert_endpoint(
                    origin=r_orig,
                    host=r_host,
                    method="GET",
                    norm_path=r_norm,
                    path_template=r_tmpl,
                    graphql_op=gql_op,
                    source="recon",
                )

    # 2. Seed surface ("seed")
    if seed_surface is not None:
        _ingest_seed_like(seed_surface, source_tag="seed")

    # 3. Stage 0 crawl result ("stage0")
    if stage0_result is not None:
        _ingest_seed_like(stage0_result, source_tag="stage0")

    # 4. HAR multi-step flows ("har")
    if isinstance(har_flows, dict):
        har_stats = har_flows.get("stats")
        if isinstance(har_stats, dict):
            har_oos = har_stats.get("entries_dropped_scope")
            if isinstance(har_oos, int) and not isinstance(har_oos, bool) and har_oos > 0:
                dropped_out_of_scope += har_oos

        for flow in har_flows.get("flows") or []:
            if not isinstance(flow, dict):
                continue
            for step in flow.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                raw_u = str(step.get("url") or "").strip()
                if not raw_u:
                    continue
                resolved = _resolve_scoped_url(raw_u, guard)
                if resolved is None:
                    dropped_out_of_scope += 1
                    continue
                origin, host, norm_path, path_template, query_str, gql_frag_op = resolved
                if is_static_asset_url(norm_path):
                    continue

                method = _normalize_method(step.get("method"), default="GET")
                raw_json_tmpl = step.get("json_template")
                gql_op = ""
                if _is_graphql_path(norm_path):
                    gql_op = (
                        str(step.get("graphql_op") or "").strip()
                        or gql_frag_op
                        or _extract_graphql_op_from_payload(raw_json_tmpl)
                        or _extract_graphql_op_from_query(query_str)
                    )

                rec = _upsert_endpoint(
                    origin=origin,
                    host=host,
                    method=method,
                    norm_path=norm_path,
                    path_template=path_template,
                    graphql_op=gql_op,
                    source="har",
                )
                for qk, _ in parse_qsl(query_str, keep_blank_values=True):
                    clean_qk = _sanitize_param_name(qk)
                    if clean_qk:
                        rec.query_params.add(clean_qk)
                for qk_raw in step.get("query_keys") or []:
                    clean_qk = _sanitize_param_name(qk_raw)
                    if clean_qk:
                        rec.query_params.add(clean_qk)

                sanitized_bt = _sanitize_body_template(raw_json_tmpl)
                if sanitized_bt is not None:
                    rec.body_template = _merge_body_templates(rec.body_template, sanitized_bt)
                    rec.body_params.update(_extract_json_param_names(sanitized_bt))
                    rec.content_types.add("application/json")
                elif isinstance(raw_json_tmpl, list):
                    rec.body_params.update(_extract_json_param_names(raw_json_tmpl))
                    rec.content_types.add("application/json")

                raw_form_tmpl = step.get("form_template")
                if isinstance(raw_form_tmpl, dict) and raw_form_tmpl:
                    sanitized_ft = _sanitize_body_template(raw_form_tmpl)
                    if sanitized_ft is not None:
                        rec.body_template = _merge_body_templates(rec.body_template, sanitized_ft)
                        rec.body_params.update(_extract_json_param_names(sanitized_ft))
                    else:
                        rec.body_params.update(_extract_json_param_names(raw_form_tmpl))
                    rec.content_types.add("application/x-www-form-urlencoded")

                raw_xml_tags = step.get("xml_tags")
                if isinstance(raw_xml_tags, list) and raw_xml_tags:
                    for tag in raw_xml_tags:
                        local_tag = str(tag or "").split(":", 1)[-1].strip()
                        clean_tag = _sanitize_param_name(local_tag)
                        if clean_tag:
                            rec.body_params.add(clean_tag)

                _merge_app_headers(rec.required_app_headers, _sanitize_app_headers(step.get("required_app_headers")))

                norm_ct = _normalize_content_type(step.get("content_type"))
                if norm_ct:
                    rec.content_types.add(norm_ct)
                elif str(step.get("body_kind") or "").strip().lower() == "xml":
                    rec.content_types.add("application/xml")

                st_code = _coerce_status(step.get("response_status"))
                if st_code is not None:
                    rec.statuses_seen.add(st_code)

    # 5. Live HTTP receipts ("live")
    for raw_receipt in receipts or ():
        if not isinstance(raw_receipt, dict):
            continue
        raw_url = str(raw_receipt.get("url") or raw_receipt.get("path") or "").strip()
        if not raw_url:
            continue
        resolved = _resolve_scoped_url(raw_url, guard)
        if resolved is None:
            dropped_out_of_scope += 1
            continue
        origin, host, norm_path, path_template, query_str, gql_frag_op = resolved
        if is_static_asset_url(norm_path):
            continue

        method = _normalize_method(raw_receipt.get("method"), default="GET")
        req_headers_raw = raw_receipt.get("request_headers")
        req_headers = req_headers_raw if isinstance(req_headers_raw, dict) else {}
        req_ct = ""
        for hk, hv in req_headers.items():
            if str(hk).strip().lower() == "content-type":
                req_ct = _normalize_content_type(hv)
                break

        req_body_text = str(raw_receipt.get("request_body") or "")
        parsed_req_json = _parse_json_object(req_body_text) if req_body_text else None

        extra_query = str(raw_receipt.get("query") or "").strip().lstrip("?")
        combined_query = "&".join(q for q in (query_str, extra_query) if q)

        gql_op = ""
        if _is_graphql_path(norm_path):
            gql_op = (
                gql_frag_op
                or _extract_graphql_op_from_payload(parsed_req_json)
                or _extract_graphql_op_from_query(combined_query)
            )

        rec = _upsert_endpoint(
            origin=origin,
            host=host,
            method=method,
            norm_path=norm_path,
            path_template=path_template,
            graphql_op=gql_op,
            source="live",
            visited=True,
        )

        rid = str(raw_receipt.get("receipt_id") or "").strip()
        if rid:
            receipt_index[rid] = (origin, method, path_template, rec.graphql_op)

        for qk, _ in parse_qsl(combined_query, keep_blank_values=True):
            clean_qk = _sanitize_param_name(qk)
            if clean_qk:
                rec.query_params.add(clean_qk)

        _merge_app_headers(rec.required_app_headers, _sanitize_app_headers(req_headers))
        if req_ct:
            rec.content_types.add(req_ct)

        resp_ct = _normalize_content_type(raw_receipt.get("content_type"))
        if resp_ct:
            rec.content_types.add(resp_ct)

        if isinstance(parsed_req_json, dict):
            sanitized_bt = _sanitize_body_template(parsed_req_json)
            if sanitized_bt is not None:
                rec.body_template = _merge_body_templates(rec.body_template, sanitized_bt)
            rec.body_params.update(_extract_json_param_names(parsed_req_json))
            rec.content_types.add("application/json")
        elif isinstance(parsed_req_json, list):
            rec.body_params.update(_extract_json_param_names(parsed_req_json))
            rec.content_types.add("application/json")
        elif req_body_text:
            mp_parsed = _extract_multipart_from_text(req_body_text)
            if mp_parsed is not None:
                rec.multipart_schema = _merge_multipart_schemas(rec.multipart_schema, mp_parsed)
                rec.body_params.update(mp_parsed.get("fields") or ())
                rec.body_params.update(mp_parsed.get("files") or ())
                rec.content_types.add("multipart/form-data")
            elif "x-www-form-urlencoded" in req_ct or (
                "=" in req_body_text and not req_body_text.lstrip().startswith(("<", "{", "["))
            ):
                for bk, _ in parse_qsl(req_body_text, keep_blank_values=True):
                    clean_bk = _sanitize_param_name(bk)
                    if clean_bk:
                        rec.body_params.add(clean_bk)

        actor = str(raw_receipt.get("actor") or "anon").strip() or "anon"
        rec.actors_seen.add(actor)

        st_code = _coerce_status(raw_receipt.get("status"))
        if st_code is not None:
            rec.statuses_seen.add(st_code)
            if actor == "anon":
                rec.anon_statuses.add(st_code)
            else:
                rec.auth_statuses.add(st_code)

        # Passive origin WAF & tech enrichment from receipt metadata
        meta = _ensure_origin(origin, host)
        resp_headers_raw = raw_receipt.get("response_headers")
        resp_headers = resp_headers_raw if isinstance(resp_headers_raw, dict) else {}
        low_resp_headers = {str(k).strip().lower(): str(v).strip() for k, v in resp_headers.items()}
        waf_info = detect_waf_block(raw_receipt)
        waf_vendor = ""
        tech_found: list[str] = []
        if isinstance(waf_info, dict) and waf_info.get("waf_blocked"):
            waf_vendor = _sanitize_single_line(waf_info.get("vendor") or "generic", max_len=64)
            if waf_vendor:
                tech_found.append(f"waf:{waf_vendor}")
        server_hdr = low_resp_headers.get("server", "")
        powered_hdr = low_resp_headers.get("x-powered-by", "")
        body_preview = str(raw_receipt.get("body") or "")[:16384]
        for t in detect_tech(server=server_hdr, powered_by=powered_hdr, body=body_preview):
            tech_found.append(t)
        if "cf-ray" in low_resp_headers:
            tech_found.append("cloudflare")
        if "x-vercel-id" in low_resp_headers:
            tech_found.append("vercel")
        if "x-nextjs-cache" in low_resp_headers or "x-nextjs-matched-path" in low_resp_headers:
            tech_found.append("nextjs")
        meta.merge(waf_vendor=waf_vendor, tech_signals=tech_found)

    # 6. Prescan leads ("prescan")
    if isinstance(prescan_doc, dict):
        waf_list = [
            _sanitize_single_line(v, max_len=64)
            for v in (prescan_doc.get("waf_vendors_seen") or [])
            if str(v or "").strip()
        ]
        if waf_list:
            _ensure_origin(base_origin_no_slash, base_host).merge(
                waf_vendor=waf_list[0],
                tech_signals=[f"waf:{v}" for v in waf_list],
            )

        for lead in prescan_doc.get("leads") or []:
            if not isinstance(lead, dict):
                continue
            kind = _sanitize_single_line(lead.get("kind") or "lead", max_len=64)
            sev_raw = str(lead.get("severity_hint") or lead.get("priority") or "low").strip().lower()
            severity_hint = sev_raw if sev_raw in _LEAD_SEVERITY_RANK else "low"
            rid = _sanitize_single_line(lead.get("receipt_id") or lead.get("proof_receipt_id") or "", max_len=64)
            raw_lead_op = str(lead.get("operation") or lead.get("graphql_op") or "").strip()
            lead_op = raw_lead_op if (raw_lead_op and _GQL_OP_NAME_RE.fullmatch(raw_lead_op)) else ""

            lead_rec: _EndpointRecord | None = None
            rid_visited = False
            if rid and rid in receipt_index:
                rid_visited = True
                cand_rec = endpoints.get(receipt_index[rid])
                if cand_rec is not None and (not lead_op or cand_rec.graphql_op == lead_op):
                    lead_rec = cand_rec
                    lead_rec.sources.add("prescan")

            if lead_rec is None:
                raw_u = str(lead.get("url") or "").strip()
                if not raw_u:
                    continue
                resolved = _resolve_scoped_url(raw_u, guard)
                if resolved is None:
                    dropped_out_of_scope += 1
                    continue
                origin, host, norm_path, path_template, query_str, gql_frag_op = resolved
                is_gql_kind = kind.startswith("graphql_")
                default_m = "POST" if is_gql_kind else "GET"
                method = _normalize_method(lead.get("method"), default=default_m)
                gql_op = ""
                if _is_graphql_path(norm_path) or is_gql_kind:
                    gql_op = lead_op or gql_frag_op or _extract_graphql_op_from_query(query_str)
                    if not gql_op and kind == "graphql_introspection":
                        gql_op = "__schema"
                lead_rec = _upsert_endpoint(
                    origin=origin,
                    host=host,
                    method=method,
                    norm_path=norm_path,
                    path_template=path_template,
                    graphql_op=gql_op,
                    source="prescan",
                    visited=rid_visited,
                )
                for qk, _ in parse_qsl(query_str, keep_blank_values=True):
                    clean_qk = _sanitize_param_name(qk)
                    if clean_qk:
                        lead_rec.query_params.add(clean_qk)

            lead_param = _sanitize_param_name(lead.get("param"))
            if lead_param:
                lead_rec.query_params.add(lead_param)
            for actor_key in ("actor", "control_actor"):
                actor_val = str(lead.get(actor_key) or "").strip()
                if actor_val:
                    lead_rec.actors_seen.add(actor_val)

            lead_key = (kind, severity_hint, rid)
            lead_rec.prescan_leads[lead_key] = {
                "kind": kind,
                "severity_hint": severity_hint,
                "receipt_id": rid,
            }

    # 7. SurfaceFrontierTracker ("tracker")
    if surface_tracker is not None:
        # 7a. visited_method_paths
        for item in _tracker_get(surface_tracker, "visited_method_paths") or ():
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            meth = _normalize_method(item[0], default="GET")
            raw_p = str(item[1] or "").strip()
            if not raw_p:
                continue
            resolved = _resolve_scoped_url(raw_p, guard)
            if resolved is None:
                dropped_out_of_scope += 1
                continue
            origin, host, norm_path, path_template, _q, gql_frag_op = resolved
            if is_static_asset_url(norm_path):
                continue
            _upsert_endpoint(
                origin=origin,
                host=host,
                method=meth,
                norm_path=norm_path,
                path_template=path_template,
                graphql_op=gql_frag_op if _is_graphql_path(norm_path) else "",
                source="tracker",
                visited=True,
            )

        # 7b. discovered_routes (dict[(method, path), sample_url] or list[[method, path, sample_url]])
        disc_routes = _tracker_get(surface_tracker, "discovered_routes") or ()
        route_triples: list[tuple[str, str, str]] = []
        if isinstance(disc_routes, dict):
            for k, v in disc_routes.items():
                if isinstance(k, (list, tuple)) and len(k) == 2:
                    route_triples.append((str(k[0]), str(k[1]), str(v or "")))
        elif isinstance(disc_routes, list):
            for row in disc_routes:
                if isinstance(row, (list, tuple)) and len(row) >= 2:
                    route_triples.append((str(row[0]), str(row[1]), str(row[2] if len(row) > 2 else "")))

        for raw_m, raw_p, sample_u in route_triples:
            meth = _normalize_method(raw_m, default="GET")
            target_u = sample_u.strip() or raw_p.strip()
            resolved = _resolve_scoped_url(target_u, guard)
            if resolved is None:
                dropped_out_of_scope += 1
                continue
            origin, host, norm_path, path_template, query_str, gql_frag_op = resolved
            if is_static_asset_url(norm_path):
                continue
            gql_op = gql_frag_op or (_extract_graphql_op_from_query(query_str) if _is_graphql_path(norm_path) else "")
            rec = _upsert_endpoint(
                origin=origin,
                host=host,
                method=meth,
                norm_path=norm_path,
                path_template=path_template,
                graphql_op=gql_op,
                source="tracker",
            )
            for qk, _ in parse_qsl(query_str, keep_blank_values=True):
                clean_qk = _sanitize_param_name(qk)
                if clean_qk:
                    rec.query_params.add(clean_qk)

        # 7c. discovered_write_ops
        disc_writes = _tracker_get(surface_tracker, "discovered_write_ops") or ()
        write_triples: list[tuple[str, str, str]] = []
        if isinstance(disc_writes, dict):
            for k, v in disc_writes.items():
                if isinstance(k, (list, tuple)) and len(k) == 2:
                    write_triples.append((str(k[0]), str(k[1]), str(v or "")))
        elif isinstance(disc_writes, list):
            for row in disc_writes:
                if isinstance(row, (list, tuple)) and len(row) >= 2:
                    write_triples.append((str(row[0]), str(row[1]), str(row[2] if len(row) > 2 else "")))

        for raw_m, raw_tmpl, sample_p in write_triples:
            meth = _normalize_method(raw_m, default="POST")
            target_u = sample_p.strip() or raw_tmpl.strip()
            resolved = _resolve_scoped_url(target_u, guard)
            if resolved is None:
                dropped_out_of_scope += 1
                continue
            origin, host, norm_path, path_template, _q, gql_frag_op = resolved
            if is_static_asset_url(norm_path):
                continue
            _upsert_endpoint(
                origin=origin,
                host=host,
                method=meth,
                norm_path=norm_path,
                path_template=path_template,
                graphql_op=gql_frag_op if _is_graphql_path(norm_path) else "",
                source="tracker",
            )

        # 7d. discovered_body_templates
        disc_bts = _tracker_get(surface_tracker, "discovered_body_templates") or ()
        bt_triples: list[tuple[str, str, Any]] = []
        if isinstance(disc_bts, dict):
            for k, v in disc_bts.items():
                if isinstance(k, (list, tuple)) and len(k) == 2:
                    bt_triples.append((str(k[0]), str(k[1]), v))
        elif isinstance(disc_bts, list):
            for row in disc_bts:
                if isinstance(row, (list, tuple)) and len(row) == 3:
                    bt_triples.append((str(row[0]), str(row[1]), row[2]))

        for raw_m, raw_tmpl, bt_val in bt_triples:
            meth = _normalize_method(raw_m, default="POST")
            resolved = _resolve_scoped_url(raw_tmpl, guard)
            if resolved is None:
                dropped_out_of_scope += 1
                continue
            origin, host, norm_path, path_template, _q, gql_frag_op = resolved
            sanitized_bt = _sanitize_body_template(bt_val)
            if sanitized_bt is None:
                continue
            gql_op = ""
            if _is_graphql_path(norm_path):
                gql_op = gql_frag_op or _extract_graphql_op_from_payload(bt_val)
            rec = _upsert_endpoint(
                origin=origin,
                host=host,
                method=meth,
                norm_path=norm_path,
                path_template=path_template,
                graphql_op=gql_op,
                source="tracker",
            )
            rec.body_template = _merge_body_templates(rec.body_template, sanitized_bt)
            rec.body_params.update(_extract_json_param_names(sanitized_bt))
            rec.content_types.add("application/json")

        # 7e. discovered_params (dict[scoped_tmpl, set/list[str]])
        disc_params = _tracker_get(surface_tracker, "discovered_params") or {}
        if isinstance(disc_params, dict):
            for raw_tmpl, pnames in disc_params.items():
                resolved = _resolve_scoped_url(str(raw_tmpl), guard)
                if resolved is None:
                    dropped_out_of_scope += 1
                    continue
                origin, host, norm_path, path_template, _q, gql_frag_op = resolved
                if is_static_asset_url(norm_path):
                    continue
                clean_pnames = [_sanitize_param_name(p) for p in (pnames or ())]
                clean_pnames = [p for p in clean_pnames if p]
                if not clean_pnames:
                    continue
                matched = [
                    ep
                    for ep in endpoints.values()
                    if ep.origin == origin
                    and ep.path_template == path_template
                    and (not gql_frag_op or ep.graphql_op == gql_frag_op)
                ]
                if not matched:
                    ep = _upsert_endpoint(
                        origin=origin,
                        host=host,
                        method="GET",
                        norm_path=norm_path,
                        path_template=path_template,
                        graphql_op=gql_frag_op if _is_graphql_path(norm_path) else "",
                        source="tracker",
                    )
                    matched = [ep]
                for ep in matched:
                    ep.sources.add("tracker")
                    if ep.method in _WRITE_METHODS:
                        ep.body_params.update(clean_pnames)
                    else:
                        ep.query_params.update(clean_pnames)

        # 7f. actors_by_template & route_2xx_actors
        actors_by_tmpl = _tracker_get(surface_tracker, "actors_by_template") or {}
        if isinstance(actors_by_tmpl, dict):
            for raw_tmpl, actors_seq in actors_by_tmpl.items():
                resolved = _resolve_scoped_url(str(raw_tmpl), guard)
                if resolved is None:
                    continue
                origin, _h, _np, path_template, _q, gql_frag_op = resolved
                clean_actors = [str(a).strip() for a in (actors_seq or ()) if str(a or "").strip()]
                if not clean_actors:
                    continue
                for ep in endpoints.values():
                    if (
                        ep.origin == origin
                        and ep.path_template == path_template
                        and (not gql_frag_op or ep.graphql_op == gql_frag_op)
                    ):
                        ep.actors_seen.update(clean_actors)

        route_2xx = _tracker_get(surface_tracker, "route_2xx_actors") or {}
        if isinstance(route_2xx, dict):
            for raw_tmpl, actors_seq in route_2xx.items():
                resolved = _resolve_scoped_url(str(raw_tmpl), guard)
                if resolved is None:
                    continue
                origin, _h, _np, path_template, _q, gql_frag_op = resolved
                clean_actors = [str(a).strip() for a in (actors_seq or ()) if str(a or "").strip()]
                if not clean_actors:
                    continue
                for ep in endpoints.values():
                    if (
                        ep.origin == origin
                        and ep.path_template == path_template
                        and (not gql_frag_op or ep.graphql_op == gql_frag_op)
                    ):
                        for a in clean_actors:
                            ep.actors_seen.add(a)
                            if a == "anon":
                                ep.anon_statuses.add(200)
                            else:
                                ep.auth_statuses.add(200)

    # Group endpoints under sorted origins & finalize deterministic stats
    endpoints_by_origin: dict[str, list[dict[str, Any]]] = {orig: [] for orig in origins_meta}
    all_endpoint_dicts: list[dict[str, Any]] = []

    for ep_rec in endpoints.values():
        ep_dict = ep_rec.to_dict()
        endpoints_by_origin.setdefault(ep_rec.origin, []).append(ep_dict)
        all_endpoint_dicts.append(ep_dict)

    origins_out: list[dict[str, Any]] = []
    for orig in sorted(origins_meta):
        meta = origins_meta[orig]
        orig_eps = endpoints_by_origin.get(orig, [])
        orig_eps.sort(
            key=lambda item: (
                -int(item["risk_score"]),
                str(item["method"]),
                str(item["path_template"]),
                str(item["graphql_op"]),
            )
        )
        if meta.role == "unknown":
            meta.role = _infer_origin_role(meta.host, [str(e["path_template"]) for e in orig_eps])
        visited_count = sum(1 for e in orig_eps if e["visited"])
        origins_out.append({
            "origin": meta.origin,
            "role": meta.role,
            "waf_vendor": meta.waf_vendor,
            "tech_signals": sorted(meta.tech_signals),
            "endpoints_count": len(orig_eps),
            "visited_count": visited_count,
            "endpoints": orig_eps,
        })

    sources_counts: dict[str, int] = {}
    for ep_dict in all_endpoint_dicts:
        for src in ep_dict["sources"]:
            sources_counts[src] = sources_counts.get(src, 0) + 1

    endpoints_total = len(all_endpoint_dicts)
    endpoints_visited = sum(1 for e in all_endpoint_dicts if e["visited"])
    write_endpoints_count = sum(1 for e in all_endpoint_dicts if e["method"] in _WRITE_METHODS)
    graphql_operations_count = sum(1 for e in all_endpoint_dicts if bool(e["graphql_op"]))
    params_total = sum(len(e["query_params"]) + len(e["body_params"]) for e in all_endpoint_dicts)

    return {
        "schema": SCHEMA,
        "base_url": guard.base_origin,
        "origins": origins_out,
        "stats": {
            "origins_count": len(origins_out),
            "endpoints_total": endpoints_total,
            "endpoints_visited": endpoints_visited,
            "endpoints_unvisited": endpoints_total - endpoints_visited,
            "write_endpoints_count": write_endpoints_count,
            "graphql_operations_count": graphql_operations_count,
            "params_total": params_total,
            "dropped_out_of_scope": int(dropped_out_of_scope),
            "sources_counts": dict(sorted(sources_counts.items())),
        },
    }


def _md_cell(value: Any, *, max_len: int = 120) -> str:
    return _sanitize_single_line(value, max_len=max_len).replace("|", "\\|")


def _format_params_cell(ep: dict[str, Any]) -> str:
    parts: list[str] = []
    q_params = [str(p) for p in (ep.get("query_params") or []) if str(p)]
    b_params = [str(p) for p in (ep.get("body_params") or []) if str(p)]
    if q_params:
        shown = ", ".join(q_params[:5])
        if len(q_params) > 5:
            shown += f" (+{len(q_params) - 5})"
        parts.append(f"q:{shown}")
    if b_params:
        shown = ", ".join(b_params[:5])
        if len(b_params) > 5:
            shown += f" (+{len(b_params) - 5})"
        parts.append(f"b:{shown}")
    mp = ep.get("multipart_schema")
    if isinstance(mp, dict) and mp.get("files"):
        file_names = ", ".join(str(f) for f in (mp.get("files") or [])[:3])
        parts.append(f"files:{file_names}")
    return _md_cell("; ".join(parts), max_len=96) if parts else "-"


def _format_leads_cell(ep: dict[str, Any]) -> str:
    leads = [item for item in (ep.get("prescan_leads") or []) if isinstance(item, dict)]
    if not leads:
        return "-"
    rendered: list[str] = []
    for lead in leads[:3]:
        sev = str(lead.get("severity_hint") or "low").lower()
        kind = str(lead.get("kind") or "lead")
        rid = str(lead.get("receipt_id") or "")
        rendered.append(f"{sev}:{kind}({rid})" if rid else f"{sev}:{kind}")
    if len(leads) > 3:
        rendered.append(f"+{len(leads) - 3}")
    return _md_cell(", ".join(rendered), max_len=96)


def render_surface_map_markdown(
    surface_map: dict[str, Any],
    *,
    max_endpoints_per_origin: int = 120,
) -> str:
    """Render a deterministic, secret-free Markdown Site Map grouped by origin."""
    cap = max(1, int(max_endpoints_per_origin))
    base_url = _sanitize_single_line(surface_map.get("base_url") or "", max_len=160)
    raw_stats = surface_map.get("stats")
    stats: dict[str, Any] = raw_stats if isinstance(raw_stats, dict) else {}
    src_counts = stats.get("sources_counts")
    src_summary = (
        ", ".join(f"{k}={v}" for k, v in sorted(src_counts.items()))
        if isinstance(src_counts, dict) and src_counts
        else "none"
    )

    lines: list[str] = [
        f"# Canonical Site Map: {base_url}",
        "",
        f"- **Schema:** `{_sanitize_single_line(surface_map.get('schema') or SCHEMA, max_len=64)}`",
        f"- **Origins:** {int(stats.get('origins_count') or 0)}",
        (
            f"- **Endpoints:** {int(stats.get('endpoints_total') or 0)} "
            f"(visited: {int(stats.get('endpoints_visited') or 0)}, "
            f"unvisited: {int(stats.get('endpoints_unvisited') or 0)}, "
            f"write: {int(stats.get('write_endpoints_count') or 0)}, "
            f"graphql_ops: {int(stats.get('graphql_operations_count') or 0)})"
        ),
        f"- **Parameters:** {int(stats.get('params_total') or 0)}",
        f"- **Dropped Out-of-Scope:** {int(stats.get('dropped_out_of_scope') or 0)}",
        f"- **Sources:** {src_summary}",
        "",
    ]

    origins = [o for o in (surface_map.get("origins") or []) if isinstance(o, dict)]
    if not origins:
        lines.append("_No in-scope origins or endpoints discovered._")
        lines.append("")
        return "\n".join(lines)

    for origin_entry in origins:
        orig_url = _md_cell(origin_entry.get("origin") or "", max_len=140)
        role = _md_cell(origin_entry.get("role") or "unknown", max_len=32)
        waf = _md_cell(origin_entry.get("waf_vendor") or "none", max_len=48)
        techs = [str(t) for t in (origin_entry.get("tech_signals") or []) if str(t).strip()]
        tech_str = _md_cell(", ".join(techs[:10]), max_len=120) if techs else "-"
        eps_count = int(origin_entry.get("endpoints_count") or 0)
        vis_count = int(origin_entry.get("visited_count") or 0)

        lines.extend([
            f"## {orig_url}",
            "",
            f"- **Role:** `{role}` | **WAF:** `{waf}` | **Tech:** {tech_str} | **Endpoints:** {eps_count} (visited: {vis_count})",
            "",
        ])

        eps = [e for e in (origin_entry.get("endpoints") or []) if isinstance(e, dict)]
        if not eps:
            lines.extend(["_No endpoints recorded for this origin._", ""])
            continue

        lines.extend([
            "| Method | Route/Op | Params | Statuses | Auth | Sources | Visited | Leads |",
            "|---|---|---|---|---|---|---|---|",
        ])
        for ep in eps[:cap]:
            method = _md_cell(ep.get("method") or "GET", max_len=16)
            pt = str(ep.get("path_template") or "/")
            gql_op = str(ep.get("graphql_op") or "")
            route_op = f"{pt}#{gql_op}" if gql_op else pt
            params_cell = _format_params_cell(ep)
            statuses = [str(s) for s in (ep.get("statuses_seen") or [])]
            statuses_cell = _md_cell(", ".join(statuses), max_len=48) if statuses else "-"
            auth_cell = _md_cell(ep.get("auth_required") or "unknown", max_len=16)
            srcs = [str(s) for s in (ep.get("sources") or []) if str(s)]
            srcs_cell = _md_cell(", ".join(srcs), max_len=64) if srcs else "-"
            vis_cell = "yes" if ep.get("visited") else "no"
            leads_cell = _format_leads_cell(ep)
            lines.append(
                f"| `{method}` | `{_md_cell(route_op, max_len=120)}` | {params_cell} | "
                f"{statuses_cell} | {auth_cell} | {srcs_cell} | {vis_cell} | {leads_cell} |"
            )

        if len(eps) > cap:
            lines.append("")
            lines.append(f"_... (+{len(eps) - cap} more endpoints in surface-map.json)_")
        lines.append("")

    return "\n".join(lines)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".surface-map-", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
        os.replace(tmp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        tmp_path.unlink(missing_ok=True)


def write_surface_map_artifacts(
    output_dir: Path | str,
    surface_map: dict[str, Any],
) -> tuple[Path, Path]:
    """Atomically write ``surface-map.json`` and ``surface-map.md`` with best-effort 0600 mode."""
    out_path = Path(output_dir).expanduser().resolve()
    out_path.mkdir(parents=True, exist_ok=True)
    json_path = out_path / "surface-map.json"
    md_path = out_path / "surface-map.md"

    json_payload = json.dumps(surface_map, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    md_payload = render_surface_map_markdown(surface_map)
    _atomic_write_text(json_path, json_payload)
    _atomic_write_text(md_path, md_payload)
    return json_path, md_path


def _read_regular_json(path: Path, *, max_bytes: int = _MAX_FILE_BYTES) -> Any:
    """Safely load a regular non-symlink UTF-8 JSON file with a hard byte cap."""
    raw_path = Path(path).expanduser()
    try:
        st = raw_path.lstat()
    except OSError as exc:
        raise ValueError(f"file is missing or unreadable: {raw_path}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"file must not be a symlink: {raw_path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"file must be a regular file: {raw_path}")
    if st.st_size > max_bytes:
        raise ValueError(f"file exceeds maximum size ({max_bytes} bytes): {raw_path}")

    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(raw_path, open_flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"file must not be a symlink: {raw_path}") from None
        raise ValueError(f"failed to open file: {raw_path}") from None

    try:
        fd_st = os.fstat(fd)
        if not stat.S_ISREG(fd_st.st_mode) or fd_st.st_size > max_bytes:
            os.close(fd)
            raise ValueError(f"invalid regular file or oversized: {raw_path}")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw_bytes = handle.read(max_bytes + 1)
    except ValueError:
        if fd >= 0:
            os.close(fd)
        raise
    except OSError as exc:
        if fd >= 0:
            os.close(fd)
        raise ValueError(f"failed to read file: {raw_path}") from exc

    if len(raw_bytes) > max_bytes:
        raise ValueError(f"file exceeds maximum size ({max_bytes} bytes): {raw_path}")
    try:
        return json.loads(raw_bytes.decode("utf-8").lstrip("\ufeff"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"file is not valid UTF-8 JSON: {raw_path}") from exc


def _load_optional_json_dict(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        parsed = _read_regular_json(path)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _merge_stage0_docs(docs: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    valid = [d for d in docs if isinstance(d, dict) and d]
    if not valid:
        return None
    if len(valid) == 1:
        return valid[0]

    merged: dict[str, Any] = {
        "schema": "stage0-seed/1",
        "url": str(valid[0].get("url") or ""),
        "links": [],
        "forms": [],
        "body_templates": {},
        "multipart_schemas": {},
        "discovery_hints": [],
        "discovered_api_hosts": [],
        "observed_app_headers": {},
        "app_headers": {},
    }
    for doc in valid:
        if not merged["url"] and doc.get("url"):
            merged["url"] = str(doc["url"])
        for list_key in ("links", "forms", "discovery_hints", "discovered_api_hosts"):
            vals = doc.get(list_key)
            if isinstance(vals, list):
                merged[list_key].extend(vals)
        bt_vals = doc.get("body_templates")
        if isinstance(bt_vals, dict):
            for k, v in bt_vals.items():
                if isinstance(v, dict):
                    merged_bt = _merge_body_templates(merged["body_templates"].get(k), v)
                    if merged_bt is not None:
                        merged["body_templates"][k] = merged_bt
        mp_vals = doc.get("multipart_schemas")
        if isinstance(mp_vals, dict):
            for k, v in mp_vals.items():
                if isinstance(v, dict):
                    merged_mp = _merge_multipart_schemas(merged["multipart_schemas"].get(k), v)
                    if merged_mp is not None:
                        merged["multipart_schemas"][k] = merged_mp
        for hdr_key in ("observed_app_headers", "app_headers"):
            raw_hdrs = doc.get(hdr_key)
            if isinstance(raw_hdrs, dict) and raw_hdrs:
                _merge_app_headers(merged[hdr_key], _sanitize_app_headers(raw_hdrs))
    return merged


def _extract_tracker_dict(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(doc, dict):
        return None
    for key in ("surface_frontier", "surface_tracker", "surface"):
        raw = doc.get(key)
        if isinstance(raw, dict):
            return raw
    return None


def _merge_tracker_dicts(docs: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    """Merge serialized SurfaceFrontierTracker dicts from monolithic & shard checkpoints."""
    valid = [d for d in docs if isinstance(d, dict) and d]
    if not valid:
        return None
    if len(valid) == 1:
        return valid[0]

    base_url = ""
    visited_set: set[tuple[str, str]] = set()
    routes_map: dict[tuple[str, str], str] = {}
    writes_map: dict[tuple[str, str], str] = {}
    bt_map: dict[tuple[str, str], dict[str, Any]] = {}
    params_map: dict[str, set[str]] = {}
    actors_map: dict[str, set[str]] = {}
    route_2xx_map: dict[str, set[str]] = {}
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    excluded_paths: list[str] = []

    def _extend_list(dst: list[str], vals: Any) -> None:
        if not isinstance(vals, (list, tuple)):
            return
        for item in vals:
            s = str(item or "").strip()
            if s and s not in dst:
                dst.append(s)

    for doc in valid:
        if not base_url:
            cand = str(doc.get("base_url") or doc.get("target") or doc.get("url") or "").strip()
            if cand:
                base_url = cand

        for item in doc.get("visited_method_paths") or ():
            if isinstance(item, (list, tuple)) and len(item) == 2:
                visited_set.add((str(item[0]), str(item[1])))

        disc_routes = doc.get("discovered_routes")
        if isinstance(disc_routes, dict):
            for k, v in disc_routes.items():
                if isinstance(k, (list, tuple)) and len(k) == 2:
                    rk = (str(k[0]), str(k[1]))
                    sv = str(v or "")
                    if rk not in routes_map or (sv and not routes_map[rk]):
                        routes_map[rk] = sv
        elif isinstance(disc_routes, list):
            for row in disc_routes:
                if isinstance(row, (list, tuple)) and len(row) >= 2:
                    rk = (str(row[0]), str(row[1]))
                    sv = str(row[2] if len(row) > 2 else "")
                    if rk not in routes_map or (sv and not routes_map[rk]):
                        routes_map[rk] = sv

        disc_writes = doc.get("discovered_write_ops")
        if isinstance(disc_writes, dict):
            for k, v in disc_writes.items():
                if isinstance(k, (list, tuple)) and len(k) == 2:
                    wk = (str(k[0]), str(k[1]))
                    sv = str(v or "")
                    if wk not in writes_map or (sv and not writes_map[wk]):
                        writes_map[wk] = sv
        elif isinstance(disc_writes, list):
            for row in disc_writes:
                if isinstance(row, (list, tuple)) and len(row) >= 2:
                    wk = (str(row[0]), str(row[1]))
                    sv = str(row[2] if len(row) > 2 else "")
                    if wk not in writes_map or (sv and not writes_map[wk]):
                        writes_map[wk] = sv

        disc_bts = doc.get("discovered_body_templates")
        bt_items: list[tuple[str, str, Any]] = []
        if isinstance(disc_bts, dict):
            for k, v in disc_bts.items():
                if isinstance(k, (list, tuple)) and len(k) == 2:
                    bt_items.append((str(k[0]), str(k[1]), v))
        elif isinstance(disc_bts, list):
            for row in disc_bts:
                if isinstance(row, (list, tuple)) and len(row) == 3:
                    bt_items.append((str(row[0]), str(row[1]), row[2]))
        for m_s, tmpl_s, bt_val in bt_items:
            if isinstance(bt_val, dict) and bt_val:
                bk = (m_s, tmpl_s)
                merged_bt = _merge_body_templates(bt_map.get(bk), bt_val)
                if merged_bt is not None:
                    bt_map[bk] = merged_bt

        for src_key, dst_map in (
            ("discovered_params", params_map),
            ("actors_by_template", actors_map),
            ("route_2xx_actors", route_2xx_map),
        ):
            raw_m = doc.get(src_key)
            if isinstance(raw_m, dict):
                for tk, vals in raw_m.items():
                    if isinstance(vals, (list, tuple, set)):
                        dst_map.setdefault(str(tk), set()).update(str(v) for v in vals if str(v or "").strip())

        _extend_list(in_scope, doc.get("in_scope_assets"))
        _extend_list(out_of_scope, doc.get("out_of_scope_assets"))
        _extend_list(excluded_paths, doc.get("excluded_paths"))

    merged_tracker: dict[str, Any] = {
        "visited_method_paths": [list(x) for x in sorted(visited_set)],
        "discovered_routes": [[k[0], k[1], v] for k, v in sorted(routes_map.items())],
        "discovered_write_ops": [[k[0], k[1], v] for k, v in sorted(writes_map.items())],
        "discovered_body_templates": [[k[0], k[1], v] for k, v in sorted(bt_map.items())],
        "discovered_params": {k: sorted(v) for k, v in sorted(params_map.items())},
        "actors_by_template": {k: sorted(v) for k, v in sorted(actors_map.items())},
        "route_2xx_actors": {k: sorted(v) for k, v in sorted(route_2xx_map.items())},
    }
    if base_url:
        merged_tracker["base_url"] = base_url
    if in_scope:
        merged_tracker["in_scope_assets"] = in_scope
    if out_of_scope:
        merged_tracker["out_of_scope_assets"] = out_of_scope
    if excluded_paths:
        merged_tracker["excluded_paths"] = excluded_paths
    return merged_tracker


def build_surface_map_from_run_dir(run_dir: Path | str) -> dict[str, Any]:
    """Load run directory artifacts offline and return the unified ``cco-surface-map/1`` dict."""
    root = Path(run_dir).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"run directory does not exist: {root}")

    manifest_doc = _load_optional_json_dict(root / "manifest.json")
    plan_doc = _load_optional_json_dict(root / "agentic-plan.json")
    meta_doc = manifest_doc or plan_doc or {}

    stage0_pre = _load_optional_json_dict(root / "stage0-seed.json")
    stage0_post = _load_optional_json_dict(root / "stage0-post-auth-seed.json")
    stage0_merged = _merge_stage0_docs([d for d in (stage0_pre, stage0_post) if d is not None])

    har_flows_doc = _load_optional_json_dict(root / "har-flows.json")
    prescan_doc = _load_optional_json_dict(root / "prescan-summary.json")
    asset_graph_doc = _load_optional_json_dict(root / "asset-graph.json")
    if asset_graph_doc is None and isinstance(meta_doc.get("asset_graph"), dict):
        ag_file_raw = meta_doc["asset_graph"].get("file")
        if isinstance(ag_file_raw, str) and ag_file_raw.strip():
            asset_graph_doc = _load_optional_json_dict(Path(ag_file_raw))
    seed_doc = _load_optional_json_dict(root / "seed-surface.json")

    tracker_docs: list[dict[str, Any]] = []
    checkpoint_doc = _load_optional_json_dict(root / "checkpoint.json")
    if isinstance(checkpoint_doc, dict):
        root_tracker = _extract_tracker_dict(checkpoint_doc)
        if root_tracker is not None:
            tracker_docs.append(root_tracker)
        completed_shards = checkpoint_doc.get("completed_shards")
        if isinstance(completed_shards, dict):
            for shard_id in sorted(completed_shards):
                shard_tracker = _extract_tracker_dict(completed_shards.get(shard_id))
                if shard_tracker is not None:
                    tracker_docs.append(shard_tracker)
    shards_dir = root / "shards"
    if shards_dir.is_dir():
        for shard_ckpt_path in sorted(shards_dir.glob("*/checkpoint.json")):
            shard_ckpt = _load_optional_json_dict(shard_ckpt_path)
            shard_tracker = _extract_tracker_dict(shard_ckpt)
            if shard_tracker is not None:
                tracker_docs.append(shard_tracker)
    tracker_doc = _merge_tracker_dicts(tracker_docs)

    receipts_list: list[dict[str, Any]] = []
    receipts_dir = root / "receipts"
    if receipts_dir.is_dir():
        receipt_files = sorted(
            receipts_dir.glob("req-*.json"),
            key=lambda p: (0, int(p.stem[4:])) if p.stem[4:].isdigit() else (1, p.name),
        )
        for rp in receipt_files:
            rec_doc = _load_optional_json_dict(rp)
            if rec_doc is not None:
                receipts_list.append(rec_doc)

    # Determine base_url from manifest/plan or any discovered artifact
    base_url = str(meta_doc.get("target") or "").strip()
    if not base_url:
        for cand_doc in (asset_graph_doc, prescan_doc, har_flows_doc, stage0_merged, seed_doc, tracker_doc):
            if not isinstance(cand_doc, dict):
                continue
            cand_u = str(cand_doc.get("target") or cand_doc.get("base_url") or cand_doc.get("url") or "").strip()
            if cand_u:
                base_url = cand_u
                break
    if not base_url and receipts_list:
        for r in receipts_list:
            cand_u = str(r.get("url") or "").strip()
            if "://" in cand_u:
                base_url = cand_u
                break
    if not base_url:
        raise ValueError(f"could not determine target base_url in run directory: {root}")

    norm_base = _normalize_base_origin(base_url)
    parsed_base = urlsplit(norm_base)
    base_scheme = parsed_base.scheme.lower()
    base_host = _canonicalize_host(parsed_base.hostname or "")
    base_port = parsed_base.port if parsed_base.port is not None else _default_port(base_scheme)

    in_scope_assets: list[str] = []
    out_of_scope_assets: list[str] = []
    excluded_paths: list[str] = []

    def _extend_unique(target: list[str], items: Any) -> None:
        if not isinstance(items, (list, tuple)):
            return
        for item in items:
            s = str(item or "").strip()
            if s and s not in target:
                target.append(s)

    # Extract scope rules from manifest/plan scope_file or embedded scope lists
    raw_scope = meta_doc.get("scope")
    if isinstance(raw_scope, dict):
        _extend_unique(in_scope_assets, raw_scope.get("in_scope_assets"))
        _extend_unique(out_of_scope_assets, raw_scope.get("out_of_scope_assets"))
        _extend_unique(excluded_paths, raw_scope.get("excluded_paths"))
        scope_file_raw = raw_scope.get("scope_file")
        if isinstance(scope_file_raw, str) and scope_file_raw.strip():
            sf_path = Path(scope_file_raw)
            if sf_path.exists():
                try:
                    sf_doc = load_scope_file(sf_path)
                    sf_in, sf_out = _extract_scope_asset_lists(sf_doc)
                    sf_exc = _extract_excluded_paths(
                        sf_doc,
                        target_scheme=base_scheme,
                        target_host=base_host,
                        target_port=base_port,
                    )
                    if not bool(raw_scope.get("loopback_only", False)):
                        _extend_unique(in_scope_assets, sf_in)
                        _extend_unique(out_of_scope_assets, sf_out)
                    else:
                        _extend_unique(in_scope_assets, _filter_loopback_scope_assets(sf_in))
                        _extend_unique(out_of_scope_assets, _filter_loopback_scope_assets(sf_out))
                    _extend_unique(excluded_paths, sf_exc)
                except ValueError:
                    pass

    if isinstance(asset_graph_doc, dict) and isinstance(asset_graph_doc.get("scope"), dict):
        ag_scope = asset_graph_doc["scope"]
        _extend_unique(in_scope_assets, ag_scope.get("in_scope_assets"))
        _extend_unique(out_of_scope_assets, ag_scope.get("out_of_scope_assets"))
        _extend_unique(excluded_paths, ag_scope.get("excluded_paths"))

    if isinstance(tracker_doc, dict):
        _extend_unique(in_scope_assets, tracker_doc.get("in_scope_assets"))
        _extend_unique(out_of_scope_assets, tracker_doc.get("out_of_scope_assets"))
        _extend_unique(excluded_paths, tracker_doc.get("excluded_paths"))

    return build_surface_map(
        base_url=norm_base,
        receipts=receipts_list,
        seed_surface=seed_doc,
        stage0_result=stage0_merged,
        har_flows=har_flows_doc,
        asset_graph=asset_graph_doc,
        prescan_doc=prescan_doc,
        surface_tracker=tracker_doc,
        in_scope_assets=in_scope_assets,
        out_of_scope_assets=out_of_scope_assets,
        excluded_paths=excluded_paths,
    )


def _merge_har_flow_docs(docs: Sequence[dict[str, Any]], *, base_url: str) -> dict[str, Any] | None:
    valid = [d for d in docs if isinstance(d, dict)]
    if not valid:
        return None
    if len(valid) == 1:
        return valid[0]
    flows: list[dict[str, Any]] = []
    dropped_scope = 0
    for doc in valid:
        for fl in doc.get("flows") or []:
            if isinstance(fl, dict):
                flows.append(fl)
        st = doc.get("stats")
        if isinstance(st, dict):
            ds = st.get("entries_dropped_scope")
            if isinstance(ds, int) and not isinstance(ds, bool) and ds > 0:
                dropped_scope += ds
    return {
        "schema": "har-flow/1",
        "base_url": base_url,
        "flows": flows,
        "stats": {"entries_dropped_scope": dropped_scope},
    }


def _classify_offline_seed_files(
    paths: Sequence[Path],
) -> tuple[list[Path], list[Path], list[dict[str, Any]]]:
    """Split offline --seed-surface files into (generic_seed_paths, har_paths, stage0_docs)."""
    generic_paths: list[Path] = []
    har_paths: list[Path] = []
    stage0_docs: list[dict[str, Any]] = []
    for p in paths:
        parsed: Any = None
        try:
            parsed = _read_regular_json(p)
        except ValueError:
            # Non-JSON formats (URL list, ffuf text, etc.) go directly to agentic_seed.
            generic_paths.append(p)
            continue
        if isinstance(parsed, dict):
            if isinstance(parsed.get("log"), dict) and isinstance(parsed["log"].get("entries"), list):
                har_paths.append(p)
                continue
            if str(parsed.get("schema") or "").startswith("stage0-seed/"):
                stage0_docs.append(parsed)
                continue
        generic_paths.append(p)
    return generic_paths, har_paths, stage0_docs


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``cco-agent map`` (0 network requests)."""
    parser = argparse.ArgumentParser(
        prog="cco-agent map",
        description="Build a canonical, scope-filtered, secret-redacted multi-origin Site Map (0 network traffic).",
    )
    parser.add_argument(
        "run_dir",
        nargs="?",
        type=Path,
        default=None,
        help="Existing assessment run directory containing manifest.json / agentic-plan.json / receipts/",
    )
    parser.add_argument(
        "--run-dir",
        dest="run_dir_opt",
        type=Path,
        default=None,
        help="Existing assessment run directory (alternative to positional run_dir)",
    )
    parser.add_argument(
        "--target",
        default="",
        help="Primary target origin for offline pre-run site mapping (0 network traffic)",
    )
    parser.add_argument(
        "--scope-file",
        type=Path,
        default=None,
        help="Explicit scope.json file (required when --allow-non-loopback is set)",
    )
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="Allow non-loopback target origin authorized by --scope-file",
    )
    parser.add_argument(
        "--asset-graph",
        type=Path,
        default=None,
        help="Optional cco-asset-graph/1 JSON file produced by 'cco-agent recon'",
    )
    parser.add_argument(
        "--seed-surface",
        "--seed-file",
        action="append",
        dest="seed_surfaces",
        type=Path,
        default=None,
        help="Offline seed surface artifact (HAR / stage0-seed / ZAP / ffuf / URL list); repeatable",
    )
    parser.add_argument(
        "--output-dir",
        "--output",
        dest="output_dir",
        type=Path,
        default=None,
        help="Output directory for surface-map.json and surface-map.md (defaults to run_dir in run-dir mode)",
    )

    opts = parser.parse_args(argv)
    eff_run_dir: Path | None = opts.run_dir_opt or opts.run_dir
    target_str = str(opts.target or "").strip()

    if eff_run_dir is not None and target_str:
        parser.error("specify either a run directory (positional/--run-dir) or --target, not both")
    if eff_run_dir is None and not target_str:
        parser.error("specify either a run directory (positional/--run-dir) or --target")

    # Mode 1: rebuild Site Map from an existing run directory (0 network traffic)
    if eff_run_dir is not None:
        try:
            surface_map = build_surface_map_from_run_dir(eff_run_dir)
        except ValueError as exc:
            parser.error(str(exc))
        out_dir = opts.output_dir if opts.output_dir is not None else eff_run_dir
        json_path, md_path = write_surface_map_artifacts(out_dir, surface_map)
        summary = {
            "schema": SCHEMA,
            "mode": "run_dir",
            "run_dir": str(eff_run_dir.expanduser().resolve()),
            "target": surface_map["base_url"],
            "surface_map_json": str(json_path),
            "surface_map_md": str(md_path),
            "network_requests": 0,
            "stats": surface_map["stats"],
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    # Mode 2: offline pre-run site mapping (0 network traffic)
    if opts.output_dir is None:
        parser.error("--output-dir is required when mapping offline with --target")

    try:
        base_origin, scope_meta = resolve_target_origin(
            target_str,
            scope_file=opts.scope_file,
            allow_non_loopback=bool(opts.allow_non_loopback),
        )
    except ValueError as exc:
        parser.error(str(exc))

    eff_loopback_only = bool(scope_meta.get("loopback_only", True))
    eff_excluded_paths = list(scope_meta.get("excluded_paths") or [])
    eff_in_scope_assets = list(scope_meta.get("in_scope_assets") or [])
    eff_out_of_scope_assets = list(scope_meta.get("out_of_scope_assets") or [])

    def _extend_offline_unique(dest: list[str], items: Any) -> None:
        if not isinstance(items, (list, tuple)):
            return
        for item in items:
            s = str(item or "").strip()
            if s and s not in dest:
                dest.append(s)

    if eff_loopback_only and opts.scope_file is not None:
        try:
            lb_scope_doc = load_scope_file(Path(opts.scope_file).expanduser())
            sf_in, sf_out = _extract_scope_asset_lists(lb_scope_doc)
            _extend_offline_unique(eff_in_scope_assets, _filter_loopback_scope_assets(sf_in))
            _extend_offline_unique(eff_out_of_scope_assets, _filter_loopback_scope_assets(sf_out))
        except ValueError:
            pass

    asset_graph_doc: dict[str, Any] | None = None
    if opts.asset_graph is not None:
        try:
            loaded_ag = _read_regular_json(opts.asset_graph)
        except ValueError as exc:
            parser.error(str(exc))
        if not isinstance(loaded_ag, dict) or loaded_ag.get("schema") != "cco-asset-graph/1":
            parser.error("asset graph must be a valid cco-asset-graph/1 JSON object")
        asset_graph_doc = loaded_ag
        ag_scope = asset_graph_doc.get("scope")
        if isinstance(ag_scope, dict):
            ag_in = ag_scope.get("in_scope_assets")
            ag_out = ag_scope.get("out_of_scope_assets")
            if eff_loopback_only:
                _extend_offline_unique(eff_in_scope_assets, _filter_loopback_scope_assets(ag_in))
                _extend_offline_unique(eff_out_of_scope_assets, _filter_loopback_scope_assets(ag_out))
            else:
                _extend_offline_unique(eff_in_scope_assets, ag_in)
                _extend_offline_unique(eff_out_of_scope_assets, ag_out)
            _extend_offline_unique(eff_excluded_paths, ag_scope.get("excluded_paths"))

    seed_surface_doc: dict[str, Any] | None = None
    har_flows_doc: dict[str, Any] | None = None
    stage0_doc: dict[str, Any] | None = None

    if opts.seed_surfaces:
        import agentic_har_flow  # type: ignore[import-not-found]
        import agentic_seed  # type: ignore[import-not-found]

        try:
            generic_paths, har_paths, stage0_docs = _classify_offline_seed_files(opts.seed_surfaces)
            if generic_paths:
                seed_surface_doc = agentic_seed.load_seed_surface_files(
                    generic_paths,
                    base_url=base_origin,
                    excluded_paths=eff_excluded_paths,
                    in_scope_assets=eff_in_scope_assets,
                    out_of_scope_assets=eff_out_of_scope_assets,
                )
            if har_paths:
                har_docs: list[dict[str, Any]] = []
                for hp in har_paths:
                    har_docs.append(
                        agentic_har_flow.extract_har_flows(
                            hp,
                            base_url=base_origin,
                            excluded_paths=eff_excluded_paths,
                            in_scope_assets=eff_in_scope_assets,
                            out_of_scope_assets=eff_out_of_scope_assets,
                        )
                    )
                har_flows_doc = _merge_har_flow_docs(har_docs, base_url=base_origin)
                # Also extract non-flow HAR routes as seed endpoints without double-counting scope drops.
                har_seed = agentic_seed.load_seed_surface_files(
                    har_paths,
                    base_url=base_origin,
                    excluded_paths=eff_excluded_paths,
                    in_scope_assets=eff_in_scope_assets,
                    out_of_scope_assets=eff_out_of_scope_assets,
                )
                if isinstance(har_seed.get("stats"), dict):
                    har_seed["stats"]["routes_dropped_scope"] = 0
                if seed_surface_doc is None:
                    seed_surface_doc = har_seed
                else:
                    seed_surface_doc = agentic_seed.merge_seed_surfaces(
                        [seed_surface_doc, har_seed],
                        base_url=base_origin,
                        excluded_paths=eff_excluded_paths,
                        in_scope_assets=eff_in_scope_assets,
                        out_of_scope_assets=eff_out_of_scope_assets,
                    )
            if stage0_docs:
                stage0_doc = _merge_stage0_docs(stage0_docs)
        except ValueError as exc:
            parser.error(str(exc))

    surface_map = build_surface_map(
        base_url=base_origin,
        seed_surface=seed_surface_doc,
        stage0_result=stage0_doc,
        har_flows=har_flows_doc,
        asset_graph=asset_graph_doc,
        in_scope_assets=eff_in_scope_assets,
        out_of_scope_assets=eff_out_of_scope_assets,
        excluded_paths=eff_excluded_paths,
    )
    json_path, md_path = write_surface_map_artifacts(opts.output_dir, surface_map)
    summary = {
        "schema": SCHEMA,
        "mode": "offline",
        "target": surface_map["base_url"],
        "surface_map_json": str(json_path),
        "surface_map_md": str(md_path),
        "network_requests": 0,
        "stats": surface_map["stats"],
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


__all__ = [
    "SCHEMA",
    "VALID_SOURCES",
    "build_surface_map",
    "build_surface_map_from_run_dir",
    "main",
    "render_surface_map_markdown",
    "write_surface_map_artifacts",
]


if __name__ == "__main__":
    raise SystemExit(main())
